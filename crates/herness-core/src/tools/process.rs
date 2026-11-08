//! Host-owned process groups for the `bash` tool.
//!
//! Every command is started as `/bin/sh -c <command>` in its own process
//! group, with the frozen working directory, inherited host environment, and a
//! null stdin. The host records the pid and pgid, captures stdout/stderr on
//! dedicated threads with bounded head/tail buffers, and owns stop handling:
//! SIGTERM to the group, a bounded grace period, then SIGKILL for lingering
//! members. A stop is only reported as confirmed when the group is empty after
//! the direct child has been reaped.
//!
//! Intentionally detached descendants (`setsid`, double fork) leave the
//! managed process group. They are outside this guarantee and must never be
//! reported as captured or stopped by the host.
//!
//! Finder's minimal `PATH` is deliberately not rewritten here; command
//! discovery is a Task 6 concern. The command inherits the host environment.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::contracts::errors::ShellFailure;
use crate::contracts::ids::OperationId;
use crate::contracts::path::AbsolutePath;
use crate::contracts::shell::{ShellOutput, ShellStopStatus};

/// Default number of bytes retained from the head and, separately, the tail of
/// each output stream.
pub const DEFAULT_OUTPUT_LIMIT: usize = 64 * 1024;

/// Default grace period between SIGTERM and SIGKILL for a host stop.
///
/// The H1 spec uses a 10-second cooperative stop grace; Task 12 owns the
/// human decision that follows it. The control surface accepts an explicit
/// grace so tests and later phases can choose a shorter window.
pub const DEFAULT_STOP_GRACE: Duration = Duration::from_secs(10);

/// Default grace period between SIGTERM and SIGKILL for a command timeout.
pub const DEFAULT_TIMEOUT_GRACE: Duration = Duration::from_secs(2);

/// Default time to wait for a group to disappear after SIGKILL.
pub const DEFAULT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(2);

/// Default time to wait for output readers after the group is gone.
pub const DEFAULT_CAPTURE_TIMEOUT: Duration = Duration::from_secs(1);

const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Signals the host sends to a managed process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedSignal {
    /// Cooperative termination.
    Terminate,
    /// Forced termination.
    Kill,
}

/// Request describing one managed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnRequest {
    command: String,
    cwd: AbsolutePath,
}

impl SpawnRequest {
    /// Creates a request for `/bin/sh -c <command>` in `cwd`.
    pub fn new(command: impl Into<String>, cwd: AbsolutePath) -> Self {
        Self {
            command: command.into(),
            cwd,
        }
    }

    /// Command string passed to `/bin/sh -c`.
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Frozen working directory.
    pub const fn cwd(&self) -> &AbsolutePath {
        &self.cwd
    }
}

/// A spawned child whose process group is managed by the host.
pub trait ManagedChild: Send {
    /// Direct child pid, which is also the process-group id.
    fn pid(&self) -> u32;
    /// Takes the stdout pipe, if it was piped.
    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>>;
    /// Takes the stderr pipe, if it was piped.
    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>>;
    /// Reaps the child if it has exited.
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;
}

/// Injectable process creation.
///
/// Production uses [`SystemLauncher`]. Tests wrap it to count spawn attempts
/// without changing the production IPC or store contract.
pub trait ProcessLauncher: Send {
    /// Child type produced by this launcher.
    type Child: ManagedChild;

    /// Starts one managed command.
    fn spawn(&mut self, request: &SpawnRequest) -> io::Result<Self::Child>;
}

/// Real `/bin/sh` launcher.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemLauncher;

impl ProcessLauncher for SystemLauncher {
    type Child = SystemChild;

    fn spawn(&mut self, request: &SpawnRequest) -> io::Result<Self::Child> {
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg(request.command())
            .current_dir(request.cwd().as_path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Start the shell as the leader of a new process group. This uses
            // `setpgid(0, 0)` semantics in the child before `exec`.
            .process_group(0)
            .spawn()?;
        Ok(SystemChild { child })
    }
}

/// Direct child created by [`SystemLauncher`].
#[derive(Debug)]
pub struct SystemChild {
    child: Child,
}

impl ManagedChild for SystemChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.child
            .stdout
            .take()
            .map(|stream| Box::new(stream) as Box<dyn Read + Send>)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        self.child
            .stderr
            .take()
            .map(|stream| Box::new(stream) as Box<dyn Read + Send>)
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
}

/// Sends a signal to a managed process group.
///
/// Returns `true` when the call was accepted. A group that has already
/// disappeared returns `false`; callers treat that as gone through
/// [`process_group_exists`].
pub fn signal_process_group(pgid: u32, signal: ManagedSignal) -> bool {
    let raw = match signal {
        ManagedSignal::Terminate => libc::SIGTERM,
        ManagedSignal::Kill => libc::SIGKILL,
    };
    #[allow(unsafe_code)]
    let result = unsafe { libc::killpg(pgid as libc::pid_t, raw) };
    result == 0
}

/// Whether at least one member of the process group still exists.
pub fn process_group_exists(pgid: u32) -> bool {
    #[allow(unsafe_code)]
    let result = unsafe { libc::killpg(pgid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// One managed group registered with the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedGroup {
    operation: OperationId,
    pid: u32,
    pgid: u32,
}

impl ManagedGroup {
    /// Operation that owns the group.
    pub const fn operation_id(&self) -> OperationId {
        self.operation
    }

    /// Direct child pid.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Process-group id.
    pub const fn pgid(&self) -> u32 {
        self.pgid
    }
}

#[derive(Debug, Clone, Copy)]
struct GroupEntry {
    operation: OperationId,
    pid: u32,
    pgid: u32,
}

impl GroupEntry {
    const fn public(self) -> ManagedGroup {
        ManagedGroup {
            operation: self.operation,
            pid: self.pid,
            pgid: self.pgid,
        }
    }
}

/// Shared host control surface for managed process groups.
///
/// `ProcessSupervisor` clones share one state. Once [`Self::begin_stop`] has
/// been called, new registrations are refused; the caller must not spawn new
/// commands without accepting that they will be terminated immediately. A stop
/// is terminal for the supervisor: create one supervisor per run/application
/// session that should be stopped independently.
#[derive(Debug, Clone, Default)]
pub struct ProcessSupervisor {
    inner: Arc<SupervisorInner>,
}

#[derive(Debug, Default)]
struct SupervisorInner {
    stopping: AtomicBool,
    force_requested: AtomicBool,
    spawn_gate: Mutex<()>,
    groups: Mutex<BTreeMap<u32, GroupEntry>>,
}

impl ProcessSupervisor {
    /// Creates an empty supervisor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether stop has begun. New commands must not spawn after this is true.
    pub fn is_stopping(&self) -> bool {
        self.inner.stopping.load(Ordering::SeqCst)
    }

    /// Whether the host has escalated the stop with SIGKILL.
    ///
    /// Executors use this to bound their final confirmation wait; they never
    /// turn an unconfirmed group into a success.
    pub fn is_force_requested(&self) -> bool {
        self.inner.force_requested.load(Ordering::SeqCst)
    }

    /// Registers a spawned group, unless stop has begun.
    ///
    /// The caller must have already spawned the child. A `None` result means
    /// stop began during the spawn window; the caller must terminate the child
    /// immediately and must not treat it as newly accepted work.
    pub fn register(&self, operation: OperationId, pid: u32, pgid: u32) -> Option<GroupLease> {
        let mut groups = self
            .inner
            .groups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.inner.stopping.load(Ordering::SeqCst) {
            return None;
        }
        groups.insert(
            pgid,
            GroupEntry {
                operation,
                pid,
                pgid,
            },
        );
        Some(GroupLease {
            supervisor: self.clone(),
            pgid,
        })
    }

    /// Serializes spawn with the start of a host stop.
    ///
    /// While the returned gate is held, [`Self::begin_stop`] waits instead of
    /// setting the stop flag. The caller must spawn the child, register it with
    /// [`Self::register`], and then drop the gate. This closes the window where
    /// stop had begun but a process was still created afterwards.
    pub fn begin_spawn(&self) -> Option<SpawnGate<'_>> {
        let guard = self
            .inner
            .spawn_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.inner.stopping.load(Ordering::SeqCst) {
            return None;
        }
        Some(SpawnGate { _guard: guard })
    }

    /// Groups currently registered for supervision.
    pub fn active_groups(&self) -> Vec<ManagedGroup> {
        let groups = self
            .inner
            .groups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        groups.values().copied().map(GroupEntry::public).collect()
    }

    /// Refuses new registrations and sends SIGTERM to every managed group.
    ///
    /// The returned [`StopRequest`] is the snapshot that was signalled. This
    /// waits for an in-progress spawn registration to finish, so a process is
    /// never created after stop has been recorded as begun.
    pub fn begin_stop(&self) -> StopRequest {
        let groups = {
            let _gate = self
                .inner
                .spawn_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let groups = self
                .inner
                .groups
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.inner.stopping.store(true, Ordering::SeqCst);
            groups
                .values()
                .copied()
                .map(GroupEntry::public)
                .collect::<Vec<_>>()
        };
        for group in &groups {
            signal_process_group(group.pgid, ManagedSignal::Terminate);
        }
        StopRequest { groups }
    }

    /// Stops every managed group: SIGTERM, bounded grace, then SIGKILL.
    ///
    /// A group is reported as confirmed only after the direct child was reaped
    /// (by the executor thread) and the group no longer exists. `stop_all`
    /// never turns an unconfirmed group into a success.
    pub fn stop_all(&self, grace: Duration) -> SupervisorStopReport {
        let request = self.begin_stop();

        // Wait for cooperative termination across all groups at once.
        let grace_deadline = Instant::now() + grace;
        loop {
            if request
                .groups
                .iter()
                .all(|group| !process_group_exists(group.pgid))
            {
                break;
            }
            if Instant::now() >= grace_deadline {
                break;
            }
            thread::sleep(POLL_INTERVAL);
        }

        // Force-stop only the groups that are still present after the grace.
        let mut forced = BTreeSet::new();
        for group in &request.groups {
            if process_group_exists(group.pgid) {
                forced.insert(group.pgid);
            }
        }
        if !forced.is_empty() {
            self.inner.force_requested.store(true, Ordering::SeqCst);
            for pgid in &forced {
                signal_process_group(*pgid, ManagedSignal::Kill);
            }
        }

        let confirm_deadline = Instant::now() + DEFAULT_CONFIRM_TIMEOUT;
        loop {
            if request
                .groups
                .iter()
                .all(|group| !process_group_exists(group.pgid))
            {
                break;
            }
            if Instant::now() >= confirm_deadline {
                break;
            }
            thread::sleep(POLL_INTERVAL);
        }

        let reports = request
            .groups
            .iter()
            .map(|group| GroupStopReport {
                group: *group,
                confirmed: !process_group_exists(group.pgid),
                kill_sent: forced.contains(&group.pgid),
            })
            .collect();
        SupervisorStopReport { reports }
    }

    fn unregister(&self, pgid: u32) {
        let mut groups = self
            .inner
            .groups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        groups.remove(&pgid);
    }
}

/// RAII gate that serializes one spawn against the start of a host stop.
#[derive(Debug)]
pub struct SpawnGate<'a> {
    _guard: std::sync::MutexGuard<'a, ()>,
}

/// RAII registration for one managed group.
#[derive(Debug)]
pub struct GroupLease {
    supervisor: ProcessSupervisor,
    pgid: u32,
}

impl GroupLease {
    /// Registered process-group id.
    pub const fn pgid(&self) -> u32 {
        self.pgid
    }
}

impl Drop for GroupLease {
    fn drop(&mut self) {
        self.supervisor.unregister(self.pgid);
    }
}

/// Snapshot returned by [`ProcessSupervisor::begin_stop`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopRequest {
    groups: Vec<ManagedGroup>,
}

impl StopRequest {
    /// Groups that received SIGTERM.
    pub fn groups(&self) -> &[ManagedGroup] {
        &self.groups
    }

    /// Whether no group was registered when stop began.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

/// One group's outcome from [`ProcessSupervisor::stop_all`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupStopReport {
    group: ManagedGroup,
    confirmed: bool,
    kill_sent: bool,
}

impl GroupStopReport {
    /// Group this report describes.
    pub const fn group(&self) -> ManagedGroup {
        self.group
    }

    /// Whether the host confirmed the group is gone.
    pub const fn confirmed(&self) -> bool {
        self.confirmed
    }

    /// Whether SIGKILL was sent after the grace period.
    pub const fn kill_sent(&self) -> bool {
        self.kill_sent
    }
}

/// Result of [`ProcessSupervisor::stop_all`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorStopReport {
    reports: Vec<GroupStopReport>,
}

impl SupervisorStopReport {
    /// Per-group reports.
    pub fn reports(&self) -> &[GroupStopReport] {
        &self.reports
    }

    /// Whether every signalled group was confirmed gone.
    pub fn all_confirmed(&self) -> bool {
        self.reports.iter().all(GroupStopReport::confirmed)
    }
}

/// How one managed command ended, from the supervisor's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    stop_status: ShellStopStatus,
    exit_code: Option<i32>,
    terminating_signal: Option<i32>,
    confirmed: bool,
}

impl Completion {
    /// Stop status to record.
    pub const fn stop_status(&self) -> ShellStopStatus {
        self.stop_status
    }

    /// Normal exit code, when available.
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Terminating signal, when the process was killed.
    pub const fn terminating_signal(&self) -> Option<i32> {
        self.terminating_signal
    }

    /// Whether the host confirmed the managed group is gone.
    pub const fn confirmed(&self) -> bool {
        self.confirmed
    }
}

/// Waits for a managed child while honoring stop and timeout.
///
/// A host stop sends SIGTERM through [`ProcessSupervisor::begin_stop`] or
/// [`ProcessSupervisor::stop_all`]. The executor itself does not decide when
/// to escalate a host stop: [`ProcessSupervisor::stop_all`] owns the bounded
/// grace and SIGKILL step, while this function reaps the direct child and
/// reports `Unconfirmed` rather than success when the group cannot be proven
/// gone. A command timeout does own its termination window because there is no
/// human decision to wait for.
pub fn supervise<C: ManagedChild>(
    child: &mut C,
    pgid: u32,
    supervisor: &ProcessSupervisor,
    timeout: Option<Duration>,
    timeout_grace: Duration,
    confirm_timeout: Duration,
) -> Completion {
    let deadline = timeout.and_then(|duration| Instant::now().checked_add(duration));
    let mut stop_requested = false;
    let mut timed_out = false;
    let mut normal_exit = None;
    let mut wait_failed = false;

    loop {
        // Stop takes precedence: once stop begins, the operation must not be
        // reported as a success even if the child exits at the same moment.
        if supervisor.is_stopping() {
            stop_requested = true;
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                normal_exit = Some(status);
                break;
            }
            Ok(None) => {}
            Err(_) => {
                wait_failed = true;
                break;
            }
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            timed_out = true;
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    if let Some(status) = normal_exit {
        return finish_normally(status, pgid, confirm_timeout);
    }

    if stop_requested {
        let (status, confirmed) = wait_for_external_stop(child, pgid, supervisor, confirm_timeout);
        return Completion {
            stop_status: if confirmed {
                ShellStopStatus::StopRequested
            } else {
                ShellStopStatus::Unconfirmed
            },
            exit_code: status.and_then(|status| status.code()),
            terminating_signal: status.and_then(|status| status.signal()),
            confirmed,
        };
    }

    // Timeout (or an unexpected wait failure): the host terminates the group
    // itself with a bounded grace. A wait failure never becomes a success.
    let (status, confirmed) = terminate_group(child, pgid, timeout_grace, confirm_timeout);
    Completion {
        stop_status: if confirmed && !wait_failed {
            if timed_out {
                ShellStopStatus::Timeout
            } else {
                ShellStopStatus::Unconfirmed
            }
        } else {
            ShellStopStatus::Unconfirmed
        },
        exit_code: status.and_then(|status| status.code()),
        terminating_signal: status.and_then(|status| status.signal()),
        confirmed: confirmed && !wait_failed,
    }
}

fn wait_for_external_stop<C: ManagedChild>(
    child: &mut C,
    pgid: u32,
    supervisor: &ProcessSupervisor,
    confirm_timeout: Duration,
) -> (Option<ExitStatus>, bool) {
    let mut status = None;
    loop {
        reap(child, &mut status);
        if status.is_some() && !process_group_exists(pgid) {
            return (status, true);
        }
        if supervisor.is_force_requested() {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    // The host has escalated to SIGKILL. Bound the final confirmation so an
    // unkillable member is reported as unconfirmed instead of waiting forever.
    let deadline = Instant::now() + confirm_timeout;
    loop {
        reap(child, &mut status);
        if status.is_some() && !process_group_exists(pgid) {
            return (status, true);
        }
        if Instant::now() >= deadline {
            return (status, false);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn finish_normally(status: ExitStatus, pgid: u32, confirm_timeout: Duration) -> Completion {
    // A shell may leave background members in its group. The host owns the
    // group, so lingering members are killed before the result is recorded.
    let confirmed = if process_group_exists(pgid) {
        signal_process_group(pgid, ManagedSignal::Kill);
        wait_until_gone(pgid, confirm_timeout)
    } else {
        true
    };
    let stop_status = if !confirmed {
        ShellStopStatus::Unconfirmed
    } else if let Some(code) = status.code() {
        if code == 0 {
            ShellStopStatus::Completed
        } else {
            ShellStopStatus::ExitedNonZero
        }
    } else if status.signal().is_some() {
        ShellStopStatus::Killed
    } else {
        ShellStopStatus::Unconfirmed
    };
    Completion {
        stop_status,
        exit_code: status.code(),
        terminating_signal: status.signal(),
        confirmed,
    }
}

fn terminate_group<C: ManagedChild>(
    child: &mut C,
    pgid: u32,
    grace: Duration,
    confirm_timeout: Duration,
) -> (Option<ExitStatus>, bool) {
    let mut status = None;
    signal_process_group(pgid, ManagedSignal::Terminate);
    let term_deadline = Instant::now() + grace;
    loop {
        reap(child, &mut status);
        if status.is_some() && !process_group_exists(pgid) {
            return (status, true);
        }
        if Instant::now() >= term_deadline {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    signal_process_group(pgid, ManagedSignal::Kill);
    let kill_deadline = Instant::now() + confirm_timeout;
    loop {
        reap(child, &mut status);
        if status.is_some() && !process_group_exists(pgid) {
            return (status, true);
        }
        if Instant::now() >= kill_deadline {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
    reap(child, &mut status);
    (status, false)
}

fn reap<C: ManagedChild>(child: &mut C, status: &mut Option<ExitStatus>) {
    if status.is_none()
        && let Ok(Some(observed)) = child.try_wait()
    {
        *status = Some(observed);
    }
}

fn wait_until_gone(pgid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_group_exists(pgid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Bounded head/tail output capture shared with one reader thread.
#[derive(Debug)]
struct BoundedCapture {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    head_limit: usize,
    tail_limit: usize,
    seen: u64,
    dropped: bool,
}

impl BoundedCapture {
    fn new(head_limit: usize, tail_limit: usize) -> Self {
        Self {
            head: Vec::new(),
            tail: VecDeque::new(),
            head_limit,
            tail_limit,
            seen: 0,
            dropped: false,
        }
    }

    fn push(&mut self, mut bytes: &[u8]) {
        self.seen = self.seen.saturating_add(bytes.len() as u64);
        let head_room = self.head_limit.saturating_sub(self.head.len());
        let take = head_room.min(bytes.len());
        self.head.extend_from_slice(&bytes[..take]);
        bytes = &bytes[take..];

        for byte in bytes {
            if self.tail_limit == 0 {
                self.dropped = true;
                continue;
            }
            if self.tail.len() == self.tail_limit {
                self.tail.pop_front();
                self.dropped = true;
            }
            self.tail.push_back(*byte);
        }
    }

    fn finish(self, complete: bool) -> ShellOutput {
        let retained = self.head.len() + self.tail.len();
        let truncated = self.dropped || self.seen > retained as u64 || !complete;
        let omitted = self.seen.saturating_sub(retained as u64);
        let mut bytes = self.head;
        if truncated {
            let marker = if complete {
                format!(
                    "\n[herness output truncated: {omitted} of {} bytes omitted]\n",
                    self.seen
                )
            } else {
                format!(
                    "\n[herness output capture incomplete: {omitted} of {} bytes not retained]\n",
                    self.seen
                )
            };
            bytes.extend_from_slice(marker.as_bytes());
        }
        bytes.extend(self.tail);
        ShellOutput::new(
            String::from_utf8_lossy(&bytes).into_owned(),
            truncated,
            self.seen,
        )
    }
}

/// Handle for one output stream being captured on a dedicated thread.
#[derive(Debug)]
pub struct CaptureHandle {
    state: Arc<Mutex<BoundedCapture>>,
    finished: Arc<AtomicBool>,
}

impl CaptureHandle {
    /// Starts capturing `stream`, retaining up to `limit` bytes from both the
    /// head and the tail. A missing stream yields an empty completed capture.
    pub fn start(stream: Option<Box<dyn Read + Send>>, limit: usize) -> Self {
        let state = Arc::new(Mutex::new(BoundedCapture::new(limit, limit)));
        let finished = Arc::new(AtomicBool::new(false));
        match stream {
            None => finished.store(true, Ordering::SeqCst),
            Some(mut stream) => {
                let captured = Arc::clone(&state);
                let done = Arc::clone(&finished);
                let spawned = thread::Builder::new()
                    .name("herness-shell-output".to_owned())
                    .spawn(move || {
                        let mut buffer = [0u8; 16 * 1024];
                        loop {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(read) => {
                                    let mut capture = captured
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                                    capture.push(&buffer[..read]);
                                }
                                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                                Err(_) => break,
                            }
                        }
                        done.store(true, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    finished.store(true, Ordering::SeqCst);
                }
            }
        }
        Self { state, finished }
    }

    /// Waits up to `timeout` for the stream to reach EOF, then returns the
    /// bounded capture. A stream that is still held open by a process outside
    /// the managed group is reported as an incomplete capture, never as a
    /// complete one.
    pub fn wait(self, timeout: Duration) -> ShellOutput {
        let deadline = Instant::now() + timeout;
        while !self.finished.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(POLL_INTERVAL);
        }
        let complete = self.finished.load(Ordering::SeqCst);
        let mut capture = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let capture = std::mem::replace(&mut *capture, BoundedCapture::new(0, 0));
        capture.finish(complete)
    }
}

/// Maps a spawn failure to a sanitized shell failure.
pub fn spawn_failure(error: &io::Error) -> ShellFailure {
    ShellFailure::SpawnFailed {
        detail: format!("{:?}", error.kind()),
    }
}
