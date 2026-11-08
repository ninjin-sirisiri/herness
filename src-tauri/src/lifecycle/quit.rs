//! Explicit application quit: grace period, human choice, and honest results.
//!
//! The production app uses a 10-second coordinated-stop grace. During that
//! window the runtime refuses new runs and tool decisions and stops every active
//! engine, stream, and managed shell group, saving the checkpoints it can. If
//! active work remains after the grace, the trusted main window is shown and the
//! human chooses to keep waiting or force quit. The app never silently
//! force-quits and never reports a forced quit as a save or stop success.
//!
//! The clock and grace are injected for tests. Nothing here is reachable from
//! the production IPC with a test clock; `quit_state`/`quit_choice` expose only
//! the human decision.

use std::sync::{Arc, Mutex, OnceLock, TryLockError};
use std::time::{Duration, Instant};

use herness_core::RunId;
use herness_core::runtime::ShutdownReport;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::app::AppState;
use crate::guard;

/// The coordinated-stop grace required by the H1 contract.
pub const DEFAULT_QUIT_GRACE: Duration = Duration::from_secs(10);

/// Normal quit exit code when every active run was stopped and saved.
pub const EXIT_QUIT_COMPLETE: i32 = 0;
/// Quit completed, but at least one stop or save was not confirmed.
pub const EXIT_QUIT_INCOMPLETE: i32 = 3;
/// The human forced the quit before coordinated stops completed.
pub const EXIT_QUIT_FORCED: i32 = 2;
/// The test launcher could not complete the quit path before its deadline.
pub const EXIT_QUIT_TEST_TIMEOUT: i32 = 4;

/// Monotonic clock used for the quit grace.
///
/// Tests inject a manual clock. Production always uses [`SystemClock`]; no IPC
/// command accepts a clock or a different grace.
pub trait QuitClock: Send + Sync + 'static {
    /// Monotonic milliseconds since an arbitrary origin.
    fn now_millis(&self) -> u64;
}

/// Production monotonic clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

static CLOCK_ORIGIN: OnceLock<Instant> = OnceLock::new();

impl QuitClock for SystemClock {
    fn now_millis(&self) -> u64 {
        let origin = CLOCK_ORIGIN.get_or_init(Instant::now);
        origin.elapsed().as_millis() as u64
    }
}

/// Stage of the explicit quit flow shown to the trusted main window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuitStage {
    /// No quit has been requested in this process.
    Idle,
    /// Coordinated stops are running inside the grace.
    Stopping,
    /// The grace expired or stops failed; the human must choose.
    AwaitingChoice,
    /// The human chose force quit.
    ForceQuitting,
    /// Every active run reached a terminal state; the app may exit.
    Finished,
    /// The stop flow failed before it could finish.
    Failed,
}

/// Human choice after the grace period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuitChoice {
    /// Keep waiting for the coordinated stops.
    KeepWaiting,
    /// Force the process to exit without claiming success.
    ForceQuit,
}

/// Non-secret quit state returned to the trusted UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuitSnapshot {
    stage: QuitStage,
    grace_ms: u64,
    remaining_ms: Option<u64>,
    stop_finished: bool,
    save_succeeded: bool,
    all_inactive: bool,
    unconfirmed_runs: Vec<RunId>,
    remaining_runs: Vec<RunId>,
    discarded_deferred_messages: u64,
    save_failures: u32,
    can_keep_waiting: bool,
    can_force_quit: bool,
    detail: Option<String>,
}

impl QuitSnapshot {
    /// Current stage.
    pub const fn stage(&self) -> QuitStage {
        self.stage
    }

    /// Configured grace in milliseconds.
    pub const fn grace_ms(&self) -> u64 {
        self.grace_ms
    }

    /// Time left in the current grace, when timing.
    pub const fn remaining_ms(&self) -> Option<u64> {
        self.remaining_ms
    }

    /// Whether the coordinated stop attempt returned.
    pub const fn stop_finished(&self) -> bool {
        self.stop_finished
    }

    /// Whether every active run was stopped and every available checkpoint was
    /// saved. Never true for a forced or unconfirmed quit.
    pub const fn save_succeeded(&self) -> bool {
        self.save_succeeded
    }

    /// Whether every active run is out of an active state.
    pub const fn all_inactive(&self) -> bool {
        self.all_inactive
    }

    /// Runs whose stop was unconfirmed or whose stop request failed.
    pub fn unconfirmed_runs(&self) -> &[RunId] {
        &self.unconfirmed_runs
    }

    /// Runs still active when the stop attempt returned.
    pub fn remaining_runs(&self) -> &[RunId] {
        &self.remaining_runs
    }

    /// Host-result messages discarded instead of replayed.
    pub const fn discarded_deferred_messages(&self) -> u64 {
        self.discarded_deferred_messages
    }

    /// Number of stop or save failures recorded.
    pub const fn save_failures(&self) -> u32 {
        self.save_failures
    }

    /// Whether "keep waiting" is a meaningful choice.
    pub const fn can_keep_waiting(&self) -> bool {
        self.can_keep_waiting
    }

    /// Whether the human may force quit.
    pub const fn can_force_quit(&self) -> bool {
        self.can_force_quit
    }

    /// Sanitized explanation for a failure or incomplete stop.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

struct Inner {
    stage: QuitStage,
    deadline_ms: Option<u64>,
    started_ms: Option<u64>,
    report: Option<ShutdownReport>,
    detail: Option<String>,
    extra_detail: Option<String>,
    failed: bool,
}

impl Inner {
    fn new() -> Self {
        Self {
            stage: QuitStage::Idle,
            deadline_ms: None,
            started_ms: None,
            report: None,
            detail: None,
            extra_detail: None,
            failed: false,
        }
    }
}

/// Testable quit state machine.
///
/// The production composition creates exactly one of these with a 10-second
/// grace. Tests create their own with a short grace and a manual clock.
pub struct QuitCoordinator<C: QuitClock> {
    clock: C,
    grace: Duration,
    inner: Mutex<Inner>,
}

impl<C: QuitClock> QuitCoordinator<C> {
    /// Creates a coordinator with an explicit clock and grace.
    pub fn new(clock: C, grace: Duration) -> Self {
        Self {
            clock,
            grace,
            inner: Mutex::new(Inner::new()),
        }
    }

    /// Starts the flow if it is idle. Returns `None` when a flow is already in
    /// progress.
    pub fn begin_if_idle(&self) -> Option<QuitSnapshot> {
        let now = self.clock.now_millis();
        let mut inner = self.lock();
        if inner.stage != QuitStage::Idle {
            return None;
        }
        inner.stage = QuitStage::Stopping;
        inner.started_ms = Some(now);
        inner.deadline_ms = Some(now.saturating_add(self.grace_ms()));
        inner.detail = None;
        inner.extra_detail = None;
        inner.failed = false;
        Some(self.snapshot_locked(&mut inner, now))
    }

    /// Current snapshot, applying the grace deadline lazily.
    pub fn snapshot(&self) -> QuitSnapshot {
        let now = self.clock.now_millis();
        let mut inner = self.lock();
        self.snapshot_locked(&mut inner, now)
    }

    /// Records a completed coordinated-stop attempt.
    ///
    /// If every run is inactive, the flow finishes. Otherwise the human is
    /// asked, because a synchronous stop attempt has no further progress to
    /// wait for.
    pub fn note_stopped(&self, report: ShutdownReport) -> QuitSnapshot {
        let now = self.clock.now_millis();
        let mut inner = self.lock();
        let all_inactive = report.all_inactive();
        let save_succeeded = report.save_succeeded();
        inner.report = Some(report);
        inner.deadline_ms = None;
        inner.stage = if all_inactive {
            QuitStage::Finished
        } else {
            QuitStage::AwaitingChoice
        };
        inner.failed = !all_inactive;
        inner.detail = if save_succeeded {
            None
        } else if all_inactive {
            Some(
                "a coordinated stop was unconfirmed or a checkpoint could not be saved; \
                 the affected runs are interrupted and reconciliation-pending"
                    .to_owned(),
            )
        } else {
            Some("some active runs could not be stopped; choose force quit to exit".to_owned())
        };
        self.snapshot_locked(&mut inner, now)
    }

    /// Records a failure of the stop attempt itself.
    pub fn note_failed(&self, detail: impl Into<String>) -> QuitSnapshot {
        let now = self.clock.now_millis();
        let mut inner = self.lock();
        inner.stage = QuitStage::AwaitingChoice;
        inner.deadline_ms = None;
        inner.failed = true;
        inner.detail = Some(detail.into());
        self.snapshot_locked(&mut inner, now)
    }

    /// Records a non-fatal save failure (for example non-secret connection
    /// settings). The quit may still finish, but it can never report a
    /// confirmed save.
    pub fn note_save_failure(&self, detail: impl Into<String>) -> QuitSnapshot {
        let now = self.clock.now_millis();
        let mut inner = self.lock();
        inner.extra_detail = Some(detail.into());
        self.snapshot_locked(&mut inner, now)
    }

    /// Applies the human choice after the grace.
    pub fn choose(&self, choice: QuitChoice) -> QuitSnapshot {
        let now = self.clock.now_millis();
        let mut inner = self.lock();
        let current = self.snapshot_locked(&mut inner, now);
        match choice {
            QuitChoice::KeepWaiting if current.can_keep_waiting => {
                inner.stage = QuitStage::Stopping;
                inner.deadline_ms = Some(now.saturating_add(self.grace_ms()));
                inner.detail = None;
            }
            QuitChoice::ForceQuit if current.can_force_quit => {
                inner.stage = QuitStage::ForceQuitting;
                inner.deadline_ms = None;
            }
            _ => {}
        }
        self.snapshot_locked(&mut inner, now)
    }

    /// Marks the flow finished.
    pub fn mark_finished(&self) -> QuitSnapshot {
        let now = self.clock.now_millis();
        let mut inner = self.lock();
        inner.stage = QuitStage::Finished;
        inner.deadline_ms = None;
        self.snapshot_locked(&mut inner, now)
    }

    fn grace_ms(&self) -> u64 {
        self.grace.as_millis().min(u128::from(u64::MAX)) as u64
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn snapshot_locked(&self, inner: &mut Inner, now: u64) -> QuitSnapshot {
        if inner.stage == QuitStage::Stopping
            && inner.deadline_ms.is_some_and(|deadline| now >= deadline)
        {
            inner.stage = QuitStage::AwaitingChoice;
        }
        let report = inner.report.as_ref();
        let stop_finished = report.is_some();
        let remaining_ms = match (inner.stage, inner.deadline_ms) {
            (QuitStage::Stopping, Some(deadline)) => Some(deadline.saturating_sub(now)),
            _ => None,
        };
        QuitSnapshot {
            stage: inner.stage,
            grace_ms: self.grace_ms(),
            remaining_ms,
            stop_finished,
            save_succeeded: report.is_some_and(ShutdownReport::save_succeeded)
                && inner.extra_detail.is_none(),
            all_inactive: report.is_some_and(ShutdownReport::all_inactive),
            unconfirmed_runs: report
                .map(|report| report.unconfirmed_runs().to_vec())
                .unwrap_or_default(),
            remaining_runs: report
                .map(|report| report.remaining_runs().to_vec())
                .unwrap_or_default(),
            discarded_deferred_messages: report
                .map_or(0, ShutdownReport::discarded_deferred_messages),
            save_failures: report.map_or(0, ShutdownReport::save_failures),
            can_keep_waiting: inner.stage == QuitStage::AwaitingChoice && !inner.failed,
            can_force_quit: inner.stage == QuitStage::AwaitingChoice,
            detail: inner.detail.clone().or_else(|| inner.extra_detail.clone()),
        }
    }
}

static COORDINATOR: OnceLock<Arc<QuitCoordinator<SystemClock>>> = OnceLock::new();

/// Process-wide production coordinator.
pub fn coordinator() -> Arc<QuitCoordinator<SystemClock>> {
    Arc::clone(
        COORDINATOR.get_or_init(|| Arc::new(QuitCoordinator::new(SystemClock, DEFAULT_QUIT_GRACE))),
    )
}

/// Requests an explicit quit through the production flow.
///
/// This is called by the `quit_app` command, the `--quit-test` launcher, and a
/// user-initiated `ExitRequested` event. Repeated requests join the running
/// flow instead of starting a second one.
pub fn request_quit(app: &AppHandle) -> QuitSnapshot {
    let coordinator = coordinator();
    let Some(snapshot) = coordinator.begin_if_idle() else {
        return coordinator.snapshot();
    };
    show_main_window(app);

    let stop_handle = app.clone();
    let stop_coordinator = Arc::clone(&coordinator);
    std::thread::spawn(move || stop_worker(stop_handle, stop_coordinator));

    let monitor_handle = app.clone();
    let monitor_coordinator = Arc::clone(&coordinator);
    std::thread::spawn(move || monitor(monitor_handle, monitor_coordinator));

    snapshot
}

/// Applies one human choice. Force quit exits from this call path even when the
/// stop worker is blocked.
pub fn choose(app: &AppHandle, choice: QuitChoice) -> Result<QuitSnapshot, String> {
    let coordinator = coordinator();
    let snapshot = coordinator.choose(choice);
    if snapshot.stage() == QuitStage::ForceQuitting {
        let handle = app.clone();
        std::thread::spawn(move || force_quit(handle));
    }
    Ok(snapshot)
}

fn stop_worker(app: AppHandle, coordinator: Arc<QuitCoordinator<SystemClock>>) {
    let state = app.state::<AppState>();
    let (sync_failure, begin_failure, stop_result) = match state.host.lock() {
        Ok(mut host) => {
            let sync_failure = host
                .persist_connection_settings()
                .err()
                .map(|error| format!("connection settings were not saved: {error}"));
            let begin_failure = host
                .begin_shutdown()
                .err()
                .map(|error| format!("shutdown state was not saved: {error}"));
            // Even when the initial record could not be written, attempt the
            // coordinated stops so checkpoints that can be saved are saved.
            let stop_result = host.stop_all_for_shutdown();
            (sync_failure, begin_failure, stop_result)
        }
        Err(_) => (
            None,
            None,
            Err("the host lock was poisoned during quit".to_owned()),
        ),
    };

    let mut snapshot = match &stop_result {
        Ok(report) => {
            // Mark H2 supervision state with the real H1 stop facts before the
            // quit decision is evaluated. The hook never starts or resumes work.
            if let Ok(mut host) = state.host.lock()
                && let Err(error) = host.mark_supervision_for_quit(report)
            {
                eprintln!(
                    "QUIT_INCOMPLETE: pid={} supervision-mark-failed=true detail={error}",
                    std::process::id()
                );
            }
            coordinator.note_stopped(report.clone())
        }
        Err(error) => coordinator.note_failed(error.clone()),
    };
    if let Some(error) = begin_failure {
        snapshot = coordinator.note_save_failure(error);
    }
    if let Some(error) = sync_failure {
        snapshot = coordinator.note_save_failure(error);
    }

    if snapshot.stage() == QuitStage::Finished {
        let finish_error = match state.host.lock() {
            Ok(mut host) => host.finish_shutdown().err(),
            Err(_) => Some("the host lock was poisoned while finishing quit".to_owned()),
        };
        if finish_error.is_some() {
            eprintln!(
                "QUIT_INCOMPLETE: pid={} finish-save-failed=true",
                std::process::id()
            );
            app.exit(EXIT_QUIT_INCOMPLETE);
        } else if snapshot.save_succeeded() {
            println!(
                "QUIT_OK: pid={} save=confirmed stop=confirmed",
                std::process::id()
            );
            app.exit(EXIT_QUIT_COMPLETE);
        } else {
            eprintln!(
                "QUIT_INCOMPLETE: pid={} save=unconfirmed stop=unconfirmed runs={:?}",
                std::process::id(),
                snapshot.unconfirmed_runs()
            );
            app.exit(EXIT_QUIT_INCOMPLETE);
        }
    }
}

fn monitor(app: AppHandle, coordinator: Arc<QuitCoordinator<SystemClock>>) {
    let mut shown = false;
    loop {
        let snapshot = coordinator.snapshot();
        match snapshot.stage() {
            QuitStage::AwaitingChoice => {
                if !shown {
                    show_main_window(&app);
                    shown = true;
                }
            }
            QuitStage::Finished
            | QuitStage::ForceQuitting
            | QuitStage::Idle
            | QuitStage::Failed => return,
            QuitStage::Stopping => {}
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn force_quit(app: AppHandle) {
    let state = app.state::<AppState>();
    let deadline = Instant::now() + Duration::from_millis(300);
    loop {
        match state.host.try_lock() {
            Ok(mut host) => {
                let _ = host.force_shutdown();
                break;
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                let _ = poisoned.into_inner().force_shutdown();
                break;
            }
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(TryLockError::WouldBlock) => break,
        }
    }
    eprintln!(
        "QUIT_FORCED: pid={} save=unconfirmed stop=unconfirmed",
        std::process::id()
    );
    app.exit(EXIT_QUIT_FORCED);
}

/// Shows and focuses the trusted main window.
pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(guard::MAIN_LABEL) {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use herness_core::runtime::{ShutdownReport, ShutdownRun};
    use herness_core::{ProjectId, RunId, RunState};

    use super::*;

    #[derive(Clone, Default)]
    struct ManualClock {
        millis: Arc<AtomicU64>,
    }

    impl ManualClock {
        fn advance(&self, millis: u64) {
            self.millis.fetch_add(millis, Ordering::SeqCst);
        }
    }

    impl QuitClock for ManualClock {
        fn now_millis(&self) -> u64 {
            self.millis.load(Ordering::SeqCst)
        }
    }

    fn report(runs: &[(RunId, RunState)], checkpoint_saved: bool) -> ShutdownReport {
        let project = ProjectId::new();
        let runs = runs
            .iter()
            .map(|(run, state)| {
                ShutdownRun::new(
                    project,
                    *run,
                    *state,
                    Some(if *state == RunState::Paused {
                        herness_core::StopReport::Stopped
                    } else {
                        herness_core::StopReport::Unconfirmed
                    }),
                    checkpoint_saved,
                    None,
                )
            })
            .collect::<Vec<_>>();
        let unconfirmed = runs
            .iter()
            .filter(|run| run.report() == Some(herness_core::StopReport::Unconfirmed))
            .map(ShutdownRun::run_id)
            .collect::<Vec<_>>();
        let remaining = runs
            .iter()
            .filter(|run| run.state().is_active())
            .map(ShutdownRun::run_id)
            .collect::<Vec<_>>();
        ShutdownReport::new(
            if remaining.is_empty() && unconfirmed.is_empty() && checkpoint_saved {
                herness_core::runtime::ShutdownOutcome::Completed
            } else if remaining.is_empty() {
                herness_core::runtime::ShutdownOutcome::CompletedWithUnconfirmed
            } else {
                herness_core::runtime::ShutdownOutcome::InProgress
            },
            runs,
            unconfirmed,
            remaining,
            2,
            if checkpoint_saved { 0 } else { 1 },
        )
    }

    #[test]
    fn default_grace_is_ten_seconds_and_never_force_quits_silently() {
        assert_eq!(DEFAULT_QUIT_GRACE, Duration::from_secs(10));
        let clock = ManualClock::default();
        let coordinator = QuitCoordinator::new(clock, Duration::from_millis(100));
        let started = coordinator.begin_if_idle().expect("quit begins");
        assert_eq!(started.stage(), QuitStage::Stopping);
        assert_eq!(started.grace_ms(), 100);
        assert!(started.remaining_ms().unwrap() <= 100);
        // Starting twice joins the same flow instead of resetting the deadline.
        assert!(coordinator.begin_if_idle().is_none());
    }

    #[test]
    fn keep_waiting_extends_the_grace_and_force_quit_is_explicit() {
        let clock = ManualClock::default();
        let coordinator = QuitCoordinator::new(clock.clone(), Duration::from_millis(100));
        coordinator.begin_if_idle().expect("quit begins");

        clock.advance(99);
        assert_eq!(coordinator.snapshot().stage(), QuitStage::Stopping);
        clock.advance(1);
        let waiting = coordinator.snapshot();
        assert_eq!(waiting.stage(), QuitStage::AwaitingChoice);
        assert!(waiting.can_keep_waiting());
        assert!(waiting.can_force_quit());
        assert!(!waiting.save_succeeded());

        // Keep waiting starts a fresh grace; it does not silently force quit.
        let kept = coordinator.choose(QuitChoice::KeepWaiting);
        assert_eq!(kept.stage(), QuitStage::Stopping);
        assert!(kept.remaining_ms().unwrap() > 0);
        clock.advance(100);
        assert_eq!(coordinator.snapshot().stage(), QuitStage::AwaitingChoice);

        let forced = coordinator.choose(QuitChoice::ForceQuit);
        assert_eq!(forced.stage(), QuitStage::ForceQuitting);
        assert!(!forced.save_succeeded());
        assert!(!forced.can_force_quit());
    }

    #[test]
    fn finished_stops_never_claim_success_after_an_unconfirmed_stop() {
        let clock = ManualClock::default();
        let coordinator = QuitCoordinator::new(clock, Duration::from_secs(10));
        coordinator.begin_if_idle().expect("quit begins");
        let project = ProjectId::new();
        let run = RunId::new(project);
        let stopped = coordinator.note_stopped(report(&[(run, RunState::Interrupted)], true));
        assert_eq!(stopped.stage(), QuitStage::Finished);
        assert!(!stopped.save_succeeded());
        assert_eq!(stopped.unconfirmed_runs(), &[run]);
    }

    #[test]
    fn a_saved_stop_reports_success_and_an_incomplete_stop_requires_force() {
        let clock = ManualClock::default();
        let coordinator = QuitCoordinator::new(clock, Duration::from_secs(10));
        coordinator.begin_if_idle().expect("quit begins");
        let project = ProjectId::new();
        let paused = RunId::new(project);
        let stopped = coordinator.note_stopped(report(&[(paused, RunState::Paused)], true));
        assert_eq!(stopped.stage(), QuitStage::Finished);
        assert!(stopped.save_succeeded());
        assert_eq!(stopped.discarded_deferred_messages(), 2);

        let clock = ManualClock::default();
        let coordinator = QuitCoordinator::new(clock, Duration::from_secs(10));
        coordinator.begin_if_idle().expect("quit begins");
        let running = RunId::new(project);
        let incomplete = coordinator.note_stopped(report(&[(running, RunState::Running)], false));
        assert_eq!(incomplete.stage(), QuitStage::AwaitingChoice);
        assert!(!incomplete.can_keep_waiting());
        assert!(incomplete.can_force_quit());
        assert_eq!(incomplete.remaining_runs(), &[running]);
    }

    #[test]
    fn failed_stop_requires_force_quit() {
        let clock = ManualClock::default();
        let coordinator = QuitCoordinator::new(clock, Duration::from_secs(10));
        coordinator.begin_if_idle().expect("quit begins");
        let failed = coordinator.note_failed("store unavailable");
        assert_eq!(failed.stage(), QuitStage::AwaitingChoice);
        assert!(!failed.can_keep_waiting());
        assert!(failed.can_force_quit());
        assert_eq!(failed.detail(), Some("store unavailable"));
    }

    #[test]
    fn a_secondary_save_failure_prevents_a_success_claim_without_a_prompt() {
        let clock = ManualClock::default();
        let coordinator = QuitCoordinator::new(clock, Duration::from_secs(10));
        coordinator.begin_if_idle().expect("quit begins");
        let project = ProjectId::new();
        let paused = RunId::new(project);
        coordinator.note_stopped(report(&[(paused, RunState::Paused)], true));
        let snapshot = coordinator.note_save_failure("connection settings were not saved");
        assert_eq!(snapshot.stage(), QuitStage::Finished);
        assert!(!snapshot.save_succeeded());
        assert_eq!(
            snapshot.detail(),
            Some("connection settings were not saved")
        );
    }
}
