//! Desktop plan-change detection: the watched plan path, the 1 s reconcile
//! clock, the durable latch over the real store, and the queued child stop.
//!
//! # Wiring
//!
//! | Piece | Real implementation |
//! | --- | --- |
//! | plan source | [`PlanFileSource`] over the canonical project root |
//! | latch store | [`LatchStore`] over the shared `StoreHandle` |
//! | clock | [`PlanReconcileClock`] (`Timestamp::now`) |
//! | notifications | [`PlanFileWatcher`] (`notify`, pinned in this crate) |
//! | child stop | [`QueuedChildStop`], drained by the host pump |
//!
//! # Why the notification is not the guard
//!
//! `notify` is only a latency optimization. The gate also runs once per
//! [`PLAN_RECONCILE_INTERVAL_MILLIS`] and again before every side effect, so a
//! dropped, coalesced, or missed watcher event cannot hide a changed plan. A
//! watcher failure is reported through [`PlanWatchNotice::Failure`] and the host
//! keeps the periodic path running; [`PlanFileWatcher::restart`] rebuilds it.
//!
//! # What it never does
//!
//! It does not read or write the plan, start a model request, or touch Git. The
//! watcher watches one directory entry; the source performs the confined read;
//! the store owns the durable latch row.

use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use herness_core::contracts::{ProjectId, Timestamp};
use herness_sdd_execute::{
    ChildStopPort, ClockPort, ExecutionId, FailureDetails, PlanChangeGate, PlanChangeGatePort,
    PlanChangeLatch, PlanChangeLatchStorePort, PlanExpectation, PlanGateDecision, PlanPath,
    ReconcileSchedule, SddExecutionError, TaskRef,
};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::sdd_execute::source::PlanFileSource;
use crate::supervision::store::StoreHandle;

// ---------------------------------------------------------------------------
// Watched path
// ---------------------------------------------------------------------------

/// One notice delivered by the plan watcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanWatchNotice {
    /// The watched plan path changed, disappeared, or appeared.
    Changed,
    /// The operating-system watcher reported an error or could not be started.
    Failure,
}

/// Why the plan watcher could not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanWatchError {
    /// The project root was missing, not a directory, or not canonical.
    InvalidRoot {
        /// Sanitized detail.
        detail: String,
    },
    /// The watched directory could not be observed.
    WatchFailed {
        /// Sanitized detail.
        detail: String,
    },
}

impl std::fmt::Display for PlanWatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRoot { detail } => write!(formatter, "invalid project root: {detail}"),
            Self::WatchFailed { detail } => {
                write!(formatter, "plan watcher unavailable: {detail}")
            }
        }
    }
}

impl std::error::Error for PlanWatchError {}

/// One watcher over the exact approved plan path.
///
/// It watches the plan's parent directory non-recursively and reports only that
/// one file name. Watching the directory instead of the file means an atomic
/// save (`write temp` + `rename`), which replaces the directory entry, is still
/// observed.
pub struct PlanFileWatcher {
    root: PathBuf,
    plan_path: PathBuf,
    directory: PathBuf,
    sender: Sender<PlanWatchNotice>,
    watcher: Option<RecommendedWatcher>,
}

impl PlanFileWatcher {
    /// Starts watching one plan path below a canonical project root.
    pub fn start(
        project_root: impl AsRef<Path>,
        plan_path: &PlanPath,
        sender: Sender<PlanWatchNotice>,
    ) -> Result<Self, PlanWatchError> {
        let root = canonical_root(project_root.as_ref())?;
        let relative = Path::new(plan_path.as_str());
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(PlanWatchError::InvalidRoot {
                detail: "the plan path must be a normalized relative path".to_owned(),
            });
        }
        let directory = root
            .join(relative)
            .parent()
            .map_or_else(|| root.clone(), Path::to_path_buf);
        let mut watcher = Self {
            root: root.clone(),
            plan_path: root.join(relative),
            directory,
            sender,
            watcher: None,
        };
        watcher.install()?;
        Ok(watcher)
    }

    /// Canonical project root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Absolute watched plan path.
    pub fn plan_path(&self) -> &Path {
        &self.plan_path
    }

    /// Whether a watcher is currently installed.
    pub const fn is_watching(&self) -> bool {
        self.watcher.is_some()
    }

    /// Rebuilds the watcher after an operating-system failure.
    ///
    /// A successful restart is followed by the caller's periodic reconciliation;
    /// the restart itself claims no observation.
    pub fn restart(&mut self) -> Result<(), PlanWatchError> {
        self.watcher = None;
        self.install()
    }

    /// Stops the watcher explicitly.
    pub fn stop(&mut self) {
        self.watcher = None;
    }

    fn install(&mut self) -> Result<(), PlanWatchError> {
        let plan_path = self.plan_path.clone();
        let sender = self.sender.clone();
        let mut watcher = RecommendedWatcher::new(
            move |result: notify::Result<Event>| match result {
                Ok(event) => {
                    if matches!(event.kind, EventKind::Access(_)) {
                        return;
                    }
                    if event.paths.iter().any(|path| path == &plan_path) {
                        let _ = sender.send(PlanWatchNotice::Changed);
                    }
                }
                Err(_) => {
                    let _ = sender.send(PlanWatchNotice::Failure);
                }
            },
            Config::default(),
        )
        .map_err(|error| PlanWatchError::WatchFailed {
            detail: error.to_string(),
        })?;
        watcher
            .watch(&self.directory, RecursiveMode::NonRecursive)
            .map_err(|error| PlanWatchError::WatchFailed {
                detail: error.to_string(),
            })?;
        self.watcher = Some(watcher);
        Ok(())
    }
}

fn canonical_root(root: &Path) -> Result<PathBuf, PlanWatchError> {
    if !root.is_absolute() {
        return Err(PlanWatchError::InvalidRoot {
            detail: "the project root must be an absolute path".to_owned(),
        });
    }
    let canonical = std::fs::canonicalize(root).map_err(|error| PlanWatchError::InvalidRoot {
        detail: error.to_string(),
    })?;
    if !canonical.is_dir() {
        return Err(PlanWatchError::InvalidRoot {
            detail: "the project root must be a directory".to_owned(),
        });
    }
    Ok(canonical)
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// The wall clock the periodic plan reconciliation reads.
///
/// Tests inject their own `ClockPort`; this is the production value.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlanReconcileClock;

impl ClockPort for PlanReconcileClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

// ---------------------------------------------------------------------------
// Latch store over the shared SQLite store
// ---------------------------------------------------------------------------

/// The [`PlanChangeLatchStorePort`] view over the shared store handle.
#[derive(Clone)]
pub struct LatchStore {
    store: StoreHandle,
}

impl std::fmt::Debug for LatchStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LatchStore")
    }
}

impl LatchStore {
    /// Creates a latch store over the shared handle.
    pub const fn new(store: StoreHandle) -> Self {
        Self { store }
    }

    /// The shared store handle.
    pub const fn store(&self) -> &StoreHandle {
        &self.store
    }
}

impl PlanChangeLatchStorePort for LatchStore {
    fn plan_change_latch(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<PlanChangeLatch>, SddExecutionError> {
        self.store
            .lock()
            .sdd_plan_change_latch(project_id, execution_id)
            .map_err(|error| SddExecutionError::Unavailable {
                feature: format!("h4.planChangeLatch: {error}"),
                details: FailureDetails::none().boxed(),
            })
    }

    fn record_plan_change_latch(
        &mut self,
        latch: &PlanChangeLatch,
    ) -> Result<(), SddExecutionError> {
        self.store
            .lock()
            .record_sdd_plan_change_latch(latch)
            .map_err(SddExecutionError::from)
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// The production plan-change gate over one project's plan file and store.
pub struct DesktopPlanChangeGate {
    gate: PlanChangeGate<PlanFileSource, LatchStore, PlanReconcileClock>,
}

impl DesktopPlanChangeGate {
    /// Creates the gate for one canonical project root and plan path.
    pub fn new(
        project_id: ProjectId,
        project_root: impl AsRef<Path>,
        store: StoreHandle,
    ) -> Result<Self, SddExecutionError> {
        let source = PlanFileSource::new(project_id, project_root)?;
        Ok(Self {
            gate: PlanChangeGate::new(source, LatchStore::new(store), PlanReconcileClock),
        })
    }

    /// Notes one host-observed candidate path a moved plan may now live at.
    pub fn note_candidate(&mut self, path: PlanPath) {
        self.gate.note_candidate(path);
    }

    /// Notes a watcher notification, which makes the next tick immediate.
    ///
    /// The notification never replaces the periodic check: the next
    /// [`Self::tick`] still runs because the schedule marked it due.
    pub fn note_signal(&mut self) {
        self.gate.schedule_mut().note_signal();
    }

    /// Runs the periodic reconciliation when it is due.
    ///
    /// `None` means "not due yet"; the caller ticks again after
    /// [`herness_sdd_execute::PLAN_RECONCILE_INTERVAL_MILLIS`]. The host calls
    /// this even when no window is open and even after a watcher failure, so
    /// notification loss is tolerated.
    pub fn tick(
        &mut self,
        execution_id: ExecutionId,
        approval_id: herness_sdd_execute::ApprovalId,
        approval: &herness_sdd_execute::PlanApproval,
    ) -> Result<Option<PlanGateDecision>, SddExecutionError> {
        let now = PlanReconcileClock.now();
        self.gate
            .reconcile(now, execution_id, approval_id, approval)
    }

    /// The gate itself.
    pub const fn gate(&self) -> &PlanChangeGate<PlanFileSource, LatchStore, PlanReconcileClock> {
        &self.gate
    }

    /// The mutable gate, for a pre-side-effect check.
    pub const fn gate_mut(
        &mut self,
    ) -> &mut PlanChangeGate<PlanFileSource, LatchStore, PlanReconcileClock> {
        &mut self.gate
    }

    /// The stored latch of one execution.
    pub fn latch(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<PlanChangeLatch>, SddExecutionError> {
        self.gate.latch(project_id, execution_id)
    }

    /// The approved identity one execution compares against.
    pub fn expectation(approval: &herness_sdd_execute::PlanApproval) -> PlanExpectation {
        PlanExpectation::new(
            approval.plan_path().clone(),
            approval.digest().clone(),
            approval.byte_length(),
            approval.plan_revision(),
        )
    }
}

impl PlanChangeGatePort for DesktopPlanChangeGate {
    fn check_before_side_effect(
        &mut self,
        execution_id: ExecutionId,
        approval_id: herness_sdd_execute::ApprovalId,
        approval: &herness_sdd_execute::PlanApproval,
    ) -> Result<PlanGateDecision, SddExecutionError> {
        self.gate
            .check_before_side_effect(execution_id, approval_id, approval)
    }
}

// ---------------------------------------------------------------------------
// Child stop queue
// ---------------------------------------------------------------------------

/// One requested cooperative child stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildStopRequest {
    project_id: ProjectId,
    execution_id: ExecutionId,
    task: Option<TaskRef>,
}

impl ChildStopRequest {
    /// Project that owns the child.
    pub const fn project_id(self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    /// Current Task, when one was active.
    pub const fn task(self) -> Option<TaskRef> {
        self.task
    }
}

/// A child-stop port that queues the request for the host pump.
///
/// The coordinator writes the durable plan-change stop first and then calls the
/// port, so a crash between the two leaves a recorded stop instead of an
/// unrecorded signal. The queue is in memory on purpose: a restart re-reads the
/// durable latch and the host asks H2/H1 to stop before any resume, so the queue
/// never needs to survive a process.
#[derive(Debug, Clone, Default)]
pub struct QueuedChildStop {
    queue: Arc<Mutex<VecDeque<ChildStopRequest>>>,
}

impl QueuedChildStop {
    /// Creates an empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drains the queued stop requests in order.
    pub fn drain(&self) -> Vec<ChildStopRequest> {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queue.drain(..).collect()
    }

    /// Number of queued requests.
    pub fn len(&self) -> usize {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ChildStopPort for QueuedChildStop {
    fn request_stop(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        task: Option<TaskRef>,
    ) -> Result<(), SddExecutionError> {
        execution_id.validate_in(project_id)?;
        if let Some(task) = task {
            task.ensure_project(project_id)?;
        }
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push_back(ChildStopRequest {
                project_id,
                execution_id,
                task,
            });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Wiring into the coordinator
// ---------------------------------------------------------------------------

/// The two ports one advance needs for plan changes, owned together.
///
/// The fields are public and separate so a caller can pass
/// `Some(&mut wiring.gate)` and `Some(&mut wiring.child_stop)` in the same
/// [`herness_sdd_execute::CoordinatorPorts`]; two disjoint field borrows are
/// accepted where two `&mut self` method calls would not be.
pub struct PlanChangeWiring {
    /// The pre-side-effect and periodic gate.
    pub gate: DesktopPlanChangeGate,
    /// The cooperative child-stop queue the host pump drains.
    pub child_stop: QueuedChildStop,
}

impl PlanChangeWiring {
    /// Wires one project's plan file, the shared store, and one stop queue.
    pub fn new(
        project_id: ProjectId,
        project_root: impl AsRef<Path>,
        store: StoreHandle,
    ) -> Result<Self, SddExecutionError> {
        Ok(Self {
            gate: DesktopPlanChangeGate::new(project_id, project_root, store)?,
            child_stop: QueuedChildStop::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Reconcile schedule helper
// ---------------------------------------------------------------------------

/// The fixed production schedule, exposed so the host names one value.
pub fn reconcile_schedule() -> ReconcileSchedule {
    ReconcileSchedule::new()
}
