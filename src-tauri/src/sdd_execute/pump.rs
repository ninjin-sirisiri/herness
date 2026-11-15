//! The app-lifetime H4 execution pump.
//!
//! The trusted desktop shell runs one pump for the whole process, independent
//! of any window or selected project. This module is that pump: it reads the
//! durable H4 executions, advances at most the one that may hold the app-wide
//! implementer slot, and never starts a second implementer.
//!
//! # What one pump does
//!
//! 1. If the runtime is shutting down, it does nothing at all.
//! 2. It rebuilds the exact approved context of one execution from the durable
//!    approval and the checkout: the approval draft, the verified spec sections,
//!    and the one Task lane (HTML barrier + host commit).
//! 3. It calls [`TaskCoordinator::advance`] once with the real H2 dispatch, the
//!    stored H2 status, the pre-side-effect plan-change gate, and the real
//!    completion seam.
//! 4. It drains the cooperative child-stop queue the plan-change gate produced.
//!
//! Rebuilding the context is read-only: the approval stores the exact plan
//! bytes, and the spec sections are re-read and verified against the approved
//! digest before a packet is assembled. No plan preview, model request, or Git
//! write happens while rebuilding.
//!
//! # What it never does
//!
//! It never pushes, pulls, merges, rebases, amends, resets, cleans, or checks
//! out a change. It creates no child for an execution that does not hold the
//! serial slot, and it performs no work while the runtime is shutting down.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use herness_core::contracts::{ProjectId, Timestamp};
use herness_core::{
    AbsolutePath, HostGitActor, HostGitBoundary, HostGitGate, ProcessSupervisor,
    RecordingHostGitAudit, SystemArgvLauncher,
};
use herness_sdd_execute::import::PreviewSpecRef;
use herness_sdd_execute::{
    ApprovalRequirement, ChildDispatchPlan, ChildDispatchPort, ChildStatus, ChildStatusPort,
    CompletionWiring, ControlRequestId, CoordinatorOutcome, CoordinatorPorts, CoordinatorRequest,
    DispatchRequestId, DispatchResult, DurableExecutionStorePort, ExecutionApproval, ExecutionId,
    ExecutionRevision, ExecutionSnapshot, ExecutionState, ExecutionStorePort, FailureDetails,
    SddExecutionError, SerialExecutionState, SnapshotSections, TaskCompletion,
    TaskCompletionRequest, TaskCoordinator, TaskProgression, TaskRef, TaskSnapshot,
    completion_wiring,
};
use herness_store::Store;

use crate::host::DesktopRuntime;
use crate::sdd_execute::barrier::{
    DesktopH4BarrierGate, HostCommitCompletion, SharedBarrierGate, VerifiedDocumentSource,
    shared_gate, shared_readiness_port,
};
use crate::sdd_execute::coordinator::{
    ApprovedTaskLaunch, child_status_from_view, dispatch_h2_task, reconcile_h2_task,
};
use crate::sdd_execute::crash::{self, CrashPoint};
use crate::sdd_execute::finalize::{
    ApprovedCommitIdentity, GitCheckoutObserver, HostGitCommitBoundary,
};
use crate::sdd_execute::git::GitRunner;
use crate::sdd_execute::host_commit::{DesktopHostCommit, TaskCommitExpectation};
use crate::sdd_execute::ledger::write_compatibility_ledger;
use crate::sdd_execute::plan_changes::{ChildStopRequest, PlanChangeWiring};
use crate::sdd_execute::registry::{ApprovalDraft, H4StartApprovalRegistry};
use crate::sdd_execute::source::read_and_verify_specs;
use crate::supervision::runtime::DesktopH1;
use crate::supervision::store::StoreHandle;
use crate::supervision::{ConfirmationKind, SupervisionHost};

/// The fixed argv gate the approved host commit runs.
///
/// It is the pack's common staged-HTML validation, executed as its own process
/// with the approved checkout as cwd. A missing script is an explicit
/// `host_git` capability error, never a silently skipped gate.
const COMMON_GATE_SCRIPT: &str = "scripts/sdd-html-pre-commit";

/// What one pump pass examined and did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SddPumpReport {
    /// No work ran because the runtime is shutting down.
    pub skipped: bool,
    /// Executions whose stored state was eligible for an advance.
    pub examined: u64,
    /// Advances that returned a progress outcome.
    pub advanced: u64,
    /// Tasks dispatched (or reconciled from one reservation).
    pub dispatched: u64,
    /// Advances that observed a still-working child.
    pub awaiting: u64,
    /// Tasks that completed through the host commit.
    pub completed: u64,
    /// Executions that stopped or need a human.
    pub stopped: u64,
    /// Executions that reached `ready_for_finish`.
    pub ready_for_finish: u64,
    /// Errors observed while rebuilding or advancing. A refusal is recorded here
    /// instead of being reported as progress.
    pub errors: Vec<String>,
    /// Cooperative child stops requested after a plan change.
    pub child_stops: u64,
}

/// The app-lifetime H4 state the pump keeps across ticks.
///
/// The serial slot and checkout claims live here so one implementer limit holds
/// across pump calls; the Task lanes keep the pre-Task HTML baseline and the
/// bound commit half for the whole Task, so the final barrier compares the same
/// observed bytes the child started from.
#[derive(Default)]
pub struct SddExecuteState {
    serial: SerialExecutionState,
    lanes: BTreeMap<(ProjectId, ExecutionId), TaskLane>,
    test_gate: Option<HostGitGate>,
}

impl SddExecuteState {
    /// Creates empty pump state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the common staged-document gate for a test composition.
    ///
    /// The production pump always runs the approved pack's
    /// `scripts/sdd-html-pre-commit`; this seam exists only so the cross-phase
    /// target can run the same validation without mutating the process
    /// environment. Nothing in the desktop shell or an IPC command reaches it.
    #[doc(hidden)]
    pub fn set_test_commit_gate(&mut self, gate: HostGitGate) {
        self.test_gate = Some(gate);
    }

    /// The test gate override, when one was installed.
    #[doc(hidden)]
    pub fn test_gate(&self) -> Option<HostGitGate> {
        self.test_gate.clone()
    }

    /// Releases the serial slot and the checkout claims of one execution.
    pub fn release(&mut self, execution: ExecutionId) {
        self.serial.release_slot(execution);
        self.serial.release_checkout(execution);
        self.lanes
            .retain(|(_, candidate), _| *candidate != execution);
    }
}

struct TaskLane {
    task: TaskRef,
    barrier: SharedBarrierGate,
    commit: DesktopHostCommit<HostGitCommitBoundary>,
}

/// The disjoint host borrows one pump pass needs.
pub struct SddPumpContext<'a> {
    /// The one desktop runtime.
    pub runtime: &'a mut DesktopRuntime,
    /// The one supervision host.
    pub supervision: &'a mut SupervisionHost,
    /// The one shared SQLite store.
    pub store: &'a Arc<Mutex<Store>>,
    /// Approved Common SDD pack root, when configured.
    pub pack_root: Option<PathBuf>,
    /// Whether the runtime already began an explicit shutdown.
    pub shutting_down: bool,
    /// A test-only gate override. Production leaves this `None` and the
    /// approved pack's common gate runs.
    pub test_gate: Option<HostGitGate>,
}

/// Runs one pump pass.
///
/// The pass advances at most the execution that holds the serial slot. Every
/// other eligible execution is left untouched until that one completes or
/// stops, so the app-wide one-implementer rule is enforced even when several
/// approved plans are restored.
fn lock_store(store: &Arc<Mutex<Store>>) -> std::sync::MutexGuard<'_, Store> {
    store
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs one pump pass over the durable H4 executions.
///
/// The caller supplies the disjoint host borrows; the state keeps the serial
/// slot and the Task lanes across passes.
pub fn run(state: &mut SddExecuteState, context: &mut SddPumpContext<'_>) -> SddPumpReport {
    let mut report = SddPumpReport::default();
    if context.shutting_down {
        report.skipped = true;
        return report;
    }
    let executions = match lock_store(context.store).sdd_stored_executions() {
        Ok(executions) => executions,
        Err(error) => {
            report
                .errors
                .push(format!("stored executions are unreadable: {error}"));
            return report;
        }
    };
    // A holder whose execution is gone or terminal no longer blocks the slot.
    if let Some(holder) = state.serial.holder() {
        let alive = executions.iter().any(|stored| {
            stored.snapshot().execution_id() == holder && pump_eligible(stored.snapshot().state())
        });
        if !alive {
            state.release(holder);
        }
    }
    for stored in &executions {
        let snapshot = stored.snapshot();
        if !pump_eligible(snapshot.state()) {
            continue;
        }
        if let Some(holder) = state.serial.holder()
            && holder != snapshot.execution_id()
        {
            continue;
        }
        report.examined += 1;
        match advance_one(state, context, stored) {
            Ok(outcome) => {
                report.advanced += 1;
                // A completion writes the compatibility ledger. A restarted
                // `ready_for_finish` execution is terminal, so the coordinator
                // reports `Finished`; its ledger intent may still be unresolved
                // from a crash and must be reconciled before the restart is
                // treated as complete.
                let completed = match &outcome {
                    CoordinatorOutcome::TaskCompleted { .. }
                    | CoordinatorOutcome::ReadyForFinish { .. } => true,
                    CoordinatorOutcome::Finished { state } => {
                        *state == ExecutionState::ReadyForFinish
                    }
                    _ => false,
                };
                match outcome {
                    CoordinatorOutcome::Dispatched { .. } => report.dispatched += 1,
                    CoordinatorOutcome::AwaitingChild { .. } => report.awaiting += 1,
                    CoordinatorOutcome::TaskCompleted { .. } => report.completed += 1,
                    CoordinatorOutcome::Stopped { .. }
                    | CoordinatorOutcome::BudgetRefused { .. }
                    | CoordinatorOutcome::CompletionNotConnected { .. }
                    | CoordinatorOutcome::PlanChanged { .. } => report.stopped += 1,
                    CoordinatorOutcome::ReadyForFinish { .. } => {
                        report.ready_for_finish += 1;
                        state.release(snapshot.execution_id());
                    }
                    CoordinatorOutcome::Busy { .. }
                    | CoordinatorOutcome::Replayed { .. }
                    | CoordinatorOutcome::Finished { .. } => {}
                }
                if completed {
                    // The compatibility ledger is written after the durable
                    // completion and before the next Task may be dispatched. A
                    // failure, an external edit, or an unconfirmed result holds
                    // the execution in `waiting_human` instead of advancing.
                    write_ledger_after_completion(context, snapshot, &mut report);
                }
            }
            Err(error) => report
                .errors
                .push(format!("{}: {error}", snapshot.execution_id())),
        }
    }
    report
}

/// Writes the compatibility ledger for a just-completed Task.
///
/// The current snapshot is re-read from the store so the document reflects the
/// durable completion (the Task's range included). A hold is not reported as
/// progress: it is recorded as an error line and the execution is already
/// `waiting_human`, so the next pass cannot dispatch another Task.
fn write_ledger_after_completion(
    context: &SddPumpContext<'_>,
    snapshot: &ExecutionSnapshot,
    report: &mut SddPumpReport,
) {
    let project = snapshot.project_id();
    let execution = snapshot.execution_id();
    let current = match lock_store(context.store).load_sdd_execution(project, execution) {
        Ok(Some(stored)) => stored.snapshot().clone(),
        Ok(None) => {
            report
                .errors
                .push(format!("{execution}: the completion snapshot is gone"));
            return;
        }
        Err(error) => {
            report.errors.push(format!(
                "{execution}: the completion snapshot is unreadable: {error}"
            ));
            return;
        }
    };
    match write_compatibility_ledger(StoreHandle::new(Arc::clone(context.store)), &current) {
        Ok(result) if result.held() => {
            report.stopped += 1;
            report.errors.push(format!(
                "{execution}: the compatibility ledger held the next Task: {}",
                result.detail().unwrap_or("the write was not confirmed")
            ));
        }
        Ok(_) => {}
        Err(error) => report.errors.push(format!(
            "{execution}: the compatibility ledger failed: {error}"
        )),
    }
}

/// A state the pump may advance. Waiting/stopped/terminal states need a human.
///
/// `committing` is deliberately excluded. Within one process the coordinator
/// writes that state and completes synchronously, so the pump never observes it
/// between passes. A stored `committing` therefore means the previous process
/// died at the host-commit boundary: the saved intent/result must be reconciled
/// by a human resume, and the pump must never re-enter a commit for it.
const fn pump_eligible(state: ExecutionState) -> bool {
    matches!(
        state,
        ExecutionState::Ready
            | ExecutionState::Running
            | ExecutionState::WaitingHtml
            | ExecutionState::Verifying
            | ExecutionState::ReadyForFinish
    )
}

fn advance_one(
    state: &mut SddExecuteState,
    context: &mut SddPumpContext<'_>,
    stored: &herness_sdd_execute::StoredExecution,
) -> Result<CoordinatorOutcome, String> {
    let snapshot = stored.snapshot().clone();
    let project = snapshot.project_id();
    let execution = snapshot.execution_id();
    let approval = bound_approval(&mut lock_store(context.store), &snapshot)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            SddExecutionError::ApprovalRequired {
                reason: ApprovalRequirement::StartApproval,
                details: FailureDetails::none().boxed(),
            }
            .to_string()
        })?;
    if approval.revision() == 0 {
        return Err("the stored approval revision is invalid".to_owned());
    }
    let draft =
        ApprovalDraft::from_approval(execution, &approval).map_err(|error| error.to_string())?;
    let sections = approved_snapshot_sections(&approval).map_err(|error| error.to_string())?;

    // The lane is fixed once per Task: the pre-Task capture must precede the
    // child, and the bound commit half must describe the same Task.
    let task = next_task(&snapshot);
    if let Some(task) = task {
        let recreate = state
            .lanes
            .get(&(project, execution))
            .is_none_or(|lane| lane.task != task);
        if recreate {
            let lane = build_lane(context, &approval, &snapshot, task)
                .map_err(|error| error.to_string())?;
            state.lanes.insert((project, execution), lane);
        }
    }
    if let Some(lane) = state.lanes.get(&(project, execution)) {
        let shared: SharedBarrierGate = Arc::clone(&lane.barrier);
        context
            .supervision
            .set_readiness_port(Some(Box::new(shared_readiness_port(shared))));
    }

    let mut wiring = PlanChangeWiring::new(
        project,
        snapshot.workspace().canonical_checkout_root(),
        StoreHandle::new(Arc::clone(context.store)),
    )
    .map_err(|error| error.to_string())?;

    let mut registry = H4StartApprovalRegistry::new();
    registry.set_current(&draft, &approval);

    let empty_handoffs: Vec<herness_sdd_execute::TaskHandoff> = Vec::new();
    let mut launch = ApprovedTaskLaunch::new(&approval, &sections, &empty_handoffs);
    let request = CoordinatorRequest::new(
        project,
        execution,
        pump_request_id(execution, stored.revision()),
        stored.revision(),
        approval.approval_id(),
        approval.revision(),
    )
    .map_err(|error| error.to_string())?;

    let plans = context.supervision.plans();
    let outcome = {
        let mut adapter = DesktopH1::new(
            context.runtime,
            StoreHandle::new(Arc::clone(context.store)),
            plans,
        );
        let cell: RefCell<&mut SupervisionHost> = RefCell::new(&mut *context.supervision);
        let mut dispatch = PumpDispatch {
            cell: &cell,
            runtime: &mut adapter,
            registry: &registry,
            draft: &draft,
            approval: &approval,
            sections: &sections,
            handoffs: &empty_handoffs,
        };
        let mut children = PumpChildren { cell: &cell };
        let mut store_port = SharedExecutionStore::new(StoreHandle::new(Arc::clone(context.store)));

        let mut lane = state.lanes.remove(&(project, execution));
        let mut completion: Box<dyn herness_sdd_execute::TaskCompletionPort> = match lane.as_mut() {
            Some(bound) => Box::new(LaneCompletion {
                gate: Arc::clone(&bound.barrier),
                commit: &mut bound.commit,
            }),
            None => Box::new(crate::sdd_execute::barrier::DesktopTaskCompletion::not_connected()),
        };
        let mut ports = CoordinatorPorts {
            store: &mut store_port,
            launch: &mut launch,
            dispatch: &mut dispatch,
            children: &mut children,
            completion: &mut *completion,
            serial: &mut state.serial,
            plan_change: Some(&mut wiring.gate),
            child_stop: Some(&mut wiring.child_stop),
        };
        let outcome = TaskCoordinator::advance(&mut ports, &request);
        drop(completion);
        if let Some(lane) = lane {
            // A completed or stopped Task no longer needs its lane; a working
            // Task keeps the same pre-Task baseline.
            let keep = matches!(
                outcome,
                Ok(CoordinatorOutcome::AwaitingChild { .. })
                    | Ok(CoordinatorOutcome::Replayed { .. })
            );
            if keep {
                state.lanes.insert((project, execution), lane);
            }
        }
        outcome
    };
    if !wiring.child_stop.is_empty() {
        for stop in wiring.child_stop.drain() {
            request_child_stop(context, stop);
        }
    }
    outcome.map_err(|error| error.to_string())
}

fn request_child_stop(context: &mut SddPumpContext<'_>, request: ChildStopRequest) {
    let Some(task) = request.task() else {
        return;
    };
    let dispatch = herness_sdd_execute::dispatch_request_id(request.execution_id(), task);
    let reservation = lock_store(context.store).sdd_task_reservation(
        request.project_id(),
        request.execution_id(),
        dispatch,
    );
    let Ok(Some(reservation)) = reservation else {
        return;
    };
    let Ok(view) = context
        .supervision
        .get(request.project_id(), reservation.supervision_id())
    else {
        return;
    };
    let Ok(operation) = herness_supervision::operations::SupervisionOperationRequest::new(
        herness_supervision::SupervisionRequestId::new(request.project_id()),
        reservation.supervision_id(),
        herness_supervision::operations::HumanOperation::Stop,
        view.revision,
    ) else {
        return;
    };
    // The durable H4 stop already exists; this is only the cooperative H2/H1
    // stop of the current child. It changes no H4 state.
    let confirmation = Some(context.supervision.confirm(ConfirmationKind::Stop));
    let policy_version = context.runtime.policy().version().get();
    let plans = context.supervision.plans();
    let mut adapter = DesktopH1::new(
        context.runtime,
        StoreHandle::new(Arc::clone(context.store)),
        plans,
    );
    let _ = context
        .supervision
        .stop(&mut adapter, operation, false, policy_version, confirmation);
}

fn next_task(snapshot: &ExecutionSnapshot) -> Option<TaskRef> {
    snapshot
        .tasks()
        .iter()
        .find(|task| task.progression() != TaskProgression::Complete)
        .map(TaskSnapshot::task)
}

/// The newest stored approval whose plan identity is the execution's.
fn bound_approval(
    store: &mut Store,
    snapshot: &ExecutionSnapshot,
) -> Result<Option<ExecutionApproval>, SddExecutionError> {
    let mut best: Option<ExecutionApproval> = None;
    for approval_id in store
        .sdd_approval_ids(snapshot.project_id())
        .map_err(SddExecutionError::from)?
    {
        let Some(approval) = store
            .latest_sdd_approval(snapshot.project_id(), approval_id)
            .map_err(SddExecutionError::from)?
        else {
            continue;
        };
        if approval.plan().digest() != snapshot.plan().digest()
            || approval.plan().plan_revision() != snapshot.plan().approved_revision()
        {
            continue;
        }
        match &best {
            Some(current) if current.revision() >= approval.revision() => {}
            _ => best = Some(approval),
        }
    }
    Ok(best)
}

/// Rebuilds the verified spec sections of one approval.
///
/// The bytes are read from the approved checkout or read-only source and
/// compared with the approved digest. A moved or changed spec is refused; the
/// packet never carries a section the human did not approve.
pub fn approved_snapshot_sections(
    approval: &ExecutionApproval,
) -> Result<SnapshotSections, SddExecutionError> {
    let plan = approval.plan();
    let layout = herness_sdd_execute::SourceLayout::from_approvals(
        approval.workspace().canonical_checkout_root(),
        plan.sources(),
    )?;
    let mut references = Vec::with_capacity(plan.spec_refs().len());
    for spec in plan.spec_refs() {
        references.push(PreviewSpecRef::new(
            spec.source(),
            spec.path(),
            spec.sections().to_vec(),
        )?);
    }
    let verified = read_and_verify_specs(&layout, &references)?;
    let mut sections = SnapshotSections::new();
    for snapshot in verified.snapshots() {
        let approved = plan
            .spec_refs()
            .iter()
            .find(|spec| spec.source() == snapshot.source() && spec.path() == snapshot.path())
            .ok_or_else(|| SddExecutionError::Unavailable {
                feature: "plan_source: the spec snapshot is not approved".to_owned(),
                details: FailureDetails::none().boxed(),
            })?;
        if approved.digest() != snapshot.digest() {
            return Err(SddExecutionError::Unavailable {
                feature: format!(
                    "plan_source: the spec {} changed after approval",
                    snapshot.path()
                ),
                details: FailureDetails::none().boxed(),
            });
        }
        let parts = snapshot
            .sections()
            .iter()
            .map(|section| {
                (
                    section.heading().to_owned(),
                    snapshot.digest().to_string(),
                    section.text().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        sections = sections.with_snapshot(snapshot.source(), snapshot.path(), parts);
    }
    Ok(sections)
}

fn build_lane(
    context: &SddPumpContext<'_>,
    approval: &ExecutionApproval,
    snapshot: &ExecutionSnapshot,
    task: TaskRef,
) -> Result<TaskLane, SddExecutionError> {
    let project = approval.project_id();
    let checkout = approval.workspace().canonical_checkout_root();
    let store = StoreHandle::new(Arc::clone(context.store));
    let dependencies = dependencies_of(&store, project, checkout);
    let mut gate = DesktopH4BarrierGate::new(store.clone(), project, checkout, dependencies)?;
    gate.bind_task(approval, task)?;
    // The pre-Task capture is what the final barrier compares against; it must
    // run before the child changes anything.
    gate.capture_verification()?;
    let barrier = shared_gate(gate);

    let git = git_program()?;
    let identity = ApprovedCommitIdentity::new(
        project,
        approval.approval_id().to_string(),
        approval.revision(),
        format!("execution:{}", snapshot.execution_id()),
        AbsolutePath::new(checkout).map_err(|error| SddExecutionError::Unavailable {
            feature: format!("workspace: {error}"),
            details: FailureDetails::none().boxed(),
        })?,
        approval.workspace().branch(),
        HostGitActor::new(
            approval.workspace().git_identity().author_name(),
            approval.workspace().git_identity().author_email(),
        )
        .map_err(|error| SddExecutionError::Unavailable {
            feature: format!("host_git: {error}"),
            details: FailureDetails::none().boxed(),
        })?,
    )?;
    let common = match context.test_gate.clone() {
        Some(gate) => gate,
        None => common_gate(context.pack_root.as_deref())?,
    };
    let boundary = HostGitCommitBoundary::new(
        HostGitBoundary::new(
            git.clone(),
            SystemArgvLauncher,
            RecordingHostGitAudit::new(),
            ProcessSupervisor::new(),
        )
        .map_err(|error| SddExecutionError::Unavailable {
            feature: format!("host_git: {error}"),
            details: FailureDetails::none().boxed(),
        })?,
        identity.clone(),
        common,
    );
    let observer = GitCheckoutObserver::new(
        GitRunner::new(git, SystemArgvLauncher, ProcessSupervisor::new(), project)?,
        AbsolutePath::new(checkout).map_err(|error| SddExecutionError::Unavailable {
            feature: format!("workspace: {error}"),
            details: FailureDetails::none().boxed(),
        })?,
    );
    let mut commit = DesktopHostCommit::new(store, boundary, observer, identity);
    let task_approval =
        approval
            .content()
            .task(task.number())
            .ok_or_else(|| SddExecutionError::InvalidValue {
                field: "approval.tasks".to_owned(),
                detail: "the selected Task is not approved".to_owned(),
            })?;
    // The Task's commit is compared with the commit it is about to become a
    // child of, not with the fixed branch baseline: a later Task must not see an
    // earlier Task's committed paths as unrelated changes. The fixed baseline
    // still governs the workspace comparison and the run's reported range.
    let parent = {
        let mut runner = GitRunner::new(
            git_program()?,
            SystemArgvLauncher,
            ProcessSupervisor::new(),
            project,
        )?;
        runner
            .head(checkout)?
            .ok_or_else(|| SddExecutionError::RecoveryRequired {
                reason: herness_sdd_execute::RecoveryReason::StateUnreadable,
                details: FailureDetails::none().boxed(),
            })?
    };
    let remaining = task_approval
        .budget()
        .active_seconds()
        .saturating_sub(snapshot.budget().consumed().active_seconds());
    commit.bind_task(TaskCommitExpectation::new(
        task,
        task_approval.title(),
        task_approval.commit_policy(),
        task_approval.scope().write_paths().to_vec(),
        herness_sdd_execute::Baseline::parse(parent.as_str())?,
        remaining,
    ));
    Ok(TaskLane {
        task,
        barrier,
        commit,
    })
}

fn dependencies_of(
    store: &StoreHandle,
    project: ProjectId,
    checkout: &str,
) -> Vec<herness_html_sync::observer::DependencyPath> {
    let root = Path::new(checkout);
    let settings = store
        .lock()
        .load_html_sync_settings(project)
        .ok()
        .flatten()
        .map(|record| record.settings().clone());
    match settings {
        Some(settings) => crate::host::discovered_dependencies(root, &settings),
        None => crate::host::default_dependencies(root),
    }
}

fn git_program() -> Result<AbsolutePath, SddExecutionError> {
    for candidate in [
        "/usr/bin/git",
        "/opt/homebrew/bin/git",
        "/usr/local/bin/git",
    ] {
        if Path::new(candidate).is_file()
            && let Ok(path) = AbsolutePath::new(candidate)
        {
            return Ok(path);
        }
    }
    Err(SddExecutionError::Unavailable {
        feature: "workspace: no Git executable was found".to_owned(),
        details: FailureDetails::none().boxed(),
    })
}

fn common_gate(pack_root: Option<&Path>) -> Result<HostGitGate, SddExecutionError> {
    let Some(pack_root) = pack_root else {
        return Err(SddExecutionError::Unavailable {
            feature: "host_git: no Common SDD pack root is configured".to_owned(),
            details: FailureDetails::none().boxed(),
        });
    };
    let script = pack_root.join(COMMON_GATE_SCRIPT);
    let program = AbsolutePath::new(script.to_string_lossy().into_owned()).map_err(|error| {
        SddExecutionError::Unavailable {
            feature: format!("host_git: {error}"),
            details: FailureDetails::none().boxed(),
        }
    })?;
    HostGitGate::new(program, Vec::new(), Some(Duration::from_secs(30))).map_err(|error| {
        SddExecutionError::Unavailable {
            feature: format!("host_git: {error}"),
            details: FailureDetails::none().boxed(),
        }
    })
}

/// One deterministic advance request per stored revision.
///
/// A re-delivered advance for the same revision returns its stored result
/// instead of repeating a dispatch or a commit.
fn pump_request_id(execution: ExecutionId, revision: ExecutionRevision) -> ControlRequestId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"h4.pump.advance\0");
    hasher.update(execution.to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(revision.get().to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ControlRequestId::from_parts(execution.project_id(), uuid::Uuid::from_bytes(bytes))
}

/// The store port the coordinator drives, locking per call.
///
/// It never holds the mutex across an H2 call, so the H2 composition's own
/// store handle can write in the same advance.
struct SharedExecutionStore {
    handle: StoreHandle,
}

impl SharedExecutionStore {
    const fn new(handle: StoreHandle) -> Self {
        Self { handle }
    }
}

impl ExecutionStorePort for SharedExecutionStore {
    fn load(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<herness_sdd_execute::StoredExecution>, SddExecutionError> {
        ExecutionStorePort::load(&*self.handle.lock(), project_id, execution_id)
    }

    fn compare_and_swap(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        ExecutionStorePort::compare_and_swap(
            &mut *self.handle.lock(),
            project_id,
            execution_id,
            expected_revision,
            next,
        )
    }

    fn dispatch_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<herness_sdd_execute::DispatchJournalEntry>, SddExecutionError> {
        ExecutionStorePort::dispatch_entry(
            &*self.handle.lock(),
            project_id,
            execution_id,
            request_id,
        )
    }

    fn commit_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: herness_sdd_execute::CommitRequestId,
    ) -> Result<Option<herness_sdd_execute::GitJournalEntry>, SddExecutionError> {
        ExecutionStorePort::commit_entry(&*self.handle.lock(), project_id, execution_id, request_id)
    }

    fn progress_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: herness_sdd_execute::ProgressJournalId,
    ) -> Result<Option<herness_sdd_execute::ProgressJournalEntry>, SddExecutionError> {
        ExecutionStorePort::progress_entry(
            &*self.handle.lock(),
            project_id,
            execution_id,
            request_id,
        )
    }

    fn operation_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<herness_sdd_execute::ControlRecord>, SddExecutionError> {
        ExecutionStorePort::operation_record(
            &*self.handle.lock(),
            project_id,
            execution_id,
            request_id,
        )
    }

    fn record_dispatch(
        &mut self,
        entry: &herness_sdd_execute::DispatchJournalEntry,
    ) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_dispatch(&mut *self.handle.lock(), entry)
    }

    fn record_git(
        &mut self,
        entry: &herness_sdd_execute::GitJournalEntry,
    ) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_git(&mut *self.handle.lock(), entry)
    }

    fn record_progress(
        &mut self,
        entry: &herness_sdd_execute::ProgressJournalEntry,
    ) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_progress(&mut *self.handle.lock(), entry)
    }

    fn record_operation(
        &mut self,
        record: &herness_sdd_execute::ControlRecord,
    ) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_operation(&mut *self.handle.lock(), record)
    }

    fn commit_operation(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
        record: &herness_sdd_execute::ControlRecord,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        ExecutionStorePort::commit_operation(
            &mut *self.handle.lock(),
            project_id,
            execution_id,
            expected_revision,
            next,
            record,
        )
    }
}

impl DurableExecutionStorePort for SharedExecutionStore {
    fn record_approval(&mut self, approval: &ExecutionApproval) -> Result<(), SddExecutionError> {
        DurableExecutionStorePort::record_approval(&mut *self.handle.lock(), approval)
    }

    fn approval(
        &self,
        project_id: ProjectId,
        approval_id: herness_sdd_execute::ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        DurableExecutionStorePort::approval(&*self.handle.lock(), project_id, approval_id, revision)
    }

    fn latest_approval(
        &self,
        project_id: ProjectId,
        approval_id: herness_sdd_execute::ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        DurableExecutionStorePort::latest_approval(&*self.handle.lock(), project_id, approval_id)
    }

    fn reserve_task(
        &mut self,
        reservation: &herness_sdd_execute::TaskReservation,
    ) -> Result<herness_sdd_execute::TaskReservation, SddExecutionError> {
        DurableExecutionStorePort::reserve_task(&mut *self.handle.lock(), reservation)
    }

    fn task_reservation(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<herness_sdd_execute::TaskReservation>, SddExecutionError> {
        DurableExecutionStorePort::task_reservation(
            &*self.handle.lock(),
            project_id,
            execution_id,
            request_id,
        )
    }

    fn record_manifest(
        &mut self,
        manifest: &herness_sdd_execute::DispatchManifest,
    ) -> Result<(), SddExecutionError> {
        DurableExecutionStorePort::record_manifest(&mut *self.handle.lock(), manifest)
    }

    fn manifest(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<herness_sdd_execute::DispatchManifest>, SddExecutionError> {
        DurableExecutionStorePort::manifest(
            &*self.handle.lock(),
            project_id,
            execution_id,
            request_id,
        )
    }

    fn record_budget_increment(
        &mut self,
        increment: &herness_sdd_execute::BudgetIncrement,
    ) -> Result<(), SddExecutionError> {
        DurableExecutionStorePort::record_budget_increment(&mut *self.handle.lock(), increment)
    }

    fn budget_increments(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<herness_sdd_execute::BudgetIncrement>, SddExecutionError> {
        DurableExecutionStorePort::budget_increments(&*self.handle.lock(), project_id, execution_id)
    }
}

/// The dispatch port over one shared H2 host.
struct PumpDispatch<'p, 'h, 'd> {
    cell: &'p RefCell<&'h mut SupervisionHost>,
    runtime: &'p mut dyn crate::supervision::runtime::DesktopSupervisionRuntime,
    registry: &'p H4StartApprovalRegistry,
    draft: &'p ApprovalDraft,
    approval: &'d ExecutionApproval,
    sections: &'d SnapshotSections,
    handoffs: &'d [herness_sdd_execute::TaskHandoff],
}

impl ChildDispatchPort for PumpDispatch<'_, '_, '_> {
    fn dispatch(&mut self, plan: &ChildDispatchPlan) -> Result<DispatchResult, SddExecutionError> {
        let mut launch = ApprovedTaskLaunch::new(self.approval, self.sections, self.handoffs);
        let mut host = self.cell.borrow_mut();
        dispatch_h2_task(
            &mut host,
            self.runtime,
            self.registry,
            self.draft,
            &mut launch,
            plan,
        )
    }

    fn reconcile(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchResult>, SddExecutionError> {
        reconcile_h2_task(&self.cell.borrow(), project_id, execution_id, request_id)
    }
}

/// The read-only status port over the same shared H2 host.
struct PumpChildren<'p, 'h> {
    cell: &'p RefCell<&'h mut SupervisionHost>,
}

impl ChildStatusPort for PumpChildren<'_, '_> {
    fn status(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<ChildStatus>, SddExecutionError> {
        let host = self.cell.borrow();
        let reservation = host
            .h4_task_reservation(project_id, execution_id, request_id)
            .map_err(|error| SddExecutionError::Unavailable {
                feature: format!("h4.h2: {error}"),
                details: FailureDetails::none().boxed(),
            })?;
        let Some(reservation) = reservation else {
            return Ok(None);
        };
        let view = host
            .get(project_id, reservation.supervision_id())
            .map_err(|error| SddExecutionError::Unavailable {
                feature: format!("h4.h2: {error}"),
                details: FailureDetails::none().boxed(),
            })?;
        Ok(Some(child_status_from_view(&reservation, &view)))
    }
}

/// The real completion seam: the final HTML barrier, then the bound host commit.
struct LaneCompletion<'a> {
    gate: SharedBarrierGate,
    commit: &'a mut DesktopHostCommit<HostGitCommitBoundary>,
}

impl herness_sdd_execute::TaskCompletionPort for LaneCompletion<'_> {
    fn wiring(&self, _task: TaskRef) -> CompletionWiring {
        completion_wiring(true, self.commit.commit_connected(), self.commit.feature())
    }

    fn complete(
        &mut self,
        request: &TaskCompletionRequest,
    ) -> Result<TaskCompletion, SddExecutionError> {
        let (report, verified) = {
            let mut gate = self
                .gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let report = gate.final_barrier(request.task(), Timestamp::now())?;
            let verified = gate.verified_documents();
            (report, verified)
        };
        if let Some(hold) = report.decision().hold() {
            return Ok(TaskCompletion::HumanWait { stop: hold.stop()? });
        }
        let completion = HostCommitCompletion::commit(&mut *self.commit, request, &verified)?;
        // The real commit result is durable here, and the coordinator has not yet
        // stored the Task completion snapshot. A crash leaves the established
        // result for recovery to attach, never a second commit.
        if matches!(completion, TaskCompletion::Complete { .. }) {
            crash::hit(CrashPoint::BeforeDbResult);
        }
        Ok(completion)
    }
}
