//! Desktop composition of the serial Task coordinator.
//!
//! This module connects the deterministic coordinator in
//! [`herness_sdd_execute::coordinator`] to the real H2 owner path, the real
//! SQLite store, the app-wide pump scope, and the readiness gate. It deliberately
//! does **not** connect the H3 barrier consumption or the host commit: those
//! belong to Task 16 and Task 17, so the composition installs
//! [`NotConnectedCompletion`], and a Task that H2 reports complete stops at
//! `waiting_human` with a `capability_unavailable` reason instead of advancing.
//!
//! # Wiring
//!
//! | Port | Real implementation |
//! | --- | --- |
//! | store | the shared `Store` (`ExecutionStorePort` + `DurableExecutionStorePort`) |
//! | launch | [`ApprovedTaskLaunch`] over the stored approval, the verified spec snapshots, and the stored handoffs |
//! | dispatch | [`H2ChildDispatch`] over `SupervisionHost::start_h4_task` |
//! | children | [`H2ChildStatus`], which re-reads the stored H2 record |
//! | completion | `not connected` until Task 16/17 |
//! | pump scope | [`PumpScope::AllExcept`] excluding only the H3 candidate target |
//!
//! The composition performs no push, pull, merge, rebase, amend, reset, or clean,
//! and it starts no second child for one Task.

use herness_core::contracts::ProjectId;
use herness_sdd_execute::{
    ApprovalRequirement, ChildDispatchPlan, ChildDispatchPort, ChildState, ChildStatus,
    ChildStatusPort, DispatchRequestId, DispatchResult, ExecutionApproval, ExecutionId,
    FailureDetails, LaunchRefusal, NotConnectedCompletion, SddExecutionError, Sha256Digest,
    SnapshotSections, TaskHandoff, TaskRef,
};
use herness_supervision::{
    ExecutionScope, SupervisionError, SupervisionId, SupervisionState, TargetVersion,
};

use crate::sdd_execute::packet::{H4TaskPacket, TaskPacketOutcome, task_packet};
use crate::sdd_execute::registry::{ApprovalDraft, H4StartApprovalRegistry};
use crate::supervision::h4_launch::{
    H4TaskLaunch, H4TaskStartOutcome, h4_commit_authorization, h4_owner_ref,
};
use crate::supervision::runtime::DesktopSupervisionRuntime;
use crate::supervision::{PumpScope, SupervisionHost, SupervisionTarget};

/// The desktop coordinator composition.
pub struct DesktopCoordinator {
    host: SupervisionHost,
    completion: NotConnectedCompletion,
}

impl DesktopCoordinator {
    /// Creates the composition over the shared H2 host.
    pub const fn new(host: SupervisionHost) -> Self {
        Self {
            host,
            completion: NotConnectedCompletion::new(),
        }
    }

    /// The H2 host.
    pub const fn host(&self) -> &SupervisionHost {
        &self.host
    }

    /// The mutable H2 host.
    pub const fn host_mut(&mut self) -> &mut SupervisionHost {
        &mut self.host
    }

    /// The host completion seam. It reports `not connected` until Task 16/17.
    pub const fn completion(&self) -> &NotConnectedCompletion {
        &self.completion
    }

    /// The native pump scope that excludes exactly one candidate target.
    ///
    /// The H3 authoring slot keeps its own `OnlyCandidate` pump; every other
    /// target, including an H4 Task's, advances with the native scope.
    pub fn task_pump_scope(project: ProjectId, candidate: Option<SupervisionTarget>) -> PumpScope {
        PumpScope::for_active_candidate([project], candidate)
    }

    /// The exact supervision target of one Task.
    pub fn task_target(project: ProjectId, supervision: SupervisionId) -> SupervisionTarget {
        SupervisionTarget::new(project, supervision)
    }
}

// ---------------------------------------------------------------------------
// Immutable launch
// ---------------------------------------------------------------------------

/// Builds one Task's launch and immutable packet from the stored approval.
///
/// The prompt and the H2 packet binding come from the same packet value, and the
/// dispatch manifest digest binds the Task identity, the approved plan revision
/// and digest, and the approved scope. The builder starts no child and performs
/// no Git operation.
pub struct ApprovedTaskLaunch<'a> {
    approval: &'a ExecutionApproval,
    snapshots: &'a SnapshotSections,
    handoffs: &'a [TaskHandoff],
}

impl<'a> ApprovedTaskLaunch<'a> {
    /// Creates one launch builder.
    pub const fn new(
        approval: &'a ExecutionApproval,
        snapshots: &'a SnapshotSections,
        handoffs: &'a [TaskHandoff],
    ) -> Self {
        Self {
            approval,
            snapshots,
            handoffs,
        }
    }

    /// Composes the immutable packet of one Task.
    pub fn packet(&self, task: TaskRef) -> Result<H4TaskPacket, LaunchRefusal> {
        match task_packet(
            self.approval,
            self.snapshots,
            task.number().get(),
            self.handoffs,
            None,
            None,
        ) {
            TaskPacketOutcome::Ready(packet) => Ok(*packet),
            TaskPacketOutcome::HumanWait { reason, detail } => Err(match reason {
                crate::sdd_execute::packet::TaskPacketRefusal::UnknownTask { number } => {
                    LaunchRefusal::UnknownTask { number }
                }
                crate::sdd_execute::packet::TaskPacketRefusal::Context { .. } => {
                    LaunchRefusal::Context { detail }
                }
                crate::sdd_execute::packet::TaskPacketRefusal::Capacity { .. } => {
                    LaunchRefusal::Capacity { detail }
                }
            }),
        }
    }

    /// The approved Task contract of one Task.
    pub fn task_approval(
        &self,
        task: TaskRef,
    ) -> Result<&'a herness_sdd_execute::TaskApproval, LaunchRefusal> {
        self.approval
            .content()
            .task(task.number())
            .ok_or(LaunchRefusal::UnknownTask {
                number: task.number().get(),
            })
    }
}

impl herness_sdd_execute::TaskLaunchPort for ApprovedTaskLaunch<'_> {
    fn launch(&mut self, task: TaskRef) -> Result<herness_sdd_execute::TaskLaunch, LaunchRefusal> {
        let packet = self.packet(task)?;
        let task_approval = self.task_approval(task)?;
        let manifest_digest = manifest_digest(self.approval, task, task_approval.scope())?;
        herness_sdd_execute::TaskLaunch::new(
            packet.prompt(),
            task_approval.scope().clone(),
            task_approval.budget().clone(),
            manifest_digest,
            packet.packet().fingerprint().clone(),
        )
        .map_err(|error| LaunchRefusal::Context {
            detail: error.to_string(),
        })
    }
}

/// The dispatch manifest digest of one approved Task.
///
/// It binds the Task identity, the approved plan revision and digest, the scope,
/// and the packet fingerprint, so a crash cannot silently widen what the child
/// may read or write.
fn manifest_digest(
    approval: &ExecutionApproval,
    task: TaskRef,
    scope: &ExecutionScope,
) -> Result<Sha256Digest, LaunchRefusal> {
    let mut read_paths = scope.read_paths().to_vec();
    let mut write_paths = scope.write_paths().to_vec();
    read_paths.sort();
    write_paths.sort();
    let content = serde_json::json!({
        "task": task.number().get(),
        "stableId": task.stable_id().to_string(),
        "planRevision": approval.plan().plan_revision().get(),
        "planDigest": approval.plan().digest().as_str(),
        "readPaths": read_paths,
        "writePaths": write_paths,
        "allowShell": scope.allow_shell(),
    });
    let bytes = serde_json::to_vec(&content).map_err(|error| LaunchRefusal::Context {
        detail: format!("could not encode the dispatch manifest: {error}"),
    })?;
    Ok(Sha256Digest::sha256(&bytes))
}

/// The H2 supervision target one dispatch request names.
///
/// It is derived deterministically from the dispatch request, so a re-delivered
/// dispatch, a crash before the reservation, and a restore all name the same
/// target and never create a second one.
pub fn supervision_target_id(dispatch: DispatchRequestId) -> SupervisionId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"h4.task.supervision\0");
    hasher.update(dispatch.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    SupervisionId::from_parts(dispatch.project_id(), uuid::Uuid::from_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Child dispatch over the real H2 owner path
// ---------------------------------------------------------------------------

/// Dispatches one H2 target and child through the real approved-owner path.
pub struct H2ChildDispatch<'a> {
    host: &'a mut SupervisionHost,
    runtime: &'a mut dyn DesktopSupervisionRuntime,
    registry: &'a H4StartApprovalRegistry,
    draft: &'a ApprovalDraft,
    launch: &'a mut ApprovedTaskLaunch<'a>,
}

impl<'a> H2ChildDispatch<'a> {
    /// Creates one dispatch adapter.
    pub const fn new(
        host: &'a mut SupervisionHost,
        runtime: &'a mut dyn DesktopSupervisionRuntime,
        registry: &'a H4StartApprovalRegistry,
        draft: &'a ApprovalDraft,
        launch: &'a mut ApprovedTaskLaunch<'a>,
    ) -> Self {
        Self {
            host,
            runtime,
            registry,
            draft,
            launch,
        }
    }

    /// Builds one H2 launch from the approved Task and its immutable packet.
    fn h2_launch(&mut self, plan: &ChildDispatchPlan) -> Result<H4TaskLaunch, SddExecutionError> {
        let request = plan.request();
        let task = request.content().task();
        let approval = self.launch.approval;
        let packet = self
            .launch
            .packet(task)
            .map_err(|refusal| launch_refusal_error(&refusal))?;
        let task_approval = self
            .launch
            .task_approval(task)
            .map_err(|refusal| launch_refusal_error(&refusal))?;
        let now = herness_core::Timestamp::now();
        let owner = h4_owner_ref(self.draft.execution(), task).map_err(supervision_value)?;
        let condition_version =
            herness_supervision::ConditionVersion::new(1).map_err(supervision_value)?;
        let conditions = h4_approved_conditions(&owner, condition_version, task_approval, now)?;
        let approval_entry = self
            .draft
            .owner_approval(approval, task, now)
            .map_err(sdd_value)?;
        let launch_request = herness_supervision::H4LaunchRequest::new(
            approval_entry.execution().clone(),
            approval_entry.task().clone(),
            approval_entry.plan_revision(),
            approval_entry.plan_digest().clone(),
            packet.h2_binding()?,
            approval_entry.pack_fingerprint().clone(),
            h4_commit_authorization(
                approval.commit().host_commit(),
                approval.commit().run_hooks(),
            )
            .map_err(supervision_value)?,
        )
        .map_err(supervision_value)?;
        let dispatch = request.identity().request_id();
        let supervision = supervision_target_id(dispatch);
        H4TaskLaunch::new(
            self.draft.execution(),
            task,
            dispatch,
            supervision,
            approval.connection().connection_id(),
            packet.prompt(),
            conditions,
            task_approval.scope().clone(),
            TargetVersion::new(1).map_err(supervision_value)?,
            task_approval.budget().clone(),
            1,
            launch_request,
        )
        .map_err(supervision_value)
    }
}

impl ChildDispatchPort for H2ChildDispatch<'_> {
    fn dispatch(&mut self, plan: &ChildDispatchPlan) -> Result<DispatchResult, SddExecutionError> {
        let launch = self.h2_launch(plan)?;
        let project = launch.project_id();
        let dispatch = launch.dispatch();
        let supervision = launch.supervision_id();
        let outcome = self
            .host
            .start_h4_task(self.runtime, self.registry, &launch)
            .map_err(supervision_error)?;
        match outcome {
            H4TaskStartOutcome::Ready { view, .. } => {
                let reservation = self
                    .host
                    .h4_task_reservation(project, self.draft.execution(), dispatch)
                    .map_err(supervision_error)?
                    .ok_or_else(|| SddExecutionError::RecoveryRequired {
                        reason: herness_sdd_execute::RecoveryReason::UnknownRequest,
                        details: FailureDetails::none().boxed(),
                    })?;
                if view.supervision_id != supervision {
                    return Err(SddExecutionError::Conflict {
                        reason: herness_sdd_execute::ConflictReason::OwnershipConflict,
                        details: FailureDetails::none().boxed(),
                    });
                }
                DispatchResult::new(reservation.supervision_id(), reservation.child())
            }
            H4TaskStartOutcome::Reconcile { reason, .. } => {
                // The reserved mapping cannot be observed. Nothing was created
                // and nothing was started; a human reconciles it.
                eprintln!("H4_DISPATCH_RECONCILE: {}", reason.as_str());
                Err(SddExecutionError::RecoveryRequired {
                    reason: herness_sdd_execute::RecoveryReason::UnknownRequest,
                    details: FailureDetails::none().boxed(),
                })
            }
        }
    }

    fn reconcile(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchResult>, SddExecutionError> {
        let reservation = self
            .host
            .h4_task_reservation(project_id, execution_id, request_id)
            .map_err(supervision_error)?;
        match reservation {
            Some(reservation) => Ok(Some(DispatchResult::new(
                reservation.supervision_id(),
                reservation.child(),
            )?)),
            None => Ok(None),
        }
    }
}

fn h4_approved_conditions(
    owner: &herness_supervision::OwnerRef,
    version: herness_supervision::ConditionVersion,
    task: &herness_sdd_execute::TaskApproval,
    now: herness_core::Timestamp,
) -> Result<herness_supervision::ConditionSet, SddExecutionError> {
    crate::supervision::h4_launch::h4_approved_conditions(owner, version, task, now)
        .map_err(supervision_value)
}

fn launch_refusal_error(refusal: &LaunchRefusal) -> SddExecutionError {
    match refusal {
        LaunchRefusal::Unavailable { feature } => SddExecutionError::Unavailable {
            feature: feature.clone(),
            details: FailureDetails::none().boxed(),
        },
        LaunchRefusal::UnknownTask { number: _ } => SddExecutionError::Conflict {
            reason: herness_sdd_execute::ConflictReason::TaskNotReady,
            details: FailureDetails::none().boxed(),
        },
        LaunchRefusal::Context { .. } | LaunchRefusal::Capacity { .. } => {
            SddExecutionError::ApprovalRequired {
                reason: ApprovalRequirement::StartApproval,
                details: FailureDetails::none().boxed(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stored H2 status
// ---------------------------------------------------------------------------

/// Re-reads the stored H2 record of one Task.
pub struct H2ChildStatus<'a> {
    host: &'a SupervisionHost,
}

impl<'a> H2ChildStatus<'a> {
    /// Creates one status reader.
    pub const fn new(host: &'a SupervisionHost) -> Self {
        Self { host }
    }
}

impl ChildStatusPort for H2ChildStatus<'_> {
    fn status(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<ChildStatus>, SddExecutionError> {
        let reservation = self
            .host
            .h4_task_reservation(project_id, execution_id, request_id)
            .map_err(supervision_error)?;
        let Some(reservation) = reservation else {
            return Ok(None);
        };
        let view = self
            .host
            .get(project_id, reservation.supervision_id())
            .map_err(supervision_error)?;
        let state = child_state(&view.state);
        let consulted = view.budget.as_ref();
        let active_seconds = consulted
            .map(|budget| budget.usage.active_seconds_consumed())
            .unwrap_or(0);
        // `runs_started` includes the first run; the additional-run cap counts
        // the runs after it.
        let additional_runs = consulted
            .map(|budget| budget.usage.runs_started().saturating_sub(1))
            .unwrap_or(0);
        // H2 owns the consecutive-stall counter and stops at its own three
        // cycles, which arrives here as the stored `stagnation` stop cause. The
        // mirror counter therefore starts from the durable value H2 recorded;
        // this composition reads it only through the stop reason, so a running
        // target reports zero rather than a guessed count.
        let stalls = 0;
        let evidence = view
            .evidence
            .iter()
            .filter_map(|evidence| evidence.evidence_id.parse().ok())
            .collect();
        let mut status = ChildStatus::new(
            reservation.supervision_id(),
            state,
            active_seconds,
            additional_runs,
            stalls,
            view.completion_stale.is_some(),
            evidence,
        );
        if let Some(cause) = stop_cause(&view.reason) {
            status = status.with_stop_cause(cause);
        }
        Ok(Some(status))
    }
}

/// Maps the stored H2 reason onto H4's stop cause.
///
/// Only an explicit H2 stop reason produces a cause; a running or waiting
/// reason produces none, so H4 never invents a stop.
pub fn stop_cause(reason: &serde_json::Value) -> Option<herness_sdd_execute::ChildStopCause> {
    let cause = reason
        .get("cause")
        .and_then(|cause| cause.get("kind"))
        .and_then(|kind| kind.as_str())?;
    Some(match cause {
        "user_request" => herness_sdd_execute::ChildStopCause::UserRequest,
        "stagnation" => herness_sdd_execute::ChildStopCause::Stagnation,
        "budget" => herness_sdd_execute::ChildStopCause::Budget,
        "stop_unconfirmed" => herness_sdd_execute::ChildStopCause::StopUnconfirmed,
        "recovery_reconciliation" => herness_sdd_execute::ChildStopCause::RecoveryReconciliation,
        _ => herness_sdd_execute::ChildStopCause::Unknown,
    })
}

/// Maps one stored H2 state label onto the H4 child state.
///
/// An unreadable label is [`ChildState::Unknown`], which is never completion.
pub fn child_state(label: &str) -> ChildState {
    match label {
        "ready" => ChildState::Ready,
        "running" => ChildState::Running,
        "verifying" => ChildState::Verifying,
        "assessing" => ChildState::Assessing,
        "waiting_human" => ChildState::WaitingHuman,
        "stopped" => ChildState::Stopped,
        "failed" => ChildState::Failed,
        "cancelled" => ChildState::Cancelled,
        "completed" => ChildState::Completed,
        _ => ChildState::Unknown,
    }
}

/// Maps one typed H2 state.
pub fn child_state_of(state: SupervisionState) -> ChildState {
    child_state(state.as_str())
}

fn supervision_error(error: SupervisionError) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: format!("h4.h2: {error}"),
        details: FailureDetails::none().boxed(),
    }
}

fn supervision_value(error: SupervisionError) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: "h4.coordinator".to_owned(),
        detail: error.to_string(),
    }
}

fn sdd_value(error: SddExecutionError) -> SddExecutionError {
    error
}
