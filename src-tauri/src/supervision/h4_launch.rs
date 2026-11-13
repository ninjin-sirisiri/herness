//! Reservation-mediated H4 Task startup.
//!
//! One H4 Task owns exactly one H2 target and one H1 child. The host records a
//! launch intent, allocates the child, and reserves the
//! `(dispatch request → supervision / child)` mapping *before* it creates the
//! target or starts a run. The mapping is durable in the store's
//! `sdd_task_reservations` row from Task 5, keyed by
//! `(project, execution, dispatch request)`.
//!
//! That ordering is what makes a re-delivered start request and every crash
//! boundary idempotent:
//!
//! | Crash point | Durable facts | Next attempt |
//! | --- | --- | --- |
//! | before the intent | none | creates the child once |
//! | after the intent, before the reservation | intent only | `reconcile`; no child, no run |
//! | after the reservation, before the target | reservation only | creates the target from the reserved child; one run |
//! | after the target, before the run result | target, phase `starting_run` | the recorded run/input IDs are reused; one run |
//! | after the run result | target + command result | returns the stored result; one run |
//!
//! Every step is gated by [`authorize_h4_owner_launch`]: no child is allocated,
//! no target is created, and no run starts unless the current H4 registry entry
//! matches the approved execution, Task, plan revision and digest, immutable
//! packet, pack fingerprint, host-commit authorization, condition set, scope,
//! profile, consent, and finite budget. A name, an `ApprovedOwner` value, repo
//! text, a receipt, an environment variable, a request actor, the owner kind,
//! model output, or an H3 approval never authorizes.

use herness_core::{ConnectionId, ProjectId};
use herness_sdd_execute::{DispatchRequestId, ExecutionId, Sha256Digest, TaskRef, TaskReservation};
use herness_supervision::budget::BudgetPolicy;
use herness_supervision::conditions::ConditionSet;
use herness_supervision::consent::{ConsentBlock, DisclosureDataKind};
use herness_supervision::error::OwnerLaunchRejection;
use herness_supervision::evidence::{ContentDigest, TargetVersion};
use herness_supervision::owner_launch::{
    H4CommitAuthorization, H4ExecutionRef, H4LaunchRequest, H4OwnerApproval,
    H4OwnerApprovalRegistryPort, H4OwnerLaunchBinding, H4PacketBinding, H4TaskRef,
    HostOwnerAuthority, authorize_h4_owner_launch,
};
use herness_supervision::ports::{ClockPort, SupervisionStorePort};
use herness_supervision::{
    ApprovalActor, ApprovalBasis, ExecutionScope, OwnerApprovalSource, OwnerKind, OwnerRef,
    ProfilePurpose, SupervisionContract, SupervisionError, SupervisionId, SupervisionRecord,
    SupervisionRequestId, TargetReadSet, WorkPacket,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::plan::BudgetSnapshot;
use super::plan::{PLAN_FORMAT_VERSION, RequestActor, StoredPlan, save_plan};
use super::runtime::{ChildIdentity, DesktopSupervisionRuntime};
use super::workspace::ProjectWorkspace;
use super::{SupervisionHost, SupervisionView};

/// Format version of one host-state launch intent.
pub const H4_LAUNCH_INTENT_FORMAT_VERSION: u32 = 1;

/// Why a reserved H4 Task cannot be observed well enough to create or start.
///
/// Every variant means no run started and no second child was created. The host
/// must reconcile the named mapping (Task 20) before it tries again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum H4ReconcileReason {
    /// A previous attempt recorded its launch intent but never recorded a
    /// reservation, so a child may exist without a durable mapping.
    CreationUnconfirmed,
    /// The reservation exists but the H2 record and plan do not match, so the
    /// reserved target must be confirmed before anything is created.
    TargetUnobservable,
    /// The stored plan names a different child than the reservation.
    ChildMismatch,
}

impl H4ReconcileReason {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreationUnconfirmed => "creation_unconfirmed",
            Self::TargetUnobservable => "target_unobservable",
            Self::ChildMismatch => "child_mismatch",
        }
    }
}

/// Outcome of ensuring or starting one reserved H4 Task.
///
/// It deliberately distinguishes "the one target exists" from "the mapping
/// cannot be observed". Nothing is created in the reconcile case.
#[derive(Debug)]
pub enum H4TaskStartOutcome {
    /// The one target exists and at most one run was started.
    Ready {
        /// Current target view.
        view: Box<SupervisionView>,
        /// Whether this call created the target.
        created_target: bool,
        /// Whether this call started the run.
        started_run: bool,
    },
    /// The mapping cannot be observed. Nothing was created or started.
    Reconcile {
        /// Reserved H2 target.
        supervision_id: SupervisionId,
        /// Dispatch request that keys the mapping.
        dispatch: DispatchRequestId,
        /// Why the mapping cannot be observed.
        reason: H4ReconcileReason,
    },
}

impl H4TaskStartOutcome {
    /// Whether the one target exists.
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    /// Current view, when the target exists.
    pub fn view(&self) -> Option<&SupervisionView> {
        match self {
            Self::Ready { view, .. } => Some(view),
            Self::Reconcile { .. } => None,
        }
    }

    /// Reconcile reason, when the mapping could not be observed.
    pub const fn reconcile_reason(&self) -> Option<H4ReconcileReason> {
        match self {
            Self::Ready { .. } => None,
            Self::Reconcile { reason, .. } => Some(*reason),
        }
    }
}

/// Outcome of reserving the one child without creating the target.
#[derive(Debug)]
pub enum H4ReservationOutcome {
    /// The reservation exists and is the one mapping for this Task.
    Reserved(TaskReservation),
    /// A crash left an intent without a reservation. Nothing was created.
    Reconcile {
        /// Reserved H2 target.
        supervision_id: SupervisionId,
        /// Dispatch request that keys the mapping.
        dispatch: DispatchRequestId,
        /// Why the mapping cannot be observed.
        reason: H4ReconcileReason,
    },
}

impl H4ReservationOutcome {
    /// Reservation, when one exists.
    pub const fn reservation(&self) -> Option<&TaskReservation> {
        match self {
            Self::Reserved(reservation) => Some(reservation),
            Self::Reconcile { .. } => None,
        }
    }
}

/// Durable host intent recorded before the one child is allocated.
///
/// The record is keyed by project and dispatch request and contains no prompt,
/// credential, or model text. Its only purpose is to distinguish "no attempt"
/// from "an attempt whose child may exist", so a crash in between waits for
/// reconciliation instead of allocating a second child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H4LaunchIntent {
    format_version: u32,
    project_id: ProjectId,
    execution_id: ExecutionId,
    task: TaskRef,
    dispatch: DispatchRequestId,
    supervision_id: SupervisionId,
    plan_revision: u64,
    plan_digest: String,
}

impl H4LaunchIntent {
    /// Records one launch intent for a reserved dispatch request.
    pub fn new(
        execution_id: ExecutionId,
        task: TaskRef,
        dispatch: DispatchRequestId,
        supervision_id: SupervisionId,
        plan_revision: u64,
        plan_digest: &ContentDigest,
    ) -> Result<Self, SupervisionError> {
        let project_id = execution_id.project_id();
        execution_id
            .validate_in(project_id)
            .map_err(|_| cross_project(project_id, execution_id.project_id()))?;
        task.ensure_project(project_id)
            .map_err(|_| cross_project(project_id, task.project_id()))?;
        dispatch
            .validate_in(project_id)
            .map_err(|_| cross_project(project_id, dispatch.project_id()))?;
        if supervision_id.project_id() != project_id {
            return Err(cross_project(project_id, supervision_id.project_id()));
        }
        if plan_revision == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "h4Launch.planRevision".to_owned(),
                detail: "plan revisions start at one".to_owned(),
            });
        }
        Ok(Self {
            format_version: H4_LAUNCH_INTENT_FORMAT_VERSION,
            project_id,
            execution_id,
            task,
            dispatch,
            supervision_id,
            plan_revision,
            plan_digest: plan_digest.to_string(),
        })
    }

    /// Project that owns the intent.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Task identity.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Dispatch request the intent belongs to.
    pub const fn dispatch(&self) -> DispatchRequestId {
        self.dispatch
    }

    /// Reserved H2 target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Approved plan revision recorded with the intent.
    pub const fn plan_revision(&self) -> u64 {
        self.plan_revision
    }

    /// Approved plan digest recorded with the intent.
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }
}

/// One H4 Task launch request.
///
/// The H2 half (condition set and digest, execution scope, target version,
/// finite budget, profile, and consent) comes from the stored approved
/// contract and live per-purpose configuration. The H4 half
/// ([`H4LaunchRequest`]) comes from the stored H4 approval. Both are compared
/// against the current H4 registry entry before any child exists.
#[derive(Debug, Clone)]
pub struct H4TaskLaunch {
    execution: ExecutionId,
    task: TaskRef,
    dispatch: DispatchRequestId,
    supervision_id: SupervisionId,
    connection: ConnectionId,
    instructions: String,
    conditions: ConditionSet,
    execution_scope: ExecutionScope,
    target_version: TargetVersion,
    budget: BudgetPolicy,
    budget_policy_version: u64,
    approval: H4LaunchRequest,
}

impl H4TaskLaunch {
    /// Creates one H4 Task launch request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution: ExecutionId,
        task: TaskRef,
        dispatch: DispatchRequestId,
        supervision_id: SupervisionId,
        connection: ConnectionId,
        instructions: impl Into<String>,
        conditions: ConditionSet,
        execution_scope: ExecutionScope,
        target_version: TargetVersion,
        budget: BudgetPolicy,
        budget_policy_version: u64,
        approval: H4LaunchRequest,
    ) -> Result<Self, SupervisionError> {
        let project = execution.project_id();
        execution
            .validate_in(project)
            .map_err(|_| cross_project(project, execution.project_id()))?;
        task.ensure_project(project)
            .map_err(|_| cross_project(project, task.project_id()))?;
        dispatch
            .validate_in(project)
            .map_err(|_| cross_project(project, dispatch.project_id()))?;
        if supervision_id.project_id() != project {
            return Err(cross_project(project, supervision_id.project_id()));
        }
        if conditions.project_id() != project {
            return Err(cross_project(project, conditions.project_id()));
        }
        if execution_scope.project_id() != project {
            return Err(cross_project(project, execution_scope.project_id()));
        }
        if budget_policy_version == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "h4Launch.budgetPolicyVersion".to_owned(),
                detail: "the approved budget policy version must be positive".to_owned(),
            });
        }
        budget.validate()?;
        let instructions = instructions.into();
        if instructions.trim().is_empty() {
            return Err(SupervisionError::InvalidValue {
                field: "h4Launch.instructions".to_owned(),
                detail: "the first instruction must not be empty".to_owned(),
            });
        }
        if approval.execution().as_str() != execution.to_string()
            || approval.task().stable_id() != task.stable_id().to_string()
            || approval.task().number() != task.number().get()
        {
            return Err(supervision_reason(OwnerLaunchRejection::TaskMismatch));
        }
        Ok(Self {
            execution,
            task,
            dispatch,
            supervision_id,
            connection,
            instructions,
            conditions,
            execution_scope,
            target_version,
            budget,
            budget_policy_version,
            approval,
        })
    }

    /// Project that owns the launch.
    pub const fn project_id(&self) -> ProjectId {
        self.execution.project_id()
    }

    /// Execution identity.
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Task identity.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Dispatch request that keys the one mapping.
    pub const fn dispatch(&self) -> DispatchRequestId {
        self.dispatch
    }

    /// Reserved H2 target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Connection the child runs on.
    pub const fn connection(&self) -> ConnectionId {
        self.connection
    }

    /// Exact first instruction handed to the child.
    pub fn instructions(&self) -> &str {
        &self.instructions
    }

    /// Approved condition set and its digest.
    pub const fn conditions(&self) -> &ConditionSet {
        &self.conditions
    }

    /// Approved execution scope.
    pub const fn execution_scope(&self) -> &ExecutionScope {
        &self.execution_scope
    }

    /// Approved target version.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }

    /// Approved finite budget.
    pub const fn budget(&self) -> &BudgetPolicy {
        &self.budget
    }

    /// Approved budget policy version.
    pub const fn budget_policy_version(&self) -> u64 {
        self.budget_policy_version
    }

    /// H4-owned identity of this launch.
    pub const fn approval(&self) -> &H4LaunchRequest {
        &self.approval
    }

    /// The H2 owner reference this Task uses inside one project.
    ///
    /// It combines the opaque H4 execution and the stable Task identity so two
    /// executions that happen to use the same Task label stay distinct. It is
    /// not an approval.
    pub fn owner(&self) -> Result<OwnerRef, SupervisionError> {
        h4_owner_ref(self.execution, self.task)
    }

    fn ensure_owner_conditions(&self, owner: &OwnerRef) -> Result<(), SupervisionError> {
        let Some(approval) = self.conditions.approval() else {
            return Err(supervision_reason(OwnerLaunchRejection::OwnerNotApproved));
        };
        match approval.basis() {
            ApprovalBasis::InheritedOwner {
                owner: approved,
                source,
                ..
            } if approved == owner && *source == OwnerApprovalSource::H4ApprovedPlan => Ok(()),
            _ => Err(supervision_reason(OwnerLaunchRejection::OwnerNotApproved)),
        }
    }

    /// Verifies the recorded conditions are still validly approved.
    fn ensure_conditions_current(
        &self,
        now: herness_core::Timestamp,
    ) -> Result<(), SupervisionError> {
        self.conditions.require_approval(now)
    }
}

/// Builds the opaque H4 execution and Task references from the typed H4 IDs.
pub fn h4_launch_identity(
    execution: ExecutionId,
    task: TaskRef,
) -> Result<(H4ExecutionRef, H4TaskRef), SupervisionError> {
    Ok((
        H4ExecutionRef::new(execution.to_string())?,
        H4TaskRef::new(task.stable_id().to_string(), task.number().get())?,
    ))
}

/// Builds the H2 owner reference of one H4 Task.
///
/// It combines the opaque H4 execution and the stable Task identity so two
/// executions that happen to use the same Task label stay distinct, and it fits
/// H2's bounded owner reference. It is not an approval.
pub fn h4_owner_ref(execution: ExecutionId, task: TaskRef) -> Result<OwnerRef, SupervisionError> {
    OwnerRef::new(
        OwnerKind::H4SddTask,
        format!(
            "h4:{}:task:{}:{}",
            execution,
            task.number().get(),
            task.stable_id()
        ),
    )
}

/// Normalizes one H4 `sha256:<hex>` digest into H2's bare hexadecimal digest.
pub fn h4_content_digest(digest: &Sha256Digest) -> Result<ContentDigest, SupervisionError> {
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .unwrap_or(digest.as_str());
    ContentDigest::parse(hex)
}

/// Builds the packet binding from the three H4 digests.
pub fn h4_packet_binding(
    task_body: &Sha256Digest,
    global_constraints: &Sha256Digest,
    spec_snapshot: &Sha256Digest,
) -> Result<H4PacketBinding, SupervisionError> {
    Ok(H4PacketBinding::new(
        h4_content_digest(task_body)?,
        h4_content_digest(global_constraints)?,
        h4_content_digest(spec_snapshot)?,
    ))
}

/// Converts the H4 commit authorization into the H2-side approval value.
pub fn h4_commit_authorization(
    host_commit: bool,
    run_hooks: bool,
) -> Result<H4CommitAuthorization, SupervisionError> {
    H4CommitAuthorization::new(host_commit, run_hooks)
}

/// Resolves one reserved H4 child into the H4 dispatch identity.
pub fn h4_child_identity(
    child: ChildIdentity,
) -> Result<herness_sdd_execute::ChildIdentity, SupervisionError> {
    herness_sdd_execute::ChildIdentity::new(child.agent_id, child.session_id).map_err(|error| {
        SupervisionError::InvalidValue {
            field: "h4Launch.child".to_owned(),
            detail: error.to_string(),
        }
    })
}

impl SupervisionHost {
    /// Reads the recorded H4 launch intent for one dispatch request.
    ///
    /// This performs no side effect and starts nothing.
    pub fn h4_launch_intent(
        &self,
        project: ProjectId,
        dispatch: DispatchRequestId,
    ) -> Result<Option<H4LaunchIntent>, SupervisionError> {
        let key = intent_key(project, dispatch);
        let bytes = self.store.lock().load_host_state(&key).map_err(storage)?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let intent: H4LaunchIntent =
            serde_json::from_slice(&bytes).map_err(|error| SupervisionError::StorageFailure {
                detail: format!("stored H4 launch intent is invalid: {error}"),
            })?;
        if intent.format_version != H4_LAUNCH_INTENT_FORMAT_VERSION
            || intent.project_id != project
            || intent.dispatch != dispatch
        {
            return Err(SupervisionError::StorageFailure {
                detail: "stored H4 launch intent does not match its key".to_owned(),
            });
        }
        Ok(Some(intent))
    }

    /// Records the host launch intent for one dispatch request.
    ///
    /// Host-only and harmless by itself: an intent without a reservation can
    /// only cause a reconcile/wait, never an approval or a run. The launcher
    /// writes it before allocating the child; recovery and tests use it to
    /// reproduce the "intent recorded, reservation missing" crash boundary.
    pub fn record_h4_launch_intent(&self, intent: &H4LaunchIntent) -> Result<(), SupervisionError> {
        let key = intent_key(intent.project_id(), intent.dispatch());
        let bytes =
            serde_json::to_vec(intent).map_err(|error| SupervisionError::StorageFailure {
                detail: format!("could not encode the H4 launch intent: {error}"),
            })?;
        self.store
            .lock()
            .save_host_state(&key, &bytes)
            .map_err(storage)
    }

    /// Reads the one durable reservation for a dispatch request.
    ///
    /// This starts nothing and creates nothing.
    pub fn h4_task_reservation(
        &self,
        project: ProjectId,
        execution: ExecutionId,
        dispatch: DispatchRequestId,
    ) -> Result<Option<TaskReservation>, SupervisionError> {
        Ok(self
            .store
            .lock()
            .sdd_task_reservation(project, execution, dispatch)?)
    }

    /// Reserves the one child for a reserved dispatch request.
    ///
    /// This is the coordinator's "record the H2 mapping before start" step
    /// (Task 15). It authorizes the launch first, then records the intent,
    /// allocates the one child, and writes the reservation. It creates no target
    /// and starts no run. A re-delivered call returns the stored reservation; a
    /// crash that left an intent without a reservation returns
    /// [`H4ReservationOutcome::Reconcile`] instead of a second child.
    pub fn reserve_h4_task(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        registry: &dyn H4OwnerApprovalRegistryPort,
        launch: &H4TaskLaunch,
    ) -> Result<H4ReservationOutcome, SupervisionError> {
        self.h4_launch_authority(registry, launch)?;
        self.reserve_h4_task_authorized(runtime, launch)
    }

    /// Reserves the one child after the caller already authorized the launch.
    fn reserve_h4_task_authorized(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        launch: &H4TaskLaunch,
    ) -> Result<H4ReservationOutcome, SupervisionError> {
        let project = launch.project_id();
        let dispatch = launch.dispatch();
        let supervision = launch.supervision_id();

        if let Some(reservation) =
            self.store
                .lock()
                .sdd_task_reservation(project, launch.execution(), dispatch)?
        {
            ensure_reservation_matches(&reservation, launch)?;
            return Ok(H4ReservationOutcome::Reserved(reservation));
        }
        if let Some(intent) = self.h4_launch_intent(project, dispatch)? {
            if intent.supervision_id() != supervision
                || intent.execution_id() != launch.execution()
                || intent.task() != launch.task()
            {
                return Err(supervision_reason(
                    OwnerLaunchRejection::ReservationConflict,
                ));
            }
            return Ok(H4ReservationOutcome::Reconcile {
                supervision_id: supervision,
                dispatch,
                reason: H4ReconcileReason::CreationUnconfirmed,
            });
        }
        let intent = H4LaunchIntent::new(
            launch.execution(),
            launch.task(),
            dispatch,
            supervision,
            launch.approval().plan_revision(),
            launch.approval().plan_digest(),
        )?;
        self.record_h4_launch_intent(&intent)?;
        let child = runtime.create_child(project, launch.connection(), launch.execution_scope())?;
        let reservation = TaskReservation::new(
            launch.execution(),
            launch.task(),
            dispatch,
            supervision,
            h4_child_identity(child)?,
        )
        .map_err(sdd)?;
        let reservation = self.store.lock().reserve_sdd_task(&reservation)?;
        Ok(H4ReservationOutcome::Reserved(reservation))
    }

    /// Ensures exactly one H2 target exists for a reserved H4 Task.
    ///
    /// The launch is authorized first. When no reservation exists it is created
    /// (allocating the one child) exactly as [`Self::reserve_h4_task`] does; when
    /// the reservation exists but the target does not, the target is created
    /// from the *reserved* child and `create_child` is not called again. No run
    /// is started.
    pub fn ensure_h4_task_target(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        registry: &dyn H4OwnerApprovalRegistryPort,
        launch: &H4TaskLaunch,
    ) -> Result<H4TaskStartOutcome, SupervisionError> {
        let authority = self.h4_launch_authority(registry, launch)?;
        let reservation = match self.reserve_h4_task_authorized(runtime, launch)? {
            H4ReservationOutcome::Reserved(reservation) => reservation,
            H4ReservationOutcome::Reconcile {
                supervision_id,
                dispatch,
                reason,
            } => {
                return Ok(H4TaskStartOutcome::Reconcile {
                    supervision_id,
                    dispatch,
                    reason,
                });
            }
        };
        self.ensure_target_from_reservation(runtime, launch, &reservation, &authority)
    }

    /// Starts exactly one run for a reserved H4 Task.
    ///
    /// The target is created once when it does not exist, then the existing
    /// approved-owner start path is used with a start request ID derived from the
    /// dispatch request. A re-delivered request returns its recorded result and
    /// never starts a second run. An unobservable mapping returns
    /// [`H4TaskStartOutcome::Reconcile`] with no run.
    pub fn start_h4_task(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        registry: &dyn H4OwnerApprovalRegistryPort,
        launch: &H4TaskLaunch,
    ) -> Result<H4TaskStartOutcome, SupervisionError> {
        let authority = self.h4_launch_authority(registry, launch)?;
        let project = launch.project_id();
        let supervision = launch.supervision_id();
        let reservation = match self.reserve_h4_task_authorized(runtime, launch)? {
            H4ReservationOutcome::Reserved(reservation) => reservation,
            H4ReservationOutcome::Reconcile {
                supervision_id,
                dispatch,
                reason,
            } => {
                return Ok(H4TaskStartOutcome::Reconcile {
                    supervision_id,
                    dispatch,
                    reason,
                });
            }
        };
        let ensured =
            self.ensure_target_from_reservation(runtime, launch, &reservation, &authority)?;
        let created_target = match &ensured {
            H4TaskStartOutcome::Ready { created_target, .. } => *created_target,
            H4TaskStartOutcome::Reconcile { .. } => return Ok(ensured),
        };
        let record = self.load(project, supervision)?;
        let request_id = h4_start_request_id(project, launch.dispatch());
        let duplicate = self.store.command_result(request_id)?.is_some();
        let outcome = self.start_approved_owner(runtime, authority, request_id, record.revision());
        match outcome {
            Ok(view) => {
                // A duplicate request answers from the command journal. Re-arm
                // the pump so an interrupted start (a run recorded but not yet
                // handed to H1) continues with the same child instead of
                // stalling. A restored target stays inert until a human restart.
                if !self.is_restored(project, supervision) {
                    self.set_active(project, supervision, true);
                }
                Ok(H4TaskStartOutcome::Ready {
                    view: Box::new(view),
                    created_target,
                    started_run: !duplicate,
                })
            }
            Err(SupervisionError::OwnerLaunchRejected {
                reason: OwnerLaunchRejection::AlreadyStarted,
            }) => Ok(H4TaskStartOutcome::Ready {
                view: Box::new(self.view(project, supervision)?),
                created_target,
                started_run: false,
            }),
            Err(error) => Err(error),
        }
    }

    /// Creates the target for an existing reservation without a new child.
    fn ensure_target_from_reservation(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        launch: &H4TaskLaunch,
        reservation: &TaskReservation,
        authority: &HostOwnerAuthority,
    ) -> Result<H4TaskStartOutcome, SupervisionError> {
        let project = launch.project_id();
        let supervision = launch.supervision_id();
        let dispatch = launch.dispatch();
        ensure_reservation_matches(reservation, launch)?;

        let record = self.store.load(project, supervision)?;
        let plan = self.stored_plan(project, supervision)?;
        match (record, plan) {
            (Some(_), Some(plan)) => {
                if plan.child.agent_id != reservation.child().agent_id()
                    || plan.child.session_id != reservation.child().session_id()
                {
                    return Ok(H4TaskStartOutcome::Reconcile {
                        supervision_id: supervision,
                        dispatch,
                        reason: H4ReconcileReason::ChildMismatch,
                    });
                }
                // The stored target must still be the approved launch.
                let record = self.load(project, supervision)?;
                let contract = plan.contract(&record, self.clock.now())?;
                authority.ensure_contract_binding(&contract, plan.budget_version)?;
                Ok(H4TaskStartOutcome::Ready {
                    view: Box::new(self.view(project, supervision)?),
                    created_target: false,
                    started_run: false,
                })
            }
            (None, None) => {
                let view = self.create_reserved_target(runtime, launch, reservation)?;
                Ok(H4TaskStartOutcome::Ready {
                    view: Box::new(view),
                    created_target: true,
                    started_run: false,
                })
            }
            (None, Some(plan)) => {
                // The create saved its plan but crashed before recording the
                // target. The plan, the reservation, and the approved launch
                // agree, so finish the one creation instead of waiting.
                if plan.child.agent_id != reservation.child().agent_id()
                    || plan.child.session_id != reservation.child().session_id()
                    || plan.contract.project_id() != project
                    || plan.contract.subject().owner() != &launch.owner()?
                {
                    return Ok(H4TaskStartOutcome::Reconcile {
                        supervision_id: supervision,
                        dispatch,
                        reason: H4ReconcileReason::TargetUnobservable,
                    });
                }
                let record = SupervisionRecord::new(&plan.contract);
                self.store
                    .compare_and_swap(project, supervision, None, &record)?;
                self.plans
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert((project, supervision), plan);
                self.set_restored(project, supervision, false);
                Ok(H4TaskStartOutcome::Ready {
                    view: Box::new(self.view(project, supervision)?),
                    created_target: true,
                    started_run: false,
                })
            }
            (Some(_), None) => Ok(H4TaskStartOutcome::Reconcile {
                supervision_id: supervision,
                dispatch,
                reason: H4ReconcileReason::TargetUnobservable,
            }),
        }
    }

    /// Builds the request-side H4 approval expectation for one launch.
    ///
    /// The profile and consent come from the live per-purpose configuration so a
    /// registry entry that names another profile, another consent, or a revoked
    /// consent cannot match. The H2-owned condition set, scope, and budget come
    /// from the launch request, which the coordinator builds from the stored
    /// approved contract.
    ///
    /// This is a request value, never an approval: it proves nothing until
    /// [`authorize_h4_owner_launch`] compares it with the current registry entry.
    /// The real approval registry (Task 13) and the tests use it to build the
    /// entry they compare against.
    pub fn h4_expected_approval(
        &self,
        launch: &H4TaskLaunch,
    ) -> Result<H4OwnerApproval, SupervisionError> {
        let project = launch.project_id();
        let owner = launch.owner()?;
        launch.ensure_owner_conditions(&owner)?;
        launch.ensure_conditions_current(self.clock.now())?;
        let config = self.config.get(project);
        let Some(profile) = config.profile(ProfilePurpose::Completion) else {
            return Err(SupervisionError::ProfileUnavailable {
                reason: herness_supervision::ProfileUnavailable::Unset {
                    purpose: ProfilePurpose::Completion,
                },
            });
        };
        let Some(consent) = config.consent(ProfilePurpose::Completion) else {
            return Err(SupervisionError::ConsentBlocked {
                reason: ConsentBlock::Revoked,
            });
        };
        consent.require_granted()?;
        if consent.target_scope_version() != launch.target_version() {
            return Err(SupervisionError::ConsentBlocked {
                reason: ConsentBlock::TargetScopeChanged,
            });
        }
        if !consent
            .scope()
            .data_kinds()
            .contains(&DisclosureDataKind::Text)
        {
            return Err(SupervisionError::ConsentBlocked {
                reason: ConsentBlock::ScopeExpanded {
                    added: vec![DisclosureDataKind::Text],
                },
            });
        }
        let expected_origin = self.connections.origin_for(profile.profile.connection())?;
        if consent.origin() != &expected_origin {
            return Err(SupervisionError::ConsentBlocked {
                reason: ConsentBlock::DifferentOrigin,
            });
        }
        let approval = launch.approval();
        H4OwnerApproval::new(
            project,
            owner,
            approval.execution().clone(),
            approval.task().clone(),
            approval.plan_revision(),
            approval.plan_digest().clone(),
            approval.packet().clone(),
            approval.pack_fingerprint().clone(),
            approval.commit(),
            launch.conditions().condition_version(),
            launch.conditions().digest().clone(),
            launch.execution_scope().clone(),
            profile.profile.binding(),
            consent.binding(),
            launch.budget_policy_version(),
            launch.budget().clone(),
        )
    }

    /// Builds and authorizes the current H4 approval expectation for one launch.
    pub fn h4_launch_authority(
        &self,
        registry: &dyn H4OwnerApprovalRegistryPort,
        launch: &H4TaskLaunch,
    ) -> Result<HostOwnerAuthority, SupervisionError> {
        let requested = self.h4_expected_approval(launch)?;
        let binding = H4OwnerLaunchBinding::new(launch.supervision_id(), requested)?;
        authorize_h4_owner_launch(registry, &binding, self.clock.now())
    }

    /// Creates the one target from an existing reservation.
    ///
    /// This mirrors [`SupervisionHost::create`] but takes the reserved
    /// supervision ID and child identity, the approved condition set, and the H4
    /// owner actor. It never calls `create_child` and never rewrites an existing
    /// plan or record.
    fn create_reserved_target(
        &mut self,
        runtime: &mut dyn DesktopSupervisionRuntime,
        launch: &H4TaskLaunch,
        reservation: &TaskReservation,
    ) -> Result<SupervisionView, SupervisionError> {
        let project = launch.project_id();
        let supervision_id = launch.supervision_id();
        let owner = launch.owner()?;
        launch.ensure_owner_conditions(&owner)?;
        let _ = runtime.project_path(project)?;
        let config = self.config.get(project);
        let Some(profile) = config.profile(ProfilePurpose::Completion) else {
            return Err(SupervisionError::ProfileUnavailable {
                reason: herness_supervision::ProfileUnavailable::Unset {
                    purpose: ProfilePurpose::Completion,
                },
            });
        };
        let Some(consent) = config.consent(ProfilePurpose::Completion) else {
            return Err(SupervisionError::ConsentBlocked {
                reason: ConsentBlock::Revoked,
            });
        };
        let now = self.clock.now();
        let workspace = ProjectWorkspace::new(runtime.project_path(project)?);
        let read_set = launch.execution_scope().read_paths().to_vec();
        let manifest = herness_supervision::freshness::capture_manifest(
            &workspace,
            project,
            launch.target_version(),
            TargetReadSet::Declared(read_set),
        )?;
        let evidence_target = manifest.target_scope()?;
        let subject = herness_supervision::SupervisionSubject::new(
            project,
            supervision_id,
            reservation.child().agent_id(),
            reservation.child().session_id(),
            owner.clone(),
        )?;
        let run_group =
            herness_supervision::RunGroup::new(herness_supervision::RunGroupId::new(project));
        let packet = WorkPacket::new(
            1,
            launch.instructions(),
            project,
            &evidence_target,
            launch.execution_scope().clone(),
            launch.conditions().condition_version(),
            profile.profile.binding(),
            consent.binding(),
            launch.budget_policy_version(),
            launch.budget().clone(),
        )?;
        let contract = SupervisionContract::new(
            ApprovalActor::ApprovedOwner {
                owner: owner.clone(),
                source: OwnerApprovalSource::H4ApprovedPlan,
            },
            subject,
            launch.execution_scope().clone(),
            run_group,
            launch.conditions().clone(),
            evidence_target.clone(),
            &profile.profile,
            consent,
            launch.budget().clone(),
            packet.clone(),
            now,
        )?;
        let plan = StoredPlan {
            format_version: PLAN_FORMAT_VERSION,
            actor: RequestActor::ApprovedOwner {
                owner: owner.clone(),
                source: OwnerApprovalSource::H4ApprovedPlan,
            },
            owner,
            child: ChildIdentity {
                agent_id: reservation.child().agent_id(),
                session_id: reservation.child().session_id(),
            },
            execution_scope: launch.execution_scope().clone(),
            conditions: launch.conditions().clone(),
            evidence_target,
            profile: profile.profile.clone(),
            consent: consent.clone(),
            budget: BudgetSnapshot::from_policy(launch.budget()),
            budget_version: launch.budget_policy_version(),
            packet,
            contract: contract.clone(),
        };
        save_plan(&self.store, project, supervision_id, &plan)?;
        let record = SupervisionRecord::new(&contract);
        self.store
            .compare_and_swap(project, supervision_id, None, &record)?;
        self.plans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert((project, supervision_id), plan);
        self.set_restored(project, supervision_id, false);
        self.view(project, supervision_id)
    }
}

fn ensure_reservation_matches(
    reservation: &TaskReservation,
    launch: &H4TaskLaunch,
) -> Result<(), SupervisionError> {
    if reservation.execution_id() != launch.execution()
        || reservation.task() != launch.task()
        || reservation.supervision_id() != launch.supervision_id()
        || reservation.request_id() != launch.dispatch()
    {
        return Err(supervision_reason(
            OwnerLaunchRejection::ReservationConflict,
        ));
    }
    Ok(())
}

fn intent_key(project: ProjectId, dispatch: DispatchRequestId) -> String {
    format!("h4.task.launch.intent:{project}:{dispatch}")
}

/// Start request ID derived from the dispatch request.
///
/// The same dispatch request always yields the same H2 command request, so a
/// re-delivered start is answered from the command journal instead of starting a
/// second run.
pub fn h4_start_request_id(
    project: ProjectId,
    dispatch: DispatchRequestId,
) -> SupervisionRequestId {
    SupervisionRequestId::from_parts(
        project,
        deterministic_uuid(&["h4.task.start", &dispatch.to_string()]),
    )
}

fn deterministic_uuid(parts: &[&str]) -> Uuid {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn cross_project(expected: ProjectId, found: ProjectId) -> SupervisionError {
    SupervisionError::CrossProjectReference {
        id_kind: "H4 Task launch".to_owned(),
        expected,
        found,
    }
}

fn supervision_reason(reason: OwnerLaunchRejection) -> SupervisionError {
    SupervisionError::OwnerLaunchRejected { reason }
}

fn storage(error: herness_store::StoreError) -> SupervisionError {
    SupervisionError::from(error)
}

fn sdd(error: herness_sdd_execute::SddExecutionError) -> SupervisionError {
    match error {
        herness_sdd_execute::SddExecutionError::CrossProjectReference {
            id_kind,
            expected,
            found,
        } => SupervisionError::CrossProjectReference {
            id_kind,
            expected,
            found,
        },
        other => SupervisionError::InvalidValue {
            field: "h4Launch".to_owned(),
            detail: other.to_string(),
        },
    }
}
