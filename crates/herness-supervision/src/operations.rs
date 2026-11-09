//! Explicit human supervision operations.
//!
//! Stop, cancel, resume, reassess, and version/limit changes are host-owned
//! commands. Every command carries one idempotent request ID, checks the
//! expected record revision, and commits through the store's compare-and-swap
//! plus command journal. A duplicate request returns the recorded result
//! without a second stop, resume, run, or notification. A stale revision
//! performs no mutation.
//!
//! Resume and reassessment are allowed only from `stopped` or `waiting_human`
//! after recovery finds no unresolved request, operation, managed process,
//! unconfirmed stop, missing/ambiguous checkpoint, unknown money reservation,
//! or stale version/limit. Consumed budget is never reset. A resume clears old
//! run/input identifiers so a previous input or approval is not replayed.

use herness_core::contracts::{ProjectId, RunId, Timestamp};

use crate::budget::ledger::{BudgetClockPort, BudgetLedger};
use crate::budget::{BudgetPolicy, BudgetUsage};
use crate::command::{CommandResult, SupervisionCommand};
use crate::conditions::ConditionSet;
use crate::consent::ConsentBinding;
use crate::contract::SupervisionContract;
use crate::error::{OwnerSupersessionRejection, SupervisionError};
use crate::evidence::TargetVersion;
use crate::ids::{SupervisionId, SupervisionRequestId, verify_scoped};
use crate::owner_launch::HostOwnerAuthority;
use crate::ports::{BudgetStorePort, ClockPort, StoredBudgetRecord};
use crate::profiles::ProfileBinding;
use crate::recovery::{
    RecoveryBlockReason, RecoveryBudgetRead, RecoveryFactsPort, RecoveryReport,
    RecoveryRuntimePort, RecoveryService, RecoveryStopState,
};
use crate::state::{
    CancelCause, ChangeKind, HumanAction, StopCause, SupervisionChangeRecord, SupervisionReason,
    SupervisionRecord, SupervisionState,
};
use crate::supervisor::{StopDisposition, SupervisorPhase};

/// One explicit human operation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum HumanOperation {
    /// Resume from stopped/waiting after the cause is resolved.
    Resume,
    /// Re-run verification/assessment without replaying an old input.
    Reassess,
    /// Stop the current run and supervision target.
    Stop,
    /// Cancel the supervision target. History and artifacts are retained.
    Cancel,
    /// Change approved conditions, target, profile, consent, or limit.
    Change(SupervisionChange),
}

/// One explicit approved version/limit change.
#[derive(Debug, Clone, PartialEq)]
pub enum SupervisionChange {
    /// Approved conditions and required checks at a newer version.
    Conditions(ConditionSet),
    /// New evidence target version.
    Target(TargetVersion),
    /// New assessment profile binding.
    Profile(ProfileBinding),
    /// New disclosure consent binding.
    Consent(ConsentBinding),
    /// New finite budget policy and strictly newer policy version.
    Budget {
        /// Approved finite policy.
        policy: BudgetPolicy,
        /// New durable policy version.
        policy_version: u64,
    },
}

/// One idempotent host-owned operation request.
#[derive(Debug, Clone, PartialEq)]
pub struct SupervisionOperationRequest {
    request_id: SupervisionRequestId,
    supervision_id: SupervisionId,
    operation: HumanOperation,
    expected_revision: u64,
}

impl SupervisionOperationRequest {
    /// Creates a request whose IDs share one project.
    pub fn new(
        request_id: SupervisionRequestId,
        supervision_id: SupervisionId,
        operation: HumanOperation,
        expected_revision: u64,
    ) -> Result<Self, SupervisionError> {
        let project = request_id.project_id();
        verify_scoped(&request_id, project)?;
        verify_scoped(&supervision_id, project)?;
        if expected_revision == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "expectedRevision".to_owned(),
                detail: "revisions start at 1".to_owned(),
            });
        }
        Ok(Self {
            request_id,
            supervision_id,
            operation,
            expected_revision,
        })
    }

    /// Host-owned idempotent request ID.
    pub const fn request_id(&self) -> SupervisionRequestId {
        self.request_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Requested operation.
    pub const fn operation(&self) -> &HumanOperation {
        &self.operation
    }

    /// Revision the caller last observed.
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    /// Project that owns the request.
    pub const fn project_id(&self) -> ProjectId {
        self.request_id.project_id()
    }

    fn command(&self) -> SupervisionCommand {
        match self.operation {
            HumanOperation::Resume => SupervisionCommand::Resume,
            HumanOperation::Reassess => SupervisionCommand::Reassess,
            HumanOperation::Stop | HumanOperation::Cancel => SupervisionCommand::Stop,
            HumanOperation::Change(_) => SupervisionCommand::Change,
        }
    }
}

/// Outcome of one operation call.
#[derive(Debug, Clone)]
pub struct OperationResult {
    command: CommandResult,
    duplicate: bool,
    recovery: Option<RecoveryReport>,
}

impl OperationResult {
    /// Committed or recorded command result.
    pub const fn command(&self) -> &CommandResult {
        &self.command
    }

    /// Whether the request ID already had the same result.
    pub const fn duplicate(&self) -> bool {
        self.duplicate
    }

    /// Recovery gate evidence for resume/reassessment.
    pub const fn recovery(&self) -> Option<&RecoveryReport> {
        self.recovery.as_ref()
    }
}

/// One host-owned approved-owner generation replacement.
///
/// The request carries the exact replacement contract. It cannot be built from
/// an owner kind or a serializable approval alone: the host also has to supply
/// a [`HostOwnerAuthority`] minted for the replacement contract by the current
/// owner registry.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnerSupersessionRequest {
    request_id: SupervisionRequestId,
    supervision_id: SupervisionId,
    expected_revision: u64,
    new_contract: SupervisionContract,
}

impl OwnerSupersessionRequest {
    /// Binds one idempotent request ID to the replacement contract.
    pub fn new(
        request_id: SupervisionRequestId,
        supervision_id: SupervisionId,
        expected_revision: u64,
        new_contract: SupervisionContract,
    ) -> Result<Self, SupervisionError> {
        let project = request_id.project_id();
        verify_scoped(&request_id, project)?;
        verify_scoped(&supervision_id, project)?;
        if supervision_id != new_contract.subject().supervision_id() {
            return Err(SupervisionError::OwnerSupersessionRejected {
                reason: OwnerSupersessionRejection::TargetMismatch,
            });
        }
        if expected_revision == 0 {
            return Err(SupervisionError::InvalidValue {
                field: "expectedRevision".to_owned(),
                detail: "revisions start at 1".to_owned(),
            });
        }
        Ok(Self {
            request_id,
            supervision_id,
            expected_revision,
            new_contract,
        })
    }

    /// Host-owned idempotent request ID.
    pub const fn request_id(&self) -> SupervisionRequestId {
        self.request_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Revision the owner last observed.
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    /// Exact replacement contract built by the host composition.
    pub const fn new_contract(&self) -> &SupervisionContract {
        &self.new_contract
    }

    /// Project that owns the request.
    pub const fn project_id(&self) -> ProjectId {
        self.request_id.project_id()
    }
}

/// Read/stop budget operations needed by explicit human commands.
///
/// A durable [`BudgetLedger`] implements this. The supervisor port remains the
/// authority for consumed run/active-time accounting; this view adds the
/// effective usage snapshot and an explicit policy version change.
pub trait OperationBudgetPort: RecoveryBudgetRead {
    /// Effective usage including the open active interval.
    fn budget_usage(&mut self) -> Result<BudgetUsage, SupervisionError>;

    /// Stops active-time accrual for a terminal state.
    fn app_stop(&mut self) -> Result<(), SupervisionError>;

    /// Replaces the finite policy after a human change.
    fn change_policy(
        &mut self,
        policy: BudgetPolicy,
        policy_version: u64,
    ) -> Result<(), SupervisionError>;
}

impl<S: BudgetStorePort, C: BudgetClockPort> RecoveryBudgetRead for BudgetLedger<S, C> {
    fn load_recovery_budget(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Option<StoredBudgetRecord>, SupervisionError> {
        self.store_mut().load_budget(project_id, supervision_id)
    }

    fn mark_recovery_waiting_human(&mut self) -> Result<(), SupervisionError> {
        BudgetLedger::wait_for_human(self)
    }

    fn mark_recovery_app_stopped(&mut self) -> Result<(), SupervisionError> {
        BudgetLedger::app_stop(self)
    }
}

impl<S: BudgetStorePort, C: BudgetClockPort> OperationBudgetPort for BudgetLedger<S, C> {
    fn budget_usage(&mut self) -> Result<BudgetUsage, SupervisionError> {
        self.effective_usage()
    }

    fn app_stop(&mut self) -> Result<(), SupervisionError> {
        BudgetLedger::app_stop(self)
    }

    fn change_policy(
        &mut self,
        policy: BudgetPolicy,
        policy_version: u64,
    ) -> Result<(), SupervisionError> {
        BudgetLedger::change_policy(self, policy, policy_version)
    }
}

/// H1 runtime reads plus one cooperative stop request.
///
/// Recovery never calls the stop method. Explicit stop/cancel and version/limit
/// changes do, and they never claim a stop that H1 did not confirm.
pub trait OperationRuntimePort: RecoveryRuntimePort {
    /// Requests a cooperative stop and reports whether H1 confirmed it.
    fn request_stop(&mut self, run: RunId) -> Result<StopDisposition, SupervisionError>;
}

/// Ports used by one explicit human operation.
pub struct OperationPorts<'a> {
    /// Durable facts and record/command store.
    pub store: &'a mut dyn RecoveryFactsPort,
    /// H1 runtime reads and cooperative stop.
    pub runtime: &'a mut dyn OperationRuntimePort,
    /// Durable budget usage and explicit policy change.
    pub budget: &'a mut dyn OperationBudgetPort,
    /// Host clock.
    pub clock: &'a dyn ClockPort,
}

/// Executes one explicit human operation idempotently.
pub fn execute_operation(
    ports: OperationPorts<'_>,
    contract: &SupervisionContract,
    expected_policy_version: u64,
    request: SupervisionOperationRequest,
) -> Result<OperationResult, SupervisionError> {
    let OperationPorts {
        store,
        runtime,
        budget,
        clock,
    } = ports;

    if let Some(recorded) = store.command_result(request.request_id())? {
        if recorded.supervision_id() != request.supervision_id()
            || recorded.command() != request.command()
        {
            return Err(SupervisionError::DuplicateRequestConflict {
                request: request.request_id().to_string(),
                recorded: recorded.command().as_str().to_owned(),
                supplied: request.command().as_str().to_owned(),
            });
        }
        return Ok(OperationResult {
            command: recorded,
            duplicate: true,
            recovery: None,
        });
    }

    let project = request.project_id();
    let current = store
        .load(project, request.supervision_id())?
        .ok_or(SupervisionError::UnknownSupervision)?;
    if current.revision() != request.expected_revision() {
        return Err(SupervisionError::RevisionConflict {
            expected: request.expected_revision(),
            found: current.revision(),
        });
    }

    // A terminal record keeps its recorded outcome. Repeated stop/cancel calls
    // are recorded for idempotency but never create another transition. A
    // version/limit change on a stopped record is still an explicit human
    // operation and falls through to the change path.
    let terminal = matches!(
        current.state(),
        SupervisionState::Completed | SupervisionState::Failed | SupervisionState::Cancelled
    ) || (current.state() == SupervisionState::Stopped
        && matches!(
            request.operation(),
            HumanOperation::Stop | HumanOperation::Cancel
        ));
    if terminal
        && !matches!(
            request.operation(),
            HumanOperation::Resume | HumanOperation::Reassess
        )
    {
        let result = CommandResult::new(
            request.request_id(),
            project,
            request.supervision_id(),
            request.command(),
            current.revision(),
            current.state(),
            current.reason().clone(),
        )?;
        let command = store.record_command_result(&result)?;
        return Ok(OperationResult {
            command,
            duplicate: false,
            recovery: None,
        });
    }

    let mut report = None;
    let mut next = match request.operation() {
        HumanOperation::Stop | HumanOperation::Cancel => {
            stop_or_cancel(&current, request.operation(), &mut *runtime, &mut *budget)?
        }
        HumanOperation::Resume | HumanOperation::Reassess => {
            let recovery = {
                let mut service =
                    RecoveryService::new(&mut *store, &mut *runtime, &mut *budget, clock);
                service.recover(contract, expected_policy_version)?
            };
            if !matches!(
                current.state(),
                SupervisionState::Stopped | SupervisionState::WaitingHuman
            ) {
                return Err(SupervisionError::NotResumable {
                    reasons: vec![RecoveryBlockReason::StateNotResumable {
                        state: current.state(),
                    }],
                });
            }
            if !recovery.resumable() {
                let mut reasons = recovery.block_reasons().to_vec();
                if reasons.is_empty() {
                    reasons.push(RecoveryBlockReason::StateNotResumable {
                        state: current.state(),
                    });
                }
                return Err(SupervisionError::NotResumable { reasons });
            }
            let mut next = current.clone();
            if matches!(request.operation(), HumanOperation::Resume) {
                next.reset_for_resume();
            } else {
                next.reset_for_reassess()?;
            }
            next.supervisor_mut().phase = match request.operation() {
                HumanOperation::Resume => SupervisorPhase::Idle,
                _ => SupervisorPhase::Evaluating,
            };
            report = Some(recovery);
            next
        }
        HumanOperation::Change(change) => {
            apply_change(&current, change, &mut *runtime, &mut *budget, clock.now())?
        }
    };

    next.set_command_revision(current.revision().saturating_add(1));
    let result = CommandResult::new(
        request.request_id(),
        project,
        request.supervision_id(),
        request.command(),
        next.revision(),
        next.state(),
        next.reason().clone(),
    )?;
    match store.commit_command(
        project,
        request.supervision_id(),
        Some(current.revision()),
        &next,
        &result,
    ) {
        Ok(revision) => Ok(OperationResult {
            command: CommandResult::new(
                result.request_id(),
                result.project_id(),
                result.supervision_id(),
                result.command(),
                revision,
                result.state(),
                result.reason().clone(),
            )?,
            duplicate: false,
            recovery: report,
        }),
        Err(SupervisionError::RevisionConflict { .. }) => {
            let found = store
                .load(project, request.supervision_id())?
                .map_or(current.revision(), |record| record.revision());
            Err(SupervisionError::RevisionConflict {
                expected: current.revision(),
                found,
            })
        }
        Err(error) => Err(error),
    }
}

/// Rejects owner supersession when a durable stop or human latch is set.
///
/// This is the shared latch check used by the host composition and the
/// operation itself. It never clears the latch and never resumes anything.
pub fn ensure_owner_supersedable(
    record: &SupervisionRecord,
) -> Result<(), SupervisionError> {
    match record.state() {
        SupervisionState::Ready
        | SupervisionState::Running
        | SupervisionState::Verifying
        | SupervisionState::Assessing => Ok(()),
        SupervisionState::WaitingHuman => {
            let action = match record.reason() {
                SupervisionReason::WaitingHuman { action } => *action,
                SupervisionReason::ConditionsChanged { .. } => HumanAction::ConfirmConditions,
                SupervisionReason::TargetChanged { .. } => HumanAction::ConfirmTarget,
                _ => HumanAction::ReconcileRecovery,
            };
            Err(rejected_supersession(
                OwnerSupersessionRejection::HumanWaiting { action },
            ))
        }
        SupervisionState::Stopped => {
            let reason = match record.reason() {
                SupervisionReason::Stopped { cause } => match cause {
                    StopCause::UserRequest => OwnerSupersessionRejection::HumanStopped,
                    StopCause::Stagnation => OwnerSupersessionRejection::Stagnated,
                    StopCause::Budget(limit) => {
                        OwnerSupersessionRejection::BudgetExhausted { limit: *limit }
                    }
                    StopCause::StopUnconfirmed => OwnerSupersessionRejection::StopUnconfirmed,
                    StopCause::RecoveryReconciliation => {
                        OwnerSupersessionRejection::RecoveryPending
                    }
                },
                _ => OwnerSupersessionRejection::RecoveryPending,
            };
            Err(rejected_supersession(reason))
        }
        SupervisionState::Failed => Err(rejected_supersession(OwnerSupersessionRejection::Failed)),
        SupervisionState::Cancelled => {
            Err(rejected_supersession(OwnerSupersessionRejection::Cancelled))
        }
        SupervisionState::Completed => {
            Err(rejected_supersession(OwnerSupersessionRejection::Completed))
        }
    }
}

/// Executes one approved-owner generation replacement in the same target.
///
/// The operation keeps the stored run group, decision history, and durable
/// budget ledger. It stops and confirms the current run before changing the
/// target version, invalidates every applied decision, and returns the record
/// to `ready` so the host can start exactly one run in the same conversation.
///
/// A duplicate request ID returns the recorded result before any load, stop,
/// budget change, or commit. Every latch (human stop/wait, stagnation, budget,
/// recovery, unconfirmed stop, cancellation) is checked before the stop and
/// before the replacement contract is applied.
pub fn execute_owner_supersession(
    ports: OperationPorts<'_>,
    current_contract: &SupervisionContract,
    expected_policy_version: u64,
    request: OwnerSupersessionRequest,
    authority: HostOwnerAuthority,
) -> Result<OperationResult, SupervisionError> {
    let OperationPorts {
        store,
        runtime,
        budget,
        clock,
    } = ports;

    if let Some(recorded) = store.command_result(request.request_id())? {
        if recorded.project_id() != request.project_id()
            || recorded.supervision_id() != request.supervision_id()
            || recorded.command() != SupervisionCommand::Supersede
        {
            return Err(SupervisionError::DuplicateRequestConflict {
                request: request.request_id().to_string(),
                recorded: recorded.command().as_str().to_owned(),
                supplied: SupervisionCommand::Supersede.as_str().to_owned(),
            });
        }
        return Ok(OperationResult {
            command: recorded,
            duplicate: true,
            recovery: None,
        });
    }

    let project = request.project_id();
    let supervision = request.supervision_id();
    let current = store
        .load(project, supervision)?
        .ok_or(SupervisionError::UnknownSupervision)?;
    if current.revision() != request.expected_revision() {
        return Err(SupervisionError::RevisionConflict {
            expected: request.expected_revision(),
            found: current.revision(),
        });
    }

    ensure_current_generation(&current, current_contract, expected_policy_version)?;
    if authority.project_id() != project || authority.supervision_id() != supervision {
        return Err(rejected_supersession(
            OwnerSupersessionRejection::TargetMismatch,
        ));
    }

    let new_contract = request.new_contract();
    let new_policy_version = new_contract.work_packet().budget_policy_version();
    authority.ensure_contract_binding(new_contract, new_policy_version)?;

    let now = clock.now();
    ensure_replacement_generation(
        &current,
        current_contract,
        new_contract,
        expected_policy_version,
        now,
    )?;
    ensure_owner_supersedable(&current)?;

    // Recovery is a latch, not a side effect: unresolved requests/operations/
    // processes, stale permission context, or an exhausted budget block the
    // owner replacement exactly as they block a human resume.
    let recovery = {
        let mut service = RecoveryService::new(&mut *store, &mut *runtime, &mut *budget, clock);
        service.recover(current_contract, expected_policy_version)?
    };
    if let Some(reason) = supersession_recovery_rejection(&recovery) {
        return Err(rejected_supersession(reason));
    }

    // The current run must be stopped and confirmed before the target version
    // or packet can change.
    let run = current
        .supervisor()
        .current_run()
        .or_else(|| current.run_group().runs().last().copied());
    if let Some(run) = run {
        let confirmed = match runtime.stop_state(run)? {
            RecoveryStopState::Confirmed => true,
            RecoveryStopState::Unconfirmed => false,
            RecoveryStopState::NotRequested => {
                !matches!(runtime.request_stop(run)?, StopDisposition::Unconfirmed)
            }
        };
        if !confirmed {
            return Err(rejected_supersession(
                OwnerSupersessionRejection::StopUnconfirmed,
            ));
        }
    }

    let budget_before = budget.budget_usage()?;
    let policy_changed = new_contract.budget() != current_contract.budget();
    if policy_changed {
        if new_policy_version <= expected_policy_version {
            return Err(rejected_supersession(
                OwnerSupersessionRejection::BudgetMismatch,
            ));
        }
        budget.change_policy(new_contract.budget().clone(), new_policy_version)?;
    } else if new_policy_version != expected_policy_version {
        return Err(rejected_supersession(
            OwnerSupersessionRejection::BudgetMismatch,
        ));
    }

    let actor = replacement_actor(new_contract)?;
    let mut next = current.clone();
    next.apply_generation(new_contract)?;
    budget.app_stop()?;
    let budget_after = budget.budget_usage()?;
    next.push_change(SupervisionChangeRecord::new(
        ChangeKind::Supersede,
        actor,
        generation_label(&current),
        generation_label_for_contract(new_contract),
        budget_before,
        budget_after,
        now,
    ));
    next.set_command_revision(current.revision().saturating_add(1));
    let result = CommandResult::new(
        request.request_id(),
        project,
        supervision,
        SupervisionCommand::Supersede,
        next.revision(),
        next.state(),
        next.reason().clone(),
    )?;
    match store.commit_command(
        project,
        supervision,
        Some(current.revision()),
        &next,
        &result,
    ) {
        Ok(revision) => Ok(OperationResult {
            command: CommandResult::new(
                result.request_id(),
                result.project_id(),
                result.supervision_id(),
                result.command(),
                revision,
                result.state(),
                result.reason().clone(),
            )?,
            duplicate: false,
            recovery: None,
        }),
        Err(SupervisionError::RevisionConflict { .. }) => {
            let found = store
                .load(project, supervision)?
                .map_or(current.revision(), |record| record.revision());
            Err(SupervisionError::RevisionConflict {
                expected: current.revision(),
                found,
            })
        }
        Err(error) => Err(error),
    }
}

fn ensure_current_generation(
    record: &SupervisionRecord,
    contract: &SupervisionContract,
    expected_policy_version: u64,
) -> Result<(), SupervisionError> {
    if contract.project_id() != record.project_id()
        || contract.subject().supervision_id() != record.supervision_id()
        || contract.conditions().condition_version() != record.condition_version()
        || contract.conditions().condition_ids() != record.condition_ids().to_vec()
        || contract
            .conditions()
            .checks()
            .iter()
            .map(|check| check.id())
            .collect::<Vec<_>>()
            != record.required_checks().to_vec()
        || contract.evidence_target().version() != record.target_version()
        || contract.profile() != record.profile()
        || contract.consent() != record.consent()
        || contract.work_packet().budget_policy_version() != expected_policy_version
    {
        return Err(rejected_supersession(
            OwnerSupersessionRejection::TargetMismatch,
        ));
    }
    Ok(())
}

fn ensure_replacement_generation(
    record: &SupervisionRecord,
    current: &SupervisionContract,
    replacement: &SupervisionContract,
    expected_policy_version: u64,
    now: Timestamp,
) -> Result<(), SupervisionError> {
    replacement_actor(replacement)?;
    if replacement.project_id() != record.project_id()
        || replacement.subject().supervision_id() != record.supervision_id()
        || replacement.subject().owner() != current.subject().owner()
        || replacement.subject().agent_id() != current.subject().agent_id()
        || replacement.subject().session_id() != current.subject().session_id()
    {
        return Err(rejected_supersession(
            OwnerSupersessionRejection::SubjectMismatch,
        ));
    }
    replacement.validate_for_start(now)?;
    if replacement.evidence_target().version() <= record.target_version() {
        return Err(rejected_supersession(
            OwnerSupersessionRejection::TargetUnchanged,
        ));
    }
    let replacement_version = replacement.conditions().condition_version();
    if replacement_version < record.condition_version()
        || (replacement_version == record.condition_version()
            && (replacement.conditions().condition_ids() != record.condition_ids().to_vec()
                || replacement
                    .conditions()
                    .checks()
                    .iter()
                    .map(|check| check.id())
                    .collect::<Vec<_>>()
                    != record.required_checks().to_vec()))
    {
        return Err(rejected_supersession(
            OwnerSupersessionRejection::ConditionsMismatch,
        ));
    }
    if replacement.work_packet().packet_version()
        <= current.work_packet().packet_version()
    {
        return Err(rejected_supersession(
            OwnerSupersessionRejection::ConditionsMismatch,
        ));
    }
    let replacement_policy_version = replacement.work_packet().budget_policy_version();
    if replacement.budget() == current.budget() {
        if replacement_policy_version != expected_policy_version {
            return Err(rejected_supersession(
                OwnerSupersessionRejection::BudgetMismatch,
            ));
        }
    } else if replacement_policy_version <= expected_policy_version {
        return Err(rejected_supersession(
            OwnerSupersessionRejection::BudgetMismatch,
        ));
    }
    Ok(())
}

fn replacement_actor(
    contract: &SupervisionContract,
) -> Result<crate::approval::ApprovalActor, SupervisionError> {
    use crate::approval::{ApprovalActor, ApprovalBasis, OwnerApprovalSource};

    let approval = contract
        .conditions()
        .approval()
        .ok_or_else(|| rejected_supersession(OwnerSupersessionRejection::ConditionsMismatch))?;
    let (owner, source) = match approval.basis() {
        ApprovalBasis::InheritedOwner { owner, source, .. } => (owner.clone(), *source),
        ApprovalBasis::ExplicitHuman { .. } => {
            return Err(rejected_supersession(
                OwnerSupersessionRejection::SubjectMismatch,
            ));
        }
    };
    if &owner != contract.subject().owner() || !owner.is_approved_owner() {
        return Err(rejected_supersession(
            OwnerSupersessionRejection::SubjectMismatch,
        ));
    }
    if !matches!(
        (owner.kind(), source),
        (
            crate::contract::OwnerKind::H3HtmlJob,
            OwnerApprovalSource::H3ApprovedSettings
        ) | (
            crate::contract::OwnerKind::H4SddTask,
            OwnerApprovalSource::H4ApprovedPlan
        )
    ) {
        return Err(rejected_supersession(
            OwnerSupersessionRejection::SubjectMismatch,
        ));
    }
    Ok(ApprovalActor::ApprovedOwner { owner, source })
}

fn supersession_recovery_rejection(
    report: &RecoveryReport,
) -> Option<OwnerSupersessionRejection> {
    for reason in report.block_reasons() {
        match reason {
            RecoveryBlockReason::BudgetExhausted { limit } => {
                return Some(OwnerSupersessionRejection::BudgetExhausted { limit: *limit });
            }
            RecoveryBlockReason::StopUnconfirmed { .. } => {
                return Some(OwnerSupersessionRejection::StopUnconfirmed);
            }
            _ => return Some(OwnerSupersessionRejection::RecoveryPending),
        }
    }
    None
}

fn generation_label(record: &SupervisionRecord) -> String {
    format!(
        "generation:target:{}:conditions:{}:profile:{}:consent:{}",
        record.target_version().get(),
        record.condition_version().get(),
        record.profile().profile_id(),
        record.consent().consent_id()
    )
}

fn generation_label_for_contract(contract: &SupervisionContract) -> String {
    format!(
        "generation:target:{}:conditions:{}:profile:{}:consent:{}:packet:{}",
        contract.evidence_target().version().get(),
        contract.conditions().condition_version().get(),
        contract.profile().profile_id(),
        contract.consent().consent_id(),
        contract.work_packet().packet_version()
    )
}

fn rejected_supersession(reason: OwnerSupersessionRejection) -> SupervisionError {
    SupervisionError::OwnerSupersessionRejected { reason }
}

fn stop_or_cancel(
    record: &SupervisionRecord,
    operation: &HumanOperation,
    runtime: &mut dyn OperationRuntimePort,
    budget: &mut dyn OperationBudgetPort,
) -> Result<SupervisionRecord, SupervisionError> {
    let mut next = record.clone();
    let run = record
        .supervisor()
        .current_run()
        .or_else(|| record.run_group().runs().last().copied());
    let unconfirmed = if let Some(run) = run {
        matches!(runtime.request_stop(run)?, StopDisposition::Unconfirmed)
    } else {
        false
    };
    if matches!(operation, HumanOperation::Cancel) && !unconfirmed {
        next.cancel(CancelCause::UserRequest)?;
    } else {
        next.stop(if unconfirmed {
            StopCause::StopUnconfirmed
        } else {
            StopCause::UserRequest
        })?;
    }
    next.supervisor_mut().phase = SupervisorPhase::Finished;
    next.supervisor_mut().pending_assessment = None;
    budget.app_stop()?;
    Ok(next)
}

fn apply_change(
    record: &SupervisionRecord,
    change: &SupervisionChange,
    runtime: &mut dyn OperationRuntimePort,
    budget: &mut dyn OperationBudgetPort,
    now: Timestamp,
) -> Result<SupervisionRecord, SupervisionError> {
    let mut next = record.clone();

    // A version/limit change stops the current run first. An unconfirmed stop
    // blocks the change rather than applying it under a possibly running child.
    let run = record
        .supervisor()
        .current_run()
        .or_else(|| record.run_group().runs().last().copied());
    if let Some(run) = run {
        let stop = runtime.stop_state(run)?;
        let confirmed = match stop {
            RecoveryStopState::Confirmed => true,
            RecoveryStopState::Unconfirmed => false,
            RecoveryStopState::NotRequested => {
                !matches!(runtime.request_stop(run)?, StopDisposition::Unconfirmed)
            }
        };
        if !confirmed {
            next.stop(StopCause::StopUnconfirmed)?;
            next.supervisor_mut().phase = SupervisorPhase::Finished;
            next.supervisor_mut().pending_assessment = None;
            budget.app_stop()?;
            return Ok(next);
        }
    }

    let before = before_label(record);
    let budget_before = budget.budget_usage()?;
    match change {
        SupervisionChange::Conditions(conditions) => {
            conditions.ensure_project(record.project_id())?;
            conditions.require_approval(now)?;
            next.revise_conditions(
                crate::approval::ApprovalActor::Human,
                conditions.condition_version(),
                conditions.condition_ids(),
                conditions.checks().iter().map(|check| check.id()).collect(),
            )?;
        }
        SupervisionChange::Target(version) => {
            next.revise_target(crate::approval::ApprovalActor::Human, *version)?;
        }
        SupervisionChange::Profile(profile) => {
            next.revise_profile(crate::approval::ApprovalActor::Human, *profile)?;
        }
        SupervisionChange::Consent(consent) => {
            next.revise_consent(crate::approval::ApprovalActor::Human, *consent)?;
        }
        SupervisionChange::Budget {
            policy,
            policy_version,
        } => {
            budget.change_policy(policy.clone(), *policy_version)?;
            next.wait_for_human(HumanAction::ReconcileRecovery)?;
        }
    }
    let budget_after = budget.budget_usage()?;
    next.supervisor_mut().phase = SupervisorPhase::Finished;
    next.supervisor_mut().pending_assessment = None;
    let kind = match change {
        SupervisionChange::Conditions(_) => ChangeKind::Conditions,
        SupervisionChange::Target(_) => ChangeKind::Target,
        SupervisionChange::Profile(_) => ChangeKind::Profile,
        SupervisionChange::Consent(_) => ChangeKind::Consent,
        SupervisionChange::Budget { .. } => ChangeKind::Budget,
    };
    next.push_change(SupervisionChangeRecord::new(
        kind,
        crate::approval::ApprovalActor::Human,
        before,
        after_label(change),
        budget_before,
        budget_after,
        now,
    ));
    budget.app_stop()?;
    Ok(next)
}

fn before_label(record: &SupervisionRecord) -> String {
    format!(
        "conditions:{}:target:{}:profile:{}:consent:{}",
        record.condition_version().get(),
        record.target_version().get(),
        record.profile().profile_id(),
        record.consent().consent_id()
    )
}

fn after_label(change: &SupervisionChange) -> String {
    match change {
        SupervisionChange::Conditions(conditions) => {
            format!("conditions:{}", conditions.condition_version().get())
        }
        SupervisionChange::Target(version) => format!("target:{}", version.get()),
        SupervisionChange::Profile(profile) => format!("profile:{}", profile.profile_id()),
        SupervisionChange::Consent(consent) => format!("consent:{}", consent.consent_id()),
        SupervisionChange::Budget {
            policy,
            policy_version,
        } => format!(
            "budget:{}:{}:{}",
            policy.active_seconds(),
            policy.max_total_runs(),
            policy_version
        ),
    }
}
