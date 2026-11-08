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
use crate::error::SupervisionError;
use crate::evidence::TargetVersion;
use crate::ids::{SupervisionId, SupervisionRequestId, verify_scoped};
use crate::ports::{BudgetStorePort, ClockPort, StoredBudgetRecord};
use crate::profiles::ProfileBinding;
use crate::recovery::{
    RecoveryBlockReason, RecoveryBudgetRead, RecoveryFactsPort, RecoveryReport,
    RecoveryRuntimePort, RecoveryService, RecoveryStopState,
};
use crate::state::{
    CancelCause, ChangeKind, HumanAction, StopCause, SupervisionChangeRecord, SupervisionRecord,
    SupervisionState,
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
