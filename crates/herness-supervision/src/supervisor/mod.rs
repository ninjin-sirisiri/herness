//! Deterministic supervision controller.
//!
//! One `Supervisor` advances one supervision target by at most one
//! deterministic step per [`Supervisor::tick`] call. It loads the current
//! record, checks the approved contract and all higher-priority stop/human/
//! budget states, performs at most one runtime, verification, or assessment
//! action, and commits the next record through the store's compare-and-swap or
//! atomic command hook. A stale revision, duplicate tick event, or late result
//! is rejected without a second mutation or notification.
//!
//! The controller never sends a model request itself: assessment is a port.
//! The H1 runtime, required-check execution, evidence storage, budget ledger,
//! clock, and owner notification are all injected side-effect boundaries.

pub mod ports;
pub mod state;

pub use ports::{
    AssessmentProfileFacts, CheckExecution, CheckExecutionRequest, ChildRunContinuation,
    ChildRunStart, ConditionAssessmentPort, ContinuationDeficiency, FailedCheck,
    OwnerNotificationPort, RequiredCheckPort, StopDisposition, SupervisionBudgetPort,
    SupervisionRuntimePort, SupervisorNotification, SupervisorPorts, TargetSnapshotRequest,
    capture_target_snapshot, target_read_set_from_manifest,
};
pub use state::{PendingAssessment, SupervisorPhase, SupervisorState};

use std::collections::BTreeSet;

use herness_core::contracts::{InputId, InputPhase, ProjectId, RunId, RunState, Timestamp};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::assessment::{AssessmentRequest, AssessmentResult};
use crate::budget::{BudgetLimit, H2_STAGNATION_CYCLES};
use crate::command::{CommandResult, SupervisionCommand};
use crate::conditions::{Condition, ConditionVersion, RequiredCheck};
use crate::contract::SupervisionContract;
use crate::error::SupervisionError;
use crate::evidence::{
    CheckStatus, ContentDigest, EvidenceRecord, RequiredCheckResult, TargetVersion,
};
use crate::freshness::TargetManifest;
use crate::ids::{
    BudgetRequestId, CheckId, ConditionId, DecisionId, EvidenceId, SupervisionId,
    SupervisionRequestId,
};
use crate::state::{
    CompletionSnapshot, DecisionInvalidation, HumanAction, StopCause, SupervisionFailure,
    SupervisionRecord, SupervisionState,
};

/// Project-scoped identifier of one committed tick event.
#[derive(Debug, Clone)]
pub struct TickRequest {
    event_id: SupervisionRequestId,
    contract: SupervisionContract,
}

impl TickRequest {
    /// Creates one tick request bound to the approved contract.
    pub fn new(
        event_id: SupervisionRequestId,
        contract: SupervisionContract,
    ) -> Result<Self, SupervisionError> {
        if event_id.project_id() != contract.project_id() {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "tick event".to_owned(),
                expected: contract.project_id(),
                found: event_id.project_id(),
            });
        }
        Ok(Self { event_id, contract })
    }

    /// Idempotent host event identifier.
    pub const fn event_id(&self) -> SupervisionRequestId {
        self.event_id
    }

    /// Approved contract passed by the host for this tick.
    pub const fn contract(&self) -> &SupervisionContract {
        &self.contract
    }
}

/// What one tick did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    /// Nothing needed to change.
    Noop,
    /// The same event was already committed; the recorded result was returned.
    Duplicate,
    /// One deterministic step was committed.
    Advanced,
    /// A run/input pair was started and the controller now waits for input
    /// completion.
    AwaitingInput,
    /// One assessment request was persisted or a result was applied.
    AwaitingAssessment,
    /// The compare-and-swap lost to a newer revision; nothing was written or
    /// notified.
    StaleRevision,
    /// A late result was kept only as history.
    StaleAssessment,
    /// Assessment was refused because a run is still active or its input has
    /// not completed.
    AssessmentRefused,
    /// A human action is now required.
    WaitingHuman,
    /// Supervision stopped.
    Stopped,
    /// Supervision failed unrecoverably.
    Failed,
    /// Supervision completed.
    Completed,
}

/// Committed revision and a small outcome summary for one tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickReport {
    outcome: TickOutcome,
    revision: u64,
    state: SupervisionState,
    notified: bool,
}

impl TickReport {
    /// What the tick did.
    pub const fn outcome(&self) -> TickOutcome {
        self.outcome
    }

    /// Stored revision observed after the tick.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Stored supervision state after the tick.
    pub const fn state(&self) -> SupervisionState {
        self.state
    }

    /// Whether this tick delivered one owner notification.
    pub const fn notified(&self) -> bool {
        self.notified
    }

    fn noop(record: &SupervisionRecord) -> Self {
        Self {
            outcome: TickOutcome::Noop,
            revision: record.revision(),
            state: record.state(),
            notified: false,
        }
    }

    fn refused(record: &SupervisionRecord) -> Self {
        Self {
            outcome: TickOutcome::AssessmentRefused,
            revision: record.revision(),
            state: record.state(),
            notified: false,
        }
    }
}

/// One controller over a fixed set of injected ports.
pub struct Supervisor<'a> {
    ports: SupervisorPorts<'a>,
}

impl<'a> Supervisor<'a> {
    /// Creates a controller over the injected side-effect boundaries.
    pub const fn new(ports: SupervisorPorts<'a>) -> Self {
        Self { ports }
    }

    /// Loads the record and performs at most the next deterministic step.
    pub fn tick(&mut self, request: TickRequest) -> Result<TickReport, SupervisionError> {
        let contract = request.contract();
        let project = contract.project_id();
        let supervision = contract.subject().supervision_id();
        let event_id = request.event_id();
        event_id.validate_in(project)?;

        if let Some(recorded) = self.ports.store.command_result(event_id)? {
            if recorded.project_id() != project || recorded.supervision_id() != supervision {
                return Err(SupervisionError::DuplicateRequestConflict {
                    request: event_id.to_string(),
                    recorded: recorded.command().as_str().to_owned(),
                    supplied: SupervisionCommand::Reassess.as_str().to_owned(),
                });
            }
            return Ok(TickReport {
                outcome: TickOutcome::Duplicate,
                revision: recorded.revision(),
                state: recorded.state(),
                notified: false,
            });
        }

        let Some(record) = self.ports.store.load(project, supervision)? else {
            return Err(SupervisionError::UnknownSupervision);
        };
        if record.project_id() != project || record.supervision_id() != supervision {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "supervision record".to_owned(),
                expected: project,
                found: record.project_id(),
            });
        }

        if matches!(
            record.state(),
            SupervisionState::WaitingHuman
                | SupervisionState::Stopped
                | SupervisionState::Failed
                | SupervisionState::Cancelled
                | SupervisionState::Completed
        ) {
            return Ok(TickReport::noop(&record));
        }

        if let Some(action) = contract_mismatch(&record, contract) {
            return self.wait_human(&record, record.clone(), &request, action);
        }

        match record.supervisor().phase() {
            SupervisorPhase::Idle => self.phase_idle(&record, &request),
            SupervisorPhase::StartingRun => self.phase_starting_run(&record, &request),
            SupervisorPhase::AwaitingInput => self.phase_awaiting_input(&record, &request),
            SupervisorPhase::Evaluating => match record.state() {
                SupervisionState::Verifying => self.phase_verifying(&record, &request),
                SupervisionState::Assessing => self.phase_assessing(&record, &request),
                _ => self.wait_human(
                    &record,
                    record.clone(),
                    &request,
                    HumanAction::ReconcileRecovery,
                ),
            },
            SupervisorPhase::Finished => Ok(TickReport::noop(&record)),
        }
    }

    // --- phases -----------------------------------------------------------

    fn phase_idle(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
    ) -> Result<TickReport, SupervisionError> {
        if record.state() != SupervisionState::Ready {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ReconcileRecovery,
            );
        }
        let contract = request.contract();
        if contract.conditions().require_approval(self.now()).is_err()
            || contract.validate_for_start(self.now()).is_err()
        {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ConfirmConditions,
            );
        }
        if !self.ports.budget.can_start_run()? {
            return self.stop(
                record,
                record.clone(),
                request,
                StopCause::Budget(BudgetLimit::RunCount),
            );
        }
        if self.ports.budget.remaining_active_seconds()? == 0 {
            return self.stop(
                record,
                record.clone(),
                request,
                StopCause::Budget(BudgetLimit::ActiveSeconds),
            );
        }
        let manifest = self.snapshot(record, contract)?;
        if !manifest.coverage().is_complete() {
            return self.wait_human(record, record.clone(), request, HumanAction::ConfirmTarget);
        }
        let digest = manifest.manifest_digest()?;
        let evidence = self.evidence_list(record)?;
        let baseline = self.progress_fingerprint(record, &manifest, &evidence)?;

        let ordinal = record.run_group().runs().len() as u64 + 1;
        let run = derive_run_id(record.project_id(), record.supervision_id(), ordinal);
        let input = derive_input_id(record.project_id(), record.supervision_id(), ordinal);
        let budget_request =
            derive_budget_request_id(record.project_id(), record.supervision_id(), ordinal);

        let mut next = record.clone();
        next.begin_run(run)?;
        let state = next.supervisor_mut();
        state.phase = SupervisorPhase::StartingRun;
        state.current_run = Some(run);
        state.current_input = Some(input);
        state.current_budget_request = Some(budget_request);
        state.continuation_of = None;
        state.pending_deficiency = None;
        state.last_target_digest = Some(digest.clone());
        state.cycle_baseline = Some(baseline);
        state.cycle_checks_done.clear();
        state.cycle_assessed.clear();
        state.pending_assessment = None;

        self.persist(record, next, request, false, TickOutcome::Advanced)
    }

    fn phase_starting_run(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
    ) -> Result<TickReport, SupervisionError> {
        let contract = request.contract();
        if contract.conditions().require_approval(self.now()).is_err()
            || contract.validate_for_start(self.now()).is_err()
        {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ConfirmConditions,
            );
        }
        let (Some(run), Some(input), Some(budget_request)) = (
            record.supervisor().current_run(),
            record.supervisor().current_input(),
            record.supervisor().current_budget_request(),
        ) else {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ReconcileRecovery,
            );
        };
        if let Err(error) = self.ports.budget.start_run(budget_request) {
            return match error {
                SupervisionError::BudgetLimitReached { limit } => {
                    self.stop(record, record.clone(), request, StopCause::Budget(limit))
                }
                other => Err(other),
            };
        }
        if self.ports.budget.remaining_active_seconds()? == 0 {
            return self.stop(
                record,
                record.clone(),
                request,
                StopCause::Budget(BudgetLimit::ActiveSeconds),
            );
        }

        let request_id = derive_runtime_request_id(record.supervision_id(), run, input);
        let result = if let Some(previous) = record.supervisor().continuation_of() {
            let Some(deficiency) = record.supervisor().pending_deficiency() else {
                return self.wait_human(
                    record,
                    record.clone(),
                    request,
                    HumanAction::ReconcileRecovery,
                );
            };
            let continuation = ChildRunContinuation::new(
                request_id,
                record.project_id(),
                record.supervision_id(),
                previous,
                run,
                input,
                record.condition_version(),
                record.target_version(),
                record.profile(),
                record.consent(),
                contract.work_packet().clone(),
                deficiency.clone(),
            );
            self.ports.runtime.continue_child(&continuation)
        } else {
            let start = ChildRunStart::new(
                request_id,
                record.project_id(),
                record.supervision_id(),
                run,
                input,
                record.condition_version(),
                record.target_version(),
                record.profile(),
                record.consent(),
                contract.work_packet().clone(),
            );
            self.ports.runtime.start_child(&start)
        };

        if let Err(_error) = result {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ReconcileRecovery,
            );
        }

        let mut next = record.clone();
        next.supervisor_mut().phase = SupervisorPhase::AwaitingInput;
        self.persist(record, next, request, false, TickOutcome::AwaitingInput)
    }

    fn phase_awaiting_input(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
    ) -> Result<TickReport, SupervisionError> {
        let (Some(run), Some(input)) = (
            record.supervisor().current_run(),
            record.supervisor().current_input(),
        ) else {
            return Ok(TickReport::noop(record));
        };
        let progress = self.ports.runtime.input_progress(input)?;
        let run_state = self.ports.runtime.run_state(run)?;

        if progress.phase().is_completed() && run_state == RunState::Idle {
            if let Some(budget_request) = record.supervisor().current_budget_request() {
                self.ports.budget.finish_run(budget_request)?;
            }
            let mut next = record.clone();
            next.begin_verification(record.required_checks().to_vec())?;
            let state = next.supervisor_mut();
            state.phase = SupervisorPhase::Evaluating;
            state.cycle_checks_done.clear();
            state.cycle_assessed.clear();
            state.pending_assessment = None;
            return self.persist(record, next, request, false, TickOutcome::Advanced);
        }

        if matches!(progress.phase(), InputPhase::Cancelled | InputPhase::Failed) {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ReconcileRecovery,
            );
        }
        match run_state {
            RunState::Failed => self.fail(
                record,
                record.clone(),
                request,
                SupervisionFailure::TargetUnstable,
            ),
            RunState::AwaitingApproval => self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ApproveOperation,
            ),
            RunState::Paused | RunState::Interrupted => self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ReconcileRecovery,
            ),
            RunState::Running | RunState::Idle => Ok(TickReport::noop(record)),
        }
    }

    fn phase_verifying(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
    ) -> Result<TickReport, SupervisionError> {
        let contract = request.contract();
        if !same_check_set(record, contract) {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ConfirmConditions,
            );
        }
        let Some(run) = record.supervisor().current_run() else {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ReconcileRecovery,
            );
        };
        match self.ports.runtime.run_state(run)? {
            RunState::Running | RunState::AwaitingApproval => {
                return Ok(TickReport::noop(record));
            }
            RunState::Paused => {
                // A paused run is a stable, non-active target. An explicit
                // reassessment may verify it without resuming the old run.
            }
            RunState::Interrupted => {
                return self.wait_human(
                    record,
                    record.clone(),
                    request,
                    HumanAction::ReconcileRecovery,
                );
            }
            RunState::Failed => {
                return self.fail(
                    record,
                    record.clone(),
                    request,
                    SupervisionFailure::TargetUnstable,
                );
            }
            RunState::Idle => {}
        }
        let manifest = self.snapshot(record, contract)?;
        if !manifest.coverage().is_complete() {
            return self.wait_human(record, record.clone(), request, HumanAction::ConfirmTarget);
        }
        let digest = manifest.manifest_digest()?;
        let evidence = self.evidence_list(record)?;

        let mut next = record.clone();
        {
            let state = next.supervisor_mut();
            if state.last_target_digest.as_ref() != Some(&digest) {
                state.cycle_checks_done.clear();
                state.cycle_assessed.clear();
                state.pending_assessment = None;
                state.last_target_digest = Some(digest.clone());
            }
        }

        for check in contract.conditions().checks() {
            if next.supervisor().cycle_checks_done().contains(&check.id()) {
                continue;
            }
            if let Some(result) = reusable_check_result(record, check, &manifest, &evidence)? {
                next.supervisor_mut().push_check_result(result);
                next.supervisor_mut().cycle_checks_done.push(check.id());
                return self.persist(record, next, request, false, TickOutcome::Advanced);
            }

            let sequence = evidence
                .iter()
                .map(EvidenceRecord::sequence)
                .max()
                .unwrap_or(0)
                .saturating_add(1);
            let evidence_id = derive_evidence_id(
                record.project_id(),
                record.supervision_id(),
                record.supervisor().evaluation_cycles(),
                check.id(),
                sequence,
            );
            let check_request = CheckExecutionRequest::new(
                record.project_id(),
                record.supervision_id(),
                check.condition_id(),
                check.id(),
                record.condition_version(),
                record.target_version(),
                evidence_id,
                sequence,
                check.operation().clone(),
                contract.evidence_target().read_set().to_vec(),
            );
            let execution = match self.ports.checks.execute(&check_request) {
                Ok(execution) => execution,
                Err(_) => {
                    return self.fail(
                        record,
                        record.clone(),
                        request,
                        SupervisionFailure::VerificationUnavailable,
                    );
                }
            };
            if !execution_matches(record, check, &execution, evidence_id) {
                return self.fail(
                    record,
                    record.clone(),
                    request,
                    SupervisionFailure::VerificationUnavailable,
                );
            }
            if let Some(stored) = execution.evidence() {
                self.ports.evidence.append(stored.clone())?;
            }
            next.supervisor_mut()
                .push_check_result(execution.result().clone());
            next.supervisor_mut().cycle_checks_done.push(check.id());
            return self.persist(record, next, request, false, TickOutcome::Advanced);
        }

        let statuses = current_check_statuses(record, contract.conditions().checks());
        if statuses
            .iter()
            .any(|(_, status)| !matches!(status, CheckStatus::Pass | CheckStatus::Fail))
        {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ReconcileRecovery,
            );
        }

        let mut next = record.clone();
        next.begin_assessment(contract.conditions().condition_ids())?;
        let state = next.supervisor_mut();
        state.phase = SupervisorPhase::Evaluating;
        state.cycle_assessed.clear();
        state.pending_assessment = None;
        state.last_target_digest = Some(digest);
        self.persist(record, next, request, false, TickOutcome::Advanced)
    }

    fn phase_assessing(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
    ) -> Result<TickReport, SupervisionError> {
        let contract = request.contract();
        let manifest = self.snapshot(record, contract)?;
        if !manifest.coverage().is_complete() {
            return self.wait_human(record, record.clone(), request, HumanAction::ConfirmTarget);
        }
        let digest = manifest.manifest_digest()?;
        if record.supervisor().last_target_digest() != Some(&digest) {
            return self.rework_after_target_change(record, request);
        }

        let (Some(run), Some(input)) = (
            record.supervisor().current_run(),
            record.supervisor().current_input(),
        ) else {
            return Ok(TickReport::refused(record));
        };
        match self.ports.runtime.run_state(run)? {
            RunState::Running | RunState::AwaitingApproval => {
                return Ok(TickReport::refused(record));
            }
            RunState::Paused => {
                // See `phase_verifying`: an explicitly reassessed target may
                // use its last stable run without resuming it.
            }
            RunState::Interrupted => {
                return self.wait_human(
                    record,
                    record.clone(),
                    request,
                    HumanAction::ReconcileRecovery,
                );
            }
            RunState::Failed => {
                return self.fail(
                    record,
                    record.clone(),
                    request,
                    SupervisionFailure::TargetUnstable,
                );
            }
            RunState::Idle => {}
        }
        if !self
            .ports
            .runtime
            .input_progress(input)?
            .phase()
            .is_completed()
        {
            return Ok(TickReport::refused(record));
        }

        let evidence = self.evidence_list(record)?;
        if let Some(pending) = record.supervisor().pending_assessment().cloned() {
            return self.send_assessment(record, request, pending, &manifest, &evidence);
        }

        let Some(condition) = contract.conditions().conditions().iter().find(|condition| {
            !record
                .supervisor()
                .cycle_assessed()
                .contains(&condition.id())
        }) else {
            return self.finish_cycle(record, request, &manifest, &evidence);
        };

        if !self.ports.assessment.requires_assessment(condition) {
            return self
                .assess_deterministic_condition(record, request, condition, &manifest, &evidence);
        }

        let evidence_ids = condition_evidence(record, condition.id(), &manifest, &evidence);
        if evidence_ids.is_empty() {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::DecideAssessment,
            );
        }
        let facts = match self.ports.assessment.profile(record.profile()) {
            Ok(facts) => facts,
            Err(_) => {
                return self.wait_human(
                    record,
                    record.clone(),
                    request,
                    HumanAction::ConfirmAssessmentProfile,
                );
            }
        };
        let decision = derive_decision_id(
            record.project_id(),
            record.supervision_id(),
            condition.id(),
            record.condition_version(),
            record.target_version(),
            record.supervisor().evaluation_cycles(),
        );
        let assessment_request = AssessmentRequest::new(
            decision,
            record.supervision_id(),
            condition.id(),
            record.condition_version(),
            record.target_version(),
            condition.rubric(),
            record.profile(),
            facts.adapter_version().clone(),
            facts.rubric_version().clone(),
            evidence_ids,
        )?;
        let mut next = record.clone();
        next.supervisor_mut().pending_assessment =
            Some(PendingAssessment::new(assessment_request, record.consent()));
        self.persist(
            record,
            next,
            request,
            false,
            TickOutcome::AwaitingAssessment,
        )
    }

    fn assess_deterministic_condition(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
        condition: &Condition,
        manifest: &TargetManifest,
        evidence: &[EvidenceRecord],
    ) -> Result<TickReport, SupervisionError> {
        let contract = request.contract();
        let checks = contract
            .conditions()
            .checks()
            .iter()
            .filter(|check| check.condition_id() == condition.id())
            .collect::<Vec<_>>();
        if checks.is_empty() {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::DecideAssessment,
            );
        }
        let mut cited = Vec::new();
        let mut all_pass = true;
        for check in checks {
            let Some(result) = record
                .supervisor()
                .check_results()
                .iter()
                .rev()
                .find(|result| result.check_id() == check.id())
            else {
                all_pass = false;
                break;
            };
            if result.status() != CheckStatus::Pass
                || result.condition_version() != record.condition_version()
                || result.target_version() != record.target_version()
            {
                all_pass = false;
                break;
            }
            let Some(evidence_id) = result.evidence_id() else {
                all_pass = false;
                break;
            };
            let Some(stored) = evidence.iter().find(|item| item.id() == evidence_id) else {
                all_pass = false;
                break;
            };
            if stored.status() != CheckStatus::Pass
                || stored.check_id() != Some(check.id())
                || stored.condition_id() != Some(check.condition_id())
                || stored.operation() != check.operation()
                || !evidence_applies(manifest, stored)
            {
                all_pass = false;
                break;
            }
            cited.push(evidence_id);
        }

        let mut next = record.clone();
        if all_pass {
            next.apply_deterministic_condition(
                condition.id(),
                record.condition_version(),
                record.target_version(),
                cited,
            )?;
        }
        next.supervisor_mut().cycle_assessed.push(condition.id());
        self.persist(
            record,
            next,
            request,
            false,
            TickOutcome::AwaitingAssessment,
        )
    }

    fn send_assessment(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
        pending: PendingAssessment,
        manifest: &TargetManifest,
        evidence: &[EvidenceRecord],
    ) -> Result<TickReport, SupervisionError> {
        if pending.request().condition_version() != record.condition_version()
            || pending.request().target_version() != record.target_version()
            || pending.request().profile() != record.profile()
            || pending.consent() != record.consent()
        {
            return self.stale_pending_without_result(record, request);
        }
        let facts = match self.ports.assessment.profile(record.profile()) {
            Ok(facts) => facts,
            Err(_) => {
                return self.wait_human(
                    record,
                    record.clone(),
                    request,
                    HumanAction::ConfirmAssessmentProfile,
                );
            }
        };
        let assessment_request = pending.request().clone();
        let result = match self.ports.assessment.assess(&assessment_request) {
            Ok(result) => result,
            Err(_) => {
                return self.wait_human(
                    record,
                    record.clone(),
                    request,
                    HumanAction::DecideAssessment,
                );
            }
        };

        let latest = self
            .ports
            .store
            .load(record.project_id(), record.supervision_id())?
            .ok_or(SupervisionError::UnknownSupervision)?;
        if latest.revision() != record.revision()
            || latest.condition_version() != record.condition_version()
            || latest.target_version() != record.target_version()
            || latest.profile() != record.profile()
            || latest.consent() != record.consent()
        {
            return self.stale_assessment(record, latest, pending, &result, request);
        }
        let current_manifest = self.snapshot(record, request.contract())?;
        if current_manifest.manifest_digest()? != manifest.manifest_digest()? {
            return self.stale_result_target_change(latest, &result, request);
        }
        if !result_matches(&assessment_request, &result) {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::DecideAssessment,
            );
        }
        if !result_evidence_applies(&result, manifest, evidence) {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::DecideAssessment,
            );
        }

        let mut next = record.clone();
        let application = next.apply_assessment(&result, facts.thresholds())?;
        next.supervisor_mut().pending_assessment = None;
        next.supervisor_mut()
            .cycle_assessed
            .push(result.condition_id());
        match application {
            crate::state::AssessmentApplication::Applied => self.persist(
                record,
                next,
                request,
                false,
                TickOutcome::AwaitingAssessment,
            ),
            crate::state::AssessmentApplication::NotDecided => {
                self.wait_human(record, next, request, HumanAction::DecideAssessment)
            }
            crate::state::AssessmentApplication::Stale => {
                self.wait_human(record, next, request, HumanAction::ConfirmConditions)
            }
        }
    }

    fn stale_assessment(
        &mut self,
        _previous: &SupervisionRecord,
        latest: SupervisionRecord,
        pending: PendingAssessment,
        result: &AssessmentResult,
        request: &TickRequest,
    ) -> Result<TickReport, SupervisionError> {
        if latest.state() == SupervisionState::Completed {
            return Ok(TickReport::noop(&latest));
        }
        let invalidation = if latest.condition_version() != pending.request().condition_version() {
            DecisionInvalidation::ConditionsChanged {
                to: latest.condition_version(),
            }
        } else if latest.target_version() != pending.request().target_version() {
            DecisionInvalidation::TargetChanged {
                to: latest.target_version(),
            }
        } else if latest.profile() != pending.request().profile() {
            DecisionInvalidation::ProfileChanged
        } else {
            DecisionInvalidation::ConsentChanged
        };
        let mut next = latest.clone();
        next.record_invalidated_assessment(result, invalidation)?;
        next.supervisor_mut().pending_assessment = None;
        if next.state() == SupervisionState::Assessing {
            next.wait_for_human(HumanAction::ReconcileRecovery)?;
            next.supervisor_mut().phase = SupervisorPhase::Finished;
            self.ports.budget.wait_for_human()?;
            return self.persist(&latest, next, request, true, TickOutcome::StaleAssessment);
        }
        self.persist(&latest, next, request, false, TickOutcome::StaleAssessment)
    }

    fn stale_pending_without_result(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
    ) -> Result<TickReport, SupervisionError> {
        let mut next = record.clone();
        next.supervisor_mut().pending_assessment = None;
        self.persist(record, next, request, false, TickOutcome::StaleAssessment)
    }

    fn stale_result_target_change(
        &mut self,
        latest: SupervisionRecord,
        result: &AssessmentResult,
        request: &TickRequest,
    ) -> Result<TickReport, SupervisionError> {
        let mut next = latest.clone();
        next.record_invalidated_assessment(
            result,
            DecisionInvalidation::TargetChanged {
                to: latest.target_version(),
            },
        )?;
        next.supervisor_mut().pending_assessment = None;
        next.begin_verification(latest.required_checks().to_vec())?;
        let state = next.supervisor_mut();
        state.phase = SupervisorPhase::Evaluating;
        state.cycle_checks_done.clear();
        state.cycle_assessed.clear();
        state.pending_assessment = None;
        self.persist(&latest, next, request, false, TickOutcome::StaleAssessment)
    }

    fn rework_after_target_change(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
    ) -> Result<TickReport, SupervisionError> {
        let mut next = record.clone();
        next.begin_verification(record.required_checks().to_vec())?;
        let state = next.supervisor_mut();
        state.phase = SupervisorPhase::Evaluating;
        state.cycle_checks_done.clear();
        state.cycle_assessed.clear();
        state.pending_assessment = None;
        self.persist(record, next, request, false, TickOutcome::Advanced)
    }

    // --- cycle end --------------------------------------------------------

    fn finish_cycle(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
        manifest: &TargetManifest,
        evidence: &[EvidenceRecord],
    ) -> Result<TickReport, SupervisionError> {
        let contract = request.contract();
        let digest = manifest.manifest_digest()?;
        if record.supervisor().last_target_digest() != Some(&digest) {
            return self.rework_after_target_change(record, request);
        }
        if self.ports.budget.remaining_active_seconds()? == 0 {
            return self.stop(
                record,
                record.clone(),
                request,
                StopCause::Budget(BudgetLimit::ActiveSeconds),
            );
        }
        if contract.conditions().require_approval(self.now()).is_err()
            || contract.validate_for_start(self.now()).is_err()
        {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ConfirmConditions,
            );
        }

        let (checks_pass, _check_evidence) = all_checks_pass(record, contract, manifest, evidence)?;
        let conditions_met = all_conditions_met(record, manifest, evidence);
        if checks_pass && conditions_met {
            return self.complete(record, request, manifest, evidence);
        }

        let statuses = current_check_statuses(record, contract.conditions().checks());
        if statuses
            .iter()
            .any(|(_, status)| !matches!(status, CheckStatus::Pass | CheckStatus::Fail))
        {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::ReconcileRecovery,
            );
        }

        let current = self.progress_fingerprint(record, manifest, evidence)?;
        let progressed = record
            .supervisor()
            .cycle_baseline()
            .is_none_or(|baseline| baseline != &current);

        let mut next = record.clone();
        {
            let state = next.supervisor_mut();
            state.evaluation_cycles = state.evaluation_cycles.saturating_add(1);
            if progressed {
                state.stagnation_cycles = 0;
                state.last_progress = Some(current.clone());
            } else {
                state.stagnation_cycles = state.stagnation_cycles.saturating_add(1);
            }
        }
        if !progressed && next.supervisor().stagnation_cycles() >= H2_STAGNATION_CYCLES {
            return self.stop(record, next, request, StopCause::Stagnation);
        }

        if !self.ports.budget.can_start_run()? {
            return self.stop(
                record,
                next,
                request,
                StopCause::Budget(BudgetLimit::RunCount),
            );
        }
        if self.ports.budget.remaining_active_seconds()? == 0 {
            return self.stop(
                record,
                next,
                request,
                StopCause::Budget(BudgetLimit::ActiveSeconds),
            );
        }

        let previous_run = record.supervisor().current_run();
        let ordinal = next.run_group().runs().len() as u64 + 1;
        let run = derive_run_id(record.project_id(), record.supervision_id(), ordinal);
        let input = derive_input_id(record.project_id(), record.supervision_id(), ordinal);
        let budget_request =
            derive_budget_request_id(record.project_id(), record.supervision_id(), ordinal);
        let deficiency = build_deficiency(record, contract, evidence)?;

        next.begin_run(run)?;
        let state = next.supervisor_mut();
        state.phase = SupervisorPhase::StartingRun;
        state.current_run = Some(run);
        state.current_input = Some(input);
        state.current_budget_request = Some(budget_request);
        state.continuation_of = previous_run;
        state.pending_deficiency = Some(deficiency);
        state.cycle_baseline = Some(current);
        state.cycle_checks_done.clear();
        state.cycle_assessed.clear();
        state.pending_assessment = None;

        self.persist(record, next, request, false, TickOutcome::Advanced)
    }

    fn complete(
        &mut self,
        record: &SupervisionRecord,
        request: &TickRequest,
        manifest: &TargetManifest,
        evidence: &[EvidenceRecord],
    ) -> Result<TickReport, SupervisionError> {
        let contract = request.contract();
        if let Some(action) = contract_mismatch(record, contract) {
            return self.wait_human(record, record.clone(), request, action);
        }
        let digest = manifest.manifest_digest()?;
        let (checks_pass, check_evidence) = all_checks_pass(record, contract, manifest, evidence)?;
        if !checks_pass || !all_conditions_met(record, manifest, evidence) {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::DecideAssessment,
            );
        }
        let mut cited = BTreeSet::new();
        for evidence_id in check_evidence {
            cited.insert(evidence_id);
        }
        for decision in record.applied_decisions() {
            if decision.verdict().is_met()
                && decision.condition_version() == record.condition_version()
                && decision.target_version() == record.target_version()
            {
                for evidence_id in decision.evidence() {
                    cited.insert(*evidence_id);
                }
            }
        }
        let cited = cited.into_iter().collect::<Vec<_>>();
        if cited.is_empty() {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::DecideAssessment,
            );
        }
        let snapshot = CompletionSnapshot::new(
            record.condition_version(),
            record.target_version(),
            record.profile(),
            record.consent(),
            record.required_checks().to_vec(),
            cited,
            digest,
            self.now(),
        )?;
        let mut next = record.clone();
        if next.complete(snapshot).is_err() {
            return self.wait_human(
                record,
                record.clone(),
                request,
                HumanAction::DecideAssessment,
            );
        }
        next.supervisor_mut().phase = SupervisorPhase::Finished;
        self.ports.budget.app_stop()?;
        self.persist(record, next, request, true, TickOutcome::Completed)
    }

    // --- higher-priority transitions -------------------------------------

    fn wait_human(
        &mut self,
        previous: &SupervisionRecord,
        mut next: SupervisionRecord,
        request: &TickRequest,
        action: HumanAction,
    ) -> Result<TickReport, SupervisionError> {
        next.wait_for_human(action)?;
        next.supervisor_mut().phase = SupervisorPhase::Finished;
        next.supervisor_mut().pending_assessment = None;
        self.ports.budget.wait_for_human()?;
        self.persist(previous, next, request, true, TickOutcome::WaitingHuman)
    }

    fn stop(
        &mut self,
        previous: &SupervisionRecord,
        mut next: SupervisionRecord,
        request: &TickRequest,
        cause: StopCause,
    ) -> Result<TickReport, SupervisionError> {
        let mut final_cause = cause;
        if let Some(run) = next.supervisor().current_run() {
            match self.ports.runtime.request_stop(run) {
                Ok(StopDisposition::Confirmed) => {}
                Ok(StopDisposition::Unconfirmed) | Err(_) => {
                    final_cause = StopCause::StopUnconfirmed;
                }
            }
        }
        next.stop(final_cause)?;
        next.supervisor_mut().phase = SupervisorPhase::Finished;
        next.supervisor_mut().pending_assessment = None;
        self.ports.budget.app_stop()?;
        self.persist(previous, next, request, true, TickOutcome::Stopped)
    }

    fn fail(
        &mut self,
        previous: &SupervisionRecord,
        mut next: SupervisionRecord,
        request: &TickRequest,
        failure: SupervisionFailure,
    ) -> Result<TickReport, SupervisionError> {
        next.fail(failure)?;
        next.supervisor_mut().phase = SupervisorPhase::Finished;
        next.supervisor_mut().pending_assessment = None;
        self.ports.budget.app_stop()?;
        self.persist(previous, next, request, true, TickOutcome::Failed)
    }

    // --- storage, notification, and deterministic values ------------------

    fn persist(
        &mut self,
        previous: &SupervisionRecord,
        mut next: SupervisionRecord,
        request: &TickRequest,
        notify: bool,
        outcome: TickOutcome,
    ) -> Result<TickReport, SupervisionError> {
        next.set_command_revision(previous.revision().saturating_add(1));
        // A controller tick is an internal reassessment event. The existing
        // command enum is left unchanged; the stored state/reason carry the
        // actual transition.
        let result = CommandResult::new(
            request.event_id(),
            next.project_id(),
            next.supervision_id(),
            SupervisionCommand::Reassess,
            next.revision(),
            next.state(),
            next.reason().clone(),
        )?;
        match self.ports.store.commit_command(
            next.project_id(),
            next.supervision_id(),
            Some(previous.revision()),
            &next,
            &result,
        ) {
            Ok(revision) => {
                let mut notified = false;
                if notify {
                    let notification = SupervisorNotification::new(
                        next.project_id(),
                        next.supervision_id(),
                        revision,
                        next.state(),
                        next.reason().clone(),
                        next.unmet_conditions().to_vec(),
                        self.now(),
                    );
                    self.ports.notifications.notify(&notification)?;
                    notified = true;
                }
                Ok(TickReport {
                    outcome,
                    revision,
                    state: next.state(),
                    notified,
                })
            }
            Err(SupervisionError::RevisionConflict { .. }) => Ok(TickReport {
                outcome: TickOutcome::StaleRevision,
                revision: previous.revision(),
                state: previous.state(),
                notified: false,
            }),
            Err(error) => Err(error),
        }
    }

    fn now(&self) -> Timestamp {
        self.ports.clock.now()
    }

    fn snapshot(
        &mut self,
        record: &SupervisionRecord,
        contract: &SupervisionContract,
    ) -> Result<TargetManifest, SupervisionError> {
        let request = TargetSnapshotRequest::new(
            record.project_id(),
            record.supervision_id(),
            record.target_version(),
            contract.evidence_target().read_set().to_vec(),
        );
        self.ports.runtime.target_snapshot(&request)
    }

    fn evidence_list(
        &mut self,
        record: &SupervisionRecord,
    ) -> Result<Vec<EvidenceRecord>, SupervisionError> {
        self.ports
            .evidence
            .list_for_supervision(record.project_id(), record.supervision_id())
    }

    fn progress_fingerprint(
        &self,
        record: &SupervisionRecord,
        manifest: &TargetManifest,
        evidence: &[EvidenceRecord],
    ) -> Result<ContentDigest, SupervisionError> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Material<'a> {
            target: Vec<(&'a str, bool, &'a str)>,
            passes: Vec<String>,
            unmet: Vec<String>,
            investigation: Vec<String>,
        }

        let target = manifest
            .entries()
            .iter()
            .map(|entry| (entry.path(), entry.present(), entry.digest().as_str()))
            .collect::<Vec<_>>();
        let passes = record
            .supervisor()
            .check_results()
            .iter()
            .filter(|result| {
                result.status() == CheckStatus::Pass
                    && result.condition_version() == record.condition_version()
                    && result.target_version() == record.target_version()
            })
            .map(|result| result.check_id().to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let unmet = record
            .unmet_conditions()
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let investigation = evidence
            .iter()
            .filter(|item| {
                item.check_id().is_none()
                    && item.target().version() == manifest.version()
                    && evidence_applies(manifest, item)
            })
            .map(|item| item.id().to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let bytes = serde_json::to_vec(&Material {
            target,
            passes,
            unmet,
            investigation,
        })
        .map_err(|error| SupervisionError::InvalidValue {
            field: "supervisor.progress".to_owned(),
            detail: format!("could not serialize the progress fingerprint: {error}"),
        })?;
        Ok(ContentDigest::sha256(&bytes))
    }
}

// --- pure helpers ---------------------------------------------------------

fn contract_mismatch(
    record: &SupervisionRecord,
    contract: &SupervisionContract,
) -> Option<HumanAction> {
    if record.condition_version() != contract.conditions().condition_version()
        || !same_check_set(record, contract)
    {
        Some(HumanAction::ConfirmConditions)
    } else if record.target_version() != contract.evidence_target().version() {
        Some(HumanAction::ConfirmTarget)
    } else if record.profile() != contract.profile() {
        Some(HumanAction::ConfirmAssessmentProfile)
    } else if record.consent() != contract.consent() {
        Some(HumanAction::GrantDisclosureConsent)
    } else {
        None
    }
}

fn same_check_set(record: &SupervisionRecord, contract: &SupervisionContract) -> bool {
    let mut expected = contract
        .conditions()
        .checks()
        .iter()
        .map(|check| check.id())
        .collect::<Vec<_>>();
    let mut stored = record.required_checks().to_vec();
    expected.sort();
    stored.sort();
    if expected != stored {
        return false;
    }
    let mut expected_conditions = contract.conditions().condition_ids();
    let mut stored_conditions = record.condition_ids().to_vec();
    expected_conditions.sort();
    stored_conditions.sort();
    expected_conditions == stored_conditions
}

fn evidence_applies(manifest: &TargetManifest, evidence: &EvidenceRecord) -> bool {
    manifest.coverage().is_complete()
        && evidence.project_id() == manifest.project_id()
        && evidence.target().version() == manifest.version()
        && manifest.diff_scope(evidence.target()).is_empty()
}

fn reusable_check_result(
    record: &SupervisionRecord,
    check: &RequiredCheck,
    manifest: &TargetManifest,
    evidence: &[EvidenceRecord],
) -> Result<Option<RequiredCheckResult>, SupervisionError> {
    let mut candidates = evidence
        .iter()
        .filter(|item| {
            item.check_id() == Some(check.id())
                && item.condition_id() == Some(check.condition_id())
                && item.status() == CheckStatus::Pass
                && item.operation() == check.operation()
                && evidence_applies(manifest, item)
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|item| item.sequence());
    let Some(candidate) = candidates.last() else {
        return Ok(None);
    };
    let result = RequiredCheckResult::from_evidence(candidate, record.condition_version())?;
    Ok(Some(result))
}

fn execution_matches(
    record: &SupervisionRecord,
    check: &RequiredCheck,
    execution: &CheckExecution,
    evidence_id: EvidenceId,
) -> bool {
    let result = execution.result();
    if result.check_id() != check.id()
        || result.condition_id() != check.condition_id()
        || result.condition_version() != record.condition_version()
        || result.target_version() != record.target_version()
    {
        return false;
    }
    match (result.status(), execution.evidence()) {
        (CheckStatus::Pass, Some(stored)) => {
            stored.id() == evidence_id
                && stored.status() == CheckStatus::Pass
                && stored.check_id() == Some(check.id())
                && stored.condition_id() == Some(check.condition_id())
                && stored.project_id() == record.project_id()
                && stored.target().version() == record.target_version()
                && stored.operation() == check.operation()
        }
        (CheckStatus::Pass, None) => false,
        (_, Some(stored)) => {
            stored.id() == evidence_id
                && stored.status() == result.status()
                && stored.check_id() == Some(check.id())
                && stored.condition_id() == Some(check.condition_id())
                && stored.project_id() == record.project_id()
                && stored.target().version() == record.target_version()
        }
        (_, None) => true,
    }
}

fn current_check_statuses(
    record: &SupervisionRecord,
    checks: &[RequiredCheck],
) -> Vec<(CheckId, CheckStatus)> {
    checks
        .iter()
        .map(|check| {
            let status = record
                .supervisor()
                .check_results()
                .iter()
                .rev()
                .find(|result| result.check_id() == check.id())
                .filter(|result| {
                    result.condition_version() == record.condition_version()
                        && result.target_version() == record.target_version()
                })
                .map_or(CheckStatus::NotRun, |result| result.status());
            (check.id(), status)
        })
        .collect()
}

fn all_checks_pass(
    record: &SupervisionRecord,
    contract: &SupervisionContract,
    manifest: &TargetManifest,
    evidence: &[EvidenceRecord],
) -> Result<(bool, Vec<EvidenceId>), SupervisionError> {
    if !same_check_set(record, contract) {
        return Ok((false, Vec::new()));
    }
    let mut cited = Vec::new();
    for check in contract.conditions().checks() {
        let Some(result) = record
            .supervisor()
            .check_results()
            .iter()
            .rev()
            .find(|result| result.check_id() == check.id())
        else {
            return Ok((false, Vec::new()));
        };
        if result.status() != CheckStatus::Pass
            || result.condition_version() != record.condition_version()
            || result.target_version() != record.target_version()
        {
            return Ok((false, Vec::new()));
        }
        let Some(evidence_id) = result.evidence_id() else {
            return Ok((false, Vec::new()));
        };
        let Some(stored) = evidence.iter().find(|item| item.id() == evidence_id) else {
            return Ok((false, Vec::new()));
        };
        if stored.status() != CheckStatus::Pass
            || stored.check_id() != Some(check.id())
            || stored.condition_id() != Some(check.condition_id())
            || stored.operation() != check.operation()
            || !evidence_applies(manifest, stored)
        {
            return Ok((false, Vec::new()));
        }
        cited.push(evidence_id);
    }
    Ok((true, cited))
}

fn all_conditions_met(
    record: &SupervisionRecord,
    manifest: &TargetManifest,
    evidence: &[EvidenceRecord],
) -> bool {
    if !record.unmet_conditions().is_empty() {
        return false;
    }
    for condition in record.condition_ids() {
        let Some(decision) = record.applied_decisions().iter().find(|decision| {
            decision.condition_id() == *condition
                && decision.verdict().is_met()
                && decision.condition_version() == record.condition_version()
                && decision.target_version() == record.target_version()
        }) else {
            return false;
        };
        if decision.evidence().is_empty() {
            return false;
        }
        for evidence_id in decision.evidence() {
            let Some(item) = evidence.iter().find(|item| item.id() == *evidence_id) else {
                return false;
            };
            if item.condition_id() != Some(*condition) || !evidence_applies(manifest, item) {
                return false;
            }
        }
    }
    true
}

fn condition_evidence(
    record: &SupervisionRecord,
    condition: ConditionId,
    manifest: &TargetManifest,
    evidence: &[EvidenceRecord],
) -> Vec<EvidenceId> {
    let mut items = evidence
        .iter()
        .filter(|item| {
            item.condition_id() == Some(condition)
                && item.target().version() == record.target_version()
                && evidence_applies(manifest, item)
        })
        .collect::<Vec<_>>();
    items.sort_by_key(|item| item.sequence());
    items
        .into_iter()
        .map(|item| item.id())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn result_matches(request: &AssessmentRequest, result: &AssessmentResult) -> bool {
    result.id() == request.id()
        && result.project_id() == request.project_id()
        && result.supervision_id() == request.supervision_id()
        && result.condition_id() == request.condition_id()
        && result.condition_version() == request.condition_version()
        && result.target_version() == request.target_version()
        && result.profile() == request.profile()
        && result
            .evidence()
            .iter()
            .all(|evidence_id| request.evidence().contains(evidence_id))
}

fn result_evidence_applies(
    result: &AssessmentResult,
    manifest: &TargetManifest,
    evidence: &[EvidenceRecord],
) -> bool {
    !result.evidence().is_empty()
        && result.evidence().iter().all(|evidence_id| {
            evidence
                .iter()
                .find(|item| item.id() == *evidence_id)
                .is_some_and(|item| evidence_applies(manifest, item))
        })
}

fn build_deficiency(
    record: &SupervisionRecord,
    contract: &SupervisionContract,
    evidence: &[EvidenceRecord],
) -> Result<ContinuationDeficiency, SupervisionError> {
    let statuses = current_check_statuses(record, contract.conditions().checks());
    let failed_checks = statuses
        .iter()
        .filter(|(_, status)| !status.is_pass())
        .map(|(check_id, status)| {
            let evidence_id = record
                .supervisor()
                .check_results()
                .iter()
                .rev()
                .find(|result| result.check_id() == *check_id)
                .and_then(RequiredCheckResult::evidence_id);
            FailedCheck::new(*check_id, *status, evidence_id)
        })
        .collect::<Vec<_>>();
    let unmet = record.unmet_conditions().to_vec();
    let mut cited = BTreeSet::new();
    for check in &failed_checks {
        if let Some(evidence_id) = check.evidence_id() {
            cited.insert(evidence_id);
        }
    }
    for decision in record.applied_decisions() {
        if !decision.verdict().is_met()
            && decision.condition_version() == record.condition_version()
            && decision.target_version() == record.target_version()
        {
            cited.extend(decision.evidence().iter().copied());
        }
    }
    if cited.is_empty() {
        cited.extend(
            evidence
                .iter()
                .filter(|item| item.target().version() == record.target_version())
                .map(|item| item.id()),
        );
    }
    let failed_labels = failed_checks
        .iter()
        .map(|check| format!("{} ({})", check.check_id(), check.status().as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    let unmet_labels = unmet
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let instruction = format!(
        "Continue the approved work. Required checks not passing: {failed_labels}. \
         Conditions not met: {unmet_labels}. Fix only these deficiencies inside the existing \
         conditions, permissions, scope, and budget. Re-run the checks and report evidence. \
         Do not change conditions, permissions, or limits."
    );
    let instruction = if instruction.chars().count() > 4_000 {
        format!(
            "Continue the approved work. {} required checks are not passing and {} conditions \
             are not met. Review the cited evidence, fix only those deficiencies inside the \
             existing conditions, permissions, scope, and budget, then re-run the checks. \
             Do not change conditions, permissions, or limits.",
            failed_checks.len(),
            unmet.len()
        )
    } else {
        instruction
    };
    ContinuationDeficiency::new(
        instruction,
        failed_checks,
        unmet,
        cited.into_iter().collect(),
    )
}

fn deterministic_uuid(parts: &[&str]) -> Uuid {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn derive_run_id(project: ProjectId, supervision: SupervisionId, ordinal: u64) -> RunId {
    RunId::from_parts(
        project,
        deterministic_uuid(&[
            "supervisor.run",
            &supervision.to_string(),
            &ordinal.to_string(),
        ]),
    )
}

fn derive_input_id(project: ProjectId, supervision: SupervisionId, ordinal: u64) -> InputId {
    InputId::from_parts(
        project,
        deterministic_uuid(&[
            "supervisor.input",
            &supervision.to_string(),
            &ordinal.to_string(),
        ]),
    )
}

fn derive_budget_request_id(
    project: ProjectId,
    supervision: SupervisionId,
    ordinal: u64,
) -> BudgetRequestId {
    BudgetRequestId::from_parts(
        project,
        deterministic_uuid(&[
            "supervisor.budget",
            &supervision.to_string(),
            &ordinal.to_string(),
        ]),
    )
}

fn derive_runtime_request_id(
    supervision: SupervisionId,
    run: RunId,
    input: InputId,
) -> SupervisionRequestId {
    SupervisionRequestId::from_parts(
        supervision.project_id(),
        deterministic_uuid(&[
            "supervisor.runtime",
            &supervision.to_string(),
            &run.to_string(),
            &input.to_string(),
        ]),
    )
}

fn derive_decision_id(
    project: ProjectId,
    supervision: SupervisionId,
    condition: ConditionId,
    condition_version: ConditionVersion,
    target_version: TargetVersion,
    cycle: u64,
) -> DecisionId {
    DecisionId::from_parts(
        project,
        deterministic_uuid(&[
            "supervisor.decision",
            &supervision.to_string(),
            &condition.to_string(),
            &condition_version.get().to_string(),
            &target_version.get().to_string(),
            &cycle.to_string(),
        ]),
    )
}

fn derive_evidence_id(
    project: ProjectId,
    supervision: SupervisionId,
    cycle: u64,
    check: CheckId,
    sequence: u64,
) -> EvidenceId {
    EvidenceId::from_parts(
        project,
        deterministic_uuid(&[
            "supervisor.evidence",
            &supervision.to_string(),
            &cycle.to_string(),
            &check.to_string(),
            &sequence.to_string(),
        ]),
    )
}
