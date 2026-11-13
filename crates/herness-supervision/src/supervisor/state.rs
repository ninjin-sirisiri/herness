//! Additive supervisor bookkeeping stored inside a supervision record.
//!
//! The H2 state enum stays the single authority for user-visible state. These
//! fields only remember the deterministic inputs a restarted controller needs:
//! which run/input it is waiting for, the current evaluation cycle, the cyclic
//! progress baseline, persisted required-check results, and one prepared
//! assessment request. Every field is serde-default so records written before
//! Task 13 continue to load.

use herness_core::contracts::{InputId, RunId, Timestamp};
use serde::{Deserialize, Serialize};

use crate::assessment::AssessmentRequest;
use crate::consent::ConsentBinding;
use crate::evidence::{ContentDigest, RequiredCheckResult};
use crate::ids::{BudgetRequestId, CheckId, ConditionId};
use crate::state::SupervisionReason;
use crate::supervisor::ports::{ContinuationDeficiency, ReadinessDecision};

/// Deterministic controller phase stored with the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorPhase {
    /// The record is ready but no run start intent has been saved.
    #[default]
    Idle,
    /// A run/input pair is recorded; the H1 control port has not acknowledged
    /// the start yet.
    StartingRun,
    /// The H1 run is active or idle and the controller waits for the matching
    /// input to complete.
    AwaitingInput,
    /// The input completed and the run is idle; the controller waits for the
    /// owner's required documents to become ready before verification starts.
    AwaitingReadiness,
    /// Required checks or condition assessments are being performed.
    Evaluating,
    /// The record reached a terminal or human-waiting state.
    Finished,
}

impl SupervisorPhase {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::StartingRun => "starting_run",
            Self::AwaitingInput => "awaiting_input",
            Self::AwaitingReadiness => "awaiting_readiness",
            Self::Evaluating => "evaluating",
            Self::Finished => "finished",
        }
    }
}

/// Kind of a persisted verification-readiness wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessWaitKind {
    /// Normal synchronization is in progress; time and deadline keep advancing.
    Pending,
    /// A human action is required; active time is excluded as a human wait.
    Blocked,
}

impl ReadinessWaitKind {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Blocked => "blocked",
        }
    }
}

/// One persisted readiness wait.
///
/// Only pending and blocked decisions are stored. A `ready` observation is never
/// persisted as a wait or as completion evidence, so a restored record always
/// re-observes the owner gate before verification continues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadinessWait {
    kind: ReadinessWaitKind,
    reason: String,
    required_action: Option<String>,
    documents: Vec<String>,
    observed_at: Timestamp,
}

impl ReadinessWait {
    /// Converts one non-ready decision into a persisted wait.
    ///
    /// A `Ready` decision returns `None` and is intentionally not stored.
    pub fn from_decision(decision: &ReadinessDecision, observed_at: Timestamp) -> Option<Self> {
        match decision {
            ReadinessDecision::Ready => None,
            ReadinessDecision::Pending { reason, awaiting } => Some(Self {
                kind: ReadinessWaitKind::Pending,
                reason: reason.clone(),
                required_action: None,
                documents: awaiting.clone(),
                observed_at,
            }),
            ReadinessDecision::Blocked {
                reason,
                required_action,
                documents,
            } => Some(Self {
                kind: ReadinessWaitKind::Blocked,
                reason: reason.clone(),
                required_action: Some(required_action.clone()),
                documents: documents.clone(),
                observed_at,
            }),
        }
    }

    /// Whether this stored wait already describes the same decision.
    ///
    /// The observation time is excluded so a repeated identical pending
    /// observation does not rewrite the record on every tick.
    pub fn same_decision(&self, decision: &ReadinessDecision) -> bool {
        match (self.kind, decision) {
            (ReadinessWaitKind::Pending, ReadinessDecision::Pending { reason, awaiting }) => {
                &self.reason == reason && &self.documents == awaiting
            }
            (
                ReadinessWaitKind::Blocked,
                ReadinessDecision::Blocked {
                    reason,
                    required_action,
                    documents,
                },
            ) => {
                &self.reason == reason
                    && self.required_action.as_deref() == Some(required_action.as_str())
                    && &self.documents == documents
            }
            _ => false,
        }
    }

    /// Structured reason for the matching supervision state.
    pub fn reason(&self) -> SupervisionReason {
        match self.kind {
            ReadinessWaitKind::Pending => SupervisionReason::AwaitingReadiness {
                reason: self.reason.clone(),
                awaiting: self.documents.clone(),
            },
            ReadinessWaitKind::Blocked => SupervisionReason::ReadinessBlocked {
                reason: self.reason.clone(),
                required_action: self.required_action.clone().unwrap_or_default(),
                documents: self.documents.clone(),
            },
        }
    }

    /// Wait kind.
    pub const fn kind(&self) -> ReadinessWaitKind {
        self.kind
    }

    /// Owner-provided reason.
    pub fn reason_text(&self) -> &str {
        &self.reason
    }

    /// Required human action for a blocked wait.
    pub fn required_action(&self) -> Option<&str> {
        self.required_action.as_deref()
    }

    /// Opaque document keys named by the wait.
    pub fn documents(&self) -> &[String] {
        &self.documents
    }

    /// When the wait was observed.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }
}

/// One condition assessment that has been persisted before sending.
///
/// The full request is stored so a duplicate tick, or a restart after the
/// request intent was saved but before the provider answered, can identify the
/// exact attempt. The consent binding at request time is kept separately so a
/// consent revision observed before the result arrives makes the result
/// history only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingAssessment {
    request: AssessmentRequest,
    consent: ConsentBinding,
}

impl PendingAssessment {
    /// Creates one persisted assessment intent.
    pub const fn new(request: AssessmentRequest, consent: ConsentBinding) -> Self {
        Self { request, consent }
    }

    /// Exact per-condition request.
    pub const fn request(&self) -> &AssessmentRequest {
        &self.request
    }

    /// Consent binding the request was sent under.
    pub const fn consent(&self) -> ConsentBinding {
        self.consent
    }
}

/// Deterministic H2 controller bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct SupervisorState {
    pub(crate) phase: SupervisorPhase,
    pub(crate) current_run: Option<RunId>,
    pub(crate) current_input: Option<InputId>,
    pub(crate) current_budget_request: Option<BudgetRequestId>,
    pub(crate) continuation_of: Option<RunId>,
    pub(crate) pending_deficiency: Option<ContinuationDeficiency>,
    pub(crate) evaluation_cycles: u64,
    pub(crate) stagnation_cycles: u32,
    pub(crate) last_progress: Option<ContentDigest>,
    pub(crate) cycle_baseline: Option<ContentDigest>,
    pub(crate) last_target_digest: Option<ContentDigest>,
    pub(crate) check_results: Vec<RequiredCheckResult>,
    pub(crate) cycle_checks_done: Vec<CheckId>,
    pub(crate) cycle_assessed: Vec<ConditionId>,
    pub(crate) pending_assessment: Option<PendingAssessment>,
    pub(crate) readiness: Option<ReadinessWait>,
}

impl SupervisorState {
    /// Current deterministic phase.
    pub const fn phase(&self) -> SupervisorPhase {
        self.phase
    }

    /// Run the controller most recently started or observed.
    pub const fn current_run(&self) -> Option<RunId> {
        self.current_run
    }

    /// Input whose completion the controller waits for.
    pub const fn current_input(&self) -> Option<InputId> {
        self.current_input
    }

    /// Budget run reservation bound to the current run.
    pub const fn current_budget_request(&self) -> Option<BudgetRequestId> {
        self.current_budget_request
    }

    /// Previous run this run continues, when the run is a continuation.
    pub const fn continuation_of(&self) -> Option<RunId> {
        self.continuation_of
    }

    /// Host-generated correction content for a prepared continuation.
    pub const fn pending_deficiency(&self) -> Option<&ContinuationDeficiency> {
        self.pending_deficiency.as_ref()
    }

    /// Number of completed evaluation cycles.
    pub const fn evaluation_cycles(&self) -> u64 {
        self.evaluation_cycles
    }

    /// Consecutive evaluation cycles without progress.
    pub const fn stagnation_cycles(&self) -> u32 {
        self.stagnation_cycles
    }

    /// Digest of the last complete cycle that showed progress.
    pub const fn last_progress(&self) -> Option<&ContentDigest> {
        self.last_progress.as_ref()
    }

    /// Progress fingerprint captured when the current run was prepared.
    pub const fn cycle_baseline(&self) -> Option<&ContentDigest> {
        self.cycle_baseline.as_ref()
    }

    /// Target manifest digest last used for verification or assessment.
    pub const fn last_target_digest(&self) -> Option<&ContentDigest> {
        self.last_target_digest.as_ref()
    }

    /// Persisted required-check results in stable order.
    pub fn check_results(&self) -> &[RequiredCheckResult] {
        &self.check_results
    }

    /// Checks already handled in the current verification cycle.
    pub fn cycle_checks_done(&self) -> &[CheckId] {
        &self.cycle_checks_done
    }

    /// Conditions already assessed in the current evaluation cycle.
    pub fn cycle_assessed(&self) -> &[ConditionId] {
        &self.cycle_assessed
    }

    /// Persisted assessment request waiting for a result.
    pub const fn pending_assessment(&self) -> Option<&PendingAssessment> {
        self.pending_assessment.as_ref()
    }

    /// Persisted verification-readiness wait, if the gate is holding.
    pub const fn readiness(&self) -> Option<&ReadinessWait> {
        self.readiness.as_ref()
    }

    pub(crate) fn push_check_result(&mut self, result: RequiredCheckResult) {
        if let Some(existing) = self
            .check_results
            .iter_mut()
            .find(|existing| existing.check_id() == result.check_id())
        {
            *existing = result;
        } else {
            self.check_results.push(result);
        }
    }
}
