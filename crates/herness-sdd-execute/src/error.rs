//! Structured, non-secret H4 errors.
//!
//! The ten failure and refusal classes from the H4 specification are distinct
//! typed values, and each can carry an H1, H2, or H3 detail reference so a
//! stored reason can name the exact upstream record. Payloads never carry
//! credentials, prompts, plan bodies, HTML bodies, or model text.

use std::fmt;

use herness_core::contracts::{InputId, OperationId, ProjectId, RunId};
use herness_html_sync::DocumentKey;
use herness_supervision::{DecisionId, EvidenceId, SupervisionId};
use serde::{Deserialize, Serialize};

use crate::approval::ApprovalSourceKind;
use crate::ids::{ExecutionRevision, PlanRevision};
use crate::plan::PlanDiagnostic;
use crate::state::{
    ApprovalRequirement, BudgetExhaustionReason, ConflictReason, GitUnknownReason, HtmlSyncReason,
    PlanChangeReason, RecoveryReason,
};
use crate::version::PlanDigest;

/// The ten failure and refusal codes H4 distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    /// The document is not an `sdd-execution-v1` plan.
    UnsupportedPlanFormat,
    /// The document claims the format but violates its schema.
    InvalidPlan,
    /// The inspector or another required tool is unavailable.
    Unavailable,
    /// A human approval is required.
    ApprovalRequired,
    /// An update conflicts with recorded state or another owner.
    Conflict,
    /// The plan bytes changed, moved, disappeared, or were unstable.
    PlanChanged,
    /// Required HTML synchronization is not established.
    HtmlNotSynced,
    /// Durable state, a process, or Git needs reconciliation.
    RecoveryRequired,
    /// A finite budget is exhausted.
    BudgetExhausted,
    /// A host commit result cannot be determined.
    GitResultUnknown,
}

impl FailureCode {
    /// Stable wire code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlanFormat => "unsupported_plan_format",
            Self::InvalidPlan => "invalid_plan",
            Self::Unavailable => "unavailable",
            Self::ApprovalRequired => "approval_required",
            Self::Conflict => "conflict",
            Self::PlanChanged => "plan_changed",
            Self::HtmlNotSynced => "html_not_synced",
            Self::RecoveryRequired => "recovery_required",
            Self::BudgetExhausted => "budget_exhausted",
            Self::GitResultUnknown => "git_result_unknown",
        }
    }

    /// The failure class of `error`, if it carries one.
    pub const fn of(error: &SddExecutionError) -> Option<Self> {
        match error {
            SddExecutionError::UnsupportedPlanFormat { .. } => Some(Self::UnsupportedPlanFormat),
            SddExecutionError::InvalidPlan { .. } => Some(Self::InvalidPlan),
            SddExecutionError::Unavailable { .. } => Some(Self::Unavailable),
            SddExecutionError::ApprovalRequired { .. } => Some(Self::ApprovalRequired),
            SddExecutionError::Conflict { .. } => Some(Self::Conflict),
            SddExecutionError::PlanChanged { .. } => Some(Self::PlanChanged),
            SddExecutionError::HtmlNotSynced { .. } => Some(Self::HtmlNotSynced),
            SddExecutionError::RecoveryRequired { .. } => Some(Self::RecoveryRequired),
            SddExecutionError::BudgetExhausted { .. } => Some(Self::BudgetExhausted),
            SddExecutionError::GitResultUnknown { .. } => Some(Self::GitResultUnknown),
            _ => None,
        }
    }
}

impl fmt::Display for FailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One H1 record named by a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum H1DetailRef {
    /// An H1 run.
    Run {
        /// Run identifier.
        run_id: RunId,
    },
    /// A submitted H1 input.
    Input {
        /// Input identifier.
        input_id: InputId,
    },
    /// An H1 tool operation.
    Operation {
        /// Operation identifier.
        operation_id: OperationId,
    },
    /// An H1 host Git operation.
    HostGit {
        /// Operation identifier.
        operation_id: OperationId,
    },
}

/// One H2 record named by a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum H2DetailRef {
    /// An H2 supervision target.
    Supervision {
        /// Supervision identifier.
        supervision_id: SupervisionId,
    },
    /// H2 evidence.
    Evidence {
        /// Supervision identifier.
        supervision_id: SupervisionId,
        /// Evidence identifier.
        evidence_id: EvidenceId,
    },
    /// An H2 assessment decision.
    Decision {
        /// Supervision identifier.
        supervision_id: SupervisionId,
        /// Decision identifier.
        decision_id: DecisionId,
    },
}

/// One H3 document or state named by a failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct H3DetailRef {
    #[serde(default)]
    document: Option<DocumentKey>,
    #[serde(default)]
    source_revision: Option<u64>,
    #[serde(default)]
    detail: Option<String>,
}

impl H3DetailRef {
    /// Creates a detail reference. At least one field must be present so the
    /// reference is not fabricated.
    pub fn new(
        document: Option<DocumentKey>,
        source_revision: Option<u64>,
        detail: Option<String>,
    ) -> Result<Self, SddExecutionError> {
        if document.is_none() && source_revision.is_none() && detail.is_none() {
            return Err(SddExecutionError::InvalidValue {
                field: "failureDetails.h3".to_owned(),
                detail: "a detail reference must name at least one H3 fact".to_owned(),
            });
        }
        Ok(Self {
            document,
            source_revision,
            detail,
        })
    }

    /// H3 document, when known.
    pub fn document(&self) -> Option<&DocumentKey> {
        self.document.as_ref()
    }

    /// H3 source revision, when known.
    pub const fn source_revision(&self) -> Option<u64> {
        self.source_revision
    }

    /// Non-secret detail text, when known.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

/// Upstream H1/H2/H3 records a failure names.
///
/// Absent references stay `None`; a failure never invents an upstream record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureDetails {
    #[serde(default)]
    h1: Option<H1DetailRef>,
    #[serde(default)]
    h2: Option<H2DetailRef>,
    #[serde(default)]
    h3: Option<H3DetailRef>,
}

impl FailureDetails {
    /// No upstream reference.
    pub const fn none() -> Self {
        Self {
            h1: None,
            h2: None,
            h3: None,
        }
    }

    /// Sets the H1 reference.
    pub fn with_h1(mut self, h1: H1DetailRef) -> Self {
        self.h1 = Some(h1);
        self
    }

    /// Sets the H2 reference.
    pub fn with_h2(mut self, h2: H2DetailRef) -> Self {
        self.h2 = Some(h2);
        self
    }

    /// Sets the H3 reference.
    pub fn with_h3(mut self, h3: H3DetailRef) -> Self {
        self.h3 = Some(h3);
        self
    }

    /// H1 reference.
    pub const fn h1(&self) -> Option<H1DetailRef> {
        self.h1
    }

    /// H2 reference.
    pub const fn h2(&self) -> Option<H2DetailRef> {
        self.h2
    }

    /// H3 reference.
    pub fn h3(&self) -> Option<&H3DetailRef> {
        self.h3.as_ref()
    }

    /// Boxes the details so the error enum stays small.
    pub fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

/// Why an approval was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ApprovalRejection {
    /// The approval came from a source that is not the H4 registry.
    ForbiddenSource {
        /// Rejected source kind.
        source: ApprovalSourceKind,
    },
    /// The approval actor was not a human.
    ActorNotHuman {
        /// Rejected actor label.
        actor: String,
    },
    /// The record belongs to another project.
    OtherProject,
    /// The plan digest differs from the approved digest.
    PlanDigestMismatch {
        /// Approved digest.
        expected: PlanDigest,
        /// Supplied digest.
        found: PlanDigest,
    },
    /// The plan revision does not match the applied revision.
    PlanRevisionMismatch {
        /// Expected revision.
        expected: PlanRevision,
        /// Supplied revision.
        found: PlanRevision,
    },
    /// A workspace fact differs from the approved value.
    WorkspaceMismatch {
        /// Field that differs.
        field: String,
    },
    /// The approval revision does not advance.
    RevisionNotAdvanced {
        /// Current approval revision.
        current: u64,
        /// Supplied approval revision.
        supplied: u64,
    },
    /// One current input no longer matches the approved value.
    ///
    /// The field names the exact part (for example `plan.specRefs`,
    /// `task.2.scope`, or `connection.profile`) so a start refusal points at
    /// what a human must re-approve instead of re-approving silently.
    CurrentInputsChanged {
        /// Field that differs.
        field: String,
    },
}

/// Structured H4 contract error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum SddExecutionError {
    /// The H4 contract version is not supported by this build.
    UnsupportedContractVersion {
        /// Version found.
        found: u32,
        /// Version written by this build.
        expected: u32,
    },
    /// The plan schema version is not supported by this build.
    UnsupportedPlanSchemaVersion {
        /// Version found.
        found: u32,
        /// Version written by this build.
        expected: u32,
    },
    /// The plan inspector protocol is not supported by this build.
    UnsupportedInspectorProtocol {
        /// Protocol identity found.
        found: String,
        /// Protocol identity expected.
        expected: String,
    },
    /// A typed H4 identifier could not be parsed.
    InvalidId {
        /// Expected identifier kind.
        id_kind: String,
        /// Rejected value.
        value: String,
    },
    /// An identifier belongs to a different project.
    CrossProjectReference {
        /// Identifier kind that was checked.
        id_kind: String,
        /// Project expected by the caller.
        expected: ProjectId,
        /// Project carried by the identifier.
        found: ProjectId,
    },
    /// A free-form value failed validation.
    InvalidValue {
        /// Field name.
        field: String,
        /// Non-secret explanation.
        detail: String,
    },
    /// An approval was forged, foreign, stale, or from a forbidden source.
    ApprovalRejected {
        /// Structured reason.
        reason: ApprovalRejection,
    },
    /// A compare-and-set update used a stale execution revision.
    RevisionConflict {
        /// Revision expected by the caller.
        expected: ExecutionRevision,
        /// Revision found in the store.
        found: ExecutionRevision,
    },
    /// A duplicate request ID was reused with different content.
    DuplicateRequestConflict {
        /// Recorded content fingerprint.
        recorded: String,
        /// Supplied content fingerprint.
        supplied: String,
    },
    /// A different result is already recorded for the request ID.
    DuplicateResultConflict {
        /// Request identifier.
        request: String,
    },
    /// An execution or Task state transition is not legal.
    IllegalStateTransition {
        /// State or phase before the attempt.
        from: String,
        /// State or phase after the attempt.
        to: String,
    },
    /// A snapshot or approval value violates a structural invariant.
    InvalidSnapshot {
        /// Field name.
        field: String,
        /// Non-secret explanation.
        detail: String,
    },
    /// The document is not an `sdd-execution-v1` plan.
    UnsupportedPlanFormat {
        /// Pack diagnostic.
        diagnostic: PlanDiagnostic,
        /// Upstream references.
        details: Box<FailureDetails>,
    },
    /// The document claims the format but violates its schema.
    InvalidPlan {
        /// Pack diagnostic.
        diagnostic: PlanDiagnostic,
        /// Upstream references.
        details: Box<FailureDetails>,
    },
    /// A required tool or capability is unavailable.
    Unavailable {
        /// Unavailable feature label.
        feature: String,
        /// Upstream references.
        details: Box<FailureDetails>,
    },
    /// A human approval is required.
    ApprovalRequired {
        /// What is missing.
        reason: ApprovalRequirement,
        /// Upstream references.
        details: Box<FailureDetails>,
    },
    /// An update conflicts with recorded state or another owner.
    Conflict {
        /// Structured conflict reason.
        reason: ConflictReason,
        /// Upstream references.
        details: Box<FailureDetails>,
    },
    /// The plan bytes changed, moved, disappeared, or were unstable.
    PlanChanged {
        /// Structured reason.
        reason: PlanChangeReason,
        /// Upstream references.
        details: Box<FailureDetails>,
    },
    /// Required HTML synchronization is not established.
    HtmlNotSynced {
        /// Structured reason.
        reason: HtmlSyncReason,
        /// Upstream references.
        details: Box<FailureDetails>,
    },
    /// Durable state, a process, or Git needs reconciliation.
    RecoveryRequired {
        /// Structured reason.
        reason: RecoveryReason,
        /// Upstream references.
        details: Box<FailureDetails>,
    },
    /// A finite budget is exhausted.
    BudgetExhausted {
        /// Exhausted budget.
        reason: BudgetExhaustionReason,
        /// Upstream references.
        details: Box<FailureDetails>,
    },
    /// A host commit result cannot be determined.
    GitResultUnknown {
        /// Structured reason.
        reason: GitUnknownReason,
        /// Upstream references.
        details: Box<FailureDetails>,
    },
}

impl SddExecutionError {
    /// The failure class this error reports, when it is one of the ten H4
    /// distinctions.
    pub const fn failure_code(&self) -> Option<FailureCode> {
        FailureCode::of(self)
    }

    /// Upstream references carried by a failure or refusal.
    pub fn failure_details(&self) -> Option<&FailureDetails> {
        match self {
            Self::UnsupportedPlanFormat { details, .. }
            | Self::InvalidPlan { details, .. }
            | Self::Unavailable { details, .. }
            | Self::ApprovalRequired { details, .. }
            | Self::Conflict { details, .. }
            | Self::PlanChanged { details, .. }
            | Self::HtmlNotSynced { details, .. }
            | Self::RecoveryRequired { details, .. }
            | Self::BudgetExhausted { details, .. }
            | Self::GitResultUnknown { details, .. } => Some(details),
            _ => None,
        }
    }

    /// The pack diagnostic for a plan defect.
    pub fn plan_diagnostic(&self) -> Option<&PlanDiagnostic> {
        match self {
            Self::UnsupportedPlanFormat { diagnostic, .. }
            | Self::InvalidPlan { diagnostic, .. } => Some(diagnostic),
            _ => None,
        }
    }
}

impl fmt::Display for SddExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedContractVersion { found, expected } => {
                write!(
                    f,
                    "unsupported H4 contract version {found}; expected {expected}"
                )
            }
            Self::UnsupportedPlanSchemaVersion { found, expected } => {
                write!(
                    f,
                    "unsupported plan schema version {found}; expected {expected}"
                )
            }
            Self::UnsupportedInspectorProtocol { found, expected } => {
                write!(
                    f,
                    "unsupported plan inspector protocol {found}; expected {expected}"
                )
            }
            Self::InvalidId { id_kind, value } => {
                write!(f, "invalid {id_kind} identifier {value:?}")
            }
            Self::CrossProjectReference {
                id_kind,
                expected,
                found,
            } => write!(
                f,
                "{id_kind} belongs to project {found}, but {expected} was required"
            ),
            Self::InvalidValue { field, detail } => write!(f, "{field}: {detail}"),
            Self::ApprovalRejected { reason } => write!(f, "approval rejected: {reason:?}"),
            Self::RevisionConflict { expected, found } => write!(
                f,
                "execution revision conflict: expected {}, found {}",
                expected.get(),
                found.get()
            ),
            Self::DuplicateRequestConflict { recorded, supplied } => write!(
                f,
                "the request ID already carries content {recorded}; supplied {supplied}"
            ),
            Self::DuplicateResultConflict { request } => {
                write!(f, "a different result is recorded for request {request}")
            }
            Self::IllegalStateTransition { from, to } => {
                write!(f, "illegal transition {from} -> {to}")
            }
            Self::InvalidSnapshot { field, detail } => write!(f, "{field}: {detail}"),
            Self::UnsupportedPlanFormat { diagnostic, .. } => write!(
                f,
                "{}: {}",
                diagnostic.code().as_str(),
                diagnostic.message()
            ),
            Self::InvalidPlan { diagnostic, .. } => {
                write!(
                    f,
                    "{}: {}",
                    diagnostic.code().as_str(),
                    diagnostic.message()
                )
            }
            Self::Unavailable { feature, .. } => write!(f, "{feature} is unavailable"),
            Self::ApprovalRequired { reason, .. } => {
                write!(f, "approval required: {reason:?}")
            }
            Self::Conflict { reason, .. } => write!(f, "conflict: {reason:?}"),
            Self::PlanChanged { reason, .. } => write!(f, "plan changed: {reason:?}"),
            Self::HtmlNotSynced { reason, .. } => {
                write!(f, "HTML is not synced: {reason:?}")
            }
            Self::RecoveryRequired { reason, .. } => {
                write!(f, "recovery required: {reason:?}")
            }
            Self::BudgetExhausted { reason, .. } => {
                write!(f, "budget exhausted: {reason:?}")
            }
            Self::GitResultUnknown { reason, .. } => {
                write!(f, "git result unknown: {reason:?}")
            }
        }
    }
}

impl std::error::Error for SddExecutionError {}
