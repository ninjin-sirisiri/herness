//! Structured, non-secret supervision errors.
//!
//! Error payloads never carry credentials, provider bodies, prompts, evidence
//! content, or model text. They describe which contract boundary rejected the
//! operation so a later task can persist a reason without leaking data.

use std::fmt;

use herness_core::contracts::ProjectId;
use serde::{Deserialize, Serialize};

use crate::budget::{BudgetClockState, BudgetLimit, BudgetPriceReason};
use crate::consent::ConsentBlock;
use crate::profiles::ProfileUnavailable;
use crate::state::{CompletionBlocker, SupervisionState};
/// Structured supervision contract error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum SupervisionError {
    /// The supervision contract version is not supported by this build.
    UnsupportedContractVersion {
        /// Version found.
        found: u32,
        /// Version written by this build.
        expected: u32,
    },
    /// A typed supervision identifier could not be parsed.
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
    /// A model attempted to approve or change conditions, a profile, a limit,
    /// or a permission scope.
    ModelCannotApproveOrChange {
        /// Operation the model attempted.
        action: String,
    },
    /// An approval was forged, foreign, stale, or expired.
    ApprovalRejected {
        /// Structured reason.
        reason: ApprovalRejection,
    },
    /// An assessment decision is stale for the current condition or target.
    StaleAssessment {
        /// Current condition version.
        current_condition_version: u64,
        /// Version carried by the assessment.
        assessment_condition_version: u64,
        /// Current target version.
        current_target_version: u64,
        /// Version carried by the assessment.
        assessment_target_version: u64,
    },
    /// A completion attempt was blocked by a higher-priority state or unmet
    /// condition.
    CompletionBlocked {
        /// Every blocker observed by the host.
        blockers: Vec<CompletionBlocker>,
    },
    /// A compare-and-set update used a stale revision.
    RevisionConflict {
        /// Revision expected by the caller.
        expected: u64,
        /// Revision found in the store.
        found: u64,
    },
    /// The supervision target is unknown or was already removed.
    UnknownSupervision,
    /// A duplicate command ID was reused with a different command.
    DuplicateRequestConflict {
        /// Request identifier.
        request: String,
        /// Command already recorded for the identifier.
        recorded: String,
        /// Command supplied by the caller.
        supplied: String,
    },
    /// A different command result is already recorded for the request ID.
    DuplicateResultConflict {
        /// Request identifier.
        request: String,
    },
    /// The selected assessment profile cannot be used.
    ProfileUnavailable {
        /// Structured reason.
        reason: ProfileUnavailable,
    },
    /// Disclosure consent does not permit the request.
    ConsentBlocked {
        /// Structured reason.
        reason: ConsentBlock,
    },
    /// A finite budget value is invalid.
    BudgetInvalid {
        /// Field name.
        field: String,
        /// Non-secret explanation.
        detail: String,
    },
    /// A finite budget limit would be exceeded.
    BudgetLimitReached {
        /// Limit that was reached.
        limit: BudgetLimit,
    },
    /// A money-capped request has no usable local price estimate.
    BudgetPriceUnavailable {
        /// Structured reason.
        reason: BudgetPriceReason,
    },
    /// The ledger is not Active, so no send or run may start.
    BudgetInactive {
        /// Current activity state.
        state: BudgetClockState,
    },
    /// A different reservation is already recorded for the same attempt.
    BudgetReservationConflict {
        /// Reservation attempt identifier.
        attempt: String,
    },
    /// An observation refers to an attempt with no recorded money reservation.
    UnknownBudgetReservation {
        /// Reservation attempt identifier.
        attempt: String,
    },
    /// A condition or check reference is unknown in its set.
    UnknownConditionReference {
        /// Referenced identifier.
        reference: String,
    },
    /// An evidence record is missing one of the five contract items.
    EvidenceContractViolation {
        /// Missing or invalid field.
        field: String,
        /// Non-secret explanation.
        detail: String,
    },
    /// An assessment request or result violates its contract.
    AssessmentContractViolation {
        /// Missing or invalid field.
        field: String,
        /// Non-secret explanation.
        detail: String,
    },
    /// A state is paired with a reason that belongs to another state.
    InvalidStateReason {
        /// State that was requested.
        state: SupervisionState,
        /// Reason that does not describe that state.
        reason: String,
    },
    /// A later phase must implement this capability.
    Unsupported {
        /// Capability label.
        feature: String,
    },
    /// Explicit resume or reassessment is blocked by unreconciled state.
    NotResumable {
        /// Structured blockers. No side effect was performed.
        reasons: Vec<crate::recovery::RecoveryBlockReason>,
    },
    /// Durable storage could not complete the operation.
    StorageFailure {
        /// Sanitized description; never contains stored content.
        detail: String,
    },
}

/// Why an approval was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ApprovalRejection {
    /// A model-origin approval is never accepted.
    ModelOrigin,
    /// The approving actor does not match the recorded approval basis.
    ActorMismatch,
    /// An inherited owner approval does not name an approved H3/H4 owner.
    OwnerNotApproved,
    /// The owner reference and the approval source disagree.
    SourceOwnerMismatch,
    /// The approval already expired.
    Expired {
        /// Expiry timestamp in unix milliseconds.
        expires_at: u64,
        /// Comparison timestamp in unix milliseconds.
        now: u64,
    },
    /// The approval covers a different condition version.
    StaleVersion {
        /// Version approved.
        approved: u64,
        /// Version used now.
        found: u64,
    },
    /// The approval covers different condition content.
    StaleDigest,
    /// The approval was recorded for another project.
    ProjectMismatch,
    /// No approval was recorded at all.
    MissingApproval,
}

impl fmt::Display for SupervisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedContractVersion { found, expected } => {
                write!(
                    f,
                    "unsupported supervision contract version {found}; expected {expected}"
                )
            }
            Self::InvalidId { id_kind, value } => {
                write!(f, "invalid {id_kind} id {value:?}")
            }
            Self::CrossProjectReference {
                id_kind,
                expected,
                found,
            } => write!(
                f,
                "{id_kind} belongs to project {found}, not the expected project {expected}"
            ),
            Self::InvalidValue { field, detail } => write!(f, "invalid {field}: {detail}"),
            Self::ModelCannotApproveOrChange { action } => write!(
                f,
                "a model cannot {action}; only a human or an approved owner may do so"
            ),
            Self::ApprovalRejected { reason } => {
                write!(f, "approval rejected: {reason:?}")
            }
            Self::StaleAssessment { .. } => {
                f.write_str("assessment is stale for the current condition or target version")
            }
            Self::CompletionBlocked { blockers } => {
                write!(f, "completion is blocked by {blockers:?}")
            }
            Self::RevisionConflict { expected, found } => {
                write!(
                    f,
                    "supervision revision changed: expected {expected}, found {found}"
                )
            }
            Self::UnknownSupervision => f.write_str("supervision target is unknown"),
            Self::DuplicateRequestConflict {
                request,
                recorded,
                supplied,
            } => write!(
                f,
                "request {request} was already used for {recorded}, not {supplied}"
            ),
            Self::DuplicateResultConflict { request } => {
                write!(
                    f,
                    "request {request} already has a different recorded result"
                )
            }
            Self::ProfileUnavailable { reason } => {
                write!(f, "assessment profile unavailable: {reason:?}")
            }
            Self::ConsentBlocked { reason } => {
                write!(f, "disclosure consent blocked the request: {reason:?}")
            }
            Self::BudgetInvalid { field, detail } => {
                write!(f, "invalid budget value {field}: {detail}")
            }
            Self::BudgetLimitReached { limit } => {
                write!(f, "the {limit:?} budget limit has been reached")
            }
            Self::BudgetPriceUnavailable { reason } => {
                write!(f, "budget price unavailable: {reason:?}")
            }
            Self::BudgetInactive { state } => {
                write!(f, "the budget ledger is not active (state {state:?})")
            }
            Self::BudgetReservationConflict { attempt } => {
                write!(f, "attempt {attempt} already has a different reservation")
            }
            Self::UnknownBudgetReservation { attempt } => {
                write!(f, "attempt {attempt} has no recorded money reservation")
            }
            Self::UnknownConditionReference { reference } => {
                write!(f, "unknown condition/check reference {reference}")
            }
            Self::EvidenceContractViolation { field, detail } => {
                write!(f, "evidence contract field {field}: {detail}")
            }
            Self::AssessmentContractViolation { field, detail } => {
                write!(f, "assessment contract field {field}: {detail}")
            }
            Self::InvalidStateReason { state, reason } => {
                write!(f, "reason {reason:?} does not describe state {state}")
            }
            Self::Unsupported { feature } => {
                write!(
                    f,
                    "supervision feature {feature} is not implemented by this build"
                )
            }
            Self::NotResumable { reasons } => {
                write!(
                    f,
                    "supervision is not resumable without reconciliation: {reasons:?}"
                )
            }
            Self::StorageFailure { detail } => {
                write!(f, "supervision storage failed: {detail}")
            }
        }
    }
}

impl std::error::Error for SupervisionError {}
