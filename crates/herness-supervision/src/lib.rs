//! H2 supervision contracts, approval, profiles, disclosure consent, evidence,
//! budget, assessment, state, and ports.
//!
//! This crate depends only on `herness-core`. It contains no SQLite, engine,
//! provider, or Tauri dependency and performs no I/O. H1 remains the owner of
//! run states, permission priority, and stop semantics; H2 states are separate
//! and never change H1 behavior.

#![doc = "The H2 numeric defaults are conservative initial values, not safety, accuracy, or calibration guarantees."]

pub mod approval;
pub mod assessment;
pub mod budget;
pub mod command;
pub mod conditions;
pub mod consent;
pub mod contract;
pub mod error;
pub mod evidence;
pub mod freshness;
pub mod ids;
pub mod ports;
pub mod profiles;
pub mod state;
pub mod verification;
pub mod version;

pub use approval::{ApprovalActor, ApprovalBasis, ConditionApproval, OwnerApprovalSource};
pub use assessment::{
    AssessmentOutcome, AssessmentProvenance, AssessmentRequest, AssessmentResult,
    ConditionProbabilities, ConditionVerdict, NativeConfidence, PermissionAssessment,
    PermissionProbabilities, PermissionVerdict, RationaleOrigin,
};
pub use budget::gate::{BudgetRequestGate, RequestBudgetEstimator};
pub use budget::ledger::{
    ActiveInterval, BUDGET_MAX_CAS_ATTEMPTS, BudgetClockPort, BudgetLedger, BudgetLedgerRecord,
    ClockReading, MoneyReservation, MoneyReservationState, MoneySettlement, RunReservation,
    RunReservationState,
};
pub use budget::{
    BudgetClockState, BudgetLimit, BudgetPolicy, BudgetPriceReason, BudgetUsage, H2_ACTIVE_SECONDS,
    H2_ADDITIONAL_RUNS, H2_ASSESSMENT_TIMEOUT_SECONDS, H2_MAX_ADDITIONAL_RETRIES,
    H2_MAX_TOTAL_RUNS, H2_RETRY_DELAY_MILLIS, H2_STAGNATION_CYCLES, Money, MoneyCap, PriceVersion,
    RequestBudgetEstimate, assessment_timeout_seconds, billed_active_seconds,
    chatgpt_login_allowed_with_money_cap, validate_assessment_spend,
};
pub use command::{CommandResult, SupervisionCommand, SupervisionRequest, execute_command};
pub use conditions::{
    Condition, ConditionDigest, ConditionOrigin, ConditionSet, ConditionVersion, RequiredCheck,
};
pub use consent::{
    ConsentApprover, ConsentBinding, ConsentBlock, ConsentState, DisclosureConsent,
    DisclosureDataKind, DisclosureRequest, DisclosureScope, OriginScheme, ProviderOrigin,
};
pub use contract::{
    ExecutionScope, OwnerKind, OwnerRef, RunGroup, SupervisionContract, SupervisionSubject,
    approval_matches_conditions, disclosure_purpose, same_approval_kind,
};
pub use error::{ApprovalRejection, SupervisionError};
pub use evidence::{
    CheckStatus, ContentDigest, ContentFingerprint, EvidenceAcquirer, EvidenceOutcome,
    EvidenceRecord, EvidenceScope, RequiredCheckResult, TargetScope, TargetVersion,
    VerificationOperation, fingerprint_bytes,
};
pub use freshness::{
    CompletionFreshness, EvidenceApplicability, EvidenceFreshness, FreshnessReport,
    FreshnessService, InputOrigin, ManifestCoverage, ManifestDiff, ManifestEntry,
    StaleCompletionReport, TargetManifest, TargetReadSet, WorkspaceInput, WorkspaceSnapshotPort,
    capture_manifest,
};
pub use ids::{
    BudgetRequestId, CheckId, ConditionId, ConsentId, DecisionId, EvidenceId, ProfileId,
    RunGroupId, SupervisionId, SupervisionKeyKind, SupervisionRequestId, SupervisionScopedId,
};
pub use ports::{
    AssessmentPort, BudgetStorePort, ClockPort, EvidenceStorePort, StoredBudgetRecord,
    SupervisionFeature, SupervisionStorePort, unsupported,
};
pub use profiles::{
    AdapterVersion, AssessmentProfile, H2_COMPLETION_MET_THRESHOLD, H2_COMPLETION_UNMET_THRESHOLD,
    H2_DISTRIBUTION_TOLERANCE, H2_PERMISSION_ALLOW_THRESHOLD, H2_PERMISSION_DENY_THRESHOLD,
    ProfileBinding, ProfileCatalog, ProfileEntry, ProfileInputs, ProfilePurpose, ProfileThresholds,
    ProfileUnavailable, ProfileVersion, ProviderKind, RubricVersion, reject_run_model_substitution,
};
pub use state::{
    AppliedDecision, AssessmentApplication, CancelCause, CompletionBlocker, CompletionSnapshot,
    DecisionInvalidation, HumanAction, InvalidatedDecision, StaleCompletion, StopCause,
    SupervisionFailure, SupervisionReason, SupervisionRecord, SupervisionState,
};
pub use verification::{
    GatewayVerification, VerificationBoundary, VerificationBoundaryOutcome,
    VerificationDisposition, VerificationExecution, VerificationPlan, VerificationService,
    validate_evidence_record,
};
pub use version::{SUPERVISION_CONTRACT_VERSION, current_contract_version, ensure_current_version};
