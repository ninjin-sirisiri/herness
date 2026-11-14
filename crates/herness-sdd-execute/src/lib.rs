//! H4 host-owned SDD execution contracts, approvals, snapshots, journals, and
//! ports.
//!
//! This crate owns the H4 contract types only: execution and Task identity,
//! execution states and Task phases, immutable execution approvals, execution
//! snapshots, dispatch/Git/progress journals with request idempotency, and the
//! host-owned ports. It contains no SQLite, Tauri, desktop, engine, or Pi
//! dependency and performs no I/O.
//!
//! H4 consumes the public H1, H2, and H3 contracts. It does not redefine H1 run
//! states, H2 supervision states or identifiers, or H3 barrier semantics, and
//! `herness-core`, `herness-supervision`, and `herness-html-sync` never depend
//! on this crate. An H2 `completed` record is never an H4 Task completion; only
//! H4's own verification, HTML barrier, host commit, and durable write make a
//! Task `complete`.
//!
//! Task 12 adds the pure import side of the pack inspector: [`import`] decodes
//! the `sdd-plan-inspect` response into a validated [`PlanPreview`], maps every
//! inspector failure onto an H4 class, and verifies the spec/source snapshots a
//! preview binds. It performs no I/O; the desktop bridge supplies the bytes.
//!
//! The ten failure and refusal classes (`unsupported_plan_format`,
//! `invalid_plan`, `unavailable`, `approval_required`, `conflict`,
//! `plan_changed`, `html_not_synced`, `recovery_required`,
//! `budget_exhausted`, `git_result_unknown`) are distinct typed errors and can
//! carry H1, H2, or H3 detail references.

#![doc = "The H4 numeric defaults are the approved spec values. This crate does not add a plan-wide budget, raise the finite H2 limits, or turn a saved `Synced`/receipt into evidence."]

pub mod approval;
pub mod contract;
pub mod durable;
pub mod error;
pub mod events;
pub mod ids;
pub mod import;
pub mod journal;
pub mod plan;
pub mod ports;
pub mod record;
pub mod snapshot;
pub mod state;
pub mod version;

pub use approval::{
    ApprovalContent, ApprovalSource, ApprovalSourceKind, ApprovedCheck, ApprovedCondition,
    ApprovedDeliverable, ApprovedSpecRef, CommitAuthorization, CommitPolicy, ConditionMode,
    DeliverableKind, ExecutionApproval, ExecutionConnection, ExternalSourceApproval, GitIdentity,
    H3ApprovalBinding, PackApproval, PlanApproval, TaskApproval, WorkspaceApproval,
};
pub use contract::{
    ApprovalContract, CheckoutClaim, ContinuationLimits, ControlRecord, Delegation,
    DelegationRules, ExecutionOperation, ExecutionOperationRequest, ExecutionOperationResult,
    ExecutionRequirements, HostExecutionContract, HtmlBarrier, ReadExecutionRequest,
    ensure_execution_project,
};
pub use durable::{BudgetIncrement, DispatchManifest, DurableExecutionStorePort, TaskReservation};
pub use error::{
    ApprovalRejection, FailureCode, FailureDetails, H1DetailRef, H2DetailRef, H3DetailRef,
    SddExecutionError,
};
pub use events::{
    SDD_DISPATCH_EVENT_KIND, SDD_EXECUTION_ACTIVITY_KIND, SDD_GIT_EVENT_KIND,
    SDD_OPERATION_EVENT_KIND, SDD_PROGRESS_EVENT_KIND, SDD_SNAPSHOT_EVENT_KIND, dispatch_event,
    execution_activity_id, git_event, operation_event, progress_event, revision_of, snapshot_event,
};
pub use herness_html_sync::H4Barrier;
pub use ids::{
    ApprovalId, ApprovalKind, Baseline, ChildIdentity, CommitKind, CommitRequestId, CommitSha,
    ControlKind, ControlRequestId, DispatchKind, DispatchRequestId, ExecutionId, ExecutionKeyKind,
    ExecutionKind, ExecutionRevision, ExecutionScopedId, H2SupervisionRef, PlanRevision,
    ProgressJournalId, ProgressKind, ProjectSequence, RunInputRef, TaskKind, TaskNumber, TaskRef,
    TaskStableId, TreeSha,
};
pub use import::{
    AliasRoot, CONTRACT_FEATURE, CONTRACT_INPUT_FEATURE, CapabilitiesReport, ContractInput,
    EXIT_FEATURE, ExecutionBlockFacts, InspectorFailure, InspectorFailureCode, InspectorOperation,
    MAX_SPEC_SNAPSHOT_BYTES, OVERSIZE_PLAN_FEATURE, OVERSIZE_RESPONSE_FEATURE,
    OVERSIZE_SNAPSHOT_FEATURE, PACK_FEATURE, PROTOCOL_FEATURE, PlanHeaderFacts, PlanPreview,
    PreviewSpecRef, PreviewTask, REQUIRED_CONTRACT_INPUTS, RESPONSE_FEATURE, ResolvedSource,
    SectionSnapshot, SourceLayout, SourceSnapshot, SpecSnapshotSet, TIMEOUT_FEATURE,
    VerifiedSpecSnapshot, decode_capabilities_response, inspect_request_envelope,
    inspector_failure_error, validate_source_alias, verify_spec_snapshots,
};
pub use journal::{
    CommitMessage, CommitTrailer, CommittedPath, DispatchContent, DispatchJournalEntry,
    DispatchRequest, DispatchResult, GitCommitIntent, GitCommitOutcome, GitJournalEntry,
    GitJournalState, GitRejection, JournalContent, JournalEntryState, PreHookState,
    ProgressContent, ProgressFailure, ProgressJournalEntry, ProgressJournalState, ProgressTaskLine,
    ProgressWriteOutcome, RequestDecision, RequestIdentity, RequestRecord, decide_request,
};
pub use plan::{
    ExactPlanBytes, ExactPlanText, InspectRequest, InspectedPlan, InspectorCapabilities,
    InspectorProtocol, ParsedPlanSummary, ParsedPlanTask, PlanByteRange, PlanDiagnostic,
    PlanDiagnosticCode, PlanPath, validate_check_cwd, validate_project_path,
};
pub use ports::{
    ChildDispatchPlan, ChildDispatchPort, ClockPort, ExecutionFeature, ExecutionStorePort,
    HostGitPort, HtmlBarrierPort, PlanInspectorPort, PlanObservation, PlanSourcePort,
    PlanSourceRead, ProgressLedgerPort, StoredControlResult, StoredExecution, SupervisionTargetId,
    WorkspacePort, WorkspacePreparation, WorkspaceState, unsupported,
};
pub use record::{RecordDecodeError, STORE_RECORD_FORMAT_VERSION, decode_record, encode_record};
pub use snapshot::{
    BudgetConsumption, CommitRange, ExecutionSnapshot, NoChangeRecord, SnapshotBudget,
    SnapshotInput, SnapshotPlan, SnapshotWorkspace, TaskSnapshot,
};
pub use state::{
    AppliedRevision, AppliedRevisionState, ApprovalRequirement, BudgetExhaustionReason,
    ConflictReason, ExecutionState, GitUnknownReason, HtmlSyncReason, HumanAction,
    PlanChangeReason, RecoveryReason, StopReason, StopRecord, TaskPhase, TaskProgression,
};
pub use version::{
    APPROVAL_APPROVER, APPROVAL_KIND, APPROVAL_SOURCE_REGISTRY, EXECUTION_CONTRACT_SCHEMA,
    EXECUTION_CONTRACT_VERSION, ExecutionContractVersion, H4_MAX_ADDITIONAL_RUNS,
    H4_MAX_CONSECUTIVE_STALLS, H4_MAX_SUPERVISION_SECONDS, HOST_COMMIT_TIMEOUT_SECONDS,
    INSPECTOR_TIMEOUT_SECONDS, MAX_CONCURRENT_TASK_EXECUTIONS, MAX_PLAN_BYTES,
    PLAN_EXECUTION_BLOCK_INFO, PLAN_INSPECTOR_PROTOCOL, PLAN_INSPECTOR_PROTOCOL_VERSION,
    PLAN_PATH_PREFIX, PLAN_RECONCILE_INTERVAL_MILLIS, PLAN_SCHEMA_NAME, PLAN_SCHEMA_VERSION,
    PackFingerprint, PlanDigest, RequestFingerprint, SDD_EXECUTION_CONTRACT_VERSION, Sha256Digest,
    current_contract_version, ensure_current_version, ensure_supported_version,
};
