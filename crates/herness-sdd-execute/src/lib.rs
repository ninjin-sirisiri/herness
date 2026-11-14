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
//! Task 14 adds the two values one Task's child work depends on:
//!
//! * [`packet`] composes the immutable, fingerprinted [`TaskPacket`] — the exact
//!   Task body, the verbatim Global Constraints, the applied spec sections with
//!   their approved snapshot text, prior interfaces and Rulings and unresolved
//!   items, the approved scope and checks, and the report requirements. It never
//!   pastes the whole plan or a diff, it is byte-deterministic for the same
//!   inputs, and a context over capacity is an explicit human wait instead of a
//!   truncation.
//! * [`report`] parses the child's report and interprets it: `DONE` alone is not
//!   completion, a missing evidence field is an explicit gap, `BLOCKED`,
//!   `NEEDS_CONTEXT`, an important unagreed item, and a claimed host commit are
//!   human waits, and an absent or unparseable report is never `DONE`. Reversible
//!   `Ruling`s are retained for later packets.
//!
//! Task 15 adds the serial coordinator and the combined Task budget:
//!
//! * [`coordinator`] decides exactly one step per call over the ports: it selects
//!   the first not-complete Task in plan order, verifies the current approval,
//!   checkout claim, and plan revision before any side effect, persists the
//!   dispatch intent and H2 binding before the one child exists, re-reads the
//!   stored H2 result instead of trusting a notification, and never lets a Task
//!   leave H2's completion unless the host barrier and commit are connected.
//!   [`coordinator::TaskCoordinator::advance`] is the entry point and
//!   [`coordinator::CoordinatorOutcome`] is the decision.
//! * [`budget`] is the finite Task budget: H2 supervision consumption plus H4's
//!   own host-side post-completion processing under 7,200 s, 30 additional runs,
//!   and 3 consecutive stalls. It is monotonic across resume, restart, and plan
//!   re-approval, and "met after the limit" is a typed refusal, not completion.
//!
//! Task 16 adds [`barrier`]: the H3 required-document union and the completion
//! barrier. The union is the Task's `htmlTargets`, the executing plan and the
//! project specs, the documents the common-Target scan confirms changed, and
//! every H3 document whose recorded dependency fingerprint changed. When the
//! set or a dependency cannot be determined it widens to the declared Target
//! scope or waits for a human; it never narrows silently. The barrier asserts
//! the exact revision, bytes, and dependency fingerprints H4 captured before
//! verification, so a saved `Synced` response or a repository receipt is never
//! trusted on its own, and it keeps `NotApproved`, `Missing`, `Mismatch`,
//! `Unsynced`, and `Orphaned` distinct.
//!
//! Task 17 adds [`git`]: the host commit finalization and the Git recovery
//! classification. [`git::finalize_task`] fixes the target set
//! (`git::select_targets`), records the intent, runs the approved host boundary,
//! records the result, and re-reads HEAD, tree, parent, trailers, index, and the
//! tracked bytes before it reports completion. A `required` Task must advance
//! HEAD from BASE; a `no_change` Task records unchanged-source evidence and
//! creates no commit. A replayed request returns the stored result, and any
//! hook failure, changed hook, unrelated index entry, external edit, unconfirmed
//! process, or failed durable write is an explicit hold that is never retried.
//! [`git::classify_commit`] classifies a saved intent as `Established`,
//! `NotRun`, or `Unknown` without mutating anything, so a human recovery can
//! link only a clearly established commit.
//!
//! The ten failure and refusal classes (`unsupported_plan_format`,
//! `invalid_plan`, `unavailable`, `approval_required`, `conflict`,
//! `plan_changed`, `html_not_synced`, `recovery_required`,
//! `budget_exhausted`, `git_result_unknown`) are distinct typed errors and can
//! carry H1, H2, or H3 detail references.
//!
//! Task 19 adds [`plan_changes`]: the typed plan-change detection, the durable
//! safety-stop latch, and the limited re-approval.
//!
//! * [`plan_changes::PlanChange`] reports `BytesChanged`, `Missing`, `Moved`, or
//!   `UnstableObservation` with the observed digest and length, the candidate
//!   path, the changed byte ranges, and whether the fenced execution JSON block
//!   is byte-identical. A JSON-identical change is never ignored: the parsed
//!   result compares the exact Global Constraints text and every Task body, so
//!   a prose-only edit is still a change.
//! * [`plan_changes::PlanChangeGate`] performs the observation, persists the
//!   latch, and answers whether a side effect may run. The coordinator asks it
//!   before dispatch, before it accepts H2's verification, and immediately
//!   before the host commit; the host also ticks it once per
//!   [`version::PLAN_RECONCILE_INTERVAL_MILLIS`], so a lost watcher
//!   notification is still caught.
//! * [`plan_changes::PlanChangeLatch`] is the durable stop. Returning to the
//!   previously approved bytes never clears it; only a human-approved plan
//!   revision does. A post-completion change keeps every recorded completion and
//!   the consumed budget and marks only the applied revision stale.
//! * [`plan_changes::evaluate_inheritance`] allows a new version only when the
//!   plan path, the Global Constraints, the root spec references, the connection
//!   and profile, and every completed or started Task's body and contract are
//!   unchanged and only not-yet-started Tasks differ. Everything else is
//!   `Incompatible` and requires a new plan and human work-state cleanup.
//! * [`plan_changes::approve_plan_revision`] saves that human revision after a
//!   confirmed stop, keeps the consumed budget and commit history, clears the
//!   latch, and is idempotent: a re-delivered request returns its stored result.

#![doc = "The H4 numeric defaults are the approved spec values. This crate does not add a plan-wide budget, raise the finite H2 limits, or turn a saved `Synced`/receipt into evidence."]

pub mod approval;
pub mod approval_registry;
pub mod barrier;
pub mod budget;
pub mod contract;
pub mod coordinator;
pub mod durable;
pub mod error;
pub mod events;
pub mod finish;
pub mod git;
pub mod ids;
pub mod import;
pub mod journal;
pub mod ledger;
pub mod packet;
pub mod plan;
pub mod plan_changes;
pub mod ports;
pub mod record;
pub mod report;
pub mod snapshot;
pub mod state;
pub mod version;

pub use approval::{
    ApprovalContent, ApprovalSource, ApprovalSourceKind, ApprovedCheck, ApprovedCondition,
    ApprovedDeliverable, ApprovedSpecRef, CommitAuthorization, CommitPolicy, ConditionMode,
    DeliverableKind, ExecutionApproval, ExecutionConnection, ExternalSourceApproval, GitIdentity,
    H3ApprovalBinding, PackApproval, PlanApproval, TaskApproval, WorkspaceApproval,
};
pub use approval_registry::{
    ApprovalInputs, ApprovalRevisionStorePort, MemoryApprovalRevisionStore, MemoryStartRecordStore,
    ObservedConnection, START_RECORD_FORMAT_VERSION, StartApprovalPost, StartApprovalRegistry,
    StartPhase, StartReceipt, StartRecord, StartRecordStorePort, ensure_budgets,
    start_record_format_version, task_budget,
};
pub use barrier::{
    BarrierCapture, BarrierDecision, BarrierHold, BarrierReport, CapturedDocument, CheckedDocument,
    DocumentBarrier, DocumentBaseline, DocumentOrigin, RequiredDocument, RequiredDocumentSet,
    RequiredSetInputs, RequiredSetOutcome, SavedDocument, ScannedTarget, StoredTarget,
    check_barrier, required_documents, verification_request,
};
pub use budget::{TaskBudget, TaskBudgetConsumption, TaskBudgetExhaustion};
pub use contract::{
    ApprovalContract, CheckoutClaim, ContinuationLimits, ControlRecord, Delegation,
    DelegationRules, ExecutionOperation, ExecutionOperationRequest, ExecutionOperationResult,
    ExecutionRequirements, HostExecutionContract, HtmlBarrier, ReadExecutionRequest,
    ensure_execution_project,
};
pub use coordinator::{
    ChildNotification, ChildState, ChildStatus, ChildStatusPort, ChildStopCause, ChildStopPort,
    CompletionFeature, CompletionWiring, CoordinatorOutcome, CoordinatorPorts, CoordinatorRequest,
    CoordinatorStorePort, LaunchRefusal, NotConnectedCompletion, SerialExecutionState,
    TaskCompletion, TaskCompletionPort, TaskCompletionRequest, TaskCoordinator, TaskLaunch,
    TaskLaunchPort, completion_wiring, dispatch_request_id, step_request_id,
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
pub use finish::{
    FinalCheckEvidence, FinalStateObservation, FinishBlocker, FinishDecision, FinishHandoff,
    FinishInputs, HandoffSideEffectPolicy, TaskCompletionEntry, decide, final_task,
    handoff_task_lines, not_ready_stop, task_artifacts,
};
pub use git::{
    ChangedPath, CommitObservation, CommitObservationPort, CommitRecovery, CommitTarget,
    FinalizePorts, FinalizeStop, ObservationRequest, ObservedPath, TargetOrigin, TargetRefusal,
    TargetSelection, TaskCommitRequest, TaskFinalizeOutcome, VerifiedPath, classify_commit,
    classify_recorded, commit_request_id, commit_request_id_with_attempt, finalize_task,
    path_within, select_targets,
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
pub use ledger::{
    LedgerConflict, LedgerInput, LedgerWorktree, LedgerWrite, PROGRESS_HEADING,
    PROGRESS_LEDGER_PATH, ProgressHoldReason, ProgressLedgerOutcome, ProgressWriteRequest,
    RenderedLedger, TaskArtifacts, execution_brief_path, hold_next_task, plan_write, render,
    render_content, write_progress,
};
pub use packet::{
    MAX_CONTEXT_ENTRY_CHARS, MAX_PACKET_BYTES, MAX_PACKET_CONTEXT_ENTRIES,
    MAX_PACKET_SECTION_BYTES, MAX_PACKET_SECTIONS, NO_GIT_RULE, PacketComposition,
    PacketContextEntry, PacketInputs, PacketOutcome, PacketPriorResult, PacketScope,
    PacketSpecSection, PacketWaitReason, PriorTaskContext, SnapshotSectionPart, SnapshotSections,
    TASK_PACKET_FORMAT_VERSION, TaskHandoff, TaskPacket, TaskPacketBinding,
    approved_spec_snapshot_digest, execution_report_path, prior_context_for,
    required_evidence_fields,
};
pub use plan::{
    ExactPlanBytes, ExactPlanText, InspectRequest, InspectedPlan, InspectorCapabilities,
    InspectorProtocol, ParsedPlanSummary, ParsedPlanTask, PlanByteRange, PlanDiagnostic,
    PlanDiagnosticCode, PlanPath, validate_check_cwd, validate_project_path,
};
pub use plan_changes::{
    ContractPart, InheritableRevision, JsonBlockState, LatchState, MAX_MOVE_CANDIDATES,
    MemoryPlanChangeLatchStore, PLAN_CHANGE_LATCH_FORMAT_VERSION, PlanChange, PlanChangeGate,
    PlanChangeGatePort, PlanChangeLatch, PlanChangeLatchStorePort, PlanExpectation,
    PlanGateDecision, PlanInheritance, PlanInheritanceBlocker, PlanRevisionApproval,
    PlanRevisionIdentity, PlanRevisionOutcome, PlanRevisionStorePort, ReconcileSchedule,
    TaskProgress, approval_task, approval_task_ref, approve_plan_revision,
    confirm_plan_change_stop, confirm_plan_stop, evaluate_inheritance, hold_stale_application,
    plan_change_stop, stale_application,
};
pub use ports::{
    ChildDispatchPlan, ChildDispatchPort, ClockPort, ExecutionFeature, ExecutionStorePort,
    HostGitPort, HtmlBarrierPort, PlanInspectorPort, PlanObservation, PlanSourcePort,
    PlanSourceRead, ProgressLedgerPort, StoredControlResult, StoredExecution, SupervisionTargetId,
    WorkspacePort, WorkspacePreparation, WorkspaceState, unsupported,
};
pub use record::{RecordDecodeError, STORE_RECORD_FORMAT_VERSION, decode_record, encode_record};
pub use report::{
    CheckEvidence, EvidenceField, EvidenceItem, MAX_REPORT_BYTES, MAX_REPORT_EVIDENCE_BLOCKS,
    Report, ReportExpectations, ReportGap, ReportOutcome, ReportParseError, ReportStatus,
    ReportWaitReason, Ruling, SpecReflection, interpret_unparseable,
};
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
