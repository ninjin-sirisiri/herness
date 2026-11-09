//! Structured errors shared by every herness public contract.
//!
//! Error payloads never carry provider response bodies, credentials, tokens,
//! or secret headers. Adapters must translate raw engine/provider failures into
//! the sanitized kinds defined here before crossing the public contract.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::contracts::artifact::ArtifactSlot;
use crate::contracts::connection::{ConnectionId, Provider};
use crate::contracts::ids::{IdKind, OperationId, ProjectId, RunId};
use crate::contracts::run::RunState;
use crate::permissions::PermissionMode;
use crate::skills::{SkillFailure, SkillId};
use crate::tools::ToolName;
use crate::tools::arguments::FileVersion;
use crate::tools::reason::{ReasonField, ReasonViolation};

/// Structured herness error. `kind` is stable public contract data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CoreError {
    /// A contract version other than the one supported by this build.
    UnknownContractVersion {
        /// Version found in the incoming value.
        found: u32,
        /// Only version supported by this build.
        expected: u32,
    },
    /// A contract version string that could not be parsed.
    InvalidContractVersion {
        /// Unparseable value.
        value: String,
    },
    /// A typed identifier could not be parsed or had the wrong type prefix.
    InvalidId {
        /// Expected identifier kind.
        id_kind: IdKind,
        /// Rejected input.
        value: String,
    },
    /// An identifier belongs to a different project than the operation scope.
    CrossProjectReference {
        /// Identifier kind that was checked.
        id_kind: IdKind,
        /// Project expected by the caller.
        expected: ProjectId,
        /// Project carried by the identifier.
        found: ProjectId,
    },
    /// A rationale or purpose violated the shared reason rules.
    InvalidReason {
        /// Which reason field failed.
        field: ReasonField,
        /// Validation failure.
        violation: ReasonViolation,
    },
    /// Tool arguments failed schema validation.
    InvalidToolArgument {
        /// Tool whose arguments failed.
        tool: ToolName,
        /// Argument field name.
        field: String,
        /// Validation failure.
        violation: ArgumentViolation,
    },
    /// A non-tool value failed validation.
    InvalidValue {
        /// Field name.
        field: String,
        /// Validation failure.
        violation: ArgumentViolation,
    },
    /// A frozen working directory was not a usable absolute path.
    InvalidPath {
        /// Rejected path as supplied.
        path: String,
        /// Validation failure.
        violation: PathViolation,
    },
    /// A policy version of zero was supplied.
    InvalidPolicyVersion {
        /// Rejected value.
        value: u64,
    },
    /// An operation was frozen under a policy version that is not current.
    ///
    /// The operation must be frozen again before evaluation; an old decision
    /// must not be reused.
    StalePolicyVersion {
        /// Policy version captured in the frozen operation.
        frozen: crate::permissions::PolicyVersion,
        /// Policy version that is current now.
        current: crate::permissions::PolicyVersion,
    },
    /// A history limit outside `1..=500` was supplied.
    InvalidHistoryLimit {
        /// Rejected value.
        value: u16,
        /// Largest permitted value.
        max: u16,
    },
    /// A checkpoint format version of zero was supplied.
    InvalidCheckpointVersion {
        /// Rejected version.
        found: u32,
    },
    /// An event failed envelope validation.
    InvalidEvent {
        /// Event field name.
        field: String,
        /// Validation failure.
        violation: ArgumentViolation,
    },
    /// A port feature is not implemented by this build.
    ///
    /// Callers must treat this as unavailable. It is never a success and the
    /// work it would authorize must not proceed.
    UnsupportedPortFeature {
        /// Port feature that is missing.
        feature: PortFeature,
    },
    /// A checkpoint commit referred to events or an operation from another run.
    MismatchedRun {
        /// Run that owns the transaction.
        expected: RunId,
        /// Run found in the child value.
        found: RunId,
    },
    /// The store already recorded this operation id.
    ///
    /// The repeated commit must not be treated as a new execution. Callers can
    /// read the recorded intent and, when present, its stored result.
    DuplicateOperation {
        /// Operation id already present in the store.
        operation: OperationId,
    },
    /// Automatic permission mode was requested without an available evaluator.
    PermissionEvaluatorUnavailable {
        /// Mode that could not be used.
        mode: PermissionMode,
    },
    /// The permission evaluator did not return a usable decision.
    PermissionEvaluationFailed {
        /// Sanitized failure reason. The operation must not run.
        failure: EvaluationFailureKind,
    },
    /// Credential resolution failed.
    CredentialUnavailable {
        /// Connection whose credential was requested.
        connection: ConnectionId,
        /// Sanitized failure reason.
        failure: CredentialFailureKind,
    },
    /// The selected connection needs a fresh human login.
    AuthenticationRequired {
        /// Connection requiring authentication.
        connection: ConnectionId,
    },
    /// The store could not complete the operation.
    StoreUnavailable {
        /// Sanitized failure reason.
        failure: StoreFailureKind,
    },
    /// The engine adapter could not complete the operation.
    EngineUnavailable {
        /// Sanitized failure reason.
        failure: EngineFailureKind,
    },
    /// A model provider failed. Provider response bodies are not carried.
    ProviderFailure {
        /// Provider that failed.
        provider: Provider,
        /// Sanitized failure reason.
        failure: ProviderFailureKind,
    },
    /// A native file tool could not complete safely.
    FileToolFailed {
        /// Tool that failed.
        tool: ToolName,
        /// Structured, non-secret failure detail.
        failure: FileFailure,
    },
    /// A managed shell command did not complete as a plain success.
    ShellToolFailed {
        /// Tool that failed.
        tool: ToolName,
        /// Structured, non-secret failure detail.
        failure: ShellFailure,
    },
    /// A candidate artifact tool could not complete safely.
    ArtifactToolFailed {
        /// Tool that failed.
        tool: ToolName,
        /// Structured, non-secret failure detail.
        failure: ArtifactFailure,
    },
    /// A skill could not be loaded, revalidated, or used for its declared
    /// flow.
    SkillFailed {
        /// Skill involved.
        skill: SkillId,
        /// Structured, non-secret failure detail.
        failure: SkillFailure,
    },
    /// A run is not in a state that permits the requested transition.
    InvalidRunTransition {
        /// State before the attempted transition.
        from: RunState,
        /// State the caller attempted to enter.
        to: RunState,
    },
    /// A paused or interrupted run cannot be restored without replaying input
    /// or a tool.
    NotResumable {
        /// Run whose saved state is not safely resumable.
        run: RunId,
        /// Sanitized reason. No SDK snapshot or provider text is carried.
        reason: ConversationFailure,
    },
    /// A stable previous conversation cannot be continued as a new run.
    NotContinuable {
        /// Previous run whose conversation cannot be carried forward.
        previous_run: RunId,
        /// Sanitized reason. No SDK snapshot or provider text is carried.
        reason: ConversationFailure,
    },
}

/// Why a conversation cannot be continued or resumed safely.
///
/// These labels are stable, non-secret contract data. They never contain SDK
/// snapshot bodies, model text, credentials, or provider responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationFailure {
    /// The previous run has no durable checkpoint.
    MissingCheckpoint,
    /// The supplied checkpoint is not the durable latest state.
    CheckpointNotLatest,
    /// The checkpoint envelope could not be validated for the requested run.
    CorruptCheckpoint,
    /// The previous run is not idle/stable.
    PreviousRunNotStable,
    /// A stop was not confirmed for the live engine session.
    StopUnconfirmed,
    /// An input was accepted but not completed.
    PendingInput,
    /// A tool invocation is not completed. Resuming could execute it again.
    PendingInvocation,
    /// A human approval is still recorded for the previous run.
    PendingApproval,
    /// A managed process still needs reconciliation.
    ManagedProcess,
    /// A tool operation intent has no durable result.
    UnresolvedOperation,
    /// The supplied continuation scope does not match the previous run.
    ScopeMismatch,
    /// The requested input is unknown or was already consumed.
    InputUnavailable,
}

/// Validation failure for a free-form argument value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ArgumentViolation {
    /// The value was empty or whitespace-only after trimming.
    Empty,
    /// The value exceeded the permitted number of Unicode scalar values.
    TooLong {
        /// Counted Unicode scalar values.
        actual: usize,
        /// Maximum permitted count.
        max: usize,
    },
    /// The value exceeded the permitted number of UTF-8 bytes.
    TooLongBytes {
        /// Counted UTF-8 bytes.
        actual: usize,
        /// Maximum permitted count.
        max: usize,
    },
    /// The value must be a positive integer.
    MustBePositive,
    /// Another schema violation, described without secrets.
    Invalid {
        /// Human-readable, non-secret explanation.
        detail: String,
    },
}

/// Validation failure for an absolute working directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathViolation {
    /// The path was empty.
    Empty,
    /// The path was relative.
    NotAbsolute,
    /// The path contained a NUL byte.
    ContainsNul,
}

/// A host-owned port feature that this build does not implement yet.
///
/// Returning this value is the explicit alternative to a fabricated empty
/// success. Later phases replace individual variants as the capability lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortFeature {
    /// Starting a new run that continues a previous conversation.
    Continuation,
    /// Correlating input acceptance, start, and completion.
    InputCorrespondence,
    /// Admitting an external model request before send.
    RequestGate,
    /// Recording a terminal model request observation and its usage.
    RequestObservation,
    /// Reading current stop and deadline control for a run.
    StopDeadlineControl,
    /// Persisting events for host activities that have no run.
    HostActivityEvents,
    /// Installing the host-resolved grant, policy, evaluator, and stop control
    /// for a run's real tool path.
    RunPermission,
    /// The host-owned candidate artifact store.
    ArtifactStore,
}

impl PortFeature {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Continuation => "continuation",
            Self::InputCorrespondence => "input_correspondence",
            Self::RequestGate => "request_gate",
            Self::RequestObservation => "request_observation",
            Self::StopDeadlineControl => "stop_deadline_control",
            Self::HostActivityEvents => "host_activity_events",
            Self::RunPermission => "run_permission",
            Self::ArtifactStore => "artifact_store",
        }
    }
}

/// Sanitized permission evaluator failure kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationFailureKind {
    /// No evaluator is connected or configured.
    Unavailable,
    /// The evaluator did not answer within its deadline.
    Timeout,
    /// The evaluator returned malformed or unsupported output.
    InvalidResponse,
    /// The evaluator could not reach a confident decision.
    LowConfidence,
    /// The evaluator refused to decide.
    Refused,
}

/// Sanitized credential failure kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFailureKind {
    /// No credential is configured for the connection.
    NotConfigured,
    /// The credential is expired and could not be refreshed.
    Expired,
    /// A token refresh failed.
    RefreshFailed,
    /// The macOS Keychain could not be reached or refused access.
    KeychainUnavailable,
    /// The macOS Keychain is locked.
    KeychainLocked,
    /// The operating system denied access to the Keychain item.
    KeychainDenied,
    /// A Keychain item could not be written or updated.
    KeychainWriteFailed,
    /// The Keychain accepted the item but reported a duplicate.
    KeychainDuplicateItem,
    /// The requested Keychain item is missing.
    KeychainItemMissing,
    /// The stored credential payload could not be decoded or had the wrong
    /// kind for the connection's authentication method.
    InvalidCredentialData,
    /// A validated ChatGPT login lacks the plan-usage scope. The account is
    /// authenticated but cannot be used for inference.
    PlanScopeMissing,
}

/// Sanitized store failure kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreFailureKind {
    /// The store is not open or not reachable.
    Unavailable,
    /// A write conflicted with an existing record.
    Conflict,
    /// Stored data failed integrity or schema checks.
    CorruptData,
    /// The stored format version is not supported by this build.
    UnsupportedVersion,
}

/// Sanitized engine adapter failure kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineFailureKind {
    /// The engine is not available.
    Unavailable,
    /// The engine returned data that could not be interpreted.
    InvalidResponse,
    /// Execution was interrupted unexpectedly.
    Interrupted,
    /// A checkpoint could not be produced or restored.
    CheckpointUnavailable,
}

/// Sanitized provider failure kinds. Raw response bodies are excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureKind {
    /// Authentication was rejected.
    Authentication,
    /// The provider rate-limited the request.
    RateLimited,
    /// The provider could not be reached.
    Network,
    /// The provider returned an invalid or unsupported response.
    InvalidResponse,
    /// The provider refused the request.
    Refused,
    /// Another sanitized provider failure.
    Unknown,
}

/// Structured, non-secret reason a native file tool failed.
///
/// These failures are decided by host path resolution and version checks. They
/// do not claim OS sandbox isolation; the project root is a trusted-project
/// boundary only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum FileFailure {
    /// The requested path resolves outside the canonical project root.
    PathOutsideProject {
        /// Rejected path as supplied.
        path: String,
    },
    /// A symlink was the target, or a not-yet-created file had a symlinked
    /// parent.
    SymlinkNotAllowed {
        /// Rejected path.
        path: String,
    },
    /// A required file or directory did not exist.
    NotFound {
        /// Missing path.
        path: String,
    },
    /// The target existed but was not a regular file.
    NotAFile {
        /// Rejected path.
        path: String,
    },
    /// A required parent existed but was not a directory.
    NotADirectory {
        /// Rejected path.
        path: String,
    },
    /// `write` creates files only; the target already existed.
    AlreadyExists {
        /// Existing path.
        path: String,
    },
    /// A not-yet-created file had no existing parent directory.
    ParentMissing {
        /// Missing parent path.
        path: String,
    },
    /// A not-yet-created file had a parent that was not a directory.
    ParentNotDirectory {
        /// Rejected parent path.
        path: String,
    },
    /// A text tool read bytes that were not valid UTF-8.
    InvalidUtf8 {
        /// Path whose contents were rejected.
        path: String,
    },
    /// The observed file version did not match the caller's expectation.
    VersionConflict {
        /// Path whose version changed.
        path: String,
        /// Version the caller expected.
        expected: FileVersion,
        /// Version observed now.
        actual: FileVersion,
    },
    /// `edit.oldText` was empty.
    EditTextEmpty,
    /// `edit.oldText` did not occur in the file.
    EditTextNotFound {
        /// Path that was searched.
        path: String,
    },
    /// `edit.oldText` occurred more than once.
    EditTextNotUnique {
        /// Path that was searched.
        path: String,
        /// Number of non-overlapping occurrences observed.
        occurrences: u64,
    },
    /// `edit` would not change the file.
    NoChange {
        /// Path that was not changed.
        path: String,
    },
    /// The intent could not be recorded, so no side effect was performed.
    NotExecutable {
        /// Sanitized explanation.
        detail: String,
    },
    /// The side effect happened but its durable result could not be recorded.
    /// Reconciliation is required; the host did not roll back or retry.
    Unverifiable {
        /// Sanitized explanation.
        detail: String,
    },
    /// The local filesystem rejected the operation.
    Io {
        /// Path involved.
        path: String,
        /// Sanitized error kind.
        error_kind: String,
    },
    /// This file executor does not handle the requested tool.
    Unsupported {
        /// Requested tool.
        tool: ToolName,
    },
}

/// Structured, non-secret reason a managed shell command failed or was
/// interrupted.
///
/// A shell `allow` rule is a policy match, not an OS sandbox. These errors do
/// not claim that the command was harmless or that detached descendants were
/// captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ShellFailure {
    /// The frozen working directory was missing or not a directory.
    WorkingDirectoryUnavailable {
        /// Rejected absolute path.
        path: String,
    },
    /// The intent could not be recorded, so no process was started.
    NotExecutable {
        /// Sanitized explanation.
        detail: String,
    },
    /// The host could not create the managed process.
    SpawnFailed {
        /// Sanitized operating-system error kind. No command output is carried.
        detail: String,
    },
    /// The command exceeded its timeout and was terminated.
    TimedOut {
        /// Whether the host confirmed that the managed group is gone.
        confirmed: bool,
    },
    /// A host stop request terminated the command.
    Stopped {
        /// Whether the host confirmed that the managed group is gone.
        confirmed: bool,
    },
    /// The host could not confirm that the managed process group is gone.
    Unconfirmed {
        /// Sanitized explanation.
        detail: String,
    },
    /// The command ran but its result could not be recorded durably.
    /// Reconciliation is required; the host did not retry or roll back.
    Unverifiable {
        /// Sanitized explanation.
        detail: String,
    },
    /// This executor does not handle the requested tool.
    Unsupported {
        /// Requested tool.
        tool: ToolName,
    },
}

/// Structured, non-secret reason a candidate artifact tool failed.
///
/// Candidate artifacts are addressed by a host-issued handle and an artifact
/// slot. These failures never carry a private storage path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ArtifactFailure {
    /// This executor was invoked for a tool outside the candidate context.
    ToolNotAllowed {
        /// Requested tool.
        tool: ToolName,
    },
    /// The supplied handle is not the current host-issued handle for the run.
    StaleHandle {
        /// Generation of the current handle.
        expected_generation: u64,
        /// Generation supplied by the operation.
        found_generation: u64,
    },
    /// Write or edit named an immutable or formal artifact slot.
    NotCandidateTarget {
        /// Rejected slot.
        artifact: ArtifactSlot,
    },
    /// The requested artifact has not been authored yet.
    NotFound {
        /// Missing slot.
        artifact: ArtifactSlot,
    },
    /// The artifact changed since the caller observed it.
    VersionConflict {
        /// Slot whose version changed.
        artifact: ArtifactSlot,
        /// Version the caller expected.
        expected: FileVersion,
        /// Version observed now.
        actual: FileVersion,
    },
    /// `candidate_edit.oldText` was empty.
    EditTextEmpty,
    /// `candidate_edit.oldText` did not occur in the artifact.
    EditTextNotFound {
        /// Slot that was searched.
        artifact: ArtifactSlot,
    },
    /// `candidate_edit.oldText` occurred more than once.
    EditTextNotUnique {
        /// Slot that was searched.
        artifact: ArtifactSlot,
        /// Number of non-overlapping occurrences observed.
        occurrences: u64,
    },
    /// `candidate_edit` would not change the artifact.
    NoChange {
        /// Slot that was not changed.
        artifact: ArtifactSlot,
    },
    /// The host artifact port returned a different artifact or version than
    /// the one the executor planned.
    ContentMismatch {
        /// Slot involved.
        artifact: ArtifactSlot,
    },
    /// The host artifact store is not wired in this build or composition.
    ///
    /// Callers must surface this as an unsupported capability. It is never a
    /// successful empty result.
    Unavailable,
    /// The intent could not be recorded, so no artifact side effect occurred.
    NotExecutable {
        /// Sanitized explanation.
        detail: String,
    },
    /// The side effect may have happened but its durable result could not be
    /// recorded. Reconciliation is required; the host did not retry.
    Unverifiable {
        /// Sanitized explanation.
        detail: String,
    },
}

/// Structured, non-secret reason a host-only publication failed.
///
/// Publication is not a model tool. These failures describe the host boundary
/// that replaces one formal companion file after an approved request. They
/// never carry agent rationales, run identifiers, or H3 approval state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum PublicationFailure {
    /// The request was structurally invalid before any filesystem access.
    InvalidRequest {
        /// Request field name.
        field: String,
        /// Validation failure.
        violation: ArgumentViolation,
    },
    /// The request belongs to another project than this writer.
    CrossProject {
        /// Project this writer is bound to.
        expected: ProjectId,
        /// Project carried by the request.
        found: ProjectId,
    },
    /// Project root, symlink, or path resolution rejected the target.
    Path {
        /// Structured native path failure.
        failure: FileFailure,
    },
    /// The target changed since the request observed it.
    VersionConflict {
        /// Project-relative target.
        target: String,
        /// Version the request expected.
        expected: FileVersion,
        /// Version observed now.
        actual: FileVersion,
    },
    /// The request expected absence but a file exists.
    ExpectedAbsentButPresent {
        /// Project-relative target.
        target: String,
        /// Version observed at the existing target.
        actual: FileVersion,
    },
    /// The request expected an existing file but the target is absent.
    ExpectedPresentButAbsent {
        /// Project-relative target.
        target: String,
        /// Version the request expected.
        expected: FileVersion,
    },
    /// Existing bytes at the target are not valid UTF-8 text.
    InvalidUtf8 {
        /// Project-relative target.
        target: String,
    },
    /// The host permission/grant check refused this publication.
    PermissionDenied {
        /// Sanitized explanation.
        detail: String,
    },
    /// The host stop/latch control does not permit publication.
    Stopped {
        /// Sanitized explanation.
        detail: String,
    },
    /// Saving the old version failed, so the target was not replaced.
    OldVersionSaveFailed {
        /// Sanitized explanation.
        detail: String,
    },
    /// The private old-version archive is not available.
    ArchiveUnavailable {
        /// Sanitized explanation.
        detail: String,
    },
    /// The private publication record store is not available.
    RecordUnavailable {
        /// Sanitized explanation.
        detail: String,
    },
    /// A stored publication record is corrupt.
    RecordCorrupt {
        /// Sanitized explanation.
        detail: String,
    },
    /// A stored publication record uses a format this build cannot read.
    UnsupportedRecordFormat {
        /// Format found in the record.
        found: u32,
    },
    /// The intent could not be recorded, so no side effect was performed.
    NotExecutable {
        /// Sanitized explanation.
        detail: String,
    },
    /// The side effect may have happened but its durable result could not be
    /// recorded. Reconciliation is required; the host did not retry or roll
    /// back.
    Unverifiable {
        /// Sanitized explanation.
        detail: String,
    },
    /// A previous attempt left this request without a usable result.
    ReconciliationRequired {
        /// Publication request identifier.
        request_id: String,
        /// Sanitized explanation.
        detail: String,
    },
    /// The same request id was reused with a different payload.
    RequestConflict {
        /// Publication request identifier.
        request_id: String,
    },
}

impl fmt::Display for IdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for ReasonField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rationale => f.write_str("rationale"),
            Self::Purpose => f.write_str("purpose"),
        }
    }
}

impl fmt::Display for ReasonViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("must not be empty after trim"),
            Self::TooLong { actual, max } => write!(
                f,
                "must contain at most {max} Unicode scalar values, found {actual}"
            ),
        }
    }
}

impl fmt::Display for ArgumentViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("must not be empty after trim"),
            Self::TooLong { actual, max } => write!(
                f,
                "must contain at most {max} Unicode scalar values, found {actual}"
            ),
            Self::TooLongBytes { actual, max } => write!(
                f,
                "must contain at most {max} UTF-8 bytes, found {actual}"
            ),
            Self::MustBePositive => f.write_str("must be a positive integer"),
            Self::Invalid { detail } => f.write_str(detail),
        }
    }
}

impl fmt::Display for PathViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("must not be empty"),
            Self::NotAbsolute => f.write_str("must be an absolute path"),
            Self::ContainsNul => f.write_str("must not contain a NUL byte"),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownContractVersion { found, expected } => write!(
                f,
                "unsupported contract version {found}; this build supports version {expected}"
            ),
            Self::InvalidContractVersion { value } => {
                write!(f, "invalid contract version value {value:?}")
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
                "{id_kind} id belongs to project {found}, not the expected project {expected}"
            ),
            Self::InvalidReason { field, violation } => {
                write!(f, "invalid {field}: {violation}")
            }
            Self::InvalidToolArgument {
                tool,
                field,
                violation,
            } => write!(f, "invalid {tool} argument {field:?}: {violation}"),
            Self::InvalidValue { field, violation } => {
                write!(f, "invalid {field}: {violation}")
            }
            Self::InvalidPath { path, violation } => {
                write!(f, "invalid path {path:?}: {violation}")
            }
            Self::InvalidPolicyVersion { value } => {
                write!(f, "invalid policy version {value}; versions start at 1")
            }
            Self::StalePolicyVersion { frozen, current } => write!(
                f,
                "operation was frozen at policy version {frozen}, current version is {current}"
            ),
            Self::InvalidHistoryLimit { value, max } => {
                write!(f, "invalid history limit {value}; expected 1..={max}")
            }
            Self::InvalidCheckpointVersion { found } => {
                write!(f, "invalid checkpoint format version {found}")
            }
            Self::InvalidEvent { field, violation } => {
                write!(f, "invalid event field {field:?}: {violation}")
            }
            Self::UnsupportedPortFeature { feature } => {
                write!(f, "port feature {} is not supported", feature.as_str())
            }
            Self::MismatchedRun { expected, found } => {
                write!(f, "run {found} does not match transaction run {expected}")
            }
            Self::DuplicateOperation { operation } => {
                write!(f, "operation {operation} is already recorded")
            }
            Self::PermissionEvaluatorUnavailable { mode } => {
                write!(f, "permission mode {mode} requires an available evaluator")
            }
            Self::PermissionEvaluationFailed { failure } => {
                write!(f, "permission evaluation failed: {failure:?}")
            }
            Self::CredentialUnavailable {
                connection,
                failure,
            } => write!(f, "credential {connection} unavailable: {failure:?}"),
            Self::AuthenticationRequired { connection } => {
                write!(f, "connection {connection} requires authentication")
            }
            Self::StoreUnavailable { failure } => {
                write!(f, "store unavailable: {failure:?}")
            }
            Self::EngineUnavailable { failure } => {
                write!(f, "engine unavailable: {failure:?}")
            }
            Self::ProviderFailure { provider, failure } => {
                write!(f, "provider {provider} failed: {failure:?}")
            }
            Self::FileToolFailed { tool, failure } => {
                write!(f, "{tool} failed: {failure}")
            }
            Self::ShellToolFailed { tool, failure } => {
                write!(f, "{tool} failed: {failure}")
            }
            Self::ArtifactToolFailed { tool, failure } => {
                write!(f, "{tool} failed: {failure}")
            }
            Self::SkillFailed { skill, failure } => {
                write!(f, "skill {skill} failed: {failure}")
            }
            Self::InvalidRunTransition { from, to } => {
                write!(f, "run cannot transition from {from} to {to}")
            }
            Self::NotResumable { run, reason } => {
                write!(f, "run {run} is not resumable: {reason:?}")
            }
            Self::NotContinuable {
                previous_run,
                reason,
            } => write!(
                f,
                "the conversation of run {previous_run} cannot be continued: {reason:?}"
            ),
        }
    }
}

impl fmt::Display for FileFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathOutsideProject { path } => {
                write!(f, "path {path:?} is outside the project root")
            }
            Self::SymlinkNotAllowed { path } => {
                write!(f, "path {path:?} is a symlink or has a symlinked parent")
            }
            Self::NotFound { path } => write!(f, "path {path:?} does not exist"),
            Self::NotAFile { path } => write!(f, "path {path:?} is not a regular file"),
            Self::NotADirectory { path } => write!(f, "path {path:?} is not a directory"),
            Self::AlreadyExists { path } => {
                write!(f, "path {path:?} already exists; write creates files only")
            }
            Self::ParentMissing { path } => {
                write!(f, "parent directory {path:?} does not exist")
            }
            Self::ParentNotDirectory { path } => {
                write!(f, "parent path {path:?} is not a directory")
            }
            Self::InvalidUtf8 { path } => write!(f, "path {path:?} is not valid UTF-8"),
            Self::VersionConflict {
                path,
                expected,
                actual,
            } => write!(
                f,
                "path {path:?} changed: expected version {expected}, observed {actual}"
            ),
            Self::EditTextEmpty => f.write_str("edit oldText must not be empty"),
            Self::EditTextNotFound { path } => {
                write!(f, "edit oldText was not found in {path:?}")
            }
            Self::EditTextNotUnique { path, occurrences } => write!(
                f,
                "edit oldText occurs {occurrences} times in {path:?}; expected exactly one"
            ),
            Self::NoChange { path } => write!(f, "edit would not change {path:?}"),
            Self::NotExecutable { detail } => {
                write!(f, "operation was not executed: {detail}")
            }
            Self::Unverifiable { detail } => write!(
                f,
                "side effect may be applied but the result is not durable; reconciliation required: {detail}"
            ),
            Self::Io { path, error_kind } => {
                write!(f, "filesystem error at {path:?}: {error_kind}")
            }
            Self::Unsupported { tool } => {
                write!(f, "{tool} is not handled by the native file executor")
            }
        }
    }
}

impl fmt::Display for ShellFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkingDirectoryUnavailable { path } => {
                write!(f, "working directory {path:?} is not usable")
            }
            Self::NotExecutable { detail } => {
                write!(f, "operation was not executed: {detail}")
            }
            Self::SpawnFailed { detail } => {
                write!(f, "the managed process could not be started: {detail}")
            }
            Self::TimedOut { confirmed } => {
                write!(f, "the command timed out")?;
                if *confirmed {
                    f.write_str("; the managed process group is gone")
                } else {
                    f.write_str("; the managed process group could not be confirmed gone")
                }
            }
            Self::Stopped { confirmed } => {
                write!(f, "the command was stopped")?;
                if *confirmed {
                    f.write_str("; the managed process group is gone")
                } else {
                    f.write_str("; the managed process group could not be confirmed gone")
                }
            }
            Self::Unconfirmed { detail } => {
                write!(
                    f,
                    "the managed process group is not confirmed stopped: {detail}"
                )
            }
            Self::Unverifiable { detail } => write!(
                f,
                "the command ran but its result is not durable; reconciliation required: {detail}"
            ),
            Self::Unsupported { tool } => {
                write!(f, "{tool} is not handled by the bash executor")
            }
        }
    }
}

impl std::error::Error for CoreError {}

impl fmt::Display for ArtifactFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ToolNotAllowed { tool } => {
                write!(f, "{tool} is not allowed in a candidate artifact context")
            }
            Self::StaleHandle {
                expected_generation,
                found_generation,
            } => write!(
                f,
                "the artifact handle is stale: expected generation {expected_generation}, found {found_generation}"
            ),
            Self::NotCandidateTarget { artifact } => {
                write!(f, "{artifact} is not a writable candidate artifact")
            }
            Self::NotFound { artifact } => {
                write!(f, "candidate artifact {artifact} has not been authored")
            }
            Self::VersionConflict {
                artifact,
                expected,
                actual,
            } => write!(
                f,
                "candidate artifact {artifact} changed: expected version {expected}, observed {actual}"
            ),
            Self::EditTextEmpty => f.write_str("candidate edit oldText must not be empty"),
            Self::EditTextNotFound { artifact } => {
                write!(f, "candidate edit oldText was not found in {artifact}")
            }
            Self::EditTextNotUnique {
                artifact,
                occurrences,
            } => write!(
                f,
                "candidate edit oldText occurs {occurrences} times in {artifact}; expected exactly one"
            ),
            Self::NoChange { artifact } => {
                write!(f, "candidate edit would not change {artifact}")
            }
            Self::ContentMismatch { artifact } => write!(
                f,
                "the host artifact store returned an unexpected body or version for {artifact}"
            ),
            Self::Unavailable => {
                f.write_str("the host candidate artifact store is not available")
            }
            Self::NotExecutable { detail } => {
                write!(f, "operation was not executed: {detail}")
            }
            Self::Unverifiable { detail } => write!(
                f,
                "artifact side effect may be applied but the result is not durable; reconciliation required: {detail}"
            ),
        }
    }
}

impl fmt::Display for PublicationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { field, violation } => {
                write!(f, "invalid publication request field {field:?}: {violation}")
            }
            Self::CrossProject { expected, found } => write!(
                f,
                "publication request belongs to project {found}, not this writer's project {expected}"
            ),
            Self::Path { failure } => write!(f, "publication path rejected: {failure}"),
            Self::VersionConflict {
                target,
                expected,
                actual,
            } => write!(
                f,
                "publication target {target:?} changed: expected version {expected}, observed {actual}"
            ),
            Self::ExpectedAbsentButPresent { target, actual } => write!(
                f,
                "publication target {target:?} was expected to be absent but has version {actual}"
            ),
            Self::ExpectedPresentButAbsent { target, expected } => write!(
                f,
                "publication target {target:?} was expected at version {expected} but is absent"
            ),
            Self::InvalidUtf8 { target } => {
                write!(f, "publication target {target:?} is not valid UTF-8")
            }
            Self::PermissionDenied { detail } => {
                write!(f, "publication permission denied: {detail}")
            }
            Self::Stopped { detail } => write!(f, "publication stopped: {detail}"),
            Self::OldVersionSaveFailed { detail } => {
                write!(f, "the old version was not saved, so no replacement occurred: {detail}")
            }
            Self::ArchiveUnavailable { detail } => {
                write!(f, "the private publication archive is unavailable: {detail}")
            }
            Self::RecordUnavailable { detail } => {
                write!(f, "the publication record store is unavailable: {detail}")
            }
            Self::RecordCorrupt { detail } => {
                write!(f, "the stored publication record is corrupt: {detail}")
            }
            Self::UnsupportedRecordFormat { found } => {
                write!(f, "publication record format {found} is not supported")
            }
            Self::NotExecutable { detail } => {
                write!(f, "publication was not executed: {detail}")
            }
            Self::Unverifiable { detail } => write!(
                f,
                "publication may be applied but its result is not durable; reconciliation required: {detail}"
            ),
            Self::ReconciliationRequired {
                request_id,
                detail,
            } => write!(
                f,
                "publication request {request_id} requires reconciliation: {detail}"
            ),
            Self::RequestConflict { request_id } => write!(
                f,
                "publication request {request_id} was reused with a different payload"
            ),
        }
    }
}

impl std::error::Error for PublicationFailure {}

impl std::error::Error for ArtifactFailure {}
