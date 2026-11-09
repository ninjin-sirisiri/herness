//! Host-owned public contracts and ports for the herness H1 runtime.
//!
//! `herness-core` is the dependency direction root: it never depends on the
//! store, the engine adapter, or Tauri. Public values carry stable identifiers,
//! versioned events, sanitized errors, and no provider tokens or raw provider
//! errors. Checkpoint bodies are versioned opaque data owned by the engine
//! adapter.

pub mod connections;
pub mod contracts;
pub mod permissions;
pub mod ports;
pub mod runtime;
pub mod skills;
pub mod tools;

pub use connections::{
    AssessmentGateway, CHATGPT_DYNAMIC_AGENT_CLIENT, CHATGPT_PLAN_SCOPE, CREDENTIAL_FORMAT_VERSION,
    ConnectionAdmin, ConnectionDirectory, ConnectionError, ConnectionSettings, ConnectionState,
    CredentialAdmin, CredentialBroker, CredentialMaterial, CredentialRef, CredentialRefresher,
    CredentialService, CredentialVault, CredentialWriter, Endpoint, EndpointViolation, HttpScheme,
    InsecureRemoteHttp, MAX_REDACTED_URL_CHARS, OAuthTokenSet, OAuthTokenSetDetails, Origin,
    REDACTED, RedirectAuthDecision, RedirectDropReason, VAULT_SERVICE, VaultAccount, VaultFailure,
    redact_error, redact_header, redact_headers, redact_known_secrets, redact_url,
    redirect_auth_decision,
};
pub use contracts::*;
pub use permissions::{
    ApprovalError, ApprovalRequest, ArgumentsDigest, Authorization, AutomaticModeCapability,
    AutomaticModeUnavailableReason, BoundedPermissionEvaluator, DEFAULT_EVALUATION_TIMEOUT,
    DecisionBinding, DecisionStatus, DenialReason, EvaluationContext, EvaluatorAvailability,
    EvaluatorFailure, GrantScope, GrantWidening, HumanWaitReason, InvalidationReason, MatchMethod,
    PermissionDecision, PermissionMode, PermissionOutcome, PermissionPolicy, PermissionRule,
    PermissionService, PolicyAdmin, PolicyVersion, ProtectedBoundary, RuleEffect, RuleTarget,
    RunControl, RunPermissionContext, SharedPolicy, SimpleCommand,
};
pub use ports::*;
pub use skills::{
    CapabilityStatus, CapabilityUnavailableReason, HostCapabilities, HostCapability, HostOverlay,
    MINIMUM_PYTHON_VERSION, OverlayProvenance, PythonVersion, SkillChange, SkillContextEntry,
    SkillContextRevalidation, SkillDigest, SkillDocument, SkillExecutionFlow, SkillExecutionStatus,
    SkillFailure, SkillFingerprint, SkillId, SkillPack, SkillReference, SkillRevalidation,
    SkillRunContext, SkillSource, ToolAvailability, ToolDetection, ToolRequirement,
    ToolchainConfig, ToolchainDeficiency, ToolchainDetector, ToolchainReport, ValidatorDetection,
    ValidatorProbe,
};
pub use tools::{
    BashArgs, DEFAULT_READ_LIMIT, DEFAULT_SEARCH_RESULTS, EditArgs, FILE_CHANGE_EVENT_KIND,
    FILE_CHANGE_INTENDED_EVENT_KIND, FileChange, FileDiff, FileLockGuard, FileLockRegistry,
    FileToolOutput, FileVersion, GatewayError, MAX_DIFF_BYTES, MAX_READ_LIMIT, MAX_REASON_SCALARS,
    MAX_SEARCH_FILE_BYTES, MAX_SEARCH_FILES, MAX_SEARCH_RESULTS, NativeFileTools, NonEmptyText,
    ProjectRoot, Purpose, Rationale, ReadArgs, ReadOutput, ReasonField, ReasonViolation,
    ResolvedPath, SearchArgs, SearchMatch, SearchOutput, ToolArguments, ToolExecutor, ToolGateway,
    ToolName, WriteArgs, glob_matches, hash_bytes,
};
#[cfg(unix)]
pub use tools::{
    BashExecutor, BashOutput, Completion, DEFAULT_CAPTURE_TIMEOUT, DEFAULT_CONFIRM_TIMEOUT,
    DEFAULT_OUTPUT_LIMIT, DEFAULT_STOP_GRACE, DEFAULT_TIMEOUT_GRACE, GroupLease, GroupStopReport,
    ManagedChild, ManagedGroup, ManagedSignal, ProcessLauncher, ProcessSupervisor,
    SHELL_FINISHED_EVENT_KIND, SHELL_SPAWNED_EVENT_KIND, SHELL_STARTED_EVENT_KIND,
    ShellReconciliation, SpawnGate, SpawnRequest, StopRequest, SupervisorStopReport, SystemChild,
    SystemLauncher, process_group_exists, reconcile_shell_operation, signal_process_group,
    spawn_failure, supervise,
};
