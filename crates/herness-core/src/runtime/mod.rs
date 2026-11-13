//! Project, agent, and run ownership for the herness host.
//!
//! The runtime is the composition point between host-owned contracts and the
//! injected store, engine, credential, evaluator, and tool implementations. It
//! never depends on the concrete store, engine adapter, or Tauri.
//!
//! See [`Runtime::restore`] for restart safety, [`Runtime::start_run`] for the
//! pre-start checks, [`Runtime::approve`] / [`Runtime::deny`] for human approval,
//! and [`Runtime::subscribe`] for committed-event reconnect.

pub mod error;
mod host;
pub mod host_git;
#[cfg(feature = "test-support")]
pub mod host_state_test_support;
pub mod publication;
pub mod reconcile;
pub mod request_gate;
pub mod shutdown;
mod state;
pub mod tools;
pub mod views;

pub use error::RuntimeError;
pub use host::{AgentSpec, Runtime, RuntimeDependencies};
pub use host_git::{
    GitObjectId, HOST_COMMIT_TIMEOUT, HOST_GIT_ACTIVITY_KIND, HOST_GIT_FINISHED_EVENT_KIND,
    HOST_GIT_STARTED_EVENT_KIND, HostCommitApproval, HostGitActor, HostGitApprover,
    HostGitAuditPort, HostGitAuthorization, HostGitBoundary, HostGitCommitObservation,
    HostGitError, HostGitGate, HostGitGateOutcome, HostGitIndexState, HostGitIntent,
    HostGitMessage, HostGitOutcome, HostGitPath, HostGitRefusal, HostGitReport, HostGitStage,
    HostGitTermination, HostGitTrailer, HostGitUnknown, MAX_HOST_GIT_GATE_ARG_BYTES,
    MAX_HOST_GIT_PATHS, RecordingHostGitAudit, StoreHostGitAudit,
};
pub use publication::{PrivateAppArchive, PublicationWriter};
pub use reconcile::{
    OperationReconciliation, PermissionReconciliation, ProjectReconciliation, ReconciliationReport,
    ReconciliationSource, RunReconciliation, ShutdownSummary,
};
pub use request_gate::StoreModelRequestGate;
pub use shutdown::{ShutdownOutcome, ShutdownReport, ShutdownRun};
pub use tools::{RunToolContext, RuntimeToolExecutor, ToolExecution};
pub use views::{
    AgentView, ApprovalOutcome, ContinuationOutcome, DenialOutcome, EventBatch, PendingApproval,
    ProjectView, PumpReport, RecoveryMode, RunView, RuntimeSnapshot, StopOutcome,
    SubscriptionCursor,
};
