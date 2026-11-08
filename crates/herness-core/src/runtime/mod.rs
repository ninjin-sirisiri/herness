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
#[cfg(feature = "test-support")]
pub mod host_state_test_support;
pub mod reconcile;
pub mod shutdown;
mod state;
pub mod tools;
pub mod views;

pub use error::RuntimeError;
pub use host::{AgentSpec, Runtime, RuntimeDependencies};
pub use reconcile::{
    OperationReconciliation, PermissionReconciliation, ProjectReconciliation, ReconciliationReport,
    ReconciliationSource, RunReconciliation, ShutdownSummary,
};
pub use shutdown::{ShutdownOutcome, ShutdownReport, ShutdownRun};
pub use tools::{RunToolContext, RuntimeToolExecutor, ToolExecution};
pub use views::{
    AgentView, ApprovalOutcome, ContinuationOutcome, DenialOutcome, EventBatch, PendingApproval,
    ProjectView, RecoveryMode, RunView, RuntimeSnapshot, StopOutcome, SubscriptionCursor,
};
