//! Ports the host uses to reach adapters and infrastructure.

pub mod credential;
pub mod engine;
pub mod evaluator;
pub mod runtime_store;
pub mod store;

pub use credential::{
    CredentialAvailability, CredentialKind, CredentialPort, ResolvedCredential, SecretString,
};
pub use engine::{
    EngineEvent, EngineInput, EnginePort, EngineStart, StopReason, StopReport,
    ToolExecutionAuthority,
};
pub use evaluator::{EvaluationRequest, PermissionEvaluatorPort};
pub use runtime_store::RuntimeStore;
pub use store::{CheckpointCommit, CommitReceipt, StorePort};
