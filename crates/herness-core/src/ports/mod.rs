//! Ports the host uses to reach adapters and infrastructure.

pub mod artifacts;
pub mod continuation;
pub mod credential;
pub mod engine;
pub mod evaluator;
pub mod request_gate;
pub mod runtime_store;
pub mod store;

pub use artifacts::{ArtifactPort, SharedArtifactPort, UnavailableArtifactPort};
pub use continuation::ContinuationPort;
pub use credential::{
    CredentialAvailability, CredentialKind, CredentialPort, ResolvedCredential, SecretString,
};
pub use engine::{
    EngineEvent, EngineInput, EnginePort, EngineStart, StopReason, StopReport,
    ToolExecutionAuthority,
};
pub use evaluator::{EvaluationRequest, PermissionEvaluatorPort, SharedPermissionEvaluator};
pub use request_gate::{ModelRequestGatePort, StopDeadlinePort};
pub use runtime_store::RuntimeStore;
pub use store::{CheckpointCommit, CommitReceipt, StorePort};
