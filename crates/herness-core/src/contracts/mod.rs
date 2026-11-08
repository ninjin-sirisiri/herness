//! Host-owned public contract values.

pub mod checkpoint;
pub mod connection;
pub mod errors;
pub mod events;
pub mod history;
pub mod ids;
pub mod input;
pub mod operation;
pub mod path;
pub mod request;
pub mod run;
pub mod shell;
pub mod time;
pub mod version;

pub use checkpoint::{Checkpoint, CheckpointFormatVersion, CheckpointPayload};
pub use connection::{
    AuthMethod, ConnectionCapabilities, ConnectionId, ConnectionInfo, ConnectionStatus,
    ConnectionUsage, EndpointClass, InputCapabilities, InputModality, Provider,
};
pub use errors::{
    ArgumentViolation, CoreError, CredentialFailureKind, EngineFailureKind, EvaluationFailureKind,
    FileFailure, PathViolation, PortFeature, ProviderFailureKind, ShellFailure, StoreFailureKind,
};
pub use events::{
    Event, EventDraft, EventKind, EventPayload, EventSubject, HostActivitySubject, RunSubject,
};
pub use history::{
    DEFAULT_HISTORY_LIMIT, HistoryCursor, HistoryLimit, HistoryPage, HistoryQuery,
    MAX_HISTORY_LIMIT,
};
pub use ids::{
    ActivityKind, AgentId, AgentKind, AttemptId, AttemptKind, HostActivityId, IdKind, InputId,
    InputKind, OperationId, OperationKind, ProjectId, ProjectScope, RequestId, RequestKind, RunId,
    RunKind, ScopedId, ScopedIdKind, SessionId, SessionKind,
};
pub use input::{ContinuationRequest, IdleEvidence, InputPhase, InputProgress};
pub use operation::{
    FileObservation, FrozenOperation, OperationEvidence, OperationIntent, OperationOutcome,
    OperationRecord, OperationResult,
};
pub use path::AbsolutePath;
pub use request::{
    ModelId, ModelRequestObservation, RequestGateIntent, RequestGateOutcome, RequestGateRefusal,
    RequestOutcome, RequestPurpose, StopDeadlineControl, StopReason, TokenCount, TokenUsage,
};
pub use run::RunState;
pub use shell::{ShellObservation, ShellOutput, ShellStopStatus};
pub use time::Timestamp;
pub use version::{CONTRACT_VERSION, ContractVersion, OLDEST_READABLE_CONTRACT_VERSION};
