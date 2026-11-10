//! Host-owned public contract values.

pub mod artifact;
pub mod checkpoint;
pub mod connection;
pub mod errors;
pub mod events;
pub mod history;
pub mod ids;
pub mod input;
pub mod operation;
pub mod path;
pub mod publication;
pub mod request;
pub mod run;
pub mod shell;
pub mod time;
pub mod version;

pub use artifact::{ArtifactHandle, ArtifactSlot, ArtifactSnapshot};
pub use checkpoint::{Checkpoint, CheckpointFormatVersion, CheckpointPayload};
pub use connection::{
    AuthMethod, ConnectionCapabilities, ConnectionCapabilityDeclaration, ConnectionId,
    ConnectionInfo, ConnectionStatus, ConnectionUsage, EndpointClass, InputCapabilities,
    InputModality, Provider,
};
pub use errors::{
    ArgumentViolation, ArtifactFailure, ConversationFailure, CoreError, CredentialFailureKind,
    EngineFailureKind, EvaluationFailureKind, FileFailure, PathViolation, PortFeature,
    ProviderFailureKind, PublicationFailure, ShellFailure, StoreFailureKind,
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
pub use publication::{
    ArchivedVersion, ExpectedTargetVersion, MAX_PUBLICATION_CONTENT_BYTES,
    MAX_PUBLICATION_REQUEST_ID_SCALARS, MAX_PUBLICATION_TARGET_BYTES, OldVersionArchive,
    OldVersionSave, PUBLICATION_ACTIVITY_KIND, PUBLICATION_EVENT_KIND,
    PUBLICATION_INTENDED_EVENT_KIND, PUBLICATION_RECORD_FORMAT, PUBLICATION_UNIT_SINGLE_FILE,
    PublicationRecord, PublicationRequest, PublicationRequestId, PublicationResult,
    PublicationStatus, PublicationUnit,
};
pub use request::{
    ModelId, ModelRequestObservation, RequestGateIntent, RequestGateOutcome, RequestGateRefusal,
    RequestOutcome, RequestPurpose, StopDeadlineControl, StopReason, TokenCount, TokenUsage,
};
pub use run::RunState;
pub use shell::{ShellObservation, ShellOutput, ShellStopStatus};
pub use time::Timestamp;
pub use version::{CONTRACT_VERSION, ContractVersion, OLDEST_READABLE_CONTRACT_VERSION};
