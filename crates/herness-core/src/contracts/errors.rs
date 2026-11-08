//! Structured errors shared by every herness public contract.
//!
//! Error payloads never carry provider response bodies, credentials, tokens,
//! or secret headers. Adapters must translate raw engine/provider failures into
//! the sanitized kinds defined here before crossing the public contract.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::contracts::connection::{ConnectionId, Provider};
use crate::contracts::ids::{IdKind, OperationId, ProjectId, RunId};
use crate::contracts::run::RunState;
use crate::permissions::PermissionMode;
use crate::tools::ToolName;
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
    /// A run is not in a state that permits the requested transition.
    InvalidRunTransition {
        /// State before the attempted transition.
        from: RunState,
        /// State the caller attempted to enter.
        to: RunState,
    },
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
            Self::InvalidHistoryLimit { value, max } => {
                write!(f, "invalid history limit {value}; expected 1..={max}")
            }
            Self::InvalidCheckpointVersion { found } => {
                write!(f, "invalid checkpoint format version {found}")
            }
            Self::InvalidEvent { field, violation } => {
                write!(f, "invalid event field {field:?}: {violation}")
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
            Self::InvalidRunTransition { from, to } => {
                write!(f, "run cannot transition from {from} to {to}")
            }
        }
    }
}

impl std::error::Error for CoreError {}
