//! Structured runtime failures.
//!
//! Every variant is non-secret. Credentials, provider bodies, checkpoints, and
//! model text never appear here; callers receive stable identifiers, run states,
//! and sanitized core error kinds instead.

use std::fmt;

use serde::Serialize;

use crate::contracts::connection::{ConnectionId, ConnectionStatus};
use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::ids::{IdKind, OperationId, ProjectId, RunId};
use crate::contracts::run::RunState;
use crate::permissions::{ApprovalError, GrantWidening, InvalidationReason, PermissionMode};
use crate::skills::{CapabilityUnavailableReason, HostCapability};
use crate::tools::ToolName;

/// A host-runtime operation failed without performing an unapproved side
/// effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum RuntimeError {
    /// A project path did not exist, could not be canonicalized, or could not be
    /// read.
    ProjectUnreadable {
        /// Path as supplied by the caller.
        path: String,
        /// Sanitized filesystem error kind.
        detail: String,
    },
    /// A project path resolved to something other than a directory.
    ProjectNotDirectory {
        /// Canonical path that was rejected.
        path: String,
    },
    /// The project is not owned by this runtime.
    UnknownProject {
        /// Project that was not opened.
        project: ProjectId,
    },
    /// The connection is not registered.
    UnknownConnection {
        /// Connection that was not found.
        connection: ConnectionId,
    },
    /// The connection registry could not be read.
    ConnectionRegistry {
        /// Sanitized registry failure.
        detail: String,
    },
    /// The connection exists but cannot start a run.
    ConnectionUnavailable {
        /// Connection that was selected.
        connection: ConnectionId,
        /// Current non-secret availability.
        status: ConnectionStatus,
    },
    /// The agent is not owned by this runtime.
    UnknownAgent {
        /// Agent that was not found.
        agent: crate::contracts::ids::AgentId,
    },
    /// The run is not owned by this runtime.
    UnknownRun {
        /// Run that was not found.
        run: RunId,
    },
    /// A project-scoped value belonged to another project.
    CrossProject {
        /// Kind of identifier that was checked.
        id_kind: IdKind,
        /// Project expected by the caller.
        expected: ProjectId,
        /// Project carried by the value.
        found: ProjectId,
    },
    /// A capability required by an agent is not available in this host.
    CapabilityUnavailable {
        /// Missing capability.
        capability: HostCapability,
        /// Why it is unavailable.
        reason: CapabilityUnavailableReason,
    },
    /// Automatic mode was selected without an available evaluator.
    PermissionModeUnavailable {
        /// Mode that cannot be used.
        mode: PermissionMode,
    },
    /// A stored grant or run permission context no longer matches the current
    /// policy.
    PermissionContextStale {
        /// Sanitized explanation.
        detail: String,
    },
    /// The requested run transition is not legal.
    InvalidRunTransition {
        /// Current state.
        from: RunState,
        /// Requested state.
        to: RunState,
    },
    /// No pending approval exists for the operation.
    ApprovalUnknown {
        /// Operation with no pending approval.
        operation: OperationId,
    },
    /// The approval was loaded from a previous process and is not reusable.
    ApprovalRestored {
        /// Restored approval.
        operation: OperationId,
    },
    /// The approval no longer matches the current policy or frozen operation.
    ApprovalInvalid {
        /// Invalidated approval.
        operation: OperationId,
        /// Why it is invalid.
        reason: InvalidationReason,
    },
    /// The permission ledger rejected the approval.
    Approval {
        /// Structured ledger failure.
        error: ApprovalError,
    },
    /// A host-created child agent requested more than its parent holds.
    GrantWidening {
        /// Structured widening failure.
        error: GrantWidening,
    },
    /// The saved checkpoint needed for resume is missing.
    NoCheckpoint {
        /// Run without a checkpoint.
        run: RunId,
    },
    /// Persisted host state could not be interpreted.
    CorruptState {
        /// Sanitized explanation.
        detail: String,
    },
    /// The store rejected the operation.
    Store {
        /// Sanitized store failure.
        error: CoreError,
    },
    /// The engine adapter rejected the operation.
    Engine {
        /// Sanitized engine failure.
        error: CoreError,
    },
    /// A tool executor rejected the operation.
    Execution {
        /// Sanitized executor failure.
        error: CoreError,
    },
    /// Tool arguments could not be frozen.
    InvalidArguments {
        /// Tool whose arguments failed.
        tool: ToolName,
        /// Sanitized explanation.
        detail: String,
    },
    /// A free-form value failed validation.
    InvalidValue {
        /// Field name.
        field: String,
        /// Validation failure.
        violation: ArgumentViolation,
    },
    /// The runtime has no executor for the requested tool.
    ToolUnavailable {
        /// Requested tool.
        tool: ToolName,
    },
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProjectUnreadable { path, detail } => {
                write!(f, "project {path:?} is not readable: {detail}")
            }
            Self::ProjectNotDirectory { path } => {
                write!(f, "project {path:?} is not a directory")
            }
            Self::UnknownProject { project } => write!(f, "project {project} was not opened"),
            Self::UnknownConnection { connection } => {
                write!(f, "connection {connection} is not registered")
            }
            Self::ConnectionRegistry { detail } => {
                write!(f, "connection registry failed: {detail}")
            }
            Self::ConnectionUnavailable { connection, status } => {
                write!(f, "connection {connection} is {status:?}")
            }
            Self::UnknownAgent { agent } => write!(f, "agent {agent} does not exist"),
            Self::UnknownRun { run } => write!(f, "run {run} does not exist"),
            Self::CrossProject {
                id_kind,
                expected,
                found,
            } => write!(
                f,
                "{id_kind} belongs to project {found}, not the expected project {expected}"
            ),
            Self::CapabilityUnavailable { capability, reason } => write!(
                f,
                "capability {} is unavailable: {reason:?}",
                capability.as_str()
            ),
            Self::PermissionModeUnavailable { mode } => {
                write!(f, "permission mode {mode} cannot be used")
            }
            Self::PermissionContextStale { detail } => {
                write!(f, "permission context is stale: {detail}")
            }
            Self::InvalidRunTransition { from, to } => {
                write!(f, "run cannot transition from {from} to {to}")
            }
            Self::ApprovalUnknown { operation } => {
                write!(f, "no pending approval exists for {operation}")
            }
            Self::ApprovalRestored { operation } => write!(
                f,
                "approval {operation} was restored from a previous process and is not reusable"
            ),
            Self::ApprovalInvalid { operation, reason } => {
                write!(f, "approval {operation} is invalid: {reason}")
            }
            Self::Approval { error } => write!(f, "approval failed: {error}"),
            Self::GrantWidening { error } => write!(f, "child grant was rejected: {error:?}"),
            Self::NoCheckpoint { run } => write!(f, "run {run} has no saved checkpoint"),
            Self::CorruptState { detail } => write!(f, "host state is corrupt: {detail}"),
            Self::Store { error } => write!(f, "store failed: {error}"),
            Self::Engine { error } => write!(f, "engine failed: {error}"),
            Self::Execution { error } => write!(f, "tool execution failed: {error}"),
            Self::InvalidArguments { tool, detail } => {
                write!(f, "{tool} arguments are invalid: {detail}")
            }
            Self::InvalidValue { field, violation } => {
                write!(f, "invalid {field}: {violation}")
            }
            Self::ToolUnavailable { tool } => {
                write!(f, "no host executor is configured for {tool}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}
