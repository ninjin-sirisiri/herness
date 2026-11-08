//! Operations frozen with their final arguments, working directory, and policy version.
//!
//! A [`FrozenOperation`] copies every execution-relevant value at approval
//! time. Nothing is re-read from the model, project, or policy store when the
//! operation later executes.

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::ids::{OperationId, ProjectScope, RunId};
use crate::contracts::path::AbsolutePath;
use crate::contracts::time::Timestamp;
use crate::permissions::{PermissionMode, PolicyVersion};
use crate::tools::{ToolArguments, ToolName};

/// One tool operation whose final inputs are fixed for permission evaluation,
/// persistence, and execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrozenOperation {
    operation_id: OperationId,
    run_id: RunId,
    tool: ToolName,
    arguments: ToolArguments,
    cwd: AbsolutePath,
    policy_version: PolicyVersion,
    permission_mode: PermissionMode,
}

impl FrozenOperation {
    /// Freezes an operation after validating project scope and tool arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: OperationId,
        run_id: RunId,
        tool: ToolName,
        arguments: ToolArguments,
        cwd: AbsolutePath,
        policy_version: PolicyVersion,
        permission_mode: PermissionMode,
    ) -> Result<Self, CoreError> {
        ProjectScope::new(run_id.project_id()).verify(&operation_id)?;
        arguments.validate()?;
        if arguments.tool_name() != tool {
            return Err(CoreError::InvalidToolArgument {
                tool,
                field: "arguments".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: format!("payload belongs to {}", arguments.tool_name()),
                },
            });
        }

        Ok(Self {
            operation_id,
            run_id,
            tool,
            arguments,
            cwd,
            policy_version,
            permission_mode,
        })
    }

    /// Operation identifier.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Run this operation belongs to.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Project this operation belongs to.
    pub const fn project_id(&self) -> crate::contracts::ids::ProjectId {
        self.operation_id.project_id()
    }

    /// Tool to execute.
    pub const fn tool(&self) -> ToolName {
        self.tool
    }

    /// Final schema-validated arguments.
    pub fn arguments(&self) -> &ToolArguments {
        &self.arguments
    }

    /// Frozen working directory.
    pub fn cwd(&self) -> &AbsolutePath {
        &self.cwd
    }

    /// Policy version used when the operation was frozen.
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Permission mode used when the operation was frozen.
    pub const fn permission_mode(&self) -> PermissionMode {
        self.permission_mode
    }
}

impl<'de> Deserialize<'de> for FrozenOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            operation_id: OperationId,
            run_id: RunId,
            tool: ToolName,
            arguments: ToolArguments,
            cwd: AbsolutePath,
            policy_version: PolicyVersion,
            permission_mode: PermissionMode,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.operation_id,
            wire.run_id,
            wire.tool,
            wire.arguments,
            wire.cwd,
            wire.policy_version,
            wire.permission_mode,
        )
        .map_err(de::Error::custom)
    }
}

/// An operation intent persisted before its side effects begin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationIntent {
    operation: FrozenOperation,
    recorded_at: Timestamp,
}

impl OperationIntent {
    /// Creates an intent for a frozen operation.
    pub const fn new(operation: FrozenOperation, recorded_at: Timestamp) -> Self {
        Self {
            operation,
            recorded_at,
        }
    }

    /// Frozen operation being recorded.
    pub const fn operation(&self) -> &FrozenOperation {
        &self.operation
    }

    /// Time the intent was recorded.
    pub const fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }
}
