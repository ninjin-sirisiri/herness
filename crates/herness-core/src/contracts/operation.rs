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
use crate::contracts::shell::ShellObservation;
use crate::contracts::time::Timestamp;
use crate::permissions::{PermissionMode, PolicyVersion};
use crate::tools::{FileVersion, ToolArguments, ToolName};

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

/// What is durably known about an operation's side effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    /// The side effect was observed as applied.
    Applied,
    /// The side effect was observed as not applied.
    NotApplied,
    /// The side effect may or may not have happened; human reconciliation is
    /// required.
    Unverifiable,
}

impl OperationOutcome {
    /// Stable wire and storage label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::NotApplied => "not_applied",
            Self::Unverifiable => "unverifiable",
        }
    }

    /// Parses a stable storage label. Unknown labels are not guessed.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "applied" => Some(Self::Applied),
            "not_applied" => Some(Self::NotApplied),
            "unverifiable" => Some(Self::Unverifiable),
            _ => None,
        }
    }
}

/// Observed versions of one file before and after an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileObservation {
    path: AbsolutePath,
    before_version: Option<FileVersion>,
    after_version: Option<FileVersion>,
}

impl FileObservation {
    /// Records the actual file path and the versions observed around the
    /// operation. Missing versions are `None`, never guessed.
    pub const fn new(
        path: AbsolutePath,
        before_version: Option<FileVersion>,
        after_version: Option<FileVersion>,
    ) -> Self {
        Self {
            path,
            before_version,
            after_version,
        }
    }

    /// Actual absolute path observed by the tool.
    pub const fn path(&self) -> &AbsolutePath {
        &self.path
    }

    /// Version observed before the side effect, when available.
    pub const fn before_version(&self) -> Option<&FileVersion> {
        self.before_version.as_ref()
    }

    /// Version observed after the side effect, when available.
    pub const fn after_version(&self) -> Option<&FileVersion> {
        self.after_version.as_ref()
    }
}

/// Evidence supporting an operation result.
///
/// Empty evidence is allowed. A shell whose completion cannot be confirmed
/// sets [`OperationEvidence::shell_outcome_unknown`] and should be recorded as
/// [`OperationOutcome::Unverifiable`] rather than as applied.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationEvidence {
    files: Vec<FileObservation>,
    shell_outcome_unknown: bool,
    #[serde(default)]
    shell: Option<ShellObservation>,
}

impl OperationEvidence {
    /// Creates evidence from file observations and the shell uncertainty flag.
    pub const fn new(files: Vec<FileObservation>, shell_outcome_unknown: bool) -> Self {
        Self {
            files,
            shell_outcome_unknown,
            shell: None,
        }
    }

    /// Evidence with no observations.
    pub const fn empty() -> Self {
        Self {
            files: Vec::new(),
            shell_outcome_unknown: false,
            shell: None,
        }
    }

    /// Attaches a structured shell observation.
    #[must_use]
    pub fn with_shell(mut self, observation: ShellObservation) -> Self {
        self.shell = Some(observation);
        self
    }

    /// File observations captured around the operation.
    pub fn files(&self) -> &[FileObservation] {
        &self.files
    }

    /// Structured shell observation, when the tool ran a managed command.
    pub const fn shell(&self) -> Option<&ShellObservation> {
        self.shell.as_ref()
    }

    /// Whether a shell's completion or cleanup could not be confirmed.
    pub const fn shell_outcome_unknown(&self) -> bool {
        self.shell_outcome_unknown
    }
}

/// A recorded operation outcome plus its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationResult {
    outcome: OperationOutcome,
    evidence: OperationEvidence,
    recorded_at: Timestamp,
}

impl OperationResult {
    /// Creates a result. The caller is responsible for using evidence that
    /// supports the claimed outcome.
    pub const fn new(
        outcome: OperationOutcome,
        evidence: OperationEvidence,
        recorded_at: Timestamp,
    ) -> Self {
        Self {
            outcome,
            evidence,
            recorded_at,
        }
    }

    /// Durably recorded outcome.
    pub const fn outcome(&self) -> OperationOutcome {
        self.outcome
    }

    /// Evidence supporting the outcome.
    pub const fn evidence(&self) -> &OperationEvidence {
        &self.evidence
    }

    /// Time the result was recorded.
    pub const fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }
}

/// A persisted operation intent and its optional result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRecord {
    intent: OperationIntent,
    result: Option<OperationResult>,
}

impl OperationRecord {
    /// Creates a record from a persisted intent and its optional result.
    pub const fn new(intent: OperationIntent, result: Option<OperationResult>) -> Self {
        Self { intent, result }
    }

    /// Operation intent recorded before the side effect.
    pub const fn intent(&self) -> &OperationIntent {
        &self.intent
    }

    /// Recorded result, if the operation has been resolved.
    pub const fn result(&self) -> Option<&OperationResult> {
        self.result.as_ref()
    }

    /// Whether no result has been recorded yet.
    pub const fn is_pending(&self) -> bool {
        self.result.is_none()
    }

    /// Whether recovery still needs to resolve this operation.
    ///
    /// Pending and unverifiable operations are unresolved. Applied and
    /// not-applied operations are resolved.
    pub fn is_unresolved(&self) -> bool {
        match &self.result {
            None => true,
            Some(result) => result.outcome() == OperationOutcome::Unverifiable,
        }
    }
}
