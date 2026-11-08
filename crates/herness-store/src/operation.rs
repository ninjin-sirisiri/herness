//! Operation records and recovery evidence.
//!
//! An [`OperationIntent`] is written in the same transaction as the checkpoint
//! that authorized it. Its result is written separately, after the side effect,
//! and may be [`OperationOutcome::Applied`], [`OperationOutcome::NotApplied`],
//! or [`OperationOutcome::Unverifiable`]. Recovery code only reads these
//! records; the store never starts execution.

use serde::{Deserialize, Serialize};

use herness_core::{AbsolutePath, FileVersion, OperationIntent, Timestamp};

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
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::NotApplied => "not_applied",
            Self::Unverifiable => "unverifiable",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
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
}

impl OperationEvidence {
    /// Creates evidence from file observations and the shell uncertainty flag.
    pub const fn new(files: Vec<FileObservation>, shell_outcome_unknown: bool) -> Self {
        Self {
            files,
            shell_outcome_unknown,
        }
    }

    /// Evidence with no observations.
    pub const fn empty() -> Self {
        Self {
            files: Vec::new(),
            shell_outcome_unknown: false,
        }
    }

    /// File observations captured around the operation.
    pub fn files(&self) -> &[FileObservation] {
        &self.files
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
    pub(crate) intent: OperationIntent,
    pub(crate) result: Option<OperationResult>,
}

impl OperationRecord {
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
