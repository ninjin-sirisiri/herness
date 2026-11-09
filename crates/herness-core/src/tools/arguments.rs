//! Argument schemas for the five native tools.
//!
//! Write and edit carry a validated [`Rationale`]; bash carries a validated
//! [`Purpose`]. Deserializing [`ToolArguments`] enforces these values plus the
//! numeric argument checks, so the gateway only receives schema-valid data.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::artifact::{ArtifactHandle, ArtifactSlot};
use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::tools::ToolName;
use crate::tools::reason::{Purpose, Rationale};

/// Maximum UTF-8 bytes accepted for one candidate artifact.
///
/// This is the H3 candidate HTML limit. It is applied to every candidate write
/// so an oversized body is held as a capability failure instead of being
/// truncated or silently stored.
pub const MAX_CANDIDATE_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;

/// A trimmed, non-empty text value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonEmptyText(String);

impl NonEmptyText {
    /// Validates and stores a non-empty text value.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CoreError> {
        let trimmed = value.as_ref().trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidValue {
                field: "text".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Borrows the trimmed text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the value and returns the trimmed string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for NonEmptyText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NonEmptyText {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for NonEmptyText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NonEmptyText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Opaque file-version token captured before an edit.
///
/// The value is produced by the file toolchain (for example a content digest).
/// Core carries it without interpreting it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileVersion(String);

impl FileVersion {
    /// Validates and stores a non-empty file-version token.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CoreError> {
        let trimmed = value.as_ref().trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidValue {
                field: "fileVersion".to_owned(),
                violation: ArgumentViolation::Empty,
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Borrows the token.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FileVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for FileVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for FileVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Arguments for `read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadArgs {
    /// Project-relative or absolute path to read.
    pub path: NonEmptyText,
    /// One-based line offset.
    pub offset: Option<u64>,
    /// Maximum number of lines to return.
    pub limit: Option<u64>,
}

impl ReadArgs {
    /// Validates numeric bounds.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.offset == Some(0) {
            return Err(invalid(
                ToolName::Read,
                "offset",
                ArgumentViolation::MustBePositive,
            ));
        }
        if self.limit == Some(0) {
            return Err(invalid(
                ToolName::Read,
                "limit",
                ArgumentViolation::MustBePositive,
            ));
        }
        Ok(())
    }
}

/// Arguments for `search`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchArgs {
    /// Text or pattern to search for.
    pub query: NonEmptyText,
    /// Optional path scope.
    pub path: Option<NonEmptyText>,
    /// Optional glob filter.
    pub glob: Option<NonEmptyText>,
    /// Optional maximum number of results.
    pub max_results: Option<u32>,
}

impl SearchArgs {
    /// Validates numeric bounds.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.max_results == Some(0) {
            return Err(invalid(
                ToolName::Search,
                "maxResults",
                ArgumentViolation::MustBePositive,
            ));
        }
        Ok(())
    }
}

/// Arguments for `write`. Write creates a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteArgs {
    /// Path to create.
    pub path: NonEmptyText,
    /// Full file content.
    pub content: String,
    /// Required file-level reason for the change.
    pub rationale: Rationale,
}

impl WriteArgs {
    /// Schema is enforced by the field types.
    pub fn validate(&self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// Arguments for `edit`. Edit modifies an existing file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EditArgs {
    /// Path to edit.
    pub path: NonEmptyText,
    /// Exact text expected before the edit.
    pub old_text: String,
    /// Replacement text.
    pub new_text: String,
    /// Required file-level reason for the change.
    pub rationale: Rationale,
    /// Version observed before the edit, when the caller supplied one.
    pub expected_version: Option<FileVersion>,
}

impl EditArgs {
    /// Schema is enforced by the field types.
    pub fn validate(&self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// Arguments for `bash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BashArgs {
    /// Command to run in the frozen working directory.
    pub command: NonEmptyText,
    /// Required command-level purpose, recorded separately from output.
    pub purpose: Purpose,
    /// Optional timeout in milliseconds.
    pub timeout_ms: Option<u64>,
}

impl BashArgs {
    /// Validates numeric bounds.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.timeout_ms == Some(0) {
            return Err(invalid(
                ToolName::Bash,
                "timeoutMs",
                ArgumentViolation::MustBePositive,
            ));
        }
        Ok(())
    }
}

/// Arguments for `candidate_read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateReadArgs {
    /// Host-issued handle for this project/job/generation.
    pub handle: ArtifactHandle,
    /// Immutable snapshot or current candidate to read.
    pub artifact: ArtifactSlot,
}

impl CandidateReadArgs {
    /// Schema is enforced by the field types.
    pub fn validate(&self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// Arguments for `candidate_write`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateWriteArgs {
    /// Host-issued handle for this project/job/generation.
    pub handle: ArtifactHandle,
    /// Candidate slot to create or replace.
    pub artifact: ArtifactSlot,
    /// Full candidate content.
    pub content: String,
    /// Required rationale for the change.
    pub rationale: Rationale,
}

impl CandidateWriteArgs {
    /// Validates the target slot and size.
    pub fn validate(&self) -> Result<(), CoreError> {
        require_candidate_target(ToolName::CandidateWrite, self.artifact)?;
        if self.content.len() > MAX_CANDIDATE_ARTIFACT_BYTES {
            return Err(invalid(
                ToolName::CandidateWrite,
                "content",
                ArgumentViolation::TooLongBytes {
                    actual: self.content.len(),
                    max: MAX_CANDIDATE_ARTIFACT_BYTES,
                },
            ));
        }
        Ok(())
    }
}

/// Arguments for `candidate_edit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateEditArgs {
    /// Host-issued handle for this project/job/generation.
    pub handle: ArtifactHandle,
    /// Candidate slot to edit.
    pub artifact: ArtifactSlot,
    /// Exact text expected before the edit.
    pub old_text: String,
    /// Replacement text.
    pub new_text: String,
    /// Required rationale for the change.
    pub rationale: Rationale,
    /// Candidate version observed before the edit, when supplied.
    pub expected_version: Option<FileVersion>,
}

impl CandidateEditArgs {
    /// Validates the target slot and size.
    pub fn validate(&self) -> Result<(), CoreError> {
        require_candidate_target(ToolName::CandidateEdit, self.artifact)?;
        if self.new_text.len() > MAX_CANDIDATE_ARTIFACT_BYTES {
            return Err(invalid(
                ToolName::CandidateEdit,
                "newText",
                ArgumentViolation::TooLongBytes {
                    actual: self.new_text.len(),
                    max: MAX_CANDIDATE_ARTIFACT_BYTES,
                },
            ));
        }
        Ok(())
    }
}

fn require_candidate_target(tool: ToolName, artifact: ArtifactSlot) -> Result<(), CoreError> {
    if artifact.is_candidate() {
        return Ok(());
    }
    Err(invalid(
        tool,
        "artifact",
        ArgumentViolation::Invalid {
            detail: format!(
                "{artifact} is read-only; write and edit accept candidate_html or candidate_provenance only"
            ),
        },
    ))
}

/// Final, schema-validated arguments for one tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "tool", content = "arguments", rename_all = "snake_case")]
pub enum ToolArguments {
    /// Arguments for `read`.
    Read(ReadArgs),
    /// Arguments for `search`.
    Search(SearchArgs),
    /// Arguments for `write`.
    Write(WriteArgs),
    /// Arguments for `edit`.
    Edit(EditArgs),
    /// Arguments for `bash`.
    Bash(BashArgs),
    /// Arguments for `candidate_read`.
    CandidateRead(CandidateReadArgs),
    /// Arguments for `candidate_write`.
    CandidateWrite(CandidateWriteArgs),
    /// Arguments for `candidate_edit`.
    CandidateEdit(CandidateEditArgs),
}

impl ToolArguments {
    /// Tool this argument payload belongs to.
    pub const fn tool_name(&self) -> ToolName {
        match self {
            Self::Read(_) => ToolName::Read,
            Self::Search(_) => ToolName::Search,
            Self::Write(_) => ToolName::Write,
            Self::Edit(_) => ToolName::Edit,
            Self::Bash(_) => ToolName::Bash,
            Self::CandidateRead(_) => ToolName::CandidateRead,
            Self::CandidateWrite(_) => ToolName::CandidateWrite,
            Self::CandidateEdit(_) => ToolName::CandidateEdit,
        }
    }

    /// Re-runs schema validation.
    pub fn validate(&self) -> Result<(), CoreError> {
        match self {
            Self::Read(args) => args.validate(),
            Self::Search(args) => args.validate(),
            Self::Write(args) => args.validate(),
            Self::Edit(args) => args.validate(),
            Self::Bash(args) => args.validate(),
            Self::CandidateRead(args) => args.validate(),
            Self::CandidateWrite(args) => args.validate(),
            Self::CandidateEdit(args) => args.validate(),
        }
    }
}

impl<'de> Deserialize<'de> for ToolArguments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "tool", content = "arguments", rename_all = "snake_case")]
        enum Wire {
            Read(ReadArgs),
            Search(SearchArgs),
            Write(WriteArgs),
            Edit(EditArgs),
            Bash(BashArgs),
            CandidateRead(CandidateReadArgs),
            CandidateWrite(CandidateWriteArgs),
            CandidateEdit(CandidateEditArgs),
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = match wire {
            Wire::Read(args) => Self::Read(args),
            Wire::Search(args) => Self::Search(args),
            Wire::Write(args) => Self::Write(args),
            Wire::Edit(args) => Self::Edit(args),
            Wire::Bash(args) => Self::Bash(args),
            Wire::CandidateRead(args) => Self::CandidateRead(args),
            Wire::CandidateWrite(args) => Self::CandidateWrite(args),
            Wire::CandidateEdit(args) => Self::CandidateEdit(args),
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

fn invalid(tool: ToolName, field: &str, violation: ArgumentViolation) -> CoreError {
    CoreError::InvalidToolArgument {
        tool,
        field: field.to_owned(),
        violation,
    }
}
