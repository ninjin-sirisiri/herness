//! Native tool argument schemas and shared reason validation.

pub mod arguments;
pub mod reason;

use std::fmt;

use serde::{Deserialize, Serialize};

pub use arguments::{
    BashArgs, EditArgs, FileVersion, NonEmptyText, ReadArgs, SearchArgs, ToolArguments, WriteArgs,
};
pub use reason::{MAX_REASON_SCALARS, Purpose, Rationale, ReasonField, ReasonViolation};

/// The five native tools available in H1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolName {
    /// Read a file from the project.
    Read,
    /// Search project contents.
    Search,
    /// Create a file.
    Write,
    /// Edit an existing file.
    Edit,
    /// Run a managed shell command.
    Bash,
}

impl ToolName {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Search => "search",
            Self::Write => "write",
            Self::Edit => "edit",
            Self::Bash => "bash",
        }
    }

    /// Whether this tool requires a file-level rationale.
    pub const fn requires_rationale(self) -> bool {
        matches!(self, Self::Write | Self::Edit)
    }

    /// Whether this tool requires a command-level purpose.
    pub const fn requires_purpose(self) -> bool {
        matches!(self, Self::Bash)
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
