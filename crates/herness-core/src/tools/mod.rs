//! Native tool argument schemas, shared reason validation, the gateway
//! permission boundary, and the native file tools.

pub mod arguments;
pub mod diff;
pub mod edit;
pub mod files;
pub mod gateway;
pub mod path;
pub mod read;
pub mod reason;
pub mod search;
pub mod write;

use std::fmt;

use serde::{Deserialize, Serialize};

pub use arguments::{
    BashArgs, EditArgs, FileVersion, NonEmptyText, ReadArgs, SearchArgs, ToolArguments, WriteArgs,
};
pub use diff::{FileDiff, MAX_DIFF_BYTES};
pub use files::{
    FILE_CHANGE_EVENT_KIND, FILE_CHANGE_INTENDED_EVENT_KIND, FileChange, FileLockGuard,
    FileLockRegistry, FileToolOutput, NativeFileTools, hash_bytes,
};
pub use gateway::{GatewayError, ToolExecutor, ToolGateway};
pub use path::{ProjectRoot, ResolvedPath};
pub use read::{DEFAULT_READ_LIMIT, MAX_READ_LIMIT, ReadOutput};
pub use reason::{MAX_REASON_SCALARS, Purpose, Rationale, ReasonField, ReasonViolation};
pub use search::{
    DEFAULT_SEARCH_RESULTS, MAX_SEARCH_FILE_BYTES, MAX_SEARCH_FILES, MAX_SEARCH_RESULTS,
    SearchMatch, SearchOutput, glob_matches,
};

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
