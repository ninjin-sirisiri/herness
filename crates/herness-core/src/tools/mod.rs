//! Native tool argument schemas, shared reason validation, the gateway
//! permission boundary, and the native file tools.

pub mod arguments;
#[cfg(unix)]
pub mod bash;
pub mod candidate;
pub mod diff;
pub mod edit;
pub mod files;
pub mod gateway;
pub mod path;
#[cfg(unix)]
pub mod process;
pub mod read;
pub mod reason;
pub mod search;
pub mod write;

use std::fmt;

use serde::{Deserialize, Serialize};

pub use arguments::{
    BashArgs, CandidateEditArgs, CandidateReadArgs, CandidateWriteArgs, EditArgs, FileVersion,
    MAX_CANDIDATE_ARTIFACT_BYTES, NonEmptyText, ReadArgs, SearchArgs, ToolArguments, WriteArgs,
};
#[cfg(unix)]
pub use bash::{
    BashExecutor, BashOutput, SHELL_FINISHED_EVENT_KIND, SHELL_SPAWNED_EVENT_KIND,
    SHELL_STARTED_EVENT_KIND, ShellReconciliation, reconcile_shell_operation,
};
pub use diff::{FileDiff, MAX_DIFF_BYTES};
pub use files::{
    FILE_CHANGE_EVENT_KIND, FILE_CHANGE_INTENDED_EVENT_KIND, FileChange, FileLockGuard,
    FileLockRegistry, FileToolOutput, NativeFileTools, hash_bytes,
};
pub use candidate::{
    ARTIFACT_CHANGE_EVENT_KIND, ARTIFACT_CHANGE_INTENDED_EVENT_KIND, CandidateArtifactTools,
    CandidateChange, CandidateReadOutput, CandidateToolOutput,
};
pub use gateway::{GatewayError, ToolExecutor, ToolGateway};
pub use path::{ProjectRoot, ResolvedPath};
#[cfg(unix)]
pub use process::{
    CaptureHandle, Completion, DEFAULT_CAPTURE_TIMEOUT, DEFAULT_CONFIRM_TIMEOUT,
    DEFAULT_OUTPUT_LIMIT, DEFAULT_STOP_GRACE, DEFAULT_TIMEOUT_GRACE, GroupLease, GroupStopReport,
    ManagedChild, ManagedGroup, ManagedSignal, ProcessLauncher, ProcessSupervisor, SpawnGate,
    SpawnRequest, StopRequest, SupervisorStopReport, SystemChild, SystemLauncher,
    process_group_exists, signal_process_group, spawn_failure, supervise,
};
pub use read::{DEFAULT_READ_LIMIT, MAX_READ_LIMIT, ReadOutput};
pub use reason::{MAX_REASON_SCALARS, Purpose, Rationale, ReasonField, ReasonViolation};
pub use search::{
    DEFAULT_SEARCH_RESULTS, MAX_SEARCH_FILE_BYTES, MAX_SEARCH_FILES, MAX_SEARCH_RESULTS,
    SearchMatch, SearchOutput, glob_matches,
};

/// The native and candidate tool names understood by H1.
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
    /// Read an immutable snapshot or current candidate artifact.
    CandidateRead,
    /// Create or replace a candidate artifact.
    CandidateWrite,
    /// Edit an existing candidate artifact.
    CandidateEdit,
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
            Self::CandidateRead => "candidate_read",
            Self::CandidateWrite => "candidate_write",
            Self::CandidateEdit => "candidate_edit",
        }
    }

    /// Whether this tool requires a file-level rationale.
    pub const fn requires_rationale(self) -> bool {
        matches!(
            self,
            Self::Write | Self::Edit | Self::CandidateWrite | Self::CandidateEdit
        )
    }

    /// Whether this tool requires a command-level purpose.
    pub const fn requires_purpose(self) -> bool {
        matches!(self, Self::Bash)
    }

    /// Whether this tool belongs to the candidate artifact context.
    pub const fn is_candidate(self) -> bool {
        matches!(
            self,
            Self::CandidateRead | Self::CandidateWrite | Self::CandidateEdit
        )
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
