//! Structured evidence from one managed shell command.
//!
//! The bash tool records how a command ended, what it wrote to stdout/stderr,
//! and whether captured output was truncated. Output is bounded; a truncated
//! capture always says so and reports the original byte count. This value is
//! evidence about the shell, not proof that any particular file changed.

use serde::{Deserialize, Serialize};

use crate::contracts::time::Timestamp;

/// How a managed shell command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellStopStatus {
    /// The command exited with code 0.
    Completed,
    /// The command exited with a non-zero code.
    ExitedNonZero,
    /// The command was terminated by a signal that the host did not send as a
    /// stop or timeout.
    Killed,
    /// The command exceeded its timeout and the host terminated its group.
    Timeout,
    /// A human or host stop request terminated the command and the host
    /// confirmed that no member of the managed process group remains.
    StopRequested,
    /// The host could not confirm that the managed process group is gone.
    ///
    /// The tool must not report this as a completed or stopped success.
    Unconfirmed,
}

/// One bounded stdout or stderr capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShellOutput {
    text: String,
    truncated: bool,
    original_bytes: u64,
}

impl ShellOutput {
    /// Creates an output capture. `original_bytes` is the number of bytes the
    /// process wrote, not the number retained in `text`.
    pub const fn new(text: String, truncated: bool, original_bytes: u64) -> Self {
        Self {
            text,
            truncated,
            original_bytes,
        }
    }

    /// Captured text, with an explicit marker when data was dropped.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether any produced bytes were not retained.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Total number of bytes observed on the stream.
    pub const fn original_bytes(&self) -> u64 {
        self.original_bytes
    }
}

/// Observed result of one managed shell command.
///
/// `exit_code` is `None` when the process did not exit normally; the
/// terminating signal is then reported separately. The process group is
/// managed by the host: a shell that intentionally detaches a descendant
/// (`setsid`, double fork) leaves that descendant outside the group guarantee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShellObservation {
    pid: u32,
    pgid: u32,
    exit_code: Option<i32>,
    terminating_signal: Option<i32>,
    stop_status: ShellStopStatus,
    stdout: ShellOutput,
    stderr: ShellOutput,
    started_at: Timestamp,
    finished_at: Timestamp,
}

impl ShellObservation {
    /// Creates a complete shell observation.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        pid: u32,
        pgid: u32,
        exit_code: Option<i32>,
        terminating_signal: Option<i32>,
        stop_status: ShellStopStatus,
        stdout: ShellOutput,
        stderr: ShellOutput,
        started_at: Timestamp,
        finished_at: Timestamp,
    ) -> Self {
        Self {
            pid,
            pgid,
            exit_code,
            terminating_signal,
            stop_status,
            stdout,
            stderr,
            started_at,
            finished_at,
        }
    }

    /// Process id of the managed shell, which was also the process-group
    /// leader.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Managed process-group id. It equals [`Self::pid`] because the shell is
    /// started in a new group led by itself.
    pub const fn pgid(&self) -> u32 {
        self.pgid
    }

    /// Normal exit code, when the process exited normally.
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Terminating signal, when the process was killed by a signal.
    pub const fn terminating_signal(&self) -> Option<i32> {
        self.terminating_signal
    }

    /// How the command ended from the host's point of view.
    pub const fn stop_status(&self) -> ShellStopStatus {
        self.stop_status
    }

    /// Bounded standard output.
    pub const fn stdout(&self) -> &ShellOutput {
        &self.stdout
    }

    /// Bounded standard error.
    pub const fn stderr(&self) -> &ShellOutput {
        &self.stderr
    }

    /// Time the host recorded the intent to run the command.
    pub const fn started_at(&self) -> Timestamp {
        self.started_at
    }

    /// Time the host finished observing the command.
    pub const fn finished_at(&self) -> Timestamp {
        self.finished_at
    }
}
