//! Run lifecycle states.

use std::fmt;

use serde::{Deserialize, Serialize};

/// State of one host-started engine run.
///
/// `Idle` means the engine has no pending response or tool call. It is not
/// task completion, goal completion, or proof that any requested work was
/// achieved; H2/H4 own those judgments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// The engine is producing a response or running a tool.
    Running,
    /// The run is waiting for a human approval decision.
    AwaitingApproval,
    /// The run is paused by the host and can be resumed as the same run.
    Paused,
    /// Execution was interrupted and the run has not been resumed.
    Interrupted,
    /// The engine has no pending response or tool call.
    ///
    /// This does not mean that a task, goal, or requested change completed.
    Idle,
    /// The run failed. Failed operations are not automatically retried.
    Failed,
}

impl RunState {
    /// Every state in the H1 contract.
    pub const ALL: [Self; 6] = [
        Self::Running,
        Self::AwaitingApproval,
        Self::Paused,
        Self::Interrupted,
        Self::Idle,
        Self::Failed,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Paused => "paused",
            Self::Interrupted => "interrupted",
            Self::Idle => "idle",
            Self::Failed => "failed",
        }
    }

    /// Returns true only for [`RunState::Idle`].
    pub const fn is_idle(self) -> bool {
        matches!(self, Self::Idle)
    }

    /// Returns true while the engine may still make progress without a new run.
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::AwaitingApproval)
    }
}

impl fmt::Display for RunState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
