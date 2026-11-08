//! H1 host capabilities and the distinction between reading a skill and
//! executing its worker flow.

use serde::{Deserialize, Serialize};

/// A host capability a skill flow may depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostCapability {
    /// Reading skill documents and their referenced files from the SDD pack.
    SkillRead,
    /// Authoring or synchronizing HTML documents.
    HtmlWorker,
    /// Driving SDD Task progress across runs.
    SddTaskController,
}

impl HostCapability {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkillRead => "skill_read",
            Self::HtmlWorker => "html_worker",
            Self::SddTaskController => "sdd_task_controller",
        }
    }
}

/// Why a capability is unavailable in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityUnavailableReason {
    /// H1 deliberately does not implement this worker. H3/H4 own it and no
    /// parent-model fallback is performed.
    NotImplementedInH1,
}

/// Availability of one capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CapabilityStatus {
    /// The capability can be used.
    Available,
    /// The capability cannot be used.
    Unavailable {
        /// Structured reason shown to callers and UI.
        reason: CapabilityUnavailableReason,
    },
}

impl CapabilityStatus {
    /// Whether the capability can be used.
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Capability report for one host configuration.
///
/// H1 can read skills, but never advertises the HTML worker or SDD Task
/// controller as available. A caller that needs one of those flows must
/// receive an explicit unavailability result; it must not silently fall back
/// to the parent model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostCapabilities {
    skill_read: CapabilityStatus,
    html_worker: CapabilityStatus,
    sdd_task_controller: CapabilityStatus,
}

impl HostCapabilities {
    /// The H1 capability set: skill reading only.
    pub const fn h1() -> Self {
        Self {
            skill_read: CapabilityStatus::Available,
            html_worker: CapabilityStatus::Unavailable {
                reason: CapabilityUnavailableReason::NotImplementedInH1,
            },
            sdd_task_controller: CapabilityStatus::Unavailable {
                reason: CapabilityUnavailableReason::NotImplementedInH1,
            },
        }
    }

    /// Returns the status of `capability`.
    pub const fn status(self, capability: HostCapability) -> CapabilityStatus {
        match capability {
            HostCapability::SkillRead => self.skill_read,
            HostCapability::HtmlWorker => self.html_worker,
            HostCapability::SddTaskController => self.sdd_task_controller,
        }
    }
}

impl Default for HostCapabilities {
    fn default() -> Self {
        Self::h1()
    }
}

/// The part of a skill that a run asks to execute.
///
/// `ReadOnly` means the skill text is loaded into context. It does not claim
/// that the skill's worker flow ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillExecutionFlow {
    /// Load the skill text for context only.
    ReadOnly,
    /// Execute HTML authoring/synchronization.
    HtmlWorker,
    /// Execute SDD Task progress.
    SddTaskController,
}

impl SkillExecutionFlow {
    /// Capability this flow depends on, or `None` for read-only context.
    pub const fn capability(self) -> Option<HostCapability> {
        match self {
            Self::ReadOnly => None,
            Self::HtmlWorker => Some(HostCapability::HtmlWorker),
            Self::SddTaskController => Some(HostCapability::SddTaskController),
        }
    }

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::HtmlWorker => "html_worker",
            Self::SddTaskController => "sdd_task_controller",
        }
    }

    /// Whether this flow runs a host worker rather than only loading text.
    pub const fn executes_worker(self) -> bool {
        !matches!(self, Self::ReadOnly)
    }
}

/// Flow requested for one skill together with its capability status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillExecutionStatus {
    flow: SkillExecutionFlow,
    status: CapabilityStatus,
}

impl SkillExecutionStatus {
    /// Combines a flow with the host capability report.
    pub const fn new(flow: SkillExecutionFlow, capabilities: HostCapabilities) -> Self {
        let status = match flow.capability() {
            None => CapabilityStatus::Available,
            Some(capability) => capabilities.status(capability),
        };
        Self { flow, status }
    }

    /// Requested flow.
    pub const fn flow(self) -> SkillExecutionFlow {
        self.flow
    }

    /// Capability status for the requested flow.
    pub const fn status(self) -> CapabilityStatus {
        self.status
    }

    /// Whether the worker flow may run. Read-only context is not a worker
    /// execution, so this is false for `ReadOnly` even though reading is
    /// allowed.
    pub const fn worker_available(self) -> bool {
        self.flow.executes_worker() && self.status.is_available()
    }
}
