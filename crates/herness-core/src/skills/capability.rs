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
    /// Dispatching an approved HTML authoring job to a host-owned worker.
    AuthoringDispatch,
    /// Calling the versioned Common SDD host API for static policy work.
    PolicyBridge,
}

impl HostCapability {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkillRead => "skill_read",
            Self::HtmlWorker => "html_worker",
            Self::SddTaskController => "sdd_task_controller",
            Self::AuthoringDispatch => "authoring_dispatch",
            Self::PolicyBridge => "policy_bridge",
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
    /// This build has not implemented the capability yet. It must stay
    /// explicitly unavailable rather than falling back to the parent model.
    NotImplementedYet,
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
/// The H1 default can read skills but never advertises the HTML worker, SDD
/// Task controller, authoring dispatch, or policy bridge as available. The H3
/// policy-bridge constructor advertises only the versioned Common SDD host API;
/// the HTML worker and authoring dispatch stay explicitly unavailable until
/// their later tasks connect them. A caller that needs an unavailable flow
/// receives an explicit result and never silently falls back to the parent
/// model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostCapabilities {
    skill_read: CapabilityStatus,
    html_worker: CapabilityStatus,
    sdd_task_controller: CapabilityStatus,
    authoring_dispatch: CapabilityStatus,
    policy_bridge: CapabilityStatus,
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
            authoring_dispatch: CapabilityStatus::Unavailable {
                reason: CapabilityUnavailableReason::NotImplementedYet,
            },
            policy_bridge: CapabilityStatus::Unavailable {
                reason: CapabilityUnavailableReason::NotImplementedYet,
            },
        }
    }

    /// The H3 policy-bridge capability set.
    ///
    /// Task 14 connects the versioned Common SDD host API. The HTML worker and
    /// authoring dispatch stay explicitly unavailable until Tasks 16/22; this
    /// report never claims them early.
    pub const fn h3_policy_bridge() -> Self {
        Self {
            skill_read: CapabilityStatus::Available,
            html_worker: CapabilityStatus::Unavailable {
                reason: CapabilityUnavailableReason::NotImplementedYet,
            },
            sdd_task_controller: CapabilityStatus::Unavailable {
                reason: CapabilityUnavailableReason::NotImplementedInH1,
            },
            authoring_dispatch: CapabilityStatus::Unavailable {
                reason: CapabilityUnavailableReason::NotImplementedYet,
            },
            policy_bridge: CapabilityStatus::Available,
        }
    }

    /// The complete H3 desktop capability set.
    ///
    /// This reports what the host implements, not that any project has approved
    /// or enabled it. The per-project H3 capability report still requires the
    /// real policy connection, render, assessment, and human approval before the
    /// HtmlWorker is bound. SDD Task progress remains outside H3.
    pub const fn h3_complete() -> Self {
        Self {
            skill_read: CapabilityStatus::Available,
            html_worker: CapabilityStatus::Available,
            sdd_task_controller: CapabilityStatus::Unavailable {
                reason: CapabilityUnavailableReason::NotImplementedInH1,
            },
            authoring_dispatch: CapabilityStatus::Available,
            policy_bridge: CapabilityStatus::Available,
        }
    }

    /// Returns a copy with one capability replaced.
    pub const fn with_status(self, capability: HostCapability, status: CapabilityStatus) -> Self {
        let mut next = self;
        match capability {
            HostCapability::SkillRead => next.skill_read = status,
            HostCapability::HtmlWorker => next.html_worker = status,
            HostCapability::SddTaskController => next.sdd_task_controller = status,
            HostCapability::AuthoringDispatch => next.authoring_dispatch = status,
            HostCapability::PolicyBridge => next.policy_bridge = status,
        }
        next
    }

    /// Returns the status of `capability`.
    pub const fn status(self, capability: HostCapability) -> CapabilityStatus {
        match capability {
            HostCapability::SkillRead => self.skill_read,
            HostCapability::HtmlWorker => self.html_worker,
            HostCapability::SddTaskController => self.sdd_task_controller,
            HostCapability::AuthoringDispatch => self.authoring_dispatch,
            HostCapability::PolicyBridge => self.policy_bridge,
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
