//! Versioned, non-secret host state.
//!
//! The runtime persists project paths, host-created agent/session identities, run
//! states, and pending approval descriptions as private JSON in the store's
//! `host_state` table. It never persists credentials, provider output,
//! checkpoints, or model reasoning here.
//!
//! The security-sensitive permission types deliberately have no `Deserialize`
//! implementation. A serializable mirror is used for child-agent grant scopes
//! and reconstructed through the validated constructor on load.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::connections::ConnectionSettings;
use crate::contracts::connection::ConnectionId;
use crate::contracts::ids::{AgentId, OperationId, ProjectId, RunId, SessionId};
use crate::contracts::operation::FrozenOperation;
use crate::contracts::path::AbsolutePath;
use crate::contracts::run::RunState;
use crate::contracts::time::Timestamp;
use crate::permissions::{
    GrantScope, MatchMethod, PermissionMode, PermissionRule, PolicyVersion, RuleEffect, RuleTarget,
};
use crate::ports::engine::StopReport;
use crate::runtime::error::RuntimeError;
use crate::runtime::shutdown::ShutdownOutcome;
use crate::skills::HostCapability;
use crate::tools::ToolName;

/// Storage key for the single host-state document.
pub(crate) const HOST_STATE_KEY: &str = "herness.runtime.host-state";
/// Current format of the host-state JSON document.
///
/// Format 2 adds non-secret connection settings and the last shutdown record.
/// Format 1 documents are still read; they contain neither field.
pub(crate) const HOST_STATE_FORMAT: u32 = 2;
/// Formats this build can read.
const SUPPORTED_HOST_STATE_FORMATS: [u32; 2] = [1, 2];

/// Whole host-owned runtime state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HostState {
    format: u32,
    projects: BTreeMap<ProjectId, ProjectRecord>,
    #[serde(default)]
    connections: BTreeMap<ConnectionId, ConnectionSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shutdown: Option<ShutdownRecord>,
}

impl Default for HostState {
    fn default() -> Self {
        Self {
            format: HOST_STATE_FORMAT,
            projects: BTreeMap::new(),
            connections: BTreeMap::new(),
            shutdown: None,
        }
    }
}

impl HostState {
    /// Parses host state, rejecting unknown formats and unknown fields.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, RuntimeError> {
        let state: Self =
            serde_json::from_slice(bytes).map_err(|error| RuntimeError::CorruptState {
                detail: format!("host-state JSON: {error}"),
            })?;
        if !SUPPORTED_HOST_STATE_FORMATS.contains(&state.format) {
            return Err(RuntimeError::CorruptState {
                detail: format!(
                    "unsupported host-state format {}; this build supports {:?}",
                    state.format, SUPPORTED_HOST_STATE_FORMATS
                ),
            });
        }
        if state.format == 1 && (!state.connections.is_empty() || state.shutdown.is_some()) {
            return Err(RuntimeError::CorruptState {
                detail: "host-state format 1 must not contain format 2 fields".to_owned(),
            });
        }
        Ok(state)
    }

    /// Serializes host state for the store. The current format is always used.
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        let mut current = self.clone();
        current.format = HOST_STATE_FORMAT;
        serde_json::to_vec(&current).map_err(|error| RuntimeError::CorruptState {
            detail: format!("host-state JSON: {error}"),
        })
    }

    /// Projects in stable identifier order.
    pub(crate) fn projects(&self) -> &BTreeMap<ProjectId, ProjectRecord> {
        &self.projects
    }

    /// Mutable project map.
    pub(crate) fn projects_mut(&mut self) -> &mut BTreeMap<ProjectId, ProjectRecord> {
        &mut self.projects
    }

    /// Persisted non-secret connection settings in stable identifier order.
    pub(crate) fn connections(&self) -> &BTreeMap<ConnectionId, ConnectionSettings> {
        &self.connections
    }

    /// Mutable persisted connection map.
    pub(crate) fn connections_mut(&mut self) -> &mut BTreeMap<ConnectionId, ConnectionSettings> {
        &mut self.connections
    }

    /// Last shutdown attempt, when this state came from a quitting process.
    pub(crate) fn shutdown(&self) -> Option<&ShutdownRecord> {
        self.shutdown.as_ref()
    }

    /// Mutable last-shutdown slot.
    pub(crate) fn shutdown_mut(&mut self) -> &mut Option<ShutdownRecord> {
        &mut self.shutdown
    }

    /// Finds a project by its canonical real path.
    pub(crate) fn project_id_for_path(&self, path: &AbsolutePath) -> Option<ProjectId> {
        self.projects
            .iter()
            .find(|(_, project)| project.path == *path)
            .map(|(project, _)| *project)
    }
}

/// One opened project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProjectRecord {
    pub(crate) path: AbsolutePath,
    pub(crate) agents: BTreeMap<AgentId, AgentRecord>,
    pub(crate) runs: BTreeMap<RunId, RunRecord>,
    #[serde(default)]
    pub(crate) approvals: BTreeMap<OperationId, ApprovalRecord>,
}

impl ProjectRecord {
    pub(crate) fn new(path: AbsolutePath) -> Self {
        Self {
            path,
            agents: BTreeMap::new(),
            runs: BTreeMap::new(),
            approvals: BTreeMap::new(),
        }
    }
}

/// One host-created agent conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentRecord {
    pub(crate) session_id: SessionId,
    pub(crate) name: String,
    pub(crate) role: String,
    pub(crate) connection: ConnectionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) parent: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) grant: Option<StoredGrant>,
    pub(crate) required_capabilities: Vec<HostCapability>,
    pub(crate) created_at: Timestamp,
}

/// One host-started run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RunRecord {
    pub(crate) agent_id: AgentId,
    pub(crate) session_id: SessionId,
    pub(crate) connection: ConnectionId,
    pub(crate) state: RunState,
    pub(crate) instructions: String,
    pub(crate) grant: StoredGrant,
    pub(crate) mode: PermissionMode,
    pub(crate) policy_version: PolicyVersion,
    pub(crate) created_at: Timestamp,
    pub(crate) updated_at: Timestamp,
}

/// One persisted pending approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApprovalRecord {
    pub(crate) run_id: RunId,
    pub(crate) agent_id: AgentId,
    pub(crate) session_id: SessionId,
    pub(crate) operation: FrozenOperation,
    pub(crate) reason: String,
    pub(crate) requested_at: Timestamp,
    #[serde(default)]
    pub(crate) restored: bool,
}

/// Serializable mirror of a child-agent grant scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoredGrant {
    grants: Vec<StoredRule>,
    mode: PermissionMode,
    policy_version: PolicyVersion,
}

impl StoredGrant {
    /// Captures one validated grant scope.
    pub(crate) fn from_scope(scope: &GrantScope) -> Self {
        Self {
            grants: scope.grants().iter().map(StoredRule::from_rule).collect(),
            mode: scope.mode(),
            policy_version: scope.policy_version(),
        }
    }

    /// Reconstructs the validated grant scope for a project.
    pub(crate) fn to_scope(&self, project: ProjectId) -> Result<GrantScope, RuntimeError> {
        let grants = self
            .grants
            .iter()
            .map(StoredRule::to_rule)
            .collect::<Result<Vec<_>, _>>()?;
        GrantScope::new(project, grants, self.mode, self.policy_version).map_err(|error| {
            RuntimeError::CorruptState {
                detail: format!("stored grant: {error}"),
            }
        })
    }
}

/// Serializable mirror of one allow rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredRule {
    effect: StoredEffect,
    target: StoredTarget,
    match_method: StoredMatchMethod,
}

impl StoredRule {
    fn from_rule(rule: &PermissionRule) -> Self {
        let target = match rule.target() {
            RuleTarget::Tool { tool } => StoredTarget::Tool { tool: *tool },
            RuleTarget::FilePath { tool, root } => StoredTarget::FilePath {
                tool: *tool,
                root: root.clone(),
            },
            RuleTarget::BashArgv { program, arguments } => StoredTarget::BashArgv {
                program: program.clone(),
                arguments: arguments.clone(),
            },
            RuleTarget::BashCommand { command } => StoredTarget::BashCommand {
                command: command.clone(),
            },
        };
        let effect = match rule.effect() {
            RuleEffect::Allow => StoredEffect::Allow,
            RuleEffect::Deny => StoredEffect::Deny,
            RuleEffect::Ask => StoredEffect::Ask,
        };
        let match_method = match rule.match_method() {
            MatchMethod::AnyInvocation => StoredMatchMethod::AnyInvocation,
            MatchMethod::ExactPath => StoredMatchMethod::ExactPath,
            MatchMethod::PathPrefix => StoredMatchMethod::PathPrefix,
            MatchMethod::ExactArgv => StoredMatchMethod::ExactArgv,
            MatchMethod::ExactCommand => StoredMatchMethod::ExactCommand,
        };
        Self {
            effect,
            target,
            match_method,
        }
    }

    fn to_rule(&self) -> Result<PermissionRule, RuntimeError> {
        let effect = match self.effect {
            StoredEffect::Allow => RuleEffect::Allow,
            StoredEffect::Deny => RuleEffect::Deny,
            StoredEffect::Ask => RuleEffect::Ask,
        };
        let target = match &self.target {
            StoredTarget::Tool { tool } => RuleTarget::Tool { tool: *tool },
            StoredTarget::FilePath { tool, root } => RuleTarget::FilePath {
                tool: *tool,
                root: root.clone(),
            },
            StoredTarget::BashArgv { program, arguments } => RuleTarget::BashArgv {
                program: program.clone(),
                arguments: arguments.clone(),
            },
            StoredTarget::BashCommand { command } => RuleTarget::BashCommand {
                command: command.clone(),
            },
        };
        let match_method = match self.match_method {
            StoredMatchMethod::AnyInvocation => MatchMethod::AnyInvocation,
            StoredMatchMethod::ExactPath => MatchMethod::ExactPath,
            StoredMatchMethod::PathPrefix => MatchMethod::PathPrefix,
            StoredMatchMethod::ExactArgv => MatchMethod::ExactArgv,
            StoredMatchMethod::ExactCommand => MatchMethod::ExactCommand,
        };
        PermissionRule::new(effect, target, match_method).map_err(|error| {
            RuntimeError::CorruptState {
                detail: format!("stored grant rule: {error}"),
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredEffect {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredMatchMethod {
    AnyInvocation,
    ExactPath,
    PathPrefix,
    ExactArgv,
    ExactCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum StoredTarget {
    Tool {
        tool: ToolName,
    },
    FilePath {
        tool: ToolName,
        root: AbsolutePath,
    },
    BashArgv {
        program: String,
        arguments: Option<Vec<String>>,
    },
    BashCommand {
        command: String,
    },
}

/// One run included in an explicit shutdown attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ShutdownRunRecord {
    pub(crate) project_id: ProjectId,
    pub(crate) run_id: RunId,
    pub(crate) state: RunState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) report: Option<StopReport>,
    pub(crate) checkpoint_saved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) failure: Option<String>,
}

/// Durable, non-secret record of the last explicit application shutdown.
///
/// The record never claims that a forced quit saved or stopped anything. The
/// next process reports it during reconciliation and treats any run still in an
/// active state as interrupted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ShutdownRecord {
    pub(crate) outcome: ShutdownOutcome,
    pub(crate) started_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) finished_at: Option<Timestamp>,
    #[serde(default)]
    pub(crate) stopped_runs: Vec<ShutdownRunRecord>,
    #[serde(default)]
    pub(crate) unconfirmed_runs: Vec<RunId>,
    #[serde(default)]
    pub(crate) remaining_runs: Vec<RunId>,
    #[serde(default)]
    pub(crate) discarded_deferred_messages: u64,
    #[serde(default)]
    pub(crate) save_failures: u32,
}

impl ShutdownRecord {
    pub(crate) fn in_progress(started_at: Timestamp, discarded_deferred_messages: usize) -> Self {
        Self {
            outcome: ShutdownOutcome::InProgress,
            started_at,
            finished_at: None,
            stopped_runs: Vec::new(),
            unconfirmed_runs: Vec::new(),
            remaining_runs: Vec::new(),
            discarded_deferred_messages: discarded_deferred_messages as u64,
            save_failures: 0,
        }
    }
}
