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

use crate::contracts::connection::ConnectionId;
use crate::contracts::ids::{AgentId, OperationId, ProjectId, RunId, SessionId};
use crate::contracts::operation::FrozenOperation;
use crate::contracts::path::AbsolutePath;
use crate::contracts::run::RunState;
use crate::contracts::time::Timestamp;
use crate::permissions::{
    GrantScope, MatchMethod, PermissionMode, PermissionRule, PolicyVersion, RuleEffect, RuleTarget,
};
use crate::runtime::error::RuntimeError;
use crate::skills::HostCapability;
use crate::tools::ToolName;

/// Storage key for the single host-state document.
pub(crate) const HOST_STATE_KEY: &str = "herness.runtime.host-state";
/// Format of the host-state JSON document.
pub(crate) const HOST_STATE_FORMAT: u32 = 1;

/// Whole host-owned runtime state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HostState {
    format: u32,
    projects: BTreeMap<ProjectId, ProjectRecord>,
}

impl Default for HostState {
    fn default() -> Self {
        Self {
            format: HOST_STATE_FORMAT,
            projects: BTreeMap::new(),
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
        if state.format != HOST_STATE_FORMAT {
            return Err(RuntimeError::CorruptState {
                detail: format!(
                    "unsupported host-state format {}; this build supports {}",
                    state.format, HOST_STATE_FORMAT
                ),
            });
        }
        Ok(state)
    }

    /// Serializes host state for the store.
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        serde_json::to_vec(self).map_err(|error| RuntimeError::CorruptState {
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
