//! Run and child-agent grant scopes.
//!
//! Permissions are fundamentally granted when a run starts and are inherited by
//! child agents. A [`GrantScope`] is an explicit allowlist ceiling expressed
//! with the same structured rule vocabulary as the policy. A child scope is
//! derived from its parent with [`GrantScope::derive_child`]; any request that
//! is not fully covered by the parent is rejected rather than silently widened.

use serde::Serialize;

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::ids::ProjectId;
use crate::contracts::operation::FrozenOperation;
use crate::permissions::{
    MatchMethod, PermissionMode, PermissionPolicy, PermissionRule, PolicyVersion, RuleEffect,
    RuleTarget,
};
use crate::tools::ToolName;

/// An allowlist ceiling for one run or child agent in one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantScope {
    project_id: ProjectId,
    grants: Vec<PermissionRule>,
    mode: PermissionMode,
    policy_version: PolicyVersion,
}

impl GrantScope {
    /// Creates a project-bound scope from allow rules.
    ///
    /// Every rule must have [`RuleEffect::Allow`]; deny and ask rules belong to
    /// the policy, not to a grant.
    pub fn new(
        project_id: ProjectId,
        grants: Vec<PermissionRule>,
        mode: PermissionMode,
        policy_version: PolicyVersion,
    ) -> Result<Self, CoreError> {
        if let Some(rule) = grants
            .iter()
            .find(|rule| rule.effect() != RuleEffect::Allow)
        {
            return Err(CoreError::InvalidValue {
                field: "grantScope".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: format!("grant rules must allow, found {}", rule.effect()),
                },
            });
        }
        Ok(Self {
            project_id,
            grants,
            mode,
            policy_version,
        })
    }

    /// An unrestricted run scope for the policy's current mode and version.
    ///
    /// This grants the five native H1 tools at the policy level. It is a
    /// ceiling, not an approval: configured mode still requires an allow rule
    /// or a human decision, and automatic mode still requires the evaluator.
    pub fn for_run(project_id: ProjectId, policy: &PermissionPolicy) -> Self {
        let grants = [
            ToolName::Read,
            ToolName::Search,
            ToolName::Write,
            ToolName::Edit,
            ToolName::Bash,
        ]
        .into_iter()
        .map(tool_allow_rule)
        .collect();
        Self {
            project_id,
            grants,
            mode: policy.mode(),
            policy_version: policy.version(),
        }
    }

    /// An unrestricted candidate-run scope for the policy's current mode and
    /// version.
    ///
    /// Candidate runs receive only the three candidate artifact tools. The
    /// native writers and shell are deliberately absent, so a candidate run
    /// cannot write a formal Target, companion, CSS, or settings path even when
    /// the policy would otherwise allow it.
    pub fn for_candidate_run(project_id: ProjectId, policy: &PermissionPolicy) -> Self {
        let grants = [
            ToolName::CandidateRead,
            ToolName::CandidateWrite,
            ToolName::CandidateEdit,
        ]
        .into_iter()
        .map(tool_allow_rule)
        .collect();
        Self {
            project_id,
            grants,
            mode: policy.mode(),
            policy_version: policy.version(),
        }
    }

    /// A scope containing exactly the policy's allow rules.
    ///
    /// This is the conservative derivation for a run that should be limited to
    /// work already granted by explicit rules.
    pub fn from_policy(project_id: ProjectId, policy: &PermissionPolicy) -> Self {
        Self {
            project_id,
            grants: policy
                .rules()
                .iter()
                .filter(|rule| rule.effect() == RuleEffect::Allow)
                .cloned()
                .collect(),
            mode: policy.mode(),
            policy_version: policy.version(),
        }
    }

    /// Project this scope belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Allow rules forming this scope.
    pub fn grants(&self) -> &[PermissionRule] {
        &self.grants
    }

    /// Maximum permission mode this scope permits.
    pub const fn mode(&self) -> PermissionMode {
        self.mode
    }

    /// Policy version this scope was derived from.
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Whether any grant rule covers the operation.
    pub fn permits(&self, operation: &FrozenOperation) -> bool {
        self.grants.iter().any(|rule| rule.matches(operation))
    }

    /// Derives a child scope from this parent.
    ///
    /// The requested scope must be in the same project and fully covered by the
    /// parent. Uncovered tools, broader paths, broader argv/command targets,
    /// automatic-mode escalation, and a different policy version are rejected.
    pub fn derive_child(&self, requested: &GrantScope) -> Result<GrantScope, GrantWidening> {
        if requested.project_id != self.project_id {
            return Err(GrantWidening::CrossProject {
                expected: self.project_id,
                found: requested.project_id,
            });
        }
        if requested.policy_version != self.policy_version {
            return Err(GrantWidening::PolicyVersionChanged {
                parent: self.policy_version,
                requested: requested.policy_version,
            });
        }
        if requested.mode == PermissionMode::Automatic && self.mode == PermissionMode::Configured {
            return Err(GrantWidening::ModeEscalation {
                parent: self.mode,
                requested: requested.mode,
            });
        }
        for grant in &requested.grants {
            if self.grants.iter().any(|parent| parent.covers(grant)) {
                continue;
            }
            return Err(widening_for(grant, &self.grants));
        }
        Ok(requested.clone())
    }
}

/// A rejected attempt to widen a child grant scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum GrantWidening {
    /// The child asked for a scope from another project.
    CrossProject {
        /// Parent project.
        expected: ProjectId,
        /// Requested project.
        found: ProjectId,
    },
    /// The child asked for a tool the parent was not granted.
    NewTool {
        /// Requested tool.
        tool: ToolName,
    },
    /// The child asked for tool-wide access while the parent has only narrower
    /// path or argv grants for that tool.
    BroaderTool {
        /// Requested tool.
        tool: ToolName,
    },
    /// The child asked for a path outside every parent path grant.
    BroaderPath {
        /// File tool.
        tool: ToolName,
        /// Requested path or root.
        path: String,
    },
    /// The child asked for a broader shell target.
    BroaderBashTarget {
        /// Requested shell target.
        target: RuleTarget,
    },
    /// The child tried to move from configured mode to automatic mode.
    ModeEscalation {
        /// Parent mode.
        parent: PermissionMode,
        /// Requested mode.
        requested: PermissionMode,
    },
    /// The child tried to use a different policy version.
    PolicyVersionChanged {
        /// Parent version.
        parent: PolicyVersion,
        /// Requested version.
        requested: PolicyVersion,
    },
}

fn tool_allow_rule(tool: ToolName) -> PermissionRule {
    PermissionRule::allow(RuleTarget::Tool { tool }, MatchMethod::AnyInvocation)
        .expect("tool-wide allow rule is valid")
}

fn widening_for(grant: &PermissionRule, parent_grants: &[PermissionRule]) -> GrantWidening {
    let tool = grant.target().tool();
    if !parent_grants
        .iter()
        .any(|parent| parent.target().tool() == tool)
    {
        return GrantWidening::NewTool { tool };
    }
    match grant.target() {
        RuleTarget::FilePath { tool, root } => GrantWidening::BroaderPath {
            tool: *tool,
            path: root.to_string(),
        },
        target @ (RuleTarget::BashArgv { .. } | RuleTarget::BashCommand { .. }) => {
            GrantWidening::BroaderBashTarget {
                target: target.clone(),
            }
        }
        RuleTarget::Tool { tool } => GrantWidening::BroaderTool { tool: *tool },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::path::AbsolutePath;

    fn path_grant(tool: ToolName, root: &str, method: MatchMethod) -> PermissionRule {
        PermissionRule::allow(
            RuleTarget::FilePath {
                tool,
                root: AbsolutePath::new(root).expect("absolute root"),
            },
            method,
        )
        .expect("path rule")
    }

    fn bash_grant(arguments: Option<Vec<&str>>) -> PermissionRule {
        PermissionRule::allow(
            RuleTarget::BashArgv {
                program: "cargo".to_owned(),
                arguments: arguments.map(|values| values.into_iter().map(str::to_owned).collect()),
            },
            MatchMethod::ExactArgv,
        )
        .expect("bash rule")
    }

    fn scope(project: ProjectId, grants: Vec<PermissionRule>) -> GrantScope {
        GrantScope::new(
            project,
            grants,
            PermissionMode::Configured,
            PolicyVersion::INITIAL,
        )
        .expect("scope")
    }

    #[test]
    fn narrower_child_scope_is_accepted() {
        let project = ProjectId::new();
        let parent = scope(
            project,
            vec![path_grant(
                ToolName::Write,
                "/tmp/project",
                MatchMethod::PathPrefix,
            )],
        );
        let child = scope(
            project,
            vec![path_grant(
                ToolName::Write,
                "/tmp/project/src",
                MatchMethod::PathPrefix,
            )],
        );
        assert_eq!(parent.derive_child(&child).expect("subset"), child);
    }

    #[test]
    fn broader_and_new_child_grants_are_rejected() {
        let project = ProjectId::new();
        let parent = scope(
            project,
            vec![
                path_grant(ToolName::Write, "/tmp/project/src", MatchMethod::PathPrefix),
                bash_grant(Some(vec!["test"])),
            ],
        );

        let new_tool = scope(
            project,
            vec![
                PermissionRule::allow(
                    RuleTarget::Tool {
                        tool: ToolName::Read,
                    },
                    MatchMethod::AnyInvocation,
                )
                .expect("rule"),
            ],
        );
        assert!(matches!(
            parent.derive_child(&new_tool),
            Err(GrantWidening::NewTool {
                tool: ToolName::Read
            })
        ));

        let broader_path = scope(
            project,
            vec![path_grant(
                ToolName::Write,
                "/tmp/project",
                MatchMethod::PathPrefix,
            )],
        );
        assert!(matches!(
            parent.derive_child(&broader_path),
            Err(GrantWidening::BroaderPath {
                tool: ToolName::Write,
                ..
            })
        ));

        let tool_wide = scope(
            project,
            vec![
                PermissionRule::allow(
                    RuleTarget::Tool {
                        tool: ToolName::Write,
                    },
                    MatchMethod::AnyInvocation,
                )
                .expect("rule"),
            ],
        );
        assert!(matches!(
            parent.derive_child(&tool_wide),
            Err(GrantWidening::BroaderTool {
                tool: ToolName::Write
            })
        ));

        let broader_bash = scope(project, vec![bash_grant(None)]);
        assert!(matches!(
            parent.derive_child(&broader_bash),
            Err(GrantWidening::BroaderBashTarget { .. })
        ));
    }

    #[test]
    fn mode_and_policy_version_cannot_be_escalated_by_a_child() {
        let project = ProjectId::new();
        let parent = scope(project, vec![]);
        let automatic = GrantScope::new(
            project,
            Vec::new(),
            PermissionMode::Automatic,
            PolicyVersion::INITIAL,
        )
        .expect("scope");
        assert!(matches!(
            parent.derive_child(&automatic),
            Err(GrantWidening::ModeEscalation { .. })
        ));

        let bumped = GrantScope::new(
            project,
            Vec::new(),
            PermissionMode::Configured,
            PolicyVersion::new(2).expect("v2"),
        )
        .expect("scope");
        assert!(matches!(
            parent.derive_child(&bumped),
            Err(GrantWidening::PolicyVersionChanged { .. })
        ));
    }

    #[test]
    fn cross_project_child_scope_is_rejected() {
        let parent = scope(ProjectId::new(), Vec::new());
        let other = scope(ProjectId::new(), Vec::new());
        assert!(matches!(
            parent.derive_child(&other),
            Err(GrantWidening::CrossProject { .. })
        ));
    }

    #[test]
    fn deny_rules_are_not_grants() {
        let deny = PermissionRule::deny(
            RuleTarget::Tool {
                tool: ToolName::Read,
            },
            MatchMethod::AnyInvocation,
        )
        .expect("rule");
        assert!(
            GrantScope::new(
                ProjectId::new(),
                vec![deny],
                PermissionMode::Configured,
                PolicyVersion::INITIAL
            )
            .is_err()
        );
    }
}
