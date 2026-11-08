//! Host-owned permission policy and the human-only administration surface.
//!
//! [`PermissionPolicy`] is a snapshot of the current mode, policy version, and
//! structured rules. It has no `Deserialize` implementation and no public
//! mutation methods. A model or tool request therefore cannot create, edit, or
//! switch a policy.
//!
//! [`PolicyAdmin`] is the human-facing mutation surface. Every effective change
//! bumps the monotonic [`PolicyVersion`]. Adding a duplicate rule, removing a
//! missing rule, or selecting the current mode is a no-op and does not bump the
//! version.

use serde::Serialize;

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::operation::FrozenOperation;
use crate::permissions::{
    EvaluatorAvailability, PermissionMode, PermissionRule, PolicyVersion, RuleEffect,
};

/// Current host permission policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionPolicy {
    version: PolicyVersion,
    mode: PermissionMode,
    rules: Vec<PermissionRule>,
}

impl PermissionPolicy {
    /// Initial H1 policy: configured mode, version 1, no rules.
    pub fn initial() -> Self {
        Self {
            version: PolicyVersion::INITIAL,
            mode: PermissionMode::Configured,
            rules: Vec::new(),
        }
    }

    /// Monotonic policy version.
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    /// Selected permission mode.
    pub const fn mode(&self) -> PermissionMode {
        self.mode
    }

    /// Configured rules.
    pub fn rules(&self) -> &[PermissionRule] {
        &self.rules
    }

    /// First rule with the requested effect that matches the operation.
    pub fn matching_rule(
        &self,
        effect: RuleEffect,
        operation: &FrozenOperation,
    ) -> Option<&PermissionRule> {
        self.rules
            .iter()
            .find(|rule| rule.effect() == effect && rule.matches(operation))
    }

    /// Whether the policy contains the exact rule.
    pub fn contains_rule(&self, rule: &PermissionRule) -> bool {
        self.rules.contains(rule)
    }
}

impl Default for PermissionPolicy {
    fn default() -> Self {
        Self::initial()
    }
}

/// Human-only policy administration.
///
/// This type is intentionally separate from the model-facing operation path.
/// Tool arguments cannot name it, and policy values cannot be deserialized from
/// model output. A model or tool request must never be able to change rules,
/// mode, or the policy version.
#[derive(Debug, Clone)]
pub struct PolicyAdmin {
    policy: PermissionPolicy,
}

impl PolicyAdmin {
    /// Starts in configured mode at policy version 1 with no rules.
    pub fn new() -> Self {
        Self {
            policy: PermissionPolicy::initial(),
        }
    }

    /// Borrows the current policy snapshot.
    pub const fn policy(&self) -> &PermissionPolicy {
        &self.policy
    }

    /// Switches mode as a human action.
    ///
    /// Automatic mode is rejected when the evaluator is unavailable. A real
    /// change bumps the policy version; selecting the current mode is a no-op.
    pub fn set_mode(
        &mut self,
        mode: PermissionMode,
        availability: EvaluatorAvailability,
    ) -> Result<PolicyVersion, CoreError> {
        if mode.requires_evaluator() && !mode.is_usable_with(availability) {
            return Err(CoreError::PermissionEvaluatorUnavailable { mode });
        }
        if self.policy.mode == mode {
            return Ok(self.policy.version);
        }
        let version = self.bump_version()?;
        self.policy.mode = mode;
        Ok(version)
    }

    /// Adds a rule as a human action.
    ///
    /// Adding an identical rule is a no-op. Any effective change bumps the
    /// policy version so prior decisions become stale.
    pub fn add_rule(&mut self, rule: PermissionRule) -> Result<PolicyVersion, CoreError> {
        if self.policy.rules.contains(&rule) {
            return Ok(self.policy.version);
        }
        let version = self.bump_version()?;
        self.policy.rules.push(rule);
        Ok(version)
    }

    /// Removes a rule as a human action.
    ///
    /// Returns the new version, or `None` when the rule was absent.
    pub fn remove_rule(
        &mut self,
        rule: &PermissionRule,
    ) -> Result<Option<PolicyVersion>, CoreError> {
        let Some(position) = self
            .policy
            .rules
            .iter()
            .position(|candidate| candidate == rule)
        else {
            return Ok(None);
        };
        let version = self.bump_version()?;
        self.policy.rules.remove(position);
        Ok(Some(version))
    }

    /// Bumps the policy version without changing rules or mode.
    ///
    /// This invalidates unused decisions and approvals. It is a human action.
    pub fn bump_version(&mut self) -> Result<PolicyVersion, CoreError> {
        let next = self
            .policy
            .version
            .next()
            .ok_or_else(|| CoreError::InvalidValue {
                field: "policyVersion".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "monotonic policy version space exhausted".to_owned(),
                },
            })?;
        self.policy.version = next;
        Ok(next)
    }
}

impl Default for PolicyAdmin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{MatchMethod, RuleTarget};
    use crate::tools::ToolName;

    fn read_rule() -> PermissionRule {
        PermissionRule::allow(
            RuleTarget::Tool {
                tool: ToolName::Read,
            },
            MatchMethod::AnyInvocation,
        )
        .expect("rule")
    }

    #[test]
    fn every_effective_human_change_bumps_the_version() {
        let mut admin = PolicyAdmin::new();
        assert_eq!(admin.policy().version(), PolicyVersion::INITIAL);
        assert_eq!(admin.policy().mode(), PermissionMode::Configured);

        let rule = read_rule();
        assert_eq!(
            admin.add_rule(rule.clone()).expect("add"),
            PolicyVersion::new(2).expect("v2")
        );
        assert_eq!(
            admin.add_rule(rule.clone()).expect("duplicate add"),
            PolicyVersion::new(2).expect("v2")
        );
        assert_eq!(
            admin.remove_rule(&rule).expect("remove").expect("present"),
            PolicyVersion::new(3).expect("v3")
        );
        assert_eq!(admin.remove_rule(&rule).expect("remove missing"), None);
        assert_eq!(
            admin.bump_version().expect("bump"),
            PolicyVersion::new(4).expect("v4")
        );
        assert_eq!(
            admin
                .set_mode(PermissionMode::Automatic, EvaluatorAvailability::Available)
                .expect("mode"),
            PolicyVersion::new(5).expect("v5")
        );
        assert_eq!(
            admin
                .set_mode(PermissionMode::Automatic, EvaluatorAvailability::Available)
                .expect("same mode"),
            PolicyVersion::new(5).expect("v5")
        );
    }

    #[test]
    fn automatic_mode_is_rejected_without_an_evaluator() {
        let mut admin = PolicyAdmin::new();
        let error = admin
            .set_mode(
                PermissionMode::Automatic,
                EvaluatorAvailability::Unavailable,
            )
            .expect_err("automatic mode requires an evaluator");
        assert_eq!(
            error,
            CoreError::PermissionEvaluatorUnavailable {
                mode: PermissionMode::Automatic
            }
        );
        assert_eq!(admin.policy().mode(), PermissionMode::Configured);
        assert_eq!(admin.policy().version(), PolicyVersion::INITIAL);
    }
}
