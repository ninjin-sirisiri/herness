//! Decision bindings, statuses, and invalidation reasons.
//!
//! A permission decision is bound to the operation identifier, final argument
//! digest, working directory, project, run, tool, policy version, and mode that
//! existed when it was made. Any later change invalidates the decision before
//! the tool executor is reached.

use std::fmt::{self, Write as _};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::contracts::ids::{OperationId, ProjectId, RunId};
use crate::contracts::operation::FrozenOperation;
use crate::contracts::path::AbsolutePath;
use crate::permissions::{PermissionMode, PermissionPolicy, PolicyVersion};
use crate::tools::{ToolArguments, ToolName};

/// SHA-256 digest of the canonical final tool arguments.
///
/// The digest is used to bind an approval to the exact arguments that were
/// displayed to the human. It is not a secret and not a signature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ArgumentsDigest(String);

impl ArgumentsDigest {
    /// Computes the digest of schema-validated final arguments.
    pub fn of(arguments: &ToolArguments) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"herness.arguments.v1\0");
        hasher.update(serde_json::to_vec(arguments).unwrap_or_default());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(hex)
    }

    /// Hex digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArgumentsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Values a decision is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionBinding {
    operation_id: OperationId,
    project_id: ProjectId,
    run_id: RunId,
    tool: ToolName,
    arguments_digest: ArgumentsDigest,
    cwd: AbsolutePath,
    policy_version: PolicyVersion,
    mode: PermissionMode,
}

impl DecisionBinding {
    /// Captures the current frozen operation and policy.
    pub fn from_operation(operation: &FrozenOperation) -> Self {
        Self {
            operation_id: operation.operation_id(),
            project_id: operation.project_id(),
            run_id: operation.run_id(),
            tool: operation.tool(),
            arguments_digest: ArgumentsDigest::of(operation.arguments()),
            cwd: operation.cwd().clone(),
            policy_version: operation.policy_version(),
            mode: operation.permission_mode(),
        }
    }

    /// Operation this decision belongs to.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Project this decision belongs to.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Run this decision belongs to.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Tool this decision belongs to.
    pub const fn tool(&self) -> ToolName {
        self.tool
    }

    /// Digest of the final arguments.
    pub const fn arguments_digest(&self) -> &ArgumentsDigest {
        &self.arguments_digest
    }

    /// Frozen working directory.
    pub const fn cwd(&self) -> &AbsolutePath {
        &self.cwd
    }

    /// Policy version at decision time.
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Permission mode at decision time.
    pub const fn mode(&self) -> PermissionMode {
        self.mode
    }

    /// Checks the binding against the operation and current policy.
    pub fn check(
        &self,
        operation: &FrozenOperation,
        policy: &PermissionPolicy,
    ) -> Result<(), InvalidationReason> {
        if self.operation_id != operation.operation_id()
            || self.project_id != operation.project_id()
            || self.run_id != operation.run_id()
            || self.tool != operation.tool()
        {
            return Err(InvalidationReason::OperationChanged {
                expected: self.operation_id,
                found: operation.operation_id(),
            });
        }
        if self.arguments_digest != ArgumentsDigest::of(operation.arguments()) {
            return Err(InvalidationReason::ArgumentsChanged);
        }
        if self.cwd != *operation.cwd() {
            return Err(InvalidationReason::CwdChanged);
        }
        if self.mode != operation.permission_mode() || self.mode != policy.mode() {
            return Err(InvalidationReason::ModeChanged {
                expected: self.mode,
                found: policy.mode(),
            });
        }
        if self.policy_version != policy.version() {
            return Err(InvalidationReason::PolicyChanged {
                expected: self.policy_version,
                found: policy.version(),
            });
        }
        Ok(())
    }
}

/// Lifecycle of one recorded permission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    /// Waiting for a human decision.
    AwaitingHuman,
    /// Allowed and not yet consumed by execution.
    Approved,
    /// Explicitly denied.
    Denied,
    /// Consumed by execution immediately before the executor was called.
    Consumed,
    /// Invalidated by a change or run resume.
    Invalidated,
}

impl DecisionStatus {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingHuman => "awaiting_human",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Consumed => "consumed",
            Self::Invalidated => "invalidated",
        }
    }
}

impl fmt::Display for DecisionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a prior decision can no longer be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum InvalidationReason {
    /// Final arguments changed.
    ArgumentsChanged,
    /// Working directory changed.
    CwdChanged,
    /// Operation identity, project, run, or tool changed.
    OperationChanged {
        /// Recorded operation.
        expected: OperationId,
        /// Supplied operation.
        found: OperationId,
    },
    /// Rules or a manual bump changed the policy version.
    PolicyChanged {
        /// Version bound into the decision.
        expected: PolicyVersion,
        /// Current policy version.
        found: PolicyVersion,
    },
    /// Permission mode changed.
    ModeChanged {
        /// Mode bound into the decision.
        expected: PermissionMode,
        /// Current mode.
        found: PermissionMode,
    },
    /// The run was resumed and prior approvals are not reusable.
    RunResumed,
    /// A newer decision replaced this one.
    Superseded,
}

impl fmt::Display for InvalidationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArgumentsChanged => f.write_str("arguments changed"),
            Self::CwdChanged => f.write_str("working directory changed"),
            Self::OperationChanged { .. } => f.write_str("operation identity changed"),
            Self::PolicyChanged { .. } => f.write_str("policy version changed"),
            Self::ModeChanged { .. } => f.write_str("permission mode changed"),
            Self::RunResumed => f.write_str("run was resumed"),
            Self::Superseded => f.write_str("decision was superseded"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{PermissionMode, PolicyVersion};
    use crate::tools::{NonEmptyText, Rationale, WriteArgs};

    #[test]
    fn digest_changes_with_final_arguments() {
        let first = ToolArguments::Write(WriteArgs {
            path: NonEmptyText::new("a.txt").expect("path"),
            content: "one".to_owned(),
            rationale: Rationale::new("first").expect("rationale"),
        });
        let second = ToolArguments::Write(WriteArgs {
            path: NonEmptyText::new("a.txt").expect("path"),
            content: "two".to_owned(),
            rationale: Rationale::new("first").expect("rationale"),
        });
        assert_ne!(ArgumentsDigest::of(&first), ArgumentsDigest::of(&second));
    }

    #[test]
    fn binding_reports_each_change_kind() {
        use crate::contracts::ids::{OperationId, ProjectId, RunId};
        use crate::contracts::path::AbsolutePath;
        use crate::tools::{ToolArguments, ToolName};

        let project = ProjectId::new();
        let operation_id = OperationId::new(project);
        let run_id = RunId::new(project);
        let arguments = ToolArguments::Write(WriteArgs {
            path: NonEmptyText::new("a.txt").expect("path"),
            content: "one".to_owned(),
            rationale: Rationale::new("first").expect("rationale"),
        });
        let operation = FrozenOperation::new(
            operation_id,
            run_id,
            ToolName::Write,
            arguments.clone(),
            AbsolutePath::new("/tmp/project").expect("absolute"),
            PolicyVersion::INITIAL,
            PermissionMode::Configured,
        )
        .expect("operation");
        let binding = DecisionBinding::from_operation(&operation);
        let policy = crate::permissions::PermissionPolicy::initial();
        assert_eq!(binding.check(&operation, &policy), Ok(()));

        let changed = FrozenOperation::new(
            operation_id,
            run_id,
            ToolName::Write,
            ToolArguments::Write(WriteArgs {
                path: NonEmptyText::new("a.txt").expect("path"),
                content: "two".to_owned(),
                rationale: Rationale::new("first").expect("rationale"),
            }),
            AbsolutePath::new("/tmp/project").expect("absolute"),
            PolicyVersion::INITIAL,
            PermissionMode::Configured,
        )
        .expect("operation");
        assert_eq!(
            binding.check(&changed, &policy),
            Err(InvalidationReason::ArgumentsChanged)
        );
    }
}
