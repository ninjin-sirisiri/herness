//! Tool-gateway permission boundary.
//!
//! The gateway is the only path between a frozen operation and a
//! [`ToolExecutor`]. It evaluates permission, offers human approval, and
//! re-checks the decision immediately before calling the executor. An invalid
//! or stale decision is an error and the executor is never invoked.
//!
//! This module intentionally contains no file or shell I/O. Tasks 4 and 5
//! provide the real executors behind [`ToolExecutor`].

use std::fmt;

use crate::contracts::errors::CoreError;
use crate::contracts::ids::ProjectId;
use crate::contracts::operation::FrozenOperation;
use crate::permissions::{
    ApprovalError, ApprovalRequest, Authorization, EvaluationContext, GrantScope,
    PermissionOutcome, PermissionPolicy, PermissionService, ProtectedBoundary,
};
use crate::ports::evaluator::PermissionEvaluatorPort;

/// Executor invoked only after the permission service consumed a valid
/// authorization.
pub trait ToolExecutor {
    /// Result of a successful tool execution.
    type Output;

    /// Executes one frozen operation.
    fn execute(&mut self, operation: &FrozenOperation) -> Result<Self::Output, CoreError>;
}

/// Gateway failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    /// The decision was missing, stale, reused, or cross-project.
    Approval(ApprovalError),
    /// The executor itself failed.
    Executor(CoreError),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval(error) => write!(f, "permission check failed: {error}"),
            Self::Executor(error) => write!(f, "tool execution failed: {error}"),
        }
    }
}

impl std::error::Error for GatewayError {}

impl From<ApprovalError> for GatewayError {
    fn from(value: ApprovalError) -> Self {
        Self::Approval(value)
    }
}

impl From<CoreError> for GatewayError {
    fn from(value: CoreError) -> Self {
        Self::Executor(value)
    }
}

/// Permission-aware gateway around one executor.
#[derive(Debug)]
pub struct ToolGateway<E> {
    service: PermissionService,
    executor: E,
}

impl<E> ToolGateway<E> {
    /// Creates a gateway with no protected host paths.
    pub fn new(executor: E) -> Self {
        Self {
            service: PermissionService::new(),
            executor,
        }
    }

    /// Creates a gateway with protected host paths.
    pub fn with_protected_boundary(executor: E, boundary: ProtectedBoundary) -> Self {
        Self {
            service: PermissionService::with_protected_boundary(boundary),
            executor,
        }
    }

    /// Permission service state.
    pub const fn service(&self) -> &PermissionService {
        &self.service
    }

    /// Mutable permission service state, for host code only.
    pub const fn service_mut(&mut self) -> &mut PermissionService {
        &mut self.service
    }

    /// Executor reference, useful for test counters.
    pub const fn executor(&self) -> &E {
        &self.executor
    }

    /// Mutable executor reference, for host/test configuration such as fault
    /// injection. Permission checks still run in [`Self::execute`].
    pub const fn executor_mut(&mut self) -> &mut E {
        &mut self.executor
    }

    /// Pending human approvals.
    pub fn pending_approvals(&self) -> Vec<ApprovalRequest> {
        self.service.pending_approvals()
    }
}

impl<E: ToolExecutor> ToolGateway<E> {
    /// Evaluates one operation without executing it.
    pub fn authorize(
        &mut self,
        policy: &PermissionPolicy,
        grant: &GrantScope,
        operation: &FrozenOperation,
        context: &EvaluationContext,
        evaluator: Option<&mut (dyn PermissionEvaluatorPort + Send + Sync)>,
    ) -> Result<PermissionOutcome, CoreError> {
        self.service
            .evaluate(policy, grant, operation, context, evaluator)
    }

    /// Approves a pending operation as a human action.
    pub fn approve(
        &mut self,
        policy: &PermissionPolicy,
        operation: &FrozenOperation,
        approver_project: ProjectId,
    ) -> Result<Authorization, ApprovalError> {
        self.service.approve(policy, operation, approver_project)
    }

    /// Denies a pending operation as a human action.
    pub fn deny(
        &mut self,
        policy: &PermissionPolicy,
        operation: &FrozenOperation,
        approver_project: ProjectId,
    ) -> Result<(), ApprovalError> {
        self.service.deny(policy, operation, approver_project)
    }

    /// Re-checks an authorization and calls the executor.
    ///
    /// The authorization is consumed before the executor runs. A subsequent
    /// call with the same authorization is rejected even if the executor
    /// failed.
    pub fn execute(
        &mut self,
        policy: &PermissionPolicy,
        operation: &FrozenOperation,
        authorization: &Authorization,
    ) -> Result<E::Output, GatewayError> {
        self.service
            .confirm_before_execution(policy, operation, authorization)?;
        self.executor
            .execute(operation)
            .map_err(GatewayError::Executor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::path::AbsolutePath;
    use crate::permissions::{MatchMethod, PermissionRule, PolicyAdmin, RuleTarget};
    use crate::tools::{NonEmptyText, ReadArgs, ToolArguments, ToolName};
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Debug, Clone)]
    struct CountingExecutor {
        calls: Rc<Cell<usize>>,
    }

    impl ToolExecutor for CountingExecutor {
        type Output = ();
        fn execute(&mut self, _operation: &FrozenOperation) -> Result<(), CoreError> {
            self.calls.set(self.calls.get() + 1);
            Ok(())
        }
    }

    fn operation(policy: &PermissionPolicy) -> FrozenOperation {
        let project = crate::contracts::ids::ProjectId::new();
        FrozenOperation::new(
            crate::contracts::ids::OperationId::new(project),
            crate::contracts::ids::RunId::new(project),
            ToolName::Read,
            ToolArguments::Read(ReadArgs {
                path: NonEmptyText::new("/tmp/project/file.txt").expect("path"),
                offset: None,
                limit: None,
            }),
            AbsolutePath::new("/tmp/project").expect("absolute"),
            policy.version(),
            policy.mode(),
        )
        .expect("operation")
    }

    #[test]
    fn stale_authorization_never_reaches_the_executor() {
        let mut admin = PolicyAdmin::new();
        admin
            .add_rule(
                PermissionRule::allow(
                    RuleTarget::Tool {
                        tool: ToolName::Read,
                    },
                    MatchMethod::AnyInvocation,
                )
                .expect("rule"),
            )
            .expect("add");
        let policy = admin.policy().clone();
        let calls = Rc::new(Cell::new(0));
        let mut gateway = ToolGateway::new(CountingExecutor {
            calls: Rc::clone(&calls),
        });
        let operation = operation(&policy);
        let grant = GrantScope::for_run(operation.project_id(), &policy);
        let outcome = gateway
            .authorize(
                &policy,
                &grant,
                &operation,
                &EvaluationContext::new("test", Vec::new()),
                None,
            )
            .expect("evaluate");
        let PermissionOutcome::Allow { authorization } = outcome else {
            panic!("expected allow");
        };
        admin.bump_version().expect("bump");
        let error = gateway
            .execute(admin.policy(), &operation, &authorization)
            .expect_err("stale authorization must fail");
        assert!(matches!(error, GatewayError::Approval(_)));
        assert_eq!(calls.get(), 0);
    }
}
