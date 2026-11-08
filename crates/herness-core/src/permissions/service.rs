//! Permission evaluation and the human-approval ledger.
//!
//! Evaluation runs in this fixed order:
//!
//! 1. schema validation;
//! 2. protected host-boundary checks;
//! 3. explicit deny rules;
//! 4. the run/child grant ceiling;
//! 5. explicit ask rules;
//! 6. mode: configured mode requires an allow-rule match, automatic mode sends
//!    every operation not resolved by deny/ask to the evaluator.
//!
//! Evaluator unavailability, timeout, malformed response, low confidence,
//! refusal, or error always produces human wait. It is never converted into an
//! allow.
//!
//! The evaluator receives the frozen operation plus human-requested work, a
//! serialized permission boundary, and host-supplied evidence. Model rationale
//! and read file contents are never copied into the authority fields. The
//! settled `EvaluationRequest` type still carries the frozen operation (which
//! includes model-authored arguments); evaluator implementations must not treat
//! those arguments or any file contents as authority to change permission.

use serde::Serialize;

use crate::contracts::errors::{CoreError, EvaluationFailureKind};
use crate::contracts::ids::{IdKind, OperationId, ProjectId, RunId};
use crate::contracts::operation::FrozenOperation;
use crate::contracts::path::AbsolutePath;
use crate::permissions::approval::{ApprovalLedger, ApprovalRequest, Authorization};
use crate::permissions::capability::AutomaticModeCapability;
use crate::permissions::decision::{DecisionBinding, DecisionStatus};
use crate::permissions::grant::GrantScope;
use crate::permissions::policy::PermissionPolicy;
use crate::permissions::protected::ProtectedBoundary;
use crate::permissions::rules::{PermissionRule, RuleEffect};
use crate::permissions::{ApprovalError, PermissionDecision, PermissionMode, PolicyVersion};
use crate::ports::evaluator::{EvaluationRequest, PermissionEvaluatorPort};
use crate::tools::ToolName;

/// Human-supplied context for an evaluation. It never includes model rationale
/// or read file contents as authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationContext {
    requested_work: String,
    evidence: Vec<String>,
}

impl EvaluationContext {
    /// Creates evaluation context. `requested_work` is the human task summary;
    /// `evidence` is host-supplied, non-secret evidence such as a path list or
    /// digest. File bodies and rationale do not belong here.
    pub fn new(requested_work: impl Into<String>, evidence: Vec<String>) -> Self {
        Self {
            requested_work: requested_work.into().trim().to_owned(),
            evidence,
        }
    }

    /// Human-requested work summary.
    pub fn requested_work(&self) -> &str {
        &self.requested_work
    }

    /// Host-supplied evidence.
    pub fn evidence(&self) -> &[String] {
        &self.evidence
    }
}

/// Why a permission evaluator could not decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluatorFailure {
    /// No evaluator is connected or it reports itself unavailable.
    Unavailable,
    /// The evaluator exceeded its deadline.
    Timeout,
    /// The evaluator returned malformed or unsupported output.
    InvalidResponse,
    /// The evaluator could not reach a confident decision.
    LowConfidence,
    /// The evaluator refused to decide.
    Refused,
    /// The evaluator returned another sanitized error.
    Error,
}

impl EvaluatorFailure {
    fn from_error(error: &CoreError) -> Self {
        match error {
            CoreError::PermissionEvaluatorUnavailable { .. } => Self::Unavailable,
            CoreError::PermissionEvaluationFailed { failure } => match failure {
                EvaluationFailureKind::Unavailable => Self::Unavailable,
                EvaluationFailureKind::Timeout => Self::Timeout,
                EvaluationFailureKind::InvalidResponse => Self::InvalidResponse,
                EvaluationFailureKind::LowConfidence => Self::LowConfidence,
                EvaluationFailureKind::Refused => Self::Refused,
            },
            _ => Self::Error,
        }
    }
}

/// Why an operation was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum DenialReason {
    /// A structured file write would modify a protected host path.
    ProtectedBoundary {
        /// Protected path that would be modified.
        path: AbsolutePath,
    },
    /// An explicit deny rule matched.
    ExplicitRule {
        /// Matching deny rule.
        rule: PermissionRule,
    },
    /// The operation is outside the run or child grant ceiling.
    GrantExceeded {
        /// Tool that was requested.
        tool: ToolName,
    },
    /// The evaluator explicitly denied the operation.
    Evaluator,
}

/// Why an operation is waiting for a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum HumanWaitReason {
    /// Configured mode matched no allow rule.
    NoMatchingAllowRule,
    /// An explicit ask rule matched.
    ExplicitRule {
        /// Matching ask rule.
        rule: PermissionRule,
    },
    /// The evaluator explicitly asked for a human decision.
    EvaluatorAsk,
    /// The evaluator could not provide a usable decision.
    EvaluatorFailure {
        /// Structured failure.
        failure: EvaluatorFailure,
    },
}

/// Result of evaluating one frozen operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PermissionOutcome {
    /// The operation may run after an immediate re-check.
    Allow {
        /// Single-use authorization.
        authorization: Authorization,
    },
    /// The operation must not run.
    Deny {
        /// Structured denial reason.
        reason: DenialReason,
    },
    /// The operation waits for a human decision.
    AwaitingApproval {
        /// Request shown to the human.
        request: Box<ApprovalRequest>,
    },
}

/// Permission service owning the approval ledger and protected boundary.
#[derive(Debug, Default)]
pub struct PermissionService {
    ledger: ApprovalLedger,
    boundary: ProtectedBoundary,
}

impl PermissionService {
    /// Creates a service with no protected paths.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a service with protected host paths.
    pub fn with_protected_boundary(boundary: ProtectedBoundary) -> Self {
        Self {
            ledger: ApprovalLedger::new(),
            boundary,
        }
    }

    /// Protected boundary in use.
    pub const fn protected_boundary(&self) -> &ProtectedBoundary {
        &self.boundary
    }

    /// Current decisions waiting for a human.
    pub fn pending_approvals(&self) -> Vec<ApprovalRequest> {
        self.ledger.pending()
    }

    /// Current status of the decision for an operation, when one exists.
    pub fn decision_status(&self, operation: OperationId) -> Option<DecisionStatus> {
        self.ledger.status(operation)
    }

    /// Evaluates one frozen operation.
    ///
    /// A frozen operation whose policy version is not the current version is
    /// rejected before any rule is consulted; it must be frozen again.
    pub fn evaluate(
        &mut self,
        policy: &PermissionPolicy,
        grant: &GrantScope,
        operation: &FrozenOperation,
        context: &EvaluationContext,
        evaluator: Option<&mut (dyn PermissionEvaluatorPort + Send + Sync + 'static)>,
    ) -> Result<PermissionOutcome, CoreError> {
        operation.arguments().validate()?;
        if operation.policy_version() != policy.version() {
            return Err(CoreError::StalePolicyVersion {
                frozen: operation.policy_version(),
                current: policy.version(),
            });
        }
        if grant.project_id() != operation.project_id() {
            return Err(CoreError::CrossProjectReference {
                id_kind: IdKind::Project,
                expected: operation.project_id(),
                found: grant.project_id(),
            });
        }
        if self.ledger.has_decision(operation.operation_id()) {
            return Err(CoreError::DuplicateOperation {
                operation: operation.operation_id(),
            });
        }

        let binding = DecisionBinding::from_operation(operation);

        if let Some(path) = self.boundary.violated_by(operation) {
            self.ledger.record_denied(operation.clone(), binding);
            return Ok(PermissionOutcome::Deny {
                reason: DenialReason::ProtectedBoundary { path },
            });
        }

        if let Some(rule) = policy.matching_rule(RuleEffect::Deny, operation) {
            self.ledger.record_denied(operation.clone(), binding);
            return Ok(PermissionOutcome::Deny {
                reason: DenialReason::ExplicitRule { rule: rule.clone() },
            });
        }

        if !grant.permits(operation) {
            self.ledger.record_denied(operation.clone(), binding);
            return Ok(PermissionOutcome::Deny {
                reason: DenialReason::GrantExceeded {
                    tool: operation.tool(),
                },
            });
        }
        if grant.mode() == PermissionMode::Configured
            && operation.permission_mode() == PermissionMode::Automatic
        {
            self.ledger.record_denied(operation.clone(), binding);
            return Ok(PermissionOutcome::Deny {
                reason: DenialReason::GrantExceeded {
                    tool: operation.tool(),
                },
            });
        }

        if let Some(rule) = policy.matching_rule(RuleEffect::Ask, operation) {
            let reason = HumanWaitReason::ExplicitRule { rule: rule.clone() };
            return Ok(self.record_pending(operation, binding, reason));
        }

        match policy.mode() {
            PermissionMode::Configured => {
                if policy.matching_rule(RuleEffect::Allow, operation).is_some() {
                    let authorization = self.ledger.record_approved(operation.clone(), binding);
                    Ok(PermissionOutcome::Allow { authorization })
                } else {
                    Ok(self.record_pending(
                        operation,
                        binding,
                        HumanWaitReason::NoMatchingAllowRule,
                    ))
                }
            }
            PermissionMode::Automatic => {
                self.evaluate_automatic(policy, grant, operation, context, binding, evaluator)
            }
        }
    }

    /// Approves a pending operation as a human action in `approver_project`.
    pub fn approve(
        &mut self,
        policy: &PermissionPolicy,
        operation: &FrozenOperation,
        approver_project: ProjectId,
    ) -> Result<Authorization, ApprovalError> {
        self.ledger.approve(policy, operation, approver_project)
    }

    /// Denies a pending operation as a human action.
    pub fn deny(
        &mut self,
        policy: &PermissionPolicy,
        operation: &FrozenOperation,
        approver_project: ProjectId,
    ) -> Result<(), ApprovalError> {
        self.ledger.deny(policy, operation, approver_project)
    }

    /// Re-checks and consumes an authorization immediately before execution.
    ///
    /// Consumption happens before the executor is called. If the executor then
    /// fails, the decision is not reusable; the operation must be evaluated
    /// again.
    pub fn confirm_before_execution(
        &mut self,
        policy: &PermissionPolicy,
        operation: &FrozenOperation,
        authorization: &Authorization,
    ) -> Result<(), ApprovalError> {
        self.ledger.confirm(policy, operation, authorization)
    }

    /// Invalidates pending and approved decisions for a resumed run.
    pub fn invalidate_run(&mut self, run: RunId) {
        self.ledger.invalidate_run(run);
    }

    fn evaluate_automatic(
        &mut self,
        policy: &PermissionPolicy,
        grant: &GrantScope,
        operation: &FrozenOperation,
        context: &EvaluationContext,
        binding: DecisionBinding,
        evaluator: Option<&mut (dyn PermissionEvaluatorPort + Send + Sync + 'static)>,
    ) -> Result<PermissionOutcome, CoreError> {
        let Some(evaluator) = evaluator else {
            return Ok(self.record_pending(
                operation,
                binding,
                HumanWaitReason::EvaluatorFailure {
                    failure: EvaluatorFailure::Unavailable,
                },
            ));
        };
        let capability = AutomaticModeCapability::from_availability(evaluator.availability());
        if !capability.usable() {
            return Ok(self.record_pending(
                operation,
                binding,
                HumanWaitReason::EvaluatorFailure {
                    failure: EvaluatorFailure::Unavailable,
                },
            ));
        }

        let boundary = boundary_summary(policy, grant);
        let request = EvaluationRequest::new(
            operation.clone(),
            context.requested_work().to_owned(),
            boundary,
            context.evidence().to_vec(),
        );

        match evaluator.evaluate(&request) {
            Ok(PermissionDecision::Allow) => {
                let authorization = self.ledger.record_approved(operation.clone(), binding);
                Ok(PermissionOutcome::Allow { authorization })
            }
            Ok(PermissionDecision::Deny) => {
                self.ledger.record_denied(operation.clone(), binding);
                Ok(PermissionOutcome::Deny {
                    reason: DenialReason::Evaluator,
                })
            }
            Ok(PermissionDecision::Ask) => {
                Ok(self.record_pending(operation, binding, HumanWaitReason::EvaluatorAsk))
            }
            Err(error) => {
                let failure = EvaluatorFailure::from_error(&error);
                Ok(self.record_pending(
                    operation,
                    binding,
                    HumanWaitReason::EvaluatorFailure { failure },
                ))
            }
        }
    }

    fn record_pending(
        &mut self,
        operation: &FrozenOperation,
        binding: DecisionBinding,
        reason: HumanWaitReason,
    ) -> PermissionOutcome {
        PermissionOutcome::AwaitingApproval {
            request: Box::new(
                self.ledger
                    .record_pending(operation.clone(), binding, reason),
            ),
        }
    }
}

/// Structured, non-secret summary given to the evaluator.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BoundarySummary<'a> {
    mode: crate::permissions::PermissionMode,
    policy_version: PolicyVersion,
    rules: &'a [PermissionRule],
    grant: &'a GrantScope,
}

fn boundary_summary(policy: &PermissionPolicy, grant: &GrantScope) -> String {
    serde_json::to_string(&BoundarySummary {
        mode: policy.mode(),
        policy_version: policy.version(),
        rules: policy.rules(),
        grant,
    })
    .unwrap_or_else(|_| "{\"unavailable\":true}".to_owned())
}
