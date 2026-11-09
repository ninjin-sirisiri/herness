//! Verification evidence acquisition through the H1 permission boundary.
//!
//! The H2 service never executes a command or reads a file itself. A
//! [`VerificationBoundary`] owns the H1 evaluation and execution path;
//! [`GatewayVerification`] implements it with the real
//! [`herness_core::permissions::PermissionService`] behind
//! [`herness_core::tools::ToolGateway`]. A denied or human-waiting operation
//! produces no evidence, and an executed operation is recorded only after the
//! target manifest is checked before and after the run.

use herness_core::contracts::ProjectId;
use herness_core::contracts::operation::{FrozenOperation, OperationOutcome};
use herness_core::permissions::{
    ApprovalRequest, DenialReason, EvaluationContext, GrantScope, PermissionOutcome,
    PermissionPolicy,
};
use herness_core::ports::PermissionEvaluatorPort;
use herness_core::tools::{ToolArguments, ToolExecutor, ToolGateway};

use crate::error::SupervisionError;
use crate::evidence::{
    CheckStatus, EvidenceAcquirer, EvidenceOutcome, EvidenceRecord, EvidenceScope, TargetVersion,
    VerificationOperation,
};
use crate::freshness::{FreshnessService, TargetManifest, TargetReadSet, WorkspaceSnapshotPort};
use crate::ids::{CheckId, ConditionId, EvidenceId, SupervisionId};
use crate::ports::{ClockPort, EvidenceStorePort};

/// One planned verification observation.
#[derive(Debug, Clone)]
pub struct VerificationPlan {
    evidence_id: EvidenceId,
    supervision_id: SupervisionId,
    condition_id: Option<ConditionId>,
    check_id: Option<CheckId>,
    acquirer: EvidenceAcquirer,
    observer: Option<String>,
    operation: VerificationOperation,
    scope: EvidenceScope,
    sequence: u64,
    target_version: TargetVersion,
    read_set: TargetReadSet,
}

impl VerificationPlan {
    /// Creates a plan bound to one project, target version, and evidence ID.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: EvidenceId,
        supervision_id: SupervisionId,
        condition_id: Option<ConditionId>,
        check_id: Option<CheckId>,
        acquirer: EvidenceAcquirer,
        observer: Option<String>,
        operation: VerificationOperation,
        scope: EvidenceScope,
        sequence: u64,
        target_version: TargetVersion,
        read_set: TargetReadSet,
    ) -> Result<Self, SupervisionError> {
        let project = evidence_id.project_id();
        evidence_id.validate_in(project)?;
        supervision_id.validate_in(project)?;
        if let Some(condition_id) = condition_id {
            condition_id.validate_in(project)?;
        }
        if let Some(check_id) = check_id {
            check_id.validate_in(project)?;
        }
        if sequence == 0 {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "evidence.sequence".to_owned(),
                detail: "evidence sequence starts at 1".to_owned(),
            });
        }
        let observer = validate_observer(acquirer, observer)?;
        Ok(Self {
            evidence_id,
            supervision_id,
            condition_id,
            check_id,
            acquirer,
            observer,
            operation,
            scope,
            sequence,
            target_version,
            read_set,
        })
    }

    /// Project that owns the plan.
    pub const fn project_id(&self) -> ProjectId {
        self.evidence_id.project_id()
    }

    /// Evidence identifier to write.
    pub const fn evidence_id(&self) -> EvidenceId {
        self.evidence_id
    }

    /// Supervision target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Required check answered, if any.
    pub const fn check_id(&self) -> Option<CheckId> {
        self.check_id
    }

    /// Who is acquiring the evidence.
    pub const fn acquirer(&self) -> EvidenceAcquirer {
        self.acquirer
    }

    /// Exact command or equivalent operation.
    pub fn operation(&self) -> &VerificationOperation {
        &self.operation
    }

    /// Recorded target version.
    pub const fn target_version(&self) -> TargetVersion {
        self.target_version
    }
}

/// Result produced by an H1-authorized verification executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationExecution {
    outcome: EvidenceOutcome,
    status: CheckStatus,
    operation_outcome: Option<OperationOutcome>,
}

impl VerificationExecution {
    /// Creates a command result. A pass requires exit code 0, no signal, no
    /// timeout, and no truncation.
    pub fn new(
        status: CheckStatus,
        exit_code: Option<i32>,
        signal: Option<i32>,
        timed_out: bool,
        truncated: bool,
        detail: impl AsRef<str>,
    ) -> Result<Self, SupervisionError> {
        let outcome = EvidenceOutcome::new(exit_code, signal, timed_out, truncated, detail)?;
        let execution = Self {
            outcome,
            status,
            operation_outcome: None,
        };
        validate_command_result(&execution.outcome, execution.status)?;
        Ok(execution)
    }

    /// Creates an equivalent-operation observation, such as a read or human
    /// inspection, where an exit code does not apply.
    pub fn observed(
        status: CheckStatus,
        detail: impl AsRef<str>,
    ) -> Result<Self, SupervisionError> {
        let outcome = EvidenceOutcome::new(None, None, false, false, detail)?;
        if status == CheckStatus::Pass && is_bare_success(outcome.detail()) {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "outcome.detail".to_owned(),
                detail: "a bare success word is not a verification result".to_owned(),
            });
        }
        Ok(Self {
            outcome,
            status,
            operation_outcome: None,
        })
    }

    /// Attaches the H1 operation outcome. An applied operation is still not a
    /// passing check by itself.
    pub fn with_operation_outcome(
        mut self,
        operation_outcome: OperationOutcome,
    ) -> Result<Self, SupervisionError> {
        if operation_outcome == OperationOutcome::Applied
            && !has_explicit_check_result(&self.outcome)
        {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "operationOutcome".to_owned(),
                detail: "an applied H1 operation is not a verification result".to_owned(),
            });
        }
        self.operation_outcome = Some(operation_outcome);
        Ok(self)
    }

    /// Actual observed result.
    pub fn outcome(&self) -> &EvidenceOutcome {
        &self.outcome
    }

    /// Explicit check status.
    pub const fn status(&self) -> CheckStatus {
        self.status
    }

    /// H1 operation outcome, when an operation was involved.
    pub const fn operation_outcome(&self) -> Option<OperationOutcome> {
        self.operation_outcome
    }
}

/// Outcome of one H1-authorized boundary call.
#[derive(Debug)]
pub enum VerificationBoundaryOutcome {
    /// The operation ran; the executor reports the observed result.
    Executed(VerificationExecution),
    /// H1 permission denied the operation.
    Denied {
        /// H1 denial reason.
        reason: DenialReason,
    },
    /// H1 permission requires a human decision.
    AwaitingHuman {
        /// Pending approval request.
        request: Box<ApprovalRequest>,
    },
    /// The boundary could not execute the operation.
    Failed {
        /// Sanitized failure description.
        detail: String,
    },
}

/// H1-owned authorization and execution boundary.
pub trait VerificationBoundary {
    /// Evaluates and, only if allowed, executes one frozen operation.
    fn run(
        &mut self,
        operation: &FrozenOperation,
    ) -> Result<VerificationBoundaryOutcome, SupervisionError>;
}

/// H1 gateway-backed verification boundary.
///
/// The gateway owns the real permission service and the injected executor. The
/// H2 service never calls the executor directly.
pub struct GatewayVerification<E> {
    gateway: ToolGateway<E>,
    policy: PermissionPolicy,
    grant: GrantScope,
    context: EvaluationContext,
}

impl<E> GatewayVerification<E> {
    /// Creates a boundary over an existing H1 gateway and its policy/grant.
    pub fn new(
        gateway: ToolGateway<E>,
        policy: PermissionPolicy,
        grant: GrantScope,
        context: EvaluationContext,
    ) -> Self {
        Self {
            gateway,
            policy,
            grant,
            context,
        }
    }

    /// H1 gateway, including the real permission service and executor.
    pub const fn gateway(&self) -> &ToolGateway<E> {
        &self.gateway
    }

    /// Mutable H1 gateway for host-only configuration and assertions.
    pub const fn gateway_mut(&mut self) -> &mut ToolGateway<E> {
        &mut self.gateway
    }

    /// Policy used for evaluation.
    pub const fn policy(&self) -> &PermissionPolicy {
        &self.policy
    }

    /// Grant ceiling used for evaluation.
    pub const fn grant(&self) -> &GrantScope {
        &self.grant
    }
}

impl<E: ToolExecutor<Output = VerificationExecution>> GatewayVerification<E> {
    /// Runs one operation with an optional H1 evaluator for automatic mode.
    ///
    /// Configured mode does not need an evaluator. Automatic mode without one
    /// waits for a human instead of allowing the operation.
    pub fn run_with_evaluator(
        &mut self,
        operation: &FrozenOperation,
        evaluator: Option<&mut (dyn PermissionEvaluatorPort + Send + Sync)>,
    ) -> Result<VerificationBoundaryOutcome, SupervisionError> {
        let outcome = self
            .gateway
            .authorize(
                &self.policy,
                &self.grant,
                operation,
                &self.context,
                evaluator,
            )
            .map_err(|error| SupervisionError::InvalidValue {
                field: "verification.permission".to_owned(),
                detail: error.to_string(),
            })?;
        match outcome {
            PermissionOutcome::Allow { authorization } => {
                match self
                    .gateway
                    .execute(&self.policy, operation, &authorization)
                {
                    Ok(execution) => Ok(VerificationBoundaryOutcome::Executed(execution)),
                    Err(error) => Ok(VerificationBoundaryOutcome::Failed {
                        detail: error.to_string(),
                    }),
                }
            }
            PermissionOutcome::Deny { reason } => {
                Ok(VerificationBoundaryOutcome::Denied { reason })
            }
            PermissionOutcome::AwaitingApproval { request } => {
                Ok(VerificationBoundaryOutcome::AwaitingHuman { request })
            }
        }
    }
}

impl<E: ToolExecutor<Output = VerificationExecution>> VerificationBoundary
    for GatewayVerification<E>
{
    fn run(
        &mut self,
        operation: &FrozenOperation,
    ) -> Result<VerificationBoundaryOutcome, SupervisionError> {
        self.run_with_evaluator(operation, None)
    }
}

/// Result of one verification attempt.
#[derive(Debug)]
pub enum VerificationDisposition {
    /// Validated evidence was stored.
    Recorded(Box<EvidenceRecord>),
    /// H1 denied the operation; nothing was stored.
    Denied {
        /// H1 denial reason.
        reason: DenialReason,
    },
    /// A human must decide before anything is stored.
    AwaitingHuman {
        /// Pending H1 approval request.
        request: Box<ApprovalRequest>,
    },
    /// The operation failed before a trustworthy result was observed.
    Failed {
        /// Sanitized failure description.
        detail: String,
    },
}

impl VerificationDisposition {
    /// Stored evidence, when the operation was recorded.
    pub fn recorded(&self) -> Option<&EvidenceRecord> {
        match self {
            Self::Recorded(record) => Some(record.as_ref()),
            _ => None,
        }
    }

    /// Whether the attempt produced a passing check.
    pub fn passing_evidence(&self) -> Option<&EvidenceRecord> {
        self.recorded().filter(|record| record.status().is_pass())
    }
}

/// Verification acquisition over a freshness service.
#[derive(Debug, Clone)]
pub struct VerificationService<W, C> {
    freshness: FreshnessService<W, C>,
}

impl<W: WorkspaceSnapshotPort, C: ClockPort> VerificationService<W, C> {
    /// Creates a service with an injected workspace reader and clock.
    pub const fn new(workspace: W, clock: C) -> Self {
        Self {
            freshness: FreshnessService::new(workspace, clock),
        }
    }

    /// Freshness service used for manifests and reuse.
    pub const fn freshness(&self) -> &FreshnessService<W, C> {
        &self.freshness
    }

    /// Captures the current target manifest.
    pub fn capture(
        &self,
        project_id: ProjectId,
        version: TargetVersion,
        read_set: TargetReadSet,
    ) -> Result<TargetManifest, SupervisionError> {
        self.freshness.capture(project_id, version, read_set)
    }

    /// Captures a whole-project manifest when the owner scope is unknown.
    pub fn widen(
        &self,
        project_id: ProjectId,
        version: TargetVersion,
    ) -> Result<TargetManifest, SupervisionError> {
        self.freshness.widen(project_id, version)
    }

    /// Runs one verification plan through the H1 boundary and stores validated
    /// evidence.
    ///
    /// The manifest is captured before and after execution. If content changed
    /// during the run, a claimed pass is downgraded to inconclusive; it is
    /// never stored as a pass.
    pub fn verify(
        &self,
        store: &mut dyn EvidenceStorePort,
        plan: VerificationPlan,
        operation: &FrozenOperation,
        boundary: &mut dyn VerificationBoundary,
    ) -> Result<VerificationDisposition, SupervisionError> {
        if operation.project_id() != plan.project_id() {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "verification operation".to_owned(),
                expected: plan.project_id(),
                found: operation.project_id(),
            });
        }
        verify_operation_matches(operation, &plan.operation)?;

        let before = self.freshness.capture(
            plan.project_id(),
            plan.target_version,
            plan.read_set.clone(),
        )?;
        let execution = match boundary.run(operation)? {
            VerificationBoundaryOutcome::Executed(execution) => execution,
            VerificationBoundaryOutcome::Denied { reason } => {
                return Ok(VerificationDisposition::Denied { reason });
            }
            VerificationBoundaryOutcome::AwaitingHuman { request } => {
                return Ok(VerificationDisposition::AwaitingHuman { request });
            }
            VerificationBoundaryOutcome::Failed { detail } => {
                return Ok(VerificationDisposition::Failed { detail });
            }
        };

        let after = self.freshness.capture(
            plan.project_id(),
            plan.target_version,
            plan.read_set.clone(),
        )?;
        let changed_during_run = before.manifest_digest()? != after.manifest_digest()?;
        let status = if changed_during_run && execution.status == CheckStatus::Pass {
            CheckStatus::Inconclusive
        } else {
            execution.status
        };

        let mut record = EvidenceRecord::new(
            plan.evidence_id,
            plan.supervision_id,
            plan.condition_id,
            plan.check_id,
            plan.acquirer,
            plan.operation,
            execution.outcome,
            before.target_scope()?,
            plan.scope,
            status,
            plan.sequence,
            self.freshness.now(),
        )?;
        if let Some(observer) = plan.observer {
            record = record.with_observer(observer);
        }
        validate_evidence_record(&record, execution.operation_outcome)?;
        let stored = store.append(record)?;
        Ok(VerificationDisposition::Recorded(Box::new(stored)))
    }

    /// Validates and stores evidence acquired outside this process, such as a
    /// child-agent, CI, or human observation. The same five-item rules apply.
    pub fn store_reused(
        &self,
        store: &mut dyn EvidenceStorePort,
        record: EvidenceRecord,
    ) -> Result<EvidenceRecord, SupervisionError> {
        validate_evidence_record(&record, None)?;
        store.append(record)
    }
}

/// Validates the five-item record before storage.
///
/// This rejects bare `DONE`/success prose, a command with no actual result, a
/// pass with a non-zero exit, signal, timeout, or truncation, and an
/// `OperationOutcome::Applied` claim that has no explicit check result.
pub fn validate_evidence_record(
    record: &EvidenceRecord,
    operation_outcome: Option<OperationOutcome>,
) -> Result<(), SupervisionError> {
    record.target().ensure_project(record.project_id())?;

    match record.acquirer() {
        EvidenceAcquirer::Human => {
            validate_observer(
                EvidenceAcquirer::Human,
                record.observer().map(str::to_owned),
            )?;
        }
        EvidenceAcquirer::ChildAgent | EvidenceAcquirer::Ci => {}
    }

    if is_bare_success(record.operation().as_str()) {
        return Err(SupervisionError::EvidenceContractViolation {
            field: "operation".to_owned(),
            detail: "a bare success word is not a verification operation".to_owned(),
        });
    }
    if is_bare_success(record.outcome().detail()) {
        return Err(SupervisionError::EvidenceContractViolation {
            field: "outcome.detail".to_owned(),
            detail: "a bare success word is not an observed result".to_owned(),
        });
    }
    if record.scope().included().is_empty() {
        return Err(SupervisionError::EvidenceContractViolation {
            field: "scope.included".to_owned(),
            detail: "a verification scope is required".to_owned(),
        });
    }

    if matches!(record.operation(), VerificationOperation::Command { .. }) {
        if !has_explicit_check_result(record.outcome()) {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "outcome".to_owned(),
                detail: "an exact command requires an exit code, signal, or timeout result"
                    .to_owned(),
            });
        }
        validate_command_result(record.outcome(), record.status())?;
    }

    if record.status() == CheckStatus::Pass {
        if record.check_id().is_none() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "evidence.checkId".to_owned(),
                detail: "passing evidence must name the required check".to_owned(),
            });
        }
        if record.condition_id().is_none() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "evidence.conditionId".to_owned(),
                detail: "passing evidence must name the condition".to_owned(),
            });
        }
    }

    if operation_outcome == Some(OperationOutcome::Applied) {
        if !has_explicit_check_result(record.outcome())
            && !(record.acquirer() == EvidenceAcquirer::Human && record.observer().is_some())
        {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "operationOutcome".to_owned(),
                detail: "an applied H1 operation is not a verification result".to_owned(),
            });
        }
        if record.status() == CheckStatus::Pass && record.check_id().is_none() {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "evidence.checkId".to_owned(),
                detail: "an applied operation cannot pass without explicit check evidence"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_command_result(
    outcome: &EvidenceOutcome,
    status: CheckStatus,
) -> Result<(), SupervisionError> {
    if status == CheckStatus::Pass
        && (outcome.exit_code() != Some(0)
            || outcome.signal().is_some()
            || outcome.timed_out()
            || outcome.truncated())
    {
        return Err(SupervisionError::EvidenceContractViolation {
            field: "status".to_owned(),
            detail: "pass requires exit code 0 with no signal, timeout, or truncation".to_owned(),
        });
    }
    Ok(())
}

fn validate_observer(
    acquirer: EvidenceAcquirer,
    observer: Option<String>,
) -> Result<Option<String>, SupervisionError> {
    match acquirer {
        EvidenceAcquirer::Human => {
            let observer = observer
                .as_deref()
                .map(str::trim)
                .filter(|observer| !observer.is_empty())
                .ok_or(SupervisionError::EvidenceContractViolation {
                    field: "evidence.observer".to_owned(),
                    detail: "human evidence must name the observer".to_owned(),
                })?;
            if observer.chars().count() > 256 {
                return Err(SupervisionError::EvidenceContractViolation {
                    field: "evidence.observer".to_owned(),
                    detail: "the observer must contain at most 256 characters".to_owned(),
                });
            }
            Ok(Some(observer.to_owned()))
        }
        EvidenceAcquirer::ChildAgent | EvidenceAcquirer::Ci => Ok(observer),
    }
}

fn has_explicit_check_result(outcome: &EvidenceOutcome) -> bool {
    outcome.exit_code().is_some() || outcome.signal().is_some() || outcome.timed_out()
}

fn is_bare_success(value: &str) -> bool {
    let normalized = value
        .trim()
        .trim_end_matches(['.', '!', '。', '、'])
        .trim()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "done"
            | "success"
            | "successful"
            | "succeeded"
            | "passed"
            | "pass"
            | "ok"
            | "okay"
            | "完了"
            | "成功"
            | "できました"
    )
}

fn verify_operation_matches(
    operation: &FrozenOperation,
    recorded: &VerificationOperation,
) -> Result<(), SupervisionError> {
    match operation.arguments() {
        ToolArguments::Bash(args) => match recorded {
            VerificationOperation::Command { command } if command == args.command.as_str() => {
                Ok(())
            }
            _ => Err(SupervisionError::EvidenceContractViolation {
                field: "operation.command".to_owned(),
                detail: "the recorded command must exactly match the frozen bash operation"
                    .to_owned(),
            }),
        },
        _ => match recorded {
            VerificationOperation::Equivalent { operation } if !operation.trim().is_empty() => {
                Ok(())
            }
            _ => Err(SupervisionError::EvidenceContractViolation {
                field: "operation.equivalent".to_owned(),
                detail: "non-shell verification must name its equivalent operation".to_owned(),
            }),
        },
    }
}

impl<E> std::fmt::Debug for GatewayVerification<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayVerification")
            .field("policy", &self.policy.version())
            .field("mode", &self.policy.mode())
            .field("grant", &self.grant)
            .finish_non_exhaustive()
    }
}
