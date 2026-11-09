//! Permission evaluator port.
//!
//! H2 injects a concrete evaluator. H1 defines only this boundary: automatic
//! mode is unavailable without an evaluator, and an evaluator failure results
//! in human confirmation rather than unconditional execution.

use std::sync::{Arc, Mutex};

use crate::contracts::errors::CoreError;
use crate::contracts::operation::FrozenOperation;
use crate::permissions::{EvaluatorAvailability, PermissionDecision};

/// Inputs supplied to a permission evaluator for one frozen operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationRequest {
    operation: FrozenOperation,
    requested_work: String,
    permission_boundary: String,
    evidence: Vec<String>,
}

impl EvaluationRequest {
    /// Creates an evaluation request.
    ///
    /// `requested_work`, `permission_boundary`, and `evidence` describe the
    /// task and policy context. Rationale text and file contents are evidence,
    /// never the authority that grants permission.
    pub fn new(
        operation: FrozenOperation,
        requested_work: impl Into<String>,
        permission_boundary: impl Into<String>,
        evidence: Vec<String>,
    ) -> Self {
        Self {
            operation,
            requested_work: requested_work.into(),
            permission_boundary: permission_boundary.into(),
            evidence,
        }
    }

    /// Frozen operation being evaluated.
    pub const fn operation(&self) -> &FrozenOperation {
        &self.operation
    }

    /// Human-requested work context.
    pub fn requested_work(&self) -> &str {
        &self.requested_work
    }

    /// Permission boundary summary.
    pub fn permission_boundary(&self) -> &str {
        &self.permission_boundary
    }

    /// Evidence supplied to the evaluator.
    pub fn evidence(&self) -> &[String] {
        &self.evidence
    }
}

/// Port implemented by the H2 permission evaluator.
pub trait PermissionEvaluatorPort {
    /// Reports whether automatic mode can currently use this evaluator.
    fn availability(&self) -> EvaluatorAvailability;

    /// Evaluates one operation. Errors must be treated as "do not run".
    fn evaluate(&mut self, request: &EvaluationRequest) -> Result<PermissionDecision, CoreError>;
}

/// One evaluator instance shared by the host runtime and every engine run.
///
/// The host creates the instance once and passes clones. The runtime and the
/// adapter therefore reach the same evaluator state instead of creating a
/// second evaluator or falling back to `None`.
#[derive(Clone)]
pub struct SharedPermissionEvaluator {
    inner: Arc<Mutex<Box<dyn PermissionEvaluatorPort + Send + Sync>>>,
}

impl SharedPermissionEvaluator {
    /// Wraps one host-selected evaluator.
    pub fn new(evaluator: Box<dyn PermissionEvaluatorPort + Send + Sync>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(evaluator)),
        }
    }
}

impl std::fmt::Debug for SharedPermissionEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedPermissionEvaluator")
    }
}

impl PermissionEvaluatorPort for SharedPermissionEvaluator {
    fn availability(&self) -> EvaluatorAvailability {
        // Never queue behind a long-running evaluation. A busy evaluator is
        // reported unavailable; automatic mode then waits for a human instead
        // of blocking a second tool or the host monitor.
        match self.inner.try_lock() {
            Ok(evaluator) => evaluator.availability(),
            Err(_) => EvaluatorAvailability::Unavailable,
        }
    }

    fn evaluate(&mut self, request: &EvaluationRequest) -> Result<PermissionDecision, CoreError> {
        // A bounded watcher may abandon a worker that still holds this lock.
        // Refuse a concurrent evaluation instead of waiting behind it; queuing
        // would reintroduce the unbounded wait the bounded wrapper prevents.
        let mut evaluator = match self.inner.try_lock() {
            Ok(evaluator) => evaluator,
            Err(_) => {
                return Err(CoreError::PermissionEvaluationFailed {
                    failure: crate::contracts::errors::EvaluationFailureKind::Unavailable,
                });
            }
        };
        evaluator.evaluate(request)
    }
}
