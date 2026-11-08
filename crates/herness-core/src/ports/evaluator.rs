//! Permission evaluator port.
//!
//! H2 injects a concrete evaluator. H1 defines only this boundary: automatic
//! mode is unavailable without an evaluator, and an evaluator failure results
//! in human confirmation rather than unconditional execution.

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
