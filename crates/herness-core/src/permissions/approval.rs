//! Human approvals, their bindings, and single-use authorization tokens.
//!
//! An [`ApprovalRequest`] is created when evaluation ends in human wait. It
//! records the exact frozen operation and the reason. Approving it produces a
//! single-use [`Authorization`]. The gateway re-checks the binding immediately
//! before execution and consumes the authorization only then.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use crate::contracts::ids::{OperationId, ProjectId, RunId};
use crate::contracts::operation::FrozenOperation;
use crate::permissions::service::HumanWaitReason;
use crate::permissions::{DecisionBinding, DecisionStatus, InvalidationReason, PermissionPolicy};

/// A structured request for a human permission decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    operation: FrozenOperation,
    binding: DecisionBinding,
    reason: HumanWaitReason,
}

impl ApprovalRequest {
    /// Frozen operation the human is asked about.
    pub const fn operation(&self) -> &FrozenOperation {
        &self.operation
    }

    /// Binding captured when the request was created.
    pub const fn binding(&self) -> &DecisionBinding {
        &self.binding
    }

    /// Why human confirmation is needed.
    pub const fn reason(&self) -> &HumanWaitReason {
        &self.reason
    }

    /// Operation identifier the human must approve.
    pub fn operation_id(&self) -> OperationId {
        self.operation.operation_id()
    }

    /// Project the operation belongs to.
    pub fn project_id(&self) -> ProjectId {
        self.operation.project_id()
    }
}

/// A single-use authorization returned by evaluation or human approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    binding: DecisionBinding,
    generation: u64,
}

impl Authorization {
    /// Decision binding the authorization covers.
    pub const fn binding(&self) -> &DecisionBinding {
        &self.binding
    }

    /// Operation the authorization covers.
    pub fn operation_id(&self) -> OperationId {
        self.binding.operation_id()
    }

    /// Project the authorization covers.
    pub fn project_id(&self) -> ProjectId {
        self.binding.project_id()
    }
}

/// Reason an approval or authorization could not be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ApprovalError {
    /// No decision exists for the operation.
    UnknownOperation {
        /// Operation that was not found.
        operation: OperationId,
    },
    /// The caller tried to decide an operation from another project.
    CrossProject {
        /// Project owning the operation.
        expected: ProjectId,
        /// Project supplied by the caller.
        found: ProjectId,
    },
    /// The decision is already approved, denied, consumed, or invalidated.
    AlreadyResolved {
        /// Operation that has no pending decision.
        operation: OperationId,
        /// Current decision status.
        status: DecisionStatus,
    },
    /// The decision was invalidated and must be evaluated again.
    Invalidated {
        /// Invalidated operation.
        operation: OperationId,
        /// Why it was invalidated.
        reason: InvalidationReason,
    },
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOperation { operation } => {
                write!(f, "no permission decision exists for operation {operation}")
            }
            Self::CrossProject { expected, found } => write!(
                f,
                "operation belongs to project {expected}, not the approving project {found}"
            ),
            Self::AlreadyResolved { operation, status } => {
                write!(f, "operation {operation} is already {status}")
            }
            Self::Invalidated { operation, reason } => {
                write!(f, "approval for operation {operation} is invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for ApprovalError {}

#[derive(Debug)]
pub(crate) struct DecisionRecord {
    operation: FrozenOperation,
    binding: DecisionBinding,
    status: DecisionStatus,
    generation: u64,
    reason: Option<HumanWaitReason>,
    invalidation: Option<InvalidationReason>,
}

#[derive(Debug, Default)]
pub(crate) struct ApprovalLedger {
    decisions: BTreeMap<OperationId, DecisionRecord>,
    next_generation: u64,
}

impl ApprovalLedger {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn status(&self, operation: OperationId) -> Option<DecisionStatus> {
        self.decisions.get(&operation).map(|record| record.status)
    }

    pub(crate) fn has_decision(&self, operation: OperationId) -> bool {
        self.decisions.contains_key(&operation)
    }

    pub(crate) fn record_pending(
        &mut self,
        operation: FrozenOperation,
        binding: DecisionBinding,
        reason: HumanWaitReason,
    ) -> ApprovalRequest {
        let generation = self.next_generation();
        let record = DecisionRecord {
            operation: operation.clone(),
            binding: binding.clone(),
            status: DecisionStatus::AwaitingHuman,
            generation,
            reason: Some(reason.clone()),
            invalidation: None,
        };
        self.decisions.insert(operation.operation_id(), record);
        ApprovalRequest {
            operation,
            binding,
            reason,
        }
    }

    pub(crate) fn record_approved(
        &mut self,
        operation: FrozenOperation,
        binding: DecisionBinding,
    ) -> Authorization {
        let generation = self.next_generation();
        let record = DecisionRecord {
            operation,
            binding: binding.clone(),
            status: DecisionStatus::Approved,
            generation,
            reason: None,
            invalidation: None,
        };
        self.decisions.insert(binding.operation_id(), record);
        Authorization {
            binding,
            generation,
        }
    }

    pub(crate) fn record_denied(&mut self, operation: FrozenOperation, binding: DecisionBinding) {
        let generation = self.next_generation();
        let record = DecisionRecord {
            operation,
            binding,
            status: DecisionStatus::Denied,
            generation,
            reason: None,
            invalidation: None,
        };
        self.decisions.insert(record.binding.operation_id(), record);
    }

    pub(crate) fn approve(
        &mut self,
        policy: &PermissionPolicy,
        operation: &FrozenOperation,
        approver_project: ProjectId,
    ) -> Result<Authorization, ApprovalError> {
        let operation_id = operation.operation_id();
        if approver_project != operation.project_id() {
            return Err(ApprovalError::CrossProject {
                expected: operation.project_id(),
                found: approver_project,
            });
        }
        let Some(record) = self.decisions.get_mut(&operation_id) else {
            return Err(ApprovalError::UnknownOperation {
                operation: operation_id,
            });
        };
        match record.status {
            DecisionStatus::AwaitingHuman => {}
            DecisionStatus::Invalidated => {
                return Err(ApprovalError::Invalidated {
                    operation: operation_id,
                    reason: record
                        .invalidation
                        .clone()
                        .unwrap_or(InvalidationReason::Superseded),
                });
            }
            status => {
                return Err(ApprovalError::AlreadyResolved {
                    operation: operation_id,
                    status,
                });
            }
        }
        if let Err(reason) = record.binding.check(operation, policy) {
            record.status = DecisionStatus::Invalidated;
            record.invalidation = Some(reason.clone());
            return Err(ApprovalError::Invalidated {
                operation: operation_id,
                reason,
            });
        }
        record.status = DecisionStatus::Approved;
        record.reason = None;
        Ok(Authorization {
            binding: record.binding.clone(),
            generation: record.generation,
        })
    }

    pub(crate) fn deny(
        &mut self,
        policy: &PermissionPolicy,
        operation: &FrozenOperation,
        approver_project: ProjectId,
    ) -> Result<(), ApprovalError> {
        let operation_id = operation.operation_id();
        if approver_project != operation.project_id() {
            return Err(ApprovalError::CrossProject {
                expected: operation.project_id(),
                found: approver_project,
            });
        }
        let Some(record) = self.decisions.get_mut(&operation_id) else {
            return Err(ApprovalError::UnknownOperation {
                operation: operation_id,
            });
        };
        match record.status {
            DecisionStatus::AwaitingHuman => {}
            DecisionStatus::Invalidated => {
                return Err(ApprovalError::Invalidated {
                    operation: operation_id,
                    reason: record
                        .invalidation
                        .clone()
                        .unwrap_or(InvalidationReason::Superseded),
                });
            }
            status => {
                return Err(ApprovalError::AlreadyResolved {
                    operation: operation_id,
                    status,
                });
            }
        }
        if let Err(reason) = record.binding.check(operation, policy) {
            record.status = DecisionStatus::Invalidated;
            record.invalidation = Some(reason.clone());
            return Err(ApprovalError::Invalidated {
                operation: operation_id,
                reason,
            });
        }
        record.status = DecisionStatus::Denied;
        record.reason = None;
        Ok(())
    }

    pub(crate) fn confirm(
        &mut self,
        policy: &PermissionPolicy,
        operation: &FrozenOperation,
        authorization: &Authorization,
    ) -> Result<(), ApprovalError> {
        let operation_id = operation.operation_id();
        if authorization.binding().operation_id() != operation_id {
            return Err(ApprovalError::Invalidated {
                operation: operation_id,
                reason: InvalidationReason::Superseded,
            });
        }
        let Some(record) = self.decisions.get_mut(&operation_id) else {
            return Err(ApprovalError::UnknownOperation {
                operation: operation_id,
            });
        };
        if record.generation != authorization.generation || record.binding != authorization.binding
        {
            record.status = DecisionStatus::Invalidated;
            record.invalidation = Some(InvalidationReason::Superseded);
            return Err(ApprovalError::Invalidated {
                operation: operation_id,
                reason: InvalidationReason::Superseded,
            });
        }
        match record.status {
            DecisionStatus::Approved => {}
            DecisionStatus::Invalidated => {
                return Err(ApprovalError::Invalidated {
                    operation: operation_id,
                    reason: record
                        .invalidation
                        .clone()
                        .unwrap_or(InvalidationReason::Superseded),
                });
            }
            status => {
                return Err(ApprovalError::AlreadyResolved {
                    operation: operation_id,
                    status,
                });
            }
        }
        if let Err(reason) = record.binding.check(operation, policy) {
            record.status = DecisionStatus::Invalidated;
            record.invalidation = Some(reason.clone());
            return Err(ApprovalError::Invalidated {
                operation: operation_id,
                reason,
            });
        }
        record.status = DecisionStatus::Consumed;
        Ok(())
    }

    pub(crate) fn invalidate_run(&mut self, run: RunId) {
        for record in self.decisions.values_mut() {
            if record.binding.run_id() == run
                && matches!(
                    record.status,
                    DecisionStatus::AwaitingHuman | DecisionStatus::Approved
                )
            {
                record.status = DecisionStatus::Invalidated;
                record.invalidation = Some(InvalidationReason::RunResumed);
            }
        }
    }

    pub(crate) fn pending(&self) -> Vec<ApprovalRequest> {
        self.decisions
            .values()
            .filter_map(|record| match (&record.reason, record.status) {
                (Some(reason), DecisionStatus::AwaitingHuman) => Some(ApprovalRequest {
                    operation: record.operation.clone(),
                    binding: record.binding.clone(),
                    reason: reason.clone(),
                }),
                _ => None,
            })
            .collect()
    }

    fn next_generation(&mut self) -> u64 {
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        self.next_generation
    }
}
