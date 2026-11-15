//! Additional durable H4 records beyond the core execution port.
//!
//! [`ExecutionStorePort`](crate::ports::ExecutionStorePort) owns snapshots,
//! request journals, and control results. H4 also persists four supporting
//! records that later Tasks (coordinator, Git, recovery, desktop) read back:
//!
//! - immutable approval revisions (with their plan revision),
//! - the Task-to-H2/child reservation created by one dispatch request,
//! - the immutable dispatch manifest that fixes the packet and scope digests,
//! - budget increments that add consumed or reserved amounts.
//!
//! These are additive to Task 4's names. They add no new execution state and
//! never replace a snapshot: an increment is an audit row that must be summed by
//! the caller, and a reservation is only the record that one request created one
//! H2 target. Neither is Task completion.

use herness_core::contracts::ProjectId;
use herness_supervision::{Money, SupervisionId};
use serde::{Deserialize, Serialize};

use crate::approval::ExecutionApproval;
use crate::error::SddExecutionError;
use crate::ids::{
    ApprovalId, Baseline, ChildIdentity, DispatchRequestId, ExecutionId, ExecutionRevision,
    PlanRevision, TaskRef,
};
use crate::version::Sha256Digest;

/// One durable Task-to-supervision reservation.
///
/// Exactly one reservation exists per `(execution, request)` and per
/// `(execution, Task)`. A re-delivered dispatch request reads the stored
/// reservation instead of creating a second H2 target or child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskReservation {
    project_id: ProjectId,
    execution_id: ExecutionId,
    task: TaskRef,
    request_id: DispatchRequestId,
    supervision_id: SupervisionId,
    child: ChildIdentity,
}

impl TaskReservation {
    /// Creates a reservation and validates every project binding.
    pub fn new(
        execution_id: ExecutionId,
        task: TaskRef,
        request_id: DispatchRequestId,
        supervision_id: SupervisionId,
        child: ChildIdentity,
    ) -> Result<Self, SddExecutionError> {
        let project_id = execution_id.project_id();
        execution_id.validate_in(project_id)?;
        task.ensure_project(project_id)?;
        request_id.validate_in(project_id)?;
        if supervision_id.project_id() != project_id {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "reserved H2 supervision".to_owned(),
                expected: project_id,
                found: supervision_id.project_id(),
            });
        }
        child.ensure_project(project_id)?;
        Ok(Self {
            project_id,
            execution_id,
            task,
            request_id,
            supervision_id,
            child,
        })
    }

    /// Project that owns the reservation.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Reserved Task.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Dispatch request that created the reservation.
    pub const fn request_id(&self) -> DispatchRequestId {
        self.request_id
    }

    /// Created H2 target.
    pub const fn supervision_id(&self) -> SupervisionId {
        self.supervision_id
    }

    /// Created H1 child.
    pub const fn child(&self) -> ChildIdentity {
        self.child
    }
}

/// The immutable packet and scope manifest bound to one dispatch request.
///
/// The manifest fixes the exact approved plan revision, baseline, and digests so
/// a crash recovery can re-check the child without re-deriving a manifest from a
/// changed plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchManifest {
    project_id: ProjectId,
    execution_id: ExecutionId,
    request_id: DispatchRequestId,
    task: TaskRef,
    approved_plan_revision: PlanRevision,
    baseline: Baseline,
    manifest_digest: Sha256Digest,
    packet_digest: Sha256Digest,
}

impl DispatchManifest {
    /// Creates a manifest and validates every project binding.
    pub fn new(
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
        task: TaskRef,
        approved_plan_revision: PlanRevision,
        baseline: Baseline,
        manifest_digest: Sha256Digest,
        packet_digest: Sha256Digest,
    ) -> Result<Self, SddExecutionError> {
        let project_id = execution_id.project_id();
        request_id.validate_in(project_id)?;
        task.ensure_project(project_id)?;
        Ok(Self {
            project_id,
            execution_id,
            request_id,
            task,
            approved_plan_revision,
            baseline,
            manifest_digest,
            packet_digest,
        })
    }

    /// Project that owns the manifest.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Dispatch request the manifest belongs to.
    pub const fn request_id(&self) -> DispatchRequestId {
        self.request_id
    }

    /// Task the manifest describes.
    pub const fn task(&self) -> TaskRef {
        self.task
    }

    /// Approved plan revision the packet was built from.
    pub const fn approved_plan_revision(&self) -> PlanRevision {
        self.approved_plan_revision
    }

    /// Fixed baseline the packet was built from.
    pub const fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// Digest of the exact read/scope manifest.
    pub const fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    /// Digest of the immutable Task packet.
    pub const fn packet_digest(&self) -> &Sha256Digest {
        &self.packet_digest
    }
}

/// One additive budget increment for an execution revision.
///
/// Increments are append-only audit rows keyed by the revision they belong to.
/// A caller sums them; H4 never zeroes a consumed or reserved amount on resume
/// or re-approval, and this record cannot express a decrease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BudgetIncrement {
    project_id: ProjectId,
    execution_id: ExecutionId,
    revision: ExecutionRevision,
    consumed_seconds_delta: u64,
    additional_runs_delta: u32,
    #[serde(default)]
    money_delta: Option<Money>,
    reserved_seconds_delta: u64,
    reserved_additional_runs_delta: u32,
    #[serde(default)]
    reserved_money_delta: Option<Money>,
}

impl BudgetIncrement {
    /// Creates an increment for one revision. Negative amounts cannot be built.
    pub const fn new(
        project_id: ProjectId,
        execution_id: ExecutionId,
        revision: ExecutionRevision,
        consumed_seconds_delta: u64,
        additional_runs_delta: u32,
        money_delta: Option<Money>,
    ) -> Self {
        Self {
            project_id,
            execution_id,
            revision,
            consumed_seconds_delta,
            additional_runs_delta,
            money_delta,
            reserved_seconds_delta: 0,
            reserved_additional_runs_delta: 0,
            reserved_money_delta: None,
        }
    }

    /// Adds a reservation released by the same revision.
    pub const fn with_reserved(
        mut self,
        reserved_seconds: u64,
        reserved_additional_runs: u32,
        reserved_money: Option<Money>,
    ) -> Self {
        self.reserved_seconds_delta = reserved_seconds;
        self.reserved_additional_runs_delta = reserved_additional_runs;
        self.reserved_money_delta = reserved_money;
        self
    }

    /// Rejects an increment whose execution belongs to another project.
    pub fn validate(&self) -> Result<(), SddExecutionError> {
        self.execution_id.validate_in(self.project_id)
    }

    /// Project that owns the increment.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Revision the increment belongs to.
    pub const fn revision(&self) -> ExecutionRevision {
        self.revision
    }

    /// Consumed seconds added.
    pub const fn consumed_seconds_delta(&self) -> u64 {
        self.consumed_seconds_delta
    }

    /// Additional runs added.
    pub const fn additional_runs_delta(&self) -> u32 {
        self.additional_runs_delta
    }

    /// Money added, when a finite cap is configured.
    pub const fn money_delta(&self) -> Option<Money> {
        self.money_delta
    }

    /// Reserved seconds added.
    pub const fn reserved_seconds_delta(&self) -> u64 {
        self.reserved_seconds_delta
    }

    /// Reserved additional runs added.
    pub const fn reserved_additional_runs_delta(&self) -> u32 {
        self.reserved_additional_runs_delta
    }

    /// Reserved money added.
    pub const fn reserved_money_delta(&self) -> Option<Money> {
        self.reserved_money_delta
    }
}

/// Durable supporting records for H4.
///
/// Every method is an exactly-once write keyed by its natural identity. A
/// re-delivered identical value is a no-op that returns the stored value; the
/// same key with different content is refused before any write.
pub trait DurableExecutionStorePort {
    /// Records one immutable approval revision.
    fn record_approval(&mut self, approval: &ExecutionApproval) -> Result<(), SddExecutionError>;

    /// Loads one approval revision.
    fn approval(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError>;

    /// Loads the newest recorded approval revision.
    fn latest_approval(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError>;

    /// Records the one reservation for a dispatch request, or returns the
    /// stored reservation for the same request.
    fn reserve_task(
        &mut self,
        reservation: &TaskReservation,
    ) -> Result<TaskReservation, SddExecutionError>;

    /// Loads the reservation created by one dispatch request.
    fn task_reservation(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<TaskReservation>, SddExecutionError>;

    /// Records the immutable manifest for one dispatch request.
    fn record_manifest(&mut self, manifest: &DispatchManifest) -> Result<(), SddExecutionError>;

    /// Loads the manifest for one dispatch request.
    fn manifest(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchManifest>, SddExecutionError>;

    /// Records one budget increment for a revision.
    fn record_budget_increment(
        &mut self,
        increment: &BudgetIncrement,
    ) -> Result<(), SddExecutionError>;

    /// Lists budget increments in revision order.
    fn budget_increments(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<BudgetIncrement>, SddExecutionError>;
}
