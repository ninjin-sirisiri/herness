//! The H4 host execution contract, shared operations, and checkout ownership.
//!
//! The contract binds this build to the pack's
//! `sdd-herness-execution-integration` version 1 definition: host-owned Task
//! dispatch, host stage and commit with repository hooks, host consumption of
//! H3's `H4Barrier`, host progress output, and no parent dispatch, child Git,
//! or push/pull/merge/rebase/amend/reset/clean.
//!
//! Every update operation requires the project, execution ID, request ID, and
//! expected revision. Inspect, get, and subscribe are read-only.

use std::fmt;

use herness_core::contracts::ProjectId;
use herness_html_sync::H4Barrier;
use serde::{Deserialize, Serialize};

use crate::approval::{ApprovalSourceKind, ExecutionApproval};
use crate::error::SddExecutionError;
use crate::ids::{
    ControlRequestId, ExecutionId, ExecutionRevision, ExecutionScopedId, verify_scoped,
};
use crate::journal::RequestIdentity;
use crate::plan::InspectorProtocol;
use crate::snapshot::ExecutionSnapshot;
use crate::state::ConflictReason;
use crate::version::{
    APPROVAL_KIND, APPROVAL_SOURCE_REGISTRY, EXECUTION_CONTRACT_SCHEMA, EXECUTION_CONTRACT_VERSION,
    H4_MAX_ADDITIONAL_RUNS, H4_MAX_CONSECUTIVE_STALLS, H4_MAX_SUPERVISION_SECONDS, PackFingerprint,
};

/// One H4 operation exposed to a trusted human UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOperation {
    /// Read-only plan preview import.
    Inspect,
    /// Read the saved snapshot.
    Get,
    /// Read snapshots and project sequences after a sequence.
    Subscribe,
    /// Approve the current inputs and start the execution.
    ApproveAndStart,
    /// Stop new dispatch, send, and commit and ask the current child to stop.
    Pause,
    /// Terminal cancellation. Changes and history are retained.
    Cancel,
    /// Human resume after a confirmed stop.
    Resume,
    /// Approve a changed plan revision after a stop.
    ApprovePlanRevision,
    /// Hand the completed execution to the finish skill.
    FinishHandoff,
}

impl ExecutionOperation {
    /// Every operation.
    pub const ALL: [Self; 9] = [
        Self::Inspect,
        Self::Get,
        Self::Subscribe,
        Self::ApproveAndStart,
        Self::Pause,
        Self::Cancel,
        Self::Resume,
        Self::ApprovePlanRevision,
        Self::FinishHandoff,
    ];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Get => "get",
            Self::Subscribe => "subscribe",
            Self::ApproveAndStart => "approve_and_start",
            Self::Pause => "pause",
            Self::Cancel => "cancel",
            Self::Resume => "resume",
            Self::ApprovePlanRevision => "approve_plan_revision",
            Self::FinishHandoff => "finish_handoff",
        }
    }

    /// Whether this operation mutates H4 state and therefore needs an update
    /// guard.
    pub const fn is_update(self) -> bool {
        matches!(
            self,
            Self::ApproveAndStart
                | Self::Pause
                | Self::Cancel
                | Self::Resume
                | Self::ApprovePlanRevision
        )
    }

    /// Whether this operation is read-only.
    pub const fn is_read_only(self) -> bool {
        !self.is_update()
    }
}

impl fmt::Display for ExecutionOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The idempotency content of one control request is its operation.
///
/// The request guard already binds the project, execution, request ID, and
/// expected revision, so the fingerprint only has to distinguish pause from
/// resume and so on. The resulting snapshot is the stored outcome, never the
/// request content: a re-delivered request returns the stored result instead of
/// computing a new fingerprint from a changed snapshot.
impl crate::journal::JournalContent for ExecutionOperation {
    fn content_fingerprint(&self) -> Result<crate::version::RequestFingerprint, SddExecutionError> {
        let bytes = serde_json::to_vec(self).map_err(|error| SddExecutionError::InvalidValue {
            field: "operation.content".to_owned(),
            detail: format!("could not encode the operation: {error}"),
        })?;
        Ok(crate::version::RequestFingerprint::sha256(&bytes))
    }
}

/// A read-only operation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadExecutionRequest {
    project_id: ProjectId,
    execution_id: ExecutionId,
    operation: ExecutionOperation,
}

impl ReadExecutionRequest {
    /// Creates a read-only request.
    pub fn new(
        project_id: ProjectId,
        execution_id: ExecutionId,
        operation: ExecutionOperation,
    ) -> Result<Self, SddExecutionError> {
        if operation.is_update() {
            return Err(invalid(
                "operation",
                "an update operation requires a request ID and expected revision",
            ));
        }
        verify_scoped(&execution_id, project_id)?;
        Ok(Self {
            project_id,
            execution_id,
            operation,
        })
    }

    /// Project that owns the execution.
    pub const fn project_id(self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }

    /// Read-only operation.
    pub const fn operation(self) -> ExecutionOperation {
        self.operation
    }
}

/// An update operation request with its mandatory request guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionOperationRequest {
    identity: RequestIdentity<crate::ids::ControlKind>,
    operation: ExecutionOperation,
}

impl ExecutionOperationRequest {
    /// Creates an update request.
    ///
    /// Project, execution ID, request ID, and expected revision are all
    /// mandatory; a read-only operation is refused here.
    pub fn new(
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
        expected_revision: ExecutionRevision,
        operation: ExecutionOperation,
    ) -> Result<Self, SddExecutionError> {
        if !operation.is_update() {
            return Err(invalid(
                "operation",
                "a read-only operation does not take an update guard",
            ));
        }
        Ok(Self {
            identity: RequestIdentity::new(
                project_id,
                execution_id,
                request_id,
                expected_revision,
            )?,
            operation,
        })
    }

    /// Mandatory project, execution, request, and revision guard.
    pub fn identity(&self) -> &RequestIdentity<crate::ids::ControlKind> {
        &self.identity
    }

    /// Update operation.
    pub const fn operation(&self) -> ExecutionOperation {
        self.operation
    }

    /// Records this request as an intent before any side effect.
    ///
    /// The fingerprint binds the operation only; the request guard already
    /// binds the project, execution, request ID, and expected revision.
    pub fn intent(&self) -> Result<ControlRecord, SddExecutionError> {
        ControlRecord::intent(*self.identity(), &self.operation)
    }

    /// Returns a recorded copy for a completed operation.
    pub fn recorded(
        &self,
        result: ExecutionOperationResult,
    ) -> Result<ControlRecord, SddExecutionError> {
        if result.operation() != self.operation {
            return Err(invalid(
                "operation.result",
                "the stored result must describe the requested operation",
            ));
        }
        Ok(self.intent()?.recorded(result))
    }
}

/// The stored result of one update operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionOperationResult {
    project_id: ProjectId,
    execution_id: ExecutionId,
    operation: ExecutionOperation,
    resulting_revision: ExecutionRevision,
    snapshot: ExecutionSnapshot,
}

impl ExecutionOperationResult {
    /// Creates a result.
    pub fn new(
        operation: ExecutionOperation,
        snapshot: ExecutionSnapshot,
    ) -> Result<Self, SddExecutionError> {
        if snapshot.project_id() != snapshot.execution_id().project_id() {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "execution".to_owned(),
                expected: snapshot.project_id(),
                found: snapshot.execution_id().project_id(),
            });
        }
        Ok(Self {
            project_id: snapshot.project_id(),
            execution_id: snapshot.execution_id(),
            operation,
            resulting_revision: snapshot.revision(),
            snapshot,
        })
    }

    /// Project that owns the result.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Operation that produced the result.
    pub const fn operation(&self) -> ExecutionOperation {
        self.operation
    }

    /// Revision after the operation.
    pub const fn resulting_revision(&self) -> ExecutionRevision {
        self.resulting_revision
    }

    /// Resulting snapshot.
    pub fn snapshot(&self) -> &ExecutionSnapshot {
        &self.snapshot
    }
}

/// The idempotent control-operation record.
pub type ControlRecord =
    crate::journal::RequestRecord<crate::ids::ControlKind, ExecutionOperationResult>;

/// How one H3 `H4Barrier` is consumed.
///
/// The alias keeps H4 ports readable while still naming the H3 value the host
/// calls. H4 never defines a second barrier or changes H3 semantics.
pub type HtmlBarrier<'a> = H4Barrier<'a>;

/// The fixed H2 continuation limits an execution approval cannot raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContinuationLimits {
    max_time_seconds: u64,
    max_additional_runs: u32,
    max_consecutive_stalls: u32,
}

impl ContinuationLimits {
    /// The approved H4 defaults.
    pub const fn h4_default() -> Self {
        Self {
            max_time_seconds: H4_MAX_SUPERVISION_SECONDS,
            max_additional_runs: H4_MAX_ADDITIONAL_RUNS,
            max_consecutive_stalls: H4_MAX_CONSECUTIVE_STALLS,
        }
    }

    /// Validates that the limits are the fixed H4 values.
    pub fn validate(self) -> Result<(), SddExecutionError> {
        let expected = Self::h4_default();
        if self != expected {
            return Err(invalid(
                "continuation",
                "H4 does not add or raise the finite H2 continuation limits",
            ));
        }
        Ok(())
    }

    /// Cumulative active seconds.
    pub const fn max_time_seconds(self) -> u64 {
        self.max_time_seconds
    }

    /// Additional child runs.
    pub const fn max_additional_runs(self) -> u32 {
        self.max_additional_runs
    }

    /// Consecutive stalls.
    pub const fn max_consecutive_stalls(self) -> u32 {
        self.max_consecutive_stalls
    }
}

/// Who performs one delegated responsibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delegation {
    /// The action is forbidden in the execution flow.
    Forbidden,
    /// The host performs the action.
    Host,
    /// The host must run the repository hooks.
    HostRequired,
    /// The host consumes the H3 barrier without changing H3.
    HostConsumesH3,
}

/// Delegation rules bound by the H4 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationRules {
    parent_task_dispatch: Delegation,
    child_git: Delegation,
    task_dispatch: Delegation,
    stage_and_commit: Delegation,
    hooks: Delegation,
    html_barrier: Delegation,
    progress_ledger: Delegation,
    push_pull_merge_rebase_amend_reset_clean: Delegation,
}

impl DelegationRules {
    /// The rules the H4 contract requires.
    pub const fn h4_required() -> Self {
        Self {
            parent_task_dispatch: Delegation::Forbidden,
            child_git: Delegation::Forbidden,
            task_dispatch: Delegation::Host,
            stage_and_commit: Delegation::Host,
            hooks: Delegation::HostRequired,
            html_barrier: Delegation::HostConsumesH3,
            progress_ledger: Delegation::Host,
            push_pull_merge_rebase_amend_reset_clean: Delegation::Forbidden,
        }
    }

    /// Validates the required rules.
    pub fn validate(self) -> Result<(), SddExecutionError> {
        if self != Self::h4_required() {
            return Err(invalid(
                "delegation",
                "the H4 contract does not take over parent dispatch, child Git, or history rewriting",
            ));
        }
        Ok(())
    }

    /// The parent model does not dispatch Tasks.
    pub const fn parent_task_dispatch(self) -> Delegation {
        self.parent_task_dispatch
    }

    /// The child does not stage, commit, or change branches.
    pub const fn child_git(self) -> Delegation {
        self.child_git
    }

    /// The host owns dispatch.
    pub const fn task_dispatch(self) -> Delegation {
        self.task_dispatch
    }

    /// The host owns stage and commit.
    pub const fn stage_and_commit(self) -> Delegation {
        self.stage_and_commit
    }

    /// The host runs repository hooks.
    pub const fn hooks(self) -> Delegation {
        self.hooks
    }

    /// The host consumes H3's barrier.
    pub const fn html_barrier(self) -> Delegation {
        self.html_barrier
    }

    /// The host writes the progress ledger.
    pub const fn progress_ledger(self) -> Delegation {
        self.progress_ledger
    }

    /// No push, pull, merge, rebase, amend, reset, or clean.
    pub const fn destructive_git(self) -> Delegation {
        self.push_pull_merge_rebase_amend_reset_clean
    }
}

/// Version 1 host capability requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionRequirements {
    task_dispatch: u32,
    host_commit: u32,
    html_barrier: u32,
    ledger_output: u32,
    plan_inspector: InspectorProtocol,
}

impl ExecutionRequirements {
    /// The required version 1 capabilities.
    pub fn required() -> Self {
        Self {
            task_dispatch: 1,
            host_commit: 1,
            html_barrier: 1,
            ledger_output: 1,
            plan_inspector: InspectorProtocol::expected(),
        }
    }

    /// Validates the required capability versions.
    pub fn validate(&self) -> Result<(), SddExecutionError> {
        self.plan_inspector.ensure_current()?;
        if [
            self.task_dispatch,
            self.host_commit,
            self.html_barrier,
            self.ledger_output,
        ] != [1, 1, 1, 1]
        {
            return Err(invalid(
                "requirements",
                "the H4 contract requires version 1 of every host capability",
            ));
        }
        Ok(())
    }

    /// Task dispatch version.
    pub const fn task_dispatch(&self) -> u32 {
        self.task_dispatch
    }

    /// Host commit version.
    pub const fn host_commit(&self) -> u32 {
        self.host_commit
    }

    /// HTML barrier version.
    pub const fn html_barrier(&self) -> u32 {
        self.html_barrier
    }

    /// Ledger output version.
    pub const fn ledger_output(&self) -> u32 {
        self.ledger_output
    }

    /// Plan inspector protocol.
    pub fn plan_inspector(&self) -> &InspectorProtocol {
        &self.plan_inspector
    }
}

/// The approval source definition an execution must satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalContract {
    source: String,
    kind: String,
    approver: String,
    forbidden_sources: Vec<ApprovalSourceKind>,
}

impl ApprovalContract {
    /// The definition the H4 contract accepts.
    pub fn required() -> Self {
        Self {
            source: APPROVAL_SOURCE_REGISTRY.to_owned(),
            kind: APPROVAL_KIND.to_owned(),
            approver: crate::version::APPROVAL_APPROVER.to_owned(),
            forbidden_sources: ApprovalSourceKind::ALL
                .into_iter()
                .filter(|kind| !kind.is_accepted())
                .collect(),
        }
    }

    /// Validates the definition.
    pub fn validate(&self) -> Result<(), SddExecutionError> {
        let required = Self::required();
        if self.source != required.source || self.kind != required.kind {
            return Err(invalid(
                "approval",
                "H4 accepts only the h4-approval-registry h4-execution-approval kind",
            ));
        }
        if self.approver != required.approver {
            return Err(invalid("approval.approver", "only a human may approve"));
        }
        if self.forbidden_sources != required.forbidden_sources {
            return Err(invalid(
                "approval.forbiddenSources",
                "every non-registry approval source must stay forbidden",
            ));
        }
        Ok(())
    }

    /// Accepted source label.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Accepted approval kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Accepted approver.
    pub fn approver(&self) -> &str {
        &self.approver
    }

    /// Sources that never approve H4 execution.
    pub fn forbidden_sources(&self) -> &[ApprovalSourceKind] {
        &self.forbidden_sources
    }

    /// Rejects an approval whose source or actor is not the accepted one.
    pub fn ensure_approval(&self, approval: &ExecutionApproval) -> Result<(), SddExecutionError> {
        if !approval.is_human() || !approval.is_registry() {
            return Err(SddExecutionError::ApprovalRequired {
                reason: crate::state::ApprovalRequirement::StartApproval,
                details: crate::error::FailureDetails::none().boxed(),
            });
        }
        Ok(())
    }
}

/// The version 1 host execution contract bound to the pack definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostExecutionContract {
    schema: String,
    version: u32,
    execution_contract: PackFingerprint,
    requirements: ExecutionRequirements,
    delegation: DelegationRules,
    approval: ApprovalContract,
    continuation: ContinuationLimits,
}

impl HostExecutionContract {
    /// Creates the contract for one pack execution-contract fingerprint.
    pub fn new(execution_contract: PackFingerprint) -> Result<Self, SddExecutionError> {
        let value = Self {
            schema: EXECUTION_CONTRACT_SCHEMA.to_owned(),
            version: EXECUTION_CONTRACT_VERSION,
            execution_contract,
            requirements: ExecutionRequirements::required(),
            delegation: DelegationRules::h4_required(),
            approval: ApprovalContract::required(),
            continuation: ContinuationLimits::h4_default(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the schema, version, capabilities, delegation, approval, and
    /// continuation limits.
    pub fn validate(&self) -> Result<(), SddExecutionError> {
        if self.schema != EXECUTION_CONTRACT_SCHEMA {
            return Err(invalid(
                "hostContract.schema",
                "must be the herness H4 execution contract schema",
            ));
        }
        if self.version != EXECUTION_CONTRACT_VERSION {
            return Err(SddExecutionError::UnsupportedContractVersion {
                found: self.version,
                expected: EXECUTION_CONTRACT_VERSION,
            });
        }
        self.requirements.validate()?;
        self.delegation.validate()?;
        self.approval.validate()?;
        self.continuation.validate()?;
        Ok(())
    }

    /// Schema name.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Contract version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Pack execution-contract fingerprint.
    pub fn execution_contract(&self) -> &PackFingerprint {
        &self.execution_contract
    }

    /// Required capabilities.
    pub fn requirements(&self) -> &ExecutionRequirements {
        &self.requirements
    }

    /// Delegation rules.
    pub const fn delegation(&self) -> DelegationRules {
        self.delegation
    }

    /// Approval definition.
    pub fn approval(&self) -> &ApprovalContract {
        &self.approval
    }

    /// Continuation limits.
    pub const fn continuation(&self) -> ContinuationLimits {
        self.continuation
    }

    /// Rejects a pack whose fingerprint differs from the approved one.
    pub fn ensure_fingerprint(&self, found: &PackFingerprint) -> Result<(), SddExecutionError> {
        if &self.execution_contract == found {
            Ok(())
        } else {
            Err(SddExecutionError::Unavailable {
                feature: "pack execution contract fingerprint".to_owned(),
                details: crate::error::FailureDetails::none().boxed(),
            })
        }
    }
}

/// Exclusive ownership of one checkout and branch by one execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckoutClaim {
    canonical_checkout_root: String,
    branch: String,
    execution_id: ExecutionId,
}

impl CheckoutClaim {
    /// Creates a claim.
    pub fn new(
        canonical_checkout_root: impl Into<String>,
        branch: impl Into<String>,
        execution_id: ExecutionId,
    ) -> Result<Self, SddExecutionError> {
        let canonical_checkout_root = canonical_checkout_root.into();
        let branch = branch.into();
        if canonical_checkout_root.trim().is_empty()
            || !std::path::Path::new(&canonical_checkout_root).is_absolute()
        {
            return Err(invalid(
                "checkoutClaim.canonicalCheckoutRoot",
                "must be an absolute path",
            ));
        }
        if branch.trim().is_empty() {
            return Err(invalid("checkoutClaim.branch", "must not be empty"));
        }
        Ok(Self {
            canonical_checkout_root,
            branch,
            execution_id,
        })
    }

    /// Canonical checkout root.
    pub fn canonical_checkout_root(&self) -> &str {
        &self.canonical_checkout_root
    }

    /// Implementation branch.
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Owning execution.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Whether another execution already owns the same checkout and branch.
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.canonical_checkout_root == other.canonical_checkout_root
            && self.branch == other.branch
            && self.execution_id != other.execution_id
    }

    /// Refuses a conflicting claim before any dispatch or commit.
    pub fn ensure_available(&self, other: &Self) -> Result<(), SddExecutionError> {
        if self.conflicts_with(other) {
            Err(SddExecutionError::Conflict {
                reason: ConflictReason::OwnershipConflict,
                details: crate::error::FailureDetails::none().boxed(),
            })
        } else {
            Ok(())
        }
    }
}

/// Rejects a decoded guard whose project does not own its execution.
pub fn ensure_execution_project(
    project_id: ProjectId,
    execution_id: ExecutionId,
) -> Result<(), SddExecutionError> {
    verify_scoped(&execution_id, project_id)
}

/// The request-ID type used by control operations, exposed for later modules.
pub type OperationRequestId = ExecutionScopedId<crate::ids::ControlKind>;

fn invalid(field: &str, detail: &str) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.to_owned(),
    }
}
