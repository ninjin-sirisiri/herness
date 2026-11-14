//! Plan change detection, the safety-stop latch, and limited re-approval.
//!
//! # What this module owns
//!
//! * [`PlanChange`] is the typed detection result. Its reason is one of
//!   [`PlanChangeReason`] — `BytesChanged`, `Missing`, `Moved`, or
//!   `UnstableObservation` — and it carries the observed digest and length, the
//!   candidate moved-to path, the byte ranges of the changed prose, and whether
//!   the fenced `sdd-execution-v1` JSON block is byte-identical. A JSON-identical
//!   change is never ignored: the exact bytes, the Global Constraints text, and
//!   every Task body are compared through the inspector's parsed result.
//! * [`PlanChangeLatch`] is the durable safety stop. Once engaged it blocks new
//!   dispatch and commit regardless of the current file, so returning to the
//!   previously approved bytes does **not** clear it. Only a human-confirmed plan
//!   revision that this module records as `cleared` releases it.
//! * [`PlanChangeGate`] performs the observation, engages the latch, and answers
//!   [`PlanGateDecision`]. It is called before every side effect (dispatch,
//!   verification acceptance, host commit) and once per
//!   [`PLAN_RECONCILE_INTERVAL_MILLIS`] by the host pump, so a lost watcher
//!   notification is still caught.
//! * [`evaluate_inheritance`] implements the limited re-approval rule: Global
//!   Constraints, root spec references, and the body plus structured contract of
//!   every completed and started Task must be unchanged; only not-yet-started
//!   Tasks may differ. Anything else is incompatible and requires a new plan and
//!   human work-state cleanup.
//! * [`approve_plan_revision`] records one new human approval revision after a
//!   confirmed stop, keeps the consumed budget and every recorded commit range,
//!   and clears the latch. Until that revision is saved neither the old nor the
//!   new plan runs, and a re-delivered request returns its stored result.
//!
//! # What this module never does
//!
//! It does not read a wall clock, open a file, spawn a process, or touch Git.
//! The plan source, latch store, and clock are ports. The desktop adapters in
//! `src-tauri/src/sdd_execute/plan_changes.rs` supply the `notify` watcher and
//! the real filesystem source.

use std::collections::BTreeMap;

use herness_core::contracts::{ProjectId, Timestamp};
use serde::{Deserialize, Serialize};

use crate::approval::{
    ApprovalContent, ApprovalSource, ExecutionApproval, PlanApproval, TaskApproval,
};
use crate::approval_registry::{ApprovalInputs, ApprovalRevisionStorePort, StartApprovalPost};
use crate::contract::{
    ControlRecord, ExecutionOperation, ExecutionOperationRequest, ExecutionOperationResult,
};
use crate::error::{ApprovalRejection, SddExecutionError};
use crate::ids::{
    ApprovalId, ControlRequestId, ExecutionId, ExecutionRevision, PlanRevision, TaskRef,
};
use crate::journal::{JournalContent, RequestIdentity};
use crate::plan::{ParsedPlanSummary, PlanByteRange, PlanPath};
use crate::ports::{ClockPort, ExecutionStorePort, PlanObservation, PlanSourcePort};
use crate::snapshot::{ExecutionSnapshot, SnapshotInput, SnapshotPlan, TaskSnapshot};
use crate::state::{
    AppliedRevision, AppliedRevisionState, HumanAction, PlanChangeReason, StopReason, StopRecord,
    TaskPhase, TaskProgression,
};
use crate::version::{PLAN_RECONCILE_INTERVAL_MILLIS, PlanDigest, RequestFingerprint};

/// Format version of one persisted latch record.
pub const PLAN_CHANGE_LATCH_FORMAT_VERSION: u32 = 1;

/// Most candidate paths one gate probes for a move.
///
/// A host reports new plan files it observed; the bound keeps one pathological
/// directory from turning a pre-side-effect check into an unbounded scan.
pub const MAX_MOVE_CANDIDATES: usize = 32;

/// The `sdd-execution-v1` fenced block info string as it appears in the plan.
const EXECUTION_FENCE_INFO: &str = "sdd-execution-v1";

// ---------------------------------------------------------------------------
// The approved expectation
// ---------------------------------------------------------------------------

/// The exact plan identity one execution approved.
///
/// It is the comparison base of every detection: the approved path, exact bytes
/// digest and length, and the approved plan revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanExpectation {
    plan_path: PlanPath,
    digest: PlanDigest,
    byte_length: u64,
    plan_revision: PlanRevision,
}

impl PlanExpectation {
    /// Records the approved identity of one plan revision.
    pub const fn new(
        plan_path: PlanPath,
        digest: PlanDigest,
        byte_length: u64,
        plan_revision: PlanRevision,
    ) -> Self {
        Self {
            plan_path,
            digest,
            byte_length,
            plan_revision,
        }
    }

    /// The approved path.
    pub fn plan_path(&self) -> &PlanPath {
        &self.plan_path
    }

    /// Digest of the approved exact bytes.
    pub fn digest(&self) -> &PlanDigest {
        &self.digest
    }

    /// Approved byte length.
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Approved plan revision.
    pub const fn plan_revision(&self) -> PlanRevision {
        self.plan_revision
    }

    /// Whether one observation still carries exactly the approved bytes.
    ///
    /// A missing or unstable observation never matches, even when a digest
    /// happens to be present.
    pub fn matches(&self, observation: &PlanObservation) -> bool {
        observation.is_stable()
            && observation.digest() == Some(&self.digest)
            && observation.byte_length() == Some(self.byte_length)
    }
}

// ---------------------------------------------------------------------------
// Change detection
// ---------------------------------------------------------------------------

/// Whether the fenced execution JSON block changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonBlockState {
    /// The fenced block is byte-identical.
    Unchanged,
    /// The fenced block bytes differ.
    Changed,
    /// The block could not be located, so nothing is claimed.
    Unknown,
}

impl JsonBlockState {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Changed => "changed",
            Self::Unknown => "unknown",
        }
    }
}

/// One detected plan change.
///
/// It is produced either from a bare observation ([`Self::from_observation`]) or
/// from a full parsed comparison ([`Self::compared`]). The parsed form reports
/// the changed byte ranges in the *current* input and whether the JSON block is
/// unchanged, so a prose-only edit is never mistaken for a no-op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanChange {
    reason: PlanChangeReason,
    #[serde(default)]
    observed_digest: Option<PlanDigest>,
    #[serde(default)]
    observed_byte_length: Option<u64>,
    #[serde(default)]
    moved_to: Option<PlanPath>,
    json_block: JsonBlockState,
    #[serde(default)]
    ranges: Vec<PlanByteRange>,
    global_constraints_changed: bool,
    #[serde(default)]
    changed_task_numbers: Vec<u32>,
    structured_contract_changed: bool,
}

impl PlanChange {
    /// Records one change from a bare observation.
    ///
    /// It never claims a byte range or a JSON identity it did not compare, so
    /// `json_block` is [`JsonBlockState::Unknown`] and the range list is empty.
    pub fn from_observation(
        reason: PlanChangeReason,
        observation: &PlanObservation,
        moved_to: Option<PlanPath>,
    ) -> Result<Self, SddExecutionError> {
        if reason == PlanChangeReason::Moved && moved_to.is_none() {
            return Err(invalid(
                "planChange.movedTo",
                "a moved plan must name the candidate path it was found at",
            ));
        }
        if reason != PlanChangeReason::Moved && moved_to.is_some() {
            return Err(invalid(
                "planChange.movedTo",
                "only a moved plan may name a new path",
            ));
        }
        Ok(Self {
            reason,
            observed_digest: observation.digest().cloned(),
            observed_byte_length: observation.byte_length(),
            moved_to,
            json_block: JsonBlockState::Unknown,
            ranges: Vec::new(),
            global_constraints_changed: false,
            changed_task_numbers: Vec::new(),
            structured_contract_changed: false,
        })
    }

    /// Records a change whose exact bytes were compared through the inspector.
    ///
    /// The reason is always [`PlanChangeReason::BytesChanged`]: a parsed
    /// comparison is only meaningful when the exact bytes moved. The digests,
    /// lengths, and byte lengths must be those of `current_source`; a mismatched
    /// claim is refused rather than reported as a different plan.
    pub fn compared(
        previous: &ParsedPlanSummary,
        previous_source: &[u8],
        current: &ParsedPlanSummary,
        current_source: &[u8],
    ) -> Result<Option<Self>, SddExecutionError> {
        let previous_digest = PlanDigest::sha256(previous_source);
        let current_digest = PlanDigest::sha256(current_source);
        if previous_digest == current_digest {
            return Ok(None);
        }
        if previous.schema_version() != current.schema_version() {
            return Err(invalid(
                "planChange.schemaVersion",
                "both sides must use the same plan schema version",
            ));
        }
        let diff = compare_parsed(previous, current);
        let json_block = json_block_state(previous_source, current_source);
        let mut ranges = Vec::new();
        if diff.global_constraints_changed {
            ranges.push(current.global_constraints().byte_range());
        }
        for change in &diff.task_bodies {
            ranges.push(change.range);
        }
        ranges.sort_by_key(|range| range.start());
        Ok(Some(Self {
            reason: PlanChangeReason::BytesChanged,
            observed_digest: Some(current_digest),
            observed_byte_length: Some(current_source.len() as u64),
            moved_to: None,
            json_block,
            ranges,
            global_constraints_changed: diff.global_constraints_changed,
            changed_task_numbers: diff
                .task_bodies
                .iter()
                .map(|change| change.number)
                .collect(),
            structured_contract_changed: diff.structured_contract_changed,
        }))
    }

    /// Why the plan changed.
    pub const fn reason(&self) -> PlanChangeReason {
        self.reason
    }

    /// Digest observed at the approved path, when one was read.
    pub fn observed_digest(&self) -> Option<&PlanDigest> {
        self.observed_digest.as_ref()
    }

    /// Byte length observed at the approved path, when one was read.
    pub const fn observed_byte_length(&self) -> Option<u64> {
        self.observed_byte_length
    }

    /// Candidate path the plan was found at, when it moved.
    pub fn moved_to(&self) -> Option<&PlanPath> {
        self.moved_to.as_ref()
    }

    /// Whether the fenced execution JSON block is byte-identical.
    pub const fn json_block(&self) -> JsonBlockState {
        self.json_block
    }

    /// Changed byte ranges in the current input, ascending.
    ///
    /// The list is empty when the comparison could not run (a missing, moved, or
    /// unstable observation), so an absent range is never read as "unchanged".
    pub fn ranges(&self) -> &[PlanByteRange] {
        &self.ranges
    }

    /// Whether the exact Global Constraints text changed.
    pub const fn global_constraints_changed(&self) -> bool {
        self.global_constraints_changed
    }

    /// Task numbers whose body changed, in plan order.
    pub fn changed_task_numbers(&self) -> &[u32] {
        &self.changed_task_numbers
    }

    /// Whether the parsed structure changed beyond the compared Task bodies
    /// (Task set or order, Task titles, final check ids, schema version).
    pub const fn structured_contract_changed(&self) -> bool {
        self.structured_contract_changed
    }

    /// The H4 stop reason this change requires.
    pub const fn stop_reason(&self) -> StopReason {
        match self.reason {
            PlanChangeReason::BytesChanged => StopReason::PlanChanged,
            PlanChangeReason::Missing => StopReason::PlanMissing,
            PlanChangeReason::Moved => StopReason::PlanMoved,
            PlanChangeReason::UnstableObservation => StopReason::PlanObservationUnstable,
        }
    }
}

struct TaskBodyChange {
    number: u32,
    range: PlanByteRange,
}

struct ParsedDiff {
    global_constraints_changed: bool,
    task_bodies: Vec<TaskBodyChange>,
    structured_contract_changed: bool,
}

/// Compares two parsed results: Global Constraints text, every Task body, and the
/// structure the parsed summary carries (Task set and order, titles, final
/// checks, schema version).
fn compare_parsed(previous: &ParsedPlanSummary, current: &ParsedPlanSummary) -> ParsedDiff {
    let global_constraints_changed =
        previous.global_constraints().text() != current.global_constraints().text();
    let mut task_bodies = Vec::new();
    let mut structured_contract_changed = previous.tasks().len() != current.tasks().len()
        || previous.final_check_ids() != current.final_check_ids()
        || previous.schema_version() != current.schema_version();
    for (index, task) in current.tasks().iter().enumerate() {
        let Some(previous_task) = previous
            .tasks()
            .iter()
            .find(|candidate| candidate.number() == task.number())
        else {
            // A new Task is a structural change; its body is not a "change" of an
            // existing Task, so no range is reported for it.
            structured_contract_changed = true;
            continue;
        };
        if previous_task.title() != task.title() {
            structured_contract_changed = true;
        }
        if previous_task.body().text() != task.body().text() {
            task_bodies.push(TaskBodyChange {
                number: task.number(),
                range: task.body().byte_range(),
            });
        }
        if index + 1 != task.number() as usize {
            structured_contract_changed = true;
        }
    }
    if previous.tasks().iter().any(|task| {
        !current
            .tasks()
            .iter()
            .any(|next| next.number() == task.number())
    }) {
        structured_contract_changed = true;
    }
    ParsedDiff {
        global_constraints_changed,
        task_bodies,
        structured_contract_changed,
    }
}

/// Locates the single `sdd-execution-v1` fenced block's content bytes.
///
/// This is a byte-level identity probe, not a parser: it finds the one fence the
/// inspector already validated, and it returns `None` when there is not exactly
/// one closed block so no identity is claimed from an ambiguous document.
fn execution_block_content(source: &[u8]) -> Option<&[u8]> {
    let text = std::str::from_utf8(source).ok()?;
    let mut blocks: Vec<(usize, usize)> = Vec::new();
    let mut open: Option<usize> = None;
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']).trim_end();
        match open {
            None => {
                if trimmed.strip_prefix("```").map(str::trim) == Some(EXECUTION_FENCE_INFO) {
                    open = Some(offset + line.len());
                }
            }
            Some(start) => {
                if trimmed == "```" {
                    blocks.push((start, offset));
                    open = None;
                }
            }
        }
        offset += line.len();
    }
    if open.is_some() || blocks.len() != 1 {
        return None;
    }
    source.get(blocks[0].0..blocks[0].1)
}

fn json_block_state(previous: &[u8], current: &[u8]) -> JsonBlockState {
    match (
        execution_block_content(previous),
        execution_block_content(current),
    ) {
        (Some(previous), Some(current)) if previous == current => JsonBlockState::Unchanged,
        (Some(_), Some(_)) => JsonBlockState::Changed,
        _ => JsonBlockState::Unknown,
    }
}

// ---------------------------------------------------------------------------
// The latch
// ---------------------------------------------------------------------------

/// Whether a latch still blocks or was released by a human approval revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum LatchState {
    /// The change is not resolved. New dispatch and commit are blocked.
    Open,
    /// A human-approved plan revision replaced the latched change.
    Cleared {
        /// Approval revision that was saved.
        approval_revision: u64,
        /// Plan revision that revision approved.
        plan_revision: PlanRevision,
    },
}

/// One durable plan-change safety stop.
///
/// The value is append-only history: an open latch keeps the first observed
/// change as its stop reason, and only a human-approved plan revision changes the
/// state to `cleared`. Re-observing the approved bytes never rewrites it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanChangeLatch {
    format_version: u32,
    project_id: ProjectId,
    execution_id: ExecutionId,
    approval_id: ApprovalId,
    expectation: PlanExpectation,
    change: PlanChange,
    state: LatchState,
}

impl PlanChangeLatch {
    /// Engages a latch for one observed change.
    pub fn engage(
        project_id: ProjectId,
        execution_id: ExecutionId,
        approval_id: ApprovalId,
        expectation: PlanExpectation,
        change: PlanChange,
    ) -> Result<Self, SddExecutionError> {
        execution_id.validate_in(project_id)?;
        if approval_id.project_id() != project_id {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "plan change approval".to_owned(),
                expected: project_id,
                found: approval_id.project_id(),
            });
        }
        Ok(Self {
            format_version: PLAN_CHANGE_LATCH_FORMAT_VERSION,
            project_id,
            execution_id,
            approval_id,
            expectation,
            change,
            state: LatchState::Open,
        })
    }

    /// Rejects a stored latch this build cannot read or that names another
    /// project.
    pub fn validate(&self) -> Result<(), SddExecutionError> {
        if self.format_version != PLAN_CHANGE_LATCH_FORMAT_VERSION {
            return Err(SddExecutionError::InvalidValue {
                field: "planChangeLatch.formatVersion".to_owned(),
                detail: format!(
                    "expected {PLAN_CHANGE_LATCH_FORMAT_VERSION}, found {}",
                    self.format_version
                ),
            });
        }
        self.execution_id.validate_in(self.project_id)?;
        if self.approval_id.project_id() != self.project_id {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "plan change approval".to_owned(),
                expected: self.project_id,
                found: self.approval_id.project_id(),
            });
        }
        if let LatchState::Cleared {
            approval_revision, ..
        } = self.state
            && approval_revision == 0
        {
            return Err(invalid(
                "planChangeLatch.approvalRevision",
                "a cleared latch must name the approval revision that cleared it",
            ));
        }
        if self.change.moved_to() == Some(self.expectation.plan_path()) {
            return Err(invalid(
                "planChangeLatch.change.movedTo",
                "a move cannot name the approved path",
            ));
        }
        Ok(())
    }

    /// Project that owns the latch.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Approval identity the latch belongs to.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// Approved plan identity the latch compared against.
    pub fn expectation(&self) -> &PlanExpectation {
        &self.expectation
    }

    /// The change that engaged the latch.
    pub fn change(&self) -> &PlanChange {
        &self.change
    }

    /// Latch state.
    pub const fn state(&self) -> LatchState {
        self.state
    }

    /// Whether the latch still blocks new dispatch and commit.
    pub const fn is_open(&self) -> bool {
        matches!(self.state, LatchState::Open)
    }

    /// Whether a human-approved plan revision released it.
    pub const fn is_cleared(&self) -> bool {
        matches!(self.state, LatchState::Cleared { .. })
    }

    /// Refuses to treat a cleared latch as a stop.
    pub fn ensure_open(&self) -> Result<(), SddExecutionError> {
        if self.is_open() {
            Ok(())
        } else {
            Err(SddExecutionError::Conflict {
                reason: crate::state::ConflictReason::TaskNotReady,
                details: crate::error::FailureDetails::none().boxed(),
            })
        }
    }

    /// Refuses a latch that belongs to another approval or another plan identity.
    ///
    /// A latch is only meaningful for the plan revision it was engaged against;
    /// reading it against different approved bytes would let a stale stop hold or
    /// release the wrong version.
    pub fn ensure_matches_approval(
        &self,
        approval_id: ApprovalId,
        approval: &PlanApproval,
    ) -> Result<(), SddExecutionError> {
        if self.approval_id != approval_id
            || self.expectation.plan_path() != approval.plan_path()
            || self.expectation.digest() != approval.digest()
            || self.expectation.plan_revision() != approval.plan_revision()
        {
            return Err(crate::error::SddExecutionError::RecoveryRequired {
                reason: crate::state::RecoveryReason::StateUnreadable,
                details: crate::error::FailureDetails::none().boxed(),
            });
        }
        Ok(())
    }

    /// The latch after a human-approved plan revision released it.
    pub fn cleared(
        &self,
        approval_revision: u64,
        plan_revision: PlanRevision,
    ) -> Result<Self, SddExecutionError> {
        self.ensure_open()?;
        if approval_revision == 0 {
            return Err(invalid(
                "planChangeLatch.approvalRevision",
                "a cleared latch must name the approval revision that cleared it",
            ));
        }
        if plan_revision.get() <= self.expectation.plan_revision().get() {
            return Err(invalid(
                "planChangeLatch.planRevision",
                "the clearing plan revision must advance past the latched one",
            ));
        }
        let mut next = self.clone();
        next.state = LatchState::Cleared {
            approval_revision,
            plan_revision,
        };
        Ok(next)
    }

    /// Refuses a write that would rewrite an open latch's stop reason or move a
    /// cleared latch backwards.
    pub fn ensure_advance(stored: &Self, next: &Self) -> Result<(), SddExecutionError> {
        if stored.project_id != next.project_id || stored.execution_id != next.execution_id {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "plan change latch".to_owned(),
                expected: stored.project_id,
                found: next.project_id,
            });
        }
        match (stored.state, next.state) {
            (LatchState::Open, LatchState::Open) => {
                if stored == next {
                    Ok(())
                } else {
                    // The first stop reason and the approved identity are the
                    // history of the stop; a later observation never replaces them.
                    Err(SddExecutionError::DuplicateResultConflict {
                        request: stored.change.reason().as_str().to_owned(),
                    })
                }
            }
            (LatchState::Open, LatchState::Cleared { .. }) => Ok(()),
            (LatchState::Cleared { .. }, LatchState::Cleared { .. }) => {
                if stored == next {
                    Ok(())
                } else {
                    Err(SddExecutionError::DuplicateResultConflict {
                        request: "plan change latch clearance".to_owned(),
                    })
                }
            }
            // A change observed after a re-approval engages a new latch.
            (LatchState::Cleared { .. }, LatchState::Open) => Ok(()),
        }
    }
}

impl PlanChangeReason {
    /// Stable wire label used in stop details.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BytesChanged => "bytes_changed",
            Self::Missing => "missing",
            Self::Moved => "moved",
            Self::UnstableObservation => "unstable_observation",
        }
    }
}

/// Durable storage for one plan-change latch per execution.
///
/// A store must refuse to rewrite an open latch's change and to move a cleared
/// latch backwards; [`PlanChangeLatch::ensure_advance`] states both rules, so a
/// store that only stores bytes behaves the same at this boundary.
pub trait PlanChangeLatchStorePort {
    /// Loads the latch of one execution, when one exists.
    fn plan_change_latch(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<PlanChangeLatch>, SddExecutionError>;

    /// Records one latch state exactly once.
    fn record_plan_change_latch(
        &mut self,
        latch: &PlanChangeLatch,
    ) -> Result<(), SddExecutionError>;
}

/// In-memory latch store for single-process composition and tests.
#[derive(Debug, Default, Clone)]
pub struct MemoryPlanChangeLatchStore {
    latches: BTreeMap<(ProjectId, ExecutionId), PlanChangeLatch>,
}

impl MemoryPlanChangeLatchStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl PlanChangeLatchStorePort for MemoryPlanChangeLatchStore {
    fn plan_change_latch(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<PlanChangeLatch>, SddExecutionError> {
        execution_id.validate_in(project_id)?;
        Ok(self.latches.get(&(project_id, execution_id)).cloned())
    }

    fn record_plan_change_latch(
        &mut self,
        latch: &PlanChangeLatch,
    ) -> Result<(), SddExecutionError> {
        latch.validate()?;
        if let Some(stored) = self
            .latches
            .get(&(latch.project_id(), latch.execution_id()))
        {
            PlanChangeLatch::ensure_advance(stored, latch)?;
        }
        self.latches
            .insert((latch.project_id(), latch.execution_id()), latch.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

/// What one pre-side-effect check decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanGateDecision {
    /// The observed plan is still the approved one (and no latch is open).
    Proceed,
    /// New dispatch and commit must stop.
    Blocked {
        /// The durable latch that holds the execution.
        latch: Box<PlanChangeLatch>,
        /// Whether the file currently carries the approved bytes again. The latch
        /// stays open regardless.
        restored: bool,
    },
}

impl PlanGateDecision {
    /// The blocking latch, when the decision blocks.
    pub fn latch(&self) -> Option<&PlanChangeLatch> {
        match self {
            Self::Proceed => None,
            Self::Blocked { latch, .. } => Some(latch),
        }
    }

    /// Whether the decision permits the side effect.
    pub const fn is_proceed(&self) -> bool {
        matches!(self, Self::Proceed)
    }
}

/// One pre-side-effect and periodic plan check.
///
/// The coordinator calls [`Self::check_before_side_effect`] before dispatch,
/// before it accepts a Task's verification for completion, and immediately
/// before the host commit. The host pump also calls it once per second, so a
/// dropped watcher notification cannot hide a change.
pub trait PlanChangeGatePort {
    /// Observes the plan and returns whether the side effect may run.
    ///
    /// A detected change is persisted in the latch before this returns.
    fn check_before_side_effect(
        &mut self,
        execution_id: ExecutionId,
        approval_id: ApprovalId,
        approval: &PlanApproval,
    ) -> Result<PlanGateDecision, SddExecutionError>;
}

/// The 1 s periodic reconciliation schedule of one gate.
///
/// The schedule is explicit so a test can drive it with a fake clock and prove
/// that the periodic path catches a change with no watcher notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileSchedule {
    interval_millis: u64,
    last_millis: Option<u64>,
    forced: bool,
}

impl ReconcileSchedule {
    /// Creates a schedule with [`PLAN_RECONCILE_INTERVAL_MILLIS`].
    pub const fn new() -> Self {
        Self {
            interval_millis: PLAN_RECONCILE_INTERVAL_MILLIS,
            last_millis: None,
            forced: false,
        }
    }

    /// Creates a schedule with an explicit interval; zero is refused.
    pub fn with_interval(interval_millis: u64) -> Result<Self, SddExecutionError> {
        if interval_millis == 0 {
            return Err(invalid(
                "planReconcile.intervalMillis",
                "must be greater than zero",
            ));
        }
        Ok(Self {
            interval_millis,
            last_millis: None,
            forced: false,
        })
    }

    /// The interval in milliseconds.
    pub const fn interval_millis(&self) -> u64 {
        self.interval_millis
    }

    /// Whether one reconciliation is due at `now`.
    ///
    /// The first call is always due, so a restored process reconciles before it
    /// trusts anything.
    pub fn due(&self, now: Timestamp) -> bool {
        self.forced
            || self.last_millis.is_none_or(|last| {
                now.as_unix_millis().saturating_sub(last) >= self.interval_millis
            })
    }

    /// Notes a watcher notification, which makes the next reconciliation
    /// immediate. A notification never replaces the periodic check.
    pub fn note_signal(&mut self) {
        self.forced = true;
    }

    /// Records one completed reconciliation at `now`.
    pub fn mark(&mut self, now: Timestamp) {
        self.last_millis = Some(now.as_unix_millis());
        self.forced = false;
    }
}

impl Default for ReconcileSchedule {
    fn default() -> Self {
        Self::new()
    }
}

/// The deterministic plan-change gate over the plan source, latch store, and
/// clock ports.
#[derive(Debug)]
pub struct PlanChangeGate<S, L, C> {
    source: S,
    latches: L,
    clock: C,
    candidates: Vec<PlanPath>,
    schedule: ReconcileSchedule,
}

impl<S, L, C> PlanChangeGate<S, L, C> {
    /// Creates a gate over its ports.
    pub const fn new(source: S, latches: L, clock: C) -> Self {
        Self {
            source,
            latches,
            clock,
            candidates: Vec::new(),
            schedule: ReconcileSchedule::new(),
        }
    }

    /// Replaces the periodic interval.
    #[must_use]
    pub fn with_schedule(mut self, schedule: ReconcileSchedule) -> Self {
        self.schedule = schedule;
        self
    }

    /// The plan source.
    pub const fn source(&self) -> &S {
        &self.source
    }

    /// The latch store.
    pub const fn latches(&self) -> &L {
        &self.latches
    }

    /// The mutable latch store.
    pub const fn latches_mut(&mut self) -> &mut L {
        &mut self.latches
    }

    /// The clock.
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    /// The reconciliation schedule.
    pub const fn schedule(&self) -> &ReconcileSchedule {
        &self.schedule
    }

    /// The mutable reconciliation schedule.
    pub const fn schedule_mut(&mut self) -> &mut ReconcileSchedule {
        &mut self.schedule
    }

    /// The candidate paths probed for a move.
    pub fn candidates(&self) -> &[PlanPath] {
        &self.candidates
    }

    /// Notes one host-observed candidate path a moved plan may now live at.
    ///
    /// Duplicates are ignored and the list stays bounded by
    /// [`MAX_MOVE_CANDIDATES`], so one directory listing cannot make a
    /// pre-side-effect check unbounded.
    pub fn note_candidate(&mut self, path: PlanPath) {
        if self.candidates.contains(&path) || self.candidates.len() >= MAX_MOVE_CANDIDATES {
            return;
        }
        self.candidates.push(path);
        self.candidates.sort();
    }
}

impl<S, L, C> PlanChangeGate<S, L, C>
where
    S: PlanSourcePort,
    L: PlanChangeLatchStorePort,
    C: ClockPort,
{
    /// Loads the current latch.
    pub fn latch(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<PlanChangeLatch>, SddExecutionError> {
        self.latches.plan_change_latch(project_id, execution_id)
    }

    /// Observes the plan and answers whether a side effect may run.
    ///
    /// Order: an already open latch blocks first (the stored stop is history and
    /// is never cleared by the file), then an unstable observation, then a
    /// missing or moved plan, then a byte change. The new latch is persisted
    /// before the decision is returned.
    pub fn check(
        &mut self,
        execution_id: ExecutionId,
        approval_id: ApprovalId,
        approval: &PlanApproval,
    ) -> Result<PlanGateDecision, SddExecutionError> {
        let project_id = execution_id.project_id();
        let expectation = PlanExpectation::new(
            approval.plan_path().clone(),
            approval.digest().clone(),
            approval.byte_length(),
            approval.plan_revision(),
        );
        let stored = self.latches.plan_change_latch(project_id, execution_id)?;
        if let Some(latch) = &stored
            && latch.is_open()
        {
            // An open latch belongs to the plan revision it was engaged against;
            // reading it against different approved bytes would let a stale stop
            // hold or release the wrong version.
            latch.ensure_matches_approval(approval_id, approval)?;
            // An open latch is the stop. The file may have returned to the
            // approved bytes; that restores nothing. A fresh observation is only
            // reported, never used to clear the stop.
            let restored = self
                .source
                .observe(project_id, approval.plan_path())
                .map(|observation| expectation.matches(&observation))
                .unwrap_or(false);
            return Ok(PlanGateDecision::Blocked {
                latch: Box::new(latch.clone()),
                restored,
            });
        }

        let observation = self.source.observe(project_id, approval.plan_path())?;
        let Some(change) = self.change_of(&observation, &expectation, project_id)? else {
            return Ok(PlanGateDecision::Proceed);
        };
        let latch =
            PlanChangeLatch::engage(project_id, execution_id, approval_id, expectation, change)?;
        self.latches.record_plan_change_latch(&latch)?;
        Ok(PlanGateDecision::Blocked {
            latch: Box::new(latch),
            restored: false,
        })
    }

    /// Runs the periodic reconciliation when it is due.
    ///
    /// `None` means "not due yet"; the caller retries at the next tick. The
    /// decision is the same as [`Self::check`], so a lost notification is
    /// detected by the periodic path alone.
    pub fn reconcile(
        &mut self,
        now: Timestamp,
        execution_id: ExecutionId,
        approval_id: ApprovalId,
        approval: &PlanApproval,
    ) -> Result<Option<PlanGateDecision>, SddExecutionError> {
        if !self.schedule.due(now) {
            return Ok(None);
        }
        let decision = self.check(execution_id, approval_id, approval)?;
        self.schedule.mark(now);
        Ok(Some(decision))
    }

    /// The change one observation represents, or `None` when it still matches.
    fn change_of(
        &self,
        observation: &PlanObservation,
        expectation: &PlanExpectation,
        project_id: ProjectId,
    ) -> Result<Option<PlanChange>, SddExecutionError> {
        if !observation.is_stable() && observation.digest().is_some() {
            let change = PlanChange::from_observation(
                PlanChangeReason::UnstableObservation,
                observation,
                None,
            )?;
            return Ok(Some(change));
        }
        let Some(digest) = observation.digest() else {
            // The approved path is unreadable. A host-known candidate that does
            // exist is a move; otherwise it is simply missing.
            for candidate in &self.candidates {
                if candidate == expectation.plan_path() {
                    continue;
                }
                if let Ok(candidate_observation) = self.source.observe(project_id, candidate)
                    && candidate_observation.is_stable()
                    && candidate_observation.digest().is_some()
                {
                    return Ok(Some(PlanChange::from_observation(
                        PlanChangeReason::Moved,
                        observation,
                        Some(candidate.clone()),
                    )?));
                }
            }
            let change =
                PlanChange::from_observation(PlanChangeReason::Missing, observation, None)?;
            return Ok(Some(change));
        };
        if expectation.matches(observation) {
            return Ok(None);
        }
        let change =
            PlanChange::from_observation(PlanChangeReason::BytesChanged, observation, None)?;
        debug_assert_eq!(change.observed_digest(), Some(digest));
        Ok(Some(change))
    }
}

impl<S, L, C> PlanChangeGatePort for PlanChangeGate<S, L, C>
where
    S: PlanSourcePort,
    L: PlanChangeLatchStorePort,
    C: ClockPort,
{
    fn check_before_side_effect(
        &mut self,
        execution_id: ExecutionId,
        approval_id: ApprovalId,
        approval: &PlanApproval,
    ) -> Result<PlanGateDecision, SddExecutionError> {
        self.check(execution_id, approval_id, approval)
    }
}

// ---------------------------------------------------------------------------
// Applying a change to the durable snapshot
// ---------------------------------------------------------------------------

/// The stop record one plan change requires.
pub fn plan_change_stop(change: &PlanChange) -> Result<StopRecord, SddExecutionError> {
    StopRecord::new(change.stop_reason(), Some(HumanAction::ResolvePlanChange))
}

/// Marks the current application stale and holds the execution for a human.
///
/// Every Task progression, commit range, no-change record, evidence reference,
/// baseline, and consumed budget is carried over unchanged, so history is never
/// erased. A post-completion change leaves the recorded completions intact and
/// only the applied revision becomes [`AppliedRevisionState::Stale`].
pub fn stale_application(
    snapshot: &ExecutionSnapshot,
    revision: ExecutionRevision,
    change: &PlanChange,
) -> Result<ExecutionSnapshot, SddExecutionError> {
    let held = snapshot.held_waiting_human(revision, plan_change_stop(change)?)?;
    let applied = snapshot.applied_revision();
    let applied = match (applied.state(), applied.revision()) {
        (AppliedRevisionState::Current, Some(revision)) => AppliedRevision::stale(revision),
        _ => applied,
    };
    held.with_applied_revision(revision, applied)
}

/// Persists one stale-application hold under a request ID.
pub fn hold_stale_application(
    store: &mut dyn ExecutionStorePort,
    snapshot: &ExecutionSnapshot,
    request_id: ControlRequestId,
    change: &PlanChange,
) -> Result<ExecutionSnapshot, SddExecutionError> {
    let next = stale_application(snapshot, snapshot.revision().next(), change)?;
    let request = ExecutionOperationRequest::new(
        snapshot.project_id(),
        snapshot.execution_id(),
        request_id,
        snapshot.revision(),
        ExecutionOperation::Pause,
    )?;
    let result = ExecutionOperationResult::new(ExecutionOperation::Pause, next.clone())?;
    let record = request.recorded(result)?;
    store.commit_operation(
        snapshot.project_id(),
        snapshot.execution_id(),
        Some(snapshot.revision()),
        &next,
        &record,
    )?;
    Ok(next)
}

/// Confirms a plan-change safety stop, moving `waiting_human` to `stopped`.
///
/// The stop record is retained: its required action is still the human plan
/// revision approval. A re-approval request requires this confirmed stop, so a
/// stop that is only requested is never treated as confirmed.
pub fn confirm_plan_stop(
    snapshot: &ExecutionSnapshot,
    revision: ExecutionRevision,
) -> Result<ExecutionSnapshot, SddExecutionError> {
    if snapshot.state() == crate::state::ExecutionState::Stopped {
        return Ok(snapshot.clone());
    }
    let stop = snapshot
        .stop()
        .ok_or_else(|| SddExecutionError::InvalidSnapshot {
            field: "snapshot.stop".to_owned(),
            detail: "a plan-change hold must record its stop".to_owned(),
        })?;
    if !is_plan_change_reason(stop.reason()) {
        return Err(SddExecutionError::InvalidSnapshot {
            field: "snapshot.stop.reason".to_owned(),
            detail: "only a plan-change hold can be confirmed as a plan-change stop".to_owned(),
        });
    }
    let state = snapshot
        .state()
        .transition_to(crate::state::ExecutionState::Stopped)?;
    ExecutionSnapshot::new(SnapshotInput {
        project_id: snapshot.project_id(),
        execution_id: snapshot.execution_id(),
        revision,
        state,
        plan: snapshot.plan().clone(),
        workspace: snapshot.workspace().clone(),
        current_task: snapshot.current_task(),
        tasks: snapshot.tasks().to_vec(),
        stop: Some(stop),
        budget: snapshot.budget(),
        applied_revision: snapshot.applied_revision(),
        final_project_sequence: snapshot.final_project_sequence(),
    })
}

fn is_plan_change_reason(reason: StopReason) -> bool {
    matches!(
        reason,
        StopReason::PlanChanged
            | StopReason::PlanMissing
            | StopReason::PlanMoved
            | StopReason::PlanObservationUnstable
    )
}

/// Confirms a plan-change stop and persists it under a request ID.
///
/// The request is idempotent: a re-delivery returns the stored result instead of
/// writing a second confirmation. A stop of another kind is refused, and an
/// already-confirmed stop is returned unchanged.
pub fn confirm_plan_change_stop(
    store: &mut dyn ExecutionStorePort,
    snapshot: &ExecutionSnapshot,
    request_id: ControlRequestId,
) -> Result<ExecutionSnapshot, SddExecutionError> {
    let project = snapshot.project_id();
    let execution = snapshot.execution_id();
    if let Some(record) = store.operation_record(project, execution, request_id)?
        && let Some(result) = record.outcome()
    {
        return Ok(result.snapshot().clone());
    }
    if snapshot.state() == crate::state::ExecutionState::Stopped {
        return Ok(snapshot.clone());
    }
    let next = confirm_plan_stop(snapshot, snapshot.revision().next())?;
    let request = ExecutionOperationRequest::new(
        project,
        execution,
        request_id,
        snapshot.revision(),
        ExecutionOperation::Pause,
    )?;
    let result = ExecutionOperationResult::new(ExecutionOperation::Pause, next.clone())?;
    let record = request.recorded(result)?;
    store.commit_operation(
        project,
        execution,
        Some(snapshot.revision()),
        &next,
        &record,
    )?;
    Ok(next)
}

// ---------------------------------------------------------------------------
// Limited re-approval inheritance
// ---------------------------------------------------------------------------

/// One Task's progression, as the re-approval rule reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskProgress {
    number: u32,
    progression: TaskProgression,
}

impl TaskProgress {
    /// Records one Task's progression.
    pub const fn new(number: u32, progression: TaskProgression) -> Self {
        Self {
            number,
            progression,
        }
    }

    /// Reads every Task's progression from a snapshot.
    pub fn from_snapshot(snapshot: &ExecutionSnapshot) -> Vec<Self> {
        snapshot
            .tasks()
            .iter()
            .map(|task| Self::new(task.task().number().get(), task.progression()))
            .collect()
    }

    /// Plan-assigned number.
    pub const fn number(self) -> u32 {
        self.number
    }

    /// Progression.
    pub const fn progression(self) -> TaskProgression {
        self.progression
    }

    /// Whether the Task is not started (no child, no work).
    pub const fn is_pending(self) -> bool {
        matches!(self.progression, TaskProgression::Pending)
    }
}

/// One part of a Task's approved contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractPart {
    /// The exact Task body.
    Body,
    /// The Task heading title.
    Title,
    /// Conditions (id, title, rubric, mode).
    Conditions,
    /// Bounded read/write scope and shell permission.
    Scope,
    /// Checks (command, cwd, timeout, input paths).
    Checks,
    /// Declared HTML targets.
    HtmlTargets,
    /// Finite budget.
    Budget,
    /// Commit policy.
    CommitPolicy,
    /// Declared deliverables.
    Deliverables,
}

impl ContractPart {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Body => "body",
            Self::Title => "title",
            Self::Conditions => "conditions",
            Self::Scope => "scope",
            Self::Checks => "checks",
            Self::HtmlTargets => "html_targets",
            Self::Budget => "budget",
            Self::CommitPolicy => "commit_policy",
            Self::Deliverables => "deliverables",
        }
    }
}

/// Why a new plan version cannot be inherited by the existing execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum PlanInheritanceBlocker {
    /// The approved plan path changed. Task stable identity is derived from it,
    /// so a move always requires a new execution.
    PlanPathChanged {
        /// Approved path.
        approved: String,
        /// New path.
        found: String,
    },
    /// The exact Global Constraints text changed.
    GlobalConstraintsChanged {
        /// Byte ranges of the changed text in the new plan.
        ranges: Vec<PlanByteRange>,
    },
    /// The root spec reference list changed.
    RootSpecRefsChanged {
        /// Non-secret detail naming the first difference.
        detail: String,
    },
    /// The plan schema version changed.
    SchemaVersionChanged {
        /// Approved version.
        approved: u32,
        /// New version.
        found: u32,
    },
    /// A completed or started Task changed.
    TaskChanged {
        /// Plan-assigned number.
        number: u32,
        /// Progression of that Task in the execution.
        progression: TaskProgression,
        /// Contract part that changed.
        part: ContractPart,
    },
    /// A completed or started Task disappeared from the new plan.
    TaskRemoved {
        /// Plan-assigned number.
        number: u32,
        /// Progression of that Task in the execution.
        progression: TaskProgression,
    },
    /// The last Task's final check list changed while that Task is not pending.
    FinalChecksChanged,
}

impl std::fmt::Display for PlanInheritanceBlocker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlanPathChanged { approved, found } => {
                write!(formatter, "plan path changed from {approved} to {found}")
            }
            Self::GlobalConstraintsChanged { .. } => {
                formatter.write_str("Global Constraints changed")
            }
            Self::RootSpecRefsChanged { detail } => {
                write!(formatter, "root spec refs changed: {detail}")
            }
            Self::SchemaVersionChanged { approved, found } => {
                write!(
                    formatter,
                    "plan schema version changed from {approved} to {found}"
                )
            }
            Self::TaskChanged {
                number,
                progression,
                part,
            } => write!(
                formatter,
                "Task {number} is {} and its {} changed",
                progression.as_str(),
                part.as_str()
            ),
            Self::TaskRemoved {
                number,
                progression,
            } => write!(
                formatter,
                "Task {number} is {} and was removed from the plan",
                progression.as_str()
            ),
            Self::FinalChecksChanged => formatter
                .write_str("the final check list changed while the last Task is not pending"),
        }
    }
}

/// What changed between two plan versions of one execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InheritableRevision {
    changed_tasks: Vec<u32>,
    added_tasks: Vec<u32>,
    removed_tasks: Vec<u32>,
    spec_snapshot_changed: bool,
}

impl InheritableRevision {
    /// Pending Task numbers whose body or contract changed.
    pub fn changed_tasks(&self) -> &[u32] {
        &self.changed_tasks
    }

    /// Task numbers added by the new version.
    pub fn added_tasks(&self) -> &[u32] {
        &self.added_tasks
    }

    /// Pending Task numbers removed by the new version.
    pub fn removed_tasks(&self) -> &[u32] {
        &self.removed_tasks
    }

    /// Whether any approved spec snapshot digest changed. The human approves the
    /// new references with this revision; it is not a blocker by itself.
    pub const fn spec_snapshot_changed(&self) -> bool {
        self.spec_snapshot_changed
    }
}

/// Whether a new plan version can be inherited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum PlanInheritance {
    /// Only not-yet-started Tasks changed and every fixed part is unchanged.
    Inheritable(InheritableRevision),
    /// At least one fixed part changed; a new plan and human work-state cleanup
    /// are required.
    Incompatible {
        /// Every reason, so one human decision can address them all.
        blockers: Vec<PlanInheritanceBlocker>,
    },
}

impl PlanInheritance {
    /// Whether the new version may be inherited after human approval.
    pub const fn is_inheritable(&self) -> bool {
        matches!(self, Self::Inheritable(_))
    }

    /// The blockers, empty when inheritable.
    pub fn blockers(&self) -> &[PlanInheritanceBlocker] {
        match self {
            Self::Inheritable(_) => &[],
            Self::Incompatible { blockers } => blockers,
        }
    }
}

/// Evaluates the limited re-approval rule.
///
/// Inheritable only when the plan path, the exact Global Constraints text, the
/// root spec reference list, and the body plus structured contract of every
/// completed or started Task are unchanged. Changes confined to not-yet-started
/// Tasks (including adding or removing them) are permitted. Everything else is
/// incompatible: the existing execution never migrates automatically, and no
/// recorded history or consumed budget is reset.
pub fn evaluate_inheritance(
    previous: &ApprovalContent,
    next: &ApprovalContent,
    progress: &[TaskProgress],
) -> PlanInheritance {
    let mut blockers = Vec::new();
    let previous_plan = previous.plan();
    let next_plan = next.plan();

    if previous_plan.plan_path() != next_plan.plan_path() {
        blockers.push(PlanInheritanceBlocker::PlanPathChanged {
            approved: previous_plan.plan_path().as_str().to_owned(),
            found: next_plan.plan_path().as_str().to_owned(),
        });
    }
    if previous_plan.parsed().schema_version() != next_plan.parsed().schema_version() {
        blockers.push(PlanInheritanceBlocker::SchemaVersionChanged {
            approved: previous_plan.parsed().schema_version(),
            found: next_plan.parsed().schema_version(),
        });
    }
    if previous_plan.parsed().global_constraints().text()
        != next_plan.parsed().global_constraints().text()
    {
        blockers.push(PlanInheritanceBlocker::GlobalConstraintsChanged {
            ranges: vec![next_plan.parsed().global_constraints().byte_range()],
        });
    }
    if let Some(detail) = spec_refs_difference(previous_plan.spec_refs(), next_plan.spec_refs()) {
        blockers.push(PlanInheritanceBlocker::RootSpecRefsChanged { detail });
    }

    let progression = |number: u32| -> TaskProgression {
        progress
            .iter()
            .find(|task| task.number == number)
            .map_or(TaskProgression::Pending, |task| task.progression)
    };

    for previous_task in previous.tasks() {
        let number = previous_task.task().number().get();
        let task_progress = progression(number);
        if task_progress == TaskProgression::Pending {
            continue;
        }
        let Some(next_task) = next
            .tasks()
            .iter()
            .find(|task| task.task().number().get() == number)
        else {
            blockers.push(PlanInheritanceBlocker::TaskRemoved {
                number,
                progression: task_progress,
            });
            continue;
        };
        for part in changed_parts(previous_plan, previous_task, next_plan, next_task) {
            blockers.push(PlanInheritanceBlocker::TaskChanged {
                number,
                progression: task_progress,
                part,
            });
        }
    }

    // The final check list belongs to the last Task's completion contract.
    let previous_final = previous_plan.parsed().final_check_ids();
    let next_final = next_plan.parsed().final_check_ids();
    if previous_final != next_final {
        let last = previous
            .tasks()
            .iter()
            .map(|task| task.task().number().get())
            .max()
            .unwrap_or_default();
        if progression(last) != TaskProgression::Pending {
            blockers.push(PlanInheritanceBlocker::FinalChecksChanged);
        }
    }

    if !blockers.is_empty() {
        return PlanInheritance::Incompatible { blockers };
    }

    let mut changed_tasks = Vec::new();
    let mut removed_tasks = Vec::new();
    for previous_task in previous.tasks() {
        let number = previous_task.task().number().get();
        if progression(number) != TaskProgression::Pending {
            continue;
        }
        match next
            .tasks()
            .iter()
            .find(|task| task.task().number().get() == number)
        {
            Some(next_task) => {
                if !changed_parts(previous_plan, previous_task, next_plan, next_task).is_empty() {
                    changed_tasks.push(number);
                }
            }
            None => removed_tasks.push(number),
        }
    }
    let mut added_tasks: Vec<u32> = next
        .tasks()
        .iter()
        .map(|task| task.task().number().get())
        .filter(|number| {
            !previous
                .tasks()
                .iter()
                .any(|task| task.task().number().get() == *number)
        })
        .collect();
    added_tasks.sort_unstable();
    let spec_snapshot_changed = previous_plan.spec_refs() != next_plan.spec_refs();

    PlanInheritance::Inheritable(InheritableRevision {
        changed_tasks,
        added_tasks,
        removed_tasks,
        spec_snapshot_changed,
    })
}

fn spec_refs_difference(
    previous: &[crate::approval::ApprovedSpecRef],
    next: &[crate::approval::ApprovedSpecRef],
) -> Option<String> {
    if previous.len() != next.len() {
        return Some(format!(
            "{} references became {}",
            previous.len(),
            next.len()
        ));
    }
    for (approved, found) in previous.iter().zip(next) {
        if approved.source() != found.source()
            || approved.path() != found.path()
            || approved.sections() != found.sections()
        {
            return Some(format!(
                "{} {} is not the approved reference",
                found.source(),
                found.path()
            ));
        }
    }
    None
}

fn changed_parts(
    previous_plan: &PlanApproval,
    previous: &TaskApproval,
    next_plan: &PlanApproval,
    next: &TaskApproval,
) -> Vec<ContractPart> {
    let number = previous.task().number().get();
    let mut parts = Vec::new();
    if task_body(previous_plan, number) != task_body(next_plan, number) {
        parts.push(ContractPart::Body);
    }
    if previous.title() != next.title() {
        parts.push(ContractPart::Title);
    }
    if previous.conditions() != next.conditions() {
        parts.push(ContractPart::Conditions);
    }
    if previous.scope() != next.scope() {
        parts.push(ContractPart::Scope);
    }
    if previous.checks() != next.checks() {
        parts.push(ContractPart::Checks);
    }
    if previous.html_targets() != next.html_targets() {
        parts.push(ContractPart::HtmlTargets);
    }
    if previous.budget() != next.budget() {
        parts.push(ContractPart::Budget);
    }
    if previous.commit_policy() != next.commit_policy() {
        parts.push(ContractPart::CommitPolicy);
    }
    if previous.deliverables() != next.deliverables() {
        parts.push(ContractPart::Deliverables);
    }
    parts
}

fn task_body(plan: &PlanApproval, number: u32) -> Option<&str> {
    plan.parsed()
        .tasks()
        .iter()
        .find(|task| task.number() == number)
        .map(|task| task.body().text())
}

// ---------------------------------------------------------------------------
// Approve a plan revision
// ---------------------------------------------------------------------------

/// The durable ports one re-approval needs.
pub trait PlanRevisionStorePort:
    ExecutionStorePort + ApprovalRevisionStorePort + PlanChangeLatchStorePort
{
}

impl<T: ExecutionStorePort + ApprovalRevisionStorePort + PlanChangeLatchStorePort>
    PlanRevisionStorePort for T
{
}

/// One human request to approve a changed plan after a confirmed stop.
#[derive(Debug, Clone)]
pub struct PlanRevisionApproval {
    identity: RequestIdentity<crate::ids::ControlKind>,
    approval_id: ApprovalId,
    expected_approval_revision: u64,
    content: ApprovalContent,
    approved_at: Timestamp,
}

/// The execution, request, revision, and approval a re-approval acts on.
///
/// It exists so a trusted command layer can name the request guard without
/// re-deriving the plan content. The identity is checked again by
/// [`PlanRevisionApproval::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanRevisionIdentity {
    project_id: ProjectId,
    execution_id: ExecutionId,
    request_id: ControlRequestId,
    expected_revision: ExecutionRevision,
    approval_id: ApprovalId,
    expected_approval_revision: u64,
}

impl PlanRevisionIdentity {
    /// Creates one identity and validates every project binding.
    pub fn new(
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
        expected_revision: ExecutionRevision,
        approval_id: ApprovalId,
        expected_approval_revision: u64,
    ) -> Result<Self, SddExecutionError> {
        execution_id.validate_in(project_id)?;
        request_id.validate_in(project_id)?;
        if approval_id.project_id() != project_id {
            return Err(SddExecutionError::CrossProjectReference {
                id_kind: "plan revision approval".to_owned(),
                expected: project_id,
                found: approval_id.project_id(),
            });
        }
        if expected_approval_revision == 0 {
            return Err(invalid(
                "planRevision.expectedApprovalRevision",
                "approval revisions start at one",
            ));
        }
        Ok(Self {
            project_id,
            execution_id,
            request_id,
            expected_revision,
            approval_id,
            expected_approval_revision,
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

    /// Idempotent update request.
    pub const fn request_id(self) -> ControlRequestId {
        self.request_id
    }

    /// Execution revision the caller expects.
    pub const fn expected_revision(self) -> ExecutionRevision {
        self.expected_revision
    }

    /// Approval identity the revision belongs to.
    pub const fn approval_id(self) -> ApprovalId {
        self.approval_id
    }

    /// Approval revision the human based this decision on.
    pub const fn expected_approval_revision(self) -> u64 {
        self.expected_approval_revision
    }
}

impl PlanRevisionApproval {
    /// Builds one request from a trusted human post.
    ///
    /// The post already proved that its content is the observed current input
    /// and that the actor is human and the source is the registry; the operation
    /// repeats the observation check before it writes anything.
    pub fn new(
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
        expected_revision: ExecutionRevision,
        approval_id: ApprovalId,
        expected_approval_revision: u64,
        post: &StartApprovalPost,
    ) -> Result<Self, SddExecutionError> {
        post.content().validate(project_id)?;
        if post.approval_id() != approval_id {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject,
            });
        }
        if expected_approval_revision == 0 {
            return Err(invalid(
                "planRevision.expectedApprovalRevision",
                "approval revisions start at one",
            ));
        }
        Ok(Self {
            identity: RequestIdentity::new(
                project_id,
                execution_id,
                request_id,
                expected_revision,
            )?,
            approval_id,
            expected_approval_revision,
            content: post.content().clone(),
            approved_at: post.approved_at(),
        })
    }

    /// The request guard.
    pub const fn identity(&self) -> &RequestIdentity<crate::ids::ControlKind> {
        &self.identity
    }

    /// Builds one request from a trusted human post and a request identity.
    ///
    /// The post already proved that its content is the observed current input
    /// and that the actor is human and the source is the registry.
    pub fn from_identity(
        identity: PlanRevisionIdentity,
        post: &StartApprovalPost,
    ) -> Result<Self, SddExecutionError> {
        post.content().validate(identity.project_id())?;
        if post.approval_id() != identity.approval_id {
            return Err(SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject,
            });
        }
        Ok(Self {
            identity: RequestIdentity::new(
                identity.project_id,
                identity.execution_id,
                identity.request_id,
                identity.expected_revision,
            )?,
            approval_id: identity.approval_id,
            expected_approval_revision: identity.expected_approval_revision,
            content: post.content().clone(),
            approved_at: post.approved_at(),
        })
    }

    /// Approval identity the revision belongs to.
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// Approval revision the human based this decision on.
    pub const fn expected_approval_revision(&self) -> u64 {
        self.expected_approval_revision
    }

    /// The human-approved content of the new revision.
    pub const fn content(&self) -> &ApprovalContent {
        &self.content
    }

    /// When the human confirmed it.
    pub const fn approved_at(&self) -> Timestamp {
        self.approved_at
    }

    fn record(&self) -> Result<ControlRecord, SddExecutionError> {
        let content = RevisionContent {
            approval_id: self.approval_id,
            content: &self.content,
        };
        let intent = ControlRecord::intent(self.identity, &content)?;
        Ok(intent)
    }
}

/// Idempotency content of one re-approval: the approval identity plus the whole
/// approved content. Two requests with the same ID but another plan are refused
/// instead of being answered with the earlier result.
#[derive(Serialize)]
struct RevisionContent<'a> {
    approval_id: ApprovalId,
    content: &'a ApprovalContent,
}

impl JournalContent for RevisionContent<'_> {
    fn content_fingerprint(&self) -> Result<RequestFingerprint, SddExecutionError> {
        let bytes = serde_json::to_vec(self).map_err(|error| SddExecutionError::InvalidValue {
            field: "planRevision.content".to_owned(),
            detail: format!("could not encode the approved content: {error}"),
        })?;
        Ok(RequestFingerprint::sha256(&bytes))
    }
}

/// What one re-approval decided.
#[derive(Debug, Clone, PartialEq)]
pub enum PlanRevisionOutcome {
    /// The new approval revision is saved, the latch is cleared, and the
    /// execution waits for the human resume.
    Approved {
        /// Newly saved (or already equal) approval revision.
        approval: Box<ExecutionApproval>,
        /// Resulting durable snapshot.
        snapshot: Box<ExecutionSnapshot>,
        /// Resulting execution revision.
        revision: ExecutionRevision,
        /// What the human approved about the new version.
        inheritance: PlanInheritance,
    },
    /// The same request was already applied; its stored result is returned.
    Replayed {
        /// Stored execution revision.
        revision: ExecutionRevision,
        /// Approval revision that was saved.
        approval_revision: u64,
    },
    /// The new version cannot be inherited. Nothing was written.
    Refused {
        /// Every reason, so one decision can address them all.
        blockers: Vec<PlanInheritanceBlocker>,
        /// The latch that still holds the execution.
        latch: Box<PlanChangeLatch>,
    },
}

impl PlanRevisionOutcome {
    /// Whether the new revision was saved.
    pub const fn is_approved(&self) -> bool {
        matches!(self, Self::Approved { .. })
    }
}

/// Approves one changed plan revision after a confirmed stop.
///
/// # Order
///
/// 1. A re-delivered request returns its stored result (or a content conflict)
///    before anything else.
/// 2. The expected execution revision and the expected approval revision are
///    checked before any side effect.
/// 3. The latch must be open, the execution must be `stopped` (a stop that is
///    only requested or waiting is `recovery_required`), and the stored plan
///    identity must be the latched one.
/// 4. The observed inputs must still match the human-approved content, the plan
///    revision must advance, and the workspace identity must not change.
/// 5. Inheritance is evaluated. An incompatible version returns
///    [`PlanRevisionOutcome::Refused`] with every blocker and writes nothing.
/// 6. The approval revision, the snapshot, and the control record are saved; the
///    latch is cleared last, and a replay of step 6 reconciles it.
///
/// Every Task progression, commit range, no-change record, evidence reference,
/// and the whole consumed budget are carried into the new snapshot unchanged, so
/// a re-approval never resets history or budget.
pub fn approve_plan_revision(
    store: &mut dyn PlanRevisionStorePort,
    request: &PlanRevisionApproval,
    inputs: &ApprovalInputs,
) -> Result<PlanRevisionOutcome, SddExecutionError> {
    let identity = *request.identity();
    let project = identity.project_id();
    let execution = identity.execution_id();
    let request_id = identity.request_id();

    // 1. A re-delivered request is answered from the store.
    if let Some(record) = store.operation_record(project, execution, request_id)? {
        let content = RevisionContent {
            approval_id: request.approval_id,
            content: &request.content,
        };
        let supplied = content.content_fingerprint()?;
        if record.fingerprint() != &supplied {
            return Err(SddExecutionError::DuplicateRequestConflict {
                recorded: record.fingerprint().to_string(),
                supplied: supplied.to_string(),
            });
        }
        let Some(result) = record.outcome() else {
            return Err(SddExecutionError::RecoveryRequired {
                reason: crate::state::RecoveryReason::UnknownRequest,
                details: crate::error::FailureDetails::none().boxed(),
            });
        };
        let stored_snapshot = result.snapshot().clone();
        reconcile_cleared_latch(store, &stored_snapshot)?;
        let approval_revision = store
            .latest_approval_revision(project, request.approval_id)?
            .map(|approval| approval.revision())
            .ok_or_else(|| SddExecutionError::RecoveryRequired {
                reason: crate::state::RecoveryReason::StateUnreadable,
                details: crate::error::FailureDetails::none().boxed(),
            })?;
        return Ok(PlanRevisionOutcome::Replayed {
            revision: result.resulting_revision(),
            approval_revision,
        });
    }

    // 2. The caller's expected revisions must be current.
    let stored =
        store
            .load(project, execution)?
            .ok_or_else(|| SddExecutionError::RecoveryRequired {
                reason: crate::state::RecoveryReason::StateUnreadable,
                details: crate::error::FailureDetails::none().boxed(),
            })?;
    let snapshot = stored.snapshot().clone();
    if stored.revision() != identity.expected_revision() {
        return Err(SddExecutionError::RevisionConflict {
            expected: identity.expected_revision(),
            found: stored.revision(),
        });
    }

    // 3. A confirmed stop and an open latch.
    let latch = store
        .plan_change_latch(project, execution)?
        .ok_or_else(|| SddExecutionError::ApprovalRequired {
            reason: crate::state::ApprovalRequirement::PlanRevisionApproval,
            details: crate::error::FailureDetails::none().boxed(),
        })?;
    latch.ensure_open()?;
    if latch.approval_id() != request.approval_id {
        return Err(SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::CurrentInputsChanged {
                field: "approvalId".to_owned(),
            },
        });
    }
    if snapshot.state() != crate::state::ExecutionState::Stopped {
        return Err(SddExecutionError::RecoveryRequired {
            reason: crate::state::RecoveryReason::StopUnconfirmed,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }
    if snapshot.plan().plan_path() != latch.expectation().plan_path()
        || snapshot.plan().digest() != latch.expectation().digest()
        || snapshot.plan().approved_revision() != latch.expectation().plan_revision()
    {
        return Err(SddExecutionError::RecoveryRequired {
            reason: crate::state::RecoveryReason::StateUnreadable,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }

    // 4. The saved approval, the observed inputs, and the new identity.
    let latest = store
        .latest_approval_revision(project, request.approval_id)?
        .ok_or_else(|| SddExecutionError::ApprovalRequired {
            reason: crate::state::ApprovalRequirement::StartApproval,
            details: crate::error::FailureDetails::none().boxed(),
        })?;
    if latest.revision() != request.expected_approval_revision {
        return Err(SddExecutionError::Conflict {
            reason: crate::state::ConflictReason::StaleRevision,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }
    if latest.plan().digest() != latch.expectation().digest()
        || latest.plan().plan_revision() != latch.expectation().plan_revision()
    {
        return Err(SddExecutionError::RecoveryRequired {
            reason: crate::state::RecoveryReason::StateUnreadable,
            details: crate::error::FailureDetails::none().boxed(),
        });
    }
    inputs.verify(&request.content)?;
    let next_plan = request.content.plan();
    if next_plan.plan_revision().get() <= latest.plan().plan_revision().get() {
        return Err(SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::RevisionNotAdvanced {
                current: latest.plan().plan_revision().get(),
                supplied: next_plan.plan_revision().get(),
            },
        });
    }
    if next_plan.plan_path() != latest.plan().plan_path() {
        return Err(SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::CurrentInputsChanged {
                field: "plan.path".to_owned(),
            },
        });
    }
    ensure_same_workspace(latest.workspace(), request.content.workspace())?;

    // 5. Limited inheritance. An incompatible version is refused before any
    //    write, so neither the old nor the new version can run from this call.
    let progress = TaskProgress::from_snapshot(&snapshot);
    let inheritance = evaluate_inheritance(latest.content(), &request.content, &progress);
    if !inheritance.is_inheritable() {
        return Ok(PlanRevisionOutcome::Refused {
            blockers: inheritance.blockers().to_vec(),
            latch: Box::new(latch),
        });
    }

    // 6. Save the approval revision, the snapshot, and the control record.
    let approval = if latest.content() == &request.content {
        latest.clone()
    } else {
        latest.revise(
            herness_supervision::ApprovalActor::Human,
            ApprovalSource::ApprovalRegistry {
                approval_id: request.approval_id,
            },
            latest.revision().saturating_add(1),
            request.approved_at,
            request.content.clone(),
        )?
    };
    store.record_approval_revision(&approval)?;

    let next_snapshot = revised_snapshot(&snapshot, &approval, &progress)?;
    let result = ExecutionOperationResult::new(
        ExecutionOperation::ApprovePlanRevision,
        next_snapshot.clone(),
    )?;
    let record = request.record()?.recorded(result);
    store.commit_operation(
        project,
        execution,
        Some(snapshot.revision()),
        &next_snapshot,
        &record,
    )?;

    let cleared = latch.cleared(
        approval.revision(),
        next_snapshot.plan().approved_revision(),
    )?;
    store.record_plan_change_latch(&cleared)?;

    Ok(PlanRevisionOutcome::Approved {
        approval: Box::new(approval),
        revision: next_snapshot.revision(),
        snapshot: Box::new(next_snapshot),
        inheritance,
    })
}

/// Clears a still-open latch after a stored approved result is replayed.
fn reconcile_cleared_latch(
    store: &mut dyn PlanRevisionStorePort,
    snapshot: &ExecutionSnapshot,
) -> Result<(), SddExecutionError> {
    let Some(latch) = store.plan_change_latch(snapshot.project_id(), snapshot.execution_id())?
    else {
        return Ok(());
    };
    if !latch.is_open() {
        return Ok(());
    }
    let cleared = latch.cleared(
        snapshot.plan().approved_revision().get(),
        snapshot.plan().approved_revision(),
    )?;
    store.record_plan_change_latch(&cleared)
}

fn ensure_same_workspace(
    approved: &crate::approval::WorkspaceApproval,
    found: &crate::approval::WorkspaceApproval,
) -> Result<(), SddExecutionError> {
    let mismatch = |field: &str| SddExecutionError::ApprovalRejected {
        reason: ApprovalRejection::WorkspaceMismatch {
            field: field.to_owned(),
        },
    };
    if approved.canonical_checkout_root() != found.canonical_checkout_root() {
        return Err(mismatch("workspace.canonicalCheckoutRoot"));
    }
    if approved.branch() != found.branch() {
        return Err(mismatch("workspace.branch"));
    }
    if approved.base_branch() != found.base_branch() {
        return Err(mismatch("workspace.baseBranch"));
    }
    if approved.isolated_worktree() != found.isolated_worktree() {
        return Err(mismatch("workspace.isolatedWorktree"));
    }
    if approved.git_identity() != found.git_identity() {
        return Err(mismatch("workspace.gitIdentity"));
    }
    if let Some(baseline) = approved.baseline()
        && found.baseline() != Some(baseline)
    {
        return Err(mismatch("workspace.baseline"));
    }
    Ok(())
}

/// Builds the post-approval snapshot: the new plan identity and applied revision,
/// the recorded progress and budget preserved, and every not-yet-started Task
/// rebuilt from the new approval.
fn revised_snapshot(
    snapshot: &ExecutionSnapshot,
    approval: &ExecutionApproval,
    progress: &[TaskProgress],
) -> Result<ExecutionSnapshot, SddExecutionError> {
    let plan = SnapshotPlan::new(
        approval.plan().plan_path().clone(),
        approval.plan().digest().clone(),
        approval.plan().plan_revision(),
    );
    let mut tasks = Vec::with_capacity(approval.tasks().len());
    for approved_task in approval.tasks() {
        let number = approved_task.task().number().get();
        let started = progress
            .iter()
            .find(|task| task.number() == number)
            .is_some_and(|task| !task.is_pending());
        if started {
            let recorded = snapshot
                .tasks()
                .iter()
                .find(|task| task.task() == approved_task.task())
                .ok_or_else(|| SddExecutionError::InvalidSnapshot {
                    field: "snapshot.tasks".to_owned(),
                    detail: "a started Task is missing from the snapshot".to_owned(),
                })?;
            tasks.push(recorded.clone());
            continue;
        }
        tasks.push(TaskSnapshot::new(
            approved_task.task(),
            TaskProgression::Pending,
            TaskPhase::Ready,
            None,
            None,
            approved_task.commit_policy(),
            None,
            None,
            Vec::new(),
            None,
            AppliedRevision::current(approval.plan().plan_revision()),
        )?);
    }
    let current_task = tasks
        .iter()
        .find(|task| task.progression() != TaskProgression::Complete)
        .map(|task| task.task());
    let stop = StopRecord::new(
        StopReason::HumanDecisionRequired,
        Some(HumanAction::ResolveHumanDecision),
    )?;
    ExecutionSnapshot::new(SnapshotInput {
        project_id: snapshot.project_id(),
        execution_id: snapshot.execution_id(),
        revision: snapshot.revision().next(),
        state: crate::state::ExecutionState::Stopped,
        plan,
        workspace: snapshot.workspace().clone(),
        current_task,
        tasks,
        stop: Some(stop),
        budget: snapshot.budget(),
        applied_revision: AppliedRevision::current(approval.plan().plan_revision()),
        final_project_sequence: snapshot.final_project_sequence(),
    })
}

fn invalid(field: &str, detail: impl Into<String>) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.into(),
    }
}

/// Exposes one Task approval's Task identity for adapters that name a Task in a
/// re-approval request.
pub fn approval_task(approval: &ApprovalContent, number: u32) -> Option<&TaskApproval> {
    approval
        .tasks()
        .iter()
        .find(|task| task.task().number().get() == number)
}

/// The Task identity of one approval Task, re-exported for symmetry with
/// [`TaskRef`] users.
pub fn approval_task_ref(approval: &ApprovalContent, number: u32) -> Option<TaskRef> {
    approval_task(approval, number).map(|task| task.task())
}
