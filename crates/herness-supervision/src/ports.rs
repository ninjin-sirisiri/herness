//! Host-owned supervision ports.
//!
//! Ports are side-effect boundaries only. This crate does not open a database,
//! call a provider, execute a verification command, or read the wall clock.
//! Later tasks supply concrete implementations.

use herness_core::contracts::{ModelRequestObservation, ProjectId, RequestGateIntent, Timestamp};

use crate::assessment::{AssessmentRequest, AssessmentResult};
use crate::budget::ledger::BudgetLedgerRecord;
use crate::command::CommandResult;
use crate::error::SupervisionError;
use crate::evidence::EvidenceRecord;
use crate::ids::{EvidenceId, SupervisionId, SupervisionRequestId};
use crate::state::SupervisionRecord;

/// Host clock. Task 9 uses an injected clock for deterministic budget tests.
pub trait ClockPort {
    /// Current wall-clock timestamp.
    fn now(&self) -> Timestamp;
}

/// Durable evidence store.
pub trait EvidenceStorePort {
    /// Appends one validated evidence record. Re-appending the same ID with
    /// the same value is idempotent; a different value conflicts.
    fn append(&mut self, evidence: EvidenceRecord) -> Result<EvidenceRecord, SupervisionError>;

    /// Reads one evidence record.
    fn get(
        &self,
        project_id: ProjectId,
        evidence_id: EvidenceId,
    ) -> Result<Option<EvidenceRecord>, SupervisionError>;

    /// Lists evidence for one supervision target in acquisition sequence.
    fn list_for_supervision(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Vec<EvidenceRecord>, SupervisionError>;
}

/// Tool-free assessment transport supplied by a later provider adapter.
///
/// Implementations must not start a normal work agent, execute tools, or send
/// more than the evidence named in the request.
pub trait AssessmentPort {
    /// Runs one per-condition assessment request.
    fn assess(&mut self, request: &AssessmentRequest)
    -> Result<AssessmentResult, SupervisionError>;
}

/// Durable supervision state with compare-and-set and idempotent command
/// results.
pub trait SupervisionStorePort {
    /// Loads the current record, if any.
    fn load(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Option<SupervisionRecord>, SupervisionError>;

    /// Creates (`None`) or updates (`Some(revision)`) a record atomically.
    ///
    /// A stale revision must be rejected without writing state. The returned
    /// value is the stored revision.
    fn compare_and_swap(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &SupervisionRecord,
    ) -> Result<u64, SupervisionError>;

    /// Returns the already recorded result for a host-owned command ID.
    fn command_result(
        &self,
        request_id: SupervisionRequestId,
    ) -> Result<Option<CommandResult>, SupervisionError>;

    /// Records a command result exactly once.
    ///
    /// Implementations must atomically bind the request ID to the result. A
    /// repeated identical result returns the stored value; a different command
    /// or result for the same ID conflicts without a second mutation. Later
    /// store code performs this in the same transaction as the state write.
    fn record_command_result(
        &mut self,
        result: &CommandResult,
    ) -> Result<CommandResult, SupervisionError>;

    /// Atomically compares the revision, writes the next record, and binds the
    /// command result.
    ///
    /// The default performs the existing two port calls in order. Durable
    /// stores should override it with one transaction so a crash cannot keep a
    /// new state revision without its recorded result.
    fn commit_command(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &SupervisionRecord,
        result: &CommandResult,
    ) -> Result<u64, SupervisionError> {
        let revision =
            self.compare_and_swap(project_id, supervision_id, expected_revision, next)?;
        self.record_command_result(result)?;
        Ok(revision)
    }
}

/// Durable budget records and atomic request-intent linkage.
///
/// A durable store commits [`BudgetStorePort::commit_budget_admission`] and
/// [`BudgetStorePort::commit_budget_observation`] in one immediate transaction
/// with the corresponding `model_requests` row. A crash therefore cannot leave
/// an admitted model request without its reservation, or a reservation for a
/// request that was never admitted.
pub trait BudgetStorePort {
    /// Loads one persisted ledger record.
    fn load_budget(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Option<StoredBudgetRecord>, SupervisionError>;

    /// Creates (`None`) or updates (`Some(revision)`) one ledger record.
    fn compare_and_swap_budget(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &BudgetLedgerRecord,
    ) -> Result<u64, SupervisionError>;

    /// Atomically writes the ledger changes and the request intent.
    fn commit_budget_admission(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &BudgetLedgerRecord,
        intent: &RequestGateIntent,
        recorded_at: Timestamp,
    ) -> Result<u64, SupervisionError>;

    /// Atomically writes the ledger changes and the request observation.
    fn commit_budget_observation(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &BudgetLedgerRecord,
        observation: &ModelRequestObservation,
        observed_at: Timestamp,
    ) -> Result<u64, SupervisionError>;
}

/// One loaded budget record with its durable revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBudgetRecord {
    revision: u64,
    record: BudgetLedgerRecord,
}

impl StoredBudgetRecord {
    /// Creates a loaded record. Revisions start at one.
    pub fn new(revision: u64, record: BudgetLedgerRecord) -> Result<Self, SupervisionError> {
        if revision == 0 {
            return Err(SupervisionError::StorageFailure {
                detail: "a durable budget revision must be positive".to_owned(),
            });
        }
        Ok(Self { revision, record })
    }

    /// Durable revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Persisted ledger payload.
    pub const fn record(&self) -> &BudgetLedgerRecord {
        &self.record
    }

    /// Consumes the wrapper and returns the payload.
    pub fn into_record(self) -> BudgetLedgerRecord {
        self.record
    }
}

/// Capability labels that later tasks may need to report as explicitly absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisionFeature {
    /// Durable supervision state.
    SupervisionStore,
    /// Evidence persistence and freshness recomputation.
    EvidenceStore,
    /// Tool-free model assessment.
    Assessment,
    /// Durable budget ledger.
    BudgetLedger,
    /// Idempotent command execution.
    CommandJournal,
}

impl SupervisionFeature {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SupervisionStore => "supervision_store",
            Self::EvidenceStore => "evidence_store",
            Self::Assessment => "assessment",
            Self::BudgetLedger => "budget_ledger",
            Self::CommandJournal => "command_journal",
        }
    }
}

/// Explicit unavailable default for a port a build does not implement yet.
pub fn unsupported(feature: SupervisionFeature) -> SupervisionError {
    SupervisionError::Unsupported {
        feature: feature.as_str().to_owned(),
    }
}
