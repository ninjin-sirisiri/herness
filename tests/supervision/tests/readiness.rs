//! Task 10: the H2 verification-readiness gate.
//!
//! Every runtime, check, assessment, evidence, budget-store, readiness, and
//! notification boundary is a deterministic fake except the one desktop test,
//! which reads a real temporary SQLite H3 store through `DesktopH4Barrier`. No
//! provider, credential, Keychain item, window, network, or external process is
//! used.
//!
//! The gate is consulted exactly at the completed-input/idle boundary. A
//! pending wait must add no verification failure, run, stagnation cycle, check,
//! assessment request, or evidence, while supervised active time keeps
//! advancing. `ready` must still run the normal required checks. A blocked wait
//! carries its reason and required action. Stop and deadline remain effective
//! while pending.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use herness_core::contracts::{
    InputId, InputPhase, InputProgress, ProjectId, RunId, RunState, Timestamp,
};
use herness_core::runtime::RecoveryMode;
use herness_desktop::html_sync::composition::DesktopH4Barrier;
use herness_desktop::sdd_execute::readiness::{DesktopH4Readiness, FixedReadinessDocuments};
use herness_desktop::supervision::store::StoreHandle;
use herness_html_sync::{
    Applicability, BarrierRequest, DocumentCommit, DocumentKey, FingerprintSet, H3ApprovalLimits,
    H3Approver, H3ConfigurationApproval, H3ConfigurationDraft, H3ConnectionApproval,
    H3DocumentState, H3OwnerBinding, H3Reason, H3Settings, H3StateReasonKind, H3StorePort,
    H3VersionBinding, HtmlSyncCommit, SettingsCommit, SourceRevision, SourceSnapshot,
    document_state_event, settings_event,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::assessment::{AssessmentRequest, AssessmentResult, ConditionVerdict};
use herness_supervision::budget::ledger::{BudgetClockPort, BudgetLedger, ClockReading};
use herness_supervision::budget::{BudgetLimit, BudgetPolicy};
use herness_supervision::command::CommandResult;
use herness_supervision::conditions::ConditionVersion;
use herness_supervision::error::SupervisionError;
use herness_supervision::evidence::{
    CheckStatus, EvidenceAcquirer, EvidenceOutcome, EvidenceRecord, EvidenceScope,
    RequiredCheckResult,
};
use herness_supervision::freshness::{
    InputOrigin, WorkspaceInput, WorkspaceSnapshotPort, input_manifest_digest,
};
use herness_supervision::ids::{CheckId, EvidenceId, SupervisionId, SupervisionRequestId};
use herness_supervision::operations::{
    HumanOperation, OperationPorts, OperationRuntimePort, SupervisionOperationRequest,
    execute_operation,
};
use herness_supervision::ports::{
    BudgetStorePort, ClockPort, EvidenceStorePort, StoredBudgetRecord, SupervisionStorePort,
};
use herness_supervision::profiles::{AssessmentProfile, ProfileUnavailable};
use herness_supervision::recovery::{
    ManagedProcessState, RecoveryCheckpoint, RecoveryFactsPort, RecoveryRuntimePort,
    RecoverySnapshot, RecoveryStopState,
};
use herness_supervision::state::{
    HumanAction, SupervisionReason, SupervisionRecord, SupervisionState,
};
use herness_supervision::supervisor::{
    AssessmentProfileFacts, CheckExecution, CheckExecutionRequest, ChildRunContinuation,
    ChildRunStart, ConditionAssessmentPort, OwnerNotificationPort, ReadinessDecision,
    ReadinessRequest, ReadinessWaitKind, RequiredCheckPort, StopDisposition,
    SupervisionRuntimePort, Supervisor, SupervisorNotification, SupervisorPhase, SupervisorPorts,
    TargetSnapshotRequest, TickOutcome, TickReport, TickRequest, VerificationReadinessPort,
    capture_target_snapshot,
};
use herness_supervision::{
    ConditionDigest, ContentDigest, DisclosureDataKind, DisclosureScope, ExecutionScope, OwnerKind,
    OwnerRef, ProfileBinding, ProfileId, ProfilePurpose, ProfileVersion, ProviderOrigin,
    TargetVersion as SupervisionTargetVersion,
};
use herness_supervision_tests::{
    assessment_result, completion_profile, contract, ids, now, project,
};
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Deterministic boundaries.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TestClock {
    millis: Rc<Cell<u64>>,
}

impl TestClock {
    fn new(millis: u64) -> Self {
        Self {
            millis: Rc::new(Cell::new(millis)),
        }
    }
}

impl ClockPort for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.millis.get())
    }
}

#[derive(Clone)]
struct TestBudgetClock {
    millis: Rc<Cell<u64>>,
    start: u64,
}

impl TestBudgetClock {
    fn new(millis: u64) -> Self {
        Self {
            millis: Rc::new(Cell::new(millis)),
            start: millis,
        }
    }

    fn advance_seconds(&self, seconds: u64) {
        self.millis
            .set(self.millis.get().saturating_add(seconds * 1_000));
    }
}

impl BudgetClockPort for TestBudgetClock {
    fn read(&self) -> ClockReading {
        let millis = self.millis.get();
        ClockReading::new(
            Timestamp::from_unix_millis(millis),
            millis.saturating_sub(self.start),
        )
    }
}

#[derive(Default)]
struct StoreState {
    record: Option<SupervisionRecord>,
    commands: BTreeMap<SupervisionRequestId, CommandResult>,
    mutations: u32,
}

#[derive(Clone, Default)]
struct TestStore {
    state: Rc<RefCell<StoreState>>,
}

impl TestStore {
    fn new(record: SupervisionRecord) -> Self {
        Self {
            state: Rc::new(RefCell::new(StoreState {
                record: Some(record),
                ..StoreState::default()
            })),
        }
    }

    fn record(&self) -> SupervisionRecord {
        self.state
            .borrow()
            .record
            .clone()
            .expect("supervision record")
    }

    fn mutations(&self) -> u32 {
        self.state.borrow().mutations
    }

    fn replace_record(&self, record: SupervisionRecord) {
        self.state.borrow_mut().record = Some(record);
    }
}

impl SupervisionStorePort for TestStore {
    fn load(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Option<SupervisionRecord>, SupervisionError> {
        if supervision_id.project_id() != project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "supervision".to_owned(),
                expected: project_id,
                found: supervision_id.project_id(),
            });
        }
        Ok(self.state.borrow().record.clone())
    }

    fn compare_and_swap(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &SupervisionRecord,
    ) -> Result<u64, SupervisionError> {
        let mut state = self.state.borrow_mut();
        let current = state.record.as_ref();
        match (expected_revision, current) {
            (Some(expected), Some(current)) if current.revision() == expected => {}
            (Some(expected), Some(current)) => {
                return Err(SupervisionError::RevisionConflict {
                    expected,
                    found: current.revision(),
                });
            }
            (None, None) => {}
            (None, Some(current)) => {
                return Err(SupervisionError::RevisionConflict {
                    expected: 0,
                    found: current.revision(),
                });
            }
            (Some(_), None) => return Err(SupervisionError::UnknownSupervision),
        }
        if next.project_id() != project_id || next.supervision_id() != supervision_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "supervision record".to_owned(),
                expected: project_id,
                found: next.project_id(),
            });
        }
        state.record = Some(next.clone());
        state.mutations += 1;
        Ok(next.revision())
    }

    fn command_result(
        &self,
        request_id: SupervisionRequestId,
    ) -> Result<Option<CommandResult>, SupervisionError> {
        Ok(self.state.borrow().commands.get(&request_id).cloned())
    }

    fn record_command_result(
        &mut self,
        result: &CommandResult,
    ) -> Result<CommandResult, SupervisionError> {
        let mut state = self.state.borrow_mut();
        if let Some(existing) = state.commands.get(&result.request_id()) {
            if existing == result {
                return Ok(existing.clone());
            }
            return Err(SupervisionError::DuplicateRequestConflict {
                request: result.request_id().to_string(),
                recorded: existing.command().as_str().to_owned(),
                supplied: result.command().as_str().to_owned(),
            });
        }
        state.commands.insert(result.request_id(), result.clone());
        Ok(result.clone())
    }

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

impl RecoveryFactsPort for TestStore {
    fn recovery_snapshot(
        &self,
        project_id: ProjectId,
    ) -> Result<RecoverySnapshot, SupervisionError> {
        let records = self
            .state
            .borrow()
            .record
            .iter()
            .filter(|record| record.project_id() == project_id)
            .cloned()
            .collect();
        Ok(RecoverySnapshot::new(
            records,
            Vec::new(),
            Vec::new(),
            BTreeMap::new(),
        ))
    }
}

#[derive(Default)]
struct WorkspaceState {
    head: Option<String>,
    files: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Default)]
struct FakeWorkspace(Rc<RefCell<WorkspaceState>>);

impl FakeWorkspace {
    fn fixture() -> Self {
        let workspace = Self::default();
        workspace.write("src/lib.rs", b"fixture source");
        workspace.write("Cargo.toml", b"fixture manifest");
        workspace
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        self.0
            .borrow_mut()
            .files
            .insert(path.to_owned(), bytes.to_vec());
    }
}

impl WorkspaceSnapshotPort for FakeWorkspace {
    fn head(&self) -> Result<Option<String>, SupervisionError> {
        Ok(self.0.borrow().head.clone())
    }

    fn inputs(&self) -> Result<Vec<WorkspaceInput>, SupervisionError> {
        self.0
            .borrow()
            .files
            .keys()
            .map(|path| WorkspaceInput::new(path, InputOrigin::Tracked))
            .collect()
    }

    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, SupervisionError> {
        Ok(self.0.borrow().files.get(path).cloned())
    }
}

struct FakeRuntime {
    project: ProjectId,
    inputs: BTreeMap<InputId, InputProgress>,
    run_inputs: BTreeMap<RunId, InputId>,
    run_states: BTreeMap<RunId, RunState>,
    request_ids: BTreeSet<SupervisionRequestId>,
    starts: Vec<ChildRunStart>,
    continuations: Vec<ChildRunContinuation>,
    stop_requests: Vec<RunId>,
    stop_disposition: StopDisposition,
    workspace: FakeWorkspace,
}

impl FakeRuntime {
    fn new(project: ProjectId, workspace: FakeWorkspace) -> Self {
        Self {
            project,
            inputs: BTreeMap::new(),
            run_inputs: BTreeMap::new(),
            run_states: BTreeMap::new(),
            request_ids: BTreeSet::new(),
            starts: Vec::new(),
            continuations: Vec::new(),
            stop_requests: Vec::new(),
            stop_disposition: StopDisposition::Confirmed,
            workspace,
        }
    }

    fn complete_input(&mut self, input: InputId) {
        self.inputs
            .insert(input, InputProgress::new(input, InputPhase::Completed));
        if let Some(run) = self
            .run_inputs
            .iter()
            .find_map(|(run, candidate)| (*candidate == input).then_some(*run))
        {
            self.run_states.insert(run, RunState::Idle);
        }
    }

    fn register_run(&mut self, request_id: SupervisionRequestId, run: RunId, input: InputId) {
        if request_id.project_id() != self.project || run.project_id() != self.project {
            panic!("cross-project runtime request");
        }
        self.inputs
            .insert(input, InputProgress::new(input, InputPhase::Accepted));
        self.run_inputs.insert(run, input);
        self.run_states.insert(run, RunState::Running);
    }

    fn runs_started(&self) -> usize {
        self.starts.len() + self.continuations.len()
    }
}

impl SupervisionRuntimePort for FakeRuntime {
    fn start_child(&mut self, request: &ChildRunStart) -> Result<(), SupervisionError> {
        if self.request_ids.insert(request.request_id()) {
            self.register_run(request.request_id(), request.run_id(), request.input_id());
            self.starts.push(request.clone());
        }
        Ok(())
    }

    fn continue_child(&mut self, request: &ChildRunContinuation) -> Result<(), SupervisionError> {
        if self.request_ids.insert(request.request_id()) {
            self.register_run(request.request_id(), request.run_id(), request.input_id());
            self.continuations.push(request.clone());
        }
        Ok(())
    }

    fn input_progress(&mut self, input_id: InputId) -> Result<InputProgress, SupervisionError> {
        Ok(*self
            .inputs
            .get(&input_id)
            .unwrap_or(&InputProgress::new(input_id, InputPhase::Accepted)))
    }

    fn run_state(&mut self, run_id: RunId) -> Result<RunState, SupervisionError> {
        Ok(*self.run_states.get(&run_id).unwrap_or(&RunState::Idle))
    }

    fn request_stop(&mut self, run_id: RunId) -> Result<StopDisposition, SupervisionError> {
        self.stop_requests.push(run_id);
        Ok(self.stop_disposition)
    }

    fn target_snapshot(
        &mut self,
        request: &TargetSnapshotRequest,
    ) -> Result<herness_supervision::freshness::TargetManifest, SupervisionError> {
        capture_target_snapshot(&self.workspace, request)
    }
}

impl RecoveryRuntimePort for FakeRuntime {
    fn run_state(&mut self, run: RunId) -> Result<RunState, SupervisionError> {
        <Self as SupervisionRuntimePort>::run_state(self, run)
    }

    fn recovery_mode(&mut self, _run: RunId) -> Result<RecoveryMode, SupervisionError> {
        Ok(RecoveryMode::SameProcess)
    }

    fn managed_processes(
        &mut self,
        _run: RunId,
    ) -> Result<Vec<ManagedProcessState>, SupervisionError> {
        Ok(Vec::new())
    }

    fn checkpoint(&mut self, _run: RunId) -> Result<RecoveryCheckpoint, SupervisionError> {
        Ok(RecoveryCheckpoint::Missing)
    }

    fn stop_state(&mut self, run: RunId) -> Result<RecoveryStopState, SupervisionError> {
        Ok(
            match <Self as SupervisionRuntimePort>::run_state(self, run)? {
                RunState::Paused => RecoveryStopState::Confirmed,
                RunState::Interrupted => RecoveryStopState::Unconfirmed,
                _ => RecoveryStopState::NotRequested,
            },
        )
    }

    fn permissions_current(
        &mut self,
        _record: &SupervisionRecord,
    ) -> Result<bool, SupervisionError> {
        Ok(true)
    }
}

impl OperationRuntimePort for FakeRuntime {
    fn request_stop(&mut self, run: RunId) -> Result<StopDisposition, SupervisionError> {
        <Self as SupervisionRuntimePort>::request_stop(self, run)
    }
}

#[derive(Clone, Default)]
struct FakeEvidenceStore {
    records: Rc<RefCell<BTreeMap<EvidenceId, EvidenceRecord>>>,
}

impl FakeEvidenceStore {
    fn push(&self, record: EvidenceRecord) {
        self.records.borrow_mut().insert(record.id(), record);
    }

    fn all(&self) -> Vec<EvidenceRecord> {
        let mut records = self.records.borrow().values().cloned().collect::<Vec<_>>();
        records.sort_by_key(EvidenceRecord::sequence);
        records
    }
}

impl EvidenceStorePort for FakeEvidenceStore {
    fn append(&mut self, evidence: EvidenceRecord) -> Result<EvidenceRecord, SupervisionError> {
        self.records
            .borrow_mut()
            .insert(evidence.id(), evidence.clone());
        Ok(evidence)
    }

    fn get(
        &self,
        project_id: ProjectId,
        evidence_id: EvidenceId,
    ) -> Result<Option<EvidenceRecord>, SupervisionError> {
        if evidence_id.project_id() != project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "evidence".to_owned(),
                expected: project_id,
                found: evidence_id.project_id(),
            });
        }
        Ok(self.records.borrow().get(&evidence_id).cloned())
    }

    fn list_for_supervision(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Vec<EvidenceRecord>, SupervisionError> {
        let mut records = self
            .records
            .borrow()
            .values()
            .filter(|record| {
                record.project_id() == project_id && record.supervision_id() == supervision_id
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by_key(EvidenceRecord::sequence);
        Ok(records)
    }
}

struct FakeChecks {
    project: ProjectId,
    supervision: SupervisionId,
    evidence: FakeEvidenceStore,
    workspace: FakeWorkspace,
    scripts: BTreeMap<CheckId, VecDeque<CheckStatus>>,
    default_status: CheckStatus,
    executions: Vec<CheckExecutionRequest>,
}

impl FakeChecks {
    fn new(
        project: ProjectId,
        supervision: SupervisionId,
        evidence: FakeEvidenceStore,
        workspace: FakeWorkspace,
    ) -> Self {
        Self {
            project,
            supervision,
            evidence,
            workspace,
            scripts: BTreeMap::new(),
            default_status: CheckStatus::Pass,
            executions: Vec::new(),
        }
    }

    fn set_default_status(&mut self, status: CheckStatus) {
        self.default_status = status;
    }

    fn next_status(&mut self, check: CheckId) -> CheckStatus {
        self.scripts
            .get_mut(&check)
            .and_then(VecDeque::pop_front)
            .unwrap_or(self.default_status)
    }
}

impl RequiredCheckPort for FakeChecks {
    fn execute(
        &mut self,
        request: &CheckExecutionRequest,
    ) -> Result<CheckExecution, SupervisionError> {
        self.executions.push(request.clone());
        let status = self.next_status(request.check_id());
        let (exit_code, detail) = match status {
            CheckStatus::Pass => (Some(0), "synthetic check passed"),
            CheckStatus::Fail => (Some(1), "synthetic check failed"),
            CheckStatus::Inconclusive => (Some(0), "synthetic check was inconclusive"),
            CheckStatus::NotRun => (None, "synthetic check was not run"),
            CheckStatus::Unavailable => (None, "synthetic check was unavailable"),
        };
        let mut read_set = request.read_set().to_vec();
        for path in request.invocation().input_paths() {
            if !read_set.contains(path) {
                read_set.push(path.clone());
            }
        }
        let snapshot = capture_target_snapshot(
            &self.workspace,
            &TargetSnapshotRequest::new(
                self.project,
                self.supervision,
                request.target_version(),
                read_set,
            ),
        )?;
        let input_digest = input_manifest_digest(&snapshot, request.invocation().input_paths())?;
        let evidence = EvidenceRecord::new(
            request.evidence_id(),
            self.supervision,
            Some(request.condition_id()),
            Some(request.check_id()),
            EvidenceAcquirer::Host,
            request.operation().clone(),
            EvidenceOutcome::new(exit_code, None, false, false, detail).expect("outcome"),
            snapshot.target_scope()?,
            EvidenceScope::new(
                vec!["src/lib.rs".to_owned()],
                vec!["synthetic check only".to_owned()],
            )
            .expect("scope"),
            status,
            request.sequence(),
            now(),
        )
        .expect("evidence")
        .with_invocation(herness_supervision::EvidenceInvocation::new(
            request.invocation().clone(),
            input_digest,
        ));
        let result = RequiredCheckResult::new(
            request.check_id(),
            request.condition_id(),
            status,
            Some(request.evidence_id()),
            request.condition_version(),
            request.target_version(),
            now(),
        )
        .expect("required check result");
        let execution = CheckExecution::new(result, Some(evidence.clone()));
        self.evidence.push(evidence);
        Ok(execution)
    }
}

struct FakeAssessment {
    profile: AssessmentProfile,
    default_verdict: ConditionVerdict,
    calls: Vec<AssessmentRequest>,
}

impl FakeAssessment {
    fn new(profile: AssessmentProfile) -> Self {
        Self {
            profile,
            default_verdict: ConditionVerdict::Met,
            calls: Vec::new(),
        }
    }
}

impl ConditionAssessmentPort for FakeAssessment {
    fn profile(&self, binding: ProfileBinding) -> Result<AssessmentProfileFacts, SupervisionError> {
        if binding != self.profile.binding() {
            return Err(SupervisionError::ProfileUnavailable {
                reason: ProfileUnavailable::ProfileMismatch {
                    bound: binding.profile_id().to_string(),
                    configured: self.profile.id().to_string(),
                },
            });
        }
        Ok(AssessmentProfileFacts::new(
            self.profile.adapter_version().clone(),
            self.profile.rubric_version().clone(),
            self.profile.thresholds(),
        ))
    }

    fn assess(
        &mut self,
        request: &AssessmentRequest,
    ) -> Result<AssessmentResult, SupervisionError> {
        self.calls.push(request.clone());
        Ok(assessment_result(
            request,
            self.default_verdict,
            request.evidence().to_vec(),
        ))
    }
}

#[derive(Default)]
struct BudgetStoreState {
    record: Option<StoredBudgetRecord>,
}

#[derive(Clone, Default)]
struct MemoryBudgetStore(Rc<RefCell<BudgetStoreState>>);

impl BudgetStorePort for MemoryBudgetStore {
    fn load_budget(
        &self,
        _project_id: ProjectId,
        _supervision_id: SupervisionId,
    ) -> Result<Option<StoredBudgetRecord>, SupervisionError> {
        Ok(self.0.borrow().record.clone())
    }

    fn compare_and_swap_budget(
        &mut self,
        _project_id: ProjectId,
        _supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &herness_supervision::BudgetLedgerRecord,
    ) -> Result<u64, SupervisionError> {
        let mut state = self.0.borrow_mut();
        let current = state.record.as_ref().map(StoredBudgetRecord::revision);
        if expected_revision != current {
            return Err(SupervisionError::RevisionConflict {
                expected: expected_revision.unwrap_or(0),
                found: current.unwrap_or(0),
            });
        }
        let revision = current.unwrap_or(0).saturating_add(1);
        state.record = Some(StoredBudgetRecord::new(revision, next.clone())?);
        Ok(revision)
    }

    fn commit_budget_admission(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &herness_supervision::BudgetLedgerRecord,
        _intent: &herness_core::contracts::RequestGateIntent,
        _recorded_at: Timestamp,
    ) -> Result<u64, SupervisionError> {
        self.compare_and_swap_budget(project_id, supervision_id, expected_revision, next)
    }

    fn commit_budget_observation(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &herness_supervision::BudgetLedgerRecord,
        _observation: &herness_core::contracts::ModelRequestObservation,
        _observed_at: Timestamp,
    ) -> Result<u64, SupervisionError> {
        self.compare_and_swap_budget(project_id, supervision_id, expected_revision, next)
    }
}

#[derive(Clone, Default)]
struct RecordingNotifier {
    notifications: Rc<RefCell<Vec<SupervisorNotification>>>,
}

impl RecordingNotifier {
    fn all(&self) -> Vec<SupervisorNotification> {
        self.notifications.borrow().clone()
    }
}

impl OwnerNotificationPort for RecordingNotifier {
    fn notify(&mut self, notification: &SupervisorNotification) -> Result<(), SupervisionError> {
        if self
            .notifications
            .borrow()
            .iter()
            .any(|existing| existing.notification_id() == notification.notification_id())
        {
            return Ok(());
        }
        self.notifications.borrow_mut().push(notification.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Readiness fakes.
// ---------------------------------------------------------------------------

/// A scripted readiness port. The last decision is repeated by default.
#[derive(Clone)]
struct FakeReadiness {
    decisions: Rc<RefCell<VecDeque<ReadinessDecision>>>,
    default: Rc<RefCell<Option<ReadinessDecision>>>,
    calls: Rc<RefCell<Vec<ReadinessRequest>>>,
}

impl FakeReadiness {
    fn new(default: ReadinessDecision) -> Self {
        Self {
            decisions: Rc::new(RefCell::new(VecDeque::new())),
            default: Rc::new(RefCell::new(Some(default))),
            calls: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn calls(&self) -> usize {
        self.calls.borrow().len()
    }
}

impl VerificationReadinessPort for FakeReadiness {
    fn readiness(
        &mut self,
        request: &ReadinessRequest,
    ) -> Result<ReadinessDecision, SupervisionError> {
        self.calls.borrow_mut().push(request.clone());
        if let Some(decision) = self.decisions.borrow_mut().pop_front() {
            return Ok(decision);
        }
        self.default
            .borrow()
            .clone()
            .ok_or_else(|| SupervisionError::InvalidValue {
                field: "readiness".to_owned(),
                detail: "the fake has no decision".to_owned(),
            })
    }
}

fn pending_decision(reason: &str, documents: &[&str]) -> ReadinessDecision {
    ReadinessDecision::pending(
        reason,
        documents.iter().map(|value| (*value).to_owned()).collect(),
    )
    .expect("pending decision")
}

fn blocked_decision(reason: &str, action: &str, documents: &[&str]) -> ReadinessDecision {
    ReadinessDecision::blocked(
        reason,
        action,
        documents.iter().map(|value| (*value).to_owned()).collect(),
    )
    .expect("blocked decision")
}

enum ReadinessMode {
    Fake(FakeReadiness),
    Desktop(DesktopH4Readiness<FixedReadinessDocuments>),
}

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

struct Harness {
    project: ProjectId,
    supervision: SupervisionId,
    contract: herness_supervision::contract::SupervisionContract,
    store: TestStore,
    runtime: FakeRuntime,
    checks: FakeChecks,
    assessment: FakeAssessment,
    evidence: FakeEvidenceStore,
    budget: BudgetLedger<MemoryBudgetStore, TestBudgetClock>,
    budget_clock: TestBudgetClock,
    clock: TestClock,
    notifier: RecordingNotifier,
    readiness: ReadinessMode,
    tick_counter: u64,
}

impl Harness {
    fn new() -> Self {
        Self::with_policy(BudgetPolicy::h2_default())
    }

    fn with_policy(policy: BudgetPolicy) -> Self {
        let project = project();
        Self::with_contract(policy, contract(project))
    }

    fn with_contract(
        policy: BudgetPolicy,
        contract: herness_supervision::SupervisionContract,
    ) -> Self {
        let project = project();
        let supervision = ids(project).supervision;
        let store = TestStore::new(SupervisionRecord::new(&contract));
        let workspace = FakeWorkspace::fixture();
        let evidence = FakeEvidenceStore::default();
        let runtime = FakeRuntime::new(project, workspace.clone());
        let checks = FakeChecks::new(project, supervision, evidence.clone(), workspace);
        let assessment = FakeAssessment::new(completion_profile(project));
        let clock = TestClock::new(now().as_unix_millis());
        let budget_clock = TestBudgetClock::new(now().as_unix_millis());
        let budget = BudgetLedger::open(
            MemoryBudgetStore::default(),
            project,
            supervision,
            policy,
            1,
            budget_clock.clone(),
        )
        .expect("budget ledger");
        Self {
            project,
            supervision,
            contract,
            store,
            runtime,
            checks,
            assessment,
            evidence,
            budget,
            budget_clock,
            clock,
            notifier: RecordingNotifier::default(),
            readiness: ReadinessMode::Fake(FakeReadiness::new(pending_decision(
                "waiting for required H3 synchronization",
                &["docs/adr/0001-queue-choice.md"],
            ))),
            tick_counter: 0,
        }
    }

    fn set_readiness(&mut self, readiness: FakeReadiness) {
        self.readiness = ReadinessMode::Fake(readiness);
    }

    fn set_desktop_readiness(&mut self, gate: DesktopH4Readiness<FixedReadinessDocuments>) {
        self.readiness = ReadinessMode::Desktop(gate);
    }

    fn record(&self) -> SupervisionRecord {
        self.store.record()
    }

    fn state(&self) -> SupervisionState {
        self.record().state()
    }

    fn remaining_active_seconds(&mut self) -> u64 {
        self.budget
            .remaining_active_seconds()
            .expect("remaining active seconds")
    }

    fn next_event_id(&mut self) -> SupervisionRequestId {
        self.tick_counter = self.tick_counter.saturating_add(1);
        SupervisionRequestId::from_parts(
            self.project,
            Uuid::from_u128(0x4000_0000_0000_4000_8000_0000_0000_0000 + self.tick_counter as u128),
        )
    }

    fn tick(&mut self) -> Result<TickReport, SupervisionError> {
        let event_id = self.next_event_id();
        let request = TickRequest::new(event_id, self.contract.clone())?;
        let readiness: &mut dyn VerificationReadinessPort = match &mut self.readiness {
            ReadinessMode::Fake(fake) => fake,
            ReadinessMode::Desktop(gate) => gate,
        };
        let mut supervisor = Supervisor::new(SupervisorPorts {
            runtime: &mut self.runtime,
            checks: &mut self.checks,
            assessment: &mut self.assessment,
            readiness: Some(readiness),
            evidence: &mut self.evidence,
            store: &mut self.store,
            budget: &mut self.budget,
            clock: &self.clock,
            notifications: &mut self.notifier,
        });
        supervisor.tick(request)
    }

    fn tick_until_readiness(&mut self, max: usize) -> TickReport {
        let mut last = self.tick().expect("tick");
        for _ in 0..max {
            if self.record().supervisor().phase() == SupervisorPhase::AwaitingInput {
                let input = self
                    .record()
                    .supervisor()
                    .current_input()
                    .expect("current input");
                self.runtime.complete_input(input);
            }
            if self.record().supervisor().readiness().is_some() {
                return last;
            }
            last = self.tick().expect("tick");
        }
        panic!("the gate did not hold: {:?}", self.record());
    }

    /// Drives verification and assessment until completion, a blocking state,
    /// or a prepared continuation run.
    fn evaluate_until_blocked(&mut self, max: usize) -> TickReport {
        let mut last = self.tick().expect("tick");
        for _ in 0..max {
            if matches!(
                self.state(),
                SupervisionState::Completed
                    | SupervisionState::Stopped
                    | SupervisionState::WaitingHuman
                    | SupervisionState::Failed
                    | SupervisionState::Cancelled
            ) || (self.state() == SupervisionState::Running
                && self.record().supervisor().phase() == SupervisorPhase::StartingRun)
            {
                return last;
            }
            last = self.tick().expect("tick");
        }
        panic!(
            "evaluation did not block: state={:?} phase={:?}",
            self.state(),
            self.record().supervisor().phase()
        );
    }
}

// ---------------------------------------------------------------------------
// Gate behaviour.
// ---------------------------------------------------------------------------

#[test]
fn pending_holds_zero_runs_stalls_checks_and_assessment_while_time_advances() {
    let mut h = Harness::new();
    let report = h.tick_until_readiness(10);
    assert_eq!(report.outcome(), TickOutcome::AwaitingReadiness);
    assert_eq!(h.state(), SupervisionState::Verifying);
    assert_eq!(
        h.record().supervisor().phase(),
        SupervisorPhase::AwaitingReadiness
    );
    let wait = h
        .record()
        .supervisor()
        .readiness()
        .cloned()
        .expect("persisted pending wait");
    assert_eq!(wait.kind(), ReadinessWaitKind::Pending);
    assert_eq!(wait.documents(), ["docs/adr/0001-queue-choice.md"]);
    assert!(wait.reason_text().contains("H3"));
    assert!(matches!(
        h.record().reason(),
        SupervisionReason::AwaitingReadiness { .. }
    ));

    // No verification failure, run, stagnation cycle, check, assessment, or
    // evidence is introduced by the wait.
    assert!(h.checks.executions.is_empty());
    assert!(h.assessment.calls.is_empty());
    assert!(h.evidence.all().is_empty());
    assert_eq!(h.record().supervisor().stagnation_cycles(), 0);
    assert_eq!(h.record().supervisor().evaluation_cycles(), 0);
    assert_eq!(h.record().run_group().runs().len(), 1);
    assert_eq!(h.runtime.runs_started(), 1);
    let revision = h.record().revision();
    let mutations = h.store.mutations();

    // A repeated identical pending observation is a no-op, but supervised time
    // still advances.
    let before = h.remaining_active_seconds();
    h.budget_clock.advance_seconds(30);
    let report = h.tick().expect("pending tick");
    let after = h.remaining_active_seconds();
    assert_eq!(report.outcome(), TickOutcome::Noop);
    assert_eq!(report.revision(), revision);
    assert_eq!(h.store.mutations(), mutations);
    assert_eq!(before.saturating_sub(after), 30);
    assert!(h.checks.executions.is_empty());
    assert!(h.record().supervisor().readiness().is_some());
}

#[test]
fn ready_still_runs_the_normal_required_checks_and_assessment() {
    let mut h = Harness::new();
    h.tick_until_readiness(10);
    assert!(h.checks.executions.is_empty());

    // A delayed readiness observation keeps the wait without side effects and
    // then advances normally once the owner reports ready.
    h.budget_clock.advance_seconds(5);
    let delayed = h.tick().expect("delayed pending tick");
    assert_eq!(delayed.outcome(), TickOutcome::Noop);
    assert!(h.checks.executions.is_empty());

    let fake = FakeReadiness::new(ReadinessDecision::ready());
    h.set_readiness(fake);

    let report = h.tick().expect("ready tick");
    assert_eq!(report.outcome(), TickOutcome::Advanced);
    assert_eq!(h.state(), SupervisionState::Verifying);
    assert_eq!(h.record().supervisor().phase(), SupervisorPhase::Evaluating);
    assert!(h.record().supervisor().readiness().is_none());
    assert!(
        h.evidence.all().is_empty(),
        "the readiness observation is not evidence"
    );

    let report = h.evaluate_until_blocked(20);
    assert_eq!(report.outcome(), TickOutcome::Completed);
    assert_eq!(h.state(), SupervisionState::Completed);
    assert!(
        !h.checks.executions.is_empty(),
        "required checks must still execute after ready"
    );
    assert!(
        !h.assessment.calls.is_empty(),
        "the assessment path must still run after ready"
    );
}

#[test]
fn blocked_waits_with_a_reason_and_required_action() {
    let mut h = Harness::new();
    h.set_readiness(FakeReadiness::new(blocked_decision(
        "the H3 settings have no human approval",
        "approve_settings",
        &["docs/adr/0001-queue-choice.md"],
    )));
    let report = h.tick_until_readiness(10);
    assert_eq!(report.outcome(), TickOutcome::WaitingHuman);
    assert_eq!(h.state(), SupervisionState::WaitingHuman);
    assert_eq!(h.record().supervisor().phase(), SupervisorPhase::Finished);
    let wait = h
        .record()
        .supervisor()
        .readiness()
        .cloned()
        .expect("persisted blocked wait");
    assert_eq!(wait.kind(), ReadinessWaitKind::Blocked);
    assert_eq!(wait.required_action(), Some("approve_settings"));
    assert!(matches!(
        h.record().reason(),
        SupervisionReason::ReadinessBlocked {
            required_action,
            ..
        } if required_action == "approve_settings"
    ));
    assert!(
        h.record()
            .completion_blockers()
            .iter()
            .any(|blocker| matches!(
                blocker,
                herness_supervision::CompletionBlocker::HumanAction {
                    action: HumanAction::ConfirmHtmlReadiness
                }
            )),
        "blocked readiness must surface the required human action"
    );
    assert_eq!(h.notifier.all().len(), 1);
    assert!(h.checks.executions.is_empty());
    assert!(h.assessment.calls.is_empty());
    assert_eq!(h.record().supervisor().stagnation_cycles(), 0);

    // A human wait excludes active time from the supervised budget.
    let before = h.remaining_active_seconds();
    h.budget_clock.advance_seconds(40);
    let after = h.remaining_active_seconds();
    assert_eq!(before, after);

    // A blocked wait is not re-notified or re-observed on a later tick.
    let calls = match &h.readiness {
        ReadinessMode::Fake(fake) => fake.calls(),
        ReadinessMode::Desktop(_) => unreachable!(),
    };
    let report = h.tick().expect("blocked tick");
    assert_eq!(report.outcome(), TickOutcome::Noop);
    let after_calls = match &h.readiness {
        ReadinessMode::Fake(fake) => fake.calls(),
        ReadinessMode::Desktop(_) => unreachable!(),
    };
    assert_eq!(calls, after_calls);
    assert_eq!(h.notifier.all().len(), 1);
}

#[test]
fn deadline_while_pending_stops_with_the_active_seconds_cause() {
    let policy = BudgetPolicy::new(60, 30, None).expect("policy");
    let mut h = Harness::with_policy(policy);
    h.tick_until_readiness(10);
    assert_eq!(h.record().supervisor().stagnation_cycles(), 0);

    h.budget_clock.advance_seconds(61);
    let report = h.tick().expect("deadline tick");
    assert_eq!(report.outcome(), TickOutcome::Stopped);
    assert_eq!(h.state(), SupervisionState::Stopped);
    assert_eq!(
        h.record().reason(),
        &SupervisionReason::Stopped {
            cause: herness_supervision::StopCause::Budget(BudgetLimit::ActiveSeconds)
        }
    );
    assert!(h.checks.executions.is_empty());
    assert!(h.assessment.calls.is_empty());
    assert_eq!(h.record().supervisor().stagnation_cycles(), 0);
}

#[test]
fn stop_while_pending_is_recorded_and_confirmed() {
    let mut h = Harness::new();
    h.tick_until_readiness(10);
    let run = h.record().supervisor().current_run().expect("run");
    let calls_before = match &h.readiness {
        ReadinessMode::Fake(fake) => fake.calls(),
        ReadinessMode::Desktop(_) => unreachable!(),
    };

    let request = SupervisionOperationRequest::new(
        SupervisionRequestId::new(h.project),
        h.supervision,
        HumanOperation::Stop,
        h.record().revision(),
    )
    .expect("stop request");
    let result = execute_operation(
        OperationPorts {
            store: &mut h.store,
            runtime: &mut h.runtime,
            budget: &mut h.budget,
            clock: &h.clock,
        },
        &h.contract,
        1,
        request,
    )
    .expect("stop while pending");
    assert_eq!(result.command().state(), SupervisionState::Stopped);
    assert_eq!(
        h.record().reason(),
        &SupervisionReason::Stopped {
            cause: herness_supervision::StopCause::UserRequest
        }
    );
    assert_eq!(h.runtime.stop_requests, vec![run]);
    assert!(h.record().supervisor().readiness().is_none());

    let report = h.tick().expect("post-stop tick");
    assert_eq!(report.outcome(), TickOutcome::Noop);
    let calls_after = match &h.readiness {
        ReadinessMode::Fake(fake) => fake.calls(),
        ReadinessMode::Desktop(_) => unreachable!(),
    };
    assert_eq!(calls_before, calls_after);
    assert!(h.checks.executions.is_empty());
}

#[test]
fn restored_pending_wait_is_preserved_and_a_stale_ready_is_not_evidence() {
    let mut h = Harness::new();
    h.tick_until_readiness(10);
    let pending = h.record();
    assert!(pending.supervisor().readiness().is_some());
    let revision = pending.revision();

    // Simulate a durable store reload: the persisted wait survives exactly.
    let encoded = serde_json::to_string(&pending).expect("record json");
    let restored: SupervisionRecord = serde_json::from_str(&encoded).expect("restored record");
    assert_eq!(
        restored.supervisor().readiness(),
        pending.supervisor().readiness()
    );
    h.store.replace_record(restored);

    let checks_before = h.checks.executions.len();
    let report = h.tick().expect("restored pending tick");
    assert_eq!(report.outcome(), TickOutcome::Noop);
    assert_eq!(h.record().revision(), revision);
    assert_eq!(h.checks.executions.len(), checks_before);
    assert!(h.record().supervisor().readiness().is_some());

    // `ready` is never persisted: only the normal verification path follows.
    h.set_readiness(FakeReadiness::new(ReadinessDecision::ready()));
    let report = h.tick().expect("ready tick");
    assert_eq!(report.outcome(), TickOutcome::Advanced);
    let ready_record = h.record();
    assert!(ready_record.supervisor().readiness().is_none());
    assert!(
        h.evidence.all().is_empty(),
        "a ready observation must not be stored as completion evidence"
    );
    assert!(
        !serde_json::to_string(&ready_record)
            .expect("ready json")
            .contains("awaiting_readiness")
    );

    // Restore after the ready observation. A later failing check must be run
    // fresh and must prevent completion instead of reusing the old ready.
    let encoded = serde_json::to_string(&ready_record).expect("ready record json");
    let restored: SupervisionRecord =
        serde_json::from_str(&encoded).expect("restored ready record");
    h.store.replace_record(restored);
    h.set_readiness(FakeReadiness::new(blocked_decision(
        "stale readiness must not be trusted",
        "resolve_html",
        &["docs/adr/0001-queue-choice.md"],
    )));
    h.checks.set_default_status(CheckStatus::Fail);
    let report = h.evaluate_until_blocked(12);
    assert_ne!(h.state(), SupervisionState::Completed);
    assert!(
        h.checks.executions.len() > checks_before,
        "a fresh required check must run after restore"
    );
    assert!(report.outcome() != TickOutcome::Completed);
    assert_eq!(
        h.record().supervisor().phase(),
        SupervisorPhase::StartingRun,
        "a failed check after the stale ready prepares a continuation"
    );

    // The prepared continuation still runs in the same child and does not start
    // over from a new target.
    let previous = h
        .record()
        .supervisor()
        .continuation_of()
        .expect("continuation");
    let report = h.tick().expect("continuation tick");
    assert_eq!(report.outcome(), TickOutcome::AwaitingInput);
    assert_eq!(h.runtime.continuations.len(), 1);
    let continuation = &h.runtime.continuations[0];
    assert_eq!(continuation.previous_run_id(), previous);
    assert_eq!(h.record().run_group().runs().len(), 2);
    assert_eq!(h.record().supervisor().stagnation_cycles(), 0);
}

// ---------------------------------------------------------------------------
// Desktop connection over the real H3 store.
// ---------------------------------------------------------------------------

const TARGET: &str = "docs/adr/0001-queue-choice.md";
const SOURCE: &[u8] = b"# Queue choice\n\nUse the queue.\n";

struct H3Fixture {
    _data: TempDir,
    store: StoreHandle,
    project: ProjectId,
}

impl H3Fixture {
    fn new(approved: bool) -> Self {
        let data = tempfile::tempdir().expect("h3 data root");
        let config = StoreConfig::new(data.path()).expect("store config");
        let store = Store::open(config).expect("store");
        let store = StoreHandle::new(Arc::new(Mutex::new(store)));
        let project = ProjectId::new();
        let fixture = Self {
            _data: data,
            store,
            project,
        };
        fixture.seed_settings(approved);
        fixture
    }

    fn document(&self) -> DocumentKey {
        DocumentKey::new(self.project, TARGET).expect("document key")
    }

    fn seed_settings(&self, approved: bool) {
        let settings = if approved {
            H3Settings::approved(self.approval(), true).expect("approved settings")
        } else {
            H3Settings::new(
                self.project,
                1,
                true,
                vec![TARGET.to_owned()],
                true,
                true,
                now(),
            )
            .expect("unapproved settings")
        };
        let event = settings_event(&settings, now()).expect("settings event");
        let mut store = self.store.clone();
        store
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_settings(SettingsCommit::new(None, settings).expect("settings commit"))
                    .with_events(vec![event]),
            )
            .expect("settings commit");
    }

    fn approval(&self) -> H3ConfigurationApproval {
        let owner = OwnerRef::new(OwnerKind::H3HtmlJob, "task-10-job").expect("owner");
        H3ConfigurationApproval::approve(
            H3ConfigurationDraft {
                project_id: self.project,
                settings_version: 1,
                approval_id: "task-10-approval".to_owned(),
                expires_at: None,
                targets: vec![TARGET.to_owned()],
                authoring: connection(self.project, ProfilePurpose::Completion),
                assessment: connection(self.project, ProfilePurpose::Html),
                versions: H3VersionBinding::new(
                    "sdd-herness-integration",
                    1,
                    1,
                    "sdd-html-policy-v1",
                    ContentDigest::sha256(b"task-10-policy"),
                    1,
                    ContentDigest::sha256(b"task-10-pack"),
                    "sdd-html-host-api",
                    1,
                )
                .expect("versions"),
                limits: H3ApprovalLimits::default(),
                auto_publish: false,
                retain_history: true,
                automatic_companion: true,
                owner: H3OwnerBinding::new(
                    self.project,
                    owner,
                    "task-10",
                    ConditionVersion::new(1).expect("condition version"),
                    ConditionDigest::sha256(b"task-10-conditions"),
                    ExecutionScope::new(
                        self.project,
                        vec![TARGET.to_owned()],
                        vec!["private/html-sync/candidates".to_owned()],
                        false,
                    )
                    .expect("scope"),
                    1,
                    BudgetPolicy::h2_default(),
                )
                .expect("owner binding"),
            },
            H3Approver::Human,
            now(),
        )
        .expect("approval")
    }

    fn fingerprints(&self) -> FingerprintSet {
        let settings = self
            .store
            .clone()
            .load_html_sync_settings(self.project)
            .expect("load settings")
            .expect("settings");
        FingerprintSet::new(
            settings.settings().fingerprint().clone(),
            ContentDigest::sha256(b"task-10-policy"),
            ContentDigest::sha256(b"task-10-css"),
            ContentDigest::sha256(b"task-10-resources"),
            None,
            None,
            None,
        )
    }

    fn seed_synced_document(&self) {
        let generation = herness_html_sync::GenerationId::new(self.project);
        let source = SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(SOURCE),
        );
        let settings_version = self
            .store
            .clone()
            .load_html_sync_settings(self.project)
            .expect("load settings")
            .expect("settings")
            .settings()
            .version();
        let state = H3DocumentState::new(
            self.document(),
            settings_version,
            None,
            None,
            Some(generation),
            source.clone(),
            self.fingerprints(),
            H3Reason::new(
                H3StateReasonKind::Synced {
                    generation,
                    source_revision: 1,
                    source_digest: source.digest().clone(),
                },
                Vec::new(),
            )
            .expect("synced reason"),
            None,
            Vec::new(),
            Applicability::current_synced(),
            now(),
        )
        .expect("synced state");
        let event = document_state_event(&self.document(), None, &state, now()).expect("event");
        self.store
            .clone()
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_document(DocumentCommit::new(None, state).expect("document commit"))
                    .with_events(vec![event]),
            )
            .expect("document commit");
    }

    fn barrier_request(&self) -> BarrierRequest {
        BarrierRequest::new(
            self.project,
            self.document(),
            1,
            ContentDigest::sha256(SOURCE),
            Vec::new(),
        )
        .expect("barrier request")
    }
}

fn connection(project: ProjectId, purpose: ProfilePurpose) -> H3ConnectionApproval {
    let local = match purpose {
        ProfilePurpose::Completion => "50000000-0000-4000-8000-000000000001",
        ProfilePurpose::Html => "50000000-0000-4000-8000-000000000002",
        ProfilePurpose::Permission => "50000000-0000-4000-8000-000000000003",
    };
    let kinds = BTreeSet::from([DisclosureDataKind::Text]);
    H3ConnectionApproval::new(
        project,
        herness_core::ConnectionId::new(),
        ProviderOrigin::parse("https://loopback.example").expect("origin"),
        DisclosureScope::new(
            purpose,
            kinds,
            vec![TARGET.to_owned()],
            SupervisionTargetVersion::new(1).expect("target version"),
        )
        .expect("disclosure"),
        ProfileBinding::new(
            ProfileId::from_parts(project, Uuid::parse_str(local).expect("uuid")),
            ProfileVersion::new(1).expect("version"),
            purpose,
        ),
        herness_supervision::ConsentBinding::new(
            herness_supervision::ConsentId::from_parts(
                project,
                Uuid::parse_str(&local.replace('5', "6")).expect("consent uuid"),
            ),
            1,
            purpose,
            SupervisionTargetVersion::new(1).expect("target version"),
        ),
    )
    .expect("connection approval")
}

fn readiness_request(project: ProjectId) -> ReadinessRequest {
    ReadinessRequest::new(
        project,
        SupervisionId::new(project),
        RunId::new(project),
        InputId::new(project),
        ConditionVersion::new(1).expect("condition version"),
        SupervisionTargetVersion::new(1).expect("target version"),
        now(),
    )
}

#[test]
fn desktop_h3_barrier_drives_pending_then_ready_through_the_supervisor() {
    let fixture = H3Fixture::new(true);
    let barrier = DesktopH4Barrier::new(fixture.store.clone());
    let documents = FixedReadinessDocuments::new(vec![fixture.barrier_request()]);

    // Missing saved document: pending, never ready.
    let mut gate = DesktopH4Readiness::new(barrier.clone(), documents.clone());
    let decision = gate
        .readiness(&readiness_request(fixture.project))
        .expect("missing readiness");
    assert!(matches!(decision, ReadinessDecision::Pending { .. }));

    let mut h = Harness::new();
    h.set_desktop_readiness(gate);
    let report = h.tick_until_readiness(10);
    assert_eq!(report.outcome(), TickOutcome::AwaitingReadiness);
    assert!(h.checks.executions.is_empty());
    assert!(h.assessment.calls.is_empty());
    assert_eq!(h.record().supervisor().stagnation_cycles(), 0);

    // H3 publishes the synced document: the same supervisor reaches ready and
    // runs the normal required check.
    fixture.seed_synced_document();
    let report = h.tick().expect("ready tick");
    assert_eq!(report.outcome(), TickOutcome::Advanced);
    assert_eq!(h.record().supervisor().phase(), SupervisorPhase::Evaluating);
    let report = h.tick().expect("check tick");
    assert_eq!(report.outcome(), TickOutcome::Advanced);
    assert_eq!(h.checks.executions.len(), 1);
    assert!(h.record().supervisor().readiness().is_none());
}

#[test]
fn desktop_gate_never_reports_ready_without_approval_or_a_required_set() {
    let unapproved = H3Fixture::new(false);
    unapproved.seed_synced_document();
    let mut gate = DesktopH4Readiness::new(
        DesktopH4Barrier::new(unapproved.store.clone()),
        FixedReadinessDocuments::new(vec![unapproved.barrier_request()]),
    );
    let decision = gate
        .readiness(&readiness_request(unapproved.project))
        .expect("unapproved readiness");
    assert!(
        matches!(decision, ReadinessDecision::Blocked { .. }),
        "a missing H3 approval must block, not pass or pend silently"
    );
    if let ReadinessDecision::Blocked {
        required_action, ..
    } = decision
    {
        assert!(required_action.contains("approve_settings"));
    }

    // An undeterminable required set is blocked, never ready.
    let fixture = H3Fixture::new(true);
    let mut gate = DesktopH4Readiness::new(
        DesktopH4Barrier::new(fixture.store.clone()),
        FailingDocuments,
    );
    let decision = gate
        .readiness(&readiness_request(fixture.project))
        .expect("failed set readiness");
    assert!(matches!(decision, ReadinessDecision::Blocked { .. }));

    // An empty required set is blocked, never ready.
    let mut gate = DesktopH4Readiness::new(
        DesktopH4Barrier::new(fixture.store.clone()),
        FixedReadinessDocuments::default(),
    );
    let decision = gate
        .readiness(&readiness_request(fixture.project))
        .expect("empty set readiness");
    assert!(matches!(decision, ReadinessDecision::Blocked { .. }));
}

struct FailingDocuments;

impl herness_desktop::sdd_execute::readiness::ReadinessDocumentSource for FailingDocuments {
    fn required(&mut self, _request: &ReadinessRequest) -> Result<Vec<BarrierRequest>, String> {
        Err("the approved Task has no resolvable htmlTargets".to_owned())
    }
}
