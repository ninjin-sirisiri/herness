//! Deterministic H2 supervisor tests.
//!
//! Every runtime, check, assessment, evidence, budget-store, and notification
//! boundary is a local fake. Records, the budget ledger, the clock contract, and
//! the compare-and-set store contract are the real supervision types. No provider,
//! credential, Keychain item, Tauri window, or external process is used.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use herness_core::contracts::{
    InputId, InputPhase, InputProgress, ProjectId, RunId, RunState, Timestamp,
};
use herness_supervision::approval::ApprovalActor;
use herness_supervision::assessment::{AssessmentRequest, AssessmentResult, ConditionVerdict};
use herness_supervision::budget::ledger::{BudgetClockPort, BudgetLedger, ClockReading};
use herness_supervision::budget::{BudgetLimit, BudgetPolicy};
use herness_supervision::command::CommandResult;
use herness_supervision::conditions::ConditionVersion;
use herness_supervision::error::SupervisionError;
use herness_supervision::evidence::{
    CheckStatus, EvidenceAcquirer, EvidenceOutcome, EvidenceRecord, EvidenceScope,
    RequiredCheckResult, TargetVersion, VerificationOperation,
};
use herness_supervision::freshness::{InputOrigin, WorkspaceInput, WorkspaceSnapshotPort};
use herness_supervision::ids::{
    BudgetRequestId, CheckId, ConditionId, EvidenceId, SupervisionId, SupervisionRequestId,
};
use herness_supervision::ports::{
    BudgetStorePort, ClockPort, EvidenceStorePort, StoredBudgetRecord, SupervisionStorePort,
};
use herness_supervision::profiles::{AssessmentProfile, ProfileUnavailable};
use herness_supervision::state::{StopCause, SupervisionRecord, SupervisionState};
use herness_supervision::supervisor::{
    AssessmentProfileFacts, CheckExecution, CheckExecutionRequest, ChildRunContinuation,
    ChildRunStart, ConditionAssessmentPort, OwnerNotificationPort, RequiredCheckPort,
    StopDisposition, SupervisionRuntimePort, Supervisor, SupervisorNotification, SupervisorPhase,
    SupervisorPorts, TargetSnapshotRequest, TickOutcome, TickReport, TickRequest,
    capture_target_snapshot,
};
use herness_supervision_tests::{
    assessment_result, completion_profile, contract, ids, now, project, record, target_scope,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Shared harness
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct OrderLog(Rc<RefCell<Vec<String>>>);

impl OrderLog {
    fn push(&self, value: impl Into<String>) {
        self.0.borrow_mut().push(value.into());
    }

    fn entries(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

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

    fn advance_seconds(&self, seconds: u64) {
        self.millis
            .set(self.millis.get().saturating_add(seconds * 1_000));
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

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StoreState {
    record: Option<SupervisionRecord>,
    commands: BTreeMap<SupervisionRequestId, CommandResult>,
    mutations: u32,
    swaps: u32,
    fail_next_commit: bool,
}

#[derive(Clone, Default)]
struct TestStore {
    state: Rc<RefCell<StoreState>>,
    order: OrderLog,
}

impl TestStore {
    fn new(record: SupervisionRecord, order: OrderLog) -> Self {
        Self {
            state: Rc::new(RefCell::new(StoreState {
                record: Some(record),
                ..StoreState::default()
            })),
            order,
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

    fn fail_next_commit(&self) {
        self.state.borrow_mut().fail_next_commit = true;
    }

    /// Applies an out-of-band human/owner revision as a newer record.
    fn revise(&self, change: impl FnOnce(&mut SupervisionRecord)) -> Result<u64, SupervisionError> {
        let mut state = self.state.borrow_mut();
        let current = state.record.clone().expect("supervision record");
        let revision = current.revision();
        let mut next = current;
        change(&mut next);
        if next.revision() <= revision {
            return Err(SupervisionError::InvalidValue {
                field: "test.revision".to_owned(),
                detail: "an out-of-band revision must increment the record".to_owned(),
            });
        }
        let next_revision = next.revision();
        state.record = Some(next);
        state.mutations += 1;
        drop(state);
        self.order
            .push(format!("store:external-change:{next_revision}"));
        Ok(next_revision)
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
        state.swaps += 1;
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
        let revision = next.revision();
        drop(state);
        self.order.push(format!("store:commit:{revision}"));
        Ok(revision)
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
        {
            let mut state = self.state.borrow_mut();
            state.swaps += 1;
            if state.fail_next_commit {
                state.fail_next_commit = false;
                return Err(SupervisionError::RevisionConflict {
                    expected: expected_revision.unwrap_or(0),
                    found: expected_revision.unwrap_or(0).saturating_add(1),
                });
            }
        }
        let revision =
            self.compare_and_swap(project_id, supervision_id, expected_revision, next)?;
        self.record_command_result(result)?;
        Ok(revision)
    }
}

// ---------------------------------------------------------------------------
// Workspace and runtime
// ---------------------------------------------------------------------------

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
    supervision: SupervisionId,
    workspace: FakeWorkspace,
    evidence: FakeEvidenceStore,
    investigation: bool,
    investigation_condition: ConditionId,
    investigation_counter: u64,
    tool_calls: u64,
    inputs: BTreeMap<InputId, InputProgress>,
    run_inputs: BTreeMap<RunId, InputId>,
    run_states: BTreeMap<RunId, RunState>,
    request_ids: BTreeSet<SupervisionRequestId>,
    starts: Vec<ChildRunStart>,
    continuations: Vec<ChildRunContinuation>,
    stop_requests: Vec<RunId>,
    stop_disposition: StopDisposition,
}

impl FakeRuntime {
    fn new(
        project: ProjectId,
        supervision: SupervisionId,
        workspace: FakeWorkspace,
        evidence: FakeEvidenceStore,
        investigation_condition: ConditionId,
    ) -> Self {
        Self {
            project,
            supervision,
            workspace,
            evidence,
            investigation: false,
            investigation_condition,
            investigation_counter: 0,
            tool_calls: 0,
            inputs: BTreeMap::new(),
            run_inputs: BTreeMap::new(),
            run_states: BTreeMap::new(),
            request_ids: BTreeSet::new(),
            starts: Vec::new(),
            continuations: Vec::new(),
            stop_requests: Vec::new(),
            stop_disposition: StopDisposition::Confirmed,
        }
    }

    fn enable_investigation_evidence(&mut self) {
        self.investigation = true;
    }

    fn set_input_phase(&mut self, input: InputId, phase: InputPhase) {
        self.inputs.insert(input, InputProgress::new(input, phase));
    }

    fn set_run_state(&mut self, run: RunId, state: RunState) {
        self.run_states.insert(run, state);
    }

    fn complete_input(&mut self, input: InputId) {
        self.set_input_phase(input, InputPhase::Completed);
        if let Some(run) = self
            .run_inputs
            .iter()
            .find_map(|(run, candidate)| (*candidate == input).then_some(*run))
        {
            self.set_run_state(run, RunState::Idle);
        }
    }

    fn push_investigation_evidence(&mut self, target_version: TargetVersion) {
        self.investigation_counter = self.investigation_counter.saturating_add(1);
        let local = Uuid::from_u128(
            0x3000_0000_0000_4000_8000_0000_0000_0000 + self.investigation_counter as u128,
        );
        let evidence = EvidenceRecord::new(
            EvidenceId::from_parts(self.project, local),
            self.supervision,
            Some(self.investigation_condition),
            None,
            EvidenceAcquirer::ChildAgent,
            VerificationOperation::equivalent(format!(
                "child investigation round {}",
                self.investigation_counter
            ))
            .expect("operation"),
            EvidenceOutcome::new(
                None,
                None,
                false,
                false,
                format!(
                    "synthetic investigation observation {}",
                    self.investigation_counter
                ),
            )
            .expect("outcome"),
            target_scope(self.project, target_version.get()),
            EvidenceScope::new(
                vec!["src/lib.rs".to_owned()],
                vec!["synthetic investigation only".to_owned()],
            )
            .expect("scope"),
            CheckStatus::Inconclusive,
            self.investigation_counter,
            now(),
        )
        .expect("investigation evidence");
        self.evidence.push(evidence);
    }

    fn register_run(&mut self, request_id: SupervisionRequestId, run: RunId, input: InputId) {
        if request_id.project_id() != self.project || run.project_id() != self.project {
            panic!("cross-project runtime request");
        }
        self.inputs
            .insert(input, InputProgress::new(input, InputPhase::Accepted));
        self.run_inputs.insert(run, input);
        self.run_states.insert(run, RunState::Running);
        if self.investigation {
            self.push_investigation_evidence(TargetVersion::new(1).expect("version"));
        }
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

// ---------------------------------------------------------------------------
// Evidence, checks, assessment, budget, notification
// ---------------------------------------------------------------------------

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

    fn push_status(&mut self, check: CheckId, status: CheckStatus) {
        self.scripts.entry(check).or_default().push_back(status);
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
        let snapshot = capture_target_snapshot(
            &self.workspace,
            &TargetSnapshotRequest::new(
                self.project,
                self.supervision,
                request.target_version(),
                request.read_set().to_vec(),
            ),
        )?;
        let evidence = EvidenceRecord::new(
            request.evidence_id(),
            self.supervision,
            Some(request.condition_id()),
            Some(request.check_id()),
            EvidenceAcquirer::ChildAgent,
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
        .expect("evidence");
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
    verdicts: BTreeMap<ConditionId, VecDeque<ConditionVerdict>>,
    default_verdict: ConditionVerdict,
    calls: Vec<AssessmentRequest>,
    hook: Option<Box<dyn FnMut()>>,
    requires_assessment: bool,
}

impl FakeAssessment {
    fn new(profile: AssessmentProfile) -> Self {
        Self {
            profile,
            verdicts: BTreeMap::new(),
            default_verdict: ConditionVerdict::Met,
            calls: Vec::new(),
            hook: None,
            requires_assessment: true,
        }
    }

    fn disable_semantic_assessment(&mut self) {
        self.requires_assessment = false;
    }

    fn push_verdict(&mut self, condition: ConditionId, verdict: ConditionVerdict) {
        self.verdicts
            .entry(condition)
            .or_default()
            .push_back(verdict);
    }

    fn set_default_verdict(&mut self, verdict: ConditionVerdict) {
        self.default_verdict = verdict;
    }

    fn on_assess(&mut self, hook: impl FnMut() + 'static) {
        self.hook = Some(Box::new(hook));
    }

    fn next_verdict(&mut self, condition: ConditionId) -> ConditionVerdict {
        self.verdicts
            .get_mut(&condition)
            .and_then(VecDeque::pop_front)
            .unwrap_or(self.default_verdict)
    }
}

impl ConditionAssessmentPort for FakeAssessment {
    fn requires_assessment(&self, _condition: &herness_supervision::conditions::Condition) -> bool {
        self.requires_assessment
    }

    fn profile(
        &self,
        binding: herness_supervision::profiles::ProfileBinding,
    ) -> Result<AssessmentProfileFacts, SupervisionError> {
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
        if let Some(hook) = self.hook.as_mut() {
            hook();
        }
        let verdict = self.next_verdict(request.condition_id());
        Ok(assessment_result(
            request,
            verdict,
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
    order: OrderLog,
}

impl RecordingNotifier {
    fn count(&self) -> usize {
        self.notifications.borrow().len()
    }

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
        self.order
            .push(format!("notify:{}", notification.notification_id()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Harness
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
    budget_store: MemoryBudgetStore,
    budget_policy: BudgetPolicy,
    clock: TestClock,
    budget_clock: TestBudgetClock,
    notifier: RecordingNotifier,
    order: OrderLog,
    tick_counter: u64,
    last_event: Option<SupervisionRequestId>,
}

impl Harness {
    fn new() -> Self {
        Self::with_policy(BudgetPolicy::h2_default())
    }

    fn with_policy(policy: BudgetPolicy) -> Self {
        let project = project();
        let supervision = ids(project).supervision;
        let contract = contract(project);
        let order = OrderLog::default();
        let store = TestStore::new(record(project), order.clone());
        let workspace = FakeWorkspace::fixture();
        let evidence = FakeEvidenceStore::default();
        let runtime = FakeRuntime::new(
            project,
            supervision,
            workspace.clone(),
            evidence.clone(),
            ids(project).condition_a,
        );
        let checks = FakeChecks::new(project, supervision, evidence.clone(), workspace);
        let assessment = FakeAssessment::new(completion_profile(project));
        let clock = TestClock::new(now().as_unix_millis());
        let budget_clock = TestBudgetClock::new(now().as_unix_millis());
        let budget_store = MemoryBudgetStore::default();
        let budget = BudgetLedger::open(
            budget_store.clone(),
            project,
            supervision,
            policy.clone(),
            1,
            budget_clock.clone(),
        )
        .expect("budget ledger");
        let notifier = RecordingNotifier {
            notifications: Rc::new(RefCell::new(Vec::new())),
            order: order.clone(),
        };
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
            budget_store,
            budget_policy: policy,
            clock,
            budget_clock,
            notifier,
            order,
            tick_counter: 0,
            last_event: None,
        }
    }

    fn record(&self) -> SupervisionRecord {
        self.store.record()
    }

    fn state(&self) -> SupervisionState {
        self.record().state()
    }

    fn next_event_id(&mut self) -> SupervisionRequestId {
        self.tick_counter = self.tick_counter.saturating_add(1);
        SupervisionRequestId::from_parts(
            self.project,
            Uuid::from_u128(0x2000_0000_0000_4000_8000_0000_0000_0000 + self.tick_counter as u128),
        )
    }

    fn tick(&mut self) -> Result<TickReport, SupervisionError> {
        let event_id = self.next_event_id();
        self.tick_with(event_id)
    }

    fn tick_with(
        &mut self,
        event_id: SupervisionRequestId,
    ) -> Result<TickReport, SupervisionError> {
        self.last_event = Some(event_id);
        let request = TickRequest::new(event_id, self.contract.clone())?;
        let mut supervisor = Supervisor::new(SupervisorPorts {
            runtime: &mut self.runtime,
            checks: &mut self.checks,
            assessment: &mut self.assessment,
            evidence: &mut self.evidence,
            store: &mut self.store,
            budget: &mut self.budget,
            clock: &self.clock,
            notifications: &mut self.notifier,
        });
        supervisor.tick(request)
    }

    fn current_run(&self) -> RunId {
        self.record()
            .supervisor()
            .current_run()
            .expect("current run")
    }

    fn current_input(&self) -> InputId {
        self.record()
            .supervisor()
            .current_input()
            .expect("current input")
    }

    fn tick_until_awaiting_input(&mut self, max: usize) -> TickReport {
        let mut last = self.tick().expect("tick");
        for _ in 0..max {
            if self.record().supervisor().phase() == SupervisorPhase::AwaitingInput {
                return last;
            }
            last = self.tick().expect("tick");
        }
        panic!("run did not reach awaiting input: {:?}", self.record());
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
// Tests
// ---------------------------------------------------------------------------

#[test]
fn normal_completion_waits_for_completed_input_and_notifies_once_after_save() {
    let mut h = Harness::new();
    h.tick().expect("ready intent");
    h.tick_until_awaiting_input(4);
    let run = h.current_run();
    let input = h.current_input();

    h.runtime.set_run_state(run, RunState::Idle);
    for _ in 0..4 {
        h.tick().expect("idle tick");
    }
    assert_eq!(h.checks.executions.len(), 0);
    assert_eq!(h.assessment.calls.len(), 0);
    assert_eq!(h.state(), SupervisionState::Running);

    h.runtime.complete_input(input);
    let report = h.evaluate_until_blocked(80);
    assert_eq!(report.outcome(), TickOutcome::Completed);
    assert_eq!(h.state(), SupervisionState::Completed);
    assert_eq!(h.notifier.count(), 1);
    assert_eq!(h.checks.executions.len(), 2);
    assert_eq!(h.assessment.calls.len(), 2);

    let record = h.record();
    let completion = record.completion().expect("completion snapshot");
    assert_eq!(completion.verified_checks().len(), 2);
    assert!(!completion.evidence().is_empty());
    let entries = h.order.entries();
    let commit = entries
        .iter()
        .position(|entry| entry.starts_with("store:commit:"))
        .expect("commit");
    let notify = entries
        .iter()
        .position(|entry| entry.starts_with("notify:"))
        .expect("notify");
    assert!(commit < notify, "save must precede notify: {entries:?}");

    let after = h.tick().expect("duplicate tick after completion");
    assert_eq!(after.outcome(), TickOutcome::Noop);
    assert_eq!(h.notifier.count(), 1);
}

#[test]
fn fixable_fail_and_unmet_continue_the_same_child_with_a_new_run_and_input() {
    let mut h = Harness::new();
    let ids = ids(h.project);
    h.checks.push_status(ids.check_b, CheckStatus::Fail);
    h.checks.push_status(ids.check_b, CheckStatus::Pass);
    h.assessment
        .push_verdict(ids.condition_a, ConditionVerdict::Met);
    h.assessment
        .push_verdict(ids.condition_b, ConditionVerdict::Unmet);
    h.assessment
        .push_verdict(ids.condition_a, ConditionVerdict::Met);
    h.assessment
        .push_verdict(ids.condition_b, ConditionVerdict::Met);

    h.tick().expect("first start intent");
    h.tick_until_awaiting_input(4);
    let first_run = h.current_run();
    let first_input = h.current_input();
    h.runtime.complete_input(first_input);

    let first_cycle = h.evaluate_until_blocked(80);
    assert_eq!(
        first_cycle.outcome(),
        TickOutcome::Advanced,
        "the cycle should prepare a continuation"
    );
    assert_eq!(h.state(), SupervisionState::Running);
    assert_eq!(
        h.record().supervisor().phase(),
        SupervisorPhase::StartingRun
    );

    let second_run = h.current_run();
    let second_input = h.current_input();
    assert_ne!(second_run, first_run);
    assert_ne!(second_input, first_input);
    let groups = h.record().run_group().runs().to_vec();
    assert_eq!(groups, vec![first_run, second_run]);

    assert!(h.runtime.continuations.is_empty());
    h.tick().expect("continue intent");
    h.tick_until_awaiting_input(4);
    assert_eq!(h.runtime.continuations.len(), 1);
    let continuation = &h.runtime.continuations[0];
    assert_eq!(continuation.previous_run_id(), first_run);
    assert_eq!(continuation.run_id(), second_run);
    assert_eq!(continuation.input_id(), second_input);
    assert_eq!(
        continuation.condition_version(),
        h.record().condition_version()
    );
    assert_eq!(continuation.target_version(), h.record().target_version());
    assert_eq!(continuation.profile(), h.record().profile());
    assert_eq!(continuation.consent(), h.record().consent());
    assert!(
        continuation
            .deficiency()
            .failed_checks()
            .iter()
            .any(|check| check.check_id() == ids.check_b),
        "the failing check must be returned to the child"
    );
    assert!(
        continuation
            .deficiency()
            .unmet_conditions()
            .contains(&ids.condition_b)
    );
    assert!(!continuation.deficiency().evidence().is_empty());

    h.runtime.complete_input(second_input);
    let completed = h.evaluate_until_blocked(80);
    assert_eq!(completed.outcome(), TickOutcome::Completed);
    assert_eq!(h.state(), SupervisionState::Completed);
    assert_eq!(h.notifier.count(), 1);
    assert_eq!(h.runtime.starts.len(), 1);
    assert_eq!(h.runtime.continuations.len(), 1);
    assert_eq!(h.record().run_group().runs().len(), 2);
    assert_eq!(
        h.checks.executions.len(),
        3,
        "the passing check must be reused in the second cycle"
    );
    assert!(
        h.assessment
            .calls
            .iter()
            .map(|request| request.id())
            .collect::<BTreeSet<_>>()
            .len()
            == h.assessment.calls.len(),
        "each assessment cycle must use a distinct request ID"
    );
}

#[test]
fn a_required_check_fail_cannot_be_overridden_by_a_model_met() {
    let mut h = Harness::new();
    let ids = ids(h.project);
    for _ in 0..8 {
        h.checks.push_status(ids.check_a, CheckStatus::Fail);
    }
    h.assessment.set_default_verdict(ConditionVerdict::Met);

    h.tick().expect("start intent");
    for cycle in 0..6 {
        h.tick_until_awaiting_input(4);
        let input = h.current_input();
        h.runtime.complete_input(input);
        let report = h.evaluate_until_blocked(120);
        if h.state() == SupervisionState::Stopped {
            assert_eq!(report.outcome(), TickOutcome::Stopped);
            break;
        }
        assert_ne!(
            h.state(),
            SupervisionState::Completed,
            "cycle {cycle} completed"
        );
        assert!(h.record().completion().is_none());
        assert!(
            h.record().unmet_conditions().is_empty(),
            "the fake model returned met for every condition"
        );
    }

    assert_eq!(h.state(), SupervisionState::Stopped);
    assert!(matches!(
        h.record().reason(),
        herness_supervision::state::SupervisionReason::Stopped {
            cause: StopCause::Stagnation
        }
    ));
    assert!(h.record().completion().is_none());
    assert!(
        h.notifier
            .all()
            .iter()
            .all(|n| n.state() != SupervisionState::Completed)
    );
}

#[test]
fn startup_idle_normal_end_and_idle_without_completed_input_never_verify() {
    let mut h = Harness::new();
    h.tick().expect("start intent");
    h.tick_until_awaiting_input(4);
    let run = h.current_run();
    let input = h.current_input();

    h.runtime.set_run_state(run, RunState::Idle);
    h.runtime.set_input_phase(input, InputPhase::Accepted);
    for _ in 0..4 {
        h.tick().expect("startup idle tick");
    }
    assert_eq!(h.checks.executions.len(), 0);
    assert_eq!(h.assessment.calls.len(), 0);

    h.runtime.set_input_phase(input, InputPhase::Started);
    h.runtime.set_run_state(run, RunState::Idle);
    for _ in 0..4 {
        h.tick().expect("normal end tick");
    }
    assert_eq!(h.checks.executions.len(), 0);
    assert_eq!(h.assessment.calls.len(), 0);

    h.runtime.set_input_phase(input, InputPhase::Completed);
    h.runtime.set_run_state(run, RunState::Running);
    for _ in 0..4 {
        h.tick().expect("completed but active tick");
    }
    assert_eq!(h.checks.executions.len(), 0);
    assert_eq!(h.assessment.calls.len(), 0);

    h.runtime.set_run_state(run, RunState::Idle);
    h.tick().expect("stable transition");
    assert_eq!(h.state(), SupervisionState::Verifying);
    assert_eq!(
        h.checks.executions.len(),
        0,
        "verification starts next tick"
    );
    h.tick().expect("first check");
    assert_eq!(h.checks.executions.len(), 1);
}

#[test]
fn assessment_is_refused_while_a_run_is_active() {
    let mut h = Harness::new();
    let run = start_and_complete_first_input(&mut h);
    tick_to_assessing(&mut h);
    assert_eq!(h.state(), SupervisionState::Assessing);
    let before = h.record();

    h.runtime.set_run_state(run, RunState::Running);
    let refused = h.tick().expect("active run tick");
    assert_eq!(refused.outcome(), TickOutcome::AssessmentRefused);
    assert_eq!(h.assessment.calls.len(), 0);
    assert_eq!(h.record().revision(), before.revision());
    assert_eq!(h.notifier.count(), 0);

    h.runtime.set_run_state(run, RunState::Idle);
    let prepared = h.tick().expect("prepare assessment");
    assert_eq!(prepared.outcome(), TickOutcome::AwaitingAssessment);
    let sent = h.tick().expect("send assessment");
    assert_eq!(sent.outcome(), TickOutcome::AwaitingAssessment);
    assert_eq!(h.assessment.calls.len(), 1);
}

#[derive(Clone, Copy)]
enum DuringAssessmentChange {
    Conditions,
    Target,
    Profile,
    Consent,
}

#[test]
fn a_change_during_assessment_is_history_only_and_never_completes() {
    for change in [
        DuringAssessmentChange::Conditions,
        DuringAssessmentChange::Target,
        DuringAssessmentChange::Profile,
        DuringAssessmentChange::Consent,
    ] {
        let mut h = Harness::new();
        let ids = ids(h.project);
        start_and_complete_first_input(&mut h);
        tick_to_assessing(&mut h);
        h.tick().expect("prepare pending assessment");
        assert!(h.record().supervisor().pending_assessment().is_some());

        let store = h.store.clone();
        let contract = h.contract.clone();
        let project = h.project;
        h.assessment.on_assess(move || {
            store
                .revise(|record| match change {
                    DuringAssessmentChange::Conditions => record
                        .revise_conditions(
                            ApprovalActor::Human,
                            ConditionVersion::new(2).expect("version"),
                            vec![ids.condition_a, ids.condition_b],
                            vec![ids.check_a, ids.check_b],
                        )
                        .expect("revise conditions"),
                    DuringAssessmentChange::Target => record
                        .revise_target(
                            ApprovalActor::Human,
                            TargetVersion::new(2).expect("version"),
                        )
                        .expect("revise target"),
                    DuringAssessmentChange::Profile => record
                        .revise_profile(
                            ApprovalActor::Human,
                            herness_supervision::profiles::ProfileBinding::new(
                                contract.profile().profile_id(),
                                herness_supervision::profiles::ProfileVersion::new(2)
                                    .expect("version"),
                                herness_supervision::profiles::ProfilePurpose::Completion,
                            ),
                        )
                        .expect("revise profile"),
                    DuringAssessmentChange::Consent => record
                        .revise_consent(
                            ApprovalActor::Human,
                            herness_supervision_tests::consent(
                                project,
                                herness_supervision::profiles::ProfilePurpose::Completion,
                                2,
                            )
                            .binding(),
                        )
                        .expect("revise consent"),
                })
                .expect("out-of-band revision");
        });

        let report = h.tick().expect("send assessment after change");
        assert_eq!(report.outcome(), TickOutcome::StaleAssessment);
        let record = h.record();
        assert_eq!(record.state(), SupervisionState::WaitingHuman);
        assert!(record.completion().is_none());
        assert!(record.applied_decisions().is_empty());
        assert_eq!(record.invalidated_decisions().len(), 1);
        assert_eq!(h.assessment.calls.len(), 1);

        let before = h.record();
        h.tick().expect("late duplicate tick");
        assert_eq!(h.record().revision(), before.revision());
        assert_eq!(h.assessment.calls.len(), 1);
        assert_eq!(h.notifier.count(), 0);
    }
}

#[test]
fn three_no_progress_cycles_stop_and_relevant_new_evidence_counts_as_progress() {
    // Part A: logs, tool counts, and unrelated content changes do not count.
    let mut h = Harness::new();
    h.checks.set_default_status(CheckStatus::Fail);
    h.assessment.set_default_verdict(ConditionVerdict::Unmet);
    h.runtime.tool_calls = 0;

    for cycle in 0..6 {
        if h.record().supervisor().phase() == SupervisorPhase::Idle {
            h.tick().expect("start intent");
        }
        h.tick_until_awaiting_input(4);
        let input = h.current_input();
        h.runtime.complete_input(input);
        h.runtime.tool_calls = h.runtime.tool_calls.saturating_add(cycle + 1);
        h.runtime.workspace.write(
            "unrelated.txt",
            format!("unrelated change {cycle}").as_bytes(),
        );
        let report = h.evaluate_until_blocked(120);
        if h.state() == SupervisionState::Stopped {
            assert_eq!(report.outcome(), TickOutcome::Stopped);
            break;
        }
        assert_ne!(h.state(), SupervisionState::Completed);
    }
    assert_eq!(h.state(), SupervisionState::Stopped);
    assert!(matches!(
        h.record().reason(),
        herness_supervision::state::SupervisionReason::Stopped {
            cause: StopCause::Stagnation
        }
    ));
    assert_eq!(h.runtime.starts.len(), 1);
    assert_eq!(h.runtime.continuations.len(), 2);
    assert_eq!(h.record().run_group().runs().len(), 3);
    assert!(
        h.runtime.tool_calls > 0,
        "tool counts changed but were ignored"
    );

    // Part B: a new relevant investigation evidence item is progress even
    // without a file edit.
    let mut h = Harness::new();
    h.checks.set_default_status(CheckStatus::Fail);
    h.assessment.set_default_verdict(ConditionVerdict::Unmet);
    h.runtime.enable_investigation_evidence();

    for _ in 0..5 {
        if h.record().supervisor().phase() == SupervisorPhase::Idle {
            h.tick().expect("start intent");
        }
        h.tick_until_awaiting_input(4);
        let input = h.current_input();
        h.runtime.complete_input(input);
        let report = h.evaluate_until_blocked(120);
        assert_ne!(report.outcome(), TickOutcome::Stopped);
    }
    assert_eq!(h.state(), SupervisionState::Running);
    assert_eq!(h.record().supervisor().stagnation_cycles(), 0);
    assert_eq!(h.runtime.starts.len(), 1);
    assert_eq!(h.runtime.continuations.len(), 4);
    assert_eq!(h.record().run_group().runs().len(), 6);
    assert_eq!(
        h.evidence
            .all()
            .iter()
            .filter(|evidence| evidence.check_id().is_none())
            .count(),
        5
    );
}

#[test]
fn duplicate_ticks_and_request_ids_do_not_repeat_side_effects() {
    let mut h = Harness::new();
    let event = h.next_event_id();
    let first = h.tick_with(event).expect("first tick");
    assert_eq!(first.outcome(), TickOutcome::Advanced);
    let mutations = h.store.mutations();
    let duplicate = h.tick_with(event).expect("duplicate tick");
    assert_eq!(duplicate.outcome(), TickOutcome::Duplicate);
    assert_eq!(h.store.mutations(), mutations);

    // A compare-and-swap failure after the runtime start is retried with the
    // same deterministic runtime request ID and does not start a second run.
    let mut h = Harness::new();
    h.tick().expect("start intent");
    h.store.fail_next_commit();
    let failed = h.tick().expect("start commit fails");
    assert_eq!(failed.outcome(), TickOutcome::StaleRevision);
    assert_eq!(h.runtime.starts.len(), 1);
    assert_eq!(
        h.record().supervisor().phase(),
        SupervisorPhase::StartingRun
    );
    h.tick().expect("retry start");
    assert_eq!(h.runtime.starts.len(), 1);
    assert_eq!(
        h.record().supervisor().phase(),
        SupervisorPhase::AwaitingInput
    );

    // Completion notification is delivered once and a redelivered event is
    // answered from the command journal.
    let mut h = Harness::new();
    let (completion_event, report) = complete_normally_with_last_event(&mut h);
    assert_eq!(report.outcome(), TickOutcome::Completed);
    assert_eq!(h.notifier.count(), 1);
    let duplicate = h.tick_with(completion_event).expect("duplicate completion");
    assert_eq!(duplicate.outcome(), TickOutcome::Duplicate);
    assert_eq!(h.notifier.count(), 1);
    let after = h.tick().expect("new event after completion");
    assert_eq!(after.outcome(), TickOutcome::Noop);
    assert_eq!(h.notifier.count(), 1);
}

#[test]
fn thirty_one_runs_are_allowed_and_the_thirty_second_is_refused_across_reopen() {
    let mut h = Harness::new();
    h.runtime.enable_investigation_evidence();
    h.checks.set_default_status(CheckStatus::Fail);
    h.assessment.set_default_verdict(ConditionVerdict::Unmet);

    for _ in 0..40 {
        if h.state() == SupervisionState::Stopped {
            break;
        }
        if h.record().supervisor().phase() == SupervisorPhase::Idle {
            h.tick().expect("start intent");
        }
        h.tick_until_awaiting_input(4);
        let input = h.current_input();
        h.runtime.complete_input(input);
        h.evaluate_until_blocked(140);
    }

    assert_eq!(h.state(), SupervisionState::Stopped);
    assert!(matches!(
        h.record().reason(),
        herness_supervision::state::SupervisionReason::Stopped {
            cause: StopCause::Budget(BudgetLimit::RunCount)
        }
    ));
    assert_eq!(h.record().run_group().runs().len(), 31);
    assert_eq!(h.runtime.starts.len(), 1);
    assert_eq!(h.runtime.continuations.len(), 30);
    assert_eq!(h.budget.record().usage().runs_started(), 31);
    assert_eq!(
        h.record()
            .supervisor()
            .current_run()
            .map(|run| run == h.current_run()),
        Some(true)
    );

    let mut reopened = BudgetLedger::open(
        h.budget_store.clone(),
        h.project,
        h.supervision,
        h.budget_policy.clone(),
        1,
        h.budget_clock.clone(),
    )
    .expect("reopen budget ledger");
    assert_eq!(reopened.record().usage().runs_started(), 31);
    let next_request = BudgetRequestId::from_parts(
        h.project,
        Uuid::from_u128(0x4000_0000_0000_4000_8000_0000_0000_0001),
    );
    assert_eq!(
        BudgetLedger::start_run(&mut reopened, next_request),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::RunCount
        })
    );
}

#[test]
fn budget_time_and_human_wait_take_priority_over_completion() {
    // Active time exhausted before completion.
    let mut h = Harness::with_policy(BudgetPolicy::new(1, 30, None).expect("finite policy"));
    let run = start_and_complete_first_input(&mut h);
    h.clock.advance_seconds(2);
    h.budget_clock.advance_seconds(2);
    let _ = run;
    let stopped = h.evaluate_until_blocked(120);
    assert_eq!(stopped.outcome(), TickOutcome::Stopped);
    assert_eq!(h.state(), SupervisionState::Stopped);
    assert!(matches!(
        h.record().reason(),
        herness_supervision::state::SupervisionReason::Stopped {
            cause: StopCause::Budget(BudgetLimit::ActiveSeconds)
        }
    ));
    assert!(h.record().completion().is_none());

    // Inconclusive verification waits for a human and never reaches assessment.
    let mut h = Harness::new();
    let ids = ids(h.project);
    h.checks.push_status(ids.check_a, CheckStatus::Inconclusive);
    let _ = start_and_complete_first_input(&mut h);
    let waiting = h.evaluate_until_blocked(120);
    assert_eq!(waiting.outcome(), TickOutcome::WaitingHuman);
    assert_eq!(h.state(), SupervisionState::WaitingHuman);
    assert!(matches!(
        h.record().reason(),
        herness_supervision::state::SupervisionReason::WaitingHuman {
            action: herness_supervision::state::HumanAction::ReconcileRecovery
        }
    ));
    assert_eq!(h.assessment.calls.len(), 0);
    assert!(h.record().completion().is_none());

    // An insufficient assessment waits for a human and does not start another run.
    let mut h = Harness::new();
    h.assessment
        .set_default_verdict(ConditionVerdict::Insufficient);
    let _ = start_and_complete_first_input(&mut h);
    let waiting = h.evaluate_until_blocked(120);
    assert_eq!(waiting.outcome(), TickOutcome::WaitingHuman);
    assert_eq!(h.state(), SupervisionState::WaitingHuman);
    assert!(matches!(
        h.record().reason(),
        herness_supervision::state::SupervisionReason::WaitingHuman {
            action: herness_supervision::state::HumanAction::DecideAssessment
        }
    ));
    assert_eq!(h.runtime.starts.len(), 1);
    assert_eq!(h.runtime.continuations.len(), 0);
    assert!(h.record().completion().is_none());
}

#[test]
fn a_stale_revision_does_not_double_mutate_or_notify() {
    let mut h = Harness::new();
    start_and_complete_first_input(&mut h);
    tick_to_assessing(&mut h);
    // Complete both condition assessments so the next tick is the completion
    // candidate.
    h.tick().expect("prepare A");
    h.tick().expect("send A");
    h.tick().expect("prepare B");
    h.tick().expect("send B");
    assert_eq!(h.state(), SupervisionState::Assessing);

    let before = h.record();
    let mutations = h.store.mutations();
    h.store.fail_next_commit();
    let stale = h.tick().expect("completion CAS conflict");
    assert_eq!(stale.outcome(), TickOutcome::StaleRevision);
    assert_eq!(h.record().revision(), before.revision());
    assert_eq!(h.store.mutations(), mutations);
    assert_eq!(h.notifier.count(), 0);

    let completed = h.tick().expect("completion retry");
    assert_eq!(completed.outcome(), TickOutcome::Completed);
    assert_eq!(h.notifier.count(), 1);
}

// ---------------------------------------------------------------------------
// Small shared test flows
// ---------------------------------------------------------------------------

fn start_and_complete_first_input(h: &mut Harness) -> RunId {
    h.tick().expect("start intent");
    h.tick_until_awaiting_input(4);
    let run = h.current_run();
    let input = h.current_input();
    h.runtime.complete_input(input);
    h.tick().expect("verifying transition");
    assert_eq!(h.state(), SupervisionState::Verifying);
    run
}

fn tick_to_assessing(h: &mut Harness) {
    for _ in 0..8 {
        h.tick().expect("advance verification");
        if h.state() == SupervisionState::Assessing {
            return;
        }
    }
    panic!("did not reach assessing: {:?}", h.record());
}

fn complete_normally_with_last_event(h: &mut Harness) -> (SupervisionRequestId, TickReport) {
    h.tick().expect("start intent");
    h.tick_until_awaiting_input(4);
    let input = h.current_input();
    h.runtime.complete_input(input);
    let mut last = h.tick().expect("verifying transition");
    for _ in 0..80 {
        if matches!(
            h.state(),
            SupervisionState::Completed
                | SupervisionState::Stopped
                | SupervisionState::WaitingHuman
        ) {
            return (h.last_event.expect("last event"), last);
        }
        last = h.tick().expect("evaluate");
    }
    panic!("did not complete");
}

#[test]
fn deterministic_conditions_complete_from_required_checks_without_model_assessment() {
    let mut h = Harness::new();
    h.assessment.disable_semantic_assessment();
    let _ = start_and_complete_first_input(&mut h);
    let report = h.evaluate_until_blocked(80);
    assert_eq!(report.outcome(), TickOutcome::Completed);
    assert_eq!(h.assessment.calls.len(), 0);
    assert_eq!(h.checks.executions.len(), 2);
    assert_eq!(h.notifier.count(), 1);
    assert_eq!(h.record().applied_decisions().len(), 2);
    assert!(h.record().unmet_conditions().is_empty());
}

#[test]
fn valid_child_ci_and_human_evidence_is_reused_without_reexecution() {
    let mut h = Harness::new();
    let ids = ids(h.project);
    seed_check_evidence(
        &h,
        ids.check_a,
        ids.condition_a,
        EvidenceAcquirer::Human,
        Some("fixture-human-reviewer"),
        1,
    );
    seed_check_evidence(
        &h,
        ids.check_b,
        ids.condition_b,
        EvidenceAcquirer::Ci,
        None,
        2,
    );

    start_and_complete_first_input(&mut h);
    tick_to_assessing(&mut h);
    assert_eq!(
        h.checks.executions.len(),
        0,
        "valid evidence must be reused"
    );
    assert_eq!(h.record().supervisor().check_results().len(), 2);

    let report = h.evaluate_until_blocked(80);
    assert_eq!(report.outcome(), TickOutcome::Completed);
    assert_eq!(h.checks.executions.len(), 0);
    assert_eq!(h.notifier.count(), 1);
    assert_eq!(
        h.record()
            .completion()
            .expect("completion")
            .evidence()
            .len(),
        2
    );
}

#[test]
fn final_recheck_rejects_target_content_changed_after_assessment_and_reverifies() {
    let mut h = Harness::new();
    start_and_complete_first_input(&mut h);
    tick_to_assessing(&mut h);
    h.tick().expect("prepare A");
    h.tick().expect("send A");
    h.tick().expect("prepare B");
    h.tick().expect("send B");
    assert_eq!(h.state(), SupervisionState::Assessing);
    let old_digest = h
        .record()
        .supervisor()
        .last_target_digest()
        .cloned()
        .expect("target digest");

    h.runtime
        .workspace
        .write("src/lib.rs", b"changed after assessment");
    let reworked = h.tick().expect("final recheck tick");
    assert_eq!(reworked.outcome(), TickOutcome::Advanced);
    assert_eq!(h.state(), SupervisionState::Verifying);
    assert!(h.record().completion().is_none());
    assert_eq!(h.notifier.count(), 0);

    let report = h.evaluate_until_blocked(120);
    assert_eq!(report.outcome(), TickOutcome::Completed);
    let record = h.record();
    let completion = record.completion().expect("completion");
    assert_ne!(completion.observation_digest(), &old_digest);
    assert_eq!(h.checks.executions.len(), 4);
    assert_eq!(h.notifier.count(), 1);
}

#[test]
fn an_unconfirmed_stop_blocks_new_runs_and_reassessment() {
    let mut h = Harness::new();
    h.checks.set_default_status(CheckStatus::Fail);
    h.assessment.set_default_verdict(ConditionVerdict::Unmet);
    h.runtime.stop_disposition = StopDisposition::Unconfirmed;

    for _ in 0..6 {
        if h.state() == SupervisionState::Stopped {
            break;
        }
        if h.record().supervisor().phase() == SupervisorPhase::Idle {
            h.tick().expect("start intent");
        }
        h.tick_until_awaiting_input(4);
        let input = h.current_input();
        h.runtime.complete_input(input);
        h.evaluate_until_blocked(120);
    }
    assert_eq!(h.state(), SupervisionState::Stopped);
    assert!(matches!(
        h.record().reason(),
        herness_supervision::state::SupervisionReason::Stopped {
            cause: StopCause::StopUnconfirmed
        }
    ));
    assert_eq!(h.record().run_group().runs().len(), 3);
    assert_eq!(h.runtime.continuations.len(), 2);
    let before = h.record();
    h.tick().expect("no tick after unconfirmed stop");
    assert_eq!(h.record().revision(), before.revision());
    assert!(h.record().completion().is_none());
}

#[test]
fn a_failed_child_run_is_unrecoverable_and_blocks_completion() {
    let mut h = Harness::new();
    h.tick().expect("start intent");
    h.tick_until_awaiting_input(4);
    let run = h.current_run();
    h.runtime.set_run_state(run, RunState::Failed);
    let report = h.tick().expect("failed run tick");
    assert_eq!(h.state(), SupervisionState::Failed);
    assert_eq!(report.outcome(), TickOutcome::Failed);
    assert!(matches!(
        h.record().reason(),
        herness_supervision::state::SupervisionReason::Failed {
            failure: herness_supervision::state::SupervisionFailure::TargetUnstable
        }
    ));
    assert!(h.record().completion().is_none());
    assert_eq!(h.checks.executions.len(), 0);
    assert_eq!(h.assessment.calls.len(), 0);
    assert_eq!(h.notifier.count(), 1);
}

fn seed_check_evidence(
    h: &Harness,
    check_id: CheckId,
    condition_id: ConditionId,
    acquirer: EvidenceAcquirer,
    observer: Option<&str>,
    sequence: u64,
) {
    let check = h
        .contract
        .conditions()
        .checks()
        .iter()
        .find(|check| check.id() == check_id)
        .expect("fixture check");
    let snapshot = capture_target_snapshot(
        &h.runtime.workspace,
        &TargetSnapshotRequest::new(
            h.project,
            h.supervision,
            TargetVersion::new(1).expect("version"),
            h.contract.evidence_target().read_set().to_vec(),
        ),
    )
    .expect("target snapshot");
    let mut record = EvidenceRecord::new(
        EvidenceId::from_parts(
            h.project,
            Uuid::from_u128(0x5000_0000_0000_4000_8000_0000_0000_0000 + sequence as u128),
        ),
        h.supervision,
        Some(condition_id),
        Some(check_id),
        acquirer,
        check.operation().clone(),
        EvidenceOutcome::new(Some(0), None, false, false, "seeded observation").expect("outcome"),
        snapshot.target_scope().expect("target scope"),
        EvidenceScope::new(
            vec!["src/lib.rs".to_owned()],
            vec!["seeded evidence only".to_owned()],
        )
        .expect("scope"),
        CheckStatus::Pass,
        sequence,
        now(),
    )
    .expect("seeded evidence");
    if let Some(observer) = observer {
        record = record.with_observer(observer);
    }
    h.evidence.push(record);
}
