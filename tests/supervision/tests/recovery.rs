//! Task 15 recovery, reconciliation, and explicit human operation tests.
//!
//! Each case uses a real temporary SQLite `herness-store` opened through two
//! separate handles (the two "processes"/openings) and a fake H1 runtime. No
//! provider, credential, Keychain item, Tauri window, shell, or external process
//! is used. Recovery is checked to make zero model requests, runs, tool
//! executions, and auto-resumes.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;

use herness_core::contracts::{
    AgentId, AttemptId, AuthMethod, CheckpointFormatVersion, ConnectionId, EventKind, EventSubject,
    FrozenOperation, HostActivityId, HostActivitySubject, ModelId, ModelRequestObservation,
    ProjectId, ProviderFailureKind, RequestGateIntent, RequestId, RequestOutcome, RequestPurpose,
    RunId, RunState, RunSubject, SessionId, StopDeadlineControl, Timestamp, TokenUsage,
};
use herness_core::runtime::RecoveryMode;
use herness_core::{
    AbsolutePath, Checkpoint, CheckpointCommit, CheckpointPayload, NonEmptyText, OperationId,
    OperationIntent, OperationOutcome, OperationResult, PermissionMode, PolicyVersion, Rationale,
    ToolArguments, ToolName, WriteArgs,
};
use herness_store::test_support::CommitFault;
use herness_store::{Store, StoreConfig};
use herness_supervision::approval::{ApprovalActor, OwnerApprovalSource};
use herness_supervision::budget::ledger::{
    BudgetClockPort, BudgetLedger, ClockReading, MoneySettlement,
};
use herness_supervision::budget::{
    BudgetLimit, BudgetPolicy, Money, MoneyCap, PriceVersion, RequestBudgetEstimate,
};
use herness_supervision::conditions::ConditionVersion;
use herness_supervision::consent::DisclosureConsent;
use herness_supervision::contract::{
    ExecutionScope, OwnerKind, OwnerRef, RunGroup, SupervisionContract, SupervisionSubject,
};
use herness_supervision::evidence::TargetVersion;
use herness_supervision::ids::{BudgetRequestId, SupervisionId, SupervisionRequestId};
use herness_supervision::operations::{
    HumanOperation, OperationPorts, OperationResult as OwnerOperationResult, OperationRuntimePort,
    OwnerSupersessionRequest, SupervisionChange, SupervisionOperationRequest, execute_operation,
    execute_owner_supersession,
};
use herness_supervision::owner_launch::{
    HostOwnerAuthority, OwnerLaunchBinding, authorize_owner_launch,
};
use herness_supervision::ports::{ClockPort, SupervisionStorePort};
use herness_supervision::profiles::{
    AdapterVersion, AssessmentProfile, ProfileInputs, ProfilePurpose, ProfileThresholds,
    ProfileVersion, ProviderKind, RubricVersion,
};
use herness_supervision::recovery::{
    HistoryOnlyReason, ManagedProcessState, RecoveryBlockReason, RecoveryCheckpoint,
    RecoveryDisposition, RecoveryRuntimePort, RecoveryService, RecoveryStopState,
    UnresolvedRequestKind, mark_active_supervision_for_quit,
};
use herness_supervision::state::{
    CancelCause, ChangeKind, DecisionInvalidation, HumanAction, StaleCompletion, StopCause,
    SupervisionFailure, SupervisionReason, SupervisionRecord, SupervisionState,
};
use herness_supervision::supervisor::{
    OwnerNotificationPort, StopDisposition, SupervisorNotification,
};
use herness_supervision::OwnerSupersessionRejection;
use herness_supervision_tests::{
    ScriptedOwnerApprovalRegistry, approved_condition_set_at, assessment_request, assessment_result,
    completion_profile, completion_snapshot, consent_for_origin, contract, ids, now, other_origin,
    owner_contract_at, owner_contract_succeeding, project, target_scope,
};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Store harness
// ---------------------------------------------------------------------------

struct Harness {
    _temp: TempDir,
    root: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp.path().join("app-data");
        std::fs::create_dir_all(&root).expect("app data directory");
        Self { _temp: temp, root }
    }

    fn config(&self) -> StoreConfig {
        StoreConfig::new(&self.root).expect("store config")
    }

    fn open(&self) -> Store {
        Store::open(self.config()).expect("open store")
    }
}

fn save_new(store: &mut Store, record: &SupervisionRecord) {
    store
        .compare_and_swap_supervision(record.project_id(), record.supervision_id(), None, record)
        .expect("save new supervision record");
}

fn save_update(store: &mut Store, expected: u64, record: &SupervisionRecord) {
    store
        .compare_and_swap_supervision(
            record.project_id(),
            record.supervision_id(),
            Some(expected),
            record,
        )
        .expect("update supervision record");
}

fn save_budget(
    store: &mut Store,
    record: &herness_supervision::budget::ledger::BudgetLedgerRecord,
) {
    store
        .compare_and_swap_budget_record(
            record_project(record),
            record_supervision(record),
            None,
            record,
        )
        .expect("save budget");
}

fn record_project(_record: &herness_supervision::budget::ledger::BudgetLedgerRecord) -> ProjectId {
    project()
}

fn record_supervision(
    _record: &herness_supervision::budget::ledger::BudgetLedgerRecord,
) -> SupervisionId {
    ids(project()).supervision
}

fn default_budget_record(
    project_id: ProjectId,
) -> herness_supervision::budget::ledger::BudgetLedgerRecord {
    herness_supervision::budget::ledger::BudgetLedgerRecord::new(
        contract(project_id).budget().clone(),
        1,
    )
    .expect("budget record")
}

// ---------------------------------------------------------------------------
// Clock, fake H1 runtime, notifications
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl FixedClock {
    fn fixture() -> Self {
        Self(now().as_unix_millis())
    }
}

impl ClockPort for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.0)
    }
}

impl BudgetClockPort for FixedClock {
    fn read(&self) -> ClockReading {
        ClockReading::new(self.now(), 0)
    }
}

struct FakeRuntime {
    run_states: BTreeMap<RunId, RunState>,
    recovery_modes: BTreeMap<RunId, RecoveryMode>,
    checkpoints: BTreeMap<RunId, RecoveryCheckpoint>,
    stop_states: BTreeMap<RunId, RecoveryStopState>,
    managed: BTreeMap<RunId, Vec<ManagedProcessState>>,
    stop_result: StopDisposition,
    stop_calls: u32,
    starts: u32,
    assessments: u32,
    permissions_current: bool,
}

impl FakeRuntime {
    fn new() -> Self {
        Self {
            run_states: BTreeMap::new(),
            recovery_modes: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            stop_states: BTreeMap::new(),
            managed: BTreeMap::new(),
            stop_result: StopDisposition::Confirmed,
            stop_calls: 0,
            starts: 0,
            assessments: 0,
            permissions_current: true,
        }
    }

    fn set_run(&mut self, run: RunId, state: RunState, mode: RecoveryMode) {
        self.run_states.insert(run, state);
        self.recovery_modes.insert(run, mode);
        self.checkpoints.insert(run, RecoveryCheckpoint::Present);
        self.stop_states.insert(run, RecoveryStopState::Confirmed);
        self.managed.insert(run, Vec::new());
    }

    fn assert_zero_external_work(&self) {
        assert_eq!(self.starts, 0, "recovery must not start a run");
        assert_eq!(self.assessments, 0, "recovery must not assess");
    }
}

impl RecoveryRuntimePort for FakeRuntime {
    fn run_state(
        &mut self,
        run: RunId,
    ) -> Result<RunState, herness_supervision::error::SupervisionError> {
        Ok(self.run_states.get(&run).copied().unwrap_or(RunState::Idle))
    }

    fn recovery_mode(
        &mut self,
        run: RunId,
    ) -> Result<RecoveryMode, herness_supervision::error::SupervisionError> {
        Ok(self
            .recovery_modes
            .get(&run)
            .copied()
            .unwrap_or(RecoveryMode::Restored))
    }

    fn managed_processes(
        &mut self,
        run: RunId,
    ) -> Result<Vec<ManagedProcessState>, herness_supervision::error::SupervisionError> {
        Ok(self.managed.get(&run).cloned().unwrap_or_default())
    }

    fn checkpoint(
        &mut self,
        run: RunId,
    ) -> Result<RecoveryCheckpoint, herness_supervision::error::SupervisionError> {
        Ok(self
            .checkpoints
            .get(&run)
            .cloned()
            .unwrap_or(RecoveryCheckpoint::Present))
    }

    fn stop_state(
        &mut self,
        run: RunId,
    ) -> Result<RecoveryStopState, herness_supervision::error::SupervisionError> {
        Ok(self
            .stop_states
            .get(&run)
            .copied()
            .unwrap_or(RecoveryStopState::NotRequested))
    }

    fn permissions_current(
        &mut self,
        _record: &SupervisionRecord,
    ) -> Result<bool, herness_supervision::error::SupervisionError> {
        Ok(self.permissions_current)
    }
}

impl OperationRuntimePort for FakeRuntime {
    fn request_stop(
        &mut self,
        run: RunId,
    ) -> Result<StopDisposition, herness_supervision::error::SupervisionError> {
        self.stop_calls = self.stop_calls.saturating_add(1);
        self.stop_states.insert(
            run,
            match self.stop_result {
                StopDisposition::Confirmed => RecoveryStopState::Confirmed,
                StopDisposition::Unconfirmed => RecoveryStopState::Unconfirmed,
            },
        );
        self.run_states.insert(
            run,
            match self.stop_result {
                StopDisposition::Confirmed => RunState::Paused,
                StopDisposition::Unconfirmed => RunState::Interrupted,
            },
        );
        Ok(self.stop_result)
    }
}

#[derive(Default)]
struct Notifications {
    count: Rc<Cell<u32>>,
}

impl Notifications {
    fn count(&self) -> u32 {
        self.count.get()
    }
}

impl OwnerNotificationPort for Notifications {
    fn notify(
        &mut self,
        _notification: &SupervisorNotification,
    ) -> Result<(), herness_supervision::error::SupervisionError> {
        self.count.set(self.count.get().saturating_add(1));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Model request helpers
// ---------------------------------------------------------------------------

fn run_subject(project_id: ProjectId, run: RunId) -> EventSubject {
    EventSubject::Run(
        RunSubject::new(
            project_id,
            AgentId::new(project_id),
            SessionId::new(project_id),
            run,
        )
        .expect("run subject"),
    )
}

fn activity_subject(project_id: ProjectId) -> EventSubject {
    EventSubject::HostActivity(
        HostActivitySubject::new(
            project_id,
            EventKind::new("supervision-assessment").expect("kind"),
            HostActivityId::new(project_id),
        )
        .expect("activity subject"),
    )
}

fn request_intent(project_id: ProjectId, run: RunId, purpose: &str) -> RequestGateIntent {
    RequestGateIntent::new(
        RequestId::new(project_id),
        AttemptId::new(project_id),
        ConnectionId::new(),
        RequestPurpose::new(purpose).expect("purpose"),
        run_subject(project_id, run),
        StopDeadlineControl::proceed(),
    )
    .expect("request intent")
}

fn activity_intent(project_id: ProjectId, purpose: &str) -> RequestGateIntent {
    RequestGateIntent::new(
        RequestId::new(project_id),
        AttemptId::new(project_id),
        ConnectionId::new(),
        RequestPurpose::new(purpose).expect("purpose"),
        activity_subject(project_id),
        StopDeadlineControl::proceed(),
    )
    .expect("activity intent")
}

fn observation(intent: &RequestGateIntent, outcome: RequestOutcome) -> ModelRequestObservation {
    ModelRequestObservation::new(
        intent.request_id(),
        intent.attempt_id(),
        outcome,
        (outcome == RequestOutcome::PreflightFailed).then_some(ProviderFailureKind::Network),
        None,
        TokenUsage::unknown(),
    )
    .expect("observation")
}

fn record_request(store: &mut Store, intent: &RequestGateIntent, outcome: Option<RequestOutcome>) {
    store
        .record_model_request(intent.clone(), now())
        .expect("record intent");
    if let Some(outcome) = outcome {
        store
            .record_model_request_observation(observation(intent, outcome), now())
            .expect("record observation");
    }
}

// ---------------------------------------------------------------------------
// Contract and record helpers
// ---------------------------------------------------------------------------

fn record_with_run(contract: &SupervisionContract, run: RunId) -> SupervisionRecord {
    let mut record = SupervisionRecord::new(contract);
    record.begin_run(run).expect("begin run");
    record
}

fn profile_at(project_id: ProjectId, version: u64) -> AssessmentProfile {
    AssessmentProfile::new(
        ids(project_id).profile,
        ProfileVersion::new(version).expect("version"),
        ProfilePurpose::Completion,
        ProviderKind::NormalLlm,
        ConnectionId::new(),
        ModelId::new("synthetic-completion-judge").expect("model"),
        AdapterVersion::new("fixture-llm-adapter-1").expect("adapter"),
        RubricVersion::new("fixture-rubric-1").expect("rubric"),
        ProfileInputs::new(true, true, true),
        ProfileThresholds::normal_llm(),
    )
    .expect("profile")
}

fn contract_with_versions(
    project_id: ProjectId,
    condition_version: u64,
    profile: AssessmentProfile,
    consent: DisclosureConsent,
    budget: BudgetPolicy,
) -> SupervisionContract {
    let ids = ids(project_id);
    let subject = SupervisionSubject::new(
        project_id,
        ids.supervision,
        AgentId::new(project_id),
        SessionId::new(project_id),
        OwnerRef::new(OwnerKind::Human, "fixture-human").expect("owner"),
    )
    .expect("subject");
    let execution = ExecutionScope::new(
        project_id,
        vec!["src".to_owned(), "Cargo.toml".to_owned()],
        vec!["src".to_owned()],
        true,
    )
    .expect("scope");
    let target = target_scope(project_id, 1);
    let conditions = approved_condition_set_at(project_id, condition_version);
    SupervisionContract::new(
        ApprovalActor::Human,
        subject,
        execution.clone(),
        RunGroup::new(ids.run_group),
        conditions.clone(),
        target.clone(),
        &profile,
        &consent,
        budget.clone(),
        herness_supervision_tests::work_packet(
            project_id,
            &target,
            &execution,
            conditions.condition_version(),
            &profile,
            &consent,
            &budget,
            "fixture recovery instruction",
        ),
        now(),
    )
    .expect("contract")
}

fn report_for(
    store: &mut Store,
    budget: &mut Store,
    runtime: &mut FakeRuntime,
    clock: &FixedClock,
    contract: &SupervisionContract,
    policy_version: u64,
) -> herness_supervision::recovery::RecoveryReport {
    let mut service = RecoveryService::new(store, runtime, budget, clock);
    service
        .recover(contract, policy_version)
        .expect("recovery report")
}

fn operation_ports<'a>(
    store: &'a mut Store,
    runtime: &'a mut FakeRuntime,
    budget: &'a mut dyn herness_supervision::operations::OperationBudgetPort,
    clock: &'a FixedClock,
) -> OperationPorts<'a> {
    OperationPorts {
        store,
        runtime,
        budget,
        clock,
    }
}

// ---------------------------------------------------------------------------
// Crash classification
// ---------------------------------------------------------------------------

fn crash_case(
    outcome: Option<RequestOutcome>,
    evaluating: bool,
) -> (
    herness_supervision::recovery::RecoveryReport,
    FakeRuntime,
    Store,
    SupervisionRecord,
) {
    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let sid = ids(project_id).supervision;
    let run = RunId::new(project_id);
    let mut record = record_with_run(&contract, run);
    if evaluating {
        record
            .begin_assessment(vec![
                ids(project_id).condition_a,
                ids(project_id).condition_b,
            ])
            .expect("assessment state");
    }

    let mut store = web.open();
    save_new(&mut store, &record);
    save_budget(&mut store, &default_budget_record(project_id));
    let intent = request_intent(project_id, run, "completion-assessment");
    let should_record = outcome.is_some();
    if should_record {
        record_request(&mut store, &intent, outcome);
    }

    let mut budget = web.open();
    let clock = FixedClock::fixture();
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Idle, RecoveryMode::Restored);
    let report = report_for(&mut store, &mut budget, &mut runtime, &clock, &contract, 1);
    assert_eq!(report.supervision_id(), sid);
    assert!(report.side_effects().is_zero());
    runtime.assert_zero_external_work();
    (report, runtime, store, record)
}

#[test]
fn reopen_classifies_crash_before_intent_as_recoverable_with_zero_requests() {
    let (report, _runtime, _store, _record) = crash_case(None, false);
    assert_eq!(report.disposition(), RecoveryDisposition::Recoverable);
    assert!(report.unresolved_requests().is_empty());
    assert!(report.history_only_requests().is_empty());
    assert!(report.side_effects().is_zero());
}

#[test]
fn reopen_keeps_intent_only_send_started_and_unknown_requests_waiting_for_human() {
    // Intent-only is never treated as "never sent".
    let (report, _runtime, _store, _record) = crash_case(None, false);
    assert!(report.unresolved_requests().is_empty());

    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let run = RunId::new(project_id);
    let mut record = record_with_run(&contract, run);
    record
        .begin_assessment(vec![ids(project_id).condition_a])
        .expect("assessment state");
    let mut store = web.open();
    save_new(&mut store, &record);
    save_budget(&mut store, &default_budget_record(project_id));
    let intent = request_intent(project_id, run, "completion-assessment");

    // intent-only
    let mut budget = web.open();
    let clock = FixedClock::fixture();
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Idle, RecoveryMode::Restored);
    store
        .record_model_request(intent.clone(), now())
        .expect("intent");
    let report = report_for(&mut store, &mut budget, &mut runtime, &clock, &contract, 1);
    assert_eq!(report.disposition(), RecoveryDisposition::WaitingHuman);
    assert_eq!(report.unresolved_requests().len(), 1);
    assert_eq!(
        report.unresolved_requests()[0].kind(),
        UnresolvedRequestKind::IntentOnly
    );

    // send-started
    let second = request_intent(project_id, run, "completion-assessment");
    store
        .record_model_request(second.clone(), now())
        .expect("intent");
    store
        .record_model_request_observation(observation(&second, RequestOutcome::SendStarted), now())
        .expect("started");
    let mut budget = web.open();
    let report = report_for(&mut store, &mut budget, &mut runtime, &clock, &contract, 1);
    assert_eq!(report.disposition(), RecoveryDisposition::WaitingHuman);
    assert!(
        report
            .unresolved_requests()
            .iter()
            .any(|item| item.kind() == UnresolvedRequestKind::SendStarted)
    );

    // send result unknown
    let third = request_intent(project_id, run, "completion-assessment");
    store
        .record_model_request(third.clone(), now())
        .expect("intent");
    store
        .record_model_request_observation(
            observation(&third, RequestOutcome::SendResultUnknown),
            now(),
        )
        .expect("unknown");
    let mut budget = web.open();
    let report = report_for(&mut store, &mut budget, &mut runtime, &clock, &contract, 1);
    assert_eq!(report.disposition(), RecoveryDisposition::WaitingHuman);
    assert!(
        report
            .unresolved_requests()
            .iter()
            .any(|item| item.kind() == UnresolvedRequestKind::SendUnknown)
    );
    assert!(report.side_effects().is_zero());
    runtime.assert_zero_external_work();
}

#[test]
fn host_activity_supervision_request_is_classified_for_recovery() {
    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let run = RunId::new(project_id);
    let record = record_with_run(&contract, run);
    let mut store = web.open();
    save_new(&mut store, &record);
    save_budget(&mut store, &default_budget_record(project_id));
    let intent = activity_intent(project_id, "completion-assessment");
    record_request(&mut store, &intent, None);

    let clock = FixedClock::fixture();
    let mut budget = web.open();
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Idle, RecoveryMode::Restored);
    let report = report_for(&mut store, &mut budget, &mut runtime, &clock, &contract, 1);
    assert_eq!(report.disposition(), RecoveryDisposition::WaitingHuman);
    assert_eq!(report.unresolved_requests().len(), 1);
    assert_eq!(
        report.unresolved_requests()[0].kind(),
        UnresolvedRequestKind::IntentOnly
    );
    runtime.assert_zero_external_work();
}

#[test]
fn terminal_observation_before_state_save_is_unresolved_but_after_save_is_history() {
    let (report, _runtime, _store, _record) = crash_case(Some(RequestOutcome::Completed), true);
    assert_eq!(report.disposition(), RecoveryDisposition::WaitingHuman);
    assert_eq!(report.unresolved_requests().len(), 1);
    assert_eq!(
        report.unresolved_requests()[0].kind(),
        UnresolvedRequestKind::TerminalObservedStateNotSaved
    );
    assert_eq!(report.history_only_requests().len(), 0);
    assert!(report.side_effects().is_zero());

    let (report, _runtime, _store, _record) = crash_case(Some(RequestOutcome::Completed), false);
    assert_eq!(report.disposition(), RecoveryDisposition::Recoverable);
    assert!(report.unresolved_requests().is_empty());
    assert_eq!(report.history_only_requests().len(), 1);
    assert_eq!(
        report.history_only_requests()[0].reason(),
        HistoryOnlyReason::AlreadyApplied
    );
    assert!(report.side_effects().is_zero());
}

// ---------------------------------------------------------------------------
// Stop, cancel, and idempotency
// ---------------------------------------------------------------------------

#[test]
fn unconfirmed_stop_and_cancel_race_record_one_terminal_transition() {
    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let sid = ids(project_id).supervision;
    let run = RunId::new(project_id);
    let record = record_with_run(&contract, run);
    let mut store = web.open();
    save_new(&mut store, &record);
    let ledger_store = web.open();
    let clock = FixedClock::fixture();
    let mut budget = BudgetLedger::open(
        ledger_store,
        project_id,
        sid,
        contract.budget().clone(),
        1,
        clock,
    )
    .expect("ledger");
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Running, RecoveryMode::SameProcess);
    runtime.stop_result = StopDisposition::Unconfirmed;

    let request = SupervisionOperationRequest::new(
        SupervisionRequestId::new(project_id),
        sid,
        HumanOperation::Stop,
        1,
    )
    .expect("request");
    let result = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        request,
    )
    .expect("stop");
    assert_eq!(result.command().state(), SupervisionState::Stopped);
    assert_eq!(runtime.stop_calls, 1);
    let after = store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    assert_eq!(after.state(), SupervisionState::Stopped);
    assert_eq!(
        after.reason(),
        &herness_supervision::state::SupervisionReason::Stopped {
            cause: StopCause::StopUnconfirmed
        }
    );
    assert_eq!(after.run_group().runs().len(), 1);
    assert_eq!(after.run_group().runs()[0], run);

    // A different request ID cannot perform a second stop on a terminal record.
    let second = SupervisionOperationRequest::new(
        SupervisionRequestId::new(project_id),
        sid,
        HumanOperation::Stop,
        after.revision(),
    )
    .expect("second");
    let second_result = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        second,
    )
    .expect("second stop");
    assert_eq!(second_result.command().state(), SupervisionState::Stopped);
    assert_eq!(runtime.stop_calls, 1);
    assert_eq!(
        store
            .load_supervision_record(project_id, sid)
            .unwrap()
            .unwrap()
            .revision(),
        after.revision()
    );

    // Cancel race: a persisted run intent is cancelled once; the run group is
    // retained and no second run is created.
    let race_web = Harness::new();
    let race_run = RunId::new(project_id);
    let race = record_with_run(&contract, race_run);
    let mut race_store = race_web.open();
    save_new(&mut race_store, &race);
    let race_ledger_store = race_web.open();
    let mut race_budget = BudgetLedger::open(
        race_ledger_store,
        project_id,
        sid,
        contract.budget().clone(),
        1,
        clock,
    )
    .expect("race ledger");
    let mut race_runtime = FakeRuntime::new();
    race_runtime.set_run(race_run, RunState::Running, RecoveryMode::SameProcess);
    let cancel = SupervisionOperationRequest::new(
        SupervisionRequestId::new(project_id),
        sid,
        HumanOperation::Cancel,
        1,
    )
    .expect("cancel");
    let cancel_result = execute_operation(
        operation_ports(&mut race_store, &mut race_runtime, &mut race_budget, &clock),
        &contract,
        1,
        cancel,
    )
    .expect("cancel");
    assert_eq!(cancel_result.command().state(), SupervisionState::Cancelled);
    assert_eq!(race_runtime.stop_calls, 1);
    let cancelled = race_store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    assert_eq!(cancelled.run_group().runs(), &[race_run]);
    let repeated = SupervisionOperationRequest::new(
        cancel_result.command().request_id(),
        sid,
        HumanOperation::Cancel,
        cancelled.revision(),
    )
    .expect("repeat cancel");
    let repeated_result = execute_operation(
        operation_ports(&mut race_store, &mut race_runtime, &mut race_budget, &clock),
        &contract,
        1,
        repeated,
    )
    .expect("repeat cancel");
    assert!(repeated_result.duplicate());
    assert_eq!(race_runtime.stop_calls, 1);
    assert_eq!(
        race_store
            .load_supervision_record(project_id, sid)
            .unwrap()
            .unwrap()
            .revision(),
        cancelled.revision()
    );
}

#[test]
fn duplicate_stop_resume_reassess_ids_are_idempotent_and_cas_conflict_has_no_side_effect() {
    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let sid = ids(project_id).supervision;
    let run = RunId::new(project_id);
    let record = record_with_run(&contract, run);
    let mut store = web.open();
    save_new(&mut store, &record);
    let ledger_store = web.open();
    let clock = FixedClock::fixture();
    let mut budget = BudgetLedger::open(
        ledger_store,
        project_id,
        sid,
        contract.budget().clone(),
        1,
        clock,
    )
    .expect("ledger");
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Running, RecoveryMode::SameProcess);

    // Stale expected revision: no stop, no record mutation.
    let stale = SupervisionOperationRequest::new(
        SupervisionRequestId::new(project_id),
        sid,
        HumanOperation::Stop,
        99,
    )
    .expect("stale");
    let stale_error = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        stale,
    )
    .expect_err("stale revision");
    assert!(matches!(
        stale_error,
        herness_supervision::error::SupervisionError::RevisionConflict { .. }
    ));
    assert_eq!(runtime.stop_calls, 0);
    assert_eq!(
        store
            .load_supervision_record(project_id, sid)
            .unwrap()
            .unwrap()
            .revision(),
        1
    );

    // Stop duplicate.
    let stop_id = SupervisionRequestId::new(project_id);
    let stop =
        SupervisionOperationRequest::new(stop_id, sid, HumanOperation::Stop, 1).expect("stop");
    let first = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        stop,
    )
    .expect("stop");
    assert_eq!(runtime.stop_calls, 1);
    let second = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        SupervisionOperationRequest::new(stop_id, sid, HumanOperation::Stop, 2)
            .expect("duplicate stop"),
    )
    .expect("duplicate stop");
    assert!(second.duplicate());
    assert_eq!(second.command().revision(), first.command().revision());
    assert_eq!(runtime.stop_calls, 1);

    // Resume a resolved stopped record, then duplicate the resume ID.
    let stopped = store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    let resume_id = SupervisionRequestId::new(project_id);
    let resume = SupervisionOperationRequest::new(
        resume_id,
        sid,
        HumanOperation::Resume,
        stopped.revision(),
    )
    .expect("resume");
    let resumed = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        resume,
    )
    .expect("resume");
    assert_eq!(resumed.command().state(), SupervisionState::Ready);
    let after_resume = store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    let duplicate = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        SupervisionOperationRequest::new(
            resume_id,
            sid,
            HumanOperation::Resume,
            after_resume.revision(),
        )
        .expect("duplicate resume"),
    )
    .expect("duplicate resume");
    assert!(duplicate.duplicate());
    assert_eq!(duplicate.command().revision(), resumed.command().revision());

    // Waiting-human record: reassess once, duplicate returns the same result.
    let mut waiting = after_resume.clone();
    waiting
        .revise_profile(ApprovalActor::Human, after_resume.profile())
        .expect("version bump/waiting");
    save_update(&mut store, after_resume.revision(), &waiting);
    let reassess_id = SupervisionRequestId::new(project_id);
    let reassess = SupervisionOperationRequest::new(
        reassess_id,
        sid,
        HumanOperation::Reassess,
        waiting.revision(),
    )
    .expect("reassess");
    let first = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        reassess,
    )
    .expect("reassess");
    assert_eq!(first.command().state(), SupervisionState::Verifying);
    let duplicate = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        SupervisionOperationRequest::new(
            reassess_id,
            sid,
            HumanOperation::Reassess,
            first.command().revision(),
        )
        .expect("duplicate reassess"),
    )
    .expect("duplicate reassess");
    assert!(duplicate.duplicate());
    assert_eq!(runtime.starts, 0);
}

// ---------------------------------------------------------------------------
// Resume gates
// ---------------------------------------------------------------------------

#[test]
fn unresolved_operation_process_and_checkpoint_block_resume_until_resolved() {
    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let sid = ids(project_id).supervision;
    let run = RunId::new(project_id);
    let mut record = record_with_run(&contract, run);
    record
        .stop(StopCause::RecoveryReconciliation)
        .expect("stop");
    let mut store = web.open();
    save_new(&mut store, &record);
    save_budget(&mut store, &default_budget_record(project_id));

    // Persist one unresolved H1 operation intent for this run.
    let operation = complete_operation_intent(project_id, run);
    let operation_id = operation.operation_id();
    store
        .commit(
            CheckpointCommit::new(
                Checkpoint::new(
                    run,
                    CheckpointFormatVersion::new(1).expect("version"),
                    CheckpointPayload::new(b"fixture".to_vec()),
                ),
                Some(OperationIntent::new(operation, now())),
                Vec::new(),
            )
            .expect("commit"),
        )
        .expect("operation intent");

    let clock = FixedClock::fixture();
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Paused, RecoveryMode::Restored);
    runtime.checkpoints.insert(run, RecoveryCheckpoint::Missing);
    runtime
        .managed
        .insert(run, vec![ManagedProcessState::new("shell-1", true, false)]);

    let mut budget_store = web.open();
    let report = report_for(
        &mut store,
        &mut budget_store,
        &mut runtime,
        &clock,
        &contract,
        1,
    );
    assert_eq!(report.disposition(), RecoveryDisposition::WaitingHuman);
    assert!(!report.resumable());
    assert!(
        report
            .block_reasons()
            .iter()
            .any(|reason| matches!(reason, RecoveryBlockReason::UnresolvedOperation { .. }))
    );
    assert!(
        report
            .block_reasons()
            .iter()
            .any(|reason| matches!(reason, RecoveryBlockReason::ManagedProcess { .. }))
    );
    assert!(
        report
            .block_reasons()
            .iter()
            .any(|reason| matches!(reason, RecoveryBlockReason::CheckpointMissing { .. }))
    );
    runtime.assert_zero_external_work();

    let mut budget = BudgetLedger::open(
        web.open(),
        project_id,
        sid,
        contract.budget().clone(),
        1,
        clock,
    )
    .expect("ledger");
    let blocked = SupervisionOperationRequest::new(
        SupervisionRequestId::new(project_id),
        sid,
        HumanOperation::Resume,
        record.revision(),
    )
    .expect("resume");
    let error = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        blocked,
    )
    .expect_err("blocked");
    assert!(matches!(
        error,
        herness_supervision::error::SupervisionError::NotResumable { .. }
    ));
    assert_eq!(runtime.stop_calls, 0);

    // Resolve the operation, process, and checkpoint; explicit human resume
    // then proceeds and preserves consumed budget.
    let operation_record = store.operation(&operation_id).unwrap().expect("operation");
    let _ = operation_record;
    store
        .record_operation_result(
            &operation_id,
            OperationResult::new(
                OperationOutcome::Applied,
                herness_core::OperationEvidence::new(Vec::new(), false),
                now(),
            ),
        )
        .expect("resolve operation");
    runtime.managed.insert(run, Vec::new());
    runtime.checkpoints.insert(run, RecoveryCheckpoint::Present);
    runtime
        .stop_states
        .insert(run, RecoveryStopState::Confirmed);

    // Consume one run and active time in the durable ledger.
    let mut ledger = BudgetLedger::open(
        web.open(),
        project_id,
        sid,
        contract.budget().clone(),
        1,
        clock,
    )
    .expect("ledger");
    ledger
        .start_run(BudgetRequestId::new(project_id))
        .expect("consume run");
    ledger.settle_active().expect("persist active");
    drop(ledger);

    let resumed = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        SupervisionOperationRequest::new(
            SupervisionRequestId::new(project_id),
            sid,
            HumanOperation::Resume,
            record.revision(),
        )
        .expect("resume"),
    )
    .expect("resume");
    assert_eq!(resumed.command().state(), SupervisionState::Ready);
    let resumed_record = store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    assert!(resumed_record.supervisor().current_run().is_none());
    let stored = store
        .load_budget_record(project_id, sid)
        .unwrap()
        .expect("budget");
    assert_eq!(stored.record().usage().runs_started(), 1);
    assert_eq!(runtime.stop_calls, 0);
}

fn complete_operation_intent(project_id: ProjectId, run: RunId) -> FrozenOperation {
    FrozenOperation::new(
        OperationId::new(project_id),
        run,
        ToolName::Write,
        ToolArguments::Write(WriteArgs {
            path: NonEmptyText::new("notes.txt").expect("path"),
            content: "recovery fixture".to_owned(),
            rationale: Rationale::new("recovery fixture").expect("rationale"),
        }),
        AbsolutePath::new("/tmp/herness-recovery-fixture").expect("cwd"),
        PolicyVersion::new(7).expect("policy"),
        PermissionMode::Configured,
    )
    .expect("frozen operation")
}

#[test]
fn changed_permission_context_blocks_resume_until_reconciled() {
    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let sid = ids(project_id).supervision;
    let run = RunId::new(project_id);
    let mut record = record_with_run(&contract, run);
    record.stop(StopCause::UserRequest).expect("stop");
    let mut store = web.open();
    save_new(&mut store, &record);
    save_budget(&mut store, &default_budget_record(project_id));
    let clock = FixedClock::fixture();
    let mut budget = BudgetLedger::open(
        web.open(),
        project_id,
        sid,
        contract.budget().clone(),
        1,
        clock,
    )
    .expect("ledger");
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Paused, RecoveryMode::Restored);
    runtime.permissions_current = false;

    let error = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        SupervisionOperationRequest::new(
            SupervisionRequestId::new(project_id),
            sid,
            HumanOperation::Resume,
            record.revision(),
        )
        .expect("resume"),
    )
    .expect_err("permission block");
    assert!(matches!(
        error,
        herness_supervision::error::SupervisionError::NotResumable { reasons }
            if reasons.iter().any(|reason| matches!(
                reason,
                RecoveryBlockReason::PermissionsChanged
            ))
    ));
    assert_eq!(runtime.stop_calls, 0);

    runtime.permissions_current = true;
    let resumed = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        SupervisionOperationRequest::new(
            SupervisionRequestId::new(project_id),
            sid,
            HumanOperation::Resume,
            record.revision(),
        )
        .expect("resume"),
    )
    .expect("resume");
    assert_eq!(resumed.command().state(), SupervisionState::Ready);
}

// ---------------------------------------------------------------------------
// Version changes, stale results, and completion freshness
// ---------------------------------------------------------------------------

#[test]
fn stale_condition_profile_consent_and_limit_require_human_and_invalidate_decisions() {
    let web = Harness::new();
    let project_id = project();
    let original = contract(project_id);
    let sid = ids(project_id).supervision;
    let run = RunId::new(project_id);
    let mut record = record_with_run(&original, run);

    let request = assessment_request(
        project_id,
        ids(project_id).condition_a,
        &completion_profile(project_id),
        vec![ids(project_id).evidence_a],
    );
    let result = assessment_result(
        &request,
        herness_supervision::assessment::ConditionVerdict::Met,
        vec![ids(project_id).evidence_a],
    );
    record
        .apply_assessment(&result, ProfileThresholds::normal_llm())
        .expect("apply decision");
    assert_eq!(record.applied_decisions().len(), 1);
    record
        .stop(StopCause::UserRequest)
        .expect("stop record before stale versions");

    let mut store = web.open();
    save_new(&mut store, &record);
    let changed_conditions = approved_condition_set_at(project_id, 2);
    let changed_profile = profile_at(project_id, 2);
    let changed_consent = consent_for_origin(
        project_id,
        herness_supervision::profiles::ProfilePurpose::Completion,
        1,
        other_origin(),
    );
    let changed_budget = BudgetPolicy::new(3_600, 20, None).expect("policy");
    let changed = contract_with_versions(
        project_id,
        2,
        changed_profile,
        changed_consent,
        changed_budget.clone(),
    );
    let changed_budget_record =
        herness_supervision::budget::ledger::BudgetLedgerRecord::new(changed_budget, 2)
            .expect("changed budget record");
    save_budget(&mut store, &changed_budget_record);

    // A terminal observation that does not belong to an evaluating record is
    // history only and is never applied.
    let intent = request_intent(project_id, run, "completion-assessment");
    record_request(&mut store, &intent, Some(RequestOutcome::Completed));

    let clock = FixedClock::fixture();
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Idle, RecoveryMode::Restored);
    let mut budget_store = web.open();
    let report = report_for(
        &mut store,
        &mut budget_store,
        &mut runtime,
        &clock,
        &changed,
        2,
    );
    assert_eq!(report.disposition(), RecoveryDisposition::WaitingHuman);
    assert!(!report.version_mismatches().is_empty());
    assert_eq!(report.history_only_requests().len(), 1);
    assert_eq!(
        report.history_only_requests()[0].reason(),
        HistoryOnlyReason::DelayedAfterStateChange
    );
    assert!(
        report
            .required_actions()
            .contains(&HumanAction::ConfirmConditions)
    );
    assert!(
        report
            .required_actions()
            .contains(&HumanAction::ConfirmAssessmentProfile)
    );
    assert_eq!(
        report.side_effects(),
        herness_supervision::recovery::RecoverySideEffects::zero()
    );

    let mut notifications = Notifications::default();
    let mut service = RecoveryService::new(&mut store, &mut runtime, &mut budget_store, &clock);
    let reconciliation = service
        .reconcile(&changed, 2, &mut notifications)
        .expect("reconcile");
    assert!(reconciliation.committed());
    let next = store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    assert_eq!(next.state(), SupervisionState::WaitingHuman);
    assert_eq!(next.applied_decisions().len(), 0);
    assert_eq!(next.invalidated_decisions().len(), 1);
    assert_eq!(
        next.invalidated_decisions()[0].invalidation(),
        DecisionInvalidation::ConditionsChanged {
            to: ConditionVersion::new(2).expect("version")
        }
    );
    assert_eq!(notifications.count(), 0);
    runtime.assert_zero_external_work();
    let _ = changed_conditions;
}

#[test]
fn unknown_money_reservation_stays_unresolved_and_counting() {
    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let sid = ids(project_id).supervision;
    let run = RunId::new(project_id);
    let record = record_with_run(&contract, run);
    let mut store = web.open();
    save_new(&mut store, &record);

    let clock = FixedClock::fixture();
    let policy = BudgetPolicy::new(
        60,
        5,
        Some(
            MoneyCap::new(
                Money::usd(10.0).expect("money"),
                PriceVersion::new("fixture-1").expect("price"),
            )
            .expect("cap"),
        ),
    )
    .expect("policy");
    let mut ledger =
        BudgetLedger::open(web.open(), project_id, sid, policy, 1, clock).expect("ledger");
    ledger.begin_active().expect("active");
    let intent = request_intent(project_id, run, "permission-evaluation");
    let estimate = RequestBudgetEstimate::new(
        Money::usd(1.0).expect("estimate"),
        PriceVersion::new("fixture-1").expect("price"),
        AuthMethod::ApiKey,
    );
    ledger
        .admit_request(&intent, Some(&estimate))
        .expect("admit");
    ledger
        .settle_money(intent.attempt_id(), MoneySettlement::Unresolved)
        .expect("unresolved");
    let reserved = ledger
        .record()
        .money_reservations()
        .values()
        .next()
        .expect("reservation")
        .estimate();
    drop(ledger);

    let mut budget_store = web.open();
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Idle, RecoveryMode::Restored);
    let report = report_for(
        &mut store,
        &mut budget_store,
        &mut runtime,
        &clock,
        &contract,
        1,
    );
    assert_eq!(report.budget().unresolved_charges(), 1);
    assert_eq!(
        report
            .block_reasons()
            .iter()
            .filter(|reason| matches!(reason, RecoveryBlockReason::UnresolvedBudgetCharge { .. }))
            .count(),
        1
    );
    assert!(report.budget().usage().money_reserved().micros() >= reserved.micros());
    assert!(!report.resumable());
    assert!(
        report
            .unresolved_requests()
            .iter()
            .any(|item| item.kind() == UnresolvedRequestKind::IntentOnly)
    );
    runtime.assert_zero_external_work();
}

#[test]
fn completed_stale_notifies_once_and_creates_no_new_run() {
    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let sid = ids(project_id).supervision;
    let run = RunId::new(project_id);
    let mut record = record_with_run(&contract, run);
    for condition in [ids(project_id).condition_a, ids(project_id).condition_b] {
        let request = assessment_request(
            project_id,
            condition,
            &completion_profile(project_id),
            vec![ids(project_id).evidence_a],
        );
        let result = assessment_result(
            &request,
            herness_supervision::assessment::ConditionVerdict::Met,
            vec![ids(project_id).evidence_a],
        );
        record
            .apply_assessment(&result, ProfileThresholds::normal_llm())
            .expect("apply");
    }
    record
        .complete(completion_snapshot(&contract))
        .expect("complete");
    record
        .mark_completion_stale(
            StaleCompletion::new(
                TargetVersion::new(1).expect("version"),
                TargetVersion::new(2).expect("version"),
                vec!["src/lib.rs".to_owned()],
                vec![ids(project_id).evidence_a],
                now(),
            )
            .expect("stale"),
        )
        .expect("mark stale");

    let mut store = web.open();
    save_new(&mut store, &record);
    save_budget(&mut store, &default_budget_record(project_id));
    let clock = FixedClock::fixture();
    let mut budget_store = web.open();
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Idle, RecoveryMode::Restored);
    let mut notifications = Notifications::default();

    let mut service = RecoveryService::new(&mut store, &mut runtime, &mut budget_store, &clock);
    let first = service
        .reconcile(&contract, 1, &mut notifications)
        .expect("first reconcile");
    assert_eq!(
        first.report().disposition(),
        RecoveryDisposition::CompletedStale
    );
    assert!(first.report().stale_completion());
    assert!(first.report().notified());
    assert_eq!(notifications.count(), 1);
    assert_eq!(runtime.starts, 0);
    assert_eq!(runtime.stop_calls, 0);

    let mut second_service =
        RecoveryService::new(&mut store, &mut runtime, &mut budget_store, &clock);
    let second = second_service
        .reconcile(&contract, 1, &mut notifications)
        .expect("second reconcile");
    assert!(!second.report().notified());
    assert_eq!(notifications.count(), 1);
    let stored = store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state(), SupervisionState::Completed);
    assert!(stored.completion_stale().is_some());
    runtime.assert_zero_external_work();
}

// ---------------------------------------------------------------------------
// Quit hook
// ---------------------------------------------------------------------------

#[test]
fn quit_hook_marks_active_records_without_claiming_unconfirmed_stops() {
    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let sid = ids(project_id).supervision;
    let run = RunId::new(project_id);
    let record = record_with_run(&contract, run);
    let mut store = web.open();
    save_new(&mut store, &record);
    let clock = FixedClock::fixture();

    let mut facts = BTreeMap::new();
    facts.insert(run, true);
    let report = mark_active_supervision_for_quit(&mut store, &clock, vec![record.clone()], &facts)
        .expect("quit mark");
    assert_eq!(report.failed(), 0);
    assert!(report.marks()[0].changed());
    assert_eq!(report.marks()[0].state(), SupervisionState::Stopped);
    let stopped = store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    assert_eq!(
        stopped.reason(),
        &herness_supervision::state::SupervisionReason::Stopped {
            cause: StopCause::RecoveryReconciliation
        }
    );

    // Reopening and recovering does not auto-run.
    let mut budget_store = web.open();
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Paused, RecoveryMode::Restored);
    let recovery = report_for(
        &mut store,
        &mut budget_store,
        &mut runtime,
        &clock,
        &contract,
        1,
    );
    assert_eq!(recovery.state(), SupervisionState::Stopped);
    runtime.assert_zero_external_work();

    // A repeated quit mark is idempotent and reports no change.
    let repeat = mark_active_supervision_for_quit(&mut store, &clock, vec![record], &facts)
        .expect("repeat quit mark");
    assert!(!repeat.marks()[0].changed());
    assert_eq!(repeat.failed(), 0);

    // Unconfirmed stop fact records stopped(stopUnconfirmed) and blocks resume.
    let other_web = Harness::new();
    let other_run = RunId::new(project_id);
    let other = record_with_run(&contract, other_run);
    let mut other_store = other_web.open();
    save_new(&mut other_store, &other);
    let mut unconfirmed = BTreeMap::new();
    unconfirmed.insert(other_run, false);
    mark_active_supervision_for_quit(&mut other_store, &clock, vec![other.clone()], &unconfirmed)
        .expect("unconfirmed quit mark");
    let unconfirmed_record = other_store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    assert_eq!(
        unconfirmed_record.reason(),
        &herness_supervision::state::SupervisionReason::Stopped {
            cause: StopCause::StopUnconfirmed
        }
    );
    let mut other_budget = other_web.open();
    let mut other_runtime = FakeRuntime::new();
    other_runtime.set_run(other_run, RunState::Interrupted, RecoveryMode::Restored);
    other_runtime
        .stop_states
        .insert(other_run, RecoveryStopState::Unconfirmed);
    let blocked = report_for(
        &mut other_store,
        &mut other_budget,
        &mut other_runtime,
        &clock,
        &contract,
        1,
    );
    assert!(!blocked.resumable());
    assert!(
        blocked
            .block_reasons()
            .iter()
            .any(|reason| matches!(reason, RecoveryBlockReason::StopUnconfirmed { .. }))
    );
    other_runtime.assert_zero_external_work();
}

// ---------------------------------------------------------------------------
// Explicit version/limit change
// ---------------------------------------------------------------------------

#[test]
fn explicit_condition_and_limit_change_records_before_after_without_resetting_budget() {
    let web = Harness::new();
    let project_id = project();
    let contract = contract(project_id);
    let sid = ids(project_id).supervision;
    let run = RunId::new(project_id);
    let mut record = record_with_run(&contract, run);
    let request = assessment_request(
        project_id,
        ids(project_id).condition_a,
        &completion_profile(project_id),
        vec![ids(project_id).evidence_a],
    );
    let result = assessment_result(
        &request,
        herness_supervision::assessment::ConditionVerdict::Met,
        vec![ids(project_id).evidence_a],
    );
    record
        .apply_assessment(&result, ProfileThresholds::normal_llm())
        .expect("apply");
    record.stop(StopCause::UserRequest).expect("stop");
    let mut store = web.open();
    save_new(&mut store, &record);
    let clock = FixedClock::fixture();
    let mut budget = BudgetLedger::open(
        web.open(),
        project_id,
        sid,
        contract.budget().clone(),
        1,
        clock,
    )
    .expect("ledger");
    budget
        .start_run(BudgetRequestId::new(project_id))
        .expect("consume a run");
    budget.settle_active().expect("persist");
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Paused, RecoveryMode::Restored);

    let changed_conditions = approved_condition_set_at(project_id, 2);
    let change = SupervisionOperationRequest::new(
        SupervisionRequestId::new(project_id),
        sid,
        HumanOperation::Change(SupervisionChange::Conditions(changed_conditions)),
        record.revision(),
    )
    .expect("change");
    let result = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        change,
    )
    .expect("change conditions");
    assert_eq!(result.command().state(), SupervisionState::WaitingHuman);
    let changed = store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    assert_eq!(changed.condition_version().get(), 2);
    assert_eq!(changed.applied_decisions().len(), 0);
    assert_eq!(changed.invalidated_decisions().len(), 1);
    assert_eq!(changed.change_log().len(), 1);
    assert_eq!(changed.change_log()[0].kind(), ChangeKind::Conditions);
    assert!(changed.change_log()[0].budget_after().runs_started() >= 1);

    let newer_policy = BudgetPolicy::new(3_600, 10, None).expect("policy");
    let limit_change = SupervisionOperationRequest::new(
        SupervisionRequestId::new(project_id),
        sid,
        HumanOperation::Change(SupervisionChange::Budget {
            policy: newer_policy,
            policy_version: 2,
        }),
        changed.revision(),
    )
    .expect("limit change");
    let result = execute_operation(
        operation_ports(&mut store, &mut runtime, &mut budget, &clock),
        &contract,
        1,
        limit_change,
    )
    .expect("change limit");
    assert_eq!(result.command().state(), SupervisionState::WaitingHuman);
    let after_limit = store
        .load_supervision_record(project_id, sid)
        .unwrap()
        .unwrap();
    assert_eq!(after_limit.change_log().len(), 2);
    assert_eq!(after_limit.change_log()[1].kind(), ChangeKind::Budget);
    assert_eq!(after_limit.change_log()[1].budget_after().runs_started(), 1);
    let stored = store
        .load_budget_record(project_id, sid)
        .unwrap()
        .expect("budget");
    assert_eq!(stored.record().policy_version(), 2);
    assert_eq!(stored.record().usage().runs_started(), 1);
    runtime.assert_zero_external_work();
}

// ---------------------------------------------------------------------------
// Approved-owner generation replacement and its latches
// ---------------------------------------------------------------------------

struct OwnerHarness {
    _web: Harness,
    project_id: ProjectId,
    supervision: SupervisionId,
    current: SupervisionContract,
    store: Store,
    budget: BudgetLedger<Store, FixedClock>,
    clock: FixedClock,
}

impl OwnerHarness {
    fn new(prepare: impl FnOnce(&mut SupervisionRecord)) -> Self {
        let web = Harness::new();
        let project_id = project();
        let owner =
            OwnerRef::new(OwnerKind::H3HtmlJob, "generation-job").expect("owner reference");
        let current = owner_contract_at(
            project_id,
            owner,
            OwnerApprovalSource::H3ApprovedSettings,
            1,
            1,
        );
        let mut record = SupervisionRecord::new(&current);
        prepare(&mut record);
        let supervision = record.supervision_id();
        let mut store = web.open();
        save_new(&mut store, &record);
        save_budget(&mut store, &default_budget_record(project_id));
        let clock = FixedClock::fixture();
        let budget = BudgetLedger::open(
            web.open(),
            project_id,
            supervision,
            current.budget().clone(),
            1,
            clock,
        )
        .expect("owner budget ledger");
        Self {
            _web: web,
            project_id,
            supervision,
            current,
            store,
            budget,
            clock,
        }
    }

    fn record(&self) -> SupervisionRecord {
        self.store
            .load_supervision_record(self.project_id, self.supervision)
            .expect("load record")
            .expect("record")
    }

    fn replacement(&self, target_version: u64) -> SupervisionContract {
        owner_contract_succeeding(
            &self.current,
            target_version,
            1,
            self.current.budget().clone(),
        )
    }

    fn authority(&self, contract: &SupervisionContract) -> HostOwnerAuthority {
        let binding =
            OwnerLaunchBinding::from_contract(contract, 1, 1, "generation-job").expect("binding");
        let mut registry = ScriptedOwnerApprovalRegistry::new();
        registry.insert(binding.approval().clone());
        authorize_owner_launch(&registry, &binding, self.clock.now()).expect("authority")
    }

    fn request(
        &self,
        contract: &SupervisionContract,
        expected_revision: u64,
    ) -> OwnerSupersessionRequest {
        OwnerSupersessionRequest::new(
            SupervisionRequestId::new(self.project_id),
            self.supervision,
            expected_revision,
            contract.clone(),
        )
        .expect("supersession request")
    }

    fn execute(
        &mut self,
        runtime: &mut FakeRuntime,
        current: &SupervisionContract,
        contract: &SupervisionContract,
        expected_revision: u64,
    ) -> Result<OwnerOperationResult, herness_supervision::SupervisionError> {
        let request = self.request(contract, expected_revision);
        let authority = self.authority(contract);
        execute_owner_supersession(
            OperationPorts {
                store: &mut self.store,
                runtime,
                budget: &mut self.budget,
                clock: &self.clock,
            },
            current,
            1,
            request,
            authority,
        )
    }
}

#[test]
#[allow(clippy::type_complexity)]
fn owner_supersession_refuses_every_human_stop_wait_stagnation_limit_recovery_cancel_and_failure_latch()
{
    let cases: Vec<(
        &str,
        Box<dyn FnOnce(&mut SupervisionRecord)>,
        OwnerSupersessionRejection,
    )> = vec![
        (
            "human stop",
            Box::new(|record| record.stop(StopCause::UserRequest).expect("stop")),
            OwnerSupersessionRejection::HumanStopped,
        ),
        (
            "waiting human",
            Box::new(|record| {
                record
                    .wait_for_human(HumanAction::ReconcileRecovery)
                    .expect("wait")
            }),
            OwnerSupersessionRejection::HumanWaiting {
                action: HumanAction::ReconcileRecovery,
            },
        ),
        (
            "stagnation",
            Box::new(|record| record.stop(StopCause::Stagnation).expect("stop")),
            OwnerSupersessionRejection::Stagnated,
        ),
        (
            "run limit",
            Box::new(|record| {
                record
                    .stop(StopCause::Budget(BudgetLimit::RunCount))
                    .expect("stop")
            }),
            OwnerSupersessionRejection::BudgetExhausted {
                limit: BudgetLimit::RunCount,
            },
        ),
        (
            "active-time limit",
            Box::new(|record| {
                record
                    .stop(StopCause::Budget(BudgetLimit::ActiveSeconds))
                    .expect("stop")
            }),
            OwnerSupersessionRejection::BudgetExhausted {
                limit: BudgetLimit::ActiveSeconds,
            },
        ),
        (
            "recovery pending",
            Box::new(|record| {
                record
                    .stop(StopCause::RecoveryReconciliation)
                    .expect("stop")
            }),
            OwnerSupersessionRejection::RecoveryPending,
        ),
        (
            "cancelled",
            Box::new(|record| record.cancel(CancelCause::UserRequest).expect("cancel")),
            OwnerSupersessionRejection::Cancelled,
        ),
        (
            "failed",
            Box::new(|record| {
                record
                    .fail(SupervisionFailure::VerificationUnavailable)
                    .expect("fail")
            }),
            OwnerSupersessionRejection::Failed,
        ),
        (
            "completed",
            Box::new(|record| {
                record
                    .set_state(
                        SupervisionState::Completed,
                        SupervisionReason::Completed {
                            snapshot: completion_snapshot(&contract(project())),
                        },
                    )
                    .expect("complete")
            }),
            OwnerSupersessionRejection::Completed,
        ),
    ];

    for (name, prepare, expected) in cases {
        let mut harness = OwnerHarness::new(prepare);
        let current = harness.current.clone();
        let replacement = harness.replacement(2);
        let before = harness.record();
        let before_usage = harness.budget.record().usage();
        let mut runtime = FakeRuntime::new();
        let result = harness.execute(&mut runtime, &current, &replacement, before.revision());
        assert_eq!(
            result.expect_err(name),
            herness_supervision::SupervisionError::OwnerSupersessionRejected {
                reason: expected
            },
            "{name}"
        );
        let after = harness.record();
        assert_eq!(after.revision(), before.revision(), "{name}");
        assert_eq!(after.state(), before.state(), "{name}");
        assert_eq!(after.target_version(), before.target_version(), "{name}");
        assert_eq!(after.change_log().len(), 0, "{name}");
        assert_eq!(harness.budget.record().usage(), before_usage, "{name}");
        assert_eq!(runtime.stop_calls, 0, "{name}: no stop may be attempted");
    }
}

#[test]
fn owner_supersession_refuses_a_running_record_with_unresolved_recovery_facts() {
    let project_id = project();
    let run = RunId::new(project_id);
    let mut harness = OwnerHarness::new(|record| {
        record.begin_run(run).expect("begin run");
    });
    let intent = request_intent(project_id, run, "completion-assessment");
    record_request(&mut harness.store, &intent, None);
    let current = harness.current.clone();
    let replacement = harness.replacement(2);
    let before = harness.record();
    let before_usage = harness.budget.record().usage();
    let mut runtime = FakeRuntime::new();
    runtime.set_run(run, RunState::Idle, RecoveryMode::SameProcess);

    let result = harness.execute(&mut runtime, &current, &replacement, before.revision());
    assert_eq!(
        result.expect_err("unresolved request"),
        herness_supervision::SupervisionError::OwnerSupersessionRejected {
            reason: OwnerSupersessionRejection::RecoveryPending
        }
    );
    let after = harness.record();
    assert_eq!(after.revision(), before.revision());
    assert_eq!(after.target_version(), before.target_version());
    assert_eq!(after.change_log().len(), 0);
    assert_eq!(harness.budget.record().usage(), before_usage);
    assert_eq!(runtime.stop_calls, 0);
}

#[test]
fn owner_supersession_refuses_an_unconfirmed_stop_before_any_state_change() {
    let project_id = project();
    let run = RunId::new(project_id);
    let mut harness = OwnerHarness::new(|record| {
        record.begin_run(run).expect("begin run");
    });
    let current = harness.current.clone();
    let replacement = harness.replacement(2);
    let before = harness.record();
    let before_usage = harness.budget.record().usage();
    let mut runtime = FakeRuntime::new();
    runtime.stop_result = StopDisposition::Unconfirmed;

    let result = harness.execute(&mut runtime, &current, &replacement, before.revision());
    assert_eq!(
        result.expect_err("unconfirmed stop"),
        herness_supervision::SupervisionError::OwnerSupersessionRejected {
            reason: OwnerSupersessionRejection::StopUnconfirmed
        }
    );
    assert_eq!(runtime.stop_calls, 1);
    let after = harness.record();
    assert_eq!(after.revision(), before.revision());
    assert_eq!(after.state(), before.state());
    assert_eq!(after.target_version(), before.target_version());
    assert_eq!(after.change_log().len(), 0);
    assert_eq!(harness.budget.record().usage(), before_usage);
}

#[test]
fn duplicate_and_crashed_owner_supersession_do_not_double_supersede() {
    let project_id = project();
    let run = RunId::new(project_id);
    let mut harness = OwnerHarness::new(|record| {
        record.begin_run(run).expect("begin run");
    });
    let current = harness.current.clone();
    let replacement = harness.replacement(2);
    let before = harness.record();
    let before_usage = harness.budget.record().usage();
    let mut runtime = FakeRuntime::new();

    let request_id = SupervisionRequestId::new(project_id);
    let authority = harness.authority(&replacement);
    let first = execute_owner_supersession(
        OperationPorts {
            store: &mut harness.store,
            runtime: &mut runtime,
            budget: &mut harness.budget,
            clock: &harness.clock,
        },
        &current,
        1,
        OwnerSupersessionRequest::new(
            request_id,
            harness.supervision,
            before.revision(),
            replacement.clone(),
        )
        .expect("first request"),
        authority,
    )
    .expect("first supersession");
    assert!(!first.duplicate());
    assert_eq!(runtime.stop_calls, 1);
    assert_eq!(harness.budget.record().usage(), before_usage);

    let after_first = harness.record();
    assert_eq!(after_first.target_version().get(), 2);
    assert_eq!(after_first.change_log().len(), 1);
    assert_eq!(
        after_first.revision(),
        before.revision().saturating_add(1)
    );

    // A duplicate id returns the recorded result and performs no load, stop,
    // budget mutation, or second state change.
    let duplicate_authority = harness.authority(&replacement);
    let duplicate = execute_owner_supersession(
        OperationPorts {
            store: &mut harness.store,
            runtime: &mut runtime,
            budget: &mut harness.budget,
            clock: &harness.clock,
        },
        &replacement,
        1,
        OwnerSupersessionRequest::new(
            request_id,
            harness.supervision,
            after_first.revision(),
            replacement.clone(),
        )
        .expect("duplicate request"),
        duplicate_authority,
    )
    .expect("duplicate request");
    assert!(duplicate.duplicate());
    let after_duplicate = harness.record();
    assert_eq!(after_duplicate.revision(), after_first.revision());
    assert_eq!(after_duplicate.change_log().len(), 1);
    assert_eq!(runtime.stop_calls, 1);

    // A new request whose atomic commit fails leaves no result. Retrying the
    // same id succeeds exactly once.
    let replacement_three = owner_contract_succeeding(
        &replacement,
        3,
        1,
        replacement.budget().clone(),
    );
    let request_three_id = SupervisionRequestId::new(project_id);
    let request_three = OwnerSupersessionRequest::new(
        request_three_id,
        harness.supervision,
        after_first.revision(),
        replacement_three.clone(),
    )
    .expect("third request");
    let authority_three = harness.authority(&replacement_three);
    harness
        .store
        .set_commit_fault(Some(CommitFault::BeforeCommit));
    let failed = execute_owner_supersession(
        OperationPorts {
            store: &mut harness.store,
            runtime: &mut runtime,
            budget: &mut harness.budget,
            clock: &harness.clock,
        },
        &replacement,
        1,
        request_three,
        authority_three,
    );
    assert!(failed.is_err(), "the injected commit fault must surface");
    harness.store.set_commit_fault(None);
    assert!(harness
        .store
        .command_result(request_three_id)
        .expect("command lookup")
        .is_none());
    let after_crash = harness.record();
    assert_eq!(after_crash.revision(), after_first.revision());
    assert_eq!(after_crash.target_version().get(), 2);
    assert_eq!(after_crash.change_log().len(), 1);
    assert_eq!(runtime.stop_calls, 1);

    let retry_authority = harness.authority(&replacement_three);
    let retried = execute_owner_supersession(
        OperationPorts {
            store: &mut harness.store,
            runtime: &mut runtime,
            budget: &mut harness.budget,
            clock: &harness.clock,
        },
        &replacement,
        1,
        OwnerSupersessionRequest::new(
            request_three_id,
            harness.supervision,
            after_first.revision(),
            replacement_three,
        )
        .expect("retry request"),
        retry_authority,
    )
    .expect("retry");
    assert!(!retried.duplicate());
    let after_retry = harness.record();
    assert_eq!(after_retry.revision(), after_first.revision().saturating_add(1));
    assert_eq!(after_retry.target_version().get(), 3);
    assert_eq!(after_retry.change_log().len(), 2);
    assert_eq!(runtime.stop_calls, 1);
}
