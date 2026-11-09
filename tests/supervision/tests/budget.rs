//! H2 durable budget ledger tests.
//!
//! Every clock, store, request, and provider value is synthetic. No real
//! provider, credential, database beyond a temporary SQLite file, or shell is
//! used.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use herness_core::contracts::{
    AgentId, AttemptId, AuthMethod, ConnectionId, EventSubject, ModelRequestObservation, ProjectId,
    ProviderFailureKind, RequestGateIntent, RequestGateOutcome, RequestGateRefusal, RequestId,
    RequestOutcome, RequestPurpose, RunId, RunSubject, SessionId, StopDeadlineControl, Timestamp,
    TokenCount, TokenUsage,
};
use herness_core::ports::request_gate::ModelRequestGatePort;
use herness_core::runtime::RecoveryMode;
use herness_core::RunState;
use herness_store::test_support::CommitFault;
use herness_store::{Store, StoreConfig};
use herness_supervision::operations::{
    OperationPorts, OperationRuntimePort, OwnerSupersessionRequest, execute_owner_supersession,
};
use herness_supervision::owner_launch::{OwnerLaunchBinding, authorize_owner_launch};
use herness_supervision::recovery::{
    ManagedProcessState, RecoveryCheckpoint, RecoveryRuntimePort, RecoveryStopState,
};
use herness_supervision::supervisor::StopDisposition;
use herness_supervision::{
    BudgetClockPort, BudgetLedger, BudgetLedgerRecord, BudgetLimit, BudgetPolicy,
    BudgetRequestGate, BudgetRequestId, BudgetStorePort, ChangeKind, ClockPort, ClockReading, Money,
    MoneyCap, MoneyReservation, MoneyReservationState, MoneySettlement, OwnerApprovalSource,
    OwnerKind, OwnerRef, OwnerSupersessionRejection, PriceVersion, RequestBudgetEstimate,
    RequestBudgetEstimator, StoredBudgetRecord, SupervisionError, SupervisionId, SupervisionRecord,
    SupervisionRequestId, SupervisionState,
};
use herness_supervision_tests::{
    ScriptedOwnerApprovalRegistry, ids, now, owner_contract_at_with_budget,
    owner_contract_succeeding, project,
};
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fake clocks and synthetic store
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct ClockState {
    wall_millis: u64,
    monotonic_millis: u64,
}

#[derive(Debug, Clone)]
struct FakeClock(Rc<RefCell<ClockState>>);

impl FakeClock {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(ClockState {
            wall_millis: now().as_unix_millis(),
            monotonic_millis: 0,
        })))
    }

    fn advance_seconds(&self, seconds: u64) {
        let millis = seconds.saturating_mul(1_000);
        let mut state = self.0.borrow_mut();
        state.wall_millis = state.wall_millis.saturating_add(millis);
        state.monotonic_millis = state.monotonic_millis.saturating_add(millis);
    }

    fn advance_wall_only(&self, seconds: u64) {
        let mut state = self.0.borrow_mut();
        state.wall_millis = state
            .wall_millis
            .saturating_add(seconds.saturating_mul(1_000));
    }

    fn reset_monotonic(&self) {
        self.0.borrow_mut().monotonic_millis = 0;
    }
}

impl BudgetClockPort for FakeClock {
    fn read(&self) -> ClockReading {
        let state = self.0.borrow();
        ClockReading::new(
            Timestamp::from_unix_millis(state.wall_millis),
            state.monotonic_millis,
        )
    }
}

impl ClockPort for FakeClock {
    fn now(&self) -> Timestamp {
        self.read().wall()
    }
}

type BeforeCommit = Box<dyn FnOnce(&mut StoreState)>;

#[derive(Default)]
struct StoreState {
    records: BTreeMap<SupervisionId, StoredBudgetRecord>,
    intents: BTreeMap<AttemptId, RequestGateIntent>,
    observations: BTreeMap<AttemptId, ModelRequestObservation>,
    admission_commits: u32,
    observation_commits: u32,
    cas_commits: u32,
    fail_cas: bool,
    fail_admission: bool,
    fail_observation: bool,
    before_cas: Option<BeforeCommit>,
}

#[derive(Clone, Default)]
struct SharedStore(Rc<RefCell<StoreState>>);

impl SharedStore {
    fn state(&self) -> std::cell::RefMut<'_, StoreState> {
        self.0.borrow_mut()
    }
}

fn revision_conflict(expected: Option<u64>, found: Option<u64>) -> SupervisionError {
    match (expected, found) {
        (Some(expected), Some(found)) => SupervisionError::RevisionConflict { expected, found },
        (None, Some(found)) => SupervisionError::RevisionConflict { expected: 0, found },
        (Some(_expected), None) => SupervisionError::UnknownSupervision,
        (None, None) => SupervisionError::RevisionConflict {
            expected: 0,
            found: 0,
        },
    }
}

fn check_expected(expected: Option<u64>, found: Option<u64>) -> Result<u64, SupervisionError> {
    let matches = match (expected, found) {
        (None, None) => true,
        (Some(expected), Some(found)) => expected == found,
        _ => false,
    };
    if !matches {
        return Err(revision_conflict(expected, found));
    }
    found
        .map(|revision| revision + 1)
        .or(Some(1))
        .ok_or_else(|| SupervisionError::StorageFailure {
            detail: "synthetic revision overflow".to_owned(),
        })
}

impl BudgetStorePort for SharedStore {
    fn load_budget(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Option<StoredBudgetRecord>, SupervisionError> {
        supervision_id.validate_in(project_id)?;
        Ok(self.0.borrow().records.get(&supervision_id).cloned())
    }

    fn compare_and_swap_budget(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &BudgetLedgerRecord,
    ) -> Result<u64, SupervisionError> {
        supervision_id.validate_in(project_id)?;
        next.validate()?;
        let mut state = self.0.borrow_mut();
        if let Some(hook) = state.before_cas.take() {
            hook(&mut state);
        }
        if state.fail_cas {
            return Err(SupervisionError::StorageFailure {
                detail: "injected budget store failure".to_owned(),
            });
        }
        let found = state
            .records
            .get(&supervision_id)
            .map(StoredBudgetRecord::revision);
        let revision = check_expected(expected_revision, found)?;
        state.records.insert(
            supervision_id,
            StoredBudgetRecord::new(revision, next.clone())?,
        );
        state.cas_commits += 1;
        Ok(revision)
    }

    fn commit_budget_admission(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &BudgetLedgerRecord,
        intent: &RequestGateIntent,
        _recorded_at: Timestamp,
    ) -> Result<u64, SupervisionError> {
        supervision_id.validate_in(project_id)?;
        if intent.subject().project_id() != project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "request subject".to_owned(),
                expected: project_id,
                found: intent.subject().project_id(),
            });
        }
        next.validate()?;
        let mut state = self.0.borrow_mut();
        if state.fail_admission {
            return Err(SupervisionError::StorageFailure {
                detail: "injected admission store failure".to_owned(),
            });
        }
        if let Some(existing) = state.intents.get(&intent.attempt_id())
            && existing != intent
        {
            return Err(SupervisionError::BudgetReservationConflict {
                attempt: intent.attempt_id().to_string(),
            });
        }
        let found = state
            .records
            .get(&supervision_id)
            .map(StoredBudgetRecord::revision);
        let revision = check_expected(expected_revision, found)?;
        state.intents.insert(intent.attempt_id(), intent.clone());
        state.records.insert(
            supervision_id,
            StoredBudgetRecord::new(revision, next.clone())?,
        );
        state.admission_commits += 1;
        Ok(revision)
    }

    fn commit_budget_observation(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &BudgetLedgerRecord,
        observation: &ModelRequestObservation,
        _observed_at: Timestamp,
    ) -> Result<u64, SupervisionError> {
        supervision_id.validate_in(project_id)?;
        if observation.request_id().project_id() != project_id
            || observation.attempt_id().project_id() != project_id
        {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "request observation".to_owned(),
                expected: project_id,
                found: observation.request_id().project_id(),
            });
        }
        next.validate()?;
        let mut state = self.0.borrow_mut();
        if state.fail_observation {
            return Err(SupervisionError::StorageFailure {
                detail: "injected observation store failure".to_owned(),
            });
        }
        if !state.intents.contains_key(&observation.attempt_id()) {
            return Err(SupervisionError::UnknownBudgetReservation {
                attempt: observation.attempt_id().to_string(),
            });
        }
        let found = state
            .records
            .get(&supervision_id)
            .map(StoredBudgetRecord::revision);
        let revision = check_expected(expected_revision, found)?;
        state
            .observations
            .insert(observation.attempt_id(), observation.clone());
        state.records.insert(
            supervision_id,
            StoredBudgetRecord::new(revision, next.clone())?,
        );
        state.observation_commits += 1;
        Ok(revision)
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn money(usd: f64) -> Money {
    Money::usd(usd).expect("fixture money")
}

fn price_version() -> PriceVersion {
    PriceVersion::new("price-v1").expect("price version")
}

fn capped_policy(limit_usd: f64) -> BudgetPolicy {
    BudgetPolicy::new(
        7_200,
        30,
        Some(MoneyCap::new(money(limit_usd), price_version()).expect("money cap")),
    )
    .expect("capped policy")
}

fn open_ledger(
    store: &SharedStore,
    policy: BudgetPolicy,
    clock: &FakeClock,
) -> BudgetLedger<SharedStore, FakeClock> {
    BudgetLedger::open(
        store.clone(),
        project(),
        ids(project()).supervision,
        policy,
        1,
        clock.clone(),
    )
    .expect("open ledger")
}

fn run_request() -> BudgetRequestId {
    BudgetRequestId::new(project())
}

fn intent_with(control: StopDeadlineControl) -> (RequestGateIntent, RequestId, AttemptId) {
    let subject = EventSubject::Run(
        RunSubject::new(
            project(),
            AgentId::new(project()),
            SessionId::new(project()),
            RunId::new(project()),
        )
        .expect("run subject"),
    );
    let request = RequestId::new(project());
    let attempt = AttemptId::new(project());
    let intent = RequestGateIntent::new(
        request,
        attempt,
        ConnectionId::new(),
        RequestPurpose::new("budget-test").expect("purpose"),
        subject,
        control,
    )
    .expect("request intent");
    (intent, request, attempt)
}

fn intent() -> (RequestGateIntent, RequestId, AttemptId) {
    intent_with(StopDeadlineControl::proceed())
}

fn known_usage(input: u64) -> TokenUsage {
    TokenUsage::new(
        TokenCount::known(input),
        TokenCount::known(input / 2),
        TokenCount::unknown(),
        TokenCount::unknown(),
    )
}

#[derive(Debug, Clone, Copy, Default)]
struct Estimator {
    estimate: Option<EstimateValues>,
    settled: Option<EstimateValues>,
    other_price_version: bool,
}

#[derive(Debug, Clone, Copy)]
struct EstimateValues {
    amount: u64,
    chatgpt: bool,
}

impl Estimator {
    fn estimated(amount_micros: u64) -> Self {
        Self {
            estimate: Some(EstimateValues {
                amount: amount_micros,
                chatgpt: false,
            }),
            settled: None,
            other_price_version: false,
        }
    }

    fn chatgpt(amount_micros: u64) -> Self {
        Self {
            estimate: Some(EstimateValues {
                amount: amount_micros,
                chatgpt: true,
            }),
            settled: None,
            other_price_version: false,
        }
    }

    fn wrong_price_version(amount_micros: u64) -> Self {
        Self {
            estimate: Some(EstimateValues {
                amount: amount_micros,
                chatgpt: false,
            }),
            settled: None,
            other_price_version: true,
        }
    }

    fn with_settled(mut self, amount_micros: u64) -> Self {
        self.settled = Some(EstimateValues {
            amount: amount_micros,
            chatgpt: false,
        });
        self
    }
}

impl RequestBudgetEstimator for Estimator {
    fn estimate(&self, _intent: &RequestGateIntent) -> Option<RequestBudgetEstimate> {
        self.estimate.map(|values| {
            RequestBudgetEstimate::new(
                Money::from_micros(values.amount),
                if self.other_price_version {
                    PriceVersion::new("other-price-v").expect("version")
                } else {
                    price_version()
                },
                if values.chatgpt {
                    AuthMethod::ChatGptLogin
                } else {
                    AuthMethod::ApiKey
                },
            )
        })
    }

    fn settled_amount(&self, _observation: &ModelRequestObservation) -> Option<Money> {
        self.settled.map(|values| Money::from_micros(values.amount))
    }
}

struct StoreHarness {
    _temp: TempDir,
    config: StoreConfig,
}

impl StoreHarness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("config");
        Self {
            _temp: temp,
            config,
        }
    }

    fn open(&self) -> Store {
        Store::open(self.config.clone()).expect("open store")
    }
}

// ---------------------------------------------------------------------------
// Active-time accounting
// ---------------------------------------------------------------------------

#[test]
fn active_time_boundaries_are_exact_at_7199_7200_and_7201() {
    for (elapsed, remaining, timeout) in [(7_199u64, 1u64, 1u64), (7_200, 0, 0), (7_201, 0, 0)] {
        let store = SharedStore::default();
        let clock = FakeClock::new();
        let mut ledger = open_ledger(&store, BudgetPolicy::h2_default(), &clock);
        ledger.begin_active().expect("activate");
        clock.advance_seconds(elapsed);
        ledger.settle_active().expect("settle");
        assert_eq!(
            ledger.record().usage().active_seconds_consumed(),
            elapsed,
            "elapsed {elapsed} must be charged exactly"
        );
        assert_eq!(
            ledger.remaining_active_seconds().expect("remaining"),
            remaining,
            "elapsed {elapsed}"
        );
        assert_eq!(
            ledger.assessment_timeout().expect("timeout"),
            timeout,
            "elapsed {elapsed}"
        );
    }

    let store = SharedStore::default();
    let clock = FakeClock::new();
    let mut ledger = open_ledger(&store, BudgetPolicy::h2_default(), &clock);
    ledger.begin_active().expect("activate");
    clock.advance_seconds(7_200);
    ledger.settle_active().expect("settle");
    let (intent, _, _) = intent();
    assert!(matches!(
        ledger.admit_request(&intent, None),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::ActiveSeconds
        })
    ));
}

#[test]
fn human_wait_pause_and_app_stop_are_excluded_and_retry_waits_are_included() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let mut ledger = open_ledger(&store, BudgetPolicy::h2_default(), &clock);
    ledger.begin_active().expect("activate");

    clock.advance_seconds(10); // execution
    clock.advance_seconds(1); // retry wait
    clock.advance_seconds(2); // retry wait
    ledger.wait_for_human().expect("human wait");
    clock.advance_seconds(1_000);
    ledger.begin_active().expect("resume");
    clock.advance_seconds(5); // verification
    ledger.pause().expect("pause");
    clock.advance_seconds(1_000);
    ledger.begin_active().expect("resume");
    clock.advance_seconds(3); // assessment
    ledger.app_stop().expect("app stop");
    clock.advance_seconds(1_000);
    ledger.begin_active().expect("resume");
    clock.advance_seconds(2); // permission evaluation
    ledger.settle_active().expect("settle");

    assert_eq!(
        ledger.record().usage().active_seconds_consumed(),
        10 + 1 + 2 + 5 + 3 + 2
    );
    assert_eq!(ledger.remaining_active_seconds().expect("remaining"), 7_177);
}

#[test]
fn assessment_timeout_is_the_shorter_of_sixty_seconds_and_remaining_active() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let mut ledger = open_ledger(&store, BudgetPolicy::h2_default(), &clock);
    ledger.begin_active().expect("activate");
    assert_eq!(ledger.assessment_timeout().expect("fresh"), 60);
    clock.advance_seconds(7_160);
    assert_eq!(ledger.assessment_timeout().expect("40 left"), 40);
    clock.advance_seconds(40);
    assert_eq!(ledger.assessment_timeout().expect("exhausted"), 0);
}

#[test]
fn crash_with_an_open_active_interval_is_charged_conservatively_and_cannot_bypass_the_cap() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let mut ledger = open_ledger(&store, capped_policy(1.0), &clock);
    ledger.start_run(run_request()).expect("start run");
    clock.advance_seconds(100);
    // No settle: the open interval persists exactly as a crash would leave it.
    drop(ledger);

    // The wall clock advances through the restart gap while the process-local
    // monotonic clock starts again from zero.
    clock.advance_wall_only(7_100);
    clock.reset_monotonic();

    let mut reopened = open_ledger(&store, capped_policy(1.0), &clock);
    assert_eq!(
        reopened.record().usage().active_seconds_consumed(),
        7_200,
        "the crash interval must include both the unpersisted 100 s and the 7,100 s gap"
    );
    assert_eq!(reopened.remaining_active_seconds().expect("remaining"), 0);
    let (intent, _, _) = intent();
    assert!(matches!(
        reopened.admit_request(
            &intent,
            Some(&RequestBudgetEstimate::new(
                money(0.10),
                price_version(),
                AuthMethod::ApiKey
            ))
        ),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::ActiveSeconds
        })
    ));
}

// ---------------------------------------------------------------------------
// Run accounting
// ---------------------------------------------------------------------------

#[test]
fn first_run_thirty_additional_runs_and_the_thirty_first_are_allowed_then_rejected() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let mut ledger = open_ledger(&store, BudgetPolicy::h2_default(), &clock);

    let reserved = run_request();
    assert_eq!(
        ledger.reserve_run(reserved).expect("reserve").state(),
        herness_supervision::RunReservationState::Reserved
    );
    assert_eq!(ledger.record().usage().runs_reserved(), 1);
    assert_eq!(
        ledger.start_run(reserved).expect("start reserved").state(),
        herness_supervision::RunReservationState::Started
    );
    assert_eq!(ledger.record().usage().runs_started(), 1);
    assert_eq!(ledger.record().usage().runs_reserved(), 0);

    for _ in 1..31 {
        ledger.start_run(run_request()).expect("additional run");
    }
    assert_eq!(ledger.record().usage().runs_started(), 31);
    assert!(matches!(
        ledger.start_run(run_request()),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::RunCount
        })
    ));
    assert!(matches!(
        ledger.reserve_run(run_request()),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::RunCount
        })
    ));

    // A duplicate start of the first request returns the recorded result.
    assert_eq!(
        ledger.start_run(reserved).expect("duplicate start").state(),
        herness_supervision::RunReservationState::Started
    );
    assert_eq!(ledger.record().usage().runs_started(), 31);
}

#[test]
fn resume_and_reopen_do_not_reset_run_counts_or_active_usage() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let policy = BudgetPolicy::h2_default();
    let mut ledger = open_ledger(&store, policy.clone(), &clock);
    let first = run_request();
    ledger.start_run(first).expect("first run");
    for _ in 1..31 {
        ledger.start_run(run_request()).expect("additional run");
    }
    clock.advance_seconds(250);
    ledger.settle_active().expect("settle");
    assert_eq!(ledger.record().usage().runs_started(), 31);
    drop(ledger);

    let mut reopened = open_ledger(&store, policy, &clock);
    assert_eq!(reopened.record().usage().runs_started(), 31);
    assert_eq!(reopened.record().usage().active_seconds_consumed(), 250);
    assert!(matches!(
        reopened.start_run(run_request()),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::RunCount
        })
    ));
    assert_eq!(
        reopened
            .start_run(first)
            .expect("duplicate survives reopen")
            .state(),
        herness_supervision::RunReservationState::Started
    );
}

// ---------------------------------------------------------------------------
// Money reservations, concurrency, and idempotency
// ---------------------------------------------------------------------------

#[test]
fn all_model_request_purposes_share_one_money_cap() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let mut ledger = open_ledger(&store, capped_policy(1.0), &clock);
    ledger.begin_active().expect("activate");

    for _ in 0..4 {
        ledger
            .reserve_money(
                RequestId::new(project()),
                AttemptId::new(project()),
                money(0.25),
                &price_version(),
            )
            .expect("shared-cap reservation");
    }
    assert_eq!(ledger.record().usage().money_reserved(), money(1.0));
    assert!(matches!(
        ledger.reserve_money(
            RequestId::new(project()),
            AttemptId::new(project()),
            money(0.01),
            &price_version()
        ),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::Money
        })
    ));
}

#[test]
fn concurrent_ledgers_cannot_exceed_the_money_or_run_cap() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let policy = capped_policy(1.0);
    let mut a = open_ledger(&store, policy.clone(), &clock);
    let mut b = open_ledger(&store, policy.clone(), &clock);
    a.begin_active().expect("activate");
    b.begin_active().expect("activate");

    let attempt_a = AttemptId::new(project());
    a.reserve_money(
        RequestId::new(project()),
        attempt_a,
        money(0.60),
        &price_version(),
    )
    .expect("first reservation");
    assert!(matches!(
        b.reserve_money(
            RequestId::new(project()),
            AttemptId::new(project()),
            money(0.60),
            &price_version()
        ),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::Money
        })
    ));
    let record = store
        .state()
        .records
        .get(&ids(project()).supervision)
        .expect("record")
        .record()
        .clone();
    assert_eq!(record.usage().money_reserved(), money(0.60));
    assert_eq!(record.money_reservations().len(), 1);

    let first_run = run_request();
    a.start_run(first_run).expect("first run");
    for _ in 1..31 {
        a.start_run(run_request()).expect("additional run");
    }
    assert!(matches!(
        b.start_run(run_request()),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::RunCount
        })
    ));
}

#[test]
fn cas_conflict_retries_and_rechecks_the_cap_before_writing() {
    // The competing reservation makes the retry exceed the cap.
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let supervision = ids(project()).supervision;
    let mut ledger = open_ledger(&store, capped_policy(1.0), &clock);
    ledger.begin_active().expect("activate");
    let competing_request = RequestId::new(project());
    let competing_attempt = AttemptId::new(project());
    let version = price_version();
    store.state().before_cas = Some(Box::new(move |state| {
        let current = state
            .records
            .get(&supervision)
            .expect("ledger record")
            .clone();
        let mut record = current.record().clone();
        record
            .reserve_money(competing_request, competing_attempt, money(0.50), &version)
            .expect("competing reservation");
        state.records.insert(
            supervision,
            StoredBudgetRecord::new(current.revision() + 1, record).expect("stored record"),
        );
    }));
    assert!(matches!(
        ledger.reserve_money(
            RequestId::new(project()),
            AttemptId::new(project()),
            money(0.60),
            &price_version()
        ),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::Money
        })
    ));

    // The same conflict retries successfully when the combined amount fits.
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let supervision = ids(project()).supervision;
    let mut ledger = open_ledger(&store, capped_policy(2.0), &clock);
    ledger.begin_active().expect("activate");
    let competing_request = RequestId::new(project());
    let competing_attempt = AttemptId::new(project());
    let version = price_version();
    store.state().before_cas = Some(Box::new(move |state| {
        let current = state
            .records
            .get(&supervision)
            .expect("ledger record")
            .clone();
        let mut record = current.record().clone();
        record
            .reserve_money(competing_request, competing_attempt, money(0.50), &version)
            .expect("competing reservation");
        state.records.insert(
            supervision,
            StoredBudgetRecord::new(current.revision() + 1, record).expect("stored record"),
        );
    }));
    ledger
        .reserve_money(
            RequestId::new(project()),
            AttemptId::new(project()),
            money(0.60),
            &price_version(),
        )
        .expect("retry after conflict");
    assert_eq!(ledger.record().usage().money_reserved(), money(1.10));
    assert_eq!(ledger.record().money_reservations().len(), 2);
}

#[test]
fn duplicate_reservation_and_run_ids_are_idempotent_and_never_double_charge() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let mut ledger = open_ledger(&store, capped_policy(1.0), &clock);
    ledger.begin_active().expect("activate");

    let request = RequestId::new(project());
    let attempt = AttemptId::new(project());
    let first = ledger
        .reserve_money(request, attempt, money(0.40), &price_version())
        .expect("reserve");
    let duplicate = ledger
        .reserve_money(request, attempt, money(0.40), &price_version())
        .expect("duplicate reserve");
    assert_eq!(duplicate, first);
    assert_eq!(ledger.record().usage().money_reserved(), money(0.40));
    assert_eq!(ledger.record().money_reservations().len(), 1);
    assert!(matches!(
        ledger.reserve_money(
            request,
            AttemptId::new(project()),
            money(0.40),
            &price_version()
        ),
        Err(SupervisionError::BudgetReservationConflict { .. })
    ));

    let run = run_request();
    ledger.start_run(run).expect("start");
    ledger.start_run(run).expect("duplicate start");
    assert_eq!(ledger.record().usage().runs_started(), 1);
    assert_eq!(ledger.record().run_reservations().len(), 1);
}

// ---------------------------------------------------------------------------
// Gate admission and money policy
// ---------------------------------------------------------------------------

#[test]
fn money_cap_requires_estimate_and_price_version_and_refuses_chatgpt_login() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let ledger = open_ledger(&store, capped_policy(1.0), &clock);
    let mut gate = BudgetRequestGate::new(ledger, Estimator::default());
    gate.ledger_mut().begin_active().expect("activate");
    let (request, _, _) = intent();

    assert_eq!(
        gate.admit(&request).expect("missing estimate"),
        RequestGateOutcome::Refuse {
            reason: RequestGateRefusal::BudgetUnavailable
        }
    );
    assert!(store.state().intents.is_empty());
    assert!(
        store
            .state()
            .records
            .values()
            .next()
            .is_none_or(|stored| stored.record().money_reservations().is_empty())
    );

    let mut wrong_gate = BudgetRequestGate::new(
        open_ledger(&store, capped_policy(1.0), &clock),
        Estimator::wrong_price_version(100_000),
    );
    wrong_gate.ledger_mut().begin_active().expect("activate");
    let (wrong_request, _, _) = intent();
    assert_eq!(
        wrong_gate
            .admit(&wrong_request)
            .expect("wrong price version"),
        RequestGateOutcome::Refuse {
            reason: RequestGateRefusal::BudgetUnavailable
        }
    );

    let store = SharedStore::default();
    let clock = FakeClock::new();
    let ledger = open_ledger(&store, capped_policy(1.0), &clock);
    let mut chatgpt = BudgetRequestGate::new(ledger, Estimator::chatgpt(100_000));
    chatgpt.ledger_mut().begin_active().expect("activate");
    let (request, _, _) = intent();
    assert_eq!(
        chatgpt.admit(&request).expect("chatgpt with cap"),
        RequestGateOutcome::Refuse {
            reason: RequestGateRefusal::BudgetUnavailable
        }
    );
    assert!(store.state().intents.is_empty());

    // Without a cap the same ChatGPT path needs no reservation.
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let ledger = open_ledger(&store, BudgetPolicy::h2_default(), &clock);
    let mut no_cap = BudgetRequestGate::new(ledger, Estimator::chatgpt(100_000));
    no_cap.ledger_mut().begin_active().expect("activate");
    let (request, _, _) = intent();
    assert_eq!(
        no_cap.admit(&request).expect("no cap"),
        RequestGateOutcome::Admit
    );
    assert_eq!(
        no_cap.ledger().record().usage().money_reserved(),
        Money::zero()
    );
}

#[test]
fn gate_refuses_stopped_and_deadline_controls_before_touching_the_ledger() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let ledger = open_ledger(&store, BudgetPolicy::h2_default(), &clock);
    let mut gate = BudgetRequestGate::new(ledger, Estimator::default());
    gate.ledger_mut().begin_active().expect("activate");

    let (stopped, _, _) = intent_with(StopDeadlineControl::stopped(
        herness_core::contracts::StopReason::UserRequest,
    ));
    assert_eq!(
        gate.admit(&stopped).expect("stopped"),
        RequestGateOutcome::Refuse {
            reason: RequestGateRefusal::Stopped
        }
    );
    let (deadline, _, _) = intent_with(StopDeadlineControl::deadline());
    assert_eq!(
        gate.admit(&deadline).expect("deadline"),
        RequestGateOutcome::Refuse {
            reason: RequestGateRefusal::DeadlineReached
        }
    );
    assert!(store.state().intents.is_empty());
    assert!(
        store
            .state()
            .records
            .values()
            .all(|stored| { stored.record().money_reservations().is_empty() })
    );
}

#[test]
fn known_completion_settles_at_least_the_reserved_estimate_and_missing_usage_stays_reserved() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let ledger = open_ledger(&store, capped_policy(1.0), &clock);
    let estimator = Estimator::estimated(300_000).with_settled(200_000);
    let mut gate = BudgetRequestGate::new(ledger, estimator);
    gate.ledger_mut().begin_active().expect("activate");

    let (completed_intent, request, attempt) = intent();
    assert_eq!(
        gate.admit(&completed_intent).expect("admit"),
        RequestGateOutcome::Admit
    );
    let completed = ModelRequestObservation::new(
        request,
        attempt,
        RequestOutcome::Completed,
        None,
        None,
        known_usage(100),
    )
    .expect("observation");
    gate.observe(&completed).expect("observe");
    let record = gate.ledger().record();
    assert_eq!(record.usage().money_consumed(), money(0.30));
    assert_eq!(record.usage().money_reserved(), Money::zero());
    assert_eq!(
        record
            .money_reservation(attempt)
            .expect("reservation")
            .state(),
        &MoneyReservationState::Settled {
            amount: money(0.30)
        }
    );

    // A completed request with missing usage keeps its reservation.
    let (unknown_intent, unknown_request, unknown_attempt) = intent();
    assert_eq!(
        gate.admit(&unknown_intent).expect("admit"),
        RequestGateOutcome::Admit
    );
    let unknown = ModelRequestObservation::new(
        unknown_request,
        unknown_attempt,
        RequestOutcome::Completed,
        None,
        None,
        TokenUsage::unknown(),
    )
    .expect("observation");
    gate.observe(&unknown).expect("observe");
    assert_eq!(
        gate.ledger()
            .record()
            .money_reservation(unknown_attempt)
            .expect("reservation")
            .state(),
        &MoneyReservationState::Unresolved
    );
    assert_eq!(gate.ledger().record().usage().money_reserved(), money(0.30));
    gate.observe(&unknown).expect("duplicate observation");
    assert_eq!(
        gate.ledger().record().usage().money_reserved(),
        money(0.30),
        "a duplicate observation must not settle or charge twice"
    );

    // The unresolved reservation still counts: only 0.30 remains, so another
    // 0.30 fits and the next one is refused.
    let (last_intent, _, _) = intent();
    assert_eq!(
        gate.admit(&last_intent).expect("last admission"),
        RequestGateOutcome::Admit
    );
    assert_eq!(gate.ledger().record().usage().money_reserved(), money(0.60));
    let (over_intent, _, _) = intent();
    assert_eq!(
        gate.admit(&over_intent).expect("cap refusal"),
        RequestGateOutcome::Refuse {
            reason: RequestGateRefusal::BudgetUnavailable
        }
    );
}

#[test]
fn preflight_failure_releases_only_when_no_send_occurred() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let ledger = open_ledger(&store, capped_policy(1.0), &clock);
    let mut gate = BudgetRequestGate::new(ledger, Estimator::estimated(400_000));
    gate.ledger_mut().begin_active().expect("activate");

    let (intent, request, attempt) = self::intent();
    gate.admit(&intent).expect("admit");
    let started = ModelRequestObservation::new(
        request,
        attempt,
        RequestOutcome::SendStarted,
        None,
        None,
        TokenUsage::unknown(),
    )
    .expect("started");
    gate.observe(&started).expect("send started");
    assert_eq!(
        gate.ledger()
            .record()
            .money_reservation(attempt)
            .expect("reservation")
            .state(),
        &MoneyReservationState::Reserved
    );
    let unknown = ModelRequestObservation::new(
        request,
        attempt,
        RequestOutcome::SendResultUnknown,
        None,
        None,
        TokenUsage::unknown(),
    )
    .expect("unknown");
    gate.observe(&unknown).expect("send unknown");
    assert_eq!(
        gate.ledger()
            .record()
            .money_reservation(attempt)
            .expect("reservation")
            .state(),
        &MoneyReservationState::Unresolved
    );
    assert_eq!(gate.ledger().record().usage().money_reserved(), money(0.40));

    // A request that definitely did not send releases its reservation.
    let (preflight_intent, preflight_request, preflight_attempt) = self::intent();
    gate.admit(&preflight_intent).expect("admit");
    let failed = ModelRequestObservation::new(
        preflight_request,
        preflight_attempt,
        RequestOutcome::PreflightFailed,
        Some(ProviderFailureKind::Refused),
        None,
        TokenUsage::unknown(),
    )
    .expect("preflight");
    gate.observe(&failed).expect("preflight observe");
    assert_eq!(
        gate.ledger()
            .record()
            .money_reservation(preflight_attempt)
            .expect("reservation")
            .state(),
        &MoneyReservationState::Released
    );
    assert_eq!(gate.ledger().record().usage().money_reserved(), money(0.40));

    let (replacement_intent, _, _) = self::intent();
    gate.admit(&replacement_intent)
        .expect("reuse released money");
    assert_eq!(gate.ledger().record().usage().money_reserved(), money(0.80));
}

// ---------------------------------------------------------------------------
// Durable store and fault injection
// ---------------------------------------------------------------------------

#[test]
fn store_persist_fault_leaves_no_admission_or_reservation_and_reopen_keeps_state() {
    let harness = StoreHarness::new();
    let clock = FakeClock::new();
    let supervision = ids(project()).supervision;
    let policy = capped_policy(1.0);
    let store = harness.open();
    let ledger = BudgetLedger::open(store, project(), supervision, policy, 1, clock.clone())
        .expect("open ledger");
    let mut gate = BudgetRequestGate::new(ledger, Estimator::estimated(400_000));
    gate.ledger_mut().begin_active().expect("activate");
    gate.ledger_mut()
        .store_mut()
        .set_commit_fault(Some(CommitFault::BeforeCommit));

    let (intent, _, attempt) = intent();
    assert!(gate.admit(&intent).is_err(), "persist fault must refuse");
    gate.ledger_mut().store_mut().set_commit_fault(None);
    assert!(
        gate.ledger()
            .store()
            .model_request(&attempt)
            .expect("read request")
            .is_none()
    );
    let unchanged = gate
        .ledger()
        .store()
        .load_budget_record(project(), supervision)
        .expect("read budget")
        .expect("ledger from the activation write");
    assert_eq!(unchanged.record().usage().money_reserved(), Money::zero());
    assert!(unchanged.record().money_reservations().is_empty());
    assert_eq!(
        gate.ledger().record().usage().money_reserved(),
        Money::zero(),
        "a failed store write must not leave an in-memory reservation"
    );

    // The same gate retries successfully after the fault is cleared.
    assert_eq!(
        gate.admit(&intent).expect("retry"),
        RequestGateOutcome::Admit
    );
    assert!(
        gate.ledger()
            .store()
            .model_request(&attempt)
            .expect("read request")
            .is_some()
    );
    let stored = gate
        .ledger()
        .store()
        .load_budget_record(project(), supervision)
        .expect("read budget")
        .expect("budget record");
    assert_eq!(stored.record().usage().money_reserved(), money(0.40));
    let revision = stored.revision();
    drop(gate);

    let reopened = harness.open();
    let stored = reopened
        .load_budget_record(project(), supervision)
        .expect("reopen budget")
        .expect("budget record");
    assert_eq!(stored.revision(), revision);
    assert_eq!(stored.record().usage().money_reserved(), money(0.40));
    assert!(
        reopened
            .model_request(&attempt)
            .expect("reopen request")
            .is_some()
    );
}

#[test]
fn store_fault_during_run_start_does_not_consume_a_run() {
    let harness = StoreHarness::new();
    let clock = FakeClock::new();
    let supervision = ids(project()).supervision;
    let store = harness.open();
    let mut ledger = BudgetLedger::open(
        store,
        project(),
        supervision,
        BudgetPolicy::h2_default(),
        1,
        clock.clone(),
    )
    .expect("open ledger");
    ledger
        .store_mut()
        .set_commit_fault(Some(CommitFault::BeforeCommit));
    assert!(ledger.start_run(run_request()).is_err());
    assert_eq!(ledger.record().usage().runs_started(), 0);
    assert_eq!(ledger.record().usage().runs_reserved(), 0);
    ledger.store_mut().set_commit_fault(None);
    ledger.start_run(run_request()).expect("retry start");
    assert_eq!(ledger.record().usage().runs_started(), 1);
}

#[test]
fn failed_schema_eight_migration_rolls_back_to_schema_seven() {
    use herness_store::test_support::{
        MigrationFault, open_at_schema_version, open_with_migration_fault,
    };

    let harness = StoreHarness::new();
    drop(open_at_schema_version(harness.config.clone(), 7).expect("schema seven"));
    let error = open_with_migration_fault(
        harness.config.clone(),
        MigrationFault::AfterStatements {
            version: 8,
            statements: 1,
        },
    )
    .expect_err("migration fault");
    assert!(matches!(
        error,
        herness_store::StoreError::InjectedFault {
            point: "migration-after-statement"
        }
    ));
    drop(open_at_schema_version(harness.config.clone(), 7).expect("rolled back"));
    drop(harness.open());
}

#[test]
fn owner_generation_change_preserves_consumed_and_reserved_budget_across_7199_and_7200() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path().join("app-data");
    std::fs::create_dir_all(&root).expect("app data directory");
    let config = StoreConfig::new(&root).expect("store config");
    let project_id = project();
    let supervision = ids(project_id).supervision;
    let owner = OwnerRef::new(OwnerKind::H3HtmlJob, "generation-job").expect("owner");
    let policy = BudgetPolicy::new(
        7_200,
        30,
        Some(MoneyCap::new(money(1.0), price_version()).expect("cap")),
    )
    .expect("finite policy");
    let current = owner_contract_at_with_budget(
        project_id,
        owner.clone(),
        OwnerApprovalSource::H3ApprovedSettings,
        1,
        1,
        policy.clone(),
    );
    let run = RunId::new(project_id);
    let mut record = SupervisionRecord::new(&current);
    record.begin_run(run).expect("first run");
    let mut store = Store::open(config.clone()).expect("store");
    store
        .compare_and_swap_supervision(project_id, supervision, None, &record)
        .expect("save record");

    let clock = FakeClock::new();
    let mut ledger = BudgetLedger::open(
        Store::open(config.clone()).expect("budget store"),
        project_id,
        supervision,
        policy.clone(),
        1,
        clock.clone(),
    )
    .expect("ledger");
    for index in 0..30u128 {
        ledger
            .start_run(BudgetRequestId::from_parts(
                project_id,
                Uuid::from_u128(0x1100_0000_0000_4000_8000_0000_0000_0000 + index),
            ))
            .expect("additional run");
    }
    clock.advance_seconds(7_199);
    ledger.settle_active().expect("settle");
    let reserved_money = money(0.10);
    ledger
        .reserve_money(
            RequestId::new(project_id),
            AttemptId::new(project_id),
            reserved_money,
            &price_version(),
        )
        .expect("money reservation");
    let before = ledger.record().usage();
    assert_eq!(before.runs_started(), 30);
    assert_eq!(before.active_seconds_consumed(), 7_199);
    assert_eq!(before.money_reserved(), reserved_money);

    let replacement = owner_contract_succeeding(&current, 2, 1, policy.clone());
    let binding =
        OwnerLaunchBinding::from_contract(&replacement, 1, 1, "generation-job").expect("binding");
    let mut registry = ScriptedOwnerApprovalRegistry::new();
    registry.insert(binding.approval().clone());
    let authority = authorize_owner_launch(&registry, &binding, now()).expect("authority");
    let mut runtime = GenerationRuntime::new(run);

    let request = OwnerSupersessionRequest::new(
        SupervisionRequestId::new(project_id),
        supervision,
        record.revision(),
        replacement.clone(),
    )
    .expect("supersession request");
    let result = execute_owner_supersession(
        OperationPorts {
            store: &mut store,
            runtime: &mut runtime,
            budget: &mut ledger,
            clock: &clock,
        },
        &current,
        1,
        request,
        authority,
    )
    .expect("owner supersession");
    assert!(!result.duplicate());
    assert_eq!(result.command().state(), SupervisionState::Ready);
    assert_eq!(runtime.stop_calls, 1);

    let changed = store
        .load_supervision_record(project_id, supervision)
        .expect("load")
        .expect("record");
    assert_eq!(changed.target_version().get(), 2);
    assert_eq!(changed.run_group().runs(), &[run]);
    assert_eq!(changed.applied_decisions().len(), 0);
    assert_eq!(changed.change_log().len(), 1);
    assert_eq!(changed.change_log()[0].kind(), ChangeKind::Supersede);
    assert_eq!(changed.change_log()[0].budget_before(), before);
    assert_eq!(changed.change_log()[0].budget_after(), before);
    assert_eq!(ledger.record().usage(), before);

    // The boundary run is the thirty-first and is still allowed.
    ledger
        .start_run(BudgetRequestId::new(project_id))
        .expect("thirty-first run");
    assert_eq!(ledger.record().usage().runs_started(), 31);
    clock.advance_seconds(1);
    ledger.settle_active().expect("settle at boundary");
    assert_eq!(ledger.record().usage().active_seconds_consumed(), 7_200);
    assert_eq!(ledger.remaining_active_seconds().expect("remaining"), 0);
    assert_eq!(ledger.record().usage().money_reserved(), reserved_money);

    // A further generation change is refused by the exhausted budget latch and
    // cannot reset the ledger or consume a thirty-second run.
    let replacement_three = owner_contract_succeeding(&replacement, 3, 1, policy.clone());
    let binding_three = OwnerLaunchBinding::from_contract(&replacement_three, 1, 1, "generation-job")
        .expect("binding three");
    registry.insert(binding_three.approval().clone());
    let authority_three =
        authorize_owner_launch(&registry, &binding_three, now()).expect("authority three");
    let request_three = OwnerSupersessionRequest::new(
        SupervisionRequestId::new(project_id),
        supervision,
        changed.revision(),
        replacement_three,
    )
    .expect("third request");
    let rejected = execute_owner_supersession(
        OperationPorts {
            store: &mut store,
            runtime: &mut runtime,
            budget: &mut ledger,
            clock: &clock,
        },
        &replacement,
        1,
        request_three,
        authority_three,
    );
    assert!(matches!(
        rejected,
        Err(SupervisionError::OwnerSupersessionRejected {
            reason: OwnerSupersessionRejection::BudgetExhausted {
                limit: BudgetLimit::RunCount
            }
        })
    ));
    assert_eq!(ledger.record().usage().runs_started(), 31);
    assert_eq!(ledger.record().usage().active_seconds_consumed(), 7_200);
    assert_eq!(ledger.record().usage().money_reserved(), reserved_money);
    assert_eq!(
        ledger.start_run(BudgetRequestId::new(project_id)),
        Err(SupervisionError::BudgetLimitReached {
            limit: BudgetLimit::RunCount
        })
    );
    let unchanged = store
        .load_supervision_record(project_id, supervision)
        .expect("load")
        .expect("record");
    assert_eq!(unchanged.target_version().get(), 2);
    assert_eq!(unchanged.change_log().len(), 1);
    assert_eq!(runtime.stop_calls, 1);
}

struct GenerationRuntime {
    run: RunId,
    stop_state: RecoveryStopState,
    stop_calls: u32,
}

impl GenerationRuntime {
    fn new(run: RunId) -> Self {
        Self {
            run,
            stop_state: RecoveryStopState::NotRequested,
            stop_calls: 0,
        }
    }
}

impl RecoveryRuntimePort for GenerationRuntime {
    fn run_state(&mut self, _run: RunId) -> Result<RunState, SupervisionError> {
        Ok(RunState::Idle)
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
        Ok(RecoveryCheckpoint::Present)
    }

    fn stop_state(&mut self, _run: RunId) -> Result<RecoveryStopState, SupervisionError> {
        let _ = self.run;
        Ok(self.stop_state)
    }

    fn permissions_current(
        &mut self,
        _record: &SupervisionRecord,
    ) -> Result<bool, SupervisionError> {
        Ok(true)
    }
}

impl OperationRuntimePort for GenerationRuntime {
    fn request_stop(&mut self, _run: RunId) -> Result<StopDisposition, SupervisionError> {
        self.stop_calls = self.stop_calls.saturating_add(1);
        self.stop_state = RecoveryStopState::Confirmed;
        Ok(StopDisposition::Confirmed)
    }
}

#[test]
fn money_reservations_are_unresolved_until_explicitly_settled_or_released() {
    let store = SharedStore::default();
    let clock = FakeClock::new();
    let mut ledger = open_ledger(&store, capped_policy(1.0), &clock);
    ledger.begin_active().expect("activate");
    let attempt = AttemptId::new(project());
    ledger
        .reserve_money(
            RequestId::new(project()),
            attempt,
            money(0.25),
            &price_version(),
        )
        .expect("reserve");
    assert!(ledger.unresolved_charges().expect("unresolved").is_empty());
    ledger
        .settle_money(attempt, MoneySettlement::Unresolved)
        .expect("unresolved");
    let unresolved: Vec<MoneyReservation> = ledger.unresolved_charges().expect("unresolved");
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].estimate(), money(0.25));
    assert_eq!(ledger.record().usage().money_reserved(), money(0.25));

    // A known completion may settle above the local estimate.
    let settled = ledger
        .settle_money(
            attempt,
            MoneySettlement::Completed {
                actual: money(0.40),
            },
        )
        .expect("settle above estimate");
    assert_eq!(
        settled.state(),
        &MoneyReservationState::Settled {
            amount: money(0.40)
        }
    );
    assert_eq!(ledger.record().usage().money_consumed(), money(0.40));
    assert_eq!(ledger.record().usage().money_reserved(), Money::zero());
    assert!(matches!(
        ledger.settle_money(attempt, MoneySettlement::NotSent),
        Err(SupervisionError::BudgetReservationConflict { .. })
    ));
}
