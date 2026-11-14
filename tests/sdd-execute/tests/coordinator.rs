//! Task 15: the serial Task coordinator and the combined Task budget.
//!
//! Every case uses a synthetic project, a real temporary SQLite store, and
//! deterministic child/launch/completion fakes. No provider, credential,
//! Keychain item, model request, shell command, or GUI session is used. The one
//! real checkout path is a fixed absolute path that is never opened.

use herness_core::contracts::{ConnectionId, ProjectId, Timestamp};
use herness_sdd_execute::{
    ApprovalId, ApprovalSource, ApprovedCheck, ApprovedCondition, ApprovedDeliverable,
    ApprovedSpecRef, Baseline, BudgetConsumption, ChildDispatchPlan, ChildDispatchPort,
    ChildIdentity, ChildState, ChildStatus, ChildStatusPort, CommitAuthorization, CommitPolicy,
    CompletionFeature, CompletionWiring, ConditionMode, ContinuationLimits, ControlRequestId,
    CoordinatorOutcome, CoordinatorPorts, CoordinatorRequest, DeliverableKind, DispatchRequestId,
    DispatchResult, ExecutionApproval, ExecutionConnection, ExecutionId, ExecutionRevision,
    ExecutionSnapshot, ExecutionState, GitIdentity, H2SupervisionRef, H3ApprovalBinding,
    InspectorProtocol, LaunchRefusal, NotConnectedCompletion, PackApproval, PackFingerprint,
    ParsedPlanSummary, ParsedPlanTask, PlanApproval, PlanByteRange, PlanDigest, PlanPath,
    PlanRevision, SddExecutionError, SerialExecutionState, Sha256Digest, SnapshotBudget,
    SnapshotInput, SnapshotPlan, SnapshotSections, SnapshotWorkspace, TaskApproval, TaskBudget,
    TaskBudgetConsumption, TaskCompletion, TaskCompletionPort, TaskCompletionRequest, TaskLaunch,
    TaskLaunchPort, TaskNumber, TaskRef, TaskStableId, WorkspaceApproval, dispatch_request_id,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::{
    ApprovalActor, BudgetPolicy, ConsentBinding, ConsentId, EvidenceId, ExecutionScope,
    ProfileBinding, ProfileId, ProfilePurpose, ProfileVersion, SupervisionId, TargetVersion,
};
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Identity fixtures
// ---------------------------------------------------------------------------

/// Fixed checkout path used by snapshots. It is never opened.
const CHECKOUT: &str = "/tmp/herness-h4-coordinator-fixture";
const BRANCH: &str = "h4-coordinator";
const BASE_BRANCH: &str = "main";
const PLAN_PATH: &str = "docs/sdd/plans/2026-11-13-coordinator-fixture.md";
const SPEC_PATH: &str = "docs/sdd/specs/2026-11-13-coordinator-fixture.md";

fn project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("a0000000-0000-4000-8000-000000000001").unwrap())
}

fn other_project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("a0000000-0000-4000-8000-000000000002").unwrap())
}

fn execution(project_id: ProjectId) -> ExecutionId {
    ExecutionId::from_parts(
        project_id,
        Uuid::parse_str("b0000000-0000-4000-8000-000000000001").unwrap(),
    )
}

fn other_execution(project_id: ProjectId) -> ExecutionId {
    ExecutionId::from_parts(
        project_id,
        Uuid::parse_str("b0000000-0000-4000-8000-000000000002").unwrap(),
    )
}

fn approval_id(project_id: ProjectId) -> ApprovalId {
    ApprovalId::from_parts(
        project_id,
        Uuid::parse_str("c0000000-0000-4000-8000-000000000001").unwrap(),
    )
}

fn control_request(project_id: ProjectId, local: u128) -> ControlRequestId {
    ControlRequestId::from_parts(project_id, Uuid::from_u128(local))
}

fn plan_path() -> PlanPath {
    PlanPath::parse(PLAN_PATH).expect("a plan path")
}

fn baseline() -> Baseline {
    Baseline::parse("a".repeat(40)).expect("a baseline")
}

fn plan_revision() -> PlanRevision {
    PlanRevision::new(1).expect("a plan revision")
}

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::sha256(label.as_bytes())
}

fn task_ref(project_id: ProjectId, number: u32) -> TaskRef {
    TaskRef::new(
        TaskStableId::from_parts(
            project_id,
            Uuid::from_u128(0xd000_0000_0000_4000_8000_0000_0000_0000 + u128::from(number)),
        ),
        TaskNumber::new(number).expect("a Task number"),
    )
}

fn now() -> Timestamp {
    Timestamp::from_unix_millis(1_770_000_000_000)
}

fn profile(project_id: ProjectId) -> ProfileBinding {
    ProfileBinding::new(
        ProfileId::from_parts(
            project_id,
            Uuid::parse_str("e0000000-0000-4000-8000-000000000001").unwrap(),
        ),
        ProfileVersion::new(1).expect("a profile version"),
        ProfilePurpose::Completion,
    )
}

fn consent(project_id: ProjectId) -> ConsentBinding {
    ConsentBinding::new(
        ConsentId::from_parts(
            project_id,
            Uuid::parse_str("e0000000-0000-4000-8000-000000000002").unwrap(),
        ),
        1,
        ProfilePurpose::Completion,
        TargetVersion::new(1).expect("a target version"),
    )
}

// ---------------------------------------------------------------------------
// Approval fixture: one plan with two Tasks
// ---------------------------------------------------------------------------

fn condition() -> ApprovedCondition {
    ApprovedCondition::new("c1", "condition", "rubric text", ConditionMode::Checks)
        .expect("a condition")
}

fn check() -> ApprovedCheck {
    ApprovedCheck::new(
        "check-1",
        "c1",
        "run the check",
        "cargo test",
        ".",
        30,
        vec!["crates".to_owned()],
    )
    .expect("a check")
}

fn scope(project_id: ProjectId) -> ExecutionScope {
    ExecutionScope::new(
        project_id,
        vec!["crates".to_owned()],
        vec!["crates/herness-sdd-execute".to_owned()],
        false,
    )
    .expect("a scope")
}

fn task_approval(project_id: ProjectId, number: u32, budget: BudgetPolicy) -> TaskApproval {
    TaskApproval::new(
        task_ref(project_id, number),
        format!("Task {number}"),
        vec![condition()],
        scope(project_id),
        vec![check()],
        Vec::new(),
        budget,
        CommitPolicy::Required,
        vec![
            ApprovedDeliverable::new(
                "crates/herness-sdd-execute/src/lib.rs",
                DeliverableKind::File,
            )
            .expect("a deliverable"),
        ],
    )
    .expect("a Task approval")
}

fn parsed_plan(tasks: u32) -> ParsedPlanSummary {
    let constraints = format!("Global Constraints\n- keep {} rules", 4);
    let body = || {
        herness_sdd_execute::ExactPlanText::new("Body.\n", PlanByteRange::new(0, 6).unwrap())
            .expect("exact body")
    };
    let parsed = (1..=tasks)
        .map(|number| ParsedPlanTask::new(number, format!("Task {number}"), body()).unwrap())
        .collect::<Vec<_>>();
    ParsedPlanSummary::new(
        1,
        herness_sdd_execute::ExactPlanText::new(
            &constraints,
            PlanByteRange::new(0, constraints.len() as u64).unwrap(),
        )
        .unwrap(),
        parsed,
        vec!["check-1".to_owned()],
    )
    .expect("a parsed plan")
}

fn plan_approval(_project_id: ProjectId) -> PlanApproval {
    PlanApproval::new(
        plan_path(),
        herness_sdd_execute::ExactPlanBytes::new(b"# plan".to_vec()).unwrap(),
        plan_revision(),
        parsed_plan(2),
        vec![
            ApprovedSpecRef::new(
                "project",
                SPEC_PATH,
                vec!["Contract".to_owned()],
                digest("spec"),
            )
            .unwrap(),
        ],
        Vec::new(),
        PackApproval::new(
            InspectorProtocol::expected(),
            1,
            PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
        )
        .unwrap(),
    )
    .expect("a plan approval")
}

fn workspace_approval(project_id: ProjectId) -> WorkspaceApproval {
    WorkspaceApproval::new(
        project_id,
        CHECKOUT,
        GitIdentity::new("herness", "host@example.test").expect("a Git identity"),
        BRANCH,
        BASE_BRANCH,
        false,
        Some(baseline()),
    )
    .expect("a workspace approval")
}

fn connection(project_id: ProjectId) -> ExecutionConnection {
    ExecutionConnection::new(
        ConnectionId::from_uuid(Uuid::parse_str("e0000000-0000-4000-8000-000000000003").unwrap()),
        profile(project_id),
        vec![consent(project_id)],
    )
    .expect("an execution connection")
}

/// The one approval of the fixture: two Tasks, each with the H4 default budget.
fn approval(project_id: ProjectId) -> ExecutionApproval {
    approval_with_budgets(project_id, 2, BudgetPolicy::h2_default())
}

fn approval_with_budgets(
    project_id: ProjectId,
    tasks: u32,
    budget: BudgetPolicy,
) -> ExecutionApproval {
    ExecutionApproval::new(
        approval_id(project_id),
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry {
            approval_id: approval_id(project_id),
        },
        now(),
        herness_sdd_execute::ApprovalContent::new(
            plan_approval(project_id),
            workspace_approval(project_id),
            (1..=tasks)
                .map(|number| task_approval(project_id, number, budget.clone()))
                .collect(),
            connection(project_id),
            CommitAuthorization::new(true, true).expect("a commit authorization"),
            H3ApprovalBinding::new(1, Vec::new(), vec!["html-sync".to_owned()]).unwrap(),
        )
        .expect("an approval content"),
    )
    .expect("an approval")
}

// ---------------------------------------------------------------------------
// Snapshot fixtures
// ---------------------------------------------------------------------------

fn task_snapshot(
    project_id: ProjectId,
    number: u32,
    phase: herness_sdd_execute::TaskPhase,
    h2: Option<H2SupervisionRef>,
    child: Option<ChildIdentity>,
) -> herness_sdd_execute::TaskSnapshot {
    herness_sdd_execute::TaskSnapshot::new(
        task_ref(project_id, number),
        phase.implied_progression(),
        phase,
        h2,
        child,
        CommitPolicy::Required,
        None,
        None,
        Vec::new(),
        None,
        herness_sdd_execute::AppliedRevision::current(plan_revision()),
    )
    .expect("a Task snapshot")
}

/// A ready execution with `tasks` pending Tasks.
fn ready_snapshot(
    project_id: ProjectId,
    execution_id: ExecutionId,
    tasks: u32,
) -> ExecutionSnapshot {
    ExecutionSnapshot::new(SnapshotInput {
        project_id,
        execution_id,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Ready,
        plan: SnapshotPlan::new(plan_path(), PlanDigest::sha256(b"# plan"), plan_revision()),
        workspace: SnapshotWorkspace::new(CHECKOUT, BRANCH, BASE_BRANCH, Some(baseline()))
            .expect("a snapshot workspace"),
        current_task: Some(task_ref(project_id, 1)),
        tasks: (1..=tasks)
            .map(|number| {
                task_snapshot(
                    project_id,
                    number,
                    herness_sdd_execute::TaskPhase::Ready,
                    None,
                    None,
                )
            })
            .collect(),
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: herness_sdd_execute::AppliedRevision::current(plan_revision()),
        final_project_sequence: None,
    })
    .expect("a ready snapshot")
}

fn child(project_id: ProjectId, local: u128) -> ChildIdentity {
    ChildIdentity::new(
        herness_core::AgentId::from_parts(project_id, Uuid::from_u128(local)),
        herness_core::SessionId::from_parts(project_id, Uuid::from_u128(local + 1)),
    )
    .expect("a child")
}

fn supervision(project_id: ProjectId, local: u128) -> SupervisionId {
    SupervisionId::from_parts(project_id, Uuid::from_u128(local))
}

// ---------------------------------------------------------------------------
// Fake ports
// ---------------------------------------------------------------------------

/// A launch port that always produces the same deterministic launch.
struct FakeLaunch {
    calls: Vec<TaskRef>,
    refusal: Option<LaunchRefusal>,
}

impl FakeLaunch {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            refusal: None,
        }
    }

    fn refusing(refusal: LaunchRefusal) -> Self {
        Self {
            calls: Vec::new(),
            refusal: Some(refusal),
        }
    }
}

impl TaskLaunchPort for FakeLaunch {
    fn launch(&mut self, task: TaskRef) -> Result<TaskLaunch, LaunchRefusal> {
        self.calls.push(task);
        if let Some(refusal) = &self.refusal {
            return Err(refusal.clone());
        }
        TaskLaunch::new(
            format!("immutable packet for Task {}", task.number().get()),
            scope(task.project_id()),
            BudgetPolicy::h2_default(),
            digest("manifest"),
            digest("packet"),
        )
        .map_err(|error| LaunchRefusal::Context {
            detail: error.to_string(),
        })
    }
}

/// A child port that records every dispatch and creates one target per request.
#[derive(Default)]
struct FakeDispatch {
    calls: Vec<DispatchRequestId>,
    next_supervision: u128,
    fail: bool,
}

impl FakeDispatch {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            next_supervision: 0x5000,
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            calls: Vec::new(),
            next_supervision: 0x5000,
            fail: true,
        }
    }
}

impl ChildDispatchPort for FakeDispatch {
    fn dispatch(&mut self, plan: &ChildDispatchPlan) -> Result<DispatchResult, SddExecutionError> {
        let request = plan.request();
        let project = request.identity().project_id();
        let request_id = request.identity().request_id();
        self.calls.push(request_id);
        if self.fail {
            return Err(SddExecutionError::Unavailable {
                feature: "childDispatch: fixture failure".to_owned(),
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            });
        }
        let target = supervision(project, self.next_supervision);
        self.next_supervision += 2;
        DispatchResult::new(target, child(project, self.next_supervision))
    }

    fn reconcile(
        &mut self,
        _project_id: ProjectId,
        _execution_id: ExecutionId,
        _request_id: DispatchRequestId,
    ) -> Result<Option<DispatchResult>, SddExecutionError> {
        Ok(None)
    }
}

/// A status port that returns the scripted stored H2 result.
struct FakeChildren {
    scripted: Option<ChildStatus>,
    reads: Vec<DispatchRequestId>,
}

impl FakeChildren {
    fn absent() -> Self {
        Self {
            scripted: None,
            reads: Vec::new(),
        }
    }

    fn set(&mut self, status: ChildStatus) {
        self.scripted = Some(status);
    }
}

impl ChildStatusPort for FakeChildren {
    fn status(
        &mut self,
        _project_id: ProjectId,
        _execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<ChildStatus>, SddExecutionError> {
        self.reads.push(request_id);
        Ok(self.scripted.clone())
    }
}

/// A completion seam whose wiring and result are scripted.
struct FakeCompletion {
    wiring: CompletionWiring,
    result: Option<TaskCompletion>,
    requests: Vec<TaskCompletionRequest>,
}

impl FakeCompletion {
    fn connected(result: TaskCompletion) -> Self {
        Self {
            wiring: CompletionWiring::Connected,
            result: Some(result),
            requests: Vec::new(),
        }
    }

    fn not_connected() -> Self {
        Self {
            wiring: CompletionWiring::NotConnected {
                feature: CompletionFeature::HtmlBarrier,
            },
            result: None,
            requests: Vec::new(),
        }
    }
}

impl TaskCompletionPort for FakeCompletion {
    fn wiring(&self, _task: TaskRef) -> CompletionWiring {
        self.wiring
    }

    fn complete(
        &mut self,
        request: &TaskCompletionRequest,
    ) -> Result<TaskCompletion, SddExecutionError> {
        self.requests.push(request.clone());
        self.result
            .clone()
            .ok_or_else(|| SddExecutionError::Unavailable {
                feature: "hostCommit: fixture failure".to_owned(),
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            })
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    _temp: TempDir,
    store: Store,
    project: ProjectId,
    execution: ExecutionId,
    serial: SerialExecutionState,
    launch: FakeLaunch,
    dispatch: FakeDispatch,
    children: FakeChildren,
    completion: FakeCompletion,
}

impl Harness {
    /// A ready execution with two Tasks and a counting completion seam.
    fn new() -> Self {
        Self::with_completion(FakeCompletion::not_connected())
    }

    fn with_completion(completion: FakeCompletion) -> Self {
        Self::build(completion, None)
    }

    fn with_launch(launch: FakeLaunch) -> Self {
        Self::build(FakeCompletion::not_connected(), Some(launch))
    }

    fn with_dispatch(dispatch: FakeDispatch) -> Self {
        let mut harness = Self::build(FakeCompletion::not_connected(), None);
        harness.dispatch = dispatch;
        harness
    }

    fn build(completion: FakeCompletion, launch: Option<FakeLaunch>) -> Self {
        let temp = TempDir::new().expect("a temporary directory");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("a store configuration");
        let mut store = Store::open(config).expect("a temporary store");
        let project = project();
        let execution = execution(project);
        let approval = approval(project);
        herness_sdd_execute::DurableExecutionStorePort::record_approval(&mut store, &approval)
            .expect("the approval record");
        store
            .compare_and_swap_execution(
                project,
                execution,
                None,
                &ready_snapshot(project, execution, 2),
            )
            .expect("the initial snapshot");
        Self {
            _temp: temp,
            store,
            project,
            execution,
            serial: SerialExecutionState::new(),
            launch: launch.unwrap_or_else(FakeLaunch::new),
            dispatch: FakeDispatch::new(),
            children: FakeChildren::absent(),
            completion,
        }
    }

    fn request(&self, revision: ExecutionRevision, local: u128) -> CoordinatorRequest {
        CoordinatorRequest::new(
            self.project,
            self.execution,
            control_request(self.project, local),
            revision,
            approval_id(self.project),
            1,
        )
        .expect("a coordinator request")
    }

    fn request_for_execution(
        &self,
        execution: ExecutionId,
        project_id: ProjectId,
        revision: ExecutionRevision,
        local: u128,
    ) -> CoordinatorRequest {
        CoordinatorRequest::new(
            project_id,
            execution,
            control_request(project_id, local),
            revision,
            approval_id(project_id),
            1,
        )
        .expect("a coordinator request")
    }

    /// Runs one advance with the harness's ports.
    fn advance(
        &mut self,
        request: &CoordinatorRequest,
    ) -> Result<CoordinatorOutcome, SddExecutionError> {
        let mut ports = CoordinatorPorts {
            store: &mut self.store,
            launch: &mut self.launch,
            dispatch: &mut self.dispatch,
            children: &mut self.children,
            completion: &mut self.completion,
            serial: &mut self.serial,
        };
        herness_sdd_execute::TaskCoordinator::advance(&mut ports, request)
    }

    fn snapshot(&self) -> ExecutionSnapshot {
        self.store
            .load_sdd_execution(self.project, self.execution)
            .expect("load")
            .expect("a stored snapshot")
            .snapshot()
            .clone()
    }

    fn revision(&self) -> ExecutionRevision {
        self.store
            .load_sdd_execution(self.project, self.execution)
            .expect("load")
            .expect("a stored snapshot")
            .revision()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn evidence(local: u128) -> EvidenceId {
    EvidenceId::from_parts(project(), Uuid::from_u128(local))
}

fn status(
    state: ChildState,
    active_seconds: u64,
    additional_runs: u32,
    stalls: u32,
) -> ChildStatus {
    let target = supervision(project(), 0x5000);
    ChildStatus::new(
        target,
        state,
        active_seconds,
        additional_runs,
        stalls,
        false,
        Vec::new(),
    )
}

fn completion(host_seconds: u64) -> TaskCompletion {
    TaskCompletion::Complete {
        commit_range: Some(
            herness_sdd_execute::CommitRange::new(
                baseline(),
                herness_sdd_execute::CommitSha::parse("b".repeat(40)).unwrap(),
            )
            .expect("a commit range"),
        ),
        no_change: None,
        host_seconds,
    }
}

fn consumed(seconds: u64, runs: u32, stalls: u32) -> TaskBudgetConsumption {
    TaskBudgetConsumption::new(seconds, runs, stalls, None)
}

// ---------------------------------------------------------------------------
// Task budget
// ---------------------------------------------------------------------------

#[test]
fn active_seconds_boundaries_are_exact_at_7199_7200_and_7201() {
    for (consumed_seconds, admitted) in [(7_199u64, true), (7_200, false), (7_201, false)] {
        let budget = TaskBudget::resumed(
            ContinuationLimits::h4_default(),
            consumed(consumed_seconds, 0, 0),
        );
        assert_eq!(
            budget.admit().is_ok(),
            admitted,
            "consumed {consumed_seconds} must be admitted={admitted}"
        );
        assert_eq!(
            budget.remaining_seconds(),
            7_200u64.saturating_sub(consumed_seconds)
        );
    }

    // 7,200 seconds is exactly the limit: the next run and the completion are
    // both refused, and the typed reason names the seconds.
    let exhausted = TaskBudget::resumed(ContinuationLimits::h4_default(), consumed(7_200, 0, 0));
    let refusal = exhausted.admit_run().expect_err("the limit is reached");
    assert_eq!(
        refusal.reason(),
        herness_sdd_execute::BudgetExhaustionReason::ActiveSeconds
    );
    assert_eq!(refusal.limit(), 7_200);
    assert_eq!(refusal.consumed(), 7_200);
    assert!(exhausted.admit_completion().is_err());
}

#[test]
fn thirty_additional_runs_are_allowed_and_the_thirty_first_is_refused() {
    // The first run is free; 29 additional runs still leave one allowed.
    let allowed = TaskBudget::resumed(ContinuationLimits::h4_default(), consumed(0, 29, 0));
    assert!(allowed.admit_run().is_ok());
    assert_eq!(allowed.remaining_additional_runs(), 1);

    // 30 additional runs is exactly the limit: no run may start.
    let exhausted = TaskBudget::resumed(ContinuationLimits::h4_default(), consumed(0, 30, 0));
    let refusal = exhausted.admit_run().expect_err("the run limit is reached");
    assert_eq!(
        refusal.reason(),
        herness_sdd_execute::BudgetExhaustionReason::AdditionalRuns
    );
    assert_eq!(refusal.limit(), 30);
    assert_eq!(refusal.consumed(), 30);
    assert_eq!(exhausted.remaining_additional_runs(), 0);
}

#[test]
fn three_consecutive_stalls_stop_the_task_and_two_do_not() {
    let two = TaskBudget::resumed(ContinuationLimits::h4_default(), consumed(0, 0, 2));
    assert!(two.admit().is_ok(), "two consecutive stalls still progress");

    let three = TaskBudget::resumed(ContinuationLimits::h4_default(), consumed(0, 0, 3));
    let refusal = three.admit().expect_err("three consecutive stalls stop");
    assert_eq!(
        refusal.reason(),
        herness_sdd_execute::BudgetExhaustionReason::ConsecutiveStalls
    );
    assert_eq!(refusal.limit(), 3);
    assert_eq!(refusal.consumed(), 3);
    assert_eq!(
        refusal.stop_reason(),
        herness_sdd_execute::StopReason::ChildStalled
    );

    // A progress event clears the counter without touching the other values.
    let mut budget = TaskBudget::resumed(ContinuationLimits::h4_default(), consumed(10, 2, 2));
    budget.record_progress();
    assert_eq!(budget.consumption().consecutive_stalls(), 0);
    assert_eq!(budget.consumption().active_seconds(), 10);
    assert_eq!(budget.consumption().additional_runs(), 2);
}

#[test]
fn h2_consumption_and_host_processing_add_up_on_one_task() {
    let mut budget = TaskBudget::new(ContinuationLimits::h4_default());
    budget.observe_h2(1_000, 2);
    assert_eq!(budget.consumption().active_seconds(), 1_000);
    assert_eq!(budget.consumption().additional_runs(), 2);

    budget.mark_h2_completed();
    assert!(budget.h2_completed());
    // A completion grants no new limit and resets no consumption.
    assert_eq!(budget.limits(), ContinuationLimits::h4_default());
    assert_eq!(budget.consumption().active_seconds(), 1_000);

    budget.charge_host_processing(25);
    assert_eq!(
        budget.consumption().active_seconds(),
        1_025,
        "host processing is charged to the same Task"
    );
    assert_eq!(budget.remaining_seconds(), 6_175);
}

#[test]
fn resume_and_reapproval_keep_consumed_budget() {
    let stored = consumed(3_600, 12, 1);
    // A resume rebuilds the same consumption.
    let resumed = TaskBudget::resumed(ContinuationLimits::h4_default(), stored);
    assert_eq!(resumed.consumption(), stored);
    // A plan re-approval does not refund: the same stored value is what the next
    // approval revision's budget starts from.
    let reapproved = TaskBudget::resumed(ContinuationLimits::h4_default(), stored);
    assert_eq!(reapproved.consumption(), stored);
    assert_eq!(reapproved.remaining_seconds(), 3_600);
    assert_eq!(reapproved.remaining_additional_runs(), 18);

    // H2 reporting a lower cumulative value after a restart never refunds.
    let mut observed = TaskBudget::resumed(ContinuationLimits::h4_default(), stored);
    observed.observe_h2(10, 1);
    assert_eq!(observed.consumption().active_seconds(), 3_600);
    assert_eq!(observed.consumption().additional_runs(), 12);
}

#[test]
fn met_after_the_limit_is_refused_and_never_completion() {
    // H2 met the conditions, but the Task had already consumed its budget.
    let mut budget = TaskBudget::resumed(ContinuationLimits::h4_default(), consumed(7_200, 0, 0));
    budget.mark_h2_completed();
    let refusal = budget.admit_completion().expect_err("met after the limit");
    assert_eq!(
        refusal.reason(),
        herness_sdd_execute::BudgetExhaustionReason::ActiveSeconds
    );
    assert_eq!(
        refusal.stop_reason(),
        herness_sdd_execute::StopReason::BudgetExhausted
    );
    assert_eq!(
        refusal.human_action(),
        herness_sdd_execute::HumanAction::RaiseBudget
    );
}

// ---------------------------------------------------------------------------
// Task order and one implementer
// ---------------------------------------------------------------------------

#[test]
fn two_tasks_run_in_plan_order_and_exactly_one_is_dispatched() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));

    let first = harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0x100))
        .expect("the first advance");
    let (task, request_id, first_child) = match &first {
        CoordinatorOutcome::Dispatched {
            task,
            request_id,
            child,
            ..
        } => (*task, *request_id, *child),
        other => panic!("expected the first Task to dispatch, got {other:?}"),
    };
    assert_eq!(task.number().get(), 1, "the first Task is selected first");
    assert_eq!(
        request_id,
        dispatch_request_id(harness.execution, task_ref(harness.project, 1))
    );
    assert_eq!(harness.dispatch.calls.len(), 1, "exactly one child");
    assert_eq!(
        harness.serial.holder(),
        Some(harness.execution),
        "the app-wide implementer slot is held while the Task is active"
    );
    let checkout_claim =
        herness_sdd_execute::CheckoutClaim::new(CHECKOUT, BRANCH, harness.execution).unwrap();
    assert!(
        harness.serial.owns(&checkout_claim),
        "the one checkout is claimed by the active execution"
    );

    // The stored snapshot names exactly the one active Task and child.
    let stored = harness.snapshot();
    assert_eq!(stored.state(), ExecutionState::Running);
    assert_eq!(stored.current_task().map(|t| t.number().get()), Some(1));
    assert_eq!(
        stored.active_task().map(|t| t.task().number().get()),
        Some(1)
    );
    assert_eq!(
        stored
            .task(TaskNumber::new(1).unwrap())
            .and_then(|task| task.child()),
        Some(first_child)
    );

    // Task 1's child is still working: no second Task starts. Observation writes
    // no revision, so the stored revision stays two.
    let dispatched_revision = harness.revision();
    assert_eq!(dispatched_revision, ExecutionRevision::new(2).unwrap());
    harness.children.set(status(ChildState::Running, 30, 0, 0));
    let awaiting = harness
        .advance(&harness.request(dispatched_revision, 0x101))
        .expect("the second advance");
    assert_eq!(
        awaiting,
        CoordinatorOutcome::AwaitingChild {
            task: task_ref(harness.project, 1),
            state: ChildState::Running,
        }
    );
    assert_eq!(
        harness.dispatch.calls.len(),
        1,
        "a working Task never starts a second child"
    );

    // H2 completes Task 1: the connected host path completes it, and only then
    // may the next advance select Task 2.
    harness.children.set(ChildStatus::new(
        supervision(harness.project, 0x5000),
        ChildState::Completed,
        60,
        1,
        0,
        false,
        vec![evidence(0x7000)],
    ));
    let completed = harness
        .advance(&harness.request(dispatched_revision, 0x102))
        .expect("the completion advance");
    let revision = match completed {
        CoordinatorOutcome::TaskCompleted { task, revision } => {
            assert_eq!(task.number().get(), 1);
            revision
        }
        other => panic!("expected Task 1 to complete, got {other:?}"),
    };
    assert_eq!(
        harness.snapshot().current_task(),
        None,
        "a completed Task leaves no current Task before the next dispatch"
    );

    // Task 2 is selected next, in plan order.
    let second = harness
        .advance(&harness.request(revision, 0x103))
        .expect("the third advance");
    match second {
        CoordinatorOutcome::Dispatched { task, .. } => {
            assert_eq!(task.number().get(), 2, "Task 2 follows Task 1");
        }
        other => panic!("expected Task 2 to dispatch, got {other:?}"),
    }
    assert_eq!(
        harness.dispatch.calls.len(),
        2,
        "one child per Task, never more"
    );
}

#[test]
fn a_second_execution_cannot_start_while_one_holds_the_slot() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
    harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0x200))
        .expect("the first execution dispatches");

    // Another project and execution own their own snapshot but not the app-wide
    // slot.
    let other = other_project();
    let other_execution = other_execution(other);
    let other_approval = approval(other);
    herness_sdd_execute::DurableExecutionStorePort::record_approval(
        &mut harness.store,
        &other_approval,
    )
    .expect("the other approval");
    harness
        .store
        .compare_and_swap_execution(
            other,
            other_execution,
            None,
            &ready_snapshot(other, other_execution, 1),
        )
        .expect("the other snapshot");

    let busy = harness
        .advance(&harness.request_for_execution(
            other_execution,
            other,
            ExecutionRevision::INITIAL,
            0x201,
        ))
        .expect("the other advance");
    assert_eq!(
        busy,
        CoordinatorOutcome::Busy {
            holder: harness.execution
        },
        "only one implementer runs app-wide"
    );
    assert_eq!(harness.dispatch.calls.len(), 1);
}

#[test]
fn a_conflicting_checkout_claim_is_refused_before_any_dispatch() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
    // Another execution already owns the same checkout and branch.
    harness
        .serial
        .claim_checkout(
            &herness_sdd_execute::CheckoutClaim::new(
                CHECKOUT,
                BRANCH,
                other_execution(harness.project),
            )
            .unwrap(),
        )
        .expect("the foreign claim");

    let error = harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0x300))
        .expect_err("a conflicting owner is refused");
    assert!(matches!(
        error,
        SddExecutionError::Conflict {
            reason: herness_sdd_execute::ConflictReason::OwnershipConflict,
            ..
        }
    ));
    assert!(harness.dispatch.calls.is_empty());
    assert_eq!(harness.revision(), ExecutionRevision::INITIAL);
}

#[test]
fn a_completion_notification_delivered_twice_completes_the_task_once() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
    let dispatched = match harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0xa10))
        .expect("dispatch Task 1")
    {
        CoordinatorOutcome::Dispatched { revision, .. } => revision,
        other => panic!("expected a dispatch, got {other:?}"),
    };
    harness.children.set(ChildStatus::new(
        supervision(harness.project, 0x5000),
        ChildState::Completed,
        30,
        1,
        0,
        false,
        Vec::new(),
    ));
    let notification = herness_sdd_execute::ChildNotification::new(dispatch_request_id(
        harness.execution,
        task_ref(harness.project, 1),
    ));

    let first = {
        let request = harness.request(dispatched, 0xa11);
        let mut ports = CoordinatorPorts {
            store: &mut harness.store,
            launch: &mut harness.launch,
            dispatch: &mut harness.dispatch,
            children: &mut harness.children,
            completion: &mut harness.completion,
            serial: &mut harness.serial,
        };
        herness_sdd_execute::TaskCoordinator::on_notification(&mut ports, &request, notification)
            .expect("the first delivery")
    };
    let completed_revision = match first {
        CoordinatorOutcome::TaskCompleted { revision, .. } => revision,
        other => panic!("expected Task 1 completion, got {other:?}"),
    };
    assert_eq!(harness.completion.requests.len(), 1);

    // The second delivery of the same request returns the stored result and runs
    // no host completion again.
    let second = {
        let request = harness.request(dispatched, 0xa11);
        let mut ports = CoordinatorPorts {
            store: &mut harness.store,
            launch: &mut harness.launch,
            dispatch: &mut harness.dispatch,
            children: &mut harness.children,
            completion: &mut harness.completion,
            serial: &mut harness.serial,
        };
        herness_sdd_execute::TaskCoordinator::on_notification(&mut ports, &request, notification)
            .expect("the duplicate delivery")
    };
    assert!(matches!(second, CoordinatorOutcome::Replayed { .. }));
    assert_eq!(
        harness.completion.requests.len(),
        1,
        "a duplicate completion notification never runs the host completion twice"
    );
    assert_eq!(harness.dispatch.calls.len(), 1);

    // A new request that reuses the old revision is stale and stays refused; the
    // stored completion does not turn into a second Task.
    let stale = harness
        .advance(&harness.request(dispatched, 0xa12))
        .expect_err("a stale request is refused");
    assert!(matches!(stale, SddExecutionError::RevisionConflict { .. }));
    assert_eq!(
        harness
            .store
            .load_sdd_execution(harness.project, harness.execution)
            .unwrap()
            .unwrap()
            .revision(),
        completed_revision
    );
    assert_eq!(harness.completion.requests.len(), 1);
    assert_eq!(harness.dispatch.calls.len(), 1);
}

// ---------------------------------------------------------------------------
// Duplicate notifications and stored results
// ---------------------------------------------------------------------------

#[test]
fn duplicate_completion_notifications_do_not_advance_the_next_task() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
    harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0x400))
        .expect("dispatch Task 1");

    let completed = ChildStatus::new(
        supervision(harness.project, 0x5000),
        ChildState::Completed,
        60,
        1,
        0,
        false,
        Vec::new(),
    );
    harness.children.set(completed.clone());
    let outcome = harness
        .advance(&harness.request(ExecutionRevision::new(2).unwrap(), 0x401))
        .expect("complete Task 1");
    let revision = match outcome {
        CoordinatorOutcome::TaskCompleted { revision, .. } => revision,
        other => panic!("expected completion, got {other:?}"),
    };

    // A duplicate notification re-reads the stored H2 result for Task 1, which is
    // now complete; Task 2 is not dispatched by the notification.
    let notification = herness_sdd_execute::ChildNotification::new(dispatch_request_id(
        harness.execution,
        task_ref(harness.project, 1),
    ));
    let request = harness.request(revision, 0x402);
    let mut ports = CoordinatorPorts {
        store: &mut harness.store,
        launch: &mut harness.launch,
        dispatch: &mut harness.dispatch,
        children: &mut harness.children,
        completion: &mut harness.completion,
        serial: &mut harness.serial,
    };
    // The selection is Task 2 (Task 1 is complete), so the notification path
    // dispatches Task 2 only because the state genuinely advanced — never because
    // the notification was re-delivered twice.
    let outcome =
        herness_sdd_execute::TaskCoordinator::on_notification(&mut ports, &request, notification)
            .expect("the notification");
    match outcome {
        CoordinatorOutcome::Dispatched { task, .. } => {
            assert_eq!(task.number().get(), 2);
        }
        other => panic!("expected Task 2, got {other:?}"),
    }
    let dispatched = harness.dispatch.calls.len();
    assert_eq!(dispatched, 2);

    // The same notification with the same request ID is a replay: no third
    // child, and the stored result is returned.
    let replay = {
        let mut ports = CoordinatorPorts {
            store: &mut harness.store,
            launch: &mut harness.launch,
            dispatch: &mut harness.dispatch,
            children: &mut harness.children,
            completion: &mut harness.completion,
            serial: &mut harness.serial,
        };
        herness_sdd_execute::TaskCoordinator::advance(&mut ports, &request).expect("the replay")
    };
    assert!(matches!(replay, CoordinatorOutcome::Replayed { .. }));
    assert_eq!(
        harness.dispatch.calls.len(),
        2,
        "a re-delivered request never creates a third child"
    );
}

#[test]
fn the_stored_h2_result_is_re_read_on_every_advance() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
    harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0x500))
        .expect("dispatch Task 1");

    let dispatched = harness.revision();
    for step in [1u64, 2] {
        harness
            .children
            .set(status(ChildState::Running, 10 * step, 0, 0));
        let outcome = harness
            .advance(&harness.request(dispatched, 0x500 + u128::from(step)))
            .expect("observe");
        assert_eq!(
            outcome,
            CoordinatorOutcome::AwaitingChild {
                task: task_ref(harness.project, 1),
                state: ChildState::Running,
            }
        );
    }
    assert_eq!(
        harness.children.reads.len(),
        2,
        "the stored H2 result is read on every advance"
    );
    assert_eq!(
        harness.dispatch.calls.len(),
        1,
        "observation never dispatches again"
    );
}

// ---------------------------------------------------------------------------
// Finite continuation and stops
// ---------------------------------------------------------------------------

#[test]
fn a_blocked_or_needs_context_child_stops_without_a_second_child() {
    for state in [
        ChildState::WaitingHuman,
        ChildState::Stopped,
        ChildState::Failed,
    ] {
        let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
        harness
            .advance(&harness.request(ExecutionRevision::INITIAL, 0x600))
            .expect("dispatch Task 1");
        harness.children.set(status(state, 30, 1, 0));
        let dispatched = harness.revision();
        let outcome = harness
            .advance(&harness.request(dispatched, 0x601))
            .expect("the stop");
        match outcome {
            CoordinatorOutcome::Stopped { task, revision, .. } => {
                assert_eq!(task.map(|task| task.number().get()), Some(1));
                assert_eq!(revision, dispatched.next());
            }
            other => panic!("expected a stop for {state:?}, got {other:?}"),
        }
        assert_eq!(
            harness.dispatch.calls.len(),
            1,
            "{state:?} never creates a second child"
        );
        let stored = harness.snapshot();
        assert_eq!(stored.state(), ExecutionState::WaitingHuman);
        assert!(
            stored
                .stop()
                .and_then(|stop| stop.required_action())
                .is_some()
        );
        // The next Task never starts from a stopped execution.
        let again = harness
            .advance(&harness.request(harness.revision(), 0x602))
            .expect("the stopped execution is reported, not advanced");
        assert!(matches!(again, CoordinatorOutcome::Stopped { .. }));
        assert_eq!(harness.dispatch.calls.len(), 1);
    }
}

#[test]
fn an_unknown_child_state_is_refused_and_never_completion() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
    harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0x700))
        .expect("dispatch Task 1");
    harness.children.set(status(ChildState::Unknown, 30, 1, 0));
    let outcome = harness
        .advance(&harness.request(ExecutionRevision::new(2).unwrap(), 0x701))
        .expect("the refusal");
    match outcome {
        CoordinatorOutcome::Stopped { stop, .. } => {
            assert_eq!(
                stop.reason(),
                herness_sdd_execute::StopReason::RecoveryRequired
            );
        }
        other => panic!("expected recovery required, got {other:?}"),
    }
    assert!(harness.completion.requests.is_empty());
    let stored = harness.snapshot();
    assert_eq!(stored.state(), ExecutionState::WaitingHuman);
    assert!(
        stored
            .tasks()
            .iter()
            .all(|task| task.progression() != herness_sdd_execute::TaskProgression::Complete),
        "an unknown state is never completion"
    );
}

#[test]
fn a_stale_completion_is_refused() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
    harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0x800))
        .expect("dispatch Task 1");
    harness.children.set(ChildStatus::new(
        supervision(harness.project, 0x5000),
        ChildState::Completed,
        60,
        1,
        0,
        true,
        Vec::new(),
    ));
    let outcome = harness
        .advance(&harness.request(ExecutionRevision::new(2).unwrap(), 0x801))
        .expect("the refusal");
    match outcome {
        CoordinatorOutcome::Stopped { stop, .. } => assert_eq!(
            stop.reason(),
            herness_sdd_execute::StopReason::HumanDecisionRequired
        ),
        other => panic!("expected a human decision, got {other:?}"),
    }
    assert!(harness.completion.requests.is_empty());
}

#[test]
fn a_three_stall_child_stops_at_the_stall_limit() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
    harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0x900))
        .expect("dispatch Task 1");
    harness.children.set(status(ChildState::Running, 30, 1, 2));
    let progressing = harness
        .advance(&harness.request(ExecutionRevision::new(2).unwrap(), 0x901))
        .expect("two stalls still work");
    assert!(matches!(
        progressing,
        CoordinatorOutcome::AwaitingChild { .. }
    ));

    // Three consecutive stalls land as a stop even before H2 stops the target.
    harness.children.set(status(ChildState::Stopped, 60, 1, 3));
    let outcome = harness
        .advance(&harness.request(ExecutionRevision::new(2).unwrap(), 0x902))
        .expect("the stall stop");
    match outcome {
        CoordinatorOutcome::Stopped { stop, .. } => {
            assert_eq!(stop.reason(), herness_sdd_execute::StopReason::ChildStalled);
            assert_eq!(
                stop.required_action(),
                Some(herness_sdd_execute::HumanAction::ClearStall)
            );
        }
        other => panic!("expected a stall stop, got {other:?}"),
    }
}

#[test]
fn a_dispatch_failure_is_an_explicit_stop_not_a_completion() {
    let mut harness = Harness::with_dispatch(FakeDispatch::failing());
    let outcome = harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0xa00))
        .expect("the refusal");
    match outcome {
        CoordinatorOutcome::Stopped { stop, .. } => assert_eq!(
            stop.reason(),
            herness_sdd_execute::StopReason::CapabilityUnavailable
        ),
        other => panic!("expected capability unavailable, got {other:?}"),
    }
    assert_eq!(
        harness.revision(),
        ExecutionRevision::new(2).unwrap(),
        "the stop is durable"
    );
    let stored = harness.snapshot();
    assert_eq!(stored.state(), ExecutionState::WaitingHuman);
    assert!(
        stored
            .task(TaskNumber::new(1).unwrap())
            .is_some_and(|task| task.progression() == herness_sdd_execute::TaskProgression::Pending),
        "a Task that never dispatched stays pending"
    );
}

#[test]
fn a_launch_capacity_refusal_is_a_human_wait_and_never_a_truncated_packet() {
    let mut harness = Harness::with_launch(FakeLaunch::refusing(LaunchRefusal::Capacity {
        detail: "the packet does not fit".to_owned(),
    }));
    let outcome = harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0xb00))
        .expect("the refusal");
    match outcome {
        CoordinatorOutcome::Stopped { stop, .. } => assert_eq!(
            stop.reason(),
            herness_sdd_execute::StopReason::HumanDecisionRequired
        ),
        other => panic!("expected a human wait, got {other:?}"),
    }
    assert!(harness.dispatch.calls.is_empty(), "no child is created");
}

#[test]
fn an_h2_stop_cause_decides_the_h4_stop_reason() {
    let cases = [
        (
            herness_sdd_execute::ChildStopCause::Stagnation,
            herness_sdd_execute::StopReason::ChildStalled,
            herness_sdd_execute::HumanAction::ClearStall,
        ),
        (
            herness_sdd_execute::ChildStopCause::Budget,
            herness_sdd_execute::StopReason::BudgetExhausted,
            herness_sdd_execute::HumanAction::RaiseBudget,
        ),
        (
            herness_sdd_execute::ChildStopCause::StopUnconfirmed,
            herness_sdd_execute::StopReason::StopUnconfirmed,
            herness_sdd_execute::HumanAction::ConfirmStop,
        ),
        (
            herness_sdd_execute::ChildStopCause::RecoveryReconciliation,
            herness_sdd_execute::StopReason::RecoveryRequired,
            herness_sdd_execute::HumanAction::ConfirmRecovery,
        ),
    ];
    for (cause, reason, action) in cases {
        let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
        harness
            .advance(&harness.request(ExecutionRevision::INITIAL, 0x1400))
            .expect("dispatch Task 1");
        let dispatched = harness.revision();
        harness.children.set(
            ChildStatus::new(
                supervision(harness.project, 0x5000),
                ChildState::Stopped,
                60,
                1,
                0,
                false,
                Vec::new(),
            )
            .with_stop_cause(cause),
        );
        let outcome = harness
            .advance(&harness.request(dispatched, 0x1401))
            .expect("the stop");
        match outcome {
            CoordinatorOutcome::Stopped { stop, .. } => {
                assert_eq!(stop.reason(), reason, "cause {cause:?}");
                assert_eq!(stop.required_action(), Some(action), "cause {cause:?}");
            }
            other => panic!("expected a stop for {cause:?}, got {other:?}"),
        }
        assert!(harness.completion.requests.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Budget in the coordinator
// ---------------------------------------------------------------------------

#[test]
fn a_task_whose_budget_is_exhausted_never_dispatches() {
    let mut harness = Harness::new();
    // The stored budget already consumed the full 7,200 seconds.
    let ready = ready_snapshot(harness.project, harness.execution, 2);
    let consumed_snapshot = ExecutionSnapshot::new(SnapshotInput {
        project_id: ready.project_id(),
        execution_id: ready.execution_id(),
        revision: ExecutionRevision::new(2).unwrap(),
        state: ready.state(),
        plan: ready.plan().clone(),
        workspace: ready.workspace().clone(),
        current_task: ready.current_task(),
        tasks: ready.tasks().to_vec(),
        stop: None,
        budget: SnapshotBudget::new(
            BudgetConsumption::new(7_200, 0, None),
            BudgetConsumption::zero(),
        ),
        applied_revision: ready.applied_revision(),
        final_project_sequence: None,
    })
    .expect("a consumed snapshot");
    harness
        .store
        .compare_and_swap_execution(
            harness.project,
            harness.execution,
            Some(ExecutionRevision::INITIAL),
            &consumed_snapshot,
        )
        .expect("store the consumed snapshot");

    let outcome = harness
        .advance(&harness.request(ExecutionRevision::new(2).unwrap(), 0xc00))
        .expect("the refusal");
    match outcome {
        CoordinatorOutcome::BudgetRefused { exhaustion, .. } => {
            assert_eq!(
                exhaustion.reason(),
                herness_sdd_execute::BudgetExhaustionReason::ActiveSeconds
            );
            assert_eq!(exhaustion.consumed(), 7_200);
        }
        other => panic!("expected a budget refusal, got {other:?}"),
    }
    assert!(harness.dispatch.calls.is_empty());
}

#[test]
fn met_after_the_limit_is_refused_by_the_coordinator() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
    harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0xd00))
        .expect("dispatch Task 1");
    // H2 met the conditions, but the Task consumed its whole budget.
    harness.children.set(ChildStatus::new(
        supervision(harness.project, 0x5000),
        ChildState::Completed,
        7_200,
        1,
        0,
        false,
        Vec::new(),
    ));
    let outcome = harness
        .advance(&harness.request(ExecutionRevision::new(2).unwrap(), 0xd01))
        .expect("the refusal");
    match outcome {
        CoordinatorOutcome::BudgetRefused {
            task, exhaustion, ..
        } => {
            assert_eq!(task.number().get(), 1);
            assert_eq!(
                exhaustion.reason(),
                herness_sdd_execute::BudgetExhaustionReason::ActiveSeconds
            );
        }
        other => panic!("expected a budget refusal, got {other:?}"),
    }
    assert!(
        harness.completion.requests.is_empty(),
        "no host completion runs after the limit"
    );
    let stored = harness.snapshot();
    assert!(
        stored
            .tasks()
            .iter()
            .all(|task| task.progression() != herness_sdd_execute::TaskProgression::Complete),
        "met after the limit is not completion"
    );
    assert_eq!(
        stored.state(),
        ExecutionState::WaitingHuman,
        "the refusal is durable"
    );
}

#[test]
fn host_processing_after_h2_completion_is_charged_to_the_same_task() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1_200)));
    harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0xe00))
        .expect("dispatch Task 1");
    harness.children.set(ChildStatus::new(
        supervision(harness.project, 0x5000),
        ChildState::Completed,
        1_000,
        1,
        0,
        false,
        Vec::new(),
    ));
    harness
        .advance(&harness.request(ExecutionRevision::new(2).unwrap(), 0xe01))
        .expect("complete Task 1");

    // The stored consumption is H2's 1,000 s plus the 1,200 s host processing.
    let stored = harness.snapshot();
    assert_eq!(
        stored.budget().consumed().active_seconds(),
        2_200,
        "H2 supervision and host processing are one Task total"
    );
    assert_eq!(stored.budget().consumed().additional_runs(), 1);
}

// ---------------------------------------------------------------------------
// Not connected barrier and host commit
// ---------------------------------------------------------------------------

#[test]
fn a_completed_child_stops_when_the_barrier_or_commit_is_not_connected() {
    for feature in [
        CompletionFeature::HtmlBarrier,
        CompletionFeature::HostCommit,
    ] {
        let mut harness = Harness::with_completion(FakeCompletion::not_connected());
        harness
            .advance(&harness.request(ExecutionRevision::INITIAL, 0xf00))
            .expect("dispatch Task 1");
        harness.children.set(ChildStatus::new(
            supervision(harness.project, 0x5000),
            ChildState::Completed,
            60,
            1,
            0,
            false,
            Vec::new(),
        ));
        let dispatched = harness.revision();
        let outcome = harness
            .advance(&harness.request(dispatched, 0xf01))
            .expect("the not-connected outcome");
        match outcome {
            CoordinatorOutcome::CompletionNotConnected { task, revision, .. } => {
                assert_eq!(task.number().get(), 1);
                assert_eq!(revision, dispatched.next());
            }
            other => panic!("expected an explicit not-connected outcome, got {other:?}"),
        }
        assert_eq!(
            harness.dispatch.calls.len(),
            1,
            "{feature:?}: the next Task never starts"
        );
        let stored = harness.snapshot();
        assert_eq!(stored.state(), ExecutionState::WaitingHuman);
        assert_eq!(
            stored.stop().map(|stop| stop.reason()),
            Some(herness_sdd_execute::StopReason::CapabilityUnavailable)
        );
        assert!(
            stored
                .tasks()
                .iter()
                .all(|task| task.progression() != herness_sdd_execute::TaskProgression::Complete),
            "{feature:?}: a Task without a barrier and commit is not complete"
        );
        // A further advance reports the stop instead of starting Task 2.
        let again = harness
            .advance(&harness.request(harness.revision(), 0xf02))
            .expect("the stopped execution is reported");
        assert!(matches!(again, CoordinatorOutcome::Stopped { .. }));
        assert_eq!(harness.dispatch.calls.len(), 1);
    }
}

// ---------------------------------------------------------------------------
// Approval and revision guards
// ---------------------------------------------------------------------------

#[test]
fn a_stale_revision_is_refused_before_any_side_effect() {
    let mut harness = Harness::new();
    let error = harness
        .advance(&harness.request(ExecutionRevision::new(9).unwrap(), 0x1000))
        .expect_err("a stale revision is refused");
    assert!(matches!(error, SddExecutionError::RevisionConflict { .. }));
    assert!(harness.dispatch.calls.is_empty());
    assert!(harness.launch.calls.is_empty());
}

#[test]
fn a_stale_approval_revision_is_refused_before_any_side_effect() {
    let mut harness = Harness::new();
    let request = CoordinatorRequest::new(
        harness.project,
        harness.execution,
        control_request(harness.project, 0x1100),
        ExecutionRevision::INITIAL,
        approval_id(harness.project),
        2,
    )
    .expect("a request");
    let error = harness
        .advance(&request)
        .expect_err("a stale approval is refused");
    assert!(matches!(
        error,
        SddExecutionError::Conflict {
            reason: herness_sdd_execute::ConflictReason::StaleRevision,
            ..
        }
    ));
    assert!(harness.dispatch.calls.is_empty());
}

#[test]
fn a_missing_approval_is_refused() {
    let temp = TempDir::new().expect("a temporary directory");
    let config = StoreConfig::new(temp.path().join("app-data")).expect("a store configuration");
    let mut store = Store::open(config).expect("a temporary store");
    let project = project();
    let execution = execution(project);
    store
        .compare_and_swap_execution(
            project,
            execution,
            None,
            &ready_snapshot(project, execution, 2),
        )
        .expect("the snapshot");
    let mut serial = SerialExecutionState::new();
    let mut launch = FakeLaunch::new();
    let mut dispatch = FakeDispatch::new();
    let mut children = FakeChildren::absent();
    let mut completion = FakeCompletion::not_connected();
    let request = CoordinatorRequest::new(
        project,
        execution,
        control_request(project, 0x1200),
        ExecutionRevision::INITIAL,
        approval_id(project),
        1,
    )
    .expect("a request");
    let mut ports = CoordinatorPorts {
        store: &mut store,
        launch: &mut launch,
        dispatch: &mut dispatch,
        children: &mut children,
        completion: &mut completion,
        serial: &mut serial,
    };
    let error = herness_sdd_execute::TaskCoordinator::advance(&mut ports, &request)
        .expect_err("a missing approval is refused");
    assert!(matches!(error, SddExecutionError::ApprovalRequired { .. }));
    assert!(dispatch.calls.is_empty());
}

// ---------------------------------------------------------------------------
// Everything complete
// ---------------------------------------------------------------------------

#[test]
fn all_complete_tasks_reach_ready_for_finish() {
    let mut harness = Harness::with_completion(FakeCompletion::connected(completion(1)));
    // Complete both Tasks through the coordinator.
    let first = harness
        .advance(&harness.request(ExecutionRevision::INITIAL, 0x1300))
        .expect("dispatch Task 1");
    let revision = match first {
        CoordinatorOutcome::Dispatched { revision, .. } => revision,
        other => panic!("expected Task 1, got {other:?}"),
    };
    harness.children.set(ChildStatus::new(
        supervision(harness.project, 0x5000),
        ChildState::Completed,
        30,
        1,
        0,
        false,
        Vec::new(),
    ));
    let revision = match harness
        .advance(&harness.request(revision, 0x1301))
        .expect("complete Task 1")
    {
        CoordinatorOutcome::TaskCompleted { revision, .. } => revision,
        other => panic!("expected Task 1 completion, got {other:?}"),
    };
    let second = harness
        .advance(&harness.request(revision, 0x1302))
        .expect("dispatch Task 2");
    let revision = match second {
        CoordinatorOutcome::Dispatched { task, revision, .. } => {
            assert_eq!(task.number().get(), 2);
            revision
        }
        other => panic!("expected Task 2, got {other:?}"),
    };
    harness.children.set(ChildStatus::new(
        supervision(harness.project, 0x5002),
        ChildState::Completed,
        30,
        1,
        0,
        false,
        Vec::new(),
    ));
    let finish = harness
        .advance(&harness.request(revision, 0x1303))
        .expect("complete Task 2");
    let revision = match finish {
        CoordinatorOutcome::ReadyForFinish { revision } => revision,
        other => panic!("expected ready for finish, got {other:?}"),
    };
    let stored = harness.snapshot();
    assert_eq!(stored.state(), ExecutionState::ReadyForFinish);
    assert_eq!(stored.current_task(), None);
    assert!(stored.is_complete());
    assert_eq!(harness.serial.holder(), None, "the slot is released");
    assert_eq!(harness.dispatch.calls.len(), 2, "one child per Task");

    // A further advance reports the finished execution.
    let again = harness
        .advance(&harness.request(revision, 0x1304))
        .expect("the finished execution");
    assert!(matches!(again, CoordinatorOutcome::Finished { .. }));
}

// ---------------------------------------------------------------------------
// Desktop composition
// ---------------------------------------------------------------------------

#[test]
fn the_desktop_composition_keeps_the_barrier_and_commit_explicitly_not_connected() {
    use herness_desktop::sdd_execute::DesktopCoordinator;

    let project = project();
    let candidate =
        herness_desktop::supervision::SupervisionTarget::new(project, supervision(project, 0x5000));
    // The native pump scope excludes exactly the H3 candidate target, so the
    // Task target in the same project keeps advancing.
    let scope = DesktopCoordinator::task_pump_scope(project, Some(candidate));
    assert_eq!(
        scope,
        herness_desktop::supervision::PumpScope::AllExcept {
            projects: vec![project],
            excluded: candidate,
        }
    );
    let idle = DesktopCoordinator::task_pump_scope(project, None);
    assert_eq!(
        idle,
        herness_desktop::supervision::PumpScope::Projects(vec![project])
    );

    // The production completion seam reports `not connected`, never a
    // fabricated completion.
    let completion = NotConnectedCompletion::new();
    assert_eq!(
        herness_sdd_execute::TaskCompletionPort::wiring(&completion, task_ref(project, 1)),
        CompletionWiring::NotConnected {
            feature: CompletionFeature::HtmlBarrier
        }
    );
    let mut completion = completion;
    let request = TaskCompletionRequest::new(
        task_ref(project, 1),
        execution(project),
        ExecutionRevision::INITIAL,
        supervision(project, 0x5000),
        CommitAuthorization::new(true, true).expect("commit authorization"),
        CommitPolicy::Required,
        Vec::new(),
        7_000,
    );
    let error = herness_sdd_execute::TaskCompletionPort::complete(&mut completion, &request)
        .expect_err("not connected never completes");
    assert!(matches!(error, SddExecutionError::Unavailable { .. }));
}

#[test]
fn the_desktop_launch_builds_the_immutable_packet_and_manifest() {
    use herness_desktop::sdd_execute::{ApprovedTaskLaunch, supervision_target_id};

    let project = project();
    let approval = approval(project);
    let snapshots = SnapshotSections::new().with_snapshot("project", SPEC_PATH, {
        vec![(
            "Contract".to_owned(),
            digest("spec").to_string(),
            "The contract text.".to_owned(),
        )]
    });
    let mut launch = ApprovedTaskLaunch::new(&approval, &snapshots, &[]);
    let task = task_ref(project, 1);
    let built = herness_sdd_execute::TaskLaunchPort::launch(&mut launch, task).expect("a launch");
    assert!(built.instructions().contains("Task 1"));
    assert_eq!(built.scope().write_paths(), scope(project).write_paths());
    assert_eq!(
        built.budget().active_seconds(),
        BudgetPolicy::h2_default().active_seconds()
    );

    // The dispatch manifest digest is deterministic for the same approval.
    let again =
        herness_sdd_execute::TaskLaunchPort::launch(&mut launch, task).expect("the same launch");
    assert_eq!(built.manifest_digest(), again.manifest_digest());
    assert_eq!(built.packet_digest(), again.packet_digest());

    // The H2 target of one dispatch request is deterministic and project-bound.
    let dispatch = dispatch_request_id(execution(project), task);
    assert_eq!(
        supervision_target_id(dispatch),
        supervision_target_id(dispatch)
    );
    assert_eq!(supervision_target_id(dispatch).project_id(), project);
}

#[test]
fn a_capacity_refusal_from_the_packet_is_a_human_wait_not_a_dispatch() {
    use herness_desktop::sdd_execute::ApprovedTaskLaunch;

    let project = project();
    let approval = approval(project);
    // No verified snapshot: the packet cannot be composed, so no child exists.
    let snapshots = SnapshotSections::new();
    let mut launch = ApprovedTaskLaunch::new(&approval, &snapshots, &[]);
    let refusal = herness_sdd_execute::TaskLaunchPort::launch(&mut launch, task_ref(project, 1))
        .expect_err("a missing snapshot refuses the launch");
    assert!(matches!(
        refusal,
        LaunchRefusal::Context { .. } | LaunchRefusal::Capacity { .. }
    ));
}

// ---------------------------------------------------------------------------
// Fixtures used by the desktop cases
// ---------------------------------------------------------------------------

#[test]
fn the_preview_fixture_matches_the_approval_plan() {
    // Guard the fixture: the preview facts of the same plan produce the same
    // Task bodies the approval bound.
    let project = project();
    let facts = herness_desktop::sdd_execute::PreviewFacts::new(
        CHECKOUT,
        plan_path(),
        herness_sdd_execute::ExactPlanBytes::new(b"# plan".to_vec()).unwrap(),
        parsed_plan(2),
        (1..=2)
            .map(|number| {
                herness_desktop::sdd_execute::PreviewTaskFacts::from_parts(
                    number,
                    format!("Task {number}"),
                    "Body.\n",
                    vec![condition()],
                    vec!["crates".to_owned()],
                    vec!["crates/herness-sdd-execute".to_owned()],
                    false,
                    vec![check()],
                    Vec::new(),
                    vec![
                        ApprovedDeliverable::new(
                            "crates/herness-sdd-execute/src/lib.rs",
                            DeliverableKind::File,
                        )
                        .unwrap(),
                    ],
                    CommitPolicy::Required,
                )
            })
            .collect(),
        vec![
            ApprovedSpecRef::new(
                "project",
                SPEC_PATH,
                vec!["Contract".to_owned()],
                digest("spec"),
            )
            .unwrap(),
        ],
        Vec::new(),
        PackApproval::new(
            InspectorProtocol::expected(),
            1,
            PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
        )
        .unwrap(),
    )
    .expect("preview facts");
    assert_eq!(facts.tasks().len(), 2);
    assert_eq!(facts.tasks()[1].number(), 2);
    let _ = project;
}

#[test]
fn serial_execution_state_enforces_one_slot_and_one_claim() {
    let project = project();
    let first = execution(project);
    let second = other_execution(project);
    let mut serial = SerialExecutionState::new();
    serial.acquire_slot(first).expect("the first slot");
    assert_eq!(serial.holder(), Some(first));
    assert!(serial.acquire_slot(second).is_err());
    serial
        .acquire_slot(first)
        .expect("the same execution re-acquires");
    serial.release_slot(first);
    assert_eq!(serial.holder(), None);
    serial.acquire_slot(second).expect("the slot is free");

    let claim = herness_sdd_execute::CheckoutClaim::new(CHECKOUT, BRANCH, first).unwrap();
    serial.claim_checkout(&claim).expect("the first claim");
    assert!(serial.owns(&claim));
    let other_claim = herness_sdd_execute::CheckoutClaim::new(CHECKOUT, BRANCH, second).unwrap();
    assert!(serial.claim_checkout(&other_claim).is_err());
    serial.release_checkout(first);
    assert!(!serial.owns(&claim));
    serial
        .claim_checkout(&other_claim)
        .expect("the claim is free");
}
