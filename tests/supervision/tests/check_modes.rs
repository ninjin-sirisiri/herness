//! Condition modes, approved check execution, and evidence reuse.
//!
//! Every provider/assessment boundary is a local fake. Required checks run as
//! real local shell commands inside a real temporary project directory; no
//! network, credential, or production endpoint is used. The durable store is a
//! temporary SQLite database.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use herness_core::contracts::{
    AgentId, InputId, InputPhase, InputProgress, ProjectId, RunId, RunState, SessionId,
};
use herness_core::permissions::{
    MatchMethod, PermissionMode, PermissionPolicy, PolicyAdmin, RuleTarget, SharedPolicy,
};
use herness_core::tools::ToolName;
use herness_desktop::supervision::checks::{
    HostCheckPort, effective_check_timeout_ms, resolve_check_cwd,
};
use herness_desktop::supervision::plan::{
    BudgetSnapshot, PLAN_FORMAT_VERSION, RequestActor, StoredPlan, decode_plan,
};
use herness_desktop::supervision::runtime::ChildIdentity;
use herness_desktop::supervision::store::{HostBudgetClock, HostClock, StoreHandle};
use herness_desktop::supervision::workspace::ProjectWorkspace;
use herness_store::{Store, StoreConfig};
use herness_supervision::assessment::{AssessmentRequest, AssessmentResult, ConditionVerdict};
use herness_supervision::budget::BudgetPolicy;
use herness_supervision::budget::ledger::BudgetLedger;
use herness_supervision::conditions::{
    Condition, ConditionMode, ConditionOrigin, ConditionSet, ConditionVersion, RequiredCheck,
};
use herness_supervision::evidence::{
    CheckInvocation, CheckStatus, EvidenceAcquirer, EvidenceInvocation, EvidenceOutcome,
    EvidenceRecord, EvidenceScope,
};
use herness_supervision::freshness::{TargetReadSet, capture_manifest, input_manifest_digest};
use herness_supervision::ids::{CheckId, ConditionId, SupervisionId, SupervisionRequestId};
use herness_supervision::ports::{EvidenceStorePort, SupervisionStorePort};
use herness_supervision::profiles::ProfileUnavailable;
use herness_supervision::state::{SupervisionRecord, SupervisionState};
use herness_supervision::supervisor::{
    AssessmentProfileFacts, CheckExecution, CheckExecutionRequest, ChildRunContinuation,
    ChildRunStart, ConditionAssessmentPort, OwnerNotificationPort, RequiredCheckPort,
    StopDisposition, SupervisionRuntimePort, Supervisor, SupervisorNotification, SupervisorPorts,
    TargetSnapshotRequest, TickOutcome, TickReport, TickRequest, capture_target_snapshot,
};
use herness_supervision::{
    ApprovalActor, ApprovalBasis, ConditionApproval, EvidenceId, ExecutionScope, OwnerKind,
    OwnerRef, ProfileBinding, SupervisionError, SupervisionSubject, TargetVersion,
    VerificationOperation,
};
use herness_supervision_tests::{completion_profile, consent, now, work_packet};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Real project and store
// ---------------------------------------------------------------------------

struct TestProject {
    _temp: TempDir,
    root: PathBuf,
    external: PathBuf,
    project: ProjectId,
    supervision: SupervisionId,
    store: StoreHandle,
}

impl TestProject {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let root = temp.path().join("project");
        let external = temp.path().join("outside");
        std::fs::create_dir_all(root.join("src")).expect("src");
        std::fs::create_dir_all(root.join("sub")).expect("sub");
        std::fs::create_dir_all(&external).expect("outside");
        std::fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").expect("source");
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"fixture\"\n")
            .expect("manifest");
        std::fs::write(root.join("sub/marker.txt"), "marker\n").expect("marker");
        let project = ProjectId::new();
        let supervision = SupervisionId::new(project);
        let config = StoreConfig::new(temp.path().join("state")).expect("store config");
        let store = Store::open(config).expect("store");
        let store = StoreHandle::new(Arc::new(Mutex::new(store)));
        Self {
            _temp: temp,
            root,
            external,
            project,
            supervision,
            store,
        }
    }

    fn log(&self) -> PathBuf {
        self._temp.path().join("executions.log")
    }

    fn log_count(&self) -> usize {
        std::fs::read_to_string(self.log())
            .map(|text| text.matches('x').count())
            .unwrap_or(0)
    }

    fn command_that_logs(&self) -> String {
        format!("printf x >> '{}'", self.log().display())
    }
}

/// Builds an approved contract over the real project contents.
fn contract_with(
    project: &TestProject,
    conditions: ConditionSet,
    read_set: Vec<String>,
) -> herness_supervision::SupervisionContract {
    let workspace = ProjectWorkspace::new(project.root.clone());
    let manifest = capture_manifest(
        &workspace,
        project.project,
        TargetVersion::new(1).expect("target version"),
        TargetReadSet::Declared(read_set.clone()),
    )
    .expect("manifest");
    let target = manifest.target_scope().expect("target scope");
    let execution =
        ExecutionScope::new(project.project, read_set, Vec::new(), true).expect("execution scope");
    let profile = completion_profile(project.project);
    let consent = consent(
        project.project,
        herness_supervision::ProfilePurpose::Completion,
        1,
    );
    let budget = BudgetPolicy::h2_default();
    let packet = work_packet(
        project.project,
        &target,
        &execution,
        conditions.condition_version(),
        &profile,
        &consent,
        &budget,
        "condition mode fixture instruction",
    );
    let subject = SupervisionSubject::new(
        project.project,
        project.supervision,
        AgentId::new(project.project),
        SessionId::new(project.project),
        OwnerRef::new(OwnerKind::Human, "check-modes-fixture").expect("owner"),
    )
    .expect("subject");
    herness_supervision::SupervisionContract::new(
        ApprovalActor::Human,
        subject,
        execution,
        herness_supervision::RunGroup::new(herness_supervision::RunGroupId::new(project.project)),
        conditions,
        target,
        &profile,
        &consent,
        budget,
        packet,
        now(),
    )
    .expect("contract")
}

struct ConditionSpec {
    title: &'static str,
    mode: ConditionMode,
    checks: Vec<CheckSpec>,
}

struct CheckSpec {
    command: String,
    cwd: String,
    timeout_seconds: u64,
    input_paths: Vec<String>,
}

fn approved_conditions(project: ProjectId, specs: Vec<ConditionSpec>) -> ConditionSet {
    let mut conditions = Vec::new();
    let mut checks = Vec::new();
    for spec in specs {
        let condition_id = ConditionId::new(project);
        let mut check_ids = Vec::new();
        for check in spec.checks {
            let check_id = CheckId::new(project);
            checks.push(
                RequiredCheck::new(
                    check_id,
                    condition_id,
                    VerificationOperation::command(&check.command).expect("command"),
                    CheckInvocation::new(&check.cwd, check.timeout_seconds, check.input_paths)
                        .expect("invocation"),
                    "approved check",
                )
                .expect("required check"),
            );
            check_ids.push(check_id);
        }
        conditions.push(
            Condition::new(
                condition_id,
                spec.title,
                "The approved rubric text.",
                spec.mode,
                check_ids,
                ConditionOrigin::Human,
            )
            .expect("condition"),
        );
    }
    let mut set = ConditionSet::new(
        project,
        ConditionVersion::new(1).expect("version"),
        conditions,
        checks,
    )
    .expect("condition set");
    let approval = ConditionApproval::new(
        project,
        ApprovalBasis::ExplicitHuman {
            approved_at: now(),
            expires_at: None,
        },
        set.condition_version(),
        set.digest().clone(),
    )
    .expect("approval");
    set.approve(ApprovalActor::Human, approval, now())
        .expect("approve");
    set
}

// ---------------------------------------------------------------------------
// Check execution through the real host port
// ---------------------------------------------------------------------------

fn check_policy() -> SharedPolicy {
    let shared = SharedPolicy::new(PermissionPolicy::initial());
    let mut admin = PolicyAdmin::from_shared(shared.clone());
    admin
        .add_rule(
            herness_core::permissions::PermissionRule::allow(
                RuleTarget::Tool {
                    tool: ToolName::Bash,
                },
                MatchMethod::AnyInvocation,
            )
            .expect("rule"),
        )
        .expect("add rule");
    assert_eq!(shared.snapshot().mode(), PermissionMode::Configured);
    shared
}

fn host_check_port(project: &TestProject) -> HostCheckPort {
    HostCheckPort::new(
        project.store.clone(),
        AgentId::new(project.project),
        SessionId::new(project.project),
        project.root.clone(),
        check_policy(),
        "condition mode fixture check",
    )
}

fn save_record_with_run(
    project: &TestProject,
    contract: &herness_supervision::SupervisionContract,
) {
    let mut record = SupervisionRecord::new(contract);
    let run = RunId::new(project.project);
    record.begin_run(run).expect("begin run");
    let mut store = project.store.clone();
    store
        .compare_and_swap(project.project, project.supervision, None, &record)
        .expect("save record");
}

fn check_request(
    project: &TestProject,
    condition_id: ConditionId,
    check_id: CheckId,
    command: &str,
    invocation: CheckInvocation,
    remaining_seconds: u64,
    sequence: u64,
    read_set: Vec<String>,
) -> CheckExecutionRequest {
    CheckExecutionRequest::new(
        project.project,
        project.supervision,
        condition_id,
        check_id,
        ConditionVersion::new(1).expect("version"),
        TargetVersion::new(1).expect("version"),
        EvidenceId::new(project.project),
        sequence,
        VerificationOperation::command(command).expect("command"),
        invocation,
        remaining_seconds,
        read_set,
    )
}

fn execute_check(project: &TestProject, request: &CheckExecutionRequest) -> CheckExecution {
    host_check_port(project)
        .execute(request)
        .expect("check executes")
}

// ---------------------------------------------------------------------------
// Supervisor runtime and assessment fakes
// ---------------------------------------------------------------------------

struct FakeRuntime {
    project: ProjectId,
    root: PathBuf,
    starts: usize,
}

impl SupervisionRuntimePort for FakeRuntime {
    fn start_child(&mut self, _request: &ChildRunStart) -> Result<(), SupervisionError> {
        self.starts += 1;
        Ok(())
    }

    fn continue_child(&mut self, _request: &ChildRunContinuation) -> Result<(), SupervisionError> {
        Ok(())
    }

    fn input_progress(&mut self, input_id: InputId) -> Result<InputProgress, SupervisionError> {
        Ok(InputProgress::new(input_id, InputPhase::Completed))
    }

    fn run_state(&mut self, _run_id: RunId) -> Result<RunState, SupervisionError> {
        Ok(RunState::Idle)
    }

    fn request_stop(&mut self, _run_id: RunId) -> Result<StopDisposition, SupervisionError> {
        Ok(StopDisposition::Confirmed)
    }

    fn target_snapshot(
        &mut self,
        request: &TargetSnapshotRequest,
    ) -> Result<herness_supervision::TargetManifest, SupervisionError> {
        assert_eq!(request.project_id(), self.project);
        let workspace = ProjectWorkspace::new(self.root.clone());
        capture_target_snapshot(&workspace, request)
    }
}

struct FakeAssessment {
    profile: herness_supervision::AssessmentProfile,
    calls: Vec<AssessmentRequest>,
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
        Ok(herness_supervision_tests::assessment_result(
            request,
            ConditionVerdict::Met,
            request.evidence().to_vec(),
        ))
    }
}

#[derive(Default)]
struct RecordingNotifier {
    notifications: Rc<RefCell<Vec<SupervisorNotification>>>,
}

impl OwnerNotificationPort for RecordingNotifier {
    fn notify(&mut self, notification: &SupervisorNotification) -> Result<(), SupervisionError> {
        self.notifications.borrow_mut().push(notification.clone());
        Ok(())
    }
}

struct Harness {
    project: TestProject,
    contract: herness_supervision::SupervisionContract,
    record: SupervisionRecord,
    runtime: FakeRuntime,
    assessment: FakeAssessment,
    budget: BudgetLedger<StoreHandle, HostBudgetClock>,
    notifier: RecordingNotifier,
    tick: u64,
}

impl Harness {
    fn new(project: TestProject, conditions: ConditionSet, read_set: Vec<String>) -> Self {
        let contract = contract_with(&project, conditions, read_set);
        let record = SupervisionRecord::new(&contract);
        let mut store = project.store.clone();
        store
            .compare_and_swap(project.project, project.supervision, None, &record)
            .expect("save record");
        let runtime = FakeRuntime {
            project: project.project,
            root: project.root.clone(),
            starts: 0,
        };
        let assessment = FakeAssessment {
            profile: completion_profile(project.project),
            calls: Vec::new(),
        };
        let budget = BudgetLedger::open(
            project.store.clone(),
            project.project,
            project.supervision,
            contract.budget().clone(),
            1,
            HostBudgetClock::new(),
        )
        .expect("budget ledger");
        Self {
            project,
            contract,
            record,
            runtime,
            assessment,
            budget,
            notifier: RecordingNotifier::default(),
            tick: 0,
        }
    }

    fn tick_once(&mut self) -> TickReport {
        self.tick = self.tick.saturating_add(1);
        let event = SupervisionRequestId::new(self.project.project);
        let request = TickRequest::new(event, self.contract.clone()).expect("tick request");
        let mut checks = host_check_port(&self.project);
        let mut store = self.project.store.clone();
        let mut evidence = self.project.store.clone();
        let clock = HostClock;
        let report = Supervisor::new(SupervisorPorts {
            runtime: &mut self.runtime,
            checks: &mut checks,
            assessment: &mut self.assessment,
            readiness: None,
            evidence: &mut evidence,
            store: &mut store,
            budget: &mut self.budget,
            clock: &clock,
            notifications: &mut self.notifier,
        })
        .tick(request)
        .expect("tick");
        self.record = self
            .project
            .store
            .load(self.project.project, self.project.supervision)
            .expect("load")
            .expect("record");
        report
    }

    fn drive_until_blocked(&mut self) -> TickReport {
        let mut last = self.tick_once();
        for _ in 0..80 {
            if matches!(
                self.record.state(),
                SupervisionState::Completed
                    | SupervisionState::Stopped
                    | SupervisionState::WaitingHuman
                    | SupervisionState::Failed
                    | SupervisionState::Cancelled
            ) {
                return last;
            }
            last = self.tick_once();
        }
        panic!("supervision did not block: {:?}", self.record.state());
    }

    fn evidence(&self) -> Vec<EvidenceRecord> {
        self.project
            .store
            .list_for_supervision(self.project.project, self.project.supervision)
            .expect("evidence list")
    }
}

// ---------------------------------------------------------------------------
// Checks mode
// ---------------------------------------------------------------------------

#[test]
fn checks_mode_completes_from_checks_only_with_zero_assessment_requests() {
    let project = TestProject::new();
    let command = project.command_that_logs();
    let conditions = approved_conditions(
        project.project,
        vec![ConditionSpec {
            title: "mode: checks",
            mode: ConditionMode::Checks,
            checks: vec![
                CheckSpec {
                    command: command.clone(),
                    cwd: ".".to_owned(),
                    timeout_seconds: 30,
                    input_paths: vec!["src/lib.rs".to_owned()],
                },
                CheckSpec {
                    command,
                    cwd: "sub".to_owned(),
                    timeout_seconds: 30,
                    input_paths: vec!["sub/marker.txt".to_owned()],
                },
            ],
        }],
    );
    let read_set = vec![
        "src/lib.rs".to_owned(),
        "sub/marker.txt".to_owned(),
        "Cargo.toml".to_owned(),
    ];
    let mut harness = Harness::new(project, conditions, read_set);
    let report = harness.drive_until_blocked();

    assert_eq!(report.outcome(), TickOutcome::Completed);
    assert_eq!(harness.record.state(), SupervisionState::Completed);
    assert!(
        harness.assessment.calls.is_empty(),
        "a checks-mode condition must not request a model assessment"
    );
    assert_eq!(
        harness.project.log_count(),
        2,
        "each approved check must run exactly once"
    );
    assert!(harness.record.unmet_conditions().is_empty());

    let evidence = harness.evidence();
    let check_evidence = evidence
        .iter()
        .filter(|item| item.check_id().is_some())
        .collect::<Vec<_>>();
    assert_eq!(check_evidence.len(), 2);
    for item in check_evidence {
        assert_eq!(
            item.acquirer(),
            EvidenceAcquirer::Host,
            "the host ran the check; the child did not"
        );
        let invocation = item.invocation().expect("recorded invocation");
        assert!(invocation.invocation().timeout_seconds() == 30);
        assert!(item.status() == CheckStatus::Pass);
    }
}

#[test]
fn checks_mode_any_failure_or_timeout_is_not_met_and_requests_no_assessment() {
    let project = TestProject::new();
    let conditions = approved_conditions(
        project.project,
        vec![ConditionSpec {
            title: "mode: checks failing",
            mode: ConditionMode::Checks,
            checks: vec![
                CheckSpec {
                    command: "exit 1".to_owned(),
                    cwd: ".".to_owned(),
                    timeout_seconds: 10,
                    input_paths: Vec::new(),
                },
                CheckSpec {
                    command: "sleep 2".to_owned(),
                    cwd: ".".to_owned(),
                    timeout_seconds: 1,
                    input_paths: Vec::new(),
                },
            ],
        }],
    );
    let read_set = vec!["src/lib.rs".to_owned(), "Cargo.toml".to_owned()];
    let mut harness = Harness::new(project, conditions, read_set);
    harness.drive_until_blocked();

    assert_ne!(harness.record.state(), SupervisionState::Completed);
    assert!(
        harness.assessment.calls.is_empty(),
        "a failing checks-mode condition must not fall back to a model assessment"
    );
    assert!(
        !harness.record.unmet_conditions().is_empty(),
        "the condition must stay unmet"
    );
    let statuses = harness
        .record
        .supervisor()
        .check_results()
        .iter()
        .map(|result| result.status())
        .collect::<Vec<_>>();
    assert!(statuses.iter().all(|status| *status != CheckStatus::Pass));
    let timed_out = harness
        .evidence()
        .into_iter()
        .any(|item| item.outcome().timed_out());
    assert!(timed_out, "the explicit 1-second timeout must be observed");
}

// ---------------------------------------------------------------------------
// Approved cwd, timeout, and inputs
// ---------------------------------------------------------------------------

#[test]
fn approved_subdirectory_cwd_is_honored_and_root_is_not_substituted() {
    let project = TestProject::new();
    let conditions = approved_conditions(
        project.project,
        vec![ConditionSpec {
            title: "cwd fixture",
            mode: ConditionMode::Checks,
            checks: vec![CheckSpec {
                command: "true".to_owned(),
                cwd: ".".to_owned(),
                timeout_seconds: 10,
                input_paths: Vec::new(),
            }],
        }],
    );
    let contract = contract_with(
        &project,
        conditions,
        vec!["src/lib.rs".to_owned(), "Cargo.toml".to_owned()],
    );
    save_record_with_run(&project, &contract);
    let condition_id = contract.conditions().conditions()[0].id();
    let check_id = contract.conditions().checks()[0].id();
    let read_set = vec!["sub/marker.txt".to_owned()];

    let in_sub = execute_check(
        &project,
        &check_request(
            &project,
            condition_id,
            check_id,
            "test -f marker.txt",
            CheckInvocation::new("sub", 10, Vec::new()).expect("invocation"),
            600,
            1,
            read_set.clone(),
        ),
    );
    assert_eq!(in_sub.result().status(), CheckStatus::Pass);
    assert_eq!(
        in_sub.evidence().expect("evidence").acquirer(),
        EvidenceAcquirer::Host
    );

    let at_root = execute_check(
        &project,
        &check_request(
            &project,
            condition_id,
            check_id,
            "test -f marker.txt",
            CheckInvocation::new(".", 10, Vec::new()).expect("invocation"),
            600,
            2,
            read_set,
        ),
    );
    assert_eq!(
        at_root.result().status(),
        CheckStatus::Fail,
        "the root must not be substituted for the approved subdirectory"
    );

    assert!(
        CheckInvocation::new("../outside", 10, Vec::new()).is_err(),
        "an escaping cwd is refused when it is stored"
    );
}

#[test]
fn escaping_cwd_is_refused_before_spawn() {
    let project = TestProject::new();
    let conditions = approved_conditions(
        project.project,
        vec![ConditionSpec {
            title: "escape fixture",
            mode: ConditionMode::Checks,
            checks: vec![CheckSpec {
                command: "true".to_owned(),
                cwd: ".".to_owned(),
                timeout_seconds: 10,
                input_paths: Vec::new(),
            }],
        }],
    );
    let contract = contract_with(
        &project,
        conditions,
        vec!["src/lib.rs".to_owned(), "Cargo.toml".to_owned()],
    );
    save_record_with_run(&project, &contract);
    let condition_id = contract.conditions().conditions()[0].id();
    let check_id = contract.conditions().checks()[0].id();

    // A lexically valid directory that is a symlink out of the project must be
    // refused by the real path check before anything is spawned.
    std::os::unix::fs::symlink(&project.external, project.root.join("escape")).expect("symlink");
    assert!(resolve_check_cwd(&project.root, "escape").is_err());

    let execution = execute_check(
        &project,
        &check_request(
            &project,
            condition_id,
            check_id,
            "touch escaped.txt",
            CheckInvocation::new("escape", 10, Vec::new()).expect("invocation"),
            600,
            1,
            vec!["src/lib.rs".to_owned()],
        ),
    );
    assert_eq!(execution.result().status(), CheckStatus::Unavailable);
    assert!(
        !project.external.join("escaped.txt").exists(),
        "nothing may run outside the project root"
    );
}

#[test]
fn out_of_scope_check_inputs_are_refused_before_spawn() {
    let project = TestProject::new();
    let conditions = approved_conditions(
        project.project,
        vec![ConditionSpec {
            title: "scope fixture",
            mode: ConditionMode::Checks,
            checks: vec![CheckSpec {
                command: "true".to_owned(),
                cwd: ".".to_owned(),
                timeout_seconds: 10,
                input_paths: Vec::new(),
            }],
        }],
    );
    let contract = contract_with(
        &project,
        conditions,
        vec!["src/lib.rs".to_owned(), "Cargo.toml".to_owned()],
    );
    save_record_with_run(&project, &contract);
    let condition_id = contract.conditions().conditions()[0].id();
    let check_id = contract.conditions().checks()[0].id();
    let command = project.command_that_logs();

    let execution = execute_check(
        &project,
        &check_request(
            &project,
            condition_id,
            check_id,
            &command,
            CheckInvocation::new(".", 10, vec!["docs/secret.md".to_owned()]).expect("invocation"),
            600,
            1,
            vec!["src/lib.rs".to_owned(), "Cargo.toml".to_owned()],
        ),
    );
    assert_eq!(execution.result().status(), CheckStatus::Unavailable);
    assert_eq!(project.log_count(), 0, "the command must not be spawned");
}

#[test]
fn explicit_timeout_and_remaining_task_time_are_honored() {
    let project = TestProject::new();
    let conditions = approved_conditions(
        project.project,
        vec![ConditionSpec {
            title: "timeout fixture",
            mode: ConditionMode::Checks,
            checks: vec![CheckSpec {
                command: "true".to_owned(),
                cwd: ".".to_owned(),
                timeout_seconds: 10,
                input_paths: Vec::new(),
            }],
        }],
    );
    let contract = contract_with(
        &project,
        conditions,
        vec!["src/lib.rs".to_owned(), "Cargo.toml".to_owned()],
    );
    save_record_with_run(&project, &contract);
    let condition_id = contract.conditions().conditions()[0].id();
    let check_id = contract.conditions().checks()[0].id();
    let read_set = vec!["src/lib.rs".to_owned()];

    // 1 second is shorter than the former hardcoded 60-second bound, so the
    // sleep is observably stopped.
    let too_short = execute_check(
        &project,
        &check_request(
            &project,
            condition_id,
            check_id,
            "sleep 2",
            CheckInvocation::new(".", 1, Vec::new()).expect("invocation"),
            600,
            1,
            read_set.clone(),
        ),
    );
    assert_ne!(too_short.result().status(), CheckStatus::Pass);
    assert!(
        too_short
            .evidence()
            .expect("evidence")
            .outcome()
            .timed_out()
    );

    // The same command passes with the explicit longer-than-observed timeout.
    let sufficient = execute_check(
        &project,
        &check_request(
            &project,
            condition_id,
            check_id,
            "sleep 1",
            CheckInvocation::new(".", 5, Vec::new()).expect("invocation"),
            600,
            2,
            read_set.clone(),
        ),
    );
    assert_eq!(sufficient.result().status(), CheckStatus::Pass);

    // Remaining Task time is shorter than the explicit value, so it wins.
    let remaining_shorter = execute_check(
        &project,
        &check_request(
            &project,
            condition_id,
            check_id,
            "sleep 2",
            CheckInvocation::new(".", 5, Vec::new()).expect("invocation"),
            1,
            3,
            read_set,
        ),
    );
    assert_ne!(remaining_shorter.result().status(), CheckStatus::Pass);
    assert!(
        remaining_shorter
            .evidence()
            .expect("evidence")
            .outcome()
            .timed_out()
    );

    // The selected bound is the shorter of the two, and an explicit value above
    // the former 60-second host bound is preserved.
    assert_eq!(
        effective_check_timeout_ms(120, 7_200).expect("bound"),
        120_000
    );
    assert_eq!(effective_check_timeout_ms(120, 30).expect("bound"), 30_000);
    assert!(effective_check_timeout_ms(10, 0).is_err());
}

// ---------------------------------------------------------------------------
// Evidence reuse and staleness
// ---------------------------------------------------------------------------

fn seed_evidence(
    harness: &Harness,
    check_index: usize,
    input_digest_override: Option<herness_supervision::ContentDigest>,
    sequence: u64,
) {
    let check = &harness.contract.conditions().checks()[check_index];
    let read_set = harness.contract.evidence_target().read_set().to_vec();
    let workspace = ProjectWorkspace::new(harness.project.root.clone());
    let manifest = capture_manifest(
        &workspace,
        harness.project.project,
        harness.contract.evidence_target().version(),
        TargetReadSet::Declared(read_set.clone()),
    )
    .expect("manifest");
    let input_digest = input_digest_override.unwrap_or_else(|| {
        input_manifest_digest(&manifest, check.invocation().input_paths()).expect("input digest")
    });
    let record = EvidenceRecord::new(
        EvidenceId::new(harness.project.project),
        harness.project.supervision,
        Some(check.condition_id()),
        Some(check.id()),
        EvidenceAcquirer::Host,
        check.operation().clone(),
        EvidenceOutcome::new(Some(0), None, false, false, "seeded host check").expect("outcome"),
        manifest.target_scope().expect("target scope"),
        EvidenceScope::new(
            vec!["seeded check".to_owned()],
            vec!["seeded fixture evidence".to_owned()],
        )
        .expect("scope"),
        CheckStatus::Pass,
        sequence,
        now(),
    )
    .expect("evidence")
    .with_invocation(EvidenceInvocation::new(
        check.invocation().clone(),
        input_digest,
    ));
    let mut store = harness.project.store.clone();
    store.append(record).expect("append evidence");
}

fn reuse_harness() -> Harness {
    let project = TestProject::new();
    let command = project.command_that_logs();
    let conditions = approved_conditions(
        project.project,
        vec![ConditionSpec {
            title: "reuse fixture",
            mode: ConditionMode::Checks,
            checks: vec![CheckSpec {
                command,
                cwd: ".".to_owned(),
                timeout_seconds: 30,
                input_paths: vec!["src/lib.rs".to_owned()],
            }],
        }],
    );
    Harness::new(
        project,
        conditions,
        vec!["src/lib.rs".to_owned(), "Cargo.toml".to_owned()],
    )
}

#[test]
fn valid_evidence_with_matching_input_manifest_is_reused_without_execution() {
    let mut harness = reuse_harness();
    seed_evidence(&harness, 0, None, 1);
    let report = harness.drive_until_blocked();

    assert_eq!(report.outcome(), TickOutcome::Completed);
    assert_eq!(harness.record.state(), SupervisionState::Completed);
    assert_eq!(
        harness.project.log_count(),
        0,
        "matching evidence must be reused instead of running the command again"
    );
    assert_eq!(harness.evidence().len(), 1);
}

#[test]
fn stale_evidence_is_re_run_exactly_once() {
    let mut harness = reuse_harness();
    // A different input manifest digest makes the evidence stale even though
    // the operation, cwd, timeout, and target version still match.
    let wrong = herness_supervision::ContentDigest::sha256(b"a different input manifest");
    seed_evidence(&harness, 0, Some(wrong), 1);
    let report = harness.drive_until_blocked();

    assert_eq!(report.outcome(), TickOutcome::Completed);
    assert_eq!(
        harness.project.log_count(),
        1,
        "stale evidence must be re-run once, not trusted"
    );
    let evidence = harness.evidence();
    assert_eq!(evidence.len(), 2, "stale and fresh evidence are both kept");
    assert!(
        evidence
            .iter()
            .any(|item| item.status() == CheckStatus::Pass)
    );
}

// ---------------------------------------------------------------------------
// Old plan format 2 meaning
// ---------------------------------------------------------------------------

fn stored_plan_fixture(project: &TestProject) -> StoredPlan {
    let conditions = approved_conditions(
        project.project,
        vec![ConditionSpec {
            title: "format fixture",
            mode: ConditionMode::Checks,
            checks: vec![CheckSpec {
                command: "true".to_owned(),
                cwd: "sub".to_owned(),
                timeout_seconds: 45,
                input_paths: vec!["sub/marker.txt".to_owned()],
            }],
        }],
    );
    let contract = contract_with(
        project,
        conditions.clone(),
        vec!["src/lib.rs".to_owned(), "Cargo.toml".to_owned()],
    );
    let owner = OwnerRef::new(OwnerKind::Human, "format-fixture").expect("owner");
    StoredPlan {
        format_version: PLAN_FORMAT_VERSION,
        actor: RequestActor::Human,
        owner: owner.clone(),
        child: ChildIdentity {
            agent_id: AgentId::new(project.project),
            session_id: SessionId::new(project.project),
        },
        execution_scope: contract.execution_scope().clone(),
        conditions,
        evidence_target: contract.evidence_target().clone(),
        profile: completion_profile(project.project),
        consent: consent(
            project.project,
            herness_supervision::ProfilePurpose::Completion,
            1,
        ),
        budget: BudgetSnapshot::from_policy(&BudgetPolicy::h2_default()),
        budget_version: 1,
        packet: contract.work_packet().clone(),
        contract,
    }
}

#[test]
fn format_two_plan_keeps_its_old_meaning_through_the_explicit_decoder() {
    let project = TestProject::new();
    let plan = stored_plan_fixture(&project);
    let mut value = serde_json::to_value(&plan).expect("plan value");
    value["formatVersion"] = serde_json::json!(2);
    let condition = value["conditions"]["conditions"][0]
        .as_object_mut()
        .expect("condition object");
    condition.remove("mode");
    let check = value["conditions"]["checks"][0]
        .as_object_mut()
        .expect("check object");
    check.remove("invocation");
    let bytes = serde_json::to_vec(&value).expect("bytes");

    let decoded = decode_plan(&bytes).expect("format 2 decodes");
    assert_eq!(decoded.format_version, PLAN_FORMAT_VERSION);
    let condition = &decoded.conditions.conditions()[0];
    assert_eq!(
        condition.mode(),
        ConditionMode::Assessment,
        "every pre-mode condition was decided by the rubric assessment"
    );
    let check = &decoded.conditions.checks()[0];
    assert_eq!(check.invocation().cwd(), ".");
    assert_eq!(
        check.invocation().timeout_seconds(),
        herness_supervision::LEGACY_CHECK_TIMEOUT_SECONDS
    );
    assert!(check.invocation().input_paths().is_empty());
}

#[test]
fn a_new_format_value_is_never_read_as_format_two() {
    let project = TestProject::new();
    let plan = stored_plan_fixture(&project);
    let mut value = serde_json::to_value(&plan).expect("plan value");

    // A value that still carries a condition mode is not format 2.
    value["formatVersion"] = serde_json::json!(2);
    let bytes = serde_json::to_vec(&value).expect("bytes");
    assert!(matches!(
        decode_plan(&bytes),
        Err(SupervisionError::Unsupported { .. })
    ));

    // An unknown mode is rejected instead of being mapped to either meaning.
    value["formatVersion"] = serde_json::json!(PLAN_FORMAT_VERSION);
    value["conditions"]["conditions"][0]["mode"] = serde_json::json!("hybrid");
    let bytes = serde_json::to_vec(&value).expect("bytes");
    assert!(decode_plan(&bytes).is_err());

    // A missing mode in the current format is rejected too.
    value["conditions"]["conditions"][0]
        .as_object_mut()
        .expect("condition object")
        .remove("mode");
    let bytes = serde_json::to_vec(&value).expect("bytes");
    assert!(decode_plan(&bytes).is_err());
}

// ---------------------------------------------------------------------------
// H4 approved plan values reach H2 storage
// ---------------------------------------------------------------------------

#[test]
fn h4_approved_check_values_reach_the_h2_condition_set() {
    use herness_sdd_execute::{
        ApprovedCheck, ApprovedCondition, ApprovedDeliverable, CommitPolicy,
        ConditionMode as H4ConditionMode, DeliverableKind, TaskApproval, TaskNumber, TaskRef,
        TaskStableId,
    };
    use herness_supervision::budget::BudgetPolicy as H2BudgetPolicy;

    let project = ProjectId::new();
    let stable = TaskStableId::from_parts(
        project,
        uuid::Uuid::from_u128(0x9000_0000_0000_4000_8000_0000_0000_0009),
    );
    let task = TaskRef::new(stable, TaskNumber::new(9).expect("number"));
    let scope = ExecutionScope::new(
        project,
        vec!["src".to_owned()],
        vec!["src".to_owned()],
        true,
    )
    .expect("scope");
    let approval = TaskApproval::new(
        task,
        "condition modes",
        vec![
            ApprovedCondition::new(
                "c1",
                "checks condition",
                "rubric one",
                H4ConditionMode::Checks,
            )
            .expect("condition"),
            ApprovedCondition::new(
                "c2",
                "assessment condition",
                "rubric two",
                H4ConditionMode::Assessment,
            )
            .expect("condition"),
        ],
        scope,
        vec![
            ApprovedCheck::new(
                "check-1",
                "c1",
                "runs in a subdirectory",
                "cargo test --locked",
                "crates/fixture",
                45,
                vec!["crates/fixture/src/lib.rs".to_owned()],
            )
            .expect("check"),
            ApprovedCheck::new(
                "check-2",
                "c2",
                "runs at root",
                "cargo clippy",
                ".",
                120,
                Vec::new(),
            )
            .expect("check"),
        ],
        Vec::new(),
        H2BudgetPolicy::new(600, 5, None).expect("budget"),
        CommitPolicy::Required,
        vec![ApprovedDeliverable::new("src/lib.rs", DeliverableKind::File).expect("deliverable")],
    )
    .expect("task approval");
    let owner = OwnerRef::new(OwnerKind::H4SddTask, "h4:execution:task:9").expect("owner");

    let set = herness_desktop::supervision::h4_launch::h4_approved_conditions(
        &owner,
        ConditionVersion::new(1).expect("version"),
        &approval,
        now(),
    )
    .expect("approved conditions");

    assert_eq!(set.conditions().len(), 2);
    assert_eq!(set.conditions()[0].mode(), ConditionMode::Checks);
    assert_eq!(set.conditions()[1].mode(), ConditionMode::Assessment);
    let first = set
        .checks()
        .iter()
        .find(|check| check.operation().as_str() == "cargo test --locked")
        .expect("first check");
    assert_eq!(first.invocation().cwd(), "crates/fixture");
    assert_eq!(first.invocation().timeout_seconds(), 45);
    assert_eq!(
        first.invocation().input_paths(),
        ["crates/fixture/src/lib.rs".to_owned()]
    );
    let second = set
        .checks()
        .iter()
        .find(|check| check.operation().as_str() == "cargo clippy")
        .expect("second check");
    assert_eq!(second.invocation().cwd(), ".");
    assert_eq!(second.invocation().timeout_seconds(), 120);
    assert!(second.invocation().input_paths().is_empty());
    assert!(set.is_approved(now()));
}
