//! Task 11 scheduling tests: one H3 authoring target and one H4 Task target in
//! the same project are pumped by target, not by project.
//!
//! The real `SupervisionHost`, store, plans, command journal, budget ledger, and
//! recovery facts are used. The H1 runtime, checks, and assessment transport are
//! deterministic fakes; no provider, credential, Keychain item, shell, or GUI
//! session is used. The pump is called directly, with no window and no selected
//! project.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use herness_assessment::AssessmentEndpoints;
use herness_core::runtime::RecoveryMode;
use herness_core::{
    AgentId, AuthMethod, ConnectionAdmin, ConnectionId, ConnectionSettings, CoreError,
    CredentialAvailability, CredentialPort, Endpoint, InputId, InputPhase, InputProgress,
    PermissionPolicy, ProjectId, Provider, ResolvedCredential, RunId, RunState, SessionId,
    SharedPolicy, Timestamp,
};
use herness_desktop::supervision::assessment::AssessmentHost;
use herness_desktop::supervision::h4_launch::{
    H4TaskLaunch, H4TaskStartOutcome, h4_commit_authorization, h4_launch_identity, h4_owner_ref,
    h4_packet_binding,
};
use herness_desktop::supervision::plan::{BudgetInput, ConfigStore};
use herness_desktop::supervision::runtime::{ChildIdentity, DesktopSupervisionRuntime};
use herness_desktop::supervision::store::StoreHandle;
use herness_desktop::supervision::{
    CheckInput, ConditionInput, ConfirmationKind, CreateSupervisionRequest, PlanRequestActor,
    PumpScope, SupervisionHost, SupervisionTarget,
};
use herness_sdd_execute::{
    DispatchRequestId, ExecutionId, Sha256Digest, TaskNumber, TaskRef, TaskStableId,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::approval::ConditionApproval;
use herness_supervision::budget::BudgetPolicy;
use herness_supervision::conditions::ConditionSet;
use herness_supervision::consent::{DisclosureDataKind, ProviderOrigin};
use herness_supervision::evidence::{ContentDigest, TargetVersion};
use herness_supervision::operations::{HumanOperation, SupervisionOperationRequest};
use herness_supervision::owner_launch::{H4LaunchRequest, authorize_owner_launch};
use herness_supervision::recovery::{
    ManagedProcessState, RecoveryCheckpoint, RecoveryRuntimePort, RecoveryStopState,
};
use herness_supervision::supervisor::{
    AssessmentProfileFacts, CheckExecution, CheckExecutionRequest, ChildRunContinuation,
    ChildRunStart, ConditionAssessmentPort, RequiredCheckPort, StopDisposition,
    SupervisionRuntimePort, TargetSnapshotRequest, capture_target_snapshot,
};
use herness_supervision::{
    ApprovalActor, ApprovalBasis, ConditionMode, ExecutionScope, OwnerApprovalSource, OwnerKind,
    OwnerRef, ProfilePurpose, SupervisionError, SupervisionId, SupervisionRecord,
    SupervisionRequestId,
};
use herness_supervision_tests::{
    ScriptedH4OwnerApprovalRegistry, ScriptedOwnerApprovalRegistry, condition_set, now,
};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Fake credentials, runtime, checks, and assessment.
// ---------------------------------------------------------------------------

struct NoCredentials;

impl CredentialPort for NoCredentials {
    fn availability(
        &self,
        _connection: &ConnectionId,
    ) -> Result<CredentialAvailability, CoreError> {
        Ok(CredentialAvailability::Available)
    }

    fn resolve(&self, connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        Err(CoreError::AuthenticationRequired {
            connection: *connection,
        })
    }
}

fn loopback_assessment_endpoints() -> AssessmentEndpoints {
    AssessmentEndpoints::for_loopback(
        "http://127.0.0.1:9",
        "http://127.0.0.1:9",
        "http://127.0.0.1:9",
    )
    .expect("unused loopback assessment endpoints")
}

/// One child start observed at the tool boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Start {
    target: SupervisionTarget,
    candidate: bool,
}

struct FakeRun {
    state: RunState,
    inputs: BTreeMap<InputId, InputPhase>,
}

/// Scripted H1 boundary that records which target each start belongs to and
/// whether the adapter carried candidate tools.
struct FakeRuntime {
    store: StoreHandle,
    roots: BTreeMap<ProjectId, PathBuf>,
    children: BTreeMap<ProjectId, ChildIdentity>,
    runs: BTreeMap<RunId, FakeRun>,
    target_by_run: BTreeMap<RunId, SupervisionTarget>,
    /// Exact target whose candidate tools are installed on this adapter.
    candidate: Option<SupervisionTarget>,
    /// Every `start_child` in order.
    starts: Vec<Start>,
    /// Every H1 stop request in order.
    stop_requests: Vec<RunId>,
    policy: SharedPolicy,
}

impl FakeRuntime {
    fn new(store: StoreHandle) -> Self {
        Self {
            store,
            roots: BTreeMap::new(),
            children: BTreeMap::new(),
            runs: BTreeMap::new(),
            target_by_run: BTreeMap::new(),
            candidate: None,
            starts: Vec::new(),
            stop_requests: Vec::new(),
            policy: SharedPolicy::new(PermissionPolicy::default()),
        }
    }

    fn add_project(&mut self, project: ProjectId, root: PathBuf) {
        self.roots.insert(project, root);
        self.children.insert(
            project,
            ChildIdentity {
                agent_id: AgentId::new(project),
                session_id: SessionId::new(project),
            },
        );
    }

    /// Installs the candidate handle for exactly this target, like the H3
    /// worker does before its `OnlyCandidate` pump.
    fn use_candidate_for(&mut self, target: SupervisionTarget) {
        self.candidate = Some(target);
    }

    /// Uses the native supervision boundary.
    fn use_native(&mut self) {
        self.candidate = None;
    }

    fn starts_for(&self, target: SupervisionTarget) -> usize {
        self.starts
            .iter()
            .filter(|start| start.target == target)
            .count()
    }

    fn candidate_starts_for(&self, target: SupervisionTarget) -> usize {
        self.starts
            .iter()
            .filter(|start| start.target == target && start.candidate)
            .count()
    }

    fn native_starts_for(&self, target: SupervisionTarget) -> usize {
        self.starts
            .iter()
            .filter(|start| start.target == target && !start.candidate)
            .count()
    }

    fn complete_all_inputs(&mut self) {
        for run in self.runs.values_mut() {
            for phase in run.inputs.values_mut() {
                *phase = InputPhase::Completed;
            }
        }
    }

    /// The current run of one target.
    fn run_for(&self, target: SupervisionTarget) -> Option<RunId> {
        self.target_by_run
            .iter()
            .find_map(|(run, owner)| (*owner == target).then_some(*run))
    }

    /// Marks the target's run idle with completed input, like a finished turn.
    fn finish_turn_for(&mut self, target: SupervisionTarget) {
        let run = self.run_for(target).expect("target has a run");
        let run = self.runs.get_mut(&run).expect("run");
        run.state = RunState::Idle;
        for phase in run.inputs.values_mut() {
            *phase = InputPhase::Completed;
        }
    }
}

impl SupervisionRuntimePort for FakeRuntime {
    fn start_child(&mut self, request: &ChildRunStart) -> Result<(), SupervisionError> {
        let target = SupervisionTarget::new(request.project_id(), request.supervision_id());
        if let Some(bound) = self.candidate {
            assert_eq!(
                bound, target,
                "candidate tools bound to {bound} crossed to {target}"
            );
        }
        self.starts.push(Start {
            target,
            candidate: self.candidate.is_some(),
        });
        let mut inputs = BTreeMap::new();
        inputs.insert(request.input_id(), InputPhase::Accepted);
        self.runs.insert(
            request.run_id(),
            FakeRun {
                state: RunState::Running,
                inputs,
            },
        );
        self.target_by_run.insert(request.run_id(), target);
        Ok(())
    }

    fn continue_child(&mut self, request: &ChildRunContinuation) -> Result<(), SupervisionError> {
        let target = SupervisionTarget::new(request.project_id(), request.supervision_id());
        if let Some(bound) = self.candidate {
            assert_eq!(
                bound, target,
                "candidate tools bound to {bound} crossed to {target}"
            );
        }
        self.starts.push(Start {
            target,
            candidate: self.candidate.is_some(),
        });
        let mut inputs = BTreeMap::new();
        inputs.insert(request.input_id(), InputPhase::Accepted);
        self.runs.insert(
            request.run_id(),
            FakeRun {
                state: RunState::Running,
                inputs,
            },
        );
        self.target_by_run.insert(request.run_id(), target);
        Ok(())
    }

    fn input_progress(&mut self, input_id: InputId) -> Result<InputProgress, SupervisionError> {
        for run in self.runs.values() {
            if let Some(phase) = run.inputs.get(&input_id) {
                return Ok(InputProgress::new(input_id, *phase));
            }
        }
        Ok(InputProgress::new(input_id, InputPhase::Failed))
    }

    fn run_state(&mut self, run_id: RunId) -> Result<RunState, SupervisionError> {
        Ok(self
            .runs
            .get(&run_id)
            .map(|run| run.state)
            .unwrap_or(RunState::Failed))
    }

    fn request_stop(&mut self, run_id: RunId) -> Result<StopDisposition, SupervisionError> {
        self.stop_requests.push(run_id);
        if let Some(run) = self.runs.get_mut(&run_id) {
            run.state = RunState::Paused;
        }
        Ok(StopDisposition::Confirmed)
    }

    fn target_snapshot(
        &mut self,
        request: &TargetSnapshotRequest,
    ) -> Result<herness_supervision::TargetManifest, SupervisionError> {
        let root = self
            .roots
            .get(&request.project_id())
            .cloned()
            .ok_or(SupervisionError::UnknownSupervision)?;
        let workspace = herness_desktop::supervision::workspace::ProjectWorkspace::new(root);
        capture_target_snapshot(&workspace, request)
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
        Ok(RecoveryCheckpoint::Present)
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

impl herness_supervision::operations::OperationRuntimePort for FakeRuntime {
    fn request_stop(&mut self, run: RunId) -> Result<StopDisposition, SupervisionError> {
        <Self as SupervisionRuntimePort>::request_stop(self, run)
    }
}

impl DesktopSupervisionRuntime for FakeRuntime {
    fn create_child(
        &mut self,
        project: ProjectId,
        _connection: ConnectionId,
        _scope: &ExecutionScope,
    ) -> Result<ChildIdentity, SupervisionError> {
        self.children
            .get(&project)
            .copied()
            .ok_or(SupervisionError::UnknownSupervision)
    }

    fn project_path(&mut self, project: ProjectId) -> Result<PathBuf, SupervisionError> {
        self.roots
            .get(&project)
            .cloned()
            .ok_or(SupervisionError::UnknownSupervision)
    }

    fn policy(&self) -> PermissionPolicy {
        self.policy.snapshot()
    }

    fn shared_policy(&self) -> SharedPolicy {
        self.policy.clone()
    }

    fn record(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<Option<SupervisionRecord>, SupervisionError> {
        Ok(self
            .store
            .lock()
            .load_supervision_record(project, supervision)?)
    }

    fn candidate_target(&self) -> Option<SupervisionTarget> {
        self.candidate
    }
}

struct PassCheck {
    root: PathBuf,
}

impl RequiredCheckPort for PassCheck {
    fn execute(
        &mut self,
        request: &CheckExecutionRequest,
    ) -> Result<CheckExecution, SupervisionError> {
        let workspace =
            herness_desktop::supervision::workspace::ProjectWorkspace::new(self.root.clone());
        let mut read_set = request.read_set().to_vec();
        for path in request.invocation().input_paths() {
            if !read_set.contains(path) {
                read_set.push(path.clone());
            }
        }
        let manifest = herness_supervision::freshness::capture_manifest(
            &workspace,
            request.project_id(),
            request.target_version(),
            herness_supervision::TargetReadSet::Declared(read_set),
        )?;
        let target = manifest.target_scope()?;
        let input_digest = herness_supervision::freshness::input_manifest_digest(
            &manifest,
            request.invocation().input_paths(),
        )?;
        let evidence = herness_supervision::EvidenceRecord::new(
            request.evidence_id(),
            request.supervision_id(),
            Some(request.condition_id()),
            Some(request.check_id()),
            herness_supervision::EvidenceAcquirer::Host,
            request.operation().clone(),
            herness_supervision::EvidenceOutcome::new(Some(0), None, false, false, "exit=0")?,
            target,
            herness_supervision::EvidenceScope::new(
                vec![format!("check: {}", request.check_id())],
                vec!["scripted check evidence".to_owned()],
            )?,
            herness_supervision::CheckStatus::Pass,
            request.sequence(),
            Timestamp::now(),
        )?
        .with_invocation(herness_supervision::EvidenceInvocation::new(
            request.invocation().clone(),
            input_digest,
        ));
        let result = herness_supervision::RequiredCheckResult::from_evidence(
            &evidence,
            request.condition_version(),
        )?;
        Ok(CheckExecution::new(result, Some(evidence)))
    }
}

struct MetAssessment;

impl ConditionAssessmentPort for MetAssessment {
    fn profile(
        &self,
        _binding: herness_supervision::ProfileBinding,
    ) -> Result<AssessmentProfileFacts, SupervisionError> {
        Ok(AssessmentProfileFacts::new(
            herness_supervision::AdapterVersion::new("herness-llm-condition-v2")?,
            herness_supervision::RubricVersion::new("herness-conditions-v1")?,
            herness_supervision::ProfileThresholds::normal_llm(),
        ))
    }

    fn assess(
        &mut self,
        request: &herness_supervision::AssessmentRequest,
    ) -> Result<herness_supervision::AssessmentResult, SupervisionError> {
        let provenance = herness_supervision::AssessmentProvenance::new(
            herness_core::Provider::OpenAi,
            herness_supervision::ProviderKind::NormalLlm,
            herness_core::ModelId::new("judge-model").expect("static model"),
            request.adapter_version().clone(),
            request.rubric_version().clone(),
        )?;
        herness_supervision::AssessmentResult::new(
            request,
            request.evidence().to_vec(),
            "scripted verdict",
            None,
            herness_supervision::AssessmentOutcome::NormalLlm {
                verdict: herness_supervision::ConditionVerdict::Met,
                confidence: None,
            },
            provenance,
            Timestamp::now(),
        )
    }
}

// ---------------------------------------------------------------------------
// Harness: one project with an H3 target and an H4 Task target.
// ---------------------------------------------------------------------------

struct Harness {
    _temp: TempDir,
    project: ProjectId,
    other_project: ProjectId,
    connection: ConnectionId,
    host: SupervisionHost,
    runtime: FakeRuntime,
}

fn harness() -> Harness {
    let temp = tempfile::tempdir().expect("temp");
    let project = ProjectId::new();
    let other_project = ProjectId::new();
    for id in [project, other_project] {
        let root = temp.path().join(id.to_string());
        std::fs::create_dir_all(root.join("src")).expect("project dirs");
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("project file");
    }
    let store_path = temp.path().join("app-data");
    let config = StoreConfig::new(&store_path).expect("store config");
    let store = Store::open(config).expect("store");
    let store = StoreHandle::new(Arc::new(std::sync::Mutex::new(store)));
    let connection = ConnectionId::new();
    let admin = ConnectionAdmin::new();
    admin
        .add(
            ConnectionSettings::new(
                connection,
                Provider::OpenAi,
                "judge-model",
                AuthMethod::ApiKey,
                None::<Endpoint>,
                None,
            )
            .expect("connection"),
        )
        .expect("add connection");
    let assessment_host = AssessmentHost {
        directory: admin.directory(),
        credentials: Arc::new(NoCredentials),
        endpoints: loopback_assessment_endpoints(),
    };
    let roots = BTreeMap::from([
        (project, temp.path().join(project.to_string())),
        (other_project, temp.path().join(other_project.to_string())),
    ]);
    let host = SupervisionHost::with_config_for_test(
        store.clone(),
        ConfigStore::new(),
        assessment_host,
        Box::new(MetAssessment),
        Box::new(PassCheck {
            root: roots[&project].clone(),
        }),
    );
    let mut runtime = FakeRuntime::new(store.clone());
    for (id, root) in &roots {
        runtime.add_project(*id, root.clone());
    }
    Harness {
        _temp: temp,
        project,
        other_project,
        connection,
        host,
        runtime,
    }
}

fn request(project: ProjectId, connection: ConnectionId) -> CreateSupervisionRequest {
    CreateSupervisionRequest {
        project,
        connection,
        instructions: "Implement the approved change.".to_owned(),
        conditions: vec![ConditionInput {
            title: "The check passes".to_owned(),
            rubric: "The required check must pass on the current target.".to_owned(),
            mode: ConditionMode::Assessment,
            checks: vec![CheckInput {
                command: "true".to_owned(),
                description: "trivial passing command".to_owned(),
                cwd: ".".to_owned(),
                timeout_seconds: 60,
                input_paths: Vec::new(),
            }],
        }],
        read_set: vec!["src/main.rs".to_owned()],
        write_paths: vec!["src".to_owned()],
        allow_shell: false,
        condition_version: Some(1),
        target_version: Some(1),
        budget: Some(BudgetInput {
            active_seconds: 7_200,
            additional_runs: 30,
            money_limit_micros: None,
            price_version: None,
        }),
    }
}

/// Builds one synthetic H4 Task launch for this project.
fn launch(project: ProjectId, connection: ConnectionId, budget: BudgetPolicy) -> H4TaskLaunch {
    let execution = ExecutionId::new(project);
    let task = TaskRef::new(TaskStableId::new(project), TaskNumber::new(1).unwrap());
    let dispatch = DispatchRequestId::new(project);
    let supervision = SupervisionId::new(project);
    let owner = h4_owner_ref(execution, task).expect("owner ref");
    let conditions = approved_h4_conditions(project, &owner);
    let scope = ExecutionScope::new(
        project,
        vec!["src/main.rs".to_owned()],
        vec!["src".to_owned()],
        false,
    )
    .expect("scope");
    H4TaskLaunch::new(
        execution,
        task,
        dispatch,
        supervision,
        connection,
        "Implement the approved Task.",
        conditions,
        scope,
        TargetVersion::new(1).expect("target version"),
        budget,
        1,
        launch_request(execution, task),
    )
    .expect("H4 launch")
}

fn launch_request(execution: ExecutionId, task: TaskRef) -> H4LaunchRequest {
    let (execution_ref, task_ref) = h4_launch_identity(execution, task).expect("identity");
    H4LaunchRequest::new(
        execution_ref,
        task_ref,
        1,
        ContentDigest::sha256(b"exact approved plan bytes"),
        h4_packet_binding(
            &Sha256Digest::sha256(b"Task body"),
            &Sha256Digest::sha256(b"Global Constraints"),
            &Sha256Digest::sha256(b"spec snapshot"),
        )
        .expect("packet binding"),
        ContentDigest::sha256(b"pack execution contract"),
        h4_commit_authorization(true, true).expect("commit authorization"),
    )
    .expect("H4 launch request")
}

fn approved_h4_conditions(project: ProjectId, owner: &OwnerRef) -> ConditionSet {
    let mut set = condition_set(project);
    let approval = ConditionApproval::new(
        project,
        ApprovalBasis::InheritedOwner {
            owner: owner.clone(),
            source: OwnerApprovalSource::H4ApprovedPlan,
            approved_at: now(),
            expires_at: None,
        },
        set.condition_version(),
        set.digest().clone(),
    )
    .expect("condition approval");
    set.approve(
        ApprovalActor::ApprovedOwner {
            owner: owner.clone(),
            source: OwnerApprovalSource::H4ApprovedPlan,
        },
        approval,
        now(),
    )
    .expect("approve");
    set
}

impl Harness {
    fn configure_completion(&mut self, project: ProjectId) {
        self.host
            .configure_profile(
                PlanRequestActor::Human,
                project,
                ProfilePurpose::Completion,
                self.connection,
                "judge-model",
                Some(self.host.confirm(ConfirmationKind::Profile)),
            )
            .expect("profile");
        self.host
            .grant_consent(
                PlanRequestActor::Human,
                project,
                ProfilePurpose::Completion,
                ProviderOrigin::parse("https://api.openai.com").expect("origin"),
                BTreeSet::from([DisclosureDataKind::Text]),
                vec!["src/main.rs".to_owned()],
                TargetVersion::new(1).expect("version"),
                Some(self.host.confirm(ConfirmationKind::Consent)),
            )
            .expect("consent");
    }

    /// Creates one H3-owned target. It is not started here.
    fn create_h3_target(&mut self, project: ProjectId, job: &str) -> SupervisionId {
        let owner = OwnerRef::new(OwnerKind::H3HtmlJob, job).expect("H3 owner");
        let actor = PlanRequestActor::ApprovedOwner {
            owner,
            source: OwnerApprovalSource::H3ApprovedSettings,
        };
        self.host
            .create(
                &mut self.runtime,
                actor,
                request(project, self.connection),
                None,
            )
            .expect("H3 create")
            .supervision_id
    }

    /// Starts the H3 target through the approved-owner path.
    fn start_h3_target(&mut self, project: ProjectId, supervision: SupervisionId, job: &str) {
        let binding = self
            .host
            .owner_launch_binding(project, supervision, 1, job)
            .expect("owner binding");
        let mut registry = ScriptedOwnerApprovalRegistry::new();
        registry.insert(binding.approval().clone());
        let authority =
            authorize_owner_launch(&registry, &binding, now()).expect("owner authority");
        let view = self.host.get(project, supervision).expect("view");
        self.host
            .start_approved_owner(
                &mut self.runtime,
                authority,
                SupervisionRequestId::new(project),
                view.revision,
            )
            .expect("approved owner start");
    }

    /// Creates and starts one H4 Task target in the same project.
    fn start_h4_task(&mut self, project: ProjectId, budget: BudgetPolicy) -> SupervisionId {
        let launch = launch(project, self.connection, budget);
        let supervision = launch.supervision_id();
        let approval = self.host.h4_expected_approval(&launch).expect("expected");
        let mut registry = ScriptedH4OwnerApprovalRegistry::new();
        registry.insert(approval);
        match self
            .host
            .start_h4_task(&mut self.runtime, &registry, &launch)
            .expect("H4 start")
        {
            H4TaskStartOutcome::Ready { view, .. } => {
                assert_eq!(view.supervision_id, supervision);
            }
            other => panic!("expected a ready H4 start, got {other:?}"),
        }
        supervision
    }

    /// Creates and starts one plain Human target in another project.
    fn start_human_target(&mut self, project: ProjectId) -> SupervisionId {
        let created = self
            .host
            .create(
                &mut self.runtime,
                PlanRequestActor::Human,
                request(project, self.connection),
                Some(self.host.confirm(ConfirmationKind::Create)),
            )
            .expect("human create");
        let view = self
            .host
            .get(project, created.supervision_id)
            .expect("view");
        self.host
            .start(
                &mut self.runtime,
                project,
                created.supervision_id,
                SupervisionRequestId::new(project),
                view.revision,
                Some(self.host.confirm(ConfirmationKind::Start)),
            )
            .expect("human start");
        created.supervision_id
    }

    fn state(&self, project: ProjectId, supervision: SupervisionId) -> String {
        self.host.get(project, supervision).expect("view").state
    }
}

fn interval() -> Duration {
    herness_desktop::supervision::PUMP_INTERVAL + Duration::from_millis(30)
}

/// Pumps the H3 target with its candidate boundary and every other target in
/// both projects with the native boundary, returning one cycle's counts.
fn pump_cycle(
    harness: &mut Harness,
    h3: SupervisionTarget,
) -> (
    (usize, Vec<SupervisionTarget>),
    (usize, Vec<SupervisionTarget>),
) {
    harness.runtime.use_native();
    let native = harness
        .host
        .pump_scoped(
            &mut harness.runtime,
            PumpScope::AllExcept {
                projects: vec![harness.project, harness.other_project],
                excluded: h3,
            },
        )
        .expect("native pump");
    harness.runtime.use_candidate_for(h3);
    let candidate = harness
        .host
        .pump_scoped(&mut harness.runtime, PumpScope::OnlyCandidate(h3))
        .expect("candidate pump");
    harness.runtime.use_native();
    (
        (native.len(), native.processed().to_vec()),
        (candidate.len(), candidate.processed().to_vec()),
    )
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[test]
fn the_host_native_scope_excludes_one_target_not_the_whole_project() {
    let project = ProjectId::new();
    let other = ProjectId::new();
    let h3 = SupervisionTarget::new(project, SupervisionId::new(project));

    let scope = PumpScope::for_active_candidate([project, other], Some(h3));
    assert_eq!(
        scope,
        PumpScope::AllExcept {
            projects: vec![project, other],
            excluded: h3,
        },
        "the active H3 slot excludes only its own target"
    );
    assert_ne!(
        scope,
        PumpScope::Projects(vec![]),
        "an active H3 target never skips the project"
    );

    let idle = PumpScope::for_active_candidate([project], None);
    assert_eq!(idle, PumpScope::Projects(vec![project]));
}

#[test]
fn each_target_is_pumped_exactly_once_per_cycle_in_the_same_project() {
    let mut harness = harness();
    let project = harness.project;
    harness.configure_completion(project);
    let h3 = harness.create_h3_target(project, "h3-job-1");
    harness.start_h3_target(project, h3, "h3-job-1");
    let task = harness.start_h4_task(project, BudgetPolicy::h2_default());
    let h3_target = SupervisionTarget::new(project, h3);
    let task_target = SupervisionTarget::new(project, task);
    assert_ne!(
        h3_target, task_target,
        "two distinct targets in one project"
    );
    let starts_before = harness.runtime.starts.len();

    let ((native_len, native), (candidate_len, candidate)) = pump_cycle(&mut harness, h3_target);

    // No H3 target in the native set; no Task target in the candidate set.
    assert_eq!(native_len, 1, "native pump processed: {native:?}");
    assert_eq!(candidate_len, 1, "candidate pump processed: {candidate:?}");
    assert_eq!(native, vec![task_target]);
    assert_eq!(candidate, vec![h3_target]);
    assert!(!native.contains(&h3_target));
    assert!(!candidate.contains(&task_target));

    // Each target was advanced exactly once across the whole cycle.
    let mut all = native.clone();
    all.extend(candidate.iter().copied());
    all.sort();
    let mut expected = vec![h3_target, task_target];
    expected.sort();
    assert_eq!(all, expected);
    assert_eq!(all.len(), 2);

    // The H3 target's child start used candidate tools; the Task target's used
    // the native tools. Nothing crossed.
    assert_eq!(harness.runtime.starts.len(), starts_before + 2);
    assert_eq!(harness.runtime.candidate_starts_for(h3_target), 1);
    assert_eq!(harness.runtime.native_starts_for(h3_target), 0);
    assert_eq!(harness.runtime.candidate_starts_for(task_target), 0);
    assert_eq!(harness.runtime.native_starts_for(task_target), 1);

    // A second cycle processes each target exactly once more, never twice.
    std::thread::sleep(interval());
    harness.runtime.complete_all_inputs();
    let ((native_len, native), (candidate_len, candidate)) = pump_cycle(&mut harness, h3_target);
    assert_eq!((native_len, candidate_len), (1, 1));
    assert_eq!(native, vec![task_target]);
    assert_eq!(candidate, vec![h3_target]);
    assert_eq!(harness.runtime.candidate_starts_for(h3_target), 1);
    assert_eq!(harness.runtime.native_starts_for(task_target), 1);
}

#[test]
fn a_candidate_adapter_cannot_widen_to_a_multi_target_scope() {
    let mut harness = harness();
    let project = harness.project;
    harness.configure_completion(project);
    let h3 = harness.create_h3_target(project, "h3-job-1");
    harness.start_h3_target(project, h3, "h3-job-1");
    let task = harness.start_h4_task(project, BudgetPolicy::h2_default());
    let h3_target = SupervisionTarget::new(project, h3);
    let task_target = SupervisionTarget::new(project, task);

    harness.runtime.use_candidate_for(h3_target);
    let starts_before = harness.runtime.starts.len();

    let illegal = harness.host.pump_scoped(
        &mut harness.runtime,
        PumpScope::AllExcept {
            projects: vec![project],
            excluded: task_target,
        },
    );
    assert!(
        matches!(illegal, Err(SupervisionError::InvalidValue { .. })),
        "candidate tools must not pump a multi-target scope: {illegal:?}"
    );
    let legacy = harness.host.pump(&mut harness.runtime, &[project]);
    assert!(
        matches!(legacy, Err(SupervisionError::InvalidValue { .. })),
        "the native multi-target entry point must refuse candidate tools: {legacy:?}"
    );

    // The exact-target candidate scope is accepted.
    let accepted = harness
        .host
        .pump_scoped(&mut harness.runtime, PumpScope::OnlyCandidate(h3_target))
        .expect("candidate only");
    assert_eq!(accepted.processed(), &[h3_target]);
    harness.runtime.use_native();
    assert_eq!(
        harness.runtime.starts.len(),
        starts_before + 1,
        "only the exact H3 target started after the refusals"
    );
    assert_eq!(harness.runtime.candidate_starts_for(h3_target), 1);
    assert_eq!(harness.runtime.starts_for(task_target), 0);
}

#[test]
fn wrong_target_candidate_binding_is_refused_before_any_tick() {
    let mut harness = harness();
    let project = harness.project;
    harness.configure_completion(project);
    let h3 = harness.create_h3_target(project, "h3-job-1");
    harness.start_h3_target(project, h3, "h3-job-1");
    let task = harness.start_h4_task(project, BudgetPolicy::h2_default());
    let h3_target = SupervisionTarget::new(project, h3);
    let task_target = SupervisionTarget::new(project, task);

    // Candidate tools are bound to the Task target, so the H3 target must not
    // be ticked with them.
    harness.runtime.use_candidate_for(task_target);
    let starts_before = harness.runtime.starts.len();
    let wrong = harness
        .host
        .pump_scoped(&mut harness.runtime, PumpScope::OnlyCandidate(h3_target));
    assert!(
        matches!(wrong, Err(SupervisionError::InvalidValue { .. })),
        "a mismatched candidate binding must be refused: {wrong:?}"
    );
    assert_eq!(harness.runtime.starts.len(), starts_before);
    harness.runtime.use_native();
}

#[test]
fn h1_stop_and_deadline_land_while_the_h3_target_is_authoring() {
    let mut harness = harness();
    let project = harness.project;
    harness.configure_completion(project);
    let h3 = harness.create_h3_target(project, "h3-job-1");
    harness.start_h3_target(project, h3, "h3-job-1");
    // This target only proves that an explicit H1 stop lands; its budget must
    // not double as the deadline test (see `deadline_task` below).
    let task = harness.start_h4_task(project, BudgetPolicy::h2_default());
    let h3_target = SupervisionTarget::new(project, h3);
    let task_target = SupervisionTarget::new(project, task);

    let ((_, native), (_, candidate)) = pump_cycle(&mut harness, h3_target);
    assert_eq!(native, vec![task_target]);
    assert_eq!(candidate, vec![h3_target]);
    assert_eq!(harness.state(project, task), "running");

    // An explicit H1 stop of the Task run still lands while H3 holds its slot
    // in the same project.
    let running = harness.host.get(project, task).expect("view");
    let request = SupervisionOperationRequest::new(
        SupervisionRequestId::new(project),
        task,
        HumanOperation::Stop,
        running.revision,
    )
    .expect("stop request");
    let stopped = harness
        .host
        .stop(
            &mut harness.runtime,
            request,
            false,
            1,
            Some(harness.host.confirm(ConfirmationKind::Stop)),
        )
        .expect("stop while H3 authors");
    assert_eq!(stopped.state, "stopped");
    assert_eq!(
        harness.runtime.stop_requests,
        vec![harness.runtime.run_for(task_target).expect("task run")],
        "the stop reached the Task run, not the H3 run"
    );
    assert_ne!(
        harness.state(project, h3),
        "stopped",
        "the H3 target must keep its own slot"
    );
    harness.runtime.use_native();
    let after_stop = harness
        .host
        .pump_scoped(
            &mut harness.runtime,
            PumpScope::AllExcept {
                projects: vec![project],
                excluded: h3_target,
            },
        )
        .expect("native pump after the stop");
    assert!(
        after_stop.is_empty(),
        "the stopped Task target is not pumped again: {after_stop:?}"
    );

    // The H3 target still advances with its candidate adapter once the
    // bounded pump interval has elapsed.
    std::thread::sleep(interval());
    harness.runtime.use_candidate_for(h3_target);
    let h3_again = harness
        .host
        .pump_scoped(&mut harness.runtime, PumpScope::OnlyCandidate(h3_target))
        .expect("candidate pump after the Task stop");
    assert_eq!(h3_again.processed(), &[h3_target]);
    harness.runtime.use_native();

    // Budget deadline: a separate Task target with a finite budget stops on
    // the bounded pump even while the H3 slot is active. The run stays Running
    // while the budget is drained, so verification cannot complete first; only
    // the deadline can stop the target once the turn is finished.
    let deadline_task = harness.start_h4_task(project, BudgetPolicy::new(3, 30, None).expect("b"));
    let deadline_target = SupervisionTarget::new(project, deadline_task);
    harness.runtime.use_native();
    harness
        .host
        .pump_scoped(
            &mut harness.runtime,
            PumpScope::AllExcept {
                projects: vec![project],
                excluded: h3_target,
            },
        )
        .expect("deadline start pump");
    assert_eq!(
        harness.state(project, deadline_task),
        "running",
        "the finite target starts before its deadline"
    );
    assert_eq!(
        harness.runtime.starts_for(deadline_target),
        1,
        "the deadline target starts exactly one run"
    );

    let drained = Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = harness
            .host
            .get(project, deadline_task)
            .expect("view")
            .budget
            .map(|budget| budget.remaining_active_seconds);
        if remaining == Some(0) {
            break;
        }
        assert!(
            Instant::now() < drained,
            "the finite active-seconds budget must be consumed: {remaining:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // The turn is finished only after the budget is already 0, so the next
    // ticks deterministically reach the deadline stop instead of completion.
    harness.runtime.finish_turn_for(deadline_target);
    let deadline = Instant::now() + Duration::from_secs(15);
    let reason = loop {
        assert!(
            Instant::now() < deadline,
            "the finite budget deadline must land"
        );
        harness
            .host
            .pump_scoped(
                &mut harness.runtime,
                PumpScope::AllExcept {
                    projects: vec![project],
                    excluded: h3_target,
                },
            )
            .expect("deadline pump");
        let view = harness.host.get(project, deadline_task).expect("view");
        if view.state == "stopped" {
            break view.reason;
        }
        // Respect the bounded pump interval between ticks.
        std::thread::sleep(interval());
    };
    let reason = reason.to_string().to_lowercase();
    assert!(
        reason.contains("active_seconds") || reason.contains("activeseconds"),
        "the stop reason must name the active-seconds budget: {reason}"
    );
    assert_eq!(
        harness.state(project, deadline_task),
        "stopped",
        "the finite budget deadline must land: {reason}"
    );
}

#[test]
fn human_owner_progresses_in_another_project_while_h3_authoring() {
    let mut harness = harness();
    let project = harness.project;
    let other = harness.other_project;
    harness.configure_completion(project);
    harness.configure_completion(other);
    let h3 = harness.create_h3_target(project, "h3-job-1");
    harness.start_h3_target(project, h3, "h3-job-1");
    let task = harness.start_h4_task(project, BudgetPolicy::h2_default());
    let human = harness.start_human_target(other);
    let h3_target = SupervisionTarget::new(project, h3);
    let task_target = SupervisionTarget::new(project, task);
    let human_target = SupervisionTarget::new(other, human);

    let ((native_len, native), (candidate_len, candidate)) = pump_cycle(&mut harness, h3_target);

    assert_eq!(native_len, 2, "native pump processed: {native:?}");
    assert_eq!(candidate_len, 1);
    assert!(native.contains(&task_target));
    assert!(native.contains(&human_target));
    assert_eq!(candidate, vec![h3_target]);
    assert_eq!(harness.runtime.starts_for(human_target), 1);
    assert_eq!(harness.runtime.starts_for(task_target), 1);
    assert_eq!(harness.runtime.candidate_starts_for(h3_target), 1);
    assert_eq!(harness.state(other, human), "running");

    // The app-wide H3 authoring slot is still one, app-wide and independent of
    // the selected project or any window.
    assert_eq!(herness_html_sync::APP_WIDE_AUTHORING_CONCURRENCY, 1);
    assert_eq!(
        herness_html_sync::DOCUMENT_PUBLICATION_CONCURRENCY,
        1,
        "publication stays per-document one"
    );
}
