//! H4 registry match and idempotent owner-target creation.
//!
//! These tests exercise two seams:
//!
//! * `herness_supervision::owner_launch` — an `OwnerKind::H4SddTask` launch is
//!   authorized only after the current H4 plan-approval registry entry matches
//!   every approved constraint. The H3-shaped registry keeps refusing with
//!   `H4ApprovalUnavailable`.
//! * the desktop supervision composition — the reserved dispatch request ID
//!   recovers exactly one `(supervision, child)` mapping across every crash
//!   boundary, and an unobservable mapping waits instead of creating a second
//!   child.
//!
//! Every value is synthetic: a temporary store, a scripted runtime, and fake
//! condition/assessment ports. No provider, credential, Keychain item, shell, or
//! GUI session is used.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

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
    H4LaunchIntent, H4ReconcileReason, H4TaskLaunch, H4TaskStartOutcome, h4_commit_authorization,
    h4_launch_identity, h4_owner_ref, h4_packet_binding,
};
use herness_desktop::supervision::plan::ConfigStore;
use herness_desktop::supervision::runtime::{ChildIdentity, DesktopSupervisionRuntime};
use herness_desktop::supervision::store::StoreHandle;
use herness_desktop::supervision::{
    BudgetInput, CheckInput, ConditionInput, ConfirmationKind, CreateSupervisionRequest,
    PlanRequestActor, SupervisionHost,
};
use herness_sdd_execute::{
    DispatchRequestId, ExecutionId, Sha256Digest, TaskNumber, TaskRef, TaskStableId,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::approval::ConditionApproval;
use herness_supervision::budget::BudgetPolicy;
use herness_supervision::conditions::{ConditionDigest, ConditionSet};
use herness_supervision::consent::{
    ConsentBinding, ConsentBlock, DisclosureDataKind, ProviderOrigin,
};
use herness_supervision::evidence::{ContentDigest, TargetVersion};
use herness_supervision::owner_launch::{
    H4CommitAuthorization, H4ExecutionRef, H4LaunchRequest, H4OwnerApproval, H4OwnerLaunchBinding,
    H4TaskRef, OwnerLaunchBinding, UnconfiguredH4ApprovalRegistry, authorize_h4_owner_launch,
    authorize_owner_launch,
};
use herness_supervision::recovery::{
    ManagedProcessState, RecoveryCheckpoint, RecoveryRuntimePort, RecoveryStopState,
};
use herness_supervision::supervisor::{
    AssessmentProfileFacts, CheckExecution, CheckExecutionRequest, ChildRunContinuation,
    ChildRunStart, ConditionAssessmentPort, RequiredCheckPort, StopDisposition,
    SupervisionRuntimePort, TargetSnapshotRequest, capture_target_snapshot,
};
use herness_supervision::{
    ApprovalActor, ApprovalBasis, ExecutionScope, OwnerApprovalSource, OwnerKind,
    OwnerLaunchRejection, OwnerRef, ProfileBinding, ProfilePurpose, ProfileVersion,
    SupervisionError, SupervisionId, SupervisionRecord, SupervisionRequestId,
};
use herness_supervision_tests::{
    ScriptedH4OwnerApprovalRegistry, ScriptedOwnerApprovalRegistry, condition_set, now,
    owner_contract,
};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Scripted runtime and ports.
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

struct FakeRun {
    state: RunState,
    inputs: BTreeMap<InputId, InputPhase>,
}

/// Scripted H1 boundary that counts real child allocations and run starts.
struct FakeRuntime {
    store: StoreHandle,
    roots: BTreeMap<ProjectId, PathBuf>,
    children: BTreeMap<ProjectId, ChildIdentity>,
    runs: BTreeMap<RunId, FakeRun>,
    /// Child allocations (`create_child` calls).
    children_created: usize,
    /// Real run starts (`start_child` calls).
    starts: usize,
    policy: SharedPolicy,
}

impl FakeRuntime {
    fn new(store: StoreHandle, project: ProjectId, root: PathBuf) -> Self {
        let mut roots = BTreeMap::new();
        roots.insert(project, root);
        let mut children = BTreeMap::new();
        children.insert(
            project,
            ChildIdentity {
                agent_id: AgentId::new(project),
                session_id: SessionId::new(project),
            },
        );
        Self {
            store,
            roots,
            children,
            runs: BTreeMap::new(),
            children_created: 0,
            starts: 0,
            policy: SharedPolicy::new(PermissionPolicy::default()),
        }
    }

    fn run_count(&self) -> usize {
        self.runs.len()
    }
}

impl SupervisionRuntimePort for FakeRuntime {
    fn start_child(&mut self, request: &ChildRunStart) -> Result<(), SupervisionError> {
        self.starts += 1;
        let mut inputs = BTreeMap::new();
        inputs.insert(request.input_id(), InputPhase::Accepted);
        self.runs.insert(
            request.run_id(),
            FakeRun {
                state: RunState::Running,
                inputs,
            },
        );
        Ok(())
    }

    fn continue_child(&mut self, request: &ChildRunContinuation) -> Result<(), SupervisionError> {
        let mut inputs = BTreeMap::new();
        inputs.insert(request.input_id(), InputPhase::Accepted);
        self.runs.insert(
            request.run_id(),
            FakeRun {
                state: RunState::Running,
                inputs,
            },
        );
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
        self.children_created += 1;
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
}

/// Required-check port that never reports a result (unused by these tests).
struct UnavailableCheck;

impl RequiredCheckPort for UnavailableCheck {
    fn execute(
        &mut self,
        request: &CheckExecutionRequest,
    ) -> Result<CheckExecution, SupervisionError> {
        let result = herness_supervision::RequiredCheckResult::new(
            request.check_id(),
            request.condition_id(),
            herness_supervision::CheckStatus::Unavailable,
            None,
            request.condition_version(),
            request.target_version(),
            Timestamp::now(),
        )?;
        Ok(CheckExecution::new(result, None))
    }
}

/// Assessment port that never evaluates (unused by these tests).
struct UnverifiedAssessment;

impl ConditionAssessmentPort for UnverifiedAssessment {
    fn profile(
        &self,
        _binding: ProfileBinding,
    ) -> Result<AssessmentProfileFacts, SupervisionError> {
        Err(SupervisionError::Unsupported {
            feature: "assessment profile is not verified".to_owned(),
        })
    }

    fn assess(
        &mut self,
        _request: &herness_supervision::AssessmentRequest,
    ) -> Result<herness_supervision::AssessmentResult, SupervisionError> {
        Err(SupervisionError::Unsupported {
            feature: "assessment profile is not verified".to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

struct Harness {
    _temp: TempDir,
    store_path: PathBuf,
    project: ProjectId,
    connection: ConnectionId,
    store: StoreHandle,
    admin: ConnectionAdmin,
    host: SupervisionHost,
    runtime: FakeRuntime,
    project_root: PathBuf,
}

fn harness() -> Harness {
    let temp = tempfile::tempdir().expect("temp");
    let project_root = temp.path().join("project");
    std::fs::create_dir_all(project_root.join("src")).expect("project dirs");
    std::fs::write(project_root.join("src/main.rs"), "fn main() {}\n").expect("project file");
    let store_path = temp.path().join("app-data");
    let config = StoreConfig::new(&store_path).expect("store config");
    let store = Store::open(config).expect("store");
    let store = StoreHandle::new(Arc::new(std::sync::Mutex::new(store)));
    let project = ProjectId::new();
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
    let host = SupervisionHost::with_config_for_test(
        store.clone(),
        ConfigStore::new(),
        assessment_host,
        Box::new(UnverifiedAssessment),
        Box::new(UnavailableCheck),
    );
    let runtime = FakeRuntime::new(store.clone(), project, project_root.clone());
    Harness {
        _temp: temp,
        store_path,
        project,
        connection,
        store,
        admin,
        host,
        runtime,
        project_root,
    }
}

impl Harness {
    fn configure_completion(&mut self) {
        self.host
            .configure_profile(
                PlanRequestActor::Human,
                self.project,
                ProfilePurpose::Completion,
                self.connection,
                "judge-model",
                Some(self.host.confirm(ConfirmationKind::Profile)),
            )
            .expect("profile");
    }

    fn grant_completion(&mut self, target_version: u64) {
        self.host
            .grant_consent(
                PlanRequestActor::Human,
                self.project,
                ProfilePurpose::Completion,
                ProviderOrigin::parse("https://api.openai.com").expect("origin"),
                BTreeSet::from([DisclosureDataKind::Text]),
                vec!["src/main.rs".to_owned()],
                TargetVersion::new(target_version).expect("version"),
                Some(self.host.confirm(ConfirmationKind::Consent)),
            )
            .expect("consent");
    }

    fn revoke_completion(&mut self) {
        self.host
            .revoke_consent(
                PlanRequestActor::Human,
                self.project,
                ProfilePurpose::Completion,
                Some(self.host.confirm(ConfirmationKind::Consent)),
            )
            .expect("revoke");
    }

    fn create_request(&self) -> CreateSupervisionRequest {
        CreateSupervisionRequest {
            project: self.project,
            connection: self.connection,
            instructions: "Implement the approved change.".to_owned(),
            conditions: vec![ConditionInput {
                title: "The check passes".to_owned(),
                rubric: "The required check must pass.".to_owned(),
                mode: herness_supervision::ConditionMode::Assessment,
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

    /// Builds one synthetic H4 Task launch.
    fn launch(&self) -> H4TaskLaunch {
        let execution = ExecutionId::new(self.project);
        let task = TaskRef::new(TaskStableId::new(self.project), TaskNumber::new(1).unwrap());
        let dispatch = DispatchRequestId::new(self.project);
        let supervision = SupervisionId::new(self.project);
        let owner = h4_owner_ref(execution, task).expect("owner ref");
        let conditions = approved_h4_conditions(self.project, &owner);
        let scope = ExecutionScope::new(
            self.project,
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
            self.connection,
            "Implement the approved Task.",
            conditions,
            scope,
            TargetVersion::new(1).expect("target version"),
            BudgetPolicy::h2_default(),
            1,
            launch_request(execution, task),
        )
        .expect("H4 launch")
    }
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

/// The current registry entry the host should accept for `launch`.
fn expected(harness: &Harness, launch: &H4TaskLaunch) -> H4OwnerApproval {
    harness
        .host
        .h4_expected_approval(launch)
        .expect("expected approval")
}

fn positive_registry(approval: H4OwnerApproval) -> ScriptedH4OwnerApprovalRegistry {
    let mut registry = ScriptedH4OwnerApprovalRegistry::new();
    registry.insert(approval);
    registry
}

/// Rebuilds one H4 approval value with a single changed field.
#[derive(Default)]
struct ApprovalChange {
    owner: Option<OwnerRef>,
    execution: Option<String>,
    task_stable_id: Option<String>,
    task_number: Option<u32>,
    plan_revision: Option<u64>,
    plan_digest: Option<ContentDigest>,
    task_body_digest: Option<ContentDigest>,
    global_constraints_digest: Option<ContentDigest>,
    spec_snapshot_digest: Option<ContentDigest>,
    pack_fingerprint: Option<ContentDigest>,
    commit: Option<H4CommitAuthorization>,
    condition_version: Option<u64>,
    conditions_digest: Option<ConditionDigest>,
    scope: Option<ExecutionScope>,
    profile: Option<ProfileBinding>,
    consent: Option<ConsentBinding>,
    budget_policy_version: Option<u64>,
    budget: Option<BudgetPolicy>,
}

fn changed_approval(base: &H4OwnerApproval, change: ApprovalChange) -> H4OwnerApproval {
    let packet = herspecific_packet(base, &change);
    let execution = change
        .execution
        .clone()
        .map(|reference| H4ExecutionRef::new(reference).expect("execution ref"))
        .unwrap_or_else(|| base.execution().clone());
    let task = H4TaskRef::new(
        change
            .task_stable_id
            .clone()
            .unwrap_or_else(|| base.task().stable_id().to_owned()),
        change.task_number.unwrap_or_else(|| base.task().number()),
    )
    .expect("task ref");
    H4OwnerApproval::new(
        base.project_id(),
        change.owner.clone().unwrap_or_else(|| base.owner().clone()),
        execution,
        task,
        change.plan_revision.unwrap_or_else(|| base.plan_revision()),
        change
            .plan_digest
            .clone()
            .unwrap_or_else(|| base.plan_digest().clone()),
        packet,
        change
            .pack_fingerprint
            .clone()
            .unwrap_or_else(|| base.pack_fingerprint().clone()),
        change.commit.unwrap_or_else(|| base.commit()),
        herness_supervision::conditions::ConditionVersion::new(
            change
                .condition_version
                .unwrap_or_else(|| base.condition_version().get()),
        )
        .expect("condition version"),
        change
            .conditions_digest
            .clone()
            .unwrap_or_else(|| base.conditions_digest().clone()),
        change
            .scope
            .clone()
            .unwrap_or_else(|| base.execution_scope().clone()),
        change.profile.unwrap_or_else(|| base.profile()),
        change.consent.unwrap_or_else(|| base.consent()),
        change
            .budget_policy_version
            .unwrap_or_else(|| base.budget_policy_version()),
        change
            .budget
            .clone()
            .unwrap_or_else(|| base.budget().clone()),
    )
    .expect("changed approval")
}

fn herspecific_packet(
    base: &H4OwnerApproval,
    change: &ApprovalChange,
) -> herness_supervision::owner_launch::H4PacketBinding {
    herness_supervision::owner_launch::H4PacketBinding::new(
        change
            .task_body_digest
            .clone()
            .unwrap_or_else(|| base.packet().task_body_digest().clone()),
        change
            .global_constraints_digest
            .clone()
            .unwrap_or_else(|| base.packet().global_constraints_digest().clone()),
        change
            .spec_snapshot_digest
            .clone()
            .unwrap_or_else(|| base.packet().spec_snapshot_digest().clone()),
    )
}

fn rejected(
    registry: &ScriptedH4OwnerApprovalRegistry,
    binding: &H4OwnerLaunchBinding,
) -> OwnerLaunchRejection {
    match authorize_h4_owner_launch(registry, binding, Timestamp::now()) {
        Err(SupervisionError::OwnerLaunchRejected { reason }) => reason,
        other => panic!("expected an owner launch rejection, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Registry match: the blanket refusal is not cleared without an implementation.
// ---------------------------------------------------------------------------

#[test]
fn h3_registry_and_unconfigured_h4_registry_keep_h4_approval_unavailable() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();

    // The H3-shaped registry cannot authorize an H4 owner even when its entry is
    // built from an H4-shaped approval for the same owner.
    let h4_owner = OwnerRef::new(OwnerKind::H4SddTask, "task-8-fixture").expect("owner");
    let h3_contract = owner_contract(
        harness.project,
        h4_owner,
        OwnerApprovalSource::H4ApprovedPlan,
    );
    let h3_binding =
        OwnerLaunchBinding::from_contract(&h3_contract, 1, 1, "task-8").expect("binding");
    let mut h3_registry = ScriptedOwnerApprovalRegistry::new();
    h3_registry.insert(h3_binding.approval().clone());
    assert_eq!(
        rejected_h3(&h3_registry, &h3_binding),
        OwnerLaunchRejection::H4ApprovalUnavailable
    );

    // The explicit "not composed" port refuses with the same variant.
    let binding = H4OwnerLaunchBinding::new(launch.supervision_id(), expected(&harness, &launch))
        .expect("H4 binding");
    assert_eq!(
        rejected(&ScriptedH4OwnerApprovalRegistry::new(), &binding),
        OwnerLaunchRejection::MissingRegistryEntry
    );
    assert_eq!(
        rejected_unconfigured(&binding),
        OwnerLaunchRejection::H4ApprovalUnavailable
    );

    // An empty H4 registry creates nothing through the desktop start path.
    let empty = ScriptedH4OwnerApprovalRegistry::new();
    assert!(
        harness
            .host
            .start_h4_task(&mut harness.runtime, &empty, &launch)
            .is_err()
    );
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.children_created, 0);
    assert_eq!(harness.runtime.run_count(), 0);
}

fn rejected_h3(
    registry: &ScriptedOwnerApprovalRegistry,
    binding: &OwnerLaunchBinding,
) -> OwnerLaunchRejection {
    match authorize_owner_launch(registry, binding, Timestamp::now()) {
        Err(SupervisionError::OwnerLaunchRejected { reason }) => reason,
        other => panic!("expected an owner launch rejection, got {other:?}"),
    }
}

fn rejected_unconfigured(binding: &H4OwnerLaunchBinding) -> OwnerLaunchRejection {
    match authorize_h4_owner_launch(&UnconfiguredH4ApprovalRegistry, binding, Timestamp::now()) {
        Err(SupervisionError::OwnerLaunchRejected { reason }) => reason,
        other => panic!("expected an owner launch rejection, got {other:?}"),
    }
}

#[test]
fn fake_owner_and_foreign_entry_never_authorize_an_h4_launch() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();
    let base = expected(&harness, &launch);
    let binding =
        H4OwnerLaunchBinding::new(launch.supervision_id(), base.clone()).expect("binding");

    // An entry registered for another H4 owner is not this Task's approval.
    let other_owner = OwnerRef::new(OwnerKind::H4SddTask, "task-99-fixture").expect("owner");
    let foreign = changed_approval(
        &base,
        ApprovalChange {
            owner: Some(other_owner),
            ..ApprovalChange::default()
        },
    );
    assert_eq!(
        rejected(&positive_registry(foreign), &binding),
        OwnerLaunchRejection::MissingRegistryEntry
    );

    // An H4 approval value cannot even be built for an H3 or human owner.
    let h3_owner = OwnerRef::new(OwnerKind::H3HtmlJob, "h3-job-fixture").expect("H3 owner");
    assert_eq!(
        match H4OwnerApproval::new(
            harness.project,
            h3_owner,
            base.execution().clone(),
            base.task().clone(),
            base.plan_revision(),
            base.plan_digest().clone(),
            base.packet().clone(),
            base.pack_fingerprint().clone(),
            base.commit(),
            base.condition_version(),
            base.conditions_digest().clone(),
            base.execution_scope().clone(),
            base.profile(),
            base.consent(),
            base.budget_policy_version(),
            base.budget().clone(),
        ) {
            Err(SupervisionError::OwnerLaunchRejected { reason }) => reason,
            other => panic!("expected an owner launch rejection, got {other:?}"),
        },
        OwnerLaunchRejection::OwnerNotApproved
    );

    // The desktop start path creates nothing for a foreign entry.
    assert!(
        harness
            .host
            .start_h4_task(
                &mut harness.runtime,
                &ScriptedH4OwnerApprovalRegistry::new(),
                &launch,
            )
            .is_err()
    );
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.children_created, 0);
}

#[test]
fn every_mismatched_registry_constraint_is_a_distinct_refusal() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();
    let base = expected(&harness, &launch);
    let binding =
        H4OwnerLaunchBinding::new(launch.supervision_id(), base.clone()).expect("binding");

    let other_scope = ExecutionScope::new(
        harness.project,
        vec!["src/main.rs".to_owned()],
        vec!["src".to_owned()],
        true,
    )
    .expect("scope");
    let other_profile = ProfileBinding::new(
        base.profile().profile_id(),
        ProfileVersion::new(2).expect("version"),
        ProfilePurpose::Completion,
    );
    let other_consent = ConsentBinding::new(
        base.consent().consent_id(),
        2,
        ProfilePurpose::Completion,
        TargetVersion::new(1).expect("version"),
    );

    let cases: Vec<(H4OwnerApproval, OwnerLaunchRejection)> = vec![
        (
            changed_approval(
                &base,
                ApprovalChange {
                    execution: Some(
                        "execution:00000000-0000-4000-8000-000000000000:00000000-0000-4000-8000-000000000000"
                            .to_owned(),
                    ),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::ExecutionMismatch,
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    task_stable_id: Some(
                        "task:00000000-0000-4000-8000-000000000000:00000000-0000-4000-8000-000000000000"
                            .to_owned(),
                    ),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::TaskMismatch,
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    task_number: Some(2),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::TaskMismatch,
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    plan_revision: Some(2),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::StalePlanRevision {
                requested: 1,
                registered: 2,
            },
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    plan_digest: Some(ContentDigest::sha256(b"another plan")),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::PlanDigestMismatch,
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    task_body_digest: Some(ContentDigest::sha256(b"another body")),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::PacketMismatch {
                field: "taskBodyDigest".to_owned(),
            },
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    global_constraints_digest: Some(ContentDigest::sha256(b"another constraints")),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::PacketMismatch {
                field: "globalConstraintsDigest".to_owned(),
            },
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    spec_snapshot_digest: Some(ContentDigest::sha256(b"another snapshot")),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::PacketMismatch {
                field: "specSnapshotDigest".to_owned(),
            },
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    pack_fingerprint: Some(ContentDigest::sha256(b"another pack")),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::PackFingerprintMismatch,
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    commit: Some(
                        serde_json::from_str::<H4CommitAuthorization>(
                            r#"{"hostCommit":true,"runHooks":false}"#,
                        )
                        .expect("decoded commit approval"),
                    ),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::CommitAuthorizationMismatch,
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    condition_version: Some(2),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::StaleConditions {
                requested: 1,
                registered: 2,
            },
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    conditions_digest: Some(ConditionDigest::sha256(b"other conditions")),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::ConditionDigestMismatch,
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    scope: Some(other_scope),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::ScopeMismatch,
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    profile: Some(other_profile),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::ProfileMismatch,
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    consent: Some(other_consent),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::ConsentMismatch,
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    budget_policy_version: Some(2),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::BudgetPolicyVersionMismatch {
                requested: 1,
                registered: 2,
            },
        ),
        (
            changed_approval(
                &base,
                ApprovalChange {
                    budget: Some(BudgetPolicy::new(3_600, 1, None).expect("budget")),
                    ..ApprovalChange::default()
                },
            ),
            OwnerLaunchRejection::BudgetMismatch,
        ),
    ];

    for (registered, refusal) in cases {
        let registry = positive_registry(registered);
        assert_eq!(
            rejected(&registry, &binding),
            refusal,
            "each mismatch must be its own refusal"
        );
        let outcome = harness
            .host
            .start_h4_task(&mut harness.runtime, &registry, &launch);
        assert!(outcome.is_err(), "a mismatched entry must not start");
        assert_eq!(harness.runtime.starts, 0);
        assert_eq!(harness.runtime.children_created, 0);
        assert_eq!(harness.runtime.run_count(), 0);
    }

    // Host-commit and hook approval are both mandatory.
    assert!(matches!(
        H4CommitAuthorization::new(false, true),
        Err(SupervisionError::InvalidValue { .. })
    ));
    assert!(matches!(
        H4CommitAuthorization::new(true, false),
        Err(SupervisionError::InvalidValue { .. })
    ));
}

#[test]
fn revoked_live_consent_blocks_the_launch() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();
    let registry = positive_registry(expected(&harness, &launch));

    harness.revoke_completion();
    assert!(matches!(
        harness
            .host
            .start_h4_task(&mut harness.runtime, &registry, &launch),
        Err(SupervisionError::ConsentBlocked {
            reason: ConsentBlock::Revoked
        })
    ));
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.children_created, 0);
    assert_eq!(harness.runtime.run_count(), 0);
}

#[test]
fn h3_approved_conditions_never_authorize_an_h4_task() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);

    // Conditions approved by an H3 owner, not by this H4 Task.
    let execution = ExecutionId::new(harness.project);
    let task = TaskRef::new(
        TaskStableId::new(harness.project),
        TaskNumber::new(1).unwrap(),
    );
    let h3_owner = OwnerRef::new(OwnerKind::H3HtmlJob, "h3-job-fixture").expect("H3 owner");
    let mut conditions = condition_set(harness.project);
    let approval = ConditionApproval::new(
        harness.project,
        ApprovalBasis::InheritedOwner {
            owner: h3_owner.clone(),
            source: OwnerApprovalSource::H3ApprovedSettings,
            approved_at: now(),
            expires_at: None,
        },
        conditions.condition_version(),
        conditions.digest().clone(),
    )
    .expect("H3 condition approval");
    conditions
        .approve(
            ApprovalActor::ApprovedOwner {
                owner: h3_owner,
                source: OwnerApprovalSource::H3ApprovedSettings,
            },
            approval,
            now(),
        )
        .expect("approve");
    let scope = ExecutionScope::new(
        harness.project,
        vec!["src/main.rs".to_owned()],
        vec!["src".to_owned()],
        false,
    )
    .expect("scope");
    let launch = H4TaskLaunch::new(
        execution,
        task,
        DispatchRequestId::new(harness.project),
        SupervisionId::new(harness.project),
        harness.connection,
        "Implement the approved Task.",
        conditions,
        scope,
        TargetVersion::new(1).expect("target version"),
        BudgetPolicy::h2_default(),
        1,
        launch_request(execution, task),
    )
    .expect("H4 launch");

    // Even a matching H4 registry entry cannot authorize H3-approved conditions:
    // the request-side expectation is refused before the registry is consulted.
    let registry = ScriptedH4OwnerApprovalRegistry::new();
    assert!(matches!(
        harness
            .host
            .h4_expected_approval(&launch)
            .expect_err("H3 conditions are not this Task's approval"),
        SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::OwnerNotApproved
        }
    ));
    assert!(matches!(
        harness
            .host
            .start_h4_task(&mut harness.runtime, &registry, &launch),
        Err(SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::OwnerNotApproved
        })
    ));
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.children_created, 0);
    assert_eq!(harness.runtime.run_count(), 0);
}

// ---------------------------------------------------------------------------
// Positive start and idempotent re-delivery.
// ---------------------------------------------------------------------------

#[test]
fn matching_h4_registry_starts_exactly_one_run() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();
    let registry = positive_registry(expected(&harness, &launch));

    let outcome = harness
        .host
        .start_h4_task(&mut harness.runtime, &registry, &launch)
        .expect("start");
    match &outcome {
        H4TaskStartOutcome::Ready {
            created_target,
            started_run,
            view,
        } => {
            assert!(*created_target, "the reserved target must be created once");
            assert!(*started_run, "the first run must start");
            assert_eq!(view.state, "running");
            assert_eq!(view.run_group.len(), 1);
        }
        other => panic!("expected a ready outcome, got {other:?}"),
    }
    assert_eq!(harness.runtime.children_created, 1);

    // The H2 start records the run; the runtime start happens on the pump.
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump");
    assert_eq!(harness.runtime.starts, 1);
    assert_eq!(harness.runtime.run_count(), 1);

    // The reservation is the one durable mapping for this dispatch request.
    let reservation = harness
        .host
        .h4_task_reservation(harness.project, launch.execution(), launch.dispatch())
        .expect("reservation lookup")
        .expect("reservation");
    assert_eq!(reservation.supervision_id(), launch.supervision_id());
    assert_eq!(reservation.task(), launch.task());
    assert_eq!(reservation.request_id(), launch.dispatch());

    // A re-delivered start request returns the recorded result without a second
    // child or a second run.
    let repeated = harness
        .host
        .start_h4_task(&mut harness.runtime, &registry, &launch)
        .expect("duplicate start");
    match repeated {
        H4TaskStartOutcome::Ready {
            created_target,
            started_run,
            view,
        } => {
            assert!(!created_target);
            assert!(!started_run, "a duplicate request must not start a run");
            assert_eq!(view.run_group.len(), 1);
        }
        other => panic!("expected a ready outcome, got {other:?}"),
    }
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump again");
    assert_eq!(harness.runtime.starts, 1);
    assert_eq!(harness.runtime.children_created, 1);
    assert_eq!(harness.runtime.run_count(), 1);
}

#[test]
fn human_and_h3_starts_still_work_after_the_h4_seam() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);

    // Human start path (unchanged): create plus explicit confirmation.
    let request = harness.create_request();
    let view = harness
        .host
        .create(
            &mut harness.runtime,
            PlanRequestActor::Human,
            request,
            Some(harness.host.confirm(ConfirmationKind::Create)),
        )
        .expect("human create");
    let started = harness
        .host
        .start(
            &mut harness.runtime,
            harness.project,
            view.supervision_id,
            SupervisionRequestId::new(harness.project),
            view.revision,
            Some(harness.host.confirm(ConfirmationKind::Start)),
        )
        .expect("human start");
    assert_eq!(started.state, "running");
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump");
    assert_eq!(harness.runtime.starts, 1);

    // H3 owner authority is still minted by the H3 registry and unchanged.
    let owner = OwnerRef::new(OwnerKind::H3HtmlJob, "h3-job-1").expect("H3 owner");
    let contract = owner_contract(
        harness.project,
        owner,
        OwnerApprovalSource::H3ApprovedSettings,
    );
    let binding =
        OwnerLaunchBinding::from_contract(&contract, 1, 1, "h3-job-1").expect("H3 binding");
    let mut registry = ScriptedOwnerApprovalRegistry::new();
    registry.insert(binding.approval().clone());
    assert!(
        authorize_owner_launch(&registry, &binding, Timestamp::now()).is_ok(),
        "the H3 path must keep working"
    );
}

// ---------------------------------------------------------------------------
// Crash boundaries and unknown mappings.
// ---------------------------------------------------------------------------

#[test]
fn crash_before_the_reservation_records_one_run() {
    // A crash before the launch intent leaves no durable fact at all. The next
    // attempt creates exactly one child and one run.
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();
    let registry = positive_registry(expected(&harness, &launch));

    assert!(
        harness
            .host
            .h4_task_reservation(harness.project, launch.execution(), launch.dispatch())
            .expect("reservation lookup")
            .is_none()
    );
    harness
        .host
        .start_h4_task(&mut harness.runtime, &registry, &launch)
        .expect("start after crash");
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump");
    assert_eq!(harness.runtime.children_created, 1);
    assert_eq!(harness.runtime.starts, 1);
    assert_eq!(harness.runtime.run_count(), 1);
}

#[test]
fn crash_after_reservation_before_creation_reuses_the_reserved_child() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();
    let registry = positive_registry(expected(&harness, &launch));

    // The coordinator reserved the mapping before any target existed.
    let reservation = harness
        .host
        .reserve_h4_task(&mut harness.runtime, &registry, &launch)
        .expect("reserve")
        .reservation()
        .copied()
        .expect("reservation");
    assert_eq!(harness.runtime.children_created, 1);
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.run_count(), 0);
    assert_eq!(
        reservation.supervision_id(),
        launch.supervision_id(),
        "the reservation fixes the one supervision id"
    );

    // The next attempt creates the target from the reserved child, then starts
    // exactly one run.
    match harness
        .host
        .start_h4_task(&mut harness.runtime, &registry, &launch)
        .expect("start")
    {
        H4TaskStartOutcome::Ready {
            created_target,
            started_run,
            ..
        } => {
            assert!(created_target);
            assert!(started_run);
        }
        other => panic!("expected a ready outcome, got {other:?}"),
    }
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump");
    assert_eq!(
        harness.runtime.children_created, 1,
        "the reserved child must be reused, not recreated"
    );
    assert_eq!(harness.runtime.starts, 1);
    assert_eq!(harness.runtime.run_count(), 1);
}

#[test]
fn crash_after_creation_before_result_records_one_run() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();
    let registry = positive_registry(expected(&harness, &launch));

    // The target was created but the start result was never recorded.
    match harness
        .host
        .ensure_h4_task_target(&mut harness.runtime, &registry, &launch)
        .expect("ensure")
    {
        H4TaskStartOutcome::Ready {
            created_target,
            started_run,
            ..
        } => {
            assert!(created_target);
            assert!(!started_run);
        }
        other => panic!("expected a ready outcome, got {other:?}"),
    }
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.run_count(), 0);

    // The next attempt must not create a second child or a second target.
    harness
        .host
        .start_h4_task(&mut harness.runtime, &registry, &launch)
        .expect("start after crash");
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump");
    assert_eq!(harness.runtime.children_created, 1);
    assert_eq!(harness.runtime.starts, 1);
    assert_eq!(harness.runtime.run_count(), 1);
    assert_eq!(
        harness.host.list(harness.project).expect("list").len(),
        1,
        "exactly one supervision target exists"
    );
}

#[test]
fn crash_between_plan_save_and_target_record_finishes_one_creation() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();
    let registry = positive_registry(expected(&harness, &launch));

    // Reserve the one child first, so the fault hits the target creation.
    harness
        .host
        .reserve_h4_task(&mut harness.runtime, &registry, &launch)
        .expect("reserve");
    assert_eq!(harness.runtime.children_created, 1);

    // The plan is written, but recording the target fails: the classic
    // "created but not recorded" boundary.
    harness
        .store
        .lock()
        .set_commit_fault(Some(herness_store::test_support::CommitFault::BeforeRows));
    assert!(
        harness
            .host
            .start_h4_task(&mut harness.runtime, &registry, &launch)
            .is_err()
    );
    harness.store.lock().set_commit_fault(None);
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.run_count(), 0);

    // The next attempt must finish the same target and start one run, without a
    // second child.
    match harness
        .host
        .start_h4_task(&mut harness.runtime, &registry, &launch)
        .expect("start after crash")
    {
        H4TaskStartOutcome::Ready {
            created_target,
            started_run,
            ..
        } => {
            assert!(created_target);
            assert!(started_run);
        }
        other => panic!("expected a ready outcome, got {other:?}"),
    }
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump");
    assert_eq!(harness.runtime.children_created, 1);
    assert_eq!(harness.runtime.starts, 1);
    assert_eq!(harness.runtime.run_count(), 1);
}

#[test]
fn unknown_mapping_waits_without_creating_a_child() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();
    let registry = positive_registry(expected(&harness, &launch));

    // A recorded intent without a reservation is an unknown correspondence.
    let intent = H4LaunchIntent::new(
        launch.execution(),
        launch.task(),
        launch.dispatch(),
        launch.supervision_id(),
        launch.approval().plan_revision(),
        launch.approval().plan_digest(),
    )
    .expect("intent");
    harness
        .host
        .record_h4_launch_intent(&intent)
        .expect("record intent");

    match harness
        .host
        .start_h4_task(&mut harness.runtime, &registry, &launch)
        .expect("start")
    {
        H4TaskStartOutcome::Reconcile {
            supervision_id,
            dispatch,
            reason,
        } => {
            assert_eq!(supervision_id, launch.supervision_id());
            assert_eq!(dispatch, launch.dispatch());
            assert_eq!(reason, H4ReconcileReason::CreationUnconfirmed);
        }
        other => panic!("expected a reconcile outcome, got {other:?}"),
    }
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.children_created, 0);
    assert_eq!(harness.runtime.run_count(), 0);

    // An intent that names another target is a conflict, not a new child.
    let conflicting = H4LaunchIntent::new(
        launch.execution(),
        launch.task(),
        launch.dispatch(),
        SupervisionId::new(harness.project),
        launch.approval().plan_revision(),
        launch.approval().plan_digest(),
    )
    .expect("intent");
    harness
        .host
        .record_h4_launch_intent(&conflicting)
        .expect("record conflicting intent");
    assert!(matches!(
        harness
            .host
            .start_h4_task(&mut harness.runtime, &registry, &launch),
        Err(SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::ReservationConflict
        })
    ));
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.children_created, 0);
}

#[test]
fn restored_target_still_requires_a_human_restart() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let launch = harness.launch();
    let registry = positive_registry(expected(&harness, &launch));

    // Create the target without starting a run, then restart the host.
    harness
        .host
        .ensure_h4_task_target(&mut harness.runtime, &registry, &launch)
        .expect("ensure");
    assert_eq!(harness.runtime.starts, 0);

    let save_path = harness.store_path.clone();
    let project = harness.project;
    let supervision = launch.supervision_id();
    let project_root = harness.project_root.clone();
    drop(harness.host);
    drop(harness.runtime);
    drop(harness.store);

    let config = StoreConfig::new(&save_path).expect("reopen config");
    let store = Store::open(config).expect("reopen store");
    let store = StoreHandle::new(Arc::new(std::sync::Mutex::new(store)));
    let assessment_host = AssessmentHost {
        directory: harness.admin.directory(),
        credentials: Arc::new(NoCredentials),
        endpoints: loopback_assessment_endpoints(),
    };
    let mut host = SupervisionHost::with_config_for_test(
        store.clone(),
        ConfigStore::new(),
        assessment_host,
        Box::new(UnverifiedAssessment),
        Box::new(UnavailableCheck),
    );
    host.restore(&[project]);
    let mut runtime = FakeRuntime::new(store.clone(), project, project_root);

    // The restored target is not auto-started, even with a matching registry.
    assert!(matches!(
        host.start_h4_task(&mut runtime, &registry, &launch),
        Err(SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::RestoredTarget
        })
    ));
    assert_eq!(runtime.starts, 0);

    // A human restart still works.
    let view = host.get(project, supervision).expect("view");
    host.start(
        &mut runtime,
        project,
        supervision,
        SupervisionRequestId::new(project),
        view.revision,
        Some(host.confirm(ConfirmationKind::Start)),
    )
    .expect("human restart");
    host.pump(&mut runtime, &[project])
        .expect("pump human start");
    assert_eq!(runtime.starts, 1);
}
