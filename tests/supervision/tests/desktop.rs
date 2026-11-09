//! Task 16 desktop supervision composition tests.
//!
//! These tests exercise the library composition without a Tauri window. The
//! H1 runtime, required-check execution, and assessment transport are scripted
//! fakes; the store, command journal, recovery facts, budget ledger, and
//! protection boundaries are the real implementations. No provider,
//! credential, Keychain item, shell, or GUI session is used.

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
use herness_desktop::guard::{self, GuardError, Navigation};
use herness_desktop::supervision::ChangeSupervisionRequest;
use herness_desktop::supervision::assessment::AssessmentHost;
use herness_desktop::supervision::plan::ConfigStore;
use herness_desktop::supervision::runtime::{ChildIdentity, DesktopSupervisionRuntime};use herness_desktop::supervision::store::StoreHandle;
use herness_desktop::supervision::{
    CheckInput, ConditionInput, ConfirmationKind, CreateSupervisionRequest, PlanRequestActor,
    SupersedeSupervisionRequest, SupervisionHost,
};
use herness_store::test_support::CommitFault;
use herness_store::{Store, StoreConfig};
use herness_supervision::operations::SupervisionOperationRequest;
use herness_supervision::operations::{HumanOperation, OperationRuntimePort};
use herness_supervision::owner_launch::{
    HostOwnerAuthority, OwnerLaunchBinding, authorize_owner_launch,
};
use herness_supervision::ports::SupervisionStorePort;
use herness_supervision::recovery::{
    ManagedProcessState, RecoveryCheckpoint, RecoveryRuntimePort, RecoveryStopState,
};
use herness_supervision::supervisor::{
    AssessmentProfileFacts, CheckExecution, CheckExecutionRequest, ChildRunContinuation,
    ChildRunStart, ConditionAssessmentPort, RequiredCheckPort, StopDisposition,
    SupervisionRuntimePort, TargetSnapshotRequest, capture_target_snapshot,
};
use herness_supervision::{
    AdapterVersion, AssessmentOutcome, AssessmentProvenance, AssessmentRequest, AssessmentResult,
    ChangeKind, CheckStatus, ConditionVerdict, DisclosureDataKind, EvidenceAcquirer, EvidenceOutcome,
    EvidenceRecord, EvidenceScope, OwnerApprovalSource, OwnerKind, OwnerLaunchRejection,
    OwnerRef, OwnerSupersessionRejection, ProfilePurpose, ProfileThresholds, ProviderKind,
    ProviderOrigin, RubricVersion, SupervisionError, SupervisionId, SupervisionRecord,
    SupervisionRequestId, TargetReadSet, TargetVersion, WorkPacketRejection,
};
use herness_supervision_tests::ScriptedOwnerApprovalRegistry;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Fake credentials and runtime.
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

struct FakeRuntime {
    store: StoreHandle,
    roots: BTreeMap<ProjectId, PathBuf>,
    children: BTreeMap<ProjectId, ChildIdentity>,
    runs: BTreeMap<RunId, FakeRun>,
    starts: usize,
    continuations: usize,
    stops: usize,
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
            starts: 0,
            continuations: 0,
            stops: 0,
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

    fn complete_all_inputs(&mut self) {
        for run in self.runs.values_mut() {
            for phase in run.inputs.values_mut() {
                *phase = InputPhase::Completed;
            }
        }
    }

    fn set_all_idle(&mut self) {
        for run in self.runs.values_mut() {
            run.state = RunState::Idle;
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
        self.continuations += 1;
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
        self.stops += 1;
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

impl OperationRuntimePort for FakeRuntime {
    fn request_stop(&mut self, run: RunId) -> Result<StopDisposition, SupervisionError> {
        <Self as SupervisionRuntimePort>::request_stop(self, run)
    }
}

impl DesktopSupervisionRuntime for FakeRuntime {
    fn create_child(
        &mut self,
        project: ProjectId,
        _connection: ConnectionId,
        _scope: &herness_supervision::ExecutionScope,
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
}

// ---------------------------------------------------------------------------
// Fake checks and assessment.
// ---------------------------------------------------------------------------

struct UnavailableCheck;

impl RequiredCheckPort for UnavailableCheck {
    fn execute(
        &mut self,
        request: &CheckExecutionRequest,
    ) -> Result<CheckExecution, SupervisionError> {
        let result = herness_supervision::RequiredCheckResult::new(
            request.check_id(),
            request.condition_id(),
            CheckStatus::Unavailable,
            None,
            request.condition_version(),
            request.target_version(),
            Timestamp::now(),
        )?;
        Ok(CheckExecution::new(result, None))
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
        let manifest = herness_supervision::freshness::capture_manifest(
            &workspace,
            request.project_id(),
            request.target_version(),
            TargetReadSet::Declared(request.read_set().to_vec()),
        )?;
        let target = manifest.target_scope()?;
        let evidence = EvidenceRecord::new(
            request.evidence_id(),
            request.supervision_id(),
            Some(request.condition_id()),
            Some(request.check_id()),
            EvidenceAcquirer::ChildAgent,
            request.operation().clone(),
            EvidenceOutcome::new(Some(0), None, false, false, "exit=0")?,
            target,
            EvidenceScope::new(
                vec![format!("check: {}", request.check_id())],
                vec!["scripted check evidence".to_owned()],
            )?,
            CheckStatus::Pass,
            request.sequence(),
            Timestamp::now(),
        )?;
        let result = herness_supervision::RequiredCheckResult::from_evidence(
            &evidence,
            request.condition_version(),
        )?;
        Ok(CheckExecution::new(result, Some(evidence)))
    }
}

struct UnverifiedAssessment;

impl ConditionAssessmentPort for UnverifiedAssessment {
    fn profile(
        &self,
        _binding: herness_supervision::ProfileBinding,
    ) -> Result<AssessmentProfileFacts, SupervisionError> {
        Err(SupervisionError::Unsupported {
            feature: "assessment profile is not verified".to_owned(),
        })
    }

    fn assess(
        &mut self,
        _request: &AssessmentRequest,
    ) -> Result<AssessmentResult, SupervisionError> {
        Err(SupervisionError::Unsupported {
            feature: "assessment profile is not verified".to_owned(),
        })
    }
}

struct MetAssessment;

impl ConditionAssessmentPort for MetAssessment {
    fn profile(
        &self,
        _binding: herness_supervision::ProfileBinding,
    ) -> Result<AssessmentProfileFacts, SupervisionError> {
        Ok(AssessmentProfileFacts::new(
            AdapterVersion::new("herness-llm-condition-v1")?,
            RubricVersion::new("herness-conditions-v1")?,
            ProfileThresholds::normal_llm(),
        ))
    }

    fn assess(
        &mut self,
        request: &AssessmentRequest,
    ) -> Result<AssessmentResult, SupervisionError> {
        assessment_result_with(request, ConditionVerdict::Met)
    }
}

struct UnmetAssessment;

impl ConditionAssessmentPort for UnmetAssessment {
    fn profile(
        &self,
        _binding: herness_supervision::ProfileBinding,
    ) -> Result<AssessmentProfileFacts, SupervisionError> {
        Ok(AssessmentProfileFacts::new(
            AdapterVersion::new("herness-llm-condition-v1")?,
            RubricVersion::new("herness-conditions-v1")?,
            ProfileThresholds::normal_llm(),
        ))
    }

    fn assess(
        &mut self,
        request: &AssessmentRequest,
    ) -> Result<AssessmentResult, SupervisionError> {
        assessment_result_with(request, ConditionVerdict::Unmet)
    }
}

fn assessment_result_with(
    request: &AssessmentRequest,
    verdict: ConditionVerdict,
) -> Result<AssessmentResult, SupervisionError> {
    let provenance = AssessmentProvenance::new(
        herness_core::Provider::OpenAi,
        ProviderKind::NormalLlm,
        herness_core::ModelId::new("judge-model").expect("static model"),
        request.adapter_version().clone(),
        request.rubric_version().clone(),
    )?;
    AssessmentResult::new(
        request,
        request.evidence().to_vec(),
        "scripted verdict",
        None,
        AssessmentOutcome::NormalLlm {
            verdict,
            confidence: None,
        },
        provenance,
        Timestamp::now(),
    )
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
}

fn supersede_request(
    project: ProjectId,
    supervision: SupervisionId,
    expected_revision: u64,
    target_version: u64,
) -> SupersedeSupervisionRequest {
    SupersedeSupervisionRequest {
        request_id: SupervisionRequestId::new(project),
        supervision_id: supervision,
        expected_revision,
        target_version: TargetVersion::new(target_version).expect("target version"),
        conditions: None,
        condition_version: None,
        profile_purpose: None,
        consent_purpose: Some(ProfilePurpose::Completion),
        budget: None,
        settings_version: 1,
        job_id: "h3-job-1".to_owned(),
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
            checks: vec![CheckInput {
                command: "true".to_owned(),
                description: "trivial passing command".to_owned(),
            }],
        }],
        read_set: vec!["src/main.rs".to_owned()],
        write_paths: vec!["src".to_owned()],
        allow_shell: false,
        condition_version: Some(1),
        target_version: Some(1),
        budget: Some(herness_desktop::supervision::BudgetInput {
            active_seconds: 7_200,
            additional_runs: 30,
            money_limit_micros: None,
            price_version: None,
        }),
    }
}

fn harness() -> Harness {
    harness_with_check(false, AssessmentMode::Unverified)
}

fn harness_with_pass_check() -> Harness {
    harness_with_check(true, AssessmentMode::Unverified)
}

fn harness_with_completion() -> Harness {
    harness_with_check(true, AssessmentMode::Met)
}

fn harness_with_pass_check_unmet() -> Harness {
    harness_with_check(true, AssessmentMode::Unmet)
}

enum AssessmentMode {
    Unverified,
    Met,
    Unmet,
}

fn harness_with_check(pass: bool, mode: AssessmentMode) -> Harness {
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
    let config_store = ConfigStore::new();
    let check: Box<dyn RequiredCheckPort + Send> = if pass {
        Box::new(PassCheck {
            root: project_root.clone(),
        })
    } else {
        Box::new(UnavailableCheck)
    };
    let assessment: Box<dyn ConditionAssessmentPort + Send> = match mode {
        AssessmentMode::Unverified => Box::new(UnverifiedAssessment),
        AssessmentMode::Met => Box::new(MetAssessment),
        AssessmentMode::Unmet => Box::new(UnmetAssessment),
    };
    let host = SupervisionHost::with_config_for_test(
        store.clone(),
        config_store,
        assessment_host,
        assessment,
        check,
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

    fn create(&mut self) -> herness_desktop::supervision::SupervisionView {
        self.host
            .create(
                &mut self.runtime,
                PlanRequestActor::Human,
                request(self.project, self.connection),
                Some(self.host.confirm(ConfirmationKind::Create)),
            )
            .expect("create")
    }

    /// Creates a target owned by an already-approved H3 job. Creating a target
    /// does not start it and does not call the owner registry.
    fn create_h3(
        &mut self,
        job: &str,
    ) -> (herness_desktop::supervision::SupervisionView, OwnerRef) {
        let owner = OwnerRef::new(OwnerKind::H3HtmlJob, job).expect("H3 owner");
        let actor = PlanRequestActor::ApprovedOwner {
            owner: owner.clone(),
            source: OwnerApprovalSource::H3ApprovedSettings,
        };
        let view = self
            .host
            .create(
                &mut self.runtime,
                actor,
                request(self.project, self.connection),
                None,
            )
            .expect("owned create");
        (view, owner)
    }

    fn owner_binding(
        &self,
        supervision: SupervisionId,
        settings_version: u64,
        job: &str,
    ) -> OwnerLaunchBinding {
        self.host
            .owner_launch_binding(self.project, supervision, settings_version, job)
            .expect("owner binding")
    }

    fn matching_owner_registry(
        &self,
        supervision: SupervisionId,
        settings_version: u64,
        job: &str,
    ) -> ScriptedOwnerApprovalRegistry {
        let binding = self.owner_binding(supervision, settings_version, job);
        let mut registry = ScriptedOwnerApprovalRegistry::new();
        registry.insert(binding.approval().clone());
        registry
    }

    fn owner_authority(
        &self,
        supervision: SupervisionId,
        settings_version: u64,
        job: &str,
    ) -> HostOwnerAuthority {
        let binding = self.owner_binding(supervision, settings_version, job);
        let registry = self.matching_owner_registry(supervision, settings_version, job);
        authorize_owner_launch(&registry, &binding, Timestamp::now()).expect("owner authority")
    }

    fn start(
        &mut self,
        supervision: SupervisionId,
    ) -> herness_desktop::supervision::SupervisionView {
        let view = self.host.get(self.project, supervision).expect("view");
        self.host
            .start(
                &mut self.runtime,
                self.project,
                supervision,
                SupervisionRequestId::new(self.project),
                view.revision,
                Some(self.host.confirm(ConfirmationKind::Start)),
            )
            .expect("start")
    }
}

fn pump_until(
    host: &mut SupervisionHost,
    runtime: &mut FakeRuntime,
    project: ProjectId,
    predicate: impl Fn(&str) -> bool,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        host.pump(runtime, &[project]).expect("pump");
        let views = host.list(project).expect("list");
        if let Some(view) = views.first()
            && predicate(&view.state)
        {
            return view.state.clone();
        }
        assert!(Instant::now() < deadline, "pump did not converge");
        std::thread::sleep(supervision_interval());
    }
}

fn supervision_interval() -> Duration {
    herness_desktop::supervision::PUMP_INTERVAL + Duration::from_millis(20)
}

// ---------------------------------------------------------------------------
// Guard and human proof.
// ---------------------------------------------------------------------------

#[test]
fn remote_and_preview_origins_cannot_invoke_the_trusted_surface() {
    assert_eq!(
        guard::verify("main", "main", Some("tauri://localhost/index.html")),
        Ok(())
    );
    assert_eq!(
        guard::verify("preview", "preview", Some("tauri://localhost/index.html")),
        Err(GuardError::UntrustedWindow)
    );
    assert_eq!(
        guard::verify("main", "preview", Some("tauri://localhost/index.html")),
        Err(GuardError::UntrustedWebview)
    );
    assert_eq!(
        guard::verify("main", "main", Some("https://example.com/")),
        Err(GuardError::UntrustedOrigin)
    );
    assert_eq!(
        guard::classify_navigation("https://example.com/"),
        Navigation::OpenExternal
    );
}

#[test]
fn model_actor_and_missing_human_confirmation_cannot_change_conditions() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let view = harness.create();

    let change = ChangeSupervisionRequest {
        conditions: Some(vec![ConditionInput {
            title: "Changed".to_owned(),
            rubric: "Changed".to_owned(),
            checks: vec![],
        }]),
        condition_version: Some(2),
        profile_purpose: None,
        consent_purpose: None,
        budget: None,
    };
    let request_id = SupervisionRequestId::new(harness.project);

    let model = harness.host.change(
        &mut harness.runtime,
        harness.project,
        view.supervision_id,
        request_id,
        view.revision,
        PlanRequestActor::Model,
        change.clone(),
        None,
    );
    assert!(matches!(
        model,
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));

    let missing = harness.host.change(
        &mut harness.runtime,
        harness.project,
        view.supervision_id,
        request_id,
        view.revision,
        PlanRequestActor::Human,
        change,
        None,
    );
    assert!(matches!(missing, Err(SupervisionError::Unsupported { .. })));

    let latest = harness
        .host
        .get(harness.project, view.supervision_id)
        .expect("view");
    assert_eq!(latest.revision, view.revision);
    assert_eq!(latest.condition_version, 1);
}

#[test]
fn profile_configuration_requires_a_human_confirmation() {
    let harness = harness();
    let model = harness.host.configure_profile(
        PlanRequestActor::Model,
        harness.project,
        ProfilePurpose::Completion,
        harness.connection,
        "judge-model",
        None,
    );
    assert!(matches!(
        model,
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));

    let missing = harness.host.configure_profile(
        PlanRequestActor::Human,
        harness.project,
        ProfilePurpose::Completion,
        harness.connection,
        "judge-model",
        None,
    );
    assert!(matches!(missing, Err(SupervisionError::Unsupported { .. })));
}

// ---------------------------------------------------------------------------
// Per-purpose profile and consent.
// ---------------------------------------------------------------------------

#[test]
fn per_purpose_profiles_and_consents_are_independent_and_consent_revocation_is_explicit() {
    let mut harness = harness();
    for purpose in [
        ProfilePurpose::Completion,
        ProfilePurpose::Html,
        ProfilePurpose::Permission,
    ] {
        harness
            .host
            .configure_profile(
                PlanRequestActor::Human,
                harness.project,
                purpose,
                harness.connection,
                "judge-model",
                Some(harness.host.confirm(ConfirmationKind::Profile)),
            )
            .expect("profile");
        harness
            .host
            .grant_consent(
                PlanRequestActor::Human,
                harness.project,
                purpose,
                ProviderOrigin::parse("https://api.openai.com").expect("origin"),
                BTreeSet::from([DisclosureDataKind::Text]),
                vec!["src/main.rs".to_owned()],
                TargetVersion::new(1).expect("version"),
                Some(harness.host.confirm(ConfirmationKind::Consent)),
            )
            .expect("consent");
    }
    harness
        .host
        .revoke_consent(
            PlanRequestActor::Human,
            harness.project,
            ProfilePurpose::Html,
            Some(harness.host.confirm(ConfirmationKind::Consent)),
        )
        .expect("revoke html");

    let view = harness.create();
    let status = |purpose: &str| {
        view.purposes
            .iter()
            .find(|status| status.purpose == purpose)
            .expect("purpose")
    };
    assert_eq!(status("completion").consent_state, "granted");
    assert_eq!(status("html").consent_state, "revoked");
    assert_eq!(status("permission").consent_state, "granted");
    assert!(status("completion").profile_id.is_some());
    assert!(status("html").profile_id.is_some());
    assert!(status("permission").profile_id.is_some());
    assert!(!status("completion").verified);
}

#[test]
fn unverified_profiles_are_displayed_as_unverified_and_never_start_a_model_request() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let view = harness.create();
    let completion = view
        .purposes
        .iter()
        .find(|status| status.purpose == "completion")
        .expect("completion");
    assert!(completion.profile_id.is_some());
    assert!(!completion.verified);
    assert_eq!(view.state, "ready");
    assert_eq!(harness.runtime.starts, 0);
}

// ---------------------------------------------------------------------------
// Create/start/pump and waiting-human.
// ---------------------------------------------------------------------------

#[test]
fn real_assessment_port_returns_unverified_without_any_network_request() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let view = harness.create();
    let port = herness_desktop::supervision::assessment::HostAssessmentPort::new(
        harness.store.clone(),
        harness.host.config(),
        AssessmentHost {
            directory: harness.admin.directory(),
            credentials: Arc::new(NoCredentials),
            endpoints: loopback_assessment_endpoints(),
        },
    );
    let error = port
        .profile(view.profile)
        .expect_err("an unverified profile must not resolve");
    assert!(matches!(
        error,
        SupervisionError::Unsupported { .. } | SupervisionError::ProfileUnavailable { .. }
    ));
    harness
        .host
        .mark_profile_verified(harness.project, ProfilePurpose::Completion, true)
        .expect("mark verified");
    let facts = port.profile(view.profile).expect("verified profile facts");
    assert_eq!(facts.adapter_version().as_str(), "herness-llm-condition-v1");
}

#[test]
fn create_does_not_start_and_pump_progresses_an_explicitly_started_target() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let view = harness.create();
    assert_eq!(view.state, "ready");
    assert!(view.run_group.is_empty());
    assert_eq!(harness.runtime.starts, 0);

    // A ready target is not pumped: no child and no continuation exist.
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump ready");
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.continuations, 0);

    let started = harness.start(view.supervision_id);
    assert_eq!(started.state, "running");
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    assert_eq!(harness.runtime.starts, 1);
    assert_eq!(harness.runtime.continuations, 0);
    harness.runtime.complete_all_inputs();
    harness.runtime.set_all_idle();

    let state = pump_until(
        &mut harness.host,
        &mut harness.runtime,
        harness.project,
        |state| state == "waiting_human",
    );
    assert_eq!(state, "waiting_human");
    assert_eq!(harness.runtime.continuations, 0);
}

#[test]
fn unverified_assessment_profile_waits_for_a_human_and_never_completes() {
    let mut harness = harness_with_pass_check();
    harness.configure_completion();
    harness.grant_completion(1);
    let view = harness.create();
    let _ = harness.start(view.supervision_id);
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    harness.runtime.complete_all_inputs();
    harness.runtime.set_all_idle();
    let state = pump_until(
        &mut harness.host,
        &mut harness.runtime,
        harness.project,
        |state| state == "waiting_human",
    );
    assert_eq!(state, "waiting_human");
    let latest = harness
        .host
        .get(harness.project, view.supervision_id)
        .expect("view");
    assert!(latest.completion.is_none());
    assert_eq!(
        latest
            .reason
            .get("action")
            .and_then(|action| action.as_str()),
        Some("confirm_assessment_profile")
    );
}

#[test]
fn inconclusive_checks_are_waiting_human_not_completed() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let view = harness.create();
    let _ = harness.start(view.supervision_id);
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    harness.runtime.complete_all_inputs();
    harness.runtime.set_all_idle();
    let state = pump_until(
        &mut harness.host,
        &mut harness.runtime,
        harness.project,
        |state| state == "waiting_human",
    );
    assert_eq!(state, "waiting_human");
    let latest = harness
        .host
        .get(harness.project, view.supervision_id)
        .expect("view");
    assert_ne!(latest.state, "completed");
    assert!(latest.completion.is_none());
    assert!(matches!(
        latest.reason.get("kind").and_then(|kind| kind.as_str()),
        Some("waiting_human")
    ));
}

#[test]
fn explicit_budget_change_updates_policy_version_and_retains_usage() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let _ = harness.start(created.supervision_id);
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    let latest = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    let change = ChangeSupervisionRequest {
        conditions: None,
        condition_version: None,
        profile_purpose: None,
        consent_purpose: None,
        budget: Some(herness_desktop::supervision::BudgetInput {
            active_seconds: 600,
            additional_runs: 5,
            money_limit_micros: None,
            price_version: None,
        }),
    };
    let changed = harness
        .host
        .change(
            &mut harness.runtime,
            harness.project,
            created.supervision_id,
            SupervisionRequestId::new(harness.project),
            latest.revision,
            PlanRequestActor::Human,
            change,
            Some(harness.host.confirm(ConfirmationKind::Change)),
        )
        .expect("budget change");
    assert_eq!(changed.state, "waiting_human");
    let budget = changed.budget.expect("budget");
    assert_eq!(budget.policy_version, 2);
    assert_eq!(budget.active_seconds, 600);
    assert_eq!(budget.additional_runs, 5);
    let record = harness
        .runtime
        .record(harness.project, created.supervision_id)
        .expect("record")
        .expect("stored");
    assert_eq!(record.change_log().len(), 1);
    assert_eq!(record.change_log()[0].kind().as_str(), "budget");
}

#[test]
fn revoking_completion_consent_stops_pump_progress_before_new_work() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let _ = harness.start(created.supervision_id);
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    assert_eq!(harness.runtime.starts, 1);
    harness
        .host
        .revoke_consent(
            PlanRequestActor::Human,
            harness.project,
            ProfilePurpose::Completion,
            Some(harness.host.confirm(ConfirmationKind::Consent)),
        )
        .expect("revoke");
    std::thread::sleep(supervision_interval());
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump after revoke");
    let latest = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    assert_eq!(latest.state, "waiting_human");
    assert_eq!(
        latest
            .reason
            .get("action")
            .and_then(|action| action.as_str()),
        Some("grant_disclosure_consent")
    );
    assert_eq!(harness.runtime.starts, 1);
}

#[test]
fn recovery_read_reports_zero_side_effects() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let _ = harness.start(created.supervision_id);
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    let recovery = harness
        .host
        .recovery(
            &mut harness.runtime,
            harness.project,
            created.supervision_id,
        )
        .expect("recovery");
    assert_eq!(
        recovery
            .side_effects
            .get("modelRequests")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert_eq!(
        recovery
            .side_effects
            .get("runsStarted")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert_eq!(
        recovery
            .side_effects
            .get("toolExecutions")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert_eq!(
        recovery
            .side_effects
            .get("autoResumes")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
}

#[test]
fn explicit_condition_change_updates_the_plan_contract_before_resume() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let change = ChangeSupervisionRequest {
        conditions: Some(vec![ConditionInput {
            title: "The replacement check passes".to_owned(),
            rubric: "The replacement check must pass on the current target.".to_owned(),
            checks: vec![CheckInput {
                command: "true".to_owned(),
                description: "replacement check".to_owned(),
            }],
        }]),
        condition_version: Some(2),
        profile_purpose: None,
        consent_purpose: None,
        budget: None,
    };
    let changed = harness
        .host
        .change(
            &mut harness.runtime,
            harness.project,
            created.supervision_id,
            SupervisionRequestId::new(harness.project),
            created.revision,
            PlanRequestActor::Human,
            change,
            Some(harness.host.confirm(ConfirmationKind::Change)),
        )
        .expect("condition change");
    assert_eq!(changed.condition_version, 2);
    assert_eq!(changed.state, "waiting_human");
    assert!(changed.plan_available);
    let plan = harness
        .host
        .plans()
        .lock()
        .expect("plans")
        .get(&(harness.project, created.supervision_id))
        .cloned()
        .expect("stored plan");
    assert_eq!(plan.packet.condition_version().get(), 2);
    assert_eq!(
        plan.packet.packet_version(),
        2,
        "an explicit condition change must create a new packet version"
    );
    assert_eq!(plan.contract.work_packet(), &plan.packet);
    let resume = SupervisionOperationRequest::new(
        SupervisionRequestId::new(harness.project),
        created.supervision_id,
        HumanOperation::Resume,
        changed.revision,
    )
    .expect("resume request");
    let resumed = harness
        .host
        .resume(
            &mut harness.runtime,
            resume,
            1,
            Some(harness.host.confirm(ConfirmationKind::Resume)),
        )
        .expect("resume after condition change");
    assert_eq!(resumed.condition_version, 2);
    assert_eq!(resumed.state, "running");
}

#[test]
fn approved_h3_owner_starts_once_and_duplicate_request_does_not_run_again() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let (created, _owner) = harness.create_h3("h3-job-1");
    assert_eq!(created.state, "ready");
    assert_eq!(created.run_group.len(), 0);
    assert_eq!(harness.runtime.starts, 0);

    let request_id = SupervisionRequestId::new(harness.project);
    let first_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    let first = harness
        .host
        .start_approved_owner(
            &mut harness.runtime,
            first_authority,
            request_id,
            created.revision,
        )
        .expect("approved owner start");
    assert_eq!(first.state, "running");
    assert_eq!(first.run_group.len(), 1);
    // `start` records the start intent; the child run is created by the
    // host-owned pump, not by the registry check.
    assert_eq!(harness.runtime.starts, 0);
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    assert_eq!(harness.runtime.starts, 1);

    let duplicate_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    let duplicate = harness
        .host
        .start_approved_owner(
            &mut harness.runtime,
            duplicate_authority,
            request_id,
            first.revision,
        )
        .expect("duplicate owner start");
    assert_eq!(duplicate.run_group.len(), 1);
    assert_eq!(harness.runtime.starts, 1);

    let second_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    let second = harness.host.start_approved_owner(
        &mut harness.runtime,
        second_authority,
        SupervisionRequestId::new(harness.project),
        duplicate.revision,
    );
    assert!(matches!(
        second,
        Err(SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::AlreadyStarted
        })
    ));
    assert_eq!(harness.runtime.starts, 1);
    assert_eq!(
        harness
            .host
            .get(harness.project, created.supervision_id)
            .expect("view")
            .run_group
            .len(),
        1
    );
}

#[test]
fn owner_supersession_after_confirmed_stop_updates_generation_and_starts_one_run() {
    let mut harness = harness_with_pass_check_unmet();
    harness.configure_completion();
    harness.grant_completion(1);
    let (created, _owner) = harness.create_h3("h3-job-1");
    let first_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    harness
        .host
        .start_approved_owner(
            &mut harness.runtime,
            first_authority,
            SupervisionRequestId::new(harness.project),
            created.revision,
        )
        .expect("approved owner start");
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    assert_eq!(harness.runtime.starts, 1);

    // Drive the first generation through one met check and one unmet
    // assessment so the record has a real applied decision to invalidate.
    harness.runtime.complete_all_inputs();
    harness.runtime.set_all_idle();
    let deadline = Instant::now() + Duration::from_secs(10);
    let before = loop {
        harness
            .host
            .pump(&mut harness.runtime, &[harness.project])
            .expect("pump assessment");
        let view = harness
            .host
            .get(harness.project, created.supervision_id)
            .expect("view");
        if view.applied_decisions >= 1 {
            break view;
        }
        assert!(Instant::now() < deadline, "assessment did not apply");
        std::thread::sleep(supervision_interval());
    };
    assert!(matches!(
        before.state.as_str(),
        "running" | "verifying" | "assessing"
    ));
    assert_eq!(before.invalidated_decisions, 0);
    let before_usage = before.budget.as_ref().expect("budget").usage;
    let before_runs = before.run_group.len();
    let before_plan = herness_desktop::supervision::plan::load_plan(
        &harness.store,
        harness.project,
        created.supervision_id,
    )
    .expect("load plan")
    .expect("plan");
    let before_packet_version = before_plan.packet.packet_version();
    let before_fingerprint = before_plan.packet.fingerprint().clone();

    // The human settings UI approved the new target scope version.
    harness.grant_completion(2);
    let supersede = supersede_request(
        harness.project,
        created.supervision_id,
        before.revision,
        2,
    );
    let binding = harness
        .host
        .owner_supersession_binding(&mut harness.runtime, &supersede)
        .expect("supersession binding");
    let mut registry = ScriptedOwnerApprovalRegistry::new();
    registry.insert(binding.approval().clone());
    let old_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    let starts_before = harness.runtime.starts;
    let continuations_before = harness.runtime.continuations;

    let superseded = harness
        .host
        .supersede_approved_owner(
            &mut harness.runtime,
            &registry,
            old_authority,
            supersede.clone(),
        )
        .expect("owner supersession");
    assert_eq!(superseded.supervision_id, created.supervision_id);
    assert_eq!(superseded.target_version, 2);
    assert_eq!(superseded.state, "running");
    assert_eq!(superseded.applied_decisions, 0);
    assert_eq!(superseded.invalidated_decisions, 1);
    assert_eq!(superseded.run_group.len(), before_runs + 1);
    assert_eq!(superseded.condition_version, before.condition_version);
    let superseded_usage = superseded.budget.as_ref().expect("budget").usage;
    assert_eq!(
        superseded_usage.runs_started(),
        before_usage.runs_started(),
        "the supersession itself must not consume a run"
    );
    assert_eq!(
        superseded_usage.money_consumed(),
        before_usage.money_consumed()
    );
    assert_eq!(
        superseded_usage.money_reserved(),
        before_usage.money_reserved()
    );
    assert!(superseded_usage.active_seconds_consumed() >= before_usage.active_seconds_consumed());

    let after_plan = herness_desktop::supervision::plan::load_plan(
        &harness.store,
        harness.project,
        created.supervision_id,
    )
    .expect("load plan")
    .expect("plan");
    assert_eq!(after_plan.evidence_target.version().get(), 2);
    assert_eq!(
        after_plan.packet.packet_version(),
        before_packet_version.saturating_add(1)
    );
    assert_ne!(after_plan.packet.fingerprint(), &before_fingerprint);
    assert_eq!(after_plan.contract.work_packet(), &after_plan.packet);
    let record = harness
        .store
        .lock()
        .load_supervision_record(harness.project, created.supervision_id)
        .expect("load record")
        .expect("record");
    assert_eq!(record.change_log().len(), 1);
    assert_eq!(record.change_log()[0].kind(), ChangeKind::Supersede);
    assert_eq!(
        record.change_log()[0].budget_before().runs_started(),
        before_usage.runs_started()
    );
    assert_eq!(
        record.change_log()[0].budget_after().runs_started(),
        before_usage.runs_started()
    );
    assert!(record.change_log()[0]
        .budget_after()
        .active_seconds_consumed()
        >= record.change_log()[0]
            .budget_before()
            .active_seconds_consumed());

    // Exactly one new run starts in the same target and conversation.
    std::thread::sleep(supervision_interval());
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump superseded generation");
    assert_eq!(harness.runtime.starts, starts_before + 1);
    assert_eq!(harness.runtime.continuations, continuations_before);
    let started = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    let started_usage = started.budget.as_ref().expect("budget").usage;
    assert_eq!(
        started_usage.runs_started(),
        before_usage.runs_started().saturating_add(1)
    );
    assert!(started_usage.active_seconds_consumed() >= before_usage.active_seconds_consumed());

    // A duplicate request returns the current view without another supersede
    // or run.
    let duplicate_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    let duplicate = harness
        .host
        .supersede_approved_owner(
            &mut harness.runtime,
            &registry,
            duplicate_authority,
            SupersedeSupervisionRequest {
                request_id: supersede.request_id,
                expected_revision: started.revision,
                ..supersede
            },
        )
        .expect("duplicate supersession");
    assert_eq!(duplicate.revision, started.revision);
    assert_eq!(duplicate.run_group.len(), started.run_group.len());
    assert_eq!(harness.runtime.starts, starts_before + 1);
    assert_eq!(
        duplicate.budget.as_ref().expect("budget").usage.runs_started(),
        started_usage.runs_started()
    );
}

#[test]
fn stale_owner_registry_entry_is_refused_before_stop_or_generation_change() {
    let mut harness = harness_with_pass_check_unmet();
    harness.configure_completion();
    harness.grant_completion(1);
    let (created, _owner) = harness.create_h3("h3-job-1");
    let first_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    harness
        .host
        .start_approved_owner(
            &mut harness.runtime,
            first_authority,
            SupervisionRequestId::new(harness.project),
            created.revision,
        )
        .expect("approved owner start");
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    assert_eq!(harness.runtime.starts, 1);

    harness.grant_completion(2);
    let view = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    let mut supersede = supersede_request(
        harness.project,
        created.supervision_id,
        view.revision,
        2,
    );
    supersede.conditions = Some(vec![ConditionInput {
        title: "Changed generation condition".to_owned(),
        rubric: "The changed target must be reassessed.".to_owned(),
        checks: vec![],
    }]);
    supersede.condition_version = Some(2);
    // The preview is well formed, but the current registry still carries the
    // old condition version.
    harness
        .host
        .owner_supersession_binding(&mut harness.runtime, &supersede)
        .expect("prospective binding");
    let registry = harness.matching_owner_registry(created.supervision_id, 1, "h3-job-1");
    let old_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    let stops_before = harness.runtime.stops;
    let result = harness.host.supersede_approved_owner(
        &mut harness.runtime,
        &registry,
        old_authority,
        supersede,
    );
    assert!(matches!(
        result,
        Err(SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::StaleConditions {
                requested: 2,
                registered: 1
            }
        })
    ));
    assert_eq!(harness.runtime.stops, stops_before);
    assert_eq!(harness.runtime.starts, 1);
    let after = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    assert_eq!(after.target_version, 1);
    assert_eq!(after.condition_version, 1);
    assert_eq!(after.revision, view.revision);
}

#[test]
fn crashed_owner_supersession_is_not_recorded_and_restart_neither_supersedes_nor_starts() {
    let mut harness = harness_with_pass_check_unmet();
    harness.configure_completion();
    harness.grant_completion(1);
    let (created, _owner) = harness.create_h3("h3-job-1");
    let first_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    harness
        .host
        .start_approved_owner(
            &mut harness.runtime,
            first_authority,
            SupervisionRequestId::new(harness.project),
            created.revision,
        )
        .expect("approved owner start");
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    assert_eq!(harness.runtime.starts, 1);

    harness.grant_completion(2);
    let view = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    let supersede = supersede_request(
        harness.project,
        created.supervision_id,
        view.revision,
        2,
    );
    let binding = harness
        .host
        .owner_supersession_binding(&mut harness.runtime, &supersede)
        .expect("supersession binding");
    let mut registry = ScriptedOwnerApprovalRegistry::new();
    registry.insert(binding.approval().clone());
    let old_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    harness
        .store
        .lock()
        .set_commit_fault(Some(CommitFault::BeforeCommit));
    let failed = harness.host.supersede_approved_owner(
        &mut harness.runtime,
        &registry,
        old_authority,
        supersede.clone(),
    );
    assert!(failed.is_err(), "the injected commit fault must surface");
    harness.store.lock().set_commit_fault(None);

    let after_crash = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    assert_eq!(after_crash.target_version, 1);
    assert_eq!(after_crash.revision, view.revision);
    assert_eq!(harness.runtime.starts, 1);
    assert!(harness
        .store
        .lock()
        .command_result(supersede.request_id)
        .expect("command lookup")
        .is_none());
    let plan_after_crash = herness_desktop::supervision::plan::load_plan(
        &harness.store,
        harness.project,
        created.supervision_id,
    )
    .expect("load plan")
    .expect("plan");
    assert_eq!(plan_after_crash.evidence_target.version().get(), 1);

    // Restart marks the target as restored. The same request neither
    // supersedes nor starts another run; a human/new cycle is needed.
    harness.host.restore(&[harness.project]);
    let retry_authority = harness.owner_authority(created.supervision_id, 1, "h3-job-1");
    let retry = harness.host.supersede_approved_owner(
        &mut harness.runtime,
        &registry,
        retry_authority,
        supersede,
    );
    assert!(matches!(
        retry,
        Err(SupervisionError::OwnerSupersessionRejected {
            reason: OwnerSupersessionRejection::RestoredTarget
        })
    ));
    assert_eq!(harness.runtime.starts, 1);
    let final_view = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    assert_eq!(final_view.target_version, 1);
    assert_eq!(final_view.revision, view.revision);
}

#[test]
fn fake_owner_and_stale_settings_never_start_a_run() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let (created, _owner) = harness.create_h3("h3-job-1");
    let binding = harness.owner_binding(created.supervision_id, 1, "h3-job-1");

    let empty = ScriptedOwnerApprovalRegistry::new();
    assert!(matches!(
        authorize_owner_launch(&empty, &binding, Timestamp::now()),
        Err(SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::MissingRegistryEntry
        })
    ));

    let stale = harness.owner_binding(created.supervision_id, 2, "h3-job-1");
    let mut registry = ScriptedOwnerApprovalRegistry::new();
    registry.insert(stale.approval().clone());
    assert!(matches!(
        authorize_owner_launch(&registry, &binding, Timestamp::now()),
        Err(SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::StaleSettings {
                requested: 1,
                registered: 2
            }
        })
    ));

    let wrong_job = harness.owner_binding(created.supervision_id, 1, "other-job");
    let mut registry = ScriptedOwnerApprovalRegistry::new();
    registry.insert(wrong_job.approval().clone());
    assert!(matches!(
        authorize_owner_launch(&registry, &binding, Timestamp::now()),
        Err(SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::JobMismatch
        })
    ));
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.continuations, 0);
    let current = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    assert_eq!(current.state, "ready");
    assert!(current.run_group.is_empty());
}

#[test]
fn model_actor_missing_confirmation_and_h4_never_start_a_run() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);

    let model = harness.host.create(
        &mut harness.runtime,
        PlanRequestActor::Model,
        request(harness.project, harness.connection),
        Some(harness.host.confirm(ConfirmationKind::Create)),
    );
    assert!(matches!(
        model,
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.continuations, 0);

    let (created, _owner) = harness.create_h3("h3-job-1");
    let missing = harness.host.start(
        &mut harness.runtime,
        harness.project,
        created.supervision_id,
        SupervisionRequestId::new(harness.project),
        created.revision,
        None,
    );
    assert!(matches!(
        missing,
        Err(SupervisionError::Unsupported { .. })
    ));
    let wrong = harness.host.start(
        &mut harness.runtime,
        harness.project,
        created.supervision_id,
        SupervisionRequestId::new(harness.project),
        created.revision,
        Some(harness.host.confirm(ConfirmationKind::Create)),
    );
    assert!(matches!(
        wrong,
        Err(SupervisionError::Unsupported { .. })
    ));
    assert_eq!(harness.runtime.starts, 0);

    let h4_owner = OwnerRef::new(OwnerKind::H4SddTask, "task-6-fixture").expect("H4 owner");
    let h4_contract = herness_supervision_tests::owner_contract(
        harness.project,
        h4_owner,
        OwnerApprovalSource::H4ApprovedPlan,
    );
    let h4_binding =
        OwnerLaunchBinding::from_contract(&h4_contract, 1, 1, "task-6").expect("H4 binding");
    let mut registry = ScriptedOwnerApprovalRegistry::new();
    registry.insert(h4_binding.approval().clone());
    assert!(matches!(
        authorize_owner_launch(&registry, &h4_binding, Timestamp::now()),
        Err(SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::H4ApprovalUnavailable
        })
    ));
    assert_eq!(harness.runtime.starts, 0);
}

#[test]
fn restored_target_is_not_auto_started_and_human_start_still_works() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let (created, _owner) = harness.create_h3("h3-job-1");
    let save_path = harness.store_path.clone();
    let project = harness.project;
    let supervision = created.supervision_id;
    let revision = created.revision;
    let project_root = harness._temp.path().join("project");

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

    let restored = host.get(project, supervision).expect("restored view");
    assert_eq!(restored.state, "ready");
    assert!(restored.plan_available);
    assert_eq!(restored.revision, revision);

    let binding = host
        .owner_launch_binding(project, supervision, 1, "h3-job-1")
        .expect("restored binding");
    let mut registry = ScriptedOwnerApprovalRegistry::new();
    registry.insert(binding.approval().clone());
    let authority = authorize_owner_launch(&registry, &binding, Timestamp::now())
        .expect("registry still matches");
    let auto = host.start_approved_owner(
        &mut runtime,
        authority,
        SupervisionRequestId::new(project),
        revision,
    );
    assert!(matches!(
        auto,
        Err(SupervisionError::OwnerLaunchRejected {
            reason: OwnerLaunchRejection::RestoredTarget
        })
    ));
    assert_eq!(runtime.starts, 0);

    let human = host
        .start(
            &mut runtime,
            project,
            supervision,
            SupervisionRequestId::new(project),
            revision,
            Some(host.confirm(ConfirmationKind::Start)),
        )
        .expect("human start after restore");
    assert_eq!(human.state, "running");
    host.pump(&mut runtime, &[project]).expect("pump human start");
    assert_eq!(runtime.starts, 1);
}

#[test]
fn duplicate_start_request_id_returns_the_recorded_result_without_a_second_run() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let request_id = SupervisionRequestId::new(harness.project);
    let first = harness
        .host
        .start(
            &mut harness.runtime,
            harness.project,
            created.supervision_id,
            request_id,
            created.revision,
            Some(harness.host.confirm(ConfirmationKind::Start)),
        )
        .expect("first start");
    let second = harness
        .host
        .start(
            &mut harness.runtime,
            harness.project,
            created.supervision_id,
            request_id,
            first.revision,
            Some(harness.host.confirm(ConfirmationKind::Start)),
        )
        .expect("duplicate start");
    assert_eq!(second.revision, first.revision);
    assert_eq!(second.run_group.len(), first.run_group.len());
    assert_eq!(harness.runtime.starts, 0);
}

#[test]
fn passing_checks_and_a_met_assessment_complete_after_the_state_is_saved() {
    let mut harness = harness_with_completion();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let _ = harness.start(created.supervision_id);
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    harness.runtime.complete_all_inputs();
    harness.runtime.set_all_idle();
    let state = pump_until(
        &mut harness.host,
        &mut harness.runtime,
        harness.project,
        |state| state == "completed",
    );
    assert_eq!(state, "completed");
    let latest = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    assert!(latest.completion.is_some());
    assert!(!latest.notifications.is_empty());
    assert_eq!(latest.unmet_conditions.len(), 0);
}

#[test]
fn reassess_from_stopped_can_complete_from_a_stable_paused_run() {
    let mut harness = harness_with_completion();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let _ = harness.start(created.supervision_id);
    harness
        .host
        .pump(&mut harness.runtime, &[harness.project])
        .expect("pump start");
    harness.runtime.complete_all_inputs();
    let running = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    let stop = SupervisionOperationRequest::new(
        SupervisionRequestId::new(harness.project),
        created.supervision_id,
        HumanOperation::Stop,
        running.revision,
    )
    .expect("stop request");
    let stopped = harness
        .host
        .stop(
            &mut harness.runtime,
            stop,
            false,
            1,
            Some(harness.host.confirm(ConfirmationKind::Stop)),
        )
        .expect("stop");
    assert_eq!(stopped.state, "stopped");
    let reassess = SupervisionOperationRequest::new(
        SupervisionRequestId::new(harness.project),
        created.supervision_id,
        HumanOperation::Reassess,
        stopped.revision,
    )
    .expect("reassess request");
    let _ = harness
        .host
        .reassess(
            &mut harness.runtime,
            reassess,
            1,
            Some(harness.host.confirm(ConfirmationKind::Reassess)),
        )
        .expect("reassess");
    let state = pump_until(
        &mut harness.host,
        &mut harness.runtime,
        harness.project,
        |state| state == "completed",
    );
    assert_eq!(state, "completed");
}

#[test]
fn pump_progresses_targets_in_every_project_without_a_window_or_selected_project() {
    let mut harness = harness();
    // Second project with its own profile/consent and target.
    let other_root = harness._temp.path().join("other-project");
    std::fs::create_dir_all(other_root.join("src")).expect("other dirs");
    std::fs::write(other_root.join("src/main.rs"), "fn other() {}\n").expect("other file");
    let other_project = ProjectId::new();
    harness
        .host
        .configure_profile(
            PlanRequestActor::Human,
            other_project,
            ProfilePurpose::Completion,
            harness.connection,
            "judge-model",
            Some(harness.host.confirm(ConfirmationKind::Profile)),
        )
        .expect("other profile");
    harness
        .host
        .grant_consent(
            PlanRequestActor::Human,
            other_project,
            ProfilePurpose::Completion,
            ProviderOrigin::parse("https://api.openai.com").expect("origin"),
            BTreeSet::from([DisclosureDataKind::Text]),
            vec!["src/main.rs".to_owned()],
            TargetVersion::new(1).expect("version"),
            Some(harness.host.confirm(ConfirmationKind::Consent)),
        )
        .expect("other consent");
    harness
        .runtime
        .add_project(other_project, other_root.clone());
    let other_view = harness
        .host
        .create(
            &mut harness.runtime,
            PlanRequestActor::Human,
            request(other_project, harness.connection),
            Some(harness.host.confirm(ConfirmationKind::Create)),
        )
        .expect("other create");
    let _ = harness
        .host
        .start(
            &mut harness.runtime,
            other_project,
            other_view.supervision_id,
            SupervisionRequestId::new(other_project),
            other_view.revision,
            Some(harness.host.confirm(ConfirmationKind::Start)),
        )
        .expect("other start");

    harness.configure_completion();
    harness.grant_completion(1);
    let view = harness.create();
    let _ = harness.start(view.supervision_id);

    // The pump receives both project IDs, not a UI selection or a window.
    for _ in 0..3 {
        harness
            .host
            .pump(&mut harness.runtime, &[harness.project, other_project])
            .expect("pump both");
        std::thread::sleep(supervision_interval());
    }
    assert_eq!(harness.runtime.starts, 2);
    assert!(harness.runtime.run_count() >= 2);
}

// ---------------------------------------------------------------------------
// Restore/reopen.
// ---------------------------------------------------------------------------

#[test]
fn reopen_restores_saved_plan_state_and_purpose_configuration() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let save_path = harness.store_path.clone();
    let project = harness.project;
    let supervision = created.supervision_id;
    let revision = created.revision;

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
    let host = SupervisionHost::with_config_for_test(
        store.clone(),
        ConfigStore::new(),
        assessment_host,
        Box::new(UnverifiedAssessment),
        Box::new(UnavailableCheck),
    );
    host.restore(&[project]);
    let views = host.list(project).expect("restored list");
    assert_eq!(views.len(), 1);
    let restored = &views[0];
    assert_eq!(restored.supervision_id, supervision);
    assert_eq!(restored.revision, revision);
    assert_eq!(restored.state, "ready");
    assert!(restored.plan_available);
    let completion = restored
        .purposes
        .iter()
        .find(|status| status.purpose == "completion")
        .expect("completion");
    assert_eq!(completion.consent_state, "granted");
    assert!(completion.profile_id.is_some());
    assert!(!completion.verified);
    assert!(
        host.get(project, supervision)
            .expect("get")
            .run_group
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Work packet format and integrity.
// ---------------------------------------------------------------------------

fn plan_key(project: ProjectId, supervision: SupervisionId) -> String {
    format!("h2.supervision.plan:{project}:{supervision}")
}

#[test]
fn legacy_plan_without_a_recoverable_packet_is_refused_explicitly() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let project = harness.project;
    let supervision = created.supervision_id;
    let plan = harness
        .host
        .plans()
        .lock()
        .expect("plans")
        .get(&(project, supervision))
        .cloned()
        .expect("stored plan");
    plan.verify().expect("current plan verifies");

    // The former format is the exact current value without the new fields.
    let mut legacy = serde_json::to_value(&plan).expect("plan value");
    let object = legacy.as_object_mut().expect("plan object");
    object.remove("formatVersion");
    object.remove("packet");
    if let Some(contract) = object.get_mut("contract").and_then(|value| value.as_object_mut()) {
        contract.remove("workPacket");
    }
    let legacy_bytes = serde_json::to_vec(&legacy).expect("legacy bytes");
    assert!(matches!(
        herness_desktop::supervision::plan::decode_plan(&legacy_bytes),
        Err(SupervisionError::Unsupported { .. })
    ));

    harness
        .store
        .lock()
        .save_host_state(&plan_key(project, supervision), &legacy_bytes)
        .expect("save legacy plan");
    harness.host.plans().lock().expect("plans").clear();
    harness.host.restore(&[project]);

    let start = harness.host.start(
        &mut harness.runtime,
        project,
        supervision,
        SupervisionRequestId::new(project),
        created.revision,
        Some(harness.host.confirm(ConfirmationKind::Start)),
    );
    assert!(
        matches!(start, Err(SupervisionError::Unsupported { .. })),
        "a legacy plan must not start or fabricate a packet: {start:?}"
    );
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.continuations, 0);
}

#[test]
fn tampered_packet_fingerprint_is_refused_before_any_child_run() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let project = harness.project;
    let supervision = created.supervision_id;
    let plan = harness
        .host
        .plans()
        .lock()
        .expect("plans")
        .get(&(project, supervision))
        .cloned()
        .expect("stored plan");

    let mut tampered = serde_json::to_value(&plan).expect("plan value");
    tampered["packet"]["instruction"] = serde_json::json!("a silently different task");
    let tampered_bytes = serde_json::to_vec(&tampered).expect("tampered bytes");
    assert!(matches!(
        herness_desktop::supervision::plan::decode_plan(&tampered_bytes),
        Err(SupervisionError::WorkPacketRejected {
            reason: WorkPacketRejection::FingerprintMismatch
        })
    ));

    harness
        .store
        .lock()
        .save_host_state(&plan_key(project, supervision), &tampered_bytes)
        .expect("save tampered plan");
    harness.host.plans().lock().expect("plans").clear();
    harness.host.restore(&[project]);

    let start = harness.host.start(
        &mut harness.runtime,
        project,
        supervision,
        SupervisionRequestId::new(project),
        created.revision,
        Some(harness.host.confirm(ConfirmationKind::Start)),
    );
    assert!(
        matches!(
            start,
            Err(SupervisionError::WorkPacketRejected {
                reason: WorkPacketRejection::FingerprintMismatch
            })
        ),
        "a changed packet must be refused, not replaced: {start:?}"
    );
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.continuations, 0);
}

// ---------------------------------------------------------------------------
// Default no-child-continuation.
// ---------------------------------------------------------------------------

#[test]
fn no_child_continuation_or_auto_start_happens_for_normal_creation() {
    let mut harness = harness();
    harness.configure_completion();
    harness.grant_completion(1);
    let created = harness.create();
    let before = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    assert_eq!(before.state, "ready");
    assert_eq!(before.run_group.len(), 0);
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.continuations, 0);

    // Repeated pumps with no explicit start still do nothing.
    for _ in 0..3 {
        harness
            .host
            .pump(&mut harness.runtime, &[harness.project])
            .expect("pump");
    }
    let after = harness
        .host
        .get(harness.project, created.supervision_id)
        .expect("view");
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.state, "ready");
    assert_eq!(harness.runtime.starts, 0);
    assert_eq!(harness.runtime.continuations, 0);
}

// ---------------------------------------------------------------------------
// Production permission-evaluator composition (Task 16 follow-up).
// ---------------------------------------------------------------------------

mod permission_composition {
    use std::collections::{BTreeSet, VecDeque};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use herness_assessment::AssessmentEndpoints;
    use herness_core::{
        AbsolutePath, ArgumentsDigest, AuthMethod, ConnectionAdmin,
        ConnectionCapabilityDeclaration, ConnectionId, ConnectionSettings, CredentialAvailability,
        CredentialKind, CredentialPort, Endpoint, EndpointClass, EvaluationContext,
        EvaluatorAvailability, FrozenOperation, InputCapabilities, InputId, ModelId, NonEmptyText,
        OperationId, PermissionEvaluatorPort, PermissionMode, PermissionOutcome, PermissionPolicy,
        PermissionRule, PolicyAdmin, ProjectId, Provider, Rationale, ResolvedCredential,
        RuleTarget, RunId, SecretString, Timestamp, ToolArguments, ToolExecutor, ToolGateway,
        ToolName, WriteArgs,
    };
    use herness_desktop::host::DesktopHost;
    use herness_desktop::supervision::assessment::{
        AssessmentHost as PortAssessmentHost, HostAssessmentPort,
    };
    use herness_desktop::supervision::runtime::DesktopH1;
    use herness_desktop::supervision::store::HostBudgetClock;
    use herness_desktop::supervision::{
        BudgetInput as HostBudgetInput, ConfirmationKind, CreateSupervisionRequest,
        PlanRequestActor,
    };
    use herness_engine_pi::ProviderEndpoints;
    use herness_supervision::ports::EvidenceStorePort;
    use herness_supervision::supervisor::{
        AssessmentProfileFacts, CheckExecution, CheckExecutionRequest, ChildRunStart,
        ConditionAssessmentPort, RequiredCheckPort, SupervisionRuntimePort,
    };
    use herness_supervision::{
        AdapterVersion, AssessmentRequest, AssessmentResult, BudgetLedger, BudgetPolicy,
        BudgetRequestId, CheckStatus, Condition, ConditionId, ConsentBlock, DecisionId,
        DisclosureDataKind, DisclosureRequest, EvidenceAcquirer, EvidenceId, EvidenceOutcome,
        EvidenceRecord, EvidenceScope, ProfileBinding, ProfilePurpose, ProfileThresholds,
        ProfileUnavailable, ProviderKind, ProviderOrigin, RequiredCheckResult, RubricVersion,
        SupervisionError, SupervisionId, SupervisionRequestId, TargetScope, TargetVersion,
        VerificationOperation, WorkPacket, WorkPacketRejection,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;

    const API_KEY: &str = "sk-permission-desktop-canary-98ac";
    const MODEL: &str = "permission-llm";
    const PACKET_INSTRUCTION: &str = "Owner packet canary: implement the approved H2 scope change.";
    const CONVERSATION_CANARY: &str = "whole-conversation-canary-1f4d";

    /// A deterministic failing check: the continuation must be requested
    /// without executing a required shell command.
    struct FailingCheck;

    impl RequiredCheckPort for FailingCheck {
        fn execute(
            &mut self,
            request: &CheckExecutionRequest,
        ) -> Result<CheckExecution, SupervisionError> {
            let result = RequiredCheckResult::new(
                request.check_id(),
                request.condition_id(),
                CheckStatus::Fail,
                None,
                request.condition_version(),
                request.target_version(),
                Timestamp::now(),
            )?;
            Ok(CheckExecution::new(result, None))
        }
    }

    /// The failing required check is sufficient; no semantic model judgment is
    /// needed to decide that the condition is unmet.
    struct DeterministicAssessment;

    impl ConditionAssessmentPort for DeterministicAssessment {
        fn requires_assessment(&self, _condition: &Condition) -> bool {
            false
        }

        fn profile(
            &self,
            _binding: ProfileBinding,
        ) -> Result<AssessmentProfileFacts, SupervisionError> {
            Err(SupervisionError::Unsupported {
                feature: "deterministic test checks do not use a profile".to_owned(),
            })
        }

        fn assess(
            &mut self,
            _request: &AssessmentRequest,
        ) -> Result<AssessmentResult, SupervisionError> {
            Err(SupervisionError::Unsupported {
                feature: "deterministic test checks do not use assessment".to_owned(),
            })
        }
    }

    fn data_event(data: Value) -> String {
        format!("data: {data}\n\n")
    }

    fn completions_text(text: &str) -> String {
        let mut body = String::new();
        body.push_str(&data_event(json!({
            "id": "chatcmpl-text",
            "choices": [{"index": 0, "delta": {"content": text}}]
        })));
        body.push_str(&data_event(json!({
            "id": "chatcmpl-text",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        })));
        body.push_str("data: [DONE]\n\n");
        body
    }

    fn completions_tool_call(call_id: &str, name: &str, arguments: Value) -> String {
        let arguments = arguments.to_string();
        let split = arguments.len() / 2;
        let (first, second) = arguments.split_at(split);
        let mut body = String::new();
        body.push_str(&data_event(json!({
            "id": "chatcmpl-tool",
            "choices": [{"index": 0, "delta": {"tool_calls": [{
                "index": 0,
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": first}
            }]}}]
        })));
        body.push_str(&data_event(json!({
            "id": "chatcmpl-tool",
            "choices": [{"index": 0, "delta": {"tool_calls": [{
                "index": 0,
                "function": {"arguments": second}
            }]}}]
        })));
        body.push_str(&data_event(json!({
            "id": "chatcmpl-tool",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]
        })));
        body.push_str("data: [DONE]\n\n");
        body
    }

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        path: String,
        body: Vec<u8>,
    }

    impl RecordedRequest {
        fn json_body(&self) -> Value {
            serde_json::from_slice(&self.body).expect("mock request body is JSON")
        }
    }

    #[derive(Debug, Clone)]
    struct MockReply {
        content_type: &'static str,
        body: Vec<u8>,
    }

    struct PermissionMock {
        address: SocketAddr,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
        responses: Arc<Mutex<VecDeque<MockReply>>>,
        stop: Arc<AtomicBool>,
    }

    impl PermissionMock {
        fn start() -> Arc<Self> {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind permission mock");
            listener
                .set_nonblocking(true)
                .expect("nonblocking permission mock");
            let address = listener.local_addr().expect("mock address");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let responses = Arc::new(Mutex::new(VecDeque::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_requests = Arc::clone(&requests);
            let thread_responses = Arc::clone(&responses);
            let thread_stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !thread_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let requests = Arc::clone(&thread_requests);
                            let responses = Arc::clone(&thread_responses);
                            thread::spawn(move || handle_connection(stream, requests, responses));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => {
                            // A reset queued connection must not stop the
                            // mock for the remaining assertions.
                            thread::sleep(Duration::from_millis(2));
                        }
                    }
                }
            });
            Arc::new(Self {
                address,
                requests,
                responses,
                stop,
            })
        }

        fn url(&self) -> String {
            format!("http://{}", self.address)
        }

        fn api_base(&self) -> String {
            format!("{}/v1", self.url())
        }

        fn push(&self, response: Value) {
            self.responses
                .lock()
                .expect("responses")
                .push_back(MockReply {
                    content_type: "application/json",
                    body: serde_json::to_vec(&response).expect("encode mock response"),
                });
        }

        fn push_sse(&self, body: String) {
            self.responses
                .lock()
                .expect("responses")
                .push_back(MockReply {
                    content_type: "text/event-stream",
                    body: body.into_bytes(),
                });
        }

        fn count(&self) -> usize {
            self.requests.lock().expect("requests").len()
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().expect("requests").clone()
        }
    }

    impl Drop for PermissionMock {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.address);
        }
    }

    fn handle_connection(
        mut stream: TcpStream,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
        responses: Arc<Mutex<VecDeque<MockReply>>>,
    ) {
        let Some((head, body)) = read_request(&mut stream) else {
            return;
        };
        let path = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("")
            .to_owned();
        requests
            .lock()
            .expect("requests")
            .push(RecordedRequest { path, body });
        let response = responses
            .lock()
            .expect("responses")
            .pop_front()
            .unwrap_or_else(|| MockReply {
                content_type: "application/json",
                body: serde_json::to_vec(&json!({"error": "mock exhausted"}))
                    .expect("encode mock error"),
            });
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.content_type,
            response.body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&response.body);
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }

    fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .ok()?;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position;
            }
            if buffer.len() > 1024 * 1024 {
                return None;
            }
        };
        let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
        let mut content_length = 0usize;
        for line in head.lines().skip(1) {
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = buffer[header_end + 4..].to_vec();
        while body.len() < content_length {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        Some((head, body))
    }

    struct FakePermissionCredentials {
        connection: ConnectionId,
        secret: String,
        resolves: AtomicUsize,
    }

    impl FakePermissionCredentials {
        fn new(connection: ConnectionId) -> Self {
            Self {
                connection,
                secret: API_KEY.to_owned(),
                resolves: AtomicUsize::new(0),
            }
        }
    }

    impl CredentialPort for FakePermissionCredentials {
        fn availability(
            &self,
            connection: &ConnectionId,
        ) -> Result<CredentialAvailability, herness_core::CoreError> {
            Ok(if connection == &self.connection {
                CredentialAvailability::Available
            } else {
                CredentialAvailability::Unavailable
            })
        }

        fn resolve(
            &self,
            connection: &ConnectionId,
        ) -> Result<ResolvedCredential, herness_core::CoreError> {
            if connection != &self.connection {
                return Err(herness_core::CoreError::AuthenticationRequired {
                    connection: *connection,
                });
            }
            self.resolves.fetch_add(1, Ordering::SeqCst);
            Ok(ResolvedCredential::new(
                CredentialKind::ApiKey,
                SecretString::new(self.secret.clone())?,
            ))
        }
    }

    struct PermissionHost {
        _temp: TempDir,
        project: ProjectId,
        root: PathBuf,
        connection: ConnectionId,
        host: DesktopHost,
        server: Arc<PermissionMock>,
        credentials: Arc<FakePermissionCredentials>,
    }

    impl PermissionHost {
        fn new() -> Self {
            Self::build(false)
        }

        fn with_test_boundaries() -> Self {
            Self::build(true)
        }

        fn build(test_boundaries: bool) -> Self {
            let temp = tempfile::tempdir().expect("temp");
            let root = temp.path().join("project");
            std::fs::create_dir_all(root.join("src")).expect("project dirs");
            std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("project file");
            let server = PermissionMock::start();
            let connection = ConnectionId::new();
            let admin = ConnectionAdmin::new();
            admin
                .add(
                    ConnectionSettings::new_with_capabilities(
                        connection,
                        Provider::OpenAiCompatible,
                        MODEL,
                        AuthMethod::ApiKey,
                        Some(
                            Endpoint::parse(server.api_base().as_str()).expect("loopback endpoint"),
                        ),
                        None,
                        ConnectionCapabilityDeclaration::new(
                            EndpointClass::OpenAiCompletions,
                            InputCapabilities::text_only(),
                        ),
                    )
                    .expect("connection"),
                )
                .expect("add connection");
            let credentials = Arc::new(FakePermissionCredentials::new(connection));
            let engine_endpoints = ProviderEndpoints::for_loopback(server.api_base(), server.url())
                .expect("engine loopback endpoints");
            let assessment_endpoints =
                AssessmentEndpoints::for_loopback(server.url(), server.api_base(), server.url())
                    .expect("assessment loopback endpoints");
            let app_data = temp.path().join("app-data");
            let mut host = if test_boundaries {
                let (host, _) = DesktopHost::open_with_test_boundaries(
                    &app_data,
                    admin,
                    credentials.clone(),
                    engine_endpoints,
                    None,
                    Box::new(DeterministicAssessment),
                    Box::new(FailingCheck),
                )
                .expect("desktop host with test boundaries");
                host
            } else {
                let (host, _) = DesktopHost::open_with_assessment_endpoints(
                    &app_data,
                    admin,
                    credentials.clone(),
                    engine_endpoints,
                    assessment_endpoints,
                )
                .expect("desktop host");
                host
            };
            let project = host
                .runtime_mut()
                .open_project(&root)
                .expect("open project")
                .project_id();
            Self {
                _temp: temp,
                project,
                root,
                connection,
                host,
                server,
                credentials,
            }
        }

        /// Allows write and bash at the policy layer so the child grant is the
        /// only reason an operation is denied.
        fn allow_write_and_shell_at_policy(&mut self) {
            let admin = self.host.runtime_mut().policy_admin_mut();
            for tool in [ToolName::Write, ToolName::Bash] {
                admin
                    .add_rule(
                        PermissionRule::allow(
                            RuleTarget::Tool { tool },
                            herness_core::MatchMethod::AnyInvocation,
                        )
                        .expect("policy rule"),
                    )
                    .expect("add policy rule");
            }
        }

        fn configure_purpose(&self, purpose: ProfilePurpose) {
            self.host
                .supervision_configure_profile(
                    PlanRequestActor::Human,
                    self.project,
                    purpose,
                    self.connection,
                    MODEL,
                    Some(self.host.confirm_supervision(ConfirmationKind::Profile)),
                )
                .expect("configure profile");
            self.host
                .supervision_grant_consent(
                    PlanRequestActor::Human,
                    self.project,
                    purpose,
                    ProviderOrigin::parse(self.server.url()).expect("origin"),
                    std::collections::BTreeSet::from([DisclosureDataKind::Text]),
                    vec!["src/main.rs".to_owned()],
                    TargetVersion::new(1).expect("version"),
                    Some(self.host.confirm_supervision(ConfirmationKind::Consent)),
                )
                .expect("grant consent");
        }

        fn configure_verified_permission(&self) {
            self.configure_purpose(ProfilePurpose::Permission);
            self.host
                .supervision()
                .mark_profile_verified(self.project, ProfilePurpose::Permission, true)
                .expect("verify permission profile");
        }

        fn create_packet_ready(
            &mut self,
        ) -> (
            herness_desktop::supervision::SupervisionView,
            herness_supervision::SupervisionId,
        ) {
            self.configure_purpose(ProfilePurpose::Completion);
            let view = self
                .host
                .supervision_create(
                    PlanRequestActor::Human,
                    CreateSupervisionRequest {
                        project: self.project,
                        connection: self.connection,
                        instructions: PACKET_INSTRUCTION.to_owned(),
                        conditions: vec![super::ConditionInput {
                            title: "The real check passes".to_owned(),
                            rubric: "The failing scripted check forces one continuation.".to_owned(),
                            checks: vec![super::CheckInput {
                                command: "false".to_owned(),
                                description: "scripted failing check".to_owned(),
                            }],
                        }],
                        read_set: vec!["src/main.rs".to_owned()],
                        write_paths: vec!["src".to_owned()],
                        allow_shell: false,
                        condition_version: Some(1),
                        target_version: Some(1),
                        budget: Some(herness_desktop::supervision::BudgetInput {
                            active_seconds: 60,
                            additional_runs: 1,
                            money_limit_micros: None,
                            price_version: None,
                        }),
                    },
                    Some(self.host.confirm_supervision(ConfirmationKind::Create)),
                )
                .expect("create supervision");
            let supervision = view.supervision_id;
            (view, supervision)
        }

        fn create_packet_started(
            &mut self,
        ) -> (
            herness_desktop::supervision::SupervisionView,
            herness_supervision::SupervisionId,
        ) {
            let (view, supervision) = self.create_packet_ready();
            self.host
                .supervision_start(
                    self.project,
                    supervision,
                    herness_supervision::SupervisionRequestId::new(self.project),
                    view.revision,
                    Some(self.host.confirm_supervision(ConfirmationKind::Start)),
                )
                .expect("start supervision");
            (view, supervision)
        }

        fn pump_until(
            &mut self,
            supervision: herness_supervision::SupervisionId,
            requests: usize,
            runs: usize,
        ) -> herness_desktop::supervision::SupervisionView {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                self.host.pump().expect("pump host");
                let view = self
                    .host
                    .supervision_get(self.project, supervision)
                    .expect("supervision view");
                if self.server.count() >= requests && view.run_group.len() >= runs {
                    return view;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for {requests} requests and {runs} runs; \
                     requests={} runs={:?} state={} reason={:?}",
                    self.server.count(),
                    view.run_group,
                    view.state,
                    view.reason
                );
                thread::sleep(Duration::from_millis(20));
            }
        }

        fn create_started(&mut self) -> (herness_desktop::supervision::SupervisionView, RunId) {
            self.configure_purpose(ProfilePurpose::Completion);
            let view = self
                .host
                .supervision_create(
                    PlanRequestActor::Human,
                    CreateSupervisionRequest {
                        project: self.project,
                        connection: self.connection,
                        instructions: "permission composition fixture".to_owned(),
                        conditions: vec![super::ConditionInput {
                            title: "The check passes".to_owned(),
                            rubric: "fixture".to_owned(),
                            checks: vec![super::CheckInput {
                                command: "true".to_owned(),
                                description: "fixture check".to_owned(),
                            }],
                        }],
                        read_set: vec!["src/main.rs".to_owned()],
                        write_paths: vec!["src".to_owned()],
                        allow_shell: false,
                        condition_version: Some(1),
                        target_version: Some(1),
                        budget: None,
                    },
                    Some(self.host.confirm_supervision(ConfirmationKind::Create)),
                )
                .expect("create supervision");
            let started = self
                .host
                .supervision_start(
                    self.project,
                    view.supervision_id,
                    super::SupervisionRequestId::new(self.project),
                    view.revision,
                    Some(self.host.confirm_supervision(ConfirmationKind::Start)),
                )
                .expect("start supervision");
            let run = started
                .run_group
                .first()
                .expect("run")
                .parse::<RunId>()
                .expect("run id");
            let mut ledger = BudgetLedger::open(
                self.host.store_handle(),
                self.project,
                view.supervision_id,
                BudgetPolicy::h2_default(),
                1,
                HostBudgetClock::new(),
            )
            .expect("ledger");
            ledger.begin_active().expect("activate ledger");
            (started, run)
        }

        fn automatic_policy(&self) -> PermissionPolicy {
            let handle = self.host.runtime().policy_handle();
            let mut admin = PolicyAdmin::from_shared(handle.clone());
            admin
                .set_mode(PermissionMode::Automatic, EvaluatorAvailability::Available)
                .expect("automatic mode");
            handle.snapshot()
        }

        fn operation(&self, run: RunId, policy: &PermissionPolicy) -> FrozenOperation {
            FrozenOperation::new(
                OperationId::new(self.project),
                run,
                ToolName::Write,
                ToolArguments::Write(WriteArgs {
                    path: NonEmptyText::new("src/main.rs").expect("path"),
                    content: "permission fixture content".to_owned(),
                    rationale: Rationale::new("permission composition fixture").expect("rationale"),
                }),
                AbsolutePath::new(self.root.to_string_lossy()).expect("cwd"),
                policy.version(),
                PermissionMode::Automatic,
            )
            .expect("frozen operation")
        }

        fn response(&self, operation: &FrozenOperation, decision: &str) -> Value {
            let content = json!({
                "decision": decision,
                "operationId": operation.operation_id().to_string(),
                "argumentsDigest": ArgumentsDigest::of(operation.arguments()).to_string(),
                "cwd": operation.cwd().to_string(),
                "policyVersion": operation.policy_version().get(),
                "mode": operation.permission_mode().to_string(),
                "rationale": "The frozen operation is inside the requested boundary.",
                "uncertainty": null,
            });
            json!({
                "model": MODEL,
                "choices": [{
                    "finish_reason": "stop",
                    "message": {"content": content.to_string()},
                }],
            })
        }
    }

    struct CountingExecutor {
        count: Arc<AtomicUsize>,
    }

    impl ToolExecutor for CountingExecutor {
        type Output = usize;

        fn execute(
            &mut self,
            _operation: &FrozenOperation,
        ) -> Result<Self::Output, herness_core::CoreError> {
            Ok(self.count.fetch_add(1, Ordering::SeqCst) + 1)
        }
    }

    #[test]
    fn production_permission_profile_runs_the_real_evaluator_and_charges_the_shared_ledger() {
        let mut harness = PermissionHost::new();
        assert!(!harness.host.permission_available());
        assert_eq!(
            harness.host.permission_evaluator().availability(),
            EvaluatorAvailability::Unavailable
        );
        assert_eq!(harness.server.count(), 0);

        harness.configure_verified_permission();
        assert!(harness.host.permission_available_for(harness.project));
        assert_eq!(
            harness.host.permission_evaluator().availability(),
            EvaluatorAvailability::Available
        );
        let (view, run) = harness.create_started();
        let policy = harness.automatic_policy();
        let grant = herness_core::GrantScope::for_run(harness.project, &policy);
        let context = EvaluationContext::new(
            "permission composition fixture",
            vec!["src/main.rs".to_owned()],
        );
        let count = Arc::new(AtomicUsize::new(0));
        let mut gateway = ToolGateway::new(CountingExecutor {
            count: Arc::clone(&count),
        });
        let mut evaluator = harness.host.permission_evaluator();

        let allow = harness.operation(run, &policy);
        harness.server.push(harness.response(&allow, "allow"));
        let request = herness_core::EvaluationRequest::new(
            allow.clone(),
            "permission composition fixture",
            "write only src/main.rs",
            vec!["fixture evidence".to_owned()],
        );
        let outcome = gateway
            .authorize(&policy, &grant, &allow, &context, Some(&mut evaluator))
            .expect("authorize allow");
        match outcome {
            PermissionOutcome::Allow { authorization } => {
                gateway
                    .execute(&policy, &allow, &authorization)
                    .expect("execute once");
            }
            other => panic!("expected allow, got {other:?}"),
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let after_allow = harness.server.count();
        assert!(after_allow >= 1, "the allow decision used the provider");

        // The budget ledger is the same durable record the supervision uses.
        let stored = harness
            .host
            .store_handle()
            .lock()
            .load_budget_record(harness.project, view.supervision_id)
            .expect("budget record")
            .expect("budget exists");
        assert!(stored.record().usage().active_seconds_consumed() >= 1);
        let requests = harness
            .host
            .store_handle()
            .lock()
            .model_requests_for_project(&harness.project)
            .expect("model requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].intent().purpose().as_str(),
            "permission_evaluation"
        );
        let recorded = harness.server.requests();
        assert_eq!(recorded[0].path, "/v1/chat/completions");
        assert!(!String::from_utf8_lossy(&recorded[0].body).contains(CONVERSATION_CANARY));
        assert!(String::from_utf8_lossy(&recorded[0].body).contains("operationId"));

        // A single-use authorization cannot execute the same operation twice,
        // and a duplicate evaluation does not reach the provider again.
        assert!(
            gateway
                .authorize(&policy, &grant, &allow, &context, Some(&mut evaluator))
                .is_err()
        );
        assert_eq!(
            harness.server.count(),
            after_allow,
            "a duplicate evaluation must not reach the provider again"
        );

        let deny = harness.operation(run, &policy);
        harness.server.push(harness.response(&deny, "deny"));
        let deny_request = herness_core::EvaluationRequest::new(
            deny.clone(),
            "permission composition fixture",
            "write only src/main.rs",
            vec!["fixture evidence".to_owned()],
        );
        assert_eq!(
            gateway
                .authorize(&policy, &grant, &deny, &context, Some(&mut evaluator))
                .expect("authorize deny"),
            PermissionOutcome::Deny {
                reason: herness_core::DenialReason::Evaluator
            }
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let after_deny = harness.server.count();
        assert!(
            after_deny > after_allow,
            "the deny decision used the provider"
        );

        let ask = harness.operation(run, &policy);
        harness.server.push(harness.response(&ask, "ask"));
        let ask_request = herness_core::EvaluationRequest::new(
            ask.clone(),
            "permission composition fixture",
            "write only src/main.rs",
            vec!["fixture evidence".to_owned()],
        );
        assert!(matches!(
            gateway
                .authorize(&policy, &grant, &ask, &context, Some(&mut evaluator))
                .expect("authorize ask"),
            PermissionOutcome::AwaitingApproval { .. }
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(
            harness.server.count() > after_deny,
            "the ask decision used the provider"
        );
        let _ = (request, deny_request, ask_request);
    }

    #[test]
    fn without_a_verified_permission_profile_the_evaluator_never_sends() {
        let harness = PermissionHost::new();
        assert!(!harness.host.permission_available());
        assert_eq!(
            harness.host.permission_evaluator().availability(),
            EvaluatorAvailability::Unavailable
        );
        assert!(!harness.host.permission_available_for(harness.project));

        let policy = PermissionPolicy::initial();
        let run = RunId::new(harness.project);
        let operation = harness.operation(run, &policy);
        let request = herness_core::EvaluationRequest::new(
            operation,
            "permission composition fixture",
            "write only src/main.rs",
            vec!["fixture evidence".to_owned()],
        );
        let mut evaluator = harness.host.permission_evaluator();
        assert!(evaluator.evaluate(&request).is_err());
        assert_eq!(harness.server.count(), 0);
        assert_eq!(harness.credentials.resolves.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn explicit_deny_precedes_the_permission_evaluator() {
        let mut harness = PermissionHost::new();
        harness.configure_verified_permission();
        let (_view, run) = harness.create_started();
        let _ = harness.automatic_policy();
        let handle = harness.host.runtime().policy_handle();
        let mut admin = PolicyAdmin::from_shared(handle.clone());
        admin
            .add_rule(
                PermissionRule::deny(
                    RuleTarget::Tool {
                        tool: ToolName::Write,
                    },
                    herness_core::MatchMethod::AnyInvocation,
                )
                .expect("deny rule"),
            )
            .expect("add rule");
        let policy = handle.snapshot();
        let grant = herness_core::GrantScope::for_run(harness.project, &policy);
        let context = EvaluationContext::new("permission composition fixture", Vec::new());
        let count = Arc::new(AtomicUsize::new(0));
        let mut gateway = ToolGateway::new(CountingExecutor {
            count: Arc::clone(&count),
        });
        let mut evaluator = harness.host.permission_evaluator();
        let operation = harness.operation(run, &policy);
        let outcome = gateway
            .authorize(&policy, &grant, &operation, &context, Some(&mut evaluator))
            .expect("authorize deny rule");
        assert!(matches!(outcome, PermissionOutcome::Deny { .. }));
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(harness.server.count(), 0);
    }

    #[test]
    fn real_pi_uses_the_owner_packet_scope_and_conversation_for_two_runs() {
        let mut harness = PermissionHost::with_test_boundaries();
        harness.allow_write_and_shell_at_policy();
        harness.server.push_sse(completions_tool_call(
            "call_outside",
            "write",
            json!({
                "path": "outside.txt",
                "content": "outside once",
                "rationale": "attempt outside the approved write scope",
            }),
        ));
        harness.server.push_sse(completions_tool_call(
            "call_inside",
            "write",
            json!({
                "path": "src/inside.txt",
                "content": "inside once",
                "rationale": "write inside the approved write scope",
            }),
        ));
        harness.server.push_sse(completions_tool_call(
            "call_shell",
            "bash",
            json!({
                "command": "printf x >> shell-ran.txt",
                "purpose": "attempt shell while allowShell is false",
            }),
        ));
        harness.server.push_sse(completions_text("first turn complete"));
        harness.server.push_sse(completions_text("second turn complete"));

        let (_created, supervision) = harness.create_packet_started();
        let view = harness.pump_until(supervision, 5, 2);
        assert!(
            view.run_group.len() >= 2,
            "the failing check must start an additional run"
        );

        let requests = harness.server.requests();
        assert!(
            requests.len() >= 5,
            "expected the first and second run requests, got {}",
            requests.len()
        );
        let first = String::from_utf8_lossy(&requests[0].body);
        assert!(
            first.contains(PACKET_INSTRUCTION),
            "the real Pi initial input must contain the owner instruction"
        );
        assert!(
            first.contains("Immutable work packet"),
            "the initial input must contain the immutable packet"
        );
        assert!(first.contains("read paths: src/main.rs"));
        assert!(first.contains("write paths: src"));
        assert!(first.contains("shell: not allowed"));
        assert!(
            !first.contains("Work toward the approved completion conditions."),
            "the generic fallback instruction must never replace the packet"
        );

        let continuation = requests
            .iter()
            .find(|request| {
                String::from_utf8_lossy(&request.body).contains("Current deficiency:")
            })
            .expect("the second run must include the current deficiency");
        let continuation = String::from_utf8_lossy(&continuation.body);
        assert!(
            continuation.contains(PACKET_INSTRUCTION),
            "the continuation must repeat the invariant owner packet"
        );
        assert!(
            continuation.contains("first turn complete"),
            "the second run must keep the first conversation"
        );
        assert!(
            continuation.contains("Required checks not passing")
                || continuation.contains("not passing"),
            "the continuation must carry the current deficiency"
        );

        assert!(
            !harness.root.join("outside.txt").exists(),
            "a write outside the approved write paths must execute zero changes"
        );
        assert_eq!(
            std::fs::read_to_string(harness.root.join("src/inside.txt")).expect("inside file"),
            "inside once",
            "a write inside the approved write paths must execute"
        );
        assert!(
            !harness.root.join("shell-ran.txt").exists(),
            "allowShell=false must execute zero model shell commands"
        );
    }

    #[test]
    fn desktop_h1_refuses_changed_packets_before_starting_a_run() {
        let mut harness = PermissionHost::with_test_boundaries();
        let (_view, supervision) = harness.create_packet_ready();
        let store = harness.host.store_handle();
        let plans = harness.host.supervision().plans();
        let plan = plans
            .lock()
            .expect("plans")
            .get(&(harness.project, supervision))
            .cloned()
            .expect("stored plan");

        let request_id = SupervisionRequestId::new(harness.project);
        let run_id = RunId::new(harness.project);
        let input_id = InputId::new(harness.project);
        let condition_version = plan.contract.conditions().condition_version();
        let target_version = plan.contract.evidence_target().version();
        let profile = plan.contract.profile();
        let consent = plan.contract.consent();

        let mut tampered = serde_json::to_value(&plan.packet).expect("packet value");
        tampered["instruction"] = json!("tampered packet instruction");
        let tampered: WorkPacket = serde_json::from_value(tampered).expect("tampered shape");
        let start = ChildRunStart::new(
            request_id,
            harness.project,
            supervision,
            run_id,
            input_id,
            condition_version,
            target_version,
            profile,
            consent,
            tampered,
        );
        let mut adapter = DesktopH1::new(harness.host.runtime_mut(), store.clone(), plans.clone());
        let result = adapter.start_child(&start);
        assert!(
            matches!(
                result,
                Err(SupervisionError::WorkPacketRejected {
                    reason: WorkPacketRejection::FingerprintMismatch
                })
            ),
            "a request packet with a bad fingerprint must be refused: {result:?}"
        );
        drop(adapter);
        assert_eq!(harness.server.count(), 0);

        let alternate = WorkPacket::new(
            plan.packet.packet_version(),
            "a different but validly fingerprinted instruction",
            harness.project,
            &plan.evidence_target,
            plan.execution_scope.clone(),
            plan.conditions.condition_version(),
            plan.profile.binding(),
            plan.consent.binding(),
            plan.budget_version,
            plan.budget.policy().expect("budget policy"),
        )
        .expect("alternate packet");
        let start = ChildRunStart::new(
            SupervisionRequestId::new(harness.project),
            harness.project,
            supervision,
            RunId::new(harness.project),
            InputId::new(harness.project),
            condition_version,
            target_version,
            profile,
            consent,
            alternate,
        );
        let mut adapter = DesktopH1::new(harness.host.runtime_mut(), store, plans);
        let result = adapter.start_child(&start);
        assert!(
            matches!(
                result,
                Err(SupervisionError::WorkPacketRejected {
                    reason: WorkPacketRejection::Mismatch { .. }
                })
            ),
            "a valid but different packet must be refused as a mismatch: {result:?}"
        );
        assert_eq!(harness.server.count(), 0);
    }

    // -----------------------------------------------------------------------
    // Html assessment purpose and consent separation (Task 12).
    // -----------------------------------------------------------------------

    struct AllConnectionCredentials {
        secret: String,
    }

    impl AllConnectionCredentials {
        fn new() -> Self {
            Self {
                secret: API_KEY.to_owned(),
            }
        }
    }

    impl CredentialPort for AllConnectionCredentials {
        fn availability(
            &self,
            _connection: &ConnectionId,
        ) -> Result<CredentialAvailability, herness_core::CoreError> {
            Ok(CredentialAvailability::Available)
        }

        fn resolve(
            &self,
            _connection: &ConnectionId,
        ) -> Result<ResolvedCredential, herness_core::CoreError> {
            Ok(ResolvedCredential::new(
                CredentialKind::ApiKey,
                SecretString::new(self.secret.clone())?,
            ))
        }
    }

    fn port_host(harness: &PermissionHost) -> PortAssessmentHost {
        PortAssessmentHost {
            directory: harness.host.directory().clone(),
            credentials: Arc::new(AllConnectionCredentials::new()),
            endpoints: AssessmentEndpoints::for_loopback(
                harness.server.url(),
                harness.server.api_base(),
                harness.server.url(),
            )
            .expect("assessment loopback endpoints"),
        }
    }

    fn add_loopback_connection(
        harness: &PermissionHost,
        base: &str,
        input: InputCapabilities,
    ) -> ConnectionId {
        let connection = ConnectionId::new();
        harness
            .host
            .connections()
            .add(
                ConnectionSettings::new_with_capabilities(
                    connection,
                    Provider::OpenAiCompatible,
                    MODEL,
                    AuthMethod::ApiKey,
                    Some(Endpoint::parse(base).expect("loopback endpoint")),
                    None,
                    ConnectionCapabilityDeclaration::new(EndpointClass::OpenAiCompletions, input),
                )
                .expect("loopback connection settings"),
            )
            .expect("add loopback connection");
        connection
    }

    fn set_html_profile(
        harness: &PermissionHost,
        connection: ConnectionId,
        required_inputs: herness_supervision::ProfileInputs,
        grant: bool,
        target_version: u64,
    ) -> herness_supervision::AssessmentProfile {
        let host = port_host(harness);
        let built = herness_desktop::supervision::assessment::build_profile(
            &host,
            harness.project,
            ProfilePurpose::Html,
            connection,
            MODEL,
        )
        .expect("html profile");
        let profile = herness_supervision::AssessmentProfile::new(
            herness_supervision_tests::ids(harness.project).profile,
            herness_supervision::ProfileVersion::new(1).expect("profile version"),
            ProfilePurpose::Html,
            built.profile.provider(),
            connection,
            built.profile.model().clone(),
            built.profile.adapter_version().clone(),
            built.profile.rubric_version().clone(),
            required_inputs,
            herness_supervision::ProfileThresholds::normal_llm(),
        )
        .expect("html profile");
        let mut config = harness.host.supervision().config().get(harness.project);
        config.set_profile(profile.clone(), true);
        harness
            .host
            .supervision()
            .config()
            .set(harness.project, config);
        if grant {
            let origin = host.origin_for(connection).expect("html profile origin");
            harness
                .host
                .supervision_grant_consent(
                    PlanRequestActor::Human,
                    harness.project,
                    ProfilePurpose::Html,
                    origin,
                    BTreeSet::from([DisclosureDataKind::Text]),
                    vec!["src/main.rs".to_owned()],
                    TargetVersion::new(target_version).expect("target version"),
                    Some(harness.host.confirm_supervision(ConfirmationKind::Consent)),
                )
                .expect("html consent");
        }
        profile
    }

    fn create_target(
        harness: &mut PermissionHost,
        connection: ConnectionId,
        budget: Option<HostBudgetInput>,
    ) -> (
        herness_desktop::supervision::SupervisionView,
        SupervisionId,
    ) {
        let project = harness.project;
        let view = harness
            .host
            .supervision_create(
                PlanRequestActor::Human,
                CreateSupervisionRequest {
                    project,
                    connection,
                    instructions: PACKET_INSTRUCTION.to_owned(),
                    conditions: vec![super::ConditionInput {
                        title: "The check passes".to_owned(),
                        rubric: "The Html assessment fixture uses a stable target.".to_owned(),
                        checks: vec![super::CheckInput {
                            command: "true".to_owned(),
                            description: "fixture check".to_owned(),
                        }],
                    }],
                    read_set: vec!["src/main.rs".to_owned()],
                    write_paths: vec!["src".to_owned()],
                    allow_shell: false,
                    condition_version: Some(1),
                    target_version: Some(1),
                    budget,
                },
                Some(harness.host.confirm_supervision(ConfirmationKind::Create)),
            )
            .expect("create html target");
        let supervision = view.supervision_id;
        (view, supervision)
    }

    fn default_budget() -> Option<HostBudgetInput> {
        Some(HostBudgetInput {
            active_seconds: 60,
            additional_runs: 1,
            money_limit_micros: None,
            price_version: None,
        })
    }

    fn activate_ledger(
        harness: &PermissionHost,
        supervision: SupervisionId,
        start_run: bool,
    ) -> BudgetPolicy {
        let store = harness.host.store_handle();
        let plan = herness_desktop::supervision::plan::load_plan(
            &store,
            harness.project,
            supervision,
        )
        .expect("load plan")
        .expect("plan");
        let policy = plan.budget.policy().expect("budget policy");
        let mut ledger = BudgetLedger::open(
            store,
            harness.project,
            supervision,
            policy.clone(),
            plan.budget_version,
            HostBudgetClock::new(),
        )
        .expect("open ledger");
        ledger.begin_active().expect("activate ledger");
        if start_run {
            ledger
                .start_run(BudgetRequestId::new(harness.project))
                .expect("start one budget run");
        }
        policy
    }

    fn append_evidence(
        harness: &PermissionHost,
        supervision: SupervisionId,
        condition: ConditionId,
        target: &TargetScope,
        sequence: u64,
        detail: &str,
    ) -> EvidenceId {
        let id = EvidenceId::new(harness.project);
        let record = EvidenceRecord::new(
            id,
            supervision,
            Some(condition),
            None,
            EvidenceAcquirer::ChildAgent,
            VerificationOperation::command("true").expect("operation"),
            EvidenceOutcome::new(Some(0), None, false, false, detail).expect("outcome"),
            target.clone(),
            EvidenceScope::new(
                vec![format!("html assessment {sequence}")],
                vec!["fixture scope".to_owned()],
            )
            .expect("scope"),
            CheckStatus::Pass,
            sequence,
            Timestamp::now(),
        )
        .expect("evidence");
        harness
            .host
            .store_handle()
            .append(record)
            .expect("append evidence");
        id
    }

    fn html_request(
        harness: &PermissionHost,
        supervision: SupervisionId,
        condition: ConditionId,
        profile: &herness_supervision::AssessmentProfile,
        target_version: u64,
        evidence: Vec<EvidenceId>,
    ) -> AssessmentRequest {
        AssessmentRequest::new(
            DecisionId::new(harness.project),
            supervision,
            condition,
            herness_supervision::ConditionVersion::new(1).expect("condition version"),
            TargetVersion::new(target_version).expect("target version"),
            "H3 Html assessment rubric: preserve source information and meaning.",
            profile.binding(),
            profile.adapter_version().clone(),
            profile.rubric_version().clone(),
            evidence,
        )
        .expect("html assessment request")
    }

    fn completion_request(
        harness: &PermissionHost,
        supervision: SupervisionId,
        condition: ConditionId,
        profile: &herness_supervision::AssessmentProfile,
        evidence: Vec<EvidenceId>,
    ) -> AssessmentRequest {
        AssessmentRequest::new(
            DecisionId::new(harness.project),
            supervision,
            condition,
            herness_supervision::ConditionVersion::new(1).expect("condition version"),
            TargetVersion::new(1).expect("target version"),
            "The completion condition is met when the recorded check passes.",
            profile.binding(),
            profile.adapter_version().clone(),
            profile.rubric_version().clone(),
            evidence,
        )
        .expect("completion assessment request")
    }

    fn push_llm_answer(server: &PermissionMock, condition: ConditionId, evidence: &[EvidenceId]) {
        let content = json!({
            "conditions": [{
                "conditionId": condition.to_string(),
                "verdict": "met",
                "evidenceIds": evidence.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "rationale": "The supplied Html evidence supports the condition.",
                "uncertainty": null,
            }],
        })
        .to_string();
        server.push(json!({
            "model": MODEL,
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": content},
            }],
        }));
    }

    fn html_condition_and_target(
        harness: &PermissionHost,
        view: &herness_desktop::supervision::SupervisionView,
    ) -> (ConditionId, TargetScope) {
        let condition = view
            .conditions
            .first()
            .expect("fixture condition")
            .condition_id
            .parse::<ConditionId>()
            .expect("condition id");
        let plan = herness_desktop::supervision::plan::load_plan(
            &harness.host.store_handle(),
            harness.project,
            view.supervision_id,
        )
        .expect("load plan")
        .expect("plan");
        (condition, plan.evidence_target)
    }

    #[test]
    fn html_assessment_uses_its_own_profile_consent_origin_and_the_same_cycle_ledger() {
        let mut harness = PermissionHost::new();
        harness.configure_purpose(ProfilePurpose::Completion);
        harness
            .host
            .supervision_mark_profile_verified(harness.project, ProfilePurpose::Completion, true)
            .expect("verify completion profile");

        // The Html assessment model is a separate connection and origin from
        // the target's Completion/authoring disclosure.
        let html_server = PermissionMock::start();
        let html_connection = add_loopback_connection(
            &harness,
            html_server.api_base().as_str(),
            InputCapabilities::text_only(),
        );
        let html_profile = set_html_profile(
            &harness,
            html_connection,
            herness_supervision::ProfileInputs::text_only(),
            true,
            1,
        );

        let connection = harness.connection;
        let (view, supervision) = create_target(&mut harness, connection, default_budget());
        let (condition, target) = html_condition_and_target(&harness, &view);
        activate_ledger(&harness, supervision, true);
        let evidence = vec![
            append_evidence(
                &harness,
                supervision,
                condition,
                &target,
                1,
                "source unit and candidate content",
            ),
            append_evidence(
                &harness,
                supervision,
                condition,
                &target,
                2,
                "render and provenance evidence",
            ),
        ];

        let request = html_request(
            &harness,
            supervision,
            condition,
            &html_profile,
            1,
            evidence.clone(),
        );
        push_llm_answer(&html_server, condition, &evidence);
        let mut port = HostAssessmentPort::new(
            harness.host.store_handle(),
            harness.host.supervision().config(),
            port_host(&harness),
        );
        let html_facts = port
            .profile(html_profile.binding())
            .expect("html profile facts");
        assert_eq!(html_facts.adapter_version().as_str(), "herness-llm-condition-v1");
        let result = port.assess(&request).expect("html assessment");
        assert_eq!(result.purpose(), ProfilePurpose::Html);
        assert_eq!(
            result.provenance().purpose(),
            Some(ProfilePurpose::Html)
        );
        assert_eq!(result.reported_verdict(), herness_supervision::ConditionVerdict::Met);
        assert_eq!(html_server.count(), 1);
        assert_eq!(harness.server.count(), 0);
        let html_body = html_server.requests()[0].json_body();
        assert!(!html_body.to_string().contains("\"tools\":"));
        assert!(!html_body.to_string().contains("\"tool_choice\":"));
        assert!(
            html_body.to_string().contains(&condition.to_string()),
            "the Html request must carry the condition id"
        );

        // The same target completes a Completion assessment using the bound
        // Completion profile/consent and its own origin. It is the same ledger.
        let completion_profile = herness_desktop::supervision::plan::load_plan(
            &harness.host.store_handle(),
            harness.project,
            supervision,
        )
        .expect("load plan")
        .expect("plan")
        .profile;
        let completion = completion_request(
            &harness,
            supervision,
            condition,
            &completion_profile,
            evidence.clone(),
        );
        push_llm_answer(&harness.server, condition, &evidence);
        let completion_result = port.assess(&completion).expect("completion assessment");
        assert_eq!(completion_result.purpose(), ProfilePurpose::Completion);
        assert_eq!(harness.server.count(), 1);
        assert_eq!(html_server.count(), 1);

        let requests = harness
            .host
            .store_handle()
            .lock()
            .model_requests_for_project(&harness.project)
            .expect("model requests");
        let mut purposes = requests
            .iter()
            .map(|request| request.intent().purpose().as_str().to_owned())
            .collect::<Vec<_>>();
        purposes.sort();
        assert_eq!(
            purposes,
            vec!["completion_assessment".to_owned(), "html_assessment".to_owned()]
        );

        let budget = harness
            .host
            .store_handle()
            .lock()
            .load_budget_record(harness.project, supervision)
            .expect("budget record")
            .expect("budget exists");
        assert_eq!(budget.record().usage().runs_started(), 1);
        assert!(budget.record().usage().active_seconds_consumed() >= 1);
        assert_eq!(
            budget.record().usage().money_consumed(),
            herness_supervision::Money::zero()
        );

        // A stale Html request cannot be sent against another target version.
        let stale = html_request(&harness, supervision, condition, &html_profile, 2, evidence);
        let error = port.assess(&stale).unwrap_err();
        assert!(matches!(
            error,
            SupervisionError::AssessmentContractViolation { .. }
        ));
        assert_eq!(html_server.count(), 1);
    }

    #[test]
    fn html_requires_its_own_consent_and_does_not_borrow_authoring_consent() {
        let mut harness = PermissionHost::new();
        harness.configure_purpose(ProfilePurpose::Completion);
        harness
            .host
            .supervision_mark_profile_verified(harness.project, ProfilePurpose::Completion, true)
            .expect("verify completion profile");

        let html_server = PermissionMock::start();
        let html_connection = add_loopback_connection(
            &harness,
            html_server.api_base().as_str(),
            InputCapabilities::text_only(),
        );
        let html_profile = set_html_profile(
            &harness,
            html_connection,
            herness_supervision::ProfileInputs::text_only(),
            false,
            1,
        );

        let connection = harness.connection;
        let (view, supervision) = create_target(&mut harness, connection, default_budget());
        let (condition, target) = html_condition_and_target(&harness, &view);
        activate_ledger(&harness, supervision, false);
        let evidence = vec![append_evidence(
            &harness,
            supervision,
            condition,
            &target,
            1,
            "html evidence",
        )];
        let request = html_request(
            &harness,
            supervision,
            condition,
            &html_profile,
            1,
            evidence.clone(),
        );
        let mut port = HostAssessmentPort::new(
            harness.host.store_handle(),
            harness.host.supervision().config(),
            port_host(&harness),
        );

        // A Completion consent exists for the target, but no Html consent does.
        // The Html request must not borrow it.
        let error = port.assess(&request).unwrap_err();
        assert!(matches!(
            error,
            SupervisionError::ConsentBlocked {
                reason: ConsentBlock::Revoked
            }
        ));
        assert_eq!(html_server.count(), 0);
        assert_eq!(harness.server.count(), 0);

        // The exact Html consent and origin allow the Html request.
        let html_origin = port_host(&harness)
            .origin_for(html_connection)
            .expect("html origin");
        let original_html_consent = harness
            .host
            .supervision()
            .config()
            .get(harness.project)
            .consent(ProfilePurpose::Html)
            .cloned();
        harness
            .host
            .supervision_grant_consent(
                PlanRequestActor::Human,
                harness.project,
                ProfilePurpose::Html,
                html_origin.clone(),
                BTreeSet::from([DisclosureDataKind::Text]),
                vec!["src/main.rs".to_owned()],
                TargetVersion::new(1).expect("target version"),
                Some(harness.host.confirm_supervision(ConfirmationKind::Consent)),
            )
            .expect("html consent");
        assert!(original_html_consent.is_none());
        push_llm_answer(&html_server, condition, &evidence);
        port.assess(&request).expect("html assessment with consent");
        assert_eq!(html_server.count(), 1);
        assert_eq!(harness.server.count(), 0);

        // Revocation rejects before a provider send.
        harness
            .host
            .supervision_revoke_consent(
                PlanRequestActor::Human,
                harness.project,
                ProfilePurpose::Html,
                Some(harness.host.confirm_supervision(ConfirmationKind::Consent)),
            )
            .expect("revoke html consent");
        let error = port.assess(&request).unwrap_err();
        assert!(matches!(
            error,
            SupervisionError::ConsentBlocked {
                reason: ConsentBlock::Revoked
            }
        ));
        assert_eq!(html_server.count(), 1);
        assert_eq!(harness.server.count(), 0);

        // The Html assessment consent is not an authoring/contract consent:
        // the contract-bound disclosure still requires the Completion consent.
        let record = harness
            .host
            .supervision_record(harness.project, supervision)
            .expect("record")
            .expect("stored record");
        let plan = herness_desktop::supervision::plan::load_plan(
            &harness.host.store_handle(),
            harness.project,
            supervision,
        )
        .expect("load plan")
        .expect("plan");
        let contract = plan.contract(&record, Timestamp::now()).expect("contract");
        let granted_html = herness_supervision::DisclosureConsent::grant(
            herness_supervision::ApprovalActor::Human,
            herness_supervision::ConsentId::new(harness.project),
            html_origin.clone(),
            herness_supervision::DisclosureScope::new(
                ProfilePurpose::Html,
                BTreeSet::from([DisclosureDataKind::Text]),
                vec!["src/main.rs".to_owned()],
                TargetVersion::new(1).expect("target version"),
            )
            .expect("html disclosure scope"),
            Timestamp::now(),
        )
        .expect("html assessment consent");
        let authoring_origin = ProviderOrigin::parse(harness.server.url()).expect("authoring origin");
        let authoring_request = DisclosureRequest::new(
            harness.project,
            authoring_origin,
            ProfilePurpose::Completion,
            BTreeSet::from([DisclosureDataKind::Text]),
            TargetVersion::new(1).expect("target version"),
        )
        .expect("authoring disclosure request");
        assert_eq!(
            contract.authorize_disclosure(&granted_html, &authoring_request),
            Err(ConsentBlock::VersionMismatch)
        );
        assert_eq!(
            granted_html.authorize(&authoring_request),
            Err(ConsentBlock::DifferentOrigin)
        );
        let html_at_authoring_origin = DisclosureRequest::new(
            harness.project,
            html_origin,
            ProfilePurpose::Completion,
            BTreeSet::from([DisclosureDataKind::Text]),
            TargetVersion::new(1).expect("target version"),
        )
        .expect("html-origin disclosure request");
        assert_eq!(
            granted_html.authorize(&html_at_authoring_origin),
            Err(ConsentBlock::DifferentPurpose)
        );
    }

    #[test]
    fn money_capped_html_and_completion_assessments_refuse_before_send() {
        let mut harness = PermissionHost::new();
        harness.configure_purpose(ProfilePurpose::Completion);
        harness
            .host
            .supervision_mark_profile_verified(harness.project, ProfilePurpose::Completion, true)
            .expect("verify completion profile");
        let html_profile = set_html_profile(
            &harness,
            harness.connection,
            herness_supervision::ProfileInputs::text_only(),
            true,
            1,
        );
        let connection = harness.connection;
        let (view, supervision) = create_target(
            &mut harness,
            connection,
            Some(HostBudgetInput {
                active_seconds: 60,
                additional_runs: 1,
                money_limit_micros: Some(100_000),
                price_version: Some("fixture-price-v1".to_owned()),
            }),
        );
        let (condition, target) = html_condition_and_target(&harness, &view);
        activate_ledger(&harness, supervision, false);
        let evidence = vec![append_evidence(
            &harness,
            supervision,
            condition,
            &target,
            1,
            "html evidence",
        )];
        let html = html_request(
            &harness,
            supervision,
            condition,
            &html_profile,
            1,
            evidence.clone(),
        );
        let completion_profile = herness_desktop::supervision::plan::load_plan(
            &harness.host.store_handle(),
            harness.project,
            supervision,
        )
        .expect("load plan")
        .expect("plan")
        .profile;
        let completion = completion_request(
            &harness,
            supervision,
            condition,
            &completion_profile,
            evidence,
        );
        let mut port = HostAssessmentPort::new(
            harness.host.store_handle(),
            harness.host.supervision().config(),
            port_host(&harness),
        );

        for request in [&html, &completion] {
            let error = port.assess(request).unwrap_err();
            assert!(matches!(
                error,
                SupervisionError::Unsupported { ref feature }
                    if feature.contains("budget admission refused")
            ));
        }
        assert_eq!(harness.server.count(), 0);
        let requests = harness
            .host
            .store_handle()
            .lock()
            .model_requests_for_project(&harness.project)
            .expect("model requests");
        assert!(requests.is_empty());
        let budget = harness
            .host
            .store_handle()
            .lock()
            .load_budget_record(harness.project, supervision)
            .expect("budget record")
            .expect("budget exists");
        assert_eq!(
            budget.record().usage().money_reserved(),
            herness_supervision::Money::zero()
        );
        assert_eq!(
            budget.record().usage().money_consumed(),
            herness_supervision::Money::zero()
        );
    }

    #[test]
    fn html_image_requirements_revoked_consent_and_oversize_evidence_reject_before_send() {
        let mut harness = PermissionHost::new();
        harness.configure_purpose(ProfilePurpose::Completion);
        harness
            .host
            .supervision_mark_profile_verified(harness.project, ProfilePurpose::Completion, true)
            .expect("verify completion profile");
        let text_profile = set_html_profile(
            &harness,
            harness.connection,
            herness_supervision::ProfileInputs::text_only(),
            true,
            1,
        );
        let connection = harness.connection;
        let (view, supervision) = create_target(&mut harness, connection, default_budget());
        let (condition, target) = html_condition_and_target(&harness, &view);
        activate_ledger(&harness, supervision, false);
        let evidence = vec![append_evidence(
            &harness,
            supervision,
            condition,
            &target,
            1,
            "html evidence",
        )];
        let mut port = HostAssessmentPort::new(
            harness.host.store_handle(),
            harness.host.supervision().config(),
            port_host(&harness),
        );

        // Revoked consent rejects before any provider request.
        harness
            .host
            .supervision_revoke_consent(
                PlanRequestActor::Human,
                harness.project,
                ProfilePurpose::Html,
                Some(harness.host.confirm_supervision(ConfirmationKind::Consent)),
            )
            .expect("revoke html consent");
        let request = html_request(
            &harness,
            supervision,
            condition,
            &text_profile,
            1,
            evidence.clone(),
        );
        let error = port.assess(&request).unwrap_err();
        assert!(matches!(
            error,
            SupervisionError::ConsentBlocked {
                reason: ConsentBlock::Revoked
            }
        ));
        assert_eq!(harness.server.count(), 0);

        // An image-requiring Html profile on a text-only connection is not a
        // text-only assessment.
        harness
            .host
            .supervision_grant_consent(
                PlanRequestActor::Human,
                harness.project,
                ProfilePurpose::Html,
                ProviderOrigin::parse(harness.server.url()).expect("origin"),
                BTreeSet::from([DisclosureDataKind::Text]),
                vec!["src/main.rs".to_owned()],
                TargetVersion::new(1).expect("target version"),
                Some(harness.host.confirm_supervision(ConfirmationKind::Consent)),
            )
            .expect("html consent");
        let text_only_connection_profile = set_html_profile(
            &harness,
            harness.connection,
            herness_supervision::ProfileInputs::new(true, true, false),
            false,
            1,
        );
        let image_request = html_request(
            &harness,
            supervision,
            condition,
            &text_only_connection_profile,
            1,
            evidence.clone(),
        );
        let error = port.assess(&image_request).unwrap_err();
        assert!(matches!(
            error,
            SupervisionError::ProfileUnavailable {
                reason: ProfileUnavailable::MissingInput { .. }
            }
        ));
        assert_eq!(harness.server.count(), 0);

        // Even an image-capable connection is not used for text-only evidence
        // when the Html profile declares an image requirement.
        let image_connection = add_loopback_connection(
            &harness,
            "http://127.0.0.1:9/v1",
            InputCapabilities::text_and_image(),
        );
        let image_profile = set_html_profile(
            &harness,
            image_connection,
            herness_supervision::ProfileInputs::new(true, true, false),
            true,
            1,
        );
        let image_request = html_request(
            &harness,
            supervision,
            condition,
            &image_profile,
            1,
            evidence.clone(),
        );
        let error = port.assess(&image_request).unwrap_err();
        assert!(matches!(
            error,
            SupervisionError::ProfileUnavailable {
                reason: ProfileUnavailable::MissingInput { .. }
            }
        ));
        assert_eq!(harness.server.count(), 0);

        // Restore the text profile and consent for the oversize evidence case.
        set_html_profile(
            &harness,
            harness.connection,
            herness_supervision::ProfileInputs::text_only(),
            true,
            1,
        );
        let oversized = append_evidence(
            &harness,
            supervision,
            condition,
            &target,
            2,
            &"x".repeat(110_000),
        );
        let oversized_request = html_request(
            &harness,
            supervision,
            condition,
            &text_profile,
            1,
            vec![oversized],
        );
        let error = port.assess(&oversized_request).unwrap_err();
        assert!(
            matches!(
                error,
                SupervisionError::AssessmentContractViolation { .. }
            ),
            "unexpected oversize error: {error:?}"
        );
        assert_eq!(harness.server.count(), 0);
        let requests = harness
            .host
            .store_handle()
            .lock()
            .model_requests_for_project(&harness.project)
            .expect("model requests");
        assert!(
            requests.is_empty(),
            "a rejected Html image/consent/oversize request must not record a send intent"
        );
    }

    #[test]
    fn html_assessment_requires_a_verified_profile_and_rejects_a_permission_request() {
        let mut harness = PermissionHost::new();
        harness.configure_purpose(ProfilePurpose::Completion);
        harness
            .host
            .supervision_mark_profile_verified(harness.project, ProfilePurpose::Completion, true)
            .expect("verify completion profile");
        let html_profile = set_html_profile(
            &harness,
            harness.connection,
            herness_supervision::ProfileInputs::text_only(),
            true,
            1,
        );
        let connection = harness.connection;
        let (view, supervision) = create_target(&mut harness, connection, default_budget());
        let (condition, target) = html_condition_and_target(&harness, &view);
        activate_ledger(&harness, supervision, false);
        let evidence = vec![append_evidence(
            &harness,
            supervision,
            condition,
            &target,
            1,
            "html evidence",
        )];
        let mut port = HostAssessmentPort::new(
            harness.host.store_handle(),
            harness.host.supervision().config(),
            port_host(&harness),
        );

        // Permission requests never enter the condition assessment gate.
        let permission_profile = herness_supervision::AssessmentProfile::new(
            herness_supervision::ProfileId::new(harness.project),
            herness_supervision::ProfileVersion::new(1).expect("version"),
            ProfilePurpose::Permission,
            ProviderKind::NormalLlm,
            harness.connection,
            ModelId::new(MODEL).expect("model"),
            AdapterVersion::new("herness-llm-condition-v1").expect("adapter"),
            RubricVersion::new("herness-conditions-v1").expect("rubric"),
            herness_supervision::ProfileInputs::text_only(),
            ProfileThresholds::normal_llm(),
        )
        .expect("permission profile");
        let mut config = harness.host.supervision().config().get(harness.project);
        config.set_profile(permission_profile.clone(), true);
        harness
            .host
            .supervision()
            .config()
            .set(harness.project, config);
        let permission_request = AssessmentRequest::new(
            DecisionId::new(harness.project),
            supervision,
            condition,
            herness_supervision::ConditionVersion::new(1).expect("version"),
            TargetVersion::new(1).expect("version"),
            "fixture permission rubric",
            permission_profile.binding(),
            permission_profile.adapter_version().clone(),
            permission_profile.rubric_version().clone(),
            evidence,
        )
        .expect("permission request");
        let error = port.assess(&permission_request).unwrap_err();
        assert!(matches!(error, SupervisionError::Unsupported { .. }));
        assert_eq!(harness.server.count(), 0);

        // An unverified Html profile is not usable.
        let mut config = harness.host.supervision().config().get(harness.project);
        let unverified = herness_supervision::AssessmentProfile::new(
            html_profile.id(),
            herness_supervision::ProfileVersion::new(2).expect("version"),
            ProfilePurpose::Html,
            html_profile.provider(),
            html_profile.connection(),
            html_profile.model().clone(),
            html_profile.adapter_version().clone(),
            html_profile.rubric_version().clone(),
            html_profile.required_inputs(),
            html_profile.thresholds(),
        )
        .expect("unverified profile");
        config.set_profile(unverified.clone(), false);
        harness
            .host
            .supervision()
            .config()
            .set(harness.project, config);
        let request = html_request(
            &harness,
            supervision,
            condition,
            &unverified,
            1,
            vec![EvidenceId::new(harness.project)],
        );
        let error = port.assess(&request).unwrap_err();
        assert!(matches!(
            error,
            SupervisionError::Unsupported { .. } | SupervisionError::ProfileUnavailable { .. }
        ));
        assert_eq!(harness.server.count(), 0);
    }
}

#[test]
fn command_code_assessment_connection_is_registered_and_profile_is_verified_by_human() {
    use herness_core::{
        AssessmentGateway, ConnectionCapabilityDeclaration, EndpointClass, InputCapabilities,
    };

    let admin = ConnectionAdmin::new();
    let connection = ConnectionId::new();
    let settings = ConnectionSettings::new_with_capabilities(
        connection,
        Provider::TypeSafe,
        herness_assessment::COMMANDCODE_JEV_REQUEST_MODEL,
        AuthMethod::ApiKey,
        None,
        None,
        ConnectionCapabilityDeclaration::new(
            EndpointClass::TypeSafeSystemOne,
            InputCapabilities::text_only(),
        ),
    )
    .expect("TypeSafe settings")
    .with_assessment_gateway(AssessmentGateway::CommandCode)
    .expect("Command Code gateway");
    admin.add(settings).expect("register connection");

    let host = AssessmentHost {
        directory: admin.directory(),
        credentials: Arc::new(NoCredentials),
        endpoints: loopback_assessment_endpoints(),
    };
    assert!(host.is_commandcode(connection));
    assert_eq!(
        host.origin_for(connection).expect("origin").host(),
        "api.commandcode.ai"
    );
    assert_eq!(
        host.provider_kind(connection).expect("provider kind"),
        ProviderKind::Jev
    );
    let project = ProjectId::new();
    let profile = herness_desktop::supervision::assessment::build_profile(
        &host,
        project,
        ProfilePurpose::Completion,
        connection,
        herness_assessment::COMMANDCODE_JEV_REQUEST_MODEL,
    )
    .expect("Command Code profile");
    assert_eq!(profile.profile.provider(), ProviderKind::Jev);
    assert_eq!(
        profile.profile.model().as_str(),
        herness_assessment::COMMANDCODE_JEV_REQUEST_MODEL
    );
    assert!(
        herness_desktop::supervision::assessment::build_profile(
            &host,
            project,
            ProfilePurpose::Completion,
            connection,
            herness_assessment::JEV_REQUEST_MODEL,
        )
        .is_err(),
        "a Command Code connection must not silently use the direct model label"
    );
}
