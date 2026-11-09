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
use herness_desktop::supervision::runtime::{ChildIdentity, DesktopSupervisionRuntime};
use herness_desktop::supervision::store::StoreHandle;
use herness_desktop::supervision::{
    CheckInput, ConditionInput, ConfirmationKind, CreateSupervisionRequest, PlanRequestActor,
    SupervisionHost,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::operations::SupervisionOperationRequest;
use herness_supervision::operations::{HumanOperation, OperationRuntimePort};
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
    CheckStatus, ConditionVerdict, DisclosureDataKind, EvidenceAcquirer, EvidenceOutcome,
    EvidenceRecord, EvidenceScope, ProfilePurpose, ProfileThresholds, ProviderKind, ProviderOrigin,
    RubricVersion, SupervisionError, SupervisionId, SupervisionRecord, SupervisionRequestId,
    TargetReadSet, TargetVersion,
};
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
            "scripted met verdict",
            None,
            AssessmentOutcome::NormalLlm {
                verdict: ConditionVerdict::Met,
                confidence: None,
            },
            provenance,
            Timestamp::now(),
        )
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
    harness_with_check(false, false)
}

fn harness_with_pass_check() -> Harness {
    harness_with_check(true, false)
}

fn harness_with_completion() -> Harness {
    harness_with_check(true, true)
}

fn harness_with_check(pass: bool, met_assessment: bool) -> Harness {
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
    let assessment: Box<dyn ConditionAssessmentPort + Send> = if met_assessment {
        Box::new(MetAssessment)
    } else {
        Box::new(UnverifiedAssessment)
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
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use herness_assessment::AssessmentEndpoints;
    use herness_core::{
        AbsolutePath, ArgumentsDigest, AuthMethod, ConnectionAdmin,
        ConnectionCapabilityDeclaration, ConnectionId, ConnectionSettings, CredentialAvailability,
        CredentialKind, CredentialPort, Endpoint, EndpointClass, EvaluationContext,
        EvaluatorAvailability, FrozenOperation, InputCapabilities, NonEmptyText, OperationId,
        PermissionEvaluatorPort, PermissionMode, PermissionOutcome, PermissionPolicy,
        PermissionRule, PolicyAdmin, ProjectId, Provider, Rationale, ResolvedCredential,
        RuleTarget, RunId, SecretString, ToolArguments, ToolExecutor, ToolGateway, ToolName,
        WriteArgs,
    };
    use herness_desktop::host::DesktopHost;
    use herness_desktop::supervision::store::HostBudgetClock;
    use herness_desktop::supervision::{
        ConfirmationKind, CreateSupervisionRequest, PlanRequestActor,
    };
    use herness_engine_pi::ProviderEndpoints;
    use herness_supervision::{
        BudgetLedger, BudgetPolicy, DisclosureDataKind, ProfilePurpose, ProviderOrigin,
        TargetVersion,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;

    const API_KEY: &str = "sk-permission-desktop-canary-98ac";
    const MODEL: &str = "permission-llm";
    const CONVERSATION_CANARY: &str = "whole-conversation-canary-1f4d";

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        path: String,
        body: Vec<u8>,
    }

    struct PermissionMock {
        address: SocketAddr,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
        responses: Arc<Mutex<VecDeque<Value>>>,
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
                .push_back(response);
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
        responses: Arc<Mutex<VecDeque<Value>>>,
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
            .unwrap_or_else(|| json!({"error": "mock exhausted"}));
        let payload = serde_json::to_vec(&response).expect("encode mock response");
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&payload);
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
            let (mut host, _) = DesktopHost::open_with_assessment_endpoints(
                &app_data,
                admin,
                credentials.clone(),
                engine_endpoints,
                assessment_endpoints,
            )
            .expect("desktop host");
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
