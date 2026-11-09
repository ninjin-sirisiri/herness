//! Task 16 coordinator tests.
//!
//! The H3 store is the real SQLite implementation; the immutable workspace is
//! read from a real temporary project through the observer's canonical reader.
//! The H1/H2 owner boundary is a scripted port so every scheduling, latch,
//! stale-result, and serialization decision is observable without a model.
//! No provider, credential, or network path is used.

#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use herness_core::{ArtifactHandle, ConnectionId, ProjectId, RunId, Timestamp};
use herness_html_sync::observer::{ChangeSource, DependencyKind, DependencyPath};
use herness_html_sync::{
    ActiveOwner, AuthoringControlPort, AuthoringGate, AuthoringJob, AuthoringWorkspace,
    CandidateAuthored, CandidateId, CandidateStorageRef, CoordinatorPorts, CycleLatch, CycleState,
    DocumentKey, GenerationStatus, H2Reference, H3ApprovalLimits, H3ConfigurationApproval,
    H3ConfigurationDraft, H3ConnectionApproval, H3OwnerBinding, H3Settings, H3State,
    H3VersionBinding, HtmlSyncCommit, ObservationEligibility, ObservationTrigger, OfferOutcome,
    OwnerGateRequest, OwnerProgress, OwnerStartRequest, OwnerStarted, OwnerSupersedeRequest,
    SettingsCommit, SourceChange, SourceObservation, SourceRevision, SourceSnapshot, StopOutcome,
    SupersessionOutcome, SyncCoordinator, WorkspaceCaptureRequest, WorkspaceReader,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::{
    BudgetPolicy, ConditionDigest, ConditionVersion, ConsentBinding, ContentDigest,
    DisclosureDataKind, DisclosureScope, ExecutionScope, OwnerKind, OwnerRef, ProfileBinding,
    ProfileId, ProfilePurpose, ProfileVersion, ProviderOrigin, SupervisionId, SupervisionState,
    TargetVersion,
};
use tempfile::TempDir;
use uuid::Uuid;

const TARGET: &str = "docs/sdd/specs/example.md";
const CSS: &str = "assets/shared.css";
const RESOURCE: &str = "assets/logo.png";

fn now() -> Timestamp {
    Timestamp::from_unix_millis(1_700_000_000_000)
}

fn profile(project: ProjectId, purpose: ProfilePurpose) -> ProfileBinding {
    ProfileBinding::new(
        ProfileId::from_parts(
            project,
            Uuid::parse_str("10000000-0000-4000-8000-00000000000b").expect("uuid"),
        ),
        ProfileVersion::new(1).expect("profile version"),
        purpose,
    )
}

fn consent(project: ProjectId, purpose: ProfilePurpose) -> ConsentBinding {
    ConsentBinding::new(
        herness_supervision::ConsentId::from_parts(
            project,
            Uuid::parse_str("10000000-0000-4000-8000-00000000000a").expect("uuid"),
        ),
        1,
        purpose,
        TargetVersion::new(1).expect("target version"),
    )
}

fn connection(project: ProjectId, purpose: ProfilePurpose, target: &str) -> H3ConnectionApproval {
    let kinds = if purpose == ProfilePurpose::Completion {
        BTreeSet::from([DisclosureDataKind::Text, DisclosureDataKind::Code])
    } else {
        BTreeSet::from([DisclosureDataKind::Text])
    };
    H3ConnectionApproval::new(
        project,
        ConnectionId::new(),
        ProviderOrigin::parse("https://loopback.example").expect("origin"),
        DisclosureScope::new(
            purpose,
            kinds,
            vec![target.to_owned()],
            TargetVersion::new(1).expect("target version"),
        )
        .expect("disclosure"),
        profile(project, purpose),
        consent(project, purpose),
    )
    .expect("connection approval")
}

fn owner(project: ProjectId, job: &str) -> H3OwnerBinding {
    H3OwnerBinding::new(
        project,
        OwnerRef::new(OwnerKind::H3HtmlJob, job).expect("owner"),
        job,
        ConditionVersion::new(1).expect("condition version"),
        ConditionDigest::sha256(b"conditions"),
        ExecutionScope::new(
            project,
            vec![TARGET.to_owned(), "CONTEXT.md".to_owned()],
            vec!["private/html-sync/candidates".to_owned()],
            false,
        )
        .expect("scope"),
        1,
        BudgetPolicy::h2_default(),
    )
    .expect("owner binding")
}

fn approval(project: ProjectId, target: &str, job: &str) -> H3ConfigurationApproval {
    H3ConfigurationApproval::approve(
        H3ConfigurationDraft {
            project_id: project,
            settings_version: 1,
            approval_id: format!("approval-{job}"),
            expires_at: None,
            targets: vec![target.to_owned()],
            authoring: connection(project, ProfilePurpose::Completion, target),
            assessment: connection(project, ProfilePurpose::Html, target),
            versions: H3VersionBinding::new(
                "sdd-herness-integration",
                1,
                1,
                "sdd-html-policy-v1",
                ContentDigest::sha256(b"policy"),
                1,
                ContentDigest::sha256(b"pack"),
                "sdd-html-host-api",
                1,
            )
            .expect("versions"),
            limits: H3ApprovalLimits::default(),
            auto_publish: false,
            retain_history: true,
            automatic_companion: true,
            owner: owner(project, job),
        },
        herness_html_sync::config::H3Approver::Human,
        now(),
    )
    .expect("approval")
}

fn settings(project: ProjectId, target: &str, job: &str) -> H3Settings {
    H3Settings::approved(approval(project, target, job), true).expect("settings")
}

struct Project {
    _temp: TempDir,
    root: PathBuf,
    project: ProjectId,
    document: DocumentKey,
    settings: H3Settings,
    job: AuthoringJob,
    source: SourceSnapshot,
}

impl Project {
    fn new(name: &str, target: &str) -> Self {
        let temp = TempDir::new().expect("project temp");
        let root = temp.path().join(name);
        fs::create_dir_all(root.join("docs/sdd/specs")).expect("spec dir");
        fs::create_dir_all(root.join("assets")).expect("assets dir");
        let source_bytes = format!("# {name}\n\nExact source for {name}.\n");
        fs::write(root.join(target), &source_bytes).expect("source");
        fs::write(root.join("docs/sdd/specs/example.html"), "<html>old</html>").expect("html");
        fs::write(root.join(CSS), "body { color: #111; }").expect("css");
        fs::write(root.join(RESOURCE), b"not-a-real-image").expect("resource");
        let project_id = ProjectId::new();
        let document = DocumentKey::new(project_id, target).expect("document");
        let settings = settings(project_id, target, name);
        let supervision_id = SupervisionId::new(project_id);
        let job = AuthoringJob::from_settings(&settings, supervision_id, now())
            .expect("job")
            .with_dependencies(vec![
                DependencyPath::new(CSS, DependencyKind::Css).expect("css"),
                DependencyPath::new(RESOURCE, DependencyKind::Resource).expect("resource"),
            ])
            .expect("deps");
        let source = SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(source_bytes.as_bytes()),
        );
        Self {
            _temp: temp,
            root,
            project: project_id,
            document,
            settings,
            job,
            source,
        }
    }

    fn workspace(&self) -> WorkspaceReader<herness_html_sync::FilesystemSourceReader> {
        WorkspaceReader::new(
            herness_html_sync::FilesystemSourceReader::new(&self.root).expect("reader"),
        )
    }

    fn observation(&self, snapshot: SourceSnapshot) -> SourceObservation {
        self.observation_with(snapshot, ObservationTrigger::FileNotification)
    }

    fn observation_with(
        &self,
        snapshot: SourceSnapshot,
        trigger: ObservationTrigger,
    ) -> SourceObservation {
        SourceObservation {
            document: self.document.clone(),
            snapshot,
            change: SourceChange::Modified,
            trigger,
            observed_via: vec![ChangeSource::ExternalEditor],
            eligibility: ObservationEligibility::approved(self.settings.version())
                .expect("eligibility"),
        }
    }

    fn observe(&self) -> SourceObservation {
        self.observation(self.source.clone())
    }

    fn changed(&self, revision: u64) -> SourceObservation {
        let bytes = b"# changed\n\nA newer exact source.\n";
        fs::write(self.root.join(self.document.target_path()), bytes).expect("changed source");
        let snapshot = SourceSnapshot::new(
            SourceRevision::new(revision).expect("revision"),
            ContentDigest::sha256(bytes),
        );
        self.observation(snapshot)
    }
}

struct MultiWorkspace {
    readers: BTreeMap<ProjectId, WorkspaceReader<herness_html_sync::FilesystemSourceReader>>,
}

impl MultiWorkspace {
    fn new(projects: &[&Project]) -> Self {
        Self {
            readers: projects
                .iter()
                .map(|project| (project.project, project.workspace()))
                .collect(),
        }
    }
}

impl AuthoringWorkspace for MultiWorkspace {
    fn capture(
        &self,
        request: &WorkspaceCaptureRequest,
    ) -> Result<herness_html_sync::AuthoringSnapshot, herness_html_sync::H3Error> {
        self.readers
            .get(&request.document().project_id())
            .ok_or_else(|| herness_html_sync::H3Error::Unavailable {
                capability: "authoring.workspace".to_owned(),
                detail: "the project is not open".to_owned(),
            })?
            .capture(request)
    }
}

fn open_store() -> (TempDir, Store) {
    let temp = TempDir::new().expect("store temp");
    let config = StoreConfig::new(temp.path().join("app-data")).expect("config");
    let store = Store::open(config).expect("store");
    (temp, store)
}

fn commit_settings(store: &mut Store, settings: &H3Settings) {
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_settings(SettingsCommit::new(None, settings.clone()).expect("commit")),
        )
        .expect("settings commit");
}

fn storage() -> CandidateStorageRef {
    CandidateStorageRef::new("ab".repeat(32), ContentDigest::sha256(b"token")).expect("storage")
}

#[derive(Default)]
struct ScriptedControl {
    gate: Option<AuthoringGate>,
    progress: Vec<OwnerProgress>,
    stop: Option<StopOutcome>,
    starts: Vec<OwnerStartRequest>,
    supersedes: Vec<OwnerSupersedeRequest>,
    stops: usize,
    next_start_error: Option<String>,
}

impl ScriptedControl {
    fn allowed(project: ProjectId, supervision: SupervisionId) -> Self {
        let h2 = H2Reference::new(
            project,
            supervision,
            None,
            Some(ConditionVersion::new(1).expect("condition")),
            Some(TargetVersion::new(1).expect("target")),
            Some(1),
            Some(SupervisionState::Ready),
        )
        .expect("h2");
        Self {
            gate: Some(AuthoringGate::Allowed {
                h2,
                target_version: TargetVersion::new(1).expect("target"),
            }),
            ..Self::default()
        }
    }

    fn started(&self, request: &OwnerStartRequest) -> OwnerStarted {
        self.started_for(
            request.job().project_id(),
            request.generation(),
            request.generation_number(),
        )
    }

    fn started_for(
        &self,
        project: ProjectId,
        generation: herness_html_sync::GenerationId,
        generation_number: u64,
    ) -> OwnerStarted {
        let h2 = H2Reference::new(
            project,
            SupervisionId::new(project),
            None,
            Some(ConditionVersion::new(1).expect("condition")),
            Some(TargetVersion::new(generation_number).expect("target")),
            Some(generation_number),
            Some(SupervisionState::Running),
        )
        .expect("h2");
        OwnerStarted::new(
            h2,
            RunId::new(project),
            generation,
            ArtifactHandle::new(project, "job", generation_number, "candidate-token")
                .expect("handle"),
            storage(),
            1,
            ContentDigest::sha256(b"packet"),
        )
        .expect("started")
    }
}

impl AuthoringControlPort for ScriptedControl {
    fn gate(
        &mut self,
        request: &OwnerGateRequest,
    ) -> Result<AuthoringGate, herness_html_sync::H3Error> {
        let gate = self.gate.clone().expect("scripted gate");
        match gate {
            AuthoringGate::Allowed { target_version, .. } => {
                let project = request.job().project_id();
                Ok(AuthoringGate::Allowed {
                    h2: H2Reference::new(
                        project,
                        request.job().supervision_id(),
                        None,
                        Some(ConditionVersion::new(1).expect("condition")),
                        Some(target_version),
                        Some(1),
                        Some(SupervisionState::Ready),
                    )
                    .expect("h2"),
                    target_version,
                })
            }
            other => Ok(other),
        }
    }

    fn start(
        &mut self,
        request: &OwnerStartRequest,
    ) -> Result<OwnerStarted, herness_html_sync::H3Error> {
        self.starts.push(request.clone());
        if let Some(error) = self.next_start_error.take() {
            return Err(herness_html_sync::H3Error::Unavailable {
                capability: "h2.owner_start".to_owned(),
                detail: error,
            });
        }
        Ok(self.started(request))
    }

    fn poll(&mut self, _active: &ActiveOwner) -> Result<OwnerProgress, herness_html_sync::H3Error> {
        if self.progress.is_empty() {
            Ok(OwnerProgress::Running)
        } else {
            Ok(self.progress.remove(0))
        }
    }

    fn request_stop(
        &mut self,
        _active: &ActiveOwner,
    ) -> Result<StopOutcome, herness_html_sync::H3Error> {
        self.stops += 1;
        Ok(self.stop.unwrap_or(StopOutcome::Confirmed))
    }

    fn supersede(
        &mut self,
        request: &OwnerSupersedeRequest,
    ) -> Result<OwnerStarted, herness_html_sync::H3Error> {
        self.supersedes.push(request.clone());
        Ok(self.started_for(
            request.job().project_id(),
            request.generation(),
            request.generation_number(),
        ))
    }
}

fn tick(
    coordinator: &mut SyncCoordinator,
    store: &mut Store,
    workspace: &dyn AuthoringWorkspace,
    control: &mut ScriptedControl,
) -> herness_html_sync::CoordinatorTick {
    coordinator
        .tick(
            &mut CoordinatorPorts {
                store,
                workspace,
                control,
            },
            now(),
        )
        .expect("tick")
}

fn candidate(project: ProjectId, generation: herness_html_sync::GenerationId) -> CandidateAuthored {
    CandidateAuthored::new(
        generation,
        CandidateId::new(project),
        storage(),
        ContentDigest::sha256(b"<html>candidate</html>"),
        ContentDigest::sha256(b"{\"units\":[]}"),
        now(),
        RunId::new(project),
    )
    .expect("candidate")
}

#[test]
fn dirty_documents_start_in_notification_order_with_one_app_wide_slot() {
    let (_store_temp, mut store) = open_store();
    let project = Project::new("a", TARGET);
    let other = Project::new("b", TARGET);
    commit_settings(&mut store, &project.settings);
    commit_settings(&mut store, &other.settings);
    let mut coordinator = SyncCoordinator::new();
    coordinator.bind_job(project.job.clone());
    coordinator.bind_job(other.job.clone());
    let mut control = ScriptedControl::allowed(project.project, project.job.supervision_id());
    let workspace = MultiWorkspace::new(&[&project, &other]);

    assert_eq!(
        coordinator.offer(&other.observe()),
        OfferOutcome::Queued,
        "the second project queues"
    );
    assert_eq!(coordinator.offer(&project.observe()), OfferOutcome::Queued);
    assert_eq!(coordinator.queued_documents().len(), 2);

    let first = tick(&mut coordinator, &mut store, &workspace, &mut control);
    assert_eq!(
        first.started.as_ref().expect("started").document,
        other.document
    );
    assert!(coordinator.is_authoring());
    assert_eq!(control.starts.len(), 1);

    // A second project cannot start while the first is active.
    let busy = tick(&mut coordinator, &mut store, &workspace, &mut control);
    assert!(busy.started.is_none());
    assert_eq!(control.starts.len(), 1);

    control.progress.push(OwnerProgress::Authored(candidate(
        other.project,
        first.started.expect("started").generation,
    )));
    let intake = tick(&mut coordinator, &mut store, &workspace, &mut control);
    assert!(intake.candidate.is_some());
    assert!(!coordinator.is_authoring());

    // Re-bind the second job's supervision target so the scripted gate can be
    // reset for the next project.
    control.gate = Some(AuthoringGate::Allowed {
        h2: H2Reference::new(
            project.project,
            project.job.supervision_id(),
            None,
            Some(ConditionVersion::new(1).expect("condition")),
            Some(TargetVersion::new(1).expect("target")),
            Some(1),
            Some(SupervisionState::Ready),
        )
        .expect("h2"),
        target_version: TargetVersion::new(1).expect("target"),
    });
    let second = tick(&mut coordinator, &mut store, &workspace, &mut control);
    assert_eq!(
        second.started.as_ref().expect("started").document,
        project.document
    );
    assert_eq!(control.starts.len(), 2);
}

#[test]
fn duplicate_notifications_do_not_create_a_second_job_and_keep_original_order() {
    let (_store_temp, mut store) = open_store();
    let a = Project::new("a", TARGET);
    let b = Project::new("b", TARGET);
    commit_settings(&mut store, &a.settings);
    commit_settings(&mut store, &b.settings);
    let mut coordinator = SyncCoordinator::new();
    coordinator.bind_job(a.job.clone());
    coordinator.bind_job(b.job.clone());
    assert_eq!(coordinator.offer(&b.observe()), OfferOutcome::Queued);
    assert_eq!(coordinator.offer(&a.observe()), OfferOutcome::Queued);
    assert_eq!(coordinator.offer(&b.observe()), OfferOutcome::Updated);
    assert_eq!(coordinator.offer(&a.observe()), OfferOutcome::Updated);
    assert_eq!(
        coordinator.queued_documents(),
        vec![b.document.clone(), a.document.clone()]
    );
}

#[test]
fn persisted_latch_is_not_cleared_by_a_new_source_and_never_starts() {
    let (_store_temp, mut store) = open_store();
    let project = Project::new("a", TARGET);
    commit_settings(&mut store, &project.settings);
    let mut coordinator = SyncCoordinator::new();
    coordinator.bind_job(project.job.clone());
    let mut control = ScriptedControl::allowed(project.project, project.job.supervision_id());
    control.gate = Some(AuthoringGate::Latched {
        latch: Some(CycleLatch::HumanStop),
        reason: herness_html_sync::H3Reason::new(
            herness_html_sync::H3StateReasonKind::Stopped {
                cause: herness_html_sync::H3StopCause::HumanRequest,
            },
            vec![herness_html_sync::RequiredAction::ResumeCycle],
        )
        .expect("reason"),
        detail: "human stopped the cycle".to_owned(),
    });

    assert_eq!(coordinator.offer(&project.observe()), OfferOutcome::Queued);
    let held = tick(
        &mut coordinator,
        &mut store,
        &project.workspace(),
        &mut control,
    );
    assert!(held.started.is_none());
    assert_eq!(held.held.expect("held").latch, Some(CycleLatch::HumanStop));
    assert_eq!(control.starts.len(), 0);
    assert!(coordinator.latch(&project.document).is_some());

    // A newer source revision arrives while the latch is set.
    assert!(matches!(
        coordinator.offer(&project.changed(2)),
        OfferOutcome::Held {
            latch: CycleLatch::HumanStop,
            ..
        }
    ));
    let still = tick(
        &mut coordinator,
        &mut store,
        &project.workspace(),
        &mut control,
    );
    assert!(still.started.is_none());
    assert_eq!(control.starts.len(), 0);
}

#[test]
fn budget_latch_is_persisted_and_new_notifications_do_not_bypass_it() {
    let (_store_temp, mut store) = open_store();
    let project = Project::new("a", TARGET);
    commit_settings(&mut store, &project.settings);
    let mut coordinator = SyncCoordinator::new();
    coordinator.bind_job(project.job.clone());
    let mut control = ScriptedControl::allowed(project.project, project.job.supervision_id());
    control.gate = Some(AuthoringGate::Latched {
        latch: Some(CycleLatch::BudgetLimit),
        reason: herness_html_sync::H3Reason::new(
            herness_html_sync::H3StateReasonKind::Stopped {
                cause: herness_html_sync::H3StopCause::BudgetLimit,
            },
            vec![herness_html_sync::RequiredAction::ResumeCycle],
        )
        .expect("reason"),
        detail: "budget exhausted".to_owned(),
    });
    coordinator.offer(&project.observe());
    tick(
        &mut coordinator,
        &mut store,
        &project.workspace(),
        &mut control,
    );
    assert_eq!(control.starts.len(), 0);

    // The persisted document state and cycle carry the latch.
    let document = store
        .load_html_sync_document(project.project, &project.document)
        .expect("load")
        .expect("document");
    assert_eq!(document.state().state(), H3State::Stopped);
    let cycle = document.state().cycle_id().expect("cycle");
    let cycle = store
        .load_html_sync_cycle(project.project, cycle)
        .expect("load cycle")
        .expect("cycle");
    assert_eq!(cycle.latch(), Some(CycleLatch::BudgetLimit));
    assert_eq!(cycle.state(), CycleState::Open);
}

#[test]
fn source_change_supersedes_the_old_generation_and_rejects_a_delayed_candidate() {
    let (_store_temp, mut store) = open_store();
    let project = Project::new("a", TARGET);
    commit_settings(&mut store, &project.settings);
    let mut coordinator = SyncCoordinator::new();
    coordinator.bind_job(project.job.clone());
    let mut control = ScriptedControl::allowed(project.project, project.job.supervision_id());
    coordinator.offer(&project.observe());
    let started = tick(
        &mut coordinator,
        &mut store,
        &project.workspace(),
        &mut control,
    )
    .started
    .expect("first start");
    let old_generation = started.generation;

    let change = project.changed(2);
    let outcome = coordinator
        .source_changed(
            &mut CoordinatorPorts {
                store: &mut store,
                workspace: &project.workspace(),
                control: &mut control,
            },
            &change,
            now(),
        )
        .expect("source change");
    assert!(matches!(
        outcome,
        SupersessionOutcome::Superseded { previous, current, .. }
            if previous == old_generation && current != old_generation
    ));
    assert_eq!(control.stops, 1);
    assert_eq!(control.supersedes.len(), 1);
    assert!(
        control.supersedes[0]
            .brief()
            .instruction()
            .contains("source_markdown")
    );

    // The old generation is history-only.
    let generations = store
        .html_sync_generations(project.project, &project.document)
        .expect("generations");
    let old = generations
        .iter()
        .find(|record| record.generation_id() == old_generation)
        .expect("old generation");
    assert_eq!(old.status(), GenerationStatus::Superseded);
    assert!(old.candidate().is_none());

    // A delayed candidate from the old generation is rejected without a write.
    control.progress.push(OwnerProgress::Authored(candidate(
        project.project,
        old_generation,
    )));
    let stale = tick(
        &mut coordinator,
        &mut store,
        &project.workspace(),
        &mut control,
    );
    assert!(stale.candidate.is_none());
    assert_eq!(stale.stale.expect("stale").found, old_generation);
    let old = store
        .html_sync_generations(project.project, &project.document)
        .expect("generations")
        .into_iter()
        .find(|record| record.generation_id() == old_generation)
        .expect("old generation");
    assert!(old.candidate().is_none());

    // The new generation accepts its own candidate and links the H1 run.
    control.progress.push(OwnerProgress::Authored(candidate(
        project.project,
        control.supersedes.last().expect("supersede").generation(),
    )));
    let intake = tick(
        &mut coordinator,
        &mut store,
        &project.workspace(),
        &mut control,
    );
    let intake = intake.candidate.expect("candidate intake");
    assert_eq!(intake.generation, control.supersedes[0].generation());
    let candidate_record = store
        .load_html_sync_candidate(project.project, intake.candidate)
        .expect("load candidate")
        .expect("candidate");
    assert!(candidate_record.h1_run().is_some());
    let generation = store
        .html_sync_generations(project.project, &project.document)
        .expect("generations")
        .into_iter()
        .find(|record| record.generation_id() == intake.generation)
        .expect("generation");
    assert!(generation.candidate().is_some());
}

#[test]
fn unconfirmed_stop_holds_the_app_wide_slot_and_does_not_start_another_project() {
    let (_store_temp, mut store) = open_store();
    let a = Project::new("a", TARGET);
    let b = Project::new("b", TARGET);
    commit_settings(&mut store, &a.settings);
    commit_settings(&mut store, &b.settings);
    let mut coordinator = SyncCoordinator::new();
    coordinator.bind_job(a.job.clone());
    coordinator.bind_job(b.job.clone());
    let mut control = ScriptedControl::allowed(a.project, a.job.supervision_id());
    let workspace = MultiWorkspace::new(&[&a, &b]);
    coordinator.offer(&a.observe());
    tick(&mut coordinator, &mut store, &workspace, &mut control);
    control.stop = Some(StopOutcome::Unconfirmed);
    coordinator.offer(&b.observe());

    let change = a.changed(2);
    let outcome = coordinator
        .source_changed(
            &mut CoordinatorPorts {
                store: &mut store,
                workspace: &workspace,
                control: &mut control,
            },
            &change,
            now(),
        )
        .expect("source change");
    assert!(matches!(
        outcome,
        SupersessionOutcome::StopUnconfirmed { .. }
    ));
    assert!(coordinator.is_authoring());

    // The other project cannot start while the old app-wide slot is held.
    let tick_report = tick(&mut coordinator, &mut store, &workspace, &mut control);
    assert!(tick_report.started.is_none());
    assert_eq!(control.starts.len(), 1);
}

#[test]
fn generated_html_and_recovery_scans_never_create_authoring_work() {
    let (_store_temp, mut store) = open_store();
    let project = Project::new("a", TARGET);
    commit_settings(&mut store, &project.settings);
    let mut coordinator = SyncCoordinator::new();
    coordinator.bind_job(project.job.clone());
    let mut control = ScriptedControl::allowed(project.project, project.job.supervision_id());

    let mut observation = project.observe();
    observation.trigger = ObservationTrigger::WatcherRecovery;
    assert_eq!(coordinator.offer(&observation), OfferOutcome::Ignored);
    observation.trigger = ObservationTrigger::FileNotification;
    observation.eligibility =
        ObservationEligibility::ineligible(herness_html_sync::IneligibleReason::Unapproved, None);
    assert_eq!(coordinator.offer(&observation), OfferOutcome::Ignored);
    assert!(coordinator.queued_documents().is_empty());
    let report = tick(
        &mut coordinator,
        &mut store,
        &project.workspace(),
        &mut control,
    );
    assert!(report.started.is_none());
    assert_eq!(control.starts.len(), 0);
}

#[test]
fn the_brief_carries_the_exact_snapshot_policy_and_conditions() {
    let (_store_temp, mut store) = open_store();
    let project = Project::new("a", TARGET);
    commit_settings(&mut store, &project.settings);
    let mut coordinator = SyncCoordinator::new();
    coordinator.bind_job(project.job.clone());
    let mut control = ScriptedControl::allowed(project.project, project.job.supervision_id());
    coordinator.offer(&project.observe());
    tick(
        &mut coordinator,
        &mut store,
        &project.workspace(),
        &mut control,
    );
    let request = control.starts.first().expect("start");
    let brief = request.brief().instruction();
    assert!(brief.contains(project.source.digest().as_str()));
    assert!(brief.contains("existing_html"));
    assert!(brief.contains("shared_css"));
    assert!(brief.contains("sdd-html-policy-v1"));
    assert!(brief.contains("conditions version 1"));
    assert!(!brief.contains("Work toward the approved completion conditions"));
    let snapshot = request.snapshot();
    assert_eq!(snapshot.source(), &project.source);
    assert_eq!(
        snapshot.source_markdown().text(),
        "# a\n\nExact source for a.\n"
    );
    assert_eq!(
        snapshot.existing_html().expect("html").text(),
        "<html>old</html>"
    );
    assert_eq!(
        snapshot.shared_css().expect("css").text(),
        "body { color: #111; }"
    );
}

#[test]
fn candidate_intake_is_one_h3_commit_with_the_generation_and_h1_link() {
    let (_store_temp, mut store) = open_store();
    let project = Project::new("a", TARGET);
    commit_settings(&mut store, &project.settings);
    let mut coordinator = SyncCoordinator::new();
    coordinator.bind_job(project.job.clone());
    let mut control = ScriptedControl::allowed(project.project, project.job.supervision_id());
    coordinator.offer(&project.observe());
    let started = tick(
        &mut coordinator,
        &mut store,
        &project.workspace(),
        &mut control,
    )
    .started
    .expect("started");
    control.progress.push(OwnerProgress::Authored(candidate(
        project.project,
        started.generation,
    )));
    let intake = tick(
        &mut coordinator,
        &mut store,
        &project.workspace(),
        &mut control,
    )
    .candidate
    .expect("intake");
    let document = store
        .load_html_sync_document(project.project, &project.document)
        .expect("load")
        .expect("document");
    assert_eq!(document.state().state(), H3State::Verifying);
    assert_eq!(document.revision(), intake.document_revision);
    assert_eq!(
        document
            .state()
            .fingerprints()
            .get(herness_html_sync::FingerprintKind::Candidate),
        Some(&intake.html_digest)
    );
    let candidate_record = store
        .load_html_sync_candidate(project.project, intake.candidate)
        .expect("load")
        .expect("candidate");
    assert_eq!(candidate_record.generation_id(), started.generation);
    assert!(candidate_record.h1_run().is_some());
}

#[test]
fn serial_constants_are_one_and_publication_is_per_document() {
    assert_eq!(herness_html_sync::APP_WIDE_AUTHORING_CONCURRENCY, 1);
    assert_eq!(herness_html_sync::DOCUMENT_PUBLICATION_CONCURRENCY, 1);
}
