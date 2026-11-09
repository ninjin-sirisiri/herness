//! Task 22: trusted desktop composition, saved-state display, and the H4
//! barrier port.
//!
//! These tests use the real SQLite store, the real `DesktopHost` composition,
//! and temporary projects. No Tauri window, GUI, provider, Keychain, login, or
//! network is used. The pack is absent, so every policy/assessment capability is
//! reported explicitly unavailable rather than mocked into success.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use herness_core::{
    ConnectionAdmin, ConnectionId, CoreError, CredentialAvailability, CredentialPort, ProjectId,
    ResolvedCredential, Timestamp,
};
use herness_desktop::commands::HTML_SYNC_MUTATION_COMMANDS;
use herness_desktop::guard::{self, GuardError};
use herness_desktop::host::DesktopHost;
use herness_desktop::html_sync::composition::{
    self, HtmlSyncApprovalRequest, HtmlSyncCapability, HtmlSyncCapabilityReport,
    MULTI_CYCLE_COST_WARNING,
};
use herness_engine_pi::ProviderEndpoints;
use herness_html_sync::observer::{
    ChangeSignal, ChangeSource, FilesystemSourceReader, ObservationEligibility, ObservationTargets,
    ProjectObserver, SystemObservationClock,
};
use herness_html_sync::{
    Applicability, ApplicabilityReason, BarrierDependency, BarrierMismatchKind, BarrierOutcome,
    BarrierRequest, DocumentCommit, DocumentKey, FingerprintKind, FingerprintSet, H3ApprovalLimits,
    H3ConnectionApproval, H3DocumentState, H3Operation, H3OperationRequest, H3OwnerBinding,
    H3Reason, H3RequestId, H3Settings, H3State, H3StateReasonKind, H3StorePort, H3VersionBinding,
    HtmlSyncCommit, HumanWaitCause, RequiredAction, SettingsCommit, SourceRevision, SourceSnapshot,
    document_state_event, settings_event,
};
use herness_supervision::budget::BudgetPolicy;
use herness_supervision::{
    ConditionDigest, ConditionVersion, ConsentBinding, ConsentId, ContentDigest,
    DisclosureDataKind, DisclosureScope, ExecutionScope, OwnerKind, OwnerRef, ProfileBinding,
    ProfileId, ProfilePurpose, ProfileVersion, ProviderOrigin, TargetVersion,
};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

const TARGET: &str = "docs/adr/0001-queue-choice.md";
const COMPANION: &str = "docs/adr/0001-queue-choice.html";

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

struct Harness {
    _data: TempDir,
    _project: TempDir,
    root: PathBuf,
    host: DesktopHost,
    project: ProjectId,
}

impl Harness {
    fn new() -> Self {
        let data = tempfile::tempdir().expect("data root");
        let project = tempfile::tempdir().expect("project root");
        std::fs::create_dir_all(project.path().join("docs/adr")).expect("adr directory");
        std::fs::create_dir_all(project.path().join("docs/sdd/assets")).expect("assets");
        std::fs::write(
            project.path().join(TARGET),
            "# Queue choice\n\nUse the queue.\n",
        )
        .expect("source");
        std::fs::write(
            project.path().join("docs/sdd/assets/sdd.css"),
            "body { color: #111; }\n",
        )
        .expect("css");
        let root = project.path().to_path_buf();
        let (mut host, _) = DesktopHost::open(
            data.path(),
            ConnectionAdmin::new(),
            Arc::new(NoCredentials),
            ProviderEndpoints::official(),
        )
        .expect("desktop host");
        let view = host.open_project(&root).expect("open project");
        Self {
            _data: data,
            _project: project,
            root,
            host,
            project: view.project_id(),
        }
    }

    fn store(&self) -> herness_desktop::supervision::store::StoreHandle {
        self.host.store_handle()
    }

    fn document(&self) -> DocumentKey {
        DocumentKey::new(self.project, TARGET).expect("document key")
    }

    fn now() -> Timestamp {
        Timestamp::now()
    }

    fn approve(&mut self, enabled: bool) {
        let request = approval_request(self.project, enabled);
        let _confirmation = self
            .host
            .confirm_supervision(herness_desktop::supervision::ConfirmationKind::ApproveHtmlSync);
        composition::approve(&mut self.host, &request).expect("approval");
    }

    fn seed_unapproved_settings(&self) {
        let settings = H3Settings::new(
            self.project,
            1,
            true,
            vec![TARGET.to_owned()],
            true,
            true,
            Self::now(),
        )
        .expect("unapproved settings");
        self.seed_settings(&settings);
    }

    fn seed_settings(&self, settings: &H3Settings) {
        let event = settings_event(settings, Self::now()).expect("settings event");
        let mut store = self.store();
        store
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_settings(SettingsCommit::new(None, settings.clone()).expect("commit"))
                    .with_events(vec![event]),
            )
            .expect("settings commit");
    }

    fn seed_document(&self, state: H3DocumentState) {
        let event =
            document_state_event(&self.document(), None, &state, Self::now()).expect("event");
        let mut store = self.store();
        store
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_document(DocumentCommit::new(None, state).expect("document commit"))
                    .with_events(vec![event]),
            )
            .expect("document commit");
    }

    fn replace_document(&self, expected_revision: u64, state: H3DocumentState) {
        let event = document_state_event(
            &self.document(),
            Some(H3State::Pending),
            &state,
            Self::now(),
        )
        .expect("event");
        let mut store = self.store();
        store
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_document(
                        DocumentCommit::new(Some(expected_revision), state)
                            .expect("document commit"),
                    )
                    .with_events(vec![event]),
            )
            .expect("document update");
    }

    fn policy_digest() -> ContentDigest {
        ContentDigest::sha256(b"task-22-policy")
    }

    fn pack_digest() -> ContentDigest {
        ContentDigest::sha256(b"task-22-pack")
    }

    fn css_digest() -> ContentDigest {
        ContentDigest::sha256(b"task-22-css")
    }

    fn resources_digest() -> ContentDigest {
        ContentDigest::sha256(b"task-22-resources")
    }

    fn fingerprints(settings: &H3Settings) -> FingerprintSet {
        FingerprintSet::new(
            settings.fingerprint().clone(),
            Self::policy_digest(),
            Self::css_digest(),
            Self::resources_digest(),
            None,
            None,
            None,
        )
    }

    fn pending_state(&self, settings: &H3Settings) -> H3DocumentState {
        let source = SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(b"# Queue choice\n\nUse the queue.\n"),
        );
        H3DocumentState::new(
            self.document(),
            settings.version(),
            None,
            None,
            None,
            source,
            Self::fingerprints(settings),
            H3Reason::new(
                H3StateReasonKind::Pending { source_revision: 1 },
                vec![RequiredAction::WaitForStableSource],
            )
            .expect("reason"),
            None,
            Vec::new(),
            Applicability::not_applicable(ApplicabilityReason::NeverPublished),
            Self::now(),
        )
        .expect("pending state")
    }

    fn synced_state(&self, settings: &H3Settings) -> H3DocumentState {
        let generation = herness_html_sync::GenerationId::new(self.project);
        let source = SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(b"# Queue choice\n\nUse the queue.\n"),
        );
        H3DocumentState::new(
            self.document(),
            settings.version(),
            None,
            None,
            Some(generation),
            source.clone(),
            Self::fingerprints(settings),
            H3Reason::new(
                H3StateReasonKind::Synced {
                    generation,
                    source_revision: 1,
                    source_digest: source.digest().clone(),
                },
                Vec::new(),
            )
            .expect("reason"),
            None,
            Vec::new(),
            Applicability::current_synced(),
            Self::now(),
        )
        .expect("synced state")
    }

    fn undetermined_state(&self, settings: &H3Settings) -> H3DocumentState {
        let source = SourceSnapshot::new(
            SourceRevision::new(2).expect("revision"),
            ContentDigest::sha256(b"# Queue choice\n\nUse the queue.\n"),
        );
        H3DocumentState::new(
            self.document(),
            settings.version(),
            None,
            None,
            None,
            source,
            Self::fingerprints(settings),
            H3Reason::new(
                H3StateReasonKind::WaitingHuman {
                    cause: HumanWaitCause::UndecidableAssessment,
                },
                vec![RequiredAction::ReassessCandidate],
            )
            .expect("reason"),
            None,
            Vec::new(),
            Applicability::not_applicable(ApplicabilityReason::NeverPublished),
            Self::now(),
        )
        .expect("undetermined state")
    }
}

fn profile(project: ProjectId, purpose: ProfilePurpose) -> ProfileBinding {
    let local = match purpose {
        ProfilePurpose::Completion => "10000000-0000-4000-8000-000000000001",
        ProfilePurpose::Html => "10000000-0000-4000-8000-000000000002",
        ProfilePurpose::Permission => "10000000-0000-4000-8000-000000000003",
    };
    ProfileBinding::new(
        ProfileId::from_parts(project, Uuid::parse_str(local).expect("uuid")),
        ProfileVersion::new(1).expect("version"),
        purpose,
    )
}

fn consent(project: ProjectId, purpose: ProfilePurpose) -> ConsentBinding {
    let local = match purpose {
        ProfilePurpose::Completion => "20000000-0000-4000-8000-000000000001",
        ProfilePurpose::Html => "20000000-0000-4000-8000-000000000002",
        ProfilePurpose::Permission => "20000000-0000-4000-8000-000000000003",
    };
    ConsentBinding::new(
        ConsentId::from_parts(project, Uuid::parse_str(local).expect("uuid")),
        1,
        purpose,
        TargetVersion::new(1).expect("target version"),
    )
}

fn connection(project: ProjectId, purpose: ProfilePurpose) -> H3ConnectionApproval {
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
            vec![TARGET.to_owned()],
            TargetVersion::new(1).expect("target version"),
        )
        .expect("disclosure"),
        profile(project, purpose),
        consent(project, purpose),
    )
    .expect("connection approval")
}

fn owner(project: ProjectId) -> H3OwnerBinding {
    H3OwnerBinding::new(
        project,
        OwnerRef::new(OwnerKind::H3HtmlJob, "task-22-job").expect("owner"),
        "task-22-job",
        ConditionVersion::new(1).expect("condition version"),
        ConditionDigest::sha256(b"task-22-conditions"),
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

fn approval_request(project: ProjectId, enabled: bool) -> HtmlSyncApprovalRequest {
    HtmlSyncApprovalRequest {
        project_id: project,
        settings_version: 1,
        approval_id: "task-22-approval".to_owned(),
        expires_at: None,
        targets: vec![TARGET.to_owned()],
        authoring: connection(project, ProfilePurpose::Completion),
        assessment: connection(project, ProfilePurpose::Html),
        versions: H3VersionBinding::new(
            "sdd-herness-integration",
            1,
            1,
            "sdd-html-policy-v1",
            Harness::policy_digest(),
            1,
            Harness::pack_digest(),
            "sdd-html-host-api",
            1,
        )
        .expect("versions"),
        limits: H3ApprovalLimits::default(),
        auto_publish: false,
        retain_history: true,
        automatic_companion: true,
        owner: owner(project),
        enabled,
    }
}

#[test]
fn preview_remote_model_and_agent_origins_cannot_invoke_any_h3_mutation() {
    let local = Some("tauri://localhost/index.html");
    for command in HTML_SYNC_MUTATION_COMMANDS {
        for (window, webview, url, expected) in [
            ("preview", "preview", local, GuardError::UntrustedWindow),
            ("main", "main-preview", local, GuardError::UntrustedWebview),
            ("model", "model", local, GuardError::UntrustedWindow),
            ("agent", "agent", local, GuardError::UntrustedWindow),
            (
                "main",
                "main",
                Some("https://example.com/h3"),
                GuardError::UntrustedOrigin,
            ),
            (
                "main",
                "main",
                Some("tauri://localhost/index.html?agent=1"),
                GuardError::UntrustedOrigin,
            ),
        ] {
            assert_eq!(
                guard::verify(window, webview, url),
                Err(expected),
                "{command} must reject {window}/{webview}/{url:?}"
            );
        }
    }
    assert_eq!(HTML_SYNC_MUTATION_COMMANDS.len(), 8);
}

#[test]
fn h3_approval_is_human_only_and_a_receipt_or_repo_file_is_not_approval() {
    let mut h = Harness::new();
    h.seed_unapproved_settings();
    std::fs::create_dir_all(h.root.join("docs/sdd/html-evidence")).expect("evidence directory");
    std::fs::write(
        h.root.join("docs/sdd/html-evidence/0001.json"),
        r#"{"schema":"sdd-html-receipt","version":1,"approvedBy":"human"}"#,
    )
    .expect("receipt");
    let view = composition::project_view(&h.host, h.project).expect("view");
    let settings = view.settings.expect("settings view");
    assert!(!settings.approved);
    assert!(settings.scan_only);

    h.approve(true);
    let view = composition::project_view(&h.host, h.project).expect("approved view");
    let settings = view.settings.expect("settings view");
    assert!(settings.approved);
    assert!(!settings.scan_only);

    let record = h
        .store()
        .load_html_sync_settings(h.project)
        .expect("settings")
        .expect("stored settings");
    let approval = record.settings().approval().expect("approval");
    let value = serde_json::to_value(approval).expect("approval json");
    assert_eq!(value["approvedBy"], "human");
    assert!(value.get("approved_by").is_none());
}

#[test]
fn purpose_specific_approval_scope_missing_companions_and_cost_warning_are_displayed() {
    let mut h = Harness::new();
    h.approve(true);
    let view = composition::project_view(&h.host, h.project).expect("view");
    let settings = view.settings.expect("settings");
    let authoring = settings.authoring.expect("authoring scope");
    let assessment = settings.assessment.expect("assessment scope");
    assert_eq!(authoring.purpose, "completion");
    assert_eq!(authoring.role, "authoring");
    assert_eq!(assessment.purpose, "html");
    assert_eq!(assessment.role, "assessment");
    assert_ne!(authoring.connection_id, assessment.connection_id);
    assert_eq!(
        authoring
            .data_kinds
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["code".to_owned(), "text".to_owned()])
    );
    assert_eq!(assessment.data_kinds, vec!["text"]);

    assert!(
        view.purposes
            .iter()
            .any(|purpose| purpose.purpose == "completion"
                && purpose.role == "authoring"
                && !purpose.supported
                && purpose.consent_state == "unset"),
        "an unverified authoring profile must be displayed as unsupported"
    );
    assert!(
        view.purposes.iter().any(|purpose| purpose.purpose == "html"
            && purpose.role == "assessment"
            && !purpose.supported),
        "an unverified Html profile must be displayed as unsupported"
    );
    assert_eq!(view.multi_cycle_cost_warning, MULTI_CYCLE_COST_WARNING);
    assert!(view.multi_cycle_cost_warning.contains("does not reset"));
    let missing = serde_json::to_value(&view.missing_companions).expect("missing json");
    assert_eq!(
        missing,
        json!([{ "target": TARGET, "companion": COMPANION }])
    );

    // No H2 budget is invented when no target/sequence exists.
    let budget = composition::budget_view(&h.host, h.project).expect("budget");
    assert!(budget.supervision_id.is_none());
    assert!(budget.budget.is_none());
    assert_eq!(budget.multi_cycle_cost_warning, MULTI_CYCLE_COST_WARNING);
}

#[test]
fn saved_state_is_refetched_instead_of_reusing_a_command_result() {
    let mut h = Harness::new();
    h.approve(true);
    let settings = h
        .store()
        .load_html_sync_settings(h.project)
        .expect("settings")
        .expect("stored settings")
        .settings()
        .clone();
    h.seed_document(h.pending_state(&settings));

    let first = composition::project_view(&h.host, h.project).expect("first view");
    assert_eq!(first.documents.len(), 1);
    assert_eq!(first.documents[0].status.revision(), 1);
    assert_eq!(first.documents[0].state, "pending");
    assert!(first.documents[0].unsynced);
    let first_sequence = first.project_sequence;

    h.replace_document(1, h.undetermined_state(&settings));
    let second = composition::project_view(&h.host, h.project).expect("second view");
    assert_eq!(second.documents[0].status.revision(), 2);
    assert_eq!(second.documents[0].state, "waiting_human");
    assert!(second.documents[0].undetermined);
    assert!(second.documents[0].unsynced);
    assert!(
        second.documents[0]
            .required_actions
            .contains(&"reassess_candidate".to_owned())
    );
    assert!(second.project_sequence >= first_sequence);

    let value = serde_json::to_value(&second).expect("view json");
    assert!(
        value.get("success").is_none(),
        "the view must not invent a UI success flag"
    );
    assert!(value["documents"][0].get("success").is_none());
}

#[test]
fn unapproved_state_is_scan_only_and_undetermined_is_not_success() {
    let mut h = Harness::new();
    h.seed_unapproved_settings();
    let settings = H3Settings::new(
        h.project,
        1,
        true,
        vec![TARGET.to_owned()],
        true,
        true,
        Harness::now(),
    )
    .expect("unapproved settings");
    h.seed_document(h.pending_state(&settings));

    let view = composition::project_view(&h.host, h.project).expect("view");
    assert!(view.scan_only);
    assert!(!view.settings.expect("settings").approved);
    assert_eq!(view.documents[0].state, "pending");

    h.replace_document(1, h.undetermined_state(&settings));
    let view = composition::project_view(&h.host, h.project).expect("view");
    assert!(view.documents[0].undetermined);
    assert!(view.documents[0].unsynced);
    assert_eq!(view.documents[0].state, "waiting_human");
    assert!(!view.documents[0].status.state().is_currently_synced());

    // The unapproved project also cannot enable the worker.
    let enabled = composition::enable(&mut h.host, h.project).expect("enable report");
    assert!(!enabled.capabilities.available());
    assert!(!enabled.worker_bound);
    assert!(
        enabled
            .capabilities
            .missing()
            .iter()
            .any(|state| state.capability() == "trusted_approval")
    );
}

#[test]
fn barrier_accepts_the_saved_synced_version_and_reports_mismatches() {
    let mut h = Harness::new();
    h.approve(true);
    let settings = h
        .store()
        .load_html_sync_settings(h.project)
        .expect("settings")
        .expect("stored settings")
        .settings()
        .clone();
    h.seed_document(h.synced_state(&settings));

    let source = SourceSnapshot::new(
        SourceRevision::new(1).expect("revision"),
        ContentDigest::sha256(b"# Queue choice\n\nUse the queue.\n"),
    );
    let request = BarrierRequest::new(
        h.project,
        h.document(),
        1,
        source.digest().clone(),
        vec![
            BarrierDependency::new(FingerprintKind::Css, Harness::css_digest()),
            BarrierDependency::new(FingerprintKind::Resources, Harness::resources_digest()),
        ],
    )
    .expect("barrier request");
    let outcome = composition::barrier_view(&h.host, &request, Harness::now()).expect("barrier");
    match outcome {
        BarrierOutcome::Synced {
            source_revision,
            source_digest,
            settings_version,
            ..
        } => {
            assert_eq!(source_revision, 1);
            assert_eq!(source_digest, *source.digest());
            assert_eq!(settings_version, settings.version());
        }
        other => panic!("expected synced barrier, got {other:?}"),
    }

    let version_mismatch =
        BarrierRequest::new(h.project, h.document(), 2, source.digest().clone(), vec![])
            .expect("barrier request");
    match composition::barrier_view(&h.host, &version_mismatch, Harness::now()).expect("barrier") {
        BarrierOutcome::Mismatch { mismatches, .. } => {
            assert!(
                mismatches
                    .iter()
                    .any(|mismatch| mismatch.kind() == &BarrierMismatchKind::SourceRevision)
            );
        }
        other => panic!("expected version mismatch, got {other:?}"),
    }

    let dependency_mismatch = BarrierRequest::new(
        h.project,
        h.document(),
        1,
        source.digest().clone(),
        vec![BarrierDependency::new(
            FingerprintKind::Css,
            ContentDigest::sha256(b"changed css"),
        )],
    )
    .expect("barrier request");
    match composition::barrier_view(&h.host, &dependency_mismatch, Harness::now()).expect("barrier")
    {
        BarrierOutcome::Mismatch { mismatches, .. } => {
            assert!(
                mismatches
                    .iter()
                    .any(|mismatch| mismatch.kind() == &BarrierMismatchKind::Dependency)
            );
        }
        other => panic!("expected dependency mismatch, got {other:?}"),
    }
}

#[test]
fn barrier_reports_unsynced_with_saved_reason_and_actions() {
    let mut h = Harness::new();
    h.approve(true);
    let settings = h
        .store()
        .load_html_sync_settings(h.project)
        .expect("settings")
        .expect("stored settings")
        .settings()
        .clone();
    h.seed_document(h.undetermined_state(&settings));
    let source = SourceSnapshot::new(
        SourceRevision::new(2).expect("revision"),
        ContentDigest::sha256(b"# Queue choice\n\nUse the queue.\n"),
    );
    let request = BarrierRequest::new(h.project, h.document(), 2, source.digest().clone(), vec![])
        .expect("barrier request");
    match composition::barrier_view(&h.host, &request, Harness::now()).expect("barrier") {
        BarrierOutcome::Unsynced {
            reason,
            required_actions,
            ..
        } => {
            assert_eq!(reason.state(), H3State::WaitingHuman);
            assert_eq!(required_actions, vec![RequiredAction::ReassessCandidate]);
        }
        other => panic!("expected unsynced, got {other:?}"),
    }
}

#[test]
fn html_worker_is_unavailable_when_any_capability_is_missing() {
    let all = [
        HtmlSyncCapability::PolicyBridge,
        HtmlSyncCapability::AuthoringDispatch,
        HtmlSyncCapability::CandidateTooling,
        HtmlSyncCapability::RealRender,
        HtmlSyncCapability::Assessment,
        HtmlSyncCapability::TrustedApproval,
    ];
    let complete = HtmlSyncCapabilityReport::from_checks(
        all.into_iter()
            .map(|capability| (capability, true, "present".to_owned())),
    );
    assert!(complete.available());
    assert!(complete.missing().is_empty());

    for missing in all {
        let report = HtmlSyncCapabilityReport::from_checks(all.into_iter().map(|capability| {
            (
                capability,
                capability != missing,
                if capability == missing {
                    "missing for the test".to_owned()
                } else {
                    "present".to_owned()
                },
            )
        }));
        assert!(!report.available());
        assert!(
            report
                .missing()
                .iter()
                .any(|state| { state.capability() == missing.as_str() && !state.available() })
        );
    }

    let unchecked = HtmlSyncCapabilityReport::unchecked();
    assert!(!unchecked.available());
    assert!(!unchecked.checked());
}

#[test]
fn enable_without_the_pack_and_h2_target_reports_explicit_unavailability() {
    let mut h = Harness::new();
    h.approve(true);
    let enabled = composition::enable(&mut h.host, h.project).expect("enable report");
    assert!(!enabled.capabilities.available());
    assert!(enabled.capabilities.checked());
    assert!(!enabled.worker_bound);
    assert!(!h.host.html_sync().is_bound(h.project));
    let missing = enabled
        .capabilities
        .missing()
        .iter()
        .map(|state| state.capability().to_owned())
        .collect::<Vec<_>>();
    assert!(missing.contains(&"policy_bridge".to_owned()));
    assert!(missing.contains(&"authoring_dispatch".to_owned()));
    assert!(
        !missing.contains(&"trusted_approval".to_owned()),
        "the human approval is present even though other capabilities are missing"
    );
}

#[test]
fn one_app_lifetime_composition_uses_one_store_worker_and_candidate_root() {
    let h = Harness::new();
    assert_eq!(h.host.html_sync().worker_count(), 1);
    assert!(Arc::ptr_eq(
        h.host.store_handle().shared(),
        h.host.html_sync().store_handle().shared()
    ));
    assert!(Arc::ptr_eq(
        h.host.store_handle().shared(),
        h.host.html_sync_services().store_handle().shared()
    ));
    assert_eq!(
        h.host.html_sync().candidate_root(),
        h._data.path().join("html-sync-candidates")
    );
    assert_eq!(
        h.host.html_sync_services().archive_root(),
        h._data.path().join("html-sync-history")
    );
    // Repeated views use the same composition; no second worker/store appears.
    let first = composition::project_view(&h.host, h.project).expect("view");
    let second = composition::project_view(&h.host, h.project).expect("view");
    assert_eq!(first.project_id, second.project_id);
    assert_eq!(first.capabilities.checked(), second.capabilities.checked());
}

#[test]
fn companion_and_receipt_observations_never_become_markdown_authoring() {
    let project = tempfile::tempdir().expect("project");
    std::fs::create_dir_all(project.path().join("docs/adr")).expect("adr");
    std::fs::write(project.path().join(TARGET), "# Source\n").expect("source");
    std::fs::write(
        project.path().join(COMPANION),
        "<!doctype html><title>old</title>",
    )
    .expect("companion");
    let project_id = ProjectId::new();
    let document = DocumentKey::new(project_id, TARGET).expect("document");
    let targets =
        ObservationTargets::new(project_id, vec![document.clone()], vec![]).expect("targets");
    let eligibility = ObservationEligibility::approved(1).expect("eligibility");
    let reader = FilesystemSourceReader::new(project.path()).expect("reader");
    let mut observer =
        ProjectObserver::new(targets, eligibility, reader, SystemObservationClock::new())
            .expect("observer");
    let initial = observer.initial_scan();
    assert_eq!(initial.sources.len(), 1);
    assert_eq!(initial.authoring_candidates().len(), 1);

    std::fs::write(
        project.path().join(COMPANION),
        "<!doctype html><title>new</title>",
    )
    .expect("changed companion");
    let signal = ChangeSignal::new(COMPANION, ChangeSource::FilesystemWatcher).expect("signal");
    assert!(observer.notify(signal));
    let tick = observer.poll();
    assert!(tick.sources.is_empty());
    assert!(
        tick.authoring_candidates().is_empty(),
        "generated HTML is a companion observation, not Markdown authoring"
    );
    assert_eq!(tick.companions.len(), 1);
}

#[test]
fn a_synced_document_has_no_pause_or_cancel_mutation() {
    let mut h = Harness::new();
    h.approve(true);
    let settings = h
        .store()
        .load_html_sync_settings(h.project)
        .expect("settings")
        .expect("stored settings")
        .settings()
        .clone();
    h.seed_document(h.synced_state(&settings));
    let request = H3OperationRequest::new(
        H3RequestId::new(h.project),
        h.project,
        Some(h.document()),
        Some(1),
        None,
        H3Operation::Pause,
        Harness::now(),
    )
    .expect("request");
    let view = composition::apply_document_operation(&mut h.host, request).expect("operation");
    match view.result.outcome() {
        herness_html_sync::H3OperationOutcome::Rejected { reason } => {
            assert_eq!(reason.state(), H3State::WaitingHuman);
        }
        other => panic!("expected a rejection, got {other:?}"),
    }
    let record = h
        .store()
        .load_html_sync_document(h.project, &h.document())
        .expect("load")
        .expect("document");
    assert_eq!(record.state().state(), H3State::Synced);
    assert_eq!(record.revision(), 1);
}
