//! Task 23 cross-phase regression: restart, scheduling, and the serial limits.
//!
//! The restart path uses the real `DesktopHost`, the real store, and the real
//! H3 startup reconciliation. It never sends a model request. The scheduling
//! test uses the real `SyncCoordinator` and approved jobs; no provider, network,
//! GUI, or render is involved.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::sync::Arc;

use herness_core::{
    ConnectionAdmin, ConnectionId, CoreError, CredentialAvailability, CredentialPort, ProjectId,
    ResolvedCredential, Timestamp,
};
use herness_desktop::host::DesktopHost;
use herness_engine_pi::ProviderEndpoints;
use herness_html_sync::{
    Applicability, ApplicabilityReason, AuthoringJob, CoordinatorTick, DocumentCommit, DocumentKey,
    FingerprintSet, H3ApprovalLimits, H3ConfigurationApproval, H3ConfigurationDraft,
    H3ConnectionApproval, H3DocumentState, H3OwnerBinding, H3Reason, H3Settings, H3State,
    H3StateReasonKind, H3StorePort, H3VersionBinding, HtmlSyncCommit, OfferOutcome, RequiredAction,
    SettingsCommit, SourceRevision, SourceSnapshot, SyncCoordinator, document_state_event,
};
use herness_supervision::{
    BudgetPolicy, ConditionDigest, ConditionVersion, ConsentBinding, ContentDigest,
    DisclosureDataKind, DisclosureScope, ExecutionScope, OwnerKind, OwnerRef, ProfileBinding,
    ProfileId, ProfilePurpose, ProfileVersion, ProviderOrigin, SupervisionId, TargetVersion,
};
use tempfile::TempDir;
use uuid::Uuid;

const TARGET: &str = "docs/adr/0001-queue-choice.md";
const CSS: &str = "docs/sdd/assets/sdd.css";

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

fn now() -> Timestamp {
    Timestamp::now()
}

fn profile(project: ProjectId, purpose: ProfilePurpose) -> ProfileBinding {
    let seed = match purpose {
        ProfilePurpose::Completion => "10000000-0000-4000-8000-000000000001",
        ProfilePurpose::Html => "10000000-0000-4000-8000-000000000002",
        ProfilePurpose::Permission => "10000000-0000-4000-8000-000000000003",
    };
    ProfileBinding::new(
        ProfileId::from_parts(project, Uuid::parse_str(seed).expect("uuid")),
        ProfileVersion::new(1).expect("version"),
        purpose,
    )
}

fn consent(project: ProjectId, purpose: ProfilePurpose) -> ConsentBinding {
    let seed = match purpose {
        ProfilePurpose::Completion => "20000000-0000-4000-8000-000000000001",
        ProfilePurpose::Html => "20000000-0000-4000-8000-000000000002",
        ProfilePurpose::Permission => "20000000-0000-4000-8000-000000000003",
    };
    ConsentBinding::new(
        herness_supervision::ConsentId::from_parts(project, Uuid::parse_str(seed).expect("uuid")),
        1,
        purpose,
        TargetVersion::new(1).expect("target"),
    )
}

fn connection(project: ProjectId, purpose: ProfilePurpose) -> H3ConnectionApproval {
    H3ConnectionApproval::new(
        project,
        ConnectionId::new(),
        ProviderOrigin::parse("https://loopback.example").expect("origin"),
        DisclosureScope::new(
            purpose,
            BTreeSet::from([DisclosureDataKind::Text]),
            vec![TARGET.to_owned()],
            TargetVersion::new(1).expect("target"),
        )
        .expect("disclosure"),
        profile(project, purpose),
        consent(project, purpose),
    )
    .expect("connection")
}

fn approved_settings(project: ProjectId, job: &str) -> H3Settings {
    let owner = H3OwnerBinding::new(
        project,
        OwnerRef::new(OwnerKind::H3HtmlJob, job).expect("owner"),
        job,
        ConditionVersion::new(1).expect("condition version"),
        ConditionDigest::sha256(b"conditions"),
        ExecutionScope::new(
            project,
            vec![TARGET.to_owned()],
            vec!["private/html-sync/candidates".to_owned()],
            false,
        )
        .expect("scope"),
        1,
        BudgetPolicy::h2_default(),
    )
    .expect("owner");
    let approval = H3ConfigurationApproval::approve(
        H3ConfigurationDraft {
            project_id: project,
            settings_version: 1,
            approval_id: format!("approval-{job}"),
            expires_at: None,
            targets: vec![TARGET.to_owned()],
            authoring: connection(project, ProfilePurpose::Completion),
            assessment: connection(project, ProfilePurpose::Html),
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
            owner,
        },
        herness_html_sync::H3Approver::Human,
        now(),
    )
    .expect("approval");
    H3Settings::approved(approval, true).expect("settings")
}

fn project_root() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().expect("project temp");
    let root = temp.path().join("project");
    std::fs::create_dir_all(root.join("docs/adr")).expect("adr");
    std::fs::create_dir_all(root.join("docs/sdd/assets")).expect("assets");
    std::fs::write(root.join(TARGET), "# Queue choice\n\nUse the queue.\n").expect("source");
    std::fs::write(root.join(CSS), "body { color: #111; }\n").expect("css");
    (temp, root)
}

fn seed_pending_state(
    store: &mut herness_desktop::supervision::store::StoreHandle,
    project: ProjectId,
    settings: &H3Settings,
) {
    let document = DocumentKey::new(project, TARGET).expect("document");
    let source = SourceSnapshot::new(
        SourceRevision::new(1).expect("revision"),
        ContentDigest::sha256(b"# Queue choice\n\nUse the queue.\n"),
    );
    let state = H3DocumentState::new(
        document.clone(),
        settings.version(),
        None,
        None,
        None,
        source,
        FingerprintSet::new(
            settings.fingerprint().clone(),
            ContentDigest::sha256(b"policy"),
            ContentDigest::sha256(b"css"),
            ContentDigest::sha256(b"resources"),
            None,
            None,
            None,
        ),
        H3Reason::new(
            H3StateReasonKind::Pending { source_revision: 1 },
            vec![RequiredAction::WaitForStableSource],
        )
        .expect("reason"),
        None,
        Vec::new(),
        Applicability::not_applicable(ApplicabilityReason::NeverPublished),
        now(),
    )
    .expect("state");
    let event = document_state_event(&document, None, &state, now()).expect("event");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(None, state).expect("commit"))
                .with_events(vec![event]),
        )
        .expect("document commit");
}

#[test]
fn restart_reconciles_without_sending_and_preserves_the_saved_document() {
    let (project_temp, root) = project_root();
    let data = TempDir::new().expect("app data");
    let (mut first, _) = DesktopHost::open(
        data.path(),
        ConnectionAdmin::new(),
        Arc::new(NoCredentials),
        ProviderEndpoints::official(),
    )
    .expect("first host");
    let view = first.open_project(&root).expect("open project");
    let project = view.project_id();
    let settings = approved_settings(project, "restart-job");
    let mut store = first.store_handle();
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_settings(SettingsCommit::new(None, settings.clone()).expect("settings")),
        )
        .expect("settings commit");
    seed_pending_state(&mut store, project, &settings);
    drop(store);
    drop(first);
    let _project_guard = project_temp;

    let (second, _) = DesktopHost::open(
        data.path(),
        ConnectionAdmin::new(),
        Arc::new(NoCredentials),
        ProviderEndpoints::official(),
    )
    .expect("second host");
    let startup = second.html_sync_startup().expect("startup report");
    assert_eq!(startup.request_count(), 0);
    assert!(startup.side_effects().is_zero());
    assert!(
        startup
            .projects()
            .iter()
            .any(|report| report.project_id() == project),
        "the open project must be reconciled on restore"
    );
    let record = second
        .store_handle()
        .load_html_sync_document(
            project,
            &DocumentKey::new(project, TARGET).expect("document"),
        )
        .expect("load")
        .expect("document");
    assert_eq!(record.state().source().revision().get(), 1);
    assert_eq!(
        record.state().state(),
        H3State::WaitingHuman,
        "restored active work is latched for an explicit human resume"
    );
    assert!(matches!(
        record.state().reason().kind(),
        H3StateReasonKind::WaitingHuman { .. }
    ));
    assert!(
        !second
            .html_sync_services()
            .store_handle()
            .load_html_sync_settings(project)
            .expect("settings")
            .is_none(),
        "the approved settings are preserved"
    );
}

#[test]
fn dirty_documents_keep_notification_order_under_one_app_wide_slot() {
    let project_a = ProjectId::new();
    let project_b = ProjectId::new();
    let settings_a = approved_settings(project_a, "job-a");
    let settings_b = approved_settings(project_b, "job-b");
    let job_a = AuthoringJob::from_settings(&settings_a, SupervisionId::new(project_a), now())
        .expect("job a");
    let job_b = AuthoringJob::from_settings(&settings_b, SupervisionId::new(project_b), now())
        .expect("job b");

    let mut coordinator = SyncCoordinator::new();
    coordinator.bind_job(job_a);
    coordinator.bind_job(job_b);
    let document_a = DocumentKey::new(project_a, TARGET).expect("document a");
    let document_b = DocumentKey::new(project_b, TARGET).expect("document b");
    let observation = |document: &DocumentKey| herness_html_sync::SourceObservation {
        document: document.clone(),
        snapshot: SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(document.project_id().to_string().as_bytes()),
        ),
        change: herness_html_sync::SourceChange::Initial,
        trigger: herness_html_sync::ObservationTrigger::FileNotification,
        observed_via: vec![herness_html_sync::observer::ChangeSource::FilesystemWatcher],
        eligibility: herness_html_sync::ObservationEligibility::approved(1).expect("eligible"),
    };
    assert_eq!(
        coordinator.offer(&observation(&document_b)),
        OfferOutcome::Queued
    );
    assert_eq!(
        coordinator.offer(&observation(&document_a)),
        OfferOutcome::Queued
    );
    assert_eq!(
        coordinator.queued_documents(),
        vec![document_b.clone(), document_a.clone()],
        "the original notification order is preserved"
    );
    assert_eq!(
        coordinator.offer(&observation(&document_b)),
        OfferOutcome::Updated,
        "a duplicate updates one entry without changing its position"
    );
    assert_eq!(coordinator.queued_documents(), vec![document_b, document_a]);
    assert!(!coordinator.is_authoring());
    assert_eq!(herness_html_sync::APP_WIDE_AUTHORING_CONCURRENCY, 1);
    assert_eq!(herness_html_sync::DOCUMENT_PUBLICATION_CONCURRENCY, 1);
    let _: Option<CoordinatorTick> = None;
}
