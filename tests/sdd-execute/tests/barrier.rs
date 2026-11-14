//! Task 16: H4's H3 required set, the pre-verification readiness gate, and the
//! final barrier.
//!
//! Every case uses real temporary files and the real H3 store (SQLite in a temp
//! directory). No provider, credential, Keychain item, model request, GUI, or
//! network is used. The checkout root is a real temporary directory; nothing is
//! committed, staged, or pushed.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use herness_core::contracts::{ConnectionId, ProjectId, Timestamp};
use herness_desktop::sdd_execute::barrier::{
    DesktopH4BarrierGate, DesktopTaskCompletion, H4RequiredDocuments,
};
use herness_desktop::sdd_execute::readiness::{DesktopH4Readiness, ReadinessDocumentSource};
use herness_desktop::supervision::store::StoreHandle;
use herness_html_sync::observer::DependencyPath;
use herness_html_sync::{
    Applicability, ApplicabilityReason, DocumentCommit, DocumentKey, FingerprintSet,
    H3ApprovalLimits, H3Approver, H3ConfigurationApproval, H3ConfigurationDraft,
    H3ConnectionApproval, H3DocumentState, H3OwnerBinding, H3Reason, H3Settings, H3StateReasonKind,
    H3StorePort, H3VersionBinding, HtmlSyncCommit, HumanWaitCause, RequiredAction, SettingsCommit,
    SourceRevision, SourceSnapshot, dependency_fingerprint, document_state_event, settings_event,
};
use herness_sdd_execute::barrier::{
    DocumentOrigin, RequiredSetInputs, RequiredSetOutcome, ScannedTarget, StoredTarget,
    required_documents,
};
use herness_sdd_execute::{
    ApprovalSource, ApprovedCheck, ApprovedCondition, ApprovedDeliverable, ApprovedSpecRef,
    Baseline, CommitAuthorization, CommitPolicy, CompletionFeature, CompletionWiring,
    ConditionMode, ControlRequestId, CoordinatorPorts, CoordinatorRequest, DeliverableKind,
    ExecutionApproval, ExecutionConnection, ExecutionId, ExecutionRevision, ExecutionSnapshot,
    ExecutionState, GitIdentity, H3ApprovalBinding, HtmlSyncReason, HumanAction, InspectorProtocol,
    PackApproval, PackFingerprint, ParsedPlanSummary, ParsedPlanTask, PlanApproval, PlanByteRange,
    PlanDigest, PlanPath, PlanRevision, SddExecutionError, SerialExecutionState, Sha256Digest,
    SnapshotBudget, SnapshotInput, SnapshotPlan, SnapshotWorkspace, StopReason, TaskApproval,
    TaskCompletion, TaskCompletionPort, TaskCompletionRequest, TaskCoordinator, TaskNumber,
    TaskRef, TaskStableId, WorkspaceApproval, completion_wiring,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::budget::BudgetPolicy;
use herness_supervision::supervisor::{ReadinessDecision, ReadinessRequest};
use herness_supervision::{
    ApprovalActor, ConditionDigest, ConditionVersion, ConsentBinding, ConsentId, ContentDigest,
    DisclosureDataKind, DisclosureScope, ExecutionScope, OwnerKind, OwnerRef, ProfileBinding,
    ProfileId, ProfilePurpose, ProfileVersion, ProviderOrigin, SupervisionId, TargetVersion,
};
use tempfile::TempDir;
use uuid::Uuid;

const CSS: &str = "docs/sdd/assets/sdd.css";
const PLAN: &str = "docs/sdd/plans/2026-11-13-barrier-fixture.md";
const SPEC: &str = "docs/sdd/specs/2026-11-13-barrier-fixture.md";
const TARGET: &str = "docs/adr/0001-queue-choice.md";
const MISSED: &str = "docs/adr/0002-missed-change.md";
const UNRELATED: &str = "docs/adr/0003-unrelated.md";

fn project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("a1000000-0000-4000-8000-000000000001").unwrap())
}

fn execution(project_id: ProjectId) -> ExecutionId {
    ExecutionId::from_parts(
        project_id,
        Uuid::parse_str("b1000000-0000-4000-8000-000000000001").unwrap(),
    )
}

fn approval_id(project_id: ProjectId) -> herness_sdd_execute::ApprovalId {
    herness_sdd_execute::ApprovalId::from_parts(
        project_id,
        Uuid::parse_str("c1000000-0000-4000-8000-000000000001").unwrap(),
    )
}

fn now() -> Timestamp {
    Timestamp::from_unix_millis(1_770_000_000_000)
}

fn task_ref(project_id: ProjectId, number: u32) -> TaskRef {
    TaskRef::new(
        TaskStableId::from_parts(
            project_id,
            Uuid::from_u128(0xd100_0000_0000_4000_8000_0000_0000_0000 + u128::from(number)),
        ),
        TaskNumber::new(number).expect("a Task number"),
    )
}

fn digest(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

// ---------------------------------------------------------------------------
// Real project fixture
// ---------------------------------------------------------------------------

struct Fixture {
    _data: TempDir,
    _project: TempDir,
    root: PathBuf,
    store: StoreHandle,
    project: ProjectId,
    settings: H3Settings,
}

impl Fixture {
    fn new() -> Self {
        let data = tempfile::tempdir().expect("app data");
        let project_root = tempfile::tempdir().expect("project root");
        let root = project_root.path().join("checkout");
        std::fs::create_dir_all(root.join("docs/adr")).expect("adr");
        std::fs::create_dir_all(root.join("docs/sdd/assets")).expect("assets");
        std::fs::create_dir_all(root.join("docs/sdd/plans")).expect("plans");
        std::fs::create_dir_all(root.join("docs/sdd/specs")).expect("specs");
        std::fs::write(root.join(TARGET), "# Queue choice\n\nUse the queue.\n").expect("target");
        std::fs::write(root.join(MISSED), "# Missed change\n\nOriginal.\n").expect("missed");
        std::fs::write(root.join(UNRELATED), "# Unrelated\n\nStable.\n").expect("unrelated");
        std::fs::write(root.join(PLAN), "# Plan\n\n## Task 1: something\n").expect("plan");
        std::fs::write(root.join(SPEC), "# Spec\n\nContract.\n").expect("spec");
        std::fs::write(root.join(CSS), "body { color: #111; }\n").expect("css");
        let canonical = std::fs::canonicalize(&root).expect("canonical checkout");

        let config = StoreConfig::new(data.path()).expect("store config");
        let store = Store::open(config).expect("store");
        let project = project();
        let store = StoreHandle::new(Arc::new(Mutex::new(store)));
        let settings = approve_settings(project);
        let mut handle = store.clone();
        handle
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_settings(
                        SettingsCommit::new(None, settings.clone()).expect("settings commit"),
                    )
                    .with_events(vec![
                        settings_event(&settings, now()).expect("settings event"),
                    ]),
            )
            .expect("settings");

        let fixture = Self {
            _data: data,
            _project: project_root,
            root: canonical,
            store,
            project,
            settings,
        };
        // The plan and the project spec are always part of the required union.
        fixture.seed_synced(PLAN);
        fixture.seed_synced(SPEC);
        fixture
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn read(&self, relative: &str) -> Vec<u8> {
        std::fs::read(self.path(relative)).expect("fixture file")
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.path(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        std::fs::write(path, contents).expect("write fixture");
    }

    fn remove(&self, relative: &str) {
        std::fs::remove_file(self.path(relative)).expect("remove fixture");
    }

    fn document(&self, relative: &str) -> DocumentKey {
        DocumentKey::new(self.project, relative).expect("document")
    }

    fn css_digest(&self) -> ContentDigest {
        dependency_fingerprint(
            herness_html_sync::observer::DependencyKind::Css,
            [(CSS, ContentDigest::sha256(&self.read(CSS)))],
        )
    }

    fn resources_digest(&self) -> ContentDigest {
        dependency_fingerprint(
            herness_html_sync::observer::DependencyKind::Resource,
            std::iter::empty(),
        )
    }

    fn policy_digest(&self) -> ContentDigest {
        self.settings
            .approval()
            .expect("an approved configuration")
            .versions()
            .policy_fingerprint()
            .clone()
    }

    fn fingerprints(&self) -> FingerprintSet {
        FingerprintSet::new(
            self.settings.fingerprint().clone(),
            self.policy_digest(),
            self.css_digest(),
            self.resources_digest(),
            None,
            None,
            None,
        )
    }

    fn synced_state(&self, relative: &str, revision: u64) -> H3DocumentState {
        let source = SourceSnapshot::new(
            SourceRevision::new(revision).expect("revision"),
            ContentDigest::sha256(&self.read(relative)),
        );
        let generation = herness_html_sync::GenerationId::new(self.project);
        let candidate =
            ContentDigest::sha256(&self.read(&relative.replace(".md", ".html"))).clone();
        H3DocumentState::new(
            self.document(relative),
            self.settings.version(),
            None,
            None,
            Some(generation),
            source.clone(),
            self.fingerprints().with_candidate(candidate),
            H3Reason::new(
                H3StateReasonKind::Synced {
                    generation,
                    source_revision: revision,
                    source_digest: source.digest().clone(),
                },
                Vec::new(),
            )
            .expect("synced reason"),
            None,
            Vec::new(),
            Applicability::current_synced(),
            now(),
        )
        .expect("synced state")
    }

    fn seed(&self, state: H3DocumentState) {
        let document = state.document_key().clone();
        let event = document_state_event(&document, None, &state, now()).expect("event");
        let mut store = self.store.clone();
        store
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_document(DocumentCommit::new(None, state).expect("document commit"))
                    .with_events(vec![event]),
            )
            .expect("document");
    }

    /// Seeds one synced document plus its companion HTML.
    fn seed_synced(&self, relative: &str) {
        self.write(&relative.replace(".md", ".html"), "<html>companion</html>");
        self.seed(self.synced_state(relative, 1));
    }

    /// Replaces one stored document with a new state and revision.
    fn replace(&self, relative: &str, state: H3DocumentState) {
        let document = self.document(relative);
        let record = self
            .store
            .load_html_sync_document(self.project, &document)
            .expect("load")
            .expect("stored");
        let event = document_state_event(&document, Some(record.state().state()), &state, now())
            .expect("event");
        let mut store = self.store.clone();
        store
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_document(
                        DocumentCommit::new(Some(record.revision()), state).expect("commit"),
                    )
                    .with_events(vec![event]),
            )
            .expect("replace");
    }

    fn pending_state(&self, relative: &str) -> H3DocumentState {
        let source = SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(&self.read(relative)),
        );
        H3DocumentState::new(
            self.document(relative),
            self.settings.version(),
            None,
            None,
            None,
            source,
            self.fingerprints(),
            H3Reason::new(
                H3StateReasonKind::Pending { source_revision: 1 },
                vec![RequiredAction::WaitForStableSource],
            )
            .expect("pending reason"),
            None,
            Vec::new(),
            Applicability::not_applicable(ApplicabilityReason::NeverPublished),
            now(),
        )
        .expect("pending state")
    }

    fn waiting_human_state(&self, relative: &str) -> H3DocumentState {
        let source = SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(&self.read(relative)),
        );
        H3DocumentState::new(
            self.document(relative),
            self.settings.version(),
            None,
            None,
            None,
            source,
            self.fingerprints(),
            H3Reason::new(
                H3StateReasonKind::WaitingHuman {
                    cause: HumanWaitCause::UndecidableAssessment,
                },
                vec![RequiredAction::ReassessCandidate],
            )
            .expect("waiting reason"),
            None,
            Vec::new(),
            Applicability::not_applicable(ApplicabilityReason::NeverPublished),
            now(),
        )
        .expect("waiting state")
    }

    fn gate(&self, targets: &[&str]) -> DesktopH4BarrierGate {
        let mut gate = DesktopH4BarrierGate::new(
            self.store.clone(),
            self.project,
            &self.root,
            vec![
                DependencyPath::new(CSS, herness_html_sync::observer::DependencyKind::Css)
                    .expect("css dependency"),
            ],
        )
        .expect("gate");
        gate.bind_task(&approval(self.project, targets), task_ref(self.project, 1))
            .expect("bind");
        gate
    }
}

fn profile(project: ProjectId, purpose: ProfilePurpose) -> ProfileBinding {
    let local = match purpose {
        ProfilePurpose::Completion => "e1000000-0000-4000-8000-000000000001",
        ProfilePurpose::Html => "e1000000-0000-4000-8000-000000000002",
        ProfilePurpose::Permission => "e1000000-0000-4000-8000-000000000003",
    };
    ProfileBinding::new(
        ProfileId::from_parts(project, Uuid::parse_str(local).expect("uuid")),
        ProfileVersion::new(1).expect("version"),
        purpose,
    )
}

fn consent(project: ProjectId, purpose: ProfilePurpose) -> ConsentBinding {
    let local = match purpose {
        ProfilePurpose::Completion => "f1000000-0000-4000-8000-000000000001",
        ProfilePurpose::Html => "f1000000-0000-4000-8000-000000000002",
        ProfilePurpose::Permission => "f1000000-0000-4000-8000-000000000003",
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
            vec![TARGET.to_owned(), MISSED.to_owned(), UNRELATED.to_owned()],
            TargetVersion::new(1).expect("target version"),
        )
        .expect("disclosure"),
        profile(project, purpose),
        consent(project, purpose),
    )
    .expect("connection approval")
}

fn approve_settings(project: ProjectId) -> H3Settings {
    let approval = H3ConfigurationApproval::approve(
        H3ConfigurationDraft {
            project_id: project,
            settings_version: 1,
            approval_id: "task-16-approval".to_owned(),
            expires_at: None,
            targets: vec![
                TARGET.to_owned(),
                MISSED.to_owned(),
                UNRELATED.to_owned(),
                PLAN.to_owned(),
                SPEC.to_owned(),
            ],
            authoring: connection(project, ProfilePurpose::Completion),
            assessment: connection(project, ProfilePurpose::Html),
            versions: H3VersionBinding::new(
                "sdd-herness-integration",
                1,
                1,
                "sdd-html-policy-v1",
                digest("task-16-policy"),
                1,
                digest("task-16-pack"),
                "sdd-html-host-api",
                1,
            )
            .expect("versions"),
            limits: H3ApprovalLimits::default(),
            auto_publish: false,
            retain_history: true,
            automatic_companion: true,
            owner: H3OwnerBinding::new(
                project,
                OwnerRef::new(OwnerKind::H3HtmlJob, "task-16-job").expect("owner"),
                "task-16-job",
                ConditionVersion::new(1).expect("condition version"),
                ConditionDigest::sha256(b"task-16-conditions"),
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
            .expect("owner binding"),
        },
        H3Approver::Human,
        now(),
    )
    .expect("approval");
    H3Settings::approved(approval, true).expect("settings")
}

// ---------------------------------------------------------------------------
// H4 approval fixture
// ---------------------------------------------------------------------------

fn scope(project: ProjectId) -> ExecutionScope {
    ExecutionScope::new(
        project,
        vec!["docs".to_owned()],
        vec!["docs/adr".to_owned()],
        false,
    )
    .expect("scope")
}

fn task_approval(project: ProjectId, html_targets: &[&str]) -> TaskApproval {
    TaskApproval::new(
        task_ref(project, 1),
        "Task 1".to_owned(),
        vec![
            ApprovedCondition::new("c1", "condition", "rubric", ConditionMode::Checks)
                .expect("condition"),
        ],
        scope(project),
        vec![
            ApprovedCheck::new(
                "check-1",
                "c1",
                "run",
                "cargo test",
                ".",
                30,
                vec!["docs".into()],
            )
            .expect("check"),
        ],
        html_targets
            .iter()
            .map(|target| (*target).to_owned())
            .collect(),
        BudgetPolicy::h2_default(),
        CommitPolicy::Required,
        vec![
            ApprovedDeliverable::new("docs/adr/0001-queue-choice.html", DeliverableKind::File)
                .expect("deliverable"),
        ],
    )
    .expect("Task approval")
}

fn plan_approval() -> PlanApproval {
    let constraints = "Global Constraints\n- keep 4 rules";
    let body = || {
        herness_sdd_execute::ExactPlanText::new("Body.\n", PlanByteRange::new(0, 6).unwrap())
            .expect("exact body")
    };
    PlanApproval::new(
        PlanPath::parse(PLAN).expect("a plan path"),
        herness_sdd_execute::ExactPlanBytes::new(b"# plan".to_vec()).unwrap(),
        PlanRevision::new(1).expect("revision"),
        ParsedPlanSummary::new(
            1,
            herness_sdd_execute::ExactPlanText::new(
                constraints,
                PlanByteRange::new(0, constraints.len() as u64).unwrap(),
            )
            .unwrap(),
            vec![ParsedPlanTask::new(1, "Task 1".to_owned(), body()).unwrap()],
            vec!["check-1".to_owned()],
        )
        .expect("parsed"),
        vec![
            ApprovedSpecRef::new("project", SPEC, vec!["Contract".to_owned()], {
                Sha256Digest::sha256(b"spec")
            })
            .expect("spec ref"),
        ],
        Vec::new(),
        PackApproval::new(
            InspectorProtocol::expected(),
            1,
            PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
        )
        .expect("pack"),
    )
    .expect("plan approval")
}

fn approval(project_id: ProjectId, html_targets: &[&str]) -> ExecutionApproval {
    ExecutionApproval::new(
        approval_id(project_id),
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry {
            approval_id: approval_id(project_id),
        },
        now(),
        herness_sdd_execute::ApprovalContent::new(
            plan_approval(),
            WorkspaceApproval::new(
                project_id,
                "/tmp/herness-h4-barrier-fixture",
                GitIdentity::new("herness", "host@example.test").expect("identity"),
                "h4-barrier",
                "main",
                false,
                Some(Baseline::parse("a".repeat(40)).unwrap()),
            )
            .expect("workspace"),
            vec![task_approval(project_id, html_targets)],
            ExecutionConnection::new(
                ConnectionId::from_uuid(
                    Uuid::parse_str("e1000000-0000-4000-8000-000000000004").unwrap(),
                ),
                profile(project_id, ProfilePurpose::Completion),
                vec![consent(project_id, ProfilePurpose::Completion)],
            )
            .expect("connection"),
            CommitAuthorization::new(true, true).expect("commit"),
            H3ApprovalBinding::new(1, Vec::new(), vec!["html-sync".to_owned()]).unwrap(),
        )
        .expect("content"),
    )
    .expect("approval")
}

fn completion_request(project_id: ProjectId, number: u32) -> TaskCompletionRequest {
    TaskCompletionRequest::new(
        task_ref(project_id, number),
        execution(project_id),
        ExecutionRevision::INITIAL,
        SupervisionId::new(project_id),
        CommitAuthorization::new(true, true).expect("commit authorization"),
        CommitPolicy::Required,
        Vec::new(),
        7_000,
    )
}

fn readiness_request(project: ProjectId) -> ReadinessRequest {
    ReadinessRequest::new(
        project,
        SupervisionId::new(project),
        herness_core::contracts::RunId::new(project),
        herness_core::contracts::InputId::new(project),
        ConditionVersion::new(1).expect("condition version"),
        TargetVersion::new(1).expect("target version"),
        now(),
    )
}

// ---------------------------------------------------------------------------
// Enumeration miss
// ---------------------------------------------------------------------------

#[test]
fn a_changed_document_outside_html_targets_enters_the_required_union() {
    // The union without the scan would only contain the plan, the spec, and the
    // declared htmlTarget.
    let inputs = RequiredSetInputs {
        html_targets: vec![TARGET.to_owned()],
        plan_paths: vec![PLAN.to_owned()],
        project_specs: vec![SPEC.to_owned()],
        declared_targets: vec![TARGET.to_owned(), MISSED.to_owned()],
        stored: vec![
            StoredTarget::new(TARGET, digest("t")),
            StoredTarget::new(MISSED, digest("old")),
        ],
        scanned: vec![
            ScannedTarget::new(TARGET, Some(digest("t"))),
            ScannedTarget::new(MISSED, Some(digest("new"))),
        ],
        ..RequiredSetInputs::default()
    };
    let RequiredSetOutcome::Ready(set) = required_documents(&inputs) else {
        panic!("a set");
    };
    assert!(
        set.get(MISSED).is_some(),
        "the scan-only change is required"
    );
    assert!(
        set.get(MISSED)
            .expect("missed target")
            .has_origin(DocumentOrigin::ChangedTarget)
    );

    // The real desktop gate reaches the same conclusion from real bytes.
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    fixture.seed_synced(MISSED);
    fixture.seed_synced(UNRELATED);
    let mut gate = fixture.gate(&[TARGET]);
    // The pre-verification capture records the baseline of the missed Target.
    let capture = gate.capture_verification().expect("capture");
    assert!(
        capture
            .inputs
            .html_targets
            .iter()
            .any(|path| path == TARGET)
    );
    assert!(
        !capture
            .inputs
            .html_targets
            .iter()
            .any(|path| path == MISSED)
    );

    // Now change the missed Target only.
    fixture.write(MISSED, "# Missed change\n\nChanged.\n");
    let mut source = H4RequiredDocuments::owned(gate);
    let requests =
        ReadinessDocumentSource::required(&mut source, &readiness_request(fixture.project))
            .expect("required documents");
    let paths = requests
        .iter()
        .map(|request| request.document().target_path().to_owned())
        .collect::<Vec<_>>();
    assert!(
        paths.iter().any(|path| path == MISSED),
        "the readiness gate must require the changed Target the JSON enumeration omits, got {paths:?}"
    );
    assert!(paths.iter().any(|path| path == PLAN));
    assert!(paths.iter().any(|path| path == SPEC));
}

// ---------------------------------------------------------------------------
// CSS invalidation
// ---------------------------------------------------------------------------

#[test]
fn a_css_change_invalidates_html_that_did_not_itself_change() {
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification()
        .expect("pre-verification capture");

    // The source and the companion are untouched; only the shared CSS changed.
    fixture.write(CSS, "body { color: #222; }\n");
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    assert!(!report.decision().is_synced());
    let hold = report.decision().hold().expect("a hold");
    assert_eq!(hold.reason(), HtmlSyncReason::Mismatch);
    assert!(
        hold.detail().contains("css"),
        "the CSS fingerprint is the mismatch, got {}",
        hold.detail()
    );
    // The documents H3 synced under the old CSS are held; the declared Targets
    // H3 never synced are not dragged in.
    assert!(hold.documents().iter().any(|path| path == TARGET));
    assert!(
        !hold
            .documents()
            .iter()
            .any(|path| path == MISSED || path == UNRELATED)
    );
}

// ---------------------------------------------------------------------------
// Stale HTML
// ---------------------------------------------------------------------------

#[test]
fn a_source_that_changed_after_verification_holds_even_when_h3_says_synced() {
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification()
        .expect("pre-verification capture");

    // The source changes after the pre-verification capture while H3 still
    // stores the earlier revision as synced.
    fixture.write(TARGET, "# Queue choice\n\nUse the queue now.\n");
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    let hold = report.decision().hold().expect("a hold");
    assert_eq!(hold.reason(), HtmlSyncReason::Mismatch);
    assert!(hold.detail().contains("differ from the bytes verified"));
}

// ---------------------------------------------------------------------------
// Returning to the same bytes
// ---------------------------------------------------------------------------

#[test]
fn returning_to_the_same_bytes_never_resurrects_a_stale_synced() {
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification()
        .expect("pre-verification capture");

    // H3 records a later source revision with exactly the same bytes.
    let replacement = fixture.synced_state(TARGET, 2);
    fixture.replace(TARGET, replacement);

    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    let hold = report.decision().hold().expect("a hold");
    assert_eq!(hold.reason(), HtmlSyncReason::Mismatch);
    assert!(
        hold.detail().contains("returned-to-earlier-bytes"),
        "a returned-to-earlier-bytes state is not the verified version, got {}",
        hold.detail()
    );
}

// ---------------------------------------------------------------------------
// Each barrier outcome
// ---------------------------------------------------------------------------

#[test]
fn every_barrier_outcome_maps_to_its_own_hold() {
    // Missing: no saved H3 document exists for the changed Target.
    let fixture = Fixture::new();
    fixture.seed_synced(UNRELATED);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("capture");
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    assert_eq!(
        report.decision().hold().expect("a hold").reason(),
        HtmlSyncReason::Missing
    );

    // Unsynced: the saved document is not currently synced.
    let fixture = Fixture::new();
    fixture.seed(fixture.pending_state(TARGET));
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("capture");
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    let hold = report.decision().hold().expect("a hold");
    assert_eq!(hold.reason(), HtmlSyncReason::Unsynced);
    assert!(
        hold.required_actions()
            .contains(&"wait_for_stable_source".to_owned())
    );

    // Mismatch: the saved source revision is not the verified one.
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("capture");
    fixture.replace(TARGET, fixture.synced_state(TARGET, 7));
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    assert_eq!(
        report.decision().hold().expect("a hold").reason(),
        HtmlSyncReason::Mismatch
    );

    // Orphaned: the Markdown source is gone while the old companion remains.
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("capture");
    fixture.remove(TARGET);
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    let hold = report.decision().hold().expect("a hold");
    assert_eq!(hold.reason(), HtmlSyncReason::Orphaned);
    assert!(fixture.path(&TARGET.replace(".md", ".html")).exists());
}

#[test]
fn missing_approval_holds_and_h4_authors_nothing() {
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    // Remove the human configuration approval by storing settings without one.
    let unapproved = H3Settings::new(
        fixture.project,
        2,
        true,
        fixture.settings.target_paths().to_vec(),
        false,
        true,
        now(),
    )
    .expect("unapproved settings");
    let mut store = fixture.store.clone();
    let record = store
        .load_html_sync_settings(fixture.project)
        .expect("load")
        .expect("stored");
    store
        .commit_html_sync(HtmlSyncCommit::new().with_settings(
            SettingsCommit::new(Some(record.revision()), unapproved).expect("commit"),
        ))
        .expect("settings");

    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification()
        .expect("pre-verification capture");
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    let hold = report.decision().hold().expect("a hold");
    assert_eq!(hold.reason(), HtmlSyncReason::NotApproved);
    assert!(
        hold.required_actions()
            .contains(&"approve_settings".to_owned())
    );
    // H4 never wrote a companion or a receipt.
    assert!(!fixture.path("docs/sdd/html-evidence").exists());
}

// ---------------------------------------------------------------------------
// Unrelated, unchanged Target
// ---------------------------------------------------------------------------

#[test]
fn an_unrelated_unchanged_target_failure_alone_does_not_stop_the_task() {
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    // A stored Target that is not referenced and whose bytes did not change is
    // failing in H3. It is observed but not required.
    fixture.seed(fixture.waiting_human_state(UNRELATED));
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("capture");

    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    assert!(
        report.decision().is_synced(),
        "an unrelated unchanged Target must not stop the Task: {:?}",
        report.decision()
    );
    assert!(
        report.unrelated().iter().any(|path| path == UNRELATED),
        "the unrelated Target is still observed"
    );
    assert!(
        report
            .required()
            .iter()
            .all(|document| document.path() != UNRELATED)
    );
}

// ---------------------------------------------------------------------------
// Pre-verification gate and final barrier share the union
// ---------------------------------------------------------------------------

#[test]
fn the_readiness_gate_and_the_final_barrier_both_use_the_union() {
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    fixture.seed_synced(MISSED);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("capture");
    fixture.write(MISSED, "# Missed change\n\nChanged again.\n");

    let mut source = H4RequiredDocuments::owned(gate);
    let requests =
        ReadinessDocumentSource::required(&mut source, &readiness_request(fixture.project))
            .expect("required");
    let union_paths = requests
        .iter()
        .map(|request| request.document().target_path().to_owned())
        .collect::<BTreeSet<_>>();
    assert!(union_paths.contains(MISSED));
    assert!(union_paths.contains(PLAN));
    assert!(union_paths.contains(SPEC));

    // The real pre-verification gate waits on that same union instead of a fixed
    // list: it has the pre-Task scan, so it sees the change the JSON omits.
    let mut readiness = DesktopH4Readiness::new(
        herness_desktop::html_sync::composition::DesktopH4Barrier::new(fixture.store.clone()),
        source,
    );
    let decision = herness_supervision::supervisor::VerificationReadinessPort::readiness(
        &mut readiness,
        &readiness_request(fixture.project),
    )
    .expect("readiness");
    assert!(
        matches!(decision, ReadinessDecision::Pending { .. }),
        "the changed Target outside htmlTargets must hold verification, got {decision:?}"
    );

    // The same gate's final barrier asserts the same union.
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("pre-Task capture");
    fixture.write(MISSED, "# Missed change\n\nChanged a third time.\n");
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    let required = report
        .required()
        .iter()
        .map(|document| document.path().to_owned())
        .collect::<BTreeSet<_>>();
    assert!(required.contains(MISSED));
    assert!(required.contains(PLAN));
    assert!(required.contains(SPEC));
    assert!(!report.decision().is_synced());
}

#[test]
fn one_shared_gate_serves_the_readiness_wait_and_the_final_barrier() {
    use herness_desktop::sdd_execute::barrier::{
        bind_shared_gate, shared_gate, shared_readiness_port,
    };

    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("capture");
    let gate = shared_gate(gate);
    bind_shared_gate(
        &gate,
        &approval(fixture.project, &[TARGET]),
        task_ref(fixture.project, 1),
    )
    .expect("bind");

    // The pre-verification gate records the verified baseline in the shared gate.
    let mut readiness = shared_readiness_port(gate.clone());
    let decision = herness_supervision::supervisor::VerificationReadinessPort::readiness(
        &mut readiness,
        &readiness_request(fixture.project),
    )
    .expect("readiness");
    assert!(
        decision.is_ready(),
        "a synced union is ready, got {decision:?}"
    );

    // The final barrier on the same gate asserts that baseline.
    let request = completion_request(fixture.project, 1);
    let mut completion =
        herness_desktop::sdd_execute::barrier::HtmlBarrierCompletion::new(gate.clone());
    match TaskCompletionPort::complete(&mut completion, &request).expect("completion") {
        TaskCompletion::HumanWait { stop } => {
            assert_eq!(stop.reason(), StopReason::CapabilityUnavailable);
        }
        other => panic!("only the commit half may be missing here, got {other:?}"),
    }

    // The same shared gate now sees a stale source and holds with the HTML reason.
    fixture.write(TARGET, "# Queue choice\n\nStale.\n");
    match TaskCompletionPort::complete(&mut completion, &request).expect("completion") {
        TaskCompletion::HumanWait { stop } => {
            assert_eq!(stop.reason(), StopReason::HtmlMismatch);
        }
        other => panic!("a stale source must hold, got {other:?}"),
    }

    // The shared-gate completion wiring is the same barrier-connected shape.
    let mut shared_completion =
        herness_desktop::sdd_execute::barrier::DesktopTaskCompletion::barrier_shared(gate);
    assert!(matches!(
        TaskCompletionPort::wiring(&shared_completion, task_ref(fixture.project, 1)),
        CompletionWiring::BarrierConnected {
            missing: CompletionFeature::HostCommit
        }
    ));
    match TaskCompletionPort::complete(&mut shared_completion, &request).expect("completion") {
        TaskCompletion::HumanWait { stop } => {
            assert_eq!(stop.reason(), StopReason::HtmlMismatch);
        }
        other => panic!("the shared gate holds the stale source, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Completion wiring
// ---------------------------------------------------------------------------

#[test]
fn the_html_barrier_holds_the_task_and_the_commit_half_stays_explicit() {
    // The barrier-only wiring runs, but still never reports completion.
    assert_eq!(
        completion_wiring(true, false, CompletionFeature::HostCommit),
        CompletionWiring::BarrierConnected {
            missing: CompletionFeature::HostCommit
        }
    );
    assert!(
        completion_wiring(true, false, CompletionFeature::HostCommit).may_run(),
        "the barrier half runs before the commit refusal"
    );
    assert_eq!(
        completion_wiring(false, false, CompletionFeature::HostCommit),
        CompletionWiring::NotConnected {
            feature: CompletionFeature::HtmlBarrier
        }
    );
    assert!(!completion_wiring(false, false, CompletionFeature::HostCommit).may_run());
    assert_eq!(
        completion_wiring(true, true, CompletionFeature::HostCommit),
        CompletionWiring::Connected
    );

    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("capture");
    let request = completion_request(fixture.project, 1);

    // A synced barrier reaches the still-missing commit and holds explicitly.
    let mut completion = DesktopTaskCompletion::barrier(gate);
    assert!(matches!(
        TaskCompletionPort::wiring(&completion, task_ref(fixture.project, 1)),
        CompletionWiring::BarrierConnected {
            missing: CompletionFeature::HostCommit
        }
    ));
    match TaskCompletionPort::complete(&mut completion, &request).expect("completion") {
        TaskCompletion::HumanWait { stop } => {
            assert_eq!(stop.reason(), StopReason::CapabilityUnavailable);
            assert_eq!(stop.required_action(), Some(HumanAction::ProvideCapability));
        }
        other => panic!("a missing host commit is never completion, got {other:?}"),
    }

    // A non-synced barrier holds with the HTML reason before the commit refusal.
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("capture");
    fixture.write(TARGET, "# Queue choice\n\nChanged.\n");
    let mut completion = DesktopTaskCompletion::barrier(gate);
    match TaskCompletionPort::complete(&mut completion, &request).expect("completion") {
        TaskCompletion::HumanWait { stop } => {
            assert_eq!(stop.reason(), StopReason::HtmlMismatch);
            assert_eq!(stop.required_action(), Some(HumanAction::ResolveHtmlSync));
        }
        other => panic!("a mismatched HTML barrier must hold, got {other:?}"),
    }

    // The unconnected default still refuses both halves explicitly.
    let mut unconnected = DesktopTaskCompletion::not_connected();
    assert_eq!(
        TaskCompletionPort::wiring(&unconnected, task_ref(fixture.project, 1)),
        CompletionWiring::NotConnected {
            feature: CompletionFeature::HtmlBarrier
        }
    );
    let error = TaskCompletionPort::complete(&mut unconnected, &request)
        .expect_err("not connected never completes");
    assert!(matches!(error, SddExecutionError::Unavailable { .. }));
}

#[test]
fn a_document_without_a_verified_baseline_holds_and_is_never_synthesized() {
    // The gate captured nothing before the Task, so a later synced state isn't
    // the verified version. A saved `Synced` response and a real receipt are not
    // evidence on their own.
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    let mut gate = fixture.gate(&[TARGET]);
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    let hold = report.decision().hold().expect("a hold");
    assert_eq!(hold.reason(), HtmlSyncReason::Mismatch);
    assert!(
        hold.detail().contains("pre-verification capture never ran"),
        "an unverified version cannot be synced, got {}",
        hold.detail()
    );
    assert!(gate.baselines().is_empty());
    assert!(!gate.verified());
}

// ---------------------------------------------------------------------------
// Delegation and orphaned cleanup
// ---------------------------------------------------------------------------

#[test]
fn a_missing_companion_is_delegated_and_an_orphan_needs_a_human() {
    let fixture = Fixture::new();
    // A declared Target with no saved H3 document: bootstrap/authoring is H3's.
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification()
        .expect("pre-verification capture");
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    let hold = report.decision().hold().expect("a hold");
    assert_eq!(hold.reason(), HtmlSyncReason::Missing);
    assert!(
        hold.required_actions()
            .contains(&"bootstrap_companion".to_owned())
    );
    assert!(
        hold.required_actions()
            .contains(&"author_companion".to_owned())
    );
    // H4 authored nothing: no companion and no receipt exist.
    assert!(!fixture.path(&TARGET.replace(".md", ".html")).exists());
    assert!(!fixture.path("docs/sdd/html-evidence").exists());

    // A deleted source leaves an orphan. H4 must not delete or move the old
    // HTML: it asks for the human decision instead.
    let fixture = Fixture::new();
    fixture.seed_synced(TARGET);
    let mut gate = fixture.gate(&[TARGET]);
    gate.capture_verification().expect("capture");
    fixture.remove(TARGET);
    let companion = fixture.path(&TARGET.replace(".md", ".html"));
    let before = std::fs::read(&companion).expect("companion");
    let report = gate
        .final_barrier(task_ref(fixture.project, 1), now())
        .expect("final barrier");
    let hold = report.decision().hold().expect("a hold");
    assert_eq!(hold.reason(), HtmlSyncReason::Orphaned);
    assert_eq!(
        hold.stop().expect("stop").reason(),
        StopReason::HtmlOrphaned
    );
    assert_eq!(
        hold.stop().expect("stop").required_action(),
        Some(HumanAction::ResolveOrphanedHtml)
    );
    assert_eq!(
        std::fs::read(&companion).expect("companion is unchanged"),
        before,
        "H4 must not delete or rewrite the orphaned HTML"
    );
}

// ---------------------------------------------------------------------------
// Coordinator seam: a barrier-connected completion never completes the Task
// ---------------------------------------------------------------------------

#[test]
fn a_barrier_connected_completion_holds_instead_of_completing_the_task() {
    use herness_desktop::sdd_execute::barrier::TaskBarrierGate;
    use herness_sdd_execute::barrier::{BarrierHold, BarrierReport};

    struct HeldGate;
    impl TaskBarrierGate for HeldGate {
        fn final_barrier(
            &mut self,
            _task: TaskRef,
            _now: Timestamp,
        ) -> Result<BarrierReport, SddExecutionError> {
            Ok(BarrierReport::hold_decision(BarrierHold::new(
                HtmlSyncReason::Unsynced,
                vec![TARGET.to_owned()],
                "the document is not synced",
                vec!["resume_cycle".to_owned()],
            )))
        }
    }
    impl herness_desktop::sdd_execute::barrier::VerifiedDocumentSource for HeldGate {
        fn verified_documents(&self) -> herness_desktop::sdd_execute::barrier::VerifiedDocuments {
            herness_desktop::sdd_execute::barrier::VerifiedDocuments::default()
        }
    }

    let project = project();
    let execution = execution(project);
    let data = tempfile::tempdir().expect("coordinator data");
    let mut store = Store::open(StoreConfig::new(data.path().join("app-data")).expect("config"))
        .expect("store");
    herness_sdd_execute::DurableExecutionStorePort::record_approval(
        &mut store,
        &approval(project, &[TARGET]),
    )
    .expect("approval");
    store
        .compare_and_swap_execution(
            project,
            execution,
            None,
            &ready_snapshot(project, execution),
        )
        .expect("snapshot");

    let mut completion =
        herness_desktop::sdd_execute::barrier::HtmlBarrierCompletion::new(HeldGate);
    let mut launch = FakeLaunch;
    let mut dispatch = NoDispatch { calls: 0 };
    let mut children = NoChildren::default();
    let mut serial = SerialExecutionState::new();
    let request = CoordinatorRequest::new(
        project,
        execution,
        ControlRequestId::from_parts(project, Uuid::from_u128(0xabc)),
        ExecutionRevision::INITIAL,
        approval_id(project),
        1,
    )
    .expect("request");

    // Dispatch Task 1 first so an active Task exists.
    let mut ports = CoordinatorPorts {
        store: &mut store,
        launch: &mut launch,
        dispatch: &mut dispatch,
        children: &mut children,
        completion: &mut completion,
        serial: &mut serial,
    };
    TaskCoordinator::advance(&mut ports, &request).expect("dispatch");

    // The child is complete; the barrier holds with the HTML reason.
    children.scripted = Some(herness_sdd_execute::ChildStatus::new(
        supervision(project, 0x5000),
        herness_sdd_execute::ChildState::Completed,
        30,
        0,
        0,
        false,
        Vec::new(),
    ));
    let revision = store
        .load_sdd_execution(project, execution)
        .expect("load")
        .expect("snapshot")
        .revision();
    let request = CoordinatorRequest::new(
        project,
        execution,
        ControlRequestId::from_parts(project, Uuid::from_u128(0xabd)),
        revision,
        approval_id(project),
        1,
    )
    .expect("request");
    let mut ports = CoordinatorPorts {
        store: &mut store,
        launch: &mut launch,
        dispatch: &mut dispatch,
        children: &mut children,
        completion: &mut completion,
        serial: &mut serial,
    };
    let outcome = TaskCoordinator::advance(&mut ports, &request).expect("advance");
    assert!(matches!(
        outcome,
        herness_sdd_execute::CoordinatorOutcome::Stopped { .. }
    ));
    let stored = store
        .load_sdd_execution(project, execution)
        .expect("load")
        .expect("snapshot")
        .snapshot()
        .clone();
    assert_eq!(stored.state(), ExecutionState::WaitingHuman);
    assert_eq!(
        stored.stop().map(|stop| stop.reason()),
        Some(StopReason::HtmlUnsynced)
    );
    assert_eq!(dispatch.calls, 1, "no second Task starts");
}

fn ready_snapshot(project: ProjectId, execution: ExecutionId) -> ExecutionSnapshot {
    ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: execution,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Ready,
        plan: SnapshotPlan::new(
            PlanPath::parse(PLAN).expect("plan"),
            PlanDigest::sha256(b"# plan"),
            PlanRevision::new(1).expect("revision"),
        ),
        workspace: SnapshotWorkspace::new(
            "/tmp/herness-h4-barrier-fixture",
            "h4-barrier",
            "main",
            Some(Baseline::parse("a".repeat(40)).unwrap()),
        )
        .expect("workspace"),
        current_task: Some(task_ref(project, 1)),
        tasks: vec![
            herness_sdd_execute::TaskSnapshot::new(
                task_ref(project, 1),
                herness_sdd_execute::TaskProgression::Pending,
                herness_sdd_execute::TaskPhase::Ready,
                None,
                None,
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(
                    PlanRevision::new(1).expect("revision"),
                ),
            )
            .expect("Task 1"),
        ],
        stop: None,
        budget: SnapshotBudget::new(
            herness_sdd_execute::BudgetConsumption::zero(),
            herness_sdd_execute::BudgetConsumption::zero(),
        ),
        applied_revision: herness_sdd_execute::AppliedRevision::current(
            PlanRevision::new(1).expect("revision"),
        ),
        final_project_sequence: None,
    })
    .expect("snapshot")
}

fn supervision(project: ProjectId, local: u128) -> SupervisionId {
    SupervisionId::from_parts(project, Uuid::from_u128(local))
}

struct FakeLaunch;

impl herness_sdd_execute::TaskLaunchPort for FakeLaunch {
    fn launch(
        &mut self,
        task: TaskRef,
    ) -> Result<herness_sdd_execute::TaskLaunch, herness_sdd_execute::LaunchRefusal> {
        herness_sdd_execute::TaskLaunch::new(
            format!("immutable packet for Task {}", task.number().get()),
            scope(task.project_id()),
            BudgetPolicy::h2_default(),
            Sha256Digest::sha256(b"manifest"),
            Sha256Digest::sha256(b"packet"),
        )
        .map_err(|error| herness_sdd_execute::LaunchRefusal::Context {
            detail: error.to_string(),
        })
    }
}

struct NoDispatch {
    calls: usize,
}

impl herness_sdd_execute::ChildDispatchPort for NoDispatch {
    fn dispatch(
        &mut self,
        plan: &herness_sdd_execute::ChildDispatchPlan,
    ) -> Result<herness_sdd_execute::DispatchResult, SddExecutionError> {
        self.calls += 1;
        let project = plan.request().identity().project_id();
        herness_sdd_execute::DispatchResult::new(
            supervision(project, 0x5000),
            herness_sdd_execute::ChildIdentity::new(
                herness_core::AgentId::from_parts(project, Uuid::from_u128(0x7000)),
                herness_core::SessionId::from_parts(project, Uuid::from_u128(0x7001)),
            )
            .expect("child"),
        )
    }

    fn reconcile(
        &mut self,
        _project_id: ProjectId,
        _execution_id: ExecutionId,
        _request_id: herness_sdd_execute::DispatchRequestId,
    ) -> Result<Option<herness_sdd_execute::DispatchResult>, SddExecutionError> {
        Ok(None)
    }
}

#[derive(Default)]
struct NoChildren {
    scripted: Option<herness_sdd_execute::ChildStatus>,
}

impl herness_sdd_execute::ChildStatusPort for NoChildren {
    fn status(
        &mut self,
        _project_id: ProjectId,
        _execution_id: ExecutionId,
        _request_id: herness_sdd_execute::DispatchRequestId,
    ) -> Result<Option<herness_sdd_execute::ChildStatus>, SddExecutionError> {
        Ok(self.scripted.clone())
    }
}
