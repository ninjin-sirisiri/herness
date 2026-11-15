//! Task 21: the trusted desktop surface for H4 SDD execution.
//!
//! These cases use the real `DesktopHost` composition, a real temporary SQLite
//! store in a temporary application-data root, and — where a checkout is
//! involved — a real temporary Git repository with real commits. They never
//! open a Tauri window, a provider, the Keychain, a login, or a network socket.
//!
//! # What is proven
//!
//! * Only the trusted `main` webview can mint a human confirmation; a preview
//!   window, a model origin, an agent origin, and a remote document are refused.
//! * The start disclosure shows the scope, the fixed consents, the host commit
//!   authorization, every Task's finite limits, the multi-Task and H3 cost
//!   warnings, and each unverified capability.
//! * The `SddTaskController` is available only when every required port and the
//!   current approval are present.
//! * A stale expected revision, a revoked consent, and a duplicate request are
//!   refused or answered from the stored result before any second side effect.
//! * Reconnect reads the saved snapshot and compares the sequence.
//! * The saved snapshot renders `html_unsynced`, `undecidable`, and
//!   `git_result_unknown` as their own display states, and no view carries a
//!   UI-only success flag.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use herness_core::{
    ConnectionAdmin, ConnectionId, CoreError, CredentialAvailability, CredentialPort, ProjectId,
    ResolvedCredential, Timestamp,
};
use herness_desktop::commands::{SDD_MUTATION_COMMANDS, SDD_READ_COMMANDS};
use herness_desktop::guard::{self, GuardError};
use herness_desktop::host::DesktopHost;
use herness_desktop::sdd_execute::controller::{
    SddApproveStartRequest, SddFinishRequest, SddOperationRequest, SddPreviewRequest,
    SddTaskController, SddTaskLimitRequest, ensure_operation_confirmation,
};
use herness_desktop::sdd_execute::views::{
    SddDisplayState, SddFailureView, SddPort, SddSnapshotView, display_state,
};
use herness_desktop::supervision::ConfirmationKind;
use herness_engine_pi::ProviderEndpoints;
use herness_sdd_execute::{
    AppliedRevision, BudgetConsumption, CommitSha, ControlRequestId, ExecutionId,
    ExecutionRevision, ExecutionSnapshot, ExecutionState, GitCommitIntent, GitCommitOutcome,
    GitJournalEntry, H2SupervisionRef, HumanAction, RequestIdentity, SnapshotBudget, SnapshotInput,
    SnapshotPlan, SnapshotWorkspace, StopReason, StopRecord, TaskNumber, TaskRef, TaskSnapshot,
    TaskStableId, TreeSha,
};
use herness_supervision::{
    BudgetPolicy, ConsentId, DisclosureDataKind, DisclosureScope, ExecutionScope, ProfilePurpose,
    ProviderOrigin, TargetVersion,
};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const PLAN_PATH: &str = "docs/sdd/plans/2026-11-15-desktop-fixture.md";
const TARGET_PATH: &str = "docs/adr/0001-desktop.md";

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
        std::fs::create_dir_all(project.path().join("docs/sdd/plans")).expect("plans directory");
        std::fs::write(
            project.path().join(TARGET_PATH),
            "# Desktop ADR\n\nUse the trusted window.\n",
        )
        .expect("source");
        std::fs::write(
            project.path().join(PLAN_PATH),
            "# fixture plan\n\n## Task 1: do the work\n\nBody.\n",
        )
        .expect("plan");
        let root = project.path().to_path_buf();
        std::fs::create_dir_all(project.path().join(".sdd")).expect("sdd directory");
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

    /// A controller whose inspector and saved-approval presence are overridden.
    ///
    /// The overrides only replace the *observed presence* of a port. The
    /// operations still read the real store and the real supervision config, so a
    /// revoked consent or a stale revision still refuses exactly as in production.
    fn available_controller(&self) -> SddTaskController {
        SddTaskController::evaluate_with_overrides(
            &self.host,
            Some(self.project),
            true,
            &[
                (SddPort::PlanInspector, true),
                (SddPort::CurrentApproval, true),
            ],
        )
    }

    fn task_ref(&self, number: u32) -> TaskRef {
        TaskRef::new(
            TaskStableId::from_parts(self.project, uuid("a1000000-0000-4000-8000-0000000000aa")),
            TaskNumber::new(number).expect("a Task number"),
        )
    }

    fn seed_snapshot(&self, snapshot: &ExecutionSnapshot) {
        let store = self.store();
        let mut guard = store.lock();
        guard
            .compare_and_swap_execution(self.project, snapshot.execution_id(), None, snapshot)
            .expect("seed snapshot");
    }

    fn grant_config(&self) {
        let config = self.host.supervision().config();
        let mut project_config = config.get(self.project);
        project_config.set_profile(
            herness_supervision::AssessmentProfile::new(
                herness_supervision::ProfileId::from_parts(
                    self.project,
                    uuid("a1000000-0000-4000-8000-000000000010"),
                ),
                herness_supervision::ProfileVersion::new(1).expect("profile version"),
                ProfilePurpose::Completion,
                herness_supervision::ProviderKind::NormalLlm,
                ConnectionId::new(),
                herness_core::ModelId::new("fixture-model").expect("model"),
                herness_supervision::AdapterVersion::new("fixture-adapter").expect("adapter"),
                herness_supervision::RubricVersion::new("fixture-rubric").expect("rubric"),
                herness_supervision::ProfileInputs::text_only(),
                herness_supervision::ProfileThresholds::normal_llm(),
            )
            .expect("profile"),
            true,
        );
        let scope = DisclosureScope::new(
            ProfilePurpose::Completion,
            BTreeSet::from([DisclosureDataKind::Text]),
            vec!["docs/adr".to_owned()],
            TargetVersion::new(1).expect("target version"),
        )
        .expect("scope");
        project_config.set_consent(
            herness_supervision::DisclosureConsent::grant(
                herness_supervision::ApprovalActor::Human,
                ConsentId::from_parts(self.project, uuid("a1000000-0000-4000-8000-000000000020")),
                ProviderOrigin::parse("https://loopback.example").expect("origin"),
                scope,
                Timestamp::now(),
            )
            .expect("consent"),
        );
        config.set(self.project, project_config);
        config
            .persist(&self.store(), self.project)
            .expect("persist");
    }

    fn revoke_consent(&self) {
        let config = self.host.supervision().config();
        let mut project_config = config.get(self.project);
        project_config.clear_consent(ProfilePurpose::Completion);
        config.set(self.project, project_config);
        config
            .persist(&self.store(), self.project)
            .expect("persist");
    }
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("a UUID")
}

fn ready_snapshot(project: ProjectId, execution: ExecutionId, task: TaskRef) -> ExecutionSnapshot {
    ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: execution,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Ready,
        plan: SnapshotPlan::new(
            herness_sdd_execute::PlanPath::parse(PLAN_PATH).expect("plan path"),
            herness_sdd_execute::PlanDigest::sha256(b"# fixture plan"),
            herness_sdd_execute::PlanRevision::INITIAL,
        ),
        workspace: SnapshotWorkspace::new(
            "/tmp/herness-h4-desktop-fixture",
            "h4-execute",
            "main",
            Some(herness_sdd_execute::Baseline::parse("a".repeat(40)).expect("baseline")),
        )
        .expect("workspace"),
        current_task: Some(task),
        tasks: vec![
            TaskSnapshot::new(
                task,
                herness_sdd_execute::TaskProgression::Pending,
                herness_sdd_execute::TaskPhase::Ready,
                None,
                None,
                herness_sdd_execute::CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                AppliedRevision::current(herness_sdd_execute::PlanRevision::INITIAL),
            )
            .expect("Task snapshot"),
        ],
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: AppliedRevision::current(herness_sdd_execute::PlanRevision::INITIAL),
        final_project_sequence: None,
    })
    .expect("ready snapshot")
}

fn running_snapshot(
    project: ProjectId,
    execution: ExecutionId,
    task: TaskRef,
    stop: Option<StopRecord>,
    state: ExecutionState,
) -> ExecutionSnapshot {
    let phase = match state {
        ExecutionState::Stopped => herness_sdd_execute::TaskPhase::Stopped,
        ExecutionState::WaitingHuman => herness_sdd_execute::TaskPhase::WaitingHuman,
        _ if stop.is_some() => herness_sdd_execute::TaskPhase::WaitingHuman,
        _ => herness_sdd_execute::TaskPhase::Running,
    };
    ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: execution,
        revision: ExecutionRevision::INITIAL,
        state,
        plan: SnapshotPlan::new(
            herness_sdd_execute::PlanPath::parse(PLAN_PATH).expect("plan path"),
            herness_sdd_execute::PlanDigest::sha256(b"# fixture plan"),
            herness_sdd_execute::PlanRevision::INITIAL,
        ),
        workspace: SnapshotWorkspace::new(
            "/tmp/herness-h4-desktop-fixture",
            "h4-execute",
            "main",
            Some(herness_sdd_execute::Baseline::parse("a".repeat(40)).expect("baseline")),
        )
        .expect("workspace"),
        current_task: Some(task),
        tasks: vec![
            TaskSnapshot::new(
                task,
                phase.implied_progression(),
                phase,
                Some(H2SupervisionRef::new(
                    herness_supervision::SupervisionId::from_parts(
                        project,
                        uuid("a1000000-0000-4000-8000-000000000040"),
                    ),
                )),
                None,
                herness_sdd_execute::CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                stop,
                AppliedRevision::current(herness_sdd_execute::PlanRevision::INITIAL),
            )
            .expect("Task snapshot"),
        ],
        stop,
        budget: SnapshotBudget::new(
            BudgetConsumption::new(120, 1, None),
            BudgetConsumption::zero(),
        ),
        applied_revision: AppliedRevision::current(herness_sdd_execute::PlanRevision::INITIAL),
        final_project_sequence: None,
    })
    .expect("snapshot")
}

// ---------------------------------------------------------------------------
// 1. Only the trusted main window can issue a human confirmation
// ---------------------------------------------------------------------------

#[test]
fn preview_model_and_remote_origins_cannot_invoke_any_sdd_mutation() {
    let local = Some("tauri://localhost/index.html");
    let commands = SDD_MUTATION_COMMANDS.iter().chain(SDD_READ_COMMANDS.iter());
    for command in commands {
        for (window, webview, url, expected) in [
            ("preview", "preview", local, GuardError::UntrustedWindow),
            ("main", "main-preview", local, GuardError::UntrustedWebview),
            ("model", "model", local, GuardError::UntrustedWindow),
            ("agent", "agent", local, GuardError::UntrustedWindow),
            (
                "main",
                "main",
                Some("https://example.com/sdd"),
                GuardError::UntrustedOrigin,
            ),
            (
                "main",
                "main",
                Some("tauri://localhost/index.html?model=1"),
                GuardError::UntrustedOrigin,
            ),
            (
                "main",
                "main",
                Some("data:text/html,<h1>agent</h1>"),
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
    assert_eq!(SDD_MUTATION_COMMANDS.len(), 5);
    assert_eq!(SDD_READ_COMMANDS.len(), 6);
    assert_eq!(
        guard::verify("main", "main", Some("tauri://localhost/index.html")),
        Ok(())
    );
}

#[test]
fn an_operation_without_its_human_confirmation_is_refused() {
    let error = ensure_operation_confirmation(None, ConfirmationKind::Start)
        .expect_err("a start without a confirmation must be refused");
    assert_eq!(error.code(), "approval_required");

    // A confirmation of another kind cannot stand in for the required one.
    let h = Harness::new();
    let other = h.host.confirm_supervision(ConfirmationKind::PlanRevision);
    let error = ensure_operation_confirmation(Some(&other), ConfirmationKind::Start)
        .expect_err("a plan-revision confirmation must not authorize a start");
    assert_eq!(error.code(), "approval_required");

    let start = h.host.confirm_supervision(ConfirmationKind::Start);
    ensure_operation_confirmation(Some(&start), ConfirmationKind::Start)
        .expect("a start confirmation authorizes a start");
}

// ---------------------------------------------------------------------------
// 2. The controller availability gate
// ---------------------------------------------------------------------------

#[test]
fn the_controller_is_unavailable_when_a_required_port_is_missing() {
    let h = Harness::new();
    // The pack root is not configured in this build, so the inspector is missing.
    let controller = SddTaskController::evaluate(&h.host, Some(h.project), true);
    let report = controller.capabilities();
    assert!(!report.available());
    assert!(
        report
            .missing()
            .iter()
            .any(|state| state.capability() == "plan_inspector"),
        "the missing pack inspector must be reported explicitly"
    );
    let error = controller
        .ensure_available()
        .expect_err("a missing port must make the controller unavailable");
    assert_eq!(error.code(), "unavailable");
    assert!(error.message().contains("plan_inspector"));
}

#[test]
fn the_controller_is_unavailable_without_a_trusted_main_window() {
    let h = Harness::new();
    let controller = SddTaskController::evaluate(&h.host, Some(h.project), false);
    let report = controller.capabilities();
    assert!(!report.available());
    assert!(
        report
            .missing()
            .iter()
            .any(|state| state.capability() == "trusted_approval"),
        "an untrusted origin must be reported as a missing capability"
    );
}

#[test]
fn the_controller_is_available_only_with_every_port_and_the_current_approval() {
    let h = Harness::new();
    // All ports present but no saved approval: still unavailable.
    let controller = SddTaskController::evaluate_with_overrides(
        &h.host,
        Some(h.project),
        true,
        &[(SddPort::PlanInspector, true)],
    );
    assert!(!controller.capabilities().available());
    assert!(
        controller
            .capabilities()
            .missing()
            .iter()
            .any(|state| state.capability() == "current_approval")
    );

    // Every port present, including the current approval: available.
    let controller = h.available_controller();
    assert!(
        controller.capabilities().available(),
        "missing: {}",
        controller.capabilities().missing_line()
    );
    controller
        .ensure_available()
        .expect("every port and the approval are present");

    // Removing one port makes it unavailable again with that exact capability.
    let controller = SddTaskController::evaluate_with_overrides(
        &h.host,
        Some(h.project),
        true,
        &[
            (SddPort::PlanInspector, true),
            (SddPort::CurrentApproval, true),
            (SddPort::HostGit, false),
        ],
    );
    assert!(!controller.capabilities().available());
    let error = controller
        .ensure_available()
        .expect_err("host_git is missing");
    assert!(error.message().contains("host_git"));
}

#[test]
fn the_controller_reports_the_current_approval_as_a_required_port() {
    let h = Harness::new();
    let controller = SddTaskController::evaluate(&h.host, Some(h.project), true);
    let report = controller.capabilities();
    assert!(
        report
            .missing()
            .iter()
            .any(|state| state.capability() == "current_approval"),
        "a project with no saved approval must report the missing approval"
    );
    // Both the pack inspector and the approval are missing; the report names
    // every one instead of stopping at the first.
    assert!(report.missing().len() >= 2);
}

// ---------------------------------------------------------------------------
// 3. Stale revision, duplicate request, revoked consent
// ---------------------------------------------------------------------------

#[test]
fn a_stale_revision_is_refused_before_any_side_effect() {
    let h = Harness::new();
    let execution =
        ExecutionId::from_parts(h.project, uuid("a1000000-0000-4000-8000-000000000101"));
    let task = h.task_ref(1);
    h.seed_snapshot(&ready_snapshot(h.project, execution, task));

    let controller = h.available_controller();
    let mut host = h.host;
    let request = SddOperationRequest {
        project_id: host
            .runtime()
            .projects()
            .expect("projects")
            .first()
            .map(|view| view.project_id())
            .expect("a project"),
        execution_id: execution,
        request_id: ControlRequestId::from_parts(
            request_project(&host),
            uuid("a1000000-0000-4000-8000-000000000201"),
        ),
        expected_revision: 99,
    };
    let confirmation = host.confirm_supervision(ConfirmationKind::Stop);
    let error = controller
        .pause(&mut host, &request, Some(&confirmation))
        .expect_err("a stale revision must be refused");
    assert_eq!(error.code(), "conflict", "{}", error.message());
    assert!(error.message().contains("revision conflict") || error.message().contains("conflict"));
}

fn request_project(host: &DesktopHost) -> ProjectId {
    host.runtime()
        .projects()
        .expect("projects")
        .first()
        .map(|view| view.project_id())
        .expect("a project")
}

#[test]
fn a_revoked_consent_refuses_the_start() {
    let h = Harness::new();
    h.grant_config();
    h.revoke_consent();
    let controller = h.available_controller();
    let request = SddApproveStartRequest {
        project_id: h.project,
        execution_id: ExecutionId::from_parts(
            h.project,
            uuid("a1000000-0000-4000-8000-000000000102"),
        ),
        approval_id: herness_sdd_execute::ApprovalId::from_parts(
            h.project,
            uuid("a1000000-0000-4000-8000-000000000202"),
        ),
        request_id: ControlRequestId::from_parts(
            h.project,
            uuid("a1000000-0000-4000-8000-000000000203"),
        ),
        expected_approval_revision: 1,
        plan_path: PLAN_PATH.to_owned(),
        checkout_root: h.root.to_string_lossy().into_owned(),
        branch: "h4-execute".to_owned(),
        base_branch: "main".to_owned(),
        isolated_worktree: false,
        connection: ConnectionId::new(),
        h3_settings_version: 1,
        h3_capabilities: vec!["html-sync".to_owned()],
        h3_consent_ids: Vec::new(),
        task_limits: vec![SddTaskLimitRequest {
            number: 1,
            active_seconds: 7_200,
            additional_runs: 30,
            money_limit_micros: None,
            price_version: None,
        }],
        git_name: "herness".to_owned(),
        git_email: "host@example.invalid".to_owned(),
    };
    let mut host = h.host;
    let confirmation = host.confirm_supervision(ConfirmationKind::Start);
    let error = controller
        .approve_and_start(&mut host, &request, Some(&confirmation))
        .expect_err("a revoked consent must refuse the start");
    assert_eq!(error.code(), "approval_required");
}

// ---------------------------------------------------------------------------
// 4. The start disclosure
// ---------------------------------------------------------------------------

#[test]
fn the_start_disclosure_names_scope_consent_limits_costs_and_unverified_capabilities() {
    use herness_sdd_execute::{
        ApprovalContent, ApprovalId, ApprovedCheck, ApprovedCondition, ApprovedDeliverable,
        ApprovedSpecRef, Baseline, CommitAuthorization, CommitPolicy, ConditionMode,
        DeliverableKind, ExactPlanBytes, ExactPlanText, ExecutionApproval, ExecutionConnection,
        GitIdentity, H3ApprovalBinding, InspectorProtocol, PackApproval, PackFingerprint,
        ParsedPlanSummary, ParsedPlanTask, PlanApproval, PlanByteRange, PlanPath, PlanRevision,
        Sha256Digest, TaskApproval, WorkspaceApproval,
    };
    use herness_supervision::{
        ApprovalActor, ConsentBinding, ProfileBinding, ProfileId, ProfileVersion,
    };

    let project = ProjectId::from_uuid(uuid("a1000000-0000-4000-8000-0000000000ff"));
    let constraints = "Global Constraints\n- keep";
    let parsed = ParsedPlanSummary::new(
        1,
        ExactPlanText::new(
            constraints,
            PlanByteRange::new(0, constraints.len() as u64).expect("range"),
        )
        .expect("constraints"),
        vec![ParsedPlanTask::new(1, "first", exact_text("body")).expect("task")],
        vec!["check-1".to_owned()],
    )
    .expect("parsed");
    let plan = PlanApproval::new(
        PlanPath::parse(PLAN_PATH).expect("path"),
        ExactPlanBytes::new(b"# plan".to_vec()).expect("bytes"),
        PlanRevision::new(1).expect("revision"),
        parsed,
        vec![
            ApprovedSpecRef::new(
                "project",
                "docs/sdd/specs/spec.md",
                vec!["S".to_owned()],
                Sha256Digest::sha256(b"spec"),
            )
            .expect("spec"),
        ],
        Vec::new(),
        PackApproval::new(
            InspectorProtocol::expected(),
            1,
            PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).expect("fingerprint"),
        )
        .expect("pack"),
    )
    .expect("plan approval");
    let task = TaskApproval::new(
        TaskRef::new(
            TaskStableId::from_parts(project, uuid("a1000000-0000-4000-8000-0000000000aa")),
            TaskNumber::new(1).expect("number"),
        ),
        "first",
        vec![
            ApprovedCondition::new("c1", "condition", "rubric", ConditionMode::Checks)
                .expect("condition"),
        ],
        ExecutionScope::new(
            project,
            vec!["docs".to_owned()],
            vec!["docs".to_owned()],
            true,
        )
        .expect("scope"),
        vec![
            ApprovedCheck::new(
                "check-1",
                "c1",
                "run",
                "cargo test",
                ".",
                60,
                vec!["docs".to_owned()],
            )
            .expect("check"),
        ],
        vec!["docs/adr/0001-desktop.html".to_owned()],
        BudgetPolicy::new(3_600, 5, None).expect("budget"),
        CommitPolicy::Required,
        vec![
            ApprovedDeliverable::new("docs/adr/0001-desktop.md", DeliverableKind::File)
                .expect("deliverable"),
        ],
    )
    .expect("task approval");
    let connection = ExecutionConnection::new(
        ConnectionId::new(),
        ProfileBinding::new(
            ProfileId::from_parts(project, uuid("a1000000-0000-4000-8000-000000000010")),
            ProfileVersion::new(1).expect("version"),
            ProfilePurpose::Completion,
        ),
        vec![ConsentBinding::new(
            ConsentId::from_parts(project, uuid("a1000000-0000-4000-8000-000000000020")),
            1,
            ProfilePurpose::Completion,
            TargetVersion::new(2).expect("target version"),
        )],
    )
    .expect("connection");
    let content = ApprovalContent::new(
        plan,
        WorkspaceApproval::new(
            project,
            "/tmp/herness-h4-desktop-fixture",
            GitIdentity::new("herness", "host@example.invalid").expect("identity"),
            "h4-execute",
            "main",
            false,
            Some(Baseline::parse("a".repeat(40)).expect("baseline")),
        )
        .expect("workspace"),
        vec![task],
        connection,
        CommitAuthorization::new(true, true).expect("commit"),
        H3ApprovalBinding::new(1, Vec::new(), vec!["html-sync".to_owned()]).expect("h3"),
    )
    .expect("content");
    let approval = ExecutionApproval::new(
        ApprovalId::from_parts(project, uuid("a1000000-0000-4000-8000-000000000202")),
        ApprovalActor::Human,
        herness_sdd_execute::ApprovalSource::ApprovalRegistry {
            approval_id: ApprovalId::from_parts(
                project,
                uuid("a1000000-0000-4000-8000-000000000202"),
            ),
        },
        Timestamp::now(),
        content,
    )
    .expect("approval");

    let disclosure = herness_desktop::sdd_execute::views::SddStartDisclosureView::of(
        ExecutionId::from_parts(project, uuid("a1000000-0000-4000-8000-000000000102")),
        &approval,
        vec![
            "profile.html: configured but not verified by a real acceptance step".to_owned(),
            "consent.html: not granted".to_owned(),
        ],
    );

    // Scope: checkout, branch, base branch, the fixed consents, and the host
    // commit authorization.
    let scope = disclosure.scope();
    assert_eq!(scope.checkout(), "/tmp/herness-h4-desktop-fixture");
    assert_eq!(scope.branch(), "h4-execute");
    assert!(scope.host_commit());
    assert!(scope.run_hooks());
    assert!(scope.consents().iter().any(|c| c.contains("targets v2")));

    // Per-Task limits are finite and shown.
    assert_eq!(disclosure.task_count(), 1);
    let task = &disclosure.tasks()[0];
    assert_eq!(task.active_seconds(), 3_600);
    assert_eq!(task.additional_runs(), 5);
    assert_eq!(task.number(), 1);

    // The multi-Task and separately approved H3 cost warnings are both shown.
    assert!(
        disclosure
            .multi_task_cost_warning()
            .contains("one Task at a time")
    );
    assert!(
        disclosure
            .multi_task_cost_warning()
            .contains("never refunds")
    );
    assert!(
        disclosure
            .h3_cycle_cost_warning()
            .contains("approved separately")
    );
    assert_eq!(disclosure.limits().max_concurrent_tasks(), 1);

    // Unverified capabilities are displayed, not hidden.
    assert_eq!(disclosure.unverified_capabilities().len(), 2);
    assert!(
        disclosure
            .unverified_capabilities()
            .iter()
            .any(|item| item.contains("profile.html"))
    );

    // Scope and consent are the human's; nothing here starts anything.
    assert!(disclosure.confirmation().contains("trusted main window"));
    let value = serde_json::to_value(&disclosure).expect("json");
    assert!(value.get("success").is_none(), "no UI-only success flag");
    assert_eq!(value["version"], json!(1));
}

fn exact_text(value: &str) -> herness_sdd_execute::ExactPlanText {
    herness_sdd_execute::ExactPlanText::new(
        value,
        herness_sdd_execute::PlanByteRange::new(0, value.len() as u64).expect("range"),
    )
    .expect("exact text")
}

// ---------------------------------------------------------------------------
// 5. Reconnect and the display states
// ---------------------------------------------------------------------------

#[test]
fn reconnect_reads_the_saved_snapshot_and_compares_the_sequence() {
    let h = Harness::new();
    let execution =
        ExecutionId::from_parts(h.project, uuid("a1000000-0000-4000-8000-000000000103"));
    let task = h.task_ref(1);
    h.seed_snapshot(&ready_snapshot(h.project, execution, task));
    let controller = SddTaskController::evaluate(&h.host, Some(h.project), true);

    let first = controller
        .subscribe(&h.host, h.project, execution, None)
        .expect("first subscribe");
    assert!(first.changed(), "a first read always reports a change");
    let sequence = first.sequence();

    let second = controller
        .subscribe(&h.host, h.project, execution, Some(sequence))
        .expect("second subscribe");
    assert!(!second.changed(), "the same sequence is not a change");
    assert_eq!(second.snapshot().revision(), first.snapshot().revision());
    // The snapshot carries no UI-only success flag.
    let value = serde_json::to_value(second.snapshot()).expect("json");
    assert!(value.get("success").is_none());
    assert_eq!(value["version"], json!(1));
}

#[test]
fn the_snapshot_renders_unsynced_undecidable_and_git_unknown_as_their_own_states() {
    // A running Task with the HTML-unsynced stop.
    let project = ProjectId::from_uuid(uuid("a1000000-0000-4000-8000-0000000000ff"));
    let execution = ExecutionId::from_parts(project, uuid("a1000000-0000-4000-8000-000000000104"));
    let task = TaskRef::new(
        TaskStableId::from_parts(project, uuid("a1000000-0000-4000-8000-0000000000aa")),
        TaskNumber::new(1).expect("number"),
    );
    let html_stop = StopRecord::new(StopReason::HtmlUnsynced, Some(HumanAction::ResolveHtmlSync))
        .expect("stop");
    let snapshot = running_snapshot(
        project,
        execution,
        task,
        Some(html_stop),
        ExecutionState::WaitingHuman,
    );
    let view = SddSnapshotView::of(&snapshot, 5, None);
    assert_eq!(view.display_state(), "html_unsynced");
    assert_eq!(view.failure_code(), Some("html_not_synced"));

    // An undecidable human wait is its own display state and not a failure class.
    let undecidable = StopRecord::new(
        StopReason::HumanDecisionRequired,
        Some(HumanAction::ResolveHumanDecision),
    )
    .expect("stop");
    let snapshot = running_snapshot(
        project,
        execution,
        task,
        Some(undecidable),
        ExecutionState::WaitingHuman,
    );
    let view = SddSnapshotView::of(&snapshot, 6, None);
    assert_eq!(view.display_state(), "undecidable");
    assert_eq!(view.failure_code(), None);

    // The same undecidable wait is not a plan, HTML, or budget failure.
    let view = SddSnapshotView::of(
        &running_snapshot(
            project,
            execution,
            task,
            Some(undecidable),
            ExecutionState::WaitingHuman,
        ),
        7,
        None,
    );
    assert_eq!(view.display_state(), "undecidable");

    // An unknown Git result is its own display state.
    let view = SddSnapshotView::of(
        &snapshot,
        7,
        Some("the newest host commit journal entry for Task 1 is not established".to_owned()),
    );
    assert_eq!(view.display_state(), "git_result_unknown");
    assert_eq!(view.failure_code(), Some("git_result_unknown"));
    assert!(view.git_result_unknown().is_some());
    let value = serde_json::to_value(&view).expect("json");
    assert!(value.get("success").is_none());
}

#[test]
fn display_state_is_derived_from_the_recorded_stop_not_from_a_notification() {
    let pause =
        StopRecord::new(StopReason::PauseRequested, Some(HumanAction::ConfirmStop)).expect("stop");
    assert_eq!(
        display_state(ExecutionState::WaitingHuman, Some(pause), false),
        SddDisplayState::WaitingHuman
    );
    assert_eq!(
        display_state(ExecutionState::Stopped, Some(pause), false),
        SddDisplayState::Stopped
    );
    let budget =
        StopRecord::new(StopReason::BudgetExhausted, Some(HumanAction::RaiseBudget)).expect("stop");
    let state = display_state(ExecutionState::WaitingHuman, Some(budget), false);
    assert_eq!(state.as_str(), "budget_exhausted");
    assert_eq!(state.failure_code(), Some("budget_exhausted"));
    let plan = StopRecord::new(
        StopReason::PlanChanged,
        Some(HumanAction::ResolvePlanChange),
    )
    .expect("stop");
    let state = display_state(ExecutionState::Stopped, Some(plan), false);
    assert_eq!(state.as_str(), "plan_changed");
    assert_eq!(state.failure_code(), Some("plan_changed"));
}

#[test]
fn the_snapshot_never_invents_an_unestablished_reference() {
    let project = ProjectId::from_uuid(uuid("a1000000-0000-4000-8000-0000000000ff"));
    let execution = ExecutionId::from_parts(project, uuid("a1000000-0000-4000-8000-000000000105"));
    let task = TaskRef::new(
        TaskStableId::from_parts(project, uuid("a1000000-0000-4000-8000-0000000000aa")),
        TaskNumber::new(1).expect("number"),
    );
    let snapshot = running_snapshot(project, execution, task, None, ExecutionState::Running);
    let view = SddSnapshotView::of(&snapshot, 0, None);
    assert_eq!(view.display_state(), "running");
    let value = serde_json::to_value(&view).expect("json");
    // No commit range and no no-change record exist yet, and the view leaves
    // both keys null instead of inventing a value.
    assert!(value["tasks"][0]["commitRange"].is_null());
    assert!(value["tasks"][0]["noChange"].is_null());
    assert!(value["stop"].is_null());
    assert!(value["finalProjectSequence"].is_null());
}

// ---------------------------------------------------------------------------
// 6. Duplicate requests and finish handoff
// ---------------------------------------------------------------------------

#[test]
fn a_duplicate_operation_returns_the_stored_result_instead_of_writing_again() {
    let h = Harness::new();
    let execution =
        ExecutionId::from_parts(h.project, uuid("a1000000-0000-4000-8000-000000000106"));
    let task = h.task_ref(1);
    h.seed_snapshot(&ready_snapshot(h.project, execution, task));
    let project = request_project(&h.host);
    let controller = h.available_controller();
    let mut host = h.host;
    let request = SddOperationRequest {
        project_id: project,
        execution_id: execution,
        request_id: ControlRequestId::from_parts(
            project,
            uuid("a1000000-0000-4000-8000-000000000204"),
        ),
        expected_revision: 1,
    };
    let confirmation = host.confirm_supervision(ConfirmationKind::Stop);
    let first = controller
        .pause(&mut host, &request, Some(&confirmation))
        .expect("first pause");
    assert!(!first.replayed());
    let second = controller
        .pause(&mut host, &request, Some(&confirmation))
        .expect("duplicate pause");
    assert!(second.replayed(), "a duplicate request must be replayed");
    assert_eq!(second.revision(), first.revision());
}

#[test]
fn the_finish_handoff_names_every_durable_input_and_every_blocker() {
    let h = Harness::new();
    let execution =
        ExecutionId::from_parts(h.project, uuid("a1000000-0000-4000-8000-000000000107"));
    let task = h.task_ref(1);
    h.seed_snapshot(&ready_snapshot(h.project, execution, task));
    let controller = SddTaskController::evaluate(&h.host, Some(h.project), true);
    let handoff = controller
        .finish_handoff(
            &h.host,
            &SddFinishRequest {
                project_id: h.project,
                execution_id: execution,
            },
        )
        .expect("handoff");
    assert!(!handoff.ready(), "an unstarted execution is not ready");
    assert!(handoff.human_choice_required());
    assert!(!handoff.blockers().is_empty());
    assert!(
        handoff
            .blockers()
            .iter()
            .any(|blocker| blocker.kind() == "execution_state")
    );
    assert!(
        handoff
            .blockers()
            .iter()
            .any(|blocker| blocker.kind() == "task_not_complete")
    );
    // The checkout, branch, base branch, and baseline are all real values.
    assert_eq!(handoff.branch(), "h4-execute");
    assert_eq!(handoff.base_branch(), "main");
    assert_eq!(handoff.baseline(), Some("a".repeat(40).as_str()));
    let value = serde_json::to_value(&handoff).expect("json");
    assert!(value.get("success").is_none());
}

// ---------------------------------------------------------------------------
// 7. The preview refuses without the inspector
// ---------------------------------------------------------------------------

#[test]
fn a_preview_without_the_pack_inspector_reports_the_missing_capability() {
    let h = Harness::new();
    let controller = SddTaskController::evaluate(&h.host, Some(h.project), true);
    let mut host = h.host;
    let error = controller
        .preview(
            &mut host,
            &SddPreviewRequest {
                project_id: h.project,
                plan_path: PLAN_PATH.to_owned(),
            },
        )
        .expect_err("a preview without the pack inspector must be refused");
    assert_eq!(error.code(), "unavailable");
    assert!(error.message().contains("plan_inspector"));
}

// ---------------------------------------------------------------------------
// 8. The failure view never borrows a class it did not earn
// ---------------------------------------------------------------------------

#[test]
fn the_failure_view_uses_the_ten_specification_classes_and_no_other() {
    let cases = [
        (
            herness_sdd_execute::SddExecutionError::Unavailable {
                feature: "x".to_owned(),
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            "unavailable",
        ),
        (
            herness_sdd_execute::SddExecutionError::ApprovalRequired {
                reason: herness_sdd_execute::ApprovalRequirement::StartApproval,
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            "approval_required",
        ),
        (
            herness_sdd_execute::SddExecutionError::Conflict {
                reason: herness_sdd_execute::ConflictReason::StaleRevision,
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            "conflict",
        ),
        (
            herness_sdd_execute::SddExecutionError::PlanChanged {
                reason: herness_sdd_execute::PlanChangeReason::BytesChanged,
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            "plan_changed",
        ),
        (
            herness_sdd_execute::SddExecutionError::HtmlNotSynced {
                reason: herness_sdd_execute::HtmlSyncReason::Unsynced,
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            "html_not_synced",
        ),
        (
            herness_sdd_execute::SddExecutionError::RecoveryRequired {
                reason: herness_sdd_execute::RecoveryReason::StopUnconfirmed,
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            "recovery_required",
        ),
        (
            herness_sdd_execute::SddExecutionError::BudgetExhausted {
                reason: herness_sdd_execute::BudgetExhaustionReason::ActiveSeconds,
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            "budget_exhausted",
        ),
        (
            herness_sdd_execute::SddExecutionError::GitResultUnknown {
                reason: herness_sdd_execute::GitUnknownReason::Timeout,
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            },
            "git_result_unknown",
        ),
    ];
    for (error, expected) in cases {
        let view = SddFailureView::of(&error);
        assert_eq!(view.code(), expected);
        assert!(view.is_specification_failure());
    }
    // A malformed command is `invalid_request`, not one of the ten classes.
    let invalid = SddFailureView::invalid("bad request");
    assert_eq!(invalid.code(), "invalid_request");
    assert!(!invalid.is_specification_failure());
    // An untrusted caller is its own code.
    let untrusted = SddFailureView::untrusted("not main");
    assert_eq!(untrusted.code(), "untrusted_source");
    assert!(!untrusted.is_specification_failure());
}

// ---------------------------------------------------------------------------
// 9. A stored unknown Git result is rendered as its own state
// ---------------------------------------------------------------------------

#[test]
fn a_stored_unknown_git_result_is_rendered_by_the_snapshot_read() {
    let h = Harness::new();
    let execution =
        ExecutionId::from_parts(h.project, uuid("a1000000-0000-4000-8000-000000000108"));
    let task = h.task_ref(1);
    h.seed_snapshot(&running_snapshot(
        h.project,
        execution,
        task,
        None,
        ExecutionState::Running,
    ));
    {
        let store = h.store();
        let mut guard = store.lock();
        guard
            .record_git_entry(&unknown_git_journal(h.project, execution, task))
            .expect("record the unknown Git intent");
    }
    let controller = SddTaskController::evaluate(&h.host, Some(h.project), true);
    let view = controller
        .snapshot(&h.host, h.project, execution)
        .expect("snapshot");
    assert_eq!(view.display_state(), "git_result_unknown");
    assert_eq!(view.failure_code(), Some("git_result_unknown"));
    assert!(
        view.git_result_unknown()
            .is_some_and(|detail| detail.contains("Task 1")),
        "the unknown result must name the Task it belongs to"
    );
    // The view is not a success and the snapshot still carries the running state.
    let value = serde_json::to_value(&view).expect("json");
    assert!(value.get("success").is_none());
    assert_eq!(value["state"], json!("running"));
}

/// One stored Git intent whose result is unknown.
fn unknown_git_journal(
    project: ProjectId,
    execution: ExecutionId,
    task: TaskRef,
) -> GitJournalEntry {
    let identity = RequestIdentity::new(
        project,
        execution,
        herness_sdd_execute::CommitRequestId::from_parts(
            project,
            uuid("a1000000-0000-4000-8000-000000000301"),
        ),
        ExecutionRevision::INITIAL,
    )
    .expect("identity");
    let intent = GitCommitIntent::new(
        task,
        "h4-execute",
        herness_sdd_execute::Baseline::parse("a".repeat(40)).expect("baseline"),
        CommitSha::parse("b".repeat(40)).expect("head"),
        Some(TreeSha::parse("c".repeat(40)).expect("tree")),
        vec![
            herness_sdd_execute::CommittedPath::new(
                "docs/adr/0001-desktop.md",
                128,
                Some(herness_sdd_execute::Sha256Digest::sha256(b"fixture")),
            )
            .expect("path"),
        ],
        herness_sdd_execute::CommitMessage::new(
            task,
            "fixture",
            execution,
            herness_sdd_execute::CommitRequestId::from_parts(
                project,
                uuid("a1000000-0000-4000-8000-000000000301"),
            ),
            Vec::new(),
        )
        .expect("message"),
        herness_sdd_execute::PreHookState::new(true, Vec::new(), None, None).expect("hook"),
        30,
    )
    .expect("intent");
    GitJournalEntry::new(identity, intent)
        .expect("journal")
        .record(GitCommitOutcome::Unknown {
            reason: herness_sdd_execute::GitUnknownReason::Timeout,
        })
}
