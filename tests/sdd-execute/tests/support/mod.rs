//! Synthetic H4 fixtures for the durable store tests.
//!
//! Every value is built through the public H4 API with a temporary project,
//! synthetic paths, and no real checkout, provider, or credential.

use std::path::PathBuf;

use herness_core::{AgentId, ConnectionId, ProjectId, SessionId, Timestamp};
use herness_sdd_execute::{
    AppliedRevision, ApprovalContent, ApprovalId, ApprovalSource, ApprovedCheck, ApprovedCondition,
    ApprovedDeliverable, ApprovedSpecRef, Baseline, BudgetConsumption, BudgetIncrement,
    ChildIdentity, CommitAuthorization, CommitPolicy, CommitRange, CommitRequestId, CommitSha,
    ConditionMode, ControlRequestId, DeliverableKind, DispatchContent, DispatchJournalEntry,
    DispatchManifest, DispatchRequest, DispatchRequestId, DispatchResult, ExactPlanBytes,
    ExecutionApproval, ExecutionConnection, ExecutionId, ExecutionOperation,
    ExecutionOperationRequest, ExecutionOperationResult, ExecutionRevision, ExecutionSnapshot,
    ExecutionState, GitCommitIntent, GitIdentity, GitJournalEntry, H2SupervisionRef,
    H3ApprovalBinding, InspectorProtocol, PackApproval, PackFingerprint, ParsedPlanSummary,
    ParsedPlanTask, PlanApproval, PlanByteRange, PlanDigest, PlanPath, PlanRevision, PreHookState,
    ProgressContent, ProgressJournalEntry, ProgressJournalId, ProgressTaskLine, RequestIdentity,
    Sha256Digest, SnapshotBudget, SnapshotInput, SnapshotPlan, SnapshotWorkspace, TaskApproval,
    TaskNumber, TaskPhase, TaskRef, TaskReservation, TaskSnapshot, TaskStableId, TreeSha,
    WorkspaceApproval,
};
use herness_supervision::{
    ApprovalActor, BudgetPolicy, ConsentBinding, ConsentId, ExecutionScope, ProfileBinding,
    ProfileId, ProfilePurpose, ProfileVersion, SupervisionId, TargetVersion,
};
use tempfile::TempDir;
use uuid::Uuid;

/// Fixed checkout path used by snapshots. It is never opened.
pub const CHECKOUT: &str = "/tmp/herness-h4-store-fixture";
pub const PLAN_PATH: &str = "docs/sdd/plans/2026-11-13-store-fixture.md";

pub fn project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap())
}

pub fn other_project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("10000000-0000-4000-8000-000000000002").unwrap())
}

pub fn execution(project_id: ProjectId) -> ExecutionId {
    ExecutionId::from_parts(
        project_id,
        Uuid::parse_str("20000000-0000-4000-8000-000000000001").unwrap(),
    )
}

pub fn other_execution(project_id: ProjectId) -> ExecutionId {
    ExecutionId::from_parts(
        project_id,
        Uuid::parse_str("20000000-0000-4000-8000-000000000002").unwrap(),
    )
}

pub fn plan_path() -> PlanPath {
    PlanPath::parse(PLAN_PATH).expect("plan path")
}

pub fn baseline() -> Baseline {
    Baseline::parse("a".repeat(40)).expect("baseline")
}

pub fn head() -> CommitSha {
    CommitSha::parse("b".repeat(40)).expect("head")
}

pub fn plan_revision() -> PlanRevision {
    PlanRevision::new(1).expect("plan revision")
}

pub fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::sha256(label.as_bytes())
}

pub fn task_ref(project_id: ProjectId, number: u32) -> TaskRef {
    TaskRef::new(
        TaskStableId::from_parts(
            project_id,
            Uuid::from_u128(0x3000_0000_0000_4000_8000_0000_0000_0000 + u128::from(number)),
        ),
        TaskNumber::new(number).expect("task number"),
    )
}

pub fn scope(project_id: ProjectId) -> ExecutionScope {
    ExecutionScope::new(
        project_id,
        vec!["crates".to_owned(), "docs".to_owned()],
        vec!["crates/herness-sdd-execute".to_owned()],
        true,
    )
    .expect("scope")
}

fn condition() -> ApprovedCondition {
    ApprovedCondition::new("c1", "condition", "rubric text", ConditionMode::Checks)
        .expect("condition")
}

fn check() -> ApprovedCheck {
    ApprovedCheck::new(
        "check-1",
        "c1",
        "run the check",
        "cargo test",
        ".",
        30,
        vec!["crates".to_owned()],
    )
    .expect("check")
}

fn spec_ref() -> ApprovedSpecRef {
    ApprovedSpecRef::new(
        "project",
        "docs/sdd/specs/2026-11-13-h4-sdd-execute-design.md",
        vec!["Durable state, plan changes and finish".to_owned()],
        digest("spec"),
    )
    .expect("spec ref")
}

fn task_approval(project_id: ProjectId, number: u32) -> TaskApproval {
    TaskApproval::new(
        task_ref(project_id, number),
        "first",
        vec![condition()],
        scope(project_id),
        vec![check()],
        vec!["docs/sdd/plans/2026-11-13-store-fixture.html".to_owned()],
        BudgetPolicy::new(600, 5, None).expect("budget"),
        CommitPolicy::Required,
        vec![
            ApprovedDeliverable::new(
                "crates/herness-sdd-execute/src/lib.rs",
                DeliverableKind::File,
            )
            .expect("deliverable"),
        ],
    )
    .expect("task approval")
}

pub fn approval(project_id: ProjectId) -> ExecutionApproval {
    approval_at(project_id, 1)
}

pub fn approval_at(project_id: ProjectId, revision: u64) -> ExecutionApproval {
    let approval_id = ApprovalId::from_parts(
        project_id,
        Uuid::parse_str("40000000-0000-4000-8000-000000000001").unwrap(),
    );
    let content = approval_content(project_id);
    if revision == 1 {
        return ExecutionApproval::new(
            approval_id,
            ApprovalActor::Human,
            ApprovalSource::ApprovalRegistry { approval_id },
            Timestamp::from_unix_millis(1_700_000_000_000),
            content,
        )
        .expect("approval");
    }
    approval(project_id)
        .revise(
            ApprovalActor::Human,
            ApprovalSource::ApprovalRegistry { approval_id },
            revision,
            Timestamp::from_unix_millis(1_700_000_000_000 + revision),
            content,
        )
        .expect("revised approval")
}

fn approval_content(project_id: ProjectId) -> ApprovalContent {
    let parsed = ParsedPlanSummary::new(
        1,
        exact_text("Global Constraints\n- keep"),
        vec![ParsedPlanTask::new(1, "first", exact_text("Task body")).expect("parsed task")],
        vec!["check-1".to_owned()],
    )
    .expect("parsed plan");
    let plan = PlanApproval::new(
        plan_path(),
        ExactPlanBytes::new(b"# plan".to_vec()).expect("plan bytes"),
        plan_revision(),
        parsed,
        vec![spec_ref()],
        Vec::new(),
        PackApproval::new(
            InspectorProtocol::expected(),
            1,
            PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).expect("fingerprint"),
        )
        .expect("pack approval"),
    )
    .expect("plan approval");
    let profile = ProfileBinding::new(
        ProfileId::new(project_id),
        ProfileVersion::new(1).expect("profile version"),
        ProfilePurpose::Completion,
    );
    let consent = ConsentBinding::new(
        ConsentId::new(project_id),
        1,
        ProfilePurpose::Completion,
        TargetVersion::new(1).expect("target version"),
    );
    ApprovalContent::new(
        plan,
        WorkspaceApproval::new(
            project_id,
            CHECKOUT,
            GitIdentity::new("herness", "host@example.test").expect("git identity"),
            "h4-store",
            "main",
            false,
            Some(baseline()),
        )
        .expect("workspace approval"),
        vec![task_approval(project_id, 1)],
        ExecutionConnection::new(ConnectionId::new(), profile, vec![consent]).expect("connection"),
        CommitAuthorization::new(true, true).expect("commit authorization"),
        H3ApprovalBinding::new(1, Vec::new(), vec!["html-sync".to_owned()]).expect("h3 binding"),
    )
    .expect("approval content")
}

pub fn exact_text(value: &str) -> herness_sdd_execute::ExactPlanText {
    herness_sdd_execute::ExactPlanText::new(
        value,
        PlanByteRange::new(0, value.len() as u64).expect("range"),
    )
    .expect("exact text")
}

pub fn task_snapshot(
    project_id: ProjectId,
    number: u32,
    phase: TaskPhase,
    h2: Option<H2SupervisionRef>,
    child: Option<ChildIdentity>,
) -> TaskSnapshot {
    TaskSnapshot::new(
        task_ref(project_id, number),
        phase.implied_progression(),
        phase,
        h2,
        child,
        CommitPolicy::Required,
        None,
        None,
        Vec::new(),
        None,
        AppliedRevision::current(plan_revision()),
    )
    .expect("task snapshot")
}

/// A ready snapshot at the given revision.
pub fn snapshot(
    project_id: ProjectId,
    execution_id: ExecutionId,
    revision: ExecutionRevision,
) -> ExecutionSnapshot {
    ExecutionSnapshot::new(SnapshotInput {
        project_id,
        execution_id,
        revision,
        state: ExecutionState::Ready,
        plan: SnapshotPlan::new(plan_path(), PlanDigest::sha256(b"# plan"), plan_revision()),
        workspace: SnapshotWorkspace::new(CHECKOUT, "h4-store", "main", Some(baseline()))
            .expect("snapshot workspace"),
        current_task: Some(task_ref(project_id, 1)),
        tasks: vec![task_snapshot(project_id, 1, TaskPhase::Ready, None, None)],
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: AppliedRevision::current(plan_revision()),
        final_project_sequence: None,
    })
    .expect("snapshot")
}

/// A running snapshot at the given revision, with an H2 reference and child.
pub fn running_snapshot(
    project_id: ProjectId,
    execution_id: ExecutionId,
    revision: ExecutionRevision,
    supervision_id: SupervisionId,
    child: ChildIdentity,
) -> ExecutionSnapshot {
    ExecutionSnapshot::new(SnapshotInput {
        project_id,
        execution_id,
        revision,
        state: ExecutionState::Running,
        plan: SnapshotPlan::new(plan_path(), PlanDigest::sha256(b"# plan"), plan_revision()),
        workspace: SnapshotWorkspace::new(CHECKOUT, "h4-store", "main", Some(baseline()))
            .expect("snapshot workspace"),
        current_task: Some(task_ref(project_id, 1)),
        tasks: vec![task_snapshot(
            project_id,
            1,
            TaskPhase::Running,
            Some(H2SupervisionRef::new(supervision_id)),
            Some(child),
        )],
        stop: None,
        budget: SnapshotBudget::new(
            BudgetConsumption::new(30, 1, None),
            BudgetConsumption::new(60, 2, None),
        ),
        applied_revision: AppliedRevision::current(plan_revision()),
        final_project_sequence: None,
    })
    .expect("running snapshot")
}

pub fn child(project_id: ProjectId) -> ChildIdentity {
    ChildIdentity::new(
        AgentId::from_parts(
            project_id,
            Uuid::parse_str("70000000-0000-4000-8000-000000000001").unwrap(),
        ),
        SessionId::from_parts(
            project_id,
            Uuid::parse_str("70000000-0000-4000-8000-000000000002").unwrap(),
        ),
    )
    .expect("child")
}

pub fn supervision(project_id: ProjectId) -> SupervisionId {
    SupervisionId::from_parts(
        project_id,
        Uuid::parse_str("50000000-0000-4000-8000-000000000001").unwrap(),
    )
}

pub fn dispatch_request_id(project_id: ProjectId) -> DispatchRequestId {
    DispatchRequestId::from_parts(
        project_id,
        Uuid::parse_str("60000000-0000-4000-8000-000000000001").unwrap(),
    )
}

pub fn commit_request_id(project_id: ProjectId) -> CommitRequestId {
    CommitRequestId::from_parts(
        project_id,
        Uuid::parse_str("60000000-0000-4000-8000-000000000002").unwrap(),
    )
}

pub fn progress_request_id(project_id: ProjectId) -> ProgressJournalId {
    ProgressJournalId::from_parts(
        project_id,
        Uuid::parse_str("60000000-0000-4000-8000-000000000003").unwrap(),
    )
}

pub fn control_request_id(project_id: ProjectId) -> ControlRequestId {
    ControlRequestId::from_parts(
        project_id,
        Uuid::parse_str("60000000-0000-4000-8000-000000000004").unwrap(),
    )
}

/// A second control request ID used to prove a new request is refused when its
/// expected revision is stale.
pub fn control_request_id_second(project_id: ProjectId) -> ControlRequestId {
    ControlRequestId::from_parts(
        project_id,
        Uuid::parse_str("60000000-0000-4000-8000-000000000005").unwrap(),
    )
}

pub fn dispatch_content(project_id: ProjectId) -> DispatchContent {
    DispatchContent::new(
        task_ref(project_id, 1),
        plan_revision(),
        baseline(),
        digest("manifest"),
        digest("packet"),
    )
    .expect("dispatch content")
}

pub fn dispatch_intent(
    project_id: ProjectId,
    execution_id: ExecutionId,
    expected: ExecutionRevision,
) -> DispatchJournalEntry {
    let identity = RequestIdentity::new(
        project_id,
        execution_id,
        dispatch_request_id(project_id),
        expected,
    )
    .expect("identity");
    let request = DispatchRequest::new(identity, dispatch_content(project_id)).expect("request");
    DispatchJournalEntry::intent(*request.identity(), request.content()).expect("dispatch intent")
}

pub fn dispatch_recorded(
    project_id: ProjectId,
    execution_id: ExecutionId,
    expected: ExecutionRevision,
) -> DispatchJournalEntry {
    dispatch_intent(project_id, execution_id, expected).recorded(
        DispatchResult::new(supervision(project_id), child(project_id)).expect("dispatch result"),
    )
}

pub fn git_intent(
    project_id: ProjectId,
    execution_id: ExecutionId,
    expected: ExecutionRevision,
) -> GitJournalEntry {
    let identity = RequestIdentity::new(
        project_id,
        execution_id,
        commit_request_id(project_id),
        expected,
    )
    .expect("identity");
    let intent = GitCommitIntent::new(
        task_ref(project_id, 1),
        "h4-store",
        baseline(),
        head(),
        Some(TreeSha::parse("c".repeat(40)).expect("tree")),
        vec![
            herness_sdd_execute::CommittedPath::new(
                "crates/herness-sdd-execute/src/lib.rs",
                128,
                Some(digest("file")),
            )
            .expect("path"),
        ],
        herness_sdd_execute::CommitMessage::new(
            task_ref(project_id, 1),
            "fixture commit",
            execution_id,
            commit_request_id(project_id),
            Vec::new(),
        )
        .expect("message"),
        PreHookState::new(
            true,
            vec!["crates/herness-sdd-execute/src/lib.rs".to_owned()],
            None,
            None,
        )
        .expect("pre hook"),
        30,
    )
    .expect("intent");
    GitJournalEntry::new(identity, intent).expect("git intent")
}

pub fn progress_content(project_id: ProjectId) -> ProgressContent {
    ProgressContent::new(
        ".sdd/progress.md",
        CHECKOUT,
        "h4-store",
        baseline(),
        vec![
            ProgressTaskLine::new(
                task_ref(project_id, 1),
                Some(CommitRange::new(baseline(), head()).expect("range")),
                false,
            )
            .expect("line"),
        ],
        vec!["fixture ruling".to_owned()],
        None,
        digest("progress document"),
    )
    .expect("progress content")
}

pub fn progress_intent(
    project_id: ProjectId,
    execution_id: ExecutionId,
    expected: ExecutionRevision,
) -> ProgressJournalEntry {
    let identity = RequestIdentity::new(
        project_id,
        execution_id,
        progress_request_id(project_id),
        expected,
    )
    .expect("identity");
    ProgressJournalEntry::new(identity, progress_content(project_id)).expect("progress intent")
}

pub fn operation_request(
    project_id: ProjectId,
    execution_id: ExecutionId,
    expected: ExecutionRevision,
    operation: ExecutionOperation,
) -> ExecutionOperationRequest {
    operation_request_with_id(
        project_id,
        execution_id,
        control_request_id(project_id),
        expected,
        operation,
    )
}

/// A control request with an explicit request ID.
pub fn operation_request_with_id(
    project_id: ProjectId,
    execution_id: ExecutionId,
    request_id: ControlRequestId,
    expected: ExecutionRevision,
    operation: ExecutionOperation,
) -> ExecutionOperationRequest {
    ExecutionOperationRequest::new(project_id, execution_id, request_id, expected, operation)
        .expect("operation request")
}

pub fn task_reservation(project_id: ProjectId, execution_id: ExecutionId) -> TaskReservation {
    TaskReservation::new(
        execution_id,
        task_ref(project_id, 1),
        dispatch_request_id(project_id),
        supervision(project_id),
        child(project_id),
    )
    .expect("reservation")
}

pub fn manifest(project_id: ProjectId, execution_id: ExecutionId) -> DispatchManifest {
    DispatchManifest::new(
        execution_id,
        dispatch_request_id(project_id),
        task_ref(project_id, 1),
        plan_revision(),
        baseline(),
        digest("manifest"),
        digest("packet"),
    )
    .expect("manifest")
}

pub fn increment(
    project_id: ProjectId,
    execution_id: ExecutionId,
    revision: ExecutionRevision,
) -> BudgetIncrement {
    BudgetIncrement::new(project_id, execution_id, revision, 42, 1, None).with_reserved(60, 2, None)
}

/// A temporary application-data root and store configuration.
pub struct Harness {
    _temp: TempDir,
    pub config: herness_store::StoreConfig,
}

impl Harness {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let config =
            herness_store::StoreConfig::new(temp.path().join("app-data")).expect("app data root");
        Self {
            _temp: temp,
            config,
        }
    }

    pub fn open(&self) -> herness_store::Store {
        herness_store::Store::open(self.config.clone()).expect("open store")
    }

    pub fn database_path(&self) -> PathBuf {
        self.config.database_path()
    }
}

/// One control result for a completed operation.
pub fn operation_result(
    operation: ExecutionOperation,
    snapshot: &ExecutionSnapshot,
) -> ExecutionOperationResult {
    ExecutionOperationResult::new(operation, snapshot.clone()).expect("operation result")
}
