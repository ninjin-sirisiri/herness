//! H4 contract tests: typed identity, states, approvals, snapshots, journals,
//! and the absence of a reverse dependency from H1/H2/H3 crates.

use herness_core::{AgentId, ConnectionId, InputId, ProjectId, RunId, SessionId, Timestamp};
use herness_sdd_execute::{
    ApprovalContent, ApprovalRejection, ApprovalSource, ApprovalSourceKind, ApprovedCheck,
    ApprovedCondition, ApprovedDeliverable, ApprovedSpecRef, Baseline, BudgetConsumption,
    CheckoutClaim, ChildIdentity, CommitAuthorization, CommitMessage, CommitPolicy, CommitRange,
    CommitRequestId, CommitSha, CommitTrailer, CommittedPath, ConditionMode, ContinuationLimits,
    Delegation, DeliverableKind, DispatchContent, DispatchJournalEntry, DispatchRequest,
    DispatchResult, ExecutionApproval, ExecutionConnection, ExecutionId, ExecutionOperation,
    ExecutionOperationRequest, ExecutionRevision, ExecutionSnapshot, ExecutionState,
    ExecutionStorePort, ExternalSourceApproval, FailureCode, GitCommitIntent, GitCommitOutcome,
    GitIdentity, GitJournalEntry, GitJournalState, GitUnknownReason, H2SupervisionRef,
    H3ApprovalBinding, H4Barrier, HostExecutionContract, HumanAction, JournalContent,
    NoChangeRecord, PackApproval, PackFingerprint, ParsedPlanSummary, ParsedPlanTask, PlanApproval,
    PlanByteRange, PlanDiagnostic, PlanDiagnosticCode, PlanDigest, PlanPath, PlanRevision,
    PreHookState, ProgressContent, ProgressJournalEntry, ProgressJournalState, ProgressTaskLine,
    RequestDecision, RequestIdentity, RequestRecord, SddExecutionError, Sha256Digest,
    SnapshotBudget, SnapshotInput, SnapshotPlan, SnapshotWorkspace, StopReason, StopRecord,
    TaskApproval, TaskNumber, TaskPhase, TaskProgression, TaskRef, TaskSnapshot, TaskStableId,
    TreeSha, WorkspaceApproval, decide_request, ensure_supported_version, validate_project_path,
};
use herness_supervision::{
    ApprovalActor, BudgetPolicy, ConsentBinding, ConsentId, ExecutionScope, ProfileBinding,
    ProfileId, ProfilePurpose, ProfileVersion, SupervisionId, TargetVersion,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CHECKOUT: &str = "/tmp/herness-h4-checkout";

fn digest_a() -> Sha256Digest {
    Sha256Digest::sha256(b"approved bytes")
}

fn plan_path() -> PlanPath {
    PlanPath::parse("docs/sdd/plans/2026-11-13-example.md").expect("plan path")
}

fn git_identity() -> GitIdentity {
    GitIdentity::new("herness", "host@example.test").expect("git identity")
}

fn condition(id: &str) -> ApprovedCondition {
    ApprovedCondition::new(id, "condition", "rubric text", ConditionMode::Checks)
        .expect("condition")
}

fn check(task_condition: &str) -> ApprovedCheck {
    ApprovedCheck::new(
        "check-1",
        task_condition,
        "run the check",
        "cargo test",
        ".",
        30,
        vec!["crates".to_owned()],
    )
    .expect("check")
}

fn scope(project_id: ProjectId) -> ExecutionScope {
    ExecutionScope::new(
        project_id,
        vec!["crates".to_owned(), "docs".to_owned()],
        vec!["crates/herness-sdd-execute".to_owned()],
        true,
    )
    .expect("scope")
}

fn task_ref(project_id: ProjectId, number: u32) -> TaskRef {
    TaskRef::new(
        TaskStableId::new(project_id),
        TaskNumber::new(number).expect("task number"),
    )
}

fn spec_ref() -> ApprovedSpecRef {
    ApprovedSpecRef::new(
        "project",
        "docs/sdd/specs/2026-11-13-h4-sdd-execute-design.md",
        vec!["Approach and architecture".to_owned()],
        digest_a(),
    )
    .expect("spec ref")
}

fn parsed_plan(tasks: &[(u32, &str)]) -> ParsedPlanSummary {
    let parsed_tasks = tasks
        .iter()
        .map(|(number, title)| {
            ParsedPlanTask::new(*number, *title, ExactPlanTextFixture::text("Task body"))
                .expect("parsed task")
        })
        .collect();
    ParsedPlanSummary::new(
        1,
        ExactPlanTextFixture::text("Global Constraints\n- keep"),
        parsed_tasks,
        vec!["check-1".to_owned()],
    )
    .expect("parsed plan")
}

/// Local helper so the fixture reads naturally at each call site.
struct ExactPlanTextFixture;

impl ExactPlanTextFixture {
    fn text(value: &str) -> herness_sdd_execute::ExactPlanText {
        herness_sdd_execute::ExactPlanText::new(
            value,
            PlanByteRange::new(0, value.len() as u64).expect("range"),
        )
        .expect("exact text")
    }
}

fn task_approval(project_id: ProjectId, number: u32, title: &str) -> TaskApproval {
    task_approval_for(task_ref(project_id, number), title)
}

fn task_approval_for(task: TaskRef, title: &str) -> TaskApproval {
    let project_id = task.project_id();
    TaskApproval::new(
        task,
        title,
        vec![condition("c1")],
        scope(project_id),
        vec![check("c1")],
        vec!["docs/sdd/plans/2026-11-13-example.html".to_owned()],
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

fn approval_content_for_refs(project_id: ProjectId, tasks: &[(TaskRef, &str)]) -> ApprovalContent {
    let plan = PlanApproval::new(
        plan_path(),
        herness_sdd_execute::ExactPlanBytes::new(b"plan".to_vec()).expect("plan bytes"),
        PlanRevision::new(1).expect("plan revision"),
        parsed_plan(
            &tasks
                .iter()
                .map(|(task, title)| (task.number().get(), *title))
                .collect::<Vec<_>>(),
        ),
        vec![spec_ref()],
        Vec::new(),
        PackApproval::new(
            herness_sdd_execute::InspectorProtocol::expected(),
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
            git_identity(),
            "h4-exec",
            "main",
            true,
            None,
        )
        .expect("workspace approval"),
        tasks
            .iter()
            .map(|(task, title)| task_approval_for(*task, title))
            .collect(),
        ExecutionConnection::new(ConnectionId::new(), profile, vec![consent]).expect("connection"),
        CommitAuthorization::new(true, true).expect("commit authorization"),
        H3ApprovalBinding::new(1, Vec::new(), vec!["html-sync".to_owned()]).expect("h3 binding"),
    )
    .expect("approval content")
}

fn approval_content(project_id: ProjectId, tasks: &[(u32, &str)]) -> ApprovalContent {
    let plan = PlanApproval::new(
        plan_path(),
        herness_sdd_execute::ExactPlanBytes::new(b"plan".to_vec()).expect("plan bytes"),
        PlanRevision::new(1).expect("plan revision"),
        parsed_plan(tasks),
        vec![spec_ref()],
        Vec::new(),
        PackApproval::new(
            herness_sdd_execute::InspectorProtocol::expected(),
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
            git_identity(),
            "h4-exec",
            "main",
            true,
            None,
        )
        .expect("workspace approval"),
        tasks
            .iter()
            .map(|(number, title)| task_approval(project_id, *number, title))
            .collect(),
        ExecutionConnection::new(ConnectionId::new(), profile, vec![consent]).expect("connection"),
        CommitAuthorization::new(true, true).expect("commit authorization"),
        H3ApprovalBinding::new(1, Vec::new(), vec!["html-sync".to_owned()]).expect("h3 binding"),
    )
    .expect("approval content")
}

fn approval(project_id: ProjectId, tasks: &[(u32, &str)]) -> ExecutionApproval {
    let approval_id = herness_sdd_execute::ApprovalId::new(project_id);
    ExecutionApproval::new(
        approval_id,
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry { approval_id },
        Timestamp::from_unix_millis(1_700_000_000_000),
        approval_content(project_id, tasks),
    )
    .expect("approval")
}

fn task_snapshot(project_id: ProjectId, number: u32, phase: TaskPhase) -> TaskSnapshot {
    TaskSnapshot::new(
        task_ref(project_id, number),
        phase.implied_progression(),
        phase,
        None,
        None,
        CommitPolicy::Required,
        None,
        None,
        Vec::new(),
        None,
        herness_sdd_execute::AppliedRevision::current(PlanRevision::new(1).expect("plan revision")),
    )
    .expect("task snapshot")
}

fn snapshot(
    project_id: ProjectId,
    state: ExecutionState,
    tasks: Vec<TaskSnapshot>,
) -> ExecutionSnapshot {
    ExecutionSnapshot::new(SnapshotInput {
        project_id,
        execution_id: ExecutionId::new(project_id),
        revision: ExecutionRevision::INITIAL,
        state,
        plan: SnapshotPlan::new(
            plan_path(),
            PlanDigest::sha256(b"plan"),
            PlanRevision::new(1).expect("plan revision"),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, "h4-exec", "main", None)
            .expect("snapshot workspace"),
        current_task: None,
        tasks,
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: herness_sdd_execute::AppliedRevision::current(
            PlanRevision::new(1).expect("plan revision"),
        ),
        final_project_sequence: None,
    })
    .expect("snapshot")
}

// ---------------------------------------------------------------------------
// Identity: every execution identity is a distinct type
// ---------------------------------------------------------------------------

#[test]
fn execution_identities_are_distinct_types() {
    let project = ProjectId::new();
    let execution = ExecutionId::new(project);
    let task = TaskStableId::new(project);
    let dispatch = herness_sdd_execute::DispatchRequestId::new(project);
    let commit = CommitRequestId::new(project);
    let progress = herness_sdd_execute::ProgressJournalId::new(project);
    let control = herness_sdd_execute::ControlRequestId::new(project);

    // Each value round-trips through its own kind prefix only.
    assert!(execution.to_string().starts_with("execution:"));
    assert!(task.to_string().starts_with("task:"));
    assert!(dispatch.to_string().starts_with("dispatch:"));
    assert!(commit.to_string().starts_with("commit:"));
    assert!(progress.to_string().starts_with("progress:"));
    assert!(control.to_string().starts_with("control:"));

    // A parsed value of one kind cannot parse as another kind.
    let execution_text = execution.to_string();
    assert!(
        execution_text
            .parse::<herness_sdd_execute::DispatchRequestId>()
            .is_err()
    );
    assert!(execution_text.parse::<ExecutionId>().is_ok());
    assert!(dispatch.to_string().parse::<CommitRequestId>().is_err());

    // H1 run, input, session, agent and H2 supervision values are not H4 Task
    // identity and are rejected by H4's own parsers.
    let run = RunId::new(project);
    let input = InputId::new(project);
    let agent = AgentId::new(project);
    let session = SessionId::new(project);
    let supervision = SupervisionId::new(project);
    for foreign in [
        run.to_string(),
        input.to_string(),
        agent.to_string(),
        session.to_string(),
        supervision.to_string(),
    ] {
        assert!(foreign.parse::<TaskStableId>().is_err());
        assert!(foreign.parse::<ExecutionId>().is_err());
    }
}

#[test]
fn h1_and_h2_references_cannot_become_task_progress() {
    let project = ProjectId::new();
    let supervision = SupervisionId::new(project);
    let reference = H2SupervisionRef::new(supervision);
    assert_eq!(reference.supervision_id(), supervision);

    let child = ChildIdentity::new(AgentId::new(project), SessionId::new(project)).expect("child");
    let run =
        herness_sdd_execute::RunInputRef::new(RunId::new(project), Some(InputId::new(project)))
            .expect("run ref");
    assert!(run.input_id().is_some());

    // An H2 target alone cannot produce a complete Task snapshot: completion
    // requires a commit range or a no_change record.
    let error = TaskSnapshot::new(
        task_ref(project, 1),
        TaskProgression::Complete,
        TaskPhase::Complete,
        Some(reference),
        Some(child),
        CommitPolicy::Required,
        None,
        None,
        Vec::new(),
        None,
        herness_sdd_execute::AppliedRevision::current(PlanRevision::new(1).expect("revision")),
    )
    .expect_err("H2 reference must not complete a Task");
    assert!(matches!(
        error,
        SddExecutionError::InvalidSnapshot { ref field, .. } if field == "task.commitRange"
    ));
}

#[test]
fn h1_run_states_and_h2_states_are_not_h4_task_state() {
    // No `From`/`Into` conversion exists between H1 run states, H2 supervision
    // states, and H4 Task phases. This test compiles only because H4 keeps its
    // own types; the labels below are disjoint where reuse would be ambiguous.
    use herness_core::RunState;
    use herness_supervision::SupervisionState;

    let h4_labels: Vec<&str> = TaskPhase::ALL.iter().map(|phase| phase.as_str()).collect();
    // H1 `idle` and `awaiting_approval`, and H2 `assessing`/`completed` have no
    // H4 Task phase with the same meaning.
    for label in ["idle", "awaiting_approval", "paused", "interrupted"] {
        assert!(RunState::ALL.iter().any(|state| state.as_str() == label));
        assert!(
            !h4_labels.contains(&label),
            "H1 {label} must not be an H4 phase"
        );
    }
    assert!(
        SupervisionState::ALL
            .iter()
            .any(|state| state.as_str() == "completed")
    );
    assert!(!h4_labels.contains(&"assessing"));

    // H4 `complete` is its own value: an H2 completed record cannot be turned
    // into it, and the only constructor is the H4 phase.
    assert!(h4_labels.contains(&"complete"));
    assert_ne!(
        TaskProgression::Complete.as_str(),
        SupervisionState::Completed.as_str()
    );
    assert_ne!(TaskProgression::Active.as_str(), RunState::Running.as_str());
}

#[test]
fn cross_project_identifiers_are_rejected() {
    let project = ProjectId::new();
    let other = ProjectId::new();
    let foreign_execution = ExecutionId::new(other);
    assert!(matches!(
        foreign_execution.validate_in(project),
        Err(SddExecutionError::CrossProjectReference { .. })
    ));

    let error = ExecutionOperationRequest::new(
        project,
        foreign_execution,
        herness_sdd_execute::ControlRequestId::new(project),
        ExecutionRevision::INITIAL,
        ExecutionOperation::Pause,
    )
    .expect_err("foreign execution must be rejected");
    assert!(matches!(
        error,
        SddExecutionError::CrossProjectReference { .. }
    ));

    // A Task reference from another project cannot be used in an approval.
    let error = TaskApproval::new(
        task_ref(other, 1),
        "title",
        vec![condition("c1")],
        scope(project),
        vec![check("c1")],
        Vec::new(),
        BudgetPolicy::new(60, 1, None).expect("budget"),
        CommitPolicy::Required,
        Vec::new(),
    )
    .expect_err("foreign Task must be rejected");
    assert!(matches!(
        error,
        SddExecutionError::CrossProjectReference { .. }
    ));
}

#[test]
fn git_object_names_and_revisions_are_typed() {
    let project = ProjectId::new();
    let baseline = Baseline::parse("a".repeat(40)).expect("baseline");
    let head = CommitSha::parse("b".repeat(40)).expect("head");
    assert_eq!(baseline.short(), "aaaaaaa");
    assert_eq!(head.short(), "bbbbbbb");

    // A 7-character short name is not a full baseline and is refused.
    assert!(Baseline::parse("aaaaaaa").is_err());
    // A non-hex value is refused.
    assert!(Baseline::parse("z".repeat(40)).is_err());

    // A revision of zero is not a revision.
    assert!(ExecutionRevision::new(0).is_err());
    assert!(PlanRevision::new(0).is_err());
    assert!(TaskNumber::new(0).is_err());
    assert_eq!(ExecutionRevision::INITIAL.get(), 1);
    assert_eq!(ExecutionRevision::INITIAL.next().get(), 2);
    let _ = project;
}

// ---------------------------------------------------------------------------
// Version: unknown versions are refused, never read with current rules
// ---------------------------------------------------------------------------

#[test]
fn unknown_contract_version_is_a_typed_error() {
    assert!(ensure_supported_version(1).is_ok());
    let error = ensure_supported_version(2).expect_err("version 2 is not implemented");
    match error {
        SddExecutionError::UnsupportedContractVersion { found, expected } => {
            assert_eq!(found, 2);
            assert_eq!(expected, 1);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    // JSON decoding of an unknown contract version fails instead of defaulting.
    assert!(serde_json::from_str::<herness_sdd_execute::ExecutionContractVersion>("1").is_ok());
    let decode = serde_json::from_str::<herness_sdd_execute::ExecutionContractVersion>("9");
    assert!(decode.is_err());

    // A snapshot whose stored contract version is unknown fails to decode.
    let project = ProjectId::new();
    let mut value = serde_json::to_value(snapshot(
        project,
        ExecutionState::Ready,
        vec![task_snapshot(project, 1, TaskPhase::Ready)],
    ))
    .expect("snapshot json");
    value["contractVersion"] = serde_json::json!(3);
    assert!(serde_json::from_value::<ExecutionSnapshot>(value).is_err());
}

#[test]
fn unknown_plan_schema_and_inspector_protocol_are_refused() {
    let error = PackApproval::new(
        herness_sdd_execute::InspectorProtocol::new("sdd-plan-inspect", 2).expect("protocol"),
        1,
        PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).expect("fingerprint"),
    )
    .expect_err("unknown inspector version must be refused");
    assert!(matches!(
        error,
        SddExecutionError::UnsupportedInspectorProtocol { .. }
    ));

    let error = herness_sdd_execute::InspectorCapabilities::new(
        herness_sdd_execute::InspectorProtocol::expected(),
        "sdd-execution-plan",
        2,
        "sdd-execution-v1",
        2 * 1024 * 1024,
        "docs/sdd/plans/",
        PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).expect("fingerprint"),
    )
    .expect_err("unknown plan schema version must be refused");
    match error {
        SddExecutionError::UnsupportedPlanSchemaVersion { found, expected } => {
            assert_eq!((found, expected), (2, 1));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn plan_diagnostics_stay_distinct_from_availability() {
    let unsupported = PlanDiagnostic::new(
        PlanDiagnosticCode::UnsupportedPlanFormat,
        "no execution block",
        None,
        Some(PlanByteRange::new(0, 12).expect("range")),
    )
    .expect("diagnostic");
    assert_eq!(unsupported.code().as_str(), "unsupported_plan_format");

    let invalid = PlanDiagnostic::new(
        PlanDiagnosticCode::InvalidPlan,
        "duplicate key",
        Some("/tasks/0".to_owned()),
        None,
    )
    .expect("diagnostic");
    assert_eq!(invalid.code().as_str(), "invalid_plan");

    let error = SddExecutionError::InvalidPlan {
        diagnostic: invalid,
        details: herness_sdd_execute::FailureDetails::none().boxed(),
    };
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));
    assert_eq!(FailureCode::InvalidPlan.as_str(), "invalid_plan");

    // The ten failure classes are all reachable and distinct.
    let codes = [
        FailureCode::UnsupportedPlanFormat,
        FailureCode::InvalidPlan,
        FailureCode::Unavailable,
        FailureCode::ApprovalRequired,
        FailureCode::Conflict,
        FailureCode::PlanChanged,
        FailureCode::HtmlNotSynced,
        FailureCode::RecoveryRequired,
        FailureCode::BudgetExhausted,
        FailureCode::GitResultUnknown,
    ];
    let mut labels: Vec<&str> = codes.iter().map(|code| code.as_str()).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), 10);
}

#[test]
fn failure_details_can_carry_h1_h2_and_h3_references_without_fabrication() {
    let project = ProjectId::new();
    let details = herness_sdd_execute::FailureDetails::none()
        .with_h1(herness_sdd_execute::H1DetailRef::Run {
            run_id: RunId::new(project),
        })
        .with_h2(herness_sdd_execute::H2DetailRef::Supervision {
            supervision_id: SupervisionId::new(project),
        });
    assert!(details.h1().is_some());
    assert!(details.h2().is_some());
    // An H3 reference is absent, not invented.
    assert!(details.h3().is_none());

    // A reference with no H3 fact at all is refused instead of fabricated.
    assert!(herness_sdd_execute::H3DetailRef::new(None, None, None).is_err());
    let h3 = herness_sdd_execute::H3DetailRef::new(None, Some(4), None).expect("h3 detail");
    assert_eq!(h3.source_revision(), Some(4));
}

// ---------------------------------------------------------------------------
// States and phases: legal and refused transitions
// ---------------------------------------------------------------------------

#[test]
fn legal_execution_transitions_are_accepted() {
    let legal = [
        (ExecutionState::Preview, ExecutionState::Ready),
        (ExecutionState::Ready, ExecutionState::Running),
        (ExecutionState::Running, ExecutionState::WaitingHtml),
        (ExecutionState::WaitingHtml, ExecutionState::Verifying),
        (ExecutionState::Verifying, ExecutionState::Committing),
        (ExecutionState::Committing, ExecutionState::Running),
        (ExecutionState::Committing, ExecutionState::ReadyForFinish),
        (ExecutionState::Running, ExecutionState::WaitingHuman),
        (ExecutionState::WaitingHuman, ExecutionState::Running),
        (ExecutionState::Running, ExecutionState::Stopping),
        (ExecutionState::Stopping, ExecutionState::Stopped),
        (ExecutionState::Stopped, ExecutionState::Running),
        (ExecutionState::WaitingHuman, ExecutionState::Cancelled),
        (ExecutionState::Ready, ExecutionState::Failed),
    ];
    for (from, to) in legal {
        assert!(from.can_transition_to(to), "{from} should allow {to}");
        assert_eq!(from.transition_to(to).expect("legal transition"), to);
    }
}

#[test]
fn illegal_execution_transitions_are_refused_with_a_type() {
    let illegal = [
        // A preview is never running before approval.
        (ExecutionState::Preview, ExecutionState::Running),
        // A commit cannot complete without the verified barrier.
        (ExecutionState::Ready, ExecutionState::Committing),
        // A finished execution never returns to running.
        (ExecutionState::ReadyForFinish, ExecutionState::Running),
        // Terminal states never restart.
        (ExecutionState::Failed, ExecutionState::Running),
        (ExecutionState::Cancelled, ExecutionState::Running),
        // A stop is confirmed before it resumes.
        (ExecutionState::Stopping, ExecutionState::Running),
        // A wait is never skipped by jumping straight to finish.
        (ExecutionState::WaitingHuman, ExecutionState::ReadyForFinish),
    ];
    for (from, to) in illegal {
        assert!(!from.can_transition_to(to), "{from} should refuse {to}");
        let error = from
            .transition_to(to)
            .expect_err("illegal transition must be refused");
        match error {
            SddExecutionError::IllegalStateTransition {
                from: ref found_from,
                to: ref found_to,
            } => {
                assert_eq!(found_from, from.as_str());
                assert_eq!(found_to, to.as_str());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
fn task_phase_and_progression_agree_and_refuse_illegal_moves() {
    assert_eq!(
        TaskPhase::Ready.implied_progression(),
        TaskProgression::Pending
    );
    assert_eq!(
        TaskPhase::Running.implied_progression(),
        TaskProgression::Active
    );
    assert_eq!(
        TaskPhase::Complete.implied_progression(),
        TaskProgression::Complete
    );

    let legal = [
        (TaskPhase::Ready, TaskPhase::Running),
        (TaskPhase::Running, TaskPhase::WaitingHtml),
        (TaskPhase::WaitingHtml, TaskPhase::Verifying),
        (TaskPhase::Verifying, TaskPhase::Committing),
        (TaskPhase::Committing, TaskPhase::Complete),
        (TaskPhase::Running, TaskPhase::WaitingHuman),
        (TaskPhase::WaitingHuman, TaskPhase::Running),
        (TaskPhase::Running, TaskPhase::Stopping),
        (TaskPhase::Stopping, TaskPhase::Stopped),
        (TaskPhase::Stopped, TaskPhase::Running),
    ];
    for (from, to) in legal {
        assert_eq!(from.transition_to(to).expect("legal Task move"), to);
    }

    let illegal = [
        (TaskPhase::Ready, TaskPhase::Complete),
        (TaskPhase::Ready, TaskPhase::Committing),
        (TaskPhase::Complete, TaskPhase::Running),
        (TaskPhase::Failed, TaskPhase::Running),
        (TaskPhase::Cancelled, TaskPhase::Complete),
        (TaskPhase::Stopping, TaskPhase::Running),
        (TaskPhase::WaitingHuman, TaskPhase::Complete),
    ];
    for (from, to) in illegal {
        assert!(from.transition_to(to).is_err(), "{from} should refuse {to}");
    }

    // A snapshot refuses a progression that disagrees with its phase.
    let project = ProjectId::new();
    let error = TaskSnapshot::new(
        task_ref(project, 1),
        TaskProgression::Complete,
        TaskPhase::Running,
        None,
        None,
        CommitPolicy::Required,
        None,
        None,
        Vec::new(),
        None,
        herness_sdd_execute::AppliedRevision::current(PlanRevision::new(1).expect("revision")),
    )
    .expect_err("progression must agree with phase");
    assert!(matches!(
        error,
        SddExecutionError::InvalidSnapshot { ref field, .. } if field == "task.progression"
    ));
}

#[test]
fn stops_require_the_human_action_they_name() {
    let stop = StopRecord::new(StopReason::PlanChanged, None)
        .expect_err("a plan change needs a human action");
    assert!(matches!(stop, SddExecutionError::InvalidValue { .. }));

    let stop = StopRecord::new(
        StopReason::PlanChanged,
        Some(HumanAction::ResolvePlanChange),
    )
    .expect("plan change stop");
    assert_eq!(stop.reason(), StopReason::PlanChanged);
    assert_eq!(stop.required_action(), Some(HumanAction::ResolvePlanChange));

    // A pause needs no human action.
    assert_eq!(StopReason::PauseRequested.default_required_action(), None);
    assert_eq!(
        StopReason::BudgetExhausted.default_required_action(),
        Some(HumanAction::RaiseBudget)
    );
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

#[test]
fn only_the_registry_and_a_human_can_approve() {
    let project = ProjectId::new();
    let approval_id = herness_sdd_execute::ApprovalId::new(project);
    let content = approval_content(project, &[(1, "First")]);

    for forbidden in [
        ApprovalSourceKind::EnvironmentVariable,
        ApprovalSourceKind::DocumentDeclaration,
        ApprovalSourceKind::HtmlMeta,
        ApprovalSourceKind::Receipt,
        ApprovalSourceKind::RequestActor,
        ApprovalSourceKind::OwnerKind,
        ApprovalSourceKind::ModelRequest,
        ApprovalSourceKind::H3Approval,
    ] {
        assert!(!forbidden.is_accepted());
    }
    assert!(ApprovalSourceKind::ApprovalRegistry.is_accepted());

    let rejected = [
        ApprovalSource::EnvironmentVariable {
            name: "SDD_APPROVED".to_owned(),
        },
        ApprovalSource::DocumentDeclaration {
            path: "docs/approved.md".to_owned(),
        },
        ApprovalSource::HtmlMeta {
            path: "docs/page.html".to_owned(),
        },
        ApprovalSource::Receipt {
            reference: "receipt-1".to_owned(),
        },
        ApprovalSource::RequestActor {
            reference: "request-actor".to_owned(),
        },
        ApprovalSource::OwnerKind {
            reference: "ApprovedOwner".to_owned(),
        },
        ApprovalSource::ModelRequest {
            reference: "model-request-1".to_owned(),
        },
        ApprovalSource::H3Approval {
            approval_id: "h3-approval-1".to_owned(),
        },
    ];
    for source in rejected {
        let kind = source.kind();
        let error = ExecutionApproval::new(
            approval_id,
            ApprovalActor::Human,
            source,
            Timestamp::from_unix_millis(1),
            content.clone(),
        )
        .expect_err("non-registry source must be rejected");
        match error {
            SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::ForbiddenSource { source: found },
            } => assert_eq!(found, kind),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // A model actor and an owner-kind actor are not human approval.
    for actor in [
        ApprovalActor::Model,
        ApprovalActor::ApprovedOwner {
            owner: herness_supervision::OwnerRef::new(
                herness_supervision::OwnerKind::H4SddTask,
                "task-1",
            )
            .expect("owner ref"),
            source: herness_supervision::OwnerApprovalSource::H4ApprovedPlan,
        },
    ] {
        let error = ExecutionApproval::new(
            approval_id,
            actor,
            ApprovalSource::ApprovalRegistry { approval_id },
            Timestamp::from_unix_millis(1),
            content.clone(),
        )
        .expect_err("non-human actor must be rejected");
        assert!(matches!(
            error,
            SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::ActorNotHuman { .. }
            }
        ));
    }

    let approval = approval(project, &[(1, "First")]);
    assert!(approval.is_human());
    assert!(approval.is_registry());
    assert_eq!(approval.revision(), 1);
}

#[test]
fn approval_revision_advances_and_old_revision_cannot_be_rewritten() {
    let project = ProjectId::new();
    let first = approval(project, &[(1, "First")]);
    let content = approval_content(project, &[(1, "First")]);

    let error = first
        .revise(
            ApprovalActor::Human,
            first.source().clone(),
            1,
            Timestamp::from_unix_millis(2),
            content.clone(),
        )
        .expect_err("a revision must strictly increase");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::RevisionNotAdvanced { .. }
        }
    ));

    let second = first
        .revise(
            ApprovalActor::Human,
            first.source().clone(),
            2,
            Timestamp::from_unix_millis(2),
            content,
        )
        .expect("revised approval");
    assert_eq!(second.revision(), 2);
    assert_eq!(second.approval_id(), first.approval_id());
    assert_eq!(first.revision(), 1, "the old revision is unchanged");
}

#[test]
fn approval_rejects_inconsistent_task_contracts() {
    let project = ProjectId::new();

    // A checks-mode condition needs at least one check.
    let error = TaskApproval::new(
        task_ref(project, 1),
        "title",
        vec![condition("c1")],
        scope(project),
        Vec::new(),
        Vec::new(),
        BudgetPolicy::new(60, 1, None).expect("budget"),
        CommitPolicy::Required,
        Vec::new(),
    )
    .expect_err("checks mode needs a check");
    assert!(matches!(error, SddExecutionError::InvalidValue { .. }));

    // A check must name a condition in the same Task.
    let error = TaskApproval::new(
        task_ref(project, 1),
        "title",
        vec![condition("c1")],
        scope(project),
        vec![check("other")],
        Vec::new(),
        BudgetPolicy::new(60, 1, None).expect("budget"),
        CommitPolicy::Required,
        Vec::new(),
    )
    .expect_err("dangling check must be refused");
    assert!(matches!(error, SddExecutionError::InvalidValue { .. }));

    // no_change requires an empty write scope and no deliverables.
    let error = TaskApproval::new(
        task_ref(project, 1),
        "title",
        vec![condition("c1")],
        scope(project),
        vec![check("c1")],
        Vec::new(),
        BudgetPolicy::new(60, 1, None).expect("budget"),
        CommitPolicy::NoChange,
        Vec::new(),
    )
    .expect_err("no_change needs an empty write scope");
    assert!(matches!(error, SddExecutionError::InvalidValue { .. }));

    // An approval cannot exceed the fixed H2 continuation limits.
    let error = TaskApproval::new(
        task_ref(project, 1),
        "title",
        vec![condition("c1")],
        ExecutionScope::new(project, vec!["crates".to_owned()], Vec::new(), false).expect("scope"),
        vec![check("c1")],
        Vec::new(),
        BudgetPolicy::new(7_201, 1, None).expect("budget"),
        CommitPolicy::NoChange,
        Vec::new(),
    )
    .expect_err("the H2 time limit cannot be raised");
    assert!(matches!(error, SddExecutionError::InvalidValue { .. }));

    // Host commit and hooks are not optional.
    assert!(CommitAuthorization::new(false, true).is_err());
    assert!(CommitAuthorization::new(true, false).is_err());
    assert!(CommitAuthorization::new(true, true).is_ok());
}

#[test]
fn another_projects_approval_cannot_be_applied() {
    let project = ProjectId::new();
    let other = ProjectId::new();
    let task = task_ref(project, 1);
    let view = ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: ExecutionId::new(project),
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Ready,
        plan: SnapshotPlan::new(
            plan_path(),
            PlanDigest::sha256(b"plan"),
            PlanRevision::new(1).expect("plan revision"),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, "h4-exec", "main", None)
            .expect("snapshot workspace"),
        current_task: None,
        tasks: vec![
            TaskSnapshot::new(
                task,
                TaskProgression::Pending,
                TaskPhase::Ready,
                None,
                None,
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(
                    PlanRevision::new(1).expect("plan revision"),
                ),
            )
            .expect("task snapshot"),
        ],
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: herness_sdd_execute::AppliedRevision::current(
            PlanRevision::new(1).expect("plan revision"),
        ),
        final_project_sequence: None,
    })
    .expect("snapshot");

    // Another project's approval is refused even when every other shape
    // matches.
    let foreign = approval(other, &[(1, "First")]);
    assert!(matches!(
        view.ensure_approval_applies(&foreign)
            .expect_err("another project's approval must be refused"),
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::OtherProject
        }
    ));

    // The same project, plan digest, revision, workspace, and Task identities
    // apply.
    let approval_id = herness_sdd_execute::ApprovalId::new(project);
    let own = ExecutionApproval::new(
        approval_id,
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry { approval_id },
        Timestamp::from_unix_millis(1),
        approval_content_for_refs(project, &[(task, "First")]),
    )
    .expect("own approval");
    assert!(view.ensure_approval_applies(&own).is_ok());

    // A different plan digest is refused.
    let mismatched = ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: ExecutionId::new(project),
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Ready,
        plan: SnapshotPlan::new(
            plan_path(),
            PlanDigest::sha256(b"different plan bytes"),
            PlanRevision::new(1).expect("plan revision"),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, "h4-exec", "main", None)
            .expect("snapshot workspace"),
        current_task: None,
        tasks: vec![
            TaskSnapshot::new(
                task,
                TaskProgression::Pending,
                TaskPhase::Ready,
                None,
                None,
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(
                    PlanRevision::new(1).expect("plan revision"),
                ),
            )
            .expect("task snapshot"),
        ],
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: herness_sdd_execute::AppliedRevision::current(
            PlanRevision::new(1).expect("plan revision"),
        ),
        final_project_sequence: None,
    })
    .expect("snapshot");
    assert!(matches!(
        mismatched
            .ensure_approval_applies(&own)
            .expect_err("digest mismatch must be refused"),
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::PlanDigestMismatch { .. }
        }
    ));

    // A different approved plan revision is refused.
    let mut moved_revision = own.clone();
    let content = approval_content_for_refs(project, &[(task, "First")]);
    let plan = PlanApproval::new(
        plan_path(),
        herness_sdd_execute::ExactPlanBytes::new(b"plan".to_vec()).expect("plan bytes"),
        PlanRevision::new(2).expect("plan revision"),
        parsed_plan(&[(1, "First")]),
        vec![spec_ref()],
        Vec::new(),
        PackApproval::new(
            herness_sdd_execute::InspectorProtocol::expected(),
            1,
            PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).expect("fingerprint"),
        )
        .expect("pack approval"),
    )
    .expect("plan approval");
    let revised = ApprovalContent::new(
        plan,
        content.workspace().clone(),
        content.tasks().to_vec(),
        content.connection().clone(),
        content.commit(),
        content.h3().clone(),
    )
    .expect("revised content");
    moved_revision = moved_revision
        .revise(
            ApprovalActor::Human,
            moved_revision.source().clone(),
            2,
            Timestamp::from_unix_millis(2),
            revised,
        )
        .expect("revised approval");
    assert!(matches!(
        view.ensure_approval_applies(&moved_revision)
            .expect_err("plan revision mismatch must be refused"),
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::PlanRevisionMismatch { .. }
        }
    ));
}

#[test]
fn approval_binds_the_spec_required_fields() {
    let project = ProjectId::new();
    let approval = approval(project, &[(1, "First"), (2, "Second")]);

    // Plan bytes, digest, parsed result, and Global Constraints text.
    assert_eq!(approval.plan().byte_length(), 4);
    assert_eq!(approval.plan().digest(), &PlanDigest::sha256(b"plan"));
    assert_eq!(approval.plan().parsed().tasks().len(), 2);
    assert!(
        approval
            .plan()
            .parsed()
            .global_constraints()
            .text()
            .contains("Global Constraints")
    );
    // Spec and pack fingerprints.
    assert_eq!(approval.plan().spec_refs().len(), 1);
    assert!(
        approval
            .plan()
            .pack()
            .execution_contract()
            .as_str()
            .starts_with("sha256:")
    );
    // Checkout, Git identity, branch, base branch.
    assert_eq!(approval.workspace().canonical_checkout_root(), CHECKOUT);
    assert_eq!(approval.workspace().git_identity().author_name(), "herness");
    assert_eq!(approval.workspace().branch(), "h4-exec");
    assert_eq!(approval.workspace().base_branch(), "main");
    // Per-Task conditions, scope, checks, HTML targets, finite budget.
    let task = &approval.tasks()[0];
    assert_eq!(task.conditions().len(), 1);
    assert_eq!(task.checks().len(), 1);
    assert_eq!(task.html_targets().len(), 1);
    assert_eq!(task.budget().active_seconds(), 600);
    assert_eq!(task.budget().additional_runs(), 5);
    // Connection, H2 profile, per-purpose consent.
    assert_eq!(
        approval.connection().profile().purpose(),
        ProfilePurpose::Completion
    );
    assert_eq!(approval.connection().consents().len(), 1);
    // Host commit, hooks, H3 settings, consent, capabilities.
    assert!(approval.commit().host_commit());
    assert!(approval.commit().run_hooks());
    assert_eq!(approval.h3().settings_version(), 1);
}

#[test]
fn approved_plan_bytes_are_exact_and_round_trip() {
    let source = "## Global Constraints\n- 原文を保持\n".as_bytes().to_vec();
    let bytes = herness_sdd_execute::ExactPlanBytes::new(source.clone()).expect("bytes");
    assert_eq!(bytes.source(), source.as_slice());
    assert_eq!(bytes.byte_length(), source.len() as u64);
    assert_eq!(bytes.digest(), &PlanDigest::sha256(&source));

    // The wire form is the standard base64 the inspector uses for
    // `sourceBase64`, so the exact UTF-8 bytes survive a JSON round trip.
    let json = serde_json::to_string(&bytes).expect("serialize");
    assert_eq!(
        json,
        "\"IyMgR2xvYmFsIENvbnN0cmFpbnRzCi0g5Y6f5paH44KS5L+d5oyBCg==\""
    );
    let decoded: herness_sdd_execute::ExactPlanBytes =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, bytes);

    // A claimed digest that does not match the bytes is refused instead of
    // trusted.
    assert!(
        herness_sdd_execute::ExactPlanBytes::verify(
            source.clone(),
            PlanDigest::sha256(b"other bytes"),
        )
        .is_err()
    );
    assert!(herness_sdd_execute::ExactPlanBytes::new(Vec::new()).is_err());

    // Bytes above the plan limit are refused, not truncated.
    let oversized = vec![b'x'; herness_sdd_execute::MAX_PLAN_BYTES as usize + 1];
    assert!(herness_sdd_execute::ExactPlanBytes::new(oversized).is_err());
}

#[test]
fn external_sources_are_read_only_and_bounded() {
    let source = ExternalSourceApproval::new(
        "pack",
        "/Users/example/sdd",
        Sha256Digest::sha256(b"pack snapshot"),
        vec!["skills".to_owned()],
    )
    .expect("external source");
    assert_eq!(source.alias(), "pack");

    // A relative root and an escaping read path are refused.
    assert!(
        ExternalSourceApproval::new(
            "pack",
            "relative/path",
            Sha256Digest::sha256(b"x"),
            vec!["skills".to_owned()],
        )
        .is_err()
    );
    assert!(
        ExternalSourceApproval::new(
            "pack",
            "/Users/example/sdd",
            Sha256Digest::sha256(b"x"),
            vec!["../outside".to_owned()],
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

#[test]
fn unestablished_references_stay_none() {
    let project = ProjectId::new();
    let view = snapshot(
        project,
        ExecutionState::Running,
        vec![task_snapshot(project, 1, TaskPhase::Running)],
    );
    let task = view
        .task(TaskNumber::new(1).expect("number"))
        .expect("task");
    assert!(task.h2_reference().is_none());
    assert!(task.child().is_none());
    assert!(task.commit_range().is_none());
    assert!(task.no_change().is_none());
    assert!(task.evidence().is_empty());
    assert!(view.current_task().is_none());
    assert!(view.workspace().baseline().is_none());
    assert!(view.final_project_sequence().is_none());
    assert!(view.stop().is_none());

    // The JSON form encodes the absent values as null, never as a guess.
    let json = serde_json::to_value(&view).expect("snapshot json");
    assert_eq!(json["currentTask"], serde_json::Value::Null);
    assert_eq!(json["finalProjectSequence"], serde_json::Value::Null);
    assert_eq!(json["workspace"]["baseline"], serde_json::Value::Null);
    assert_eq!(json["tasks"][0]["h2Reference"], serde_json::Value::Null);
    assert_eq!(json["tasks"][0]["commitRange"], serde_json::Value::Null);

    // The snapshot decodes back to the same value.
    let decoded: ExecutionSnapshot = serde_json::from_value(json).expect("decode");
    assert_eq!(decoded, view);
}

#[test]
fn a_complete_required_task_needs_its_commit_range() {
    let project = ProjectId::new();
    let baseline = Baseline::parse("a".repeat(40)).expect("baseline");
    let head = CommitSha::parse("b".repeat(40)).expect("head");
    let range = CommitRange::new(baseline.clone(), head.clone()).expect("range");
    assert_eq!(range.short_range(), "aaaaaaa..bbbbbbb");
    assert_eq!(range.full_range(), format!("{baseline}..{head}"));

    // A range with equal base and head is refused: a required Task advances
    // HEAD.
    assert!(
        CommitRange::new(
            baseline.clone(),
            CommitSha::parse("a".repeat(40)).expect("same")
        )
        .is_err()
    );

    let evidence = vec![herness_supervision::EvidenceId::new(project)];
    let complete = TaskSnapshot::new(
        task_ref(project, 1),
        TaskProgression::Complete,
        TaskPhase::Complete,
        None,
        None,
        CommitPolicy::Required,
        Some(range),
        None,
        evidence.clone(),
        None,
        herness_sdd_execute::AppliedRevision::current(PlanRevision::new(1).expect("revision")),
    )
    .expect("complete required Task");
    assert_eq!(complete.progression(), TaskProgression::Complete);

    // A no_change Task with a commit range is refused.
    assert!(
        TaskSnapshot::new(
            task_ref(project, 1),
            TaskProgression::Complete,
            TaskPhase::Complete,
            None,
            None,
            CommitPolicy::NoChange,
            Some(CommitRange::new(baseline.clone(), head).expect("range")),
            None,
            evidence.clone(),
            None,
            herness_sdd_execute::AppliedRevision::current(PlanRevision::new(1).expect("revision")),
        )
        .is_err()
    );

    // A no_change Task needs its own evidence and never an empty commit.
    let record = NoChangeRecord::new(true, evidence.clone(), None).expect("no change record");
    let no_change = TaskSnapshot::new(
        task_ref(project, 1),
        TaskProgression::Complete,
        TaskPhase::Complete,
        None,
        None,
        CommitPolicy::NoChange,
        None,
        Some(record),
        evidence,
        None,
        herness_sdd_execute::AppliedRevision::current(PlanRevision::new(1).expect("revision")),
    )
    .expect("no_change Task");
    assert!(no_change.no_change().is_some());
}

#[test]
fn snapshot_refuses_more_than_one_active_task_and_fabricated_current_task() {
    let project = ProjectId::new();
    let error = ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: ExecutionId::new(project),
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Running,
        plan: SnapshotPlan::new(
            plan_path(),
            PlanDigest::sha256(b"plan"),
            PlanRevision::new(1).expect("plan revision"),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, "h4-exec", "main", None)
            .expect("snapshot workspace"),
        current_task: None,
        tasks: vec![
            task_snapshot(project, 1, TaskPhase::Running),
            task_snapshot(project, 2, TaskPhase::Running),
        ],
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: herness_sdd_execute::AppliedRevision::current(
            PlanRevision::new(1).expect("plan revision"),
        ),
        final_project_sequence: None,
    })
    .expect_err("only one Task may be active");
    assert!(matches!(
        error,
        SddExecutionError::InvalidSnapshot { ref field, .. } if field == "snapshot.tasks"
    ));

    // A current Task carrying only a number and a different stable ID is
    // refused.
    let foreign_task = task_ref(ProjectId::new(), 1);
    let error = ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: ExecutionId::new(project),
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Running,
        plan: SnapshotPlan::new(
            plan_path(),
            PlanDigest::sha256(b"plan"),
            PlanRevision::new(1).expect("plan revision"),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, "h4-exec", "main", None)
            .expect("snapshot workspace"),
        current_task: Some(foreign_task),
        tasks: vec![task_snapshot(project, 1, TaskPhase::Running)],
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: herness_sdd_execute::AppliedRevision::current(
            PlanRevision::new(1).expect("plan revision"),
        ),
        final_project_sequence: None,
    })
    .expect_err("a foreign current Task must be refused");
    assert!(matches!(
        error,
        SddExecutionError::CrossProjectReference { .. } | SddExecutionError::InvalidSnapshot { .. }
    ));
}

#[test]
fn ready_for_finish_requires_every_task_complete_and_no_current_task() {
    let project = ProjectId::new();
    let error = ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: ExecutionId::new(project),
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::ReadyForFinish,
        plan: SnapshotPlan::new(
            plan_path(),
            PlanDigest::sha256(b"plan"),
            PlanRevision::new(1).expect("plan revision"),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, "h4-exec", "main", None)
            .expect("snapshot workspace"),
        current_task: None,
        tasks: vec![task_snapshot(project, 1, TaskPhase::Running)],
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: herness_sdd_execute::AppliedRevision::current(
            PlanRevision::new(1).expect("plan revision"),
        ),
        final_project_sequence: None,
    })
    .expect_err("an unfinished Task blocks ready_for_finish");
    assert!(matches!(
        error,
        SddExecutionError::InvalidSnapshot { ref field, .. } if field == "snapshot.state"
    ));

    // A waiting execution records its stop and required action.
    let error = ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: ExecutionId::new(project),
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::WaitingHuman,
        plan: SnapshotPlan::new(
            plan_path(),
            PlanDigest::sha256(b"plan"),
            PlanRevision::new(1).expect("plan revision"),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, "h4-exec", "main", None)
            .expect("snapshot workspace"),
        current_task: None,
        tasks: vec![task_snapshot(project, 1, TaskPhase::Running)],
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: herness_sdd_execute::AppliedRevision::current(
            PlanRevision::new(1).expect("plan revision"),
        ),
        final_project_sequence: None,
    })
    .expect_err("waiting_human needs a stop record");
    assert!(matches!(
        error,
        SddExecutionError::InvalidSnapshot { ref field, .. } if field == "snapshot.stop"
    ));
}

// ---------------------------------------------------------------------------
// Journals and request idempotency
// ---------------------------------------------------------------------------

fn dispatch_content(project: ProjectId) -> DispatchContent {
    DispatchContent::new(
        task_ref(project, 1),
        PlanRevision::new(1).expect("plan revision"),
        Baseline::parse("a".repeat(40)).expect("baseline"),
        Sha256Digest::sha256(b"manifest"),
        Sha256Digest::sha256(b"packet"),
    )
    .expect("dispatch content")
}

#[test]
fn duplicate_dispatch_returns_the_stored_child_instead_of_creating_one() {
    let project = ProjectId::new();
    let execution = ExecutionId::new(project);
    let request_id = herness_sdd_execute::DispatchRequestId::new(project);
    let identity = RequestIdentity::new(project, execution, request_id, ExecutionRevision::INITIAL)
        .expect("identity");
    let content = dispatch_content(project);
    let request = DispatchRequest::new(identity, content.clone()).expect("dispatch request");

    let entry = DispatchJournalEntry::intent(*request.identity(), request.content())
        .expect("dispatch intent");
    let supervision = SupervisionId::new(project);
    let child = ChildIdentity::new(AgentId::new(project), SessionId::new(project)).expect("child");
    let result = DispatchResult::new(supervision, child).expect("dispatch result");
    let recorded = entry.recorded(result);

    // A re-delivered request with the same content returns the stored result,
    // even though its expected revision is now stale.
    let decision = decide_request(
        Some(&recorded),
        &identity,
        &content,
        ExecutionRevision::new(9).expect("revision"),
    )
    .expect("decision");
    match &decision {
        RequestDecision::Duplicate {
            outcome: Some(stored),
        } => {
            assert_eq!(stored, &result);
            assert_eq!(stored.child(), child);
        }
        other => panic!("expected a stored duplicate, got {other:?}"),
    }
    assert!(decision.duplicate_outcome().is_some());
    assert!(decision.refusal("dispatch").is_none());
}

#[test]
fn same_request_id_with_different_content_is_refused() {
    let project = ProjectId::new();
    let execution = ExecutionId::new(project);
    let request_id = herness_sdd_execute::DispatchRequestId::new(project);
    let identity = RequestIdentity::new(project, execution, request_id, ExecutionRevision::INITIAL)
        .expect("identity");
    let content = dispatch_content(project);
    let entry = DispatchJournalEntry::intent(identity, &content).expect("intent");

    let different = DispatchContent::new(
        task_ref(project, 2),
        PlanRevision::new(1).expect("plan revision"),
        Baseline::parse("a".repeat(40)).expect("baseline"),
        Sha256Digest::sha256(b"other manifest"),
        Sha256Digest::sha256(b"packet"),
    )
    .expect("content");

    let decision = decide_request(
        Some(&entry),
        &identity,
        &different,
        ExecutionRevision::INITIAL,
    )
    .expect("decision");
    match &decision {
        RequestDecision::ContentConflict { recorded, supplied } => {
            assert_ne!(recorded, supplied);
        }
        other => panic!("expected a content conflict, got {other:?}"),
    }
    let refusal = decision
        .refusal(&request_id.to_string())
        .expect("content conflict is a refusal");
    assert!(matches!(
        refusal,
        SddExecutionError::DuplicateRequestConflict { .. }
    ));
}

#[test]
fn stale_revision_is_refused_before_any_side_effect() {
    let project = ProjectId::new();
    let execution = ExecutionId::new(project);
    let request_id = herness_sdd_execute::DispatchRequestId::new(project);
    let identity = RequestIdentity::new(project, execution, request_id, ExecutionRevision::INITIAL)
        .expect("identity");
    let content = dispatch_content(project);

    // A new request ID against a newer stored revision is a conflict, not an
    // intent.
    let decision = decide_request::<herness_sdd_execute::DispatchKind, DispatchResult>(
        None,
        &identity,
        &content,
        ExecutionRevision::new(4).expect("revision"),
    )
    .expect("decision");
    match decision {
        RequestDecision::StaleRevision { expected, found } => {
            assert_eq!(expected, ExecutionRevision::INITIAL);
            assert_eq!(found.get(), 4);
        }
        other => panic!("expected a stale revision, got {other:?}"),
    }
    assert!(matches!(
        decision.refusal("dispatch").expect("refusal"),
        SddExecutionError::RevisionConflict { .. }
    ));

    // A duplicate with only an intent recorded is refused instead of
    // repeating the side effect.
    let partial = DispatchJournalEntry::intent(identity, &content).expect("intent");
    let decision = decide_request(
        Some(&partial),
        &identity,
        &content,
        ExecutionRevision::INITIAL,
    )
    .expect("decision");
    assert!(matches!(
        decision,
        RequestDecision::Duplicate { outcome: None }
    ));
    assert!(matches!(
        decision.refusal("dispatch").expect("intent-only refusal"),
        SddExecutionError::DuplicateResultConflict { .. }
    ));
}

#[test]
fn update_operations_require_the_full_guard_and_reads_do_not() {
    let project = ProjectId::new();
    let execution = ExecutionId::new(project);

    let request = ExecutionOperationRequest::new(
        project,
        execution,
        herness_sdd_execute::ControlRequestId::new(project),
        ExecutionRevision::INITIAL,
        ExecutionOperation::ApproveAndStart,
    )
    .expect("update request");
    assert_eq!(request.operation(), ExecutionOperation::ApproveAndStart);
    assert_eq!(
        request.identity().expected_revision(),
        ExecutionRevision::INITIAL
    );

    // A read-only operation cannot carry an update guard.
    assert!(
        ExecutionOperationRequest::new(
            project,
            execution,
            herness_sdd_execute::ControlRequestId::new(project),
            ExecutionRevision::INITIAL,
            ExecutionOperation::Get,
        )
        .is_err()
    );

    let read = herness_sdd_execute::ReadExecutionRequest::new(
        project,
        execution,
        ExecutionOperation::Subscribe,
    )
    .expect("read request");
    assert!(read.operation().is_read_only());

    // No operation makes plan import an implementation permission.
    assert!(ExecutionOperation::Inspect.is_read_only());
    assert!(ExecutionOperation::ApproveAndStart.is_update());
}

#[test]
fn git_journal_records_intent_before_side_effects_and_unknown_results() {
    let project = ProjectId::new();
    let execution = ExecutionId::new(project);
    let request_id = CommitRequestId::new(project);
    let identity = RequestIdentity::new(project, execution, request_id, ExecutionRevision::INITIAL)
        .expect("identity");
    let task = task_ref(project, 1);
    let message = CommitMessage::new(
        task,
        "define the H4 contract",
        execution,
        request_id,
        vec![CommitTrailer::new("Herness-Gate", "passed").expect("trailer")],
    )
    .expect("commit message");
    assert!(message.render().contains("Task 1: define the H4 contract"));
    assert!(message.trailer("Herness-Execution").is_some());
    assert!(message.trailer("Herness-Task").is_some());
    assert!(message.trailer("Herness-Request").is_some());
    // A required trailer cannot be repeated.
    assert!(
        CommitMessage::new(
            task,
            "title",
            execution,
            request_id,
            vec![CommitTrailer::new("Herness-Task", "1").expect("trailer")],
        )
        .is_err()
    );

    let pre_hook = PreHookState::new(
        true,
        vec!["crates/herness-sdd-execute/src/lib.rs".to_owned()],
        Some(Sha256Digest::sha256(b"hooks")),
        Some(TreeSha::parse("c".repeat(40)).expect("tree")),
    )
    .expect("pre-hook state");
    let intent = GitCommitIntent::new(
        task,
        "h4-exec",
        Baseline::parse("a".repeat(40)).expect("baseline"),
        CommitSha::parse("a".repeat(40)).expect("parent"),
        Some(TreeSha::parse("d".repeat(40)).expect("tree")),
        vec![
            CommittedPath::new(
                "crates/herness-sdd-execute/src/lib.rs",
                1_024,
                Some(Sha256Digest::sha256(b"content")),
            )
            .expect("path"),
        ],
        message,
        pre_hook,
        30,
    )
    .expect("commit intent");

    let entry = GitJournalEntry::new(identity, intent.clone()).expect("git journal intent");
    assert_eq!(entry.state(), GitJournalState::Intent);
    assert!(entry.outcome().is_none());

    // The intent already carries the expected parent, tree, explicit paths,
    // message, and pre-hook state.
    assert_eq!(entry.intent().expected_parent().as_str(), "a".repeat(40));
    assert!(entry.intent().expected_tree().is_some());
    assert_eq!(entry.intent().paths().len(), 1);
    assert!(entry.intent().pre_hook().index_clean());

    // An unknown or too-late result is recorded explicitly, not as success.
    let unknown = entry.clone().mark_result_unknown(GitUnknownReason::Timeout);
    assert_eq!(unknown.state(), GitJournalState::ResultUnknown);
    assert!(matches!(
        unknown.outcome(),
        Some(GitCommitOutcome::Unknown {
            reason: GitUnknownReason::Timeout
        })
    ));
    assert!(unknown.outcome().expect("outcome").is_unknown());
    assert!(unknown.outcome().expect("outcome").may_exist());

    // A committed outcome records the observed object names.
    let committed = entry.clone().record(GitCommitOutcome::Committed {
        commit: CommitSha::parse("e".repeat(40)).expect("commit"),
        tree: TreeSha::parse("d".repeat(40)).expect("tree"),
        parent: CommitSha::parse("a".repeat(40)).expect("parent"),
    });
    assert_eq!(committed.state(), GitJournalState::Committed);

    // Re-delivering the same commit request returns the stored outcome.
    let decision = committed
        .decide(
            &identity,
            &intent,
            ExecutionRevision::new(7).expect("revision"),
        )
        .expect("decision");
    assert!(matches!(
        decision,
        RequestDecision::Duplicate { outcome: Some(_) }
    ));

    // A commit intent with no explicit path is refused: no `git add .`.
    assert!(
        GitCommitIntent::new(
            task,
            "h4-exec",
            Baseline::parse("a".repeat(40)).expect("baseline"),
            CommitSha::parse("a".repeat(40)).expect("parent"),
            None,
            Vec::new(),
            CommitMessage::new(task, "title", execution, request_id, Vec::new()).expect("message"),
            PreHookState::new(true, Vec::new(), None, None).expect("pre-hook"),
            30,
        )
        .is_err()
    );

    // A dirty index blocks the commit before any side effect.
    assert!(PreHookState::new(false, Vec::new(), None, None).is_err());

    // A commit budget above the host commit limit is refused.
    assert!(
        GitCommitIntent::new(
            task,
            "h4-exec",
            Baseline::parse("a".repeat(40)).expect("baseline"),
            CommitSha::parse("a".repeat(40)).expect("parent"),
            None,
            vec![CommittedPath::new("src/lib.rs", 1, None).expect("path")],
            CommitMessage::new(task, "title", execution, request_id, Vec::new()).expect("message"),
            PreHookState::new(true, vec!["src/lib.rs".to_owned()], None, None).expect("pre-hook"),
            31,
        )
        .is_err()
    );
}

#[test]
fn progress_journal_is_a_projection_of_durable_state() {
    let project = ProjectId::new();
    let execution = ExecutionId::new(project);
    let request_id = herness_sdd_execute::ProgressJournalId::new(project);
    let identity = RequestIdentity::new(project, execution, request_id, ExecutionRevision::INITIAL)
        .expect("identity");
    let task = task_ref(project, 1);
    let range = CommitRange::new(
        Baseline::parse("a".repeat(40)).expect("baseline"),
        CommitSha::parse("b".repeat(40)).expect("head"),
    )
    .expect("range");
    let line = ProgressTaskLine::new(task, Some(range), false).expect("line");
    let content = ProgressContent::new(
        ".sdd/progress.md",
        CHECKOUT,
        "h4-exec",
        Baseline::parse("a".repeat(40)).expect("baseline"),
        vec![line],
        vec!["Ruling: keep H2 limits".to_owned()],
        Some(herness_sdd_execute::ProjectSequence::new(42)),
        Sha256Digest::sha256(b"document"),
    )
    .expect("progress content");

    let entry = ProgressJournalEntry::new(identity, content.clone()).expect("progress intent");
    assert_eq!(entry.state(), ProgressJournalState::Intent);
    let written = entry.record(herness_sdd_execute::ProgressWriteOutcome::Written {
        digest: Sha256Digest::sha256(b"document"),
    });
    assert_eq!(written.state(), ProgressJournalState::Recorded);
    assert_eq!(written.content().completed().len(), 1);

    // A no_change line carries no commit range.
    assert!(ProgressTaskLine::new(task, None, true).is_ok());
    assert!(ProgressTaskLine::new(task, None, false).is_err());
}

#[test]
fn checkout_ownership_is_exclusive() {
    let project = ProjectId::new();
    let first = CheckoutClaim::new(CHECKOUT, "h4-exec", ExecutionId::new(project)).expect("claim");
    let same_checkout_other_execution =
        CheckoutClaim::new(CHECKOUT, "h4-exec", ExecutionId::new(project)).expect("claim");
    assert!(first.conflicts_with(&same_checkout_other_execution));
    assert!(matches!(
        first
            .ensure_available(&same_checkout_other_execution)
            .expect_err("ownership conflict"),
        SddExecutionError::Conflict {
            reason: herness_sdd_execute::ConflictReason::OwnershipConflict,
            ..
        }
    ));

    let other_branch =
        CheckoutClaim::new(CHECKOUT, "other-branch", ExecutionId::new(project)).expect("claim");
    assert!(!first.conflicts_with(&other_branch));
    assert!(first.ensure_available(&other_branch).is_ok());
}

// ---------------------------------------------------------------------------
// Host contract
// ---------------------------------------------------------------------------

#[test]
fn host_contract_binds_the_pack_definition() {
    let fingerprint = PackFingerprint::parse(format!("sha256:{}", "f".repeat(64))).expect("fp");
    let contract = HostExecutionContract::new(fingerprint.clone()).expect("contract");
    assert_eq!(contract.schema(), "herness-sdd-execution-contract");
    assert_eq!(contract.version(), 1);
    assert_eq!(contract.delegation().task_dispatch(), Delegation::Host);
    assert_eq!(contract.delegation().child_git(), Delegation::Forbidden);
    assert_eq!(
        contract.delegation().destructive_git(),
        Delegation::Forbidden
    );
    assert_eq!(contract.delegation().hooks(), Delegation::HostRequired);
    assert_eq!(contract.continuation(), ContinuationLimits::h4_default());
    assert_eq!(contract.continuation().max_time_seconds(), 7_200);
    assert_eq!(contract.continuation().max_additional_runs(), 30);
    assert_eq!(contract.continuation().max_consecutive_stalls(), 3);
    assert_eq!(
        contract.approval().forbidden_sources().len(),
        ApprovalSourceKind::ALL.len() - 1
    );
    assert!(contract.ensure_fingerprint(&fingerprint).is_ok());
    assert!(
        contract
            .ensure_fingerprint(
                &PackFingerprint::parse(format!("sha256:{}", "e".repeat(64))).expect("fp")
            )
            .is_err()
    );

    // The H4 contract does not add a plan-wide budget or raise H2 limits.
    let limits = ContinuationLimits::h4_default();
    assert!(limits.validate().is_ok());
}

#[test]
fn html_barrier_is_the_h3_value_not_a_redefinition() {
    // The H4 alias names H3's own barrier type, so H4 cannot change H3
    // semantics by construction.
    fn takes_h4_barrier(barrier: H4Barrier<'_>) -> H4Barrier<'_> {
        barrier
    }
    let _ = takes_h4_barrier as fn(H4Barrier<'_>) -> H4Barrier<'_>;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

#[test]
fn project_paths_are_bounded() {
    assert!(validate_project_path("readPaths", "crates/herness-core/src").is_ok());
    for path in [
        "",
        ".",
        "*",
        "/absolute",
        "../escape",
        "a/../b",
        "a//b",
        "crates\\windows",
    ] {
        assert!(
            validate_project_path("readPaths", path).is_err(),
            "{path:?} should be refused"
        );
    }
    assert!(PlanPath::parse("docs/sdd/plans/plan.md").is_ok());
    assert!(PlanPath::parse("docs/other/plan.md").is_err());
    assert!(PlanPath::parse("docs/sdd/plans/nested/plan.md").is_err());
    assert!(PlanPath::parse("docs/sdd/plans/plan.txt").is_err());
    assert!(PlanPath::parse("/docs/sdd/plans/plan.md").is_err());
}

#[test]
fn plan_text_is_bound_to_an_exact_byte_range() {
    let text = ExecText::text("Global Constraints", 10);
    assert_eq!(text.byte_range().start(), 10);
    assert_eq!(text.byte_range().len(), "Global Constraints".len() as u64);
    assert!(PlanByteRange::new(5, 4).is_err());
}

struct ExecText;

impl ExecText {
    fn text(value: &str, start: u64) -> herness_sdd_execute::ExactPlanText {
        herness_sdd_execute::ExactPlanText::new(
            value,
            PlanByteRange::new(start, start + value.len() as u64).expect("range"),
        )
        .expect("text")
    }
}

// ---------------------------------------------------------------------------
// Durable store port boundary and no reverse dependency
// ---------------------------------------------------------------------------

/// The crate must not gain a reverse dependency from H1, H2, or H3.
#[test]
fn core_supervision_and_html_sync_do_not_depend_on_h4() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf();
    let manifests = [
        ("herness-core", "crates/herness-core/Cargo.toml"),
        (
            "herness-supervision",
            "crates/herness-supervision/Cargo.toml",
        ),
        ("herness-html-sync", "crates/herness-html-sync/Cargo.toml"),
        ("herness-store", "crates/herness-store/Cargo.toml"),
    ];
    for (name, relative) in manifests {
        let path = workspace_root.join(relative);
        let manifest = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert!(
            !manifest.contains("herness-sdd-execute"),
            "{name} must not list herness-sdd-execute"
        );
    }

    // The H4 crate itself depends only on the public contract crates.
    let h4 = std::fs::read_to_string(workspace_root.join("crates/herness-sdd-execute/Cargo.toml"))
        .expect("H4 manifest");
    for forbidden in [
        "rusqlite",
        "tauri",
        "herness-store",
        "herness-engine-pi",
        "herness-desktop",
    ] {
        assert!(
            !h4.contains(forbidden),
            "the H4 contract crate must not depend on {forbidden}"
        );
    }
}

/// A durable store is a port, not a type this crate implements.
#[test]
fn the_store_is_only_a_port() {
    // `ExecutionStorePort` is a trait with no implementation in this crate.
    let _ = (|_store: &dyn ExecutionStorePort| {}) as fn(&dyn ExecutionStorePort);
}

#[test]
fn request_content_fingerprints_are_bound_to_the_exact_content() {
    let project = ProjectId::new();
    let first = dispatch_content(project);
    let second = DispatchContent::new(
        task_ref(project, 1),
        PlanRevision::new(1).expect("plan revision"),
        Baseline::parse("a".repeat(40)).expect("baseline"),
        Sha256Digest::sha256(b"another manifest"),
        Sha256Digest::sha256(b"packet"),
    )
    .expect("content");
    assert_ne!(
        first.content_fingerprint().expect("fingerprint"),
        second.content_fingerprint().expect("fingerprint")
    );
    assert_eq!(
        first.content_fingerprint().expect("fingerprint"),
        first.content_fingerprint().expect("fingerprint")
    );
}

/// A request record type is used here to prove the generic guard is reusable.
#[test]
fn request_records_are_generic_over_the_request_kind() {
    let project = ProjectId::new();
    let execution = ExecutionId::new(project);
    let identity = RequestIdentity::new(
        project,
        execution,
        CommitRequestId::new(project),
        ExecutionRevision::INITIAL,
    )
    .expect("identity");
    let content = dispatch_content(project);
    let record: RequestRecord<herness_sdd_execute::CommitKind, DispatchResult> =
        RequestRecord::intent(identity, &content).expect("record");
    assert_eq!(
        record.state(),
        herness_sdd_execute::JournalEntryState::Intent
    );
    assert!(record.outcome().is_none());
}
