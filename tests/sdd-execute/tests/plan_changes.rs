//! Task 19: plan-change detection, the safety-stop latch, and the limited
//! re-approval.
//!
//! Every case uses a synthetic project, a real temporary filesystem with atomic
//! saves (write a temporary file, then rename over the plan), a real temporary
//! SQLite store, a deterministic fake clock, and — where the parsed comparison
//! is exercised — the real pack inspector. No network, no model, no credential,
//! and no Git operation is used.
//!
//! The real pack root is `SDD_PACK_ROOT`, defaulting to
//! `/Users/h-uma/Documents/sdd/.worktrees/h4-exec`; the cases that need it report
//! the root they used and fail with an explicit message when it is absent.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;

use herness_core::contracts::{ConnectionId, ProjectId, Timestamp};
use herness_core::{AbsolutePath, ProcessSupervisor, SystemArgvLauncher};
use herness_desktop::sdd_execute::{
    PlanFileSource, PlanFileWatcher, PlanImporter, PlanWatchNotice,
};
use herness_sdd_execute::{
    ApprovalContent, ApprovalId, ApprovalInputs, ApprovalSource, ApprovedCheck, ApprovedCondition,
    ApprovedDeliverable, ApprovedSpecRef, Baseline, BudgetConsumption, ChildDispatchPlan,
    ChildDispatchPort, ChildIdentity, ChildState, ChildStatus, ChildStatusPort, ClockPort,
    CommitAuthorization, CommitPolicy, CommitRange, ConditionMode, ControlRequestId,
    CoordinatorOutcome, CoordinatorPorts, CoordinatorRequest, DeliverableKind, DispatchRequestId,
    DispatchResult, ExactPlanBytes, ExactPlanText, ExecutionApproval, ExecutionConnection,
    ExecutionId, ExecutionRevision, ExecutionSnapshot, ExecutionState, GitIdentity,
    H2SupervisionRef, H3ApprovalBinding, HumanAction, InspectorProtocol, JsonBlockState,
    LatchState, MemoryPlanChangeLatchStore, ObservedConnection, PackApproval, PackFingerprint,
    ParsedPlanSummary, ParsedPlanTask, PlanApproval, PlanByteRange, PlanChange, PlanChangeGate,
    PlanChangeGatePort, PlanChangeLatch, PlanChangeLatchStorePort, PlanChangeReason, PlanDigest,
    PlanExpectation, PlanGateDecision, PlanInheritanceBlocker, PlanPath, PlanRevision,
    PlanRevisionApproval, PlanRevisionOutcome, PlanSourcePort, ReconcileSchedule,
    SddExecutionError, SerialExecutionState, Sha256Digest, SnapshotBudget, SnapshotInput,
    SnapshotPlan, SnapshotWorkspace, StartApprovalPost, StopReason, TaskApproval, TaskCompletion,
    TaskCompletionPort, TaskCompletionRequest, TaskLaunch, TaskLaunchPort, TaskNumber, TaskPhase,
    TaskProgress, TaskProgression, TaskRef, TaskSnapshot, TaskStableId, WorkspaceApproval,
    approve_plan_revision, confirm_plan_change_stop, evaluate_inheritance,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::{
    ApprovalActor, BudgetPolicy, ConsentBinding, ConsentId, ExecutionScope, ProfileBinding,
    ProfileId, ProfilePurpose, ProfileVersion, SupervisionId, TargetVersion,
};
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Identity fixtures
// ---------------------------------------------------------------------------

const CHECKOUT: &str = "/tmp/herness-h4-plan-change-fixture";
const BRANCH: &str = "h4-plan-change";
const BASE_BRANCH: &str = "main";
const PLAN_PATH: &str = "docs/sdd/plans/2026-11-14-plan-change-fixture.md";
const SPEC_PATH: &str = "docs/sdd/specs/2026-11-14-plan-change-fixture.md";
const SECTION: &str = "Durable state, plan changes and finish";

/// The documented default pack checkout, overridable with `SDD_PACK_ROOT`.
const DEFAULT_PACK_ROOT: &str = "/Users/h-uma/Documents/sdd/.worktrees/h4-exec";

fn project() -> ProjectId {
    ProjectId::from_uuid(uuid("c1000000-0000-4000-8000-000000000001"))
}

fn execution(project_id: ProjectId) -> ExecutionId {
    ExecutionId::from_parts(project_id, uuid("c2000000-0000-4000-8000-000000000001"))
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("a UUID")
}

fn approval_id(project_id: ProjectId) -> ApprovalId {
    ApprovalId::from_parts(project_id, uuid("c3000000-0000-4000-8000-000000000001"))
}

fn control_request(project_id: ProjectId, local: u128) -> ControlRequestId {
    ControlRequestId::from_parts(project_id, Uuid::from_u128(local))
}

fn plan_path() -> PlanPath {
    PlanPath::parse(PLAN_PATH).expect("a plan path")
}

fn other_plan_path() -> PlanPath {
    PlanPath::parse("docs/sdd/plans/2026-11-14-moved-fixture.md").expect("a moved plan path")
}

fn baseline() -> Baseline {
    Baseline::parse("a".repeat(40)).expect("a baseline")
}

fn head() -> herness_sdd_execute::CommitSha {
    herness_sdd_execute::CommitSha::parse("b".repeat(40)).expect("a head")
}

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::sha256(label.as_bytes())
}

fn task_ref(project_id: ProjectId, number: u32) -> TaskRef {
    TaskRef::new(
        TaskStableId::from_parts(
            project_id,
            Uuid::from_u128(0xe000_0000_0000_4000_8000_0000_0000_0000 + u128::from(number)),
        ),
        TaskNumber::new(number).expect("a Task number"),
    )
}

fn now() -> Timestamp {
    Timestamp::from_unix_millis(1_780_000_000_000)
}

fn supervision(project_id: ProjectId) -> SupervisionId {
    SupervisionId::from_parts(project_id, Uuid::from_u128(0xf000))
}

fn child(project_id: ProjectId) -> ChildIdentity {
    ChildIdentity::new(
        herness_core::AgentId::from_parts(project_id, Uuid::from_u128(0xf100)),
        herness_core::SessionId::from_parts(project_id, Uuid::from_u128(0xf101)),
    )
    .expect("a child")
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// A deterministic clock the test advances by hand.
#[derive(Debug, Clone)]
struct FakeClock {
    now: Arc<std::sync::Mutex<Timestamp>>,
}

impl FakeClock {
    fn at(value: Timestamp) -> Self {
        Self {
            now: Arc::new(std::sync::Mutex::new(value)),
        }
    }

    fn advance(&self, millis: u64) {
        let mut guard = self.now.lock().expect("the fake clock");
        *guard = Timestamp::from_unix_millis(guard.as_unix_millis() + millis);
    }
}

impl ClockPort for FakeClock {
    fn now(&self) -> Timestamp {
        *self.now.lock().expect("the fake clock")
    }
}

// ---------------------------------------------------------------------------
// Filesystem fixtures
// ---------------------------------------------------------------------------

fn write_atomic(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("a created parent directory");
    }
    let temporary = path.with_extension("md.tmp");
    std::fs::write(&temporary, bytes).expect("a written temporary file");
    std::fs::rename(&temporary, &path).expect("an atomic rename");
}

fn write_plain(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("a created parent directory");
    }
    std::fs::write(&path, bytes).expect("a written fixture file");
}

/// One plan document with the exact prose and Global Constraints a case wants.
fn plan_document(
    goal: &str,
    constraints: &str,
    task_one_body: &str,
    task_two_body: &str,
) -> Vec<u8> {
    let spec_ref =
        format!(r#"{{"source":"project","path":"{SPEC_PATH}","sections":["{SECTION}"]}}"#);
    format!(
        r#"# Plan change fixture

**Goal:** {goal}

**Architecture:** One Task writes one module in one checkout.

**Tech Stack:** Rust

**Spec:** {SPEC_PATH}

## Global Constraints

{constraints}

```sdd-execution-v1
{{
  "schema": "sdd-execution-plan",
  "version": 1,
  "specRefs": [{spec_ref}],
  "tasks": [
    {{
      "number": 1,
      "dependsOn": [],
      "specRefs": [{spec_ref}],
      "readPaths": ["src/a.rs"],
      "writePaths": ["src/a.rs"],
      "allowShell": true,
      "deliverables": [{{"path": "src/a.rs", "kind": "file"}}],
      "conditions": [
        {{
          "id": "written",
          "title": "The module is written",
          "rubric": "src/a.rs contains a main function returning zero.",
          "mode": "checks"
        }}
      ],
      "checks": [
        {{
          "id": "build",
          "conditionId": "written",
          "description": "Build the crate.",
          "command": "cargo check",
          "cwd": ".",
          "timeoutSeconds": 60,
          "inputPaths": ["src/a.rs"]
        }}
      ],
      "htmlTargets": [],
      "commitPolicy": "required"
    }},
    {{
      "number": 2,
      "dependsOn": [1],
      "specRefs": [{spec_ref}],
      "readPaths": ["src/b.rs"],
      "writePaths": ["src/b.rs"],
      "allowShell": true,
      "deliverables": [{{"path": "src/b.rs", "kind": "file"}}],
      "conditions": [
        {{
          "id": "written-2",
          "title": "The second module is written",
          "rubric": "src/b.rs exists.",
          "mode": "checks"
        }}
      ],
      "checks": [
        {{
          "id": "build-2",
          "conditionId": "written-2",
          "description": "Build the crate again.",
          "command": "cargo check",
          "cwd": ".",
          "timeoutSeconds": 60,
          "inputPaths": ["src/b.rs"]
        }}
      ],
      "htmlTargets": [],
      "commitPolicy": "required"
    }}
  ],
  "finalChecks": ["build-2"]
}}
```

## Task 1: Write the module

{task_one_body}

## Task 2: Write the second module

{task_two_body}
"#
    )
    .into_bytes()
}

fn spec_markdown() -> &'static str {
    "# Plan change fixture design\n\n## Durable state, plan changes and finish\n\nThe plan is the source of truth for one execution.\n"
}

/// A temp project with the plan, the spec, and optionally a real store.
struct TempProject {
    _temp: TempDir,
    root: PathBuf,
}

impl TempProject {
    fn new(plan: &[u8]) -> Self {
        let temp = TempDir::new().expect("a temporary project");
        let root = temp.path().to_path_buf();
        write_plain(&root, PLAN_PATH, plan);
        write_plain(&root, SPEC_PATH, spec_markdown().as_bytes());
        Self { _temp: temp, root }
    }

    fn plan_bytes(&self) -> Vec<u8> {
        std::fs::read(self.root.join(PLAN_PATH)).expect("the plan file")
    }

    fn save(&self, bytes: &[u8]) {
        write_atomic(&self.root, PLAN_PATH, bytes);
    }
}

// ---------------------------------------------------------------------------
// Approval fixtures
// ---------------------------------------------------------------------------

fn scope(project_id: ProjectId) -> ExecutionScope {
    ExecutionScope::new(
        project_id,
        vec!["src".to_owned()],
        vec!["src".to_owned()],
        true,
    )
    .expect("a scope")
}

fn parsed_summary(constraints: &str, bodies: &[&str], revision_marker: &str) -> ParsedPlanSummary {
    let constraints_text = ExactPlanText::new(
        constraints,
        PlanByteRange::new(0, constraints.len() as u64).expect("a range"),
    )
    .expect("exact constraints");
    let tasks = bodies
        .iter()
        .enumerate()
        .map(|(index, body)| {
            let number = u32::try_from(index + 1).expect("a Task number");
            ParsedPlanTask::new(
                number,
                format!("Task {number}"),
                ExactPlanText::new(
                    format!("{body}{revision_marker}"),
                    PlanByteRange::new(0, body.len() as u64).expect("a range"),
                )
                .expect("an exact body"),
            )
            .expect("a parsed Task")
        })
        .collect();
    ParsedPlanSummary::new(1, constraints_text, tasks, vec!["build-2".to_owned()])
        .expect("a parsed plan")
}

fn spec_ref(digest_of_spec: Sha256Digest) -> ApprovedSpecRef {
    ApprovedSpecRef::new(
        "project",
        SPEC_PATH,
        vec![SECTION.to_owned()],
        digest_of_spec,
    )
    .expect("a spec reference")
}

fn task_approval(project_id: ProjectId, number: u32, rubric: &str) -> TaskApproval {
    let condition_id = format!("written-{number}");
    let check_id = if number == 1 {
        "build".to_owned()
    } else {
        "build-2".to_owned()
    };
    let deliverable = if number == 1 { "src/a.rs" } else { "src/b.rs" };
    TaskApproval::new(
        task_ref(project_id, number),
        format!("Task {number}"),
        vec![
            ApprovedCondition::new(&condition_id, "condition", rubric, ConditionMode::Checks)
                .expect("a condition"),
        ],
        ExecutionScope::new(
            project_id,
            vec!["src".to_owned()],
            vec![deliverable.to_owned()],
            true,
        )
        .expect("a Task scope"),
        vec![
            ApprovedCheck::new(
                &check_id,
                &condition_id,
                "run the check",
                "cargo check",
                ".",
                60,
                vec![deliverable.to_owned()],
            )
            .expect("a check"),
        ],
        Vec::new(),
        BudgetPolicy::new(600, 5, None).expect("a budget"),
        CommitPolicy::Required,
        vec![ApprovedDeliverable::new(deliverable, DeliverableKind::File).expect("a deliverable")],
    )
    .expect("a Task approval")
}

fn workspace_approval(project_id: ProjectId) -> WorkspaceApproval {
    WorkspaceApproval::new(
        project_id,
        CHECKOUT,
        GitIdentity::new("herness", "host@example.test").expect("a Git identity"),
        BRANCH,
        BASE_BRANCH,
        false,
        Some(baseline()),
    )
    .expect("a workspace approval")
}

fn profile(project_id: ProjectId) -> ProfileBinding {
    ProfileBinding::new(
        ProfileId::from_parts(project_id, Uuid::from_u128(0xf200)),
        ProfileVersion::new(1).expect("a profile version"),
        ProfilePurpose::Completion,
    )
}

fn consent(project_id: ProjectId) -> ConsentBinding {
    ConsentBinding::new(
        ConsentId::from_parts(project_id, Uuid::from_u128(0xf300)),
        1,
        ProfilePurpose::Completion,
        TargetVersion::new(1).expect("a target version"),
    )
}

fn connection(project_id: ProjectId) -> ExecutionConnection {
    ExecutionConnection::new(
        ConnectionId::from_uuid(Uuid::from_u128(0xf400)),
        profile(project_id),
        vec![consent(project_id)],
    )
    .expect("a connection")
}

fn h3() -> H3ApprovalBinding {
    H3ApprovalBinding::new(1, Vec::new(), vec!["html-sync".to_owned()]).expect("an H3 binding")
}

/// Builds one approval content over the *real* plan bytes on disk.
struct ContentSpec<'a> {
    project_id: ProjectId,
    plan_revision: PlanRevision,
    source: &'a [u8],
    constraints: &'a str,
    bodies: [&'a str; 2],
    rubric_one: &'a str,
    rubric_two: &'a str,
}

fn content(spec: ContentSpec<'_>) -> ApprovalContent {
    let parsed = parsed_summary(spec.constraints, &spec.bodies, "");
    let plan = PlanApproval::new(
        plan_path(),
        ExactPlanBytes::new(spec.source.to_vec()).expect("exact plan bytes"),
        spec.plan_revision,
        parsed,
        vec![spec_ref(digest("spec"))],
        Vec::new(),
        PackApproval::new(
            InspectorProtocol::expected(),
            1,
            PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).expect("a fingerprint"),
        )
        .expect("a pack approval"),
    )
    .expect("a plan approval");
    ApprovalContent::new(
        plan,
        workspace_approval(spec.project_id),
        vec![
            task_approval(spec.project_id, 1, spec.rubric_one),
            task_approval(spec.project_id, 2, spec.rubric_two),
        ],
        connection(spec.project_id),
        CommitAuthorization::new(true, true).expect("a commit authorization"),
        h3(),
    )
    .expect("an approval content")
}

fn approval(project_id: ProjectId, revision: u64, content: ApprovalContent) -> ExecutionApproval {
    let id = approval_id(project_id);
    if revision == 1 {
        ExecutionApproval::new(
            id,
            ApprovalActor::Human,
            ApprovalSource::ApprovalRegistry { approval_id: id },
            now(),
            content,
        )
        .expect("an approval")
    } else {
        let first = ExecutionApproval::new(
            id,
            ApprovalActor::Human,
            ApprovalSource::ApprovalRegistry { approval_id: id },
            now(),
            content.clone(),
        )
        .expect("a first approval");
        first
            .revise(
                ApprovalActor::Human,
                ApprovalSource::ApprovalRegistry { approval_id: id },
                revision,
                now(),
                content,
            )
            .expect("a revised approval")
    }
}

fn plan_revision(value: u64) -> PlanRevision {
    PlanRevision::new(value).expect("a plan revision")
}

// ---------------------------------------------------------------------------
// Store fixtures
// ---------------------------------------------------------------------------

struct Harness {
    _temp: TempDir,
    store: Store,
    project: ProjectId,
    execution: ExecutionId,
}

impl Harness {
    fn new() -> Self {
        let temp = TempDir::new().expect("a temporary directory");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("a store configuration");
        let store = Store::open(config).expect("a temporary store");
        let project = project();
        let execution = execution(project);
        Self {
            _temp: temp,
            store,
            project,
            execution,
        }
    }

    fn snapshot(&self) -> ExecutionSnapshot {
        self.store
            .load_sdd_execution(self.project, self.execution)
            .expect("load")
            .expect("a stored snapshot")
            .snapshot()
            .clone()
    }
}

/// A ready execution with Task 1 active and Task 2 pending.
fn running_snapshot(project_id: ProjectId, execution_id: ExecutionId) -> ExecutionSnapshot {
    ExecutionSnapshot::new(SnapshotInput {
        project_id,
        execution_id,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Running,
        plan: SnapshotPlan::new(
            plan_path(),
            PlanDigest::sha256(b"placeholder"),
            plan_revision(1),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, BRANCH, BASE_BRANCH, Some(baseline()))
            .expect("a snapshot workspace"),
        current_task: Some(task_ref(project_id, 1)),
        tasks: vec![
            TaskSnapshot::new(
                task_ref(project_id, 1),
                TaskProgression::Active,
                TaskPhase::Running,
                Some(H2SupervisionRef::new(supervision(project_id))),
                Some(child(project_id)),
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(plan_revision(1)),
            )
            .expect("Task 1"),
            TaskSnapshot::new(
                task_ref(project_id, 2),
                TaskProgression::Pending,
                TaskPhase::Ready,
                None,
                None,
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(plan_revision(1)),
            )
            .expect("Task 2"),
        ],
        stop: None,
        budget: SnapshotBudget::new(
            BudgetConsumption::new(120, 4, None),
            BudgetConsumption::zero(),
        ),
        applied_revision: herness_sdd_execute::AppliedRevision::current(plan_revision(1)),
        final_project_sequence: None,
    })
    .expect("a running snapshot")
}

/// A stopped execution whose plan change was already confirmed.
fn stopped_snapshot(
    project_id: ProjectId,
    execution_id: ExecutionId,
    revision: ExecutionRevision,
    plan: &PlanApproval,
) -> ExecutionSnapshot {
    stopped_snapshot_with(project_id, execution_id, revision, plan, true)
}

/// A stopped execution whose Task 2 is either started (blocking inheritance) or
/// still pending (allowing it).
fn stopped_snapshot_with(
    project_id: ProjectId,
    execution_id: ExecutionId,
    revision: ExecutionRevision,
    plan: &PlanApproval,
    second_started: bool,
) -> ExecutionSnapshot {
    ExecutionSnapshot::new(SnapshotInput {
        project_id,
        execution_id,
        revision,
        state: ExecutionState::Stopped,
        plan: SnapshotPlan::new(
            plan.plan_path().clone(),
            plan.digest().clone(),
            plan.plan_revision(),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, BRANCH, BASE_BRANCH, Some(baseline()))
            .expect("a snapshot workspace"),
        current_task: Some(task_ref(project_id, 2)),
        tasks: vec![
            TaskSnapshot::new(
                task_ref(project_id, 1),
                TaskProgression::Complete,
                TaskPhase::Complete,
                Some(H2SupervisionRef::new(supervision(project_id))),
                Some(child(project_id)),
                CommitPolicy::Required,
                Some(CommitRange::new(baseline(), head()).expect("a commit range")),
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(plan_revision(1)),
            )
            .expect("Task 1"),
            if second_started {
                TaskSnapshot::new(
                    task_ref(project_id, 2),
                    TaskProgression::Active,
                    TaskPhase::Stopped,
                    Some(H2SupervisionRef::new(supervision(project_id))),
                    Some(child(project_id)),
                    CommitPolicy::Required,
                    None,
                    None,
                    Vec::new(),
                    Some(
                        herness_sdd_execute::StopRecord::new(
                            StopReason::PlanChanged,
                            Some(HumanAction::ResolvePlanChange),
                        )
                        .expect("a stop"),
                    ),
                    herness_sdd_execute::AppliedRevision::stale(plan_revision(1)),
                )
                .expect("Task 2")
            } else {
                TaskSnapshot::new(
                    task_ref(project_id, 2),
                    TaskProgression::Pending,
                    TaskPhase::Ready,
                    None,
                    None,
                    CommitPolicy::Required,
                    None,
                    None,
                    Vec::new(),
                    None,
                    herness_sdd_execute::AppliedRevision::stale(plan_revision(1)),
                )
                .expect("Task 2")
            },
        ],
        stop: Some(
            herness_sdd_execute::StopRecord::new(
                StopReason::PlanChanged,
                Some(HumanAction::ResolvePlanChange),
            )
            .expect("a stop"),
        ),
        budget: SnapshotBudget::new(
            BudgetConsumption::new(120, 4, None),
            BudgetConsumption::zero(),
        ),
        applied_revision: herness_sdd_execute::AppliedRevision::stale(plan_revision(1)),
        final_project_sequence: None,
    })
    .expect("a stopped snapshot")
}

fn record_snapshot(store: &mut Store, snapshot: &ExecutionSnapshot) {
    store
        .compare_and_swap_execution(
            snapshot.project_id(),
            snapshot.execution_id(),
            None,
            snapshot,
        )
        .expect("the initial snapshot");
}

// ---------------------------------------------------------------------------
// A gate the tests drive directly
// ---------------------------------------------------------------------------

fn expectation_of(approval: &PlanApproval) -> PlanExpectation {
    PlanExpectation::new(
        approval.plan_path().clone(),
        approval.digest().clone(),
        approval.byte_length(),
        approval.plan_revision(),
    )
}

fn plan_gate(
    temp_project: &TempProject,
    clock: &FakeClock,
    latches: MemoryPlanChangeLatchStore,
) -> PlanChangeGate<PlanFileSource, herness_sdd_execute::MemoryPlanChangeLatchStore, FakeClock> {
    let source = PlanFileSource::new(project(), &temp_project.root).expect("a plan source");
    PlanChangeGate::new(source, latches, clock.clone())
}

// ===========================================================================
// 1. Exact bytes, missing, move, unstable
// ===========================================================================

#[test]
fn atomic_save_with_changed_bytes_engages_the_latch() {
    let temp = TempProject::new(&plan_document(
        "Prove the latch.",
        "- keep the plan bytes exact",
        "Write the module.",
        "Write the second module.",
    ));
    let clock = FakeClock::at(now());
    let mut gate = plan_gate(&temp, &clock, Default::default());
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &temp.plan_bytes(),
            constraints: "- keep the plan bytes exact",
            bodies: ["Write the module.", "Write the second module."],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );
    let first = gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("the first check");
    assert!(first.is_proceed(), "an unchanged plan proceeds");

    // One atomic save: a temporary file replaced over the plan path.
    temp.save(&plan_document(
        "Prove the latch.",
        "- keep the plan bytes exact",
        "Write the module, then explain it.",
        "Write the second module.",
    ));

    let blocked = gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("the second check");
    let latch = blocked.latch().expect("the change latched");
    assert_eq!(latch.change().reason(), PlanChangeReason::BytesChanged);
    assert_eq!(latch.change().stop_reason(), StopReason::PlanChanged);
    assert_eq!(latch.state(), LatchState::Open);
    assert_eq!(latch.expectation(), &expectation_of(approved.plan()));

    // The latch is durable, not only in the gate's result.
    let stored = gate
        .latches()
        .plan_change_latch(project(), execution(project()))
        .expect("the latch row")
        .expect("a stored latch");
    assert_eq!(stored, *latch);
    assert_eq!(
        stored.change().observed_digest(),
        Some(PlanDigest::sha256(&temp.plan_bytes())).as_ref()
    );
    assert_ne!(
        stored.change().observed_digest(),
        Some(approved.plan().digest())
    );
    assert_eq!(
        stored.change().observed_byte_length(),
        Some(temp.plan_bytes().len() as u64)
    );
}

#[test]
fn deleted_plan_stops_with_plan_missing() {
    let temp = TempProject::new(&plan_document("Deletion.", "- constraints", "one", "two"));
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &temp.plan_bytes(),
            constraints: "- constraints",
            bodies: ["one", "two"],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );
    let clock = FakeClock::at(now());
    let mut gate = plan_gate(&temp, &clock, Default::default());
    std::fs::remove_file(temp.root.join(PLAN_PATH)).expect("the plan is deleted");

    let blocked = gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a check");
    let latch = blocked.latch().expect("the deletion latched");
    assert_eq!(latch.change().reason(), PlanChangeReason::Missing);
    assert_eq!(latch.change().stop_reason(), StopReason::PlanMissing);
    assert!(latch.change().observed_digest().is_none());
    assert!(latch.change().moved_to().is_none());
}

#[test]
fn moved_plan_reports_the_candidate_path() {
    let temp = TempProject::new(&plan_document("Move.", "- constraints", "one", "two"));
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &temp.plan_bytes(),
            constraints: "- constraints",
            bodies: ["one", "two"],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );
    let clock = FakeClock::at(now());
    let mut gate = plan_gate(&temp, &clock, Default::default());
    gate.note_candidate(other_plan_path());

    // The approved path disappears; a host-observed candidate appears.
    std::fs::rename(
        temp.root.join(PLAN_PATH),
        temp.root.join(other_plan_path().as_str()),
    )
    .expect("the plan is moved");

    let blocked = gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a check");
    let latch = blocked.latch().expect("the move latched");
    assert_eq!(latch.change().reason(), PlanChangeReason::Moved);
    assert_eq!(latch.change().stop_reason(), StopReason::PlanMoved);
    assert_eq!(latch.change().moved_to(), Some(&other_plan_path()));
}

/// A source whose two reads disagree inside one observation window.
struct UnstableSource {
    project_id: ProjectId,
    reads: AtomicUsize,
    stable_digest: PlanDigest,
    stable_length: u64,
}

impl PlanSourcePort for UnstableSource {
    fn read_plan(
        &self,
        _project_id: ProjectId,
        _plan_path: &PlanPath,
    ) -> Result<herness_sdd_execute::PlanSourceRead, SddExecutionError> {
        panic!("the unstable gate must not read the exact bytes");
    }

    fn observe(
        &self,
        project_id: ProjectId,
        _plan_path: &PlanPath,
    ) -> Result<herness_sdd_execute::PlanObservation, SddExecutionError> {
        assert_eq!(project_id, self.project_id);
        let read = self.reads.fetch_add(1, Ordering::SeqCst);
        // The first observation window is unstable: the two inner reads
        // disagreed, so the digest is reported with `stable = false`.
        if read == 0 {
            return Ok(herness_sdd_execute::PlanObservation::observed(
                self.stable_digest.clone(),
                self.stable_length,
                false,
            ));
        }
        Ok(herness_sdd_execute::PlanObservation::observed(
            self.stable_digest.clone(),
            self.stable_length,
            true,
        ))
    }
}

#[test]
fn unstable_observation_stops_the_task() {
    let temp = TempProject::new(&plan_document("Unstable.", "- constraints", "one", "two"));
    let bytes = temp.plan_bytes();
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &bytes,
            constraints: "- constraints",
            bodies: ["one", "two"],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );
    let clock = FakeClock::at(now());
    let source = UnstableSource {
        project_id: project(),
        reads: AtomicUsize::new(0),
        stable_digest: PlanDigest::sha256(&bytes),
        stable_length: bytes.len() as u64,
    };
    let mut gate = PlanChangeGate::new(
        source,
        herness_sdd_execute::MemoryPlanChangeLatchStore::new(),
        clock,
    );
    let blocked = gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a check");
    let latch = blocked.latch().expect("the instability latched");
    assert_eq!(
        latch.change().reason(),
        PlanChangeReason::UnstableObservation
    );
    assert_eq!(
        latch.change().stop_reason(),
        StopReason::PlanObservationUnstable
    );
}

// ===========================================================================
// 2. Prose and Global Constraints changes with an identical JSON block
// ===========================================================================

#[test]
fn prose_only_change_keeps_the_json_block_and_reports_ranges() {
    let temp = TempProject::new(&plan_document(
        "Prove the prose comparison.",
        "- keep the plan bytes exact",
        "Write the module.",
        "Write the second module.",
    ));
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &temp.plan_bytes(),
            constraints: "- keep the plan bytes exact",
            bodies: ["Write the module.", "Write the second module."],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );
    let clock = FakeClock::at(now());
    let mut gate = plan_gate(&temp, &clock, Default::default());
    assert!(
        gate.check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan()
        )
        .expect("a check")
        .is_proceed()
    );

    // The JSON block is byte-identical; only Task 1's prose changed.
    temp.save(&plan_document(
        "Prove the prose comparison.",
        "- keep the plan bytes exact",
        "Write the module, then explain every line.",
        "Write the second module.",
    ));
    let blocked = gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a check");
    let latch = blocked.latch().expect("the prose change latched");
    assert_eq!(latch.change().reason(), PlanChangeReason::BytesChanged);
    assert_eq!(latch.change().json_block(), JsonBlockState::Unknown);
}

#[test]
fn parsed_comparison_reports_an_unchanged_json_block_and_the_changed_ranges() {
    let pack = pack_root();
    let before = plan_document(
        "Prove the parsed comparison.",
        "- keep the constraints exact",
        "Write the module.",
        "Write the second module.",
    );
    let after = plan_document(
        "Prove the parsed comparison.",
        "- keep the constraints exact",
        "Write the module, then explain every line.",
        "Write the second module.",
    );
    let temp = TempProject::new(&before);
    let mut importer = plan_importer(&pack, &temp.root);
    let first = importer.import(&plan_path()).expect("the first preview");
    let previous = first.preview().parsed().clone();
    let previous_bytes = first.source().source().to_vec();

    temp.save(&after);
    let mut importer = plan_importer(&pack, &temp.root);
    let second = importer.import(&plan_path()).expect("the second preview");
    let current = second.preview().parsed().clone();

    let change = PlanChange::compared(
        &previous,
        &previous_bytes,
        &current,
        second.source().source(),
    )
    .expect("a comparison")
    .expect("a change");
    assert_eq!(change.reason(), PlanChangeReason::BytesChanged);
    assert_eq!(change.json_block(), JsonBlockState::Unchanged);
    assert!(!change.global_constraints_changed());
    assert_eq!(change.changed_task_numbers(), [1]);
    assert_eq!(change.ranges().len(), 1);
    let range = change.ranges()[0];
    let body = second.preview().tasks()[0].parsed().body().byte_range();
    assert_eq!(range, body, "the range is the changed Task 1 body");
    let source = second.source().source();
    let sliced = &source[range.start() as usize..range.end() as usize];
    assert!(String::from_utf8_lossy(sliced).contains("explain every line"));
}

#[test]
fn global_constraints_change_is_never_ignored_when_the_json_is_identical() {
    let pack = pack_root();
    let before = plan_document(
        "Prove the constraint comparison.",
        "- keep the constraints exact",
        "one",
        "two",
    );
    let after = plan_document(
        "Prove the constraint comparison.",
        "- keep the constraints exact\n- and never send a secret",
        "one",
        "two",
    );
    let temp = TempProject::new(&before);
    let mut importer = plan_importer(&pack, &temp.root);
    let first = importer.import(&plan_path()).expect("the first preview");
    let previous = first.preview().parsed().clone();
    let previous_bytes = first.source().source().to_vec();

    temp.save(&after);
    let mut importer = plan_importer(&pack, &temp.root);
    let second = importer.import(&plan_path()).expect("the second preview");

    let change = PlanChange::compared(
        &previous,
        &previous_bytes,
        second.preview().parsed(),
        second.source().source(),
    )
    .expect("a comparison")
    .expect("a change");
    assert_eq!(change.json_block(), JsonBlockState::Unchanged);
    assert!(change.global_constraints_changed());
    assert!(
        change
            .ranges()
            .contains(&second.preview().global_constraints().byte_range())
    );
    // The last Task's final checks still match this revision's list.
    assert_eq!(change.changed_task_numbers(), Vec::<u32>::new());
}

// ===========================================================================
// 3. Lost notification, periodic reconcile, and the pre-commit check
// ===========================================================================

#[test]
fn dropped_notification_is_caught_by_the_periodic_reconcile() {
    let temp = TempProject::new(&plan_document(
        "Prove the periodic check.",
        "- constraints",
        "one",
        "two",
    ));
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &temp.plan_bytes(),
            constraints: "- constraints",
            bodies: ["one", "two"],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );
    let clock = FakeClock::at(now());
    let mut gate = plan_gate(&temp, &clock, Default::default());
    assert_eq!(
        ReconcileSchedule::new().interval_millis(),
        herness_sdd_execute::PLAN_RECONCILE_INTERVAL_MILLIS
    );

    // The first reconciliation is always due.
    let first = gate
        .reconcile(
            clock.now(),
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a reconcile")
        .expect("due");
    assert!(first.is_proceed());

    // The plan changes with no notification at all.
    temp.save(&plan_document(
        "Prove the periodic check.",
        "- constraints changed",
        "one",
        "two",
    ));
    // Not yet due.
    clock.advance(999);
    assert!(
        gate.reconcile(
            clock.now(),
            execution(project()),
            approval_id(project()),
            approved.plan()
        )
        .expect("a reconcile")
        .is_none()
    );
    // Due at exactly one second and the change is caught.
    clock.advance(1);
    let due = gate
        .reconcile(
            clock.now(),
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a reconcile")
        .expect("due");
    let latch = due.latch().expect("the change latched");
    assert_eq!(latch.change().reason(), PlanChangeReason::BytesChanged);
}

#[test]
fn a_watcher_notification_makes_the_next_reconcile_immediate() {
    let temp = TempProject::new(&plan_document("Immediate.", "- constraints", "one", "two"));
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &temp.plan_bytes(),
            constraints: "- constraints",
            bodies: ["one", "two"],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );
    let clock = FakeClock::at(now());
    let mut gate = plan_gate(&temp, &clock, Default::default());
    gate.reconcile(
        clock.now(),
        execution(project()),
        approval_id(project()),
        approved.plan(),
    )
    .expect("a reconcile")
    .expect("due");
    // Without a notification the next tick is not due.
    assert!(
        gate.reconcile(
            clock.now(),
            execution(project()),
            approval_id(project()),
            approved.plan()
        )
        .expect("a reconcile")
        .is_none()
    );
    // A notification only brings the tick forward; it never claims the file is
    // unchanged, so the change is still detected.
    temp.save(&plan_document(
        "Immediate.",
        "- constraints changed",
        "one",
        "two",
    ));
    gate.schedule_mut().note_signal();
    let due = gate
        .reconcile(
            clock.now(),
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a reconcile")
        .expect("due after the notification");
    assert!(due.latch().is_some());
}

/// A gate that proceeds on the first call of an advance and blocks on the
/// second, so a test can prove the pre-commit check exists.
struct TwoPhaseGate {
    latch: PlanChangeLatch,
    calls: Arc<AtomicUsize>,
    blocks_at: usize,
}

impl PlanChangeGatePort for TwoPhaseGate {
    fn check_before_side_effect(
        &mut self,
        _execution_id: ExecutionId,
        _approval_id: ApprovalId,
        _approval: &PlanApproval,
    ) -> Result<PlanGateDecision, SddExecutionError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call >= self.blocks_at {
            return Ok(PlanGateDecision::Blocked {
                latch: Box::new(self.latch.clone()),
                restored: false,
            });
        }
        Ok(PlanGateDecision::Proceed)
    }
}

fn latch_fixture(approved: &PlanApproval) -> PlanChangeLatch {
    PlanChangeLatch::engage(
        project(),
        execution(project()),
        approval_id(project()),
        expectation_of(approved),
        PlanChange::from_observation(
            PlanChangeReason::BytesChanged,
            &herness_sdd_execute::PlanObservation::observed(
                approved.digest().clone(),
                approved.byte_length(),
                true,
            ),
            None,
        )
        .expect("a change"),
    )
    .expect("a latch")
}

/// One dispatch/launch/child/completion set of fakes for the coordinator.
struct FakeLaunch;

impl TaskLaunchPort for FakeLaunch {
    fn launch(&mut self, task: TaskRef) -> Result<TaskLaunch, herness_sdd_execute::LaunchRefusal> {
        TaskLaunch::new(
            format!("immutable packet for Task {}", task.number().get()),
            scope(task.project_id()),
            BudgetPolicy::new(600, 5, None).expect("a budget"),
            digest("manifest"),
            digest("packet"),
        )
        .map_err(|error| herness_sdd_execute::LaunchRefusal::Context {
            detail: error.to_string(),
        })
    }
}

struct FakeDispatch {
    requests: usize,
}

impl ChildDispatchPort for FakeDispatch {
    fn dispatch(&mut self, _plan: &ChildDispatchPlan) -> Result<DispatchResult, SddExecutionError> {
        self.requests += 1;
        DispatchResult::new(supervision(project()), child(project()))
    }

    fn reconcile(
        &mut self,
        _project_id: ProjectId,
        _execution_id: ExecutionId,
        _request_id: DispatchRequestId,
    ) -> Result<Option<DispatchResult>, SddExecutionError> {
        Ok(None)
    }
}

struct CompletedChildren;

impl ChildStatusPort for CompletedChildren {
    fn status(
        &mut self,
        _project_id: ProjectId,
        _execution_id: ExecutionId,
        _request_id: DispatchRequestId,
    ) -> Result<Option<ChildStatus>, SddExecutionError> {
        Ok(Some(ChildStatus::new(
            supervision(project()),
            ChildState::Completed,
            10,
            1,
            0,
            false,
            Vec::new(),
        )))
    }
}

/// Counts `complete` calls and never writes a Task.
struct CountingCompletion {
    calls: Arc<AtomicUsize>,
}

impl TaskCompletionPort for CountingCompletion {
    fn wiring(&self, _task: TaskRef) -> herness_sdd_execute::CompletionWiring {
        herness_sdd_execute::CompletionWiring::Connected
    }

    fn complete(
        &mut self,
        _request: &TaskCompletionRequest,
    ) -> Result<TaskCompletion, SddExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(TaskCompletion::Complete {
            commit_range: Some(CommitRange::new(baseline(), head()).expect("a range")),
            no_change: None,
            host_seconds: 1,
        })
    }
}

#[test]
fn post_completion_change_makes_the_application_stale_without_erasing_history() {
    let temp = TempProject::new(&plan_document(
        "Post-completion.",
        "- constraints",
        "one",
        "two",
    ));
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &temp.plan_bytes(),
            constraints: "- constraints",
            bodies: ["one", "two"],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );
    let mut harness = Harness::new();
    harness
        .store
        .record_sdd_approval(&approved)
        .expect("the approval");
    let snapshot = ExecutionSnapshot::new(ready_for_finish_input(
        project(),
        execution(project()),
        approved.plan(),
    ))
    .expect("a ready-for-finish snapshot");
    record_snapshot(&mut harness.store, &snapshot);

    // The change is observed by a gate that blocks.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut gate = TwoPhaseGate {
        latch: latch_fixture(approved.plan()),
        calls,
        blocks_at: 1,
    };
    let mut launch = FakeLaunch;
    let mut dispatch = FakeDispatch { requests: 0 };
    let mut children = CompletedChildren;
    let mut completion = CountingCompletion {
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let mut serial = SerialExecutionState::new();
    let request = CoordinatorRequest::new(
        project(),
        execution(project()),
        control_request(project(), 9),
        ExecutionRevision::INITIAL,
        approval_id(project()),
        1,
    )
    .expect("a request");
    let mut ports = CoordinatorPorts {
        store: &mut harness.store,
        launch: &mut launch,
        dispatch: &mut dispatch,
        children: &mut children,
        completion: &mut completion,
        serial: &mut serial,
        plan_change: Some(&mut gate),
        child_stop: None,
    };
    let outcome =
        herness_sdd_execute::TaskCoordinator::advance(&mut ports, &request).expect("an advance");
    assert!(
        matches!(outcome, CoordinatorOutcome::PlanChanged { .. }),
        "a post-completion change stops the finish handoff"
    );

    // History and budget are complete and unchanged; only the applied revision is
    // stale and the execution waits for a human.
    let stored = harness.snapshot();
    assert_eq!(stored.state(), ExecutionState::WaitingHuman);
    assert_eq!(
        stored.applied_revision().state(),
        herness_sdd_execute::AppliedRevisionState::Stale
    );
    assert_eq!(
        stored.stop().expect("a stop").required_action(),
        Some(HumanAction::ResolvePlanChange)
    );
    assert_eq!(stored.budget().consumed().active_seconds(), 300);
    for number in 1..=2 {
        let task = stored
            .task(TaskNumber::new(number).expect("a number"))
            .expect("a Task");
        assert_eq!(task.progression(), TaskProgression::Complete);
        assert_eq!(
            task.commit_range().expect("a range").full_range(),
            format!("{}..{}", baseline(), head())
        );
    }
}

#[test]
fn change_immediately_before_commit_blocks_the_commit_with_zero_commits() {
    let temp = TempProject::new(&plan_document(
        "Prove the pre-commit check.",
        "- constraints",
        "one",
        "two",
    ));
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &temp.plan_bytes(),
            constraints: "- constraints",
            bodies: ["one", "two"],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );
    let mut harness = Harness::new();
    harness
        .store
        .record_sdd_approval(&approved)
        .expect("the approval");
    let snapshot = ExecutionSnapshot::new(snapshot_input_for_approval(
        project(),
        execution(project()),
        approved.plan(),
    ))
    .expect("a running snapshot");
    record_snapshot(&mut harness.store, &snapshot);

    // Call 1 is the top-of-advance check, call 2 the verification acceptance,
    // and call 3 the check immediately before the host commit.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut gate = TwoPhaseGate {
        latch: latch_fixture(approved.plan()),
        calls: Arc::clone(&calls),
        blocks_at: 3,
    };
    let mut launch = FakeLaunch;
    let mut dispatch = FakeDispatch { requests: 0 };
    let mut children = CompletedChildren;
    let commit_calls = Arc::new(AtomicUsize::new(0));
    let mut completion = CountingCompletion {
        calls: Arc::clone(&commit_calls),
    };
    let mut serial = SerialExecutionState::new();
    let request = CoordinatorRequest::new(
        project(),
        execution(project()),
        control_request(project(), 1),
        ExecutionRevision::INITIAL,
        approval_id(project()),
        1,
    )
    .expect("a request");
    let mut ports = CoordinatorPorts {
        store: &mut harness.store,
        launch: &mut launch,
        dispatch: &mut dispatch,
        children: &mut children,
        completion: &mut completion,
        serial: &mut serial,
        plan_change: Some(&mut gate),
        child_stop: None,
    };
    let outcome =
        herness_sdd_execute::TaskCoordinator::advance(&mut ports, &request).expect("an advance");
    match outcome {
        CoordinatorOutcome::PlanChanged {
            change, restored, ..
        } => {
            assert_eq!(change.reason(), PlanChangeReason::BytesChanged);
            assert!(!restored);
        }
        other => panic!("expected a plan-change stop, found {other:?}"),
    }
    assert_eq!(
        commit_calls.load(Ordering::SeqCst),
        0,
        "a change before the commit creates no commit and no completion"
    );
    assert_eq!(dispatch.requests, 0, "the Task was already dispatched");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "dispatch, verification, and the pre-commit check each observed the plan"
    );

    // The durable state holds the plan stop and keeps the recorded budget.
    let stored = harness.snapshot();
    assert_eq!(stored.state(), ExecutionState::WaitingHuman);
    assert_eq!(
        stored.stop().expect("a stop").reason(),
        StopReason::PlanChanged
    );
    assert_eq!(stored.budget().consumed().active_seconds(), 120);
    assert_eq!(stored.budget().consumed().additional_runs(), 4);
}

fn snapshot_input_for_approval(
    project_id: ProjectId,
    execution_id: ExecutionId,
    plan: &PlanApproval,
) -> SnapshotInput {
    SnapshotInput {
        project_id,
        execution_id,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Running,
        plan: SnapshotPlan::new(
            plan.plan_path().clone(),
            plan.digest().clone(),
            plan.plan_revision(),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, BRANCH, BASE_BRANCH, Some(baseline()))
            .expect("a snapshot workspace"),
        current_task: Some(task_ref(project_id, 1)),
        tasks: vec![
            TaskSnapshot::new(
                task_ref(project_id, 1),
                TaskProgression::Active,
                TaskPhase::Running,
                Some(H2SupervisionRef::new(supervision(project_id))),
                Some(child(project_id)),
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(plan.plan_revision()),
            )
            .expect("Task 1"),
            TaskSnapshot::new(
                task_ref(project_id, 2),
                TaskProgression::Pending,
                TaskPhase::Ready,
                None,
                None,
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(plan.plan_revision()),
            )
            .expect("Task 2"),
        ],
        stop: None,
        budget: SnapshotBudget::new(
            BudgetConsumption::new(120, 4, None),
            BudgetConsumption::zero(),
        ),
        applied_revision: herness_sdd_execute::AppliedRevision::current(plan.plan_revision()),
        final_project_sequence: None,
    }
}

/// The same snapshot after every Task completed: a ready-for-finish execution.
fn ready_for_finish_input(
    project_id: ProjectId,
    execution_id: ExecutionId,
    plan: &PlanApproval,
) -> SnapshotInput {
    SnapshotInput {
        project_id,
        execution_id,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::ReadyForFinish,
        plan: SnapshotPlan::new(
            plan.plan_path().clone(),
            plan.digest().clone(),
            plan.plan_revision(),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, BRANCH, BASE_BRANCH, Some(baseline()))
            .expect("a snapshot workspace"),
        current_task: None,
        tasks: vec![
            TaskSnapshot::new(
                task_ref(project_id, 1),
                TaskProgression::Complete,
                TaskPhase::Complete,
                Some(H2SupervisionRef::new(supervision(project_id))),
                Some(child(project_id)),
                CommitPolicy::Required,
                Some(CommitRange::new(baseline(), head()).expect("a commit range")),
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(plan.plan_revision()),
            )
            .expect("Task 1"),
            TaskSnapshot::new(
                task_ref(project_id, 2),
                TaskProgression::Complete,
                TaskPhase::Complete,
                Some(H2SupervisionRef::new(supervision(project_id))),
                Some(child(project_id)),
                CommitPolicy::Required,
                Some(CommitRange::new(baseline(), head()).expect("a commit range")),
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(plan.plan_revision()),
            )
            .expect("Task 2"),
        ],
        stop: None,
        budget: SnapshotBudget::new(
            BudgetConsumption::new(300, 6, None),
            BudgetConsumption::zero(),
        ),
        applied_revision: herness_sdd_execute::AppliedRevision::current(plan.plan_revision()),
        final_project_sequence: None,
    }
}

// ===========================================================================
// 4. Returning to the same bytes never clears the latch
// ===========================================================================

#[test]
fn returning_to_the_same_bytes_does_not_clear_the_latch() {
    let approved_bytes = plan_document("Prove the latch is sticky.", "- constraints", "one", "two");
    let temp = TempProject::new(&approved_bytes);
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &approved_bytes,
            constraints: "- constraints",
            bodies: ["one", "two"],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );
    let clock = FakeClock::at(now());
    let mut gate = plan_gate(&temp, &clock, Default::default());

    temp.save(&plan_document(
        "Prove the latch is sticky.",
        "- constraints",
        "one changed",
        "two",
    ));
    let blocked = gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a check");
    assert!(blocked.latch().is_some());

    // A byte-exact restore. The file is approved again, the latch is not.
    temp.save(&approved_bytes);
    let again = gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a check");
    match again {
        PlanGateDecision::Blocked { latch, restored } => {
            assert!(restored, "the observation reports the restore");
            assert!(latch.is_open(), "the latch stays open");
            assert_eq!(latch.change().reason(), PlanChangeReason::BytesChanged);
        }
        other => panic!("expected a blocking latch, found {other:?}"),
    }
}

// ===========================================================================
// 5. Limited re-approval
// ===========================================================================

fn approval_inputs(content: &ApprovalContent) -> ApprovalInputs {
    ApprovalInputs::new(
        content.plan().clone(),
        content.workspace().clone(),
        content.tasks().to_vec(),
        ObservedConnection::from_approved(
            content.connection(),
            content.connection().consents().to_vec(),
        ),
        content.commit(),
        Some(content.h3().clone()),
    )
}

#[test]
fn inheritable_change_is_approved_and_keeps_the_consumed_budget_and_history() {
    let harness = Harness::new();
    let mut store = harness.store;
    let project_id = harness.project;
    let execution_id = harness.execution;

    let bytes = plan_document("Inherit.", "- constraints", "one", "two");
    let first = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(1),
        source: &bytes,
        constraints: "- constraints",
        bodies: ["one", "two"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let approved = approval(project_id, 1, first.clone());
    store.record_sdd_approval(&approved).expect("the approval");
    let mut stopped = stopped_snapshot_with(
        project_id,
        execution_id,
        ExecutionRevision::INITIAL,
        first.plan(),
        false,
    );
    record_snapshot(&mut store, &stopped);
    let latch = PlanChangeLatch::engage(
        project_id,
        execution_id,
        approval_id(project_id),
        expectation_of(first.plan()),
        PlanChange::from_observation(
            PlanChangeReason::BytesChanged,
            &herness_sdd_execute::PlanObservation::observed(
                first.plan().digest().clone(),
                first.plan().byte_length(),
                true,
            ),
            None,
        )
        .expect("a change"),
    )
    .expect("a latch");
    store
        .record_plan_change_latch(&latch)
        .expect("the latch row");

    // Only Task 2, not yet started, changes.
    let next_bytes = plan_document("Inherit.", "- constraints", "one", "two changed");
    let next = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(2),
        source: &next_bytes,
        constraints: "- constraints",
        bodies: ["one", "two changed"],
        rubric_one: "one",
        rubric_two: "two updated",
    });
    let inputs = approval_inputs(&next);
    let post = StartApprovalPost::new(
        approval_id(project_id),
        now(),
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry {
            approval_id: approval_id(project_id),
        },
        next.clone(),
        inputs.clone(),
    )
    .expect("a human post");
    let request = PlanRevisionApproval::new(
        project_id,
        execution_id,
        control_request(project_id, 2),
        ExecutionRevision::INITIAL,
        approval_id(project_id),
        1,
        &post,
    )
    .expect("a re-approval request");

    let outcome = approve_plan_revision(&mut store, &request, &inputs).expect("a re-approval");
    let PlanRevisionOutcome::Approved {
        approval,
        snapshot,
        revision,
        inheritance,
    } = outcome
    else {
        panic!("expected an approval, found {outcome:?}");
    };
    assert!(inheritance.is_inheritable());
    assert_eq!(
        approval.revision(),
        2,
        "the approval revision advanced once"
    );
    assert_eq!(revision, ExecutionRevision::INITIAL.next());
    assert_eq!(snapshot.plan().approved_revision(), plan_revision(2));
    assert_eq!(snapshot.state(), ExecutionState::Stopped);
    assert_eq!(
        snapshot.applied_revision().state(),
        herness_sdd_execute::AppliedRevisionState::Current
    );

    // Consumed budget and recorded history are kept.
    assert_eq!(snapshot.budget().consumed().active_seconds(), 120);
    assert_eq!(snapshot.budget().consumed().additional_runs(), 4);
    let task_one = snapshot
        .task(TaskNumber::new(1).expect("a number"))
        .expect("Task 1");
    assert_eq!(task_one.progression(), TaskProgression::Complete);
    assert_eq!(
        task_one.commit_range().expect("a range").full_range(),
        format!("{}..{}", baseline(), head())
    );
    let task_two = snapshot
        .task(TaskNumber::new(2).expect("a number"))
        .expect("Task 2");
    assert_eq!(task_two.progression(), TaskProgression::Pending);
    assert_eq!(task_two.phase(), TaskPhase::Ready);
    assert_eq!(snapshot.budget().consumed().active_seconds(), 120);

    // The latch is cleared with the approved revision.
    let stored_latch = store
        .sdd_plan_change_latch(project_id, execution_id)
        .expect("the latch row")
        .expect("a latch");
    assert_eq!(
        stored_latch.state(),
        LatchState::Cleared {
            approval_revision: 2,
            plan_revision: plan_revision(2),
        }
    );
    // Nothing runs before a human resume: the state is still `stopped`.
    stopped = snapshot.as_ref().clone();
    assert_eq!(stopped.state(), ExecutionState::Stopped);
    assert!(stopped.stop().is_some());
}

#[test]
fn started_task_modification_is_refused_and_writes_nothing() {
    let harness = Harness::new();
    let mut store = harness.store;
    let project_id = harness.project;
    let execution_id = harness.execution;

    let bytes = plan_document("Started.", "- constraints", "one", "two");
    let first = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(1),
        source: &bytes,
        constraints: "- constraints",
        bodies: ["one", "two"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let approved = approval(project_id, 1, first.clone());
    store.record_sdd_approval(&approved).expect("the approval");
    record_snapshot(
        &mut store,
        &stopped_snapshot(
            project_id,
            execution_id,
            ExecutionRevision::INITIAL,
            first.plan(),
        ),
    );
    let latch = PlanChangeLatch::engage(
        project_id,
        execution_id,
        approval_id(project_id),
        expectation_of(first.plan()),
        PlanChange::from_observation(
            PlanChangeReason::BytesChanged,
            &herness_sdd_execute::PlanObservation::observed(
                first.plan().digest().clone(),
                first.plan().byte_length(),
                true,
            ),
            None,
        )
        .expect("a change"),
    )
    .expect("a latch");
    store
        .record_plan_change_latch(&latch)
        .expect("the latch row");

    // Task 1 is complete; its contract must not change.
    let next_bytes = plan_document("Started.", "- constraints", "one", "two");
    let next = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(2),
        source: &next_bytes,
        constraints: "- constraints",
        bodies: ["one", "two"],
        rubric_one: "one",
        rubric_two: "a different rubric",
    });
    let inputs = approval_inputs(&next);
    let post = StartApprovalPost::new(
        approval_id(project_id),
        now(),
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry {
            approval_id: approval_id(project_id),
        },
        next.clone(),
        inputs.clone(),
    )
    .expect("a human post");
    let request = PlanRevisionApproval::new(
        project_id,
        execution_id,
        control_request(project_id, 3),
        ExecutionRevision::INITIAL,
        approval_id(project_id),
        1,
        &post,
    )
    .expect("a re-approval request");

    let outcome = approve_plan_revision(&mut store, &request, &inputs).expect("a decision");
    match outcome {
        PlanRevisionOutcome::Refused { blockers, latch } => {
            assert!(latch.is_open(), "the safety stop remains");
            assert_eq!(
                blockers,
                vec![PlanInheritanceBlocker::TaskChanged {
                    number: 2,
                    progression: TaskProgression::Active,
                    part: herness_sdd_execute::ContractPart::Conditions,
                }]
            );
        }
        other => panic!("expected a refusal, found {other:?}"),
    }

    // Nothing was written: one approval revision, the same latch, the same state.
    assert_eq!(
        store
            .sdd_approval_revisions(project_id, approval_id(project_id))
            .expect("the revisions")
            .len(),
        1
    );
    assert!(
        store
            .sdd_plan_change_latch(project_id, execution_id)
            .expect("the latch row")
            .expect("a latch")
            .is_open()
    );
    assert_eq!(
        store
            .load_sdd_execution(project_id, execution_id)
            .expect("load")
            .expect("a snapshot")
            .revision(),
        ExecutionRevision::INITIAL
    );
}

#[test]
fn duplicate_re_approval_returns_the_stored_result_and_one_revision() {
    let harness = Harness::new();
    let mut store = harness.store;
    let project_id = harness.project;
    let execution_id = harness.execution;

    let bytes = plan_document("Duplicate.", "- constraints", "one", "two");
    let first = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(1),
        source: &bytes,
        constraints: "- constraints",
        bodies: ["one", "two"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let approved = approval(project_id, 1, first.clone());
    store.record_sdd_approval(&approved).expect("the approval");
    record_snapshot(
        &mut store,
        &stopped_snapshot_with(
            project_id,
            execution_id,
            ExecutionRevision::INITIAL,
            first.plan(),
            false,
        ),
    );
    let latch = PlanChangeLatch::engage(
        project_id,
        execution_id,
        approval_id(project_id),
        expectation_of(first.plan()),
        PlanChange::from_observation(
            PlanChangeReason::BytesChanged,
            &herness_sdd_execute::PlanObservation::observed(
                first.plan().digest().clone(),
                first.plan().byte_length(),
                true,
            ),
            None,
        )
        .expect("a change"),
    )
    .expect("a latch");
    store
        .record_plan_change_latch(&latch)
        .expect("the latch row");

    let next_bytes = plan_document("Duplicate.", "- constraints", "one", "two changed");
    let next = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(2),
        source: &next_bytes,
        constraints: "- constraints",
        bodies: ["one", "two changed"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let inputs = approval_inputs(&next);
    let post = StartApprovalPost::new(
        approval_id(project_id),
        now(),
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry {
            approval_id: approval_id(project_id),
        },
        next.clone(),
        inputs.clone(),
    )
    .expect("a human post");
    let request = PlanRevisionApproval::new(
        project_id,
        execution_id,
        control_request(project_id, 4),
        ExecutionRevision::INITIAL,
        approval_id(project_id),
        1,
        &post,
    )
    .expect("a re-approval request");

    let first_outcome = approve_plan_revision(&mut store, &request, &inputs).expect("the approval");
    let PlanRevisionOutcome::Approved { revision, .. } = first_outcome else {
        panic!("the first request is approved");
    };
    let second_outcome = approve_plan_revision(&mut store, &request, &inputs).expect("the replay");
    match second_outcome {
        PlanRevisionOutcome::Replayed {
            revision: replayed,
            approval_revision,
        } => {
            assert_eq!(replayed, revision);
            assert_eq!(approval_revision, 2);
        }
        other => panic!("expected a replay, found {other:?}"),
    }

    // Exactly one new approval revision and one execution write.
    assert_eq!(
        store
            .sdd_approval_revisions(project_id, approval_id(project_id))
            .expect("the revisions")
            .len(),
        2
    );
    assert_eq!(
        store
            .load_sdd_execution(project_id, execution_id)
            .expect("load")
            .expect("a snapshot")
            .revision(),
        revision
    );
}

#[test]
fn re_approval_before_a_confirmed_stop_is_refused() {
    let harness = Harness::new();
    let mut store = harness.store;
    let project_id = harness.project;
    let execution_id = harness.execution;

    let bytes = plan_document("Unconfirmed.", "- constraints", "one", "two");
    let first = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(1),
        source: &bytes,
        constraints: "- constraints",
        bodies: ["one", "two"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let approved = approval(project_id, 1, first.clone());
    store.record_sdd_approval(&approved).expect("the approval");
    // A stop that is only requested/held, never confirmed.
    let mut running = running_snapshot(project_id, execution_id);
    running = ExecutionSnapshot::new(SnapshotInput {
        project_id,
        execution_id,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::WaitingHuman,
        plan: SnapshotPlan::new(
            first.plan().plan_path().clone(),
            first.plan().digest().clone(),
            first.plan().plan_revision(),
        ),
        workspace: SnapshotWorkspace::new(CHECKOUT, BRANCH, BASE_BRANCH, Some(baseline()))
            .expect("a snapshot workspace"),
        current_task: Some(task_ref(project_id, 1)),
        tasks: running.tasks().to_vec(),
        stop: Some(
            herness_sdd_execute::StopRecord::new(
                StopReason::PlanChanged,
                Some(HumanAction::ResolvePlanChange),
            )
            .expect("a stop"),
        ),
        budget: running.budget(),
        applied_revision: herness_sdd_execute::AppliedRevision::stale(plan_revision(1)),
        final_project_sequence: None,
    })
    .expect("a held snapshot");
    record_snapshot(&mut store, &running);
    let latch = PlanChangeLatch::engage(
        project_id,
        execution_id,
        approval_id(project_id),
        expectation_of(first.plan()),
        PlanChange::from_observation(
            PlanChangeReason::BytesChanged,
            &herness_sdd_execute::PlanObservation::observed(
                first.plan().digest().clone(),
                first.plan().byte_length(),
                true,
            ),
            None,
        )
        .expect("a change"),
    )
    .expect("a latch");
    store
        .record_plan_change_latch(&latch)
        .expect("the latch row");

    let next_bytes = plan_document("Unconfirmed.", "- constraints", "one", "two changed");
    let next = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(2),
        source: &next_bytes,
        constraints: "- constraints",
        bodies: ["one", "two changed"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let inputs = approval_inputs(&next);
    let post = StartApprovalPost::new(
        approval_id(project_id),
        now(),
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry {
            approval_id: approval_id(project_id),
        },
        next.clone(),
        inputs.clone(),
    )
    .expect("a human post");
    let request = PlanRevisionApproval::new(
        project_id,
        execution_id,
        control_request(project_id, 5),
        ExecutionRevision::INITIAL,
        approval_id(project_id),
        1,
        &post,
    )
    .expect("a re-approval request");

    let error = approve_plan_revision(&mut store, &request, &inputs)
        .expect_err("an unconfirmed stop cannot be re-approved");
    assert!(matches!(
        error,
        SddExecutionError::RecoveryRequired {
            reason: herness_sdd_execute::RecoveryReason::StopUnconfirmed,
            ..
        }
    ));
    assert!(
        store
            .sdd_plan_change_latch(project_id, execution_id)
            .expect("the latch row")
            .expect("a latch")
            .is_open()
    );
}

#[test]
fn confirmed_stop_is_idempotent_and_required_before_re_approval() {
    let harness = Harness::new();
    let mut store = harness.store;
    let project_id = harness.project;
    let execution_id = harness.execution;
    let held = ExecutionSnapshot::new(SnapshotInput {
        project_id,
        execution_id,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::WaitingHuman,
        plan: SnapshotPlan::new(plan_path(), PlanDigest::sha256(b"plan"), plan_revision(1)),
        workspace: SnapshotWorkspace::new(CHECKOUT, BRANCH, BASE_BRANCH, Some(baseline()))
            .expect("a snapshot workspace"),
        current_task: Some(task_ref(project_id, 1)),
        tasks: vec![
            TaskSnapshot::new(
                task_ref(project_id, 1),
                TaskProgression::Active,
                TaskPhase::Running,
                Some(H2SupervisionRef::new(supervision(project_id))),
                Some(child(project_id)),
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::stale(plan_revision(1)),
            )
            .expect("Task 1"),
        ],
        stop: Some(
            herness_sdd_execute::StopRecord::new(
                StopReason::PlanMissing,
                Some(HumanAction::ResolvePlanChange),
            )
            .expect("a stop"),
        ),
        budget: SnapshotBudget::new(
            BudgetConsumption::new(90, 3, None),
            BudgetConsumption::zero(),
        ),
        applied_revision: herness_sdd_execute::AppliedRevision::stale(plan_revision(1)),
        final_project_sequence: None,
    })
    .expect("a held snapshot");
    record_snapshot(&mut store, &held);

    let request = control_request(project_id, 6);
    let confirmed = confirm_plan_change_stop(&mut store, &held, request).expect("a confirmed stop");
    assert_eq!(confirmed.state(), ExecutionState::Stopped);
    assert_eq!(
        confirmed.stop().expect("a stop").reason(),
        StopReason::PlanMissing
    );
    assert_eq!(confirmed.budget().consumed().active_seconds(), 90);

    // A re-delivered confirmation returns the same stored result.
    let again = confirm_plan_change_stop(&mut store, &held, request).expect("a replay");
    assert_eq!(again, confirmed);
    assert_eq!(
        store
            .load_sdd_execution(project_id, execution_id)
            .expect("load")
            .expect("a snapshot")
            .revision(),
        confirmed.revision()
    );
}

#[test]
fn completed_task_modification_is_refused_and_needs_a_new_plan() {
    let harness = Harness::new();
    let mut store = harness.store;
    let project_id = harness.project;
    let execution_id = harness.execution;

    let bytes = plan_document("Completed.", "- constraints", "one", "two");
    let first = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(1),
        source: &bytes,
        constraints: "- constraints",
        bodies: ["one", "two"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let approved = approval(project_id, 1, first.clone());
    store.record_sdd_approval(&approved).expect("the approval");
    // Task 1 is complete, Task 2 is started and stopped.
    record_snapshot(
        &mut store,
        &stopped_snapshot_with(
            project_id,
            execution_id,
            ExecutionRevision::INITIAL,
            first.plan(),
            true,
        ),
    );
    let latch = PlanChangeLatch::engage(
        project_id,
        execution_id,
        approval_id(project_id),
        expectation_of(first.plan()),
        PlanChange::from_observation(
            PlanChangeReason::BytesChanged,
            &herness_sdd_execute::PlanObservation::observed(
                first.plan().digest().clone(),
                first.plan().byte_length(),
                true,
            ),
            None,
        )
        .expect("a change"),
    )
    .expect("a latch");
    store
        .record_plan_change_latch(&latch)
        .expect("the latch row");

    // The completed Task 1's structured contract changes.
    let next_bytes = plan_document("Completed.", "- constraints", "one", "two");
    let next = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(2),
        source: &next_bytes,
        constraints: "- constraints",
        bodies: ["one", "two"],
        rubric_one: "a rewritten rubric",
        rubric_two: "two",
    });
    let inputs = approval_inputs(&next);
    let post = StartApprovalPost::new(
        approval_id(project_id),
        now(),
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry {
            approval_id: approval_id(project_id),
        },
        next.clone(),
        inputs.clone(),
    )
    .expect("a human post");
    let request = PlanRevisionApproval::new(
        project_id,
        execution_id,
        control_request(project_id, 7),
        ExecutionRevision::INITIAL,
        approval_id(project_id),
        1,
        &post,
    )
    .expect("a re-approval request");

    let outcome = approve_plan_revision(&mut store, &request, &inputs).expect("a decision");
    let PlanRevisionOutcome::Refused { blockers, .. } = outcome else {
        panic!("a completed Task's change must never be automatic");
    };
    assert!(blockers.contains(&PlanInheritanceBlocker::TaskChanged {
        number: 1,
        progression: TaskProgression::Complete,
        part: herness_sdd_execute::ContractPart::Conditions,
    }));
    // History and budget are untouched by the refusal.
    let snapshot = store
        .load_sdd_execution(project_id, execution_id)
        .expect("load")
        .expect("a snapshot")
        .snapshot()
        .clone();
    assert_eq!(snapshot.budget().consumed().active_seconds(), 120);
    assert_eq!(
        snapshot
            .task(TaskNumber::new(1).expect("a number"))
            .expect("Task 1")
            .commit_range()
            .expect("a range")
            .full_range(),
        format!("{}..{}", baseline(), head())
    );
    assert_eq!(
        store
            .sdd_approval_revisions(project_id, approval_id(project_id))
            .expect("the revisions")
            .len(),
        1,
        "a refusal writes no approval revision"
    );
}

#[test]
fn re_approved_execution_continues_with_the_consumed_budget_and_a_new_stop() {
    let harness = Harness::new();
    let mut store = harness.store;
    let project_id = harness.project;
    let execution_id = harness.execution;

    let bytes = plan_document("Continue.", "- constraints", "one", "two");
    let first = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(1),
        source: &bytes,
        constraints: "- constraints",
        bodies: ["one", "two"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let approved = approval(project_id, 1, first.clone());
    store.record_sdd_approval(&approved).expect("the approval");
    record_snapshot(
        &mut store,
        &stopped_snapshot_with(
            project_id,
            execution_id,
            ExecutionRevision::INITIAL,
            first.plan(),
            false,
        ),
    );
    let latch = PlanChangeLatch::engage(
        project_id,
        execution_id,
        approval_id(project_id),
        expectation_of(first.plan()),
        PlanChange::from_observation(
            PlanChangeReason::BytesChanged,
            &herness_sdd_execute::PlanObservation::observed(
                first.plan().digest().clone(),
                first.plan().byte_length(),
                true,
            ),
            None,
        )
        .expect("a change"),
    )
    .expect("a latch");
    store
        .record_plan_change_latch(&latch)
        .expect("the latch row");

    let next_bytes = plan_document("Continue.", "- constraints", "one", "two changed");
    let next = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(2),
        source: &next_bytes,
        constraints: "- constraints",
        bodies: ["one", "two changed"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let inputs = approval_inputs(&next);
    let post = StartApprovalPost::new(
        approval_id(project_id),
        now(),
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry {
            approval_id: approval_id(project_id),
        },
        next.clone(),
        inputs.clone(),
    )
    .expect("a human post");
    let request = PlanRevisionApproval::new(
        project_id,
        execution_id,
        control_request(project_id, 8),
        ExecutionRevision::INITIAL,
        approval_id(project_id),
        1,
        &post,
    )
    .expect("a re-approval request");
    let PlanRevisionOutcome::Approved { snapshot, .. } =
        approve_plan_revision(&mut store, &request, &inputs).expect("the approval")
    else {
        panic!("the pending-only change is inheritable");
    };

    // The re-approved execution keeps its consumed budget and its Task 1 range,
    // and it still needs an explicit human resume before the next Task starts.
    assert_eq!(snapshot.budget().consumed().active_seconds(), 120);
    assert_eq!(snapshot.budget().consumed().additional_runs(), 4);
    assert_eq!(snapshot.state(), ExecutionState::Stopped);
    assert_eq!(
        snapshot
            .task(TaskNumber::new(1).expect("a number"))
            .expect("Task 1")
            .progression(),
        TaskProgression::Complete
    );

    // A later change re-engages a new open latch against the new revision; the
    // old clearance is history, not a permanent exemption.
    let cleared = store
        .sdd_plan_change_latch(project_id, execution_id)
        .expect("the latch row")
        .expect("a latch");
    assert!(cleared.is_cleared());
    let next_latch = PlanChangeLatch::engage(
        project_id,
        execution_id,
        approval_id(project_id),
        PlanExpectation::new(
            next.plan().plan_path().clone(),
            next.plan().digest().clone(),
            next.plan().byte_length(),
            next.plan().plan_revision(),
        ),
        PlanChange::from_observation(
            PlanChangeReason::BytesChanged,
            &herness_sdd_execute::PlanObservation::observed(
                next.plan().digest().clone(),
                next.plan().byte_length(),
                true,
            ),
            None,
        )
        .expect("a change"),
    )
    .expect("a latch");
    store
        .record_plan_change_latch(&next_latch)
        .expect("the new latch");
    assert!(
        store
            .sdd_plan_change_latch(project_id, execution_id)
            .expect("the latch row")
            .expect("a latch")
            .is_open()
    );
}

// ===========================================================================
// 6. Inheritance rules
// ===========================================================================

#[test]
fn inheritance_allows_only_pending_changes_and_requires_every_fixed_part() {
    let project_id = project();
    let bytes = b"# plan";
    let mut previous = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(1),
        source: bytes,
        constraints: "- constraints",
        bodies: ["one", "two"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let progress = vec![
        TaskProgress::new(1, TaskProgression::Complete),
        TaskProgress::new(2, TaskProgression::Pending),
    ];

    // A pending-only body change is inheritable.
    let pending = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(2),
        source: bytes,
        constraints: "- constraints",
        bodies: ["one", "two changed"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let decision = evaluate_inheritance(&previous, &pending, &progress);
    assert!(decision.is_inheritable());
    let herness_sdd_execute::PlanInheritance::Inheritable(revision) = decision else {
        unreachable!()
    };
    assert_eq!(revision.changed_tasks(), [2]);

    // Global Constraints are never inheritable when they change.
    let constraints = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(2),
        source: bytes,
        constraints: "- constraints changed",
        bodies: ["one", "two"],
        rubric_one: "one",
        rubric_two: "two",
    });
    let decision = evaluate_inheritance(&previous, &constraints, &progress);
    assert!(!decision.is_inheritable());
    assert!(matches!(
        decision.blockers()[0],
        PlanInheritanceBlocker::GlobalConstraintsChanged { .. }
    ));

    // A completed Task's rubric is never inheritable.
    let completed = content(ContentSpec {
        project_id,
        plan_revision: plan_revision(2),
        source: bytes,
        constraints: "- constraints",
        bodies: ["one", "two"],
        rubric_one: "one changed",
        rubric_two: "two",
    });
    let decision = evaluate_inheritance(&previous, &completed, &progress);
    assert!(!decision.is_inheritable());

    previous = pending;
    // The root spec reference list is fixed.
    let spec_changed = ApprovalContent::new(
        PlanApproval::new(
            plan_path(),
            ExactPlanBytes::new(bytes.to_vec()).expect("the exact bytes"),
            plan_revision(3),
            parsed_summary("- constraints", &["one", "two changed"], ""),
            vec![
                ApprovedSpecRef::new(
                    "project",
                    SPEC_PATH,
                    vec!["Another section".to_owned()],
                    digest("spec"),
                )
                .expect("a spec reference"),
            ],
            Vec::new(),
            PackApproval::new(
                InspectorProtocol::expected(),
                1,
                PackFingerprint::parse(format!("sha256:{}", "a".repeat(64)))
                    .expect("a fingerprint"),
            )
            .expect("a pack approval"),
        )
        .expect("a plan approval"),
        workspace_approval(project_id),
        vec![
            task_approval(project_id, 1, "one"),
            task_approval(project_id, 2, "two"),
        ],
        connection(project_id),
        CommitAuthorization::new(true, true).expect("a commit authorization"),
        h3(),
    )
    .expect("an approval content");
    let decision = evaluate_inheritance(&previous, &spec_changed, &progress);
    assert!(
        decision
            .blockers()
            .iter()
            .any(|blocker| matches!(blocker, PlanInheritanceBlocker::RootSpecRefsChanged { .. }))
    );
}

// ===========================================================================
// 7. Desktop watcher
// ===========================================================================

#[test]
fn desktop_watcher_reports_an_atomic_save_of_the_plan() {
    let temp = TempProject::new(&plan_document("Watch.", "- constraints", "one", "two"));
    let (sender, receiver): (_, Receiver<PlanWatchNotice>) = std::sync::mpsc::channel();
    let mut watcher =
        PlanFileWatcher::start(&temp.root, &plan_path(), sender).expect("a plan watcher");
    assert!(watcher.is_watching());

    // An atomic save replaces the directory entry; the watched directory still
    // reports the change.
    temp.save(&plan_document(
        "Watch.",
        "- constraints",
        "one changed",
        "two",
    ));
    let notice = receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the watcher reported the save");
    assert_eq!(notice, PlanWatchNotice::Changed);

    watcher.stop();
    assert!(!watcher.is_watching());
}

#[test]
fn desktop_gate_persists_the_latch_across_a_reopened_store() {
    use herness_desktop::sdd_execute::{LatchStore, PlanChangeWiring};
    use std::sync::{Arc, Mutex};

    let temp = TempProject::new(&plan_document("Persist.", "- constraints", "one", "two"));
    let bytes = temp.plan_bytes();
    let approved = approval(
        project(),
        1,
        content(ContentSpec {
            project_id: project(),
            plan_revision: plan_revision(1),
            source: &bytes,
            constraints: "- constraints",
            bodies: ["one", "two"],
            rubric_one: "one",
            rubric_two: "two",
        }),
    );

    let store_dir = TempDir::new().expect("a store directory");
    let config =
        StoreConfig::new(store_dir.path().join("app-data")).expect("a store configuration");
    let store = Arc::new(Mutex::new(Store::open(config.clone()).expect("a store")));
    let handle = herness_desktop::supervision::store::StoreHandle::new(Arc::clone(&store));
    let mut wiring = PlanChangeWiring::new(project(), &temp.root, handle.clone())
        .expect("the plan-change wiring");

    let before = wiring
        .gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a check");
    assert!(before.is_proceed());

    temp.save(&plan_document(
        "Persist.",
        "- constraints",
        "one changed",
        "two",
    ));
    let blocked = wiring
        .gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a check");
    assert!(blocked.latch().is_some());
    drop(wiring);
    drop(handle);
    drop(store);

    // A reopened store reads the same open latch: the stop survives a restart.
    let reopened = Store::open(config.clone()).expect("the reopened store");
    let latch = reopened
        .sdd_plan_change_latch(project(), execution(project()))
        .expect("the latch row")
        .expect("a stored latch");
    assert!(latch.is_open());
    assert_eq!(latch.change().reason(), PlanChangeReason::BytesChanged);

    // Returning to the approved bytes does not clear the stored latch either.
    temp.save(&bytes);
    let reopened_handle =
        herness_desktop::supervision::store::StoreHandle::new(Arc::new(Mutex::new(reopened)));
    let mut wiring = PlanChangeWiring::new(project(), &temp.root, reopened_handle)
        .expect("the plan-change wiring");
    let restored = wiring
        .gate
        .check_before_side_effect(
            execution(project()),
            approval_id(project()),
            approved.plan(),
        )
        .expect("a check");
    match restored {
        PlanGateDecision::Blocked { latch, restored } => {
            assert!(restored);
            assert!(latch.is_open());
        }
        other => panic!("expected a blocking latch, found {other:?}"),
    }

    // The port view is the same durable row.
    let mut port = LatchStore::new(herness_desktop::supervision::store::StoreHandle::new(
        Arc::new(Mutex::new(Store::open(config).expect("the reopened store"))),
    ));
    let stored = <LatchStore as PlanChangeLatchStorePort>::plan_change_latch(
        &port,
        project(),
        execution(project()),
    )
    .expect("the port latch")
    .expect("a stored latch");
    assert!(stored.is_open());
    // A cleared latch requires a newer plan revision than the latched one.
    let cleared = stored
        .cleared(2, plan_revision(2))
        .expect("a cleared latch");
    port.record_plan_change_latch(&cleared)
        .expect("the cleared latch");
    assert!(
        <LatchStore as PlanChangeLatchStorePort>::plan_change_latch(
            &port,
            project(),
            execution(project())
        )
        .expect("the port latch")
        .expect("a stored latch")
        .is_cleared()
    );
}

// ===========================================================================
// Real pack helpers
// ===========================================================================

fn pack_root() -> PathBuf {
    let root = std::env::var_os("SDD_PACK_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PACK_ROOT));
    let script = root.join("scripts/plan-inspect");
    assert!(
        script.is_file(),
        "no SDD pack inspector at {}. Set SDD_PACK_ROOT to a pack checkout that has \
         scripts/plan-inspect (documented default {DEFAULT_PACK_ROOT}).",
        script.display()
    );
    eprintln!("plan_changes tests: SDD pack root = {}", root.display());
    root
}

fn python() -> AbsolutePath {
    for candidate in [
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/usr/bin/python3",
    ] {
        if Path::new(candidate).is_file() {
            return AbsolutePath::new(candidate).expect("an absolute interpreter path");
        }
    }
    panic!("python3 was not found at a known absolute path");
}

fn plan_importer(pack: &Path, root: &Path) -> PlanImporter<SystemArgvLauncher, PlanFileSource> {
    let bridge = herness_desktop::sdd_execute::PackInspector::new(
        pack,
        python(),
        SystemArgvLauncher,
        ProcessSupervisor::new(),
        project(),
    )
    .expect("the pack inspector is constructible")
    .with_project_root(
        root.canonicalize()
            .expect("a canonical root")
            .to_str()
            .expect("UTF-8"),
    );
    let source = PlanFileSource::new(project(), root).expect("a plan source");
    PlanImporter::new(
        bridge,
        source,
        herness_sdd_execute::SourceLayout::new(
            root.canonicalize()
                .expect("a canonical root")
                .to_str()
                .expect("UTF-8"),
        )
        .expect("a layout"),
        None,
    )
}
