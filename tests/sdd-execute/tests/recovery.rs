//! Task 20: quit, post-crash reconciliation, and the human resume.
//!
//! Every case uses a real temporary SQLite store in a temporary application-data
//! root and, where a commit is involved, a real temporary Git repository with
//! real commits. A restart is simulated by opening a **second** store connection
//! on the same database in this process, so the values read after "restart" come
//! back through SQLite rather than through an in-memory copy.
//!
//! The child side is a counting fake port, never a real engine: the fake counts
//! every read and asserts that restoring and describing an execution issues no
//! external request. No network, model, credential, Keychain item, or GUI is
//! used. Nothing is pushed, merged, rebased, amended, reset, or cleaned.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use herness_core::contracts::{ConnectionId, ProjectId};
use herness_core::runtime::{ShutdownOutcome, ShutdownReport, ShutdownRun};
use herness_core::{
    AbsolutePath, ProcessSupervisor, RunId, RunState, StopReport, SystemArgvLauncher, Timestamp,
};
use herness_desktop::sdd_execute::GitCheckoutObserver;
use herness_desktop::sdd_execute::recovery::{
    DesktopRecoveryHost, NoDocuments, RecoveryChildSource,
};
use herness_sdd_execute::{
    ApprovalContent, ApprovalId, ApprovalInputs, ApprovalRevisionStorePort, ApprovalSource,
    ApprovedCheck, ApprovedCondition, ApprovedDeliverable, ApprovedSpecRef, Baseline,
    BudgetConsumption, ChildIdentity, ChildState, ChildStatus, CommitAuthorization,
    CommitObservationPort, CommitPolicy, CommitRange, CommitSha, ConditionMode, ControlRequestId,
    DeliverableKind, DispatchContent, DispatchJournalEntry, DispatchRequest, DispatchResult,
    ExactPlanBytes, ExactPlanText, ExecutionApproval, ExecutionConnection, ExecutionId,
    ExecutionOperation, ExecutionOperationRequest, ExecutionRevision, ExecutionSnapshot,
    ExecutionState, ExecutionStorePort, GitCommitIntent, GitCommitOutcome, GitIdentity,
    GitJournalEntry, GitJournalState, H2SupervisionRef, H3ApprovalBinding, HumanAction,
    HumanResume, InspectorProtocol, PackApproval, PackFingerprint, ParsedPlanSummary,
    ParsedPlanTask, PlanApproval, PlanByteRange, PlanChange, PlanChangeLatch,
    PlanChangeLatchStorePort, PlanChangeReason, PlanDigest, PlanExpectation, PlanPath,
    PlanRevision, PreHookState, ProgressContent, ProgressJournalEntry, ProgressJournalId,
    ProgressTaskLine, ProgressWriteOutcome, RecoveryClass, RecoveryContext,
    RecoveryEnumerationPort, RecoveryFacts, RecoveryRecordKind, RequestIdentity, ResumeBlocker,
    ResumeOutcome, ResumeRequest, SddExecutionError, Sha256Digest, SnapshotBudget, SnapshotInput,
    SnapshotPlan, SnapshotWorkspace, StopReason, TaskApproval, TaskNumber, TaskPhase, TaskRef,
    TaskSnapshot, TaskStableId, WorkspaceApproval, quit_confirmed_snapshot,
    quit_requested_snapshot, reconcile, resume,
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

const BRANCH: &str = "h4-recovery";
const BASE_BRANCH: &str = "main";
const PLAN_PATH: &str = "docs/sdd/plans/2026-11-15-recovery-fixture.md";
const SPEC_PATH: &str = "docs/sdd/specs/2026-11-15-recovery-fixture.md";
const SECTION: &str = "Numeric defaults and lifecycle";

fn project() -> ProjectId {
    ProjectId::from_uuid(uuid("d1000000-0000-4000-8000-000000000001"))
}

fn execution(project_id: ProjectId) -> ExecutionId {
    ExecutionId::from_parts(project_id, uuid("d2000000-0000-4000-8000-000000000001"))
}

fn approval_id(project_id: ProjectId) -> ApprovalId {
    ApprovalId::from_parts(project_id, uuid("d3000000-0000-4000-8000-000000000001"))
}

fn control_request(project_id: ProjectId, local: u128) -> ControlRequestId {
    ControlRequestId::from_parts(project_id, Uuid::from_u128(local))
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("a UUID")
}

fn plan_path() -> PlanPath {
    PlanPath::parse(PLAN_PATH).expect("a plan path")
}

fn plan_revision() -> PlanRevision {
    PlanRevision::new(1).expect("a plan revision")
}

fn baseline() -> Baseline {
    Baseline::parse("a".repeat(40)).expect("a baseline")
}

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::sha256(label.as_bytes())
}

fn task_ref(project_id: ProjectId, number: u32) -> TaskRef {
    TaskRef::new(
        TaskStableId::from_parts(
            project_id,
            Uuid::from_u128(0xd400_0000_0000_4000_8000_0000_0000_0000 + u128::from(number)),
        ),
        TaskNumber::new(number).expect("a Task number"),
    )
}

fn supervision(project_id: ProjectId, local: u128) -> SupervisionId {
    SupervisionId::from_parts(project_id, Uuid::from_u128(local))
}

fn child(project_id: ProjectId, local: u128) -> ChildIdentity {
    ChildIdentity::new(
        herness_core::AgentId::from_parts(project_id, Uuid::from_u128(local)),
        herness_core::SessionId::from_parts(project_id, Uuid::from_u128(local + 1)),
    )
    .expect("a child")
}

fn now() -> Timestamp {
    Timestamp::from_unix_millis(1_790_000_000_000)
}

// ---------------------------------------------------------------------------
// Approval fixture
// ---------------------------------------------------------------------------

fn scope(project_id: ProjectId) -> ExecutionScope {
    ExecutionScope::new(
        project_id,
        vec!["docs".to_owned()],
        vec!["docs/adr".to_owned()],
        false,
    )
    .expect("a scope")
}

fn condition() -> ApprovedCondition {
    ApprovedCondition::new(
        "written",
        "condition",
        "the document is written",
        ConditionMode::Checks,
    )
    .expect("a condition")
}

fn check() -> ApprovedCheck {
    ApprovedCheck::new(
        "build",
        "written",
        "run the check",
        "cargo check",
        ".",
        60,
        vec!["docs".to_owned()],
    )
    .expect("a check")
}

fn task_approval(project_id: ProjectId, number: u32) -> TaskApproval {
    TaskApproval::new(
        task_ref(project_id, number),
        format!("Task {number}"),
        vec![condition()],
        scope(project_id),
        vec![check()],
        Vec::new(),
        BudgetPolicy::new(600, 5, None).expect("a budget"),
        CommitPolicy::Required,
        vec![
            ApprovedDeliverable::new("docs/adr/0001.md", DeliverableKind::File)
                .expect("a deliverable"),
        ],
    )
    .expect("a Task approval")
}

fn profile(project_id: ProjectId) -> ProfileBinding {
    ProfileBinding::new(
        ProfileId::from_parts(project_id, Uuid::from_u128(0xd500)),
        ProfileVersion::new(1).expect("a profile version"),
        ProfilePurpose::Completion,
    )
}

fn consent(project_id: ProjectId) -> ConsentBinding {
    ConsentBinding::new(
        ConsentId::from_parts(project_id, Uuid::from_u128(0xd501)),
        1,
        ProfilePurpose::Completion,
        TargetVersion::new(1).expect("a target version"),
    )
}

fn connection_id() -> ConnectionId {
    ConnectionId::from_uuid(Uuid::from_u128(0xd502))
}

fn h3() -> H3ApprovalBinding {
    H3ApprovalBinding::new(1, Vec::new(), vec!["html-sync".to_owned()]).expect("an H3 binding")
}

fn approval(project_id: ProjectId, checkout: &str) -> ExecutionApproval {
    approval_with_tasks(project_id, checkout, 1)
}

fn approval_with_tasks(project_id: ProjectId, checkout: &str, tasks: u32) -> ExecutionApproval {
    let constraints = "Global Constraints\n- keep";
    let bodies = (1..=tasks)
        .map(|number| {
            ParsedPlanTask::new(number, format!("Task {number}"), body()).expect("parsed")
        })
        .collect();
    let plan = PlanApproval::new(
        plan_path(),
        ExactPlanBytes::new(b"# plan".to_vec()).expect("plan bytes"),
        plan_revision(),
        ParsedPlanSummary::new(
            1,
            ExactPlanText::new(
                constraints,
                PlanByteRange::new(0, constraints.len() as u64).unwrap(),
            )
            .expect("constraints"),
            bodies,
            vec!["build".to_owned()],
        )
        .expect("parsed plan"),
        vec![
            ApprovedSpecRef::new(
                "project",
                SPEC_PATH,
                vec![SECTION.to_owned()],
                digest("spec"),
            )
            .expect("a spec reference"),
        ],
        Vec::new(),
        PackApproval::new(
            InspectorProtocol::expected(),
            1,
            PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).expect("a fingerprint"),
        )
        .expect("a pack approval"),
    )
    .expect("a plan approval");
    let content = ApprovalContent::new(
        plan,
        WorkspaceApproval::new(
            project_id,
            checkout,
            GitIdentity::new("herness", "host@example.test").expect("a Git identity"),
            BRANCH,
            BASE_BRANCH,
            false,
            Some(baseline()),
        )
        .expect("a workspace approval"),
        (1..=tasks)
            .map(|number| task_approval(project_id, number))
            .collect(),
        ExecutionConnection::new(
            connection_id(),
            profile(project_id),
            vec![consent(project_id)],
        )
        .expect("a connection"),
        CommitAuthorization::new(true, true).expect("a commit authorization"),
        h3(),
    )
    .expect("an approval content");
    let id = approval_id(project_id);
    ExecutionApproval::new(
        id,
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry { approval_id: id },
        now(),
        content,
    )
    .expect("an approval")
}

fn body() -> ExactPlanText {
    ExactPlanText::new("Body.\n", PlanByteRange::new(0, 6).unwrap()).expect("a body")
}

/// The observed current inputs of an approval. It matches the stored approval
/// unless a case deliberately changes one part.
fn inputs(approval: &ExecutionApproval) -> ApprovalInputs {
    ApprovalInputs::new(
        approval.plan().clone(),
        approval.workspace().clone(),
        approval.tasks().to_vec(),
        herness_sdd_execute::ObservedConnection::new(
            approval.connection().connection_id(),
            approval.connection().profile(),
            approval.connection().consents().to_vec(),
        ),
        approval.commit(),
        Some(approval.h3().clone()),
    )
}

// ---------------------------------------------------------------------------
// Real repository
// ---------------------------------------------------------------------------

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("a temporary directory");
        let root = fs::canonicalize(temp.path()).expect("a canonical temp root");
        run_git(&root, &["init", "-q", "-b", BRANCH]);
        run_git(&root, &["config", "user.name", "Host Test"]);
        run_git(&root, &["config", "user.email", "host@example.invalid"]);
        run_git(&root, &["config", "core.hooksPath", ".git/hooks"]);
        fs::create_dir_all(root.join("docs/adr")).expect("docs");
        fs::write(root.join("README.md"), "initial\n").expect("seed");
        run_git(&root, &["add", "--", "README.md"]);
        run_git(&root, &["commit", "-q", "-m", "initial"]);
        Self { _temp: temp, root }
    }

    fn path(&self) -> &str {
        self.root.to_str().expect("a UTF-8 checkout root")
    }

    fn head(&self) -> String {
        git_stdout(&self.root, &["rev-parse", "HEAD"])
    }

    fn commit_count(&self) -> usize {
        git_stdout(&self.root, &["rev-list", "--count", "HEAD"])
            .parse()
            .expect("a commit count")
    }

    fn write(&self, relative: &str, contents: &str) -> Vec<u8> {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("a parent directory");
        }
        fs::write(&path, contents).expect("a written file");
        contents.as_bytes().to_vec()
    }

    fn observer(&self, project: ProjectId) -> GitCheckoutObserver {
        let runner = herness_desktop::sdd_execute::GitRunner::new(
            AbsolutePath::new(git_program()).expect("an absolute git"),
            SystemArgvLauncher,
            ProcessSupervisor::new(),
            project,
        )
        .expect("a Git runner");
        GitCheckoutObserver::new(
            runner,
            AbsolutePath::new(self.path().to_owned()).expect("an absolute root"),
        )
    }
}

fn run_git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(root)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .output()
        .expect("git starts");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_stdout(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn git_program() -> String {
    Command::new("/usr/bin/which")
        .arg("git")
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .map(|line| line.trim().to_owned())
        })
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| "/usr/bin/git".to_owned())
}

// ---------------------------------------------------------------------------
// Counting child port
// ---------------------------------------------------------------------------

/// A read-only child port that counts every read and never starts anything.
#[derive(Debug, Default)]
struct CountingChildren {
    reads: usize,
    statuses: Vec<(TaskRef, ChildStatus)>,
}

impl CountingChildren {
    fn new() -> Self {
        Self::default()
    }

    fn with(mut self, task: TaskRef, status: ChildStatus) -> Self {
        self.statuses.push((task, status));
        self
    }

    fn reads(&self) -> usize {
        self.reads
    }
}

impl RecoveryChildSource for CountingChildren {
    fn child_status(
        &mut self,
        _project_id: ProjectId,
        _execution_id: ExecutionId,
        task: TaskRef,
    ) -> Result<Option<ChildStatus>, SddExecutionError> {
        self.reads += 1;
        Ok(self
            .statuses
            .iter()
            .find(|(stored, _)| *stored == task)
            .map(|(_, status)| status.clone()))
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    _data: TempDir,
    config: StoreConfig,
    store: Store,
    repo: Repo,
    project: ProjectId,
    execution: ExecutionId,
}

impl Harness {
    fn new() -> Self {
        Self::with_tasks(1)
    }

    fn with_tasks(tasks: u32) -> Self {
        let repo = Repo::new();
        let data = tempfile::tempdir().expect("an application data root");
        let config = StoreConfig::new(data.path().join("app-data")).expect("a store config");
        let mut store = Store::open(config.clone()).expect("a store");
        let project = project();
        let execution = execution(project);
        let approval = approval_with_tasks(project, repo.path(), tasks);
        store
            .record_approval_revision(&approval)
            .expect("a recorded approval");
        let snapshot = ready_snapshot(project, execution, repo.path(), tasks);
        store
            .compare_and_swap(project, execution, None, &snapshot)
            .expect("a stored snapshot");
        Self {
            _data: data,
            config,
            store,
            repo,
            project,
            execution,
        }
    }

    /// Opens a second connection on the same database, as a restarted process
    /// would.
    fn restart(&self) -> Store {
        Store::open(self.config.clone()).expect("a reopened store")
    }

    /// Stores the next snapshot against `expected`.
    fn save_snapshot(
        &mut self,
        expected: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
    ) -> ExecutionRevision {
        let project = self.project;
        let execution = self.execution;
        self.store
            .compare_and_swap(project, execution, expected, next)
            .expect("a stored snapshot")
    }

    /// Stores one dispatch journal row.
    fn save_dispatch(&mut self, entry: &DispatchJournalEntry) {
        self.store.record_dispatch(entry).expect("a dispatch row");
    }

    /// Stores one Git journal row.
    fn save_git(&mut self, entry: &GitJournalEntry) {
        self.store.record_git(entry).expect("a git row");
    }

    /// Stores one progress journal row.
    fn save_progress(&mut self, entry: &ProgressJournalEntry) {
        self.store.record_progress(entry).expect("a progress row");
    }

    /// Stores one control-operation row.
    fn save_operation(&mut self, record: &herness_sdd_execute::ControlRecord) {
        self.store.record_operation(record).expect("a control row");
    }

    /// Stores the plan-change latch.
    fn save_latch(&mut self, latch: &PlanChangeLatch) {
        self.store
            .record_plan_change_latch(latch)
            .expect("a latch row");
    }

    fn snapshot(&self) -> ExecutionSnapshot {
        self.store
            .load(self.project, self.execution)
            .expect("a load")
            .expect("a stored execution")
            .snapshot()
            .clone()
    }

    fn stored(&self) -> herness_sdd_execute::StoredExecution {
        self.store
            .load(self.project, self.execution)
            .expect("a load")
            .expect("a stored execution")
    }

    fn approval(&self) -> ExecutionApproval {
        self.store
            .latest_approval_revision(self.project, approval_id(self.project))
            .expect("an approval load")
            .expect("a stored approval")
    }

    /// Every saved journal row, read through the enumeration port.
    fn facts(&self) -> RecoveryFacts {
        RecoveryFacts::new()
            .with_dispatch(
                self.store
                    .dispatch_entries(self.project, self.execution)
                    .expect("dispatch rows"),
            )
            .with_git(
                self.store
                    .git_entries(self.project, self.execution)
                    .expect("git rows"),
            )
            .with_progress(
                self.store
                    .progress_entries(self.project, self.execution)
                    .expect("progress rows"),
            )
            .with_control(
                self.store
                    .control_records(self.project, self.execution)
                    .expect("control rows"),
            )
            .with_reservations(
                self.store
                    .task_reservations(self.project, self.execution)
                    .expect("reservation rows"),
            )
    }

    /// The saved facts plus the read-only checkout observation.
    fn observed_facts(&self) -> RecoveryFacts {
        self.facts().with_observation(self.observe())
    }

    fn observe(&self) -> herness_sdd_execute::CommitObservation {
        let facts = self.facts();
        let request = herness_sdd_execute::observation_request(self.project, BRANCH, facts.git())
            .expect("an observation request");
        let mut observer = self.repo.observer(self.project);
        CommitObservationPort::observe(&mut observer, &request).expect("an observation")
    }

    fn reconcile(&self) -> herness_sdd_execute::RecoveryReport {
        let stored = self.stored();
        let approval = self.approval();
        let latch = self
            .store
            .plan_change_latch(self.project, self.execution)
            .expect("a latch load");
        let facts = self.observed_facts();
        reconcile(
            &stored,
            &facts,
            RecoveryContext {
                plan_change: latch.as_ref(),
                approval: Some(&approval),
            },
        )
        .expect("a reconciliation")
    }

    fn resume_request(&self, local: u128, approval_revision: u64) -> ResumeRequest {
        ResumeRequest::new(
            self.project,
            self.execution,
            control_request(self.project, local),
            self.snapshot().revision(),
            HumanResume::after_main_window_confirmation(),
            approval_id(self.project),
            approval_revision,
        )
        .expect("a resume request")
    }
}

fn ready_snapshot(
    project: ProjectId,
    execution: ExecutionId,
    checkout: &str,
    tasks: u32,
) -> ExecutionSnapshot {
    let task_snapshots = (1..=tasks)
        .map(|number| {
            TaskSnapshot::new(
                task_ref(project, number),
                herness_sdd_execute::TaskProgression::Pending,
                TaskPhase::Ready,
                None,
                None,
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(plan_revision()),
            )
            .expect("a Task snapshot")
        })
        .collect();
    ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: execution,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Ready,
        plan: SnapshotPlan::new(plan_path(), PlanDigest::sha256(b"# plan"), plan_revision()),
        workspace: SnapshotWorkspace::new(checkout, BRANCH, BASE_BRANCH, Some(baseline()))
            .expect("a snapshot workspace"),
        current_task: Some(task_ref(project, 1)),
        tasks: task_snapshots,
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: herness_sdd_execute::AppliedRevision::current(plan_revision()),
        final_project_sequence: None,
    })
    .expect("a ready snapshot")
}

fn running_snapshot(
    project: ProjectId,
    execution: ExecutionId,
    checkout: &str,
    revision: ExecutionRevision,
    supervision_id: SupervisionId,
    child_identity: ChildIdentity,
    consumed_seconds: u64,
) -> ExecutionSnapshot {
    ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: execution,
        revision,
        state: ExecutionState::Running,
        plan: SnapshotPlan::new(plan_path(), PlanDigest::sha256(b"# plan"), plan_revision()),
        workspace: SnapshotWorkspace::new(checkout, BRANCH, BASE_BRANCH, Some(baseline()))
            .expect("a snapshot workspace"),
        current_task: Some(task_ref(project, 1)),
        tasks: vec![
            TaskSnapshot::new(
                task_ref(project, 1),
                herness_sdd_execute::TaskProgression::Active,
                TaskPhase::Running,
                Some(H2SupervisionRef::new(supervision_id)),
                Some(child_identity),
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(plan_revision()),
            )
            .expect("a Task snapshot"),
        ],
        stop: None,
        budget: SnapshotBudget::new(
            BudgetConsumption::new(consumed_seconds, 1, None),
            BudgetConsumption::zero(),
        ),
        applied_revision: herness_sdd_execute::AppliedRevision::current(plan_revision()),
        final_project_sequence: None,
    })
    .expect("a running snapshot")
}

/// A dispatch intent for one Task, saved before the child exists.
fn dispatch_intent(harness: &Harness, task: TaskRef) -> DispatchJournalEntry {
    let request_id = herness_sdd_execute::dispatch_request_id(harness.execution, task);
    let identity = RequestIdentity::new(
        harness.project,
        harness.execution,
        request_id,
        harness.snapshot().revision(),
    )
    .expect("an identity");
    let content = DispatchContent::new(
        task,
        plan_revision(),
        baseline(),
        digest("manifest"),
        digest("packet"),
    )
    .expect("dispatch content");
    let request = DispatchRequest::new(identity, content).expect("a dispatch request");
    DispatchJournalEntry::intent(*request.identity(), request.content()).expect("a dispatch intent")
}

/// A Git intent for one Task with one explicitly staged path.
fn git_intent(
    harness: &Harness,
    task: TaskRef,
    path: &str,
    bytes: &[u8],
    parent: &str,
    request_local: u128,
) -> GitJournalEntry {
    let request_id = herness_sdd_execute::CommitRequestId::from_parts(
        harness.project,
        Uuid::from_u128(request_local),
    );
    let identity = RequestIdentity::new(
        harness.project,
        harness.execution,
        request_id,
        harness.snapshot().revision(),
    )
    .expect("an identity");
    let message = herness_sdd_execute::CommitMessage::new(
        task,
        "record the document",
        harness.execution,
        request_id,
        Vec::new(),
    )
    .expect("a commit message");
    let intent = GitCommitIntent::new(
        task,
        BRANCH,
        baseline(),
        CommitSha::parse(parent).expect("a parent"),
        None,
        vec![
            herness_sdd_execute::CommittedPath::new(
                path,
                bytes.len() as u64,
                Some(Sha256Digest::sha256(bytes)),
            )
            .expect("a committed path"),
        ],
        message,
        PreHookState::new(true, vec![path.to_owned()], None, None).expect("a pre-hook state"),
        20,
    )
    .expect("a commit intent");
    GitJournalEntry::new(identity, intent).expect("a git journal entry")
}

/// One progress journal entry for a document with these exact bytes.
fn progress_intent(
    harness: &Harness,
    path: &str,
    bytes: &[u8],
    request_local: u128,
) -> ProgressJournalEntry {
    let request_id = ProgressJournalId::from_parts(harness.project, Uuid::from_u128(request_local));
    let identity = RequestIdentity::new(
        harness.project,
        harness.execution,
        request_id,
        harness.snapshot().revision(),
    )
    .expect("an identity");
    let content = ProgressContent::new(
        path,
        harness.repo.path(),
        BRANCH,
        baseline(),
        vec![
            ProgressTaskLine::new(
                task_ref(harness.project, 1),
                Some(
                    CommitRange::new(baseline(), CommitSha::parse("b".repeat(40)).unwrap())
                        .unwrap(),
                ),
                false,
            )
            .expect("a progress line"),
        ],
        Vec::new(),
        None,
        Sha256Digest::sha256(bytes),
    )
    .expect("progress content");
    ProgressJournalEntry::new(identity, content).expect("a progress intent")
}

fn item(report: &herness_sdd_execute::RecoveryReport, kind: RecoveryRecordKind) -> RecoveryClass {
    report
        .items()
        .iter()
        .find(|item| item.kind() == kind)
        .unwrap_or_else(|| panic!("a {kind:?} record is reported: {:?}", report.items()))
        .class()
}

// ---------------------------------------------------------------------------
// Restore: read-only, zero external requests, latches and budget preserved
// ---------------------------------------------------------------------------

#[test]
fn restore_issues_zero_external_requests_and_reads_only_saved_state() {
    let mut harness = Harness::new();
    let task = task_ref(harness.project, 1);
    let supervision_id = supervision(harness.project, 0xd600);
    let child_identity = child(harness.project, 0xd610);
    let snapshot = running_snapshot(
        harness.project,
        harness.execution,
        harness.repo.path(),
        ExecutionRevision::new(2).expect("a revision"),
        supervision_id,
        child_identity,
        120,
    );
    harness.save_snapshot(Some(ExecutionRevision::INITIAL), &snapshot);
    let dispatched = dispatch_intent(&harness, task)
        .recorded(DispatchResult::new(supervision_id, child_identity).expect("a dispatch result"));
    harness.save_dispatch(&dispatched);

    let before_revision = harness.snapshot().revision();
    let before_dispatch = harness
        .store
        .dispatch_entries(harness.project, harness.execution)
        .expect("dispatch rows")
        .len();

    let mut children = CountingChildren::new().with(
        task,
        ChildStatus::new(
            supervision_id,
            ChildState::Running,
            120,
            1,
            0,
            false,
            Vec::new(),
        ),
    );
    let mut host = DesktopRecoveryHost::new(
        herness_desktop::supervision::store::StoreHandle::new(std::sync::Arc::new(
            std::sync::Mutex::new(harness.restart()),
        )),
        Some(AbsolutePath::new(git_program()).expect("an absolute git")),
    )
    .with_documents(NoDocuments);

    let report = host.restore(&mut children);

    assert_eq!(
        report.request_count(),
        0,
        "restore sends no external request"
    );
    assert_eq!(
        report.failures(),
        &[] as &[herness_desktop::sdd_execute::recovery::RecoveryFailure]
    );
    assert_eq!(report.reports().len(), 1);
    let execution_report = &report.reports()[0];
    assert_eq!(execution_report.external_requests(), 0);
    assert_eq!(execution_report.state(), ExecutionState::Running);
    assert_eq!(execution_report.budget().active_seconds(), 120);
    assert_eq!(execution_report.remaining_seconds(), 7_200 - 120);
    // The stored child was read exactly once per Task; nothing was started.
    assert_eq!(children.reads(), 1);
    // The restore wrote nothing: the revision and the journal row count are the
    // same through a second connection.
    let restarted = harness.restart();
    assert_eq!(
        restarted
            .load(harness.project, harness.execution)
            .expect("a load")
            .expect("a stored execution")
            .revision(),
        before_revision
    );
    assert_eq!(
        restarted
            .dispatch_entries(harness.project, harness.execution)
            .expect("dispatch rows")
            .len(),
        before_dispatch
    );
    assert!(item(execution_report, RecoveryRecordKind::Dispatch) == RecoveryClass::Established);
    assert!(item(execution_report, RecoveryRecordKind::Process) == RecoveryClass::Established);
}

#[test]
fn the_stop_and_plan_change_latches_survive_a_reopened_store() {
    let mut harness = Harness::new();
    let approval = harness.approval();
    let latch = PlanChangeLatch::engage(
        harness.project,
        harness.execution,
        approval.approval_id(),
        PlanExpectation::new(
            plan_path(),
            approval.plan().digest().clone(),
            approval.plan().byte_length(),
            plan_revision(),
        ),
        PlanChange::from_observation(
            PlanChangeReason::BytesChanged,
            &herness_sdd_execute::PlanObservation::observed(
                PlanDigest::sha256(b"# changed plan"),
                16,
                true,
            ),
            None,
        )
        .expect("a plan change"),
    )
    .expect("a plan change latch");
    harness.save_latch(&latch);
    // A durable stop latch at the execution level.
    let stopped = quit_confirmed_snapshot(
        &harness.snapshot(),
        ExecutionRevision::new(2).unwrap(),
        true,
    )
    .expect("a stopped snapshot");
    harness.save_snapshot(Some(ExecutionRevision::INITIAL), &stopped);

    let restarted = harness.restart();
    let stored_latch = restarted
        .plan_change_latch(harness.project, harness.execution)
        .expect("a latch load")
        .expect("a stored latch");
    assert!(stored_latch.is_open(), "the plan-change latch survives");
    let stored = restarted
        .load(harness.project, harness.execution)
        .expect("a load")
        .expect("a stored execution")
        .snapshot()
        .clone();
    assert_eq!(stored.state(), ExecutionState::Stopped);
    assert_eq!(
        stored.stop().map(|stop| stop.reason()),
        Some(StopReason::RecoveryRequired)
    );

    // Reconcile against the reopened store and report both latches.
    let facts = harness.facts();
    let report = reconcile(
        &herness_sdd_execute::StoredExecution::new(stored.revision(), stored.clone()).unwrap(),
        &facts,
        RecoveryContext {
            plan_change: Some(&stored_latch),
            approval: Some(&approval),
        },
    )
    .expect("a reconciliation");
    assert!(report.plan_change_open());
    assert_eq!(report.state(), ExecutionState::Stopped);
}

// ---------------------------------------------------------------------------
// Fault boundaries: dispatch, process, Git, progress, control
// ---------------------------------------------------------------------------

#[test]
fn every_dispatch_and_process_boundary_reconciles_without_resetting_an_unknown() {
    // (1) Before the dispatch intent: nothing was sent.
    let mut harness = Harness::new();
    let report = harness.reconcile();
    assert_eq!(
        item(&report, RecoveryRecordKind::Dispatch),
        RecoveryClass::NotRun
    );
    assert_eq!(
        item(&report, RecoveryRecordKind::Process),
        RecoveryClass::NotRun
    );
    assert!(report.is_clean(), "a never-dispatched Task is clean");

    // (2) After the dispatch intent, before the child exists: unknown, never
    // not-run.
    let task = task_ref(harness.project, 1);
    harness.save_dispatch(&dispatch_intent(&harness, task));
    let report = harness.reconcile();
    assert_eq!(
        item(&report, RecoveryRecordKind::Dispatch),
        RecoveryClass::Unknown
    );
    assert!(
        report
            .items()
            .iter()
            .any(|item| { item.kind() == RecoveryRecordKind::Dispatch && item.is_blocking() })
    );
    assert!(!report.is_clean());

    // (3) After the child was created and its H2 result stored: established.
    let supervision_id = supervision(harness.project, 0xd620);
    let child_identity = child(harness.project, 0xd630);
    let revision = harness.snapshot().revision();
    let snapshot = running_snapshot(
        harness.project,
        harness.execution,
        harness.repo.path(),
        revision.next(),
        supervision_id,
        child_identity,
        0,
    );
    harness.save_snapshot(Some(revision), &snapshot);
    let facts = harness.facts().with_child(ChildStatus::new(
        supervision_id,
        ChildState::Running,
        30,
        0,
        0,
        false,
        Vec::new(),
    ));
    let approval = harness.approval();
    let stored = harness.stored();
    let report = reconcile(
        &stored,
        &facts,
        RecoveryContext {
            plan_change: None,
            approval: Some(&approval),
        },
    )
    .expect("a reconciliation");
    assert_eq!(
        item(&report, RecoveryRecordKind::Process),
        RecoveryClass::Established
    );

    // (4) An unconfirmed process stop is unknown, never "stopped".
    let facts = harness.facts().with_child(
        ChildStatus::new(
            supervision_id,
            ChildState::Stopped,
            30,
            0,
            0,
            false,
            Vec::new(),
        )
        .with_stop_cause(herness_sdd_execute::ChildStopCause::StopUnconfirmed),
    );
    let report = reconcile(
        &harness.stored(),
        &facts,
        RecoveryContext {
            plan_change: None,
            approval: Some(&approval),
        },
    )
    .expect("a reconciliation");
    assert_eq!(
        item(&report, RecoveryRecordKind::Process),
        RecoveryClass::Unknown
    );
    assert!(report.items().iter().any(|item| {
        item.kind() == RecoveryRecordKind::Process && item.detail().contains("not confirmed")
    }));

    // An H2 target the Task names but H2 does not record is also unknown.
    let facts = harness.facts();
    let report = reconcile(
        &harness.stored(),
        &facts,
        RecoveryContext {
            plan_change: None,
            approval: Some(&approval),
        },
    )
    .expect("a reconciliation");
    assert_eq!(
        item(&report, RecoveryRecordKind::Process),
        RecoveryClass::Unknown
    );
}

#[test]
fn every_git_boundary_reconciles_and_an_established_commit_waits_for_the_human() {
    let mut harness = Harness::new();
    let task = task_ref(harness.project, 1);
    let bytes = harness.repo.write("docs/adr/0001.md", "# One\n");
    let parent = harness.repo.head();

    // (1) Before the Git intent: no commit ran.
    let report = harness.reconcile();
    assert_eq!(
        item(&report, RecoveryRecordKind::Git),
        RecoveryClass::NotRun
    );

    // (2) After the Git intent, before the commit: unknown, never not-run.
    let intent = git_intent(&harness, task, "docs/adr/0001.md", &bytes, &parent, 0xd700);
    harness.save_git(&intent);
    let report = harness.reconcile();
    assert_eq!(
        item(&report, RecoveryRecordKind::Git),
        RecoveryClass::Unknown
    );
    assert!(report.pending_link().is_none());

    // A recorded rejection is the one honest not-run after an intent.
    let rejected = intent.clone().record(GitCommitOutcome::Rejected {
        reason: herness_sdd_execute::GitRejection::HookFailed,
    });
    harness.save_git(&rejected);
    let report = harness.reconcile();
    assert_eq!(
        item(&report, RecoveryRecordKind::Git),
        RecoveryClass::NotRun
    );

    // (3) After the commit, before the result store: the commit is established
    // but not linked, so the Task is never re-dispatched or committed again.
    let mut fresh = Harness::new();
    let task = task_ref(fresh.project, 1);
    let bytes = fresh.repo.write("docs/adr/0001.md", "# One\n");
    let parent = fresh.repo.head();
    let intent = git_intent(&fresh, task, "docs/adr/0001.md", &bytes, &parent, 0xd701);
    fresh.save_git(&intent);
    run_git(&fresh.repo.root, &["add", "--", "docs/adr/0001.md"]);
    run_git(
        &fresh.repo.root,
        &["commit", "-q", "-m", &intent.intent().message().render()],
    );
    assert_eq!(fresh.repo.parent_head(), parent);
    assert_eq!(fresh.repo.commit_count(), 2);

    let report = fresh.reconcile();
    assert_eq!(
        item(&report, RecoveryRecordKind::Git),
        RecoveryClass::Established
    );
    let pending = report
        .pending_link()
        .expect("an unlinked established commit");
    assert_eq!(pending.task(), task);
    assert!(!report.is_clean());

    // The human resume links it exactly once and completes the Task.
    let approval = fresh.approval();
    let mut store = fresh.restart();
    let request = ResumeRequest::new(
        fresh.project,
        fresh.execution,
        control_request(fresh.project, 0xd710),
        fresh.snapshot().revision(),
        HumanResume::after_main_window_confirmation(),
        approval_id(fresh.project),
        approval.revision(),
    )
    .expect("a resume request");
    let outcome = resume(
        &mut store,
        &request,
        &fresh.observed_facts(),
        None,
        &inputs(&approval),
    )
    .expect("a resume");
    match outcome {
        ResumeOutcome::CommitLinked {
            task: linked,
            range,
            ..
        } => {
            assert_eq!(linked, task);
            assert_eq!(range.base().as_str(), baseline().as_str());
            assert_eq!(range.head().as_str(), fresh.repo.head());
        }
        other => panic!("expected a linked commit, got {other:?}"),
    }
    let restarted = fresh.restart();
    let stored = restarted
        .load(fresh.project, fresh.execution)
        .expect("a load")
        .expect("a stored execution")
        .snapshot()
        .clone();
    let completed = stored.task(TaskNumber::new(1).unwrap()).expect("Task 1");
    assert!(completed.progression().is_complete());
    assert_eq!(
        completed
            .commit_range()
            .map(|range| range.head().as_str().to_owned()),
        Some(fresh.repo.head())
    );
    // The journal row is now a recorded commit, so a second reconciliation finds
    // nothing left to link.
    let journal = restarted
        .git_entries(fresh.project, fresh.execution)
        .expect("git rows");
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].state(), GitJournalState::Committed);
    assert_eq!(fresh.repo.commit_count(), 2, "no second commit exists");

    // A re-delivered resume returns the stored result and links nothing again.
    let replayed = resume(
        &mut fresh.restart(),
        &request,
        &fresh.observed_facts(),
        None,
        &inputs(&approval),
    )
    .expect("a replayed resume");
    assert!(matches!(replayed, ResumeOutcome::Replayed { .. }));
    assert_eq!(fresh.repo.commit_count(), 2);
}

#[test]
fn every_progress_boundary_reconciles() {
    let mut harness = Harness::new();
    let path = ".sdd/progress.md";
    let bytes = b"# SDD Progress\n";
    // Before any write: no record and no document.
    let report = harness.reconcile();
    assert!(
        !report
            .items()
            .iter()
            .any(|item| item.kind() == RecoveryRecordKind::Progress)
    );

    // After the intent, before the write: unknown.
    let intent = progress_intent(&harness, path, bytes, 0xd800);
    harness.save_progress(&intent);
    let stored = harness.stored();
    let approval = harness.approval();
    let absent = harness
        .facts()
        .with_document(path, None)
        .with_progress(vec![intent.clone()]);
    let report = reconcile(
        &stored,
        &absent,
        RecoveryContext {
            plan_change: None,
            approval: Some(&approval),
        },
    )
    .expect("a reconciliation");
    assert_eq!(
        item(&report, RecoveryRecordKind::Progress),
        RecoveryClass::Unknown
    );

    // After the write: established when the document carries the exact digest.
    let written = intent.clone().record(ProgressWriteOutcome::Written {
        digest: Sha256Digest::sha256(bytes),
    });
    let present = harness
        .facts()
        .with_document(path, Some(Sha256Digest::sha256(bytes)))
        .with_progress(vec![written.clone()]);
    let report = reconcile(
        &stored,
        &present,
        RecoveryContext {
            plan_change: None,
            approval: Some(&approval),
        },
    )
    .expect("a reconciliation");
    assert_eq!(
        item(&report, RecoveryRecordKind::Progress),
        RecoveryClass::Established
    );

    // An unconfirmed write whose document does not match is unknown.
    let unconfirmed = intent.clone().record(ProgressWriteOutcome::Unknown);
    let mismatched = harness
        .facts()
        .with_document(path, Some(digest("a different document")))
        .with_progress(vec![unconfirmed]);
    let report = reconcile(
        &stored,
        &mismatched,
        RecoveryContext {
            plan_change: None,
            approval: Some(&approval),
        },
    )
    .expect("a reconciliation");
    assert_eq!(
        item(&report, RecoveryRecordKind::Progress),
        RecoveryClass::Unknown
    );

    // A recorded failed write is the one honest not-run.
    let failed = intent.clone().record(ProgressWriteOutcome::Failed {
        reason: herness_sdd_execute::ProgressFailure::ReplaceFailed,
    });
    let failed_facts = harness
        .facts()
        .with_document(path, None)
        .with_progress(vec![failed]);
    let report = reconcile(
        &stored,
        &failed_facts,
        RecoveryContext {
            plan_change: None,
            approval: Some(&approval),
        },
    )
    .expect("a reconciliation");
    assert_eq!(
        item(&report, RecoveryRecordKind::Progress),
        RecoveryClass::NotRun
    );
}

#[test]
fn an_operation_intent_without_its_result_is_reported_and_never_re_runs() {
    let mut harness = Harness::new();
    let operation = ExecutionOperationRequest::new(
        harness.project,
        harness.execution,
        control_request(harness.project, 0xd900),
        harness.snapshot().revision(),
        ExecutionOperation::Pause,
    )
    .expect("an operation request");
    harness.save_operation(&operation.intent().expect("an intent"));
    let report = harness.reconcile();
    let control = report
        .items()
        .iter()
        .find(|item| item.kind() == RecoveryRecordKind::Control)
        .expect("a control record");
    assert_eq!(control.class(), RecoveryClass::Unknown);
    assert!(
        !control.is_blocking(),
        "the snapshot revision decides, so it never blocks"
    );
    // The stored snapshot is unchanged: the intent applied nothing.
    assert_eq!(harness.snapshot().state(), ExecutionState::Ready);
}

// ---------------------------------------------------------------------------
// Human resume: confirmation, current inputs, budget, blockers
// ---------------------------------------------------------------------------

#[test]
fn a_resume_refuses_a_changed_current_input_and_never_runs_without_a_human() {
    let harness = Harness::new();
    let approval = harness.approval();
    let mut request = harness.resume_request(0xda00, approval.revision());
    let mut store = harness.restart();
    // A changed consent list is a current-input refusal.
    let mut changed = inputs(&approval);
    changed = ApprovalInputs::new(
        changed.plan().clone(),
        changed.workspace().clone(),
        changed.tasks().to_vec(),
        herness_sdd_execute::ObservedConnection::new(
            approval.connection().connection_id(),
            approval.connection().profile(),
            Vec::new(),
        ),
        changed.commit(),
        changed.h3().cloned(),
    );
    let error = resume(
        &mut store,
        &request,
        &harness.observed_facts(),
        None,
        &changed,
    )
    .expect_err("a changed consent list is refused");
    assert!(matches!(error, SddExecutionError::ApprovalRequired { .. }));
    assert_eq!(harness.snapshot().state(), ExecutionState::Ready);

    // The right inputs with a stale revision are refused before any write.
    let stale = ResumeRequest::new(
        harness.project,
        harness.execution,
        control_request(harness.project, 0xda01),
        ExecutionRevision::new(99).unwrap(),
        HumanResume::after_main_window_confirmation(),
        approval_id(harness.project),
        approval.revision(),
    )
    .unwrap();
    let error = resume(
        &mut store,
        &stale,
        &harness.observed_facts(),
        None,
        &inputs(&approval),
    )
    .expect_err("a stale revision is refused");
    assert!(matches!(error, SddExecutionError::RevisionConflict { .. }));

    // A `ready` execution has no child, so it needs no extra stop confirmation:
    // the correct request resumes to the same Task.
    request = harness.resume_request(0xda02, approval.revision());
    let outcome = resume(
        &mut store,
        &request,
        &harness.observed_facts(),
        None,
        &inputs(&approval),
    )
    .expect("a resume");
    match outcome {
        ResumeOutcome::Resumed { task, snapshot, .. } => {
            assert_eq!(task, Some(task_ref(harness.project, 1)));
            assert_eq!(snapshot.revision().get(), 2);
        }
        other => panic!("expected a resume, got {other:?}"),
    }
    assert_eq!(
        harness
            .restart()
            .load(harness.project, harness.execution)
            .unwrap()
            .unwrap()
            .snapshot()
            .state(),
        ExecutionState::Ready
    );
}

#[test]
fn a_quit_requested_stop_is_not_resumed_before_the_human_confirms_it() {
    let mut harness = Harness::new();
    let approval = harness.approval();
    // The quit writes `waiting_human` with `pause_requested`: a stop that is
    // requested but not confirmed.
    let requested =
        quit_requested_snapshot(&harness.snapshot(), ExecutionRevision::new(2).unwrap())
            .expect("a quit-requested snapshot");
    harness.save_snapshot(Some(ExecutionRevision::INITIAL), &requested);
    let request = harness.resume_request(0xda10, approval.revision());
    let outcome = resume(
        &mut harness.restart(),
        &request,
        &harness.observed_facts(),
        None,
        &inputs(&approval),
    )
    .expect("a resume");
    match outcome {
        ResumeOutcome::Blocked {
            blockers, revision, ..
        } => {
            assert!(
                blockers
                    .iter()
                    .any(|blocker| matches!(blocker, ResumeBlocker::StopUnconfirmed { .. }))
            );
            // The hold advances the revision, so the refusal is itself durable.
            assert_eq!(revision, Some(ExecutionRevision::new(3).unwrap()));
        }
        other => panic!("expected an unconfirmed-stop block, got {other:?}"),
    }
    let held = harness
        .restart()
        .load(harness.project, harness.execution)
        .unwrap()
        .unwrap()
        .snapshot()
        .clone();
    assert_eq!(held.state(), ExecutionState::WaitingHuman);
    assert_eq!(
        held.stop().map(|stop| stop.reason()),
        Some(StopReason::StopUnconfirmed)
    );

    // Once the human confirms the stop, the resume continues and preserves the
    // consumed budget.
    let stopped =
        quit_confirmed_snapshot(&held, ExecutionRevision::new(4).unwrap(), true).expect("a stop");
    harness.save_snapshot(Some(ExecutionRevision::new(3).unwrap()), &stopped);
    let request = harness.resume_request(0xda11, approval.revision());
    let outcome = resume(
        &mut harness.restart(),
        &request,
        &harness.observed_facts(),
        None,
        &inputs(&approval),
    )
    .expect("a resume");
    match outcome {
        ResumeOutcome::Resumed { task, snapshot, .. } => {
            assert_eq!(task, Some(task_ref(harness.project, 1)));
            assert_eq!(snapshot.revision().get(), 5);
            assert_eq!(snapshot.budget().consumed().active_seconds(), 0);
        }
        other => panic!("expected a resume, got {other:?}"),
    }
}

#[test]
fn the_budget_is_preserved_by_a_human_resume_and_an_exhausted_budget_blocks_it() {
    let mut harness = Harness::with_tasks(1);
    let supervision_id = supervision(harness.project, 0xd650);
    let child_identity = child(harness.project, 0xd660);
    let snapshot = running_snapshot(
        harness.project,
        harness.execution,
        harness.repo.path(),
        ExecutionRevision::new(2).unwrap(),
        supervision_id,
        child_identity,
        1_500,
    );
    harness.save_snapshot(Some(ExecutionRevision::INITIAL), &snapshot);
    let approval = harness.approval();
    let mut facts = harness.observed_facts().with_child(ChildStatus::new(
        supervision_id,
        ChildState::Running,
        1_500,
        1,
        0,
        false,
        Vec::new(),
    ));
    // The Task must be stoppable: record a confirmed stop first.
    let stopped = quit_confirmed_snapshot(
        &harness.snapshot(),
        ExecutionRevision::new(3).unwrap(),
        true,
    )
    .expect("a stopped snapshot");
    harness.save_snapshot(Some(ExecutionRevision::new(2).unwrap()), &stopped);

    let request = harness.resume_request(0xdb00, approval.revision());
    let mut store = harness.restart();
    let outcome = resume(&mut store, &request, &facts, None, &inputs(&approval)).expect("a resume");
    match outcome {
        ResumeOutcome::Resumed { snapshot, .. } => {
            assert_eq!(snapshot.budget().consumed().active_seconds(), 1_500);
            assert_eq!(snapshot.budget().consumed().additional_runs(), 1);
        }
        other => panic!("expected a resume, got {other:?}"),
    }

    // A store whose consumption is at the limit refuses even a human resume.
    let mut harness = Harness::new();
    let exhausted = ExecutionSnapshot::new(SnapshotInput {
        project_id: harness.project,
        execution_id: harness.execution,
        revision: ExecutionRevision::new(2).unwrap(),
        state: ExecutionState::Stopped,
        plan: SnapshotPlan::new(plan_path(), PlanDigest::sha256(b"# plan"), plan_revision()),
        workspace: SnapshotWorkspace::new(
            harness.repo.path(),
            BRANCH,
            BASE_BRANCH,
            Some(baseline()),
        )
        .unwrap(),
        current_task: Some(task_ref(harness.project, 1)),
        tasks: harness.snapshot().tasks().to_vec(),
        stop: Some(
            herness_sdd_execute::StopRecord::new(
                StopReason::RecoveryRequired,
                Some(HumanAction::ConfirmRecovery),
            )
            .unwrap(),
        ),
        budget: SnapshotBudget::new(
            BudgetConsumption::new(7_200, 0, None),
            BudgetConsumption::zero(),
        ),
        applied_revision: herness_sdd_execute::AppliedRevision::current(plan_revision()),
        final_project_sequence: None,
    })
    .expect("an exhausted snapshot");
    harness.save_snapshot(Some(ExecutionRevision::INITIAL), &exhausted);
    let approval = harness.approval();
    facts = harness.observed_facts();
    let request = harness.resume_request(0xdb01, approval.revision());
    let outcome = resume(
        &mut harness.restart(),
        &request,
        &facts,
        None,
        &inputs(&approval),
    )
    .expect("a resume");
    match outcome {
        ResumeOutcome::Blocked {
            blockers,
            stop,
            revision,
        } => {
            assert!(blockers.iter().any(|blocker| matches!(
                blocker,
                ResumeBlocker::BudgetExhausted {
                    action: HumanAction::RaiseBudget,
                    ..
                }
            )));
            assert_eq!(
                stop.map(|stop| stop.reason()),
                Some(StopReason::BudgetExhausted)
            );
            assert_eq!(revision, Some(ExecutionRevision::new(3).unwrap()));
        }
        other => panic!("expected a budget block, got {other:?}"),
    }
    let stored = harness
        .restart()
        .load(harness.project, harness.execution)
        .unwrap()
        .unwrap()
        .snapshot()
        .clone();
    // The hold keeps the confirmed stop instead of regressing to waiting_human.
    assert_eq!(stored.state(), ExecutionState::Stopped);
    assert_eq!(stored.budget().consumed().active_seconds(), 7_200);
}

#[test]
fn an_open_plan_change_latch_blocks_the_resume_after_a_restart() {
    let mut harness = Harness::new();
    let approval = harness.approval();
    let latch = PlanChangeLatch::engage(
        harness.project,
        harness.execution,
        approval.approval_id(),
        PlanExpectation::new(
            plan_path(),
            approval.plan().digest().clone(),
            approval.plan().byte_length(),
            plan_revision(),
        ),
        PlanChange::from_observation(
            PlanChangeReason::Missing,
            &herness_sdd_execute::PlanObservation::missing(),
            None,
        )
        .expect("a plan change"),
    )
    .expect("a latch");
    harness.save_latch(&latch);
    let stopped = quit_confirmed_snapshot(
        &harness.snapshot(),
        ExecutionRevision::new(2).unwrap(),
        true,
    )
    .unwrap();
    harness.save_snapshot(Some(ExecutionRevision::INITIAL), &stopped);

    let request = harness.resume_request(0xdc00, approval.revision());
    let outcome = resume(
        &mut harness.restart(),
        &request,
        &harness.observed_facts(),
        None,
        &inputs(&approval),
    )
    .expect("a resume");
    match outcome {
        ResumeOutcome::Blocked {
            blockers,
            stop,
            revision,
        } => {
            assert!(
                blockers
                    .iter()
                    .any(|blocker| matches!(blocker, ResumeBlocker::PlanChangeOpen { .. }))
            );
            assert_eq!(stop, None, "the latch already holds the stop");
            assert_eq!(revision, None, "nothing was written");
        }
        other => panic!("expected a plan-change block, got {other:?}"),
    }
    // The latch is still open and the state unchanged.
    assert!(
        harness
            .restart()
            .plan_change_latch(harness.project, harness.execution)
            .unwrap()
            .unwrap()
            .is_open()
    );
    assert_eq!(harness.snapshot().state(), ExecutionState::Stopped);
}

#[test]
fn an_unresolved_git_result_blocks_the_resume_and_stays_unknown_after_a_restart() {
    let mut harness = Harness::new();
    let approval = harness.approval();
    let task = task_ref(harness.project, 1);
    let bytes = harness.repo.write("docs/adr/0001.md", "# One\n");
    let parent = harness.repo.head();
    // The intent is recorded, the commit never ran, and the result was never
    // stored: HEAD is still the expected parent.
    let intent = git_intent(&harness, task, "docs/adr/0001.md", &bytes, &parent, 0xdd00);
    harness.save_git(&intent);
    let stopped = quit_confirmed_snapshot(
        &harness.snapshot(),
        ExecutionRevision::new(2).unwrap(),
        true,
    )
    .unwrap();
    harness.save_snapshot(Some(ExecutionRevision::INITIAL), &stopped);

    // A second connection reads the same unknown classification.
    let restarted = harness.restart();
    let stored = herness_sdd_execute::StoredExecution::new(
        restarted
            .load(harness.project, harness.execution)
            .unwrap()
            .unwrap()
            .revision(),
        restarted
            .load(harness.project, harness.execution)
            .unwrap()
            .unwrap()
            .snapshot()
            .clone(),
    )
    .unwrap();
    let report = reconcile(
        &stored,
        &harness.facts(),
        RecoveryContext {
            plan_change: None,
            approval: Some(&approval),
        },
    )
    .unwrap();
    assert_eq!(
        item(&report, RecoveryRecordKind::Git),
        RecoveryClass::Unknown
    );

    let request = harness.resume_request(0xdd01, approval.revision());
    let outcome = resume(
        &mut harness.restart(),
        &request,
        &harness.observed_facts(),
        None,
        &inputs(&approval),
    )
    .expect("a resume");
    match outcome {
        ResumeOutcome::Blocked { blockers, stop, .. } => {
            assert!(blockers.iter().any(|blocker| matches!(
                blocker,
                ResumeBlocker::Unresolved {
                    kind: RecoveryRecordKind::Git,
                    ..
                }
            )));
            assert_eq!(
                stop.map(|stop| stop.reason()),
                Some(StopReason::GitResultUnknown)
            );
        }
        other => panic!("expected a git block, got {other:?}"),
    }
    // The Git journal still has one intent row and no commit exists.
    let journal = harness
        .restart()
        .git_entries(harness.project, harness.execution)
        .unwrap();
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].state(), GitJournalState::Intent);
    assert_eq!(harness.repo.commit_count(), 1);
}

// ---------------------------------------------------------------------------
// Quit
// ---------------------------------------------------------------------------

#[test]
fn quit_closes_dispatch_sends_and_commits_and_saves_confirmed_or_unconfirmed() {
    // A confirmed quit stops the execution durably.
    let mut harness = Harness::new();
    let requested =
        quit_requested_snapshot(&harness.snapshot(), ExecutionRevision::new(2).unwrap()).unwrap();
    harness.save_snapshot(Some(ExecutionRevision::INITIAL), &requested);
    let reopened = harness.restart();
    let stored = reopened
        .load(harness.project, harness.execution)
        .unwrap()
        .unwrap()
        .snapshot()
        .clone();
    assert_eq!(stored.state(), ExecutionState::WaitingHuman);
    assert_eq!(
        stored.stop().map(|stop| stop.reason()),
        Some(StopReason::PauseRequested)
    );
    assert_eq!(
        stored.stop().and_then(|stop| stop.required_action()),
        Some(HumanAction::ConfirmStop)
    );

    let confirmed =
        quit_confirmed_snapshot(&stored, ExecutionRevision::new(3).unwrap(), true).unwrap();
    assert_eq!(confirmed.state(), ExecutionState::Stopped);
    assert_eq!(
        confirmed.stop().map(|stop| stop.reason()),
        Some(StopReason::RecoveryRequired)
    );

    // An unconfirmed H1 stop is recorded as unconfirmed, never as a stop.
    let unconfirmed =
        quit_confirmed_snapshot(&stored, ExecutionRevision::new(3).unwrap(), false).unwrap();
    assert_eq!(unconfirmed.state(), ExecutionState::Stopped);
    assert_eq!(
        unconfirmed.stop().map(|stop| stop.reason()),
        Some(StopReason::StopUnconfirmed)
    );
    assert_eq!(
        unconfirmed.stop().and_then(|stop| stop.required_action()),
        Some(HumanAction::ConfirmStop)
    );
}

#[test]
fn the_desktop_quit_and_restore_report_zero_requests_and_surface_a_save_failure() {
    let harness = Harness::new();
    let store = std::sync::Arc::new(std::sync::Mutex::new(harness.restart()));
    let handle =
        herness_desktop::supervision::store::StoreHandle::new(std::sync::Arc::clone(&store));
    let mut host = DesktopRecoveryHost::new(
        handle.clone(),
        Some(AbsolutePath::new(git_program()).unwrap()),
    )
    .with_documents(NoDocuments);
    let mut children = CountingChildren::default();

    // Restore is read-only and issues no request.
    let startup = host.restore(&mut children);
    assert_eq!(startup.request_count(), 0);
    assert_eq!(children.reads(), 1);
    assert!(startup.failures().is_empty());

    // Quit begins by closing dispatch, sends, and commits.
    let begun = host.begin_quit();
    assert!(
        begun.is_complete(),
        "{}",
        begun.obstacle().unwrap_or_default()
    );
    assert_eq!(begun.marks().len(), 1);
    let reopened = store.lock().expect("the store");
    assert_eq!(
        reopened
            .load(harness.project, harness.execution)
            .unwrap()
            .unwrap()
            .snapshot()
            .state(),
        ExecutionState::WaitingHuman
    );
    drop(reopened);

    // An H1 report that did not confirm the run leaves the stop unconfirmed.
    let h1 = ShutdownReport::new(
        ShutdownOutcome::InProgress,
        vec![ShutdownRun::new(
            harness.project,
            RunId::new(harness.project),
            RunState::Running,
            Some(StopReport::Unconfirmed),
            false,
            None,
        )],
        vec![RunId::new(harness.project)],
        vec![RunId::new(harness.project)],
        0,
        1,
    );
    let marked = host.mark_quit(&h1);
    assert_eq!(marked.unconfirmed().count(), 1);
    let reopened = store.lock().expect("the store");
    let stored = reopened
        .load(harness.project, harness.execution)
        .unwrap()
        .unwrap()
        .snapshot()
        .clone();
    assert_eq!(stored.state(), ExecutionState::Stopped);
    assert_eq!(
        stored.stop().map(|stop| stop.reason()),
        Some(StopReason::StopUnconfirmed)
    );
    drop(reopened);

    // A failing H4 save is reported as a reason quit did not complete. The
    // second connection carries the injected commit fault, so the stop write
    // fails before any row is written.
    let fresh = Harness::new();
    let store = std::sync::Arc::new(std::sync::Mutex::new(fresh.restart()));
    store
        .lock()
        .expect("the store")
        .set_commit_fault(Some(herness_store::test_support::CommitFault::BeforeRows));
    let handle =
        herness_desktop::supervision::store::StoreHandle::new(std::sync::Arc::clone(&store));
    let mut host = DesktopRecoveryHost::new(handle, None).with_documents(NoDocuments);
    let failed = host.begin_quit();
    assert!(!failed.is_complete(), "the H4 save failure is surfaced");
    assert!(
        failed
            .obstacle()
            .expect("an obstacle")
            .contains("could not be saved")
    );
    assert_eq!(
        host.store_handle()
            .lock()
            .load(fresh.project, fresh.execution)
            .unwrap()
            .unwrap()
            .snapshot()
            .state(),
        ExecutionState::Ready,
        "a failed save wrote nothing"
    );
}

#[test]
fn quit_keeps_every_recorded_range_evidence_and_the_consumed_budget() {
    let mut harness = Harness::new();
    // One Task is already complete with a recorded range; the next one is
    // pending. The quit must not erase either fact.
    let completed = TaskSnapshot::new(
        task_ref(harness.project, 1),
        herness_sdd_execute::TaskProgression::Complete,
        TaskPhase::Complete,
        None,
        None,
        CommitPolicy::Required,
        Some(CommitRange::new(baseline(), CommitSha::parse("b".repeat(40)).unwrap()).unwrap()),
        None,
        vec![herness_supervision::EvidenceId::from_parts(
            harness.project,
            uuid("d8000000-0000-4000-8000-000000000001"),
        )],
        None,
        herness_sdd_execute::AppliedRevision::current(plan_revision()),
    )
    .expect("a complete Task");
    let snapshot = ExecutionSnapshot::new(SnapshotInput {
        project_id: harness.project,
        execution_id: harness.execution,
        revision: ExecutionRevision::new(2).unwrap(),
        state: ExecutionState::Running,
        plan: SnapshotPlan::new(plan_path(), PlanDigest::sha256(b"# plan"), plan_revision()),
        workspace: SnapshotWorkspace::new(
            harness.repo.path(),
            BRANCH,
            BASE_BRANCH,
            Some(baseline()),
        )
        .unwrap(),
        current_task: Some(task_ref(harness.project, 2)),
        tasks: vec![
            completed,
            TaskSnapshot::new(
                task_ref(harness.project, 2),
                herness_sdd_execute::TaskProgression::Active,
                TaskPhase::Running,
                Some(H2SupervisionRef::new(supervision(harness.project, 0xd810))),
                Some(child(harness.project, 0xd820)),
                CommitPolicy::Required,
                None,
                None,
                Vec::new(),
                None,
                herness_sdd_execute::AppliedRevision::current(plan_revision()),
            )
            .expect("an active Task"),
        ],
        stop: None,
        budget: SnapshotBudget::new(
            BudgetConsumption::new(900, 2, None),
            BudgetConsumption::zero(),
        ),
        applied_revision: herness_sdd_execute::AppliedRevision::current(plan_revision()),
        final_project_sequence: None,
    })
    .expect("a two-Task snapshot");
    harness.save_snapshot(Some(ExecutionRevision::INITIAL), &snapshot);

    let stopped = quit_confirmed_snapshot(&snapshot, ExecutionRevision::new(3).unwrap(), true)
        .expect("a stopped snapshot");
    harness.save_snapshot(Some(ExecutionRevision::new(2).unwrap()), &stopped);

    let reopened = harness.restart();
    let stored = reopened
        .load(harness.project, harness.execution)
        .unwrap()
        .unwrap()
        .snapshot()
        .clone();
    assert_eq!(stored.state(), ExecutionState::Stopped);
    let first = stored.task(TaskNumber::new(1).unwrap()).expect("Task 1");
    assert!(first.progression().is_complete());
    assert_eq!(
        first
            .commit_range()
            .map(|range| range.head().as_str().to_owned()),
        Some("b".repeat(40))
    );
    assert_eq!(first.evidence().len(), 1, "evidence is preserved");
    let second = stored.task(TaskNumber::new(2).unwrap()).expect("Task 2");
    assert!(!second.progression().is_complete());
    assert_eq!(stored.budget().consumed().active_seconds(), 900);
    assert_eq!(stored.budget().consumed().additional_runs(), 2);

    // A terminal or finished execution is never touched by a quit.
    let finished = harness.snapshot();
    assert!(herness_sdd_execute::quit_skips(
        &quit_confirmed_snapshot(&finished, ExecutionRevision::new(9).unwrap(), true).unwrap()
    ));
}

// ---------------------------------------------------------------------------
// A separate process re-reads the same restored classification
// ---------------------------------------------------------------------------

#[test]
fn a_separate_process_re_reads_the_same_reconciliation() {
    let temp = tempfile::tempdir().expect("a temporary directory");
    let app_data = temp.path().join("app-data");
    let repo = Repo::new();
    let project = project();
    let execution = execution(project);
    let approval = approval(project, repo.path());

    // This process records a running Task, a confirmed stop, and a saved budget.
    let config = StoreConfig::new(&app_data).expect("a store config");
    let mut store = Store::open(config.clone()).expect("a store");
    store
        .record_approval_revision(&approval)
        .expect("an approval");
    let snapshot = ready_snapshot(project, execution, repo.path(), 1);
    store
        .compare_and_swap(project, execution, None, &snapshot)
        .expect("a snapshot");
    let supervision_id = supervision(project, 0xde00);
    let child_identity = child(project, 0xde10);
    let running = running_snapshot(
        project,
        execution,
        repo.path(),
        ExecutionRevision::new(2).unwrap(),
        supervision_id,
        child_identity,
        240,
    );
    store
        .compare_and_swap(
            project,
            execution,
            Some(ExecutionRevision::INITIAL),
            &running,
        )
        .expect("a running snapshot");
    let stopped = quit_confirmed_snapshot(&running, ExecutionRevision::new(3).unwrap(), false)
        .expect("a stopped snapshot");
    store
        .compare_and_swap(
            project,
            execution,
            Some(ExecutionRevision::new(2).unwrap()),
            &stopped,
        )
        .expect("a stored stop");
    drop(store);

    // A child process reads the same database and reports the same values.
    let exe = std::env::current_exe().expect("the current test executable");
    let output = Command::new(exe)
        .arg("--exact")
        .arg("recovery_worker_entrypoint")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env("HERNESS_TASK20_WORKER", "1")
        .env("HERNESS_TASK20_APP_DATA", &app_data)
        .env("HERNESS_TASK20_PROJECT", project.to_string())
        .env("HERNESS_TASK20_EXECUTION", execution.to_string())
        .env("HERNESS_TASK20_CHECKOUT", repo.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("the worker starts");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "the recovery worker failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("TASK20_OK"),
        "the worker reported the restored state\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("state=stopped"));
    assert!(stdout.contains("stop=stop_unconfirmed"));
    assert!(stdout.contains("budget=240"));
    assert!(stdout.contains("external_requests=0"));
    assert!(stdout.contains("requests=0"));
}

/// A separate-process worker: reads the same store and reconciles it.
#[test]
fn recovery_worker_entrypoint() {
    if std::env::var_os("HERNESS_TASK20_WORKER").is_none() {
        return;
    }
    let app_data = PathBuf::from(std::env::var("HERNESS_TASK20_APP_DATA").expect("app data"));
    let project: ProjectId = std::env::var("HERNESS_TASK20_PROJECT")
        .expect("project")
        .parse()
        .expect("a project id");
    let execution: ExecutionId = std::env::var("HERNESS_TASK20_EXECUTION")
        .expect("execution")
        .parse()
        .expect("an execution id");
    let checkout = std::env::var("HERNESS_TASK20_CHECKOUT").expect("checkout");

    let config = StoreConfig::new(&app_data).expect("a store config");
    let mut store = Store::open(config).expect("a reopened store");
    let stored = store
        .load(project, execution)
        .expect("a load")
        .expect("a stored execution");
    let approval = store
        .latest_approval_revision(project, approval_id(project))
        .expect("an approval load")
        .expect("a stored approval");
    let facts = RecoveryFacts::new()
        .with_dispatch(
            store
                .dispatch_entries(project, execution)
                .expect("dispatch rows"),
        )
        .with_git(store.git_entries(project, execution).expect("git rows"))
        .with_progress(
            store
                .progress_entries(project, execution)
                .expect("progress rows"),
        )
        .with_control(
            store
                .control_records(project, execution)
                .expect("control rows"),
        )
        .with_reservations(
            store
                .task_reservations(project, execution)
                .expect("reservation rows"),
        );
    let report = reconcile(
        &stored,
        &facts,
        RecoveryContext {
            plan_change: store
                .plan_change_latch(project, execution)
                .expect("a latch load")
                .as_ref(),
            approval: Some(&approval),
        },
    )
    .expect("a reconciliation");
    // Nothing was dispatched, sent, or committed by this read.
    assert_eq!(report.external_requests(), 0);
    assert_eq!(
        store.load(project, execution).unwrap().unwrap().revision(),
        stored.revision()
    );
    assert!(checkout.starts_with('/'), "the checkout path is absolute");
    let stop = report
        .stop()
        .map(|stop| stop.reason().as_str().to_owned())
        .unwrap_or_else(|| "none".to_owned());
    println!(
        "TASK20_OK state={} stop={} budget={} external_requests={} requests=0",
        report.state().as_str(),
        stop,
        report.budget().active_seconds(),
        report.external_requests()
    );
    // Keep the mutable handle used above in one place so the read cannot be
    // mistaken for a write path.
    let _ = &mut store;
}

// ---------------------------------------------------------------------------
// Helper extension: previous HEAD
// ---------------------------------------------------------------------------

trait RepoParent {
    fn parent_head(&self) -> String;
}

impl RepoParent for Repo {
    fn parent_head(&self) -> String {
        git_stdout(&self.root, &["rev-parse", "HEAD^{commit}^"])
    }
}
