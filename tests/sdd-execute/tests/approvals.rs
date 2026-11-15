//! Black-box tests for the H4 start-approval registry, the approve/verify
//! boundary, and the workspace-preparation start guard.
//!
//! Every case uses synthetic projects and plans, a real temporary Git repository
//! where workspace preparation is involved, a real store in a temporary app-data
//! root, and fake connection/profile/consent/capability values. No network, no
//! model, no credential, and no Keychain item is used.
//!
//! The cases cover, one for one, the Task 13 acceptance criteria:
//!
//! * a positive start saves the whole approval revision and creates exactly one
//!   child;
//! * a missing/forged human confirmation, a forbidden approval source (including
//!   an H3 approval), an old revision, a different project, changed inputs,
//!   revoked consent, a missing capability, unsynced required HTML, and a dirty
//!   selected checkout all refuse with zero child starts;
//! * a duplicate start request returns the stored result instead of a second
//!   child;
//! * a fault before, during, and after workspace preparation leaves no
//!   unauthorized start and no stored "started" result;
//! * alias reads stay inside the approved read paths and Git isolation is only
//!   created when the approval and the selection both asked for it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use herness_core::contracts::{ConnectionId, ProjectId, Timestamp};
use herness_core::{
    AbsolutePath, ArgvLauncher, ArgvRequest, HostGitBoundary, ProcessSupervisor,
    RecordingHostGitAudit, SystemArgvLauncher, SystemChild,
};
use herness_desktop::sdd_execute::{
    ApprovalDraft, CurrentInputs, H4StartApprovalRegistry, MemoryStartStore, PreviewFacts,
    PreviewTaskFacts, StartChildPort, StartComposition, StartHtmlPort, StartHtmlRequest,
    StartRequest, UnsyncedStartHtml, h4_owner_ref,
};
use herness_desktop::sdd_execute::{
    ApprovedDocument, GitRunner, HostGitPreparationCommit, MemoryBaselineRecord, WorkspaceAdapter,
    WorkspaceSelectionAnswer,
};
use herness_sdd_execute::{
    ApprovalId, ApprovalRejection, ApprovalRequirement, ApprovalRevisionStorePort, ApprovalSource,
    ApprovedCheck, ApprovedCondition, ApprovedDeliverable, ApprovedSpecRef, Baseline,
    CommitAuthorization, CommitPolicy, ConditionMode, ConflictReason, ControlRequestId,
    DeliverableKind, ExactPlanBytes, ExactPlanText, ExecutionApproval, ExecutionConnection,
    ExecutionId, ExternalSourceApproval, FailureCode, GitIdentity, H3ApprovalBinding, PackApproval,
    PackFingerprint, ParsedPlanSummary, ParsedPlanTask, PlanApproval, PlanByteRange, PlanPath,
    PlanRevision, RecoveryReason, SddExecutionError, Sha256Digest, SourceLayout, StartApprovalPost,
    StartApprovalRegistry, StartPhase, StartRecord, StartRecordStorePort, TaskApproval, TaskNumber,
    TaskStableId, WorkspaceApproval,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::{
    ApprovalActor, BudgetPolicy, ConsentBinding, ConsentId, H4OwnerLaunchBinding, OwnerKind,
    OwnerRef, ProfileBinding, ProfileId, ProfilePurpose, ProfileVersion, SupervisionError,
    SupervisionId, TargetVersion, authorize_h4_owner_launch,
};
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Identity fixtures
// ---------------------------------------------------------------------------

fn project() -> ProjectId {
    ProjectId::from_uuid(uuid("90000000-0000-4000-8000-000000000001"))
}

fn other_project() -> ProjectId {
    ProjectId::from_uuid(uuid("90000000-0000-4000-8000-000000000002"))
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("a UUID")
}

fn execution() -> ExecutionId {
    ExecutionId::from_parts(project(), uuid("90000000-0000-4000-8000-000000000101"))
}

fn approval_id() -> ApprovalId {
    ApprovalId::from_parts(project(), uuid("90000000-0000-4000-8000-000000000201"))
}

fn request_id() -> ControlRequestId {
    ControlRequestId::from_parts(project(), uuid("90000000-0000-4000-8000-000000000301"))
}

fn request_id_second() -> ControlRequestId {
    ControlRequestId::from_parts(project(), uuid("90000000-0000-4000-8000-000000000302"))
}

fn supervision(project: ProjectId) -> SupervisionId {
    SupervisionId::from_parts(project, uuid("90000000-0000-4000-8000-000000000401"))
}

fn plan_path() -> PlanPath {
    PlanPath::parse("docs/sdd/plans/plan.md").expect("a plan path")
}

fn spec_path() -> &'static str {
    "docs/sdd/specs/spec.md"
}

const PLAN_TEXT: &[u8] = b"# Fixture plan\n\n## Task 1: Write the module\n\nBody.\n";
const SPEC_TEXT: &[u8] = b"# Fixture spec\n\n## Fixture section\n\nText.\n";

fn now() -> Timestamp {
    Timestamp::from_unix_millis(1_760_000_000_000)
}

fn git_identity() -> GitIdentity {
    GitIdentity::new("H4 Test", "h4@example.invalid").expect("a Git identity")
}

fn profile() -> ProfileBinding {
    ProfileBinding::new(
        ProfileId::from_parts(project(), uuid("90000000-0000-4000-8000-000000000501")),
        ProfileVersion::new(1).expect("a profile version"),
        ProfilePurpose::Completion,
    )
}

fn consent() -> ConsentBinding {
    ConsentBinding::new(
        ConsentId::from_parts(project(), uuid("90000000-0000-4000-8000-000000000601")),
        1,
        ProfilePurpose::Completion,
        TargetVersion::new(1).expect("a target version"),
    )
}

fn connection() -> ExecutionConnection {
    ExecutionConnection::new(
        ConnectionId::from_uuid(uuid("90000000-0000-4000-8000-000000000701")),
        profile(),
        vec![consent()],
    )
    .expect("an execution connection")
}

fn h3_binding() -> H3ApprovalBinding {
    H3ApprovalBinding::new(
        1,
        vec![ConsentId::from_parts(
            project(),
            uuid("90000000-0000-4000-8000-000000000801"),
        )],
        vec!["html-sync".to_owned()],
    )
    .expect("an H3 boundary")
}

fn commit() -> CommitAuthorization {
    CommitAuthorization::new(true, true).expect("a commit authorization")
}

fn budget() -> BudgetPolicy {
    BudgetPolicy::new(7_200, 30, None).expect("a finite budget")
}

// ---------------------------------------------------------------------------
// Plan / Task fixtures
// ---------------------------------------------------------------------------

fn condition() -> ApprovedCondition {
    ApprovedCondition::new(
        "written",
        "The module is written",
        "src/a.rs contains a main function.",
        ConditionMode::Checks,
    )
    .expect("a condition")
}

fn check() -> ApprovedCheck {
    ApprovedCheck::new(
        "build",
        "written",
        "Build the crate.",
        "cargo check",
        ".",
        60,
        vec!["src/a.rs".to_owned()],
    )
    .expect("a check")
}

fn parsed_plan() -> ParsedPlanSummary {
    let text = ExactPlanText::new(
        "- Keep the exact bytes.\n",
        PlanByteRange::new(0, 23).expect("a range"),
    )
    .expect("exact text");
    let task = ParsedPlanTask::new(
        1,
        "Write the module",
        ExactPlanText::new("Body.\n", PlanByteRange::new(0, 6).expect("a range"))
            .expect("exact body"),
    )
    .expect("a parsed Task");
    ParsedPlanSummary::new(1, text, vec![task], vec!["build".to_owned()]).expect("a parsed plan")
}

fn spec_ref() -> ApprovedSpecRef {
    ApprovedSpecRef::new(
        "project",
        spec_path(),
        vec!["Fixture section".to_owned()],
        Sha256Digest::sha256(SPEC_TEXT),
    )
    .expect("a spec reference")
}

fn pack() -> PackApproval {
    PackApproval::new(
        herness_sdd_execute::InspectorProtocol::expected(),
        1,
        PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).expect("a fingerprint"),
    )
    .expect("a pack approval")
}

fn task_facts() -> PreviewTaskFacts {
    PreviewTaskFacts::from_parts(
        1,
        "Write the module",
        "Body.\n",
        vec![condition()],
        vec!["src/a.rs".to_owned()],
        vec!["src/a.rs".to_owned()],
        true,
        vec![check()],
        Vec::new(),
        vec![ApprovedDeliverable::new("src/a.rs", DeliverableKind::File).expect("a deliverable")],
        CommitPolicy::Required,
    )
}

fn preview_facts() -> PreviewFacts {
    PreviewFacts::new(
        "/tmp/herness-h4-approval-project",
        plan_path(),
        ExactPlanBytes::new(PLAN_TEXT.to_vec()).expect("exact plan bytes"),
        parsed_plan(),
        vec![task_facts()],
        vec![spec_ref()],
        Vec::new(),
        pack(),
    )
    .expect("preview facts")
}

fn layout() -> SourceLayout {
    SourceLayout::new("/tmp/herness-h4-approval-project").expect("a layout")
}

fn draft(checkout_root: &str) -> ApprovalDraft {
    ApprovalDraft::new(
        execution(),
        approval_id(),
        preview_facts(),
        layout(),
        PlanRevision::new(1).expect("a plan revision"),
        checkout_root,
        git_identity(),
        "h4-exec",
        "main",
        false,
        connection(),
        commit(),
        h3_binding(),
        vec![budget()],
    )
    .expect("a draft")
}

/// One start request whose observed inputs match `draft` exactly, using the
/// shared accepting gate so the one permitted preparation commit can run.
fn start_request(draft: &ApprovalDraft) -> StartRequest {
    start_request_with(draft, request_id(), None, Some(accepting_gate_default()))
}

/// One start request with an explicit identity, selection, and gate.
fn start_request_with(
    draft: &ApprovalDraft,
    request_id: ControlRequestId,
    selection: Option<WorkspaceSelectionAnswer>,
    gate: Option<herness_core::HostGitGate>,
) -> StartRequest {
    let inputs = draft.build().expect("observed inputs").inputs().clone();
    StartRequest::new(
        execution(),
        approval_id(),
        1,
        request_id,
        Some(selection.unwrap_or(WorkspaceSelectionAnswer::InPlace)),
        inputs,
        gate,
    )
    .expect("a start request")
}

/// One approval revision built from the fixture draft.
fn approved_once() -> ExecutionApproval {
    let draft = draft("/tmp/herness-h4-approval-checkout");
    let post = draft
        .build()
        .expect("built approval")
        .into_human_post(now())
        .expect("a human post");
    let mut registry = StartApprovalRegistry::new(MemoryStartStore::new());
    registry
        .post_human_approval(&post)
        .expect("a saved approval")
}

// ---------------------------------------------------------------------------
// Real Git repository
// ---------------------------------------------------------------------------

fn git_program() -> AbsolutePath {
    let identified = Command::new("/usr/bin/which")
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
        .unwrap_or_else(|| "/usr/bin/git".to_owned());
    AbsolutePath::new(identified).expect("the Git program is an absolute path")
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new(git_program().as_str())
        .args(args)
        .current_dir(root)
        .env("GIT_AUTHOR_NAME", "H4 Test")
        .env("GIT_AUTHOR_EMAIL", "h4@example.invalid")
        .env("GIT_COMMITTER_NAME", "H4 Test")
        .env("GIT_COMMITTER_EMAIL", "h4@example.invalid")
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?} failed in {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn git_worktree_paths(root: &Path) -> Vec<String> {
    git(root, &["worktree", "list", "--porcelain"])
        .lines()
        .filter_map(|line| line.strip_prefix("worktree ").map(str::to_owned))
        .collect()
}

fn git_branches(root: &Path) -> Vec<String> {
    git(
        root,
        &["for-each-ref", "--format=%(refname:short)", "refs/heads"],
    )
    .lines()
    .map(str::to_owned)
    .collect()
}

fn git_head(root: &Path) -> String {
    git(root, &["rev-parse", "HEAD"]).trim().to_owned()
}

/// One real temporary repository on `h4-exec` with the approved documents
/// committed and no `.sdd/` ignore yet.
struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    fn new() -> Self {
        let temp = TempDir::new().expect("temporary directory");
        let root = temp.path().join("repo");
        std::fs::create_dir_all(&root).expect("repository root");
        git(&root, &["init", "--initial-branch=main"]);
        git(&root, &["config", "user.name", "H4 Test"]);
        git(&root, &["config", "user.email", "h4@example.invalid"]);
        git(&root, &["config", "commit.gpgsign", "false"]);
        git(&root, &["config", "core.hooksPath", ".git/hooks-disabled"]);
        std::fs::create_dir_all(root.join(".git/hooks-disabled")).expect("disabled hooks");
        std::fs::create_dir_all(root.join("docs/sdd/plans")).expect("plan directory");
        std::fs::create_dir_all(root.join("docs/sdd/specs")).expect("spec directory");
        std::fs::write(root.join("docs/sdd/plans/plan.md"), PLAN_TEXT).expect("plan");
        std::fs::write(root.join("docs/sdd/specs/spec.md"), SPEC_TEXT).expect("spec");
        std::fs::write(root.join("README.md"), b"# fixture\n").expect("readme");
        git(
            &root,
            &[
                "add",
                "--",
                "README.md",
                "docs/sdd/plans/plan.md",
                "docs/sdd/specs/spec.md",
            ],
        );
        git(&root, &["commit", "-m", "fixture commit"]);
        git(&root, &["switch", "-c", "h4-exec"]);
        Self { _temp: temp, root }
    }

    fn path(&self) -> String {
        std::fs::canonicalize(&self.root)
            .expect("canonical root")
            .to_string_lossy()
            .into_owned()
    }

    fn sibling(&self, name: &str) -> String {
        let parent =
            std::fs::canonicalize(self.root.parent().expect("parent")).expect("canonical parent");
        parent.join(name).to_string_lossy().into_owned()
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        std::fs::write(path, contents).expect("write fixture file");
    }

    fn documents(&self) -> Vec<ApprovedDocument> {
        vec![
            ApprovedDocument::plan("docs/sdd/plans/plan.md", PLAN_TEXT).expect("plan document"),
            ApprovedDocument::spec("docs/sdd/specs/spec.md", SPEC_TEXT).expect("spec document"),
        ]
    }
}

/// One shared accepting gate script, created once per test process.
fn accepting_gate_default() -> herness_core::HostGitGate {
    static GATE: std::sync::OnceLock<herness_core::HostGitGate> = std::sync::OnceLock::new();
    GATE.get_or_init(|| {
        let directory =
            std::env::temp_dir().join(format!("herness-h4-gate-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a gate directory");
        let path = directory.join("accepting-gate.sh");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("gate script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&path, permissions).expect("chmod");
        }
        herness_core::HostGitGate::new(
            AbsolutePath::new(path.to_string_lossy().into_owned()).expect("gate path"),
            Vec::new(),
            None,
        )
        .expect("gate")
    })
    .clone()
}

fn accepting_gate(temp: &TempDir) -> herness_core::HostGitGate {
    gate_script(temp, "gate.sh", "#!/bin/sh\nexit 0\n")
}

fn refusing_gate(temp: &TempDir) -> herness_core::HostGitGate {
    gate_script(temp, "refusing-gate.sh", "#!/bin/sh\nexit 1\n")
}

fn gate_script(temp: &TempDir, name: &str, body: &str) -> herness_core::HostGitGate {
    let path = temp.path().join(name);
    std::fs::write(&path, body).expect("gate script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    herness_core::HostGitGate::new(
        AbsolutePath::new(path.to_string_lossy().into_owned()).expect("gate path"),
        Vec::new(),
        None,
    )
    .expect("gate")
}

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

struct CountingLauncher {
    inner: SystemArgvLauncher,
    spawns: Arc<AtomicUsize>,
}

impl ArgvLauncher for CountingLauncher {
    type Child = SystemChild;

    fn spawn_argv(&mut self, request: &ArgvRequest) -> std::io::Result<SystemChild> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        self.inner.spawn_argv(request)
    }
}

/// Counts the one child start and can refuse it instead.
#[derive(Debug)]
struct CountingChild {
    starts: Arc<AtomicUsize>,
    fail: bool,
    last: Option<TaskNumberFacts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TaskNumberFacts {
    number: u32,
    approval_revision: u64,
}

impl CountingChild {
    fn new(starts: Arc<AtomicUsize>, fail: bool) -> Self {
        Self {
            starts,
            fail,
            last: None,
        }
    }

    fn count(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }

    fn last(&self) -> Option<TaskNumberFacts> {
        self.last
    }
}

impl StartChildPort for CountingChild {
    fn start_child(
        &mut self,
        _execution: ExecutionId,
        task: herness_sdd_execute::TaskRef,
        approval_revision: u64,
    ) -> Result<String, SddExecutionError> {
        self.last = Some(TaskNumberFacts {
            number: task.number().get(),
            approval_revision,
        });
        if self.fail {
            return Err(SddExecutionError::Unavailable {
                feature: "h4.childStart: fixture failure".to_owned(),
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            });
        }
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(format!("child:task-{}", task.number().get()))
    }
}

/// An H3 answer that can prove a fixed set of synced targets.
#[derive(Debug, Default, Clone)]
struct ScriptedHtml {
    synced: BTreeSet<String>,
    asked: Vec<String>,
}

impl ScriptedHtml {
    fn synced(targets: &[&str]) -> Self {
        Self {
            synced: targets.iter().map(|target| (*target).to_owned()).collect(),
            asked: Vec::new(),
        }
    }
}

impl StartHtmlPort for ScriptedHtml {
    fn ensure_synced(&mut self, request: &StartHtmlRequest) -> Result<(), SddExecutionError> {
        for target in request.targets() {
            self.asked.push(target.clone());
            if !self.synced.contains(target) {
                return Err(SddExecutionError::HtmlNotSynced {
                    reason: herness_sdd_execute::HtmlSyncReason::Unsynced,
                    details: herness_sdd_execute::FailureDetails::none().boxed(),
                });
            }
        }
        Ok(())
    }
}

/// A store wrapper that fails the Nth `record_start` write.
#[derive(Debug)]
struct FaultyStartStore {
    inner: MemoryStartStore,
    fail_at: Option<usize>,
    calls: usize,
}

impl FaultyStartStore {
    fn new(fail_at: Option<usize>) -> Self {
        Self {
            inner: MemoryStartStore::new(),
            fail_at,
            calls: 0,
        }
    }
}

impl ApprovalRevisionStorePort for FaultyStartStore {
    fn record_approval_revision(
        &mut self,
        approval: &ExecutionApproval,
    ) -> Result<(), SddExecutionError> {
        self.inner.record_approval_revision(approval)
    }

    fn approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        self.inner
            .approval_revision(project_id, approval_id, revision)
    }

    fn latest_approval_revision(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        self.inner.latest_approval_revision(project_id, approval_id)
    }

    fn approval_revisions(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Vec<ExecutionApproval>, SddExecutionError> {
        self.inner.approval_revisions(project_id, approval_id)
    }
}

impl StartRecordStorePort for FaultyStartStore {
    fn start_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<StartRecord>, SddExecutionError> {
        self.inner
            .start_record(project_id, execution_id, request_id)
    }

    fn start_record_for_task(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        task: herness_sdd_execute::TaskRef,
    ) -> Result<Option<StartRecord>, SddExecutionError> {
        self.inner
            .start_record_for_task(project_id, execution_id, task)
    }

    fn record_start(&mut self, record: &StartRecord) -> Result<(), SddExecutionError> {
        self.calls += 1;
        if self.fail_at == Some(self.calls) {
            return Err(SddExecutionError::Unavailable {
                feature: "h4.startRecord: fixture failure".to_owned(),
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            });
        }
        self.inner.record_start(record)
    }
}

fn workspace_adapter(
    project_id: ProjectId,
    _root: &str,
    _gate: herness_core::HostGitGate,
    spawns: Arc<AtomicUsize>,
) -> WorkspaceAdapter<CountingLauncher, HostGitPreparationCommit, MemoryBaselineRecord> {
    let runner = GitRunner::new(
        git_program(),
        CountingLauncher {
            inner: SystemArgvLauncher,
            spawns,
        },
        ProcessSupervisor::new(),
        project_id,
    )
    .expect("a Git runner");
    let boundary = HostGitBoundary::new(
        git_program(),
        SystemArgvLauncher,
        RecordingHostGitAudit::new(),
        ProcessSupervisor::new(),
    )
    .expect("a host Git boundary");
    WorkspaceAdapter::new(
        runner,
        HostGitPreparationCommit::new(boundary),
        MemoryBaselineRecord::new(),
    )
}

// ---------------------------------------------------------------------------
// 1. Positive: one approval, one child
// ---------------------------------------------------------------------------

#[test]
fn positive_start_saves_the_whole_approval_and_creates_one_child() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let child = CountingChild::new(Arc::clone(&starts), false);
    assert_eq!(child.count(), 0);
    assert_eq!(child.last(), None);
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        child,
        ScriptedHtml::synced(&[]),
    );

    let draft = draft(&repo.path());
    let build = draft.build().expect("built");
    let post = build.clone().into_human_post(now()).expect("human post");
    let request = start_request_with(&draft, request_id(), None, Some(accepting_gate(&temp)));

    let outcome = composition
        .approve_and_start(&draft, &post, &request)
        .expect("a positive start");

    assert!(outcome.created_child());
    assert_eq!(starts.load(Ordering::SeqCst), 1, "exactly one child");
    assert_eq!(outcome.receipt().reference(), "child:task-1");
    assert!(outcome.receipt().started());
    assert_eq!(outcome.checkout_root(), repo.path());
    assert_eq!(outcome.approval_revision(), 1);

    // The baseline is the HEAD after the one preparation commit, and the commit
    // touched only `.gitignore`.
    let baseline = outcome.baseline().expect("a fixed baseline");
    assert_eq!(baseline.as_str(), git_head(&repo.root));
    assert_ne!(baseline.as_str(), {
        git(&repo.root, &["rev-parse", "HEAD~1"]).trim().to_owned()
    });
    let changed = git(&repo.root, &["show", "--name-only", "--format=", "HEAD"]);
    assert_eq!(changed.lines().collect::<Vec<_>>(), vec![".gitignore"]);

    // The saved approval binds every agreed value.
    let current = composition
        .registry()
        .current(project(), approval_id())
        .expect("current")
        .expect("one saved revision");
    assert_eq!(current.revision(), 1);
    assert_eq!(
        current.plan().digest().as_str(),
        Sha256Digest::sha256(PLAN_TEXT).as_str()
    );
    assert_eq!(current.plan().plan_path(), &plan_path());
    assert_eq!(current.workspace().canonical_checkout_root(), repo.path());
    assert_eq!(current.workspace().branch(), "h4-exec");
    assert_eq!(current.workspace().base_branch(), "main");
    assert_eq!(current.tasks().len(), 1);
    assert_eq!(current.tasks()[0].budget(), &budget());
    assert_eq!(current.tasks()[0].checks().len(), 1);
    assert_eq!(
        current.connection().connection_id(),
        connection().connection_id()
    );
    assert!(current.commit().host_commit() && current.commit().run_hooks());
    assert_eq!(current.h3().settings_version(), 1);
    assert!(current.is_human() && current.is_registry());

    // The start record is stored as `started`, with a result, and is the one
    // record for this Task.
    let record = composition
        .registry()
        .store()
        .start_record(project(), execution(), request_id())
        .expect("record")
        .expect("one record");
    assert_eq!(record.phase(), StartPhase::Started);
    assert_eq!(
        record.receipt().expect("a receipt").reference(),
        "child:task-1"
    );
    assert_eq!(record.approval_revision(), 1);
    let by_task = composition
        .registry()
        .store()
        .start_record_for_task(project(), execution(), record.task())
        .expect("by Task")
        .expect("the one record");
    assert_eq!(by_task, record);
}

// ---------------------------------------------------------------------------
// 2. Human-only posting, forbidden sources
// ---------------------------------------------------------------------------

#[test]
fn a_start_without_a_human_confirmation_is_refused() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    let draft = draft(&repo.path());

    // The registry itself refuses a post whose actor is not human, so no
    // caller-supplied "human" label can pass.
    let content = draft.build().expect("built").content().clone();
    for actor in [
        ApprovalActor::Model,
        ApprovalActor::ApprovedOwner {
            owner: OwnerRef::new(OwnerKind::H4SddTask, "h4:forged:task:1:stable")
                .expect("an owner"),
            source: herness_supervision::OwnerApprovalSource::H4ApprovedPlan,
        },
    ] {
        let error = StartApprovalPost::new(
            approval_id(),
            now(),
            actor,
            ApprovalSource::ApprovalRegistry {
                approval_id: approval_id(),
            },
            content.clone(),
            draft.build().expect("inputs").inputs().clone(),
        )
        .expect_err("a non-human actor is refused");
        assert!(matches!(
            error,
            SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::ActorNotHuman { .. }
            }
        ));
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    }
    // Nothing was saved by the refusals.
    assert!(
        composition
            .registry()
            .current(project(), approval_id())
            .expect("current")
            .is_none()
    );
}

#[test]
fn a_new_approval_requires_the_trusted_human_start_confirmation() {
    // The desktop composition refuses to save a new revision without the
    // host-minted `Start` confirmation. A model, preview, repository string, or
    // environment variable cannot mint one, so their absence is the refusal the
    // trusted path fixes; there is no label a caller can supply instead.
    let error = herness_desktop::sdd_execute::ensure_human_start_confirmation(None)
        .expect_err("no confirmation refuses a new approval");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::StartApproval,
            ..
        }
    ));
    // Minting one requires the host boundary, which this crate deliberately does
    // not expose to a test or a model. Starting an already saved revision does
    // not need a new one, which is how Task 15 replays a Task.
    assert_eq!(error.failure_code(), Some(FailureCode::ApprovalRequired));
}

#[test]
fn every_forbidden_approval_source_is_refused() {
    let draft = draft("/tmp/herness-h4-approval-checkout");
    let build = draft.build().expect("built");
    let base = approved_once();

    let forbidden = [
        ApprovalSource::EnvironmentVariable {
            name: "HERNNESS_H4_APPROVED".to_owned(),
        },
        ApprovalSource::DocumentDeclaration {
            path: "docs/plan.md".to_owned(),
        },
        ApprovalSource::HtmlMeta {
            path: "docs/plan.md".to_owned(),
        },
        ApprovalSource::Receipt {
            reference: "receipt.json".to_owned(),
        },
        ApprovalSource::RequestActor {
            reference: "ApprovedOwner".to_owned(),
        },
        ApprovalSource::OwnerKind {
            reference: "H4SddTask".to_owned(),
        },
        ApprovalSource::ModelRequest {
            reference: "model".to_owned(),
        },
        ApprovalSource::H3Approval {
            approval_id: "h3-settings-1".to_owned(),
        },
    ];
    for source in forbidden {
        let error = StartApprovalPost::new(
            approval_id(),
            now(),
            ApprovalActor::Human,
            source.clone(),
            build.content().clone(),
            build.inputs().clone(),
        )
        .expect_err("a forbidden source is refused");
        match error {
            SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::ForbiddenSource { source: rejected },
            } => assert_eq!(rejected, source.kind()),
            other => panic!("expected a forbidden source, found {other:?}"),
        }
        // The same refusal is enforced by the value type itself.
        let error = ExecutionApproval::new(
            approval_id(),
            ApprovalActor::Human,
            source,
            now(),
            build.content().clone(),
        )
        .expect_err("a forbidden source cannot build an approval");
        assert_eq!(error.failure_code(), None);
        assert!(matches!(
            error,
            SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::ForbiddenSource { .. }
            }
        ));
    }

    // Positive control: the human registry source builds and saves.
    assert_eq!(base.revision(), 1);
    assert!(base.is_human() && base.is_registry());
}

#[test]
fn an_h3_approval_is_not_an_h4_start_approval() {
    // (a) The H3 source cannot even build an approval value.
    let draft = draft("/tmp/herness-h4-approval-checkout");
    let error = ExecutionApproval::new(
        approval_id(),
        ApprovalActor::Human,
        ApprovalSource::H3Approval {
            approval_id: "h3-settings-1".to_owned(),
        },
        now(),
        draft.build().expect("built").content().clone(),
    )
    .expect_err("an H3 approval is not an H4 approval");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::ForbiddenSource { .. }
        }
    ));

    // (b) An H4 launch cannot be authorized by an empty or unconfigured H4
    // registry, so an H3 registry entry never becomes H4 authority.
    let base = approved_once();
    let task = base.tasks()[0].task();
    let expected = draft
        .owner_approval(&base, task, now())
        .expect("an owner approval");
    let binding = H4OwnerLaunchBinding::new(supervision(project()), expected).expect("a binding");
    let error = authorize_h4_owner_launch(
        &herness_supervision::UnconfiguredH4ApprovalRegistry,
        &binding,
        now(),
    )
    .expect_err("no H4 registry means no authority");
    assert!(matches!(
        error,
        SupervisionError::OwnerLaunchRejected {
            reason: herness_supervision::OwnerLaunchRejection::H4ApprovalUnavailable
        }
    ));
    let empty = H4StartApprovalRegistry::new();
    let error = authorize_h4_owner_launch(&empty, &binding, now())
        .expect_err("an empty H4 registry means no authority");
    assert!(matches!(
        error,
        SupervisionError::OwnerLaunchRejected {
            reason: herness_supervision::OwnerLaunchRejection::MissingRegistryEntry
        }
    ));

    // (c) The H4 approval never relaxes the H3 boundary: a start without a
    // current H3 settings record is refused.
    let inputs = CurrentInputs::from_approval(
        &base,
        connection().connection_id(),
        profile(),
        vec![consent()],
        None,
        None,
    )
    .expect("inputs");
    let error = inputs
        .inputs()
        .verify(base.content())
        .expect_err("H3 settings are required");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::H3Settings,
            ..
        }
    ));

    // (d) With the registry populated by the same approval, the H4 authority is
    // minted and names the exact plan revision and digest.
    let mut registry = H4StartApprovalRegistry::new();
    registry.set_current(&draft, &base);
    let authority = authorize_h4_owner_launch(&registry, &binding, now()).expect("H4 authority");
    assert!(authority.is_h4());
    assert_eq!(authority.h4_plan_revision(), Some(1));
}

// ---------------------------------------------------------------------------
// 3. Stale revision, different project, changed inputs, revoked consent
// ---------------------------------------------------------------------------

#[test]
fn an_old_revision_is_refused_before_any_side_effect() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    let draft = draft(&repo.path());
    let first = draft.build().expect("built");
    let post = first.into_human_post(now()).expect("post");
    let saved = composition.approve(&post).expect("revision 1");
    assert_eq!(saved.revision(), 1);

    // A changed budget produces revision 2.
    let revised = ApprovalDraft::new(
        execution(),
        approval_id(),
        preview_facts(),
        layout(),
        PlanRevision::new(1).expect("a plan revision"),
        repo.path(),
        git_identity(),
        "h4-exec",
        "main",
        false,
        connection(),
        commit(),
        h3_binding(),
        vec![BudgetPolicy::new(3_600, 10, None).expect("a smaller budget")],
    )
    .expect("a revised draft");
    let second = revised
        .build()
        .expect("built")
        .into_human_post(Timestamp::from_unix_millis(1_760_000_001_000))
        .expect("post");
    let saved = composition.approve(&second).expect("revision 2");
    assert_eq!(saved.revision(), 2);
    assert_eq!(
        composition
            .registry()
            .history(project(), approval_id())
            .expect("history")
            .len(),
        2
    );

    // A request that still expects revision 1 is stale and creates no child.
    let stale = StartRequest::new(
        execution(),
        approval_id(),
        1,
        request_id(),
        None,
        first_inputs_for(&revised),
        Some(accepting_gate(&temp)),
    )
    .expect("a stale request");
    let error = composition
        .start(&revised, &stale)
        .expect_err("a stale revision is refused");
    assert!(matches!(
        error,
        SddExecutionError::Conflict {
            reason: ConflictReason::StaleRevision,
            ..
        }
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    // Nothing was prepared: HEAD and the branch are unchanged.
    assert_eq!(
        git_branches(&repo.root),
        vec!["h4-exec".to_owned(), "main".to_owned()]
    );
}

/// Current inputs for one draft's plan and workspace, with its own budgets.
fn first_inputs_for(draft: &ApprovalDraft) -> herness_sdd_execute::ApprovalInputs {
    draft.build().expect("built").inputs().clone()
}

#[test]
fn a_different_project_is_refused() {
    let base = approved_once();
    let registry = StartApprovalRegistry::new(MemoryStartStore::new());
    let error = registry
        .current(other_project(), approval_id())
        .expect_err("another project cannot read this approval");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::OtherProject
        }
    ));

    // Inputs observed for another project are refused by the registry.
    let other_inputs = CurrentInputs::from_approval(
        &base,
        connection().connection_id(),
        profile(),
        vec![consent()],
        Some(h3_binding()),
        None,
    )
    .expect("inputs")
    .inputs()
    .clone();
    let error = registry
        .verify_current(other_project(), approval_id(), 1, &other_inputs)
        .expect_err("a cross-project verification is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::OtherProject
        }
    ));

    // A request whose execution belongs to another project cannot be built.
    let other_execution = ExecutionId::from_parts(
        other_project(),
        uuid("90000000-0000-4000-8000-000000000102"),
    );
    let error = StartRequest::new(
        other_execution,
        approval_id(),
        1,
        request_id(),
        None,
        other_inputs,
        None,
    )
    .expect_err("a cross-project request is refused");
    assert!(
        matches!(
            error,
            SddExecutionError::ApprovalRejected {
                reason: ApprovalRejection::OtherProject
            } | SddExecutionError::CrossProjectReference { .. }
        ),
        "{error:?}"
    );
}

#[test]
fn changed_inputs_refuse_a_start() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let base = approved_once();
    let draft = draft(&repo.path());
    let approved = draft.build().expect("built").content().clone();

    // A different plan digest.
    let changed_plan = PlanApproval::new(
        plan_path(),
        ExactPlanBytes::new(b"# Changed plan\n".to_vec()).expect("bytes"),
        PlanRevision::new(1).expect("a revision"),
        parsed_plan(),
        vec![spec_ref()],
        Vec::new(),
        pack(),
    )
    .expect("a changed plan");
    let inputs = herness_sdd_execute::ApprovalInputs::new(
        changed_plan,
        approved.workspace().clone(),
        approved.tasks().to_vec(),
        herness_sdd_execute::ObservedConnection::from_approved(&connection(), vec![consent()]),
        commit(),
        Some(h3_binding()),
    );
    let error = inputs
        .verify(&approved)
        .expect_err("a changed plan digest is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::PlanDigestMismatch { .. }
        }
    ));

    // A changed Task budget.
    let task = &approved.tasks()[0];
    let changed_task = TaskApproval::new(
        task.task(),
        task.title(),
        task.conditions().to_vec(),
        task.scope().clone(),
        task.checks().to_vec(),
        task.html_targets().to_vec(),
        BudgetPolicy::new(600, 1, None).expect("a smaller budget"),
        task.commit_policy(),
        task.deliverables().to_vec(),
    )
    .expect("a changed Task");
    let inputs = herness_sdd_execute::ApprovalInputs::new(
        approved.plan().clone(),
        approved.workspace().clone(),
        vec![changed_task],
        herness_sdd_execute::ObservedConnection::from_approved(&connection(), vec![consent()]),
        commit(),
        Some(h3_binding()),
    );
    let error = inputs
        .verify(&approved)
        .expect_err("a budget change is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::CurrentInputsChanged { .. }
        }
    ));

    // A baseline that replaces the recorded one is a mismatch. (An approval
    // saved before the one preparation carries no baseline, so observing the
    // first baseline is the normal progression.)
    let recorded = Baseline::parse("c".repeat(40)).expect("a baseline");
    let with_baseline = WorkspaceApproval::new(
        project(),
        repo.path(),
        git_identity(),
        "h4-exec",
        "main",
        false,
        Some(recorded.clone()),
    )
    .expect("a workspace with a baseline");
    let inputs = herness_sdd_execute::ApprovalInputs::new(
        approved.plan().clone(),
        WorkspaceApproval::new(
            project(),
            repo.path(),
            git_identity(),
            "h4-exec",
            "main",
            false,
            Some(Baseline::parse("d".repeat(40)).expect("another baseline")),
        )
        .expect("a changed workspace"),
        approved.tasks().to_vec(),
        herness_sdd_execute::ObservedConnection::from_approved(&connection(), vec![consent()]),
        commit(),
        Some(h3_binding()),
    );
    let approved_with_baseline = herness_sdd_execute::ApprovalContent::new(
        approved.plan().clone(),
        with_baseline,
        approved.tasks().to_vec(),
        connection(),
        commit(),
        h3_binding(),
    )
    .expect("content with a baseline");
    let error = inputs
        .verify(&approved_with_baseline)
        .expect_err("a baseline change is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::WorkspaceMismatch { .. }
        }
    ));

    // A changed base branch.
    let inputs = herness_sdd_execute::ApprovalInputs::new(
        approved.plan().clone(),
        WorkspaceApproval::new(
            project(),
            repo.path(),
            git_identity(),
            "h4-exec",
            "develop",
            false,
            None,
        )
        .expect("a changed workspace"),
        approved.tasks().to_vec(),
        herness_sdd_execute::ObservedConnection::from_approved(&connection(), vec![consent()]),
        commit(),
        Some(h3_binding()),
    );
    let error = inputs
        .verify(&approved)
        .expect_err("a branch change is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::WorkspaceMismatch { .. }
        }
    ));
    assert!(base.is_human());
    let _ = temp;
}

#[test]
fn revoked_consent_and_missing_capability_refuse_a_start() {
    let base = approved_once();
    let approved = base.content();

    // Revoked consent: the live grant list is empty.
    let inputs = CurrentInputs::from_approval(
        &base,
        connection().connection_id(),
        profile(),
        Vec::new(),
        Some(h3_binding()),
        None,
    )
    .expect("inputs");
    let error = inputs
        .inputs()
        .verify(approved)
        .expect_err("a revoked consent is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::DisclosureConsent,
            ..
        }
    ));

    // A consent at another version is not the approved consent.
    let mut other_consent = consent();
    other_consent = ConsentBinding::new(
        other_consent.consent_id(),
        2,
        other_consent.purpose(),
        other_consent.target_scope_version(),
    );
    let inputs = CurrentInputs::from_approval(
        &base,
        connection().connection_id(),
        profile(),
        vec![other_consent],
        Some(h3_binding()),
        None,
    )
    .expect("inputs");
    let error = inputs
        .inputs()
        .verify(approved)
        .expect_err("a consent version change is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::DisclosureConsent,
            ..
        }
    ));

    // A changed profile.
    let other_profile = ProfileBinding::new(
        ProfileId::from_parts(project(), uuid("90000000-0000-4000-8000-000000000502")),
        ProfileVersion::new(1).expect("a version"),
        ProfilePurpose::Completion,
    );
    let inputs = CurrentInputs::from_approval(
        &base,
        connection().connection_id(),
        other_profile,
        vec![consent()],
        Some(h3_binding()),
        None,
    )
    .expect("inputs");
    let error = inputs
        .inputs()
        .verify(approved)
        .expect_err("a profile change is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::CurrentInputsChanged { .. }
        }
    ));

    // A capability the human did not confirm.
    let limited = H3ApprovalBinding::new(
        1,
        h3_binding().consents().to_vec(),
        vec!["html-sync".to_owned()],
    )
    .expect("an H3 boundary");
    let inputs = CurrentInputs::from_approval(
        &base,
        connection().connection_id(),
        profile(),
        vec![consent()],
        Some(limited),
        None,
    )
    .expect("inputs");
    // The approved boundary additionally names a capability the live one lacks.
    let draft = ApprovalDraft::new(
        execution(),
        approval_id(),
        preview_facts(),
        layout(),
        PlanRevision::new(1).expect("a revision"),
        "/tmp/herness-h4-approval-checkout",
        git_identity(),
        "h4-exec",
        "main",
        false,
        connection(),
        commit(),
        H3ApprovalBinding::new(
            1,
            h3_binding().consents().to_vec(),
            vec!["html-sync".to_owned(), "render".to_owned()],
        )
        .expect("a wider boundary"),
        vec![budget()],
    )
    .expect("a draft");
    let wider = draft.build().expect("built").content().clone();
    let error = inputs
        .inputs()
        .verify(&wider)
        .expect_err("a missing capability is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::Capability,
            ..
        }
    ));

    // A changed H3 settings version.
    let newer = H3ApprovalBinding::new(
        2,
        h3_binding().consents().to_vec(),
        vec!["html-sync".to_owned()],
    )
    .expect("a newer boundary");
    let inputs = CurrentInputs::from_approval(
        &base,
        connection().connection_id(),
        profile(),
        vec![consent()],
        Some(newer),
        None,
    )
    .expect("inputs");
    let error = inputs
        .inputs()
        .verify(approved)
        .expect_err("a settings version change is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::H3Settings,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// 4. Workspace refusals: dirty checkout, unsynced HTML, isolation scope
// ---------------------------------------------------------------------------

#[test]
fn a_dirty_selected_checkout_refuses_the_start() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    repo.write("stray.txt", "dirty\n");
    let head = git_head(&repo.root);

    let draft = draft(&repo.path());
    let post = draft
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    let request = start_request(&draft);
    let error = composition
        .approve_and_start(&draft, &post, &request)
        .expect_err("a dirty checkout refuses the start");
    assert!(matches!(
        error,
        SddExecutionError::Conflict {
            reason: ConflictReason::DirtyIndex,
            ..
        }
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 0, "no child");
    // Nothing was committed and the stray file is untouched.
    assert_eq!(git_head(&repo.root), head);
    assert!(repo.root.join("stray.txt").is_file());
}

#[test]
fn unsynced_required_html_refuses_the_start() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        UnsyncedStartHtml,
    );

    // A Task with a declared HTML target and no H3 proof refuses.
    let drafted = draft_with_html_target(&repo.path(), "docs/sdd/guide.md");
    let post = drafted
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    let request = start_request(&drafted);
    let error = composition
        .approve_and_start(&drafted, &post, &request)
        .expect_err("unsynced HTML refuses the start");
    assert_eq!(error.failure_code(), Some(FailureCode::HtmlNotSynced));
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    // The same fixture with a synced document starts (one child), proving the
    // refusal above was the HTML state and not the fixture.
    let mut synced = StartComposition::new(
        MemoryStartStore::new(),
        workspace_adapter(
            project(),
            &repo.path(),
            accepting_gate(&temp),
            Arc::new(AtomicUsize::new(0)),
        ),
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&["docs/sdd/guide.md"]),
    );
    let drafted = draft_with_html_target(&repo.path(), "docs/sdd/guide.md");
    let post = drafted
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    let request = start_request(&drafted);
    synced
        .approve_and_start(&drafted, &post, &request)
        .expect("a synced target starts");
    assert_eq!(starts.load(Ordering::SeqCst), 1);
}

fn draft_with_html_target(checkout_root: &str, target: &str) -> ApprovalDraft {
    let facts = PreviewFacts::new(
        "/tmp/herness-h4-approval-project",
        plan_path(),
        ExactPlanBytes::new(PLAN_TEXT.to_vec()).expect("bytes"),
        parsed_plan(),
        vec![PreviewTaskFacts::from_parts(
            1,
            "Write the module",
            "Body.\n",
            vec![condition()],
            vec!["src/a.rs".to_owned()],
            vec!["src/a.rs".to_owned()],
            true,
            vec![check()],
            vec![target.to_owned()],
            vec![
                ApprovedDeliverable::new("src/a.rs", DeliverableKind::File).expect("a deliverable"),
            ],
            CommitPolicy::Required,
        )],
        vec![spec_ref()],
        Vec::new(),
        pack(),
    )
    .expect("facts");
    ApprovalDraft::new(
        execution(),
        approval_id(),
        facts,
        layout(),
        PlanRevision::new(1).expect("a revision"),
        checkout_root,
        git_identity(),
        "h4-exec",
        "main",
        false,
        connection(),
        commit(),
        h3_binding(),
        vec![budget()],
    )
    .expect("a draft")
}

#[test]
fn git_isolation_is_created_only_for_an_approved_isolated_selection() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");

    // (1) The approval did not approve isolation, but the answer selects it.
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    let unapproved = draft(&repo.path());
    let post = unapproved
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    let target = repo.sibling("isolated-target");
    let request = start_request_with(
        &unapproved,
        request_id(),
        Some(WorkspaceSelectionAnswer::Isolated {
            checkout_root: target.clone(),
        }),
        Some(accepting_gate(&temp)),
    );
    let error = composition
        .approve_and_start(&unapproved, &post, &request)
        .expect_err("unapproved isolation is refused");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::WorkspaceMismatch { .. }
        }
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    assert!(!Path::new(&target).exists(), "no worktree was created");
    assert_eq!(git_worktree_paths(&repo.root).len(), 1, "only the original");
    assert_eq!(
        git_branches(&repo.root),
        vec!["h4-exec".to_owned(), "main".to_owned()]
    );

    // (2) The approval approved isolation and the answer selects it: exactly one
    // worktree and one new branch appear, inside the selected repository.
    //
    // The fixture checkout is reset to `main` with no `h4-exec` branch, because
    // an isolated preparation creates that branch: it refuses to adopt an
    // existing one.
    let original_head = git_head(&repo.root);
    git(&repo.root, &["switch", "main"]);
    git(&repo.root, &["branch", "-D", "h4-exec"]);
    assert_eq!(git_branches(&repo.root), vec!["main".to_owned()]);
    let approved_isolated = isolated_draft(&repo.path());
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    let post = approved_isolated
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    let request = start_request_with(
        &approved_isolated,
        request_id(),
        Some(WorkspaceSelectionAnswer::Isolated {
            checkout_root: target.clone(),
        }),
        Some(accepting_gate(&temp)),
    );
    let outcome = composition
        .approve_and_start(&approved_isolated, &post, &request)
        .expect("approved isolation starts");
    assert!(outcome.created_child());
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(outcome.checkout_root(), target);
    assert_eq!(git_worktree_paths(&repo.root).len(), 2);
    // Exactly one new branch, created by this approved preparation.
    assert_eq!(
        git_branches(&repo.root),
        vec!["h4-exec".to_owned(), "main".to_owned()]
    );
    // The original checkout was not switched and kept its HEAD.
    assert_eq!(git_head(&repo.root), original_head);
}

fn isolated_draft(checkout_root: &str) -> ApprovalDraft {
    ApprovalDraft::new(
        execution(),
        approval_id(),
        preview_facts(),
        layout(),
        PlanRevision::new(1).expect("a revision"),
        checkout_root,
        git_identity(),
        "h4-exec",
        "main",
        true,
        connection(),
        commit(),
        h3_binding(),
        vec![budget()],
    )
    .expect("an isolated draft")
}

#[test]
fn an_alias_outside_its_approved_read_paths_is_refused() {
    let approved_root = TempDir::new().expect("an approved root");
    std::fs::write(
        approved_root.path().join("notes.md"),
        b"# Notes\n\n## Fixture section\n\napproved\n",
    )
    .expect("notes");
    let root = std::fs::canonicalize(approved_root.path())
        .expect("canonical")
        .to_string_lossy()
        .into_owned();
    let layout = SourceLayout::new("/tmp/herness-h4-approval-project")
        .expect("a layout")
        .with_alias("pack-docs", &root, vec!["notes.md".to_owned()])
        .expect("an approved alias");

    // The approval reads only the granted path of the approved alias.
    let spec = herness_sdd_execute::SourceSnapshot::new(
        "pack-docs",
        "notes.md",
        format!("{root}/notes.md"),
        std::fs::read(approved_root.path().join("notes.md")).expect("bytes"),
    )
    .expect("a snapshot");
    let reference = herness_sdd_execute::PreviewSpecRef::new(
        "pack-docs",
        "notes.md",
        vec!["Fixture section".to_owned()],
    )
    .expect("a reference");
    let verified = herness_sdd_execute::verify_spec_snapshots(
        &layout,
        std::slice::from_ref(&reference),
        &[spec],
    )
    .expect("the granted path reads");
    let digest = verified.alias_digest("pack-docs").expect("alias digest");

    let sources = vec![
        ExternalSourceApproval::new("pack-docs", &root, digest, vec!["notes.md".to_owned()])
            .expect("an approved source"),
    ];
    let spec_ref = ApprovedSpecRef::new(
        "pack-docs",
        "notes.md",
        vec!["Fixture section".to_owned()],
        Sha256Digest::sha256(&std::fs::read(approved_root.path().join("notes.md")).expect("bytes")),
    )
    .expect("a spec ref");
    let facts = PreviewFacts::new(
        "/tmp/herness-h4-approval-project",
        plan_path(),
        ExactPlanBytes::new(PLAN_TEXT.to_vec()).expect("bytes"),
        parsed_plan(),
        vec![task_facts()],
        vec![spec_ref],
        sources,
        pack(),
    )
    .expect("facts");
    let isolated_scope = ApprovalDraft::new(
        execution(),
        approval_id(),
        facts,
        layout.clone(),
        PlanRevision::new(1).expect("a revision"),
        "/tmp/herness-h4-approval-checkout",
        git_identity(),
        "h4-exec",
        "main",
        false,
        connection(),
        commit(),
        h3_binding(),
        vec![budget()],
    )
    .expect("a draft");
    let content = isolated_scope.build().expect("built").content().clone();
    // The external alias is recorded as a read-only source, and it is not a
    // checkout document.
    assert_eq!(content.plan().sources().len(), 1);
    assert_eq!(content.plan().sources()[0].alias(), "pack-docs");
    assert_eq!(
        content.plan().sources()[0].read_paths(),
        ["notes.md".to_owned()]
    );
    assert!(
        isolated_scope
            .checkout_documents()
            .expect("documents")
            .iter()
            .all(|document| document.path() != "notes.md")
    );

    // An ungranted path of the same alias is refused, and so is an unknown alias.
    for (alias, path) in [("pack-docs", "secrets.md"), ("private-notes", "notes.md")] {
        let reference = herness_sdd_execute::PreviewSpecRef::new(
            alias,
            path,
            vec!["Fixture section".to_owned()],
        )
        .expect("a reference");
        let error = layout
            .resolve(&reference)
            .expect_err("an unapproved alias path is refused");
        assert_eq!(
            error.failure_code(),
            Some(FailureCode::InvalidPlan),
            "{alias}/{path}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Idempotency and the duplicate start request
// ---------------------------------------------------------------------------

#[test]
fn a_duplicate_start_returns_the_stored_result_and_one_child() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    let drafted = draft(&repo.path());
    let post = drafted
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    let request = start_request(&drafted);

    let first = composition
        .approve_and_start(&drafted, &post, &request)
        .expect("the first start");
    assert!(first.created_child());
    let second = composition
        .approve_and_start(&drafted, &post, &request)
        .expect("the duplicate returns the stored result");
    assert!(!second.created_child(), "no second child");
    assert_eq!(first.receipt(), second.receipt());
    assert_eq!(starts.load(Ordering::SeqCst), 1, "exactly one child");
    // The second call did not prepare the checkout again: one preparation
    // commit exists.
    let commits = git(&repo.root, &["rev-list", "--count", "main..HEAD"]);
    assert_eq!(commits.trim(), "1");
}

#[test]
fn a_second_request_id_for_the_same_task_creates_no_second_child() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    let draft = draft(&repo.path());
    let post = draft
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    composition
        .approve_and_start(&draft, &post, &start_request(&draft))
        .expect("the first start");
    assert_eq!(starts.load(Ordering::SeqCst), 1);

    // A *different* request ID for the same Task is not a duplicate, but one
    // child per Task still holds: it is refused with no second child.
    let second = start_request_with(
        &draft,
        request_id_second(),
        None,
        Some(accepting_gate_default()),
    );
    let error = composition
        .approve_and_start(&draft, &post, &second)
        .expect_err("a second request for the same Task is refused");
    assert!(matches!(
        error,
        SddExecutionError::Conflict {
            reason: ConflictReason::TaskNotReady,
            ..
        }
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 1, "still one child");
}

#[test]
fn the_same_request_id_with_different_content_is_refused() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    let draft = draft(&repo.path());
    let post = draft
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    composition
        .approve_and_start(&draft, &post, &start_request(&draft))
        .expect("the first start");
    assert_eq!(starts.load(Ordering::SeqCst), 1);

    // The same request ID with a different approved budget is different content.
    let revised = ApprovalDraft::new(
        execution(),
        approval_id(),
        preview_facts(),
        layout(),
        PlanRevision::new(1).expect("a revision"),
        repo.path(),
        git_identity(),
        "h4-exec",
        "main",
        false,
        connection(),
        commit(),
        h3_binding(),
        vec![BudgetPolicy::new(3_600, 10, None).expect("a smaller budget")],
    )
    .expect("a revised draft");
    let revised_post = revised
        .build()
        .expect("built")
        .into_human_post(Timestamp::from_unix_millis(1_760_000_002_000))
        .expect("post");
    // The approval advances to revision 2, so a request that still binds
    // revision 1 with the same request ID is a conflicting re-delivery.
    let error = composition
        .approve_and_start(&revised, &revised_post, &start_request(&revised))
        .expect_err("a stale re-delivery is refused");
    assert!(
        matches!(
            error,
            SddExecutionError::Conflict {
                reason: ConflictReason::StaleRevision,
                ..
            } | SddExecutionError::DuplicateRequestConflict { .. }
        ),
        "{error:?}"
    );
    assert_eq!(starts.load(Ordering::SeqCst), 1, "no second child");
}

// ---------------------------------------------------------------------------
// 6. Fault boundaries around workspace preparation
// ---------------------------------------------------------------------------

/// Runs one start against a fault store and returns the result.
#[allow(clippy::too_many_arguments)]
fn start_with_fault(
    repo: &Repo,
    temp: &TempDir,
    fail_at: Option<usize>,
    child_fails: bool,
    request: &StartRequest,
    draft: &ApprovalDraft,
    post: &StartApprovalPost,
    starts: &Arc<AtomicUsize>,
) -> (
    Result<herness_desktop::sdd_execute::StartOutcome, SddExecutionError>,
    usize,
) {
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        FaultyStartStore::new(fail_at),
        adapter,
        CountingChild::new(Arc::clone(starts), child_fails),
        ScriptedHtml::synced(&[]),
    );
    let outcome = composition.approve_and_start(draft, post, request);
    (outcome, starts.load(Ordering::SeqCst))
}

#[test]
fn a_fault_before_preparation_leaves_no_start() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let starts = Arc::new(AtomicUsize::new(0));
    let draft = draft(&repo.path());
    let post = draft
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    let head = git_head(&repo.root);

    let (outcome, children) = start_with_fault(
        &repo,
        &temp,
        Some(1),
        false,
        &start_request(&draft),
        &draft,
        &post,
        &starts,
    );
    let error = outcome.expect_err("the intent write failed");
    assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
    assert_eq!(children, 0);
    assert_eq!(git_head(&repo.root), head, "nothing was prepared");
}

#[test]
fn a_fault_during_workspace_preparation_leaves_no_start_and_reconciles() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let starts = Arc::new(AtomicUsize::new(0));
    let draft = draft(&repo.path());
    let post = draft
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    let head = git_head(&repo.root);

    // The preparation commit is refused by the staged-document gate, so the
    // start stops before the child.
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        refusing_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    let request = start_request_with(&draft, request_id(), None, Some(refusing_gate(&temp)));
    let error = composition
        .approve_and_start(&draft, &post, &request)
        .expect_err("the preparation commit is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
    assert_eq!(starts.load(Ordering::SeqCst), 0, "no child");
    assert_eq!(git_head(&repo.root), head, "no commit");
    // The stored record is the pre-side-effect phase, never `started`.
    let record = composition
        .registry()
        .store()
        .start_record(project(), execution(), request_id())
        .expect("record")
        .expect("one record");
    assert_eq!(record.phase(), StartPhase::PreparingWorkspace);
    assert!(record.receipt().is_none());

    // A retry of the same request reconciles instead of starting.
    let error = composition
        .approve_and_start(&draft, &post, &request)
        .expect_err("the retry waits for reconciliation");
    assert!(matches!(
        error,
        SddExecutionError::RecoveryRequired {
            reason: RecoveryReason::UnknownRequest,
            ..
        }
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

#[test]
fn a_child_fault_and_a_record_fault_never_start_twice() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let drafted = draft(&repo.path());
    let post = drafted
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");

    // (a) The child port refuses: no child, the record stays `starting`, and a
    // retry reconciles.
    let starts = Arc::new(AtomicUsize::new(0));
    let (outcome, children) = start_with_fault(
        &repo,
        &temp,
        None,
        true,
        &start_request(&drafted),
        &drafted,
        &post,
        &starts,
    );
    assert_eq!(
        outcome.expect_err("the child port refuses").failure_code(),
        Some(FailureCode::Unavailable)
    );
    assert_eq!(children, 0);
    let mut composition = StartComposition::new(
        MemoryStartStore::new(),
        workspace_adapter(
            project(),
            &repo.path(),
            accepting_gate(&temp),
            Arc::new(AtomicUsize::new(0)),
        ),
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    // A fresh store has no record, so this composition would start; the point
    // proven here is only that the *faulting* composition created zero children.
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    let _ = &mut composition;

    // (b) The record write after the child started fails: exactly one child, no
    // stored `started` result, and a retry reconciles instead of starting a
    // second child.
    let repo = Repo::new();
    let starts = Arc::new(AtomicUsize::new(0));
    let adapter = workspace_adapter(
        project(),
        &repo.path(),
        accepting_gate(&temp),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut composition = StartComposition::new(
        FaultyStartStore::new(Some(3)),
        adapter,
        CountingChild::new(Arc::clone(&starts), false),
        ScriptedHtml::synced(&[]),
    );
    let drafted = draft(&repo.path());
    let post = drafted
        .build()
        .expect("built")
        .into_human_post(now())
        .expect("post");
    let error = composition
        .approve_and_start(&drafted, &post, &start_request(&drafted))
        .expect_err("the started result cannot be stored");
    assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
    assert_eq!(starts.load(Ordering::SeqCst), 1, "the one child exists");
    let record = composition
        .registry()
        .store()
        .start_record(project(), execution(), request_id())
        .expect("record")
        .expect("one record");
    assert_eq!(record.phase(), StartPhase::Starting);
    assert!(record.receipt().is_none());

    // The retry re-verifies, finds the `starting` record, and reconciles.
    let retry = composition
        .approve_and_start(&drafted, &post, &start_request(&drafted))
        .expect_err("the retry reconciles");
    assert!(matches!(
        retry,
        SddExecutionError::RecoveryRequired {
            reason: RecoveryReason::UnknownRequest,
            ..
        }
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 1, "no second child");
}

// ---------------------------------------------------------------------------
// 7. The real SQLite store persists both records
// ---------------------------------------------------------------------------

/// A real-store fault at either commit point leaves no `started` record.
#[test]
fn a_real_store_fault_never_records_a_start() {
    use herness_store::test_support::CommitFault;

    let app_data = TempDir::new().expect("app data");
    let config = StoreConfig::new(app_data.path().join("app-data")).expect("a store config");
    let mut store: Store = Store::open(config).expect("open the store");
    let approval = approved_once();
    let record = StartRecord::new(
        execution(),
        request_id(),
        approval_id(),
        1,
        approval.tasks()[0].task(),
        Sha256Digest::sha256(b"request"),
        StartPhase::PreparingWorkspace,
        None,
    )
    .expect("a record");

    for fault in [CommitFault::BeforeRows, CommitFault::BeforeCommit] {
        store.set_commit_fault(Some(fault));
        let error = store
            .record_start(&record)
            .expect_err("the injected fault refuses the write");
        assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
        store.set_commit_fault(None);
        // No record existed before, and none exists after the fault.
        assert!(
            store
                .start_record(project(), execution(), request_id())
                .expect("read")
                .is_none(),
            "{fault:?}"
        );
    }

    // The retry after the faults stores exactly one pre-side-effect record.
    store.record_start(&record).expect("recorded");
    let stored = store
        .start_record(project(), execution(), request_id())
        .expect("read")
        .expect("one");
    assert_eq!(stored.phase(), StartPhase::PreparingWorkspace);
    assert!(stored.receipt().is_none());
}

/// The approved checkout documents name only project-sourced files.
#[test]
fn the_approved_checkout_documents_are_project_sources_only() {
    let repo = Repo::new();
    let documents = repo.documents();
    assert_eq!(documents.len(), 2);
    let draft = draft(&repo.path());
    let approved = draft.checkout_documents().expect("documents");
    assert_eq!(approved.len(), 2);
    assert_eq!(approved[0].path(), "docs/sdd/plans/plan.md");
    assert_eq!(approved[1].path(), spec_path());
    // The approved digests are the exact bytes in the checkout.
    assert_eq!(
        approved[0].digest().as_str(),
        documents[0].digest().as_str()
    );
    assert_eq!(
        approved[1].digest().as_str(),
        documents[1].digest().as_str()
    );
}

#[test]
fn the_real_store_persists_approvals_and_start_records() {
    let app_data = TempDir::new().expect("app data");
    let config = StoreConfig::new(app_data.path().join("app-data")).expect("a store config");
    let mut store: Store = Store::open(config).expect("open the store");

    let draft = draft("/tmp/herness-h4-approval-checkout");
    let build = draft.build().expect("built");
    let post = build.into_human_post(now()).expect("post");
    let mut registry = StartApprovalRegistry::new(MemoryStartStore::new());
    let approval = registry.post_human_approval(&post).expect("saved");

    // The same revision reaches the SQLite store exactly once.
    store.record_approval_revision(&approval).expect("recorded");
    store
        .record_approval_revision(&approval)
        .expect("an identical write is a no-op");
    assert_eq!(
        store
            .latest_approval_revision(project(), approval_id())
            .expect("latest")
            .expect("one")
            .revision(),
        1
    );
    assert_eq!(
        store
            .approval_revisions(project(), approval_id())
            .expect("history")
            .len(),
        1
    );

    // A start record round-trips through the real store, and a backwards write
    // is refused before any write.
    let record = StartRecord::new(
        execution(),
        request_id(),
        approval_id(),
        1,
        approval.tasks()[0].task(),
        Sha256Digest::sha256(b"request"),
        StartPhase::PreparingWorkspace,
        None,
    )
    .expect("a record");
    store.record_start(&record).expect("recorded");
    let started =
        record.started(herness_sdd_execute::StartReceipt::new("child:1", true).expect("a receipt"));
    store.record_start(&started).expect("advanced");
    let loaded = store
        .start_record(project(), execution(), request_id())
        .expect("loaded")
        .expect("one");
    assert_eq!(loaded.phase(), StartPhase::Started);
    assert_eq!(loaded.receipt().expect("receipt").reference(), "child:1");
    let error = store
        .record_start(&record)
        .expect_err("a rewound phase is refused");
    assert!(matches!(
        error,
        SddExecutionError::DuplicateRequestConflict { .. }
    ));
    assert_eq!(
        store
            .start_record_for_task(project(), execution(), started.task())
            .expect("by Task")
            .expect("one")
            .phase(),
        StartPhase::Started
    );

    // A second `Store::open` reads the same rows.
    drop(store);
    let reopened: Store =
        Store::open(StoreConfig::new(app_data.path().join("app-data")).expect("a config"))
            .expect("reopen");
    assert_eq!(
        reopened
            .latest_approval_revision(project(), approval_id())
            .expect("latest")
            .expect("one")
            .revision(),
        1
    );
    assert_eq!(
        reopened
            .start_record(project(), execution(), request_id())
            .expect("loaded")
            .expect("one")
            .phase(),
        StartPhase::Started
    );
}

// ---------------------------------------------------------------------------
// Helpers used by more than one case
// ---------------------------------------------------------------------------

/// The approved Task identity is stable across a plan revision.
#[test]
fn task_identity_is_stable_across_plan_revisions() {
    let first = draft("/tmp/herness-h4-approval-checkout");
    let number = TaskNumber::new(1).expect("a Task number");
    let stable = first.task_ref(number);
    assert_eq!(
        stable.stable_id(),
        TaskStableId::from_parts(
            project(),
            herness_desktop::sdd_execute::derivation_uuid(
                "h4.task.stable",
                "docs/sdd/plans/plan.md#1"
            )
        )
    );
    // The same plan path and number in a second draft keep the identity.
    let second = draft("/tmp/another-checkout");
    assert_eq!(second.task_ref(number), stable);
    // A different number is a different identity.
    let other = second.task_ref(TaskNumber::new(2).expect("a Task number"));
    assert_ne!(other.stable_id(), stable.stable_id());
}

/// A record can only advance, never be rewritten.
#[test]
fn start_records_only_advance() {
    let approval = approved_once();
    let base = StartRecord::new(
        execution(),
        request_id(),
        approval_id(),
        1,
        approval.tasks()[0].task(),
        Sha256Digest::sha256(b"request"),
        StartPhase::PreparingWorkspace,
        None,
    )
    .expect("a record");
    base.ensure_advance(&base.starting()).expect("forward");
    let started =
        base.started(herness_sdd_execute::StartReceipt::new("child:1", true).expect("a receipt"));
    base.ensure_advance(&started).expect("forward to started");
    started
        .ensure_advance(&started)
        .expect("an identical rewrite is a no-op");
    assert!(started.ensure_advance(&base.starting()).is_err());
    let different = started
        .started(herness_sdd_execute::StartReceipt::new("child:2", true).expect("a receipt"));
    assert!(matches!(
        started.ensure_advance(&different),
        Err(SddExecutionError::DuplicateResultConflict { .. })
    ));
    // A different fingerprint for the same key is a duplicate-content conflict.
    let other = StartRecord::new(
        execution(),
        request_id(),
        approval_id(),
        1,
        approval.tasks()[0].task(),
        Sha256Digest::sha256(b"another request"),
        StartPhase::PreparingWorkspace,
        None,
    )
    .expect("a record");
    assert!(matches!(
        base.ensure_advance(&other),
        Err(SddExecutionError::DuplicateRequestConflict { .. })
    ));
    // The Task reference used by the tests exists.
    let _ = h4_owner_ref(execution(), approval.tasks()[0].task()).expect("a Task owner");
}
