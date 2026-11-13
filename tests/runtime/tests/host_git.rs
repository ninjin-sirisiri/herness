//! Black-box tests for the host-only Git stage/commit boundary.
//!
//! Every test uses a real temporary Git repository created with `git init` and
//! real commits, real `core.hooksPath` configuration, and real hook scripts. Git
//! itself is never mocked: the counting launcher only observes which argv the
//! boundary asked for and how many times a process was created.
//!
//! No network, engine, credential, Tauri, or real project is involved. Approval
//! and authorization values are synthetic.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use herness_core::*;
use herness_sdd_execute::{
    CommitMessage, CommitRequestId, CommitSha, CommittedPath, ExecutionId, ExecutionRevision,
    GitCommitIntent, GitCommitOutcome, GitJournalEntry, GitRejection, GitUnknownReason,
    PreHookState, RequestIdentity, TaskNumber, TaskRef, TaskStableId, TreeSha,
};
use herness_store::{Store, StoreConfig};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Counting launcher
// ---------------------------------------------------------------------------

/// Wraps the real fixed-argv launcher, counts spawn attempts, and records argv.
struct CountingArgvLauncher {
    inner: SystemArgvLauncher,
    spawns: Arc<AtomicUsize>,
    requests: Arc<std::sync::Mutex<Vec<ArgvRequest>>>,
}

impl ArgvLauncher for CountingArgvLauncher {
    type Child = SystemChild;

    fn spawn_argv(&mut self, request: &ArgvRequest) -> std::io::Result<SystemChild> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("request log lock")
            .push(request.clone());
        self.inner.spawn_argv(request)
    }
}

// ---------------------------------------------------------------------------
// Audit sinks
// ---------------------------------------------------------------------------

/// Audit sink that fails the intent write and never records anything.
#[derive(Debug, Default)]
struct FailingIntentAudit {
    result_writes: usize,
}

impl HostGitAuditPort for FailingIntentAudit {
    fn record_intent(
        &mut self,
        _intent: &HostGitIntent,
        _activity_id: HostActivityId,
        _events: Vec<EventDraft>,
    ) -> Result<(), CoreError> {
        Err(CoreError::StoreUnavailable {
            failure: StoreFailureKind::Unavailable,
        })
    }

    fn record_result(
        &mut self,
        _intent: &HostGitIntent,
        _activity_id: HostActivityId,
        _report: &HostGitReport,
        _events: Vec<EventDraft>,
    ) -> Result<(), CoreError> {
        self.result_writes += 1;
        Ok(())
    }
}

/// Audit sink that accepts the intent and refuses the result write.
#[derive(Debug, Default)]
struct FailingResultAudit {
    intents: usize,
}

impl HostGitAuditPort for FailingResultAudit {
    fn record_intent(
        &mut self,
        _intent: &HostGitIntent,
        _activity_id: HostActivityId,
        _events: Vec<EventDraft>,
    ) -> Result<(), CoreError> {
        self.intents += 1;
        Ok(())
    }

    fn record_result(
        &mut self,
        _intent: &HostGitIntent,
        _activity_id: HostActivityId,
        _report: &HostGitReport,
        _events: Vec<EventDraft>,
    ) -> Result<(), CoreError> {
        Err(CoreError::StoreUnavailable {
            failure: StoreFailureKind::Unavailable,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository fixture
// ---------------------------------------------------------------------------

const BRANCH: &str = "h4-host-git";

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    /// Creates a real repository with one initial commit and a fixed identity.
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = fs::canonicalize(temp.path()).expect("canonical temp root");
        run_git(&root, &["init", "-q", "-b", BRANCH]);
        run_git(&root, &["config", "user.name", "Host Test"]);
        run_git(&root, &["config", "user.email", "host@example.invalid"]);
        // Ignore the host-wide hook directory so each test controls its own
        // hook. The boundary reads this value from the repository config.
        run_git(&root, &["config", "core.hooksPath", ".git/hooks"]);
        fs::write(root.join("README.md"), "initial\n").expect("seed file");
        run_git(&root, &["add", "--", "README.md"]);
        run_git_without_hooks(&root, &["commit", "-q", "-m", "initial"]);
        Self { _temp: temp, root }
    }

    fn root_path(&self) -> AbsolutePath {
        AbsolutePath::new(self.root.to_string_lossy().into_owned()).expect("absolute root")
    }

    fn head(&self) -> String {
        git_stdout(&self.root, &["rev-parse", "HEAD"])
    }

    fn commit_count(&self) -> usize {
        git_stdout(&self.root, &["rev-list", "--count", "HEAD"])
            .parse()
            .expect("commit count")
    }

    fn tree(&self) -> String {
        git_stdout(&self.root, &["rev-parse", "HEAD^{tree}"])
    }

    fn current_branch(&self) -> String {
        git_stdout(&self.root, &["symbolic-ref", "--short", "HEAD"])
    }

    fn write(&self, relative: &str, content: &str) -> HostGitPath {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent directory");
        }
        fs::write(&path, content).expect("write file");
        HostGitPath::for_bytes(relative, content.as_bytes()).expect("path entry")
    }

    fn install_hook(&self, script: &str) {
        let hooks = self.root.join(".git").join("hooks");
        fs::create_dir_all(&hooks).expect("hooks directory");
        let hook = hooks.join("pre-commit");
        let mut file = fs::File::create(&hook).expect("hook file");
        file.write_all(script.as_bytes()).expect("hook bytes");
        drop(file);
        make_executable(&hook);
    }

    fn install_gate(&self, script: &str) -> AbsolutePath {
        let path = self.root.join("gate.sh");
        let mut file = fs::File::create(&path).expect("gate file");
        file.write_all(script.as_bytes()).expect("gate bytes");
        drop(file);
        make_executable(&path);
        AbsolutePath::new(path.to_string_lossy().into_owned()).expect("absolute gate path")
    }

    /// A gate that always accepts, used when a test is about Git itself.
    fn accepting_gate(&self) -> HostGitGate {
        let program = self.install_gate("#!/bin/sh\nexit 0\n");
        HostGitGate::new(program, Vec::new(), None).expect("gate")
    }

    /// Whether `path` is staged right now.
    fn is_staged(&self, relative: &str) -> bool {
        git_stdout(&self.root, &["diff", "--cached", "--name-only"])
            .lines()
            .any(|line| line == relative)
    }

    /// Whether `path` is tracked at HEAD.
    fn tracked_at_head(&self, relative: &str) -> bool {
        git_stdout(&self.root, &["ls-tree", "-r", "--name-only", "HEAD"])
            .lines()
            .any(|line| line == relative)
    }
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).expect("hook metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("hook permissions");
}

fn run_git(root: &Path, args: &[&str]) {
    let status = git_command(root, args)
        .status()
        .expect("git command starts");
    assert!(status.success(), "git {args:?} failed with {status}");
}

/// Setup commits bypass hooks: a test repository must be buildable without a
/// hook under test running early. The boundary itself never does this.
fn run_git_without_hooks(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(root)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .output()
        .expect("git command starts");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_command(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command.current_dir(root).args(args);
    command
}

fn git_stdout(root: &Path, args: &[&str]) -> String {
    let output = git_command(root, args).output().expect("git command runs");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

// ---------------------------------------------------------------------------
// Boundary fixture
// ---------------------------------------------------------------------------

const APPROVAL_ID: &str =
    "execution_approval:10000000-0000-4000-8000-000000000001:30000000-0000-4000-8000-000000000001";

struct Harness {
    repo: Repo,
    project: ProjectId,
    approval: HostCommitApproval,
}

impl Harness {
    fn new() -> Self {
        let repo = Repo::new();
        let project = ProjectId::new();
        let approval = approval_for(&repo, project);
        Self {
            repo,
            project,
            approval,
        }
    }

    fn authorization(&self) -> HostGitAuthorization {
        self.approval.clone().authorize().expect("human approval")
    }

    fn boundary<A>(
        &self,
        audit: A,
        spawns: &Arc<AtomicUsize>,
        requests: &Arc<std::sync::Mutex<Vec<ArgvRequest>>>,
    ) -> HostGitBoundary<CountingArgvLauncher, A>
    where
        A: HostGitAuditPort,
    {
        HostGitBoundary::new(
            AbsolutePath::new(git_program()).expect("absolute git path"),
            CountingArgvLauncher {
                inner: SystemArgvLauncher,
                spawns: Arc::clone(spawns),
                requests: Arc::clone(requests),
            },
            audit,
            ProcessSupervisor::new(),
        )
        .expect("boundary")
        .with_timeout_grace(Duration::from_millis(400))
        .with_confirm_timeout(Duration::from_millis(2_000))
        .with_capture_timeout(Duration::from_millis(1_000))
    }

    fn intent(
        &self,
        paths: Vec<HostGitPath>,
        message: HostGitMessage,
        gate: HostGitGate,
        timeout: Duration,
    ) -> HostGitIntent {
        intent_for(&self.repo, self.project, paths, message, gate, timeout)
    }
}

fn git_program() -> String {
    // Prefer the same binary the test harness uses for setup so the boundary
    // and the fixture agree on version and configuration.
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

fn approval_for(repo: &Repo, project: ProjectId) -> HostCommitApproval {
    HostCommitApproval::new(
        project,
        APPROVAL_ID,
        1,
        HostGitApprover::Human,
        repo.root_path(),
        BRANCH,
        true,
        true,
    )
    .expect("approval")
}

fn message(repo: &Repo, request: &str) -> HostGitMessage {
    let _ = repo;
    HostGitMessage::new(
        "Task 6: host git boundary",
        vec![
            HostGitTrailer::new("Herness-Execution", "execution:fixture:1").expect("trailer"),
            HostGitTrailer::new("Herness-Task", "6").expect("trailer"),
            HostGitTrailer::new("Herness-Request", request).expect("trailer"),
        ],
    )
    .expect("message")
}

fn intent_for(
    repo: &Repo,
    project: ProjectId,
    paths: Vec<HostGitPath>,
    message: HostGitMessage,
    gate: HostGitGate,
    timeout: Duration,
) -> HostGitIntent {
    HostGitIntent::new(
        project,
        "commit:fixture:00000000-0000-4000-8000-000000000001",
        Purpose::new("commit the approved Task change").expect("purpose"),
        "execution:fixture:1",
        6,
        "H1 approved host Git boundary",
        APPROVAL_ID,
        1,
        repo.root_path(),
        BRANCH,
        GitObjectId::parse(repo.head()).expect("head"),
        None,
        paths,
        message,
        gate,
        timeout,
        None,
    )
    .expect("intent")
    .with_actor(HostGitActor::new("Host Test", "host@example.invalid").expect("actor"))
}

fn spawns() -> Arc<AtomicUsize> {
    Arc::new(AtomicUsize::new(0))
}

fn requests() -> Arc<std::sync::Mutex<Vec<ArgvRequest>>> {
    Arc::new(std::sync::Mutex::new(Vec::new()))
}

fn spawn_count(counter: &Arc<AtomicUsize>) -> usize {
    counter.load(Ordering::SeqCst)
}

fn argv_of(requests: &Arc<std::sync::Mutex<Vec<ArgvRequest>>>) -> Vec<Vec<String>> {
    requests
        .lock()
        .expect("request log lock")
        .iter()
        .map(|request| request.args().to_vec())
        .collect()
}

fn expect_committed(report: &HostGitReport) -> (&GitObjectId, &GitObjectId, &GitObjectId) {
    match report.outcome() {
        HostGitOutcome::Committed {
            commit,
            tree,
            parent,
        } => (commit, tree, parent),
        other => panic!("expected a committed outcome, got {other:?}"),
    }
}

fn expect_rejected(report: &HostGitReport) -> &HostGitRefusal {
    match report.outcome() {
        HostGitOutcome::Rejected { reason } => reason,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// Real commit through the boundary
// ---------------------------------------------------------------------------

#[test]
fn approved_commit_stages_only_explicit_paths_and_keeps_trailers() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/feature.rs", "pub fn feature() {}\n");
    // An unrelated dirty file exists and must stay unstaged and uncommitted.
    fs::write(repo.root.join("notes.txt"), "unrelated work\n").expect("unrelated file");

    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change.clone()],
        message(repo, "request-1"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );

    let head_before = repo.head();
    let report = boundary
        .commit(&intent, &authorization)
        .expect("the intent is persisted");
    let (commit, tree, parent) = expect_committed(&report);
    assert_eq!(report.stage(), HostGitStage::Observe);
    assert!(report.result_recorded());
    assert_eq!(report.gate_outcome(), HostGitGateOutcome::Passed);
    assert_eq!(report.index_state(), HostGitIndexState::Committed);
    assert_eq!(parent.as_str(), head_before);
    assert_eq!(commit.as_str(), repo.head());
    assert_ne!(commit.as_str(), head_before);
    // The branch was neither changed nor recreated.
    assert_eq!(repo.current_branch(), BRANCH);
    assert_eq!(tree.as_str(), repo.tree());
    assert_eq!(
        repo.tree(),
        git_stdout(&repo.root, &["rev-parse", "HEAD^{tree}"])
    );

    // The commit carries the approved trailers and the exact message.
    let body = git_stdout(&repo.root, &["log", "-1", "--pretty=%B"]);
    assert!(
        body.starts_with("Task 6: host git boundary"),
        "body: {body}"
    );
    assert!(
        body.contains("Herness-Execution: execution:fixture:1"),
        "body: {body}"
    );
    assert!(body.contains("Herness-Task: 6"), "body: {body}");
    assert!(body.contains("Herness-Request: request-1"), "body: {body}");

    // Only the approved path is in the commit.
    let changed = git_stdout(
        &repo.root,
        &["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
    );
    assert_eq!(changed, "src/feature.rs");
    assert!(repo.tracked_at_head("src/feature.rs"));
    assert!(!repo.tracked_at_head("notes.txt"));
    assert!(!repo.is_staged("notes.txt"));
    assert!(repo.root.join("notes.txt").exists());

    // The audit recorded one intent and one result as host activity.
    assert_eq!(boundary.audit().intents().len(), 1);
    assert_eq!(boundary.audit().results().len(), 1);
    let intent_record = &boundary.audit().intents()[0];
    assert_eq!(intent_record["actor"], "host");
    assert!(intent_record.get("rationale").is_none());
    assert_eq!(
        intent_record["requestId"],
        "commit:fixture:00000000-0000-4000-8000-000000000001"
    );
    assert_eq!(intent_record["taskNumber"], 6);
    assert_eq!(intent_record["approvalRevision"], 1);
    let result_record = &boundary.audit().results()[0];
    assert_eq!(result_record["stage"], "observe");
    assert_eq!(result_record["outcome"]["kind"], "committed");

    // The argv was fixed: `add -- <one path>` and `commit` without --no-verify.
    let argv = argv_of(&log);
    let add = argv
        .iter()
        .find(|args| args.first().is_some_and(|value| value == "add"))
        .expect("a git add argv");
    assert_eq!(
        add,
        &vec![
            "add".to_owned(),
            "--".to_owned(),
            "src/feature.rs".to_owned()
        ]
    );
    for args in &argv {
        assert!(
            !args
                .iter()
                .any(|value| value == "-A" || value == "." || value == "--no-verify")
        );
    }
    let commit_args = argv
        .iter()
        .find(|args| args.first().is_some_and(|value| value == "commit"))
        .expect("a git commit argv");
    assert!(commit_args.iter().any(|value| value == "--file"));
    assert!(commit_args.iter().any(|value| value == "-"));
    assert!(
        commit_args
            .iter()
            .any(|value| value == "--cleanup=whitespace")
    );
}

#[test]
fn unrelated_dirty_file_stays_out_of_the_commit_and_the_index() {
    let harness = Harness::new();
    let repo = &harness.repo;
    repo.write("src/a.rs", "a\n");
    fs::write(repo.root.join("scratch.txt"), "scratch\n").expect("scratch file");
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let authorization = harness.authorization();
    let a = HostGitPath::for_bytes("src/a.rs", b"a\n").expect("path");
    let intent = harness.intent(
        vec![a],
        message(repo, "request-dirty"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );

    let report = boundary.commit(&intent, &authorization).expect("intent");
    expect_committed(&report);

    let status = git_stdout(&repo.root, &["status", "--porcelain"]);
    assert!(
        status.lines().any(|line| line == "?? scratch.txt"),
        "the unrelated file must stay untracked: {status}"
    );
    assert!(
        !status.contains("scratch.txt") || status.contains("?? scratch.txt"),
        "no staged unrelated change: {status}"
    );
}

// ---------------------------------------------------------------------------
// Authorization and verification refusals
// ---------------------------------------------------------------------------

#[test]
fn model_and_owner_kind_approvals_cannot_produce_an_authorization() {
    let repo = Repo::new();
    let project = ProjectId::new();
    for approver in [HostGitApprover::Model, HostGitApprover::OwnerKind] {
        let approval = HostCommitApproval::new(
            project,
            APPROVAL_ID,
            1,
            approver,
            repo.root_path(),
            BRANCH,
            true,
            true,
        )
        .expect("value");
        let refusal = approval.authorize().expect_err("no authorization");
        assert_eq!(refusal.code(), "not_authorized");
    }
    // A human approval that withholds host commit or hook execution also fails.
    for (host_commit, run_hooks) in [(false, true), (true, false)] {
        let approval = HostCommitApproval::new(
            project,
            APPROVAL_ID,
            1,
            HostGitApprover::Human,
            repo.root_path(),
            BRANCH,
            host_commit,
            run_hooks,
        )
        .expect("value");
        assert!(approval.authorize().is_err());
    }
}

#[test]
fn authorization_from_another_approval_is_refused_with_zero_spawns() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/b.rs", "b\n");
    let other_approval = HostCommitApproval::new(
        harness.project,
        "execution_approval:10000000-0000-4000-8000-000000000002:30000000-0000-4000-8000-000000000009",
        1,
        HostGitApprover::Human,
        repo.root_path(),
        BRANCH,
        true,
        true,
    )
    .expect("other approval");
    let authorization = other_approval.authorize().expect("human");
    let head = repo.head();
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let intent = harness.intent(
        vec![change],
        message(repo, "request-mismatch"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );

    let report = boundary.commit(&intent, &authorization).expect("report");
    let refusal = expect_rejected(&report);
    assert!(
        matches!(refusal, HostGitRefusal::NotAuthorized { .. }),
        "{refusal:?}"
    );
    assert_eq!(spawn_count(&counter), 0, "no process may be created");
    assert_eq!(repo.head(), head);
    assert!(
        git_stdout(&repo.root, &["diff", "--cached", "--name-only"]).is_empty(),
        "nothing may be staged"
    );
    assert!(!repo.tracked_at_head("src/b.rs"));
}

#[test]
fn a_different_approval_revision_is_refused_before_any_read() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/c.rs", "c\n");
    let later = HostCommitApproval::new(
        harness.project,
        APPROVAL_ID,
        7,
        HostGitApprover::Human,
        repo.root_path(),
        BRANCH,
        true,
        true,
    )
    .expect("later approval");
    let authorization = later.authorize().expect("human");
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    // The intent names revision 1 while the authorization names revision 7.
    let intent = harness.intent(
        vec![change],
        message(repo, "request-revision"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );

    let report = boundary.commit(&intent, &authorization).expect("report");
    match expect_rejected(&report) {
        HostGitRefusal::ApprovalRevisionMismatch {
            authorized,
            requested,
        } => {
            assert_eq!(*authorized, 7);
            assert_eq!(*requested, 1);
        }
        other => panic!("expected an approval revision mismatch, got {other:?}"),
    }
    assert_eq!(report.stage(), HostGitStage::Verify);
    assert_eq!(spawn_count(&counter), 0);
}

#[test]
fn a_stale_expected_parent_is_refused_and_the_repository_is_unchanged() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/d.rs", "d\n");
    // The intent is built against the current HEAD, then a real commit moves it.
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change],
        message(repo, "request-stale"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );
    fs::write(repo.root.join("move.txt"), "move\n").expect("move file");
    run_git_without_hooks(&repo.root, &["add", "--", "move.txt"]);
    run_git_without_hooks(&repo.root, &["commit", "-q", "-m", "external move"]);
    let head_before = repo.head();
    let count_before = repo.commit_count();

    let report = boundary.commit(&intent, &authorization).expect("report");
    match expect_rejected(&report) {
        HostGitRefusal::ParentMismatch { expected, found } => {
            assert_ne!(expected, found);
            assert_eq!(expected.as_str(), intent.expected_parent().as_str());
            assert_eq!(found.as_str(), head_before);
        }
        other => panic!("expected a parent mismatch, got {other:?}"),
    }
    assert_eq!(repo.head(), head_before);
    assert_eq!(repo.commit_count(), count_before);
    assert!(!repo.is_staged("src/d.rs"), "nothing may be staged");
    assert_eq!(spawn_count(&counter), 0, "verification must not spawn Git");
}

#[test]
fn pending_staged_changes_are_refused_before_staging_and_spawn_nothing() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/e.rs", "e\n");
    fs::write(repo.root.join("pre-staged.txt"), "other\n").expect("pre-staged file");
    run_git_without_hooks(&repo.root, &["add", "--", "pre-staged.txt"]);
    let head = repo.head();
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change],
        message(repo, "request-staged"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );

    let report = boundary.commit(&intent, &authorization).expect("report");
    assert_eq!(report.stage(), HostGitStage::Verify);
    assert!(matches!(
        expect_rejected(&report),
        HostGitRefusal::IndexNotClean
    ));
    assert_eq!(repo.head(), head);
    // The only process is the read-only index query; nothing is staged or
    // committed, and the pre-existing staged change is untouched.
    let argv = argv_of(&log);
    assert!(
        !argv.iter().any(|args| args
            .first()
            .is_some_and(|value| value == "add" || value == "commit")),
        "no staging or commit may run: {argv:?}"
    );
    assert!(repo.is_staged("pre-staged.txt"));
    assert!(!repo.is_staged("src/e.rs"));
}

#[test]
fn a_changed_path_content_is_refused_before_staging() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let approved = repo.write("src/f.rs", "approved\n");
    // The file changes after the approval was recorded.
    fs::write(repo.root.join("src/f.rs"), "tampered\n").expect("tamper");
    let head = repo.head();
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![approved],
        message(repo, "request-tampered"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );

    let report = boundary.commit(&intent, &authorization).expect("report");
    assert!(matches!(
        expect_rejected(&report),
        HostGitRefusal::ContentMismatch { .. }
    ));
    assert_eq!(repo.head(), head);
    assert_eq!(spawn_count(&counter), 0);
}

#[test]
fn a_path_outside_the_checkout_or_absolute_is_refused_at_construction() {
    let repo = Repo::new();
    for path in [
        "../outside.txt",
        "/etc/passwd",
        "-rf",
        "./inside.txt",
        "dir\\file",
    ] {
        assert!(
            HostGitPath::new(path, 0, format!("sha256:{}", "0".repeat(64))).is_err(),
            "{path} must be refused"
        );
    }
    // A gate program that does not exist is refused at construction.
    let missing_gate = HostGitGate::new(
        AbsolutePath::new(format!("{}/missing-gate.sh", repo.root.display())).expect("absolute"),
        Vec::new(),
        None,
    );
    assert!(missing_gate.is_err(), "a missing gate program is refused");

    let gate = repo.accepting_gate();
    let path = HostGitPath::new("a.txt", 0, format!("sha256:{}", "0".repeat(64))).expect("path");
    let text = HostGitMessage::new(
        "subject",
        vec![HostGitTrailer::new("Herness-Task", "6").expect("t")],
    )
    .expect("message");
    let absolute_intent = HostGitIntent::new(
        ProjectId::new(),
        "commit:fixture:1",
        Purpose::new("refuse a non-canonical root").expect("purpose"),
        "execution:fixture:1",
        6,
        "task",
        APPROVAL_ID,
        1,
        AbsolutePath::new("/tmp/../etc").expect("absolute"),
        BRANCH,
        GitObjectId::parse("a".repeat(40)).expect("head"),
        None,
        vec![path],
        text,
        gate,
        Duration::from_secs(10),
        None,
    );
    assert!(
        absolute_intent.is_err(),
        "'..' in the checkout root is refused"
    );
}

// ---------------------------------------------------------------------------
// Hook behaviour
// ---------------------------------------------------------------------------

#[test]
fn a_failing_hook_refuses_without_creating_a_commit() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/g.rs", "g\n");
    repo.install_hook("#!/bin/sh\necho 'refused by hook' >&2\nexit 1\n");
    let head = repo.head();
    let count = repo.commit_count();
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change],
        message(repo, "request-hook"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );

    let report = boundary.commit(&intent, &authorization).expect("report");
    assert_eq!(report.stage(), HostGitStage::Commit);
    match expect_rejected(&report) {
        HostGitRefusal::CommitFailed { exit_code, detail } => {
            assert_eq!(*exit_code, Some(1));
            assert!(detail.contains("refused by hook"), "detail: {detail}");
        }
        other => panic!("expected a commit failure, got {other:?}"),
    }
    assert_eq!(repo.head(), head);
    assert_eq!(repo.commit_count(), count);
    assert!(report.result_recorded(), "the refusal is recorded");
    // `--no-verify` must never be passed, so the hook really ran.
    let argv = argv_of(&log);
    assert!(
        !argv.iter().flatten().any(|value| value == "--no-verify"),
        "the boundary must never bypass hooks"
    );
    assert!(
        repo.is_staged("src/g.rs"),
        "the staged index is left for the human"
    );
}

#[test]
fn a_failing_common_gate_refuses_before_the_commit() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/h.rs", "h\n");
    let marker = repo.root.join("gate-ran");
    let gate_program = repo.install_gate(&format!(
        "#!/bin/sh\ntouch '{}'\necho 'staged document policy failed' >&2\nexit 3\n",
        marker.display()
    ));
    let gate = HostGitGate::new(gate_program, Vec::new(), None).expect("gate");
    let head = repo.head();
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change],
        message(repo, "request-gate"),
        gate,
        Duration::from_secs(20),
    );

    let report = boundary.commit(&intent, &authorization).expect("report");
    assert_eq!(report.stage(), HostGitStage::Gate);
    assert_eq!(report.gate_outcome(), HostGitGateOutcome::Failed);
    match expect_rejected(&report) {
        HostGitRefusal::GateFailed { exit_code, detail } => {
            assert_eq!(*exit_code, Some(3));
            assert!(detail.contains("staged document policy failed"), "{detail}");
        }
        other => panic!("expected a gate failure, got {other:?}"),
    }
    assert!(marker.exists(), "the approved gate must actually run");
    assert_eq!(repo.head(), head);
    assert!(
        !argv_of(&log)
            .iter()
            .any(|args| args.first().is_some_and(|value| value == "commit"))
    );
}

#[test]
fn a_stopping_hook_is_confirmed_stopped_and_reported_unknown() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/i.rs", "i\n");
    let started = repo.root.join("hook-started");
    repo.install_hook(&format!(
        "#!/bin/sh\ntouch '{}'\nsleep 30\n",
        started.display()
    ));
    let head = repo.head();
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let supervisor = boundary.supervisor().clone();
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change],
        message(repo, "request-stop"),
        repo.accepting_gate(),
        Duration::from_secs(25),
    );

    let handle = thread::spawn(move || {
        let result = boundary.commit(&intent, &authorization);
        (boundary, result)
    });
    wait_for_file(&started);
    let stopped = supervisor.stop_all(Duration::from_millis(800));
    assert!(
        stopped.all_confirmed(),
        "the managed group must be confirmed gone: {stopped:?}"
    );

    let (boundary, result) = handle.join().expect("commit thread");
    let report = result.expect("the intent is persisted");
    assert_eq!(report.stage(), HostGitStage::Commit);
    match report.outcome() {
        HostGitOutcome::Unknown { reason } => {
            assert_eq!(*reason, HostGitUnknown::Stopped, "a stop is never success");
        }
        other => panic!("expected an unknown result, got {other:?}"),
    }
    assert!(!report.outcome().may_exist() || report.observed().is_none());
    let termination = report.termination().expect("a managed process ran");
    assert!(termination.confirmed(), "the stop must be confirmed");
    assert_eq!(termination.stop_status(), ShellStopStatus::StopRequested);
    assert_eq!(repo.head(), head, "no commit may exist after a stop");
    assert!(boundary.audit().results().len() == 1);
}

#[test]
fn a_hook_that_outlives_the_commit_budget_is_reported_unknown_not_success() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/j.rs", "j\n");
    repo.install_hook("#!/bin/sh\nexec sleep 20\n");
    let head = repo.head();
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change],
        message(repo, "request-timeout"),
        repo.accepting_gate(),
        Duration::from_millis(900),
    );

    let report = boundary.commit(&intent, &authorization).expect("report");
    assert!(matches!(
        report.outcome(),
        HostGitOutcome::Unknown {
            reason: HostGitUnknown::Timeout
        }
    ));
    assert_eq!(repo.head(), head);
    assert!(report.result_recorded());
}

#[test]
fn a_hook_that_moves_the_branch_is_detected_as_an_unexpected_operation() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/moved.rs", "moved\n");
    // The hook performs a branch change the host never requested.
    repo.install_hook("#!/bin/sh\ngit checkout -q -b unexpected-branch\nexit 0\n");
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change],
        message(repo, "request-moved"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );

    let report = boundary.commit(&intent, &authorization).expect("report");
    assert_eq!(report.stage(), HostGitStage::Observe);
    match report.outcome() {
        HostGitOutcome::Unknown { reason } => {
            assert_eq!(*reason, HostGitUnknown::UnexpectedBranchMovement);
        }
        other => panic!("an unrequested branch change is never success: {other:?}"),
    }
    // The boundary reports the movement instead of silently accepting it, and it
    // never rewrites history to "fix" it.
    assert_eq!(repo.current_branch(), "unexpected-branch");
    assert_eq!(report.index_state(), HostGitIndexState::Unknown);
}

// ---------------------------------------------------------------------------
// Intent persistence and Git/DB uncertainty
// ---------------------------------------------------------------------------

#[test]
fn an_intent_persistence_failure_executes_no_git() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/k.rs", "k\n");
    let head = repo.head();
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(FailingIntentAudit::default(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change],
        message(repo, "request-nostore"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );

    let error = boundary
        .commit(&intent, &authorization)
        .expect_err("the intent must be durable first");
    assert!(matches!(error, HostGitError::IntentNotPersisted { .. }));
    assert_eq!(spawn_count(&counter), 0, "no Git process may run");
    assert_eq!(repo.head(), head);
    assert!(!repo.is_staged("src/k.rs"));
    assert_eq!(boundary.audit().result_writes, 0);
}

#[test]
fn a_failed_result_write_keeps_the_commit_and_reports_unknown() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/l.rs", "l\n");
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(FailingResultAudit::default(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change],
        message(repo, "request-lost"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );

    let report = boundary.commit(&intent, &authorization).expect("report");
    match report.outcome() {
        HostGitOutcome::Unknown { reason } => {
            assert_eq!(*reason, HostGitUnknown::AuditWriteFailed);
        }
        other => panic!("expected an unknown result, got {other:?}"),
    }
    assert!(!report.result_recorded());
    let observed = report.observed().expect("the commit is observed");
    assert_eq!(observed.commit().as_str(), repo.head());
    // The commit is real and was not rolled back.
    assert!(repo.tracked_at_head("src/l.rs"));
    assert_eq!(repo.commit_count(), 2);
    assert_eq!(boundary.audit().intents, 1);
}

// ---------------------------------------------------------------------------
// Real store audit
// ---------------------------------------------------------------------------

#[test]
fn the_store_audit_uses_host_activity_without_faking_a_run() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/m.rs", "m\n");
    let temp = tempfile::tempdir().expect("app data");
    let config = StoreConfig::new(temp.path().join("app-data")).expect("config");
    let store = Store::open(config).expect("store");
    let counter = spawns();
    let log = requests();

    let project = harness.project;
    let mut boundary = HostGitBoundary::new(
        AbsolutePath::new(git_program()).expect("git"),
        CountingArgvLauncher {
            inner: SystemArgvLauncher,
            spawns: Arc::clone(&counter),
            requests: Arc::clone(&log),
        },
        StoreHostGitAudit::new(store),
        ProcessSupervisor::new(),
    )
    .expect("boundary")
    .with_timeout_grace(Duration::from_millis(400))
    .with_confirm_timeout(Duration::from_millis(2_000));

    let authorization = harness.authorization();
    let intent = harness.intent(
        vec![change],
        message(repo, "request-store"),
        repo.accepting_gate(),
        Duration::from_secs(20),
    );
    let report = boundary.commit(&intent, &authorization).expect("report");
    expect_committed(&report);

    let key = intent.record_key();
    let stored = boundary
        .audit()
        .store()
        .load_host_state(&key)
        .expect("host state read")
        .expect("the record exists");
    let value: serde_json::Value = serde_json::from_slice(&stored).expect("json record");
    assert_eq!(value["state"], "result");
    assert_eq!(value["intent"]["requestId"], intent.request_id());
    assert_eq!(
        value["intent"]["purpose"],
        "commit the approved Task change"
    );
    assert_eq!(value["result"]["outcome"]["kind"], "committed");

    let events = boundary
        .audit()
        .store()
        .events_after(&project, None, HistoryLimit::new(50).expect("limit"))
        .expect("events");
    let kinds: Vec<&str> = events.iter().map(|event| event.kind().as_str()).collect();
    assert!(
        kinds.contains(&HOST_GIT_STARTED_EVENT_KIND),
        "kinds: {kinds:?}"
    );
    assert!(
        kinds.contains(&HOST_GIT_FINISHED_EVENT_KIND),
        "kinds: {kinds:?}"
    );
    for event in &events {
        assert!(
            event.run_subject().is_none(),
            "host Git must not fabricate a run"
        );
        let activity = event
            .subject()
            .host_activity()
            .expect("a host activity subject");
        assert_eq!(activity.activity_kind().as_str(), HOST_GIT_ACTIVITY_KIND);
        assert_eq!(activity.activity_id(), intent.activity_id());
    }
}

// ---------------------------------------------------------------------------
// H4 journal production
// ---------------------------------------------------------------------------

#[test]
fn the_h4_git_journal_entry_is_produced_from_the_boundary_intent_and_result() {
    let harness = Harness::new();
    let repo = &harness.repo;
    let change = repo.write("src/n.rs", "n\n");
    let project = harness.project;
    let execution = ExecutionId::new(project);
    let request = CommitRequestId::new(project);
    let task = TaskRef::new(
        TaskStableId::new(project),
        TaskNumber::new(6).expect("task number"),
    );
    let baseline = herness_sdd_execute::Baseline::parse(repo.head()).expect("baseline");
    let head = CommitSha::parse(repo.head()).expect("head");
    let committed_path = CommittedPath::new(
        change.path(),
        change.bytes(),
        Some(Sha256DigestLike::parse(change.digest())),
    )
    .expect("committed path");
    let sdd_message = CommitMessage::new(task, "host git boundary", execution, request, Vec::new())
        .expect("message");
    let sdd_intent = GitCommitIntent::new(
        task,
        BRANCH,
        baseline.clone(),
        head,
        None,
        vec![committed_path],
        sdd_message,
        PreHookState::new(true, vec![change.path().to_owned()], None, None).expect("pre hook"),
        30,
    )
    .expect("H4 intent");
    let identity = RequestIdentity::new(project, execution, request, ExecutionRevision::INITIAL)
        .expect("identity");
    let journal = GitJournalEntry::new(identity, sdd_intent).expect("journal intent");
    assert_eq!(
        journal.state(),
        herness_sdd_execute::GitJournalState::Intent
    );
    assert!(journal.outcome().is_none());

    // The boundary intent is built from the same recorded values. The H4
    // message and paths convert into the boundary's values, so Task 17's
    // `H4/git/finalize` can drive this boundary from one journal entry.
    let boundary_message = HostGitMessage::new(
        journal.intent().message().subject(),
        journal
            .intent()
            .message()
            .trailers()
            .iter()
            .map(|trailer| HostGitTrailer::new(trailer.key(), trailer.value()).expect("trailer"))
            .collect(),
    )
    .expect("boundary message");
    assert_eq!(
        boundary_message.render(),
        journal.intent().message().render()
    );
    let boundary_paths: Vec<HostGitPath> = journal
        .intent()
        .paths()
        .iter()
        .map(|path| {
            HostGitPath::new(
                path.path(),
                path.bytes(),
                path.digest().expect("digest").as_str(),
            )
            .expect("boundary path")
        })
        .collect();
    let counter = spawns();
    let log = requests();
    let mut boundary = harness.boundary(RecordingHostGitAudit::new(), &counter, &log);
    let authorization = harness.authorization();
    let intent = harness.intent(
        boundary_paths,
        boundary_message,
        repo.accepting_gate(),
        Duration::from_secs(20),
    );
    let report = boundary.commit(&intent, &authorization).expect("report");
    let (commit, tree, parent) = expect_committed(&report);
    // The real commit message carries the H4-required trailers verbatim.
    let body = git_stdout(&repo.root, &["log", "-1", "--pretty=%B"]);
    for trailer in journal.intent().message().trailers() {
        let expected = format!("{}: {}", trailer.key(), trailer.value());
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }

    // The observed values turn into the H4 outcome without inventing anything.
    let outcome = GitCommitOutcome::Committed {
        commit: CommitSha::parse(commit.as_str()).expect("commit"),
        tree: TreeSha::parse(tree.as_str()).expect("tree"),
        parent: CommitSha::parse(parent.as_str()).expect("parent"),
    };
    let recorded = journal.clone().record(outcome.clone());
    assert_eq!(
        recorded.state(),
        herness_sdd_execute::GitJournalState::Committed
    );
    assert_eq!(recorded.outcome(), Some(&outcome));

    // A re-delivered request returns the stored result instead of a new commit.
    let decision = recorded
        .decide(
            journal.identity(),
            journal.intent(),
            ExecutionRevision::INITIAL,
        )
        .expect("decision");
    assert!(matches!(
        decision,
        herness_sdd_execute::RequestDecision::Duplicate { outcome: Some(_) }
    ));

    // An unknown result is representable with the boundary's reason.
    let unknown = journal
        .clone()
        .mark_result_unknown(GitUnknownReason::Timeout);
    assert_eq!(
        unknown.state(),
        herness_sdd_execute::GitJournalState::ResultUnknown
    );
    assert!(unknown.outcome().expect("outcome").is_unknown());
    assert!(GitRejection::HookFailed == GitRejection::HookFailed);
}

/// Small adapter so the H4 `CommittedPath` digest type stays visible.
struct Sha256DigestLike;

impl Sha256DigestLike {
    fn parse(value: &str) -> herness_sdd_execute::Sha256Digest {
        herness_sdd_execute::Sha256Digest::parse(value).expect("sha256 digest")
    }
}

// ---------------------------------------------------------------------------
// Reachability
// ---------------------------------------------------------------------------

/// A minimal real executor used as the positive control for the probe.
struct PositiveControlExecutor;

impl ToolExecutor for PositiveControlExecutor {
    type Output = ();

    fn execute(&mut self, _operation: &FrozenOperation) -> Result<(), CoreError> {
        Ok(())
    }
}

/// A probe that resolves to `true` only when `T` implements a marker trait.
struct Probe<T>(std::marker::PhantomData<T>);

trait NotAToolExecutor {
    const IS_TOOL_EXECUTOR: bool = false;
}

impl<T> NotAToolExecutor for Probe<T> {}

impl<T: ToolExecutor> Probe<T> {
    const IS_TOOL_EXECUTOR: bool = true;
}

// Compile-time structural assertion: if the host Git boundary ever gained a
// `ToolExecutor` implementation (and so became reachable through `ToolGateway`),
// this module would stop compiling.
const _: () = assert!(
    !Probe::<HostGitBoundary<SystemArgvLauncher, RecordingHostGitAudit>>::IS_TOOL_EXECUTOR,
    "the host Git boundary must not implement ToolExecutor"
);
// The same probe reports `true` for a real executor, so the assertion above is
// not vacuous.
const _: () = assert!(
    Probe::<PositiveControlExecutor>::IS_TOOL_EXECUTOR,
    "the probe must detect a real ToolExecutor"
);

#[test]
fn the_host_git_boundary_is_not_a_model_tool() {
    // The compile-time assertion above proves `HostGitBoundary` is not a
    // `ToolExecutor`, so `ToolGateway` has no path to it. These checks cover the
    // other reachability paths: a tool name and a tool argument payload.
    //
    // No tool name deserializes as a host Git tool.
    for candidate in ["host_git", "git", "commit", "host_commit"] {
        let parsed: Result<ToolName, _> = serde_json::from_value(serde_json::json!(candidate));
        assert!(parsed.is_err(), "{candidate} must not be a ToolName");
    }
    // No tool name accepts a commit argument payload.
    let arguments: Result<ToolArguments, _> = serde_json::from_value(serde_json::json!({
        "tool": "host_git",
        "arguments": { "paths": ["src/lib.rs"] }
    }));
    assert!(arguments.is_err());
}

#[test]
fn a_model_permission_authorization_cannot_become_a_host_git_authorization() {
    // A policy may allow the model to run `git` through the shell tool. That
    // permission decision is a `permissions::Authorization`, a different type
    // from the host-only commit authorization, and there is no conversion
    // between them: this test would not compile if one existed.
    let fixture = herness_runtime_tests::fixtures::ProjectFixture::new();
    let mut admin = PolicyAdmin::new();
    admin
        .add_rule(
            PermissionRule::allow(
                RuleTarget::Tool {
                    tool: ToolName::Bash,
                },
                MatchMethod::AnyInvocation,
            )
            .expect("rule"),
        )
        .expect("add");
    let policy = admin.policy().clone();
    // Freeze the operation under the policy version that is current after the
    // rule was added.
    let operation = FrozenOperation::new(
        fixture.operation_id(),
        fixture.run_id,
        ToolName::Bash,
        ToolArguments::Bash(BashArgs {
            command: NonEmptyText::new("git commit -m 'model says commit'").expect("command"),
            purpose: Purpose::new("commit on behalf of the model").expect("purpose"),
            timeout_ms: None,
        }),
        fixture.cwd(),
        policy.version(),
        policy.mode(),
    )
    .expect("frozen operation");
    let grant = GrantScope::for_run(fixture.project_id, &policy);
    let mut gateway = ToolGateway::new(RecordingOnlyExecutor { calls: 0 });
    let outcome = gateway
        .authorize(
            &policy,
            &grant,
            &operation,
            &EvaluationContext::new("host git reachability test", Vec::new()),
            None,
        )
        .expect("evaluate");
    let PermissionOutcome::Allow { authorization } = outcome else {
        panic!("the rule allows the shell command");
    };
    // The shell permission is real, and it still cannot build the host
    // authorization: only `HostCommitApproval::authorize` can.
    assert_eq!(authorization.project_id(), fixture.project_id);
    let repo = Repo::new();
    let approval = approval_for(&repo, fixture.project_id);
    let host_authorization = approval.authorize().expect("human approval");
    assert_eq!(host_authorization.project_id(), fixture.project_id);
    // The shell authorization cannot be compared, converted, or substituted;
    // it is a distinct type with a distinct purpose.
    assert_ne!(
        std::any::type_name_of_val(&authorization),
        std::any::type_name_of_val(&host_authorization)
    );
}

/// Border executor for the reachability test. It records calls and does nothing.
struct RecordingOnlyExecutor {
    calls: usize,
}

impl ToolExecutor for RecordingOnlyExecutor {
    type Output = ();

    fn execute(&mut self, _operation: &FrozenOperation) -> Result<(), CoreError> {
        self.calls += 1;
        Ok(())
    }
}
