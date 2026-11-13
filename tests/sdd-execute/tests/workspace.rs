//! Black-box tests for the desktop H4 workspace adapter.
//!
//! Every case uses real temporary Git repositories created with `git init`, real
//! commits, a real linked worktree, and real `git status`/`git worktree` output.
//! Git is never mocked. The only synthetic values are the H4 project, the
//! approval identity, and the temporary `.gitignore` gate script.
//!
//! The cases cover, one for one, the Task 7 acceptance criteria:
//!
//! - a real linked worktree is honored and reported as the selected checkout;
//! - in-place selection, and every already-recorded decision being reused without
//!   asking again, while a genuinely undecided state asks the human;
//! - an original checkout left dirty never blocks a start, and is never touched;
//! - a dirty selected checkout refuses the start;
//! - a failing `git worktree add` creates zero worktrees and zero branches and
//!   never falls back to in-place;
//! - the `.gitignore` preparation commit touches only `.gitignore` and the
//!   baseline is fixed after it, once;
//! - `state()` and `start_check()` leave Git byte-identical;
//! - a second repository receives zero writes.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use herness_core::contracts::ProjectId;
use herness_core::{
    AbsolutePath, ArgvLauncher, ArgvRequest, HostGitBoundary, ProcessSupervisor,
    RecordingHostGitAudit, SystemArgvLauncher, SystemChild,
};
use herness_desktop::sdd_execute::{
    ApprovedDocument, GitRunner, HostGitPreparationCommit, ISOLATION_FEATURE, MemoryBaselineRecord,
    PREPARATION_COMMIT_FEATURE, WorkspaceAdapter, WorkspaceExpectation, WorkspaceSelectionAnswer,
    WorkspaceSelectionInput, WorkspaceSelectionSource, WorkspaceUndecided,
};
use herness_sdd_execute::{
    ApprovalRejection, ApprovalRequirement, ConflictReason, FailureCode, SddExecutionError,
    Sha256Digest, WorkspacePort, WorkspacePreparation,
};
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("20000000-0000-4000-8000-000000000007").unwrap())
}

fn other_project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("20000000-0000-4000-8000-000000000008").unwrap())
}

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

fn git_status(root: &Path) -> String {
    // Read-only in the test harness too, so measuring never perturbs the index.
    git(
        root,
        &["--no-optional-locks", "status", "--porcelain", "-z"],
    )
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

fn git_worktree_paths(root: &Path) -> Vec<String> {
    git(root, &["worktree", "list", "--porcelain"])
        .lines()
        .filter_map(|line| line.strip_prefix("worktree ").map(str::to_owned))
        .collect()
}

fn git_refs(root: &Path) -> String {
    git(root, &["for-each-ref", "--format=%(refname) %(objectname)"])
}

fn git_head(root: &Path) -> String {
    git(root, &["rev-parse", "HEAD"]).trim().to_owned()
}

/// One real temporary repository with one commit on `main`.
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
        let plan = b"# Plan\n\n## Task 1: something\n";
        std::fs::create_dir_all(root.join("docs/sdd/plans")).expect("plan directory");
        std::fs::write(root.join("docs/sdd/plans/plan.md"), plan).expect("plan");
        std::fs::create_dir_all(root.join("docs/sdd/specs")).expect("spec directory");
        std::fs::write(root.join("docs/sdd/specs/spec.md"), b"# Spec\n").expect("spec");
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
        let plan = std::fs::read(self.root.join("docs/sdd/plans/plan.md")).expect("plan bytes");
        let spec = std::fs::read(self.root.join("docs/sdd/specs/spec.md")).expect("spec bytes");
        vec![
            ApprovedDocument::plan("docs/sdd/plans/plan.md", &plan).expect("plan document"),
            ApprovedDocument::spec("docs/sdd/specs/spec.md", &spec).expect("spec document"),
        ]
    }

    /// Creates a real linked worktree on `branch` at `target`.
    fn linked_worktree(&self, target: &str, branch: &str) {
        git(
            &self.root,
            &["worktree", "add", "-b", branch, target, "main"],
        );
    }

    /// Puts the original checkout on the approved implementation branch.
    fn switch_to_approved_branch(&self) {
        git(&self.root, &["switch", "-c", "h4-exec"]);
    }

    /// Installs a real `Worktree: created <path>` progress ledger.
    fn record_progress_worktree(&self, recorded: &str) {
        self.write(
            ".sdd/progress.md",
            &format!(
                "Worktree: created {recorded}\nBranch baseline: {}\n",
                git_head(&self.root)
            ),
        );
    }
}

/// A passing staged-document gate script.
fn accepting_gate(temp: &TempDir) -> herness_core::HostGitGate {
    let path = temp.path().join("gate.sh");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("gate script");
    make_executable(&path);
    herness_core::HostGitGate::new(
        AbsolutePath::new(path.to_string_lossy().into_owned()).expect("gate path"),
        Vec::new(),
        None,
    )
    .expect("gate")
}

/// A failing staged-document gate script.
fn refusing_gate(temp: &TempDir) -> herness_core::HostGitGate {
    let path = temp.path().join("refusing-gate.sh");
    std::fs::write(&path, "#!/bin/sh\nexit 1\n").expect("gate script");
    make_executable(&path);
    herness_core::HostGitGate::new(
        AbsolutePath::new(path.to_string_lossy().into_owned()).expect("gate path"),
        Vec::new(),
        None,
    )
    .expect("gate")
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("chmod");
}

// ---------------------------------------------------------------------------
// Adapter construction
// ---------------------------------------------------------------------------

/// Wraps the real launcher, counts spawns, and records argv.
struct CountingArgvLauncher {
    inner: SystemArgvLauncher,
    spawns: Arc<AtomicUsize>,
}

impl ArgvLauncher for CountingArgvLauncher {
    type Child = SystemChild;

    fn spawn_argv(&mut self, request: &ArgvRequest) -> std::io::Result<SystemChild> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        self.inner.spawn_argv(request)
    }
}

struct Harness {
    adapter: WorkspaceAdapter<CountingArgvLauncher, HostGitPreparationCommit, MemoryBaselineRecord>,
    spawns: Arc<AtomicUsize>,
    expectation: WorkspaceExpectation,
}

fn harness(repo: &Repo, gate: herness_core::HostGitGate) -> Harness {
    let spawns = Arc::new(AtomicUsize::new(0));
    let runner = GitRunner::new(
        git_program(),
        CountingArgvLauncher {
            inner: SystemArgvLauncher,
            spawns: Arc::clone(&spawns),
        },
        ProcessSupervisor::new(),
        project(),
    )
    .expect("Git runner");
    let boundary = HostGitBoundary::new(
        git_program(),
        SystemArgvLauncher,
        RecordingHostGitAudit::new(),
        ProcessSupervisor::new(),
    )
    .expect("host Git boundary");
    let adapter = WorkspaceAdapter::new(
        runner,
        HostGitPreparationCommit::new(boundary),
        MemoryBaselineRecord::new(),
    );
    let expectation = WorkspaceExpectation::new(
        project(),
        repo.path(),
        "h4-exec",
        "main",
        "execution:fixture",
        "execution_approval:fixture",
        1,
        repo.documents(),
    )
    .expect("explicit expectation")
    .with_gate(gate);
    adapter.expect(expectation.clone());
    Harness {
        adapter,
        spawns,
        expectation,
    }
}

fn selection(repo: &Repo, answer: Option<WorkspaceSelectionAnswer>) -> WorkspaceSelectionInput {
    WorkspaceSelectionInput::new(project(), repo.path(), "main", "h4-exec", answer)
}

// ---------------------------------------------------------------------------
// 1. Decision reuse
// ---------------------------------------------------------------------------

#[test]
fn a_linked_worktree_is_honored_without_asking_again() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("linked");
    repo.linked_worktree(&linked, "h4-exec");
    let harness = harness(&repo, accepting_gate(&temp));

    let decision = harness
        .adapter
        .decide(&selection(&repo, None))
        .expect("decision");
    let chosen = decision.selection().expect("a decided checkout");
    assert_eq!(chosen.checkout_root(), linked);
    assert_eq!(chosen.branch(), "h4-exec");
    assert!(chosen.isolated());
    assert_eq!(chosen.source(), WorkspaceSelectionSource::LinkedWorktree);
    assert!(decision.question().is_none());
    // Nothing was created or written by deciding.
    assert_eq!(git_worktree_paths(&repo.root).len(), 2);
}

#[test]
fn a_progress_ledger_worktree_line_is_honored_without_asking_again() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("recorded");
    repo.linked_worktree(&linked, "h4-exec");
    repo.record_progress_worktree(&linked);
    let harness = harness(&repo, accepting_gate(&temp));

    let decision = harness
        .adapter
        .decide(&selection(&repo, None))
        .expect("decision");
    let chosen = decision.selection().expect("a decided checkout");
    assert_eq!(chosen.checkout_root(), linked);
    assert_eq!(chosen.source(), WorkspaceSelectionSource::ProgressLedger);
    assert!(chosen.isolated());
}

#[test]
fn an_in_place_progress_ledger_record_is_honored_without_asking_again() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    git(&repo.root, &["switch", "-c", "h4-exec"]);
    let root = repo.path();
    repo.record_progress_worktree(&root);
    let harness = harness(&repo, accepting_gate(&temp));

    let decision = harness
        .adapter
        .decide(&selection(&repo, None))
        .expect("decision");
    let chosen = decision.selection().expect("a decided checkout");
    assert_eq!(chosen.checkout_root(), root);
    assert!(!chosen.isolated());
    assert_eq!(chosen.source(), WorkspaceSelectionSource::ProgressLedger);
}

#[test]
fn a_recorded_conversation_answer_is_honored_without_asking_again() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("answered");
    repo.linked_worktree(&linked, "h4-exec");
    let harness = harness(&repo, accepting_gate(&temp));

    let decision = harness
        .adapter
        .decide(&selection(
            &repo,
            Some(WorkspaceSelectionAnswer::Isolated {
                checkout_root: linked.clone(),
            }),
        ))
        .expect("decision");
    let chosen = decision.selection().expect("a decided checkout");
    assert_eq!(chosen.checkout_root(), linked);
    assert_eq!(
        chosen.source(),
        WorkspaceSelectionSource::ConversationAnswer
    );
}

#[test]
fn only_an_undecided_state_asks_the_human() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let harness = harness(&repo, accepting_gate(&temp));

    let decision = harness
        .adapter
        .decide(&selection(&repo, None))
        .expect("decision");
    let question = decision.question().expect("a question");
    assert_eq!(question.reason(), &WorkspaceUndecided::NoRecord);
    assert_eq!(question.original_checkout_root(), repo.path());
    assert_eq!(question.base_branch(), "main");
    assert_eq!(question.approved_branch(), "h4-exec");
    assert!(decision.selection().is_none());
    // Asking created nothing.
    assert_eq!(git_worktrees(&repo.root), vec![repo.path()]);
    assert_eq!(git_branches(&repo.root), vec!["main".to_owned()]);
}

#[test]
fn a_recorded_worktree_that_vanished_asks_instead_of_guessing() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let missing = repo.sibling("gone");
    repo.record_progress_worktree(&missing);
    let harness = harness(&repo, accepting_gate(&temp));

    let decision = harness
        .adapter
        .decide(&selection(&repo, None))
        .expect("decision");
    match decision.question().expect("a question").reason() {
        WorkspaceUndecided::RecordedWorktreeMissing { path } => assert_eq!(path, &missing),
        other => panic!("unexpected reason {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 2. Start verification
// ---------------------------------------------------------------------------

#[test]
fn an_original_checkout_left_dirty_never_blocks_the_selected_clean_checkout() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("selected");
    repo.linked_worktree(&linked, "h4-exec");
    let harness = harness(&repo, accepting_gate(&temp));

    // Dirt in the original checkout, which is deliberately *not* the selection.
    repo.write("original-only.txt", "uncommitted\n");
    repo.write("README.md", "edited in the original\n");
    let original_status = git_status(&repo.root);
    let original_head = git_head(&repo.root);

    let state = harness
        .adapter
        .start_check(project(), &linked)
        .expect("the selected checkout is clean");
    assert_eq!(state.canonical_checkout_root(), linked);
    assert_eq!(state.branch(), "h4-exec");
    assert_eq!(state.base_branch(), "main");
    assert!(state.worktree_clean());
    assert!(state.index_clean());
    assert!(state.is_startable());
    assert!(state.head().is_some());
    assert!(state.baseline().is_none());

    // The original checkout's dirt and HEAD are untouched.
    assert_eq!(git_status(&repo.root), original_status);
    assert_eq!(git_head(&repo.root), original_head);
}

#[test]
fn a_dirty_selected_checkout_refuses_the_start() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("dirty-selected");
    repo.linked_worktree(&linked, "h4-exec");
    let harness = harness(&repo, accepting_gate(&temp));

    std::fs::write(Path::new(&linked).join("stray.txt"), "dirty\n").expect("dirty file");

    let state = harness
        .adapter
        .start_check(project(), &linked)
        .expect("the state is read");
    assert!(!state.worktree_clean());
    assert!(state.index_clean());
    assert!(!state.is_startable());
}

#[test]
fn a_staged_change_in_the_selected_checkout_refuses_the_start() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("staged-selected");
    repo.linked_worktree(&linked, "h4-exec");
    let harness = harness(&repo, accepting_gate(&temp));

    std::fs::write(Path::new(&linked).join("README.md"), "staged\n").expect("edit");
    git(Path::new(&linked), &["add", "--", "README.md"]);

    let state = harness
        .adapter
        .start_check(project(), &linked)
        .expect("the state is read");
    assert!(!state.index_clean());
    assert!(!state.is_startable());
}

#[test]
fn a_start_is_refused_when_the_approved_plan_version_is_not_there() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("plan-changed");
    repo.linked_worktree(&linked, "h4-exec");
    let harness = harness(&repo, accepting_gate(&temp));

    std::fs::write(
        Path::new(&linked).join("docs/sdd/plans/plan.md"),
        "# Plan\n\n## Task 1: rewritten\n",
    )
    .expect("rewrite plan");

    let error = harness
        .adapter
        .start_check(project(), &linked)
        .expect_err("the plan changed");
    assert_eq!(error.failure_code(), Some(FailureCode::PlanChanged));
}

#[test]
fn a_start_is_refused_when_the_approved_spec_version_is_not_there() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("spec-changed");
    repo.linked_worktree(&linked, "h4-exec");
    let harness = harness(&repo, accepting_gate(&temp));

    std::fs::write(
        Path::new(&linked).join("docs/sdd/specs/spec.md"),
        b"# Spec v2\n",
    )
    .expect("rewrite spec");

    let error = harness
        .adapter
        .start_check(project(), &linked)
        .expect_err("the spec changed");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::WorkspaceMismatch { .. }
        }
    ));
}

#[test]
fn a_start_is_refused_when_the_checkout_is_on_another_branch() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("wrong-branch");
    repo.linked_worktree(&linked, "not-approved");
    let harness = harness(&repo, accepting_gate(&temp));

    let error = harness
        .adapter
        .start_check(project(), &linked)
        .expect_err("the branch differs");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRejected {
            reason: ApprovalRejection::WorkspaceMismatch { .. }
        }
    ));
}

// ---------------------------------------------------------------------------
// 3. Isolation
// ---------------------------------------------------------------------------

#[test]
fn an_isolated_preparation_creates_one_real_worktree_and_branch() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("new-isolated");
    let mut harness = harness(&repo, accepting_gate(&temp));

    let state = harness
        .adapter
        .prepare(&WorkspacePreparation::isolated(
            project(),
            linked.clone(),
            "main",
            "h4-exec",
        ))
        .expect("isolation succeeds");

    assert_eq!(state.canonical_checkout_root(), linked);
    assert_eq!(state.branch(), "h4-exec");
    assert!(state.is_startable());
    let mut expected_worktrees = vec![repo.path(), linked.clone()];
    expected_worktrees.sort();
    assert_eq!(git_worktrees(&repo.root), expected_worktrees);
    let branches = git_branches(&repo.root);
    assert!(branches.contains(&"main".to_owned()));
    assert!(branches.contains(&"h4-exec".to_owned()));
    // The baseline is the full SHA the prepared branch actually points at. The
    // fixture had no `.gitignore`, so the one permitted preparation commit ran in
    // the new worktree and the baseline is after it.
    let recorded = harness
        .adapter
        .baseline(project())
        .expect("baseline read")
        .expect("baseline recorded");
    assert_eq!(recorded.as_str(), git_head(Path::new(&linked)));
    let changed = git(
        Path::new(&linked),
        &["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
    );
    assert_eq!(changed.lines().collect::<Vec<_>>(), vec![".gitignore"]);
    // The original checkout's branch never moved.
    assert_eq!(git_branches(&repo.root).len(), 2);
}

#[test]
fn a_failing_worktree_add_creates_zero_worktrees_and_zero_branches() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));

    // An unwritable parent makes `git worktree add` fail for real.
    let blocked = repo.sibling("blocked");
    std::fs::create_dir_all(&blocked).expect("blocked parent");
    let target = Path::new(&blocked).join("isolated");
    make_unwritable(Path::new(&blocked));

    let worktrees_before = git_worktrees(&repo.root);
    let branches_before = git_branches(&repo.root);
    let refs_before = git_refs(&repo.root);
    let head_before = git_head(&repo.root);
    let status_before = git_status(&repo.root);

    let error = harness
        .adapter
        .prepare(&WorkspacePreparation::isolated(
            project(),
            target.to_string_lossy().into_owned(),
            "main",
            "h4-exec",
        ))
        .expect_err("isolation fails");
    make_writable(Path::new(&blocked));

    // A typed isolation failure, never an in-place success.
    match error {
        SddExecutionError::Unavailable { feature, .. } => {
            assert!(
                feature.starts_with(ISOLATION_FEATURE),
                "unexpected feature {feature}"
            );
        }
        other => panic!("isolation reported {other:?} instead of a typed failure"),
    }
    assert_eq!(git_worktrees(&repo.root), worktrees_before);
    assert_eq!(git_branches(&repo.root), branches_before);
    assert_eq!(git_refs(&repo.root), refs_before);
    assert_eq!(git_head(&repo.root), head_before);
    assert_eq!(git_status(&repo.root), status_before);
    assert!(!target.exists());
    assert!(
        harness
            .adapter
            .baseline(project())
            .expect("baseline")
            .is_none(),
        "a failed isolation must not fix a baseline"
    );
}

#[test]
fn an_existing_target_path_refuses_isolation_and_never_falls_back_to_in_place() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));
    let target = repo.sibling("already-there");
    std::fs::create_dir_all(&target).expect("existing target");
    std::fs::write(Path::new(&target).join("keep.txt"), "keep\n").expect("keep file");

    let branches_before = git_branches(&repo.root);
    let error = harness
        .adapter
        .prepare(&WorkspacePreparation::isolated(
            project(),
            target,
            "main",
            "h4-exec",
        ))
        .expect_err("exception");
    assert_eq!(
        error.failure_code(),
        Some(FailureCode::Unavailable),
        "{error:?}"
    );
    assert_eq!(git_branches(&repo.root), branches_before);
    assert_eq!(git_worktrees(&repo.root), vec![repo.path()]);
    assert!(
        harness
            .adapter
            .baseline(project())
            .expect("baseline")
            .is_none(),
        "no baseline after an isolation failure"
    );
}

#[test]
fn an_isolation_failure_never_reports_an_in_place_state() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));
    let target = repo.sibling("refused");
    std::fs::create_dir_all(&target).expect("existing target");

    let result = harness.adapter.prepare(&WorkspacePreparation::isolated(
        project(),
        target.clone(),
        "main",
        "h4-exec",
    ));
    match result {
        Ok(state) => panic!(
            "an isolation failure became state at {}",
            state.canonical_checkout_root()
        ),
        Err(error) => assert_eq!(error.failure_code(), Some(FailureCode::Unavailable)),
    }
    // `.sdd/` is still not ignored, so nothing was "prepared" either.
    assert!(!repo.root.join(".gitignore").exists());
}

// ---------------------------------------------------------------------------
// 4. Preparation commit and baseline
// ---------------------------------------------------------------------------

#[test]
fn the_gitignore_preparation_commit_touches_only_gitignore_and_fixes_the_baseline_after_it() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));
    repo.switch_to_approved_branch();
    // The existing SDD scratch directory is the only untracked content.
    std::fs::create_dir_all(repo.root.join(".sdd")).expect(".sdd");
    std::fs::write(
        repo.root.join(".sdd/progress.md"),
        "Worktree: created (undecided)\n",
    )
    .expect("progress");

    let head_before = git_head(&repo.root);
    let status_before = git_status(&repo.root);
    assert!(
        status_before.contains(".sdd/"),
        "the fixture must start with untracked .sdd content"
    );

    let state = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            repo.path(),
            "main",
            true,
        ))
        .expect("in-place preparation");

    // Exactly one new commit, and it changed only `.gitignore`.
    let head_after = git_head(&repo.root);
    assert_ne!(head_after, head_before);
    let changed = git(
        &repo.root,
        &["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
    );
    assert_eq!(changed.lines().collect::<Vec<_>>(), vec![".gitignore"]);
    let ignored = std::fs::read_to_string(repo.root.join(".gitignore")).expect(".gitignore");
    assert_eq!(ignored, ".sdd/\n");

    // The baseline is the preparation commit itself, not the pre-preparation HEAD
    // and not the commit before it.
    assert_eq!(
        state.baseline().expect("baseline").as_str(),
        head_after,
        "the baseline must be the full SHA after preparation"
    );
    assert_eq!(
        harness
            .adapter
            .baseline(project())
            .expect("baseline")
            .expect("recorded")
            .as_str(),
        head_after
    );
    // The `.sdd/` scratch is now ignored, so the checkout is clean.
    assert!(state.is_startable());
    assert_eq!(git_status(&repo.root), "");
}

#[test]
fn an_existing_sdd_ignore_line_creates_no_preparation_commit() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));
    repo.switch_to_approved_branch();
    repo.write(".gitignore", "target/\n.sdd/\n");
    git(&repo.root, &["add", "--", ".gitignore"]);
    git(&repo.root, &["commit", "-m", "ignore .sdd"]);
    std::fs::create_dir_all(repo.root.join(".sdd")).expect(".sdd");
    std::fs::write(repo.root.join(".sdd/progress.md"), "Worktree: (none)\n").expect("progress");
    let head_before = git_head(&repo.root);

    let state = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            repo.path(),
            "main",
            true,
        ))
        .expect("in-place preparation");

    assert_eq!(git_head(&repo.root), head_before);
    assert_eq!(state.baseline().expect("baseline").as_str(), head_before);
    assert!(state.is_startable());
}

#[test]
fn an_unapproved_preparation_commit_refuses_instead_of_committing() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));
    repo.switch_to_approved_branch();
    std::fs::create_dir_all(repo.root.join(".sdd")).expect(".sdd");
    std::fs::write(repo.root.join(".sdd/progress.md"), "Worktree: (none)\n").expect("progress");
    let head_before = git_head(&repo.root);

    let error = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            repo.path(),
            "main",
            false,
        ))
        .expect_err("the preparation commit was not approved");
    assert!(matches!(
        error,
        SddExecutionError::ApprovalRequired {
            reason: ApprovalRequirement::StartApproval,
            ..
        }
    ));
    assert_eq!(git_head(&repo.root), head_before);
    assert!(!repo.root.join(".gitignore").exists());
    assert!(
        harness
            .adapter
            .baseline(project())
            .expect("baseline")
            .is_none()
    );
}

#[test]
fn a_preparation_commit_refused_by_the_document_gate_creates_no_commit() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, refusing_gate(&temp));
    repo.switch_to_approved_branch();
    std::fs::create_dir_all(repo.root.join(".sdd")).expect(".sdd");
    std::fs::write(repo.root.join(".sdd/progress.md"), "Worktree: (none)\n").expect("progress");
    let head_before = git_head(&repo.root);

    let error = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            repo.path(),
            "main",
            true,
        ))
        .expect_err("the gate refused the staged document");
    match error {
        SddExecutionError::Unavailable { feature, .. } => {
            assert!(feature.starts_with(PREPARATION_COMMIT_FEATURE), "{feature}");
        }
        other => panic!("the gate refusal became {other:?}"),
    }
    // No commit and no baseline: the gate ran before the commit.
    assert_eq!(git_head(&repo.root), head_before);
    assert!(
        harness
            .adapter
            .baseline(project())
            .expect("baseline")
            .is_none()
    );
    let count = git(&repo.root, &["rev-list", "--count", "HEAD"]);
    assert_eq!(count.trim(), "1");

    // The refusal leaves the written `.gitignore` and its staged entry behind,
    // because unstaging would discard a change. A second attempt therefore
    // refuses with a conflict and never silently retries or resets.
    assert_eq!(
        std::fs::read_to_string(repo.root.join(".gitignore")).expect(".gitignore stays"),
        ".sdd/\n"
    );
    let retry = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            repo.path(),
            "main",
            true,
        ))
        .expect_err("a leftover staged change refuses the next preparation");
    assert!(
        matches!(
            retry,
            SddExecutionError::Conflict {
                reason: ConflictReason::DirtyIndex,
                ..
            }
        ),
        "{retry:?}"
    );
    assert_eq!(git_head(&repo.root), head_before);
    // Nothing was reset: the staged entry is still there for a human to resolve.
    assert!(!git_status(&repo.root).is_empty());
}

#[test]
fn a_different_baseline_is_refused_on_resume_and_never_overwrites() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));
    repo.switch_to_approved_branch();
    repo.write(".gitignore", ".sdd/\n");
    git(&repo.root, &["add", "--", ".gitignore"]);
    git(&repo.root, &["commit", "-m", "ignore .sdd"]);
    let first = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            repo.path(),
            "main",
            true,
        ))
        .expect("first preparation")
        .baseline()
        .expect("baseline")
        .clone();

    // Advance HEAD, then resume: the recorded baseline must not move.
    repo.write("README.md", "second commit\n");
    git(&repo.root, &["add", "--", "README.md"]);
    git(&repo.root, &["commit", "-m", "second"]);
    let error = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            repo.path(),
            "main",
            true,
        ))
        .expect_err("a resume must not replace the baseline");
    assert!(matches!(
        error,
        SddExecutionError::Conflict {
            reason: ConflictReason::ConcurrentEdit,
            ..
        }
    ));
    assert_eq!(
        harness
            .adapter
            .baseline(project())
            .expect("baseline")
            .expect("recorded"),
        first
    );
}

#[test]
fn a_preparation_with_unrelated_dirt_refuses_without_touching_it() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));
    repo.switch_to_approved_branch();
    repo.write("unrelated.txt", "must survive\n");
    let head_before = git_head(&repo.root);

    let error = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            repo.path(),
            "main",
            true,
        ))
        .expect_err("unrelated dirt is refused");
    assert!(matches!(
        error,
        SddExecutionError::Conflict {
            reason: ConflictReason::DirtyIndex,
            ..
        }
    ));
    assert_eq!(git_head(&repo.root), head_before);
    assert_eq!(
        std::fs::read_to_string(repo.root.join("unrelated.txt")).expect("survives"),
        "must survive\n"
    );
    assert!(!repo.root.join(".gitignore").exists());
}

// ---------------------------------------------------------------------------
// 5. Read-only state
// ---------------------------------------------------------------------------

#[test]
fn state_and_start_check_write_nothing_to_git() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("observed");
    repo.linked_worktree(&linked, "h4-exec");
    let harness = harness(&repo, accepting_gate(&temp));

    let original_status = git_status(&repo.root);
    let original_refs = git_refs(&repo.root);
    let original_worktrees = git_worktrees(&repo.root);
    let linked_status = git_status(Path::new(&linked));
    let linked_refs = git_refs(Path::new(&linked));
    let index_digest = file_digest(&Path::new(&linked).join(".git"));
    let spawned_before = harness.spawns.load(Ordering::SeqCst);

    for _ in 0..2 {
        let watched = harness
            .adapter
            .state(project(), &linked)
            .expect("port state");
        assert_eq!(watched.branch(), "h4-exec");
        let checked = harness
            .adapter
            .start_check(project(), &linked)
            .expect("start check");
        assert!(checked.is_startable());
    }

    // Git was read by spawning real processes, and nothing changed.
    assert!(harness.spawns.load(Ordering::SeqCst) > spawned_before);
    assert_eq!(git_status(&repo.root), original_status);
    assert_eq!(git_refs(&repo.root), original_refs);
    assert_eq!(git_worktrees(&repo.root), original_worktrees);
    assert_eq!(git_status(Path::new(&linked)), linked_status);
    assert_eq!(git_refs(Path::new(&linked)), linked_refs);
    assert_eq!(
        file_digest(&Path::new(&linked).join(".git")),
        index_digest,
        "observation must not rewrite the index or any Git bookkeeping"
    );
}

// ---------------------------------------------------------------------------
// 6. No writes outside the selected checkout
// ---------------------------------------------------------------------------

#[test]
fn a_second_repository_receives_zero_writes() {
    let repo = Repo::new();
    let other = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));

    let selected = repo.path();
    git(&repo.root, &["switch", "-c", "h4-exec"]);
    repo.record_progress_worktree(&selected);

    let other_root = other.path();
    let other_snapshot = RepoSnapshot::capture(&other_root);

    // Decide, observe, and prepare a real in-place start in the selected repo.
    std::fs::create_dir_all(repo.root.join(".sdd")).expect(".sdd");
    let decision = harness
        .adapter
        .decide(&selection(&repo, None))
        .expect("decide");
    let chosen = decision.selection().expect("a decided checkout");
    assert_eq!(chosen.checkout_root(), selected);
    let _ = harness.adapter.state(project(), &selected).expect("state");
    let _ = harness
        .adapter
        .start_check(project(), &selected)
        .expect("check");
    let prepared = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            selected.clone(),
            "main",
            true,
        ))
        .expect("in-place preparation");
    assert_eq!(prepared.branch(), "h4-exec");
    assert!(prepared.baseline().is_some());

    other_snapshot.assert_unchanged(&other_root);
    // The other repository is not even a worktree of the selected one.
    assert_eq!(git_worktrees(&other.root), vec![other_root]);
    assert!(
        harness
            .adapter
            .baseline(other_project())
            .expect("baseline")
            .is_none()
    );
}

#[test]
fn an_already_linked_worktree_is_prepared_in_place_without_creating_another() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let linked = repo.sibling("reused");
    repo.linked_worktree(&linked, "h4-exec");
    repo.record_progress_worktree(&linked);
    std::fs::create_dir_all(Path::new(&linked).join(".sdd")).expect(".sdd");
    let mut harness = harness(&repo, accepting_gate(&temp));

    let decision = harness
        .adapter
        .decide(&selection(&repo, None))
        .expect("decision");
    let chosen = decision
        .selection()
        .expect("the recorded worktree is honored");
    assert_eq!(chosen.checkout_root(), linked);

    let worktrees_before = git_worktrees(&repo.root);
    let branches_before = git_branches(&repo.root);
    let original_head_before = git_head(&repo.root);
    let state = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            chosen.checkout_root(),
            "main",
            true,
        ))
        .expect("the reused worktree is prepared in place");

    // Preparation used the existing worktree; nothing new was created.
    assert_eq!(git_worktrees(&repo.root), worktrees_before);
    assert_eq!(git_branches(&repo.root), branches_before);
    assert_eq!(state.canonical_checkout_root(), linked);
    assert_eq!(state.branch(), "h4-exec");
    assert!(state.is_startable());
    assert_eq!(
        state.baseline().expect("baseline").as_str(),
        git_head(Path::new(&linked))
    );
    // The original checkout's branch never moved.
    assert_eq!(git_head(&repo.root), original_head_before);
}

#[test]
fn an_in_place_preparation_refuses_another_repository() {
    let repo = Repo::new();
    let other = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));
    repo.switch_to_approved_branch();

    let error = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            other.path(),
            "main",
            true,
        ))
        .expect_err("another repository is not the approved checkout");
    assert!(
        matches!(error, SddExecutionError::InvalidValue { .. }),
        "{error:?}"
    );
    assert_eq!(git_branches(&other.root), vec!["main".to_owned()]);
}

#[test]
fn an_unapproved_project_has_no_expectation_and_asks_for_approval() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let harness = harness(&repo, accepting_gate(&temp));

    // Both `state()` and `start_check()` need the approved facts, because a
    // `WorkspaceState` names an approved base branch; the adapter will not
    // invent one. Before approval, `decide()` is the only read.
    for result in [
        harness.adapter.state(other_project(), &repo.path()),
        harness.adapter.start_check(other_project(), &repo.path()),
    ] {
        let error = result.expect_err("no approved facts for this project");
        assert!(
            matches!(
                error,
                SddExecutionError::ApprovalRequired {
                    reason: ApprovalRequirement::StartApproval,
                    ..
                }
            ),
            "{error:?}"
        );
    }
    assert!(harness.adapter.expectation(other_project()).is_none());
    assert_eq!(git_worktrees(&repo.root), vec![repo.path()]);
}

#[test]
fn a_missing_gate_makes_the_preparation_commit_explicitly_unavailable() {
    let repo = Repo::new();
    let temp = TempDir::new().expect("temp");
    let mut harness = harness(&repo, accepting_gate(&temp));
    // Re-register the same approved facts without a gate.
    let ungated = WorkspaceExpectation::new(
        project(),
        repo.path(),
        "h4-exec",
        "main",
        "execution:fixture",
        "execution_approval:fixture",
        1,
        repo.documents(),
    )
    .expect("expectation");
    harness.adapter.expect(ungated);
    harness.expectation = harness.adapter.expectation(project()).expect("registered");
    git(&repo.root, &["switch", "-c", "h4-exec"]);
    std::fs::create_dir_all(repo.root.join(".sdd")).expect(".sdd");
    std::fs::write(repo.root.join(".sdd/progress.md"), "Worktree: (none)\n").expect("progress");
    let head_before = git_head(&repo.root);

    let error = harness
        .adapter
        .prepare(&WorkspacePreparation::in_place(
            project(),
            repo.path(),
            "main",
            true,
        ))
        .expect_err("no gate is bound");
    match error {
        SddExecutionError::Unavailable { feature, .. } => {
            assert!(feature.starts_with(PREPARATION_COMMIT_FEATURE), "{feature}");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(git_head(&repo.root), head_before);
    // The missing gate is detected before anything is written to the checkout.
    assert!(
        !repo.root.join(".gitignore").exists(),
        "the refusal must precede the .gitignore write"
    );
}

#[test]
fn a_document_path_outside_the_project_is_refused_at_construction() {
    for path in [
        "../outside/spec.md",
        "/absolute/spec.md",
        "docs/../escape.md",
    ] {
        let error = ApprovedDocument::spec(path, b"# Spec\n")
            .expect_err("an escaping document path must be refused");
        assert!(
            matches!(error, SddExecutionError::InvalidValue { .. }),
            "{path}: {error:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn git_worktrees(root: &Path) -> Vec<String> {
    let mut paths = git_worktree_paths(root);
    paths.sort();
    paths
}

#[cfg(unix)]
fn make_unwritable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o555);
    std::fs::set_permissions(path, permissions).expect("chmod");
}

#[cfg(unix)]
fn make_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("chmod");
}

fn file_digest(root: &Path) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    let mut entries: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(path) = entries.pop() {
        let metadata = std::fs::symlink_metadata(&path).expect("metadata");
        if metadata.is_dir() {
            bytes.extend_from_slice(path.to_string_lossy().as_bytes());
            let mut children: Vec<PathBuf> = std::fs::read_dir(&path)
                .expect("read dir")
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .collect();
            children.sort();
            entries.extend(children);
        } else {
            bytes.extend_from_slice(path.to_string_lossy().as_bytes());
            bytes.extend_from_slice(&std::fs::read(&path).expect("file bytes"));
        }
    }
    Sha256Digest::sha256(&bytes).as_str().to_owned()
}

/// Exact snapshot of one repository, including every file under its `.git`.
struct RepoSnapshot {
    files: std::collections::BTreeMap<String, String>,
    refs: String,
    head: String,
    status: String,
}

impl RepoSnapshot {
    fn capture(root: &str) -> Self {
        let root = Path::new(root);
        let mut files = std::collections::BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let metadata = std::fs::symlink_metadata(&path).expect("metadata");
            if metadata.is_dir() {
                let mut children: Vec<PathBuf> = std::fs::read_dir(&path)
                    .expect("read dir")
                    .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                    .collect();
                children.sort();
                pending.extend(children);
            } else {
                files.insert(path.to_string_lossy().into_owned(), file_digest(&path));
            }
        }
        Self {
            files,
            refs: git_refs(root),
            head: git_head(root),
            status: git_status(root),
        }
    }

    fn assert_unchanged(&self, root: &str) {
        let after = Self::capture(root);
        assert_eq!(after.refs, self.refs, "the other repository's refs changed");
        assert_eq!(after.head, self.head, "the other repository's HEAD changed");
        assert_eq!(
            after.status, self.status,
            "the other repository's worktree changed"
        );
        assert_eq!(
            after.files, self.files,
            "the other repository received a file write"
        );
    }
}
