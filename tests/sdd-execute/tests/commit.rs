//! Task 17: the host commit journal and Task finalization.
//!
//! Every case uses a **real** temporary Git repository (`git init`, real
//! commits, real `core.hooksPath`, real hook scripts, and the common
//! staged-document validation installed as a real repository hook), a real
//! SQLite store in a temporary application-data root, and the real host Git
//! boundary. Git is never mocked: the only test doubles are fault injectors that
//! make one chosen durable write fail or one boundary step report an unknown
//! result, and they wrap the real implementations.
//!
//! No network, provider, credential, Keychain item, model request, or GUI is
//! used. Nothing is pushed, merged, rebased, amended, reset, or cleaned.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use herness_core::{
    AbsolutePath, HostGitBoundary, HostGitGate, ProcessSupervisor, ProjectId,
    RecordingHostGitAudit, SystemArgvLauncher, Timestamp,
};
use herness_desktop::sdd_execute::barrier::{
    HostCommitCompletion, HtmlBarrierCompletion, TaskBarrierGate, VerifiedDocumentSource,
    VerifiedDocuments,
};
use herness_desktop::sdd_execute::{
    ApprovedCommitIdentity, DesktopHostCommit, GitCheckoutObserver, HostGitCommitBoundary,
    TaskCommitExpectation,
};
use herness_sdd_execute::barrier::{BarrierHold, BarrierReport};
use herness_sdd_execute::{
    Baseline, ChangedPath, ChildStatus, CommitAuthorization, CommitObservation,
    CommitObservationPort, CommitPolicy, CommitRecovery, CommitRequestId, CommitSha, CommitTarget,
    ControlRequestId, CoordinatorOutcome, CoordinatorPorts, CoordinatorRequest,
    DispatchJournalEntry, DispatchRequestId, DurableExecutionStorePort, ExecutionId,
    ExecutionRevision, ExecutionSnapshot, ExecutionStorePort, FinalizePorts, FinalizeStop,
    GitCommitOutcome, GitJournalEntry, GitJournalState, GitRejection, GitUnknownReason,
    HostGitPort, HtmlSyncReason, HumanAction, LaunchRefusal, ObservationRequest, ObservedPath,
    ProgressJournalEntry, ProgressJournalId, SddExecutionError, Sha256Digest, StopReason,
    StoredExecution, TargetOrigin, TargetRefusal, TaskCommitRequest, TaskCompletion,
    TaskCompletionPort, TaskCompletionRequest, TaskCoordinator, TaskFinalizeOutcome, TaskLaunch,
    TaskLaunchPort, TaskRef, VerifiedPath, commit_request_id, finalize_task, select_targets,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::budget::BudgetPolicy;
use herness_supervision::{EvidenceId, SupervisionId};
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Real repository
// ---------------------------------------------------------------------------

const BRANCH: &str = "h4-commit";

struct Repo {
    _temp: TempDir,
    root: PathBuf,
}

impl Repo {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = fs::canonicalize(temp.path()).expect("canonical temp root");
        run_git(&root, &["init", "-q", "-b", BRANCH]);
        run_git(&root, &["config", "user.name", "Host Test"]);
        run_git(&root, &["config", "user.email", "host@example.invalid"]);
        run_git(&root, &["config", "core.hooksPath", ".git/hooks"]);
        fs::create_dir_all(root.join("docs/adr")).expect("docs");
        fs::write(root.join("README.md"), "initial\n").expect("seed");
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

    fn tree(&self) -> String {
        git_stdout(&self.root, &["rev-parse", "HEAD^{tree}"])
    }

    fn parent(&self) -> String {
        git_stdout(&self.root, &["rev-parse", "HEAD^{commit}^"])
    }

    fn commit_count(&self) -> usize {
        git_stdout(&self.root, &["rev-list", "--count", "HEAD"])
            .parse()
            .expect("count")
    }

    fn message(&self) -> String {
        git_stdout(&self.root, &["log", "-1", "--pretty=%B"])
    }

    fn changed_paths(&self) -> Vec<String> {
        git_stdout(
            &self.root,
            &["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
        )
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
    }

    fn tracked_paths(&self) -> Vec<String> {
        git_stdout(&self.root, &["ls-tree", "-r", "--name-only", "HEAD"])
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn write(&self, relative: &str, contents: &str) -> Vec<u8> {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent");
        }
        fs::write(&path, contents).expect("write");
        contents.as_bytes().to_vec()
    }

    fn is_staged(&self, relative: &str) -> bool {
        git_stdout(&self.root, &["diff", "--cached", "--name-only"])
            .lines()
            .any(|line| line == relative)
    }

    fn install_hook(&self, script: &str) {
        let hooks = self.root.join(".git").join("hooks");
        fs::create_dir_all(&hooks).expect("hooks");
        let hook = hooks.join("pre-commit");
        let mut file = fs::File::create(&hook).expect("hook");
        file.write_all(script.as_bytes()).expect("hook bytes");
        drop(file);
        make_executable(&hook);
    }

    fn install_gate(&self, script: &str) -> HostGitGate {
        // The gate lives inside the Git directory, so it is never an untracked
        // path the commit-target scan would have to reason about.
        let git_dir = self.root.join(".git");
        let path = git_dir.join("herness-gate.sh");
        let mut file = fs::File::create(&path).expect("gate");
        file.write_all(script.as_bytes()).expect("gate bytes");
        drop(file);
        make_executable(&path);
        let program = AbsolutePath::new(path.to_string_lossy().into_owned()).expect("absolute");
        HostGitGate::new(program, Vec::new(), None).expect("gate")
    }

    /// The common staged-document validation, installed as a real repository
    /// hook exactly like the shared HTML gate the approved commit runs.
    fn install_common_staged_html_gate(&self) -> HostGitGate {
        self.install_hook(
            "#!/bin/sh\n\
             for path in $(git diff --cached --name-only); do\n\
               case \"$path\" in\n\
                 *.html)\n\
                   head -c 15 \"$path\" | grep -q '<!doctype html>' || {\n\
                     echo \"staged HTML is not a complete document: $path\" >&2\n\
                     exit 4\n\
                   }\n\
                   ;;\n\
               esac\n\
             done\n\
             exit 0\n",
        );
        self.install_gate("#!/bin/sh\nexit 0\n")
    }

    fn accepting_hook(&self) {
        self.install_hook("#!/bin/sh\nexit 0\n");
    }
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("permissions");
}

fn run_git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(root)
        .args(args)
        .status()
        .expect("git starts");
    assert!(status.success(), "git {args:?} failed with {status}");
}

fn run_git_without_hooks(root: &Path, args: &[&str]) {
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
// Identities and fixture values
// ---------------------------------------------------------------------------

fn project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("a2000000-0000-4000-8000-000000000001").unwrap())
}

fn execution(project: ProjectId) -> ExecutionId {
    ExecutionId::from_parts(
        project,
        Uuid::parse_str("b2000000-0000-4000-8000-000000000001").unwrap(),
    )
}

fn task_ref(project: ProjectId, number: u32) -> TaskRef {
    TaskRef::new(
        herness_sdd_execute::TaskStableId::from_parts(
            project,
            Uuid::from_u128(0xd200_0000_0000_4000_8000_0000_0000_0000 + u128::from(number)),
        ),
        herness_sdd_execute::TaskNumber::new(number).expect("Task number"),
    )
}

fn evidence(project: ProjectId, local: u128) -> EvidenceId {
    EvidenceId::from_parts(project, Uuid::from_u128(local))
}

const APPROVAL_ID: &str =
    "execution_approval:a2000000-0000-4000-8000-000000000001:c2000000-0000-4000-8000-000000000001";

fn identity(repo: &Repo, project: ProjectId) -> ApprovedCommitIdentity {
    ApprovedCommitIdentity::new(
        project,
        APPROVAL_ID,
        1,
        "execution:b2000000-0000-4000-8000-000000000001",
        repo.root_path(),
        BRANCH,
        herness_core::HostGitActor::new("Host Test", "host@example.invalid").expect("actor"),
    )
    .expect("identity")
}

fn target(path: &str, bytes: &[u8], origin: TargetOrigin) -> CommitTarget {
    CommitTarget::for_bytes(path, bytes, origin).expect("target")
}

fn pre_hook(targets: &[CommitTarget]) -> herness_sdd_execute::PreHookState {
    herness_sdd_execute::PreHookState::new(
        true,
        targets
            .iter()
            .map(|target| target.path().to_owned())
            .collect(),
        None,
        None,
    )
    .expect("pre-hook state")
}

#[allow(clippy::too_many_arguments)]
fn commit_request(
    repo: &Repo,
    project: ProjectId,
    task_number: u32,
    policy: CommitPolicy,
    targets: Vec<CommitTarget>,
    tracked: Vec<VerifiedPath>,
    evidence_ids: Vec<EvidenceId>,
    pre_hook: herness_sdd_execute::PreHookState,
) -> Result<TaskCommitRequest, SddExecutionError> {
    let head = CommitSha::parse(repo.head()).expect("head");
    let base = Baseline::parse(head.as_str()).expect("base");
    TaskCommitRequest::new(
        task_ref(project, task_number),
        execution(project),
        commit_request_id(execution(project), task_ref(project, task_number), &head),
        ExecutionRevision::INITIAL,
        CommitAuthorization::new(true, true).expect("authorization"),
        policy,
        format!("commit Task {task_number}"),
        BRANCH,
        base,
        head,
        None,
        targets,
        tracked,
        evidence_ids,
        pre_hook,
        20,
    )
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    repo: Repo,
    project: ProjectId,
    _data: TempDir,
    store: Store,
}

impl Harness {
    fn new() -> Self {
        let repo = Repo::new();
        let project = project();
        let data = tempfile::tempdir().expect("application data");
        let store = Store::open(StoreConfig::new(data.path()).expect("config")).expect("store");
        Self {
            repo,
            project,
            _data: data,
            store,
        }
    }

    fn boundary(&self) -> HostGitCommitBoundary {
        self.boundary_with_gate(self.repo.install_gate("#!/bin/sh\nexit 0\n"))
    }

    fn boundary_with_gate(&self, gate: HostGitGate) -> HostGitCommitBoundary {
        boundary_for(&self.repo, self.project, gate)
    }

    fn observer(&self) -> GitCheckoutObserver {
        observer_for(&self.repo, self.project)
    }

    fn finalize(
        &mut self,
        request: &TaskCommitRequest,
    ) -> Result<TaskFinalizeOutcome, SddExecutionError> {
        let mut git = self.boundary();
        let mut checkout = self.observer();
        let mut ports = FinalizePorts {
            git: &mut git,
            store: &mut self.store,
            checkout: &mut checkout,
        };
        finalize_task(&mut ports, request)
    }
}

fn boundary_for(repo: &Repo, project: ProjectId, gate: HostGitGate) -> HostGitCommitBoundary {
    let inner = HostGitBoundary::new(
        AbsolutePath::new(git_program()).expect("absolute git"),
        SystemArgvLauncher,
        RecordingHostGitAudit::new(),
        ProcessSupervisor::new(),
    )
    .expect("boundary");
    HostGitCommitBoundary::new(inner, identity(repo, project), gate)
}

fn observer_for(repo: &Repo, project: ProjectId) -> GitCheckoutObserver {
    let runner = herness_desktop::sdd_execute::GitRunner::new(
        AbsolutePath::new(git_program()).expect("absolute git"),
        SystemArgvLauncher,
        ProcessSupervisor::new(),
        project,
    )
    .expect("runner");
    GitCheckoutObserver::new(runner, repo.root_path())
}

fn stored_entry(
    store: &Store,
    project: ProjectId,
    request: &TaskCommitRequest,
) -> Option<GitJournalEntry> {
    ExecutionStorePort::commit_entry(store, project, execution(project), request.request_id())
        .expect("stored")
}

// ---------------------------------------------------------------------------
// Target selection
// ---------------------------------------------------------------------------

#[test]
fn only_the_task_change_and_the_verified_companion_are_committed() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let change = harness
        .repo
        .write("docs/adr/0001-queue.md", "# Queue\n\nUse the queue.\n");
    let companion = harness.repo.write(
        "docs/adr/0001-queue.html",
        "<!doctype html><html><body>Queue</body></html>\n",
    );
    // An unrelated dirty file exists and must never be staged or committed.
    harness.repo.write("notes.txt", "unrelated work\n");

    let targets = vec![
        target("docs/adr/0001-queue.md", &change, TargetOrigin::TaskChange),
        target(
            "docs/adr/0001-queue.html",
            &companion,
            TargetOrigin::HtmlCompanion,
        ),
    ];
    let request = commit_request(
        &harness.repo,
        harness.project,
        1,
        CommitPolicy::Required,
        targets.clone(),
        vec![
            VerifiedPath::present("docs/adr/0001-queue.md", Sha256Digest::sha256(&change))
                .expect("verified"),
        ],
        Vec::new(),
        pre_hook(&targets),
    )
    .expect("request");
    let base = harness.repo.head();
    let count = harness.repo.commit_count();

    let outcome = harness.finalize(&request).expect("finalize");
    let range = outcome.range().expect("a commit range").clone();
    assert_eq!(range.base().as_str(), base);
    assert_eq!(range.head().as_str(), harness.repo.head());
    assert_ne!(harness.repo.head(), base);
    assert_eq!(harness.repo.commit_count(), count + 1);
    assert_eq!(harness.repo.parent(), base);

    // Exactly the two approved paths changed.
    let mut changed = harness.repo.changed_paths();
    changed.sort();
    assert_eq!(
        changed,
        vec![
            "docs/adr/0001-queue.html".to_owned(),
            "docs/adr/0001-queue.md".to_owned()
        ]
    );
    // The unrelated file is still untracked and unstaged.
    assert!(!harness.repo.is_staged("notes.txt"));
    assert!(harness.repo.root.join("notes.txt").exists());
    assert!(
        !harness
            .repo
            .tracked_paths()
            .iter()
            .any(|path| path == "notes.txt"),
        "the unrelated file is never committed"
    );

    // The message carries the subject and the three required trailers.
    let message = harness.repo.message();
    assert!(message.starts_with("Task 1: commit Task 1"), "{message}");
    assert!(
        message.contains(&format!(
            "Herness-Execution: {}",
            execution(harness.project)
        )),
        "{message}"
    );
    assert!(message.contains("Herness-Task: 1"), "{message}");
    assert!(
        message.contains(&format!("Herness-Request: {}", request.request_id())),
        "{message}"
    );

    // The recorded journal names the observed commit, tree, and parent.
    let journal = outcome.journal().expect("a journal").clone();
    match journal.outcome() {
        Some(GitCommitOutcome::Committed {
            commit,
            tree,
            parent,
        }) => {
            assert_eq!(commit.as_str(), harness.repo.head());
            assert_eq!(tree.as_str(), harness.repo.tree());
            assert_eq!(parent.as_str(), base);
        }
        other => panic!("expected a committed outcome, got {other:?}"),
    }
    assert_eq!(journal.state(), GitJournalState::Committed);

    // The journal is durable in the real store and holds the same result.
    let stored = stored_entry(&harness.store, harness.project, &request).expect("recorded entry");
    assert_eq!(stored.state(), GitJournalState::Committed);
    assert_eq!(stored.outcome(), journal.outcome());
}

#[test]
fn an_unrelated_change_outside_the_write_scope_never_becomes_a_target() {
    let change = ChangedPath::for_bytes("docs/adr/0004.md", b"# 4\n").expect("changed");
    let unrelated = ChangedPath::for_bytes("src/main.rs", b"fn main() {}\n").expect("changed");
    assert_eq!(
        select_targets(&[change, unrelated], &["docs/adr".to_owned()], &[]),
        Err(TargetRefusal::Unrelated {
            path: "src/main.rs".to_owned()
        })
    );

    // A deletion inside the scope is refused rather than inferred.
    let deleted = ChangedPath::deleted("docs/adr/0005.md").expect("deleted");
    assert_eq!(
        select_targets(&[deleted], &["docs/adr".to_owned()], &[]),
        Err(TargetRefusal::Deleted {
            path: "docs/adr/0005.md".to_owned()
        })
    );

    // A derived-looking path the barrier did not verify is refused even though
    // it sits under the evidence directory.
    let fake = ChangedPath::for_bytes("docs/sdd/html-evidence/0006.json", b"{\"receipt\":true}\n")
        .expect("changed");
    assert_eq!(
        select_targets(&[fake], &["docs/adr".to_owned()], &[]),
        Err(TargetRefusal::Unrelated {
            path: "docs/sdd/html-evidence/0006.json".to_owned()
        })
    );

    // A verified companion whose bytes moved is refused.
    let verified = target(
        "docs/adr/0007.html",
        b"<!doctype html><html>v1</html>\n",
        TargetOrigin::HtmlCompanion,
    );
    let moved = ChangedPath::for_bytes("docs/adr/0007.html", b"<!doctype html><html>v2</html>\n")
        .expect("changed");
    assert_eq!(
        select_targets(&[moved], &["docs/adr".to_owned()], &[verified]),
        Err(TargetRefusal::UnverifiedDerived {
            path: "docs/adr/0007.html".to_owned()
        })
    );
}

#[test]
fn a_required_task_with_no_target_is_refused_at_construction() {
    let harness = Harness::new();
    let error = commit_request(
        &harness.repo,
        harness.project,
        1,
        CommitPolicy::Required,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        herness_sdd_execute::PreHookState::new(true, Vec::new(), None, None).expect("state"),
    )
    .expect_err("a required Task must stage at least one path");
    assert!(matches!(error, SddExecutionError::InvalidValue { .. }));
}

// ---------------------------------------------------------------------------
// The common staged-HTML gate as a real hook
// ---------------------------------------------------------------------------

#[test]
fn the_common_staged_html_gate_runs_as_a_repository_hook() {
    let mut harness = Harness::new();
    let gate = harness.repo.install_common_staged_html_gate();

    // A complete staged HTML document is accepted by the same hook.
    let change = harness.repo.write("docs/adr/0002-ok.md", "# Ok\n");
    let companion = harness.repo.write(
        "docs/adr/0002-ok.html",
        "<!doctype html><html><body>ok</body></html>\n",
    );
    let targets = vec![
        target("docs/adr/0002-ok.md", &change, TargetOrigin::TaskChange),
        target(
            "docs/adr/0002-ok.html",
            &companion,
            TargetOrigin::HtmlCompanion,
        ),
    ];
    let request = commit_request(
        &harness.repo,
        harness.project,
        2,
        CommitPolicy::Required,
        targets.clone(),
        Vec::new(),
        Vec::new(),
        pre_hook(&targets),
    )
    .expect("request");
    let count = harness.repo.commit_count();
    {
        let mut git = harness.boundary_with_gate(gate);
        let mut checkout = harness.observer();
        let mut ports = FinalizePorts {
            git: &mut git,
            store: &mut harness.store,
            checkout: &mut checkout,
        };
        let outcome = finalize_task(&mut ports, &request).expect("finalize");
        assert!(outcome.range().is_some(), "the gate passed: {outcome:?}");
    }
    assert_eq!(harness.repo.commit_count(), count + 1);

    // A staged HTML document that is not complete is refused by the same hook.
    let broken = harness.repo.write("docs/adr/0003-broken.md", "# Broken\n");
    let broken_companion = harness
        .repo
        .write("docs/adr/0003-broken.html", "<html>truncated\n");
    let targets = vec![
        target("docs/adr/0003-broken.md", &broken, TargetOrigin::TaskChange),
        target(
            "docs/adr/0003-broken.html",
            &broken_companion,
            TargetOrigin::HtmlCompanion,
        ),
    ];
    let request = commit_request(
        &harness.repo,
        harness.project,
        3,
        CommitPolicy::Required,
        targets.clone(),
        Vec::new(),
        Vec::new(),
        pre_hook(&targets),
    )
    .expect("request");
    let head = harness.repo.head();
    let count = harness.repo.commit_count();
    let outcome = harness.finalize(&request).expect("finalize");
    match outcome {
        TaskFinalizeOutcome::Held {
            stop: FinalizeStop::Rejected(GitRejection::HookFailed),
            ..
        } => {}
        other => panic!("the common gate must refuse, got {other:?}"),
    }
    assert_eq!(harness.repo.head(), head, "no commit is created");
    assert_eq!(harness.repo.commit_count(), count);
    // The staged index is left for the human: nothing is reset or cleaned.
    assert!(harness.repo.is_staged("docs/adr/0003-broken.html"));
    assert_eq!(
        FinalizeStop::Rejected(GitRejection::HookFailed)
            .stop()
            .expect("stop")
            .required_action(),
        Some(HumanAction::ResolveHumanDecision)
    );
}

// ---------------------------------------------------------------------------
// required vs no_change
// ---------------------------------------------------------------------------

#[test]
fn a_no_change_task_records_evidence_and_creates_no_commit() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let tracked = harness.repo.write("docs/adr/0008.md", "# Stable\n");
    let request = commit_request(
        &harness.repo,
        harness.project,
        8,
        CommitPolicy::NoChange,
        Vec::new(),
        vec![
            VerifiedPath::present("docs/adr/0008.md", Sha256Digest::sha256(&tracked))
                .expect("verified"),
        ],
        vec![evidence(harness.project, 0x8001)],
        herness_sdd_execute::PreHookState::new(true, Vec::new(), None, None).expect("state"),
    )
    .expect("request");
    let head = harness.repo.head();
    let count = harness.repo.commit_count();
    let outcome = harness.finalize(&request).expect("finalize");
    match outcome {
        TaskFinalizeOutcome::NoChange { record } => {
            assert!(record.source_unchanged());
            assert_eq!(record.evidence(), &[evidence(harness.project, 0x8001)]);
        }
        other => panic!("expected a no-change result, got {other:?}"),
    }
    assert_eq!(harness.repo.head(), head, "no empty commit exists");
    assert_eq!(harness.repo.commit_count(), count);
    assert!(
        stored_entry(&harness.store, harness.project, &request).is_none(),
        "a no_change Task writes no Git journal"
    );
}

#[test]
fn a_no_change_task_whose_document_moved_holds() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let before = harness.repo.write("docs/adr/0009.md", "# Before\n");
    let request = commit_request(
        &harness.repo,
        harness.project,
        9,
        CommitPolicy::NoChange,
        Vec::new(),
        vec![
            VerifiedPath::present("docs/adr/0009.md", Sha256Digest::sha256(&before))
                .expect("verified"),
        ],
        vec![evidence(harness.project, 0x9001)],
        herness_sdd_execute::PreHookState::new(true, Vec::new(), None, None).expect("state"),
    )
    .expect("request");
    harness.repo.write("docs/adr/0009.md", "# After\n");
    let head = harness.repo.head();
    let outcome = harness.finalize(&request).expect("finalize");
    match outcome {
        TaskFinalizeOutcome::Held {
            stop: FinalizeStop::EvidenceChanged { paths },
            ..
        } => assert_eq!(paths, vec!["docs/adr/0009.md".to_owned()]),
        other => panic!("a moved document must hold, got {other:?}"),
    }
    assert_eq!(harness.repo.head(), head);
}

#[test]
fn a_no_change_task_with_no_evidence_is_refused_at_construction() {
    let harness = Harness::new();
    let error = commit_request(
        &harness.repo,
        harness.project,
        1,
        CommitPolicy::NoChange,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        herness_sdd_execute::PreHookState::new(true, Vec::new(), None, None).expect("state"),
    )
    .expect_err("a no_change Task needs evidence");
    assert!(matches!(error, SddExecutionError::InvalidValue { .. }));
}

// ---------------------------------------------------------------------------
// Hook failure and hook change
// ---------------------------------------------------------------------------

#[test]
fn a_failing_hook_holds_without_creating_a_commit() {
    let mut harness = Harness::new();
    harness
        .repo
        .install_hook("#!/bin/sh\necho 'refused by hook' >&2\nexit 1\n");
    let change = harness.repo.write("docs/adr/0010.md", "# 10\n");
    let targets = vec![target(
        "docs/adr/0010.md",
        &change,
        TargetOrigin::TaskChange,
    )];
    let request = commit_request(
        &harness.repo,
        harness.project,
        10,
        CommitPolicy::Required,
        targets.clone(),
        Vec::new(),
        Vec::new(),
        pre_hook(&targets),
    )
    .expect("request");
    let head = harness.repo.head();
    let count = harness.repo.commit_count();
    let outcome = harness.finalize(&request).expect("finalize");
    match outcome {
        TaskFinalizeOutcome::Held {
            stop: FinalizeStop::Rejected(GitRejection::HookFailed),
            journal,
        } => {
            assert_eq!(
                journal.expect("recorded journal").state(),
                GitJournalState::Rejected
            );
        }
        other => panic!("a failing hook must hold, got {other:?}"),
    }
    assert_eq!(harness.repo.head(), head);
    assert_eq!(harness.repo.commit_count(), count);
    assert_eq!(
        FinalizeStop::Rejected(GitRejection::HookFailed)
            .stop()
            .expect("stop")
            .reason(),
        StopReason::HumanDecisionRequired
    );
}

#[test]
fn a_changed_hook_configuration_holds_before_anything_is_staged() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let change = harness.repo.write("docs/adr/0011.md", "# 11\n");
    let targets = vec![target(
        "docs/adr/0011.md",
        &change,
        TargetOrigin::TaskChange,
    )];
    // The intent records the hook digest the approval was bound to.
    let hooks =
        herness_core::hooks_configuration_digest(&harness.repo.root_path()).expect("hooks digest");
    let recorded = herness_sdd_execute::PreHookState::new(
        true,
        vec!["docs/adr/0011.md".to_owned()],
        Some(Sha256Digest::parse(hooks).expect("digest")),
        None,
    )
    .expect("pre-hook state");
    let request = commit_request(
        &harness.repo,
        harness.project,
        11,
        CommitPolicy::Required,
        targets,
        Vec::new(),
        Vec::new(),
        recorded,
    )
    .expect("request");
    // The hook changes after the intent was fixed.
    harness.repo.install_hook("#!/bin/sh\nexit 0\n# changed\n");
    let head = harness.repo.head();
    let count = harness.repo.commit_count();
    let outcome = harness.finalize(&request).expect("finalize");
    match outcome {
        TaskFinalizeOutcome::Held {
            stop: FinalizeStop::Rejected(GitRejection::HookFailed),
            ..
        } => {}
        other => panic!("a changed hook must hold, got {other:?}"),
    }
    assert_eq!(harness.repo.head(), head);
    assert_eq!(harness.repo.commit_count(), count);
    assert!(
        !harness.repo.is_staged("docs/adr/0011.md"),
        "nothing is staged when the hook digest already differs"
    );
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

#[test]
fn a_replayed_request_returns_the_stored_result_and_creates_no_second_commit() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let change = harness.repo.write("docs/adr/0012.md", "# 12\n");
    let targets = vec![target(
        "docs/adr/0012.md",
        &change,
        TargetOrigin::TaskChange,
    )];
    let request = commit_request(
        &harness.repo,
        harness.project,
        12,
        CommitPolicy::Required,
        targets.clone(),
        Vec::new(),
        Vec::new(),
        pre_hook(&targets),
    )
    .expect("request");
    let first = harness.finalize(&request).expect("first finalize");
    let count = harness.repo.commit_count();
    let head = harness.repo.head();
    let second = harness.finalize(&request).expect("replayed finalize");
    assert_eq!(first.range(), second.range());
    assert_eq!(harness.repo.head(), head);
    assert_eq!(harness.repo.commit_count(), count, "no duplicate commit");
}

// ---------------------------------------------------------------------------
// Journal-boundary faults
// ---------------------------------------------------------------------------

/// One injected durable-write fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// The Git **intent** write fails, before any Git side effect.
    IntentWrite,
    /// The Git **result** write fails after the side effect.
    ResultWrite,
}

/// `ExecutionStorePort` that fails exactly one chosen write and delegates
/// everything else to the real store.
struct FaultyStore<'a> {
    store: &'a mut Store,
    fault: Fault,
    git_writes: usize,
}

impl<'a> FaultyStore<'a> {
    fn new(store: &'a mut Store, fault: Fault) -> Self {
        Self {
            store,
            fault,
            git_writes: 0,
        }
    }
}

impl ExecutionStorePort for FaultyStore<'_> {
    fn load(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<StoredExecution>, SddExecutionError> {
        ExecutionStorePort::load(self.store, project_id, execution_id)
    }

    fn compare_and_swap(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        ExecutionStorePort::compare_and_swap(
            self.store,
            project_id,
            execution_id,
            expected_revision,
            next,
        )
    }

    fn dispatch_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchJournalEntry>, SddExecutionError> {
        ExecutionStorePort::dispatch_entry(self.store, project_id, execution_id, request_id)
    }

    fn commit_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: CommitRequestId,
    ) -> Result<Option<GitJournalEntry>, SddExecutionError> {
        ExecutionStorePort::commit_entry(self.store, project_id, execution_id, request_id)
    }

    fn progress_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ProgressJournalId,
    ) -> Result<Option<ProgressJournalEntry>, SddExecutionError> {
        ExecutionStorePort::progress_entry(self.store, project_id, execution_id, request_id)
    }

    fn operation_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<herness_sdd_execute::ControlRecord>, SddExecutionError> {
        ExecutionStorePort::operation_record(self.store, project_id, execution_id, request_id)
    }

    fn record_dispatch(&mut self, entry: &DispatchJournalEntry) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_dispatch(self.store, entry)
    }

    fn record_git(&mut self, entry: &GitJournalEntry) -> Result<(), SddExecutionError> {
        self.git_writes += 1;
        let injected = match self.fault {
            Fault::IntentWrite => self.git_writes == 1,
            Fault::ResultWrite => self.git_writes == 2,
        };
        if injected {
            return Err(SddExecutionError::Unavailable {
                feature: "test.injectedGitWriteFault".to_owned(),
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            });
        }
        ExecutionStorePort::record_git(self.store, entry)
    }

    fn record_progress(&mut self, entry: &ProgressJournalEntry) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_progress(self.store, entry)
    }

    fn record_operation(
        &mut self,
        record: &herness_sdd_execute::ControlRecord,
    ) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_operation(self.store, record)
    }

    fn commit_operation(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
        record: &herness_sdd_execute::ControlRecord,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        ExecutionStorePort::commit_operation(
            self.store,
            project_id,
            execution_id,
            expected_revision,
            next,
            record,
        )
    }
}

/// A `HostGitPort` that fails at one chosen point in the boundary sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitFault {
    /// Report an error before the boundary runs, so no Git process starts.
    BeforeBoundary,
    /// Run the real boundary and then report an error, so the commit exists but
    /// its result was never delivered.
    AfterBoundary,
    /// Report an unknown timeout instead of running the boundary.
    Timeout,
}

struct FaultyGit<'a> {
    inner: &'a mut dyn HostGitPort,
    fault: GitFault,
}

impl HostGitPort for FaultyGit<'_> {
    fn commit(
        &mut self,
        entry: &GitJournalEntry,
        authorization: CommitAuthorization,
    ) -> Result<GitCommitOutcome, SddExecutionError> {
        match self.fault {
            GitFault::BeforeBoundary => Err(SddExecutionError::Unavailable {
                feature: "test.injectedGitFault".to_owned(),
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            }),
            GitFault::Timeout => Ok(GitCommitOutcome::Unknown {
                reason: GitUnknownReason::Timeout,
            }),
            GitFault::AfterBoundary => {
                self.inner.commit(entry, authorization)?;
                Err(SddExecutionError::Unavailable {
                    feature: "test.injectedGitFault".to_owned(),
                    details: herness_sdd_execute::FailureDetails::none().boxed(),
                })
            }
        }
    }

    fn observe(&mut self, entry: &GitJournalEntry) -> Result<GitCommitOutcome, SddExecutionError> {
        self.inner.observe(entry)
    }
}

/// One harness task: a changed document and its exact target list.
struct Case {
    request: TaskCommitRequest,
}

fn required_case(harness: &Harness, number: u32, path: &str, contents: &str) -> Case {
    let bytes = harness.repo.write(path, contents);
    let targets = vec![target(path, &bytes, TargetOrigin::TaskChange)];
    let request = commit_request(
        &harness.repo,
        harness.project,
        number,
        CommitPolicy::Required,
        targets.clone(),
        Vec::new(),
        Vec::new(),
        pre_hook(&targets),
    )
    .expect("request");
    Case { request }
}

#[test]
fn the_intent_write_fails_before_any_git_side_effect() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let case = required_case(&harness, 13, "docs/adr/0013.md", "# 13\n");
    let count = harness.repo.commit_count();
    let mut git = harness.boundary();
    let mut checkout = harness.observer();
    {
        let mut store = FaultyStore::new(&mut harness.store, Fault::IntentWrite);
        let mut ports = FinalizePorts {
            git: &mut git,
            store: &mut store,
            checkout: &mut checkout,
        };
        let error = finalize_task(&mut ports, &case.request).expect_err("the intent write fails");
        assert!(matches!(error, SddExecutionError::Unavailable { .. }));
    }
    assert_eq!(harness.repo.commit_count(), count, "no commit exists");
    assert!(
        stored_entry(&harness.store, harness.project, &case.request).is_none(),
        "no journal entry is left behind"
    );
}

#[test]
fn a_result_write_failure_after_the_commit_is_unknown_and_never_recommitted() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let case = required_case(&harness, 14, "docs/adr/0014.md", "# 14\n");
    let count = harness.repo.commit_count();
    let head_before = harness.repo.head();
    let mut git = harness.boundary();
    let mut checkout = harness.observer();
    {
        let mut store = FaultyStore::new(&mut harness.store, Fault::ResultWrite);
        let mut ports = FinalizePorts {
            git: &mut git,
            store: &mut store,
            checkout: &mut checkout,
        };
        let outcome = finalize_task(&mut ports, &case.request).expect("finalize");
        match outcome {
            TaskFinalizeOutcome::Held {
                stop: FinalizeStop::ResultUnknown(GitUnknownReason::JournalWriteFailed),
                ..
            } => {}
            other => panic!("a lost result write must be unknown, got {other:?}"),
        }
    }
    // The commit exists exactly once and was not rolled back.
    assert_eq!(harness.repo.commit_count(), count + 1);
    assert_ne!(harness.repo.head(), head_before);
    let committed_head = harness.repo.head();

    // The journal holds the intent only; a replay is an explicit unknown.
    let stored = stored_entry(&harness.store, harness.project, &case.request).expect("intent");
    assert_eq!(stored.state(), GitJournalState::Intent);
    assert_eq!(
        FinalizeStop::ResultUnknown(GitUnknownReason::JournalWriteFailed)
            .stop()
            .expect("stop")
            .required_action(),
        Some(HumanAction::ConfirmGitRecovery)
    );
    let replay = harness.finalize(&case.request).expect("replay");
    assert!(matches!(
        replay,
        TaskFinalizeOutcome::Held {
            stop: FinalizeStop::ResultUnknown(_),
            ..
        }
    ));
    assert_eq!(harness.repo.head(), committed_head);
    assert_eq!(
        harness.repo.commit_count(),
        count + 1,
        "no duplicate commit"
    );
}

#[test]
fn a_boundary_that_starts_nothing_leaves_no_commit_and_an_explicit_unknown() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let case = required_case(&harness, 15, "docs/adr/0015.md", "# 15\n");
    let count = harness.repo.commit_count();
    let mut git = harness.boundary();
    let mut checkout = harness.observer();
    {
        let mut faulty = FaultyGit {
            inner: &mut git,
            fault: GitFault::BeforeBoundary,
        };
        let mut ports = FinalizePorts {
            git: &mut faulty,
            store: &mut harness.store,
            checkout: &mut checkout,
        };
        let outcome = finalize_task(&mut ports, &case.request).expect("finalize");
        assert!(matches!(
            outcome,
            TaskFinalizeOutcome::Held {
                stop: FinalizeStop::ResultUnknown(_),
                ..
            }
        ));
    }
    assert_eq!(harness.repo.commit_count(), count);
    // The journal records the unknown rather than leaving a bare intent.
    let stored = stored_entry(&harness.store, harness.project, &case.request).expect("journal");
    assert_eq!(stored.state(), GitJournalState::ResultUnknown);
}

#[test]
fn a_boundary_timeout_is_unknown_and_a_replay_never_commits() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let case = required_case(&harness, 16, "docs/adr/0016.md", "# 16\n");
    let count = harness.repo.commit_count();
    let mut git = harness.boundary();
    let mut checkout = harness.observer();
    {
        let mut faulty = FaultyGit {
            inner: &mut git,
            fault: GitFault::Timeout,
        };
        let mut ports = FinalizePorts {
            git: &mut faulty,
            store: &mut harness.store,
            checkout: &mut checkout,
        };
        let outcome = finalize_task(&mut ports, &case.request).expect("finalize");
        match outcome {
            TaskFinalizeOutcome::Held {
                stop: FinalizeStop::ResultUnknown(GitUnknownReason::Timeout),
                journal,
            } => assert_eq!(
                journal.expect("recorded unknown").state(),
                GitJournalState::ResultUnknown
            ),
            other => panic!("a timeout must be unknown, got {other:?}"),
        }
    }
    assert_eq!(harness.repo.commit_count(), count);
    let replay = harness.finalize(&case.request).expect("replay");
    assert!(matches!(
        replay,
        TaskFinalizeOutcome::Held {
            stop: FinalizeStop::ResultUnknown(GitUnknownReason::Timeout),
            ..
        }
    ));
    assert_eq!(harness.repo.commit_count(), count, "no re-commit");
}

#[test]
fn a_boundary_that_commits_then_loses_its_result_creates_exactly_one_commit() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let case = required_case(&harness, 17, "docs/adr/0017.md", "# 17\n");
    let count = harness.repo.commit_count();
    let mut git = harness.boundary();
    let mut checkout = harness.observer();
    {
        let mut faulty = FaultyGit {
            inner: &mut git,
            fault: GitFault::AfterBoundary,
        };
        let mut ports = FinalizePorts {
            git: &mut faulty,
            store: &mut harness.store,
            checkout: &mut checkout,
        };
        let outcome = finalize_task(&mut ports, &case.request).expect("finalize");
        assert!(matches!(
            outcome,
            TaskFinalizeOutcome::Held {
                stop: FinalizeStop::ResultUnknown(_),
                ..
            }
        ));
    }
    assert_eq!(harness.repo.commit_count(), count + 1);
    let replay = harness.finalize(&case.request).expect("replay");
    assert!(matches!(
        replay,
        TaskFinalizeOutcome::Held {
            stop: FinalizeStop::ResultUnknown(_),
            ..
        }
    ));
    assert_eq!(harness.repo.commit_count(), count + 1);
}

// ---------------------------------------------------------------------------
// Post-commit content re-read
// ---------------------------------------------------------------------------

/// An observer that reports a moved digest after the first read, so the
/// post-commit re-read sees content that no longer matches the verified bytes.
struct MovingObserver<'a> {
    inner: &'a mut dyn CommitObservationPort,
    path: String,
    moved: Sha256Digest,
    reads: usize,
}

impl CommitObservationPort for MovingObserver<'_> {
    fn observe(
        &mut self,
        request: &ObservationRequest,
    ) -> Result<CommitObservation, SddExecutionError> {
        self.reads += 1;
        let observation = self.inner.observe(request)?;
        // The post-commit re-read is the one that sees the moved bytes.
        Ok(moved_observation(observation, &self.path, &self.moved))
    }
}

fn moved_observation(
    observation: CommitObservation,
    path: &str,
    digest: &Sha256Digest,
) -> CommitObservation {
    let tracked = observation
        .tracked()
        .iter()
        .map(|entry| {
            if entry.path() == path {
                ObservedPath::new(path, Some(digest.clone()))
            } else {
                entry.clone()
            }
        })
        .collect();
    CommitObservation::new(
        observation.project_id(),
        observation.branch().map(str::to_owned),
        observation.head().cloned(),
        observation.head_tree().cloned(),
        observation.head_parent().cloned(),
        observation.head_message().to_owned(),
        observation.index_clean(),
        observation.staged_paths().to_vec(),
        tracked,
    )
}

#[test]
fn a_document_that_moved_after_the_commit_invalidates_the_evidence() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let document = harness.repo.write("docs/adr/0018.md", "# 18\n");
    let change = harness.repo.write("docs/adr/0018-impl.md", "# impl\n");
    let targets = vec![target(
        "docs/adr/0018-impl.md",
        &change,
        TargetOrigin::TaskChange,
    )];
    let request = commit_request(
        &harness.repo,
        harness.project,
        18,
        CommitPolicy::Required,
        targets.clone(),
        vec![
            VerifiedPath::present("docs/adr/0018.md", Sha256Digest::sha256(&document))
                .expect("verified"),
        ],
        Vec::new(),
        pre_hook(&targets),
    )
    .expect("request");
    let mut git = harness.boundary();
    let mut checkout = harness.observer();
    let mut moving = MovingObserver {
        inner: &mut checkout,
        path: "docs/adr/0018.md".to_owned(),
        moved: Sha256Digest::sha256(b"# edited after the commit\n"),
        reads: 0,
    };
    let mut ports = FinalizePorts {
        git: &mut git,
        store: &mut harness.store,
        checkout: &mut moving,
    };
    let outcome = finalize_task(&mut ports, &request).expect("finalize");
    match outcome {
        TaskFinalizeOutcome::Held {
            stop: FinalizeStop::EvidenceChanged { paths },
            journal,
        } => {
            assert_eq!(paths, vec!["docs/adr/0018.md".to_owned()]);
            // The commit exists and is recorded; only the evidence is stale.
            assert_eq!(
                journal.expect("recorded commit").state(),
                GitJournalState::Committed
            );
        }
        other => panic!("a moved document must invalidate the evidence, got {other:?}"),
    }
    assert_eq!(
        FinalizeStop::EvidenceChanged {
            paths: vec!["docs/adr/0018.md".to_owned()]
        }
        .stop()
        .expect("stop")
        .reason(),
        StopReason::RecoveryRequired
    );
}

// ---------------------------------------------------------------------------
// Recovery classification (Task 20 input)
// ---------------------------------------------------------------------------

#[test]
fn the_recovery_classification_separates_established_not_run_and_unknown() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let change = harness.repo.write("docs/adr/0019.md", "# 19\n");
    let targets = vec![target(
        "docs/adr/0019.md",
        &change,
        TargetOrigin::TaskChange,
    )];
    let request = commit_request(
        &harness.repo,
        harness.project,
        19,
        CommitPolicy::Required,
        targets.clone(),
        Vec::new(),
        Vec::new(),
        pre_hook(&targets),
    )
    .expect("request");
    let intent = request.intent().expect("intent");
    let base = harness.repo.head();

    // Before the commit: HEAD is still the expected parent.
    let mut observer = harness.observer();
    let before = observer
        .observe(&request.observation_request())
        .expect("observation");
    assert_eq!(
        herness_desktop::sdd_execute::recovery_of(&intent, &before),
        CommitRecovery::NotRun
    );

    // After the commit: every saved value matches.
    let outcome = harness.finalize(&request).expect("finalize");
    let range = outcome.range().expect("range").clone();
    let after = observer
        .observe(&request.observation_request())
        .expect("observation");
    match herness_desktop::sdd_execute::recovery_of(&intent, &after) {
        CommitRecovery::Established {
            commit,
            tree,
            parent,
            range: observed,
        } => {
            assert_eq!(commit.as_str(), harness.repo.head());
            assert_eq!(tree.as_str(), harness.repo.tree());
            assert_eq!(parent.as_str(), base);
            assert_eq!(observed, range);
        }
        other => panic!("the saved intent is established, got {other:?}"),
    }

    // A different branch holding a different commit is unknown, never
    // established.
    run_git(&harness.repo.root, &["checkout", "-q", "-b", "other"]);
    harness.repo.write("docs/adr/0019.md", "# rewritten\n");
    run_git(&harness.repo.root, &["add", "--", "docs/adr/0019.md"]);
    run_git_without_hooks(&harness.repo.root, &["commit", "-q", "-m", "unrelated"]);
    let diverged = observer
        .observe(&request.observation_request())
        .expect("observation");
    assert!(matches!(
        herness_desktop::sdd_execute::recovery_of(&intent, &diverged),
        CommitRecovery::Unknown { .. }
    ));
}

// ---------------------------------------------------------------------------
// The completion seam: barrier, commit, and the DB gate
// ---------------------------------------------------------------------------

/// A barrier gate that is synced and reports one verified companion.
struct SyncedGate {
    derived: Vec<(String, Vec<u8>)>,
}

impl TaskBarrierGate for SyncedGate {
    fn final_barrier(
        &mut self,
        _task: TaskRef,
        _now: Timestamp,
    ) -> Result<BarrierReport, SddExecutionError> {
        Ok(BarrierReport::synced(self.derived.len(), false))
    }
}

impl VerifiedDocumentSource for SyncedGate {
    fn verified_documents(&self) -> VerifiedDocuments {
        VerifiedDocuments::from_derived(self.derived.clone())
    }
}

/// A barrier gate that holds, so the commit half must never run.
struct HeldGate;

impl TaskBarrierGate for HeldGate {
    fn final_barrier(
        &mut self,
        _task: TaskRef,
        _now: Timestamp,
    ) -> Result<BarrierReport, SddExecutionError> {
        Ok(BarrierReport::hold_decision(BarrierHold::new(
            HtmlSyncReason::Unsynced,
            vec!["docs/adr/0019.md".to_owned()],
            "the document is not synced",
            vec!["resume_cycle".to_owned()],
        )))
    }
}

impl VerifiedDocumentSource for HeldGate {
    fn verified_documents(&self) -> VerifiedDocuments {
        VerifiedDocuments::default()
    }
}

/// A commit half that reports connected but must never run.
struct NeverCalledCommit;

impl HostCommitCompletion for NeverCalledCommit {
    fn commit_connected(&self) -> bool {
        true
    }

    fn commit(
        &mut self,
        _request: &TaskCompletionRequest,
        _verified: &VerifiedDocuments,
    ) -> Result<TaskCompletion, SddExecutionError> {
        panic!("the commit half must not run when the barrier holds");
    }
}

fn completion_request(project: ProjectId, task_number: u32) -> TaskCompletionRequest {
    TaskCompletionRequest::new(
        task_ref(project, task_number),
        execution(project),
        ExecutionRevision::INITIAL,
        SupervisionId::new(project),
        CommitAuthorization::new(true, true).expect("authorization"),
        CommitPolicy::Required,
        vec![EvidenceId::from_parts(project, Uuid::from_u128(0x9001))],
        20,
    )
}

#[test]
fn a_synced_barrier_reaches_the_real_host_commit_and_reports_the_range() {
    let harness = Harness::new();
    let companion_bytes = harness.repo.write(
        "docs/adr/0020.html",
        "<!doctype html><html><body>20</body></html>\n",
    );
    harness.repo.write("docs/adr/0020.md", "# 20\n");
    harness.repo.accepting_hook();

    // The verified companion enters the commit target through the barrier only.
    let derived = vec![("docs/adr/0020.html".to_owned(), companion_bytes)];
    let data = tempfile::tempdir().expect("data");
    let store = Store::open(StoreConfig::new(data.path()).expect("config")).expect("store");
    let shared = Arc::new(Mutex::new(store));
    let handle = herness_desktop::supervision::store::StoreHandle::new(Arc::clone(&shared));

    let boundary = harness.boundary();
    let observer = harness.observer();
    let mut commit = DesktopHostCommit::new(
        handle,
        boundary,
        observer,
        identity(&harness.repo, harness.project),
    );
    commit.bind_task(TaskCommitExpectation::new(
        task_ref(harness.project, 1),
        "commit Task 1",
        CommitPolicy::Required,
        vec!["docs/adr".to_owned()],
        Baseline::parse(harness.repo.head()).expect("base"),
        20,
    ));
    let mut completion = HtmlBarrierCompletion::with_commit(SyncedGate { derived }, commit);
    let outcome =
        TaskCompletionPort::complete(&mut completion, &completion_request(harness.project, 1))
            .expect("completion");
    match outcome {
        TaskCompletion::Complete {
            commit_range,
            no_change,
            ..
        } => {
            let range = commit_range.expect("a commit range");
            assert_eq!(range.head().as_str(), harness.repo.head());
            assert!(no_change.is_none());
        }
        other => panic!("a synced barrier commits, got {other:?}"),
    }
    // Both the Task change and the verified companion are committed.
    let mut changed = harness.repo.changed_paths();
    changed.sort();
    assert_eq!(
        changed,
        vec![
            "docs/adr/0020.html".to_owned(),
            "docs/adr/0020.md".to_owned()
        ]
    );

    // The recorded journal is durable in the shared store.
    let stored = ExecutionStorePort::commit_entry(
        &*shared.lock().expect("lock"),
        harness.project,
        execution(harness.project),
        commit_request_id(
            execution(harness.project),
            task_ref(harness.project, 1),
            &CommitSha::parse(harness.repo.parent()).expect("parent"),
        ),
    )
    .expect("stored")
    .expect("journal");
    assert_eq!(stored.state(), GitJournalState::Committed);
}

#[test]
fn a_held_barrier_never_reaches_the_commit_half() {
    let mut completion = HtmlBarrierCompletion::with_commit(HeldGate, NeverCalledCommit);
    let outcome = TaskCompletionPort::complete(&mut completion, &completion_request(project(), 1))
        .expect("completion");
    match outcome {
        TaskCompletion::HumanWait { stop } => {
            assert_eq!(stop.reason(), StopReason::HtmlUnsynced);
            assert_eq!(stop.required_action(), Some(HumanAction::ResolveHtmlSync));
        }
        other => panic!("a held barrier must not commit, got {other:?}"),
    }
    assert!(HostCommitCompletion::commit_connected(&NeverCalledCommit));
}

#[test]
fn an_unconnected_commit_half_still_reports_the_missing_capability() {
    let harness = Harness::new();
    harness.repo.accepting_hook();
    let mut completion = HtmlBarrierCompletion::with_commit(
        SyncedGate {
            derived: Vec::new(),
        },
        herness_desktop::sdd_execute::NotConnectedCommit,
    );
    let outcome =
        TaskCompletionPort::complete(&mut completion, &completion_request(harness.project, 1))
            .expect("completion");
    match outcome {
        TaskCompletion::HumanWait { stop } => {
            assert_eq!(stop.reason(), StopReason::CapabilityUnavailable);
        }
        other => panic!("an unconnected commit never completes, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The next Task never starts before the DB commit
// ---------------------------------------------------------------------------

use herness_sdd_execute::{
    ApprovalId, ApprovalSource, ApprovedCheck, ApprovedCondition, ApprovedDeliverable,
    ApprovedSpecRef, BudgetConsumption, ChildDispatchPlan, ChildDispatchPort, ChildIdentity,
    ChildStatusPort, CompletionWiring, ConditionMode, DispatchResult, ExecutionApproval,
    ExecutionConnection, ExecutionState, GitIdentity, H3ApprovalBinding, InspectorProtocol,
    PackApproval, PackFingerprint, ParsedPlanSummary, ParsedPlanTask, PlanApproval, PlanByteRange,
    PlanDigest, PlanPath, PlanRevision, SerialExecutionState, SnapshotBudget, SnapshotInput,
    SnapshotPlan, SnapshotWorkspace, TaskApproval, TaskPhase, TaskProgression, TaskSnapshot,
    TaskStableId, WorkspaceApproval,
};
use herness_supervision::{
    ApprovalActor, ConsentBinding, ConsentId, ExecutionScope, ProfileBinding, ProfileId,
    ProfilePurpose, ProfileVersion, TargetVersion,
};

const CHECKOUT: &str = "/tmp/herness-h4-commit-coordinator";
const BASE_BRANCH: &str = "main";
const PLAN_PATH: &str = "docs/sdd/plans/2026-11-13-commit-fixture.md";
const SPEC_PATH: &str = "docs/sdd/specs/2026-11-13-commit-fixture.md";

fn coordinator_project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("a3000000-0000-4000-8000-000000000001").unwrap())
}

fn coordinator_execution(project: ProjectId) -> ExecutionId {
    ExecutionId::from_parts(
        project,
        Uuid::parse_str("b3000000-0000-4000-8000-000000000001").unwrap(),
    )
}

fn coordinator_approval_id(project: ProjectId) -> ApprovalId {
    ApprovalId::from_parts(
        project,
        Uuid::parse_str("c3000000-0000-4000-8000-000000000001").unwrap(),
    )
}

fn coordinator_task(project: ProjectId, number: u32) -> TaskRef {
    TaskRef::new(
        TaskStableId::from_parts(
            project,
            Uuid::from_u128(0xd300_0000_0000_4000_8000_0000_0000_0000 + u128::from(number)),
        ),
        herness_sdd_execute::TaskNumber::new(number).expect("Task number"),
    )
}

fn plan_revision() -> PlanRevision {
    PlanRevision::new(1).expect("plan revision")
}

fn plan_path() -> PlanPath {
    PlanPath::parse(PLAN_PATH).expect("plan path")
}

fn coordinator_scope(project: ProjectId) -> ExecutionScope {
    ExecutionScope::new(
        project,
        vec!["docs".to_owned()],
        vec!["docs/adr".to_owned()],
        false,
    )
    .expect("scope")
}

fn coordinator_approval(project: ProjectId) -> ExecutionApproval {
    let constraints = "Global Constraints\n- keep 4 rules";
    let body = || {
        herness_sdd_execute::ExactPlanText::new("Body.\n", PlanByteRange::new(0, 6).unwrap())
            .expect("body")
    };
    let profile = ProfileBinding::new(
        ProfileId::from_parts(project, Uuid::from_u128(0xe300)),
        ProfileVersion::new(1).expect("profile version"),
        ProfilePurpose::Completion,
    );
    let consent = ConsentBinding::new(
        ConsentId::from_parts(project, Uuid::from_u128(0xe301)),
        1,
        ProfilePurpose::Completion,
        TargetVersion::new(1).expect("target version"),
    );
    ExecutionApproval::new(
        coordinator_approval_id(project),
        ApprovalActor::Human,
        ApprovalSource::ApprovalRegistry {
            approval_id: coordinator_approval_id(project),
        },
        Timestamp::from_unix_millis(1_770_000_000_000),
        herness_sdd_execute::ApprovalContent::new(
            PlanApproval::new(
                plan_path(),
                herness_sdd_execute::ExactPlanBytes::new(b"# plan".to_vec()).expect("plan bytes"),
                plan_revision(),
                ParsedPlanSummary::new(
                    1,
                    herness_sdd_execute::ExactPlanText::new(
                        constraints,
                        PlanByteRange::new(0, constraints.len() as u64).unwrap(),
                    )
                    .unwrap(),
                    vec![
                        ParsedPlanTask::new(1, "Task 1", body()).unwrap(),
                        ParsedPlanTask::new(2, "Task 2", body()).unwrap(),
                    ],
                    vec!["check-1".to_owned()],
                )
                .expect("parsed"),
                vec![
                    ApprovedSpecRef::new(
                        "project",
                        SPEC_PATH,
                        vec!["Contract".to_owned()],
                        Sha256Digest::sha256(b"spec"),
                    )
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
            .expect("plan"),
            WorkspaceApproval::new(
                project,
                CHECKOUT,
                GitIdentity::new("herness", "host@example.test").expect("identity"),
                BRANCH,
                BASE_BRANCH,
                false,
                Some(Baseline::parse("a".repeat(40)).expect("baseline")),
            )
            .expect("workspace"),
            vec![
                TaskApproval::new(
                    coordinator_task(project, 1),
                    "Task 1",
                    vec![
                        ApprovedCondition::new("c1", "condition", "rubric", ConditionMode::Checks)
                            .expect("condition"),
                    ],
                    coordinator_scope(project),
                    vec![
                        ApprovedCheck::new(
                            "check-1",
                            "c1",
                            "run",
                            "cargo test",
                            ".",
                            30,
                            vec!["docs".to_owned()],
                        )
                        .expect("check"),
                    ],
                    Vec::new(),
                    BudgetPolicy::h2_default(),
                    CommitPolicy::Required,
                    vec![
                        ApprovedDeliverable::new(
                            "docs/adr/0001.md",
                            herness_sdd_execute::DeliverableKind::File,
                        )
                        .expect("deliverable"),
                    ],
                )
                .expect("Task 1"),
                TaskApproval::new(
                    coordinator_task(project, 2),
                    "Task 2",
                    vec![
                        ApprovedCondition::new("c1", "condition", "rubric", ConditionMode::Checks)
                            .expect("condition"),
                    ],
                    coordinator_scope(project),
                    vec![
                        ApprovedCheck::new(
                            "check-1",
                            "c1",
                            "run",
                            "cargo test",
                            ".",
                            30,
                            vec!["docs".to_owned()],
                        )
                        .expect("check"),
                    ],
                    Vec::new(),
                    BudgetPolicy::h2_default(),
                    CommitPolicy::Required,
                    vec![
                        ApprovedDeliverable::new(
                            "docs/adr/0002.md",
                            herness_sdd_execute::DeliverableKind::File,
                        )
                        .expect("deliverable"),
                    ],
                )
                .expect("Task 2"),
            ],
            ExecutionConnection::new(
                herness_core::ConnectionId::from_uuid(Uuid::from_u128(0xe302)),
                profile,
                vec![consent],
            )
            .expect("connection"),
            CommitAuthorization::new(true, true).expect("commit"),
            H3ApprovalBinding::new(1, Vec::new(), vec!["html-sync".to_owned()]).expect("h3"),
        )
        .expect("content"),
    )
    .expect("approval")
}

fn coordinator_task_snapshot(project: ProjectId, number: u32, phase: TaskPhase) -> TaskSnapshot {
    TaskSnapshot::new(
        coordinator_task(project, number),
        phase.implied_progression(),
        phase,
        None,
        None,
        CommitPolicy::Required,
        None,
        None,
        Vec::new(),
        None,
        herness_sdd_execute::AppliedRevision::current(plan_revision()),
    )
    .expect("Task snapshot")
}

fn coordinator_snapshot(project: ProjectId, execution: ExecutionId) -> ExecutionSnapshot {
    ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: execution,
        revision: ExecutionRevision::INITIAL,
        state: ExecutionState::Ready,
        plan: SnapshotPlan::new(plan_path(), PlanDigest::sha256(b"# plan"), plan_revision()),
        workspace: SnapshotWorkspace::new(
            CHECKOUT,
            BRANCH,
            BASE_BRANCH,
            Some(Baseline::parse("a".repeat(40)).expect("baseline")),
        )
        .expect("workspace"),
        current_task: Some(coordinator_task(project, 1)),
        tasks: vec![
            coordinator_task_snapshot(project, 1, TaskPhase::Ready),
            coordinator_task_snapshot(project, 2, TaskPhase::Ready),
        ],
        stop: None,
        budget: SnapshotBudget::new(BudgetConsumption::zero(), BudgetConsumption::zero()),
        applied_revision: herness_sdd_execute::AppliedRevision::current(plan_revision()),
        final_project_sequence: None,
    })
    .expect("snapshot")
}

struct CoordinatorLaunch;

impl TaskLaunchPort for CoordinatorLaunch {
    fn launch(&mut self, task: TaskRef) -> Result<TaskLaunch, LaunchRefusal> {
        TaskLaunch::new(
            format!("packet for Task {}", task.number().get()),
            coordinator_scope(task.project_id()),
            BudgetPolicy::h2_default(),
            Sha256Digest::sha256(b"manifest"),
            Sha256Digest::sha256(b"packet"),
        )
        .map_err(|error| LaunchRefusal::Context {
            detail: error.to_string(),
        })
    }
}

#[derive(Default)]
struct CoordinatorDispatch {
    calls: Vec<DispatchRequestId>,
    next: u128,
}

impl ChildDispatchPort for CoordinatorDispatch {
    fn dispatch(&mut self, plan: &ChildDispatchPlan) -> Result<DispatchResult, SddExecutionError> {
        let request = plan.request();
        let project = request.identity().project_id();
        self.calls.push(request.identity().request_id());
        let supervision = SupervisionId::from_parts(project, Uuid::from_u128(0x5300 + self.next));
        let child = ChildIdentity::new(
            herness_core::AgentId::from_parts(project, Uuid::from_u128(0x7300 + self.next)),
            herness_core::SessionId::from_parts(project, Uuid::from_u128(0x7301 + self.next)),
        )
        .expect("child");
        self.next += 2;
        DispatchResult::new(supervision, child)
    }

    fn reconcile(
        &mut self,
        _project: ProjectId,
        _execution: ExecutionId,
        _request: DispatchRequestId,
    ) -> Result<Option<DispatchResult>, SddExecutionError> {
        Ok(None)
    }
}

#[derive(Default)]
struct CoordinatorChildren {
    scripted: Option<ChildStatus>,
}

impl ChildStatusPort for CoordinatorChildren {
    fn status(
        &mut self,
        _project: ProjectId,
        _execution: ExecutionId,
        _request: DispatchRequestId,
    ) -> Result<Option<ChildStatus>, SddExecutionError> {
        Ok(self.scripted.clone())
    }
}

/// The completion seam that runs a real barrier decision and a caller-supplied
/// commit result.
struct ScriptedCompletion {
    result: Option<TaskCompletion>,
}

impl TaskCompletionPort for ScriptedCompletion {
    fn wiring(&self, _task: TaskRef) -> CompletionWiring {
        CompletionWiring::Connected
    }

    fn complete(
        &mut self,
        _request: &TaskCompletionRequest,
    ) -> Result<TaskCompletion, SddExecutionError> {
        self.result
            .clone()
            .ok_or_else(|| SddExecutionError::Unavailable {
                feature: "hostCommit: fixture".to_owned(),
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            })
    }
}

/// A `CoordinatorStorePort` that fails the completion snapshot write once.
struct CompletionFaultStore<'a> {
    store: &'a mut Store,
    writes: usize,
    fail_at: usize,
}

impl ExecutionStorePort for CompletionFaultStore<'_> {
    fn load(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Option<StoredExecution>, SddExecutionError> {
        ExecutionStorePort::load(self.store, project_id, execution_id)
    }

    fn compare_and_swap(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        ExecutionStorePort::compare_and_swap(
            self.store,
            project_id,
            execution_id,
            expected_revision,
            next,
        )
    }

    fn dispatch_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<DispatchJournalEntry>, SddExecutionError> {
        ExecutionStorePort::dispatch_entry(self.store, project_id, execution_id, request_id)
    }

    fn commit_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: CommitRequestId,
    ) -> Result<Option<GitJournalEntry>, SddExecutionError> {
        ExecutionStorePort::commit_entry(self.store, project_id, execution_id, request_id)
    }

    fn progress_entry(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ProgressJournalId,
    ) -> Result<Option<ProgressJournalEntry>, SddExecutionError> {
        ExecutionStorePort::progress_entry(self.store, project_id, execution_id, request_id)
    }

    fn operation_record(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: ControlRequestId,
    ) -> Result<Option<herness_sdd_execute::ControlRecord>, SddExecutionError> {
        ExecutionStorePort::operation_record(self.store, project_id, execution_id, request_id)
    }

    fn record_dispatch(&mut self, entry: &DispatchJournalEntry) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_dispatch(self.store, entry)
    }

    fn record_git(&mut self, entry: &GitJournalEntry) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_git(self.store, entry)
    }

    fn record_progress(&mut self, entry: &ProgressJournalEntry) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_progress(self.store, entry)
    }

    fn record_operation(
        &mut self,
        record: &herness_sdd_execute::ControlRecord,
    ) -> Result<(), SddExecutionError> {
        ExecutionStorePort::record_operation(self.store, record)
    }

    fn commit_operation(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        expected_revision: Option<ExecutionRevision>,
        next: &ExecutionSnapshot,
        record: &herness_sdd_execute::ControlRecord,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        self.writes += 1;
        if self.writes == self.fail_at {
            return Err(SddExecutionError::Unavailable {
                feature: "test.injectedCompletionWrite".to_owned(),
                details: herness_sdd_execute::FailureDetails::none().boxed(),
            });
        }
        ExecutionStorePort::commit_operation(
            self.store,
            project_id,
            execution_id,
            expected_revision,
            next,
            record,
        )
    }
}

impl DurableExecutionStorePort for CompletionFaultStore<'_> {
    fn record_approval(&mut self, approval: &ExecutionApproval) -> Result<(), SddExecutionError> {
        DurableExecutionStorePort::record_approval(self.store, approval)
    }

    fn approval(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
        revision: u64,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        DurableExecutionStorePort::approval(self.store, project_id, approval_id, revision)
    }

    fn latest_approval(
        &self,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<ExecutionApproval>, SddExecutionError> {
        DurableExecutionStorePort::latest_approval(self.store, project_id, approval_id)
    }

    fn reserve_task(
        &mut self,
        reservation: &herness_sdd_execute::TaskReservation,
    ) -> Result<herness_sdd_execute::TaskReservation, SddExecutionError> {
        DurableExecutionStorePort::reserve_task(self.store, reservation)
    }

    fn task_reservation(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<herness_sdd_execute::TaskReservation>, SddExecutionError> {
        DurableExecutionStorePort::task_reservation(
            self.store,
            project_id,
            execution_id,
            request_id,
        )
    }

    fn record_manifest(
        &mut self,
        manifest: &herness_sdd_execute::DispatchManifest,
    ) -> Result<(), SddExecutionError> {
        DurableExecutionStorePort::record_manifest(self.store, manifest)
    }

    fn manifest(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        request_id: DispatchRequestId,
    ) -> Result<Option<herness_sdd_execute::DispatchManifest>, SddExecutionError> {
        DurableExecutionStorePort::manifest(self.store, project_id, execution_id, request_id)
    }

    fn record_budget_increment(
        &mut self,
        increment: &herness_sdd_execute::BudgetIncrement,
    ) -> Result<(), SddExecutionError> {
        DurableExecutionStorePort::record_budget_increment(self.store, increment)
    }

    fn budget_increments(
        &self,
        project_id: ProjectId,
        execution_id: ExecutionId,
    ) -> Result<Vec<herness_sdd_execute::BudgetIncrement>, SddExecutionError> {
        DurableExecutionStorePort::budget_increments(self.store, project_id, execution_id)
    }
}

#[test]
fn the_next_task_never_starts_before_the_completion_is_durable() {
    let project = coordinator_project();
    let execution = coordinator_execution(project);
    let data = tempfile::tempdir().expect("data");
    let mut store = Store::open(StoreConfig::new(data.path()).expect("config")).expect("store");
    DurableExecutionStorePort::record_approval(&mut store, &coordinator_approval(project))
        .expect("approval");
    store
        .compare_and_swap_execution(
            project,
            execution,
            None,
            &coordinator_snapshot(project, execution),
        )
        .expect("snapshot");

    let approval_id = coordinator_approval_id(project);
    let mut serial = SerialExecutionState::new();
    let mut launch = CoordinatorLaunch;
    let mut dispatch = CoordinatorDispatch::default();
    let mut children = CoordinatorChildren::default();
    let mut completion = ScriptedCompletion {
        result: Some(TaskCompletion::Complete {
            commit_range: Some(
                herness_sdd_execute::CommitRange::new(
                    Baseline::parse("a".repeat(40)).expect("base"),
                    CommitSha::parse("b".repeat(40)).expect("head"),
                )
                .expect("range"),
            ),
            no_change: None,
            host_seconds: 0,
        }),
    };

    // Dispatch Task 1.
    let request = CoordinatorRequest::new(
        project,
        execution,
        ControlRequestId::from_parts(project, Uuid::from_u128(0x1)),
        ExecutionRevision::INITIAL,
        approval_id,
        1,
    )
    .expect("request");
    {
        let mut ports = CoordinatorPorts {
            store: &mut store,
            launch: &mut launch,
            dispatch: &mut dispatch,
            children: &mut children,
            completion: &mut completion,
            serial: &mut serial,
        };
        let outcome = TaskCoordinator::advance(&mut ports, &request).expect("dispatch");
        assert!(matches!(outcome, CoordinatorOutcome::Dispatched { .. }));
    }
    assert_eq!(dispatch.calls.len(), 1);

    // H2 completes Task 1. The completion snapshot write fails.
    let revision = store
        .load_sdd_execution(project, execution)
        .expect("load")
        .expect("snapshot")
        .revision();
    children.scripted = Some(ChildStatus::new(
        SupervisionId::from_parts(project, Uuid::from_u128(0x5300)),
        herness_sdd_execute::ChildState::Completed,
        30,
        0,
        0,
        false,
        vec![EvidenceId::from_parts(project, Uuid::from_u128(0x9001))],
    ));
    let completion_request = CoordinatorRequest::new(
        project,
        execution,
        ControlRequestId::from_parts(project, Uuid::from_u128(0x2)),
        revision,
        approval_id,
        1,
    )
    .expect("request");
    {
        // The `committing` step is write one; the completion is write two.
        let mut faulty = CompletionFaultStore {
            store: &mut store,
            writes: 0,
            fail_at: 2,
        };
        let mut ports = CoordinatorPorts {
            store: &mut faulty,
            launch: &mut launch,
            dispatch: &mut dispatch,
            children: &mut children,
            completion: &mut completion,
            serial: &mut serial,
        };
        let error = TaskCoordinator::advance(&mut ports, &completion_request)
            .expect_err("the completion write fails");
        assert!(matches!(error, SddExecutionError::Unavailable { .. }));
        assert_eq!(faulty.writes, 2, "the final transaction was attempted");
    }

    // The stored snapshot is the `committing` step: Task 1 is active and Task 2
    // has not started, holds no H2 reference, and is still pending.
    let stored = store
        .load_sdd_execution(project, execution)
        .expect("load")
        .expect("snapshot")
        .snapshot()
        .clone();
    assert_eq!(stored.state(), ExecutionState::Committing);
    assert_eq!(
        stored.current_task().map(|task| task.number().get()),
        Some(1)
    );
    let second = stored
        .task(herness_sdd_execute::TaskNumber::new(2).expect("number"))
        .expect("Task 2");
    assert_eq!(second.progression(), TaskProgression::Pending);
    assert!(second.h2_reference().is_none());
    assert_eq!(dispatch.calls.len(), 1, "the next Task never starts");
}

// ---------------------------------------------------------------------------
// The journal-boundary table, in one place
// ---------------------------------------------------------------------------

/// One row of the journal-boundary table.
#[derive(Debug, Clone, Copy)]
enum Boundary {
    /// The Git intent write fails before the boundary runs.
    BeforeIntentStore,
    /// The intent is durable and the boundary refuses before staging.
    AfterIntentStoreBeforeStage,
    /// Staging succeeded and the approved hook (or common gate) refused.
    AfterStageBeforeHook,
    /// The hook passed and the commit did not happen.
    AfterHookBeforeCommit,
    /// The commit happened and its result write failed.
    AfterCommitBeforeResult,
    /// The result is durable and the completion snapshot write failed.
    AfterResultBeforeSnapshot,
}

impl Boundary {
    /// The expected commit count delta for this boundary.
    const fn expected_commits(self) -> usize {
        match self {
            Self::BeforeIntentStore
            | Self::AfterIntentStoreBeforeStage
            | Self::AfterStageBeforeHook
            | Self::AfterHookBeforeCommit => 0,
            Self::AfterCommitBeforeResult | Self::AfterResultBeforeSnapshot => 1,
        }
    }

    /// Whether the boundary is expected to report an explicit unknown.
    const fn expects_unknown(self) -> bool {
        matches!(
            self,
            Self::BeforeIntentStore
                | Self::AfterIntentStoreBeforeStage
                | Self::AfterCommitBeforeResult
        )
    }
}

#[test]
fn the_journal_boundary_table_creates_at_most_one_commit() {
    let boundaries = [
        Boundary::BeforeIntentStore,
        Boundary::AfterIntentStoreBeforeStage,
        Boundary::AfterStageBeforeHook,
        Boundary::AfterHookBeforeCommit,
        Boundary::AfterCommitBeforeResult,
        Boundary::AfterResultBeforeSnapshot,
    ];
    for boundary in boundaries {
        let mut harness = Harness::new();
        harness.repo.accepting_hook();
        let case = required_case(&harness, 21, "docs/adr/0021.md", "# 21\n");
        let count = harness.repo.commit_count();

        let has_commit = match boundary {
            Boundary::BeforeIntentStore => {
                let mut git = harness.boundary();
                let mut checkout = harness.observer();
                let mut store = FaultyStore::new(&mut harness.store, Fault::IntentWrite);
                let mut ports = FinalizePorts {
                    git: &mut git,
                    store: &mut store,
                    checkout: &mut checkout,
                };
                let error =
                    finalize_task(&mut ports, &case.request).expect_err("the intent write fails");
                assert!(matches!(error, SddExecutionError::Unavailable { .. }));
                assert!(identical_observation(&mut harness, &case).is_some());
                false
            }
            Boundary::AfterIntentStoreBeforeStage => {
                let mut git = harness.boundary();
                let mut faulty = FaultyGit {
                    inner: &mut git,
                    fault: GitFault::BeforeBoundary,
                };
                let mut checkout = harness.observer();
                let mut ports = FinalizePorts {
                    git: &mut faulty,
                    store: &mut harness.store,
                    checkout: &mut checkout,
                };
                let outcome = finalize_task(&mut ports, &case.request).expect("finalize");
                assert!(matches!(
                    outcome,
                    TaskFinalizeOutcome::Held {
                        stop: FinalizeStop::ResultUnknown(_),
                        ..
                    }
                ));
                false
            }
            Boundary::AfterStageBeforeHook | Boundary::AfterHookBeforeCommit => {
                // The approved hook refuses the staged content, which is the
                // stage→hook and hook→commit pair the boundary reports as one
                // rejection.
                harness
                    .repo
                    .install_hook("#!/bin/sh\necho 'policy refused' >&2\nexit 1\n");
                let mut git = harness.boundary();
                let mut checkout = harness.observer();
                let mut ports = FinalizePorts {
                    git: &mut git,
                    store: &mut harness.store,
                    checkout: &mut checkout,
                };
                let outcome = finalize_task(&mut ports, &case.request).expect("finalize");
                assert!(matches!(
                    outcome,
                    TaskFinalizeOutcome::Held {
                        stop: FinalizeStop::Rejected(GitRejection::HookFailed),
                        ..
                    }
                ));
                false
            }
            Boundary::AfterCommitBeforeResult => {
                let mut git = harness.boundary();
                let mut checkout = harness.observer();
                let mut store = FaultyStore::new(&mut harness.store, Fault::ResultWrite);
                let mut ports = FinalizePorts {
                    git: &mut git,
                    store: &mut store,
                    checkout: &mut checkout,
                };
                let outcome = finalize_task(&mut ports, &case.request).expect("finalize");
                assert!(matches!(
                    outcome,
                    TaskFinalizeOutcome::Held {
                        stop: FinalizeStop::ResultUnknown(GitUnknownReason::JournalWriteFailed),
                        ..
                    }
                ));
                true
            }
            Boundary::AfterResultBeforeSnapshot => {
                // The Git journal result is durable; the completion snapshot is
                // the coordinator's transaction and is covered by
                // `the_next_task_never_starts_before_the_completion_is_durable`.
                let outcome = harness.finalize(&case.request).expect("finalize");
                assert!(outcome.range().is_some());
                true
            }
        };

        let delta = harness.repo.commit_count() - count;
        assert_eq!(
            delta,
            usize::from(has_commit),
            "the {boundary:?} boundary created {delta} commits"
        );
        assert!(
            delta <= boundary.expected_commits(),
            "the {boundary:?} boundary must create at most {} commit(s)",
            boundary.expected_commits()
        );
        if boundary.expects_unknown() {
            let stored = stored_entry(&harness.store, harness.project, &case.request);
            assert!(
                stored.is_none()
                    || stored.as_ref().is_some_and(|entry| {
                        entry.outcome().is_none_or(|outcome| outcome.is_unknown())
                    }),
                "the {boundary:?} boundary must leave an unknown or nothing"
            );
        }
        // A duplicate delivery of the same request never creates a second one.
        // A boundary that left no journal entry at all is a new attempt, so it
        // commits at most once; every further replay adds nothing.
        let after = harness.repo.commit_count();
        let _ = harness.finalize(&case.request).expect("replay");
        let replay_delta = harness.repo.commit_count() - after;
        assert!(
            replay_delta <= 1,
            "the {boundary:?} replay created {replay_delta} commits"
        );
        if after > count {
            assert_eq!(
                replay_delta, 0,
                "the {boundary:?} replay of a recorded attempt must not commit again"
            );
        }
        let settled = harness.repo.commit_count();
        let _ = harness.finalize(&case.request).expect("second replay");
        assert_eq!(
            harness.repo.commit_count(),
            settled,
            "the {boundary:?} second replay created a duplicate commit"
        );
    }
}

fn identical_observation(harness: &mut Harness, case: &Case) -> Option<CommitObservation> {
    let mut observer = harness.observer();
    observer.observe(&case.request.observation_request()).ok()
}

// ---------------------------------------------------------------------------
// Unknown index and external conflict
// ---------------------------------------------------------------------------

#[test]
fn a_preexisting_staged_change_holds_the_task_and_leaves_the_index_alone() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let case = required_case(&harness, 22, "docs/adr/0022.md", "# 22\n");
    // Someone else staged an unrelated path before the Task finished.
    harness.repo.write("notes.txt", "someone else's work\n");
    run_git(&harness.repo.root, &["add", "--", "notes.txt"]);
    let head = harness.repo.head();
    let count = harness.repo.commit_count();

    let outcome = harness.finalize(&case.request).expect("finalize");
    match outcome {
        TaskFinalizeOutcome::Held {
            stop: FinalizeStop::Rejected(GitRejection::UnrelatedChanges),
            journal,
        } => {
            assert_eq!(
                journal.expect("recorded refusal").state(),
                GitJournalState::Rejected
            );
        }
        other => panic!("an unclean index must hold, got {other:?}"),
    }
    assert_eq!(harness.repo.head(), head);
    assert_eq!(harness.repo.commit_count(), count);
    // Nothing was reset, cleaned, or committed: the other work is untouched.
    assert!(harness.repo.is_staged("notes.txt"));
    assert_eq!(
        fs::read_to_string(harness.repo.root.join("notes.txt")).expect("notes"),
        "someone else's work\n"
    );
    assert_eq!(
        FinalizeStop::Rejected(GitRejection::UnrelatedChanges)
            .stop()
            .expect("stop")
            .required_action(),
        Some(HumanAction::ResolveConflict)
    );
}

#[test]
fn an_external_commit_that_moves_head_holds_before_any_attempt() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let case = required_case(&harness, 23, "docs/adr/0023.md", "# 23\n");

    // After the intent fixed its expected parent, another process commits.
    harness.repo.write("README.md", "changed elsewhere\n");
    run_git(&harness.repo.root, &["add", "--", "README.md"]);
    run_git_without_hooks(&harness.repo.root, &["commit", "-q", "-m", "external"]);
    let external_head = harness.repo.head();
    let count = harness.repo.commit_count();

    let outcome = harness.finalize(&case.request).expect("finalize");
    match outcome {
        TaskFinalizeOutcome::Held {
            stop: FinalizeStop::Rejected(GitRejection::ConcurrentEdit),
            ..
        } => {}
        other => panic!("a moved HEAD must hold, got {other:?}"),
    }
    assert_eq!(harness.repo.head(), external_head);
    assert_eq!(harness.repo.commit_count(), count, "no commit is added");
}

#[test]
fn the_desktop_commit_half_holds_on_a_staged_change_or_an_unrelated_change() {
    // 1. Someone else staged a path before the Task's commit half runs.
    let harness = Harness::new();
    harness.repo.write("docs/adr/0024.md", "# 24\n");
    harness.repo.write("notes.txt", "someone else\n");
    run_git(&harness.repo.root, &["add", "--", "notes.txt"]);
    harness.repo.accepting_hook();
    let data = tempfile::tempdir().expect("data");
    let store = Store::open(StoreConfig::new(data.path()).expect("config")).expect("store");
    let handle = herness_desktop::supervision::store::StoreHandle::new(Arc::new(Mutex::new(store)));
    let mut commit = DesktopHostCommit::new(
        handle,
        harness.boundary(),
        harness.observer(),
        identity(&harness.repo, harness.project),
    );
    commit.bind_task(TaskCommitExpectation::new(
        task_ref(harness.project, 1),
        "commit Task 1",
        CommitPolicy::Required,
        vec!["docs/adr".to_owned()],
        Baseline::parse(harness.repo.head()).expect("base"),
        20,
    ));
    let mut completion = HtmlBarrierCompletion::with_commit(
        SyncedGate {
            derived: Vec::new(),
        },
        commit,
    );
    let head = harness.repo.head();
    let count = harness.repo.commit_count();
    match TaskCompletionPort::complete(&mut completion, &completion_request(harness.project, 1))
        .expect("completion")
    {
        TaskCompletion::HumanWait { stop } => {
            assert_eq!(stop.reason(), StopReason::Conflict);
            assert_eq!(stop.required_action(), Some(HumanAction::ResolveConflict));
        }
        other => panic!("a staged change must hold, got {other:?}"),
    }
    assert_eq!(harness.repo.head(), head);
    assert_eq!(harness.repo.commit_count(), count);
    assert!(
        harness.repo.is_staged("notes.txt"),
        "the other work is never discarded"
    );

    // 2. A change outside the approved write scope outside the index.
    let harness = Harness::new();
    harness.repo.write("docs/adr/0025.md", "# 25\n");
    harness.repo.write("src/main.rs", "fn main() {}\n");
    harness.repo.accepting_hook();
    let data = tempfile::tempdir().expect("data");
    let store = Store::open(StoreConfig::new(data.path()).expect("config")).expect("store");
    let handle = herness_desktop::supervision::store::StoreHandle::new(Arc::new(Mutex::new(store)));
    let mut commit = DesktopHostCommit::new(
        handle,
        harness.boundary(),
        harness.observer(),
        identity(&harness.repo, harness.project),
    );
    commit.bind_task(TaskCommitExpectation::new(
        task_ref(harness.project, 1),
        "commit Task 1",
        CommitPolicy::Required,
        vec!["docs/adr".to_owned()],
        Baseline::parse(harness.repo.head()).expect("base"),
        20,
    ));
    let mut completion = HtmlBarrierCompletion::with_commit(
        SyncedGate {
            derived: Vec::new(),
        },
        commit,
    );
    let head = harness.repo.head();
    match TaskCompletionPort::complete(&mut completion, &completion_request(harness.project, 1))
        .expect("completion")
    {
        TaskCompletion::HumanWait { stop } => {
            assert_eq!(stop.reason(), StopReason::Conflict);
        }
        other => panic!("an unrelated change must hold, got {other:?}"),
    }
    assert_eq!(harness.repo.head(), head);
    assert!(!harness.repo.is_staged("src/main.rs"));
}

#[test]
fn the_recorded_result_is_a_second_gate_on_the_recovery_classification() {
    let mut harness = Harness::new();
    harness.repo.accepting_hook();
    let change = harness.repo.write("docs/adr/0026.md", "# 26\n");
    let targets = vec![target(
        "docs/adr/0026.md",
        &change,
        TargetOrigin::TaskChange,
    )];
    let request = commit_request(
        &harness.repo,
        harness.project,
        26,
        CommitPolicy::Required,
        targets.clone(),
        Vec::new(),
        Vec::new(),
        pre_hook(&targets),
    )
    .expect("request");
    let intent = request.intent().expect("intent");
    let outcome = harness.finalize(&request).expect("finalize");
    let journal = outcome.journal().expect("journal").clone();
    let recorded = journal.outcome().expect("recorded outcome");
    let mut observer = harness.observer();
    let observation = observer
        .observe(&request.observation_request())
        .expect("observation");

    assert!(matches!(
        herness_sdd_execute::classify_recorded(&intent, Some(recorded), &observation),
        CommitRecovery::Established { .. }
    ));

    // A recorded result naming another commit is not established even though
    // the checkout itself still matches the intent's trailers and paths.
    let mut other = match recorded.clone() {
        GitCommitOutcome::Committed {
            tree,
            parent,
            commit: _,
        } => GitCommitOutcome::Committed {
            commit: CommitSha::parse("e".repeat(40)).expect("commit"),
            tree,
            parent,
        },
        other => other,
    };
    assert!(matches!(
        herness_sdd_execute::classify_recorded(&intent, Some(&other), &observation),
        CommitRecovery::Unknown { .. }
    ));
    other = GitCommitOutcome::Unknown {
        reason: GitUnknownReason::Timeout,
    };
    // An unknown that the checkout now shows as the saved commit is exactly what
    // a human recovery reconciles: the classification is `Established`, but the
    // ledger links it only after the human confirms.
    assert!(matches!(
        herness_sdd_execute::classify_recorded(&intent, Some(&other), &observation),
        CommitRecovery::Established { .. }
    ));

    // With the correct recorded result the comparison is established.
    assert!(matches!(
        herness_sdd_execute::classify_recorded(&intent, Some(recorded), &observation),
        CommitRecovery::Established { .. }
    ));
}
