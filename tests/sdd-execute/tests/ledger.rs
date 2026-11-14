//! Task 18: the compatibility ledger, the finish handoff, and the
//! `ready_for_finish` decision.
//!
//! # The pack under test
//!
//! The accept cases run the **real** pack parsers from an SDD pack checkout:
//! `sddlib.ledger.parse_ledger` / `extract_baseline` and `scripts/stack-prs
//! --dry-run`. The pack root is resolved from `SDD_PACK_ROOT`, defaulting to
//! `/Users/h-uma/Documents/sdd/.worktrees/h4-exec`, and every run prints the
//! resolved root so its evidence names the pack it used. A missing pack fails
//! with the resolved path instead of skipping.
//!
//! # Real state
//!
//! Every case uses a real temporary directory, a real SQLite store in a
//! temporary application-data root, and — for the stacked-PR preflight — a real
//! Git repository with real commits. Nothing is pushed, merged, published,
//! rebased, amended, reset, or cleaned. No network, provider, credential,
//! model, or GUI is used.
//!
//! # Acceptance map
//!
//! * The emitted ledger is accepted by the real pack parser, byte for byte:
//!   [`emitted_ledger_is_accepted_by_the_real_pack_parser`].
//! * Idempotent bytes: [`rendering_the_same_state_twice_is_byte_identical`],
//!   [`a_second_write_of_the_same_state_is_unchanged`].
//! * `no_change` renders an empty range and the stacked preflight refuses:
//!   [`no_change_renders_an_empty_range_and_breaks_stacked_prs`].
//! * A fully-required ledger passes `stack-prs --dry-run`:
//!   [`all_required_tasks_pass_the_real_stacked_pr_preflight`].
//! * Output fault holds the next Task:
//!   [`a_denied_write_holds_the_next_task`],
//!   [`a_failed_replace_holds_the_next_task`].
//! * External modification is refused, never overwritten:
//!   [`an_externally_edited_ledger_is_refused`],
//!   [`a_change_between_plan_and_replace_is_refused`].
//! * The baseline and every recorded range survive a hold:
//!   [`a_hold_never_changes_the_baseline_or_a_recorded_range`].
//! * `ready_for_finish` needs current evidence and spec reflection:
//!   [`ready_only_with_current_final_evidence_and_spec_reflection`],
//!   [`stale_full_suite_evidence_is_not_ready`],
//!   [`a_post_commit_change_makes_the_evidence_stale`],
//!   [`a_missing_spec_reflection_with_a_later_phase_is_not_ready`].
//! * The handoff carries every required field and grants no side effect:
//!   [`the_handoff_carries_every_finish_field_and_no_side_effect`].

use std::path::{Path, PathBuf};
use std::process::Command;

use herness_core::contracts::ProjectId;
use herness_desktop::sdd_execute::{DesktopProgressLedger, ProgressWriteResult, write_and_hold};
use herness_sdd_execute::{
    AppliedRevision, Baseline, CheckEvidence, CommitPolicy, CommitRange, CommitSha, EvidenceField,
    EvidenceItem, ExecutionId, ExecutionRevision, ExecutionSnapshot, ExecutionState,
    FinalStateObservation, FinishBlocker, FinishDecision, FinishInputs, LedgerConflict,
    LedgerInput, LedgerWorktree, NoChangeRecord, PlanDigest, PlanPath, PlanRevision,
    ProgressJournalId, ProgressLedgerOutcome, ProgressTaskLine, ProgressWriteRequest, Ruling,
    Sha256Digest, SnapshotBudget, SnapshotInput, SnapshotPlan, SpecReflection, TaskArtifacts,
    TaskNumber, TaskPhase, TaskRef, TaskSnapshot, TaskStableId, decide, plan_write, render,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::EvidenceId;
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// The pack
// ---------------------------------------------------------------------------

/// The documented default pack checkout, overridable with `SDD_PACK_ROOT`.
const DEFAULT_PACK_ROOT: &str = "/Users/h-uma/Documents/sdd/.worktrees/h4-exec";

fn pack_root() -> PathBuf {
    let root = std::env::var_os("SDD_PACK_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PACK_ROOT));
    let script = root.join("scripts/stack-prs");
    assert!(
        script.is_file(),
        "no SDD pack at {}. Set SDD_PACK_ROOT to a pack checkout that has \
         scripts/stack-prs (documented default {DEFAULT_PACK_ROOT}).",
        script.display()
    );
    eprintln!("ledger tests: SDD pack root = {}", root.display());
    root
}

fn python() -> String {
    for candidate in [
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/usr/bin/python3",
    ] {
        if Path::new(candidate).is_file() {
            return candidate.to_owned();
        }
    }
    let output = Command::new("/usr/bin/which")
        .arg("python3")
        .output()
        .expect("which python3");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// One parsed `TaskComplete` triple, as the real pack parser reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTask {
    number: i64,
    base: String,
    head: String,
}

/// Runs the real `sddlib.ledger` parser over one document.
fn parse_with_real_pack(path: &Path) -> (Vec<ParsedTask>, Option<String>) {
    let root = pack_root();
    let scripts = root.join("scripts");
    let script = format!(
        "import sys\n\
         sys.path.insert(0, {scripts:?})\n\
         from sddlib.ledger import parse_ledger, extract_baseline\n\
         with open({path:?}, encoding='utf-8') as handle:\n\
         \x20   text = handle.read()\n\
         items = parse_ledger(text)\n\
         print('TASKS=' + repr([(i.number, i.base, i.head) for i in items]))\n\
         print('BASELINE=' + repr(extract_baseline(text)))\n",
        scripts = scripts.to_string_lossy(),
        path = path.to_string_lossy(),
    );
    let output = Command::new(python())
        .args(["-c", &script])
        .output()
        .expect("python3 starts");
    assert!(
        output.status.success(),
        "the real pack parser failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    eprintln!("real pack parse of {}:\n{stdout}", path.display());
    let tasks = stdout
        .lines()
        .find_map(|line| line.strip_prefix("TASKS="))
        .expect("the parser printed its tasks");
    let baseline = stdout
        .lines()
        .find_map(|line| line.strip_prefix("BASELINE="))
        .expect("the parser printed the baseline");
    let tasks = parse_tuples(tasks);
    let baseline = baseline.trim();
    let baseline = (baseline != "None").then(|| baseline.trim_matches('\'').to_owned());
    (tasks, baseline)
}

/// Parses Python's `[(1, 'aaa', 'bbb'), ...]` repr without a Python bridge.
fn parse_tuples(text: &str) -> Vec<ParsedTask> {
    let mut tasks = Vec::new();
    let body = text.trim().trim_start_matches('[').trim_end_matches(']');
    if body.trim().is_empty() {
        return tasks;
    }
    for item in split_top_level(body) {
        let inner = item.trim().trim_start_matches('(').trim_end_matches(')');
        let parts = split_top_level(inner);
        assert_eq!(parts.len(), 3, "a TaskComplete has three fields: {item:?}");
        let number = parts[0].trim().parse().expect("a Task number");
        let base = parts[1].trim().trim_matches('\'').to_owned();
        let head = parts[2].trim().trim_matches('\'').to_owned();
        tasks.push(ParsedTask { number, base, head });
    }
    tasks
}

fn split_top_level(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (index, character) in text.char_indices() {
        match character {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&text[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CHECKOUT_PLACEHOLDER: &str = "/tmp/herness-h4-ledger-fixture";
const BRANCH: &str = "h4-ledger";
const BASE_BRANCH: &str = "main";
const PLAN_PATH: &str = "docs/sdd/plans/2026-11-13-ledger-fixture.md";
const SPEC_PATH: &str = "docs/sdd/specs/2026-11-13-ledger-fixture.md";

fn project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("a4000000-0000-4000-8000-000000000018").unwrap())
}

fn execution(project: ProjectId) -> ExecutionId {
    ExecutionId::from_parts(
        project,
        Uuid::parse_str("b4000000-0000-4000-8000-000000000018").unwrap(),
    )
}

fn sha(seed: u8) -> String {
    let hex = format!("{seed:02x}");
    hex.repeat(20)
}

fn baseline() -> Baseline {
    Baseline::parse(sha(0x11)).expect("baseline")
}

fn commit(seed: u8) -> CommitSha {
    CommitSha::parse(sha(seed)).expect("commit")
}

fn plan_path() -> PlanPath {
    PlanPath::parse(PLAN_PATH).expect("plan path")
}

fn plan_revision() -> PlanRevision {
    PlanRevision::new(1).expect("plan revision")
}

fn task_ref(project: ProjectId, number: u32) -> TaskRef {
    TaskRef::new(
        TaskStableId::from_parts(
            project,
            Uuid::from_u128(0x4400_0000_0000_4000_8000_0000_0000_0000 + u128::from(number)),
        ),
        TaskNumber::new(number).expect("Task number"),
    )
}

fn evidence(project: ProjectId, local: u128) -> EvidenceId {
    EvidenceId::from_parts(project, Uuid::from_u128(local))
}

fn progress_request(project: ProjectId) -> ProgressJournalId {
    ProgressJournalId::from_parts(
        project,
        Uuid::parse_str("64000000-0000-4000-8000-000000000018").unwrap(),
    )
}

/// One Task's completion in a fixture snapshot.
#[derive(Debug, Clone, Copy)]
enum Completion {
    Pending,
    Active,
    Range(u8, u8),
    NoChange,
}

fn task_snapshot(
    project: ProjectId,
    number: u32,
    completion: Completion,
    state: TaskPhase,
) -> TaskSnapshot {
    let (policy, range, no_change) = match completion {
        Completion::Pending | Completion::Active => (CommitPolicy::Required, None, None),
        Completion::Range(base, head) => (
            CommitPolicy::Required,
            Some(CommitRange::new(baseline_for(base), commit(head)).expect("range")),
            None,
        ),
        Completion::NoChange => (
            CommitPolicy::NoChange,
            None,
            Some(
                NoChangeRecord::new(
                    true,
                    vec![evidence(project, 0x9900 + u128::from(number))],
                    None,
                )
                .expect("no-change record"),
            ),
        ),
    };
    TaskSnapshot::new(
        task_ref(project, number),
        state.implied_progression(),
        state,
        None,
        None,
        policy,
        range,
        no_change,
        if matches!(completion, Completion::Range(..) | Completion::NoChange) {
            vec![evidence(project, 0x8800 + u128::from(number))]
        } else {
            Vec::new()
        },
        None,
        AppliedRevision::current(plan_revision()),
    )
    .expect("Task snapshot")
}

/// A commit range base: the previous Task's head, or the fixed baseline.
fn baseline_for(seed: u8) -> Baseline {
    if seed == 0x11 {
        baseline()
    } else {
        Baseline::parse(sha(seed)).expect("range base")
    }
}

fn snapshot(
    project: ProjectId,
    state: ExecutionState,
    completions: &[Completion],
    current: Option<u32>,
) -> ExecutionSnapshot {
    let execution = execution(project);
    let tasks = completions
        .iter()
        .enumerate()
        .map(|(index, completion)| {
            let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
            let phase = match completion {
                Completion::Pending => TaskPhase::Ready,
                Completion::Active => TaskPhase::Running,
                Completion::Range(..) | Completion::NoChange => TaskPhase::Complete,
            };
            task_snapshot(project, number, *completion, phase)
        })
        .collect();
    ExecutionSnapshot::new(SnapshotInput {
        project_id: project,
        execution_id: execution,
        revision: ExecutionRevision::INITIAL,
        state,
        plan: SnapshotPlan::new(plan_path(), PlanDigest::sha256(b"# plan"), plan_revision()),
        workspace: SnapshotWorkspaceFixture::build(),
        current_task: current.map(|number| task_ref(project, number)),
        tasks,
        stop: None,
        budget: SnapshotBudget::new(
            herness_sdd_execute::BudgetConsumption::zero(),
            herness_sdd_execute::BudgetConsumption::zero(),
        ),
        applied_revision: AppliedRevision::current(plan_revision()),
        final_project_sequence: None,
    })
    .expect("snapshot")
}

struct SnapshotWorkspaceFixture;

impl SnapshotWorkspaceFixture {
    fn build() -> herness_sdd_execute::SnapshotWorkspace {
        herness_sdd_execute::SnapshotWorkspace::new(
            CHECKOUT_PLACEHOLDER,
            BRANCH,
            BASE_BRANCH,
            Some(baseline()),
        )
        .expect("snapshot workspace")
    }
}

fn ledger_input(project: ProjectId, completions: &[Completion]) -> LedgerInput {
    let completed = completions
        .iter()
        .enumerate()
        .filter_map(|(index, completion)| {
            let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
            match completion {
                Completion::Range(base, head) => Some(
                    ProgressTaskLine::new(
                        task_ref(project, number),
                        Some(CommitRange::new(baseline_for(*base), commit(*head)).expect("range")),
                        false,
                    )
                    .expect("line"),
                ),
                Completion::NoChange => Some(
                    ProgressTaskLine::new(task_ref(project, number), None, true).expect("line"),
                ),
                Completion::Pending | Completion::Active => None,
            }
        })
        .collect();
    LedgerInput::new(
        LedgerWorktree::Created(CHECKOUT_PLACEHOLDER.to_owned()),
        BRANCH,
        baseline(),
        completed,
        vec![
            Ruling::new("pick names", "clarity", "low").expect("ruling"),
            Ruling::new("keep order", "spec fixes it", "one row").expect("ruling"),
        ],
    )
    .expect("ledger input")
}

fn workspace() -> (TempDir, DesktopProgressLedger) {
    let temp = tempfile::tempdir().expect("temporary directory");
    let ledger = DesktopProgressLedger::new(temp.path()).expect("ledger writer");
    (temp, ledger)
}

/// A real SQLite store whose application-data directory outlives it.
struct TestStore {
    _data: TempDir,
    store: Store,
}

impl TestStore {
    fn new() -> Self {
        let data = tempfile::tempdir().expect("application data");
        let store = Store::open(StoreConfig::new(data.path()).expect("config")).expect("store");
        Self { _data: data, store }
    }
}

fn request(
    project: ProjectId,
    input: LedgerInput,
    revision: ExecutionRevision,
) -> ProgressWriteRequest {
    let identity = herness_sdd_execute::RequestIdentity::<herness_sdd_execute::ProgressKind>::new(
        project,
        execution(project),
        progress_request(project),
        revision,
    )
    .expect("identity");
    ProgressWriteRequest::new(identity, input, ".sdd/progress.md").expect("request")
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

#[test]
fn emitted_ledger_is_accepted_by_the_real_pack_parser() {
    let project = project();
    let (temp, mut ledger) = workspace();
    let input = ledger_input(
        project,
        &[Completion::Range(0x11, 0x22), Completion::Range(0x22, 0x33)],
    );
    let rendered = render(&input).expect("render");
    let mut harness = TestStore::new();
    let store = &mut harness.store;
    let request = request(project, input, ExecutionRevision::INITIAL);
    let outcome = herness_sdd_execute::write_progress(store, &mut ledger, &request).expect("write");
    assert!(matches!(outcome, ProgressLedgerOutcome::Written { .. }));
    let path = temp.path().join(".sdd/progress.md");
    let text = std::fs::read_to_string(&path).expect("the document");

    // The exact compatibility shape.
    assert!(text.starts_with("# SDD Progress\n"), "{text}");
    assert!(
        text.contains(&format!("Worktree: created {CHECKOUT_PLACEHOLDER}\n")),
        "{text}"
    );
    assert!(text.contains(&format!("Branch: {BRANCH}\n")), "{text}");
    assert!(
        text.contains(&format!("Branch baseline: {}\n", baseline())),
        "the baseline is printed in full: {text}"
    );
    assert!(
        text.contains(&format!(
            "Task 1: complete (commits {}..{})\n",
            &sha(0x11)[..7],
            &sha(0x22)[..7]
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "Task 2: complete (commits {}..{})\n",
            &sha(0x22)[..7],
            &sha(0x33)[..7]
        )),
        "{text}"
    );
    assert!(
        text.contains("Ruling: pick names — clarity — low\n"),
        "{text}"
    );

    let (tasks, parsed_baseline) = parse_with_real_pack(&path);
    assert_eq!(
        tasks,
        vec![
            ParsedTask {
                number: 1,
                base: sha(0x11)[..7].to_owned(),
                head: sha(0x22)[..7].to_owned(),
            },
            ParsedTask {
                number: 2,
                base: sha(0x22)[..7].to_owned(),
                head: sha(0x33)[..7].to_owned(),
            },
        ],
        "the real pack parser accepts the emitted TaskComplete list"
    );
    assert_eq!(parsed_baseline.as_deref(), Some(baseline().as_str()));

    // The durable row records exactly the bytes on disk.
    let stored = store
        .sdd_progress_entry(project, execution(project), progress_request(project))
        .expect("stored entry")
        .expect("a stored progress row");
    let digest = Sha256Digest::sha256(&std::fs::read(&path).expect("bytes"));
    assert_eq!(
        stored.outcome(),
        Some(&herness_sdd_execute::ProgressWriteOutcome::Written {
            digest: digest.clone()
        })
    );
    assert_eq!(stored.content().document_digest(), &digest);
    assert!(rendered.digest() == &digest);
}

#[test]
fn rendering_the_same_state_twice_is_byte_identical() {
    let project = project();
    let completions = [
        Completion::Range(0x11, 0x22),
        Completion::NoChange,
        Completion::Range(0x22, 0x44),
    ];
    let first = render(&ledger_input(project, &completions)).expect("render");
    let second = render(&ledger_input(project, &completions)).expect("render");
    assert_eq!(first.text(), second.text());
    assert_eq!(first.digest(), second.digest());
    // Tasks 3's range base is the previous recorded head (0x22), because a
    // no_change Task consumes no range and never fabricates one.
    assert!(
        first
            .text()
            .contains("Task 3: complete (commits 2222222..4444444)\n")
    );
}

#[test]
fn non_contiguous_ranges_are_refused_and_never_rendered() {
    let project = project();
    // Task 2 starts from the wrong base.
    let completed = vec![
        ProgressTaskLine::new(
            task_ref(project, 1),
            Some(CommitRange::new(baseline(), commit(0x22)).expect("range")),
            false,
        )
        .expect("line"),
        ProgressTaskLine::new(
            task_ref(project, 2),
            Some(CommitRange::new(baseline_for(0x33), commit(0x44)).expect("range")),
            false,
        )
        .expect("line"),
    ];
    let input = LedgerInput::new(
        LedgerWorktree::InPlace,
        BRANCH,
        baseline(),
        completed,
        Vec::new(),
    )
    .expect("input");
    let error = render(&input).expect_err("a discontinuous chain is refused");
    assert!(error.to_string().contains("does not continue"), "{error}");
}

#[test]
fn task_artifact_paths_follow_the_pack_layout() {
    let artifacts = TaskArtifacts::new(18).expect("artifacts");
    assert_eq!(artifacts.brief_path(), ".sdd/briefs/task-18-brief.md");
    assert_eq!(artifacts.report_path(), ".sdd/reports/task-18-report.md");
    assert_eq!(
        herness_sdd_execute::execution_brief_path(3),
        ".sdd/briefs/task-3-brief.md"
    );
    assert_eq!(
        herness_sdd_execute::PROGRESS_LEDGER_PATH,
        ".sdd/progress.md"
    );
    assert!(TaskArtifacts::new(0).is_err());
}

#[test]
fn the_brief_file_is_written_atomically_and_never_overwritten() {
    let (temp, ledger) = workspace();
    let artifacts = TaskArtifacts::new(18).expect("artifacts");
    herness_desktop::sdd_execute::write_task_brief(
        &ledger,
        artifacts.brief_path(),
        "## Task 18: the fixture brief\n\nbody\n",
    )
    .expect("brief written");
    let path = temp.path().join(".sdd/briefs/task-18-brief.md");
    assert_eq!(
        std::fs::read_to_string(&path).expect("brief"),
        "## Task 18: the fixture brief\n\nbody\n"
    );
    // Writing the same body again is idempotent.
    herness_desktop::sdd_execute::write_task_brief(
        &ledger,
        artifacts.brief_path(),
        "## Task 18: the fixture brief\n\nbody\n",
    )
    .expect("identical brief");
    // A different body is refused: the host never overwrites a brief it did not
    // produce for this Task.
    let error = herness_desktop::sdd_execute::write_task_brief(
        &ledger,
        artifacts.brief_path(),
        "another body\n",
    )
    .expect_err("a different brief is refused");
    eprintln!("brief refusal: {error}");
    assert!(error.to_string().contains("does not overwrite"), "{error}");

    // A path escape is refused before any file is created.
    let escape = herness_desktop::sdd_execute::write_task_brief(&ledger, "../escape.md", "x");
    assert!(escape.is_err());
    assert!(temp.path().parent().is_some());
    assert!(
        !temp
            .path()
            .join(".sdd/briefs/task-18-brief.md.tmp")
            .exists()
    );
}

// ---------------------------------------------------------------------------
// no_change and the stacked preflight
// ---------------------------------------------------------------------------

#[test]
fn no_change_renders_an_empty_range_and_breaks_stacked_prs() {
    let project = project();
    let (temp, mut ledger) = workspace();
    let completions = [Completion::Range(0x11, 0x22), Completion::NoChange];
    let input = ledger_input(project, &completions);
    let rendered = render(&input).expect("render");
    assert!(
        rendered.text().contains("Task 2: complete (no_change)\n"),
        "{}",
        rendered.text()
    );
    assert!(
        !rendered.text().contains("Task 2: complete (commits"),
        "no range is invented for a no_change Task: {}",
        rendered.text()
    );
    let notice = rendered
        .stacked_pr_incompatibility()
        .expect("the incompatibility is explicit");
    eprintln!("stacked-PR notice: {notice}");
    assert!(notice.contains("Task 2"), "{notice}");
    assert!(notice.contains("scripts/stack-prs"), "{notice}");

    let mut harness = TestStore::new();
    let store = &mut harness.store;
    let request = request(project, input, ExecutionRevision::INITIAL);
    herness_sdd_execute::write_progress(store, &mut ledger, &request).expect("write");
    let path = temp.path().join(".sdd/progress.md");
    let (tasks, _) = parse_with_real_pack(&path);
    assert_eq!(
        tasks,
        vec![ParsedTask {
            number: 1,
            base: sha(0x11)[..7].to_owned(),
            head: sha(0x22)[..7].to_owned(),
        }],
        "the pack parser sees only the Task with a non-empty range"
    );

    // The real stacked preflight refuses: the ledger has fewer Tasks than the
    // plan, and the no_change Task has no non-empty range to chart.
    let repo = GitRepo::with_two_tasks();
    let plan = repo.write_plan(&["Task 1: One", "Task 2: Two"]);
    let ledger_target = repo.root().join(".sdd/progress.md");
    std::fs::create_dir_all(repo.root().join(".sdd")).expect(".sdd");
    std::fs::copy(&path, &ledger_target).expect("copy the emitted ledger");
    let (code, stdout, stderr) = repo.stack_prs_dry_run(&plan, &ledger_target);
    eprintln!(
        "stack-prs --dry-run with a no_change Task: exit {code}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        code, 1,
        "stacked PRs are incompatible with the no_change range"
    );
    assert!(
        stderr.contains("ledger tasks [1] do not match plan tasks [1, 2]"),
        "the preflight names the incompatibility: {stderr}"
    );
    // Dry run must not create a ref.
    assert!(!repo.has_ref("sdd-stack/task-1"));
}

#[test]
fn all_required_tasks_pass_the_real_stacked_pr_preflight() {
    let project = project();
    let repo = GitRepo::with_two_tasks();
    let (c0, c1, c2) = (repo.commit(0), repo.commit(1), repo.commit(2));
    let base = Baseline::parse(&c0).expect("baseline");
    let completed = vec![
        ProgressTaskLine::new(
            task_ref(project, 1),
            Some(
                CommitRange::new(base.clone(), CommitSha::parse(&c1).expect("c1")).expect("range"),
            ),
            false,
        )
        .expect("line"),
        ProgressTaskLine::new(
            task_ref(project, 2),
            Some(
                CommitRange::new(
                    Baseline::parse(&c1).expect("c1"),
                    CommitSha::parse(&c2).expect("c2"),
                )
                .expect("range"),
            ),
            false,
        )
        .expect("line"),
    ];
    let input = LedgerInput::new(
        LedgerWorktree::Created(repo.root().to_string_lossy().into_owned()),
        BRANCH,
        base,
        completed,
        Vec::new(),
    )
    .expect("input");
    let rendered = render(&input).expect("render");
    assert!(rendered.stacked_pr_incompatibility().is_none());
    let ledger_target = repo.root().join(".sdd/progress.md");
    std::fs::create_dir_all(repo.root().join(".sdd")).expect(".sdd");
    std::fs::write(&ledger_target, rendered.text()).expect("ledger");
    let plan = repo.write_plan(&["Task 1: One", "Task 2: Two"]);

    let (tasks, parsed_baseline) = parse_with_real_pack(&ledger_target);
    assert_eq!(tasks.len(), 2);
    assert_eq!(parsed_baseline.as_deref(), Some(c0.as_str()));

    let (code, stdout, stderr) = repo.stack_prs_dry_run(&plan, &ledger_target);
    eprintln!("stack-prs --dry-run exit {code}\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        code, 0,
        "the read-only preflight accepts the handoff ledger"
    );
    assert!(stdout.contains("sdd-stack/task-1 base=main"), "{stdout}");
    assert!(
        stdout.contains("sdd-stack/task-2 base=sdd-stack/task-1"),
        "{stdout}"
    );
    // Dry run performed no side effect: no new branch, no remote work.
    assert!(!repo.has_ref("sdd-stack/task-1"));
    assert!(!repo.has_ref("sdd-stack/task-2"));
    assert!(repo.remotes().is_empty(), "nothing is pushed anywhere");
}

// ---------------------------------------------------------------------------
// Output faults
// ---------------------------------------------------------------------------

#[test]
fn a_denied_write_holds_the_next_task() {
    let project = project();
    let (temp, ledger) = workspace();
    let mut ledger = ledger;
    let mut harness = TestStore::new();
    let store = &mut harness.store;
    let snapshot = snapshot(
        project,
        ExecutionState::Running,
        &[Completion::Active, Completion::Pending],
        Some(1),
    );
    store
        .compare_and_swap_execution(project, execution(project), None, &snapshot)
        .expect("stored snapshot");

    // Make the document directory read-only so the temporary file cannot be
    // created. The destination itself does not exist yet.
    let directory = temp.path().join(".sdd");
    std::fs::create_dir_all(&directory).expect(".sdd");
    let mut permissions = std::fs::metadata(&directory)
        .expect("metadata")
        .permissions();
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o555);
    std::fs::set_permissions(&directory, permissions).expect("read-only directory");

    let request = request(
        project,
        ledger_input(project, &[Completion::Active]),
        ExecutionRevision::INITIAL,
    );
    let result: ProgressWriteResult =
        write_and_hold(store, &mut ledger, &request, &snapshot).expect("gated write");
    eprintln!("denied write: {result:?}");

    assert!(result.held(), "the next Task is held");
    assert!(!result.may_continue());
    assert!(matches!(
        result.outcome(),
        ProgressLedgerOutcome::HumanWait {
            reason: herness_sdd_execute::ProgressHoldReason::TemporaryFileFailed,
            ..
        }
    ));
    assert_eq!(result.revision(), ExecutionRevision::INITIAL.next());

    // The hold is durable and names the reason.
    let stored = store
        .load_sdd_execution(project, execution(project))
        .expect("load")
        .expect("stored");
    assert_eq!(stored.snapshot().state(), ExecutionState::WaitingHuman);
    let stop = stored.snapshot().stop().expect("a stop record");
    assert_eq!(
        stop.reason(),
        herness_sdd_execute::StopReason::InternalFailure
    );
    assert_eq!(
        stop.required_action(),
        Some(herness_sdd_execute::HumanAction::ResolveInternalFailure)
    );

    // Task 2 is still pending: the next Task never started.
    assert_eq!(
        stored
            .snapshot()
            .task(TaskNumber::new(2).expect("number"))
            .map(TaskSnapshot::progression),
        Some(herness_sdd_execute::TaskProgression::Pending)
    );
    // No document was written.
    assert!(!temp.path().join(".sdd/progress.md").exists());
    // No temporary file is left behind.
    let leftovers: Vec<String> = std::fs::read_dir(&directory)
        .expect("directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temporary file remains: {leftovers:?}"
    );

    // Restore the permissions so the temporary directory can be cleaned up.
    let mut permissions = std::fs::metadata(&directory)
        .expect("metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&directory, permissions).expect("restore");
}

#[test]
fn a_failed_replace_holds_the_next_task() {
    let project = project();
    let (temp, mut ledger) = workspace();
    let mut harness = TestStore::new();
    let store = &mut harness.store;
    let snapshot = snapshot(
        project,
        ExecutionState::Verifying,
        &[Completion::Active, Completion::Pending],
        Some(1),
    );
    store
        .compare_and_swap_execution(project, execution(project), None, &snapshot)
        .expect("stored snapshot");

    // A directory occupies the document path, so the atomic replacement cannot
    // succeed. The host refuses before deleting or truncating anything.
    let destination = temp.path().join(".sdd/progress.md");
    std::fs::create_dir_all(&destination).expect("directory at the document path");

    let request = request(
        project,
        ledger_input(project, &[Completion::Active]),
        ExecutionRevision::INITIAL,
    );
    let result = write_and_hold(store, &mut ledger, &request, &snapshot).expect("gated write");
    eprintln!("failed replace: {result:?}");
    assert!(result.held());
    assert!(matches!(
        result.outcome(),
        ProgressLedgerOutcome::HumanWait {
            reason: herness_sdd_execute::ProgressHoldReason::ReplaceFailed,
            ..
        }
    ));
    // The obstructing path is untouched: the host never removes it.
    assert!(destination.is_dir());
    let stored = store
        .load_sdd_execution(project, execution(project))
        .expect("load")
        .expect("stored");
    assert_eq!(stored.snapshot().state(), ExecutionState::WaitingHuman);
    assert_eq!(
        stored
            .snapshot()
            .task(TaskNumber::new(2).expect("number"))
            .map(TaskSnapshot::progression),
        Some(herness_sdd_execute::TaskProgression::Pending)
    );
}

// ---------------------------------------------------------------------------
// External modification
// ---------------------------------------------------------------------------

#[test]
fn an_externally_edited_ledger_is_refused() {
    let project = project();
    let (temp, mut ledger) = workspace();
    let mut harness = TestStore::new();
    let store = &mut harness.store;
    let snapshot = snapshot(
        project,
        ExecutionState::Running,
        &[Completion::Active, Completion::Pending],
        Some(1),
    );
    store
        .compare_and_swap_execution(project, execution(project), None, &snapshot)
        .expect("stored snapshot");

    // Another execution's ledger already sits at the path.
    let path = temp.path().join(".sdd/progress.md");
    std::fs::create_dir_all(path.parent().expect("parent")).expect(".sdd");
    let foreign = format!(
        "# SDD Progress\n\nWorktree: in-place\nBranch: other\nBranch baseline: {}\n\n\
         Task 1: complete (commits aaaaaaa..bbbbbbb)\n",
        sha(0x99)
    );
    std::fs::write(&path, &foreign).expect("foreign ledger");

    let input = ledger_input(
        project,
        &[Completion::Range(0x11, 0x22), Completion::Pending],
    );
    let rendered = render(
        &LedgerInput::new(
            LedgerWorktree::Created(CHECKOUT_PLACEHOLDER.to_owned()),
            BRANCH,
            baseline(),
            input.completed().to_vec(),
            input.rulings().to_vec(),
        )
        .expect("render input"),
    )
    .expect("render");
    // The plan decision itself refuses a different baseline before any write.
    let planned = plan_write(&rendered, Some(foreign.as_bytes()));
    assert_eq!(
        planned,
        Err(LedgerConflict::BaselineChanged {
            recorded: sha(0x99),
            rendered: baseline().to_string(),
        })
    );

    let request = request(project, input, ExecutionRevision::INITIAL);
    let result = write_and_hold(store, &mut ledger, &request, &snapshot).expect("gated write");
    eprintln!("external ledger refusal: {result:?}");
    assert!(result.held());
    assert!(matches!(
        result.outcome(),
        ProgressLedgerOutcome::HumanWait {
            reason: herness_sdd_execute::ProgressHoldReason::Conflict(
                LedgerConflict::BaselineChanged { .. }
            ),
            ..
        }
    ));
    // The foreign document is untouched, byte for byte.
    assert_eq!(std::fs::read_to_string(&path).expect("bytes"), foreign);
    let stored = store
        .load_sdd_execution(project, execution(project))
        .expect("load")
        .expect("stored");
    assert_eq!(stored.snapshot().state(), ExecutionState::WaitingHuman);

    // A hand-edited completion range in this execution's own ledger is refused
    // too: the host never rewrites a recorded range.
    let edited = rendered.text().replacen(
        &format!("{}..{}", &sha(0x11)[..7], &sha(0x22)[..7]),
        "1234567..89abcde",
        1,
    );
    assert_ne!(edited, rendered.text());
    assert_eq!(
        plan_write(&rendered, Some(edited.as_bytes())),
        Err(LedgerConflict::CompletionRangeChanged {
            task: 1,
            recorded: "Task 1: complete (commits 1234567..89abcde)".to_owned(),
            rendered: format!(
                "Task 1: complete (commits {}..{})",
                &sha(0x11)[..7],
                &sha(0x22)[..7]
            ),
        })
    );

    // A foreign line is refused rather than carried into the new document.
    let appended = format!("{}\nFinish: merged locally\n", rendered.text());
    assert!(matches!(
        plan_write(&rendered, Some(appended.as_bytes())),
        Err(LedgerConflict::ExistingNotReproduced { .. })
    ));
}

#[test]
fn a_change_between_plan_and_replace_is_refused() {
    let project = project();
    let (temp, ledger) = workspace();
    let input = ledger_input(project, &[Completion::Range(0x11, 0x22)]);
    let rendered = render(&input).expect("render");
    let path = temp.path().join(".sdd/progress.md");
    std::fs::create_dir_all(path.parent().expect("parent")).expect(".sdd");
    std::fs::write(&path, rendered.text()).expect("first write");

    // A human edits the file after the host read it.
    let expected = Sha256Digest::sha256(rendered.text().as_bytes());
    std::fs::write(&path, "edited by hand\n").expect("external edit");

    let outcome = ledger
        .write_document(
            ".sdd/progress.md",
            rendered.text().as_bytes(),
            Some(&expected),
        )
        .expect("write");
    eprintln!("mid-write external modification: {outcome:?}");
    assert_eq!(
        outcome,
        herness_sdd_execute::ProgressWriteOutcome::Failed {
            reason: herness_sdd_execute::ProgressFailure::ExternalModification,
        }
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("bytes"),
        "edited by hand\n",
        "the external edit is preserved"
    );
}

// ---------------------------------------------------------------------------
// Holds never change recorded history
// ---------------------------------------------------------------------------

#[test]
fn a_hold_never_changes_the_baseline_or_a_recorded_range() {
    let project = project();
    let (_temp, mut ledger) = workspace();
    let mut harness = TestStore::new();
    let store = &mut harness.store;
    // Task 1 is complete, Task 2 is active.
    let snapshot = snapshot(
        project,
        ExecutionState::Running,
        &[Completion::Range(0x11, 0x22), Completion::Active],
        Some(2),
    );
    store
        .compare_and_swap_execution(project, execution(project), None, &snapshot)
        .expect("stored snapshot");

    let stop = herness_sdd_execute::not_ready_stop(&[]);
    let revision = herness_sdd_execute::hold_next_task(store, &snapshot, stop).expect("hold");
    assert_eq!(revision, ExecutionRevision::INITIAL.next());

    let stored = store
        .load_sdd_execution(project, execution(project))
        .expect("load")
        .expect("stored");
    assert_eq!(stored.snapshot().state(), ExecutionState::WaitingHuman);
    assert_eq!(
        stored.snapshot().workspace().baseline(),
        Some(&baseline()),
        "the fixed baseline is unchanged"
    );
    let first = stored
        .snapshot()
        .task(TaskNumber::new(1).expect("number"))
        .expect("Task 1");
    assert_eq!(
        first.commit_range().map(CommitRange::full_range),
        Some(format!("{}..{}", sha(0x11), sha(0x22))),
        "the recorded completion range is unchanged"
    );
    assert_eq!(
        stored
            .snapshot()
            .task(TaskNumber::new(2).expect("number"))
            .map(TaskSnapshot::progression),
        Some(herness_sdd_execute::TaskProgression::Active)
    );
    let _ = &mut ledger;
}

#[test]
fn a_ledger_failure_at_finish_holds_the_execution_instead_of_finishing() {
    let project = project();
    let mut harness = TestStore::new();
    let store = &mut harness.store;
    let snapshot = complete_snapshot(project, false);
    store
        .compare_and_swap_execution(project, execution(project), None, &snapshot)
        .expect("stored snapshot");

    // A `ready_for_finish` execution is held when its compatibility ledger
    // could not be written: finish must never proceed on a missing document.
    let stop = herness_sdd_execute::not_ready_stop(&[]);
    let revision = herness_sdd_execute::hold_next_task(store, &snapshot, stop).expect("hold");
    let stored = store
        .load_sdd_execution(project, execution(project))
        .expect("load")
        .expect("stored");
    assert_eq!(revision, ExecutionRevision::INITIAL.next());
    assert_eq!(stored.snapshot().state(), ExecutionState::WaitingHuman);
    assert_eq!(
        stored
            .snapshot()
            .stop()
            .and_then(herness_sdd_execute::StopRecord::required_action),
        Some(herness_sdd_execute::HumanAction::ResolveHumanDecision)
    );
    // Every recorded range and the baseline survive the hold.
    assert_eq!(stored.snapshot().workspace().baseline(), Some(&baseline()));
    for (number, base, head) in [(1u32, 0x11u8, 0x22u8), (2, 0x22, 0x33)] {
        let task = stored
            .snapshot()
            .task(TaskNumber::new(number).expect("number"))
            .expect("Task");
        assert_eq!(
            task.commit_range().map(CommitRange::full_range),
            Some(format!("{}..{}", sha(base), sha(head)))
        );
    }
}

#[test]
fn a_terminal_failure_is_never_held() {
    let project = project();
    let mut harness = TestStore::new();
    let store = &mut harness.store;
    let failed = snapshot(
        project,
        ExecutionState::Failed,
        &[Completion::Range(0x11, 0x22), Completion::Pending],
        None,
    );
    store
        .compare_and_swap_execution(project, execution(project), None, &failed)
        .expect("stored snapshot");
    let stop = herness_sdd_execute::not_ready_stop(&[]);
    assert!(
        herness_sdd_execute::hold_next_task(store, &failed, stop).is_err(),
        "a failed execution is not a task to hold"
    );
}

// ---------------------------------------------------------------------------
// Finish decision
// ---------------------------------------------------------------------------

fn complete_snapshot(project: ProjectId, no_change: bool) -> ExecutionSnapshot {
    let completions = if no_change {
        vec![Completion::Range(0x11, 0x22), Completion::NoChange]
    } else {
        vec![Completion::Range(0x11, 0x22), Completion::Range(0x22, 0x33)]
    };
    snapshot(project, ExecutionState::ReadyForFinish, &completions, None)
}

fn ledger_for(
    _project: ProjectId,
    snapshot: &ExecutionSnapshot,
) -> herness_sdd_execute::RenderedLedger {
    let input = LedgerInput::from_snapshot(
        snapshot,
        LedgerWorktree::Created(CHECKOUT_PLACEHOLDER.to_owned()),
        Vec::new(),
    )
    .expect("ledger input");
    render(&input).expect("render")
}

fn report_text(spec_reflection: &str, actual_result: &str) -> String {
    format!(
        "# Task 2 report\n\n\
         ## What I implemented\n\n\
         The compatibility ledger and the finish handoff.\n\n\
         ## Deliverables\n\n\
         - crates/herness-sdd-execute/src/ledger.rs\n\
         - crates/herness-sdd-execute/src/finish.rs\n\n\
         ## Verification evidence\n\n\
         ### ledger\n\n\
         - Check: ledger\n\
         - Executor: the implementer\n\
         - Command: cargo test -p herness-sdd-execute-tests --test ledger --locked\n\
         - Actual result: {actual_result}\n\
         - Target change: HEAD\n\
         - Scope: the whole ledger target\n\n\
         ## Canonical spec reflection\n\n\
         Updated: {spec_reflection}\n\n\
         ## Decisions that affect later phases\n\n\
         - The compatibility ledger prints the full baseline and 7-character ranges.\n\n\
         ## Unconfirmed scope\n\n\
         - The pack's own test suite was run separately.\n\n\
         ## Status\n\n\
         DONE\n"
    )
}

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::sha256(label.as_bytes())
}

fn ready_inputs<'a>(
    _project: ProjectId,
    snapshot: &'a ExecutionSnapshot,
    report: &'a herness_sdd_execute::Report,
    observation: &'a FinalStateObservation,
    ledger: herness_sdd_execute::RenderedLedger,
    reflection: SpecReflection,
) -> FinishInputs<'a> {
    FinishInputs {
        snapshot,
        approval_current: true,
        approval_detail: String::new(),
        final_check_ids: vec!["ledger".to_owned()],
        last_report: report,
        observation,
        spec_reflection: reflection,
        later_phase_depends: false,
        ledger,
        unconfirmed: vec!["the pack suite is run separately".to_owned()],
    }
}

#[test]
fn ready_only_with_current_final_evidence_and_spec_reflection() {
    let project = project();
    let snapshot = complete_snapshot(project, false);
    let ledger = ledger_for(project, &snapshot);
    let head = sha(0x33);
    let content = digest("final content");
    let observation =
        FinalStateObservation::new(&head, content.clone(), content, vec![SPEC_PATH.to_owned()]);
    let report = herness_sdd_execute::Report::parse(&report_text(SPEC_PATH, "2 passed"))
        .expect("a valid report");
    let reflection = SpecReflection::Updated {
        path: SPEC_PATH.to_owned(),
        detail: None,
    };

    let decision = decide(ready_inputs(
        project,
        &snapshot,
        &report,
        &observation,
        ledger,
        reflection,
    ))
    .expect("a decision");
    assert!(decision.is_ready(), "{:?}", decision.blockers());
    let handoff = decision.handoff().expect("a handoff");
    eprintln!("handoff:\n{}", handoff.render());

    assert_eq!(handoff.checkout(), CHECKOUT_PLACEHOLDER);
    assert_eq!(handoff.base_branch(), BASE_BRANCH);
    assert_eq!(handoff.branch(), BRANCH);
    assert_eq!(handoff.baseline(), &baseline());
    assert_eq!(handoff.plan_path(), PLAN_PATH);
    assert_eq!(handoff.plan_revision(), 1);
    assert_eq!(handoff.final_check_ids(), ["ledger".to_owned()]);
    assert_eq!(handoff.task_completions().len(), 2);
    assert_eq!(
        handoff.task_completions()[0],
        herness_sdd_execute::TaskCompletionEntry::Range {
            number: 1,
            base: sha(0x11),
            head: sha(0x22),
            short: format!("{}..{}", &sha(0x11)[..7], &sha(0x22)[..7]),
        }
    );
    let evidence = handoff.final_evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].check(), "ledger");
    assert_eq!(evidence[0].executor(), "the implementer");
    assert_eq!(
        evidence[0].command(),
        "cargo test -p herness-sdd-execute-tests --test ledger --locked"
    );
    assert_eq!(evidence[0].actual_result(), "2 passed");
    assert_eq!(evidence[0].target_change(), "HEAD");
    assert_eq!(evidence[0].scope(), "the whole ledger target");
    assert!(handoff.spec_reflection().starts_with("updated "));
    assert_eq!(
        handoff.unconfirmed(),
        ["the pack suite is run separately".to_owned()]
    );
    assert!(handoff.stacked_prs_available());

    // Accepting the handoff grants no Git side effect.
    let policy = handoff.assert_no_side_effects();
    assert!(!policy.push_allowed);
    assert!(!policy.merge_allowed);
    assert!(!policy.publish_allowed);
    assert!(policy.human_choice_required);
    assert!(matches!(
        decision,
        FinishDecision::Ready {
            human_choice_required: true,
            ..
        }
    ));

    // The handoff carries the ledger the pack will parse.
    let rendered = handoff.render();
    assert!(rendered.contains(&format!("Branch baseline: {}\n", baseline())));
    assert!(rendered.contains("Task 2: complete (commits "));
    assert!(rendered.contains("## Final-state evidence"));
    assert!(!rendered.contains("## Stacked PRs"));
}

#[test]
fn an_execution_that_is_not_finished_is_not_ready() {
    let project = project();
    // Every Task is complete, but the state is still `running`: the coordinator
    // has not recorded ready_for_finish, so the handoff does not exist.
    let snapshot = snapshot(
        project,
        ExecutionState::Running,
        &[Completion::Range(0x11, 0x22), Completion::Range(0x22, 0x33)],
        None,
    );
    let ledger = ledger_for(project, &snapshot);
    let report = herness_sdd_execute::Report::parse(&report_text(SPEC_PATH, "2 passed"))
        .expect("a valid report");
    let content = digest("final content");
    let observation = FinalStateObservation::new(
        sha(0x33),
        content.clone(),
        content,
        vec![SPEC_PATH.to_owned()],
    );
    let decision = decide(ready_inputs(
        project,
        &snapshot,
        &report,
        &observation,
        ledger,
        SpecReflection::Updated {
            path: SPEC_PATH.to_owned(),
            detail: None,
        },
    ))
    .expect("a decision");
    assert!(!decision.is_ready());
    assert!(decision.blockers().iter().any(|blocker| matches!(
        blocker,
        FinishBlocker::ExecutionState { state } if state == "running"
    )));
}

#[test]
fn stale_full_suite_evidence_is_not_ready() {
    let project = project();
    let snapshot = complete_snapshot(project, false);
    let ledger = ledger_for(project, &snapshot);
    let report = herness_sdd_execute::Report::parse(&report_text(SPEC_PATH, "2 passed"))
        .expect("a valid report");
    let reflection = SpecReflection::Updated {
        path: SPEC_PATH.to_owned(),
        detail: None,
    };
    // The recorded evidence was observed against another content.
    let observation = FinalStateObservation::new(
        sha(0x33),
        digest("final content"),
        digest("an earlier content"),
        vec![SPEC_PATH.to_owned()],
    );
    let decision = decide(ready_inputs(
        project,
        &snapshot,
        &report,
        &observation,
        ledger,
        reflection,
    ))
    .expect("a decision");
    eprintln!("stale evidence blockers: {:?}", decision.blockers());
    assert!(!decision.is_ready());
    assert!(decision.blockers().iter().any(|blocker| matches!(
        blocker,
        FinishBlocker::StaleEvidence { detail } if detail.contains("differs from the current final content")
    )));
}

#[test]
fn a_post_commit_change_makes_the_evidence_stale() {
    let project = project();
    let snapshot = complete_snapshot(project, false);
    let ledger = ledger_for(project, &snapshot);
    let report = herness_sdd_execute::Report::parse(&report_text(SPEC_PATH, "2 passed"))
        .expect("a valid report");
    let reflection = SpecReflection::Updated {
        path: SPEC_PATH.to_owned(),
        detail: None,
    };
    // A post-commit hook moved HEAD after the Task recorded its range.
    let content = digest("final content");
    let observation = FinalStateObservation::new(
        sha(0x44),
        content.clone(),
        content,
        vec![SPEC_PATH.to_owned()],
    );
    let decision = decide(ready_inputs(
        project,
        &snapshot,
        &report,
        &observation,
        ledger,
        reflection,
    ))
    .expect("a decision");
    eprintln!("post-commit change blockers: {:?}", decision.blockers());
    assert!(!decision.is_ready());
    assert!(decision.blockers().iter().any(|blocker| matches!(
        blocker,
        FinishBlocker::StaleEvidence { detail } if detail.contains("post-commit change")
    )));
}

#[test]
fn a_missing_spec_reflection_with_a_later_phase_is_not_ready() {
    let project = project();
    let snapshot = complete_snapshot(project, false);
    let ledger = ledger_for(project, &snapshot);
    let report = herness_sdd_execute::Report::parse(&report_text("none", "2 passed"))
        .expect("a valid report");
    let content = digest("final content");
    let observation = FinalStateObservation::new(sha(0x33), content.clone(), content, Vec::new());
    let mut inputs = ready_inputs(
        project,
        &snapshot,
        &report,
        &observation,
        ledger,
        SpecReflection::None { detail: None },
    );
    inputs.later_phase_depends = true;
    let decision = decide(inputs).expect("a decision");
    eprintln!("missing reflection blockers: {:?}", decision.blockers());
    assert!(!decision.is_ready());
    assert!(
        decision
            .blockers()
            .iter()
            .any(|blocker| matches!(blocker, FinishBlocker::SpecReflection { .. }))
    );

    // A report claiming an updated spec at a path that does not exist is also
    // refused.
    let snapshot = complete_snapshot(project, false);
    let ledger = ledger_for(project, &snapshot);
    let content = digest("final content");
    let observation = FinalStateObservation::new(sha(0x33), content.clone(), content, Vec::new());
    let decision = decide(ready_inputs(
        project,
        &snapshot,
        &report,
        &observation,
        ledger,
        SpecReflection::Updated {
            path: SPEC_PATH.to_owned(),
            detail: None,
        },
    ))
    .expect("a decision");
    assert!(!decision.is_ready());
    assert!(decision.blockers().iter().any(|blocker| matches!(
        blocker,
        FinishBlocker::SpecReflection { detail } if detail.contains("does not exist")
    )));
}

#[test]
fn a_final_check_without_evidence_is_not_ready() {
    let project = project();
    let snapshot = complete_snapshot(project, false);
    let ledger = ledger_for(project, &snapshot);
    // The report evidences a different check.
    let report = herness_sdd_execute::Report::parse(&report_text(SPEC_PATH, "2 passed"))
        .expect("a valid report");
    let content = digest("final content");
    let observation = FinalStateObservation::new(
        sha(0x33),
        content.clone(),
        content,
        vec![SPEC_PATH.to_owned()],
    );
    let mut inputs = ready_inputs(
        project,
        &snapshot,
        &report,
        &observation,
        ledger,
        SpecReflection::Updated {
            path: SPEC_PATH.to_owned(),
            detail: None,
        },
    );
    inputs.final_check_ids = vec!["ledger".to_owned(), "full-suite".to_owned()];
    let decision = decide(inputs).expect("a decision");
    assert!(decision.blockers().iter().any(|blocker| matches!(
        blocker,
        FinishBlocker::MissingFinalCheck { check } if check == "full-suite"
    )));
}

#[test]
fn an_incomplete_evidence_block_is_not_ready() {
    let project = project();
    // An evidence block missing the scope is refused with the exact field.
    let block = CheckEvidence::new(
        "ledger",
        "",
        vec![
            EvidenceItem::new(EvidenceField::Executor, "the implementer").expect("item"),
            EvidenceItem::new(EvidenceField::Command, "cargo test").expect("item"),
            EvidenceItem::new(EvidenceField::ActualResult, "ok").expect("item"),
            EvidenceItem::new(EvidenceField::TargetChange, "HEAD").expect("item"),
        ],
    )
    .expect("block");
    assert_eq!(
        herness_sdd_execute::FinalCheckEvidence::from_block(&block),
        Err(vec![EvidenceField::Scope])
    );

    let snapshot = complete_snapshot(project, false);
    let ledger = ledger_for(project, &snapshot);
    let report_text = "# Task 2 report\n\n## Verification evidence\n\n### ledger\n\n\
         - Check: ledger\n- Executor: e\n- Command: c\n- Actual result: r\n\
         - Target change: t\n\n\
         ## Canonical spec reflection\n\nUpdated: none\n\n## Status\n\nDONE\n"
        .to_owned();
    let report = herness_sdd_execute::Report::parse(&report_text).expect("a valid report");
    let content = digest("final content");
    let observation = FinalStateObservation::new(
        sha(0x33),
        content.clone(),
        content,
        vec![SPEC_PATH.to_owned()],
    );
    let decision = decide(ready_inputs(
        project,
        &snapshot,
        &report,
        &observation,
        ledger,
        SpecReflection::None { detail: None },
    ))
    .expect("a decision");
    assert!(!decision.is_ready());
    assert!(decision.blockers().iter().any(|blocker| matches!(
        blocker,
        FinishBlocker::IncompleteFinalCheck { check, fields }
            if check == "ledger" && fields == &vec![EvidenceField::Scope]
    )));
}

#[test]
fn the_handoff_carries_every_finish_field_and_no_side_effect() {
    let project = project();
    // A handoff with a no_change Task states the stacked incompatibility and
    // still carries every other field.
    let snapshot = complete_snapshot(project, true);
    let ledger = ledger_for(project, &snapshot);
    let report = herness_sdd_execute::Report::parse(&report_text(SPEC_PATH, "2 passed"))
        .expect("a valid report");
    let content = digest("final content");
    let observation = FinalStateObservation::new(
        sha(0x22),
        content.clone(),
        content,
        vec![SPEC_PATH.to_owned()],
    );
    let decision = decide(ready_inputs(
        project,
        &snapshot,
        &report,
        &observation,
        ledger,
        SpecReflection::Updated {
            path: SPEC_PATH.to_owned(),
            detail: None,
        },
    ))
    .expect("a decision");
    assert!(decision.is_ready(), "{:?}", decision.blockers());
    let handoff = decision.handoff().expect("a handoff");
    assert!(!handoff.stacked_prs_available());
    let notice = handoff
        .stacked_pr_incompatibility()
        .expect("the incompatibility is explicit");
    assert!(notice.contains("Task 2"), "{notice}");
    assert!(notice.contains("empty commit range"), "{notice}");
    assert_eq!(
        handoff.task_completions()[1],
        herness_sdd_execute::TaskCompletionEntry::NoChange {
            number: 2,
            detail: None,
        }
    );

    let rendered = handoff.render();
    eprintln!("no_change handoff:\n{rendered}");
    for required in [
        "Checkout:",
        "Branch:",
        "Base branch:",
        "Branch baseline:",
        "Plan:",
        "Plan revision:",
        "finalChecks:",
        "## Task ranges",
        "Task 2: complete (no_change)",
        "## Final-state evidence",
        "## Canonical-spec reflection",
        "## Unconfirmed",
        "## Ledger",
        "## Stacked PRs",
        "Stacked PRs are incompatible",
    ] {
        assert!(
            rendered.contains(required),
            "the handoff lacks {required:?}:\n{rendered}"
        );
    }
    // The ledger inside the handoff is what the pack parses.
    let (tasks, parsed_baseline) = {
        let temp = tempfile::tempdir().expect("directory");
        let path = temp.path().join("progress.md");
        std::fs::write(&path, handoff.ledger().text()).expect("ledger");
        parse_with_real_pack(&path)
    };
    assert_eq!(tasks.len(), 1);
    assert_eq!(parsed_baseline.as_deref(), Some(baseline().as_str()));

    // Presenting the handoff performs no Git work: nothing was pushed, merged,
    // or published, and the policy still requires the human's choice.
    let policy = handoff.assert_no_side_effects();
    assert!(!policy.push_allowed && !policy.merge_allowed && !policy.publish_allowed);
    assert!(policy.human_choice_required);
}

// ---------------------------------------------------------------------------
// A real repository for the stacked preflight
// ---------------------------------------------------------------------------

struct GitRepo {
    _temp: TempDir,
    root: PathBuf,
}

impl GitRepo {
    /// A repository with a base commit, then one commit per Task.
    fn with_two_tasks() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = std::fs::canonicalize(temp.path()).expect("canonical root");
        run_git(&root, &["init", "-q", "-b", BASE_BRANCH]);
        run_git(&root, &["config", "user.name", "Ledger Test"]);
        run_git(&root, &["config", "user.email", "ledger@example.invalid"]);
        std::fs::write(root.join("README.md"), "initial\n").expect("seed");
        run_git(&root, &["add", "--", "README.md"]);
        run_git(&root, &["commit", "-q", "-m", "initial"]);
        for (index, name) in ["one", "two"].iter().enumerate() {
            let path = format!("task-{}.txt", index + 1);
            std::fs::write(root.join(&path), name).expect("task file");
            run_git(&root, &["add", "--", &path]);
            run_git(&root, &["commit", "-q", "-m", name]);
        }
        Self { _temp: temp, root }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    /// The commit SHA at `index`: 0 is the baseline, then one per Task.
    fn commit(&self, index: usize) -> String {
        let revision = format!("HEAD~{}", 2 - index);
        git_stdout(&self.root, &["rev-parse", &revision])
    }

    fn write_plan(&self, headings: &[&str]) -> PathBuf {
        let directory = self.root.join("docs/sdd/plans");
        std::fs::create_dir_all(&directory).expect("plan directory");
        let path = directory.join("2026-11-13-ledger-fixture.md");
        let mut text = String::from("# Ledger fixture plan\n\n**Goal:** Prove the handoff.\n\n");
        for heading in headings {
            text.push_str(&format!("## {heading}\n\nbody\n\n"));
        }
        std::fs::write(&path, text).expect("plan");
        path
    }

    /// Runs the real read-only stacked-PR preflight.
    fn stack_prs_dry_run(&self, plan: &Path, ledger: &Path) -> (i32, String, String) {
        let root = pack_root();
        let output = Command::new(python())
            .arg(root.join("scripts/stack-prs"))
            .args(["--base", BASE_BRANCH, "--ledger"])
            .arg(ledger)
            .arg("--plan")
            .arg(plan)
            .arg("--dry-run")
            .current_dir(&self.root)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C")
            .output()
            .expect("stack-prs starts");
        let code = output.status.code().unwrap_or(-1);
        (
            code,
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    fn has_ref(&self, name: &str) -> bool {
        Command::new("git")
            .current_dir(&self.root)
            .args(["rev-parse", "--verify", &format!("refs/heads/{name}")])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn remotes(&self) -> String {
        git_stdout(&self.root, &["remote"])
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
