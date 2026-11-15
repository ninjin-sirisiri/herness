//! Task 23: the real-Tauri H4 lifecycle fixture.
//!
//! The fixture seeds one durable H4 execution whose single Task was already
//! dispatched and whose stored H2 target already completed. It then launches the
//! real `herness-desktop` binary in the windowless `--h4-lifecycle-test` mode
//! with a fresh absolute `HERNESS_APP_DATA_ROOT`, loopback provider and
//! assessment bases, and the real pack root. No main window is created and no
//! project is selected.
//!
//! The first process performs the real HTML barrier and the real host commit,
//! writes `.sdd/progress.md`, and quits through the real explicit-quit path. A
//! second process restores the same root and must send zero external requests.
//! Four additional cases crash a real process at the durable boundaries and then
//! restore it:
//!
//! * before the host commit (intent durable, no Git process),
//! * after the host commit (real commit exists, journal result not recorded),
//! * after the journal result (H4 completion snapshot not stored),
//! * before the progress-ledger replacement.
//!
//! No case may create a second commit, re-dispatch the Task, or reset an unknown
//! result to not-executed. A clearly established commit is reported as pending
//! and linked only by the human resume. This is a process/lifecycle check, not a
//! provider or GUI acceptance run.

#![cfg(target_os = "macos")]

#[path = "native_fixture/mod.rs"]
mod fixture;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use herness_core::AbsolutePath;
use herness_desktop::sdd_execute::{DesktopRecoveryHost, FilesystemDocuments, NoChildren};
use herness_desktop::supervision::store::StoreHandle;
use herness_sdd_execute::{
    ExecutionState, RecoveryClass, RecoveryEnumerationPort, RecoveryRecordKind, RecoveryReport,
    TaskProgression,
};
use herness_store::{Store, StoreConfig};

static SERIAL: Mutex<()> = Mutex::new(());

/// One loopback listener that only counts accepted connections.
///
/// The launcher receives its URL as `HERNESS_H4_TEST_ENDPOINT`. Any provider or
/// assessment request in the tested process would connect here, so a count of
/// zero is direct evidence that the restore sent nothing.
struct Counting {
    url: String,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Counting {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind counting listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_count = Arc::clone(&count);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_count.fetch_add(1, Ordering::SeqCst);
                        drop(stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url,
            count,
            stop,
            thread: Some(thread),
        }
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl Drop for Counting {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn windowless_commit_progress_and_restart_send_nothing() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let seeded = fixture::seed();
    let listener = Counting::start();
    let before_head = fixture::head(&seeded.root);
    let before_commits = fixture::commit_count(&seeded.root);

    let first = run_desktop(&seeded, &listener, &["--h4-lifecycle-test"]);
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(
        first.status.success(),
        "windowless launcher failed: status={:?} stdout={} stderr={}",
        first.status,
        stdout,
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        stdout.contains("H4_LIFECYCLE_OK:"),
        "missing facts: {stdout}"
    );
    for expected in [
        "window=absent",
        "selected_project=none",
        "request_count=0",
        "tasks_completed=1",
        "commits=1",
        "progress=present",
        "pump_errors=0",
    ] {
        assert!(stdout.contains(expected), "missing {expected}: {stdout}");
    }
    assert!(
        stdout.contains("QUIT_OK:"),
        "the real quit path did not confirm: {stdout}"
    );
    assert_eq!(listener.count(), 0, "the commit run sent no request");
    eprintln!(
        "H4_NATIVE_EVIDENCE commit root={} app_data={} exit={:?} connections={} head={} baseline={} commits={} facts={}",
        seeded.root.display(),
        seeded.data.path().display(),
        first.status.code(),
        listener.count(),
        fixture::head(&seeded.root),
        seeded.baseline,
        fixture::commit_count(&seeded.root),
        fact_line(&stdout)
    );

    let stored = load(&seeded);
    assert_eq!(stored.snapshot().state(), ExecutionState::ReadyForFinish);
    let tasks = stored.snapshot().tasks();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].progression(), TaskProgression::Complete);
    assert_eq!(tasks[0].phase(), herness_sdd_execute::TaskPhase::Complete);
    let range = tasks[0].commit_range().expect("real commit range");
    assert_eq!(range.base().as_str(), seeded.baseline);
    assert_eq!(range.head().as_str(), fixture::head(&seeded.root));
    assert_eq!(
        fixture::commit_count(&seeded.root),
        before_commits + 1,
        "exactly one host commit"
    );
    assert_ne!(fixture::head(&seeded.root), before_head);

    let changed = fixture::git_stdout(
        &seeded.root,
        &["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
    );
    assert_eq!(changed.lines().collect::<Vec<_>>(), vec![fixture::TASK_ONE]);
    let message = fixture::git_stdout(&seeded.root, &["log", "-1", "--format=%B"]);
    assert!(
        message.starts_with("Task 1:"),
        "the commit subject names the Task: {message}"
    );
    for trailer in ["Herness-Task: 1", "Herness-Execution:", "Herness-Request:"] {
        assert!(
            message.contains(trailer),
            "missing {trailer} in the commit message: {message}"
        );
    }

    let progress_path = seeded.root.join(herness_sdd_execute::PROGRESS_LEDGER_PATH);
    let progress = std::fs::read_to_string(&progress_path).expect("progress ledger");
    assert!(progress.contains("# SDD Progress"));
    assert!(progress.contains("Worktree: in-place"));
    assert!(progress.contains("Branch: h4-native-lifecycle"));
    assert!(
        progress.contains(&format!("Branch baseline: {}", seeded.baseline)),
        "the full baseline is preserved: {progress}"
    );
    assert!(
        progress.contains("Task 1: complete ("),
        "the completed range is recorded: {progress}"
    );

    // A second real process restores the same root. It must not dispatch,
    // commit, write a different ledger, or contact anything.
    let second = run_desktop(&seeded, &listener, &["--h4-lifecycle-test"]);
    let second_stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        second.status.success(),
        "windowless restart failed: status={:?} stdout={} stderr={}",
        second.status,
        second_stdout,
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(second_stdout.contains("H4_LIFECYCLE_OK:"));
    assert!(second_stdout.contains("request_count=0"));
    assert!(second_stdout.contains("tasks_completed=1"));
    assert_eq!(listener.count(), 0, "the restart sent no request");
    assert_eq!(fixture::head(&seeded.root), range.head().as_str());
    assert_eq!(fixture::commit_count(&seeded.root), before_commits + 1);
    let restored = load(&seeded);
    assert_eq!(restored.snapshot().state(), ExecutionState::ReadyForFinish);
    assert_eq!(
        restored.snapshot().tasks()[0]
            .commit_range()
            .expect("range")
            .head()
            .as_str(),
        range.head().as_str()
    );
    assert_eq!(restored.revision(), stored.revision());
    assert_eq!(
        std::fs::read_to_string(&progress_path).expect("progress ledger"),
        progress,
        "the restart reproduces the same ledger instead of rewriting it"
    );
}

#[test]
fn each_crash_boundary_is_reconciled_without_a_second_commit_or_dispatch() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for point in [
        herness_desktop::sdd_execute::crash::CrashPoint::BeforeHostCommit,
        herness_desktop::sdd_execute::crash::CrashPoint::AfterHostCommit,
        herness_desktop::sdd_execute::crash::CrashPoint::BeforeDbResult,
        herness_desktop::sdd_execute::crash::CrashPoint::BeforeProgressReplace,
    ] {
        assert_case(point);
    }
}

fn assert_case(point: herness_desktop::sdd_execute::crash::CrashPoint) {
    let seeded = fixture::seed();
    let listener = Counting::start();
    let before_head = fixture::head(&seeded.root);
    let before_commits = fixture::commit_count(&seeded.root);

    let crashed = run_desktop(
        &seeded,
        &listener,
        &["--h4-lifecycle-test", "--h4-crash-point", point.label()],
    );
    let stdout = String::from_utf8_lossy(&crashed.stdout);
    assert_eq!(
        crashed.status.code(),
        Some(herness_desktop::sdd_execute::crash::CRASH_EXIT_CODE),
        "{} did not crash at the boundary: stdout={} stderr={}",
        point.label(),
        stdout,
        String::from_utf8_lossy(&crashed.stderr)
    );
    assert!(
        stdout.contains(&format!("H4_LIFECYCLE_CRASH: point={}", point.label())),
        "{} did not report its point: {stdout}",
        point.label()
    );
    assert_eq!(listener.count(), 0, "{} sent no request", point.label());

    let after_crash_head = fixture::head(&seeded.root);
    let after_crash_commits = fixture::commit_count(&seeded.root);
    match point {
        herness_desktop::sdd_execute::crash::CrashPoint::BeforeHostCommit => {
            assert_eq!(after_crash_head, before_head, "no commit before a");
            assert_eq!(after_crash_commits, before_commits);
        }
        _ => {
            assert_eq!(
                after_crash_commits,
                before_commits + 1,
                "{} leaves exactly the one real commit",
                point.label()
            );
        }
    }

    let report = recovery(&seeded);
    assert_eq!(report.project_id(), seeded.project);
    assert_eq!(report.execution_id(), seeded.execution);
    let git_items = items(&report, RecoveryRecordKind::Git);
    let progress_items = items(&report, RecoveryRecordKind::Progress);
    match point {
        herness_desktop::sdd_execute::crash::CrashPoint::BeforeHostCommit => {
            assert!(
                git_items
                    .iter()
                    .any(|item| item.class() == RecoveryClass::Unknown),
                "a recorded intent without a result is unknown: {:?}",
                git_items
                    .iter()
                    .map(|item| item.class())
                    .collect::<Vec<_>>()
            );
            assert!(report.pending_link().is_none(), "no commit was established");
        }
        herness_desktop::sdd_execute::crash::CrashPoint::AfterHostCommit
        | herness_desktop::sdd_execute::crash::CrashPoint::BeforeDbResult => {
            assert!(
                git_items
                    .iter()
                    .any(|item| item.class() == RecoveryClass::Established),
                "the real commit is established: {:?}",
                git_items
                    .iter()
                    .map(|item| item.class())
                    .collect::<Vec<_>>()
            );
            let pending = report
                .pending_link()
                .expect("an established commit waits for the human link");
            assert_eq!(pending.task().number().get(), 1);
            assert!(!pending.is_complete());
        }
        herness_desktop::sdd_execute::crash::CrashPoint::BeforeProgressReplace => {
            assert!(
                progress_items
                    .iter()
                    .any(|item| item.class() == RecoveryClass::Unknown),
                "the unconfirmed ledger write is unknown: {:?}",
                progress_items
                    .iter()
                    .map(|item| item.class())
                    .collect::<Vec<_>>()
            );
        }
    }

    // The recovery process restores and reports. It must not re-dispatch, and a
    // `committing` execution is never advanced by the pump.
    let recovered = run_desktop(
        &seeded,
        &listener,
        &["--h4-lifecycle-test", "--h4-lifecycle-no-quit"],
    );
    let recovered_stdout = String::from_utf8_lossy(&recovered.stdout);
    assert!(
        recovered.status.success(),
        "{} restore failed: status={:?} stdout={} stderr={}",
        point.label(),
        recovered.status,
        recovered_stdout,
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(recovered_stdout.contains("H4_LIFECYCLE_OK:"));
    assert!(
        recovered_stdout.contains("request_count=0"),
        "{} restore sent no request: {recovered_stdout}",
        point.label()
    );
    assert_eq!(
        listener.count(),
        0,
        "{} restore sent no request",
        point.label()
    );

    let stored = load(&seeded);
    let tasks = stored.snapshot().tasks();
    assert_eq!(tools_dispatched(&seeded), 1, "{}", point.label());
    match point {
        herness_desktop::sdd_execute::crash::CrashPoint::BeforeHostCommit
        | herness_desktop::sdd_execute::crash::CrashPoint::AfterHostCommit
        | herness_desktop::sdd_execute::crash::CrashPoint::BeforeDbResult => {
            assert_eq!(
                stored.snapshot().state(),
                ExecutionState::Committing,
                "{} waits for the human resume without advancing",
                point.label()
            );
            assert!(
                tasks[0].progression() != TaskProgression::Complete,
                "the Task is not fabricated as complete"
            );
            assert_eq!(fixture::head(&seeded.root), after_crash_head);
            assert_eq!(
                fixture::commit_count(&seeded.root),
                after_crash_commits,
                "no second commit"
            );
        }
        herness_desktop::sdd_execute::crash::CrashPoint::BeforeProgressReplace => {
            assert_eq!(
                stored.snapshot().state(),
                ExecutionState::WaitingHuman,
                "the unconfirmed ledger holds the execution"
            );
            assert_eq!(tasks[0].progression(), TaskProgression::Complete);
            assert_eq!(fixture::head(&seeded.root), after_crash_head);
            assert_eq!(fixture::commit_count(&seeded.root), after_crash_commits);
            assert!(
                !seeded
                    .root
                    .join(herness_sdd_execute::PROGRESS_LEDGER_PATH)
                    .exists(),
                "the destination was never replaced"
            );
        }
    }
    eprintln!(
        "H4_NATIVE_EVIDENCE crash point={} crash_exit={:?} crash_head={} crash_commits={} recovery_exit={:?} connections={} recovery_head={} recovery_commits={} git_classes={:?} progress_classes={:?} facts={}",
        point.label(),
        crashed.status.code(),
        after_crash_head,
        after_crash_commits,
        recovered.status.code(),
        listener.count(),
        fixture::head(&seeded.root),
        fixture::commit_count(&seeded.root),
        git_items
            .iter()
            .map(|item| item.class())
            .collect::<Vec<_>>(),
        progress_items
            .iter()
            .map(|item| item.class())
            .collect::<Vec<_>>(),
        fact_line(&recovered_stdout)
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run_desktop(seeded: &fixture::Seeded, listener: &Counting, args: &[&str]) -> Output {
    let binary = desktop_binary();
    assert!(
        binary.is_file(),
        "desktop binary {} is missing; run cargo build -p herness-desktop --locked first",
        binary.display()
    );
    Command::new(binary)
        .args(args)
        .env("HERNESS_APP_DATA_ROOT", seeded.data.path())
        .env("SDD_PACK_ROOT", fixture::PACK_ROOT)
        .env("HERNESS_H4_TEST_ENDPOINT", &listener.url)
        .stdin(Stdio::null())
        .output()
        .expect("run desktop lifecycle fixture")
}

fn desktop_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("HERNESS_DESKTOP_BIN") {
        return PathBuf::from(path);
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("target"));
    target.join("debug/herness-desktop")
}

fn open_store(seeded: &fixture::Seeded) -> Store {
    Store::open(StoreConfig::new(seeded.data.path()).expect("store config")).expect("store")
}

fn load(seeded: &fixture::Seeded) -> herness_sdd_execute::StoredExecution {
    open_store(seeded)
        .load_sdd_execution(seeded.project, seeded.execution)
        .expect("load execution")
        .expect("stored execution")
}

fn recovery(seeded: &fixture::Seeded) -> RecoveryReport {
    let store = open_store(seeded);
    let handle = StoreHandle::new(Arc::new(Mutex::new(store)));
    let git = AbsolutePath::new("/usr/bin/git").expect("git path");
    let mut host = DesktopRecoveryHost::new(handle, Some(git)).with_documents(FilesystemDocuments);
    let startup = host.restore(&mut NoChildren);
    assert!(startup.failures().is_empty(), "{:?}", startup.failures());
    assert_eq!(startup.reports().len(), 1);
    assert_eq!(startup.request_count(), 0);
    startup.reports()[0].clone()
}

fn items(
    report: &RecoveryReport,
    kind: RecoveryRecordKind,
) -> Vec<&herness_sdd_execute::RecoveryItem> {
    report
        .items()
        .iter()
        .filter(|item| item.kind() == kind)
        .collect()
}

fn fact_line(stdout: &str) -> String {
    stdout
        .lines()
        .find(|line| line.starts_with("H4_LIFECYCLE_OK:"))
        .unwrap_or("")
        .to_owned()
}

fn tools_dispatched(seeded: &fixture::Seeded) -> usize {
    let store = open_store(seeded);
    let dispatches = store
        .dispatch_entries(seeded.project, seeded.execution)
        .expect("dispatch journal")
        .len();
    let reservations = store
        .task_reservations(seeded.project, seeded.execution)
        .expect("reservations")
        .len();
    assert_eq!(dispatches, reservations, "one dispatch, one reservation");
    dispatches
}
