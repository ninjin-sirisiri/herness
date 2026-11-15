//! Windowless H4 lifecycle launcher.
//!
//! This is the explicit native test mode behind `--h4-lifecycle-test`. It
//! creates no main window, selects no project, and drives the same
//! app-lifetime [`DesktopHost::pump`](crate::host::DesktopHost::pump) the
//! production shell runs. The application data root is a fresh absolute
//! `HERNESS_APP_DATA_ROOT`, the provider and assessment bases are loopback
//! (`HERNESS_H4_TEST_ENDPOINT`), and the credential port is in-process so the
//! Keychain is never read.
//!
//! It prints one `H4_LIFECYCLE_OK:` line with the observable facts (pid,
//! projects, executions, completed Tasks, commits, whether the ledger exists,
//! `request_count`, `window=absent`, `selected_project=none`, and the startup
//! reconciliation counts) and then either runs the real explicit-quit path or,
//! for a crash-recovery observation, exits without the quit hook overwriting the
//! reconciled state.
//!
//! A crash boundary is armed here, only after the launch parser accepted
//! `--h4-crash-point` together with `--h4-lifecycle-test`.

use std::time::Duration;

use herness_core::{
    ConnectionId, CoreError, CredentialAvailability, CredentialKind, CredentialPort,
    ResolvedCredential, SecretString,
};
use tauri::Manager;

use crate::app::{AppState, H4LifecycleLaunch};
use crate::guard;
use crate::lifecycle::quit;
use crate::sdd_execute::crash;

/// In-process credential for the H4 lifecycle fixture.
///
/// The fixture's child already completed before this process starts, so this
/// port is never resolved. It exists so the host composition needs no Keychain
/// and no environment credential.
pub struct H4TestCredentials;

impl CredentialPort for H4TestCredentials {
    fn availability(
        &self,
        _connection: &ConnectionId,
    ) -> Result<CredentialAvailability, CoreError> {
        Ok(CredentialAvailability::Available)
    }

    fn resolve(&self, _connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        Ok(ResolvedCredential::new(
            CredentialKind::ApiKey,
            SecretString::new("sk-h4-lifecycle-fixture").expect("static fake credential"),
        ))
    }
}

/// Arms the requested crash point and starts the windowless launcher thread.
pub fn start(app: &tauri::App, launch: H4LifecycleLaunch) {
    if let Some(point) = launch.crash_point {
        crash::arm(point);
    }
    let handle = app.handle().clone();
    std::thread::spawn(move || run(&handle, launch));
}

fn run(handle: &tauri::AppHandle, launch: H4LifecycleLaunch) {
    let facts = match drive(handle).and_then(|pump_errors| observe(handle, pump_errors)) {
        Ok(facts) => facts,
        Err(error) => {
            eprintln!(
                "H4_LIFECYCLE_FAILED: pid={} detail={error}",
                std::process::id()
            );
            handle.exit(2);
            return;
        }
    };
    if !facts.window_absent || !facts.selected_none {
        eprintln!(
            "H4_LIFECYCLE_FAILED: pid={} window_absent={} selected_none={}",
            std::process::id(),
            facts.window_absent,
            facts.selected_none
        );
        handle.exit(2);
        return;
    }
    println!(
        "H4_LIFECYCLE_OK: pid={} projects={} executions={} tasks={} tasks_completed={} commits={} progress={} request_count={} window=absent selected_project=none startup_reports={} startup_failures={} pump_errors={} states={}",
        std::process::id(),
        facts.projects,
        facts.executions,
        facts.tasks,
        facts.completed,
        facts.commits,
        if facts.progress { "present" } else { "absent" },
        facts.request_count,
        facts.startup_reports,
        facts.startup_failures,
        facts.pump_errors,
        facts.states
    );
    if launch.quit {
        // The real explicit-quit path owns the exit code and the coordinated
        // stop. No host lock is held here.
        quit::request_quit(handle);
    } else {
        handle.exit(0);
    }
}

/// Pumps until the stored execution signature is stable for two passes.
///
/// A seeded execution completes on the first pass. A crash-recovery run may
/// need one more pass to reconcile, and a restart after quit changes nothing.
/// The short bounded wait keeps the launcher deterministic without depending on
/// the window or a selected project.
fn drive(handle: &tauri::AppHandle) -> Result<usize, String> {
    let state = handle.state::<AppState>();
    let mut last: Option<Vec<String>> = None;
    let mut stable = 0usize;
    let mut pump_errors = 0usize;
    for _ in 0..600 {
        {
            let mut host = state
                .host
                .lock()
                .map_err(|_| "the host lock was poisoned".to_owned())?;
            host.pump()?;
            pump_errors += host.last_sdd_pump().errors.len();
        }
        let signature = stored_signature(handle)?;
        if last.as_ref() == Some(&signature) {
            stable += 1;
            if stable >= 2 {
                break;
            }
        } else {
            stable = 0;
            last = Some(signature);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(pump_errors)
}

/// A stable description of every stored H4 execution.
fn stored_signature(handle: &tauri::AppHandle) -> Result<Vec<String>, String> {
    let state = handle.state::<AppState>();
    let store = {
        let host = state
            .host
            .lock()
            .map_err(|_| "the host lock was poisoned".to_owned())?;
        host.store_handle()
    };
    let guard = store.lock();
    let executions = guard
        .sdd_stored_executions()
        .map_err(|error| error.to_string())?;
    Ok(executions
        .iter()
        .map(|stored| {
            let snapshot = stored.snapshot();
            let tasks = snapshot
                .tasks()
                .iter()
                .map(|task| {
                    format!(
                        "{}:{:?}:{}",
                        task.task().number().get(),
                        task.progression(),
                        task.commit_range()
                            .map(|range| range.head().as_str().to_owned())
                            .unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{}:{:?}:{}:{}",
                snapshot.execution_id(),
                snapshot.state(),
                snapshot.revision().get(),
                tasks
            )
        })
        .collect())
}

/// The observable facts printed on the `H4_LIFECYCLE_OK` line.
struct Facts {
    projects: usize,
    executions: usize,
    tasks: usize,
    completed: usize,
    commits: usize,
    progress: bool,
    request_count: u32,
    startup_reports: usize,
    startup_failures: usize,
    pump_errors: usize,
    states: String,
    window_absent: bool,
    selected_none: bool,
}

fn observe(handle: &tauri::AppHandle, pump_errors: usize) -> Result<Facts, String> {
    let state = handle.state::<AppState>();
    let selected_none = state
        .selected_project
        .lock()
        .map(|selected| selected.is_none())
        .map_err(|_| "the selected-project lock was poisoned".to_owned())?;
    let window_absent = handle.get_webview_window(guard::MAIN_LABEL).is_none();
    let host = state
        .host
        .lock()
        .map_err(|_| "the host lock was poisoned".to_owned())?;
    let projects = host
        .runtime()
        .projects()
        .map_err(|error| error.to_string())?
        .len();
    let startup = host.sdd_startup();
    let request_count = startup.request_count();
    let startup_reports = startup.reports().len();
    let startup_failures = startup.failures().len();
    let store = host.store_handle();
    let guard = store.lock();
    let executions = guard
        .sdd_stored_executions()
        .map_err(|error| error.to_string())?;
    let mut tasks = 0usize;
    let mut completed = 0usize;
    let mut commits = 0usize;
    let mut states = Vec::with_capacity(executions.len());
    let mut progress = false;
    for (index, stored) in executions.iter().enumerate() {
        let snapshot = stored.snapshot();
        tasks += snapshot.tasks().len();
        completed += snapshot
            .tasks()
            .iter()
            .filter(|task| task.progression().is_complete())
            .count();
        commits += snapshot
            .tasks()
            .iter()
            .filter(|task| task.commit_range().is_some())
            .count();
        states.push(format!(
            "{}={:?}",
            snapshot.execution_id(),
            snapshot.state()
        ));
        if index == 0 {
            progress = std::path::Path::new(snapshot.workspace().canonical_checkout_root())
                .join(herness_sdd_execute::PROGRESS_LEDGER_PATH)
                .is_file();
        }
    }
    Ok(Facts {
        projects,
        executions: executions.len(),
        tasks,
        completed,
        commits,
        progress,
        request_count,
        startup_reports,
        startup_failures,
        pump_errors,
        states: states.join(","),
        window_absent,
        selected_none,
    })
}
