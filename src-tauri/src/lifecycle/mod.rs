//! Window lifetime, explicit quit, and navigation policy.
//!
//! Closing the last window hides it and leaves the Rust host running. Reopening
//! shows the same main window and reloads the page so JavaScript state is not
//! reused; the page then reads a fresh runtime snapshot. The WebView never loads
//! a remote document, and external HTTP(S) links open in the system browser.
//!
//! Explicit quit is a separate path. It never disposes the runtime as a
//! substitute for a saveable stop; [`quit`] owns the coordinated stop, grace,
//! and human choice.

pub mod quit;
pub mod supervision_quit;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tauri::{Manager, RunEvent, WebviewWindow, WebviewWindowBuilder, WindowEvent};

use crate::guard::{self, Navigation};

static UI_READY: AtomicBool = AtomicBool::new(false);
static UI_READY_GENERATION: AtomicUsize = AtomicUsize::new(0);

/// Records that the trusted UI completed its first host-state call.
pub fn mark_ui_ready() {
    UI_READY.store(true, Ordering::SeqCst);
    UI_READY_GENERATION.fetch_add(1, Ordering::SeqCst);
}

/// Whether the trusted UI has completed its first host-state call.
pub fn ui_ready() -> bool {
    UI_READY.load(Ordering::SeqCst)
}

/// Number of successful trusted-UI readiness reports.
pub fn ui_ready_generation() -> usize {
    UI_READY_GENERATION.load(Ordering::SeqCst)
}

/// Starts the host-owned monitoring pump.
///
/// The pump runs for the application lifetime and drives every project's
/// engine events and deadlines without a WebView command. It stops touching the
/// host as soon as an explicit shutdown begins, so quit grace and coordinated
/// stops keep their existing timing. The thread is detached and uses the single
/// `AppState` host.
pub fn start_host_pump(app: &tauri::App) {
    let handle = app.handle().clone();
    std::thread::spawn(move || {
        loop {
            let state = handle.state::<crate::app::AppState>();
            let Ok(mut host) = state.host.lock() else {
                // A poisoned host during quit cannot be advanced safely.
                return;
            };
            if host.is_shutting_down() {
                return;
            }
            if host.pump().is_err() {
                // One failed iteration must not spin without yielding. The
                // error is retried after the normal interval; it is never
                // reported as progress.
                drop(host);
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            drop(host);
            std::thread::sleep(Duration::from_millis(25));
        }
    });
}

/// Creates the single trusted `main` window from `tauri.conf.json`.
pub fn create_main_window(app: &tauri::App) -> Result<WebviewWindow, Box<dyn std::error::Error>> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == guard::MAIN_LABEL)
        .ok_or("tauri.conf.json does not declare the main window")?
        .clone();
    let window = WebviewWindowBuilder::from_config(app.handle(), &config)?
        .on_navigation(|url| match guard::classify_navigation(url.as_str()) {
            Navigation::LoadLocal => true,
            Navigation::OpenExternal => {
                open_in_system_browser(url.as_str());
                false
            }
            Navigation::Refuse => false,
        })
        .build()?;
    install_close_policy(&window);
    Ok(window)
}

/// Closing the window hides it instead of destroying it or exiting the host.
fn install_close_policy(window: &WebviewWindow) {
    let handle = window.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            api.prevent_close();
            let _ = handle.hide();
        }
    });
}

/// Handles macOS dock reopen and explicit quit requests.
pub fn handle_run_event(app: &tauri::AppHandle, event: &RunEvent) {
    match event {
        RunEvent::ExitRequested { api, code, .. } if code.is_none() => {
            // A user-initiated quit (for example Cmd+Q) goes through the same
            // coordinated shutdown as the explicit UI action. Programmatic
            // exits from the quit worker already carry a code and are allowed.
            api.prevent_exit();
            quit::request_quit(app);
        }
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => {
            if let Some(window) = app.get_webview_window(guard::MAIN_LABEL) {
                let _ = window.show();
                let _ = window.set_focus();
                // Re-run the bootstrap instead of trusting a hidden page's JS state.
                let _ = window.eval("window.location.reload()");
            }
        }
        _ => {}
    }
}

/// Exits successfully after the main window exists and the trusted UI has
/// completed its first `frontend_state` call.
///
/// This is a launch check only. It does not claim that a human observed or
/// operated the UI. `HERNESS_SMOKE_HOLD_MS` keeps the app alive after the ready
/// signal so memory can be sampled; it never changes production behavior.
pub fn start_smoke_test(app: &tauri::App, started: Instant) {
    let handle = app.handle().clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(window) = handle.get_webview_window(guard::MAIN_LABEL) {
                let visible = window.is_visible().unwrap_or(false);
                if visible && ui_ready() {
                    println!(
                        "SMOKE_READY: pid={} startup_ms={}",
                        std::process::id(),
                        started.elapsed().as_millis()
                    );
                    let hold = std::env::var("HERNESS_SMOKE_HOLD_MS")
                        .ok()
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0);
                    if hold > 0 {
                        std::thread::sleep(Duration::from_millis(hold));
                    }
                    println!(
                        "SMOKE_OK: main window is visible and the trusted UI is ready (pid={} startup_ms={})",
                        std::process::id(),
                        started.elapsed().as_millis()
                    );
                    handle.exit(0);
                    return;
                }
            }
            if Instant::now() >= deadline {
                let detail = handle
                    .get_webview_window(guard::MAIN_LABEL)
                    .map(|window| {
                        format!(
                            "visible={:?} title={:?}",
                            window.is_visible(),
                            window.title()
                        )
                    })
                    .unwrap_or_else(|| "main window is missing".to_owned());
                eprintln!(
                    "SMOKE_FAILED: main window or trusted UI was not ready before the deadline: {detail}"
                );
                handle.exit(1);
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
}

/// Drives the real explicit-quit path for automation after the trusted UI is
/// ready.
///
/// This is a test launcher, not a production IPC surface. It uses the same
/// coordinator, 10-second grace, stop worker, and exit codes as the UI action.
/// A human choice is only requested if active work remains; otherwise the app
/// exits normally.
pub fn start_quit_test(app: &tauri::App) {
    let handle = app.handle().clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ui_ready() || !window_visible(&handle) {
            if Instant::now() >= deadline {
                eprintln!("QUIT_TEST_FAILED: trusted UI was not ready before the deadline");
                handle.exit(quit::EXIT_QUIT_TEST_TIMEOUT);
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        println!("QUIT_TEST_READY: pid={}", std::process::id());
        quit::request_quit(&handle);

        // A human-choice prompt in this automated launcher would hang forever.
        // Fail the check explicitly rather than pretending the app quit.
        let timeout = Instant::now() + Duration::from_secs(40);
        while Instant::now() < timeout {
            let snapshot = quit::coordinator().snapshot();
            if snapshot.stage() == quit::QuitStage::AwaitingChoice {
                eprintln!(
                    "QUIT_TEST_NEEDS_HUMAN: pid={} detail={:?}",
                    std::process::id(),
                    snapshot.detail()
                );
                handle.exit(quit::EXIT_QUIT_TEST_TIMEOUT);
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!("QUIT_TEST_FAILED: quit did not complete before the deadline");
        handle.exit(quit::EXIT_QUIT_TEST_TIMEOUT);
    });
}

/// Drives the real window close/reopen path for automation.
///
/// `WebviewWindow::close` emits the same `CloseRequested` event as the close
/// button. The installed policy must hide the window without destroying it or
/// exiting the host. The test then shows and reloads the same window and waits
/// for a new trusted-UI readiness report. This is a test launcher, not a
/// production IPC surface; it does not claim a human clicked the button.
pub fn start_close_reopen_test(app: &tauri::App) {
    let handle = app.handle().clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ui_ready() || !window_visible(&handle) {
            if Instant::now() >= deadline {
                eprintln!("CLOSE_REOPEN_FAILED: trusted UI was not ready before the deadline");
                handle.exit(1);
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let generation = ui_ready_generation();
        let Some(window) = handle.get_webview_window(guard::MAIN_LABEL) else {
            eprintln!("CLOSE_REOPEN_FAILED: main window is missing");
            handle.exit(1);
            return;
        };
        if let Err(error) = window.close() {
            eprintln!("CLOSE_REOPEN_FAILED: close request failed: {error}");
            handle.exit(1);
            return;
        }
        let hide_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if !window.is_visible().unwrap_or(true) {
                break;
            }
            if Instant::now() >= hide_deadline {
                eprintln!("CLOSE_REOPEN_FAILED: close request did not hide the window");
                handle.exit(1);
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        println!(
            "CLOSE_REOPEN_HIDDEN: pid={} generation={generation}",
            std::process::id()
        );

        let _ = window.show();
        let _ = window.set_focus();
        let _ = window.eval("window.location.reload()");
        let ready_deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if ui_ready_generation() > generation {
                println!(
                    "CLOSE_REOPEN_OK: pid={} previous_generation={generation} generation={}",
                    std::process::id(),
                    ui_ready_generation()
                );
                handle.exit(0);
                return;
            }
            if Instant::now() >= ready_deadline {
                eprintln!("CLOSE_REOPEN_FAILED: reloaded UI did not become ready");
                handle.exit(1);
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
}

fn window_visible(app: &tauri::AppHandle) -> bool {
    app.get_webview_window(guard::MAIN_LABEL)
        .and_then(|window| window.is_visible().ok())
        .unwrap_or(false)
}

fn open_in_system_browser(url: &str) {
    // The URL is a user-clicked HTTP(S) link, never a credential. Refuse
    // anything else rather than handing an arbitrary scheme to LaunchServices.
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return;
    }
    let _ = std::process::Command::new("/usr/bin/open")
        .arg("-u")
        .arg(url)
        .spawn();
}
