//! Window lifetime and navigation policy.
//!
//! Closing the last window hides it and leaves the Rust host running. Reopening
//! shows the same main window and reloads the page so JavaScript state is not
//! reused; the page then reads a fresh runtime snapshot. The WebView never loads
//! a remote document, and external HTTP(S) links open in the system browser.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tauri::{Manager, RunEvent, WebviewWindow, WebviewWindowBuilder, WindowEvent};

use crate::guard::{self, Navigation};

static UI_READY: AtomicBool = AtomicBool::new(false);

/// Records that the trusted UI completed its first host-state call.
pub fn mark_ui_ready() {
    UI_READY.store(true, Ordering::SeqCst);
}

/// Whether the trusted UI has completed its first host-state call.
pub fn ui_ready() -> bool {
    UI_READY.load(Ordering::SeqCst)
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

/// Handles macOS dock reopen by showing and refreshing the same window.
pub fn handle_run_event(app: &tauri::AppHandle, event: &RunEvent) {
    #[cfg(target_os = "macos")]
    if let RunEvent::Reopen { .. } = event
        && let Some(window) = app.get_webview_window(guard::MAIN_LABEL)
    {
        let _ = window.show();
        let _ = window.set_focus();
        // Re-run the bootstrap instead of trusting a hidden page's JS state.
        let _ = window.eval("window.location.reload()");
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (app, event);
}

/// Exits successfully after the main window exists and the trusted UI has
/// completed its first `frontend_state` call.
///
/// This is a launch check only. It does not claim that a human observed or
/// operated the UI.
pub fn start_smoke_test(app: &tauri::App) {
    let handle = app.handle().clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(window) = handle.get_webview_window(guard::MAIN_LABEL) {
                let visible = window.is_visible().unwrap_or(false);
                if visible && ui_ready() {
                    println!("SMOKE_OK: main window is visible and the trusted UI is ready");
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
