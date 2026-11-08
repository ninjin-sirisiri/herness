//! Tauri build script.
//!
//! The app manifest declares every custom command so Tauri 2.12.5 can generate
//! an explicit `allow-<command>` permission for each one. Commands that are not
//! listed here are denied by the runtime authority; `capabilities/main.json`
//! then grants the allow permissions to the trusted `main` window only.

fn main() {
    const COMMANDS: &[&str] = &[
        "ui_ready",
        "open_project",
        "list_projects",
        "select_project",
        "project_view",
        "add_connection",
        "list_connections",
        "save_api_key",
        "start_chatgpt_login",
        "cancel_chatgpt_login",
        "chatgpt_login_status",
        "start_run",
        "stop_run",
        "resume_run",
        "poll_project",
        "snapshot",
        "history",
        "approve",
        "deny",
        "frontend_state",
        "quit_app",
        "quit_state",
        "quit_choice",
    ];

    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to run tauri-build");
}
