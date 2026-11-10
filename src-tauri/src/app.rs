//! Tauri application composition.
//!
//! One `AppState` owns the single desktop host. Commands never construct a
//! second engine, executor, or store. The ChatGPT login service shares the
//! connection registry and Keychain vault with the host.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use herness_core::runtime::ReconciliationReport;
use herness_core::{
    ConnectionAdmin, CredentialAdmin, CredentialPort, CredentialService, ProjectId,
};
use herness_engine_pi::ProviderEndpoints;
use tauri::Manager;

use crate::commands;
use crate::credentials::{MacKeychainVault, SystemKeychain};
use crate::host::DesktopHost;
use crate::html_sync::RenderTestLaunch;
use crate::lifecycle;
use crate::login::LoginManager;

/// How this desktop process was launched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchMode {
    /// Normal interactive launch with the trusted main window.
    Normal {
        /// Run the smoke-test launcher.
        smoke_test: bool,
        /// Run the explicit-quit launcher.
        quit_test: bool,
        /// Run the close/reopen launcher.
        close_reopen_test: bool,
        /// Run the windowless H3 lifecycle launcher.
        h3_lifecycle_test: bool,
    },
    /// Desktop child-process render evidence launcher.
    RenderTest(RenderTestLaunch),
}

impl Default for LaunchMode {
    fn default() -> Self {
        Self::Normal {
            smoke_test: false,
            quit_test: false,
            close_reopen_test: false,
            h3_lifecycle_test: false,
        }
    }
}

/// Parses the desktop process arguments.
///
/// Unknown flags are ignored, matching the existing launchers. `--h3-render-test`
/// requires a fixture directory and an output directory and cannot be combined
/// with the normal window launchers.
pub fn parse_launch_mode<I>(args: I) -> Result<LaunchMode, String>
where
    I: IntoIterator<Item = String>,
{
    let mut smoke_test = false;
    let mut quit_test = false;
    let mut close_reopen_test = false;
    let mut h3_lifecycle_test = false;
    let mut render: Option<(std::path::PathBuf, std::path::PathBuf)> = None;
    let mut budget_ms = 30_000u64;
    let mut cancel_after_ms = None;
    let mut arguments = args.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--smoke-test" => smoke_test = true,
            "--quit-test" => quit_test = true,
            "--close-reopen-test" => close_reopen_test = true,
            "--h3-lifecycle-test" => h3_lifecycle_test = true,
            "--h3-render-test" => {
                let fixture = arguments
                    .next()
                    .ok_or_else(|| "--h3-render-test requires a fixture directory".to_owned())?;
                let output = arguments.next().ok_or_else(|| {
                    "--h3-render-test requires an evidence output directory".to_owned()
                })?;
                if fixture.starts_with("--") || output.starts_with("--") {
                    return Err("--h3-render-test requires two directory arguments".to_owned());
                }
                render = Some((fixture.into(), output.into()));
            }
            "--h3-render-budget-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--h3-render-budget-ms requires a value".to_owned())?;
                budget_ms = value
                    .parse()
                    .map_err(|_| "--h3-render-budget-ms must be an integer".to_owned())?;
            }
            "--h3-render-cancel-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--h3-render-cancel-ms requires a value".to_owned())?;
                cancel_after_ms = Some(
                    value
                        .parse()
                        .map_err(|_| "--h3-render-cancel-ms must be an integer".to_owned())?,
                );
            }
            _ => {}
        }
    }

    if h3_lifecycle_test && (smoke_test || quit_test || close_reopen_test) {
        return Err("--h3-lifecycle-test cannot be combined with the window launchers".to_owned());
    }
    if let Some((fixture_dir, output_dir)) = render {
        if smoke_test || quit_test || close_reopen_test || h3_lifecycle_test {
            return Err("--h3-render-test cannot be combined with the window launchers".to_owned());
        }
        return Ok(LaunchMode::RenderTest(RenderTestLaunch {
            fixture_dir,
            output_dir,
            budget_ms,
            cancel_after_ms,
        }));
    }
    Ok(LaunchMode::Normal {
        smoke_test,
        quit_test,
        close_reopen_test,
        h3_lifecycle_test,
    })
}

/// State managed by Tauri for the process lifetime.
pub struct AppState {
    pub(crate) host: Mutex<DesktopHost>,
    pub(crate) credential_admin: CredentialAdmin<MacKeychainVault<SystemKeychain>>,
    pub(crate) login: Mutex<Option<LoginManager>>,
    pub(crate) selected_project: Mutex<Option<ProjectId>>,
    /// Non-secret restore/reconciliation report produced by this process's
    /// startup. It is shown to the trusted UI and never re-executes work.
    pub(crate) reconciliation: Mutex<ReconciliationReport>,
}

/// Builds and runs the desktop application.
pub fn run(mode: LaunchMode) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let app = tauri::Builder::default()
        .setup(move |app| {
            if let LaunchMode::RenderTest(launch) = &mode {
                let root = std::env::var("HERNESS_APP_DATA_ROOT")
                    .map_err(|_| "--h3-render-test requires an absolute HERNESS_APP_DATA_ROOT")?;
                let root = PathBuf::from(root);
                if !root.is_absolute() {
                    return Err("HERNESS_APP_DATA_ROOT must be an absolute path".into());
                }
                std::fs::create_dir_all(&root)?;
                start_render_test(app, launch.clone());
                return Ok(());
            }
            let (smoke_test, quit_test, close_reopen_test, h3_lifecycle_test) = match &mode {
                LaunchMode::Normal {
                    smoke_test,
                    quit_test,
                    close_reopen_test,
                    h3_lifecycle_test,
                } => (
                    *smoke_test,
                    *quit_test,
                    *close_reopen_test,
                    *h3_lifecycle_test,
                ),
                LaunchMode::RenderTest(_) => unreachable!("render mode returned above"),
            };

            let root = application_data_root(app)?;
            std::fs::create_dir_all(&root)?;

            let connections = ConnectionAdmin::new();
            let vault = MacKeychainVault::default();
            let login_result = LoginManager::new(connections.clone(), vault.clone(), root.clone());
            let (credentials, credential_admin, login) = match login_result {
                Ok(login) => {
                    let credentials = login.credential_port();
                    let admin = login.credential_admin();
                    (credentials, admin, Some(login))
                }
                Err(_) => {
                    // API-key connections still work without the ChatGPT
                    // refresh machinery. The UI reports login as unavailable.
                    let service = CredentialService::new(connections.directory(), vault.clone());
                    let admin = service.admin();
                    (
                        Arc::new(service) as Arc<dyn CredentialPort + Send + Sync>,
                        admin,
                        None,
                    )
                }
            };
            let (mut host, reconciliation) = DesktopHost::open_with_html_sync_pack(
                &root,
                connections,
                credentials,
                ProviderEndpoints::official(),
                std::env::var_os("SDD_PACK_ROOT")
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute()),
            )?;
            // The production render port uses the same application handle and
            // the real hidden WKWebView. It grants no candidate access.
            host.html_sync_services_mut()
                .install_native_render(app.handle().clone());

            app.manage(AppState {
                host: Mutex::new(host),
                credential_admin,
                login: Mutex::new(login),
                selected_project: Mutex::new(None),
                reconciliation: Mutex::new(reconciliation),
            });

            // Execution is host-owned: the pump drains every project's engine
            // events and applies run deadlines even with no window and no
            // non-selected project poll.
            lifecycle::start_host_pump(app);
            if h3_lifecycle_test {
                lifecycle::start_h3_lifecycle_test(app);
                return Ok(());
            }
            lifecycle::create_main_window(app)?;
            if smoke_test {
                lifecycle::start_smoke_test(app, started);
            }
            if quit_test {
                lifecycle::start_quit_test(app);
            }
            if close_reopen_test {
                lifecycle::start_close_reopen_test(app);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::ui_ready,
            commands::frontend_state,
            commands::open_project,
            commands::list_projects,
            commands::select_project,
            commands::project_view,
            commands::add_connection,
            commands::list_connections,
            commands::save_api_key,
            commands::start_chatgpt_login,
            commands::cancel_chatgpt_login,
            commands::chatgpt_login_status,
            commands::chatgpt_models,
            commands::set_connection_model,
            commands::start_run,
            commands::stop_run,
            commands::resume_run,
            commands::poll_project,
            commands::snapshot,
            commands::history,
            commands::approve,
            commands::deny,
            commands::supervision_create,
            commands::supervision_list,
            commands::supervision_get,
            commands::supervision_start,
            commands::supervision_stop,
            commands::supervision_cancel,
            commands::supervision_resume,
            commands::supervision_reassess,
            commands::supervision_change,
            commands::supervision_profile,
            commands::supervision_verify_profile,
            commands::supervision_consent,
            commands::supervision_evidence,
            commands::supervision_budget,
            commands::supervision_recovery,
            commands::html_sync_state,
            commands::html_sync_history,
            commands::html_sync_budget,
            commands::html_sync_barrier,
            commands::html_sync_approve,
            commands::html_sync_enable,
            commands::html_sync_pause,
            commands::html_sync_cancel,
            commands::html_sync_resume,
            commands::html_sync_reassess,
            commands::html_sync_resolve_conflict,
            commands::html_sync_restore,
            commands::quit_app,
            commands::quit_state,
            commands::quit_choice,
        ])
        .build(tauri::generate_context!())?;

    app.run(|app, event| lifecycle::handle_run_event(app, &event));
    Ok(())
}

/// Starts the desktop render-evidence child process and exits when it finishes.
///
/// The producer is a raw hidden WKWebView created by the render bridge, never
/// the trusted main UI webview. No main window is created in this mode.
fn start_render_test(app: &tauri::App, launch: RenderTestLaunch) {
    let handle = app.handle().clone();
    std::thread::spawn(
        move || match crate::html_sync::render_test::execute(&handle, &launch) {
            Ok(()) => handle.exit(0),
            Err(error) => {
                eprintln!("H3_RENDER_FAILED: {error}");
                handle.exit(2);
            }
        },
    );
}

fn application_data_root(app: &tauri::App) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(value) = std::env::var("HERNESS_APP_DATA_ROOT") {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err("HERNESS_APP_DATA_ROOT must be an absolute path".into());
        }
        return Ok(path);
    }
    let base = app.path().app_data_dir()?;
    Ok(base.join("herness"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn render_test_launch_is_explicit_and_carries_the_budget() {
        let mode = parse_launch_mode(args(&[
            "--h3-render-test",
            "fixture",
            "out",
            "--h3-render-budget-ms",
            "1234",
            "--h3-render-cancel-ms",
            "99",
            "--some-future-flag",
        ]))
        .expect("render launch");
        let LaunchMode::RenderTest(launch) = mode else {
            panic!("render launch expected");
        };
        assert_eq!(launch.fixture_dir, PathBuf::from("fixture"));
        assert_eq!(launch.output_dir, PathBuf::from("out"));
        assert_eq!(launch.budget_ms, 1_234);
        assert_eq!(launch.cancel_after_ms, Some(99));
    }

    #[test]
    fn render_test_launch_rejects_missing_directories_and_window_combinations() {
        assert!(parse_launch_mode(args(&["--h3-render-test", "fixture"])).is_err());
        assert!(
            parse_launch_mode(args(&[
                "--h3-render-test",
                "fixture",
                "out",
                "--smoke-test"
            ]))
            .is_err()
        );
        assert!(parse_launch_mode(args(&["--h3-render-budget-ms", "not-a-number"])).is_err());
    }

    #[test]
    fn normal_launch_flags_keep_their_existing_meaning() {
        assert_eq!(
            parse_launch_mode(Vec::<String>::new()).expect("normal"),
            LaunchMode::default()
        );
        assert_eq!(
            parse_launch_mode(args(&["--smoke-test"])).expect("smoke"),
            LaunchMode::Normal {
                smoke_test: true,
                quit_test: false,
                close_reopen_test: false,
                h3_lifecycle_test: false,
            }
        );
        assert_eq!(
            parse_launch_mode(args(&["--h3-lifecycle-test"])).expect("h3 lifecycle"),
            LaunchMode::Normal {
                smoke_test: false,
                quit_test: false,
                close_reopen_test: false,
                h3_lifecycle_test: true,
            }
        );
        assert!(
            parse_launch_mode(args(&["--h3-lifecycle-test", "--smoke-test"])).is_err(),
            "the windowless lifecycle launcher cannot also create a window"
        );
    }
}
