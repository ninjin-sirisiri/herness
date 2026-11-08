//! Tauri application composition.
//!
//! One `AppState` owns the single desktop host. Commands never construct a
//! second engine, executor, or store. The ChatGPT login service shares the
//! connection registry and Keychain vault with the host.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use herness_core::{
    ConnectionAdmin, CredentialAdmin, CredentialPort, CredentialService, ProjectId,
};
use herness_engine_pi::ProviderEndpoints;
use tauri::Manager;

use crate::commands;
use crate::credentials::{MacKeychainVault, SystemKeychain};
use crate::host::DesktopHost;
use crate::lifecycle;
use crate::login::LoginManager;

/// State managed by Tauri for the process lifetime.
pub struct AppState {
    pub(crate) host: Mutex<DesktopHost>,
    pub(crate) credential_admin: CredentialAdmin<MacKeychainVault<SystemKeychain>>,
    pub(crate) login: Mutex<Option<LoginManager>>,
    pub(crate) selected_project: Mutex<Option<ProjectId>>,
}

/// Builds and runs the desktop application.
pub fn run(smoke_test: bool) -> Result<(), Box<dyn std::error::Error>> {
    let app = tauri::Builder::default()
        .setup(move |app| {
            let root = application_data_root(app)?;
            std::fs::create_dir_all(&root)?;

            let connections = ConnectionAdmin::new();
            let vault = MacKeychainVault::default();
            let credential_service = CredentialService::new(connections.directory(), vault.clone());
            let credential_admin = credential_service.admin();
            let credentials: Arc<dyn CredentialPort + Send + Sync> = Arc::new(credential_service);
            let (host, _reconciliation) = DesktopHost::open(
                &root,
                connections.clone(),
                credentials,
                ProviderEndpoints::official(),
            )?;
            let login = LoginManager::new(connections, vault, root).ok();

            app.manage(AppState {
                host: Mutex::new(host),
                credential_admin,
                login: Mutex::new(login),
                selected_project: Mutex::new(None),
            });

            lifecycle::create_main_window(app)?;
            if smoke_test {
                lifecycle::start_smoke_test(app);
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
            commands::start_run,
            commands::stop_run,
            commands::resume_run,
            commands::poll_project,
            commands::snapshot,
            commands::history,
            commands::approve,
            commands::deny,
        ])
        .build(tauri::generate_context!())?;

    app.run(|app, event| lifecycle::handle_run_event(app, &event));
    Ok(())
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
