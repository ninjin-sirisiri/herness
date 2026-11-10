//! Real Tauri H3 lifecycle fixture.
//!
//! The fixture seeds a durable pending H3 cycle, then launches the real
//! `herness-desktop` binary in its windowless `--h3-lifecycle-test` mode with a
//! fresh absolute `HERNESS_APP_DATA_ROOT`. No main window is created and no
//! project is selected. The launcher restores, pumps, and exits; the test reads
//! the saved store to confirm that startup reconciliation produced the explicit
//! human-wait latch without sending a model request.
//!
//! This is a process/lifecycle check, not a provider or GUI acceptance run.

#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use herness_core::{
    ConnectionAdmin, CredentialAvailability, CredentialPort, ResolvedCredential,
};
use herness_desktop::host::DesktopHost;
use herness_engine_pi::ProviderEndpoints;
use herness_html_sync::{
    Applicability, ApplicabilityReason, CycleId, DocumentCommit, DocumentKey, FingerprintSet,
    H3DocumentState, H3Reason, H3Settings, H3State, H3StateReasonKind, HtmlSyncCommit,
    HumanWaitCause, SourceSnapshot, SyncCycle, document_state_event,
};
use herness_html_sync_tests::fixtures;
use herness_store::{Store, StoreConfig};
use tempfile::TempDir;
use uuid::Uuid;

const TARGET: &str = fixtures::TARGET_PATH;
const SOURCE_V1: &str = "source v1";
static SERIAL: Mutex<()> = Mutex::new(());

struct UnavailableCredentials;

impl CredentialPort for UnavailableCredentials {
    fn availability(
        &self,
        _connection: &herness_core::ConnectionId,
    ) -> Result<CredentialAvailability, herness_core::CoreError> {
        Ok(CredentialAvailability::Unavailable)
    }

    fn resolve(
        &self,
        _connection: &herness_core::ConnectionId,
    ) -> Result<ResolvedCredential, herness_core::CoreError> {
        Err(herness_core::CoreError::InvalidValue {
            field: "credential".to_owned(),
            violation: herness_core::ArgumentViolation::Invalid {
                detail: "the native lifecycle fixture has no credential".to_owned(),
            },
        })
    }
}

#[test]
fn native_lifecycle_startup_quit_and_restore_keep_the_h3_recovery_latch() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = TempDir::new().expect("temporary directory");
    let app_data = temp.path().join("app-data");
    let project_root = temp.path().join("project");
    fs::create_dir_all(project_root.join("docs/sdd/specs")).expect("project");
    fs::write(project_root.join(TARGET), SOURCE_V1).expect("source");

    let credentials: Arc<dyn CredentialPort + Send + Sync> = Arc::new(UnavailableCredentials);
    let endpoints =
        ProviderEndpoints::for_loopback("http://127.0.0.1:1/v1", "http://127.0.0.1:1")
            .expect("loopback endpoints");

    // First host open only assigns the durable project identity.
    let (mut host, _) = DesktopHost::open(
        &app_data,
        ConnectionAdmin::new(),
        Arc::clone(&credentials),
        endpoints.clone(),
    )
    .expect("first host");
    let view = host.open_project(&project_root).expect("open project");
    let project = view.project_id();
    drop(host);

    // Seed a pending cycle as if the process had quit mid-cycle.
    let key = DocumentKey::new(project, TARGET).expect("document key");
    let settings = H3Settings::new(
        project,
        1,
        true,
        vec![TARGET.to_owned()],
        false,
        true,
        fixtures::now(),
    )
    .expect("settings");
    let cycle_id = CycleId::from_parts(project, Uuid::nil());
    let source: SourceSnapshot = fixtures::source(SOURCE_V1);
    let document = H3DocumentState::new(
        key.clone(),
        1,
        None,
        Some(cycle_id),
        None,
        source.clone(),
        FingerprintSet::new(
            settings.fingerprint().clone(),
            fixtures::digest("native-lifecycle-policy"),
            fixtures::digest("native-lifecycle-css"),
            fixtures::digest("native-lifecycle-resources"),
            None,
            None,
            None,
        ),
        H3Reason::new(
            H3StateReasonKind::Pending {
                source_revision: 1,
            },
            Vec::new(),
        )
        .expect("reason"),
        None,
        Vec::new(),
        Applicability::not_applicable(ApplicabilityReason::NeverPublished),
        fixtures::now(),
    )
    .expect("document");
    let cycle = SyncCycle::new(
        cycle_id,
        key.clone(),
        1,
        fixtures::now(),
        source,
        None,
    )
    .expect("cycle");
    let event = document_state_event(&key, None, &document, fixtures::now()).expect("event");
    let config = StoreConfig::new(&app_data).expect("store config");
    let mut store = Store::open(config).expect("store");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(None, document).expect("document commit"))
                .with_cycle(cycle)
                .with_events(vec![event]),
        )
        .expect("seed pending cycle");
    drop(store);

    // Real Tauri process, windowless, no selected project.
    let first = run_desktop(&app_data, "--h3-lifecycle-test");
    assert!(
        first.status.success(),
        "windowless launcher failed: status={:?} stdout={} stderr={}",
        first.status,
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(
        stdout.contains("H3_LIFECYCLE_OK:"),
        "launcher did not report success: {stdout}"
    );
    assert!(stdout.contains("projects=1"), "one restored project: {stdout}");
    assert!(
        stdout.contains("failures=0") && stdout.contains("request_count=0"),
        "startup must not fail or send: {stdout}"
    );
    assert!(
        stdout.contains("window=absent") && stdout.contains("selected_project=none"),
        "the fixture must be windowless and non-selected: {stdout}"
    );

    let config = StoreConfig::new(&app_data).expect("store config");
    let store = Store::open(config).expect("store");
    let record = store
        .load_html_sync_document(project, &key)
        .expect("load document")
        .expect("document");
    assert_eq!(record.state().state(), H3State::WaitingHuman);
    assert_eq!(
        record.state().reason().kind(),
        &H3StateReasonKind::WaitingHuman {
            cause: HumanWaitCause::RecoveryReconciliation
        }
    );
    drop(store);

    // A second real process restores the saved latch and sends nothing.
    let second = run_desktop(&app_data, "--h3-lifecycle-test");
    assert!(
        second.status.success(),
        "windowless restore failed: status={:?} stdout={} stderr={}",
        second.status,
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(String::from_utf8_lossy(&second.stdout).contains("H3_LIFECYCLE_OK:"));
    let config = StoreConfig::new(&app_data).expect("store config");
    let store = Store::open(config).expect("store");
    let record = store
        .load_html_sync_document(project, &key)
        .expect("load document")
        .expect("document");
    assert_eq!(record.state().state(), H3State::WaitingHuman);
    assert_eq!(
        record.state().reason().kind(),
        &H3StateReasonKind::WaitingHuman {
            cause: HumanWaitCause::RecoveryReconciliation
        }
    );
    drop(store);

    // The real windowed quit path runs the H3 quit hook over the same root.
    let quit = run_desktop(&app_data, "--quit-test");
    assert!(
        quit.status.success(),
        "quit test failed: status={:?} stdout={} stderr={}",
        quit.status,
        String::from_utf8_lossy(&quit.stdout),
        String::from_utf8_lossy(&quit.stderr)
    );
    assert!(
        String::from_utf8_lossy(&quit.stdout).contains("QUIT_OK:"),
        "quit did not confirm: {}",
        String::from_utf8_lossy(&quit.stdout)
    );
    let config = StoreConfig::new(&app_data).expect("store config");
    let store = Store::open(config).expect("store");
    let record = store
        .load_html_sync_document(project, &key)
        .expect("load document")
        .expect("document");
    assert_eq!(record.state().state(), H3State::WaitingHuman);
    assert_eq!(
        record.state().reason().kind(),
        &H3StateReasonKind::WaitingHuman {
            cause: HumanWaitCause::RecoveryReconciliation
        }
    );
}

fn run_desktop(app_data: &Path, flag: &str) -> std::process::Output {
    let binary = desktop_binary();
    assert!(
        binary.is_file(),
        "desktop binary {} is missing; run cargo build -p herness-desktop --locked first",
        binary.display()
    );
    Command::new(binary)
        .arg(flag)
        .env("HERNESS_APP_DATA_ROOT", app_data)
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
