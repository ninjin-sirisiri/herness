//! Black-box tests for connection settings, URL and redirect policy, the
//! write-only credential boundary, Keychain failure handling, no-fallback
//! resolution, refresh serialization, and redaction.
//!
//! Every test uses an in-memory vault fake. No real Keychain item, network
//! request, external service, or real credential is used. The SQLite store is
//! opened only in a temporary application-data directory and is scanned for a
//! synthetic secret canary.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use herness_core::*;
use herness_runtime_tests::fixtures::ProjectFixture;
use herness_store::{Store, StoreConfig};
use serde_json::json;
use tempfile::TempDir;

const CANARY: &str = "sk-canary-7f2c9d1e-connections";
const CANARY_B: &str = "sk-canary-b-4a8e1c0d-connections";

#[derive(Debug, Default)]
struct VaultState {
    items: BTreeMap<String, Vec<u8>>,
    reads: Vec<String>,
    writes: Vec<String>,
    deletes: Vec<String>,
    read_failure: Option<VaultFailure>,
    write_failure: Option<VaultFailure>,
    delete_failure: Option<VaultFailure>,
}

#[derive(Debug, Clone, Default)]
struct FakeVault {
    state: Arc<Mutex<VaultState>>,
}

impl FakeVault {
    fn fail_write(&self, failure: VaultFailure) {
        self.state.lock().unwrap().write_failure = Some(failure);
    }

    fn fail_read(&self, failure: VaultFailure) {
        self.state.lock().unwrap().read_failure = Some(failure);
    }

    fn fail_delete(&self, failure: VaultFailure) {
        self.state.lock().unwrap().delete_failure = Some(failure);
    }

    fn raw(&self, account: &str) -> Option<Vec<u8>> {
        self.state.lock().unwrap().items.get(account).cloned()
    }

    fn set_raw(&self, account: &str, bytes: &[u8]) {
        self.state
            .lock()
            .unwrap()
            .items
            .insert(account.to_owned(), bytes.to_vec());
    }

    fn reads(&self) -> Vec<String> {
        self.state.lock().unwrap().reads.clone()
    }

    fn writes(&self) -> Vec<String> {
        self.state.lock().unwrap().writes.clone()
    }

    fn account_reads(&self, account: &str) -> usize {
        self.reads()
            .iter()
            .filter(|read| read.as_str() == account)
            .count()
    }
}

impl CredentialVault for FakeVault {
    fn set(&self, account: &VaultAccount, data: &[u8]) -> Result<(), VaultFailure> {
        let mut state = self.state.lock().unwrap();
        state.writes.push(account.as_str().to_owned());
        if let Some(failure) = state.write_failure.take() {
            return Err(failure);
        }
        state
            .items
            .insert(account.as_str().to_owned(), data.to_vec());
        Ok(())
    }

    fn get(&self, account: &VaultAccount) -> Result<Option<Vec<u8>>, VaultFailure> {
        let mut state = self.state.lock().unwrap();
        state.reads.push(account.as_str().to_owned());
        if let Some(failure) = state.read_failure.take() {
            return Err(failure);
        }
        Ok(state.items.get(account.as_str()).cloned())
    }

    fn delete(&self, account: &VaultAccount) -> Result<(), VaultFailure> {
        let mut state = self.state.lock().unwrap();
        state.deletes.push(account.as_str().to_owned());
        if let Some(failure) = state.delete_failure.take() {
            return Err(failure);
        }
        match state.items.remove(account.as_str()) {
            Some(_) => Ok(()),
            None => Err(VaultFailure::MissingItem),
        }
    }
}

fn api_key_settings(provider: Provider, model: &str) -> ConnectionSettings {
    ConnectionSettings::new(
        ConnectionId::new(),
        provider,
        model,
        AuthMethod::ApiKey,
        None,
        None,
    )
    .expect("valid API-key settings")
}

fn compatible_settings() -> ConnectionSettings {
    ConnectionSettings::new(
        ConnectionId::new(),
        Provider::OpenAiCompatible,
        "local-model",
        AuthMethod::ApiKey,
        Some(Endpoint::parse("http://127.0.0.1:11434/v1").expect("loopback endpoint")),
        None,
    )
    .expect("valid compatible settings")
}

fn chatgpt_settings() -> ConnectionSettings {
    ConnectionSettings::new(
        ConnectionId::new(),
        Provider::OpenAi,
        "gpt-5",
        AuthMethod::ChatGptLogin,
        None,
        None,
    )
    .expect("valid ChatGPT settings")
}

struct Harness {
    admin: ConnectionAdmin,
    vault: FakeVault,
    service: CredentialService<FakeVault>,
}

impl Harness {
    fn new() -> Self {
        let admin = ConnectionAdmin::new();
        let vault = FakeVault::default();
        let service = CredentialService::new(admin.directory(), vault.clone());
        Self {
            admin,
            vault,
            service,
        }
    }

    fn with_refresher<R: CredentialRefresher + 'static>(refresher: R) -> Self {
        let admin = ConnectionAdmin::new();
        let vault = FakeVault::default();
        let service =
            CredentialService::with_refresher(admin.directory(), vault.clone(), refresher);
        Self {
            admin,
            vault,
            service,
        }
    }

    fn add(&self, settings: ConnectionSettings) -> ConnectionSettings {
        self.admin.add(settings.clone()).expect("add connection");
        settings
    }

    fn save_api_key(&self, connection: ConnectionId, secret: &str) {
        self.service
            .admin()
            .save_api_key(
                connection,
                SecretString::new(secret).expect("non-empty secret"),
            )
            .expect("save API key");
    }

    fn save_token_set(&self, connection: ConnectionId, token_set: OAuthTokenSet) {
        self.service
            .admin()
            .save_oauth_token_set(connection, token_set)
            .expect("save token set");
    }
}

fn expired_token_set(access: &str) -> OAuthTokenSet {
    OAuthTokenSet::new(
        SecretString::new(access).expect("non-empty access token"),
        Some(SecretString::new("refresh-token").expect("non-empty refresh token")),
        Some(Timestamp::from_unix_millis(1_000)),
    )
}

fn valid_token_set(access: &str) -> OAuthTokenSet {
    OAuthTokenSet::new(
        SecretString::new(access).expect("non-empty access token"),
        Some(SecretString::new("refresh-token").expect("non-empty refresh token")),
        Some(Timestamp::from_unix_millis(4_000_000_000_000)),
    )
}

#[test]
fn required_provider_kinds_have_non_secret_settings_and_status() {
    let harness = Harness::new();
    let openai = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    let anthropic = harness.add(api_key_settings(Provider::Anthropic, "claude-sonnet"));
    let compatible = harness.add(compatible_settings());
    let chatgpt = harness.add(chatgpt_settings());

    assert_eq!(harness.admin.directory().list().unwrap().len(), 4);
    assert_eq!(openai.provider(), Provider::OpenAi);
    assert_eq!(anthropic.provider(), Provider::Anthropic);
    assert_eq!(compatible.provider(), Provider::OpenAiCompatible);
    assert_eq!(
        compatible.endpoint().unwrap().as_url(),
        "http://127.0.0.1:11434/v1"
    );
    assert_eq!(chatgpt.auth_method(), AuthMethod::ChatGptLogin);

    let broker = harness.service.broker();
    assert_eq!(
        broker.state(openai.connection_id()).unwrap(),
        ConnectionState::AuthRequired
    );
    assert_eq!(
        broker.state(chatgpt.connection_id()).unwrap(),
        ConnectionState::LoginRequired
    );

    let info = broker.connection_info(openai.connection_id()).unwrap();
    assert_eq!(info.status(), ConnectionStatus::AuthRequired);
    let encoded = serde_json::to_string(&info).unwrap();
    assert!(encoded.contains("\"provider\":\"openai\""));
    assert!(encoded.contains("\"authMethod\":\"api_key\""));
    assert!(encoded.contains("\"status\":\"auth_required\""));

    assert_eq!(
        broker.availability(&openai.connection_id()).unwrap(),
        CredentialAvailability::Unavailable
    );
    assert_eq!(
        broker.availability(&chatgpt.connection_id()).unwrap(),
        CredentialAvailability::LoginRequired
    );
}

#[test]
fn assessment_connection_capabilities_are_registered_and_round_trip() {
    let harness = Harness::new();
    let directory = harness.admin.directory();

    let jev = harness.add(
        ConnectionSettings::new(
            ConnectionId::new(),
            Provider::TypeSafe,
            "jev-1.14.0",
            AuthMethod::ApiKey,
            None,
            None,
        )
        .expect("valid legacy TypeSafe settings"),
    );
    let jev_capabilities = directory.capabilities(jev.connection_id()).unwrap();
    assert_eq!(
        jev_capabilities.endpoint_class(),
        EndpointClass::TypeSafeSystemOne
    );
    assert_eq!(jev_capabilities.usage(), ConnectionUsage::AssessmentOnly);
    assert!(!jev_capabilities.allows_agent_execution());
    assert_eq!(
        directory
            .agent_execution_capabilities(jev.connection_id())
            .unwrap_err(),
        ConnectionError::AgentExecutionNotAllowed {
            connection: jev.connection_id()
        }
    );

    let decisions = harness.add(
        ConnectionSettings::new_with_capabilities(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-6-luna",
            AuthMethod::ApiKey,
            None,
            None,
            ConnectionCapabilityDeclaration::new(
                EndpointClass::OpenAiDecisions,
                InputCapabilities::text_and_image(),
            ),
        )
        .expect("valid Decisions settings"),
    );
    let decisions_capabilities = directory.capabilities(decisions.connection_id()).unwrap();
    assert_eq!(
        decisions_capabilities.endpoint_class(),
        EndpointClass::OpenAiDecisions
    );
    assert_eq!(
        decisions_capabilities.usage(),
        ConnectionUsage::AssessmentOnly
    );
    assert!(decisions_capabilities.input().supports_image());
    assert_eq!(
        directory
            .agent_execution_capabilities(decisions.connection_id())
            .unwrap_err(),
        ConnectionError::AgentExecutionNotAllowed {
            connection: decisions.connection_id()
        }
    );

    let openai = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    let openai_capabilities = directory.capabilities(openai.connection_id()).unwrap();
    assert_eq!(
        openai_capabilities.endpoint_class(),
        EndpointClass::OpenAiResponses
    );
    assert_eq!(openai_capabilities.usage(), ConnectionUsage::AgentExecution);
    assert!(openai_capabilities.allows_agent_execution());
    assert_eq!(directory.list_capabilities().unwrap().len(), 3);

    // The declaration is non-secret and round-trips with the settings.
    let encoded = serde_json::to_value(&decisions).unwrap();
    assert_eq!(encoded["capabilities"]["endpointClass"], "openai_decisions");
    assert_eq!(encoded["capabilities"]["input"]["text"], true);
    assert_eq!(encoded["capabilities"]["input"]["image"], true);
    let encoded_text = encoded.to_string().to_ascii_lowercase();
    for forbidden in ["token", "secret", "authorization"] {
        assert!(!encoded_text.contains(forbidden), "leaked {forbidden}");
    }
    assert_eq!(
        serde_json::from_value::<ConnectionSettings>(encoded.clone()).unwrap(),
        decisions
    );

    // Settings written before H2 have no capability declaration. The absent
    // field is an H1 row and keeps the H1 OpenAI agent endpoint; new
    // assessment-only settings always write the declaration.
    let mut legacy = encoded.clone();
    legacy.as_object_mut().unwrap().remove("capabilities");
    let decoded: ConnectionSettings = serde_json::from_value(legacy).unwrap();
    assert_eq!(
        decoded.capabilities().unwrap().endpoint_class(),
        EndpointClass::OpenAiResponses,
        "legacy OpenAI settings keep the H1 agent endpoint"
    );

    // A newer/unknown capability form is rejected instead of guessed.
    let mut unknown_field = encoded.clone();
    unknown_field["capabilities"]["usage"] = serde_json::json!("agent_execution");
    assert!(serde_json::from_value::<ConnectionSettings>(unknown_field).is_err());
    let mut unknown_class = encoded;
    unknown_class["capabilities"]["endpointClass"] = serde_json::json!("openai_newer_endpoint");
    assert!(serde_json::from_value::<ConnectionSettings>(unknown_class).is_err());

    // A foreign origin cannot be attached to TypeSafe or Decisions.
    let custom = Endpoint::parse("http://127.0.0.1:8080/v1").unwrap();
    assert!(matches!(
        ConnectionSettings::new(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-6-luna",
            AuthMethod::ApiKey,
            Some(custom.clone()),
            None,
        )
        .unwrap_err(),
        ConnectionError::EndpointNotAllowed {
            provider: Provider::OpenAi
        }
    ));
    assert!(matches!(
        ConnectionSettings::new(
            ConnectionId::new(),
            Provider::TypeSafe,
            "jev-1.14.0",
            AuthMethod::ApiKey,
            Some(custom),
            None,
        )
        .unwrap_err(),
        ConnectionError::EndpointNotAllowed {
            provider: Provider::TypeSafe
        }
    ));

    // Credentials in a URL are rejected by endpoint validation.
    assert_eq!(
        Endpoint::parse("https://user:pass@api.example.com/v1").unwrap_err(),
        EndpointViolation::UserInfoNotAllowed
    );

    // Decisions never accept ChatGPT login.
    assert!(matches!(
        ConnectionSettings::new_with_capabilities(
            ConnectionId::new(),
            Provider::OpenAi,
            "gpt-6-luna",
            AuthMethod::ChatGptLogin,
            None,
            None,
            ConnectionCapabilityDeclaration::new(
                EndpointClass::OpenAiDecisions,
                InputCapabilities::text_only(),
            ),
        )
        .unwrap_err(),
        ConnectionError::CapabilityDeclarationRejected { .. }
    ));
}

#[test]
fn url_validation_and_remote_http_acknowledgment_are_enforced() {
    // Accepted forms.
    for value in [
        "https://api.example.com/v1/",
        "HTTPS://API.Example.COM:443/v1",
        "http://127.0.0.1:8080/v1",
        "http://127.200.0.1",
        "http://[::1]:11434/v1",
        "http://localhost:3000",
    ] {
        let endpoint = Endpoint::parse(value).expect(value);
        assert!(!endpoint.as_url().contains("?"), "{value}");
    }
    assert_eq!(
        Endpoint::parse("HTTPS://API.Example.COM:443/v1/")
            .unwrap()
            .as_url(),
        "https://api.example.com/v1"
    );

    // Rejected forms.
    assert_eq!(
        Endpoint::parse("http://user:pass@example.com").unwrap_err(),
        EndpointViolation::UserInfoNotAllowed
    );
    assert!(matches!(
        Endpoint::parse("file:///etc/passwd").unwrap_err(),
        EndpointViolation::UnsupportedScheme { .. }
    ));
    assert!(matches!(
        Endpoint::parse("javascript:alert(1)").unwrap_err(),
        EndpointViolation::UnsupportedScheme { .. }
    ));
    assert_eq!(
        Endpoint::parse("https://exa\nmple.com").unwrap_err(),
        EndpointViolation::ControlCharacter
    );
    assert_eq!(
        Endpoint::parse("https://exa mple.com").unwrap_err(),
        EndpointViolation::Whitespace
    );
    assert_eq!(
        Endpoint::parse("http://").unwrap_err(),
        EndpointViolation::MissingHost
    );
    assert_eq!(
        Endpoint::parse("https://example.com/path?token=1").unwrap_err(),
        EndpointViolation::QueryNotAllowed
    );
    assert_eq!(
        Endpoint::parse("https://example.com/path#fragment").unwrap_err(),
        EndpointViolation::FragmentNotAllowed
    );
    assert_eq!(
        Endpoint::parse("http://example.com:99999").unwrap_err(),
        EndpointViolation::InvalidPort
    );

    // Remote plain HTTP needs and records an explicit acknowledgment.
    let remote = Endpoint::parse("http://api.example.com/v1").unwrap();
    let connection = ConnectionId::new();
    let missing = ConnectionSettings::new(
        connection,
        Provider::OpenAiCompatible,
        "model",
        AuthMethod::ApiKey,
        Some(remote.clone()),
        None,
    );
    assert_eq!(
        missing.unwrap_err(),
        ConnectionError::RemoteHttpRequiresAcknowledgment
    );
    let acknowledged = ConnectionSettings::new(
        connection,
        Provider::OpenAiCompatible,
        "model",
        AuthMethod::ApiKey,
        Some(remote),
        Some(InsecureRemoteHttp::Acknowledged),
    )
    .unwrap();
    assert_eq!(
        acknowledged.insecure_http_acknowledged(),
        Some(InsecureRemoteHttp::Acknowledged)
    );
    let encoded = serde_json::to_value(&acknowledged).unwrap();
    assert_eq!(encoded["insecureHttpAcknowledged"], "acknowledged");
    assert_eq!(encoded["endpoint"], "http://api.example.com/v1");

    // Loopback plain HTTP does not require the acknowledgment.
    let loopback = ConnectionSettings::new(
        ConnectionId::new(),
        Provider::OpenAiCompatible,
        "model",
        AuthMethod::ApiKey,
        Some(Endpoint::parse("http://127.0.0.1:11434/v1").unwrap()),
        None,
    )
    .unwrap();
    assert!(loopback.insecure_http_acknowledged().is_none());
}

#[test]
fn redirect_policy_attaches_only_to_the_exact_same_origin() {
    let request = Origin::parse("https://api.example.com:443/v1").unwrap();
    for target in [
        "https://api.example.com/v2",
        "HTTPS://API.EXAMPLE.COM:443/v2",
        "https://api.example.com/v2?next=1#section",
    ] {
        assert_eq!(
            redirect_auth_decision(&request, target),
            RedirectAuthDecision::AttachAuthorization,
            "{target}"
        );
    }

    for target in [
        "http://api.example.com/v2",
        "https://api.example.com:8443/v2",
        "https://other.example.com/v2",
        "https://sub.api.example.com/v2",
        "https://user:pass@api.example.com/v2",
        "ftp://api.example.com/v2",
        "not a url",
    ] {
        match redirect_auth_decision(&request, target) {
            RedirectAuthDecision::DropAuthorization {
                requires_re_resolution,
                reason,
            } => {
                assert!(requires_re_resolution, "{target}");
                assert!(
                    matches!(
                        reason,
                        RedirectDropReason::CrossOrigin | RedirectDropReason::InvalidTarget
                    ),
                    "{target}"
                );
            }
            RedirectAuthDecision::AttachAuthorization => {
                panic!("credential would be attached to {target}")
            }
        }
    }
}

#[test]
fn api_key_canary_stays_in_the_vault_and_out_of_public_values() {
    let harness = Harness::new();
    let settings = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    harness.save_api_key(settings.connection_id(), CANARY);

    let broker = harness.service.broker();
    let resolved = broker.resolve(&settings.connection_id()).unwrap();
    assert_eq!(resolved.kind(), CredentialKind::ApiKey);
    assert_eq!(resolved.expose_secret(), CANARY);
    assert!(!format!("{resolved:?}").contains(CANARY));

    let info = broker.connection_info(settings.connection_id()).unwrap();
    assert!(!format!("{info:?}").contains(CANARY));
    assert!(!serde_json::to_string(&info).unwrap().contains(CANARY));
    assert!(!format!("{settings:?}").contains(CANARY));
    assert!(!serde_json::to_string(&settings).unwrap().contains(CANARY));

    let material = CredentialMaterial::ApiKey(SecretString::new(CANARY).unwrap());
    assert!(!format!("{material:?}").contains(CANARY));

    let account = settings.credential_ref().as_str();
    let stored = harness
        .vault
        .raw(account)
        .expect("credential in fake vault");
    assert!(contains_bytes(&stored, CANARY.as_bytes()));
    assert_eq!(harness.vault.writes(), vec![account.to_owned()]);

    // A synthetic error with the canary in a detail field is scrubbed before
    // display.
    let error = CoreError::InvalidValue {
        field: "endpoint".to_owned(),
        violation: ArgumentViolation::Invalid {
            detail: format!("failed with {CANARY}"),
        },
    };
    let rendered = redact_error(&error, [CANARY]);
    assert!(!rendered.contains(CANARY));
    assert!(rendered.contains(REDACTED));

    // Headers are redacted, including proxy and cookie variants.
    let authorization = format!("Bearer {CANARY}");
    let headers = redact_headers([
        ("Authorization", authorization.as_str()),
        ("Proxy-Authorization", CANARY),
        ("Cookie", CANARY),
        ("Content-Type", "application/json"),
    ]);
    let joined = format!("{headers:?}");
    assert!(!joined.contains(CANARY));
    assert!(joined.contains("application/json"));

    let log_line =
        format!("connection={info:?} settings={settings:?} headers={joined} error={rendered}");
    assert!(
        !log_line.contains(CANARY),
        "secret reached a log-shaped value"
    );
}

#[test]
fn secret_canary_never_reaches_store_checkpoint_event_or_app_data_files() {
    let temp = TempDir::new().unwrap();
    let app_data = temp.path().join("app-data");
    let project = temp.path().join("project");
    fs::create_dir_all(&project).unwrap();

    let fixture = ProjectFixture::new();
    let config = StoreConfig::new(&app_data).unwrap();
    config.ensure_outside_project(&project).unwrap();

    let harness = Harness::new();
    let settings = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    harness.save_api_key(settings.connection_id(), CANARY);
    let info = harness
        .service
        .broker()
        .connection_info(settings.connection_id())
        .unwrap();

    let settings_json = serde_json::to_value(&settings).unwrap();
    let event_payload = EventPayload::new(json!({
        "connection": info,
        "settings": settings_json,
    }));
    let event = EventDraft::new(
        fixture.project_id,
        fixture.agent_id,
        fixture.session_id,
        fixture.run_id,
        None,
        EventKind::new("connection.settings").unwrap(),
        Timestamp::from_unix_millis(1_700_000_000_000),
        event_payload,
    )
    .unwrap();

    let checkpoint_payload = serde_json::to_vec(&settings).unwrap();
    assert!(!contains_bytes(&checkpoint_payload, CANARY.as_bytes()));
    let checkpoint = Checkpoint::new(
        fixture.run_id,
        CheckpointFormatVersion::new(1).unwrap(),
        CheckpointPayload::new(checkpoint_payload),
    );

    let mut store = Store::open(config.clone()).unwrap();
    let receipt = store
        .commit_checkpoint(
            CheckpointCommit::new(checkpoint, None, vec![event]).expect("valid commit"),
        )
        .expect("commit settings event");
    assert!(!contains_bytes(
        &serde_json::to_vec(receipt.events()).unwrap(),
        CANARY.as_bytes()
    ));
    drop(store);

    let mut files = Vec::new();
    collect_files(temp.path(), &mut files);
    assert!(!files.is_empty(), "store should have created a database");
    for file in files {
        let bytes = fs::read(&file).unwrap();
        assert!(
            !contains_bytes(&bytes, CANARY.as_bytes()),
            "secret canary found in {}",
            file.display()
        );
    }

    // The vault remains the one place that holds the secret.
    let stored = harness
        .vault
        .raw(settings.credential_ref().as_str())
        .expect("credential in fake vault");
    assert!(contains_bytes(&stored, CANARY.as_bytes()));
}

#[test]
fn keychain_denial_lock_and_update_failure_never_write_plaintext() {
    let cases = [
        (VaultFailure::Denied, CredentialFailureKind::KeychainDenied),
        (VaultFailure::Locked, CredentialFailureKind::KeychainLocked),
        (
            VaultFailure::UpdateFailed,
            CredentialFailureKind::KeychainWriteFailed,
        ),
        (
            VaultFailure::DuplicateItem,
            CredentialFailureKind::KeychainDuplicateItem,
        ),
        (
            VaultFailure::Unavailable,
            CredentialFailureKind::KeychainUnavailable,
        ),
    ];

    for (vault_failure, expected_kind) in cases {
        let temp = TempDir::new().unwrap();
        let app_data = temp.path().join("app-data");
        fs::create_dir_all(&app_data).unwrap();

        let harness = Harness::new();
        harness.vault.fail_write(vault_failure);
        let settings = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
        let error = harness
            .service
            .admin()
            .save_api_key(settings.connection_id(), SecretString::new(CANARY).unwrap())
            .expect_err("vault failure must fail the save");
        assert_eq!(
            error,
            CoreError::CredentialUnavailable {
                connection: settings.connection_id(),
                failure: expected_kind,
            }
        );
        assert!(!format!("{error:?}").contains(CANARY));
        assert!(!error.to_string().contains(CANARY));

        let mut files = Vec::new();
        collect_files(temp.path(), &mut files);
        assert!(
            files.is_empty(),
            "plaintext fallback appeared: {files:?} for {vault_failure:?}"
        );
        assert_eq!(harness.vault.reads(), Vec::<String>::new());
    }
}

#[test]
fn removing_a_credential_reports_keychain_update_failure_and_missing_is_idempotent() {
    let harness = Harness::new();
    let connection = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    harness.save_api_key(connection.connection_id(), CANARY);

    harness.vault.fail_delete(VaultFailure::UpdateFailed);
    let error = harness
        .service
        .admin()
        .remove(connection.connection_id())
        .expect_err("delete failure must be reported");
    assert_eq!(
        error,
        CoreError::CredentialUnavailable {
            connection: connection.connection_id(),
            failure: CredentialFailureKind::KeychainWriteFailed,
        }
    );
    assert!(!format!("{error:?}").contains(CANARY));

    // A missing item is already removed and does not fail the human action.
    harness
        .service
        .admin()
        .remove(connection.connection_id())
        .unwrap();
    assert_eq!(
        harness
            .service
            .broker()
            .state(connection.connection_id())
            .unwrap(),
        ConnectionState::AuthRequired
    );
}

#[test]
fn resolving_one_connection_never_falls_back_to_another() {
    let harness = Harness::new();
    let first = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    let second = harness.add(api_key_settings(Provider::Anthropic, "claude-sonnet"));
    harness.save_api_key(first.connection_id(), CANARY);
    harness.save_api_key(second.connection_id(), CANARY_B);

    let broker = harness.service.broker();
    assert_eq!(
        broker
            .resolve(&first.connection_id())
            .unwrap()
            .expose_secret(),
        CANARY
    );
    assert_eq!(
        broker
            .resolve(&second.connection_id())
            .unwrap()
            .expose_secret(),
        CANARY_B
    );
    assert_eq!(
        broker.state(first.connection_id()).unwrap(),
        ConnectionState::Available
    );

    let second_account = second.credential_ref().as_str();
    let second_reads_before = harness.vault.account_reads(second_account);

    harness
        .service
        .admin()
        .remove(first.connection_id())
        .unwrap();
    let error = broker
        .resolve(&first.connection_id())
        .expect_err("removed credential must stop the request");
    assert_eq!(
        error,
        CoreError::AuthenticationRequired {
            connection: first.connection_id()
        }
    );
    assert!(!format!("{error:?}").contains(CANARY_B));
    assert_eq!(
        broker.state(first.connection_id()).unwrap(),
        ConnectionState::AuthRequired
    );
    assert_eq!(
        harness.vault.account_reads(second_account),
        second_reads_before,
        "another connection was consulted"
    );

    let unknown = ConnectionId::new();
    let reads_before = harness.vault.reads().len();
    let error = broker.resolve(&unknown).expect_err("unknown connection");
    assert_eq!(
        error,
        CoreError::CredentialUnavailable {
            connection: unknown,
            failure: CredentialFailureKind::NotConfigured,
        }
    );
    assert_eq!(harness.vault.reads().len(), reads_before);
}

#[test]
fn credential_status_tracks_missing_available_expired_and_corrupt_items() {
    let harness = Harness::new();
    let api_key = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    let chatgpt = harness.add(chatgpt_settings());
    let broker = harness.service.broker();

    assert_eq!(
        broker.state(api_key.connection_id()).unwrap(),
        ConnectionState::AuthRequired
    );
    assert_eq!(
        broker.state(chatgpt.connection_id()).unwrap(),
        ConnectionState::LoginRequired
    );
    assert_eq!(
        broker
            .connection_info(api_key.connection_id())
            .unwrap()
            .status(),
        ConnectionStatus::AuthRequired
    );

    harness.save_api_key(api_key.connection_id(), CANARY);
    assert_eq!(
        broker.state(api_key.connection_id()).unwrap(),
        ConnectionState::Available
    );
    assert_eq!(
        broker
            .connection_info(api_key.connection_id())
            .unwrap()
            .status(),
        ConnectionStatus::Available
    );

    harness.save_token_set(chatgpt.connection_id(), valid_token_set(CANARY_B));
    assert_eq!(
        broker.state(chatgpt.connection_id()).unwrap(),
        ConnectionState::Available
    );
    assert_eq!(
        broker.availability(&chatgpt.connection_id()).unwrap(),
        CredentialAvailability::Available
    );
    assert_eq!(
        broker
            .resolve_at(chatgpt.connection_id(), Timestamp::from_unix_millis(2_000))
            .unwrap()
            .expose_secret(),
        CANARY_B
    );

    let wrong_kind = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    let error = harness
        .service
        .admin()
        .save_oauth_token_set(wrong_kind.connection_id(), valid_token_set(CANARY_B))
        .expect_err("API-key connection must reject an OAuth token set");
    assert_eq!(
        error,
        CoreError::CredentialUnavailable {
            connection: wrong_kind.connection_id(),
            failure: CredentialFailureKind::InvalidCredentialData,
        }
    );

    let expired = harness.add(chatgpt_settings());
    harness.save_token_set(expired.connection_id(), expired_token_set(CANARY_B));
    assert_eq!(
        broker
            .state_at(expired.connection_id(), Timestamp::from_unix_millis(2_000))
            .unwrap(),
        ConnectionState::AuthRequired
    );
    assert_eq!(
        broker
            .resolve_at(expired.connection_id(), Timestamp::from_unix_millis(2_000))
            .expect_err("expired token without a refresher must fail"),
        CoreError::CredentialUnavailable {
            connection: expired.connection_id(),
            failure: CredentialFailureKind::Expired,
        }
    );

    let denied = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    harness.vault.fail_read(VaultFailure::Denied);
    assert_eq!(
        broker.state(denied.connection_id()).unwrap(),
        ConnectionState::Unavailable {
            failure: CredentialFailureKind::KeychainDenied,
        }
    );
    harness.vault.fail_read(VaultFailure::Denied);
    assert_eq!(
        broker
            .connection_info(denied.connection_id())
            .unwrap()
            .status(),
        ConnectionStatus::Unavailable
    );

    let missing_item = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    harness.vault.fail_read(VaultFailure::MissingItem);
    assert_eq!(
        broker
            .resolve(&missing_item.connection_id())
            .expect_err("missing vault item must map to a structured failure"),
        CoreError::CredentialUnavailable {
            connection: missing_item.connection_id(),
            failure: CredentialFailureKind::KeychainItemMissing,
        }
    );

    let corrupt = harness.add(api_key_settings(Provider::OpenAi, "gpt-5"));
    harness
        .vault
        .set_raw(corrupt.credential_ref().as_str(), br#"{"format":99}"#);
    assert_eq!(
        broker.state(corrupt.connection_id()).unwrap(),
        ConnectionState::Unavailable {
            failure: CredentialFailureKind::InvalidCredentialData,
        }
    );
    assert_eq!(
        broker
            .resolve(&corrupt.connection_id())
            .expect_err("unknown credential format must not be interpreted"),
        CoreError::CredentialUnavailable {
            connection: corrupt.connection_id(),
            failure: CredentialFailureKind::InvalidCredentialData,
        }
    );
}

struct CountingRefresher {
    calls: AtomicUsize,
    delay: Duration,
    rendezvous: Option<Arc<Rendezvous>>,
    outcome: RefresherOutcome,
}

#[derive(Clone, Copy)]
enum RefresherOutcome {
    Fresh,
    AlreadyExpired,
    Failure,
}

impl CountingRefresher {
    fn new(outcome: RefresherOutcome, delay: Duration) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            delay,
            rendezvous: None,
            outcome,
        }
    }

    fn with_rendezvous(mut self, rendezvous: Arc<Rendezvous>) -> Self {
        self.rendezvous = Some(rendezvous);
        self
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CredentialRefresher for CountingRefresher {
    fn refresh(
        &self,
        connection: ConnectionId,
        _current: &OAuthTokenSet,
    ) -> Result<OAuthTokenSet, CredentialFailureKind> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if !self.delay.is_zero() {
            thread::sleep(self.delay);
        }
        if let Some(rendezvous) = &self.rendezvous
            && !rendezvous.wait_for_two()
        {
            return Err(CredentialFailureKind::RefreshFailed);
        }
        match self.outcome {
            RefresherOutcome::Fresh => Ok(OAuthTokenSet::new(
                SecretString::new(format!("refreshed-{call}-{connection}")).unwrap(),
                Some(SecretString::new("new-refresh-token").unwrap()),
                Some(Timestamp::from_unix_millis(10_000)),
            )),
            RefresherOutcome::AlreadyExpired => Ok(OAuthTokenSet::new(
                SecretString::new(format!("expired-{call}")).unwrap(),
                None,
                Some(Timestamp::from_unix_millis(1)),
            )),
            RefresherOutcome::Failure => Err(CredentialFailureKind::RefreshFailed),
        }
    }
}

#[derive(Default)]
struct Rendezvous {
    state: Mutex<usize>,
    condition: Condvar,
}

impl Rendezvous {
    fn wait_for_two(&self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut count = self.state.lock().unwrap();
        *count += 1;
        self.condition.notify_all();
        while *count < 2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next, timeout) = self.condition.wait_timeout(count, remaining).unwrap();
            count = next;
            if timeout.timed_out() && *count < 2 {
                return false;
            }
        }
        true
    }
}

#[test]
fn concurrent_refreshes_for_the_same_connection_are_serialized() {
    let refresher = Arc::new(CountingRefresher::new(
        RefresherOutcome::Fresh,
        Duration::from_millis(50),
    ));
    let harness = Harness::with_refresher(CountingRefresherClone(Arc::clone(&refresher)));
    let connection = harness.add(chatgpt_settings());
    harness.save_token_set(connection.connection_id(), expired_token_set("old-token"));

    let broker = harness.service.broker();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let broker = broker.clone();
            let barrier = Arc::clone(&barrier);
            let connection = connection.connection_id();
            thread::spawn(move || {
                barrier.wait();
                broker.resolve_at(connection, Timestamp::from_unix_millis(2_000))
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    for result in results {
        assert!(result.unwrap().expose_secret().starts_with("refreshed-1-"));
    }
    assert_eq!(
        refresher.calls(),
        1,
        "same connection refreshed more than once"
    );

    let third = broker
        .resolve_at(
            connection.connection_id(),
            Timestamp::from_unix_millis(2_000),
        )
        .unwrap();
    assert!(third.expose_secret().starts_with("refreshed-1-"));
    assert_eq!(refresher.calls(), 1, "fresh token was refreshed again");
    assert_eq!(
        broker
            .state_at(
                connection.connection_id(),
                Timestamp::from_unix_millis(2_000)
            )
            .unwrap(),
        ConnectionState::Available
    );
}

#[test]
fn concurrent_refreshes_for_different_connections_do_not_block_each_other() {
    let refresher = Arc::new(
        CountingRefresher::new(RefresherOutcome::Fresh, Duration::ZERO)
            .with_rendezvous(Arc::new(Rendezvous::default())),
    );
    let harness = Harness::with_refresher(CountingRefresherClone(Arc::clone(&refresher)));
    let first = harness.add(chatgpt_settings());
    let second = harness.add(chatgpt_settings());
    harness.save_token_set(first.connection_id(), expired_token_set("old-a"));
    harness.save_token_set(second.connection_id(), expired_token_set("old-b"));

    let broker = harness.service.broker();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [first.connection_id(), second.connection_id()]
        .into_iter()
        .map(|connection| {
            let broker = broker.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                broker.resolve_at(connection, Timestamp::from_unix_millis(2_000))
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    for result in results {
        assert!(result.is_ok(), "independent refresh failed: {result:?}");
    }
    assert_eq!(refresher.calls(), 2);
}

#[test]
fn explicit_refresh_refreshes_an_unexpired_token_once() {
    let refresher = Arc::new(CountingRefresher::new(
        RefresherOutcome::Fresh,
        Duration::ZERO,
    ));
    let harness = Harness::with_refresher(CountingRefresherClone(Arc::clone(&refresher)));
    let connection = harness.add(chatgpt_settings());
    harness.save_token_set(connection.connection_id(), valid_token_set("still-valid"));

    let broker = harness.service.broker();
    // A normal resolve keeps the unexpired token and does not refresh.
    let resolved = broker
        .resolve_at(
            connection.connection_id(),
            Timestamp::from_unix_millis(2_000),
        )
        .expect("resolve");
    assert_eq!(resolved.expose_secret(), "still-valid");
    assert_eq!(refresher.calls(), 0);

    let refreshed = broker
        .refresh_at(
            connection.connection_id(),
            Timestamp::from_unix_millis(2_000),
        )
        .expect("forced refresh");
    assert!(refreshed.expose_secret().starts_with("refreshed-1-"));
    assert_eq!(refresher.calls(), 1);
}

#[test]
fn failed_refresh_stops_and_never_publishes_an_expired_or_bogus_credential() {
    let refresher = Arc::new(CountingRefresher::new(
        RefresherOutcome::Failure,
        Duration::ZERO,
    ));
    let harness = Harness::with_refresher(CountingRefresherClone(Arc::clone(&refresher)));
    let connection = harness.add(chatgpt_settings());
    harness.save_token_set(connection.connection_id(), expired_token_set("old-token"));
    let account = connection.credential_ref().as_str();
    let before = harness.vault.raw(account).unwrap();

    let broker = harness.service.broker();
    for expected_calls in 1..=2 {
        let error = broker
            .resolve_at(
                connection.connection_id(),
                Timestamp::from_unix_millis(2_000),
            )
            .expect_err("refresh failure must stop");
        assert_eq!(
            error,
            CoreError::CredentialUnavailable {
                connection: connection.connection_id(),
                failure: CredentialFailureKind::RefreshFailed,
            }
        );
        assert_eq!(refresher.calls(), expected_calls);
        assert_eq!(harness.vault.raw(account).unwrap(), before);
    }
    assert_eq!(
        broker
            .state_at(
                connection.connection_id(),
                Timestamp::from_unix_millis(2_000)
            )
            .unwrap(),
        ConnectionState::AuthRequired
    );

    let expired = Arc::new(CountingRefresher::new(
        RefresherOutcome::AlreadyExpired,
        Duration::ZERO,
    ));
    let harness = Harness::with_refresher(CountingRefresherClone(Arc::clone(&expired)));
    let connection = harness.add(chatgpt_settings());
    harness.save_token_set(connection.connection_id(), expired_token_set("old-token"));
    let account = connection.credential_ref().as_str();
    let before = harness.vault.raw(account).unwrap();
    assert_eq!(
        harness
            .service
            .broker()
            .resolve_at(
                connection.connection_id(),
                Timestamp::from_unix_millis(2_000)
            )
            .expect_err("an already-expired refresh result is not usable"),
        CoreError::CredentialUnavailable {
            connection: connection.connection_id(),
            failure: CredentialFailureKind::RefreshFailed,
        }
    );
    assert_eq!(harness.vault.raw(account).unwrap(), before);
}

// `CredentialService` takes ownership of one refresher. Tests need to inspect
// the same counter, so they pass this shared wrapper.
struct CountingRefresherClone(Arc<CountingRefresher>);

impl CredentialRefresher for CountingRefresherClone {
    fn refresh(
        &self,
        connection: ConnectionId,
        current: &OAuthTokenSet,
    ) -> Result<OAuthTokenSet, CredentialFailureKind> {
        self.0.refresh(connection, current)
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_files(&path, files);
        } else {
            files.push(path);
        }
    }
}

#[test]
fn command_code_assessment_gateway_is_fixed_and_assessment_only() {
    let settings = ConnectionSettings::new_with_capabilities(
        ConnectionId::new(),
        Provider::TypeSafe,
        "typesafe/jev-1.14.0",
        AuthMethod::ApiKey,
        None,
        None,
        ConnectionCapabilityDeclaration::new(
            EndpointClass::TypeSafeSystemOne,
            InputCapabilities::text_only(),
        ),
    )
    .expect("TypeSafe settings")
    .with_assessment_gateway(AssessmentGateway::CommandCode)
    .expect("Command Code gateway");
    let capabilities = settings.capabilities().expect("capabilities");
    assert_eq!(
        capabilities.endpoint_class(),
        EndpointClass::TypeSafeSystemOne
    );
    assert!(!capabilities.allows_agent_execution());
    assert!(capabilities.allows_assessment());
    assert_eq!(
        settings.assessment_gateway(),
        Some(AssessmentGateway::CommandCode)
    );

    let json = serde_json::to_value(&settings).expect("serialize");
    assert_eq!(json["assessmentGateway"], "command_code");
    let decoded: ConnectionSettings = serde_json::from_value(json).expect("decode");
    assert_eq!(decoded, settings);

    let agent = ConnectionSettings::new(
        ConnectionId::new(),
        Provider::OpenAi,
        "gpt-test",
        AuthMethod::ApiKey,
        None,
        None,
    )
    .expect("agent settings");
    assert!(
        agent
            .with_assessment_gateway(AssessmentGateway::CommandCode)
            .is_err()
    );
}
