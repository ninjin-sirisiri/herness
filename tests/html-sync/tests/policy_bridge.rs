//! H3 configuration approval and Common SDD policy bridge tests.
//!
//! The real SDD pack at `/Users/h-uma/Documents/sdd` is read-only here. Python
//! is an external local process; no provider, credential, network, model, or
//! Tauri UI path is used. Temporary projects and SQLite databases are created
//! per test.

#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use herness_core::{ConnectionId, ProjectId, Timestamp};
use herness_desktop::html_sync::policy::{
    CandidateDecision, CandidateStage, HtmlPolicyBridge, PolicyBridgeError,
};
use herness_html_sync::config::{
    H3ApprovalLimits, H3ConfigurationApproval, H3ConfigurationDraft, H3ConnectionApproval,
    H3OwnerBinding, H3PackBinding, H3ScopeChangeKind, H3VersionBinding, HOST_API_PROTOCOL,
    HOST_API_VERSION, PACK_INTEGRATION_SCHEMA, PACK_POLICY_VERSION,
    StoreBackedOwnerApprovalRegistry,
};
use herness_html_sync::{
    H3Settings, HtmlSyncCommit, SettingsCommit, decode_record,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::owner_launch::{
    authorize_owner_launch, OwnerApproval, OwnerApprovalRegistryPort, OwnerLaunchBinding,
};
use herness_supervision::{
    BudgetPolicy, ConditionDigest, ConditionVersion, ConsentBinding, ConsentId, ContentDigest,
    DisclosureDataKind, DisclosureScope, ExecutionScope, OwnerKind, OwnerRef, ProfileBinding,
    ProfileId, ProfilePurpose, ProfileVersion, ProviderOrigin, SupervisionError, SupervisionId,
    TargetVersion,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const REAL_PACK_ROOT: &str = "/Users/h-uma/Documents/sdd";
const TARGET_PATH: &str = "docs/sdd/specs/2026-11-09-h3-html-sync-design.md";
const NOW_MILLIS: u64 = 1_700_000_000_000;
const PROJECT_UUID: &str = "33333333-3333-4333-8333-333333333333";

fn project() -> ProjectId {
    PROJECT_UUID.parse().expect("fixture project")
}

fn other_project() -> ProjectId {
    "44444444-4444-4444-8444-444444444444"
        .parse()
        .expect("fixture project")
}

fn now() -> Timestamp {
    Timestamp::from_unix_millis(NOW_MILLIS)
}

fn uuid(seed: &str) -> uuid::Uuid {
    uuid::Uuid::parse_str(seed).expect("fixture uuid")
}

fn profile(purpose: ProfilePurpose, version: u64) -> ProfileBinding {
    ProfileBinding::new(
        ProfileId::from_parts(project(), uuid("10000000-0000-4000-8000-00000000000b")),
        ProfileVersion::new(version).expect("profile version"),
        purpose,
    )
}

fn consent_binding(purpose: ProfilePurpose, version: u64) -> ConsentBinding {
    ConsentBinding::new(
        ConsentId::from_parts(project(), uuid("10000000-0000-4000-8000-00000000000a")),
        version,
        purpose,
        TargetVersion::new(1).expect("target version"),
    )
}

fn disclosure(purpose: ProfilePurpose, target: &str) -> DisclosureScope {
    let kinds = match purpose {
        ProfilePurpose::Completion => BTreeSet::from([
            DisclosureDataKind::Text,
            DisclosureDataKind::Code,
        ]),
        ProfilePurpose::Html => BTreeSet::from([DisclosureDataKind::Text]),
        ProfilePurpose::Permission => BTreeSet::from([DisclosureDataKind::Text]),
    };
    DisclosureScope::new(
        purpose,
        kinds,
        vec![target.to_owned()],
        TargetVersion::new(1).expect("target version"),
    )
    .expect("disclosure")
}

fn connection_approval(
    purpose: ProfilePurpose,
    origin: &str,
    target: &str,
    profile_version: u64,
    consent_version: u64,
) -> H3ConnectionApproval {
    connection_approval_with_kinds(
        purpose,
        origin,
        target,
        profile_version,
        consent_version,
        disclosure(purpose, target).data_kinds().clone(),
    )
}

fn connection_approval_with_kinds(
    purpose: ProfilePurpose,
    origin: &str,
    target: &str,
    profile_version: u64,
    consent_version: u64,
    kinds: BTreeSet<DisclosureDataKind>,
) -> H3ConnectionApproval {
    connection_approval_with_id(
        ConnectionId::new(),
        purpose,
        origin,
        target,
        profile_version,
        consent_version,
        kinds,
    )
}

#[allow(clippy::too_many_arguments)]
fn connection_approval_with_id(
    connection_id: ConnectionId,
    purpose: ProfilePurpose,
    origin: &str,
    target: &str,
    profile_version: u64,
    consent_version: u64,
    kinds: BTreeSet<DisclosureDataKind>,
) -> H3ConnectionApproval {
    H3ConnectionApproval::new(
        project(),
        connection_id,
        ProviderOrigin::parse(origin).expect("origin"),
        DisclosureScope::new(
            purpose,
            kinds,
            vec![target.to_owned()],
            TargetVersion::new(1).expect("target version"),
        )
        .expect("disclosure"),
        profile(purpose, profile_version),
        consent_binding(purpose, consent_version),
    )
    .expect("connection approval")
}

fn owner_binding() -> H3OwnerBinding {
    owner_binding_with_job("job-14")
}

fn owner_binding_with_job(job: &str) -> H3OwnerBinding {
    let product = project();
    H3OwnerBinding::new(
        product,
        OwnerRef::new(OwnerKind::H3HtmlJob, job).expect("owner"),
        job,
        ConditionVersion::new(1).expect("condition version"),
        ConditionDigest::sha256(b"condition-14"),
        ExecutionScope::new(
            product,
            vec![TARGET_PATH.to_owned()],
            vec!["private/html-sync/candidates".to_owned()],
            false,
        )
        .expect("scope"),
        1,
        BudgetPolicy::h2_default(),
    )
    .expect("owner binding")
}

fn versions(policy_fingerprint: ContentDigest, pack_fingerprint: ContentDigest) -> H3VersionBinding {
    H3VersionBinding::new(
        PACK_INTEGRATION_SCHEMA,
        1,
        1,
        PACK_POLICY_VERSION,
        policy_fingerprint,
        1,
        pack_fingerprint,
        HOST_API_PROTOCOL,
        HOST_API_VERSION,
    )
    .expect("version binding")
}

fn approval_draft(
    policy_fingerprint: ContentDigest,
    pack_fingerprint: ContentDigest,
) -> H3ConfigurationDraft {
    H3ConfigurationDraft {
        project_id: project(),
        settings_version: 1,
        approval_id: "approval-14".to_owned(),
        expires_at: None,
        targets: vec![TARGET_PATH.to_owned()],
        authoring: connection_approval(
            ProfilePurpose::Completion,
            "https://authoring.example",
            TARGET_PATH,
            1,
            1,
        ),
        assessment: connection_approval(
            ProfilePurpose::Html,
            "https://assessment.example",
            TARGET_PATH,
            1,
            1,
        ),
        versions: versions(policy_fingerprint, pack_fingerprint),
        limits: H3ApprovalLimits::default(),
        auto_publish: false,
        retain_history: true,
        automatic_companion: true,
        owner: owner_binding(),
    }
}

fn approval_with(
    policy_fingerprint: ContentDigest,
    pack_fingerprint: ContentDigest,
    expires_at: Option<Timestamp>,
) -> H3ConfigurationApproval {
    let mut draft = approval_draft(policy_fingerprint, pack_fingerprint);
    draft.expires_at = expires_at;
    H3ConfigurationApproval::approve(
        draft,
        herness_html_sync::config::H3Approver::Human,
        now(),
    )
    .expect("approval")
}

fn dummy_approval() -> H3ConfigurationApproval {
    approval_with(
        ContentDigest::sha256(b"policy"),
        ContentDigest::sha256(b"pack"),
        None,
    )
}

fn approved_settings(approval: H3ConfigurationApproval) -> H3Settings {
    H3Settings::approved(approval, true).expect("approved settings")
}

struct StoreHarness {
    _temp: TempDir,
    config: StoreConfig,
}

impl StoreHarness {
    fn new() -> Self {
        let temp = TempDir::new().expect("temporary directory");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("store config");
        Self {
            _temp: temp,
            config,
        }
    }

    fn open(&self) -> Store {
        Store::open(self.config.clone()).expect("open store")
    }
}

fn store_settings(store: &mut Store, settings: H3Settings) {
    store
        .commit_html_sync(
            HtmlSyncCommit::new().with_settings(SettingsCommit::new(None, settings).expect("commit")),
        )
        .expect("commit settings");
}

fn real_pack_present() -> bool {
    Path::new(REAL_PACK_ROOT).join("scripts/html-docs").is_file()
}

fn toolchain() -> herness_core::ToolchainConfig {
    herness_core::ToolchainConfig::from_environment()
        .with_html_docs_path(Path::new(REAL_PACK_ROOT).join("scripts/html-docs"))
        .expect("validator path")
}

fn glossary_bytes() -> (Vec<u8>, Vec<u8>) {
    let source = fs::read(Path::new(REAL_PACK_ROOT).join("tests/fixtures/glossary/CONTEXT.md"))
        .expect("fixture source");
    let html = fs::read(Path::new(REAL_PACK_ROOT).join("tests/fixtures/glossary/CONTEXT.html"))
        .expect("fixture companion");
    (source, html)
}

struct ProjectFixture {
    _temp: TempDir,
    root: PathBuf,
    source: Vec<u8>,
    html: Vec<u8>,
}

fn glossary_project() -> ProjectFixture {
    let temp = TempDir::new().expect("temporary project");
    let root = temp.path().join("project");
    fs::create_dir_all(&root).expect("project directory");
    let (source, html) = glossary_bytes();
    fs::write(root.join("CONTEXT.md"), &source).expect("write source");
    fs::write(root.join("CONTEXT.html"), &html).expect("write companion");
    ProjectFixture {
        _temp: temp,
        root,
        source,
        html,
    }
}

fn input_map(source: &[u8], html: &[u8]) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        ("CONTEXT.md".to_owned(), source.to_vec()),
        ("CONTEXT.html".to_owned(), html.to_vec()),
    ])
}

fn approval_from_bridge(bridge: &HtmlPolicyBridge) -> H3ConfigurationApproval {
    let probe = bridge.probe();
    approval_with(
        probe.policy_fingerprint().clone(),
        probe.pack_fingerprint().clone(),
        None,
    )
}

fn connect_real(bridge: HtmlPolicyBridge) -> (herness_desktop::html_sync::policy::ConnectedPolicyBridge, H3ConfigurationApproval) {
    let approval = approval_from_bridge(&bridge);
    let connected = bridge
        .connect(&approval.pack_binding())
        .expect("connect real pack");
    (connected, approval)
}

#[test]
fn real_pack_candidate_check_allows_without_writing_and_uses_the_common_fixture_digest() {
    if !real_pack_present() {
        eprintln!("skip real pack policy bridge test: pack absent");
        return;
    }
    let project = glossary_project();
    // The disk pair is deliberately stale. The supplied bytes must be used and
    // the official files must not be written.
    fs::write(project.root.join("CONTEXT.md"), b"# stale on disk\n").expect("stale source");
    fs::write(project.root.join("CONTEXT.html"), b"<html>stale disk candidate</html>")
        .expect("stale companion");
    let before_source = fs::read(project.root.join("CONTEXT.md")).expect("read source");
    let before_html = fs::read(project.root.join("CONTEXT.html")).expect("read companion");
    let before_listing = sorted_tree(&project.root);

    let bridge = HtmlPolicyBridge::detect(&project.root, REAL_PACK_ROOT, toolchain())
        .expect("detect real pack");
    let probe = bridge.probe().clone();
    let (connected, approval) = connect_real(bridge);

    assert_eq!(connected.invocations(), 1, "capabilities is invoked once");
    assert_eq!(connected.bootstrap().pack(), &approval.pack_binding());
    assert_eq!(
        connected.bootstrap().capabilities()["protocol"]["name"],
        HOST_API_PROTOCOL
    );
    assert_eq!(
        connected.bootstrap().capabilities()["protocol"]["version"],
        json!(1)
    );
    assert!(connected.bootstrap().operations().contains("candidate-check"));
    assert_eq!(connected.bootstrap(), connected.bootstrap());
    assert_eq!(connected.invocations(), 1, "cached bootstrap is reused");

    let discovered = connected
        .discover(&["CONTEXT.md".to_owned()])
        .expect("discover");
    assert_eq!(discovered["targets"][0]["source"], "CONTEXT.md");
    assert_eq!(discovered["targets"][0]["html"], "CONTEXT.html");
    assert!(discovered["unrelated"].as_array().expect("unrelated").is_empty());

    let check = connected
        .candidate_check(
            "CONTEXT.md",
            CandidateStage::Structural,
            None,
            &input_map(&project.source, &project.html),
        )
        .expect("structural candidate check");
    assert_eq!(check.decision(), CandidateDecision::Allow);
    assert_eq!(check.stage(), "structural");
    assert!(!check.final_pass(), "structural is never a final pass");
    assert!(!check.final_binding());
    assert_eq!(check.contract(), "strict");
    assert_eq!(connected.invocations(), 3, "capabilities, discover, check");

    let source_digest = format!(
        "sha256:{}",
        ContentDigest::sha256(&project.source).as_str()
    );
    let candidate_digest = format!(
        "sha256:{}",
        ContentDigest::sha256(&project.html).as_str()
    );
    assert_eq!(check.digests()["source"], json!(source_digest));
    assert_eq!(check.digests()["candidate"], json!(candidate_digest));
    assert!(check.digests()["receipt"].is_null());
    assert_eq!(
        check.input_digests()["CONTEXT.md"],
        json!(source_digest)
    );
    assert_eq!(
        check.input_digests()["CONTEXT.html"],
        json!(candidate_digest)
    );
    assert_eq!(
        probe.policy_fingerprint(),
        approval.versions().policy_fingerprint()
    );
    assert_eq!(
        probe.pack_fingerprint(),
        approval.versions().pack_fingerprint()
    );

    // The same fixture bytes are digested by the Rust side and the real Python
    // source-unit operation. The HTML's declared source digest agrees.
    let units = connected
        .source_units("CONTEXT.md", &input_map(&project.source, &project.html))
        .expect("source units");
    assert_eq!(units["source"]["digest"], json!(source_digest));
    let html_text = String::from_utf8(project.html.clone()).expect("fixture HTML");
    assert!(
        html_text.contains(&format!("content=\"sha256:{}", &source_digest[7..])),
        "the candidate fixture declares the same common source digest"
    );

    assert_eq!(
        fs::read(project.root.join("CONTEXT.md")).expect("read source"),
        before_source
    );
    assert_eq!(
        fs::read(project.root.join("CONTEXT.html")).expect("read companion"),
        before_html
    );
    assert_eq!(sorted_tree(&project.root), before_listing);
}

#[test]
fn real_pack_denies_a_stale_candidate_without_claiming_a_final_pass() {
    if !real_pack_present() {
        eprintln!("skip real pack policy bridge test: pack absent");
        return;
    }
    let project = glossary_project();
    let bridge = HtmlPolicyBridge::detect(&project.root, REAL_PACK_ROOT, toolchain())
        .expect("detect real pack");
    let (connected, _) = connect_real(bridge);
    let check = connected
        .candidate_check(
            "CONTEXT.md",
            CandidateStage::Structural,
            None,
            &input_map(&project.source, b"<html><body>incomplete</body></html>"),
        )
        .expect("deny result is a structured result");
    assert_eq!(check.decision(), CandidateDecision::Deny);
    assert!(!check.final_pass());
    assert!(!check.final_binding());
    assert!(!check.violations().is_empty());
    assert!(
        check
            .violations()
            .iter()
            .any(|finding| finding.code() == "digest-metadata"),
        "the missing source digest is reported: {:?}",
        check.violations()
    );
}

#[test]
fn approved_pack_identity_is_checked_before_any_host_api_process() {
    if !real_pack_present() {
        eprintln!("skip real pack policy bridge test: pack absent");
        return;
    }
    let project = glossary_project();
    let bridge = HtmlPolicyBridge::detect(&project.root, REAL_PACK_ROOT, toolchain())
        .expect("detect real pack");
    let probe = bridge.probe().clone();

    let changed_policy = H3PackBinding::new(
        PACK_INTEGRATION_SCHEMA,
        1,
        1,
        PACK_POLICY_VERSION,
        ContentDigest::sha256(b"different-policy"),
        probe.pack_fingerprint().clone(),
        HOST_API_PROTOCOL,
        HOST_API_VERSION,
    )
    .expect("binding");
    assert_eq!(
        bridge.clone().connect(&changed_policy).unwrap_err(),
        PolicyBridgeError::PolicyFingerprintMismatch {
            approved: ContentDigest::sha256(b"different-policy").as_str().to_owned(),
            found: probe.policy_fingerprint().as_str().to_owned(),
        }
    );
    assert_eq!(bridge.invocations(), 0);

    let changed_pack = H3PackBinding::new(
        PACK_INTEGRATION_SCHEMA,
        1,
        1,
        PACK_POLICY_VERSION,
        probe.policy_fingerprint().clone(),
        ContentDigest::sha256(b"different-pack"),
        HOST_API_PROTOCOL,
        HOST_API_VERSION,
    )
    .expect("binding");
    assert!(matches!(
        bridge.clone().connect(&changed_pack).unwrap_err(),
        PolicyBridgeError::PackFingerprintMismatch { .. }
    ));
    assert_eq!(bridge.invocations(), 0);

    let changed_revision = H3PackBinding::new(
        PACK_INTEGRATION_SCHEMA,
        1,
        2,
        PACK_POLICY_VERSION,
        probe.policy_fingerprint().clone(),
        probe.pack_fingerprint().clone(),
        HOST_API_PROTOCOL,
        HOST_API_VERSION,
    )
    .expect("binding");
    assert_eq!(
        bridge.clone().connect(&changed_revision).unwrap_err(),
        PolicyBridgeError::IntegrationMismatch {
            field: "revision",
            approved: "2".to_owned(),
            found: "1".to_owned(),
        }
    );
    assert_eq!(bridge.invocations(), 0);
}

#[test]
fn old_or_changed_pack_is_explicitly_unavailable() {
    if !real_pack_present() {
        eprintln!("skip real pack policy bridge test: pack absent");
        return;
    }
    let project = glossary_project();
    let real_bridge = HtmlPolicyBridge::detect(&project.root, REAL_PACK_ROOT, toolchain())
        .expect("detect real pack");
    let approved = approval_from_bridge(&real_bridge).pack_binding();
    let probe = real_bridge.probe().clone();

    // Unknown/old integration definition version.
    let old_pack = temp_pack_copy();
    let integration_path = old_pack.join("adapters/herness/integration.json");
    let mut integration: Value =
        serde_json::from_slice(&fs::read(&integration_path).expect("read definition"))
            .expect("definition JSON");
    integration["version"] = json!(2);
    fs::write(
        &integration_path,
        serde_json::to_vec_pretty(&integration).expect("serialize definition"),
    )
    .expect("write old definition");
    let old_bridge = HtmlPolicyBridge::detect(
        &project.root,
        &old_pack,
        herness_core::ToolchainConfig::from_environment()
            .with_html_docs_path(old_pack.join("scripts/html-docs"))
            .expect("old pack validator"),
    )
    .expect("old pack detection");
    assert_eq!(
        old_bridge.clone().connect(&approved).unwrap_err(),
        PolicyBridgeError::IntegrationMismatch {
            field: "version",
            approved: "1".to_owned(),
            found: "2".to_owned(),
        }
    );
    assert_eq!(old_bridge.invocations(), 0);

    // Changed policy module bytes require a new human approval.
    let changed_pack = temp_pack_copy();
    let policy_file = changed_pack.join("scripts/sddlib/html_semantic.py");
    let mut policy = fs::read(&policy_file).expect("read policy module");
    policy.extend_from_slice(b"\n# local drift\n");
    fs::write(&policy_file, policy).expect("write changed policy");
    let changed_bridge = HtmlPolicyBridge::detect(
        &project.root,
        &changed_pack,
        herness_core::ToolchainConfig::from_environment()
            .with_html_docs_path(changed_pack.join("scripts/html-docs"))
            .expect("changed pack validator"),
    )
    .expect("changed pack detection");
    let changed_found = changed_bridge.probe().policy_fingerprint().as_str().to_owned();
    assert_eq!(
        changed_bridge.clone().connect(&approved).unwrap_err(),
        PolicyBridgeError::PolicyFingerprintMismatch {
            approved: probe.policy_fingerprint().as_str().to_owned(),
            found: changed_found,
        }
    );
    assert_eq!(changed_bridge.invocations(), 0);
}

#[test]
fn invalid_json_timeout_and_missing_capability_are_unavailable_not_missing_approval() {
    if !real_pack_present() {
        eprintln!("skip real pack policy bridge test: pack absent");
        return;
    }
    let project = glossary_project();
    let real_bridge = HtmlPolicyBridge::detect(&project.root, REAL_PACK_ROOT, toolchain())
        .expect("detect real pack");
    let approved = approval_from_bridge(&real_bridge).pack_binding();
    let probe = real_bridge.probe().clone();

    // Invalid JSON from the process.
    let invalid = fake_python(&project.root, "print('not json')");
    let invalid_bridge = fake_bridge(&project.root, &invalid, None);
    assert!(matches!(
        invalid_bridge.clone().connect(&approved).unwrap_err(),
        PolicyBridgeError::InvalidJson { .. }
    ));
    assert_eq!(invalid_bridge.invocations(), 1);

    // A request that exceeds the bridge budget is killed and reported as a
    // timeout, not as a missing approval.
    let sleeping = fake_python(&project.root, "import time\ntime.sleep(10)\nprint('{}')");
    let sleep_bridge = fake_bridge(&project.root, &sleeping, Some(100));
    let started = Instant::now();
    assert_eq!(
        sleep_bridge.clone().connect(&approved).unwrap_err(),
        PolicyBridgeError::Timeout { timeout_ms: 100 }
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(sleep_bridge.invocations(), 1);

    // A valid envelope that omits a required operation is an explicit
    // capability shortage.
    let capabilities = json!({
        "ok": true,
        "version": 1,
        "operation": "capabilities",
        "root": fs::canonicalize(&project.root).expect("canonical project").to_string_lossy(),
        "result": {
            "protocol": {"name": HOST_API_PROTOCOL, "version": 1},
            "operations": ["capabilities", "discover", "source-units"],
            "contracts": ["strict", "semantic-v1"],
            "stages": {
                "structural": {"final": false},
                "final": {"final_binding": true}
            },
            "writes": {"files": false, "html": false},
            "bootstrap": {"implicit": false},
            "policy": {
                "version": probe.policy_version(),
                "digest": format!("sha256:{}", probe.policy_fingerprint().as_str())
            },
            "assurance": "static-only"
        }
    });
    let missing = fake_python(
        &project.root,
        &format!(
            "print({})",
            serde_json::to_string(&serde_json::to_string(&capabilities).expect("serialize"))
                .expect("serialize")
        ),
    );
    let missing_bridge = fake_bridge(&project.root, &missing, None);
    assert_eq!(
        missing_bridge.clone().connect(&approved).unwrap_err(),
        PolicyBridgeError::MissingCapability {
            operation: "candidate-check".to_owned()
        }
    );
    assert_eq!(missing_bridge.invocations(), 1);

    // A pack that understands only the strict contract cannot provide the
    // semantic-v1 policy H3 requires. This is a capability shortage, not a
    // missing approval and not a silent strict fallback.
    let mut no_semantic = capabilities.clone();
    no_semantic["result"]["operations"] = json!([
        "capabilities",
        "discover",
        "source-units",
        "candidate-check"
    ]);
    no_semantic["result"]["contracts"] = json!(["strict"]);
    let no_semantic_fake = fake_python(
        &project.root,
        &format!(
            "print({})",
            serde_json::to_string(
                &serde_json::to_string(&no_semantic).expect("serialize no-semantic")
            )
            .expect("serialize")
        ),
    );
    let no_semantic_bridge = fake_bridge(&project.root, &no_semantic_fake, None);
    assert_eq!(
        no_semantic_bridge.clone().connect(&approved).unwrap_err(),
        PolicyBridgeError::MissingCapability {
            operation: "semantic-v1".to_owned()
        }
    );
    assert_eq!(no_semantic_bridge.invocations(), 1);
}

#[test]
fn unapproved_settings_scan_only_and_make_zero_owner_and_host_api_requests() {
    if !real_pack_present() {
        eprintln!("skip real pack policy bridge test: pack absent");
        return;
    }
    let harness = StoreHarness::new();
    let mut store = harness.open();
    // A recorded settings record without the human configuration approval is
    // scan-only.
    let settings = H3Settings::new(
        project(),
        1,
        true,
        vec![TARGET_PATH.to_owned()],
        false,
        true,
        now(),
    )
    .expect("unapproved settings");
    store_settings(&mut store, settings);
    let registry = StoreBackedOwnerApprovalRegistry::new(&store);
    assert!(
        registry
            .current_owner_approval(project(), owner_binding().owner(), now())
            .expect("registry read")
            .is_none()
    );

    let fixture = glossary_project();
    let bridge = HtmlPolicyBridge::detect(&fixture.root, REAL_PACK_ROOT, toolchain())
        .expect("detect real pack");
    // The caller may discover pack metadata, but there is no approval to
    // connect, so no host API process starts.
    assert_eq!(bridge.invocations(), 0);

    let requested = requested_owner_approval();
    let binding = OwnerLaunchBinding::new(SupervisionId::new(project()), requested)
        .expect("owner launch binding");
    let error = authorize_owner_launch(&registry, &binding, now()).unwrap_err();
    assert_eq!(
        error,
        SupervisionError::OwnerLaunchRejected {
            reason: herness_supervision::OwnerLaunchRejection::MissingRegistryEntry
        }
    );
    assert_eq!(bridge.invocations(), 0, "zero local host-api requests");
}

#[test]
fn store_backed_registry_returns_none_for_unapproved_revoked_expired_superseded_and_disabled() {
    let approval = dummy_approval();

    // Approved.
    let harness = StoreHarness::new();
    let mut store = harness.open();
    store_settings(&mut store, approved_settings(approval.clone()));
    let registry = StoreBackedOwnerApprovalRegistry::new(&store);
    let current = registry
        .current_owner_approval(project(), owner_binding().owner(), now())
        .expect("registry read")
        .expect("current approval");
    assert_eq!(current.settings_version(), 1);
    assert_eq!(current.job_id(), "job-14");
    assert_eq!(current.conditions_digest(), &ConditionDigest::sha256(b"condition-14"));
    assert_eq!(current.profile(), profile(ProfilePurpose::Completion, 1));
    assert_eq!(current.consent(), consent_binding(ProfilePurpose::Completion, 1));
    assert_eq!(current.budget_policy_version(), 1);
    assert_eq!(current.budget(), &BudgetPolicy::h2_default());
    let binding = OwnerLaunchBinding::new(
        SupervisionId::new(project()),
        requested_owner_approval(),
    )
    .expect("binding");
    assert!(
        authorize_owner_launch(&registry, &binding, now()).is_ok(),
        "only the fully matching current entry mints authority"
    );
    assert!(
        registry
            .current_owner_approval(project(), &other_owner(), now())
            .expect("registry read")
            .is_none(),
        "another owner has no entry"
    );
    assert!(
        registry
            .current_owner_approval(other_project(), owner_binding().owner(), now())
            .expect("registry read")
            .is_none(),
        "another project has no entry"
    );

    // Disabled.
    let harness = StoreHarness::new();
    let mut store = harness.open();
    store_settings(
        &mut store,
        H3Settings::approved(approval.clone(), false).expect("disabled settings"),
    );
    let registry = StoreBackedOwnerApprovalRegistry::new(&store);
    assert!(
        registry
            .current_owner_approval(project(), owner_binding().owner(), now())
            .expect("registry read")
            .is_none()
    );

    // Revoked.
    let harness = StoreHarness::new();
    let mut store = harness.open();
    store_settings(
        &mut store,
        approved_settings(approval.clone().revoke(now())),
    );
    let registry = StoreBackedOwnerApprovalRegistry::new(&store);
    assert!(
        registry
            .current_owner_approval(project(), owner_binding().owner(), now())
            .expect("registry read")
            .is_none()
    );

    // Expired.
    let expired = approval_with(
        ContentDigest::sha256(b"policy"),
        ContentDigest::sha256(b"pack"),
        Some(now()),
    );
    let harness = StoreHarness::new();
    let mut store = harness.open();
    store_settings(&mut store, approved_settings(expired));
    let registry = StoreBackedOwnerApprovalRegistry::new(&store);
    assert!(
        registry
            .current_owner_approval(project(), owner_binding().owner(), now())
            .expect("registry read")
            .is_none(),
        "an expiry at now is stale"
    );

    // Superseded.
    let harness = StoreHarness::new();
    let mut store = harness.open();
    store_settings(
        &mut store,
        approved_settings(approval.clone().supersede(2).expect("supersede")),
    );
    let registry = StoreBackedOwnerApprovalRegistry::new(&store);
    assert!(
        registry
            .current_owner_approval(project(), owner_binding().owner(), now())
            .expect("registry read")
            .is_none()
    );
    assert_eq!(
        registry
            .current_approval(project(), now())
            .expect("registry read"),
        None
    );
}

#[test]
fn tampered_settings_and_scope_expansion_are_rejected_instead_of_approved() {
    let harness = StoreHarness::new();
    let mut store = harness.open();
    let approval = dummy_approval();
    let settings = approved_settings(approval);
    store_settings(&mut store, settings.clone());

    // Adding a Target without a new human approval must not be accepted.
    let mut payload: Value = serde_json::from_slice(
        &herness_html_sync::encode_record(&settings).expect("encode settings"),
    )
    .expect("settings JSON");
    payload["targetPaths"] = json!([TARGET_PATH, "docs/adr/0001-unapproved.md"]);
    let tampered: H3Settings =
        decode_record(&serde_json::to_vec(&payload).expect("tampered bytes"))
            .expect("decode tampered settings");
    assert!(!tampered.verify_fingerprint());
    store
        .commit_html_sync(
            HtmlSyncCommit::new().with_settings(
                SettingsCommit::new(Some(1), tampered).expect("tampered commit"),
            ),
        )
        .expect("store accepts opaque payload");
    let registry = StoreBackedOwnerApprovalRegistry::new(&store);
    assert!(
        registry.current_approval(project(), now()).is_err(),
        "tampered scope is corrupt storage, not an approval"
    );
    assert!(
        registry
            .current_owner_approval(project(), owner_binding().owner(), now())
            .is_err(),
        "no owner authority is minted from tampered settings"
    );
}

#[test]
fn every_scope_change_requires_a_new_human_approval() {
    let base = approval_draft(
        ContentDigest::sha256(b"policy"),
        ContentDigest::sha256(b"pack"),
    );
    let approved = H3ConfigurationApproval::approve(
        base.clone(),
        herness_html_sync::config::H3Approver::Human,
        now(),
    )
    .expect("approval");
    assert!(!approved.scope_change(&base).requires_reapproval());

    let mut new_target = base.clone();
    new_target
        .targets
        .push("docs/adr/0001-new-target.md".to_owned());
    assert_eq!(
        approved.scope_change(&new_target).changes(),
        &[H3ScopeChangeKind::Targets]
    );

    let authoring_id = base.authoring.connection_id();
    let mut new_origin = base.clone();
    new_origin.authoring = connection_approval_with_id(
        authoring_id,
        ProfilePurpose::Completion,
        "https://other-authoring.example",
        TARGET_PATH,
        1,
        1,
        disclosure(ProfilePurpose::Completion, TARGET_PATH)
            .data_kinds()
            .clone(),
    );
    assert_eq!(
        approved.scope_change(&new_origin).changes(),
        &[H3ScopeChangeKind::Origins]
    );

    let mut more_data = base.clone();
    more_data.authoring = connection_approval_with_id(
        authoring_id,
        ProfilePurpose::Completion,
        "https://authoring.example",
        TARGET_PATH,
        1,
        1,
        BTreeSet::from([
            DisclosureDataKind::Text,
            DisclosureDataKind::Code,
            DisclosureDataKind::Image,
        ]),
    );
    assert_eq!(
        approved.scope_change(&more_data).changes(),
        &[H3ScopeChangeKind::DataKinds]
    );

    let mut new_profile = base.clone();
    new_profile.authoring = connection_approval_with_id(
        authoring_id,
        ProfilePurpose::Completion,
        "https://authoring.example",
        TARGET_PATH,
        2,
        1,
        disclosure(ProfilePurpose::Completion, TARGET_PATH)
            .data_kinds()
            .clone(),
    );
    assert_eq!(
        approved.scope_change(&new_profile).changes(),
        &[H3ScopeChangeKind::Profiles]
    );

    let mut new_versions = base.clone();
    new_versions.versions = versions(
        ContentDigest::sha256(b"policy-2"),
        ContentDigest::sha256(b"pack-2"),
    );
    assert_eq!(
        approved.scope_change(&new_versions).changes(),
        &[H3ScopeChangeKind::PackPolicyRubric]
    );

    let mut new_limits = base.clone();
    new_limits.limits = H3ApprovalLimits::new(
        1024,
        2048,
        100,
        1000,
        100,
        1000,
        1,
        1,
        60,
        3,
        1,
    )
    .expect("lower limits");
    assert_eq!(
        approved.scope_change(&new_limits).changes(),
        &[H3ScopeChangeKind::Limits]
    );

    let mut new_owner = base.clone();
    new_owner.owner = owner_binding_with_job("job-other");
    assert_eq!(
        approved.scope_change(&new_owner).changes(),
        &[H3ScopeChangeKind::OwnerBinding]
    );

    let mut auto_publish = base.clone();
    auto_publish.auto_publish = true;
    assert_eq!(
        approved.scope_change(&auto_publish).changes(),
        &[H3ScopeChangeKind::RetentionAndCapability]
    );

    let mut no_retention = base;
    no_retention.retain_history = false;
    assert_eq!(
        approved.scope_change(&no_retention).changes(),
        &[H3ScopeChangeKind::RetentionAndCapability]
    );
}

#[test]
fn authoring_scope_cannot_write_a_target_or_its_parent() {
    let mut draft = approval_draft(
        ContentDigest::sha256(b"policy"),
        ContentDigest::sha256(b"pack"),
    );
    draft.owner = H3OwnerBinding::new(
        project(),
        OwnerRef::new(OwnerKind::H3HtmlJob, "job-14").expect("owner"),
        "job-14",
        ConditionVersion::new(1).expect("condition version"),
        ConditionDigest::sha256(b"condition-14"),
        ExecutionScope::new(
            project(),
            vec![TARGET_PATH.to_owned()],
            vec!["docs/sdd/specs".to_owned()],
            false,
        )
        .expect("scope"),
        1,
        BudgetPolicy::h2_default(),
    )
    .expect("owner binding");
    assert!(
        H3ConfigurationApproval::approve(
            draft,
            herness_html_sync::config::H3Approver::Human,
            now()
        )
        .is_err(),
        "a write scope covering the Target's parent must not be approved"
    );
}

#[test]
fn a_receipt_or_contract_file_is_not_an_approval() {
    let harness = StoreHarness::new();
    let mut store = harness.open();
    let settings = H3Settings::new(
        project(),
        1,
        true,
        vec![TARGET_PATH.to_owned()],
        false,
        true,
        now(),
    )
    .expect("unapproved settings");
    store_settings(&mut store, settings);
    let registry = StoreBackedOwnerApprovalRegistry::new(&store);

    // A host contract and a receipt in the project tree are plain files. The
    // registry never reads them and cannot mint authority from them.
    let fixture = glossary_project();
    fs::write(
        fixture.root.join("host-contract.json"),
        serde_json::to_vec(&json!({
            "schema": "herness-sdd-host-contract",
            "version": 1,
            "host": "herness",
            "approval": {
                "source": "h3-configuration-registry",
                "kind": "h3-configuration-approval",
                "approvedBy": "human",
                "project": project().to_string(),
                "settingsVersion": 1,
                "approvalId": "forged"
            }
        }))
        .expect("contract bytes"),
    )
    .expect("write contract");
    fs::write(
        fixture.root.join("receipt.json"),
        serde_json::to_vec(&json!({
            "schema": "sdd-html-receipt",
            "version": 1,
            "conditions": {"all_met": true}
        }))
        .expect("receipt bytes"),
    )
    .expect("write receipt");

    assert!(
        registry
            .current_owner_approval(project(), owner_binding().owner(), now())
            .expect("registry read")
            .is_none(),
        "repo files are not the approved settings registry"
    );
}

#[test]
fn scripted_registry_is_only_used_to_prove_every_field_mismatch_is_rejected() {
    let base = requested_owner_approval();
    let registry = ScriptedRegistry(Some(base.clone()));

    for (label, variant, expected) in [
        (
            "job",
            variant_with_job(&base, "other-job"),
            herness_supervision::OwnerLaunchRejection::JobMismatch,
        ),
        (
            "settings",
            variant_with_settings(&base, 2),
            herness_supervision::OwnerLaunchRejection::StaleSettings {
                requested: 2,
                registered: 1,
            },
        ),
        (
            "conditions",
            variant_with_conditions(&base, 2),
            herness_supervision::OwnerLaunchRejection::StaleConditions {
                requested: 2,
                registered: 1,
            },
        ),
        (
            "digest",
            variant_with_digest(&base, ConditionDigest::sha256(b"other")),
            herness_supervision::OwnerLaunchRejection::ConditionDigestMismatch,
        ),
        (
            "scope",
            variant_with_scope(&base),
            herness_supervision::OwnerLaunchRejection::ScopeMismatch,
        ),
        (
            "profile",
            variant_with_profile(&base, 2),
            herness_supervision::OwnerLaunchRejection::ProfileMismatch,
        ),
        (
            "consent",
            variant_with_consent(&base, 2),
            herness_supervision::OwnerLaunchRejection::ConsentMismatch,
        ),
        (
            "budget-version",
            variant_with_budget_version(&base, 2),
            herness_supervision::OwnerLaunchRejection::BudgetPolicyVersionMismatch {
                requested: 2,
                registered: 1,
            },
        ),
        (
            "budget",
            variant_with_budget(&base),
            herness_supervision::OwnerLaunchRejection::BudgetMismatch,
        ),
    ] {
        let binding = OwnerLaunchBinding::new(SupervisionId::new(project()), variant)
            .expect("binding");
        let error = authorize_owner_launch(&registry, &binding, now()).unwrap_err();
        assert_eq!(
            error,
            SupervisionError::OwnerLaunchRejected { reason: expected },
            "the {label} mismatch is rejected by the registry comparison"
        );
    }

    // A missing entry is also a rejection, never a synthesized approval.
    let empty = ScriptedRegistry(None);
    let binding =
        OwnerLaunchBinding::new(SupervisionId::new(project()), requested_owner_approval())
            .expect("binding");
    assert_eq!(
        authorize_owner_launch(&empty, &binding, now()).unwrap_err(),
        SupervisionError::OwnerLaunchRejected {
            reason: herness_supervision::OwnerLaunchRejection::MissingRegistryEntry
        }
    );
}

#[test]
fn pack_fingerprint_recipe_matches_the_python_side() {
    if !real_pack_present() {
        eprintln!("skip real pack policy bridge test: pack absent");
        return;
    }
    let project = glossary_project();
    let bridge = HtmlPolicyBridge::detect(&project.root, REAL_PACK_ROOT, toolchain())
        .expect("detect real pack");
    let probe = bridge.probe().clone();
    let definition = fs::read(Path::new(REAL_PACK_ROOT).join("adapters/herness/integration.json"))
        .expect("definition bytes");
    let definition_digest = sha256_hex(&definition);
    let script = r#"
import hashlib, json, sys
payload = json.loads(sys.stdin.read())
h = hashlib.sha256()
h.update(b"herness.sdd.pack.v1\0")
for value in [
    payload["schema"], payload["version"], payload["revision"],
    payload["definitionDigest"], payload["policyVersion"],
    payload["policyDigest"], payload["protocol"], payload["hostApiVersion"],
]:
    h.update(str(value).encode("utf-8"))
    h.update(b"\0")
print(h.hexdigest())
"#;
    let mut child = Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3");
    let payload = json!({
        "schema": PACK_INTEGRATION_SCHEMA,
        "version": probe.integration_version(),
        "revision": probe.integration_revision(),
        "definitionDigest": definition_digest,
        "policyVersion": probe.policy_version(),
        "policyDigest": probe.policy_fingerprint().as_str(),
        "protocol": probe.host_api_protocol(),
        "hostApiVersion": probe.host_api_version(),
    });
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write python payload");
    let output = child.wait_with_output().expect("python output");
    let python_digest = String::from_utf8(output.stdout)
        .expect("python utf-8")
        .trim()
        .to_owned();
    assert_eq!(
        python_digest,
        probe.pack_fingerprint().as_str(),
        "Rust and Python compute the same pack fingerprint from the same fixture identity"
    );
}

#[test]
fn symlinked_project_root_is_canonicalized_as_cwd() {
    if !real_pack_present() {
        eprintln!("skip real pack policy bridge test: pack absent");
        return;
    }
    let project = glossary_project();
    let link_parent = TempDir::new().expect("link parent");
    let link = link_parent.path().join("project-link");
    symlink(&project.root, &link).expect("symlink project");
    let canonical = fs::canonicalize(&project.root).expect("canonical project");

    let bridge = HtmlPolicyBridge::detect(&link, REAL_PACK_ROOT, toolchain())
        .expect("detect through symlink");
    assert_eq!(bridge.project_root(), canonical.as_path());
    let (connected, _) = connect_real(bridge);
    let check = connected
        .candidate_check(
            "CONTEXT.md",
            CandidateStage::Structural,
            None,
            &input_map(&project.source, &project.html),
        )
        .expect("candidate check through canonical cwd");
    assert_eq!(check.decision(), CandidateDecision::Allow);
    assert_eq!(
        connected.project_root(),
        canonical.as_path(),
        "the host API runs in the canonical project root"
    );
}

#[test]
fn base64_encoder_matches_known_vectors() {
    use herness_desktop::html_sync::policy::base64_encode;
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
}

fn sorted_tree(root: &Path) -> Vec<String> {
    let mut entries = Vec::new();
    fn walk(root: &Path, current: &Path, entries: &mut Vec<String>) {
        for entry in fs::read_dir(current).expect("read directory") {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .expect("inside root")
                .to_string_lossy()
                .into_owned();
            entries.push(relative);
            if entry.file_type().expect("file type").is_dir() {
                walk(root, &path, entries);
            }
        }
    }
    walk(root, root, &mut entries);
    entries.sort();
    entries
}

fn temp_pack_copy() -> PathBuf {
    let temp = TempDir::new().expect("pack copy");
    let root = temp.keep().join("pack");
    fs::create_dir_all(root.join("scripts")).expect("pack scripts");
    fs::create_dir_all(root.join("adapters/herness")).expect("pack adapters");
    copy_dir_all(
        &Path::new(REAL_PACK_ROOT).join("scripts/sddlib"),
        &root.join("scripts/sddlib"),
    )
    .expect("copy sddlib");
    fs::copy(
        Path::new(REAL_PACK_ROOT).join("scripts/html-docs"),
        root.join("scripts/html-docs"),
    )
    .expect("copy html-docs");
    fs::copy(
        Path::new(REAL_PACK_ROOT).join("adapters/herness/integration.json"),
        root.join("adapters/herness/integration.json"),
    )
    .expect("copy integration");
    root
}

fn copy_dir_all(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn fake_python(root: &Path, body: &str) -> PathBuf {
    let path = root.join(format!("fake-python-{}", uuid::Uuid::new_v4()));
    let script = format!(
        "#!/usr/bin/env python3\nimport sys\nif '--version' in sys.argv:\n    print('Python 3.11.4')\n    sys.exit(0)\nif 'host-api' not in sys.argv:\n    sys.exit(0)\nsys.stdin.read()\n{body}\n"
    );
    fs::write(&path, script).expect("write fake python");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod fake python");
    path
}

fn fake_bridge(root: &Path, python: &Path, timeout_ms: Option<u64>) -> HtmlPolicyBridge {
    let config = herness_core::ToolchainConfig::from_environment()
        .with_python_path(python)
        .expect("fake python path")
        .with_html_docs_path(Path::new(REAL_PACK_ROOT).join("scripts/html-docs"))
        .expect("validator path");
    let bridge = HtmlPolicyBridge::detect(root, REAL_PACK_ROOT, config).expect("fake bridge");
    match timeout_ms {
        Some(timeout_ms) => bridge.with_timeout_ms(timeout_ms).expect("timeout"),
        None => bridge,
    }
}

fn expected_owner() -> OwnerRef {
    owner_binding().owner().clone()
}

fn requested_owner_approval() -> OwnerApproval {
    OwnerApproval::new(
        project(),
        expected_owner(),
        herness_supervision::OwnerApprovalSource::H3ApprovedSettings,
        1,
        "job-14",
        ConditionVersion::new(1).expect("condition version"),
        ConditionDigest::sha256(b"condition-14"),
        owner_binding().execution_scope().clone(),
        profile(ProfilePurpose::Completion, 1),
        consent_binding(ProfilePurpose::Completion, 1),
        1,
        BudgetPolicy::h2_default(),
    )
    .expect("owner approval")
}

fn other_owner() -> OwnerRef {
    OwnerRef::new(OwnerKind::H3HtmlJob, "job-other").expect("owner")
}

fn variant_with_job(base: &OwnerApproval, job: &str) -> OwnerApproval {
    OwnerApproval::new(
        base.project_id(),
        base.owner().clone(),
        base.source(),
        base.settings_version(),
        job,
        base.condition_version(),
        base.conditions_digest().clone(),
        base.execution_scope().clone(),
        base.profile(),
        base.consent(),
        base.budget_policy_version(),
        base.budget().clone(),
    )
    .expect("variant")
}

fn variant_with_settings(base: &OwnerApproval, version: u64) -> OwnerApproval {
    OwnerApproval::new(
        base.project_id(),
        base.owner().clone(),
        base.source(),
        version,
        base.job_id(),
        base.condition_version(),
        base.conditions_digest().clone(),
        base.execution_scope().clone(),
        base.profile(),
        base.consent(),
        base.budget_policy_version(),
        base.budget().clone(),
    )
    .expect("variant")
}

fn variant_with_conditions(base: &OwnerApproval, version: u64) -> OwnerApproval {
    OwnerApproval::new(
        base.project_id(),
        base.owner().clone(),
        base.source(),
        base.settings_version(),
        base.job_id(),
        ConditionVersion::new(version).expect("condition version"),
        base.conditions_digest().clone(),
        base.execution_scope().clone(),
        base.profile(),
        base.consent(),
        base.budget_policy_version(),
        base.budget().clone(),
    )
    .expect("variant")
}

fn variant_with_digest(base: &OwnerApproval, digest: ConditionDigest) -> OwnerApproval {
    OwnerApproval::new(
        base.project_id(),
        base.owner().clone(),
        base.source(),
        base.settings_version(),
        base.job_id(),
        base.condition_version(),
        digest,
        base.execution_scope().clone(),
        base.profile(),
        base.consent(),
        base.budget_policy_version(),
        base.budget().clone(),
    )
    .expect("variant")
}

fn variant_with_scope(base: &OwnerApproval) -> OwnerApproval {
    OwnerApproval::new(
        base.project_id(),
        base.owner().clone(),
        base.source(),
        base.settings_version(),
        base.job_id(),
        base.condition_version(),
        base.conditions_digest().clone(),
        ExecutionScope::new(
            project(),
            vec![TARGET_PATH.to_owned()],
            vec!["private/html-sync/other".to_owned()],
            false,
        )
        .expect("scope"),
        base.profile(),
        base.consent(),
        base.budget_policy_version(),
        base.budget().clone(),
    )
    .expect("variant")
}

fn variant_with_profile(base: &OwnerApproval, version: u64) -> OwnerApproval {
    OwnerApproval::new(
        base.project_id(),
        base.owner().clone(),
        base.source(),
        base.settings_version(),
        base.job_id(),
        base.condition_version(),
        base.conditions_digest().clone(),
        base.execution_scope().clone(),
        profile(ProfilePurpose::Completion, version),
        base.consent(),
        base.budget_policy_version(),
        base.budget().clone(),
    )
    .expect("variant")
}

fn variant_with_consent(base: &OwnerApproval, version: u64) -> OwnerApproval {
    OwnerApproval::new(
        base.project_id(),
        base.owner().clone(),
        base.source(),
        base.settings_version(),
        base.job_id(),
        base.condition_version(),
        base.conditions_digest().clone(),
        base.execution_scope().clone(),
        base.profile(),
        consent_binding(ProfilePurpose::Completion, version),
        base.budget_policy_version(),
        base.budget().clone(),
    )
    .expect("variant")
}

fn variant_with_budget_version(base: &OwnerApproval, version: u64) -> OwnerApproval {
    OwnerApproval::new(
        base.project_id(),
        base.owner().clone(),
        base.source(),
        base.settings_version(),
        base.job_id(),
        base.condition_version(),
        base.conditions_digest().clone(),
        base.execution_scope().clone(),
        base.profile(),
        base.consent(),
        version,
        base.budget().clone(),
    )
    .expect("variant")
}

fn variant_with_budget(base: &OwnerApproval) -> OwnerApproval {
    OwnerApproval::new(
        base.project_id(),
        base.owner().clone(),
        base.source(),
        base.settings_version(),
        base.job_id(),
        base.condition_version(),
        base.conditions_digest().clone(),
        base.execution_scope().clone(),
        base.profile(),
        base.consent(),
        base.budget_policy_version(),
        BudgetPolicy::new(100, 30, None).expect("budget"),
    )
    .expect("variant")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("hex");
    }
    hex
}

struct ScriptedRegistry(Option<OwnerApproval>);

impl OwnerApprovalRegistryPort for ScriptedRegistry {
    fn current_owner_approval(
        &self,
        _project_id: ProjectId,
        _owner: &OwnerRef,
        _now: Timestamp,
    ) -> Result<Option<OwnerApproval>, SupervisionError> {
        Ok(self.0.clone())
    }
}
