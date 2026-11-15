//! Task 24: evaluation fixtures and the explicit opt-in gate for real
//! connections.
//!
//! This target has three jobs.
//!
//! 1. Run hand-authored new-format plans through the real Common SDD pack
//!    inspector. Two plans must be accepted; each negative fixture must be
//!    refused for its named reason. Importing a plan changes no file and opens
//!    no socket.
//! 2. Execute the default-deny acceptance gate: a run without an explicit
//!    human opt-in refuses before the first transport call, and an expired,
//!    out-of-scope, over-budget, or cost-less manifest is refused the same way.
//! 3. Keep the metrics separate. Wrong completion, wrong commit and wrong
//!    dispatch are their own counters; pending and human-wait holds are not
//!    defects; inherited H1/H2/H3/H4 unknowns stay explicitly unconfirmed.
//!
//! No real provider is contacted. The only transport in this target records
//! calls in memory, and the default run is refused before it is reached, so the
//! external request count is zero and the real-provider column is
//! `not_executed` / unconfirmed.

mod acceptance_gate;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use acceptance_gate::{
    AcceptanceGate, AcceptanceHold, AcceptanceMetrics, AcceptanceRequest, AcceptanceTransport,
    ConnectionIdentity, GateRefusal, INHERITED_UNCONFIRMED, MANIFEST_ENV, OPT_IN_ENV,
    REQUIRED_SEND_BYTE_KINDS, RunRefusal, RunReport, ScheduledSend, SendByteKind, TransportFailure,
    run_acceptance,
};
use herness_core::{AbsolutePath, ProcessSupervisor, ProjectId, SystemArgvLauncher};
use herness_desktop::sdd_execute::pack::ImportPreview;
use herness_desktop::sdd_execute::{PackInspector, PlanFileSource, PlanImporter};
use herness_sdd_execute::{FailureCode, PlanPath, SddExecutionError, SourceLayout};
use serde_json::{Value, json};
use tempfile::TempDir;
use uuid::Uuid;

const PLAN_DIR: &str = "docs/sdd/plans/";
const SPEC_PATH: &str = "docs/sdd/specs/2026-11-15-h4-acceptance-design.md";
const DEFAULT_PACK_ROOT: &str = "/Users/h-uma/Documents/sdd/.worktrees/h4-exec";
const NOW_MILLIS: u64 = 1_800_000_000_000;
const FIXTURE_CONNECTION: [&str; 4] = ["openai", "conn-fixture", "openai_responses", "gpt-fixture"];

// ---------------------------------------------------------------------------
// Fixture files
// ---------------------------------------------------------------------------

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/acceptance")
        .join(name)
}

fn fixture_text(name: &str) -> String {
    fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|error| panic!("fixture {name} is readable: {error}"))
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    fs::read(fixture_path(name))
        .unwrap_or_else(|error| panic!("fixture {name} is readable: {error}"))
}

fn fixture_manifest() -> Vec<u8> {
    fixture_bytes("acceptance.manifest.json")
}

fn plan_path_for(plan_file: &str) -> PlanPath {
    PlanPath::parse(format!("{PLAN_DIR}{plan_file}")).expect("a fixture plan path")
}

fn pack_root() -> PathBuf {
    let root = std::env::var_os("SDD_PACK_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PACK_ROOT));
    let script = root.join("scripts/plan-inspect");
    assert!(
        script.is_file(),
        "no SDD pack inspector at {}. Set SDD_PACK_ROOT to a pack checkout that has \
         scripts/plan-inspect (documented default {DEFAULT_PACK_ROOT}).",
        script.display()
    );
    eprintln!("acceptance tests: SDD pack root = {}", root.display());
    root
}

fn python() -> AbsolutePath {
    for candidate in [
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/usr/bin/python3",
    ] {
        if Path::new(candidate).is_file() {
            return AbsolutePath::new(candidate).expect("an absolute interpreter path");
        }
    }
    panic!("python3 was not found at a known absolute path");
}

fn project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("d1000000-0000-4000-8000-000000000001").expect("a UUID"))
}

/// Writes one plan and its spec into a fresh temporary checkout.
fn checkout_with(plan_file: &str) -> (TempDir, PathBuf) {
    let temp = TempDir::new().expect("a temporary directory");
    let root = temp.path().join("checkout");
    fs::create_dir_all(root.join("docs/sdd/plans")).expect("the plan directory");
    fs::create_dir_all(root.join("docs/sdd/specs")).expect("the spec directory");
    fs::create_dir_all(root.join("src")).expect("the source directory");
    fs::write(root.join(SPEC_PATH), fixture_text("spec.md")).expect("the fixture spec");
    fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").expect("the fixture source");
    fs::write(
        root.join(PLAN_DIR).join(plan_file),
        fixture_bytes(&format!("plans/{plan_file}")),
    )
    .expect("the fixture plan");
    (temp, root)
}

fn import(root: &Path, plan: &PlanPath) -> Result<ImportPreview, SddExecutionError> {
    let bridge = PackInspector::new(
        pack_root(),
        python(),
        SystemArgvLauncher,
        ProcessSupervisor::new(),
        project(),
    )
    .expect("the pack inspector is constructible");
    let source = PlanFileSource::new(project(), root).expect("a plan source");
    let canonical = root.canonicalize().expect("a canonical root");
    let layout = SourceLayout::new(canonical.to_str().expect("the root is UTF-8").to_owned())
        .expect("a source layout");
    PlanImporter::new(bridge, source, layout, None).import(plan)
}

/// Every file under `root` with its exact bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, current: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let entries = fs::read_dir(current).expect("a readable directory");
        for entry in entries {
            let entry = entry.expect("a directory entry");
            let path = entry.path();
            if entry.file_type().expect("a file type").is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root)
                        .expect("a relative path")
                        .to_path_buf(),
                    fs::read(&path).expect("a readable file"),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Connection probe
// ---------------------------------------------------------------------------

/// A loopback listener that records whether anything connected.
struct ConnectionProbe {
    listener: TcpListener,
    connections: u64,
}

impl ConnectionProbe {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking");
        Self {
            listener,
            connections: 0,
        }
    }

    fn observe(&mut self) -> u64 {
        loop {
            match self.listener.accept() {
                Ok((_stream, _address)) => self.connections += 1,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return self.connections,
                Err(error) => panic!("the probe listener failed: {error}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Plan fixtures against the real pack
// ---------------------------------------------------------------------------

struct AcceptedCase {
    file: &'static str,
    tasks: usize,
    dependency: Vec<u32>,
    final_checks: usize,
}

struct RefusedCase {
    file: &'static str,
    invalid_plan: bool,
    contains: &'static str,
}

#[test]
fn synthetic_plans_are_accepted_or_refused_by_the_real_pack() {
    let mut probe = ConnectionProbe::new();
    let accepted = [
        AcceptedCase {
            file: "valid-two-task.md",
            tasks: 2,
            dependency: vec![1],
            final_checks: 1,
        },
        AcceptedCase {
            file: "valid-single-task.md",
            tasks: 1,
            dependency: Vec::new(),
            final_checks: 1,
        },
    ];
    for case in &accepted {
        let (_temp, root) = checkout_with(case.file);
        let before = snapshot(&root);
        let preview = import(&root, &plan_path_for(case.file))
            .unwrap_or_else(|error| panic!("{} must be accepted: {error}", case.file));
        assert_eq!(preview.preview().tasks().len(), case.tasks, "{}", case.file);
        assert_eq!(
            preview.preview().tasks()[case.tasks - 1].depends_on(),
            case.dependency.as_slice(),
            "{} task dependencies",
            case.file
        );
        assert_eq!(
            preview.preview().final_check_ids().len(),
            case.final_checks,
            "{} final checks",
            case.file
        );
        assert_eq!(
            preview.preview().tasks()[0].number(),
            1,
            "{} starts at Task 1",
            case.file
        );
        assert_eq!(
            snapshot(&root),
            before,
            "{} import must not change the checkout",
            case.file
        );
        assert_eq!(probe.observe(), 0, "{} opened no socket", case.file);
        eprintln!(
            "H4_ACCEPTANCE_PLAN_ACCEPTED: {} tasks={} connection=0",
            case.file,
            preview.preview().tasks().len()
        );
    }

    let refused = [
        RefusedCase {
            file: "invalid-unknown-field.md",
            invalid_plan: true,
            contains: "unknown field(s): hostHint",
        },
        RefusedCase {
            file: "invalid-unknown-version.md",
            invalid_plan: true,
            contains: "unsupported schema version 2",
        },
        RefusedCase {
            file: "invalid-broken-fence.md",
            invalid_plan: true,
            contains: "fenced code block is never closed",
        },
        RefusedCase {
            file: "invalid-path-escape.md",
            invalid_plan: true,
            contains: "must not contain '..'",
        },
        RefusedCase {
            file: "invalid-forward-dependency.md",
            invalid_plan: true,
            contains: "strictly earlier task",
        },
        RefusedCase {
            file: "invalid-non-contiguous-numbering.md",
            invalid_plan: true,
            contains: "numbered 1..N in order",
        },
        RefusedCase {
            file: "legacy-prose.md",
            invalid_plan: false,
            contains: "old free-prose plan format",
        },
    ];
    for case in &refused {
        let (_temp, root) = checkout_with(case.file);
        let before = snapshot(&root);
        let error = import(&root, &plan_path_for(case.file))
            .err()
            .unwrap_or_else(|| panic!("{} must be refused", case.file));
        let diagnostic = error
            .plan_diagnostic()
            .unwrap_or_else(|| panic!("{} must be a plan diagnostic: {error}", case.file));
        if case.invalid_plan {
            assert_eq!(
                FailureCode::of(&error).map(FailureCode::as_str),
                Some("invalid_plan"),
                "{} is a schema defect: {error}",
                case.file
            );
            assert_eq!(
                diagnostic.code().as_str(),
                "invalid_plan",
                "{} diagnostic code",
                case.file
            );
        } else {
            assert_eq!(
                FailureCode::of(&error).map(FailureCode::as_str),
                Some("unsupported_plan_format"),
                "{} is an old-format document: {error}",
                case.file
            );
        }
        assert!(
            diagnostic.message().contains(case.contains),
            "{} must report {:?}, observed {:?}",
            case.file,
            case.contains,
            diagnostic.message()
        );
        assert_eq!(
            snapshot(&root),
            before,
            "{} refusal must not change the checkout",
            case.file
        );
        assert_eq!(probe.observe(), 0, "{} opened no socket", case.file);
        eprintln!(
            "H4_ACCEPTANCE_PLAN_REFUSED: {} code={} pointer={:?} message={}",
            case.file,
            diagnostic.code().as_str(),
            diagnostic.pointer(),
            diagnostic.message()
        );
    }

    assert_eq!(
        probe.observe(),
        0,
        "the inspector sent no network request for any fixture"
    );
    eprintln!(
        "H4_ACCEPTANCE_PLANS: accepted={} refused={} connections={}",
        accepted.len(),
        refused.len(),
        probe.observe()
    );
}

// ---------------------------------------------------------------------------
// Manifest fixtures
// ---------------------------------------------------------------------------

fn valid_manifest() -> Value {
    let inherited = INHERITED_UNCONFIRMED
        .iter()
        .map(|(id, detail)| json!({"id": id, "status": "unconfirmed", "detail": detail}))
        .collect::<Vec<_>>();
    json!({
        "schema": "h4-real-connection-acceptance-v1",
        "status": "approved",
        "note": "Synthetic test manifest. It is not a human approval and authorizes nothing.",
        "externalRequests": 0,
        "approvedBy": "fixture-controller",
        "approvedAt": "2026-11-15T00:00:00Z",
        "expiresAtMillis": 2_000_000_000_000u64,
        "connection": {
            "provider": FIXTURE_CONNECTION[0],
            "connectionId": FIXTURE_CONNECTION[1],
            "endpointClass": FIXTURE_CONNECTION[2],
            "model": FIXTURE_CONNECTION[3],
            "purpose": "assessment"
        },
        "credentialAccess": "none",
        "fixtures": ["valid-two-task", "valid-single-task"],
        "sendByteKinds": REQUIRED_SEND_BYTE_KINDS
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        "h3Capabilities": {
            "image": "unconfirmed",
            "support": "unconfirmed",
            "usability": "unconfirmed",
            "render": "unconfirmed",
            "humanReadingObservation": "unconfirmed"
        },
        "requestBudget": {"maxRequests": 4, "perFixtureMax": 2},
        "retryPolicy": {
            "maxAttempts": 2,
            "sameConnectionOnly": true,
            "retryOn": ["timeout", "connection-reset"]
        },
        "cost": {
            "priced": true,
            "feeCapUsd": 0.5,
            "quotaLabel": "fixture-quota",
            "quotaConfirmed": true
        },
        "inheritedUnconfirmed": inherited
    })
}

fn manifest_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("a serializable manifest")
}

fn valid_request() -> AcceptanceRequest {
    AcceptanceRequest {
        connection: ConnectionIdentity::new(
            FIXTURE_CONNECTION[0],
            FIXTURE_CONNECTION[1],
            FIXTURE_CONNECTION[2],
            FIXTURE_CONNECTION[3],
        ),
        fixtures: vec!["valid-two-task".to_owned(), "valid-single-task".to_owned()],
        send_byte_kinds: REQUIRED_SEND_BYTE_KINDS.to_vec(),
        requests: 2,
        per_fixture_requests: 1,
        retries: 0,
    }
}

fn valid_schedule() -> Vec<ScheduledSend> {
    vec![
        ScheduledSend {
            fixture: "valid-two-task".to_owned(),
            kind: SendByteKind::PlanPacket,
        },
        ScheduledSend {
            fixture: "valid-single-task".to_owned(),
            kind: SendByteKind::PlanPacket,
        },
    ]
}

#[derive(Default)]
struct RecordingTransport {
    sends: Vec<ScheduledSend>,
    connections: Vec<ConnectionIdentity>,
}

impl AcceptanceTransport for RecordingTransport {
    fn send(
        &mut self,
        connection: &ConnectionIdentity,
        send: &ScheduledSend,
    ) -> Result<(), TransportFailure> {
        self.sends.push(send.clone());
        self.connections.push(connection.clone());
        Ok(())
    }
}

struct FailingTransport {
    reason: String,
    calls: u64,
}

impl FailingTransport {
    fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_owned(),
            calls: 0,
        }
    }
}

impl AcceptanceTransport for FailingTransport {
    fn send(
        &mut self,
        _connection: &ConnectionIdentity,
        _send: &ScheduledSend,
    ) -> Result<(), TransportFailure> {
        self.calls += 1;
        Err(TransportFailure::new(self.reason.clone()))
    }
}

fn expect_refusal(
    label: &str,
    opt_in: Option<&str>,
    manifest: &[u8],
    request: &AcceptanceRequest,
    schedule: &[ScheduledSend],
) -> GateRefusal {
    let mut transport = RecordingTransport::default();
    let error = run_acceptance(
        opt_in,
        Some(manifest),
        NOW_MILLIS,
        request,
        schedule,
        &mut transport,
    )
    .expect_err(&format!("{label} must be refused"));
    assert!(
        transport.sends.is_empty(),
        "{label} must refuse before any send, observed {}",
        transport.sends.len()
    );
    match error {
        RunRefusal::Gate(refusal) => refusal,
        other => panic!("{label} must be refused by the gate, observed {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Default deny
// ---------------------------------------------------------------------------

#[test]
fn no_explicit_opt_in_refuses_before_sending() {
    assert!(
        std::env::var_os(OPT_IN_ENV).is_none(),
        "{OPT_IN_ENV} is set in this process; the default-deny evidence requires a clean \
         environment. Unset it and re-run."
    );
    assert!(
        std::env::var_os(MANIFEST_ENV).is_none(),
        "{MANIFEST_ENV} is set in this process; the default-deny evidence requires a clean \
         environment. Unset it and re-run."
    );

    let mut probe = ConnectionProbe::new();
    let request = valid_request();
    let manifest = manifest_bytes(&valid_manifest());

    // The explicit opt-in string is required; every other value is a refusal.
    for opt_in in [
        None,
        Some("0"),
        Some("true"),
        Some("yes"),
        Some(""),
        Some(" 1"),
    ] {
        let refusal = expect_refusal(
            &format!("opt-in {opt_in:?}"),
            opt_in,
            &manifest,
            &request,
            &valid_schedule(),
        );
        match opt_in {
            None => assert_eq!(refusal, GateRefusal::OptInMissing),
            Some(_) => assert!(
                matches!(refusal, GateRefusal::OptInNotExplicit { .. }),
                "opt-in {opt_in:?} must be refused as not explicit, observed {refusal:?}"
            ),
        }
    }

    // The environment reader is the shipped entry point. In a default test
    // process it has no manifest path, so it refuses without a transport.
    let error = AcceptanceGate::from_environment(NOW_MILLIS, &request)
        .expect_err("a default environment is not an approval");
    assert!(
        matches!(
            error,
            GateRefusal::OptInMissing | GateRefusal::ManifestMissing
        ),
        "the default environment must refuse for a missing opt-in or manifest, observed {error:?}"
    );

    // The shipped manifest is a template, not an approval.
    let mut transport = RecordingTransport::default();
    let error = run_acceptance(
        Some("1"),
        Some(&fixture_manifest()),
        NOW_MILLIS,
        &request,
        &valid_schedule(),
        &mut transport,
    )
    .expect_err("the shipped manifest must be refused");
    assert!(
        matches!(
            error,
            RunRefusal::Gate(GateRefusal::NotAuthorized { .. })
                | RunRefusal::Gate(GateRefusal::ManifestFieldMissing { .. })
        ),
        "the template is not authorized, observed {error:?}"
    );
    assert!(transport.sends.is_empty(), "the template sends nothing");

    assert_eq!(probe.observe(), 0, "no socket connection was opened");
    eprintln!(
        "H4_ACCEPTANCE_DEFAULT_DENY: external_requests=0 socket_connections={} template_status={}",
        probe.observe(),
        fixture_manifest_status()
    );
}

fn fixture_manifest_status() -> String {
    let value: Value =
        serde_json::from_slice(&fixture_manifest()).expect("the shipped manifest is JSON");
    value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("<missing>")
        .to_owned()
}

#[test]
fn the_shipped_manifest_template_is_not_an_approval() {
    let value: Value =
        serde_json::from_slice(&fixture_manifest()).expect("the shipped manifest is JSON");
    assert_eq!(
        value.get("schema").and_then(Value::as_str),
        Some("h4-real-connection-acceptance-v1")
    );
    assert_eq!(
        value.get("status").and_then(Value::as_str),
        Some("not_authorized")
    );
    assert_eq!(
        value.get("externalRequests").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        value.get("credentialAccess").and_then(Value::as_str),
        Some("none")
    );
    assert_eq!(
        value.get("expiresAtMillis").and_then(Value::as_u64),
        Some(0),
        "the template has no usable expiry"
    );
    assert!(
        value
            .get("fixtures")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    );
    assert!(
        value
            .get("sendByteKinds")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(
        value
            .get("requestBudget")
            .and_then(|budget| budget.get("maxRequests"))
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        value
            .get("retryPolicy")
            .and_then(|policy| policy.get("maxAttempts"))
            .and_then(Value::as_u64),
        Some(0)
    );
    assert!(
        value
            .get("cost")
            .and_then(|cost| cost.get("feeCapUsd"))
            .is_some_and(Value::is_null)
    );
    let inherited = value
        .get("inheritedUnconfirmed")
        .and_then(Value::as_array)
        .expect("inherited list");
    assert_eq!(inherited.len(), INHERITED_UNCONFIRMED.len());
    for item in inherited {
        assert_eq!(
            item.get("status").and_then(Value::as_str),
            Some("unconfirmed")
        );
    }
}

// ---------------------------------------------------------------------------
// Gate refusals
// ---------------------------------------------------------------------------

#[test]
fn an_expired_manifest_is_refused_before_sending() {
    let mut manifest = valid_manifest();
    manifest["expiresAtMillis"] = json!(NOW_MILLIS - 1);
    let request = valid_request();
    let refusal = expect_refusal(
        "an expired manifest",
        Some("1"),
        &manifest_bytes(&manifest),
        &request,
        &valid_schedule(),
    );
    assert_eq!(
        refusal,
        GateRefusal::Expired {
            expires_at_millis: NOW_MILLIS - 1,
            now_millis: NOW_MILLIS
        }
    );

    manifest["expiresAtMillis"] = json!(NOW_MILLIS);
    let refusal = expect_refusal(
        "a manifest expiring now",
        Some("1"),
        &manifest_bytes(&manifest),
        &request,
        &valid_schedule(),
    );
    assert!(
        matches!(refusal, GateRefusal::Expired { .. }),
        "the expiry boundary refuses, observed {refusal:?}"
    );
}

#[test]
fn an_out_of_scope_request_is_refused_before_sending() {
    let manifest = valid_manifest();
    let bytes = manifest_bytes(&manifest);
    let schedule = valid_schedule();

    let mut request = valid_request();
    request.fixtures[0] = "not-approved".to_owned();
    assert!(matches!(
        expect_refusal(
            "an unapproved fixture",
            Some("1"),
            &bytes,
            &request,
            &schedule
        ),
        GateRefusal::FixtureOutOfScope { .. }
    ));

    let mut request = valid_request();
    request.connection.model = "gpt-other".to_owned();
    assert_eq!(
        expect_refusal("a different model", Some("1"), &bytes, &request, &schedule),
        GateRefusal::ConnectionMismatch { field: "model" }
    );

    let mut request = valid_request();
    request.send_byte_kinds.pop();
    assert_eq!(
        expect_refusal(
            "a narrowed send-byte set",
            Some("1"),
            &bytes,
            &request,
            &schedule
        ),
        GateRefusal::SendByteKindsMismatch
    );

    let mut request = valid_request();
    request.requests = 9;
    assert_eq!(
        expect_refusal("a request overrun", Some("1"), &bytes, &request, &schedule),
        GateRefusal::RequestCountOverrun {
            approved: 4,
            requested: 9
        }
    );

    let mut request = valid_request();
    request.per_fixture_requests = 3;
    assert_eq!(
        expect_refusal(
            "a per-fixture overrun",
            Some("1"),
            &bytes,
            &request,
            &schedule
        ),
        GateRefusal::PerFixtureOverrun {
            approved: 2,
            requested: 3
        }
    );

    let mut request = valid_request();
    request.retries = 3;
    assert_eq!(
        expect_refusal("a retry overrun", Some("1"), &bytes, &request, &schedule),
        GateRefusal::RetryOverrun {
            approved: 2,
            requested: 3
        }
    );

    let mut request = valid_request();
    request.requests = 1;
    assert_eq!(
        expect_refusal(
            "a request that cannot cover its fixtures",
            Some("1"),
            &bytes,
            &request,
            &schedule
        ),
        GateRefusal::RequestCountOverrun {
            approved: 1,
            requested: 2
        }
    );
}

#[test]
fn a_manifest_without_cost_or_quota_is_refused() {
    let request = valid_request();
    let schedule = valid_schedule();

    let mut manifest = valid_manifest();
    manifest["cost"] = json!({
        "priced": false,
        "feeCapUsd": null,
        "quotaLabel": "",
        "quotaConfirmed": false
    });
    assert_eq!(
        expect_refusal(
            "no cost and no quota",
            Some("1"),
            &manifest_bytes(&manifest),
            &request,
            &schedule
        ),
        GateRefusal::CostOrQuotaMissing
    );

    let mut manifest = valid_manifest();
    manifest["cost"] = json!({
        "priced": true,
        "feeCapUsd": null,
        "quotaLabel": "fixture-quota",
        "quotaConfirmed": true
    });
    assert_eq!(
        expect_refusal(
            "a priced request without a money cap",
            Some("1"),
            &manifest_bytes(&manifest),
            &request,
            &schedule
        ),
        GateRefusal::PricedRequestWithoutMoneyCap
    );

    let mut manifest = valid_manifest();
    manifest["cost"] = json!({
        "priced": false,
        "feeCapUsd": null,
        "quotaLabel": "fixture-quota",
        "quotaConfirmed": false
    });
    assert_eq!(
        expect_refusal(
            "an unconfirmed quota",
            Some("1"),
            &manifest_bytes(&manifest),
            &request,
            &schedule
        ),
        GateRefusal::CostOrQuotaMissing
    );

    let mut manifest = valid_manifest();
    manifest["cost"]["feeCapUsd"] = json!(-1.0);
    assert_eq!(
        expect_refusal(
            "a negative money cap",
            Some("1"),
            &manifest_bytes(&manifest),
            &request,
            &schedule
        ),
        GateRefusal::CostNotFinite
    );
}

#[test]
fn the_approval_is_never_widened_into_a_login_or_credential() {
    let request = valid_request();
    let schedule = valid_schedule();

    let mut manifest = valid_manifest();
    manifest["credentialAccess"] = json!("login");
    assert_eq!(
        expect_refusal(
            "a login widening",
            Some("1"),
            &manifest_bytes(&manifest),
            &request,
            &schedule
        ),
        GateRefusal::CredentialAccessWidened {
            value: "login".to_owned()
        }
    );

    let mut manifest = valid_manifest();
    manifest["apiKey"] = json!("sk-fixture-never-used");
    let refusal = expect_refusal(
        "an embedded credential",
        Some("1"),
        &manifest_bytes(&manifest),
        &request,
        &schedule,
    );
    assert_eq!(
        refusal,
        GateRefusal::CredentialMaterialPresent {
            field: "apiKey".to_owned()
        }
    );

    let mut manifest = valid_manifest();
    manifest["connection"]["accessToken"] = json!("fixture-token-never-used");
    let refusal = expect_refusal(
        "a nested credential",
        Some("1"),
        &manifest_bytes(&manifest),
        &request,
        &schedule,
    );
    assert_eq!(
        refusal,
        GateRefusal::CredentialMaterialPresent {
            field: "connection.accessToken".to_owned()
        }
    );
}

#[test]
fn required_h3_capabilities_and_inherited_unknowns_cannot_be_omitted() {
    let request = valid_request();
    let schedule = valid_schedule();

    let mut manifest = valid_manifest();
    manifest["h3Capabilities"]["image"] = json!("confirmed");
    assert_eq!(
        expect_refusal(
            "a confirmed image capability",
            Some("1"),
            &manifest_bytes(&manifest),
            &request,
            &schedule
        ),
        GateRefusal::UnconfirmedCapabilityClaimed {
            capability: "image",
            value: "confirmed".to_owned()
        }
    );

    let mut manifest = valid_manifest();
    manifest["h3Capabilities"]
        .as_object_mut()
        .expect("capabilities")
        .remove("render");
    assert_eq!(
        expect_refusal(
            "a missing render capability",
            Some("1"),
            &manifest_bytes(&manifest),
            &request,
            &schedule
        ),
        GateRefusal::ManifestFieldMissing { field: "render" }
    );

    let mut manifest = valid_manifest();
    let kinds = manifest["sendByteKinds"]
        .as_array_mut()
        .expect("send kinds");
    kinds.retain(|kind| kind.as_str() != Some("h3_render_evidence"));
    assert_eq!(
        expect_refusal(
            "an omitted H3 render evidence kind",
            Some("1"),
            &manifest_bytes(&manifest),
            &request,
            &schedule
        ),
        GateRefusal::RequiredSendByteKindMissing {
            kind: SendByteKind::H3RenderEvidence
        }
    );

    let mut manifest = valid_manifest();
    for item in manifest["inheritedUnconfirmed"]
        .as_array_mut()
        .expect("inherited list")
    {
        if item.get("id").and_then(Value::as_str) == Some("h3-residual-conditions") {
            item["status"] = json!("confirmed");
        }
    }
    assert_eq!(
        expect_refusal(
            "a confirmed residual condition",
            Some("1"),
            &manifest_bytes(&manifest),
            &request,
            &schedule
        ),
        GateRefusal::InheritedUnconfirmedClaimed {
            id: "h3-residual-conditions".to_owned()
        }
    );

    let mut manifest = valid_manifest();
    manifest["inheritedUnconfirmed"]
        .as_array_mut()
        .expect("inherited list")
        .retain(|item| item.get("id").and_then(Value::as_str) != Some("h1-acceptance"));
    assert_eq!(
        expect_refusal(
            "an omitted H1 inherited item",
            Some("1"),
            &manifest_bytes(&manifest),
            &request,
            &schedule
        ),
        GateRefusal::InheritedUnconfirmedMissing {
            id: "h1-acceptance"
        }
    );
}

// ---------------------------------------------------------------------------
// Authorized run (recording transport only)
// ---------------------------------------------------------------------------

#[test]
fn an_authorized_scope_sends_only_what_the_manifest_allows() {
    let manifest = manifest_bytes(&valid_manifest());
    let request = valid_request();
    let gate = AcceptanceGate::authorize(Some("1"), Some(&manifest), NOW_MILLIS, &request)
        .expect("a complete manifest authorizes the run");
    assert_eq!(gate.approved_by(), "fixture-controller");
    assert_eq!(gate.approved_at(), "2026-11-15T00:00:00Z");
    assert_eq!(gate.expires_at_millis(), 2_000_000_000_000);
    assert_eq!(
        gate.connection(),
        &ConnectionIdentity::new(
            FIXTURE_CONNECTION[0],
            FIXTURE_CONNECTION[1],
            FIXTURE_CONNECTION[2],
            FIXTURE_CONNECTION[3]
        )
    );
    assert_eq!(gate.max_requests(), 4);
    assert_eq!(gate.per_fixture_max(), 2);
    assert_eq!(gate.max_attempts(), 2);
    assert_eq!(gate.fee_cap_usd(), Some(0.5));
    assert_eq!(gate.quota_label(), Some("fixture-quota"));
    assert!(
        gate.fixtures().contains("valid-two-task"),
        "the approved fixtures are visible"
    );
    assert!(
        gate.send_byte_kinds()
            .contains(&SendByteKind::H3RenderEvidence),
        "the approved kinds keep the H3 render evidence"
    );
    assert!(
        gate.retry_on().contains("timeout"),
        "the approved retry reasons are visible"
    );

    let mut transport = RecordingTransport::default();
    let report: RunReport = run_acceptance(
        Some("1"),
        Some(&manifest),
        NOW_MILLIS,
        &request,
        &valid_schedule(),
        &mut transport,
    )
    .expect("a complete manifest authorizes the run");

    assert_eq!(report.sends, 2);
    assert_eq!(report.retries, 0);
    assert_eq!(report.metrics.external_requests(), 2);
    assert_eq!(report.metrics.wrong_completion(), 0);
    assert_eq!(report.metrics.wrong_commit(), 0);
    assert_eq!(report.metrics.wrong_dispatch(), 0);
    assert_eq!(report.metrics.held_pending(), 0);
    assert_eq!(report.metrics.held_human_wait(), 0);
    assert_eq!(transport.sends.len(), 2);
    assert_eq!(
        transport.connections,
        vec![
            ConnectionIdentity::new(
                FIXTURE_CONNECTION[0],
                FIXTURE_CONNECTION[1],
                FIXTURE_CONNECTION[2],
                FIXTURE_CONNECTION[3]
            ),
            ConnectionIdentity::new(
                FIXTURE_CONNECTION[0],
                FIXTURE_CONNECTION[1],
                FIXTURE_CONNECTION[2],
                FIXTURE_CONNECTION[3]
            )
        ],
        "every send stays on the approved connection"
    );

    let metrics = report.metrics.to_json(false);
    assert_eq!(
        metrics["realProvider"]["status"],
        json!("not_executed"),
        "the real-provider column is not executed in this task"
    );
    assert_eq!(metrics["realProvider"]["confirmed"], json!(false));
    assert_eq!(metrics["externalRequests"], json!(2));

    // A schedule that exceeds the gate is refused before the transport.
    let extra = {
        let mut schedule = valid_schedule();
        schedule.push(ScheduledSend {
            fixture: "valid-two-task".to_owned(),
            kind: SendByteKind::PlanPacket,
        });
        schedule
    };
    let mut transport = RecordingTransport::default();
    let error = run_acceptance(
        Some("1"),
        Some(&manifest),
        NOW_MILLIS,
        &request,
        &extra,
        &mut transport,
    )
    .expect_err("an over-long schedule is refused");
    assert_eq!(
        error,
        RunRefusal::ScheduleCountMismatch {
            approved: 2,
            scheduled: 3
        }
    );
    assert!(transport.sends.is_empty());

    // Per-fixture overrun is enforced while running.
    let mut manifest = valid_manifest();
    manifest["requestBudget"]["perFixtureMax"] = json!(1);
    let mut request = valid_request();
    request.requests = 2;
    let repeated = vec![
        ScheduledSend {
            fixture: "valid-two-task".to_owned(),
            kind: SendByteKind::PlanPacket,
        },
        ScheduledSend {
            fixture: "valid-two-task".to_owned(),
            kind: SendByteKind::TaskReport,
        },
    ];
    let mut transport = RecordingTransport::default();
    let error = run_acceptance(
        Some("1"),
        Some(&manifest_bytes(&manifest)),
        NOW_MILLIS,
        &request,
        &repeated,
        &mut transport,
    )
    .expect_err("a per-fixture overrun is refused");
    assert_eq!(
        error,
        RunRefusal::PerFixtureOverrun {
            approved: 1,
            observed: 1
        }
    );
    assert_eq!(
        transport.sends.len(),
        1,
        "the overrun stops before the second send"
    );

    // An unapproved retry reason stops at the first failed send.
    let mut failing = FailingTransport::new("quota");
    let error = run_acceptance(
        Some("1"),
        Some(&manifest_bytes(&valid_manifest())),
        NOW_MILLIS,
        &valid_request(),
        &valid_schedule(),
        &mut failing,
    )
    .expect_err("an unapproved retry reason is refused");
    assert_eq!(
        error,
        RunRefusal::RetryReasonNotApproved {
            reason: "quota".to_owned()
        }
    );
    assert_eq!(failing.calls, 1);

    // The approved retry count is finite and enforced.
    let mut manifest = valid_manifest();
    manifest["requestBudget"]["perFixtureMax"] = json!(8);
    manifest["retryPolicy"]["maxAttempts"] = json!(2);
    let mut failing = FailingTransport::new("timeout");
    let error = run_acceptance(
        Some("1"),
        Some(&manifest_bytes(&manifest)),
        NOW_MILLIS,
        &valid_request(),
        &valid_schedule(),
        &mut failing,
    )
    .expect_err("the retry budget is enforced");
    assert_eq!(error, RunRefusal::RetryBudgetExceeded { approved: 2 });
    assert_eq!(
        failing.calls, 3,
        "the attempt plus two approved retries were tried, then refused"
    );
}

// ---------------------------------------------------------------------------
// Metrics separation
// ---------------------------------------------------------------------------

#[test]
fn wrong_results_and_holds_are_counted_separately() {
    let mut metrics = AcceptanceMetrics::zero();
    metrics.observe(acceptance_gate::AcceptanceDefect::Completion);
    metrics.observe(acceptance_gate::AcceptanceDefect::Completion);
    metrics.observe(acceptance_gate::AcceptanceDefect::Commit);
    metrics.observe(acceptance_gate::AcceptanceDefect::Dispatch);
    metrics.observe(acceptance_gate::AcceptanceDefect::Dispatch);
    metrics.observe(acceptance_gate::AcceptanceDefect::Dispatch);
    metrics.hold(AcceptanceHold::Pending);
    metrics.hold(AcceptanceHold::Pending);
    metrics.hold(AcceptanceHold::HumanWait);

    assert_eq!(metrics.wrong_completion(), 2);
    assert_eq!(metrics.wrong_commit(), 1);
    assert_eq!(metrics.wrong_dispatch(), 3);
    assert_eq!(metrics.held_pending(), 2);
    assert_eq!(metrics.held_human_wait(), 1);
    assert_eq!(metrics.external_requests(), 0);

    let value = metrics.to_json(false);
    assert_eq!(value["counts"]["wrongCompletion"], json!(2));
    assert_eq!(value["counts"]["wrongCommit"], json!(1));
    assert_eq!(value["counts"]["wrongDispatch"], json!(3));
    assert_eq!(value["holds"]["pending"], json!(2));
    assert_eq!(value["holds"]["humanWait"], json!(1));
    assert_eq!(
        value["realProvider"]["status"],
        json!("not_executed"),
        "simulated metrics never claim a real-provider result"
    );
    assert_eq!(value["realProvider"]["confirmed"], json!(false));

    let inherited = value["inheritedUnconfirmed"]
        .as_array()
        .expect("inherited array");
    assert_eq!(inherited.len(), INHERITED_UNCONFIRMED.len());
    let ids = inherited
        .iter()
        .map(|item| item["id"].as_str().expect("an id").to_owned())
        .collect::<BTreeSet<_>>();
    for (id, _) in INHERITED_UNCONFIRMED {
        assert!(ids.contains(id), "the metrics inherit {id}");
    }
    for item in inherited {
        assert_eq!(item["status"], json!("unconfirmed"));
        assert_eq!(item["confirmed"], json!(false));
    }
}

#[test]
fn the_metrics_template_keeps_defects_holds_and_inherited_items_apart() {
    let value: Value = serde_json::from_slice(&fixture_bytes("metrics.template.json"))
        .expect("the metrics template is JSON");
    assert_eq!(value["schema"], json!("h4-acceptance-metrics-v1"));
    assert_eq!(value["status"], json!("not_run"));
    assert_eq!(value["externalRequests"], json!(0));
    assert_eq!(value["realProvider"]["status"], json!("not_executed"));
    assert_eq!(value["realProvider"]["confirmed"], json!(false));

    let counts = value["counts"].as_object().expect("a counts object");
    assert_eq!(counts.len(), 3, "only the three defect counters live here");
    for key in ["wrongCompletion", "wrongCommit", "wrongDispatch"] {
        assert_eq!(
            counts[key],
            json!(0),
            "{key} stays a separate defect counter"
        );
    }
    let holds = value["holds"].as_object().expect("a holds object");
    assert_eq!(holds.len(), 2, "holds are their own object");
    assert_eq!(holds["pending"], json!(0));
    assert_eq!(holds["humanWait"], json!(0));

    let inherited = value["inheritedUnconfirmed"]
        .as_array()
        .expect("inherited array");
    assert_eq!(inherited.len(), INHERITED_UNCONFIRMED.len());
    for item in inherited {
        assert_eq!(item["status"], json!("unconfirmed"));
        assert_eq!(item["confirmed"], json!(false));
    }

    // The zero metrics produced by a gate-only run serialize to the same shape.
    let generated = AcceptanceMetrics::zero().to_json(false);
    assert_eq!(generated["counts"], value["counts"]);
    assert_eq!(generated["holds"], value["holds"]);
    assert_eq!(generated["realProvider"], value["realProvider"]);
}

#[test]
fn the_real_provider_column_is_stated_as_not_executed() {
    // This is deliberately a statement of the delivered evidence, not a test of
    // a provider. No transport in this target reaches the network.
    let mut metrics = AcceptanceMetrics::zero();
    let report = RunReport {
        sends: 0,
        retries: 0,
        metrics: metrics.clone(),
    };
    let value = report.metrics.to_json(false);
    assert_eq!(value["status"], json!("not_run"));
    assert_eq!(value["realProvider"]["status"], json!("not_executed"));
    assert_eq!(value["realProvider"]["confirmed"], json!(false));
    assert_eq!(value["externalRequests"], json!(0));
    metrics.hold(AcceptanceHold::HumanWait);
    let value = metrics.to_json(false);
    assert_eq!(value["holds"]["humanWait"], json!(1));
    assert_eq!(value["counts"]["wrongCompletion"], json!(0));
    eprintln!(
        "H4_ACCEPTANCE_REAL_PROVIDER: status=not_executed confirmed=false external_requests=0"
    );
}
