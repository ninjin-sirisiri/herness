//! Task 16 worker tests.
//!
//! The H1 runtime, Pi adapter, store, and candidate store are real. The only
//! provider is a loopback HTTP mock; credentials are fake and no external
//! network or real account is used. A scripted owner registry proves that an
//! empty registry cannot mint an owner authority and therefore cannot start a
//! run.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use herness_core::permissions::RuleTarget;
use herness_core::{
    AuthMethod, ConnectionAdmin, ConnectionId, ConnectionSettings, CoreError, CredentialKind,
    CredentialPort, Endpoint, MatchMethod, PermissionRule, ProjectId, Provider, ResolvedCredential,
    SecretString, Timestamp, ToolName,
};
use herness_desktop::host::DesktopHost;
use herness_desktop::html_sync::HtmlSyncWorker;
use herness_desktop::supervision::plan::load_plan;
use herness_desktop::supervision::{
    ConditionInput, ConfirmationKind, CreateSupervisionRequest, PlanRequestActor,
};
use herness_engine_pi::ProviderEndpoints;
use herness_html_sync::observer::{ChangeSource, DependencyKind, DependencyPath};
use herness_html_sync::{
    CandidateArtifactStore, DocumentKey, H3ApprovalLimits, H3Approver, H3ConfigurationApproval,
    H3ConfigurationDraft, H3ConnectionApproval, H3OwnerBinding, H3Settings, H3StorePort,
    H3VersionBinding, HtmlSyncCommit, ObservationEligibility, ObservationTrigger, SettingsCommit,
    SourceChange, SourceObservation, SourceRevision, SourceSnapshot,
    StoreBackedOwnerApprovalRegistry,
};
use herness_supervision::owner_launch::OwnerApprovalRegistryPort;
use herness_supervision::{
    BudgetPolicy, ConditionDigest, ConditionVersion, ConsentBinding, ConsentId, ContentDigest,
    DisclosureDataKind, DisclosureScope, OwnerApproval, OwnerApprovalSource, OwnerKind, OwnerRef,
    ProfileBinding, ProfileId, ProfilePurpose, ProfileVersion, ProviderOrigin, SupervisionError,
    SupervisionId, TargetVersion,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use uuid::Uuid;

const TARGET: &str = "docs/sdd/specs/worker-fixture.md";
const CSS: &str = "assets/shared.css";
const SOURCE: &str =
    "# Worker fixture\n\nExact worker source with a condition: only when approved.\n";
const CANDIDATE_HTML: &str =
    "<!doctype html><html><body><p>Exact worker source with a condition</p></body></html>";
const PROVENANCE: &str = "{\"formatVersion\":1,\"units\":[]}";
const STABLE_INSTRUCTION: &str = "Author the HTML companion for the approved Target Markdown. Read the exact immutable source, existing HTML, and shared CSS through candidate_read with the host-issued handle. Write only candidate_html and candidate_provenance with a concrete rationale. Do not write formal Markdown, HTML, CSS, settings, or receipts, and do not use shell.";

// ---------------------------------------------------------------------------
// Loopback mock.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    body: String,
}

struct MockResponse {
    status: u16,
    content_type: &'static str,
    body: String,
}

impl MockResponse {
    fn sse(body: String) -> Self {
        Self {
            status: 200,
            content_type: "text/event-stream",
            body,
        }
    }
}

struct MockServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    calls: Arc<AtomicUsize>,
}

impl MockServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(usize, &RecordedRequest) -> MockResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::clone(&requests);
        let counter = Arc::clone(&calls);
        let handler = Arc::new(handler);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let recorded = Arc::clone(&recorded);
                let counter = Arc::clone(&counter);
                let handler = Arc::clone(&handler);
                std::thread::spawn(move || {
                    let index = counter.fetch_add(1, Ordering::SeqCst);
                    let mut stream = stream;
                    if let Some(request) = read_request(&mut stream) {
                        let response = handler(index, &request);
                        recorded.lock().expect("requests").push(request);
                        write_response(stream, response);
                    }
                });
            }
        });
        Self {
            address,
            requests,
            calls,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn request_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("requests").clone()
    }
}

fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        if buffer.len() > 1024 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut content_length = 0usize;
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    let first = head.lines().next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    Some(RecordedRequest {
        method: parts.next().unwrap_or_default().to_owned(),
        path: parts.next().unwrap_or_default().to_owned(),
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn write_response(mut stream: TcpStream, response: MockResponse) {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(response.body.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

fn sse(event: &str, data: Value) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

fn responses_text(text: &str) -> MockResponse {
    let mut body = String::new();
    body.push_str(&sse(
        "response.created",
        json!({"type": "response.created", "response": {"id": "resp_1"}}),
    ));
    body.push_str(&sse(
        "response.output_item.added",
        json!({"type": "response.output_item.added", "output_index": 0, "item": {"type": "message", "id": "msg_1"}}),
    ));
    body.push_str(&sse(
        "response.output_text.delta",
        json!({"type": "response.output_text.delta", "output_index": 0, "delta": text}),
    ));
    body.push_str(&sse(
        "response.output_item.done",
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {"type": "message", "id": "msg_1", "content": [{"type": "output_text", "text": text}]}
        }),
    ));
    body.push_str(&sse(
        "response.completed",
        json!({
            "type": "response.completed",
            "response": {
                "id": "resp_1",
                "status": "completed",
                "output": [{"type": "message", "id": "msg_1", "content": [{"type": "output_text", "text": text}]}]
            }
        }),
    ));
    MockResponse::sse(body)
}

fn responses_tool_call(call_id: &str, name: &str, arguments: Value) -> MockResponse {
    let arguments = arguments.to_string();
    let item = |arguments: &str| {
        json!({
            "type": "function_call",
            "id": format!("fc_{call_id}"),
            "call_id": call_id,
            "name": name,
            "arguments": arguments
        })
    };
    let mut body = String::new();
    body.push_str(&sse(
        "response.created",
        json!({"type": "response.created", "response": {"id": "resp_tool"}}),
    ));
    body.push_str(&sse(
        "response.output_item.added",
        json!({"type": "response.output_item.added", "output_index": 0, "item": item("")}),
    ));
    body.push_str(&sse(
        "response.function_call_arguments.delta",
        json!({"type": "response.function_call_arguments.delta", "output_index": 0, "delta": arguments}),
    ));
    body.push_str(&sse(
        "response.output_item.done",
        json!({"type": "response.output_item.done", "output_index": 0, "item": item(&arguments)}),
    ));
    body.push_str(&sse(
        "response.completed",
        json!({
            "type": "response.completed",
            "response": {"id": "resp_tool", "status": "completed", "output": [item(&arguments)]}
        }),
    ));
    MockResponse::sse(body)
}

fn response_content_text(value: &Value) -> Vec<String> {
    let mut texts = Vec::new();
    let Some(input) = value.get("input").and_then(Value::as_array) else {
        return texts;
    };
    for item in input {
        match item.get("content") {
            Some(Value::String(text)) => texts.push(text.clone()),
            Some(Value::Array(parts)) => {
                for part in parts {
                    if let Some(text) = part.get("text").and_then(Value::as_str) {
                        texts.push(text.to_owned());
                    }
                }
            }
            _ => {}
        }
        if let Some(output) = item.get("output").and_then(Value::as_str) {
            texts.push(output.to_owned());
        }
    }
    texts
}

fn extract_handle(body: &str) -> Value {
    let value: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let text = response_content_text(&value).join("\n");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Candidate handle JSON: ") {
            if let Ok(handle) = serde_json::from_str(rest.trim()) {
                return handle;
            }
        }
    }
    Value::Null
}

fn model_response(index: usize, request: &RecordedRequest) -> MockResponse {
    let handle = extract_handle(&request.body);
    match index {
        0 => responses_tool_call(
            "call_forbidden",
            "candidate_write",
            json!({
                "handle": handle,
                "artifact": "source_markdown",
                "content": "forbidden formal source change",
                "rationale": "try a formal Markdown write"
            }),
        ),
        1 => responses_tool_call(
            "call_read",
            "candidate_read",
            json!({"handle": handle, "artifact": "source_markdown"}),
        ),
        2 => responses_tool_call(
            "call_html",
            "candidate_write",
            json!({
                "handle": handle,
                "artifact": "candidate_html",
                "content": CANDIDATE_HTML,
                "rationale": "author the candidate HTML from the exact source"
            }),
        ),
        3 => responses_tool_call(
            "call_prov",
            "candidate_write",
            json!({
                "handle": handle,
                "artifact": "candidate_provenance",
                "content": PROVENANCE,
                "rationale": "record the visible-source mapping"
            }),
        ),
        _ => responses_text("candidate authored"),
    }
}

// ---------------------------------------------------------------------------
// Fake credentials.
// ---------------------------------------------------------------------------

struct FakeCredentials {
    connection: ConnectionId,
    secret: String,
}

impl FakeCredentials {
    fn new(connection: ConnectionId, secret: &str) -> Self {
        Self {
            connection,
            secret: secret.to_owned(),
        }
    }
}

impl CredentialPort for FakeCredentials {
    fn availability(
        &self,
        connection: &ConnectionId,
    ) -> Result<herness_core::CredentialAvailability, CoreError> {
        if connection == &self.connection {
            Ok(herness_core::CredentialAvailability::Available)
        } else {
            Ok(herness_core::CredentialAvailability::Unavailable)
        }
    }

    fn resolve(&self, connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        if connection != &self.connection {
            return Err(CoreError::AuthenticationRequired {
                connection: *connection,
            });
        }
        Ok(ResolvedCredential::new(
            CredentialKind::ApiKey,
            SecretString::new(self.secret.clone())?,
        ))
    }
}

// ---------------------------------------------------------------------------
// Fixture.
// ---------------------------------------------------------------------------

struct Fixture {
    _temp: TempDir,
    project_root: PathBuf,
    project: ProjectId,
    document: DocumentKey,
    store: herness_desktop::supervision::store::StoreHandle,
    candidate_root: PathBuf,
    host: DesktopHost,
    supervision: SupervisionId,
    settings: H3Settings,
    server: MockServer,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().expect("temp");
        let project_root = temp.path().join("project");
        fs::create_dir_all(project_root.join("docs/sdd/specs")).expect("specs");
        fs::create_dir_all(project_root.join("assets")).expect("assets");
        fs::write(project_root.join(TARGET), SOURCE).expect("source");
        fs::write(project_root.join(CSS), "body { color: #111; }").expect("css");

        let server = MockServer::start(model_response);
        let endpoints =
            ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
                .expect("loopback endpoints");
        let connection = ConnectionId::new();
        let connections = ConnectionAdmin::new();
        connections
            .add(
                ConnectionSettings::new(
                    connection,
                    Provider::OpenAi,
                    "gpt-test",
                    AuthMethod::ApiKey,
                    None::<Endpoint>,
                    None,
                )
                .expect("settings"),
            )
            .expect("add connection");
        let credentials = Arc::new(FakeCredentials::new(connection, "sk-worker-canary"));
        let (mut host, _) = DesktopHost::open(
            temp.path().join("app-data"),
            connections,
            credentials,
            endpoints,
        )
        .expect("host");
        host.open_project(&project_root).expect("open project");
        {
            let policy = host.runtime_mut().policy_admin_mut();
            for tool in [
                ToolName::CandidateRead,
                ToolName::CandidateWrite,
                ToolName::CandidateEdit,
            ] {
                policy
                    .add_rule(
                        PermissionRule::allow(
                            RuleTarget::Tool { tool },
                            MatchMethod::AnyInvocation,
                        )
                        .expect("candidate allow rule"),
                    )
                    .expect("add candidate rule");
            }
        }
        let project = host
            .runtime()
            .projects()
            .expect("projects")
            .into_iter()
            .next()
            .expect("project")
            .project_id();
        let document = DocumentKey::new(project, TARGET).expect("document");

        host.supervision_configure_profile(
            PlanRequestActor::Human,
            project,
            ProfilePurpose::Completion,
            connection,
            "gpt-test",
            Some(host.confirm_supervision(ConfirmationKind::Profile)),
        )
        .expect("profile");
        host.supervision_grant_consent(
            PlanRequestActor::Human,
            project,
            ProfilePurpose::Completion,
            ProviderOrigin::parse("https://api.openai.com").expect("origin"),
            BTreeSet::from([DisclosureDataKind::Text]),
            vec![TARGET.to_owned()],
            TargetVersion::new(1).expect("target version"),
            Some(host.confirm_supervision(ConfirmationKind::Consent)),
        )
        .expect("consent");
        let owner = OwnerRef::new(OwnerKind::H3HtmlJob, "h3-worker-job").expect("owner");
        let created = host
            .supervision_create(
                PlanRequestActor::ApprovedOwner {
                    owner: owner.clone(),
                    source: OwnerApprovalSource::H3ApprovedSettings,
                },
                CreateSupervisionRequest {
                    project,
                    connection,
                    instructions: STABLE_INSTRUCTION.to_owned(),
                    conditions: vec![ConditionInput {
                        title: "The HTML companion preserves the approved content".to_owned(),
                        rubric: "All source units, conditions, and exceptions are visible and \
                                 supported by the provenance mapping."
                            .to_owned(),
                        checks: Vec::new(),
                    }],
                    read_set: vec![TARGET.to_owned()],
                    write_paths: Vec::new(),
                    allow_shell: false,
                    condition_version: Some(1),
                    target_version: Some(1),
                    budget: None,
                },
                None,
            )
            .expect("create H3 target");

        let mut store = host.store_handle();
        let plan = load_plan(&store, project, created.supervision_id)
            .expect("plan")
            .expect("stored plan");
        let settings = approved_settings(&plan, project, connection, owner);
        store
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_settings(SettingsCommit::new(None, settings.clone()).expect("commit")),
            )
            .expect("settings commit");

        let candidate_root = temp.path().join("app-data/html-sync/candidates");
        Self {
            _temp: temp,
            project_root,
            project,
            document,
            store,
            candidate_root,
            host,
            supervision: created.supervision_id,
            settings,
            server,
        }
    }

    fn candidate_store(&self) -> CandidateArtifactStore {
        CandidateArtifactStore::new(&self.candidate_root).expect("candidate store")
    }

    fn worker(&self) -> HtmlSyncWorker {
        let mut worker = HtmlSyncWorker::new(self.store.clone(), self.candidate_store());
        worker
            .bind_project(
                self.project,
                &self.project_root,
                self.settings.clone(),
                self.supervision,
                vec![DependencyPath::new(CSS, DependencyKind::Css).expect("css")],
            )
            .expect("bind project");
        worker
    }

    fn observation(&self) -> SourceObservation {
        SourceObservation {
            document: self.document.clone(),
            snapshot: SourceSnapshot::new(
                SourceRevision::new(1).expect("revision"),
                ContentDigest::sha256(SOURCE.as_bytes()),
            ),
            change: SourceChange::Initial,
            trigger: ObservationTrigger::InitialScan,
            observed_via: vec![ChangeSource::FilesystemWatcher],
            eligibility: ObservationEligibility::approved(1).expect("eligibility"),
        }
    }
}

fn profile(project: ProjectId, purpose: ProfilePurpose) -> ProfileBinding {
    ProfileBinding::new(
        ProfileId::from_parts(
            project,
            Uuid::parse_str("20000000-0000-4000-8000-00000000000b").expect("uuid"),
        ),
        ProfileVersion::new(1).expect("profile version"),
        purpose,
    )
}

fn consent(project: ProjectId, purpose: ProfilePurpose) -> ConsentBinding {
    ConsentBinding::new(
        ConsentId::from_parts(
            project,
            Uuid::parse_str("20000000-0000-4000-8000-00000000000a").expect("uuid"),
        ),
        1,
        purpose,
        TargetVersion::new(1).expect("target"),
    )
}

fn approved_settings(
    plan: &herness_desktop::supervision::plan::StoredPlan,
    project: ProjectId,
    connection: ConnectionId,
    owner: OwnerRef,
) -> H3Settings {
    let origin = ProviderOrigin::parse("https://api.openai.com").expect("origin");
    let authoring = H3ConnectionApproval::new(
        project,
        connection,
        origin.clone(),
        DisclosureScope::new(
            ProfilePurpose::Completion,
            BTreeSet::from([DisclosureDataKind::Text]),
            vec![TARGET.to_owned()],
            TargetVersion::new(1).expect("target"),
        )
        .expect("disclosure"),
        plan.profile.binding(),
        plan.consent.binding(),
    )
    .expect("authoring connection");
    let assessment = H3ConnectionApproval::new(
        project,
        connection,
        origin,
        DisclosureScope::new(
            ProfilePurpose::Html,
            BTreeSet::from([DisclosureDataKind::Text]),
            vec![TARGET.to_owned()],
            TargetVersion::new(1).expect("target"),
        )
        .expect("disclosure"),
        profile(project, ProfilePurpose::Html),
        consent(project, ProfilePurpose::Html),
    )
    .expect("assessment connection");
    let binding = H3OwnerBinding::new(
        project,
        owner,
        "h3-worker-job",
        plan.conditions.condition_version(),
        plan.conditions.digest().clone(),
        plan.execution_scope.clone(),
        plan.budget_version,
        plan.budget.policy().expect("budget"),
    )
    .expect("owner binding");
    let approval = H3ConfigurationApproval::approve(
        H3ConfigurationDraft {
            project_id: project,
            settings_version: 1,
            approval_id: "approval-worker".to_owned(),
            expires_at: None,
            targets: vec![TARGET.to_owned()],
            authoring,
            assessment,
            versions: H3VersionBinding::new(
                "sdd-herness-integration",
                1,
                1,
                "sdd-html-policy-v1",
                ContentDigest::sha256(b"worker-policy"),
                1,
                ContentDigest::sha256(b"worker-pack"),
                "sdd-html-host-api",
                1,
            )
            .expect("versions"),
            limits: H3ApprovalLimits::default(),
            auto_publish: false,
            retain_history: true,
            automatic_companion: true,
            owner: binding,
        },
        H3Approver::Human,
        Timestamp::now(),
    )
    .expect("approval");
    H3Settings::approved(approval, true).expect("settings")
}

struct EmptyRegistry;

impl OwnerApprovalRegistryPort for EmptyRegistry {
    fn current_owner_approval(
        &self,
        _project_id: ProjectId,
        _owner: &OwnerRef,
        _now: Timestamp,
    ) -> Result<Option<OwnerApproval>, SupervisionError> {
        Ok(None)
    }
}

#[test]
fn real_pi_candidate_run_authors_one_candidate_and_rejects_forbidden_changes() {
    let mut fixture = Fixture::new();
    let mut worker = fixture.worker();
    assert_eq!(
        worker.observe(&fixture.observation()),
        herness_html_sync::OfferOutcome::Queued
    );

    let registry_store = fixture.store.clone();
    let registry = StoreBackedOwnerApprovalRegistry::new(&registry_store);
    let started = {
        let (runtime, supervision) = fixture.host.runtime_and_supervision_mut();
        worker
            .pump(runtime, supervision, &registry)
            .expect("first pump")
    };
    assert!(
        started.started.is_some(),
        "the owner start must begin one run"
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut intake = None;
    while Instant::now() < deadline {
        let (runtime, supervision) = fixture.host.runtime_and_supervision_mut();
        let tick = worker.pump(runtime, supervision, &registry).expect("pump");
        if let Some(candidate) = tick.candidate {
            intake = Some(candidate);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let intake = intake.expect("candidate intake");

    assert!(
        !fixture.project_root.join("formal.html").exists(),
        "a candidate run must not write a formal file"
    );
    assert_eq!(
        fs::read_to_string(fixture.project_root.join(TARGET)).expect("source"),
        SOURCE,
        "the forbidden source_markdown candidate write must not change the formal source"
    );
    assert_eq!(
        fs::read_to_string(fixture.project_root.join(CSS)).expect("css"),
        "body { color: #111; }",
        "the candidate run must not change shared CSS"
    );
    let document = fixture
        .store
        .load_html_sync_document(fixture.project, &fixture.document)
        .expect("load document")
        .expect("document");
    assert_eq!(
        document.state().state(),
        herness_html_sync::H3State::Verifying
    );

    let candidate = fixture
        .store
        .load_html_sync_candidate(fixture.project, intake.candidate)
        .expect("load candidate")
        .expect("candidate");
    assert_eq!(
        candidate.html_digest(),
        &ContentDigest::sha256(CANDIDATE_HTML.as_bytes())
    );
    assert_eq!(
        candidate.provenance_digest(),
        &ContentDigest::sha256(PROVENANCE.as_bytes())
    );
    assert!(candidate.h1_run().is_some());

    let requests = fixture.server.requests();
    assert!(
        requests.len() >= 5,
        "expected the forbidden write, read, two writes, and a final turn; got {}",
        requests.len()
    );
    assert!(
        requests
            .iter()
            .all(|request| request.method == "POST" && request.path == "/v1/responses")
    );
    let first: Value = serde_json::from_str(&requests[0].body).expect("first request json");
    let tools = first["tools"]
        .as_array()
        .expect("tool declarations")
        .iter()
        .filter_map(|tool| {
            tool["name"]
                .as_str()
                .or_else(|| tool["function"]["name"].as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        tools,
        vec!["candidate_read", "candidate_write", "candidate_edit"]
    );
    let all_text = requests
        .iter()
        .filter_map(|request| serde_json::from_str::<Value>(&request.body).ok())
        .flat_map(|value| response_content_text(&value))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(all_text.contains("Immutable authoring snapshot"));
    assert!(all_text.contains("sdd-html-policy-v1"));
    assert!(
        all_text.contains("Exact worker source with a condition: only when approved."),
        "candidate_read must return the exact source"
    );
    assert!(
        all_text.contains("Candidate handle JSON:"),
        "the run input must carry the host-issued candidate handle"
    );
    assert!(
        !fixture.project_root.join("formal.html").exists(),
        "the forbidden write stays absent"
    );

    // The raw token is in the run input, but the H3 candidate manifest persists
    // only its digest.
    let manifest_path = fixture
        .candidate_root
        .join(candidate.storage().namespace())
        .join("manifest.json");
    let manifest = fs::read_to_string(manifest_path).expect("manifest");
    let handle = extract_handle(&requests[1].body);
    let token = handle["token"].as_str().expect("token");
    assert!(!manifest.contains(token));
    assert_eq!(
        candidate.storage().token_digest(),
        &ContentDigest::sha256(token.as_bytes())
    );
}

#[test]
fn an_empty_owner_registry_cannot_mint_authority_or_start_a_run() {
    let mut fixture = Fixture::new();
    let mut worker = fixture.worker();
    worker.observe(&fixture.observation());
    let registry = EmptyRegistry;
    let (runtime, supervision) = fixture.host.runtime_and_supervision_mut();
    let tick = worker.pump(runtime, supervision, &registry).expect("pump");
    assert!(tick.started.is_none());
    assert_eq!(fixture.server.request_count(), 0);
    assert!(!fixture.project_root.join("formal.html").exists());
    let document = fixture
        .store
        .load_html_sync_document(fixture.project, &fixture.document)
        .expect("load document")
        .expect("document");
    assert_eq!(document.state().state(), herness_html_sync::H3State::Failed);
}

#[test]
fn constants_keep_app_wide_authoring_and_document_publication_at_one() {
    assert_eq!(herness_html_sync::APP_WIDE_AUTHORING_CONCURRENCY, 1);
    assert_eq!(herness_html_sync::DOCUMENT_PUBLICATION_CONCURRENCY, 1);
}

// Keep the imports used by the fixture explicit; these are the exact production
// construction values, not a second test-only type.
const _: Option<(BudgetPolicy, ConditionDigest, ConditionVersion)> = None;
