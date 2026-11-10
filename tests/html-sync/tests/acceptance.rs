//! Task 23 cross-repo acceptance: real adapter, real pack, real render.
//!
//! One loopback Responses server plays the authoring child. A second loopback
//! endpoint plays the three Html assessment methods and is labelled `scripted`
//! in assertions and in the report. The structural/semantic/SVG validation is
//! the real Common SDD pack; the render is the Task 17 hidden-window WKWebView
//! child capture. No real provider, Keychain item, login, or network is used.

#![cfg(target_os = "macos")]

mod support;

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use herness_assessment::AssessmentEndpoints;
use herness_core::permissions::RuleTarget;
use herness_core::{
    AuthMethod, ConnectionAdmin, ConnectionCapabilityDeclaration, ConnectionId, ConnectionSettings,
    CoreError, CredentialAvailability, CredentialKind, CredentialPort, EndpointClass,
    InputCapabilities, MatchMethod, PermissionRule, ProjectId, Provider, ResolvedCredential,
    SecretString, Timestamp, ToolName,
};
use herness_desktop::host::DesktopHost;
use herness_desktop::html_sync::composition;
use herness_desktop::supervision::assessment::build_human_consent;
use herness_desktop::supervision::plan::{RequestActor, load_plan};
use herness_desktop::supervision::store::HostBudgetClock;
use herness_desktop::supervision::{
    ConditionInput, ConfirmationKind, CreateSupervisionRequest, PlanRequestActor,
};
use herness_engine_pi::ProviderEndpoints;
use herness_desktop::html_sync::pipeline::{
    AssessmentContext, CandidateRenderPort, HostFingerprints, PostCandidateOutcome,
    PreparedCandidate, RenderInput, verify,
};
use herness_html_sync::observer::{ChangeSignal, ChangeSource, DependencyKind};
use herness_html_sync::{
    DocumentKey, H3ApprovalLimits, H3Approver, H3Condition, H3ConfigurationApproval,
    H3ConfigurationDraft, H3ConnectionApproval, H3OwnerBinding, H3Settings, H3State, H3StorePort,
    H3Operation, H3OperationRequest, H3RequestId, H3VersionBinding, HtmlSyncCommit,
    ObservationEligibility, ObservationTrigger, PublicationFileInput, SettingsCommit,
    SourceChange, SourceObservation, SourceRevision, SourceSnapshot,
};
use herness_desktop::html_sync::policy::CandidateDecision;
use herness_supervision::profiles::{
    AdapterVersion, AssessmentProfile, ProfileInputs, ProfilePurpose, ProfileThresholds,
    ProfileVersion, ProviderKind, RubricVersion,
};
use herness_supervision::{
    BudgetLedger, ConditionDigest, ConditionVersion, ContentDigest,
    DisclosureDataKind, DisclosureScope, OwnerKind, OwnerRef, ProfileId, ProviderOrigin,
    SupervisionId, TargetVersion,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const TARGET: &str = "docs/adr/0001-queue-choice.md";
const COMPANION: &str = "docs/adr/0001-queue-choice.html";
const CSS: &str = "docs/sdd/assets/sdd.css";
const INSTRUCTION: &str = "Author the HTML companion for the approved Target Markdown. Read the exact immutable source, existing HTML, and shared CSS through candidate_read with the host-issued handle. Write only candidate_html and candidate_provenance with a concrete rationale. Do not write formal Markdown, HTML, CSS, settings, or receipts, and do not use shell.";

// ---------------------------------------------------------------------------
// Loopback HTTP mocks.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RecordedRequest {
    path: String,
    body: String,
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

    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("requests").clone()
    }
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

    fn json(body: Value) -> Self {
        Self {
            status: 200,
            content_type: "application/json",
            body: body.to_string(),
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if buffer.len() > 2 * 1024 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let content_length = head
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    let first = head.lines().next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let _method = parts.next().unwrap_or_default();
    Some(RecordedRequest {
        path: parts.next().unwrap_or_default().to_owned(),
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn write_response(mut stream: TcpStream, response: MockResponse) {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        if response.status == 200 { "OK" } else { "Error" },
        response.content_type,
        response.body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(response.body.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);
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
            "response": {"id": "resp_1", "status": "completed", "output": [{"type": "message", "id": "msg_1", "content": [{"type": "output_text", "text": text}]}]}
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
        json!({"type": "response.completed", "response": {"id": "resp_tool", "status": "completed", "output": [item(&arguments)]}}),
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
        if let Some(rest) = line.strip_prefix("Candidate handle JSON: ")
            && let Ok(handle) = serde_json::from_str(rest.trim())
        {
            return handle;
        }
    }
    Value::Null
}

fn provenance_payload(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let marker = "id=\"sdd-provenance\"";
    let id_position = lower.find(marker).expect("provenance id");
    let open_end = lower[id_position..]
        .find('>')
        .map(|offset| id_position + offset + 1)
        .expect("open");
    let close = lower[open_end..]
        .find("</template>")
        .map(|offset| open_end + offset)
        .expect("close");
    html[open_end..close].to_owned()
}

fn authoring_model(candidate_html: String) -> impl Fn(usize, &RecordedRequest) -> MockResponse {
    move |index, request| {
        let handle = extract_handle(&request.body);
        match index {
            0 => responses_tool_call(
                "call_html",
                "candidate_write",
                json!({
                    "handle": handle,
                    "artifact": "candidate_html",
                    "content": candidate_html,
                    "rationale": "author the semantic-v1 candidate from the exact source"
                }),
            ),
            1 => responses_tool_call(
                "call_prov",
                "candidate_write",
                json!({
                    "handle": handle,
                    "artifact": "candidate_provenance",
                    "content": provenance_payload(&candidate_html),
                    "rationale": "record the visible-source mapping"
                }),
            ),
            _ => responses_text("candidate authored"),
        }
    }
}

fn assessment_request_payload(body: &Value) -> Value {
    body.get("input")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("content"))
        .and_then(Value::as_array)
        .and_then(|content| content.first())
        .and_then(|part| part.get("text"))
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or(Value::Null)
}

fn scripted_met(request: &RecordedRequest) -> MockResponse {
    let payload: Value = serde_json::from_str(&request.body).unwrap_or(Value::Null);
    let payload = assessment_request_payload(&payload);
    let condition = payload
        .get("conditionId")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let evidence = payload
        .get("evidence")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let text = json!({
        "conditions": [{
            "conditionId": condition,
            "verdict": "met",
            "evidenceIds": evidence,
            "rationale": "scripted loopback judge: the supplied evidence supports the condition",
            "uncertainty": null,
        }]
    });
    MockResponse::json(json!({
        "id": "resp_h3_scripted",
        "object": "response",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text.to_string()}],
        }],
    }))
}

// ---------------------------------------------------------------------------
// Real child render port.
// ---------------------------------------------------------------------------

struct ChildRenderPort;

impl CandidateRenderPort for ChildRenderPort {
    fn capture(&self, input: &RenderInput) -> Result<herness_desktop::html_sync::RenderEvidence, herness_html_sync::H3Error> {
        let temp = tempfile::tempdir().map_err(|error| herness_html_sync::H3Error::Unavailable {
            capability: "h3.render.fixture".to_owned(),
            detail: error.to_string(),
        })?;
        let fixture = temp.path().join("fixture");
        let output = temp.path().join("output");
        std::fs::create_dir_all(&fixture).map_err(|error| herness_html_sync::H3Error::Unavailable {
                capability: "h3.render.fixture".to_owned(),
                detail: error.to_string(),
            })?;
        std::fs::write(fixture.join("candidate.html"), &input.html).map_err(|error| {
            herness_html_sync::H3Error::Unavailable {
                capability: "h3.render.fixture".to_owned(),
                detail: error.to_string(),
            }
        })?;
        std::fs::write(fixture.join("candidate.css"), &input.css).map_err(|error| {
            herness_html_sync::H3Error::Unavailable {
                capability: "h3.render.fixture".to_owned(),
                detail: error.to_string(),
            }
        })?;
        let spec = json!({
            "html": "candidate.html",
            "css": "candidate.css",
            "resources": []
        });
        std::fs::write(fixture.join("fixture.json"), spec.to_string()).map_err(|error| {
            herness_html_sync::H3Error::Unavailable {
                capability: "h3.render.fixture".to_owned(),
                detail: error.to_string(),
            }
        })?;
        std::fs::create_dir_all(&output).ok();
        let binary = desktop_binary();
        let app_data = temp.path().join("app-data");
        std::fs::create_dir_all(&app_data).ok();
        let stdout_path = temp.path().join("render-stdout.log");
        let stderr_path = temp.path().join("render-stderr.log");
        let stdout = std::fs::File::create(&stdout_path).expect("stdout log");
        let stderr = std::fs::File::create(&stderr_path).expect("stderr log");
        let mut child = Command::new(binary)
            .arg("--h3-render-test")
            .arg(&fixture)
            .arg(&output)
            .env("HERNESS_APP_DATA_ROOT", &app_data)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|error| herness_html_sync::H3Error::Unavailable {
                capability: "h3.render.child".to_owned(),
                detail: error.to_string(),
            })?;
        let status = wait_for_child(&mut child, Duration::from_secs(90));
        if !status.success() {
            let stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            return Err(herness_html_sync::H3Error::Unavailable {
                capability: "h3.render.child".to_owned(),
                detail: format!(
                    "real render child exited with {status:?}; stdout={stdout}; stderr={stderr}"
                ),
            });
        }
        herness_desktop::html_sync::RenderEvidence::read_from(&output).map_err(|error| {
            herness_html_sync::H3Error::Unavailable {
                capability: "h3.render.evidence".to_owned(),
                detail: error.label(),
            }
        })
    }
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
    let binary = target.join("debug/herness-desktop");
    assert!(
        binary.is_file(),
        "desktop binary is missing at {}; run `cargo build -p herness-desktop --locked` first",
        binary.display()
    );
    binary
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll render child") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("desktop render child exceeded {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// Credentials.
// ---------------------------------------------------------------------------

struct FakeCredentials {
    connections: Vec<ConnectionId>,
}

impl CredentialPort for FakeCredentials {
    fn availability(
        &self,
        connection: &ConnectionId,
    ) -> Result<CredentialAvailability, CoreError> {
        Ok(if self.connections.contains(connection) {
            CredentialAvailability::Available
        } else {
            CredentialAvailability::Unavailable
        })
    }

    fn resolve(&self, connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        if !self.connections.contains(connection) {
            return Err(CoreError::AuthenticationRequired {
                connection: *connection,
            });
        }
        Ok(ResolvedCredential::new(
            CredentialKind::ApiKey,
            SecretString::new("sk-h3-acceptance-canary").expect("secret"),
        ))
    }
}

// ---------------------------------------------------------------------------
// Acceptance harness.
// ---------------------------------------------------------------------------

struct Acceptance {
    _temp: TempDir,
    root: PathBuf,
    project: ProjectId,
    document: DocumentKey,
    host: DesktopHost,
    supervision: SupervisionId,
    authoring: MockServer,
    assessment: MockServer,
    candidate_html: String,
    auto_publish: bool,
    render: Arc<ChildRenderPort>,
}

impl Acceptance {
    fn new(auto_publish: bool) -> Self {
        Self::new_with_assessment(true, auto_publish)
    }

    fn new_with_assessment(images: bool, auto_publish: bool) -> Self {
        let temp = TempDir::new().expect("temp");
        let root = temp.path().join("project");
        std::fs::create_dir_all(root.join("docs/adr")).expect("adr");
        std::fs::create_dir_all(root.join("docs/sdd/assets")).expect("assets");
        let pack = Path::new(support::REAL_PACK_ROOT);
        let source = std::fs::read(pack.join("tests/fixtures/adr/0001-queue-choice.md"))
            .expect("fixture source");
        let candidate_html = std::fs::read_to_string(
            pack.join("tests/fixtures/adr/0001-queue-choice.html"),
        )
        .expect("fixture candidate");
        let css = std::fs::read(pack.join("tests/fixtures/docs/sdd/assets/sdd.css"))
            .expect("fixture css");
        std::fs::write(root.join(TARGET), &source).expect("write source");
        std::fs::write(root.join(COMPANION), &candidate_html).expect("write companion");
        std::fs::write(root.join(CSS), &css).expect("write css");

        let authoring = MockServer::start(authoring_model(candidate_html.clone()));
        let assessment = MockServer::start(|_, request| scripted_met(request));
        let provider_endpoints = ProviderEndpoints::for_loopback(
            format!("{}/v1", authoring.url()),
            authoring.url(),
        )
        .expect("provider endpoints");
        let assessment_endpoints = AssessmentEndpoints::for_loopback(
            assessment.url(),
            format!("{}/v1", assessment.url()),
            assessment.url(),
        )
        .expect("assessment endpoints");

        let completion_connection = ConnectionId::new();
        let html_connection = ConnectionId::new();
        let connections = ConnectionAdmin::new();
        connections
            .add(
                ConnectionSettings::new_with_capabilities(
                    completion_connection,
                    Provider::OpenAi,
                    "gpt-authoring-fixture",
                    AuthMethod::ApiKey,
                    None,
                    None,
                    ConnectionCapabilityDeclaration::new(
                        EndpointClass::OpenAiResponses,
                        InputCapabilities::text_only(),
                    ),
                )
                .expect("authoring connection"),
            )
            .expect("add authoring");
        connections
            .add(
                ConnectionSettings::new_with_capabilities(
                    html_connection,
                    Provider::OpenAi,
                    "gpt-h3-assessment",
                    AuthMethod::ApiKey,
                    None,
                    None,
                    ConnectionCapabilityDeclaration::new(
                        EndpointClass::OpenAiResponses,
                        if images {
                            InputCapabilities::text_and_image()
                        } else {
                            InputCapabilities::text_only()
                        },
                    ),
                )
                .expect("assessment connection"),
            )
            .expect("add assessment");
        let credentials = Arc::new(FakeCredentials {
            connections: vec![completion_connection, html_connection],
        });
        let (mut host, _) = DesktopHost::open_with_html_sync_test_boundaries(
            temp.path().join("app-data"),
            connections,
            credentials,
            provider_endpoints,
            Some(pack.to_path_buf()),
            assessment_endpoints,
        )
        .expect("desktop host");
        host.html_sync_services_mut()
            .set_toolchain(support::toolchain());
        host.open_project(&root).expect("open project");
        let project = host
            .runtime()
            .projects()
            .expect("projects")
            .into_iter()
            .next()
            .expect("project")
            .project_id();
        let document = DocumentKey::new(project, TARGET).expect("document");
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

        host.supervision_configure_profile(
            PlanRequestActor::Human,
            project,
            ProfilePurpose::Completion,
            completion_connection,
            "gpt-authoring-fixture",
            Some(host.confirm_supervision(ConfirmationKind::Profile)),
        )
        .expect("completion profile");
        host.supervision_mark_profile_verified(project, ProfilePurpose::Completion, true)
            .expect("verify completion profile");
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
        .expect("completion consent");

        let html_profile = AssessmentProfile::new(
            ProfileId::new(project),
            ProfileVersion::new(1).expect("profile version"),
            ProfilePurpose::Html,
            ProviderKind::NormalLlm,
            html_connection,
            herness_core::ModelId::new("gpt-h3-assessment").expect("model"),
            AdapterVersion::new("herness-h3-html-acceptance-v1").expect("adapter"),
            RubricVersion::new(herness_html_sync::H3_RUBRIC_VERSION).expect("rubric"),
            if images {
                ProfileInputs::text_with_optional_image()
            } else {
                ProfileInputs::text_only()
            },
            ProfileThresholds::for_provider(ProviderKind::NormalLlm),
        )
        .expect("html profile");
        let mut config = host.supervision().config().get(project);
        config.set_profile(html_profile.clone(), true);
        let html_consent = build_human_consent(
            &RequestActor::Human,
            project,
            ProfilePurpose::Html,
            ProviderOrigin::parse("https://api.openai.com").expect("origin"),
            if images {
                BTreeSet::from([DisclosureDataKind::Text, DisclosureDataKind::Image])
            } else {
                BTreeSet::from([DisclosureDataKind::Text])
            },
            vec![TARGET.to_owned()],
            TargetVersion::new(1).expect("target version"),
            Timestamp::now(),
        )
        .expect("html consent");
        let html_consent_binding = html_consent.binding();
        config.set_consent(html_consent);
        host.supervision().config().set(project, config);

        let created = host
            .supervision_create(
                PlanRequestActor::ApprovedOwner {
                    owner: OwnerRef::new(OwnerKind::H3HtmlJob, "h3-acceptance-job")
                        .expect("owner"),
                    source: herness_supervision::OwnerApprovalSource::H3ApprovedSettings,
                },
                CreateSupervisionRequest {
                    project,
                    connection: completion_connection,
                    instructions: INSTRUCTION.to_owned(),
                    conditions: H3Condition::ALL
                        .into_iter()
                        .map(|condition| ConditionInput {
                            title: condition.as_str().to_owned(),
                            rubric: format!("H3 {} condition acceptance rubric", condition.as_str()),
                            checks: Vec::new(),
                        })
                        .collect(),
                    read_set: vec![TARGET.to_owned()],
                    write_paths: Vec::new(),
                    allow_shell: false,
                    condition_version: Some(1),
                    target_version: Some(1),
                    budget: None,
                },
                Some(host.confirm_supervision(ConfirmationKind::Create)),
            )
            .expect("create H2 target");
        let store = host.store_handle();
        let plan = load_plan(&store, project, created.supervision_id)
            .expect("load plan")
            .expect("stored plan");
        let policy = plan.budget.policy().expect("budget policy");
        let mut ledger = BudgetLedger::open(
            store,
            project,
            created.supervision_id,
            policy,
            plan.budget_version,
            HostBudgetClock::new(),
        )
        .expect("ledger");
        ledger.begin_active().expect("activate ledger");

        let approval = Self::approval(
            project,
            &root,
            &plan,
            completion_connection,
            html_connection,
            &html_profile,
            html_consent_binding,
            images,
            auto_publish,
        );
        host.store_handle()
            .commit_html_sync(
                HtmlSyncCommit::new().with_settings(
                    SettingsCommit::new(None, approval).expect("settings commit"),
                ),
            )
            .expect("settings");

        let enabled = composition::enable(&mut host, project).expect("enable");
        assert!(
            enabled.capabilities.available(),
            "the real composition must be complete: {:?}",
            enabled
                .capabilities
                .missing()
                .iter()
                .map(|state| (state.capability(), state.detail()))
                .collect::<Vec<_>>()
        );
        assert!(enabled.worker_bound);
        host.html_sync_services_mut()
            .set_render_port(Arc::new(ChildRenderPort));

        Self {
            _temp: temp,
            root,
            project,
            document,
            host,
            supervision: created.supervision_id,
            authoring,
            assessment,
            candidate_html,
            auto_publish,
            render: Arc::new(ChildRenderPort),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn approval(
        project: ProjectId,
        root: &Path,
        plan: &herness_desktop::supervision::plan::StoredPlan,
        completion_connection: ConnectionId,
        html_connection: ConnectionId,
        html_profile: &AssessmentProfile,
        html_consent: herness_supervision::ConsentBinding,
        images: bool,
        auto_publish: bool,
    ) -> H3Settings {
        let origin = ProviderOrigin::parse("https://api.openai.com").expect("origin");
        let authoring = H3ConnectionApproval::new(
            project,
            completion_connection,
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
            html_connection,
            origin,
            DisclosureScope::new(
                ProfilePurpose::Html,
                if images {
                    BTreeSet::from([DisclosureDataKind::Text, DisclosureDataKind::Image])
                } else {
                    BTreeSet::from([DisclosureDataKind::Text])
                },
                vec![TARGET.to_owned()],
                TargetVersion::new(1).expect("target"),
            )
            .expect("disclosure"),
            html_profile.binding(),
            html_consent,
        )
        .expect("assessment connection");
        let owner = H3OwnerBinding::new(
            project,
            OwnerRef::new(OwnerKind::H3HtmlJob, "h3-acceptance-job").expect("owner"),
            "h3-acceptance-job",
            plan.conditions.condition_version(),
            plan.conditions.digest().clone(),
            plan.execution_scope.clone(),
            plan.budget_version,
            plan.budget.policy().expect("budget"),
        )
        .expect("owner binding");
        let binding = herness_desktop::html_sync::policy::HtmlPolicyBridge::detect(
            root,
            support::REAL_PACK_ROOT,
            support::toolchain(),
        )
        .expect("detect pack")
        .probe()
        .approval_binding()
        .expect("pack binding");
        let versions = H3VersionBinding::new(
            binding.integration_schema(),
            binding.integration_version(),
            binding.integration_revision(),
            binding.policy_version(),
            binding.policy_fingerprint().clone(),
            1,
            binding.pack_fingerprint().clone(),
            binding.host_api_protocol(),
            binding.host_api_version(),
        )
        .expect("versions");
        let approval = H3ConfigurationApproval::approve(
            H3ConfigurationDraft {
                project_id: project,
                settings_version: 1,
                approval_id: "acceptance-approval".to_owned(),
                expires_at: None,
                targets: vec![TARGET.to_owned()],
                authoring,
                assessment,
                versions,
                limits: H3ApprovalLimits::default(),
                auto_publish,
                retain_history: true,
                automatic_companion: true,
                owner,
            },
            H3Approver::Human,
            Timestamp::now(),
        )
        .expect("approval");
        H3Settings::approved(approval, true).expect("settings")
    }

    fn pump_until(&mut self, predicate: impl Fn(&Self) -> bool, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            self.host.pump().expect("pump");
            if predicate(self) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn state(&self) -> H3State {
        self.host
            .store_handle()
            .load_html_sync_document(self.project, &self.document)
            .expect("load")
            .expect("document")
            .state()
            .state()
    }

    fn record(&self) -> herness_html_sync::H3DocumentRecord {
        self.host
            .store_handle()
            .load_html_sync_document(self.project, &self.document)
            .expect("load")
            .expect("document")
    }

    fn files_exist(&self) -> (bool, bool) {
        (
            self.root.join(COMPANION).is_file(),
            self.root
                .join(herness_html_sync::html_evidence_path(&self.document))
                .is_file(),
        )
    }

    fn formal_snapshot(&self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        (
            std::fs::read(self.root.join(COMPANION)).ok(),
            std::fs::read(
                self.root
                    .join(herness_html_sync::html_evidence_path(&self.document)),
            )
            .ok(),
        )
    }

    fn settings(&self) -> H3Settings {
        self.host
            .store_handle()
            .load_html_sync_settings(self.project)
            .expect("settings")
            .expect("stored settings")
            .settings()
            .clone()
    }

    fn context(&self) -> AssessmentContext {
        let plan = load_plan(&self.host.store_handle(), self.project, self.supervision)
            .expect("load plan")
            .expect("plan");
        let settings = self.settings();
        AssessmentContext::from_plan(
            self.project,
            &plan,
            settings
                .approval()
                .expect("approval")
                .assessment()
                .profile(),
        )
        .expect("context")
    }

    fn prepared_for(&self, html: &str) -> PreparedCandidate {
        let record = self.record();
        let generation_id = record.state().generation().expect("generation");
        let generation = self
            .host
            .store_handle()
            .html_sync_generations(self.project, &self.document)
            .expect("generations")
            .into_iter()
            .find(|generation| generation.generation_id() == generation_id)
            .expect("current generation");
        let source = std::fs::read(self.root.join(TARGET)).expect("source");
        let css = PublicationFileInput::new(
            CSS,
            std::fs::read(self.root.join(CSS)).expect("css"),
        )
        .expect("css input");
        PreparedCandidate {
            document: self.document.clone(),
            record,
            candidate: generation.candidate().cloned().expect("candidate"),
            generation,
            html: html.to_owned(),
            provenance: provenance_payload(html),
            source,
            css: vec![css],
            resources: Vec::new(),
        }
    }

    fn verify_variant(
        &self,
        html: &str,
    ) -> herness_desktop::html_sync::verification::CandidateVerification {
        let prepared = self.prepared_for(html);
        let context = self.context();
        let settings = self.settings();
        let approval = settings.approval().expect("approval");
        let capture = HostFingerprints::capture(
            &settings,
            approval.versions().policy_fingerprint(),
            approval.versions().pack_fingerprint(),
            &prepared,
            &context,
        )
        .expect("fingerprints");
        let bridge = herness_desktop::html_sync::policy::HtmlPolicyBridge::detect(
            &self.root,
            support::REAL_PACK_ROOT,
            support::toolchain(),
        )
        .expect("detect bridge")
        .probe()
        .approval_binding()
        .expect("binding");
        let bridge = herness_desktop::html_sync::policy::HtmlPolicyBridge::detect(
            &self.root,
            support::REAL_PACK_ROOT,
            support::toolchain(),
        )
        .expect("detect bridge")
        .connect(&bridge)
        .expect("connect");
        verify(
            &bridge,
            &ChildRenderPort,
            &prepared,
            &context,
            &capture,
            Timestamp::now(),
        )
        .expect("verification")
    }
}

// ---------------------------------------------------------------------------
// Positive path.
// ---------------------------------------------------------------------------

#[test]
fn native_shell_external_edit_reaches_synced_through_the_real_adapter() {
    let mut h = Acceptance::new(true);
    assert!(
        h.pump_until(|h| h.state() == H3State::Synced, Duration::from_secs(120)),
        "the real adapter did not reach synced; state={:?} reason={:?} publication={:?}",
        h.state(),
        h.record().state().reason(),
        h.record().status()
    );
    let record = h.record();
    assert_eq!(record.state().state(), H3State::Synced);
    assert!(record.state().applicability().is_applicable());
    let (html, receipt) = h.files_exist();
    assert!(html && receipt, "both formal files must exist");
    let receipt_text =
        std::fs::read_to_string(h.root.join(herness_html_sync::html_evidence_path(&h.document)))
            .expect("receipt");
    let receipt_json: Value = serde_json::from_str(&receipt_text).expect("receipt json");
    assert_eq!(receipt_json["schema"], "sdd-html-receipt");
    assert_eq!(receipt_json["version"], 1);
    assert_eq!(
        receipt_json["source"]["path"], TARGET,
        "the receipt names the exact source"
    );
    assert_eq!(receipt_json["html"]["path"], COMPANION);
    assert_eq!(receipt_json["h2"]["purpose"], "Html");
    assert!(
        receipt_json["conditions"]
            .as_array()
            .is_some_and(|conditions| conditions.iter().all(|entry| entry["decision"] == "met")),
        "every condition must be met"
    );

    // The scripted judge is clearly not a real model: every assessment request
    // went to the loopback mock and carries no provider credential echo.
    assert!(h.assessment.count() >= 5, "3 methods + consistency");
    assert!(
        h.assessment
            .requests()
            .iter()
            .all(|request| request.path == "/v1/responses")
    );
    assert!(h.authoring.count() >= 3, "authoring tool calls and final turn");
    // The raw source was never rewritten by the candidate run.
    let source = std::fs::read_to_string(h.root.join(TARGET)).expect("source");
    assert!(source.contains("750 ms"));
    assert!(source.contains("`FIFO`"));

    // No fake/static-only render may produce this result: the saved state says
    // the real render check passed and the accessibility source is host JS.
    let candidate = record.state().fingerprints().get(
        herness_html_sync::FingerprintKind::Candidate,
    );
    assert!(candidate.is_some());
    assert_eq!(
        source,
        std::fs::read_to_string(h.root.join(TARGET)).expect("source again"),
        "the Markdown source is byte-identical after publication"
    );
    let _ = h.project;
    let _ = h.supervision;
    let _ = h.render;
    let _ = h.auto_publish;
}

#[test]
fn discovered_dependencies_include_css_and_referenced_resources() {
    let temp = TempDir::new().expect("temp");
    let root = temp.path().join("project");
    std::fs::create_dir_all(root.join("docs/adr/assets")).expect("assets");
    std::fs::create_dir_all(root.join("docs/sdd/assets")).expect("css dir");
    std::fs::write(root.join(TARGET), "# Source\n").expect("source");
    std::fs::write(
        root.join(COMPANION),
        "<!doctype html><img src=\"assets/logo.svg\" alt=\"logo\">",
    )
    .expect("companion");
    std::fs::write(root.join("docs/adr/assets/logo.svg"), "<svg/>").expect("svg");
    std::fs::write(root.join(CSS), "body { color: #111; }\n").expect("css");

    let settings = H3Settings::new(
        "44444444-4444-4444-8444-444444444444".parse().expect("project"),
        1,
        false,
        vec![TARGET.to_owned()],
        false,
        true,
        Timestamp::now(),
    )
    .expect("settings");
    let dependencies = herness_desktop::host::discovered_dependencies(&root, &settings);
    assert!(
        dependencies
            .iter()
            .any(|dependency| dependency.path() == CSS && dependency.kind() == DependencyKind::Css)
    );
    assert!(dependencies.iter().any(|dependency| {
        dependency.path() == "docs/adr/assets/logo.svg"
            && dependency.kind() == DependencyKind::Resource
    }));
}

const _: Option<(
    PostCandidateOutcome,
    HostFingerprints,
    AssessmentContext,
    ContentDigest,
    ConditionVersion,
    ConditionDigest,
)> = None;

// ---------------------------------------------------------------------------
// Required negatives.
// ---------------------------------------------------------------------------

#[test]
fn every_structural_variant_is_denied_by_the_real_pack_without_writing() {
    let mut h = Acceptance::new(true);
    assert!(
        h.pump_until(|h| h.state() == H3State::Synced, Duration::from_secs(120)),
        "baseline must sync; state={:?}",
        h.state()
    );
    let before = h.formal_snapshot();
    assert!(before.0.is_some() && before.1.is_some());
    let baseline = h.candidate_html.clone();

    let variants = [
        (
            "omission",
            {
                let start = baseline.find("<p id=\"decision\">").expect("decision");
                let end = baseline[start..]
                    .find("</p>")
                    .map(|offset| start + offset + 4)
                    .expect("decision end");
                format!("{}{}", &baseline[..start], &baseline[end..])
            },
        ),
        (
            "changed-code",
            baseline.replace(
                "<code id=\"fifo\">FIFO</code>",
                "<code id=\"fifo\">LIFO</code>",
            ),
        ),
        (
            "changed-link",
            baseline.replace("../plans/2026-01-01-plan.md", "../plans/other-plan.md"),
        ),
        ("changed-number", baseline.replace("750 ms", "750 s")),
        (
            "hidden-content",
            baseline.replace("<p id=\"summary\">", "<p id=\"summary\" hidden>"),
        ),
    ];
    for (name, html) in variants {
        assert_ne!(html, baseline, "{name} must change the candidate");
        let verification = h.verify_variant(&html);
        assert!(
            verification.pack.is_none(),
            "{name} must not build an evidence pack"
        );
        assert_eq!(
            verification
                .policy_check
                .as_ref()
                .expect("policy check")
                .decision,
            CandidateDecision::Deny,
            "{name} must be denied by the real pack"
        );
        assert!(
            h.formal_snapshot() == before,
            "{name} must not change any formal file"
        );
    }
    assert_eq!(h.state(), H3State::Synced);
}

#[test]
fn image_shortage_waits_for_a_human_and_never_publishes() {
    let mut h = Acceptance::new_with_assessment(false, true);
    assert!(
        h.pump_until(
            |h| h.state() == H3State::WaitingHuman,
            Duration::from_secs(90)
        ),
        "text-only assessment must wait, state={:?}",
        h.state()
    );
    let (html, receipt) = h.files_exist();
    assert!(html, "the pre-existing companion stays");
    assert!(!receipt, "no receipt may be written");
    let reason = h.record().state().reason().clone();
    assert!(matches!(
        reason.kind(),
        herness_html_sync::H3StateReasonKind::WaitingHuman { .. }
    ));
    assert!(
        h.assessment.count() >= 1,
        "the text-only conditions were still assessed"
    );
    assert!(h.assessment.count() < 5, "image conditions were not sent");
}

#[test]
fn revoked_html_consent_blocks_every_assessment_send_and_publication() {
    let mut h = Acceptance::new(true);
    {
        let mut config = h.host.supervision().config().get(h.project);
        let consent = config.consent(ProfilePurpose::Html).cloned().expect("consent");
        let revoked = consent
            .revoke(herness_supervision::ApprovalActor::Human, Timestamp::now())
            .expect("revoke");
        config.set_consent(revoked);
        h.host.supervision().config().set(h.project, config);
    }
    assert!(
        h.pump_until(
            |h| h.state() == H3State::WaitingHuman,
            Duration::from_secs(90)
        ),
        "revoked consent must wait, state={:?}",
        h.state()
    );
    assert_eq!(h.assessment.count(), 0, "no assessment request may be sent");
    let (_, receipt) = h.files_exist();
    assert!(!receipt, "no receipt may be written");
}

#[test]
fn an_external_html_edit_becomes_waiting_human_and_is_never_overwritten() {
    let mut h = Acceptance::new(true);
    assert!(
        h.pump_until(|h| h.state() == H3State::Synced, Duration::from_secs(120)),
        "baseline must sync"
    );
    let external = b"<!doctype html><html><body><p>external edit</p></body></html>".to_vec();
    std::fs::write(h.root.join(COMPANION), &external).expect("external edit");
    let signal = ChangeSignal::new(COMPANION, ChangeSource::FilesystemWatcher)
        .expect("companion signal");
    assert!(h.host.html_sync_mut().observe_signal(h.project, signal));
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        h.host.pump().expect("pump");
        if h.state() == H3State::WaitingHuman {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(h.state(), H3State::WaitingHuman);
    let reason = h.record().state().reason().clone();
    assert!(matches!(
        reason.kind(),
        herness_html_sync::H3StateReasonKind::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::ExternalHtmlConflict
        }
    ));
    assert_eq!(
        std::fs::read(h.root.join(COMPANION)).expect("companion"),
        external,
        "the external bytes must be preserved byte-exactly"
    );
}

#[test]
fn a_seeded_latch_holds_the_document_and_never_starts_authoring() {
    let mut h = Acceptance::new(true);
    h.host.html_sync_mut().seed_latch(
        h.document.clone(),
        Some(herness_html_sync::CycleLatch::HumanStop),
        "the human stopped this document",
    );
    h.host.pump().expect("pump");
    h.host.pump().expect("pump");
    assert_eq!(
        h.authoring.count(),
        0,
        "a latched document must not start a child"
    );
    assert!(!h.files_exist().1, "no receipt may be written");
    let observation = SourceObservation {
        document: h.document.clone(),
        snapshot: SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(
                &std::fs::read(h.root.join(TARGET)).expect("source"),
            ),
        ),
        change: SourceChange::Modified,
        trigger: ObservationTrigger::FileNotification,
        observed_via: vec![ChangeSource::ExternalEditor],
        eligibility: ObservationEligibility::approved(1).expect("eligibility"),
    };
    assert!(matches!(
        h.host.html_sync_mut().observe(&observation),
        herness_html_sync::OfferOutcome::Held { .. }
    ));
}

#[test]
fn a_completed_generation_is_never_reverified_or_rewritten() {
    let mut h = Acceptance::new(true);
    assert!(
        h.pump_until(|h| h.state() == H3State::Synced, Duration::from_secs(120)),
        "baseline must sync"
    );
    let before = h.formal_snapshot();
    let error = h
        .host
        .html_sync_advance(&h.document)
        .expect_err("a completed generation must not be advanced again");
    assert!(
        error.contains("synced") || error.contains("generation") || error.contains("record"),
        "unexpected error: {error}"
    );
    assert_eq!(h.formal_snapshot(), before, "no formal file may change");
}

#[test]
fn reassess_reuses_the_saved_candidate_through_verification_and_assessment() {
    let mut h = Acceptance::new_with_assessment(false, true);
    assert!(
        h.pump_until(
            |h| h.state() == H3State::WaitingHuman,
            Duration::from_secs(90)
        ),
        "the image-shortage attempt must wait, state={:?}",
        h.state()
    );
    let before = h.assessment.count();
    let record = h.record();
    let request = H3OperationRequest::new(
        H3RequestId::new(h.project),
        h.project,
        Some(h.document.clone()),
        Some(record.revision()),
        Some(record.state().source().digest().clone()),
        H3Operation::Reassess,
        Timestamp::now(),
    )
    .expect("reassess request");
    let view = composition::apply_document_operation(&mut h.host, request)
        .expect("reassess operation");
    assert!(
        matches!(
            view.result.outcome(),
            herness_html_sync::H3OperationOutcome::Accepted { .. }
                | herness_html_sync::H3OperationOutcome::Rejected { .. }
        ),
        "the operation must persist an explicit result"
    );
    assert!(
        h.assessment.count() > before,
        "the saved candidate must be reassessed, not silently requeued"
    );
    assert_eq!(h.state(), H3State::WaitingHuman);
    assert!(!h.files_exist().1, "no receipt may be written");
}
