//! Desktop command guard, state, and approval wiring tests.
//!
//! These tests exercise the real Tauri-facing composition: the SQLite store,
//! the pi engine adapter inside `PiEngine`, the runtime, and the desktop
//! executor. Provider traffic goes to a loopback mock and credentials are fake
//! and non-secret. No Keychain, real provider, browser, or GUI session is used.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use herness_core::runtime::AgentSpec;
use herness_core::{
    AuthMethod, ConnectionAdmin, ConnectionId, ConnectionSettings, CredentialAvailability,
    CredentialKind, CredentialPort, Endpoint, HistoryLimit, MatchMethod, OperationOutcome,
    PermissionRule, Provider, ResolvedCredential, RuleTarget, RunState, SecretString, ToolName,
};
use herness_desktop::guard::{self, GuardError, Navigation};
use herness_desktop::host::DesktopHost;
use herness_engine_pi::ProviderEndpoints;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Loopback provider mock.
// ---------------------------------------------------------------------------

#[derive(Clone)]
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
    requests: Arc<AtomicUsize>,
}

impl MockServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(usize) -> MockResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let address = listener.local_addr().expect("mock address");
        let requests = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::clone(&requests);
        let handler = Arc::new(handler);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let handler = Arc::clone(&handler);
                let recorded = Arc::clone(&recorded);
                thread::spawn(move || {
                    let index = recorded.fetch_add(1, Ordering::SeqCst);
                    handle_connection(stream, handler(index));
                });
            }
        });
        Self { address, requests }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

fn handle_connection(mut stream: TcpStream, response: MockResponse) {
    let Some(_request) = read_request(&mut stream) else {
        return;
    };
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
        401 => "Unauthorized",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

fn read_request(stream: &mut TcpStream) -> Option<String> {
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
    Some(head)
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

fn responses_tool_call(name: &str, arguments: Value) -> MockResponse {
    let arguments = arguments.to_string();
    let item = |arguments: &str| {
        json!({
            "type": "function_call",
            "id": "fc_desktop",
            "call_id": "call_desktop",
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

// ---------------------------------------------------------------------------
// Fake credentials.
// ---------------------------------------------------------------------------

struct FakeCredentials {
    connection: ConnectionId,
    secret: String,
    resolves: AtomicUsize,
}

impl FakeCredentials {
    fn new(connection: ConnectionId, secret: &str) -> Self {
        Self {
            connection,
            secret: secret.to_owned(),
            resolves: AtomicUsize::new(0),
        }
    }
}

impl CredentialPort for FakeCredentials {
    fn availability(
        &self,
        connection: &ConnectionId,
    ) -> Result<CredentialAvailability, herness_core::CoreError> {
        if connection == &self.connection {
            Ok(CredentialAvailability::Available)
        } else {
            Ok(CredentialAvailability::Unavailable)
        }
    }

    fn resolve(
        &self,
        connection: &ConnectionId,
    ) -> Result<ResolvedCredential, herness_core::CoreError> {
        if connection != &self.connection {
            return Err(herness_core::CoreError::AuthenticationRequired {
                connection: *connection,
            });
        }
        self.resolves.fetch_add(1, Ordering::SeqCst);
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
    _temp: tempfile::TempDir,
    project: std::path::PathBuf,
    app_data: std::path::PathBuf,
    connection: ConnectionId,
    host: DesktopHost,
    _server: MockServer,
}

impl Fixture {
    fn new(responses: Vec<MockResponse>) -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).expect("project");
        let app_data = temp.path().join("app-data");
        let queue = Arc::new(Mutex::new(VecDeque::from(responses)));
        let server = MockServer::start({
            let queue = Arc::clone(&queue);
            move |_index| {
                let mut queue = queue.lock().expect("responses");
                queue.pop_front().unwrap_or_else(|| MockResponse {
                    status: 500,
                    content_type: "application/json",
                    body: json!({"error": {"message": "mock exhausted"}}).to_string(),
                })
            }
        });
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
        let credentials = Arc::new(FakeCredentials::new(connection, "sk-desktop-canary"));
        let (host, _report) = DesktopHost::open(&app_data, connections, credentials, endpoints)
            .expect("desktop host");
        Self {
            _temp: temp,
            project,
            app_data,
            connection,
            host,
            _server: server,
        }
    }

    fn connection(&self) -> ConnectionId {
        self.connection
    }
}

fn wait_for_approval(
    host: &mut DesktopHost,
    project: herness_core::ProjectId,
) -> herness_core::runtime::PendingApproval {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let runs = {
            let snapshot = host.runtime().snapshot(project).expect("snapshot");
            snapshot
                .runs()
                .iter()
                .map(|run| run.run_id())
                .collect::<Vec<_>>()
        };
        for run in runs {
            let _ = host.runtime_mut().poll_run(project, run);
        }
        let pending = host
            .runtime()
            .pending_approvals(project)
            .expect("pending approvals");
        if let Some(approval) = pending.into_iter().next() {
            return approval;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for an approval");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// Guard tests.
// ---------------------------------------------------------------------------

#[test]
fn project_open_rejects_the_private_application_data_area() {
    let mut fixture = Fixture::new(Vec::new());
    let app_data = fixture.app_data.clone();
    assert!(fixture.host.open_project(&app_data).is_err());
    let nested = app_data.join("nested-project");
    std::fs::create_dir_all(&nested).expect("nested project");
    assert!(fixture.host.open_project(&nested).is_err());
}

#[test]
fn ui_uses_text_only_rendering_and_no_browser_secret_storage() {
    let app_js = include_str!("../../../ui/app.js");
    for forbidden in [
        "innerHTML",
        "insertAdjacentHTML",
        "document.write",
        "localStorage",
        "sessionStorage",
        "document.cookie",
    ] {
        assert!(
            !app_js.contains(forbidden),
            "ui/app.js must not use {forbidden}"
        );
    }
    let index = include_str!("../../../ui/index.html");
    assert!(!index.contains("innerHTML"));
    assert!(!index.contains("http://"));
    assert!(!index.contains("https://"));
}

#[test]
fn trusted_main_origin_succeeds_and_other_sources_are_rejected() {
    assert_eq!(
        guard::verify("main", "main", Some("tauri://localhost/index.html")),
        Ok(())
    );
    assert_eq!(
        guard::classify_navigation("tauri://localhost/index.html"),
        Navigation::LoadLocal
    );

    assert_eq!(
        guard::verify("settings", "settings", Some("tauri://localhost/index.html")),
        Err(GuardError::UntrustedWindow)
    );
    assert_eq!(
        guard::verify("main", "preview", Some("tauri://localhost/index.html")),
        Err(GuardError::UntrustedWebview)
    );
    assert_eq!(
        guard::verify("main", "main", Some("https://example.com/")),
        Err(GuardError::UntrustedOrigin)
    );
    assert_eq!(
        guard::verify("main", "main", Some("tauri://localhost/preview.html")),
        Err(GuardError::UntrustedOrigin)
    );
    assert_eq!(
        guard::classify_navigation("https://example.com/"),
        Navigation::OpenExternal
    );
}

// ---------------------------------------------------------------------------
// Runtime state and approval wiring.
// ---------------------------------------------------------------------------

#[test]
fn approved_engine_operation_executes_once_and_is_history_visible() {
    let responses = vec![
        responses_tool_call(
            "write",
            json!({
                "path": "approved.txt",
                "content": "approved once",
                "rationale": "desktop approval wiring test"
            }),
        ),
        responses_text("waiting for approval"),
        responses_text("done after approval"),
    ];
    let mut fixture = Fixture::new(responses);
    let connection = fixture.connection();
    let project = fixture
        .host
        .runtime_mut()
        .open_project(&fixture.project)
        .expect("open project")
        .project_id();
    let agent = fixture
        .host
        .runtime_mut()
        .create_agent(project, AgentSpec::new("main", "implementer", connection))
        .expect("agent");
    let run = fixture
        .host
        .runtime_mut()
        .start_run(project, agent.agent_id(), "write the approved file")
        .expect("run");
    fixture
        .host
        .runtime_mut()
        .submit_input(project, run.run_id(), "write the approved file")
        .expect("submit input");

    let approval = wait_for_approval(&mut fixture.host, project);
    assert_eq!(
        fixture
            .host
            .runtime()
            .run(project, run.run_id())
            .expect("run view")
            .state(),
        RunState::AwaitingApproval
    );
    assert!(!fixture.project.join("approved.txt").exists());
    let operation = approval.operation().clone();
    assert_eq!(operation.tool(), herness_core::ToolName::Write);
    assert!(approval.reusable());

    // The engine records an awaiting audit event but no operation intent.
    let before = fixture
        .host
        .runtime()
        .subscribe(project, None, HistoryLimit::new(500).expect("limit"))
        .expect("history");
    let kinds = before
        .events()
        .iter()
        .map(|event| event.kind().as_str())
        .collect::<Vec<_>>();
    assert!(kinds.contains(&"engine.tool.awaiting_approval"));
    assert!(!kinds.contains(&"file.change.intended"));

    let approved = fixture
        .host
        .runtime_mut()
        .approve(project, operation.operation_id())
        .expect("approve");
    assert!(approved.executed());
    assert_eq!(approved.outcome(), OperationOutcome::Applied);
    assert_eq!(
        std::fs::read_to_string(fixture.project.join("approved.txt")).expect("file"),
        "approved once"
    );

    // A repeated approval cannot execute the side effect again.
    assert!(
        fixture
            .host
            .runtime_mut()
            .approve(project, operation.operation_id())
            .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(fixture.project.join("approved.txt")).expect("file"),
        "approved once"
    );

    let after = fixture
        .host
        .runtime()
        .subscribe(project, None, HistoryLimit::new(500).expect("limit"))
        .expect("history");
    let kinds = after
        .events()
        .iter()
        .map(|event| event.kind().as_str())
        .collect::<Vec<_>>();
    assert!(kinds.contains(&"run.awaiting_approval"));
    assert!(kinds.contains(&"run.operation_completed"));
    assert!(kinds.contains(&"run.approval_resolved"));
    assert!(kinds.contains(&"file.change.intended"));

    // The fake credential canary never reaches events, host state, or the
    // SQLite database.
    let serialized = serde_json::to_string(after.events()).expect("events json");
    assert!(!serialized.contains("sk-desktop-canary"));
    for entry in std::fs::read_dir(&fixture.app_data).expect("app data") {
        let path = entry.expect("entry").path();
        if path.is_file() {
            let bytes = std::fs::read(&path).expect("database bytes");
            assert!(
                !bytes
                    .windows("sk-desktop-canary".len())
                    .any(|window| window == b"sk-desktop-canary"),
                "credential canary leaked into {}",
                path.display()
            );
        }
    }
}

#[test]
fn denied_engine_operation_never_executes_and_cannot_be_approved_later() {
    let responses = vec![
        responses_tool_call(
            "write",
            json!({
                "path": "denied.txt",
                "content": "must not exist",
                "rationale": "desktop denial wiring test"
            }),
        ),
        responses_text("waiting for approval"),
        responses_text("denied"),
    ];
    let mut fixture = Fixture::new(responses);
    let connection = fixture.connection();
    let project = fixture
        .host
        .runtime_mut()
        .open_project(&fixture.project)
        .expect("open project")
        .project_id();
    let agent = fixture
        .host
        .runtime_mut()
        .create_agent(project, AgentSpec::new("main", "implementer", connection))
        .expect("agent");
    let run = fixture
        .host
        .runtime_mut()
        .start_run(project, agent.agent_id(), "write a denied file")
        .expect("run");
    fixture
        .host
        .runtime_mut()
        .submit_input(project, run.run_id(), "write a denied file")
        .expect("submit input");

    let approval = wait_for_approval(&mut fixture.host, project);
    let operation = approval.operation().operation_id();
    fixture
        .host
        .runtime_mut()
        .deny(project, operation)
        .expect("deny");
    assert!(!fixture.project.join("denied.txt").exists());
    assert!(
        fixture
            .host
            .runtime_mut()
            .approve(project, operation)
            .is_err()
    );
    assert!(!fixture.project.join("denied.txt").exists());

    let history = fixture
        .host
        .runtime()
        .subscribe(project, None, HistoryLimit::new(500).expect("limit"))
        .expect("history");
    let kinds = history
        .events()
        .iter()
        .map(|event| event.kind().as_str())
        .collect::<Vec<_>>();
    assert!(kinds.contains(&"run.approval_resolved"));
    assert!(!kinds.contains(&"run.operation_completed"));
    assert!(!kinds.contains(&"file.change.intended"));
}

#[test]
fn adapter_authority_prevents_a_second_executor_for_allowed_tools() {
    let responses = vec![
        responses_tool_call(
            "bash",
            json!({
                "command": "printf x >> count.txt",
                "purpose": "prove a single executor"
            }),
        ),
        responses_text("single execution"),
    ];
    let mut fixture = Fixture::new(responses);
    let connection = fixture.connection();
    {
        let policy = fixture.host.runtime_mut().policy_admin_mut();
        policy
            .add_rule(
                PermissionRule::allow(
                    RuleTarget::Tool {
                        tool: ToolName::Bash,
                    },
                    MatchMethod::AnyInvocation,
                )
                .expect("allow rule"),
            )
            .expect("add allow rule");
        let policy = policy.policy().clone();
        fixture
            .host
            .runtime_mut()
            .engine_mut()
            .replace_policy(policy);
    }
    let project = fixture
        .host
        .runtime_mut()
        .open_project(&fixture.project)
        .expect("open project")
        .project_id();
    let agent = fixture
        .host
        .runtime_mut()
        .create_agent(project, AgentSpec::new("main", "implementer", connection))
        .expect("agent");
    let run = fixture
        .host
        .runtime_mut()
        .start_run(project, agent.agent_id(), "count the executions")
        .expect("run");
    fixture
        .host
        .runtime_mut()
        .submit_input(project, run.run_id(), "count the executions")
        .expect("submit input");

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let _ = fixture.host.runtime_mut().poll_run(project, run.run_id());
        if fixture.project.join("count.txt").exists() {
            break;
        }
        let state = fixture
            .host
            .runtime()
            .run(project, run.run_id())
            .expect("run view")
            .state();
        assert_ne!(state, RunState::Failed, "allowed bash run failed");
        if Instant::now() >= deadline {
            panic!("allowed bash tool did not execute; state={state}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        std::fs::read_to_string(fixture.project.join("count.txt")).expect("count file"),
        "x"
    );
    let history = fixture
        .host
        .runtime()
        .subscribe(project, None, HistoryLimit::new(500).expect("limit"))
        .expect("history");
    let kinds = history
        .events()
        .iter()
        .map(|event| event.kind().as_str())
        .collect::<Vec<_>>();
    assert!(kinds.contains(&"engine.tool.intent"));
    assert!(!kinds.contains(&"run.operation_completed"));
    assert!(!kinds.contains(&"run.awaiting_approval"));
}

#[test]
fn restore_is_read_only_and_reports_interrupted_state_without_pending_reuse() {
    let responses = vec![
        responses_tool_call(
            "write",
            json!({
                "path": "restored.txt",
                "content": "not written",
                "rationale": "restore read-only test"
            }),
        ),
        responses_text("waiting for approval"),
    ];
    let mut fixture = Fixture::new(responses);
    let connection = fixture.connection();
    let project = fixture
        .host
        .runtime_mut()
        .open_project(&fixture.project)
        .expect("open project")
        .project_id();
    let agent = fixture
        .host
        .runtime_mut()
        .create_agent(project, AgentSpec::new("main", "implementer", connection))
        .expect("agent");
    let run = fixture
        .host
        .runtime_mut()
        .start_run(project, agent.agent_id(), "restore test")
        .expect("run");
    fixture
        .host
        .runtime_mut()
        .submit_input(project, run.run_id(), "restore test")
        .expect("submit input");
    let _ = wait_for_approval(&mut fixture.host, project);
    // Let the adapter finish the turn that produced the approval request so the
    // restore check observes a quiet engine.
    let settle = Instant::now() + Duration::from_secs(15);
    while fixture._server.request_count() < 2 {
        assert!(
            Instant::now() < settle,
            "adapter did not finish the approval turn"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let requests_before_restore = fixture._server.request_count();
    let app_data = fixture.app_data.clone();
    let connection = fixture.connection();
    let project_path = std::fs::canonicalize(&fixture.project).expect("canonical project");
    let make_admin = || {
        let admin = ConnectionAdmin::new();
        admin
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
        admin
    };
    let dummy_root = fixture._temp.path().join("dummy-app-data");
    let dummy = DesktopHost::open(
        &dummy_root,
        make_admin(),
        Arc::new(FakeCredentials::new(connection, "sk-desktop-canary")),
        ProviderEndpoints::for_loopback("http://127.0.0.1:9/v1", "http://127.0.0.1:9")
            .expect("unused loopback"),
    )
    .expect("dummy host")
    .0;
    let old = std::mem::replace(&mut fixture.host, dummy);
    drop(old);
    let (restored, _report) = DesktopHost::open(
        &app_data,
        make_admin(),
        Arc::new(FakeCredentials::new(connection, "sk-desktop-canary")),
        ProviderEndpoints::for_loopback("http://127.0.0.1:9/v1", "http://127.0.0.1:9")
            .expect("unused loopback"),
    )
    .expect("restored host");
    fixture.host = restored;
    let restored_project = fixture
        .host
        .runtime()
        .projects()
        .expect("projects")
        .into_iter()
        .find(|view| view.path().as_str() == project_path.to_string_lossy().as_ref())
        .expect("restored project");
    let restored_run = fixture
        .host
        .runtime()
        .snapshot(restored_project.project_id())
        .expect("snapshot")
        .runs()
        .first()
        .cloned()
        .expect("run");
    assert_eq!(restored_run.state(), RunState::Interrupted);
    let approvals = fixture
        .host
        .runtime()
        .pending_approvals(restored_project.project_id())
        .expect("approvals");
    assert!(
        approvals
            .iter()
            .all(|approval| approval.restored() && !approval.reusable())
    );
    assert!(!fixture.project.join("restored.txt").exists());
    assert_eq!(fixture._server.request_count(), requests_before_restore);
}
