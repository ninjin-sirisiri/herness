//! Black-box engine adapter tests.
//!
//! Every provider request in this file goes to a loopback mock. No test opens a
//! browser, reads a real Keychain item, or contacts a provider host.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use herness_core::runtime::{
    AgentSpec, RunToolContext, Runtime, RuntimeDependencies, RuntimeToolExecutor, ToolExecution,
};
use herness_core::{
    AbsolutePath, AgentId, AuthMethod, Checkpoint, CheckpointCommit, CheckpointFormatVersion,
    CheckpointPayload, ConnectionAdmin, ConnectionDirectory, ConnectionId, ConnectionSettings,
    ConversationFailure, CoreError, CredentialAvailability, CredentialKind, CredentialPort,
    CredentialService, CredentialVault, Endpoint, EngineEvent, EngineFailureKind, EngineInput,
    EnginePort, EngineStart, FrozenOperation, HistoryLimit, MatchMethod, OperationOutcome,
    PermissionPolicy, PermissionRule, PolicyAdmin, ProjectId, Provider, ResolvedCredential,
    RuleTarget, RunId, RunState, SecretString, SessionId, StopReason, StopReport, StorePort,
    ToolExecutor, ToolName, VaultAccount, VaultFailure,
};
use herness_engine_pi::{PiEngine, PiEngineConfig, ProviderEndpoints};
use herness_store::{Store, StoreConfig};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Loopback HTTP mock
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

#[derive(Clone, Debug)]
struct MockResponse {
    status: u16,
    content_type: &'static str,
    body: String,
    delay: Duration,
}

impl MockResponse {
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: value.to_string(),
            delay: Duration::ZERO,
        }
    }

    fn sse(body: String) -> Self {
        Self {
            status: 200,
            content_type: "text/event-stream",
            body,
            delay: Duration::ZERO,
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: String::new(),
            delay: Duration::ZERO,
        }
    }

    fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

struct MockServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let address = listener.local_addr().expect("mock address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let handler = Arc::new(handler);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let handler = Arc::clone(&handler);
                let recorded = Arc::clone(&recorded);
                thread::spawn(move || handle_connection(stream, handler, recorded));
            }
        });
        Self { address, requests }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("requests").clone()
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("requests").len()
    }
}

fn handle_connection(
    mut stream: TcpStream,
    handler: Arc<dyn Fn(&RecordedRequest) -> MockResponse + Send + Sync>,
    recorded: Arc<Mutex<Vec<RecordedRequest>>>,
) {
    let request = match read_request(&mut stream) {
        Some(request) => request,
        None => return,
    };
    recorded.lock().expect("record").push(request.clone());
    let response = handler(&request);
    if !response.delay.is_zero() {
        thread::sleep(response.delay);
    }
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
        302 => "Found",
        401 => "Unauthorized",
        403 => "Forbidden",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Error",
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
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap_or(0);
        }
        headers.push((name.to_owned(), value));
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some(RecordedRequest {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

// ---------------------------------------------------------------------------
// Provider stream fixtures
// ---------------------------------------------------------------------------

fn sse(event: &str, data: Value) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

fn data_event(data: Value) -> String {
    format!("data: {data}\n\n")
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

fn responses_tool_call(call_id: &str, item_id: &str, name: &str, arguments: Value) -> MockResponse {
    let arguments = arguments.to_string();
    let item = |arguments: &str| {
        json!({
            "type": "function_call",
            "id": item_id,
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

fn responses_duplicate_tool_calls(
    call_id: &str,
    item_id: &str,
    name: &str,
    arguments: Value,
) -> MockResponse {
    let arguments = arguments.to_string();
    let item = |arguments: &str| {
        json!({
            "type": "function_call",
            "id": item_id,
            "call_id": call_id,
            "name": name,
            "arguments": arguments
        })
    };
    let mut body = String::new();
    body.push_str(&sse(
        "response.created",
        json!({"type": "response.created", "response": {"id": "resp_dup"}}),
    ));
    for index in 0..2 {
        body.push_str(&sse(
            "response.output_item.added",
            json!({"type": "response.output_item.added", "output_index": index, "item": item("")}),
        ));
        body.push_str(&sse(
            "response.function_call_arguments.delta",
            json!({"type": "response.function_call_arguments.delta", "output_index": index, "delta": arguments}),
        ));
        body.push_str(&sse(
            "response.output_item.done",
            json!({"type": "response.output_item.done", "output_index": index, "item": item(&arguments)}),
        ));
    }
    body.push_str(&sse(
        "response.completed",
        json!({
            "type": "response.completed",
            "response": {"id": "resp_dup", "status": "completed", "output": [item(&arguments)]}
        }),
    ));
    MockResponse::sse(body)
}

fn responses_incomplete() -> MockResponse {
    let mut body = String::new();
    body.push_str(&sse(
        "response.created",
        json!({"type": "response.created", "response": {"id": "resp_inc"}}),
    ));
    body.push_str(&sse(
        "response.incomplete",
        json!({
            "type": "response.incomplete",
            "response": {
                "id": "resp_inc",
                "status": "incomplete",
                "incomplete_details": {"reason": "max_output_tokens"},
                "output": []
            }
        }),
    ));
    MockResponse::sse(body)
}

fn responses_failed(code: &str) -> MockResponse {
    let mut body = String::new();
    body.push_str(&sse(
        "response.created",
        json!({"type": "response.created", "response": {"id": "resp_fail"}}),
    ));
    body.push_str(&sse(
        "response.failed",
        json!({
            "type": "response.failed",
            "response": {
                "id": "resp_fail",
                "status": "failed",
                "error": {"code": code, "message": "sanitized provider text"}
            }
        }),
    ));
    MockResponse::sse(body)
}

fn responses_early_disconnect(text: &str) -> MockResponse {
    let mut body = String::new();
    body.push_str(&sse(
        "response.created",
        json!({"type": "response.created", "response": {"id": "resp_cut"}}),
    ));
    body.push_str(&sse(
        "response.output_item.added",
        json!({"type": "response.output_item.added", "output_index": 0, "item": {"type": "message", "id": "msg_cut"}}),
    ));
    body.push_str(&sse(
        "response.output_text.delta",
        json!({"type": "response.output_text.delta", "output_index": 0, "delta": text}),
    ));
    MockResponse::sse(body)
}

fn anthropic_text(text: &str) -> MockResponse {
    let mut body = String::new();
    body.push_str(&sse(
        "message_start",
        json!({"type": "message_start", "message": {"id": "msg_a", "model": "claude-test", "usage": {"input_tokens": 1, "output_tokens": 0}}}),
    ));
    body.push_str(&sse(
        "content_block_start",
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
    ));
    body.push_str(&sse(
        "content_block_delta",
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}),
    ));
    body.push_str(&sse(
        "content_block_stop",
        json!({"type": "content_block_stop", "index": 0}),
    ));
    body.push_str(&sse(
        "message_delta",
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 1}}),
    ));
    body.push_str(&sse("message_stop", json!({"type": "message_stop"})));
    MockResponse::sse(body)
}

fn anthropic_tool_call(call_id: &str, name: &str, arguments: Value) -> MockResponse {
    let partial = arguments.to_string();
    let mut body = String::new();
    body.push_str(&sse(
        "message_start",
        json!({"type": "message_start", "message": {"id": "msg_at", "model": "claude-test", "usage": {"input_tokens": 1, "output_tokens": 0}}}),
    ));
    body.push_str(&sse(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": call_id, "name": name, "input": {}}
        }),
    ));
    body.push_str(&sse(
        "content_block_delta",
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": partial}}),
    ));
    body.push_str(&sse(
        "content_block_stop",
        json!({"type": "content_block_stop", "index": 0}),
    ));
    body.push_str(&sse(
        "message_delta",
        json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 1}}),
    ));
    body.push_str(&sse("message_stop", json!({"type": "message_stop"})));
    MockResponse::sse(body)
}

fn completions_text(text: &str) -> MockResponse {
    let mut body = String::new();
    body.push_str(&data_event(json!({
        "id": "chatcmpl-text",
        "choices": [{"index": 0, "delta": {"content": text}}]
    })));
    body.push_str(&data_event(json!({
        "id": "chatcmpl-text",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
    })));
    body.push_str("data: [DONE]\n\n");
    MockResponse::sse(body)
}

fn completions_tool_call(call_id: &str, name: &str, arguments: Value) -> MockResponse {
    let arguments = arguments.to_string();
    let split = arguments.len() / 2;
    let (first, second) = arguments.split_at(split);
    let mut body = String::new();
    body.push_str(&data_event(json!({
        "id": "chatcmpl-tool",
        "choices": [{"index": 0, "delta": {"tool_calls": [{
            "index": 0,
            "id": call_id,
            "type": "function",
            "function": {"name": name, "arguments": first}
        }]}}]
    })));
    body.push_str(&data_event(json!({
        "id": "chatcmpl-tool",
        "choices": [{"index": 0, "delta": {"tool_calls": [{
            "index": 0,
            "function": {"arguments": second}
        }]}}]
    })));
    body.push_str(&data_event(json!({
        "id": "chatcmpl-tool",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]
    })));
    body.push_str("data: [DONE]\n\n");
    MockResponse::sse(body)
}

fn catalog_response(models: Value) -> MockResponse {
    MockResponse::json(200, json!({"models": models}))
}

#[derive(Clone)]
struct Responses {
    items: Arc<Mutex<VecDeque<MockResponse>>>,
}

impl Responses {
    fn new(items: Vec<MockResponse>) -> Self {
        Self {
            items: Arc::new(Mutex::new(items.into())),
        }
    }

    fn next(&self) -> MockResponse {
        self.items
            .lock()
            .expect("responses")
            .pop_front()
            .unwrap_or_else(|| {
                MockResponse::json(
                    500,
                    json!({"error": {"code": "unexpected_request", "message": "mock exhausted"}}),
                )
            })
    }
}

// ---------------------------------------------------------------------------
// Credentials, connections, store
// ---------------------------------------------------------------------------

struct RotatingCredentials {
    secrets: Mutex<HashMap<ConnectionId, VecDeque<String>>>,
    calls: AtomicUsize,
}

impl RotatingCredentials {
    fn new(connection: ConnectionId, secrets: impl IntoIterator<Item = String>) -> Self {
        let mut map = HashMap::new();
        map.insert(connection, secrets.into_iter().collect());
        Self {
            secrets: Mutex::new(map),
            calls: AtomicUsize::new(0),
        }
    }

    fn insert(&self, connection: ConnectionId, secrets: impl IntoIterator<Item = String>) {
        self.secrets
            .lock()
            .expect("secrets")
            .insert(connection, secrets.into_iter().collect());
    }
}

impl CredentialPort for RotatingCredentials {
    fn availability(
        &self,
        _connection: &ConnectionId,
    ) -> Result<CredentialAvailability, herness_core::CoreError> {
        Ok(CredentialAvailability::Available)
    }

    fn resolve(
        &self,
        connection: &ConnectionId,
    ) -> Result<ResolvedCredential, herness_core::CoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut map = self.secrets.lock().expect("secrets");
        let queue =
            map.get_mut(connection)
                .ok_or(herness_core::CoreError::AuthenticationRequired {
                    connection: *connection,
                })?;
        let secret = if queue.len() > 1 {
            queue.pop_front().expect("secret")
        } else {
            queue
                .front()
                .cloned()
                .ok_or(herness_core::CoreError::AuthenticationRequired {
                    connection: *connection,
                })?
        };
        Ok(ResolvedCredential::new(
            CredentialKind::ApiKey,
            SecretString::new(secret)?,
        ))
    }
}

#[derive(Default)]
struct TestVault {
    items: Mutex<BTreeMap<VaultAccount, Vec<u8>>>,
}

impl CredentialVault for TestVault {
    fn set(&self, account: &VaultAccount, data: &[u8]) -> Result<(), VaultFailure> {
        self.items
            .lock()
            .map_err(|_| VaultFailure::Unavailable)?
            .insert(account.clone(), data.to_vec());
        Ok(())
    }

    fn get(&self, account: &VaultAccount) -> Result<Option<Vec<u8>>, VaultFailure> {
        Ok(self
            .items
            .lock()
            .map_err(|_| VaultFailure::Unavailable)?
            .get(account)
            .cloned())
    }

    fn delete(&self, account: &VaultAccount) -> Result<(), VaultFailure> {
        self.items
            .lock()
            .map_err(|_| VaultFailure::Unavailable)?
            .remove(account);
        Ok(())
    }
}

fn allow_all_policy() -> PermissionPolicy {
    let mut admin = PolicyAdmin::new();
    for tool in [
        ToolName::Read,
        ToolName::Search,
        ToolName::Write,
        ToolName::Edit,
        ToolName::Bash,
    ] {
        admin
            .add_rule(
                PermissionRule::allow(RuleTarget::Tool { tool }, MatchMethod::AnyInvocation)
                    .expect("rule"),
            )
            .expect("add rule");
    }
    admin.policy().clone()
}

struct Fixture {
    _temp: tempfile::TempDir,
    project: std::path::PathBuf,
    project_id: ProjectId,
    store: Arc<Mutex<Store>>,
    engine: PiEngine<Store>,
    connection: ConnectionId,
    directory: ConnectionDirectory,
    credentials: Arc<dyn CredentialPort + Send + Sync>,
    endpoints: ProviderEndpoints,
    policy: PermissionPolicy,
}

struct FixtureOptions {
    provider: Provider,
    model: &'static str,
    auth: AuthMethod,
    endpoint: Option<String>,
    endpoints: ProviderEndpoints,
    credentials: Arc<dyn CredentialPort + Send + Sync>,
    connection_id: Option<ConnectionId>,
}

fn fixture_with(options: FixtureOptions) -> Fixture {
    fixture_with_policy(options, allow_all_policy())
}

fn fixture_with_policy(options: FixtureOptions, policy: PermissionPolicy) -> Fixture {
    let temp = tempfile::tempdir().expect("temp");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("project");
    let config = StoreConfig::new(temp.path().join("app")).expect("store config");
    let store = Store::open(config).expect("store");
    let store = Arc::new(Mutex::new(store));
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let connection = options.connection_id.unwrap_or_default();
    let endpoint = options
        .endpoint
        .as_deref()
        .map(|value| Endpoint::parse(value).expect("endpoint"));
    let settings = ConnectionSettings::new(
        connection,
        options.provider,
        options.model,
        options.auth,
        endpoint,
        None,
    )
    .expect("connection settings");
    admin.add(settings).expect("add connection");
    let directory = directory.clone();
    let credentials = options.credentials;
    let endpoints = options.endpoints;
    let engine = PiEngine::new(
        Arc::clone(&store),
        Arc::clone(&credentials),
        directory.clone(),
        PiEngineConfig::new(policy.clone()).with_endpoints(endpoints.clone()),
    )
    .expect("engine");
    Fixture {
        _temp: temp,
        project,
        project_id: ProjectId::new(),
        store,
        engine,
        connection,
        directory,
        credentials,
        endpoints,
        policy,
    }
}

fn restart_engine(
    store: Arc<Mutex<Store>>,
    credentials: Arc<dyn CredentialPort + Send + Sync>,
    directory: ConnectionDirectory,
    endpoints: ProviderEndpoints,
    policy: PermissionPolicy,
) -> PiEngine<Store> {
    PiEngine::new(
        store,
        credentials,
        directory,
        PiEngineConfig::new(policy).with_endpoints(endpoints),
    )
    .expect("restarted engine")
}

fn wait_for_event_kind(
    store: &Arc<Mutex<Store>>,
    project: ProjectId,
    kind: &str,
) -> Vec<herness_core::Event> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let events = {
            let store = store.lock().expect("store");
            store
                .events_after(&project, None, HistoryLimit::new(500).expect("limit"))
                .expect("events")
        };
        if events.iter().any(|event| event.kind().as_str() == kind) {
            return events;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for event kind {kind}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn default_credentials(
    connection: ConnectionId,
    secret: &str,
) -> Arc<dyn CredentialPort + Send + Sync> {
    Arc::new(RotatingCredentials::new(connection, [secret.to_owned()]))
}

fn engine_start(fixture: &Fixture, instructions: &str) -> (AgentId, SessionId, RunId, EngineStart) {
    let project = fixture.project_id;
    let agent = AgentId::new(project);
    let session = SessionId::new(project);
    let run = RunId::new(project);
    let cwd = AbsolutePath::new(fixture.project.to_string_lossy().into_owned()).expect("cwd");
    let start = EngineStart::new(
        project,
        agent,
        session,
        run,
        fixture.connection,
        cwd,
        instructions,
    )
    .expect("engine start");
    (agent, session, run, start)
}

fn collect_until_terminal(
    engine: &mut PiEngine<Store>,
    run: &RunId,
    timeout: Duration,
) -> Vec<EngineEvent> {
    let deadline = Instant::now() + timeout;
    let mut events = Vec::new();
    loop {
        events.extend(engine.poll_events(run).expect("poll"));
        if events.iter().any(|event| {
            matches!(
                event,
                EngineEvent::StateChanged(
                    RunState::Idle | RunState::Failed | RunState::Interrupted
                )
            )
        }) {
            return events;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for a terminal engine state; events={events:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn text_of(events: &[EngineEvent]) -> String {
    events
        .iter()
        .filter_map(|event| match event {
            EngineEvent::TextCompleted { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

fn wait_for_requests(server: &MockServer, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.request_count() < count {
        if Instant::now() >= deadline {
            panic!("timed out waiting for {count} mock requests");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn openai_api_key_text_turn_completes_and_uses_the_responses_path() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |request| {
        if request.path.ends_with("/models") {
            return catalog_response(json!([]));
        }
        responses_text("hello from openai")
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-test-canary"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("say hello".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(text_of(&events), "hello from openai");
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Idle)));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/responses");
    assert_eq!(
        request.header("authorization"),
        Some("Bearer sk-test-canary")
    );
    let body = request.json();
    assert_eq!(body["model"], "gpt-test");
    assert_eq!(body["stream"], true);
    assert_eq!(body["store"], false);
}

#[test]
fn openai_tool_round_trip_goes_through_the_host_gateway() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_tool_call(
            "call_read_1",
            "fc_read_1",
            "read",
            json!({"path": "notes.txt"}),
        ),
        responses_text("finished reading"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |request| {
            if request.path.ends_with("/models") {
                return catalog_response(json!([]));
            }
            responses.next()
        }
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-tool-canary"),
        connection_id: Some(connection),
    });
    std::fs::write(fixture.project.join("notes.txt"), "hello from notes\n").expect("notes");
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("read notes".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(text_of(&events), "finished reading");
    assert!(events.iter().any(|event| matches!(
        event,
        EngineEvent::ToolCall {
            tool: ToolName::Read,
            ..
        }
    )));
    let requests = server.requests();
    assert_eq!(
        requests.len(),
        2,
        "tool round trip must issue a second request"
    );
    let second = requests[1].json();
    let body = second.to_string();
    assert!(
        body.contains("hello from notes"),
        "second request must carry the host tool result: {body}"
    );
}

#[test]
fn anthropic_tool_round_trip_goes_through_the_host_gateway() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        anthropic_tool_call("toolu_read_1", "read", json!({"path": "notes.txt"})),
        anthropic_text("finished reading with anthropic"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(server.url(), server.url()).expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::Anthropic,
        model: "claude-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "claude-test-key"),
        connection_id: Some(connection),
    });
    std::fs::write(fixture.project.join("notes.txt"), "anthropic notes\n").expect("notes");
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("read notes".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(text_of(&events), "finished reading with anthropic");
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/v1/messages");
    assert_eq!(requests[0].header("x-api-key"), Some("claude-test-key"));
    assert_eq!(requests[0].json()["stream"], true);
    assert_eq!(requests[0].json()["model"], "claude-test");
    assert!(requests[1].body.contains("anthropic notes"));
}

#[test]
fn openai_compatible_tool_round_trip_goes_through_the_host_gateway() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        completions_tool_call("call_read_1", "read", json!({"path": "notes.txt"})),
        completions_text("finished reading with compatible"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoint = format!("{}/v1", server.url());
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAiCompatible,
        model: "local-test",
        auth: AuthMethod::ApiKey,
        endpoint: Some(endpoint),
        endpoints: ProviderEndpoints::official(),
        credentials: default_credentials(connection, "compatible-key"),
        connection_id: Some(connection),
    });
    std::fs::write(fixture.project.join("notes.txt"), "compatible notes\n").expect("notes");
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("read notes".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(text_of(&events), "finished reading with compatible");
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/v1/chat/completions");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer compatible-key")
    );
    assert_eq!(requests[0].json()["stream"], true);
    assert_eq!(requests[0].json()["model"], "local-test");
    assert!(requests[1].body.contains("compatible notes"));
}

fn chatgpt_fixture(
    server: &MockServer,
    model: &'static str,
    connection: ConnectionId,
    credentials: Arc<dyn CredentialPort + Send + Sync>,
) -> Fixture {
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model,
        auth: AuthMethod::ChatGptLogin,
        endpoint: None,
        endpoints,
        credentials,
        connection_id: Some(connection),
    })
}

#[test]
fn chatgpt_uses_the_public_catalog_and_completed_responses_stream() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![responses_text("hello from chatgpt")]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |request| {
            if request.method == "GET" && request.path == "/v1/models" {
                return catalog_response(json!([
                    {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"},
                    {"slug": "hidden-model", "display_name": "Hidden", "visibility": "none"},
                    {"slug": "gpt-6.1-mini", "display_name": "GPT 6.1 Mini", "visibility": "list"}
                ]));
            }
            assert_eq!(request.path, "/v1/responses");
            responses.next()
        }
    });
    let fixture = chatgpt_fixture(
        &server,
        "gpt-6.1-sol",
        connection,
        Arc::new(RotatingCredentials::new(
            connection,
            ["oauth-access-canary".to_owned()],
        )),
    );
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("say hello".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(text_of(&events), "hello from chatgpt");
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/v1/models");
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer oauth-access-canary")
    );
    let body = requests[1].json();
    assert_eq!(requests[1].method, "POST");
    assert_eq!(requests[1].path, "/v1/responses");
    assert_eq!(body["model"], "gpt-6.1-sol");
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], true);
    assert!(
        requests
            .iter()
            .all(|request| !request.path.contains("backend-api"))
    );
    // The catalog returned a second listed model; the adapter must not switch
    // to it.
    assert_eq!(body["model"], "gpt-6.1-sol");
}

#[test]
fn chatgpt_unlisted_model_fails_before_inference() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |request| {
        assert_eq!(request.path, "/v1/models");
        catalog_response(json!([
            {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"}
        ]))
    });
    let fixture = chatgpt_fixture(
        &server,
        "hidden-model",
        connection,
        Arc::new(RotatingCredentials::new(
            connection,
            ["oauth-access-canary".to_owned()],
        )),
    );
    let (_, _, _run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    let error = engine.start(start).expect_err("unlisted model must fail");
    assert!(matches!(
        error,
        herness_core::CoreError::ProviderFailure {
            failure: herness_core::ProviderFailureKind::Refused,
            ..
        }
    ));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/models");
}

#[test]
fn chatgpt_incomplete_response_is_a_failure() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![responses_incomplete()]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |request| {
            if request.path == "/v1/models" {
                catalog_response(json!([
                    {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"}
                ]))
            } else {
                responses.next()
            }
        }
    });
    let fixture = chatgpt_fixture(
        &server,
        "gpt-6.1-sol",
        connection,
        Arc::new(RotatingCredentials::new(
            connection,
            ["oauth-access-canary".to_owned()],
        )),
    );
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("say hello".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(events.iter().any(|event| matches!(
        event,
        EngineEvent::Failure {
            failure: herness_core::EngineFailureKind::InvalidResponse
        }
    )));
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Failed)));
    assert!(!events.contains(&EngineEvent::StateChanged(RunState::Idle)));
}

#[test]
fn chatgpt_early_disconnect_is_a_failure() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![responses_early_disconnect("partial answer")]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |request| {
            if request.path == "/v1/models" {
                catalog_response(json!([
                    {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"}
                ]))
            } else {
                responses.next()
            }
        }
    });
    let fixture = chatgpt_fixture(
        &server,
        "gpt-6.1-sol",
        connection,
        Arc::new(RotatingCredentials::new(
            connection,
            ["oauth-access-canary".to_owned()],
        )),
    );
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("say hello".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, EngineEvent::Failure { .. }))
    );
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Failed)));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, EngineEvent::TextCompleted { .. }))
    );
}

#[test]
fn chatgpt_failed_usage_limit_is_a_failure() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![responses_failed(
        "subscription_sharing_usage_limit_exceeded",
    )]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |request| {
            if request.path == "/v1/models" {
                catalog_response(json!([
                    {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"}
                ]))
            } else {
                responses.next()
            }
        }
    });
    let fixture = chatgpt_fixture(
        &server,
        "gpt-6.1-sol",
        connection,
        Arc::new(RotatingCredentials::new(
            connection,
            ["oauth-access-canary".to_owned()],
        )),
    );
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("say hello".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Failed)));
    let requests = server.requests();
    assert!(
        requests
            .iter()
            .all(|request| !request.path.contains("backend-api"))
    );
}

#[test]
fn chatgpt_catalog_auth_failure_prevents_inference() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |request| {
        assert_eq!(request.path, "/v1/models");
        MockResponse::empty(401)
    });
    let fixture = chatgpt_fixture(
        &server,
        "gpt-6.1-sol",
        connection,
        Arc::new(RotatingCredentials::new(
            connection,
            ["oauth-access-canary".to_owned()],
        )),
    );
    let (_, _, _run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    let error = engine.start(start).expect_err("catalog auth failure");
    assert!(matches!(
        error,
        herness_core::CoreError::ProviderFailure {
            failure: herness_core::ProviderFailureKind::Authentication,
            ..
        }
    ));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/models");
}

#[test]
fn openai_auth_failure_is_reported_without_success() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |_request| MockResponse::empty(401));
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-rejected"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("hello".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, EngineEvent::Failure { .. }))
    );
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Failed)));
    assert!(!events.contains(&EngineEvent::StateChanged(RunState::Idle)));
}

#[test]
fn anthropic_auth_failure_is_reported_without_success() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |_request| MockResponse::empty(401));
    let endpoints = ProviderEndpoints::for_loopback(server.url(), server.url()).expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::Anthropic,
        model: "claude-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "claude-rejected"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("hello".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, EngineEvent::Failure { .. }))
    );
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Failed)));
}

#[test]
fn openai_compatible_auth_failure_is_reported_without_success() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |_request| MockResponse::empty(401));
    let endpoint = format!("{}/v1", server.url());
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAiCompatible,
        model: "local-test",
        auth: AuthMethod::ApiKey,
        endpoint: Some(endpoint),
        endpoints: ProviderEndpoints::official(),
        credentials: default_credentials(connection, "compatible-rejected"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("hello".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, EngineEvent::Failure { .. }))
    );
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Failed)));
}

#[test]
fn cancellation_stops_a_slow_provider_request() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |_request| {
        responses_text("too late").delayed(Duration::from_secs(5))
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-cancel"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("hello".to_owned()))
        .expect("input");
    wait_for_requests(&server, 1);
    let report = engine
        .request_stop(&run, StopReason::UserRequest)
        .expect("stop request");
    assert_eq!(report, StopReport::Stopped);
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Interrupted)));
    assert!(!events.contains(&EngineEvent::StateChanged(RunState::Idle)));
    assert!(!events.iter().any(|event| matches!(
        event,
        EngineEvent::TextCompleted { text } if text.contains("too late")
    )));
}

#[test]
fn sqlite_saves_intent_and_engine_checkpoint_before_the_side_effect() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_tool_call(
            "call_bash_order",
            "fc_bash_order",
            "bash",
            json!({"command": "printf 'order' > order.txt", "purpose": "create the order fixture"}),
        ),
        responses_text("order created"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-order"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("create order".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(text_of(&events), "order created");
    assert_eq!(
        std::fs::read_to_string(fixture.project.join("order.txt")).expect("order file"),
        "order"
    );

    let stored = {
        let store = fixture.store.lock().expect("store");
        store
            .events_after(
                &fixture.project_id,
                None,
                HistoryLimit::new(500).expect("limit"),
            )
            .expect("events")
    };
    let operation_id = stored
        .iter()
        .find(|event| event.kind().as_str() == "engine.tool.intent")
        .and_then(herness_core::Event::operation_id)
        .expect("tool intent event");
    let kinds: Vec<&str> = stored
        .iter()
        .filter(|event| event.operation_id() == Some(operation_id))
        .map(|event| event.kind().as_str())
        .collect();
    assert_eq!(
        kinds,
        vec![
            "engine.tool.intent",
            "shell.started",
            "shell.spawned",
            "shell.finished"
        ]
    );
    assert!(stored.iter().any(|event| {
        event.kind().as_str() == "engine.checkpoint"
            && event.payload().as_value()["sdkSequence"].is_number()
    }));

    let checkpoint = {
        let store = fixture.store.lock().expect("store");
        store
            .load_checkpoint_record(&run)
            .expect("checkpoint")
            .expect("checkpoint present")
    };
    let payload = String::from_utf8_lossy(checkpoint.checkpoint().payload().as_bytes());
    assert!(payload.contains("\"engine\":\"pi-embedded\""));
    assert!(!payload.contains("herness.shell-operation"));

    let record = {
        let store = fixture.store.lock().expect("store");
        store
            .operation(&operation_id)
            .expect("operation")
            .expect("record")
    };
    let result = record.result().expect("durable result");
    assert_eq!(result.outcome(), OperationOutcome::Applied);
    assert!(
        store_has_no_pending(&fixture.store, fixture.project_id),
        "the completed shell operation must not remain pending"
    );
}

fn store_has_no_pending(store: &Arc<Mutex<Store>>, project: ProjectId) -> bool {
    let store = store.lock().expect("store");
    store
        .pending_operations(&project)
        .expect("pending operations")
        .is_empty()
}

#[test]
fn history_and_event_redelivery_do_not_reexecute_a_tool() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_tool_call(
            "call_bash_redelivery",
            "fc_bash_redelivery",
            "bash",
            json!({"command": "printf 'tick\\n' >> ticks.txt", "purpose": "append one tick"}),
        ),
        responses_text("tick appended"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-redelivery"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("append tick".to_owned()))
        .expect("input");
    let _ = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));

    let first: Vec<u64> = {
        let store = fixture.store.lock().expect("store");
        store
            .events_after(
                &fixture.project_id,
                None,
                HistoryLimit::new(500).expect("limit"),
            )
            .expect("events")
            .iter()
            .map(herness_core::Event::sequence)
            .collect()
    };
    let second: Vec<u64> = {
        let store = fixture.store.lock().expect("store");
        store
            .events_after(
                &fixture.project_id,
                None,
                HistoryLimit::new(500).expect("limit"),
            )
            .expect("events")
            .iter()
            .map(herness_core::Event::sequence)
            .collect()
    };
    assert_eq!(first, second, "reading history must not append events");
    assert!(
        engine.poll_events(&run).expect("poll").is_empty(),
        "a drained event queue must stay drained"
    );
    let ticks = std::fs::read_to_string(fixture.project.join("ticks.txt")).expect("ticks");
    assert_eq!(
        ticks, "tick\n",
        "redelivery must not execute the shell again"
    );
}

#[test]
fn duplicate_tool_call_ids_fail_without_a_side_effect() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![responses_duplicate_tool_calls(
        "call_dup",
        "fc_dup",
        "bash",
        json!({"command": "printf 'dup' > duplicate.txt", "purpose": "must never run"}),
    )]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-duplicate"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("do the thing".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Failed)));
    assert!(!fixture.project.join("duplicate.txt").exists());
    let stored = {
        let store = fixture.store.lock().expect("store");
        store
            .events_after(
                &fixture.project_id,
                None,
                HistoryLimit::new(500).expect("limit"),
            )
            .expect("events")
    };
    assert!(
        !stored
            .iter()
            .any(|event| event.kind().as_str() == "engine.tool.intent")
    );
}

#[test]
fn stop_mid_tool_prevents_a_late_side_effect_and_restore_does_not_resend() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![responses_tool_call(
        "call_bash_stop",
        "fc_bash_stop",
        "bash",
        json!({"command": "sleep 5; printf 'late' > late.txt", "purpose": "slow write that stop must prevent"}),
    )]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-stop"),
        connection_id: Some(connection),
    });
    let Fixture {
        _temp,
        project,
        project_id,
        store,
        engine,
        connection: _,
        directory,
        credentials,
        endpoints,
        policy,
    } = fixture;
    let (_, _, run, start) = {
        let cwd = AbsolutePath::new(project.to_string_lossy().into_owned()).expect("cwd");
        let agent = AgentId::new(project_id);
        let session = SessionId::new(project_id);
        let run = RunId::new(project_id);
        let start = EngineStart::new(
            project_id,
            agent,
            session,
            run,
            connection,
            cwd,
            "stop test",
        )
        .expect("start");
        (agent, session, run, start)
    };
    let mut engine = engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("run the slow command".to_owned()))
        .expect("input");
    let _ = wait_for_event_kind(&store, project_id, "shell.spawned");
    let report = engine
        .request_stop(&run, StopReason::UserRequest)
        .expect("stop");
    assert_eq!(report, StopReport::Stopped);
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Interrupted)));
    assert!(
        !project.join("late.txt").exists(),
        "late side effect must not occur"
    );
    let checkpoint = engine
        .checkpoint(&run)
        .expect("checkpoint")
        .expect("checkpoint present");
    let payload = String::from_utf8_lossy(checkpoint.payload().as_bytes()).into_owned();
    assert!(payload.contains("\"status\":\"interrupted\""));
    assert!(payload.contains("\"phase\":\"completed\""));
    assert!(payload.contains("\"needsResponse\":true"));

    let requests_before = server.request_count();
    let mut restarted = restart_engine(store, credentials, directory, endpoints, policy);
    restarted.resume(&run, checkpoint).expect("resume");
    assert_eq!(
        server.request_count(),
        requests_before,
        "restoring must not send a provider request"
    );
    let restored_events: Vec<EngineEvent> = restarted.poll_events(&run).expect("poll");
    assert!(restored_events.contains(&EngineEvent::StateChanged(RunState::Interrupted)));
    assert!(
        restarted
            .send_input(&run, EngineInput::Text("continue".to_owned()))
            .is_err()
    );
    thread::sleep(Duration::from_millis(100));
    assert!(!project.join("late.txt").exists());
    drop(_temp);
}

fn responses_bad_tool_arguments(
    call_id: &str,
    item_id: &str,
    name: &str,
    arguments: &str,
) -> MockResponse {
    let item = json!({
        "type": "function_call",
        "id": item_id,
        "call_id": call_id,
        "name": name,
        "arguments": arguments
    });
    let mut body = String::new();
    body.push_str(&sse(
        "response.created",
        json!({"type": "response.created", "response": {"id": "resp_bad"}}),
    ));
    body.push_str(&sse(
        "response.output_item.added",
        json!({"type": "response.output_item.added", "output_index": 0, "item": item}),
    ));
    body.push_str(&sse(
        "response.function_call_arguments.delta",
        json!({"type": "response.function_call_arguments.delta", "output_index": 0, "delta": arguments}),
    ));
    body.push_str(&sse(
        "response.output_item.done",
        json!({"type": "response.output_item.done", "output_index": 0, "item": item}),
    ));
    body.push_str(&sse(
        "response.completed",
        json!({
            "type": "response.completed",
            "response": {"id": "resp_bad", "status": "completed", "output": [item]}
        }),
    ));
    MockResponse::sse(body)
}

#[test]
fn partial_tool_arguments_never_reach_the_gateway() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_bad_tool_arguments(
            "call_partial",
            "fc_partial",
            "bash",
            "{\"command\":\"printf 'partial' > partial.txt\"",
        ),
        responses_text("partial rejected"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-partial"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("do a partial thing".to_owned()))
        .expect("input");
    let _ = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(
        !fixture.project.join("partial.txt").exists(),
        "incomplete arguments must never execute"
    );
}

#[test]
fn multiple_sessions_do_not_share_conversation_state() {
    let temp = tempfile::tempdir().expect("temp");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("project");
    let project_id = ProjectId::new();
    let config = StoreConfig::new(temp.path().join("app")).expect("config");
    let store = Arc::new(Mutex::new(Store::open(config).expect("store")));
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let connection_a = ConnectionId::new();
    let connection_b = ConnectionId::new();
    for (connection, model) in [(connection_a, "model-a"), (connection_b, "model-b")] {
        admin
            .add(
                ConnectionSettings::new(
                    connection,
                    Provider::OpenAi,
                    model,
                    AuthMethod::ApiKey,
                    None,
                    None,
                )
                .expect("settings"),
            )
            .expect("add");
    }
    let server = MockServer::start(move |request| {
        let model = request.json()["model"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if model == "model-a" {
            responses_text("alpha reply")
        } else {
            responses_text("beta reply")
        }
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let credentials = Arc::new(RotatingCredentials::new(connection_a, ["key-a".to_owned()]));
    credentials.insert(connection_b, ["key-b".to_owned()]);
    let mut engine = PiEngine::new(
        Arc::clone(&store),
        credentials,
        directory,
        PiEngineConfig::new(allow_all_policy()).with_endpoints(endpoints),
    )
    .expect("engine");
    let cwd = AbsolutePath::new(project.to_string_lossy().into_owned()).expect("cwd");
    let agent_a = AgentId::new(project_id);
    let session_a = SessionId::new(project_id);
    let run_a = RunId::new(project_id);
    let start_a = EngineStart::new(
        project_id,
        agent_a,
        session_a,
        run_a,
        connection_a,
        cwd.clone(),
        "alpha agent",
    )
    .expect("start a");
    let agent_b = AgentId::new(project_id);
    let session_b = SessionId::new(project_id);
    let run_b = RunId::new(project_id);
    let start_b = EngineStart::new(
        project_id,
        agent_b,
        session_b,
        run_b,
        connection_b,
        cwd,
        "beta agent",
    )
    .expect("start b");
    engine.start(start_a).expect("start a");
    engine.start(start_b).expect("start b");
    let _ = engine.poll_events(&run_a);
    let _ = engine.poll_events(&run_b);
    engine
        .send_input(&run_a, EngineInput::Text("alpha request".to_owned()))
        .expect("input a");
    engine
        .send_input(&run_b, EngineInput::Text("beta request".to_owned()))
        .expect("input b");
    let events_a = collect_until_terminal(&mut engine, &run_a, Duration::from_secs(10));
    let events_b = collect_until_terminal(&mut engine, &run_b, Duration::from_secs(10));
    assert_eq!(text_of(&events_a), "alpha reply");
    assert_eq!(text_of(&events_b), "beta reply");
    assert!(!text_of(&events_a).contains("beta"));
    assert!(!text_of(&events_b).contains("alpha"));

    let checkpoint_a = {
        let store = store.lock().expect("store");
        store
            .load_checkpoint_record(&run_a)
            .expect("checkpoint a")
            .expect("present")
    };
    let checkpoint_b = {
        let store = store.lock().expect("store");
        store
            .load_checkpoint_record(&run_b)
            .expect("checkpoint b")
            .expect("present")
    };
    let text_a =
        String::from_utf8_lossy(checkpoint_a.checkpoint().payload().as_bytes()).into_owned();
    let text_b =
        String::from_utf8_lossy(checkpoint_b.checkpoint().payload().as_bytes()).into_owned();
    assert!(text_a.contains("alpha reply"));
    assert!(!text_a.contains("beta reply"));
    assert!(text_b.contains("beta reply"));
    assert!(!text_b.contains("alpha reply"));
    assert_ne!(
        checkpoint_a.checkpoint().run_id(),
        checkpoint_b.checkpoint().run_id()
    );
}

#[test]
fn secrets_never_reach_the_checkpoint_events_or_database() {
    let temp = tempfile::tempdir().expect("temp");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("project");
    let project_id = ProjectId::new();
    let store_config = StoreConfig::new(temp.path().join("app")).expect("config");
    let database_path = store_config.database_path();
    let store = Arc::new(Mutex::new(Store::open(store_config).expect("store")));
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let connection = ConnectionId::new();
    admin
        .add(
            ConnectionSettings::new(
                connection,
                Provider::OpenAi,
                "gpt-test",
                AuthMethod::ApiKey,
                None,
                None,
            )
            .expect("settings"),
        )
        .expect("add");
    let service = CredentialService::new(directory.clone(), TestVault::default());
    let canary = "sk-canary-never-store-this-value";
    service
        .admin()
        .save_api_key(connection, SecretString::new(canary).expect("secret"))
        .expect("save api key");
    let server = MockServer::start(move |_request| responses_text("canary turn"));
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let mut engine = PiEngine::new(
        Arc::clone(&store),
        Arc::new(service.broker()),
        directory,
        PiEngineConfig::new(allow_all_policy()).with_endpoints(endpoints),
    )
    .expect("engine");
    let cwd = AbsolutePath::new(project.to_string_lossy().into_owned()).expect("cwd");
    let agent = AgentId::new(project_id);
    let session = SessionId::new(project_id);
    let run = RunId::new(project_id);
    let start = EngineStart::new(
        project_id,
        agent,
        session,
        run,
        connection,
        cwd,
        "canary agent",
    )
    .expect("start");
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("hello".to_owned()))
        .expect("input");
    let _ = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(
        server.requests()[0].header("authorization"),
        Some("Bearer sk-canary-never-store-this-value")
    );

    let checkpoint = {
        let store = store.lock().expect("store");
        store
            .load_checkpoint_record(&run)
            .expect("checkpoint")
            .expect("present")
    };
    let checkpoint_text =
        String::from_utf8_lossy(checkpoint.checkpoint().payload().as_bytes()).into_owned();
    assert!(!checkpoint_text.contains(canary));
    let events = {
        let store = store.lock().expect("store");
        store
            .events_after(&project_id, None, HistoryLimit::new(500).expect("limit"))
            .expect("events")
    };
    for event in &events {
        assert!(!event.payload().as_value().to_string().contains(canary));
    }
    let operations = {
        let store = store.lock().expect("store");
        store.pending_operations(&project_id).expect("pending")
    };
    for operation in &operations {
        assert!(!format!("{operation:?}").contains(canary));
    }
    let db = std::fs::read(&database_path).expect("database");
    assert!(!contains_bytes(&db, canary.as_bytes()));
    let wal = database_path.with_file_name("herness.sqlite3-wal");
    if let Ok(bytes) = std::fs::read(&wal) {
        assert!(!contains_bytes(&bytes, canary.as_bytes()));
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn credentials_are_resolved_for_every_provider_request() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_tool_call(
            "call_read_key",
            "fc_read_key",
            "read",
            json!({"path": "notes.txt"}),
        ),
        responses_text("two requests"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: Arc::new(RotatingCredentials::new(
            connection,
            ["key-one".to_owned(), "key-two".to_owned()],
        )),
        connection_id: Some(connection),
    });
    std::fs::write(fixture.project.join("notes.txt"), "notes").expect("notes");
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("read notes".to_owned()))
        .expect("input");
    let _ = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].header("authorization"), Some("Bearer key-one"));
    assert_eq!(requests[1].header("authorization"), Some("Bearer key-two"));
}

#[test]
fn unknown_checkpoint_versions_are_rejected_and_preserved() {
    let temp = tempfile::tempdir().expect("temp");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("project");
    let project_id = ProjectId::new();
    let config = StoreConfig::new(temp.path().join("app"))
        .expect("config")
        .accept_checkpoint_format(CheckpointFormatVersion::new(2).expect("version"));
    let store = Arc::new(Mutex::new(Store::open(config).expect("store")));
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let connection = ConnectionId::new();
    admin
        .add(
            ConnectionSettings::new(
                connection,
                Provider::OpenAi,
                "gpt-test",
                AuthMethod::ApiKey,
                None,
                None,
            )
            .expect("settings"),
        )
        .expect("add");
    let server = MockServer::start(move |_request| responses_text("version turn"));
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let credentials: Arc<dyn CredentialPort + Send + Sync> =
        default_credentials(connection, "sk-version");
    let mut engine = PiEngine::new(
        Arc::clone(&store),
        Arc::clone(&credentials),
        directory.clone(),
        PiEngineConfig::new(allow_all_policy()).with_endpoints(endpoints.clone()),
    )
    .expect("engine");
    let cwd = AbsolutePath::new(project.to_string_lossy().into_owned()).expect("cwd");
    let agent = AgentId::new(project_id);
    let session = SessionId::new(project_id);
    let run = RunId::new(project_id);
    let start = EngineStart::new(
        project_id,
        agent,
        session,
        run,
        connection,
        cwd,
        "version agent",
    )
    .expect("start");
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("hello".to_owned()))
        .expect("input");
    let _ = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    let v1 = engine
        .checkpoint(&run)
        .expect("checkpoint")
        .expect("present");
    let v2 = Checkpoint::new(
        run,
        CheckpointFormatVersion::new(2).expect("version"),
        v1.payload().clone(),
    );
    {
        let mut store = store.lock().expect("store");
        store
            .commit_checkpoint(CheckpointCommit::new(v2.clone(), None, Vec::new()).expect("commit"))
            .expect("commit v2");
    }
    let mut restarted = restart_engine(
        store.clone(),
        credentials,
        directory,
        endpoints,
        allow_all_policy(),
    );
    let error = restarted.resume(&run, v2).expect_err("unknown version");
    assert!(matches!(
        error,
        herness_core::CoreError::EngineUnavailable {
            failure: herness_core::EngineFailureKind::CheckpointUnavailable
        }
    ));
    let stored = {
        let store = store.lock().expect("store");
        store
            .load_checkpoint_record(&run)
            .expect("checkpoint")
            .expect("present")
    };
    assert_eq!(stored.checkpoint().format_version().get(), 2);
}

#[test]
fn configured_mode_without_an_allow_rule_waits_and_never_executes() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_tool_call(
            "call_bash_wait",
            "fc_bash_wait",
            "bash",
            json!({"command": "printf 'denied' > denied.txt", "purpose": "must not run without approval"}),
        ),
        responses_text("approval required"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with_policy(
        FixtureOptions {
            provider: Provider::OpenAi,
            model: "gpt-test",
            auth: AuthMethod::ApiKey,
            endpoint: None,
            endpoints,
            credentials: default_credentials(connection, "sk-wait"),
            connection_id: Some(connection),
        },
        PermissionPolicy::initial(),
    );
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("try a bash command".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(text_of(&events), "approval required");
    assert!(!fixture.project.join("denied.txt").exists());
    let stored = {
        let store = fixture.store.lock().expect("store");
        store
            .events_after(
                &fixture.project_id,
                None,
                HistoryLimit::new(500).expect("limit"),
            )
            .expect("events")
    };
    assert!(
        stored
            .iter()
            .any(|event| event.kind().as_str() == "engine.tool.awaiting_approval")
    );
    assert!(
        !stored
            .iter()
            .any(|event| event.kind().as_str() == "engine.tool.intent")
    );
    let pending = {
        let store = fixture.store.lock().expect("store");
        store
            .pending_operations(&fixture.project_id)
            .expect("pending")
    };
    assert!(pending.is_empty());
}

#[test]
fn write_tool_records_a_rationale_and_a_durable_file_change() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_tool_call(
            "call_write",
            "fc_write",
            "write",
            json!({
                "path": "created.txt",
                "content": "hello from the engine",
                "rationale": "create the engine fixture"
            }),
        ),
        responses_text("file written"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-write"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("create a file".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(text_of(&events), "file written");
    assert_eq!(
        std::fs::read_to_string(fixture.project.join("created.txt")).expect("created"),
        "hello from the engine"
    );
    let stored = {
        let store = fixture.store.lock().expect("store");
        store
            .events_after(
                &fixture.project_id,
                None,
                HistoryLimit::new(500).expect("limit"),
            )
            .expect("events")
    };
    assert!(stored.iter().any(|event| {
        event.kind().as_str() == "file.change.intended"
            && event.payload().as_value()["rationale"] == "create the engine fixture"
    }));
    assert!(
        stored
            .iter()
            .any(|event| event.kind().as_str() == "file.change")
    );
}

#[test]
fn chatgpt_tool_round_trip_uses_the_public_responses_path() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_tool_call(
            "call_read_chatgpt",
            "fc_read_chatgpt",
            "read",
            json!({"path": "notes.txt"}),
        ),
        responses_text("chatgpt read the notes"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |request| {
            if request.path == "/v1/models" {
                catalog_response(json!([
                    {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"}
                ]))
            } else {
                responses.next()
            }
        }
    });
    let fixture = chatgpt_fixture(
        &server,
        "gpt-6.1-sol",
        connection,
        Arc::new(RotatingCredentials::new(
            connection,
            ["oauth-tool-canary".to_owned()],
        )),
    );
    std::fs::write(fixture.project.join("notes.txt"), "chatgpt notes\n").expect("notes");
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("read notes".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(text_of(&events), "chatgpt read the notes");
    let requests = server.requests();
    assert_eq!(requests.len(), 3, "catalog + two inference requests");
    assert_eq!(requests[0].path, "/v1/models");
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.path == "/v1/responses")
    );
    assert!(requests[2].body.contains("chatgpt notes"));
    assert!(
        requests
            .iter()
            .all(|request| !request.path.contains("backend-api"))
    );
}

fn cancel_slow_fixture(fixture: Fixture, server: &MockServer, expected_requests: usize) {
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("slow request".to_owned()))
        .expect("input");
    wait_for_requests(server, expected_requests);
    let report = engine
        .request_stop(&run, StopReason::ApplicationQuit)
        .expect("stop");
    assert_eq!(report, StopReport::Stopped);
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Interrupted)));
}

#[test]
fn anthropic_cancellation_interrupts_the_stream() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |_request| {
        anthropic_text("too late").delayed(Duration::from_secs(5))
    });
    let endpoints = ProviderEndpoints::for_loopback(server.url(), server.url()).expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::Anthropic,
        model: "claude-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "claude-cancel"),
        connection_id: Some(connection),
    });
    cancel_slow_fixture(fixture, &server, 1);
}

#[test]
fn openai_compatible_cancellation_interrupts_the_stream() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |_request| {
        completions_text("too late").delayed(Duration::from_secs(5))
    });
    let endpoint = format!("{}/v1", server.url());
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAiCompatible,
        model: "local-test",
        auth: AuthMethod::ApiKey,
        endpoint: Some(endpoint),
        endpoints: ProviderEndpoints::official(),
        credentials: default_credentials(connection, "compatible-cancel"),
        connection_id: Some(connection),
    });
    cancel_slow_fixture(fixture, &server, 1);
}

#[test]
fn chatgpt_cancellation_interrupts_the_stream() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |request| {
        if request.path == "/v1/models" {
            catalog_response(json!([
                {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"}
            ]))
        } else {
            responses_text("too late").delayed(Duration::from_secs(5))
        }
    });
    let fixture = chatgpt_fixture(
        &server,
        "gpt-6.1-sol",
        connection,
        Arc::new(RotatingCredentials::new(
            connection,
            ["oauth-cancel-canary".to_owned()],
        )),
    );
    cancel_slow_fixture(fixture, &server, 2);
}

#[test]
fn chatgpt_restore_makes_no_network_request() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![responses_text("restored chatgpt turn")]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |request| {
            if request.path == "/v1/models" {
                catalog_response(json!([
                    {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"}
                ]))
            } else {
                responses.next()
            }
        }
    });
    let fixture = chatgpt_fixture(
        &server,
        "gpt-6.1-sol",
        connection,
        Arc::new(RotatingCredentials::new(
            connection,
            ["oauth-restore-canary".to_owned()],
        )),
    );
    let Fixture {
        _temp,
        project: _project,
        project_id: _project_id,
        store,
        engine,
        connection: _connection,
        directory,
        credentials,
        endpoints,
        policy,
    } = fixture;
    let (_, _, run, start) = {
        let cwd = AbsolutePath::new(_project.to_string_lossy().into_owned()).expect("cwd");
        let agent = AgentId::new(_project_id);
        let session = SessionId::new(_project_id);
        let run = RunId::new(_project_id);
        let start = EngineStart::new(
            _project_id,
            agent,
            session,
            run,
            connection,
            cwd,
            "restore agent",
        )
        .expect("start");
        (agent, session, run, start)
    };
    let mut engine = engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("hello".to_owned()))
        .expect("input");
    let _ = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    let checkpoint = engine
        .checkpoint(&run)
        .expect("checkpoint")
        .expect("present");
    let requests_before = server.request_count();
    let mut restarted = restart_engine(store, credentials, directory, endpoints, policy);
    restarted.resume(&run, checkpoint).expect("resume");
    assert_eq!(
        server.request_count(),
        requests_before,
        "restore must not call the catalog or the model"
    );
}

#[test]
fn chatgpt_inference_auth_failure_is_reported_without_success() {
    let connection = ConnectionId::new();
    let server = MockServer::start(move |request| {
        if request.path == "/v1/models" {
            catalog_response(json!([
                {"slug": "gpt-6.1-sol", "display_name": "GPT 6.1 Sol", "visibility": "list"}
            ]))
        } else {
            MockResponse::empty(401)
        }
    });
    let fixture = chatgpt_fixture(
        &server,
        "gpt-6.1-sol",
        connection,
        Arc::new(RotatingCredentials::new(
            connection,
            ["oauth-rejected".to_owned()],
        )),
    );
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("hello".to_owned()))
        .expect("input");
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Failed)));
    assert!(!events.contains(&EngineEvent::StateChanged(RunState::Idle)));
}

// ---------------------------------------------------------------------------
// H2 continuation and recovery gates
// ---------------------------------------------------------------------------

fn rewritten_checkpoint(
    checkpoint: &Checkpoint,
    run: RunId,
    mutate: impl FnOnce(&mut Value),
) -> Checkpoint {
    let mut value: Value =
        serde_json::from_slice(checkpoint.payload().as_bytes()).expect("checkpoint envelope");
    value["runId"] = json!(run.to_string());
    mutate(&mut value);
    Checkpoint::new(
        run,
        checkpoint.format_version(),
        CheckpointPayload::new(serde_json::to_vec(&value).expect("rewritten envelope")),
    )
}

fn continuation_start(previous: &EngineStart, run: RunId) -> EngineStart {
    EngineStart::new(
        previous.project_id(),
        previous.agent_id(),
        previous.session_id(),
        run,
        previous.connection(),
        previous.cwd().clone(),
        previous.instructions(),
    )
    .expect("continuation start")
}

#[test]
fn continuation_preserves_the_previous_conversation_in_a_new_run() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_text("The access code is ORANGE-42."),
        responses_text("The access code is ORANGE-42."),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-continuation"),
        connection_id: Some(connection),
    });
    let (_, _, run1, start1) = engine_start(&fixture, "You are a test agent.");
    let mut engine = fixture.engine;

    engine.start(start1.clone()).expect("first start");
    let _ = engine.poll_events(&run1);
    engine
        .send_input(
            &run1,
            EngineInput::Text("Remember this fact: the access code is ORANGE-42.".to_owned()),
        )
        .expect("first input");
    let first_events = collect_until_terminal(&mut engine, &run1, Duration::from_secs(10));
    assert_eq!(text_of(&first_events), "The access code is ORANGE-42.");
    let checkpoint1 = engine
        .checkpoint(&run1)
        .expect("checkpoint")
        .expect("checkpoint present");

    let run2 = RunId::new(start1.project_id());
    let start2 = continuation_start(&start1, run2);
    assert_ne!(run1, run2);
    engine
        .check_continuation(&start2, &checkpoint1)
        .expect("continuation preflight");
    engine
        .start_continuation(start2, checkpoint1.clone())
        .expect("continuation start");

    // The new run's recovery publication is a startup idle, never completion.
    let startup = engine.poll_events(&run2).expect("startup events");
    assert!(startup.contains(&EngineEvent::StateChanged(RunState::Idle)));

    engine
        .send_input(
            &run2,
            EngineInput::Text("What is the access code?".to_owned()),
        )
        .expect("second input");
    let second_events = collect_until_terminal(&mut engine, &run2, Duration::from_secs(10));
    assert_eq!(text_of(&second_events), "The access code is ORANGE-42.");
    assert_eq!(server.request_count(), 2);

    let requests = server.requests();
    let second_request = requests[1].json().to_string();
    assert!(
        second_request.contains("ORANGE-42"),
        "the second request must see the first run's conversation: {second_request}"
    );
    assert!(
        second_request.contains("Remember this fact"),
        "the first user turn must be preserved"
    );

    let checkpoint2 = engine
        .checkpoint(&run2)
        .expect("checkpoint")
        .expect("checkpoint present");
    let envelope1: Value =
        serde_json::from_slice(checkpoint1.payload().as_bytes()).expect("first envelope");
    let envelope2: Value =
        serde_json::from_slice(checkpoint2.payload().as_bytes()).expect("second envelope");
    assert_eq!(envelope1["runId"], json!(run1.to_string()));
    assert_eq!(envelope2["runId"], json!(run2.to_string()));
    assert_eq!(
        envelope2["sessionId"],
        json!(start1.session_id().to_string())
    );
    assert!(
        envelope2["snapshot"]["messages"]
            .to_string()
            .contains("ORANGE-42"),
        "the new run's checkpoint must carry the conversation"
    );
    assert_eq!(
        engine.checkpoint(&run1).unwrap().unwrap().run_id(),
        run1,
        "the previous run's checkpoint must not be rewritten"
    );
}

#[test]
fn continuation_tool_events_and_checkpoints_belong_to_the_new_run() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_text("first answer"),
        responses_tool_call(
            "call_cont_write",
            "fc_cont_write",
            "write",
            json!({
                "path": "created.txt",
                "content": "tool facts",
                "rationale": "record a continuation tool fact"
            }),
        ),
        responses_text("file written"),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-continuation-tool"),
        connection_id: Some(connection),
    });
    std::fs::write(fixture.project.join("notes.txt"), "tool facts").expect("notes");
    let (_, _, run1, start1) = engine_start(&fixture, "You are a test agent.");
    let store = Arc::clone(&fixture.store);
    let project = fixture.project_id;
    let mut engine = fixture.engine;

    engine.start(start1.clone()).expect("first start");
    let _ = engine.poll_events(&run1);
    engine
        .send_input(&run1, EngineInput::Text("first turn".to_owned()))
        .expect("first input");
    let _ = collect_until_terminal(&mut engine, &run1, Duration::from_secs(10));
    let checkpoint1 = engine
        .checkpoint(&run1)
        .expect("checkpoint")
        .expect("checkpoint present");

    let run2 = RunId::new(project);
    let start2 = continuation_start(&start1, run2);
    engine
        .start_continuation(start2, checkpoint1)
        .expect("continuation start");
    let _ = engine.poll_events(&run2);
    engine
        .send_input(&run2, EngineInput::Text("write the notes".to_owned()))
        .expect("second input");
    let _ = collect_until_terminal(&mut engine, &run2, Duration::from_secs(10));
    assert_eq!(
        std::fs::read_to_string(fixture.project.join("created.txt")).expect("created file"),
        "tool facts"
    );

    let events = {
        let store = store.lock().expect("store");
        store
            .events_after(&project, None, HistoryLimit::new(500).expect("limit"))
            .expect("events")
    };
    let intents: Vec<_> = events
        .iter()
        .filter(|event| event.kind().as_str() == "engine.tool.intent")
        .collect();
    assert_eq!(intents.len(), 1, "one tool call in the continuation run");
    assert_eq!(
        intents[0].run_id(),
        Some(run2),
        "the tool operation must belong to the new run"
    );
    assert!(intents[0].operation_id().is_some());

    let checkpoint2 = engine
        .checkpoint(&run2)
        .expect("checkpoint")
        .expect("checkpoint present");
    let envelope2: Value =
        serde_json::from_slice(checkpoint2.payload().as_bytes()).expect("second envelope");
    assert_eq!(envelope2["runId"], json!(run2.to_string()));
    assert_eq!(engine.checkpoint(&run1).unwrap().unwrap().run_id(), run1);
}

#[test]
fn continuation_refuses_missing_unstable_or_pending_checkpoints_without_sending() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![responses_text("stable answer")]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-continuation-refuse"),
        connection_id: Some(connection),
    });
    let (_, _, run1, start1) = engine_start(&fixture, "You are a test agent.");
    let store = Arc::clone(&fixture.store);
    let mut engine = fixture.engine;
    engine.start(start1.clone()).expect("start");
    let _ = engine.poll_events(&run1);
    engine
        .send_input(&run1, EngineInput::Text("hello".to_owned()))
        .expect("input");
    let _ = collect_until_terminal(&mut engine, &run1, Duration::from_secs(10));
    let checkpoint1 = engine
        .checkpoint(&run1)
        .expect("checkpoint")
        .expect("checkpoint present");
    let requests_before = server.request_count();

    // Missing durable checkpoint: the previous run is not in the store.
    let missing = RunId::new(start1.project_id());
    let missing_start = continuation_start(&start1, RunId::new(start1.project_id()));
    let missing_checkpoint = rewritten_checkpoint(&checkpoint1, missing, |_| {});
    let error = engine
        .check_continuation(&missing_start, &missing_checkpoint)
        .expect_err("missing checkpoint must be refused");
    assert!(matches!(
        error,
        herness_core::CoreError::NotContinuable {
            previous_run,
            reason: ConversationFailure::MissingCheckpoint,
        } if previous_run == missing
    ));
    assert!(
        engine
            .start_continuation(missing_start, missing_checkpoint)
            .is_err()
    );

    // Idle but not a completed input.
    let run2 = RunId::new(start1.project_id());
    let start2 = continuation_start(&start1, run2);
    let unstable = rewritten_checkpoint(&checkpoint1, run1, |value| {
        value["snapshot"]["needsResponse"] = json!(true);
    });
    store
        .lock()
        .expect("store")
        .commit_checkpoint(
            CheckpointCommit::new(unstable.clone(), None, Vec::new()).expect("commit"),
        )
        .expect("save unstable checkpoint");
    let error = engine
        .check_continuation(&start2, &unstable)
        .expect_err("an unfinished input must be refused");
    assert!(matches!(
        error,
        herness_core::CoreError::NotContinuable {
            reason: ConversationFailure::PreviousRunNotStable,
            ..
        }
    ));
    assert!(engine.start_continuation(start2.clone(), unstable).is_err());

    // A pending tool invocation could execute twice if continued.
    let pending = rewritten_checkpoint(&checkpoint1, run1, |value| {
        let session = value["snapshot"]["id"].clone();
        value["snapshot"]["invocations"] = json!([{
            "sessionId": session,
            "id": "pending-call",
            "name": "read",
            "args": {"path": "notes.txt"},
            "effect": "read",
            "phase": "executing"
        }]);
    });
    store
        .lock()
        .expect("store")
        .commit_checkpoint(
            CheckpointCommit::new(pending.clone(), None, Vec::new()).expect("commit"),
        )
        .expect("save pending checkpoint");
    let error = engine
        .check_continuation(&start2, &pending)
        .expect_err("a pending invocation must be refused");
    assert!(
        matches!(
            error,
            herness_core::CoreError::NotContinuable {
                reason: ConversationFailure::PendingInvocation,
                ..
            }
        ),
        "unexpected pending error: {error:?}"
    );
    assert!(engine.start_continuation(start2, pending).is_err());

    assert_eq!(
        server.request_count(),
        requests_before,
        "refused continuations must not send a model request"
    );
}

#[test]
fn same_process_resume_reuses_the_live_session_and_restore_is_distinct() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_text("first answer").delayed(Duration::from_millis(300)),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-resume"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let store = Arc::clone(&fixture.store);
    let credentials = Arc::clone(&fixture.credentials);
    let directory = fixture.directory.clone();
    let endpoints = fixture.endpoints.clone();
    let policy = fixture.policy.clone();
    let mut engine = fixture.engine;

    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("slow question".to_owned()))
        .expect("input");
    wait_for_requests(&server, 1);
    let report = engine
        .request_stop(&run, StopReason::UserRequest)
        .expect("stop");
    assert_eq!(report, StopReport::Stopped);
    let events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert!(events.contains(&EngineEvent::StateChanged(RunState::Interrupted)));
    let checkpoint = engine
        .checkpoint(&run)
        .expect("checkpoint")
        .expect("checkpoint present");
    let requests_before = server.request_count();

    // Same-process: the live session is confirmed stopped and reused. No
    // restore event, model request, input, or tool is produced.
    engine
        .check_resume(&run, &checkpoint)
        .expect("same-process preflight");
    engine
        .resume(&run, checkpoint.clone())
        .expect("same-process resume");
    assert!(
        engine.poll_events(&run).expect("poll").is_empty(),
        "reusing the live session must not publish a second recovery state"
    );
    assert_eq!(server.request_count(), requests_before);
    assert!(
        engine
            .send_input(&run, EngineInput::Text("another turn".to_owned()))
            .is_err(),
        "the incomplete response must not be replayed as new input"
    );
    assert_eq!(server.request_count(), requests_before);

    // Cross-process: a new adapter rebuilds from the durable checkpoint. It
    // publishes the recovered state and still makes no request.
    let mut restarted = restart_engine(store, credentials, directory, endpoints, policy);
    restarted
        .check_resume(&run, &checkpoint)
        .expect("cross-process preflight");
    restarted
        .resume(&run, checkpoint)
        .expect("cross-process resume");
    let restored = restarted.poll_events(&run).expect("poll");
    assert!(restored.contains(&EngineEvent::StateChanged(RunState::Interrupted)));
    assert_eq!(
        server.request_count(),
        requests_before,
        "restoring must not send a model request"
    );
    assert!(
        restarted
            .send_input(&run, EngineInput::Text("another turn".to_owned()))
            .is_err()
    );
    assert_eq!(server.request_count(), requests_before);
}

#[test]
fn unsafe_checkpoint_state_is_explicitly_not_resumable() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![responses_text("answer")]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-unsafe"),
        connection_id: Some(connection),
    });
    let (_, _, run, start) = engine_start(&fixture, "You are a test agent.");
    let store = Arc::clone(&fixture.store);
    let credentials = Arc::clone(&fixture.credentials);
    let directory = fixture.directory.clone();
    let endpoints = fixture.endpoints.clone();
    let policy = fixture.policy.clone();
    let mut engine = fixture.engine;
    engine.start(start).expect("start");
    let _ = engine.poll_events(&run);
    engine
        .send_input(&run, EngineInput::Text("hello".to_owned()))
        .expect("input");
    let _ = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    let checkpoint = engine
        .checkpoint(&run)
        .expect("checkpoint")
        .expect("checkpoint present");
    let requests_before = server.request_count();

    let pending = rewritten_checkpoint(&checkpoint, run, |value| {
        let session = value["snapshot"]["id"].clone();
        value["snapshot"]["invocations"] = json!([{
            "sessionId": session,
            "id": "unsafe-call",
            "name": "read",
            "args": {"path": "notes.txt"},
            "effect": "read",
            "phase": "executing"
        }]);
    });
    {
        let mut store = store.lock().expect("store");
        store
            .commit_checkpoint(
                CheckpointCommit::new(pending.clone(), None, Vec::new()).expect("commit"),
            )
            .expect("save unsafe checkpoint");
    }

    let store_for_check = Arc::clone(&store);
    let mut restarted = restart_engine(store, credentials, directory, endpoints, policy);
    let error = restarted
        .check_resume(&run, &pending)
        .expect_err("pending invocation must not be resumable");
    assert!(matches!(
        error,
        herness_core::CoreError::NotResumable {
            reason: ConversationFailure::PendingInvocation,
            ..
        }
    ));
    let error = restarted
        .resume(&run, pending.clone())
        .expect_err("resume must refuse the unsafe snapshot");
    assert!(matches!(
        error,
        herness_core::CoreError::NotResumable {
            reason: ConversationFailure::PendingInvocation,
            ..
        }
    ));
    assert!(
        restarted.poll_events(&run).expect("poll").is_empty(),
        "a refused resume must not start an engine session"
    );
    assert_eq!(
        server.request_count(),
        requests_before,
        "a refused resume must not send a model request"
    );
    let stored = {
        let store = store_for_check.lock().expect("store");
        store
            .load_checkpoint(&run)
            .expect("checkpoint")
            .expect("checkpoint present")
    };
    assert_eq!(
        stored.payload().as_bytes(),
        pending.payload().as_bytes(),
        "the unsafe checkpoint must not be rewritten or discarded"
    );
}

struct HostNoopExecutor;

impl RuntimeToolExecutor for HostNoopExecutor {
    fn enter_run(&mut self, _context: RunToolContext) -> Result<(), CoreError> {
        Ok(())
    }
}

impl ToolExecutor for HostNoopExecutor {
    type Output = ToolExecution;

    fn execute(&mut self, _operation: &FrozenOperation) -> Result<ToolExecution, CoreError> {
        Err(CoreError::EngineUnavailable {
            failure: EngineFailureKind::Unavailable,
        })
    }
}

type EngineTestHost = Runtime<Store, PiEngine<Store>, HostNoopExecutor>;

fn poll_host_until_completed(
    host: &mut EngineTestHost,
    project: ProjectId,
    run: RunId,
    input: herness_core::InputId,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        host.poll_run(project, run).expect("host poll");
        if host
            .input_progress(input)
            .expect("input progress")
            .is_some_and(|progress| progress.is_completed())
        {
            return;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for input completion");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn host_continuation_preserves_conversation_and_input_ids_with_real_pi() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_text("The access code is ORANGE-42."),
        responses_text("It is ORANGE-42."),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-host-continuation"),
        connection_id: Some(connection),
    });
    let store = Arc::clone(&fixture.store);
    let directory = fixture.directory.clone();
    let credentials = Arc::clone(&fixture.credentials);
    let project_path = fixture.project.clone();
    let engine = fixture.engine;
    let deps = RuntimeDependencies::new(
        Arc::clone(&store),
        engine,
        credentials,
        directory,
        PolicyAdmin::new(),
        HostNoopExecutor,
    );
    let (mut host, _) = Runtime::restore(deps).expect("host restore");
    let project = host
        .open_project(&project_path)
        .expect("project")
        .project_id();
    let agent = host
        .create_agent(project, AgentSpec::new("worker", "implementer", connection))
        .expect("agent");
    let run1 = host
        .start_run(project, agent.agent_id(), "test instructions")
        .expect("first run");
    let input1 = host
        .submit_input_with_id(
            project,
            run1.run_id(),
            "Remember this fact: the access code is ORANGE-42.",
        )
        .expect("first input");

    // The startup idle is queued before the submitted turn starts. It must not
    // complete the accepted input.
    host.poll_run(project, run1.run_id()).expect("startup poll");
    assert!(
        !host
            .input_progress(input1)
            .expect("progress")
            .expect("accepted")
            .is_completed(),
        "startup idle must not complete the input"
    );
    poll_host_until_completed(&mut host, project, run1.run_id(), input1);
    assert_eq!(
        host.run(project, run1.run_id()).unwrap().state(),
        RunState::Idle
    );

    let outcome = host
        .continue_run(project, run1.run_id(), "What is the access code?")
        .expect("continuation");
    let run2 = outcome.run().run_id();
    let input2 = outcome.input_id();
    assert_ne!(run1.run_id(), run2);
    assert!(!host.input_progress(input2).unwrap().unwrap().is_completed());
    poll_host_until_completed(&mut host, project, run2, input2);

    assert_eq!(server.request_count(), 2);
    let requests = server.requests();
    let second = requests[1].json().to_string();
    assert!(
        second.contains("ORANGE-42"),
        "the continuation request must include the previous conversation: {second}"
    );

    let checkpoint = {
        let store = store.lock().expect("store");
        store
            .load_checkpoint(&run2)
            .expect("checkpoint")
            .expect("checkpoint present")
    };
    let envelope: Value =
        serde_json::from_slice(checkpoint.payload().as_bytes()).expect("envelope");
    assert_eq!(envelope["runId"], json!(run2.to_string()));

    let events = host
        .subscribe(project, None, HistoryLimit::new(500).expect("limit"))
        .expect("subscribe")
        .events()
        .to_vec();
    let started = events
        .iter()
        .find(|event| event.run_id() == Some(run2) && event.kind().as_str() == "run.input_started")
        .expect("started input event");
    let completed = events
        .iter()
        .find(|event| {
            event.run_id() == Some(run2) && event.kind().as_str() == "run.input_completed"
        })
        .expect("completed input event");
    assert_eq!(
        started.payload().as_value()["inputId"],
        json!(input2.to_string())
    );
    assert_eq!(
        completed.payload().as_value()["inputId"],
        json!(input2.to_string())
    );
    assert!(started.sequence() < completed.sequence());
    assert!(
        events
            .iter()
            .any(|event| event.run_id() == Some(run2) && event.kind().as_str() == "run.started")
    );
}

#[test]
fn cross_process_continuation_restores_the_previous_conversation() {
    let connection = ConnectionId::new();
    let responses = Responses::new(vec![
        responses_text("The access code is ORANGE-42."),
        responses_text("It is still ORANGE-42."),
    ]);
    let server = MockServer::start({
        let responses = responses.clone();
        move |_request| responses.next()
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("loopback");
    let fixture = fixture_with(FixtureOptions {
        provider: Provider::OpenAi,
        model: "gpt-test",
        auth: AuthMethod::ApiKey,
        endpoint: None,
        endpoints,
        credentials: default_credentials(connection, "sk-cross-continuation"),
        connection_id: Some(connection),
    });
    let (_, _, run1, start1) = engine_start(&fixture, "You are a test agent.");
    let store = Arc::clone(&fixture.store);
    let credentials = Arc::clone(&fixture.credentials);
    let directory = fixture.directory.clone();
    let endpoints = fixture.endpoints.clone();
    let policy = fixture.policy.clone();
    let mut engine = fixture.engine;
    engine.start(start1.clone()).expect("first start");
    let _ = engine.poll_events(&run1);
    engine
        .send_input(
            &run1,
            EngineInput::Text("Remember: ORANGE-42 is the access code.".to_owned()),
        )
        .expect("first input");
    let _ = collect_until_terminal(&mut engine, &run1, Duration::from_secs(10));
    let checkpoint1 = engine
        .checkpoint(&run1)
        .expect("checkpoint")
        .expect("checkpoint present");

    // A new process has no live session for the previous run. It must rebuild
    // the conversation from the durable checkpoint before starting the new run.
    let mut restarted = restart_engine(store, credentials, directory, endpoints, policy);
    let run2 = RunId::new(start1.project_id());
    let start2 = continuation_start(&start1, run2);
    restarted
        .check_continuation(&start2, &checkpoint1)
        .expect("cross-process continuation preflight");
    restarted
        .start_continuation(start2, checkpoint1)
        .expect("cross-process continuation");
    let _ = restarted.poll_events(&run2);
    restarted
        .send_input(&run2, EngineInput::Text("What is the code?".to_owned()))
        .expect("second input");
    let _ = collect_until_terminal(&mut restarted, &run2, Duration::from_secs(10));

    assert_eq!(server.request_count(), 2);
    let second = server.requests()[1].json().to_string();
    assert!(
        second.contains("ORANGE-42"),
        "the new process must restore the previous conversation: {second}"
    );
}
