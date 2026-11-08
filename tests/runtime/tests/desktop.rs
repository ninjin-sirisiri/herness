//! Desktop command guard, state, and approval wiring tests.
//!
//! These tests exercise the real Tauri-facing composition: the SQLite store,
//! the pi engine adapter inside `PiEngine`, the runtime, and the desktop
//! executor. Provider traffic goes to a loopback mock and credentials are fake
//! and non-secret. No Keychain, real provider, browser, or GUI session is used.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use herness_core::runtime::{
    AgentSpec, RunToolContext, Runtime, RuntimeDependencies, RuntimeToolExecutor, ToolExecution,
};
use herness_core::{
    AbsolutePath, AuthMethod, BashArgs, Checkpoint, CheckpointCommit, CheckpointFormatVersion,
    CheckpointPayload, ConnectionAdmin, ConnectionId, ConnectionSettings, CoreError,
    CredentialAvailability, CredentialKind, CredentialPort, Endpoint, FileLockRegistry,
    FrozenOperation, HistoryLimit, MatchMethod, NativeFileTools, NonEmptyText, OperationId,
    OperationIntent, OperationOutcome, PermissionRule, Provider, Purpose, ResolvedCredential,
    RuleTarget, RunId, RunState, SecretString, StopReport, StorePort, Timestamp, ToolArguments,
    ToolExecutor, ToolName, VaultAccount, WriteArgs,
};
use herness_desktop::guard::{self, GuardError, Navigation};
use herness_desktop::host::DesktopHost;
use herness_engine_pi::ProviderEndpoints;
use herness_store::{Store, StoreConfig};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Loopback provider mock.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockResponse {
    status: u16,
    content_type: &'static str,
    body: String,
    delay: Duration,
}

impl MockResponse {
    fn sse(body: String) -> Self {
        Self {
            status: 200,
            content_type: "text/event-stream",
            body,
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
    available: bool,
}

impl FakeCredentials {
    fn new(connection: ConnectionId, secret: &str) -> Self {
        Self {
            connection,
            secret: secret.to_owned(),
            resolves: AtomicUsize::new(0),
            available: true,
        }
    }

    fn unavailable(connection: ConnectionId) -> Self {
        Self {
            connection,
            secret: String::new(),
            resolves: AtomicUsize::new(0),
            available: false,
        }
    }
}

impl CredentialPort for FakeCredentials {
    fn availability(
        &self,
        connection: &ConnectionId,
    ) -> Result<CredentialAvailability, herness_core::CoreError> {
        if connection == &self.connection && self.available {
            Ok(CredentialAvailability::Available)
        } else {
            Ok(CredentialAvailability::Unavailable)
        }
    }

    fn resolve(
        &self,
        connection: &ConnectionId,
    ) -> Result<ResolvedCredential, herness_core::CoreError> {
        if connection != &self.connection || !self.available {
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
                    delay: Duration::ZERO,
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
// Task 12 separate-process workers.
//
// The integration test binary re-executes itself with `--exact
// task12_worker_entrypoint` and an environment-selected mode. This is a
// test-only process fixture: it is not a production binary, IPC command, or
// feature. It uses the same real SQLite store and, for the normal-quit mode,
// the same real Tauri host composition with a loopback provider and fake
// credentials.
// ---------------------------------------------------------------------------

fn task12_worker_main() {
    let Ok(mode) = std::env::var("HERNESS_TASK12_WORKER") else {
        return;
    };
    let app_data = PathBuf::from(worker_env("HERNESS_TASK12_APP_DATA"));
    let project = PathBuf::from(worker_env("HERNESS_TASK12_PROJECT"));
    let connection: ConnectionId = worker_env("HERNESS_TASK12_CONNECTION")
        .parse()
        .expect("worker connection id");
    let secret = std::env::var("HERNESS_TASK12_SECRET").unwrap_or_default();
    match mode.as_str() {
        "normal-quit" => worker_normal_quit(&app_data, &project, connection, &secret),
        "unconfirmed-quit" => worker_unconfirmed_quit(&app_data, &project, connection),
        "force-quit" => worker_force_quit(&app_data, &project, connection),
        "crash-after-apply" => worker_crash_after_apply(&app_data, &project, connection),
        other => panic!("unknown Task 12 worker mode: {other}"),
    }
}

#[test]
fn task12_worker_entrypoint() {
    task12_worker_main();
}

fn worker_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn worker_settings(connection: ConnectionId) -> ConnectionSettings {
    ConnectionSettings::new(
        connection,
        Provider::OpenAi,
        "gpt-test",
        AuthMethod::ApiKey,
        None::<Endpoint>,
        None,
    )
    .expect("worker connection settings")
}

fn worker_sequence(store: &Arc<Mutex<Store>>, project: herness_core::ProjectId) -> u64 {
    store
        .lock()
        .expect("worker store lock")
        .history(herness_core::HistoryQuery::first(project))
        .expect("worker history")
        .events()
        .first()
        .map_or(0, herness_core::Event::sequence)
}

fn worker_open_runtime(
    app_data: &Path,
    project: &Path,
    connection: ConnectionId,
    stop_report: StopReport,
) -> (
    Runtime<Store, WorkerEngine, WorkerExecutor>,
    Arc<Mutex<Store>>,
    herness_core::ProjectId,
    herness_core::AgentId,
) {
    let config = StoreConfig::new(app_data).expect("worker store config");
    let store = Arc::new(Mutex::new(Store::open(config).expect("worker store")));
    let admin = ConnectionAdmin::new();
    let settings = worker_settings(connection);
    admin.add(settings.clone()).expect("worker connection");
    let credentials: Arc<dyn CredentialPort + Send + Sync> =
        Arc::new(FakeCredentials::new(connection, "sk-task12-worker"));
    let deps = RuntimeDependencies::new(
        Arc::clone(&store),
        WorkerEngine::new(stop_report),
        credentials,
        admin.directory(),
        herness_core::PolicyAdmin::new(),
        WorkerExecutor,
    );
    let (mut runtime, _) = Runtime::restore(deps).expect("worker runtime");
    runtime
        .record_connection_settings(settings)
        .expect("persist worker connection");
    let project_id = runtime
        .open_project(project)
        .expect("worker open project")
        .project_id();
    let agent = runtime
        .create_agent(
            project_id,
            AgentSpec::new("worker", "implementer", connection),
        )
        .expect("worker agent");
    (runtime, store, project_id, agent.agent_id())
}

fn worker_normal_quit(app_data: &Path, project: &Path, connection: ConnectionId, secret: &str) {
    let queue = Arc::new(Mutex::new(VecDeque::from(vec![
        responses_tool_call(
            "write",
            json!({
                "path": "quit-normal.txt",
                "content": "approved later",
                "rationale": "cross-process normal quit fixture"
            }),
        ),
        responses_text("waiting for approval"),
    ])));
    let server = MockServer::start({
        let queue = Arc::clone(&queue);
        move |_index| {
            let mut queue = queue.lock().expect("worker responses");
            queue.pop_front().unwrap_or_else(|| MockResponse {
                status: 500,
                content_type: "application/json",
                body: json!({"error": {"message": "worker mock exhausted"}}).to_string(),
                delay: Duration::ZERO,
            })
        }
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("worker loopback endpoints");
    let admin = ConnectionAdmin::new();
    admin
        .add(worker_settings(connection))
        .expect("worker connection");
    let credentials: Arc<dyn CredentialPort + Send + Sync> =
        Arc::new(FakeCredentials::new(connection, secret));
    let (mut host, _) =
        DesktopHost::open(app_data, admin, credentials, endpoints).expect("worker desktop host");
    let project_id = host
        .runtime_mut()
        .open_project(project)
        .expect("worker project")
        .project_id();
    let agent = host
        .runtime_mut()
        .create_agent(
            project_id,
            AgentSpec::new("worker", "implementer", connection),
        )
        .expect("worker agent");
    let run = host
        .runtime_mut()
        .start_run(project_id, agent.agent_id(), "normal quit fixture")
        .expect("worker run");
    host.runtime_mut()
        .submit_input(project_id, run.run_id(), "normal quit fixture")
        .expect("worker submit");
    let _approval = wait_for_approval(&mut host, project_id);
    // Let the adapter finish the tool-failure turn and save its checkpoint.
    let settle = Instant::now() + Duration::from_secs(10);
    while server.request_count() < 2 {
        assert!(Instant::now() < settle, "worker adapter did not settle");
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(100));

    let sequence_before = host.runtime().last_sequence(project_id).expect("sequence");
    host.begin_shutdown().expect("begin worker shutdown");
    let stopped = host
        .stop_all_for_shutdown()
        .expect("worker coordinated stops");
    let _ = host.finish_shutdown();
    let sequence_after = host.runtime().last_sequence(project_id).expect("sequence");
    let state = host
        .runtime()
        .run(project_id, run.run_id())
        .expect("worker run view")
        .state();
    let checkpoint_saved = stopped
        .runs()
        .iter()
        .find(|entry| entry.run_id() == run.run_id())
        .is_some_and(|entry| entry.checkpoint_saved());
    println!("WORKER_PID={}", std::process::id());
    println!("WORKER_MODE=normal-quit");
    println!("WORKER_PROJECT={project_id}");
    println!("WORKER_RUN={}", run.run_id());
    println!("WORKER_CONNECTION={connection}");
    println!("WORKER_RUN_STATE={}", state.as_str());
    println!("WORKER_CHECKPOINT_SAVED={checkpoint_saved}");
    println!("WORKER_SAVE_SUCCEEDED={}", stopped.save_succeeded());
    println!("WORKER_SEQUENCE_BEFORE={sequence_before}");
    println!("WORKER_SEQUENCE_AFTER={sequence_after}");
    let code = if stopped.save_succeeded() { 0 } else { 3 };
    std::process::exit(code);
}

fn worker_unconfirmed_quit(app_data: &Path, project: &Path, connection: ConnectionId) {
    let (mut runtime, store, project_id, agent) =
        worker_open_runtime(app_data, project, connection, StopReport::Unconfirmed);
    let run = runtime
        .start_run(project_id, agent, "unconfirmed quit fixture")
        .expect("worker run");
    runtime.begin_shutdown().expect("begin worker shutdown");
    let stopped = runtime
        .stop_all_for_shutdown()
        .expect("worker coordinated stops");
    let state = runtime
        .run(project_id, run.run_id())
        .expect("worker run view")
        .state();
    println!("WORKER_PID={}", std::process::id());
    println!("WORKER_MODE=unconfirmed-quit");
    println!("WORKER_PROJECT={project_id}");
    println!("WORKER_RUN={}", run.run_id());
    println!("WORKER_RUN_STATE={}", state.as_str());
    println!("WORKER_SAVE_SUCCEEDED={}", stopped.save_succeeded());
    println!(
        "WORKER_SEQUENCE_AFTER={}",
        worker_sequence(&store, project_id)
    );
    let code = if stopped.save_succeeded() { 0 } else { 3 };
    std::process::exit(code);
}

fn worker_force_quit(app_data: &Path, project: &Path, connection: ConnectionId) {
    let (mut runtime, store, project_id, agent) =
        worker_open_runtime(app_data, project, connection, StopReport::Stopped);
    let run = runtime
        .start_run(project_id, agent, "force quit fixture")
        .expect("worker run");
    let policy = runtime.policy().clone();
    let arguments = ToolArguments::Bash(BashArgs {
        command: NonEmptyText::new("sleep 30").expect("worker command"),
        purpose: Purpose::new("pending operation before forced quit").expect("worker purpose"),
        timeout_ms: None,
    });
    let operation = FrozenOperation::new(
        OperationId::new(project_id),
        run.run_id(),
        ToolName::Bash,
        arguments,
        AbsolutePath::new(
            std::fs::canonicalize(project)
                .expect("canonical worker project")
                .to_str()
                .expect("worker project utf8"),
        )
        .expect("worker absolute path"),
        policy.version(),
        policy.mode(),
    )
    .expect("worker frozen operation");
    let operation_id = operation.operation_id();
    let checkpoint = Checkpoint::new(
        run.run_id(),
        CheckpointFormatVersion::new(1).expect("checkpoint version"),
        CheckpointPayload::new(b"force-quit-worker".to_vec()),
    );
    let intent = OperationIntent::new(operation, Timestamp::now());
    store
        .lock()
        .expect("worker store lock")
        .commit(CheckpointCommit::new(checkpoint, Some(intent), Vec::new()).expect("commit"))
        .expect("worker intent commit");

    runtime.begin_shutdown().expect("begin worker shutdown");
    let forced = runtime.force_shutdown().expect("worker force shutdown");
    let state = runtime
        .run(project_id, run.run_id())
        .expect("worker run view")
        .state();
    println!("WORKER_PID={}", std::process::id());
    println!("WORKER_MODE=force-quit");
    println!("WORKER_PROJECT={project_id}");
    println!("WORKER_RUN={}", run.run_id());
    println!("WORKER_OPERATION={operation_id}");
    println!("WORKER_RUN_STATE={}", state.as_str());
    println!("WORKER_SAVE_SUCCEEDED={}", forced.save_succeeded());
    println!(
        "WORKER_SEQUENCE_AFTER={}",
        worker_sequence(&store, project_id)
    );
    std::process::exit(2);
}

fn worker_crash_after_apply(app_data: &Path, project: &Path, connection: ConnectionId) {
    let (mut runtime, store, project_id, agent) =
        worker_open_runtime(app_data, project, connection, StopReport::Stopped);
    let run = runtime
        .start_run(project_id, agent, "crash after apply fixture")
        .expect("worker run");
    let agent_view = runtime
        .snapshot(project_id)
        .expect("worker snapshot")
        .runs()
        .first()
        .expect("worker run view")
        .agent_id();
    let session = runtime
        .snapshot(project_id)
        .expect("worker snapshot")
        .runs()
        .first()
        .expect("worker run view")
        .session_id();
    let policy = runtime.policy().clone();
    let operation = FrozenOperation::new(
        OperationId::new(project_id),
        run.run_id(),
        ToolName::Write,
        ToolArguments::Write(WriteArgs {
            path: NonEmptyText::new("crash-after-apply.txt").expect("worker path"),
            content: "applied before the result record".to_owned(),
            rationale: herness_core::Rationale::new("cross-process crash fixture")
                .expect("worker rationale"),
        }),
        AbsolutePath::new(
            std::fs::canonicalize(project)
                .expect("canonical worker project")
                .to_str()
                .expect("worker project utf8"),
        )
        .expect("worker absolute path"),
        policy.version(),
        policy.mode(),
    )
    .expect("worker frozen operation");
    let operation_id = operation.operation_id();
    println!("WORKER_PID={}", std::process::id());
    println!("WORKER_MODE=crash-after-apply");
    println!("WORKER_PROJECT={project_id}");
    println!("WORKER_RUN={}", run.run_id());
    println!("WORKER_OPERATION={operation_id}");
    let root = herness_core::ProjectRoot::new(
        std::fs::canonicalize(project).expect("canonical worker project"),
    )
    .expect("worker project root");
    let mut files = NativeFileTools::with_lock_registry(
        root,
        agent_view,
        session,
        CrashStore(Arc::clone(&store)),
        Arc::new(FileLockRegistry::new()),
    )
    .expect("worker native tools");
    let _ = files.execute(&operation);
    panic!("the crash fixture should never record an operation result");
}

struct WorkerEngine {
    stop_report: StopReport,
}

impl WorkerEngine {
    fn new(stop_report: StopReport) -> Self {
        Self { stop_report }
    }
}

impl herness_core::EnginePort for WorkerEngine {
    fn start(&mut self, _start: herness_core::EngineStart) -> Result<(), CoreError> {
        Ok(())
    }

    fn send_input(
        &mut self,
        _run: &RunId,
        _input: herness_core::EngineInput,
    ) -> Result<(), CoreError> {
        Ok(())
    }

    fn request_stop(
        &mut self,
        _run: &RunId,
        _reason: herness_core::StopReason,
    ) -> Result<StopReport, CoreError> {
        Ok(self.stop_report)
    }

    fn resume(&mut self, _run: &RunId, _checkpoint: Checkpoint) -> Result<(), CoreError> {
        Ok(())
    }

    fn checkpoint(&mut self, run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        Ok(Some(Checkpoint::new(
            *run,
            CheckpointFormatVersion::new(1).expect("checkpoint version"),
            CheckpointPayload::new(b"task12-worker-checkpoint".to_vec()),
        )))
    }

    fn poll_events(&mut self, _run: &RunId) -> Result<Vec<herness_core::EngineEvent>, CoreError> {
        Ok(Vec::new())
    }
}

struct WorkerExecutor;

impl RuntimeToolExecutor for WorkerExecutor {
    fn enter_run(&mut self, _context: RunToolContext) -> Result<(), CoreError> {
        Ok(())
    }
}

impl ToolExecutor for WorkerExecutor {
    type Output = ToolExecution;

    fn execute(&mut self, _operation: &FrozenOperation) -> Result<ToolExecution, CoreError> {
        Err(CoreError::EngineUnavailable {
            failure: herness_core::EngineFailureKind::Unavailable,
        })
    }
}

#[derive(Clone)]
struct CrashStore(Arc<Mutex<Store>>);

impl CrashStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl StorePort for CrashStore {
    fn commit_checkpoint(
        &mut self,
        commit: CheckpointCommit,
    ) -> Result<herness_core::CommitReceipt, CoreError> {
        self.lock().commit(commit).map_err(Into::into)
    }

    fn load_checkpoint(&self, run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        <Store as StorePort>::load_checkpoint(&self.lock(), run)
    }

    fn history(
        &self,
        query: herness_core::HistoryQuery,
    ) -> Result<herness_core::HistoryPage, CoreError> {
        <Store as StorePort>::history(&self.lock(), query)
    }

    fn pending_operations(
        &self,
        project: &herness_core::ProjectId,
    ) -> Result<Vec<OperationIntent>, CoreError> {
        <Store as StorePort>::pending_operations(&self.lock(), project)
    }

    fn operation(
        &self,
        operation: &OperationId,
    ) -> Result<Option<herness_core::OperationRecord>, CoreError> {
        <Store as StorePort>::operation(&self.lock(), operation)
    }

    fn record_operation_result(
        &mut self,
        operation: &OperationId,
        _result: herness_core::OperationResult,
    ) -> Result<(), CoreError> {
        print_crash_sequence(self, operation);
        std::process::exit(70);
    }

    fn record_operation_result_with_events(
        &mut self,
        operation: &OperationId,
        _result: herness_core::OperationResult,
        _events: Vec<herness_core::EventDraft>,
    ) -> Result<herness_core::CommitReceipt, CoreError> {
        print_crash_sequence(self, operation);
        std::process::exit(70);
    }
}

fn print_crash_sequence(store: &CrashStore, operation: &OperationId) {
    let sequence = store
        .lock()
        .history(herness_core::HistoryQuery::first(operation.project_id()))
        .ok()
        .and_then(|page| page.events().first().map(herness_core::Event::sequence))
        .unwrap_or(0);
    println!("WORKER_CRASH_AFTER_APPLY=1");
    println!("WORKER_OPERATION={operation}");
    println!("WORKER_SEQUENCE_AFTER={sequence}");
}

struct WorkerFixture {
    _temp: tempfile::TempDir,
    project: PathBuf,
    app_data: PathBuf,
    connection: ConnectionId,
}

impl WorkerFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("worker temp dir");
        let project = temp.path().join("project");
        std::fs::create_dir_all(&project).expect("worker project");
        let app_data = temp.path().join("app-data");
        std::fs::create_dir_all(&app_data).expect("worker app data");
        Self {
            _temp: temp,
            project,
            app_data,
            connection: ConnectionId::new(),
        }
    }

    fn spawn(&self, mode: &str) -> Output {
        let exe = std::env::current_exe().expect("current test executable");
        Command::new(exe)
            .arg("--exact")
            .arg("task12_worker_entrypoint")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("HERNESS_TASK12_WORKER", mode)
            .env("HERNESS_TASK12_APP_DATA", &self.app_data)
            .env("HERNESS_TASK12_PROJECT", &self.project)
            .env("HERNESS_TASK12_CONNECTION", self.connection.to_string())
            .env("HERNESS_TASK12_SECRET", "sk-task12-canary")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn Task 12 worker")
    }

    fn open_restored_counting(
        &self,
        server: &MockServer,
    ) -> (DesktopHost, herness_core::runtime::ReconciliationReport) {
        self.open_restored_with_endpoints(server)
    }

    fn open_restored_unavailable_counting(
        &self,
        server: &MockServer,
    ) -> (DesktopHost, herness_core::runtime::ReconciliationReport) {
        let admin = ConnectionAdmin::new();
        let credentials: Arc<dyn CredentialPort + Send + Sync> =
            Arc::new(FakeCredentials::unavailable(self.connection));
        let endpoints =
            ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
                .expect("loopback endpoints");
        DesktopHost::open(&self.app_data, admin, credentials, endpoints)
            .expect("restored desktop host with unavailable credentials")
    }

    fn open_restored_with_endpoints(
        &self,
        server: &MockServer,
    ) -> (DesktopHost, herness_core::runtime::ReconciliationReport) {
        let admin = ConnectionAdmin::new();
        let credentials: Arc<dyn CredentialPort + Send + Sync> =
            Arc::new(FakeCredentials::new(self.connection, "sk-task12-canary"));
        let endpoints =
            ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
                .expect("loopback endpoints");
        DesktopHost::open(&self.app_data, admin, credentials, endpoints)
            .expect("restored desktop host")
    }

    fn project_id(&self, host: &DesktopHost) -> herness_core::ProjectId {
        host.runtime()
            .projects()
            .expect("projects")
            .into_iter()
            .find(|view| {
                view.path().as_str()
                    == std::fs::canonicalize(&self.project)
                        .expect("canonical")
                        .to_string_lossy()
                        .as_ref()
            })
            .expect("restored project")
            .project_id()
    }
}

fn worker_output(output: &Output, key: &str) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    text.lines()
        .find_map(|line| {
            line.split_once(&format!("{key}="))
                .map(|(_, value)| value.trim().to_owned())
        })
        .unwrap_or_else(|| panic!("worker output is missing {key}:\n{text}"))
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

// ---------------------------------------------------------------------------
// Task 12: explicit quit, cross-process restore, and lifecycle measurements.
// ---------------------------------------------------------------------------

#[test]
fn connection_settings_survive_restart_with_the_selected_chatgpt_account() {
    let temp = tempfile::tempdir().expect("temp dir");
    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("app data");
    let connection = ConnectionId::new();
    let account = VaultAccount::for_chatgpt_account(connection, "oaiapp_task12", "subject-task12")
        .expect("chatgpt account");
    let settings = ConnectionSettings::new(
        connection,
        Provider::OpenAi,
        "gpt-test",
        AuthMethod::ChatGptLogin,
        None::<Endpoint>,
        None,
    )
    .expect("settings")
    .select_chatgpt_account(account.clone())
    .expect("selected account");

    let admin = ConnectionAdmin::new();
    let credentials: Arc<dyn CredentialPort + Send + Sync> =
        Arc::new(FakeCredentials::new(connection, "sk-task12-canary"));
    let endpoints = ProviderEndpoints::for_loopback("http://127.0.0.1:9/v1", "http://127.0.0.1:9")
        .expect("unused loopback endpoints");
    let (mut host, _) =
        DesktopHost::open(&app_data, admin, credentials, endpoints).expect("first host");
    let info = host
        .register_connection(settings.clone())
        .expect("register");
    assert_eq!(info.auth_method(), AuthMethod::ChatGptLogin);
    drop(host);

    let reopened_admin = ConnectionAdmin::new();
    let credentials: Arc<dyn CredentialPort + Send + Sync> =
        Arc::new(FakeCredentials::new(connection, "sk-task12-canary"));
    let endpoints = ProviderEndpoints::for_loopback("http://127.0.0.1:9/v1", "http://127.0.0.1:9")
        .expect("unused loopback endpoints");
    let (host, _) = DesktopHost::open(&app_data, reopened_admin, credentials, endpoints)
        .expect("reopened host");
    let restored = host
        .directory()
        .get(connection)
        .expect("persisted chatgpt connection");
    assert_eq!(restored.selected_chatgpt_account(), Some(&account));
    assert_eq!(restored.vault_account(), account);
    assert_eq!(
        host.connection_infos().expect("connections")[0].status(),
        herness_core::ConnectionStatus::Available
    );

    // The store has no token field: connection settings are non-secret and the
    // fake key was never saved by this path.
    let bytes = std::fs::read(app_data.join("herness.sqlite3")).expect("database bytes");
    assert!(
        !bytes
            .windows("sk-task12-canary".len())
            .any(|window| window == b"sk-task12-canary")
    );
}

#[test]
fn stored_connection_settings_cannot_contain_secret_fields() {
    let temp = tempfile::tempdir().expect("temp dir");
    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("app data");
    let connection = ConnectionId::new();
    let mut store = Store::open(StoreConfig::new(&app_data).expect("store config")).expect("store");
    let state = json!({
        "format": 2,
        "projects": {},
        "connections": {
            connection.to_string(): {
                "connectionId": connection.to_string(),
                "provider": "openai",
                "model": "gpt-test",
                "authMethod": "api_key",
                "credentialRef": format!("connection/{connection}/api_key"),
                "token": "sk-must-not-be-accepted"
            }
        }
    });
    store
        .save_host_state(
            "herness.runtime.host-state",
            serde_json::to_vec(&state).expect("state json").as_slice(),
        )
        .expect("save host state");
    drop(store);

    let admin = ConnectionAdmin::new();
    let credentials: Arc<dyn CredentialPort + Send + Sync> =
        Arc::new(FakeCredentials::new(connection, "sk-task12-canary"));
    let endpoints = ProviderEndpoints::for_loopback("http://127.0.0.1:9/v1", "http://127.0.0.1:9")
        .expect("unused loopback endpoints");
    let error = DesktopHost::open(&app_data, admin, credentials, endpoints)
        .err()
        .expect("unknown secret field must be rejected");
    assert!(
        error.contains("host-state JSON"),
        "unexpected error: {error}"
    );
}

#[test]
fn host_state_format_one_is_readable_and_unknown_formats_are_rejected() {
    // Format 1 (Task 10/11) has no connection or shutdown fields.
    let temp = tempfile::tempdir().expect("temp dir");
    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("app data");
    let mut store = Store::open(StoreConfig::new(&app_data).expect("store config")).expect("store");
    store
        .save_host_state(
            "herness.runtime.host-state",
            br#"{"format":1,"projects":{}}"#,
        )
        .expect("save format 1");
    drop(store);
    let admin = ConnectionAdmin::new();
    let credentials: Arc<dyn CredentialPort + Send + Sync> = Arc::new(FakeCredentials::new(
        ConnectionId::new(),
        "sk-task12-canary",
    ));
    let endpoints = ProviderEndpoints::for_loopback("http://127.0.0.1:9/v1", "http://127.0.0.1:9")
        .expect("unused loopback endpoints");
    let (host, report) =
        DesktopHost::open(&app_data, admin, credentials, endpoints).expect("read format 1");
    assert!(report.previous_shutdown().is_none());
    assert!(host.runtime().persisted_connections().is_empty());
    drop(host);

    // An unknown format is rejected rather than silently interpreted.
    let temp = tempfile::tempdir().expect("temp dir");
    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("app data");
    let mut store = Store::open(StoreConfig::new(&app_data).expect("store config")).expect("store");
    store
        .save_host_state(
            "herness.runtime.host-state",
            br#"{"format":4,"projects":{}}"#,
        )
        .expect("save unknown format");
    drop(store);
    let admin = ConnectionAdmin::new();
    let credentials: Arc<dyn CredentialPort + Send + Sync> = Arc::new(FakeCredentials::new(
        ConnectionId::new(),
        "sk-task12-canary",
    ));
    let endpoints = ProviderEndpoints::for_loopback("http://127.0.0.1:9/v1", "http://127.0.0.1:9")
        .expect("unused loopback endpoints");
    let error = DesktopHost::open(&app_data, admin, credentials, endpoints)
        .err()
        .expect("unknown format must be rejected");
    assert!(
        error.contains("unsupported host-state format"),
        "unexpected error: {error}"
    );
}

#[test]
fn normal_quit_process_saves_checkpoint_and_restores_connection_settings() {
    let fixture = WorkerFixture::new();
    let output = fixture.spawn("normal-quit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "normal quit worker failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(worker_output(&output, "WORKER_PID").parse::<u32>().unwrap() > 0);
    assert_eq!(worker_output(&output, "WORKER_RUN_STATE"), "paused");
    assert_eq!(worker_output(&output, "WORKER_CHECKPOINT_SAVED"), "true");
    assert_eq!(worker_output(&output, "WORKER_SAVE_SUCCEEDED"), "true");
    let sequence_after: u64 = worker_output(&output, "WORKER_SEQUENCE_AFTER")
        .parse()
        .unwrap();
    let sequence_before: u64 = worker_output(&output, "WORKER_SEQUENCE_BEFORE")
        .parse()
        .unwrap();
    assert!(sequence_after > sequence_before);

    let server = MockServer::start(|_index| MockResponse {
        status: 500,
        content_type: "application/json",
        body: json!({"error": {"message": "restore must not send requests"}}).to_string(),
        delay: Duration::ZERO,
    });

    // The restore reports the persisted connection but cannot resume while the
    // credential is unavailable. No model request is sent.
    let (mut unavailable, _) = fixture.open_restored_unavailable_counting(&server);
    let project = fixture.project_id(&unavailable);
    let run = unavailable
        .runtime()
        .snapshot(project)
        .expect("snapshot")
        .runs()
        .first()
        .cloned()
        .expect("restored run");
    assert_eq!(run.state(), RunState::Paused);
    assert_eq!(
        unavailable.connection_infos().expect("connections")[0].status(),
        herness_core::ConnectionStatus::AuthRequired
    );
    assert!(matches!(
        unavailable.runtime_mut().resume_run(project, run.run_id()),
        Err(herness_core::runtime::RuntimeError::ConnectionUnavailable { .. })
    ));
    assert_eq!(server.request_count(), 0);
    drop(unavailable);

    let (mut host, report) = fixture.open_restored_counting(&server);
    let previous = report.previous_shutdown().expect("previous shutdown");
    assert_eq!(
        previous.outcome(),
        herness_core::runtime::ShutdownOutcome::Completed
    );
    assert_eq!(previous.stopped_runs(), 1);
    assert!(previous.unconfirmed_runs().is_empty());
    assert_eq!(server.request_count(), 0);
    let project = fixture.project_id(&host);
    assert!(host.runtime().last_sequence(project).unwrap() >= sequence_after);
    assert_eq!(
        host.connection_infos().expect("connections")[0].status(),
        herness_core::ConnectionStatus::Available
    );
    assert_eq!(
        host.directory()
            .get(fixture.connection)
            .expect("persisted connection")
            .model(),
        "gpt-test"
    );
    assert!(
        host.runtime()
            .pending_approvals(project)
            .unwrap()
            .is_empty()
    );
    let run = host
        .runtime()
        .snapshot(project)
        .expect("snapshot")
        .runs()
        .first()
        .cloned()
        .expect("run");
    assert_eq!(run.state(), RunState::Paused);

    // The fake credential used by the quitting process never reaches the store.
    for entry in std::fs::read_dir(&fixture.app_data).expect("app data") {
        let path = entry.expect("app data entry").path();
        if path.is_file() {
            let bytes = std::fs::read(&path).expect("database bytes");
            assert!(
                !bytes
                    .windows("sk-task12-canary".len())
                    .any(|window| window == b"sk-task12-canary"),
                "credential canary leaked into {}",
                path.display()
            );
        }
    }

    // Human resume re-checks the current credential and restores from the
    // saved checkpoint without sending a model request.
    let resumed = host
        .runtime_mut()
        .resume_run(project, run.run_id())
        .expect("resume after restore");
    assert_eq!(resumed.state(), RunState::Running);
    assert_eq!(server.request_count(), 0);
}

#[test]
fn unconfirmed_quit_process_restores_interrupted_without_claiming_success() {
    let fixture = WorkerFixture::new();
    let output = fixture.spawn("unconfirmed-quit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(3),
        "unconfirmed quit worker must exit 3\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(worker_output(&output, "WORKER_PID").parse::<u32>().unwrap() > 0);
    assert_eq!(worker_output(&output, "WORKER_RUN_STATE"), "interrupted");
    assert_eq!(worker_output(&output, "WORKER_SAVE_SUCCEEDED"), "false");
    let sequence_after: u64 = worker_output(&output, "WORKER_SEQUENCE_AFTER")
        .parse()
        .unwrap();

    let server = MockServer::start(|_index| MockResponse {
        status: 500,
        content_type: "application/json",
        body: String::new(),
        delay: Duration::ZERO,
    });
    let (host, report) = fixture.open_restored_counting(&server);
    let project = fixture.project_id(&host);
    let previous = report.previous_shutdown().expect("previous shutdown");
    assert_eq!(
        previous.outcome(),
        herness_core::runtime::ShutdownOutcome::CompletedWithUnconfirmed
    );
    assert_eq!(previous.unconfirmed_runs().len(), 1);
    let run = host
        .runtime()
        .snapshot(project)
        .expect("snapshot")
        .runs()
        .first()
        .cloned()
        .expect("run");
    assert_eq!(run.state(), RunState::Interrupted);
    assert!(host.runtime().last_sequence(project).unwrap() >= sequence_after);
    assert_eq!(server.request_count(), 0);
}

#[test]
fn forced_quit_process_keeps_operation_pending_for_reconciliation() {
    let fixture = WorkerFixture::new();
    let output = fixture.spawn("force-quit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "forced quit worker must exit 2\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(worker_output(&output, "WORKER_PID").parse::<u32>().unwrap() > 0);
    let operation: OperationId = worker_output(&output, "WORKER_OPERATION")
        .parse()
        .expect("operation id");
    assert_eq!(worker_output(&output, "WORKER_RUN_STATE"), "interrupted");
    assert_eq!(worker_output(&output, "WORKER_SAVE_SUCCEEDED"), "false");
    let sequence_after: u64 = worker_output(&output, "WORKER_SEQUENCE_AFTER")
        .parse()
        .unwrap();

    let server = MockServer::start(|_index| MockResponse {
        status: 500,
        content_type: "application/json",
        body: String::new(),
        delay: Duration::ZERO,
    });
    let (host, report) = fixture.open_restored_counting(&server);
    let project = fixture.project_id(&host);
    let previous = report.previous_shutdown().expect("previous shutdown");
    assert_eq!(
        previous.outcome(),
        herness_core::runtime::ShutdownOutcome::Forced
    );
    assert_eq!(previous.unconfirmed_runs().len(), 1);
    let run = host
        .runtime()
        .snapshot(project)
        .expect("snapshot")
        .runs()
        .first()
        .cloned()
        .expect("run");
    assert_eq!(run.state(), RunState::Interrupted);
    let project_report = report
        .projects()
        .iter()
        .find(|entry| entry.project_id() == project)
        .expect("project report");
    let reconciled = project_report
        .operations()
        .iter()
        .find(|entry| entry.operation_id() == operation)
        .expect("forced operation appears in reconciliation");
    assert_eq!(reconciled.outcome(), OperationOutcome::Unverifiable);
    assert_eq!(
        reconciled.source(),
        herness_core::runtime::ReconciliationSource::ShellUncertain
    );
    assert!(host.runtime().last_sequence(project).unwrap() >= sequence_after);
    assert_eq!(server.request_count(), 0);

    let store = Store::open(StoreConfig::new(&fixture.app_data).expect("store config"))
        .expect("read store");
    let record = store
        .operation(&operation)
        .expect("operation")
        .expect("record");
    assert!(
        record.result().is_none(),
        "forced quit must not invent an operation result"
    );
    assert!(
        store
            .unresolved_operations(&project)
            .expect("unresolved")
            .iter()
            .any(|entry| entry.intent().operation().operation_id() == operation)
    );
}

#[test]
fn crash_after_file_apply_restores_evidence_without_inventing_a_result() {
    let fixture = WorkerFixture::new();
    let output = fixture.spawn("crash-after-apply");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(70),
        "crash-after-apply worker must exit 70\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(worker_output(&output, "WORKER_PID").parse::<u32>().unwrap() > 0);
    assert_eq!(worker_output(&output, "WORKER_CRASH_AFTER_APPLY"), "1");
    let operation: OperationId = worker_output(&output, "WORKER_OPERATION")
        .parse()
        .expect("operation id");
    let sequence_after: u64 = worker_output(&output, "WORKER_SEQUENCE_AFTER")
        .parse()
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(fixture.project.join("crash-after-apply.txt"))
            .expect("applied file"),
        "applied before the result record"
    );

    let server = MockServer::start(|_index| MockResponse {
        status: 500,
        content_type: "application/json",
        body: String::new(),
        delay: Duration::ZERO,
    });
    let (host, report) = fixture.open_restored_counting(&server);
    let project = fixture.project_id(&host);
    let run = host
        .runtime()
        .snapshot(project)
        .expect("snapshot")
        .runs()
        .first()
        .cloned()
        .expect("run");
    assert_eq!(run.state(), RunState::Interrupted);
    let project_report = report
        .projects()
        .iter()
        .find(|entry| entry.project_id() == project)
        .expect("project report");
    let reconciled = project_report
        .operations()
        .iter()
        .find(|entry| entry.operation_id() == operation)
        .expect("crash operation appears in reconciliation");
    assert_eq!(reconciled.outcome(), OperationOutcome::Applied);
    assert_eq!(
        reconciled.source(),
        herness_core::runtime::ReconciliationSource::NativeFileContent
    );
    assert!(host.runtime().last_sequence(project).unwrap() >= sequence_after);
    assert_eq!(server.request_count(), 0);

    let store = Store::open(StoreConfig::new(&fixture.app_data).expect("store config"))
        .expect("read store");
    let record = store
        .operation(&operation)
        .expect("operation")
        .expect("record");
    assert!(
        record.result().is_none(),
        "native content evidence must not be written back as an invented result"
    );
    assert!(
        store
            .unresolved_operations(&project)
            .expect("unresolved")
            .iter()
            .any(|entry| entry.intent().operation().operation_id() == operation)
    );
}

#[test]
fn explicit_shutdown_stops_a_managed_shell_group() {
    let responses = vec![
        responses_tool_call(
            "bash",
            json!({
                "command": "sleep 30",
                "purpose": "hold a managed shell group for shutdown"
            }),
        ),
        responses_text("shell turn finished"),
    ];
    let mut fixture = Fixture::new(responses);
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
                .expect("allow bash"),
            )
            .expect("add allow rule");
        let policy = policy.policy().clone();
        fixture
            .host
            .runtime_mut()
            .engine_mut()
            .replace_policy(policy);
    }
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
        .start_run(project, agent.agent_id(), "start a managed shell")
        .expect("run");
    fixture
        .host
        .runtime_mut()
        .submit_input(project, run.run_id(), "start a managed shell")
        .expect("submit");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut shell_pid = None;
    while shell_pid.is_none() {
        let _ = fixture.host.runtime_mut().poll_run(project, run.run_id());
        let history = fixture
            .host
            .runtime()
            .subscribe(project, None, HistoryLimit::new(500).expect("limit"))
            .expect("history");
        shell_pid = history.events().iter().find_map(|event| {
            (event.kind().as_str() == "shell.spawned")
                .then(|| {
                    event
                        .payload()
                        .as_value()
                        .get("pid")
                        .and_then(Value::as_u64)
                })
                .flatten()
        });
        assert!(Instant::now() < deadline, "managed shell did not spawn");
        thread::sleep(Duration::from_millis(10));
    }
    let shell_pid = u32::try_from(shell_pid.unwrap()).expect("pid");
    assert!(
        herness_core::process_group_exists(shell_pid),
        "managed shell group should be alive before shutdown"
    );

    fixture.host.begin_shutdown().expect("begin shutdown");
    let stopped = fixture
        .host
        .stop_all_for_shutdown()
        .expect("coordinated shutdown");
    assert!(stopped.all_inactive());
    assert!(
        !herness_core::process_group_exists(shell_pid),
        "the managed shell group must be gone after shutdown"
    );
    let state = fixture
        .host
        .runtime()
        .run(project, run.run_id())
        .expect("run view")
        .state();
    assert!(
        matches!(state, RunState::Paused | RunState::Interrupted),
        "unexpected state after shell stop: {state}"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let history = fixture
            .host
            .runtime()
            .subscribe(project, None, HistoryLimit::new(500).expect("limit"))
            .expect("history");
        if history
            .events()
            .iter()
            .any(|event| event.kind().as_str() == "shell.finished")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "stopped shell must record a non-success finish"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let store = Store::open(StoreConfig::new(&fixture.app_data).expect("store config"))
        .expect("read store");
    let unresolved = store
        .unresolved_operations(&project)
        .expect("unresolved operations");
    assert!(
        !unresolved.is_empty(),
        "a stopped shell outcome must remain reconciliation-pending"
    );
}

#[test]
fn closed_window_runtime_keeps_processing_and_reopen_reads_latest_sequence() {
    let mut fixture = Fixture::new(vec![
        responses_text("continued while hidden"),
        responses_text("second project progressed"),
    ]);
    let connection = fixture.connection();
    let project = fixture
        .host
        .runtime_mut()
        .open_project(&fixture.project)
        .expect("open project")
        .project_id();
    let second_path = fixture._temp.path().join("second-project");
    std::fs::create_dir_all(&second_path).expect("second project");
    let second = fixture
        .host
        .runtime_mut()
        .open_project(&second_path)
        .expect("open second project")
        .project_id();
    let mut runs = Vec::new();
    for (project, text) in [
        (project, "continue while hidden"),
        (second, "non-selected project progresses"),
    ] {
        let agent = fixture
            .host
            .runtime_mut()
            .create_agent(project, AgentSpec::new("main", "implementer", connection))
            .expect("agent");
        let run = fixture
            .host
            .runtime_mut()
            .start_run(project, agent.agent_id(), text)
            .expect("run");
        fixture
            .host
            .runtime_mut()
            .submit_input(project, run.run_id(), text)
            .expect("submit");
        runs.push((project, run.run_id()));
    }

    // No UI command, poll_run, or lifecycle call runs here: only the
    // host-owned pump advances both projects, including the non-selected one.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        fixture.host.pump().expect("pump while hidden");
        let all_ready = runs.iter().all(|(project, run)| {
            let idle = fixture
                .host
                .runtime()
                .snapshot(*project)
                .expect("snapshot")
                .runs()
                .iter()
                .find(|view| view.run_id() == *run)
                .is_some_and(|view| view.state() == RunState::Idle);
            idle && fixture
                .host
                .runtime()
                .subscribe(*project, None, HistoryLimit::new(500).expect("limit"))
                .expect("history")
                .events()
                .iter()
                .any(|event| event.kind().as_str() == "run.text_completed")
        });
        if all_ready {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "hidden projects did not progress solely via the pump"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fixture._server.request_count(),
        2,
        "each hidden run must make exactly one model request"
    );

    // The page-reload path used on reopen reads a fresh snapshot and history
    // instead of reusing hidden-page state.
    for (project, run) in &runs {
        let snapshot = fixture
            .host
            .runtime()
            .snapshot(*project)
            .expect("reopen snapshot");
        assert!(snapshot.runs().iter().any(|view| view.run_id() == *run));
        assert!(snapshot.runs()[0].state() == RunState::Idle);
        let history = fixture
            .host
            .runtime()
            .subscribe(*project, None, HistoryLimit::new(500).expect("limit"))
            .expect("reopen history");
        assert!(history.last_sequence() > 0);
        assert!(history.events().iter().any(|event| {
            event.kind().as_str() == "run.text_completed"
                && !event.payload().as_value()["text"]
                    .as_str()
                    .unwrap_or("")
                    .is_empty()
        }));
    }
}

#[test]
fn pump_stops_one_long_running_request_when_its_deadline_passes() {
    let mut fixture = Fixture::new(vec![
        responses_text("too late").delayed(Duration::from_secs(5)),
    ]);
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
        .start_run(project, agent.agent_id(), "long request")
        .expect("run");
    fixture
        .host
        .runtime_mut()
        .submit_input(project, run.run_id(), "wait for a slow provider")
        .expect("submit");

    let request_deadline = Instant::now() + Duration::from_secs(10);
    while fixture._server.request_count() == 0 {
        fixture.host.pump().expect("pump before request");
        assert!(
            Instant::now() < request_deadline,
            "the provider request did not start"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fixture._server.request_count(), 1);

    fixture
        .host
        .runtime_mut()
        .set_run_deadline(project, run.run_id(), Some(Instant::now()))
        .expect("deadline");
    let report = fixture.host.pump().expect("pump at deadline");
    assert!(
        report.deadline_stops().contains(&run.run_id()),
        "the pump must record the deadline stop"
    );
    let snapshot = fixture.host.runtime().snapshot(project).expect("snapshot");
    let state = snapshot
        .runs()
        .iter()
        .find(|view| view.run_id() == run.run_id())
        .expect("run")
        .state();
    assert!(
        matches!(state, RunState::Paused | RunState::Interrupted),
        "a deadline stop must use the H1 cooperative stop path: {state:?}"
    );
    let history = fixture
        .host
        .runtime()
        .subscribe(project, None, HistoryLimit::new(500).expect("limit"))
        .expect("history");
    assert!(
        history
            .events()
            .iter()
            .any(|event| event.kind().as_str() == "run.stopped")
    );
    assert_eq!(
        fixture._server.request_count(),
        1,
        "a stopped request must not be retried"
    );
    let second = fixture.host.pump().expect("pump after stop");
    assert!(
        second.deadline_stops().is_empty(),
        "a stopped run must not be stopped twice"
    );
}

#[test]
fn pump_does_no_work_after_shutdown_begins() {
    let mut fixture = Fixture::new(Vec::new());
    fixture
        .host
        .runtime_mut()
        .open_project(&fixture.project)
        .expect("open project");
    fixture.host.begin_shutdown().expect("begin shutdown");
    let report = fixture.host.pump().expect("pump during shutdown");
    assert!(
        report.is_skipped(),
        "the pump must not delay the existing quit path"
    );
}

/// Manual Task 12 running-memory fixture.
///
/// This is not part of the normal test suite. It composes the same desktop host
/// (real store, real PiEngine, loopback provider, fake credentials) in a
/// separate OS process, starts an allowed `bash` command that sleeps, prints its
/// PID and the managed shell PID, then holds so an external sampler can measure
/// RSS. It is the host-runtime running measurement; the Tauri WebView is not in
/// this process.
#[test]
#[ignore = "manual Task 12 running-memory measurement fixture"]
fn measure_running_host_rss() {
    let temp = tempfile::tempdir().expect("measurement temp dir");
    let project = temp.path().join("project");
    std::fs::create_dir_all(&project).expect("measurement project");
    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("measurement app data");
    let queue = Arc::new(Mutex::new(VecDeque::from(vec![
        responses_tool_call(
            "bash",
            json!({
                "command": "sleep 20",
                "purpose": "hold the host in a running state for memory measurement"
            }),
        ),
        responses_text("measurement turn finished"),
    ])));
    let server = MockServer::start({
        let queue = Arc::clone(&queue);
        move |_index| {
            let mut queue = queue.lock().expect("measurement responses");
            queue.pop_front().unwrap_or_else(|| MockResponse {
                status: 500,
                content_type: "application/json",
                body: String::new(),
                delay: Duration::ZERO,
            })
        }
    });
    let endpoints = ProviderEndpoints::for_loopback(format!("{}/v1", server.url()), server.url())
        .expect("measurement endpoints");
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
            .expect("measurement settings"),
        )
        .expect("measurement connection");
    let credentials: Arc<dyn CredentialPort + Send + Sync> =
        Arc::new(FakeCredentials::new(connection, "sk-measurement-fake"));
    let (mut host, _) = DesktopHost::open(&app_data, connections, credentials, endpoints)
        .expect("measurement host");
    {
        let policy = host.runtime_mut().policy_admin_mut();
        policy
            .add_rule(
                PermissionRule::allow(
                    RuleTarget::Tool {
                        tool: ToolName::Bash,
                    },
                    MatchMethod::AnyInvocation,
                )
                .expect("allow bash"),
            )
            .expect("add allow rule");
        let policy = policy.policy().clone();
        host.runtime_mut().engine_mut().replace_policy(policy);
    }
    let project_id = host
        .runtime_mut()
        .open_project(&project)
        .expect("measurement project")
        .project_id();
    let agent = host
        .runtime_mut()
        .create_agent(
            project_id,
            AgentSpec::new("measure", "implementer", connection),
        )
        .expect("measurement agent");
    let run = host
        .runtime_mut()
        .start_run(project_id, agent.agent_id(), "hold a shell process")
        .expect("measurement run");
    host.runtime_mut()
        .submit_input(project_id, run.run_id(), "hold a shell process")
        .expect("measurement submit");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut shell_pid = None;
    while shell_pid.is_none() {
        let _ = host.runtime_mut().poll_run(project_id, run.run_id());
        let history = host
            .runtime()
            .subscribe(project_id, None, HistoryLimit::new(500).expect("limit"))
            .expect("measurement history");
        shell_pid = history.events().iter().find_map(|event| {
            (event.kind().as_str() == "shell.spawned")
                .then(|| {
                    event
                        .payload()
                        .as_value()
                        .get("pid")
                        .and_then(Value::as_u64)
                })
                .flatten()
        });
        assert!(Instant::now() < deadline, "measurement shell did not spawn");
        thread::sleep(Duration::from_millis(20));
    }
    println!("MEASURE_READY: pid={}", std::process::id());
    println!("MEASURE_SHELL_PID: {}", shell_pid.unwrap());
    let hold = std::env::var("HERNESS_MEASURE_HOLD_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15_000);
    thread::sleep(Duration::from_millis(hold));

    let _ = host.begin_shutdown();
    let _ = host.stop_all_for_shutdown();
    let _ = host.finish_shutdown();
    println!("MEASURE_DONE: pid={}", std::process::id());
    std::process::exit(0);
}
