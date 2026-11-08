//! Task 17: H1-to-H2 loopback regression across an old store, a real Pi run,
//! continuation, budget/permission gates, supervision completion, and quit.
//!
//! The provider is a loopback mock, the credentials are fake, and the required
//! checks/assessments are scripted. The store, SQLite migration, Pi engine,
//! tool executor, request gate, budget ledger, supervision record, and quit
//! path are the real implementations.

use std::collections::{BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use herness_assessment::{
    AssessmentEndpoints, AssessmentTransport, PermissionBudgetScope, PermissionEvaluator,
    PermissionEvaluatorConfig, RetryPolicy, SharedModelRequestGate,
};
use herness_core::{
    AuthMethod, ConnectionAdmin, ConnectionId, ConnectionSettings, ConnectionStatus, CoreError,
    CredentialAvailability, CredentialKind, CredentialPort, Endpoint, EndpointClass, HistoryQuery,
    InputCapabilities, ModelId, ModelRequestGatePort, ModelRequestObservation, ProjectId, Provider,
    RequestGateIntent, RequestGateOutcome, ResolvedCredential, SecretString, StorePort, Timestamp,
};
use herness_desktop::host::DesktopHost;
use herness_desktop::supervision::store::HostBudgetClock;
use herness_desktop::supervision::{
    BudgetInput, CheckInput, ConditionInput, ConfirmationKind, CreateSupervisionRequest,
    PlanRequestActor,
};
use herness_engine_pi::ProviderEndpoints;
use herness_runtime_tests::fixtures::ProjectFixture;
use herness_store::test_support::open_at_schema_version;
use herness_store::{Store, StoreConfig};
use herness_supervision::freshness::capture_manifest;
use herness_supervision::supervisor::{
    AssessmentProfileFacts, CheckExecution, CheckExecutionRequest, ConditionAssessmentPort,
    RequiredCheckPort,
};
use herness_supervision::{
    AdapterVersion, ApprovalActor, AssessmentOutcome, AssessmentProfile, AssessmentProvenance,
    AssessmentRequest, AssessmentResult, BudgetLedger, CheckStatus, ConditionVerdict, ConsentId,
    DisclosureConsent, DisclosureDataKind, DisclosureScope, EvidenceAcquirer, EvidenceOutcome,
    EvidenceRecord, EvidenceScope, ProfileEntry, ProfileInputs, ProfilePurpose, ProfileThresholds,
    ProfileVersion, ProviderKind, ProviderOrigin, RubricVersion, SupervisionRequestId,
    TargetReadSet, TargetVersion,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;

const SCHEMA_BEFORE: u32 = 3;
const AGENT_MODEL: &str = "gpt-test";
const ASSESSMENT_MODEL: &str = "permission-judge-fixture";

// ---------------------------------------------------------------------------
// Loopback mocks.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
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

    fn json(value: Value) -> Self {
        Self {
            status: 200,
            content_type: "application/json",
            body: value.to_string(),
        }
    }
}

struct QueueServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl QueueServer {
    fn start(responses: Vec<MockResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent mock");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_responses = Arc::clone(&responses);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = Arc::clone(&thread_requests);
                        let responses = Arc::clone(&thread_responses);
                        thread::spawn(move || respond_queue(stream, requests, responses));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for QueueServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn respond_queue(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    loop {
        let Some(body) = read_request_body(&mut stream) else {
            return;
        };
        requests.lock().unwrap().push(body);
        let response = responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| MockResponse::json(json!({"error": "agent mock exhausted"})));
        if write_response(&mut stream, &response).is_err() {
            return;
        }
    }
}

struct AssessmentServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl AssessmentServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind assessment mock");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_count = Arc::clone(&count);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = Arc::clone(&thread_requests);
                        let count = Arc::clone(&thread_count);
                        thread::spawn(move || respond_assessment(stream, requests, count));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            requests,
            count,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn openai_base(&self) -> String {
        format!("{}/v1", self.url())
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for AssessmentServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn respond_assessment(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    count: Arc<AtomicUsize>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    loop {
        let Some(body) = read_request_body(&mut stream) else {
            return;
        };
        count.fetch_add(1, Ordering::SeqCst);
        requests.lock().unwrap().push(body.clone());
        let response = permission_response(&body);
        if write_response(&mut stream, &response).is_err() {
            return;
        }
    }
}

fn permission_response(body: &[u8]) -> MockResponse {
    let request: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let payload = request
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| messages.last())
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .and_then(|content| serde_json::from_str::<Value>(content).ok())
        .unwrap_or(Value::Null);
    let choice = json!({
        "decision": "allow",
        "operationId": payload.get("operationId").and_then(Value::as_str).unwrap_or_default(),
        "argumentsDigest": payload.get("argumentsDigest").and_then(Value::as_str).unwrap_or_default(),
        "cwd": payload.get("cwd").and_then(Value::as_str).unwrap_or_default(),
        "policyVersion": payload.get("policyVersion").and_then(Value::as_u64).unwrap_or(1),
        "mode": payload.get("permissionMode").and_then(Value::as_str).unwrap_or("automatic"),
        "rationale": "The frozen operation is inside the requested boundary.",
        "uncertainty": null,
    });
    MockResponse::json(json!({
        "model": ASSESSMENT_MODEL,
        "choices": [{
            "finish_reason": "stop",
            "message": {"content": choice.to_string()},
        }],
    }))
}

fn write_response(stream: &mut TcpStream, response: &MockResponse) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(response.body.as_bytes())?;
    stream.flush()
}

fn read_request_body(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > 1024 * 1024 {
            return None;
        }
    };
    let header = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut content_length = 0_usize;
    for line in header.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().ok()?;
        }
    }
    while buffer.len() < header_end + content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    Some(buffer[header_end..header_end + content_length].to_vec())
}

// ---------------------------------------------------------------------------
// SSE fixtures.
// ---------------------------------------------------------------------------

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
            "id": "fc_task17",
            "call_id": "call_task17",
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

struct FakeCredentials;

impl CredentialPort for FakeCredentials {
    fn availability(
        &self,
        _connection: &ConnectionId,
    ) -> Result<CredentialAvailability, CoreError> {
        Ok(CredentialAvailability::Available)
    }

    fn resolve(&self, _connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        Ok(ResolvedCredential::new(
            CredentialKind::ApiKey,
            SecretString::new("sk-task17-cross-phase").expect("fake credential"),
        ))
    }
}

// ---------------------------------------------------------------------------
// Scripted supervision ports.
// ---------------------------------------------------------------------------

struct ScriptedAssessment {
    verdicts: Arc<Mutex<VecDeque<ConditionVerdict>>>,
}

impl ScriptedAssessment {
    fn new(verdicts: Vec<ConditionVerdict>) -> Self {
        Self {
            verdicts: Arc::new(Mutex::new(VecDeque::from(verdicts))),
        }
    }
}

impl ConditionAssessmentPort for ScriptedAssessment {
    fn profile(
        &self,
        _binding: herness_supervision::ProfileBinding,
    ) -> Result<AssessmentProfileFacts, herness_supervision::SupervisionError> {
        Ok(AssessmentProfileFacts::new(
            AdapterVersion::new("scripted-task17-adapter-1")?,
            RubricVersion::new("scripted-task17-rubric-1")?,
            ProfileThresholds::normal_llm(),
        ))
    }

    fn assess(
        &mut self,
        request: &AssessmentRequest,
    ) -> Result<AssessmentResult, herness_supervision::SupervisionError> {
        let verdict = self
            .verdicts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(ConditionVerdict::Insufficient);
        let provenance = AssessmentProvenance::new(
            Provider::OpenAi,
            ProviderKind::NormalLlm,
            herness_core::contracts::ModelId::new("scripted-task17-judge")
                .expect("static scripted model"),
            request.adapter_version().clone(),
            request.rubric_version().clone(),
        )?;
        AssessmentResult::new(
            request,
            request.evidence().to_vec(),
            "scripted Task 17 assessment",
            None,
            AssessmentOutcome::NormalLlm {
                verdict,
                confidence: None,
            },
            provenance,
            Timestamp::now(),
        )
    }
}

struct PassCheck {
    root: PathBuf,
}

impl RequiredCheckPort for PassCheck {
    fn execute(
        &mut self,
        request: &CheckExecutionRequest,
    ) -> Result<CheckExecution, herness_supervision::SupervisionError> {
        let workspace =
            herness_desktop::supervision::workspace::ProjectWorkspace::new(self.root.clone());
        let manifest = capture_manifest(
            &workspace,
            request.project_id(),
            request.target_version(),
            TargetReadSet::Declared(request.read_set().to_vec()),
        )?;
        let target = manifest.target_scope()?;
        let evidence = EvidenceRecord::new(
            request.evidence_id(),
            request.supervision_id(),
            Some(request.condition_id()),
            Some(request.check_id()),
            EvidenceAcquirer::ChildAgent,
            request.operation().clone(),
            EvidenceOutcome::new(Some(0), None, false, false, "exit=0")?,
            target,
            EvidenceScope::new(
                vec![format!("check: {}", request.check_id())],
                vec!["scripted Task 17 check evidence".to_owned()],
            )?,
            CheckStatus::Pass,
            request.sequence(),
            Timestamp::now(),
        )?;
        let result = herness_supervision::RequiredCheckResult::from_evidence(
            &evidence,
            request.condition_version(),
        )?;
        Ok(CheckExecution::new(result, Some(evidence)))
    }
}

struct PanicAssessment;

impl ConditionAssessmentPort for PanicAssessment {
    fn profile(
        &self,
        _binding: herness_supervision::ProfileBinding,
    ) -> Result<AssessmentProfileFacts, herness_supervision::SupervisionError> {
        panic!("restore must not call the assessment port");
    }

    fn assess(
        &mut self,
        _request: &AssessmentRequest,
    ) -> Result<AssessmentResult, herness_supervision::SupervisionError> {
        panic!("restore must not call the assessment port");
    }
}

struct PanicCheck;

impl RequiredCheckPort for PanicCheck {
    fn execute(
        &mut self,
        _request: &CheckExecutionRequest,
    ) -> Result<CheckExecution, herness_supervision::SupervisionError> {
        panic!("restore must not execute a required check");
    }
}

// ---------------------------------------------------------------------------
// Permission budget gate.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct CountingGate {
    state: Arc<Mutex<GateState>>,
}

#[derive(Default)]
struct GateState {
    admits: usize,
    observations: usize,
}

impl CountingGate {
    fn shared(&self) -> SharedModelRequestGate {
        SharedModelRequestGate::new(Box::new(self.clone()))
    }

    fn admits(&self) -> usize {
        self.state.lock().unwrap().admits
    }
}

impl ModelRequestGatePort for CountingGate {
    fn admit(&mut self, _intent: &RequestGateIntent) -> Result<RequestGateOutcome, CoreError> {
        self.state.lock().unwrap().admits += 1;
        Ok(RequestGateOutcome::Admit)
    }

    fn observe(&mut self, _observation: &ModelRequestObservation) -> Result<(), CoreError> {
        self.state.lock().unwrap().observations += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Old schema fixture.
// ---------------------------------------------------------------------------

type LegacyEventRow = (
    String,
    i64,
    i64,
    String,
    String,
    String,
    Option<String>,
    String,
    i64,
    String,
);

fn raw(path: &Path) -> Connection {
    Connection::open(path).expect("raw sqlite")
}

#[allow(clippy::too_many_arguments)]
fn insert_legacy_event(
    conn: &Connection,
    fixture: &ProjectFixture,
    sequence: u64,
    contract_version: u32,
    operation: Option<herness_core::OperationId>,
    kind: &str,
    occurred_at: u64,
    payload: &str,
) {
    conn.execute(
        "INSERT INTO events (project_id, sequence, contract_version, agent_id, session_id,
                             run_id, operation_id, kind, occurred_at, payload)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            fixture.project_id.to_string(),
            i64::try_from(sequence).unwrap(),
            i64::from(contract_version),
            fixture.agent_id.to_string(),
            fixture.session_id.to_string(),
            fixture.run_id.to_string(),
            operation.map(|operation| operation.to_string()),
            kind,
            i64::try_from(occurred_at).unwrap(),
            payload,
        ],
    )
    .expect("legacy event");
}

fn legacy_rows(conn: &Connection) -> Vec<LegacyEventRow> {
    conn.prepare(
        "SELECT project_id, sequence, contract_version, agent_id, session_id, run_id,
                operation_id, kind, occurred_at, payload
         FROM events ORDER BY sequence ASC",
    )
    .expect("legacy query")
    .query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
        ))
    })
    .expect("legacy rows")
    .map(Result::unwrap)
    .collect()
}

fn create_legacy_store(config: &StoreConfig) -> (ProjectFixture, Vec<LegacyEventRow>) {
    let fixture = ProjectFixture::new();
    let operation = herness_core::OperationId::new(fixture.project_id);
    {
        let store = open_at_schema_version(config.clone(), SCHEMA_BEFORE).expect("schema 3");
        assert_eq!(store.schema_version().expect("version"), SCHEMA_BEFORE);
    }
    let conn = raw(&config.database_path());
    conn.execute(
        "INSERT INTO checkpoints (run_id, project_id, format_version, payload, last_sequence)
         VALUES (?1, ?2, 1, ?3, 2)",
        rusqlite::params![
            fixture.run_id.to_string(),
            fixture.project_id.to_string(),
            b"legacy-task17-checkpoint".as_slice(),
        ],
    )
    .expect("legacy checkpoint");
    conn.execute(
        "INSERT INTO project_sequences (project_id, next_sequence) VALUES (?1, 3)",
        [fixture.project_id.to_string()],
    )
    .expect("legacy sequence");
    conn.execute(
        "INSERT INTO operations (operation_id, project_id, run_id, tool, arguments, cwd,
                                 policy_version, permission_mode, recorded_at)
         VALUES (?1, ?2, ?3, 'write', ?4, ?5, 7, 'configured', 10)",
        rusqlite::params![
            operation.to_string(),
            fixture.project_id.to_string(),
            fixture.run_id.to_string(),
            serde_json::to_string(&herness_core::ToolArguments::Write(
                herness_core::WriteArgs {
                    path: herness_core::NonEmptyText::new("notes.txt").expect("path"),
                    content: "legacy".to_owned(),
                    rationale: herness_core::Rationale::new("legacy fixture").expect("rationale"),
                }
            ))
            .expect("arguments"),
            fixture.cwd().as_str(),
        ],
    )
    .expect("legacy operation");
    insert_legacy_event(
        &conn,
        &fixture,
        1,
        1,
        None,
        "run.state_changed",
        1_000,
        r#"{"legacy":1}"#,
    );
    insert_legacy_event(
        &conn,
        &fixture,
        2,
        2,
        Some(operation),
        "operation.requested",
        2_000,
        r#"{"legacy":2}"#,
    );
    let rows = legacy_rows(&conn);
    assert_eq!(rows.len(), 2);
    (fixture, rows)
}

fn assert_legacy_preserved(
    store: &Arc<Mutex<Store>>,
    database_path: &Path,
    fixture: &ProjectFixture,
    before: &[LegacyEventRow],
) {
    assert_eq!(store.lock().unwrap().schema_version().unwrap(), 8);
    let conn = raw(database_path);
    assert_eq!(legacy_rows(&conn), before);
    let next_sequence: i64 = conn
        .query_row(
            "SELECT next_sequence FROM project_sequences WHERE project_id = ?1",
            [fixture.project_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(next_sequence, 3);
    let checkpoint = store
        .lock()
        .unwrap()
        .load_checkpoint(&fixture.run_id)
        .unwrap()
        .expect("legacy checkpoint");
    assert_eq!(checkpoint.payload().as_bytes(), b"legacy-task17-checkpoint");
    let page = store
        .lock()
        .unwrap()
        .history(HistoryQuery::first(fixture.project_id))
        .expect("history");
    assert_eq!(
        page.events()
            .iter()
            .map(herness_core::Event::sequence)
            .collect::<Vec<_>>(),
        vec![2, 1]
    );
    assert_eq!(page.events()[1].payload().as_value(), &json!({"legacy": 1}));
    assert_eq!(page.events()[0].payload().as_value(), &json!({"legacy": 2}));
}

fn input_ids(store: &Arc<Mutex<Store>>, project: ProjectId) -> Vec<String> {
    store
        .lock()
        .unwrap()
        .history(HistoryQuery::first(project))
        .expect("history")
        .events()
        .iter()
        .filter(|event| event.kind().as_str() == "run.input_submitted")
        .filter_map(|event| {
            event
                .payload()
                .as_value()
                .get("inputId")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Test.
// ---------------------------------------------------------------------------

#[test]
fn old_store_real_pi_supervision_budget_permission_and_quit_restore() {
    let temp = TempDir::new().expect("temp");
    let project_root = temp.path().join("project");
    std::fs::create_dir_all(project_root.join("src")).expect("project dirs");
    std::fs::write(project_root.join("src/main.rs"), "fn main() {}\n").expect("project file");
    let app_data = temp.path().join("app-data");
    let config = StoreConfig::new(&app_data).expect("store config");
    let (legacy_fixture, legacy_before) = create_legacy_store(&config);

    let agent_server = QueueServer::start(vec![
        responses_tool_call(
            "write",
            json!({
                "path": "notes.txt",
                "content": "task 17 fixture",
                "rationale": "record the cross-phase fixture note"
            }),
        ),
        responses_text("first task 17 run"),
        responses_text("second task 17 run"),
    ]);
    let assessment_server = AssessmentServer::start();

    let agent_connection = ConnectionId::new();
    let assessment_connection = ConnectionId::new();
    let agent_settings = ConnectionSettings::new(
        agent_connection,
        Provider::OpenAi,
        AGENT_MODEL,
        AuthMethod::ApiKey,
        None::<Endpoint>,
        None,
    )
    .expect("agent settings");
    let assessment_settings = ConnectionSettings::new_with_capabilities(
        assessment_connection,
        Provider::OpenAiCompatible,
        ASSESSMENT_MODEL,
        AuthMethod::ApiKey,
        Some(Endpoint::parse(&assessment_server.openai_base()).expect("assessment endpoint")),
        None,
        herness_core::ConnectionCapabilityDeclaration::new(
            EndpointClass::OpenAiCompletions,
            InputCapabilities::text_only(),
        ),
    )
    .expect("assessment settings");
    let admin = ConnectionAdmin::new();
    admin.add(agent_settings.clone()).expect("agent connection");
    admin
        .add(assessment_settings.clone())
        .expect("assessment connection");
    let credentials: Arc<dyn CredentialPort + Send + Sync> = Arc::new(FakeCredentials);
    let endpoints =
        ProviderEndpoints::for_loopback(format!("{}/v1", agent_server.url()), agent_server.url())
            .expect("agent endpoints");

    // First opening migrates schema 3 to the current schema and persists the
    // project id that later openings reuse. It does not start a run.
    let (mut setup, _) =
        DesktopHost::open(&app_data, admin, credentials.clone(), endpoints.clone())
            .expect("setup host");
    let setup_store = setup.store_handle();
    assert_legacy_preserved(
        setup_store.shared(),
        &config.database_path(),
        &legacy_fixture,
        &legacy_before,
    );
    let directory = setup.directory().clone();
    let project = setup
        .open_project(&project_root)
        .expect("setup project")
        .project_id();
    drop(setup);

    // Build the real permission evaluator against the same store-backed project
    // and the loopback assessment server. The gate is counted and admitted for
    // the one permission request.
    let permission_profile = permission_profile_for_project(project, assessment_connection);
    let permission_entry = ProfileEntry::new(
        permission_profile,
        assessment_settings
            .capabilities()
            .expect("assessment capabilities"),
        ConnectionStatus::Available,
        false,
    );
    let permission_origin =
        ProviderOrigin::parse(assessment_server.url()).expect("assessment origin");
    let permission_consent = DisclosureConsent::grant(
        ApprovalActor::Human,
        ConsentId::new(project),
        permission_origin.clone(),
        DisclosureScope::new(
            ProfilePurpose::Permission,
            BTreeSet::from([DisclosureDataKind::Text, DisclosureDataKind::Code]),
            vec!["src/main.rs".to_owned(), "notes.txt".to_owned()],
            TargetVersion::new(1).expect("target version"),
        )
        .expect("permission disclosure scope"),
        Timestamp::now(),
    )
    .expect("permission consent");
    let permission_gate = CountingGate::default();
    let permission_transport = AssessmentTransport::new(
        credentials.clone(),
        directory,
        AssessmentEndpoints::for_loopback(
            assessment_server.url(),
            assessment_server.openai_base(),
            assessment_server.url(),
        )
        .expect("assessment endpoints"),
    )
    .expect("assessment transport")
    .with_retry_policy(RetryPolicy::with_base_delays([
        Duration::from_millis(1),
        Duration::from_millis(1),
    ]));
    let permission_config = PermissionEvaluatorConfig::new(
        permission_entry,
        Some(permission_consent),
        permission_origin,
        TargetVersion::new(1).expect("target version"),
        permission_transport,
    )
    .with_budget_scope(PermissionBudgetScope::RunScoped { max_requests: 4 })
    .with_budget_gate(permission_gate.shared());
    let permission_evaluator = PermissionEvaluator::new(permission_config)
        .expect("permission evaluator")
        .into_shared();

    let second_admin = ConnectionAdmin::new();
    second_admin
        .add(agent_settings.clone())
        .expect("agent connection");
    second_admin
        .add(assessment_settings.clone())
        .expect("assessment connection");
    let (mut host, _) = DesktopHost::open_with_test_boundaries(
        &app_data,
        second_admin,
        credentials.clone(),
        endpoints.clone(),
        Some(permission_evaluator),
        Box::new(ScriptedAssessment::new(vec![
            ConditionVerdict::Unmet,
            ConditionVerdict::Met,
        ])),
        Box::new(PassCheck {
            root: project_root.clone(),
        }),
    )
    .expect("cross-phase host");
    assert_eq!(
        host.open_project(&project_root)
            .expect("project")
            .project_id(),
        project
    );
    host.runtime_mut()
        .policy_admin_mut()
        .set_mode(
            herness_core::PermissionMode::Automatic,
            herness_core::EvaluatorAvailability::Available,
        )
        .expect("automatic mode");

    host.supervision_configure_profile(
        PlanRequestActor::Human,
        project,
        herness_supervision::ProfilePurpose::Completion,
        agent_connection,
        AGENT_MODEL,
        Some(host.confirm_supervision(ConfirmationKind::Profile)),
    )
    .expect("completion profile");
    host.supervision_grant_consent(
        PlanRequestActor::Human,
        project,
        herness_supervision::ProfilePurpose::Completion,
        ProviderOrigin::parse("https://api.openai.com").expect("origin"),
        BTreeSet::from([
            herness_supervision::DisclosureDataKind::Text,
            herness_supervision::DisclosureDataKind::Code,
        ]),
        vec!["src/main.rs".to_owned(), "notes.txt".to_owned()],
        TargetVersion::new(1).expect("target version"),
        Some(host.confirm_supervision(ConfirmationKind::Consent)),
    )
    .expect("completion consent");
    let created = host
        .supervision_create(
            PlanRequestActor::Human,
            CreateSupervisionRequest {
                project,
                connection: agent_connection,
                instructions: "Implement the approved change.".to_owned(),
                conditions: vec![ConditionInput {
                    title: "The check passes".to_owned(),
                    rubric: "The required check must pass on the current target.".to_owned(),
                    checks: vec![CheckInput {
                        command: "true".to_owned(),
                        description: "trivial scripted passing command".to_owned(),
                    }],
                }],
                read_set: vec!["src/main.rs".to_owned()],
                write_paths: vec!["src".to_owned(), "notes.txt".to_owned()],
                allow_shell: false,
                condition_version: Some(1),
                target_version: Some(1),
                budget: Some(BudgetInput {
                    active_seconds: 7_200,
                    additional_runs: 30,
                    money_limit_micros: None,
                    price_version: None,
                }),
            },
            Some(host.confirm_supervision(ConfirmationKind::Create)),
        )
        .expect("create supervision");
    let supervision = created.supervision_id;
    let view = host.supervision_get(project, supervision).expect("view");
    host.supervision_start(
        project,
        supervision,
        SupervisionRequestId::new(project),
        view.revision,
        Some(host.confirm_supervision(ConfirmationKind::Start)),
    )
    .expect("start supervision");

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        host.pump().expect("host pump");
        let view = host.supervision_get(project, supervision).expect("view");
        if view.state == "completed" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "supervision did not complete: state={} reason={}",
            view.state,
            view.reason
        );
        thread::sleep(Duration::from_millis(220));
    }
    let completed = host
        .supervision_get(project, supervision)
        .expect("completed view");
    assert!(completed.completion.is_some());
    assert_eq!(
        completed.run_group.len(),
        2,
        "first run and one continuation"
    );
    assert_eq!(
        agent_server.count(),
        3,
        "tool call, follow-up, and continuation"
    );
    let agent_bodies = agent_server.bodies();
    assert_eq!(agent_bodies.len(), 3);
    assert!(
        String::from_utf8_lossy(&agent_bodies[2]).contains("first task 17 run"),
        "the continuation did not preserve the previous run's conversation"
    );
    assert_eq!(assessment_server.count(), 1, "one permission evaluation");
    assert_eq!(permission_gate.admits(), 1);
    assert!(project_root.join("notes.txt").exists());
    assert_eq!(
        std::fs::read_to_string(project_root.join("notes.txt")).unwrap(),
        "task 17 fixture"
    );
    let permission_bodies = assessment_server.bodies();
    assert_eq!(permission_bodies.len(), 1);
    assert!(
        String::from_utf8_lossy(&permission_bodies[0]).contains("permission")
            || String::from_utf8_lossy(&permission_bodies[0]).contains("messages")
    );

    let store_handle = host.store_handle();
    let plans = host.supervision().plans();
    let plan = plans
        .lock()
        .unwrap()
        .get(&(project, supervision))
        .cloned()
        .expect("stored plan");
    let policy = plan.budget.policy().expect("budget policy");
    let usage_before = {
        let mut ledger = BudgetLedger::open(
            store_handle.clone(),
            project,
            supervision,
            policy.clone(),
            plan.budget_version,
            HostBudgetClock::new(),
        )
        .expect("ledger before quit");
        ledger.effective_usage().expect("usage before quit")
    };
    assert_eq!(usage_before.runs_started(), 2);
    assert!(usage_before.active_seconds_consumed() > 0);
    let inputs_before = input_ids(store_handle.shared(), project);
    assert_eq!(inputs_before.len(), 2, "two inputs were accepted");
    let agent_requests_before_quit = agent_server.count();
    let assessment_requests_before_quit = assessment_server.count();

    let _report = host.begin_shutdown().expect("begin shutdown");
    let report = host.stop_all_for_shutdown().expect("stop for shutdown");
    host.mark_supervision_for_quit(&report).expect("quit mark");
    host.finish_shutdown().expect("finish shutdown");
    drop(host);

    let third_admin = ConnectionAdmin::new();
    third_admin.add(agent_settings).expect("agent connection");
    third_admin
        .add(assessment_settings)
        .expect("assessment connection");
    let (mut restored, _) = DesktopHost::open_with_test_boundaries(
        &app_data,
        third_admin,
        credentials,
        endpoints,
        None,
        Box::new(PanicAssessment),
        Box::new(PanicCheck),
    )
    .expect("restored host");
    let restored_project = restored
        .open_project(&project_root)
        .expect("restored project")
        .project_id();
    assert_eq!(restored_project, project);
    restored.pump().expect("restored pump");
    assert_eq!(
        agent_server.count(),
        agent_requests_before_quit,
        "restore must not send an agent request"
    );
    assert_eq!(
        assessment_server.count(),
        assessment_requests_before_quit,
        "restore must not send an assessment request"
    );
    let restored_view = restored
        .supervision_get(project, supervision)
        .expect("restored view");
    assert_eq!(restored_view.state, "completed");
    let restored_store = restored.store_handle();
    let inputs_after = input_ids(restored_store.shared(), project);
    assert_eq!(
        inputs_after, inputs_before,
        "restore must not replay an input"
    );

    let usage_after = {
        let mut ledger = BudgetLedger::open(
            restored.store_handle(),
            project,
            supervision,
            policy,
            plan.budget_version,
            HostBudgetClock::new(),
        )
        .expect("ledger after restore");
        ledger.effective_usage().expect("usage after restore")
    };
    assert_eq!(usage_after.runs_started(), usage_before.runs_started());
    assert!(
        usage_after.active_seconds_consumed() >= usage_before.active_seconds_consumed(),
        "restore must not reset consumed budget"
    );
}

fn permission_profile_for_project(
    project: ProjectId,
    connection: ConnectionId,
) -> AssessmentProfile {
    AssessmentProfile::new(
        herness_supervision::ProfileId::new(project),
        ProfileVersion::new(1).expect("profile version"),
        ProfilePurpose::Permission,
        ProviderKind::NormalLlm,
        connection,
        ModelId::new(ASSESSMENT_MODEL).expect("model"),
        AdapterVersion::new("fixture-permission-llm-adapter-1").expect("adapter"),
        RubricVersion::new("fixture-permission-rubric-1").expect("rubric"),
        ProfileInputs::text_only(),
        ProfileThresholds::normal_llm(),
    )
    .expect("permission profile")
}
