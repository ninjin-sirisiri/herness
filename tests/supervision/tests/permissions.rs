//! Black-box permission-evaluator tests.
//!
//! Every provider request goes to a loopback HTTP mock with a fake in-memory
//! credential. No real provider, Keychain item, login, paid call, or external
//! network request is used.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use herness_assessment::{
    AssessmentEndpoints, AssessmentTransport, CancelToken, PermissionBudgetScope,
    PermissionConsentHandle, PermissionEvaluator, PermissionEvaluatorConfig, RetryPolicy,
    SharedModelRequestGate, TransportControl,
};
use herness_core::*;
use herness_store::{Store, StoreConfig};
use herness_supervision::{
    ApprovalActor, BudgetClockPort, BudgetLedger, BudgetLedgerRecord, BudgetPolicy,
    BudgetRequestGate, BudgetStorePort, ClockReading, DisclosureConsent, DisclosureDataKind,
    DisclosureScope, ProfileEntry, ProfileInputs, ProfilePurpose, ProviderKind, ProviderOrigin,
    RequestBudgetEstimate, StoredBudgetRecord, SupervisionError, SupervisionId, TargetVersion,
};
use herness_supervision_tests::{
    consent_for_origin, ids, now, permission_entry_for, permission_profile_for_provider, project,
};
use serde_json::{Value, json};

const API_KEY: &str = "sk-permission-canary-7f2c9d1e";
const CANARY: &str = "provider-body-canary-4a8e1c0d";
const JEV_MODEL: &str = "jev-1.14.0";
const DECISIONS_MODEL: &str = "gpt-6-luna";
const LLM_MODEL: &str = "permission-llm";

// ---------------------------------------------------------------------------
// Loopback HTTP mock
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct RecordedRequest {
    #[allow(dead_code)]
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

#[derive(Clone, Debug)]
struct MockResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    delay: Duration,
}

impl MockResponse {
    fn json(status: u16, value: Value) -> Self {
        Self::raw_json(status, serde_json::to_vec(&value).expect("mock body"))
    }

    fn raw_json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into(),
            delay: Duration::ZERO,
        }
    }

    fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

struct MockServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl MockServer {
    fn start() -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback mock");
        listener
            .set_nonblocking(true)
            .expect("nonblocking loopback mock");
        let address = listener.local_addr().expect("mock address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(VecDeque::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_responses = Arc::clone(&responses);
        let thread_stop = Arc::clone(&stop);
        let accept_thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _peer)) => {
                        let requests = Arc::clone(&thread_requests);
                        let responses = Arc::clone(&thread_responses);
                        thread::spawn(move || handle_connection(stream, requests, responses));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Arc::new(Self {
            address,
            requests,
            responses,
            stop,
            accept_thread: Some(accept_thread),
        })
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn openai_base(&self) -> String {
        format!("{}/v1", self.url())
    }

    fn push(&self, response: MockResponse) {
        self.responses
            .lock()
            .expect("responses")
            .push_back(response);
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("requests").clone()
    }

    fn count(&self) -> usize {
        self.requests.lock().expect("requests").len()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
) {
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    requests.lock().expect("requests").push(request);
    let response = responses
        .lock()
        .expect("responses")
        .pop_front()
        .unwrap_or_else(|| {
            MockResponse::raw_json(404, br#"{"error":"no scripted response"}"#.to_vec())
        });
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
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Status",
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
    let mut headers = BTreeMap::new();
    let mut content_length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        if name == "content-length" {
            content_length = value.parse().unwrap_or(0);
        }
        headers.insert(name, value);
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
        body,
    })
}

// ---------------------------------------------------------------------------
// Credentials and fixtures
// ---------------------------------------------------------------------------

struct FakeCredential {
    secret: Option<String>,
    kind: CredentialKind,
    calls: AtomicUsize,
}

impl FakeCredential {
    fn api_key(secret: &str) -> Arc<Self> {
        Arc::new(Self {
            secret: Some(secret.to_owned()),
            kind: CredentialKind::ApiKey,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CredentialPort for FakeCredential {
    fn availability(
        &self,
        _connection: &ConnectionId,
    ) -> Result<CredentialAvailability, CoreError> {
        Ok(if self.secret.is_some() {
            CredentialAvailability::Available
        } else {
            CredentialAvailability::Unavailable
        })
    }

    fn resolve(&self, connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.secret {
            Some(secret) => Ok(ResolvedCredential::new(
                self.kind,
                SecretString::new(secret.clone()).expect("non-empty secret"),
            )),
            None => Err(CoreError::AuthenticationRequired {
                connection: *connection,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Llm,
    Jev,
    Decisions,
}

struct Harness {
    _admin: ConnectionAdmin,
    server: Arc<MockServer>,
    project: ProjectId,
    profile: ProfileEntry,
    transport: AssessmentTransport,
    origin: ProviderOrigin,
    consent: DisclosureConsent,
    credentials: Arc<FakeCredential>,
}

impl Harness {
    fn new(method: Method) -> Self {
        let server = MockServer::start();
        let project = project();
        let admin = ConnectionAdmin::new();
        let directory = admin.directory();
        let credentials = FakeCredential::api_key(API_KEY);
        let (settings, provider, model) = match method {
            Method::Llm => (
                ConnectionSettings::new_with_capabilities(
                    ConnectionId::new(),
                    Provider::OpenAiCompatible,
                    LLM_MODEL,
                    AuthMethod::ApiKey,
                    Some(Endpoint::parse(&server.openai_base()).expect("loopback endpoint")),
                    None,
                    ConnectionCapabilityDeclaration::new(
                        EndpointClass::OpenAiCompletions,
                        InputCapabilities::text_only(),
                    ),
                )
                .expect("llm settings"),
                ProviderKind::NormalLlm,
                LLM_MODEL,
            ),
            Method::Jev => (
                ConnectionSettings::new_with_capabilities(
                    ConnectionId::new(),
                    Provider::TypeSafe,
                    JEV_MODEL,
                    AuthMethod::ApiKey,
                    None,
                    None,
                    ConnectionCapabilityDeclaration::new(
                        EndpointClass::TypeSafeSystemOne,
                        InputCapabilities::text_only(),
                    ),
                )
                .expect("jev settings"),
                ProviderKind::Jev,
                JEV_MODEL,
            ),
            Method::Decisions => (
                ConnectionSettings::new_with_capabilities(
                    ConnectionId::new(),
                    Provider::OpenAi,
                    DECISIONS_MODEL,
                    AuthMethod::ApiKey,
                    None,
                    None,
                    ConnectionCapabilityDeclaration::new(
                        EndpointClass::OpenAiDecisions,
                        InputCapabilities::text_only(),
                    ),
                )
                .expect("decisions settings"),
                ProviderKind::Decisions,
                DECISIONS_MODEL,
            ),
        };
        admin.add(settings.clone()).expect("register connection");
        let profile = permission_profile_for_provider(
            project,
            provider,
            settings.connection_id(),
            model,
            ProfileInputs::text_only(),
        );
        let profile = permission_entry_for(&settings, profile, false);
        let endpoints =
            AssessmentEndpoints::for_loopback(server.url(), server.openai_base(), server.url())
                .expect("loopback assessment endpoints");
        let transport = AssessmentTransport::new(credentials.clone(), directory, endpoints)
            .expect("assessment transport")
            .with_retry_policy(RetryPolicy::with_base_delays([
                Duration::from_millis(1),
                Duration::from_millis(1),
            ]));
        let origin = ProviderOrigin::parse(server.url()).expect("loopback origin");
        let consent = consent_for_origin(project, ProfilePurpose::Permission, 1, origin.clone());
        Self {
            _admin: admin,
            server,
            project,
            profile,
            transport,
            origin,
            consent,
            credentials,
        }
    }

    fn into_evaluator(
        self,
        consent: Option<DisclosureConsent>,
        gate: Option<SharedModelRequestGate>,
        scope: PermissionBudgetScope,
    ) -> (PermissionEvaluator, Arc<MockServer>, Arc<FakeCredential>) {
        let mut config = PermissionEvaluatorConfig::new(
            self.profile,
            consent,
            self.origin,
            target(1),
            self.transport,
        )
        .with_budget_scope(scope);
        if let Some(gate) = gate {
            config = config.with_budget_gate(gate);
        }
        let evaluator = PermissionEvaluator::new(config).expect("permission evaluator");
        (evaluator, self.server, self.credentials)
    }
}

fn target(version: u64) -> TargetVersion {
    TargetVersion::new(version).expect("target version")
}

fn evaluation_request(project: ProjectId, seed: u128) -> EvaluationRequest {
    let run = RunId::from_parts(project, uuid::Uuid::from_u128(0x5eed));
    let arguments = ToolArguments::Write(WriteArgs {
        path: NonEmptyText::new("src/lib.rs").expect("path"),
        content: format!("fixture content {seed}"),
        rationale: Rationale::new("update the fixture").expect("rationale"),
    });
    let operation = FrozenOperation::new(
        OperationId::from_parts(project, uuid::Uuid::from_u128(seed)),
        run,
        ToolName::Write,
        arguments,
        AbsolutePath::new("/tmp/permission-fixture").expect("absolute cwd"),
        PolicyVersion::INITIAL,
        PermissionMode::Automatic,
    )
    .expect("frozen operation");
    EvaluationRequest::new(
        operation,
        "update the fixture module",
        "write only inside src/lib.rs",
        vec!["the fixture content is expected".to_owned()],
    )
}

fn permission_body(request: &EvaluationRequest, decision: &str) -> Value {
    let operation = request.operation();
    json!({
        "decision": decision,
        "operationId": operation.operation_id().to_string(),
        "argumentsDigest": ArgumentsDigest::of(operation.arguments()).to_string(),
        "cwd": operation.cwd().to_string(),
        "policyVersion": operation.policy_version().get(),
        "mode": operation.permission_mode().to_string(),
        "rationale": "The frozen operation is inside the requested boundary.",
        "uncertainty": null,
    })
}

fn llm_envelope(value: &Value) -> MockResponse {
    MockResponse::json(
        200,
        json!({
            "model": LLM_MODEL,
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": value.to_string()},
            }],
        }),
    )
}

fn llm_raw(content: &str) -> MockResponse {
    MockResponse::json(
        200,
        json!({
            "model": LLM_MODEL,
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": content},
            }],
        }),
    )
}

fn question_id(request: &EvaluationRequest) -> String {
    herness_assessment::permission_question_id(request.operation())
}

fn jev_response(
    request: &EvaluationRequest,
    choice: &str,
    allow: f64,
    deny: f64,
    ask: f64,
    confidence: f64,
) -> MockResponse {
    MockResponse::json(
        200,
        json!({
            "model": JEV_MODEL,
            "answers": {
                question_id(request): {
                    "type": "choice",
                    "choice": choice,
                    "confidence": confidence,
                    "probabilities": {"allow": allow, "deny": deny, "ask": ask},
                }
            },
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }),
    )
}

fn decisions_response(
    request: &EvaluationRequest,
    choice: &str,
    allow: f64,
    deny: f64,
    ask: f64,
    confidence: f64,
) -> MockResponse {
    MockResponse::json(
        200,
        json!({
            "model": DECISIONS_MODEL,
            "answers": [{
                "type": "choice",
                "name": question_id(request),
                "choice": choice,
                "confidence": confidence,
                "probabilities": [
                    {"value": "allow", "probability": allow},
                    {"value": "deny", "probability": deny},
                    {"value": "ask", "probability": ask},
                ],
            }],
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }),
    )
}

#[derive(Clone, Default)]
struct CountingGate {
    state: Arc<Mutex<GateState>>,
}

#[derive(Default)]
struct GateState {
    admits: Vec<RequestGateIntent>,
    observations: Vec<ModelRequestObservation>,
    refuse: bool,
}

impl CountingGate {
    fn shared(&self) -> SharedModelRequestGate {
        SharedModelRequestGate::new(Box::new(self.clone()))
    }

    fn admits(&self) -> usize {
        self.state.lock().expect("gate").admits.len()
    }

    fn observations(&self) -> usize {
        self.state.lock().expect("gate").observations.len()
    }

    fn refusing() -> Self {
        let gate = Self::default();
        gate.state.lock().expect("gate").refuse = true;
        gate
    }
}

impl ModelRequestGatePort for CountingGate {
    fn admit(&mut self, intent: &RequestGateIntent) -> Result<RequestGateOutcome, CoreError> {
        let mut state = self.state.lock().expect("gate");
        state.admits.push(intent.clone());
        if state.refuse {
            return Ok(RequestGateOutcome::Refuse {
                reason: RequestGateRefusal::BudgetUnavailable,
            });
        }
        Ok(RequestGateOutcome::Admit)
    }

    fn observe(&mut self, observation: &ModelRequestObservation) -> Result<(), CoreError> {
        self.state
            .lock()
            .expect("gate")
            .observations
            .push(observation.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Ledger-backed gate
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SharedBudgetStore(Arc<Mutex<Store>>);

impl BudgetStorePort for SharedBudgetStore {
    fn load_budget(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Option<StoredBudgetRecord>, SupervisionError> {
        let store = self.0.lock().expect("budget store");
        BudgetStorePort::load_budget(&*store, project_id, supervision_id)
    }

    fn compare_and_swap_budget(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &BudgetLedgerRecord,
    ) -> Result<u64, SupervisionError> {
        let mut store = self.0.lock().expect("budget store");
        BudgetStorePort::compare_and_swap_budget(
            &mut *store,
            project_id,
            supervision_id,
            expected_revision,
            next,
        )
    }

    fn commit_budget_admission(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &BudgetLedgerRecord,
        intent: &RequestGateIntent,
        recorded_at: Timestamp,
    ) -> Result<u64, SupervisionError> {
        let mut store = self.0.lock().expect("budget store");
        BudgetStorePort::commit_budget_admission(
            &mut *store,
            project_id,
            supervision_id,
            expected_revision,
            next,
            intent,
            recorded_at,
        )
    }

    fn commit_budget_observation(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &BudgetLedgerRecord,
        observation: &ModelRequestObservation,
        observed_at: Timestamp,
    ) -> Result<u64, SupervisionError> {
        let mut store = self.0.lock().expect("budget store");
        BudgetStorePort::commit_budget_observation(
            &mut *store,
            project_id,
            supervision_id,
            expected_revision,
            next,
            observation,
            observed_at,
        )
    }
}

#[derive(Clone)]
struct FakeClock(Arc<Mutex<(u64, u64)>>);

impl FakeClock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new((now().as_unix_millis(), 0))))
    }

    fn advance_seconds(&self, seconds: u64) {
        let mut state = self.0.lock().expect("clock");
        state.0 = state.0.saturating_add(seconds.saturating_mul(1_000));
        state.1 = state.1.saturating_add(seconds.saturating_mul(1_000));
    }
}

impl BudgetClockPort for FakeClock {
    fn read(&self) -> ClockReading {
        let state = self.0.lock().expect("clock");
        ClockReading::new(Timestamp::from_unix_millis(state.0), state.1)
    }
}

fn no_estimate(_intent: &RequestGateIntent) -> Option<RequestBudgetEstimate> {
    None
}

type TestBudgetGate = BudgetRequestGate<
    SharedBudgetStore,
    FakeClock,
    fn(&RequestGateIntent) -> Option<RequestBudgetEstimate>,
>;

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

fn ask(result: Result<PermissionDecision, CoreError>) {
    assert_eq!(
        result.expect("a malformed or uncertain answer is not a transport error"),
        PermissionDecision::Ask
    );
}

fn expect_decision(
    evaluator: &mut PermissionEvaluator,
    server: &MockServer,
    gate: &CountingGate,
    request: &EvaluationRequest,
    response: MockResponse,
    expected: PermissionDecision,
) {
    let before = server.count();
    server.push(response);
    assert_eq!(evaluator.evaluate(request).expect("evaluation"), expected);
    assert_eq!(server.count(), before + 1);
    assert_eq!(gate.observations(), gate.admits());
}

// ---------------------------------------------------------------------------
// Normal LLM
// ---------------------------------------------------------------------------

#[test]
fn llm_permission_evaluator_adopts_only_a_bound_rationale_without_uncertainty() {
    let harness = Harness::new(Method::Llm);
    let project = harness.project;
    let consent = harness.consent.clone();
    let gate = CountingGate::default();
    let (mut evaluator, server, _) = harness.into_evaluator(
        Some(consent),
        Some(gate.shared()),
        PermissionBudgetScope::Supervised,
    );

    let request = evaluation_request(project, 1);
    server.push(llm_envelope(&permission_body(&request, "allow")));
    assert_eq!(
        evaluator.evaluate(&request).expect("allow"),
        PermissionDecision::Allow
    );
    assert_eq!(gate.admits(), 1);
    assert_eq!(gate.observations(), 1);
    let recorded = server.requests();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].path, "/v1/chat/completions");
    let expected_auth = format!("Bearer {API_KEY}");
    assert_eq!(
        recorded[0].header("authorization"),
        Some(expected_auth.as_str())
    );

    let deny = evaluation_request(project, 2);
    server.push(llm_envelope(&permission_body(&deny, "deny")));
    assert_eq!(
        evaluator.evaluate(&deny).expect("deny"),
        PermissionDecision::Deny
    );

    let ask_request = evaluation_request(project, 3);
    server.push(llm_envelope(&permission_body(&ask_request, "ask")));
    assert_eq!(
        evaluator.evaluate(&ask_request).expect("ask"),
        PermissionDecision::Ask
    );

    let uncertain = evaluation_request(project, 4);
    let mut body = permission_body(&uncertain, "allow");
    body["uncertainty"] = json!("the boundary is ambiguous");
    server.push(llm_envelope(&body));
    assert_eq!(
        evaluator
            .evaluate(&uncertain)
            .expect("uncertainty is an ask"),
        PermissionDecision::Ask
    );

    let numeric_confidence = evaluation_request(project, 5);
    let mut body = permission_body(&numeric_confidence, "allow");
    body["confidence"] = json!(0.999);
    server.push(llm_envelope(&body));
    assert_eq!(
        evaluator
            .evaluate(&numeric_confidence)
            .expect("no probability fabrication"),
        PermissionDecision::Ask
    );

    let missing_rationale = evaluation_request(project, 6);
    let mut body = permission_body(&missing_rationale, "allow");
    body.as_object_mut().expect("object").remove("rationale");
    server.push(llm_envelope(&body));
    assert_eq!(
        evaluator
            .evaluate(&missing_rationale)
            .expect("rationale required"),
        PermissionDecision::Ask
    );

    for (seed, field, value) in [
        (7, "operationId", json!("operation:other")),
        (8, "argumentsDigest", json!("00")),
        (9, "cwd", json!("/tmp/other")),
        (10, "policyVersion", json!(2)),
        (11, "mode", json!("configured")),
        (12, "decision", json!("met")),
    ] {
        let request = evaluation_request(project, seed);
        let mut body = permission_body(&request, "allow");
        body[field] = value;
        server.push(llm_envelope(&body));
        assert_eq!(
            evaluator
                .evaluate(&request)
                .expect("stale binding is an ask"),
            PermissionDecision::Ask,
            "{field}"
        );
    }

    let malformed = evaluation_request(project, 13);
    server.push(llm_raw("not-json"));
    assert_eq!(
        evaluator.evaluate(&malformed).expect("malformed is an ask"),
        PermissionDecision::Ask
    );

    let completion = evaluation_request(project, 14);
    server.push(llm_raw(
        &json!({
            "conditions": [{
                "conditionId": "condition:fixture",
                "verdict": "met",
                "evidenceIds": ["evidence:fixture"],
                "rationale": "the completion condition is met",
                "uncertainty": null,
            }]
        })
        .to_string(),
    ));
    assert_eq!(
        evaluator
            .evaluate(&completion)
            .expect("completion verdict is not permission"),
        PermissionDecision::Ask
    );
    assert_eq!(server.count(), 14);
}

// ---------------------------------------------------------------------------
// Jev
// ---------------------------------------------------------------------------

#[test]
fn jev_permission_evaluator_enforces_threshold_distribution_and_confidence_separation() {
    let harness = Harness::new(Method::Jev);
    let project = harness.project;
    let consent = harness.consent.clone();
    let gate = CountingGate::default();
    let (mut evaluator, server, _) = harness.into_evaluator(
        Some(consent),
        Some(gate.shared()),
        PermissionBudgetScope::Supervised,
    );

    let cases = [
        ("allow", 0.99, 0.006, 0.004, 0.9, PermissionDecision::Allow),
        ("deny", 0.004, 0.99, 0.006, 0.9, PermissionDecision::Deny),
        ("allow", 0.989, 0.007, 0.004, 0.9, PermissionDecision::Ask),
        ("ask", 0.001, 0.002, 0.997, 0.99, PermissionDecision::Ask),
        (
            "allow",
            0.995,
            0.003,
            0.002,
            0.01,
            PermissionDecision::Allow,
        ),
        ("allow", 0.98, 0.012, 0.008, 0.999, PermissionDecision::Ask),
        ("deny", 0.5, 0.4, 0.1, 0.99, PermissionDecision::Ask),
    ];
    for (index, (choice, allow, deny, ask_value, confidence, expected)) in
        cases.into_iter().enumerate()
    {
        let request = evaluation_request(project, 100 + index as u128);
        let response = jev_response(&request, choice, allow, deny, ask_value, confidence);
        expect_decision(&mut evaluator, &server, &gate, &request, response, expected);
    }

    let malformed = evaluation_request(project, 120);
    let body = json!({
        "model": JEV_MODEL,
        "answers": {
            question_id(&malformed): {
                "type": "choice",
                "choice": "allow",
                "confidence": 0.9,
                "probabilities": {"allow": 0.5, "deny": 0.3, "ask": 0.198},
            }
        }
    });
    server.push(MockResponse::json(200, body));
    assert_eq!(
        evaluator.evaluate(&malformed).expect("sum is an ask"),
        PermissionDecision::Ask
    );

    let missing = evaluation_request(project, 121);
    let body = json!({
        "model": JEV_MODEL,
        "answers": {
            question_id(&missing): {
                "type": "choice",
                "choice": "allow",
                "confidence": 0.9,
                "probabilities": {"allow": 0.99, "deny": 0.01},
            }
        }
    });
    server.push(MockResponse::json(200, body));
    assert_eq!(
        evaluator
            .evaluate(&missing)
            .expect("missing choice is an ask"),
        PermissionDecision::Ask
    );

    let extra = evaluation_request(project, 122);
    let body = json!({
        "model": JEV_MODEL,
        "answers": {
            question_id(&extra): {
                "type": "choice",
                "choice": "allow",
                "confidence": 0.9,
                "probabilities": {"allow": 0.98, "deny": 0.01, "ask": 0.005, "met": 0.005},
            }
        }
    });
    server.push(MockResponse::json(200, body));
    assert_eq!(
        evaluator.evaluate(&extra).expect("extra choice is an ask"),
        PermissionDecision::Ask
    );

    let duplicate = evaluation_request(project, 123);
    let text = format!(
        "{{\"model\":\"{JEV_MODEL}\",\"answers\":{{\"{}\":{{\"type\":\"choice\",\"choice\":\"allow\",\"confidence\":0.9,\"probabilities\":{{\"allow\":0.99,\"deny\":0.005,\"ask\":0.005,\"allow\":0.99}}}}}}}}",
        question_id(&duplicate)
    );
    server.push(MockResponse::raw_json(200, text.into_bytes()));
    assert_eq!(
        evaluator
            .evaluate(&duplicate)
            .expect("duplicate key is an ask"),
        PermissionDecision::Ask
    );

    let refusal = evaluation_request(project, 124);
    server.push(MockResponse::json(
        200,
        json!({
            "model": JEV_MODEL,
            "answers": {
                question_id(&refusal): {"type": "refusal", "name": question_id(&refusal)},
            }
        }),
    ));
    assert_eq!(
        evaluator.evaluate(&refusal).expect("refusal is an ask"),
        PermissionDecision::Ask
    );

    let model_mismatch = evaluation_request(project, 125);
    server.push(MockResponse::json(
        200,
        json!({
            "model": "jev-latest",
            "answers": {
                question_id(&model_mismatch): {
                    "type": "choice",
                    "choice": "allow",
                    "confidence": 0.9,
                    "probabilities": {"allow": 0.99, "deny": 0.005, "ask": 0.005},
                }
            }
        }),
    ));
    assert_eq!(
        evaluator
            .evaluate(&model_mismatch)
            .expect("model mismatch is an ask"),
        PermissionDecision::Ask
    );

    assert_eq!(gate.observations(), gate.admits());
    assert_eq!(server.count(), 13);
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

#[test]
fn decisions_permission_evaluator_enforces_order_distribution_and_threshold() {
    let harness = Harness::new(Method::Decisions);
    let project = harness.project;
    let consent = harness.consent.clone();
    let gate = CountingGate::default();
    let (mut evaluator, server, _) = harness.into_evaluator(
        Some(consent),
        Some(gate.shared()),
        PermissionBudgetScope::Supervised,
    );

    let cases = [
        ("allow", 0.99, 0.006, 0.004, 0.9, PermissionDecision::Allow),
        ("deny", 0.004, 0.99, 0.006, 0.9, PermissionDecision::Deny),
        ("allow", 0.989, 0.007, 0.004, 0.9, PermissionDecision::Ask),
        ("ask", 0.001, 0.002, 0.997, 0.99, PermissionDecision::Ask),
        (
            "allow",
            0.995,
            0.003,
            0.002,
            0.01,
            PermissionDecision::Allow,
        ),
        ("allow", 0.98, 0.012, 0.008, 0.999, PermissionDecision::Ask),
        ("deny", 0.5, 0.4, 0.1, 0.99, PermissionDecision::Ask),
    ];
    for (index, (choice, allow, deny, ask_value, confidence, expected)) in
        cases.into_iter().enumerate()
    {
        let request = evaluation_request(project, 200 + index as u128);
        let response = decisions_response(&request, choice, allow, deny, ask_value, confidence);
        expect_decision(&mut evaluator, &server, &gate, &request, response, expected);
    }

    let reordered = evaluation_request(project, 220);
    server.push(MockResponse::json(
        200,
        json!({
            "model": DECISIONS_MODEL,
            "answers": [{
                "type": "choice",
                "name": question_id(&reordered),
                "choice": "allow",
                "confidence": 0.9,
                "probabilities": [
                    {"value": "deny", "probability": 0.005},
                    {"value": "allow", "probability": 0.99},
                    {"value": "ask", "probability": 0.005},
                ],
            }]
        }),
    ));
    assert_eq!(
        evaluator.evaluate(&reordered).expect("order is an ask"),
        PermissionDecision::Ask
    );

    let sum = evaluation_request(project, 221);
    server.push(MockResponse::json(
        200,
        json!({
            "model": DECISIONS_MODEL,
            "answers": [{
                "type": "choice",
                "name": question_id(&sum),
                "choice": "allow",
                "confidence": 0.9,
                "probabilities": [
                    {"value": "allow", "probability": 0.5},
                    {"value": "deny", "probability": 0.3},
                    {"value": "ask", "probability": 0.198},
                ],
            }]
        }),
    ));
    assert_eq!(
        evaluator.evaluate(&sum).expect("sum is an ask"),
        PermissionDecision::Ask
    );

    let missing = evaluation_request(project, 222);
    server.push(MockResponse::json(
        200,
        json!({
            "model": DECISIONS_MODEL,
            "answers": [{
                "type": "choice",
                "name": question_id(&missing),
                "choice": "allow",
                "confidence": 0.9,
                "probabilities": [
                    {"value": "allow", "probability": 0.99},
                    {"value": "deny", "probability": 0.01},
                ],
            }]
        }),
    ));
    assert_eq!(
        evaluator
            .evaluate(&missing)
            .expect("missing choice is an ask"),
        PermissionDecision::Ask
    );

    let extra = evaluation_request(project, 223);
    server.push(MockResponse::json(
        200,
        json!({
            "model": DECISIONS_MODEL,
            "answers": [{
                "type": "choice",
                "name": question_id(&extra),
                "choice": "allow",
                "confidence": 0.9,
                "probabilities": [
                    {"value": "allow", "probability": 0.99},
                    {"value": "deny", "probability": 0.005},
                    {"value": "ask", "probability": 0.005},
                    {"value": "met", "probability": 0.0},
                ],
            }]
        }),
    ));
    assert_eq!(
        evaluator.evaluate(&extra).expect("extra choice is an ask"),
        PermissionDecision::Ask
    );

    let refusal = evaluation_request(project, 224);
    server.push(MockResponse::json(
        200,
        json!({
            "model": DECISIONS_MODEL,
            "answers": [{"type": "refusal", "name": question_id(&refusal)}],
        }),
    ));
    assert_eq!(
        evaluator.evaluate(&refusal).expect("refusal is an ask"),
        PermissionDecision::Ask
    );

    let model_mismatch = evaluation_request(project, 225);
    server.push(MockResponse::json(
        200,
        json!({
            "model": "gpt-6-luna-latest",
            "answers": [{
                "type": "choice",
                "name": question_id(&model_mismatch),
                "choice": "allow",
                "confidence": 0.9,
                "probabilities": [
                    {"value": "allow", "probability": 0.99},
                    {"value": "deny", "probability": 0.005},
                    {"value": "ask", "probability": 0.005},
                ],
            }]
        }),
    ));
    assert_eq!(
        evaluator
            .evaluate(&model_mismatch)
            .expect("model mismatch is an ask"),
        PermissionDecision::Ask
    );

    assert_eq!(gate.observations(), gate.admits());
    assert_eq!(server.count(), 13);
}

// ---------------------------------------------------------------------------
// Consent and budget
// ---------------------------------------------------------------------------

#[test]
fn permission_evaluator_sends_nothing_without_a_current_permission_consent() {
    let harness = Harness::new(Method::Llm);
    let project = harness.project;
    let gate = CountingGate::default();
    let (mut evaluator, server, credentials) =
        harness.into_evaluator(None, Some(gate.shared()), PermissionBudgetScope::Supervised);
    assert_eq!(evaluator.availability(), EvaluatorAvailability::Unavailable);
    ask(evaluator.evaluate(&evaluation_request(project, 300)));
    assert_eq!(server.count(), 0);
    assert_eq!(gate.admits(), 0);
    assert_eq!(credentials.calls(), 0);

    for name in [
        "revoked",
        "different origin",
        "different purpose",
        "target version",
    ] {
        let harness = Harness::new(Method::Llm);
        let project = harness.project;
        let server = Arc::clone(&harness.server);
        let gate = CountingGate::default();
        let consent = match name {
            "revoked" => harness
                .consent
                .clone()
                .revoke(ApprovalActor::Human, now())
                .expect("revoke"),
            "different origin" => consent_for_origin(
                project,
                ProfilePurpose::Permission,
                1,
                ProviderOrigin::parse("https://permission.example.test").expect("origin"),
            ),
            "different purpose" => consent_for_origin(
                project,
                ProfilePurpose::Completion,
                1,
                loopback_origin(&server),
            ),
            "target version" => consent_for_origin(
                project,
                ProfilePurpose::Permission,
                2,
                loopback_origin(&server),
            ),
            _ => unreachable!(),
        };
        let (mut evaluator, server, _) = harness.into_evaluator(
            Some(consent),
            Some(gate.shared()),
            PermissionBudgetScope::Supervised,
        );
        ask(evaluator.evaluate(&evaluation_request(project, 301)));
        assert_eq!(server.count(), 0, "{name}");
        assert_eq!(gate.admits(), 0, "{name}");
    }

    let harness = Harness::new(Method::Llm);
    let project = harness.project;
    let server = Arc::clone(&harness.server);
    let gate = CountingGate::default();
    let scope = DisclosureScope::new(
        ProfilePurpose::Permission,
        BTreeSet::from([DisclosureDataKind::Text]),
        vec!["src/lib.rs".to_owned()],
        target(1),
    )
    .expect("text-only scope");
    let consent = DisclosureConsent::grant(
        ApprovalActor::Human,
        ids(project).consent,
        loopback_origin(&server),
        scope,
        now(),
    )
    .expect("consent");
    let (mut evaluator, server, _) = harness.into_evaluator(
        Some(consent),
        Some(gate.shared()),
        PermissionBudgetScope::Supervised,
    );
    ask(evaluator.evaluate(&evaluation_request(project, 302)));
    assert_eq!(server.count(), 0, "data-kind expansion");
    assert_eq!(gate.admits(), 0, "data-kind expansion");
}

#[test]
fn permission_evaluator_requires_a_budget_and_shares_the_ledger_cap() {
    let harness = Harness::new(Method::Llm);
    let project = harness.project;
    let consent = harness.consent.clone();
    let (mut evaluator, server, _) =
        harness.into_evaluator(Some(consent), None, PermissionBudgetScope::Supervised);
    assert_eq!(evaluator.availability(), EvaluatorAvailability::Unavailable);
    ask(evaluator.evaluate(&evaluation_request(project, 400)));
    assert_eq!(server.count(), 0);

    let harness = Harness::new(Method::Llm);
    let project = harness.project;
    let consent = harness.consent.clone();
    let gate = CountingGate::refusing();
    let (mut evaluator, server, _) = harness.into_evaluator(
        Some(consent),
        Some(gate.shared()),
        PermissionBudgetScope::Supervised,
    );
    ask(evaluator.evaluate(&evaluation_request(project, 401)));
    assert_eq!(server.count(), 0);
    assert_eq!(gate.admits(), 1);
    assert_eq!(gate.observations(), 0);

    let temp = tempfile::tempdir().expect("temp");
    let config = StoreConfig::new(temp.path().join("app")).expect("store config");
    let store = Arc::new(Mutex::new(Store::open(config).expect("store")));
    let clock = FakeClock::new();
    let mut ledger = BudgetLedger::open(
        SharedBudgetStore(Arc::clone(&store)),
        project,
        ids(project).supervision,
        BudgetPolicy::new(2, 30, None).expect("budget policy"),
        1,
        clock.clone(),
    )
    .expect("ledger");
    ledger.begin_active().expect("active budget");
    let budget_gate: TestBudgetGate = BudgetRequestGate::new(ledger, no_estimate);
    let shared = SharedModelRequestGate::new(Box::new(budget_gate));

    let harness = Harness::new(Method::Llm);
    let project = harness.project;
    let consent = harness.consent.clone();
    let (mut evaluator, server, _) = harness.into_evaluator(
        Some(consent),
        Some(shared),
        PermissionBudgetScope::Supervised,
    );
    let first = evaluation_request(project, 402);
    server.push(llm_envelope(&permission_body(&first, "allow")));
    assert_eq!(
        evaluator
            .evaluate(&first)
            .expect("first budgeted evaluation"),
        PermissionDecision::Allow
    );
    let records = store
        .lock()
        .expect("store")
        .model_requests_for_project(&project)
        .expect("model request records");
    assert_eq!(
        records.len(),
        1,
        "the permission request used the shared store"
    );
    assert_eq!(
        records[0].intent().purpose().as_str(),
        "permission_evaluation"
    );

    clock.advance_seconds(2);
    let second = evaluation_request(project, 403);
    server.push(llm_envelope(&permission_body(&second, "allow")));
    ask(evaluator.evaluate(&second));
    assert_eq!(server.count(), 1, "the exhausted cap must not send");
}

// ---------------------------------------------------------------------------
// Purpose boundary and transport failures
// ---------------------------------------------------------------------------

#[test]
fn permission_consent_revocation_during_evaluation_returns_ask() {
    let harness = Harness::new(Method::Llm);
    let project = harness.project;
    let server = Arc::clone(&harness.server);
    let gate = CountingGate::default();
    let handle = PermissionConsentHandle::new(harness.consent.clone());
    let config = PermissionEvaluatorConfig::new(
        harness.profile,
        None,
        harness.origin,
        target(1),
        harness.transport,
    )
    .with_consent_handle(handle.clone())
    .with_budget_gate(gate.shared());
    let evaluator = PermissionEvaluator::new(config).expect("evaluator");
    let request = evaluation_request(project, 450);
    server
        .push(llm_envelope(&permission_body(&request, "allow")).delay(Duration::from_millis(200)));
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let mut evaluator = evaluator;
        let _ = sender.send(evaluator.evaluate(&request));
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while server.count() == 0 {
        assert!(Instant::now() < deadline, "permission request was not sent");
        thread::sleep(Duration::from_millis(5));
    }
    handle.revoke(now()).expect("revoke consent");
    let result = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("result");
    worker.join().expect("evaluation thread");
    assert_eq!(
        result.expect("a revocation during evaluation is an ask"),
        PermissionDecision::Ask
    );
    assert_eq!(server.count(), 1);
}

#[test]
fn permission_questions_are_purpose_specific_and_never_include_a_whole_conversation() {
    let requested_canary = "REQUESTED-WORK-CANARY-77";
    let boundary_canary = "BOUNDARY-CANARY-88";
    let evidence_canary = "EVIDENCE-CANARY-99";
    let unrelated_canary = "UNRELATED-CONVERSATION-CANARY-11";

    for method in [Method::Llm, Method::Jev, Method::Decisions] {
        let harness = Harness::new(method);
        let project = harness.project;
        let consent = harness.consent.clone();
        let gate = CountingGate::default();
        let (mut evaluator, server, _) = harness.into_evaluator(
            Some(consent),
            Some(gate.shared()),
            PermissionBudgetScope::Supervised,
        );
        let request = EvaluationRequest::new(
            evaluation_request(project, 500).operation().clone(),
            requested_canary,
            boundary_canary,
            vec![evidence_canary.to_owned()],
        );
        let response = match method {
            Method::Llm => llm_envelope(&permission_body(&request, "allow")),
            Method::Jev => jev_response(&request, "allow", 0.99, 0.005, 0.005, 0.9),
            Method::Decisions => decisions_response(&request, "allow", 0.99, 0.005, 0.005, 0.9),
        };
        server.push(response);
        assert_eq!(
            evaluator.evaluate(&request).expect("purpose question"),
            PermissionDecision::Allow
        );
        let body = {
            let recorded = server.requests();
            String::from_utf8_lossy(&recorded[0].body).into_owned()
        };
        assert!(body.contains(requested_canary), "{method:?}");
        assert!(body.contains(boundary_canary), "{method:?}");
        assert!(body.contains(evidence_canary), "{method:?}");
        assert!(!body.contains(unrelated_canary), "{method:?}");
        assert!(!body.contains("conversation"), "{method:?}");
        assert!(!body.contains("repository"), "{method:?}");
        assert!(!body.contains("\"tools\""), "{method:?}");
        assert!(!body.contains("tool_choice"), "{method:?}");
        let operation_id = request.operation().operation_id().to_string();
        assert!(body.contains(&operation_id), "{method:?}");
    }
}

#[test]
fn permission_evaluator_never_reuses_a_completion_profile_or_verdict() {
    let harness = Harness::new(Method::Llm);
    let server = Arc::clone(&harness.server);
    let project = harness.project;
    let consent = harness.consent.clone();
    let completion =
        herness_supervision_tests::completion_entry(project, ConnectionStatus::Available, false);
    let config = PermissionEvaluatorConfig::new(
        completion,
        Some(consent),
        harness.origin,
        target(1),
        harness.transport,
    );
    assert!(PermissionEvaluator::new(config).is_err());
    assert_eq!(server.count(), 0);

    let harness = Harness::new(Method::Jev);
    let project = harness.project;
    let consent = harness.consent.clone();
    let gate = CountingGate::default();
    let (mut evaluator, server, _) = harness.into_evaluator(
        Some(consent),
        Some(gate.shared()),
        PermissionBudgetScope::Supervised,
    );
    let request = evaluation_request(project, 600);
    server.push(MockResponse::json(
        200,
        json!({
            "model": JEV_MODEL,
            "answers": {
                question_id(&request): {
                    "type": "choice",
                    "choice": "met",
                    "confidence": 0.99,
                    "probabilities": {"met": 0.99, "unmet": 0.005, "insufficient": 0.005},
                }
            }
        }),
    ));
    assert_eq!(
        evaluator
            .evaluate(&request)
            .expect("completion choice is not permission"),
        PermissionDecision::Ask
    );
}

#[test]
fn permission_evaluator_failures_are_sanitized_and_never_allow() {
    let harness = Harness::new(Method::Llm);
    let project = harness.project;
    let consent = harness.consent.clone();
    let gate = CountingGate::default();
    let (mut evaluator, server, _) = harness.into_evaluator(
        Some(consent),
        Some(gate.shared()),
        PermissionBudgetScope::Supervised,
    );

    for _ in 0..3 {
        server.push(MockResponse::json(
            500,
            json!({"error": {"message": CANARY}}),
        ));
    }
    let error = evaluator
        .evaluate(&evaluation_request(project, 700))
        .expect_err("a provider failure never authorizes execution");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(CANARY));
    assert!(!rendered.contains(API_KEY));
    assert_eq!(server.count(), 3);
    assert_eq!(gate.observations(), 1);

    let harness = Harness::new(Method::Llm);
    let project = harness.project;
    let gate = CountingGate::default();
    let control =
        TransportControl::new(CancelToken::new()).with_remaining(Duration::from_millis(50));
    let config = PermissionEvaluatorConfig::new(
        harness.profile,
        Some(harness.consent),
        harness.origin,
        target(1),
        harness.transport,
    )
    .with_budget_gate(gate.shared())
    .with_transport_control(control);
    let mut evaluator = PermissionEvaluator::new(config).expect("evaluator");
    let timed_out = evaluation_request(project, 701);
    let server = harness.server;
    server.push(
        llm_envelope(&permission_body(&timed_out, "allow")).delay(Duration::from_millis(200)),
    );
    let error = evaluator
        .evaluate(&timed_out)
        .expect_err("a timeout never authorizes execution");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(CANARY));
    assert!(!rendered.contains(API_KEY));
}

// ---------------------------------------------------------------------------
// Run-scoped budget
// ---------------------------------------------------------------------------

#[test]
fn run_scoped_permission_budget_allows_one_request_per_run_and_never_loops() {
    let harness = Harness::new(Method::Llm);
    let project = harness.project;
    let consent = harness.consent.clone();
    let gate = CountingGate::default();
    let (mut evaluator, server, _) = harness.into_evaluator(
        Some(consent),
        Some(gate.shared()),
        PermissionBudgetScope::RunScoped { max_requests: 1 },
    );
    let first = evaluation_request(project, 800);
    server.push(llm_envelope(&permission_body(&first, "allow")));
    assert_eq!(
        evaluator.evaluate(&first).expect("first request"),
        PermissionDecision::Allow
    );
    assert_eq!(server.count(), 1);

    let second = evaluation_request(project, 801);
    ask(evaluator.evaluate(&second));
    assert_eq!(
        server.count(),
        1,
        "the second request in the run is not sent"
    );
    assert_eq!(gate.admits(), 1);

    let original = evaluation_request(project, 802);
    let replacement = FrozenOperation::new(
        original.operation().operation_id(),
        RunId::from_parts(project, uuid::Uuid::from_u128(0x5eff)),
        original.operation().tool(),
        original.operation().arguments().clone(),
        original.operation().cwd().clone(),
        original.operation().policy_version(),
        original.operation().permission_mode(),
    )
    .expect("other run operation");
    let other_run = EvaluationRequest::new(
        replacement,
        original.requested_work(),
        original.permission_boundary(),
        original.evidence().to_vec(),
    );
    server.push(llm_envelope(&permission_body(&other_run, "allow")));
    assert_eq!(
        evaluator
            .evaluate(&other_run)
            .expect("a new run has its own request"),
        PermissionDecision::Allow
    );
    assert_eq!(server.count(), 2);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn loopback_origin(server: &MockServer) -> ProviderOrigin {
    ProviderOrigin::parse(server.url()).expect("loopback origin")
}
