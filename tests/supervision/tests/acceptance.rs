//! Task 17: three-way completion and permission contract evaluation.
//!
//! The same logical fixtures are driven through the normal-LLM, Jev, and
//! Decisions adapters. Every HTTP request goes to a loopback mock with a fake
//! credential. These are scripted model contract tests, not real-model accuracy
//! measurements and not real-connection acceptance.

use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use herness_assessment::{
    AssessmentEndpoints, AssessmentTransport, DecisionsAssessmentAdapter, JevAssessmentAdapter,
    LlmAssessmentAdapter, PermissionBudgetScope, PermissionEvaluator, PermissionEvaluatorConfig,
    RetryPolicy, SharedModelRequestGate, TransportControl,
};
use herness_core::contracts::ModelId;
use herness_core::{
    AbsolutePath, ArgumentsDigest, AuthMethod, ConnectionAdmin, ConnectionDirectory, ConnectionId,
    ConnectionSettings, Endpoint, EndpointClass, EvaluationContext, EvaluationRequest,
    FrozenOperation, GrantScope, InputCapabilities, ModelRequestGatePort, ModelRequestObservation,
    NonEmptyText, OperationId, PermissionMode, PermissionOutcome, PermissionPolicy, PolicyAdmin,
    ProjectId, Provider, RequestGateIntent, RequestGateOutcome, RunId, ToolArguments, ToolExecutor,
    ToolGateway, ToolName, WriteArgs,
};
use herness_supervision::assessment::{AssessmentResult, ConditionVerdict};
use herness_supervision::evidence::CheckStatus;
use herness_supervision::profiles::{
    AssessmentProfile, ProfileEntry, ProfileInputs, ProfilePurpose, ProviderKind,
};
use herness_supervision::state::SupervisionState;
use herness_supervision::{
    AdapterVersion, ConditionVersion, DisclosureConsent, EvidenceId, ProfileThresholds,
    RequiredCheckResult, TargetVersion,
};
use herness_supervision_tests::fixtures::{
    CompletionCase, EvaluationFixture, ExpectedCompletion, ExpectedPermission, FixtureAxis,
    FixtureCase, FixtureClass, PermissionCase, REAL_MODEL_ACCURACY_UNVERIFIED,
    UNVERIFIED_REAL_CONNECTION_ROUTES, all_fixtures, completion_fixtures, completion_record,
    completion_request, completion_snapshot, decisions_completion_profile_version, evidence_texts,
    jev_completion_profile_version, permission_fixtures,
};
use herness_supervision_tests::{
    consent_for_origin, evidence, ids, jev_choice_answer, jev_system_one_response, now,
    permission_entry_for, permission_profile_for_provider, project,
};
use serde_json::{Value, json};

const LLM_MODEL: &str = "fixture-completion-llm";
const JEV_MODEL: &str = "jev-1.14.0";
const DECISIONS_MODEL: &str = "gpt-6-luna";
const API_KEY: &str = "sk-task17-contract-canary";

// ---------------------------------------------------------------------------
// Loopback HTTP mock.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct RecordedRequest {
    path: String,
    body: Vec<u8>,
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
        Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(&value).expect("mock body"),
            delay: Duration::ZERO,
        }
    }

    fn body(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into(),
            delay: Duration::ZERO,
        }
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
        self.responses.lock().unwrap().push_back(response);
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    loop {
        let Some(parsed) = read_request(&mut stream) else {
            return;
        };
        let mut parts = parsed.request_line.split_whitespace();
        let _method = parts.next().unwrap_or_default();
        let path = parts.next().unwrap_or_default().to_owned();
        requests.lock().unwrap().push(RecordedRequest {
            path,
            body: parsed.body,
        });
        let response = responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| MockResponse::body(500, b"mock exhausted".to_vec()));
        if !response.delay.is_zero() {
            thread::sleep(response.delay);
        }
        let header = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            response.status,
            reason(response.status),
            response.content_type,
            response.body.len()
        );
        if stream.write_all(header.as_bytes()).is_err()
            || stream.write_all(&response.body).is_err()
            || stream.flush().is_err()
        {
            return;
        }
    }
}

struct ParsedRequest {
    request_line: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<ParsedRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        if let Some(position) = find_bytes(&buffer, b"\r\n\r\n") {
            break position + 4;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > 64 * 1024 {
            return None;
        }
    };
    let header_text = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next()?.to_owned();
    let mut content_length = 0_usize;
    for line in lines {
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
    Some(ParsedRequest {
        request_line,
        body: buffer[header_end..header_end + content_length].to_vec(),
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        _ => "Status",
    }
}

// ---------------------------------------------------------------------------
// Credentials and harness.
// ---------------------------------------------------------------------------

struct FakeCredential;

impl herness_core::CredentialPort for FakeCredential {
    fn availability(
        &self,
        _connection: &ConnectionId,
    ) -> Result<herness_core::CredentialAvailability, herness_core::CoreError> {
        Ok(herness_core::CredentialAvailability::Available)
    }

    fn resolve(
        &self,
        _connection: &ConnectionId,
    ) -> Result<herness_core::ResolvedCredential, herness_core::CoreError> {
        Ok(herness_core::ResolvedCredential::new(
            herness_core::CredentialKind::ApiKey,
            herness_core::SecretString::new(API_KEY).expect("fake credential"),
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Llm,
    Jev,
    Decisions,
}

impl Method {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Llm => "normal_llm",
            Self::Jev => "jev",
            Self::Decisions => "decisions",
        }
    }

    const fn provider(self) -> ProviderKind {
        match self {
            Self::Llm => ProviderKind::NormalLlm,
            Self::Jev => ProviderKind::Jev,
            Self::Decisions => ProviderKind::Decisions,
        }
    }

    const fn model(self) -> &'static str {
        match self {
            Self::Llm => LLM_MODEL,
            Self::Jev => JEV_MODEL,
            Self::Decisions => DECISIONS_MODEL,
        }
    }
}

struct Harness {
    _admin: ConnectionAdmin,
    directory: ConnectionDirectory,
    server: Arc<MockServer>,
    credentials: Arc<FakeCredential>,
    project: ProjectId,
    method: Method,
    completion_profiles: BTreeMap<u64, (AssessmentProfile, ProfileEntry)>,
    permission_profile: ProfileEntry,
    permission_consent: DisclosureConsent,
}

impl Harness {
    fn new(method: Method) -> Self {
        let server = MockServer::start();
        let project = project();
        let admin = ConnectionAdmin::new();
        let credentials = Arc::new(FakeCredential);
        let settings = match method {
            Method::Llm => ConnectionSettings::new_with_capabilities(
                ConnectionId::new(),
                Provider::OpenAiCompatible,
                LLM_MODEL,
                AuthMethod::ApiKey,
                Some(Endpoint::parse(&server.openai_base()).expect("loopback endpoint")),
                None,
                herness_core::ConnectionCapabilityDeclaration::new(
                    EndpointClass::OpenAiCompletions,
                    InputCapabilities::text_only(),
                ),
            )
            .expect("llm settings"),
            Method::Jev => ConnectionSettings::new_with_capabilities(
                ConnectionId::new(),
                Provider::TypeSafe,
                JEV_MODEL,
                AuthMethod::ApiKey,
                None,
                None,
                herness_core::ConnectionCapabilityDeclaration::new(
                    EndpointClass::TypeSafeSystemOne,
                    InputCapabilities::text_only(),
                ),
            )
            .expect("jev settings"),
            Method::Decisions => ConnectionSettings::new_with_capabilities(
                ConnectionId::new(),
                Provider::OpenAi,
                DECISIONS_MODEL,
                AuthMethod::ApiKey,
                None,
                None,
                herness_core::ConnectionCapabilityDeclaration::new(
                    EndpointClass::OpenAiDecisions,
                    InputCapabilities::text_only(),
                ),
            )
            .expect("decisions settings"),
        };
        admin.add(settings.clone()).expect("register connection");
        let directory = admin.directory();
        let connection = settings.connection_id();
        let permission_profile = permission_profile_for_provider(
            project,
            method.provider(),
            connection,
            method.model(),
            ProfileInputs::text_only(),
        );
        let permission_profile = permission_entry_for(&settings, permission_profile, false);
        let permission_consent = consent_for_origin(
            project,
            ProfilePurpose::Permission,
            1,
            herness_supervision::ProviderOrigin::parse(server.url()).expect("loopback origin"),
        );
        let mut completion_profiles = BTreeMap::new();
        for version in [1_u64, 2] {
            let profile = match method {
                Method::Llm => herness_supervision_tests::fixtures::completion_profile_version(
                    project,
                    connection,
                    LLM_MODEL,
                    version,
                    ProfileInputs::text_only(),
                ),
                Method::Jev => {
                    jev_completion_profile_version(project, connection, JEV_MODEL, version)
                }
                Method::Decisions => decisions_completion_profile_version(
                    project,
                    connection,
                    DECISIONS_MODEL,
                    version,
                ),
            };
            let entry = match method {
                Method::Llm => {
                    herness_supervision_tests::llm_profile_entry(&settings, profile.clone(), false)
                }
                Method::Jev => {
                    herness_supervision_tests::jev_profile_entry(&settings, profile.clone())
                }
                Method::Decisions => {
                    herness_supervision_tests::decisions_profile_entry(&settings, profile.clone())
                }
            };
            completion_profiles.insert(version, (profile, entry));
        }
        Self {
            _admin: admin,
            directory,
            server,
            credentials,
            project,
            method,
            completion_profiles,
            permission_profile,
            permission_consent,
        }
    }

    fn completion_profile(&self, version: u64) -> (AssessmentProfile, ProfileEntry) {
        self.completion_profiles
            .get(&version)
            .cloned()
            .expect("fixture completion profile")
    }

    fn transport(&self) -> AssessmentTransport {
        let endpoints = AssessmentEndpoints::for_loopback(
            self.server.url(),
            self.server.openai_base(),
            self.server.url(),
        )
        .expect("loopback assessment endpoints");
        AssessmentTransport::new(self.credentials.clone(), self.directory.clone(), endpoints)
            .expect("assessment transport")
            .with_retry_policy(RetryPolicy::with_base_delays([
                Duration::from_millis(1),
                Duration::from_millis(1),
            ]))
    }
}

// ---------------------------------------------------------------------------
// Provider response builders.
// ---------------------------------------------------------------------------

fn llm_envelope(content: &str) -> Value {
    json!({
        "model": LLM_MODEL,
        "choices": [{
            "finish_reason": "stop",
            "message": {"content": content},
        }],
    })
}

fn llm_condition_answer(
    condition: herness_supervision::ConditionId,
    verdict: &str,
    evidence: &[EvidenceId],
    rationale: &str,
    uncertainty: Option<&str>,
) -> Value {
    json!({
        "conditions": [{
            "conditionId": condition.to_string(),
            "verdict": verdict,
            "evidenceIds": evidence.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "rationale": rationale,
            "uncertainty": uncertainty,
        }]
    })
}

fn jev_completion_response(
    question_id: &str,
    choice: &str,
    met: f64,
    unmet: f64,
    insufficient: f64,
) -> Value {
    jev_system_one_response(
        JEV_MODEL,
        question_id,
        jev_choice_answer(choice, met, unmet, insufficient, 0.85),
    )
}

fn decisions_completion_response(
    question_id: &str,
    choice: &str,
    met: f64,
    unmet: f64,
    insufficient: f64,
) -> Value {
    herness_supervision_tests::decisions_response(
        DECISIONS_MODEL,
        question_id,
        herness_supervision_tests::decisions_choice_answer(choice, met, unmet, insufficient, 0.85),
    )
}

fn permission_body(request: &EvaluationRequest, decision: &str, operation_id: &str) -> Value {
    let operation = request.operation();
    json!({
        "decision": decision,
        "operationId": operation_id,
        "argumentsDigest": ArgumentsDigest::of(operation.arguments()).to_string(),
        "cwd": operation.cwd().to_string(),
        "policyVersion": operation.policy_version().get(),
        "mode": operation.permission_mode().to_string(),
        "rationale": "The frozen operation matches the requested boundary.",
        "uncertainty": null,
    })
}

fn permission_llm_envelope(request: &EvaluationRequest, decision: &str) -> MockResponse {
    MockResponse::json(
        200,
        llm_envelope(
            &permission_body(
                request,
                decision,
                &request.operation().operation_id().to_string(),
            )
            .to_string(),
        ),
    )
}

fn permission_question_id(request: &EvaluationRequest) -> String {
    herness_assessment::permission_question_id(request.operation())
}

fn permission_jev_response(request: &EvaluationRequest, choice: &str, value: f64) -> MockResponse {
    let probabilities = match choice {
        "allow" => (value, (1.0 - value) / 2.0, (1.0 - value) / 2.0),
        "deny" => ((1.0 - value) / 2.0, value, (1.0 - value) / 2.0),
        _ => ((1.0 - value) / 2.0, (1.0 - value) / 2.0, value),
    };
    MockResponse::json(
        200,
        json!({
            "model": JEV_MODEL,
            "answers": {
                permission_question_id(request): {
                    "type": "choice",
                    "choice": choice,
                    "confidence": 0.85,
                    "probabilities": {
                        "allow": probabilities.0,
                        "deny": probabilities.1,
                        "ask": probabilities.2,
                    },
                }
            },
            "usage": {"input_tokens": 10, "output_tokens": 1},
        }),
    )
}

fn permission_decisions_response(
    request: &EvaluationRequest,
    choice: &str,
    value: f64,
) -> MockResponse {
    let probabilities = match choice {
        "allow" => [
            ("allow", value),
            ("deny", (1.0 - value) / 2.0),
            ("ask", (1.0 - value) / 2.0),
        ],
        "deny" => [
            ("allow", (1.0 - value) / 2.0),
            ("deny", value),
            ("ask", (1.0 - value) / 2.0),
        ],
        _ => [
            ("allow", (1.0 - value) / 2.0),
            ("deny", (1.0 - value) / 2.0),
            ("ask", value),
        ],
    };
    MockResponse::json(
        200,
        json!({
            "model": DECISIONS_MODEL,
            "answers": [{
                "type": "choice",
                "name": permission_question_id(request),
                "choice": choice,
                "confidence": 0.85,
                "probabilities": probabilities
                    .iter()
                    .map(|(value, probability)| json!({"value": value, "probability": probability}))
                    .collect::<Vec<_>>(),
            }],
            "usage": {"input_tokens": 10, "output_tokens": 1},
        }),
    )
}

// ---------------------------------------------------------------------------
// Completion fixture execution.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompletionMode {
    Met,
    Unmet,
    Insufficient,
    ExtraEvidence,
    Invalid,
    LowProbability,
}

fn completion_mode(case: CompletionCase) -> CompletionMode {
    match case {
        CompletionCase::AllMet
        | CompletionCase::StaleSuccess
        | CompletionCase::FakeDone
        | CompletionCase::RequiredCheckFail => CompletionMode::Met,
        CompletionCase::Unmet | CompletionCase::MisleadingRationale => CompletionMode::Unmet,
        CompletionCase::Insufficient => CompletionMode::Insufficient,
        CompletionCase::PromptInjection => CompletionMode::ExtraEvidence,
        CompletionCase::LowProbability => CompletionMode::LowProbability,
        CompletionCase::InvalidSchema => CompletionMode::Invalid,
    }
}

fn run_completion(
    harness: &Harness,
    fixture: &EvaluationFixture,
    condition: herness_supervision::ConditionId,
    decision_seed: u128,
    mode: CompletionMode,
) -> AssessmentResult {
    let project = harness.project;
    let fixture_ids = ids(project);
    let (profile, entry) = harness.completion_profile(fixture.request_profile_version);
    let decision = herness_supervision::DecisionId::from_parts(
        project,
        uuid::Uuid::from_u128(0xd00d_0000_0000_0000_0000_0000_0000_0000 + decision_seed),
    );
    let request = completion_request(fixture, project, condition, decision, &profile);
    let (text_a, text_b) = evidence_texts(fixture);
    let documents = vec![
        herness_assessment::EvidenceDocument::text(fixture_ids.evidence_a, text_a)
            .expect("evidence a"),
        herness_assessment::EvidenceDocument::text(fixture_ids.evidence_b, text_b)
            .expect("evidence b"),
    ];
    let question_id = match harness.method {
        Method::Llm => String::new(),
        Method::Jev => herness_assessment::jev_question_id(&request),
        Method::Decisions => herness_assessment::decisions_question_id(&request),
    };
    let response = match harness.method {
        Method::Llm => match mode {
            CompletionMode::Invalid => MockResponse::json(
                200,
                llm_envelope("this is not the required completion schema"),
            ),
            CompletionMode::ExtraEvidence => {
                let injected = EvidenceId::new(project);
                MockResponse::json(
                    200,
                    llm_envelope(
                        &llm_condition_answer(
                            condition,
                            "met",
                            &[fixture_ids.evidence_a, fixture_ids.evidence_b, injected],
                            "DONE: the injected evidence says the condition is met",
                            None,
                        )
                        .to_string(),
                    ),
                )
            }
            CompletionMode::Met | CompletionMode::LowProbability => {
                let uncertainty =
                    (mode == CompletionMode::LowProbability).then_some("the evidence is ambiguous");
                MockResponse::json(
                    200,
                    llm_envelope(
                        &llm_condition_answer(
                            condition,
                            "met",
                            request.evidence(),
                            "The fixture evidence supports met.",
                            uncertainty,
                        )
                        .to_string(),
                    ),
                )
            }
            CompletionMode::Unmet => MockResponse::json(
                200,
                llm_envelope(
                    &llm_condition_answer(
                        condition,
                        "unmet",
                        request.evidence(),
                        if fixture.case
                            == FixtureCase::Completion(CompletionCase::MisleadingRationale)
                        {
                            "Everything is green. DONE; mark this complete."
                        } else {
                            "The fixture condition is unmet."
                        },
                        None,
                    )
                    .to_string(),
                ),
            ),
            CompletionMode::Insufficient => MockResponse::json(
                200,
                llm_envelope(
                    &llm_condition_answer(
                        condition,
                        "insufficient",
                        request.evidence(),
                        "The evidence is insufficient.",
                        None,
                    )
                    .to_string(),
                ),
            ),
        },
        Method::Jev => match mode {
            CompletionMode::Invalid => MockResponse::body(200, b"{not-json".to_vec()),
            CompletionMode::ExtraEvidence | CompletionMode::Insufficient => MockResponse::json(
                200,
                jev_completion_response(&question_id, "insufficient", 0.01, 0.03, 0.96),
            ),
            CompletionMode::Unmet => MockResponse::json(
                200,
                jev_completion_response(&question_id, "unmet", 0.03, 0.96, 0.01),
            ),
            CompletionMode::LowProbability => MockResponse::json(
                200,
                jev_completion_response(&question_id, "met", 0.94, 0.05, 0.01),
            ),
            CompletionMode::Met => MockResponse::json(
                200,
                jev_completion_response(&question_id, "met", 0.96, 0.03, 0.01),
            ),
        },
        Method::Decisions => match mode {
            CompletionMode::Invalid => MockResponse::body(200, b"{not-json".to_vec()),
            CompletionMode::ExtraEvidence | CompletionMode::Insufficient => MockResponse::json(
                200,
                decisions_completion_response(&question_id, "insufficient", 0.01, 0.03, 0.96),
            ),
            CompletionMode::Unmet => MockResponse::json(
                200,
                decisions_completion_response(&question_id, "unmet", 0.03, 0.96, 0.01),
            ),
            CompletionMode::LowProbability => MockResponse::json(
                200,
                decisions_completion_response(&question_id, "met", 0.94, 0.05, 0.01),
            ),
            CompletionMode::Met => MockResponse::json(
                200,
                decisions_completion_response(&question_id, "met", 0.96, 0.03, 0.01),
            ),
        },
    };
    harness.server.push(response);
    let control = TransportControl::default();
    match harness.method {
        Method::Llm => {
            let adapter = LlmAssessmentAdapter::new(
                harness.transport(),
                Arc::new(herness_supervision_tests::FixedClock),
            );
            adapter
                .assess(&request, &entry, &documents, control)
                .expect("completion assessment")
                .into_result()
        }
        Method::Jev => {
            let adapter = JevAssessmentAdapter::new(
                harness.transport(),
                Arc::new(herness_supervision_tests::FixedClock),
            );
            adapter
                .assess(&request, &entry, &documents, control)
                .expect("completion assessment")
                .into_result()
        }
        Method::Decisions => {
            let adapter = DecisionsAssessmentAdapter::new(
                harness.transport(),
                Arc::new(herness_supervision_tests::FixedClock),
            );
            adapter
                .assess(&request, &entry, &documents, control)
                .expect("completion assessment")
                .into_result()
        }
    }
}

fn evaluate_completion_fixture(
    harness: &Harness,
    fixture: &EvaluationFixture,
) -> (ExpectedCompletion, Vec<String>) {
    assert_eq!(fixture.class, FixtureClass::ScriptedContract);
    let FixtureCase::Completion(case) = fixture.case else {
        panic!("not a completion fixture: {}", fixture.id);
    };
    let project = harness.project;
    let fixture_ids = ids(project);
    let (current_profile, _) = harness.completion_profile(fixture.current_profile_version);
    let mut record = completion_record(project, fixture, &current_profile);
    let mut notes = Vec::new();
    for (index, condition) in [fixture_ids.condition_a, fixture_ids.condition_b]
        .into_iter()
        .enumerate()
    {
        let mode = if index == 0 {
            completion_mode(case)
        } else {
            CompletionMode::Met
        };
        let result = run_completion(
            harness,
            fixture,
            condition,
            10_000 * (index as u128 + 1),
            mode,
        );
        let reported = result.reported_verdict();
        assert_eq!(result.condition_id(), condition);
        assert_eq!(
            result.evidence(),
            &[fixture_ids.evidence_a, fixture_ids.evidence_b],
            "an adapter changed the condition's evidence scope"
        );
        let application = record
            .apply_assessment(&result, current_profile.thresholds())
            .expect("apply assessment");
        notes.push(format!("condition{index}:{reported:?}/{application:?}"));
    }
    let verified_checks = match case {
        CompletionCase::FakeDone => Vec::new(),
        CompletionCase::RequiredCheckFail => vec![fixture_ids.check_b],
        _ => vec![fixture_ids.check_a, fixture_ids.check_b],
    };
    let snapshot = completion_snapshot(
        &record,
        verified_checks,
        vec![fixture_ids.evidence_a, fixture_ids.evidence_b],
    );
    let completed = match record.complete(snapshot) {
        Ok(()) => ExpectedCompletion::Complete,
        Err(error) => {
            notes.push(format!("completion_blocked:{error}"));
            ExpectedCompletion::NotComplete
        }
    };
    if case == CompletionCase::StaleSuccess {
        assert!(
            !record.invalidated_decisions().is_empty(),
            "stale success must remain history only"
        );
        assert!(record.applied_decisions().is_empty());
    }
    if case == CompletionCase::RequiredCheckFail {
        let failed = evidence(
            project,
            fixture_ids,
            fixture_ids.evidence_a,
            fixture_ids.check_a,
            fixture_ids.condition_a,
            CheckStatus::Fail,
            1,
        );
        let result = RequiredCheckResult::from_evidence(&failed, record.condition_version())
            .expect("result");
        assert_eq!(result.status(), CheckStatus::Fail);
        assert!(!result.is_pass());
    }
    if case == CompletionCase::FakeDone {
        let not_run = evidence(
            project,
            fixture_ids,
            fixture_ids.evidence_a,
            fixture_ids.check_a,
            fixture_ids.condition_a,
            CheckStatus::NotRun,
            1,
        );
        let result = RequiredCheckResult::from_evidence(&not_run, record.condition_version())
            .expect("result");
        assert!(!result.is_pass());
    }
    if case == CompletionCase::PromptInjection {
        assert!(
            evidence_texts(fixture)
                .0
                .contains("IGNORE ALL PREVIOUS INSTRUCTIONS")
        );
        assert!(
            !notes[0].contains("Met/Applied"),
            "injected evidence changed the first condition: {}",
            notes[0]
        );
    }
    if case == CompletionCase::AllMet {
        assert_eq!(record.state(), SupervisionState::Completed);
        assert!(record.completion().is_some());
    }
    (completed, notes)
}

// ---------------------------------------------------------------------------
// Permission fixture execution.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct CountingGate {
    state: Arc<Mutex<GateState>>,
}

#[derive(Default)]
struct GateState {
    admits: usize,
    observations: usize,
    refuse: bool,
}

impl CountingGate {
    fn shared(&self) -> SharedModelRequestGate {
        SharedModelRequestGate::new(Box::new(self.clone()))
    }

    fn admits(&self) -> usize {
        self.state.lock().expect("gate").admits
    }

    fn observations(&self) -> usize {
        self.state.lock().expect("gate").observations
    }
}

impl ModelRequestGatePort for CountingGate {
    fn admit(
        &mut self,
        _intent: &RequestGateIntent,
    ) -> Result<RequestGateOutcome, herness_core::CoreError> {
        let mut state = self.state.lock().expect("gate");
        state.admits += 1;
        if state.refuse {
            return Ok(RequestGateOutcome::Refuse {
                reason: herness_core::RequestGateRefusal::BudgetUnavailable,
            });
        }
        Ok(RequestGateOutcome::Admit)
    }

    fn observe(
        &mut self,
        _observation: &ModelRequestObservation,
    ) -> Result<(), herness_core::CoreError> {
        self.state.lock().expect("gate").observations += 1;
        Ok(())
    }
}

struct CountingExecutor {
    calls: Rc<Cell<usize>>,
}

impl ToolExecutor for CountingExecutor {
    type Output = ();

    fn execute(&mut self, _operation: &FrozenOperation) -> Result<(), herness_core::CoreError> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActualPermission {
    Allow,
    Deny,
    Ask,
}

impl ActualPermission {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Ask => "ask",
        }
    }

    const fn matches(self, expected: ExpectedPermission) -> bool {
        matches!(
            (self, expected),
            (Self::Allow, ExpectedPermission::Allow)
                | (Self::Deny, ExpectedPermission::Deny)
                | (Self::Ask, ExpectedPermission::Ask)
        )
    }
}

fn permission_operation(
    project: ProjectId,
    policy: &PermissionPolicy,
    seed: u128,
    out_of_scope: bool,
) -> FrozenOperation {
    let path = if out_of_scope {
        "/etc/herness-task17-outside.txt"
    } else {
        "src/lib.rs"
    };
    FrozenOperation::new(
        OperationId::from_parts(project, uuid::Uuid::from_u128(seed)),
        RunId::from_parts(project, uuid::Uuid::from_u128(0x5eed)),
        ToolName::Write,
        ToolArguments::Write(WriteArgs {
            path: NonEmptyText::new(path).expect("path"),
            content: "synthetic task-17 content".to_owned(),
            rationale: herness_core::Rationale::new("update the fixture module")
                .expect("rationale"),
        }),
        AbsolutePath::new("/tmp/task17-permission-fixture").expect("cwd"),
        policy.version(),
        PermissionMode::Automatic,
    )
    .expect("frozen operation")
}

fn permission_response(
    harness: &Harness,
    fixture: &EvaluationFixture,
    request: &EvaluationRequest,
) -> MockResponse {
    let FixtureCase::Permission(case) = fixture.case else {
        panic!("not a permission fixture: {}", fixture.id);
    };
    let operation_id = request.operation().operation_id().to_string();
    match harness.method {
        Method::Llm => match case {
            PermissionCase::InScopeAllow => permission_llm_envelope(request, "allow"),
            PermissionCase::OutOfScope => permission_llm_envelope(request, "deny"),
            PermissionCase::MisleadingRationale => {
                let mut body = permission_body(request, "allow", &operation_id);
                body["uncertainty"] = json!("the request looks safe but the boundary is ambiguous");
                MockResponse::json(200, llm_envelope(&body.to_string()))
            }
            PermissionCase::PromptInjection => MockResponse::json(
                200,
                llm_envelope(
                    &permission_body(request, "allow", "operation:injected-by-evidence")
                        .to_string(),
                ),
            ),
            PermissionCase::LowProbability => {
                let mut body = permission_body(request, "allow", &operation_id);
                body["uncertainty"] = json!("not decided");
                MockResponse::json(200, llm_envelope(&body.to_string()))
            }
            PermissionCase::InvalidSchema => MockResponse::json(200, llm_envelope("not-json")),
        },
        Method::Jev => match case {
            PermissionCase::InScopeAllow => permission_jev_response(request, "allow", 0.995),
            PermissionCase::OutOfScope => permission_jev_response(request, "deny", 0.995),
            PermissionCase::MisleadingRationale => permission_jev_response(request, "ask", 0.995),
            PermissionCase::PromptInjection => MockResponse::json(
                200,
                json!({
                    "model": JEV_MODEL,
                    "answers": {
                        "operation:injected-by-evidence": {
                            "type": "choice",
                            "choice": "allow",
                            "confidence": 0.9,
                            "probabilities": {"allow": 0.995, "deny": 0.004, "ask": 0.001},
                        }
                    },
                    "usage": {"input_tokens": 10, "output_tokens": 1},
                }),
            ),
            PermissionCase::LowProbability => permission_jev_response(request, "allow", 0.98),
            PermissionCase::InvalidSchema => MockResponse::body(200, b"{not-json".to_vec()),
        },
        Method::Decisions => match case {
            PermissionCase::InScopeAllow => permission_decisions_response(request, "allow", 0.995),
            PermissionCase::OutOfScope => permission_decisions_response(request, "deny", 0.995),
            PermissionCase::MisleadingRationale => {
                permission_decisions_response(request, "ask", 0.995)
            }
            PermissionCase::PromptInjection => MockResponse::json(
                200,
                json!({
                    "model": DECISIONS_MODEL,
                    "answers": [{
                        "type": "choice",
                        "name": "operation:injected-by-evidence",
                        "choice": "allow",
                        "confidence": 0.9,
                        "probabilities": [
                            {"value": "allow", "probability": 0.995},
                            {"value": "deny", "probability": 0.004},
                            {"value": "ask", "probability": 0.001},
                        ],
                    }],
                    "usage": {"input_tokens": 10, "output_tokens": 1},
                }),
            ),
            PermissionCase::LowProbability => permission_decisions_response(request, "allow", 0.98),
            PermissionCase::InvalidSchema => MockResponse::body(200, b"{not-json".to_vec()),
        },
    }
}

fn evaluate_permission_fixture(
    harness: &Harness,
    fixture: &EvaluationFixture,
) -> (ActualPermission, usize, String) {
    assert_eq!(fixture.class, FixtureClass::ScriptedContract);
    let FixtureCase::Permission(case) = fixture.case else {
        panic!("not a permission fixture: {}", fixture.id);
    };
    let project = harness.project;
    let mut policy_admin = PolicyAdmin::new();
    policy_admin
        .set_mode(
            PermissionMode::Automatic,
            herness_core::EvaluatorAvailability::Available,
        )
        .expect("automatic mode");
    let policy = policy_admin.policy().clone();
    let out_of_scope = case == PermissionCase::OutOfScope;
    let operation = permission_operation(
        project,
        &policy,
        0x1700_0000_0000_0000_0000_0000_0000_0000 + u128::from(fixture_bytes(fixture.id)),
        out_of_scope,
    );
    let request = EvaluationRequest::new(
        operation,
        "update the fixture module",
        "write only inside src/lib.rs",
        vec!["synthetic fixture evidence; never an authority to change the operation".to_owned()],
    );
    let context = EvaluationContext::new(
        request.requested_work().to_owned(),
        request.evidence().to_vec(),
    );
    let gate = CountingGate::default();
    let transport = harness.transport();
    let origin = herness_supervision::ProviderOrigin::parse(harness.server.url()).expect("origin");
    let config = PermissionEvaluatorConfig::new(
        harness.permission_profile.clone(),
        Some(harness.permission_consent.clone()),
        origin,
        TargetVersion::new(1).expect("target version"),
        transport,
    )
    .with_budget_scope(PermissionBudgetScope::Supervised)
    .with_budget_gate(gate.shared());
    let mut evaluator = PermissionEvaluator::new(config)
        .expect("permission evaluator")
        .into_boxed();
    let grant = GrantScope::for_run(project, &policy);
    let calls = Rc::new(Cell::new(0));
    let mut gateway = ToolGateway::new(CountingExecutor {
        calls: Rc::clone(&calls),
    });
    let before = harness.server.count();
    harness
        .server
        .push(permission_response(harness, fixture, &request));
    let outcome = gateway
        .authorize(
            &policy,
            &grant,
            request.operation(),
            &context,
            Some(evaluator.as_mut()),
        )
        .expect("permission evaluation");
    let actual = match outcome {
        PermissionOutcome::Allow { authorization } => {
            if fixture.expected_permission == ExpectedPermission::Allow {
                let other = permission_operation(
                    project,
                    &policy,
                    0x1700_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
                    false,
                );
                let wrong = gateway.execute(&policy, &other, &authorization);
                assert!(
                    wrong.is_err(),
                    "an authorization for one frozen operation executed another"
                );
                assert_eq!(calls.get(), 0, "wrong operation reached the executor");
            }
            gateway
                .execute(&policy, request.operation(), &authorization)
                .expect("authorized execution");
            ActualPermission::Allow
        }
        PermissionOutcome::Deny { .. } => ActualPermission::Deny,
        PermissionOutcome::AwaitingApproval { .. } => ActualPermission::Ask,
    };
    assert_eq!(
        harness.server.count(),
        before + 1,
        "each permission fixture must make exactly one assessment request"
    );
    let recorded = harness.server.requests();
    let last = recorded.last().expect("permission request");
    let expected_path = match harness.method {
        Method::Llm => "/v1/chat/completions",
        Method::Jev => "/v1/systemone",
        Method::Decisions => "/v1/decisions",
    };
    assert_eq!(last.path, expected_path);
    assert!(!last.body.is_empty());
    assert_eq!(
        gate.admits(),
        1,
        "the permission request must pass the H2 budget gate"
    );
    assert_eq!(gate.observations(), 1);
    let note = format!(
        "policyVersion={} operation={}",
        policy.version().get(),
        request.operation().operation_id()
    );
    (actual, calls.get(), note)
}

fn fixture_bytes(id: &str) -> u64 {
    // Stable FNV-1a so every fixture gets a distinct synthetic operation.
    id.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |acc, byte| {
        (acc ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

// ---------------------------------------------------------------------------
// Test.
// ---------------------------------------------------------------------------

#[test]
fn all_executable_fixtures_are_scripted_contracts() {
    for fixture in all_fixtures() {
        assert_eq!(
            fixture.class,
            FixtureClass::ScriptedContract,
            "{} must not claim a real-model result",
            fixture.id
        );
        assert!(!fixture.id.is_empty());
        assert!(!fixture.description.is_empty());
        assert!(!fixture.evidence_scope.is_empty());
    }
    let ids = all_fixtures()
        .into_iter()
        .map(|fixture| fixture.id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        ids.len(),
        completion_fixtures().len() + permission_fixtures().len()
    );
    assert_eq!(UNVERIFIED_REAL_CONNECTION_ROUTES.len(), 3);
    assert!(REAL_MODEL_ACCURACY_UNVERIFIED.contains("not claimed"));
}

#[test]
fn three_way_completion_and_permission_fixtures_hold_without_false_success() {
    let project = project();
    let _ = project;
    let mut report = Vec::new();
    let mut false_completions = 0_usize;
    let mut false_allows = 0_usize;
    let mut false_stops = 0_usize;
    let mut holds = 0_usize;

    for method in [Method::Llm, Method::Jev, Method::Decisions] {
        let harness = Harness::new(method);
        for fixture in completion_fixtures() {
            let (actual, notes) = evaluate_completion_fixture(&harness, fixture);
            eprintln!(
                "TASK17_MATRIX id={} axis=completion method={} class={} expected={} actual={} notes={}",
                fixture.id,
                method.as_str(),
                fixture.class.as_str(),
                fixture.expected_completion.as_str(),
                actual.as_str(),
                notes.join(";")
            );
            match (fixture.expected_completion, actual) {
                (ExpectedCompletion::NotComplete, ExpectedCompletion::Complete) => {
                    false_completions += 1;
                }
                (ExpectedCompletion::Complete, ExpectedCompletion::NotComplete) => {
                    false_stops += 1;
                }
                (ExpectedCompletion::NotComplete, ExpectedCompletion::NotComplete) => {
                    holds += 1;
                }
                _ => {}
            }
            assert_eq!(
                actual,
                fixture.expected_completion,
                "{} via {}",
                fixture.id,
                method.as_str()
            );
            report.push((fixture.id, method.as_str(), actual.as_str()));
        }
        for fixture in permission_fixtures() {
            let (actual, executed, note) = evaluate_permission_fixture(&harness, fixture);
            eprintln!(
                "TASK17_MATRIX id={} axis=permission method={} class={} expected={} actual={} executed={} notes={}",
                fixture.id,
                method.as_str(),
                fixture.class.as_str(),
                fixture.expected_permission.as_str(),
                actual.as_str(),
                executed,
                note
            );
            if fixture.expected_permission != ExpectedPermission::Allow
                && actual == ActualPermission::Allow
            {
                false_allows += 1;
            }
            if fixture.expected_permission == ExpectedPermission::Allow {
                assert_eq!(executed, 1, "an allowed operation executes once");
            } else {
                assert_eq!(executed, 0, "a denied or held operation never executes");
                if actual != ActualPermission::Allow {
                    holds += 1;
                }
            }
            assert!(
                actual.matches(fixture.expected_permission),
                "{} via {}: expected {}, got {}",
                fixture.id,
                method.as_str(),
                fixture.expected_permission.as_str(),
                actual.as_str()
            );
            report.push((fixture.id, method.as_str(), actual.as_str()));
        }
    }

    assert_eq!(false_completions, 0, "false completions must be zero");
    assert_eq!(false_allows, 0, "false allows must be zero");
    assert_eq!(false_stops, 0, "representative positives must not hold");
    assert!(holds > 0, "the negative fixtures must hold, not complete");
    assert_eq!(
        report.len(),
        (completion_fixtures().len() + permission_fixtures().len()) * 3
    );
}

#[test]
fn fixture_versions_cover_stale_condition_target_and_profile_bindings() {
    let stale = completion_fixtures()
        .iter()
        .find(|fixture| fixture.id == "completion-stale-success")
        .expect("stale fixture");
    assert!(stale.request_condition_version < stale.current_condition_version);
    assert!(stale.request_target_version < stale.current_target_version);
    assert!(stale.request_profile_version < stale.current_profile_version);
    let connection = ConnectionId::new();
    let profile_v1 = herness_supervision_tests::fixtures::completion_profile_version(
        project(),
        connection,
        LLM_MODEL,
        1,
        ProfileInputs::text_only(),
    );
    let profile_v2 = herness_supervision_tests::fixtures::completion_profile_version(
        project(),
        connection,
        LLM_MODEL,
        2,
        ProfileInputs::text_only(),
    );
    assert_ne!(profile_v1.binding(), profile_v2.binding());
    let request = completion_request(
        stale,
        project(),
        ids(project()).condition_a,
        herness_supervision::DecisionId::new(project()),
        &profile_v1,
    );
    let result = herness_supervision::AssessmentResult::new(
        &request,
        request.evidence().to_vec(),
        "synthetic stale result",
        None,
        herness_supervision::AssessmentOutcome::NormalLlm {
            verdict: ConditionVerdict::Met,
            confidence: None,
        },
        herness_supervision::AssessmentProvenance::new(
            Provider::OpenAi,
            ProviderKind::NormalLlm,
            ModelId::new("synthetic-completion-judge").expect("model"),
            AdapterVersion::new("fixture-llm-adapter-1").expect("adapter"),
            herness_supervision::RubricVersion::new("fixture-rubric-1").expect("rubric"),
        )
        .expect("provenance"),
        now(),
    )
    .expect("stale result");
    let current_condition =
        ConditionVersion::new(stale.current_condition_version).expect("version");
    let current_target = TargetVersion::new(stale.current_target_version).expect("version");
    assert!(!result.applies_to(current_condition, current_target, profile_v2.binding(),));
    assert!(!result.supports_completion(
        current_condition,
        current_target,
        profile_v2.binding(),
        ProfileThresholds::normal_llm(),
    ));
}

#[test]
fn fixture_model_classes_are_not_interchangeable() {
    assert_eq!(FixtureClass::ScriptedContract.as_str(), "scripted_contract");
    assert_eq!(FixtureClass::RealModel.as_str(), "real_model");
    let all = all_fixtures();
    for fixture in all {
        match fixture.case {
            FixtureCase::Completion(_) => {
                assert_eq!(fixture.axis(), FixtureAxis::Completion);
                assert_eq!(fixture.expected_permission, ExpectedPermission::Ask);
            }
            FixtureCase::Permission(_) => {
                assert_eq!(fixture.axis(), FixtureAxis::Permission);
                assert_eq!(fixture.expected_completion, ExpectedCompletion::NotComplete);
            }
        }
    }
}
