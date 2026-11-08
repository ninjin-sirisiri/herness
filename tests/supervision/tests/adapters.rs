//! Black-box tests for assessment connection capabilities and the tool-less
//! transport.
//!
//! Every test uses a loopback HTTP mock and an in-memory credential port. No
//! real provider, Keychain item, Tauri window, paid call, or external network
//! request is used.

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use herness_assessment::{
    AssessmentEndpoints, AssessmentError, AssessmentErrorKind, AssessmentRequest,
    AssessmentTransport, CancelToken, ImageInput, ImageSource, RetryPolicy, TransportControl,
};
use herness_core::{
    AuthMethod, ConnectionAdmin, ConnectionCapabilityDeclaration, ConnectionDirectory,
    ConnectionError, ConnectionId, ConnectionSettings, CoreError, CredentialAvailability,
    CredentialKind, CredentialPort, Endpoint, EndpointClass, InputCapabilities, Provider,
    ResolvedCredential, SecretString,
};
use serde_json::json;

const CANARY: &str = "sk-canary-7f2c9d1e-assessment";
const CANARY_B: &str = "sk-canary-b-4a8e1c0d-assessment";
const JEV_MODEL: &str = "jev-1.14.0";
const DECISIONS_MODEL: &str = "gpt-6-luna";

struct FakeCredential {
    secret: Option<String>,
    kind: CredentialKind,
    calls: AtomicUsize,
    delay: Duration,
}

impl FakeCredential {
    fn api_key(secret: &str) -> Arc<Self> {
        Self::new(Some(secret.to_owned()), CredentialKind::ApiKey)
    }

    fn oauth(secret: &str) -> Arc<Self> {
        Self::new(Some(secret.to_owned()), CredentialKind::OAuthToken)
    }

    fn missing() -> Arc<Self> {
        Self::new(None, CredentialKind::ApiKey)
    }

    fn new(secret: Option<String>, kind: CredentialKind) -> Arc<Self> {
        Arc::new(Self {
            secret,
            kind,
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        })
    }

    fn with_delay(mut self: Arc<Self>, delay: Duration) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("test credential is uniquely owned")
            .delay = delay;
        self
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
        if !self.delay.is_zero() {
            thread::sleep(self.delay);
        }
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

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    fn json_body(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("mock request body is JSON")
    }
}

#[derive(Debug, Clone)]
struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
}

impl MockResponse {
    fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: br#"{"ok":true}"#.to_vec(),
            delay: Duration::ZERO,
        }
    }

    fn json(status: u16, value: serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: serde_json::to_vec(&value).expect("serializable mock body"),
            delay: Duration::ZERO,
        }
    }

    fn body(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
            delay: Duration::ZERO,
        }
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
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
                        thread::spawn(move || {
                            handle_connection(stream, requests, responses);
                        });
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
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();
        let mut header_map = BTreeMap::new();
        for (name, value) in parsed.headers {
            header_map.insert(name.to_ascii_lowercase(), value);
        }
        requests.lock().unwrap().push(RecordedRequest {
            method,
            path,
            headers: header_map,
            body: parsed.body,
        });
        let response = responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| MockResponse::status(200));
        if !response.delay.is_zero() {
            thread::sleep(response.delay);
        }
        let mut encoded = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
            response.status,
            reason_phrase(response.status),
            response.body.len()
        );
        for (name, value) in &response.headers {
            encoded.push_str(name);
            encoded.push_str(": ");
            encoded.push_str(value);
            encoded.push_str("\r\n");
        }
        encoded.push_str("\r\n");
        if stream.write_all(encoded.as_bytes()).is_err()
            || stream.write_all(&response.body).is_err()
        {
            return;
        }
        let _ = stream.flush();
    }
}

struct ParsedRequest {
    request_line: String,
    headers: Vec<(String, String)>,
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
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok()?;
        }
        headers.push((name.to_owned(), value));
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
        headers,
        body: buffer[header_end..header_end + content_length].to_vec(),
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

fn settings(
    admin: &ConnectionAdmin,
    provider: Provider,
    auth_method: AuthMethod,
    model: &str,
    endpoint: Option<Endpoint>,
    endpoint_class: EndpointClass,
    input: InputCapabilities,
) -> ConnectionSettings {
    let settings = ConnectionSettings::new_with_capabilities(
        ConnectionId::new(),
        provider,
        model,
        auth_method,
        endpoint,
        None,
        ConnectionCapabilityDeclaration::new(endpoint_class, input),
    )
    .expect("valid assessment settings");
    admin.add(settings.clone()).expect("register connection");
    settings
}

fn jev(admin: &ConnectionAdmin, input: InputCapabilities) -> ConnectionSettings {
    settings(
        admin,
        Provider::TypeSafe,
        AuthMethod::ApiKey,
        JEV_MODEL,
        None,
        EndpointClass::TypeSafeSystemOne,
        input,
    )
}

fn decisions(admin: &ConnectionAdmin, input: InputCapabilities) -> ConnectionSettings {
    settings(
        admin,
        Provider::OpenAi,
        AuthMethod::ApiKey,
        DECISIONS_MODEL,
        None,
        EndpointClass::OpenAiDecisions,
        input,
    )
}

fn agent_openai(admin: &ConnectionAdmin, input: InputCapabilities) -> ConnectionSettings {
    settings(
        admin,
        Provider::OpenAi,
        AuthMethod::ApiKey,
        "gpt-5",
        None,
        EndpointClass::OpenAiResponses,
        input,
    )
}

fn transport_for(
    credentials: Arc<dyn CredentialPort + Send + Sync>,
    directory: ConnectionDirectory,
    typesafe: &MockServer,
    openai: &MockServer,
) -> AssessmentTransport {
    let endpoints =
        AssessmentEndpoints::for_loopback(typesafe.url(), openai.openai_base(), openai.url())
            .expect("loopback endpoints");
    AssessmentTransport::new(credentials, directory, endpoints)
        .expect("transport")
        .with_retry_policy(RetryPolicy::with_base_delays([
            Duration::from_millis(1),
            Duration::from_millis(1),
        ]))
}

fn request_for(
    connection: ConnectionId,
    model: &str,
    body: serde_json::Value,
) -> AssessmentRequest {
    AssessmentRequest::new(connection, model, body).expect("valid assessment request")
}

fn send_without_deadline(
    transport: &AssessmentTransport,
    request: AssessmentRequest,
) -> Result<herness_assessment::AssessmentResponse, AssessmentError> {
    transport.send(request, TransportControl::default())
}

fn wait_for_requests(server: &MockServer, count: usize, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if server.count() >= count {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    server.count() >= count
}

#[test]
fn assessment_only_connections_are_rejected_for_agent_execution() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let decisions = decisions(&admin, InputCapabilities::text_and_image());
    let agent = agent_openai(&admin, InputCapabilities::text_and_image());

    let jev_capabilities = directory.capabilities(jev.connection_id()).unwrap();
    assert_eq!(
        jev_capabilities.endpoint_class(),
        EndpointClass::TypeSafeSystemOne
    );
    assert!(!jev_capabilities.allows_agent_execution());
    assert!(jev_capabilities.allows_assessment());
    assert_eq!(
        directory
            .agent_execution_capabilities(jev.connection_id())
            .unwrap_err(),
        ConnectionError::AgentExecutionNotAllowed {
            connection: jev.connection_id()
        }
    );

    let decisions_capabilities = directory.capabilities(decisions.connection_id()).unwrap();
    assert_eq!(
        decisions_capabilities.endpoint_class(),
        EndpointClass::OpenAiDecisions
    );
    assert!(!decisions_capabilities.allows_agent_execution());
    assert_eq!(
        directory
            .agent_execution_capabilities(decisions.connection_id())
            .unwrap_err(),
        ConnectionError::AgentExecutionNotAllowed {
            connection: decisions.connection_id()
        }
    );

    let agent_capabilities = directory.capabilities(agent.connection_id()).unwrap();
    assert!(agent_capabilities.allows_agent_execution());
    assert_eq!(
        agent_capabilities.input(),
        InputCapabilities::text_and_image()
    );

    // Legacy settings without a declaration keep the H1 agent defaults, except
    // that TypeSafe is always assessment-only.
    let legacy_type_safe = ConnectionSettings::new(
        ConnectionId::new(),
        Provider::TypeSafe,
        JEV_MODEL,
        AuthMethod::ApiKey,
        None,
        None,
    )
    .unwrap();
    let capabilities = legacy_type_safe.capabilities().unwrap();
    assert_eq!(
        capabilities.endpoint_class(),
        EndpointClass::TypeSafeSystemOne
    );
    assert!(!capabilities.allows_agent_execution());
}

#[test]
fn chatgpt_login_and_foreign_origins_are_rejected_for_decisions() {
    let chatgpt = ConnectionSettings::new_with_capabilities(
        ConnectionId::new(),
        Provider::OpenAi,
        DECISIONS_MODEL,
        AuthMethod::ChatGptLogin,
        None,
        None,
        ConnectionCapabilityDeclaration::new(
            EndpointClass::OpenAiDecisions,
            InputCapabilities::text_only(),
        ),
    );
    assert!(matches!(
        chatgpt.unwrap_err(),
        ConnectionError::CapabilityDeclarationRejected { .. }
    ));

    let custom_endpoint = Endpoint::parse("http://127.0.0.1:8080/v1").unwrap();
    let compatible = ConnectionSettings::new_with_capabilities(
        ConnectionId::new(),
        Provider::OpenAiCompatible,
        DECISIONS_MODEL,
        AuthMethod::ApiKey,
        Some(custom_endpoint.clone()),
        None,
        ConnectionCapabilityDeclaration::new(
            EndpointClass::OpenAiDecisions,
            InputCapabilities::text_only(),
        ),
    );
    assert!(matches!(
        compatible.unwrap_err(),
        ConnectionError::CapabilityDeclarationRejected { .. }
    ));

    let openai_endpoint = ConnectionSettings::new(
        ConnectionId::new(),
        Provider::OpenAi,
        DECISIONS_MODEL,
        AuthMethod::ApiKey,
        Some(custom_endpoint.clone()),
        None,
    );
    assert!(matches!(
        openai_endpoint.unwrap_err(),
        ConnectionError::EndpointNotAllowed {
            provider: Provider::OpenAi
        }
    ));

    let typesafe_endpoint = ConnectionSettings::new(
        ConnectionId::new(),
        Provider::TypeSafe,
        JEV_MODEL,
        AuthMethod::ApiKey,
        Some(custom_endpoint),
        None,
    );
    assert!(matches!(
        typesafe_endpoint.unwrap_err(),
        ConnectionError::EndpointNotAllowed {
            provider: Provider::TypeSafe
        }
    ));

    let agent_class_on_typesafe = ConnectionSettings::new_with_capabilities(
        ConnectionId::new(),
        Provider::TypeSafe,
        JEV_MODEL,
        AuthMethod::ApiKey,
        None,
        None,
        ConnectionCapabilityDeclaration::new(
            EndpointClass::OpenAiResponses,
            InputCapabilities::text_only(),
        ),
    );
    assert!(agent_class_on_typesafe.is_err());
}

#[test]
fn capability_registration_and_input_checks_are_exposed_by_the_directory() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let decisions = decisions(&admin, InputCapabilities::text_and_image());
    let capabilities = directory.list_capabilities().unwrap();
    assert_eq!(capabilities.len(), 2);
    assert!(capabilities.iter().any(|caps| {
        caps.connection_id() == jev.connection_id()
            && caps.endpoint_class() == EndpointClass::TypeSafeSystemOne
            && !caps.input().supports_image()
    }));
    assert!(capabilities.iter().any(|cap| {
        cap.connection_id() == decisions.connection_id()
            && cap.endpoint_class() == EndpointClass::OpenAiDecisions
            && cap.input().supports_image()
    }));

    let server = MockServer::start();
    server.push(MockResponse::status(200));
    let credentials = FakeCredential::api_key(CANARY);
    let transport = transport_for(credentials, directory.clone(), &server, &server);

    let image = ImageInput::new("image/png", vec![1_u8, 2, 3]).unwrap();
    let image_request = request_for(
        jev.connection_id(),
        JEV_MODEL,
        json!({"input": "check", "image": "placeholder"}),
    )
    .with_image(image.clone());
    let error = send_without_deadline(&transport, image_request).unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::UnsupportedModality);
    assert_eq!(
        server.count(),
        0,
        "unsupported modality reached the provider"
    );

    let image_url = request_for(jev.connection_id(), JEV_MODEL, json!({"input": "check"}))
        .with_image_sources([ImageSource::Url(
            "https://example.com/remote.png".to_owned(),
        )]);
    assert_eq!(
        image_url.unwrap_err().kind(),
        AssessmentErrorKind::ExternalImageUrl
    );
    assert_eq!(server.count(), 0);

    let image_request = request_for(
        decisions.connection_id(),
        DECISIONS_MODEL,
        json!({"input": "check", "image": "bytes"}),
    )
    .with_image(image);
    let response = send_without_deadline(&transport, image_request).unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(server.count(), 1);
    assert_eq!(
        server.requests()[0].json_body()["image"].as_str(),
        Some("bytes")
    );

    let mismatch = request_for(
        decisions.connection_id(),
        "gpt-other",
        json!({"input": "x"}),
    );
    assert_eq!(
        send_without_deadline(&transport, mismatch)
            .unwrap_err()
            .kind(),
        AssessmentErrorKind::ModelMismatch
    );
    assert_eq!(server.count(), 1);
}

#[test]
fn tool_less_payload_is_sent_without_tools_or_tool_choice() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let server = MockServer::start();
    server.push(MockResponse::json(200, json!({"decision": "allow"})));
    let transport = transport_for(FakeCredential::api_key(CANARY), directory, &server, &server);

    let request = request_for(
        jev.connection_id(),
        JEV_MODEL,
        json!({"input": "assess this evidence", "system": "no tools"}),
    );
    let response = send_without_deadline(&transport, request).unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(server.count(), 1);
    assert_eq!(server.requests()[0].method, "POST");
    assert_eq!(server.requests()[0].path, "/v1/systemone");
    let body = server.requests()[0].json_body();
    assert!(body.get("tools").is_none());
    assert!(body.get("tool_choice").is_none());
    assert_eq!(body["input"], "assess this evidence");

    let rejected = AssessmentRequest::new(
        jev.connection_id(),
        JEV_MODEL,
        json!({"input": "x", "tools": [{"name": "bash"}]}),
    );
    assert_eq!(
        rejected.unwrap_err().kind(),
        AssessmentErrorKind::ToolUseNotAllowed
    );
    assert_eq!(server.count(), 1);
}

#[test]
fn timeout_is_capped_and_ambiguous_send_timeout_is_not_retried() {
    let capped = TransportControl::default().with_remaining(Duration::from_secs(3_600));
    assert_eq!(capped.timeout(), Duration::from_secs(60));
    let short = TransportControl::default().with_remaining(Duration::from_millis(90));
    assert_eq!(short.timeout(), Duration::from_millis(90));

    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let server = MockServer::start();
    server.push(MockResponse::status(200).delay(Duration::from_secs(2)));
    let transport = transport_for(FakeCredential::api_key(CANARY), directory, &server, &server);
    let started = Instant::now();
    let error = transport
        .send(
            request_for(jev.connection_id(), JEV_MODEL, json!({"input": "slow"})),
            TransportControl::default().with_remaining(Duration::from_millis(100)),
        )
        .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::SendResultUnknown);
    assert_eq!(error.attempts(), 1);
    assert!(!error.is_retryable());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(server.count(), 1, "an ambiguous timeout was retried");
}

#[test]
fn cancellation_stops_an_in_flight_request_without_retry() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let server = MockServer::start();
    server.push(MockResponse::status(200).delay(Duration::from_secs(2)));
    let transport = transport_for(FakeCredential::api_key(CANARY), directory, &server, &server);

    let token = CancelToken::new();
    let cancel = token.clone();
    let watched = Arc::clone(&server);
    let canceller = thread::spawn(move || {
        assert!(wait_for_requests(&watched, 1, Duration::from_secs(2)));
        cancel.cancel();
    });
    let started = Instant::now();
    let error = transport
        .send(
            request_for(
                jev.connection_id(),
                JEV_MODEL,
                json!({"input": "cancel me"}),
            ),
            TransportControl::new(token).with_remaining(Duration::from_secs(10)),
        )
        .unwrap_err();
    canceller.join().unwrap();
    assert_eq!(error.kind(), AssessmentErrorKind::Cancelled);
    assert_eq!(error.attempts(), 1);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(server.count(), 1, "a cancelled request was retried");
}

#[test]
fn retry_after_is_honored_only_when_it_fits_the_deadline() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());

    let server = MockServer::start();
    server
        .push(MockResponse::json(429, json!({"error": "rate limited"})).header("retry-after", "0"));
    server.push(MockResponse::status(200));
    let transport = AssessmentTransport::new(
        FakeCredential::api_key(CANARY),
        directory.clone(),
        AssessmentEndpoints::for_loopback(server.url(), server.openai_base(), server.url())
            .unwrap(),
    )
    .unwrap()
    .with_retry_policy(RetryPolicy::with_base_delays([
        Duration::from_secs(30),
        Duration::from_secs(30),
    ]));
    let started = Instant::now();
    let response = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "retry"})),
    )
    .unwrap();
    assert_eq!(response.attempts(), 2);
    assert_eq!(server.count(), 2);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "Retry-After was not honored"
    );

    let server = MockServer::start();
    server.push(
        MockResponse::json(429, json!({"error": "rate limited"})).header("retry-after", "30"),
    );
    let transport = transport_for(
        FakeCredential::api_key(CANARY),
        directory.clone(),
        &server,
        &server,
    );
    let error = transport
        .send(
            request_for(jev.connection_id(), JEV_MODEL, json!({"input": "retry"})),
            TransportControl::default().with_remaining(Duration::from_secs(1)),
        )
        .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::RetryAfterBeyondDeadline);
    assert_eq!(error.attempts(), 1);
    assert_eq!(server.count(), 1);
}

#[test]
fn transient_server_failures_retry_at_most_twice() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());

    let server = MockServer::start();
    server.push(MockResponse::status(503));
    server.push(MockResponse::status(200));
    let transport = transport_for(
        FakeCredential::api_key(CANARY),
        directory.clone(),
        &server,
        &server,
    );
    let response = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "recover"})),
    )
    .unwrap();
    assert_eq!(response.attempts(), 2);
    assert_eq!(server.count(), 2);

    let server = MockServer::start();
    for _ in 0..5 {
        server.push(MockResponse::status(503));
    }
    let transport = transport_for(FakeCredential::api_key(CANARY), directory, &server, &server);
    let error = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "exhaust"})),
    )
    .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::ServerFailure);
    assert_eq!(error.status(), Some(503));
    assert_eq!(error.attempts(), 3);
    assert!(error.is_retry_exhausted());
    assert_eq!(server.count(), 3, "more than two additional retries");
}

#[test]
fn authentication_failure_and_invalid_response_are_not_retried() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());

    let server = MockServer::start();
    server.push(MockResponse::status(401));
    let transport = transport_for(
        FakeCredential::api_key(CANARY),
        directory.clone(),
        &server,
        &server,
    );
    let error = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "auth"})),
    )
    .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::AuthenticationFailed);
    assert_eq!(error.attempts(), 1);
    assert_eq!(server.count(), 1);

    let server = MockServer::start();
    server.push(MockResponse::body(200, Vec::new()));
    let transport = transport_for(FakeCredential::api_key(CANARY), directory, &server, &server);
    let error = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "invalid"})),
    )
    .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::InvalidResponse);
    assert_eq!(error.attempts(), 1);
    assert_eq!(server.count(), 1);
}

#[test]
fn provider_refusal_and_low_confidence_results_are_not_retried() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let server = MockServer::start();
    server.push(MockResponse::json(
        200,
        json!({"decision": "refuse", "confidence": 0.1, "insufficient": true}),
    ));
    let transport = transport_for(FakeCredential::api_key(CANARY), directory, &server, &server);
    let response = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "judge"})),
    )
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.attempts(), 1);
    assert_eq!(server.count(), 1);
    assert_eq!(
        response.json().unwrap()["decision"].as_str(),
        Some("refuse")
    );
}

#[test]
fn credential_resolution_is_bounded_by_the_request_deadline() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let server = MockServer::start();
    let credentials = FakeCredential::api_key(CANARY).with_delay(Duration::from_millis(500));
    let transport = transport_for(credentials, directory, &server, &server);
    let started = Instant::now();
    let error = transport
        .send(
            request_for(
                jev.connection_id(),
                JEV_MODEL,
                json!({"input": "slow credential"}),
            ),
            TransportControl::default().with_remaining(Duration::from_millis(80)),
        )
        .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::DeadlineReached);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(server.count(), 0);
}

#[test]
fn connection_failures_before_send_are_retried_twice() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());

    // A privileged loopback port with no listener refuses every connection
    // before request bytes can be sent. A fixed port avoids racing another
    // test's ephemeral mock listener.
    let base = "http://127.0.0.1:1";
    let transport = AssessmentTransport::new(
        FakeCredential::api_key(CANARY),
        directory,
        AssessmentEndpoints::for_loopback(base, base, base).unwrap(),
    )
    .unwrap()
    .with_retry_policy(RetryPolicy::with_base_delays([
        Duration::from_millis(1),
        Duration::from_millis(1),
    ]));
    let error = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "connect"})),
    )
    .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::ConnectionFailed);
    assert_eq!(error.attempts(), 3);
    assert!(error.is_retry_exhausted());
}

#[test]
fn cross_origin_redirect_never_receives_authorization() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let target = MockServer::start();
    let source = MockServer::start();
    source.push(MockResponse::status(302).header("location", &format!("{}/steal", target.url())));
    let transport = transport_for(FakeCredential::api_key(CANARY), directory, &source, &source);
    let error = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "redirect"})),
    )
    .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::CrossOriginRedirect);
    assert_eq!(error.attempts(), 1);
    assert_eq!(source.count(), 1);
    assert_eq!(target.count(), 0, "cross-origin target received a request");
    let source_request = &source.requests()[0];
    let expected = format!("Bearer {CANARY}");
    assert_eq!(
        source_request.header("authorization"),
        Some(expected.as_str())
    );

    let same_origin = MockServer::start();
    same_origin.push(MockResponse::status(302).header("location", "/next"));
    let transport = transport_for(
        FakeCredential::api_key(CANARY),
        admin.directory(),
        &same_origin,
        &same_origin,
    );
    let error = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "redirect"})),
    )
    .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::NoRedirectFollowing);
    assert_eq!(same_origin.count(), 1);
}

#[test]
fn secret_canary_is_absent_from_errors_and_debug_output() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let server = MockServer::start();
    for _ in 0..3 {
        server.push(MockResponse::body(
            500,
            format!("{{\"error\":\"{CANARY}\",\"body\":\"{CANARY_B}\"}}"),
        ));
    }
    let transport = transport_for(FakeCredential::api_key(CANARY), directory, &server, &server);
    let request = request_for(
        jev.connection_id(),
        JEV_MODEL,
        json!({"input": format!("request body {CANARY_B}")}),
    );
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains(CANARY_B));
    let error = send_without_deadline(&transport, request).unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::ServerFailure);
    let error_debug = format!("{error:?}");
    let error_display = error.to_string();
    for rendered in [&error_debug, &error_display] {
        assert!(!rendered.contains(CANARY), "secret in error: {rendered}");
        assert!(!rendered.contains(CANARY_B), "body in error: {rendered}");
    }
    // The credential was attached to the configured origin, proving the test
    // exercised the secret path rather than a missing-credential error.
    assert!(
        server.requests()[0]
            .header("authorization")
            .is_some_and(|value| value.contains(CANARY))
    );

    let server = MockServer::start();
    server.push(MockResponse::json(
        200,
        json!({"text": format!("provider body {CANARY_B}")}),
    ));
    let transport = transport_for(
        FakeCredential::api_key(CANARY),
        admin.directory(),
        &server,
        &server,
    );
    let response = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "ok"})),
    )
    .unwrap();
    assert!(!format!("{response:?}").contains(CANARY_B));
    assert!(
        response
            .body()
            .windows(CANARY_B.len())
            .any(|window| { window == CANARY_B.as_bytes() })
    );
}

#[test]
fn image_bytes_are_accepted_only_when_the_connection_supports_images() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let text_only = jev(&admin, InputCapabilities::text_only());
    let image_capable = decisions(&admin, InputCapabilities::text_and_image());
    let server = MockServer::start();
    server.push(MockResponse::status(200));
    let transport = transport_for(FakeCredential::api_key(CANARY), directory, &server, &server);

    let bytes = ImageInput::new("image/png", vec![0x89, b'P', b'N', b'G']).unwrap();
    let unsupported = request_for(
        text_only.connection_id(),
        JEV_MODEL,
        json!({"input": "image"}),
    )
    .with_image(bytes.clone());
    assert_eq!(
        send_without_deadline(&transport, unsupported)
            .unwrap_err()
            .kind(),
        AssessmentErrorKind::UnsupportedModality
    );
    assert_eq!(server.count(), 0);

    let supported = request_for(
        image_capable.connection_id(),
        DECISIONS_MODEL,
        json!({"input": "image", "imageBytes": "present"}),
    )
    .with_image(bytes);
    let response = send_without_deadline(&transport, supported).unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(server.count(), 1);
    assert_eq!(server.requests()[0].path, "/v1/decisions");
    assert_eq!(
        server.requests()[0].json_body()["imageBytes"].as_str(),
        Some("present")
    );
}

#[test]
fn retries_stay_on_the_same_connection_without_provider_fallback() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let _decisions = decisions(&admin, InputCapabilities::text_and_image());
    let jev_server = MockServer::start();
    for _ in 0..5 {
        jev_server.push(MockResponse::status(503));
    }
    let decisions_server = MockServer::start();
    decisions_server.push(MockResponse::status(200));
    let jev_credentials = FakeCredential::api_key(CANARY);
    let decisions_credentials = FakeCredential::api_key(CANARY_B);
    // A single transport resolves both connections, so a provider fallback
    // would be observable as a request on the Decisions server.
    let endpoints = AssessmentEndpoints::for_loopback(
        jev_server.url(),
        decisions_server.openai_base(),
        decisions_server.url(),
    )
    .unwrap();
    let transport = AssessmentTransport::new(
        Arc::new(FallbackCredentials {
            jev: Arc::clone(&jev_credentials),
            decisions: Arc::clone(&decisions_credentials),
            jev_connection: jev.connection_id(),
        }),
        directory,
        endpoints,
    )
    .unwrap()
    .with_retry_policy(RetryPolicy::with_base_delays([
        Duration::from_millis(1),
        Duration::from_millis(1),
    ]));
    let error = send_without_deadline(
        &transport,
        request_for(jev.connection_id(), JEV_MODEL, json!({"input": "fail"})),
    )
    .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::ServerFailure);
    assert_eq!(jev_server.count(), 3);
    assert_eq!(decisions_server.count(), 0);
    assert_eq!(jev_credentials.calls(), 3);
    assert_eq!(decisions_credentials.calls(), 0);
}

struct FallbackCredentials {
    jev: Arc<FakeCredential>,
    decisions: Arc<FakeCredential>,
    jev_connection: ConnectionId,
}

impl CredentialPort for FallbackCredentials {
    fn availability(&self, connection: &ConnectionId) -> Result<CredentialAvailability, CoreError> {
        if *connection == self.jev_connection {
            self.jev.availability(connection)
        } else {
            self.decisions.availability(connection)
        }
    }

    fn resolve(&self, connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        if *connection == self.jev_connection {
            self.jev.resolve(connection)
        } else {
            self.decisions.resolve(connection)
        }
    }
}

#[test]
fn transport_returns_no_billing_or_cost_records() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let server = MockServer::start();
    server.push(MockResponse::json(
        200,
        json!({
            "decision": "allow",
            "model": JEV_MODEL,
            "usage": {"input_tokens": 12, "output_tokens": 3},
        }),
    ));
    let transport = transport_for(FakeCredential::api_key(CANARY), directory, &server, &server);
    let response = send_without_deadline(
        &transport,
        request_for(
            jev.connection_id(),
            JEV_MODEL,
            json!({"input": "billing boundary"}),
        ),
    )
    .unwrap();
    assert_eq!(response.reported_model().as_deref(), Some(JEV_MODEL));
    let metadata = response.json().unwrap();
    let object = metadata.as_object().unwrap();
    assert!(object.get("cost").is_none());
    assert!(object.get("billing").is_none());
    assert!(object.get("reservation").is_none());
    // The transport has no store or billing dependency; the upper H2 request
    // gate owns cost reservation and recording.
    assert_eq!(server.count(), 1);
}

#[test]
fn missing_credential_stops_before_send_without_fallback() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let jev = jev(&admin, InputCapabilities::text_only());
    let server = MockServer::start();
    let credentials = FakeCredential::missing();
    let transport = transport_for(credentials.clone(), directory, &server, &server);
    let error = send_without_deadline(
        &transport,
        request_for(
            jev.connection_id(),
            JEV_MODEL,
            json!({"input": "no credential"}),
        ),
    )
    .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::CredentialUnavailable);
    assert_eq!(error.attempts(), 0);
    assert_eq!(credentials.calls(), 1);
    assert_eq!(server.count(), 0);
}

#[test]
fn chatgpt_login_credentials_are_attached_as_bearer_to_agent_connections() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let connection = settings(
        &admin,
        Provider::OpenAi,
        AuthMethod::ChatGptLogin,
        "gpt-5",
        None,
        EndpointClass::OpenAiResponses,
        InputCapabilities::text_and_image(),
    );
    let server = MockServer::start();
    server.push(MockResponse::json(200, json!({"ok": true})));
    let credentials = FakeCredential::oauth(CANARY_B);
    let transport = transport_for(credentials.clone(), directory, &server, &server);
    let response = send_without_deadline(
        &transport,
        request_for(
            connection.connection_id(),
            "gpt-5",
            json!({"input": "oauth"}),
        ),
    )
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(credentials.calls(), 1);
    assert_eq!(
        server.requests()[0].header("authorization"),
        Some(format!("Bearer {CANARY_B}").as_str())
    );
}

#[test]
fn decisions_require_api_key_credentials_even_with_a_stale_settings_value() {
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
    let connection = decisions(&admin, InputCapabilities::text_only());
    let server = MockServer::start();
    let credentials = FakeCredential::oauth(CANARY_B);
    let transport = transport_for(credentials, directory, &server, &server);
    let error = send_without_deadline(
        &transport,
        request_for(
            connection.connection_id(),
            DECISIONS_MODEL,
            json!({"input": "oauth"}),
        ),
    )
    .unwrap_err();
    assert_eq!(error.kind(), AssessmentErrorKind::CredentialUnavailable);
    assert_eq!(error.attempts(), 0);
    assert_eq!(server.count(), 0);
}
