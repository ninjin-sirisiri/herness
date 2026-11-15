//! A host-run required check must not replace the child run's engine
//! conversation checkpoint.
//!
//! The check is a real [`HostCheckPort`] verification over a real temporary
//! project, a real SQLite store, and the real H1 `bash` executor. The child
//! conversation checkpoint comes from a real `PiEngine` run whose only provider
//! is a loopback HTTP mock. No credential, provider host, or other network
//! endpoint is used.
//!
//! Regression: the check's `BashExecutor` audit checkpoint used to be committed
//! into the child run's checkpoint slot, so a later continuation of that run
//! failed with `CheckpointNotLatest` and fixable unmet work could not return to
//! the same child.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use herness_core::contracts::{AgentId, RunState, SessionId};
use herness_core::permissions::{
    MatchMethod, PermissionMode, PermissionPolicy, PolicyAdmin, RuleTarget, SharedPolicy,
};
use herness_core::tools::ToolName;
use herness_core::{
    AbsolutePath, AuthMethod, Checkpoint, ConnectionAdmin, ConnectionId, ConnectionSettings,
    CredentialAvailability, CredentialKind, CredentialPort, EngineEvent, EngineInput, EnginePort,
    EngineStart, GrantScope, HistoryLimit, ProjectId, Provider, ResolvedCredential, RunControl,
    RunId, RunPermissionContext, SecretString, StorePort, hash_bytes,
};
use herness_desktop::supervision::checks::HostCheckPort;
use herness_desktop::supervision::store::StoreHandle;
use herness_desktop::supervision::workspace::ProjectWorkspace;
use herness_engine_pi::{PiEngine, PiEngineConfig, ProviderEndpoints};
use herness_store::{Store, StoreConfig};
use herness_supervision::budget::BudgetPolicy;
use herness_supervision::conditions::{
    Condition, ConditionMode, ConditionOrigin, ConditionSet, ConditionVersion, RequiredCheck,
};
use herness_supervision::evidence::CheckInvocation;
use herness_supervision::freshness::{TargetReadSet, capture_manifest};
use herness_supervision::ids::{CheckId, ConditionId, EvidenceId, SupervisionId};
use herness_supervision::ports::SupervisionStorePort;
use herness_supervision::state::SupervisionRecord;
use herness_supervision::supervisor::{CheckExecution, CheckExecutionRequest, RequiredCheckPort};
use herness_supervision::{
    ApprovalActor, ApprovalBasis, ConditionApproval, ExecutionScope, OwnerKind, OwnerRef, RunGroup,
    RunGroupId, SupervisionSubject, TargetVersion, VerificationOperation,
};
use herness_supervision_tests::{completion_profile, consent, now, work_packet};
use serde_json::{Value, json};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Loopback provider mock
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct RecordedRequest {
    body: String,
}

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
}

fn handle_connection(
    mut stream: TcpStream,
    handler: Arc<dyn Fn(&RecordedRequest) -> MockResponse + Send + Sync>,
    recorded: Arc<Mutex<Vec<RecordedRequest>>>,
) {
    let body = match read_body(&mut stream) {
        Some(body) => body,
        None => return,
    };
    let request = RecordedRequest { body };
    recorded.lock().expect("record").push(request.clone());
    let response = handler(&request);
    let header = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(response.body.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn read_body(stream: &mut TcpStream) -> Option<String> {
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
    for line in head.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
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
    Some(String::from_utf8_lossy(&body).into_owned())
}

fn sse(event: &str, data: Value) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

/// One completed OpenAI Responses turn carrying `text`.
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
            .unwrap_or_else(|| MockResponse {
                status: 500,
                content_type: "application/json",
                body: json!({"error": {"code": "unexpected_request"}}).to_string(),
            })
    }
}

// ---------------------------------------------------------------------------
// In-memory credential port
// ---------------------------------------------------------------------------

struct FixedCredentials {
    connection: ConnectionId,
    secret: String,
}

impl CredentialPort for FixedCredentials {
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
        if connection != &self.connection {
            return Err(herness_core::CoreError::AuthenticationRequired {
                connection: *connection,
            });
        }
        Ok(ResolvedCredential::new(
            CredentialKind::ApiKey,
            SecretString::new(self.secret.clone()).expect("non-empty secret"),
        ))
    }
}

// ---------------------------------------------------------------------------
// Real project, store, and permission policy
// ---------------------------------------------------------------------------

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    project: ProjectId,
    supervision: SupervisionId,
    store: Arc<Mutex<Store>>,
    handle: StoreHandle,
    policy: PermissionPolicy,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let root = temp.path().join("project");
        std::fs::create_dir_all(root.join("src")).expect("src");
        std::fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").expect("source");
        let project = ProjectId::new();
        let supervision = SupervisionId::new(project);
        let config = StoreConfig::new(temp.path().join("state")).expect("store config");
        let store = Arc::new(Mutex::new(Store::open(config).expect("store")));
        let handle = StoreHandle::new(Arc::clone(&store));
        let policy = configured_bash_policy();
        Self {
            _temp: temp,
            root,
            project,
            supervision,
            store,
            handle,
            policy,
        }
    }

    fn shared_policy(&self) -> SharedPolicy {
        SharedPolicy::new(self.policy.clone())
    }

    fn load_checkpoint(&self, run: RunId) -> Option<Checkpoint> {
        <Store as StorePort>::load_checkpoint(&self.store.lock().expect("store"), &run)
            .expect("load checkpoint")
    }

    /// Builds a real approved contract over the fixture project.
    fn contract(
        &self,
        conditions: ConditionSet,
        read_set: Vec<String>,
    ) -> herness_supervision::SupervisionContract {
        let workspace = ProjectWorkspace::new(self.root.clone());
        let manifest = capture_manifest(
            &workspace,
            self.project,
            TargetVersion::new(1).expect("target version"),
            TargetReadSet::Declared(read_set.clone()),
        )
        .expect("manifest");
        let target = manifest.target_scope().expect("target scope");
        let execution =
            ExecutionScope::new(self.project, read_set, Vec::new(), true).expect("execution scope");
        let profile = completion_profile(self.project);
        let consent = consent(
            self.project,
            herness_supervision::ProfilePurpose::Completion,
            1,
        );
        let budget = BudgetPolicy::h2_default();
        let packet = work_packet(
            self.project,
            &target,
            &execution,
            conditions.condition_version(),
            &profile,
            &consent,
            &budget,
            "host check continuation fixture",
        );
        let subject = SupervisionSubject::new(
            self.project,
            self.supervision,
            AgentId::new(self.project),
            SessionId::new(self.project),
            OwnerRef::new(OwnerKind::Human, "check-continuation-fixture").expect("owner"),
        )
        .expect("subject");
        herness_supervision::SupervisionContract::new(
            ApprovalActor::Human,
            subject,
            execution,
            RunGroup::new(RunGroupId::new(self.project)),
            conditions,
            target,
            &profile,
            &consent,
            budget,
            packet,
            now(),
        )
        .expect("contract")
    }

    fn save_record_with_run(
        &self,
        contract: &herness_supervision::SupervisionContract,
        run: RunId,
    ) {
        let mut record = SupervisionRecord::new(contract);
        record.begin_run(run).expect("begin run");
        let mut store = self.handle.clone();
        store
            .compare_and_swap(self.project, self.supervision, None, &record)
            .expect("save record");
    }
}

fn configured_bash_policy() -> PermissionPolicy {
    let mut admin = PolicyAdmin::new();
    admin
        .add_rule(
            herness_core::permissions::PermissionRule::allow(
                RuleTarget::Tool {
                    tool: ToolName::Bash,
                },
                MatchMethod::AnyInvocation,
            )
            .expect("rule"),
        )
        .expect("add rule");
    let policy = admin.policy().clone();
    assert_eq!(policy.mode(), PermissionMode::Configured);
    policy
}

/// One approved `Checks` condition with one approved shell check.
fn approved_conditions(project: ProjectId, command: &str) -> ConditionSet {
    let condition_id = ConditionId::new(project);
    let check_id = CheckId::new(project);
    let check = RequiredCheck::new(
        check_id,
        condition_id,
        VerificationOperation::command(command).expect("command"),
        CheckInvocation::new(".", 60, Vec::new()).expect("invocation"),
        "host-run required check",
    )
    .expect("required check");
    let condition = Condition::new(
        condition_id,
        "continuation condition",
        "The approved rubric text.",
        ConditionMode::Checks,
        vec![check_id],
        ConditionOrigin::Human,
    )
    .expect("condition");
    let mut set = ConditionSet::new(
        project,
        ConditionVersion::new(1).expect("version"),
        vec![condition],
        vec![check],
    )
    .expect("condition set");
    let approval = ConditionApproval::new(
        project,
        ApprovalBasis::ExplicitHuman {
            approved_at: now(),
            expires_at: None,
        },
        set.condition_version(),
        set.digest().clone(),
    )
    .expect("approval");
    set.approve(ApprovalActor::Human, approval, now())
        .expect("approve");
    set
}

// ---------------------------------------------------------------------------
// Engine helpers
// ---------------------------------------------------------------------------

fn engine_permission(fixture: &Fixture, run: RunId) -> RunPermissionContext {
    RunPermissionContext::new(
        fixture.project,
        run,
        GrantScope::for_run(fixture.project, &fixture.policy),
        fixture.shared_policy(),
        None,
        RunControl::new(),
    )
    .expect("engine permission context")
}

fn engine_start(
    fixture: &Fixture,
    connection: ConnectionId,
    instructions: &str,
) -> (AgentId, SessionId, RunId, EngineStart) {
    let agent = AgentId::new(fixture.project);
    let session = SessionId::new(fixture.project);
    let run = RunId::new(fixture.project);
    let cwd = AbsolutePath::new(fixture.root.to_string_lossy().into_owned()).expect("cwd");
    let start = EngineStart::new(
        fixture.project,
        agent,
        session,
        run,
        connection,
        cwd,
        instructions,
    )
    .expect("engine start")
    .with_permission(engine_permission(fixture, run));
    (agent, session, run, start)
}

fn continuation_start(previous: &EngineStart, run: RunId) -> EngineStart {
    let permission = previous
        .permission()
        .expect("previous start has a permission context")
        .for_run(run)
        .expect("continuation permission context");
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
    .with_permission(permission)
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

// ---------------------------------------------------------------------------
// The regression
// ---------------------------------------------------------------------------

#[test]
fn a_real_host_check_keeps_the_child_conversation_continuable() {
    let fixture = Fixture::new();
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
        .expect("loopback endpoints");
    let admin = ConnectionAdmin::new();
    let directory = admin.directory();
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
            .expect("connection settings"),
        )
        .expect("add connection");
    let credentials = Arc::new(FixedCredentials {
        connection,
        // Loopback-only fake bearer token; never a real provider credential.
        secret: ["sk", "test", "loopback", "placeholder"].join("-"),
    });
    let mut engine = PiEngine::new(
        Arc::clone(&fixture.store),
        credentials,
        directory,
        PiEngineConfig::new(fixture.policy.clone()).with_endpoints(endpoints),
    )
    .expect("engine");

    let (_, _, run, start) = engine_start(&fixture, connection, "You are a test agent.");
    engine.start(start.clone()).expect("first start");
    let _ = engine.poll_events(&run).expect("startup events");
    engine
        .send_input(
            &run,
            EngineInput::Text("Remember this fact: the access code is ORANGE-42.".to_owned()),
        )
        .expect("first input");
    let first_events = collect_until_terminal(&mut engine, &run, Duration::from_secs(10));
    assert_eq!(text_of(&first_events), "The access code is ORANGE-42.");

    let before = fixture
        .load_checkpoint(run)
        .expect("the child run has an engine checkpoint");
    assert_eq!(
        before.run_id(),
        run,
        "the conversation checkpoint must belong to the child run"
    );
    let before_digest = hash_bytes(before.payload().as_bytes());

    // Real approved check execution through the host port for that same run.
    let conditions = approved_conditions(fixture.project, "printf check-ok");
    let contract = fixture.contract(conditions.clone(), vec!["src/lib.rs".to_owned()]);
    fixture.save_record_with_run(&contract, run);
    let condition = &conditions.conditions()[0];
    let check = &conditions.checks()[0];
    let request = CheckExecutionRequest::new(
        fixture.project,
        fixture.supervision,
        condition.id(),
        check.id(),
        ConditionVersion::new(1).expect("version"),
        TargetVersion::new(1).expect("version"),
        EvidenceId::new(fixture.project),
        1,
        VerificationOperation::command("printf check-ok").expect("command"),
        CheckInvocation::new(".", 60, Vec::new()).expect("invocation"),
        60,
        vec!["src/lib.rs".to_owned()],
    );
    let mut port = HostCheckPort::new(
        fixture.handle.clone(),
        AgentId::new(fixture.project),
        SessionId::new(fixture.project),
        fixture.root.clone(),
        fixture.shared_policy(),
        "host check continuation fixture",
    );
    let execution: CheckExecution = port.execute(&request).expect("check executes");
    assert_eq!(
        execution.result().status(),
        herness_supervision::CheckStatus::Pass,
        "the approved check must observe a pass; result={:?}",
        execution.result()
    );

    // The child's conversation checkpoint is untouched, byte for byte.
    let after = fixture
        .load_checkpoint(run)
        .expect("the child run still has an engine checkpoint");
    assert_eq!(
        before.format_version(),
        after.format_version(),
        "a host check must not change the conversation checkpoint format"
    );
    assert_eq!(
        before.payload().as_bytes(),
        after.payload().as_bytes(),
        "a host check must not replace the child conversation checkpoint \
         (before digest {before_digest}, after digest {})",
        hash_bytes(after.payload().as_bytes())
    );

    // The same child can be continued: no CorruptCheckpoint/CheckpointNotLatest.
    let run2 = RunId::new(fixture.project);
    let start2 = continuation_start(&start, run2);
    engine
        .check_continuation(&start2, &before)
        .expect("the previous run stays continuable after a real host check");
    engine
        .start_continuation(start2, before.clone())
        .expect("continuation start");
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

    let requests = server.requests();
    assert_eq!(requests.len(), 2, "one provider request per turn");
    assert!(
        requests[1].body.contains("ORANGE-42"),
        "the continuation must carry the previous run's conversation: {}",
        requests[1].body
    );
    assert!(
        requests[1].body.contains("Remember this fact"),
        "the first user turn must be preserved through the continuation"
    );

    // The check's own H1 audit trail is still durable.
    let events = fixture
        .store
        .lock()
        .expect("store")
        .events_after(
            &fixture.project,
            None,
            HistoryLimit::new(200).expect("limit"),
        )
        .expect("events");
    let started = events
        .iter()
        .find(|event| event.kind().as_str() == "shell.started")
        .expect("the check recorded its intent before spawning");
    assert_eq!(started.run_id(), Some(run));
    let operation = started.operation_id().expect("check operation id");
    assert!(
        events
            .iter()
            .any(|event| event.kind().as_str() == "shell.finished"),
        "the check recorded its result after the process ended"
    );
    let record = fixture
        .store
        .lock()
        .expect("store")
        .operation(&operation)
        .expect("operation record")
        .expect("the check operation is durable");
    assert_eq!(
        record.intent().operation().run_id(),
        run,
        "the check operation stays attached to the child run"
    );
    assert!(
        record.result().is_some(),
        "the check result is durable after the process ended"
    );
    assert!(
        !record.is_unresolved(),
        "a completed check must not look like an interrupted operation"
    );

    // The audit checkpoint body itself is still durable, under a check-only
    // host-state key rather than the child run's checkpoint slot.
    let audit_key = format!("h2.supervision.check.audit:{operation}");
    let audit = fixture
        .store
        .lock()
        .expect("store")
        .load_host_state(&audit_key)
        .expect("host state")
        .expect("the check audit checkpoint is durable");
    let audit: Value = serde_json::from_slice(&audit).expect("audit checkpoint JSON");
    assert_eq!(audit["runId"], json!(run.to_string()));
    assert_eq!(
        audit["payload"].as_str().map(|_| ()),
        Some(()),
        "the audit checkpoint keeps its opaque payload: {audit}"
    );
}
