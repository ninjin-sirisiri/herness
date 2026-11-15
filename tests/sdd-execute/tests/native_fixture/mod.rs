//! Shared fixture for the real-Tauri H4 lifecycle target.
//!
//! The fixture seeds one durable H4 execution whose single Task was already
//! dispatched, whose child (a real Pi engine talking to a loopback HTTP mock)
//! already finished, and whose stored H2 target is `completed`. Nothing about
//! the host commit is simulated: the native `herness-desktop` process performs
//! the real HTML barrier and the real `Index → gate → commit` boundary.
//!
//! The seeding host uses the real plan inspector, the real SQLite store, the
//! real H2 supervisor, the real required-check port (`true`), the real
//! assessment port (never called because every condition is `checks` mode), and
//! the real tool executor. Only the provider endpoint is a loopback mock.

#![allow(dead_code)]

use std::collections::{BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use herness_core::{
    AuthMethod, ConnectionAdmin, ConnectionId, ConnectionSettings, CoreError,
    CredentialAvailability, CredentialKind, CredentialPort, Endpoint, ProjectId, Provider,
    ResolvedCredential, SecretString, Timestamp,
};
use herness_desktop::host::DesktopHost;
use herness_desktop::sdd_execute::controller::{
    SddApproveStartRequest, SddPreviewRequest, SddTaskController, SddTaskLimitRequest,
};
use herness_desktop::supervision::PumpScope;
use herness_desktop::supervision::runtime::DesktopH1;
use herness_desktop::supervision::store::StoreHandle;
use herness_desktop::supervision::{ConfirmationKind, PlanRequestActor};
use herness_engine_pi::ProviderEndpoints;
use herness_html_sync::{
    Applicability, DocumentCommit, DocumentKey, FingerprintSet, H3ApprovalLimits, H3Approver,
    H3ConfigurationApproval, H3ConfigurationDraft, H3ConnectionApproval, H3DocumentState,
    H3OwnerBinding, H3Reason, H3Settings, H3StateReasonKind, H3StorePort, H3VersionBinding,
    HtmlSyncCommit, SettingsCommit, SourceRevision, SourceSnapshot, dependency_fingerprint,
    document_state_event,
};
use herness_sdd_execute::{ApprovalId, ControlRequestId, ExecutionId};
use herness_supervision::ContentDigest;
use herness_supervision::{
    BudgetPolicy, ConditionDigest, ConditionVersion, DisclosureDataKind, DisclosureScope,
    ExecutionScope, OwnerKind, OwnerRef, ProfileId, ProfilePurpose, ProfileVersion, ProviderOrigin,
    SupervisionId, TargetVersion,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use uuid::Uuid;

/// The real pack checkout the fixture inspects.
pub const PACK_ROOT: &str = "/Users/h-uma/Documents/sdd/.worktrees/h4-exec";
/// Approved plan path inside the fixture checkout.
pub const PLAN: &str = "docs/sdd/plans/2026-11-15-h4-native-lifecycle.md";
/// Approved spec path inside the fixture checkout.
pub const SPEC: &str = "docs/sdd/specs/2026-11-15-h4-native-lifecycle-design.md";
/// CSS dependency used by the H3 fingerprints.
pub const CSS: &str = "docs/sdd/assets/sdd.css";
/// The one Task deliverable the child writes.
pub const TASK_ONE: &str = "src/task-one.txt";
/// Fixture branch.
pub const BRANCH: &str = "h4-native-lifecycle";
/// Agent model recorded on the connection.
pub const AGENT_MODEL: &str = "gpt-native-lifecycle";

/// One seeded execution and the temporary roots that own it.
pub struct Seeded {
    /// Application data root; keep alive for the whole test.
    pub data: TempDir,
    /// Parent of the checkout; keep alive for the whole test.
    pub project_dir: TempDir,
    /// Canonical checkout the native process commits in.
    pub root: PathBuf,
    /// Project identity assigned by the first host open.
    pub project: ProjectId,
    /// The pre-dispatched execution.
    pub execution: ExecutionId,
    /// The one Task's H2 target, already `completed`.
    pub supervision: SupervisionId,
    /// Baseline commit the Task must advance from.
    pub baseline: String,
}

// ---------------------------------------------------------------------------
// Loopback Pi mock
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
}

struct Loopback {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Loopback {
    fn start(responses: Vec<MockResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::from(responses)));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = Arc::clone(&thread_requests);
                        let queue = Arc::clone(&queue);
                        thread::spawn(move || respond(stream, requests, queue));
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

    fn openai_base(&self) -> String {
        format!("{}/v1", self.url())
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn respond(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    queue: Arc<Mutex<VecDeque<MockResponse>>>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    loop {
        let Some(body) = read_request(&mut stream) else {
            return;
        };
        requests.lock().unwrap().push(body);
        let response = queue
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| MockResponse::sse(String::new()));
        if write_response(&mut stream, &response).is_err() {
            return;
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
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
    Some(buffer)
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

fn sse(event: &str, data: Value) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

fn responses_text(text: &str) -> MockResponse {
    let mut body = String::new();
    body.push_str(&sse(
        "response.created",
        json!({"type": "response.created", "response": {"id": "resp_text"}}),
    ));
    body.push_str(&sse(
        "response.output_item.added",
        json!({
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {"type": "message", "id": "msg_1", "content": []}
        }),
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
                "id": "resp_text",
                "status": "completed",
                "output": [{"type": "message", "id": "msg_1", "content": [{"type": "output_text", "text": text}]}]
            }
        }),
    ));
    MockResponse::sse(body)
}

fn responses_write(path: &str, content: &str) -> MockResponse {
    let arguments = json!({
        "path": path,
        "content": content,
        "rationale": "write the approved Task deliverable",
    })
    .to_string();
    let item = json!({
        "type": "function_call",
        "id": "fc_native_lifecycle",
        "call_id": "call_native_lifecycle",
        "name": "write",
        "arguments": arguments
    });
    let mut body = String::new();
    body.push_str(&sse(
        "response.created",
        json!({"type": "response.created", "response": {"id": "resp_tool"}}),
    ));
    body.push_str(&sse(
        "response.output_item.added",
        json!({"type": "response.output_item.added", "output_index": 0, "item": {"type": "function_call", "id": "fc_native_lifecycle", "call_id": "call_native_lifecycle", "name": "write", "arguments": ""}}),
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
            "response": {"id": "resp_tool", "status": "completed", "output": [item]}
        }),
    ));
    MockResponse::sse(body)
}

// ---------------------------------------------------------------------------
// Credentials and permission policy
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
            SecretString::new("sk-native-lifecycle-fixture").expect("fake credential"),
        ))
    }
}

fn configure_policy(host: &mut DesktopHost, root: &Path) {
    use herness_core::ToolName;
    use herness_core::permissions::{MatchMethod, PermissionRule, RuleTarget};

    let admin = host.runtime_mut().policy_admin_mut();
    for tool in [ToolName::Read, ToolName::Search] {
        admin
            .add_rule(
                PermissionRule::allow(
                    RuleTarget::FilePath {
                        tool,
                        root: herness_core::AbsolutePath::new(
                            root.join("src").to_string_lossy().into_owned(),
                        )
                        .expect("src root"),
                    },
                    MatchMethod::PathPrefix,
                )
                .expect("read rule"),
            )
            .expect("read rule");
    }
    for tool in [ToolName::Write, ToolName::Edit] {
        admin
            .add_rule(
                PermissionRule::allow(
                    RuleTarget::FilePath {
                        tool,
                        root: herness_core::AbsolutePath::new(
                            root.join("src").to_string_lossy().into_owned(),
                        )
                        .expect("src root"),
                    },
                    MatchMethod::PathPrefix,
                )
                .expect("write rule"),
            )
            .expect("write rule");
    }
    admin
        .add_rule(
            PermissionRule::allow(
                RuleTarget::Tool {
                    tool: ToolName::Bash,
                },
                MatchMethod::AnyInvocation,
            )
            .expect("bash rule"),
        )
        .expect("bash rule");
}

// ---------------------------------------------------------------------------
// Git
// ---------------------------------------------------------------------------

pub fn run_git(root: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .current_dir(root)
        .args(args)
        .status()
        .expect("git");
    assert!(status.success(), "git {args:?}");
}

pub fn git_stdout(root: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .expect("git");
    assert!(output.status.success(), "git {args:?}");
    String::from_utf8(output.stdout)
        .expect("git utf8")
        .trim_end()
        .to_owned()
}

pub fn head(root: &Path) -> String {
    git_stdout(root, &["rev-parse", "HEAD"])
}

pub fn commit_count(root: &Path) -> usize {
    git_stdout(root, &["rev-list", "--count", "HEAD"])
        .parse()
        .expect("count")
}

// ---------------------------------------------------------------------------
// H3 seeding
// ---------------------------------------------------------------------------

fn now() -> Timestamp {
    Timestamp::now()
}

fn digest(text: &str) -> ContentDigest {
    ContentDigest::sha256(text.as_bytes())
}

fn profile(project: ProjectId, purpose: ProfilePurpose) -> herness_supervision::ProfileBinding {
    herness_supervision::ProfileBinding::new(
        ProfileId::from_parts(project, Uuid::new_v4()),
        ProfileVersion::new(1).expect("profile version"),
        purpose,
    )
}

fn consent(project: ProjectId, purpose: ProfilePurpose) -> herness_supervision::ConsentBinding {
    herness_supervision::ConsentBinding::new(
        herness_supervision::ConsentId::from_parts(project, Uuid::new_v4()),
        1,
        purpose,
        TargetVersion::new(1).expect("target version"),
    )
}

fn h3_connection(project: ProjectId, purpose: ProfilePurpose) -> H3ConnectionApproval {
    H3ConnectionApproval::new(
        project,
        ConnectionId::new(),
        ProviderOrigin::parse("https://loopback.example").expect("origin"),
        DisclosureScope::new(
            purpose,
            BTreeSet::from([DisclosureDataKind::Text]),
            vec![PLAN.to_owned(), SPEC.to_owned()],
            TargetVersion::new(1).expect("target version"),
        )
        .expect("disclosure"),
        profile(project, purpose),
        consent(project, purpose),
    )
    .expect("connection approval")
}

pub fn seed_settings(store: &StoreHandle, project: ProjectId) -> H3Settings {
    let approval = H3ConfigurationApproval::approve(
        H3ConfigurationDraft {
            project_id: project,
            settings_version: 1,
            approval_id: "native-lifecycle".to_owned(),
            expires_at: None,
            targets: vec![PLAN.to_owned(), SPEC.to_owned()],
            authoring: h3_connection(project, ProfilePurpose::Completion),
            assessment: h3_connection(project, ProfilePurpose::Html),
            versions: H3VersionBinding::new(
                "sdd-herness-integration",
                1,
                1,
                "sdd-html-policy-v1",
                digest("native-lifecycle-policy"),
                1,
                digest("native-lifecycle-pack"),
                "sdd-html-host-api",
                1,
            )
            .expect("versions"),
            limits: H3ApprovalLimits::default(),
            auto_publish: false,
            retain_history: true,
            automatic_companion: true,
            owner: H3OwnerBinding::new(
                project,
                OwnerRef::new(OwnerKind::H3HtmlJob, "native-lifecycle-h3").expect("owner"),
                "native-lifecycle-h3",
                ConditionVersion::new(1).expect("condition version"),
                ConditionDigest::sha256(b"native-lifecycle-conditions"),
                ExecutionScope::new(
                    project,
                    vec![PLAN.to_owned(), SPEC.to_owned()],
                    vec!["private/html-sync/candidates".to_owned()],
                    false,
                )
                .expect("scope"),
                1,
                BudgetPolicy::h2_default(),
            )
            .expect("owner binding"),
        },
        H3Approver::Human,
        now(),
    )
    .expect("approval");
    let settings = H3Settings::approved(approval, true).expect("settings");
    let mut handle = store.clone();
    handle
        .commit_html_sync(
            HtmlSyncCommit::new().with_settings(
                SettingsCommit::new(None, settings.clone()).expect("settings commit"),
            ),
        )
        .expect("settings");
    settings
}

fn fingerprints(settings: &H3Settings, root: &Path) -> FingerprintSet {
    let css = std::fs::read(root.join(CSS)).expect("css");
    FingerprintSet::new(
        settings.fingerprint().clone(),
        settings
            .approval()
            .expect("approved")
            .versions()
            .policy_fingerprint()
            .clone(),
        dependency_fingerprint(
            herness_html_sync::observer::DependencyKind::Css,
            [(CSS, ContentDigest::sha256(&css))],
        ),
        dependency_fingerprint(
            herness_html_sync::observer::DependencyKind::Resource,
            std::iter::empty(),
        ),
        None,
        None,
        None,
    )
}

fn seed_synced(
    store: &StoreHandle,
    project: ProjectId,
    settings: &H3Settings,
    root: &Path,
    relative: &str,
) {
    let companion = relative.replace(".md", ".html");
    std::fs::write(
        root.join(&companion),
        format!(
            "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>{relative}</title></head><body><main id=\"content\">{relative}</main></body></html>\n"
        ),
    )
    .expect("companion");
    let document = DocumentKey::new(project, relative.to_owned()).expect("document");
    let source = SourceSnapshot::new(
        SourceRevision::new(1).expect("revision"),
        ContentDigest::sha256(&std::fs::read(root.join(relative)).expect("source")),
    );
    let generation = herness_html_sync::GenerationId::new(project);
    let candidate =
        ContentDigest::sha256(&std::fs::read(root.join(&companion)).expect("companion"));
    let state = H3DocumentState::new(
        document.clone(),
        settings.version(),
        None,
        None,
        Some(generation),
        source.clone(),
        fingerprints(settings, root).with_candidate(candidate.clone()),
        H3Reason::new(
            H3StateReasonKind::Synced {
                generation,
                source_revision: 1,
                source_digest: source.digest().clone(),
            },
            Vec::new(),
        )
        .expect("synced reason"),
        None,
        Vec::new(),
        Applicability::current_synced(),
        now(),
    )
    .expect("synced state");
    let event = document_state_event(&document, None, &state, now()).expect("event");
    // A Synced document must also carry a published journal; otherwise the real
    // H3 startup reconciliation marks it `waiting_human` for a missing
    // publication and the H4 barrier refuses the restart.
    let publication = herness_html_sync::PublicationJournal::new(
        herness_html_sync::PublicationId::from_parts(project, Uuid::new_v4()),
        document.clone(),
        generation,
        herness_html_sync::CandidateId::from_parts(project, Uuid::new_v4()),
        herness_core::contracts::publication::PublicationRequestId::new(format!(
            "native-lifecycle-html-{relative}"
        ))
        .expect("publication request id"),
        herness_core::contracts::publication::ExpectedTargetVersion::absent(),
        candidate.clone(),
        digest("native-lifecycle-provenance"),
        source,
        now(),
    )
    .expect("publication")
    .replacing(now())
    .expect("replacing")
    .published(candidate, now())
    .expect("published")
    .with_final_project_sequence(1);
    let mut handle = store.clone();
    handle
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(None, state).expect("document commit"))
                .with_publication(publication)
                .with_events(vec![event]),
        )
        .expect("document");
}

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

/// Seeds one dispatched Task whose child and H2 target already completed.
pub fn seed() -> Seeded {
    let data = tempfile::tempdir().expect("app data");
    let project_dir = tempfile::tempdir().expect("project root");
    let root = std::fs::canonicalize(project_dir.path())
        .expect("canonical project")
        .join("checkout");
    std::fs::create_dir_all(root.join("docs/sdd/plans")).expect("plans");
    std::fs::create_dir_all(root.join("docs/sdd/specs")).expect("specs");
    std::fs::create_dir_all(root.join("docs/sdd/assets")).expect("assets");
    std::fs::create_dir_all(root.join("src")).expect("src");
    std::fs::write(root.join(CSS), "body { color: #111; }\n").expect("css");
    std::fs::write(root.join(PLAN), PLAN_BYTES).expect("plan");
    std::fs::write(root.join(SPEC), SPEC_BYTES).expect("spec");
    std::fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n").expect("source");
    std::fs::write(root.join("README.md"), "native lifecycle fixture\n").expect("readme");
    run_git(&root, &["init", "-q", "-b", BRANCH]);
    run_git(&root, &["config", "user.name", "Host Test"]);
    run_git(&root, &["config", "user.email", "host@example.invalid"]);
    run_git(&root, &["config", "core.hooksPath", ".git/hooks"]);
    run_git(&root, &["add", "--", "."]);
    run_git(&root, &["commit", "-q", "-m", "fixture baseline"]);

    let agent_connection = ConnectionId::new();
    let settings = ConnectionSettings::new(
        agent_connection,
        Provider::OpenAi,
        AGENT_MODEL,
        AuthMethod::ApiKey,
        None::<Endpoint>,
        None,
    )
    .expect("agent settings");
    let admin = ConnectionAdmin::new();
    admin.add(settings).expect("agent connection");
    let credentials: Arc<dyn CredentialPort + Send + Sync> = Arc::new(FakeCredentials);

    let agent = Loopback::start(vec![
        responses_write(TASK_ONE, "task one\n"),
        responses_text("task one done"),
    ]);
    let endpoints =
        ProviderEndpoints::for_loopback(agent.openai_base(), agent.url()).expect("endpoints");
    let (mut host, _) = DesktopHost::open_with_sdd_test_boundaries(
        data.path(),
        admin,
        credentials,
        endpoints,
        Some(PathBuf::from(PACK_ROOT)),
        None,
        None,
        None,
    )
    .expect("seeding host");
    let project = host.open_project(&root).expect("project").project_id();
    // Persist the non-secret connection so the native restart restores it
    // without any request.
    host.persist_connection_settings()
        .expect("persist connection");
    let store = host.store_handle();
    let h3_settings = seed_settings(&store, project);
    configure_policy(&mut host, &root);
    seed_synced(&store, project, &h3_settings, &root, PLAN);
    seed_synced(&store, project, &h3_settings, &root, SPEC);
    // The seeded companions are real tracked files; the approved checkout must
    // be clean before the start.
    run_git(&root, &["add", "--", "."]);
    run_git(&root, &["commit", "-q", "-m", "fixture H3 companions"]);
    let baseline = head(&root);

    configure_completion(&mut host, project);
    let execution = ExecutionId::from_parts(project, Uuid::new_v4());
    start(&mut host, project, execution, h3_settings.version(), &root);

    // One H4 pass dispatches the Task and installs the pre-Task barrier. No
    // second H4 pass runs before the child completes, so the host commit is
    // left to the native process under test.
    host.pump_sdd_execute();
    let task = {
        let guard = store.lock();
        let stored = guard
            .load_sdd_execution(project, execution)
            .expect("load")
            .expect("execution");
        stored.snapshot().tasks()[0].task()
    };
    let dispatch = herness_sdd_execute::dispatch_request_id(execution, task);
    let supervision = {
        let guard = store.lock();
        guard
            .sdd_task_reservation(project, execution, dispatch)
            .expect("reservation")
            .expect("dispatched")
            .supervision_id()
    };
    pump_h2_until_completed(&mut host, project, supervision);
    assert_eq!(
        std::fs::read_to_string(root.join(TASK_ONE)).expect("deliverable"),
        "task one\n"
    );
    assert!(
        agent.count() >= 2,
        "the child used the loopback Pi: {}",
        agent.count()
    );
    drop(host);
    drop(agent);
    Seeded {
        data,
        project_dir,
        root,
        project,
        execution,
        supervision,
        baseline,
    }
}

fn configure_completion(host: &mut DesktopHost, project: ProjectId) {
    let connection = host.connection_infos().expect("connections")[0].connection_id();
    host.supervision_configure_profile(
        PlanRequestActor::Human,
        project,
        ProfilePurpose::Completion,
        connection,
        AGENT_MODEL,
        Some(host.confirm_supervision(ConfirmationKind::Profile)),
    )
    .expect("completion profile");
    host.supervision_mark_profile_verified(project, ProfilePurpose::Completion, true)
        .expect("verified completion profile");
    host.supervision_grant_consent(
        PlanRequestActor::Human,
        project,
        ProfilePurpose::Completion,
        ProviderOrigin::parse("https://api.openai.com").expect("origin"),
        BTreeSet::from([DisclosureDataKind::Text, DisclosureDataKind::Code]),
        vec![
            TASK_ONE.to_owned(),
            "src".to_owned(),
            PLAN.to_owned(),
            SPEC.to_owned(),
        ],
        TargetVersion::new(1).expect("target version"),
        Some(host.confirm_supervision(ConfirmationKind::Consent)),
    )
    .expect("completion consent");
}

fn start(
    host: &mut DesktopHost,
    project: ProjectId,
    execution: ExecutionId,
    settings_version: u64,
    root: &Path,
) {
    let controller = SddTaskController::evaluate(host, Some(project), true);
    let preview = controller
        .preview(
            host,
            &SddPreviewRequest {
                project_id: project,
                plan_path: PLAN.to_owned(),
            },
        )
        .expect("preview");
    assert_eq!(preview.tasks().len(), 1);
    let connection = host.connection_infos().expect("connections")[0].connection_id();
    let request = SddApproveStartRequest {
        project_id: project,
        execution_id: execution,
        approval_id: ApprovalId::from_parts(project, Uuid::new_v4()),
        request_id: ControlRequestId::from_parts(project, Uuid::new_v4()),
        expected_approval_revision: 1,
        plan_path: PLAN.to_owned(),
        checkout_root: root.to_string_lossy().into_owned(),
        branch: BRANCH.to_owned(),
        base_branch: BRANCH.to_owned(),
        isolated_worktree: false,
        connection,
        h3_settings_version: settings_version,
        h3_capabilities: vec!["html-sync".to_owned()],
        h3_consent_ids: Vec::new(),
        task_limits: vec![SddTaskLimitRequest {
            number: 1,
            active_seconds: 300,
            additional_runs: 5,
            money_limit_micros: None,
            price_version: None,
        }],
        git_name: "Host Test".to_owned(),
        git_email: "host@example.invalid".to_owned(),
    };
    let confirmation = host.confirm_supervision(ConfirmationKind::Start);
    let started = controller
        .approve_and_start(host, &request, Some(&confirmation))
        .expect("approve and start");
    assert!(!started.child_started(), "the start creates no child");
}

fn pump_h2_until_completed(host: &mut DesktopHost, project: ProjectId, supervision: SupervisionId) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // The H1 runtime pump drives the child's engine events and tool calls.
        // Only the H4 pass is withheld so the native process under test owns the
        // barrier and host commit.
        host.runtime_mut().pump().expect("H1 pump");
        let store = host.store_handle();
        let (runtime, supervision_host) = host.runtime_and_supervision_mut();
        let plans = supervision_host.plans();
        let mut adapter = DesktopH1::new(runtime, store, plans);
        supervision_host
            .pump_scoped(
                &mut adapter,
                PumpScope::for_active_candidate([project], None),
            )
            .expect("H2 pump");
        let view = host.supervision().get(project, supervision).expect("view");
        if view.state == "completed" {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the child never completed: state={:?}",
            view.state
        );
        thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// Plan and spec bytes
// ---------------------------------------------------------------------------

const SPEC_BYTES: &str = r#"# H4 native lifecycle fixture

**Classification:** architectural

## Contract

One approved Task writes one deliverable and reaches one host commit.
"#;

const PLAN_BYTES: &str = r#"# H4 native lifecycle implementation plan

**Goal:** Prove one approved Task commits from the app-lifetime pump.

**Architecture:** The child writes one file; the host runs the barrier and commit.

**Tech Stack:** Rust, Git

**Spec:** docs/sdd/specs/2026-11-15-h4-native-lifecycle-design.md

## Global Constraints

- Keep the approved scope exact.

```sdd-execution-v1
{
  "schema": "sdd-execution-plan",
  "version": 1,
  "specRefs": [
    {
      "source": "project",
      "path": "docs/sdd/specs/2026-11-15-h4-native-lifecycle-design.md",
      "sections": ["Contract"]
    }
  ],
  "tasks": [
    {
      "number": 1,
      "dependsOn": [],
      "specRefs": [
        {
          "source": "project",
          "path": "docs/sdd/specs/2026-11-15-h4-native-lifecycle-design.md",
          "sections": ["Contract"]
        }
      ],
      "readPaths": ["src/lib.rs"],
      "writePaths": ["src/task-one.txt"],
      "allowShell": false,
      "deliverables": [{"path": "src/task-one.txt", "kind": "file"}],
      "conditions": [
        {
          "id": "one-produced",
          "title": "Task one produced its file",
          "rubric": "src/task-one.txt exists with the recorded content.",
          "mode": "checks"
        }
      ],
      "checks": [
        {
          "id": "one-check",
          "conditionId": "one-produced",
          "description": "The fixture check passes.",
          "command": "true",
          "cwd": ".",
          "timeoutSeconds": 30,
          "inputPaths": []
        }
      ],
      "htmlTargets": [],
      "commitPolicy": "required"
    }
  ],
  "finalChecks": ["one-check"]
}
```

## File structure

- `src/task-one.txt` — Task 1 output.

## Task 1: Write the file

Write `src/task-one.txt`.
"#;
