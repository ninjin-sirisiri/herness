//! Task 18 Html condition-assessment tests.
//!
//! Every provider request goes to a loopback mock. Credentials are synthetic and
//! no Keychain, real login, or external network request is used. Render evidence
//! is explicitly fake or native-shaped fixture data; the tests report that
//! distinction instead of claiming a real WKWebView run.

#![cfg(unix)]

mod support;

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use herness_assessment::AssessmentEndpoints;
use herness_core::{
    AuthMethod, ConnectionCapabilityDeclaration, ConnectionId, ConnectionSettings, CoreError,
    CredentialAvailability, CredentialKind, CredentialPort, EndpointClass, InputCapabilities,
    Provider, ResolvedCredential, SecretString, Timestamp,
};
use herness_desktop::host::DesktopHost;
use herness_desktop::html_sync::assessment::HtmlAssessmentHost;
use herness_desktop::supervision::assessment::{AssessmentHost, build_human_consent};
use herness_desktop::supervision::plan::{RequestActor, load_plan};
use herness_desktop::supervision::store::HostBudgetClock;
use herness_desktop::supervision::{
    ConditionInput, ConfirmationKind, CreateSupervisionRequest, PlanRequestActor,
};
use herness_engine_pi::ProviderEndpoints;
use herness_html_sync::{
    AppliedEvaluation, AssessmentPlan, ConditionBinding, EvidenceValidationError,
    H3_RUBRIC_VERSION, H3Condition, RubricSet,
};
use herness_supervision::conditions::ConditionDigest;
use herness_supervision::evidence::TargetVersion;
use herness_supervision::ids::ConditionId;
use herness_supervision::ids::ProfileId;
use herness_supervision::profiles::{
    AdapterVersion, AssessmentProfile, ProfileInputs, ProfilePurpose, ProfileThresholds,
    ProfileVersion, ProviderKind, RubricVersion,
};
use herness_supervision::{
    BudgetLedger, DisclosureDataKind, ProviderOrigin, SupervisionError, SupervisionId,
};
use serde_json::{Value, json};
use tempfile::TempDir;

use support::*;

// ---------------------------------------------------------------------------
// Loopback mock.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RecordedRequest {
    path: String,
    body: Vec<u8>,
}

impl RecordedRequest {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

struct MockServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    calls: Arc<AtomicUsize>,
}

impl MockServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(&RecordedRequest) -> Value + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::clone(&requests);
        let counter = Arc::clone(&calls);
        let handler = Arc::new(handler);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let recorded = Arc::clone(&recorded);
                let counter = Arc::clone(&counter);
                let handler = Arc::clone(&handler);
                thread::spawn(move || {
                    let mut stream = stream;
                    let Some(request) = read_request(&mut stream) else {
                        return;
                    };
                    let body = handler(&request);
                    counter.fetch_add(1, Ordering::SeqCst);
                    recorded.lock().expect("requests").push(request);
                    write_json(stream, &body);
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

fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]).to_ascii_lowercase();
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = buffer[header_end..].to_vec();
    let path = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    Some(RecordedRequest { path, body })
}

fn write_json(mut stream: TcpStream, body: &Value) {
    let bytes = serde_json::to_vec(body).expect("response JSON");
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
}

// ---------------------------------------------------------------------------
// Credentials.
// ---------------------------------------------------------------------------

struct FakeCredentials {
    resolved: AtomicUsize,
}

impl FakeCredentials {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            resolved: AtomicUsize::new(0),
        })
    }
}

impl CredentialPort for FakeCredentials {
    fn availability(
        &self,
        _connection: &ConnectionId,
    ) -> Result<CredentialAvailability, CoreError> {
        Ok(CredentialAvailability::Available)
    }

    fn resolve(&self, _connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        self.resolved.fetch_add(1, Ordering::SeqCst);
        Ok(ResolvedCredential::new(
            CredentialKind::ApiKey,
            SecretString::new("sk-h3-assessment-canary").expect("secret"),
        ))
    }
}

// ---------------------------------------------------------------------------
// Method harness.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    NormalLlm,
    NormalLlmInsufficient,
    NormalLlmUnmet,
    Jev,
    Decisions,
}

impl Method {
    const fn provider_kind(self) -> ProviderKind {
        match self {
            Self::NormalLlm | Self::NormalLlmInsufficient | Self::NormalLlmUnmet => {
                ProviderKind::NormalLlm
            }
            Self::Jev => ProviderKind::Jev,
            Self::Decisions => ProviderKind::Decisions,
        }
    }

    const fn model(self) -> &'static str {
        match self {
            Self::NormalLlm | Self::NormalLlmInsufficient | Self::NormalLlmUnmet => {
                "gpt-h3-assessment"
            }
            Self::Jev => "jev-1.14.0",
            Self::Decisions => "gpt-6-luna",
        }
    }
}

struct AssessmentHarness {
    _temp: TempDir,
    project: herness_core::ProjectId,
    host: DesktopHost,
    supervision: SupervisionId,
    conditions: ConditionBinding,
    condition_digest: ConditionDigest,
    profile: AssessmentProfile,
    method: Method,
    server: Arc<MockServer>,
}

impl AssessmentHarness {
    fn new(method: Method, image_profile: bool) -> Self {
        let temp = TempDir::new().expect("temp");
        let root = temp.path().join("project");
        std::fs::create_dir_all(root.join("docs/adr")).expect("adr dir");
        std::fs::create_dir_all(root.join("docs/sdd/assets")).expect("assets dir");
        let source = std::fs::read(
            std::path::Path::new(REAL_PACK_ROOT).join("tests/fixtures/adr/0001-queue-choice.md"),
        )
        .expect("source");
        let html = std::fs::read(
            std::path::Path::new(REAL_PACK_ROOT).join("tests/fixtures/adr/0001-queue-choice.html"),
        )
        .expect("html");
        std::fs::write(root.join(TARGET_PATH), &source).expect("write source");
        std::fs::write(root.join("docs/adr/0001-queue-choice.html"), &html).expect("write html");
        std::fs::write(
            root.join("docs/sdd/assets/sdd.css"),
            "body { color: #111; }\n",
        )
        .expect("css");

        let server = Arc::new(MockServer::start(move |request| match method {
            Method::NormalLlm => normal_llm_response(request),
            Method::NormalLlmInsufficient => normal_llm_verdict_response(request, "insufficient"),
            Method::NormalLlmUnmet => normal_llm_verdict_response(request, "unmet"),
            Method::Jev => jev_response(request),
            Method::Decisions => decisions_response(request),
        }));

        let connections = herness_core::ConnectionAdmin::new();
        let assessment_connection = ConnectionId::new();
        let completion_connection = ConnectionId::new();
        let capabilities = if image_profile {
            InputCapabilities::text_and_image()
        } else {
            InputCapabilities::text_only()
        };
        let (provider, endpoint_class) = match method {
            Method::NormalLlm | Method::NormalLlmInsufficient | Method::NormalLlmUnmet => {
                (Provider::OpenAi, EndpointClass::OpenAiResponses)
            }
            Method::Jev => (Provider::TypeSafe, EndpointClass::TypeSafeSystemOne),
            Method::Decisions => (Provider::OpenAi, EndpointClass::OpenAiDecisions),
        };
        connections
            .add(
                ConnectionSettings::new_with_capabilities(
                    assessment_connection,
                    provider,
                    method.model(),
                    AuthMethod::ApiKey,
                    None,
                    None,
                    ConnectionCapabilityDeclaration::new(endpoint_class, capabilities),
                )
                .expect("assessment connection"),
            )
            .expect("add assessment connection");
        connections
            .add(
                ConnectionSettings::new_with_capabilities(
                    completion_connection,
                    Provider::OpenAi,
                    "gpt-completion-fixture",
                    AuthMethod::ApiKey,
                    None,
                    None,
                    ConnectionCapabilityDeclaration::new(
                        EndpointClass::OpenAiResponses,
                        InputCapabilities::text_only(),
                    ),
                )
                .expect("completion connection"),
            )
            .expect("add completion connection");
        let credentials = FakeCredentials::new();
        let endpoints = ProviderEndpoints::for_loopback(server.url(), server.url())
            .expect("provider endpoints");
        let (mut host, _) = DesktopHost::open(
            temp.path().join("app-data"),
            connections,
            credentials.clone(),
            endpoints,
        )
        .expect("desktop host");
        host.open_project(&root).expect("open project");
        let project = host
            .runtime()
            .projects()
            .expect("projects")
            .into_iter()
            .next()
            .expect("project")
            .project_id();

        host.supervision_configure_profile(
            PlanRequestActor::Human,
            project,
            ProfilePurpose::Completion,
            completion_connection,
            "gpt-completion-fixture",
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
            vec![TARGET_PATH.to_owned()],
            TargetVersion::new(1).expect("target version"),
            Some(host.confirm_supervision(ConfirmationKind::Consent)),
        )
        .expect("completion consent");

        let html_profile = AssessmentProfile::new(
            ProfileId::new(project),
            ProfileVersion::new(1).expect("profile version"),
            ProfilePurpose::Html,
            method.provider_kind(),
            assessment_connection,
            herness_core::ModelId::new(method.model()).expect("model"),
            AdapterVersion::new("herness-h3-html-v1").expect("adapter"),
            RubricVersion::new(H3_RUBRIC_VERSION).expect("rubric"),
            if image_profile {
                ProfileInputs::text_with_optional_image()
            } else {
                ProfileInputs::text_only()
            },
            ProfileThresholds::for_provider(method.provider_kind()),
        )
        .expect("html profile");
        let mut config = host.supervision().config().get(project);
        config.set_profile(html_profile.clone(), true);
        let data_kinds = if image_profile {
            BTreeSet::from([DisclosureDataKind::Text, DisclosureDataKind::Image])
        } else {
            BTreeSet::from([DisclosureDataKind::Text])
        };
        let consent = build_human_consent(
            &RequestActor::Human,
            project,
            ProfilePurpose::Html,
            ProviderOrigin::parse(match method {
                Method::Jev => "https://api.typesafe.ai",
                Method::NormalLlm
                | Method::NormalLlmInsufficient
                | Method::NormalLlmUnmet
                | Method::Decisions => "https://api.openai.com",
            })
            .expect("origin"),
            data_kinds,
            vec![TARGET_PATH.to_owned()],
            TargetVersion::new(1).expect("target version"),
            Timestamp::now(),
        )
        .expect("html consent");
        config.set_consent(consent.clone());
        host.supervision().config().set(project, config);

        let created = host
            .supervision_create(
                PlanRequestActor::Human,
                CreateSupervisionRequest {
                    project,
                    connection: completion_connection,
                    instructions: "Assess the Html candidate against the approved conditions."
                        .to_owned(),
                    conditions: H3Condition::ALL
                        .into_iter()
                        .map(|condition| ConditionInput {
                            title: condition.as_str().to_owned(),
                            rubric: format!("H3 {} condition fixture rubric", condition.as_str()),
                            checks: Vec::new(),
                        })
                        .collect(),
                    read_set: vec![TARGET_PATH.to_owned()],
                    write_paths: Vec::new(),
                    allow_shell: false,
                    condition_version: Some(1),
                    target_version: Some(1),
                    budget: None,
                },
                Some(host.confirm_supervision(ConfirmationKind::Create)),
            )
            .expect("create H2 target");
        let view = host
            .supervision_get(project, created.supervision_id)
            .expect("target view");
        let condition_ids = view
            .conditions
            .iter()
            .map(|condition| {
                condition
                    .condition_id
                    .parse::<ConditionId>()
                    .expect("condition id")
            })
            .collect::<Vec<_>>();
        assert_eq!(condition_ids.len(), 4, "four H3 conditions");
        let conditions = ConditionBinding::new(
            project,
            [
                condition_ids[0],
                condition_ids[1],
                condition_ids[2],
                condition_ids[3],
            ],
        )
        .expect("condition binding");
        let store = host.store_handle();
        let plan = load_plan(&store, project, created.supervision_id)
            .expect("load plan")
            .expect("stored plan");
        let condition_digest = plan.conditions.digest().clone();
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

        Self {
            _temp: temp,
            project,
            host,
            supervision: created.supervision_id,
            conditions,
            condition_digest,
            profile: html_profile,
            method,
            server,
        }
    }

    fn pack(&self, fake_render: bool) -> herness_html_sync::EvidencePack {
        let fixture = AdrFixture::new();
        let bridge = connect_bridge(&fixture.root);
        let units = source_units(&bridge, &fixture);
        let render = if fake_render {
            if self.method == Method::Jev {
                fixture_fake_render_compact(&fixture)
            } else {
                fixture_fake_render(&fixture)
            }
        } else {
            fixture_native_render(&fixture)
        };
        let (structural, render_check) = if fake_render {
            pass_and_fake_checks()
        } else {
            pass_and_native_checks()
        };
        build_pack_with(
            &fixture,
            &units,
            render,
            structural,
            render_check,
            self.conditions.clone(),
            self.condition_digest.clone(),
            self.profile.binding(),
            self.project,
        )
        .expect("evidence pack")
    }

    fn assessment_host(&self) -> HtmlAssessmentHost {
        let endpoints = AssessmentEndpoints::for_loopback(
            self.server.url(),
            format!("{}/v1", self.server.url()),
            self.server.url(),
        )
        .expect("assessment endpoints");
        HtmlAssessmentHost::new(
            self.host.store_handle(),
            self.host.supervision().config(),
            AssessmentHost {
                directory: self.host.directory().clone(),
                credentials: self.host.credentials().clone(),
                endpoints,
            },
        )
    }

    fn assess(
        &self,
        pack: &herness_html_sync::EvidencePack,
        allow_fake: bool,
    ) -> Result<AppliedEvaluation, herness_html_sync::H3Error> {
        let mut host = self.assessment_host();
        let store = self.host.store_handle();
        let plan = load_plan(&store, self.project, self.supervision)
            .expect("load plan")
            .expect("plan");
        let target = plan.evidence_target.clone();
        let binding = herness_html_sync::EvaluationBinding::verification(
            pack.fingerprints().clone(),
            pack.fingerprints().clone(),
        );
        let before = pack.fingerprints().clone();
        let after = pack.fingerprints().clone();
        host.assess(
            pack,
            &RubricSet::approved(),
            self.profile.binding(),
            if self.profile.required_inputs().supports_image() {
                ProfileInputs::text_with_optional_image()
            } else {
                ProfileInputs::text_only()
            },
            self.supervision,
            &target,
            binding,
            before,
            &|| Ok(after.clone()),
            allow_fake,
            Timestamp::now(),
            1,
        )
    }

    fn set_html_consent(&self, kinds: BTreeSet<DisclosureDataKind>) {
        let mut config = self.host.supervision().config().get(self.project);
        let consent = build_human_consent(
            &RequestActor::Human,
            self.project,
            ProfilePurpose::Html,
            ProviderOrigin::parse(match self.method {
                Method::Jev => "https://api.typesafe.ai",
                Method::NormalLlm
                | Method::NormalLlmInsufficient
                | Method::NormalLlmUnmet
                | Method::Decisions => "https://api.openai.com",
            })
            .expect("origin"),
            kinds,
            vec![TARGET_PATH.to_owned()],
            TargetVersion::new(1).expect("target version"),
            Timestamp::now(),
        )
        .expect("consent");
        config.set_consent(consent);
        self.host.supervision().config().set(self.project, config);
    }

    fn revoke_html_consent(&self) {
        let mut config = self.host.supervision().config().get(self.project);
        if let Some(consent) = config.consent(ProfilePurpose::Html).cloned() {
            let revoked = consent
                .revoke(herness_supervision::ApprovalActor::Human, Timestamp::now())
                .expect("revoke");
            config.set_consent(revoked);
            self.host.supervision().config().set(self.project, config);
        }
    }

    fn plan(&self) -> AssessmentPlan {
        let pack = self.pack(true);
        AssessmentPlan::build(
            &pack,
            &RubricSet::approved(),
            self.profile.binding(),
            if self.profile.required_inputs().supports_image() {
                ProfileInputs::text_with_optional_image()
            } else {
                ProfileInputs::text_only()
            },
            ProfileThresholds::for_provider(self.profile.provider()),
            herness_html_sync::MAX_DEFAULT_SLICE_UNITS,
            herness_html_sync::MAX_DEFAULT_SLICE_BYTES,
        )
        .expect("plan")
    }
}

// ---------------------------------------------------------------------------
// Provider responses.
// ---------------------------------------------------------------------------

fn request_payload(body: &Value) -> Value {
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

fn normal_llm_response(request: &RecordedRequest) -> Value {
    let payload = request_payload(&request.json());
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
            "rationale": "The supplied evidence supports the condition.",
            "uncertainty": null,
        }]
    });
    json!({
        "id": "resp_h3_fixture",
        "object": "response",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text.to_string()}],
        }],
    })
}

fn normal_llm_verdict_response(request: &RecordedRequest, forced: &str) -> Value {
    let body = request.json();
    let payload = request_payload(&body);
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
    let rubric = payload.get("rubric").and_then(Value::as_str).unwrap_or("");
    let verdict = if rubric.contains("supplementary") {
        forced
    } else {
        "met"
    };
    let text = json!({
        "conditions": [{
            "conditionId": condition,
            "verdict": verdict,
            "evidenceIds": evidence,
            "rationale": "The fixture returns an explicit assessment verdict.",
            "uncertainty": null,
        }]
    });
    json!({
        "id": "resp_h3_fixture",
        "object": "response",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text.to_string()}],
        }],
    })
}

fn jev_response(request: &RecordedRequest) -> Value {
    let body = request.json();
    let question_id = body
        .get("questions")
        .and_then(Value::as_object)
        .and_then(|questions| questions.keys().next())
        .cloned()
        .unwrap_or_else(|| "unknown".to_owned());
    json!({
        "model": "jev-1.14.0",
        "answers": {
            question_id: {
                "type": "choice",
                "choice": "met",
                "confidence": 0.9,
                "probabilities": {"met": 0.99, "unmet": 0.005, "insufficient": 0.005},
            }
        },
        "usage": {"input_tokens": 12, "output_tokens": 6},
    })
}

fn decisions_response(request: &RecordedRequest) -> Value {
    let body = request.json();
    let question_id = body
        .get("questions")
        .and_then(Value::as_array)
        .and_then(|questions| questions.first())
        .and_then(|question| question.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    json!({
        "model": "gpt-6-luna",
        "answers": [{
            "type": "choice",
            "name": question_id,
            "choice": "met",
            "confidence": 0.9,
            "probabilities": [
                {"value": "met", "probability": 0.99},
                {"value": "unmet", "probability": 0.005},
                {"value": "insufficient", "probability": 0.005},
            ],
        }],
        "usage": {"input_tokens": 12, "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}, "output_tokens": 6},
    })
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[test]
fn normal_llm_assesses_all_four_conditions_with_exact_evidence() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlm, true);
    let pack = harness.pack(true);
    let evaluation = harness.assess(&pack, true).expect("assessment");
    assert_eq!(evaluation.conditions().len(), 4);
    for condition in H3Condition::ALL {
        let adoption = evaluation.condition(condition).expect("condition");
        assert!(adoption.met(), "{condition} should be met in the fixture");
        assert_eq!(adoption.parts_met(), adoption.parts_total());
    }
    assert!(evaluation.consistency().expect("consistency").met());
    assert!(evaluation.test_only(), "a fake render is distinguished");
    assert!(
        !evaluation.completion_ready(),
        "a fake render can never make completion ready"
    );
    assert_eq!(
        harness.server.count(),
        5,
        "four conditions plus consistency"
    );
    let bodies = harness.server.requests();
    assert!(bodies.iter().all(|request| {
        let body = request.json();
        let text = body.to_string();
        !text.contains("\"tools\"") && !text.contains("\"tool_choice\"")
    }));
    assert!(
        bodies
            .iter()
            .all(|request| request.path.contains("responses")),
        "normal LLM requests used the Responses route"
    );
    let information = harness.conditions.id(H3Condition::Information).to_string();
    let information_request = bodies
        .iter()
        .find(|request| {
            request_payload(&request.json())
                .get("conditionId")
                .and_then(Value::as_str)
                == Some(information.as_str())
        })
        .expect("information request");
    let payload = request_payload(&information_request.json());
    assert!(
        payload
            .get("evidence")
            .and_then(Value::as_array)
            .is_some_and(|evidence| evidence.iter().all(|item| item
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "text"))),
        "the information condition remains text-only"
    );
    let store = harness.host.store_handle();
    let evidence = herness_supervision::ports::EvidenceStorePort::list_for_supervision(
        &store,
        harness.project,
        harness.supervision,
    )
    .expect("evidence");
    assert!(!evidence.is_empty(), "exact evidence records were appended");
    assert!(
        evidence
            .iter()
            .all(|record| record.acquirer() == herness_supervision::EvidenceAcquirer::Ci)
    );
}

#[test]
fn jev_and_decisions_assess_all_four_conditions_with_loopback_mocks() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    for method in [Method::Jev, Method::Decisions] {
        let harness = AssessmentHarness::new(method, true);
        let pack = harness.pack(true);
        let evaluation = harness.assess(&pack, true).expect("assessment");
        for condition in H3Condition::ALL {
            assert!(
                evaluation.condition(condition).expect("condition").met(),
                "{method:?} {condition} should be met"
            );
        }
        assert!(evaluation.consistency().expect("consistency").met());
        assert_eq!(harness.server.count(), 5, "{method:?} request count");
        let expected_path = match method {
            Method::Jev => "systemone",
            Method::Decisions => "decisions",
            Method::NormalLlm | Method::NormalLlmInsufficient | Method::NormalLlmUnmet => {
                "responses"
            }
        };
        assert!(
            harness
                .server
                .requests()
                .iter()
                .all(|request| request.path.contains(expected_path)),
            "{method:?} used its own provider route"
        );
        assert!(evaluation.test_only());
        assert!(!evaluation.completion_ready());
    }
}

#[test]
fn structural_failure_blocks_assessment_before_any_send() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlm, true);
    let fixture = AdrFixture::new();
    let bridge = connect_bridge(&fixture.root);
    let units = source_units(&bridge, &fixture);
    let pack = build_pack_with(
        &fixture,
        &units,
        fixture_fake_render(&fixture),
        structural_check(herness_html_sync::EvidenceCheckResult::Fail),
        render_check(herness_html_sync::EvidenceOrigin::Fake),
        harness.conditions.clone(),
        harness.condition_digest.clone(),
        harness.profile.binding(),
        harness.project,
    )
    .expect("pack with a failed structural check");
    let error = harness
        .assess(&pack, true)
        .expect_err("structural failure must not be assessed");
    assert!(matches!(
        error,
        herness_html_sync::H3Error::Unavailable { .. }
    ));
    assert_eq!(harness.server.count(), 0);
}

#[test]
fn changed_code_link_number_and_hidden_content_are_denied_by_the_pack() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let original = AdrFixture::new();
    let variants = [
        (
            "omission",
            original
                .candidate_html()
                .replace(r#"{"unit": "paragraph-000016", "representation": "paraphrase", "targets": ["summary"]}, "#, ""),
        ),
        (
            "code",
            original.candidate_html().replace("FIFO", "LIFO"),
        ),
        (
            "link",
            original
                .candidate_html()
                .replace("../plans/2026-01-01-plan.md", "../plans/other.md"),
        ),
        (
            "number",
            original.candidate_html().replace("750 ms", "750 s"),
        ),
        (
            "hidden",
            original.candidate_html().replace(
                r#"<p id="summary">"#,
                r#"<div hidden><p id="summary">"#,
            ),
        ),
    ];
    for (label, html) in variants {
        let mut changed = AdrFixture::new();
        changed.html = if label == "hidden" {
            html.replace(
                "the limit is at most 2 MiB.</p>",
                "the limit is at most 2 MiB.</p></div>",
            )
            .into_bytes()
        } else {
            html.into_bytes()
        };
        let bridge = connect_bridge(&changed.root);
        let check = structural_policy(&bridge, &changed);
        assert_eq!(
            check.decision(),
            herness_desktop::html_sync::policy::CandidateDecision::Deny,
            "{label} must be denied by the common policy"
        );
        assert!(
            !check.violations().is_empty(),
            "{label} must report a violation"
        );
        assert!(!check.final_pass());
    }
}

#[test]
fn stale_met_is_never_applied() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlm, true);
    let pack = harness.pack(true);
    let evaluation = harness.assess(&pack, true).expect("assessment");
    assert!(
        evaluation
            .condition(H3Condition::Information)
            .expect("info")
            .met()
    );
    let fingerprints = pack.fingerprints().clone();
    let changed = herness_html_sync::EvidenceFingerprints::new(
        fingerprints.settings().clone(),
        fingerprints.policy().clone(),
        fingerprints.pack().clone(),
        fingerprints.css().clone(),
        fingerprints.resources().clone(),
        herness_supervision::ContentDigest::sha256(b"changed-candidate"),
        fingerprints.provenance().clone(),
        fingerprints.source().clone(),
        fingerprints.rubric().clone(),
        fingerprints.profile(),
        fingerprints.condition_version(),
        fingerprints.condition_digest().clone(),
        fingerprints.target_version(),
    );
    assert!(!evaluation.applies_to(&changed));
    let error = evaluation
        .current_or_stale(&changed)
        .expect_err("a changed candidate invalidates the met result");
    assert!(matches!(
        error,
        herness_html_sync::EvidenceValidationError::StaleEvidence { .. }
    ));
    assert!(!evaluation.completion_ready());
}

#[test]
fn missing_split_unit_is_rejected_by_the_plan_application() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlm, true);
    let plan = harness.plan();
    let binding = herness_html_sync::EvaluationBinding::verification(
        harness.pack(true).fingerprints().clone(),
        harness.pack(true).fingerprints().clone(),
    );
    let error = AppliedEvaluation::apply(&plan, Vec::new(), binding, true, Timestamp::now())
        .expect_err("a missing split unit must not be applied");
    assert!(matches!(
        error,
        EvidenceValidationError::MissingAssessment { .. }
    ));
}

#[test]
fn image_shortage_keeps_image_required_conditions_insufficient() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlm, false);
    let pack = harness.pack(true);
    let plan = harness.plan();
    assert!(plan.missing_images().contains(&H3Condition::Support));
    assert!(plan.missing_images().contains(&H3Condition::Usability));
    assert!(plan.missing_images().contains(&H3Condition::Render));
    let evaluation = harness.assess(&pack, true).expect("assessment");
    assert!(
        !evaluation
            .condition(H3Condition::Support)
            .expect("support")
            .met(),
        "text-only support must not be met"
    );
    assert!(!evaluation.completion_ready());
    assert_eq!(
        evaluation.disposition().state(),
        herness_html_sync::EvaluationDispositionState::WaitingHuman
    );
    assert_eq!(
        harness.server.count(),
        2,
        "only text conditions may be sent"
    );
}

#[test]
fn revoked_html_consent_blocks_the_send() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlm, true);
    let pack = harness.pack(true);
    harness.revoke_html_consent();
    let error = harness
        .assess(&pack, true)
        .expect_err("revoked consent must block the send");
    assert!(matches!(
        error,
        herness_html_sync::H3Error::Unavailable { .. }
    ));
    assert_eq!(harness.server.count(), 0);
}

#[test]
fn fake_and_native_shaped_render_are_distinguished() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlm, true);
    let fake = harness.pack(true);
    let fake_evaluation = harness.assess(&fake, true).expect("fake assessment");
    assert!(fake_evaluation.test_only());
    assert!(!fake_evaluation.completion_ready());
    let native = harness.pack(false);
    let native_evaluation = harness.assess(&native, true).expect("native assessment");
    assert!(!native_evaluation.test_only());
    assert!(
        native_evaluation.completion_ready(),
        "the native-shaped fixture exercises the completion path; it is not a real WKWebView claim"
    );
}

#[test]
fn a_stale_assessment_binding_is_waiting_human() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlm, true);
    let pack = harness.pack(true);
    let plan = harness.plan();
    let changed = herness_html_sync::EvidenceFingerprints::new(
        pack.fingerprints().settings().clone(),
        pack.fingerprints().policy().clone(),
        pack.fingerprints().pack().clone(),
        pack.fingerprints().css().clone(),
        pack.fingerprints().resources().clone(),
        herness_supervision::ContentDigest::sha256(b"changed"),
        pack.fingerprints().provenance().clone(),
        pack.fingerprints().source().clone(),
        pack.fingerprints().rubric().clone(),
        pack.fingerprints().profile(),
        pack.fingerprints().condition_version(),
        pack.fingerprints().condition_digest().clone(),
        pack.fingerprints().target_version(),
    );
    let positive = harness.assess(&pack, true).expect("positive assessment");
    let binding = herness_html_sync::EvaluationBinding::verification(
        pack.fingerprints().clone(),
        pack.fingerprints().clone(),
    )
    .with_assessment(pack.fingerprints().clone(), changed);
    let applied = AppliedEvaluation::apply(
        &plan,
        positive.slices().to_vec(),
        binding,
        true,
        Timestamp::now(),
    )
    .expect("apply with a stale assessment stage");
    assert!(!applied.completion_ready());
    assert_eq!(
        applied.disposition().state(),
        herness_html_sync::EvaluationDispositionState::WaitingHuman
    );
    assert_eq!(applied.disposition().stale_stage(), Some("assessment"));
}

#[test]
fn truncated_evidence_is_rejected_instead_of_shortened() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlm, true);
    let pack = harness.pack(true);
    let error = AssessmentPlan::build(
        &pack,
        &RubricSet::approved(),
        harness.profile.binding(),
        ProfileInputs::text_with_optional_image(),
        ProfileThresholds::for_provider(ProviderKind::NormalLlm),
        herness_html_sync::MAX_DEFAULT_SLICE_UNITS,
        10,
    )
    .expect_err("a slice over the text limit must not be shortened");
    assert!(matches!(error, EvidenceValidationError::Truncated { .. }));
    assert_eq!(harness.server.count(), 0);
}

#[test]
fn secret_excluded_content_is_rejected_before_send() {
    use std::sync::Arc;

    use herness_html_sync::{EvidenceContentSource, EvidenceDocumentContent};
    use herness_supervision::ids::EvidenceId;
    use herness_supervision::supervisor::ConditionAssessmentPort;
    use herness_supervision::{
        EvidenceAcquirer, EvidenceOutcome, EvidenceRecord, EvidenceScope, EvidenceStorePort,
        VerificationOperation,
    };

    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    struct SecretContent(EvidenceDocumentContent);
    impl EvidenceContentSource for SecretContent {
        fn document(
            &self,
            project_id: herness_core::ProjectId,
            evidence_id: EvidenceId,
        ) -> Result<Option<EvidenceDocumentContent>, SupervisionError> {
            if evidence_id == self.0.evidence_id() && project_id == evidence_id.project_id() {
                Ok(Some(self.0.clone()))
            } else {
                Ok(None)
            }
        }
    }

    let harness = AssessmentHarness::new(Method::NormalLlm, true);
    let plan = harness.plan();
    let condition = harness.conditions.id(H3Condition::Information);
    let evidence_id = EvidenceId::from_parts(
        harness.project,
        uuid::Uuid::parse_str("70000000-0000-4000-8000-000000000001").expect("uuid"),
    );
    let content = EvidenceDocumentContent::text(evidence_id, "secret-bearing evidence")
        .expect("content")
        .secret_excluded();
    let store = harness.host.store_handle();
    let target = load_plan(&store, harness.project, harness.supervision)
        .expect("plan")
        .expect("stored plan")
        .evidence_target;
    let mut writer = store.clone();
    writer
        .append(
            EvidenceRecord::new(
                evidence_id,
                harness.supervision,
                Some(condition),
                None,
                EvidenceAcquirer::Ci,
                VerificationOperation::equivalent("fixture evidence").expect("operation"),
                EvidenceOutcome::new(None, None, false, false, "excluded secret content")
                    .expect("outcome"),
                target.clone(),
                EvidenceScope::new(vec!["fixture".to_owned()], Vec::new()).expect("scope"),
                herness_supervision::CheckStatus::Pass,
                1,
                Timestamp::now(),
            )
            .expect("evidence"),
        )
        .expect("append");
    let request = herness_supervision::AssessmentRequest::new(
        herness_supervision::DecisionId::from_parts(
            harness.project,
            uuid::Uuid::parse_str("70000000-0000-4000-8000-000000000002").expect("uuid"),
        ),
        harness.supervision,
        condition,
        herness_supervision::ConditionVersion::new(1).expect("version"),
        herness_supervision::TargetVersion::new(1).expect("version"),
        plan.slices()[0].rubric(),
        harness.profile.binding(),
        harness.profile.adapter_version().clone(),
        harness.profile.rubric_version().clone(),
        vec![evidence_id],
    )
    .expect("request");
    let endpoints = herness_assessment::AssessmentEndpoints::for_loopback(
        harness.server.url(),
        format!("{}/v1", harness.server.url()),
        harness.server.url(),
    )
    .expect("endpoints");
    let mut port = herness_desktop::supervision::assessment::HostAssessmentPort::new(
        harness.host.store_handle(),
        harness.host.supervision().config(),
        AssessmentHost {
            directory: harness.host.directory().clone(),
            credentials: harness.host.credentials().clone(),
            endpoints,
        },
    )
    .with_evidence_content(Arc::new(SecretContent(content)));
    let error = port
        .assess(&request)
        .expect_err("secret exclusion must block");
    assert!(matches!(
        error,
        SupervisionError::EvidenceContractViolation { .. }
    ));
    assert_eq!(harness.server.count(), 0);
}

#[test]
fn missing_image_consent_blocks_image_evidence() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlm, true);
    let pack = harness.pack(true);
    harness.set_html_consent(BTreeSet::from([DisclosureDataKind::Text]));
    let error = harness
        .assess(&pack, true)
        .expect_err("image evidence requires image consent");
    assert!(matches!(
        error,
        herness_html_sync::H3Error::Unavailable { .. }
    ));
    assert_eq!(
        harness.server.count(),
        1,
        "only the text-only information condition may be sent"
    );
    let sent = request_payload(&harness.server.requests()[0].json());
    assert_eq!(
        sent.get("conditionId").and_then(Value::as_str),
        Some(
            harness
                .conditions
                .id(H3Condition::Information)
                .to_string()
                .as_str()
        ),
        "the sent request is the text-only information condition"
    );
}

#[test]
fn an_insufficient_condition_waits_for_a_human_not_a_child_retry() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlmInsufficient, true);
    let pack = harness.pack(true);
    let evaluation = harness.assess(&pack, true).expect("assessment");
    assert!(
        !evaluation
            .condition(H3Condition::Support)
            .expect("support")
            .met()
    );
    assert!(!evaluation.completion_ready());
    assert_eq!(
        evaluation.disposition().state(),
        herness_html_sync::EvaluationDispositionState::WaitingHuman
    );
    assert!(
        evaluation
            .disposition()
            .waiting_human_reasons()
            .iter()
            .any(|reason| reason.contains("support")),
        "insufficient condition is a human wait"
    );
    assert!(
        evaluation.disposition().fixable_conditions().is_empty(),
        "an insufficient result is not a fixable child retry"
    );
}

#[test]
fn a_fixable_unmet_returns_only_the_same_condition_to_the_child() {
    if !real_pack_present() {
        eprintln!("skip real pack assessment test: pack absent");
        return;
    }
    let harness = AssessmentHarness::new(Method::NormalLlmUnmet, true);
    let pack = harness.pack(false);
    let evaluation = harness.assess(&pack, true).expect("assessment");
    assert!(
        !evaluation
            .condition(H3Condition::Support)
            .expect("support")
            .met()
    );
    assert_eq!(
        evaluation.disposition().state(),
        herness_html_sync::EvaluationDispositionState::FixableUnmet
    );
    assert_eq!(
        evaluation.disposition().fixable_conditions(),
        &[H3Condition::Support],
        "only the unmet condition goes back to the same child"
    );
    assert!(evaluation.disposition().waiting_human_reasons().is_empty());
    assert!(!evaluation.completion_ready());
}
