//! Black-box tests that the four ports are object-safe and keep secrets out of
//! debug output.

use herness_core::*;

struct Fixture {
    project: ProjectId,
    agent: AgentId,
    session: SessionId,
    run: RunId,
    connection: ConnectionId,
}

impl Fixture {
    fn new() -> Self {
        let project = ProjectId::new();
        Self {
            project,
            agent: AgentId::new(project),
            session: SessionId::new(project),
            run: RunId::new(project),
            connection: ConnectionId::new(),
        }
    }

    fn operation(&self) -> FrozenOperation {
        let arguments = ToolArguments::Write(WriteArgs {
            path: NonEmptyText::new("notes.txt").unwrap(),
            content: "hello".to_owned(),
            rationale: Rationale::new("record the note").unwrap(),
        });
        FrozenOperation::new(
            OperationId::new(self.project),
            self.run,
            ToolName::Write,
            arguments,
            AbsolutePath::new("/tmp/herness-ports-test").unwrap(),
            PolicyVersion::INITIAL,
            PermissionMode::Configured,
        )
        .unwrap()
    }

    fn start(&self) -> EngineStart {
        EngineStart::new(
            self.project,
            self.agent,
            self.session,
            self.run,
            self.connection,
            AbsolutePath::new("/tmp/herness-ports-test").unwrap(),
            "Finish the task",
        )
        .unwrap()
    }

    fn draft(&self, kind: &str) -> EventDraft {
        EventDraft::new(
            self.project,
            self.agent,
            self.session,
            self.run,
            None,
            EventKind::new(kind).unwrap(),
            Timestamp::from_unix_millis(1_700_000_000_000),
            EventPayload::new(serde_json::json!({ "state": "running" })),
        )
        .unwrap()
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint::new(
            self.run,
            CheckpointFormatVersion::new(1).unwrap(),
            CheckpointPayload::new(vec![1, 2, 3]),
        )
    }
}

#[derive(Default)]
struct FakeEngine {
    started: Vec<EngineStart>,
    events: Vec<EngineEvent>,
    resumed: Option<Checkpoint>,
}

impl EnginePort for FakeEngine {
    fn start(&mut self, start: EngineStart) -> Result<(), CoreError> {
        self.started.push(start);
        Ok(())
    }

    fn send_input(&mut self, _run: &RunId, _input: EngineInput) -> Result<(), CoreError> {
        Ok(())
    }

    fn request_stop(&mut self, _run: &RunId, _reason: StopReason) -> Result<StopReport, CoreError> {
        Ok(StopReport::Stopped)
    }

    fn resume(&mut self, _run: &RunId, checkpoint: Checkpoint) -> Result<(), CoreError> {
        self.resumed = Some(checkpoint);
        Ok(())
    }

    fn checkpoint(&mut self, _run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        Ok(None)
    }

    fn poll_events(&mut self, _run: &RunId) -> Result<Vec<EngineEvent>, CoreError> {
        Ok(std::mem::take(&mut self.events))
    }
}

#[derive(Default)]
struct FakeStore {
    last: Option<CheckpointCommit>,
}

impl StorePort for FakeStore {
    fn commit_checkpoint(&mut self, commit: CheckpointCommit) -> Result<CommitReceipt, CoreError> {
        let events = commit
            .events()
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, draft)| draft.into_event(index as u64 + 1))
            .collect::<Result<Vec<_>, _>>()?;
        let max_sequence = events.last().map_or(0, Event::sequence);
        let run = commit.checkpoint().run_id();
        let checkpoint = commit.checkpoint().clone();
        self.last = Some(commit);
        assert_eq!(run, checkpoint.run_id());
        Ok(CommitReceipt::new(events, max_sequence))
    }

    fn load_checkpoint(&self, run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        Ok(self
            .last
            .as_ref()
            .map(|commit| commit.checkpoint().clone())
            .filter(|checkpoint| checkpoint.run_id() == *run))
    }

    fn history(&self, query: HistoryQuery) -> Result<HistoryPage, CoreError> {
        let _ = query;
        HistoryPage::new(Vec::new(), None)
    }

    fn pending_operations(&self, _project: &ProjectId) -> Result<Vec<OperationIntent>, CoreError> {
        Ok(Vec::new())
    }
}

struct FakeCredential {
    availability: CredentialAvailability,
    material: &'static str,
}

impl CredentialPort for FakeCredential {
    fn availability(
        &self,
        _connection: &ConnectionId,
    ) -> Result<CredentialAvailability, CoreError> {
        Ok(self.availability)
    }

    fn resolve(&self, _connection: &ConnectionId) -> Result<ResolvedCredential, CoreError> {
        Ok(ResolvedCredential::new(
            CredentialKind::ApiKey,
            SecretString::new(self.material)?,
        ))
    }
}

struct FakeEvaluator {
    availability: EvaluatorAvailability,
    decision: PermissionDecision,
}

impl PermissionEvaluatorPort for FakeEvaluator {
    fn availability(&self) -> EvaluatorAvailability {
        self.availability
    }

    fn evaluate(&mut self, _request: &EvaluationRequest) -> Result<PermissionDecision, CoreError> {
        Ok(self.decision)
    }
}

#[test]
fn ports_are_object_safe_and_usable_through_trait_objects() {
    let fixture = Fixture::new();

    let mut engine = FakeEngine {
        events: vec![EngineEvent::ToolCall {
            tool: ToolName::Read,
            arguments: ToolArguments::Read(ReadArgs {
                path: NonEmptyText::new("src/lib.rs").unwrap(),
                offset: None,
                limit: None,
            }),
        }],
        ..FakeEngine::default()
    };
    let engine: &mut dyn EnginePort = &mut engine;
    engine.start(fixture.start()).unwrap();
    engine
        .send_input(&fixture.run, EngineInput::Text("continue".to_owned()))
        .unwrap();
    assert_eq!(
        engine
            .request_stop(&fixture.run, StopReason::UserRequest)
            .unwrap(),
        StopReport::Stopped
    );
    let events = engine.poll_events(&fixture.run).unwrap();
    assert!(matches!(events.as_slice(), [EngineEvent::ToolCall { .. }]));

    let mut store = FakeStore::default();
    let store: &mut dyn StorePort = &mut store;
    let intent = OperationIntent::new(
        fixture.operation(),
        Timestamp::from_unix_millis(1_700_000_000_000),
    );
    let commit = CheckpointCommit::new(
        fixture.checkpoint(),
        Some(intent),
        vec![fixture.draft("operation.requested")],
    )
    .unwrap();
    let receipt = store.commit_checkpoint(commit).unwrap();
    assert_eq!(receipt.max_sequence(), 1);
    assert_eq!(receipt.events().len(), 1);
    assert_eq!(receipt.events()[0].sequence(), 1);
    assert_eq!(
        store.load_checkpoint(&fixture.run).unwrap(),
        Some(fixture.checkpoint())
    );
    assert_eq!(
        store
            .history(HistoryQuery::first(fixture.project))
            .unwrap()
            .events()
            .len(),
        0
    );
    assert!(
        store
            .pending_operations(&fixture.project)
            .unwrap()
            .is_empty()
    );

    let credential = FakeCredential {
        availability: CredentialAvailability::Available,
        material: "sk-test-canary-value",
    };
    let credential: &dyn CredentialPort = &credential;
    assert_eq!(
        credential.availability(&fixture.connection).unwrap(),
        CredentialAvailability::Available
    );
    let resolved = credential.resolve(&fixture.connection).unwrap();
    assert_eq!(resolved.expose_secret(), "sk-test-canary-value");
    assert!(!format!("{resolved:?}").contains("canary"));

    let mut evaluator = FakeEvaluator {
        availability: EvaluatorAvailability::Available,
        decision: PermissionDecision::Allow,
    };
    let evaluator: &mut dyn PermissionEvaluatorPort = &mut evaluator;
    assert_eq!(evaluator.availability(), EvaluatorAvailability::Available);
    let request = EvaluationRequest::new(
        fixture.operation(),
        "Finish the task",
        "trusted project root",
        vec!["the requested file".to_owned()],
    );
    assert_eq!(request.operation().project_id(), fixture.project);
    assert_eq!(
        evaluator.evaluate(&request).unwrap(),
        PermissionDecision::Allow
    );
}

#[test]
fn automatic_mode_requires_an_available_evaluator() {
    assert!(PermissionMode::Configured.is_usable_with(EvaluatorAvailability::Unavailable));
    assert!(!PermissionMode::Automatic.is_usable_with(EvaluatorAvailability::Unavailable));
    assert!(PermissionMode::Automatic.is_usable_with(EvaluatorAvailability::Available));
    assert!(PermissionMode::Automatic.requires_evaluator());
    assert!(!PermissionMode::Configured.requires_evaluator());
    assert_eq!(PermissionMode::default(), PermissionMode::Configured);
}

#[test]
fn engine_start_rejects_cross_project_ids() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let error = EngineStart::new(
        fixture.project,
        other.agent,
        fixture.session,
        fixture.run,
        fixture.connection,
        AbsolutePath::new("/tmp/herness-ports-test").unwrap(),
        "Finish the task",
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Agent,
            ..
        }
    ));
}

#[test]
fn checkpoint_commit_rejects_events_from_another_run() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let other_run = other.run;
    let draft = EventDraft::new(
        other.project,
        other.agent,
        other.session,
        other_run,
        None,
        EventKind::new("run.state_changed").unwrap(),
        Timestamp::from_unix_millis(1),
        EventPayload::new(serde_json::json!({ "state": "running" })),
    )
    .unwrap();
    let error = CheckpointCommit::new(fixture.checkpoint(), None, vec![draft]).unwrap_err();
    assert_eq!(
        error,
        CoreError::MismatchedRun {
            expected: fixture.run,
            found: other_run
        }
    );
}

#[test]
fn secret_values_are_redacted_and_runtime_errors_are_sanitized() {
    let secret = SecretString::new("sk-live-canary").unwrap();
    let debug = format!("{secret:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("canary"));

    let credential = ResolvedCredential::new(CredentialKind::OAuthToken, secret);
    let debug = format!("{credential:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("canary"));

    let error = CoreError::CredentialUnavailable {
        connection: ConnectionId::new(),
        failure: CredentialFailureKind::Expired,
    };
    let encoded = serde_json::to_string(&error).unwrap();
    assert!(!encoded.contains("canary"));
    assert!(encoded.contains("expired"));
}
