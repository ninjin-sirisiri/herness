//! Black-box tests for the public `herness-core` contract values.

use std::collections::BTreeSet;

use herness_core::*;
use serde_json::json;

struct Fixture {
    project: ProjectId,
    agent: AgentId,
    session: SessionId,
    run: RunId,
}

impl Fixture {
    fn new() -> Self {
        let project = ProjectId::new();
        Self {
            project,
            agent: AgentId::new(project),
            session: SessionId::new(project),
            run: RunId::new(project),
        }
    }

    fn operation(&self) -> OperationId {
        OperationId::new(self.project)
    }

    fn input(&self) -> InputId {
        InputId::new(self.project)
    }

    fn request(&self) -> RequestId {
        RequestId::new(self.project)
    }

    fn attempt(&self) -> AttemptId {
        AttemptId::new(self.project)
    }

    fn activity(&self) -> HostActivityId {
        HostActivityId::new(self.project)
    }

    fn run_subject(&self) -> RunSubject {
        RunSubject::new(self.project, self.agent, self.session, self.run).unwrap()
    }

    fn draft(&self, kind: &str, payload: serde_json::Value) -> EventDraft {
        EventDraft::new(
            self.project,
            self.agent,
            self.session,
            self.run,
            None,
            EventKind::new(kind).unwrap(),
            Timestamp::from_unix_millis(1_700_000_000_000),
            EventPayload::new(payload),
        )
        .unwrap()
    }

    fn event(&self) -> Event {
        self.draft("run.state_changed", json!({ "state": "idle" }))
            .into_event(7)
            .unwrap()
    }

    fn cwd(&self) -> AbsolutePath {
        AbsolutePath::new("/tmp/herness-contract-test").unwrap()
    }

    fn write_operation(&self, rationale: &str) -> FrozenOperation {
        let arguments = ToolArguments::Write(WriteArgs {
            path: NonEmptyText::new("src/main.rs").unwrap(),
            content: "fn main() {}".to_owned(),
            rationale: Rationale::new(rationale).unwrap(),
        });
        FrozenOperation::new(
            self.operation(),
            self.run,
            ToolName::Write,
            arguments,
            self.cwd(),
            PolicyVersion::INITIAL,
            PermissionMode::Configured,
        )
        .unwrap()
    }
}

#[test]
fn contract_version_writes_two_and_reads_one_and_two() {
    assert_eq!(CONTRACT_VERSION, 2);
    assert_eq!(OLDEST_READABLE_CONTRACT_VERSION, 1);
    assert_eq!(ContractVersion::CURRENT.get(), 2);
    assert_eq!(ContractVersion::try_from(1), Ok(ContractVersion::V1));
    assert_eq!(ContractVersion::try_from(2), Ok(ContractVersion::CURRENT));
    assert_eq!(
        ContractVersion::READABLE,
        [ContractVersion::V1, ContractVersion::V2]
    );
    assert!(ContractVersion::V1.is_readable());
    assert!(ContractVersion::V2.is_readable());
    assert_eq!(
        ContractVersion::try_from(3),
        Err(CoreError::UnknownContractVersion {
            found: 3,
            expected: 2
        })
    );
    assert_eq!(
        ContractVersion::try_from(0),
        Err(CoreError::UnknownContractVersion {
            found: 0,
            expected: 2
        })
    );
    assert_eq!("1".parse::<ContractVersion>(), Ok(ContractVersion::V1));
    assert_eq!("2".parse::<ContractVersion>(), Ok(ContractVersion::CURRENT));
    assert!(matches!(
        "3".parse::<ContractVersion>(),
        Err(CoreError::UnknownContractVersion { found: 3, .. })
    ));
    assert!(matches!(
        "not-a-version".parse::<ContractVersion>(),
        Err(CoreError::InvalidContractVersion { .. })
    ));
    assert_eq!(
        serde_json::from_str::<ContractVersion>("1").unwrap(),
        ContractVersion::V1
    );
    assert!(serde_json::from_str::<ContractVersion>("3").is_err());
}

#[test]
fn event_roundtrip_is_camel_case_and_rejects_unknown_version() {
    let fixture = Fixture::new();
    let event = fixture.event();
    let value = serde_json::to_value(&event).unwrap();

    let keys: BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "contractVersion",
            "projectId",
            "subject",
            "operationId",
            "sequence",
            "kind",
            "occurredAt",
            "payload",
        ])
    );
    assert_eq!(value["contractVersion"], 2);
    assert_eq!(value["sequence"], 7);
    assert_eq!(value["subject"]["type"], "run");
    assert_eq!(value["subject"]["projectId"], fixture.project.to_string());
    assert_eq!(value["subject"]["agentId"], fixture.agent.to_string());
    assert_eq!(value["subject"]["sessionId"], fixture.session.to_string());
    assert_eq!(value["subject"]["runId"], fixture.run.to_string());

    let decoded: Event = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(decoded, event);
    assert_eq!(decoded.contract_version(), ContractVersion::CURRENT);
    assert_eq!(decoded.sequence(), 7);
    assert_eq!(decoded.kind().as_str(), "run.state_changed");
    assert_eq!(decoded.run_id(), Some(fixture.run));

    let mut future = value;
    future["contractVersion"] = json!(3);
    let error = serde_json::from_value::<Event>(future).unwrap_err();
    assert!(
        error.to_string().contains("unsupported contract version 3"),
        "unexpected error: {error}"
    );
}

#[test]
fn version_1_event_decodes_as_a_run_subject_and_round_trips() {
    let fixture = Fixture::new();
    let operation = fixture.operation();
    let version_1 = json!({
        "contractVersion": 1,
        "projectId": fixture.project.to_string(),
        "agentId": fixture.agent.to_string(),
        "sessionId": fixture.session.to_string(),
        "runId": fixture.run.to_string(),
        "operationId": operation.to_string(),
        "sequence": 9,
        "kind": "run.state_changed",
        "occurredAt": 1_700_000_000_000u64,
        "payload": { "state": "idle" },
    });

    let decoded: Event = serde_json::from_value(version_1).unwrap();
    assert_eq!(decoded.contract_version(), ContractVersion::V1);
    assert_eq!(decoded.project_id(), fixture.project);
    assert_eq!(decoded.agent_id(), Some(fixture.agent));
    assert_eq!(decoded.session_id(), Some(fixture.session));
    assert_eq!(decoded.run_id(), Some(fixture.run));
    assert_eq!(decoded.operation_id(), Some(operation));
    assert_eq!(decoded.sequence(), 9);
    assert_eq!(decoded.kind().as_str(), "run.state_changed");
    assert_eq!(decoded.payload().as_value(), &json!({ "state": "idle" }));

    let direct = Event::from_v1(
        fixture.project,
        fixture.agent,
        fixture.session,
        fixture.run,
        Some(operation),
        9,
        EventKind::new("run.state_changed").unwrap(),
        Timestamp::from_unix_millis(1_700_000_000_000),
        EventPayload::new(json!({ "state": "idle" })),
    )
    .unwrap();
    assert_eq!(direct, decoded);

    let encoded = serde_json::to_value(&decoded).unwrap();
    assert_eq!(encoded["contractVersion"], 1);
    assert_eq!(encoded["projectId"], fixture.project.to_string());
    assert_eq!(encoded["agentId"], fixture.agent.to_string());
    assert_eq!(encoded["sessionId"], fixture.session.to_string());
    assert_eq!(encoded["runId"], fixture.run.to_string());
    assert_eq!(encoded["operationId"], operation.to_string());
    assert_eq!(encoded["sequence"], 9);
    assert!(
        encoded.get("subject").is_none(),
        "version 1 must not gain a version 2 subject"
    );
    let round_tripped: Event = serde_json::from_value(encoded).unwrap();
    assert_eq!(round_tripped, decoded);
}

#[test]
fn event_subjects_reject_mixing_and_cross_project_operations() {
    let fixture = Fixture::new();
    let other = Fixture::new();

    let mut mixed = serde_json::to_value(fixture.event()).unwrap();
    mixed["runId"] = json!(fixture.run.to_string());
    let error = serde_json::from_value::<Event>(mixed).unwrap_err();
    assert!(
        error.to_string().contains("must use subject"),
        "unexpected error: {error}"
    );

    let mut version_1_with_subject = json!({
        "contractVersion": 1,
        "projectId": fixture.project.to_string(),
        "agentId": fixture.agent.to_string(),
        "sessionId": fixture.session.to_string(),
        "runId": fixture.run.to_string(),
        "sequence": 1,
        "kind": "run.started",
        "occurredAt": 1u64,
        "payload": {},
        "subject": {
            "type": "run",
            "projectId": fixture.project.to_string(),
            "agentId": fixture.agent.to_string(),
            "sessionId": fixture.session.to_string(),
            "runId": fixture.run.to_string(),
        },
    });
    let error = serde_json::from_value::<Event>(version_1_with_subject.clone()).unwrap_err();
    assert!(
        error.to_string().contains("do not carry a subject"),
        "unexpected error: {error}"
    );

    version_1_with_subject["contractVersion"] = json!(2);
    let error = serde_json::from_value::<Event>(version_1_with_subject).unwrap_err();
    assert!(
        error.to_string().contains("must use subject"),
        "unexpected error: {error}"
    );

    let cross_project_operation = EventDraft::new(
        fixture.project,
        fixture.agent,
        fixture.session,
        fixture.run,
        Some(other.operation()),
        EventKind::new("operation.requested").unwrap(),
        Timestamp::from_unix_millis(1),
        EventPayload::new(json!({})),
    )
    .unwrap_err();
    assert!(matches!(
        cross_project_operation,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Operation,
            ..
        }
    ));

    let cross_project_subject = Event::new(
        EventSubject::Run(fixture.run_subject()),
        Some(other.operation()),
        1,
        EventKind::new("operation.requested").unwrap(),
        Timestamp::from_unix_millis(1),
        EventPayload::new(json!({})),
    )
    .unwrap_err();
    assert!(matches!(
        cross_project_subject,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Operation,
            ..
        }
    ));
}

#[test]
fn host_activity_subject_is_project_bound_and_has_no_run_or_operation() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let activity_id = fixture.activity();
    let activity = EventDraft::for_host_activity(
        fixture.project,
        EventKind::new("supervision").unwrap(),
        activity_id,
        EventKind::new("supervision.created").unwrap(),
        Timestamp::from_unix_millis(1_700_000_000_000),
        EventPayload::new(json!({ "revision": 1 })),
    )
    .unwrap();
    assert_eq!(activity.project_id(), fixture.project);
    assert_eq!(activity.run_id(), None);
    assert_eq!(activity.agent_id(), None);
    assert_eq!(activity.session_id(), None);
    assert_eq!(activity.operation_id(), None);

    let event = activity.into_event(11).unwrap();
    assert_eq!(event.contract_version(), ContractVersion::CURRENT);
    assert_eq!(event.project_id(), fixture.project);
    let EventSubject::HostActivity(subject) = event.subject() else {
        panic!("expected a host activity subject");
    };
    assert_eq!(subject.project_id(), fixture.project);
    assert_eq!(subject.activity_kind().as_str(), "supervision");
    assert_eq!(subject.activity_id(), activity_id);

    let value = serde_json::to_value(&event).unwrap();
    assert_eq!(value["contractVersion"], 2);
    assert_eq!(value["subject"]["type"], "hostActivity");
    assert_eq!(value["subject"]["activityKind"], "supervision");
    assert_eq!(value["subject"]["activityId"], activity_id.to_string());
    assert!(value["subject"].get("runId").is_none());
    assert!(value.get("agentId").is_none());
    assert_eq!(serde_json::from_value::<Event>(value).unwrap(), event);

    let cross_project = EventDraft::for_host_activity(
        fixture.project,
        EventKind::new("supervision").unwrap(),
        HostActivityId::new(other.project),
        EventKind::new("supervision.created").unwrap(),
        Timestamp::from_unix_millis(1),
        EventPayload::new(json!({})),
    )
    .unwrap_err();
    assert!(matches!(
        cross_project,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Activity,
            ..
        }
    ));

    let with_operation = Event::new(
        event.subject().clone(),
        Some(fixture.operation()),
        12,
        EventKind::new("supervision.created").unwrap(),
        Timestamp::from_unix_millis(1),
        EventPayload::new(json!({})),
    )
    .unwrap_err();
    assert!(matches!(
        with_operation,
        CoreError::InvalidEvent { field, .. } if field == "operationId"
    ));
}

#[test]
fn event_rejects_zero_sequence_and_cross_project_ids() {
    let fixture = Fixture::new();
    let error = fixture
        .draft("run.state_changed", json!({}))
        .into_event(0)
        .unwrap_err();
    assert_eq!(
        error,
        CoreError::InvalidEvent {
            field: "sequence".to_owned(),
            violation: ArgumentViolation::MustBePositive
        }
    );

    let other = Fixture::new();
    let agent_error = EventDraft::new(
        fixture.project,
        other.agent,
        fixture.session,
        fixture.run,
        None,
        EventKind::new("run.state_changed").unwrap(),
        Timestamp::from_unix_millis(1),
        EventPayload::new(json!({})),
    )
    .unwrap_err();
    assert!(matches!(
        agent_error,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Agent,
            ..
        }
    ));

    let operation_error = EventDraft::new(
        fixture.project,
        fixture.agent,
        fixture.session,
        fixture.run,
        Some(other.operation()),
        EventKind::new("operation.requested").unwrap(),
        Timestamp::from_unix_millis(1),
        EventPayload::new(json!({})),
    )
    .unwrap_err();
    assert!(matches!(
        operation_error,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Operation,
            ..
        }
    ));
}

#[test]
fn run_states_match_the_spec_and_idle_is_not_completion() {
    assert_eq!(RunState::ALL.len(), 6);
    let names: BTreeSet<_> = RunState::ALL.iter().map(|state| state.as_str()).collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "running",
            "awaiting_approval",
            "paused",
            "interrupted",
            "idle",
            "failed",
        ])
    );
    assert!(!names.contains("completed"));
    for state in RunState::ALL {
        assert_eq!(
            serde_json::to_value(state).unwrap(),
            serde_json::Value::String(state.as_str().to_owned())
        );
    }
    assert!(RunState::Idle.is_idle());
    assert!(!RunState::Idle.is_active());
    for state in RunState::ALL {
        if state != RunState::Idle {
            assert!(!state.is_idle());
        }
    }
}

#[test]
fn input_idle_evidence_separates_startup_idle_from_completed_input() {
    let fixture = Fixture::new();
    let input = fixture.input();
    assert_eq!(input.project_id(), fixture.project);

    let startup = IdleEvidence::startup();
    assert_eq!(startup, IdleEvidence::StartupIdle);
    assert!(!startup.is_input_completed());
    assert_eq!(startup.input_id(), None);
    assert!(RunState::Idle.is_idle(), "idle remains an engine fact");

    let accepted = InputProgress::new(input, InputPhase::Accepted);
    let started = InputProgress::new(input, InputPhase::Started);
    let completed = InputProgress::new(input, InputPhase::Completed);
    assert!(!accepted.is_completed());
    assert!(!started.is_completed());
    assert!(completed.is_completed());

    let accepted_idle = IdleEvidence::from_progress(accepted);
    let started_idle = IdleEvidence::from_progress(started);
    let completed_idle = IdleEvidence::from_progress(completed);
    assert!(!accepted_idle.is_input_completed());
    assert!(!started_idle.is_input_completed());
    assert!(completed_idle.is_input_completed());
    assert_eq!(completed_idle.input_id(), Some(input));
    assert_eq!(accepted_idle.input_id(), Some(input));

    let cancelled = IdleEvidence::from_progress(InputProgress::new(input, InputPhase::Cancelled));
    let failed = IdleEvidence::from_progress(InputProgress::new(input, InputPhase::Failed));
    assert!(!cancelled.is_input_completed());
    assert!(!failed.is_input_completed());

    let encoded = serde_json::to_value(completed_idle).unwrap();
    assert_eq!(encoded["kind"], "input_completed");
    assert_eq!(
        serde_json::from_value::<IdleEvidence>(encoded).unwrap(),
        completed_idle
    );
}

#[test]
fn continuation_request_requires_a_new_run_and_matching_project() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let input = fixture.input();
    let previous = fixture.run;
    let next = RunId::new(fixture.project);
    let policy = PolicyVersion::new(2).unwrap();
    let request = ContinuationRequest::new(
        fixture.project,
        input,
        previous,
        next,
        fixture.agent,
        fixture.session,
        PermissionMode::Automatic,
        policy,
    )
    .unwrap();
    assert_eq!(request.input_id(), input);
    assert_eq!(request.previous_run_id(), previous);
    assert_eq!(request.run_id(), next);
    assert_eq!(request.permission_mode(), PermissionMode::Automatic);
    assert_eq!(request.policy_version(), policy);

    let encoded = serde_json::to_value(request).unwrap();
    assert_eq!(encoded["inputId"], input.to_string());
    assert_eq!(
        serde_json::from_value::<ContinuationRequest>(encoded).unwrap(),
        request
    );

    let same_run = ContinuationRequest::new(
        fixture.project,
        input,
        previous,
        previous,
        fixture.agent,
        fixture.session,
        PermissionMode::Configured,
        PolicyVersion::INITIAL,
    )
    .unwrap_err();
    assert!(matches!(
        same_run,
        CoreError::InvalidValue { ref field, .. } if field == "runId"
    ));

    let cross_project = ContinuationRequest::new(
        fixture.project,
        InputId::new(other.project),
        previous,
        next,
        fixture.agent,
        fixture.session,
        PermissionMode::Configured,
        PolicyVersion::INITIAL,
    )
    .unwrap_err();
    assert!(matches!(
        cross_project,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Input,
            ..
        }
    ));
}

#[test]
fn token_usage_missing_is_unknown_and_never_zero() {
    let unknown = TokenUsage::unknown();
    assert_eq!(unknown.input_tokens(), TokenCount::Unknown);
    assert_eq!(unknown.output_tokens(), TokenCount::Unknown);
    assert_eq!(unknown.cache_read_tokens(), TokenCount::Unknown);
    assert_eq!(unknown.cache_write_tokens(), TokenCount::Unknown);
    assert_eq!(unknown.input_tokens().reported(), None);
    assert!(unknown.is_unknown());
    assert_eq!(TokenUsage::default(), unknown);

    let encoded = serde_json::to_value(unknown).unwrap();
    assert_eq!(encoded["inputTokens"], "unknown");
    assert_eq!(encoded["outputTokens"], "unknown");
    assert_eq!(
        serde_json::from_value::<TokenUsage>(encoded).unwrap(),
        unknown
    );

    let known_zero = TokenUsage::new(
        TokenCount::known(0),
        TokenCount::unknown(),
        TokenCount::unknown(),
        TokenCount::unknown(),
    );
    assert_eq!(known_zero.input_tokens().reported(), Some(0));
    assert!(!known_zero.is_unknown());

    let fixture = Fixture::new();
    let observation = ModelRequestObservation::new(
        fixture.request(),
        fixture.attempt(),
        RequestOutcome::Completed,
        None,
        Some(ModelId::new("gpt-6-luna").unwrap()),
        TokenUsage::unknown(),
    )
    .unwrap();
    assert!(observation.usage().is_unknown());
    let encoded = serde_json::to_value(&observation).unwrap();
    assert_eq!(encoded["usage"]["inputTokens"], "unknown");
    assert_eq!(encoded["modelId"], "gpt-6-luna");
    assert_eq!(
        serde_json::from_value::<ModelRequestObservation>(encoded).unwrap(),
        observation
    );

    let missing_failure = ModelRequestObservation::new(
        fixture.request(),
        fixture.attempt(),
        RequestOutcome::PreflightFailed,
        None,
        None,
        TokenUsage::unknown(),
    )
    .unwrap_err();
    assert!(matches!(
        missing_failure,
        CoreError::InvalidValue { ref field, .. } if field == "failure"
    ));

    let preflight_usage = ModelRequestObservation::new(
        fixture.request(),
        fixture.attempt(),
        RequestOutcome::PreflightFailed,
        Some(ProviderFailureKind::Network),
        None,
        TokenUsage::new(
            TokenCount::known(1),
            TokenCount::unknown(),
            TokenCount::unknown(),
            TokenCount::unknown(),
        ),
    )
    .unwrap_err();
    assert!(matches!(
        preflight_usage,
        CoreError::InvalidValue { ref field, .. } if field == "usage"
    ));
}

#[test]
fn request_gate_intent_is_project_bound_and_reports_stop_deadline() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let subject = EventSubject::Run(fixture.run_subject());
    let intent = RequestGateIntent::new(
        fixture.request(),
        fixture.attempt(),
        ConnectionId::new(),
        RequestPurpose::new("completion-assessment").unwrap(),
        subject,
        StopDeadlineControl::proceed(),
    )
    .unwrap();
    assert_eq!(intent.request_id().project_id(), fixture.project);
    assert_eq!(intent.attempt_id().project_id(), fixture.project);
    assert_eq!(intent.purpose().as_str(), "completion-assessment");
    assert!(intent.control().permits_send());
    assert!(!StopDeadlineControl::stopped(StopReason::Policy).permits_send());
    assert!(!StopDeadlineControl::deadline().permits_send());
    assert_eq!(
        StopDeadlineControl::stopped(StopReason::UserRequest).stop_reason(),
        Some(StopReason::UserRequest)
    );

    let cross_project = RequestGateIntent::new(
        fixture.request(),
        AttemptId::new(other.project),
        ConnectionId::new(),
        RequestPurpose::new("permission-evaluation").unwrap(),
        EventSubject::Run(fixture.run_subject()),
        StopDeadlineControl::proceed(),
    )
    .unwrap_err();
    assert!(matches!(
        cross_project,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Attempt,
            ..
        }
    ));

    assert!(RequestPurpose::new("  ").is_err());
    assert!(ModelId::new("  ").is_err());
}

#[test]
fn scoped_ids_detect_cross_project_references() {
    let first = Fixture::new();
    let second = Fixture::new();
    let operation = first.operation();

    assert_eq!(operation.project_id(), first.project);
    operation.validate_in(&first.project).unwrap();
    assert_eq!(
        operation.validate_in(&second.project),
        Err(CoreError::CrossProjectReference {
            id_kind: IdKind::Operation,
            expected: second.project,
            found: first.project,
        })
    );
    assert!(
        ProjectScope::new(second.project)
            .verify(&operation)
            .is_err()
    );

    let parsed: OperationId = operation.to_string().parse().unwrap();
    assert_eq!(parsed, operation);
    assert_eq!(parsed.project_id(), first.project);

    assert!(matches!(
        operation.to_string().parse::<RunId>(),
        Err(CoreError::InvalidId {
            id_kind: IdKind::Run,
            ..
        })
    ));
    assert!(matches!(
        "operation:not-a-project:not-a-local".parse::<OperationId>(),
        Err(CoreError::InvalidId {
            id_kind: IdKind::Operation,
            ..
        })
    ));
    assert!("not-a-project".parse::<ProjectId>().is_err());
}

#[test]
fn frozen_operation_rejects_cross_project_and_mismatched_tool() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let arguments = ToolArguments::Write(WriteArgs {
        path: NonEmptyText::new("a.txt").unwrap(),
        content: "content".to_owned(),
        rationale: Rationale::new("reason").unwrap(),
    });

    let cross_project = FrozenOperation::new(
        other.operation(),
        fixture.run,
        ToolName::Write,
        arguments.clone(),
        fixture.cwd(),
        PolicyVersion::INITIAL,
        PermissionMode::Configured,
    )
    .unwrap_err();
    assert!(matches!(
        cross_project,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Operation,
            ..
        }
    ));

    let mismatched = FrozenOperation::new(
        fixture.operation(),
        fixture.run,
        ToolName::Edit,
        arguments,
        fixture.cwd(),
        PolicyVersion::INITIAL,
        PermissionMode::Configured,
    )
    .unwrap_err();
    assert!(matches!(
        mismatched,
        CoreError::InvalidToolArgument {
            tool: ToolName::Edit,
            ..
        }
    ));
}

#[test]
fn frozen_operation_preserves_final_inputs_through_serde() {
    let fixture = Fixture::new();
    let operation = fixture.write_operation("  keep the build green  ");
    assert_eq!(operation.project_id(), fixture.project);
    assert_eq!(operation.run_id(), fixture.run);
    assert_eq!(operation.tool(), ToolName::Write);
    assert_eq!(operation.cwd().as_str(), "/tmp/herness-contract-test");
    assert_eq!(operation.policy_version(), PolicyVersion::INITIAL);
    assert_eq!(operation.permission_mode(), PermissionMode::Configured);
    assert_eq!(
        operation.arguments().tool_name(),
        ToolName::Write,
        "arguments must remain attached to the frozen tool"
    );

    let json = serde_json::to_value(&operation).unwrap();
    assert_eq!(json["policyVersion"], 1);
    assert_eq!(json["cwd"], "/tmp/herness-contract-test");
    let decoded: FrozenOperation = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, operation);

    assert!(matches!(
        PolicyVersion::new(0),
        Err(CoreError::InvalidPolicyVersion { value: 0 })
    ));
    assert_eq!(PolicyVersion::INITIAL.next(), PolicyVersion::new(2).ok());
}

#[test]
fn rationale_and_purpose_use_unicode_scalar_boundaries() {
    assert_eq!(MAX_REASON_SCALARS, 1_000);

    check_reason_boundaries(ReasonField::Rationale, |value| {
        Rationale::new(value).map(Rationale::into_string)
    });
    check_reason_boundaries(ReasonField::Purpose, |value| {
        Purpose::new(value).map(Purpose::into_string)
    });
}

fn check_reason_boundaries(field: ReasonField, make: impl Fn(&str) -> Result<String, CoreError>) {
    assert_eq!(
        make(""),
        Err(CoreError::InvalidReason {
            field,
            violation: ReasonViolation::Empty
        })
    );
    assert_eq!(
        make("  \t\n\u{3000}  "),
        Err(CoreError::InvalidReason {
            field,
            violation: ReasonViolation::Empty
        })
    );
    assert_eq!(make("a").unwrap(), "a");
    assert_eq!(make("  a  ").unwrap(), "a");

    let one_thousand = "a".repeat(1_000);
    assert_eq!(make(&one_thousand).unwrap().chars().count(), 1_000);
    assert_eq!(
        make(&"a".repeat(1_001)),
        Err(CoreError::InvalidReason {
            field,
            violation: ReasonViolation::TooLong {
                actual: 1_001,
                max: 1_000
            }
        })
    );

    let padded_boundary = format!("  {}  ", "x".repeat(1_000));
    assert_eq!(make(&padded_boundary).unwrap().chars().count(), 1_000);

    let non_ascii = "あ".repeat(1_000);
    assert_eq!(non_ascii.len(), 3_000, "UTF-8 byte length must not be used");
    assert_eq!(make(&non_ascii).unwrap(), non_ascii);
    assert_eq!(
        make(&"あ".repeat(1_001)),
        Err(CoreError::InvalidReason {
            field,
            violation: ReasonViolation::TooLong {
                actual: 1_001,
                max: 1_000
            }
        })
    );

    let astral = "😀".repeat(1_000);
    assert_eq!(
        astral.encode_utf16().count(),
        2_000,
        "UTF-16 code-unit length must not be used"
    );
    assert_eq!(make(&astral).unwrap(), astral);
    assert_eq!(
        make(&"😀".repeat(1_001)),
        Err(CoreError::InvalidReason {
            field,
            violation: ReasonViolation::TooLong {
                actual: 1_001,
                max: 1_000
            }
        })
    );
}

#[test]
fn tool_argument_schemas_reject_invalid_values() {
    assert!(
        serde_json::from_value::<ToolArguments>(
            json!({ "tool": "read", "arguments": { "path": "src/lib.rs", "offset": 0 } })
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<ToolArguments>(
            json!({ "tool": "search", "arguments": { "query": "needle", "maxResults": 0 } })
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<ToolArguments>(
            json!({ "tool": "bash", "arguments": { "command": "ls", "purpose": "inspect", "timeoutMs": 0 } })
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<ToolArguments>(
            json!({ "tool": "read", "arguments": { "path": "   " } })
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<ToolArguments>(
            json!({ "tool": "search", "arguments": { "query": "x", "unknown": true } })
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<WriteArgs>(
            json!({ "path": "a.txt", "content": "x", "rationale": "" })
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<BashArgs>(json!({ "command": "ls", "purpose": "  " })).is_err()
    );
    assert!(
        serde_json::from_value::<BashArgs>(
            json!({ "command": "ls", "purpose": "😀".repeat(1_001) })
        )
        .is_err()
    );

    let astral_boundary = "😀".repeat(1_000);
    let write = serde_json::from_value::<WriteArgs>(json!({
        "path": "a.txt",
        "content": "x",
        "rationale": astral_boundary,
    }))
    .unwrap();
    assert_eq!(write.rationale.as_str().chars().count(), 1_000);

    let arguments = ToolArguments::Write(write);
    let encoded = serde_json::to_value(&arguments).unwrap();
    assert_eq!(encoded["tool"], "write");
    assert_eq!(
        serde_json::from_value::<ToolArguments>(encoded).unwrap(),
        arguments
    );
}

#[test]
fn history_limits_are_default_100_and_max_500() {
    assert_eq!(DEFAULT_HISTORY_LIMIT, 100);
    assert_eq!(MAX_HISTORY_LIMIT, 500);
    assert_eq!(HistoryLimit::default().get(), 100);
    assert_eq!(HistoryLimit::new(500).unwrap().get(), 500);
    assert_eq!(
        HistoryLimit::new(0),
        Err(CoreError::InvalidHistoryLimit { value: 0, max: 500 })
    );
    assert_eq!(
        HistoryLimit::new(501),
        Err(CoreError::InvalidHistoryLimit {
            value: 501,
            max: 500
        })
    );

    let fixture = Fixture::new();
    let query = HistoryQuery::first(fixture.project);
    assert_eq!(query.limit().get(), 100);
    assert_eq!(query.cursor(), None);
    assert_eq!(query.before_sequence(), None);
    let encoded = serde_json::to_value(query).unwrap();
    assert_eq!(encoded["projectId"], fixture.project.to_string());
    assert_eq!(
        serde_json::from_value::<HistoryQuery>(encoded).unwrap(),
        query
    );

    let cursor = HistoryCursor::new(fixture.project, 7).unwrap();
    let query = HistoryQuery::new(fixture.project, Some(cursor), HistoryLimit::default()).unwrap();
    assert_eq!(query.before_sequence(), Some(7));
    let encoded = serde_json::to_value(query).unwrap();
    assert_eq!(encoded["cursor"]["beforeSequence"], 7);
    assert_eq!(
        serde_json::from_value::<HistoryQuery>(encoded).unwrap(),
        query
    );
    assert!(HistoryCursor::new(fixture.project, 0).is_err());
    assert!(HistoryQuery::new(fixture.project, Some(cursor), HistoryLimit::default()).is_ok());

    let other = Fixture::new();
    let cross_project =
        HistoryQuery::new(other.project, Some(cursor), HistoryLimit::default()).unwrap_err();
    assert!(matches!(
        cross_project,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Project,
            expected,
            found,
        } if expected == other.project && found == fixture.project
    ));

    let page = HistoryPage::new(vec![fixture.event()], Some(cursor)).unwrap();
    let encoded = serde_json::to_value(&page).unwrap();
    assert_eq!(
        encoded["nextCursor"]["projectId"],
        fixture.project.to_string()
    );
    assert_eq!(encoded["nextCursor"]["beforeSequence"], 7);
    assert_eq!(
        serde_json::from_value::<HistoryPage>(encoded).unwrap(),
        page
    );
    assert!(HistoryPage::new(Vec::new(), Some(cursor)).is_err());
    assert!(
        HistoryPage::new(
            vec![fixture.event()],
            Some(HistoryCursor::new(other.project, 7).unwrap())
        )
        .is_err()
    );
}

#[test]
fn connection_info_contains_no_secret_material() {
    let connection = ConnectionInfo::new(
        ConnectionId::new(),
        Provider::OpenAi,
        "  gpt-5  ",
        AuthMethod::ApiKey,
        ConnectionStatus::Available,
    )
    .unwrap();
    assert_eq!(connection.model(), "gpt-5");

    let value = serde_json::to_value(&connection).unwrap();
    let keys: BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from(["connectionId", "provider", "model", "authMethod", "status"])
    );
    let encoded = value.to_string().to_ascii_lowercase();
    for forbidden in ["token", "secret", "authorization"] {
        assert!(
            !encoded.contains(forbidden),
            "leaked {forbidden}: {encoded}"
        );
    }
    assert_eq!(
        serde_json::from_value::<ConnectionInfo>(value.clone()).unwrap(),
        connection
    );

    let mut with_secret = value;
    with_secret["token"] = json!("sk-should-not-be-accepted");
    assert!(serde_json::from_value::<ConnectionInfo>(with_secret).is_err());
    assert!(
        ConnectionInfo::new(
            ConnectionId::new(),
            Provider::Anthropic,
            "   ",
            AuthMethod::ChatGptLogin,
            ConnectionStatus::LoginRequired,
        )
        .is_err()
    );
}

#[test]
fn connection_capabilities_separate_assessment_only_connections() {
    let openai = ConnectionCapabilities::new(
        ConnectionId::new(),
        Provider::OpenAi,
        AuthMethod::ApiKey,
        EndpointClass::OpenAiResponses,
        InputCapabilities::text_and_image(),
        ConnectionUsage::AgentExecution,
    )
    .unwrap();
    assert!(openai.allows_agent_execution());
    assert!(openai.allows_assessment());
    assert!(openai.input().supports(InputModality::Text));
    assert!(openai.input().supports(InputModality::Image));

    let jev = ConnectionCapabilities::new(
        ConnectionId::new(),
        Provider::TypeSafe,
        AuthMethod::ApiKey,
        EndpointClass::TypeSafeSystemOne,
        InputCapabilities::text_only(),
        ConnectionUsage::AssessmentOnly,
    )
    .unwrap();
    assert_eq!(jev.provider(), Provider::TypeSafe);
    assert_eq!(jev.endpoint_class(), EndpointClass::TypeSafeSystemOne);
    assert!(!jev.allows_agent_execution());
    assert!(jev.allows_assessment());
    assert!(!jev.input().supports(InputModality::Image));

    let decisions = ConnectionCapabilities::new(
        ConnectionId::new(),
        Provider::OpenAi,
        AuthMethod::ApiKey,
        EndpointClass::OpenAiDecisions,
        InputCapabilities::text_only(),
        ConnectionUsage::AssessmentOnly,
    )
    .unwrap();
    assert!(!decisions.allows_agent_execution());
    assert!(decisions.allows_assessment());

    assert!(
        ConnectionCapabilities::new(
            ConnectionId::new(),
            Provider::TypeSafe,
            AuthMethod::ApiKey,
            EndpointClass::TypeSafeSystemOne,
            InputCapabilities::text_only(),
            ConnectionUsage::AgentExecution,
        )
        .is_err(),
        "Jev System One must never run as an agent connection"
    );
    assert!(
        ConnectionCapabilities::new(
            ConnectionId::new(),
            Provider::OpenAi,
            AuthMethod::ChatGptLogin,
            EndpointClass::OpenAiDecisions,
            InputCapabilities::text_only(),
            ConnectionUsage::AssessmentOnly,
        )
        .is_err(),
        "ChatGPT login must not flow to OpenAI Decisions"
    );
    assert!(
        ConnectionCapabilities::new(
            ConnectionId::new(),
            Provider::OpenAi,
            AuthMethod::ApiKey,
            EndpointClass::OpenAiDecisions,
            InputCapabilities::text_only(),
            ConnectionUsage::AgentExecution,
        )
        .is_err()
    );
    assert!(
        ConnectionCapabilities::new(
            ConnectionId::new(),
            Provider::Anthropic,
            AuthMethod::ApiKey,
            EndpointClass::OpenAiResponses,
            InputCapabilities::text_only(),
            ConnectionUsage::AgentExecution,
        )
        .is_err()
    );

    let value = serde_json::to_value(&jev).unwrap();
    let keys: BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "connectionId",
            "provider",
            "authMethod",
            "endpointClass",
            "input",
            "usage",
        ])
    );
    assert_eq!(value["provider"], "typesafe");
    assert_eq!(value["endpointClass"], "typesafe_system_one");
    assert_eq!(value["usage"], "assessment_only");
    let encoded = value.to_string().to_ascii_lowercase();
    for forbidden in ["token", "secret", "authorization"] {
        assert!(
            !encoded.contains(forbidden),
            "leaked {forbidden}: {encoded}"
        );
    }
    assert_eq!(
        serde_json::from_value::<ConnectionCapabilities>(value).unwrap(),
        jev
    );
}

#[test]
fn checkpoint_payload_is_versioned_opaque_and_redacted() {
    let fixture = Fixture::new();
    let payload = CheckpointPayload::new(vec![0x00, 0xff, 0x10]);
    let checkpoint = Checkpoint::new(
        fixture.run,
        CheckpointFormatVersion::new(4).unwrap(),
        payload,
    );
    assert_eq!(checkpoint.run_id(), fixture.run);
    assert_eq!(checkpoint.format_version().get(), 4);
    assert_eq!(checkpoint.payload().as_bytes(), &[0x00, 0xff, 0x10]);

    let value = serde_json::to_value(&checkpoint).unwrap();
    assert_eq!(value["payload"], "00ff10");
    assert_eq!(value["formatVersion"], 4);
    let decoded: Checkpoint = serde_json::from_value(value).unwrap();
    assert_eq!(decoded, checkpoint);

    let debug = format!("{checkpoint:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("00ff10"));

    assert_eq!(
        CheckpointFormatVersion::new(0),
        Err(CoreError::InvalidCheckpointVersion { found: 0 })
    );
    let mut invalid = serde_json::to_value(&checkpoint).unwrap();
    invalid["formatVersion"] = json!(0);
    assert!(serde_json::from_value::<Checkpoint>(invalid).is_err());
}

#[test]
fn structured_errors_serialize_without_provider_bodies() {
    let error = CoreError::UnknownContractVersion {
        found: 3,
        expected: 2,
    };
    let value = serde_json::to_value(&error).unwrap();
    assert_eq!(value["kind"], "unknown_contract_version");
    assert_eq!(value["found"], 3);
    assert!(error.to_string().contains("version 3"));

    let first = Fixture::new();
    let second = Fixture::new();
    let cross = CoreError::CrossProjectReference {
        id_kind: IdKind::Run,
        expected: first.project,
        found: second.project,
    };
    let value = serde_json::to_value(&cross).unwrap();
    assert_eq!(value["kind"], "cross_project_reference");
    assert_eq!(value["idKind"], "run");
    assert_eq!(value["expected"], first.project.to_string());
    assert_eq!(value["found"], second.project.to_string());

    let provider = CoreError::ProviderFailure {
        provider: Provider::Anthropic,
        failure: ProviderFailureKind::Authentication,
    };
    let encoded = serde_json::to_string(&provider).unwrap();
    assert_eq!(
        encoded,
        r#"{"kind":"provider_failure","provider":"anthropic","failure":"authentication"}"#
    );
}
