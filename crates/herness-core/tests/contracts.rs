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
fn contract_version_is_one_and_rejects_unknown_versions() {
    assert_eq!(CONTRACT_VERSION, 1);
    assert_eq!(ContractVersion::CURRENT.get(), 1);
    assert_eq!(ContractVersion::try_from(1), Ok(ContractVersion::CURRENT));
    assert_eq!(
        ContractVersion::try_from(2),
        Err(CoreError::UnknownContractVersion {
            found: 2,
            expected: 1
        })
    );
    assert_eq!(
        ContractVersion::try_from(0),
        Err(CoreError::UnknownContractVersion {
            found: 0,
            expected: 1
        })
    );
    assert_eq!("1".parse::<ContractVersion>(), Ok(ContractVersion::CURRENT));
    assert!(matches!(
        "2".parse::<ContractVersion>(),
        Err(CoreError::UnknownContractVersion { found: 2, .. })
    ));
    assert!(matches!(
        "not-a-version".parse::<ContractVersion>(),
        Err(CoreError::InvalidContractVersion { .. })
    ));
    assert!(serde_json::from_str::<ContractVersion>("2").is_err());
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
            "agentId",
            "sessionId",
            "runId",
            "operationId",
            "sequence",
            "kind",
            "occurredAt",
            "payload",
        ])
    );
    assert_eq!(value["contractVersion"], 1);
    assert_eq!(value["sequence"], 7);

    let decoded: Event = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(decoded, event);
    assert_eq!(decoded.contract_version(), ContractVersion::CURRENT);
    assert_eq!(decoded.sequence(), 7);
    assert_eq!(decoded.kind().as_str(), "run.state_changed");

    let mut future = value;
    future["contractVersion"] = json!(2);
    let error = serde_json::from_value::<Event>(future).unwrap_err();
    assert!(
        error.to_string().contains("unsupported contract version 2"),
        "unexpected error: {error}"
    );
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
        found: 2,
        expected: 1,
    };
    let value = serde_json::to_value(&error).unwrap();
    assert_eq!(value["kind"], "unknown_contract_version");
    assert_eq!(value["found"], 2);
    assert!(error.to_string().contains("version 2"));

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
