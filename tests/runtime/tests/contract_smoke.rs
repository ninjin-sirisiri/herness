//! Smoke tests proving the shared fixture crate can exercise the public contract.

use herness_core::*;
use herness_runtime_tests::fixtures::{ProjectFixture, second_project};
use serde_json::json;

#[test]
fn contract_version_writes_two_and_reads_one_and_two() {
    assert_eq!(CONTRACT_VERSION, 2);
    assert_eq!(ContractVersion::CURRENT.get(), 2);
    assert_eq!(ContractVersion::try_from(1), Ok(ContractVersion::V1));
}

#[test]
fn fixture_event_roundtrips_through_public_json() {
    let fixture = ProjectFixture::new();
    let event = fixture.event(
        "run.state_changed",
        EventPayload::new(json!({ "state": "idle" })),
    );

    let encoded = serde_json::to_value(&event).unwrap();
    assert_eq!(encoded["contractVersion"], 2);
    assert_eq!(encoded["projectId"], fixture.project_id.to_string());
    assert_eq!(encoded["subject"]["runId"], fixture.run_id.to_string());
    assert_eq!(serde_json::from_value::<Event>(encoded).unwrap(), event);
}

#[test]
fn an_identifier_from_another_project_is_rejected() {
    let first = ProjectFixture::new();
    let second = second_project();
    let operation = first.operation_id();

    let error = operation.validate_in(&second.project_id).unwrap_err();
    assert!(matches!(
        error,
        CoreError::CrossProjectReference {
            id_kind: IdKind::Operation,
            ..
        }
    ));
}

#[test]
fn fixture_frozen_operation_keeps_its_policy_version() {
    let fixture = ProjectFixture::new();
    let operation = fixture.frozen_operation(
        ToolName::Read,
        ToolArguments::Read(ReadArgs {
            path: NonEmptyText::new("README.md").unwrap(),
            offset: None,
            limit: Some(20),
        }),
    );
    assert_eq!(operation.policy_version(), PolicyVersion::INITIAL);
    assert_eq!(operation.cwd().as_str(), "/tmp/herness-runtime-fixture");
}
