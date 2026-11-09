//! Explicit opt-in real-connection checks.
//!
//! These tests are ignored by default and only run when a human has approved
//! the exact route, synthetic data, request count, and cost. They read a
//! credential from an environment variable; they never write it to a report,
//! event, or log. No test in this file is part of the default acceptance run.

use std::sync::Arc;
use std::time::Duration;

use herness_assessment::llm::EvidenceDocument;
use herness_assessment::{
    AssessmentEndpoints, AssessmentTransport, COMMANDCODE_JEV_REQUEST_MODEL, CancelToken,
    JevAssessmentAdapter, TransportControl,
};
use herness_core::contracts::Timestamp;
use herness_core::{
    AuthMethod, ConnectionAdmin, ConnectionCapabilityDeclaration, ConnectionId, ConnectionStatus,
    CredentialAvailability, CredentialKind, CredentialPort, EndpointClass, InputCapabilities,
    Provider, ResolvedCredential, SecretString,
};
use herness_supervision::AssessmentRequest;
use herness_supervision::conditions::ConditionVersion;
use herness_supervision::evidence::TargetVersion;
use herness_supervision::ids::{ConditionId, DecisionId, EvidenceId, ProfileId, SupervisionId};
use herness_supervision::ports::ClockPort;
use herness_supervision::profiles::{
    AdapterVersion, AssessmentProfile, ProfileInputs, ProfilePurpose, ProfileThresholds,
    ProfileVersion, ProviderKind, RubricVersion,
};

struct EnvCredential {
    connection: ConnectionId,
    secret: String,
}

impl CredentialPort for EnvCredential {
    fn availability(
        &self,
        connection: &ConnectionId,
    ) -> Result<CredentialAvailability, herness_core::CoreError> {
        if connection == &self.connection {
            Ok(CredentialAvailability::Available)
        } else {
            Ok(CredentialAvailability::Unavailable)
        }
    }

    fn resolve(
        &self,
        connection: &ConnectionId,
    ) -> Result<ResolvedCredential, herness_core::CoreError> {
        if connection != &self.connection {
            return Err(herness_core::CoreError::CredentialUnavailable {
                connection: *connection,
                failure: herness_core::CredentialFailureKind::NotConfigured,
            });
        }
        let secret = SecretString::new(self.secret.clone())?;
        Ok(ResolvedCredential::new(CredentialKind::ApiKey, secret))
    }
}

struct FixedClock;

impl ClockPort for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(1_700_000_000_000)
    }
}

fn commandcode_key() -> String {
    let key = std::env::var("COMMANDCODE_API_KEY").unwrap_or_default();
    assert!(
        !key.trim().is_empty(),
        "COMMANDCODE_API_KEY is required for this opt-in real check; no request was sent"
    );
    key
}

#[test]
#[ignore = "opt-in real CommandCode GOAT Jev System One check; requires COMMANDCODE_API_KEY and human approval"]
fn commandcode_jev_completion_met_and_unmet_are_real() {
    let key = commandcode_key();
    let project = herness_core::ProjectId::new();
    let connection = ConnectionId::new();
    let model = COMMANDCODE_JEV_REQUEST_MODEL;

    let settings = herness_core::ConnectionSettings::new_with_capabilities(
        connection,
        Provider::TypeSafe,
        model,
        AuthMethod::ApiKey,
        None,
        None,
        ConnectionCapabilityDeclaration::new(
            EndpointClass::TypeSafeSystemOne,
            InputCapabilities::text_only(),
        ),
    )
    .expect("Command Code Jev connection settings");

    let admin = ConnectionAdmin::new();
    admin.add(settings.clone()).expect("register connection");
    let directory = admin.directory();

    let profile = AssessmentProfile::new(
        ProfileId::new(project),
        ProfileVersion::new(1).expect("profile version"),
        ProfilePurpose::Completion,
        ProviderKind::Jev,
        connection,
        herness_core::ModelId::new(model).expect("model"),
        AdapterVersion::new("real-jev-adapter-1").expect("adapter version"),
        RubricVersion::new("real-jev-rubric-1").expect("rubric version"),
        ProfileInputs::text_only(),
        ProfileThresholds::decisions(),
    )
    .expect("Jev profile");
    let entry = herness_supervision::profiles::ProfileEntry::new(
        profile.clone(),
        settings.capabilities().expect("capabilities"),
        ConnectionStatus::Available,
        false,
    );

    let transport = AssessmentTransport::new(
        Arc::new(EnvCredential {
            connection,
            secret: key,
        }),
        directory,
        AssessmentEndpoints::for_commandcode(),
    )
    .expect("Command Code assessment transport");
    let adapter = JevAssessmentAdapter::with_wire_model(transport, Arc::new(FixedClock), model)
        .expect("Command Code Jev adapter");

    let evidence_id = EvidenceId::new(project);
    let positive_evidence = EvidenceDocument::text(evidence_id, "Synthetic evidence: herness-ok")
        .expect("positive evidence");
    let positive = AssessmentRequest::new(
        DecisionId::new(project),
        SupervisionId::new(project),
        ConditionId::new(project),
        ConditionVersion::new(1).expect("condition version"),
        TargetVersion::new(1).expect("target version"),
        "The evidence contains the exact token herness-ok.",
        profile.binding(),
        AdapterVersion::new("real-jev-adapter-1").expect("adapter version"),
        RubricVersion::new("real-jev-rubric-1").expect("rubric version"),
        vec![evidence_id],
    )
    .expect("positive request");
    let control = TransportControl::new(CancelToken::new()).with_remaining(Duration::from_secs(60));
    let positive_result = adapter
        .assess(&positive, &entry, &[positive_evidence], control)
        .expect("real Command Code positive assessment");
    assert!(
        positive_result.rejection().is_none(),
        "positive assessment was rejected: {:?}",
        positive_result.rejection()
    );
    let positive_verdict = positive_result.result().reported_verdict();
    assert_eq!(
        positive_verdict,
        herness_supervision::assessment::ConditionVerdict::Met,
        "positive fixture did not return met"
    );
    let adopted = positive_result.adopted_verdict(ProfileThresholds::decisions());
    println!(
        "REAL_JEV_POSITIVE_OUTCOME outcome={:?} adopted={:?}",
        positive_result.result().outcome(),
        adopted
    );
    assert_eq!(
        adopted,
        Some(herness_supervision::assessment::ConditionVerdict::Met),
        "positive fixture was not adopted as met"
    );
    let usage = positive_result.usage().expect("reported usage");
    println!(
        "REAL_JEV_POSITIVE_OK model={model} verdict={} usage_in={} usage_out={} attempts={}",
        positive_verdict.as_str(),
        usage.input_tokens(),
        usage.output_tokens(),
        positive_result.attempts()
    );

    let negative_evidence_id = EvidenceId::new(project);
    let negative_evidence =
        EvidenceDocument::text(negative_evidence_id, "Synthetic evidence: herness-no")
            .expect("negative evidence");
    let negative = AssessmentRequest::new(
        DecisionId::new(project),
        SupervisionId::new(project),
        ConditionId::new(project),
        ConditionVersion::new(1).expect("condition version"),
        TargetVersion::new(1).expect("target version"),
        "The evidence contains the exact token herness-ok.",
        profile.binding(),
        AdapterVersion::new("real-jev-adapter-1").expect("adapter version"),
        RubricVersion::new("real-jev-rubric-1").expect("rubric version"),
        vec![negative_evidence_id],
    )
    .expect("negative request");
    let negative_result = adapter
        .assess(
            &negative,
            &entry,
            &[negative_evidence],
            TransportControl::new(CancelToken::new()).with_remaining(Duration::from_secs(60)),
        )
        .expect("real Command Code negative assessment");
    assert!(
        negative_result.rejection().is_none(),
        "negative assessment was rejected: {:?}",
        negative_result.rejection()
    );
    let negative_verdict = negative_result.result().reported_verdict();
    assert_ne!(
        negative_verdict,
        herness_supervision::assessment::ConditionVerdict::Met,
        "negative fixture incorrectly returned met"
    );
    let negative_usage = negative_result.usage().expect("reported usage");
    println!(
        "REAL_JEV_NEGATIVE_OK model={model} verdict={} usage_in={} usage_out={} attempts={}",
        negative_verdict.as_str(),
        negative_usage.input_tokens(),
        negative_usage.output_tokens(),
        negative_result.attempts()
    );
}
