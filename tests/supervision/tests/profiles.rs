//! Purpose-specific profile, threshold, confidence, and distribution tests.

use herness_core::contracts::{
    AuthMethod, ConnectionCapabilities, ConnectionId, ConnectionStatus, ConnectionUsage,
    EndpointClass, InputCapabilities, ModelId, Provider,
};
use herness_supervision::assessment::{
    AssessmentOutcome, AssessmentProvenance, AssessmentResult, ConditionProbabilities,
    ConditionVerdict, NativeConfidence, PermissionAssessment, PermissionProbabilities,
    PermissionVerdict, RationaleOrigin,
};
use herness_supervision::conditions::ConditionVersion;
use herness_supervision::error::SupervisionError;
use herness_supervision::evidence::TargetVersion;
use herness_supervision::profiles::{
    AdapterVersion, AssessmentProfile, H2_COMPLETION_MET_THRESHOLD, H2_COMPLETION_UNMET_THRESHOLD,
    H2_DISTRIBUTION_TOLERANCE, H2_PERMISSION_ALLOW_THRESHOLD, H2_PERMISSION_DENY_THRESHOLD,
    ProfileBinding, ProfileCatalog, ProfileEntry, ProfileInputs, ProfilePurpose, ProfileThresholds,
    ProfileUnavailable, ProfileVersion, ProviderKind, RubricVersion, reject_run_model_substitution,
};

use herness_supervision_tests::*;

fn unavailable(reason: ProfileUnavailable) -> SupervisionError {
    SupervisionError::ProfileUnavailable { reason }
}

#[test]
fn thresholds_preserve_h2_defaults_and_normal_llm_has_no_probability_threshold() {
    assert_eq!(H2_COMPLETION_MET_THRESHOLD, 0.95);
    assert_eq!(H2_COMPLETION_UNMET_THRESHOLD, 0.95);
    assert_eq!(H2_PERMISSION_ALLOW_THRESHOLD, 0.99);
    assert_eq!(H2_PERMISSION_DENY_THRESHOLD, 0.99);
    assert_eq!(H2_DISTRIBUTION_TOLERANCE, 0.001);

    let decisions = ProfileThresholds::decisions();
    assert_eq!(decisions.completion_met(), Some(0.95));
    assert_eq!(decisions.completion_unmet(), Some(0.95));
    assert_eq!(decisions.permission_allow(), Some(0.99));
    assert_eq!(decisions.permission_deny(), Some(0.99));
    assert_eq!(decisions.distribution_tolerance(), 0.001);

    let lowered = ProfileThresholds::new(Some(0.94), Some(0.95), Some(0.99), Some(0.99), 0.001)
        .expect("custom thresholds");
    assert!(lowered.below_h2_defaults(ProviderKind::Decisions));
    assert!(!ProfileThresholds::decisions().below_h2_defaults(ProviderKind::Decisions));
    assert!(!lowered.below_h2_defaults(ProviderKind::NormalLlm));
    assert!(ProfileThresholds::new(Some(f64::NAN), None, None, None, 0.001).is_err());

    let normal = ProfileThresholds::normal_llm();
    assert_eq!(normal.completion_met(), None);
    assert_eq!(normal.completion_unmet(), None);
    assert_eq!(normal.permission_allow(), None);
    assert_eq!(normal.permission_deny(), None);

    let project = project();
    let ids = ids(project);
    assert!(
        AssessmentProfile::new(
            ids.profile,
            ProfileVersion::new(1).expect("version"),
            ProfilePurpose::Completion,
            ProviderKind::NormalLlm,
            normal_connection().connection_id(),
            ModelId::new("synthetic").expect("model"),
            AdapterVersion::new("adapter").expect("adapter"),
            RubricVersion::new("rubric").expect("rubric"),
            ProfileInputs::text_only(),
            ProfileThresholds::decisions(),
        )
        .is_err()
    );

    assert!(
        AssessmentProfile::new(
            ids.permission_profile,
            ProfileVersion::new(1).expect("version"),
            ProfilePurpose::Permission,
            ProviderKind::Decisions,
            decisions_connection().connection_id(),
            ModelId::new("synthetic").expect("model"),
            AdapterVersion::new("adapter").expect("adapter"),
            RubricVersion::new("rubric").expect("rubric"),
            ProfileInputs::text_only(),
            ProfileThresholds::normal_llm(),
        )
        .is_err()
    );
}

#[test]
fn unset_profile_is_unusable_and_has_no_fallback() {
    let project = project();
    let empty = ProfileCatalog::unset();
    assert_eq!(
        empty.resolve(ProfilePurpose::Completion),
        Err(unavailable(ProfileUnavailable::Unset {
            purpose: ProfilePurpose::Completion
        }))
    );

    let catalog = profile_catalog(project);
    let completion = catalog
        .resolve(ProfilePurpose::Completion)
        .expect("completion");
    assert_eq!(completion.purpose(), ProfilePurpose::Completion);
    assert_eq!(
        catalog.resolve(ProfilePurpose::Html),
        Err(unavailable(ProfileUnavailable::Unset {
            purpose: ProfilePurpose::Html
        }))
    );

    let mut completion_only = ProfileCatalog::for_project(project);
    completion_only
        .insert(completion_entry(project, ConnectionStatus::Available, true))
        .expect("insert");
    assert_eq!(
        completion_only.resolve(ProfilePurpose::Permission),
        Err(unavailable(ProfileUnavailable::Unset {
            purpose: ProfilePurpose::Permission
        }))
    );
    let permission_binding = ProfileBinding::new(
        ids(project).permission_profile,
        ProfileVersion::new(1).expect("version"),
        ProfilePurpose::Permission,
    );
    assert!(matches!(
        completion_only.resolve_bound(permission_binding),
        Err(SupervisionError::ProfileUnavailable {
            reason: ProfileUnavailable::Unset {
                purpose: ProfilePurpose::Permission
            }
        })
    ));

    let run_model = ModelId::new("synthetic-run-model").expect("model");
    let judge = completion_profile(project);
    assert!(reject_run_model_substitution(&run_model, Some(&judge)).is_ok());
    let same_model = judge.model().clone();
    assert_eq!(
        reject_run_model_substitution(&same_model, Some(&judge)),
        Err(unavailable(
            ProfileUnavailable::RunModelSubstitutionRejected
        ))
    );
    assert!(matches!(
        reject_run_model_substitution(&run_model, None),
        Err(SupervisionError::ProfileUnavailable {
            reason: ProfileUnavailable::Unset { .. }
        })
    ));
}

#[test]
fn incompatible_connections_and_inputs_are_unusable() {
    let project = project();
    let text_only_connection = ConnectionCapabilities::new(
        ConnectionId::new(),
        Provider::OpenAiCompatible,
        AuthMethod::ApiKey,
        EndpointClass::OpenAiCompletions,
        InputCapabilities::text_only(),
        ConnectionUsage::AgentExecution,
    )
    .expect("connection");
    let image_profile = completion_profile_for(project, text_only_connection.connection_id());
    let image_entry = ProfileEntry::new(
        image_profile,
        text_only_connection,
        ConnectionStatus::Available,
        true,
    );
    assert_eq!(
        image_entry.validate(),
        Err(unavailable(ProfileUnavailable::MissingInput {
            modality: herness_core::contracts::InputModality::Image
        }))
    );

    let login_required = completion_entry(project, ConnectionStatus::LoginRequired, true);
    assert_eq!(
        login_required.validate(),
        Err(unavailable(ProfileUnavailable::ConnectionNotAvailable {
            status: ConnectionStatus::LoginRequired
        }))
    );

    let no_structured = completion_entry(project, ConnectionStatus::Available, false);
    assert_eq!(
        no_structured.validate(),
        Err(unavailable(ProfileUnavailable::MissingStructuredOutput))
    );

    let normal = normal_connection();
    let jev_profile = AssessmentProfile::new(
        ids(project).profile,
        ProfileVersion::new(1).expect("version"),
        ProfilePurpose::Completion,
        ProviderKind::Jev,
        normal.connection_id(),
        ModelId::new("synthetic-jev").expect("model"),
        AdapterVersion::new("adapter").expect("adapter"),
        RubricVersion::new("rubric").expect("rubric"),
        ProfileInputs::text_only(),
        ProfileThresholds::decisions(),
    )
    .expect("profile");
    let mismatch = ProfileEntry::new(jev_profile, normal, ConnectionStatus::Available, true);
    assert!(matches!(
        mismatch.validate(),
        Err(SupervisionError::ProfileUnavailable {
            reason: ProfileUnavailable::ProviderMismatch { .. }
        })
    ));

    let assessment_only = jev_connection();
    let normal_profile = completion_profile_for(project, assessment_only.connection_id());
    let wrong_assessment = ProfileEntry::new(
        normal_profile,
        assessment_only,
        ConnectionStatus::Available,
        true,
    );
    assert!(matches!(
        wrong_assessment.validate(),
        Err(SupervisionError::ProfileUnavailable {
            reason: ProfileUnavailable::ProviderMismatch { .. }
        })
    ));
}

#[test]
fn native_confidence_is_not_probability_and_uncertainty_never_supports_completion() {
    let confidence = NativeConfidence::new(0.92, "fixture-native-scale").expect("confidence");
    assert!(!confidence.is_probability());
    assert_eq!(confidence.scale(), "fixture-native-scale");
    assert!(NativeConfidence::new(f64::NAN, "scale").is_err());
    assert!(NativeConfidence::new(1.01, "scale").is_err());

    let project = project();
    let fixture_ids = ids(project);
    let profile = completion_profile(project);
    let request = assessment_request(
        project,
        fixture_ids.condition_a,
        &profile,
        vec![fixture_ids.evidence_a],
    );
    let uncertain = AssessmentResult::new(
        &request,
        vec![fixture_ids.evidence_a],
        "The fixture is not confident.",
        Some("the evidence is partial".to_owned()),
        AssessmentOutcome::NormalLlm {
            verdict: ConditionVerdict::Met,
            confidence: Some(confidence),
        },
        AssessmentProvenance::new(
            Provider::OpenAi,
            ProviderKind::NormalLlm,
            ModelId::new("synthetic-completion-judge").expect("model"),
            request.adapter_version().clone(),
            request.rubric_version().clone(),
        )
        .expect("provenance"),
        now(),
    )
    .expect("result");
    assert_eq!(
        uncertain.adopted_verdict(ProfileThresholds::normal_llm()),
        None
    );
    assert!(!uncertain.supports_completion(
        ConditionVersion::new(1).expect("version"),
        TargetVersion::new(1).expect("version"),
        profile.binding(),
        ProfileThresholds::normal_llm(),
    ));
}

#[test]
fn decision_distribution_and_adoption_threshold_are_validated() {
    let valid = ConditionProbabilities::new(0.95, 0.04, 0.01).expect("distribution");
    assert_eq!(valid.met(), 0.95);
    assert_eq!(valid.unmet(), 0.04);
    assert_eq!(valid.insufficient(), 0.01);

    assert!(ConditionProbabilities::new(0.95, 0.05, 0.01).is_err());
    assert!(ConditionProbabilities::new(-0.01, 0.60, 0.41).is_err());
    assert!(ConditionProbabilities::new(1.01, -0.01, 0.0).is_err());
    assert!(ConditionProbabilities::new(f64::NAN, 0.5, 0.5).is_err());
    assert!(ConditionProbabilities::new(f64::INFINITY, 0.0, 0.0).is_err());

    let project = project();
    let fixture_ids = ids(project);
    let profile = permission_profile(project);
    let request = assessment_request(
        project,
        fixture_ids.condition_a,
        &profile,
        vec![fixture_ids.evidence_a],
    );

    let met = decision_result(&request, 0.95, 0.04, 0.01, ConditionVerdict::Met);
    assert_eq!(
        met.adopted_verdict(ProfileThresholds::decisions()),
        Some(ConditionVerdict::Met)
    );

    let below = decision_result(&request, 0.949, 0.050, 0.001, ConditionVerdict::Met);
    assert_eq!(below.adopted_verdict(ProfileThresholds::decisions()), None);

    let insufficient = decision_result(&request, 0.10, 0.10, 0.80, ConditionVerdict::Insufficient);
    assert_eq!(
        insufficient.adopted_verdict(ProfileThresholds::decisions()),
        None
    );
    assert!(!insufficient.supports_completion(
        ConditionVersion::new(1).expect("version"),
        TargetVersion::new(1).expect("version"),
        profile.binding(),
        ProfileThresholds::decisions(),
    ));
}

#[test]
fn permission_thresholds_and_ask_are_conservative() {
    let thresholds = ProfileThresholds::decisions();
    let allow = PermissionAssessment::Decision {
        selected: PermissionVerdict::Allow,
        probabilities: PermissionProbabilities::new(0.99, 0.005, 0.005).expect("distribution"),
    };
    assert_eq!(
        allow.adopted_verdict(thresholds),
        Some(PermissionVerdict::Allow)
    );
    assert!(allow.allows_execution(thresholds));

    let deny = PermissionAssessment::Decision {
        selected: PermissionVerdict::Deny,
        probabilities: PermissionProbabilities::new(0.005, 0.99, 0.005).expect("distribution"),
    };
    assert_eq!(
        deny.adopted_verdict(thresholds),
        Some(PermissionVerdict::Deny)
    );
    assert!(!deny.allows_execution(thresholds));

    let below = PermissionAssessment::Decision {
        selected: PermissionVerdict::Deny,
        probabilities: PermissionProbabilities::new(0.006, 0.989, 0.005).expect("distribution"),
    };
    assert_eq!(below.adopted_verdict(thresholds), None);
    assert!(!below.allows_execution(thresholds));

    let ask = PermissionAssessment::Decision {
        selected: PermissionVerdict::Ask,
        probabilities: PermissionProbabilities::new(0.1, 0.1, 0.8).expect("distribution"),
    };
    assert_eq!(ask.adopted_verdict(thresholds), None);
    assert!(!ask.allows_execution(thresholds));

    let normal_uncertain = PermissionAssessment::NormalLlm {
        verdict: PermissionVerdict::Deny,
        uncertain: true,
    };
    assert_eq!(
        normal_uncertain.adopted_verdict(ProfileThresholds::normal_llm()),
        None
    );
    assert!(!normal_uncertain.allows_execution(ProfileThresholds::normal_llm()));

    assert!(PermissionProbabilities::new(0.99, 0.02, -0.01).is_err());
    assert!(PermissionProbabilities::new(0.99, 0.02, 0.01).is_err());
}

#[test]
fn fixed_profile_version_does_not_apply_after_a_version_change() {
    let project = project();
    let catalog = profile_catalog(project);
    let completion = completion_profile(project);
    let resolved = catalog
        .resolve_bound(completion.binding())
        .expect("bound profile");
    assert_eq!(resolved.id(), completion.id());

    let newer = ProfileBinding::new(
        completion.id(),
        ProfileVersion::new(2).expect("version"),
        ProfilePurpose::Completion,
    );
    assert_eq!(
        catalog.resolve_bound(newer),
        Err(unavailable(ProfileUnavailable::VersionMismatch {
            bound: 2,
            configured: 1
        }))
    );

    let wrong_profile = ProfileBinding::new(
        ids(project).permission_profile,
        ProfileVersion::new(1).expect("version"),
        ProfilePurpose::Completion,
    );
    assert!(matches!(
        catalog.resolve_bound(wrong_profile),
        Err(SupervisionError::ProfileUnavailable {
            reason: ProfileUnavailable::ProfileMismatch { .. }
        })
    ));

    let mut completion_only = ProfileCatalog::for_project(project);
    completion_only
        .insert(completion_entry(project, ConnectionStatus::Available, true))
        .expect("insert");
    let wrong_purpose = ProfileBinding::new(
        completion.id(),
        ProfileVersion::new(1).expect("version"),
        ProfilePurpose::Permission,
    );
    assert!(matches!(
        completion_only.resolve_bound(wrong_purpose),
        Err(SupervisionError::ProfileUnavailable {
            reason: ProfileUnavailable::Unset { .. }
        })
    ));
}

#[test]
fn profile_catalog_rejects_cross_project_profiles() {
    let project = project();
    let mut catalog = ProfileCatalog::for_project(project);
    let foreign = completion_entry(other_project(), ConnectionStatus::Available, true);
    assert!(matches!(
        catalog.insert(foreign),
        Err(SupervisionError::CrossProjectReference { .. })
    ));

    assert!(!catalog.contains(ProfilePurpose::Completion));
    assert_eq!(
        catalog.resolve(ProfilePurpose::Completion),
        Err(unavailable(ProfileUnavailable::Unset {
            purpose: ProfilePurpose::Completion
        }))
    );
}

#[test]
fn fixture_catalog_resolves_jev_and_decisions_connections() {
    let project = project();
    let jev = jev_connection();
    let jev_profile = AssessmentProfile::new(
        herness_supervision::ids::ProfileId::new(project),
        ProfileVersion::new(1).expect("version"),
        ProfilePurpose::Completion,
        ProviderKind::Jev,
        jev.connection_id(),
        ModelId::new("jev-1.14.0").expect("model"),
        AdapterVersion::new("jev-adapter").expect("adapter"),
        RubricVersion::new("jev-rubric").expect("rubric"),
        ProfileInputs::text_only(),
        ProfileThresholds::decisions(),
    )
    .expect("profile");
    let entry = ProfileEntry::new(jev_profile, jev, ConnectionStatus::Available, false);
    entry.validate().expect("valid Jev profile");

    let decisions = decisions_connection();
    let decisions_profile = permission_profile_for(project, decisions.connection_id());
    let entry = ProfileEntry::new(
        decisions_profile,
        decisions,
        ConnectionStatus::Available,
        true,
    );
    entry.validate().expect("valid Decisions profile");
}

#[test]
fn decision_confidence_and_rationale_provenance_are_additive_and_not_adoption_inputs() {
    let project = project();
    let fixture_ids = ids(project);
    let profile = permission_profile(project);
    let request = assessment_request(
        project,
        fixture_ids.condition_a,
        &profile,
        vec![fixture_ids.evidence_a],
    );
    let result = AssessmentResult::new(
        &request,
        vec![fixture_ids.evidence_a],
        "The fixture distribution supports the recorded verdict.",
        None,
        AssessmentOutcome::Decision {
            selected: ConditionVerdict::Met,
            probabilities: ConditionProbabilities::new(0.96, 0.03, 0.01).expect("distribution"),
            confidence: Some(
                NativeConfidence::new(0.2, "fixture-derived-scale").expect("confidence"),
            ),
        },
        AssessmentProvenance::new(
            Provider::OpenAi,
            ProviderKind::Decisions,
            ModelId::new("synthetic-decision-judge").expect("model"),
            request.adapter_version().clone(),
            request.rubric_version().clone(),
        )
        .expect("provenance")
        .with_reported_model(ModelId::new("gpt-6-luna").expect("reported model")),
        now(),
    )
    .expect("result")
    .with_rationale_origin(RationaleOrigin::Host);

    assert_eq!(
        result.adopted_verdict(ProfileThresholds::decisions()),
        Some(ConditionVerdict::Met)
    );
    assert_eq!(
        result
            .provenance()
            .reported_model()
            .map(|model| model.as_str()),
        Some("gpt-6-luna")
    );
    assert_eq!(result.rationale_origin(), RationaleOrigin::Host);

    // The derived confidence is not the selected probability: a high
    // confidence does not rescue a below-threshold distribution.
    let below = AssessmentResult::new(
        &request,
        vec![fixture_ids.evidence_a],
        "The fixture distribution is below the completion threshold.",
        None,
        AssessmentOutcome::Decision {
            selected: ConditionVerdict::Met,
            probabilities: ConditionProbabilities::new(0.94, 0.05, 0.01).expect("distribution"),
            confidence: Some(
                NativeConfidence::new(0.99, "fixture-derived-scale").expect("confidence"),
            ),
        },
        AssessmentProvenance::new(
            Provider::OpenAi,
            ProviderKind::Decisions,
            ModelId::new("synthetic-decision-judge").expect("model"),
            request.adapter_version().clone(),
            request.rubric_version().clone(),
        )
        .expect("provenance"),
        now(),
    )
    .expect("result");
    assert_eq!(below.adopted_verdict(ProfileThresholds::decisions()), None);

    // Old payloads without the additive fields still decode. The default
    // rationale origin is unspecified rather than silently treated as model
    // prose.
    let mut value = serde_json::to_value(&result).expect("result JSON");
    value.as_object_mut().unwrap().remove("rationaleOrigin");
    value["provenance"]
        .as_object_mut()
        .unwrap()
        .remove("reportedModel");
    value["outcome"]
        .as_object_mut()
        .unwrap()
        .remove("confidence");
    let decoded: AssessmentResult = serde_json::from_value(value).expect("legacy result JSON");
    assert_eq!(decoded.rationale_origin(), RationaleOrigin::Unspecified);
    assert_eq!(decoded.provenance().reported_model(), None);
    match decoded.outcome() {
        AssessmentOutcome::Decision { confidence, .. } => assert_eq!(*confidence, None),
        _ => panic!("expected Decision"),
    }
}

// ---------------------------------------------------------------------------
// Html purpose (Task 12)
// ---------------------------------------------------------------------------

#[test]
fn html_is_a_distinct_condition_purpose_with_no_completion_fallback() {
    assert!(ProfilePurpose::Completion.is_condition_assessment());
    assert!(ProfilePurpose::Html.is_condition_assessment());
    assert!(!ProfilePurpose::Permission.is_condition_assessment());

    let project = project();
    let connection = normal_connection();
    let html = llm_html_profile_for(
        project,
        connection.connection_id(),
        "synthetic-html-judge",
        ProfileInputs::text_only(),
    );
    assert_eq!(html.purpose(), ProfilePurpose::Html);
    let html_entry =
        ProfileEntry::new(html.clone(), connection, ConnectionStatus::Available, false);

    let mut catalog = ProfileCatalog::for_project(project);
    catalog.insert(html_entry).expect("insert html profile");
    assert!(catalog.resolve(ProfilePurpose::Html).is_ok());
    assert_eq!(
        catalog.resolve(ProfilePurpose::Completion),
        Err(unavailable(ProfileUnavailable::Unset {
            purpose: ProfilePurpose::Completion
        }))
    );

    let completion_binding =
        ProfileBinding::new(html.id(), html.version(), ProfilePurpose::Completion);
    assert!(!completion_binding.matches(&html));
    assert!(matches!(
        catalog.resolve_bound(completion_binding),
        Err(SupervisionError::ProfileUnavailable {
            reason: ProfileUnavailable::Unset { .. }
        })
    ));
}

#[test]
fn html_assessment_results_record_their_purpose_and_never_support_completion() {
    let project = project();
    let fixture_ids = ids(project);
    let profile = llm_html_profile_for(
        project,
        normal_connection().connection_id(),
        "synthetic-html-judge",
        ProfileInputs::text_only(),
    );
    let request = assessment_request(
        project,
        fixture_ids.condition_a,
        &profile,
        vec![fixture_ids.evidence_a],
    );
    let provenance = AssessmentProvenance::new(
        Provider::OpenAi,
        ProviderKind::NormalLlm,
        profile.model().clone(),
        request.adapter_version().clone(),
        request.rubric_version().clone(),
    )
    .expect("provenance")
    .with_purpose(ProfilePurpose::Html);
    let result = AssessmentResult::new(
        &request,
        vec![fixture_ids.evidence_a],
        "The Html evidence supports the recorded verdict.",
        None,
        AssessmentOutcome::NormalLlm {
            verdict: ConditionVerdict::Met,
            confidence: None,
        },
        provenance,
        now(),
    )
    .expect("result");

    assert_eq!(result.purpose(), ProfilePurpose::Html);
    assert_eq!(result.profile().purpose(), ProfilePurpose::Html);
    assert_eq!(result.provenance().purpose(), Some(ProfilePurpose::Html));

    let completion_binding =
        ProfileBinding::new(profile.id(), profile.version(), ProfilePurpose::Completion);
    assert!(!result.supports_completion(
        ConditionVersion::new(1).expect("version"),
        TargetVersion::new(1).expect("version"),
        completion_binding,
        ProfileThresholds::normal_llm(),
    ));

    // A provenance record that claims Completion for an Html request is
    // rejected; the purpose is never inferred or silently substituted.
    let wrong_provenance = AssessmentProvenance::new(
        Provider::OpenAi,
        ProviderKind::NormalLlm,
        profile.model().clone(),
        request.adapter_version().clone(),
        request.rubric_version().clone(),
    )
    .expect("provenance")
    .with_purpose(ProfilePurpose::Completion);
    assert!(matches!(
        AssessmentResult::new(
            &request,
            vec![fixture_ids.evidence_a],
            "The Html evidence supports the recorded verdict.",
            None,
            AssessmentOutcome::NormalLlm {
                verdict: ConditionVerdict::Met,
                confidence: None,
            },
            wrong_provenance,
            now(),
        ),
        Err(SupervisionError::AssessmentContractViolation { .. })
    ));

    // Older payloads without a provenance purpose remain readable and are not
    // relabelled as Completion. The profile binding still records Html.
    let mut value = serde_json::to_value(&result).expect("result JSON");
    value["provenance"]
        .as_object_mut()
        .unwrap()
        .remove("purpose");
    let decoded: AssessmentResult = serde_json::from_value(value).expect("legacy result JSON");
    assert_eq!(decoded.provenance().purpose(), None);
    assert_eq!(decoded.purpose(), ProfilePurpose::Html);
}
