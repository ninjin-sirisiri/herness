//! Contract-level H2 supervision tests.

use std::collections::BTreeSet;

use herness_core::contracts::{AgentId, ContractVersion, RunId, SessionId, Timestamp};
use herness_supervision::approval::ApprovalActor;
use herness_supervision::assessment::{ConditionVerdict, PermissionAssessment, PermissionVerdict};
use herness_supervision::budget::{
    BudgetClockState, BudgetLimit, BudgetPolicy, BudgetUsage, H2_ACTIVE_SECONDS,
    H2_ADDITIONAL_RUNS, H2_MAX_TOTAL_RUNS, Money, MoneyCap, PriceVersion,
    assessment_timeout_seconds, billed_active_seconds, chatgpt_login_allowed_with_money_cap,
    validate_assessment_spend,
};
use herness_supervision::command::{SupervisionRequest, execute_command};
use herness_supervision::conditions::{Condition, ConditionOrigin, ConditionSet, ConditionVersion};
use herness_supervision::consent::{
    ConsentBlock, DisclosureDataKind, DisclosureScope, ProviderOrigin,
};
use herness_supervision::contract::{
    OwnerKind, OwnerRef, RunGroup, SupervisionSubject, same_approval_kind,
};
use herness_supervision::error::{ApprovalRejection, SupervisionError};
use herness_supervision::evidence::{
    CheckStatus, EvidenceAcquirer, EvidenceOutcome, EvidenceRecord, EvidenceScope,
    RequiredCheckResult, TargetScope, TargetVersion, VerificationOperation,
};
use herness_supervision::profiles::{ProfilePurpose, ProfileThresholds};
use herness_supervision::state::{
    CompletionBlocker, HumanAction, StopCause, SupervisionFailure, SupervisionRecord,
    SupervisionState,
};
use herness_supervision::version::{SUPERVISION_CONTRACT_VERSION, ensure_current_version};

use herness_supervision_tests::*;

fn project_set() -> (herness_core::contracts::ProjectId, Ids) {
    let project = project();
    (project, ids(project))
}

#[test]
fn fake_foreign_expired_and_stale_approvals_are_rejected() {
    let (project, _) = project_set();
    let set = condition_set(project);
    let human = human_approval(&set);

    let mut model_set = set.clone();
    assert!(matches!(
        model_set.approve(ApprovalActor::Model, human.clone(), now()),
        Err(SupervisionError::ApprovalRejected {
            reason: ApprovalRejection::ModelOrigin
        })
    ));

    let mut foreign_set = condition_set(other_project());
    assert!(matches!(
        foreign_set.approve(ApprovalActor::Human, human.clone(), now()),
        Err(SupervisionError::ApprovalRejected {
            reason: ApprovalRejection::ProjectMismatch
        })
    ));

    let mut expired_set = set.clone();
    let expired = herness_supervision::approval::ConditionApproval::new(
        project,
        herness_supervision::approval::ApprovalBasis::ExplicitHuman {
            approved_at: now(),
            expires_at: Some(Timestamp::from_unix_millis(NOW_MILLIS - 1)),
        },
        set.condition_version(),
        set.digest().clone(),
    )
    .expect("approval shape");
    assert!(matches!(
        expired_set.approve(ApprovalActor::Human, expired, now()),
        Err(SupervisionError::ApprovalRejected {
            reason: ApprovalRejection::Expired { .. }
        })
    ));

    let fixture_ids = ids(project);
    let altered_conditions = vec![
        Condition::new(
            fixture_ids.condition_a,
            "changed fixture condition",
            "Different content with the same version.",
            vec![fixture_ids.check_a],
            ConditionOrigin::Human,
        )
        .expect("condition"),
        conditions(fixture_ids)[1].clone(),
    ];
    let altered = ConditionSet::new(
        project,
        ConditionVersion::new(1).expect("version"),
        altered_conditions,
        checks(fixture_ids),
    )
    .expect("set");
    let mut stale_set = altered;
    assert!(matches!(
        stale_set.approve(ApprovalActor::Human, human.clone(), now()),
        Err(SupervisionError::ApprovalRejected {
            reason: ApprovalRejection::StaleDigest
        })
    ));

    let h3_owner = OwnerRef::new(OwnerKind::H3HtmlJob, "h3-fixture").expect("owner");
    assert!(matches!(
        herness_supervision::approval::ConditionApproval::new(
            project,
            herness_supervision::approval::ApprovalBasis::InheritedOwner {
                owner: h3_owner,
                source: herness_supervision::approval::OwnerApprovalSource::H4ApprovedPlan,
                approved_at: now(),
                expires_at: None,
            },
            set.condition_version(),
            set.digest().clone(),
        ),
        Err(SupervisionError::ApprovalRejected {
            reason: ApprovalRejection::SourceOwnerMismatch
        })
    ));

    let mut wrong_actor = set.clone();
    assert!(matches!(
        wrong_actor.approve(ApprovalActor::Human, owner_approval(&set), now()),
        Err(SupervisionError::ApprovalRejected {
            reason: ApprovalRejection::ActorMismatch
        })
    ));

    let mut approved = set.clone();
    approved
        .approve(ApprovalActor::Human, human.clone(), now())
        .expect("human approval succeeds");
    assert!(approved.is_approved(now()));
    assert!(human.basis().is_human());
    assert!(!same_approval_kind(
        human.basis(),
        owner_approval(&set).basis()
    ));

    let owner = OwnerRef::new(OwnerKind::H4SddTask, "task-6-fixture").expect("owner");
    let mut inherited = set;
    inherited
        .approve(
            ApprovalActor::ApprovedOwner {
                owner,
                source: herness_supervision::approval::OwnerApprovalSource::H4ApprovedPlan,
            },
            owner_approval(&inherited.clone()),
            now(),
        )
        .expect("inherited approval succeeds");
    assert!(inherited.is_approved(now()));
}

#[test]
fn model_origin_conditions_cannot_be_approved_or_changed_by_a_model() {
    let (project, fixture_ids) = project_set();
    let model_condition = Condition::new(
        fixture_ids.condition_a,
        "model-proposed condition",
        "A model proposed this and a human must confirm it.",
        vec![fixture_ids.check_a],
        ConditionOrigin::ModelProposal,
    )
    .expect("condition");
    let mut proposed = ConditionSet::new(
        project,
        ConditionVersion::new(1).expect("version"),
        vec![model_condition],
        vec![checks(fixture_ids)[0].clone()],
    )
    .expect("set");

    assert!(matches!(
        proposed.approve(ApprovalActor::Model, human_approval(&proposed), now()),
        Err(SupervisionError::ApprovalRejected {
            reason: ApprovalRejection::ModelOrigin
        })
    ));
    assert!(!proposed.is_approved(now()));
    proposed
        .approve(ApprovalActor::Human, human_approval(&proposed), now())
        .expect("a human can confirm a model proposal");

    let mut contract = contract(project);
    let set_v2 = approved_condition_set_at(project, 2);
    assert!(matches!(
        contract.revise_conditions(ApprovalActor::Model, set_v2.clone(), now()),
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));
    assert!(matches!(
        contract.revise_profile(ApprovalActor::Model, &completion_profile(project),),
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));
    assert!(matches!(
        contract.revise_budget(ApprovalActor::Model, BudgetPolicy::h2_default()),
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));
    assert!(matches!(
        contract.revise_permissions(ApprovalActor::Model, contract.execution_scope().clone(),),
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));

    let mut record = record(project);
    assert!(matches!(
        record.revise_conditions(
            ApprovalActor::Model,
            ConditionVersion::new(2).expect("version"),
            fixture_ids.into_condition_ids(),
            vec![fixture_ids.check_a, fixture_ids.check_b],
        ),
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));
    assert!(matches!(
        record.revise_target(
            ApprovalActor::Model,
            TargetVersion::new(2).expect("version"),
        ),
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));
    assert!(matches!(
        record.revise_consent(ApprovalActor::Model, contract.consent()),
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));
    assert!(matches!(
        herness_supervision::consent::DisclosureConsent::grant(
            ApprovalActor::Model,
            fixture_ids.consent,
            origin(),
            disclosure_scope(ProfilePurpose::Completion, 1),
            now(),
        ),
        Err(SupervisionError::ModelCannotApproveOrChange { .. })
    ));

    let foreign_owner = OwnerRef::new(OwnerKind::H4SddTask, "another-owner").expect("owner");
    assert!(matches!(
        contract.revise_budget(
            ApprovalActor::ApprovedOwner {
                owner: foreign_owner,
                source: herness_supervision::approval::OwnerApprovalSource::H4ApprovedPlan,
            },
            BudgetPolicy::h2_default(),
        ),
        Err(SupervisionError::ApprovalRejected {
            reason: ApprovalRejection::ActorMismatch
        })
    ));
}

#[test]
fn cross_project_ids_and_runs_are_rejected() {
    let (project, fixture_ids) = project_set();
    let other = other_project();

    assert!(matches!(
        SupervisionSubject::new(
            project,
            herness_supervision::ids::SupervisionId::new(other),
            AgentId::new(project),
            SessionId::new(project),
            OwnerRef::new(OwnerKind::Human, "human").expect("owner"),
        ),
        Err(SupervisionError::CrossProjectReference { .. })
    ));

    let mut group = RunGroup::new(fixture_ids.run_group);
    assert!(matches!(
        group.push(RunId::new(other)),
        Err(SupervisionError::CrossProjectReference { .. })
    ));
    assert!(!group.contains(&RunId::new(project)));

    assert!(matches!(
        SupervisionRequest::new(
            fixture_ids.request,
            herness_supervision::ids::SupervisionId::new(other),
            herness_supervision::command::SupervisionCommand::Start,
            1,
        ),
        Err(SupervisionError::CrossProjectReference { .. })
    ));

    let target = target_scope(other, 1);
    let evidence_id = fixture_ids.evidence_a;
    assert!(matches!(
        EvidenceRecord::new(
            evidence_id,
            fixture_ids.supervision,
            Some(fixture_ids.condition_a),
            Some(fixture_ids.check_a),
            EvidenceAcquirer::Ci,
            VerificationOperation::command("cargo test").expect("command"),
            EvidenceOutcome::new(Some(0), None, false, false, "ok").expect("outcome"),
            target,
            EvidenceScope::new(vec!["src/lib.rs".to_owned()], vec![]).expect("scope"),
            CheckStatus::Pass,
            1,
            now(),
        ),
        Err(SupervisionError::CrossProjectReference { .. })
    ));

    let mut record = record(project);
    assert!(matches!(
        record.revise_conditions(
            ApprovalActor::Human,
            ConditionVersion::new(2).expect("version"),
            vec![herness_supervision::ids::ConditionId::new(other)],
            vec![fixture_ids.check_a],
        ),
        Err(SupervisionError::CrossProjectReference { .. })
    ));
}

#[test]
fn condition_version_change_invalidates_decisions_and_completion() {
    let (project, fixture_ids) = project_set();
    let profile = completion_profile(project);
    let contract = contract(project);
    let mut record = SupervisionRecord::new(&contract);

    let set = approved_condition_set(project);
    let request_a = assessment_request(
        project,
        fixture_ids.condition_a,
        &profile,
        vec![fixture_ids.evidence_a],
    );
    let request_b = assessment_request(
        project,
        fixture_ids.condition_b,
        &profile,
        vec![fixture_ids.evidence_b],
    );
    assert_eq!(
        record
            .apply_assessment(
                &assessment_result(
                    &request_a,
                    ConditionVerdict::Met,
                    vec![fixture_ids.evidence_a]
                ),
                profile.thresholds(),
            )
            .expect("apply"),
        herness_supervision::state::AssessmentApplication::Applied
    );
    assert_eq!(
        record
            .apply_assessment(
                &assessment_result(
                    &request_b,
                    ConditionVerdict::Met,
                    vec![fixture_ids.evidence_b]
                ),
                profile.thresholds(),
            )
            .expect("apply"),
        herness_supervision::state::AssessmentApplication::Applied
    );
    assert!(record.unmet_conditions().is_empty());
    record
        .complete(completion_snapshot(&contract))
        .expect("completion before the change");
    assert_eq!(record.state(), SupervisionState::Completed);
    assert!(record.completion().is_some());

    record
        .revise_conditions(
            ApprovalActor::Human,
            ConditionVersion::new(2).expect("version"),
            set.condition_ids(),
            set.checks().iter().map(|check| check.id()).collect(),
        )
        .expect("human condition change");
    assert_eq!(record.state(), SupervisionState::WaitingHuman);
    assert!(matches!(
        record.reason(),
        herness_supervision::state::SupervisionReason::ConditionsChanged { .. }
    ));
    assert!(record.completion().is_none());
    assert!(record.applied_decisions().is_empty());
    assert_eq!(record.invalidated_decisions().len(), 2);
    assert_eq!(record.unmet_conditions().len(), 2);

    let old_snapshot = completion_snapshot(&contract);
    assert!(matches!(
        record.complete(old_snapshot),
        Err(SupervisionError::CompletionBlocked { blockers })
            if blockers.contains(&CompletionBlocker::StaleSnapshot)
    ));

    assert_eq!(
        record
            .apply_assessment(
                &assessment_result(
                    &request_a,
                    ConditionVerdict::Met,
                    vec![fixture_ids.evidence_a]
                ),
                profile.thresholds(),
            )
            .expect("stale apply"),
        herness_supervision::state::AssessmentApplication::Stale
    );
    assert_eq!(record.invalidated_decisions().len(), 3);
    assert!(record.completion().is_none());
}

#[test]
fn consent_revocation_origin_purpose_scope_and_image_require_reconfirmation() {
    let (project, _) = project_set();
    let consent = consent(project, ProfilePurpose::Completion, 1);
    let same_scope = disclosure_request(
        project,
        ProfilePurpose::Completion,
        [DisclosureDataKind::Text, DisclosureDataKind::Code],
        1,
    );
    consent
        .authorize(&same_scope)
        .expect("same scope continuation");
    consent.authorize(&same_scope).expect("same scope repeats");

    let revoked = consent
        .revoke(
            ApprovalActor::Human,
            Timestamp::from_unix_millis(NOW_MILLIS + 1),
        )
        .expect("revoke");
    assert_eq!(revoked.authorize(&same_scope), Err(ConsentBlock::Revoked));
    assert!(ConsentBlock::Revoked.requires_reconfirmation());

    let different_origin = herness_supervision::consent::DisclosureRequest::new(
        project,
        other_origin(),
        ProfilePurpose::Completion,
        BTreeSet::from([DisclosureDataKind::Text]),
        TargetVersion::new(1).expect("version"),
    )
    .expect("request");
    assert_eq!(
        consent.authorize(&different_origin),
        Err(ConsentBlock::DifferentOrigin)
    );

    let different_purpose =
        disclosure_request(project, ProfilePurpose::Html, [DisclosureDataKind::Text], 1);
    assert_eq!(
        consent.authorize(&different_purpose),
        Err(ConsentBlock::DifferentPurpose)
    );

    let expanded = disclosure_request(
        project,
        ProfilePurpose::Completion,
        [DisclosureDataKind::Text, DisclosureDataKind::Log],
        1,
    );
    assert!(matches!(
        consent.authorize(&expanded),
        Err(ConsentBlock::ScopeExpanded { added }) if added == vec![DisclosureDataKind::Log]
    ));
    assert!(
        ConsentBlock::ScopeExpanded {
            added: vec![DisclosureDataKind::Log]
        }
        .requires_reconfirmation()
    );

    let image = disclosure_request(
        project,
        ProfilePurpose::Completion,
        [DisclosureDataKind::Text, DisclosureDataKind::Image],
        1,
    );
    assert_eq!(
        consent.authorize(&image),
        Err(ConsentBlock::ImageNotApproved)
    );

    let changed_target = disclosure_request(
        project,
        ProfilePurpose::Completion,
        [DisclosureDataKind::Text],
        2,
    );
    assert_eq!(
        consent.authorize(&changed_target),
        Err(ConsentBlock::TargetScopeChanged)
    );

    let contract = contract(project);
    assert_eq!(
        contract.authorize_disclosure(&revoked, &same_scope),
        Err(ConsentBlock::VersionMismatch)
    );
}

#[test]
fn empty_or_unbounded_disclosure_scope_is_invalid() {
    let (project, _) = project_set();
    assert!(matches!(
        DisclosureScope::new(
            ProfilePurpose::Completion,
            BTreeSet::new(),
            vec!["src/lib.rs".to_owned()],
            TargetVersion::new(1).expect("version"),
        ),
        Err(SupervisionError::ConsentBlocked {
            reason: ConsentBlock::EmptyScope
        })
    ));
    assert!(matches!(
        DisclosureScope::new(
            ProfilePurpose::Completion,
            BTreeSet::from([DisclosureDataKind::Text]),
            Vec::new(),
            TargetVersion::new(1).expect("version"),
        ),
        Err(SupervisionError::ConsentBlocked {
            reason: ConsentBlock::EmptyScope
        })
    ));
    for target in ["*", "**", ".", "/", "src/../secret"] {
        assert!(matches!(
            DisclosureScope::new(
                ProfilePurpose::Completion,
                BTreeSet::from([DisclosureDataKind::Text]),
                vec![target.to_owned()],
                TargetVersion::new(1).expect("version"),
            ),
            Err(SupervisionError::ConsentBlocked {
                reason: ConsentBlock::UnboundedScope
            })
        ));
    }
    assert!(matches!(
        herness_supervision::consent::DisclosureRequest::new(
            project,
            origin(),
            ProfilePurpose::Completion,
            BTreeSet::new(),
            TargetVersion::new(1).expect("version"),
        ),
        Err(SupervisionError::ConsentBlocked {
            reason: ConsentBlock::EmptyScope
        })
    ));
    assert!(
        herness_supervision::consent::ProviderOrigin::parse(
            "https://user:password@assessment.example.test"
        )
        .is_err()
    );
}

#[test]
fn duplicate_request_id_returns_the_same_result_without_a_second_mutation() {
    let (project, fixture_ids) = project_set();
    let memory = MemorySupervisionStore::with_record(record(project));
    let mut store = memory;
    let request = SupervisionRequest::new(
        fixture_ids.request,
        fixture_ids.supervision,
        herness_supervision::command::SupervisionCommand::Start,
        1,
    )
    .expect("request");

    let mut calls = 0;
    let first = {
        let calls_ref = &mut calls;
        execute_command(&mut store, request, |current| {
            *calls_ref += 1;
            let mut next = current.clone();
            next.begin_run(RunId::new(project))?;
            Ok(next)
        })
        .expect("first command")
    };
    assert_eq!(first.state(), SupervisionState::Running);
    assert_eq!(first.revision(), 2);
    assert_eq!(calls, 1);
    assert_eq!(store.mutations, 1);
    assert_eq!(store.swaps, 1);

    let second = execute_command(&mut store, request, |_current| {
        calls += 1;
        panic!("a duplicate request must not apply the mutation twice");
    })
    .expect("duplicate command");
    assert_eq!(second, first);
    assert_eq!(calls, 1);
    assert_eq!(store.mutations, 1);
    assert_eq!(store.swaps, 1);

    let conflicting = SupervisionRequest::new(
        fixture_ids.request,
        fixture_ids.supervision,
        herness_supervision::command::SupervisionCommand::Stop,
        1,
    )
    .expect("request");
    assert!(matches!(
        execute_command(&mut store, conflicting, |_| panic!("must not run")),
        Err(SupervisionError::DuplicateRequestConflict { .. })
    ));

    let stale = SupervisionRequest::new(
        herness_supervision::ids::SupervisionRequestId::new(project),
        fixture_ids.supervision,
        herness_supervision::command::SupervisionCommand::Reassess,
        1,
    )
    .expect("request");
    assert!(matches!(
        execute_command(&mut store, stale, |_| panic!("must not run")),
        Err(SupervisionError::RevisionConflict { .. })
    ));
    assert_eq!(store.mutations, 1);
}

#[test]
fn budget_defaults_finite_money_and_human_wait_exclusion_are_validated() {
    let policy = BudgetPolicy::h2_default();
    assert_eq!(policy.active_seconds(), H2_ACTIVE_SECONDS);
    assert_eq!(policy.additional_runs(), H2_ADDITIONAL_RUNS);
    assert_eq!(policy.max_total_runs(), H2_MAX_TOTAL_RUNS);
    assert_eq!(policy.max_total_runs(), 31);
    assert!(policy.money_cap().is_none());

    let empty = BudgetUsage::empty();
    assert_eq!(empty.remaining_active_seconds(&policy), H2_ACTIVE_SECONDS);
    assert!(empty.permits_run_start(&policy));
    let at_cap = BudgetUsage::new(0, 0, 30, 0, Money::zero(), Money::zero());
    assert!(at_cap.permits_run_start(&policy));
    let over = BudgetUsage::new(0, 0, 31, 0, Money::zero(), Money::zero());
    assert!(!over.permits_run_start(&policy));
    let reserved_over = BudgetUsage::new(0, 0, 30, 1, Money::zero(), Money::zero());
    assert!(!reserved_over.permits_run_start(&policy));
    let used = BudgetUsage::new(100, 50, 1, 0, Money::zero(), Money::zero());
    assert_eq!(used.remaining_active_seconds(&policy), 7_050);

    assert_eq!(billed_active_seconds(BudgetClockState::Active, 10), 10);
    assert_eq!(billed_active_seconds(BudgetClockState::WaitingHuman, 10), 0);
    assert_eq!(billed_active_seconds(BudgetClockState::Paused, 10), 0);
    assert_eq!(billed_active_seconds(BudgetClockState::AppStopped, 10), 0);

    assert!(BudgetPolicy::new(0, 30, None).is_err());
    assert!(Money::usd(f64::NAN).is_err());
    assert!(Money::usd(f64::INFINITY).is_err());
    assert!(Money::usd(-0.01).is_err());
    let price = PriceVersion::new("fixture-price-2026-11-08").expect("price");
    assert!(MoneyCap::new(Money::zero(), price.clone()).is_err());
    assert!(PriceVersion::new("   ").is_err());

    let cap = MoneyCap::new(Money::usd(2.50).expect("amount"), price).expect("cap");
    let capped = BudgetPolicy::new(7_200, 30, Some(cap)).expect("policy");
    assert!(!chatgpt_login_allowed_with_money_cap(&capped));
    assert!(chatgpt_login_allowed_with_money_cap(&policy));
    let usage = BudgetUsage::new(0, 0, 1, 0, Money::usd(1.0).expect("money"), Money::zero());

    assert!(matches!(
        validate_assessment_spend(&capped, &usage, None, 60),
        Err(SupervisionError::BudgetInvalid { .. })
    ));
    validate_assessment_spend(&capped, &usage, Some(Money::usd(1.0).expect("money")), 60)
        .expect("within cap");
    assert!(
        validate_assessment_spend(&capped, &usage, Some(Money::usd(1.51).expect("money")), 60,)
            .is_err()
    );
    assert!(validate_assessment_spend(&policy, &usage, None, 7_201).is_err());
    assert_eq!(assessment_timeout_seconds(&policy, &empty), 60);
    let nearly_exhausted = BudgetUsage::new(7_190, 0, 1, 0, Money::zero(), Money::zero());
    assert_eq!(assessment_timeout_seconds(&policy, &nearly_exhausted), 10);

    assert!(
        serde_json::from_str::<ProviderOrigin>(
            r#"{"scheme":"https","host":"bad/path","port":443}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<BudgetPolicy>(
            r#"{"activeSeconds":0,"additionalRuns":30,"moneyCap":null}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<herness_supervision::evidence::ContentDigest>(r#""not-a-digest""#)
            .is_err()
    );
}

#[test]
fn required_check_results_distinguish_non_pass_states() {
    let statuses = [
        CheckStatus::Pass,
        CheckStatus::Fail,
        CheckStatus::NotRun,
        CheckStatus::Unavailable,
        CheckStatus::Inconclusive,
    ];
    for status in statuses {
        assert_eq!(status.is_pass(), status == CheckStatus::Pass);
    }

    let (project, fixture_ids) = project_set();
    assert!(matches!(
        RequiredCheckResult::new(
            fixture_ids.check_a,
            fixture_ids.condition_a,
            CheckStatus::Pass,
            None,
            ConditionVersion::new(1).expect("version"),
            TargetVersion::new(1).expect("version"),
            now(),
        ),
        Err(SupervisionError::EvidenceContractViolation { .. })
    ));

    let inconclusive = evidence(
        project,
        fixture_ids,
        fixture_ids.evidence_a,
        fixture_ids.check_a,
        fixture_ids.condition_a,
        CheckStatus::Inconclusive,
        1,
    );
    assert_eq!(inconclusive.outcome().exit_code(), Some(0));
    assert!(!inconclusive.status().is_pass());
    let result = check_result(&inconclusive, ConditionVersion::new(1).expect("version"));
    assert_eq!(result.status(), CheckStatus::Inconclusive);
    assert!(!result.is_pass());

    let not_run = EvidenceRecord::new(
        fixture_ids.evidence_b,
        fixture_ids.supervision,
        Some(fixture_ids.condition_b),
        Some(fixture_ids.check_b),
        EvidenceAcquirer::Human,
        VerificationOperation::equivalent("manual fixture inspection").expect("operation"),
        EvidenceOutcome::new(Some(0), None, false, false, "operation reported success")
            .expect("outcome"),
        target_scope(project, 1),
        EvidenceScope::new(vec!["src/lib.rs".to_owned()], vec![]).expect("scope"),
        CheckStatus::NotRun,
        2,
        now(),
    )
    .expect("evidence");
    assert_ne!(not_run.status(), CheckStatus::Pass);

    assert!(EvidenceOutcome::new(None, None, false, false, " ").is_err());
    assert!(VerificationOperation::command(" ").is_err());
    assert!(EvidenceScope::new(Vec::new(), Vec::new()).is_err());
    assert!(matches!(
        TargetScope::new(
            project,
            TargetVersion::new(1).expect("version"),
            vec!["src/lib.rs".to_owned()],
            Vec::new(),
        ),
        Err(SupervisionError::EvidenceContractViolation { .. })
    ));
}

#[test]
fn stopped_waiting_limit_and_failure_override_completion() {
    let (project, fixture_ids) = project_set();
    let profile = completion_profile(project);
    let contract = contract(project);
    let snapshot = completion_snapshot(&contract);

    let mut record = SupervisionRecord::new(&contract);
    assert_eq!(record.state(), SupervisionState::Ready);
    assert_eq!(record.unmet_conditions().len(), 2);
    assert!(matches!(
        record.complete(snapshot.clone()),
        Err(SupervisionError::CompletionBlocked { blockers })
            if blockers.iter().any(|blocker| matches!(blocker, CompletionBlocker::UnmetConditions { .. }))
    ));

    let request_a = assessment_request(
        project,
        fixture_ids.condition_a,
        &profile,
        vec![fixture_ids.evidence_a],
    );
    let request_b = assessment_request(
        project,
        fixture_ids.condition_b,
        &profile,
        vec![fixture_ids.evidence_b],
    );
    record
        .apply_assessment(
            &assessment_result(
                &request_a,
                ConditionVerdict::Met,
                vec![fixture_ids.evidence_a],
            ),
            profile.thresholds(),
        )
        .expect("apply");
    record
        .apply_assessment(
            &assessment_result(
                &request_b,
                ConditionVerdict::Met,
                vec![fixture_ids.evidence_b],
            ),
            profile.thresholds(),
        )
        .expect("apply");
    assert!(record.unmet_conditions().is_empty());

    let missing_checks = herness_supervision::state::CompletionSnapshot::new(
        contract.conditions().condition_version(),
        contract.evidence_target().version(),
        contract.profile(),
        contract.consent(),
        Vec::new(),
        vec![fixture_ids.evidence_a],
        herness_supervision::evidence::ContentDigest::sha256(b"fixture observations"),
        now(),
    )
    .expect("snapshot shape");
    assert!(matches!(
        record.complete(missing_checks),
        Err(SupervisionError::CompletionBlocked { blockers })
            if blockers.iter().any(|blocker| matches!(blocker, CompletionBlocker::RequiredChecksNotPassed { .. }))
    ));

    record
        .wait_for_human(HumanAction::DecideAssessment)
        .expect("wait");
    assert!(matches!(
        record.complete(snapshot.clone()),
        Err(SupervisionError::CompletionBlocked { blockers })
            if blockers.iter().any(|blocker| matches!(blocker, CompletionBlocker::HumanAction { .. }))
    ));
    assert_eq!(record.state(), SupervisionState::WaitingHuman);

    record
        .stop(StopCause::Budget(BudgetLimit::RunCount))
        .expect("stop");
    assert!(matches!(
        record.complete(snapshot.clone()),
        Err(SupervisionError::CompletionBlocked { blockers })
            if blockers.iter().any(|blocker| matches!(blocker, CompletionBlocker::Limit {
                limit: BudgetLimit::RunCount
            }))
    ));
    assert_eq!(record.state(), SupervisionState::Stopped);

    record
        .fail(SupervisionFailure::UnrecoverableRecovery)
        .expect("fail");
    assert!(matches!(
        record.complete(snapshot.clone()),
        Err(SupervisionError::CompletionBlocked { blockers })
            if blockers.iter().any(|blocker| matches!(blocker, CompletionBlocker::Unrecoverable { .. }))
    ));
    assert_eq!(record.state(), SupervisionState::Failed);

    record
        .cancel(herness_supervision::state::CancelCause::UserRequest)
        .expect("cancel");
    assert!(matches!(
        record.complete(snapshot),
        Err(SupervisionError::CompletionBlocked { blockers })
            if blockers.iter().any(|blocker| matches!(blocker, CompletionBlocker::State {
                state: SupervisionState::Cancelled
            }))
    ));
    assert_eq!(record.state(), SupervisionState::Cancelled);
}

#[test]
fn state_and_reason_are_representable_and_versioned() {
    let (project, fixture_ids) = project_set();
    let contract = contract(project);
    assert_eq!(contract.contract_version(), ContractVersion::V2);
    assert_eq!(SUPERVISION_CONTRACT_VERSION, 2);
    assert!(ensure_current_version(ContractVersion::V2).is_ok());
    assert!(matches!(
        ensure_current_version(ContractVersion::V1),
        Err(SupervisionError::UnsupportedContractVersion { .. })
    ));

    let mut record = SupervisionRecord::new(&contract);
    assert_eq!(record.reason().state(), SupervisionState::Ready);
    assert_eq!(record.condition_version(), set_version(1));
    assert_eq!(
        record.target_version(),
        TargetVersion::new(1).expect("version")
    );
    assert_eq!(record.run_group().id(), fixture_ids.run_group);

    assert!(matches!(
        record.set_state(
            SupervisionState::Running,
            herness_supervision::state::SupervisionReason::AwaitingStart
        ),
        Err(SupervisionError::InvalidStateReason { .. })
    ));

    record.begin_run(RunId::new(project)).expect("begin run");
    assert_eq!(record.state(), SupervisionState::Running);
    assert_eq!(record.reason().state(), SupervisionState::Running);

    record
        .begin_verification(vec![fixture_ids.check_a])
        .expect("verify");
    assert_eq!(record.state(), SupervisionState::Verifying);
    record
        .begin_assessment(vec![fixture_ids.condition_a])
        .expect("assess");
    assert_eq!(record.state(), SupervisionState::Assessing);

    let json = serde_json::to_string(&record).expect("serialize record");
    let decoded: SupervisionRecord = serde_json::from_str(&json).expect("deserialize record");
    assert_eq!(decoded, record);

    let contract_json = serde_json::to_string(&contract).expect("serialize contract");
    let decoded_contract: herness_supervision::contract::SupervisionContract =
        serde_json::from_str(&contract_json).expect("deserialize contract");
    assert_eq!(decoded_contract, contract);

    assert_eq!(SupervisionState::ALL.len(), 9);
    for state in SupervisionState::ALL {
        if state != SupervisionState::Completed {
            assert!(!state.as_str().is_empty());
            assert_eq!(
                state.blocks_completion(),
                matches!(
                    state,
                    SupervisionState::WaitingHuman
                        | SupervisionState::Stopped
                        | SupervisionState::Failed
                        | SupervisionState::Cancelled
                )
            );
        }
    }
}

#[test]
fn permission_ask_uncertainty_and_low_probability_never_authorize_execution() {
    let thresholds = ProfileThresholds::decisions();
    let allow = PermissionAssessment::Decision {
        selected: PermissionVerdict::Allow,
        probabilities: herness_supervision::assessment::PermissionProbabilities::new(
            0.99, 0.005, 0.005,
        )
        .expect("distribution"),
    };
    assert_eq!(
        allow.adopted_verdict(thresholds),
        Some(PermissionVerdict::Allow)
    );
    assert!(allow.allows_execution(thresholds));

    let below = PermissionAssessment::Decision {
        selected: PermissionVerdict::Allow,
        probabilities: herness_supervision::assessment::PermissionProbabilities::new(
            0.989, 0.005, 0.006,
        )
        .expect("distribution"),
    };
    assert_eq!(below.adopted_verdict(thresholds), None);
    assert!(!below.allows_execution(thresholds));

    let ask = PermissionAssessment::Decision {
        selected: PermissionVerdict::Ask,
        probabilities: herness_supervision::assessment::PermissionProbabilities::new(
            0.10, 0.10, 0.80,
        )
        .expect("distribution"),
    };
    assert_eq!(ask.adopted_verdict(thresholds), None);
    assert!(!ask.allows_execution(thresholds));

    let uncertain = PermissionAssessment::NormalLlm {
        verdict: PermissionVerdict::Allow,
        uncertain: true,
    };
    assert_eq!(
        uncertain.adopted_verdict(ProfileThresholds::normal_llm()),
        None
    );
    assert!(!uncertain.allows_execution(ProfileThresholds::normal_llm()));
}

fn set_version(version: u64) -> ConditionVersion {
    ConditionVersion::new(version).expect("version")
}

trait IntoConditionIds {
    fn into_condition_ids(self) -> Vec<herness_supervision::ids::ConditionId>;
}

impl IntoConditionIds for Ids {
    fn into_condition_ids(self) -> Vec<herness_supervision::ids::ConditionId> {
        vec![self.condition_a, self.condition_b]
    }
}
