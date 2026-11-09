//! Synthetic H2 fixtures shared by the supervision contract tests.
//!
//! Every value is local and deterministic. No credential, real provider body,
//! production endpoint, or user conversation is included.

pub mod fixtures;

use std::collections::{BTreeMap, BTreeSet};

use herness_core::ConnectionSettings;
use herness_core::contracts::{
    AgentId, AuthMethod, ConnectionCapabilities, ConnectionId, ConnectionStatus, ConnectionUsage,
    EndpointClass, InputCapabilities, ModelId, ProjectId, Provider, SessionId, Timestamp,
};
use herness_supervision::approval::{
    ApprovalActor, ApprovalBasis, ConditionApproval, OwnerApprovalSource,
};
use herness_supervision::assessment::{
    AssessmentOutcome, AssessmentProvenance, AssessmentRequest, AssessmentResult,
    ConditionProbabilities, ConditionVerdict, NativeConfidence,
};
use herness_supervision::budget::BudgetPolicy;
use herness_supervision::command::CommandResult;
use herness_supervision::conditions::{
    Condition, ConditionOrigin, ConditionSet, ConditionVersion, RequiredCheck,
};
use herness_supervision::consent::{
    DisclosureConsent, DisclosureDataKind, DisclosureRequest, DisclosureScope, ProviderOrigin,
};
use herness_supervision::contract::{
    ExecutionScope, OwnerKind, OwnerRef, RunGroup, SupervisionContract, SupervisionSubject,
};
use herness_supervision::error::SupervisionError;
use herness_supervision::evidence::{
    CheckStatus, ContentDigest, ContentFingerprint, EvidenceAcquirer, EvidenceOutcome,
    EvidenceRecord, EvidenceScope, RequiredCheckResult, TargetScope, TargetVersion,
    VerificationOperation,
};
use herness_supervision::ids::{
    CheckId, ConditionId, ConsentId, DecisionId, EvidenceId, ProfileId, RunGroupId, SupervisionId,
    SupervisionRequestId,
};
use herness_supervision::owner_launch::{OwnerApproval, OwnerApprovalRegistryPort};
use herness_supervision::ports::{ClockPort, SupervisionStorePort};
use herness_supervision::profiles::{
    AdapterVersion, AssessmentProfile, ProfileCatalog, ProfileEntry, ProfileInputs, ProfilePurpose,
    ProfileThresholds, ProfileVersion, ProviderKind, RubricVersion,
};
use herness_supervision::state::{CompletionSnapshot, SupervisionRecord};
use herness_supervision::WorkPacket;

/// Deterministic project UUID used by every fixture.
pub const PROJECT_UUID: &str = "11111111-1111-4111-8111-111111111111";
/// A second project used to prove cross-project rejection.
pub const OTHER_PROJECT_UUID: &str = "22222222-2222-4222-8222-222222222222";
/// Fixed fixture time in unix milliseconds.
pub const NOW_MILLIS: u64 = 1_700_000_000_000;

/// Primary fixture project.
pub fn project() -> ProjectId {
    PROJECT_UUID.parse().expect("fixture project")
}

/// Another fixture project.
pub fn other_project() -> ProjectId {
    OTHER_PROJECT_UUID.parse().expect("fixture project")
}

/// Fixed fixture time.
pub fn now() -> Timestamp {
    Timestamp::from_unix_millis(NOW_MILLIS)
}

/// A host clock that always returns the fixture time.
#[derive(Debug, Clone, Copy, Default)]
pub struct FixedClock;

impl ClockPort for FixedClock {
    fn now(&self) -> Timestamp {
        now()
    }
}

/// A deliberately scripted, in-memory implementation of the host owner
/// approval registry port.
///
/// This exists only for the H2 contract tests. It is not an H3 registry and
/// must never be used as production approval data: Task 14 supplies the real H3
/// settings registry. Tests insert, replace, or remove an entry explicitly so a
/// missing, stale, or mismatched registry value is observable.
#[derive(Debug, Default)]
pub struct ScriptedOwnerApprovalRegistry {
    entries: BTreeMap<(ProjectId, OwnerRef), OwnerApproval>,
}

impl ScriptedOwnerApprovalRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces the current entry for one project and owner.
    pub fn insert(&mut self, approval: OwnerApproval) {
        self.entries.insert(
            (approval.project_id(), approval.owner().clone()),
            approval,
        );
    }

    /// Removes the current entry for one project and owner.
    pub fn remove(&mut self, project_id: ProjectId, owner: &OwnerRef) -> Option<OwnerApproval> {
        self.entries.remove(&(project_id, owner.clone()))
    }
}

impl OwnerApprovalRegistryPort for ScriptedOwnerApprovalRegistry {
    fn current_owner_approval(
        &self,
        project_id: ProjectId,
        owner: &OwnerRef,
        _now: Timestamp,
    ) -> Result<Option<OwnerApproval>, SupervisionError> {
        Ok(self
            .entries
            .get(&(project_id, owner.clone()))
            .cloned())
    }
}

/// All stable fixture IDs for one project.
#[derive(Debug, Clone, Copy)]
pub struct Ids {
    /// Supervision target.
    pub supervision: SupervisionId,
    /// First condition.
    pub condition_a: ConditionId,
    /// Second condition.
    pub condition_b: ConditionId,
    /// First required check.
    pub check_a: CheckId,
    /// Second required check.
    pub check_b: CheckId,
    /// First evidence item.
    pub evidence_a: EvidenceId,
    /// Second evidence item.
    pub evidence_b: EvidenceId,
    /// Decision request/result.
    pub decision: DecisionId,
    /// Run group.
    pub run_group: RunGroupId,
    /// Consent record.
    pub consent: ConsentId,
    /// Completion profile.
    pub profile: ProfileId,
    /// Permission profile.
    pub permission_profile: ProfileId,
    /// Idempotent command request.
    pub request: SupervisionRequestId,
}

/// Builds deterministic IDs for `project`.
pub fn ids(project: ProjectId) -> Ids {
    let local = |seed: &str| uuid::Uuid::parse_str(seed).expect("fixture uuid");
    Ids {
        supervision: SupervisionId::from_parts(
            project,
            local("10000000-0000-4000-8000-000000000001"),
        ),
        condition_a: ConditionId::from_parts(
            project,
            local("10000000-0000-4000-8000-000000000002"),
        ),
        condition_b: ConditionId::from_parts(
            project,
            local("10000000-0000-4000-8000-000000000003"),
        ),
        check_a: CheckId::from_parts(project, local("10000000-0000-4000-8000-000000000004")),
        check_b: CheckId::from_parts(project, local("10000000-0000-4000-8000-000000000005")),
        evidence_a: EvidenceId::from_parts(project, local("10000000-0000-4000-8000-000000000006")),
        evidence_b: EvidenceId::from_parts(project, local("10000000-0000-4000-8000-000000000007")),
        decision: DecisionId::from_parts(project, local("10000000-0000-4000-8000-000000000008")),
        run_group: RunGroupId::from_parts(project, local("10000000-0000-4000-8000-000000000009")),
        consent: ConsentId::from_parts(project, local("10000000-0000-4000-8000-00000000000a")),
        profile: ProfileId::from_parts(project, local("10000000-0000-4000-8000-00000000000b")),
        permission_profile: ProfileId::from_parts(
            project,
            local("10000000-0000-4000-8000-00000000000c"),
        ),
        request: SupervisionRequestId::from_parts(
            project,
            local("10000000-0000-4000-8000-00000000000d"),
        ),
    }
}

/// A synthetic provider origin with no credential material.
pub fn origin() -> ProviderOrigin {
    ProviderOrigin::parse("https://assessment.example.test").expect("fixture origin")
}

/// A different synthetic origin.
pub fn other_origin() -> ProviderOrigin {
    ProviderOrigin::parse("https://other-assessment.example.test").expect("fixture origin")
}

/// A synthetic normal-LLM connection capability set.
pub fn normal_connection() -> ConnectionCapabilities {
    ConnectionCapabilities::new(
        ConnectionId::new(),
        Provider::OpenAiCompatible,
        AuthMethod::ApiKey,
        EndpointClass::OpenAiCompletions,
        InputCapabilities::text_and_image(),
        ConnectionUsage::AgentExecution,
    )
    .expect("fixture connection")
}

/// A synthetic Jev connection capability set.
pub fn jev_connection() -> ConnectionCapabilities {
    ConnectionCapabilities::new(
        ConnectionId::new(),
        Provider::TypeSafe,
        AuthMethod::ApiKey,
        EndpointClass::TypeSafeSystemOne,
        InputCapabilities::text_only(),
        ConnectionUsage::AssessmentOnly,
    )
    .expect("fixture connection")
}

/// A synthetic Decisions connection capability set.
pub fn decisions_connection() -> ConnectionCapabilities {
    ConnectionCapabilities::new(
        ConnectionId::new(),
        Provider::OpenAi,
        AuthMethod::ApiKey,
        EndpointClass::OpenAiDecisions,
        InputCapabilities::text_only(),
        ConnectionUsage::AssessmentOnly,
    )
    .expect("fixture connection")
}

/// Required checks for the fixture conditions.
pub fn checks(ids: Ids) -> Vec<RequiredCheck> {
    vec![
        RequiredCheck::new(
            ids.check_a,
            ids.condition_a,
            VerificationOperation::command("cargo test -p fixture-app --locked").expect("command"),
            "the fixture test suite passes",
        )
        .expect("check"),
        RequiredCheck::new(
            ids.check_b,
            ids.condition_b,
            VerificationOperation::command("cargo clippy -p fixture-app --locked")
                .expect("command"),
            "the fixture lint pass is clean",
        )
        .expect("check"),
    ]
}

/// Conditions in the fixture set.
pub fn conditions(ids: Ids) -> Vec<Condition> {
    vec![
        Condition::new(
            ids.condition_a,
            "fixture tests pass",
            "Every test named in the fixture rubric passes with exit code 0 and no truncation.",
            vec![ids.check_a],
            ConditionOrigin::Human,
        )
        .expect("condition"),
        Condition::new(
            ids.condition_b,
            "fixture lint is clean",
            "Clippy reports no warnings for the fixture package.",
            vec![ids.check_b],
            ConditionOrigin::Human,
        )
        .expect("condition"),
    ]
}

/// An unapproved fixture condition set at version 1.
pub fn condition_set(project: ProjectId) -> ConditionSet {
    condition_set_at(project, 1)
}

/// An unapproved fixture condition set at `version`.
pub fn condition_set_at(project: ProjectId, version: u64) -> ConditionSet {
    let ids = ids(project);
    ConditionSet::new(
        project,
        ConditionVersion::new(version).expect("version"),
        conditions(ids),
        checks(ids),
    )
    .expect("condition set")
}

/// A human approval bound to the exact fixture condition set.
pub fn human_approval(set: &ConditionSet) -> ConditionApproval {
    ConditionApproval::new(
        set.project_id(),
        ApprovalBasis::ExplicitHuman {
            approved_at: now(),
            expires_at: None,
        },
        set.condition_version(),
        set.digest().clone(),
    )
    .expect("human approval")
}

/// An inherited H4 owner approval bound to the exact fixture condition set.
pub fn owner_approval(set: &ConditionSet) -> ConditionApproval {
    let owner = OwnerRef::new(OwnerKind::H4SddTask, "task-6-fixture").expect("owner");
    ConditionApproval::new(
        set.project_id(),
        ApprovalBasis::InheritedOwner {
            owner,
            source: herness_supervision::approval::OwnerApprovalSource::H4ApprovedPlan,
            approved_at: now(),
            expires_at: None,
        },
        set.condition_version(),
        set.digest().clone(),
    )
    .expect("owner approval")
}

/// A condition set approved by a human.
pub fn approved_condition_set(project: ProjectId) -> ConditionSet {
    approved_condition_set_at(project, 1)
}

/// A condition set at `version` approved by a human.
pub fn approved_condition_set_at(project: ProjectId, version: u64) -> ConditionSet {
    let mut set = condition_set_at(project, version);
    let approval = human_approval(&set);
    set.approve(ApprovalActor::Human, approval, now())
        .expect("approval");
    set
}

/// Target scope at version `version`.
pub fn target_scope(project: ProjectId, version: u64) -> TargetScope {
    TargetScope::new(
        project,
        TargetVersion::new(version).expect("target version"),
        vec!["src/lib.rs".to_owned(), "Cargo.toml".to_owned()],
        vec![
            ContentFingerprint::new("src/lib.rs", ContentDigest::sha256(b"fixture source"))
                .expect("fingerprint"),
            ContentFingerprint::new("Cargo.toml", ContentDigest::sha256(b"fixture manifest"))
                .expect("fingerprint"),
        ],
    )
    .expect("target scope")
}

/// Normal-LLM completion profile bound to `connection`.
pub fn completion_profile_for(project: ProjectId, connection: ConnectionId) -> AssessmentProfile {
    let ids = ids(project);
    AssessmentProfile::new(
        ids.profile,
        ProfileVersion::new(1).expect("version"),
        ProfilePurpose::Completion,
        ProviderKind::NormalLlm,
        connection,
        ModelId::new("synthetic-completion-judge").expect("model"),
        AdapterVersion::new("fixture-llm-adapter-1").expect("adapter"),
        RubricVersion::new("fixture-rubric-1").expect("rubric"),
        ProfileInputs::new(true, true, true),
        ProfileThresholds::normal_llm(),
    )
    .expect("completion profile")
}

/// Normal-LLM completion profile using a fresh synthetic connection.
pub fn completion_profile(project: ProjectId) -> AssessmentProfile {
    completion_profile_for(project, normal_connection().connection_id())
}

/// Normal-LLM completion profile with an explicit connection, model, and
/// required inputs.
pub fn llm_completion_profile_for(
    project: ProjectId,
    connection: ConnectionId,
    model: &str,
    required_inputs: ProfileInputs,
) -> AssessmentProfile {
    let ids = ids(project);
    AssessmentProfile::new(
        ids.profile,
        ProfileVersion::new(1).expect("version"),
        ProfilePurpose::Completion,
        ProviderKind::NormalLlm,
        connection,
        ModelId::new(model).expect("model"),
        AdapterVersion::new("fixture-llm-adapter-1").expect("adapter"),
        RubricVersion::new("fixture-rubric-1").expect("rubric"),
        required_inputs,
        ProfileThresholds::normal_llm(),
    )
    .expect("completion profile")
}

/// Profile entry whose profile and connection are the registered settings.
pub fn llm_profile_entry(
    settings: &ConnectionSettings,
    profile: AssessmentProfile,
    structured_output: bool,
) -> ProfileEntry {
    ProfileEntry::new(
        profile,
        settings.capabilities().expect("connection capabilities"),
        ConnectionStatus::Available,
        structured_output,
    )
}

/// Jev completion profile at `version` with the fixture adapter/rubric.
pub fn jev_completion_profile_for(
    project: ProjectId,
    connection: ConnectionId,
    model: &str,
    version: u64,
) -> AssessmentProfile {
    jev_completion_profile_with_inputs(
        project,
        connection,
        model,
        version,
        ProfileInputs::text_only(),
    )
}

/// Jev completion profile with explicit required inputs.
pub fn jev_completion_profile_with_inputs(
    project: ProjectId,
    connection: ConnectionId,
    model: &str,
    version: u64,
    required_inputs: ProfileInputs,
) -> AssessmentProfile {
    let ids = ids(project);
    AssessmentProfile::new(
        ids.profile,
        ProfileVersion::new(version).expect("version"),
        ProfilePurpose::Completion,
        ProviderKind::Jev,
        connection,
        ModelId::new(model).expect("model"),
        AdapterVersion::new("fixture-jev-adapter-1").expect("adapter"),
        RubricVersion::new("fixture-jev-rubric-1").expect("rubric"),
        required_inputs,
        ProfileThresholds::decisions(),
    )
    .expect("jev completion profile")
}

/// Profile entry for a Jev profile and its registered connection.
pub fn jev_profile_entry(
    settings: &ConnectionSettings,
    profile: AssessmentProfile,
) -> ProfileEntry {
    ProfileEntry::new(
        profile,
        settings.capabilities().expect("connection capabilities"),
        ConnectionStatus::Available,
        false,
    )
}

/// A per-condition Jev assessment request.
pub fn jev_assessment_request(
    project: ProjectId,
    condition: ConditionId,
    profile: &AssessmentProfile,
    evidence_ids: Vec<EvidenceId>,
) -> AssessmentRequest {
    let ids = ids(project);
    AssessmentRequest::new(
        ids.decision,
        ids.supervision,
        condition,
        ConditionVersion::new(1).expect("version"),
        TargetVersion::new(1).expect("version"),
        "The fixture condition is met when the recorded check passes.",
        profile.binding(),
        AdapterVersion::new("fixture-jev-adapter-1").expect("adapter"),
        RubricVersion::new("fixture-jev-rubric-1").expect("rubric"),
        evidence_ids,
    )
    .expect("jev assessment request")
}

/// Synthetic Jev choice answer.
pub fn jev_choice_answer(
    choice: &str,
    met: f64,
    unmet: f64,
    insufficient: f64,
    confidence: f64,
) -> serde_json::Value {
    serde_json::json!({
        "type": "choice",
        "choice": choice,
        "confidence": confidence,
        "probabilities": {
            "met": met,
            "unmet": unmet,
            "insufficient": insufficient,
        },
    })
}

/// Synthetic System One response with one answer and usage.
pub fn jev_system_one_response(
    model: &str,
    question_id: &str,
    answer: serde_json::Value,
) -> serde_json::Value {
    let mut answers = serde_json::Map::new();
    answers.insert(question_id.to_owned(), answer);
    serde_json::json!({
        "model": model,
        "answers": serde_json::Value::Object(answers),
        "usage": {"input_tokens": 120, "output_tokens": 12},
    })
}

/// Decisions completion profile at `version` with the fixture adapter/rubric.
pub fn decisions_completion_profile_for(
    project: ProjectId,
    connection: ConnectionId,
    model: &str,
    version: u64,
) -> AssessmentProfile {
    decisions_completion_profile_with_inputs(
        project,
        connection,
        model,
        version,
        ProfileInputs::text_only(),
    )
}

/// Decisions completion profile with explicit required inputs.
pub fn decisions_completion_profile_with_inputs(
    project: ProjectId,
    connection: ConnectionId,
    model: &str,
    version: u64,
    required_inputs: ProfileInputs,
) -> AssessmentProfile {
    let ids = ids(project);
    AssessmentProfile::new(
        ids.profile,
        ProfileVersion::new(version).expect("version"),
        ProfilePurpose::Completion,
        ProviderKind::Decisions,
        connection,
        ModelId::new(model).expect("model"),
        AdapterVersion::new("fixture-decisions-adapter-1").expect("adapter"),
        RubricVersion::new("fixture-decisions-rubric-1").expect("rubric"),
        required_inputs,
        ProfileThresholds::decisions(),
    )
    .expect("decisions completion profile")
}

/// Profile entry for a Decisions profile and its registered connection.
pub fn decisions_profile_entry(
    settings: &ConnectionSettings,
    profile: AssessmentProfile,
) -> ProfileEntry {
    ProfileEntry::new(
        profile,
        settings.capabilities().expect("connection capabilities"),
        ConnectionStatus::Available,
        false,
    )
}

/// A per-condition Decisions assessment request.
pub fn decisions_assessment_request(
    project: ProjectId,
    condition: ConditionId,
    profile: &AssessmentProfile,
    evidence_ids: Vec<EvidenceId>,
) -> AssessmentRequest {
    let ids = ids(project);
    AssessmentRequest::new(
        ids.decision,
        ids.supervision,
        condition,
        ConditionVersion::new(1).expect("version"),
        TargetVersion::new(1).expect("version"),
        "The fixture condition is met when the recorded check passes.",
        profile.binding(),
        AdapterVersion::new("fixture-decisions-adapter-1").expect("adapter"),
        RubricVersion::new("fixture-decisions-rubric-1").expect("rubric"),
        evidence_ids,
    )
    .expect("decisions assessment request")
}

/// Synthetic Decisions choice answer with ordered probabilities.
pub fn decisions_choice_answer(
    choice: &str,
    met: f64,
    unmet: f64,
    insufficient: f64,
    confidence: f64,
) -> serde_json::Value {
    serde_json::json!({
        "type": "choice",
        "choice": choice,
        "confidence": confidence,
        "probabilities": [
            {"value": "met", "probability": met},
            {"value": "unmet", "probability": unmet},
            {"value": "insufficient", "probability": insufficient},
        ],
    })
}

/// Synthetic Decisions response with one named answer and usage details.
pub fn decisions_response(
    model: &str,
    question_id: &str,
    answer: serde_json::Value,
) -> serde_json::Value {
    let mut answer = answer;
    answer["name"] = serde_json::json!(question_id);
    serde_json::json!({
        "model": model,
        "answers": [answer],
        "usage": {
            "input_tokens": 120,
            "input_tokens_details": {"cached_tokens": 20, "cache_write_tokens": 30},
            "output_tokens": 12,
        },
    })
}

/// Completion profile entry whose profile and connection match.
pub fn completion_entry(
    project: ProjectId,
    status: ConnectionStatus,
    structured_output: bool,
) -> ProfileEntry {
    let connection = normal_connection();
    let profile = completion_profile_for(project, connection.connection_id());
    ProfileEntry::new(profile, connection, status, structured_output)
}

/// Decisions permission profile bound to `connection`.
pub fn permission_profile_for(project: ProjectId, connection: ConnectionId) -> AssessmentProfile {
    let ids = ids(project);
    AssessmentProfile::new(
        ids.permission_profile,
        ProfileVersion::new(1).expect("version"),
        ProfilePurpose::Permission,
        ProviderKind::Decisions,
        connection,
        ModelId::new("synthetic-permission-judge").expect("model"),
        AdapterVersion::new("fixture-decisions-adapter-1").expect("adapter"),
        RubricVersion::new("fixture-permission-rubric-1").expect("rubric"),
        ProfileInputs::new(true, false, true),
        ProfileThresholds::decisions(),
    )
    .expect("permission profile")
}

/// Decisions permission profile using a fresh synthetic connection.
pub fn permission_profile(project: ProjectId) -> AssessmentProfile {
    permission_profile_for(project, decisions_connection().connection_id())
}

/// Permission profile entry whose profile and connection match.
pub fn permission_entry(project: ProjectId) -> ProfileEntry {
    let connection = decisions_connection();
    let profile = permission_profile_for(project, connection.connection_id());
    ProfileEntry::new(profile, connection, ConnectionStatus::Available, true)
}

/// Permission profile for one provider kind and connection.
pub fn permission_profile_for_provider(
    project: ProjectId,
    provider: ProviderKind,
    connection: ConnectionId,
    model: &str,
    required_inputs: ProfileInputs,
) -> AssessmentProfile {
    let ids = ids(project);
    let (adapter, rubric) = match provider {
        ProviderKind::NormalLlm => (
            "fixture-permission-llm-adapter-1",
            "fixture-permission-rubric-1",
        ),
        ProviderKind::Jev => (
            "fixture-permission-jev-adapter-1",
            "fixture-permission-rubric-1",
        ),
        ProviderKind::Decisions => (
            "fixture-permission-decisions-adapter-1",
            "fixture-permission-rubric-1",
        ),
    };
    AssessmentProfile::new(
        ids.permission_profile,
        ProfileVersion::new(1).expect("version"),
        ProfilePurpose::Permission,
        provider,
        connection,
        ModelId::new(model).expect("model"),
        AdapterVersion::new(adapter).expect("adapter"),
        RubricVersion::new(rubric).expect("rubric"),
        required_inputs,
        ProfileThresholds::for_provider(provider),
    )
    .expect("permission profile")
}

/// Profile entry for a permission profile and its registered connection.
pub fn permission_entry_for(
    settings: &ConnectionSettings,
    profile: AssessmentProfile,
    structured_output: bool,
) -> ProfileEntry {
    ProfileEntry::new(
        profile,
        settings.capabilities().expect("connection capabilities"),
        ConnectionStatus::Available,
        structured_output,
    )
}

/// Human-approved consent for an explicit synthetic origin.
pub fn consent_for_origin(
    project: ProjectId,
    purpose: ProfilePurpose,
    target_version: u64,
    origin: ProviderOrigin,
) -> DisclosureConsent {
    let ids = ids(project);
    DisclosureConsent::grant(
        ApprovalActor::Human,
        ids.consent,
        origin,
        disclosure_scope(purpose, target_version),
        now(),
    )
    .expect("consent")
}

/// A catalog with both fixture profiles available.
pub fn profile_catalog(project: ProjectId) -> ProfileCatalog {
    let mut catalog = ProfileCatalog::for_project(project);
    catalog
        .insert(completion_entry(project, ConnectionStatus::Available, true))
        .expect("insert");
    catalog.insert(permission_entry(project)).expect("insert");
    catalog
}

/// Bounded disclosure scope for one purpose and target version.
pub fn disclosure_scope(purpose: ProfilePurpose, target_version: u64) -> DisclosureScope {
    DisclosureScope::new(
        purpose,
        BTreeSet::from([
            DisclosureDataKind::Text,
            DisclosureDataKind::Code,
            DisclosureDataKind::Diff,
        ]),
        vec!["src/lib.rs".to_owned()],
        TargetVersion::new(target_version).expect("target version"),
    )
    .expect("scope")
}

/// Human-approved disclosure consent for the fixture scope.
pub fn consent(
    project: ProjectId,
    purpose: ProfilePurpose,
    target_version: u64,
) -> DisclosureConsent {
    let ids = ids(project);
    DisclosureConsent::grant(
        ApprovalActor::Human,
        ids.consent,
        origin(),
        disclosure_scope(purpose, target_version),
        now(),
    )
    .expect("consent")
}

/// A disclosure request with an explicit data-kind set.
pub fn disclosure_request(
    project: ProjectId,
    purpose: ProfilePurpose,
    data_kinds: impl IntoIterator<Item = DisclosureDataKind>,
    target_version: u64,
) -> DisclosureRequest {
    DisclosureRequest::new(
        project,
        origin(),
        purpose,
        data_kinds.into_iter().collect(),
        TargetVersion::new(target_version).expect("target version"),
    )
    .expect("disclosure request")
}

/// A complete approved fixture contract.
pub fn contract(project: ProjectId) -> SupervisionContract {
    let ids = ids(project);
    let subject = SupervisionSubject::new(
        project,
        ids.supervision,
        AgentId::new(project),
        SessionId::new(project),
        OwnerRef::new(OwnerKind::Human, "fixture-human").expect("owner"),
    )
    .expect("subject");
    let execution = ExecutionScope::new(
        project,
        vec!["src".to_owned(), "Cargo.toml".to_owned()],
        vec!["src".to_owned()],
        true,
    )
    .expect("scope");
    let profile = completion_profile(project);
    let consent = consent(project, ProfilePurpose::Completion, 1);
    let target = target_scope(project, 1);
    let budget = BudgetPolicy::h2_default();
    let conditions = approved_condition_set(project);
    let packet = work_packet(
        project,
        &target,
        &execution,
        conditions.condition_version(),
        &profile,
        &consent,
        &budget,
        "fixture owner instruction",
    );
    SupervisionContract::new(
        ApprovalActor::Human,
        subject,
        execution,
        RunGroup::new(ids.run_group),
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

/// A complete approved fixture contract owned by an approved H3/H4 owner.
///
/// The condition set carries the matching inherited approval so the contract is
/// accepted by the same H2 rules as production.
pub fn owner_contract(
    project: ProjectId,
    owner: OwnerRef,
    source: OwnerApprovalSource,
) -> SupervisionContract {
    let ids = ids(project);
    let mut conditions = condition_set(project);
    let approval = ConditionApproval::new(
        project,
        ApprovalBasis::InheritedOwner {
            owner: owner.clone(),
            source,
            approved_at: now(),
            expires_at: None,
        },
        conditions.condition_version(),
        conditions.digest().clone(),
    )
    .expect("owner condition approval");
    conditions
        .approve(
            ApprovalActor::ApprovedOwner {
                owner: owner.clone(),
                source,
            },
            approval,
            now(),
        )
        .expect("inherited approval");
    let subject = SupervisionSubject::new(
        project,
        ids.supervision,
        AgentId::new(project),
        SessionId::new(project),
        owner.clone(),
    )
    .expect("subject");
    let execution = ExecutionScope::new(
        project,
        vec!["src".to_owned(), "Cargo.toml".to_owned()],
        vec!["src".to_owned()],
        true,
    )
    .expect("scope");
    let profile = completion_profile(project);
    let consent = consent(project, ProfilePurpose::Completion, 1);
    let target = target_scope(project, 1);
    let budget = BudgetPolicy::h2_default();
    let packet = work_packet(
        project,
        &target,
        &execution,
        conditions.condition_version(),
        &profile,
        &consent,
        &budget,
        "owner fixture instruction",
    );
    SupervisionContract::new(
        ApprovalActor::ApprovedOwner { owner, source },
        subject,
        execution,
        RunGroup::new(ids.run_group),
        conditions,
        target,
        &profile,
        &consent,
        budget,
        packet,
        now(),
    )
    .expect("owner contract")
}

/// A complete approved owner contract at an explicit target/condition version.
///
/// The consent covers the same target version and the work packet matches the
/// exact approved constraints, so the value is accepted by the same H2 rules as
/// an owner generation replacement.
pub fn owner_contract_at(
    project: ProjectId,
    owner: OwnerRef,
    source: OwnerApprovalSource,
    target_version: u64,
    condition_version: u64,
) -> SupervisionContract {
    owner_contract_at_with_budget(
        project,
        owner,
        source,
        target_version,
        condition_version,
        BudgetPolicy::h2_default(),
    )
}

/// A complete approved owner contract with an explicit finite budget policy.
#[allow(clippy::too_many_arguments)]
pub fn owner_contract_at_with_budget(
    project: ProjectId,
    owner: OwnerRef,
    source: OwnerApprovalSource,
    target_version: u64,
    condition_version: u64,
    budget: BudgetPolicy,
) -> SupervisionContract {
    let ids = ids(project);
    let mut conditions = condition_set_at(project, condition_version);
    let approval = ConditionApproval::new(
        project,
        ApprovalBasis::InheritedOwner {
            owner: owner.clone(),
            source,
            approved_at: now(),
            expires_at: None,
        },
        conditions.condition_version(),
        conditions.digest().clone(),
    )
    .expect("owner condition approval");
    conditions
        .approve(
            ApprovalActor::ApprovedOwner {
                owner: owner.clone(),
                source,
            },
            approval,
            now(),
        )
        .expect("inherited approval");
    let subject = SupervisionSubject::new(
        project,
        ids.supervision,
        AgentId::new(project),
        SessionId::new(project),
        owner.clone(),
    )
    .expect("subject");
    let execution = ExecutionScope::new(
        project,
        vec!["src".to_owned(), "Cargo.toml".to_owned()],
        vec!["src".to_owned()],
        true,
    )
    .expect("scope");
    let profile = completion_profile(project);
    let consent = consent(project, ProfilePurpose::Completion, target_version);
    let target = target_scope(project, target_version);
    let packet = work_packet(
        project,
        &target,
        &execution,
        conditions.condition_version(),
        &profile,
        &consent,
        &budget,
        "owner fixture instruction",
    );
    SupervisionContract::new(
        ApprovalActor::ApprovedOwner {
            owner: owner.clone(),
            source,
        },
        subject,
        execution,
        RunGroup::new(ids.run_group),
        conditions,
        target,
        &profile,
        &consent,
        budget,
        packet,
        now(),
    )
    .expect("owner contract at version")
}

/// A replacement owner contract that keeps the current subject and execution
/// scope while advancing the target and condition versions.
pub fn owner_contract_succeeding(
    current: &SupervisionContract,
    target_version: u64,
    condition_version: u64,
    budget: BudgetPolicy,
) -> SupervisionContract {
    let project = current.project_id();
    let owner = current.subject().owner().clone();
    let source = match current.conditions().approval().map(|approval| approval.basis()) {
        Some(ApprovalBasis::InheritedOwner { source, .. }) => *source,
        _ => panic!("the current contract must carry an inherited owner approval"),
    };
    let mut conditions = condition_set_at(project, condition_version);
    let approval = ConditionApproval::new(
        project,
        ApprovalBasis::InheritedOwner {
            owner: owner.clone(),
            source,
            approved_at: now(),
            expires_at: None,
        },
        conditions.condition_version(),
        conditions.digest().clone(),
    )
    .expect("owner condition approval");
    conditions
        .approve(
            ApprovalActor::ApprovedOwner {
                owner: owner.clone(),
                source,
            },
            approval,
            now(),
        )
        .expect("inherited approval");
    let subject = SupervisionSubject::new(
        project,
        current.subject().supervision_id(),
        current.subject().agent_id(),
        current.subject().session_id(),
        owner.clone(),
    )
    .expect("subject");
    let execution = current.execution_scope().clone();
    let profile = completion_profile(project);
    assert_eq!(
        profile.binding(),
        current.profile(),
        "the fixture replacement must keep the current profile binding"
    );
    let consent = consent(project, profile.purpose(), target_version);
    let target = target_scope(project, target_version);
    let packet = work_packet_at(
        current.work_packet().packet_version().saturating_add(1),
        project,
        &target,
        &execution,
        conditions.condition_version(),
        &profile,
        &consent,
        &budget,
        "owner fixture instruction",
    );
    SupervisionContract::new(
        ApprovalActor::ApprovedOwner { owner, source },
        subject,
        execution,
        RunGroup::new(ids(project).run_group),
        conditions,
        target,
        &profile,
        &consent,
        budget,
        packet,
        now(),
    )
    .expect("succeeding owner contract")
}

/// A replacement human contract that keeps the current subject and execution
/// scope while advancing the target and condition versions.
pub fn contract_succeeding(
    current: &SupervisionContract,
    target_version: u64,
    condition_version: u64,
) -> SupervisionContract {
    let project = current.project_id();
    let conditions = approved_condition_set_at(project, condition_version);
    let subject = SupervisionSubject::new(
        project,
        current.subject().supervision_id(),
        current.subject().agent_id(),
        current.subject().session_id(),
        current.subject().owner().clone(),
    )
    .expect("subject");
    let execution = current.execution_scope().clone();
    let profile = completion_profile(project);
    assert_eq!(
        profile.binding(),
        current.profile(),
        "the fixture replacement must keep the current profile binding"
    );
    let consent = consent(project, profile.purpose(), target_version);
    let target = target_scope(project, target_version);
    let budget = current.budget().clone();
    let packet = work_packet_at(
        current.work_packet().packet_version().saturating_add(1),
        project,
        &target,
        &execution,
        conditions.condition_version(),
        &profile,
        &consent,
        &budget,
        "fixture owner instruction",
    );
    SupervisionContract::new(
        ApprovalActor::Human,
        subject,
        execution,
        RunGroup::new(ids(project).run_group),
        conditions,
        target,
        &profile,
        &consent,
        budget,
        packet,
        now(),
    )
    .expect("succeeding human contract")
}

/// A fixture work packet matching the supplied approved values.
#[allow(clippy::too_many_arguments)]
pub fn work_packet(
    project: ProjectId,
    target: &TargetScope,
    execution: &ExecutionScope,
    condition_version: ConditionVersion,
    profile: &AssessmentProfile,
    consent: &DisclosureConsent,
    budget: &BudgetPolicy,
    instruction: &str,
) -> WorkPacket {
    work_packet_at(
        1,
        project,
        target,
        execution,
        condition_version,
        profile,
        consent,
        budget,
        instruction,
    )
}

/// A fixture work packet at an explicit packet version.
#[allow(clippy::too_many_arguments)]
pub fn work_packet_at(
    packet_version: u64,
    project: ProjectId,
    target: &TargetScope,
    execution: &ExecutionScope,
    condition_version: ConditionVersion,
    profile: &AssessmentProfile,
    consent: &DisclosureConsent,
    budget: &BudgetPolicy,
    instruction: &str,
) -> WorkPacket {
    WorkPacket::new(
        packet_version,
        instruction,
        project,
        target,
        execution.clone(),
        condition_version,
        profile.binding(),
        consent.binding(),
        1,
        budget.clone(),
    )
    .expect("work packet")
}

/// A mutable supervision record for the fixture contract.
pub fn record(project: ProjectId) -> SupervisionRecord {
    SupervisionRecord::new(&contract(project))
}

/// A synthetic evidence record for one check.
pub fn evidence(
    project: ProjectId,
    ids: Ids,
    evidence_id: EvidenceId,
    check: CheckId,
    condition: ConditionId,
    status: CheckStatus,
    sequence: u64,
) -> EvidenceRecord {
    EvidenceRecord::new(
        evidence_id,
        ids.supervision,
        Some(condition),
        Some(check),
        EvidenceAcquirer::ChildAgent,
        VerificationOperation::command("cargo test -p fixture-app --locked").expect("command"),
        EvidenceOutcome::new(
            match status {
                CheckStatus::Pass | CheckStatus::Inconclusive => Some(0),
                CheckStatus::Fail => Some(1),
                _ => None,
            },
            None,
            false,
            false,
            "synthetic fixture result",
        )
        .expect("outcome"),
        target_scope(project, 1),
        EvidenceScope::new(
            vec!["src/lib.rs".to_owned()],
            vec!["fixture only; no network".to_owned()],
        )
        .expect("scope"),
        status,
        sequence,
        now(),
    )
    .expect("evidence")
}

/// A required-check result derived from explicit evidence.
pub fn check_result(
    evidence: &EvidenceRecord,
    condition_version: ConditionVersion,
) -> RequiredCheckResult {
    RequiredCheckResult::from_evidence(evidence, condition_version).expect("check result")
}

/// A per-condition normal-LLM assessment request.
pub fn assessment_request(
    project: ProjectId,
    condition: ConditionId,
    profile: &AssessmentProfile,
    evidence_ids: Vec<EvidenceId>,
) -> AssessmentRequest {
    let ids = ids(project);
    AssessmentRequest::new(
        ids.decision,
        ids.supervision,
        condition,
        ConditionVersion::new(1).expect("version"),
        TargetVersion::new(1).expect("version"),
        "The fixture condition is met when the recorded check passes.",
        profile.binding(),
        AdapterVersion::new("fixture-llm-adapter-1").expect("adapter"),
        RubricVersion::new("fixture-rubric-1").expect("rubric"),
        evidence_ids,
    )
    .expect("assessment request")
}

/// A normal-LLM assessment result for a request.
pub fn assessment_result(
    request: &AssessmentRequest,
    verdict: ConditionVerdict,
    evidence_ids: Vec<EvidenceId>,
) -> AssessmentResult {
    AssessmentResult::new(
        request,
        evidence_ids,
        "The fixture evidence supports the recorded verdict.",
        None,
        AssessmentOutcome::NormalLlm {
            verdict,
            confidence: Some(
                NativeConfidence::new(0.8, "fixture-provider-scale").expect("confidence"),
            ),
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
    .expect("assessment result")
}

/// A Decisions condition distribution result.
pub fn decision_result(
    request: &AssessmentRequest,
    met: f64,
    unmet: f64,
    insufficient: f64,
    selected: ConditionVerdict,
) -> AssessmentResult {
    AssessmentResult::new(
        request,
        request.evidence().to_vec(),
        "The fixture distribution selects the recorded verdict.",
        None,
        AssessmentOutcome::Decision {
            selected,
            probabilities: ConditionProbabilities::new(met, unmet, insufficient)
                .expect("distribution"),
            confidence: None,
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
    .expect("assessment result")
}

/// Completion snapshot matching the fixture contract.
pub fn completion_snapshot(contract: &SupervisionContract) -> CompletionSnapshot {
    let ids = ids(contract.project_id());
    CompletionSnapshot::new(
        contract.conditions().condition_version(),
        contract.evidence_target().version(),
        contract.profile(),
        contract.consent(),
        contract
            .conditions()
            .checks()
            .iter()
            .map(|check| check.id())
            .collect(),
        vec![ids.evidence_a],
        ContentDigest::sha256(b"fixture observations"),
        now(),
    )
    .expect("completion snapshot")
}

/// In-memory supervision store for idempotent-command tests.
#[derive(Debug, Default)]
pub struct MemorySupervisionStore {
    records: BTreeMap<SupervisionId, SupervisionRecord>,
    commands: BTreeMap<SupervisionRequestId, CommandResult>,
    /// Counts committed state mutations.
    pub mutations: u32,
    /// Counts compare-and-swap attempts.
    pub swaps: u32,
}

impl MemorySupervisionStore {
    /// Creates a store holding one record.
    pub fn with_record(record: SupervisionRecord) -> Self {
        let mut store = Self::default();
        store.records.insert(record.supervision_id(), record);
        store
    }
}

impl SupervisionStorePort for MemorySupervisionStore {
    fn load(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Option<SupervisionRecord>, SupervisionError> {
        if supervision_id.project_id() != project_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "supervision".to_owned(),
                expected: project_id,
                found: supervision_id.project_id(),
            });
        }
        Ok(self.records.get(&supervision_id).cloned())
    }

    fn compare_and_swap(
        &mut self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
        expected_revision: Option<u64>,
        next: &SupervisionRecord,
    ) -> Result<u64, SupervisionError> {
        self.swaps += 1;
        let current = self.records.get(&supervision_id);
        match (expected_revision, current) {
            (Some(expected), Some(current)) if current.revision() == expected => {}
            (Some(expected), Some(current)) => {
                return Err(SupervisionError::RevisionConflict {
                    expected,
                    found: current.revision(),
                });
            }
            (None, None) => {}
            (None, Some(current)) => {
                return Err(SupervisionError::RevisionConflict {
                    expected: 0,
                    found: current.revision(),
                });
            }
            (Some(_), None) => return Err(SupervisionError::UnknownSupervision),
        }
        if next.project_id() != project_id || next.supervision_id() != supervision_id {
            return Err(SupervisionError::CrossProjectReference {
                id_kind: "supervision record".to_owned(),
                expected: project_id,
                found: next.project_id(),
            });
        }
        let revision = next.revision();
        self.records.insert(supervision_id, next.clone());
        self.mutations += 1;
        Ok(revision)
    }

    fn command_result(
        &self,
        request_id: SupervisionRequestId,
    ) -> Result<Option<CommandResult>, SupervisionError> {
        Ok(self.commands.get(&request_id).cloned())
    }

    fn record_command_result(
        &mut self,
        result: &CommandResult,
    ) -> Result<CommandResult, SupervisionError> {
        if let Some(existing) = self.commands.get(&result.request_id()) {
            if existing == result {
                return Ok(existing.clone());
            }
            return Err(SupervisionError::DuplicateRequestConflict {
                request: result.request_id().to_string(),
                recorded: existing.command().as_str().to_owned(),
                supplied: result.command().as_str().to_owned(),
            });
        }
        self.commands.insert(result.request_id(), result.clone());
        Ok(result.clone())
    }
}
