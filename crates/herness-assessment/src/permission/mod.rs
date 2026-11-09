//! Purpose-specific permission evaluator over the tool-less assessment
//! transports.
//!
//! This module turns the H1 [`EvaluationRequest`] into a separate permission
//! question, never a completion-condition assessment. The normal-LLM adapter
//! requires a closed schema, an exact operation/argument-digest/cwd/policy/mode
//! binding, a short rationale, and no uncertainty. The Jev and Decisions
//! adapters require a complete finite `allow`/`deny`/`ask` distribution and
//! adopt `allow`/`deny` only at the H2 permission floor of 0.99 (or a higher
//! human-configured profile threshold). Provider-native confidence is validated
//! separately and never used for adoption.
//!
//! Every request requires a permission-purpose disclosure consent and a
//! host-owned budget admission. A supervised supervision target shares the same
//! [`SharedModelRequestGate`] as its agent model requests. A non-supervised run
//! may use [`PermissionBudgetScope::RunScoped`] with a finite per-run request
//! limit. Missing consent, missing budget, a refusal, a stale binding, a
//! malformed answer, a low-confidence distribution, or a transport failure
//! results in an ask; none of them can authorize execution.

mod decisions;
mod jev;
mod llm;
mod question;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock};

use herness_core::contracts::Timestamp;
use herness_core::contracts::{
    AttemptId, EventKind, EventSubject, HostActivityId, HostActivitySubject, ModelId,
    ModelRequestObservation, RequestGateIntent, RequestGateOutcome, RequestId, RequestOutcome,
    RequestPurpose, RunId, StopDeadlineControl, StoreFailureKind, TokenUsage,
};
use herness_core::ports::{
    ModelRequestGatePort, PermissionEvaluatorPort, SharedPermissionEvaluator,
};
use herness_core::{
    CoreError, EvaluationFailureKind, EvaluatorAvailability, PermissionDecision,
    ProviderFailureKind,
};
use herness_supervision::consent::{
    DisclosureConsent, DisclosureDataKind, DisclosureRequest, ProviderOrigin,
};
use herness_supervision::error::SupervisionError;
use herness_supervision::evidence::TargetVersion;
use herness_supervision::profiles::{ProfileEntry, ProfilePurpose, ProviderKind};

use crate::error::AssessmentError;
use crate::transport::{AssessmentTransport, TransportControl};

pub(crate) use question::PermissionQuestion;
pub use question::permission_question_id;

/// Shared host-owned model request gate.
///
/// The same value can be installed into the Pi engine and this evaluator so one
/// budget ledger admits both agent model requests and permission evaluations.
/// The engine receives [`Self::boxed`], which is a second handle to the same
/// mutex, not a second gate.
#[derive(Clone)]
pub struct SharedModelRequestGate {
    inner: Arc<Mutex<Box<dyn ModelRequestGatePort + Send>>>,
}

impl SharedModelRequestGate {
    /// Wraps one host-owned gate.
    pub fn new(gate: Box<dyn ModelRequestGatePort + Send>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(gate)),
        }
    }

    /// Returns a boxed handle for the engine adapter's gate injection.
    pub fn boxed(&self) -> Box<dyn ModelRequestGatePort + Send> {
        Box::new(self.clone())
    }

    fn with_gate<T>(
        &self,
        action: impl FnOnce(&mut Box<dyn ModelRequestGatePort + Send>) -> T,
    ) -> Result<T, CoreError> {
        let mut gate = self.inner.lock().map_err(|_| CoreError::StoreUnavailable {
            failure: StoreFailureKind::Unavailable,
        })?;
        Ok(action(&mut gate))
    }
}

impl ModelRequestGatePort for SharedModelRequestGate {
    fn admit(&mut self, intent: &RequestGateIntent) -> Result<RequestGateOutcome, CoreError> {
        self.with_gate(|gate| gate.admit(intent))?
    }

    fn observe(&mut self, observation: &ModelRequestObservation) -> Result<(), CoreError> {
        self.with_gate(|gate| gate.observe(observation))?
    }
}

/// How permission-evaluation requests consume the finite H2 budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionBudgetScope {
    /// Share the supervised target's budget with every agent, verification, and
    /// assessment request. Only the shared ledger's cap limits the number of
    /// evaluations.
    Supervised,
    /// A non-supervised run may issue at most `max_requests` permission
    /// evaluations. The shared budget still checks time and money; this limit
    /// additionally prevents a normal chat from entering a permission-evaluation
    /// continuation loop.
    RunScoped {
        /// Finite number of permission requests allowed for one run.
        max_requests: u32,
    },
}

/// Thread-safe holder for the current permission-purpose disclosure consent.
///
/// The host can revoke or replace consent while a run is active. The evaluator
/// re-checks this handle immediately before sending and again after the provider
/// answer, so a revocation during an in-flight evaluation becomes an ask rather
/// than an execution.
#[derive(Clone)]
pub struct PermissionConsentHandle {
    inner: Arc<RwLock<Option<DisclosureConsent>>>,
}

impl PermissionConsentHandle {
    /// Creates a handle with an initial consent record.
    pub fn new(consent: DisclosureConsent) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Some(consent))),
        }
    }

    /// Creates an empty handle. No permission request may be sent.
    pub fn unavailable() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    /// Replaces the current consent record. `None` blocks every request.
    pub fn set(&self, consent: Option<DisclosureConsent>) {
        if let Ok(mut current) = self.inner.write() {
            *current = consent;
        }
    }

    /// Current consent record, when one exists.
    pub fn current(&self) -> Option<DisclosureConsent> {
        self.inner.read().ok().and_then(|current| current.clone())
    }

    /// Revokes the current consent record and advances its version.
    pub fn revoke(&self, revoked_at: Timestamp) -> Result<(), SupervisionError> {
        let current = self.current();
        let Some(current) = current else {
            return Ok(());
        };
        let revoked = current.revoke(herness_supervision::ApprovalActor::Human, revoked_at)?;
        self.set(Some(revoked));
        Ok(())
    }
}

/// Host-owned configuration for the permission evaluator.
///
/// The profile must be a permission-purpose `ProfileEntry`. The origin and
/// target version are exactly the values a permission disclosure consent was
/// granted for. The transport owns the provider connection and credential
/// boundary; this value never reads a conversation, repository, or credential.
pub struct PermissionEvaluatorConfig {
    profile: ProfileEntry,
    consent: Option<PermissionConsentHandle>,
    origin: ProviderOrigin,
    target_version: TargetVersion,
    data_kinds: BTreeSet<DisclosureDataKind>,
    transport: AssessmentTransport,
    budget_gate: Option<SharedModelRequestGate>,
    budget_scope: PermissionBudgetScope,
    control: TransportControl,
    jev_wire_model: String,
}

impl PermissionEvaluatorConfig {
    /// Creates a configuration without consent or a budget gate.
    ///
    /// Both must be supplied by the host before automatic mode is available;
    /// [`PermissionEvaluator::availability`] reports unavailable until then.
    pub fn new(
        profile: ProfileEntry,
        consent: Option<DisclosureConsent>,
        origin: ProviderOrigin,
        target_version: TargetVersion,
        transport: AssessmentTransport,
    ) -> Self {
        Self {
            profile,
            consent: consent.map(PermissionConsentHandle::new),
            origin,
            target_version,
            data_kinds: BTreeSet::from([DisclosureDataKind::Text, DisclosureDataKind::Code]),
            transport,
            budget_gate: None,
            budget_scope: PermissionBudgetScope::Supervised,
            control: TransportControl::default(),
            jev_wire_model: crate::jev::JEV_REQUEST_MODEL.to_owned(),
        }
    }

    /// Replaces the disclosure consent record.
    #[must_use]
    pub fn with_consent(mut self, consent: DisclosureConsent) -> Self {
        self.consent = Some(PermissionConsentHandle::new(consent));
        self
    }

    /// Attaches a shared consent handle the host can revoke or replace.
    #[must_use]
    pub fn with_consent_handle(mut self, consent: PermissionConsentHandle) -> Self {
        self.consent = Some(consent);
        self
    }

    /// Attaches the shared host budget gate.
    #[must_use]
    pub fn with_budget_gate(mut self, gate: SharedModelRequestGate) -> Self {
        self.budget_gate = Some(gate);
        self
    }

    /// Selects the supervised or run-scoped budget behavior.
    #[must_use]
    pub const fn with_budget_scope(mut self, scope: PermissionBudgetScope) -> Self {
        self.budget_scope = scope;
        self
    }

    /// Replaces the exact data kinds the question may disclose.
    #[must_use]
    pub fn with_data_kinds(mut self, data_kinds: BTreeSet<DisclosureDataKind>) -> Self {
        self.data_kinds = data_kinds;
        self
    }

    /// Replaces the transport timeout/cancellation control.
    #[must_use]
    pub fn with_transport_control(mut self, control: TransportControl) -> Self {
        self.control = control;
        self
    }

    /// Selects the fixed Jev wire model for a trusted gateway.
    ///
    /// The direct TypeSafe route uses `jev-1.14.0`; Command Code's Provider API
    /// uses `typesafe/jev-1.14.0`. Aliases and arbitrary model names are
    /// rejected. The configured connection model remains the canonical value
    /// used for the transport binding.
    #[must_use]
    pub fn with_jev_wire_model(mut self, wire_model: impl Into<String>) -> Self {
        let wire_model = wire_model.into();
        if wire_model == crate::jev::JEV_REQUEST_MODEL
            || wire_model == crate::jev::COMMANDCODE_JEV_REQUEST_MODEL
        {
            self.jev_wire_model = wire_model;
        }
        self
    }
}

/// Provider answer returned by one permission assessment.
pub(crate) struct PermissionReply {
    pub(crate) decision: PermissionDecision,
    pub(crate) usage: TokenUsage,
    pub(crate) reported_model: Option<ModelId>,
}

impl PermissionReply {
    pub(crate) fn ask(usage: TokenUsage, reported_model: Option<ModelId>) -> Self {
        Self {
            decision: PermissionDecision::Ask,
            usage,
            reported_model,
        }
    }
}

/// A host-installable permission evaluator.
pub struct PermissionEvaluator {
    config: PermissionEvaluatorConfig,
    run_requests: BTreeMap<RunId, u32>,
}

enum EvaluateError {
    Ask,
    Assessment(AssessmentError),
    Gate(CoreError),
}

impl PermissionEvaluator {
    /// Creates an evaluator for a permission-purpose profile.
    pub fn new(config: PermissionEvaluatorConfig) -> Result<Self, CoreError> {
        if config.profile.profile().purpose() != ProfilePurpose::Permission {
            return Err(CoreError::PermissionEvaluationFailed {
                failure: EvaluationFailureKind::Unavailable,
            });
        }
        config
            .profile
            .validate()
            .map_err(|_| CoreError::PermissionEvaluationFailed {
                failure: EvaluationFailureKind::Unavailable,
            })?;
        if let PermissionBudgetScope::RunScoped { max_requests } = config.budget_scope
            && max_requests == 0
        {
            return Err(CoreError::InvalidValue {
                field: "permissionBudget.maxRequests".to_owned(),
                violation: herness_core::ArgumentViolation::MustBePositive,
            });
        }
        Ok(Self {
            config,
            run_requests: BTreeMap::new(),
        })
    }

    /// Wraps the evaluator for `RuntimeDependencies::with_shared_evaluator`.
    pub fn into_shared(self) -> SharedPermissionEvaluator {
        SharedPermissionEvaluator::new(Box::new(self))
    }

    /// Boxes the evaluator for `RuntimeDependencies::with_evaluator`.
    pub fn into_boxed(self) -> Box<dyn PermissionEvaluatorPort + Send + Sync> {
        Box::new(self)
    }

    /// Project that owns the profile, consent, and budget.
    pub fn project_id(&self) -> herness_core::ProjectId {
        self.config.profile.profile().id().project_id()
    }

    fn consent_allows(&self) -> bool {
        let Some(handle) = self.config.consent.as_ref() else {
            return false;
        };
        let Some(consent) = handle.current() else {
            return false;
        };
        let project = self.project_id();
        if consent.ensure_project(project).is_err()
            || consent.purpose() != ProfilePurpose::Permission
            || consent.origin() != &self.config.origin
            || consent.target_scope_version() != self.config.target_version
        {
            return false;
        }
        let Ok(request) = DisclosureRequest::new(
            project,
            self.config.origin.clone(),
            ProfilePurpose::Permission,
            self.config.data_kinds.clone(),
            self.config.target_version,
        ) else {
            return false;
        };
        consent.authorize(&request).is_ok()
    }

    fn budget_allows_run(&self, run: RunId) -> bool {
        match self.config.budget_scope {
            PermissionBudgetScope::Supervised => true,
            PermissionBudgetScope::RunScoped { max_requests } => {
                self.run_requests.get(&run).copied().unwrap_or(0) < max_requests
            }
        }
    }

    fn evaluate_inner(
        &mut self,
        request: &herness_core::EvaluationRequest,
    ) -> Result<PermissionDecision, EvaluateError> {
        let profile = self.config.profile.profile();
        if profile.purpose() != ProfilePurpose::Permission
            || self.config.profile.validate().is_err()
            || !self.consent_allows()
        {
            return Err(EvaluateError::Ask);
        }
        let Some(gate) = self.config.budget_gate.as_ref() else {
            return Err(EvaluateError::Ask);
        };
        let operation = request.operation();
        if !self.budget_allows_run(operation.run_id()) {
            return Err(EvaluateError::Ask);
        }
        if self.config.control.timeout().is_zero() {
            return Err(EvaluateError::Ask);
        }
        let question =
            question::PermissionQuestion::from_request(request).map_err(|_| EvaluateError::Ask)?;
        let intent = request_intent(profile, &question).map_err(EvaluateError::Gate)?;
        let admitted = gate
            .with_gate(|gate| gate.admit(&intent))
            .map_err(EvaluateError::Gate)?;
        match admitted {
            Ok(RequestGateOutcome::Admit) => {}
            Ok(RequestGateOutcome::Refuse { .. }) => return Err(EvaluateError::Ask),
            Err(error) => return Err(EvaluateError::Gate(error)),
        }
        if let PermissionBudgetScope::RunScoped { .. } = self.config.budget_scope {
            let count = self.run_requests.entry(operation.run_id()).or_insert(0);
            *count = count.saturating_add(1);
        }

        let reply = match profile.provider() {
            ProviderKind::NormalLlm => llm::assess(
                &self.config.transport,
                &self.config.profile,
                &question,
                self.config.control.clone(),
            ),
            ProviderKind::Jev => jev::assess(
                &self.config.transport,
                &self.config.profile,
                &question,
                &self.config.jev_wire_model,
                self.config.control.clone(),
            ),
            ProviderKind::Decisions => decisions::assess(
                &self.config.transport,
                &self.config.profile,
                &question,
                self.config.control.clone(),
            ),
        };

        let observation = match &reply {
            Ok(reply) => ModelRequestObservation::new(
                intent.request_id(),
                intent.attempt_id(),
                RequestOutcome::Completed,
                None,
                reply.reported_model.clone(),
                reply.usage,
            ),
            Err(error) => observation_for_error(&intent, error),
        }
        .map_err(EvaluateError::Gate)?;
        let observed = gate
            .with_gate(|gate| gate.observe(&observation))
            .map_err(EvaluateError::Gate)?;
        observed.map_err(EvaluateError::Gate)?;

        if reply.is_ok() && !self.consent_allows() {
            return Err(EvaluateError::Ask);
        }

        match reply {
            Ok(reply) => Ok(reply.decision),
            Err(error) => Err(EvaluateError::Assessment(error)),
        }
    }
}

impl PermissionEvaluatorPort for PermissionEvaluator {
    fn availability(&self) -> EvaluatorAvailability {
        if self.config.profile.profile().purpose() == ProfilePurpose::Permission
            && self.config.profile.validate().is_ok()
            && self.consent_allows()
            && self.config.budget_gate.is_some()
        {
            EvaluatorAvailability::Available
        } else {
            EvaluatorAvailability::Unavailable
        }
    }

    fn evaluate(
        &mut self,
        request: &herness_core::EvaluationRequest,
    ) -> Result<PermissionDecision, CoreError> {
        match self.evaluate_inner(request) {
            Ok(decision) => Ok(decision),
            Err(EvaluateError::Ask) => Ok(PermissionDecision::Ask),
            Err(EvaluateError::Assessment(error)) => Err(CoreError::PermissionEvaluationFailed {
                failure: failure_kind(error),
            }),
            Err(EvaluateError::Gate(error)) => Err(error),
        }
    }
}

fn request_intent(
    profile: &herness_supervision::profiles::AssessmentProfile,
    question: &question::PermissionQuestion,
) -> Result<RequestGateIntent, CoreError> {
    let project = profile.id().project_id();
    let operation = question.operation().local_id();
    let request_id = RequestId::from_parts(project, operation);
    let attempt_id = AttemptId::from_parts(project, operation);
    let subject = EventSubject::HostActivity(HostActivitySubject::new(
        project,
        EventKind::new("permission_evaluation")?,
        HostActivityId::from_parts(project, operation),
    )?);
    RequestGateIntent::new(
        request_id,
        attempt_id,
        profile.connection(),
        RequestPurpose::new("permission_evaluation")?,
        subject,
        StopDeadlineControl::proceed(),
    )
}

fn observation_for_error(
    intent: &RequestGateIntent,
    error: &AssessmentError,
) -> Result<ModelRequestObservation, CoreError> {
    use crate::error::AssessmentErrorKind;
    let preflight = matches!(
        error.kind(),
        AssessmentErrorKind::InvalidRequest
            | AssessmentErrorKind::ToolUseNotAllowed
            | AssessmentErrorKind::ExternalImageUrl
            | AssessmentErrorKind::UnsupportedModality
            | AssessmentErrorKind::StructuredOutputUnavailable
            | AssessmentErrorKind::InvalidEvidence
            | AssessmentErrorKind::InputTooLarge
            | AssessmentErrorKind::CrossProjectReference
            | AssessmentErrorKind::ProfileBindingMismatch
            | AssessmentErrorKind::UnknownConnection
            | AssessmentErrorKind::CapabilityMismatch
            | AssessmentErrorKind::ModelMismatch
            | AssessmentErrorKind::CredentialUnavailable
            | AssessmentErrorKind::ConnectionFailed
            | AssessmentErrorKind::InvalidConfiguration
            | AssessmentErrorKind::Internal
    );
    if preflight {
        let failure = match error.kind() {
            AssessmentErrorKind::ConnectionFailed => ProviderFailureKind::Network,
            AssessmentErrorKind::CredentialUnavailable => ProviderFailureKind::Authentication,
            _ => ProviderFailureKind::Unknown,
        };
        return ModelRequestObservation::new(
            intent.request_id(),
            intent.attempt_id(),
            RequestOutcome::PreflightFailed,
            Some(failure),
            None,
            TokenUsage::unknown(),
        );
    }
    let outcome = match error.kind() {
        AssessmentErrorKind::Cancelled
        | AssessmentErrorKind::DeadlineReached
        | AssessmentErrorKind::RetryAfterBeyondDeadline => RequestOutcome::Cancelled,
        AssessmentErrorKind::SendResultUnknown => RequestOutcome::SendResultUnknown,
        _ => RequestOutcome::Completed,
    };
    let failure = match error.kind() {
        AssessmentErrorKind::AuthenticationFailed => Some(ProviderFailureKind::Authentication),
        AssessmentErrorKind::RateLimited => Some(ProviderFailureKind::RateLimited),
        AssessmentErrorKind::InvalidResponse | AssessmentErrorKind::ResponseTooLarge => {
            Some(ProviderFailureKind::InvalidResponse)
        }
        _ => None,
    };
    ModelRequestObservation::new(
        intent.request_id(),
        intent.attempt_id(),
        outcome,
        failure,
        None,
        TokenUsage::unknown(),
    )
}

fn failure_kind(error: AssessmentError) -> EvaluationFailureKind {
    use crate::error::AssessmentErrorKind;
    match error.kind() {
        AssessmentErrorKind::DeadlineReached
        | AssessmentErrorKind::SendResultUnknown
        | AssessmentErrorKind::RetryAfterBeyondDeadline => EvaluationFailureKind::Timeout,
        AssessmentErrorKind::AuthenticationFailed => EvaluationFailureKind::Refused,
        AssessmentErrorKind::InvalidResponse | AssessmentErrorKind::ResponseTooLarge => {
            EvaluationFailureKind::InvalidResponse
        }
        _ => EvaluationFailureKind::Unavailable,
    }
}
