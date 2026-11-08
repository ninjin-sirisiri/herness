//! Per-purpose profile/consent registry and the real tool-less assessment port.
//!
//! A profile becomes usable only when a human configured it and a separate
//! acceptance step marked it verified. This build starts every new profile as
//! unverified and returns an explicit unavailable result instead of sending a
//! provider request or substituting the run model.

use std::sync::Arc;

use herness_assessment::llm::EvidenceDocument;
use herness_assessment::{
    AssessmentEndpoints, AssessmentTransport, DecisionsAssessmentAdapter, JevAssessmentAdapter,
    LlmAssessmentAdapter,
};
use herness_core::{
    AttemptId, ConnectionDirectory, ConnectionStatus, CredentialAvailability, CredentialPort,
    EventKind, EventSubject, HostActivityId, HostActivitySubject, ModelRequestGatePort,
    ModelRequestObservation, RequestGateIntent, RequestGateOutcome, RequestId, RequestOutcome,
    RequestPurpose, StopDeadlineControl, TokenUsage,
};
use herness_supervision::budget::gate::BudgetRequestGate;
use herness_supervision::budget::ledger::BudgetLedger;
use herness_supervision::supervisor::{AssessmentProfileFacts, ConditionAssessmentPort};
use herness_supervision::{
    AssessmentProfile, AssessmentRequest, AssessmentResult, EvidenceStorePort, ProfilePurpose,
    ProfileUnavailable, ProviderOrigin, SupervisionError, SupervisionStorePort,
};

use crate::supervision::plan::{
    ConfigStore, ConfiguredProfile, RequestActor, build_consent, model_id,
};
use crate::supervision::store::{HostBudgetClock, HostClock, StoreHandle};

/// Host-owned connection facts needed to validate and build assessment routes.
#[derive(Clone)]
pub struct AssessmentHost {
    /// Shared connection directory (the same registry used by the runtime).
    pub directory: ConnectionDirectory,
    /// Shared credential port (the same Keychain boundary used by the runtime).
    pub credentials: Arc<dyn CredentialPort + Send + Sync>,
    /// Assessment provider bases (official in production, loopback in tests).
    pub endpoints: AssessmentEndpoints,
}

impl AssessmentHost {
    /// Rebuilds a profile entry from the current connection facts.
    pub fn entry(
        &self,
        profile: &AssessmentProfile,
    ) -> Result<herness_supervision::ProfileEntry, SupervisionError> {
        let connection = self
            .directory
            .capabilities(profile.connection())
            .map_err(|error| SupervisionError::ProfileUnavailable {
                reason: profile_unavailable_error(&error),
            })?;
        let status = self
            .credentials
            .availability(&profile.connection())
            .map(|availability| match availability {
                CredentialAvailability::Available => ConnectionStatus::Available,
                CredentialAvailability::LoginRequired => ConnectionStatus::LoginRequired,
                CredentialAvailability::Unavailable => ConnectionStatus::AuthRequired,
            })
            .unwrap_or(ConnectionStatus::Unavailable);
        Ok(herness_supervision::ProfileEntry::new(
            profile.clone(),
            connection,
            status,
            false,
        ))
    }

    /// Exact provider origin used by one registered connection.
    pub fn origin_for(
        &self,
        connection: herness_core::ConnectionId,
    ) -> Result<ProviderOrigin, SupervisionError> {
        let settings =
            self.directory
                .get(connection)
                .map_err(|error| SupervisionError::Unsupported {
                    feature: format!("connection origin is unavailable: {error}"),
                })?;
        if let Some(endpoint) = settings.endpoint() {
            // The consent origin is scheme + host + port; a compatible
            // endpoint may carry a path such as `/v1`.
            let raw = endpoint.as_url();
            let (scheme, rest) = raw.split_once("://").ok_or(SupervisionError::Unsupported {
                feature: "the configured endpoint has no scheme".to_owned(),
            })?;
            let authority = rest
                .split(['/', '?', '#'])
                .next()
                .filter(|authority| !authority.is_empty())
                .ok_or(SupervisionError::Unsupported {
                    feature: "the configured endpoint has no host".to_owned(),
                })?;
            return ProviderOrigin::parse(format!("{scheme}://{authority}"));
        }
        let origin = match settings.provider() {
            herness_core::Provider::OpenAi => "https://api.openai.com",
            herness_core::Provider::Anthropic => "https://api.anthropic.com",
            herness_core::Provider::TypeSafe => "https://api.typesafe.ai",
            herness_core::Provider::OpenAiCompatible => {
                return Err(SupervisionError::Unsupported {
                    feature: "an OpenAI-compatible profile needs an explicit endpoint origin"
                        .to_owned(),
                });
            }
        };
        ProviderOrigin::parse(origin)
    }

    /// Provider kind implied by a registered connection.
    pub fn provider_kind(
        &self,
        connection: herness_core::ConnectionId,
    ) -> Result<herness_supervision::ProviderKind, SupervisionError> {
        let capabilities = self.directory.capabilities(connection).map_err(|error| {
            SupervisionError::Unsupported {
                feature: format!("connection capabilities are unavailable: {error}"),
            }
        })?;
        Ok(match capabilities.endpoint_class() {
            herness_core::EndpointClass::TypeSafeSystemOne => {
                herness_supervision::ProviderKind::Jev
            }
            herness_core::EndpointClass::OpenAiDecisions => {
                herness_supervision::ProviderKind::Decisions
            }
            _ => herness_supervision::ProviderKind::NormalLlm,
        })
    }
}

fn profile_unavailable_error(error: &herness_core::ConnectionError) -> ProfileUnavailable {
    match error {
        herness_core::ConnectionError::UnknownConnection { .. } => {
            ProfileUnavailable::ConnectionMissing
        }
        _ => ProfileUnavailable::ConnectionMissing,
    }
}

/// Builds a new unverified profile for one purpose.
#[allow(clippy::too_many_arguments)]
pub fn build_profile(
    host: &AssessmentHost,
    project: herness_core::ProjectId,
    purpose: ProfilePurpose,
    connection: herness_core::ConnectionId,
    model: &str,
) -> Result<ConfiguredProfile, SupervisionError> {
    let provider = host.provider_kind(connection)?;
    let profile = AssessmentProfile::new(
        herness_supervision::ProfileId::new(project),
        herness_supervision::ProfileVersion::new(1)?,
        purpose,
        provider,
        connection,
        model_id(model)?,
        herness_supervision::AdapterVersion::new(adapter_version(provider))?,
        herness_supervision::RubricVersion::new("herness-conditions-v1")?,
        herness_supervision::ProfileInputs::text_only(),
        herness_supervision::ProfileThresholds::for_provider(provider),
    )?;
    Ok(ConfiguredProfile {
        profile,
        verified: false,
    })
}

/// Adapter version label recorded in the fixed profile.
pub const fn adapter_version(provider: herness_supervision::ProviderKind) -> &'static str {
    match provider {
        herness_supervision::ProviderKind::NormalLlm => "herness-llm-condition-v1",
        herness_supervision::ProviderKind::Jev => "herness-jev-systemone-v1",
        herness_supervision::ProviderKind::Decisions => "herness-openai-decisions-v1",
    }
}

/// Production tool-free condition assessment boundary.
pub struct HostAssessmentPort {
    store: StoreHandle,
    config: ConfigStore,
    host: AssessmentHost,
}

impl HostAssessmentPort {
    /// Creates the port over the shared store and connection registry.
    pub fn new(store: StoreHandle, config: ConfigStore, host: AssessmentHost) -> Self {
        Self {
            store,
            config,
            host,
        }
    }

    fn transport(&self) -> Result<AssessmentTransport, SupervisionError> {
        AssessmentTransport::new(
            Arc::clone(&self.host.credentials),
            self.host.directory.clone(),
            self.host.endpoints.clone(),
        )
        .map_err(|error| SupervisionError::Unsupported {
            feature: format!("assessment transport is unavailable: {error}"),
        })
    }

    fn configured(
        &self,
        project: herness_core::ProjectId,
        binding: herness_supervision::ProfileBinding,
    ) -> Result<ConfiguredProfile, SupervisionError> {
        let config = self.config.get(project);
        let Some(configured) = config.profile(binding.purpose()) else {
            return Err(SupervisionError::ProfileUnavailable {
                reason: ProfileUnavailable::Unset {
                    purpose: binding.purpose(),
                },
            });
        };
        if configured.profile.binding() != binding {
            return Err(SupervisionError::ProfileUnavailable {
                reason: ProfileUnavailable::VersionMismatch {
                    bound: binding.version().get(),
                    configured: configured.profile.version().get(),
                },
            });
        }
        if !configured.verified {
            return Err(SupervisionError::Unsupported {
                feature: "assessment profile is not verified".to_owned(),
            });
        }
        Ok(configured.clone())
    }

    fn consent(
        &self,
        record: &herness_supervision::SupervisionRecord,
        purpose: ProfilePurpose,
    ) -> Result<herness_supervision::DisclosureConsent, SupervisionError> {
        let config = self.config.get(record.project_id());
        let Some(consent) = config.consent(purpose) else {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::Revoked,
            });
        };
        if consent.binding() != record.consent() {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::VersionMismatch,
            });
        }
        if consent.target_scope_version() != record.target_version() {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::TargetScopeChanged,
            });
        }
        consent.require_granted()?;
        Ok(consent.clone())
    }

    fn budget_gate(
        &self,
        request: &AssessmentRequest,
    ) -> Result<
        BudgetRequestGate<StoreHandle, HostBudgetClock, crate::supervision::gate::NoPriceEstimator>,
        SupervisionError,
    > {
        let project = request.project_id();
        let plan =
            crate::supervision::plan::load_plan(&self.store, project, request.supervision_id())
                .ok_or(SupervisionError::Unsupported {
                    feature: "assessment budget plan is unavailable".to_owned(),
                })?;
        let ledger = BudgetLedger::open(
            self.store.clone(),
            project,
            request.supervision_id(),
            plan.budget.policy()?,
            plan.budget_version,
            HostBudgetClock::new(),
        )?;
        Ok(BudgetRequestGate::new(
            ledger,
            crate::supervision::gate::NoPriceEstimator,
        ))
    }

    fn request_intent(
        &self,
        request: &AssessmentRequest,
        connection: herness_core::ConnectionId,
    ) -> Result<RequestGateIntent, SupervisionError> {
        let project = request.project_id();
        let local = request.id().local_id();
        let subject = EventSubject::HostActivity(
            HostActivitySubject::new(
                project,
                EventKind::new("supervision-assessment").map_err(|error| {
                    SupervisionError::AssessmentContractViolation {
                        field: "assessment.activityKind".to_owned(),
                        detail: error.to_string(),
                    }
                })?,
                HostActivityId::from_parts(project, local),
            )
            .map_err(|error| SupervisionError::AssessmentContractViolation {
                field: "assessment.activity".to_owned(),
                detail: error.to_string(),
            })?,
        );
        RequestGateIntent::new(
            RequestId::from_parts(project, local),
            AttemptId::from_parts(project, local),
            connection,
            RequestPurpose::new("completion_assessment").map_err(|error| {
                SupervisionError::AssessmentContractViolation {
                    field: "assessment.purpose".to_owned(),
                    detail: error.to_string(),
                }
            })?,
            subject,
            StopDeadlineControl::proceed(),
        )
        .map_err(|error| SupervisionError::AssessmentContractViolation {
            field: "assessment.gate".to_owned(),
            detail: error.to_string(),
        })
    }
}

impl ConditionAssessmentPort for HostAssessmentPort {
    fn profile(
        &self,
        binding: herness_supervision::ProfileBinding,
    ) -> Result<AssessmentProfileFacts, SupervisionError> {
        let configured = self.configured(binding.profile_id().project_id(), binding)?;
        Ok(AssessmentProfileFacts::new(
            configured.profile.adapter_version().clone(),
            configured.profile.rubric_version().clone(),
            configured.profile.thresholds(),
        ))
    }

    fn assess(
        &mut self,
        request: &AssessmentRequest,
    ) -> Result<AssessmentResult, SupervisionError> {
        let project = request.project_id();
        let record = self
            .store
            .load(project, request.supervision_id())?
            .ok_or(SupervisionError::UnknownSupervision)?;
        let configured = self.configured(project, request.profile())?;
        let consent = self.consent(&record, request.profile().purpose())?;
        let origin = self.host.origin_for(configured.profile.connection())?;
        if consent.origin() != &origin {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::DifferentOrigin,
            });
        }
        if !consent
            .scope()
            .data_kinds()
            .contains(&herness_supervision::DisclosureDataKind::Text)
        {
            return Err(SupervisionError::ConsentBlocked {
                reason: herness_supervision::ConsentBlock::ScopeExpanded {
                    added: vec![herness_supervision::DisclosureDataKind::Text],
                },
            });
        }

        let evidence = self
            .store
            .list_for_supervision(project, request.supervision_id())?;
        let mut documents = Vec::new();
        for evidence_id in request.evidence() {
            let Some(record) = evidence.iter().find(|record| record.id() == *evidence_id) else {
                return Err(SupervisionError::EvidenceContractViolation {
                    field: "assessment.evidence".to_owned(),
                    detail: "requested evidence is no longer present".to_owned(),
                });
            };
            let content = format!(
                "operation: {}\nstatus: {}\noutcome: {}",
                record.operation().as_str(),
                record.status().as_str(),
                record.outcome().detail()
            );
            documents.push(
                EvidenceDocument::text(*evidence_id, content).map_err(|error| {
                    SupervisionError::AssessmentContractViolation {
                        field: "assessment.evidence".to_owned(),
                        detail: error.to_string(),
                    }
                })?,
            );
        }
        if documents.is_empty() {
            return Err(SupervisionError::AssessmentContractViolation {
                field: "assessment.evidence".to_owned(),
                detail: "an assessment needs at least one evidence document".to_owned(),
            });
        }
        let entry = self.host.entry(&configured.profile)?;
        let mut gate = self.budget_gate(request)?;
        let intent = self.request_intent(request, configured.profile.connection())?;
        match gate.admit(&intent).map_err(|error| {
            SupervisionError::AssessmentContractViolation {
                field: "assessment.budget".to_owned(),
                detail: error.to_string(),
            }
        })? {
            RequestGateOutcome::Admit => {}
            RequestGateOutcome::Refuse { reason } => {
                return Err(SupervisionError::Unsupported {
                    feature: format!("assessment budget admission refused: {reason:?}"),
                });
            }
        }
        let remaining = gate.ledger_mut().remaining_active_seconds().unwrap_or(0);
        let transport = self.transport()?;
        let control = herness_assessment::TransportControl::default()
            .with_remaining(std::time::Duration::from_secs(remaining));
        let clock: Arc<dyn herness_supervision::ClockPort + Send + Sync> = Arc::new(HostClock);
        let result = match configured.profile.provider() {
            herness_supervision::ProviderKind::NormalLlm => {
                LlmAssessmentAdapter::new(transport, clock)
                    .assess(request, &entry, &documents, control)
                    .map_err(assessment_error)
                    .map(|assessment| assessment.into_result())
            }
            herness_supervision::ProviderKind::Jev => JevAssessmentAdapter::new(transport, clock)
                .assess(request, &entry, &documents, control)
                .map_err(assessment_error)
                .map(|assessment| assessment.into_result()),
            herness_supervision::ProviderKind::Decisions => {
                DecisionsAssessmentAdapter::new(transport, clock)
                    .assess(request, &entry, &documents, control)
                    .map_err(assessment_error)
                    .map(|assessment| assessment.into_result())
            }
        };
        let observation = match &result {
            Ok(_) => ModelRequestObservation::new(
                intent.request_id(),
                intent.attempt_id(),
                RequestOutcome::Completed,
                None,
                None,
                TokenUsage::unknown(),
            ),
            Err(_) => ModelRequestObservation::new(
                intent.request_id(),
                intent.attempt_id(),
                RequestOutcome::SendResultUnknown,
                None,
                None,
                TokenUsage::unknown(),
            ),
        }
        .map_err(|error| SupervisionError::AssessmentContractViolation {
            field: "assessment.observation".to_owned(),
            detail: error.to_string(),
        })?;
        gate.observe(&observation).map_err(|error| {
            SupervisionError::AssessmentContractViolation {
                field: "assessment.budgetObservation".to_owned(),
                detail: error.to_string(),
            }
        })?;
        result
    }
}

fn assessment_error(error: herness_assessment::AssessmentError) -> SupervisionError {
    // Sanitized error text only; provider bodies and credentials never appear.
    SupervisionError::Unsupported {
        feature: format!("assessment request failed: {error}"),
    }
}

/// Builds a consent record from a human request.
#[allow(clippy::too_many_arguments)]
pub fn build_human_consent(
    actor: &RequestActor,
    project: herness_core::ProjectId,
    purpose: ProfilePurpose,
    origin: herness_supervision::ProviderOrigin,
    data_kinds: std::collections::BTreeSet<herness_supervision::DisclosureDataKind>,
    targets: Vec<String>,
    target_version: herness_supervision::TargetVersion,
    now: herness_core::Timestamp,
) -> Result<herness_supervision::DisclosureConsent, SupervisionError> {
    build_consent(
        actor,
        project,
        purpose,
        origin,
        data_kinds,
        targets,
        target_version,
        now,
    )
}

/// Loads the current consent for one target and purpose, if any.
pub fn configured_consent(
    config: &ConfigStore,
    project: herness_core::ProjectId,
    purpose: ProfilePurpose,
) -> Option<herness_supervision::DisclosureConsent> {
    config.get(project).consent(purpose).cloned()
}
