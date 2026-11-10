//! App-lifetime H3 desktop composition and the trusted operation commands.
//!
//! One [`crate::host::DesktopHost`] owns exactly one [`HtmlSyncRecoveryHost`]
//! (one `HtmlSyncWorker`, one private candidate store, one observer per open
//! project) and one [`HtmlSyncServices`] (policy bridges, publication
//! operations, assessment host, and the H4 barrier port). Commands never
//! construct a second engine, store, worker, or runtime.
//!
//! The HTML worker is activated only when every required capability is really
//! present: the versioned policy bridge, authoring dispatch, candidate tooling,
//! a real render path, Html assessment, and a current human approval. The pack
//! definition alone is never enough, and an unavailable capability is reported
//! explicitly rather than replaced by a model or a different provider.
//!
//! Every mutation here is host-only. The command layer verifies the trusted main
//! window first; this module additionally requires the stored current revision,
//! a current human approval, and an explicit human confirmation for destructive
//! operations.
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use herness_core::{ProjectId, RunControl, Timestamp};
use herness_html_sync::{
    BarrierOutcome, BarrierRequest, CycleId, CycleState, DocumentCommit, DocumentKey,
    H3ApprovalState, H3Approver, H3CancelCause, H3ConfigurationApproval, H3ConfigurationDraft,
    H3DocumentRecord, H3DocumentState, H3DocumentStatus, H3Operation, H3OperationOutcome,
    H3OperationRequest, H3OperationResult, H3Reason, H3Settings, H3SettingsRecord, H3State,
    H3StateReasonKind, H3StopCause, H3StorePort, H4Barrier, HistoryReadPort, HtmlSyncCommit,
    PublicationFileReadPort, PublicationJournal, PublicationStatus, RequestCommit, RequiredAction,
    SettingsCommit, SyncCycle, document_state_event, settings_event,
};
use herness_supervision::{BudgetUsage, ContentDigest, ProfilePurpose, SupervisionId};
use serde::{Deserialize, Serialize};

use crate::host::DesktopHost;
use crate::html_sync::assessment::HtmlAssessmentHost;
use crate::html_sync::operations::DesktopHtmlSyncOperations;
use crate::html_sync::pipeline::{CandidateRenderPort, NativeRenderPort};
use crate::html_sync::policy::{ConnectedPolicyBridge, HtmlPolicyBridge, PolicyBridgeError};
use crate::html_sync::publish::ProjectPublicationFiles;
use crate::supervision::store::StoreHandle;
use crate::supervision::{BudgetView, EvidenceView, SupervisionView};

/// One required HtmlWorker capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HtmlSyncCapability {
    /// Verified Common SDD host API connection.
    PolicyBridge,
    /// Approved H2 owner dispatch to the H1 candidate run.
    AuthoringDispatch,
    /// Private candidate storage and candidate-only H1 tools.
    CandidateTooling,
    /// Real isolated render evidence.
    RealRender,
    /// Html-purpose assessment with a verified profile and consent.
    Assessment,
    /// Current human configuration approval bound to the settings version.
    TrustedApproval,
}

impl HtmlSyncCapability {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyBridge => "policy_bridge",
            Self::AuthoringDispatch => "authoring_dispatch",
            Self::CandidateTooling => "candidate_tooling",
            Self::RealRender => "real_render",
            Self::Assessment => "assessment",
            Self::TrustedApproval => "trusted_approval",
        }
    }
}

/// One capability result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncCapabilityState {
    capability: &'static str,
    available: bool,
    detail: String,
}

impl HtmlSyncCapabilityState {
    /// Capability label.
    pub const fn capability(&self) -> &'static str {
        self.capability
    }

    /// Whether the capability is really present.
    pub const fn available(&self) -> bool {
        self.available
    }

    /// Sanitized explanation.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Complete HtmlWorker capability report for one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncCapabilityReport {
    checked: bool,
    available: bool,
    states: Vec<HtmlSyncCapabilityState>,
}

impl HtmlSyncCapabilityReport {
    /// Builds a report from explicit checks. Missing checks are treated as
    /// unavailable, so a partial report can never enable the worker.
    pub fn from_checks(
        checks: impl IntoIterator<Item = (HtmlSyncCapability, bool, String)>,
    ) -> Self {
        let mut found = BTreeMap::new();
        for (capability, available, detail) in checks {
            found.insert(capability, (available, detail));
        }
        let states = HtmlSyncCapability::ALL
            .into_iter()
            .map(|capability| match found.remove(&capability) {
                Some((available, detail)) => HtmlSyncCapabilityState {
                    capability: capability.as_str(),
                    available,
                    detail,
                },
                None => HtmlSyncCapabilityState {
                    capability: capability.as_str(),
                    available: false,
                    detail: "capability was not checked".to_owned(),
                },
            })
            .collect::<Vec<_>>();
        let available = states.iter().all(HtmlSyncCapabilityState::available);
        Self {
            checked: true,
            available,
            states,
        }
    }

    /// Report for a project whose capabilities have not been checked yet.
    pub fn unchecked() -> Self {
        Self {
            checked: false,
            available: false,
            states: HtmlSyncCapability::ALL
                .into_iter()
                .map(|capability| HtmlSyncCapabilityState {
                    capability: capability.as_str(),
                    available: false,
                    detail: "capability has not been checked in this process".to_owned(),
                })
                .collect(),
        }
    }

    /// Every required capability in stable order.
    pub fn states(&self) -> &[HtmlSyncCapabilityState] {
        &self.states
    }

    /// Whether every required capability is present.
    pub const fn available(&self) -> bool {
        self.available
    }

    /// Whether this process actually evaluated the capabilities.
    pub const fn checked(&self) -> bool {
        self.checked
    }

    /// Missing capabilities only.
    pub fn missing(&self) -> Vec<&HtmlSyncCapabilityState> {
        self.states
            .iter()
            .filter(|state| !state.available)
            .collect()
    }
}

impl HtmlSyncCapability {
    /// Every capability in stable order.
    pub const ALL: [Self; 6] = [
        Self::PolicyBridge,
        Self::AuthoringDispatch,
        Self::CandidateTooling,
        Self::RealRender,
        Self::Assessment,
        Self::TrustedApproval,
    ];
}

/// One authoring or assessment send scope bound by the human approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncSendScopeView {
    pub purpose: String,
    pub role: &'static str,
    pub connection_id: String,
    pub origin: String,
    pub data_kinds: Vec<String>,
    pub targets: Vec<String>,
    pub target_scope_version: u64,
}

/// One purpose-specific profile/consent display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncPurposeView {
    pub purpose: String,
    pub role: &'static str,
    pub configured: bool,
    pub verified: bool,
    pub supported: bool,
    pub consent_state: String,
    pub detail: String,
}

/// One approved settings display value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncSettingsView {
    pub revision: u64,
    pub version: u64,
    pub enabled: bool,
    pub approved: bool,
    pub scan_only: bool,
    pub approval_id: Option<String>,
    pub approval_state: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub target_paths: Vec<String>,
    pub auto_publish: bool,
    pub retain_history: bool,
    pub authoring: Option<HtmlSyncSendScopeView>,
    pub assessment: Option<HtmlSyncSendScopeView>,
}

/// One Target whose companion is absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncMissingCompanion {
    pub target: String,
    pub companion: String,
}

/// Observer health for one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncObserverView {
    pub watcher_healthy: bool,
    pub pending_documents: usize,
    pub uncertain_documents: Vec<String>,
}

/// Latest publication state for one document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncPublicationView {
    pub publication_id: String,
    pub generation: String,
    pub status: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub final_project_sequence: Option<u64>,
    pub detail: Option<String>,
}

/// External HTML conflict display. No file is changed by reading this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncConflictView {
    pub cause: String,
    pub expected_html_digest: Option<String>,
    pub observed_html_digest: Option<String>,
    pub required_actions: Vec<String>,
}

/// One saved document state as shown to the trusted UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncDocumentView {
    pub status: H3DocumentStatus,
    pub state: String,
    pub unsynced: bool,
    pub undetermined: bool,
    pub reason: H3Reason,
    pub required_actions: Vec<String>,
    pub publication: Option<HtmlSyncPublicationView>,
    pub conflict: Option<HtmlSyncConflictView>,
    pub history: Vec<HtmlSyncHistoryEntryView>,
}

/// H2 reference and saved evidence/budget summary.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncH2View {
    pub supervision_id: SupervisionId,
    pub revision: u64,
    pub state: String,
    pub reason: serde_json::Value,
    pub condition_version: u64,
    pub target_version: u64,
    pub unmet_conditions: Vec<String>,
    pub budget: Option<BudgetView>,
    pub evidence: Vec<EvidenceView>,
    pub conditions: Vec<crate::supervision::ConditionView>,
    pub completion_stale: Option<serde_json::Value>,
    pub plan_available: bool,
}

/// Complete saved H3/H2 state for one project.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncProjectView {
    pub project_id: ProjectId,
    pub project_sequence: u64,
    pub capabilities: HtmlSyncCapabilityReport,
    pub settings: Option<HtmlSyncSettingsView>,
    pub scan_only: bool,
    pub purposes: Vec<HtmlSyncPurposeView>,
    pub missing_companions: Vec<HtmlSyncMissingCompanion>,
    pub multi_cycle_cost_warning: &'static str,
    pub observer: Option<HtmlSyncObserverView>,
    pub h2: Option<HtmlSyncH2View>,
    pub documents: Vec<HtmlSyncDocumentView>,
}

/// Human approval input. There is no approver field: the command layer always
/// records [`H3Approver::Human`] after the trusted-main guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HtmlSyncApprovalRequest {
    /// Project being approved.
    pub project_id: ProjectId,
    /// Positive settings version this approval covers.
    pub settings_version: u64,
    /// Host-owned approval identifier.
    pub approval_id: String,
    /// Optional expiry.
    pub expires_at: Option<Timestamp>,
    /// Approved canonical Target paths.
    pub targets: Vec<String>,
    /// Authoring (Completion) connection approval.
    pub authoring: herness_html_sync::H3ConnectionApproval,
    /// Html assessment connection approval.
    pub assessment: herness_html_sync::H3ConnectionApproval,
    /// Pack/policy/rubric/host-API versions.
    pub versions: herness_html_sync::H3VersionBinding,
    /// Approved numeric limits.
    pub limits: herness_html_sync::H3ApprovalLimits,
    /// Whether an evaluated candidate may publish automatically.
    pub auto_publish: bool,
    /// Whether old versions are retained.
    pub retain_history: bool,
    /// Must be true; the approved capability is the automatic companion.
    pub automatic_companion: bool,
    /// H2 owner binding for the job.
    pub owner: herness_html_sync::H3OwnerBinding,
    /// Whether the new settings version is enabled.
    pub enabled: bool,
}

/// Result of storing one human approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncApprovalView {
    pub project_id: ProjectId,
    pub settings_revision: u64,
    pub settings_version: u64,
    pub enabled: bool,
    pub approval_id: String,
}

/// Result of one explicit enable attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncEnableView {
    pub project_id: ProjectId,
    pub settings_version: u64,
    pub capabilities: HtmlSyncCapabilityReport,
    pub worker_bound: bool,
}

/// One document mutation command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HtmlSyncDocumentCommand {
    /// Idempotent request identifier.
    pub request_id: herness_html_sync::H3RequestId,
    /// Project that owns the document.
    pub project_id: ProjectId,
    /// Document to change.
    pub document: DocumentKey,
    /// Durable revision the human observed.
    pub expected_revision: u64,
    /// Exact source digest the human observed, when supplied.
    #[serde(default)]
    pub expected_source_digest: Option<ContentDigest>,
}

/// Persisted result of one mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncOperationView {
    pub result: H3OperationResult,
    pub document: Option<H3DocumentStatus>,
    pub project_sequence: u64,
}

/// One saved generation history entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncHistoryEntryView {
    pub generation_id: String,
    pub generation: u64,
    pub generation_status: String,
    pub completed: bool,
    pub source_revision: u64,
    pub source_digest: String,
    pub candidate_html_digest: Option<String>,
    pub publication: Option<HtmlSyncPublicationView>,
    pub started_at: Timestamp,
    pub completed_at: Option<Timestamp>,
    pub superseded_at: Option<Timestamp>,
}

/// One saved document history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncHistoryView {
    pub project_id: ProjectId,
    pub document: DocumentKey,
    pub generations: Vec<HtmlSyncHistoryEntryView>,
}

/// Saved H3/H2 budget state. The H2 ledger is authoritative.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncBudgetView {
    pub project_id: ProjectId,
    pub supervision_id: Option<SupervisionId>,
    pub budget: Option<BudgetView>,
    pub usage: Option<BudgetUsage>,
    pub multi_cycle_cost_warning: &'static str,
}

/// Multi-cycle cost warning shown next to approval and budget displays.
pub const MULTI_CYCLE_COST_WARNING: &str = "Approved authoring and Html assessment send data to the selected connections. Each new sync \
     cycle can incur additional model cost; H3 does not reset the H2 cycle budget on source edits, \
     generation supersession, or resume.";

/// Read-only H4 completion barrier adapter.
#[derive(Clone)]
pub struct DesktopH4Barrier {
    store: StoreHandle,
}

impl DesktopH4Barrier {
    /// Creates the barrier over the one shared H3 store.
    pub fn new(store: StoreHandle) -> Self {
        Self { store }
    }

    /// Checks the requested document version and dependent inputs without
    /// mutating H3 state or implementing H4 Task progress.
    pub fn check(
        &self,
        request: &BarrierRequest,
        now: Timestamp,
    ) -> Result<BarrierOutcome, String> {
        H4Barrier::new(&self.store)
            .check(request, now)
            .map_err(|error| error.to_string())
    }
}

/// App-lifetime H3 services other than the worker/recovery host.
pub struct HtmlSyncServices {
    store: StoreHandle,
    archive_root: PathBuf,
    pack_root: Option<PathBuf>,
    toolchain: herness_core::ToolchainConfig,
    control: RunControl,
    assessment: Option<HtmlAssessmentHost>,
    bridges: BTreeMap<ProjectId, Arc<ConnectedPolicyBridge>>,
    operations: BTreeMap<ProjectId, DesktopHtmlSyncOperations>,
    barrier: DesktopH4Barrier,
    render_available: bool,
    candidate_tooling_available: bool,
    render: Option<Arc<dyn CandidateRenderPort>>,
    evidence_root: PathBuf,
}

impl HtmlSyncServices {
    /// Creates the one app-lifetime service set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: StoreHandle,
        app_data_root: &Path,
        pack_root: Option<PathBuf>,
        toolchain: herness_core::ToolchainConfig,
        control: RunControl,
        assessment: Option<HtmlAssessmentHost>,
    ) -> Result<Self, String> {
        let archive_root = app_data_root.join("html-sync-history");
        if !archive_root.is_absolute() {
            return Err("the private history root must be absolute".to_owned());
        }
        let store_for_barrier = store.clone();
        Ok(Self {
            store,
            archive_root,
            pack_root,
            toolchain,
            control,
            assessment,
            bridges: BTreeMap::new(),
            operations: BTreeMap::new(),
            barrier: DesktopH4Barrier::new(store_for_barrier),
            render_available: cfg!(target_os = "macos"),
            candidate_tooling_available: true,
            render: None,
            evidence_root: app_data_root.join("html-sync-evidence"),
        })
    }

    /// The H4 completion barrier port.
    pub const fn barrier(&self) -> &DesktopH4Barrier {
        &self.barrier
    }

    /// Test seam: override the two capabilities that cannot be simulated from
    /// an ordinary desktop test without a GUI or provider.
    #[doc(hidden)]
    pub fn set_test_capabilities(
        &mut self,
        render_available: bool,
        candidate_tooling_available: bool,
    ) {
        self.render_available = render_available;
        self.candidate_tooling_available = candidate_tooling_available;
    }

    /// Shared store handle.
    pub fn store_handle(&self) -> StoreHandle {
        self.store.clone()
    }

    /// Private history archive root.
    pub fn archive_root(&self) -> &Path {
        &self.archive_root
    }

    /// Private root for durable assessment content.
    pub fn evidence_root(&self) -> &Path {
        &self.evidence_root
    }

    /// Replaces the toolchain used for the verified Common SDD host-API
    /// connection. Production reads it from the host environment; acceptance
    /// tests pass the repository's explicit validator path.
    pub fn set_toolchain(&mut self, toolchain: herness_core::ToolchainConfig) {
        self.toolchain = toolchain;
    }

    /// Installs the production hidden-window render port once the desktop
    /// application handle exists. It is not an approval and grants no access.
    pub fn install_native_render(&mut self, app: tauri::AppHandle) {
        self.render = Some(Arc::new(NativeRenderPort::new(app)));
        self.render_available = true;
    }

    /// Installs an explicit render port. Used by the real child-capture
    /// acceptance tests; the production path uses the native port.
    pub fn set_render_port(&mut self, render: Arc<dyn CandidateRenderPort>) {
        self.render = Some(render);
        self.render_available = true;
    }

    /// The installed render port, when present.
    pub fn render_port(&self) -> Option<Arc<dyn CandidateRenderPort>> {
        self.render.clone()
    }

    /// Mutable Html assessment host.
    pub fn assessment_mut(&mut self) -> Option<&mut HtmlAssessmentHost> {
        self.assessment.as_mut()
    }

    /// The verified policy connection for one approved project, connecting it
    /// once when needed. It never sends a model request.
    pub fn policy_bridge(
        &mut self,
        project: ProjectId,
        root: &Path,
        settings: &H3Settings,
    ) -> Result<Arc<ConnectedPolicyBridge>, String> {
        self.prepare_policy_bridge(project, root, settings)
    }

    fn prepare_policy_bridge(
        &mut self,
        project: ProjectId,
        root: &Path,
        settings: &H3Settings,
    ) -> Result<Arc<ConnectedPolicyBridge>, String> {
        if let Some(bridge) = self.bridges.get(&project) {
            return Ok(Arc::clone(bridge));
        }
        let Some(pack_root) = self.pack_root.as_ref() else {
            return Err(
                "no Common SDD pack root is configured; the pack definition alone cannot enable the HtmlWorker"
                    .to_owned(),
            );
        };
        let bridge = HtmlPolicyBridge::detect(root, pack_root, self.toolchain.clone())
            .map_err(policy_error)?;
        let observed = bridge
            .probe()
            .approval_binding()
            .map_err(|error| format!("the pack approval binding is invalid: {error}"))?;
        if let Some(approval) = settings.approval() {
            let approved = approval.pack_binding();
            if approved.integration_schema() != observed.integration_schema()
                || approved.integration_version() != observed.integration_version()
                || approved.integration_revision() != observed.integration_revision()
                || approved.policy_version() != observed.policy_version()
                || approved.policy_fingerprint() != observed.policy_fingerprint()
                || approved.pack_fingerprint() != observed.pack_fingerprint()
                || approved.host_api_protocol() != observed.host_api_protocol()
                || approved.host_api_version() != observed.host_api_version()
            {
                return Err(
                    "the current pack identity differs from the human-approved pack binding"
                        .to_owned(),
                );
            }
        }
        let connected = bridge.connect(&observed).map_err(policy_error)?;
        let connected = Arc::new(connected);
        self.bridges.insert(project, Arc::clone(&connected));
        Ok(connected)
    }

    pub(crate) fn ensure_operations(
        &mut self,
        project: ProjectId,
        root: &Path,
    ) -> Result<&mut DesktopHtmlSyncOperations, String> {
        if !self.operations.contains_key(&project) {
            let bridge = self
                .bridges
                .get(&project)
                .cloned()
                .ok_or_else(|| "the policy bridge is not connected".to_owned())?;
            let operations = DesktopHtmlSyncOperations::from_shared(
                project,
                root,
                self.store.clone(),
                self.archive_root.clone(),
                bridge,
                self.control.clone(),
            )
            .map_err(|error| error.to_string())?;
            self.operations.insert(project, operations);
        }
        Ok(self
            .operations
            .get_mut(&project)
            .expect("operations were inserted above"))
    }

    /// Evaluates every required HtmlWorker capability for one project.
    ///
    /// This may start one local host-API `capabilities` call for the policy
    /// bridge. It never sends a model request or writes a project file.
    pub fn evaluate(
        &mut self,
        project: ProjectId,
        root: &Path,
        settings: &H3Settings,
        h2: Option<&SupervisionView>,
    ) -> HtmlSyncCapabilityReport {
        let now = Timestamp::now();
        let approval_current = settings.verify_fingerprint()
            && settings.enabled()
            && settings.approval().is_some_and(|approval| {
                approval.project_id() == project
                    && approval.settings_version() == settings.version()
                    && approval.is_current_at(now)
            });

        let policy = match self.prepare_policy_bridge(project, root, settings) {
            Ok(_) => (true, "verified Common SDD host-API connection".to_owned()),
            Err(error) => (false, error),
        };

        let dispatch = match h2 {
            Some(view) => {
                let supported =
                    !matches!(view.state.as_str(), "failed" | "cancelled" | "completed");
                (
                    supported,
                    if supported {
                        format!("H2 target {} is available", view.supervision_id)
                    } else {
                        format!("H2 target {} is {}", view.supervision_id, view.state)
                    },
                )
            }
            None => (
                false,
                "no approved H2 supervision target is associated with the project".to_owned(),
            ),
        };

        let assessment = match (&self.assessment, h2) {
            (Some(_), Some(view)) => match view
                .purposes
                .iter()
                .find(|purpose| purpose.purpose == ProfilePurpose::Html.as_str())
            {
                Some(purpose) if purpose.verified && purpose.consent_state == "granted" => (
                    true,
                    "verified Html profile and granted Html consent".to_owned(),
                ),
                Some(purpose) => (
                    false,
                    format!(
                        "Html profile verified={}, consent={}",
                        purpose.verified, purpose.consent_state
                    ),
                ),
                None => (false, "no Html assessment profile is configured".to_owned()),
            },
            (Some(_), None) => (
                false,
                "no H2 target is available to carry Html assessment".to_owned(),
            ),
            (None, _) => (false, "the Html assessment host is not composed".to_owned()),
        };

        let trusted = match &settings.approval() {
            Some(approval) if approval_current => (
                true,
                format!(
                    "current human approval {} for settings version {}",
                    approval.approval_id(),
                    approval.settings_version()
                ),
            ),
            Some(_) => (
                false,
                "the stored human approval is disabled, stale, expired, or tampered".to_owned(),
            ),
            None => (
                false,
                "the stored settings carry no human configuration approval".to_owned(),
            ),
        };

        let report = HtmlSyncCapabilityReport::from_checks([
            (HtmlSyncCapability::PolicyBridge, policy.0, policy.1),
            (
                HtmlSyncCapability::AuthoringDispatch,
                dispatch.0,
                dispatch.1,
            ),
            (
                HtmlSyncCapability::CandidateTooling,
                self.candidate_tooling_available,
                if self.candidate_tooling_available {
                    "private candidate storage and candidate-only tools are composed".to_owned()
                } else {
                    "private candidate storage or candidate-only tools are unavailable".to_owned()
                },
            ),
            (
                HtmlSyncCapability::RealRender,
                self.render_available,
                if self.render_available {
                    "native isolated render evidence is available".to_owned()
                } else {
                    "no real isolated render path is available".to_owned()
                },
            ),
            (HtmlSyncCapability::Assessment, assessment.0, assessment.1),
            (HtmlSyncCapability::TrustedApproval, trusted.0, trusted.1),
        ]);

        if report.available() {
            let _ = self.ensure_operations(project, root);
        }
        report
    }
}

fn policy_error(error: PolicyBridgeError) -> String {
    format!("policy bridge unavailable: {error}")
}

// ---------------------------------------------------------------------------
// Saved-state view.
// ---------------------------------------------------------------------------

/// Builds the complete saved state view. It reads the store and runtime
/// snapshot on every call; it never reuses a command result as success.
pub fn project_view(host: &DesktopHost, project: ProjectId) -> Result<HtmlSyncProjectView, String> {
    let store = host.store_handle();
    let project_sequence = host
        .runtime()
        .last_sequence(project)
        .map_err(|error| error.to_string())?;
    let settings_record = store
        .load_html_sync_settings(project)
        .map_err(|error| error.to_string())?;
    let settings = settings_record.as_ref().map(|record| record.settings());
    let capabilities = host
        .html_sync()
        .capability_report(project)
        .cloned()
        .unwrap_or_else(HtmlSyncCapabilityReport::unchecked);
    let supervision_id = host.html_sync_supervision_id(project);
    let h2_view =
        supervision_id.and_then(|supervision| host.supervision_get(project, supervision).ok());
    let root = host
        .html_sync()
        .project_root(project)
        .map(Path::to_path_buf);
    let settings_view = settings_record
        .as_ref()
        .map(|record| settings_display(record, Timestamp::now()));
    let scan_only = settings_view.as_ref().is_none_or(|view| view.scan_only);
    let purposes = purposes_display(settings, h2_view.as_ref());
    let missing_companions = match (root.as_deref(), settings) {
        (Some(root), Some(settings)) => missing_companions(root, settings),
        _ => Vec::new(),
    };
    let observer = host
        .html_sync()
        .observer_health(project)
        .map(|health| HtmlSyncObserverView {
            watcher_healthy: health.watcher_is_healthy(),
            pending_documents: health.pending_documents,
            uncertain_documents: health
                .uncertain_documents
                .iter()
                .map(|document| document.target_path().to_owned())
                .collect(),
        });
    let h2 = h2_view.map(|view| HtmlSyncH2View {
        supervision_id: view.supervision_id,
        revision: view.revision,
        state: view.state,
        reason: view.reason,
        condition_version: view.condition_version,
        target_version: view.target_version,
        unmet_conditions: view.unmet_conditions,
        budget: view.budget,
        evidence: view.evidence,
        conditions: view.conditions,
        completion_stale: view.completion_stale,
        plan_available: view.plan_available,
    });
    let mut documents = Vec::new();
    for record in store
        .list_html_sync_documents(project)
        .map_err(|error| error.to_string())?
    {
        documents.push(document_view(&store, project, &record)?);
    }
    Ok(HtmlSyncProjectView {
        project_id: project,
        project_sequence,
        capabilities,
        settings: settings_view,
        scan_only,
        purposes,
        missing_companions,
        multi_cycle_cost_warning: MULTI_CYCLE_COST_WARNING,
        observer,
        h2,
        documents,
    })
}

fn settings_display(record: &H3SettingsRecord, now: Timestamp) -> HtmlSyncSettingsView {
    let settings = record.settings();
    let approval = settings.approval();
    let approved = settings.verify_fingerprint()
        && settings.enabled()
        && approval.is_some_and(|approval| {
            approval.settings_version() == settings.version()
                && approval.project_id() == settings.project_id()
                && approval.is_current_at(now)
        });
    let approval_state = approval.map(|approval| match approval.state() {
        H3ApprovalState::Approved => "approved".to_owned(),
        H3ApprovalState::Revoked { .. } => "revoked".to_owned(),
        H3ApprovalState::Superseded { .. } => "superseded".to_owned(),
    });
    let send_scope = |entry: Option<&herness_html_sync::H3ConnectionApproval>,
                      role: &'static str|
     -> Option<HtmlSyncSendScopeView> {
        entry.map(|entry| HtmlSyncSendScopeView {
            purpose: entry.disclosure().purpose().as_str().to_owned(),
            role,
            connection_id: entry.connection_id().to_string(),
            origin: entry.origin().to_string(),
            data_kinds: entry
                .disclosure()
                .data_kinds()
                .iter()
                .map(|kind| kind.as_str().to_owned())
                .collect(),
            targets: entry.disclosure().targets().to_vec(),
            target_scope_version: entry.disclosure().target_scope_version().get(),
        })
    };
    HtmlSyncSettingsView {
        revision: record.revision(),
        version: settings.version(),
        enabled: settings.enabled(),
        approved,
        scan_only: !approved,
        approval_id: approval.map(|approval| approval.approval_id().to_owned()),
        approval_state,
        expires_at: approval.and_then(|approval| approval.expires_at()),
        target_paths: settings.target_paths().to_vec(),
        auto_publish: settings.auto_publish(),
        retain_history: settings.retain_history(),
        authoring: send_scope(approval.map(|approval| approval.authoring()), "authoring"),
        assessment: send_scope(approval.map(|approval| approval.assessment()), "assessment"),
    }
}

fn purposes_display(
    settings: Option<&H3Settings>,
    h2: Option<&SupervisionView>,
) -> Vec<HtmlSyncPurposeView> {
    let mut purposes = Vec::new();
    for purpose in [ProfilePurpose::Completion, ProfilePurpose::Html] {
        let status = h2.and_then(|view| {
            view.purposes
                .iter()
                .find(|entry| entry.purpose == purpose.as_str())
        });
        let approved = settings
            .and_then(H3Settings::approval)
            .and_then(|approval| {
                if purpose == ProfilePurpose::Completion {
                    Some(approval.authoring())
                } else {
                    Some(approval.assessment())
                }
            });
        let configured = status.is_some_and(|status| status.configured) || approved.is_some();
        let verified = status.is_some_and(|status| status.verified);
        let consent_state = status
            .map(|status| status.consent_state.clone())
            .unwrap_or_else(|| "unset".to_owned());
        let supported = configured && verified && consent_state == "granted";
        let detail = if supported {
            "verified profile with granted consent".to_owned()
        } else if configured {
            format!(
                "not supported for automatic work: verified={verified}, consent={consent_state}"
            )
        } else {
            "no profile or consent is configured for this purpose".to_owned()
        };
        purposes.push(HtmlSyncPurposeView {
            purpose: purpose.as_str().to_owned(),
            role: if purpose == ProfilePurpose::Completion {
                "authoring"
            } else {
                "assessment"
            },
            configured,
            verified,
            supported,
            consent_state,
            detail,
        });
    }
    purposes
}

fn missing_companions(root: &Path, settings: &H3Settings) -> Vec<HtmlSyncMissingCompanion> {
    let mut missing = Vec::new();
    for target in settings.target_paths() {
        let Ok(document) = DocumentKey::new(settings.project_id(), target.clone()) else {
            continue;
        };
        let companion = document.companion_path();
        if !root.join(&companion).is_file() {
            missing.push(HtmlSyncMissingCompanion {
                target: target.clone(),
                companion,
            });
        }
    }
    missing
}

fn document_view(
    store: &StoreHandle,
    project: ProjectId,
    record: &H3DocumentRecord,
) -> Result<HtmlSyncDocumentView, String> {
    let state = record.state();
    let journals = store
        .list_html_sync_publications(project, state.document_key())
        .map_err(|error| error.to_string())?;
    let publication = journals.last().map(publication_view);
    let reason = state.reason().clone();
    let unsynced = state.state() != H3State::Synced || !state.applicability().is_applicable();
    let undetermined = matches!(
        reason.kind(),
        H3StateReasonKind::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::UndecidableAssessment
        }
    );
    let conflict = match reason.kind() {
        H3StateReasonKind::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::ExternalHtmlConflict,
        } => Some(HtmlSyncConflictView {
            cause: "external_html_conflict".to_owned(),
            expected_html_digest: match state.applicability().reason() {
                herness_html_sync::ApplicabilityReason::HtmlChanged { expected, .. } => {
                    Some(expected.as_str().to_owned())
                }
                _ => None,
            },
            observed_html_digest: match state.applicability().reason() {
                herness_html_sync::ApplicabilityReason::HtmlChanged { observed, .. } => {
                    Some(observed.as_str().to_owned())
                }
                _ => None,
            },
            required_actions: reason
                .required_actions()
                .iter()
                .map(|action| action.as_str().to_owned())
                .collect(),
        }),
        _ => None,
    };
    let history = generation_entries(store, project, state.document_key(), 5, &journals)?;
    Ok(HtmlSyncDocumentView {
        status: record.status(),
        state: state.state().as_str().to_owned(),
        unsynced,
        undetermined,
        required_actions: reason
            .required_actions()
            .iter()
            .map(|action| action.as_str().to_owned())
            .collect(),
        reason,
        publication,
        conflict,
        history,
    })
}

fn publication_view(journal: &PublicationJournal) -> HtmlSyncPublicationView {
    HtmlSyncPublicationView {
        publication_id: journal.publication_id().to_string(),
        generation: journal.generation_id().to_string(),
        status: publication_status_label(journal.status()).to_owned(),
        created_at: journal.created_at(),
        updated_at: journal.updated_at(),
        final_project_sequence: journal.final_project_sequence(),
        detail: journal.detail().map(str::to_owned),
    }
}

fn publication_status_label(status: PublicationStatus) -> &'static str {
    match status {
        PublicationStatus::Prepared => "prepared",
        PublicationStatus::OldVersionSaved => "old_version_saved",
        PublicationStatus::Replacing => "replacing",
        PublicationStatus::Published => "published",
        PublicationStatus::NotPublished => "not_published",
        PublicationStatus::Unverifiable => "unverifiable",
        PublicationStatus::Conflict => "conflict",
    }
}

/// Reads one document's saved generation history. This is read-only and does
/// not synthesize a current-synced flag.
pub fn history_view(
    host: &DesktopHost,
    project: ProjectId,
    document: &DocumentKey,
    limit: u32,
) -> Result<HtmlSyncHistoryView, String> {
    if limit == 0 {
        return Err("history limit must be positive".to_owned());
    }
    document
        .validate_in(project)
        .map_err(|error| error.to_string())?;
    let store = host.store_handle();
    let journals = store
        .list_html_sync_publications(project, document)
        .map_err(|error| error.to_string())?;
    let generations = generation_entries(&store, project, document, limit, &journals)?;
    Ok(HtmlSyncHistoryView {
        project_id: project,
        document: document.clone(),
        generations,
    })
}

fn generation_entries(
    store: &StoreHandle,
    project: ProjectId,
    document: &DocumentKey,
    limit: u32,
    journals: &[PublicationJournal],
) -> Result<Vec<HtmlSyncHistoryEntryView>, String> {
    Ok(store
        .html_sync_generations(project, document)
        .map_err(|error| error.to_string())?
        .into_iter()
        .rev()
        .take(limit as usize)
        .map(|generation| {
            let publication = generation
                .publication()
                .and_then(|publication| {
                    journals
                        .iter()
                        .find(|journal| journal.publication_id() == publication)
                })
                .map(publication_view);
            HtmlSyncHistoryEntryView {
                generation_id: generation.generation_id().to_string(),
                generation: generation.generation(),
                generation_status: format!("{:?}", generation.status()).to_ascii_lowercase(),
                completed: generation.completed(),
                source_revision: generation.source().revision().get(),
                source_digest: generation.source().digest().as_str().to_owned(),
                candidate_html_digest: generation
                    .candidate()
                    .map(|candidate| candidate.html_digest().as_str().to_owned()),
                publication,
                started_at: generation.started_at(),
                completed_at: generation.completed_at(),
                superseded_at: generation.superseded_at(),
            }
        })
        .collect())
}

/// Reads the saved H3/H2 budget state for one project.
pub fn budget_view(host: &DesktopHost, project: ProjectId) -> Result<HtmlSyncBudgetView, String> {
    let supervision_id = host.html_sync_supervision_id(project);
    let h2 = supervision_id.and_then(|supervision| host.supervision_get(project, supervision).ok());
    let budget = h2.as_ref().and_then(|view| view.budget.clone());
    Ok(HtmlSyncBudgetView {
        project_id: project,
        supervision_id,
        usage: budget.as_ref().map(|budget| budget.usage.clone()),
        budget,
        multi_cycle_cost_warning: MULTI_CYCLE_COST_WARNING,
    })
}

/// Checks the requested H4 barrier version and dependent inputs.
pub fn barrier_view(
    host: &DesktopHost,
    request: &BarrierRequest,
    now: Timestamp,
) -> Result<BarrierOutcome, String> {
    host.html_sync_services().barrier().check(request, now)
}

// ---------------------------------------------------------------------------
// Approve / enable.
// ---------------------------------------------------------------------------

impl DesktopHost {
    /// Finds the approved H2 supervision target associated with one project.
    ///
    /// Saved H3 document/cycle/generation state is the first source. Before the
    /// first document exists, the human-approved owner binding is matched
    /// against the durable H2 plan map. No target is invented.
    pub fn html_sync_supervision_id(&self, project: ProjectId) -> Option<SupervisionId> {
        if let Some(supervision) = self.html_sync().supervision_for(project) {
            return Some(supervision);
        }
        let owner = self
            .store_handle()
            .load_html_sync_settings(project)
            .ok()
            .flatten()?
            .settings()
            .approval()?
            .owner_binding()
            .owner()
            .clone();
        let plans = self.supervision().plans();
        let plans = plans.lock().ok()?;
        plans
            .iter()
            .find(|((candidate, _), plan)| *candidate == project && plan.owner == owner)
            .map(|((_, supervision), _)| *supervision)
    }
}

/// Stores one human configuration approval. The caller has already passed the
/// trusted-main guard and supplied a human confirmation.
pub fn approve(
    host: &mut DesktopHost,
    request: &HtmlSyncApprovalRequest,
) -> Result<HtmlSyncApprovalView, String> {
    if host.html_sync().active_project() == Some(request.project_id) {
        return Err(
            "the project has active H3 authoring; stop it before changing the approval".to_owned(),
        );
    }
    let now = Timestamp::now();
    let approval = H3ConfigurationApproval::approve(
        H3ConfigurationDraft {
            project_id: request.project_id,
            settings_version: request.settings_version,
            approval_id: request.approval_id.clone(),
            expires_at: request.expires_at,
            targets: request.targets.clone(),
            authoring: request.authoring.clone(),
            assessment: request.assessment.clone(),
            versions: request.versions.clone(),
            limits: request.limits.clone(),
            auto_publish: request.auto_publish,
            retain_history: request.retain_history,
            automatic_companion: request.automatic_companion,
            owner: request.owner.clone(),
        },
        H3Approver::Human,
        now,
    )
    .map_err(|error| error.to_string())?;
    let settings =
        H3Settings::approved(approval, request.enabled).map_err(|error| error.to_string())?;
    let mut store = host.store_handle();
    let existing = store
        .load_html_sync_settings(request.project_id)
        .map_err(|error| error.to_string())?;
    let event = settings_event(&settings, now).map_err(|error| error.to_string())?;
    let commit = HtmlSyncCommit::new()
        .with_settings(
            SettingsCommit::new(
                existing.as_ref().map(H3SettingsRecord::revision),
                settings.clone(),
            )
            .map_err(|error| error.to_string())?,
        )
        .with_events(vec![event]);
    let outcome = store
        .commit_html_sync(commit)
        .map_err(|error| error.to_string())?;
    let record = match outcome {
        herness_html_sync::HtmlSyncCommitOutcome::Applied { settings, .. } => settings
            .ok_or_else(|| "the settings commit did not return the new settings".to_owned())?,
        herness_html_sync::HtmlSyncCommitOutcome::Duplicate { .. } => {
            return Err("the settings commit was unexpectedly treated as a duplicate".to_owned());
        }
    };
    host.html_sync_mut()
        .set_capability_report(request.project_id, HtmlSyncCapabilityReport::unchecked());
    Ok(HtmlSyncApprovalView {
        project_id: request.project_id,
        settings_revision: record.revision(),
        settings_version: record.settings().version(),
        enabled: record.settings().enabled(),
        approval_id: record
            .settings()
            .approval()
            .map(|approval| approval.approval_id().to_owned())
            .unwrap_or_default(),
    })
}

/// Explicitly enables the already-approved settings when, and only when, every
/// required HtmlWorker capability is present.
pub fn enable(host: &mut DesktopHost, project: ProjectId) -> Result<HtmlSyncEnableView, String> {
    let store = host.store_handle();
    let settings_record = store
        .load_html_sync_settings(project)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the project has no stored H3 settings".to_owned())?;
    let settings = settings_record.settings().clone();
    let root = host
        .html_sync()
        .project_root(project)
        .map(Path::to_path_buf)
        .ok_or_else(|| "the project is not registered with the H3 composition".to_owned())?;
    let supervision_id = host.html_sync_supervision_id(project);
    let h2 = supervision_id.and_then(|supervision| host.supervision_get(project, supervision).ok());
    let report = host
        .html_sync_services_mut()
        .evaluate(project, &root, &settings, h2.as_ref());
    host.html_sync_mut()
        .set_capability_report(project, report.clone());
    let mut worker_bound = false;
    if report.available()
        && let Some(supervision_id) = supervision_id
    {
        let dependencies = crate::host::discovered_dependencies(&root, &settings);
        host.html_sync_mut()
            .register_project(project, &root, dependencies.clone());
        worker_bound = host
            .html_sync_mut()
            .activate_project(
                project,
                &root,
                settings.clone(),
                supervision_id,
                dependencies,
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(HtmlSyncEnableView {
        project_id: project,
        settings_version: settings.version(),
        capabilities: report,
        worker_bound,
    })
}

// ---------------------------------------------------------------------------
// Document mutations.
// ---------------------------------------------------------------------------

/// Applies one explicit human document operation.
pub fn apply_document_operation(
    host: &mut DesktopHost,
    request: H3OperationRequest,
) -> Result<HtmlSyncOperationView, String> {
    let project = request.project_id();
    let store = host.store_handle();
    if let Some(stored) = store
        .html_sync_request_result(project, request.request_id())
        .map_err(|error| error.to_string())?
    {
        if stored.fingerprint() == request.fingerprint() {
            return Ok(HtmlSyncOperationView {
                document: request
                    .document()
                    .and_then(|document| {
                        store
                            .load_html_sync_document(project, document)
                            .ok()
                            .flatten()
                    })
                    .map(|record| record.status()),
                project_sequence: stored.result().final_project_sequence(),
                result: stored.replay(),
            });
        }
        return Err(format!(
            "request {} was already recorded for another operation",
            request.request_id()
        ));
    }

    let document = request
        .document()
        .cloned()
        .ok_or_else(|| "this operation requires one document".to_owned())?;
    let record = store
        .load_html_sync_document(project, &document)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the document has no saved H3 state".to_owned())?;
    if request.expected_revision() != Some(record.revision()) {
        return Err(format!(
            "the document revision changed: expected {:?}, found {}",
            request.expected_revision(),
            record.revision()
        ));
    }
    if let Some(expected) = request.expected_source_digest()
        && expected != record.state().source().digest()
    {
        return Err("the document source changed after the human observed it".to_owned());
    }
    let now = Timestamp::now();
    match request.operation() {
        H3Operation::Pause => pause_document(host, &request, &record, now),
        H3Operation::Cancel => cancel_document(host, &request, &record, now),
        H3Operation::Resume => resume_document(host, &request, &record, now),
        H3Operation::Reassess | H3Operation::Regenerate => {
            reassess_document(host, &request, &record, now)
        }
        H3Operation::ResolveConflict { resolution } => {
            resolve_conflict(host, &request, &record, *resolution, now)
        }
        H3Operation::RestoreHistory { generation } => {
            restore_document(host, &request, &record, *generation)
        }
        _ => Err(format!(
            "{} is not a supported document mutation",
            request.operation().as_str()
        )),
    }
}

fn pause_document(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    record: &H3DocumentRecord,
    now: Timestamp,
) -> Result<HtmlSyncOperationView, String> {
    let state = record.state();
    if state.state() == H3State::Synced {
        return reject(host, request, record, now, RequiredAction::ResumeCycle);
    }
    let document = state.document_key();
    let stop = host
        .html_sync_stop_active(document)
        .map_err(|error| error.to_string())?;
    if stop == Some(herness_html_sync::StopOutcome::Unconfirmed) {
        host.html_sync_mut().seed_latch(
            document.clone(),
            Some(herness_html_sync::CycleLatch::RecoveryReconciliation),
            "the H1 stop was not confirmed; reconcile before another run",
        );
        let reason = H3Reason::new(
            H3StateReasonKind::Stopped {
                cause: H3StopCause::StopUnconfirmed,
            },
            vec![RequiredAction::ReconcileRecovery],
        )
        .map_err(|error| error.to_string())?;
        return reject_with_reason(host, request, record, reason, now);
    }
    let reason = H3Reason::new(
        H3StateReasonKind::Stopped {
            cause: H3StopCause::HumanRequest,
        },
        vec![RequiredAction::ResumeCycle],
    )
    .map_err(|error| error.to_string())?;
    let latch = Some(herness_html_sync::CycleLatch::HumanStop);
    commit_state(
        host,
        request,
        record,
        reason,
        herness_html_sync::Applicability::not_applicable(
            herness_html_sync::ApplicabilityReason::NeverPublished,
        ),
        latch,
        Some(CycleState::Stopped),
        now,
    )
}

fn cancel_document(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    record: &H3DocumentRecord,
    now: Timestamp,
) -> Result<HtmlSyncOperationView, String> {
    let state = record.state();
    if state.state() == H3State::Synced {
        return reject(host, request, record, now, RequiredAction::ResumeCycle);
    }
    let document = state.document_key();
    let stop = host
        .html_sync_stop_active(document)
        .map_err(|error| error.to_string())?;
    if stop == Some(herness_html_sync::StopOutcome::Unconfirmed) {
        host.html_sync_mut().seed_latch(
            document.clone(),
            Some(herness_html_sync::CycleLatch::RecoveryReconciliation),
            "the H1 stop was not confirmed; reconcile before another run",
        );
        let reason = H3Reason::new(
            H3StateReasonKind::Stopped {
                cause: H3StopCause::StopUnconfirmed,
            },
            vec![RequiredAction::ReconcileRecovery],
        )
        .map_err(|error| error.to_string())?;
        return reject_with_reason(host, request, record, reason, now);
    }
    let reason = H3Reason::new(
        H3StateReasonKind::Cancelled {
            cause: H3CancelCause::HumanRequest,
        },
        vec![RequiredAction::ResumeCycle],
    )
    .map_err(|error| error.to_string())?;
    commit_state(
        host,
        request,
        record,
        reason,
        herness_html_sync::Applicability::not_applicable(
            herness_html_sync::ApplicabilityReason::NeverPublished,
        ),
        Some(herness_html_sync::CycleLatch::HumanStop),
        Some(CycleState::Cancelled),
        now,
    )
}

fn resume_document(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    record: &H3DocumentRecord,
    now: Timestamp,
) -> Result<HtmlSyncOperationView, String> {
    let document = record.state().document_key().clone();
    let preflight = host
        .html_sync_resume_preflight(&document, record.revision(), now)
        .map_err(|error| error.to_string())?;
    if !preflight.allowed() {
        let reason = H3Reason::new(
            H3StateReasonKind::Stopped {
                cause: H3StopCause::RecoveryReconciliation,
            },
            preflight.required_actions().to_vec(),
        )
        .map_err(|error| error.to_string())?;
        return reject_with_reason(host, request, record, reason, now);
    }
    // A human resume is the only path that may create a new cycle after a
    // stop/cancel. An already-open cycle is reused so the H2 budget ledger is
    // not replaced; a stopped cycle is never reopened.
    let state = record.state();
    let (cycle, new_cycle) = resumable_cycle(
        host,
        state,
        state.settings_version(),
        now,
    )?;
    let reason = H3Reason::new(
        H3StateReasonKind::Pending {
            source_revision: state.source().revision().get(),
        },
        vec![RequiredAction::WaitForStableSource],
    )
    .map_err(|error| error.to_string())?;
    let new_state = rebuild_state(
        state,
        reason,
        herness_html_sync::Applicability::not_applicable(
            herness_html_sync::ApplicabilityReason::NeverPublished,
        ),
        None,
        Some(cycle.cycle_id()),
        now,
    )?;
    let result = H3OperationResult::new(
        request,
        H3OperationOutcome::Accepted {
            state: H3State::Pending,
            revision: record.revision() + 1,
        },
        0,
        now,
    )
    .map_err(|error| error.to_string())?;
    let event = document_state_event(&document, Some(state.state()), &new_state, now)
        .map_err(|error| error.to_string())?;
    let mut commit = HtmlSyncCommit::new()
        .with_document(
            DocumentCommit::new(Some(record.revision()), new_state)
                .map_err(|error| error.to_string())?,
        )
        .with_request(
            RequestCommit::new(request.clone(), result).map_err(|error| error.to_string())?,
        )
        .with_events(vec![event]);
    if new_cycle {
        commit = commit.with_cycle(cycle);
    }
    commit_operation(host, request, commit)?;
    host.html_sync_mut().clear_latch(&document);
    let _ = host
        .html_sync_mut()
        .requeue_document(state.project_id(), &document);
    operation_view(host, request)
}

fn reassess_document(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    record: &H3DocumentRecord,
    now: Timestamp,
) -> Result<HtmlSyncOperationView, String> {
    let state = record.state();
    let settings = host
        .store_handle()
        .load_html_sync_settings(state.project_id())
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the project has no stored H3 settings".to_owned())?;
    if !settings.settings().verify_fingerprint()
        || !settings.settings().enabled()
        || settings
            .settings()
            .approval()
            .is_none_or(|approval| !approval.is_current_at(now))
    {
        return reject(host, request, record, now, RequiredAction::ApproveSettings);
    }
    let document = state.document_key().clone();
    // A saved active generation with an exact candidate is reassessed in place:
    // the current source/dependencies are re-verified, the real render and the
    // three Html assessment methods run again, and only a completion-ready
    // evaluation reaches publication. A document with no stored candidate is
    // requeued from the source as before.
    if let Some(generation_id) = state.generation()
        && host
            .store_handle()
            .html_sync_generations(state.project_id(), &document)
            .ok()
            .and_then(|generations| {
                generations
                    .into_iter()
                    .find(|generation| generation.generation_id() == generation_id)
            })
            .is_some_and(|generation| {
                generation.status() == herness_html_sync::GenerationStatus::Active
                    && generation.candidate().is_some()
            })
    {
        return reassess_saved_candidate(host, request, now);
    }
    let (cycle, new_cycle) = resumable_cycle(host, state, settings.settings().version(), now)?;
    let reason = H3Reason::new(
        H3StateReasonKind::Pending {
            source_revision: state.source().revision().get(),
        },
        vec![RequiredAction::ReassessCandidate],
    )
    .map_err(|error| error.to_string())?;
    let new_state = rebuild_state(
        state,
        reason,
        herness_html_sync::Applicability::not_applicable(
            herness_html_sync::ApplicabilityReason::NeverPublished,
        ),
        None,
        Some(cycle.cycle_id()),
        now,
    )?;
    let result = H3OperationResult::new(
        request,
        H3OperationOutcome::Accepted {
            state: H3State::Pending,
            revision: record.revision() + 1,
        },
        0,
        now,
    )
    .map_err(|error| error.to_string())?;
    let event = document_state_event(&document, Some(state.state()), &new_state, now)
        .map_err(|error| error.to_string())?;
    let mut commit = HtmlSyncCommit::new()
        .with_document(
            DocumentCommit::new(Some(record.revision()), new_state)
                .map_err(|error| error.to_string())?,
        )
        .with_request(
            RequestCommit::new(request.clone(), result).map_err(|error| error.to_string())?,
        )
        .with_events(vec![event]);
    if new_cycle {
        commit = commit.with_cycle(cycle);
    }
    commit_operation(host, request, commit)?;
    host.html_sync_mut().clear_latch(&document);
    let _ = host
        .html_sync_mut()
        .requeue_document(state.project_id(), &document);
    operation_view(host, request)
}

fn reassess_saved_candidate(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    now: Timestamp,
) -> Result<HtmlSyncOperationView, String> {
    let document = request
        .document()
        .cloned()
        .ok_or_else(|| "reassess requires one document".to_owned())?;
    host.html_sync_mut().clear_latch(&document);
    let advanced = host.html_sync_advance(&document);
    let record = host
        .store_handle()
        .load_html_sync_document(request.project_id(), &document)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the document state disappeared during reassessment".to_owned())?;
    let outcome = match &advanced {
        Ok(crate::html_sync::pipeline::PostCandidateOutcome::Publication(
            herness_html_sync::PublicationOutcome::Synced { .. },
        )) => H3OperationOutcome::Accepted {
            state: H3State::Synced,
            revision: record.revision(),
        },
        Ok(crate::html_sync::pipeline::PostCandidateOutcome::WaitingHuman {
            cause,
            detail: _,
        }) => H3OperationOutcome::Rejected {
            reason: H3Reason::new(
                H3StateReasonKind::WaitingHuman { cause: *cause },
                vec![RequiredAction::ReassessCandidate],
            )
            .map_err(|error| error.to_string())?,
        },
        Ok(crate::html_sync::pipeline::PostCandidateOutcome::FixableUnmet { .. })
        | Ok(crate::html_sync::pipeline::PostCandidateOutcome::VerificationRejected {
            ..
        }) => H3OperationOutcome::Rejected {
            reason: H3Reason::new(
                H3StateReasonKind::Failed {
                    cause: herness_html_sync::H3FailureCause::CandidateRejected,
                },
                vec![RequiredAction::ReviewFailure],
            )
            .map_err(|error| error.to_string())?,
        },
        Ok(_) => H3OperationOutcome::Accepted {
            state: record.state().state(),
            revision: record.revision(),
        },
        Err(_detail) => H3OperationOutcome::Rejected {
            reason: H3Reason::new(
                H3StateReasonKind::WaitingHuman {
                    cause: herness_html_sync::HumanWaitCause::RecoveryReconciliation,
                },
                vec![RequiredAction::ReconcileRecovery],
            )
            .map_err(|error| error.to_string())?,
        },
    };
    let result = H3OperationResult::new(request, outcome, 0, now)
        .map_err(|error| error.to_string())?;
    commit_request_with_current_state(host, request, result, now)?;
    operation_view(host, request)
}

fn commit_request_with_current_state(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    result: H3OperationResult,
    now: Timestamp,
) -> Result<(), String> {
    let document = request
        .document()
        .cloned()
        .ok_or_else(|| "the operation requires one document".to_owned())?;
    let record = host
        .store_handle()
        .load_html_sync_document(request.project_id(), &document)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the document state disappeared".to_owned())?;
    let state = record.state().clone();
    let event = document_state_event(&document, Some(state.state()), &state, now)
        .map_err(|error| error.to_string())?;
    commit_operation(
        host,
        request,
        HtmlSyncCommit::new()
            .with_document(
                DocumentCommit::new(Some(record.revision()), state)
                    .map_err(|error| error.to_string())?,
            )
            .with_request(
                RequestCommit::new(request.clone(), result).map_err(|error| error.to_string())?,
            )
            .with_events(vec![event]),
    )
}

fn resolve_conflict(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    record: &H3DocumentRecord,
    resolution: herness_html_sync::ConflictResolution,
    now: Timestamp,
) -> Result<HtmlSyncOperationView, String> {
    use herness_html_sync::ConflictResolution;
    match resolution {
        ConflictResolution::KeepWaiting => {
            let reason = H3Reason::new(
                H3StateReasonKind::WaitingHuman {
                    cause: herness_html_sync::HumanWaitCause::ExternalHtmlConflict,
                },
                vec![
                    RequiredAction::ResolveHtmlConflict {
                        target: record.state().document_key().companion_path(),
                    },
                    RequiredAction::ReassessCandidate,
                ],
            )
            .map_err(|error| error.to_string())?;
            reject_with_reason(host, request, record, reason, now)
        }
        ConflictResolution::AdoptCurrent => Err(
            "adopting the current HTML requires an explicit validated adoption payload; no \
             structural-only result is accepted"
                .to_owned(),
        ),
        ConflictResolution::ReplaceWithCandidate => {
            let document = record.state().document_key().clone();
            let generation = record
                .state()
                .generation()
                .ok_or_else(|| {
                    "replacing the current HTML requires a saved scanned candidate".to_owned()
                })?;
            let candidate_exists = host
                .store_handle()
                .html_sync_generations(record.state().project_id(), &document)
                .map_err(|error| error.to_string())?
                .into_iter()
                .find(|entry| entry.generation_id() == generation)
                .is_some_and(|entry| entry.candidate().is_some());
            if !candidate_exists {
                return Err(
                    "replacing the current HTML requires a saved scanned candidate".to_owned(),
                );
            }
            host.html_sync_mut().clear_latch(&document);
            let advanced = host.html_sync_replace_with_candidate(&document);
            let current = host
                .store_handle()
                .load_html_sync_document(record.state().project_id(), &document)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "the document state disappeared during replacement".to_owned())?;
            let outcome = match &advanced {
                Ok(crate::html_sync::pipeline::PostCandidateOutcome::Publication(
                    herness_html_sync::PublicationOutcome::Synced { .. },
                )) => H3OperationOutcome::Accepted {
                    state: H3State::Synced,
                    revision: current.revision(),
                },
                Ok(crate::html_sync::pipeline::PostCandidateOutcome::WaitingHuman {
                    cause,
                    ..
                }) => H3OperationOutcome::Rejected {
                    reason: H3Reason::new(
                        H3StateReasonKind::WaitingHuman { cause: *cause },
                        vec![RequiredAction::ReassessCandidate],
                    )
                    .map_err(|error| error.to_string())?,
                },
                Ok(_) | Err(_) => H3OperationOutcome::Rejected {
                    reason: H3Reason::new(
                        H3StateReasonKind::WaitingHuman {
                            cause: herness_html_sync::HumanWaitCause::ExternalHtmlConflict,
                        },
                        vec![RequiredAction::ResolveHtmlConflict {
                            target: record.state().document_key().companion_path(),
                        }],
                    )
                    .map_err(|error| error.to_string())?,
                },
            };
            let result = H3OperationResult::new(request, outcome, 0, now)
                .map_err(|error| error.to_string())?;
            commit_request_with_current_state(host, request, result, now)?;
            operation_view(host, request)
        }
    }
}

fn restore_document(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    record: &H3DocumentRecord,
    generation: herness_html_sync::GenerationId,
) -> Result<HtmlSyncOperationView, String> {
    let project = record.state().project_id();
    let document = record.state().document_key().clone();
    let root = host
        .html_sync()
        .project_root(project)
        .map(Path::to_path_buf)
        .ok_or_else(|| "the project is not registered with the H3 composition".to_owned())?;
    {
        let operations = host
            .html_sync_services_mut()
            .ensure_operations(project, &root)?;
        let selected = operations
            .history_reader()
            .load_version(&document, generation)
            .map_err(|error| error.to_string())?;
        if selected.is_none() {
            return Err(
                "the selected generation has no complete published history pair".to_owned(),
            );
        }
    }
    let publication = host
        .store_handle()
        .list_html_sync_publications(project, &document)
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|journal| {
            journal.generation_id() == generation
                && journal.status() == PublicationStatus::Published
        })
        .map(|journal| journal.publication_id())
        .ok_or_else(|| "the selected generation has no published journal".to_owned())?;
    let files = ProjectPublicationFiles::new(&root).map_err(|error| error.to_string())?;
    let expected_html = current_expected(&files, &document.companion_path())?;
    let receipt_path = herness_html_sync::html_evidence_path(&document);
    let expected_receipt = current_expected(&files, &receipt_path)?;
    let now = Timestamp::now();
    let outcome = host
        .html_sync_services_mut()
        .ensure_operations(project, &root)?
        .restore_history(request, publication, &expected_html, &expected_receipt, now)
        .map_err(|error| error.to_string())?;
    match outcome {
        herness_html_sync::HistoryRestoreOutcome::Restored { .. }
        | herness_html_sync::HistoryRestoreOutcome::Unchanged { .. } => {
            host.html_sync_mut().clear_latch(&document);
            operation_view(host, request)
        }
        other => Err(format!(
            "the restore was not applied: {}",
            restore_label(&other)
        )),
    }
}

fn restore_label(outcome: &herness_html_sync::HistoryRestoreOutcome) -> &'static str {
    match outcome {
        herness_html_sync::HistoryRestoreOutcome::Restored { .. } => "restored",
        herness_html_sync::HistoryRestoreOutcome::Unchanged { .. } => "unchanged",
        herness_html_sync::HistoryRestoreOutcome::Conflict { .. } => "conflict",
        herness_html_sync::HistoryRestoreOutcome::WaitingHuman { .. } => "waiting_human",
        herness_html_sync::HistoryRestoreOutcome::NotRestored { .. } => "not_restored",
        herness_html_sync::HistoryRestoreOutcome::ReconciliationRequired { .. } => {
            "reconciliation_required"
        }
    }
}

fn current_expected(
    files: &ProjectPublicationFiles,
    path: &str,
) -> Result<herness_core::ExpectedTargetVersion, String> {
    match files.read(path).map_err(|error| error.to_string())? {
        Some(bytes) => Ok(herness_core::ExpectedTargetVersion::present(
            herness_core::FileVersion::new(ContentDigest::sha256(&bytes).as_str())
                .map_err(|error| error.to_string())?,
        )),
        None => Ok(herness_core::ExpectedTargetVersion::absent()),
    }
}

fn resumable_cycle(
    host: &DesktopHost,
    state: &H3DocumentState,
    settings_version: u64,
    now: Timestamp,
) -> Result<(SyncCycle, bool), String> {
    if let Some(cycle_id) = state.cycle_id()
        && let Some(cycle) = host
            .store_handle()
            .load_html_sync_cycle(state.project_id(), cycle_id)
            .map_err(|error| error.to_string())?
        && cycle.state() == CycleState::Open
    {
        return Ok((cycle, false));
    }
    let cycle = SyncCycle::new(
        CycleId::new(state.project_id()),
        state.document_key().clone(),
        settings_version,
        now,
        state.source().clone(),
        host.html_sync_supervision_id(state.project_id()),
    )
    .map_err(|error| error.to_string())?;
    Ok((cycle, true))
}

fn commit_state(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    record: &H3DocumentRecord,
    reason: H3Reason,
    applicability: herness_html_sync::Applicability,
    latch: Option<herness_html_sync::CycleLatch>,
    cycle_end: Option<CycleState>,
    now: Timestamp,
) -> Result<HtmlSyncOperationView, String> {
    let state = record.state();
    let next = rebuild_state(
        state,
        reason.clone(),
        applicability,
        state.generation(),
        state.cycle_id(),
        now,
    )?;
    let result = H3OperationResult::new(
        request,
        H3OperationOutcome::Accepted {
            state: reason.state(),
            revision: record.revision() + 1,
        },
        0,
        now,
    )
    .map_err(|error| error.to_string())?;
    let event = document_state_event(state.document_key(), Some(state.state()), &next, now)
        .map_err(|error| error.to_string())?;
    let mut commit = HtmlSyncCommit::new()
        .with_document(
            DocumentCommit::new(Some(record.revision()), next)
                .map_err(|error| error.to_string())?,
        )
        .with_request(
            RequestCommit::new(request.clone(), result).map_err(|error| error.to_string())?,
        )
        .with_events(vec![event]);
    if let Some(cycle_end) = cycle_end
        && let Some(cycle_id) = state.cycle_id()
        && let Some(cycle) = host
            .store_handle()
            .load_html_sync_cycle(state.project_id(), cycle_id)
            .map_err(|error| error.to_string())?
        && cycle.state() == CycleState::Open
    {
        commit = commit.with_cycle(
            cycle
                .end(cycle_end, now)
                .map_err(|error| error.to_string())?,
        );
    }
    commit_operation(host, request, commit)?;
    if let Some(latch) = latch {
        host.html_sync_mut().seed_latch(
            state.document_key().clone(),
            Some(latch),
            "explicit human stop/cancel",
        );
    }
    operation_view(host, request)
}

fn rebuild_state(
    state: &H3DocumentState,
    reason: H3Reason,
    applicability: herness_html_sync::Applicability,
    generation: Option<herness_html_sync::GenerationId>,
    cycle: Option<herness_html_sync::CycleId>,
    now: Timestamp,
) -> Result<H3DocumentState, String> {
    H3DocumentState::new(
        state.document_key().clone(),
        state.settings_version(),
        state.job_id(),
        cycle,
        generation,
        state.source().clone(),
        state.fingerprints().clone(),
        reason,
        state.h2().cloned(),
        state.evidence().to_vec(),
        applicability,
        now,
    )
    .map_err(|error| error.to_string())
}

fn reject(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    record: &H3DocumentRecord,
    now: Timestamp,
    action: RequiredAction,
) -> Result<HtmlSyncOperationView, String> {
    let reason = H3Reason::new(
        H3StateReasonKind::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::RecoveryReconciliation,
        },
        vec![action],
    )
    .map_err(|error| error.to_string())?;
    reject_with_reason(host, request, record, reason, now)
}

fn reject_with_reason(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    _record: &H3DocumentRecord,
    reason: H3Reason,
    now: Timestamp,
) -> Result<HtmlSyncOperationView, String> {
    let result = H3OperationResult::new(request, H3OperationOutcome::Rejected { reason }, 0, now)
        .map_err(|error| error.to_string())?;
    Ok(HtmlSyncOperationView {
        document: request
            .document()
            .and_then(|document| load_status(host, request.project_id(), document)),
        project_sequence: host
            .runtime()
            .last_sequence(request.project_id())
            .map_err(|error| error.to_string())?,
        result,
    })
}

fn commit_operation(
    host: &mut DesktopHost,
    request: &H3OperationRequest,
    commit: HtmlSyncCommit,
) -> Result<(), String> {
    let mut store = host.store_handle();
    match store
        .commit_html_sync(commit)
        .map_err(|error| error.to_string())?
    {
        herness_html_sync::HtmlSyncCommitOutcome::Applied { .. } => Ok(()),
        herness_html_sync::HtmlSyncCommitOutcome::Duplicate { stored, .. } => {
            if stored.fingerprint() == request.fingerprint() {
                Ok(())
            } else {
                Err(format!(
                    "request {} was already recorded for another operation",
                    request.request_id()
                ))
            }
        }
    }
}

fn operation_view(
    host: &DesktopHost,
    request: &H3OperationRequest,
) -> Result<HtmlSyncOperationView, String> {
    let project = request.project_id();
    let store = host.store_handle();
    let stored = store
        .html_sync_request_result(project, request.request_id())
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the operation result was not persisted".to_owned())?;
    let document = request
        .document()
        .and_then(|document| load_status(host, project, document));
    Ok(HtmlSyncOperationView {
        result: stored.result().clone(),
        document,
        project_sequence: stored.result().final_project_sequence(),
    })
}

fn load_status(
    host: &DesktopHost,
    project: ProjectId,
    document: &DocumentKey,
) -> Option<H3DocumentStatus> {
    host.store_handle()
        .load_html_sync_document(project, document)
        .ok()
        .flatten()
        .map(|record| record.status())
}
