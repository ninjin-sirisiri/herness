//! Desktop H3 HTML sync adapters.
//!
//! Task 14 adds the Common SDD policy bridge, Task 17 the non-privileged
//! WKWebView render evidence, and Task 18 the versioned evidence and Html
//! condition-assessment adapters. Assessment calls the existing H2 tool-free
//! transport through its purpose, consent, and budget gates; nothing in this
//! module writes a formal file, creates HTML, or bypasses those gates.

pub mod assessment;
pub mod composition;
pub mod observer;
pub mod operations;
pub mod policy;
pub mod publish;
pub mod recovery;
pub mod render;
#[cfg(target_os = "macos")]
mod render_macos;
pub mod render_test;
pub mod verification;
pub mod store;
pub mod worker;

pub use observer::{
    ProjectFilesystemWatcher, WatchAdapterError, WatchNotice, external_editor_change,
    native_saved_change, shell_change, signal_from_absolute,
};

pub use policy::{
    CandidateCheck, CandidateDecision, CandidateStage, ConnectedPolicyBridge, HtmlPolicyBridge,
    PackProbe, PolicyBootstrap, PolicyBridgeError, PolicyFinding,
};
pub use render::{
    BrowserEvidence, CancellationToken, CandidateEvidence, ConfigurationEvidence, CssViewport,
    HiddenWindowEvidence, IsolationEvidence, PngEvidence, ProtocolEvidence, ProtocolRequestRecord,
    RENDER_CONFIGURATIONS, RENDER_HARD_TIMEOUT, RENDER_MANIFEST_VERSION, RenderAppearance,
    RenderBudget, RenderConfiguration, RenderError, RenderEvidence, RenderFailure, RenderJob,
    RenderManifest, RenderPng, RenderResource, RenderSignals, RenderStatus, RenderViewport,
    RouterSelfProbe, render_candidate,
};
pub use render_test::RenderTestLaunch;
pub use verification::{
    CandidateVerification, CandidateVerificationRequest, FingerprintCapture, PolicyCheckSummary,
    render_facts, verify_candidate,
};
pub use assessment::{HTML_ASSESSMENT_PURPOSE, HtmlAssessmentHost};
pub use composition::{
    DesktopH4Barrier, HtmlSyncApprovalRequest, HtmlSyncApprovalView, HtmlSyncBudgetView,
    HtmlSyncCapability, HtmlSyncCapabilityReport, HtmlSyncCapabilityState, HtmlSyncDocumentCommand,
    HtmlSyncDocumentView, HtmlSyncEnableView, HtmlSyncH2View, HtmlSyncHistoryEntryView,
    HtmlSyncHistoryView, HtmlSyncMissingCompanion, HtmlSyncObserverView, HtmlSyncOperationView,
    HtmlSyncProjectView, HtmlSyncPublicationView, HtmlSyncPurposeView, HtmlSyncSendScopeView,
    HtmlSyncServices, HtmlSyncSettingsView, MULTI_CYCLE_COST_WARNING,
};
pub use operations::{
    DesktopHtmlSyncOperations, PrivateHistoryReader, validate_current_html,
};
pub use publish::{
    DesktopPublisher, H3PublicationRecords, H3PublicationSafety, ObserverWriteExpectations,
    PolicyFinalCheck, ProjectPublicationFiles, SharedHistoryArchive,
};
pub use recovery::{
    HtmlSyncQuitReport, HtmlSyncRecoveryFailure, HtmlSyncRecoveryHost, HtmlSyncStartupReport,
    RecoveryProject,
};
pub use worker::{HtmlSyncWorker, ProjectWorkspaces};
