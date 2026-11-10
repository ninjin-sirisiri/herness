//! Desktop composition of the host runtime.
//!
//! This module owns the one process-wide store, engine adapter, and runtime used
//! by the Tauri shell. It contains no Tauri types, so the same composition is
//! exercised by the desktop integration test with fake credentials and a
//! loopback provider. No second engine or executor is created: allowed tools
//! continue to execute inside `PiEngine`, and the runtime executor is reached
//! only for an operation the adapter explicitly reported as awaiting approval.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use herness_assessment::AssessmentEndpoints;
use herness_core::runtime::{
    ProjectView, PumpReport, ReconciliationReport, RunToolContext, Runtime, RuntimeDependencies,
    RuntimeToolExecutor, ShutdownReport, ToolExecution,
};
use herness_core::{
    ArgumentViolation, BashExecutor, Checkpoint, CheckpointCommit, ConnectionAdmin,
    ConnectionDirectory, ConnectionSettings, CoreError, EventDraft, FileLockRegistry,
    FileObservation, FileToolOutput, FrozenOperation, HistoryPage, HistoryQuery,
    ModelRequestObservation, NativeFileTools, OperationEvidence, OperationId, OperationIntent,
    OperationRecord, OperationResult, PermissionPolicy, PolicyAdmin, PortFeature,
    ProcessSupervisor, ProjectId, ProjectRoot, RequestGateIntent, RunControl, RunId,
    SharedPermissionEvaluator, StorePort, Timestamp, ToolExecutor, ToolName, ToolchainConfig,
};
use herness_engine_pi::{PiEngine, PiEngineConfig, ProviderEndpoints};
use herness_store::{Store, StoreConfig};

use crate::html_sync::assessment::HtmlAssessmentHost;
use crate::html_sync::composition::HtmlSyncServices;
use crate::html_sync::recovery::{HtmlSyncRecoveryHost, HtmlSyncStartupReport};
use herness_html_sync::observer::{DependencyKind, DependencyPath};
use herness_html_sync::H3StorePort;
use crate::supervision::assessment::{AssessmentHost, HostAssessmentPort};
use crate::supervision::permission::PermissionRuntime;
use crate::supervision::plan::ConfigStore;
use crate::supervision::runtime::DesktopH1;
use crate::supervision::store::StoreHandle;
use crate::supervision::{
    ChangeSupervisionRequest, ConfirmationKind, CreateSupervisionRequest, HumanConfirmation,
    PlanRequestActor, PurposeStatusView, RecoveryView, SupervisionHost, SupervisionView,
};
use herness_supervision::{
    ProviderOrigin, SupervisionError, SupervisionId, SupervisionOperationRequest,
    SupervisionRequestId, TargetVersion,
};

/// The concrete runtime composed by the desktop shell.
pub type DesktopRuntime = Runtime<Store, PiEngine<Store>, DesktopToolExecutor>;

/// Process-wide desktop host.
pub struct DesktopHost {
    runtime: DesktopRuntime,
    store: Arc<Mutex<Store>>,
    supervision: SupervisionHost,
    html_sync: HtmlSyncRecoveryHost,
    html_sync_services: HtmlSyncServices,
    connections: ConnectionAdmin,
    directory: ConnectionDirectory,
    credentials: Arc<dyn herness_core::CredentialPort + Send + Sync>,
    app_data_root: PathBuf,
    endpoints: ProviderEndpoints,
}

impl DesktopHost {
    /// Opens the private store and restores runtime state.
    ///
    /// Restore is read-only and never starts an engine or executes a tool. The
    /// caller owns the returned reconciliation report.
    pub fn open(
        app_data_root: impl AsRef<Path>,
        connections: ConnectionAdmin,
        credentials: Arc<dyn herness_core::CredentialPort + Send + Sync>,
        endpoints: ProviderEndpoints,
    ) -> Result<(Self, ReconciliationReport), String> {
        Self::open_inner(
            app_data_root,
            connections,
            credentials,
            endpoints,
            AssessmentEndpoints::official(),
            None,
            None,
            None,
        )
    }

    /// Production composition seam with an explicit Common SDD pack root.
    ///
    /// The desktop application passes the selected pack checkout from its host
    /// configuration. The pack root is not an approval; the stored human H3
    /// approval is still required. An absent root only makes the policy bridge
    /// explicitly unavailable.
    pub fn open_with_html_sync_pack(
        app_data_root: impl AsRef<Path>,
        connections: ConnectionAdmin,
        credentials: Arc<dyn herness_core::CredentialPort + Send + Sync>,
        endpoints: ProviderEndpoints,
        pack_root: Option<PathBuf>,
    ) -> Result<(Self, ReconciliationReport), String> {
        Self::open_inner(
            app_data_root,
            connections,
            credentials,
            endpoints,
            AssessmentEndpoints::official(),
            None,
            None,
            pack_root,
        )
    }

    /// Test composition seam combining the real pack root with loopback
    /// assessment bases.
    ///
    /// This is never selected by the desktop shell. It lets the cross-phase
    /// acceptance test run the real pack, real render child, and the existing
    /// Html assessment gate against a scripted loopback judge.
    #[doc(hidden)]
    pub fn open_with_html_sync_test_boundaries(
        app_data_root: impl AsRef<Path>,
        connections: ConnectionAdmin,
        credentials: Arc<dyn herness_core::CredentialPort + Send + Sync>,
        endpoints: ProviderEndpoints,
        pack_root: Option<PathBuf>,
        assessment_endpoints: AssessmentEndpoints,
    ) -> Result<(Self, ReconciliationReport), String> {
        Self::open_inner(
            app_data_root,
            connections,
            credentials,
            endpoints,
            assessment_endpoints,
            None,
            None,
            pack_root,
        )
    }

    /// Test composition seam with explicit assessment provider bases.
    ///
    /// Production uses [`Self::open`] with official bases. Tests pass loopback
    /// bases so the same permission-evaluator and completion-assessment
    /// composition is exercised without a real provider.
    #[doc(hidden)]
    pub fn open_with_assessment_endpoints(
        app_data_root: impl AsRef<Path>,
        connections: ConnectionAdmin,
        credentials: Arc<dyn herness_core::CredentialPort + Send + Sync>,
        endpoints: ProviderEndpoints,
        assessment_endpoints: AssessmentEndpoints,
    ) -> Result<(Self, ReconciliationReport), String> {
        Self::open_inner(
            app_data_root,
            connections,
            credentials,
            endpoints,
            assessment_endpoints,
            None,
            None,
            None,
        )
    }

    /// Test-only composition seam for cross-phase loopback regression tests.
    ///
    /// This is deliberately not an IPC command and is never selected by the
    /// desktop shell. It lets the Task 17 regression use the real runtime,
    /// store, tool executor, request gate, and quit path while injecting
    /// scripted required-check and assessment ports and a loopback permission
    /// evaluator. Production `open` uses the real dynamic permission evaluator
    /// described by `supervision::permission`; this seam overrides it only for
    /// the regression test.
    #[doc(hidden)]
    pub fn open_with_test_boundaries(
        app_data_root: impl AsRef<Path>,
        connections: ConnectionAdmin,
        credentials: Arc<dyn herness_core::CredentialPort + Send + Sync>,
        endpoints: ProviderEndpoints,
        evaluator: Option<SharedPermissionEvaluator>,
        assessment: Box<dyn herness_supervision::supervisor::ConditionAssessmentPort + Send>,
        checks: Box<dyn herness_supervision::supervisor::RequiredCheckPort + Send>,
    ) -> Result<(Self, ReconciliationReport), String> {
        Self::open_inner(
            app_data_root,
            connections,
            credentials,
            endpoints,
            AssessmentEndpoints::official(),
            evaluator,
            Some((assessment, checks)),
            None,
        )
    }

    fn open_inner(
        app_data_root: impl AsRef<Path>,
        connections: ConnectionAdmin,
        credentials: Arc<dyn herness_core::CredentialPort + Send + Sync>,
        endpoints: ProviderEndpoints,
        assessment_endpoints: AssessmentEndpoints,
        evaluator: Option<SharedPermissionEvaluator>,
        test_ports: Option<(
            Box<dyn herness_supervision::supervisor::ConditionAssessmentPort + Send>,
            Box<dyn herness_supervision::supervisor::RequiredCheckPort + Send>,
        )>,
        pack_root: Option<PathBuf>,
    ) -> Result<(Self, ReconciliationReport), String> {
        let config = StoreConfig::new(app_data_root.as_ref()).map_err(|error| error.to_string())?;
        let store = Store::open(config).map_err(|error| error.to_string())?;
        let store = Arc::new(Mutex::new(store));
        let store_handle = StoreHandle::new(Arc::clone(&store));
        let directory = connections.directory();
        let policy = PolicyAdmin::new();
        let mut engine = PiEngine::new(
            Arc::clone(&store),
            Arc::clone(&credentials),
            directory.clone(),
            PiEngineConfig::new(policy.policy().clone()).with_endpoints(endpoints.clone()),
        )
        .map_err(|error| error.to_string())?;
        engine.set_request_gate(
            crate::supervision::gate::SupervisionAwareGate::new(store_handle.clone()).boxed(),
        );
        let executor = DesktopToolExecutor::new(Arc::clone(&store));
        let assessment_host = AssessmentHost {
            directory: directory.clone(),
            credentials: Arc::clone(&credentials),
            endpoints: assessment_endpoints,
        };
        let permission = PermissionRuntime::new(store_handle.clone(), assessment_host.clone());
        let evaluator = evaluator.unwrap_or_else(|| permission.evaluator());
        let dependencies = RuntimeDependencies::new(
            Arc::clone(&store),
            engine,
            Arc::clone(&credentials),
            directory.clone(),
            policy,
            executor,
        )
        .with_shared_evaluator(evaluator)
        .with_capabilities(herness_core::HostCapabilities::h3_complete());
        let (runtime, report) =
            Runtime::restore(dependencies).map_err(|error| error.to_string())?;
        let supervision_config = ConfigStore::new();
        let (assessment, check_mode) = match test_ports {
            Some((assessment, checks)) => {
                (assessment, crate::supervision::CheckMode::Injected(checks))
            }
            None => {
                let assessment = HostAssessmentPort::new(
                    store_handle.clone(),
                    supervision_config.clone(),
                    assessment_host.clone(),
                );
                (
                    Box::new(assessment)
                        as Box<dyn herness_supervision::supervisor::ConditionAssessmentPort + Send>,
                    crate::supervision::CheckMode::Real,
                )
            }
        };
        let html_assessment_host = assessment_host.clone();
        let supervision = SupervisionHost::with_permission(
            store_handle,
            supervision_config,
            assessment_host,
            assessment,
            check_mode,
            permission,
        );
        let mut runtime = runtime;
        let mut supervision = supervision;
        let project_views = runtime.projects().map_err(|error| error.to_string())?;
        let projects = project_views
            .iter()
            .map(|view| view.project_id())
            .collect::<Vec<_>>();
        supervision.restore(&projects);
        let candidate_root = app_data_root.as_ref().join("html-sync-candidates");
        let recovery_store = StoreHandle::new(Arc::clone(&store));
        let mut html_sync = HtmlSyncRecoveryHost::new(recovery_store, candidate_root)
            .map_err(|error| error.to_string())?;
        for view in &project_views {
            let dependencies = stored_settings(&store, view.project_id())
                .map(|settings| discovered_dependencies(view.path().as_path(), &settings))
                .unwrap_or_else(|| default_dependencies(view.path().as_path()));
            html_sync.register_project(
                view.project_id(),
                view.path().as_path(),
                dependencies,
            );
        }
        let mut html_sync_services = HtmlSyncServices::new(
            StoreHandle::new(Arc::clone(&store)),
            app_data_root.as_ref(),
            pack_root,
            ToolchainConfig::from_environment(),
            RunControl::new(),
            Some(HtmlAssessmentHost::new(
                StoreHandle::new(Arc::clone(&store)),
                supervision.config(),
                html_assessment_host,
            )),
        )?;
        // Evaluate the real capabilities for approved projects before restore
        // binds the one worker. An unavailable capability is explicit; the pack
        // definition alone never activates the worker.
        for view in &project_views {
            let project = view.project_id();
            let Ok(Some(record)) = html_sync_services
                .store_handle()
                .load_html_sync_settings(project)
            else {
                continue;
            };
            let settings = record.settings();
            if !settings.enabled() || settings.approval().is_none() {
                continue;
            }
            let h2 = approved_supervision(&supervision, &html_sync_services, project)
                .and_then(|supervision_id| supervision.get(project, supervision_id).ok());
            let report = html_sync_services.evaluate(
                project,
                view.path().as_path(),
                settings,
                h2.as_ref(),
            );
            html_sync.set_capability_report(project, report);
        }
        let startup = html_sync.restore(&mut runtime, &mut supervision, Timestamp::now());
        for failure in startup.failures() {
            eprintln!(
                "HTML_SYNC_RECOVERY_ERROR: project={} detail={}",
                failure.project_id, failure.detail
            );
        }
        let mut host = Self {
            runtime,
            store: Arc::clone(&store),
            supervision,
            html_sync,
            html_sync_services,
            connections,
            directory,
            credentials,
            app_data_root: app_data_root.as_ref().to_path_buf(),
            endpoints,
        };
        let reconciliation = host.restore_connection_settings(report)?;
        Ok((host, reconciliation))
    }

    /// Restores non-secret connection settings into the trusted registry and
    /// refreshes the reconciliation report's status list.
    ///
    /// Persisted settings are the durable source. A connection already present
    /// in the in-memory registry must match exactly; a conflict is an error
    /// rather than a silent re-point. Conversely, in-memory settings that were
    /// not persisted yet are persisted before any run can use them.
    fn restore_connection_settings(
        &mut self,
        mut report: ReconciliationReport,
    ) -> Result<ReconciliationReport, String> {
        let persisted = self.runtime.persisted_connections();
        for settings in persisted {
            let connection = settings.connection_id();
            match self.directory.get(connection) {
                Ok(existing) if existing == settings => {}
                Ok(_) => {
                    return Err(format!(
                        "persisted connection {connection} differs from the registered settings"
                    ));
                }
                Err(_) => self
                    .connections
                    .add(settings)
                    .map_err(|error| error.to_string())?,
            }
        }
        let registered = self.directory.list().map_err(|error| error.to_string())?;
        self.runtime
            .replace_connection_settings(registered)
            .map_err(|error| error.to_string())?;
        let connections = self
            .runtime
            .connection_infos()
            .map_err(|error| error.to_string())?;
        report.replace_connections(connections);
        Ok(report)
    }

    /// Registers one human-configured connection and persists its non-secret
    /// settings in the same operation.
    pub fn register_connection(
        &mut self,
        settings: ConnectionSettings,
    ) -> Result<herness_core::ConnectionInfo, String> {
        let connection = settings.connection_id();
        self.connections
            .add(settings.clone())
            .map_err(|error| error.to_string())?;
        if let Err(error) = self.runtime.record_connection_settings(settings) {
            let _ = self.connections.remove(connection);
            return Err(error.to_string());
        }
        self.runtime
            .connection_infos()
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|info| info.connection_id() == connection)
            .ok_or_else(|| "the new connection is not visible".to_owned())
    }

    /// Persists every currently registered non-secret connection setting.
    ///
    /// The quit flow calls this before starting coordinated stops so a ChatGPT
    /// account selection or other human settings change made in this process is
    /// not lost. Secrets remain in the Keychain only.
    pub fn persist_connection_settings(&mut self) -> Result<(), String> {
        let registered = self.directory.list().map_err(|error| error.to_string())?;
        self.runtime
            .replace_connection_settings(registered)
            .map_err(|error| error.to_string())
    }

    /// Begins explicit shutdown and refuses new runs and tool decisions.
    pub fn begin_shutdown(&mut self) -> Result<ShutdownReport, String> {
        self.runtime
            .begin_shutdown()
            .map_err(|error| error.to_string())
    }

    /// Stops active runs, saves checkpoints, and records what it could not
    /// confirm.
    pub fn stop_all_for_shutdown(&mut self) -> Result<ShutdownReport, String> {
        self.runtime
            .stop_all_for_shutdown()
            .map_err(|error| error.to_string())
    }

    /// Records a completed shutdown after all active runs reached a terminal
    /// state.
    pub fn finish_shutdown(&mut self) -> Result<ShutdownReport, String> {
        self.runtime
            .finish_shutdown()
            .map_err(|error| error.to_string())
    }

    /// Forces remaining runs to `interrupted` without claiming saved stops.
    pub fn force_shutdown(&mut self) -> Result<ShutdownReport, String> {
        self.runtime
            .force_shutdown()
            .map_err(|error| error.to_string())
    }

    /// Drains every project's engine events and applies run deadlines.
    ///
    /// The trusted desktop shell runs this from a host-owned worker thread so a
    /// closed window or a non-selected project still makes progress. It uses the
    /// single existing runtime, store, engine, and executor. During explicit
    /// shutdown it performs no work and returns a skipped report.
    pub fn pump(&mut self) -> Result<PumpReport, String> {
        let report = self.runtime.pump().map_err(|error| error.to_string())?;
        if self.runtime.is_shutting_down() {
            return Ok(report);
        }
        let projects = self
            .runtime
            .projects()
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|view| view.project_id())
            .collect::<Vec<_>>();
        // An active H3 target must be pumped with its candidate handle installed;
        // otherwise the H2 start tick could start a child with native tools. The
        // H3 worker owns that tick. The generic H2 pump therefore skips exactly
        // the project with the active H3 slot and still advances every other
        // project independently of a window or UI selection.
        let h3_active_project = self.html_sync.active_project();
        let h2_projects = projects
            .iter()
            .copied()
            .filter(|project| Some(*project) != h3_active_project)
            .collect::<Vec<_>>();
        let plans = self.supervision.plans();
        let store = self.store_handle();
        let mut adapter = DesktopH1::new(&mut self.runtime, store, plans);
        if let Err(error) = self.supervision.pump(&mut adapter, &h2_projects) {
            // Supervision progress is independent from the H1 pump. A single
            // H2 failure must not stop H1 event delivery; it is retried on the
            // next bounded interval.
            eprintln!("SUPERVISION_PUMP_ERROR: {error}");
        }
        // The app-lifetime H3 worker keeps ticking with no window and no
        // selected project. A restart latch prevents it from starting authoring.
        match self
            .html_sync
            .pump(&mut self.runtime, &mut self.supervision)
        {
            Ok(Some(tick)) => {
                if let Some(candidate) = tick.candidate {
                    // Verification/assessment/publication run only after the
                    // exact candidate bytes are durably stored. A failure is
                    // reported by the saved state, never by a fake synced flag.
                    match self.html_sync_advance(&candidate.document) {
                        Ok(crate::html_sync::pipeline::PostCandidateOutcome::Publication(
                            outcome,
                        )) => {
                            eprintln!(
                                "HTML_SYNC_PIPELINE: document={} publication={outcome:?}",
                                candidate.document.target_path()
                            );
                        }
                        Ok(
                            crate::html_sync::pipeline::PostCandidateOutcome::VerificationRejected {
                                detail,
                                fixable,
                            },
                        ) => {
                            eprintln!(
                                "HTML_SYNC_VERIFICATION_REJECTED: document={} fixable={fixable} detail={detail}",
                                candidate.document.target_path()
                            );
                        }
                        Ok(crate::html_sync::pipeline::PostCandidateOutcome::FixableUnmet {
                            conditions,
                        }) => {
                            eprintln!(
                                "HTML_SYNC_FIXABLE_UNMET: document={} conditions={conditions:?}",
                                candidate.document.target_path()
                            );
                        }
                        Ok(crate::html_sync::pipeline::PostCandidateOutcome::WaitingHuman {
                            cause,
                            detail,
                        }) => {
                            eprintln!(
                                "HTML_SYNC_WAITING_HUMAN: document={} cause={cause:?} detail={detail}",
                                candidate.document.target_path()
                            );
                        }
                        Ok(crate::html_sync::pipeline::PostCandidateOutcome::Stale) => {}
                        Err(error) => {
                            eprintln!(
                                "HTML_SYNC_PIPELINE_ERROR: document={} detail={error}",
                                candidate.document.target_path()
                            );
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(error) => eprintln!("HTML_SYNC_PUMP_ERROR: {error}"),
        }
        // A companion edit that is not one of our own publication writes is an
        // external conflict. It becomes waiting_human and is never overwritten.
        for companion in self.html_sync.take_companions() {
            if companion.file != herness_html_sync::observer::CompanionFileKind::Html
                || companion.change != herness_html_sync::observer::CompanionChange::External
            {
                continue;
            }
            let project = companion.document.project_id();
            let mut store = self.store_handle();
            let Ok(Some(record)) = store.load_html_sync_document(project, &companion.document)
            else {
                continue;
            };
            if let Err(error) = herness_html_sync::record_external_html_conflict(
                &mut store,
                &record,
                companion.digest.as_ref(),
                Timestamp::now(),
            ) {
                eprintln!(
                    "HTML_SYNC_CONFLICT_ERROR: document={} detail={error}",
                    companion.document.target_path()
                );
            } else {
                self.html_sync_mut()
                    .seed_latch(
                        companion.document.clone(),
                        Some(herness_html_sync::CycleLatch::WaitingHuman),
                        "the formal HTML changed outside H3",
                    );
            }
        }
        Ok(report)
    }

    /// Marks active supervision records for quit using the real H1 stop report.
    ///
    /// This is called after H1 coordinated stops and before finish_shutdown. It
    /// never starts, resumes, or sends anything.
    pub fn mark_supervision_for_quit(
        &mut self,
        report: &herness_core::runtime::ShutdownReport,
    ) -> Result<(), String> {
        let projects = self.runtime.projects().map_err(|error| error.to_string())?;
        let now = herness_core::Timestamp::now();
        for project in projects {
            let project_id = project.project_id();
            let mut facts = std::collections::BTreeMap::new();
            for run in report.runs() {
                if run.project_id() != project_id {
                    continue;
                }
                let confirmed = matches!(
                    run.report(),
                    Some(herness_core::StopReport::Stopped | herness_core::StopReport::NotRunning)
                );
                facts.insert(run.run_id(), confirmed);
            }
            let mut store = self
                .store
                .lock()
                .map_err(|_| "the supervision store is unavailable".to_owned())?;
            crate::lifecycle::supervision_quit::mark_supervision_for_quit(
                &mut store, project_id, &facts, now,
            )?;
        }
        Ok(())
    }

    /// Marks H3 documents for quit after H1 coordinated stops.
    ///
    /// New H3 authoring/sends/publications are refused first. Each active
    /// document requests a cooperative stop through the real H1 run and saves
    /// `stopped` with a recovery latch. An unconfirmed stop is never reported as
    /// success.
    pub fn mark_html_sync_for_quit(
        &mut self,
        report: &herness_core::runtime::ShutdownReport,
    ) -> Result<(), String> {
        let quit = self.html_sync.begin_quit(
            &mut self.runtime,
            &mut self.supervision,
            report,
            herness_core::Timestamp::now(),
        );
        for failure in quit.failures() {
            eprintln!(
                "HTML_SYNC_QUIT_ERROR: project={} detail={}",
                failure.project_id, failure.detail
            );
        }
        if !quit.failures().is_empty() {
            return Err("one or more H3 projects could not be saved for quit".to_owned());
        }
        Ok(())
    }

    /// Last H3 startup reconciliation report, when startup ran.
    pub const fn html_sync_startup(&self) -> Option<&HtmlSyncStartupReport> {
        self.html_sync.last_startup()
    }

    /// App-lifetime H3 recovery host.
    pub const fn html_sync(&self) -> &HtmlSyncRecoveryHost {
        &self.html_sync
    }

    /// Mutable app-lifetime H3 recovery host for the trusted command layer.
    ///
    /// This is not an IPC surface; Task 22 owns the trusted command wiring.
    pub fn html_sync_mut(&mut self) -> &mut HtmlSyncRecoveryHost {
        &mut self.html_sync
    }

    /// Read-only H3 service composition.
    pub const fn html_sync_services(&self) -> &HtmlSyncServices {
        &self.html_sync_services
    }

    /// Mutable H3 service composition for explicit trusted operations.
    pub fn html_sync_services_mut(&mut self) -> &mut HtmlSyncServices {
        &mut self.html_sync_services
    }

    /// Runs the real post-candidate verification, assessment and publication
    /// path for one stored candidate.
    ///
    /// Every input is read from the exact private candidate store and current
    /// project bytes. A missing render, pack, assessment host, or approval is an
    /// explicit error. Only a completion-ready evaluation with a native render
    /// reaches the Task 19 publication orchestrator.
    pub fn html_sync_advance(
        &mut self,
        document: &herness_html_sync::DocumentKey,
    ) -> Result<crate::html_sync::pipeline::PostCandidateOutcome, String> {
        self.html_sync_advance_attempt(document, false)
    }

    /// Runs the same verification/assessment path as an explicit human
    /// regenerated replacement. The candidate must already be stored; the
    /// publication path records the explicit-resolution journal marker.
    pub fn html_sync_replace_with_candidate(
        &mut self,
        document: &herness_html_sync::DocumentKey,
    ) -> Result<crate::html_sync::pipeline::PostCandidateOutcome, String> {
        self.html_sync_advance_attempt(document, true)
    }

    fn html_sync_advance_attempt(
        &mut self,
        document: &herness_html_sync::DocumentKey,
        explicit: bool,
    ) -> Result<crate::html_sync::pipeline::PostCandidateOutcome, String> {
        use crate::html_sync::pipeline::{
            self, AssessmentContext, HostFingerprints, PostCandidateOutcome,
        };

        let project = document.project_id();
        let now = Timestamp::now();
        if let Ok(Some(record)) = self.store_handle().load_html_sync_document(project, document)
            && record.state().state() == herness_html_sync::H3State::Synced
        {
            return Err("the document is already synced; it is not re-verified or rewritten".to_owned());
        }
        let root = self
            .html_sync
            .project_root(project)
            .map(Path::to_path_buf)
            .ok_or_else(|| "the project is not registered with the H3 composition".to_owned())?;
        let settings_record = self
            .store_handle()
            .load_html_sync_settings(project)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "the project has no stored H3 settings".to_owned())?;
        let settings = settings_record.settings().clone();
        let approval = settings
            .approval()
            .cloned()
            .ok_or_else(|| "the stored settings carry no human approval".to_owned())?;
        let supervision_id = self
            .html_sync_supervision_id(project)
            .ok_or_else(|| "the project has no approved H2 target".to_owned())?;
        let plan = crate::supervision::plan::load_plan(
            &self.store_handle(),
            project,
            supervision_id,
        )
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the approved H2 plan is unavailable".to_owned())?;
        let context = AssessmentContext::from_plan(
            project,
            &plan,
            approval.assessment().profile(),
        )
        .map_err(|error| error.to_string())?;
        let files = crate::html_sync::publish::ProjectPublicationFiles::new(&root)
            .map_err(|error| error.to_string())?;
        let candidates = self.html_sync.candidate_store();
        let dependencies = self.html_sync.dependencies(project);
        let mut store = self.store_handle();
        let mut prepared = pipeline::load_prepared(
            &mut store,
            &files,
            &candidates,
            &dependencies,
            project,
            document,
        )
        .map_err(|error| error.to_string())?;
        let capture = HostFingerprints::capture(
            &settings,
            approval.versions().policy_fingerprint(),
            approval.versions().pack_fingerprint(),
            &prepared,
            &context,
        )
        .map_err(|error| error.to_string())?;
        let bridge = self
            .html_sync_services
            .policy_bridge(project, &root, &settings)?;
        let render = self
            .html_sync_services
            .render_port()
            .ok_or_else(|| "no real render port is installed".to_owned())?;
        let verification = match pipeline::verify(
            bridge.as_ref(),
            render.as_ref(),
            &prepared,
            &context,
            &capture,
            now,
        ) {
            Ok(verification) => verification,
            Err(error) => {
                let _ = pipeline::mark_rejected(
                    &mut store,
                    &prepared,
                    herness_html_sync::H3FailureCause::VerificationUnavailable,
                    now,
                );
                return Ok(PostCandidateOutcome::VerificationRejected {
                    detail: error.to_string(),
                    fixable: false,
                });
            }
        };
        if !verification.is_usable() {
            let (detail, fixable) = pipeline::verification_detail(&verification);
            let _ = pipeline::mark_rejected(
                &mut store,
                &prepared,
                herness_html_sync::H3FailureCause::CandidateRejected,
                now,
            );
            return Ok(PostCandidateOutcome::VerificationRejected { detail, fixable });
        }
        let pack = verification
            .pack
            .clone()
            .ok_or_else(|| "the verification produced no evidence pack".to_owned())?;
        let record = pipeline::mark_assessing(&mut store, &prepared, now)
            .map_err(|error| error.to_string())?;
        prepared.record = record;

        let persisted = pipeline::load_evidence(
            self.html_sync_services.evidence_root(),
            document,
            prepared.generation.generation_id(),
        )
        .map_err(|error| error.to_string())?;
        let assessment = self
            .html_sync_services
            .assessment_mut()
            .ok_or_else(|| "the Html assessment host is not composed".to_owned())?;
        assessment
            .rehydrate_content(&persisted)
            .map_err(|error| error.to_string())?;
        let evaluation = match pipeline::assess(
            assessment,
            &pack,
            &context,
            supervision_id,
            &verification,
            &capture,
            now,
        ) {
            Ok(evaluation) => evaluation,
            Err(error) => {
                let detail = error.to_string();
                let lower = detail.to_ascii_lowercase();
                let cause = if lower.contains("consent")
                    || lower.contains("permission")
                    || lower.contains("approval")
                {
                    herness_html_sync::HumanWaitCause::PermissionDenied
                } else {
                    herness_html_sync::HumanWaitCause::UndecidableAssessment
                };
                let _ = pipeline::mark_waiting(
                    &mut store,
                    &prepared,
                    cause,
                    vec![herness_html_sync::RequiredAction::ReassessCandidate],
                    now,
                );
                return Ok(PostCandidateOutcome::WaitingHuman { cause, detail });
            }
        };
        let content = assessment.content().clone();
        pipeline::persist_evidence(
            self.html_sync_services.evidence_root(),
            document,
            prepared.generation.generation_id(),
            &content,
        )
        .map_err(|error| error.to_string())?;

        use herness_html_sync::EvaluationDispositionState;
        match evaluation.disposition().state() {
            EvaluationDispositionState::CompletionReady => {
                let policy = pipeline::policy_identity(&settings)
                    .map_err(|error| error.to_string())?;
                let attempt =
                    pipeline::publication_attempt(&files, &prepared, &evaluation, &policy, now)
                        .map_err(|error| error.to_string())?;
                let attempt = if explicit {
                    attempt.with_explicit_resolution()
                } else {
                    attempt
                };
                let services = &mut self.html_sync_services;
                let recovery = &mut self.html_sync;
                let operations = services
                    .ensure_operations(project, &root)?;
                let published = recovery
                    .with_publication_expectations(project, |expectations| {
                        if explicit {
                            operations
                                .replace_with_regenerated(attempt, expectations, now)
                                .map_err(|error| error.to_string())
                        } else {
                            operations
                                .publish(attempt, expectations, now)
                                .map_err(|error| error.to_string())
                        }
                    })
                    .ok_or_else(|| {
                        "the project has no observer for publication expectations".to_owned()
                    })??;
                Ok(PostCandidateOutcome::Publication(published))
            }
            EvaluationDispositionState::FixableUnmet => {
                let conditions = evaluation.disposition().fixable_conditions().to_vec();
                let _ = pipeline::mark_rejected(
                    &mut store,
                    &prepared,
                    herness_html_sync::H3FailureCause::CandidateRejected,
                    now,
                );
                Ok(PostCandidateOutcome::FixableUnmet { conditions })
            }
            EvaluationDispositionState::WaitingHuman => {
                let detail = evaluation
                    .disposition()
                    .waiting_human_reasons()
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "the Html assessment needs a human".to_owned());
                let _ = pipeline::mark_waiting(
                    &mut store,
                    &prepared,
                    herness_html_sync::HumanWaitCause::UndecidableAssessment,
                    vec![herness_html_sync::RequiredAction::ReassessCandidate],
                    now,
                );
                Ok(PostCandidateOutcome::WaitingHuman {
                    cause: herness_html_sync::HumanWaitCause::UndecidableAssessment,
                    detail,
                })
            }
        }
    }

    /// Requests a cooperative stop for one project's active H3 authoring run.
    pub fn html_sync_stop_active(
        &mut self,
        document: &herness_html_sync::DocumentKey,
    ) -> Result<Option<herness_html_sync::StopOutcome>, String> {
        let Self {
            runtime, html_sync, ..
        } = self;
        html_sync
            .stop_active(runtime, document)
            .map_err(|error| error.to_string())
    }

    /// Runs the read-only human resume preflight with the real runtime facts.
    pub fn html_sync_resume_preflight(
        &mut self,
        document: &herness_html_sync::DocumentKey,
        expected_revision: u64,
        now: Timestamp,
    ) -> Result<herness_html_sync::ResumePreflight, String> {
        let Self {
            runtime,
            supervision,
            html_sync,
            ..
        } = self;
        html_sync
            .resume_preflight(runtime, supervision, document, expected_revision, now)
            .map_err(|error| error.to_string())
    }

    /// Reads a saved supervision record through the shared store.
    pub fn supervision_record(
        &self,
        project: herness_core::ProjectId,
        supervision: SupervisionId,
    ) -> Result<Option<herness_supervision::SupervisionRecord>, String> {
        let store = self
            .store
            .lock()
            .map_err(|_| "the supervision store is unavailable".to_owned())?;
        store
            .load_supervision_record(project, supervision)
            .map_err(|error| error.to_string())
    }

    /// Whether an explicit shutdown has begun.
    pub const fn is_shutting_down(&self) -> bool {
        self.runtime.is_shutting_down()
    }

    /// Runtime used by the trusted command layer.
    pub const fn runtime(&self) -> &DesktopRuntime {
        &self.runtime
    }

    /// Mutable runtime used by the trusted command layer.
    pub const fn runtime_mut(&mut self) -> &mut DesktopRuntime {
        &mut self.runtime
    }

    /// Cloneable handle to the one durable store shared with H2 supervision.
    pub fn store_handle(&self) -> StoreHandle {
        StoreHandle::new(Arc::clone(&self.store))
    }

    /// Read-only supervision composition.
    pub const fn supervision(&self) -> &SupervisionHost {
        &self.supervision
    }

    /// Mutable supervision composition for the host-owned H3 worker.
    ///
    /// This is not an IPC surface. The worker needs the same supervision host
    /// and the same H1 runtime in one call; borrowing the two fields together
    /// avoids a second composition.
    pub fn runtime_and_supervision_mut(&mut self) -> (&mut DesktopRuntime, &mut SupervisionHost) {
        (&mut self.runtime, &mut self.supervision)
    }

    /// Mints a host-owned human confirmation after the command guard passed.
    pub fn confirm_supervision(&self, kind: ConfirmationKind) -> HumanConfirmation {
        self.supervision.confirm(kind)
    }

    /// Shared permission evaluator installed into H1 at open.
    pub fn permission_evaluator(&self) -> SharedPermissionEvaluator {
        self.supervision.permission().evaluator()
    }

    /// Whether any project has a verified permission profile and consent.
    pub fn permission_available(&self) -> bool {
        self.supervision.permission_available()
    }

    /// Whether one project has a verified permission profile and consent.
    pub fn permission_available_for(&self, project: herness_core::ProjectId) -> bool {
        self.supervision.permission_available_for(project)
    }

    /// Creates a supervision target.
    pub fn supervision_create(
        &mut self,
        actor: PlanRequestActor,
        request: CreateSupervisionRequest,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        let plans = self.supervision.plans();
        let store = self.store_handle();
        let mut adapter = DesktopH1::new(&mut self.runtime, store, plans);
        self.supervision
            .create(&mut adapter, actor, request, confirmation)
    }

    /// Configures a per-purpose profile.
    #[allow(clippy::too_many_arguments)]
    pub fn supervision_configure_profile(
        &self,
        actor: PlanRequestActor,
        project: herness_core::ProjectId,
        purpose: herness_supervision::ProfilePurpose,
        connection: herness_core::ConnectionId,
        model: &str,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<PurposeStatusView, SupervisionError> {
        self.supervision
            .configure_profile(actor, project, purpose, connection, model, confirmation)
    }

    /// Marks a configured assessment profile verified or unverified after a
    /// trusted human confirmation. This is not exposed to the model.
    pub fn supervision_mark_profile_verified(
        &self,
        project: herness_core::ProjectId,
        purpose: herness_supervision::ProfilePurpose,
        verified: bool,
    ) -> Result<PurposeStatusView, SupervisionError> {
        self.supervision
            .mark_profile_verified(project, purpose, verified)
    }

    /// Grants per-purpose disclosure consent.
    #[allow(clippy::too_many_arguments)]
    pub fn supervision_grant_consent(
        &self,
        actor: PlanRequestActor,
        project: herness_core::ProjectId,
        purpose: herness_supervision::ProfilePurpose,
        origin: ProviderOrigin,
        data_kinds: std::collections::BTreeSet<herness_supervision::DisclosureDataKind>,
        targets: Vec<String>,
        target_version: TargetVersion,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<PurposeStatusView, SupervisionError> {
        self.supervision.grant_consent(
            actor,
            project,
            purpose,
            origin,
            data_kinds,
            targets,
            target_version,
            confirmation,
        )
    }

    /// Revokes per-purpose disclosure consent.
    pub fn supervision_revoke_consent(
        &self,
        actor: PlanRequestActor,
        project: herness_core::ProjectId,
        purpose: herness_supervision::ProfilePurpose,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<PurposeStatusView, SupervisionError> {
        self.supervision
            .revoke_consent(actor, project, purpose, confirmation)
    }

    /// Starts the first run of a ready target.
    pub fn supervision_start(
        &mut self,
        project: herness_core::ProjectId,
        supervision: SupervisionId,
        request_id: SupervisionRequestId,
        expected_revision: u64,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        let plans = self.supervision.plans();
        let store = self.store_handle();
        let mut adapter = DesktopH1::new(&mut self.runtime, store, plans);
        self.supervision.start(
            &mut adapter,
            project,
            supervision,
            request_id,
            expected_revision,
            confirmation,
        )
    }

    /// Stops or cancels one target.
    pub fn supervision_stop(
        &mut self,
        request: SupervisionOperationRequest,
        cancel: bool,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        let policy_version = self.runtime.policy().version().get();
        let plans = self.supervision.plans();
        let store = self.store_handle();
        let mut adapter = DesktopH1::new(&mut self.runtime, store, plans);
        self.supervision
            .stop(&mut adapter, request, cancel, policy_version, confirmation)
    }

    /// Resumes a stopped/waiting target.
    pub fn supervision_resume(
        &mut self,
        request: SupervisionOperationRequest,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        let policy_version = self.runtime.policy().version().get();
        let plans = self.supervision.plans();
        let store = self.store_handle();
        let mut adapter = DesktopH1::new(&mut self.runtime, store, plans);
        self.supervision
            .resume(&mut adapter, request, policy_version, confirmation)
    }

    /// Reassesses from fresh or reused evidence.
    pub fn supervision_reassess(
        &mut self,
        request: SupervisionOperationRequest,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        let policy_version = self.runtime.policy().version().get();
        let plans = self.supervision.plans();
        let store = self.store_handle();
        let mut adapter = DesktopH1::new(&mut self.runtime, store, plans);
        self.supervision
            .reassess(&mut adapter, request, policy_version, confirmation)
    }

    /// Changes conditions/profile/consent explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn supervision_change(
        &mut self,
        project: herness_core::ProjectId,
        supervision: SupervisionId,
        request_id: SupervisionRequestId,
        expected_revision: u64,
        actor: PlanRequestActor,
        change: ChangeSupervisionRequest,
        confirmation: Option<HumanConfirmation>,
    ) -> Result<SupervisionView, SupervisionError> {
        let plans = self.supervision.plans();
        let store = self.store_handle();
        let mut adapter = DesktopH1::new(&mut self.runtime, store, plans);
        self.supervision.change(
            &mut adapter,
            project,
            supervision,
            request_id,
            expected_revision,
            actor,
            change,
            confirmation,
        )
    }

    /// Reads one supervision view without executing anything.
    pub fn supervision_get(
        &self,
        project: herness_core::ProjectId,
        supervision: SupervisionId,
    ) -> Result<SupervisionView, SupervisionError> {
        self.supervision.get(project, supervision)
    }

    /// Lists saved supervision targets for one project.
    pub fn supervision_list(
        &self,
        project: herness_core::ProjectId,
    ) -> Result<Vec<SupervisionView>, SupervisionError> {
        self.supervision.list(project)
    }

    /// Reads the durable recovery report.
    pub fn supervision_recovery(
        &mut self,
        project: herness_core::ProjectId,
        supervision: SupervisionId,
    ) -> Result<RecoveryView, SupervisionError> {
        let plans = self.supervision.plans();
        let store = self.store_handle();
        let mut adapter = DesktopH1::new(&mut self.runtime, store, plans);
        self.supervision
            .recovery(&mut adapter, project, supervision)
    }

    /// Human-only connection registry.
    pub const fn connections(&self) -> &ConnectionAdmin {
        &self.connections
    }

    /// Read-only connection directory shared with the engine and runtime.
    pub const fn directory(&self) -> &ConnectionDirectory {
        &self.directory
    }

    /// Credential port shared with the engine.
    pub fn credentials(&self) -> &Arc<dyn herness_core::CredentialPort + Send + Sync> {
        &self.credentials
    }

    /// Current non-secret permission policy.
    pub fn policy(&self) -> &PermissionPolicy {
        self.runtime.policy()
    }

    /// Opens a project, rejecting the private application-data area.
    ///
    /// The store and its checkpoints must never live inside the project the
    /// agent can edit, and the app-data directory (or a child) is never a
    /// valid project. `Runtime::open_project` still performs the canonical
    /// readable-directory checks.
    pub fn open_project(&mut self, path: impl AsRef<Path>) -> Result<ProjectView, String> {
        let config = StoreConfig::new(&self.app_data_root).map_err(|error| error.to_string())?;
        config
            .ensure_outside_project(path.as_ref())
            .map_err(|error| error.to_string())?;
        let project = std::fs::canonicalize(path.as_ref())
            .map_err(|error| format!("project is not readable: {error}"))?;
        let app_data = std::fs::canonicalize(&self.app_data_root)
            .unwrap_or_else(|_| self.app_data_root.clone());
        if project == app_data || project.starts_with(&app_data) {
            return Err(
                "the application data directory or its children cannot be opened as a project"
                    .to_owned(),
            );
        }
        let Self {
            runtime,
            store,
            html_sync,
            ..
        } = self;
        let view = runtime
            .open_project(&project)
            .map_err(|error| error.to_string())?;
        let dependencies = StoreHandle::new(Arc::clone(store))
            .load_html_sync_settings(view.project_id())
            .ok()
            .flatten()
            .map(|record| discovered_dependencies(project.as_path(), record.settings()))
            .unwrap_or_else(|| default_dependencies(project.as_path()));
        html_sync.register_project(
            view.project_id(),
            project.as_path(),
            dependencies,
        );
        Ok(view)
    }

    /// Non-secret connection views for the UI.
    pub fn connection_infos(&self) -> Result<Vec<herness_core::ConnectionInfo>, String> {
        self.runtime
            .connection_infos()
            .map_err(|error| error.to_string())
    }

    /// Lists the selected ChatGPT account's model catalog.
    ///
    /// This is a real network read, reached only from a human action in the
    /// trusted UI or the opt-in controller real-check. It never changes the
    /// selected connection or model.
    pub fn list_chatgpt_models(
        &self,
        connection: herness_core::ConnectionId,
    ) -> Result<Vec<herness_engine_pi::ChatGptModel>, String> {
        herness_engine_pi::probe::list_chatgpt_models(
            &self.directory,
            Arc::clone(&self.credentials),
            &self.endpoints,
            connection,
        )
        .map_err(|failure| failure.as_str().to_owned())
    }

    /// Changes only the non-secret model name of an existing connection.
    ///
    /// The provider, endpoint, authentication method, credential reference, and
    /// selected ChatGPT account stay unchanged. A model inferred by a provider
    /// cannot call this: only the trusted main window reaches the command.
    pub fn set_connection_model(
        &mut self,
        connection: herness_core::ConnectionId,
        model: impl Into<String>,
    ) -> Result<herness_core::ConnectionInfo, String> {
        let current = self
            .directory
            .get(connection)
            .map_err(|error| error.to_string())?;
        let next = ConnectionSettings::new(
            connection,
            current.provider(),
            model,
            current.auth_method(),
            current.endpoint().cloned(),
            current.insecure_http_acknowledged(),
        )
        .map_err(|error| error.to_string())?;
        self.connections
            .update(next)
            .map_err(|error| error.to_string())?;
        if let Err(error) = self.persist_connection_settings() {
            let _ = self.connections.update(current);
            return Err(error);
        }
        self.connection_infos()?
            .into_iter()
            .find(|info| info.connection_id() == connection)
            .ok_or_else(|| "the updated connection is not visible".to_owned())
    }

    /// Removes one connection from host state after its credential was deleted.
    ///
    /// The credential deletion is the caller's responsibility so the ChatGPT
    /// sign-out path can attempt remote revocation first. A persistence failure
    /// restores the registry entry instead of silently forgetting the
    /// connection.
    pub fn forget_connection(
        &mut self,
        connection: herness_core::ConnectionId,
    ) -> Result<(), String> {
        let settings = self
            .directory
            .get(connection)
            .map_err(|error| error.to_string())?;
        self.connections
            .remove(connection)
            .map_err(|error| error.to_string())?;
        if let Err(error) = self.persist_connection_settings() {
            let _ = self.connections.add(settings);
            return Err(error);
        }
        Ok(())
    }

    /// Private application-data root used by the opt-in real-check evidence.
    pub fn app_data_root(&self) -> &Path {
        &self.app_data_root
    }

    /// Provider base URLs in use by this host.
    pub const fn endpoints(&self) -> &ProviderEndpoints {
        &self.endpoints
    }
}

/// Registers the shared CSS dependency when the project contains it.
///
/// Task 22 registers the canonical shared stylesheet only. Referenced images and
/// other resources are added by later acceptance work; an unsupplied path is
/// never treated as a dependency change.
fn default_dependencies(root: &Path) -> Vec<DependencyPath> {
    let mut dependencies = Vec::new();
    let css = "docs/sdd/assets/sdd.css";
    if root.join(css).is_file()
        && let Ok(dependency) = DependencyPath::new(css, DependencyKind::Css)
    {
        dependencies.push(dependency);
    }
    dependencies
}

fn stored_settings(
    store: &Arc<std::sync::Mutex<herness_store::Store>>,
    project: ProjectId,
) -> Option<herness_html_sync::H3Settings> {
    store
        .lock()
        .ok()?
        .load_html_sync_settings(project)
        .ok()
        .flatten()
        .map(|record| record.settings().clone())
}

/// Discovers the shared CSS plus every local `src`/`href` resource referenced
/// by each approved Target's current HTML companion.
///
/// Paths are canonical project-relative values; absolute URLs, fragments, and
/// data URLs are ignored. A referenced path that escapes the project or does
/// not exist is not registered and is therefore never treated as a dependency
/// change. This makes recovery/dependency reconciliation cover real resources
/// rather than only the shared stylesheet.
pub fn discovered_dependencies(
    root: &Path,
    settings: &herness_html_sync::H3Settings,
) -> Vec<DependencyPath> {
    let mut dependencies = default_dependencies(root);
    let mut seen = dependencies
        .iter()
        .map(|dependency| dependency.path().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    for target in settings.target_paths() {
        let Ok(document) = herness_html_sync::DocumentKey::new(settings.project_id(), target.clone())
        else {
            continue;
        };
        let companion = document.companion_path();
        let Ok(text) = std::fs::read_to_string(root.join(&companion)) else {
            continue;
        };
        for reference in local_references(&text) {
            if dependencies.len() >= 64 {
                break;
            }
            if reference.ends_with(".css") || reference.ends_with(".md") || reference.ends_with(".html")
            {
                continue;
            }
            let Some(relative) = resolve_reference(&companion, &reference) else {
                continue;
            };
            if !seen.insert(relative.clone()) {
                continue;
            }
            let path = canonical_root.join(&relative);
            if !path.is_file() {
                continue;
            }
            if let Ok(canonical) = std::fs::canonicalize(&path)
                && !canonical.starts_with(&canonical_root)
            {
                continue;
            }
            if let Ok(dependency) =
                DependencyPath::new(relative, DependencyKind::Resource)
            {
                dependencies.push(dependency);
            }
        }
    }
    dependencies
}

fn local_references(html: &str) -> Vec<String> {
    let mut references = Vec::new();
    for (marker, attribute) in [("src=\"", "\""), ("href=\"", "\"")] {
        let mut rest = html;
        while let Some(position) = rest.find(marker) {
            rest = &rest[position + marker.len()..];
            let Some(end) = rest.find(attribute) else {
                break;
            };
            let value = &rest[..end];
            if !value.starts_with("http:")
                && !value.starts_with("https:")
                && !value.starts_with("data:")
                && !value.starts_with('#')
                && !value.starts_with("mailto:")
                && !value.starts_with('/')
            {
                references.push(value.to_owned());
            }
            rest = &rest[end + 1..];
        }
    }
    references.sort();
    references.dedup();
    references
}

fn resolve_reference(companion: &str, reference: &str) -> Option<String> {
    let parent = Path::new(companion).parent()?;
    let mut components = Vec::new();
    for component in parent.components() {
        if let std::path::Component::Normal(part) = component {
            components.push(part.to_string_lossy().into_owned());
        }
    }
    for part in reference.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            part if part.contains('\\') => return None,
            part => components.push(part.to_owned()),
        }
    }
    Some(components.join("/"))
}

/// Finds the H2 target whose plan owner matches the human H3 owner binding.
fn approved_supervision(
    supervision: &SupervisionHost,
    services: &HtmlSyncServices,
    project: ProjectId,
) -> Option<SupervisionId> {
    let owner = services
        .store_handle()
        .load_html_sync_settings(project)
        .ok()
        .flatten()?
        .settings()
        .approval()?
        .owner_binding()
        .owner()
        .clone();
    let plans = supervision.plans();
    let plans = plans.lock().ok()?;
    plans
        .iter()
        .find(|((candidate, _), plan)| *candidate == project && plan.owner == owner)
        .map(|((_, supervision), _)| *supervision)
}

// ---------------------------------------------------------------------------
// Store handle shared by the executor and the engine.
// ---------------------------------------------------------------------------

/// Store handle that can be cloned into the runtime executor.
#[derive(Clone)]
pub struct SharedStore(Arc<Mutex<Store>>);

impl SharedStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl StorePort for SharedStore {
    fn commit_checkpoint(
        &mut self,
        commit: CheckpointCommit,
    ) -> Result<herness_core::CommitReceipt, CoreError> {
        self.lock().commit(commit).map_err(Into::into)
    }

    fn load_checkpoint(&self, run: &RunId) -> Result<Option<Checkpoint>, CoreError> {
        <Store as StorePort>::load_checkpoint(&self.lock(), run)
    }

    fn history(&self, query: HistoryQuery) -> Result<HistoryPage, CoreError> {
        <Store as StorePort>::history(&self.lock(), query)
    }

    fn pending_operations(&self, project: &ProjectId) -> Result<Vec<OperationIntent>, CoreError> {
        <Store as StorePort>::pending_operations(&self.lock(), project)
    }

    fn operation(&self, operation: &OperationId) -> Result<Option<OperationRecord>, CoreError> {
        <Store as StorePort>::operation(&self.lock(), operation)
    }

    fn record_operation_result(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
    ) -> Result<(), CoreError> {
        <Store as StorePort>::record_operation_result(&mut self.lock(), operation, result)
    }

    fn record_operation_result_with_events(
        &mut self,
        operation: &OperationId,
        result: OperationResult,
        events: Vec<EventDraft>,
    ) -> Result<herness_core::CommitReceipt, CoreError> {
        <Store as StorePort>::record_operation_result_with_events(
            &mut self.lock(),
            operation,
            result,
            events,
        )
    }

    fn record_model_request(
        &mut self,
        intent: RequestGateIntent,
        recorded_at: Timestamp,
    ) -> Result<(), CoreError> {
        <Store as StorePort>::record_model_request(&mut self.lock(), intent, recorded_at)
    }

    fn record_model_request_observation(
        &mut self,
        observation: ModelRequestObservation,
        observed_at: Timestamp,
    ) -> Result<(), CoreError> {
        <Store as StorePort>::record_model_request_observation(
            &mut self.lock(),
            observation,
            observed_at,
        )
    }
}

// ---------------------------------------------------------------------------
// Runtime executor for adapter-reported awaiting-approval operations.
// ---------------------------------------------------------------------------

/// Executes only the frozen operations the trusted engine adapter refused to run
/// because a human decision was required.
///
/// The adapter never executes an awaiting operation, so reaching this executor
/// means the human approved it. File and shell tools persist their intent and
/// result through the same `StorePort` contract used by the engine adapter.
pub struct DesktopToolExecutor {
    store: SharedStore,
    locks: Arc<FileLockRegistry>,
    supervisor: ProcessSupervisor,
    files: Option<NativeFileTools<SharedStore>>,
    shell: Option<BashExecutor<SharedStore>>,
}

impl DesktopToolExecutor {
    fn new(store: Arc<Mutex<Store>>) -> Self {
        Self {
            store: SharedStore(store),
            locks: Arc::new(FileLockRegistry::new()),
            supervisor: ProcessSupervisor::new(),
            files: None,
            shell: None,
        }
    }

    fn missing_context() -> CoreError {
        CoreError::InvalidValue {
            field: "runContext".to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: "the runtime must enter a run before executing a tool".to_owned(),
            },
        }
    }
}

impl RuntimeToolExecutor for DesktopToolExecutor {
    fn enter_run(&mut self, context: RunToolContext) -> Result<(), CoreError> {
        let root = ProjectRoot::new(context.cwd().as_path())?;
        self.files = Some(NativeFileTools::with_lock_registry(
            root,
            context.agent_id(),
            context.session_id(),
            self.store.clone(),
            Arc::clone(&self.locks),
        )?);
        self.shell = Some(BashExecutor::new(
            context.agent_id(),
            context.session_id(),
            self.store.clone(),
            herness_core::SystemLauncher,
            self.supervisor.clone(),
        )?);
        Ok(())
    }
}

impl ToolExecutor for DesktopToolExecutor {
    type Output = ToolExecution;

    fn execute(&mut self, operation: &FrozenOperation) -> Result<ToolExecution, CoreError> {
        match operation.tool() {
            ToolName::Read | ToolName::Search | ToolName::Write | ToolName::Edit => {
                let files = self.files.as_mut().ok_or_else(Self::missing_context)?;
                match files.execute(operation)? {
                    FileToolOutput::Change(change) => {
                        let evidence = OperationEvidence::new(
                            vec![FileObservation::new(
                                change.path().clone(),
                                change.before_version().cloned(),
                                Some(change.after_version().clone()),
                            )],
                            false,
                        );
                        Ok(ToolExecution::applied(
                            evidence,
                            serde_json::to_value(&change).unwrap_or(serde_json::Value::Null),
                        ))
                    }
                    other => Ok(ToolExecution::observed(
                        serde_json::to_value(&other).unwrap_or(serde_json::Value::Null),
                    )),
                }
            }
            ToolName::Bash => {
                let shell = self.shell.as_mut().ok_or_else(Self::missing_context)?;
                let output = shell.execute(operation)?;
                let evidence = OperationEvidence::empty().with_shell(output.observation().clone());
                let summary = serde_json::to_value(&output).unwrap_or(serde_json::Value::Null);
                Ok(ToolExecution::new(output.outcome(), evidence, summary))
            }
            ToolName::CandidateRead | ToolName::CandidateWrite | ToolName::CandidateEdit => {
                // This desktop composition does not install a host artifact
                // port. An explicit unsupported capability is required; never
                // fabricate an empty candidate success.
                Err(CoreError::UnsupportedPortFeature {
                    feature: PortFeature::ArtifactStore,
                })
            }
        }
    }
}
