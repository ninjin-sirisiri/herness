//! Desktop H3 startup/quit recovery composition.
//!
//! This module connects the pure [`herness_html_sync::RecoveryService`] to the
//! one process-wide SQLite store, the canonical project file reader, the private
//! candidate store, H1 runtime facts, and H2 recovery facts. It performs no
//! model request, run start, candidate authoring, publication, or file rollback.
//!
//! Startup reconciliation runs for every open project independent of the
//! selected window/project. A clean synced document stays unchanged; active
//! work, unresolved publication journals, stale source, external HTML/receipt
//! changes, unknown requests, and unconfirmed stops produce explicit latches.
//! The app-lifetime H3 worker is bound only from approved settings and an
//! existing H2 target; it is seeded with recovery latches so a restart cannot
//! auto-author. The host pump continues to tick the worker with no window.
//!
//! Quit sets the worker to refuse new work, requests cooperative stops through
//! the real H1 run boundary, saves the H3 stopped/recovery latch, and reports
//! unconfirmed stops without claiming success.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};

use herness_core::{ProjectId, StopReason, Timestamp};
use herness_html_sync::observer::{
    ChangeSignal, DependencyKind, DependencyPath, FilesystemSourceReader, ObservationEligibility,
    ObservationTargets, ObserverHealth, ObserverTick, ProjectObserver, SourceChange, SourceReadError,
    SystemObservationClock, dependency_fingerprint,
};
use herness_html_sync::recovery::{
    self, CandidateBytes, H2RecoveryFacts, H2RequestUnknown, ProjectRecoveryReport,
    QuitProjectReport, RecoveryReadPort, RecoveryRuntimePort, RecoveryService, RecoverySideEffects,
    RecoveryStop, ResumePreflight,
};
use herness_html_sync::{
    CandidateArtifactStore, CoordinatorTick, CycleLatch, DocumentKey, H3Error, H3StorePort, JobId,
    OfferOutcome, SourceObservation, StopOutcome, StoreBackedOwnerApprovalRegistry, SyncCycle,
};
use herness_supervision::{BudgetUsage, ClockPort, ContentDigest, SupervisionId, SupervisionState};
use serde::Serialize;

use crate::host::DesktopRuntime;
use crate::html_sync::composition::HtmlSyncCapabilityReport;
use crate::html_sync::observer::{ProjectFilesystemWatcher, WatchNotice};
use crate::html_sync::worker::HtmlSyncWorker;
use crate::supervision::SupervisionHost;
use crate::supervision::runtime::DesktopH1;
use crate::supervision::store::StoreHandle;

/// One project registered for H3 recovery.
#[derive(Debug, Clone)]
pub struct RecoveryProject {
    root: PathBuf,
    dependencies: Vec<DependencyPath>,
}

/// One project recovery failure. No partial success is claimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncRecoveryFailure {
    /// Project.
    pub project_id: ProjectId,
    /// Sanitized failure detail.
    pub detail: String,
}

/// Startup reconciliation result for every open project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncStartupReport {
    projects: Vec<ProjectRecoveryReport>,
    bound_projects: Vec<ProjectId>,
    failures: Vec<HtmlSyncRecoveryFailure>,
    side_effects: RecoverySideEffects,
}

impl HtmlSyncStartupReport {
    /// Successful project reports.
    pub fn projects(&self) -> &[ProjectRecoveryReport] {
        &self.projects
    }

    /// Projects bound to the app-lifetime worker.
    pub fn bound_projects(&self) -> &[ProjectId] {
        &self.bound_projects
    }

    /// Projects whose reconciliation failed. They are never reported as clean.
    pub fn failures(&self) -> &[HtmlSyncRecoveryFailure] {
        &self.failures
    }

    /// Proof that startup sent, started, authored, and published nothing.
    pub const fn side_effects(&self) -> RecoverySideEffects {
        self.side_effects
    }

    /// Total model requests sent during startup. Always zero.
    pub fn request_count(&self) -> u32 {
        self.projects
            .iter()
            .map(ProjectRecoveryReport::request_count)
            .sum()
    }
}

/// One quit reconciliation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlSyncQuitReport {
    projects: Vec<QuitProjectReport>,
    failures: Vec<HtmlSyncRecoveryFailure>,
    accepting_new_work: bool,
}

impl HtmlSyncQuitReport {
    /// Per-project quit reports.
    pub fn projects(&self) -> &[QuitProjectReport] {
        &self.projects
    }

    /// Projects whose quit save failed.
    pub fn failures(&self) -> &[HtmlSyncRecoveryFailure] {
        &self.failures
    }

    /// Always false after the quit hook starts.
    pub const fn accepting_new_work(&self) -> bool {
        self.accepting_new_work
    }

    /// Every document whose stop H1 did not confirm.
    pub fn unconfirmed(&self) -> Vec<DocumentKey> {
        self.projects
            .iter()
            .flat_map(|project| project.unconfirmed().iter().cloned())
            .collect()
    }
}

/// App-lifetime H3 recovery host.
pub struct HtmlSyncRecoveryHost {
    store: StoreHandle,
    candidates: CandidateArtifactStore,
    worker: HtmlSyncWorker,
    projects: BTreeMap<ProjectId, RecoveryProject>,
    bound: BTreeSet<ProjectId>,
    capabilities: BTreeMap<ProjectId, HtmlSyncCapabilityReport>,
    observers: BTreeMap<ProjectId, ProjectObserver<FilesystemSourceReader, SystemObservationClock>>,
    watchers: BTreeMap<ProjectId, ProjectFilesystemWatcher>,
    watch_tx: Sender<WatchNotice>,
    watch_rx: Receiver<WatchNotice>,
    accepting: bool,
    last_startup: Option<HtmlSyncStartupReport>,
}

impl HtmlSyncRecoveryHost {
    /// Creates the host over one store and one private candidate root.
    pub fn new(store: StoreHandle, candidate_root: impl AsRef<Path>) -> Result<Self, H3Error> {
        let candidate_root = candidate_root.as_ref();
        let candidate_root = if candidate_root.is_absolute() {
            candidate_root.to_path_buf()
        } else {
            std::path::absolute(candidate_root).map_err(|error| H3Error::Storage {
                detail: format!("the private candidate root is not absolute: {error}"),
            })?
        };
        let candidates = CandidateArtifactStore::new(candidate_root)?;
        let worker = HtmlSyncWorker::new(store.clone(), candidates.clone());
        let (watch_tx, watch_rx) = channel();
        Ok(Self {
            store,
            candidates,
            worker,
            projects: BTreeMap::new(),
            bound: BTreeSet::new(),
            capabilities: BTreeMap::new(),
            observers: BTreeMap::new(),
            watchers: BTreeMap::new(),
            watch_tx,
            watch_rx,
            accepting: true,
            last_startup: None,
        })
    }

    /// Shared store handle used by the one H3 worker.
    pub fn store_handle(&self) -> StoreHandle {
        self.store.clone()
    }

    /// Private candidate root used by the one H3 worker.
    pub fn candidate_root(&self) -> &Path {
        self.candidates.root()
    }

    /// This host owns exactly one worker. The value is a stable invariant used
    /// by the desktop composition test.
    pub const fn worker_count(&self) -> usize {
        1
    }

    /// Registered project root.
    pub fn project_root(&self, project: ProjectId) -> Option<&Path> {
        self.projects.get(&project).map(|binding| binding.root.as_path())
    }

    /// Whether the project is bound to the app-lifetime worker.
    pub fn is_bound(&self, project: ProjectId) -> bool {
        self.bound.contains(&project)
    }

    /// Last capability report stored by the trusted composition.
    pub fn capability_report(&self, project: ProjectId) -> Option<&HtmlSyncCapabilityReport> {
        self.capabilities.get(&project)
    }

    /// Stores one host-computed capability report. An unavailable report
    /// unbinds the project's worker so a missing capability cannot keep
    /// authoring active.
    pub fn set_capability_report(
        &mut self,
        project: ProjectId,
        report: HtmlSyncCapabilityReport,
    ) {
        if !report.available() {
            self.bound.remove(&project);
            self.observers.remove(&project);
            self.watchers.remove(&project);
        }
        self.capabilities.insert(project, report);
    }

    /// Current observer health, when the project has an observer.
    pub fn observer_health(&self, project: ProjectId) -> Option<ObserverHealth> {
        self.observers.get(&project).map(ProjectObserver::health)
    }

    /// Delivers one project-relative signal to the project observer.
    ///
    /// This is the seam used by H1 persisted file-change notifications. It does
    /// not author or send by itself; the next pump settles the observation.
    pub fn observe_signal(&mut self, project: ProjectId, signal: ChangeSignal) -> bool {
        self.observers
            .get_mut(&project)
            .is_some_and(|observer| observer.notify(signal))
    }

    /// Binds one approved project only when its capability report is complete.
    ///
    /// It creates the per-project observer and watcher, seeds the stored source
    /// revisions, and performs one initial scan. The scan only offers stable
    /// observations to the one worker; the normal gate still decides whether a
    /// run may start.
    pub fn activate_project(
        &mut self,
        project: ProjectId,
        root: impl AsRef<Path>,
        settings: herness_html_sync::H3Settings,
        supervision: SupervisionId,
        dependencies: Vec<DependencyPath>,
    ) -> Result<bool, H3Error> {
        if !self
            .capabilities
            .get(&project)
            .is_some_and(HtmlSyncCapabilityReport::available)
        {
            return Ok(false);
        }
        self.worker.bind_project(
            project,
            root.as_ref(),
            settings.clone(),
            supervision,
            dependencies.clone(),
        )?;
        self.bound.insert(project);
        self.start_observer(project, root.as_ref(), &settings, dependencies)?;
        Ok(true)
    }

    /// Offers the saved current source after an explicit human resume.
    ///
    /// This does not send, start, or publish. It queues one normal authoring
    /// observation; the existing H2 budget/approval gate still applies.
    pub fn requeue_document(
        &mut self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<OfferOutcome, H3Error> {
        let settings = self
            .store
            .load_html_sync_settings(project)?
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h3.settings".to_owned(),
                detail: "the project has no stored settings".to_owned(),
            })?;
        let state = self
            .store
            .load_html_sync_document(project, document)?
            .ok_or_else(|| H3Error::NotFound {
                record: "document state",
                id: document.target_path().to_owned(),
            })?;
        let observation = SourceObservation {
            document: document.clone(),
            snapshot: state.state().source().clone(),
            change: SourceChange::Modified,
            trigger: herness_html_sync::ObservationTrigger::FileNotification,
            observed_via: vec![herness_html_sync::ChangeSource::ExternalEditor],
            eligibility: ObservationEligibility::from_settings(
                Some(settings.settings()),
                Timestamp::now(),
            ),
        };
        Ok(self.worker.observe(&observation))
    }

    fn start_observer(
        &mut self,
        project: ProjectId,
        root: &Path,
        settings: &herness_html_sync::H3Settings,
        dependencies: Vec<DependencyPath>,
    ) -> Result<(), H3Error> {
        if self.observers.contains_key(&project) {
            return Ok(());
        }
        let targets = ObservationTargets::from_settings(settings, dependencies)?;
        let eligibility = ObservationEligibility::from_settings(Some(settings), Timestamp::now());
        let reader = FilesystemSourceReader::new(root)?;
        let mut observer =
            ProjectObserver::new(targets, eligibility, reader, SystemObservationClock::new())?;
        if let Ok(documents) = self.store.list_html_sync_documents(project) {
            for record in documents {
                let _ = observer.seed_source(
                    record.state().document_key(),
                    record.state().source().clone(),
                );
            }
        }
        let tick = observer.initial_scan();
        self.feed_tick(&tick);
        self.observers.insert(project, observer);
        match ProjectFilesystemWatcher::start(root, self.watch_tx.clone()) {
            Ok(watcher) => {
                self.watchers.insert(project, watcher);
            }
            Err(_) => {
                if let Some(observer) = self.observers.get_mut(&project) {
                    observer.report_watcher_failure();
                }
            }
        }
        Ok(())
    }

    fn feed_tick(&mut self, tick: &ObserverTick) {
        // Generated HTML and receipts are companion observations. They never
        // become Markdown authoring work.
        for observation in &tick.sources {
            if observation.is_authoring_candidate() {
                self.worker.observe(observation);
            }
        }
    }

    fn drain_watch_notices(&mut self) {
        while let Ok(notice) = self.watch_rx.try_recv() {
            for observer in self.observers.values_mut() {
                match &notice {
                    WatchNotice::Signal(signal) => {
                        observer.notify(signal.clone());
                    }
                    WatchNotice::Failure => {
                        observer.report_watcher_failure();
                    }
                }
            }
        }
    }

    fn poll_observers(&mut self) {
        let mut sources = Vec::new();
        for observer in self.observers.values_mut() {
            sources.extend(observer.poll().sources);
        }
        for observation in &sources {
            if observation.is_authoring_candidate() {
                self.worker.observe(observation);
            }
        }
    }

    /// Registers one open project without starting anything.
    pub fn register_project(
        &mut self,
        project: ProjectId,
        root: impl AsRef<Path>,
        dependencies: Vec<DependencyPath>,
    ) {
        self.projects.insert(
            project,
            RecoveryProject {
                root: root.as_ref().to_path_buf(),
                dependencies,
            },
        );
    }

    /// Removes one closed project from future recovery scans.
    pub fn remove_project(&mut self, project: ProjectId) {
        self.projects.remove(&project);
        self.bound.remove(&project);
        self.capabilities.remove(&project);
        self.observers.remove(&project);
        self.watchers.remove(&project);
    }

    /// Last startup report.
    pub const fn last_startup(&self) -> Option<&HtmlSyncStartupReport> {
        self.last_startup.as_ref()
    }

    /// Whether new H3 authoring/publication starts are accepted.
    pub const fn accepting_new_work(&self) -> bool {
        self.accepting
    }

    /// Project with the active H3 authoring slot, when one exists.
    pub fn active_project(&self) -> Option<ProjectId> {
        self.worker.active_project()
    }

    /// Restores H3 state for every registered project.
    ///
    /// Each project is reconciled independently. A failure is recorded and never
    /// converted into a clean result. The H3 worker is bound only when the
    /// stored settings carry a current human approval and an existing H2 target
    /// can be recovered from the durable H3 state.
    pub fn restore(
        &mut self,
        runtime: &mut DesktopRuntime,
        supervision: &mut SupervisionHost,
        now: Timestamp,
    ) -> HtmlSyncStartupReport {
        let mut reports = Vec::new();
        let mut failures = Vec::new();
        let mut bound = Vec::new();
        let dependencies = self.dependency_map();
        for (project, binding) in self.projects.clone() {
            let reader = match FilesystemSourceReader::new(&binding.root) {
                Ok(reader) => reader,
                Err(error) => {
                    failures.push(HtmlSyncRecoveryFailure {
                        project_id: project,
                        detail: error.to_string(),
                    });
                    continue;
                }
            };
            let reads = DesktopRecoveryReads {
                reader,
                candidates: self.candidates.clone(),
            };
            let mut runtime_port = DesktopRecoveryRuntime {
                runtime,
                supervision,
                store: self.store.clone(),
            };
            let clock = FixedClock(now);
            let report = {
                let mut service = RecoveryService::new(
                    &mut self.store,
                    &reads,
                    &mut runtime_port,
                    &clock,
                    &dependencies,
                );
                service.reconcile_project(project)
            };
            match report {
                Ok(report) => {
                    let settings = report.settings().map(|record| record.settings().clone());
                    if let Some(settings) = settings
                        && settings.enabled()
                        && settings.approval().is_some()
                        && let Some(supervision_id) = self.supervision_for(project)
                        && self
                            .capabilities
                            .get(&project)
                            .is_some_and(HtmlSyncCapabilityReport::available)
                    {
                        match self.activate_project(
                            project,
                            &binding.root,
                            settings.clone(),
                            supervision_id,
                            binding.dependencies.clone(),
                        ) {
                            Ok(true) => {
                                if let Some(job_id) = self.durable_job_id(project) {
                                    if let Err(error) =
                                        self.worker.restore_job_id(project, job_id)
                                    {
                                        failures.push(HtmlSyncRecoveryFailure {
                                            project_id: project,
                                            detail: error.to_string(),
                                        });
                                    }
                                }
                                self.bound.insert(project);
                                bound.push(project);
                                // A restart never auto-authors. Every approved
                                // Target starts latched until an explicit human
                                // resume/reassess clears it.
                                for path in settings.target_paths() {
                                    if let Ok(document) = DocumentKey::new(project, path.clone()) {
                                        self.worker.seed_latch(
                                            document,
                                            Some(CycleLatch::RecoveryReconciliation),
                                            "the process restarted; a human resume is required",
                                        );
                                    }
                                }
                            }
                            Ok(false) => {}
                            Err(error) => {
                                failures.push(HtmlSyncRecoveryFailure {
                                    project_id: project,
                                    detail: error.to_string(),
                                });
                            }
                        }
                    }
                    for recovery in report.documents() {
                        if let Some(latch) = recovery.latch() {
                            self.worker.seed_latch(
                                recovery.document().clone(),
                                Some(latch),
                                "stored H3 recovery latch",
                            );
                        }
                    }
                    reports.push(report);
                }
                Err(error) => failures.push(HtmlSyncRecoveryFailure {
                    project_id: project,
                    detail: error.to_string(),
                }),
            }
        }
        let report = HtmlSyncStartupReport {
            projects: reports,
            bound_projects: bound,
            failures,
            side_effects: RecoverySideEffects::zero(),
        };
        self.last_startup = Some(report.clone());
        report
    }

    /// Records one observer candidate without starting anything.
    pub fn observe(
        &mut self,
        observation: &herness_html_sync::SourceObservation,
    ) -> herness_html_sync::OfferOutcome {
        self.worker.observe(observation)
    }

    /// Clears one persisted restart latch after an explicit human resume.
    ///
    /// The trusted command layer owns the preflight and request record; this
    /// method only updates the in-process coordinator latch.
    pub fn clear_latch(&mut self, document: &DocumentKey) -> bool {
        self.worker.clear_latch(document)
    }

    /// Seeds one persisted human-stop/recovery latch.
    pub fn seed_latch(
        &mut self,
        document: DocumentKey,
        latch: Option<CycleLatch>,
        detail: impl Into<String>,
    ) {
        self.worker.seed_latch(document, latch, detail);
    }

    /// Requests a cooperative stop for one project's active authoring run.
    pub fn stop_active(
        &mut self,
        runtime: &mut DesktopRuntime,
        document: &DocumentKey,
    ) -> Result<Option<StopOutcome>, H3Error> {
        self.worker.stop_active(runtime, document)
    }

    /// Runs the read-only human resume preflight for one document.
    ///
    /// The current source is read from the project, H2 facts come from the real
    /// supervision recovery path, and the approved profile/consent/policy/pack
    /// values come from the saved human approval. It never sends or writes.
    pub fn resume_preflight(
        &mut self,
        runtime: &mut DesktopRuntime,
        supervision: &mut SupervisionHost,
        document: &DocumentKey,
        expected_revision: u64,
        now: Timestamp,
    ) -> Result<ResumePreflight, H3Error> {
        let project = document.project_id();
        let settings = self
            .store
            .load_html_sync_settings(project)?
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h3.settings".to_owned(),
                detail: "the project has no stored settings".to_owned(),
            })?;
        let approval = settings
            .settings()
            .approval()
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h3.approval".to_owned(),
                detail: "the stored settings carry no human approval".to_owned(),
            })?
            .clone();
        let job = self
            .worker
            .job(project)
            .cloned()
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h3.job".to_owned(),
                detail: "the project is not bound to an approved H3 job".to_owned(),
            })?;
        let binding = self.projects.get(&project).ok_or_else(|| H3Error::NotFound {
            record: "open project",
            id: project.to_string(),
        })?;
        let reader = FilesystemSourceReader::new(&binding.root)?;
        let reads = DesktopRecoveryReads {
            reader,
            candidates: self.candidates.clone(),
        };
        let bytes = reads.read_source(document)?.ok_or_else(|| H3Error::NotFound {
            record: "source",
            id: document.target_path().to_owned(),
        })?;
        let record = self
            .store
            .load_html_sync_document(project, document)?
            .ok_or_else(|| H3Error::NotFound {
                record: "document state",
                id: document.target_path().to_owned(),
            })?;
        let observed_source = herness_html_sync::SourceSnapshot::new(
            herness_html_sync::SourceRevision::new(record.state().source().revision().get())?,
            ContentDigest::sha256(&bytes),
        );
        let dependencies = self.dependency_map();
        let mut runtime_port = DesktopRecoveryRuntime {
            runtime,
            supervision,
            store: self.store.clone(),
        };
        let cycle = match record.state().cycle_id() {
            Some(cycle_id) => self.store.load_html_sync_cycle(project, cycle_id)?,
            None => None,
        };
        let h2 = runtime_port.h2_facts(document, record.state().h2(), cycle.as_ref())?;
        let clock = FixedClock(now);
        let mut service = RecoveryService::new(
            &mut self.store,
            &reads,
            &mut runtime_port,
            &clock,
            &dependencies,
        );
        service.resume_preflight(herness_html_sync::ResumePreflightRequest {
            document,
            expected_revision,
            job: &job,
            settings: &settings,
            observed_source: &observed_source,
            policy_version: approval.versions().policy_version(),
            policy_digest: approval.versions().policy_fingerprint(),
            pack_digest: approval.versions().pack_fingerprint(),
            h2: h2.as_ref(),
            current_authoring_profile: Some(&approval.authoring().profile()),
            current_authoring_consent: Some(&approval.authoring().consent()),
            current_html_profile: Some(&approval.assessment().profile()),
            current_html_consent: Some(&approval.assessment().consent()),
            now,
        })
    }

    /// One app-lifetime worker pass. It never creates a window or selects a
    /// project; the host pump calls it for every registered project.
    pub fn pump(
        &mut self,
        runtime: &mut DesktopRuntime,
        supervision: &mut SupervisionHost,
    ) -> Result<Option<CoordinatorTick>, H3Error> {
        if !self.accepting || self.bound.is_empty() {
            return Ok(None);
        }
        self.drain_watch_notices();
        self.poll_observers();
        let registry_store = self.store.clone();
        let registry = StoreBackedOwnerApprovalRegistry::new(&registry_store);
        self.worker.pump(runtime, supervision, &registry).map(Some)
    }

    /// Stops accepting new H3 work, requests cooperative stops, and saves the
    /// H3 stopped/recovery latches after the H1 coordinated-stop attempt.
    pub fn begin_quit(
        &mut self,
        runtime: &mut DesktopRuntime,
        supervision: &mut SupervisionHost,
        h1_report: &herness_core::runtime::ShutdownReport,
        now: Timestamp,
    ) -> HtmlSyncQuitReport {
        self.accepting = false;
        self.watchers.clear();
        let mut projects = Vec::new();
        let mut failures = Vec::new();
        for project in self.projects.keys().copied().collect::<Vec<_>>() {
            let confirmed = self.confirmed_stops(project, h1_report);
            let mut runtime_port = DesktopRecoveryRuntime {
                runtime,
                supervision,
                store: self.store.clone(),
            };
            let clock = FixedClock(now);
            let dependencies = BTreeMap::new();
            let report = {
                let mut service = RecoveryService::new(
                    &mut self.store,
                    &NoopRecoveryReads,
                    &mut runtime_port,
                    &clock,
                    &dependencies,
                );
                service.quit_project(project, &confirmed)
            };
            match report {
                Ok(report) => projects.push(report),
                Err(error) => failures.push(HtmlSyncRecoveryFailure {
                    project_id: project,
                    detail: error.to_string(),
                }),
            }
        }
        HtmlSyncQuitReport {
            projects,
            failures,
            accepting_new_work: false,
        }
    }

    fn dependency_map(&self) -> BTreeMap<ProjectId, Vec<DependencyPath>> {
        self.projects
            .iter()
            .map(|(project, binding)| (*project, binding.dependencies.clone()))
            .collect()
    }

    /// The exact dependency paths registered for one project.
    pub fn dependencies(&self, project: ProjectId) -> Vec<DependencyPath> {
        self.projects
            .get(&project)
            .map(|binding| binding.dependencies.clone())
            .unwrap_or_default()
    }

    pub(crate) fn supervision_for(&self, project: ProjectId) -> Option<SupervisionId> {
        let store = self.store.lock();
        let documents = store
            .list_html_sync_documents(project)
            .ok()
            .unwrap_or_default();
        for document in &documents {
            if let Some(h2) = document.state().h2() {
                return Some(h2.supervision_id());
            }
            if let Some(cycle_id) = document.state().cycle_id()
                && let Ok(Some(cycle)) = store.load_html_sync_cycle(project, cycle_id)
                && let Some(supervision_id) = cycle.supervision_id()
            {
                return Some(supervision_id);
            }
            if let Some(generation_id) = document.state().generation()
                && let Ok(generations) =
                    store.html_sync_generations(project, document.state().document_key())
                && let Some(generation) = generations
                    .iter()
                    .find(|generation| generation.generation_id() == generation_id)
                && let Some(h2) = generation.h2()
            {
                return Some(h2.supervision_id());
            }
        }
        None
    }

    fn durable_job_id(&self, project: ProjectId) -> Option<JobId> {
        let store = self.store.lock();
        let documents = store.list_html_sync_documents(project).ok()?;
        for document in documents {
            let Some(generation_id) = document.state().generation() else {
                continue;
            };
            let generations = store
                .html_sync_generations(project, document.state().document_key())
                .ok()?;
            if let Some(generation) = generations
                .iter()
                .find(|generation| generation.generation_id() == generation_id)
            {
                return Some(generation.job_id());
            }
        }
        None
    }

    fn confirmed_stops(
        &self,
        project: ProjectId,
        report: &herness_core::runtime::ShutdownReport,
    ) -> BTreeMap<DocumentKey, bool> {
        let mut confirmed = BTreeMap::new();
        let store = self.store.lock();
        let documents = store
            .list_html_sync_documents(project)
            .ok()
            .unwrap_or_default();
        for document in documents {
            let state = document.state();
            let Some(supervision_id) = state.h2().map(|h2| h2.supervision_id()).or_else(|| {
                state.cycle_id().and_then(|cycle_id| {
                    store
                        .load_html_sync_cycle(project, cycle_id)
                        .ok()
                        .flatten()
                        .and_then(|cycle| cycle.supervision_id())
                })
            }) else {
                continue;
            };
            let Ok(Some(record)) = store.load_supervision_record(project, supervision_id) else {
                continue;
            };
            let Some(run) = record.run_group().runs().last() else {
                continue;
            };
            if let Some(observed) = report
                .runs()
                .iter()
                .find(|observed| observed.run_id() == *run)
            {
                confirmed.insert(
                    state.document_key().clone(),
                    matches!(
                        observed.report(),
                        Some(
                            herness_core::StopReport::Stopped
                                | herness_core::StopReport::NotRunning
                        )
                    ),
                );
            }
        }
        confirmed
    }
}

#[derive(Debug, Clone, Copy)]
struct FixedClock(Timestamp);

impl ClockPort for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

struct DesktopRecoveryReads {
    reader: FilesystemSourceReader,
    candidates: CandidateArtifactStore,
}

impl RecoveryReadPort for DesktopRecoveryReads {
    fn read_source(&self, document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error> {
        read_optional(&self.reader, document.target_path())
    }

    fn read_companion(&self, document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error> {
        read_optional(&self.reader, &document.companion_path())
    }

    fn read_receipt(&self, document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error> {
        read_optional(&self.reader, &recovery::receipt_path(document))
    }

    fn candidate_bytes(
        &self,
        candidate: &herness_html_sync::CandidateRecord,
    ) -> Result<CandidateBytes, H3Error> {
        let verification = self.candidates.verify_candidate_record(candidate)?;
        Ok(recovery::candidate_bytes(verification))
    }

    fn dependency_digest(
        &self,
        _document: &DocumentKey,
        kind: DependencyKind,
        paths: &[DependencyPath],
    ) -> Result<Option<ContentDigest>, H3Error> {
        let mut entries = Vec::with_capacity(paths.len());
        for dependency in paths.iter().filter(|dependency| dependency.kind() == kind) {
            let Some(bytes) = read_optional(&self.reader, dependency.path())? else {
                return Ok(None);
            };
            entries.push((dependency.path(), ContentDigest::sha256(&bytes)));
        }
        Ok(Some(dependency_fingerprint(kind, entries)))
    }
}

struct NoopRecoveryReads;

impl RecoveryReadPort for NoopRecoveryReads {
    fn read_source(&self, _document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error> {
        Ok(None)
    }

    fn read_companion(&self, _document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error> {
        Ok(None)
    }

    fn read_receipt(&self, _document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error> {
        Ok(None)
    }

    fn candidate_bytes(
        &self,
        _candidate: &herness_html_sync::CandidateRecord,
    ) -> Result<CandidateBytes, H3Error> {
        Ok(CandidateBytes::Missing)
    }

    fn dependency_digest(
        &self,
        _document: &DocumentKey,
        _kind: DependencyKind,
        _paths: &[DependencyPath],
    ) -> Result<Option<ContentDigest>, H3Error> {
        Ok(None)
    }
}

struct DesktopRecoveryRuntime<'a> {
    runtime: &'a mut DesktopRuntime,
    supervision: &'a mut SupervisionHost,
    store: StoreHandle,
}

impl RecoveryRuntimePort for DesktopRecoveryRuntime<'_> {
    fn h2_facts(
        &mut self,
        document: &DocumentKey,
        h2: Option<&herness_html_sync::H2Reference>,
        cycle: Option<&SyncCycle>,
    ) -> Result<Option<H2RecoveryFacts>, H3Error> {
        let project = document.project_id();
        let supervision_id = h2
            .map(|reference| reference.supervision_id())
            .or_else(|| cycle.and_then(SyncCycle::supervision_id));
        let Some(supervision_id) = supervision_id else {
            return Ok(None);
        };
        let plans = self.supervision.plans();
        let mut adapter = DesktopH1::new(self.runtime, self.store.clone(), plans);
        let view = match self
            .supervision
            .recovery(&mut adapter, project, supervision_id)
        {
            Ok(view) => view,
            Err(_) => return Ok(None),
        };
        let state = supervision_state(&view.state);
        let unresolved = view
            .unresolved_requests
            .iter()
            .map(|request| {
                H2RequestUnknown::new(
                    request
                        .get("attemptId")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown"),
                    request
                        .get("kind")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown"),
                    request
                        .get("purpose")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown"),
                )
            })
            .collect::<Vec<_>>();
        let budget_usage = view
            .budget
            .get("usage")
            .cloned()
            .and_then(|value| serde_json::from_value::<BudgetUsage>(value).ok())
            .unwrap_or_else(BudgetUsage::empty);
        let remaining = view
            .budget
            .get("remainingActiveSeconds")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let money_cap = view
            .budget
            .get("moneyLimitMicros")
            .and_then(serde_json::Value::as_u64);
        let can_start = view
            .budget
            .get("canStartRun")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let unresolved_charges = view
            .budget
            .get("unresolvedCharges")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let mut labels = view
            .block_reasons
            .iter()
            .filter_map(|reason| reason.get("kind").and_then(serde_json::Value::as_str))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        labels.extend(
            view.version_mismatches
                .iter()
                .filter_map(|mismatch| mismatch.get("kind").and_then(serde_json::Value::as_str))
                .map(str::to_owned),
        );
        let has = |label: &str| labels.iter().any(|candidate| candidate == label);
        let has_mismatch = |label: &str| {
            view.version_mismatches.iter().any(|mismatch| {
                mismatch.get("kind").and_then(serde_json::Value::as_str) == Some(label)
            })
        };
        let budget_exhausted = !can_start
            || remaining == 0
            || unresolved_charges > 0
            || !view
                .budget
                .get("policyMatches")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
        Ok(Some(H2RecoveryFacts::new(
            supervision_id,
            view.revision.max(1),
            state,
            view.resumable,
            unresolved,
            has("stop_unconfirmed"),
            !view.resumable,
            budget_usage,
            remaining,
            money_cap,
            budget_exhausted,
            !has("permissions_changed"),
            !has("profile_changed") && !has_mismatch("profile"),
            !has("consent_changed") && !has_mismatch("consent"),
            !has("approval_invalid") && !has_mismatch("approval"),
            labels,
        )?))
    }

    fn request_stop(&mut self, document: &DocumentKey) -> Result<RecoveryStop, H3Error> {
        let project = document.project_id();
        let store = self.store.lock();
        let Some(record) = store.load_html_sync_document(project, document)? else {
            return Ok(RecoveryStop::NotRunning);
        };
        let supervision_id = record
            .state()
            .h2()
            .map(|h2| h2.supervision_id())
            .or_else(|| {
                record.state().cycle_id().and_then(|cycle_id| {
                    store
                        .load_html_sync_cycle(project, cycle_id)
                        .ok()
                        .flatten()
                        .and_then(|cycle| cycle.supervision_id())
                })
            });
        let Some(supervision_id) = supervision_id else {
            return Ok(RecoveryStop::NotRunning);
        };
        let Some(supervision) = store.load_supervision_record(project, supervision_id)? else {
            return Ok(RecoveryStop::NotRunning);
        };
        let Some(run) = supervision.run_group().runs().last() else {
            return Ok(RecoveryStop::NotRunning);
        };
        drop(store);
        let state = match self.runtime.run(project, *run) {
            Ok(view) => view.state(),
            Err(error) => {
                return Err(H3Error::Unavailable {
                    capability: "h1.recovery.run".to_owned(),
                    detail: error.to_string(),
                });
            }
        };
        if !state.is_active() {
            return Ok(RecoveryStop::NotRunning);
        }
        let outcome = self
            .runtime
            .stop_run(project, *run, StopReason::UserRequest)
            .map_err(|error| H3Error::Unavailable {
                capability: "h1.recovery.stop".to_owned(),
                detail: error.to_string(),
            })?;
        Ok(match outcome.report() {
            herness_core::StopReport::Stopped | herness_core::StopReport::NotRunning => {
                RecoveryStop::Confirmed
            }
            herness_core::StopReport::Unconfirmed => RecoveryStop::Unconfirmed,
        })
    }
}

fn read_optional(reader: &FilesystemSourceReader, path: &str) -> Result<Option<Vec<u8>>, H3Error> {
    use herness_html_sync::SourceReadPort;
    match reader.read(path) {
        Ok(read) if read.is_stable() => Ok(Some(read.bytes().to_vec())),
        Ok(_) => Err(H3Error::Unavailable {
            capability: "h3.recovery.read".to_owned(),
            detail: format!("{path} changed while recovery was reading it"),
        }),
        Err(SourceReadError::NotFound) => Ok(None),
        Err(error) => Err(H3Error::Unavailable {
            capability: "h3.recovery.read".to_owned(),
            detail: format!("{path} could not be read: {}", error.as_str()),
        }),
    }
}

fn supervision_state(label: &str) -> SupervisionState {
    match label {
        "ready" => SupervisionState::Ready,
        "running" => SupervisionState::Running,
        "verifying" => SupervisionState::Verifying,
        "assessing" => SupervisionState::Assessing,
        "waiting_human" => SupervisionState::WaitingHuman,
        "stopped" => SupervisionState::Stopped,
        "failed" => SupervisionState::Failed,
        "cancelled" => SupervisionState::Cancelled,
        "completed" => SupervisionState::Completed,
        _ => SupervisionState::WaitingHuman,
    }
}
