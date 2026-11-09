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

use herness_core::{ProjectId, StopReason, Timestamp};
use herness_html_sync::observer::{
    DependencyKind, DependencyPath, FilesystemSourceReader, SourceReadError, dependency_fingerprint,
};
use herness_html_sync::recovery::{
    self, CandidateBytes, H2RecoveryFacts, H2RequestUnknown, ProjectRecoveryReport,
    QuitProjectReport, RecoveryReadPort, RecoveryRuntimePort, RecoveryService, RecoverySideEffects,
    RecoveryStop,
};
use herness_html_sync::{
    CandidateArtifactStore, CoordinatorTick, CycleLatch, DocumentKey, H3Error, JobId,
    StoreBackedOwnerApprovalRegistry, SyncCycle,
};
use herness_supervision::{BudgetUsage, ClockPort, ContentDigest, SupervisionId, SupervisionState};
use serde::Serialize;

use crate::host::DesktopRuntime;
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
        Ok(Self {
            store,
            candidates,
            worker,
            projects: BTreeMap::new(),
            bound: BTreeSet::new(),
            accepting: true,
            last_startup: None,
        })
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
                    {
                        match self.worker.bind_project(
                            project,
                            &binding.root,
                            settings.clone(),
                            supervision_id,
                            binding.dependencies.clone(),
                        ) {
                            Ok(_) => {
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

    fn supervision_for(&self, project: ProjectId) -> Option<SupervisionId> {
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
