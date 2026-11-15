//! Desktop quit, startup reconciliation, and the human-resume entry point.
//!
//! This module is the desktop half of [`herness_sdd_execute::recovery`]. It
//! assembles [`RecoveryFacts`](herness_sdd_execute::RecoveryFacts) from the shared
//! SQLite store, the stored H2 records, one read-only checkout observation, and
//! the exact progress-document bytes, and then:
//!
//! * on **quit**, writes the durable stop that closes new dispatch, sends, and
//!   commits before the coordinated stops begin, and writes the confirmed or
//!   unconfirmed stop afterwards. A failed H4 save is returned in
//!   [`H4QuitReport::failures`] so the quit flow can report that quit did not
//!   complete;
//! * on **startup**, reconciles every stored execution and keeps the report. It
//!   starts no child, sends no request, stages nothing, and commits nothing: the
//!   child side is a read of stored H2 state through [`RecoveryChildSource`];
//! * on **human resume**, assembles the same facts, verifies the current approval
//!   inputs, links at most one clearly established commit, and records the durable
//!   hold or the resumed state.
//!
//! Task 21 exposes these values over the trusted IPC; this module adds no Tauri
//! window, command, or UI type.

use std::collections::BTreeMap;
use std::path::Path;

use herness_core::contracts::ProjectId;
use herness_core::runtime::ShutdownReport;
use herness_core::{AbsolutePath, HostGitActor, ProcessSupervisor, SystemArgvLauncher};
use herness_sdd_execute::{
    ApprovalInputs, ChildStatus, CommitObservation, CommitObservationPort,
    DurableExecutionStorePort, ExecutionId, ExecutionRevision, ExecutionStorePort, FailureDetails,
    GitJournalEntry, HumanResume, PlanChangeGatePort, PlanChangeLatchStorePort,
    ProgressJournalEntry, RecoveryClass, RecoveryContext, RecoveryEnumerationPort, RecoveryFacts,
    RecoveryItem, RecoveryReport, ResumeBlocker, ResumeOutcome, ResumeRequest, SddExecutionError,
    Sha256Digest, StoredExecution, TaskRef, observation_request, reconcile,
    resume as resume_execution,
};

use crate::sdd_execute::coordinator::child_status_from_view;
use crate::sdd_execute::finalize::GitCheckoutObserver;
use crate::sdd_execute::git::GitRunner;
use crate::sdd_execute::ledger::DesktopProgressLedger;
use crate::supervision::SupervisionHost;
use crate::supervision::store::StoreHandle;

// ---------------------------------------------------------------------------
// Read-only fact sources
// ---------------------------------------------------------------------------

/// Reads the stored H2 result of one Task's child. It never starts a run.
pub trait RecoveryChildSource {
    /// Returns the stored H2 status, or `None` when H2 records no target.
    fn child_status(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        task: TaskRef,
    ) -> Result<Option<ChildStatus>, SddExecutionError>;
}

/// A source that reports every child as absent. It reads nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoChildren;

impl RecoveryChildSource for NoChildren {
    fn child_status(
        &mut self,
        _project_id: ProjectId,
        _execution_id: ExecutionId,
        _task: TaskRef,
    ) -> Result<Option<ChildStatus>, SddExecutionError> {
        Ok(None)
    }
}

/// Read-only child states over the shared H2 host.
pub struct SupervisionChildren<'a> {
    host: &'a SupervisionHost,
}

impl<'a> SupervisionChildren<'a> {
    /// Creates the read-only adapter.
    pub const fn new(host: &'a SupervisionHost) -> Self {
        Self { host }
    }
}

impl RecoveryChildSource for SupervisionChildren<'_> {
    fn child_status(
        &mut self,
        project_id: ProjectId,
        execution_id: ExecutionId,
        task: TaskRef,
    ) -> Result<Option<ChildStatus>, SddExecutionError> {
        let request = herness_sdd_execute::dispatch_request_id(execution_id, task);
        let Some(reservation) = self
            .host
            .h4_task_reservation(project_id, execution_id, request)
            .map_err(supervision_error)?
        else {
            return Ok(None);
        };
        let view = self
            .host
            .get(project_id, reservation.supervision_id())
            .map_err(supervision_error)?;
        Ok(Some(child_status_from_view(&reservation, &view)))
    }
}

/// Reads one project-relative document from the approved checkout.
pub trait RecoveryDocumentSource {
    /// Returns the exact bytes, or `None` when the document is absent.
    fn read(
        &mut self,
        checkout_root: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SddExecutionError>;
}

/// Confined filesystem document reads for the desktop composition.
#[derive(Debug, Default, Clone, Copy)]
pub struct FilesystemDocuments;

impl RecoveryDocumentSource for FilesystemDocuments {
    fn read(
        &mut self,
        checkout_root: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SddExecutionError> {
        let ledger = DesktopProgressLedger::new(checkout_root)?;
        ledger.read_document(path)
    }
}

/// A document source that reports every document as absent.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDocuments;

impl RecoveryDocumentSource for NoDocuments {
    fn read(
        &mut self,
        _checkout_root: &str,
        _path: &str,
    ) -> Result<Option<Vec<u8>>, SddExecutionError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/// One execution that could not be reconciled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryFailure {
    /// Project that owns the execution, when it could be read.
    pub project_id: Option<ProjectId>,
    /// Execution identity, when it could be read.
    pub execution_id: Option<ExecutionId>,
    /// Non-secret explanation.
    pub detail: String,
}

impl RecoveryFailure {
    fn of(project_id: ProjectId, execution_id: ExecutionId, detail: impl Into<String>) -> Self {
        Self {
            project_id: Some(project_id),
            execution_id: Some(execution_id),
            detail: detail.into(),
        }
    }

    fn global(detail: impl Into<String>) -> Self {
        Self {
            project_id: None,
            execution_id: None,
            detail: detail.into(),
        }
    }
}

/// One startup reconciliation result per stored execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H4StartupReport {
    reports: Vec<RecoveryReport>,
    failures: Vec<RecoveryFailure>,
}

impl H4StartupReport {
    /// Every reconciled execution.
    pub fn reports(&self) -> &[RecoveryReport] {
        &self.reports
    }

    /// Every execution that could not be reconciled.
    pub fn failures(&self) -> &[RecoveryFailure] {
        &self.failures
    }

    /// External requests issued while restoring. Always zero.
    pub const fn request_count(&self) -> u32 {
        0
    }

    /// The report of one execution.
    pub fn report(&self, execution_id: ExecutionId) -> Option<&RecoveryReport> {
        self.reports
            .iter()
            .find(|report| report.execution_id() == execution_id)
    }

    /// Whether every stored execution reconciled and nothing failed.
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty() && self.reports.iter().all(RecoveryReport::is_clean)
    }
}

/// One execution's quit result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H4QuitMark {
    /// Project that owns the execution.
    pub project_id: ProjectId,
    /// Execution identity.
    pub execution_id: ExecutionId,
    /// Whether the durable stop was confirmed by H1.
    pub confirmed: bool,
    /// Revision written, when a write happened.
    pub revision: Option<ExecutionRevision>,
}

/// The quit result for every execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct H4QuitReport {
    marks: Vec<H4QuitMark>,
    failures: Vec<RecoveryFailure>,
}

impl H4QuitReport {
    /// Every execution the quit marked.
    pub fn marks(&self) -> &[H4QuitMark] {
        &self.marks
    }

    /// Every execution whose quit state could not be saved.
    pub fn failures(&self) -> &[RecoveryFailure] {
        &self.failures
    }

    /// Whether every H4 save succeeded.
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }

    /// Every recorded stop H1 did not confirm.
    pub fn unconfirmed(&self) -> impl Iterator<Item = &H4QuitMark> {
        self.marks.iter().filter(|mark| !mark.confirmed)
    }

    /// A one-line reason quit did not complete, when a save failed.
    pub fn obstacle(&self) -> Option<String> {
        if self.failures.is_empty() {
            return None;
        }
        Some(format!(
            "{} H4 execution(s) could not be saved for quit: {}",
            self.failures.len(),
            self.failures
                .iter()
                .map(|failure| failure.detail.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        ))
    }
}

// ---------------------------------------------------------------------------
// The recovery host
// ---------------------------------------------------------------------------

/// The desktop quit, startup reconciliation, and human-resume composition.
///
/// One instance is app-lifetime. It opens no child and starts no run.
pub struct DesktopRecoveryHost {
    store: StoreHandle,
    git: Option<AbsolutePath>,
    documents: Box<dyn RecoveryDocumentSource + Send>,
    startup: H4StartupReport,
    reports: BTreeMap<ExecutionId, RecoveryReport>,
    quit: H4QuitReport,
}

impl DesktopRecoveryHost {
    /// Creates the composition over the shared store.
    ///
    /// `git` is the absolute Git executable used for the read-only checkout
    /// observation. `None` makes every commit classification `unknown`, which is
    /// the honest answer when the checkout cannot be compared.
    pub fn new(store: StoreHandle, git: Option<AbsolutePath>) -> Self {
        Self {
            store,
            git,
            documents: Box::new(FilesystemDocuments),
            startup: H4StartupReport::default(),
            reports: BTreeMap::new(),
            quit: H4QuitReport::default(),
        }
    }

    /// Replaces the read-only document source.
    #[must_use]
    pub fn with_documents(
        mut self,
        documents: impl RecoveryDocumentSource + Send + 'static,
    ) -> Self {
        self.documents = Box::new(documents);
        self
    }

    /// The shared store handle.
    pub const fn store_handle(&self) -> &StoreHandle {
        &self.store
    }

    /// Last startup reconciliation.
    pub const fn startup(&self) -> &H4StartupReport {
        &self.startup
    }

    /// Last quit result.
    pub const fn quit(&self) -> &H4QuitReport {
        &self.quit
    }

    /// The last reconciled report of one execution.
    pub fn report(&self, execution_id: ExecutionId) -> Option<&RecoveryReport> {
        self.reports.get(&execution_id)
    }

    /// Every reconciled report.
    pub fn reports(&self) -> impl Iterator<Item = &RecoveryReport> {
        self.reports.values()
    }

    /// Reconciles every stored execution without any external request.
    ///
    /// It opens no child, starts no run, stages nothing, and writes nothing. The
    /// child side is a read of stored H2 state only.
    pub fn restore(&mut self, children: &mut dyn RecoveryChildSource) -> H4StartupReport {
        let executions = match self.stored_executions() {
            Ok(executions) => executions,
            Err(error) => {
                self.startup = H4StartupReport {
                    reports: Vec::new(),
                    failures: vec![RecoveryFailure::global(format!(
                        "the stored executions could not be read: {error}"
                    ))],
                };
                return self.startup.clone();
            }
        };
        let mut reports = Vec::with_capacity(executions.len());
        let mut failures = Vec::new();
        for stored in executions {
            match self.reconcile_one(&stored, children) {
                Ok(report) => reports.push(report),
                Err(error) => failures.push(RecoveryFailure::of(
                    stored.snapshot().project_id(),
                    stored.snapshot().execution_id(),
                    error.to_string(),
                )),
            }
        }
        self.reports = reports
            .iter()
            .map(|report| (report.execution_id(), report.clone()))
            .collect();
        self.startup = H4StartupReport { reports, failures };
        self.startup.clone()
    }

    /// Reconciles exactly one stored execution.
    pub fn reconcile_execution(
        &mut self,
        execution_id: ExecutionId,
        children: &mut dyn RecoveryChildSource,
    ) -> Result<RecoveryReport, SddExecutionError> {
        let stored = self
            .stored_executions()?
            .into_iter()
            .find(|stored| stored.snapshot().execution_id() == execution_id)
            .ok_or_else(|| SddExecutionError::RecoveryRequired {
                reason: herness_sdd_execute::RecoveryReason::StateUnreadable,
                details: FailureDetails::none().boxed(),
            })?;
        let report = self.reconcile_one(&stored, children)?;
        self.reports.insert(execution_id, report.clone());
        Ok(report)
    }

    fn stored_executions(&self) -> Result<Vec<StoredExecution>, SddExecutionError> {
        let store = self.store.lock();
        store.stored_executions()
    }

    fn reconcile_one(
        &mut self,
        stored: &StoredExecution,
        children: &mut dyn RecoveryChildSource,
    ) -> Result<RecoveryReport, SddExecutionError> {
        let facts = self.facts_for(stored, children)?;
        let snapshot = stored.snapshot();
        let project = snapshot.project_id();
        let execution = snapshot.execution_id();
        let approval = self.bound_approval(stored);
        let latch = self.store.lock().plan_change_latch(project, execution)?;
        reconcile(
            stored,
            &facts,
            RecoveryContext {
                plan_change: latch.as_ref(),
                approval: approval.as_ref(),
            },
        )
    }

    /// The newest stored approval whose plan identity is the one this execution
    /// applies.
    ///
    /// The snapshot records the plan path, digest, and plan revision but not the
    /// approval identity, so the binding is the plan identity itself. A project
    /// with no matching approval yields `None`; the report then carries none, and
    /// a resume refuses with `approval_required`.
    fn bound_approval(
        &self,
        stored: &StoredExecution,
    ) -> Option<herness_sdd_execute::ExecutionApproval> {
        let snapshot = stored.snapshot();
        let store = self.store.lock();
        for approval_id in store.sdd_approval_ids(snapshot.project_id()).ok()? {
            let approval = store
                .latest_approval(snapshot.project_id(), approval_id)
                .ok()??;
            if approval.plan().digest() == snapshot.plan().digest()
                && approval.plan().plan_revision() == snapshot.plan().approved_revision()
            {
                return Some(approval);
            }
        }
        None
    }

    fn facts_for(
        &mut self,
        stored: &StoredExecution,
        children: &mut dyn RecoveryChildSource,
    ) -> Result<RecoveryFacts, SddExecutionError> {
        let snapshot = stored.snapshot();
        let project = snapshot.project_id();
        let execution = snapshot.execution_id();
        let (dispatch, git, progress, control, reservations) = {
            let store = self.store.lock();
            (
                store.dispatch_entries(project, execution)?,
                store.git_entries(project, execution)?,
                store.progress_entries(project, execution)?,
                store.control_records(project, execution)?,
                store.task_reservations(project, execution)?,
            )
        };
        let mut facts = RecoveryFacts::new()
            .with_dispatch(dispatch)
            .with_progress(progress.clone())
            .with_control(control)
            .with_reservations(reservations);
        for task in snapshot.tasks() {
            if let Some(status) = children.child_status(project, execution, task.task())? {
                facts = facts.with_child(status);
            }
        }
        if let Some(observation) = self.observe(stored, &git) {
            facts = facts.with_observation(observation);
        }
        let mut documents: Vec<String> = progress
            .iter()
            .map(|entry: &ProgressJournalEntry| entry.content().output_path().to_owned())
            .collect();
        documents.sort();
        documents.dedup();
        for path in documents {
            let bytes = self
                .documents
                .read(snapshot.workspace().canonical_checkout_root(), &path)?;
            facts = facts.with_document(path, bytes.as_deref().map(Sha256Digest::sha256));
        }
        Ok(facts.with_git(git))
    }

    /// Reads the checkout when a Git executable is configured and the checkout
    /// resolves. A failure is not an error: the classification then reports the
    /// commit as unknown instead of guessing.
    fn observe(
        &self,
        stored: &StoredExecution,
        git: &[GitJournalEntry],
    ) -> Option<CommitObservation> {
        let program = self.git.as_ref()?;
        let snapshot = stored.snapshot();
        let root =
            canonical_root(Path::new(snapshot.workspace().canonical_checkout_root())).ok()?;
        let request =
            observation_request(snapshot.project_id(), snapshot.workspace().branch(), git).ok()?;
        let runner = GitRunner::new(
            program.clone(),
            SystemArgvLauncher,
            ProcessSupervisor::new(),
            snapshot.project_id(),
        )
        .ok()?;
        let mut observer = GitCheckoutObserver::new(runner, root);
        CommitObservationPort::observe(&mut observer, &request).ok()
    }

    /// Writes the durable stop that closes new dispatch, sends, and commits.
    ///
    /// It runs before the coordinated stops, so a crash after this point leaves an
    /// execution the coordinator refuses to advance.
    pub fn begin_quit(&mut self) -> H4QuitReport {
        let executions = match self.stored_executions() {
            Ok(executions) => executions,
            Err(error) => return self.failed(format!("stored executions: {error}")),
        };
        let mut marks = Vec::new();
        let mut failures = Vec::new();
        for stored in executions {
            let snapshot = stored.snapshot();
            if herness_sdd_execute::quit_skips(snapshot) {
                continue;
            }
            let next = match herness_sdd_execute::quit_requested_snapshot(
                snapshot,
                snapshot.revision().next(),
            ) {
                Ok(next) => next,
                Err(error) => {
                    failures.push(RecoveryFailure::of(
                        snapshot.project_id(),
                        snapshot.execution_id(),
                        error.to_string(),
                    ));
                    continue;
                }
            };
            match self.write(snapshot, &next) {
                Ok(revision) => marks.push(H4QuitMark {
                    project_id: snapshot.project_id(),
                    execution_id: snapshot.execution_id(),
                    confirmed: false,
                    revision: Some(revision),
                }),
                Err(error) => failures.push(RecoveryFailure::of(
                    snapshot.project_id(),
                    snapshot.execution_id(),
                    error.to_string(),
                )),
            }
        }
        self.quit = H4QuitReport { marks, failures };
        self.quit.clone()
    }

    /// Writes the confirmed or unconfirmed stop after the H1 coordinated stops.
    ///
    /// A stop H1 did not confirm is recorded as `stop_unconfirmed`; it is never
    /// reported as a confirmed stop.
    pub fn mark_quit(&mut self, h1: &ShutdownReport) -> H4QuitReport {
        let executions = match self.stored_executions() {
            Ok(executions) => executions,
            Err(error) => return self.failed(format!("stored executions: {error}")),
        };
        let mut marks = Vec::new();
        let mut failures = Vec::new();
        for stored in executions {
            let snapshot = stored.snapshot();
            if herness_sdd_execute::quit_skips(snapshot) {
                continue;
            }
            let confirmed = stop_confirmed(snapshot.project_id(), h1);
            let next = match herness_sdd_execute::quit_confirmed_snapshot(
                snapshot,
                snapshot.revision().next(),
                confirmed,
            ) {
                Ok(next) => next,
                Err(error) => {
                    failures.push(RecoveryFailure::of(
                        snapshot.project_id(),
                        snapshot.execution_id(),
                        error.to_string(),
                    ));
                    continue;
                }
            };
            match self.write(snapshot, &next) {
                Ok(revision) => marks.push(H4QuitMark {
                    project_id: snapshot.project_id(),
                    execution_id: snapshot.execution_id(),
                    confirmed,
                    revision: Some(revision),
                }),
                Err(error) => failures.push(RecoveryFailure::of(
                    snapshot.project_id(),
                    snapshot.execution_id(),
                    error.to_string(),
                )),
            }
        }
        self.quit = H4QuitReport { marks, failures };
        self.quit.clone()
    }

    fn write(
        &mut self,
        snapshot: &herness_sdd_execute::ExecutionSnapshot,
        next: &herness_sdd_execute::ExecutionSnapshot,
    ) -> Result<ExecutionRevision, SddExecutionError> {
        let mut store = self.store.lock();
        store.compare_and_swap(
            snapshot.project_id(),
            snapshot.execution_id(),
            Some(snapshot.revision()),
            next,
        )
    }

    fn failed(&mut self, detail: impl Into<String>) -> H4QuitReport {
        self.quit = H4QuitReport {
            marks: Vec::new(),
            failures: vec![RecoveryFailure::global(detail)],
        };
        self.quit.clone()
    }

    /// Resumes one execution after a human confirmation.
    ///
    /// It re-observes the current inputs, links at most one established commit,
    /// and records the durable outcome. The report cache is refreshed from the
    /// written snapshot.
    pub fn resume(
        &mut self,
        request: &ResumeRequest,
        children: &mut dyn RecoveryChildSource,
        gate: Option<&mut dyn PlanChangeGatePort>,
        inputs: &ApprovalInputs,
    ) -> Result<ResumeOutcome, SddExecutionError> {
        let execution_id = request.identity().execution_id();
        let stored = self
            .stored_executions()?
            .into_iter()
            .find(|stored| stored.snapshot().execution_id() == execution_id)
            .ok_or_else(|| SddExecutionError::RecoveryRequired {
                reason: herness_sdd_execute::RecoveryReason::StateUnreadable,
                details: FailureDetails::none().boxed(),
            })?;
        let facts = self.facts_for(&stored, children)?;
        let project = stored.snapshot().project_id();
        let outcome = {
            let mut store = self.store.lock();
            resume_execution(&mut *store, request, &facts, gate, inputs)?
        };
        let stored = {
            let store = self.store.lock();
            store.load(project, execution_id)?
        };
        if let Some(stored) = stored {
            let facts = self.facts_for(&stored, children)?;
            let latch = self.store.lock().plan_change_latch(project, execution_id)?;
            let report = reconcile(
                &stored,
                &facts,
                RecoveryContext {
                    plan_change: latch.as_ref(),
                    approval: None,
                },
            )?;
            self.reports.insert(execution_id, report);
        }
        Ok(outcome)
    }
}

fn supervision_error(error: herness_supervision::SupervisionError) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: format!("h4.recovery.h2: {error}"),
        details: FailureDetails::none().boxed(),
    }
}

/// Whether every H1 run of `project` confirmed its coordinated stop.
///
/// A project with no processed run is unconfirmed: the H1 report cannot prove a
/// stop it did not observe.
fn stop_confirmed(project: ProjectId, h1: &ShutdownReport) -> bool {
    let mut seen = false;
    for run in h1.runs() {
        if run.project_id() != project {
            continue;
        }
        seen = true;
        if !matches!(
            run.report(),
            Some(herness_core::StopReport::Stopped | herness_core::StopReport::NotRunning)
        ) {
            return false;
        }
    }
    seen && h1
        .unconfirmed_runs()
        .iter()
        .all(|run| run.project_id() != project)
}

/// A canonical absolute checkout root for one observation.
pub fn canonical_root(root: &Path) -> Result<AbsolutePath, SddExecutionError> {
    let canonical =
        std::fs::canonicalize(root).map_err(|error| SddExecutionError::Unavailable {
            feature: format!("sdd_execute.recoveryRoot: {}", error.kind()),
            details: FailureDetails::none().boxed(),
        })?;
    AbsolutePath::new(canonical.to_string_lossy().into_owned()).map_err(|error| {
        SddExecutionError::InvalidValue {
            field: "recovery.checkoutRoot".to_owned(),
            detail: error.to_string(),
        }
    })
}

/// The host Git actor a read-only observation runs as.
pub fn observation_actor() -> Result<HostGitActor, SddExecutionError> {
    HostGitActor::new("herness", "host@example.invalid").map_err(|error| {
        SddExecutionError::InvalidValue {
            field: "recovery.actor".to_owned(),
            detail: error.to_string(),
        }
    })
}

/// The stable lines of one reconciled report, for the trusted UI and logs.
pub fn report_lines(report: &RecoveryReport) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "execution {} state={} revision={} external_requests={} budget_seconds={} remaining_seconds={}",
        report.execution_id(),
        report.state().as_str(),
        report.saved_revision().get(),
        report.external_requests(),
        report.budget().active_seconds(),
        report.remaining_seconds(),
    ));
    if let Some(latch) = report.plan_change() {
        lines.push(format!(
            "plan_change open={} reason={}",
            latch.is_open(),
            latch.change().reason().as_str()
        ));
    }
    for item in report.items() {
        lines.push(item_line(item));
    }
    lines
}

/// One classified record in one line.
pub fn item_line(item: &RecoveryItem) -> String {
    format!(
        "{} task={} class={} blocking={} detail={}",
        item.kind().as_str(),
        item.task()
            .map(|task| task.number().get().to_string())
            .unwrap_or_else(|| "-".to_owned()),
        item.class().as_str(),
        item.is_blocking(),
        item.detail()
    )
}

/// One blocked resume in one line, with the human action that clears it.
pub fn blocker_lines(blockers: &[ResumeBlocker]) -> Vec<String> {
    blockers
        .iter()
        .map(|blocker| match blocker {
            ResumeBlocker::Unresolved {
                kind,
                task,
                request,
                detail,
            } => format!(
                "unresolved kind={} task={} request={} action={} detail={detail}",
                kind.as_str(),
                task_number(*task),
                request.as_deref().unwrap_or("-"),
                blocker.human_action().as_str()
            ),
            ResumeBlocker::StopUnconfirmed { task } => format!(
                "stop_unconfirmed task={} action={}",
                task_number(*task),
                blocker.human_action().as_str()
            ),
            ResumeBlocker::PlanChangeOpen { change } => format!(
                "plan_change_open reason={} action={}",
                change.reason().as_str(),
                blocker.human_action().as_str()
            ),
            ResumeBlocker::BudgetExhausted { action, detail } => format!(
                "budget_exhausted action={} detail={detail}",
                action.as_str()
            ),
        })
        .collect()
}

fn task_number(task: Option<TaskRef>) -> String {
    task.map(|task| task.number().get().to_string())
        .unwrap_or_else(|| "-".to_owned())
}

/// The class of the newest Git journal record, when one exists.
pub fn newest_git_class(items: &[RecoveryItem]) -> Option<RecoveryClass> {
    items
        .iter()
        .rev()
        .find(|item| item.kind() == herness_sdd_execute::RecoveryRecordKind::Git)
        .map(RecoveryItem::class)
}

/// Mints a human resume confirmation for the trusted main-window path.
///
/// Only this call produces the value the core resume requires; a model tool, a
/// preview, or a request payload cannot reach it.
pub const fn confirm_resume() -> HumanResume {
    HumanResume::after_main_window_confirmation()
}
