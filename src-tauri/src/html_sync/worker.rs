//! Desktop composition of the H3 authoring loop.
//!
//! The pure H3 coordinator decides when one approved document may be authored.
//! This module connects that decision to the real H1 candidate run, the H2
//! approved-owner start/supersession path, the private candidate store, and the
//! durable H3 store. It creates no second runtime, engine, store, or H2 target.
//!
//! Candidate runs receive only `candidate_read`, `candidate_write`, and
//! `candidate_edit` bound to a host-issued `ArtifactHandle`. No model or IPC
//! input reaches the owner-authority mint, and a missing port or capability is
//! an explicit unavailable error.

use std::collections::BTreeMap;
use std::path::Path;

use herness_core::{
    ArtifactHandle, ArtifactPort, ArtifactSlot, ProjectId, RunState, StopReason, Timestamp,
};
use herness_html_sync::{
    ActiveOwner, AuthoringControlPort, AuthoringGate, AuthoringJob, AuthoringSnapshot,
    AuthoringWorkspace, CandidateArtifactStore, CandidateAuthored, CandidateGenerationRequest,
    CandidateId, CandidateStorageRef, CoordinatorPorts, CoordinatorTick, CycleLatch, DocumentKey,
    FilesystemSourceReader, GenerationId, H2Reference, H3Error, H3FailureCause, H3Reason,
    H3Settings, H3StateReasonKind, H3StopCause, HumanWaitCause, OfferOutcome, OwnerGateRequest,
    OwnerProgress, OwnerStartRequest, OwnerStarted, OwnerSupersedeRequest, RequiredAction,
    SourceObservation, StopOutcome, SupersessionOutcome, SyncCoordinator, WorkspaceReader,
};
use herness_supervision::owner_launch::{OwnerApprovalRegistryPort, authorize_owner_launch};
use herness_supervision::{
    ApprovalActor, ConsentId, DisclosureConsent, DisclosureScope,
    ProfilePurpose, StopCause, SupervisionId, SupervisionRequestId, SupervisionState,
    TargetVersion,
};

use crate::host::DesktopRuntime;
use crate::supervision::plan::{StoredPlan, load_plan};
use crate::supervision::runtime::DesktopH1;
use crate::supervision::store::StoreHandle;
use crate::supervision::{SupersedeSupervisionRequest, SupervisionHost};

/// Canonical workspace readers for every open project.
///
/// One coordinator is shared by all projects, so the capture port dispatches on
/// the document's project. Each reader is the observer's canonical filesystem
/// reader; the coordinator never constructs a project path.
#[derive(Debug, Clone, Default)]
pub struct ProjectWorkspaces {
    readers: BTreeMap<ProjectId, WorkspaceReader<FilesystemSourceReader>>,
}

impl ProjectWorkspaces {
    /// Adds or replaces one canonical project reader.
    pub fn insert(&mut self, project: ProjectId, root: impl AsRef<Path>) -> Result<(), H3Error> {
        let reader = FilesystemSourceReader::new(root)?;
        self.readers.insert(project, WorkspaceReader::new(reader));
        Ok(())
    }

    /// Removes a closed project.
    pub fn remove(&mut self, project: ProjectId) -> bool {
        self.readers.remove(&project).is_some()
    }
}

impl AuthoringWorkspace for ProjectWorkspaces {
    fn capture(
        &self,
        request: &herness_html_sync::WorkspaceCaptureRequest,
    ) -> Result<AuthoringSnapshot, H3Error> {
        self.readers
            .get(&request.document().project_id())
            .ok_or_else(|| H3Error::Unavailable {
                capability: "authoring.workspace".to_owned(),
                detail: "the document's project is not open".to_owned(),
            })?
            .capture(request)
    }
}

/// One app-lifetime H3 authoring worker.
///
/// The caller registers each open project with its approved settings, the H2
/// target that owns the job, and the exact dependency set. Notifications and
/// ticks are driven by the host pump, not by a parent-model tool call.
pub struct HtmlSyncWorker {
    coordinator: SyncCoordinator,
    store: StoreHandle,
    candidate_store: CandidateArtifactStore,
    workspaces: ProjectWorkspaces,
    jobs: BTreeMap<ProjectId, AuthoringJob>,
    settings: BTreeMap<ProjectId, H3Settings>,
}

impl HtmlSyncWorker {
    /// Creates a worker over the one process-wide H3 store.
    pub fn new(store: StoreHandle, candidate_store: CandidateArtifactStore) -> Self {
        Self {
            coordinator: SyncCoordinator::new(),
            store,
            candidate_store,
            workspaces: ProjectWorkspaces::default(),
            jobs: BTreeMap::new(),
            settings: BTreeMap::new(),
        }
    }

    /// Registers one open project and its approved job/Target scope.
    ///
    /// The job-to-`SupervisionId` mapping is host-owned; the caller supplies the
    /// exact existing H2 target. This method neither creates nor replaces a
    /// supervision target.
    pub fn bind_project(
        &mut self,
        project: ProjectId,
        root: impl AsRef<Path>,
        settings: H3Settings,
        supervision: SupervisionId,
        dependencies: Vec<herness_html_sync::observer::DependencyPath>,
    ) -> Result<AuthoringJob, H3Error> {
        let job = AuthoringJob::from_settings(&settings, supervision, Timestamp::now())?
            .with_dependencies(dependencies)?;
        self.workspaces.insert(project, root)?;
        self.settings.insert(project, settings);
        self.jobs.insert(project, job.clone());
        self.coordinator.bind_job(job.clone());
        Ok(job)
    }

    /// The approved job for one project.
    pub fn job(&self, project: ProjectId) -> Option<&AuthoringJob> {
        self.jobs.get(&project)
    }

    /// The current approved settings for one project.
    pub fn settings(&self, project: ProjectId) -> Option<&H3Settings> {
        self.settings.get(&project)
    }

    /// Records one stable observer candidate without starting anything.
    pub fn observe(&mut self, observation: &SourceObservation) -> OfferOutcome {
        self.coordinator.offer(observation)
    }

    /// The active generation, when one exists.
    pub fn active_generation(&self) -> Option<GenerationId> {
        self.coordinator.active_generation()
    }

    /// Project with the active authoring slot, when one exists.
    pub fn active_project(&self) -> Option<ProjectId> {
        self.coordinator
            .active_owner()
            .map(|owner| owner.job().project_id())
    }

    /// Documents in dirty notification order.
    pub fn queued_documents(&self) -> Vec<DocumentKey> {
        self.coordinator.queued_documents()
    }

    /// The current latch for one document, when observed by this process.
    pub fn latch(&self, document: &DocumentKey) -> Option<&herness_html_sync::HeldAuthoring> {
        self.coordinator.latch(document)
    }

    /// Restores the durable job identity of an already bound project.
    pub fn restore_job_id(
        &mut self,
        project: ProjectId,
        job_id: herness_html_sync::JobId,
    ) -> Result<(), H3Error> {
        let job = self.jobs.get(&project).cloned().ok_or_else(|| H3Error::NotFound {
            record: "authoring job",
            id: project.to_string(),
        })?;
        let job = job.with_durable_job_id(job_id)?;
        self.jobs.insert(project, job.clone());
        self.coordinator.bind_job(job);
        Ok(())
    }

    /// Seeds one persisted latch after a restart.
    ///
    /// This never queues, starts, sends, or clears anything. A later human
    /// resume/reassess must call [`Self::clear_latch`]; a new notification is
    /// still held until then.
    pub fn seed_latch(
        &mut self,
        document: DocumentKey,
        latch: Option<CycleLatch>,
        detail: impl Into<String>,
    ) {
        self.coordinator
            .seed_latch(herness_html_sync::HeldAuthoring {
                document,
                latch,
                detail: detail.into(),
            });
    }

    /// Clears one latch after an explicit human resume.
    pub fn clear_latch(&mut self, document: &DocumentKey) -> bool {
        self.coordinator.clear_latch(document).is_some()
    }

    /// Requests a cooperative stop for the document's active H1 run.
    ///
    /// A confirmed stop releases the app-wide authoring slot so a human pause or
    /// cancel cannot leave the slot allocated. An unconfirmed stop keeps the
    /// slot and returns `Unconfirmed`; the caller must persist the recovery
    /// latch rather than claiming the stop succeeded.
    pub fn stop_active(
        &mut self,
        runtime: &mut DesktopRuntime,
        document: &DocumentKey,
    ) -> Result<Option<StopOutcome>, H3Error> {
        let Some(owner) = self.coordinator.active_owner().cloned() else {
            return Ok(None);
        };
        if owner.document() != document {
            return Ok(None);
        }
        let outcome = self.stop_run(runtime, &owner)?;
        if outcome == StopOutcome::Confirmed {
            self.coordinator.take_active(document);
        }
        Ok(Some(outcome))
    }

    /// Releases the app-wide authoring slot after a stop that was already
    /// confirmed by the host.
    pub fn release_active(&mut self, document: &DocumentKey) -> bool {
        self.coordinator.take_active(document).is_some()
    }

    fn stop_run(
        &self,
        runtime: &mut DesktopRuntime,
        owner: &ActiveOwner,
    ) -> Result<StopOutcome, H3Error> {
        let outcome = runtime
            .stop_run(
                owner.job().project_id(),
                owner.run(),
                StopReason::UserRequest,
            )
            .map_err(|error| H3Error::Unavailable {
                capability: "h1.stop".to_owned(),
                detail: error.to_string(),
            })?;
        Ok(match outcome.report() {
            herness_core::StopReport::Stopped | herness_core::StopReport::NotRunning => {
                StopOutcome::Confirmed
            }
            herness_core::StopReport::Unconfirmed => StopOutcome::Unconfirmed,
        })
    }

    /// Runs one app-wide authoring pass.
    pub fn pump(
        &mut self,
        runtime: &mut DesktopRuntime,
        supervision: &mut SupervisionHost,
        registry: &dyn OwnerApprovalRegistryPort,
    ) -> Result<CoordinatorTick, H3Error> {
        runtime.pump().map_err(|error| H3Error::Unavailable {
            capability: "h1.pump".to_owned(),
            detail: error.to_string(),
        })?;
        // The H2 start intent is started by the host-owned supervisor pump. It
        // must use the same candidate handle as the H3 generation; otherwise a
        // run started by the pump would fall back to native tools.
        if let Some(owner) = self.coordinator.active_owner().cloned() {
            // The supervisor's first tick allocates the run and a later tick
            // starts it. Pump H2 while the allocated H1 run is not present yet;
            // the adapter carries the same candidate handle, so the run can
            // never start with native tools.
            let run_missing = runtime.run(owner.job().project_id(), owner.run()).is_err();
            if run_missing {
                let plans = supervision.plans();
                let mut adapter = DesktopH1::new(runtime, self.store.clone(), plans);
                adapter.set_candidate_artifact(Some(owner.handle().clone()));
                supervision
                    .pump(&mut adapter, &[owner.job().project_id()])
                    .map_err(|error| H3Error::Unavailable {
                        capability: "h2.pump".to_owned(),
                        detail: error.to_string(),
                    })?;
            }
        }
        let mut control = SupervisionAuthoringControl {
            runtime,
            supervision,
            registry,
            store: self.store.clone(),
            candidate_store: self.candidate_store.clone(),
            now: Timestamp::now(),
        };
        let mut ports = CoordinatorPorts {
            store: &mut self.store,
            workspace: &self.workspaces,
            control: &mut control,
        };
        self.coordinator.tick(&mut ports, Timestamp::now())
    }

    /// Handles a source change for the document currently being authored.
    ///
    /// The coordinator marks the old generation superseded, requires a
    /// confirmed H1 stop, and only then calls the H2 owner supersession path.
    pub fn source_changed(
        &mut self,
        runtime: &mut DesktopRuntime,
        supervision: &mut SupervisionHost,
        registry: &dyn OwnerApprovalRegistryPort,
        observation: &SourceObservation,
    ) -> Result<SupersessionOutcome, H3Error> {
        let mut control = SupervisionAuthoringControl {
            runtime,
            supervision,
            registry,
            store: self.store.clone(),
            candidate_store: self.candidate_store.clone(),
            now: Timestamp::now(),
        };
        let mut ports = CoordinatorPorts {
            store: &mut self.store,
            workspace: &self.workspaces,
            control: &mut control,
        };
        self.coordinator
            .source_changed(&mut ports, observation, Timestamp::now())
    }
}

struct SupervisionAuthoringControl<'a> {
    runtime: &'a mut DesktopRuntime,
    supervision: &'a mut SupervisionHost,
    registry: &'a dyn OwnerApprovalRegistryPort,
    store: StoreHandle,
    candidate_store: CandidateArtifactStore,
    now: Timestamp,
}

impl SupervisionAuthoringControl<'_> {
    fn record(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<herness_supervision::SupervisionRecord, H3Error> {
        self.store
            .lock()
            .load_supervision_record(project, supervision)?
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h2.supervision".to_owned(),
                detail: "the approved H2 target does not exist".to_owned(),
            })
    }

    fn plan(&self, project: ProjectId, supervision: SupervisionId) -> Result<StoredPlan, H3Error> {
        load_plan(&self.store, project, supervision)?.ok_or_else(|| H3Error::Unavailable {
            capability: "h2.plan".to_owned(),
            detail: "the approved H2 plan is unavailable".to_owned(),
        })
    }

    fn h2(record: &herness_supervision::SupervisionRecord) -> Result<H2Reference, H3Error> {
        Ok(H2Reference::new(
            record.project_id(),
            record.supervision_id(),
            Some(record.run_group().id()),
            Some(record.condition_version()),
            Some(record.target_version()),
            Some(record.revision()),
            Some(record.state()),
        )?)
    }

    fn started(
        &self,
        generation: GenerationId,
        handle: ArtifactHandle,
        storage: CandidateStorageRef,
        project: ProjectId,
        supervision: SupervisionId,
    ) -> Result<OwnerStarted, H3Error> {
        let record = self.record(project, supervision)?;
        let plan = self.plan(project, supervision)?;
        let run =
            record
                .run_group()
                .runs()
                .last()
                .copied()
                .ok_or_else(|| H3Error::Unavailable {
                    capability: "h1.run".to_owned(),
                    detail: "the H2 owner start did not create a run".to_owned(),
                })?;
        OwnerStarted::new(
            Self::h2(&record)?,
            run,
            generation,
            handle,
            storage,
            plan.packet.packet_version(),
            plan.packet.fingerprint().clone(),
        )
    }

    fn open_candidate(
        &self,
        request: &OwnerStartRequest,
    ) -> Result<(ArtifactHandle, CandidateStorageRef), H3Error> {
        self.open_candidate_for(
            request.document(),
            request.job(),
            request.handle(),
            request.snapshot(),
        )
    }

    fn open_candidate_for(
        &self,
        document: &DocumentKey,
        job: &AuthoringJob,
        handle: &ArtifactHandle,
        snapshot: &AuthoringSnapshot,
    ) -> Result<(ArtifactHandle, CandidateStorageRef), H3Error> {
        let request = CandidateGenerationRequest::new(
            document.clone(),
            job.job_label(),
            handle.generation(),
            Some(handle.token().to_owned()),
            snapshot.source_markdown().text().to_owned(),
            snapshot.existing_html().map(|html| html.text().to_owned()),
            snapshot.shared_css().map(|css| css.text().to_owned()),
        )?;
        let opened = self.candidate_store.open_generation(request)?;
        if opened.handle() != handle {
            return Err(H3Error::RecordConflict {
                record: "candidate generation",
                id: handle.generation().to_string(),
            });
        }
        Ok((opened.handle().clone(), opened.storage().clone()))
    }

    fn install_candidate_port(&mut self) {
        self.runtime
            .engine_mut()
            .set_artifact_port(Box::new(self.candidate_store.clone()));
    }

    fn authority(
        &self,
        project: ProjectId,
        supervision: SupervisionId,
        job: &AuthoringJob,
    ) -> Result<herness_supervision::HostOwnerAuthority, H3Error> {
        let binding = self.supervision.owner_launch_binding(
            project,
            supervision,
            job.settings_version(),
            job.job_label(),
        )?;
        Ok(authorize_owner_launch(self.registry, &binding, self.now)?)
    }

    /// Reissues the completion and Html consents for one exact approved
    /// Target set at the new H2 target version.
    ///
    /// This is host-only. It never widens the Target set, data kinds, origin,
    /// or purpose, and it records the previous/new version and the exact set in
    /// host state. A missing human H3 approval or any expanded scope is an
    /// explicit error before the supersession starts.
    fn reissue_range_consent(
        &mut self,
        project: ProjectId,
        supervision: SupervisionId,
        target_version: TargetVersion,
    ) -> Result<(), H3Error> {
        let settings = self
            .store
            .lock()
            .load_html_sync_settings(project)?
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h3.consent.settings".to_owned(),
                detail: "the project has no stored H3 settings".to_owned(),
            })?
            .settings()
            .clone();
        if !settings.verify_fingerprint() || !settings.enabled() {
            return Err(H3Error::Unavailable {
                capability: "h3.consent.approval".to_owned(),
                detail: "the stored H3 settings are disabled or tampered".to_owned(),
            });
        }
        let approval = settings.approval().cloned().ok_or_else(|| H3Error::Unavailable {
            capability: "h3.consent.approval".to_owned(),
            detail: "the stored settings carry no human range approval".to_owned(),
        })?;
        if !approval.is_current_at(self.now) {
            return Err(H3Error::Unavailable {
                capability: "h3.consent.approval".to_owned(),
                detail: "the human range approval is revoked, superseded, or expired".to_owned(),
            });
        }
        let mut config = self.supervision.config().get(project);
        for (purpose, approved) in [
            (ProfilePurpose::Completion, approval.authoring()),
            (ProfilePurpose::Html, approval.assessment()),
        ] {
            let Some(current) = config.consent(purpose).cloned() else {
                return Err(H3Error::Unavailable {
                    capability: "h3.consent".to_owned(),
                    detail: format!("no {} consent is configured", purpose.as_str()),
                });
            };
            if !matches!(
                current.state(),
                herness_supervision::ConsentState::Granted { .. }
            ) {
                return Err(H3Error::Unavailable {
                    capability: "h3.consent".to_owned(),
                    detail: format!("the {} consent is revoked", purpose.as_str()),
                });
            }
            let disclosure = approved.disclosure();
            if current.scope().targets() != disclosure.targets()
                || current.scope().data_kinds() != disclosure.data_kinds()
                || current.origin() != approved.origin()
            {
                return Err(H3Error::Unavailable {
                    capability: "h3.consent.scope".to_owned(),
                    detail: format!(
                        "reissuing {} consent would expand the human-approved Target set, data kinds, or origin",
                        purpose.as_str()
                    ),
                });
            }
            let scope = DisclosureScope::new(
                purpose,
                current.scope().data_kinds().clone(),
                current.scope().targets().to_vec(),
                target_version,
            )
            .map_err(H3Error::from)?;
            let consent = DisclosureConsent::grant(
                ApprovalActor::Human,
                ConsentId::new(project),
                current.origin().clone(),
                scope,
                self.now,
            )
            .map_err(H3Error::from)?;
            config.set_consent(consent);
            let record = serde_json::json!({
                "schema": "h3-range-consent-reissue-v1",
                "projectId": project,
                "supervisionId": supervision,
                "purpose": purpose.as_str(),
                "previousTargetVersion": current.target_scope_version().get(),
                "targetVersion": target_version.get(),
                "targets": current.scope().targets(),
                "dataKinds": current.scope().data_kinds(),
                "origin": current.origin().to_string(),
                "approvalId": approval.approval_id(),
                "reissuedAt": self.now,
            });
            let bytes = serde_json::to_vec(&record).map_err(|error| H3Error::Storage {
                detail: format!("consent reissue record: {error}"),
            })?;
            let key = format!(
                "h3.consent.reissue:{}:{}:{}",
                project,
                purpose.as_str(),
                target_version.get()
            );
            self.store
                .lock()
                .save_host_state(&key, &bytes)
                .map_err(|error| H3Error::Storage {
                    detail: format!("consent reissue record: {error}"),
                })?;
        }
        self.supervision.config().set(project, config);
        self.supervision
            .config()
            .persist(&self.store, project)
            .map_err(H3Error::from)?;
        Ok(())
    }

    fn read_candidate(&self, active: &ActiveOwner) -> Result<CandidateAuthored, H3Error> {
        let mut store = self.candidate_store.clone();
        let html = store
            .read_artifact(active.handle(), ArtifactSlot::CandidateHtml)
            .map_err(|failure| H3Error::Unavailable {
                capability: "candidate.read".to_owned(),
                detail: format!("candidate_html is unavailable: {failure:?}"),
            })?
            .ok_or_else(|| H3Error::Unavailable {
                capability: "candidate.read".to_owned(),
                detail: "the run ended without a candidate_html artifact".to_owned(),
            })?;
        let provenance = store
            .read_artifact(active.handle(), ArtifactSlot::CandidateProvenance)
            .map_err(|failure| H3Error::Unavailable {
                capability: "candidate.read".to_owned(),
                detail: format!("candidate_provenance is unavailable: {failure:?}"),
            })?
            .ok_or_else(|| H3Error::Unavailable {
                capability: "candidate.read".to_owned(),
                detail: "the run ended without a candidate_provenance artifact".to_owned(),
            })?;
        CandidateAuthored::new(
            active.generation(),
            CandidateId::new(active.job().project_id()),
            active.storage().clone(),
            herness_supervision::ContentDigest::sha256(html.content().as_bytes()),
            herness_supervision::ContentDigest::sha256(provenance.content().as_bytes()),
            Timestamp::now(),
            active.run(),
        )
    }
}

impl AuthoringControlPort for SupervisionAuthoringControl<'_> {
    fn gate(&mut self, request: &OwnerGateRequest) -> Result<AuthoringGate, H3Error> {
        request.job().verify_against(
            self.store
                .lock()
                .load_html_sync_settings(request.job().project_id())?
                .ok_or_else(|| H3Error::Unavailable {
                    capability: "h3.settings".to_owned(),
                    detail: "the project has no stored settings".to_owned(),
                })?
                .settings(),
            self.now,
        )?;
        let record = self.record(request.job().project_id(), request.job().supervision_id())?;
        let target_version = match request.previous_target() {
            Some(previous) => previous.next(),
            None => record.target_version(),
        };
        let state = record.state();
        match state {
            SupervisionState::WaitingHuman => {
                return Ok(AuthoringGate::Latched {
                    latch: Some(CycleLatch::WaitingHuman),
                    reason: H3Reason::new(
                        H3StateReasonKind::WaitingHuman {
                            cause: HumanWaitCause::RecoveryReconciliation,
                        },
                        vec![RequiredAction::ReconcileRecovery],
                    )?,
                    detail: "the H2 target is waiting for a human".to_owned(),
                });
            }
            SupervisionState::Stopped => {
                let cause = match record.reason() {
                    herness_supervision::SupervisionReason::Stopped { cause } => *cause,
                    _ => StopCause::RecoveryReconciliation,
                };
                let (latch, h3_cause) = match cause {
                    StopCause::UserRequest => (CycleLatch::HumanStop, H3StopCause::HumanRequest),
                    StopCause::Stagnation => (CycleLatch::Stagnation, H3StopCause::Stagnation),
                    StopCause::Budget(_) => (CycleLatch::BudgetLimit, H3StopCause::BudgetLimit),
                    StopCause::StopUnconfirmed => (
                        CycleLatch::RecoveryReconciliation,
                        H3StopCause::StopUnconfirmed,
                    ),
                    StopCause::RecoveryReconciliation => (
                        CycleLatch::RecoveryReconciliation,
                        H3StopCause::RecoveryReconciliation,
                    ),
                };
                return Ok(AuthoringGate::Latched {
                    latch: Some(latch),
                    reason: H3Reason::new(
                        H3StateReasonKind::Stopped { cause: h3_cause },
                        vec![RequiredAction::ResumeCycle],
                    )?,
                    detail: "the H2 target is stopped".to_owned(),
                });
            }
            SupervisionState::Failed => {
                return Ok(AuthoringGate::Failed {
                    cause: H3FailureCause::TargetUnstable,
                    detail: "the H2 target failed".to_owned(),
                });
            }
            SupervisionState::Cancelled => {
                return Ok(AuthoringGate::Latched {
                    latch: Some(CycleLatch::RecoveryReconciliation),
                    reason: H3Reason::new(
                        H3StateReasonKind::Stopped {
                            cause: H3StopCause::RecoveryReconciliation,
                        },
                        vec![RequiredAction::ResumeCycle],
                    )?,
                    detail: "the H2 target was cancelled and requires a human resume".to_owned(),
                });
            }
            SupervisionState::Running
            | SupervisionState::Verifying
            | SupervisionState::Assessing => {
                if request.previous_target().is_none() {
                    return Ok(AuthoringGate::Latched {
                        latch: Some(CycleLatch::RecoveryReconciliation),
                        reason: H3Reason::new(
                            H3StateReasonKind::WaitingHuman {
                                cause: HumanWaitCause::RecoveryReconciliation,
                            },
                            vec![RequiredAction::ReconcileRecovery],
                        )?,
                        detail: "the H2 target already has an active run".to_owned(),
                    });
                }
            }
            SupervisionState::Ready => {
                if request.previous_target().is_none() && !record.run_group().runs().is_empty() {
                    return Ok(AuthoringGate::Unavailable {
                        capability: "h2.owner_start".to_owned(),
                        detail: "the H2 target was already started".to_owned(),
                    });
                }
            }
            SupervisionState::Completed => {
                if request.previous_target().is_none() {
                    return Ok(AuthoringGate::Unavailable {
                        capability: "h2.owner_start".to_owned(),
                        detail:
                            "a completed target is not restarted; a new cycle needs its own target"
                                .to_owned(),
                    });
                }
            }
        }
        let view = self
            .supervision
            .get(request.job().project_id(), request.job().supervision_id())?;
        if let Some(budget) = &view.budget {
            let run_cap = budget.additional_runs.saturating_add(1);
            if budget.remaining_active_seconds == 0
                || budget
                    .usage
                    .runs_started()
                    .saturating_add(budget.usage.runs_reserved())
                    >= run_cap
            {
                return Ok(AuthoringGate::Latched {
                    latch: Some(CycleLatch::BudgetLimit),
                    reason: H3Reason::new(
                        H3StateReasonKind::Stopped {
                            cause: H3StopCause::BudgetLimit,
                        },
                        vec![RequiredAction::ResumeCycle],
                    )?,
                    detail: "the H2 cycle budget is exhausted".to_owned(),
                });
            }
        }
        Ok(AuthoringGate::Allowed {
            h2: Self::h2(&record)?,
            target_version,
        })
    }

    fn start(&mut self, request: &OwnerStartRequest) -> Result<OwnerStarted, H3Error> {
        let project = request.job().project_id();
        let supervision = request.job().supervision_id();
        let (handle, storage) = self.open_candidate(request)?;
        self.install_candidate_port();
        let authority = self.authority(project, supervision, request.job())?;
        let expected = self.record(project, supervision)?.revision();
        self.supervision.bind_owner_instruction(
            project,
            supervision,
            expected,
            request.brief().instruction(),
            &authority,
        )?;
        let plans = self.supervision.plans();
        let mut adapter = DesktopH1::new(self.runtime, self.store.clone(), plans);
        adapter.set_candidate_artifact(Some(handle.clone()));
        self.supervision.start_approved_owner(
            &mut adapter,
            authority,
            SupervisionRequestId::new(project),
            expected,
        )?;
        self.started(request.generation(), handle, storage, project, supervision)
    }

    fn poll(&mut self, active: &ActiveOwner) -> Result<OwnerProgress, H3Error> {
        let state = self
            .runtime
            .run(active.job().project_id(), active.run())
            .map_err(|error| H3Error::Unavailable {
                capability: "h1.run".to_owned(),
                detail: error.to_string(),
            })?
            .state();
        match state {
            RunState::Running => Ok(OwnerProgress::Running),
            RunState::AwaitingApproval => Ok(OwnerProgress::WaitingHuman {
                cause: HumanWaitCause::PermissionDenied,
                detail: "the candidate run is awaiting a human permission decision".to_owned(),
            }),
            RunState::Idle => match self.read_candidate(active) {
                Ok(candidate) => Ok(OwnerProgress::Authored(candidate)),
                Err(error) => Ok(OwnerProgress::Failed {
                    cause: H3FailureCause::CandidateRejected,
                    detail: error.to_string(),
                }),
            },
            RunState::Paused => Ok(OwnerProgress::Stopped {
                latch: Some(CycleLatch::HumanStop),
                reason: H3Reason::new(
                    H3StateReasonKind::Stopped {
                        cause: H3StopCause::HumanRequest,
                    },
                    vec![RequiredAction::ResumeCycle],
                )?,
                detail: "the candidate run is paused".to_owned(),
            }),
            RunState::Interrupted => Ok(OwnerProgress::Stopped {
                latch: Some(CycleLatch::RecoveryReconciliation),
                reason: H3Reason::new(
                    H3StateReasonKind::Stopped {
                        cause: H3StopCause::StopUnconfirmed,
                    },
                    vec![RequiredAction::ReconcileRecovery],
                )?,
                detail: "the candidate run was interrupted without a confirmed stop".to_owned(),
            }),
            RunState::Failed => Ok(OwnerProgress::Failed {
                cause: H3FailureCause::TargetUnstable,
                detail: "the candidate run failed".to_owned(),
            }),
        }
    }

    fn request_stop(&mut self, active: &ActiveOwner) -> Result<StopOutcome, H3Error> {
        let outcome = self
            .runtime
            .stop_run(
                active.job().project_id(),
                active.run(),
                StopReason::UserRequest,
            )
            .map_err(|error| H3Error::Unavailable {
                capability: "h1.stop".to_owned(),
                detail: error.to_string(),
            })?;
        Ok(match outcome.report() {
            herness_core::StopReport::Stopped | herness_core::StopReport::NotRunning => {
                StopOutcome::Confirmed
            }
            herness_core::StopReport::Unconfirmed => StopOutcome::Unconfirmed,
        })
    }

    fn supersede(&mut self, request: &OwnerSupersedeRequest) -> Result<OwnerStarted, H3Error> {
        let project = request.job().project_id();
        let supervision = request.job().supervision_id();
        // A source change advances the H2 target version. The human H3 range
        // approval already covers the exact Target set; reissue the purpose
        // consents for that same set at the new target version and record it.
        // Any target/kind/origin expansion is refused before the supersession.
        self.reissue_range_consent(project, supervision, request.target_version())?;
        let (handle, storage) = self.open_candidate_for(
            request.document(),
            request.job(),
            request.handle(),
            request.snapshot(),
        )?;
        self.install_candidate_port();
        let old_authority = self.authority(project, supervision, request.job())?;
        let expected = self.record(project, supervision)?.revision();
        let supersede = SupersedeSupervisionRequest {
            request_id: SupervisionRequestId::new(project),
            supervision_id: supervision,
            expected_revision: expected,
            target_version: request.target_version(),
            conditions: None,
            condition_version: None,
            profile_purpose: None,
            consent_purpose: Some(ProfilePurpose::Completion),
            budget: None,
            settings_version: request.job().settings_version(),
            job_id: request.job().job_label().to_owned(),
            packet_instruction: Some(request.brief().instruction().to_owned()),
        };
        let plans = self.supervision.plans();
        let mut adapter = DesktopH1::new(self.runtime, self.store.clone(), plans);
        adapter.set_candidate_artifact(Some(handle.clone()));
        self.supervision.supersede_approved_owner(
            &mut adapter,
            self.registry,
            old_authority,
            supersede,
        )?;
        self.started(request.generation(), handle, storage, project, supervision)
    }
}
