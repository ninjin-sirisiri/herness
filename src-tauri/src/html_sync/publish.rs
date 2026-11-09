//! Desktop composition of the H3 publication path.
//!
//! The pure H3 orchestrator decides what may be published and records the
//! journal. This module supplies the real project read boundary, the Common SDD
//! final `candidate-check` through the existing policy bridge, the H2 budget and
//! consent re-check, the private old-version archive, the observer's expected
//! write registration, and the H1 host-only single-file `PublicationWriter`.
//!
//! Nothing here is a model tool, a tool argument, or an IPC command. The H1
//! writer replaces one file per request; the H3 journal records the two-file
//! sequence.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use herness_core::{
    ArchivedVersion, EventDraft, ExpectedTargetVersion, OldVersionArchive, ProjectId, ProjectRoot,
    PublicationFailure, PublicationRecord, PublicationRequest, RunControl, Timestamp,
};
use herness_core::ports::publish::{
    PublicationArchivePort, PublicationGatePort, PublicationRecordPort,
};
use herness_core::runtime::{PrivateAppArchive, PublicationWriter};
use herness_html_sync::{
    CandidatePublication, ExpectedPublicationWrite, FilesystemSourceReader,
    FinalCandidateCheck, FinalCandidateCheckPort, FinalCandidateCheckRequest, H3Error,
    H3OperationRequest, H3StorePort, HistoryReadPort, HistoryRestoreOutcome, ObservationClock,
    ProjectObserver, PublicationFileReadPort, PublicationId, PublicationOrchestrator,
    PublicationOutcome, PublicationSafety, PublicationSafetyPort, PublicationSafetyRequest,
    PublicationWriteExpectationPort, SourceReadError, SourceReadPort, replace_with_regenerated,
    restore_history,
};
use herness_supervision::TargetVersion;
use herness_supervision::profiles::ProfileBinding;

use crate::html_sync::policy::{CandidateDecision, CandidateStage, ConnectedPolicyBridge};
use crate::supervision::store::StoreHandle;

/// Exact project file reads through the observer's canonical reader.
#[derive(Debug, Clone)]
pub struct ProjectPublicationFiles {
    root: PathBuf,
    reader: FilesystemSourceReader,
}

impl ProjectPublicationFiles {
    /// Opens one canonical project root.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, H3Error> {
        let reader = FilesystemSourceReader::new(root.as_ref())?;
        let canonical = fs::canonicalize(root.as_ref()).map_err(|error| H3Error::Unavailable {
            capability: "h3.publication.read".to_owned(),
            detail: format!("the project root could not be canonicalized: {error}"),
        })?;
        Ok(Self {
            root: canonical,
            reader,
        })
    }
}

impl PublicationFileReadPort for ProjectPublicationFiles {
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, H3Error> {
        match self.reader.read(path) {
            Ok(read) => {
                if !read.is_stable() {
                    return Err(H3Error::Unavailable {
                        capability: "h3.publication.read".to_owned(),
                        detail: format!("the file {path} changed during its read"),
                    });
                }
                Ok(Some(read.bytes().to_vec()))
            }
            Err(SourceReadError::NotFound) => Ok(None),
            Err(error) => Err(H3Error::Unavailable {
                capability: "h3.publication.read".to_owned(),
                detail: format!("{}: {}", path, error.as_str()),
            }),
        }
    }

    fn ensure_parent(&self, path: &str) -> Result<(), H3Error> {
        let parent = Path::new(path).parent().ok_or_else(|| H3Error::invalid(
            "publicationPath",
            "the formal path has no parent",
        ))?;
        if parent.as_os_str().is_empty() {
            return Ok(());
        }
        if parent.is_absolute()
            || parent
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(H3Error::invalid(
                "publicationPath",
                "the formal parent directory must stay inside the project",
            ));
        }
        let directory = self.root.join(parent);
        // Reject an existing symlink component before creating anything.
        let mut current = self.root.clone();
        for component in parent.components() {
            current.push(component.as_os_str());
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(H3Error::invalid(
                        "publicationPath",
                        "the formal parent directory contains a symlink",
                    ));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(H3Error::invalid(
                        "publicationPath",
                        "the formal parent path is not a directory",
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(H3Error::Unavailable {
                        capability: "h3.publication.read".to_owned(),
                        detail: format!("the formal parent could not be inspected: {error}"),
                    });
                }
            }
        }
        fs::create_dir_all(&directory).map_err(|error| H3Error::Unavailable {
            capability: "h3.publication.read".to_owned(),
            detail: format!("the formal parent directory could not be created: {error}"),
        })?;
        let canonical = fs::canonicalize(&directory).map_err(|error| H3Error::Unavailable {
            capability: "h3.publication.read".to_owned(),
            detail: format!("the formal parent directory could not be verified: {error}"),
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(H3Error::invalid(
                "publicationPath",
                "the formal parent directory escapes the project root",
            ));
        }
        Ok(())
    }
}

/// Common SDD final `candidate-check` over exact supplied bytes.
#[derive(Debug)]
pub struct PolicyFinalCheck {
    bridge: Arc<ConnectedPolicyBridge>,
}

impl PolicyFinalCheck {
    /// Uses one already-verified policy connection.
    pub fn new(bridge: ConnectedPolicyBridge) -> Self {
        Self {
            bridge: Arc::new(bridge),
        }
    }

    /// Uses the app-lifetime verified connection without reconnecting.
    pub fn shared(bridge: Arc<ConnectedPolicyBridge>) -> Self {
        Self { bridge }
    }

    /// The verified connection.
    pub fn bridge(&self) -> &ConnectedPolicyBridge {
        self.bridge.as_ref()
    }
}

impl FinalCandidateCheckPort for PolicyFinalCheck {
    fn check(
        &self,
        request: &FinalCandidateCheckRequest<'_>,
    ) -> Result<FinalCandidateCheck, H3Error> {
        let mut inputs = BTreeMap::new();
        inputs.insert(request.source_path.to_owned(), request.source.to_vec());
        inputs.insert(request.html_path.to_owned(), request.html.to_vec());
        inputs.insert(
            request.receipt_path.to_owned(),
            request.receipt.as_bytes().to_vec(),
        );
        for input in request.css.iter().chain(request.resources.iter()) {
            inputs.insert(input.path().to_owned(), input.bytes().to_vec());
        }
        let result = self
            .bridge
            .candidate_check(
                request.html_path,
                CandidateStage::Final,
                Some(request.receipt_path),
                &inputs,
            )
            .map_err(|error| H3Error::Unavailable {
                capability: "h3.policy.final".to_owned(),
                detail: error.to_string(),
            })?;
        Ok(FinalCandidateCheck {
            allowed: result.decision() == CandidateDecision::Allow,
            final_pass: result.final_pass(),
            final_binding: result.final_binding(),
            contract: result.contract().to_owned(),
            violations: result
                .violations()
                .iter()
                .map(|finding| format!("{}: {}", finding.code(), finding.message()))
                .collect(),
        })
    }
}

/// H3 approval, consent, stop, and H2 budget re-check.
#[derive(Clone)]
pub struct H3PublicationSafety {
    store: StoreHandle,
    control: RunControl,
}

impl H3PublicationSafety {
    /// Creates the safety port over the shared H3/H2 store and stop control.
    pub const fn new(store: StoreHandle, control: RunControl) -> Self {
        Self { store, control }
    }
}

impl PublicationSafetyPort for H3PublicationSafety {
    fn recheck(
        &self,
        request: &PublicationSafetyRequest<'_>,
    ) -> Result<PublicationSafety, H3Error> {
        let project = request.document.project_id();
        let settings = self
            .store
            .load_html_sync_settings(project)?
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h3.publication.approval".to_owned(),
                detail: "the project has no stored H3 settings".to_owned(),
            })?;
        let settings = settings.settings();
        let approval_current = settings.verify_fingerprint()
            && settings.version() == request.settings.version()
            && settings
                .approval()
                .is_some_and(|approval| approval.is_current_at(request.now));
        let consent_current = settings.approval().is_some_and(|approval| {
            let consent = approval.assessment().consent();
            consent.purpose() == herness_supervision::ProfilePurpose::Html
                && consent.target_scope_version() == request.target_version
                && approval.assessment().profile() == request.profile
        });
        let budget_remaining = match request.generation.h2() {
            Some(h2) => {
                let record = self
                    .store
                    .lock()
                    .load_budget_record(project, h2.supervision_id())
                    .map_err(|error| H3Error::Storage {
                        detail: format!("the H2 budget could not be read: {error}"),
                    })?;
                record.is_some_and(|record| {
                    let policy = record.record().policy();
                    let usage = record.record().usage();
                    usage.remaining_active_seconds(policy) > 0 && usage.within_money_cap(policy)
                })
            }
            None => false,
        };
        Ok(PublicationSafety {
            stop_requested: !self.control.permits_side_effect(),
            consent_current,
            approval_current,
            budget_remaining,
        })
    }
}

/// Observer-backed expected publication write registration.
///
/// Before retiring an expectation after the journal commit, the adapter reports
/// the two expected paths to the observer and scans them. That consumes the
/// self-notification while the exact expected bytes are still registered, so a
/// delayed watcher event after the commit is not misclassified as an external
/// edit. The resulting companion observations are kept for the host pump via
/// [`Self::take_companions`].
pub struct ObserverWriteExpectations<'a, R: SourceReadPort, C: ObservationClock> {
    observer: &'a mut ProjectObserver<R, C>,
    expected: Vec<ExpectedPublicationWrite>,
    companions: Vec<herness_html_sync::CompanionObservation>,
    sources: Vec<herness_html_sync::SourceObservation>,
    uncertainties: Vec<herness_html_sync::ObservationUncertainty>,
}

impl<'a, R: SourceReadPort, C: ObservationClock> ObserverWriteExpectations<'a, R, C> {
    /// Wraps one project observer.
    pub fn new(observer: &'a mut ProjectObserver<R, C>) -> Self {
        Self {
            observer,
            expected: Vec::new(),
            companions: Vec::new(),
            sources: Vec::new(),
            uncertainties: Vec::new(),
        }
    }

    /// Returns the observer after publication.
    pub fn into_inner(self) -> &'a mut ProjectObserver<R, C> {
        self.observer
    }

    /// Companion observations produced while retiring expectations.
    pub fn take_companions(&mut self) -> Vec<herness_html_sync::CompanionObservation> {
        std::mem::take(&mut self.companions)
    }

    /// Source observations produced while retiring expectations.
    pub fn take_sources(&mut self) -> Vec<herness_html_sync::SourceObservation> {
        std::mem::take(&mut self.sources)
    }

    /// Uncertainty results produced while retiring expectations.
    pub fn take_uncertainties(
        &mut self,
    ) -> Vec<herness_html_sync::ObservationUncertainty> {
        std::mem::take(&mut self.uncertainties)
    }
}

impl<R: SourceReadPort, C: ObservationClock> PublicationWriteExpectationPort
    for ObserverWriteExpectations<'_, R, C>
{
    fn expect(&mut self, write: ExpectedPublicationWrite) -> Result<(), H3Error> {
        self.observer.expect_publication_write(write.clone())?;
        self.expected.push(write);
        Ok(())
    }

    fn retire(&mut self, publication: herness_html_sync::PublicationId) {
        let Some(expected) = self
            .expected
            .iter()
            .find(|write| write.publication() == publication)
            .cloned()
        else {
            return;
        };
        self.expected
            .retain(|write| write.publication() != publication);
        let html = expected.document().companion_path();
        let receipt = herness_html_sync::html_evidence_path(expected.document());
        if let Ok(signal) = herness_html_sync::ChangeSignal::new(
            html,
            herness_html_sync::ChangeSource::FilesystemWatcher,
        ) {
            self.observer.notify(signal);
        }
        if let Ok(signal) = herness_html_sync::ChangeSignal::new(
            receipt,
            herness_html_sync::ChangeSource::FilesystemWatcher,
        ) {
            self.observer.notify(signal);
        }
        let tick = self.observer.poll();
        self.companions.extend(tick.companions);
        self.sources.extend(tick.sources);
        self.uncertainties.extend(tick.uncertainties);
        self.observer.retire_publication_write(publication);
    }
}

/// Private archive shared by the H3 pre-save and the H1 writer.
///
/// Both sides use the same root. Saving an identical request/content pair is
/// idempotent; a different archive entry for the same request is refused.
#[derive(Debug, Clone)]
pub struct SharedHistoryArchive {
    root: PathBuf,
}

impl SharedHistoryArchive {
    /// Creates an archive under one host-supplied private app root.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, PublicationFailure> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(PublicationFailure::ArchiveUnavailable {
                detail: "the private history root is empty".to_owned(),
            });
        }
        if !root.is_absolute() {
            return Err(PublicationFailure::ArchiveUnavailable {
                detail: "the private history root must be absolute".to_owned(),
            });
        }
        // Creating and validating the root here catches an unusable private
        // area before the journal intent is persisted.
        let archive = PrivateAppArchive::new(&root)?;
        Ok(Self {
            root: archive.root().to_path_buf(),
        })
    }

    /// Canonical private root.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl PublicationArchivePort for SharedHistoryArchive {
    fn save_old_version(
        &mut self,
        archive: &OldVersionArchive<'_>,
    ) -> Result<ArchivedVersion, PublicationFailure> {
        let mut inner = PrivateAppArchive::new(&self.root)?;
        inner.save_old_version(archive)
    }
}

/// H1 publication record store over the shared process-wide store.
#[derive(Clone)]
pub struct H3PublicationRecords {
    store: StoreHandle,
}

impl H3PublicationRecords {
    /// Wraps the shared store handle.
    pub const fn new(store: StoreHandle) -> Self {
        Self { store }
    }
}

impl PublicationRecordPort for H3PublicationRecords {
    fn load_publication(
        &self,
        key: &str,
    ) -> Result<Option<PublicationRecord>, PublicationFailure> {
        let bytes = self
            .store
            .lock()
            .load_host_state(key)
            .map_err(|error| PublicationFailure::RecordUnavailable {
                detail: error.to_string(),
            })?;
        match bytes {
            Some(bytes) => PublicationRecord::from_bytes(&bytes).map(Some),
            None => Ok(None),
        }
    }

    fn save_publication(
        &mut self,
        key: &str,
        record: &PublicationRecord,
        events: Vec<EventDraft>,
    ) -> Result<herness_core::CommitReceipt, PublicationFailure> {
        let bytes = record.to_bytes()?;
        self.store
            .lock()
            .save_host_state_and_events(key, &bytes, events)
            .map_err(|error| PublicationFailure::RecordUnavailable {
                detail: error.to_string(),
            })
    }
}

/// H1 gate re-check immediately before each rename.
struct H3PublicationGate<'a> {
    store: StoreHandle,
    safety: &'a dyn PublicationSafetyPort,
    control: RunControl,
    document: herness_html_sync::DocumentKey,
    generation: herness_html_sync::GenerationRecord,
    target_version: TargetVersion,
    profile: ProfileBinding,
}

impl PublicationGatePort for H3PublicationGate<'_> {
    fn authorize_publication(
        &self,
        _request: &PublicationRequest,
    ) -> Result<(), PublicationFailure> {
        if !self.control.permits_side_effect() {
            return Err(PublicationFailure::PermissionDenied {
                detail: "the host stop or deadline is set".to_owned(),
            });
        }
        let settings = self
            .store
            .load_html_sync_settings(self.document.project_id())
            .map_err(|error| PublicationFailure::PermissionDenied {
                detail: format!("the H3 settings could not be re-read: {error}"),
            })?
            .ok_or_else(|| PublicationFailure::PermissionDenied {
                detail: "the project has no stored H3 settings".to_owned(),
            })?;
        let safety = self
            .safety
            .recheck(&PublicationSafetyRequest {
                document: &self.document,
                generation: &self.generation,
                settings: settings.settings(),
                target_version: self.target_version,
                profile: self.profile,
                now: Timestamp::now(),
            })
            .map_err(|error| PublicationFailure::PermissionDenied {
                detail: error.to_string(),
            })?;
        if safety.permits_publication() {
            Ok(())
        } else {
            Err(PublicationFailure::PermissionDenied {
                detail: "the H3 consent, approval, stop, or budget re-check denied publication"
                    .to_owned(),
            })
        }
    }
}

/// Desktop H3 publisher composing all host boundaries.
pub struct DesktopPublisher {
    project: ProjectId,
    project_root: PathBuf,
    files: ProjectPublicationFiles,
    store: StoreHandle,
    archive_root: PathBuf,
    final_check: PolicyFinalCheck,
    safety: H3PublicationSafety,
    control: RunControl,
}

impl DesktopPublisher {
    /// Creates the publisher for one project.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectId,
        project_root: impl AsRef<Path>,
        store: StoreHandle,
        archive_root: impl Into<PathBuf>,
        final_check: PolicyFinalCheck,
        control: RunControl,
    ) -> Result<Self, H3Error> {
        let canonical_project = fs::canonicalize(project_root.as_ref()).map_err(|error| {
            H3Error::invalid(
                "projectRoot",
                format!("the project root could not be canonicalized: {error}"),
            )
        })?;
        let archive_root = archive_root.into();
        let archive_probe = SharedHistoryArchive::new(&archive_root).map_err(|error| {
            H3Error::Storage {
                detail: format!("the private history archive is unavailable: {error}"),
            }
        })?;
        if archive_probe.root().starts_with(&canonical_project) {
            return Err(H3Error::invalid(
                "archiveRoot",
                "the private history root must be outside the project",
            ));
        }
        Ok(Self {
            project,
            project_root: project_root.as_ref().to_path_buf(),
            files: ProjectPublicationFiles::new(&project_root)?,
            safety: H3PublicationSafety::new(store.clone(), control.clone()),
            store,
            archive_root,
            final_check,
            control,
        })
    }

    /// The verified Common SDD policy connection used by this publisher.
    pub fn bridge(&self) -> &ConnectedPolicyBridge {
        self.final_check.bridge()
    }

    /// Runs one idempotent publication attempt.
    pub fn publish(
        &mut self,
        attempt: CandidatePublication,
        expectations: &mut dyn PublicationWriteExpectationPort,
        now: Timestamp,
    ) -> Result<PublicationOutcome, H3Error> {
        if attempt.document().project_id() != self.project {
            return Err(H3Error::CrossProject {
                id_kind: "publication".to_owned(),
                expected: self.project,
                found: attempt.document().project_id(),
            });
        }
        let target_version = attempt
            .applied()
            .binding()
            .post_verification()
            .target_version();
        let profile = attempt.applied().binding().post_verification().profile();
        let document = attempt.document().clone();
        let generation = attempt.generation().clone();
        self.with_orchestrator(
            &document,
            &generation,
            target_version,
            profile,
            expectations,
            |orchestrator| orchestrator.publish(attempt, now),
        )
    }

    /// Runs one explicit regenerated replacement through the H3 conflict rules.
    pub fn replace_explicit(
        &mut self,
        attempt: CandidatePublication,
        expectations: &mut dyn PublicationWriteExpectationPort,
        now: Timestamp,
    ) -> Result<PublicationOutcome, H3Error> {
        if attempt.document().project_id() != self.project {
            return Err(H3Error::CrossProject {
                id_kind: "publication".to_owned(),
                expected: self.project,
                found: attempt.document().project_id(),
            });
        }
        let target_version = attempt
            .applied()
            .binding()
            .post_verification()
            .target_version();
        let profile = attempt.applied().binding().post_verification().profile();
        let document = attempt.document().clone();
        let generation = attempt.generation().clone();
        self.with_orchestrator(
            &document,
            &generation,
            target_version,
            profile,
            expectations,
            |orchestrator| replace_with_regenerated(orchestrator, attempt, now),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_orchestrator<R>(
        &mut self,
        document: &herness_html_sync::DocumentKey,
        generation: &herness_html_sync::GenerationRecord,
        target_version: TargetVersion,
        profile: ProfileBinding,
        expectations: &mut dyn PublicationWriteExpectationPort,
        run: impl FnOnce(&mut PublicationOrchestrator<'_>) -> Result<R, H3Error>,
    ) -> Result<R, H3Error> {
        let mut archive = SharedHistoryArchive::new(&self.archive_root).map_err(|error| {
            H3Error::Storage {
                detail: format!("the private history archive is unavailable: {error}"),
            }
        })?;
        let gate = H3PublicationGate {
            store: self.store.clone(),
            safety: &self.safety,
            control: self.control.clone(),
            document: document.clone(),
            generation: generation.clone(),
            target_version,
            profile,
        };
        let mut writer = PublicationWriter::new(
            self.project,
            ProjectRoot::new(&self.project_root).map_err(|error| {
                H3Error::invalid("projectRoot", error.to_string())
            })?,
            H3PublicationRecords::new(self.store.clone()),
            archive.clone(),
            gate,
            self.control.clone(),
        )
        .map_err(|error| H3Error::invalid("publicationWriter", error.to_string()))?;
        let mut h3_store = self.store.clone();
        let mut orchestrator = PublicationOrchestrator {
            store: &mut h3_store,
            files: &self.files,
            archive: &mut archive,
            host: &mut writer,
            final_check: &self.final_check,
            safety: &self.safety,
            expectations,
            control: &self.control,
        };
        run(&mut orchestrator)
    }

    /// Restores one selected historical pair through the same host writer.
    ///
    /// The H3 restore orchestrator saves the current pair to history first and
    /// never marks the document synced. This method only supplies the real
    /// project read boundary, private archive, H1 writer, and safety gate.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        &mut self,
        request: &H3OperationRequest,
        publication: PublicationId,
        expected_html: &ExpectedTargetVersion,
        expected_receipt: &ExpectedTargetVersion,
        history: &dyn HistoryReadPort,
        now: Timestamp,
    ) -> Result<HistoryRestoreOutcome, H3Error> {
        let document = request
            .document()
            .cloned()
            .ok_or_else(|| H3Error::empty("document"))?;
        let herness_html_sync::H3Operation::RestoreHistory { generation } = request.operation()
        else {
            return Err(H3Error::invalid(
                "operation",
                "restore requires a RestoreHistory operation",
            ));
        };
        let settings = self
            .store
            .load_html_sync_settings(self.project)?
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h3.restore.settings".to_owned(),
                detail: "the project has no stored H3 settings".to_owned(),
            })?;
        let approval = settings
            .settings()
            .approval()
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h3.restore.approval".to_owned(),
                detail: "the project has no human configuration approval".to_owned(),
            })?;
        let target_version = approval.assessment().consent().target_scope_version();
        let profile = approval.assessment().profile();
        let selected_generation = self
            .store
            .lock()
            .html_sync_generations(document.project_id(), &document)?
            .into_iter()
            .find(|record| record.generation_id() == *generation)
            .ok_or_else(|| H3Error::NotFound {
                record: "generation",
                id: generation.to_string(),
            })?;
        let mut archive = SharedHistoryArchive::new(&self.archive_root).map_err(|error| {
            H3Error::Storage {
                detail: format!("the private history archive is unavailable: {error}"),
            }
        })?;
        let gate = H3PublicationGate {
            store: self.store.clone(),
            safety: &self.safety,
            control: self.control.clone(),
            document,
            generation: selected_generation,
            target_version,
            profile,
        };
        let mut writer = PublicationWriter::new(
            self.project,
            ProjectRoot::new(&self.project_root)
                .map_err(|error| H3Error::invalid("projectRoot", error.to_string()))?,
            H3PublicationRecords::new(self.store.clone()),
            archive.clone(),
            gate,
            self.control.clone(),
        )
        .map_err(|error| H3Error::invalid("publicationWriter", error.to_string()))?;
        let mut h3_store = self.store.clone();
        restore_history(
            &mut h3_store,
            &self.files,
            history,
            &mut archive,
            &mut writer,
            request,
            publication,
            expected_html,
            expected_receipt,
            now,
        )
    }
}
