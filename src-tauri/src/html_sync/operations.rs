//! Desktop composition of H3 conflict, adoption, restore, and orphan handling.
//!
//! This module is host-only. It supplies the real project read boundary, the
//! Common SDD structural/semantic/SVG validation, the private history archive
//! reader, and the existing Task 19 publication writer. It performs no Git or
//! deletion operation: source removal only records `orphaned` and returns the
//! retained companion plus the remaining approved paths.
//!
//! Adoption and explicit replacement still run the full publication path. The
//! host never treats a structural-only check as adoption evidence: the caller
//! must also supply a current completion-ready H2 evaluation bound to the exact
//! external HTML.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use herness_core::{ExpectedTargetVersion, ProjectId, RunControl, Timestamp};
use herness_html_sync::{
    AdoptionOutcome, AdoptionPreparation, CandidatePublication, CurrentHtmlAdoption,
    CurrentHtmlValidation, DocumentKey, GenerationId, H3DocumentRecord, H3Error,
    H3OperationRequest, H3StorePort, HistoryReadPort, HistoryRestoreOutcome, HistoryVersion,
    PublicationFileInput, PublicationFileReadPort, PublicationId, PublicationWriteExpectationPort,
    SourceJobControlPort, SourceRemovalOutcome, prepare_adoption,
    record_external_html_conflict as record_conflict_state,
    record_source_removal as record_removal_state,
};
use herness_supervision::ContentDigest;
use serde::Deserialize;

use crate::html_sync::policy::{CandidateDecision, CandidateStage, ConnectedPolicyBridge};
use crate::html_sync::publish::{
    DesktopPublisher, PolicyFinalCheck, ProjectPublicationFiles, SharedHistoryArchive,
};
use crate::supervision::store::StoreHandle;

const ARCHIVE_FORMAT: u32 = 1;
const MAX_ARCHIVE_ENTRY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArchivedEntry {
    format: u32,
    project_id: ProjectId,
    #[allow(dead_code)]
    request_id: herness_core::PublicationRequestId,
    target: String,
    version: String,
    content: String,
}

/// Reads complete historical pairs from the shared private archive.
///
/// A generation may still be the current formal pair; in that case the exact
/// formal bytes are used. Otherwise both the HTML and receipt entries must exist
/// in the archive for the exact generation and match its published journal.
#[derive(Clone)]
pub struct PrivateHistoryReader {
    root: PathBuf,
    store: StoreHandle,
    files: ProjectPublicationFiles,
}

impl PrivateHistoryReader {
    /// Creates a reader over one private archive root.
    pub fn new(
        archive_root: impl AsRef<Path>,
        store: StoreHandle,
        files: ProjectPublicationFiles,
    ) -> Result<Self, H3Error> {
        let root =
            SharedHistoryArchive::new(archive_root.as_ref()).map_err(|error| H3Error::Storage {
                detail: format!("the private history archive is unavailable: {error}"),
            })?;
        Ok(Self {
            root: root.root().to_path_buf(),
            store,
            files,
        })
    }
}

impl HistoryReadPort for PrivateHistoryReader {
    fn load_version(
        &self,
        document: &DocumentKey,
        generation: GenerationId,
    ) -> Result<Option<HistoryVersion>, H3Error> {
        let generations = self
            .store
            .html_sync_generations(document.project_id(), document)?;
        let Some(selected) = generations
            .into_iter()
            .find(|record| record.generation_id() == generation)
        else {
            return Ok(None);
        };
        let Some(candidate) = selected.candidate() else {
            return Ok(None);
        };
        let journal = match selected.publication() {
            Some(publication) => self
                .store
                .load_html_sync_publication(document.project_id(), publication)?,
            None => self
                .store
                .list_html_sync_publications(document.project_id(), document)?
                .into_iter()
                .find(|journal| {
                    journal.generation_id() == selected.generation_id()
                        && journal.status() == herness_html_sync::PublicationStatus::Published
                }),
        };
        let Some(journal) = journal else {
            return Ok(None);
        };
        let Some(receipt_digest) = journal.receipt_digest() else {
            return Ok(None);
        };
        let html_path = document.companion_path();
        let receipt_path = herness_html_sync::html_evidence_path(document);

        if let (Some(html), Some(receipt)) = (
            self.files.read(&html_path)?,
            self.files.read(&receipt_path)?,
        ) && ContentDigest::sha256(&html) == *candidate.html_digest()
            && ContentDigest::sha256(&receipt) == *receipt_digest
        {
            return Ok(Some(HistoryVersion::new(
                document,
                generation,
                PublicationFileInput::new(html_path, html)?,
                PublicationFileInput::new(receipt_path, receipt)?,
            )?));
        }

        let entries = self.read_entries(document.project_id())?;
        let html = find_entry(&entries, &html_path, candidate.html_digest())?;
        let receipt = find_entry(&entries, &receipt_path, receipt_digest)?;
        match (html, receipt) {
            (Some(html), Some(receipt)) => Ok(Some(HistoryVersion::new(
                document,
                generation,
                PublicationFileInput::new(html_path, html)?,
                PublicationFileInput::new(receipt_path, receipt)?,
            )?)),
            _ => Ok(None),
        }
    }
}

impl PrivateHistoryReader {
    fn read_entries(&self, project: ProjectId) -> Result<Vec<ArchivedEntry>, H3Error> {
        let directory = self.root.join(project.to_string());
        match fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(H3Error::Storage {
                    detail: "the private history project directory is a symlink".to_owned(),
                });
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(H3Error::Storage {
                    detail: "the private history project path is not a directory".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(H3Error::Storage {
                    detail: format!("the private history directory could not be read: {error}"),
                });
            }
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|error| H3Error::Storage {
            detail: format!("the private history directory could not be listed: {error}"),
        })? {
            let entry = entry.map_err(|error| H3Error::Storage {
                detail: format!("a private history entry could not be read: {error}"),
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| H3Error::Storage {
                detail: format!("a private history entry could not be inspected: {error}"),
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.len() > MAX_ARCHIVE_ENTRY_BYTES as u64 {
                continue;
            }
            let bytes = fs::read(&path).map_err(|error| H3Error::Storage {
                detail: format!("a private history entry could not be read: {error}"),
            })?;
            let archived: ArchivedEntry =
                serde_json::from_slice(&bytes).map_err(|error| H3Error::Corrupt {
                    record: "history archive entry",
                    detail: error.to_string(),
                })?;
            if archived.format != ARCHIVE_FORMAT {
                return Err(H3Error::Corrupt {
                    record: "history archive entry",
                    detail: "unknown archive format".to_owned(),
                });
            }
            if archived.project_id != project {
                continue;
            }
            entries.push(archived);
        }
        Ok(entries)
    }
}

fn find_entry(
    entries: &[ArchivedEntry],
    target: &str,
    digest: &ContentDigest,
) -> Result<Option<Vec<u8>>, H3Error> {
    let mut found: Option<Vec<u8>> = None;
    for entry in entries
        .iter()
        .filter(|entry| entry.target == target && entry.version == digest.as_str())
    {
        let bytes = entry.content.as_bytes().to_vec();
        if ContentDigest::sha256(&bytes) != *digest {
            return Err(H3Error::Corrupt {
                record: "history archive content",
                detail: format!("the archive entry for {target} does not match its digest"),
            });
        }
        if found.as_ref().is_some_and(|existing| existing != &bytes) {
            return Err(H3Error::Corrupt {
                record: "history archive entry",
                detail: format!("conflicting archive entries for {target}"),
            });
        }
        found = Some(bytes);
    }
    Ok(found)
}

/// Validates the exact current HTML with the real Common SDD policy.
///
/// The structural stage also performs the semantic source-unit mapping and
/// SVG/figure policy checks. A structural pass is never a final publication
/// pass; adoption additionally requires a current all-met evaluation and the
/// normal final validation inside the publication path.
pub fn validate_current_html(
    bridge: &ConnectedPolicyBridge,
    document: &DocumentKey,
    source: &[u8],
    html: &[u8],
    css: &[PublicationFileInput],
    resources: &[PublicationFileInput],
) -> Result<CurrentHtmlValidation, H3Error> {
    let mut inputs = BTreeMap::new();
    inputs.insert(document.target_path().to_owned(), source.to_vec());
    inputs.insert(document.companion_path(), html.to_vec());
    for input in css.iter().chain(resources.iter()) {
        inputs.insert(input.path().to_owned(), input.bytes().to_vec());
    }
    let check = bridge
        .candidate_check(
            document.companion_path().as_str(),
            CandidateStage::Structural,
            None,
            &inputs,
        )
        .map_err(|error| H3Error::Unavailable {
            capability: "h3.adoption.structural".to_owned(),
            detail: error.to_string(),
        })?;
    let violations = check
        .violations()
        .iter()
        .map(|finding| format!("{}: {}", finding.code(), finding.message()))
        .collect::<Vec<_>>();
    let passed = check.decision() == CandidateDecision::Allow
        && check.contract() == herness_html_sync::RECEIPT_CONTRACT
        && violations.is_empty();
    CurrentHtmlValidation::new(
        ContentDigest::sha256(html),
        ContentDigest::sha256(source),
        check.contract(),
        passed,
        passed,
        passed,
        violations,
        "sdd-html-host-api:structural",
        "python -B scripts/html-docs host-api (structural candidate-check)",
        Timestamp::now(),
    )
}

/// Desktop composition for H3 conflict, adoption, restore, and orphan commands.
pub struct DesktopHtmlSyncOperations {
    store: StoreHandle,
    files: ProjectPublicationFiles,
    history: PrivateHistoryReader,
    publisher: DesktopPublisher,
}

impl DesktopHtmlSyncOperations {
    /// Creates the host operation set for one open project.
    pub fn new(
        project: ProjectId,
        project_root: impl AsRef<Path>,
        store: StoreHandle,
        archive_root: impl AsRef<Path>,
        bridge: ConnectedPolicyBridge,
        control: RunControl,
    ) -> Result<Self, H3Error> {
        Self::from_shared(
            project,
            project_root,
            store,
            archive_root,
            Arc::new(bridge),
            control,
        )
    }

    /// Creates the host operation set over the app-lifetime verified bridge.
    pub fn from_shared(
        project: ProjectId,
        project_root: impl AsRef<Path>,
        store: StoreHandle,
        archive_root: impl AsRef<Path>,
        bridge: Arc<ConnectedPolicyBridge>,
        control: RunControl,
    ) -> Result<Self, H3Error> {
        let files = ProjectPublicationFiles::new(project_root.as_ref())?;
        let history =
            PrivateHistoryReader::new(archive_root.as_ref(), store.clone(), files.clone())?;
        let publisher = DesktopPublisher::new(
            project,
            project_root.as_ref(),
            store.clone(),
            archive_root.as_ref(),
            PolicyFinalCheck::shared(bridge),
            control,
        )?;
        Ok(Self {
            store,
            files,
            history,
            publisher,
        })
    }

    /// The verified policy connection.
    pub fn bridge(&self) -> &ConnectedPolicyBridge {
        self.publisher.bridge()
    }

    /// Records an external companion/receipt change without overwriting it.
    pub fn record_conflict(
        &self,
        record: &H3DocumentRecord,
        observed: Option<&ContentDigest>,
        now: Timestamp,
    ) -> Result<H3DocumentRecord, H3Error> {
        let mut store = self.store.clone();
        record_conflict_state(&mut store, record, observed, now)
    }

    /// Validates the exact current HTML with the real pack.
    pub fn validate_current_html(
        &self,
        document: &DocumentKey,
        source: &[u8],
        html: &[u8],
        css: &[PublicationFileInput],
        resources: &[PublicationFileInput],
    ) -> Result<CurrentHtmlValidation, H3Error> {
        validate_current_html(self.bridge(), document, source, html, css, resources)
    }

    /// Adopts the current external HTML after exact validation and evaluation.
    pub fn adopt_current_html(
        &mut self,
        adoption: CurrentHtmlAdoption,
        expectations: &mut dyn PublicationWriteExpectationPort,
        now: Timestamp,
    ) -> Result<AdoptionOutcome, H3Error> {
        // Never trust a caller-supplied summary on the host path: re-run the
        // real Common SDD structural, semantic, and SVG/figure validation over
        // the exact supplied bytes before preparation.
        let validation = self.validate_current_html(
            adoption.document(),
            adoption.source_bytes(),
            adoption.candidate_html().as_bytes(),
            adoption.css(),
            adoption.resources(),
        )?;
        let adoption = adoption.with_validation(validation);
        let mut store = self.store.clone();
        let prepared = prepare_adoption(&mut store, &self.files, adoption, now)?;
        match prepared {
            AdoptionPreparation::Ready(attempt) => self
                .publisher
                .publish(*attempt, expectations, now)
                .map(AdoptionOutcome::Adopted),
            AdoptionPreparation::WaitingHuman { cause, detail } => {
                Ok(AdoptionOutcome::WaitingHuman { cause, detail })
            }
            AdoptionPreparation::NotApplicable { detail } => {
                Ok(AdoptionOutcome::NotApplicable { detail })
            }
            AdoptionPreparation::Conflict { target, detail } => {
                Ok(AdoptionOutcome::Conflict { target, detail })
            }
        }
    }

    /// Publishes one evaluated candidate through the Task 19 orchestrator.
    pub fn publish(
        &mut self,
        attempt: CandidatePublication,
        expectations: &mut dyn PublicationWriteExpectationPort,
        now: Timestamp,
    ) -> Result<herness_html_sync::PublicationOutcome, H3Error> {
        self.publisher.publish(attempt, expectations, now)
    }

    /// Publishes one explicit regenerated replacement through Task 19.
    pub fn replace_with_regenerated(
        &mut self,
        attempt: CandidatePublication,
        expectations: &mut dyn PublicationWriteExpectationPort,
        now: Timestamp,
    ) -> Result<herness_html_sync::PublicationOutcome, H3Error> {
        self.publisher.replace_explicit(attempt, expectations, now)
    }

    /// Restores one historical pair with history-before-replacement ordering.
    pub fn restore_history(
        &mut self,
        request: &H3OperationRequest,
        publication: PublicationId,
        expected_html: &ExpectedTargetVersion,
        expected_receipt: &ExpectedTargetVersion,
        now: Timestamp,
    ) -> Result<HistoryRestoreOutcome, H3Error> {
        self.publisher.restore(
            request,
            publication,
            expected_html,
            expected_receipt,
            &self.history,
            now,
        )
    }

    /// Records a deleted/moved Markdown source. No file is moved or deleted.
    pub fn record_source_removal(
        &self,
        request: &H3OperationRequest,
        controls: &mut dyn SourceJobControlPort,
        remaining_targets: &[String],
        now: Timestamp,
    ) -> Result<SourceRemovalOutcome, H3Error> {
        let mut store = self.store.clone();
        record_removal_state(&mut store, controls, request, remaining_targets, now)
    }

    /// The private history reader bound to this project archive.
    pub const fn history_reader(&self) -> &PrivateHistoryReader {
        &self.history
    }
}
