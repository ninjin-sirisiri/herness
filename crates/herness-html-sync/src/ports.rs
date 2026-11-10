//! Durable H3 persistence boundary.
//!
//! `herness-html-sync` owns these versioned values and ports. `herness-store`
//! implements the port over transactional SQLite rows and the existing H1
//! event/project sequence. H3 never depends on rusqlite or the store crate.

use herness_core::{CommitReceipt, EventDraft, ProjectId};
use herness_supervision::ContentDigest;

use crate::document::DocumentKey;
use crate::error::H3Error;
use crate::ids::{CandidateId, CycleId, H3RequestId, PublicationId};
use crate::request::{H3OperationResult, RequestCommit, StoredRequestResult};
use crate::state::{
    CandidateRecord, GenerationRecord, H3DocumentState, H3DocumentStatus, H3Settings,
    PublicationJournal, SyncCycle,
};
use crate::version::decode_record;

/// One settings compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsCommit {
    expected_revision: Option<u64>,
    settings: H3Settings,
}

impl SettingsCommit {
    /// Creates a settings write against an observed revision.
    pub fn new(expected_revision: Option<u64>, settings: H3Settings) -> Result<Self, H3Error> {
        if expected_revision == Some(0) {
            return Err(H3Error::must_be_positive("expectedSettingsRevision"));
        }
        Ok(Self {
            expected_revision,
            settings,
        })
    }

    /// Revision the writer observed.
    pub const fn expected_revision(&self) -> Option<u64> {
        self.expected_revision
    }

    /// Next settings value.
    pub const fn settings(&self) -> &H3Settings {
        &self.settings
    }
}

/// One document compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentCommit {
    expected_revision: Option<u64>,
    document: H3DocumentState,
}

impl DocumentCommit {
    /// Creates a document write against an observed revision.
    pub fn new(
        expected_revision: Option<u64>,
        document: H3DocumentState,
    ) -> Result<Self, H3Error> {
        if expected_revision == Some(0) {
            return Err(H3Error::must_be_positive("expectedDocumentRevision"));
        }
        Ok(Self {
            expected_revision,
            document,
        })
    }

    /// Revision the writer observed.
    pub const fn expected_revision(&self) -> Option<u64> {
        self.expected_revision
    }

    /// Next document state.
    pub const fn document(&self) -> &H3DocumentState {
        &self.document
    }
}

/// One atomic H3 state commit.
///
/// A commit may update settings, one document, and related cycle, generation,
/// candidate, publication, and idempotent request records. Events are committed
/// in the same transaction and are visible only after the commit succeeds.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HtmlSyncCommit {
    settings: Option<SettingsCommit>,
    document: Option<DocumentCommit>,
    cycle: Option<SyncCycle>,
    generations: Vec<GenerationRecord>,
    candidate: Option<CandidateRecord>,
    publication: Option<PublicationJournal>,
    request: Option<RequestCommit>,
    events: Vec<EventDraft>,
}

impl HtmlSyncCommit {
    /// Creates an empty commit. At least one state change is required.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a settings write.
    pub fn with_settings(mut self, settings: SettingsCommit) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Adds a document write.
    pub fn with_document(mut self, document: DocumentCommit) -> Self {
        self.document = Some(document);
        self
    }

    /// Adds a cycle write.
    pub fn with_cycle(mut self, cycle: SyncCycle) -> Self {
        self.cycle = Some(cycle);
        self
    }

    /// Adds one generation history write. Multiple writes may atomically
    /// supersede an old generation and append the new one.
    pub fn with_generation(mut self, generation: GenerationRecord) -> Self {
        self.generations.push(generation);
        self
    }

    /// Adds a candidate metadata write.
    pub fn with_candidate(mut self, candidate: CandidateRecord) -> Self {
        self.candidate = Some(candidate);
        self
    }

    /// Adds a publication journal write.
    pub fn with_publication(mut self, publication: PublicationJournal) -> Self {
        self.publication = Some(publication);
        self
    }

    /// Adds an idempotent request result.
    pub fn with_request(mut self, request: RequestCommit) -> Self {
        self.request = Some(request);
        self
    }

    /// Adds events committed with this state.
    pub fn with_events(mut self, events: Vec<EventDraft>) -> Self {
        self.events = events;
        self
    }

    /// Settings write, when any.
    pub const fn settings(&self) -> Option<&SettingsCommit> {
        self.settings.as_ref()
    }

    /// Document write, when any.
    pub const fn document(&self) -> Option<&DocumentCommit> {
        self.document.as_ref()
    }

    /// Cycle write, when any.
    pub const fn cycle(&self) -> Option<&SyncCycle> {
        self.cycle.as_ref()
    }

    /// Generation writes in commit order.
    pub fn generations(&self) -> &[GenerationRecord] {
        &self.generations
    }

    /// Candidate write, when any.
    pub const fn candidate(&self) -> Option<&CandidateRecord> {
        self.candidate.as_ref()
    }

    /// Publication journal write, when any.
    pub const fn publication(&self) -> Option<&PublicationJournal> {
        self.publication.as_ref()
    }

    /// Idempotent request commit, when any.
    pub const fn request(&self) -> Option<&RequestCommit> {
        self.request.as_ref()
    }

    /// Events committed with the state.
    pub fn events(&self) -> &[EventDraft] {
        &self.events
    }

    /// Validates cross-record ownership and scope before any write.
    pub fn validate(&self) -> Result<(), H3Error> {
        let project = self
            .project_id()
            .ok_or_else(|| H3Error::invalid("commit", "the commit has no project"))?;
        let document_key = self.document_key();

        if let Some(settings) = &self.settings
            && settings.settings().project_id() != project
        {
            return Err(H3Error::CrossProject {
                id_kind: "settings".to_owned(),
                expected: project,
                found: settings.settings().project_id(),
            });
        }
        if let Some(key) = &document_key {
            key.validate_in(project)?;
        }
        if let Some(document) = &self.document {
            document.document().document_key().validate_in(project)?;
            if let Some(key) = &document_key
                && key != document.document().document_key()
            {
                return Err(H3Error::invalid(
                    "document",
                    "all records in one commit must address the same document",
                ));
            }
        }
        if self.settings.is_none()
            && self.document.is_none()
            && self.request.is_none()
            && self.cycle.is_none()
            && self.generations.is_empty()
            && self.candidate.is_none()
            && self.publication.is_none()
        {
            return Err(H3Error::invalid("commit", "the commit has no state change"));
        }
        if self.document.is_none()
            && (self.cycle.is_some()
                || !self.generations.is_empty()
                || self.candidate.is_some()
                || self.publication.is_some())
        {
            return Err(H3Error::invalid(
                "document",
                "document-scoped records require the matching document commit",
            ));
        }
        if let Some(key) = &document_key
            && Some(key) != self.document.as_ref().map(|document| document.document().document_key())
        {
            return Err(H3Error::invalid(
                "document",
                "document-scoped records require the matching document commit",
            ));
        }
        if let Some(cycle) = &self.cycle {
            if cycle.project_id() != project {
                return Err(H3Error::CrossProject {
                    id_kind: "cycle".to_owned(),
                    expected: project,
                    found: cycle.project_id(),
                });
            }
            if Some(cycle.document_key()) != document_key.as_ref() {
                return Err(H3Error::invalid(
                    "cycle",
                    "the cycle must address the commit document",
                ));
            }
        }
        for (index, generation) in self.generations.iter().enumerate() {
            if self.generations[..index]
                .iter()
                .any(|earlier| earlier.generation_id() == generation.generation_id())
            {
                return Err(H3Error::invalid(
                    "generations",
                    "one commit cannot write the same generation twice",
                ));
            }
            if self.generations[..index]
                .iter()
                .any(|earlier| earlier.generation() == generation.generation())
            {
                return Err(H3Error::invalid(
                    "generations",
                    "one commit cannot write two generations with the same number",
                ));
            }
            if generation.project_id() != project {
                return Err(H3Error::CrossProject {
                    id_kind: "generation".to_owned(),
                    expected: project,
                    found: generation.project_id(),
                });
            }
            if Some(generation.document_key()) != document_key.as_ref() {
                return Err(H3Error::invalid(
                    "generation",
                    "the generation must address the commit document",
                ));
            }
        }
        if let Some(candidate) = &self.candidate {
            if candidate.project_id() != project {
                return Err(H3Error::CrossProject {
                    id_kind: "candidate".to_owned(),
                    expected: project,
                    found: candidate.project_id(),
                });
            }
            if Some(candidate.document_key()) != document_key.as_ref() {
                return Err(H3Error::invalid(
                    "candidate",
                    "the candidate must address the commit document",
                ));
            }
        }
        if let Some(publication) = &self.publication {
            if publication.project_id() != project {
                return Err(H3Error::CrossProject {
                    id_kind: "publication".to_owned(),
                    expected: project,
                    found: publication.project_id(),
                });
            }
            if Some(publication.document_key()) != document_key.as_ref() {
                return Err(H3Error::invalid(
                    "publication",
                    "the publication must address the commit document",
                ));
            }
        }
        for event in &self.events {
            if event.project_id() != project {
                return Err(H3Error::CrossProject {
                    id_kind: "event".to_owned(),
                    expected: project,
                    found: event.project_id(),
                });
            }
            if event.subject().host_activity().is_none() {
                return Err(H3Error::invalid(
                    "event.subject",
                    "H3 state events must use a host-activity subject, not a fabricated run",
                ));
            }
        }
        if let Some(request) = &self.request {
            let request_value = request.request();
            if request_value.project_id() != project {
                return Err(H3Error::CrossProject {
                    id_kind: "request".to_owned(),
                    expected: project,
                    found: request_value.project_id(),
                });
            }
            if request_value.document() != document_key.as_ref() {
                return Err(H3Error::invalid(
                    "request.document",
                    "the request must address the commit document",
                ));
            }
        }
        Ok(())
    }

    /// Project derived from the document, settings, or request write.
    pub fn project_id(&self) -> Option<ProjectId> {
        self.document
            .as_ref()
            .map(|document| document.document().project_id())
            .or_else(|| self.settings.as_ref().map(|settings| settings.settings().project_id()))
            .or_else(|| self.request.as_ref().map(|request| request.request().project_id()))
            .or_else(|| self.cycle.as_ref().map(SyncCycle::project_id))
            .or_else(|| self.generations.first().map(|generation| generation.project_id()))
            .or_else(|| self.candidate.as_ref().map(|candidate| candidate.project_id()))
            .or_else(|| self.publication.as_ref().map(|publication| publication.project_id()))
    }

    /// Document key derived from any document-scoped record.
    pub fn document_key(&self) -> Option<DocumentKey> {
        self.document
            .as_ref()
            .map(|document| document.document().document_key().clone())
            .or_else(|| self.cycle.as_ref().map(|cycle| cycle.document_key().clone()))
            .or_else(|| self.generations.first().map(|generation| generation.document_key().clone()))
            .or_else(|| self.candidate.as_ref().map(|candidate| candidate.document_key().clone()))
            .or_else(|| self.publication.as_ref().map(|publication| publication.document_key().clone()))
    }
}

/// One loaded settings value and its durable revision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct H3SettingsRecord {
    revision: u64,
    settings: H3Settings,
}

impl H3SettingsRecord {
    /// Creates a loaded record.
    pub fn new(revision: u64, settings: H3Settings) -> Result<Self, H3Error> {
        if revision == 0 {
            return Err(H3Error::must_be_positive("settingsRevision"));
        }
        Ok(Self { revision, settings })
    }

    /// Durable compare-and-swap revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Stored settings.
    pub const fn settings(&self) -> &H3Settings {
        &self.settings
    }
}

/// One loaded document state, durable revision, and last project sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3DocumentRecord {
    revision: u64,
    last_sequence: u64,
    state: H3DocumentState,
}

impl H3DocumentRecord {
    /// Creates a loaded document record.
    pub fn new(revision: u64, last_sequence: u64, state: H3DocumentState) -> Result<Self, H3Error> {
        if revision == 0 {
            return Err(H3Error::must_be_positive("documentRevision"));
        }
        Ok(Self {
            revision,
            last_sequence,
            state,
        })
    }

    /// Durable compare-and-swap revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Final project sequence included in this state.
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Stored document state.
    pub const fn state(&self) -> &H3DocumentState {
        &self.state
    }

    /// Versioned public status carrying the revision, final project sequence,
    /// state, reason, H2/evidence references, and current applicability.
    pub fn status(&self) -> H3DocumentStatus {
        H3DocumentStatus::new(self.revision, self.last_sequence, self.state.clone())
            .expect("a loaded document record has a positive revision")
    }
}

/// Result of one atomic H3 commit.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum HtmlSyncCommitOutcome {
    /// State was written and events are visible after the commit.
    Applied {
        /// New settings record, when settings changed.
        settings: Option<H3SettingsRecord>,
        /// New document record, when the document changed.
        document: Option<H3DocumentRecord>,
        /// Stored request result with the committed sequence, when the commit
        /// carried an idempotent request.
        request: Option<StoredRequestResult>,
        /// Committed events with assigned project sequences.
        receipt: CommitReceipt,
        /// Final project sequence observed by the commit.
        final_project_sequence: u64,
    },
    /// The request was already stored; nothing was written or sent.
    Duplicate {
        /// Stored request and result.
        stored: StoredRequestResult,
        /// Sequence recorded by the original result.
        final_project_sequence: u64,
    },
}

/// Durable H3 store implemented by the host SQLite store.
pub trait H3StorePort {
    /// Loads project settings.
    fn load_html_sync_settings(
        &self,
        project: ProjectId,
    ) -> Result<Option<H3SettingsRecord>, H3Error>;

    /// Loads one document state.
    fn load_html_sync_document(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Option<H3DocumentRecord>, H3Error>;

    /// Lists document states in canonical path order.
    fn list_html_sync_documents(
        &self,
        project: ProjectId,
    ) -> Result<Vec<H3DocumentRecord>, H3Error>;

    /// Lists every generation of one document in generation order.
    fn html_sync_generations(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Vec<GenerationRecord>, H3Error>;

    /// Loads one persisted candidate metadata record.
    fn load_html_sync_candidate(
        &self,
        project: ProjectId,
        candidate: CandidateId,
    ) -> Result<Option<CandidateRecord>, H3Error>;

    /// Loads one sync cycle.
    fn load_html_sync_cycle(
        &self,
        project: ProjectId,
        cycle: CycleId,
    ) -> Result<Option<SyncCycle>, H3Error>;

    /// Loads one publication journal entry.
    fn load_html_sync_publication(
        &self,
        project: ProjectId,
        publication: PublicationId,
    ) -> Result<Option<PublicationJournal>, H3Error>;

    /// Lists publication journal entries for one document in creation order.
    fn list_html_sync_publications(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Vec<PublicationJournal>, H3Error>;

    /// Loads one narrow host-state record used for a recorded, host-only
    /// consent reissue inside the exact human-approved Target set. The default
    /// is explicit absence; concrete stores that support the record override it.
    fn load_html_sync_host_state(&self, _key: &str) -> Result<Option<Vec<u8>>, H3Error> {
        Ok(None)
    }

    /// Returns a stored idempotent request result.
    fn html_sync_request_result(
        &self,
        project: ProjectId,
        request: H3RequestId,
    ) -> Result<Option<StoredRequestResult>, H3Error>;

    /// Lists stored idempotent request results in durable recording order.
    ///
    /// Recovery uses this to prove that previously committed operations were
    /// loaded and are never replayed merely because the process restarted.
    fn list_html_sync_request_results(
        &self,
        project: ProjectId,
    ) -> Result<Vec<StoredRequestResult>, H3Error>;

    /// Commits state and events atomically.
    fn commit_html_sync(
        &mut self,
        commit: HtmlSyncCommit,
    ) -> Result<HtmlSyncCommitOutcome, H3Error>;

    /// Updates one existing publication journal payload without adding a
    /// project sequence or event.
    ///
    /// H3 uses this only to fill the assigned synced sequence after the
    /// atomic state/event commit. It never changes the document, generation,
    /// candidate, or event stream.
    fn update_html_sync_publication(
        &mut self,
        journal: PublicationJournal,
    ) -> Result<(), H3Error>;
}

/// Decodes one stored settings payload.
pub fn decode_settings(bytes: &[u8]) -> Result<H3Settings, H3Error> {
    decode_record::<H3Settings>(bytes)
}

/// Decodes one stored generation payload.
pub fn decode_generation(bytes: &[u8]) -> Result<GenerationRecord, H3Error> {
    decode_record::<GenerationRecord>(bytes)
}

/// Decodes one stored candidate payload.
pub fn decode_candidate(bytes: &[u8]) -> Result<CandidateRecord, H3Error> {
    decode_record::<CandidateRecord>(bytes)
}

/// Decodes one stored cycle payload.
pub fn decode_cycle(bytes: &[u8]) -> Result<SyncCycle, H3Error> {
    decode_record::<SyncCycle>(bytes)
}

/// Decodes one stored publication payload.
pub fn decode_publication(bytes: &[u8]) -> Result<PublicationJournal, H3Error> {
    decode_record::<PublicationJournal>(bytes)
}

/// Decodes one stored operation result payload.
pub fn decode_operation_result(bytes: &[u8]) -> Result<H3OperationResult, H3Error> {
    decode_record::<H3OperationResult>(bytes)
}

/// Decodes one stored request-result payload.
pub fn decode_stored_request(bytes: &[u8]) -> Result<StoredRequestResult, H3Error> {
    decode_record::<StoredRequestResult>(bytes)
}

/// Verifies that a digest matches the exact bytes it describes.
pub fn verify_bytes_digest(bytes: &[u8], expected: &ContentDigest) -> bool {
    ContentDigest::sha256(bytes) == *expected
}
