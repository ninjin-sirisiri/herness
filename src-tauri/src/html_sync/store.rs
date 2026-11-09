//! H3 durable store composition.
//!
//! `herness-store` implements the H3 port over the one process-wide SQLite
//! connection. This module exposes the same connection through the existing
//! supervision `StoreHandle`, so H3 state, H2 supervision records, H1
//! checkpoints, and the project sequence stay in one transaction store.

use herness_core::ProjectId;
use herness_html_sync::{
    CandidateId, CandidateRecord, CycleId, DocumentKey, GenerationRecord, H3DocumentRecord,
    H3Error, H3RequestId, H3SettingsRecord, H3StorePort, HtmlSyncCommit, HtmlSyncCommitOutcome,
    PublicationId, PublicationJournal, StoredRequestResult, SyncCycle,
};

use crate::supervision::store::StoreHandle;

impl H3StorePort for StoreHandle {
    fn load_html_sync_settings(
        &self,
        project: ProjectId,
    ) -> Result<Option<H3SettingsRecord>, H3Error> {
        self.lock()
            .load_html_sync_settings(project)
            .map_err(H3Error::from)
    }

    fn load_html_sync_document(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Option<H3DocumentRecord>, H3Error> {
        self.lock()
            .load_html_sync_document(project, document)
            .map_err(H3Error::from)
    }

    fn list_html_sync_documents(
        &self,
        project: ProjectId,
    ) -> Result<Vec<H3DocumentRecord>, H3Error> {
        self.lock()
            .list_html_sync_documents(project)
            .map_err(H3Error::from)
    }

    fn html_sync_generations(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Vec<GenerationRecord>, H3Error> {
        self.lock()
            .html_sync_generations(project, document)
            .map_err(H3Error::from)
    }

    fn load_html_sync_candidate(
        &self,
        project: ProjectId,
        candidate: CandidateId,
    ) -> Result<Option<CandidateRecord>, H3Error> {
        self.lock()
            .load_html_sync_candidate(project, candidate)
            .map_err(H3Error::from)
    }

    fn load_html_sync_cycle(
        &self,
        project: ProjectId,
        cycle: CycleId,
    ) -> Result<Option<SyncCycle>, H3Error> {
        self.lock()
            .load_html_sync_cycle(project, cycle)
            .map_err(H3Error::from)
    }

    fn load_html_sync_publication(
        &self,
        project: ProjectId,
        publication: PublicationId,
    ) -> Result<Option<PublicationJournal>, H3Error> {
        self.lock()
            .load_html_sync_publication(project, publication)
            .map_err(H3Error::from)
    }

    fn list_html_sync_publications(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Vec<PublicationJournal>, H3Error> {
        self.lock()
            .list_html_sync_publications(project, document)
            .map_err(H3Error::from)
    }

    fn html_sync_request_result(
        &self,
        project: ProjectId,
        request: H3RequestId,
    ) -> Result<Option<StoredRequestResult>, H3Error> {
        self.lock()
            .html_sync_request_result(project, request)
            .map_err(H3Error::from)
    }

    fn commit_html_sync(
        &mut self,
        commit: HtmlSyncCommit,
    ) -> Result<HtmlSyncCommitOutcome, H3Error> {
        self.lock().commit_html_sync(commit).map_err(H3Error::from)
    }
}
