//! SQLite implementation of the H3 persistence port.
//!
//! H3 state is stored in dedicated rows whose payloads are opaque versioned
//! JSON owned by `herness-html-sync`. Compare-and-swap revisions, immutable
//! generation history, idempotent requests, and state events commit in one
//! immediate transaction. Events use the existing H1 `events` table and project
//! sequence; there is no second H3 sequence.

use herness_core::{Event, ProjectId, Timestamp};
use herness_html_sync::{
    CandidateId, CandidateRecord, CycleId, DocumentKey, GenerationRecord, H3DocumentRecord,
    H3DocumentState, H3Error, H3RequestId, H3SettingsRecord, H3StorePort, HtmlSyncCommit,
    HtmlSyncCommitOutcome, PublicationId, PublicationJournal, StoredRequestResult, SyncCycle,
    decode_candidate, decode_cycle, decode_generation, decode_publication, decode_settings,
    decode_stored_request, encode_record,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::error::StoreError;
use crate::fault::CommitPoint;
use crate::store::{
    Store, append_event_drafts, next_sequence, sequence_to_sql,
};

impl From<H3Error> for StoreError {
    fn from(error: H3Error) -> Self {
        match error {
            H3Error::CrossProject { expected, found, .. } => {
                Self::HtmlSyncCrossProject { expected, found }
            }
            H3Error::UnsupportedFormat {
                record,
                found,
                expected,
            } => Self::HtmlSyncFormat {
                record,
                found,
                expected,
            },
            H3Error::StaleRevision {
                key,
                expected,
                found,
            } => Self::StaleRevision {
                key,
                expected,
                found,
            },
            H3Error::DuplicateRequestConflict {
                request,
                recorded,
                supplied,
            } => Self::HtmlSyncRequestConflict {
                request,
                recorded,
                supplied,
            },
            H3Error::RecordConflict { record, id } => Self::HtmlSyncRecordConflict { record, id },
            H3Error::Corrupt { detail, .. } => Self::CorruptData { detail },
            H3Error::Storage { detail } => Self::Database { detail },
            other => Self::HtmlSyncInvalidCommit {
                detail: other.to_string(),
            },
        }
    }
}

impl From<StoreError> for H3Error {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::CrossProjectReference { expected, found }
            | StoreError::HtmlSyncCrossProject { expected, found } => Self::CrossProject {
                id_kind: "html sync".to_owned(),
                expected,
                found,
            },
            StoreError::StaleRevision {
                key,
                expected,
                found,
            } => Self::StaleRevision {
                key,
                expected,
                found,
            },
            StoreError::HtmlSyncRequestConflict {
                request,
                recorded,
                supplied,
            } => Self::DuplicateRequestConflict {
                request,
                recorded,
                supplied,
            },
            StoreError::HtmlSyncRecordConflict { record, id } => Self::RecordConflict { record, id },
            StoreError::HtmlSyncFormat {
                record,
                found,
                expected,
            } => Self::UnsupportedFormat {
                record,
                found,
                expected,
            },
            StoreError::CorruptData { detail }
            | StoreError::Codec { detail }
            | StoreError::HtmlSyncInvalidCommit { detail } => Self::Corrupt {
                record: "H3 store",
                detail,
            },
            other => Self::Storage {
                detail: other.to_string(),
            },
        }
    }
}

fn positive(value: i64, field: &str) -> Result<u64, StoreError> {
    if value <= 0 {
        return Err(StoreError::corrupt(format!("{field} must be positive")));
    }
    u64::try_from(value).map_err(|_| StoreError::corrupt(format!("{field} does not fit in u64")))
}

fn non_negative(value: i64, field: &str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::corrupt(format!("{field} is negative")))
}

fn timestamp(value: Timestamp, field: &str) -> Result<i64, StoreError> {
    i64::try_from(value.as_unix_millis())
        .map_err(|_| StoreError::corrupt(format!("{field} does not fit in sqlite")))
}

fn check_revision(
    expected: Option<u64>,
    found: Option<u64>,
    key: &str,
) -> Result<(), StoreError> {
    let matches = match (expected, found) {
        (None, None) => true,
        (Some(expected), Some(found)) => expected == found,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(StoreError::StaleRevision {
            key: key.to_owned(),
            expected,
            found,
        })
    }
}

fn next_revision(found: Option<u64>, key: &str) -> Result<u64, StoreError> {
    found
        .map(|revision| {
            revision
                .checked_add(1)
                .ok_or_else(|| StoreError::corrupt(format!("{key} revision overflow")))
        })
        .transpose()
        .map(|revision| revision.unwrap_or(1))
}

fn settings_revision(
    conn: &Connection,
    project: ProjectId,
) -> Result<Option<u64>, StoreError> {
    let value: Option<i64> = conn
        .query_row(
            "SELECT revision FROM html_sync_settings WHERE project_id = ?1",
            [project.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    value.map(|value| positive(value, "settings revision")).transpose()
}

fn document_revision(
    conn: &Connection,
    project: ProjectId,
    key: &DocumentKey,
) -> Result<Option<u64>, StoreError> {
    let value: Option<i64> = conn
        .query_row(
            "SELECT revision FROM html_sync_documents
             WHERE project_id = ?1 AND target_path = ?2",
            params![project.to_string(), key.target_path()],
            |row| row.get(0),
        )
        .optional()?;
    value.map(|value| positive(value, "document revision")).transpose()
}

fn load_settings(
    conn: &Connection,
    project: ProjectId,
) -> Result<Option<H3SettingsRecord>, StoreError> {
    let row = conn
        .query_row(
            "SELECT revision, payload FROM html_sync_settings WHERE project_id = ?1",
            [project.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((revision, payload)) = row else {
        return Ok(None);
    };
    let settings = decode_settings(&payload)?;
    if settings.project_id() != project {
        return Err(StoreError::HtmlSyncCrossProject {
            expected: project,
            found: settings.project_id(),
        });
    }
    Ok(Some(H3SettingsRecord::new(
        positive(revision, "settings revision")?,
        settings,
    )?))
}

fn load_document(
    conn: &Connection,
    project: ProjectId,
    key: &DocumentKey,
) -> Result<Option<H3DocumentRecord>, StoreError> {
    let row = conn
        .query_row(
            "SELECT revision, last_sequence, payload FROM html_sync_documents
             WHERE project_id = ?1 AND target_path = ?2",
            params![project.to_string(), key.target_path()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((revision, last_sequence, payload)) = row else {
        return Ok(None);
    };
    let state: H3DocumentState = herness_html_sync::decode_record(&payload)?;
    if state.document_key() != key {
        return Err(StoreError::corrupt(
            "document row target path does not match its payload",
        ));
    }
    Ok(Some(H3DocumentRecord::new(
        positive(revision, "document revision")?,
        non_negative(last_sequence, "document last sequence")?,
        state,
    )?))
}

fn load_generation(
    conn: &Connection,
    project: ProjectId,
    generation_id: herness_html_sync::GenerationId,
) -> Result<Option<GenerationRecord>, StoreError> {
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM html_sync_generations
             WHERE project_id = ?1 AND generation_id = ?2",
            params![project.to_string(), generation_id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let record = decode_generation(&payload)?;
    if record.project_id() != project || record.generation_id() != generation_id {
        return Err(StoreError::corrupt(
            "generation row does not match its recorded identifiers",
        ));
    }
    Ok(Some(record))
}

fn load_candidate(
    conn: &Connection,
    project: ProjectId,
    candidate_id: CandidateId,
) -> Result<Option<CandidateRecord>, StoreError> {
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM html_sync_candidates
             WHERE project_id = ?1 AND candidate_id = ?2",
            params![project.to_string(), candidate_id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let record = decode_candidate(&payload)?;
    if record.project_id() != project || record.candidate_id() != candidate_id {
        return Err(StoreError::corrupt(
            "candidate row does not match its recorded identifiers",
        ));
    }
    Ok(Some(record))
}

fn load_cycle(
    conn: &Connection,
    project: ProjectId,
    cycle_id: CycleId,
) -> Result<Option<SyncCycle>, StoreError> {
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM html_sync_cycles
             WHERE project_id = ?1 AND cycle_id = ?2",
            params![project.to_string(), cycle_id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let cycle = decode_cycle(&payload)?;
    if cycle.project_id() != project || cycle.cycle_id() != cycle_id {
        return Err(StoreError::corrupt(
            "cycle row does not match its recorded identifiers",
        ));
    }
    Ok(Some(cycle))
}

fn load_publication(
    conn: &Connection,
    project: ProjectId,
    publication_id: PublicationId,
) -> Result<Option<PublicationJournal>, StoreError> {
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM html_sync_publications
             WHERE project_id = ?1 AND publication_id = ?2",
            params![project.to_string(), publication_id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let journal = decode_publication(&payload)?;
    if journal.project_id() != project || journal.publication_id() != publication_id {
        return Err(StoreError::corrupt(
            "publication row does not match its recorded identifiers",
        ));
    }
    Ok(Some(journal))
}

fn load_request(
    conn: &Connection,
    project: ProjectId,
    request_id: H3RequestId,
) -> Result<Option<StoredRequestResult>, StoreError> {
    let row = conn
        .query_row(
            "SELECT fingerprint, payload FROM html_sync_requests
             WHERE project_id = ?1 AND request_id = ?2",
            params![project.to_string(), request_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((fingerprint, payload)) = row else {
        return Ok(None);
    };
    let stored = decode_stored_request(&payload)?;
    if stored.request().project_id() != project
        || stored.request().request_id() != request_id
        || stored.fingerprint().as_str() != fingerprint
    {
        return Err(StoreError::corrupt(
            "request row does not match its payload or fingerprint",
        ));
    }
    Ok(Some(stored))
}

fn ensure_generation_update(
    existing: &GenerationRecord,
    next: &GenerationRecord,
) -> Result<(), StoreError> {
    if existing == next {
        return Ok(());
    }
    let conflict = || StoreError::HtmlSyncRecordConflict {
        record: "generation",
        id: next.generation_id().to_string(),
    };
    if existing.document_key() != next.document_key()
        || existing.generation() != next.generation()
        || existing.cycle_id() != next.cycle_id()
        || existing.job_id() != next.job_id()
        || existing.source() != next.source()
        || existing.fingerprints() != next.fingerprints()
    {
        return Err(conflict());
    }
    let allowed = match existing.status() {
        herness_html_sync::GenerationStatus::Active => matches!(
            next.status(),
            herness_html_sync::GenerationStatus::Completed
                | herness_html_sync::GenerationStatus::Superseded
                | herness_html_sync::GenerationStatus::Failed
                | herness_html_sync::GenerationStatus::Cancelled
                | herness_html_sync::GenerationStatus::Orphaned
        ),
        herness_html_sync::GenerationStatus::Completed => matches!(
            next.status(),
            herness_html_sync::GenerationStatus::Superseded
                | herness_html_sync::GenerationStatus::Orphaned
        ),
        herness_html_sync::GenerationStatus::Superseded => {
            next.status() == herness_html_sync::GenerationStatus::Orphaned
        }
        herness_html_sync::GenerationStatus::Failed
        | herness_html_sync::GenerationStatus::Cancelled
        | herness_html_sync::GenerationStatus::Orphaned => false,
    };
    if !allowed {
        return Err(conflict());
    }
    if existing.completed() && !next.completed() {
        return Err(conflict());
    }
    if let Some(candidate) = existing.candidate()
        && next.candidate() != Some(candidate)
    {
        return Err(conflict());
    }
    if let Some(h2) = existing.h2()
        && next.h2() != Some(h2)
    {
        return Err(conflict());
    }
    if existing.publication().is_some() && existing.publication() != next.publication() {
        return Err(conflict());
    }
    let previous_evidence = existing.evidence();
    if !next.evidence().starts_with(previous_evidence) {
        return Err(conflict());
    }
    Ok(())
}

impl Store {
    /// Loads project settings.
    pub fn load_html_sync_settings(
        &self,
        project: ProjectId,
    ) -> Result<Option<H3SettingsRecord>, StoreError> {
        load_settings(&self.conn, project)
    }

    /// Loads one document state.
    pub fn load_html_sync_document(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Option<H3DocumentRecord>, StoreError> {
        document.validate_in(project)?;
        load_document(&self.conn, project, document)
    }

    /// Lists document states in canonical path order.
    pub fn list_html_sync_documents(
        &self,
        project: ProjectId,
    ) -> Result<Vec<H3DocumentRecord>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT target_path, revision, last_sequence, payload
             FROM html_sync_documents WHERE project_id = ?1 ORDER BY target_path ASC",
        )?;
        let mut rows = statement.query([project.to_string()])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            let target_path: String = row.get(0)?;
            let revision: i64 = row.get(1)?;
            let last_sequence: i64 = row.get(2)?;
            let payload: Vec<u8> = row.get(3)?;
            let state: H3DocumentState = herness_html_sync::decode_record(&payload)?;
            if state.document_key().target_path() != target_path {
                return Err(StoreError::corrupt(
                    "document row target path does not match its payload",
                ));
            }
            records.push(H3DocumentRecord::new(
                positive(revision, "document revision")?,
                non_negative(last_sequence, "document last sequence")?,
                state,
            )?);
        }
        Ok(records)
    }

    /// Lists every generation of one document in generation order.
    pub fn html_sync_generations(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Vec<GenerationRecord>, StoreError> {
        document.validate_in(project)?;
        let mut statement = self.conn.prepare(
            "SELECT payload FROM html_sync_generations
             WHERE project_id = ?1 AND target_path = ?2 ORDER BY generation ASC",
        )?;
        let mut rows = statement.query(params![project.to_string(), document.target_path()])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            let payload: Vec<u8> = row.get(0)?;
            let record = decode_generation(&payload)?;
            if record.project_id() != project || record.document_key() != document {
                return Err(StoreError::corrupt(
                    "generation row does not match its document",
                ));
            }
            records.push(record);
        }
        Ok(records)
    }

    /// Loads one candidate metadata record.
    pub fn load_html_sync_candidate(
        &self,
        project: ProjectId,
        candidate: CandidateId,
    ) -> Result<Option<CandidateRecord>, StoreError> {
        candidate.validate_in(project)?;
        load_candidate(&self.conn, project, candidate)
    }

    /// Loads one sync cycle.
    pub fn load_html_sync_cycle(
        &self,
        project: ProjectId,
        cycle: CycleId,
    ) -> Result<Option<SyncCycle>, StoreError> {
        cycle.validate_in(project)?;
        load_cycle(&self.conn, project, cycle)
    }

    /// Loads one publication journal entry.
    pub fn load_html_sync_publication(
        &self,
        project: ProjectId,
        publication: PublicationId,
    ) -> Result<Option<PublicationJournal>, StoreError> {
        publication.validate_in(project)?;
        load_publication(&self.conn, project, publication)
    }

    /// Lists publication journal entries for one document in creation order.
    pub fn list_html_sync_publications(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Vec<PublicationJournal>, StoreError> {
        document.validate_in(project)?;
        let mut statement = self.conn.prepare(
            "SELECT payload FROM html_sync_publications
             WHERE project_id = ?1 AND target_path = ?2 ORDER BY updated_at ASC, publication_id ASC",
        )?;
        let mut rows = statement.query(params![project.to_string(), document.target_path()])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            let payload: Vec<u8> = row.get(0)?;
            let journal = decode_publication(&payload)?;
            if journal.project_id() != project || journal.document_key() != document {
                return Err(StoreError::corrupt(
                    "publication row does not match its document",
                ));
            }
            records.push(journal);
        }
        Ok(records)
    }

    /// Returns a stored idempotent request result.
    pub fn html_sync_request_result(
        &self,
        project: ProjectId,
        request: H3RequestId,
    ) -> Result<Option<StoredRequestResult>, StoreError> {
        request.validate_in(project)?;
        load_request(&self.conn, project, request)
    }

    /// Commits H3 state and events atomically.
    #[allow(clippy::too_many_lines)]
    pub fn commit_html_sync(
        &mut self,
        commit: HtmlSyncCommit,
    ) -> Result<HtmlSyncCommitOutcome, StoreError> {
        commit.validate()?;
        let project = commit
            .project_id()
            .ok_or_else(|| StoreError::HtmlSyncInvalidCommit {
                detail: "the commit has no project".to_owned(),
            })?;

        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(request) = commit.request() {
            let request_value = request.request();
            if let Some(stored) = load_request(&transaction, project, request_value.request_id())? {
                if stored.fingerprint() == request_value.fingerprint() {
                    return Ok(HtmlSyncCommitOutcome::Duplicate {
                        final_project_sequence: stored.result().final_project_sequence(),
                        stored,
                    });
                }
                return Err(StoreError::HtmlSyncRequestConflict {
                    request: request_value.request_id().to_string(),
                    recorded: stored.request().describe(),
                    supplied: request_value.describe(),
                });
            }
        }

        if self.fault.commit == Some(CommitPoint::BeforeRows) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeRows.as_str(),
            });
        }

        if let Some(settings) = commit.settings() {
            let current = settings_revision(&transaction, project)?;
            check_revision(
                settings.expected_revision(),
                current,
                "html sync settings",
            )?;
        }
        if let Some(document) = commit.document() {
            let key = document.document().document_key();
            let current = document_revision(&transaction, project, key)?;
            check_revision(document.expected_revision(), current, key.target_path())?;
        }

        for generation in commit.generations() {
            if let Some(existing) =
                load_generation(&transaction, project, generation.generation_id())?
            {
                ensure_generation_update(&existing, generation)?;
            }
            let same_number: Option<String> = transaction
                .query_row(
                    "SELECT generation_id FROM html_sync_generations
                     WHERE project_id = ?1 AND target_path = ?2 AND generation = ?3",
                    params![
                        project.to_string(),
                        generation.document_key().target_path(),
                        sequence_to_sql(generation.generation())?,
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(found) = same_number
                && found != generation.generation_id().to_string()
            {
                return Err(StoreError::HtmlSyncRecordConflict {
                    record: "generation number",
                    id: generation.generation_id().to_string(),
                });
            }
        }
        if let Some(candidate) = commit.candidate()
            && let Some(existing) = load_candidate(&transaction, project, candidate.candidate_id())?
            && existing != *candidate
        {
            return Err(StoreError::HtmlSyncRecordConflict {
                record: "candidate",
                id: candidate.candidate_id().to_string(),
            });
        }
        if let Some(cycle) = commit.cycle()
            && let Some(existing) = load_cycle(&transaction, project, cycle.cycle_id())?
            && existing.document_key() != cycle.document_key()
        {
            return Err(StoreError::HtmlSyncRecordConflict {
                record: "cycle",
                id: cycle.cycle_id().to_string(),
            });
        }
        if let Some(publication) = commit.publication()
            && let Some(existing) =
                load_publication(&transaction, project, publication.publication_id())?
        {
            if existing.document_key() != publication.document_key() {
                return Err(StoreError::HtmlSyncRecordConflict {
                    record: "publication",
                    id: publication.publication_id().to_string(),
                });
            }
            if existing.updated_at() > publication.updated_at() {
                return Err(StoreError::HtmlSyncInvalidCommit {
                    detail: "the publication journal cannot move its update time backwards"
                        .to_owned(),
                });
            }
        }

        let (events, _) = append_event_drafts(&transaction, &project, commit.events())?;
        let max_sequence = events.last().map_or(0, Event::sequence);
        let final_sequence = if events.is_empty() {
            next_sequence(&transaction, &project)?.saturating_sub(1)
        } else {
            max_sequence
        };

        let settings = if let Some(settings_commit) = commit.settings() {
            let current = settings_revision(&transaction, project)?;
            let revision = next_revision(current, "settings")?;
            let settings = settings_commit.settings();
            let payload = encode_record(settings)?;
            transaction.execute(
                "INSERT INTO html_sync_settings (project_id, revision, payload, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(project_id) DO UPDATE SET
                     revision = excluded.revision,
                     payload = excluded.payload,
                     updated_at = excluded.updated_at",
                params![
                    project.to_string(),
                    sequence_to_sql(revision)?,
                    payload,
                    timestamp(settings.approved_at(), "settings approved_at")?,
                ],
            )?;
            Some(H3SettingsRecord::new(revision, settings.clone())?)
        } else {
            None
        };

        let document = if let Some(document_commit) = commit.document() {
            let state = document_commit.document();
            let key = state.document_key();
            let current = document_revision(&transaction, project, key)?;
            let revision = next_revision(current, "document")?;
            let payload = encode_record(state)?;
            transaction.execute(
                "INSERT INTO html_sync_documents
                     (project_id, target_path, revision, payload, updated_at, last_sequence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(project_id, target_path) DO UPDATE SET
                     revision = excluded.revision,
                     payload = excluded.payload,
                     updated_at = excluded.updated_at,
                     last_sequence = excluded.last_sequence",
                params![
                    project.to_string(),
                    key.target_path(),
                    sequence_to_sql(revision)?,
                    payload,
                    timestamp(state.updated_at(), "document updated_at")?,
                    sequence_to_sql(final_sequence)?,
                ],
            )?;
            Some(H3DocumentRecord::new(revision, final_sequence, state.clone())?)
        } else {
            None
        };

        if let Some(cycle) = commit.cycle() {
            let payload = encode_record(cycle)?;
            let updated_at = cycle.ended_at().unwrap_or_else(|| cycle.started_at());
            transaction.execute(
                "INSERT INTO html_sync_cycles
                     (project_id, cycle_id, target_path, payload, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(project_id, cycle_id) DO UPDATE SET
                     target_path = excluded.target_path,
                     payload = excluded.payload,
                     updated_at = excluded.updated_at",
                params![
                    project.to_string(),
                    cycle.cycle_id().to_string(),
                    cycle.document_key().target_path(),
                    payload,
                    timestamp(updated_at, "cycle updated_at")?,
                ],
            )?;
        }

        for generation in commit.generations() {
            let payload = encode_record(generation)?;
            transaction.execute(
                "INSERT INTO html_sync_generations
                     (project_id, generation_id, target_path, generation, cycle_id,
                      completed, payload, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(project_id, generation_id) DO UPDATE SET
                     completed = excluded.completed,
                     payload = excluded.payload",
                params![
                    project.to_string(),
                    generation.generation_id().to_string(),
                    generation.document_key().target_path(),
                    sequence_to_sql(generation.generation())?,
                    generation.cycle_id().to_string(),
                    if generation.completed() { 1_i64 } else { 0 },
                    payload,
                    timestamp(generation.started_at(), "generation started_at")?,
                ],
            )?;
        }

        if let Some(candidate) = commit.candidate() {
            let payload = encode_record(candidate)?;
            transaction.execute(
                "INSERT INTO html_sync_candidates
                     (project_id, candidate_id, target_path, generation_id, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(project_id, candidate_id) DO UPDATE SET
                     target_path = excluded.target_path,
                     generation_id = excluded.generation_id,
                     payload = excluded.payload",
                params![
                    project.to_string(),
                    candidate.candidate_id().to_string(),
                    candidate.document_key().target_path(),
                    candidate.generation_id().to_string(),
                    payload,
                ],
            )?;
        }

        if let Some(publication) = commit.publication() {
            let payload = encode_record(publication)?;
            transaction.execute(
                "INSERT INTO html_sync_publications
                     (project_id, publication_id, target_path, h1_request_id, payload, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(project_id, publication_id) DO UPDATE SET
                     target_path = excluded.target_path,
                     h1_request_id = excluded.h1_request_id,
                     payload = excluded.payload,
                     updated_at = excluded.updated_at",
                params![
                    project.to_string(),
                    publication.publication_id().to_string(),
                    publication.document_key().target_path(),
                    publication.h1_request_id().to_string(),
                    payload,
                    timestamp(publication.updated_at(), "publication updated_at")?,
                ],
            )?;
        }

        let stored_request = if let Some(request) = commit.request() {
            let result = request
                .result()
                .clone()
                .with_final_project_sequence(final_sequence);
            let stored = StoredRequestResult::new(
                request.request().clone(),
                result,
                request.result().recorded_at(),
            )?;
            let payload = encode_record(&stored)?;
            transaction.execute(
                "INSERT INTO html_sync_requests
                     (project_id, request_id, fingerprint, payload, recorded_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    project.to_string(),
                    request.request().request_id().to_string(),
                    stored.fingerprint().as_str(),
                    payload,
                    timestamp(stored.recorded_at(), "request recorded_at")?,
                ],
            )?;
            Some(stored)
        } else {
            None
        };

        if self.fault.commit == Some(CommitPoint::BeforeCommit) {
            return Err(StoreError::InjectedFault {
                point: CommitPoint::BeforeCommit.as_str(),
            });
        }

        transaction.commit()?;
        Ok(HtmlSyncCommitOutcome::Applied {
            settings,
            document,
            request: stored_request,
            receipt: herness_core::CommitReceipt::new(events, max_sequence),
            final_project_sequence: final_sequence,
        })
    }
}

impl H3StorePort for Store {
    fn load_html_sync_settings(
        &self,
        project: ProjectId,
    ) -> Result<Option<H3SettingsRecord>, H3Error> {
        Store::load_html_sync_settings(self, project).map_err(H3Error::from)
    }

    fn load_html_sync_document(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Option<H3DocumentRecord>, H3Error> {
        Store::load_html_sync_document(self, project, document).map_err(H3Error::from)
    }

    fn list_html_sync_documents(
        &self,
        project: ProjectId,
    ) -> Result<Vec<H3DocumentRecord>, H3Error> {
        Store::list_html_sync_documents(self, project).map_err(H3Error::from)
    }

    fn html_sync_generations(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Vec<GenerationRecord>, H3Error> {
        Store::html_sync_generations(self, project, document).map_err(H3Error::from)
    }

    fn load_html_sync_candidate(
        &self,
        project: ProjectId,
        candidate: CandidateId,
    ) -> Result<Option<CandidateRecord>, H3Error> {
        Store::load_html_sync_candidate(self, project, candidate).map_err(H3Error::from)
    }

    fn load_html_sync_cycle(
        &self,
        project: ProjectId,
        cycle: CycleId,
    ) -> Result<Option<SyncCycle>, H3Error> {
        Store::load_html_sync_cycle(self, project, cycle).map_err(H3Error::from)
    }

    fn load_html_sync_publication(
        &self,
        project: ProjectId,
        publication: PublicationId,
    ) -> Result<Option<PublicationJournal>, H3Error> {
        Store::load_html_sync_publication(self, project, publication).map_err(H3Error::from)
    }

    fn list_html_sync_publications(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Vec<PublicationJournal>, H3Error> {
        Store::list_html_sync_publications(self, project, document).map_err(H3Error::from)
    }

    fn html_sync_request_result(
        &self,
        project: ProjectId,
        request: H3RequestId,
    ) -> Result<Option<StoredRequestResult>, H3Error> {
        Store::html_sync_request_result(self, project, request).map_err(H3Error::from)
    }

    fn commit_html_sync(
        &mut self,
        commit: HtmlSyncCommit,
    ) -> Result<HtmlSyncCommitOutcome, H3Error> {
        Store::commit_html_sync(self, commit).map_err(H3Error::from)
    }
}
