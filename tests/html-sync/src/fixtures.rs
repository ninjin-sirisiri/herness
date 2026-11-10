//! Deterministic, synthetic H3 values shared by the black-box tests.
//!
//! No real project, credential, provider body, or user document is used.

use herness_core::{ExpectedTargetVersion, ProjectId, Timestamp};
use herness_html_sync::{
    Applicability, ApplicabilityReason, CandidateId, CandidateRecord, CandidateStorageRef, CycleId,
    DocumentKey, FingerprintSet, GenerationId, GenerationRecord, GenerationStatus, H2Reference,
    H3DocumentState, H3Operation, H3OperationOutcome, H3OperationRequest, H3OperationResult,
    H3Reason, H3RequestId, H3Settings, H3State, H3StateReasonKind, JobId, PublicationId,
    PublicationJournal, RequestCommit, SourceRevision, SourceSnapshot, SyncCycle,
};
use herness_supervision::ContentDigest;
use uuid::Uuid;

/// Primary fixture project.
pub const PROJECT_UUID: &str = "33333333-3333-4333-8333-333333333333";
/// Second project used to prove cross-project rejection.
pub const OTHER_PROJECT_UUID: &str = "44444444-4444-4444-8444-444444444444";
/// Fixed fixture timestamp.
pub const NOW_MILLIS: u64 = 1_700_000_000_000;
/// Canonical fixture Target path.
pub const TARGET_PATH: &str = "docs/sdd/specs/2026-11-09-h3-html-sync-design.md";

/// Primary fixture project.
pub fn project() -> ProjectId {
    PROJECT_UUID.parse().expect("fixture project")
}

/// Another fixture project.
pub fn other_project() -> ProjectId {
    OTHER_PROJECT_UUID.parse().expect("fixture project")
}

/// Fixed fixture timestamp.
pub fn now() -> Timestamp {
    Timestamp::from_unix_millis(NOW_MILLIS)
}

/// A fixed digest for a named fixture dependency.
pub fn digest(name: &str) -> ContentDigest {
    ContentDigest::sha256(format!("fixture:{name}").as_bytes())
}

/// Primary document key.
pub fn document_key() -> DocumentKey {
    DocumentKey::new(project(), TARGET_PATH).expect("document key")
}

/// A document key for another project with the same target path.
pub fn other_document_key() -> DocumentKey {
    DocumentKey::new(other_project(), TARGET_PATH).expect("document key")
}

fn local(seed: &str) -> Uuid {
    Uuid::parse_str(seed).expect("fixture uuid")
}

/// Stable fixture identifiers.
#[derive(Debug, Clone, Copy)]
pub struct Ids {
    /// Job.
    pub job: JobId,
    /// Current cycle.
    pub cycle: CycleId,
    /// First generation.
    pub generation_one: GenerationId,
    /// Second generation.
    pub generation_two: GenerationId,
    /// Publication journal.
    pub publication: PublicationId,
    /// First idempotent request.
    pub request_one: H3RequestId,
    /// Second idempotent request.
    pub request_two: H3RequestId,
    /// First candidate.
    pub candidate_one: CandidateId,
    /// Second candidate.
    pub candidate_two: CandidateId,
}

/// Builds deterministic fixture identifiers for `project`.
pub fn ids(project: ProjectId) -> Ids {
    Ids {
        job: JobId::from_parts(project, local("50000000-0000-4000-8000-000000000001")),
        cycle: CycleId::from_parts(project, local("50000000-0000-4000-8000-000000000002")),
        generation_one: GenerationId::from_parts(
            project,
            local("50000000-0000-4000-8000-000000000003"),
        ),
        generation_two: GenerationId::from_parts(
            project,
            local("50000000-0000-4000-8000-000000000004"),
        ),
        publication: PublicationId::from_parts(
            project,
            local("50000000-0000-4000-8000-000000000005"),
        ),
        request_one: H3RequestId::from_parts(
            project,
            local("50000000-0000-4000-8000-000000000006"),
        ),
        request_two: H3RequestId::from_parts(
            project,
            local("50000000-0000-4000-8000-000000000007"),
        ),
        candidate_one: CandidateId::from_parts(
            project,
            local("50000000-0000-4000-8000-000000000008"),
        ),
        candidate_two: CandidateId::from_parts(
            project,
            local("50000000-0000-4000-8000-000000000009"),
        ),
    }
}

/// A source snapshot at revision one holding `text`.
pub fn source(text: &str) -> SourceSnapshot {
    source_at(1, text)
}

/// A source snapshot at an explicit revision.
pub fn source_at(revision: u64, text: &str) -> SourceSnapshot {
    SourceSnapshot::new(
        SourceRevision::new(revision).expect("revision"),
        ContentDigest::sha256(text.as_bytes()),
    )
}

/// A fingerprint set with separate dependency values.
pub fn fingerprints() -> FingerprintSet {
    FingerprintSet::new(
        digest("settings"),
        digest("policy"),
        digest("css"),
        digest("resources"),
        None,
        None,
        None,
    )
}

/// A fingerprint set including candidate and provenance values.
pub fn authored_fingerprints(html: &str, provenance: &str) -> FingerprintSet {
    fingerprints()
        .with_candidate(ContentDigest::sha256(html.as_bytes()))
        .with_provenance(ContentDigest::sha256(provenance.as_bytes()))
}

/// A pending reason for `revision`.
pub fn pending_reason(revision: u64) -> H3Reason {
    H3Reason::new(
        H3StateReasonKind::Pending {
            source_revision: revision,
        },
        vec![],
    )
    .expect("pending reason")
}

/// A synced reason.
pub fn synced_reason(generation: GenerationId, snapshot: &SourceSnapshot) -> H3Reason {
    H3Reason::new(
        H3StateReasonKind::Synced {
            generation,
            source_revision: snapshot.revision().get(),
            source_digest: snapshot.digest().clone(),
        },
        vec![],
    )
    .expect("synced reason")
}

/// A waiting-human reason for an external conflict.
pub fn conflict_reason() -> H3Reason {
    H3Reason::new(
        H3StateReasonKind::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::ExternalHtmlConflict,
        },
        vec![herness_html_sync::RequiredAction::ResolveHtmlConflict {
            target: document_key().companion_path(),
        }],
    )
    .expect("conflict reason")
}

/// A pending document state.
pub fn pending_document(source: SourceSnapshot) -> H3DocumentState {
    pending_document_with(source, None)
}

/// A pending document state carrying an optional current generation.
pub fn pending_document_with(
    source: SourceSnapshot,
    generation: Option<GenerationId>,
) -> H3DocumentState {
    let key = document_key();
    let ids = ids(key.project_id());
    H3DocumentState::new(
        key,
        1,
        Some(ids.job),
        Some(ids.cycle),
        generation,
        source,
        fingerprints(),
        pending_reason(1),
        None,
        Vec::new(),
        Applicability::not_applicable(ApplicabilityReason::NeverPublished),
        now(),
    )
    .expect("pending document")
}

/// A synced document state for one generation.
pub fn synced_document(
    generation: GenerationId,
    source: SourceSnapshot,
    fingerprints: FingerprintSet,
) -> H3DocumentState {
    let key = document_key();
    let ids = ids(key.project_id());
    H3DocumentState::new(
        key,
        1,
        Some(ids.job),
        Some(ids.cycle),
        Some(generation),
        source.clone(),
        fingerprints,
        synced_reason(generation, &source),
        None,
        Vec::new(),
        Applicability::current_synced(),
        now(),
    )
    .expect("synced document")
}

/// Settings approved with one Target.
pub fn settings(enabled: bool) -> H3Settings {
    H3Settings::new(
        project(),
        1,
        enabled,
        vec![TARGET_PATH.to_owned()],
        true,
        true,
        now(),
    )
    .expect("settings")
}

/// A fixture cycle.
pub fn cycle() -> SyncCycle {
    let key = document_key();
    SyncCycle::new(
        ids(key.project_id()).cycle,
        key,
        1,
        now(),
        source("source v1"),
        None,
    )
    .expect("cycle")
}

/// A fixture H2 reference.
pub fn h2_reference() -> H2Reference {
    H2Reference::new(
        project(),
        herness_supervision::SupervisionId::from_parts(
            project(),
            local("50000000-0000-4000-8000-00000000000a"),
        ),
        None,
        Some(herness_supervision::ConditionVersion::new(1).expect("condition version")),
        Some(herness_supervision::TargetVersion::new(1).expect("target version")),
        Some(1),
        Some(herness_supervision::SupervisionState::Ready),
    )
    .expect("H2 reference")
}

/// Candidate storage reference with a valid namespace shape.
pub fn candidate_storage() -> CandidateStorageRef {
    CandidateStorageRef::new("ab".repeat(32), ContentDigest::sha256(b"fixture-token"))
        .expect("candidate storage")
}

/// A candidate record for one generation.
pub fn candidate(
    candidate_id: CandidateId,
    generation: GenerationId,
    html: &str,
    provenance: &str,
) -> CandidateRecord {
    CandidateRecord::new(
        candidate_id,
        document_key(),
        generation,
        candidate_storage(),
        ContentDigest::sha256(html.as_bytes()),
        ContentDigest::sha256(provenance.as_bytes()),
        now(),
    )
    .expect("candidate")
}

/// A generation record in the active state.
pub fn generation(
    generation_id: GenerationId,
    number: u64,
    source: SourceSnapshot,
    fingerprints: FingerprintSet,
) -> GenerationRecord {
    let key = document_key();
    let ids = ids(key.project_id());
    GenerationRecord::new(
        generation_id,
        key,
        number,
        ids.cycle,
        ids.job,
        source,
        fingerprints,
        GenerationStatus::Active,
        false,
        now(),
    )
    .expect("generation")
}

/// A publication journal entry expecting an absent target.
pub fn publication(
    generation: GenerationId,
    candidate: CandidateId,
    html: &str,
    provenance: &str,
) -> PublicationJournal {
    PublicationJournal::new(
        ids(project()).publication,
        document_key(),
        generation,
        candidate,
        herness_core::PublicationRequestId::new("h1-publication-1").expect("H1 request id"),
        ExpectedTargetVersion::absent(),
        ContentDigest::sha256(html.as_bytes()),
        ContentDigest::sha256(provenance.as_bytes()),
        source("source v1"),
        now(),
    )
    .expect("publication journal")
}

/// A pause request for one document revision.
pub fn pause_request(request: H3RequestId, expected_revision: u64) -> H3OperationRequest {
    H3OperationRequest::new(
        request,
        project(),
        Some(document_key()),
        Some(expected_revision),
        None,
        H3Operation::Pause,
        now(),
    )
    .expect("pause request")
}

/// An accepted result template for `request`.
pub fn accepted_result(request: &H3OperationRequest, revision: u64) -> H3OperationResult {
    H3OperationResult::new(
        request,
        H3OperationOutcome::Accepted {
            state: H3State::Pending,
            revision,
        },
        0,
        now(),
    )
    .expect("operation result")
}

/// A request commit with an accepted result.
pub fn request_commit(request: H3OperationRequest, revision: u64) -> RequestCommit {
    let result = accepted_result(&request, revision);
    RequestCommit::new(request, result).expect("request commit")
}

/// A settings commit for creation.
pub fn settings_commit(settings: H3Settings) -> herness_html_sync::SettingsCommit {
    herness_html_sync::SettingsCommit::new(None, settings).expect("settings commit")
}

/// A document commit for creation.
pub fn document_commit(document: H3DocumentState) -> herness_html_sync::DocumentCommit {
    herness_html_sync::DocumentCommit::new(None, document).expect("document commit")
}
