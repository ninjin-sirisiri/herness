//! H3 state events on the existing H1 host-activity envelope.
//!
//! H3 does not define a second sequence or a private event table. State,
//! settings, and publication journal changes are committed through the H1
//! store, which assigns the next project sequence and exposes the events only
//! after the transaction commits. Candidate edits and host publication audit
//! already use the H1 `artifact.change*` and `artifact.publish*` events; H3
//! links to those instead of duplicating them.

use herness_core::{
    EventDraft, EventKind, EventPayload, HostActivitySubject, ProjectId, Timestamp,
};
use serde_json::json;

use crate::document::DocumentKey;
use crate::error::H3Error;
use crate::state::{
    H3DocumentState, H3Settings, H3State, PublicationJournal, PublicationStatus,
};

/// Host-activity kind for one H3 document.
pub const H3_DOCUMENT_ACTIVITY_KIND: &str = "html_sync.document";
/// Host-activity kind for project-level H3 settings.
pub const H3_PROJECT_ACTIVITY_KIND: &str = "html_sync.project";
/// Event kind for a committed document state change.
pub const H3_STATE_EVENT_KIND: &str = "html_sync.state";
/// Event kind for a committed settings approval or enablement.
pub const H3_SETTINGS_EVENT_KIND: &str = "html_sync.settings";
/// Event kind for a committed publication journal status change.
pub const H3_PUBLICATION_EVENT_KIND: &str = "html_sync.publication";

fn kind(value: &'static str) -> Result<EventKind, H3Error> {
    EventKind::new(value).map_err(|error| H3Error::invalid("eventKind", error.to_string()))
}

/// Builds one document state event.
///
/// The event carries the state, versioned reason, applicability, source
/// revision/digest, generation, and H2/evidence references. The store assigns
/// the project sequence.
pub fn document_state_event(
    document: &DocumentKey,
    previous: Option<H3State>,
    state: &H3DocumentState,
    occurred_at: Timestamp,
) -> Result<EventDraft, H3Error> {
    document.validate_in(state.project_id())?;
    let payload = json!({
        "formatVersion": crate::version::H3_FORMAT_VERSION,
        "actor": "host",
        "targetPath": document.target_path(),
        "previousState": previous.map(H3State::as_str),
        "state": state.state().as_str(),
        "reason": state.reason(),
        "applicability": state.applicability(),
        "sourceRevision": state.source().revision().get(),
        "sourceDigest": state.source().digest(),
        "generation": state.generation(),
        "cycle": state.cycle_id(),
        "h2": state.h2(),
        "evidence": state.evidence(),
        "settingsVersion": state.settings_version(),
        "updatedAt": state.updated_at().as_unix_millis(),
    });
    EventDraft::for_host_activity(
        document.project_id(),
        kind(H3_DOCUMENT_ACTIVITY_KIND)?,
        document.activity_id(),
        kind(H3_STATE_EVENT_KIND)?,
        occurred_at,
        EventPayload::new(payload),
    )
    .map_err(|error| H3Error::invalid("eventDraft", error.to_string()))
}

/// Builds one project settings event.
pub fn settings_event(
    settings: &H3Settings,
    occurred_at: Timestamp,
) -> Result<EventDraft, H3Error> {
    let activity_id = crate::state::project_activity_id(settings.project_id());
    let payload = json!({
        "formatVersion": crate::version::H3_FORMAT_VERSION,
        "actor": "host",
        "settingsVersion": settings.version(),
        "enabled": settings.enabled(),
        "targetPaths": settings.target_paths(),
        "autoPublish": settings.auto_publish(),
        "retainHistory": settings.retain_history(),
        "settingsFingerprint": settings.fingerprint(),
    });
    project_event(settings.project_id(), activity_id, H3_SETTINGS_EVENT_KIND, occurred_at, payload)
}

/// Builds one publication journal status event.
pub fn publication_event(
    journal: &PublicationJournal,
    occurred_at: Timestamp,
) -> Result<EventDraft, H3Error> {
    let document = journal.document_key();
    let payload = json!({
        "formatVersion": crate::version::H3_FORMAT_VERSION,
        "actor": "host",
        "targetPath": document.target_path(),
        "publicationId": journal.publication_id(),
        "generation": journal.generation_id(),
        "candidate": journal.candidate_id(),
        "h1RequestId": journal.h1_request_id(),
        "status": publication_status_label(journal.status()),
        "approvedHtmlDigest": journal.approved_html_digest(),
        "provenanceDigest": journal.provenance_digest(),
        "sourceRevision": journal.source().revision().get(),
        "sourceDigest": journal.source().digest(),
        "detail": journal.detail(),
    });
    EventDraft::for_host_activity(
        document.project_id(),
        kind(H3_DOCUMENT_ACTIVITY_KIND)?,
        document.activity_id(),
        kind(H3_PUBLICATION_EVENT_KIND)?,
        occurred_at,
        EventPayload::new(payload),
    )
    .map_err(|error| H3Error::invalid("eventDraft", error.to_string()))
}

/// Stable label for a publication journal status.
pub const fn publication_status_label(status: PublicationStatus) -> &'static str {
    match status {
        PublicationStatus::Prepared => "prepared",
        PublicationStatus::OldVersionSaved => "old_version_saved",
        PublicationStatus::Replacing => "replacing",
        PublicationStatus::Published => "published",
        PublicationStatus::NotPublished => "not_published",
        PublicationStatus::Unverifiable => "unverifiable",
        PublicationStatus::Conflict => "conflict",
    }
}

fn project_event(
    project: ProjectId,
    activity_id: herness_core::HostActivityId,
    event_kind: &'static str,
    occurred_at: Timestamp,
    payload: serde_json::Value,
) -> Result<EventDraft, H3Error> {
    let _ = HostActivitySubject::new(project, kind(H3_PROJECT_ACTIVITY_KIND)?, activity_id)
        .map_err(|error| H3Error::invalid("eventSubject", error.to_string()))?;
    EventDraft::for_host_activity(
        project,
        kind(H3_PROJECT_ACTIVITY_KIND)?,
        activity_id,
        kind(event_kind)?,
        occurred_at,
        EventPayload::new(payload),
    )
    .map_err(|error| H3Error::invalid("eventDraft", error.to_string()))
}
