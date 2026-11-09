//! Black-box H3 contract tests.
//!
//! Every value is synthetic and local. These tests check the versioned state
//! and operation surface, not a model, provider, or user document.

use herness_core::{ExpectedTargetVersion, Timestamp};
use herness_html_sync::{
    Applicability, ApplicabilityReason, ArchivedVersionRef, DocumentKey, FingerprintKind,
    FingerprintSet, GenerationStatus, H3DocumentState, H3Error, H3Operation,
    H3OperationOutcome, H3OperationRequest, H3OperationResult, H3Reason, H3Settings, H3State,
    H3StateReasonKind, H3StopCause, PublicationJournal, PublicationStatus, RequestCommit,
    SourceRevision, SourceSnapshot, StoredRequestResult, decode_record, document_state_event,
    publication_event, settings_event,
};
use herness_html_sync_tests::fixtures::{
    TARGET_PATH, accepted_result, authored_fingerprints, candidate, conflict_reason, digest,
    document_key, fingerprints, generation, h2_reference, ids, now, other_document_key,
    other_project, pending_document, pending_reason, project, publication, request_commit,
    settings, source, source_at, synced_document,
};
use serde_json::json;

#[test]
fn states_are_exactly_the_agreed_set_and_wire_labels_are_stable() {
    let labels: Vec<&str> = H3State::ALL.iter().map(|state| state.as_str()).collect();
    assert_eq!(
        labels,
        vec![
            "disabled",
            "pending",
            "authoring",
            "verifying",
            "assessing",
            "ready_to_publish",
            "publishing",
            "synced",
            "waiting_human",
            "stopped",
            "failed",
            "cancelled",
            "orphaned",
        ]
    );
    assert_eq!(H3State::ALL.len(), 13);
    let unique: std::collections::BTreeSet<_> = labels.iter().collect();
    assert_eq!(unique.len(), 13);
    assert!(H3State::Synced.is_currently_synced());
    assert!(H3State::WaitingHuman.requires_human());
    assert!(H3State::Stopped.requires_human());
    assert!(H3State::Failed.is_terminal_without_sync());
}

#[test]
fn versioned_reasons_require_actions_and_reject_unknown_formats_or_fields() {
    let reason = conflict_reason();
    assert_eq!(reason.state(), H3State::WaitingHuman);
    assert!(matches!(
        reason.kind(),
        H3StateReasonKind::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::ExternalHtmlConflict
        }
    ));
    assert_eq!(
        reason.required_actions()[0].as_str(),
        "resolve_html_conflict"
    );

    assert!(H3Reason::new(
        H3StateReasonKind::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::PermissionDenied,
        },
        Vec::new(),
    )
    .is_err());
    assert!(H3Reason::new(
        H3StateReasonKind::Stopped {
            cause: H3StopCause::HumanRequest,
        },
        vec![
            herness_html_sync::RequiredAction::ResumeCycle,
            herness_html_sync::RequiredAction::ResumeCycle,
        ],
    )
    .is_err());

    let encoded = serde_json::to_value(&reason).expect("serialize reason");
    assert_eq!(encoded["formatVersion"], 1);
    assert_eq!(encoded["kind"]["kind"], "waiting_human");
    assert_eq!(encoded["kind"]["cause"], "external_html_conflict");
    let mut unknown = encoded.clone();
    unknown["unknownField"] = json!(true);
    assert!(serde_json::from_value::<H3Reason>(unknown).is_err());

    let mut future = encoded.clone();
    future["formatVersion"] = json!(2);
    let bytes = serde_json::to_vec(&future).expect("bytes");
    assert!(matches!(
        decode_record::<H3Reason>(&bytes),
        Err(H3Error::UnsupportedFormat { .. })
    ));
}

#[test]
fn source_revision_is_monotonic_while_the_digest_tracks_exact_bytes() {
    let first = SourceSnapshot::observe(None, 5, digest("source-v5")).expect("first");
    assert_eq!(first.revision().get(), 5);

    let back = SourceSnapshot::observe(Some(&first), 2, digest("source-v2")).expect("back");
    assert_eq!(back.revision().get(), 5);
    assert_ne!(back.digest(), first.digest());
    assert!(!back.same_bytes(&first));

    let same = SourceSnapshot::observe(Some(&back), 6, digest("source-v2")).expect("same");
    assert_eq!(same.revision().get(), 6);
    assert!(same.same_bytes(&back));

    assert!(SourceRevision::new(0).is_err());
    assert!(SourceSnapshot::observe(Some(&first), 0, digest("zero")).is_err());
}

#[test]
fn dependency_fingerprints_stay_separate_and_invalidate_current_applicability() {
    let base = fingerprints();
    let kinds = [
        FingerprintKind::Settings,
        FingerprintKind::Policy,
        FingerprintKind::Css,
        FingerprintKind::Resources,
    ];
    let mut values = Vec::new();
    for kind in kinds {
        let value = base.get(kind).expect("mandatory fingerprint");
        assert!(!values.contains(value), "fingerprints must stay distinct");
        values.push(value.clone());
    }
    assert!(base.get(FingerprintKind::Candidate).is_none());
    assert!(base.get(FingerprintKind::Provenance).is_none());
    assert!(base.get(FingerprintKind::Evidence).is_none());

    let authored = authored_fingerprints("<html></html>", "{}");
    assert!(authored.get(FingerprintKind::Candidate).is_some());
    assert!(authored.get(FingerprintKind::Provenance).is_some());
    assert_eq!(
        authored.changed_since(&base),
        Some(FingerprintKind::Candidate)
    );

    let changed_css = FingerprintSet::new(
        base.get(FingerprintKind::Settings).unwrap().clone(),
        base.get(FingerprintKind::Policy).unwrap().clone(),
        digest("css-v2"),
        base.get(FingerprintKind::Resources).unwrap().clone(),
        None,
        None,
        None,
    );
    assert_eq!(
        base.changed_since(&changed_css),
        Some(FingerprintKind::Css)
    );
    assert_eq!(
        base.changed_since(&base),
        None,
        "returning to the same dependency fingerprints does not invalidate"
    );

    let encoded = serde_json::to_value(&base).expect("serialize");
    assert_eq!(encoded["formatVersion"], 1);
    let mut unknown = encoded;
    unknown["unknownDependency"] = json!("x");
    assert!(serde_json::from_value::<FingerprintSet>(unknown).is_err());
}

#[test]
fn document_key_is_project_scoped_canonical_and_derives_the_companion() {
    let key = document_key();
    assert_eq!(key.project_id(), project());
    assert_eq!(key.target_path(), TARGET_PATH);
    assert_eq!(
        key.companion_path(),
        "docs/sdd/specs/2026-11-09-h3-html-sync-design.html"
    );
    assert_eq!(key.activity_id(), document_key().activity_id());
    assert_ne!(key.activity_id(), other_document_key().activity_id());
    assert_ne!(key.digest(), other_document_key().digest());
    key.validate_in(project()).expect("same project");
    assert!(matches!(
        key.validate_in(other_project()),
        Err(H3Error::CrossProject { .. })
    ));

    for invalid in [
        "/absolute.md",
        "../escape.md",
        "docs/../escape.md",
        "docs//double.md",
        "docs\\windows.md",
        "docs/not-markdown.txt",
        "",
        "docs/./dot.md",
    ] {
        assert!(
            DocumentKey::new(project(), invalid).is_err(),
            "{invalid:?} must be rejected"
        );
    }
    assert!(DocumentKey::new(project(), format!("{}.md", "a".repeat(4_096))).is_err());

    let encoded = serde_json::to_value(&key).expect("serialize");
    assert_eq!(encoded["projectId"], project().to_string());
    assert_eq!(encoded["targetPath"], TARGET_PATH);
    let mut unknown = encoded;
    unknown["modelPath"] = json!("/tmp/escape");
    assert!(serde_json::from_value::<DocumentKey>(unknown).is_err());
}

#[test]
fn h3_identifiers_roundtrip_and_reject_other_projects_and_kinds() {
    let ids = ids(project());
    let values = [
        ids.job.to_string(),
        ids.cycle.to_string(),
        ids.generation_one.to_string(),
        ids.publication.to_string(),
        ids.request_one.to_string(),
        ids.candidate_one.to_string(),
    ];
    for value in &values {
        assert!(value.contains(&project().to_string()));
    }
    assert_eq!(
        ids.job.to_string().parse::<herness_html_sync::JobId>().unwrap(),
        ids.job
    );
    assert!(ids.job.to_string().replace("h3_job", "h3_cycle").parse::<herness_html_sync::JobId>().is_err());
    assert!(matches!(
        ids.job.validate_in(other_project()),
        Err(H3Error::CrossProject { .. })
    ));
}

#[test]
fn past_generation_success_is_separate_from_current_synced_applicability() {
    let ids = ids(project());
    let first_source = source("source v1");
    let first = generation(
        ids.generation_one,
        1,
        first_source.clone(),
        authored_fingerprints("<html>1</html>", "{\"unit\":1}"),
    )
    .with_candidate(candidate(
        ids.candidate_one,
        ids.generation_one,
        "<html>1</html>",
        "{\"unit\":1}",
    ))
    .expect("candidate binding")
    .with_h2(h2_reference());
    let first = first.complete(now()).expect("first completion");
    let first = first
        .supersede(Timestamp::from_unix_millis(now().as_unix_millis() + 1))
        .expect("supersede");
    assert!(first.completed());
    assert_eq!(first.status(), GenerationStatus::Superseded);

    let second_source = source_at(2, "source v2");
    let second = generation(
        ids.generation_two,
        2,
        second_source.clone(),
        authored_fingerprints("<html>2</html>", "{\"unit\":2}"),
    )
    .complete(Timestamp::from_unix_millis(now().as_unix_millis() + 2))
    .expect("second completion");

    let synced = synced_document(
        ids.generation_two,
        second_source.clone(),
        second.fingerprints().clone(),
    );
    assert_eq!(synced.state(), H3State::Synced);
    assert!(synced.applicability().is_applicable());
    assert_eq!(
        synced.applicability().reason(),
        &ApplicabilityReason::CurrentSynced
    );
    assert_eq!(synced.generation(), Some(ids.generation_two));

    // A later dependency change invalidates the current success without
    // deleting either historical completion.
    let mut later_fingerprints = second.fingerprints().clone();
    later_fingerprints = FingerprintSet::new(
        later_fingerprints
            .get(FingerprintKind::Settings)
            .unwrap()
            .clone(),
        later_fingerprints
            .get(FingerprintKind::Policy)
            .unwrap()
            .clone(),
        digest("css-v2"),
        later_fingerprints
            .get(FingerprintKind::Resources)
            .unwrap()
            .clone(),
        later_fingerprints
            .get(FingerprintKind::Candidate)
            .cloned(),
        later_fingerprints
            .get(FingerprintKind::Provenance)
            .cloned(),
        later_fingerprints
            .get(FingerprintKind::Evidence)
            .cloned(),
    );
    let pending = H3DocumentState::new(
        document_key(),
        1,
        Some(ids.job),
        Some(ids.cycle),
        Some(ids.generation_two),
        source_at(3, "source v2"),
        later_fingerprints,
        pending_reason(3),
        second.h2().cloned(),
        Vec::new(),
        Applicability::not_applicable(ApplicabilityReason::DependencyChanged {
            fingerprint: FingerprintKind::Css,
        }),
        now(),
    )
    .expect("invalidated document");
    assert_eq!(pending.state(), H3State::Pending);
    assert!(!pending.applicability().is_applicable());
    assert!(first.completed(), "the first past success stays in history");
    assert!(second.completed(), "the second past success stays in history");

    assert!(generation(
        ids.generation_one,
        1,
        first_source,
        fingerprints(),
    )
    .complete(now())
    .and_then(|record| record.complete(now()))
    .is_err());
}

#[test]
fn operation_requests_enforce_scope_revision_and_canonical_idempotency() {
    let ids = ids(project());
    let request = herness_html_sync_tests::fixtures::pause_request(ids.request_one, 1);
    assert_eq!(request.operation().as_str(), "pause");
    assert!(request.operation().requires_expected_revision());
    assert_eq!(request.document(), Some(&document_key()));

    assert!(H3OperationRequest::new(
        ids.request_two,
        project(),
        None,
        Some(1),
        None,
        H3Operation::Pause,
        now(),
    )
    .is_err());
    assert!(H3OperationRequest::new(
        ids.request_two,
        project(),
        Some(document_key()),
        None,
        None,
        H3Operation::Pause,
        now(),
    )
    .is_err());
    assert!(H3OperationRequest::new(
        ids.request_two,
        project(),
        Some(document_key()),
        Some(0),
        None,
        H3Operation::Pause,
        now(),
    )
    .is_err());
    assert!(H3OperationRequest::new(
        ids.request_two,
        project(),
        Some(document_key()),
        None,
        None,
        H3Operation::ListDocuments,
        now(),
    )
    .is_err());
    assert!(H3OperationRequest::new(
        ids.request_two,
        project(),
        Some(document_key()),
        None,
        Some(digest("source")),
        H3Operation::GetDocument,
        now(),
    )
    .is_ok());
    assert!(H3OperationRequest::new(
        ids.request_two,
        other_project(),
        None,
        None,
        None,
        H3Operation::ListDocuments,
        now(),
    )
    .is_err());

    let same = herness_html_sync_tests::fixtures::pause_request(ids.request_one, 1);
    assert_eq!(request.fingerprint(), same.fingerprint());
    let retried_later = H3OperationRequest::new(
        ids.request_one,
        project(),
        Some(document_key()),
        Some(1),
        None,
        H3Operation::Pause,
        Timestamp::from_unix_millis(now().as_unix_millis() + 10_000),
    )
    .expect("retry at a later time");
    assert_eq!(
        request.fingerprint(),
        retried_later.fingerprint(),
        "a retry keeps the same semantic fingerprint"
    );
    let different = herness_html_sync_tests::fixtures::pause_request(ids.request_one, 2);
    assert_ne!(request.fingerprint(), different.fingerprint());

    let result = accepted_result(&request, 2);
    let commit = request_commit(request.clone(), 2);
    assert_eq!(commit.result().final_project_sequence(), 0);
    let stored = commit.stored().expect("stored");
    assert_eq!(stored.fingerprint(), request.fingerprint());
    assert!(!stored.result().duplicate());
    let replay = stored.replay();
    assert!(replay.duplicate());
    assert_eq!(
        replay.outcome(),
        &H3OperationOutcome::Accepted {
            state: H3State::Pending,
            revision: 2,
        }
    );
    assert_eq!(result.outcome(), replay.outcome());

    let other_request = herness_html_sync_tests::fixtures::pause_request(ids.request_two, 1);
    let wrong_result = accepted_result(&other_request, 2);
    assert!(StoredRequestResult::new(request.clone(), wrong_result, now()).is_err());
    assert!(RequestCommit::new(other_request, result).is_err());

    let listed = H3OperationResult::new(
        &request,
        H3OperationOutcome::Accepted {
            state: H3State::Pending,
            revision: 2,
        },
        7,
        now(),
    )
    .expect("result")
    .with_final_project_sequence(9);
    assert_eq!(listed.final_project_sequence(), 9);
}

#[test]
fn publication_journal_links_to_h1_and_never_claims_an_unobserved_success() {
    let ids = ids(project());
    let journal = publication(
        ids.generation_one,
        ids.candidate_one,
        "<html>candidate</html>",
        "{\"unit\":1}",
    );
    assert_eq!(journal.status(), PublicationStatus::Prepared);
    assert_eq!(journal.h1_request_id().as_str(), "h1-publication-1");
    assert!(journal.old_html().is_none());

    let journal = journal.replacing(now()).expect("absent target is replaceable");
    assert!(journal.published(digest("<html>candidate</html>"), now()).is_ok());

    let existing = PublicationJournal::new(
        ids.publication,
        document_key(),
        ids.generation_one,
        ids.candidate_one,
        herness_core::PublicationRequestId::new("h1-publication-2").expect("id"),
        ExpectedTargetVersion::present(herness_core::FileVersion::new("old").expect("version")),
        digest("<html>candidate</html>"),
        digest("{}"),
        source("source v1"),
        now(),
    )
    .expect("journal");
    assert!(existing.clone().replacing(now()).is_err());
    assert!(existing.clone().old_versions_saved(None, None, now()).is_err());
    let saved = existing
        .old_versions_saved(
            Some(
                ArchivedVersionRef::new("history/html-old.json", digest("old-html"))
                    .expect("archive ref"),
            ),
            None,
            now(),
        )
        .expect("old version saved");
    let replacing = saved.replacing(now()).expect("replaceable");
    assert!(replacing.published(digest("<html>candidate</html>"), now()).is_ok());

    assert!(ArchivedVersionRef::new("/absolute.json", digest("x")).is_err());
    assert!(ArchivedVersionRef::new("../escape.json", digest("x")).is_err());
    assert!(journal_with_status().failed(PublicationStatus::Published, "bad", now()).is_err());
}

fn journal_with_status() -> PublicationJournal {
    let ids = ids(project());
    publication(
        ids.generation_one,
        ids.candidate_one,
        "<html>candidate</html>",
        "{\"unit\":1}",
    )
}

#[test]
fn document_state_rejects_inconsistent_applicability_and_cross_project_ids() {
    let ids = ids(project());
    let source = source("source v1");
    let synced = herness_html_sync_tests::fixtures::synced_reason(ids.generation_two, &source);
    assert!(H3DocumentState::new(
        document_key(),
        1,
        Some(ids.job),
        Some(ids.cycle),
        Some(ids.generation_two),
        source.clone(),
        fingers(),
        synced,
        None,
        Vec::new(),
        Applicability::not_applicable(ApplicabilityReason::NeverPublished),
        now(),
    )
    .is_err());

    let other_job = herness_html_sync::JobId::from_parts(other_project(), uuid::Uuid::nil());
    assert!(H3DocumentState::new(
        document_key(),
        1,
        Some(other_job),
        Some(ids.cycle),
        Some(ids.generation_two),
        source.clone(),
        fingers(),
        pending_reason(1),
        None,
        Vec::new(),
        Applicability::not_applicable(ApplicabilityReason::NeverPublished),
        now(),
    )
    .is_err());

    assert!(H3Settings::new(
        project(),
        1,
        true,
        vec!["docs/../escape.md".to_owned()],
        true,
        true,
        now(),
    )
    .is_err());
    let settings = settings(true);
    let enabled = settings.clone().enable(now()).expect("enable");
    assert_eq!(enabled.version(), 2);
    assert_ne!(enabled.fingerprint(), settings.fingerprint());
    let different_scope = H3Settings::new(
        project(),
        1,
        true,
        vec![TARGET_PATH.to_owned(), "docs/adr/0001-test.md".to_owned()],
        true,
        true,
        now(),
    )
    .expect("different scope");
    assert_ne!(different_scope.fingerprint(), settings.fingerprint());
}

fn fingers() -> FingerprintSet {
    fingerprints()
}

#[test]
fn events_use_the_h1_host_activity_envelope_and_h3_kinds() {
    let key = document_key();
    let document = pending_document(source("source v1"));
    let state_event = document_state_event(&key, None, &document, now()).expect("state event");
    assert_eq!(state_event.kind().as_str(), "html_sync.state");
    let subject = state_event
        .subject()
        .host_activity()
        .expect("host activity subject");
    assert_eq!(subject.activity_kind().as_str(), "html_sync.document");
    assert_eq!(subject.activity_id(), key.activity_id());
    assert!(state_event.run_id().is_none());
    assert_eq!(state_event.payload().as_value()["targetPath"], TARGET_PATH);
    assert_eq!(state_event.payload().as_value()["state"], "pending");
    assert_eq!(state_event.payload().as_value()["sourceRevision"], 1);
    assert_eq!(
        state_event.payload().as_value()["sourceDigest"],
        herness_supervision::ContentDigest::sha256(b"source v1").as_str()
    );

    let settings = settings(true);
    let settings_event = settings_event(&settings, now()).expect("settings event");
    assert_eq!(settings_event.kind().as_str(), "html_sync.settings");
    assert_eq!(
        settings_event
            .subject()
            .host_activity()
            .expect("subject")
            .activity_kind()
            .as_str(),
        "html_sync.project"
    );

    let ids = ids(project());
    let journal = publication(
        ids.generation_one,
        ids.candidate_one,
        "<html>candidate</html>",
        "{}",
    );
    let publication_event = publication_event(&journal, now()).expect("publication event");
    assert_eq!(publication_event.kind().as_str(), "html_sync.publication");
    assert_eq!(
        publication_event.payload().as_value()["h1RequestId"],
        "h1-publication-1"
    );
}

#[test]
fn public_document_status_is_versioned_and_carries_sequence_applicability_and_references() {
    let ids = ids(project());
    let source = source("source v1");
    let document = synced_document(
        ids.generation_two,
        source.clone(),
        authored_fingerprints("<html>2</html>", "{}"),
    );
    let record = herness_html_sync::H3DocumentRecord::new(4, 17, document).expect("record");
    let status = record.status();
    assert_eq!(
        serde_json::to_value(&status).expect("serialize")["formatVersion"],
        1
    );
    assert_eq!(status.revision(), 4);
    assert_eq!(status.final_project_sequence(), 17);
    assert_eq!(status.project_id(), project());
    assert_eq!(status.document_key().target_path(), TARGET_PATH);
    assert_eq!(status.state(), H3State::Synced);
    assert_eq!(status.reason().state(), H3State::Synced);
    assert!(status.applicability().is_applicable());
    assert_eq!(status.generation(), Some(ids.generation_two));
    assert_eq!(status.settings_version(), 1);
    assert_eq!(status.source().digest(), source.digest());

    let encoded = serde_json::to_value(&status).expect("serialize");
    let mut unknown = encoded.clone();
    unknown["uiSuccess"] = json!(true);
    assert!(serde_json::from_value::<herness_html_sync::H3DocumentStatus>(unknown).is_err());
    let mut future = encoded;
    future["formatVersion"] = json!(2);
    let bytes = serde_json::to_vec(&future).expect("bytes");
    assert!(matches!(
        decode_record::<herness_html_sync::H3DocumentStatus>(&bytes),
        Err(H3Error::UnsupportedFormat { .. })
    ));
}

#[test]
fn settings_and_operation_results_roundtrip_without_unknown_fields() {
    let request = herness_html_sync_tests::fixtures::pause_request(
        ids(project()).request_one,
        1,
    );
    let result = accepted_result(&request, 2).with_final_project_sequence(4);
    let bytes = serde_json::to_vec(&result).expect("serialize");
    let decoded: H3OperationResult =
        herness_html_sync::decode_record(&bytes).expect("decode result");
    assert_eq!(decoded, result);
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).expect("value");
    unknown["unknown"] = json!(1);
    assert!(serde_json::from_value::<H3OperationResult>(unknown).is_err());

    let settings = settings(true);
    let encoded = serde_json::to_vec(&settings).expect("settings bytes");
    let decoded: H3Settings =
        herness_html_sync::decode_record(&encoded).expect("settings decode");
    assert_eq!(decoded, settings);
    let mut future: serde_json::Value = serde_json::from_slice(&encoded).expect("value");
    future["formatVersion"] = json!(99);
    assert!(matches!(
        decode_record::<H3Settings>(&serde_json::to_vec(&future).unwrap()),
        Err(H3Error::UnsupportedFormat { .. })
    ));
}
