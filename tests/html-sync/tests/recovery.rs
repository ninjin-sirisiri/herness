//! Task 21: quit/crash reconciliation and human resume preflight.
//!
//! The H3 store is the real SQLite store in a temporary data root. Source,
//! candidate, and H2 facts are injected through the same ports the desktop host
//! uses. Separate-process cases spawn this test binary as a child, seed a
//! durable crash boundary, and exit with code 70 without dropping the store.
//! That is an abrupt child exit, not a claim of OS `SIGKILL`; the same-process
//! reopen test is explicitly a simulated restart. No provider, Keychain, real
//! account, network, Tauri window, or GUI is used.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use herness_core::runtime::{ShutdownOutcome, ShutdownReport};
use herness_core::{
    ConnectionAdmin, CredentialAvailability, CredentialPort, ExpectedTargetVersion, ProjectId,
    ResolvedCredential, Timestamp,
};
use herness_html_sync::observer::{DependencyKind, DependencyPath, dependency_fingerprint};
use herness_html_sync::{
    Applicability, ApplicabilityReason, CandidateArtifactStore, CandidateBytes,
    CandidateGenerationRequest, CandidateId, CandidateRecord, CandidateVerification, CycleId,
    CycleLatch, DocumentCommit, DocumentKey, FingerprintSet, GenerationId, GenerationRecord,
    H2RecoveryFacts, H2Reference, H3DocumentRecord, H3DocumentState, H3Error, H3Reason, H3Settings,
    H3SettingsRecord, H3State, H3StateReasonKind, H3StopCause, HtmlSyncCommit, HumanWaitCause,
    PublicationFileJournal, PublicationFileRole, PublicationId, PublicationJournal,
    PublicationStatus, RecoveryBoundary, RecoveryReadPort, RecoveryRuntimePort, RecoveryService,
    RecoverySideEffects, RecoveryStop, RequiredAction, SourceSnapshot, SyncCycle,
};
use herness_html_sync_tests::fixtures;
use herness_store::{Store, StoreConfig};
use herness_supervision::budget::BudgetUsage;
use herness_supervision::{
    BudgetPolicy, ClockPort, ConditionDigest, ConditionVersion, ConsentBinding, ConsentId,
    ContentDigest, DisclosureDataKind, DisclosureScope, ExecutionScope, OwnerKind, OwnerRef,
    ProfileBinding, ProfileId, ProfilePurpose, ProfileVersion, SupervisionState, TargetVersion,
};
use tempfile::TempDir;
use uuid::Uuid;

const TARGET: &str = fixtures::TARGET_PATH;
const SOURCE_V1: &str = "source v1";
const CANDIDATE_HTML: &str = "<html><body>candidate one</body></html>";
const PROVENANCE: &str = "{\"formatVersion\":1,\"units\":[]}";
const RECEIPT: &str = "{\"schema\":\"sdd-html-receipt\",\"version\":1}";

// ---------------------------------------------------------------------------
// Clock, read, and runtime ports.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct FixedClock(Timestamp);

impl ClockPort for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

#[derive(Default)]
struct FakeReads {
    sources: BTreeMap<String, Vec<u8>>,
    html: BTreeMap<String, Vec<u8>>,
    receipts: BTreeMap<String, Vec<u8>>,
    candidates: BTreeMap<CandidateId, CandidateBytes>,
    dependencies: BTreeMap<(String, DependencyKind), ContentDigest>,
}

impl FakeReads {
    fn set_source(&mut self, document: &DocumentKey, bytes: &str) {
        self.sources
            .insert(document.target_path().to_owned(), bytes.as_bytes().to_vec());
    }

    fn set_html(&mut self, document: &DocumentKey, bytes: &str) {
        self.html
            .insert(document.companion_path(), bytes.as_bytes().to_vec());
    }

    fn set_receipt(&mut self, document: &DocumentKey, bytes: &str) {
        self.receipts
            .insert(receipt_path(document), bytes.as_bytes().to_vec());
    }

    fn set_dependency(
        &mut self,
        document: &DocumentKey,
        kind: DependencyKind,
        digest: ContentDigest,
    ) {
        self.dependencies
            .insert((document.target_path().to_owned(), kind), digest);
    }
}

impl RecoveryReadPort for FakeReads {
    fn read_source(&self, document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error> {
        Ok(self.sources.get(document.target_path()).cloned())
    }

    fn read_companion(&self, document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error> {
        Ok(self.html.get(&document.companion_path()).cloned())
    }

    fn read_receipt(&self, document: &DocumentKey) -> Result<Option<Vec<u8>>, H3Error> {
        Ok(self.receipts.get(&receipt_path(document)).cloned())
    }

    fn candidate_bytes(&self, candidate: &CandidateRecord) -> Result<CandidateBytes, H3Error> {
        Ok(self
            .candidates
            .get(&candidate.candidate_id())
            .cloned()
            .unwrap_or(CandidateBytes::Missing))
    }

    fn dependency_digest(
        &self,
        document: &DocumentKey,
        kind: DependencyKind,
        _paths: &[DependencyPath],
    ) -> Result<Option<ContentDigest>, H3Error> {
        Ok(Some(
            self.dependencies
                .get(&(document.target_path().to_owned(), kind))
                .cloned()
                .unwrap_or_else(|| dependency_fingerprint(kind, std::iter::empty())),
        ))
    }
}

#[derive(Default)]
struct FakeRuntime {
    h2: BTreeMap<String, H2RecoveryFacts>,
    stops: BTreeMap<String, RecoveryStop>,
    stop_calls: Arc<AtomicU32>,
}

impl FakeRuntime {
    fn set_h2(&mut self, document: &DocumentKey, facts: H2RecoveryFacts) {
        self.h2.insert(document.target_path().to_owned(), facts);
    }

    fn set_stop(&mut self, document: &DocumentKey, stop: RecoveryStop) {
        self.stops.insert(document.target_path().to_owned(), stop);
    }

    fn stop_calls(&self) -> u32 {
        self.stop_calls.load(Ordering::SeqCst)
    }
}

impl RecoveryRuntimePort for FakeRuntime {
    fn h2_facts(
        &mut self,
        document: &DocumentKey,
        _h2: Option<&H2Reference>,
        _cycle: Option<&SyncCycle>,
    ) -> Result<Option<H2RecoveryFacts>, H3Error> {
        Ok(self.h2.get(document.target_path()).cloned())
    }

    fn request_stop(&mut self, document: &DocumentKey) -> Result<RecoveryStop, H3Error> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .stops
            .get(document.target_path())
            .copied()
            .unwrap_or(RecoveryStop::NotRunning))
    }
}

fn receipt_path(document: &DocumentKey) -> String {
    herness_html_sync::recovery::receipt_path(document)
}

// ---------------------------------------------------------------------------
// Store harness.
// ---------------------------------------------------------------------------

struct Harness {
    _temp: TempDir,
    config: StoreConfig,
    store: Option<Store>,
    reads: FakeReads,
    runtime: FakeRuntime,
    clock: FixedClock,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("store config");
        let store = Store::open(config.clone()).expect("open store");
        Self {
            _temp: temp,
            config,
            store: Some(store),
            reads: FakeReads::default(),
            runtime: FakeRuntime::default(),
            clock: FixedClock(fixtures::now()),
        }
    }

    fn store(&mut self) -> &mut Store {
        self.store.as_mut().expect("open store")
    }

    fn reopen(&mut self) {
        self.store = Some(Store::open(self.config.clone()).expect("reopen store"));
    }

    fn document(&self) -> DocumentKey {
        fixtures::document_key()
    }

    fn dependencies(&self) -> BTreeMap<ProjectId, Vec<DependencyPath>> {
        BTreeMap::from([(fixtures::project(), Vec::new())])
    }

    fn seed_settings(&mut self) {
        let settings = fixtures::settings(true);
        let event = herness_html_sync::settings_event(&settings, fixtures::now()).expect("event");
        self.store()
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_settings(fixtures::settings_commit(settings))
                    .with_events(vec![event]),
            )
            .expect("settings commit");
    }

    fn seed_document(
        &mut self,
        document: H3DocumentState,
        cycle: Option<SyncCycle>,
        generation: Option<GenerationRecord>,
        candidate: Option<CandidateRecord>,
        publication: Option<PublicationJournal>,
    ) {
        self.seed_document_with_request(document, cycle, generation, candidate, publication, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn seed_document_with_request(
        &mut self,
        document: H3DocumentState,
        cycle: Option<SyncCycle>,
        generation: Option<GenerationRecord>,
        candidate: Option<CandidateRecord>,
        publication: Option<PublicationJournal>,
        request: Option<herness_html_sync::RequestCommit>,
    ) {
        let key = document.document_key().clone();
        let event = herness_html_sync::document_state_event(&key, None, &document, fixtures::now())
            .expect("event");
        let mut commit = HtmlSyncCommit::new()
            .with_document(fixtures::document_commit(document))
            .with_events(vec![event]);
        if let Some(cycle) = cycle {
            commit = commit.with_cycle(cycle);
        }
        if let Some(generation) = generation {
            commit = commit.with_generation(generation);
        }
        if let Some(candidate) = candidate {
            commit = commit.with_candidate(candidate);
        }
        if let Some(publication) = publication {
            commit = commit.with_publication(publication);
        }
        if let Some(request) = request {
            commit = commit.with_request(request);
        }
        self.store().commit_html_sync(commit).expect("seed commit");
    }

    fn reconcile(&mut self) -> herness_html_sync::ProjectRecoveryReport {
        let dependencies = self.dependencies();
        let mut service = RecoveryService::new(
            self.store.as_mut().expect("store"),
            &self.reads,
            &mut self.runtime,
            &self.clock,
            &dependencies,
        );
        service
            .reconcile_project(fixtures::project())
            .expect("reconcile project")
    }

    fn quit(&mut self) -> herness_html_sync::QuitProjectReport {
        let confirmed = BTreeMap::new();
        let dependencies = self.dependencies();
        let mut service = RecoveryService::new(
            self.store.as_mut().expect("store"),
            &self.reads,
            &mut self.runtime,
            &self.clock,
            &dependencies,
        );
        service
            .quit_project(fixtures::project(), &confirmed)
            .expect("quit project")
    }

    fn load_document(&self) -> H3DocumentRecord {
        self.store
            .as_ref()
            .expect("store")
            .load_html_sync_document(fixtures::project(), &self.document())
            .expect("load document")
            .expect("document")
    }

    fn document_state(&self) -> H3DocumentState {
        self.load_document().state().clone()
    }
}

// ---------------------------------------------------------------------------
// Fixture builders.
// ---------------------------------------------------------------------------

fn fingerprints() -> FingerprintSet {
    fixtures::fingerprints()
}

fn synced_document(generation: GenerationId) -> H3DocumentState {
    fixtures::synced_document(generation, fixtures::source(SOURCE_V1), fingerprints())
}

fn pending_document() -> H3DocumentState {
    fixtures::pending_document_with(fixtures::source(SOURCE_V1), None)
}

fn document_with_reason(
    state: H3StateReasonKind,
    actions: Vec<RequiredAction>,
    generation: Option<GenerationId>,
    applicability: Applicability,
) -> H3DocumentState {
    let key = fixtures::document_key();
    H3DocumentState::new(
        key.clone(),
        1,
        Some(fixtures::ids(fixtures::project()).job),
        Some(fixtures::ids(fixtures::project()).cycle),
        generation,
        fixtures::source(SOURCE_V1),
        fingerprints(),
        H3Reason::new(state, actions).expect("reason"),
        None,
        Vec::new(),
        applicability,
        fixtures::now(),
    )
    .expect("document")
}

fn active_document(generation: GenerationId) -> H3DocumentState {
    document_with_reason(
        H3StateReasonKind::Authoring { generation },
        vec![],
        Some(generation),
        Applicability::not_applicable(ApplicabilityReason::NeverPublished),
    )
}

fn publishing_document(generation: GenerationId, publication: PublicationId) -> H3DocumentState {
    document_with_reason(
        H3StateReasonKind::Publishing {
            generation,
            publication,
        },
        vec![],
        Some(generation),
        Applicability::not_applicable(ApplicabilityReason::NeverPublished),
    )
}

fn candidate_record(html: &str, provenance: &str) -> CandidateRecord {
    fixtures::candidate(
        fixtures::ids(fixtures::project()).candidate_one,
        fixtures::ids(fixtures::project()).generation_one,
        html,
        provenance,
    )
}

fn completed_generation(
    source: SourceSnapshot,
    candidate: &CandidateRecord,
    publication: Option<PublicationId>,
) -> GenerationRecord {
    let generation = fixtures::generation(
        fixtures::ids(fixtures::project()).generation_one,
        1,
        source,
        fingerprints()
            .with_candidate(candidate.html_digest().clone())
            .with_provenance(candidate.provenance_digest().clone()),
    )
    .with_candidate(candidate.clone())
    .expect("candidate")
    .with_h2(fixtures::h2_reference());
    let generation = if let Some(publication) = publication {
        generation.with_publication(publication)
    } else {
        generation
    };
    generation.complete(fixtures::now()).expect("complete")
}

fn published_journal(candidate: &CandidateRecord, html: &str, receipt: &str) -> PublicationJournal {
    let key = fixtures::document_key();
    let journal = fixtures::publication(
        fixtures::ids(fixtures::project()).generation_one,
        candidate.candidate_id(),
        html,
        PROVENANCE,
    );
    journal
        .with_receipt(
            receipt_path(&key),
            ExpectedTargetVersion::absent(),
            ContentDigest::sha256(receipt.as_bytes()),
            herness_core::PublicationRequestId::new("h1-receipt-1").expect("request"),
            fixtures::now(),
        )
        .expect("receipt")
        .replacing(fixtures::now())
        .expect("replacing")
        .published_pair(
            ContentDigest::sha256(html.as_bytes()),
            ContentDigest::sha256(receipt.as_bytes()),
            Some(7),
            fixtures::now(),
        )
        .expect("published")
}

fn prepared_journal(candidate: &CandidateRecord) -> PublicationJournal {
    fixtures::publication(
        fixtures::ids(fixtures::project()).generation_one,
        candidate.candidate_id(),
        CANDIDATE_HTML,
        PROVENANCE,
    )
}

fn old_version_saved_journal(candidate: &CandidateRecord) -> PublicationJournal {
    prepared_journal(candidate)
        .old_versions_saved(None, None, fixtures::now())
        .expect("old version saved")
}

fn replacing_journal(candidate: &CandidateRecord) -> PublicationJournal {
    old_version_saved_journal(candidate)
        .replacing(fixtures::now())
        .expect("replacing")
}

fn after_one_file_journal(candidate: &CandidateRecord) -> PublicationJournal {
    let key = fixtures::document_key();
    let html = PublicationFileJournal::pending(
        PublicationFileRole::Html,
        key.companion_path(),
        ExpectedTargetVersion::absent(),
        ContentDigest::sha256(CANDIDATE_HTML.as_bytes()),
        None,
        fixtures::now(),
    )
    .expect("pending html")
    .observed(
        ContentDigest::sha256(CANDIDATE_HTML.as_bytes()),
        fixtures::now(),
    );
    let receipt = PublicationFileJournal::pending(
        PublicationFileRole::Receipt,
        receipt_path(&key),
        ExpectedTargetVersion::absent(),
        ContentDigest::sha256(RECEIPT.as_bytes()),
        None,
        fixtures::now(),
    )
    .expect("pending receipt");
    replacing_journal(candidate)
        .with_files(vec![html, receipt])
        .with_receipt(
            receipt_path(&key),
            ExpectedTargetVersion::absent(),
            ContentDigest::sha256(RECEIPT.as_bytes()),
            herness_core::PublicationRequestId::new("h1-receipt-1").expect("request"),
            fixtures::now(),
        )
        .expect("receipt")
}

fn unverifiable_journal(candidate: &CandidateRecord) -> PublicationJournal {
    replacing_journal(candidate).unverifiable("after both writes", fixtures::now())
}

fn h2_facts(
    state: SupervisionState,
    resumable: bool,
    unresolved: Vec<herness_html_sync::H2RequestUnknown>,
    stop_unconfirmed: bool,
    budget: BudgetUsage,
    remaining_active_seconds: u64,
) -> H2RecoveryFacts {
    H2RecoveryFacts::new(
        fixtures::h2_reference().supervision_id(),
        1,
        state,
        resumable,
        unresolved,
        stop_unconfirmed,
        !resumable,
        budget,
        remaining_active_seconds,
        None,
        false,
        true,
        true,
        true,
        true,
        Vec::new(),
    )
    .expect("H2 facts")
}

fn clean_reads(harness: &mut Harness) {
    harness.reads.set_source(&harness.document(), SOURCE_V1);
    harness.reads.set_html(&harness.document(), CANDIDATE_HTML);
    harness.reads.set_receipt(&harness.document(), RECEIPT);
    harness.reads.set_dependency(
        &harness.document(),
        DependencyKind::Css,
        fixtures::digest("css"),
    );
    harness.reads.set_dependency(
        &harness.document(),
        DependencyKind::Resource,
        fixtures::digest("resources"),
    );
    harness.reads.candidates.insert(
        fixtures::ids(fixtures::project()).candidate_one,
        CandidateBytes::Present,
    );
}

#[test]
fn candidate_verification_uses_exact_private_bytes_without_a_raw_token() {
    use herness_core::{ArtifactPort, ArtifactSlot};

    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path().join("candidates");
    let mut store = CandidateArtifactStore::new(&root).expect("candidate store");
    let opened = store
        .open_generation(
            CandidateGenerationRequest::new(
                fixtures::document_key(),
                "h3-recovery-job",
                1,
                Some("task21-token".to_owned()),
                SOURCE_V1,
                Some(CANDIDATE_HTML.to_owned()),
                None,
            )
            .expect("request"),
        )
        .expect("open");
    let handle = opened.handle().clone();
    store
        .write_artifact(&handle, ArtifactSlot::CandidateHtml, CANDIDATE_HTML, None)
        .expect("html");
    store
        .write_artifact(&handle, ArtifactSlot::CandidateProvenance, PROVENANCE, None)
        .expect("provenance");
    let record = CandidateRecord::new(
        fixtures::ids(fixtures::project()).candidate_one,
        fixtures::document_key(),
        fixtures::ids(fixtures::project()).generation_one,
        opened.storage().clone(),
        ContentDigest::sha256(CANDIDATE_HTML.as_bytes()),
        ContentDigest::sha256(PROVENANCE.as_bytes()),
        fixtures::now(),
    )
    .expect("candidate");
    assert_eq!(
        store.verify_candidate_record(&record).expect("verify"),
        CandidateVerification::Present
    );
    let mismatched = CandidateRecord::new(
        fixtures::ids(fixtures::project()).candidate_two,
        fixtures::document_key(),
        fixtures::ids(fixtures::project()).generation_one,
        opened.storage().clone(),
        ContentDigest::sha256(b"different html"),
        ContentDigest::sha256(PROVENANCE.as_bytes()),
        fixtures::now(),
    )
    .expect("candidate");
    assert_eq!(
        store.verify_candidate_record(&mismatched).expect("verify"),
        CandidateVerification::Mismatch {
            html: true,
            provenance: false
        }
    );
    let missing = CandidateRecord::new(
        fixtures::ids(fixtures::project()).candidate_two,
        fixtures::document_key(),
        fixtures::ids(fixtures::project()).generation_one,
        fixtures::candidate_storage(),
        ContentDigest::sha256(CANDIDATE_HTML.as_bytes()),
        ContentDigest::sha256(PROVENANCE.as_bytes()),
        fixtures::now(),
    )
    .expect("candidate");
    assert_eq!(
        store.verify_candidate_record(&missing).expect("verify"),
        CandidateVerification::Missing
    );
}

// ---------------------------------------------------------------------------
// Tests: startup reconciliation and crash boundaries.
// ---------------------------------------------------------------------------

#[test]
fn clean_synced_document_stays_synced_with_zero_side_effects() {
    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(
        fixtures::source(SOURCE_V1),
        &candidate,
        Some(fixtures::ids(fixtures::project()).publication),
    );
    let journal = published_journal(&candidate, CANDIDATE_HTML, RECEIPT);
    // A previously committed operation result is loaded and never replayed.
    let request = fixtures::pause_request(fixtures::ids(fixtures::project()).request_one, 1);
    harness.seed_document_with_request(
        synced_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate),
        Some(journal),
        Some(fixtures::request_commit(request, 2)),
    );

    let report = harness.reconcile();
    assert!(report.side_effects().is_zero());
    assert_eq!(report.request_count(), 0);
    assert_eq!(report.request_results(), 1);
    assert!(report.last_request_sequence().is_some());
    assert!(!report.committed());
    let recovery = &report.documents()[0];
    assert_eq!(recovery.boundaries(), &[RecoveryBoundary::Clean]);
    assert!(!recovery.requires_human());
    assert_eq!(recovery.stored_state(), H3State::Synced);
    assert_eq!(recovery.next_state(), H3State::Synced);
    assert!(!recovery.state_changed());
    assert_eq!(harness.document_state().state(), H3State::Synced);

    // Recovery is read-only for the formal files.
    assert_eq!(
        harness.reads.html[&harness.document().companion_path()],
        CANDIDATE_HTML.as_bytes()
    );
}

#[test]
fn active_work_is_restored_as_waiting_human_and_never_auto_resumed() {
    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(fixtures::source(SOURCE_V1), &candidate, None);
    harness.seed_document(
        active_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate),
        None,
    );

    let report = harness.reconcile();
    assert!(report.side_effects().is_zero());
    assert_eq!(report.request_count(), 0);
    assert!(report.committed());
    let recovery = &report.documents()[0];
    assert!(recovery.requires_human());
    assert!(
        recovery
            .boundaries()
            .contains(&RecoveryBoundary::ActiveWorkRestored)
    );
    assert_eq!(recovery.next_state(), H3State::WaitingHuman);
    assert_eq!(recovery.latch(), Some(CycleLatch::RecoveryReconciliation));
    assert!(
        recovery
            .required_actions()
            .contains(&RequiredAction::ReconcileRecovery)
    );
    let state = harness.document_state();
    assert_eq!(state.state(), H3State::WaitingHuman);
    assert_eq!(
        state.reason().kind(),
        &H3StateReasonKind::WaitingHuman {
            cause: HumanWaitCause::RecoveryReconciliation
        }
    );
    let cycle = harness
        .store
        .as_ref()
        .unwrap()
        .load_html_sync_cycle(
            fixtures::project(),
            fixtures::ids(fixtures::project()).cycle,
        )
        .unwrap()
        .unwrap();
    assert_eq!(cycle.latch(), Some(CycleLatch::RecoveryReconciliation));
}

#[test]
fn pending_publication_intent_is_reconciliation_required_not_success() {
    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(fixtures::source(SOURCE_V1), &candidate, None);
    let journal = prepared_journal(&candidate);
    harness.seed_document(
        publishing_document(
            fixtures::ids(fixtures::project()).generation_one,
            fixtures::ids(fixtures::project()).publication,
        ),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate),
        Some(journal),
    );

    let report = harness.reconcile();
    let recovery = &report.documents()[0];
    assert!(
        recovery
            .boundaries()
            .contains(&RecoveryBoundary::PendingPublicationIntent)
    );
    assert_eq!(recovery.next_state(), H3State::WaitingHuman);
    assert!(report.side_effects().is_zero());
    assert_eq!(report.request_count(), 0);
    let journal = harness
        .store
        .as_ref()
        .unwrap()
        .load_html_sync_publication(
            fixtures::project(),
            fixtures::ids(fixtures::project()).publication,
        )
        .unwrap()
        .unwrap();
    assert_eq!(journal.status(), PublicationStatus::Prepared);
}

#[test]
fn old_version_saved_replacing_after_one_file_and_unverifiable_are_distinct() {
    for (boundary, journal) in [
        (
            RecoveryBoundary::PublicationOldVersionSaved,
            old_version_saved_journal(&candidate_record(CANDIDATE_HTML, PROVENANCE)),
        ),
        (
            RecoveryBoundary::PublicationReplacing,
            replacing_journal(&candidate_record(CANDIDATE_HTML, PROVENANCE)),
        ),
        (
            RecoveryBoundary::PublicationAfterOneFile,
            after_one_file_journal(&candidate_record(CANDIDATE_HTML, PROVENANCE)),
        ),
        (
            RecoveryBoundary::PublicationUnverifiable,
            unverifiable_journal(&candidate_record(CANDIDATE_HTML, PROVENANCE)),
        ),
    ] {
        let mut harness = Harness::new();
        harness.seed_settings();
        clean_reads(&mut harness);
        let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
        let generation = completed_generation(fixtures::source(SOURCE_V1), &candidate, None);
        harness.seed_document(
            publishing_document(
                fixtures::ids(fixtures::project()).generation_one,
                fixtures::ids(fixtures::project()).publication,
            ),
            Some(fixtures::cycle()),
            Some(generation),
            Some(candidate),
            Some(journal),
        );
        let report = harness.reconcile();
        let recovery = &report.documents()[0];
        assert!(
            recovery.boundaries().contains(&boundary),
            "expected {boundary:?}, got {:?}",
            recovery.boundaries()
        );
        assert_eq!(recovery.next_state(), H3State::WaitingHuman);
        assert_ne!(recovery.next_state(), H3State::Synced);
        assert!(report.side_effects().is_zero());
        let stored = harness
            .store
            .as_ref()
            .unwrap()
            .load_html_sync_publication(
                fixtures::project(),
                fixtures::ids(fixtures::project()).publication,
            )
            .unwrap()
            .unwrap();
        assert_ne!(stored.status(), PublicationStatus::Published);
        assert_eq!(
            harness.reads.html[&harness.document().companion_path()],
            CANDIDATE_HTML.as_bytes(),
            "recovery must not roll back or rewrite the formal HTML"
        );
    }
}

#[test]
fn published_journal_without_the_final_sequence_is_not_success() {
    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(
        fixtures::source(SOURCE_V1),
        &candidate,
        Some(fixtures::ids(fixtures::project()).publication),
    );
    let key = fixtures::document_key();
    let journal = prepared_journal(&candidate)
        .with_receipt(
            receipt_path(&key),
            ExpectedTargetVersion::absent(),
            ContentDigest::sha256(RECEIPT.as_bytes()),
            herness_core::PublicationRequestId::new("h1-receipt-1").expect("request"),
            fixtures::now(),
        )
        .expect("receipt")
        .replacing(fixtures::now())
        .expect("replacing")
        .published_pair(
            ContentDigest::sha256(CANDIDATE_HTML.as_bytes()),
            ContentDigest::sha256(RECEIPT.as_bytes()),
            None,
            fixtures::now(),
        )
        .expect("published without sequence");
    harness.seed_document(
        synced_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate),
        Some(journal),
    );
    let report = harness.reconcile();
    let recovery = &report.documents()[0];
    assert!(
        recovery
            .boundaries()
            .contains(&RecoveryBoundary::PublicationPublishedWithoutSequence)
    );
    assert_eq!(recovery.next_state(), H3State::WaitingHuman);
    assert_ne!(recovery.next_state(), H3State::Synced);
    assert!(report.side_effects().is_zero());
}

#[test]
fn missing_candidate_bytes_are_reported_without_regeneration() {
    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    harness
        .reads
        .candidates
        .insert(candidate.candidate_id(), CandidateBytes::Missing);
    let generation = completed_generation(fixtures::source(SOURCE_V1), &candidate, None);
    harness.seed_document(
        active_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate),
        None,
    );

    let report = harness.reconcile();
    let recovery = &report.documents()[0];
    assert!(
        recovery
            .boundaries()
            .contains(&RecoveryBoundary::CandidateMissing)
    );
    assert_eq!(recovery.next_state(), H3State::WaitingHuman);
    assert!(
        recovery
            .required_actions()
            .contains(&RequiredAction::RegenerateCandidate)
    );
    assert_eq!(report.side_effects().candidates_authored, 0);
    assert_eq!(report.request_count(), 0);
}

#[test]
fn stale_source_and_external_html_change_are_explicit_and_preserved() {
    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(
        fixtures::source(SOURCE_V1),
        &candidate,
        Some(fixtures::ids(fixtures::project()).publication),
    );
    harness.seed_document(
        synced_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate.clone()),
        Some(published_journal(&candidate, CANDIDATE_HTML, RECEIPT)),
    );

    // The source changed while the process was closed.
    harness.reads.set_source(&harness.document(), "source v2");
    let report = harness.reconcile();
    let recovery = &report.documents()[0];
    assert!(
        recovery
            .boundaries()
            .contains(&RecoveryBoundary::StaleSource)
    );
    assert_eq!(recovery.next_state(), H3State::WaitingHuman);
    assert_eq!(
        harness.document_state().applicability().reason(),
        &ApplicabilityReason::Superseded {
            generation: fixtures::ids(fixtures::project()).generation_one,
            source_revision: 1,
        }
    );

    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(
        fixtures::source(SOURCE_V1),
        &candidate,
        Some(fixtures::ids(fixtures::project()).publication),
    );
    harness.seed_document(
        synced_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate.clone()),
        Some(published_journal(&candidate, CANDIDATE_HTML, RECEIPT)),
    );
    harness
        .reads
        .set_html(&harness.document(), "<html>external edit</html>");
    let report = harness.reconcile();
    let recovery = &report.documents()[0];
    assert!(
        recovery
            .boundaries()
            .contains(&RecoveryBoundary::ExternalHtmlChange)
    );
    assert_eq!(recovery.next_state(), H3State::WaitingHuman);
    assert!(
        recovery
            .required_actions()
            .iter()
            .any(|action| matches!(action, RequiredAction::ResolveHtmlConflict { .. }))
    );
    assert_eq!(
        harness.reads.html[&harness.document().companion_path()],
        b"<html>external edit</html>",
        "the external edit must not be rolled back"
    );
    let applicability = harness.document_state().applicability().reason().clone();
    assert!(matches!(
        applicability,
        ApplicabilityReason::HtmlChanged { .. }
    ));
}

#[test]
fn request_unknown_and_unconfirmed_stop_preserve_budget_and_never_fake_a_stop() {
    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(fixtures::source(SOURCE_V1), &candidate, None);
    harness.seed_document(
        active_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate),
        None,
    );
    let usage = BudgetUsage::new(
        7,
        1,
        29,
        1,
        herness_supervision::budget::Money::from_micros(50),
        herness_supervision::budget::Money::zero(),
    );
    harness.runtime.set_h2(
        &harness.document(),
        h2_facts(
            SupervisionState::Running,
            false,
            vec![herness_html_sync::H2RequestUnknown::new(
                "attempt-1",
                "send_unknown",
                "Html",
            )],
            false,
            usage,
            7_000,
        ),
    );
    let report = harness.reconcile();
    let recovery = &report.documents()[0];
    assert!(
        recovery
            .boundaries()
            .contains(&RecoveryBoundary::RequestUnknown)
    );
    assert_eq!(recovery.next_state(), H3State::WaitingHuman);
    let facts = recovery.h2().expect("H2 facts");
    assert_eq!(facts.budget(), usage);
    assert_eq!(facts.remaining_active_seconds(), 7_000);
    assert_eq!(report.side_effects().model_requests, 0);

    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(fixtures::source(SOURCE_V1), &candidate, None);
    harness.seed_document(
        active_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate),
        None,
    );
    harness.runtime.set_h2(
        &harness.document(),
        h2_facts(
            SupervisionState::Stopped,
            false,
            Vec::new(),
            true,
            BudgetUsage::empty(),
            7_200,
        ),
    );
    let report = harness.reconcile();
    let recovery = &report.documents()[0];
    assert_eq!(recovery.next_state(), H3State::Stopped);
    assert_eq!(
        harness.document_state().reason().kind(),
        &H3StateReasonKind::Stopped {
            cause: H3StopCause::StopUnconfirmed
        }
    );
    assert!(report.side_effects().is_zero());
}

// ---------------------------------------------------------------------------
// Tests: human resume preflight.
// ---------------------------------------------------------------------------

fn approved_settings() -> H3Settings {
    let project = fixtures::project();
    let owner = OwnerRef::new(OwnerKind::H3HtmlJob, "h3-recovery-job").expect("owner");
    let completion_profile = ProfileBinding::new(
        ProfileId::from_parts(
            project,
            Uuid::parse_str("20000000-0000-4000-8000-00000000000b").expect("uuid"),
        ),
        ProfileVersion::new(1).expect("profile version"),
        ProfilePurpose::Completion,
    );
    let completion_consent = ConsentBinding::new(
        ConsentId::from_parts(
            project,
            Uuid::parse_str("20000000-0000-4000-8000-00000000000a").expect("uuid"),
        ),
        1,
        ProfilePurpose::Completion,
        TargetVersion::new(1).expect("target"),
    );
    let html_profile = ProfileBinding::new(
        ProfileId::from_parts(
            project,
            Uuid::parse_str("20000000-0000-4000-8000-00000000000c").expect("uuid"),
        ),
        ProfileVersion::new(1).expect("profile version"),
        ProfilePurpose::Html,
    );
    let html_consent = ConsentBinding::new(
        ConsentId::from_parts(
            project,
            Uuid::parse_str("20000000-0000-4000-8000-00000000000d").expect("uuid"),
        ),
        1,
        ProfilePurpose::Html,
        TargetVersion::new(1).expect("target"),
    );
    let authoring = herness_html_sync::H3ConnectionApproval::new(
        project,
        herness_core::ConnectionId::new(),
        herness_supervision::ProviderOrigin::parse("https://api.openai.com").expect("origin"),
        DisclosureScope::new(
            ProfilePurpose::Completion,
            std::collections::BTreeSet::from([DisclosureDataKind::Text]),
            vec![TARGET.to_owned()],
            TargetVersion::new(1).expect("target"),
        )
        .expect("disclosure"),
        completion_profile,
        completion_consent,
    )
    .expect("authoring");
    let assessment = herness_html_sync::H3ConnectionApproval::new(
        project,
        herness_core::ConnectionId::new(),
        herness_supervision::ProviderOrigin::parse("https://api.openai.com").expect("origin"),
        DisclosureScope::new(
            ProfilePurpose::Html,
            std::collections::BTreeSet::from([DisclosureDataKind::Text]),
            vec![TARGET.to_owned()],
            TargetVersion::new(1).expect("target"),
        )
        .expect("disclosure"),
        html_profile,
        html_consent,
    )
    .expect("assessment");
    let scope =
        ExecutionScope::new(project, vec![TARGET.to_owned()], Vec::new(), false).expect("scope");
    let binding = herness_html_sync::H3OwnerBinding::new(
        project,
        owner,
        "h3-recovery-job",
        ConditionVersion::new(1).expect("conditions"),
        ConditionDigest::sha256(b"recovery-conditions"),
        scope,
        1,
        BudgetPolicy::h2_default(),
    )
    .expect("binding");
    let approval = herness_html_sync::H3ConfigurationApproval::approve(
        herness_html_sync::H3ConfigurationDraft {
            project_id: project,
            settings_version: 1,
            approval_id: "approval-recovery".to_owned(),
            expires_at: None,
            targets: vec![TARGET.to_owned()],
            authoring,
            assessment,
            versions: herness_html_sync::H3VersionBinding::new(
                "sdd-herness-integration",
                1,
                1,
                "sdd-html-policy-v1",
                ContentDigest::sha256(b"recovery-policy"),
                1,
                ContentDigest::sha256(b"recovery-pack"),
                "sdd-html-host-api",
                1,
            )
            .expect("versions"),
            limits: herness_html_sync::H3ApprovalLimits::default(),
            auto_publish: false,
            retain_history: true,
            automatic_companion: true,
            owner: binding,
        },
        herness_html_sync::H3Approver::Human,
        Timestamp::now(),
    )
    .expect("approval");
    H3Settings::approved(approval, true).expect("settings")
}

fn approved_job(settings: &H3Settings) -> herness_html_sync::AuthoringJob {
    herness_html_sync::AuthoringJob::from_settings(
        settings,
        fixtures::h2_reference().supervision_id(),
        fixtures::now(),
    )
    .expect("job")
}

fn restored_document(settings: &H3Settings) -> H3DocumentState {
    let generation = fixtures::ids(fixtures::project()).generation_one;
    H3DocumentState::new(
        fixtures::document_key(),
        settings.version(),
        Some(fixtures::ids(fixtures::project()).job),
        Some(fixtures::ids(fixtures::project()).cycle),
        None,
        fixtures::source(SOURCE_V1),
        FingerprintSet::new(
            settings.fingerprint().clone(),
            ContentDigest::sha256(b"recovery-policy"),
            fixtures::digest("css"),
            fixtures::digest("resources"),
            None,
            None,
            None,
        ),
        H3Reason::new(
            H3StateReasonKind::WaitingHuman {
                cause: HumanWaitCause::RecoveryReconciliation,
            },
            vec![RequiredAction::ReassessCandidate],
        )
        .expect("reason"),
        None,
        Vec::new(),
        Applicability::not_applicable(ApplicabilityReason::Restored { generation }),
        fixtures::now(),
    )
    .expect("document")
}

fn resume_preflight(
    harness: &mut Harness,
    settings: &H3Settings,
    observed_source: SourceSnapshot,
    h2: Option<H2RecoveryFacts>,
) -> herness_html_sync::ResumePreflight {
    let job = approved_job(settings);
    let document = harness.load_document();
    let key = harness.document();
    let dependencies = harness.dependencies();
    let mut service = RecoveryService::new(
        harness.store.as_mut().expect("store"),
        &harness.reads,
        &mut harness.runtime,
        &harness.clock,
        &dependencies,
    );
    service
        .resume_preflight(herness_html_sync::ResumePreflightRequest {
            document: &key,
            expected_revision: document.revision(),
            job: &job,
            settings: &H3SettingsRecord::new(1, settings.clone()).expect("record"),
            observed_source: &observed_source,
            policy_version: "sdd-html-policy-v1",
            policy_digest: &ContentDigest::sha256(b"recovery-policy"),
            pack_digest: &ContentDigest::sha256(b"recovery-pack"),
            h2: h2.as_ref(),
            current_authoring_profile: None,
            current_authoring_consent: None,
            current_html_profile: None,
            current_html_consent: None,
            now: fixtures::now(),
        })
        .expect("preflight")
}

#[test]
fn human_resume_preflight_allows_a_current_restored_document_only() {
    let mut harness = Harness::new();
    let settings = approved_settings();
    let event = herness_html_sync::settings_event(&settings, fixtures::now()).expect("event");
    harness
        .store()
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_settings(
                    herness_html_sync::SettingsCommit::new(None, settings.clone()).unwrap(),
                )
                .with_events(vec![event]),
        )
        .unwrap();
    clean_reads(&mut harness);
    harness.seed_document(
        restored_document(&settings),
        Some(fixtures::cycle()),
        None,
        None,
        None,
    );
    let facts = h2_facts(
        SupervisionState::WaitingHuman,
        true,
        Vec::new(),
        false,
        BudgetUsage::new(
            100,
            0,
            2,
            0,
            herness_supervision::budget::Money::zero(),
            herness_supervision::budget::Money::zero(),
        ),
        7_000,
    );
    let preflight = resume_preflight(
        &mut harness,
        &settings,
        fixtures::source(SOURCE_V1),
        Some(facts),
    );
    assert!(preflight.allowed(), "blocks: {:?}", preflight.blocks());
    assert_eq!(preflight.state(), H3State::WaitingHuman);
    assert!(
        preflight
            .required_actions()
            .contains(&RequiredAction::ReassessCandidate)
    );
    assert!(preflight.side_effects().is_zero());
}

#[test]
fn human_resume_preflight_blocks_stale_source_consent_profile_policy_and_budget() {
    let mut harness = Harness::new();
    let settings = approved_settings();
    let event = herness_html_sync::settings_event(&settings, fixtures::now()).expect("event");
    harness
        .store()
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_settings(
                    herness_html_sync::SettingsCommit::new(None, settings.clone()).unwrap(),
                )
                .with_events(vec![event]),
        )
        .unwrap();
    clean_reads(&mut harness);
    harness.seed_document(
        restored_document(&settings),
        Some(fixtures::cycle()),
        None,
        None,
        None,
    );

    // Stale source.
    let preflight = resume_preflight(&mut harness, &settings, fixtures::source("source v2"), None);
    assert!(!preflight.allowed());
    assert!(
        preflight
            .blocks()
            .contains(&herness_html_sync::ResumeBlock::StaleSource)
    );

    // Consent/profile/approval/budget blocks.
    let bad = H2RecoveryFacts::new(
        fixtures::h2_reference().supervision_id(),
        1,
        SupervisionState::Stopped,
        false,
        vec![herness_html_sync::H2RequestUnknown::new(
            "attempt-2",
            "intent_only",
            "Html",
        )],
        false,
        true,
        BudgetUsage::new(
            30,
            1,
            31,
            0,
            herness_supervision::budget::Money::zero(),
            herness_supervision::budget::Money::zero(),
        ),
        0,
        None,
        true,
        false,
        false,
        false,
        false,
        vec!["consent_changed".to_owned()],
    )
    .expect("facts");
    let preflight = resume_preflight(
        &mut harness,
        &settings,
        fixtures::source(SOURCE_V1),
        Some(bad),
    );
    assert!(!preflight.allowed());
    for block in [
        herness_html_sync::ResumeBlock::RequestUnknown,
        herness_html_sync::ResumeBlock::PermissionsChanged,
        herness_html_sync::ResumeBlock::ProfileChanged,
        herness_html_sync::ResumeBlock::ConsentChanged,
        herness_html_sync::ResumeBlock::ApprovalChanged,
        herness_html_sync::ResumeBlock::BudgetExhausted,
        herness_html_sync::ResumeBlock::H2RecoveryPending,
    ] {
        assert!(preflight.blocks().contains(&block), "missing {block:?}");
    }

    // Policy/pack identity changes block even when source/settings match.
    let current = fixtures::h2_reference();
    let _ = current;
    let document = harness.load_document();
    let key = harness.document();
    let job = approved_job(&settings);
    let dependencies = harness.dependencies();
    let mut service = RecoveryService::new(
        harness.store.as_mut().expect("store"),
        &harness.reads,
        &mut harness.runtime,
        &harness.clock,
        &dependencies,
    );
    let preflight = service
        .resume_preflight(herness_html_sync::ResumePreflightRequest {
            document: &key,
            expected_revision: document.revision(),
            job: &job,
            settings: &H3SettingsRecord::new(1, settings.clone()).expect("record"),
            observed_source: &fixtures::source(SOURCE_V1),
            policy_version: "sdd-html-policy-v2",
            policy_digest: &ContentDigest::sha256(b"other-policy"),
            pack_digest: &ContentDigest::sha256(b"other-pack"),
            h2: None,
            current_authoring_profile: None,
            current_authoring_consent: None,
            current_html_profile: None,
            current_html_consent: None,
            now: fixtures::now(),
        })
        .expect("preflight");
    assert!(
        preflight
            .blocks()
            .contains(&herness_html_sync::ResumeBlock::PolicyChanged)
    );
    assert!(
        preflight
            .blocks()
            .contains(&herness_html_sync::ResumeBlock::PackChanged)
    );
}

#[test]
fn human_resume_preflight_blocks_changed_authoring_and_html_bindings() {
    let mut harness = Harness::new();
    let settings = approved_settings();
    let event = herness_html_sync::settings_event(&settings, fixtures::now()).expect("event");
    harness
        .store()
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_settings(
                    herness_html_sync::SettingsCommit::new(None, settings.clone()).unwrap(),
                )
                .with_events(vec![event]),
        )
        .unwrap();
    clean_reads(&mut harness);
    harness.seed_document(
        restored_document(&settings),
        Some(fixtures::cycle()),
        None,
        None,
        None,
    );
    let project = fixtures::project();
    let other_profile = ProfileBinding::new(
        ProfileId::from_parts(project, Uuid::nil()),
        ProfileVersion::new(2).expect("version"),
        ProfilePurpose::Html,
    );
    let other_consent = ConsentBinding::new(
        ConsentId::from_parts(project, Uuid::max()),
        2,
        ProfilePurpose::Html,
        TargetVersion::new(1).expect("target"),
    );
    let document = harness.load_document();
    let key = harness.document();
    let job = approved_job(&settings);
    let dependencies = harness.dependencies();
    let mut service = RecoveryService::new(
        harness.store.as_mut().expect("store"),
        &harness.reads,
        &mut harness.runtime,
        &harness.clock,
        &dependencies,
    );
    let preflight = service
        .resume_preflight(herness_html_sync::ResumePreflightRequest {
            document: &key,
            expected_revision: document.revision(),
            job: &job,
            settings: &H3SettingsRecord::new(1, settings.clone()).expect("record"),
            observed_source: &fixtures::source(SOURCE_V1),
            policy_version: "sdd-html-policy-v1",
            policy_digest: &ContentDigest::sha256(b"recovery-policy"),
            pack_digest: &ContentDigest::sha256(b"recovery-pack"),
            h2: None,
            current_authoring_profile: Some(&other_profile),
            current_authoring_consent: Some(&other_consent),
            current_html_profile: Some(&other_profile),
            current_html_consent: Some(&other_consent),
            now: fixtures::now(),
        })
        .expect("preflight");
    assert!(!preflight.allowed());
    assert!(
        preflight
            .blocks()
            .contains(&herness_html_sync::ResumeBlock::ProfileChanged)
    );
    assert!(
        preflight
            .blocks()
            .contains(&herness_html_sync::ResumeBlock::ConsentChanged)
    );
}

// ---------------------------------------------------------------------------
// Tests: quit.
// ---------------------------------------------------------------------------

#[test]
fn quit_marks_active_work_stopped_and_reports_unconfirmed_stops() {
    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(fixtures::source(SOURCE_V1), &candidate, None);
    harness.seed_document(
        active_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate),
        None,
    );
    harness
        .runtime
        .set_stop(&harness.document(), RecoveryStop::Unconfirmed);

    let report = harness.quit();
    assert_eq!(report.model_requests(), 0);
    assert_eq!(report.publications(), 0);
    assert_eq!(report.stop_requests(), 1);
    assert_eq!(harness.runtime.stop_calls(), 1);
    assert_eq!(report.unconfirmed(), &[harness.document()]);
    assert!(report.committed());
    assert_eq!(harness.document_state().state(), H3State::Stopped);
    assert_eq!(
        harness.document_state().reason().kind(),
        &H3StateReasonKind::Stopped {
            cause: H3StopCause::StopUnconfirmed
        }
    );
    let cycle = harness
        .store
        .as_ref()
        .unwrap()
        .load_html_sync_cycle(
            fixtures::project(),
            fixtures::ids(fixtures::project()).cycle,
        )
        .unwrap()
        .unwrap();
    assert_eq!(cycle.latch(), Some(CycleLatch::RecoveryReconciliation));
}

#[test]
fn quit_grace_is_still_ten_seconds_and_a_confirmed_stop_is_saved() {
    use herness_desktop::lifecycle::quit::{DEFAULT_QUIT_GRACE, QuitCoordinator, QuitStage};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    #[derive(Clone)]
    struct ManualClock(Arc<AtomicU64>);
    impl herness_desktop::lifecycle::quit::QuitClock for ManualClock {
        fn now_millis(&self) -> u64 {
            self.0.load(AtomicOrdering::SeqCst)
        }
    }

    assert_eq!(DEFAULT_QUIT_GRACE.as_secs(), 10);
    let clock = ManualClock(Arc::new(AtomicU64::new(0)));
    let coordinator = QuitCoordinator::new(clock.clone(), DEFAULT_QUIT_GRACE);
    assert_eq!(
        coordinator.begin_if_idle().expect("begin").stage(),
        QuitStage::Stopping
    );
    clock.0.fetch_add(9_999, AtomicOrdering::SeqCst);
    assert_eq!(coordinator.snapshot().stage(), QuitStage::Stopping);
    clock.0.fetch_add(1, AtomicOrdering::SeqCst);
    assert_eq!(coordinator.snapshot().stage(), QuitStage::AwaitingChoice);

    // The H3 hook saves a confirmed stop honestly.
    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(fixtures::source(SOURCE_V1), &candidate, None);
    harness.seed_document(
        active_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate),
        None,
    );
    harness
        .runtime
        .set_stop(&harness.document(), RecoveryStop::Confirmed);
    let report = harness.quit();
    assert!(report.unconfirmed().is_empty());
    assert_eq!(harness.document_state().state(), H3State::Stopped);
    assert_eq!(
        harness.document_state().reason().kind(),
        &H3StateReasonKind::Stopped {
            cause: H3StopCause::RecoveryReconciliation
        }
    );
}

// ---------------------------------------------------------------------------
// Tests: lost notification queue and observer rescan.
// ---------------------------------------------------------------------------

#[test]
fn observer_rescan_recovers_a_missed_change_but_a_restored_latch_holds_it() {
    use herness_html_sync::observer::{
        ObservationClock, ObservationEligibility, ObservationTargets, ProjectObserver,
        SourceReadPort,
    };
    use herness_html_sync::{HeldAuthoring, SyncCoordinator};
    use herness_supervision::ClockReading;
    use std::sync::atomic::AtomicU64;

    struct Reader(BTreeMap<String, Vec<u8>>);
    impl SourceReadPort for Reader {
        fn read(
            &self,
            path: &str,
        ) -> Result<herness_html_sync::FileRead, herness_html_sync::SourceReadError> {
            Ok(herness_html_sync::FileRead::new(
                self.0.get(path).cloned().unwrap_or_default(),
                true,
            ))
        }
    }
    #[derive(Clone)]
    struct Clock(Arc<AtomicU64>);
    impl ObservationClock for Clock {
        fn read(&self) -> ClockReading {
            ClockReading::new(fixtures::now(), self.0.load(Ordering::SeqCst))
        }
    }

    let document = fixtures::document_key();
    let targets = ObservationTargets::new(fixtures::project(), vec![document.clone()], Vec::new())
        .expect("targets");
    let clock = Clock(Arc::new(AtomicU64::new(0)));
    let reader = Reader(BTreeMap::from([(
        document.target_path().to_owned(),
        b"source v1".to_vec(),
    )]));
    let mut observer = ProjectObserver::new(
        targets,
        ObservationEligibility::approved(1).expect("eligibility"),
        reader,
        clock.clone(),
    )
    .expect("observer");
    let initial = observer.initial_scan();
    assert_eq!(initial.sources.len(), 1);

    // The process was closed; the edit notification was lost.
    let reader2 = Reader(BTreeMap::from([(
        document.target_path().to_owned(),
        b"source v2".to_vec(),
    )]));
    let mut restarted = ProjectObserver::new(
        ObservationTargets::new(fixtures::project(), vec![document.clone()], Vec::new())
            .expect("targets"),
        ObservationEligibility::approved(1).expect("eligibility"),
        reader2,
        clock.clone(),
    )
    .expect("observer");
    restarted
        .seed_source(&document, fixtures::source(SOURCE_V1))
        .expect("seed source");
    clock.0.fetch_add(5_000, Ordering::SeqCst);
    let scan = restarted.poll();
    assert!(
        !scan.sources.is_empty(),
        "the periodic scan recovers the missed source revision"
    );
    assert!(
        scan.sources
            .iter()
            .any(|source| source.document == document)
    );

    // A restart latch from stored H3 state holds the rescan until a human
    // clears it. The observer scan itself never starts anything.
    let mut coordinator = SyncCoordinator::new();
    coordinator.seed_latch(HeldAuthoring {
        document: document.clone(),
        latch: Some(CycleLatch::RecoveryReconciliation),
        detail: "restart recovery".to_owned(),
    });
    for source in &scan.sources {
        assert_eq!(
            coordinator.offer(source),
            herness_html_sync::OfferOutcome::Held {
                latch: CycleLatch::RecoveryReconciliation,
                detail: "restart recovery".to_owned(),
            }
        );
    }
    assert_eq!(coordinator.queued_documents(), Vec::new());
    coordinator.clear_latch(&document);
    assert!(coordinator.latch(&document).is_none());
}

// ---------------------------------------------------------------------------
// Tests: separate-process crash boundaries.
// ---------------------------------------------------------------------------

fn task21_worker_main() {
    let Ok(mode) = std::env::var("HERNESS_TASK21_WORKER") else {
        return;
    };
    let app_data = PathBuf::from(worker_env("HERNESS_TASK21_APP_DATA"));
    let project = PathBuf::from(worker_env("HERNESS_TASK21_PROJECT"));
    let candidate_root = PathBuf::from(worker_env("HERNESS_TASK21_CANDIDATES"));
    worker_seed(&mode, &app_data, &project, &candidate_root);
    println!("TASK21_WORKER_CRASHED: pid={}", std::process::id());
    std::process::exit(70);
}

fn worker_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn worker_seed(mode: &str, app_data: &Path, project_root: &Path, candidate_root: &Path) {
    fs::create_dir_all(project_root.join("docs/sdd/specs")).expect("project");
    fs::write(project_root.join(TARGET), SOURCE_V1).expect("source");
    fs::write(
        project_root.join(fixtures::document_key().companion_path()),
        CANDIDATE_HTML,
    )
    .expect("html");
    let receipt = receipt_path(&fixtures::document_key());
    fs::create_dir_all(
        project_root
            .join(&receipt)
            .parent()
            .expect("receipt parent"),
    )
    .expect("receipt dir");
    fs::write(project_root.join(&receipt), RECEIPT).expect("receipt");

    let config = StoreConfig::new(app_data).expect("config");
    let mut store = Store::open(config).expect("store");
    let settings = fixtures::settings(true);
    let event = herness_html_sync::settings_event(&settings, fixtures::now()).expect("event");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_settings(fixtures::settings_commit(settings))
                .with_events(vec![event]),
        )
        .expect("settings");
    let ids = fixtures::ids(fixtures::project());
    let document_key = fixtures::document_key();
    let candidate = if mode == "missing-candidate" {
        CandidateRecord::new(
            ids.candidate_one,
            document_key.clone(),
            ids.generation_one,
            fixtures::candidate_storage(),
            ContentDigest::sha256(CANDIDATE_HTML.as_bytes()),
            ContentDigest::sha256(PROVENANCE.as_bytes()),
            fixtures::now(),
        )
        .expect("candidate")
        .with_h1_run(herness_core::RunId::from_parts(
            fixtures::project(),
            Uuid::parse_str("80000000-0000-4000-8000-000000000001").unwrap(),
        ))
    } else {
        use herness_core::{ArtifactPort, ArtifactSlot};
        let mut artifacts = CandidateArtifactStore::new(candidate_root).expect("candidate store");
        let opened = artifacts
            .open_generation(
                CandidateGenerationRequest::new(
                    document_key.clone(),
                    "h3-recovery-job",
                    1,
                    Some("task21-token".to_owned()),
                    SOURCE_V1,
                    Some(CANDIDATE_HTML.to_owned()),
                    None,
                )
                .expect("candidate request"),
            )
            .expect("open generation");
        let handle = opened.handle().clone();
        artifacts
            .write_artifact(&handle, ArtifactSlot::CandidateHtml, CANDIDATE_HTML, None)
            .expect("candidate html");
        artifacts
            .write_artifact(&handle, ArtifactSlot::CandidateProvenance, PROVENANCE, None)
            .expect("provenance");
        CandidateRecord::new(
            ids.candidate_one,
            document_key.clone(),
            ids.generation_one,
            opened.storage().clone(),
            ContentDigest::sha256(CANDIDATE_HTML.as_bytes()),
            ContentDigest::sha256(PROVENANCE.as_bytes()),
            fixtures::now(),
        )
        .expect("candidate")
        .with_h1_run(herness_core::RunId::from_parts(
            fixtures::project(),
            Uuid::parse_str("80000000-0000-4000-8000-000000000001").unwrap(),
        ))
    };
    let generation = completed_generation(fixtures::source(SOURCE_V1), &candidate, None);
    let journal = match mode {
        "prepared" => Some(prepared_journal(&candidate)),
        "old-version-saved" => Some(old_version_saved_journal(&candidate)),
        "replacing" => Some(replacing_journal(&candidate)),
        "after-one-file" => Some(after_one_file_journal(&candidate)),
        "unverifiable" => Some(unverifiable_journal(&candidate)),
        _ => None,
    };
    let document = match mode {
        "pending-cycle" => pending_document(),
        "active-work" | "missing-candidate" | "request-unknown" | "stop-unconfirmed" => {
            active_document(ids.generation_one)
        }
        _ => publishing_document(ids.generation_one, ids.publication),
    };
    let event = herness_html_sync::document_state_event(
        &fixtures::document_key(),
        None,
        &document,
        fixtures::now(),
    )
    .expect("event");
    let mut commit = HtmlSyncCommit::new()
        .with_document(fixtures::document_commit(document))
        .with_cycle(fixtures::cycle())
        .with_generation(generation)
        .with_candidate(candidate.clone())
        .with_events(vec![event]);
    if let Some(journal) = journal {
        commit = commit.with_publication(journal);
    }
    store.commit_html_sync(commit).expect("seed crash state");
}

#[test]
fn task21_worker_entrypoint() {
    task21_worker_main();
}

struct CrashFixture {
    _temp: TempDir,
    project: PathBuf,
    app_data: PathBuf,
    candidates: PathBuf,
}

impl CrashFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let project = temp.path().join("project");
        let app_data = temp.path().join("app-data");
        let candidates = temp.path().join("candidates");
        fs::create_dir_all(&project).expect("project");
        fs::create_dir_all(&app_data).expect("app data");
        fs::create_dir_all(&candidates).expect("candidates");
        Self {
            _temp: temp,
            project,
            app_data,
            candidates,
        }
    }

    fn crash(&self, mode: &str) -> Output {
        Command::new(std::env::current_exe().expect("test exe"))
            .arg("--exact")
            .arg("task21_worker_entrypoint")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("HERNESS_TASK21_WORKER", mode)
            .env("HERNESS_TASK21_APP_DATA", &self.app_data)
            .env("HERNESS_TASK21_PROJECT", &self.project)
            .env("HERNESS_TASK21_CANDIDATES", &self.candidates)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn crash worker")
    }
}

fn recover_crash_fixture(
    fixture: &CrashFixture,
    mode: &str,
) -> herness_html_sync::ProjectRecoveryReport {
    let config = StoreConfig::new(&fixture.app_data).expect("config");
    let mut store = Store::open(config).expect("reopen store");
    let mut reads = FakeReads::default();
    reads.set_source(&fixtures::document_key(), SOURCE_V1);
    reads.set_html(&fixtures::document_key(), CANDIDATE_HTML);
    reads.set_receipt(&fixtures::document_key(), RECEIPT);
    reads.set_dependency(
        &fixtures::document_key(),
        DependencyKind::Css,
        fixtures::digest("css"),
    );
    reads.set_dependency(
        &fixtures::document_key(),
        DependencyKind::Resource,
        fixtures::digest("resources"),
    );
    if mode != "missing-candidate" {
        reads.candidates.insert(
            fixtures::ids(fixtures::project()).candidate_one,
            CandidateBytes::Present,
        );
    }
    let mut runtime = FakeRuntime::default();
    if mode == "request-unknown" {
        runtime.set_h2(
            &fixtures::document_key(),
            h2_facts(
                SupervisionState::Running,
                false,
                vec![herness_html_sync::H2RequestUnknown::new(
                    "attempt-child",
                    "send_unknown",
                    "Html",
                )],
                false,
                BudgetUsage::new(
                    12,
                    0,
                    31,
                    0,
                    herness_supervision::budget::Money::zero(),
                    herness_supervision::budget::Money::zero(),
                ),
                7_188,
            ),
        );
    }
    if mode == "stop-unconfirmed" {
        runtime.set_h2(
            &fixtures::document_key(),
            h2_facts(
                SupervisionState::Stopped,
                false,
                Vec::new(),
                true,
                BudgetUsage::empty(),
                7_200,
            ),
        );
    }
    let dependencies = BTreeMap::from([(fixtures::project(), Vec::new())]);
    let clock = FixedClock(fixtures::now());
    let mut service = RecoveryService::new(&mut store, &reads, &mut runtime, &clock, &dependencies);
    service
        .reconcile_project(fixtures::project())
        .expect("reconcile crashed state")
}

#[test]
fn separate_process_crashes_reconcile_every_publication_boundary() {
    for (mode, expected) in [
        ("prepared", RecoveryBoundary::PendingPublicationIntent),
        (
            "old-version-saved",
            RecoveryBoundary::PublicationOldVersionSaved,
        ),
        ("replacing", RecoveryBoundary::PublicationReplacing),
        ("after-one-file", RecoveryBoundary::PublicationAfterOneFile),
        ("unverifiable", RecoveryBoundary::PublicationUnverifiable),
    ] {
        let fixture = CrashFixture::new();
        let output = fixture.crash(mode);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(70),
            "child must exit abruptly (not cleanly) for {mode}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(stdout.contains("TASK21_WORKER_CRASHED"));
        let report = recover_crash_fixture(&fixture, mode);
        let recovery = &report.documents()[0];
        assert!(
            recovery.boundaries().contains(&expected),
            "mode {mode}: expected {expected:?}, got {:?}",
            recovery.boundaries()
        );
        assert_eq!(recovery.next_state(), H3State::WaitingHuman);
        assert!(report.side_effects().is_zero());
        assert_eq!(report.request_count(), 0);
        // Formal files are never rolled back.
        assert_eq!(
            fs::read(
                fixture
                    .project
                    .join(fixtures::document_key().companion_path())
            )
            .unwrap(),
            CANDIDATE_HTML.as_bytes()
        );
        // The journal is still not a success.
        let config = StoreConfig::new(&fixture.app_data).unwrap();
        let store = Store::open(config).unwrap();
        let journal = store
            .load_html_sync_publication(
                fixtures::project(),
                fixtures::ids(fixtures::project()).publication,
            )
            .unwrap()
            .unwrap();
        assert_ne!(journal.status(), PublicationStatus::Published);
    }
}

#[test]
fn separate_process_missing_candidate_and_unknown_request_are_not_fabricated() {
    for mode in ["missing-candidate", "request-unknown", "stop-unconfirmed"] {
        let fixture = CrashFixture::new();
        let output = fixture.crash(mode);
        assert_eq!(output.status.code(), Some(70), "mode {mode}");
        let report = recover_crash_fixture(&fixture, mode);
        let recovery = &report.documents()[0];
        match mode {
            "missing-candidate" => {
                assert!(
                    recovery
                        .boundaries()
                        .contains(&RecoveryBoundary::CandidateMissing)
                );
                assert_eq!(recovery.next_state(), H3State::WaitingHuman);
            }
            "request-unknown" => {
                assert!(
                    recovery
                        .boundaries()
                        .contains(&RecoveryBoundary::RequestUnknown)
                );
                assert_eq!(recovery.next_state(), H3State::WaitingHuman);
                assert_eq!(
                    recovery.h2().expect("facts").budget(),
                    BudgetUsage::new(
                        12,
                        0,
                        31,
                        0,
                        herness_supervision::budget::Money::zero(),
                        herness_supervision::budget::Money::zero()
                    )
                );
            }
            "stop-unconfirmed" => {
                assert_eq!(recovery.next_state(), H3State::Stopped);
                let config = StoreConfig::new(&fixture.app_data).unwrap();
                let store = Store::open(config).unwrap();
                let document = store
                    .load_html_sync_document(fixtures::project(), &fixtures::document_key())
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    document.state().reason().kind(),
                    &H3StateReasonKind::Stopped {
                        cause: H3StopCause::StopUnconfirmed
                    }
                );
            }
            _ => unreachable!(),
        }
        assert!(report.side_effects().is_zero());
        assert_eq!(report.request_count(), 0);
    }
}

struct UnavailableCredentials;

impl CredentialPort for UnavailableCredentials {
    fn availability(
        &self,
        _connection: &herness_core::ConnectionId,
    ) -> Result<CredentialAvailability, herness_core::CoreError> {
        Ok(CredentialAvailability::Unavailable)
    }

    fn resolve(
        &self,
        _connection: &herness_core::ConnectionId,
    ) -> Result<ResolvedCredential, herness_core::CoreError> {
        Err(herness_core::CoreError::InvalidValue {
            field: "credential".to_owned(),
            violation: herness_core::ArgumentViolation::Invalid {
                detail: "the recovery test has no credential".to_owned(),
            },
        })
    }
}

fn empty_shutdown_report() -> ShutdownReport {
    ShutdownReport::new(
        ShutdownOutcome::Completed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        0,
        0,
    )
}

#[test]
fn desktop_startup_and_pump_run_without_a_window_and_report_the_saved_latch() {
    use herness_desktop::host::DesktopHost;
    use herness_engine_pi::ProviderEndpoints;

    let temp = tempfile::tempdir().expect("temporary directory");
    let app_data = temp.path().join("app-data");
    let project_root = temp.path().join("project");
    fs::create_dir_all(project_root.join("docs/sdd/specs")).expect("project");
    fs::write(project_root.join(TARGET), SOURCE_V1).expect("source");
    fs::write(
        project_root.join(fixtures::document_key().companion_path()),
        CANDIDATE_HTML,
    )
    .expect("html");
    let receipt = receipt_path(&DocumentKey::new(fixtures::project(), TARGET).unwrap());
    fs::create_dir_all(project_root.join(&receipt).parent().unwrap()).expect("evidence dir");
    fs::write(project_root.join(&receipt), RECEIPT).expect("receipt");
    let credentials: Arc<dyn CredentialPort + Send + Sync> = Arc::new(UnavailableCredentials);
    let endpoints =
        ProviderEndpoints::for_loopback("http://127.0.0.1:1/v1", "http://127.0.0.1:1").unwrap();

    // First process: open the project and save its durable identity.
    let (mut host, _) = DesktopHost::open(
        &app_data,
        ConnectionAdmin::new(),
        Arc::clone(&credentials),
        endpoints.clone(),
    )
    .expect("first host");
    let view = host.open_project(&project_root).expect("open project");
    let project = view.project_id();
    drop(host);

    // Seed a pending H3 cycle as if the process had quit mid-cycle.
    let config = StoreConfig::new(&app_data).expect("config");
    let mut store = Store::open(config).expect("store");
    let settings = H3Settings::new(
        project,
        1,
        true,
        vec![TARGET.to_owned()],
        false,
        true,
        fixtures::now(),
    )
    .expect("settings");
    let document = H3DocumentState::new(
        DocumentKey::new(project, TARGET).expect("document"),
        1,
        None,
        Some(CycleId::from_parts(project, Uuid::nil())),
        None,
        fixtures::source(SOURCE_V1),
        FingerprintSet::new(
            settings.fingerprint().clone(),
            ContentDigest::sha256(b"recovery-policy"),
            fixtures::digest("css"),
            fixtures::digest("resources"),
            None,
            None,
            None,
        ),
        H3Reason::new(
            H3StateReasonKind::Pending { source_revision: 1 },
            Vec::new(),
        )
        .expect("reason"),
        None,
        Vec::new(),
        Applicability::not_applicable(ApplicabilityReason::NeverPublished),
        fixtures::now(),
    )
    .expect("document");
    let cycle = SyncCycle::new(
        CycleId::from_parts(project, Uuid::nil()),
        DocumentKey::new(project, TARGET).expect("document"),
        1,
        fixtures::now(),
        fixtures::source(SOURCE_V1),
        None,
    )
    .expect("cycle");
    let event = herness_html_sync::document_state_event(
        document.document_key(),
        None,
        &document,
        fixtures::now(),
    )
    .expect("event");
    store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(DocumentCommit::new(None, document).expect("commit"))
                .with_cycle(cycle)
                .with_events(vec![event]),
        )
        .expect("seed pending cycle");
    drop(store);

    // Second process: startup recovery runs with no window at all, and the
    // host pump continues without a UI selection.
    let (mut host, _) =
        DesktopHost::open(&app_data, ConnectionAdmin::new(), credentials, endpoints)
            .expect("restored host");
    let startup = host.html_sync_startup().expect("startup report").clone();
    assert_eq!(startup.request_count(), 0);
    assert!(startup.failures().is_empty());
    let persisted = host.store_handle();
    let record = persisted
        .lock()
        .load_html_sync_document(project, &DocumentKey::new(project, TARGET).unwrap())
        .expect("load")
        .expect("document");
    assert_eq!(record.state().state(), H3State::WaitingHuman);
    assert_eq!(
        record.state().reason().kind(),
        &H3StateReasonKind::WaitingHuman {
            cause: HumanWaitCause::RecoveryReconciliation
        }
    );
    // The pump is window-free and performs no provider request.
    host.pump().expect("host pump");
    // A quit hook saves the already-latched document honestly; there was no
    // active H1 run to stop, so it is not claimed as a new stop.
    host.mark_html_sync_for_quit(&empty_shutdown_report())
        .expect("H3 quit hook");
    let record = persisted
        .lock()
        .load_html_sync_document(project, &DocumentKey::new(project, TARGET).unwrap())
        .expect("load")
        .expect("document");
    assert_eq!(record.state().state(), H3State::WaitingHuman);
}

#[test]
fn same_process_reopen_is_a_simulated_restart_and_is_reported_honestly() {
    let mut harness = Harness::new();
    harness.seed_settings();
    clean_reads(&mut harness);
    let candidate = candidate_record(CANDIDATE_HTML, PROVENANCE);
    let generation = completed_generation(fixtures::source(SOURCE_V1), &candidate, None);
    harness.seed_document(
        active_document(fixtures::ids(fixtures::project()).generation_one),
        Some(fixtures::cycle()),
        Some(generation),
        Some(candidate),
        None,
    );
    // Reopen the same durable store in this process. This is not a crash: the
    // previous handle is dropped normally.
    harness.reopen();
    let report = harness.reconcile();
    assert_eq!(report.request_count(), 0);
    assert_eq!(report.documents()[0].next_state(), H3State::WaitingHuman);
    assert_eq!(report.side_effects(), RecoverySideEffects::zero());
}
