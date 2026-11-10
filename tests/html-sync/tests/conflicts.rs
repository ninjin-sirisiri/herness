//! Task 20 conflict, adoption, history restore, and orphan tests.
//!
//! The real Common SDD pack is used read-only. No provider, Keychain, login, or
//! external network is used: H2 results are synthetic all-met fixtures bound to
//! a native-shaped render fixture. The tests report that distinction rather
//! than claiming a real WKWebView or real-model evaluation.

#![cfg(unix)]

mod support;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use herness_core::ports::publish::{PublicationArchivePort, PublicationGatePort};
use herness_core::runtime::PublicationWriter;
use herness_core::{
    ConnectionId, ExpectedTargetVersion, OldVersionArchive, PublicationFailure, PublicationRequest,
    PublicationRequestId, RunControl, hash_bytes,
};
use herness_desktop::html_sync::policy::HtmlPolicyBridge;
use herness_desktop::html_sync::publish::{
    H3PublicationRecords, PolicyFinalCheck, ProjectPublicationFiles, SharedHistoryArchive,
};
use herness_desktop::supervision::store::StoreHandle;
use herness_html_sync::ids::GenerationId;
use herness_html_sync::{
    Applicability, ApplicabilityReason, CandidateId, CandidateRecord, CandidateStorageRef,
    CurrentHtmlAdoption, CurrentHtmlValidation, CycleId, DocumentCommit, DocumentKey,
    EvidenceFingerprints, ExpectedPublicationWrite, FingerprintSet, H2Reference, H3ApprovalLimits,
    H3Approver, H3ConfigurationApproval, H3ConfigurationDraft, H3ConnectionApproval,
    H3DocumentRecord, H3DocumentState, H3Error, H3Operation, H3OperationRequest, H3OwnerBinding,
    H3Reason, H3RequestId, H3Settings, H3State, H3StateReasonKind, H3StorePort, H3VersionBinding,
    HOST_API_PROTOCOL, HOST_API_VERSION, HistoryReadPort, HistoryRestoreOutcome, HistoryVersion,
    HtmlSyncCommit, HtmlSyncCommitOutcome, JobId, PACK_INTEGRATION_SCHEMA, PACK_POLICY_VERSION,
    PublicationFileInput, PublicationFileRole, PublicationId, PublicationJournal,
    PublicationOrchestrator, PublicationOutcome, PublicationPolicyIdentity, PublicationSafety,
    PublicationSafetyPort, PublicationSafetyRequest, PublicationWriteExpectationPort, RubricSet,
    SourceJobControlPort, SourceRevision, SourceSnapshot, SourceStop, dependency_fingerprint,
    html_evidence_path, record_external_html_conflict, record_source_removal,
    replace_with_regenerated, restore_history,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::ids::{ConsentId, ProfileId};
use herness_supervision::profiles::{ProfileBinding, ProfilePurpose, ProfileVersion};
use herness_supervision::{
    BudgetPolicy, ContentDigest, DisclosureDataKind, DisclosureScope, ExecutionScope, OwnerKind,
    OwnerRef, ProviderOrigin,
};
use tempfile::TempDir;
use uuid::Uuid;

use support::{
    AdrFixture, REAL_PACK_ROOT, TARGET_PATH, build_pack_with_fingerprints, condition_binding,
    condition_digest, condition_version, document_key, now, pass_and_native_checks,
    positive_evaluation, project, real_pack_present, source_units, supervision, target_version,
    toolchain,
};

const JOB: &str = "job-20";
const EXTRA_TARGET: &str = "docs/adr/0002-keep.md";

fn fver(digest: &ContentDigest) -> herness_core::FileVersion {
    herness_core::FileVersion::new(digest.as_str()).expect("file version")
}

fn skip_without_pack() -> bool {
    if real_pack_present() {
        false
    } else {
        eprintln!("skip conflicts test: real pack absent");
        true
    }
}

fn profile(purpose: ProfilePurpose) -> ProfileBinding {
    let seed = match purpose {
        ProfilePurpose::Html => "91000000-0000-4000-8000-000000000001",
        ProfilePurpose::Completion => "91000000-0000-4000-8000-000000000002",
        ProfilePurpose::Permission => "91000000-0000-4000-8000-000000000003",
    };
    ProfileBinding::new(
        ProfileId::from_parts(project(), Uuid::parse_str(seed).expect("profile uuid")),
        ProfileVersion::new(1).expect("profile version"),
        purpose,
    )
}

fn connection_approval(purpose: ProfilePurpose, origin: &str) -> H3ConnectionApproval {
    let target_version = target_version();
    H3ConnectionApproval::new(
        project(),
        ConnectionId::new(),
        ProviderOrigin::parse(origin).expect("origin"),
        DisclosureScope::new(
            purpose,
            BTreeSet::from([DisclosureDataKind::Text, DisclosureDataKind::Image]),
            vec![TARGET_PATH.to_owned(), EXTRA_TARGET.to_owned()],
            target_version,
        )
        .expect("disclosure"),
        profile(purpose),
        herness_supervision::consent::ConsentBinding::new(
            ConsentId::new(project()),
            1,
            purpose,
            target_version,
        ),
    )
    .expect("connection approval")
}

fn approval(policy: ContentDigest, pack: ContentDigest) -> H3ConfigurationApproval {
    H3ConfigurationApproval::approve(
        H3ConfigurationDraft {
            project_id: project(),
            settings_version: 1,
            approval_id: "approval-20".to_owned(),
            expires_at: None,
            targets: vec![TARGET_PATH.to_owned(), EXTRA_TARGET.to_owned()],
            authoring: connection_approval(ProfilePurpose::Completion, "https://authoring.example"),
            assessment: connection_approval(ProfilePurpose::Html, "https://assessment.example"),
            versions: H3VersionBinding::new(
                PACK_INTEGRATION_SCHEMA,
                1,
                1,
                PACK_POLICY_VERSION,
                policy,
                1,
                pack,
                HOST_API_PROTOCOL,
                HOST_API_VERSION,
            )
            .expect("version binding"),
            limits: H3ApprovalLimits::default(),
            auto_publish: true,
            retain_history: true,
            automatic_companion: true,
            owner: H3OwnerBinding::new(
                project(),
                OwnerRef::new(OwnerKind::H3HtmlJob, JOB).expect("owner"),
                JOB,
                condition_version(),
                condition_digest(),
                ExecutionScope::new(
                    project(),
                    vec![TARGET_PATH.to_owned(), EXTRA_TARGET.to_owned()],
                    vec!["private/html-sync/candidates".to_owned()],
                    false,
                )
                .expect("execution scope"),
                1,
                BudgetPolicy::h2_default(),
            )
            .expect("owner binding"),
        },
        H3Approver::Human,
        now(),
    )
    .expect("approval")
}

struct Env {
    _app: TempDir,
    _archive: TempDir,
    fixture: AdrFixture,
    store: StoreHandle,
    settings: H3Settings,
    document: DocumentKey,
    policy: PublicationPolicyIdentity,
    css: PublicationFileInput,
    source: Vec<u8>,
    candidate_html: String,
    provenance: String,
    applied: herness_html_sync::AppliedEvaluation,
    archive_root: PathBuf,
    final_check: PolicyFinalCheck,
    control: RunControl,
    receipt_path: String,
}

impl Env {
    fn new() -> Self {
        let fixture = AdrFixture::new();
        let app = TempDir::new().expect("app data");
        let config = StoreConfig::new(app.path().join("app-data")).expect("store config");
        config
            .ensure_outside_project(&fixture.root)
            .expect("app data outside project");
        let store = Store::open(config).expect("open store");
        let mut handle = StoreHandle::new(Arc::new(Mutex::new(store)));

        let bridge = HtmlPolicyBridge::detect(&fixture.root, REAL_PACK_ROOT, toolchain())
            .expect("detect pack");
        let probe = bridge.probe();
        let policy = PublicationPolicyIdentity::new(
            PACK_POLICY_VERSION,
            probe.policy_fingerprint().clone(),
            probe.pack_fingerprint().clone(),
        )
        .expect("policy identity");
        let approved = approval(policy.digest().clone(), policy.pack().clone());
        let connected = bridge
            .connect(&approved.pack_binding())
            .expect("connect real pack");
        let settings = H3Settings::approved(approved.clone(), true).expect("settings");
        let budget = herness_supervision::BudgetLedgerRecord::new(BudgetPolicy::h2_default(), 1)
            .expect("budget ledger");
        handle
            .lock()
            .compare_and_swap_budget_record(project(), supervision(), None, &budget)
            .expect("seed budget");
        handle
            .commit_html_sync(
                HtmlSyncCommit::new().with_settings(
                    herness_html_sync::SettingsCommit::new(None, settings.clone())
                        .expect("settings commit"),
                ),
            )
            .expect("store settings");

        let source = fs::read(fixture.root.join(TARGET_PATH)).expect("source");
        let css_bytes = fs::read(fixture.root.join("docs/sdd/assets/sdd.css")).expect("shared css");
        let css =
            PublicationFileInput::new("docs/sdd/assets/sdd.css", css_bytes).expect("css input");
        let css_fp = dependency_fingerprint(
            herness_html_sync::DependencyKind::Css,
            [(css.path(), css.digest())],
        );
        let resources_fp = dependency_fingerprint(herness_html_sync::DependencyKind::Resource, []);
        let candidate_html = fixture.candidate_html().to_owned();
        let provenance = support::provenance_payload(&candidate_html);
        let candidate_digest = ContentDigest::sha256(candidate_html.as_bytes());
        let provenance_digest = ContentDigest::sha256(provenance.as_bytes());
        let source_digest = ContentDigest::sha256(&source);
        let evidence_fingerprints = EvidenceFingerprints::new(
            settings.fingerprint().clone(),
            policy.digest().clone(),
            policy.pack().clone(),
            css_fp.clone(),
            resources_fp.clone(),
            candidate_digest.clone(),
            provenance_digest.clone(),
            source_digest.clone(),
            RubricSet::approved().digest(),
            profile(ProfilePurpose::Html),
            condition_version(),
            condition_digest(),
            target_version(),
        );
        let units = source_units(&connected, &fixture);
        let render = support::fixture_native_render_with_dependencies(
            &fixture,
            css_fp.clone(),
            resources_fp.clone(),
        );
        let (structural, render_check) = pass_and_native_checks();
        let pack = build_pack_with_fingerprints(
            &fixture,
            &units,
            render,
            structural,
            render_check,
            condition_binding(),
            condition_digest(),
            project(),
            evidence_fingerprints,
        )
        .expect("evidence pack");
        let applied = positive_evaluation(&pack);
        let final_check = PolicyFinalCheck::new(connected);
        let control = RunControl::new();
        let receipt_path = html_evidence_path(&document_key());
        let archive = TempDir::new().expect("archive temp");
        let archive_root = archive.path().to_path_buf();
        Self {
            _app: app,
            _archive: archive,
            fixture,
            store: handle,
            settings,
            document: document_key(),
            policy,
            css,
            source,
            candidate_html,
            provenance,
            applied,
            archive_root,
            final_check,
            control,
            receipt_path,
        }
    }

    fn document_record(&self) -> H3DocumentRecord {
        self.store
            .lock()
            .load_html_sync_document(project(), &self.document)
            .expect("document")
            .expect("stored document")
    }

    fn generation_id(&self, seed: u128) -> GenerationId {
        GenerationId::from_parts(
            project(),
            Uuid::from_u128(seed | 0x9000_0000_0000_4000_8000_0000_0000_0000),
        )
    }

    fn candidate_id(&self, seed: u128) -> CandidateId {
        CandidateId::from_parts(
            project(),
            Uuid::from_u128(seed | 0xa000_0000_0000_4000_8000_0000_0000_0000),
        )
    }

    fn publication_id(&self, seed: u128) -> PublicationId {
        PublicationId::from_parts(
            project(),
            Uuid::from_u128(seed | 0xb000_0000_0000_4000_8000_0000_0000_0000),
        )
    }

    fn cycle_id(&self, seed: u128) -> CycleId {
        CycleId::from_parts(
            project(),
            Uuid::from_u128(seed | 0xc000_0000_0000_4000_8000_0000_0000_0000),
        )
    }

    fn job_id(&self, seed: u128) -> JobId {
        JobId::from_parts(
            project(),
            Uuid::from_u128(seed | 0xd000_0000_0000_4000_8000_0000_0000_0000),
        )
    }

    fn candidate_record(
        &self,
        seed: u128,
        generation: GenerationId,
        html_digest: &ContentDigest,
        provenance_digest: &ContentDigest,
    ) -> CandidateRecord {
        CandidateRecord::new(
            self.candidate_id(seed),
            self.document.clone(),
            generation,
            CandidateStorageRef::new("e".repeat(64), ContentDigest::sha256(b"candidate-token"))
                .expect("storage ref"),
            html_digest.clone(),
            provenance_digest.clone(),
            now(),
        )
        .expect("candidate record")
    }

    fn h2(&self) -> H2Reference {
        H2Reference::new(
            project(),
            supervision(),
            None,
            Some(condition_version()),
            Some(target_version()),
            Some(1),
            None,
        )
        .expect("h2 reference")
    }

    fn generation_record(
        &self,
        number: u64,
        html_digest: &ContentDigest,
        provenance_digest: &ContentDigest,
        fingerprints: FingerprintSet,
        completed: bool,
    ) -> herness_html_sync::GenerationRecord {
        let generation = self.generation_id(u128::from(number));
        herness_html_sync::GenerationRecord::new(
            generation,
            self.document.clone(),
            number,
            self.cycle_id(u128::from(number)),
            self.job_id(u128::from(number)),
            SourceSnapshot::new(
                SourceRevision::new(1).expect("source revision"),
                ContentDigest::sha256(&self.source),
            ),
            fingerprints,
            if completed {
                herness_html_sync::GenerationStatus::Completed
            } else {
                herness_html_sync::GenerationStatus::Active
            },
            completed,
            now(),
        )
        .expect("generation")
        .with_candidate(self.candidate_record(
            u128::from(number),
            generation,
            html_digest,
            provenance_digest,
        ))
        .expect("generation candidate")
        .with_h2(self.h2())
    }

    fn fingerprints(
        &self,
        candidate: &ContentDigest,
        provenance: &ContentDigest,
    ) -> FingerprintSet {
        let evidence = self.applied.binding().post_verification().digest();
        FingerprintSet::new(
            self.settings.fingerprint().clone(),
            self.policy.digest().clone(),
            self.applied.binding().post_verification().css().clone(),
            self.applied
                .binding()
                .post_verification()
                .resources()
                .clone(),
            Some(candidate.clone()),
            Some(provenance.clone()),
            Some(evidence),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn document_state(
        &self,
        reason: H3Reason,
        applicability: Applicability,
        source: SourceSnapshot,
        fingerprints: FingerprintSet,
        generation: Option<GenerationId>,
        job: Option<JobId>,
        cycle: Option<CycleId>,
    ) -> H3DocumentState {
        H3DocumentState::new(
            self.document.clone(),
            self.settings.version(),
            job,
            cycle,
            generation,
            source,
            fingerprints,
            reason,
            Some(self.h2()),
            Vec::new(),
            applicability,
            now(),
        )
        .expect("document state")
    }

    fn store_new_document(&self, state: H3DocumentState) -> H3DocumentRecord {
        let mut store = self.store.clone();
        match store
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_document(DocumentCommit::new(None, state).expect("document commit")),
            )
            .expect("store document")
        {
            HtmlSyncCommitOutcome::Applied { document, .. } => document.expect("stored document"),
            HtmlSyncCommitOutcome::Duplicate { .. } => panic!("unexpected duplicate"),
        }
    }

    fn set_companion(&self, bytes: &[u8]) {
        fs::write(
            self.fixture.root.join(self.document.companion_path()),
            bytes,
        )
        .expect("write companion");
    }

    fn companion(&self) -> Option<Vec<u8>> {
        fs::read(self.fixture.root.join(self.document.companion_path())).ok()
    }

    fn source_bytes(&self) -> Vec<u8> {
        fs::read(self.fixture.root.join(self.document.target_path())).expect("source")
    }

    fn set_receipt(&self, bytes: &[u8]) {
        let path = self.fixture.root.join(&self.receipt_path);
        fs::create_dir_all(path.parent().expect("parent")).expect("evidence dir");
        fs::write(path, bytes).expect("write receipt");
    }

    fn receipt(&self) -> Option<Vec<u8>> {
        fs::read(self.fixture.root.join(&self.receipt_path)).ok()
    }

    fn adoption(
        &self,
        generation: herness_html_sync::GenerationRecord,
        publication: PublicationId,
        expected_html: ExpectedTargetVersion,
        expected_receipt: ExpectedTargetVersion,
    ) -> CurrentHtmlAdoption {
        let html_digest = ContentDigest::sha256(self.candidate_html.as_bytes());
        let source_digest = ContentDigest::sha256(&self.source);
        CurrentHtmlAdoption::new(
            self.document_record().revision(),
            publication,
            generation,
            self.candidate_html.clone(),
            self.provenance.clone(),
            self.source.clone(),
            vec![self.css.clone()],
            Vec::new(),
            self.policy.clone(),
            self.applied.clone(),
            CurrentHtmlValidation::new(
                html_digest,
                source_digest,
                "semantic-v1",
                true,
                true,
                true,
                Vec::new(),
                "fixture:real pack structural stage",
                "python -B scripts/html-docs host-api (structural candidate-check)",
                now(),
            )
            .expect("validation"),
            expected_html,
            expected_receipt,
        )
        .expect("adoption")
    }

    fn replacement_attempt(
        &self,
        generation: herness_html_sync::GenerationRecord,
        publication: PublicationId,
        expected_html: ExpectedTargetVersion,
        expected_receipt: ExpectedTargetVersion,
    ) -> herness_html_sync::CandidatePublication {
        herness_html_sync::CandidatePublication::new(
            publication,
            self.document.clone(),
            self.document_record().revision(),
            self.settings.version(),
            generation,
            self.candidate_html.clone(),
            self.provenance.clone(),
            self.source.clone(),
            vec![self.css.clone()],
            Vec::new(),
            self.policy.clone(),
            self.applied.clone(),
            expected_html,
            expected_receipt,
        )
        .expect("replacement attempt")
        .with_explicit_resolution()
    }

    fn connect_bridge(&self) -> herness_desktop::html_sync::policy::ConnectedPolicyBridge {
        let bridge = HtmlPolicyBridge::detect(&self.fixture.root, REAL_PACK_ROOT, toolchain())
            .expect("detect pack");
        let approved = approval(self.policy.digest().clone(), self.policy.pack().clone());
        bridge
            .connect(&approved.pack_binding())
            .expect("connect real pack")
    }

    fn archive_files(&self) -> Vec<PathBuf> {
        let directory = self.archive_root.join(project().to_string());
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir(directory) {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    files.push(entry.path());
                }
            }
        }
        files.sort();
        files
    }
}

#[derive(Default)]
struct RecordingExpectations {
    expected: Vec<ExpectedPublicationWrite>,
    retired: Vec<PublicationId>,
}

impl PublicationWriteExpectationPort for RecordingExpectations {
    fn expect(&mut self, write: ExpectedPublicationWrite) -> Result<(), H3Error> {
        self.expected.push(write);
        Ok(())
    }

    fn retire(&mut self, publication: PublicationId) {
        self.retired.push(publication);
    }
}

struct AllowsAll;

impl PublicationSafetyPort for AllowsAll {
    fn recheck(
        &self,
        _request: &PublicationSafetyRequest<'_>,
    ) -> Result<PublicationSafety, H3Error> {
        Ok(PublicationSafety {
            stop_requested: false,
            consent_current: true,
            approval_current: true,
            budget_remaining: true,
        })
    }
}

struct AllowGate;

impl PublicationGatePort for AllowGate {
    fn authorize_publication(
        &self,
        _request: &PublicationRequest,
    ) -> Result<(), herness_core::PublicationFailure> {
        Ok(())
    }
}

struct CountingArchive<A: PublicationArchivePort> {
    inner: A,
    saves: usize,
}

impl<A: PublicationArchivePort> CountingArchive<A> {
    fn new(inner: A) -> Self {
        Self { inner, saves: 0 }
    }
}

impl<A: PublicationArchivePort> PublicationArchivePort for CountingArchive<A> {
    fn save_old_version(
        &mut self,
        archive: &herness_core::OldVersionArchive<'_>,
    ) -> Result<herness_core::ArchivedVersion, herness_core::PublicationFailure> {
        self.saves += 1;
        self.inner.save_old_version(archive)
    }
}

struct FailingArchive {
    inner: SharedHistoryArchive,
    fail_on: usize,
    saves: usize,
}

impl FailingArchive {
    fn new(inner: SharedHistoryArchive, fail_on: usize) -> Self {
        Self {
            inner,
            fail_on,
            saves: 0,
        }
    }
}

impl PublicationArchivePort for FailingArchive {
    fn save_old_version(
        &mut self,
        archive: &OldVersionArchive<'_>,
    ) -> Result<herness_core::ArchivedVersion, PublicationFailure> {
        self.saves += 1;
        if self.saves == self.fail_on {
            return Err(PublicationFailure::OldVersionSaveFailed {
                detail: "injected history capacity failure".to_owned(),
            });
        }
        self.inner.save_old_version(archive)
    }
}

struct CountingWriter<W: herness_html_sync::HostPublicationPort> {
    inner: W,
    calls: usize,
}

impl<W: herness_html_sync::HostPublicationPort> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, calls: 0 }
    }
}

impl<W: herness_html_sync::HostPublicationPort> herness_html_sync::HostPublicationPort
    for CountingWriter<W>
{
    fn publish(
        &mut self,
        request: PublicationRequest,
    ) -> Result<herness_core::PublicationResult, herness_core::PublicationFailure> {
        self.calls += 1;
        self.inner.publish(request)
    }
}

fn files(env: &Env) -> ProjectPublicationFiles {
    ProjectPublicationFiles::new(&env.fixture.root).expect("project files")
}

fn history_archive(env: &Env) -> SharedHistoryArchive {
    SharedHistoryArchive::new(&env.archive_root).expect("history archive")
}

fn writer<G: PublicationGatePort>(
    env: &Env,
    records: H3PublicationRecords,
    archive: SharedHistoryArchive,
    gate: G,
) -> PublicationWriter<H3PublicationRecords, SharedHistoryArchive, G> {
    PublicationWriter::new(
        project(),
        herness_core::ProjectRoot::new(&env.fixture.root).expect("project root"),
        records,
        archive,
        gate,
        env.control.clone(),
    )
    .expect("publication writer")
}

fn replace_direct(
    env: &Env,
    attempt: herness_html_sync::CandidatePublication,
    expectations: &mut dyn PublicationWriteExpectationPort,
) -> Result<PublicationOutcome, H3Error> {
    let files = files(env);
    let mut store = env.store.clone();
    let mut archive = history_archive(env);
    let mut writer = writer(
        env,
        H3PublicationRecords::new(env.store.clone()),
        history_archive(env),
        AllowGate,
    );
    let mut orchestrator = PublicationOrchestrator {
        store: &mut store,
        files: &files,
        archive: &mut archive,
        host: &mut writer,
        final_check: &env.final_check,
        safety: &AllowsAll,
        expectations,
        control: &env.control,
    };
    replace_with_regenerated(&mut orchestrator, attempt, now())
}

fn adopt_direct(
    env: &Env,
    adoption: CurrentHtmlAdoption,
    expectations: &mut dyn PublicationWriteExpectationPort,
) -> Result<herness_html_sync::AdoptionOutcome, H3Error> {
    let files = files(env);
    let mut store = env.store.clone();
    let mut archive = history_archive(env);
    let mut writer = writer(
        env,
        H3PublicationRecords::new(env.store.clone()),
        history_archive(env),
        AllowGate,
    );
    let mut orchestrator = PublicationOrchestrator {
        store: &mut store,
        files: &files,
        archive: &mut archive,
        host: &mut writer,
        final_check: &env.final_check,
        safety: &AllowsAll,
        expectations,
        control: &env.control,
    };
    herness_html_sync::adopt_current_html(&mut orchestrator, adoption, now())
}

fn waiting_conflict_state(
    env: &Env,
    generation: herness_html_sync::GenerationRecord,
    candidate: &ContentDigest,
    provenance: &ContentDigest,
    job: JobId,
    cycle: CycleId,
) -> H3DocumentState {
    env.document_state(
        H3Reason::new(
            H3StateReasonKind::WaitingHuman {
                cause: herness_html_sync::HumanWaitCause::ExternalHtmlConflict,
            },
            vec![herness_html_sync::RequiredAction::ResolveHtmlConflict {
                target: env.document.companion_path(),
            }],
        )
        .expect("conflict reason"),
        Applicability::not_applicable(ApplicabilityReason::NeverPublished),
        SourceSnapshot::new(
            SourceRevision::new(1).expect("source revision"),
            ContentDigest::sha256(&env.source),
        ),
        env.fingerprints(candidate, provenance),
        Some(generation.generation_id()),
        Some(job),
        Some(cycle),
    )
}

#[test]
fn an_external_edit_during_authoring_is_waiting_human_and_never_overwrites() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let candidate = ContentDigest::sha256(env.candidate_html.as_bytes());
    let provenance = ContentDigest::sha256(env.provenance.as_bytes());
    let generation = env.generation_record(
        1,
        &candidate,
        &provenance,
        env.fingerprints(&candidate, &provenance),
        false,
    );
    let state = env.document_state(
        H3Reason::new(
            H3StateReasonKind::Authoring {
                generation: generation.generation_id(),
            },
            Vec::new(),
        )
        .expect("authoring reason"),
        Applicability::not_applicable(ApplicabilityReason::NeverPublished),
        generation.source().clone(),
        generation.fingerprints().clone(),
        Some(generation.generation_id()),
        Some(generation.job_id()),
        Some(generation.cycle_id()),
    );
    let record = env.store_new_document(state);
    let original_revision = record.revision();
    let original_html = env.companion();
    let observed = ContentDigest::sha256(b"external edit during authoring");

    let updated =
        record_external_html_conflict(&mut env.store.clone(), &record, Some(&observed), now())
            .expect("record conflict");
    assert_eq!(updated.state().state(), H3State::WaitingHuman);
    assert!(matches!(
        updated.state().reason().kind(),
        H3StateReasonKind::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::ExternalHtmlConflict
        }
    ));
    assert!(
        updated
            .state()
            .reason()
            .required_actions()
            .iter()
            .any(|action| matches!(
                action,
                herness_html_sync::RequiredAction::ResolveHtmlConflict { target }
                    if target == &env.document.companion_path()
            ))
    );
    assert!(!updated.state().applicability().is_applicable());
    assert_eq!(updated.revision(), original_revision + 1);
    assert_eq!(env.companion(), original_html, "no file write");
    assert_eq!(env.receipt(), None);

    let repeated =
        record_external_html_conflict(&mut env.store.clone(), &updated, Some(&observed), now())
            .expect("repeat conflict");
    assert_eq!(
        repeated.revision(),
        updated.revision(),
        "a repeated external notification adds no state revision or event"
    );
}

#[test]
fn an_external_edit_or_invalid_metadata_after_synced_is_waiting_human() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let candidate = ContentDigest::sha256(env.candidate_html.as_bytes());
    let provenance = ContentDigest::sha256(env.provenance.as_bytes());
    let generation = env.generation_record(
        1,
        &candidate,
        &provenance,
        env.fingerprints(&candidate, &provenance),
        true,
    );
    let synced = env.document_state(
        H3Reason::new(
            H3StateReasonKind::Synced {
                generation: generation.generation_id(),
                source_revision: 1,
                source_digest: ContentDigest::sha256(&env.source),
            },
            Vec::new(),
        )
        .expect("synced reason"),
        Applicability::current_synced(),
        generation.source().clone(),
        generation.fingerprints().clone(),
        Some(generation.generation_id()),
        Some(generation.job_id()),
        Some(generation.cycle_id()),
    );
    let record = env.store_new_document(synced);
    env.set_companion(&env.candidate_html.clone().into_bytes());
    let invalid_receipt = b"{not valid receipt metadata";
    env.set_receipt(invalid_receipt);
    let observed = ContentDigest::sha256(b"external replacement html");

    let updated =
        record_external_html_conflict(&mut env.store.clone(), &record, Some(&observed), now())
            .expect("record conflict");
    assert_eq!(updated.state().state(), H3State::WaitingHuman);
    assert!(matches!(
        updated.state().applicability().reason(),
        ApplicabilityReason::HtmlChanged {
            expected,
            observed: found
        } if expected == &candidate && found == &observed
    ));
    assert_eq!(env.receipt().as_deref(), Some(invalid_receipt.as_slice()));
    assert_eq!(
        env.companion().expect("html"),
        env.candidate_html.as_bytes(),
        "the formal HTML is never overwritten by conflict handling"
    );
    assert!(
        updated
            .state()
            .reason()
            .required_actions()
            .iter()
            .any(|action| matches!(
                action,
                herness_html_sync::RequiredAction::ResolveHtmlConflict { .. }
            ))
    );
}

#[test]
fn adoption_requires_exact_validation_and_a_current_evaluation() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let candidate = ContentDigest::sha256(env.candidate_html.as_bytes());
    let provenance = ContentDigest::sha256(env.provenance.as_bytes());
    let old_generation = env.generation_record(
        1,
        &candidate,
        &provenance,
        env.fingerprints(&candidate, &provenance),
        false,
    );
    let state = waiting_conflict_state(
        &env,
        old_generation.clone(),
        &candidate,
        &provenance,
        old_generation.job_id(),
        old_generation.cycle_id(),
    );
    let record = env.store_new_document(state);
    env.set_companion(env.candidate_html.as_bytes());

    // A structural-only validation is not enough to adopt.
    let adopted_generation = env.generation_record(
        2,
        &candidate,
        &provenance,
        env.fingerprints(&candidate, &provenance),
        false,
    );
    let adoption = env.adoption(
        adopted_generation.clone(),
        env.publication_id(1),
        ExpectedTargetVersion::Present {
            version: fver(&candidate),
        },
        ExpectedTargetVersion::Absent,
    );
    // A semantic failure is a structural-only validation, not an adoption
    // evaluation. Build the same adoption with an explicit semantic failure.
    let invalid_validation = CurrentHtmlValidation::new(
        candidate.clone(),
        ContentDigest::sha256(&env.source),
        "semantic-v1",
        true,
        false,
        true,
        Vec::new(),
        "fixture",
        "structural-only fixture",
        now(),
    )
    .expect("invalid validation");
    let invalid = CurrentHtmlAdoption::new(
        record.revision(),
        env.publication_id(2),
        adopted_generation.clone(),
        env.candidate_html.clone(),
        env.provenance.clone(),
        env.source.clone(),
        vec![env.css.clone()],
        Vec::new(),
        env.policy.clone(),
        env.applied.clone(),
        invalid_validation,
        ExpectedTargetVersion::Present {
            version: fver(&candidate),
        },
        ExpectedTargetVersion::Absent,
    )
    .expect("invalid adoption");
    let mut expectations = RecordingExpectations::default();
    let outcome = adopt_direct(&env, invalid, &mut expectations).expect("adoption outcome");
    assert!(matches!(
        outcome,
        herness_html_sync::AdoptionOutcome::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::UndecidableAssessment,
            ..
        }
    ));
    assert_eq!(env.document_record().revision(), record.revision());
    assert_eq!(env.document_record().state().state(), H3State::WaitingHuman);
    assert_eq!(
        env.companion().expect("html"),
        env.candidate_html.as_bytes()
    );
    assert_eq!(env.receipt(), None);

    // A current, all-met evaluation bound to the exact external HTML adopts it.
    let mut expectations = RecordingExpectations::default();
    let outcome = adopt_direct(&env, adoption, &mut expectations).expect("adoption");
    let herness_html_sync::AdoptionOutcome::Adopted(PublicationOutcome::Synced {
        publication,
        html_digest,
        ..
    }) = outcome
    else {
        panic!("expected adopted synced outcome, got {outcome:?}");
    };
    assert_eq!(publication, env.publication_id(1));
    assert_eq!(html_digest, candidate);
    assert_eq!(env.document_record().state().state(), H3State::Synced);
    assert!(
        env.document_record()
            .state()
            .applicability()
            .is_applicable()
    );
    assert_eq!(
        env.companion().expect("html"),
        env.candidate_html.as_bytes()
    );
    assert!(env.receipt().is_some(), "adoption records a receipt");
    assert_eq!(expectations.retired, vec![env.publication_id(1)]);
    let generations = env
        .store
        .lock()
        .html_sync_generations(project(), &env.document)
        .expect("generations");
    assert!(
        generations.iter().any(|generation| {
            generation.generation_id() == adopted_generation.generation_id()
                && generation.completed()
                && generation.publication() == Some(env.publication_id(1))
        }),
        "the adopted version is recorded in history and linked to its publication"
    );
}

#[test]
fn desktop_operations_validate_the_current_html_and_use_the_publication_writer() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let candidate = ContentDigest::sha256(env.candidate_html.as_bytes());
    let provenance = ContentDigest::sha256(env.provenance.as_bytes());
    let old_generation = env.generation_record(
        1,
        &candidate,
        &provenance,
        env.fingerprints(&candidate, &provenance),
        false,
    );
    let state = waiting_conflict_state(
        &env,
        old_generation.clone(),
        &candidate,
        &provenance,
        old_generation.job_id(),
        old_generation.cycle_id(),
    );
    env.store_new_document(state);
    env.set_companion(env.candidate_html.as_bytes());
    let mut ops = herness_desktop::html_sync::operations::DesktopHtmlSyncOperations::new(
        project(),
        &env.fixture.root,
        env.store.clone(),
        &env.archive_root,
        env.connect_bridge(),
        env.control.clone(),
    )
    .expect("desktop operations");
    let validation = ops
        .validate_current_html(
            &env.document,
            &env.source,
            env.candidate_html.as_bytes(),
            std::slice::from_ref(&env.css),
            &[],
        )
        .expect("host validation");
    assert!(validation.is_passing());
    assert_eq!(validation.html_digest(), &candidate);
    assert_eq!(
        validation.source_digest(),
        &ContentDigest::sha256(&env.source)
    );

    let adopted_generation = env.generation_record(
        2,
        &candidate,
        &provenance,
        env.fingerprints(&candidate, &provenance),
        false,
    );
    let adoption = env.adoption(
        adopted_generation,
        env.publication_id(20),
        ExpectedTargetVersion::Present {
            version: fver(&candidate),
        },
        ExpectedTargetVersion::Absent,
    );
    let mut expectations = RecordingExpectations::default();
    let outcome = ops
        .adopt_current_html(adoption, &mut expectations, now())
        .expect("desktop adoption");
    let herness_html_sync::AdoptionOutcome::Adopted(PublicationOutcome::Synced { .. }) = outcome
    else {
        panic!("expected desktop adoption synced, got {outcome:?}");
    };
    assert_eq!(env.document_record().state().state(), H3State::Synced);
    assert_eq!(
        env.companion().expect("html"),
        env.candidate_html.as_bytes()
    );
    assert!(env.receipt().is_some());
}

#[test]
fn an_explicit_regenerated_replacement_uses_publication_and_keeps_history() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let external_html = b"<!doctype html><html><body><p>external edit</p></body></html>";
    env.set_companion(external_html);
    env.set_receipt(b"{invalid external metadata");
    let external_digest = ContentDigest::sha256(external_html);
    let candidate = ContentDigest::sha256(env.candidate_html.as_bytes());
    let provenance = ContentDigest::sha256(env.provenance.as_bytes());
    let old_generation = env.generation_record(
        1,
        &candidate,
        &provenance,
        env.fingerprints(&candidate, &provenance),
        false,
    );
    let state = waiting_conflict_state(
        &env,
        old_generation.clone(),
        &candidate,
        &provenance,
        old_generation.job_id(),
        old_generation.cycle_id(),
    );
    let record = env.store_new_document(state);
    let replacement_generation = env.generation_record(
        2,
        &candidate,
        &provenance,
        env.fingerprints(&candidate, &provenance),
        false,
    );
    let attempt = env.replacement_attempt(
        replacement_generation.clone(),
        env.publication_id(1),
        ExpectedTargetVersion::Present {
            version: fver(&external_digest),
        },
        ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(b"{invalid external metadata")),
        },
    );
    let mut expectations = RecordingExpectations::default();
    let outcome =
        replace_direct(&env, attempt.clone(), &mut expectations).expect("replacement publication");
    let PublicationOutcome::Synced { duplicate, .. } = outcome else {
        panic!("expected synced replacement, got {outcome:?}");
    };
    assert!(!duplicate);
    assert_eq!(
        env.companion().expect("html"),
        env.candidate_html.as_bytes()
    );
    assert!(env.receipt().is_some());
    assert_eq!(env.document_record().state().state(), H3State::Synced);
    assert!(env.document_record().revision() > record.revision());
    let archive_contents = env
        .archive_files()
        .into_iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        archive_contents.contains("external edit"),
        "the replaced external HTML is retained in history"
    );
    assert!(
        archive_contents.contains("invalid external metadata"),
        "the invalid previous receipt is retained in history"
    );

    // Same publication request replays the stored result without another write.
    let mut duplicate_expectations = RecordingExpectations::default();
    let duplicate_outcome =
        replace_direct(&env, attempt, &mut duplicate_expectations).expect("duplicate replacement");
    assert!(matches!(
        duplicate_outcome,
        PublicationOutcome::Synced {
            duplicate: true,
            ..
        }
    ));
    assert_eq!(duplicate_expectations.expected.len(), 0);
}

#[test]
fn restore_saves_the_current_pair_first_and_leaves_the_document_unsynced() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let current_html = b"<!doctype html><html><body><p>current published</p></body></html>";
    let current_receipt = receipt_bytes(&env, current_html, b"current");
    let selected_html = b"<!doctype html><html><body><p>selected history</p></body></html>";
    let selected_receipt = receipt_bytes(&env, selected_html, b"selected");
    let (record, selected_generation) = store_two_published_versions(
        &env,
        current_html,
        &current_receipt,
        selected_html,
        &selected_receipt,
    );
    let source_before = env.source_bytes();
    let current_digest = ContentDigest::sha256(current_html);
    let current_receipt_digest = ContentDigest::sha256(&current_receipt);
    let request = restore_request(
        &env,
        record.revision(),
        selected_generation.generation_id(),
        "restore-1",
    );
    let history = FakeHistory::new(
        HistoryVersion::new(
            &env.document,
            selected_generation.generation_id(),
            PublicationFileInput::new(env.document.companion_path(), selected_html.to_vec())
                .expect("history html"),
            PublicationFileInput::new(env.receipt_path.clone(), selected_receipt.clone())
                .expect("history receipt"),
        )
        .expect("history version"),
    );
    let mut archive = CountingArchive::new(history_archive(&env));
    let mut writer = CountingWriter::new(writer(
        &env,
        H3PublicationRecords::new(env.store.clone()),
        history_archive(&env),
        AllowGate,
    ));
    let outcome = restore_history(
        &mut env.store.clone(),
        &files(&env),
        &history,
        &mut archive,
        &mut writer,
        &request,
        env.publication_id(9),
        &ExpectedTargetVersion::Present {
            version: fver(&current_digest),
        },
        &ExpectedTargetVersion::Present {
            version: fver(&current_receipt_digest),
        },
        now(),
    )
    .expect("restore");
    let HistoryRestoreOutcome::Restored {
        generation,
        html_digest,
        receipt_digest,
        duplicate,
        ..
    } = outcome
    else {
        panic!("expected restored, got {outcome:?}");
    };
    assert!(!duplicate);
    assert_eq!(generation, selected_generation.generation_id());
    assert_eq!(html_digest, ContentDigest::sha256(selected_html));
    assert_eq!(receipt_digest, ContentDigest::sha256(&selected_receipt));
    assert_eq!(archive.saves, 2, "current HTML and receipt are saved first");
    assert_eq!(
        writer.calls, 2,
        "HTML and receipt are two single-file writes"
    );
    assert_eq!(env.companion().expect("html"), selected_html);
    assert_eq!(env.receipt().expect("receipt"), selected_receipt);
    assert_eq!(
        env.source_bytes(),
        source_before,
        "Markdown is never changed"
    );
    let document = env.document_record();
    assert_eq!(document.state().state(), H3State::WaitingHuman);
    assert!(matches!(
        document.state().reason().kind(),
        H3StateReasonKind::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::RecoveryReconciliation
        }
    ));
    assert!(matches!(
        document.state().applicability().reason(),
        ApplicabilityReason::Restored { generation: found }
            if *found == selected_generation.generation_id()
    ));
    assert!(
        document
            .state()
            .reason()
            .required_actions()
            .iter()
            .any(|action| matches!(action, herness_html_sync::RequiredAction::ReassessCandidate))
    );

    // Same request id replays the stored result and performs no write.
    let duplicate = restore_history(
        &mut env.store.clone(),
        &files(&env),
        &history,
        &mut archive,
        &mut writer,
        &request,
        env.publication_id(9),
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(selected_html)),
        },
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(&selected_receipt)),
        },
        now(),
    )
    .expect("duplicate restore");
    assert!(matches!(
        duplicate,
        HistoryRestoreOutcome::Restored {
            duplicate: true,
            ..
        }
    ));
    assert_eq!(archive.saves, 2);
    assert_eq!(writer.calls, 2);
}

#[test]
fn restore_conflict_and_a_second_restore_do_not_duplicate_side_effects() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let current_html = b"<!doctype html><html><body><p>current</p></body></html>";
    let current_receipt = receipt_bytes(&env, current_html, b"current");
    let selected_html = b"<!doctype html><html><body><p>selected</p></body></html>";
    let selected_receipt = receipt_bytes(&env, selected_html, b"selected");
    let (record, selected_generation) = store_two_published_versions(
        &env,
        current_html,
        &current_receipt,
        selected_html,
        &selected_receipt,
    );
    let history = FakeHistory::new(
        HistoryVersion::new(
            &env.document,
            selected_generation.generation_id(),
            PublicationFileInput::new(env.document.companion_path(), selected_html.to_vec())
                .expect("history html"),
            PublicationFileInput::new(env.receipt_path.clone(), selected_receipt.clone())
                .expect("history receipt"),
        )
        .expect("history version"),
    );
    let request = restore_request(
        &env,
        record.revision(),
        selected_generation.generation_id(),
        "restore-conflict",
    );
    let mut archive = CountingArchive::new(history_archive(&env));
    let mut writer = CountingWriter::new(writer(
        &env,
        H3PublicationRecords::new(env.store.clone()),
        history_archive(&env),
        AllowGate,
    ));
    let conflict = restore_history(
        &mut env.store.clone(),
        &files(&env),
        &history,
        &mut archive,
        &mut writer,
        &request,
        env.publication_id(10),
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(b"stale expectation")),
        },
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(&current_receipt)),
        },
        now(),
    )
    .expect("restore conflict");
    assert!(matches!(conflict, HistoryRestoreOutcome::Conflict { .. }));
    assert_eq!(archive.saves, 0);
    assert_eq!(writer.calls, 0);
    assert_eq!(env.document_record().revision(), record.revision());

    // A stale document revision conflicts before any side effect.
    let stale = restore_request(
        &env,
        record.revision() - 1,
        selected_generation.generation_id(),
        "restore-stale",
    );
    let stale_outcome = restore_history(
        &mut env.store.clone(),
        &files(&env),
        &history,
        &mut archive,
        &mut writer,
        &stale,
        env.publication_id(11),
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(current_html)),
        },
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(&current_receipt)),
        },
        now(),
    )
    .expect("stale restore");
    assert!(matches!(
        stale_outcome,
        HistoryRestoreOutcome::Conflict { .. }
    ));
    assert_eq!(archive.saves, 0);

    // A new request restoring the same selected bytes after a successful
    // restore reports unchanged; it does not publish or regenerate.
    let good_request = restore_request(
        &env,
        env.document_record().revision(),
        selected_generation.generation_id(),
        "restore-good",
    );
    let first = restore_history(
        &mut env.store.clone(),
        &files(&env),
        &history,
        &mut archive,
        &mut writer,
        &good_request,
        env.publication_id(12),
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(current_html)),
        },
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(&current_receipt)),
        },
        now(),
    )
    .expect("first restore");
    assert!(matches!(first, HistoryRestoreOutcome::Restored { .. }));
    assert_eq!(env.document_record().state().state(), H3State::WaitingHuman);
    let saves_after_first = archive.saves;
    let writes_after_first = writer.calls;
    let second_request = restore_request(
        &env,
        env.document_record().revision(),
        selected_generation.generation_id(),
        "restore-second",
    );
    let second = restore_history(
        &mut env.store.clone(),
        &files(&env),
        &history,
        &mut archive,
        &mut writer,
        &second_request,
        env.publication_id(13),
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(selected_html)),
        },
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(&selected_receipt)),
        },
        now(),
    )
    .expect("second restore");
    assert!(matches!(
        second,
        HistoryRestoreOutcome::Unchanged {
            generation,
            duplicate: false
        } if generation == selected_generation.generation_id()
    ));
    assert_eq!(archive.saves, saves_after_first);
    assert_eq!(writer.calls, writes_after_first);
}

#[test]
fn a_history_save_failure_keeps_the_formal_pair_and_replays_the_stored_failure() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let current_html = b"<!doctype html><html><body><p>failure current</p></body></html>";
    let current_receipt = receipt_bytes(&env, current_html, b"failure current");
    let selected_html = b"<!doctype html><html><body><p>failure selected</p></body></html>";
    let selected_receipt = receipt_bytes(&env, selected_html, b"failure selected");
    let (record, selected_generation) = store_two_published_versions(
        &env,
        current_html,
        &current_receipt,
        selected_html,
        &selected_receipt,
    );
    let history = FakeHistory::new(
        HistoryVersion::new(
            &env.document,
            selected_generation.generation_id(),
            PublicationFileInput::new(env.document.companion_path(), selected_html.to_vec())
                .expect("history html"),
            PublicationFileInput::new(env.receipt_path.clone(), selected_receipt.clone())
                .expect("history receipt"),
        )
        .expect("history version"),
    );
    let request = restore_request(
        &env,
        record.revision(),
        selected_generation.generation_id(),
        "restore-capacity",
    );
    let mut archive = FailingArchive::new(history_archive(&env), 1);
    let mut writer = CountingWriter::new(writer(
        &env,
        H3PublicationRecords::new(env.store.clone()),
        history_archive(&env),
        AllowGate,
    ));
    let outcome = restore_history(
        &mut env.store.clone(),
        &files(&env),
        &history,
        &mut archive,
        &mut writer,
        &request,
        env.publication_id(40),
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(current_html)),
        },
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(&current_receipt)),
        },
        now(),
    )
    .expect("capacity failure restore");
    assert!(matches!(
        outcome,
        HistoryRestoreOutcome::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::CapacityInsufficient,
            ..
        }
    ));
    assert_eq!(archive.saves, 1);
    assert_eq!(writer.calls, 0);
    assert_eq!(env.companion().expect("html"), current_html);
    assert_eq!(env.receipt().expect("receipt"), current_receipt);
    assert_eq!(env.document_record().state().state(), H3State::WaitingHuman);
    let stored = env
        .store
        .lock()
        .html_sync_request_result(project(), request.request_id())
        .expect("stored result")
        .expect("stored failure result");
    assert!(matches!(
        stored.result().outcome(),
        herness_html_sync::H3OperationOutcome::Rejected { .. }
    ));

    // The same request replays the stored failure without another archive save.
    let replay = restore_history(
        &mut env.store.clone(),
        &files(&env),
        &history,
        &mut archive,
        &mut writer,
        &request,
        env.publication_id(40),
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(current_html)),
        },
        &ExpectedTargetVersion::Present {
            version: fver(&ContentDigest::sha256(&current_receipt)),
        },
        now(),
    )
    .expect("replay capacity failure");
    assert!(matches!(
        replay,
        HistoryRestoreOutcome::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::CapacityInsufficient,
            ..
        }
    ));
    assert_eq!(archive.saves, 1);
    assert_eq!(writer.calls, 0);
}

#[test]
fn desktop_restore_reads_the_private_history_and_restores_through_the_writer() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let current_html = b"<!doctype html><html><body><p>desktop current</p></body></html>";
    let current_receipt = receipt_bytes(&env, current_html, b"desktop current");
    let selected_html = b"<!doctype html><html><body><p>desktop selected</p></body></html>";
    let selected_receipt = receipt_bytes(&env, selected_html, b"desktop selected");
    let (record, selected_generation) = store_two_published_versions(
        &env,
        current_html,
        &current_receipt,
        selected_html,
        &selected_receipt,
    );
    let mut archive = SharedHistoryArchive::new(&env.archive_root).expect("archive");
    for (target, content, seed) in [
        (
            env.document.companion_path(),
            selected_html.as_slice(),
            "selected-html",
        ),
        (
            env.receipt_path.clone(),
            selected_receipt.as_slice(),
            "selected-receipt",
        ),
    ] {
        let version = hash_bytes(content);
        let request_id = PublicationRequestId::new(seed).expect("archive request");
        archive
            .save_old_version(&OldVersionArchive::new(
                &request_id,
                project(),
                &target,
                &version,
                std::str::from_utf8(content).expect("utf8"),
            ))
            .expect("archive selected version");
    }
    let mut ops = herness_desktop::html_sync::operations::DesktopHtmlSyncOperations::new(
        project(),
        &env.fixture.root,
        env.store.clone(),
        &env.archive_root,
        env.connect_bridge(),
        env.control.clone(),
    )
    .expect("desktop operations");
    let request = restore_request(
        &env,
        record.revision(),
        selected_generation.generation_id(),
        "desktop-restore",
    );
    let outcome = ops
        .restore_history(
            &request,
            env.publication_id(30),
            &ExpectedTargetVersion::Present {
                version: fver(&ContentDigest::sha256(current_html)),
            },
            &ExpectedTargetVersion::Present {
                version: fver(&ContentDigest::sha256(&current_receipt)),
            },
            now(),
        )
        .expect("desktop restore");
    assert!(matches!(outcome, HistoryRestoreOutcome::Restored { .. }));
    assert_eq!(env.companion().expect("html"), selected_html);
    assert_eq!(env.receipt().expect("receipt"), selected_receipt);
    assert_eq!(env.document_record().state().state(), H3State::WaitingHuman);
}

#[test]
fn source_deletion_and_rename_keep_old_artifacts_and_report_remaining_paths() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let html = b"<!doctype html><html><body><p>kept</p></body></html>";
    let receipt = receipt_bytes(&env, html, b"kept");
    env.set_companion(html);
    env.set_receipt(&receipt);
    let (record, _generation) = store_synced_document(&env, html, &receipt);
    let before = project_tree(&env.fixture.root);
    let source_before = env.source_bytes();
    let mut controls = FakeJobs::new(SourceStop::Stopped);
    let request = H3OperationRequest::new(
        H3RequestId::new(project()),
        project(),
        Some(env.document.clone()),
        Some(record.revision()),
        Some(ContentDigest::sha256(&env.source)),
        H3Operation::SourceRemoved { new_path: None },
        now(),
    )
    .expect("delete request");
    let outcome = record_source_removal(
        &mut env.store.clone(),
        &mut controls,
        &request,
        env.settings.target_paths(),
        now(),
    )
    .expect("source deletion");
    assert_eq!(controls.stopped, vec![env.document.clone()]);
    assert_eq!(outcome.target, env.document.companion_path());
    assert_eq!(outcome.remaining_paths, vec![EXTRA_TARGET.to_owned()]);
    assert_eq!(outcome.new_target, None);
    assert!(!outcome.duplicate);
    assert_eq!(env.document_record().state().state(), H3State::Orphaned);
    assert!(matches!(
        env.document_record().state().reason().kind(),
        H3StateReasonKind::Orphaned { last_companion }
            if last_companion == &env.document.companion_path()
    ));
    assert_eq!(env.companion().expect("html"), html);
    assert_eq!(env.receipt().expect("receipt"), receipt);
    assert_eq!(env.source_bytes(), source_before);
    assert_eq!(
        project_tree(&env.fixture.root),
        before,
        "no file move or deletion"
    );
    assert!(!env.fixture.root.join(".git").exists());

    // Duplicate request replays the stored result and stops the job only once.
    let duplicate = record_source_removal(
        &mut env.store.clone(),
        &mut controls,
        &request,
        env.settings.target_paths(),
        now(),
    )
    .expect("duplicate deletion");
    assert!(duplicate.duplicate);
    assert_eq!(controls.stopped.len(), 1);
    assert_eq!(env.document_record().state().state(), H3State::Orphaned);

    // A rename is old-path orphan plus a new-path target. The new path is only
    // approved if it is inside the existing settings scope; no new document is
    // created or authored here.
    let env = Env::new();
    let html = b"<!doctype html><html><body><p>kept rename</p></body></html>";
    let receipt = receipt_bytes(&env, html, b"kept rename");
    env.set_companion(html);
    env.set_receipt(&receipt);
    let (record, _generation) = store_synced_document(&env, html, &receipt);
    let before = project_tree(&env.fixture.root);
    let mut controls = FakeJobs::new(SourceStop::Stopped);
    let moved = "docs/adr/0009-moved.md";
    let request = H3OperationRequest::new(
        H3RequestId::new(project()),
        project(),
        Some(env.document.clone()),
        Some(record.revision()),
        Some(ContentDigest::sha256(&env.source)),
        H3Operation::SourceRemoved {
            new_path: Some(moved.to_owned()),
        },
        now(),
    )
    .expect("move request");
    let outcome = record_source_removal(
        &mut env.store.clone(),
        &mut controls,
        &request,
        env.settings.target_paths(),
        now(),
    )
    .expect("source move");
    assert_eq!(outcome.new_target.as_deref(), Some(moved));
    assert!(
        !outcome.new_target_approved,
        "a move does not silently extend the approved Target scope"
    );
    assert_eq!(outcome.remaining_paths, vec![EXTRA_TARGET.to_owned()]);
    assert_eq!(env.document_record().state().state(), H3State::Orphaned);
    assert_eq!(env.companion().expect("html"), html);
    assert_eq!(env.receipt().expect("receipt"), receipt);
    assert_eq!(project_tree(&env.fixture.root), before);
}

#[test]
fn a_source_removal_does_not_orphan_when_the_job_stop_is_unconfirmed() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let html = b"<!doctype html><html><body><p>kept</p></body></html>";
    let receipt = receipt_bytes(&env, html, b"kept");
    env.set_companion(html);
    env.set_receipt(&receipt);
    let (record, _generation) = store_synced_document(&env, html, &receipt);
    let mut controls = FakeJobs::new(SourceStop::Unconfirmed);
    let request = H3OperationRequest::new(
        H3RequestId::new(project()),
        project(),
        Some(env.document.clone()),
        Some(record.revision()),
        Some(ContentDigest::sha256(&env.source)),
        H3Operation::SourceRemoved { new_path: None },
        now(),
    )
    .expect("delete request");
    let error = record_source_removal(
        &mut env.store.clone(),
        &mut controls,
        &request,
        env.settings.target_paths(),
        now(),
    )
    .expect_err("unconfirmed stop is not orphaned");
    assert!(matches!(error, H3Error::Unavailable { .. }));
    let document = env.document_record();
    assert_eq!(document.state().state(), H3State::Stopped);
    assert!(matches!(
        document.state().reason().kind(),
        H3StateReasonKind::Stopped {
            cause: herness_html_sync::H3StopCause::StopUnconfirmed
        }
    ));
    assert_ne!(document.state().state(), H3State::Orphaned);
    assert_eq!(env.companion().expect("html"), html);
    assert_eq!(env.receipt().expect("receipt"), receipt);
    let revision = document.revision();
    let replay = record_source_removal(
        &mut env.store.clone(),
        &mut controls,
        &request,
        env.settings.target_paths(),
        now(),
    )
    .expect_err("a stored unconfirmed stop is replayed as the same failure");
    assert!(matches!(replay, H3Error::Unavailable { .. }));
    assert_eq!(controls.stopped.len(), 1);
    assert_eq!(env.document_record().revision(), revision);
}

fn receipt_bytes(env: &Env, html: &[u8], label: &[u8]) -> Vec<u8> {
    let source_digest = ContentDigest::sha256(&env.source);
    let html_digest = ContentDigest::sha256(html);
    format!(
        "{{\n  \"schema\": \"sdd-html-receipt\",\n  \"version\": 1,\n  \"contract\": \"semantic-v1\",\n  \"source\": {{\"path\": \"{}\", \"digest\": \"sha256:{}\"}},\n  \"html\": {{\"path\": \"{}\", \"digest\": \"sha256:{}\"}},\n  \"label\": \"{}\"\n}}\n",
        TARGET_PATH,
        source_digest.as_str(),
        env.document.companion_path(),
        html_digest.as_str(),
        String::from_utf8_lossy(label)
    )
    .into_bytes()
}

fn restore_request(
    env: &Env,
    revision: u64,
    generation: GenerationId,
    seed: &str,
) -> H3OperationRequest {
    H3OperationRequest::new(
        H3RequestId::new(project()),
        project(),
        Some(env.document.clone()),
        Some(revision),
        Some(ContentDigest::sha256(&env.source)),
        H3Operation::RestoreHistory { generation },
        now(),
    )
    .expect(seed)
}

struct FakeHistory {
    version: Option<HistoryVersion>,
    loads: Cell<usize>,
}

impl FakeHistory {
    fn new(version: HistoryVersion) -> Self {
        Self {
            version: Some(version),
            loads: Cell::new(0),
        }
    }
}

impl HistoryReadPort for FakeHistory {
    fn load_version(
        &self,
        _document: &DocumentKey,
        _generation: GenerationId,
    ) -> Result<Option<HistoryVersion>, H3Error> {
        self.loads.set(self.loads.get() + 1);
        Ok(self.version.clone())
    }
}

struct FakeJobs {
    result: SourceStop,
    stopped: Vec<DocumentKey>,
}

impl FakeJobs {
    fn new(result: SourceStop) -> Self {
        Self {
            result,
            stopped: Vec::new(),
        }
    }
}

impl SourceJobControlPort for FakeJobs {
    fn stop_source(&mut self, document: &DocumentKey) -> Result<SourceStop, H3Error> {
        self.stopped.push(document.clone());
        Ok(self.result)
    }
}

fn store_synced_document(
    env: &Env,
    html: &[u8],
    receipt: &[u8],
) -> (H3DocumentRecord, herness_html_sync::GenerationRecord) {
    let html_digest = ContentDigest::sha256(html);
    let provenance = ContentDigest::sha256(b"provenance");
    let generation = env
        .generation_record(
            1,
            &html_digest,
            &provenance,
            env.fingerprints(&html_digest, &provenance),
            true,
        )
        .with_publication(env.publication_id(1));
    let publication = env.publication_id(1);
    let journal = published_journal(
        env,
        publication,
        &generation,
        &html_digest,
        &ContentDigest::sha256(receipt),
        receipt,
    );
    let state = env.document_state(
        H3Reason::new(
            H3StateReasonKind::Synced {
                generation: generation.generation_id(),
                source_revision: 1,
                source_digest: ContentDigest::sha256(&env.source),
            },
            Vec::new(),
        )
        .expect("synced reason"),
        Applicability::current_synced(),
        generation.source().clone(),
        generation.fingerprints().clone(),
        Some(generation.generation_id()),
        Some(generation.job_id()),
        Some(generation.cycle_id()),
    );
    let record = env.store_new_document(state.clone());
    let mut record = record;
    record = commit_publication(env, &record, journal);
    (record, generation)
}

fn store_two_published_versions(
    env: &Env,
    current_html: &[u8],
    current_receipt: &[u8],
    selected_html: &[u8],
    selected_receipt: &[u8],
) -> (H3DocumentRecord, herness_html_sync::GenerationRecord) {
    env.set_companion(current_html);
    env.set_receipt(current_receipt);
    let selected_digest = ContentDigest::sha256(selected_html);
    let selected_provenance = ContentDigest::sha256(b"selected provenance");
    let selected = env
        .generation_record(
            1,
            &selected_digest,
            &selected_provenance,
            env.fingerprints(&selected_digest, &selected_provenance),
            true,
        )
        .with_publication(env.publication_id(1));
    let selected_journal = published_journal(
        env,
        env.publication_id(1),
        &selected,
        &selected_digest,
        &ContentDigest::sha256(selected_receipt),
        selected_receipt,
    );
    let current_digest = ContentDigest::sha256(current_html);
    let current_provenance = ContentDigest::sha256(b"current provenance");
    let current = env
        .generation_record(
            2,
            &current_digest,
            &current_provenance,
            env.fingerprints(&current_digest, &current_provenance),
            true,
        )
        .with_publication(env.publication_id(2));
    let current_journal = published_journal(
        env,
        env.publication_id(2),
        &current,
        &current_digest,
        &ContentDigest::sha256(current_receipt),
        current_receipt,
    );
    let state = env.document_state(
        H3Reason::new(
            H3StateReasonKind::Synced {
                generation: current.generation_id(),
                source_revision: 2,
                source_digest: ContentDigest::sha256(&env.source),
            },
            Vec::new(),
        )
        .expect("synced reason"),
        Applicability::current_synced(),
        current.source().clone(),
        current.fingerprints().clone(),
        Some(current.generation_id()),
        Some(current.job_id()),
        Some(current.cycle_id()),
    );
    let mut record = env.store_new_document(state);
    record = commit_generation(env, &record, selected.clone());
    record = commit_generation(env, &record, current.clone());
    record = commit_publication(env, &record, selected_journal);
    record = commit_publication(env, &record, current_journal);
    (record, selected)
}

fn commit_generation(
    env: &Env,
    record: &H3DocumentRecord,
    generation: herness_html_sync::GenerationRecord,
) -> H3DocumentRecord {
    let mut store = env.store.clone();
    match store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(
                    DocumentCommit::new(Some(record.revision()), record.state().clone())
                        .expect("document commit"),
                )
                .with_generation(generation),
        )
        .expect("store generation")
    {
        HtmlSyncCommitOutcome::Applied { document, .. } => document.expect("stored document"),
        HtmlSyncCommitOutcome::Duplicate { .. } => panic!("unexpected duplicate"),
    }
}

fn commit_publication(
    env: &Env,
    record: &H3DocumentRecord,
    journal: PublicationJournal,
) -> H3DocumentRecord {
    let mut store = env.store.clone();
    match store
        .commit_html_sync(
            HtmlSyncCommit::new()
                .with_document(
                    DocumentCommit::new(Some(record.revision()), record.state().clone())
                        .expect("document commit"),
                )
                .with_events(vec![
                    herness_html_sync::publication_event(&journal, now()).expect("event"),
                ])
                .with_publication(journal),
        )
        .expect("store publication")
    {
        HtmlSyncCommitOutcome::Applied { document, .. } => document.expect("stored document"),
        HtmlSyncCommitOutcome::Duplicate { .. } => panic!("unexpected duplicate"),
    }
}

fn published_journal(
    env: &Env,
    publication: PublicationId,
    generation: &herness_html_sync::GenerationRecord,
    html_digest: &ContentDigest,
    receipt_digest: &ContentDigest,
    receipt: &[u8],
) -> PublicationJournal {
    let html_request = PublicationRequestId::new(format!("{publication}:html")).expect("html id");
    let receipt_request =
        PublicationRequestId::new(format!("{publication}:receipt")).expect("receipt id");
    let journal = PublicationJournal::new(
        publication,
        env.document.clone(),
        generation.generation_id(),
        generation.candidate().expect("candidate").candidate_id(),
        html_request.clone(),
        ExpectedTargetVersion::Absent,
        html_digest.clone(),
        generation
            .candidate()
            .expect("candidate")
            .provenance_digest()
            .clone(),
        generation.source().clone(),
        now(),
    )
    .expect("journal")
    .with_receipt(
        env.receipt_path.clone(),
        ExpectedTargetVersion::Absent,
        receipt_digest.clone(),
        receipt_request.clone(),
        now(),
    )
    .expect("journal receipt")
    .with_file(
        herness_html_sync::PublicationFileJournal::pending(
            PublicationFileRole::Html,
            env.document.companion_path(),
            ExpectedTargetVersion::Absent,
            html_digest.clone(),
            Some(html_request),
            now(),
        )
        .expect("html file"),
    )
    .expect("journal html file")
    .with_file(
        herness_html_sync::PublicationFileJournal::pending(
            PublicationFileRole::Receipt,
            &env.receipt_path,
            ExpectedTargetVersion::Absent,
            receipt_digest.clone(),
            Some(receipt_request),
            now(),
        )
        .expect("receipt file"),
    )
    .expect("journal receipt file")
    .old_versions_saved(None, None, now())
    .expect("old versions")
    .replacing(now())
    .expect("replacing");
    assert!(!receipt.is_empty());
    journal
        .published_pair(html_digest.clone(), receipt_digest.clone(), None, now())
        .expect("published")
}

fn project_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    collect_tree(root, root, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn collect_tree(root: &Path, directory: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            collect_tree(root, &path, files);
        } else if metadata.is_file()
            && let Ok(bytes) = fs::read(&path)
            && let Ok(relative) = path.strip_prefix(root)
        {
            files.push((relative.to_path_buf(), bytes));
        }
    }
}
