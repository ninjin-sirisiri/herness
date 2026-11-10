//! Task 19 publication, history, and idempotency tests.
//!
//! The real Common SDD pack is used read-only. Provider access is not used:
//! the H2 evaluation is a synthetic all-met fixture bound to a native-shaped
//! render fixture. The tests report that distinction instead of claiming a real
//! WKWebView or real-model evaluation.

#![cfg(unix)]

mod support;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use herness_core::{
    ConnectionId, ExpectedTargetVersion, ProjectId, PublicationRequest, RunControl, StorePort,
};
use herness_core::ports::publish::{PublicationGatePort, PublicationRecordPort};
use herness_core::runtime::PublicationWriter;
use herness_desktop::html_sync::publish::{
    H3PublicationRecords, ObserverWriteExpectations, PolicyFinalCheck, ProjectPublicationFiles,
    SharedHistoryArchive,
};
use herness_desktop::html_sync::policy::{CandidateStage, HtmlPolicyBridge};
use herness_desktop::supervision::store::StoreHandle;
use herness_html_sync::ids::GenerationId;
use herness_html_sync::{
    Applicability, CandidatePublication, CandidateRecord, CandidateStorageRef, ChangeSignal,
    ChangeSource, CycleId, DocumentCommit, DocumentKey, EvidenceFingerprints,
    ExpectedPublicationWrite, FilesystemSourceReader, FinalCandidateCheck, FinalCandidateCheckPort,
    FinalCandidateCheckRequest, FingerprintSet, H2Reference, H3ApprovalLimits, H3Approver,
    H3ConfigurationApproval, H3ConfigurationDraft, H3ConnectionApproval, H3DocumentRecord,
    H3DocumentState, H3Error, H3OwnerBinding, H3Reason, H3Settings, H3StateReasonKind, H3StorePort,
    H3VersionBinding, HOST_API_PROTOCOL, HOST_API_VERSION, HtmlSyncCommit, HtmlSyncCommitOutcome,
    JobId, ObservationEligibility, PACK_INTEGRATION_SCHEMA, PACK_POLICY_VERSION, ProjectObserver,
    PublicationFileInput, PublicationFileRole, PublicationFileStatus, PublicationId,
    PublicationJournal, PublicationOrchestrator, PublicationOutcome, PublicationPolicyIdentity,
    PublicationSafety, PublicationSafetyPort, PublicationSafetyRequest, PublicationStatus,
    PublicationWriteExpectationPort, RubricSet, SourceRevision, SourceSnapshot, SyncCycle,
    SystemObservationClock, dependency_fingerprint, html_evidence_path,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::ids::{ConsentId, ProfileId};
use herness_supervision::profiles::{ProfileBinding, ProfilePurpose, ProfileVersion};
use herness_supervision::{
    BudgetPolicy, ContentDigest, DisclosureDataKind, DisclosureScope, ExecutionScope, OwnerKind,
    OwnerRef, ProviderOrigin,
};
use serde_json::Value;
use tempfile::TempDir;
use uuid::Uuid;

use support::{
    AdrFixture, REAL_PACK_ROOT, TARGET_PATH, build_pack_with_fingerprints, condition_binding,
    condition_digest, condition_version, document_key, now, pass_and_native_checks,
    positive_evaluation, project, real_pack_present, source_units, supervision, target_version,
    toolchain,
};

const JOB: &str = "job-19";
const CYCLE_UUID: &str = "50000000-0000-4000-8000-000000000012";
const GENERATION_UUID: &str = "50000000-0000-4000-8000-000000000011";
const CANDIDATE_UUID: &str = "50000000-0000-4000-8000-000000000031";

fn skip_without_pack() -> bool {
    if real_pack_present() {
        false
    } else {
        eprintln!("skip publication test: real pack absent");
        true
    }
}

fn cycle_id() -> CycleId {
    CycleId::from_parts(project(), Uuid::parse_str(CYCLE_UUID).expect("cycle uuid"))
}

fn generation_id() -> GenerationId {
    GenerationId::from_parts(
        project(),
        Uuid::parse_str(GENERATION_UUID).expect("generation uuid"),
    )
}

fn candidate_id() -> herness_html_sync::CandidateId {
    herness_html_sync::CandidateId::from_parts(
        project(),
        Uuid::parse_str(CANDIDATE_UUID).expect("candidate uuid"),
    )
}

fn publication_id() -> PublicationId {
    PublicationId::from_parts(
        project(),
        Uuid::parse_str("50000000-0000-4000-8000-000000000041").expect("publication uuid"),
    )
}

fn profile(purpose: ProfilePurpose) -> ProfileBinding {
    let seed = match purpose {
        ProfilePurpose::Html => "90000000-0000-4000-8000-000000000001",
        ProfilePurpose::Completion => "90000000-0000-4000-8000-000000000002",
        ProfilePurpose::Permission => "90000000-0000-4000-8000-000000000003",
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
            vec![TARGET_PATH.to_owned()],
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
            approval_id: "approval-19".to_owned(),
            expires_at: None,
            targets: vec![TARGET_PATH.to_owned()],
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
                    vec![TARGET_PATH.to_owned()],
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
    generation: herness_html_sync::GenerationRecord,
    applied: herness_html_sync::AppliedEvaluation,
    policy: PublicationPolicyIdentity,
    css: PublicationFileInput,
    source: Vec<u8>,
    candidate_html: String,
    provenance: String,
    document_revision: u64,
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
                HtmlSyncCommit::new()
                    .with_settings(
                        herness_html_sync::SettingsCommit::new(None, settings.clone())
                            .expect("settings commit"),
                    ),
            )
            .expect("store settings");

        let source = fs::read(fixture.root.join(TARGET_PATH)).expect("source");
        let css_bytes =
            fs::read(fixture.root.join("docs/sdd/assets/sdd.css")).expect("shared css");
        let css = PublicationFileInput::new("docs/sdd/assets/sdd.css", css_bytes.clone())
            .expect("css input");
        let css_fp =
            dependency_fingerprint(herness_html_sync::DependencyKind::Css, [(css.path(), css.digest())]);
        let resources_fp =
            dependency_fingerprint(herness_html_sync::DependencyKind::Resource, []);
        let candidate_html = fixture.candidate_html().to_owned();
        let provenance =
            support::provenance_payload(&candidate_html);
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

        let fingerprints = FingerprintSet::new(
            settings.fingerprint().clone(),
            policy.digest().clone(),
            css_fp,
            resources_fp,
            Some(candidate_digest.clone()),
            Some(provenance_digest.clone()),
            None,
        );
        let source_snapshot = SourceSnapshot::new(
            SourceRevision::new(1).expect("source revision"),
            source_digest,
        );
        let storage = CandidateStorageRef::new(
            "a".repeat(64),
            ContentDigest::sha256(b"candidate-token"),
        )
        .expect("storage ref");
        let candidate = CandidateRecord::new(
            candidate_id(),
            document_key(),
            generation_id(),
            storage,
            candidate_digest.clone(),
            provenance_digest.clone(),
            now(),
        )
        .expect("candidate record");
        let h2 = H2Reference::new(
            project(),
            supervision(),
            None,
            Some(condition_version()),
            Some(target_version()),
            Some(1),
            None,
        )
        .expect("h2 reference");
        let generation = herness_html_sync::GenerationRecord::new(
            generation_id(),
            document_key(),
            1,
            cycle_id(),
            JobId::from_parts(
                project(),
                Uuid::parse_str("50000000-0000-4000-8000-000000000013").expect("job uuid"),
            ),
            source_snapshot.clone(),
            fingerprints.clone(),
            herness_html_sync::GenerationStatus::Active,
            false,
            now(),
        )
        .expect("generation")
        .with_candidate(candidate)
        .expect("generation candidate")
        .with_h2(h2.clone());
        let state = H3DocumentState::new(
            document_key(),
            settings.version(),
            Some(generation.job_id()),
            Some(cycle_id()),
            Some(generation_id()),
            source_snapshot,
            fingerprints,
            H3Reason::new(
                H3StateReasonKind::Assessing {
                    generation: generation_id(),
                },
                Vec::new(),
            )
            .expect("reason"),
            Some(h2),
            Vec::new(),
            Applicability::not_applicable(herness_html_sync::ApplicabilityReason::NeverPublished),
            now(),
        )
        .expect("document state");
        let outcome = handle
            .commit_html_sync(
                HtmlSyncCommit::new()
                    .with_document(
                        DocumentCommit::new(None, state).expect("document commit"),
                    )
                    .with_generation(generation.clone()),
            )
            .expect("store document");
        let document_revision = match outcome {
            HtmlSyncCommitOutcome::Applied { document, .. } => {
                document.expect("stored document").revision()
            }
            HtmlSyncCommitOutcome::Duplicate { .. } => panic!("unexpected duplicate"),
        };

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
            generation,
            applied,
            policy,
            css,
            source,
            candidate_html,
            provenance,
            document_revision,
            archive_root,
            final_check,
            control,
            receipt_path,
        }
    }

    fn attempt(
        &self,
        expected_html: ExpectedTargetVersion,
        expected_receipt: ExpectedTargetVersion,
    ) -> CandidatePublication {
        CandidatePublication::new(
            publication_id(),
            self.document.clone(),
            self.document_revision,
            self.settings.version(),
            self.generation.clone(),
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
        .expect("publication attempt")
    }

    fn set_companion(&self, bytes: &[u8]) {
        fs::write(
            self.fixture.root.join(self.document.companion_path()),
            bytes,
        )
        .expect("write companion");
    }

    fn remove_companion(&self) {
        let path = self.fixture.root.join(self.document.companion_path());
        let _ = fs::remove_file(path);
    }

    fn set_receipt(&self, bytes: &[u8]) {
        let path = self.fixture.root.join(&self.receipt_path);
        fs::create_dir_all(path.parent().expect("parent")).expect("evidence dir");
        fs::write(path, bytes).expect("write receipt");
    }

    fn remove_receipt(&self) {
        let _ = fs::remove_file(self.fixture.root.join(&self.receipt_path));
    }

    fn companion(&self) -> Option<Vec<u8>> {
        fs::read(self.fixture.root.join(self.document.companion_path())).ok()
    }

    fn receipt(&self) -> Option<Vec<u8>> {
        fs::read(self.fixture.root.join(&self.receipt_path)).ok()
    }

    fn journal(&self) -> Option<PublicationJournal> {
        self.store
            .lock()
            .load_html_sync_publication(project(), publication_id())
            .expect("journal")
    }

    fn document_record(&self) -> H3DocumentRecord {
        self.store
            .lock()
            .load_html_sync_document(project(), &self.document)
            .expect("document")
            .expect("stored document")
    }
}

#[derive(Default)]
struct RecordingExpectations {
    expected: Vec<ExpectedPublicationWrite>,
    retired: Vec<PublicationId>,
    fail_expect: bool,
}

impl PublicationWriteExpectationPort for RecordingExpectations {
    fn expect(&mut self, write: ExpectedPublicationWrite) -> Result<(), H3Error> {
        if self.fail_expect {
            return Err(H3Error::Storage {
                detail: "injected expectation fault".to_owned(),
            });
        }
        self.expected.push(write);
        Ok(())
    }

    fn retire(&mut self, publication: PublicationId) {
        self.retired.push(publication);
    }
}

struct ScriptedSafety {
    safety: PublicationSafety,
}

impl PublicationSafetyPort for ScriptedSafety {
    fn recheck(
        &self,
        _request: &PublicationSafetyRequest<'_>,
    ) -> Result<PublicationSafety, H3Error> {
        Ok(self.safety)
    }
}

fn allows() -> ScriptedSafety {
    ScriptedSafety {
        safety: PublicationSafety {
            stop_requested: false,
            consent_current: true,
            approval_current: true,
            budget_remaining: true,
        },
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

struct DenyAfterGate {
    allowed: usize,
    calls: Cell<usize>,
}

impl PublicationGatePort for DenyAfterGate {
    fn authorize_publication(
        &self,
        _request: &PublicationRequest,
    ) -> Result<(), herness_core::PublicationFailure> {
        let calls = self.calls.get() + 1;
        self.calls.set(calls);
        if calls > self.allowed {
            return Err(herness_core::PublicationFailure::PermissionDenied {
                detail: "injected gate denial before the rename".to_owned(),
            });
        }
        Ok(())
    }
}

struct FaultyH3Store {
    inner: StoreHandle,
    fail_on: Option<usize>,
    commits: usize,
}

impl FaultyH3Store {
    fn new(inner: StoreHandle, fail_on: Option<usize>) -> Self {
        Self {
            inner,
            fail_on,
            commits: 0,
        }
    }
}

impl H3StorePort for FaultyH3Store {
    fn load_html_sync_settings(
        &self,
        project: ProjectId,
    ) -> Result<Option<herness_html_sync::H3SettingsRecord>, H3Error> {
        self.inner.load_html_sync_settings(project)
    }

    fn load_html_sync_document(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Option<H3DocumentRecord>, H3Error> {
        self.inner.load_html_sync_document(project, document)
    }

    fn list_html_sync_documents(
        &self,
        project: ProjectId,
    ) -> Result<Vec<H3DocumentRecord>, H3Error> {
        self.inner.list_html_sync_documents(project)
    }

    fn html_sync_generations(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Vec<herness_html_sync::GenerationRecord>, H3Error> {
        self.inner.html_sync_generations(project, document)
    }

    fn load_html_sync_candidate(
        &self,
        project: ProjectId,
        candidate: herness_html_sync::CandidateId,
    ) -> Result<Option<CandidateRecord>, H3Error> {
        self.inner.load_html_sync_candidate(project, candidate)
    }

    fn load_html_sync_cycle(
        &self,
        project: ProjectId,
        cycle: CycleId,
    ) -> Result<Option<SyncCycle>, H3Error> {
        self.inner.load_html_sync_cycle(project, cycle)
    }

    fn load_html_sync_publication(
        &self,
        project: ProjectId,
        publication: PublicationId,
    ) -> Result<Option<PublicationJournal>, H3Error> {
        self.inner.load_html_sync_publication(project, publication)
    }

    fn list_html_sync_publications(
        &self,
        project: ProjectId,
        document: &DocumentKey,
    ) -> Result<Vec<PublicationJournal>, H3Error> {
        self.inner.list_html_sync_publications(project, document)
    }

    fn html_sync_request_result(
        &self,
        project: ProjectId,
        request: herness_html_sync::H3RequestId,
    ) -> Result<Option<herness_html_sync::StoredRequestResult>, H3Error> {
        self.inner.html_sync_request_result(project, request)
    }

    fn list_html_sync_request_results(
        &self,
        project: ProjectId,
    ) -> Result<Vec<herness_html_sync::StoredRequestResult>, H3Error> {
        self.inner.list_html_sync_request_results(project)
    }

    fn commit_html_sync(
        &mut self,
        commit: HtmlSyncCommit,
    ) -> Result<HtmlSyncCommitOutcome, H3Error> {
        self.commits += 1;
        if self.fail_on == Some(self.commits) {
            return Err(H3Error::Storage {
                detail: format!("injected H3 commit fault at {}", self.commits),
            });
        }
        self.inner.commit_html_sync(commit)
    }

    fn update_html_sync_publication(
        &mut self,
        journal: PublicationJournal,
    ) -> Result<(), H3Error> {
        self.inner.update_html_sync_publication(journal)
    }
}

struct FaultyRecords {
    inner: H3PublicationRecords,
    fail_on: Option<usize>,
    saves: usize,
}

impl FaultyRecords {
    fn new(inner: H3PublicationRecords, fail_on: Option<usize>) -> Self {
        Self {
            inner,
            fail_on,
            saves: 0,
        }
    }
}

impl PublicationRecordPort for FaultyRecords {
    fn load_publication(
        &self,
        key: &str,
    ) -> Result<Option<herness_core::PublicationRecord>, herness_core::PublicationFailure> {
        self.inner.load_publication(key)
    }

    fn save_publication(
        &mut self,
        key: &str,
        record: &herness_core::PublicationRecord,
        events: Vec<herness_core::EventDraft>,
    ) -> Result<herness_core::CommitReceipt, herness_core::PublicationFailure> {
        self.saves += 1;
        if self.fail_on == Some(self.saves) {
            return Err(herness_core::PublicationFailure::RecordUnavailable {
                detail: format!("injected record fault at {}", self.saves),
            });
        }
        self.inner.save_publication(key, record, events)
    }
}

struct FaultyArchive {
    inner: SharedHistoryArchive,
    fail_on: Option<usize>,
    saves: usize,
}

impl FaultyArchive {
    fn new(inner: SharedHistoryArchive, fail_on: Option<usize>) -> Self {
        Self {
            inner,
            fail_on,
            saves: 0,
        }
    }
}

impl herness_core::ports::publish::PublicationArchivePort for FaultyArchive {
    fn save_old_version(
        &mut self,
        archive: &herness_core::OldVersionArchive<'_>,
    ) -> Result<herness_core::ArchivedVersion, herness_core::PublicationFailure> {
        self.saves += 1;
        if self.fail_on == Some(self.saves) {
            return Err(herness_core::PublicationFailure::OldVersionSaveFailed {
                detail: format!("injected archive fault at {}", self.saves),
            });
        }
        self.inner.save_old_version(archive)
    }
}

fn files(env: &Env) -> ProjectPublicationFiles {
    ProjectPublicationFiles::new(&env.fixture.root).expect("project files")
}

fn archive(env: &Env, fail_on: Option<usize>) -> FaultyArchive {
    FaultyArchive::new(
        SharedHistoryArchive::new(&env.archive_root).expect("history archive"),
        fail_on,
    )
}

fn writer<G: PublicationGatePort>(
    env: &Env,
    records: FaultyRecords,
    writer_archive: FaultyArchive,
    gate: G,
) -> PublicationWriter<FaultyRecords, FaultyArchive, G> {
    PublicationWriter::new(
        project(),
        herness_core::ProjectRoot::new(&env.fixture.root).expect("project root"),
        records,
        writer_archive,
        gate,
        env.control.clone(),
    )
    .expect("publication writer")
}

struct FinalOnly<'a> {
    inner: &'a PolicyFinalCheck,
}

impl FinalCandidateCheckPort for FinalOnly<'_> {
    fn check(
        &self,
        request: &FinalCandidateCheckRequest<'_>,
    ) -> Result<FinalCandidateCheck, H3Error> {
        self.inner.check(request)
    }
}

struct StructuralOnly<'a> {
    inner: &'a PolicyFinalCheck,
}

impl FinalCandidateCheckPort for StructuralOnly<'_> {
    fn check(
        &self,
        request: &FinalCandidateCheckRequest<'_>,
    ) -> Result<FinalCandidateCheck, H3Error> {
        let result = self
            .inner
            .bridge()
            .candidate_check(
                request.html_path,
                CandidateStage::Structural,
                None,
                &{
                    let mut inputs = std::collections::BTreeMap::new();
                    inputs.insert(request.source_path.to_owned(), request.source.to_vec());
                    inputs.insert(request.html_path.to_owned(), request.html.to_vec());
                    inputs
                },
            )
            .map_err(|error| H3Error::Unavailable {
                capability: "test.structural".to_owned(),
                detail: error.to_string(),
            })?;
        Ok(FinalCandidateCheck {
            allowed: result.decision() == herness_desktop::html_sync::policy::CandidateDecision::Allow,
            final_pass: result.final_pass(),
            final_binding: result.final_binding(),
            contract: result.contract().to_owned(),
            violations: Vec::new(),
        })
    }
}

struct RejectingFinal<'a> {
    inner: &'a PolicyFinalCheck,
}

impl FinalCandidateCheckPort for RejectingFinal<'_> {
    fn check(
        &self,
        request: &FinalCandidateCheckRequest<'_>,
    ) -> Result<FinalCandidateCheck, H3Error> {
        let mut receipt: Value =
            serde_json::from_str(request.receipt).expect("receipt JSON");
        receipt["inputs"]["policy"]["digest"] =
            Value::String(format!("sha256:{}", "0".repeat(64)));
        let mutated = serde_json::to_string_pretty(&receipt).expect("mutated receipt");
        let mutated = FinalCandidateCheckRequest {
            source_path: request.source_path,
            source: request.source,
            html_path: request.html_path,
            html: request.html,
            receipt_path: request.receipt_path,
            receipt: &mutated,
            css: request.css,
            resources: request.resources,
        };
        self.inner.check(&mutated)
    }
}

#[allow(clippy::too_many_arguments)]
fn publish_direct(
    env: &Env,
    mut store: FaultyH3Store,
    mut writer: PublicationWriter<FaultyRecords, FaultyArchive, AllowGate>,
    mut h3_archive: FaultyArchive,
    final_check: &dyn FinalCandidateCheckPort,
    safety: &dyn PublicationSafetyPort,
    expectations: &mut dyn PublicationWriteExpectationPort,
    attempt: CandidatePublication,
) -> Result<PublicationOutcome, H3Error> {
    let files = files(env);
    let mut orchestrator = PublicationOrchestrator {
        store: &mut store,
        files: &files,
        archive: &mut h3_archive,
        host: &mut writer,
        final_check,
        safety,
        expectations,
        control: &env.control,
    };
    orchestrator.publish(attempt, now())
}

#[test]
fn publication_writes_the_exact_html_and_receipt_and_commits_synced_with_the_sequence() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_direct(
        &env,
        FaultyH3Store::new(env.store.clone(), None),
        writer(
            &env,
            FaultyRecords::new(H3PublicationRecords::new(env.store.clone()), None),
            archive(&env, None),
            AllowGate,
        ),
        archive(&env, None),
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
    )
    .expect("publication");
    let PublicationOutcome::Synced {
        final_project_sequence,
        html_digest,
        receipt_digest,
        duplicate,
        ..
    } = outcome
    else {
        panic!("expected synced, got {outcome:?}");
    };
    assert!(!duplicate);
    assert_eq!(
        env.companion().expect("html"),
        env.candidate_html.as_bytes()
    );
    let receipt = env.receipt().expect("receipt");
    assert_eq!(ContentDigest::sha256(&receipt), receipt_digest);
    assert_eq!(
        ContentDigest::sha256(env.companion().expect("html").as_slice()),
        html_digest
    );
    let receipt_json: Value = serde_json::from_slice(&receipt).expect("receipt JSON");
    assert_eq!(receipt_json["schema"], "sdd-html-receipt");
    assert_eq!(receipt_json["version"], 1);
    assert_eq!(receipt_json["contract"], "semantic-v1");
    assert_eq!(receipt_json["source"]["path"], TARGET_PATH);
    assert_eq!(
        receipt_json["source"]["digest"],
        format!("sha256:{}", ContentDigest::sha256(&env.source).as_str())
    );
    assert_eq!(
        receipt_json["html"]["path"],
        "docs/adr/0001-queue-choice.html"
    );
    assert_eq!(
        receipt_json["html"]["digest"],
        format!("sha256:{}", ContentDigest::sha256(env.candidate_html.as_bytes()).as_str())
    );
    assert_eq!(
        receipt_json["inputs"]["css"][0]["path"],
        "docs/sdd/assets/sdd.css"
    );
    assert_eq!(
        receipt_json["inputs"]["policy"]["digest"],
        format!("sha256:{}", env.policy.digest().as_str())
    );
    assert_eq!(receipt_json["inputs"]["policy"]["version"], PACK_POLICY_VERSION);
    assert_eq!(receipt_json["versions"]["settings"], "settings:1");
    assert_eq!(receipt_json["generation"]["id"], generation_id().to_string());
    assert_eq!(receipt_json["generation"]["revision"], 1);
    assert_eq!(receipt_json["generation"]["parent"], Value::Null);
    assert_eq!(receipt_json["h2"]["purpose"], "Html");
    assert_eq!(receipt_json["verification"]["result"], "pass");
    for check in receipt_json["verification"]["checks"]
        .as_array()
        .expect("checks")
    {
        assert_eq!(check["decision"], "pass");
    }
    for condition in receipt_json["conditions"].as_array().expect("conditions") {
        assert_eq!(condition["decision"], "met");
        assert!(!condition["evidence"].as_array().expect("evidence").is_empty());
    }
    let text = String::from_utf8(receipt).expect("utf8");
    for secret in ["api_key", "Bearer", "provider error", "raw response"] {
        assert!(!text.contains(secret), "receipt must not contain {secret}");
    }

    let journal = env.journal().expect("journal");
    assert_eq!(journal.status(), PublicationStatus::Published);
    assert_eq!(journal.final_project_sequence(), Some(final_project_sequence));
    assert_eq!(journal.observed_after_html(), Some(&html_digest));
    assert_eq!(journal.observed_after_receipt(), Some(&receipt_digest));
    assert_eq!(
        journal.file(PublicationFileRole::Html).expect("html file").status(),
        PublicationFileStatus::Published
    );
    assert_eq!(
        journal
            .file(PublicationFileRole::Receipt)
            .expect("receipt file")
            .status(),
        PublicationFileStatus::Published
    );
    assert!(journal.receipt_path().is_some());
    assert!(journal.old_html().is_none());
    assert!(journal.old_receipt().is_none());

    let document = env.document_record();
    assert_eq!(document.state().state(), herness_html_sync::H3State::Synced);
    assert!(document.state().applicability().is_applicable());
    assert_eq!(document.last_sequence(), final_project_sequence);
    assert_eq!(expectations.retired, vec![publication_id()]);

    let page = env
        .store
        .history(herness_core::HistoryQuery::first(project()))
        .expect("history");
    let events = page.events();
    let latest = events.first().expect("latest event");
    assert_eq!(latest.sequence(), final_project_sequence);
    assert_eq!(latest.kind().as_str(), "html_sync.publication");
    assert_eq!(
        latest.payload().as_value()["status"],
        Value::String("published".to_owned())
    );
    let state_event = events
        .iter()
        .find(|event| event.sequence() == final_project_sequence - 1)
        .expect("synced state event");
    assert_eq!(state_event.kind().as_str(), "html_sync.state");
    assert_eq!(state_event.payload().as_value()["state"], "synced");
    assert_eq!(
        journal.file(PublicationFileRole::Html).expect("html").h1_request_id(),
        Some(&herness_core::PublicationRequestId::new(format!("{}:html", publication_id())).expect("id"))
    );
    assert_eq!(
        journal
            .file(PublicationFileRole::Receipt)
            .expect("receipt")
            .h1_request_id(),
        Some(&herness_core::PublicationRequestId::new(format!("{}:receipt", publication_id())).expect("id"))
    );
}

#[allow(clippy::too_many_arguments)]
fn publish_allow(
    env: &Env,
    attempt: CandidatePublication,
    h3_fail: Option<usize>,
    records_fail: Option<usize>,
    h3_archive_fail: Option<usize>,
    h1_archive_fail: Option<usize>,
    final_check: &dyn FinalCandidateCheckPort,
    safety: &dyn PublicationSafetyPort,
    expectations: &mut dyn PublicationWriteExpectationPort,
) -> Result<PublicationOutcome, H3Error> {
    publish_direct(
        env,
        FaultyH3Store::new(env.store.clone(), h3_fail),
        writer(
            env,
            FaultyRecords::new(H3PublicationRecords::new(env.store.clone()), records_fail),
            archive(env, h1_archive_fail),
            AllowGate,
        ),
        archive(env, h3_archive_fail),
        final_check,
        safety,
        expectations,
        attempt,
    )
}

fn old_receipt(env: &Env, old_html: &[u8]) -> Vec<u8> {
    let policy = env.policy.digest();
    let css = ContentDigest::sha256(
        &fs::read(env.fixture.root.join("docs/sdd/assets/sdd.css")).expect("css"),
    );
    let value = serde_json::json!({
        "schema": "sdd-html-receipt",
        "version": 1,
        "contract": "semantic-v1",
        "source": {
            "path": TARGET_PATH,
            "digest": format!("sha256:{}", ContentDigest::sha256(&env.source).as_str()),
        },
        "html": {
            "path": "docs/adr/0001-queue-choice.html",
            "digest": format!("sha256:{}", ContentDigest::sha256(old_html).as_str()),
        },
        "inputs": {
            "css": [{"path": "docs/sdd/assets/sdd.css", "digest": format!("sha256:{}", css.as_str())}],
            "resources": [],
            "policy": {"version": PACK_POLICY_VERSION, "digest": format!("sha256:{}", policy.as_str())},
        },
        "versions": {"settings": "settings:0", "rubric": "h3-html-evaluation-v1", "profile": "previous-profile"},
        "generation": {"id": "previous-generation", "revision": 0, "parent": null, "job": JOB, "cycle": "previous-cycle"},
        "h2": {"reference": supervision().to_string(), "purpose": "Html"},
        "verification": {"result": "pass", "checks": [{"name": "static", "decision": "pass", "evidence": ["old-static"]}]},
        "conditions": [
            {"id": "information", "decision": "met", "evidence": ["old-information"]},
            {"id": "support", "decision": "met", "evidence": ["old-support"]},
            {"id": "usability", "decision": "met", "evidence": ["old-usability"]},
            {"id": "render", "decision": "met", "evidence": ["old-render"]}
        ],
    });
    serde_json::to_vec_pretty(&value).expect("old receipt")
}

fn archive_entry(env: &Env, reference: &str) -> Value {
    let bytes = fs::read(env.archive_root.join(reference)).expect("archive entry");
    serde_json::from_slice(&bytes).expect("archive JSON")
}

#[test]
fn old_html_and_receipt_are_retained_with_exact_bytes_and_the_generation_chains() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let old_html = b"<!doctype html><html><body><p>old version</p></body></html>".to_vec();
    let old_receipt = old_receipt(&env, &old_html);
    env.set_companion(&old_html);
    env.set_receipt(&old_receipt);
    let old_html_digest = ContentDigest::sha256(&old_html);
    let old_receipt_digest = ContentDigest::sha256(&old_receipt);
    let expected_html = ExpectedTargetVersion::Present {
        version: herness_core::FileVersion::new(old_html_digest.as_str()).expect("file version"),
    };
    let expected_receipt = ExpectedTargetVersion::Present {
        version: herness_core::FileVersion::new(old_receipt_digest.as_str()).expect("file version"),
    };
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        env.attempt(expected_html, expected_receipt),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("publication");
    assert!(matches!(outcome, PublicationOutcome::Synced { .. }));
    assert_eq!(env.companion().expect("html"), env.candidate_html.as_bytes());
    let journal = env.journal().expect("journal");
    assert_eq!(journal.status(), PublicationStatus::Published);
    let old_html_ref = journal.old_html().expect("old html ref");
    let old_receipt_ref = journal.old_receipt().expect("old receipt ref");
    assert_eq!(old_html_ref.digest(), &old_html_digest);
    assert_eq!(old_receipt_ref.digest(), &old_receipt_digest);
    let archived_html = archive_entry(&env, old_html_ref.reference());
    assert_eq!(archived_html["content"].as_str().expect("content"), std::str::from_utf8(&old_html).expect("utf8"));
    assert_eq!(archived_html["target"], "docs/adr/0001-queue-choice.html");
    let archived_receipt = archive_entry(&env, old_receipt_ref.reference());
    assert_eq!(
        archived_receipt["content"].as_str().expect("content"),
        std::str::from_utf8(&old_receipt).expect("utf8")
    );
    let published_receipt: Value =
        serde_json::from_slice(&env.receipt().expect("receipt")).expect("receipt JSON");
    assert_eq!(published_receipt["generation"]["revision"], 1);
    assert_eq!(published_receipt["generation"]["parent"], "previous-generation");
}

#[test]
fn duplicate_publication_returns_the_stored_result_with_zero_extra_writes() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    let mut first = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut first,
    )
    .expect("first publication");
    let PublicationOutcome::Synced {
        final_project_sequence,
        ..
    } = outcome
    else {
        panic!("expected synced");
    };
    let journal_before = env.journal().expect("journal");
    let events_before = env
        .store
        .history(herness_core::HistoryQuery::first(project()))
        .expect("history")
        .events()
        .len();
    env.set_companion(b"external edit after publication");
    let mut second = RecordingExpectations::default();
    let duplicate = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut second,
    )
    .expect("duplicate");
    let PublicationOutcome::Synced {
        duplicate: true,
        final_project_sequence: duplicate_sequence,
        ..
    } = duplicate
    else {
        panic!("expected duplicate synced, got {duplicate:?}");
    };
    assert_eq!(duplicate_sequence, final_project_sequence);
    assert_eq!(
        env.companion().expect("html"),
        b"external edit after publication"
    );
    assert!(second.expected.is_empty());
    assert!(second.retired.is_empty());
    let journal_after = env.journal().expect("journal");
    assert_eq!(journal_after.status(), PublicationStatus::Published);
    assert_eq!(
        journal_after.final_project_sequence(),
        journal_before.final_project_sequence()
    );
    assert_eq!(
        journal_after.observed_after_html(),
        journal_before.observed_after_html()
    );
    let events_after = env
        .store
        .history(herness_core::HistoryQuery::first(project()))
        .expect("history")
        .events()
        .len();
    assert_eq!(events_after, events_before, "duplicate added no event");

    // The same publication id with different exact inputs is a conflict and
    // also does not touch the external edit.
    let changed = CandidatePublication::new(
        publication_id(),
        env.document.clone(),
        env.document_revision,
        env.settings.version(),
        env.generation.clone(),
        format!("{}<!-- changed -->", env.candidate_html),
        env.provenance.clone(),
        env.source.clone(),
        vec![env.css.clone()],
        Vec::new(),
        env.policy.clone(),
        env.applied.clone(),
        ExpectedTargetVersion::Absent,
        ExpectedTargetVersion::Absent,
    )
    .expect("changed attempt");
    let conflict = publish_allow(
        &env,
        changed,
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut second,
    )
    .expect("conflict");
    assert!(matches!(conflict, PublicationOutcome::Conflict { .. }));
    assert_eq!(
        env.companion().expect("html"),
        b"external edit after publication"
    );
}

#[test]
fn an_existing_companion_or_receipt_that_differs_from_the_expected_version_is_a_conflict() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    let existing = b"<!doctype html><html><body><p>external</p></body></html>";
    env.set_companion(existing);
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("conflict");
    assert!(matches!(
        outcome,
        PublicationOutcome::Conflict { ref target, .. }
            if target == "docs/adr/0001-queue-choice.html"
    ));
    assert_eq!(env.companion().expect("html"), existing);
    assert!(env.receipt().is_none());
    let journal = env.journal().expect("journal");
    assert_eq!(journal.status(), PublicationStatus::Conflict);
    let document = env.document_record();
    assert_eq!(
        document.state().state(),
        herness_html_sync::H3State::WaitingHuman
    );
    match document.state().reason().kind() {
        H3StateReasonKind::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::ExternalHtmlConflict,
        } => {}
        other => panic!("expected external conflict, got {other:?}"),
    }

    // An expected present version that differs from the formal file is the
    // same class of conflict.
    let env_present = Env::new();
    env_present.set_companion(existing);
    let mut expectations_present = RecordingExpectations::default();
    let outcome = publish_allow(
        &env_present,
        env_present.attempt(
            ExpectedTargetVersion::Present {
                version: herness_core::FileVersion::new("0".repeat(64)).expect("version"),
            },
            ExpectedTargetVersion::Absent,
        ),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env_present.final_check,
        },
        &allows(),
        &mut expectations_present,
    )
    .expect("present-version conflict");
    assert!(matches!(outcome, PublicationOutcome::Conflict { .. }));
    assert_eq!(env_present.companion().expect("html"), existing);

    // A present receipt with an unexpected version is the same class of
    // conflict and never overwrites the companion.
    let env2 = Env::new();
    env2.remove_companion();
    env2.set_receipt(b"{\"not\":\"the expected receipt\"}");
    let mut expectations2 = RecordingExpectations::default();
    let outcome = publish_allow(
        &env2,
        env2.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env2.final_check,
        },
        &allows(),
        &mut expectations2,
    )
    .expect("receipt conflict");
    assert!(matches!(outcome, PublicationOutcome::Conflict { .. }));
    assert!(env2.companion().is_none());
    assert_eq!(
        env2.receipt().expect("receipt"),
        b"{\"not\":\"the expected receipt\"}"
    );
}

#[test]
fn source_and_candidate_changes_are_refused_before_any_write() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    fs::write(env.fixture.root.join(TARGET_PATH), b"changed source\n").expect("change source");
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("source refusal");
    assert!(matches!(outcome, PublicationOutcome::NotPublished { .. }));
    assert!(env.companion().is_none());
    assert!(env.receipt().is_none());
    assert_eq!(
        env.journal().expect("journal").status(),
        PublicationStatus::NotPublished
    );

    let env2 = Env::new();
    env2.remove_companion();
    env2.remove_receipt();
    let changed = CandidatePublication::new(
        publication_id(),
        env2.document.clone(),
        env2.document_revision,
        env2.settings.version(),
        env2.generation.clone(),
        format!("{}<!-- stale -->", env2.candidate_html),
        env2.provenance.clone(),
        env2.source.clone(),
        vec![env2.css.clone()],
        Vec::new(),
        env2.policy.clone(),
        env2.applied.clone(),
        ExpectedTargetVersion::Absent,
        ExpectedTargetVersion::Absent,
    )
    .expect("changed candidate");
    let mut expectations2 = RecordingExpectations::default();
    let outcome = publish_allow(
        &env2,
        changed,
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env2.final_check,
        },
        &allows(),
        &mut expectations2,
    )
    .expect("candidate refusal");
    assert!(matches!(outcome, PublicationOutcome::NotPublished { .. }));
    assert!(env2.companion().is_none());
    assert!(env2.receipt().is_none());
    assert_eq!(
        env2.journal().expect("journal").status(),
        PublicationStatus::NotPublished
    );
}

#[test]
fn final_validation_denial_blocks_publication_and_structural_only_is_not_final() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &RejectingFinal {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("final denial");
    assert!(matches!(outcome, PublicationOutcome::NotPublished { .. }));
    assert!(env.companion().is_none());
    assert!(env.receipt().is_none());
    let journal = env.journal().expect("journal");
    assert_eq!(journal.status(), PublicationStatus::NotPublished);
    assert!(journal.detail().is_some());
    let document = env.document_record();
    assert_eq!(document.state().state(), herness_html_sync::H3State::Failed);
    match document.state().reason().kind() {
        H3StateReasonKind::Failed {
            cause: herness_html_sync::H3FailureCause::CandidateRejected,
        } => {}
        other => panic!("expected candidate rejection, got {other:?}"),
    }

    let env2 = Env::new();
    env2.remove_companion();
    env2.remove_receipt();
    let mut expectations2 = RecordingExpectations::default();
    let outcome = publish_allow(
        &env2,
        env2.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &StructuralOnly {
            inner: &env2.final_check,
        },
        &allows(),
        &mut expectations2,
    )
    .expect("structural-only denial");
    assert!(matches!(outcome, PublicationOutcome::NotPublished { .. }));
    assert!(env2.companion().is_none());
    assert!(env2.receipt().is_none());
    assert!(env2.archive_root.read_dir().map(|mut entries| entries.next().is_none()).unwrap_or(true));
}

#[test]
fn stop_consent_budget_and_approval_rechecks_refuse_before_writing() {
    if skip_without_pack() {
        return;
    }
    for (label, safety, expected_wait, expected_stop) in [
        (
            "consent",
            PublicationSafety {
                stop_requested: false,
                consent_current: false,
                approval_current: true,
                budget_remaining: true,
            },
            Some(herness_html_sync::HumanWaitCause::PermissionDenied),
            None,
        ),
        (
            "approval",
            PublicationSafety {
                stop_requested: false,
                consent_current: true,
                approval_current: false,
                budget_remaining: true,
            },
            Some(herness_html_sync::HumanWaitCause::PermissionDenied),
            None,
        ),
        (
            "budget",
            PublicationSafety {
                stop_requested: false,
                consent_current: true,
                approval_current: true,
                budget_remaining: false,
            },
            None,
            Some(herness_html_sync::H3StopCause::BudgetLimit),
        ),
        (
            "stop",
            PublicationSafety {
                stop_requested: true,
                consent_current: true,
                approval_current: true,
                budget_remaining: true,
            },
            None,
            Some(herness_html_sync::H3StopCause::HumanRequest),
        ),
    ] {
        let env = Env::new();
        env.remove_companion();
        env.remove_receipt();
        let mut expectations = RecordingExpectations::default();
        let outcome = publish_allow(
            &env,
            env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
            None,
            None,
            None,
            None,
            &FinalOnly {
                inner: &env.final_check,
            },
            &ScriptedSafety { safety },
            &mut expectations,
        )
        .unwrap_or_else(|error| panic!("{label}: {error}"));
        match (expected_wait, expected_stop) {
            (Some(cause), None) => {
                assert!(
                    matches!(outcome, PublicationOutcome::WaitingHuman { cause: found, .. } if found == cause),
                    "{label}: {outcome:?}"
                );
            }
            (None, Some(cause)) => {
                assert!(
                    matches!(outcome, PublicationOutcome::Stopped { cause: found, .. } if found == cause),
                    "{label}: {outcome:?}"
                );
            }
            _ => unreachable!(),
        }
        assert!(env.companion().is_none(), "{label} must not write");
        assert!(env.receipt().is_none(), "{label} must not write");
        assert!(
            env.journal().expect("journal").status() == PublicationStatus::NotPublished,
            "{label}"
        );
    }

    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    env.control.request_stop(herness_core::StopReason::UserRequest);
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("stop refusal");
    assert!(matches!(
        outcome,
        PublicationOutcome::Stopped {
            cause: herness_html_sync::H3StopCause::HumanRequest,
            ..
        }
    ));
    assert!(env.companion().is_none());
}

#[test]
fn settings_policy_and_css_mismatches_are_refused_without_writing() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    let wrong_policy = PublicationPolicyIdentity::new(
        PACK_POLICY_VERSION,
        ContentDigest::sha256(b"wrong policy"),
        env.policy.pack().clone(),
    )
    .expect("policy identity");
    let attempt = CandidatePublication::new(
        publication_id(),
        env.document.clone(),
        env.document_revision,
        env.settings.version(),
        env.generation.clone(),
        env.candidate_html.clone(),
        env.provenance.clone(),
        env.source.clone(),
        vec![env.css.clone()],
        Vec::new(),
        wrong_policy,
        env.applied.clone(),
        ExpectedTargetVersion::Absent,
        ExpectedTargetVersion::Absent,
    )
    .expect("policy mismatch attempt");
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        attempt,
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("policy refusal");
    assert!(matches!(
        outcome,
        PublicationOutcome::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::CapabilityMissing,
            ..
        }
    ));
    assert!(env.companion().is_none());
    assert!(env.receipt().is_none());

    let env2 = Env::new();
    env2.remove_companion();
    env2.remove_receipt();
    let changed_css =
        PublicationFileInput::new("docs/sdd/assets/sdd.css", b"body { color: red; }\n".to_vec())
            .expect("css input");
    let attempt = CandidatePublication::new(
        publication_id(),
        env2.document.clone(),
        env2.document_revision,
        env2.settings.version(),
        env2.generation.clone(),
        env2.candidate_html.clone(),
        env2.provenance.clone(),
        env2.source.clone(),
        vec![changed_css],
        Vec::new(),
        env2.policy.clone(),
        env2.applied.clone(),
        ExpectedTargetVersion::Absent,
        ExpectedTargetVersion::Absent,
    )
    .expect("css mismatch attempt");
    let mut expectations2 = RecordingExpectations::default();
    let outcome = publish_allow(
        &env2,
        attempt,
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env2.final_check,
        },
        &allows(),
        &mut expectations2,
    )
    .expect("css refusal");
    assert!(matches!(outcome, PublicationOutcome::NotPublished { .. }));
    assert!(env2.companion().is_none());

    let env3 = Env::new();
    env3.remove_companion();
    env3.remove_receipt();
    let attempt = CandidatePublication::new(
        publication_id(),
        env3.document.clone(),
        env3.document_revision,
        env3.settings.version() + 7,
        env3.generation.clone(),
        env3.candidate_html.clone(),
        env3.provenance.clone(),
        env3.source.clone(),
        vec![env3.css.clone()],
        Vec::new(),
        env3.policy.clone(),
        env3.applied.clone(),
        ExpectedTargetVersion::Absent,
        ExpectedTargetVersion::Absent,
    )
    .expect("settings mismatch attempt");
    let mut expectations3 = RecordingExpectations::default();
    let outcome = publish_allow(
        &env3,
        attempt,
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env3.final_check,
        },
        &allows(),
        &mut expectations3,
    )
    .expect("settings refusal");
    assert!(matches!(
        outcome,
        PublicationOutcome::WaitingHuman {
            cause: herness_html_sync::HumanWaitCause::PermissionDenied,
            ..
        }
    ));
    assert!(env3.companion().is_none());
}

#[test]
fn archive_save_faults_never_replace_any_formal_file() {
    if skip_without_pack() {
        return;
    }
    let old_html = b"<!doctype html><html><body><p>old</p></body></html>".to_vec();
    let old_receipt = old_receipt(&Env::new(), &old_html);

    for (label, h3_fail, h1_fail) in [
        ("h3-html", Some(1), None),
        ("h3-receipt", Some(2), None),
        ("h1-html", None, Some(1)),
    ] {
        let env = Env::new();
        env.set_companion(&old_html);
        env.set_receipt(&old_receipt);
        let expected_html = ExpectedTargetVersion::Present {
            version: herness_core::FileVersion::new(
                ContentDigest::sha256(&old_html).as_str(),
            )
            .expect("file version"),
        };
        let expected_receipt = ExpectedTargetVersion::Present {
            version: herness_core::FileVersion::new(
                ContentDigest::sha256(&old_receipt).as_str(),
            )
            .expect("file version"),
        };
        let mut expectations = RecordingExpectations::default();
        let outcome = publish_allow(
            &env,
            env.attempt(expected_html, expected_receipt),
            None,
            None,
            h3_fail,
            h1_fail,
            &FinalOnly {
                inner: &env.final_check,
            },
            &allows(),
            &mut expectations,
        )
        .unwrap_or_else(|error| panic!("{label}: {error}"));
        assert!(
            matches!(
                outcome,
                PublicationOutcome::WaitingHuman {
                    cause: herness_html_sync::HumanWaitCause::CapacityInsufficient,
                    ..
                }
            ),
            "{label}: {outcome:?}"
        );
        assert_eq!(env.companion().expect("html"), old_html, "{label}");
        assert_eq!(env.receipt().expect("receipt"), old_receipt, "{label}");
        assert_eq!(
            env.journal().expect("journal").status(),
            PublicationStatus::NotPublished,
            "{label}"
        );
    }
}

#[test]
fn h3_intent_and_pre_replace_commit_faults_leave_no_file_side_effect() {
    if skip_without_pack() {
        return;
    }
    for (fail_on, durable) in [(1, false), (2, true), (3, true)] {
        let env = Env::new();
        env.remove_companion();
        env.remove_receipt();
        let mut expectations = RecordingExpectations::default();
        let result = publish_allow(
            &env,
            env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
            Some(fail_on),
            None,
            None,
            None,
            &FinalOnly {
                inner: &env.final_check,
            },
            &allows(),
            &mut expectations,
        );
        assert!(result.is_err(), "commit {fail_on} must fail");
        assert!(env.companion().is_none(), "commit {fail_on} wrote html");
        assert!(env.receipt().is_none(), "commit {fail_on} wrote receipt");
        assert_eq!(env.journal().is_some(), durable, "commit {fail_on}");
        if fail_on >= 3 {
            assert_eq!(expectations.expected.len(), 1, "commit {fail_on}");
        } else {
            assert!(expectations.expected.is_empty(), "commit {fail_on}");
        }
        assert!(expectations.retired.is_empty());
        if let Some(journal) = env.journal() {
            let expected_status = if fail_on == 2 {
                PublicationStatus::Prepared
            } else {
                PublicationStatus::OldVersionSaved
            };
            assert_eq!(journal.status(), expected_status);
            let mut retry = RecordingExpectations::default();
            let duplicate = publish_allow(
                &env,
                env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
                None,
                None,
                None,
                None,
                &FinalOnly {
                    inner: &env.final_check,
                },
                &allows(),
                &mut retry,
            )
            .expect("duplicate after an interrupted intent");
            assert!(matches!(
                duplicate,
                PublicationOutcome::ReconciliationRequired { .. }
            ));
            assert!(retry.expected.is_empty());
        }
    }
}

#[test]
fn a_fault_after_both_writes_is_reconciliation_required_not_synced() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        Some(4),
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("after-write fault");
    assert!(matches!(
        outcome,
        PublicationOutcome::ReconciliationRequired { .. }
    ));
    assert_eq!(env.companion().expect("html"), env.candidate_html.as_bytes());
    assert!(env.receipt().is_some());
    let journal = env.journal().expect("journal");
    assert_eq!(journal.status(), PublicationStatus::Replacing);
    assert_eq!(
        env.document_record().state().state(),
        herness_html_sync::H3State::Publishing
    );
    let mut retry = RecordingExpectations::default();
    let duplicate = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut retry,
    )
    .expect("duplicate after an uncommitted result");
    assert!(matches!(
        duplicate,
        PublicationOutcome::ReconciliationRequired { .. }
    ));
    assert!(retry.expected.is_empty());
}

#[test]
fn a_h1_intent_or_rename_failure_never_replaces_the_target() {
    if skip_without_pack() {
        return;
    }

    let env = Env::new();
    let existing = b"<!doctype html><html><body><p>existing</p></body></html>";
    env.set_companion(existing);
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        env.attempt(
            ExpectedTargetVersion::Present {
                version: herness_core::FileVersion::new(
                    ContentDigest::sha256(existing).as_str(),
                )
                .expect("version"),
            },
            ExpectedTargetVersion::Absent,
        ),
        None,
        Some(1),
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("intent failure");
    assert!(
        matches!(outcome, PublicationOutcome::NotPublished { .. }),
        "intent failure outcome: {outcome:?}"
    );
    assert_eq!(env.companion().expect("html"), existing);
    assert!(env.receipt().is_none());

    let env2 = Env::new();
    env2.set_companion(existing);
    let mut expectations2 = RecordingExpectations::default();
    let files = files(&env2);
    let mut store = FaultyH3Store::new(env2.store.clone(), None);
    let mut h3_archive = archive(&env2, None);
    let mut writer = writer(
        &env2,
        FaultyRecords::new(H3PublicationRecords::new(env2.store.clone()), None),
        archive(&env2, None),
        DenyAfterGate {
            allowed: 1,
            calls: Cell::new(0),
        },
    );
    let mut orchestrator = PublicationOrchestrator {
        store: &mut store,
        files: &files,
        archive: &mut h3_archive,
        host: &mut writer,
        final_check: &FinalOnly {
            inner: &env2.final_check,
        },
        safety: &allows(),
        expectations: &mut expectations2,
        control: &env2.control,
    };
    let outcome = orchestrator
        .publish(
            env2.attempt(
                ExpectedTargetVersion::Present {
                    version: herness_core::FileVersion::new(
                        ContentDigest::sha256(existing).as_str(),
                    )
                    .expect("version"),
                },
                ExpectedTargetVersion::Absent,
            ),
            now(),
        )
        .expect("gate failure");
    assert!(
        matches!(
            outcome,
            PublicationOutcome::WaitingHuman {
                cause: herness_html_sync::HumanWaitCause::PermissionDenied,
                ..
            }
        ),
        "gate failure outcome: {outcome:?}"
    );
    assert_eq!(env2.companion().expect("html"), existing);
    assert!(env2.receipt().is_none());
    assert_eq!(
        env2.journal().expect("journal").status(),
        PublicationStatus::NotPublished
    );
}

#[test]
fn a_h1_result_fault_after_the_rename_is_unverifiable_and_never_retried_as_success() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        Some(2),
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("result persistence fault");
    assert!(matches!(
        outcome,
        PublicationOutcome::ReconciliationRequired { .. }
    ));
    assert_eq!(env.companion().expect("html"), env.candidate_html.as_bytes());
    assert!(env.receipt().is_none());
    let journal = env.journal().expect("journal");
    assert_eq!(journal.status(), PublicationStatus::Unverifiable);
    assert_eq!(
        env.document_record().state().state(),
        herness_html_sync::H3State::WaitingHuman
    );

    let mut retry = RecordingExpectations::default();
    let duplicate = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut retry,
    )
    .expect("duplicate");
    assert!(matches!(
        duplicate,
        PublicationOutcome::ReconciliationRequired { .. }
    ));
    assert!(retry.expected.is_empty());
}

#[test]
fn a_receipt_failure_after_the_html_is_published_is_reconciliation_required() {
    if skip_without_pack() {
        return;
    }
    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    let mut expectations = RecordingExpectations::default();
    let outcome = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        Some(3),
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("receipt failure");
    assert!(matches!(
        outcome,
        PublicationOutcome::ReconciliationRequired { .. }
    ));
    assert_eq!(env.companion().expect("html"), env.candidate_html.as_bytes());
    assert!(env.receipt().is_none());
    let journal = env.journal().expect("journal");
    assert_eq!(journal.status(), PublicationStatus::Unverifiable);
    assert_eq!(
        journal
            .file(PublicationFileRole::Html)
            .expect("html file")
            .status(),
        PublicationFileStatus::Published
    );
    assert_ne!(
        journal
            .file(PublicationFileRole::Receipt)
            .expect("receipt file")
            .status(),
        PublicationFileStatus::Published
    );
    assert_eq!(
        env.document_record().state().state(),
        herness_html_sync::H3State::WaitingHuman
    );
}

struct MutatingGate {
    path: PathBuf,
    bytes: Vec<u8>,
    done: Cell<bool>,
}

impl PublicationGatePort for MutatingGate {
    fn authorize_publication(
        &self,
        _request: &PublicationRequest,
    ) -> Result<(), herness_core::PublicationFailure> {
        if !self.done.get() {
            self.done.set(true);
            fs::write(&self.path, &self.bytes).expect("injected external change");
        }
        Ok(())
    }
}

#[test]
fn a_source_or_dependency_change_detected_after_the_writes_is_never_synced() {
    if skip_without_pack() {
        return;
    }
    for (label, path, bytes) in [
        (
            "source",
            TARGET_PATH.to_owned(),
            b"changed after publication\n".to_vec(),
        ),
        (
            "dependency",
            "docs/sdd/assets/sdd.css".to_owned(),
            b"body { color: red; }\n".to_vec(),
        ),
    ] {
        let env = Env::new();
        env.remove_companion();
        env.remove_receipt();
        let mut expectations = RecordingExpectations::default();
        let files = files(&env);
        let mut store = FaultyH3Store::new(env.store.clone(), None);
        let mut h3_archive = archive(&env, None);
        let mut writer = writer(
            &env,
            FaultyRecords::new(H3PublicationRecords::new(env.store.clone()), None),
            archive(&env, None),
            MutatingGate {
                path: env.fixture.root.join(&path),
                bytes,
                done: Cell::new(false),
            },
        );
        let mut orchestrator = PublicationOrchestrator {
            store: &mut store,
            files: &files,
            archive: &mut h3_archive,
            host: &mut writer,
            final_check: &FinalOnly {
                inner: &env.final_check,
            },
            safety: &allows(),
            expectations: &mut expectations,
            control: &env.control,
        };
        let outcome = orchestrator
            .publish(
                env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
                now(),
            )
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        assert!(
            matches!(outcome, PublicationOutcome::ReconciliationRequired { .. }),
            "{label}: {outcome:?}"
        );
        assert_eq!(
            env.companion().expect("html"),
            env.candidate_html.as_bytes(),
            "{label}"
        );
        let journal = env.journal().expect("journal");
        assert_eq!(journal.status(), PublicationStatus::Unverifiable, "{label}");
        assert_eq!(
            env.document_record().state().state(),
            herness_html_sync::H3State::WaitingHuman,
            "{label}"
        );
    }
}

#[test]
fn the_observer_absorbs_the_self_publication_notification_by_id_and_bytes() {
    if skip_without_pack() {
        return;
    }
    use herness_html_sync::{
        CompanionChange, DependencyPath, DependencyKind, ObservationTargets,
    };
    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    let targets = ObservationTargets::new(
        project(),
        vec![env.document.clone()],
        vec![DependencyPath::new(
            "docs/sdd/assets/sdd.css",
            DependencyKind::Css,
        )
        .expect("dependency")],
    )
    .expect("targets");
    let mut observer = ProjectObserver::new(
        targets,
        ObservationEligibility::approved(env.settings.version()).expect("eligibility"),
        FilesystemSourceReader::new(&env.fixture.root).expect("reader"),
        SystemObservationClock::new(),
    )
    .expect("observer");
    observer.initial_scan();
    let mut expectations = ObserverWriteExpectations::new(&mut observer);
    let outcome = publish_allow(
        &env,
        env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
        None,
        None,
        None,
        None,
        &FinalOnly {
            inner: &env.final_check,
        },
        &allows(),
        &mut expectations,
    )
    .expect("publication");
    assert!(matches!(outcome, PublicationOutcome::Synced { .. }));
    let companions = expectations.take_companions();
    assert_eq!(companions.len(), 2, "html and receipt");
    let expected_request =
        herness_core::PublicationRequestId::new(format!("{}:html", publication_id()))
            .expect("request id");
    for companion in &companions {
        match &companion.change {
            CompanionChange::SelfNotification {
                publication,
                request,
            } => {
                assert_eq!(*publication, publication_id());
                assert_eq!(request, &expected_request);
            }
            other => panic!("expected self notification, got {other:?}"),
        }
    }
    assert!(
        companions
            .iter()
            .any(|companion| companion.path == "docs/adr/0001-queue-choice.html")
    );
    assert!(
        companions
            .iter()
            .any(|companion| companion.path == env.receipt_path)
    );
    assert!(expectations.take_sources().is_empty());
    assert!(expectations.take_uncertainties().is_empty());

    // After retirement the same path with different bytes is external.
    let observer = expectations.into_inner();
    let changed = format!("{}\n<!-- external -->", env.candidate_html);
    fs::write(
        env.fixture.root.join(env.document.companion_path()),
        changed.as_bytes(),
    )
    .expect("external edit");
    assert!(observer.notify(
        ChangeSignal::new(
            env.document.companion_path(),
            ChangeSource::ExternalEditor,
        )
        .expect("signal")
    ));
    let tick = observer.poll();
    assert!(tick.companions.iter().any(|companion| matches!(
        companion.change,
        CompanionChange::External
    )));
}

#[test]
fn the_desktop_publisher_composes_the_real_writer_archive_and_safety_port() {
    if skip_without_pack() {
        return;
    }
    use herness_desktop::html_sync::publish::DesktopPublisher;
    let env = Env::new();
    env.remove_companion();
    env.remove_receipt();
    let bridge = HtmlPolicyBridge::detect(&env.fixture.root, REAL_PACK_ROOT, toolchain())
        .expect("detect pack");
    let connected = bridge
        .connect(&env.settings.approval().expect("approval").pack_binding())
        .expect("connect");
    let mut publisher = DesktopPublisher::new(
        project(),
        &env.fixture.root,
        env.store.clone(),
        env.archive_root.clone(),
        PolicyFinalCheck::new(connected),
        env.control.clone(),
    )
    .expect("desktop publisher");
    let mut expectations = RecordingExpectations::default();
    let outcome = publisher
        .publish(
            env.attempt(ExpectedTargetVersion::Absent, ExpectedTargetVersion::Absent),
            &mut expectations,
            now(),
        )
        .expect("desktop publication");
    assert!(
        matches!(outcome, PublicationOutcome::Synced { .. }),
        "{outcome:?}"
    );
    assert_eq!(env.companion().expect("html"), env.candidate_html.as_bytes());
    assert!(env.receipt().is_some());
    assert_eq!(expectations.retired, vec![publication_id()]);
}

#[test]
fn the_desktop_safety_port_rechecks_the_real_approval_and_consent() {
    if skip_without_pack() {
        return;
    }
    use herness_desktop::html_sync::publish::H3PublicationSafety;
    use herness_html_sync::SettingsCommit;
    let env = Env::new();
    let safety = H3PublicationSafety::new(env.store.clone(), env.control.clone());
    let settings_record = env
        .store
        .lock()
        .load_html_sync_settings(project())
        .expect("settings")
        .expect("stored settings");
    let request = PublicationSafetyRequest {
        document: &env.document,
        generation: &env.generation,
        settings: settings_record.settings(),
        target_version: target_version(),
        profile: profile(ProfilePurpose::Html),
        now: now(),
    };
    let allowed = safety.recheck(&request).expect("safety");
    assert!(allowed.permits_publication(), "{allowed:?}");

    let revoked = settings_record
        .settings()
        .approval()
        .expect("approval")
        .clone()
        .revoke(now());
    let revoked_settings =
        H3Settings::approved(revoked, true).expect("revoked settings");
    env.store
        .lock()
        .commit_html_sync(
            HtmlSyncCommit::new().with_settings(
                SettingsCommit::new(Some(settings_record.revision()), revoked_settings)
                    .expect("settings commit"),
            ),
        )
        .expect("store revoked settings");
    let current = env
        .store
        .lock()
        .load_html_sync_settings(project())
        .expect("settings")
        .expect("stored settings");
    let request = PublicationSafetyRequest {
        document: &env.document,
        generation: &env.generation,
        settings: current.settings(),
        target_version: target_version(),
        profile: profile(ProfilePurpose::Html),
        now: now(),
    };
    let denied = safety.recheck(&request).expect("safety");
    assert!(!denied.approval_current);
    assert!(!denied.permits_publication());
}
