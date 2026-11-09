//! H3 observer tests: real temporary filesystem, fake clock, no sleeps.
//!
//! Every test drives the injected clock. The `.md`, companion, receipt, CSS,
//! and resource bytes are written to real temporary directories; only the
//! unstable-read test injects a port implementation around the real reader.

#![cfg(unix)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use herness_core::{AbsolutePath, PublicationRequestId, Timestamp};
use herness_desktop::html_sync::observer::ProjectFilesystemWatcher;
use herness_html_sync::{
    ApplicabilityReason, ChangeSignal, ChangeSource, CompanionChange, CompanionFileKind,
    DependencyKind, DependencyPath, DocumentKey, ExpectedPublicationWrite, FileRead,
    FilesystemSourceReader, H3Settings, IneligibleReason, ObservationClock, ObservationEligibility,
    ObservationTargets, ObservationUncertainty, ProjectObserver, PublicationId, SourceChange,
    SourceReadError, SourceReadPort, SourceRevision, SourceSnapshot, WatcherStatus,
    html_evidence_path,
};
use herness_html_sync_tests::fixtures::{NOW_MILLIS, project as fixture_project};
use herness_supervision::{ClockReading, ContentDigest};
use tempfile::TempDir;
use uuid::Uuid;

const TARGET: &str = "docs/sdd/specs/2026-11-09-h3-html-sync-design.md";
const SECOND_TARGET: &str = "docs/sdd/plans/2026-11-10-h3-plan.md";

#[derive(Clone, Debug)]
struct FakeClock {
    reading: Arc<Mutex<ClockReading>>,
}

impl FakeClock {
    fn new() -> Self {
        Self {
            reading: Arc::new(Mutex::new(ClockReading::new(
                Timestamp::from_unix_millis(NOW_MILLIS),
                0,
            ))),
        }
    }

    fn advance(&self, millis: u64) {
        let mut reading = self.reading.lock().expect("fake clock lock");
        *reading = ClockReading::new(
            Timestamp::from_unix_millis(reading.wall().as_unix_millis().saturating_add(millis)),
            reading.monotonic_millis().saturating_add(millis),
        );
    }
}

impl ObservationClock for FakeClock {
    fn read(&self) -> ClockReading {
        *self.reading.lock().expect("fake clock lock")
    }
}

struct TestProject {
    dir: TempDir,
}

impl TestProject {
    fn new() -> Self {
        Self {
            dir: TempDir::new().expect("temporary project"),
        }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent directory");
        }
        let mut file = fs::File::create(&path).expect("create test file");
        file.write_all(bytes).expect("write test file");
        path
    }

    fn write_atomic(&self, relative: &str, bytes: &[u8], temp: &str) -> PathBuf {
        let target = self.root().join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).expect("create parent directory");
        }
        let temp_path = self.root().join(temp);
        let mut file = fs::File::create(&temp_path).expect("create temp file");
        file.write_all(bytes).expect("write temp file");
        file.sync_all().expect("sync temp file");
        fs::rename(&temp_path, &target).expect("atomic rename");
        target
    }
}

fn approved() -> ObservationEligibility {
    ObservationEligibility::approved(1).expect("approved settings version")
}

fn key(path: &str) -> DocumentKey {
    DocumentKey::new(fixture_project(), path).expect("document key")
}

fn make_observer(
    root: &Path,
    documents: &[&str],
    dependencies: &[(&str, DependencyKind)],
    eligibility: ObservationEligibility,
    clock: FakeClock,
) -> ProjectObserver<FilesystemSourceReader, FakeClock> {
    let documents = documents.iter().map(|path| key(path)).collect::<Vec<_>>();
    let dependencies = dependencies
        .iter()
        .map(|(path, kind)| DependencyPath::new(*path, *kind).expect("dependency"))
        .collect::<Vec<_>>();
    let targets = ObservationTargets::new(fixture_project(), documents, dependencies)
        .expect("observation targets");
    ProjectObserver::new(
        targets,
        eligibility,
        FilesystemSourceReader::new(root).expect("filesystem reader"),
        clock,
    )
    .expect("project observer")
}

fn signal(path: &str, source: ChangeSource) -> ChangeSignal {
    ChangeSignal::new(path, source).expect("change signal")
}

fn settle(clock: &FakeClock) {
    clock.advance(750);
}

#[test]
fn real_temp_filesystem_external_change_is_content_compared_and_settled() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    let clock = FakeClock::new();
    let mut observer = make_observer(project.root(), &[TARGET], &[], approved(), clock.clone());
    let document = key(TARGET);

    let initial = observer.initial_scan();
    assert_eq!(initial.sources.len(), 1);
    assert_eq!(initial.sources[0].change, SourceChange::Initial);
    assert_eq!(initial.sources[0].snapshot.revision().get(), 1);
    assert_eq!(
        initial.sources[0].snapshot.digest(),
        &ContentDigest::sha256(b"one")
    );
    assert_eq!(initial.authoring_candidates().len(), 1);
    assert!(initial.sources[0].observed_via.is_empty());

    project.write(TARGET, b"two");
    assert!(observer.notify(signal(TARGET, ChangeSource::FilesystemWatcher)));

    clock.advance(700);
    let early = observer.poll();
    assert!(
        early.sources.is_empty(),
        "the quiet period is still running"
    );
    assert!(observer.is_pending(&document));
    assert_eq!(early.health.pending_documents, 1);

    clock.advance(50);
    let settled = observer.poll();
    assert_eq!(settled.sources.len(), 1);
    assert_eq!(settled.sources[0].change, SourceChange::Modified);
    assert_eq!(settled.sources[0].snapshot.revision().get(), 2);
    assert_eq!(
        settled.sources[0].snapshot.digest(),
        &ContentDigest::sha256(b"two")
    );
    assert_eq!(
        settled.sources[0].observed_via,
        vec![ChangeSource::FilesystemWatcher]
    );
    assert_eq!(settled.authoring_candidates().len(), 1);
    assert!(!observer.is_pending(&document));

    // The same bytes notified again is an observation, never a second job.
    assert!(observer.notify(signal(TARGET, ChangeSource::Shell)));
    settle(&clock);
    let duplicate = observer.poll();
    assert_eq!(duplicate.sources.len(), 1);
    assert_eq!(duplicate.sources[0].change, SourceChange::Unchanged);
    assert_eq!(duplicate.sources[0].snapshot.revision().get(), 2);
    assert!(duplicate.authoring_candidates().is_empty());

    // Returning to exactly the first bytes is a new observation at revision 3;
    // the revision never moves backwards and the content digest is exact.
    project.write(TARGET, b"one");
    assert!(observer.notify(signal(TARGET, ChangeSource::ExternalEditor)));
    settle(&clock);
    let returned = observer.poll();
    assert_eq!(returned.sources.len(), 1);
    assert_eq!(returned.sources[0].change, SourceChange::Modified);
    assert_eq!(returned.sources[0].snapshot.revision().get(), 3);
    assert_eq!(
        returned.sources[0].snapshot.digest(),
        &ContentDigest::sha256(b"one")
    );
    assert!(returned.sources[0].snapshot.revision().get() > 2);
}

#[test]
fn atomic_save_and_rename_is_one_stable_revision() {
    let project = TestProject::new();
    project.write(TARGET, b"old");
    let clock = FakeClock::new();
    let mut observer = make_observer(project.root(), &[TARGET], &[], approved(), clock.clone());

    observer.initial_scan();
    project.write_atomic(TARGET, b"new", "docs/sdd/specs/.design.md.tmp");

    // A temp-file event is outside the caller-supplied Target set and ignored.
    assert!(!observer.notify(signal(
        "docs/sdd/specs/.design.md.tmp",
        ChangeSource::FilesystemWatcher
    )));
    // The final rename is the only notification for the Target.
    assert!(observer.notify(signal(TARGET, ChangeSource::FilesystemWatcher)));
    settle(&clock);
    let tick = observer.poll();
    assert_eq!(tick.sources.len(), 1);
    assert_eq!(tick.sources[0].change, SourceChange::Modified);
    assert_eq!(tick.sources[0].snapshot.revision().get(), 2);
    assert_eq!(
        tick.sources[0].snapshot.digest(),
        &ContentDigest::sha256(b"new")
    );
    assert_eq!(tick.authoring_candidates().len(), 1);
    assert!(!observer.is_pending(&key(TARGET)));
}

#[test]
fn missed_notification_is_explicit_and_recovered_by_the_periodic_scan() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    let clock = FakeClock::new();
    let mut observer = make_observer(project.root(), &[TARGET], &[], approved(), clock.clone());

    observer.initial_scan();
    project.write(TARGET, b"two");

    clock.advance(4_000);
    let early = observer.poll();
    assert!(early.sources.is_empty());

    clock.advance(1_000);
    let detected = observer.poll();
    assert!(detected.sources.is_empty(), "the quiet period starts first");
    assert!(detected.uncertainties.iter().any(|uncertainty| matches!(
        uncertainty,
        ObservationUncertainty::MissedNotification { document, .. } if document == &key(TARGET)
    )));
    assert!(observer.is_pending(&key(TARGET)));

    settle(&clock);
    let settled = observer.poll();
    assert_eq!(settled.sources.len(), 1);
    assert_eq!(settled.sources[0].change, SourceChange::Modified);
    assert_eq!(
        settled.sources[0].trigger,
        herness_html_sync::ObservationTrigger::PeriodicScan
    );
    assert_eq!(
        settled.sources[0].snapshot.digest(),
        &ContentDigest::sha256(b"two")
    );
}

#[test]
fn duplicate_notifications_from_every_source_create_one_authoring_candidate() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    let clock = FakeClock::new();
    let mut observer = make_observer(project.root(), &[TARGET], &[], approved(), clock.clone());
    let document = key(TARGET);
    observer.initial_scan();

    project.write(TARGET, b"two");
    for source in [
        ChangeSource::NativeSaved,
        ChangeSource::Shell,
        ChangeSource::ExternalEditor,
        ChangeSource::FilesystemWatcher,
        ChangeSource::NativeSaved,
    ] {
        assert!(observer.notify(signal(TARGET, source)));
    }
    settle(&clock);
    let tick = observer.poll();
    assert_eq!(tick.sources.len(), 1);
    assert_eq!(tick.authoring_candidates().len(), 1);
    assert_eq!(tick.sources[0].snapshot.revision().get(), 2);
    assert_eq!(
        tick.sources[0].observed_via,
        vec![
            ChangeSource::NativeSaved,
            ChangeSource::Shell,
            ChangeSource::ExternalEditor,
            ChangeSource::FilesystemWatcher,
        ]
    );

    // A second notification for exactly the same bytes does not add a job.
    assert!(observer.notify(signal(TARGET, ChangeSource::NativeSaved)));
    settle(&clock);
    let duplicate = observer.poll();
    assert_eq!(duplicate.sources[0].change, SourceChange::Unchanged);
    assert!(duplicate.authoring_candidates().is_empty());
    assert_eq!(
        observer
            .source_snapshot(&document)
            .unwrap()
            .revision()
            .get(),
        2
    );
}

#[test]
fn dotfiles_hierarchy_and_unrelated_paths_are_not_targets() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    project.write("docs/sdd/specs/nested/deep.md", b"deep");
    project.write("docs/sdd/specs/.hidden.md", b"hidden");
    project.write(".env", b"secret");
    project.write("README.md", b"readme");
    project.write("docs/sdd/plans/plan.md", b"plan");
    let clock = FakeClock::new();
    let mut observer = make_observer(
        project.root(),
        &[TARGET, "docs/sdd/specs/nested/deep.md"],
        &[],
        approved(),
        clock.clone(),
    );

    let initial = observer.initial_scan();
    assert_eq!(initial.sources.len(), 2);
    assert_eq!(
        initial
            .sources
            .iter()
            .map(|source| source.document.target_path().to_owned())
            .collect::<Vec<_>>(),
        vec![
            TARGET.to_owned(),
            "docs/sdd/specs/nested/deep.md".to_owned()
        ]
    );

    for path in [
        "docs/sdd/specs/.hidden.md",
        ".env",
        "README.md",
        "docs/sdd/plans/plan.md",
        "docs/sdd/specs/undeclared.md",
    ] {
        assert!(
            !observer.notify(signal(path, ChangeSource::FilesystemWatcher)),
            "{path} must not become a Target"
        );
    }
    settle(&clock);
    let tick = observer.poll();
    assert!(tick.sources.is_empty());
    assert!(tick.uncertainties.is_empty());
}

#[test]
fn symlink_escape_is_rejected_without_observing_the_outside_file() {
    let outside = TempDir::new().expect("outside directory");
    let outside_file = outside.path().join("secret.md");
    fs::write(&outside_file, b"outside bytes").expect("outside file");

    let project = TestProject::new();
    let link = project.root().join(TARGET);
    fs::create_dir_all(link.parent().unwrap()).expect("target parent");
    std::os::unix::fs::symlink(&outside_file, &link).expect("symlink");

    let clock = FakeClock::new();
    let mut observer = make_observer(project.root(), &[TARGET], &[], approved(), clock);

    let tick = observer.initial_scan();
    assert!(tick.sources.is_empty());
    assert!(tick.uncertainties.iter().any(|uncertainty| matches!(
        uncertainty,
        ObservationUncertainty::UnreadableSource {
            document,
            reason: SourceReadError::OutsideProject,
            ..
        } if document == &key(TARGET)
    )));
    assert!(observer.source_snapshot(&key(TARGET)).is_none());
    assert!(observer.health().has_uncertainty());
}

#[test]
fn css_and_resource_changes_invalidate_evidence_but_markdown_changes_do_not() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    project.write("docs/sdd/shared/shared.css", b"body{color:black}");
    project.write("docs/sdd/specs/diagram.png", b"png-one");
    let clock = FakeClock::new();
    let mut observer = make_observer(
        project.root(),
        &[TARGET],
        &[
            ("docs/sdd/shared/shared.css", DependencyKind::Css),
            ("docs/sdd/specs/diagram.png", DependencyKind::Resource),
        ],
        approved(),
        clock.clone(),
    );
    let document = key(TARGET);

    let initial = observer.initial_scan();
    assert_eq!(initial.sources.len(), 1);
    assert!(
        initial.dependencies.is_empty(),
        "the first scan seeds fingerprints"
    );

    project.write("docs/sdd/shared/shared.css", b"body{color:navy}");
    assert!(observer.notify(signal(
        "docs/sdd/shared/shared.css",
        ChangeSource::FilesystemWatcher
    )));
    let css = observer.poll();
    assert!(css.sources.is_empty());
    assert_eq!(css.dependencies.len(), 1);
    assert_eq!(
        css.dependencies[0].kind,
        herness_html_sync::FingerprintKind::Css
    );
    assert_eq!(css.dependencies[0].documents, vec![document.clone()]);
    assert!(matches!(
        css.dependencies[0].reason,
        ApplicabilityReason::DependencyChanged {
            fingerprint: herness_html_sync::FingerprintKind::Css
        }
    ));
    assert_ne!(css.dependencies[0].before, css.dependencies[0].after);
    assert_eq!(
        observer.stale_dependency(&document),
        Some(herness_html_sync::FingerprintKind::Css)
    );

    project.write("docs/sdd/specs/diagram.png", b"png-two");
    assert!(observer.notify(signal(
        "docs/sdd/specs/diagram.png",
        ChangeSource::FilesystemWatcher
    )));
    let resource = observer.poll();
    assert_eq!(resource.dependencies.len(), 1);
    assert_eq!(
        resource.dependencies[0].kind,
        herness_html_sync::FingerprintKind::Resources
    );
    assert!(
        observer.stale_dependency(&document).is_some(),
        "the evidence stays stale after another dependency change"
    );

    project.write(TARGET, b"two");
    assert!(observer.notify(signal(TARGET, ChangeSource::FilesystemWatcher)));
    settle(&clock);
    let markdown = observer.poll();
    assert_eq!(markdown.sources.len(), 1);
    assert_eq!(markdown.sources[0].change, SourceChange::Modified);
    assert!(
        markdown.dependencies.is_empty(),
        "a source edit is not a dependency change"
    );
}

#[test]
fn unapproved_settings_are_scanned_but_never_start_authoring() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    let clock = FakeClock::new();
    let settings = H3Settings::new(
        fixture_project(),
        1,
        true,
        vec![TARGET.to_owned()],
        false,
        true,
        Timestamp::from_unix_millis(NOW_MILLIS),
    )
    .expect("unapproved settings");
    assert!(settings.approval().is_none());
    let eligibility = ObservationEligibility::from_settings(
        Some(&settings),
        Timestamp::from_unix_millis(NOW_MILLIS),
    );
    assert!(!eligibility.is_approved());
    assert_eq!(
        eligibility.ineligible_reason(),
        Some(IneligibleReason::Unapproved)
    );
    let settings_targets =
        ObservationTargets::from_settings(&settings, vec![]).expect("Target set from settings");
    assert_eq!(
        settings_targets
            .documents()
            .iter()
            .map(|document| document.target_path().to_owned())
            .collect::<Vec<_>>(),
        vec![TARGET.to_owned()]
    );
    assert_eq!(settings_targets.settle_ms(), 750);
    assert_eq!(settings_targets.reconcile_interval_ms(), 5_000);

    let mut observer = make_observer(project.root(), &[TARGET], &[], eligibility, clock.clone());
    let initial = observer.initial_scan();
    assert_eq!(initial.sources.len(), 1);
    assert!(!initial.sources[0].eligibility.is_approved());
    assert!(initial.authoring_candidates().is_empty());

    project.write(TARGET, b"two");
    assert!(observer.notify(signal(TARGET, ChangeSource::FilesystemWatcher)));
    settle(&clock);
    let changed = observer.poll();
    assert_eq!(changed.sources.len(), 1);
    assert_eq!(changed.sources[0].change, SourceChange::Modified);
    assert!(changed.authoring_candidates().is_empty());

    assert_eq!(
        ObservationEligibility::from_settings(None, Timestamp::from_unix_millis(NOW_MILLIS))
            .ineligible_reason(),
        Some(IneligibleReason::NoSettings)
    );
    assert!(approved().is_approved());
}

#[test]
fn self_publication_is_absorbed_by_request_and_expected_bytes() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    project.write(
        "docs/sdd/specs/2026-11-09-h3-html-sync-design.html",
        b"old-html",
    );
    let clock = FakeClock::new();
    let mut observer = make_observer(project.root(), &[TARGET], &[], approved(), clock.clone());
    let document = key(TARGET);
    observer.initial_scan();

    let publication = PublicationId::from_parts(
        fixture_project(),
        Uuid::parse_str("50000000-0000-4000-8000-0000000000aa").expect("publication uuid"),
    );
    let request = PublicationRequestId::new("publish-request-1").expect("request id");
    let expected_html = ContentDigest::sha256(b"new-html");
    let expected_receipt = ContentDigest::sha256(b"new-receipt");
    let expected = ExpectedPublicationWrite::new(
        publication,
        request.clone(),
        document.clone(),
        expected_html.clone(),
    )
    .expect("expected write")
    .with_receipt(expected_receipt.clone());
    observer
        .expect_publication_write(expected)
        .expect("register expected write");

    project.write(
        "docs/sdd/specs/2026-11-09-h3-html-sync-design.html",
        b"new-html",
    );
    project.write(&html_evidence_path(&document), b"new-receipt");
    assert!(observer.notify(signal(
        "docs/sdd/specs/2026-11-09-h3-html-sync-design.html",
        ChangeSource::FilesystemWatcher
    )));
    assert!(observer.notify(signal(
        &html_evidence_path(&document),
        ChangeSource::FilesystemWatcher
    )));
    let tick = observer.poll();
    assert_eq!(tick.companions.len(), 2);
    let html = tick
        .companions
        .iter()
        .find(|observation| observation.file == CompanionFileKind::Html)
        .expect("html observation");
    assert_eq!(
        html.change,
        CompanionChange::SelfNotification {
            publication,
            request: request.clone(),
        }
    );
    assert_eq!(html.digest, Some(expected_html));
    let receipt = tick
        .companions
        .iter()
        .find(|observation| observation.file == CompanionFileKind::Receipt)
        .expect("receipt observation");
    assert_eq!(
        receipt.change,
        CompanionChange::SelfNotification {
            publication,
            request: request.clone(),
        }
    );
    assert_eq!(receipt.digest, Some(expected_receipt));
    assert!(tick.authoring_candidates().is_empty());

    // The same notification again is still absorbed, not duplicated.
    assert!(observer.notify(signal(
        "docs/sdd/specs/2026-11-09-h3-html-sync-design.html",
        ChangeSource::FilesystemWatcher
    )));
    let duplicate = observer.poll();
    assert!(duplicate.companions.is_empty());

    // Unmatched companion bytes are an external conflict signal.
    project.write(
        "docs/sdd/specs/2026-11-09-h3-html-sync-design.html",
        b"external-html",
    );
    assert!(observer.notify(signal(
        "docs/sdd/specs/2026-11-09-h3-html-sync-design.html",
        ChangeSource::FilesystemWatcher
    )));
    let external = observer.poll();
    assert_eq!(external.companions.len(), 1);
    assert_eq!(external.companions[0].file, CompanionFileKind::Html);
    assert_eq!(external.companions[0].change, CompanionChange::External);
    assert_eq!(
        external.companions[0].digest,
        Some(ContentDigest::sha256(b"external-html"))
    );

    assert!(observer.retire_publication_write(publication));
}

#[test]
fn watcher_failure_is_explicit_and_recovery_resyncs_without_authoring() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    let clock = FakeClock::new();
    let mut observer = make_observer(project.root(), &[TARGET], &[], approved(), clock.clone());
    let document = key(TARGET);
    observer.initial_scan();

    let failure = observer.report_watcher_failure();
    assert!(matches!(
        failure.health.watcher,
        WatcherStatus::Unavailable { .. }
    ));
    assert_eq!(failure.uncertainties.len(), 1);
    assert!(matches!(
        failure.uncertainties[0],
        ObservationUncertainty::WatcherUnavailable { .. }
    ));
    assert!(!failure.health.watcher_is_healthy());

    // The periodic path keeps working while the watcher is unavailable.
    project.write(TARGET, b"two");
    clock.advance(5_000);
    let detected = observer.poll();
    assert!(detected.sources.is_empty());
    assert!(detected.uncertainties.iter().any(|uncertainty| matches!(
        uncertainty,
        ObservationUncertainty::MissedNotification { .. }
    )));

    // Recovery compares the full Target set and resynchronises the revision
    // without producing an authoring candidate or a source observation.
    let recovery = observer.recover_watcher();
    assert!(recovery.health.watcher_is_healthy());
    assert_eq!(recovery.recoveries.len(), 1);
    assert_eq!(recovery.recoveries[0].document, document);
    assert!(recovery.recoveries[0].changed);
    assert_eq!(
        recovery.recoveries[0]
            .current
            .as_ref()
            .expect("resynchronised snapshot")
            .digest(),
        &ContentDigest::sha256(b"two")
    );
    assert!(recovery.sources.is_empty());
    assert!(recovery.authoring_candidates().is_empty());

    // The next periodic scan sees the resynchronised bytes and stays quiet.
    clock.advance(5_000);
    let after = observer.poll();
    assert!(after.sources.is_empty());
    assert!(after.recoveries.is_empty());
}

#[derive(Clone)]
struct FlakyReader {
    inner: FilesystemSourceReader,
    unstable_next: Arc<AtomicBool>,
}

impl SourceReadPort for FlakyReader {
    fn read(&self, path: &str) -> Result<FileRead, SourceReadError> {
        let read = self.inner.read(path)?;
        if self.unstable_next.swap(false, Ordering::SeqCst) {
            Ok(FileRead::new(read.bytes().to_vec(), false))
        } else {
            Ok(read)
        }
    }
}

#[test]
fn unstable_read_is_uncertain_and_retried_after_the_quiet_period() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    let clock = FakeClock::new();
    let unstable = Arc::new(AtomicBool::new(false));
    let reader = FlakyReader {
        inner: FilesystemSourceReader::new(project.root()).expect("reader"),
        unstable_next: Arc::clone(&unstable),
    };
    let targets =
        ObservationTargets::new(fixture_project(), vec![key(TARGET)], vec![]).expect("targets");
    let mut observer =
        ProjectObserver::new(targets, approved(), reader, clock.clone()).expect("observer");
    observer.initial_scan();

    project.write(TARGET, b"two");
    assert!(observer.notify(signal(TARGET, ChangeSource::FilesystemWatcher)));
    unstable.store(true, Ordering::SeqCst);
    settle(&clock);
    let unstable_tick = observer.poll();
    assert!(unstable_tick.sources.is_empty());
    assert!(
        unstable_tick
            .uncertainties
            .iter()
            .any(|uncertainty| matches!(uncertainty, ObservationUncertainty::UnstableRead { .. }))
    );
    assert!(observer.is_pending(&key(TARGET)));
    assert!(observer.health().has_uncertainty());

    settle(&clock);
    let stable_tick = observer.poll();
    assert_eq!(stable_tick.sources.len(), 1);
    assert_eq!(stable_tick.sources[0].change, SourceChange::Modified);
    assert_eq!(
        stable_tick.sources[0].snapshot.digest(),
        &ContentDigest::sha256(b"two")
    );
    assert!(!observer.health().has_uncertainty());
}

#[derive(Clone)]
struct CountingReader {
    inner: FilesystemSourceReader,
    reads: Arc<AtomicUsize>,
}

impl SourceReadPort for CountingReader {
    fn read(&self, path: &str) -> Result<FileRead, SourceReadError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(path)
    }
}

#[test]
fn periodic_scan_waits_for_five_seconds_and_uses_the_approved_interval() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    project.write(
        "docs/sdd/specs/2026-11-09-h3-html-sync-design.html",
        b"html",
    );
    project.write("docs/sdd/shared/shared.css", b"css");
    let clock = FakeClock::new();
    let reads = Arc::new(AtomicUsize::new(0));
    let reader = CountingReader {
        inner: FilesystemSourceReader::new(project.root()).expect("reader"),
        reads: Arc::clone(&reads),
    };
    let targets = ObservationTargets::new(
        fixture_project(),
        vec![key(TARGET)],
        vec![
            DependencyPath::new("docs/sdd/shared/shared.css", DependencyKind::Css)
                .expect("dependency"),
        ],
    )
    .expect("targets");
    let mut observer =
        ProjectObserver::new(targets, approved(), reader, clock.clone()).expect("observer");
    observer.initial_scan();
    let after_initial = reads.load(Ordering::SeqCst);
    assert!(after_initial >= 4, "source, css, html, and missing receipt");

    clock.advance(4_999);
    let early = observer.poll();
    assert!(early.sources.is_empty());
    assert_eq!(reads.load(Ordering::SeqCst), after_initial);

    clock.advance(1);
    observer.poll();
    assert!(reads.load(Ordering::SeqCst) > after_initial);
}

#[test]
fn dirty_documents_settle_in_notification_order() {
    let project = TestProject::new();
    project.write(TARGET, b"a-one");
    project.write(SECOND_TARGET, b"b-one");
    let clock = FakeClock::new();
    let mut observer = make_observer(
        project.root(),
        &[TARGET, SECOND_TARGET],
        &[],
        approved(),
        clock.clone(),
    );
    observer.initial_scan();

    project.write(TARGET, b"a-two");
    project.write(SECOND_TARGET, b"b-two");
    assert!(observer.notify(signal(SECOND_TARGET, ChangeSource::FilesystemWatcher)));
    assert!(observer.notify(signal(TARGET, ChangeSource::FilesystemWatcher)));
    assert_eq!(
        observer
            .pending_documents()
            .iter()
            .map(|document| document.target_path().to_owned())
            .collect::<Vec<_>>(),
        vec![SECOND_TARGET.to_owned(), TARGET.to_owned()]
    );

    settle(&clock);
    let tick = observer.poll();
    assert_eq!(
        tick.sources
            .iter()
            .map(|source| source.document.target_path().to_owned())
            .collect::<Vec<_>>(),
        vec![SECOND_TARGET.to_owned(), TARGET.to_owned()]
    );
    assert_eq!(tick.authoring_candidates().len(), 2);
}

#[test]
fn source_over_the_approved_limit_is_held_without_truncation() {
    let project = TestProject::new();
    project.write(TARGET, b"12345");
    let clock = FakeClock::new();
    let limits = herness_html_sync::H3ApprovalLimits::new(
        4,
        8 * 1024 * 1024,
        5_000,
        30_000,
        750,
        5_000,
        1,
        1,
        7_200,
        30,
        3,
    )
    .expect("lowered source limit");
    let targets =
        ObservationTargets::with_limits(fixture_project(), vec![key(TARGET)], vec![], &limits)
            .expect("targets");
    assert_eq!(targets.max_source_bytes(), 4);
    let mut observer = ProjectObserver::new(
        targets,
        approved(),
        FilesystemSourceReader::new(project.root()).expect("reader"),
        clock,
    )
    .expect("observer");

    let tick = observer.initial_scan();
    assert!(tick.sources.is_empty());
    assert!(tick.uncertainties.iter().any(|uncertainty| matches!(
        uncertainty,
        ObservationUncertainty::SourceTooLarge {
            bytes: 5,
            max: 4,
            ..
        }
    )));
    assert!(observer.source_snapshot(&key(TARGET)).is_none());
    assert_eq!(
        fs::read(project.root().join(TARGET)).expect("source stays intact"),
        b"12345"
    );
}

#[test]
fn restored_source_and_dependency_baselines_keep_revisions_monotonic() {
    let project = TestProject::new();
    project.write(TARGET, b"one");
    project.write("docs/sdd/shared/shared.css", b"css-one");
    let clock = FakeClock::new();
    let mut observer = make_observer(
        project.root(),
        &[TARGET],
        &[("docs/sdd/shared/shared.css", DependencyKind::Css)],
        approved(),
        clock.clone(),
    );
    let document = key(TARGET);
    observer
        .seed_source(
            &document,
            SourceSnapshot::new(
                SourceRevision::new(9).expect("revision"),
                ContentDigest::sha256(b"one"),
            ),
        )
        .expect("seed source");
    observer.seed_dependency(DependencyKind::Css, ContentDigest::sha256(b"css-old"));

    let initial = observer.initial_scan();
    assert_eq!(initial.sources.len(), 1);
    assert_eq!(initial.sources[0].change, SourceChange::Unchanged);
    assert_eq!(initial.sources[0].snapshot.revision().get(), 9);
    assert!(initial.authoring_candidates().is_empty());
    // The seeded CSS fingerprint differs from disk, so evidence is stale.
    assert_eq!(initial.dependencies.len(), 1);
    assert_eq!(
        initial.dependencies[0].kind,
        herness_html_sync::FingerprintKind::Css
    );

    project.write(TARGET, b"two");
    assert!(observer.notify(signal(TARGET, ChangeSource::NativeSaved)));
    settle(&clock);
    let changed = observer.poll();
    assert_eq!(changed.sources[0].snapshot.revision().get(), 10);
    assert!(changed.sources[0].snapshot.revision().get() > 9);
}

#[test]
fn dependency_fingerprint_recipe_is_order_independent_and_kind_bound() {
    let css_one = ContentDigest::sha256(b"css-one");
    let css_two = ContentDigest::sha256(b"css-two");
    let left = herness_html_sync::dependency_fingerprint(
        DependencyKind::Css,
        [
            ("docs/sdd/shared/a.css", css_one.clone()),
            ("docs/sdd/shared/b.css", css_two.clone()),
        ],
    );
    let right = herness_html_sync::dependency_fingerprint(
        DependencyKind::Css,
        [
            ("docs/sdd/shared/b.css", css_two.clone()),
            ("docs/sdd/shared/a.css", css_one.clone()),
        ],
    );
    assert_eq!(left, right);
    let resource = herness_html_sync::dependency_fingerprint(
        DependencyKind::Resource,
        [
            ("docs/sdd/shared/a.css", css_one),
            ("docs/sdd/shared/b.css", css_two),
        ],
    );
    assert_ne!(left, resource);
}

#[test]
fn observation_targets_reject_duplicates_cross_project_and_dependency_collisions() {
    let duplicate =
        ObservationTargets::new(fixture_project(), vec![key(TARGET), key(TARGET)], vec![]);
    assert!(duplicate.is_err());

    let cross_project = ObservationTargets::new(
        fixture_project(),
        vec![
            DocumentKey::new(herness_html_sync_tests::fixtures::other_project(), TARGET)
                .expect("other-project key"),
        ],
        vec![],
    );
    assert!(cross_project.is_err());

    let companion_collision = ObservationTargets::new(
        fixture_project(),
        vec![key(TARGET)],
        vec![
            DependencyPath::new(
                "docs/sdd/specs/2026-11-09-h3-html-sync-design.html",
                DependencyKind::Resource,
            )
            .expect("companion dependency"),
        ],
    );
    assert!(companion_collision.is_err());

    let invalid_signal = ChangeSignal::new("../outside.md", ChangeSource::FilesystemWatcher);
    assert!(invalid_signal.is_err());
}

#[test]
fn desktop_watcher_starts_recursively_and_reports_watching() {
    let project = TestProject::new();
    let (sender, _receiver) = std::sync::mpsc::channel();
    let mut watcher = ProjectFilesystemWatcher::start(project.root(), sender)
        .expect("the desktop watcher starts");
    assert!(watcher.is_watching());
    watcher.stop();
    assert!(!watcher.is_watching());
}

#[test]
fn desktop_adapter_converts_only_project_relative_paths() {
    let project = TestProject::new();
    let absolute = AbsolutePath::new(project.root().join(TARGET).to_str().expect("utf8 path"))
        .expect("absolute path");
    let signal =
        herness_desktop::html_sync::observer::native_saved_change(project.root(), &absolute)
            .expect("native saved signal");
    assert_eq!(signal.path(), TARGET);
    assert_eq!(signal.source(), ChangeSource::NativeSaved);

    let outside = TempDir::new().expect("outside");
    let outside_path = outside.path().join("outside.md");
    assert!(
        herness_desktop::html_sync::observer::signal_from_absolute(
            project.root(),
            &outside_path,
            ChangeSource::FilesystemWatcher,
        )
        .is_none()
    );

    let shell_absolute = AbsolutePath::new(
        project
            .root()
            .join("docs/sdd/shared/shared.css")
            .to_str()
            .expect("utf8 path"),
    )
    .expect("absolute path");
    let shell = herness_desktop::html_sync::observer::shell_change(project.root(), &shell_absolute)
        .expect("shell signal");
    assert_eq!(shell.path(), "docs/sdd/shared/shared.css");
    assert_eq!(shell.source(), ChangeSource::Shell);
    let external = herness_desktop::html_sync::observer::external_editor_change(
        project.root(),
        &shell_absolute,
    )
    .expect("external signal");
    assert_eq!(external.source(), ChangeSource::ExternalEditor);
}
