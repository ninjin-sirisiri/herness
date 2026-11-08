//! Black-box tests for read-only SDD pack access, skill fingerprints, host
//! overlays, run context capability checks, and toolchain detection.
//!
//! The real SDD pack at `/Users/h-uma/Documents/sdd` is only read. Synthetic
//! packs are used for change detection, missing skills, overlays, and
//! toolchain edge cases. No network, credential, engine, or Tauri code runs.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use herness_core::*;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn skill_id(value: &str) -> SkillId {
    SkillId::new(value).expect("valid skill id")
}

fn fixture_pack() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/skills/pack")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to a string cannot fail");
    }
    hex
}

fn copy_dir_all(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("make executable");
}

fn write_plain_file(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("make non-executable");
}

const REAL_PACK_ROOT: &str = "/Users/h-uma/Documents/sdd";

#[test]
fn synthetic_pack_records_source_digest_and_resolves_relative_references() {
    let pack = SkillPack::open(fixture_pack()).expect("open fixture pack");
    let demo = skill_id("demo");
    let document = pack.load(&demo).expect("load demo skill");
    let source = document.source();

    let canonical_root = fs::canonicalize(fixture_pack()).expect("canonical fixture root");
    assert_eq!(source.pack_root.as_path(), canonical_root);
    assert_eq!(source.skill_id, demo);
    assert_eq!(
        source.skill_path.as_path(),
        canonical_root.join("skills/demo/SKILL.md")
    );
    assert_eq!(
        source.document_digest.as_str(),
        sha256_hex(document.text().as_bytes())
    );

    let paths = document
        .fingerprint()
        .references
        .iter()
        .map(|reference| reference.relative_path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec![
            "skills/demo/assets/snippet.css",
            "skills/demo/notes/reference.md"
        ],
        "relative references resolve inside the pack, not against cwd or the project"
    );
    for reference in &document.fingerprint().references {
        assert!(reference.path.as_path().starts_with(&canonical_root));
        assert!(reference.path.as_path().is_file());
        assert_eq!(
            reference.digest.as_str(),
            sha256_hex(&fs::read(reference.path.as_path()).expect("read reference"))
        );
    }
    assert_eq!(document.fingerprint().combined.as_str().len(), 64);

    let revalidation = document.revalidate().expect("revalidate unchanged skill");
    assert!(!revalidation.changed());
    assert_eq!(&revalidation.current, document.fingerprint());
}

#[test]
fn referenced_file_change_invalidates_fingerprint() {
    let temp = TempDir::new().expect("temp dir");
    let pack_root = temp.path().join("pack");
    copy_dir_all(&fixture_pack(), &pack_root).expect("copy synthetic pack");
    let pack = SkillPack::open(&pack_root).expect("open copied pack");
    let demo = skill_id("demo");
    let document = pack.load(&demo).expect("load demo skill");
    let original = document.fingerprint().combined.clone();

    let reference = pack_root.join("skills/demo/notes/reference.md");
    fs::write(
        &reference,
        "# Reference\n\nChanged while a run was active.\n",
    )
    .expect("modify reference");

    let revalidation = document.revalidate().expect("revalidate changed reference");
    assert!(revalidation.changed());
    assert!(matches!(
        revalidation.changes.as_slice(),
        [SkillChange::ReferenceChanged { path, .. }] if path == "skills/demo/notes/reference.md"
    ));
    assert_ne!(revalidation.current.combined, original);

    let error = document
        .ensure_current()
        .expect_err("old fingerprint must not match");
    assert!(matches!(
        error,
        CoreError::SkillFailed {
            failure: SkillFailure::ChangedDuringRun { .. },
            ..
        }
    ));

    let reloaded = document.reload().expect("reload changed skill");
    assert_ne!(reloaded.fingerprint(), document.fingerprint());
    assert!(!reloaded.revalidate().expect("revalidate reload").changed());
}

#[test]
fn skill_text_change_is_reported_and_requires_reload() {
    let temp = TempDir::new().expect("temp dir");
    let pack_root = temp.path().join("pack");
    copy_dir_all(&fixture_pack(), &pack_root).expect("copy synthetic pack");
    let pack = SkillPack::open(&pack_root).expect("open copied pack");
    let demo = skill_id("demo");
    let document = pack.load(&demo).expect("load demo skill");
    let old_fingerprint = document.fingerprint().combined.clone();
    let skill_path = pack_root.join("skills/demo/SKILL.md");

    let mut changed = fs::read_to_string(&skill_path).expect("read skill");
    changed.push_str("\nHost-neutral changed text.\n");
    fs::write(&skill_path, changed).expect("modify skill text");

    let revalidation = document
        .revalidate()
        .expect("revalidate changed skill text");
    assert!(revalidation.changed());
    assert!(
        revalidation
            .changes
            .iter()
            .any(|change| matches!(change, SkillChange::DocumentChanged { .. }))
    );
    assert_ne!(revalidation.current.combined, old_fingerprint);

    let reloaded = document.reload().expect("reload changed skill");
    assert!(reloaded.text().contains("Host-neutral changed text."));
    assert_ne!(reloaded.fingerprint().combined, old_fingerprint);
    assert!(!reloaded.revalidate().expect("revalidate reload").changed());
}

#[test]
fn missing_skill_and_invalid_ids_are_structured() {
    let pack = SkillPack::open(fixture_pack()).expect("open fixture pack");
    let error = pack
        .load(&skill_id("does-not-exist"))
        .expect_err("missing skill");
    assert!(matches!(
        error,
        CoreError::SkillFailed {
            failure: SkillFailure::NotFound { .. },
            ..
        }
    ));

    assert!(SkillId::new("../escape").is_err());
    assert!(SkillId::new("a/b").is_err());
    assert!(SkillId::new("").is_err());

    let explicit_error = pack
        .load_with_references(&skill_id("demo"), &["missing-reference.md"])
        .expect_err("missing explicit reference");
    assert!(matches!(
        explicit_error,
        CoreError::SkillFailed {
            failure: SkillFailure::NotFound { .. },
            ..
        }
    ));
}

#[test]
fn host_overlay_is_attributed_to_host_and_never_rewrites_pack() {
    let pack = SkillPack::open(fixture_pack()).expect("open fixture pack");
    let demo = skill_id("demo");
    let document = pack.load(&demo).expect("load demo skill");
    let pack_bytes = fs::read(document.source().skill_path.as_path()).expect("read pack bytes");

    let overlay = HostOverlay::new(
        demo.clone(),
        "\n## Herness host instructions\n\nUse the host run context.\n",
        Some("This text is replaced by the host overlay probe.".to_owned()),
    )
    .expect("overlay");
    assert_eq!(overlay.provenance(), OverlayProvenance::Host);
    assert_eq!(overlay.skill_id(), &demo);

    let composed = overlay.apply(document.text()).expect("apply overlay");
    assert!(!composed.contains("This text is replaced by the host overlay probe."));
    assert!(composed.contains("Herness host instructions"));
    assert_eq!(
        fs::read(document.source().skill_path.as_path()).expect("re-read pack bytes"),
        pack_bytes,
        "applying an overlay must not rewrite the pack"
    );

    let encoded = serde_json::to_value(&overlay).expect("serialize overlay");
    assert_eq!(encoded["provenance"], "host");

    let missing = HostOverlay::new(
        demo.clone(),
        "host addition",
        Some("text that is not in the pack".to_owned()),
    )
    .expect("overlay with missing removal target");
    assert!(matches!(
        missing.apply(document.text()),
        Err(CoreError::SkillFailed {
            failure: SkillFailure::OverlayRemovalNotFound { .. },
            ..
        })
    ));
}

#[test]
fn run_context_distinguishes_reading_from_unavailable_worker_execution() {
    let pack = SkillPack::open(fixture_pack()).expect("open fixture pack");
    let demo = skill_id("demo");
    let worker = skill_id("worker");
    let demo_document = pack.load(&demo).expect("load demo");
    let worker_document = pack.load(&worker).expect("load worker");
    let overlay = HostOverlay::new(demo.clone(), "\nHost-only text.\n", None).expect("overlay");
    let root = pack.root_absolute().expect("absolute root");
    let flows = vec![
        (demo.clone(), SkillExecutionFlow::HtmlWorker),
        (worker.clone(), SkillExecutionFlow::SddTaskController),
    ];
    let context = SkillRunContext::build(
        &root,
        vec![demo_document.clone(), worker_document.clone()],
        &[overlay],
        &flows,
        HostCapabilities::h1(),
    )
    .expect("build run context");

    assert!(
        context
            .capabilities()
            .status(HostCapability::SkillRead)
            .is_available()
    );
    assert!(
        !context
            .capabilities()
            .status(HostCapability::HtmlWorker)
            .is_available()
    );
    assert!(
        !context
            .capabilities()
            .status(HostCapability::SddTaskController)
            .is_available()
    );

    let demo_entry = context.entry(&demo).expect("demo entry");
    assert_eq!(demo_entry.text(), demo_document.text());
    assert_eq!(demo_entry.fingerprint(), demo_document.fingerprint());
    assert!(
        demo_entry
            .overlaid_text()
            .expect("overlaid text")
            .contains("Host-only text.")
    );
    assert!(!demo_entry.execution().worker_available());
    assert_eq!(
        demo_entry.execution().status(),
        CapabilityStatus::Unavailable {
            reason: CapabilityUnavailableReason::NotImplementedInH1
        }
    );

    let workers = context.entry(&worker).expect("worker entry");
    assert!(!workers.execution().worker_available());
    assert!(workers.text().contains("Worker skill"));

    let error = context
        .require_execution(&demo)
        .expect_err("HTML worker must not be advertised as available");
    assert!(matches!(
        error,
        CoreError::SkillFailed {
            failure: SkillFailure::CapabilityUnavailable {
                flow: SkillExecutionFlow::HtmlWorker,
                capability: HostCapability::HtmlWorker,
                reason: CapabilityUnavailableReason::NotImplementedInH1,
            },
            ..
        }
    ));

    let read_only =
        SkillRunContext::build(&root, vec![demo_document], &[], &[], HostCapabilities::h1())
            .expect("read-only context");
    assert_eq!(
        read_only
            .require_execution(&demo)
            .expect("read-only loading is allowed")
            .flow(),
        SkillExecutionFlow::ReadOnly
    );
    assert!(
        !read_only
            .require_execution(&demo)
            .expect("read-only loading is allowed")
            .worker_available()
    );
}

#[test]
fn run_context_detects_change_mid_run() {
    let temp = TempDir::new().expect("temp dir");
    let pack_root = temp.path().join("pack");
    copy_dir_all(&fixture_pack(), &pack_root).expect("copy synthetic pack");
    let pack = SkillPack::open(&pack_root).expect("open copied pack");
    let demo = skill_id("demo");
    let document = pack.load(&demo).expect("load demo");
    let root = pack.root_absolute().expect("absolute root");
    let context = SkillRunContext::build(&root, vec![document], &[], &[], HostCapabilities::h1())
        .expect("build context");

    fs::write(
        pack_root.join("skills/demo/SKILL.md"),
        "# Demo skill\n\nChanged during the run.\n",
    )
    .expect("modify skill");

    let revalidation = context.revalidate().expect("revalidate context");
    assert!(revalidation.changed);
    assert!(revalidation.skills[0].changed());
    assert!(context.ensure_current().is_err());
}

#[test]
fn toolchain_finder_minimal_path_uses_explicit_nonstandard_paths() {
    let temp = TempDir::new().expect("temp dir");
    let bin = temp.path().join("custom-bin");
    fs::create_dir_all(&bin).expect("create bin");
    let git = bin.join("git");
    let python = bin.join("python3");
    let validator = bin.join("html-docs");
    write_executable(
        &git,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'git version 2.50.1'; exit 0; fi\nexit 1\n",
    );
    write_executable(
        &python,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'Python 3.12.4'; exit 0; fi\necho '{\"decision\":\"deny\",\"message\":\"usage: html-docs\"}'\nexit 0\n",
    );
    write_executable(&validator, "#!/bin/sh\nexit 0\n");

    let minimal_path = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
    let config = ToolchainConfig::empty()
        .with_path_dirs(minimal_path)
        .with_git_path(&git)
        .expect("git path")
        .with_python_path(&python)
        .expect("python path")
        .with_html_docs_path(&validator)
        .expect("validator path");
    let report = ToolchainDetector::new(config).detect();

    assert!(report.git.is_available());
    assert_eq!(
        report
            .git
            .executable_path
            .as_ref()
            .expect("git path")
            .as_path(),
        git
    );
    assert_eq!(report.git.version.as_deref(), Some("2.50.1"));
    assert!(report.python.is_available());
    assert_eq!(
        report
            .python
            .executable_path
            .as_ref()
            .expect("python path")
            .as_path(),
        python
    );
    assert_eq!(report.python.version.as_deref(), Some("3.12.4"));
    assert!(report.html_docs.is_available());
    assert_eq!(
        report
            .html_docs
            .script_path
            .as_ref()
            .expect("validator path")
            .as_path(),
        validator
    );
    assert_eq!(
        report
            .html_docs
            .interpreter_path
            .as_ref()
            .expect("interpreter path")
            .as_path(),
        python
    );
    assert_eq!(report.html_docs.version, Some(PythonVersion::new(3, 12, 4)));
    assert!(report.html_docs.probe.as_ref().expect("probe").responded);
    assert!(report.is_ready());
    assert!(report.deficiencies().is_empty());

    let searched = ToolchainDetector::new(
        ToolchainConfig::empty()
            .with_search_dir(&bin)
            .expect("search dir"),
    )
    .detect();
    assert!(searched.git.is_available());
    assert_eq!(
        searched
            .git
            .executable_path
            .as_ref()
            .expect("searched git")
            .as_path(),
        git
    );
    assert_eq!(searched.git.version.as_deref(), Some("2.50.1"));

    let from_path =
        ToolchainDetector::new(ToolchainConfig::empty().with_path_dirs(vec![bin.clone()])).detect();
    assert!(from_path.python.is_available());
    assert_eq!(
        from_path
            .python
            .executable_path
            .as_ref()
            .expect("path python")
            .as_path(),
        python
    );
    assert_eq!(from_path.python.version.as_deref(), Some("3.12.4"));

    let without_explicit = ToolchainConfig::empty().with_path_dirs(minimal_path);
    let missing = ToolchainDetector::new(without_explicit).detect();
    assert_eq!(missing.html_docs.status, ToolAvailability::Missing);
    assert!(
        report
            .deficiency(ToolRequirement::HtmlDocsValidator)
            .is_none()
    );
}

#[test]
fn old_python_reports_insufficient_version_with_found_version() {
    let temp = TempDir::new().expect("temp dir");
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).expect("create bin");
    let python = bin.join("python3");
    let validator = bin.join("html-docs");
    write_executable(&python, "#!/bin/sh\necho 'Python 3.10.12'\n");
    write_executable(&validator, "#!/bin/sh\nexit 0\n");

    let config = ToolchainConfig::empty()
        .with_python_path(&python)
        .expect("python path")
        .with_html_docs_path(&validator)
        .expect("validator path");
    let report = ToolchainDetector::new(config).detect();

    assert_eq!(
        report.python.status,
        ToolAvailability::InsufficientVersion {
            minimum: PythonVersion::new(3, 11, 0),
            found: PythonVersion::new(3, 10, 12),
        }
    );
    assert_eq!(report.python.version.as_deref(), Some("3.10.12"));
    assert_eq!(
        report.html_docs.status,
        ToolAvailability::InsufficientVersion {
            minimum: PythonVersion::new(3, 11, 0),
            found: PythonVersion::new(3, 10, 12),
        }
    );
    assert!(!report.is_ready());
    assert!(report.deficiencies().iter().any(|deficiency| {
        deficiency.tool == ToolRequirement::Python
            && matches!(
                deficiency.status,
                ToolAvailability::InsufficientVersion { found, .. }
                    if found == PythonVersion::new(3, 10, 12)
            )
    }));
    assert!(
        report
            .deficiencies()
            .iter()
            .any(|deficiency| { deficiency.tool == ToolRequirement::HtmlDocsValidator })
    );
}

#[test]
fn missing_and_non_executable_tools_are_deficiencies_without_installing() {
    let temp = TempDir::new().expect("temp dir");
    let empty_dir = temp.path().join("empty-search");
    fs::create_dir_all(&empty_dir).expect("create search dir");

    let missing_config = ToolchainConfig::empty()
        .with_search_dir(&empty_dir)
        .expect("search dir");
    let missing = ToolchainDetector::new(missing_config).detect();
    assert_eq!(missing.git.status, ToolAvailability::Missing);
    assert_eq!(missing.python.status, ToolAvailability::Missing);
    assert_eq!(missing.html_docs.status, ToolAvailability::Missing);
    assert!(!missing.is_ready());
    assert_eq!(missing.deficiencies().len(), 3);
    assert!(missing.require(ToolRequirement::Git).is_err());
    assert_eq!(
        fs::read_dir(&empty_dir).expect("read search dir").count(),
        0,
        "detection must not install anything"
    );

    let non_executable_python = temp.path().join("python-not-executable");
    write_plain_file(&non_executable_python, "Python 3.12.0\n");
    let config = ToolchainConfig::empty()
        .with_python_path(&non_executable_python)
        .expect("python path");
    let report = ToolchainDetector::new(config).detect();
    assert!(matches!(
        report.python.status,
        ToolAvailability::NotExecutable { .. }
    ));
}

#[test]
fn explicit_non_executable_validator_is_not_replaced_by_searched_candidate() {
    let temp = TempDir::new().expect("temp dir");
    let search = temp.path().join("search");
    fs::create_dir_all(&search).expect("create search dir");
    let searched = search.join("html-docs");
    write_executable(&searched, "#!/bin/sh\nexit 0\n");

    let explicit = temp.path().join("configured-html-docs");
    write_plain_file(&explicit, "not executable\n");

    let config = ToolchainConfig::empty()
        .with_search_dir(&search)
        .expect("search dir")
        .with_html_docs_path(&explicit)
        .expect("validator path");
    let report = ToolchainDetector::new(config).detect();

    assert!(matches!(
        report.html_docs.status,
        ToolAvailability::NotExecutable { ref path } if path == explicit.to_str().expect("utf8 path")
    ));
    assert_eq!(
        report
            .html_docs
            .script_path
            .as_ref()
            .map(|path| path.as_path()),
        None,
        "an explicit configured validator is authoritative"
    );
    assert!(report.html_docs.probe.is_none());
}

#[test]
fn real_sdd_pack_is_read_only_and_reports_fingerprints_and_toolchain() {
    let real_root = PathBuf::from(REAL_PACK_ROOT);
    if !real_root.is_dir() {
        eprintln!("skip real SDD pack test: {REAL_PACK_ROOT} is absent");
        return;
    }

    let pack = SkillPack::open(&real_root).expect("open real SDD pack");
    let execute = skill_id("sdd-execute");
    let sdd = skill_id("sdd");
    let execute_document = pack
        .load_with_references(&execute, &["implementer-prompt.md"])
        .expect("load real sdd-execute skill");
    let sdd_document = pack.load(&sdd).expect("load real sdd skill");

    for (document, name) in [(&execute_document, "sdd-execute"), (&sdd_document, "sdd")] {
        assert_eq!(document.source().document_digest.as_str().len(), 64);
        assert_eq!(document.fingerprint().combined.as_str().len(), 64);
        assert!(!document.text().is_empty());
        assert!(
            !document
                .revalidate()
                .expect("revalidate real skill")
                .changed()
        );
        println!(
            "real skill {name}: path={} document={} references={:?} combined={}",
            document.source().skill_path,
            document.source().document_digest,
            document
                .fingerprint()
                .references
                .iter()
                .map(|reference| reference.relative_path.as_str())
                .collect::<Vec<_>>(),
            document.fingerprint().combined
        );
    }
    assert!(
        execute_document
            .fingerprint()
            .reference("skills/sdd-execute/implementer-prompt.md")
            .is_some()
    );

    let root = pack.root_absolute().expect("absolute pack root");
    let context = SkillRunContext::build(
        &root,
        vec![execute_document.clone(), sdd_document.clone()],
        &[],
        &[(execute.clone(), SkillExecutionFlow::SddTaskController)],
        HostCapabilities::h1(),
    )
    .expect("build real run context");
    assert!(
        context
            .capabilities()
            .status(HostCapability::SkillRead)
            .is_available()
    );
    assert!(
        !context
            .capabilities()
            .status(HostCapability::SddTaskController)
            .is_available()
    );
    assert!(context.require_execution(&execute).is_err());
    assert_eq!(
        context
            .require_execution(&sdd)
            .expect("reading sdd routing skill is allowed")
            .flow(),
        SkillExecutionFlow::ReadOnly
    );

    let validator = real_root.join("scripts/html-docs");
    let config = ToolchainConfig::from_environment()
        .with_html_docs_path(&validator)
        .expect("validator path");
    let report = ToolchainDetector::new(config).detect();
    println!(
        "real toolchain: {}",
        serde_json::to_string_pretty(&report).expect("serialize report")
    );
    assert!(report.git.is_available(), "git must be detectable");
    assert!(
        report.python.is_available(),
        "the configured environment must provide Python 3.11 or newer"
    );
    assert!(
        report.html_docs.is_available(),
        "the SDD validator must be executable with the detected Python"
    );
    assert!(report.is_ready());
}
