//! Black-box tests for the real pack inspector bridge and the side-effect-free
//! import preview.
//!
//! # The pack under test
//!
//! The happy-path cases run the **real** `sdd-plan-inspect` implementation from
//! an SDD pack checkout. The pack root is resolved at test time from
//! `SDD_PACK_ROOT`, defaulting to
//! `/Users/h-uma/Documents/sdd/.worktrees/h4-exec`, and every run prints the
//! resolved root so its evidence names the pack it used. A missing pack fails
//! with the resolved path instead of skipping: a preview that never ran is not
//! evidence of one that works.
//!
//! # Mechanics stubs
//!
//! Two mechanics are exercised against a stub pack root, which the Task allows
//! for exactly them: a sleeping script for the 30 second inspector timeout
//! (shortened so the suite stays fast) and canned scripts for invalid, oversize,
//! version-mismatched, and non-zero-exit responses. The stub never parses a plan
//! and never stands in for the happy path.
//!
//! # Acceptance map
//!
//! * Toolchain/fingerprint verified, argv/stdin form, 30 s timeout, 2 MiB limit:
//!   [`real_pack_preview_keeps_exact_bytes`], [`argv_stdin_and_cwd_are_exact`],
//!   [`slow_inspector_times_out`], [`oversized_plan_is_refused`],
//!   [`stale_or_changed_pack_is_unavailable`].
//! * Exact bytes and ranges with Japanese text and CRLF:
//!   [`crlf_japanese_plan_is_byte_exact`].
//! * Spec/section existence, root confinement, snapshot capture, external alias
//!   refusal: the `spec_snapshot_*` and `alias_*` cases.
//! * Invalid responses and stale packs are distinct typed errors:
//!   [`invalid_inspector_responses_are_unavailable`],
//!   [`failure_codes_are_mapped_distinctly`], [`stale_or_changed_pack_is_unavailable`].
//! * Zero child dispatch, zero model request, zero Git change:
//!   [`import_starts_only_the_inspector_and_changes_no_repository`].
//! * Real parser evidence: valid, old format, malformed, and 2 MiB+1.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use herness_core::AbsolutePath;
use herness_core::contracts::ProjectId;
use herness_core::tools::process::{
    ArgvLauncher, ArgvRequest, ProcessSupervisor, SystemArgvLauncher, SystemChild,
};
use herness_desktop::sdd_execute::{
    INSPECTOR_TIMEOUT, PackInspector, PlanFileSource, PlanImporter, RootedPlanSource,
    read_and_verify_specs, read_spec_snapshot,
};
use herness_sdd_execute::import::{
    CONTRACT_FEATURE, CONTRACT_INPUT_FEATURE, EXIT_FEATURE, InspectorFailureCode,
    OVERSIZE_PLAN_FEATURE, RESPONSE_FEATURE, TIMEOUT_FEATURE,
};
use herness_sdd_execute::{
    FailureCode, INSPECTOR_TIMEOUT_SECONDS, InspectRequest, InspectorCapabilities,
    InspectorProtocol, MAX_PLAN_BYTES, PackFingerprint, PlanDiagnosticCode, PlanDigest, PlanPath,
    PlanPreview, PlanSourcePort, PlanSourceRead, SddExecutionError, SourceLayout, SourceSnapshot,
    SpecSnapshotSet, inspect_request_envelope, verify_spec_snapshots,
};
use tempfile::TempDir;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const PLAN_PATH: &str = "docs/sdd/plans/2026-11-13-import-fixture.md";
const SPEC_PATH: &str = "docs/sdd/specs/2026-11-13-import-fixture.md";
const SECTION: &str = "Fixture section";

/// The documented default pack checkout, overridable with `SDD_PACK_ROOT`.
const DEFAULT_PACK_ROOT: &str = "/Users/h-uma/Documents/sdd/.worktrees/h4-exec";

fn project() -> ProjectId {
    ProjectId::from_uuid(Uuid::parse_str("50000000-0000-4000-8000-000000000012").unwrap())
}

/// Resolves the real pack root at test time and reports it.
fn pack_root() -> PathBuf {
    let root = std::env::var_os("SDD_PACK_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PACK_ROOT));
    let script = root.join("scripts/plan-inspect");
    assert!(
        script.is_file(),
        "no SDD pack inspector at {}. Set SDD_PACK_ROOT to a pack checkout that has \
         scripts/plan-inspect (documented default {DEFAULT_PACK_ROOT}).",
        script.display()
    );
    eprintln!("import tests: SDD pack root = {}", root.display());
    root
}

fn python() -> AbsolutePath {
    for candidate in [
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/usr/bin/python3",
    ] {
        if Path::new(candidate).is_file() {
            return AbsolutePath::new(candidate).expect("an absolute interpreter path");
        }
    }
    let output = Command::new("/usr/bin/which")
        .arg("python3")
        .output()
        .expect("which python3");
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    AbsolutePath::new(text).expect("python3 is an absolute path")
}

fn git() -> AbsolutePath {
    let output = Command::new("/usr/bin/which")
        .arg("git")
        .output()
        .expect("which git");
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    AbsolutePath::new(text).expect("git is an absolute path")
}

/// One valid `sdd-execution-v1` plan. `crlf` converts every line ending.
fn plan_markdown(crlf: bool) -> Vec<u8> {
    let spec_ref =
        format!(r#"{{"source":"project","path":"{SPEC_PATH}","sections":["{SECTION}"]}}"#);
    let text = format!(
        r#"# Import preview fixture

**Goal:** Prove the preview keeps the exact plan bytes.

**Architecture:** One Task writes one module in one checkout.

**Tech Stack:** Rust

**Spec:** {SPEC_PATH}

## Global Constraints

- 日本語の本文とglobal constraintsを原文のまま保持する。
- Reject unknown fields and unknown versions.

```sdd-execution-v1
{{
  "schema": "sdd-execution-plan",
  "version": 1,
  "specRefs": [{spec_ref}],
  "tasks": [
    {{
      "number": 1,
      "dependsOn": [],
      "specRefs": [{spec_ref}],
      "readPaths": ["src/a.rs"],
      "writePaths": ["src/a.rs"],
      "allowShell": true,
      "deliverables": [{{"path": "src/a.rs", "kind": "file"}}],
      "conditions": [
        {{
          "id": "written",
          "title": "The module is written",
          "rubric": "src/a.rs contains a main function returning zero.",
          "mode": "checks"
        }}
      ],
      "checks": [
        {{
          "id": "build",
          "conditionId": "written",
          "description": "Build the crate.",
          "command": "cargo check",
          "cwd": ".",
          "timeoutSeconds": 60,
          "inputPaths": ["src/a.rs"]
        }}
      ],
      "htmlTargets": [],
      "commitPolicy": "required"
    }}
  ],
  "finalChecks": ["build"]
}}
```

## File structure

- `src/a.rs` — the module.

## Task 1: Write the module

Write `src/a.rs` and report the exact command and exit code.
"#
    );
    if crlf {
        text.replace("\r\n", "\n")
            .replace('\n', "\r\n")
            .into_bytes()
    } else {
        text.into_bytes()
    }
}

fn spec_markdown() -> &'static str {
    "# Import fixture design\n\n## Terms\n\nThe plan is the source of truth.\n\n## Fixture section\n\n日本語の適用section。The host binds this snapshot.\n\n### Detail\n\nA nested paragraph that belongs to the fixture section.\n"
}

/// A temp project with one plan, one spec, and optionally a real Git repository.
fn project_fixture(init_git: bool) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("a temp project");
    let root = dir.path().to_path_buf();
    write(&root, PLAN_PATH, &plan_markdown(false));
    write(&root, SPEC_PATH, spec_markdown().as_bytes());
    if init_git {
        run_git(&root, &["init", "--quiet"]);
        run_git(&root, &["config", "user.email", "fixture@example.invalid"]);
        run_git(&root, &["config", "user.name", "H4 Fixture"]);
        run_git(&root, &["add", "--", PLAN_PATH, SPEC_PATH]);
        run_git(
            &root,
            &["commit", "--quiet", "--no-gpg-sign", "-m", "fixture"],
        );
    }
    (dir, root)
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("a created parent directory");
    }
    std::fs::write(&path, bytes).expect("a written fixture file");
}

fn run_git(root: &Path, args: &[&str]) -> String {
    let output = Command::new(git().as_str())
        .args(args)
        .current_dir(root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C")
        .output()
        .expect("git ran");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Delegates to the real launcher and records every argv request.
#[derive(Clone, Default)]
struct RecordingLauncher {
    requests: Arc<std::sync::Mutex<Vec<ArgvRequest>>>,
    spawns: Arc<AtomicUsize>,
}

impl RecordingLauncher {
    fn requests(&self) -> Vec<ArgvRequest> {
        self.requests.lock().expect("the recorder").clone()
    }

    fn spawns(&self) -> usize {
        self.spawns.load(Ordering::SeqCst)
    }
}

impl ArgvLauncher for RecordingLauncher {
    type Child = SystemChild;

    fn spawn_argv(&mut self, request: &ArgvRequest) -> std::io::Result<Self::Child> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("the recorder")
            .push(request.clone());
        SystemArgvLauncher.spawn_argv(request)
    }
}

fn inspector(pack_root: &Path, launcher: RecordingLauncher) -> PackInspector<RecordingLauncher> {
    PackInspector::new(
        pack_root,
        python(),
        launcher,
        ProcessSupervisor::new(),
        project(),
    )
    .expect("the pack inspector is constructible")
}

fn plan_path() -> PlanPath {
    PlanPath::parse(PLAN_PATH).expect("a valid plan path")
}

fn layout(root: &Path) -> SourceLayout {
    SourceLayout::new(
        root.canonicalize()
            .expect("a canonical root")
            .to_str()
            .expect("UTF-8"),
    )
    .expect("a layout")
}

fn failure_feature(error: &SddExecutionError) -> String {
    match error {
        SddExecutionError::Unavailable { feature, .. } => feature.clone(),
        other => panic!("expected unavailable, found {other:?}"),
    }
}

fn digest_of(bytes: &[u8]) -> String {
    PlanDigest::sha256(bytes).as_str().to_owned()
}

// ---------------------------------------------------------------------------
// Real pack: happy path
// ---------------------------------------------------------------------------

#[test]
fn real_pack_preview_keeps_exact_bytes() {
    let pack = pack_root();
    let (_dir, root) = project_fixture(false);
    let bridge = inspector(&pack, RecordingLauncher::default());
    let source = PlanFileSource::new(project(), &root).expect("a plan source");
    let mut importer = PlanImporter::new(bridge, source, layout(&root), None);
    let imported = importer.import(&plan_path()).expect("a real pack preview");
    let preview = imported.preview();

    let exact = plan_markdown(false);
    assert_eq!(preview.byte_length(), exact.len() as u64);
    assert_eq!(preview.digest().as_str(), digest_of(&exact));
    assert_eq!(preview.plan_path().as_str(), PLAN_PATH);

    // Global Constraints: verbatim text is the exact slice, Japanese included.
    let constraints = preview.global_constraints();
    let start = constraints.byte_range().start() as usize;
    let end = constraints.byte_range().end() as usize;
    assert_eq!(constraints.text().as_bytes(), &exact[start..end]);
    assert!(
        constraints
            .text()
            .contains("日本語の本文とglobal constraintsを原文のまま保持する。")
    );
    assert_eq!(preview.global_constraints_body(), constraints.byte_range());
    assert!(
        preview.global_constraints_heading().start() < preview.global_constraints_body().start()
    );

    // Task body and heading are exact slices too.
    let task = &preview.tasks()[0];
    assert_eq!(task.number(), 1);
    assert_eq!(task.title(), "Write the module");
    let body = task.parsed().body();
    assert_eq!(
        body.text().as_bytes(),
        &exact[body.byte_range().start() as usize..body.byte_range().end() as usize]
    );
    assert!(body.text().contains("Write `src/a.rs`"));
    assert_eq!(task.heading_text(), "## Task 1: Write the module");
    assert_eq!(
        task.commit_policy(),
        herness_sdd_execute::CommitPolicy::Required
    );
    assert_eq!(task.checks().len(), 1);
    assert_eq!(task.checks()[0].command(), "cargo check");
    assert_eq!(
        task.conditions()[0].mode(),
        herness_sdd_execute::ConditionMode::Checks
    );
    assert_eq!(task.read_paths(), ["src/a.rs".to_owned()]);
    assert_eq!(preview.final_check_ids(), ["build".to_owned()]);
    assert_eq!(preview.spec_refs().len(), 1);
    assert_eq!(
        preview.header().goal(),
        "Prove the preview keeps the exact plan bytes."
    );

    // Spec snapshot: exact bytes, digest, and the applied section.
    let snapshot = imported
        .specs()
        .find("project", SPEC_PATH)
        .expect("one snapshot");
    assert_eq!(snapshot.bytes(), spec_markdown().as_bytes());
    assert_eq!(
        snapshot.digest().as_str(),
        digest_of(spec_markdown().as_bytes())
    );
    assert_eq!(snapshot.sections()[0].heading(), SECTION);
    assert!(
        snapshot.sections()[0]
            .text()
            .contains("日本語の適用section。")
    );
    assert!(snapshot.sections()[0].text().contains("### Detail"));
    assert_eq!(snapshot.section_headings(), vec![SECTION.to_owned()]);
    assert!(
        snapshot
            .canonical_path()
            .starts_with(root.canonicalize().unwrap().to_str().unwrap())
    );
}

#[test]
fn crlf_japanese_plan_is_byte_exact() {
    let pack = pack_root();
    let (_dir, root) = project_fixture(false);
    let crlf = plan_markdown(true);
    assert!(crlf.contains(&b'\r'));
    write(&root, PLAN_PATH, &crlf);
    assert!(crlf.len() > plan_markdown(false).len());

    let bridge = inspector(&pack, RecordingLauncher::default());
    let source = PlanFileSource::new(project(), &root).expect("a plan source");
    let mut importer = PlanImporter::new(bridge, source, layout(&root), None);
    let imported = importer.import(&plan_path()).expect("a CRLF preview");
    let preview = imported.preview();

    assert_eq!(preview.byte_length(), crlf.len() as u64);
    assert_eq!(preview.digest().as_str(), digest_of(&crlf));
    let constraints = preview.global_constraints();
    assert_eq!(
        constraints.text().as_bytes(),
        &crlf[constraints.byte_range().start() as usize..constraints.byte_range().end() as usize]
    );
    assert!(constraints.text().contains("\r\n"));
    assert!(constraints.text().contains("日本語"));
    let task = &preview.tasks()[0];
    // The heading range ends before the CRLF, so the heading text carries no
    // line ending while the body keeps every CRLF byte.
    assert_eq!(task.heading_text(), "## Task 1: Write the module");
    assert_eq!(
        task.heading_range().end(),
        task.heading_range().start() + task.heading_text().len() as u64
    );
    let body = task.parsed().body();
    assert_eq!(
        body.text().as_bytes(),
        &crlf[body.byte_range().start() as usize..body.byte_range().end() as usize]
    );
    assert!(body.text().contains("\r\n"));
    // CRLF changes the digest, so a same-JSON different-bytes plan is visible.
    assert_ne!(preview.digest().as_str(), digest_of(&plan_markdown(false)));
}

#[test]
fn real_pack_reports_old_format_as_unsupported() {
    let pack = pack_root();
    let (_dir, root) = project_fixture(false);
    write(
        &root,
        PLAN_PATH,
        format!(
            "# Old plan\n\n**Goal:** Old.\n\n**Architecture:** Old.\n\n**Tech Stack:** Old.\n\n**Spec:** {SPEC_PATH}\n\n## Global Constraints\n\n- old\n\n## Task 1: Old\n\nDo the old thing.\n"
        )
        .as_bytes(),
    );
    let bridge = inspector(&pack, RecordingLauncher::default());
    let source = PlanFileSource::new(project(), &root).expect("a plan source");
    let mut importer = PlanImporter::new(bridge, source, layout(&root), None);
    let error = importer
        .import(&plan_path())
        .expect_err("the old format is refused");
    assert_eq!(
        error.failure_code(),
        Some(FailureCode::UnsupportedPlanFormat)
    );
    let diagnostic = error.plan_diagnostic().expect("a pack diagnostic");
    assert_eq!(diagnostic.code(), PlanDiagnosticCode::UnsupportedPlanFormat);
    assert!(!diagnostic.message().trim().is_empty());
    assert!(diagnostic.byte_range().is_some());
}

#[test]
fn real_pack_reports_malformed_plan_as_invalid() {
    let pack = pack_root();
    let (_dir, root) = project_fixture(false);
    let exact = String::from_utf8(plan_markdown(false))
        .expect("UTF-8")
        .replace(
            r#""schema": "sdd-execution-plan","#,
            r#""schema": "sdd-execution-plan", "unexpected": true,"#,
        );
    write(&root, PLAN_PATH, exact.as_bytes());
    let bridge = inspector(&pack, RecordingLauncher::default());
    let source = PlanFileSource::new(project(), &root).expect("a plan source");
    let mut importer = PlanImporter::new(bridge, source, layout(&root), None);
    let error = importer
        .import(&plan_path())
        .expect_err("the malformed plan is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));
    let diagnostic = error.plan_diagnostic().expect("a pack diagnostic");
    assert_eq!(diagnostic.code(), PlanDiagnosticCode::InvalidPlan);
    let range = diagnostic.byte_range().expect("a byte range");
    assert!(range.end() <= exact.len() as u64);
}

#[test]
fn oversized_plan_is_refused() {
    // The host refuses 2 MiB + 1 before the bytes are read or sent.
    let (_dir, root) = project_fixture(false);
    let mut bytes = plan_markdown(false);
    bytes.resize(MAX_PLAN_BYTES as usize + 1, b' ');
    write(&root, PLAN_PATH, &bytes);
    let source = PlanFileSource::new(project(), &root).expect("a plan source");
    let error = source
        .read_exact(&plan_path())
        .expect_err("2 MiB+1 is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
    assert!(
        failure_feature(&error).starts_with(OVERSIZE_PLAN_FEATURE),
        "{}",
        failure_feature(&error)
    );

    // An import of the oversize plan starts no process at all: the exact-byte
    // read happens before the interpreter probe and capabilities.
    let launcher = RecordingLauncher::default();
    let bridge = inspector(&pack_root(), launcher.clone());
    let source = PlanFileSource::new(project(), &root).expect("a plan source");
    let mut importer = PlanImporter::new(bridge, source, layout(&root), None);
    let error = importer
        .import(&plan_path())
        .expect_err("the oversize plan is refused");
    assert!(failure_feature(&error).starts_with(OVERSIZE_PLAN_FEATURE));
    assert_eq!(launcher.spawns(), 0, "an oversize plan starts no inspector");

    // The request type refuses the same oversize input, and accepts exactly the
    // limit: the boundary is inclusive and nothing is truncated.
    let mut too_large = plan_markdown(false);
    too_large.resize(MAX_PLAN_BYTES as usize + 1, b'x');
    assert!(InspectRequest::new(plan_path(), too_large).is_err());
    let mut at_limit = plan_markdown(false);
    at_limit.resize(MAX_PLAN_BYTES as usize, b'x');
    let accepted = InspectRequest::new(plan_path(), at_limit).expect("exactly 2 MiB is accepted");
    assert_eq!(accepted.source().len() as u64, MAX_PLAN_BYTES);
    assert_eq!(MAX_PLAN_BYTES, 2 * 1024 * 1024);

    // The pack's own `source_too_large` maps onto the same host class.
    let response = concat!(
        r#"{"protocol":"sdd-plan-inspect","version":1,"operation":"inspect","ok":false,"#,
        r#""error":{"code":"source_too_large","message":"plan is too large"},"diagnostics":[]}"#
    );
    let error = PlanPreview::decode(
        &stub_capabilities(),
        &InspectRequest::new(plan_path(), plan_markdown(false)).expect("a request"),
        response.as_bytes(),
    )
    .expect_err("an oversized source is unavailable");
    assert!(failure_feature(&error).starts_with(OVERSIZE_PLAN_FEATURE));

    // Real pack evidence: given the oversize bytes directly, the inspector
    // refuses them with `source_too_large` instead of truncating, and the host
    // maps that to the same class. This path exists only to prove the pack
    // agrees; the bridge never sends an oversize plan at all.
    let pack = pack_root();
    let oversized = bytes;
    let envelope = serde_json::to_vec(&serde_json::json!({
        "protocol": "sdd-plan-inspect",
        "version": 1,
        "operation": "inspect",
        "planPath": PLAN_PATH,
        "sourceBase64": herness_sdd_execute::plan::base64_encode(&oversized),
    }))
    .expect("an envelope");
    let response = run_inspector_allow_failure(&pack, &envelope);
    let value: serde_json::Value =
        serde_json::from_slice(&response).expect("the pack answered JSON");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "source_too_large");
    let error = PlanPreview::decode(&stub_capabilities(), &request_at_limit(), &response)
        .expect_err("the real oversize answer is unavailable");
    assert!(failure_feature(&error).starts_with(OVERSIZE_PLAN_FEATURE));
}

fn request_at_limit() -> InspectRequest {
    let mut at_limit = plan_markdown(false);
    at_limit.resize(MAX_PLAN_BYTES as usize, b'x');
    InspectRequest::new(plan_path(), at_limit).expect("exactly 2 MiB")
}

#[test]
fn stale_or_changed_pack_is_unavailable() {
    let pack = pack_root();
    let mut capabilities_bridge = inspector(&pack, RecordingLauncher::default());
    let caps = PackInspector::capabilities(
        &mut capabilities_bridge,
        pack.to_str().expect("a UTF-8 pack path"),
    )
    .expect("capabilities");

    let bridge = inspector(&pack, RecordingLauncher::default());
    let wrong = PackFingerprint::parse(format!("sha256:{}", "0".repeat(64))).expect("a digest");
    let error = bridge
        .verify_binding(&caps, Some(&wrong))
        .expect_err("a different fingerprint is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
    assert!(
        failure_feature(&error).starts_with(CONTRACT_FEATURE),
        "{}",
        failure_feature(&error)
    );

    // The current fingerprint binds without an expected value.
    let binding = bridge
        .verify_binding(&caps, None)
        .expect("a verified binding");
    assert_eq!(
        binding.root(),
        pack.canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(binding.fingerprint(), caps.fingerprint());
    assert!(binding.inputs().len() >= 7);
    assert!(
        binding
            .inputs()
            .iter()
            .any(|(id, _, _)| id == "plan-parser")
    );

    // A fingerprint that is not the digest of the exact files at the pack root is
    // refused: the value is recomputed from the verified inputs, not trusted.
    let capabilities_envelope = serde_json::to_vec(&serde_json::json!({
        "protocol": "sdd-plan-inspect",
        "version": 1,
        "operation": "capabilities",
    }))
    .expect("an envelope");
    let raw = run_inspector(&pack, &capabilities_envelope);
    let mut value: serde_json::Value = serde_json::from_slice(&raw).expect("JSON");
    value["result"]["executionContract"]["fingerprint"] =
        serde_json::Value::String(format!("sha256:{}", "c".repeat(64)));
    let tampered = serde_json::to_vec(&value).expect("JSON");
    let forged = herness_sdd_execute::decode_capabilities_response(&tampered)
        .expect("a structurally valid forged capability");
    let error = bridge
        .verify_binding(&forged, None)
        .expect_err("a fingerprint that does not hash the files is refused");
    assert!(
        failure_feature(&error).starts_with(CONTRACT_FEATURE),
        "{}",
        failure_feature(&error)
    );

    // A claimed input whose bytes do not match is a distinct label, so "the pack
    // changed" never reads as "the plan is invalid".
    let stub = stub_pack(CannedInspect::CapabilitiesMismatchedDigest);
    let mut stub_bridge = inspector(stub.path(), RecordingLauncher::default());
    let caps = PackInspector::capabilities(
        &mut stub_bridge,
        stub.path().to_str().expect("a UTF-8 stub path"),
    )
    .expect("stub capabilities");
    let error = stub_bridge
        .verify_binding(&caps, None)
        .expect_err("a mismatched input digest is refused");
    assert!(
        failure_feature(&error).starts_with(CONTRACT_INPUT_FEATURE),
        "{}",
        failure_feature(&error)
    );
}

// ---------------------------------------------------------------------------
// Mechanics: timeout, invalid responses, exit codes
// ---------------------------------------------------------------------------

/// What a stub `scripts/plan-inspect` prints.
#[derive(Clone, Copy)]
enum CannedInspect {
    Sleep,
    /// Answer after a short delay with the same shape as `UnknownField`, so a
    /// generous budget is proven not to be treated as a timeout.
    SlowAnswer,
    /// Print more than a bounded capture retains.
    OversizeResponse,
    CapabilitiesMismatchedDigest,
    ExitNonZero,
    NotJson,
    UnknownField,
    FutureProtocolVersion,
}

fn contract_input_path(id: &str) -> &'static str {
    match id {
        "inspector" => "scripts/sddlib/plan_inspect.py",
        "plan-parser" => "scripts/sddlib/plan_schema.py",
        "schema-document" => "docs/formats/sdd-execution-plan.md",
        "execute-instructions" => "skills/sdd-execute/SKILL.md",
        "implementer-instructions" => "skills/sdd-execute/implementer-prompt.md",
        "herness-execution-definition" => "adapters/herness/execution.json",
        "herness-execution-module" => "adapters/herness/execution.py",
        other => panic!("unstubbed contract input {other}"),
    }
}

/// A stub pack root with the required contract inputs and one script.
fn stub_pack(mode: CannedInspect) -> TempDir {
    let dir = TempDir::new().expect("a stub pack");
    let root = dir.path();
    let script = match mode {
        CannedInspect::Sleep => "import sys, time\nsys.stdin.buffer.read()\ntime.sleep(30)\n",
        CannedInspect::SlowAnswer => concat!(
            "import sys, time\nsys.stdin.buffer.read()\ntime.sleep(0.3)\n",
            "sys.stdout.write('",
            r#"{"protocol":"sdd-plan-inspect","version":1,"operation":"inspect","ok":true,"result":{},"diagnostics":[]}"#,
            "')\n"
        ),
        CannedInspect::ExitNonZero => "import sys\nsys.stdin.buffer.read()\nsys.exit(3)\n",
        CannedInspect::OversizeResponse => {
            "import sys\nsys.stdin.buffer.read()\nsys.stdout.write('x' * 65536)\n"
        }
        CannedInspect::NotJson => {
            "import sys\nsys.stdin.buffer.read()\nsys.stdout.write('not json')\n"
        }
        CannedInspect::UnknownField => concat!(
            "import sys\nsys.stdin.buffer.read()\nsys.stdout.write('",
            r#"{"protocol":"sdd-plan-inspect","version":1,"operation":"inspect","ok":true,"result":{},"diagnostics":[],"extra":1}"#,
            "')\n"
        ),
        CannedInspect::FutureProtocolVersion => concat!(
            "import sys\nsys.stdin.buffer.read()\nsys.stdout.write('",
            r#"{"protocol":"sdd-plan-inspect","version":2,"operation":"inspect","ok":true,"result":{},"diagnostics":[]}"#,
            "')\n"
        ),
        CannedInspect::CapabilitiesMismatchedDigest => "",
    };
    write(root, "scripts/plan-inspect", script.as_bytes());
    for id in herness_sdd_execute::REQUIRED_CONTRACT_INPUTS {
        write(
            root,
            contract_input_path(id),
            format!("stub content for {id}\n").as_bytes(),
        );
    }
    if let CannedInspect::CapabilitiesMismatchedDigest = mode {
        let inputs: Vec<String> = herness_sdd_execute::REQUIRED_CONTRACT_INPUTS
            .iter()
            .map(|id| {
                // A claimed digest that is deliberately not the file's digest.
                format!(
                    r#"{{"id":"{id}","path":"{}","digest":"sha256:{}"}}"#,
                    contract_input_path(id),
                    "0".repeat(64)
                )
            })
            .collect();
        let response = format!(
            r#"{{"protocol":"sdd-plan-inspect","version":1,"operation":"capabilities","ok":true,"result":{{"schemaName":"sdd-execution-plan","schemaVersion":1,"executionBlockInfo":"sdd-execution-v1","maxPlanBytes":2097152,"planPathPrefix":"docs/sdd/plans/","executionContract":{{"fingerprint":"sha256:{}","algorithm":"sha256","inputs":[{}]}}}},"diagnostics":[]}}"#,
            "1".repeat(64),
            inputs.join(",")
        );
        let script =
            format!("import sys\nsys.stdin.buffer.read()\nsys.stdout.write({response:?})\n");
        write(root, "scripts/plan-inspect", script.as_bytes());
    }
    dir
}

fn stub_capabilities() -> InspectorCapabilities {
    InspectorCapabilities::new(
        InspectorProtocol::expected(),
        "sdd-execution-plan",
        1,
        "sdd-execution-v1",
        MAX_PLAN_BYTES,
        "docs/sdd/plans/",
        PackFingerprint::parse(format!("sha256:{}", "a".repeat(64))).expect("a digest"),
    )
    .expect("valid capabilities")
}

/// A pack root without the inspector entry point is refused before any process
/// or read, and the interpreter probe refuses an unusable path.
#[test]
fn pack_root_and_toolchain_are_verified() {
    let empty = TempDir::new().expect("an empty pack root");
    let error = PackInspector::<SystemArgvLauncher>::new(
        empty.path(),
        python(),
        SystemArgvLauncher,
        ProcessSupervisor::new(),
        project(),
    )
    .err()
    .expect("an empty pack root is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
    assert!(
        failure_feature(&error).starts_with(herness_sdd_execute::import::PACK_FEATURE),
        "{}",
        failure_feature(&error)
    );

    // A directory in place of the script is not an entry point.
    let directory_pack = TempDir::new().expect("a pack root");
    std::fs::create_dir_all(directory_pack.path().join("scripts/plan-inspect"))
        .expect("a directory named like the script");
    let error = PackInspector::<SystemArgvLauncher>::new(
        directory_pack.path(),
        python(),
        SystemArgvLauncher,
        ProcessSupervisor::new(),
        project(),
    )
    .err()
    .expect("a directory script is refused");
    assert!(failure_feature(&error).starts_with(herness_sdd_execute::import::PACK_FEATURE));

    // A missing interpreter path is refused, and the probe reports it as a pack
    // capability failure rather than as a plan defect.
    let mut bridge = PackInspector::<SystemArgvLauncher>::new(
        stub_pack(CannedInspect::NotJson).path(),
        AbsolutePath::new("/nonexistent/python3").expect("an absolute path"),
        SystemArgvLauncher,
        ProcessSupervisor::new(),
        project(),
    )
    .expect("a bridge over an unusable interpreter");
    let error = bridge
        .probe_python("/tmp")
        .expect_err("an unusable interpreter is refused");
    assert!(failure_feature(&error).starts_with(herness_sdd_execute::import::PACK_FEATURE));
}

#[test]
fn slow_inspector_times_out() {
    // The default budget is the spec's 30 seconds.
    assert_eq!(INSPECTOR_TIMEOUT_SECONDS, 30);
    assert_eq!(INSPECTOR_TIMEOUT.as_secs(), 30);

    let stub = stub_pack(CannedInspect::Sleep);
    let launcher = RecordingLauncher::default();
    let supervisor = ProcessSupervisor::new();
    let mut bridge = PackInspector::new(
        stub.path(),
        python(),
        launcher.clone(),
        supervisor.clone(),
        project(),
    )
    .expect("a stub bridge")
    .with_timeout(Duration::from_millis(400));
    let request = InspectRequest::new(plan_path(), plan_markdown(false)).expect("a request");
    let started = std::time::Instant::now();
    let error = bridge
        .preview(
            stub.path().to_str().expect("a UTF-8 path"),
            &stub_capabilities(),
            &request,
        )
        .expect_err("a slow inspector is unavailable");
    let elapsed = started.elapsed();
    assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
    assert!(
        failure_feature(&error).starts_with(TIMEOUT_FEATURE),
        "{}",
        failure_feature(&error)
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "a 400 ms budget must not wait for the full 30 s: {elapsed:?}"
    );
    // Exactly one inspector child started, and the host confirmed the whole
    // process group is gone before the timeout was reported.
    assert_eq!(launcher.spawns(), 1);
    assert!(
        supervisor.active_groups().is_empty(),
        "a timed-out inspector group must be gone: {:?}",
        supervisor.active_groups()
    );

    // The timeout is never raised above the host ceiling, and the default budget
    // is the spec's 30 seconds.
    let capped =
        inspector(stub.path(), RecordingLauncher::default()).with_timeout(Duration::from_secs(600));
    assert_eq!(capped.timeout(), INSPECTOR_TIMEOUT);
    assert_eq!(
        inspector(stub.path(), RecordingLauncher::default()).timeout(),
        INSPECTOR_TIMEOUT
    );

    // Positive control: a slow answer inside a generous budget is not a timeout,
    // so the label means a real elapsed budget rather than a slow process.
    let answering = stub_pack(CannedInspect::SlowAnswer);
    let mut bridge = inspector(answering.path(), RecordingLauncher::default())
        .with_timeout(Duration::from_secs(5));
    let error = bridge
        .preview(
            answering.path().to_str().expect("a UTF-8 path"),
            &stub_capabilities(),
            &request,
        )
        .expect_err("the canned empty result is not a valid preview");
    assert!(
        !failure_feature(&error).starts_with(TIMEOUT_FEATURE),
        "a 300 ms answer inside 5 s must not be a timeout: {}",
        failure_feature(&error)
    );
}

#[test]
fn invalid_inspector_responses_are_unavailable() {
    for (mode, expected) in [
        (CannedInspect::ExitNonZero, EXIT_FEATURE),
        (CannedInspect::NotJson, RESPONSE_FEATURE),
        (CannedInspect::UnknownField, RESPONSE_FEATURE),
    ] {
        let stub = stub_pack(mode);
        let mut bridge = inspector(stub.path(), RecordingLauncher::default());
        let request = InspectRequest::new(plan_path(), plan_markdown(false)).expect("a request");
        let error = bridge
            .preview(
                stub.path().to_str().expect("a UTF-8 path"),
                &stub_capabilities(),
                &request,
            )
            .expect_err("an unusable response is unavailable");
        assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
        assert!(
            failure_feature(&error).starts_with(expected),
            "expected {expected}, found {}",
            failure_feature(&error)
        );
    }

    // A response larger than the bounded capture is refused, never parsed from
    // a truncated buffer.
    let stub = stub_pack(CannedInspect::OversizeResponse);
    let mut bridge = inspector(stub.path(), RecordingLauncher::default()).with_output_limit(1024);
    assert_eq!(bridge.output_limit(), 1024);
    let request = InspectRequest::new(plan_path(), plan_markdown(false)).expect("a request");
    let error = bridge
        .preview(
            stub.path().to_str().expect("a UTF-8 path"),
            &stub_capabilities(),
            &request,
        )
        .expect_err("an oversized response is unavailable");
    assert!(
        failure_feature(&error).starts_with(herness_sdd_execute::import::OVERSIZE_RESPONSE_FEATURE),
        "{}",
        failure_feature(&error)
    );

    // A future protocol version is its own typed error, not `unavailable`.
    let stub = stub_pack(CannedInspect::FutureProtocolVersion);
    let mut bridge = inspector(stub.path(), RecordingLauncher::default());
    let request = InspectRequest::new(plan_path(), plan_markdown(false)).expect("a request");
    let error = bridge
        .preview(
            stub.path().to_str().expect("a UTF-8 path"),
            &stub_capabilities(),
            &request,
        )
        .expect_err("a future protocol is refused");
    match error {
        SddExecutionError::UnsupportedInspectorProtocol { found, expected } => {
            assert_eq!(found, "sdd-plan-inspect/2");
            assert_eq!(expected, "sdd-plan-inspect/1");
        }
        other => panic!("expected an unsupported protocol, found {other:?}"),
    }
}

#[test]
fn failure_codes_are_mapped_distinctly() {
    let request = InspectRequest::new(plan_path(), plan_markdown(false)).expect("a request");
    for code in [
        InspectorFailureCode::InvalidJson,
        InspectorFailureCode::RequestNotObject,
        InspectorFailureCode::MissingRequestField,
        InspectorFailureCode::UnknownRequestField,
        InspectorFailureCode::InvalidRequestValue,
        InspectorFailureCode::UnknownProtocol,
        InspectorFailureCode::UnsupportedProtocolVersion,
        InspectorFailureCode::UnknownOperation,
        InspectorFailureCode::InvalidPlanPath,
        InspectorFailureCode::InvalidSourceBase64,
        InspectorFailureCode::SourceTooLarge,
        InspectorFailureCode::FingerprintInputMissing,
        InspectorFailureCode::InternalError,
    ] {
        let response = format!(
            r#"{{"protocol":"sdd-plan-inspect","version":1,"operation":"inspect","ok":false,"error":{{"code":"{}","message":"stub"}},"diagnostics":[]}}"#,
            code.as_str()
        );
        let error = PlanPreview::decode(&stub_capabilities(), &request, response.as_bytes())
            .expect_err("a failure is refused");
        assert_eq!(
            error.failure_code(),
            Some(FailureCode::Unavailable),
            "{code:?}"
        );
    }
    for (code, class) in [
        (InspectorFailureCode::InvalidPlan, FailureCode::InvalidPlan),
        (
            InspectorFailureCode::UnsupportedPlanFormat,
            FailureCode::UnsupportedPlanFormat,
        ),
    ] {
        let response = format!(
            r#"{{"protocol":"sdd-plan-inspect","version":1,"operation":"inspect","ok":false,"error":{{"code":"{}","message":"stub"}},"diagnostics":[{{"code":"{}","message":"stub","range":{{"start":3,"end":9}}}}]}}"#,
            code.as_str(),
            code.as_str()
        );
        let error = PlanPreview::decode(&stub_capabilities(), &request, response.as_bytes())
            .expect_err("a plan defect is refused");
        assert_eq!(error.failure_code(), Some(class));
        let diagnostic = error.plan_diagnostic().expect("a diagnostic");
        assert_eq!(diagnostic.byte_range().expect("a range").start(), 3);
    }

    // An unknown wire code is an invalid response, not a guessed plan defect.
    let response = r#"{"protocol":"sdd-plan-inspect","version":1,"operation":"inspect","ok":false,"error":{"code":"invented_code","message":"stub"},"diagnostics":[]}"#;
    let error = PlanPreview::decode(&stub_capabilities(), &request, response.as_bytes())
        .expect_err("an unknown code is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
    assert!(failure_feature(&error).starts_with(RESPONSE_FEATURE));
}

#[test]
fn argv_stdin_and_cwd_are_exact() {
    let pack = pack_root();
    let (_dir, root) = project_fixture(false);
    let launcher = RecordingLauncher::default();
    let bridge = inspector(&pack, launcher.clone());
    let source = PlanFileSource::new(project(), &root).expect("a plan source");
    let mut importer = PlanImporter::new(bridge, source, layout(&root), None);
    let imported = importer.import(&plan_path()).expect("a preview");
    assert_eq!(imported.preview().tasks().len(), 1);

    let requests = launcher.requests();
    // One `--version` probe, one `capabilities`, one `inspect`: no other child.
    assert_eq!(launcher.spawns(), 3, "{requests:?}");
    let root_text = root.canonicalize().expect("the canonical project root");
    let root_text = root_text.to_str().expect("a UTF-8 path");
    let pack_script = pack
        .canonicalize()
        .expect("a canonical pack root")
        .join("scripts/plan-inspect");
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request.program(), python().as_str());
        if index == 0 {
            // The version probe is the interpreter with `--version` only: the
            // inspector script is not involved.
            assert_eq!(request.args(), ["--version".to_owned()]);
        } else {
            assert_eq!(request.args()[0], pack_script.to_str().expect("UTF-8"));
        }
        // The protocol requires the project root as cwd.
        assert_eq!(request.cwd().as_str(), root_text);
        assert!(
            request
                .env()
                .iter()
                .any(|(key, value)| key == "PYTHONDONTWRITEBYTECODE" && value == "1")
        );
    }
    // argv is fixed: one argument each, no `-c`, no extra argument.
    assert_eq!(requests[0].args().len(), 1);
    assert_eq!(requests[1].args().len(), 1);
    assert_eq!(requests[2].args().len(), 1);
    assert!(requests[0].stdin().is_none());

    // Both protocol requests carry exactly one JSON object on stdin.
    let capabilities: serde_json::Value =
        serde_json::from_slice(requests[1].stdin().expect("capabilities stdin"))
            .expect("capabilities JSON");
    assert_eq!(capabilities["operation"], "capabilities");
    assert_eq!(capabilities["protocol"], "sdd-plan-inspect");
    assert_eq!(capabilities["version"], 1);

    let inspect: serde_json::Value =
        serde_json::from_slice(requests[2].stdin().expect("inspect stdin")).expect("inspect JSON");
    assert_eq!(inspect["operation"], "inspect");
    assert_eq!(inspect["planPath"], PLAN_PATH);
    let encoded = inspect["sourceBase64"].as_str().expect("a base64 string");
    // Canonical base64 of the exact plan bytes, no whitespace.
    assert_eq!(
        encoded,
        herness_sdd_execute::plan::base64_encode(&plan_markdown(false))
    );
    assert!(!encoded.contains('\n'));
    assert_eq!(
        plan_markdown(false).len(),
        imported.preview().byte_length() as usize
    );
}

/// The `PlanInspectorPort` path needs an explicit project root: a bridge without
/// one refuses rather than substituting the pack root as cwd.
#[test]
fn plan_inspector_port_requires_a_bound_project_root() {
    let pack = pack_root();
    let (_dir, root) = project_fixture(false);
    let request = InspectRequest::new(plan_path(), plan_markdown(false)).expect("a request");

    let mut unbound = PackInspector::<SystemArgvLauncher>::new(
        &pack,
        python(),
        SystemArgvLauncher,
        ProcessSupervisor::new(),
        project(),
    )
    .expect("a bridge");
    assert!(unbound.project_root().is_none());
    let error = herness_sdd_execute::PlanInspectorPort::inspect(&mut unbound, &request)
        .expect_err("an unbound bridge refuses");
    assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
    assert!(failure_feature(&error).starts_with(herness_sdd_execute::import::PACK_FEATURE));

    let mut bound = PackInspector::<SystemArgvLauncher>::new(
        &pack,
        python(),
        SystemArgvLauncher,
        ProcessSupervisor::new(),
        project(),
    )
    .expect("a bridge")
    .with_project_root(
        root.canonicalize()
            .expect("a canonical root")
            .to_str()
            .expect("UTF-8")
            .to_owned(),
    );
    let capabilities = herness_sdd_execute::PlanInspectorPort::capabilities(&mut bound)
        .expect("the bound capabilities");
    assert_eq!(capabilities.schema_version(), 1);
    assert_eq!(capabilities.max_plan_bytes(), MAX_PLAN_BYTES);
    let inspected = herness_sdd_execute::PlanInspectorPort::inspect(&mut bound, &request)
        .expect("the bound inspect");
    assert_eq!(inspected.byte_length(), plan_markdown(false).len() as u64);
    assert_eq!(inspected.parsed().tasks().len(), 1);
    assert_eq!(
        inspected.digest().as_str(),
        digest_of(&plan_markdown(false))
    );
}

// ---------------------------------------------------------------------------
// Spec and source snapshots
// ---------------------------------------------------------------------------

fn snapshot_of(root: &Path, source: &str, relative: &str, bytes: &[u8]) -> SourceSnapshot {
    SourceSnapshot::new(
        source,
        relative,
        root.canonicalize()
            .expect("a canonical root")
            .join(relative)
            .to_str()
            .expect("UTF-8"),
        bytes.to_vec(),
    )
    .expect("a snapshot")
}

#[test]
fn spec_snapshot_requires_existing_section() {
    let (_dir, root) = project_fixture(false);
    let layouts = layout(&root);
    let refs = vec![
        herness_sdd_execute::PreviewSpecRef::new("project", SPEC_PATH, vec![SECTION.to_owned()])
            .expect("a reference"),
    ];
    let verified = verify_spec_snapshots(
        &layouts,
        &refs,
        &[snapshot_of(
            &root,
            "project",
            SPEC_PATH,
            spec_markdown().as_bytes(),
        )],
    )
    .expect("a verified snapshot");
    assert_eq!(verified.total_bytes(), spec_markdown().len() as u64);
    assert_eq!(
        verified.snapshots()[0].digest().as_str(),
        digest_of(spec_markdown().as_bytes())
    );

    // A section the document does not contain is refused, never guessed.
    let missing = vec![
        herness_sdd_execute::PreviewSpecRef::new(
            "project",
            SPEC_PATH,
            vec!["Not A Real Section".to_owned()],
        )
        .expect("a reference"),
    ];
    let error = verify_spec_snapshots(
        &layouts,
        &missing,
        &[snapshot_of(
            &root,
            "project",
            SPEC_PATH,
            spec_markdown().as_bytes(),
        )],
    )
    .expect_err("a missing section is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));
    assert!(format!("{error}").contains("Not A Real Section"));

    // A heading the document has twice is ambiguous: refused, not the first one.
    let duplicate = b"# Duplicate\n\n## Repeated\n\none\n\n## Repeated\n\ntwo\n";
    write(&root, "docs/sdd/specs/duplicate.md", duplicate);
    let ambiguous = vec![
        herness_sdd_execute::PreviewSpecRef::new(
            "project",
            "docs/sdd/specs/duplicate.md",
            vec!["Repeated".to_owned()],
        )
        .expect("a reference"),
    ];
    let error = verify_spec_snapshots(
        &layouts,
        &ambiguous,
        &[snapshot_of(
            &root,
            "project",
            "docs/sdd/specs/duplicate.md",
            duplicate,
        )],
    )
    .expect_err("an ambiguous section is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));
    assert!(format!("{error}").contains("more than once"));

    // A heading inside a fenced block is not a section.
    let fenced = b"# Fenced\n\n```\n## Fixture section\n```\n\n## Fenced\n\nbody\n";
    write(&root, "docs/sdd/specs/fenced.md", fenced);
    let fenced_ref = vec![
        herness_sdd_execute::PreviewSpecRef::new(
            "project",
            "docs/sdd/specs/fenced.md",
            vec!["Fixture section".to_owned()],
        )
        .expect("a reference"),
    ];
    let error = verify_spec_snapshots(
        &layouts,
        &fenced_ref,
        &[snapshot_of(
            &root,
            "project",
            "docs/sdd/specs/fenced.md",
            fenced,
        )],
    )
    .expect_err("a fenced pseudo-heading is not a section");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));
}

#[test]
fn spec_snapshot_refuses_missing_file_or_extra_snapshot() {
    let (_dir, root) = project_fixture(false);
    let layouts = layout(&root);
    let refs = vec![
        herness_sdd_execute::PreviewSpecRef::new("project", SPEC_PATH, vec![SECTION.to_owned()])
            .expect("a reference"),
    ];
    let error = verify_spec_snapshots(&layouts, &refs, &[]).expect_err("no snapshot is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));

    // A snapshot for a document the plan never declares is refused.
    let extra = snapshot_of(
        &root,
        "project",
        "docs/sdd/specs/other.md",
        b"# Other\n\n## Fixture section\n\nx\n",
    );
    let real = snapshot_of(&root, "project", SPEC_PATH, spec_markdown().as_bytes());
    let error = verify_spec_snapshots(&layouts, &refs, &[real, extra])
        .expect_err("an undeclared snapshot is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));

    // A declared file the reader could not open is refused before parsing.
    let absent = herness_sdd_execute::PreviewSpecRef::new(
        "project",
        "docs/sdd/specs/absent.md",
        vec![SECTION.to_owned()],
    )
    .expect("a reference");
    let error = read_spec_snapshot(&layouts, &absent).expect_err("a missing file is refused");
    assert!(matches!(
        error,
        SddExecutionError::InvalidValue { .. } | SddExecutionError::InvalidPlan { .. }
    ));
}

#[test]
fn alias_outside_the_approved_roots_is_refused() {
    let approved = TempDir::new().expect("an approved alias root");
    let unapproved = TempDir::new().expect("an unapproved root");
    write(
        approved.path(),
        "notes.md",
        b"# Approved notes\n\n## Fixture section\n\napproved\n",
    );
    write(
        unapproved.path(),
        "notes.md",
        b"# Unapproved notes\n\n## Fixture section\n\nunapproved\n",
    );
    let approved_root = approved
        .path()
        .canonicalize()
        .expect("a canonical alias root");
    let layouts = SourceLayout::new("/tmp/herness-h4-import-project")
        .expect("a project root")
        .with_alias(
            "pack-docs",
            approved_root.to_str().expect("UTF-8"),
            vec!["notes.md".to_owned()],
        )
        .expect("an approved alias");

    let reference =
        herness_sdd_execute::PreviewSpecRef::new("pack-docs", "notes.md", vec![SECTION.to_owned()])
            .expect("a reference");
    let snapshot =
        read_spec_snapshot(&layouts, &reference).expect("the approved alias is readable");
    assert!(
        snapshot
            .canonical_path()
            .starts_with(approved_root.to_str().unwrap())
    );
    let verified = read_and_verify_specs(&layouts, std::slice::from_ref(&reference))
        .expect("a verified alias snapshot");
    assert_eq!(verified.snapshots().len(), 1);
    assert_eq!(verified.snapshots()[0].sections()[0].heading(), SECTION);

    // An unknown alias is refused before any read.
    let unknown = herness_sdd_execute::PreviewSpecRef::new(
        "private-notes",
        "notes.md",
        vec![SECTION.to_owned()],
    )
    .expect("a reference");
    let error = read_spec_snapshot(&layouts, &unknown).expect_err("an unknown alias is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));

    // An alias path outside its approved read paths is refused.
    let outside = herness_sdd_execute::PreviewSpecRef::new(
        "pack-docs",
        "secrets.md",
        vec![SECTION.to_owned()],
    )
    .expect("a reference");
    let error = read_spec_snapshot(&layouts, &outside).expect_err("an ungranted path is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));

    // A snapshot read from a different root cannot be passed off as the
    // approved alias: confinement compares the canonical path.
    let forged = SourceSnapshot::new(
        "pack-docs",
        "notes.md",
        unapproved
            .path()
            .canonicalize()
            .unwrap()
            .join("notes.md")
            .to_str()
            .unwrap(),
        b"# Unapproved notes\n\n## Fixture section\n\nunapproved\n".to_vec(),
    )
    .expect("a forged snapshot");
    let error = verify_spec_snapshots(&layouts, std::slice::from_ref(&reference), &[forged])
        .expect_err("a snapshot outside the approved root is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));

    // A symlink inside the approved root that leaves it is refused.
    let alias_root = TempDir::new().expect("a symlink alias root");
    std::os::unix::fs::symlink(
        unapproved.path().join("notes.md"),
        alias_root.path().join("notes.md"),
    )
    .expect("a symlink");
    let alias_root = alias_root.path().canonicalize().expect("canonical");
    let escaping = SourceLayout::new("/tmp/herness-h4-import-project")
        .expect("a project root")
        .with_alias(
            "pack-docs",
            alias_root.to_str().expect("UTF-8"),
            vec!["notes.md".to_owned()],
        )
        .expect("an approved alias");
    let error = read_spec_snapshot(&escaping, &reference).expect_err("a symlink escape is refused");
    assert!(
        matches!(
            error,
            SddExecutionError::InvalidPlan { .. } | SddExecutionError::InvalidValue { .. }
        ),
        "{error:?}"
    );
}

/// The real canonical specs carry every section this Task and its neighbours
/// name, and the pure scanner finds each one exactly once.
#[test]
fn canonical_spec_sections_resolve() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root");
    let layouts = SourceLayout::new(repo.to_str().expect("UTF-8")).expect("a layout");
    let h4 = "docs/sdd/specs/2026-11-13-h4-sdd-execute-design.md";
    let h1 = "docs/sdd/specs/2026-11-07-h1-runtime-design.md";
    let refs = vec![
        herness_sdd_execute::PreviewSpecRef::new(
            "project",
            h4,
            vec![
                "New plan format and inspection".to_owned(),
                "Shared operations and authorization".to_owned(),
                "Workspace, context and task identity".to_owned(),
            ],
        )
        .expect("a reference"),
        herness_sdd_execute::PreviewSpecRef::new(
            "project",
            h1,
            vec!["Skills and documents".to_owned()],
        )
        .expect("a reference"),
    ];
    let verified = read_and_verify_specs(&layouts, &refs).expect("the canonical sections resolve");
    assert_eq!(verified.snapshots().len(), 2);

    let h4_snapshot = verified.find("project", h4).expect("the H4 spec");
    assert_eq!(
        h4_snapshot.section_headings(),
        vec![
            "New plan format and inspection".to_owned(),
            "Shared operations and authorization".to_owned(),
            "Workspace, context and task identity".to_owned(),
        ]
    );
    assert!(
        h4_snapshot.sections()[0]
            .text()
            .contains("sdd-plan-inspect")
    );
    assert!(h4_snapshot.sections()[0].text().contains("sourceBase64"));
    assert!(h4_snapshot.sections()[0].text().contains("task-brief"));

    let h1_snapshot = verified.find("project", h1).expect("the H1 spec");
    assert_eq!(
        h1_snapshot.section_headings(),
        vec!["Skills and documents".to_owned()]
    );
    assert!(h1_snapshot.sections()[0].text().contains("Python 3.11"));

    // The snapshot digest is the digest of the exact bytes on disk.
    let exact = std::fs::read(repo.join(h4)).expect("the H4 spec bytes");
    assert_eq!(h4_snapshot.digest().as_str(), digest_of(&exact));
    assert_eq!(h4_snapshot.bytes(), exact.as_slice());
}

/// An approved root that is not canonical is refused with a diagnosable error,
/// instead of every read failing as an escape.
#[test]
fn non_canonical_approved_root_is_refused() {
    let parent = TempDir::new().expect("a temp parent");
    let real_root = parent.path().join("real");
    std::fs::create_dir_all(&real_root).expect("a real root");
    write(
        &real_root,
        "notes.md",
        b"# Notes\n\n## Fixture section\n\nbody\n",
    );
    let link = parent.path().join("linked");
    std::os::unix::fs::symlink(&real_root, &link).expect("a root symlink");
    let layouts = SourceLayout::new(parent.path().canonicalize().unwrap().to_str().unwrap())
        .expect("a project root")
        .with_alias(
            "pack-docs",
            link.to_str().expect("UTF-8"),
            vec!["notes.md".to_owned()],
        )
        .expect("an approved alias");
    let reference =
        herness_sdd_execute::PreviewSpecRef::new("pack-docs", "notes.md", vec![SECTION.to_owned()])
            .expect("a reference");
    let error =
        read_spec_snapshot(&layouts, &reference).expect_err("a non-canonical root is refused");
    assert!(
        matches!(error, SddExecutionError::InvalidValue { .. }),
        "{error:?}"
    );
}

#[test]
fn project_symlink_escape_is_refused() {
    let (_dir, root) = project_fixture(false);
    let outside = TempDir::new().expect("an outside directory");
    write(
        outside.path(),
        "outside.md",
        b"# Outside\n\n## Fixture section\n\noutside\n",
    );
    std::os::unix::fs::symlink(
        outside.path().join("outside.md"),
        root.join("docs/sdd/specs/linked.md"),
    )
    .expect("a symlink");
    let layouts = layout(&root);
    let reference = herness_sdd_execute::PreviewSpecRef::new(
        "project",
        "docs/sdd/specs/linked.md",
        vec![SECTION.to_owned()],
    )
    .expect("a reference");
    let error =
        read_spec_snapshot(&layouts, &reference).expect_err("a project symlink escape is refused");
    assert!(
        matches!(
            error,
            SddExecutionError::InvalidValue { .. } | SddExecutionError::InvalidPlan { .. }
        ),
        "{error:?}"
    );
}

// ---------------------------------------------------------------------------
// Zero child, model, and Git side effects
// ---------------------------------------------------------------------------

/// A fake dispatch port whose every method panics: a preview never calls it.
struct ForbiddenDispatch {
    calls: Arc<AtomicUsize>,
}

impl herness_sdd_execute::ChildDispatchPort for ForbiddenDispatch {
    fn dispatch(
        &mut self,
        _plan: &herness_sdd_execute::ChildDispatchPlan,
    ) -> Result<herness_sdd_execute::DispatchResult, SddExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("import must not dispatch a child");
    }

    fn reconcile(
        &mut self,
        _project: ProjectId,
        _execution: herness_sdd_execute::ExecutionId,
        _request: herness_sdd_execute::DispatchRequestId,
    ) -> Result<Option<herness_sdd_execute::DispatchResult>, SddExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("import must not reconcile a child");
    }
}

/// A fake Git port whose every method panics.
struct ForbiddenGit {
    calls: Arc<AtomicUsize>,
}

impl herness_sdd_execute::HostGitPort for ForbiddenGit {
    fn commit(
        &mut self,
        _entry: &herness_sdd_execute::GitJournalEntry,
        _authorization: herness_sdd_execute::CommitAuthorization,
    ) -> Result<herness_sdd_execute::GitCommitOutcome, SddExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("import must not commit");
    }

    fn observe(
        &mut self,
        _entry: &herness_sdd_execute::GitJournalEntry,
    ) -> Result<herness_sdd_execute::GitCommitOutcome, SddExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("import must not observe a commit");
    }
}

/// A plan source that counts its calls.
struct CountingSource {
    inner: PlanFileSource,
    reads: Arc<AtomicUsize>,
    observations: Arc<AtomicUsize>,
}

impl PlanSourcePort for CountingSource {
    fn read_plan(
        &self,
        project_id: ProjectId,
        plan_path: &PlanPath,
    ) -> Result<PlanSourceRead, SddExecutionError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read_plan(project_id, plan_path)
    }

    fn observe(
        &self,
        project_id: ProjectId,
        plan_path: &PlanPath,
    ) -> Result<herness_sdd_execute::PlanObservation, SddExecutionError> {
        self.observations.fetch_add(1, Ordering::SeqCst);
        self.inner.observe(project_id, plan_path)
    }
}

impl RootedPlanSource for CountingSource {
    fn project_root(&self) -> Option<&str> {
        Some(self.inner.project_root())
    }

    fn project_id(&self) -> ProjectId {
        self.inner.project_id()
    }
}

#[test]
fn import_starts_only_the_inspector_and_changes_no_repository() {
    let pack = pack_root();
    let (_dir, root) = project_fixture(true);

    let head_before = run_git(&root, &["rev-parse", "HEAD"]);
    let index_before = run_git(&root, &["ls-files", "-s", "--", "."]);
    let status_before = run_git(&root, &["status", "--porcelain", "-z"]);
    let tree_before = tree_digest(&root);
    let pack_before = tree_digest_filtered(&pack, |relative| {
        relative.starts_with("scripts")
            || relative.starts_with("skills")
            || relative.starts_with("adapters")
    });

    let launcher = RecordingLauncher::default();
    let bridge = inspector(&pack, launcher.clone());
    let reads = Arc::new(AtomicUsize::new(0));
    let observations = Arc::new(AtomicUsize::new(0));
    let source = CountingSource {
        inner: PlanFileSource::new(project(), &root).expect("a plan source"),
        reads: Arc::clone(&reads),
        observations: Arc::clone(&observations),
    };
    let mut importer = PlanImporter::new(bridge, source, layout(&root), None);

    // The fake ports panic if touched; the importer holds no such port at all,
    // so a preview cannot reach them.
    let dispatch_calls = Arc::new(AtomicUsize::new(0));
    let git_calls = Arc::new(AtomicUsize::new(0));
    let _forbidden_dispatch = ForbiddenDispatch {
        calls: Arc::clone(&dispatch_calls),
    };
    let _forbidden_git = ForbiddenGit {
        calls: Arc::clone(&git_calls),
    };

    let imported = importer.import(&plan_path()).expect("a preview");
    assert_eq!(imported.preview().tasks().len(), 1);

    // Zero H2 children: the only spawned processes are the three inspector
    // invocations (version probe, capabilities, inspect), all `python3`.
    assert_eq!(launcher.spawns(), 3);
    assert!(
        launcher
            .requests()
            .iter()
            .all(|request| request.program() == python().as_str())
    );
    // Zero model requests (no engine or provider type exists here) and zero Git
    // operations.
    assert_eq!(dispatch_calls.load(Ordering::SeqCst), 0);
    assert_eq!(git_calls.load(Ordering::SeqCst), 0);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(observations.load(Ordering::SeqCst), 0);

    // The repository is byte-identical: same HEAD, index, status, and content.
    assert_eq!(run_git(&root, &["rev-parse", "HEAD"]), head_before);
    assert_eq!(run_git(&root, &["ls-files", "-s", "--", "."]), index_before);
    assert_eq!(
        run_git(&root, &["status", "--porcelain", "-z"]),
        status_before
    );
    assert_eq!(status_before, "");
    assert_eq!(tree_digest(&root), tree_before);

    // Python wrote no bytecode into the pack.
    assert_eq!(
        tree_digest_filtered(&pack, |relative| {
            relative.starts_with("scripts")
                || relative.starts_with("skills")
                || relative.starts_with("adapters")
        }),
        pack_before
    );
}

/// Hashes every file below `root`, excluding `.git` (whose index the test's own
/// `git status` may refresh).
fn tree_digest(root: &Path) -> BTreeMap<String, String> {
    tree_digest_filtered(root, |_| true)
}

fn tree_digest_filtered(root: &Path, keep: impl Fn(&str) -> bool) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    walk(root, root, &keep, &mut out);
    out
}

fn walk(
    root: &Path,
    current: &Path,
    keep: &impl Fn(&str) -> bool,
    out: &mut BTreeMap<String, String>,
) {
    let Ok(entries) = std::fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .expect("a path under the root")
            .to_string_lossy()
            .into_owned();
        if relative == ".git" || relative.starts_with(".git/") {
            continue;
        }
        let metadata = entry.metadata().expect("metadata");
        if metadata.is_dir() {
            walk(root, &path, keep, out);
        } else if metadata.is_file() && keep(&relative) {
            let bytes = std::fs::read(&path).expect("a readable file");
            out.insert(relative, digest_of(&bytes));
        }
    }
}

// ---------------------------------------------------------------------------
// Preview invariants without a second pack run
// ---------------------------------------------------------------------------

#[test]
fn preview_rejects_a_tampered_response() {
    let pack = pack_root();
    let (_dir, _root) = project_fixture(false);
    let mut capabilities_bridge = inspector(&pack, RecordingLauncher::default());
    let caps = PackInspector::capabilities(
        &mut capabilities_bridge,
        pack.to_str().expect("a UTF-8 path"),
    )
    .expect("capabilities");
    let capabilities = caps.capabilities().clone();

    let exact = plan_markdown(false);
    let request = InspectRequest::new(plan_path(), exact.clone()).expect("a request");
    let envelope = inspect_request_envelope(&request).expect("an envelope");
    let response = run_inspector(&pack, &envelope);
    // The real response decodes.
    PlanPreview::decode(&capabilities, &request, &response).expect("the real response decodes");

    // Global Constraints text that is not its range's bytes is refused.
    let mut value: serde_json::Value = serde_json::from_slice(&response).expect("JSON");
    value["result"]["globalConstraints"]["text"] = serde_json::Value::String("tampered".to_owned());
    let damaged = serde_json::to_vec(&value).expect("JSON");
    let error = PlanPreview::decode(&capabilities, &request, &damaged)
        .expect_err("a tampered text is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::Unavailable));
    assert!(failure_feature(&error).starts_with(RESPONSE_FEATURE));

    // A digest that does not describe the request bytes is a plan defect: the
    // inspector did not parse the bytes the host sent.
    let mut value: serde_json::Value = serde_json::from_slice(&response).expect("JSON");
    value["result"]["digest"] = serde_json::Value::String(format!("sha256:{}", "b".repeat(64)));
    let damaged = serde_json::to_vec(&value).expect("JSON");
    let error = PlanPreview::decode(&capabilities, &request, &damaged)
        .expect_err("a wrong digest is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));

    // A different plan path is refused: the path and the bytes are bound.
    let mut value: serde_json::Value = serde_json::from_slice(&response).expect("JSON");
    value["result"]["planPath"] = serde_json::Value::String("docs/sdd/plans/other.md".to_owned());
    let damaged = serde_json::to_vec(&value).expect("JSON");
    let error = PlanPreview::decode(&capabilities, &request, &damaged)
        .expect_err("a different plan path is refused");
    assert!(failure_feature(&error).starts_with(RESPONSE_FEATURE));

    // A range past the end of the input is refused, never clamped.
    let mut value: serde_json::Value = serde_json::from_slice(&response).expect("JSON");
    value["result"]["tasks"][0]["bodyRange"]["end"] =
        serde_json::Value::from(exact.len() as u64 + 10);
    let damaged = serde_json::to_vec(&value).expect("JSON");
    let error = PlanPreview::decode(&capabilities, &request, &damaged)
        .expect_err("an out-of-range slice is refused");
    assert!(failure_feature(&error).starts_with(RESPONSE_FEATURE));

    // A Task number that skips a position is a plan defect.
    let mut value: serde_json::Value = serde_json::from_slice(&response).expect("JSON");
    value["result"]["tasks"][0]["number"] = serde_json::Value::from(2);
    let damaged = serde_json::to_vec(&value).expect("JSON");
    let error = PlanPreview::decode(&capabilities, &request, &damaged)
        .expect_err("a non-contiguous Task number is refused");
    assert_eq!(error.failure_code(), Some(FailureCode::InvalidPlan));
}

/// Runs the real inspector once and returns its stdout bytes, requiring exit 0.
fn run_inspector(pack: &Path, stdin: &[u8]) -> Vec<u8> {
    let (stdout, success) = inspector_exchange(pack, stdin);
    assert!(
        success,
        "the inspector failed on a request it should answer"
    );
    stdout
}

/// Runs the real inspector and returns its stdout with its exit status.
fn run_inspector_allow_failure(pack: &Path, stdin: &[u8]) -> Vec<u8> {
    inspector_exchange(pack, stdin).0
}

fn inspector_exchange(pack: &Path, stdin: &[u8]) -> (Vec<u8>, bool) {
    let script = pack.join("scripts/plan-inspect");
    let mut child = Command::new(python().as_str())
        .arg(&script)
        .current_dir(pack)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONIOENCODING", "utf-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the inspector starts");
    {
        use std::io::Write;
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(stdin).expect("stdin write");
    }
    let output = child.wait_with_output().expect("the inspector exits");
    (output.stdout, output.status.success())
}

#[test]
fn preview_serializes_without_losing_ranges() {
    let pack = pack_root();
    let (_dir, root) = project_fixture(false);
    let bridge = inspector(&pack, RecordingLauncher::default());
    let source = PlanFileSource::new(project(), &root).expect("a plan source");
    let mut importer = PlanImporter::new(bridge, source, layout(&root), None);
    let imported = importer.import(&plan_path()).expect("a preview");
    let json = serde_json::to_value(imported.preview()).expect("a serializable preview");
    assert_eq!(json["planPath"], PLAN_PATH);
    assert_eq!(json["tasks"][0]["parsed"]["number"], 1);
    assert_eq!(json["finalCheckIds"][0], "build");
    assert_eq!(
        json["inspected"]["byteLength"].as_u64(),
        Some(plan_markdown(false).len() as u64)
    );
    let specs: SpecSnapshotSet = imported.specs().clone();
    assert_eq!(specs.snapshots().len(), 1);
    // The preview keeps the parsed summary an approval binds.
    assert_eq!(imported.preview().parsed().tasks().len(), 1);
    assert_eq!(
        imported.preview().parsed().global_constraints().text(),
        imported.preview().global_constraints().text()
    );
}
