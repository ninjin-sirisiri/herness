//! Shared fixtures for the Task 18 evidence and assessment tests.
//!
//! The real Common SDD pack is used read-only when present. Render bytes are
//! synthetic and explicitly distinguished from native WKWebView evidence; no
//! test claims that a synthetic capture is a real browser run.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use herness_core::{ModelId, ProjectId, Provider, Timestamp};
use herness_desktop::html_sync::policy::{ConnectedPolicyBridge, HtmlPolicyBridge};
use herness_html_sync::{
    AppliedEvaluation, AssessmentPlan, CheckSet, ConditionBinding, CoverageReport, DocumentKey,
    EvaluationBinding, EvidenceBuildInput, EvidenceCheckResult, EvidenceFingerprints,
    EvidenceOrigin, EvidencePack, EvidenceValidationError, GenerationId, MAX_DEFAULT_SLICE_BYTES,
    MAX_DEFAULT_SLICE_UNITS, RenderCandidateFingerprints, RenderConfigurationEvidence,
    RenderEvidence, RenderPngEvidence, RenderSignalEvidence, RequiredCheck, RequiredCheckKind,
    RubricSet, SliceAssessment, SourceRevision, SourceSnapshot, SourceUnits, StrictRequirement,
    UnitEvidence,
};
use herness_supervision::assessment::{
    AssessmentOutcome, AssessmentProvenance, AssessmentRequest, AssessmentResult, ConditionVerdict,
};
use herness_supervision::conditions::{ConditionDigest, ConditionVersion};
use herness_supervision::evidence::{EvidenceScope, TargetVersion};
use herness_supervision::ids::{ConditionId, DecisionId, EvidenceId, ProfileId, SupervisionId};
use herness_supervision::profiles::{
    AdapterVersion, ProfileBinding, ProfileInputs, ProfilePurpose, ProfileThresholds,
    ProfileVersion, RubricVersion,
};
use herness_supervision::{ContentDigest, ContentFingerprint, TargetScope};
use serde_json::{Value, json};
use tempfile::TempDir;
use uuid::Uuid;

/// Real pack root used by the repository's existing policy tests.
pub const REAL_PACK_ROOT: &str = "/Users/h-uma/Documents/sdd";
/// ADR Target used by the semantic-v1 fixture.
pub const TARGET_PATH: &str = "docs/adr/0001-queue-choice.md";

/// The real pack is optional; tests skip with a clear note when absent.
pub fn real_pack_present() -> bool {
    Path::new(REAL_PACK_ROOT)
        .join("scripts/html-docs")
        .is_file()
}

/// The repository's existing Python toolchain detection.
pub fn toolchain() -> herness_core::ToolchainConfig {
    herness_core::ToolchainConfig::from_environment()
        .with_html_docs_path(Path::new(REAL_PACK_ROOT).join("scripts/html-docs"))
        .expect("validator path")
}

/// A temporary project holding the semantic-v1 ADR fixture.
pub struct AdrFixture {
    _temp: TempDir,
    pub root: PathBuf,
    pub source: Vec<u8>,
    pub html: Vec<u8>,
}

impl AdrFixture {
    /// Copies the real pack's ADR fixture into a temporary project.
    pub fn new() -> Self {
        let temp = TempDir::new().expect("temporary project");
        let root = temp.path().join("project");
        fs::create_dir_all(root.join("docs/adr")).expect("adr directory");
        fs::create_dir_all(root.join("docs/sdd/assets")).expect("assets directory");
        let source =
            fs::read(Path::new(REAL_PACK_ROOT).join("tests/fixtures/adr/0001-queue-choice.md"))
                .expect("ADR source");
        let html =
            fs::read(Path::new(REAL_PACK_ROOT).join("tests/fixtures/adr/0001-queue-choice.html"))
                .expect("ADR candidate");
        fs::write(root.join(TARGET_PATH), &source).expect("write source");
        fs::write(root.join("docs/adr/0001-queue-choice.html"), &html).expect("write candidate");
        fs::write(
            root.join("docs/sdd/assets/sdd.css"),
            "body { color: #111; background: #fff; }\n",
        )
        .expect("write CSS");
        Self {
            _temp: temp,
            root,
            source,
            html,
        }
    }

    /// Candidate HTML as UTF-8.
    pub fn candidate_html(&self) -> &str {
        std::str::from_utf8(&self.html).expect("fixture candidate is UTF-8")
    }

    /// Exact source/candidate inputs for the host API.
    pub fn inputs(&self) -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([
            (TARGET_PATH.to_owned(), self.source.clone()),
            (
                "docs/adr/0001-queue-choice.html".to_owned(),
                self.html.clone(),
            ),
        ])
    }
}

/// Connects the real pack bridge to the fixture project.
pub fn connect_bridge(root: &Path) -> ConnectedPolicyBridge {
    let bridge = HtmlPolicyBridge::detect(root, REAL_PACK_ROOT, toolchain()).expect("detect pack");
    let binding = bridge.probe().approval_binding().expect("pack binding");
    bridge.connect(&binding).expect("connect real pack")
}

/// The project id used by the fixtures.
pub fn project() -> ProjectId {
    "33333333-3333-4333-8333-333333333333"
        .parse()
        .expect("project id")
}

/// A fixed timestamp.
pub fn now() -> Timestamp {
    Timestamp::from_unix_millis(1_700_000_000_000)
}

/// A document key for the fixture Target.
pub fn document_key() -> DocumentKey {
    document_key_for(project())
}

/// A document key for an explicit project.
pub fn document_key_for(project: ProjectId) -> DocumentKey {
    DocumentKey::new(project, TARGET_PATH).expect("document key")
}

/// Deterministic H2 supervision id.
pub fn supervision() -> SupervisionId {
    SupervisionId::from_parts(
        project(),
        Uuid::parse_str("70000000-0000-4000-8000-000000000001").expect("supervision uuid"),
    )
}

/// Deterministic H3 generation id.
pub fn generation() -> GenerationId {
    generation_for(project())
}

/// Deterministic H3 generation id for an explicit project.
pub fn generation_for(project: ProjectId) -> GenerationId {
    GenerationId::from_parts(
        project,
        Uuid::parse_str("50000000-0000-4000-8000-000000000011").expect("uuid"),
    )
}

/// Deterministic H3 cycle id.
pub fn cycle() -> herness_html_sync::CycleId {
    cycle_for(project())
}

/// Deterministic H3 cycle id for an explicit project.
pub fn cycle_for(project: ProjectId) -> herness_html_sync::CycleId {
    herness_html_sync::CycleId::from_parts(
        project,
        Uuid::parse_str("50000000-0000-4000-8000-000000000012").expect("uuid"),
    )
}

/// Four deterministic H2 condition ids in H3 order.
pub fn condition_binding() -> ConditionBinding {
    let seeds = [
        "60000000-0000-4000-8000-000000000001",
        "60000000-0000-4000-8000-000000000002",
        "60000000-0000-4000-8000-000000000003",
        "60000000-0000-4000-8000-000000000004",
    ];
    let conditions = seeds.map(|seed| {
        ConditionId::from_parts(project(), Uuid::parse_str(seed).expect("condition uuid"))
    });
    ConditionBinding::new(project(), conditions).expect("condition binding")
}

/// Condition version used by the fixtures.
pub fn condition_version() -> ConditionVersion {
    ConditionVersion::new(1).expect("condition version")
}

/// Condition digest used by the fixtures.
pub fn condition_digest() -> ConditionDigest {
    ConditionDigest::sha256(b"h3-condition-set-fixture")
}

/// Target version used by the fixtures.
pub fn target_version() -> TargetVersion {
    TargetVersion::new(1).expect("target version")
}

/// Html assessment profile binding used by the fixtures.
pub fn html_profile() -> ProfileBinding {
    ProfileBinding::new(
        ProfileId::new(project()),
        ProfileVersion::new(1).expect("profile version"),
        ProfilePurpose::Html,
    )
}

/// Source snapshot for the fixture bytes.
pub fn source_snapshot(source: &[u8]) -> SourceSnapshot {
    SourceSnapshot::new(
        SourceRevision::new(1).expect("source revision"),
        ContentDigest::sha256(source),
    )
}

/// Fingerprints bound to the exact fixture candidate and profile.
pub fn fingerprints(fixture: &AdrFixture) -> EvidenceFingerprints {
    fingerprints_with(fixture, html_profile(), condition_digest())
}

/// Fingerprints for an explicit Html profile and condition digest.
pub fn fingerprints_with(
    fixture: &AdrFixture,
    profile: ProfileBinding,
    condition_digest: ConditionDigest,
) -> EvidenceFingerprints {
    let css = ContentDigest::sha256(b"fixture-css");
    let resources = ContentDigest::sha256(b"fixture-resources");
    EvidenceFingerprints::new(
        ContentDigest::sha256(b"fixture-settings"),
        ContentDigest::sha256(b"fixture-policy"),
        ContentDigest::sha256(b"fixture-pack"),
        css,
        resources,
        ContentDigest::sha256(&fixture.html),
        ContentDigest::sha256(
            provenance_payload(std::str::from_utf8(&fixture.html).expect("html")).as_bytes(),
        ),
        ContentDigest::sha256(&fixture.source),
        RubricSet::approved().digest(),
        profile,
        condition_version(),
        condition_digest,
        target_version(),
    )
}

/// Required check scope used by the fixtures.
pub fn check_scope() -> EvidenceScope {
    EvidenceScope::new(
        vec![TARGET_PATH.to_owned()],
        vec!["fixture: no real provider or network request".to_owned()],
    )
    .expect("check scope")
}

/// Structural required check with an explicit result.
pub fn structural_check(status: EvidenceCheckResult) -> RequiredCheck {
    RequiredCheck::new(
        RequiredCheckKind::CommonStructural,
        status,
        EvidenceOrigin::PackPolicy,
        "sdd-html-host-api:source-units+candidate-check",
        "python -B scripts/html-docs host-api (structural candidate-check)",
        "fixture structural result",
        target_version(),
        check_scope(),
        None,
        now(),
    )
    .expect("structural check")
}

/// Render required check with an explicit distinguished origin.
pub fn render_check(origin: EvidenceOrigin) -> RequiredCheck {
    let status = if origin.is_native_render() {
        EvidenceCheckResult::Pass
    } else {
        EvidenceCheckResult::Inconclusive
    };
    RequiredCheck::new(
        RequiredCheckKind::RealRender,
        status,
        origin,
        if origin.is_native_render() {
            "h3-render-wkwebview"
        } else {
            "h3-render-fixture"
        },
        "fixture render",
        "fixture render result",
        target_version(),
        check_scope(),
        None,
        now(),
    )
    .expect("render check")
}

/// A structurally valid PNG fixture with the requested dimensions.
///
/// The assessment adapters only read PNG dimensions and require image data
/// and an end marker; this fixture supplies an IHDR, a marker IDAT, and IEND.
/// It is not a decodable photograph and is never presented as one.
fn png_bytes(id: &str, width: u32, height: u32) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut chunk = |kind: &[u8; 4], data: &[u8]| {
        bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&[0_u8; 4]);
    };
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(b"IHDR", &ihdr);
    chunk(b"IDAT", &[0_u8; 4]);
    chunk(b"tEXt", id.as_bytes());
    chunk(b"IEND", &[]);
    bytes
}

/// Render configurations and PNGs shaped like the Task 17 matrix.
fn render_matrix(
    html: &ContentDigest,
    css: &ContentDigest,
    resources: &ContentDigest,
) -> (
    Vec<RenderConfigurationEvidence>,
    Vec<RenderPngEvidence>,
    RenderCandidateFingerprints,
) {
    let candidates = [
        ("desktop-light", 1280, 800, "light", 1.0, 1280, 800),
        ("desktop-dark", 1280, 800, "dark", 1.0, 1280, 800),
        ("desktop-zoom-200", 1280, 800, "light", 2.0, 640, 400),
        ("desktop-zoom-200-dark", 1280, 800, "dark", 2.0, 640, 400),
        ("mobile-light", 390, 844, "light", 1.0, 390, 844),
        ("mobile-dark", 390, 844, "dark", 1.0, 390, 844),
        ("mobile-zoom-200", 390, 844, "light", 2.0, 195, 422),
        ("mobile-zoom-200-dark", 390, 844, "dark", 2.0, 195, 422),
    ];
    let dom = json!({
        "outline": {
            "headings": [
                {"level": 1, "text": "Queue choice", "selector": "#queue-choice"},
                {"level": 2, "text": "Decision", "selector": "#decision"}
            ],
            "landmarks": [
                {"tag": "main", "name": "", "selector": "main"},
                {"tag": "nav", "name": "On this page", "selector": "nav"}
            ]
        },
        "keyboard": {"tabOrder": ["#plan-link"]},
        "blocks": [
            {"selector": "header", "rect": {"y": 0.0}},
            {"selector": "main", "rect": {"y": 40.0}},
            {"selector": "h1", "rect": {"y": 48.0}},
            {"selector": "h2", "rect": {"y": 120.0}},
            {"selector": "footer", "rect": {"y": 400.0}}
        ]
    });
    let accessibility = json!({
        "source": "host-js-aria-snapshot-v1",
        "nodes": [{"role": "main"}, {"role": "heading", "level": 1}]
    });
    let mut configurations = Vec::new();
    let mut pngs = Vec::new();
    for (id, width, height, appearance, zoom, css_width, css_height) in candidates {
        let bytes = png_bytes(id, width * 2, height * 2);
        let path = format!("{id}.png");
        let digest = ContentDigest::sha256(&bytes);
        let png = RenderPngEvidence::new(path.clone(), bytes, width * 2, height * 2)
            .expect("fixture PNG");
        pngs.push(png);
        configurations.push(
            RenderConfigurationEvidence::new(
                id,
                width,
                height,
                appearance,
                zoom,
                css_width,
                css_height,
                path,
                digest,
                width * 2,
                height * 2,
                dom.clone(),
                accessibility.clone(),
            )
            .expect("render configuration"),
        );
    }
    let aggregate = ContentDigest::sha256(format!("{html}:{css}:{resources}").as_bytes());
    (
        configurations,
        pngs,
        RenderCandidateFingerprints::new(html.clone(), css.clone(), resources.clone(), aggregate),
    )
}

/// Synthetic render shaped like a native capture. The tests label it as a
/// fixture; it is not a real WKWebView run.
pub fn fixture_native_render(fixture: &AdrFixture) -> RenderEvidence {
    fixture_native_render_with_dependencies(
        fixture,
        ContentDigest::sha256(b"fixture-css"),
        ContentDigest::sha256(b"fixture-resources"),
    )
}

/// Native-shaped fixture bound to caller-computed CSS/resource digests.
///
/// This still reports synthetic PNG bytes and is never presented as a real
/// WKWebView capture.
pub fn fixture_native_render_with_dependencies(
    fixture: &AdrFixture,
    css: ContentDigest,
    resources: ContentDigest,
) -> RenderEvidence {
    let html = ContentDigest::sha256(&fixture.html);
    let (configurations, pngs, candidate) = render_matrix(&html, &css, &resources);
    RenderEvidence::native(
        "h3-render-manifest-v1",
        "wkwebview-native",
        "fixture-render-job-0001",
        true,
        configurations,
        "host-js-aria-snapshot-v1",
        69,
        fixture_signals(),
        true,
        true,
        false,
        candidate,
        pngs,
        0,
    )
    .expect("fixture native render shape")
}

/// Native-shaped fixture with an explicit accessibility source label.
pub fn fixture_native_render_with_accessibility_source(
    fixture: &AdrFixture,
    source: &str,
) -> Result<RenderEvidence, EvidenceValidationError> {
    let html = ContentDigest::sha256(&fixture.html);
    let css = ContentDigest::sha256(b"fixture-css");
    let resources = ContentDigest::sha256(b"fixture-resources");
    let (configurations, pngs, candidate) = render_matrix(&html, &css, &resources);
    RenderEvidence::native(
        "h3-render-manifest-v1",
        "wkwebview-native",
        "fixture-render-job-0001",
        true,
        configurations,
        source,
        69,
        fixture_signals(),
        true,
        true,
        false,
        candidate,
        pngs,
        0,
    )
}

/// Explicitly fake render evidence. It can never satisfy the real-render check.
pub fn fixture_fake_render(fixture: &AdrFixture) -> RenderEvidence {
    fake_render_with_long_edge(fixture, 2.0)
}

/// Fake render with smaller PNG dimensions so a Jev image limit can be
/// exercised without pretending the real render matrix was resized.
pub fn fixture_fake_render_compact(fixture: &AdrFixture) -> RenderEvidence {
    fake_render_with_long_edge(fixture, 0.5)
}

fn fake_render_with_long_edge(fixture: &AdrFixture, scale: f64) -> RenderEvidence {
    let html = ContentDigest::sha256(&fixture.html);
    let css = ContentDigest::sha256(b"fixture-css");
    let resources = ContentDigest::sha256(b"fixture-resources");
    let (mut configurations, mut pngs, candidate) = render_matrix(&html, &css, &resources);
    if scale < 1.0 {
        for (configuration, png) in configurations.iter_mut().zip(pngs.iter_mut()) {
            let width = (configuration.png_pixel_width() as f64 * scale)
                .round()
                .max(280.0) as u32;
            let height = (configuration.png_pixel_height() as f64 * scale)
                .round()
                .max(280.0) as u32;
            let id = configuration.id().to_owned();
            let path = configuration.png_path().to_owned();
            let bytes = png_bytes(&id, width, height);
            let digest = ContentDigest::sha256(&bytes);
            *configuration = RenderConfigurationEvidence::new(
                id.clone(),
                configuration.viewport_width(),
                configuration.viewport_height(),
                configuration.appearance(),
                configuration.page_zoom(),
                configuration.css_viewport_width(),
                configuration.css_viewport_height(),
                path.clone(),
                digest,
                width,
                height,
                configuration.dom().clone(),
                configuration.accessibility().clone(),
            )
            .expect("compact configuration");
            *png = RenderPngEvidence::new(path, bytes, width, height).expect("compact PNG");
        }
    }
    RenderEvidence::fake(
        EvidenceOrigin::Fake,
        true,
        configurations,
        "host-js-aria-snapshot-v1",
        fixture_signals(),
        candidate,
        pngs,
    )
    .expect("fixture fake render")
}

fn fixture_signals() -> RenderSignalEvidence {
    RenderSignalEvidence::new(false, 0, 0, 0, 14.0, 1.4, 0, 0, 0, 0, 69, 7)
}

/// Builds a complete evidence pack from the real pack response.
#[allow(clippy::too_many_arguments)]
pub fn build_pack(
    fixture: &AdrFixture,
    source_units: &SourceUnits,
    render: RenderEvidence,
    structural: RequiredCheck,
    render_check: RequiredCheck,
) -> Result<EvidencePack, EvidenceValidationError> {
    build_pack_with(
        fixture,
        source_units,
        render,
        structural,
        render_check,
        condition_binding(),
        condition_digest(),
        html_profile(),
        project(),
    )
}

/// Builds a pack for an explicit H2 condition binding and Html profile.
#[allow(clippy::too_many_arguments)]
pub fn build_pack_with(
    fixture: &AdrFixture,
    source_units: &SourceUnits,
    render: RenderEvidence,
    structural: RequiredCheck,
    render_check: RequiredCheck,
    conditions: ConditionBinding,
    condition_digest: ConditionDigest,
    profile: ProfileBinding,
    project: ProjectId,
) -> Result<EvidencePack, EvidenceValidationError> {
    let fingerprints = fingerprints_with(fixture, profile, condition_digest.clone());
    build_pack_with_fingerprints(
        fixture,
        source_units,
        render,
        structural,
        render_check,
        conditions,
        condition_digest,
        project,
        fingerprints,
    )
}

/// Builds a pack with caller-computed exact fingerprints. Publication tests use
/// this to bind the real on-disk CSS/resource digests rather than placeholders.
#[allow(clippy::too_many_arguments)]
pub fn build_pack_with_fingerprints(
    fixture: &AdrFixture,
    source_units: &SourceUnits,
    render: RenderEvidence,
    structural: RequiredCheck,
    render_check: RequiredCheck,
    conditions: ConditionBinding,
    condition_digest: ConditionDigest,
    project: ProjectId,
    fingerprints: EvidenceFingerprints,
) -> Result<EvidencePack, EvidenceValidationError> {
    let checks = CheckSet::new(vec![structural, render_check])?;
    let provenance_digest =
        ContentDigest::sha256(provenance_payload(fixture.candidate_html()).as_bytes());
    EvidencePack::build(EvidenceBuildInput {
        document: document_key_for(project),
        generation: generation_for(project),
        cycle: cycle_for(project),
        conditions,
        condition_version: condition_version(),
        condition_digest,
        target_version: target_version(),
        source: source_snapshot(&fixture.source),
        source_bytes: &fixture.source,
        candidate_html: fixture.candidate_html(),
        candidate_digest: ContentDigest::sha256(&fixture.html),
        provenance_digest,
        source_units,
        checks,
        render,
        fingerprints,
        created_at: now(),
    })
}

/// Applies an all-met, native-shaped fixture evaluation to one evidence pack.
///
/// The request/result pairs are synthetic host values, not provider calls. The
/// render evidence remains the native-shaped fixture supplied by the caller.
pub fn positive_evaluation(pack: &EvidencePack) -> AppliedEvaluation {
    let profile = pack.fingerprints().profile();
    let plan = AssessmentPlan::build(
        pack,
        &RubricSet::approved(),
        profile,
        ProfileInputs::text_with_optional_image(),
        ProfileThresholds::normal_llm(),
        MAX_DEFAULT_SLICE_UNITS,
        MAX_DEFAULT_SLICE_BYTES,
    )
    .expect("assessment plan");
    let adapter = AdapterVersion::new("fixture-adapter-v1").expect("adapter version");
    let rubric = RubricVersion::new(herness_html_sync::H3_RUBRIC_VERSION).expect("rubric version");
    let mut results = Vec::new();
    for (index, slice) in plan.slices().iter().enumerate() {
        if !plan.slice_is_sendable(slice) {
            continue;
        }
        let evidence = vec![evidence_id(200 + index as u64)];
        let request = AssessmentRequest::new(
            DecisionId::from_parts(
                project(),
                Uuid::from_u128(0x8000_0000_0000_4000_8000_0000_0000_0000 + index as u128),
            ),
            supervision(),
            pack.conditions().id(slice.condition()),
            pack.condition_version(),
            pack.target_version(),
            slice.rubric(),
            profile,
            adapter.clone(),
            rubric.clone(),
            evidence.clone(),
        )
        .expect("assessment request");
        let provenance = AssessmentProvenance::new(
            Provider::OpenAi,
            herness_supervision::ProviderKind::NormalLlm,
            ModelId::new("fixture-judge").expect("model id"),
            adapter.clone(),
            rubric.clone(),
        )
        .expect("provenance")
        .with_purpose(ProfilePurpose::Html);
        let result = AssessmentResult::new(
            &request,
            evidence,
            "fixture all-met result",
            None,
            AssessmentOutcome::NormalLlm {
                verdict: ConditionVerdict::Met,
                confidence: None,
            },
            provenance,
            now(),
        )
        .expect("assessment result");
        let scope = EvidenceScope::new(
            vec![format!("slice:{}", slice.id())],
            vec!["synthetic fixture; no provider request".to_owned()],
        )
        .expect("scope");
        results.push(
            SliceAssessment::from_result(
                slice,
                &request,
                &result,
                ProfileThresholds::normal_llm(),
                scope,
            )
            .expect("slice assessment"),
        );
    }
    let binding =
        EvaluationBinding::verification(pack.fingerprints().clone(), pack.fingerprints().clone())
            .with_assessment(pack.fingerprints().clone(), pack.fingerprints().clone());
    AppliedEvaluation::apply(&plan, results, binding, false, now()).expect("applied evaluation")
}

/// Extracts the exact non-executed provenance payload from the fixture.
pub fn provenance_payload(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let marker = "id=\"sdd-provenance\"";
    let id_position = lower.find(marker).expect("provenance id");
    let open_end = lower[id_position..]
        .find('>')
        .map(|offset| id_position + offset + 1)
        .expect("open");
    let close = lower[open_end..]
        .find("</template>")
        .map(|offset| open_end + offset)
        .expect("close");
    html[open_end..close].to_owned()
}

/// Parses the real pack's source units for one fixture.
pub fn source_units(bridge: &ConnectedPolicyBridge, fixture: &AdrFixture) -> SourceUnits {
    let value = bridge
        .source_units(TARGET_PATH, &fixture.inputs())
        .expect("source-units");
    SourceUnits::from_policy(&value).expect("parsed source units")
}

/// Runs the real structural candidate check.
pub fn structural_policy(
    bridge: &ConnectedPolicyBridge,
    fixture: &AdrFixture,
) -> herness_desktop::html_sync::policy::CandidateCheck {
    bridge
        .candidate_check(
            TARGET_PATH,
            herness_desktop::html_sync::policy::CandidateStage::Structural,
            None,
            &fixture.inputs(),
        )
        .expect("structural candidate-check")
}

/// A coverage report over every fixture unit.
pub fn coverage(units: &[UnitEvidence]) -> CoverageReport {
    let expected = units
        .iter()
        .map(|unit| unit.unit_id().to_owned())
        .collect::<Vec<_>>();
    CoverageReport::new(&expected, &expected).expect("coverage")
}

/// A condition-aware target scope for H2 evidence records.
pub fn target_scope(fingerprints: &EvidenceFingerprints) -> TargetScope {
    TargetScope::new(
        project(),
        target_version(),
        vec![TARGET_PATH.to_owned()],
        vec![
            ContentFingerprint::new(TARGET_PATH, fingerprints.source().clone())
                .expect("source fingerprint"),
        ],
    )
    .expect("target scope")
}

/// An evidence id for a test document.
pub fn evidence_id(seed: u64) -> EvidenceId {
    let mut bytes = [0_u8; 16];
    bytes[8..].copy_from_slice(&seed.to_be_bytes());
    EvidenceId::from_parts(project(), Uuid::from_bytes(bytes))
}

/// Strict requirements parsed from the real pack, when a test needs them.
pub fn strict_values(units: &SourceUnits) -> Vec<StrictRequirement> {
    units.strict().to_vec()
}

/// Convenience: a structural pass check and a fake render check.
pub fn pass_and_fake_checks() -> (RequiredCheck, RequiredCheck) {
    (
        structural_check(EvidenceCheckResult::Pass),
        render_check(EvidenceOrigin::Fake),
    )
}

/// Convenience: a structural pass check and a native-shaped render check.
pub fn pass_and_native_checks() -> (RequiredCheck, RequiredCheck) {
    (
        structural_check(EvidenceCheckResult::Pass),
        render_check(EvidenceOrigin::WkWebViewNative),
    )
}

/// A tiny HTML fixture for scanner tests.
pub fn scanner_fixture() -> &'static str {
    r##"<!doctype html><html><head><title>Hidden title</title></head><body>
<header><h1 id="top">Top</h1></header>
<nav><a href="#one">One</a></nav>
<main id="content">
<h2 id="one">One</h2>
<p id="para">Visible <code id="code">FIFO</code> text.</p>
<div hidden><p id="hidden-para">Hidden</p></div>
<aside><p id="aside-para">Aside</p></aside>
<template><p id="template-para">Template</p></template>
<figure id="fig"><figcaption>Caption</figcaption></figure>
</main></body></html>"##
}

/// Builds a render signal value for scanner tests.
pub fn signal_value() -> Value {
    json!({"pageHorizontalOverflow": false})
}
