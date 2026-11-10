//! Task 18 evidence coverage and mandatory-check tests.
//!
//! The real Common SDD pack is used read-only. Render captures in these tests
//! are synthetic and explicitly marked fake or native-shaped fixtures; they are
//! not a claim that a real WKWebView ran.

#![cfg(unix)]

mod support;

use herness_html_sync::{
    EvidenceCheckResult, EvidenceOrigin, EvidenceValidationError, H3Condition,
    HOST_JS_ACCESSIBILITY_SOURCE,
};
use support::*;

#[test]
fn real_pack_evidence_covers_every_unit_once() {
    if !real_pack_present() {
        eprintln!("skip real pack evidence test: pack absent");
        return;
    }
    let fixture = AdrFixture::new();
    let bridge = connect_bridge(&fixture.root);
    let units = source_units(&bridge, &fixture);
    assert_eq!(units.status(), "complete");
    assert!(units.unsupported().is_empty());
    assert_eq!(units.units().len(), 6);
    let check = structural_policy(&bridge, &fixture);
    assert_eq!(check.stage(), "structural");
    assert!(!check.final_pass());
    assert!(!check.final_binding());
    assert_eq!(check.contract(), "semantic-v1");

    let pack = build_pack(
        &fixture,
        &units,
        fixture_fake_render(&fixture),
        structural_check(EvidenceCheckResult::Pass),
        render_check(EvidenceOrigin::Fake),
    )
    .expect("evidence pack");
    pack.validate().expect("valid pack");
    assert_eq!(pack.coverage().expected_units().len(), 6);
    assert_eq!(pack.coverage().covered_units().len(), 6);
    assert_eq!(pack.information().len(), 6);
    assert_eq!(pack.consistency().unit_ids().len(), 6);
    for unit in pack.information() {
        assert!(
            units
                .units()
                .iter()
                .any(|source| source.id() == unit.unit_id()),
            "unit {} came from the fresh scan",
            unit.unit_id()
        );
        assert!(!unit.text().is_empty(), "full unit text is retained");
        assert!(!unit.targets().is_empty(), "unit maps to visible HTML");
        for target in unit.targets() {
            assert!(pack.visible_targets().contains_key(target));
        }
        assert!(!unit.related_context().is_empty());
    }
    assert!(pack.strict().iter().all(|strict| strict.preserved()));
    assert!(pack.usability().outline_valid());
    assert_eq!(
        pack.render().accessibility_source(),
        HOST_JS_ACCESSIBILITY_SOURCE
    );
    assert!(!pack.checks().render_pass(), "a fake render cannot pass");
    assert!(!pack.native_render_available());
}

#[test]
fn native_shaped_fixture_requires_the_exact_matrix_and_never_claims_native_ax() {
    let fixture = AdrFixture::new();
    let render = fixture_native_render(&fixture);
    render.validate_native().expect("native-shaped fixture");
    assert_eq!(render.configurations().len(), 8);
    assert_eq!(render.accessibility_source(), HOST_JS_ACCESSIBILITY_SOURCE);
    assert!(render.images().len() >= 8);
}

#[test]
fn scanner_excludes_hidden_aside_template_and_nav_content() {
    let scanned = herness_html_sync::ScannedHtml::scan(scanner_fixture());
    assert!(scanned.target("para").is_some());
    assert!(scanned.target("code").is_some());
    assert!(scanned.target("fig").is_some());
    assert!(scanned.target("hidden-para").is_none());
    assert!(scanned.target("aside-para").is_none());
    assert!(scanned.target("template-para").is_none());
    assert!(scanned.hidden_targets().contains("hidden-para"));
    assert!(scanned.hidden_targets().contains("aside-para"));
    assert!(scanned.hidden_targets().contains("template-para"));
    assert!(scanned.visible_text().contains("Visible FIFO text."));
    assert!(!scanned.visible_text().contains("Hidden"));
    assert!(!scanned.visible_text().contains("Aside"));
    assert_eq!(scanned.headings().len(), 1);
    assert_eq!(scanned.headings()[0].text(), "One");
    assert_eq!(scanned.navigation_targets(), &["#one".to_owned()]);
}

#[test]
fn omitted_mapping_is_rejected_before_assessment() {
    if !real_pack_present() {
        eprintln!("skip real pack evidence test: pack absent");
        return;
    }
    let fixture = AdrFixture::new();
    let bridge = connect_bridge(&fixture.root);
    let units = source_units(&bridge, &fixture);
    let html = fixture.candidate_html().replace(
        r#"{"unit": "paragraph-000016", "representation": "paraphrase", "targets": ["summary"]}, "#,
        "",
    );
    let mut changed = AdrFixture::new();
    changed.html = html.into_bytes();
    let error = build_pack(
        &changed,
        &units,
        fixture_fake_render(&changed),
        structural_check(EvidenceCheckResult::Pass),
        render_check(EvidenceOrigin::Fake),
    )
    .expect_err("an omitted mapping must not produce evidence");
    assert!(
        matches!(error, EvidenceValidationError::UnitMissing { .. }),
        "{error:?}"
    );
}

#[test]
fn hidden_target_is_rejected_before_assessment() {
    if !real_pack_present() {
        eprintln!("skip real pack evidence test: pack absent");
        return;
    }
    let fixture = AdrFixture::new();
    let bridge = connect_bridge(&fixture.root);
    let units = source_units(&bridge, &fixture);
    let html = fixture
        .candidate_html()
        .replace(r#"<p id="summary">"#, r#"<div hidden><p id="summary">"#);
    let html = html.replace(
        r#"the limit is at most 2 MiB.</p>"#,
        r#"the limit is at most 2 MiB.</p></div>"#,
    );
    let mut changed = AdrFixture::new();
    changed.html = html.into_bytes();
    let error = build_pack(
        &changed,
        &units,
        fixture_fake_render(&changed),
        structural_check(EvidenceCheckResult::Pass),
        render_check(EvidenceOrigin::Fake),
    )
    .expect_err("hidden content must not produce evidence");
    assert!(
        matches!(
            error,
            EvidenceValidationError::TargetHidden { .. }
                | EvidenceValidationError::TargetMissing { .. }
        ),
        "{error:?}"
    );
}

#[test]
fn fake_render_cannot_satisfy_the_real_render_check() {
    let fixture = AdrFixture::new();
    let error = herness_html_sync::RequiredCheck::new(
        herness_html_sync::RequiredCheckKind::RealRender,
        EvidenceCheckResult::Pass,
        EvidenceOrigin::Fake,
        "fixture",
        "fixture",
        "fake pass",
        target_version(),
        check_scope(),
        None,
        now(),
    )
    .expect_err("fake pass must be rejected");
    assert_eq!(error, EvidenceValidationError::FakeRender);
    let fake = fixture_fake_render(&fixture);
    assert!(!fake.origin().is_native_render());
    assert!(fake.validate_native().is_err());
}

#[test]
fn split_evaluation_rejects_missing_duplicate_and_extraneous_units() {
    let expected = (0..6)
        .map(|index| format!("unit-{index}"))
        .collect::<Vec<_>>();
    let split = herness_html_sync::EvaluationSplit::contiguous(&expected, 2).expect("split");
    split.validate(&expected).expect("valid split");
    assert_eq!(split.parts().len(), 3);

    let missing =
        herness_html_sync::EvaluationSplit::contiguous(&expected[..5], 2).expect("partial split");
    assert!(matches!(
        missing.validate(&expected),
        Err(EvidenceValidationError::UnitMissing { .. })
    ));

    let mut duplicated = expected.clone();
    duplicated.push(expected[0].clone());
    assert!(matches!(
        herness_html_sync::CoverageReport::new(&expected, &duplicated),
        Err(EvidenceValidationError::UnitDuplicate { .. })
    ));

    let mut extraneous = expected.clone();
    extraneous.push("unit-unknown".to_owned());
    assert!(matches!(
        herness_html_sync::CoverageReport::new(&expected, &extraneous),
        Err(EvidenceValidationError::UnitExtraneous { .. })
    ));
}

#[test]
fn condition_identities_are_distinct_and_ordered() {
    let binding = condition_binding();
    assert_eq!(binding.ids().len(), 4);
    assert_eq!(binding.id(H3Condition::Information), binding.ids()[0]);
    assert_eq!(binding.id(H3Condition::Support), binding.ids()[1]);
    assert_eq!(binding.id(H3Condition::Usability), binding.ids()[2]);
    assert_eq!(binding.id(H3Condition::Render), binding.ids()[3]);
    assert_eq!(
        binding.condition_for(binding.id(H3Condition::Usability)),
        Some(H3Condition::Usability)
    );
}

#[test]
fn host_js_accessibility_cannot_be_relabelled_as_native_ax() {
    let fixture = AdrFixture::new();
    let error = fixture_native_render_with_accessibility_source(&fixture, "native-ax-tree")
        .expect_err("native AX must not be claimed from the host projection");
    assert_eq!(error, EvidenceValidationError::NativeAccessibilityClaim);
}

#[test]
fn desktop_verification_calls_the_real_pack_bridge_and_records_an_unavailable_render() {
    if !real_pack_present() {
        eprintln!("skip real pack evidence test: pack absent");
        return;
    }
    use herness_desktop::html_sync::verification::{
        CandidateVerificationRequest, FingerprintCapture, verify_candidate,
    };

    struct Capture(herness_html_sync::EvidenceFingerprints);
    impl FingerprintCapture for Capture {
        fn capture(
            &self,
        ) -> Result<herness_html_sync::EvidenceFingerprints, herness_html_sync::H3Error> {
            Ok(self.0.clone())
        }
    }

    let fixture = AdrFixture::new();
    let bridge = connect_bridge(&fixture.root);
    let conditions = condition_binding();
    let profile = html_profile();
    let fingerprints = fingerprints(&fixture);
    let request = CandidateVerificationRequest {
        document: document_key(),
        generation: generation(),
        cycle: cycle(),
        conditions,
        condition_version: condition_version(),
        condition_digest: condition_digest(),
        target_version: target_version(),
        source: source_snapshot(&fixture.source),
        source_bytes: &fixture.source,
        candidate_html: fixture.candidate_html(),
        candidate_digest: herness_supervision::ContentDigest::sha256(&fixture.html),
        provenance_digest: herness_supervision::ContentDigest::sha256(
            provenance_payload(fixture.candidate_html()).as_bytes(),
        ),
        css_digest: fingerprints.css().clone(),
        render_css_digest: herness_supervision::ContentDigest::sha256(b"fixture-css"),
        resources_digest: fingerprints.resources().clone(),
        settings_digest: fingerprints.settings().clone(),
        policy_digest: fingerprints.policy().clone(),
        pack_digest: fingerprints.pack().clone(),
        rubric_digest: fingerprints.rubric().clone(),
        profile,
        inputs: &fixture.inputs(),
        structural_evidence_id: None,
        render_evidence_id: None,
        check_scope: check_scope(),
        created_at: now(),
    };
    let verification =
        verify_candidate(&bridge, &request, None, &Capture(fingerprints)).expect("verification");
    assert!(verification.checks.structural_pass());
    assert!(!verification.checks.render_pass());
    assert_eq!(
        verification
            .checks
            .get(herness_html_sync::RequiredCheckKind::RealRender)
            .expect("render check")
            .status(),
        EvidenceCheckResult::Unavailable
    );
    assert!(verification.source_units.is_some());
    assert!(verification.pack.is_none());
    assert!(!verification.is_usable());
}
