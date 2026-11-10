//! Desktop verification adapter for H3 candidate evidence.
//!
//! The adapter calls the real Common SDD policy bridge (`source-units` and a
//! structural `candidate-check`) and converts the real Task 17 render evidence
//! into the versioned H3 evidence shape. It never treats a structural pass as a
//! final pass, never repairs a denial, and never accepts a fake/stationary
//! render as a native pass.

use std::collections::BTreeMap;

use herness_core::Timestamp;
use herness_html_sync::ids::CycleId;
use herness_html_sync::{
    CheckSet, ConditionBinding, DocumentKey, EvaluationBinding, EvidenceBuildInput,
    EvidenceCheckResult, EvidenceFingerprints, EvidenceOrigin, EvidencePack,
    EvidenceValidationError, GenerationId, H3Condition, H3Error, RenderCandidateFingerprints,
    RenderConfigurationEvidence, RenderEvidence, RenderPngEvidence, RenderSignalEvidence,
    RequiredCheck, RequiredCheckKind, SourceSnapshot, SourceUnits,
};
use herness_supervision::ContentDigest;
use herness_supervision::conditions::{ConditionDigest, ConditionVersion};
use herness_supervision::evidence::{EvidenceScope, TargetVersion};
use herness_supervision::ids::EvidenceId;
use herness_supervision::profiles::{ProfileBinding, RubricVersion};
use serde_json::Value;

use crate::html_sync::policy::{CandidateCheck, CandidateDecision, CandidateStage};
use crate::html_sync::render::{RENDER_MANIFEST_VERSION, RenderEvidence as NativeRenderEvidence};

/// Summary of the exact structural policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCheckSummary {
    /// Allow or deny.
    pub decision: CandidateDecision,
    /// Supplied stage.
    pub stage: String,
    /// Whether the pack claimed a final pass. Structural must be false.
    pub final_pass: bool,
    /// Whether final receipt/input binding was checked.
    pub final_binding: bool,
    /// Declared contract.
    pub contract: String,
    /// Violation codes and messages.
    pub violations: Vec<(String, String)>,
    /// Warning codes and messages.
    pub warnings: Vec<(String, String)>,
    /// Exact source/candidate/receipt digests.
    pub digests: Value,
    /// Exact per-input digests.
    pub input_digests: Value,
    /// Pack message.
    pub message: String,
}

impl PolicyCheckSummary {
    fn from_check(check: &CandidateCheck) -> Self {
        Self {
            decision: check.decision(),
            stage: check.stage().to_owned(),
            final_pass: check.final_pass(),
            final_binding: check.final_binding(),
            contract: check.contract().to_owned(),
            violations: check
                .violations()
                .iter()
                .map(|finding| (finding.code().to_owned(), finding.message().to_owned()))
                .collect(),
            warnings: check
                .warnings()
                .iter()
                .map(|finding| (finding.code().to_owned(), finding.message().to_owned()))
                .collect(),
            digests: check.digests().clone(),
            input_digests: check.input_digests().clone(),
            message: check.message().to_owned(),
        }
    }
}

/// Exact inputs for one candidate verification.
pub struct CandidateVerificationRequest<'a> {
    /// Document key.
    pub document: DocumentKey,
    /// Generation id.
    pub generation: GenerationId,
    /// Cycle id.
    pub cycle: CycleId,
    /// Four condition identities.
    pub conditions: ConditionBinding,
    /// Condition version.
    pub condition_version: ConditionVersion,
    /// Condition digest.
    pub condition_digest: ConditionDigest,
    /// Target version.
    pub target_version: TargetVersion,
    /// Exact source snapshot.
    pub source: SourceSnapshot,
    /// Exact source bytes.
    pub source_bytes: &'a [u8],
    /// Exact candidate HTML.
    pub candidate_html: &'a str,
    /// Exact candidate digest.
    pub candidate_digest: ContentDigest,
    /// Exact provenance digest.
    pub provenance_digest: ContentDigest,
    /// Exact shared CSS dependency fingerprint used by the H3 evidence pack.
    pub css_digest: ContentDigest,
    /// Exact shared CSS byte digest bound by the real render manifest. The H3
    /// dependency fingerprint covers the path and kind, while the render binds
    /// the exact CSS bytes; they are not interchangeable.
    pub render_css_digest: ContentDigest,
    /// Exact resource-set digest.
    pub resources_digest: ContentDigest,
    /// Exact settings digest.
    pub settings_digest: ContentDigest,
    /// Exact policy digest.
    pub policy_digest: ContentDigest,
    /// Exact pack digest.
    pub pack_digest: ContentDigest,
    /// Exact rubric digest.
    pub rubric_digest: ContentDigest,
    /// Fixed Html assessment profile.
    pub profile: ProfileBinding,
    /// Exact inputs keyed by canonical relative path. It must contain the
    /// source, candidate, shared CSS, and every declared resource.
    pub inputs: &'a BTreeMap<String, Vec<u8>>,
    /// Structural evidence id, when already recorded.
    pub structural_evidence_id: Option<EvidenceId>,
    /// Render evidence id, when already recorded.
    pub render_evidence_id: Option<EvidenceId>,
    /// Scope recorded for both required checks.
    pub check_scope: EvidenceScope,
    /// Build time.
    pub created_at: Timestamp,
}

/// Result of one candidate verification attempt.
#[derive(Debug, Clone)]
pub struct CandidateVerification {
    /// Exact mandatory checks. Both kinds are always present.
    pub checks: CheckSet,
    /// Parsed source units, when the pack returned a complete scan.
    pub source_units: Option<SourceUnits>,
    /// Structural policy report, when the pack answered.
    pub policy_check: Option<PolicyCheckSummary>,
    /// Built evidence pack, when all mandatory inputs were usable.
    pub pack: Option<EvidencePack>,
    /// Fingerprints before and after verification.
    pub binding: Option<EvaluationBinding>,
    /// The first explicit failure. A failed check is retained in `checks`.
    pub failure: Option<EvidenceValidationError>,
}

impl CandidateVerification {
    /// Whether this verification may be used for assessment.
    pub fn is_usable(&self) -> bool {
        self.failure.is_none()
            && self.pack.is_some()
            && self.checks.all_pass()
            && self
                .binding
                .as_ref()
                .is_some_and(EvaluationBinding::is_current)
    }
}

/// Captures the exact current fingerprints. The caller owns the workspace and
/// must fail rather than guess when an input is unreadable.
pub trait FingerprintCapture {
    /// Captures the current exact fingerprint set.
    fn capture(&self) -> Result<EvidenceFingerprints, H3Error>;
}

/// Runs the real structural policy bridge and converts a real render into the
/// complete H3 evidence pack.
pub fn verify_candidate(
    bridge: &crate::html_sync::policy::ConnectedPolicyBridge,
    request: &CandidateVerificationRequest<'_>,
    render: Option<&NativeRenderEvidence>,
    capture: &dyn FingerprintCapture,
) -> Result<CandidateVerification, H3Error> {
    let before = capture.capture()?;
    let (structural, source_units, policy_check) = match run_structural(bridge, request) {
        Ok((source_units, check)) => {
            let pass = check.decision == CandidateDecision::Allow
                && check.stage == "structural"
                && !check.final_pass
                && !check.final_binding
                && check.contract == "semantic-v1";
            let status = if pass {
                EvidenceCheckResult::Pass
            } else {
                EvidenceCheckResult::Fail
            };
            let result = if pass {
                "structural allow; explicitly not a final pass".to_owned()
            } else {
                format!(
                    "structural {} with {} violations; contract={} final={}",
                    if check.decision == CandidateDecision::Allow {
                        "allow without a semantic-v1 structural contract"
                    } else {
                        "deny"
                    },
                    check.violations.len(),
                    check.contract,
                    check.final_pass
                )
            };
            let check_record = RequiredCheck::new(
                RequiredCheckKind::CommonStructural,
                status,
                EvidenceOrigin::PackPolicy,
                "sdd-html-host-api:source-units+candidate-check",
                "python -B scripts/html-docs host-api (structural candidate-check)",
                result,
                request.target_version,
                request.check_scope.clone(),
                request.structural_evidence_id,
                request.created_at,
            )
            .map_err(H3Error::from)?;
            (check_record, Some(source_units), Some(check))
        }
        Err(error) => {
            let check_record = RequiredCheck::new(
                RequiredCheckKind::CommonStructural,
                EvidenceCheckResult::Unavailable,
                EvidenceOrigin::PackPolicy,
                "sdd-html-host-api:source-units+candidate-check",
                "python -B scripts/html-docs host-api (structural candidate-check)",
                format!("the real pack bridge failed: {error}"),
                request.target_version,
                request.check_scope.clone(),
                request.structural_evidence_id,
                request.created_at,
            )
            .map_err(H3Error::from)?;
            (check_record, None, None)
        }
    };

    let (render_check, render_facts) = render_check(render, request)?;
    let checks = CheckSet::new(vec![structural, render_check]).map_err(H3Error::from)?;
    let after = capture.capture()?;
    let binding = EvaluationBinding::verification(before.clone(), after);

    let Some(source_units) = source_units else {
        return Ok(CandidateVerification {
            checks,
            source_units: None,
            policy_check,
            pack: None,
            binding: Some(binding),
            failure: None,
        });
    };
    let Some(render_facts) = render_facts else {
        return Ok(CandidateVerification {
            checks,
            source_units: Some(source_units),
            policy_check,
            pack: None,
            binding: Some(binding),
            failure: None,
        });
    };
    if !checks.structural_pass() {
        return Ok(CandidateVerification {
            checks,
            source_units: Some(source_units),
            policy_check,
            pack: None,
            binding: Some(binding),
            failure: Some(EvidenceValidationError::RequiredCheckNotPass {
                check: "common-structural",
                status: "fail",
            }),
        });
    }
    if !checks.render_pass() {
        let status = checks
            .get(RequiredCheckKind::RealRender)
            .map(|check| check.status().as_str())
            .unwrap_or("missing");
        return Ok(CandidateVerification {
            checks,
            source_units: Some(source_units),
            policy_check,
            pack: None,
            binding: Some(binding),
            failure: Some(EvidenceValidationError::RequiredCheckNotPass {
                check: "real-render",
                status,
            }),
        });
    }

    let fingerprints = before.clone();
    if fingerprints.candidate() != &request.candidate_digest
        || fingerprints.source() != request.source.digest()
        || fingerprints.provenance() != &request.provenance_digest
        || fingerprints.css() != &request.css_digest
        || fingerprints.resources() != &request.resources_digest
        || fingerprints.settings() != &request.settings_digest
        || fingerprints.policy() != &request.policy_digest
        || fingerprints.pack() != &request.pack_digest
        || fingerprints.rubric() != &request.rubric_digest
        || fingerprints.profile() != request.profile
        || fingerprints.condition_version() != request.condition_version
        || fingerprints.condition_digest() != &request.condition_digest
        || fingerprints.target_version() != request.target_version
    {
        return Ok(CandidateVerification {
            checks,
            source_units: Some(source_units),
            policy_check,
            pack: None,
            binding: Some(binding),
            failure: Some(EvidenceValidationError::StaleEvidence {
                stage: "fingerprint-capture",
            }),
        });
    }
    let pack_result = EvidencePack::build(EvidenceBuildInput {
        document: request.document.clone(),
        generation: request.generation,
        cycle: request.cycle,
        conditions: request.conditions.clone(),
        condition_version: request.condition_version,
        condition_digest: request.condition_digest.clone(),
        target_version: request.target_version,
        source: request.source.clone(),
        source_bytes: request.source_bytes,
        candidate_html: request.candidate_html,
        candidate_digest: request.candidate_digest.clone(),
        provenance_digest: request.provenance_digest.clone(),
        source_units: &source_units,
        checks: checks.clone(),
        render: render_facts,
        fingerprints,
        created_at: request.created_at,
    });
    match pack_result {
        Ok(pack) => {
            let stale = !binding.is_current();
            Ok(CandidateVerification {
                checks,
                source_units: Some(source_units),
                policy_check,
                pack: Some(pack),
                binding: Some(binding),
                failure: stale.then_some(EvidenceValidationError::StaleEvidence {
                    stage: "verification",
                }),
            })
        }
        Err(error) => Ok(CandidateVerification {
            checks,
            source_units: Some(source_units),
            policy_check,
            pack: None,
            binding: Some(binding),
            failure: Some(error),
        }),
    }
}

fn run_structural(
    bridge: &crate::html_sync::policy::ConnectedPolicyBridge,
    request: &CandidateVerificationRequest<'_>,
) -> Result<(SourceUnits, PolicyCheckSummary), crate::html_sync::policy::PolicyBridgeError> {
    let path = request.document.target_path();
    let units = bridge.source_units(path, request.inputs)?;
    let source_units = SourceUnits::from_policy(&units).map_err(|error| {
        crate::html_sync::policy::PolicyBridgeError::InvalidMetadata {
            detail: error.to_string(),
        }
    })?;
    let check = bridge.candidate_check(path, CandidateStage::Structural, None, request.inputs)?;
    let summary = PolicyCheckSummary::from_check(&check);
    if !source_units.status().eq("complete") || !source_units.unsupported().is_empty() {
        return Err(
            crate::html_sync::policy::PolicyBridgeError::InvalidMetadata {
                detail: "source-units was not a complete supported scan".to_owned(),
            },
        );
    }
    Ok((source_units, summary))
}

fn render_check(
    render: Option<&NativeRenderEvidence>,
    request: &CandidateVerificationRequest<'_>,
) -> Result<(RequiredCheck, Option<RenderEvidence>), H3Error> {
    let Some(render) = render else {
        let check = RequiredCheck::new(
            RequiredCheckKind::RealRender,
            EvidenceCheckResult::Unavailable,
            EvidenceOrigin::WkWebViewNative,
            "h3-render-wkwebview",
            "render_candidate (non-privileged WKWebView)",
            "no real render evidence was captured".to_owned(),
            request.target_version,
            request.check_scope.clone(),
            request.render_evidence_id,
            request.created_at,
        )
        .map_err(H3Error::from)?;
        return Ok((check, None));
    };
    match render_facts(render, request) {
        Ok(facts) => {
            let check = RequiredCheck::new(
                RequiredCheckKind::RealRender,
                EvidenceCheckResult::Pass,
                EvidenceOrigin::WkWebViewNative,
                "h3-render-wkwebview",
                "render_candidate (non-privileged WKWebView, 8 configurations)",
                format!(
                    "complete native render with {} configurations; accessibility={}",
                    facts.configurations().len(),
                    facts.accessibility_source()
                ),
                request.target_version,
                request.check_scope.clone(),
                request.render_evidence_id,
                request.created_at,
            )
            .map_err(H3Error::from)?;
            Ok((check, Some(facts)))
        }
        Err(error) => {
            let check = RequiredCheck::new(
                RequiredCheckKind::RealRender,
                if matches!(
                    error,
                    EvidenceValidationError::FakeRender
                        | EvidenceValidationError::NativeAccessibilityClaim
                ) {
                    EvidenceCheckResult::Inconclusive
                } else {
                    EvidenceCheckResult::Fail
                },
                EvidenceOrigin::WkWebViewNative,
                "h3-render-wkwebview",
                "render_candidate (non-privileged WKWebView, 8 configurations)",
                format!("render evidence was rejected: {error}"),
                request.target_version,
                request.check_scope.clone(),
                request.render_evidence_id,
                request.created_at,
            )
            .map_err(H3Error::from)?;
            Ok((check, None))
        }
    }
}

/// Converts the real Task 17 render evidence into the versioned H3 shape.
pub fn render_facts(
    render: &NativeRenderEvidence,
    request: &CandidateVerificationRequest<'_>,
) -> Result<RenderEvidence, EvidenceValidationError> {
    render
        .validate()
        .map_err(|error| EvidenceValidationError::IncompleteRender {
            detail: error.to_string(),
        })?;
    let manifest = render.manifest();
    if manifest.manifest_version != RENDER_MANIFEST_VERSION {
        return Err(EvidenceValidationError::IncompleteRender {
            detail: "unexpected render manifest version".to_owned(),
        });
    }
    if manifest.candidate.html_sha256 != request.candidate_digest
        || manifest.candidate.css_sha256 != request.render_css_digest
        || manifest.candidate.resources_sha256 != request.resources_digest
    {
        return Err(EvidenceValidationError::RenderFingerprintMismatch { field: "candidate" });
    }
    let mut configurations = Vec::with_capacity(manifest.configurations.len());
    let mut pngs = Vec::with_capacity(render.pngs().len());
    let mut accessibility_source = None;
    for configuration in &manifest.configurations {
        let png = render
            .pngs()
            .iter()
            .find(|png| png.path() == configuration.png.path)
            .ok_or_else(|| EvidenceValidationError::IncompleteRender {
                detail: format!("PNG {:?} is missing", configuration.png.path),
            })?;
        if accessibility_source.is_none() {
            accessibility_source = configuration
                .accessibility
                .get("source")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        configurations.push(RenderConfigurationEvidence::new(
            configuration.id.clone(),
            configuration.viewport.width,
            configuration.viewport.height,
            configuration.appearance.as_str(),
            configuration.page_zoom,
            configuration.css_viewport.inner_width,
            configuration.css_viewport.inner_height,
            configuration.png.path.clone(),
            configuration.png.sha256.clone(),
            configuration.png.pixel_width,
            configuration.png.pixel_height,
            configuration.dom.clone(),
            configuration.accessibility.clone(),
        )?);
        pngs.push(RenderPngEvidence::new(
            png.path().to_owned(),
            png.bytes().to_vec(),
            png.pixel_width(),
            png.pixel_height(),
        )?);
    }
    let accessibility_source =
        accessibility_source.ok_or_else(|| EvidenceValidationError::IncompleteRender {
            detail: "the render has no accessibility source label".to_owned(),
        })?;
    if accessibility_source != herness_html_sync::HOST_JS_ACCESSIBILITY_SOURCE {
        return Err(EvidenceValidationError::NativeAccessibilityClaim);
    }
    let primary = manifest
        .configurations
        .iter()
        .find(|configuration| configuration.id == "desktop-light")
        .or_else(|| manifest.configurations.first())
        .ok_or_else(|| EvidenceValidationError::IncompleteRender {
            detail: "the render has no configurations".to_owned(),
        })?;
    let signals = aggregate_signals(&manifest.configurations);
    RenderEvidence::native(
        manifest.manifest_version.clone(),
        manifest.evidence_source.clone(),
        manifest.job_id.clone(),
        manifest.is_complete(),
        configurations,
        accessibility_source,
        manifest
            .configurations
            .iter()
            .map(|configuration| configuration.signals.aria_nodes)
            .max()
            .unwrap_or(primary.signals.aria_nodes),
        signals,
        manifest.hidden_window.capture_succeeded_while_hidden
            && !manifest.hidden_window.visible_to_user,
        manifest.isolation.is_isolated(),
        manifest.browser.tauri_ipc_injected,
        RenderCandidateFingerprints::new(
            request.candidate_digest.clone(),
            request.css_digest.clone(),
            request.resources_digest.clone(),
            manifest.candidate.candidate_sha256.clone(),
        ),
        pngs,
        manifest.started_at_unix_ms,
    )
}

fn aggregate_signals(
    configurations: &[crate::html_sync::render::ConfigurationEvidence],
) -> RenderSignalEvidence {
    let signals = configurations
        .iter()
        .map(|configuration| &configuration.signals)
        .collect::<Vec<_>>();
    if signals.is_empty() {
        return RenderSignalEvidence::new(false, 0, 0, 0, 0.0, 0.0, 0, 0, 0, 0, 0, 0);
    }
    let min_nonzero = |values: Vec<f64>| {
        values
            .into_iter()
            .filter(|value| *value > 0.0)
            .fold(f64::INFINITY, f64::min)
    };
    RenderSignalEvidence::new(
        signals.iter().any(|signal| signal.page_horizontal_overflow),
        signals
            .iter()
            .map(|signal| signal.overflowing_elements)
            .max()
            .unwrap_or(0),
        signals
            .iter()
            .map(|signal| signal.overlapping_blocks)
            .max()
            .unwrap_or(0),
        signals
            .iter()
            .map(|signal| signal.readability_failures)
            .max()
            .unwrap_or(0),
        min_nonzero(
            signals
                .iter()
                .map(|signal| signal.min_font_size_px)
                .collect(),
        ),
        min_nonzero(
            signals
                .iter()
                .map(|signal| signal.min_line_height_ratio)
                .collect(),
        ),
        signals
            .iter()
            .map(|signal| signal.small_text_elements)
            .max()
            .unwrap_or(0),
        signals
            .iter()
            .map(|signal| signal.contrast_failures)
            .max()
            .unwrap_or(0),
        signals
            .iter()
            .map(|signal| signal.failed_images)
            .max()
            .unwrap_or(0),
        signals
            .iter()
            .map(|signal| signal.svg_elements)
            .max()
            .unwrap_or(0),
        signals
            .iter()
            .map(|signal| signal.aria_nodes)
            .max()
            .unwrap_or(0),
        signals
            .iter()
            .map(|signal| signal.headings)
            .max()
            .unwrap_or(0),
    )
}

/// The H3 condition order used by the desktop adapter.
pub const CONDITION_ORDER: [H3Condition; 4] = H3Condition::ALL;

/// A fixed rubric version for callers that do not have the rubric set yet.
pub fn default_rubric_version() -> Result<RubricVersion, H3Error> {
    RubricVersion::new(herness_html_sync::H3_RUBRIC_VERSION)
        .map_err(|error| H3Error::invalid("rubricVersion", error.to_string()))
}
