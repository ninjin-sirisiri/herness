//! Desktop Html condition-assessment adapter.
//!
//! The adapter builds the versioned H3 assessment plan, records exact
//! content-carrying evidence records in the H2 store, and calls the existing
//! `HostAssessmentPort`. Purpose, profile, consent, budget, and model-request
//! recording remain the H2 port's responsibility and are not duplicated here.
//!
//! The four H3 conditions use the same H2 condition contract. A split
//! information evaluation still covers every source unit exactly once because
//! the plan is built from the evidence pack's exact-once coverage report.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use herness_core::Timestamp;
use herness_html_sync::{
    AppliedEvaluation, AssessmentPlan, AssessmentSlice, EvaluationBinding, EvidenceContentStore,
    EvidenceDocumentContent, EvidenceFingerprints, EvidencePack, H3_RUBRIC_VERSION, H3Condition,
    H3Error, MAX_DEFAULT_SLICE_BYTES, MAX_DEFAULT_SLICE_UNITS, RubricSet, SliceAssessment,
};
use herness_supervision::supervisor::ConditionAssessmentPort;
use herness_supervision::{
    AssessmentRequest, EvidenceAcquirer, EvidenceId, EvidenceOutcome, EvidenceRecord,
    EvidenceScope, EvidenceStorePort, ProfileBinding, ProfileInputs, ProfilePurpose,
    SupervisionError, SupervisionId, TargetScope, VerificationOperation,
};
use uuid::Uuid;

use crate::supervision::assessment::{AssessmentHost, HostAssessmentPort};
use crate::supervision::plan::ConfigStore;
use crate::supervision::store::StoreHandle;

static ASSESSMENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Desktop Html assessment host with an exact content-carrying evidence store.
pub struct HtmlAssessmentHost {
    store: StoreHandle,
    config: ConfigStore,
    port: HostAssessmentPort,
    content: EvidenceContentStore,
}

impl HtmlAssessmentHost {
    /// Creates the adapter over the shared store, configuration, and connection
    /// registry.
    pub fn new(store: StoreHandle, config: ConfigStore, host: AssessmentHost) -> Self {
        let content = EvidenceContentStore::new();
        let port = HostAssessmentPort::new(store.clone(), config.clone(), host)
            .with_evidence_content(Arc::new(content.clone()));
        Self {
            store,
            config,
            port,
            content,
        }
    }

    /// Resolves the exact input capabilities approved for one fixed profile.
    ///
    /// The H3 plan uses this so a text-only connection is never planned as
    /// image-bearing evidence. A missing or changed profile is explicit.
    pub fn profile_inputs(&self, profile: ProfileBinding) -> Result<ProfileInputs, H3Error> {
        let project = profile.profile_id().project_id();
        let config = self.config.get(project);
        let configured = config
            .profile(profile.purpose())
            .ok_or_else(|| H3Error::Unavailable {
                capability: "h3.assessment.profile".to_owned(),
                detail: format!("no {} profile is configured", profile.purpose().as_str()),
            })?;
        if configured.profile.binding() != profile {
            return Err(H3Error::Unavailable {
                capability: "h3.assessment.profile".to_owned(),
                detail: "the configured profile differs from the approved profile".to_owned(),
            });
        }
        let inputs = configured.profile.required_inputs();
        Ok(if inputs.supports_image() {
            ProfileInputs::text_with_optional_image()
        } else {
            ProfileInputs::text_only()
        })
    }

    /// Rehydrates persisted evidence content before a post-restart assessment.
    pub fn rehydrate_content(&self, store: &EvidenceContentStore) -> Result<(), H3Error> {
        self.content.merge(store).map_err(H3Error::from)
    }

    /// Exact content store shared with the H2 port.
    pub const fn content(&self) -> &EvidenceContentStore {
        &self.content
    }

    /// Builds the plan and runs the three H2 methods through the existing Html
    /// send gate.
    #[allow(clippy::too_many_arguments)]
    pub fn assess(
        &mut self,
        pack: &EvidencePack,
        rubrics: &RubricSet,
        profile: ProfileBinding,
        profile_inputs: ProfileInputs,
        supervision_id: SupervisionId,
        target: &TargetScope,
        verification_binding: EvaluationBinding,
        before_assessment: EvidenceFingerprints,
        after_assessment: &dyn Fn() -> Result<EvidenceFingerprints, H3Error>,
        allow_fake_render_for_tests: bool,
        now: Timestamp,
        sequence_base: u64,
    ) -> Result<AppliedEvaluation, H3Error> {
        target
            .ensure_project(pack.project_id())
            .map_err(|error| H3Error::invalid("assessment.target", error.to_string()))?;
        if target.version() != pack.target_version() {
            return Err(H3Error::invalid(
                "assessment.targetVersion",
                "the H2 evidence target version differs from the pack",
            ));
        }
        if !pack.checks().structural_pass() {
            return Err(H3Error::Unavailable {
                capability: "h3.assessment.structural".to_owned(),
                detail: "the common structural required check did not pass".to_owned(),
            });
        }
        if !pack.checks().render_present() {
            return Err(H3Error::Unavailable {
                capability: "h3.assessment.render".to_owned(),
                detail: "the real render required check is missing".to_owned(),
            });
        }
        if !pack.checks().render_pass() && !pack.checks().render_is_fake() {
            return Err(H3Error::Unavailable {
                capability: "h3.assessment.render".to_owned(),
                detail: "the real render did not pass and cannot support Html assessment"
                    .to_owned(),
            });
        }
        if pack.checks().render_is_fake() && !allow_fake_render_for_tests {
            return Err(H3Error::Unavailable {
                capability: "h3.assessment.render".to_owned(),
                detail: "a fake/stationary render cannot support Html assessment".to_owned(),
            });
        }
        if verification_binding.stale_stage().is_some() {
            return Err(H3Error::Unavailable {
                capability: "h3.assessment.binding".to_owned(),
                detail: "the verification binding is already stale".to_owned(),
            });
        }
        if verification_binding.post_verification() != &before_assessment {
            return Err(H3Error::Unavailable {
                capability: "h3.assessment.binding".to_owned(),
                detail: "assessment input does not match the verified fingerprints".to_owned(),
            });
        }
        if pack.fingerprints() != &before_assessment {
            return Err(H3Error::Unavailable {
                capability: "h3.assessment.binding".to_owned(),
                detail: "the evidence pack is bound to different fingerprints".to_owned(),
            });
        }
        let facts = self
            .port
            .profile(profile)
            .map_err(|error| assessment_error("profile", error))?;
        if facts.rubric_version().as_str() != H3_RUBRIC_VERSION {
            return Err(H3Error::Unavailable {
                capability: "h3.assessment.rubric".to_owned(),
                detail: format!(
                    "the Html profile rubric version {:?} differs from the H3 rubric {:?}",
                    facts.rubric_version().as_str(),
                    H3_RUBRIC_VERSION
                ),
            });
        }
        let plan = AssessmentPlan::build(
            pack,
            rubrics,
            profile,
            profile_inputs,
            facts.thresholds(),
            MAX_DEFAULT_SLICE_UNITS,
            MAX_DEFAULT_SLICE_BYTES,
        )
        .map_err(H3Error::from)?;

        let mut results = Vec::new();
        let attempt = ASSESSMENT_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let mut sequence = (now.as_unix_millis().saturating_mul(1_000_000))
            .saturating_add(attempt.saturating_mul(1_000))
            .saturating_add(sequence_base)
            .max(1);
        for (index, slice) in plan.slices().iter().enumerate() {
            if !plan.slice_is_sendable(slice) {
                continue;
            }
            if slice.image_required() && slice.images().is_empty() {
                // Defensive: the plan already classifies this as unsendable.
                continue;
            }
            let evidence_ids = self.record_slice_evidence(
                pack,
                slice,
                supervision_id,
                target,
                now,
                &mut sequence,
                index,
            )?;
            let request = AssessmentRequest::new(
                decision_id(pack, slice, index, &evidence_ids, now),
                supervision_id,
                pack.conditions().id(slice.condition()),
                pack.condition_version(),
                pack.target_version(),
                slice.rubric(),
                profile,
                facts.adapter_version().clone(),
                facts.rubric_version().clone(),
                evidence_ids,
            )
            .map_err(H3Error::from)?;
            let result = self
                .port
                .assess(&request)
                .map_err(|error| assessment_error("send", error))?;
            let scope = EvidenceScope::new(
                vec![
                    format!("condition:{}", slice.condition()),
                    format!("slice:{}", slice.id()),
                    format!("units:{}", slice.unit_ids().len()),
                ],
                vec![
                    "one Html condition assessment; no repository or tool access".to_owned(),
                    "the model sees only the supplied evidence documents".to_owned(),
                ],
            )
            .map_err(H3Error::from)?;
            results.push(
                SliceAssessment::from_result(slice, &request, &result, facts.thresholds(), scope)
                    .map_err(H3Error::from)?,
            );
        }
        let after = after_assessment()?;
        let binding = verification_binding.with_assessment(before_assessment, after);
        AppliedEvaluation::apply(&plan, results, binding, allow_fake_render_for_tests, now)
            .map_err(H3Error::from)
    }

    #[allow(clippy::too_many_arguments)]
    fn record_slice_evidence(
        &mut self,
        pack: &EvidencePack,
        slice: &AssessmentSlice,
        supervision_id: SupervisionId,
        target: &TargetScope,
        now: Timestamp,
        sequence: &mut u64,
        slice_index: usize,
    ) -> Result<Vec<EvidenceId>, H3Error> {
        let project = pack.project_id();
        let mut ids = Vec::new();
        let mut index = 0usize;
        let mut push = |content: EvidenceDocumentContent,
                        ids: &mut Vec<EvidenceId>,
                        sequence: &mut u64|
         -> Result<(), H3Error> {
            let evidence_id = content.evidence_id();
            self.content.insert(content).map_err(H3Error::from)?;
            let record = EvidenceRecord::new(
                evidence_id,
                supervision_id,
                Some(pack.conditions().id(slice.condition())),
                None,
                EvidenceAcquirer::Ci,
                VerificationOperation::equivalent(format!(
                    "h3 html evidence pack {} / slice {} / document {}",
                    pack.candidate_digest(),
                    slice.id(),
                    index
                ))
                .map_err(H3Error::from)?,
                EvidenceOutcome::new(
                    None,
                    None,
                    false,
                    false,
                    format!(
                        "exact evidence content recorded; slice={} units={}",
                        slice.id(),
                        slice.unit_ids().len()
                    ),
                )
                .map_err(H3Error::from)?,
                target.clone(),
                EvidenceScope::new(
                    vec![
                        format!("condition:{}", slice.condition()),
                        format!("slice:{}", slice.id()),
                    ],
                    vec!["content is carried by the H3 evidence store".to_owned()],
                )
                .map_err(H3Error::from)?,
                herness_supervision::CheckStatus::Pass,
                *sequence,
                now,
            )
            .map_err(H3Error::from)?;
            self.store
                .append(record)
                .map_err(|error| assessment_error("evidence", error))?;
            *sequence = (*sequence).saturating_add(1);
            ids.push(evidence_id);
            index += 1;
            Ok(())
        };

        let text_id = evidence_id(
            project,
            pack.generation(),
            slice.condition(),
            slice.id(),
            slice_index,
            0,
            "text",
            herness_supervision::ContentDigest::sha256(slice.text().as_bytes()).as_str(),
            now.as_unix_millis(),
        );
        let text = EvidenceDocumentContent::text(text_id, slice.text()).map_err(H3Error::from)?;
        push(text, &mut ids, sequence)?;

        for (image_index, image) in slice.images().iter().enumerate() {
            let digest = herness_supervision::ContentDigest::sha256(image.bytes());
            let image_id = evidence_id(
                project,
                pack.generation(),
                slice.condition(),
                slice.id(),
                slice_index,
                image_index + 1,
                "image",
                digest.as_str(),
                now.as_unix_millis(),
            );
            let document = EvidenceDocumentContent::image(
                image_id,
                image.media_type(),
                image.bytes().to_vec(),
            )
            .map_err(H3Error::from)?;
            push(document, &mut ids, sequence)?;
        }
        Ok(ids)
    }
}

#[allow(clippy::too_many_arguments)]
fn evidence_id(
    project: herness_core::ProjectId,
    generation: herness_html_sync::GenerationId,
    condition: H3Condition,
    slice_id: &str,
    slice_index: usize,
    part_index: usize,
    kind: &str,
    digest: &str,
    attempt: u64,
) -> EvidenceId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"h3-html-assessment-evidence\0");
    hasher.update(project.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(generation.local_id().as_bytes());
    hasher.update(b"\0");
    hasher.update(condition.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(slice_id.as_bytes());
    hasher.update(b"\0");
    hasher.update((slice_index as u64).to_le_bytes());
    hasher.update((part_index as u64).to_le_bytes());
    hasher.update(b"\0");
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(digest.as_bytes());
    hasher.update(b"\0");
    hasher.update(attempt.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EvidenceId::from_parts(project, Uuid::from_bytes(bytes))
}

fn decision_id(
    pack: &EvidencePack,
    slice: &AssessmentSlice,
    index: usize,
    evidence_ids: &[EvidenceId],
    attempt: Timestamp,
) -> herness_supervision::DecisionId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"h3-html-assessment-request\0");
    hasher.update(pack.project_id().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(pack.generation().local_id().as_bytes());
    hasher.update(b"\0");
    hasher.update(slice.condition().as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(slice.id().as_bytes());
    hasher.update(b"\0");
    hasher.update((index as u64).to_le_bytes());
    hasher.update(attempt.as_unix_millis().to_le_bytes());
    for evidence in evidence_ids {
        hasher.update(evidence.to_string().as_bytes());
        hasher.update(b"\0");
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    herness_supervision::DecisionId::from_parts(pack.project_id(), Uuid::from_bytes(bytes))
}

fn assessment_error(stage: &str, error: SupervisionError) -> H3Error {
    H3Error::Unavailable {
        capability: format!("h3.assessment.{stage}"),
        detail: error.to_string(),
    }
}

/// The purpose used by every H3 condition assessment.
pub const HTML_ASSESSMENT_PURPOSE: ProfilePurpose = ProfilePurpose::Html;
