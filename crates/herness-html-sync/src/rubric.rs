//! Versioned H3 condition rubrics.
//!
//! The rubric text is sent to the H2 condition assessment transports together
//! with the exact evidence documents. It is a fixed, human-approved H3
//! artifact: the assessment layer never derives a rubric from model output and
//! never shortens one to fit a provider. A changed rubric changes
//! [`RubricSet::digest`] and therefore invalidates saved evidence.

use herness_supervision::ContentDigest;
use serde::{Deserialize, Serialize};

use crate::evidence::H3Condition;
use crate::version::{H3_FORMAT_VERSION, H3Record};

/// Versioned H3 rubric schema.
pub const H3_RUBRIC_SCHEMA: &str = "h3-html-rubric-v1";
/// Rubric version recorded with every Html assessment request.
pub const H3_RUBRIC_VERSION: &str = "h3-html-evaluation-v1";

/// One condition rubric and its evidence requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConditionRubric {
    condition: H3Condition,
    title: String,
    rubric: String,
    image_required: bool,
    required_evidence: Vec<String>,
}

impl ConditionRubric {
    /// Creates one fixed condition rubric.
    pub fn new(
        condition: H3Condition,
        title: impl Into<String>,
        rubric: impl Into<String>,
        image_required: bool,
        required_evidence: Vec<String>,
    ) -> Self {
        Self {
            condition,
            title: title.into(),
            rubric: rubric.into(),
            image_required,
            required_evidence,
        }
    }

    /// Logical H3 condition.
    pub const fn condition(&self) -> H3Condition {
        self.condition
    }

    /// Short human title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Exact rubric sent to the assessor.
    pub fn rubric(&self) -> &str {
        &self.rubric
    }

    /// Whether the condition needs approved render image bytes.
    pub const fn image_required(&self) -> bool {
        self.image_required
    }

    /// Evidence categories the assessor must receive.
    pub fn required_evidence(&self) -> &[String] {
        &self.required_evidence
    }
}

/// The fixed H3 rubric set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RubricSet {
    format_version: u32,
    schema: String,
    version: String,
    conditions: Vec<ConditionRubric>,
    document_consistency: String,
}

impl RubricSet {
    /// Returns the approved H3 rubric set.
    ///
    /// The texts deliberately repeat the "insufficient over guessing" rule so a
    /// text-only profile can never turn missing image or omitted-unit evidence
    /// into `met`.
    pub fn approved() -> Self {
        let conditions = vec![
            ConditionRubric::new(
                H3Condition::Information,
                "Source information and conditions are preserved",
                "Assess whether every supplied source unit's information, condition, \
                 exception, negation, scope, permission, failure result, dependency, and \
                 required execution order is preserved in the corresponding visible HTML \
                 and provenance mapping. The original prose may be paraphrased and moved. \
                 Exact code, commands, paths, identifiers, glossary canonical names and \
                 Avoid values, link destinations, numbers, units, comparison operators, and \
                 thresholds must remain exact. A summary may not replace source information. \
                 Information hidden in a template, aside, nav, or hidden element does not \
                 count. If any supplied unit is missing, duplicated, truncated, or its \
                 visible target cannot be resolved, choose insufficient. If a supplied unit \
                 is contradicted or a strict value changed, choose unmet. Cite the supplied \
                 evidence IDs that support the verdict.",
                false,
                vec![
                    "source unit full text and related context".to_owned(),
                    "corresponding visible HTML".to_owned(),
                    "provenance mapping and strict preservation targets".to_owned(),
                ],
            ),
            ConditionRubric::new(
                H3Condition::Support,
                "Supplementary summaries, diagrams, and graphs are supported",
                "Assess whether each supplied supplementary representation is supported by \
                 its declared source-unit roots and does not mix source-derived facts with \
                 unsupported additions. A diagram node, edge, label, causal claim, timeline, \
                 dependency, number, unit, series, or axis must be grounded in a declared \
                 unit. A caption, text equivalent, or data table must carry the essential \
                 information; a diagram alone may not hide required facts, and colour alone \
                 may not carry meaning. If the approved render images are missing, the \
                 connection cannot receive images, consent does not cover image bytes, or \
                 the evidence was truncated, choose insufficient rather than guessing from \
                 text alone. If a claim is unsupported or misstates a source value, choose \
                 unmet. Cite the supplied evidence IDs.",
                true,
                vec![
                    "supplementary entry with declared root units and sections".to_owned(),
                    "diagram or graph structure and its declared roots".to_owned(),
                    "caption, text equivalent, and data table".to_owned(),
                    "approved render images of the supplement".to_owned(),
                ],
            ),
            ConditionRubric::new(
                H3Condition::Usability,
                "The reconstruction is findable and usable",
                "Assess whether the document's whole-document navigation, heading hierarchy, \
                 landmarks, reading order, and visual presentation make the purpose, \
                 decisions, constraints, and operations easier to find than a flat \
                 sequence, without hiding information or adding decoration that competes \
                 with it. Use the supplied render images, layout signals, accessibility \
                 projection, and navigation facts together. Reading order must agree with \
                 visual order; headings must be distinguishable; keyboard focus must follow \
                 a usable order; overflow, overlap, and unreadable text are defects. If \
                 images or the accessibility projection are unavailable, or the evidence is \
                 truncated, choose insufficient. If the document hides required content or \
                 the reconstruction makes a required operation harder to find, choose \
                 unmet. Cite the supplied evidence IDs.",
                true,
                vec![
                    "whole-document heading, landmark, navigation, and reading-order facts"
                        .to_owned(),
                    "render layout signals for desktop, mobile, and 200% zoom".to_owned(),
                    "approved render images".to_owned(),
                    "accessibility projection labelled host-js-aria-snapshot-v1".to_owned(),
                ],
            ),
            ConditionRubric::new(
                H3Condition::Render,
                "The real rendered document is available",
                "Assess whether the supplied real render evidence shows a usable rendered \
                 document: the required desktop and mobile, light and dark, and 200% zoom \
                 captures are complete; no capture timed out or was partial; the layout has \
                 no page-level horizontal overflow, overlapping blocks, unreadable text, or \
                 failed required images; headings, tables, diagrams, and their captions are \
                 visible and distinguishable; and keyboard focus and landmarks are usable. \
                 The accessibility projection is a host-side ARIA snapshot \
                 (host-js-aria-snapshot-v1), not a native AX tree. A fake, stationary, \
                 missing, or partial render is insufficient, never met. Cite the supplied \
                 evidence IDs.",
                true,
                vec![
                    "real render manifest and configuration matrix".to_owned(),
                    "approved render image bytes and digests".to_owned(),
                    "layout and accessibility projection".to_owned(),
                ],
            ),
        ];
        Self {
            format_version: H3_FORMAT_VERSION,
            schema: H3_RUBRIC_SCHEMA.to_owned(),
            version: H3_RUBRIC_VERSION.to_owned(),
            conditions,
            document_consistency: "Assess the document as a whole after all condition evidence \
                 has been seen. Check that no source unit is contradicted by another section, \
                 that conditions, exceptions, negations, scope, permissions, and required \
                 orders are consistent across sections, that a summary or diagram does not \
                 overstate a source claim, and that terminology and numeric values agree \
                 throughout. This is a separate judgment over all condition evidence; it does \
                 not replace per-unit coverage. If any unit, condition evidence set, image, or \
                 mandatory check is missing or truncated, choose insufficient. If two visible \
                 sections contradict one another, choose unmet. Cite the supplied evidence IDs."
                .to_owned(),
        }
    }

    /// Format version.
    pub const fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Schema label.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Rubric version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Rubric for one logical condition.
    pub fn condition(&self, condition: H3Condition) -> Option<&ConditionRubric> {
        self.conditions
            .iter()
            .find(|rubric| rubric.condition == condition)
    }

    /// Whole-document consistency rubric.
    pub fn document_consistency(&self) -> &str {
        &self.document_consistency
    }

    /// Every condition rubric in fixed order.
    pub fn conditions(&self) -> &[ConditionRubric] {
        &self.conditions
    }

    /// Stable digest over the exact rubric content.
    pub fn digest(&self) -> ContentDigest {
        let bytes = serde_json::to_vec(self).expect("the rubric set is serializable");
        ContentDigest::sha256(&bytes)
    }
}

impl H3Record for RubricSet {
    const RECORD: &'static str = "H3 rubric set";

    fn format_version(&self) -> u32 {
        self.format_version
    }
}

/// Rubric text and version for one logical condition.
pub fn condition_rubric(condition: H3Condition) -> (String, bool) {
    let set = RubricSet::approved();
    let rubric = set
        .condition(condition)
        .expect("the approved rubric has every H3 condition");
    (rubric.rubric().to_owned(), rubric.image_required())
}
