//! OpenAI Decisions permission evaluator.
//!
//! The fixed `gpt-6-luna` model receives one `allow` / `deny` / `ask` choice
//! question. Its answer must report the fixed model, exactly one answer for the
//! derived question name, a complete ordered finite distribution over the three
//! choices, and a selected maximum choice. `allow`/`deny` are adopted only at
//! the profile's permission threshold (0.99 by default); the provider-native
//! confidence is validated separately and never used for adoption.

use herness_core::PermissionDecision;
use herness_core::contracts::{ModelId, TokenCount, TokenUsage};
use herness_supervision::assessment::{
    PermissionAssessment, PermissionProbabilities, PermissionVerdict,
};
use herness_supervision::profiles::H2_DISTRIBUTION_TOLERANCE;
use herness_supervision::profiles::ProfileEntry;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::decisions::DECISIONS_REQUEST_MODEL;
use crate::error::{AssessmentError, AssessmentErrorKind};
use crate::transport::{
    AssessmentRequest as TransportRequest, AssessmentTransport, TransportControl,
};

use super::PermissionQuestion;
use super::PermissionReply;
use super::jev::permission_thresholds;

const MAX_INPUT_BYTES: usize = 1_000_000;
const MAX_REQUEST_BYTES: usize = 1_200_000;
const PROBABILITY_VALUES: [&str; 3] = ["allow", "deny", "ask"];

/// Assesses one permission question through OpenAI Decisions.
pub(crate) fn assess(
    transport: &AssessmentTransport,
    entry: &ProfileEntry,
    question: &PermissionQuestion,
    control: TransportControl,
) -> Result<PermissionReply, AssessmentError> {
    let input = question.text();
    if input.len() > MAX_INPUT_BYTES {
        return Err(AssessmentError::new(AssessmentErrorKind::InputTooLarge));
    }
    let body = build(question, input)?;
    let request =
        TransportRequest::new(entry.profile().connection(), DECISIONS_REQUEST_MODEL, body)?;
    let response = transport.send(request, control)?;
    Ok(parse_response(
        response.body(),
        entry,
        &question.question_id(),
    ))
}

fn build(question: &PermissionQuestion, input: String) -> Result<Value, AssessmentError> {
    let body = json!({
        "model": DECISIONS_REQUEST_MODEL,
        "input": input,
        "questions": [{
            "type": "choice",
            "name": question.question_id(),
            "instructions": format!(
                "{}\nFrozen operation: {}\nTool: {}",
                PermissionQuestion::instructions(),
                question.operation_id(),
                question.tool(),
            ),
            "choices": [
                {
                    "value": "allow",
                    "description": "The frozen operation is within the requested work and permission boundary, and no material doubt remains.",
                },
                {
                    "value": "deny",
                    "description": "The frozen operation is outside the requested work or permission boundary, or is unsafe.",
                },
                {
                    "value": "ask",
                    "description": "The supplied information cannot decide, is contradictory, or leaves material doubt.",
                },
            ],
        }],
    });
    let encoded = serde_json::to_vec(&body)
        .map_err(|_| AssessmentError::new(AssessmentErrorKind::Internal))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(AssessmentError::new(AssessmentErrorKind::InputTooLarge));
    }
    Ok(body)
}

fn parse_response(body: &[u8], entry: &ProfileEntry, question_id: &str) -> PermissionReply {
    let unknown = PermissionReply::ask(TokenUsage::unknown(), None);
    let value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return unknown,
    };
    if value.get("error").is_some_and(|error| !error.is_null()) {
        return unknown;
    }
    let wire: WireResponse = match serde_json::from_slice(body) {
        Ok(wire) => wire,
        Err(_) => return unknown,
    };
    if wire.model.as_ref().and_then(Value::as_str) != Some(DECISIONS_REQUEST_MODEL) {
        return unknown;
    }
    if wire.answers.len() != 1 {
        return unknown;
    }
    let Some(answer) = wire.answers.first() else {
        return unknown;
    };
    if answer.name.as_ref().and_then(Value::as_str) != Some(question_id) {
        return unknown;
    }
    if answer.kind.as_ref().and_then(Value::as_str) != Some("choice") {
        return unknown;
    }
    let Some(selected) = answer
        .choice
        .as_ref()
        .and_then(Value::as_str)
        .and_then(parse_choice)
    else {
        return unknown;
    };
    if !valid_confidence(answer.confidence.as_ref()) {
        return unknown;
    }
    let Some(probabilities) = parse_probabilities(answer.probabilities.as_deref(), selected) else {
        return unknown;
    };
    let usage = parse_usage(&value);
    let reported_model = parse_reported_model(&value);
    let assessment = PermissionAssessment::Decision {
        selected,
        probabilities,
    };
    let decision = match assessment.adopted_verdict(permission_thresholds(entry)) {
        Some(PermissionVerdict::Allow) => PermissionDecision::Allow,
        Some(PermissionVerdict::Deny) => PermissionDecision::Deny,
        Some(PermissionVerdict::Ask) | None => PermissionDecision::Ask,
    };
    PermissionReply {
        decision,
        usage,
        reported_model,
    }
}

fn parse_choice(value: &str) -> Option<PermissionVerdict> {
    match value {
        "allow" => Some(PermissionVerdict::Allow),
        "deny" => Some(PermissionVerdict::Deny),
        "ask" => Some(PermissionVerdict::Ask),
        _ => None,
    }
}

fn valid_confidence(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_f64)
        .is_some_and(|value| value.is_finite() && (0.0..=1.0).contains(&value))
}

fn parse_probabilities(
    probabilities: Option<&[WireProbability]>,
    selected: PermissionVerdict,
) -> Option<PermissionProbabilities> {
    let items = probabilities?;
    if items.len() != PROBABILITY_VALUES.len() {
        return None;
    }
    let mut values = [0.0_f64; 3];
    for (index, item) in items.iter().enumerate() {
        let value = item.value.as_ref()?.as_str()?;
        if value != PROBABILITY_VALUES[index] {
            return None;
        }
        let probability = item.probability.as_ref()?.as_f64()?;
        if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
            return None;
        }
        values[index] = probability;
    }
    if (values.iter().sum::<f64>() - 1.0).abs() > H2_DISTRIBUTION_TOLERANCE {
        return None;
    }
    let probabilities = PermissionProbabilities::new(values[0], values[1], values[2]).ok()?;
    let selected_probability = probabilities.probability(selected);
    let maximum = probabilities
        .probability(PermissionVerdict::Allow)
        .max(probabilities.probability(PermissionVerdict::Deny))
        .max(probabilities.probability(PermissionVerdict::Ask));
    if selected_probability < maximum {
        return None;
    }
    Some(probabilities)
}

fn parse_usage(value: &Value) -> TokenUsage {
    let Some(usage) = value.get("usage").and_then(Value::as_object) else {
        return TokenUsage::unknown();
    };
    let (Some(input), Some(output)) = (
        usage.get("input_tokens").and_then(Value::as_u64),
        usage.get("output_tokens").and_then(Value::as_u64),
    ) else {
        return TokenUsage::unknown();
    };
    let details = usage.get("input_tokens_details").and_then(Value::as_object);
    let cached = details
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .map_or(TokenCount::unknown(), TokenCount::known);
    let cache_write = details
        .and_then(|details| details.get("cache_write_tokens"))
        .and_then(Value::as_u64)
        .map_or(TokenCount::unknown(), TokenCount::known);
    TokenUsage::new(
        TokenCount::known(input),
        TokenCount::known(output),
        cached,
        cache_write,
    )
}

fn parse_reported_model(value: &Value) -> Option<ModelId> {
    let model = value.get("model")?.as_str()?.trim();
    if model.is_empty() || model.chars().count() > 256 || model.chars().any(char::is_control) {
        return None;
    }
    ModelId::new(model).ok()
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    model: Option<Value>,
    #[serde(default)]
    answers: Vec<WireAnswer>,
}

#[derive(Deserialize)]
struct WireAnswer {
    #[serde(rename = "type", default)]
    kind: Option<Value>,
    #[serde(default)]
    name: Option<Value>,
    #[serde(default)]
    choice: Option<Value>,
    #[serde(default)]
    confidence: Option<Value>,
    #[serde(default)]
    probabilities: Option<Vec<WireProbability>>,
}

#[derive(Deserialize)]
struct WireProbability {
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    probability: Option<Value>,
}
