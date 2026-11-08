//! Jev System One permission evaluator.
//!
//! The fixed `jev-1.14.0` model receives one `allow` / `deny` / `ask` choice
//! question. A usable answer needs the exact model, exactly one answer for the
//! derived question name, a complete finite distribution over the three
//! choices, a sum within the H2 tolerance, and a selected maximum choice.
//! `allow`/`deny` are adopted only at the profile's permission threshold
//! (0.99 by default); native confidence is validated and retained separately,
//! never used for adoption.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use herness_core::PermissionDecision;
use herness_core::contracts::{ModelId, TokenCount, TokenUsage};
use herness_supervision::assessment::{
    PermissionAssessment, PermissionProbabilities, PermissionVerdict,
};
use herness_supervision::profiles::ProfileEntry;
use herness_supervision::profiles::{
    H2_DISTRIBUTION_TOLERANCE, H2_PERMISSION_ALLOW_THRESHOLD, H2_PERMISSION_DENY_THRESHOLD,
    ProfileThresholds,
};
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde_json::{Value, json};

use crate::error::{AssessmentError, AssessmentErrorKind};
use crate::jev::JEV_REQUEST_MODEL;
use crate::transport::{
    AssessmentRequest as TransportRequest, AssessmentTransport, TransportControl,
};

use super::PermissionQuestion;
use super::PermissionReply;

const MAX_REQUEST_TEXT_BYTES: usize = 24_000;
const MAX_REQUEST_BYTES: usize = 32_000;

/// Assesses one permission question through Jev System One.
pub(crate) fn assess(
    transport: &AssessmentTransport,
    entry: &ProfileEntry,
    question: &PermissionQuestion,
    control: TransportControl,
) -> Result<PermissionReply, AssessmentError> {
    let text = question.text();
    if text.len() > MAX_REQUEST_TEXT_BYTES {
        return Err(AssessmentError::new(AssessmentErrorKind::InputTooLarge));
    }
    let body = build(question)?;
    let request = TransportRequest::new(entry.profile().connection(), JEV_REQUEST_MODEL, body)?;
    let response = transport.send(request, control)?;
    Ok(parse_response(
        response.body(),
        entry,
        &question.question_id(),
    ))
}

fn build(question: &PermissionQuestion) -> Result<Value, AssessmentError> {
    let mut questions = serde_json::Map::new();
    questions.insert(
        question.question_id(),
        json!({
            "type": "choice",
            "instructions": format!(
                "{}\nFrozen operation: {}\nTool: {}",
                PermissionQuestion::instructions(),
                question.operation_id(),
                question.tool(),
            ),
            "criteria": {
                "allow": "The frozen operation is within the requested work and permission boundary, and no material doubt remains.",
                "deny": "The frozen operation is outside the requested work or permission boundary, or is unsafe.",
                "ask": "The supplied information cannot decide, is contradictory, or leaves material doubt.",
            },
        }),
    );
    let body = json!({
        "model": JEV_REQUEST_MODEL,
        "state": {
            "operation": question.payload(),
        },
        "questions": Value::Object(questions),
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
    if wire.model.as_ref().and_then(Value::as_str) != Some(JEV_REQUEST_MODEL) {
        return unknown;
    }
    if wire.answers.len() != 1 {
        return unknown;
    }
    let Some((name, answer)) = wire.answers.iter().next() else {
        return unknown;
    };
    if name != question_id {
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
    let Some(probabilities) = parse_probabilities(&answer.probabilities, selected) else {
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

/// The H2 permission floor is 0.99. A profile may raise the threshold but not
/// lower it for a Decision provider.
pub(crate) fn permission_thresholds(entry: &ProfileEntry) -> ProfileThresholds {
    let configured = entry.profile().thresholds();
    let allow = configured
        .permission_allow()
        .unwrap_or(H2_PERMISSION_ALLOW_THRESHOLD)
        .max(H2_PERMISSION_ALLOW_THRESHOLD);
    let deny = configured
        .permission_deny()
        .unwrap_or(H2_PERMISSION_DENY_THRESHOLD)
        .max(H2_PERMISSION_DENY_THRESHOLD);
    ProfileThresholds::new(
        None,
        None,
        Some(allow),
        Some(deny),
        H2_DISTRIBUTION_TOLERANCE,
    )
    .expect("effective permission thresholds are valid")
}

fn valid_confidence(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_f64)
        .is_some_and(|value| value.is_finite() && (0.0..=1.0).contains(&value))
}

fn parse_probabilities(
    probabilities: &BTreeMap<String, Value>,
    selected: PermissionVerdict,
) -> Option<PermissionProbabilities> {
    const KEYS: [&str; 3] = ["allow", "deny", "ask"];
    if probabilities.len() != KEYS.len() || KEYS.iter().any(|key| !probabilities.contains_key(*key))
    {
        return None;
    }
    let mut values = [0.0_f64; 3];
    for (index, key) in KEYS.iter().enumerate() {
        let value = probabilities.get(*key)?.as_f64()?;
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return None;
        }
        values[index] = value;
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
    TokenUsage::new(
        TokenCount::known(input),
        TokenCount::known(output),
        TokenCount::unknown(),
        TokenCount::unknown(),
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
    #[serde(default, deserialize_with = "deserialize_answers")]
    answers: BTreeMap<String, WireAnswer>,
}

#[derive(Deserialize)]
struct WireAnswer {
    #[serde(rename = "type", default)]
    kind: Option<Value>,
    #[serde(default)]
    choice: Option<Value>,
    #[serde(default)]
    confidence: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_probabilities")]
    probabilities: BTreeMap<String, Value>,
}

fn deserialize_answers<'de, D>(deserializer: D) -> Result<BTreeMap<String, WireAnswer>, D::Error>
where
    D: Deserializer<'de>,
{
    strict_map(deserializer, "answer")
}

fn deserialize_probabilities<'de, D>(deserializer: D) -> Result<BTreeMap<String, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    strict_map(deserializer, "probability")
}

/// Deserializes a JSON object while rejecting duplicate keys.
fn strict_map<'de, D, T>(
    deserializer: D,
    label: &'static str,
) -> Result<BTreeMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct StrictMapVisitor<T> {
        label: &'static str,
        marker: PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> Visitor<'de> for StrictMapVisitor<T> {
        type Value = BTreeMap<String, T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "an object with unique {} keys", self.label)
        }

        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            let mut map = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, T>()? {
                if map.insert(key, value).is_some() {
                    return Err(de::Error::custom(format!("duplicate {} key", self.label)));
                }
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(StrictMapVisitor {
        label,
        marker: PhantomData,
    })
}
