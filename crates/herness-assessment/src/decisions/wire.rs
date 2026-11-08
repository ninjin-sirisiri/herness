//! Strict parsing and validation of an OpenAI Decisions choice response.
//!
//! A response is usable only when the reported model is the fixed requested
//! model, the `answers` array contains exactly one answer for the derived
//! question name, the answer type is `choice`, the selected choice is one of the
//! three supplied values, the probability array contains exactly those three
//! values once each in the supplied order, the sum is within the H2 tolerance,
//! the selected choice is the maximum-probability choice, and the native
//! confidence is finite in `0..=1`. Every failure is mapped to an `insufficient`
//! result, never to `met` or `unmet`.

use std::collections::BTreeSet;
use std::fmt;

use herness_supervision::assessment::{ConditionProbabilities, ConditionVerdict, NativeConfidence};
use herness_supervision::profiles::H2_DISTRIBUTION_TOLERANCE;
use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::Value;

use super::{
    DECISIONS_CONFIDENCE_SCALE, DECISIONS_REQUEST_MODEL, DecisionsRejection, DecisionsUsage,
};

const MAX_MODEL_CHARS: usize = 256;
const PROBABILITY_VALUES: [&str; 3] = ["met", "unmet", "insufficient"];

/// One parsed response, including metadata that remains useful when the choice
/// is rejected.
pub(crate) struct ParsedResponse {
    pub(crate) choice: Result<ParsedChoice, DecisionsRejection>,
    pub(crate) confidence: Option<NativeConfidence>,
    pub(crate) usage: Option<DecisionsUsage>,
    pub(crate) reported_model: Option<String>,
}

/// A validated choice and complete distribution.
#[derive(Debug)]
pub(crate) struct ParsedChoice {
    pub(crate) selected: ConditionVerdict,
    pub(crate) probabilities: ConditionProbabilities,
}

/// Parses one Decisions response body.
pub(crate) fn parse_response(body: &[u8], question_id: &str) -> ParsedResponse {
    let value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return rejected(DecisionsRejection::InvalidJson, None, None, None),
    };
    let usage = parse_usage(&value);
    let reported_model = parse_reported_model(&value);
    if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
        let reason = if error_is_refusal(error) {
            DecisionsRejection::Refusal
        } else {
            DecisionsRejection::ProviderFailure
        };
        return rejected(reason, None, usage, reported_model);
    }

    let wire: WireResponse = match serde_json::from_slice(body) {
        Ok(wire) => wire,
        Err(_) => {
            return rejected(
                DecisionsRejection::SchemaViolation,
                None,
                usage,
                reported_model,
            );
        }
    };

    match wire.model.as_ref().and_then(Value::as_str) {
        Some(model) if model == DECISIONS_REQUEST_MODEL => {}
        _ => {
            return rejected(
                DecisionsRejection::ModelMismatch,
                None,
                usage,
                reported_model,
            );
        }
    }

    let answers = match wire.answers {
        Some(answers) => answers,
        None => {
            return rejected(
                DecisionsRejection::MissingAnswer,
                None,
                usage,
                reported_model,
            );
        }
    };
    if answers.is_empty() {
        return rejected(
            DecisionsRejection::MissingAnswer,
            None,
            usage,
            reported_model,
        );
    }

    let mut names = BTreeSet::new();
    for answer in &answers {
        let Some(name) = answer.name.as_ref().and_then(Value::as_str) else {
            return rejected(
                DecisionsRejection::UnknownAnswer,
                None,
                usage,
                reported_model,
            );
        };
        if !names.insert(name.to_owned()) {
            return rejected(
                DecisionsRejection::DuplicateAnswer,
                None,
                usage,
                reported_model,
            );
        }
    }
    if answers.len() != 1 {
        return rejected(
            DecisionsRejection::UnknownAnswer,
            None,
            usage,
            reported_model,
        );
    }
    let answer = &answers[0];
    if answer.name.as_ref().and_then(Value::as_str) != Some(question_id) {
        return rejected(
            DecisionsRejection::UnknownAnswer,
            None,
            usage,
            reported_model,
        );
    }

    match answer.kind.as_ref().and_then(Value::as_str) {
        Some("choice") => {}
        Some("refusal") => {
            return rejected(DecisionsRejection::Refusal, None, usage, reported_model);
        }
        _ => {
            return rejected(
                DecisionsRejection::WrongAnswerType,
                None,
                usage,
                reported_model,
            );
        }
    }

    let confidence = match parse_confidence(answer.confidence.as_ref()) {
        Ok(confidence) => confidence,
        Err(reason) => return rejected(reason, None, usage, reported_model),
    };

    let selected = match answer
        .choice
        .as_ref()
        .and_then(Value::as_str)
        .and_then(parse_choice)
    {
        Some(selected) => selected,
        None => {
            return rejected(
                DecisionsRejection::InvalidChoice,
                Some(confidence),
                usage,
                reported_model,
            );
        }
    };
    let probabilities = match parse_probabilities(answer.probabilities.as_deref(), selected) {
        Ok(probabilities) => probabilities,
        Err(reason) => {
            return rejected(reason, Some(confidence), usage, reported_model);
        }
    };
    ParsedResponse {
        choice: Ok(ParsedChoice {
            selected,
            probabilities,
        }),
        confidence: Some(confidence),
        usage,
        reported_model,
    }
}

fn rejected(
    reason: DecisionsRejection,
    confidence: Option<NativeConfidence>,
    usage: Option<DecisionsUsage>,
    reported_model: Option<String>,
) -> ParsedResponse {
    ParsedResponse {
        choice: Err(reason),
        confidence,
        usage,
        reported_model,
    }
}

fn parse_choice(value: &str) -> Option<ConditionVerdict> {
    match value {
        "met" => Some(ConditionVerdict::Met),
        "unmet" => Some(ConditionVerdict::Unmet),
        "insufficient" => Some(ConditionVerdict::Insufficient),
        _ => None,
    }
}

fn parse_confidence(value: Option<&Value>) -> Result<NativeConfidence, DecisionsRejection> {
    let value = value
        .and_then(Value::as_f64)
        .ok_or(DecisionsRejection::InvalidConfidence)?;
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(DecisionsRejection::InvalidConfidence);
    }
    NativeConfidence::new(value, DECISIONS_CONFIDENCE_SCALE)
        .map_err(|_| DecisionsRejection::InvalidConfidence)
}

fn parse_probabilities(
    probabilities: Option<&[WireProbability]>,
    selected: ConditionVerdict,
) -> Result<ConditionProbabilities, DecisionsRejection> {
    let Some(items) = probabilities else {
        return Err(DecisionsRejection::MissingProbabilities);
    };
    if items.len() < PROBABILITY_VALUES.len() {
        return Err(DecisionsRejection::MissingProbabilities);
    }
    if items.len() > PROBABILITY_VALUES.len() {
        return Err(DecisionsRejection::ExtraProbabilities);
    }

    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        let value = item
            .value
            .as_ref()
            .and_then(Value::as_str)
            .ok_or(DecisionsRejection::ExtraProbabilities)?;
        let probability = item
            .probability
            .as_ref()
            .and_then(Value::as_f64)
            .ok_or(DecisionsRejection::InvalidProbability)?;
        if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
            return Err(DecisionsRejection::InvalidProbability);
        }
        entries.push((value.to_owned(), probability));
    }

    let mut seen = BTreeSet::new();
    for (value, _) in &entries {
        if !seen.insert(value.clone()) {
            return Err(DecisionsRejection::DuplicateProbability);
        }
    }
    if entries
        .iter()
        .any(|(value, _)| !PROBABILITY_VALUES.contains(&value.as_str()))
    {
        return Err(DecisionsRejection::ExtraProbabilities);
    }
    let values: Vec<&str> = entries.iter().map(|(value, _)| value.as_str()).collect();
    if values.as_slice() != PROBABILITY_VALUES.as_slice() {
        return Err(DecisionsRejection::ReorderedProbabilities);
    }

    let sum = entries
        .iter()
        .map(|(_, probability)| probability)
        .sum::<f64>();
    if (sum - 1.0).abs() > H2_DISTRIBUTION_TOLERANCE {
        return Err(DecisionsRejection::ProbabilitySum);
    }
    let probabilities = ConditionProbabilities::new(entries[0].1, entries[1].1, entries[2].1)
        .map_err(|_| DecisionsRejection::InvalidProbability)?;
    let selected_probability = probabilities.probability(selected);
    let maximum = probabilities
        .met()
        .max(probabilities.unmet())
        .max(probabilities.insufficient());
    if selected_probability < maximum {
        return Err(DecisionsRejection::SelectionNotMaximum);
    }
    Ok(probabilities)
}

fn parse_usage(value: &Value) -> Option<DecisionsUsage> {
    let usage = value.get("usage")?.as_object()?;
    let input_tokens = usage.get("input_tokens")?.as_u64()?;
    let output_tokens = usage.get("output_tokens")?.as_u64()?;
    let details = usage.get("input_tokens_details").and_then(Value::as_object);
    let cached_tokens = details
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64);
    let cache_write_tokens = details
        .and_then(|details| details.get("cache_write_tokens"))
        .and_then(Value::as_u64);
    Some(
        DecisionsUsage::new(input_tokens, output_tokens)
            .with_cache_details(cached_tokens, cache_write_tokens),
    )
}

fn parse_reported_model(value: &Value) -> Option<String> {
    let model = value.get("model")?.as_str()?;
    if model.is_empty()
        || model.chars().count() > MAX_MODEL_CHARS
        || model.chars().any(char::is_control)
    {
        return None;
    }
    Some(model.to_owned())
}

fn error_is_refusal(error: &Value) -> bool {
    for field in ["type", "code", "status"] {
        if matches!(
            error.get(field).and_then(Value::as_str),
            Some("refusal" | "content_filter" | "refused")
        ) {
            return true;
        }
    }
    false
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    model: Option<Value>,
    #[serde(default)]
    answers: Option<Vec<WireAnswer>>,
}

/// One answer object with duplicate-field rejection.
///
/// `serde_json` otherwise keeps the last duplicate key, which could hide a
/// malformed provider answer.
#[derive(Default)]
struct WireAnswer {
    kind: Option<Value>,
    name: Option<Value>,
    choice: Option<Value>,
    confidence: Option<Value>,
    probabilities: Option<Vec<WireProbability>>,
}

impl<'de> Deserialize<'de> for WireAnswer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AnswerVisitor;

        impl<'de> Visitor<'de> for AnswerVisitor {
            type Value = WireAnswer;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Decisions answer object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<WireAnswer, A::Error> {
                let mut answer = WireAnswer::default();
                let mut seen = BTreeSet::new();
                while let Some(key) = access.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate answer field"));
                    }
                    match key.as_str() {
                        "type" => answer.kind = Some(access.next_value()?),
                        "name" => answer.name = Some(access.next_value()?),
                        "choice" => answer.choice = Some(access.next_value()?),
                        "confidence" => answer.confidence = Some(access.next_value()?),
                        "probabilities" => answer.probabilities = Some(access.next_value()?),
                        _ => {
                            let _ = access.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(answer)
            }
        }

        deserializer.deserialize_map(AnswerVisitor)
    }
}

/// One probability entry with duplicate-field rejection.
#[derive(Default)]
struct WireProbability {
    value: Option<Value>,
    probability: Option<Value>,
}

impl<'de> Deserialize<'de> for WireProbability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProbabilityVisitor;

        impl<'de> Visitor<'de> for ProbabilityVisitor {
            type Value = WireProbability;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Decisions probability entry")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<WireProbability, A::Error> {
                let mut entry = WireProbability::default();
                let mut seen = BTreeSet::new();
                while let Some(key) = access.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate probability field"));
                    }
                    match key.as_str() {
                        "value" => entry.value = Some(access.next_value()?),
                        "probability" => entry.probability = Some(access.next_value()?),
                        _ => {
                            let _ = access.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(entry)
            }
        }

        deserializer.deserialize_map(ProbabilityVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const QUESTION: &str = "condition:project:question";

    fn valid_body() -> Value {
        json!({
            "model": DECISIONS_REQUEST_MODEL,
            "answers": [{
                "type": "choice",
                "name": QUESTION,
                "choice": "met",
                "confidence": 0.82,
                "probabilities": [
                    {"value": "met", "probability": 0.96},
                    {"value": "unmet", "probability": 0.03},
                    {"value": "insufficient", "probability": 0.01},
                ],
            }],
            "usage": {
                "input_tokens": 120,
                "input_tokens_details": {"cached_tokens": 20, "cache_write_tokens": 30},
                "output_tokens": 12,
            },
        })
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("serializable body")
    }

    #[test]
    fn valid_choice_distribution_is_parsed() {
        let parsed = parse_response(&bytes(&valid_body()), QUESTION);
        assert!(parsed.choice.is_ok());
        assert_eq!(
            parsed.confidence.as_ref().map(NativeConfidence::value),
            Some(0.82)
        );
        assert_eq!(
            parsed.usage,
            Some(DecisionsUsage::new(120, 12).with_cache_details(Some(20), Some(30)))
        );
        assert_eq!(
            parsed.reported_model.as_deref(),
            Some(DECISIONS_REQUEST_MODEL)
        );
    }

    #[test]
    fn reordered_and_duplicate_probabilities_are_rejected() {
        let mut reordered = valid_body();
        reordered["answers"][0]["probabilities"] = json!([
            {"value": "unmet", "probability": 0.03},
            {"value": "met", "probability": 0.96},
            {"value": "insufficient", "probability": 0.01},
        ]);
        assert_eq!(
            parse_response(&bytes(&reordered), QUESTION)
                .choice
                .unwrap_err(),
            DecisionsRejection::ReorderedProbabilities
        );

        let mut duplicate = valid_body();
        duplicate["answers"][0]["probabilities"] = json!([
            {"value": "met", "probability": 0.96},
            {"value": "met", "probability": 0.03},
            {"value": "insufficient", "probability": 0.01},
        ]);
        assert_eq!(
            parse_response(&bytes(&duplicate), QUESTION)
                .choice
                .unwrap_err(),
            DecisionsRejection::DuplicateProbability
        );
    }

    #[test]
    fn duplicate_answer_names_and_refusals_are_rejected() {
        let mut duplicate = valid_body();
        duplicate["answers"] = json!([
            {
                "type": "choice",
                "name": QUESTION,
                "choice": "met",
                "confidence": 0.9,
                "probabilities": [
                    {"value": "met", "probability": 0.96},
                    {"value": "unmet", "probability": 0.03},
                    {"value": "insufficient", "probability": 0.01},
                ],
            },
            {
                "type": "choice",
                "name": QUESTION,
                "choice": "met",
                "confidence": 0.9,
                "probabilities": [
                    {"value": "met", "probability": 0.96},
                    {"value": "unmet", "probability": 0.03},
                    {"value": "insufficient", "probability": 0.01},
                ],
            },
        ]);
        assert_eq!(
            parse_response(&bytes(&duplicate), QUESTION)
                .choice
                .unwrap_err(),
            DecisionsRejection::DuplicateAnswer
        );

        let refusal = json!({
            "model": DECISIONS_REQUEST_MODEL,
            "answers": [{"type": "refusal", "name": QUESTION}],
        });
        assert_eq!(
            parse_response(&bytes(&refusal), QUESTION)
                .choice
                .unwrap_err(),
            DecisionsRejection::Refusal
        );
    }

    #[test]
    fn model_mismatch_and_usage_unknown_are_reported() {
        let mut response = valid_body();
        response["model"] = json!("gpt-6-luna-latest");
        let parsed = parse_response(&bytes(&response), QUESTION);
        assert_eq!(
            parsed.choice.unwrap_err(),
            DecisionsRejection::ModelMismatch
        );
        assert_eq!(parsed.reported_model.as_deref(), Some("gpt-6-luna-latest"));

        let mut missing_usage = valid_body();
        missing_usage.as_object_mut().unwrap().remove("usage");
        assert_eq!(parse_response(&bytes(&missing_usage), QUESTION).usage, None);

        let mut malformed_usage = valid_body();
        malformed_usage["usage"] = json!({"input_tokens": "120", "output_tokens": 12});
        assert_eq!(
            parse_response(&bytes(&malformed_usage), QUESTION).usage,
            None
        );

        let mut zero_usage = valid_body();
        zero_usage["usage"] = json!({"input_tokens": 0, "output_tokens": 0});
        assert_eq!(
            parse_response(&bytes(&zero_usage), QUESTION).usage,
            Some(DecisionsUsage::new(0, 0))
        );
    }
}
