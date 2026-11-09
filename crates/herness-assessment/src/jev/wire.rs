//! Strict parsing and validation of a System One choice response.
//!
//! A response is usable only when the reported model is the fixed requested
//! version, there is exactly one answer for the derived question ID, the
//! answer type is `choice`, the selected choice is one of the three criteria,
//! the distribution has exactly those three finite keys, the sum is within the
//! H2 tolerance, the selected choice is the maximum-probability choice, and
//! the native confidence is finite in `0..=1`. Every failure is mapped to an
//! `insufficient` result, never to `met` or `unmet`.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use herness_supervision::assessment::{ConditionProbabilities, ConditionVerdict, NativeConfidence};
use herness_supervision::profiles::H2_DISTRIBUTION_TOLERANCE;
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde_json::Value;

use super::{JEV_CONFIDENCE_SCALE, JevRejection, JevUsage};

const MAX_MODEL_CHARS: usize = 256;

/// One parsed response, including metadata that remains useful when the
/// choice is rejected.
pub(crate) struct ParsedResponse {
    pub(crate) choice: Result<ParsedChoice, JevRejection>,
    pub(crate) confidence: Option<NativeConfidence>,
    pub(crate) usage: Option<JevUsage>,
    pub(crate) reported_model: Option<String>,
}

/// A validated choice and complete distribution.
#[derive(Debug)]
pub(crate) struct ParsedChoice {
    pub(crate) selected: ConditionVerdict,
    pub(crate) probabilities: ConditionProbabilities,
}

/// Parses one System One response body.
pub(crate) fn parse_response(
    body: &[u8],
    question_id: &str,
    expected_model: &str,
) -> ParsedResponse {
    let value: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return rejected(JevRejection::InvalidJson, None, None, None),
    };
    let usage = parse_usage(&value);
    let reported_model = parse_reported_model(&value);
    if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
        let reason = if error_is_refusal(error) {
            JevRejection::Refusal
        } else {
            JevRejection::ProviderFailure
        };
        return rejected(reason, None, usage, reported_model);
    }

    let wire: WireResponse = match serde_json::from_slice(body) {
        Ok(wire) => wire,
        Err(error) => {
            return rejected(schema_error(&error), None, usage, reported_model);
        }
    };

    let model = match wire.model.as_ref().and_then(Value::as_str) {
        Some(model) if model == expected_model => model,
        _ => return rejected(JevRejection::ModelMismatch, None, usage, reported_model),
    };
    debug_assert_eq!(model, expected_model);

    if wire.answers.is_empty() {
        return rejected(JevRejection::MissingAnswer, None, usage, reported_model);
    }
    if wire.answers.len() != 1 {
        return rejected(JevRejection::UnknownAnswer, None, usage, reported_model);
    }
    let (answer_id, answer) = wire
        .answers
        .iter()
        .next()
        .expect("a non-empty map has one entry");
    if answer_id.as_str() != question_id {
        return rejected(JevRejection::UnknownAnswer, None, usage, reported_model);
    }

    match answer.kind.as_ref().and_then(Value::as_str) {
        Some("choice") => {}
        Some("refusal") => {
            return rejected(JevRejection::Refusal, None, usage, reported_model);
        }
        _ => return rejected(JevRejection::WrongAnswerType, None, usage, reported_model),
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
                JevRejection::InvalidChoice,
                Some(confidence),
                usage,
                reported_model,
            );
        }
    };
    let probabilities = match parse_probabilities(&answer.probabilities, selected) {
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
    reason: JevRejection,
    confidence: Option<NativeConfidence>,
    usage: Option<JevUsage>,
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

fn parse_confidence(value: Option<&Value>) -> Result<NativeConfidence, JevRejection> {
    let value = value
        .and_then(Value::as_f64)
        .ok_or(JevRejection::InvalidConfidence)?;
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(JevRejection::InvalidConfidence);
    }
    NativeConfidence::new(value, JEV_CONFIDENCE_SCALE).map_err(|_| JevRejection::InvalidConfidence)
}

fn parse_probabilities(
    probabilities: &BTreeMap<String, Value>,
    selected: ConditionVerdict,
) -> Result<ConditionProbabilities, JevRejection> {
    const KEYS: [&str; 3] = ["met", "unmet", "insufficient"];
    if KEYS.iter().any(|key| !probabilities.contains_key(*key)) {
        return Err(JevRejection::MissingProbabilities);
    }
    if probabilities.len() != KEYS.len() {
        return Err(JevRejection::ExtraProbabilities);
    }
    let mut values = [0.0_f64; 3];
    for (index, key) in KEYS.iter().enumerate() {
        let value = probabilities
            .get(*key)
            .and_then(Value::as_f64)
            .ok_or(JevRejection::InvalidProbability)?;
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(JevRejection::InvalidProbability);
        }
        values[index] = value;
    }
    if (values.iter().sum::<f64>() - 1.0).abs() > H2_DISTRIBUTION_TOLERANCE {
        return Err(JevRejection::ProbabilitySum);
    }
    let probabilities = ConditionProbabilities::new(values[0], values[1], values[2])
        .map_err(|_| JevRejection::InvalidProbability)?;
    let selected_probability = probabilities.probability(selected);
    let maximum = probabilities
        .met()
        .max(probabilities.unmet())
        .max(probabilities.insufficient());
    if selected_probability < maximum {
        return Err(JevRejection::SelectionNotMaximum);
    }
    Ok(probabilities)
}

fn parse_usage(value: &Value) -> Option<JevUsage> {
    let usage = value.get("usage")?.as_object()?;
    let input_tokens = usage.get("input_tokens")?.as_u64()?;
    let output_tokens = usage.get("output_tokens")?.as_u64()?;
    Some(JevUsage::new(input_tokens, output_tokens))
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

fn schema_error(error: &serde_json::Error) -> JevRejection {
    if error.is_syntax() || error.is_eof() {
        return JevRejection::InvalidJson;
    }
    let message = error.to_string();
    if message.contains("duplicate answer") {
        JevRejection::DuplicateAnswer
    } else if message.contains("duplicate probability") {
        JevRejection::DuplicateProbability
    } else {
        JevRejection::SchemaViolation
    }
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

/// Deserializes a JSON object while rejecting duplicate keys. `serde_json`
/// otherwise keeps only the last duplicate, which would hide a malformed
/// provider answer.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jev::JEV_REQUEST_MODEL;
    use serde_json::json;

    const QUESTION: &str = "condition:project:question";

    fn valid_body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "model": JEV_REQUEST_MODEL,
            "answers": {
                QUESTION: {
                    "type": "choice",
                    "choice": "met",
                    "confidence": 0.82,
                    "probabilities": {
                        "met": 0.96,
                        "unmet": 0.03,
                        "insufficient": 0.01
                    }
                }
            },
            "usage": {"input_tokens": 120, "output_tokens": 12}
        }))
        .expect("valid body")
    }

    #[test]
    fn valid_choice_distribution_is_parsed() {
        let parsed = parse_response(&valid_body(), QUESTION, JEV_REQUEST_MODEL);
        assert!(parsed.choice.is_ok());
        assert_eq!(
            parsed.confidence.as_ref().map(NativeConfidence::value),
            Some(0.82)
        );
        assert_eq!(parsed.usage, Some(JevUsage::new(120, 12)));
        assert_eq!(parsed.reported_model.as_deref(), Some(JEV_REQUEST_MODEL));
    }

    #[test]
    fn duplicate_question_and_probability_keys_are_rejected() {
        let duplicate_question = format!(
            r#"{{"model":"{JEV_REQUEST_MODEL}","answers":{{"{QUESTION}":{{"type":"choice","choice":"met","confidence":0.9,"probabilities":{{"met":0.96,"unmet":0.03,"insufficient":0.01}}}},"{QUESTION}":{{"type":"choice","choice":"met","confidence":0.9,"probabilities":{{"met":0.96,"unmet":0.03,"insufficient":0.01}}}}}}}}"#
        );
        assert_eq!(
            parse_response(duplicate_question.as_bytes(), QUESTION, JEV_REQUEST_MODEL)
                .choice
                .unwrap_err(),
            JevRejection::DuplicateAnswer
        );

        let duplicate_probability = format!(
            r#"{{"model":"{JEV_REQUEST_MODEL}","answers":{{"{QUESTION}":{{"type":"choice","choice":"met","confidence":0.9,"probabilities":{{"met":0.96,"met":0.96,"unmet":0.03,"insufficient":0.01}}}}}}}}"#
        );
        assert_eq!(
            parse_response(
                duplicate_probability.as_bytes(),
                QUESTION,
                JEV_REQUEST_MODEL
            )
            .choice
            .unwrap_err(),
            JevRejection::DuplicateProbability
        );
    }

    #[test]
    fn selection_must_be_the_maximum_probability() {
        let body = serde_json::to_vec(&json!({
            "model": JEV_REQUEST_MODEL,
            "answers": {
                QUESTION: {
                    "type": "choice",
                    "choice": "met",
                    "confidence": 0.9,
                    "probabilities": {"met": 0.2, "unmet": 0.7, "insufficient": 0.1}
                }
            }
        }))
        .expect("body");
        assert_eq!(
            parse_response(&body, QUESTION, JEV_REQUEST_MODEL)
                .choice
                .unwrap_err(),
            JevRejection::SelectionNotMaximum
        );
    }

    #[test]
    fn usage_is_unknown_when_missing_or_malformed() {
        let missing = serde_json::to_vec(&json!({
            "model": JEV_REQUEST_MODEL,
            "answers": {
                QUESTION: {
                    "type": "choice",
                    "choice": "met",
                    "confidence": 0.9,
                    "probabilities": {"met": 0.96, "unmet": 0.03, "insufficient": 0.01}
                }
            }
        }))
        .expect("body");
        assert_eq!(
            parse_response(&missing, QUESTION, JEV_REQUEST_MODEL).usage,
            None
        );

        let malformed = serde_json::to_vec(&json!({
            "model": JEV_REQUEST_MODEL,
            "answers": {
                QUESTION: {
                    "type": "choice",
                    "choice": "met",
                    "confidence": 0.9,
                    "probabilities": {"met": 0.96, "unmet": 0.03, "insufficient": 0.01}
                }
            },
            "usage": {"input_tokens": "120", "output_tokens": 12}
        }))
        .expect("body");
        assert_eq!(
            parse_response(&malformed, QUESTION, JEV_REQUEST_MODEL).usage,
            None
        );
    }
}
