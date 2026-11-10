//! Strict parsing of normal-LLM provider envelopes and condition answers.
//!
//! Provider envelopes are reduced to one text answer. The answer itself is then
//! parsed with a closed schema: unknown fields (including self-reported
//! probabilities or confidence numbers), missing fields, multiple conditions,
//! and unknown/duplicate evidence IDs are all rejected. Rejections never become
//! `met`.

use std::collections::BTreeSet;

use herness_supervision::assessment::{AssessmentRequest, ConditionVerdict};
use herness_supervision::ids::{ConditionId, EvidenceId};
use serde::Deserialize;
use serde_json::Value;

use super::request::Route;
use super::{InconclusiveReason, LlmUsage};

const MAX_RATIONALE_CHARS: usize = 2_000;
const MAX_UNCERTAINTY_CHARS: usize = 2_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireAssessment {
    conditions: Vec<WireCondition>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireCondition {
    condition_id: String,
    verdict: WireVerdict,
    evidence_ids: Vec<String>,
    rationale: String,
    #[serde(default)]
    uncertainty: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireVerdict {
    Met,
    Unmet,
    Insufficient,
}

impl From<WireVerdict> for ConditionVerdict {
    fn from(verdict: WireVerdict) -> Self {
        match verdict {
            WireVerdict::Met => Self::Met,
            WireVerdict::Unmet => Self::Unmet,
            WireVerdict::Insufficient => Self::Insufficient,
        }
    }
}

pub(crate) struct ParsedCondition {
    pub(crate) verdict: ConditionVerdict,
    pub(crate) evidence: Vec<EvidenceId>,
    pub(crate) rationale: String,
    pub(crate) uncertainty: Option<String>,
}

/// Extracts one model answer from a provider envelope.
pub(crate) fn extract_text(route: Route, body: &[u8]) -> Result<String, InconclusiveReason> {
    let value: Value = serde_json::from_slice(body).map_err(|_| InconclusiveReason::InvalidJson)?;
    match route {
        Route::OpenAiResponses => openai_responses_text(&value),
        Route::AnthropicMessages => anthropic_text(&value),
        Route::OpenAiCompletions => openai_completions_text(&value),
    }
}

/// Extracts provider-reported token usage from the same response envelope.
///
/// Responses and Anthropic use `input_tokens`/`output_tokens`; OpenAI
/// completions use `prompt_tokens`/`completion_tokens`. A missing, malformed,
/// or negative count yields `None`, never zero.
pub(crate) fn extract_usage(body: &[u8]) -> Option<LlmUsage> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let usage = value.get("usage")?.as_object()?;
    let input = usage
        .get("input_tokens")
        .or_else(|| usage.get("prompt_tokens"))?
        .as_u64()?;
    let output = usage
        .get("output_tokens")
        .or_else(|| usage.get("completion_tokens"))?
        .as_u64()?;
    Some(LlmUsage::new(input, output))
}

/// Parses and strictly validates one condition answer.
pub(crate) fn parse_condition(
    text: &str,
    request: &AssessmentRequest,
    supplied: &BTreeSet<EvidenceId>,
) -> Result<ParsedCondition, InconclusiveReason> {
    let wire: WireAssessment = match serde_json::from_str(text) {
        Ok(wire) => wire,
        Err(error) => {
            return Err(if error.is_syntax() || error.is_eof() {
                InconclusiveReason::InvalidJson
            } else if error.to_string().starts_with("missing field") {
                InconclusiveReason::MissingField
            } else {
                InconclusiveReason::SchemaViolation
            });
        }
    };
    let condition = match wire.conditions.as_slice() {
        [] => return Err(InconclusiveReason::MissingField),
        [condition] => condition,
        _ => return Err(InconclusiveReason::MultipleConditions),
    };
    let condition_id: ConditionId = condition
        .condition_id
        .parse()
        .map_err(|_| InconclusiveReason::SchemaViolation)?;
    if condition_id != request.condition_id() {
        return Err(InconclusiveReason::UnknownCondition);
    }
    let mut cited = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in &condition.evidence_ids {
        let id: EvidenceId = raw
            .parse()
            .map_err(|_| InconclusiveReason::UnknownEvidence)?;
        if id.project_id() != request.project_id() || !supplied.contains(&id) {
            return Err(InconclusiveReason::UnknownEvidence);
        }
        if !seen.insert(id) {
            return Err(InconclusiveReason::DuplicateEvidence);
        }
        cited.push(id);
    }
    if cited.is_empty() {
        return Err(InconclusiveReason::MissingEvidence);
    }
    let rationale = condition.rationale.trim();
    if rationale.is_empty() {
        return Err(InconclusiveReason::MissingField);
    }
    if rationale.chars().count() > MAX_RATIONALE_CHARS {
        return Err(InconclusiveReason::SchemaViolation);
    }
    let uncertainty = condition
        .uncertainty
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if uncertainty
        .as_ref()
        .is_some_and(|value| value.chars().count() > MAX_UNCERTAINTY_CHARS)
    {
        return Err(InconclusiveReason::SchemaViolation);
    }
    Ok(ParsedCondition {
        verdict: condition.verdict.into(),
        evidence: cited,
        rationale: rationale.to_owned(),
        uncertainty,
    })
}

fn has_error(value: &Value) -> bool {
    value.get("error").is_some_and(|error| !error.is_null())
}

fn openai_responses_text(value: &Value) -> Result<String, InconclusiveReason> {
    if has_error(value) {
        return Err(InconclusiveReason::ProviderFailure);
    }
    match value.get("status").and_then(Value::as_str) {
        Some("completed") => {}
        Some("incomplete") => return Err(InconclusiveReason::Truncated),
        Some("failed" | "cancelled") => return Err(InconclusiveReason::ProviderFailure),
        _ => return Err(InconclusiveReason::SchemaViolation),
    }
    let mut texts = Vec::new();
    if let Some(output) = value.get("output").and_then(Value::as_array) {
        for item in output {
            match item.get("type").and_then(Value::as_str) {
                Some("message") => {
                    let content = item
                        .get("content")
                        .and_then(Value::as_array)
                        .ok_or(InconclusiveReason::SchemaViolation)?;
                    for part in content {
                        match part.get("type").and_then(Value::as_str) {
                            Some("output_text") => {
                                if let Some(text) = part.get("text").and_then(Value::as_str)
                                    && !text.trim().is_empty()
                                {
                                    texts.push(text.to_owned());
                                }
                            }
                            Some("refusal") => return Err(InconclusiveReason::Refusal),
                            Some("function_call" | "tool_use") => {
                                return Err(InconclusiveReason::ToolUse);
                            }
                            _ => {}
                        }
                    }
                }
                Some(
                    "function_call"
                    | "custom_tool_call"
                    | "computer_call"
                    | "file_search_call"
                    | "web_search_call"
                    | "code_interpreter_call"
                    | "image_generation_call",
                ) => return Err(InconclusiveReason::ToolUse),
                // Reasoning items are intentionally ignored and never stored.
                _ => {}
            }
        }
    }
    if texts.is_empty()
        && let Some(text) = value.get("output_text").and_then(Value::as_str)
        && !text.trim().is_empty()
    {
        texts.push(text.to_owned());
    }
    single_answer(texts)
}

fn anthropic_text(value: &Value) -> Result<String, InconclusiveReason> {
    if has_error(value) || value.get("type").and_then(Value::as_str) == Some("error") {
        return Err(InconclusiveReason::ProviderFailure);
    }
    match value.get("stop_reason").and_then(Value::as_str) {
        Some("end_turn") => {}
        Some("refusal") => return Err(InconclusiveReason::Refusal),
        Some("max_tokens") => return Err(InconclusiveReason::Truncated),
        Some("tool_use") => return Err(InconclusiveReason::ToolUse),
        _ => return Err(InconclusiveReason::SchemaViolation),
    }
    let content = value
        .get("content")
        .and_then(Value::as_array)
        .ok_or(InconclusiveReason::SchemaViolation)?;
    let mut texts = Vec::new();
    for block in content {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = block.get("text").and_then(Value::as_str)
                    && !text.trim().is_empty()
                {
                    texts.push(text.to_owned());
                }
            }
            Some("refusal") => return Err(InconclusiveReason::Refusal),
            Some("tool_use") => return Err(InconclusiveReason::ToolUse),
            // Extended thinking must never be stored as model rationale.
            Some("thinking" | "redacted_thinking") => {}
            _ => {}
        }
    }
    single_answer(texts)
}

fn openai_completions_text(value: &Value) -> Result<String, InconclusiveReason> {
    if has_error(value) {
        return Err(InconclusiveReason::ProviderFailure);
    }
    let choices = value
        .get("choices")
        .and_then(Value::as_array)
        .ok_or(InconclusiveReason::SchemaViolation)?;
    let choice = match choices.as_slice() {
        [] => return Err(InconclusiveReason::EmptyAnswer),
        [choice] => choice,
        _ => return Err(InconclusiveReason::MultipleAnswers),
    };
    let message = choice
        .get("message")
        .ok_or(InconclusiveReason::SchemaViolation)?;
    if message
        .get("refusal")
        .and_then(Value::as_str)
        .is_some_and(|refusal| !refusal.trim().is_empty())
    {
        return Err(InconclusiveReason::Refusal);
    }
    if message
        .get("tool_calls")
        .and_then(Value::as_array)
        .is_some_and(|calls| !calls.is_empty())
    {
        return Err(InconclusiveReason::ToolUse);
    }
    match choice.get("finish_reason").and_then(Value::as_str) {
        Some("stop") => {}
        Some("length") => return Err(InconclusiveReason::Truncated),
        Some("content_filter") => return Err(InconclusiveReason::Refusal),
        Some("tool_calls" | "function_call") => return Err(InconclusiveReason::ToolUse),
        _ => return Err(InconclusiveReason::SchemaViolation),
    }
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .ok_or(InconclusiveReason::SchemaViolation)?;
    if content.trim().is_empty() {
        return Err(InconclusiveReason::EmptyAnswer);
    }
    Ok(content.to_owned())
}

fn single_answer(mut texts: Vec<String>) -> Result<String, InconclusiveReason> {
    match texts.len() {
        0 => Err(InconclusiveReason::EmptyAnswer),
        1 => Ok(texts.remove(0)),
        _ => Err(InconclusiveReason::MultipleAnswers),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_reads_responses_anthropic_and_completions_shapes() {
        for body in [
            br#"{"usage":{"input_tokens":16,"output_tokens":7}}"#.as_slice(),
            br#"{"usage":{"input_tokens":16,"output_tokens":7,"total_tokens":23}}"#.as_slice(),
        ] {
            assert_eq!(extract_usage(body), Some(LlmUsage::new(16, 7)));
        }
        assert_eq!(
            extract_usage(br#"{"usage":{"prompt_tokens":12,"completion_tokens":3}}"#),
            Some(LlmUsage::new(12, 3))
        );
        assert_eq!(
            extract_usage(br#"{"usage":{"input_tokens":0,"output_tokens":0}}"#),
            Some(LlmUsage::new(0, 0))
        );
    }

    #[test]
    fn missing_or_malformed_usage_is_none_not_zero() {
        for body in [
            br#"{}"#.as_slice(),
            br#"{"usage":null}"#.as_slice(),
            br#"{"usage":{"input_tokens":"16","output_tokens":7}}"#.as_slice(),
            br#"{"usage":{"input_tokens":16}}"#.as_slice(),
            br#"{"usage":{"input_tokens":-1,"output_tokens":7}}"#.as_slice(),
            b"not json".as_slice(),
        ] {
            assert_eq!(extract_usage(body), None);
        }
    }
}
