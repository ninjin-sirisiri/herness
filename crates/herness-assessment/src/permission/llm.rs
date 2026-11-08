//! Normal-LLM permission evaluator.
//!
//! The provider receives one closed-schema permission question and must echo
//! the frozen operation identity, argument digest, working directory, policy
//! version, and mode. A missing, malformed, uncertain, or stale-bound answer is
//! an ask. Self-reported probabilities or confidence values are not part of the
//! schema and are rejected rather than converted into an adoption threshold.

use herness_core::PermissionDecision;
use herness_core::contracts::{ModelId, TokenUsage};
use herness_supervision::assessment::{PermissionAssessment, PermissionVerdict};
use herness_supervision::profiles::ProfileEntry;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{AssessmentError, AssessmentErrorKind};
use crate::llm::{Route, extract_envelope_text};
use crate::transport::{
    AssessmentRequest as TransportRequest, AssessmentTransport, TransportControl,
};

use super::PermissionQuestion;
use super::PermissionReply;

const MAX_OUTPUT_TOKENS: u32 = 2_048;
const MAX_RATIONALE_CHARS: usize = 2_000;
const MAX_PERMISSION_TEXT_BYTES: usize = 500_000;
const RESPONSE_SCHEMA_NAME: &str = "herness_permission_evaluation";

/// Assesses one permission question through a normal LLM route.
pub(crate) fn assess(
    transport: &AssessmentTransport,
    entry: &ProfileEntry,
    question: &PermissionQuestion,
    control: TransportControl,
) -> Result<PermissionReply, AssessmentError> {
    let route = Route::for_capabilities(entry.connection())?;
    let required = entry.profile().required_inputs();
    let native_structured_output = required.requires_structured_output();
    if native_structured_output
        && (!entry.structured_output() || !route.supports_native_structured_output())
    {
        return Err(AssessmentError::new(
            AssessmentErrorKind::StructuredOutputUnavailable,
        ));
    }
    if required.requires_image() {
        return Err(AssessmentError::new(
            AssessmentErrorKind::UnsupportedModality,
        ));
    }

    let body = build(route, entry, question, native_structured_output)?;
    let request = TransportRequest::new(
        entry.profile().connection(),
        entry.profile().model().as_str(),
        body,
    )?;
    let response = transport.send(request, control)?;
    let reported_model = response
        .reported_model()
        .and_then(|model| ModelId::new(model).ok());
    let text = match extract_envelope_text(route, response.body()) {
        Ok(text) => text,
        Err(_) => {
            return Ok(PermissionReply::ask(TokenUsage::unknown(), reported_model));
        }
    };
    Ok(parse_answer(&text, entry, question, reported_model))
}

fn parse_answer(
    text: &str,
    entry: &ProfileEntry,
    question: &PermissionQuestion,
    reported_model: Option<ModelId>,
) -> PermissionReply {
    let wire: WirePermission = match serde_json::from_str(text) {
        Ok(wire) => wire,
        Err(_) => {
            return PermissionReply::ask(TokenUsage::unknown(), reported_model);
        }
    };
    if wire.operation_id != question.operation_id()
        || wire.arguments_digest != question.arguments_digest().as_str()
        || wire.cwd != question.cwd()
        || wire.policy_version != question.policy_version().get()
        || wire.mode != question.mode().to_string()
    {
        return PermissionReply::ask(TokenUsage::unknown(), reported_model);
    }
    let rationale = wire.rationale.trim();
    if rationale.is_empty() || rationale.chars().count() > MAX_RATIONALE_CHARS {
        return PermissionReply::ask(TokenUsage::unknown(), reported_model);
    }
    if wire
        .uncertainty
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        return PermissionReply::ask(TokenUsage::unknown(), reported_model);
    }
    let verdict = match wire.decision {
        WireDecision::Allow => PermissionVerdict::Allow,
        WireDecision::Deny => PermissionVerdict::Deny,
        WireDecision::Ask => {
            return PermissionReply::ask(TokenUsage::unknown(), reported_model);
        }
    };
    let assessment = PermissionAssessment::NormalLlm {
        verdict,
        uncertain: false,
    };
    let decision = match assessment.adopted_verdict(entry.profile().thresholds()) {
        Some(PermissionVerdict::Allow) => PermissionDecision::Allow,
        Some(PermissionVerdict::Deny) => PermissionDecision::Deny,
        Some(PermissionVerdict::Ask) | None => PermissionDecision::Ask,
    };
    PermissionReply {
        decision,
        usage: TokenUsage::unknown(),
        reported_model,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WirePermission {
    decision: WireDecision,
    operation_id: String,
    arguments_digest: String,
    cwd: String,
    policy_version: u64,
    mode: String,
    rationale: String,
    #[serde(default)]
    uncertainty: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireDecision {
    Allow,
    Deny,
    Ask,
}

fn build(
    route: Route,
    entry: &ProfileEntry,
    question: &PermissionQuestion,
    native_structured_output: bool,
) -> Result<Value, AssessmentError> {
    let model = entry.profile().model().as_str();
    let payload = serde_json::to_string(&question.payload())
        .map_err(|_| AssessmentError::new(AssessmentErrorKind::Internal))?;
    if payload.len() > MAX_PERMISSION_TEXT_BYTES {
        return Err(AssessmentError::new(AssessmentErrorKind::InputTooLarge));
    }
    let instructions = PermissionQuestion::instructions();
    Ok(match route {
        Route::OpenAiResponses => {
            let mut body = json!({
                "model": model,
                "instructions": instructions,
                "input": [{"role": "user", "content": [{"type": "input_text", "text": payload}]}],
                "max_output_tokens": MAX_OUTPUT_TOKENS,
                "store": false,
            });
            if native_structured_output {
                body["text"] = json!({
                    "format": {
                        "type": "json_schema",
                        "name": RESPONSE_SCHEMA_NAME,
                        "schema": response_schema(),
                        "strict": true,
                    }
                });
            }
            body
        }
        Route::AnthropicMessages => json!({
            "model": model,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "system": instructions,
            "messages": [{"role": "user", "content": [{"type": "text", "text": payload}]}],
        }),
        Route::OpenAiCompletions => {
            let mut body = json!({
                "model": model,
                "messages": [
                    {"role": "system", "content": instructions},
                    {"role": "user", "content": payload},
                ],
                "max_tokens": MAX_OUTPUT_TOKENS,
            });
            if native_structured_output {
                body["response_format"] = json!({
                    "type": "json_schema",
                    "json_schema": {
                        "name": RESPONSE_SCHEMA_NAME,
                        "schema": response_schema(),
                        "strict": true,
                    }
                });
            }
            body
        }
    })
}

fn response_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "decision",
            "operationId",
            "argumentsDigest",
            "cwd",
            "policyVersion",
            "mode",
            "rationale",
            "uncertainty"
        ],
        "properties": {
            "decision": {"type": "string", "enum": ["allow", "deny", "ask"]},
            "operationId": {"type": "string"},
            "argumentsDigest": {"type": "string"},
            "cwd": {"type": "string"},
            "policyVersion": {"type": "integer", "minimum": 1},
            "mode": {"type": "string", "enum": ["configured", "automatic"]},
            "rationale": {"type": "string"},
            "uncertainty": {"type": ["string", "null"]}
        }
    })
}
