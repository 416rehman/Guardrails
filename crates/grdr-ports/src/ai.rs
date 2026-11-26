// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! JudgeBackend port and conformance codecs for OpenAI-compatible and Anthropic providers.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use grdr_model::CodedError;

pub const CODE_AI_BACKEND_UNAVAILABLE: &str = "GRDR-AI-0001";
pub const CODE_AI_MALFORMED_RESPONSE: &str = "GRDR-AI-0002";
pub const CODE_AI_PERMISSIVE_REJECTED: &str = "GRDR-AI-0003";
pub const CODE_AI_TOKEN_BUDGET_EXCEEDED: &str = "GRDR-AI-0004";
pub const CODE_AI_COMMITMENT_FAILED: &str = "GRDR-AI-0005";

pub const ANTHROPIC_API_VERSION: &str = "2023-06-01";
pub const MAX_JUDGE_OUTPUT_TOKENS: u32 = 4_096;
pub const MAX_JUDGE_TEMPERATURE_MILLI: u16 = 1_000;
pub const MAX_JUDGE_TIMEOUT_MS: u32 = 120_000;
pub const MAX_JUDGE_RAW_JSON_BYTES: usize = 256 * 1024;
pub const MAX_JUDGE_SYSTEM_BYTES: usize = 64 * 1024;
pub const MAX_JUDGE_SCHEMA_BYTES: usize = 64 * 1024;
const MAX_JUDGE_ID_BYTES: usize = 128;
const MAX_JUDGE_MODEL_BYTES: usize = 256;
const MAX_STOP_REASON_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendProtocol {
    OpenAiCompatible,
    Anthropic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum JudgeAvailability {
    Available,
    CouldNotLook { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsageLedger {
    pub provider: String,
    pub model_id: String,
    pub job_kind: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cached_tokens: u64,
    pub recorded_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JudgeRequestSpec {
    pub job_id: String,
    pub job_kind: String,
    pub model_id: String,
    pub system_instructions: String,
    pub framed_user_prompt: String,
    pub max_output_tokens: u32,
    pub timeout_ms: u32,
    pub temperature_milli: u16,
    pub json_schema_name: String,
    pub json_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JudgeRawResponse {
    pub model_id: String,
    pub raw_json_text: String,
    pub stop_reason: String,
    pub usage: TokenUsageLedger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConformanceReport {
    pub protocol: BackendProtocol,
    pub roundtrip_ok: bool,
    pub usage_metered: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OpenAiCompatibleWire;

#[derive(Debug, Clone, Copy, Default)]
pub struct AnthropicMessagesWire;

pub trait JudgeBackend {
    fn protocol(&self) -> BackendProtocol;
    fn backend_name(&self) -> &str;
    fn invoke_structured(&self, req: &JudgeRequestSpec) -> Result<JudgeRawResponse, CodedError>;
}

impl TokenUsageLedger {
    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.prompt_tokens
            .saturating_add(self.completion_tokens)
            .saturating_add(self.cached_tokens)
    }
}

impl OpenAiCompatibleWire {
    pub fn encode_chat_request(req: &JudgeRequestSpec) -> Result<Value, CodedError> {
        validate_request_spec(req)?;
        let temp = f64::from(req.temperature_milli) / 1000.0;
        Ok(json!({
            "model": req.model_id,
            "temperature": temp,
            "max_tokens": req.max_output_tokens,
            "messages": [
                { "role": "system", "content": req.system_instructions },
                { "role": "user", "content": req.framed_user_prompt }
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": req.json_schema_name,
                    "strict": true,
                    "schema": req.json_schema
                }
            }
        }))
    }

    pub fn decode_chat_response(
        body: &Value,
        provider_name: &str,
        job_kind: &str,
        recorded_at_ms: i64,
    ) -> Result<JudgeRawResponse, CodedError> {
        let model_id =
            decode_bounded_wire_field(body.get("model"), MAX_JUDGE_MODEL_BYTES, true, "model")?;
        let choices = body
            .get("choices")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed_err("missing choices array in OpenAI-compatible response"))?;
        if choices.len() != 1 {
            return Err(malformed_err(
                "OpenAI-compatible response must contain exactly one choice",
            ));
        }
        let choice = choices
            .first()
            .ok_or_else(|| malformed_err("missing choices[0] in OpenAI-compatible response"))?;
        let message = choice
            .get("message")
            .ok_or_else(|| malformed_err("missing choices[0].message"))?;
        if let Some(refusal) = message.get("refusal").and_then(Value::as_str)
            && !refusal.is_empty()
        {
            return Err(CodedError::new(
                CODE_AI_BACKEND_UNAVAILABLE,
                "model backend refused structured evaluation",
                "Treat refusal as could_not_look advisory outcome.",
            ));
        }
        let raw_json_text = message
            .get("content")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| malformed_err("empty choices[0].message.content"))?
            .to_owned();
        if raw_json_text.len() > MAX_JUDGE_RAW_JSON_BYTES {
            return Err(malformed_err(
                "judge response exceeds MAX_JUDGE_RAW_JSON_BYTES",
            ));
        }
        let stop_reason = decode_bounded_wire_field(
            choice.get("finish_reason"),
            MAX_STOP_REASON_BYTES,
            false,
            "finish_reason",
        )?;

        let usage_obj = body.get("usage");
        let prompt_tokens = usage_obj
            .and_then(|u| u.get("prompt_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let completion_tokens = usage_obj
            .and_then(|u| u.get("completion_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let cached_tokens = usage_obj
            .and_then(|u| u.get("prompt_tokens_details"))
            .and_then(|d| d.get("cached_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0);

        Ok(JudgeRawResponse {
            model_id: model_id.clone(),
            raw_json_text,
            stop_reason,
            usage: TokenUsageLedger {
                provider: provider_name.to_owned(),
                model_id,
                job_kind: job_kind.to_owned(),
                prompt_tokens,
                completion_tokens,
                cached_tokens,
                recorded_at_ms,
            },
        })
    }
}

impl AnthropicMessagesWire {
    pub fn encode_messages_request(req: &JudgeRequestSpec) -> Result<Value, CodedError> {
        validate_request_spec(req)?;
        let temp = f64::from(req.temperature_milli) / 1000.0;
        Ok(json!({
            "model": req.model_id,
            "max_tokens": req.max_output_tokens,
            "temperature": temp,
            "system": req.system_instructions,
            "messages": [
                {
                    "role": "user",
                    "content": req.framed_user_prompt
                }
            ],
            "tools": [
                {
                    "name": req.json_schema_name,
                    "description": "Emit restrict-only structured advisory output",
                    "input_schema": req.json_schema
                }
            ],
            "tool_choice": {
                "type": "tool",
                "name": req.json_schema_name
            }
        }))
    }

    pub fn decode_messages_response_for_tool(
        body: &Value,
        provider_name: &str,
        job_kind: &str,
        expected_tool_name: &str,
        recorded_at_ms: i64,
    ) -> Result<JudgeRawResponse, CodedError> {
        Self::decode_messages_response_internal(
            body,
            provider_name,
            job_kind,
            expected_tool_name,
            recorded_at_ms,
        )
    }

    fn decode_messages_response_internal(
        body: &Value,
        provider_name: &str,
        job_kind: &str,
        expected_tool_name: &str,
        recorded_at_ms: i64,
    ) -> Result<JudgeRawResponse, CodedError> {
        let model_id =
            decode_bounded_wire_field(body.get("model"), MAX_JUDGE_MODEL_BYTES, true, "model")?;
        let blocks = body
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed_err("missing content array in Anthropic response"))?;

        let raw_json_text = extract_anthropic_json_payload(blocks, expected_tool_name)?;
        if raw_json_text.len() > MAX_JUDGE_RAW_JSON_BYTES {
            return Err(malformed_err(
                "judge response exceeds MAX_JUDGE_RAW_JSON_BYTES",
            ));
        }
        let stop_reason = decode_bounded_wire_field(
            body.get("stop_reason"),
            MAX_STOP_REASON_BYTES,
            false,
            "stop_reason",
        )?;
        let usage_obj = body.get("usage");
        let prompt_tokens = usage_obj
            .and_then(|u| u.get("input_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let completion_tokens = usage_obj
            .and_then(|u| u.get("output_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let cached_tokens = usage_obj
            .and_then(|u| u.get("cache_read_input_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0);

        Ok(JudgeRawResponse {
            model_id: model_id.clone(),
            raw_json_text,
            stop_reason,
            usage: TokenUsageLedger {
                provider: provider_name.to_owned(),
                model_id,
                job_kind: job_kind.to_owned(),
                prompt_tokens,
                completion_tokens,
                cached_tokens,
                recorded_at_ms,
            },
        })
    }
}

/// Validates that any `JudgeBackend` honors P2 structured output and token metering contracts.
pub fn verify_backend_conformance<B: JudgeBackend>(
    backend: &B,
) -> Result<ConformanceReport, CodedError> {
    let spec = JudgeRequestSpec {
        job_id: "conformance-0001".into(),
        job_kind: "judge.conformance".into(),
        model_id: "conformance-model".into(),
        system_instructions: "Return restrict-only JSON advisory".into(),
        framed_user_prompt: "<rec id=\"r1\">status ok</rec>".into(),
        max_output_tokens: 256,
        timeout_ms: 1_500,
        temperature_milli: 0,
        json_schema_name: "advisory_finding".into(),
        json_schema: json!({
            "type": "object",
            "properties": { "action": { "type": "string" } },
            "required": ["action"],
            "additionalProperties": false
        }),
    };
    let wire_ok = match backend.protocol() {
        BackendProtocol::OpenAiCompatible => {
            OpenAiCompatibleWire::encode_chat_request(&spec).is_ok()
        }
        BackendProtocol::Anthropic => AnthropicMessagesWire::encode_messages_request(&spec).is_ok(),
    };
    let response = backend.invoke_structured(&spec)?;
    if response.raw_json_text.len() > MAX_JUDGE_RAW_JSON_BYTES {
        return Err(malformed_err(
            "backend raw_json_text exceeds MAX_JUDGE_RAW_JSON_BYTES",
        ));
    }
    let parsed: Value = serde_json::from_str(&response.raw_json_text)
        .map_err(|e| malformed_err(&format!("backend emitted non-JSON response: {e}")))?;
    let Some(obj) = parsed.as_object() else {
        return Err(malformed_err("backend response must be a JSON object"));
    };
    if obj.len() != 1 {
        return Err(malformed_err(
            "backend conformance response violated additionalProperties: false",
        ));
    }
    let Some(action) = obj.get("action").and_then(Value::as_str) else {
        return Err(malformed_err(
            "backend conformance response missing string `action`",
        ));
    };
    if !is_allowed_strict_p2_action(action) {
        return Err(CodedError::new(
            CODE_AI_PERMISSIVE_REJECTED,
            "backend attempted disallowed or non-canonical P2 action",
            "Models may only return restrict-only closed advisory actions.",
        ));
    }

    let model_clean = response.usage.model_id.trim();
    let has_real_model = !model_clean.is_empty() && !model_clean.eq_ignore_ascii_case("unknown");
    let usage_metered = has_real_model && response.usage.total_tokens() > 0;

    Ok(ConformanceReport {
        protocol: backend.protocol(),
        roundtrip_ok: wire_ok && !response.raw_json_text.is_empty(),
        usage_metered,
    })
}

fn is_allowed_strict_p2_action(action: &str) -> bool {
    matches!(
        action,
        "no_change" | "add_advisory_label" | "raise_review_priority" | "escalate_finding"
    )
}

fn validate_request_spec(req: &JudgeRequestSpec) -> Result<(), CodedError> {
    let schema_bytes = serde_json::to_vec(&req.json_schema)
        .map_err(|_| malformed_err("failed to serialize JudgeRequestSpec json_schema"))?;
    if req.job_id.trim().is_empty()
        || req.job_id.len() > MAX_JUDGE_ID_BYTES
        || req.job_kind.trim().is_empty()
        || req.job_kind.len() > MAX_JUDGE_ID_BYTES
        || req.model_id.trim().is_empty()
        || req.model_id.len() > MAX_JUDGE_MODEL_BYTES
        || req.system_instructions.trim().is_empty()
        || req.system_instructions.len() > MAX_JUDGE_SYSTEM_BYTES
        || req.max_output_tokens == 0
        || req.max_output_tokens > MAX_JUDGE_OUTPUT_TOKENS
        || req.timeout_ms == 0
        || req.timeout_ms > MAX_JUDGE_TIMEOUT_MS
        || req.temperature_milli > MAX_JUDGE_TEMPERATURE_MILLI
        || req.framed_user_prompt.len() > MAX_JUDGE_RAW_JSON_BYTES
        || !req.json_schema.is_object()
        || schema_bytes.len() > MAX_JUDGE_SCHEMA_BYTES
        || req.json_schema_name.is_empty()
        || req.json_schema_name.len() > 64
        || !req
            .json_schema_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(malformed_err(
            "invalid JudgeRequestSpec bounds or missing identifier",
        ));
    }
    Ok(())
}

fn extract_anthropic_json_payload(
    blocks: &[Value],
    expected_tool_name: &str,
) -> Result<String, CodedError> {
    if expected_tool_name.trim().is_empty() {
        return Err(malformed_err("expected_tool_name cannot be empty"));
    }
    let mut tool_use_blocks = blocks
        .iter()
        .filter(|b| b.get("type").and_then(Value::as_str) == Some("tool_use"));
    let Some(block) = tool_use_blocks.next() else {
        return Err(malformed_err("no tool_use block in Anthropic response"));
    };
    if tool_use_blocks.next().is_some() {
        return Err(malformed_err(
            "multiple tool_use blocks rejected in Anthropic response",
        ));
    }
    let name = block
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| malformed_err("missing tool_use name in Anthropic response"))?;
    if name != expected_tool_name {
        return Err(malformed_err("Anthropic tool_use name mismatch"));
    }
    let input = block
        .get("input")
        .filter(|v| v.is_object())
        .ok_or_else(|| malformed_err("Anthropic tool_use input must be an object"))?;
    serde_json::to_string(input).map_err(|_| malformed_err("failed to serialise tool_use input"))
}

fn decode_bounded_wire_field(
    val: Option<&Value>,
    max_bytes: usize,
    trim: bool,
    field_name: &str,
) -> Result<String, CodedError> {
    let Some(v) = val else {
        return Ok(String::new());
    };
    if v.is_null() {
        return Ok(String::new());
    }
    let Some(raw) = v.as_str() else {
        return Err(malformed_err(&format!(
            "judge response `{field_name}` must be a string"
        )));
    };
    if raw.len() > max_bytes || raw.chars().any(is_disallowed_wire_char) {
        return Err(malformed_err(&format!(
            "judge response `{field_name}` contains disallowed chars or exceeds {max_bytes} bytes"
        )));
    }
    Ok(if trim {
        raw.trim().to_owned()
    } else {
        raw.to_owned()
    })
}

fn is_disallowed_wire_char(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{070F}'
                | '\u{08E2}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{17B4}'
                | '\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E01EF}'
        )
}

fn malformed_err(msg: &str) -> CodedError {
    CodedError::new(
        CODE_AI_MALFORMED_RESPONSE,
        msg.to_owned(),
        "Collapse malformed judge output to could_not_look.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAnthropicBackend {
        action: String,
        model: Option<String>,
        tokens: u64,
    }

    impl JudgeBackend for MockAnthropicBackend {
        fn protocol(&self) -> BackendProtocol {
            BackendProtocol::Anthropic
        }

        fn backend_name(&self) -> &str {
            "mock-anthropic"
        }

        fn invoke_structured(
            &self,
            req: &JudgeRequestSpec,
        ) -> Result<JudgeRawResponse, CodedError> {
            let _encoded = AnthropicMessagesWire::encode_messages_request(req)?;
            let mut wire_resp = json!({
                "stop_reason": "tool_use",
                "content": [
                    {
                        "type": "tool_use",
                        "name": req.json_schema_name,
                        "input": { "action": self.action }
                    }
                ],
                "usage": {
                    "input_tokens": self.tokens,
                    "output_tokens": 0,
                    "cache_read_input_tokens": 0
                }
            });
            if let Some(m) = &self.model {
                wire_resp
                    .as_object_mut()
                    .expect("obj")
                    .insert("model".into(), json!(m));
            }
            AnthropicMessagesWire::decode_messages_response_for_tool(
                &wire_resp,
                self.backend_name(),
                &req.job_kind,
                &req.json_schema_name,
                1_700_000_000_000,
            )
        }
    }

    struct RawActionBackend(String);

    impl JudgeBackend for RawActionBackend {
        fn protocol(&self) -> BackendProtocol {
            BackendProtocol::OpenAiCompatible
        }
        fn backend_name(&self) -> &str {
            "mock-raw"
        }
        fn invoke_structured(
            &self,
            _req: &JudgeRequestSpec,
        ) -> Result<JudgeRawResponse, CodedError> {
            Ok(JudgeRawResponse {
                model_id: "gpt-test".into(),
                raw_json_text: self.0.clone(),
                stop_reason: "stop".into(),
                usage: TokenUsageLedger {
                    provider: "mock".into(),
                    model_id: "gpt-test".into(),
                    job_kind: "judge.conformance".into(),
                    prompt_tokens: 10,
                    completion_tokens: 5,
                    cached_tokens: 0,
                    recorded_at_ms: 0,
                },
            })
        }
    }

    #[test]
    fn openai_and_anthropic_wires_and_conformance_work_cleanly() {
        let report = verify_backend_conformance(&MockAnthropicBackend {
            action: "escalate_finding".into(),
            model: Some("claude-sonnet-conformance".into()),
            tokens: 160,
        })
        .expect("conformance ok");
        assert_eq!(report.protocol, BackendProtocol::Anthropic);
        assert!(report.roundtrip_ok);
        assert!(report.usage_metered);

        let oai_resp = json!({
            "model": "gpt-conformance",
            "choices": [{
                "finish_reason": "stop",
                "message": { "content": r#"{"action":"no_change"}"# }
            }],
            "usage": {
                "prompt_tokens": 90,
                "completion_tokens": 12,
                "prompt_tokens_details": { "cached_tokens": 30 }
            }
        });
        let decoded = OpenAiCompatibleWire::decode_chat_response(
            &oai_resp,
            "openai-compat",
            "review.finder",
            1_700_000_001_000,
        )
        .expect("oai decode");
        assert_eq!(decoded.usage.total_tokens(), 132);
    }

    #[test]
    fn negative_conformance_rejects_permissive_variants_unmetered_usage_and_text_fallback() {
        for bad_action in [
            "permit",
            "declassify",
            "bypass",
            "allow ",
            "no_change ",
            "approve",
            "tighten_to_step_up",
            "No_Change",
        ] {
            let err = verify_backend_conformance(&MockAnthropicBackend {
                action: bad_action.into(),
                model: Some("claude-sonnet".into()),
                tokens: 50,
            })
            .expect_err("must reject non-allowlisted action");
            assert_eq!(err.code, CODE_AI_PERMISSIVE_REJECTED);
        }

        for bad_json in [r#"{}"#, r#"{"action": 42}"#, r#"["no_change"]"#] {
            let err = verify_backend_conformance(&RawActionBackend(bad_json.into()))
                .expect_err("must reject missing/non-string action");
            assert_eq!(err.code, CODE_AI_MALFORMED_RESPONSE);
        }

        let no_model = verify_backend_conformance(&MockAnthropicBackend {
            action: "no_change".into(),
            model: None,
            tokens: 100,
        })
        .expect("report");
        assert!(!no_model.usage_metered);

        let unknown_model = verify_backend_conformance(&MockAnthropicBackend {
            action: "no_change".into(),
            model: Some("unknown".into()),
            tokens: 100,
        })
        .expect("report");
        assert!(!unknown_model.usage_metered);

        let zero_tokens = verify_backend_conformance(&MockAnthropicBackend {
            action: "no_change".into(),
            model: Some("claude-sonnet".into()),
            tokens: 0,
        })
        .expect("report");
        assert!(!zero_tokens.usage_metered);

        let text_only = json!({
            "model": "claude-sonnet",
            "content": [{ "type": "text", "text": r#"{"action":"no_change"}"# }]
        });
        assert!(
            AnthropicMessagesWire::decode_messages_response_for_tool(
                &text_only,
                "anthropic",
                "review",
                "advisory_finding",
                0
            )
            .is_err()
        );

        let wrong_tool = json!({
            "model": "claude-sonnet",
            "content": [{
                "type": "tool_use",
                "name": "other_tool",
                "input": { "action": "no_change" }
            }]
        });
        assert!(
            AnthropicMessagesWire::decode_messages_response_for_tool(
                &wrong_tool,
                "anthropic",
                "review",
                "advisory_finding",
                0
            )
            .is_err()
        );

        let bad_temp_spec = JudgeRequestSpec {
            job_id: "j1".into(),
            job_kind: "k1".into(),
            model_id: "m1".into(),
            system_instructions: "sys".into(),
            framed_user_prompt: "prompt".into(),
            max_output_tokens: 128,
            timeout_ms: 1000,
            temperature_milli: 5000,
            json_schema_name: "advisory_finding".into(),
            json_schema: json!({}),
        };
        assert!(OpenAiCompatibleWire::encode_chat_request(&bad_temp_spec).is_err());
    }

    #[test]
    fn round2_ai_wire_conformance_multi_tool_use_and_spec_bounds() {
        // Conformance rejects extra keys beyond {"action": ...}.
        assert!(
            verify_backend_conformance(&RawActionBackend(
                r#"{"action":"no_change","smuggled":true}"#.into()
            ))
            .is_err()
        );

        // Anthropic rejects multiple tool_use blocks and empty expected_tool_name.
        let multi_tool = serde_json::json!({
            "model": "claude-3-7-sonnet",
            "content": [
                { "type": "tool_use", "name": "advisory_finding", "input": { "action": "no_change" } },
                { "type": "tool_use", "name": "advisory_finding", "input": { "action": "escalate_finding" } }
            ],
            "usage": { "input_tokens": 10, "output_tokens": 5 }
        });
        assert!(
            AnthropicMessagesWire::decode_messages_response_for_tool(
                &multi_tool,
                "anthropic",
                "judge.review",
                "advisory_finding",
                1_700_000_000_000
            )
            .is_err()
        );
        let single_tool = serde_json::json!({
            "model": "claude-3-7-sonnet",
            "content": [
                { "type": "tool_use", "name": "advisory_finding", "input": { "action": "no_change" } }
            ],
            "usage": { "input_tokens": 10, "output_tokens": 5 }
        });
        assert!(
            AnthropicMessagesWire::decode_messages_response_for_tool(
                &single_tool,
                "anthropic",
                "judge.review",
                "",
                1_700_000_000_000
            )
            .is_err()
        );

        // Oversized system_instructions and json_schema rejected on both wires.
        let big_sys_spec = JudgeRequestSpec {
            job_id: "j1".into(),
            job_kind: "k1".into(),
            model_id: "m1".into(),
            system_instructions: "s".repeat(MAX_JUDGE_SYSTEM_BYTES + 1),
            framed_user_prompt: "prompt".into(),
            max_output_tokens: 128,
            timeout_ms: 1000,
            temperature_milli: 0,
            json_schema_name: "advisory_finding".into(),
            json_schema: json!({"type": "object"}),
        };
        assert!(OpenAiCompatibleWire::encode_chat_request(&big_sys_spec).is_err());
        assert!(AnthropicMessagesWire::encode_messages_request(&big_sys_spec).is_err());

        let big_schema_spec = JudgeRequestSpec {
            system_instructions: "sys".into(),
            json_schema: json!({"desc": "z".repeat(MAX_JUDGE_SCHEMA_BYTES + 1)}),
            ..big_sys_spec
        };
        assert!(OpenAiCompatibleWire::encode_chat_request(&big_schema_spec).is_err());
    }

    #[test]
    fn round4_rejects_multi_or_empty_openai_choices_and_untrimmed_anthropic_tool_name() {
        let empty_choices = json!({
            "model": "gpt-test",
            "choices": [],
            "usage": { "prompt_tokens": 5, "completion_tokens": 2 }
        });
        assert_eq!(
            OpenAiCompatibleWire::decode_chat_response(&empty_choices, "oai", "review", 0)
                .unwrap_err()
                .code,
            CODE_AI_MALFORMED_RESPONSE
        );

        let multi_choices = json!({
            "model": "gpt-test",
            "choices": [
                { "finish_reason": "stop", "message": { "content": r#"{"action":"no_change"}"# } },
                { "finish_reason": "stop", "message": { "content": r#"{"action":"escalate_finding"}"# } }
            ],
            "usage": { "prompt_tokens": 5, "completion_tokens": 2 }
        });
        assert_eq!(
            OpenAiCompatibleWire::decode_chat_response(&multi_choices, "oai", "review", 0)
                .unwrap_err()
                .code,
            CODE_AI_MALFORMED_RESPONSE
        );

        let padded_tool = json!({
            "model": "claude-sonnet",
            "content": [{
                "type": "tool_use",
                "name": " advisory_finding ",
                "input": { "action": "no_change" }
            }]
        });
        assert_eq!(
            AnthropicMessagesWire::decode_messages_response_for_tool(
                &padded_tool,
                "anthropic",
                "review",
                "advisory_finding",
                0
            )
            .unwrap_err()
            .code,
            CODE_AI_MALFORMED_RESPONSE
        );
    }

    #[test]
    fn round5_rejects_oversized_or_control_model_and_stop_reason_without_echo() {
        let long_model = "m".repeat(MAX_JUDGE_MODEL_BYTES + 1);
        let long_stop = "s".repeat(MAX_STOP_REASON_BYTES + 1);

        for bad_model in [long_model.as_str(), "gpt-4\nSECRET", "gpt-4\x1b[31m"] {
            let oai = json!({
                "model": bad_model,
                "choices": [{
                    "finish_reason": "stop",
                    "message": { "content": r#"{"action":"no_change"}"# }
                }]
            });
            let err = OpenAiCompatibleWire::decode_chat_response(&oai, "oai", "review", 0)
                .expect_err("must reject bad model");
            assert_eq!(err.code, CODE_AI_MALFORMED_RESPONSE);
            assert!(!err.to_string().contains("SECRET"));

            let anth = json!({
                "model": bad_model,
                "stop_reason": "tool_use",
                "content": [{
                    "type": "tool_use",
                    "name": "advisory_finding",
                    "input": { "action": "no_change" }
                }]
            });
            let a_err = AnthropicMessagesWire::decode_messages_response_for_tool(
                &anth,
                "anthropic",
                "review",
                "advisory_finding",
                0,
            )
            .expect_err("must reject bad model");
            assert_eq!(a_err.code, CODE_AI_MALFORMED_RESPONSE);
            assert!(!a_err.to_string().contains("SECRET"));
        }

        for bad_stop in [long_stop.as_str(), "stop\nSECRET", "stop\x00"] {
            let oai = json!({
                "model": "gpt-test",
                "choices": [{
                    "finish_reason": bad_stop,
                    "message": { "content": r#"{"action":"no_change"}"# }
                }]
            });
            let err = OpenAiCompatibleWire::decode_chat_response(&oai, "oai", "review", 0)
                .expect_err("must reject bad finish_reason");
            assert_eq!(err.code, CODE_AI_MALFORMED_RESPONSE);
            assert!(!err.to_string().contains("SECRET"));

            let anth = json!({
                "model": "claude-sonnet",
                "stop_reason": bad_stop,
                "content": [{
                    "type": "tool_use",
                    "name": "advisory_finding",
                    "input": { "action": "no_change" }
                }]
            });
            let a_err = AnthropicMessagesWire::decode_messages_response_for_tool(
                &anth,
                "anthropic",
                "review",
                "advisory_finding",
                0,
            )
            .expect_err("must reject bad stop_reason");
            assert_eq!(a_err.code, CODE_AI_MALFORMED_RESPONSE);
            assert!(!a_err.to_string().contains("SECRET"));
        }

        let null_fields = json!({
            "model": Value::Null,
            "choices": [{
                "finish_reason": Value::Null,
                "message": { "content": r#"{"action":"no_change"}"# }
            }]
        });
        let decoded = OpenAiCompatibleWire::decode_chat_response(&null_fields, "oai", "review", 0)
            .expect("null model/finish_reason allowed");
        assert_eq!(decoded.model_id, "");
        assert_eq!(decoded.stop_reason, "");
    }

    #[test]
    fn round6_rejects_bidi_zero_width_and_format_chars_in_wire_fields_without_echo() {
        for ch in [
            '\u{202A}',
            '\u{202E}',
            '\u{2066}',
            '\u{2069}',
            '\u{200B}',
            '\u{200F}',
            '\u{FEFF}',
            '\u{180E}',
            '\u{180F}',
            '\u{E0001}',
        ] {
            let bad_model = format!("gpt-4{ch}UNTRUSTED_MODEL_ECHO");
            let oai_model = json!({
                "model": bad_model,
                "choices": [{
                    "finish_reason": "stop",
                    "message": { "content": r#"{"action":"no_change"}"# }
                }]
            });
            let err = OpenAiCompatibleWire::decode_chat_response(&oai_model, "oai", "review", 0)
                .expect_err("must reject format/bidi char in model");
            assert_eq!(err.code, CODE_AI_MALFORMED_RESPONSE);
            assert!(!err.to_string().contains("UNTRUSTED_MODEL_ECHO"));

            let bad_stop = format!("tool_use{ch}UNTRUSTED_STOP_ECHO");
            let anth_stop = json!({
                "model": "claude-sonnet",
                "stop_reason": bad_stop,
                "content": [{
                    "type": "tool_use",
                    "name": "advisory_finding",
                    "input": { "action": "no_change" }
                }]
            });
            let a_err = AnthropicMessagesWire::decode_messages_response_for_tool(
                &anth_stop,
                "anthropic",
                "review",
                "advisory_finding",
                0,
            )
            .expect_err("must reject format/bidi char in stop_reason");
            assert_eq!(a_err.code, CODE_AI_MALFORMED_RESPONSE);
            assert!(!a_err.to_string().contains("UNTRUSTED_STOP_ECHO"));
        }
    }
}
