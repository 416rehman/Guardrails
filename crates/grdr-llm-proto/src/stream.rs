// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProtoError;
use crate::schema::ProviderFamily;
use crate::strict_json::{
    MAX_JSON_DEPTH, MAX_SSE_EVENT_BYTES, decode_base64_std, parse_strict_json_str,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    pub event: Option<String>,
    pub id: Option<String>,
    pub data: String,
    pub retry_ms: Option<u64>,
    pub is_done: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamedToolCall {
    pub index: usize,
    pub call_id: Option<String>,
    pub name: Option<String>,
    pub arguments_delta: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmStreamDelta {
    pub family: ProviderFamily,
    pub event_type: Option<String>,
    pub text_delta: String,
    pub tool_calls: Vec<StreamedToolCall>,
    pub stop_reason: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub finished: bool,
}

#[derive(Debug, Clone)]
pub struct SseLineDecoder {
    pending: Vec<u8>,
    event_name: Option<String>,
    event_id: Option<String>,
    data_lines: Vec<String>,
    retry_ms: Option<u64>,
    max_event_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct LlmStreamInspector {
    family: ProviderFamily,
    decoder: SseLineDecoder,
}

impl SseLineDecoder {
    #[must_use]
    pub fn new(max_event_bytes: usize) -> Self {
        Self {
            pending: Vec::new(),
            event_name: None,
            event_id: None,
            data_lines: Vec::new(),
            retry_ms: None,
            max_event_bytes: max_event_bytes.min(MAX_SSE_EVENT_BYTES),
        }
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<SseFrame>, ProtoError> {
        if self.pending.len().saturating_add(chunk.len()) > self.max_event_bytes {
            return Err(ProtoError::PayloadTooLarge);
        }
        self.pending.extend_from_slice(chunk);
        let mut frames = Vec::new();
        while let Some(line_bytes) = take_next_sse_line(&mut self.pending) {
            let line = std::str::from_utf8(&line_bytes)
                .map_err(|_| ProtoError::Parse("non-UTF8 SSE line".to_string()))?;
            if let Some(frame) = self.consume_line(line)? {
                frames.push(frame);
            }
        }
        Ok(frames)
    }

    #[must_use]
    pub fn has_unflushed_state(&self) -> bool {
        !self.pending.is_empty() || !self.data_lines.is_empty() || self.event_name.is_some()
    }

    pub fn finish(&mut self) -> Result<Option<SseFrame>, ProtoError> {
        if !self.pending.is_empty() {
            let raw = std::mem::take(&mut self.pending);
            let s = std::str::from_utf8(&raw)
                .map_err(|_| ProtoError::Parse("non-UTF8 SSE trailing bytes".to_string()))?;
            let line = s.strip_suffix('\r').unwrap_or(s);
            if let Some(frame) = self.consume_line(line)? {
                return Ok(Some(frame));
            }
        }
        self.flush_event()
    }

    fn consume_line(&mut self, line: &str) -> Result<Option<SseFrame>, ProtoError> {
        if line.is_empty() {
            return self.flush_event();
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, val) = match line.split_once(':') {
            Some((k, v)) => (k, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => self.event_name = Some(val.to_string()),
            "id" => self.event_id = Some(val.to_string()),
            "retry" => {
                if let Ok(ms) = val.parse::<u64>() {
                    self.retry_ms = Some(ms);
                }
            }
            "data" => {
                let current_len: usize = self
                    .data_lines
                    .iter()
                    .map(|s| s.len().saturating_add(1))
                    .sum();
                if current_len.saturating_add(val.len()) > self.max_event_bytes {
                    return Err(ProtoError::PayloadTooLarge);
                }
                self.data_lines.push(val.to_string());
            }
            _ => {}
        }
        Ok(None)
    }

    fn flush_event(&mut self) -> Result<Option<SseFrame>, ProtoError> {
        if self.data_lines.is_empty() && self.event_name.is_none() {
            return Ok(None);
        }
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        let is_done = data.trim() == "[DONE]";
        Ok(Some(SseFrame {
            event: self.event_name.take(),
            id: self.event_id.take(),
            data,
            retry_ms: self.retry_ms.take(),
            is_done,
        }))
    }
}

impl LlmStreamInspector {
    #[must_use]
    pub fn new(family: ProviderFamily) -> Self {
        Self {
            family,
            decoder: SseLineDecoder::new(MAX_SSE_EVENT_BYTES),
        }
    }

    pub fn push_sse_chunk(&mut self, chunk: &[u8]) -> Result<Vec<LlmStreamDelta>, ProtoError> {
        let frames = self.decoder.push_chunk(chunk)?;
        let mut out = Vec::with_capacity(frames.len());
        for frame in &frames {
            out.push(self.inspect_sse_frame(frame)?);
        }
        Ok(out)
    }

    pub fn finish_sse(&mut self) -> Result<Option<LlmStreamDelta>, ProtoError> {
        match self.decoder.finish()? {
            Some(frame) => Ok(Some(self.inspect_sse_frame(&frame)?)),
            None => Ok(None),
        }
    }

    #[must_use]
    pub fn has_unflushed_state(&self) -> bool {
        self.decoder.has_unflushed_state()
    }

    pub fn inspect_sse_frame(&self, frame: &SseFrame) -> Result<LlmStreamDelta, ProtoError> {
        if frame.is_done {
            return Ok(empty_delta(self.family, frame.event.clone(), true));
        }
        let trimmed = frame.data.trim();
        if trimmed.is_empty() {
            return Ok(empty_delta(self.family, frame.event.clone(), false));
        }
        let val = parse_strict_json_str(trimmed, MAX_SSE_EVENT_BYTES, MAX_JSON_DEPTH)?;
        match self.family {
            ProviderFamily::AnthropicMessages => parse_anthropic_delta(frame.event.clone(), &val),
            ProviderFamily::OpenAiChat => parse_openai_chat_delta(frame.event.clone(), &val),
            ProviderFamily::OpenAiResponses => {
                parse_openai_responses_delta(frame.event.clone(), &val)
            }
            ProviderFamily::GoogleGemini => parse_gemini_delta(frame.event.clone(), &val),
            ProviderFamily::AwsBedrock => parse_bedrock_json_delta(frame.event.clone(), &val),
            _ => Ok(empty_delta(self.family, frame.event.clone(), false)),
        }
    }
}

fn parse_anthropic_delta(
    event_hint: Option<String>,
    val: &Value,
) -> Result<LlmStreamDelta, ProtoError> {
    let ev = val
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or(event_hint);
    let mut delta = empty_delta(ProviderFamily::AnthropicMessages, ev.clone(), false);
    match ev.as_deref() {
        Some("content_block_start") => {
            if let Some(cb) = val.get("content_block")
                && cb.get("type").and_then(Value::as_str) == Some("tool_use")
            {
                let idx = usize::try_from(val.get("index").and_then(Value::as_u64).unwrap_or(0))
                    .unwrap_or(0);
                delta.tool_calls.push(StreamedToolCall {
                    index: idx,
                    call_id: cb.get("id").and_then(Value::as_str).map(str::to_string),
                    name: cb.get("name").and_then(Value::as_str).map(str::to_string),
                    arguments_delta: String::new(),
                });
            }
        }
        Some("content_block_delta") => {
            if let Some(d) = val.get("delta") {
                if let Some(txt) = d.get("text").and_then(Value::as_str) {
                    delta.text_delta = txt.to_string();
                } else if let Some(partial) = d.get("partial_json").and_then(Value::as_str) {
                    let idx =
                        usize::try_from(val.get("index").and_then(Value::as_u64).unwrap_or(0))
                            .unwrap_or(0);
                    delta.tool_calls.push(StreamedToolCall {
                        index: idx,
                        call_id: None,
                        name: None,
                        arguments_delta: partial.to_string(),
                    });
                }
            }
        }
        Some("message_delta") => {
            delta.stop_reason = val
                .get("delta")
                .and_then(|d| d.get("stop_reason"))
                .and_then(Value::as_str)
                .map(str::to_string);
            delta.output_tokens = val
                .get("usage")
                .and_then(|u| u.get("output_tokens"))
                .and_then(Value::as_u64);
        }
        Some("message_start") => {
            delta.input_tokens = val
                .get("message")
                .and_then(|m| m.get("usage"))
                .and_then(|u| u.get("input_tokens"))
                .and_then(Value::as_u64);
        }
        Some("message_stop") => delta.finished = true,
        _ => {}
    }
    Ok(delta)
}

fn parse_openai_chat_delta(
    event_hint: Option<String>,
    val: &Value,
) -> Result<LlmStreamDelta, ProtoError> {
    let mut delta = empty_delta(ProviderFamily::OpenAiChat, event_hint, false);
    if let Some(usage) = val.get("usage") {
        delta.input_tokens = usage.get("prompt_tokens").and_then(Value::as_u64);
        delta.output_tokens = usage.get("completion_tokens").and_then(Value::as_u64);
    }
    if let Some(choices) = val.get("choices").and_then(Value::as_array) {
        for choice in choices {
            if let Some(fr) = choice.get("finish_reason").and_then(Value::as_str) {
                delta.stop_reason = Some(fr.to_string());
                delta.finished = true;
            }
            if let Some(d) = choice.get("delta") {
                if let Some(content) = d.get("content").and_then(Value::as_str) {
                    delta.text_delta.push_str(content);
                }
                collect_openai_tool_deltas(d, &mut delta.tool_calls);
            }
        }
    }
    Ok(delta)
}

fn collect_openai_tool_deltas(d: &Value, out: &mut Vec<StreamedToolCall>) {
    let Some(tcs) = d.get("tool_calls").and_then(Value::as_array) else {
        return;
    };
    for tc in tcs {
        let idx =
            usize::try_from(tc.get("index").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0);
        let func = tc.get("function");
        out.push(StreamedToolCall {
            index: idx,
            call_id: tc.get("id").and_then(Value::as_str).map(str::to_string),
            name: func
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
                .map(str::to_string),
            arguments_delta: func
                .and_then(|f| f.get("arguments"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
}

fn parse_openai_responses_delta(
    event_hint: Option<String>,
    val: &Value,
) -> Result<LlmStreamDelta, ProtoError> {
    let ev = val
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or(event_hint);
    let mut delta = empty_delta(ProviderFamily::OpenAiResponses, ev.clone(), false);
    match ev.as_deref() {
        Some("response.output_text.delta") => {
            if let Some(txt) = val.get("delta").and_then(Value::as_str) {
                delta.text_delta = txt.to_string();
            }
        }
        Some("response.output_item.added") => {
            if let Some(item) = val.get("item")
                && item.get("type").and_then(Value::as_str) == Some("function_call")
            {
                let idx =
                    usize::try_from(val.get("output_index").and_then(Value::as_u64).unwrap_or(0))
                        .unwrap_or(0);
                delta.tool_calls.push(StreamedToolCall {
                    index: idx,
                    call_id: item
                        .get("call_id")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    name: item.get("name").and_then(Value::as_str).map(str::to_string),
                    arguments_delta: String::new(),
                });
            }
        }
        Some("response.function_call_arguments.delta") => {
            let idx = usize::try_from(val.get("output_index").and_then(Value::as_u64).unwrap_or(0))
                .unwrap_or(0);
            delta.tool_calls.push(StreamedToolCall {
                index: idx,
                call_id: val
                    .get("item_id")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                name: None,
                arguments_delta: val
                    .get("delta")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            });
        }
        Some("response.completed") => {
            delta.finished = true;
            if let Some(resp) = val.get("response") {
                delta.stop_reason = resp
                    .get("status")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if let Some(usage) = resp.get("usage") {
                    delta.input_tokens = usage.get("input_tokens").and_then(Value::as_u64);
                    delta.output_tokens = usage.get("output_tokens").and_then(Value::as_u64);
                }
            }
        }
        _ => {}
    }
    Ok(delta)
}

fn parse_gemini_delta(
    event_hint: Option<String>,
    val: &Value,
) -> Result<LlmStreamDelta, ProtoError> {
    let mut delta = empty_delta(ProviderFamily::GoogleGemini, event_hint, false);
    if let Some(usage) = val.get("usageMetadata") {
        delta.input_tokens = usage.get("promptTokenCount").and_then(Value::as_u64);
        delta.output_tokens = usage.get("candidatesTokenCount").and_then(Value::as_u64);
    }
    let Some(cands) = val.get("candidates").and_then(Value::as_array) else {
        return Ok(delta);
    };
    for cand in cands {
        if let Some(fr) = cand.get("finishReason").and_then(Value::as_str) {
            delta.stop_reason = Some(fr.to_string());
            delta.finished = true;
        }
        let Some(parts) = cand
            .get("content")
            .and_then(|c| c.get("parts"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for (idx, part) in parts.iter().enumerate() {
            if let Some(txt) = part.get("text").and_then(Value::as_str) {
                delta.text_delta.push_str(txt);
            }
            if let Some(fc) = part.get("functionCall") {
                delta.tool_calls.push(StreamedToolCall {
                    index: idx,
                    call_id: None,
                    name: fc.get("name").and_then(Value::as_str).map(str::to_string),
                    arguments_delta: fc.get("args").map_or_else(String::new, Value::to_string),
                });
            }
        }
    }
    Ok(delta)
}

fn parse_bedrock_json_delta(
    event_hint: Option<String>,
    val: &Value,
) -> Result<LlmStreamDelta, ProtoError> {
    if let Some(b64) = val.get("bytes").and_then(Value::as_str)
        && let Some(raw) = decode_base64_std(b64)
        && let Ok(text) = std::str::from_utf8(&raw)
        && let Ok(inner) = parse_strict_json_str(text, MAX_SSE_EVENT_BYTES, MAX_JSON_DEPTH)
    {
        return parse_anthropic_delta(event_hint, &inner);
    }
    let mut delta = empty_delta(ProviderFamily::AwsBedrock, event_hint, false);
    if let Some(txt) = val
        .get("delta")
        .and_then(|d| d.get("text"))
        .and_then(Value::as_str)
    {
        delta.text_delta = txt.to_string();
    }
    if let Some(tu) = val.get("start").and_then(|s| s.get("toolUse")) {
        delta.tool_calls.push(StreamedToolCall {
            index: usize::try_from(
                val.get("contentBlockIndex")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
            .unwrap_or(0),
            call_id: tu
                .get("toolUseId")
                .and_then(Value::as_str)
                .map(str::to_string),
            name: tu.get("name").and_then(Value::as_str).map(str::to_string),
            arguments_delta: String::new(),
        });
    }
    if let Some(sr) = val.get("stopReason").and_then(Value::as_str) {
        delta.stop_reason = Some(sr.to_string());
        delta.finished = true;
    }
    Ok(delta)
}

fn take_next_sse_line(pending: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut i = 0usize;
    while let Some(&b) = pending.get(i) {
        if b == b'\n' {
            let mut line: Vec<u8> = pending.drain(..i.saturating_add(1)).collect();
            line.truncate(i);
            return Some(line);
        }
        if b == b'\r' {
            let next_pos = i.saturating_add(1);
            let &next_b = pending.get(next_pos)?;
            let drain_end = if next_b == b'\n' {
                i.saturating_add(2)
            } else {
                next_pos
            };
            let mut line: Vec<u8> = pending.drain(..drain_end).collect();
            line.truncate(i);
            return Some(line);
        }
        i = i.saturating_add(1);
    }
    None
}

fn empty_delta(
    family: ProviderFamily,
    event_type: Option<String>,
    finished: bool,
) -> LlmStreamDelta {
    LlmStreamDelta {
        family,
        event_type,
        text_delta: String::new(),
        tool_calls: Vec::new(),
        stop_reason: None,
        input_tokens: None,
        output_tokens: None,
        finished,
    }
}
