// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! 24k token review reducer preserving whole action/finding records and 2 KB head + 1 KB tail cuts (`docs/design/19`).

use serde::{Deserialize, Serialize};

use grdr_crypto::{domain_hmac_sha256, encode_lower_hex};
use grdr_model::DataClass;
use grdr_schema::limits::load_embedded_limits;

pub const MAX_REDUCED_TOKENS: usize = 24_000;
const TOOL_HEAD_BYTES: usize = 2_048;
const TOOL_TAIL_BYTES: usize = 1_024;
pub const ELISION_MARKER: &str = "\n[...elided...]\n";
const CLASS_COMMIT_DOMAIN: &str = "grdr.review.class-commit.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRecordKind {
    Action,
    Finding,
    ToolOutput,
    UserPrompt,
    Policy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSegment {
    pub record_id: String,
    pub kind: ReviewRecordKind,
    pub data_class: DataClass,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanOffsetMapEntry {
    pub record_id: String,
    pub reduced_start: u64,
    pub reduced_end: u64,
    pub source_start: u64,
    pub source_end: u64,
    pub class_commitment_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReducedTranscript {
    pub token_count_approx: u64,
    pub partial: bool,
    pub offset_map: Vec<SpanOffsetMapEntry>,
    pub reduced_records: Vec<SourceSegment>,
}

impl ReviewRecordKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::Finding => "finding",
            Self::ToolOutput => "tool_output",
            Self::UserPrompt => "user_prompt",
            Self::Policy => "policy",
        }
    }

    #[must_use]
    pub const fn trust_label(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Action | Self::Finding => "derived",
            Self::UserPrompt => "user-claimed",
            Self::ToolOutput => "untrusted",
        }
    }

    #[must_use]
    pub const fn must_keep_whole(self) -> bool {
        matches!(self, Self::Action | Self::Finding | Self::Policy)
    }
}

/// Computes a salted HMAC-SHA256 commitment binding `(record_id, data_class, plain_text)`.
#[must_use]
pub fn salted_class_commitment(
    class_salt: &[u8; 32],
    record_id: &str,
    class: DataClass,
    plain_text: &str,
) -> String {
    let mut buf = Vec::new();
    append_len_prefixed(&mut buf, record_id.as_bytes());
    append_len_prefixed(&mut buf, class.as_str().as_bytes());
    append_len_prefixed(&mut buf, plain_text.as_bytes());
    let mac = domain_hmac_sha256(class_salt, CLASS_COMMIT_DOMAIN, &buf);
    encode_lower_hex(&mac)
}

/// Reduces session records to at most `24_000` approximate tokens (clamped by `limits.endpoint.ipc.max_frame_bytes`),
/// keeping action/finding records whole, preserving 2 KB head + 1 KB tail on long tool outputs,
/// marking `partial` when any content is cut or omitted, and never emitting empty segments.
#[must_use]
pub fn reduce_for_review(
    segments: &[SourceSegment],
    max_tokens: usize,
    class_salt: &[u8; 32],
) -> ReducedTranscript {
    let frame_cap = load_embedded_limits()
        .map(|l| l.endpoint.ipc.max_frame_bytes)
        .unwrap_or(1_048_576);
    let cap_tokens = max_tokens.clamp(1, MAX_REDUCED_TOKENS);
    let approx_char_budget = cap_tokens.saturating_mul(4).min(frame_cap);

    let mut reserved_whole_bytes: usize = 0;
    let mut keep_whole = vec![false; segments.len()];
    let mut partial = false;
    for (idx, seg) in segments.iter().enumerate() {
        if seg.text.is_empty() || !seg.kind.must_keep_whole() {
            continue;
        }
        if reserved_whole_bytes.saturating_add(seg.text.len()) <= approx_char_budget {
            reserved_whole_bytes = reserved_whole_bytes.saturating_add(seg.text.len());
            if let Some(slot) = keep_whole.get_mut(idx) {
                *slot = true;
            }
        } else {
            partial = true;
        }
    }

    let mut flex_remaining = approx_char_budget.saturating_sub(reserved_whole_bytes);
    let mut used_bytes: usize = 0;
    let mut reduced_records = Vec::new();
    let mut offset_map = Vec::new();
    let head_tail_max = TOOL_HEAD_BYTES
        .saturating_add(TOOL_TAIL_BYTES)
        .saturating_add(ELISION_MARKER.len());

    for (idx, seg) in segments.iter().enumerate() {
        if seg.text.is_empty() {
            continue;
        }
        if seg.kind.must_keep_whole() {
            if !keep_whole.get(idx).copied().unwrap_or(false) {
                partial = true;
                continue;
            }
            let commit =
                salted_class_commitment(class_salt, &seg.record_id, seg.data_class, &seg.text);
            let seg_len = seg.text.len();
            offset_map.push(SpanOffsetMapEntry {
                record_id: seg.record_id.clone(),
                reduced_start: 0,
                reduced_end: to_u64(seg_len),
                source_start: 0,
                source_end: to_u64(seg_len),
                class_commitment_sha256: commit,
            });
            used_bytes = used_bytes.saturating_add(seg_len);
            reduced_records.push(seg.clone());
            continue;
        }

        if flex_remaining == 0 {
            partial = true;
            continue;
        }
        if seg.text.len() <= flex_remaining && seg.text.len() <= head_tail_max {
            let commit =
                salted_class_commitment(class_salt, &seg.record_id, seg.data_class, &seg.text);
            let seg_len = seg.text.len();
            offset_map.push(SpanOffsetMapEntry {
                record_id: seg.record_id.clone(),
                reduced_start: 0,
                reduced_end: to_u64(seg_len),
                source_start: 0,
                source_end: to_u64(seg_len),
                class_commitment_sha256: commit,
            });
            flex_remaining = flex_remaining.saturating_sub(seg_len);
            used_bytes = used_bytes.saturating_add(seg_len);
            reduced_records.push(seg.clone());
            continue;
        }

        partial = true;
        let Some((cut_text, head_end, tail_start)) =
            build_head_tail_slice(&seg.text, flex_remaining)
        else {
            continue;
        };
        let full_commit =
            salted_class_commitment(class_salt, &seg.record_id, seg.data_class, &seg.text);
        offset_map.push(SpanOffsetMapEntry {
            record_id: seg.record_id.clone(),
            reduced_start: 0,
            reduced_end: to_u64(head_end),
            source_start: 0,
            source_end: to_u64(head_end),
            class_commitment_sha256: full_commit.clone(),
        });
        if let Some(t_start) = tail_start {
            let tail_len = seg.text.len().saturating_sub(t_start);
            let red_tail_start = head_end.saturating_add(ELISION_MARKER.len());
            offset_map.push(SpanOffsetMapEntry {
                record_id: seg.record_id.clone(),
                reduced_start: to_u64(red_tail_start),
                reduced_end: to_u64(red_tail_start.saturating_add(tail_len)),
                source_start: to_u64(t_start),
                source_end: to_u64(seg.text.len()),
                class_commitment_sha256: full_commit,
            });
        }
        flex_remaining = flex_remaining.saturating_sub(cut_text.len());
        used_bytes = used_bytes.saturating_add(cut_text.len());
        reduced_records.push(SourceSegment {
            record_id: seg.record_id.clone(),
            kind: seg.kind,
            data_class: seg.data_class,
            text: cut_text,
        });
    }

    ReducedTranscript {
        token_count_approx: to_u64(used_bytes.div_ceil(4)),
        partial,
        offset_map,
        reduced_records,
    }
}

fn build_head_tail_slice(
    text: &str,
    remaining_budget: usize,
) -> Option<(String, usize, Option<usize>)> {
    if remaining_budget == 0 {
        return None;
    }
    let min_needed_for_head_tail = ELISION_MARKER.len().saturating_add(8);
    if remaining_budget < min_needed_for_head_tail {
        let end = floor_char_boundary(text, remaining_budget);
        if end == 0 {
            return None;
        }
        let head = text.get(..end)?.to_owned();
        return Some((head, end, None));
    }

    let usable = remaining_budget.saturating_sub(ELISION_MARKER.len());
    let head_cap = TOOL_HEAD_BYTES.min(usable);
    let head_end = floor_char_boundary(text, head_cap);
    if head_end == 0 {
        return None;
    }

    let tail_budget = TOOL_TAIL_BYTES.min(usable.saturating_sub(head_end));
    if tail_budget == 0 || head_end >= text.len() {
        let head = text.get(..head_end)?.to_owned();
        return Some((head, head_end, None));
    }

    let raw_tail_start = text.len().saturating_sub(tail_budget).max(head_end);
    let tail_start = ceil_char_boundary(text, raw_tail_start);
    if tail_start >= text.len() {
        let head = text.get(..head_end)?.to_owned();
        return Some((head, head_end, None));
    }

    let head = text.get(..head_end)?;
    let tail = text.get(tail_start..)?;
    Some((
        format!("{head}{ELISION_MARKER}{tail}"),
        head_end,
        Some(tail_start),
    ))
}

fn floor_char_boundary(s: &str, idx: usize) -> usize {
    let mut end = idx.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    end
}

fn ceil_char_boundary(s: &str, idx: usize) -> usize {
    let mut start = idx.min(s.len());
    while start < s.len() && !s.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    start
}

fn to_u64(v: usize) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

pub(crate) fn append_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}
