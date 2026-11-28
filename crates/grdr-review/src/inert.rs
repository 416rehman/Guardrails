// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Strictly inert text sanitizer and typed `Explain` / `Summarise` formatters (`SR-36`, `docs/design/19`).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const MAX_INERT_EXPLANATION_CHARS: usize = 500;
const MAX_INERT_RAW_BYTES: usize = 64 * 1024;
const MAX_ANSI_SEQ_BYTES: usize = 256;
const MAX_TIMELINE_REFS: usize = 16;
const MAX_REF_ID_LEN: usize = 128;

const URL_SCHEMES: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "file://",
    concat!("ws", "://"),
    "wss://",
    "ssh://",
    "smb://",
    "ldap://",
    "vscode://",
    "javascript:",
    "data:",
    "vbscript:",
    "mailto:",
    "blob:",
    "about:",
    "//",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InertExplanation {
    pub text: String,
    pub advisory_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistantContentOrigin {
    VerifiedModel,
    DeterministicFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplainFindingDraft {
    pub summary: String,
    pub rationale: String,
    pub referenced_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainFindingOutput {
    pub finding_id: String,
    pub rule_id: String,
    pub origin: AssistantContentOrigin,
    pub summary: InertExplanation,
    pub rationale: InertExplanation,
    pub referenced_ids: Vec<String>,
    pub advisory_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummariseSessionDraft {
    pub headline: String,
    pub timeline_narrative: String,
    pub referenced_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummariseSessionOutput {
    pub session_id: String,
    pub origin: AssistantContentOrigin,
    pub headline: InertExplanation,
    pub timeline_narrative: InertExplanation,
    pub referenced_ids: Vec<String>,
    pub advisory_only: bool,
}

/// Renders untrusted explanation or summary text as strictly inert plain text.
#[must_use]
pub fn render_inert_explanation(raw: &str) -> InertExplanation {
    render_inert_with_limit(raw, MAX_INERT_EXPLANATION_CHARS)
}

#[must_use]
pub(crate) fn render_inert_with_limit(raw: &str, max_chars: usize) -> InertExplanation {
    let mut end = raw.len().min(MAX_INERT_RAW_BYTES);
    while end > 0 && !raw.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let bounded_raw = raw.get(..end).unwrap_or("");
    let ansi_stripped = strip_ansi_sequences(bounded_raw);
    let mut cleaned = String::with_capacity(ansi_stripped.len().min(max_chars));
    for ch in ansi_stripped.chars() {
        if is_disallowed_display_char(ch) {
            continue;
        }
        let mapped = match ch {
            '<' => '(',
            '>' => ')',
            '\n' | '\r' | '\t' => ' ',
            c if c.is_control() => continue,
            c => c,
        };
        cleaned.push(mapped);
    }
    let pre_neutralized = neutralize_urls(cleaned.trim());
    let unlinked = strip_markdown_links(&pre_neutralized);
    let post_neutralized = neutralize_urls(&unlinked);
    let capped: String = post_neutralized.chars().take(max_chars).collect();

    InertExplanation {
        text: capped.trim().to_owned(),
        advisory_only: true,
    }
}

/// Validates model `Explain` output against resolved references and falls back
/// deterministically to template text when absent or ungrounded (`AI-23`).
#[must_use]
pub fn build_explain_finding_output(
    finding_id: &str,
    rule_id: &str,
    template_summary: &str,
    known_references: &BTreeSet<String>,
    model_draft: Option<&ExplainFindingDraft>,
) -> ExplainFindingOutput {
    let safe_finding_id = sanitize_ref_id(finding_id, "invalid-finding-id");
    let safe_rule_id = sanitize_ref_id(rule_id, "invalid-rule-id");
    if let Some(draft) = model_draft
        && all_references_resolve(&draft.referenced_ids, known_references)
    {
        let summary = render_inert_explanation(&draft.summary);
        let rationale = render_inert_explanation(&draft.rationale);
        if !summary.text.is_empty() && !rationale.text.is_empty() {
            return ExplainFindingOutput {
                finding_id: safe_finding_id,
                rule_id: safe_rule_id,
                origin: AssistantContentOrigin::VerifiedModel,
                summary,
                rationale,
                referenced_ids: dedup_bounded_refs(&draft.referenced_ids),
                advisory_only: true,
            };
        }
    }

    let fallback_refs: Vec<String> = [finding_id, rule_id]
        .into_iter()
        .filter(|id| is_valid_ref_id(id) && known_references.contains(*id))
        .map(str::to_owned)
        .collect();
    ExplainFindingOutput {
        finding_id: safe_finding_id.clone(),
        rule_id: safe_rule_id.clone(),
        origin: AssistantContentOrigin::DeterministicFallback,
        summary: render_inert_explanation(&format!(
            "Rule {safe_rule_id} matched finding {safe_finding_id}: {template_summary}"
        )),
        rationale: render_inert_explanation(
            "Generated from deterministic rule template without model inference.",
        ),
        referenced_ids: fallback_refs,
        advisory_only: true,
    }
}

/// Validates model `Summarise` output against resolved timeline references and
/// provides a deterministic event-timeline fallback when absent or invalid.
#[must_use]
pub fn build_summarise_session_output(
    session_id: &str,
    timeline_entries: &[String],
    known_references: &BTreeSet<String>,
    model_draft: Option<&SummariseSessionDraft>,
) -> SummariseSessionOutput {
    let safe_session_id = sanitize_ref_id(session_id, "invalid-session-id");
    if let Some(draft) = model_draft
        && all_references_resolve(&draft.referenced_ids, known_references)
    {
        let headline = render_inert_explanation(&draft.headline);
        let narrative = render_inert_explanation(&draft.timeline_narrative);
        if !headline.text.is_empty() && !narrative.text.is_empty() {
            return SummariseSessionOutput {
                session_id: safe_session_id,
                origin: AssistantContentOrigin::VerifiedModel,
                headline,
                timeline_narrative: narrative,
                referenced_ids: dedup_bounded_refs(&draft.referenced_ids),
                advisory_only: true,
            };
        }
    }

    let joined = timeline_entries
        .iter()
        .take(6)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    let fallback_refs: Vec<String> = known_references
        .iter()
        .filter(|id| is_valid_ref_id(id))
        .take(MAX_TIMELINE_REFS)
        .cloned()
        .collect();
    SummariseSessionOutput {
        session_id: safe_session_id.clone(),
        origin: AssistantContentOrigin::DeterministicFallback,
        headline: render_inert_explanation(&format!(
            "Session {safe_session_id}: {} recorded timeline events",
            timeline_entries.len()
        )),
        timeline_narrative: render_inert_explanation(if joined.is_empty() {
            "No notable timeline actions recorded."
        } else {
            &joined
        }),
        referenced_ids: fallback_refs,
        advisory_only: true,
    }
}

fn sanitize_ref_id(raw: &str, fallback: &str) -> String {
    let trimmed = raw.trim();
    if is_valid_ref_id(trimmed) {
        return trimmed.to_owned();
    }
    let cleaned: String = trimmed
        .chars()
        .filter(|&ch| {
            !ch.is_control()
                && !is_disallowed_display_char(ch)
                && !ch.is_whitespace()
                && ch != '<'
                && ch != '>'
        })
        .take(MAX_REF_ID_LEN)
        .collect();
    if cleaned.is_empty() {
        fallback.to_owned()
    } else {
        cleaned
    }
}

fn is_valid_ref_id(id: &str) -> bool {
    !id.trim().is_empty()
        && id.len() <= MAX_REF_ID_LEN
        && id.chars().all(|ch| {
            !ch.is_control()
                && !is_disallowed_display_char(ch)
                && !ch.is_whitespace()
                && ch != '<'
                && ch != '>'
        })
}

fn all_references_resolve(refs: &[String], known: &BTreeSet<String>) -> bool {
    !refs.is_empty()
        && refs.len() <= MAX_TIMELINE_REFS
        && refs
            .iter()
            .all(|id| is_valid_ref_id(id) && known.contains(id))
}

fn dedup_bounded_refs(refs: &[String]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for item in refs {
        if set.len() >= MAX_TIMELINE_REFS {
            break;
        }
        set.insert(item.clone());
    }
    set.into_iter().collect()
}

/// Strips `[label](target)` links in strict O(N) time via a single scan.
fn strip_markdown_links(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut bracket_stack: Vec<usize> = Vec::new();
    let mut no_close_paren_ahead = false;
    let mut idx: usize = 0;

    while idx < bytes.len() {
        let Some(&b) = bytes.get(idx) else {
            break;
        };
        if b == b'[' {
            bracket_stack.push(out.len());
            out.push('[');
            idx = idx.saturating_add(1);
            continue;
        }
        if b == b']'
            && bytes.get(idx.saturating_add(1)) == Some(&b'(')
            && !bracket_stack.is_empty()
            && !no_close_paren_ahead
        {
            let target_start = idx.saturating_add(2);
            let close_rel = bytes
                .get(target_start..)
                .and_then(|tail| tail.iter().position(|c| *c == b')'));
            if let Some(rel) = close_rel
                && let Some(open_out_idx) = bracket_stack.pop()
            {
                let label_start = open_out_idx.saturating_add(1);
                if label_start <= out.len() {
                    let label = out.get(label_start..).unwrap_or("").to_owned();
                    out.truncate(open_out_idx);
                    out.push_str(&label);
                    idx = target_start.saturating_add(rel).saturating_add(1);
                    continue;
                }
            } else if close_rel.is_none() {
                no_close_paren_ahead = true;
            }
        }
        let Some(tail) = input.get(idx..) else {
            break;
        };
        let Some(ch) = tail.chars().next() else {
            break;
        };
        out.push(ch);
        idx = idx.saturating_add(ch.len_utf8());
    }
    out
}

fn strip_ansi_sequences(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes.get(idx) == Some(&0x1B) {
            idx = skip_esc_sequence(raw, bytes, idx);
            continue;
        }
        let Some(tail) = raw.get(idx..) else {
            break;
        };
        let Some(ch) = tail.chars().next() else {
            break;
        };
        idx = idx.saturating_add(ch.len_utf8());
        if matches!(
            ch,
            '\u{009B}' | '\u{009D}' | '\u{0090}' | '\u{0098}' | '\u{009E}' | '\u{009F}'
        ) {
            idx = skip_c1_body(raw, bytes, idx, ch == '\u{009B}');
            continue;
        }
        out.push(ch);
    }
    out
}

fn skip_esc_sequence(raw: &str, bytes: &[u8], esc_idx: usize) -> usize {
    let next_idx = esc_idx.saturating_add(1);
    let Some(&kind) = bytes.get(next_idx) else {
        return bytes.len();
    };
    let intro_two = next_idx.saturating_add(1);
    let candidate = match kind {
        b'[' => scan_csi_body(bytes, intro_two).unwrap_or(intro_two),
        b']' | b'P' | b'X' | b'^' | b'_' => {
            scan_st_body(raw, bytes, intro_two).unwrap_or(intro_two)
        }
        0x40..=0x5F => intro_two,
        _ => next_idx,
    };
    ensure_char_boundary(raw, candidate, next_idx)
}

fn skip_c1_body(raw: &str, bytes: &[u8], start: usize, is_csi: bool) -> usize {
    let candidate = if is_csi {
        scan_csi_body(bytes, start).unwrap_or(start)
    } else {
        scan_st_body(raw, bytes, start).unwrap_or(start)
    };
    ensure_char_boundary(raw, candidate, start)
}

fn scan_csi_body(bytes: &[u8], start: usize) -> Option<usize> {
    let limit = bytes.len().min(start.saturating_add(MAX_ANSI_SEQ_BYTES));
    let mut cur = start;
    while cur < limit {
        let &b = bytes.get(cur)?;
        if (0x40..=0x7E).contains(&b) {
            return Some(cur.saturating_add(1));
        }
        if !(0x20..=0x3F).contains(&b) {
            return None;
        }
        cur = cur.saturating_add(1);
    }
    None
}

fn scan_st_body(raw: &str, bytes: &[u8], start: usize) -> Option<usize> {
    let limit = bytes.len().min(start.saturating_add(MAX_ANSI_SEQ_BYTES));
    let mut cur = start;
    while cur < limit {
        let &b = bytes.get(cur)?;
        if b == 0x07 {
            return Some(cur.saturating_add(1));
        }
        if b == 0x1B {
            if bytes.get(cur.saturating_add(1)) == Some(&b'\\') {
                return Some(cur.saturating_add(2));
            }
            return None;
        }
        if raw.is_char_boundary(cur)
            && let Some(tail) = raw.get(cur..)
            && let Some('\u{009C}') = tail.chars().next()
        {
            return Some(cur.saturating_add('\u{009C}'.len_utf8()));
        }
        cur = cur.saturating_add(1);
    }
    None
}

fn ensure_char_boundary(raw: &str, candidate: usize, fallback: usize) -> usize {
    if raw.is_char_boundary(candidate) {
        candidate
    } else if raw.is_char_boundary(fallback) {
        fallback
    } else {
        raw.len()
    }
}

pub(crate) fn is_disallowed_display_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{070F}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E00FF}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

fn neutralize_urls(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut pos: usize = 0;

    while pos < input.len() {
        if let Some((hit_pos, scheme)) = find_earliest_url_scheme(&lower, pos) {
            if let Some(prefix) = input.get(pos..hit_pos) {
                out.push_str(prefix);
            }
            out.push_str("[redacted-url]");
            pos = advance_past_url_token(input, hit_pos.saturating_add(scheme.len()));
            continue;
        }
        if let Some(tail) = input.get(pos..) {
            out.push_str(tail);
        }
        break;
    }
    out
}

fn find_earliest_url_scheme(lower: &str, from: usize) -> Option<(usize, &'static str)> {
    let tail = lower.get(from..)?;
    let mut best: Option<(usize, &'static str)> = None;
    for &scheme in URL_SCHEMES {
        if let Some(rel) = tail.find(scheme) {
            let abs = from.saturating_add(rel);
            if best.is_none_or(|(best_pos, _)| abs < best_pos) {
                best = Some((abs, scheme));
            }
        }
    }
    best
}

fn advance_past_url_token(input: &str, start: usize) -> usize {
    let mut idx = start;
    let mut paren_depth: usize = 0;
    while let Some(tail) = input.get(idx..) {
        let Some(ch) = tail.chars().next() else {
            break;
        };
        if ch.is_whitespace() || matches!(ch, '"' | '\'' | ']' | '}' | '>') {
            break;
        }
        if ch == '(' {
            paren_depth = paren_depth.saturating_add(1);
        } else if ch == ')' {
            if paren_depth == 0 {
                break;
            }
            paren_depth = paren_depth.saturating_sub(1);
        }
        idx = idx.saturating_add(ch.len_utf8());
    }
    idx
}
