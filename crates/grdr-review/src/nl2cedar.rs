// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Watch-only `nl2cedar` AST draft builder and inert `Explain` / `Summarise` sanitizers (`docs/design/19`, `P2`).

use serde::{Deserialize, Serialize};

use grdr_model::{ActionClass, ApprovalGrade, CodedError, Mode};
use grdr_schema::cedar::{CedarPlane, resource_entity_type_for_action, validate_policy_source};

use crate::ReviewRequirement;

pub const CODE_REV_NL2CEDAR_FORBIDDEN: &str = "GRDR-REV-0007";
pub const MAX_INERT_EXPLANATION_CHARS: usize = 500;
const MAX_INERT_RAW_BYTES: usize = 64 * 1024;
const MAX_NL2CEDAR_PROMPT_BYTES: usize = 4_096;
const MAX_ANSI_SEQ_BYTES: usize = 256;
const MAX_RULE_ID_LEN: usize = 64;

const URL_SCHEMES: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "file://",
    concat!("ws", "://"),
    "wss://",
    "javascript:",
    "data:",
    "vbscript:",
];

const PERMISSIVE_TOKENS: &[&str] = &[
    "permit",
    "allow",
    "grant",
    "bypass",
    "suppress",
    "disable rule",
    "turn off",
    "mode: off",
    "unrestrict",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nl2CedarTargetRule {
    pub keywords: Vec<String>,
    pub action_class: ActionClass,
    pub target_prefix: String,
    pub resource_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nl2CedarTargetCatalog {
    pub rules: Vec<Nl2CedarTargetRule>,
    pub fallback_action: ActionClass,
    pub fallback_prefix: String,
    pub fallback_class: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftMode {
    WatchOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CedarDraftRule {
    pub rule_id: String,
    pub mode: DraftMode,
    pub mapped_mode: Mode,
    pub effect: String,
    pub action_class: ActionClass,
    pub target_prefix: String,
    pub cedar_source: String,
    pub requires_human_review: ReviewRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InertExplanation {
    pub text: String,
    pub advisory_only: bool,
}

struct CedarForbidAst<'a> {
    rule_id: &'a str,
    action_class: ActionClass,
    resource_class: &'a str,
}

impl Default for Nl2CedarTargetCatalog {
    fn default() -> Self {
        Self {
            rules: vec![
                Nl2CedarTargetRule {
                    keywords: vec![".ssh".into(), "id_rsa".into()],
                    action_class: ActionClass::FileRead,
                    target_prefix: "credential-store.ssh".into(),
                    resource_class: "credential-store".into(),
                },
                Nl2CedarTargetRule {
                    keywords: vec![".aws".into(), "credentials".into()],
                    action_class: ActionClass::FileRead,
                    target_prefix: "credential-store.aws".into(),
                    resource_class: "credential-store".into(),
                },
                Nl2CedarTargetRule {
                    keywords: vec!["pastebin".into(), "webhook".into(), "outbound".into()],
                    action_class: ActionClass::NetRequest,
                    target_prefix: "egress.paste-or-webhook".into(),
                    resource_class: "egress.external".into(),
                },
                Nl2CedarTargetRule {
                    keywords: vec!["rm -rf".into(), "delete".into()],
                    action_class: ActionClass::FileDelete,
                    target_prefix: "destructive.delete".into(),
                    resource_class: "destructive-target".into(),
                },
            ],
            fallback_action: ActionClass::Exec,
            fallback_prefix: "exec.network-fetch".into(),
            fallback_class: "net-fetch".into(),
        }
    }
}

/// Generates a strictly `forbid`-only, `Watch`-only Cedar rule draft (`GRDR-REV-0007`)
/// validated against the canonical Cedar 4.x runtime schema.
pub fn draft_watch_only_nl2cedar(
    prompt: &str,
    rule_id: &str,
) -> Result<CedarDraftRule, CodedError> {
    draft_watch_only_nl2cedar_with_catalog(prompt, rule_id, &Nl2CedarTargetCatalog::default())
}

/// Generates a Watch-only `forbid` Cedar draft using an explicit data-driven target catalog.
pub fn draft_watch_only_nl2cedar_with_catalog(
    prompt: &str,
    rule_id: &str,
    catalog: &Nl2CedarTargetCatalog,
) -> Result<CedarDraftRule, CodedError> {
    validate_cedar_rule_id(rule_id)?;
    if prompt.len() > MAX_NL2CEDAR_PROMPT_BYTES {
        return Err(CodedError::new(
            CODE_REV_NL2CEDAR_FORBIDDEN,
            "nl2cedar prompt exceeds maximum byte bound",
            "Shorten the natural-language policy description and retry.",
        ));
    }
    let lower = prompt.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return Err(CodedError::new(
            CODE_REV_NL2CEDAR_FORBIDDEN,
            "nl2cedar prompt cannot be empty",
            "Provide a restrictive condition description.",
        ));
    }
    for bad in PERMISSIVE_TOKENS {
        if lower.contains(bad) {
            return Err(CodedError::new(
                CODE_REV_NL2CEDAR_FORBIDDEN,
                format!("nl2cedar refused permissive request token `{bad}` under P2"),
                "nl2cedar generates Watch-only forbid drafts and cannot emit permits or weaken rules.",
            ));
        }
    }

    let (action_class, target_prefix, resource_class) = infer_target_from_catalog(&lower, catalog);
    let safe_prefix = sanitize_cedar_string_literal(&target_prefix)?;
    let safe_class = sanitize_cedar_string_literal(&resource_class)?;
    let ast = CedarForbidAst {
        rule_id,
        action_class,
        resource_class: &safe_class,
    };
    let cedar_source = render_and_validate_ast(&ast)?;

    Ok(CedarDraftRule {
        rule_id: rule_id.to_owned(),
        mode: DraftMode::WatchOnly,
        mapped_mode: Mode::Watch,
        effect: "forbid".into(),
        action_class,
        target_prefix: safe_prefix,
        cedar_source,
        requires_human_review: ReviewRequirement::StepUpApproval {
            min_grade: ApprovalGrade::G2,
        },
    })
}

/// Renders untrusted explanation / summary strings as strictly inert plain text:
/// strips ANSI CSI/OSC/DCS/C1 escapes, bidi overrides/isolates, tag/invisible Unicode,
/// neutralizes URLs, escapes angle brackets, and caps length.
#[must_use]
pub fn render_inert_explanation(raw: &str) -> InertExplanation {
    let mut end = raw.len().min(MAX_INERT_RAW_BYTES);
    while end > 0 && !raw.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let bounded_raw = raw.get(..end).unwrap_or("");
    let ansi_stripped = strip_ansi_sequences(bounded_raw);
    let mut cleaned = String::with_capacity(ansi_stripped.len().min(MAX_INERT_EXPLANATION_CHARS));
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
    let url_neutralized = neutralize_urls(cleaned.trim());
    let capped: String = url_neutralized
        .chars()
        .take(MAX_INERT_EXPLANATION_CHARS)
        .collect();

    InertExplanation {
        text: capped.trim().to_owned(),
        advisory_only: true,
    }
}

fn render_and_validate_ast(ast: &CedarForbidAst<'_>) -> Result<String, CodedError> {
    let resource_type = resource_entity_type_for_action(ast.action_class.as_str());
    let source = format!(
        "@id(\"{}\")\n@mode(\"watch\")\nforbid (\n  principal is Grdr::Session,\n  action == Grdr::Action::\"{}\",\n  resource is {resource_type}\n)\nwhen {{ resource.classes.contains(\"{}\") }};",
        ast.rule_id,
        ast.action_class.as_str(),
        ast.resource_class
    );
    let policy_set = validate_policy_source(CedarPlane::Runtime, &source).map_err(|e| {
        CodedError::new(
            CODE_REV_NL2CEDAR_FORBIDDEN,
            format!("generated Cedar draft failed strict schema validation: {e}"),
            "Review rule parameters and retry.",
        )
    })?;
    let count = policy_set.policies().count();
    let all_watch_forbid_non_final = policy_set.policies().all(|p| {
        p.effect() == cedar_policy::Effect::Forbid
            && p.annotation("mode") == Some("watch")
            && p.annotation("final").is_none()
    });
    if count != 1 || !all_watch_forbid_non_final {
        return Err(CodedError::new(
            CODE_REV_NL2CEDAR_FORBIDDEN,
            "nl2cedar AST validation rejected non-watch, final, permit, or multi-statement draft",
            "Only a single Watch-only non-final forbid statement is permitted.",
        ));
    }
    Ok(source)
}

fn validate_cedar_rule_id(rule_id: &str) -> Result<(), CodedError> {
    if rule_id.is_empty()
        || rule_id.len() > MAX_RULE_ID_LEN
        || !rule_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(CodedError::new(
            CODE_REV_NL2CEDAR_FORBIDDEN,
            "invalid rule_id: must match ^[A-Za-z0-9._-]{1,64}$",
            "Use an alphanumeric identifier with `.`, `_`, or `-` only.",
        ));
    }
    Ok(())
}

fn sanitize_cedar_string_literal(raw: &str) -> Result<String, CodedError> {
    if raw.is_empty()
        || raw.len() > 128
        || raw.contains('"')
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return Err(CodedError::new(
            CODE_REV_NL2CEDAR_FORBIDDEN,
            "invalid target string literal in nl2cedar catalog",
            "Use bounded ASCII string literals without quotes or control bytes.",
        ));
    }
    Ok(raw.to_owned())
}

fn infer_target_from_catalog(
    lower: &str,
    catalog: &Nl2CedarTargetCatalog,
) -> (ActionClass, String, String) {
    for entry in &catalog.rules {
        if entry.keywords.iter().any(|kw| lower.contains(kw.as_str())) {
            return (
                entry.action_class,
                entry.target_prefix.clone(),
                entry.resource_class.clone(),
            );
        }
    }
    (
        catalog.fallback_action,
        catalog.fallback_prefix.clone(),
        catalog.fallback_class.clone(),
    )
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

fn is_disallowed_display_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{070F}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
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
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut pos: usize = 0;

    while pos < input.len() {
        if let Some((hit_pos, scheme)) = find_earliest_url_scheme(&lower, bytes, pos) {
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

fn find_earliest_url_scheme(
    lower: &str,
    bytes: &[u8],
    from: usize,
) -> Option<(usize, &'static str)> {
    let tail = lower.get(from..)?;
    let mut best: Option<(usize, &'static str)> = None;
    for &scheme in URL_SCHEMES {
        let mut search_from: usize = 0;
        while let Some(sub) = tail.get(search_from..) {
            let Some(rel) = sub.find(scheme) else {
                break;
            };
            let abs = from.saturating_add(search_from).saturating_add(rel);
            let boundary_ok = abs == 0
                || bytes
                    .get(abs.saturating_sub(1))
                    .is_some_and(|b| !b.is_ascii_alphanumeric());
            if boundary_ok {
                if best.is_none_or(|(best_pos, _)| abs < best_pos) {
                    best = Some((abs, scheme));
                }
                break;
            }
            search_from = search_from.saturating_add(rel).saturating_add(1);
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
