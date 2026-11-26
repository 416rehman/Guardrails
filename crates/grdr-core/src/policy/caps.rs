// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Control-point capabilities, entropy sources, obligations, and deterministic MODIFY transforms.

use std::sync::LazyLock;

use grdr_crypto::{domain_sha256_digest, encode_lower_hex, fill_random};
use grdr_model::eval::{ObligationKind, TransformKind, capped_hold_deadline_ms};
use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, ControlPointCaps, FailureDisposition, HoldCapability,
    ObligationSupport, VerdictDiscriminant,
};
use grdr_schema::limits::{LimitsConfig, load_embedded_limits};

use super::PolicyError;

const FALLBACK_HOLD_CAP_MS: u64 = 1_000;
static EMBEDDED_LIMITS: LazyLock<Result<LimitsConfig, String>> =
    LazyLock::new(|| load_embedded_limits().map_err(|e| e.to_string()));

pub trait Entropy {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), PolicyError>;
}

#[derive(Debug, Default)]
pub struct CryptoEntropy;

#[derive(Debug, Clone)]
pub struct DeterministicEntropy {
    seed: [u8; 32],
    counter: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obligation {
    pub kind: ObligationKind,
    pub rule_id: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTransform {
    pub kind: TransformKind,
    pub original_target: String,
    pub rewritten_target: String,
}

pub(crate) fn cached_limits() -> Option<&'static LimitsConfig> {
    EMBEDDED_LIMITS.as_ref().ok()
}

fn max_hold_cap_ms() -> u64 {
    cached_limits().map_or(FALLBACK_HOLD_CAP_MS, |l| l.endpoint.ipc.command_hold_max_ms)
}

impl Entropy for CryptoEntropy {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), PolicyError> {
        fill_random(dest).map_err(|e| PolicyError::RequestBuildFailed {
            detail: format!("entropy failure: {e}"),
        })
    }
}

impl DeterministicEntropy {
    pub fn from_seed_bytes(seed_material: &[u8]) -> Self {
        Self {
            seed: domain_sha256_digest("grdr.engine.entropy.v1", seed_material),
            counter: 0,
        }
    }
}

impl Entropy for DeterministicEntropy {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), PolicyError> {
        let mut written: usize = 0;
        while written < dest.len() {
            let mut input = [0u8; 40];
            let (seed_dst, cnt_dst) = input.split_at_mut(32);
            seed_dst.copy_from_slice(&self.seed);
            cnt_dst.copy_from_slice(&self.counter.to_le_bytes());
            self.counter = self.counter.saturating_add(1);
            let block = domain_sha256_digest("grdr.engine.entropy.block.v1", &input);
            let take = block.len().min(dest.len().saturating_sub(written));
            if let (Some(dst), Some(src)) = (
                dest.get_mut(written..written.saturating_add(take)),
                block.get(..take),
            ) {
                dst.copy_from_slice(src);
            }
            written = written.saturating_add(take);
        }
        Ok(())
    }
}

pub fn default_control_point_caps(
    cp: ControlPoint,
    host_deadline_ms: Option<u64>,
) -> ControlPointCaps {
    let hold = match (cp, host_deadline_ms) {
        (
            ControlPoint::McpBroker
            | ControlPoint::Proxy
            | ControlPoint::Sandbox
            | ControlPoint::Browser
            | ControlPoint::Gateway,
            Some(ms),
        ) if ms > 0 => HoldCapability::CanHold {
            deadline_ms: capped_hold_deadline_ms(ms, max_hold_cap_ms()),
        },
        _ => HoldCapability::NoHold,
    };
    let (verbs, failure_mode, snapshot, modify) = match cp {
        ControlPoint::Hook => (
            [
                VerdictDiscriminant::Allow,
                VerdictDiscriminant::Deny,
                VerdictDiscriminant::StepUp,
            ]
            .into_iter()
            .collect(),
            FailureDisposition::Open,
            ObligationSupport::Unsupported,
            ObligationSupport::Unsupported,
        ),
        ControlPoint::McpBroker | ControlPoint::Proxy | ControlPoint::Sandbox => (
            [
                VerdictDiscriminant::Allow,
                VerdictDiscriminant::Modify,
                VerdictDiscriminant::StepUp,
                VerdictDiscriminant::Defer,
                VerdictDiscriminant::Deny,
            ]
            .into_iter()
            .collect(),
            FailureDisposition::Closed,
            ObligationSupport::Supported,
            ObligationSupport::Supported,
        ),
        ControlPoint::Gateway => (
            [
                VerdictDiscriminant::Allow,
                VerdictDiscriminant::Modify,
                VerdictDiscriminant::StepUp,
                VerdictDiscriminant::Defer,
                VerdictDiscriminant::Deny,
            ]
            .into_iter()
            .collect(),
            FailureDisposition::Closed,
            ObligationSupport::Unsupported,
            ObligationSupport::Supported,
        ),
        ControlPoint::Browser => (
            [
                VerdictDiscriminant::Allow,
                VerdictDiscriminant::StepUp,
                VerdictDiscriminant::Defer,
                VerdictDiscriminant::Deny,
            ]
            .into_iter()
            .collect(),
            FailureDisposition::Closed,
            ObligationSupport::Unsupported,
            ObligationSupport::Unsupported,
        ),
        ControlPoint::Connector => (
            [
                VerdictDiscriminant::Allow,
                VerdictDiscriminant::Deny,
                VerdictDiscriminant::StepUp,
            ]
            .into_iter()
            .collect(),
            FailureDisposition::Closed,
            ObligationSupport::Unsupported,
            ObligationSupport::Unsupported,
        ),
        ControlPoint::Sensor => (
            [VerdictDiscriminant::Allow].into_iter().collect(),
            FailureDisposition::Open,
            ObligationSupport::Unsupported,
            ObligationSupport::Unsupported,
        ),
    };
    ControlPointCaps {
        verbs,
        hold,
        failure_mode,
        snapshot,
        modify,
    }
}

pub(crate) fn generate_retry_token(entropy: &mut dyn Entropy) -> Result<String, PolicyError> {
    let mut raw = [0u8; 16];
    entropy.fill_bytes(&mut raw)?;
    Ok(format!("rty_{}", encode_lower_hex(&raw)))
}

pub(crate) fn apply_modify_transform(
    attempt: &ActionAttempt,
    remedy_hint: Option<&str>,
) -> Option<AppliedTransform> {
    let secret_prefixes = [
        "ghp_",
        "github_pat_",
        "sk-ant-",
        "sk-live-",
        "sk_live_",
        "xoxb-",
        "xoxp-",
        "aiza",
        "akia",
        "asia",
    ];
    let suffix = match remedy_hint {
        None | Some("modify") | Some("modify:auto") => "auto",
        Some(other) => other.strip_prefix("modify:")?,
    };
    match suffix {
        "wrap-launcher" => {
            if attempt.action_class == ActionClass::Exec
                && !attempt.target.trim_start().starts_with("grdr-run ")
            {
                return Some(AppliedTransform {
                    kind: TransformKind::WrapLauncher,
                    original_target: attempt.target.clone(),
                    rewritten_target: format!("grdr-run -- {}", attempt.target),
                });
            }
            None
        }
        "swap-credential" => {
            let swapped = redact_aws_env_assign(&attempt.target);
            (swapped != attempt.target).then(|| AppliedTransform {
                kind: TransformKind::SwapCredential,
                original_target: attempt.target.clone(),
                rewritten_target: swapped,
            })
        }
        "redact-secrets" => {
            let mut rewritten = redact_secret_tokens(&attempt.target, &secret_prefixes);
            rewritten = redact_aws_env_assign(&rewritten);
            (rewritten != attempt.target).then(|| AppliedTransform {
                kind: TransformKind::RedactSecrets,
                original_target: attempt.target.clone(),
                rewritten_target: rewritten,
            })
        }
        "auto" => {
            let mut rewritten = redact_secret_tokens(&attempt.target, &secret_prefixes);
            let has_secrets = rewritten != attempt.target;
            rewritten = redact_aws_env_assign(&rewritten);
            if rewritten == attempt.target {
                return None;
            }
            Some(AppliedTransform {
                kind: if has_secrets {
                    TransformKind::RedactSecrets
                } else {
                    TransformKind::SwapCredential
                },
                original_target: attempt.target.clone(),
                rewritten_target: rewritten,
            })
        }
        _ => None,
    }
}

fn is_shell_join_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '"' | '\'' | '_' | '-' | '$' | '\\')
}

fn redact_secret_tokens(input: &str, prefixes: &[&str]) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while !rest.is_empty() {
        let matched = prefixes.iter().find(|&&p| {
            rest.get(..p.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(p))
        });
        if matched.is_some() {
            out.push_str("[REDACTED]");
            rest = consume_secret_span(rest);
        } else if let Some(ch) = rest.chars().next() {
            out.push(ch);
            rest = rest.get(ch.len_utf8()..).unwrap_or("");
        } else {
            break;
        }
    }
    out
}

fn consume_secret_span(mut rest: &str) -> &str {
    while let Some((idx, ch)) = rest.char_indices().next() {
        let _ = idx;
        if ch.is_whitespace() || matches!(ch, '&' | ';' | ',' | '|' | ':' | '}' | ']' | ')') {
            break;
        }
        if matches!(ch, '"' | '\'') {
            let after = rest.get(ch.len_utf8()..).unwrap_or("");
            if after.chars().next().is_some_and(is_shell_join_char) {
                rest = after;
                continue;
            }
            break;
        }
        rest = rest.get(ch.len_utf8()..).unwrap_or("");
    }
    rest
}

fn consume_shell_or_json_value(input: &str) -> Option<(&str, bool)> {
    let mut rest = input;
    let mut consumed = false;
    while !rest.is_empty() {
        if let Some(after_dollar) = rest.strip_prefix("$'") {
            let body_end = consume_quoted_body(after_dollar, '\'', true);
            rest = after_dollar.get(body_end..).unwrap_or("");
            consumed = true;
            continue;
        }
        if let Some(quote) = rest.chars().next().filter(|&c| c == '"' || c == '\'') {
            let body = rest.get(quote.len_utf8()..).unwrap_or("");
            let body_end = consume_quoted_body(body, quote, quote == '"');
            rest = body.get(body_end..).unwrap_or("");
            consumed = true;
            if rest.chars().next().is_some_and(is_shell_join_char) {
                continue;
            }
            break;
        }
        let mut idx = 0usize;
        let mut escaped = false;
        while idx < rest.len() {
            let Some(ch) = rest.get(idx..).and_then(|s| s.chars().next()) else {
                break;
            };
            if escaped {
                escaped = false;
                idx = idx.saturating_add(ch.len_utf8());
                continue;
            }
            if ch == '\\' {
                escaped = true;
                idx = idx.saturating_add(1);
                continue;
            }
            if ch.is_whitespace() || matches!(ch, '&' | ';' | '|' | ',' | '}' | ']') {
                break;
            }
            if matches!(ch, '"' | '\'') {
                break;
            }
            idx = idx.saturating_add(ch.len_utf8());
        }
        if idx > 0 {
            consumed = true;
            rest = rest.get(idx..).unwrap_or("");
            if rest.chars().next().is_some_and(|c| c == '"' || c == '\'') {
                continue;
            }
        }
        break;
    }
    consumed.then_some((rest, true))
}

fn consume_quoted_body(body: &str, quote: char, allow_backslash: bool) -> usize {
    let mut escaped = false;
    for (idx, ch) in body.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' && allow_backslash {
            escaped = true;
        } else if ch == quote {
            return idx.saturating_add(ch.len_utf8());
        }
    }
    body.len()
}

fn redact_aws_env_assign(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    let key = "AWS_ACCESS_KEY_ID";
    while !rest.is_empty() {
        if rest
            .get(..key.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(key))
        {
            let after_key = rest.get(key.len()..).unwrap_or("");
            let (json_key_closed, after_quote) = if let Some(q_tail) = after_key.strip_prefix('"') {
                (true, q_tail)
            } else {
                (false, after_key)
            };
            let trimmed_ws = after_quote.trim_start_matches([' ', '\t']);
            let sep = if json_key_closed {
                trimmed_ws.strip_prefix(':').map(|r| (':', r))
            } else {
                trimmed_ws
                    .strip_prefix('=')
                    .map(|r| ('=', r))
                    .or_else(|| trimmed_ws.strip_prefix(':').map(|r| (':', r)))
            };
            if let Some((delim, after_delim)) = sep {
                let val_start = after_delim.trim_start_matches([' ', '\t']);
                if let Some((tail, _)) = consume_shell_or_json_value(val_start) {
                    if json_key_closed {
                        out.push_str("GRDR_BROKER_CRED\":\"[REDACTED]\"");
                    } else if delim == ':' {
                        out.push_str("GRDR_BROKER_CRED: [REDACTED]");
                    } else {
                        out.push_str("GRDR_BROKER_CRED=[REDACTED]");
                    }
                    rest = tail;
                    continue;
                }
            }
        }
        if let Some(ch) = rest.chars().next() {
            out.push(ch);
            rest = rest.get(ch.len_utf8()..).unwrap_or("");
        } else {
            break;
        }
    }
    out
}
