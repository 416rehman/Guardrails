// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Signed `provider-index.tsv` lookup/verification and conservative `command-hook` stdout evaluation.

use std::io::Read;
use std::path::Path;

use grdr_crypto::verify_bytes;
use grdr_peer_os::fs_open::{
    OpenNofollowAccess, open_nofollow_dir, open_nofollow_file, verify_open_dir_trust,
    verify_open_file_trust,
};
use grdr_wire::messages::WireVerdict;

use crate::json_lexer::JsonScanner;
use crate::provider_exec::CommandHookOutput;

pub const MAX_PROVIDER_INDEX_BYTES: usize = 128 * 1024;
pub const MAX_FLOOR_PUB_BYTES: usize = 512;
pub const MAX_COMMAND_HOOK_TIMEOUT_MS: u64 = 1_000;
const PROVIDER_INDEX_SIGN_DOMAIN: &str = "grdr.provider-index.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderFailureMode {
    FailClosed,
    StepUp,
    Ignore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderIndexEntry {
    pub provider_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub timeout_ms: u64,
    pub on_failure: ProviderFailureMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderHookOutcome {
    pub verdict: WireVerdict,
    pub rule_id: String,
    pub reason: String,
    pub degraded_reason: String,
}

impl ProviderIndexEntry {
    #[must_use]
    pub fn is_fail_closed(&self) -> bool {
        !matches!(self.on_failure, ProviderFailureMode::Ignore)
    }
}

pub fn lookup_provider_index(
    state_dir: &Path,
    provider_id: &str,
    protected: bool,
) -> Result<ProviderIndexEntry, String> {
    let dir_file = open_nofollow_dir(state_dir).map_err(|e| e.to_string())?;
    verify_open_dir_trust(&dir_file, state_dir, protected).map_err(|e| e.to_string())?;

    let pub_path = state_dir.join("floor.pub");
    let pub_bytes = read_trusted_file(&pub_path, MAX_FLOOR_PUB_BYTES, protected, "floor.pub")?;
    let pub_str =
        std::str::from_utf8(&pub_bytes).map_err(|_| "floor.pub not valid UTF-8".to_string())?;
    let (trusted_kid, pub_b64) = pub_str
        .trim()
        .split_once(':')
        .ok_or_else(|| "floor.pub missing `<key_id>:<b64>`".to_string())?;

    let idx_path = state_dir.join("provider-index.tsv");
    let idx_bytes = read_trusted_file(
        &idx_path,
        MAX_PROVIDER_INDEX_BYTES,
        protected,
        "provider-index.tsv",
    )?;
    let text = std::str::from_utf8(&idx_bytes)
        .map_err(|_| "provider index not valid UTF-8".to_string())?;
    let verified_body = verify_signed_provider_index(text, trusted_kid.trim(), pub_b64.trim())?;
    parse_provider_index_entry(verified_body, provider_id)
}

pub fn verify_signed_provider_index<'a>(
    text: &'a str,
    trusted_key_id: &str,
    pub_b64: &str,
) -> Result<&'a str, String> {
    let (body, sig_tail) = text
        .rsplit_once("# sig_v1:")
        .ok_or_else(|| "provider-index.tsv missing Ed25519 signature footer".to_string())?;
    if body.contains("# sig_v1:") {
        return Err("provider-index.tsv contains duplicate signature footers".to_string());
    }
    let clean_sig = sig_tail.trim_end_matches(['\r', '\n']);
    if clean_sig.contains('\n') || clean_sig.contains('\r') {
        return Err("provider-index.tsv contains unsigned trailing lines".to_string());
    }
    let (sig_kid, sig_b64) = clean_sig
        .split_once(':')
        .ok_or_else(|| "malformed provider-index.tsv signature footer".to_string())?;
    if sig_kid.trim() != trusted_key_id {
        return Err("provider-index.tsv signer key_id mismatch".to_string());
    }
    verify_bytes(
        pub_b64,
        PROVIDER_INDEX_SIGN_DOMAIN,
        body.as_bytes(),
        sig_b64.trim(),
    )
    .map_err(|e| format!("provider-index.tsv signature invalid: {e}"))?;
    Ok(body)
}

pub fn parse_provider_index_entry(
    text: &str,
    provider_id: &str,
) -> Result<ProviderIndexEntry, String> {
    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('\t').collect();
        let Some(id) = parts.first().map(|s| s.trim()) else {
            continue;
        };
        if id != provider_id {
            continue;
        }
        let cmd = parts.get(1).map(|s| s.trim()).unwrap_or("");
        validate_command_syntax(cmd, provider_id)?;
        let args = parts
            .get(2)
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for arg in &args {
            if arg.chars().any(char::is_control) {
                return Err(format!("invalid arg in provider index for `{provider_id}`"));
            }
        }
        let timeout_ms = parts
            .get(3)
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(MAX_COMMAND_HOOK_TIMEOUT_MS)
            .clamp(1, MAX_COMMAND_HOOK_TIMEOUT_MS);
        let on_failure = match parts
            .get(4)
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("fail_closed") => ProviderFailureMode::FailClosed,
            Some("step_up") => ProviderFailureMode::StepUp,
            Some("ignore") => ProviderFailureMode::Ignore,
            other => {
                return Err(format!(
                    "invalid on_failure mode `{}` for `{provider_id}`",
                    other.unwrap_or("")
                ));
            }
        };
        return Ok(ProviderIndexEntry {
            provider_id: id.to_string(),
            command: cmd.to_string(),
            args,
            timeout_ms,
            on_failure,
        });
    }
    Err(format!(
        "provider `{provider_id}` missing from signed provider index"
    ))
}

#[must_use]
pub fn evaluate_command_hook_outcome(
    entry: &ProviderIndexEntry,
    out: &CommandHookOutput,
) -> ProviderHookOutcome {
    let id = &entry.provider_id;
    if out.timed_out || out.stdout_truncated {
        return failure_mode_outcome(
            entry,
            if out.stdout_truncated {
                format!("re-hosted provider `{id}` exceeded 64 KiB stdout ceiling")
            } else {
                format!(
                    "re-hosted provider `{id}` exceeded {} ms deadline",
                    entry.timeout_ms
                )
            },
            if out.stdout_truncated {
                "provider-stdout-overrun"
            } else {
                "provider-timeout"
            },
        );
    }

    if out.exit_code == 2 {
        return ProviderHookOutcome {
            verdict: WireVerdict::Block,
            rule_id: format!("provider/{id}"),
            reason: parse_reason_field(&out.stdout_bounded)
                .unwrap_or_else(|| format!("re-hosted provider `{id}` denied invocation")),
            degraded_reason: String::new(),
        };
    }
    if out.exit_code != 0 {
        return failure_mode_outcome(
            entry,
            format!(
                "re-hosted provider `{id}` exited with code {}",
                out.exit_code
            ),
            "provider-nonzero-exit",
        );
    }

    let Ok(raw_text) = std::str::from_utf8(&out.stdout_bounded) else {
        return failure_mode_outcome(
            entry,
            format!("re-hosted provider `{id}` emitted non-UTF8 stdout"),
            "provider-malformed-stdout",
        );
    };
    let trimmed = raw_text.trim();
    if trimmed.is_empty() {
        return failure_mode_outcome(
            entry,
            format!("re-hosted provider `{id}` produced empty stdout"),
            "provider.command_hook.empty_stdout",
        );
    }

    match parse_provider_stdout_json(trimmed) {
        Ok((Some(dec), reason)) => {
            let reason_text =
                reason.unwrap_or_else(|| format!("re-hosted provider `{id}` verdict `{dec}`"));
            match dec.as_str() {
                "allow" => ProviderHookOutcome {
                    verdict: WireVerdict::Allow,
                    rule_id: format!("provider/{id}"),
                    reason: reason_text,
                    degraded_reason: String::new(),
                },
                "deny" | "block" => ProviderHookOutcome {
                    verdict: WireVerdict::Block,
                    rule_id: format!("provider/{id}"),
                    reason: reason_text,
                    degraded_reason: String::new(),
                },
                "step_up" | "step-up" | "ask" => ProviderHookOutcome {
                    verdict: WireVerdict::Ask,
                    rule_id: format!("provider/{id}"),
                    reason: reason_text,
                    degraded_reason: String::new(),
                },
                other => failure_mode_outcome(
                    entry,
                    format!("re-hosted provider `{id}` emitted unknown decision `{other}`"),
                    "provider-unknown-decision",
                ),
            }
        }
        Ok((None, _)) => failure_mode_outcome(
            entry,
            format!("re-hosted provider `{id}` stdout missing decision/verdict field"),
            "provider-missing-decision",
        ),
        Err(detail) => failure_mode_outcome(
            entry,
            format!("re-hosted provider `{id}` emitted malformed JSON stdout: {detail}"),
            "provider-malformed-stdout",
        ),
    }
}

#[must_use]
pub fn failure_mode_outcome(
    entry: &ProviderIndexEntry,
    reason: String,
    degraded: &str,
) -> ProviderHookOutcome {
    let verdict = match entry.on_failure {
        ProviderFailureMode::FailClosed => WireVerdict::Block,
        ProviderFailureMode::StepUp => WireVerdict::Ask,
        ProviderFailureMode::Ignore => WireVerdict::Allow,
    };
    ProviderHookOutcome {
        verdict,
        rule_id: format!("provider/{}", entry.provider_id),
        reason,
        degraded_reason: degraded.to_string(),
    }
}

fn read_trusted_file(
    path: &Path,
    max_bytes: usize,
    protected: bool,
    label: &str,
) -> Result<Vec<u8>, String> {
    let file = open_nofollow_file(path, OpenNofollowAccess::ReadOnly, 0o600)
        .map_err(|e| format!("{label} open error: {e}"))?;
    verify_open_file_trust(&file, protected).map_err(|e| format!("{label} trust error: {e}"))?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if usize::try_from(meta.len()).unwrap_or(usize::MAX) > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} byte ceiling"));
    }
    let mut bytes = Vec::new();
    let cap = u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    file.take(cap)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max_bytes {
        return Err(format!("{label} exceeded {max_bytes} byte ceiling"));
    }
    Ok(bytes)
}

fn validate_command_syntax(cmd: &str, provider_id: &str) -> Result<(), String> {
    if cmd.is_empty()
        || cmd
            .chars()
            .any(|c| c.is_control() || matches!(c, '\t' | ';' | '|' | '&' | '`' | '$' | '<' | '>'))
        || cmd.contains("..")
    {
        return Err(format!(
            "invalid command in provider index for `{provider_id}`"
        ));
    }
    let is_abs = Path::new(cmd).is_absolute() || cmd.starts_with('/');
    if !is_abs {
        return Err(format!(
            "provider `{provider_id}` command `{cmd}` must be an absolute path"
        ));
    }
    Ok(())
}

fn parse_reason_field(stdout: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(stdout).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    parse_provider_stdout_json(text).ok()?.1
}

fn parse_provider_stdout_json(text: &str) -> Result<(Option<String>, Option<String>), String> {
    let mut scanner = JsonScanner::new(text.as_bytes());
    scanner.skip_ws();
    if scanner.next() != Some(b'{') {
        return Err("expected JSON object".to_string());
    }
    scanner.skip_ws();
    let mut decision: Option<String> = None;
    let mut reason: Option<String> = None;
    if scanner.peek() != Some(b'}') {
        loop {
            scanner.skip_ws();
            let key = scanner.read_string().map_err(|e| e.to_string())?;
            scanner.skip_ws();
            if scanner.next() != Some(b':') {
                return Err("expected ':'".to_string());
            }
            scanner.skip_ws();
            match scanner.peek() {
                Some(b'"') => {
                    let val = scanner.read_string().map_err(|e| e.to_string())?;
                    if key == "decision" || key == "verdict" {
                        decision = Some(val.trim().to_ascii_lowercase());
                    } else if key == "reason" && !val.trim().is_empty() {
                        reason = Some(val);
                    }
                }
                Some(b't' | b'f' | b'n') => {
                    scanner.skip_keyword().map_err(|e| e.to_string())?;
                }
                Some(b'-' | b'0'..=b'9') => {
                    scanner.skip_number().map_err(|e| e.to_string())?;
                }
                _ => return Err("unsupported JSON value type".to_string()),
            }
            scanner.skip_ws();
            match scanner.next() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err("expected ',' or '}'".to_string()),
            }
        }
    } else {
        scanner.advance(1);
    }
    scanner.skip_ws();
    if scanner.pos() != text.len() {
        return Err("trailing data after JSON object".to_string());
    }
    Ok((decision, reason))
}
