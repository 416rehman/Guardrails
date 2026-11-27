// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]

use grdr_fastpath::{
    BinaryFloorHit, BinaryFloorTable, BinaryRuleInput, FLAG_BYPASS_PERMISSION, FLAG_CONTROL_PATH,
    FLAG_CRED_PATH, FLAG_GRDR_DISABLE, FLAG_HOOKS_DISABLED, FastActionClass, FastVerdict,
    FastpathError, LABEL_CREDENTIAL_ACCESSED, LABEL_TAINTED_EXFIL, MAX_HOOK_SCAN_BYTES,
    PRINCIPAL_SESSION, encode_binary_floor, evaluate_failsafe, scan_hook_payload,
};

const MAX_RULE_ID_BYTES: usize = 96;
const MAX_REASON_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserMode {
    Off,
    Watch,
    Ask,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmEvalSummary<'a> {
    pub verdict: FastVerdict,
    pub rule_id: &'a str,
    pub reason: &'a str,
    pub flags: u32,
    pub floor_hit: bool,
    pub hard_fail_closed: bool,
}

impl BrowserMode {
    pub const fn from_u32(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Off),
            1 => Some(Self::Watch),
            2 => Some(Self::Ask),
            3 => Some(Self::Block),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Watch => "watch",
            Self::Ask => "ask",
            Self::Block => "block",
        }
    }
}

pub const fn verdict_code(verdict: FastVerdict) -> i32 {
    match verdict {
        FastVerdict::Allow => 0,
        FastVerdict::StepUp => 1,
        FastVerdict::Deny => 2,
    }
}

const fn verdict_label(verdict: FastVerdict) -> &'static str {
    match verdict {
        FastVerdict::Allow => "allow",
        FastVerdict::StepUp => "step_up",
        FastVerdict::Deny => "deny",
    }
}

const fn verdict_rank(verdict: FastVerdict) -> u8 {
    match verdict {
        FastVerdict::Allow => 0,
        FastVerdict::StepUp => 1,
        FastVerdict::Deny => 2,
    }
}

pub fn push_json_escaped(out: &mut String, input: &str, max_chars: usize) {
    for ch in input.chars().take(max_chars) {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
}

pub fn format_eval_json(summary: &WasmEvalSummary<'_>, observed_mode: BrowserMode) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("{\"verdict\":\"");
    out.push_str(verdict_label(summary.verdict));
    out.push_str("\",\"rule_id\":\"");
    push_json_escaped(&mut out, summary.rule_id, MAX_RULE_ID_BYTES);
    out.push_str("\",\"reason\":\"");
    push_json_escaped(&mut out, summary.reason, MAX_REASON_BYTES);
    out.push_str("\",\"flags\":");
    out.push_str(&summary.flags.to_string());
    out.push_str(",\"floor_hit\":");
    out.push_str(if summary.floor_hit { "true" } else { "false" });
    out.push_str(",\"hard_fail_closed\":");
    out.push_str(if summary.hard_fail_closed {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"mode\":\"");
    out.push_str(observed_mode.as_str());
    out.push_str("\"}");
    out
}

pub fn format_error_json(code: &str, message: &str) -> String {
    let mut out = String::with_capacity(192);
    out.push_str("{\"verdict\":\"deny\",\"rule_id\":\"");
    push_json_escaped(&mut out, code, MAX_RULE_ID_BYTES);
    out.push_str("\",\"reason\":\"");
    push_json_escaped(&mut out, message, MAX_REASON_BYTES);
    out.push_str("\",\"error\":\"");
    push_json_escaped(&mut out, code, MAX_RULE_ID_BYTES);
    out.push_str("\",\"flags\":0,\"floor_hit\":true,\"hard_fail_closed\":true}");
    out
}

pub fn encode_default_browser_floor() -> Result<Vec<u8>, FastpathError> {
    let rules = [
        BinaryRuleInput {
            rule_id: "browser.webmcp.deny-shell",
            reason: "Blocked WebMCP tool attempting local shell execution.",
            action_mask: FastActionClass::McpCall.bit(),
            principal_mask: PRINCIPAL_SESSION,
            label_mask: 0,
            verdict: FastVerdict::Deny,
            agents: &[],
            prefixes: &[],
            contains: &["exec_shell", "run_command", "bash_exec"],
        },
        BinaryRuleInput {
            rule_id: "browser.webmcp.ask-filesystem",
            reason: "WebMCP filesystem read or write requires confirmation.",
            action_mask: FastActionClass::McpCall.bit(),
            principal_mask: PRINCIPAL_SESSION,
            label_mask: 0,
            verdict: FastVerdict::StepUp,
            agents: &[],
            prefixes: &[],
            contains: &["read_file", "write_file", "sync_local_env"],
        },
        BinaryRuleInput {
            rule_id: "browser.dlp.block-secrets-floor",
            reason: "Compiled fastpath blocked outbound credential match.",
            action_mask: FastActionClass::CredUse.bit() | FastActionClass::DataFlow.bit(),
            principal_mask: PRINCIPAL_SESSION,
            label_mask: LABEL_CREDENTIAL_ACCESSED,
            verdict: FastVerdict::Deny,
            agents: &[],
            prefixes: &[],
            contains: &[],
        },
        BinaryRuleInput {
            rule_id: "browser.dlp.block-env-upload",
            reason: "Compiled fastpath intercepted restricted environment artifact.",
            action_mask: FastActionClass::DataFlow.bit() | FastActionClass::LlmRequest.bit(),
            principal_mask: PRINCIPAL_SESSION,
            label_mask: LABEL_TAINTED_EXFIL,
            verdict: FastVerdict::StepUp,
            agents: &[],
            prefixes: &[],
            contains: &[".env", ".pem", ".kubeconfig", "id_rsa", "id_ed25519"],
        },
    ];
    let mut buf = vec![0u8; 4096];
    let written = encode_binary_floor(&rules, &mut buf)?;
    buf.truncate(written);
    Ok(buf)
}

fn pick_stronger<'a>(
    current: &mut WasmEvalSummary<'a>,
    candidate_verdict: FastVerdict,
    rule_id: &'a str,
    reason: &'a str,
    floor_hit: bool,
    hard_fail_closed: bool,
) {
    if verdict_rank(candidate_verdict) > verdict_rank(current.verdict)
        || (current.rule_id == "browser.allow.default" && candidate_verdict != FastVerdict::Allow)
    {
        current.verdict = candidate_verdict;
        current.rule_id = rule_id;
        current.reason = reason;
        current.floor_hit = floor_hit;
        current.hard_fail_closed = current.hard_fail_closed || hard_fail_closed;
    } else if hard_fail_closed {
        current.hard_fail_closed = true;
    }
}

fn parse_triple(input: &[u8]) -> Result<(&str, &str, &[u8]), &'static str> {
    let mut parts = input.splitn(3, |b| *b == 0);
    let raw_agent = parts.next().ok_or("browser.input.missing-agent")?;
    let agent = std::str::from_utf8(raw_agent).map_err(|_| "browser.input.invalid-utf8")?;
    let target = match parts.next() {
        Some(raw_target) => {
            std::str::from_utf8(raw_target).map_err(|_| "browser.input.invalid-utf8")?
        }
        None => "",
    };
    let payload = parts.next().unwrap_or(&[]);
    Ok((agent, target, payload))
}

pub fn evaluate_action_with_floor<'a>(
    floor_bytes: &'a [u8],
    input: &'a [u8],
    action: FastActionClass,
    mode: BrowserMode,
    labels_mask: u16,
    principal_mask: u16,
) -> WasmEvalSummary<'a> {
    let Ok((agent, target, payload)) = parse_triple(input) else {
        return WasmEvalSummary {
            verdict: FastVerdict::Deny,
            rule_id: "browser.input.invalid-utf8",
            reason: "Rejected non-UTF-8 browser metadata fail-closed.",
            flags: 0,
            floor_hit: true,
            hard_fail_closed: true,
        };
    };

    let scan = scan_hook_payload(payload, MAX_HOOK_SCAN_BYTES);
    let mut summary = WasmEvalSummary {
        verdict: FastVerdict::Allow,
        rule_id: "browser.allow.default",
        reason: "No fastpath floor rule matched.",
        flags: scan.flags,
        floor_hit: false,
        hard_fail_closed: false,
    };

    if !floor_bytes.is_empty() {
        match BinaryFloorTable::parse(floor_bytes) {
            Ok(table) => {
                if let Some(hit) =
                    table.evaluate(action, principal_mask, labels_mask, agent, target)
                {
                    let BinaryFloorHit {
                        rule_id,
                        reason,
                        verdict,
                    } = hit;
                    let locked_deny = matches!(verdict, FastVerdict::Deny);
                    pick_stronger(&mut summary, verdict, rule_id, reason, true, locked_deny);
                }
            }
            Err(_) => {
                return WasmEvalSummary {
                    verdict: FastVerdict::Deny,
                    rule_id: "browser.floor.corrupt",
                    reason: "Compiled floor table failed verification.",
                    flags: scan.flags,
                    floor_hit: true,
                    hard_fail_closed: true,
                };
            }
        }
    }

    if let Some(hit) = evaluate_failsafe(action, target) {
        let locked_deny = matches!(hit.verdict, FastVerdict::Deny);
        pick_stronger(
            &mut summary,
            hit.verdict,
            hit.rule_id,
            hit.reason,
            true,
            locked_deny,
        );
    }

    let critical_flags = FLAG_BYPASS_PERMISSION | FLAG_HOOKS_DISABLED | FLAG_GRDR_DISABLE;
    if (scan.flags & critical_flags) != 0 {
        pick_stronger(
            &mut summary,
            FastVerdict::Deny,
            "browser.fastpath.bypass-flag",
            "Payload contains disabled-guardrail or sandbox-bypass flags.",
            true,
            true,
        );
    } else if (scan.flags & (FLAG_CRED_PATH | FLAG_CONTROL_PATH)) != 0 {
        pick_stronger(
            &mut summary,
            FastVerdict::StepUp,
            "browser.fastpath.sensitive-path",
            "Payload references local credentials or agent control paths.",
            true,
            false,
        );
    }

    if matches!(mode, BrowserMode::Off) {
        if summary.hard_fail_closed {
            return summary;
        }
        return WasmEvalSummary {
            verdict: FastVerdict::Allow,
            rule_id: "browser.mode.off",
            reason: "Destination mode is Off.",
            flags: scan.flags,
            floor_hit: summary.floor_hit,
            hard_fail_closed: false,
        };
    }

    if (labels_mask & LABEL_CREDENTIAL_ACCESSED) != 0 {
        let secret_verdict = match mode {
            BrowserMode::Block => FastVerdict::Deny,
            BrowserMode::Ask => FastVerdict::StepUp,
            BrowserMode::Watch | BrowserMode::Off => FastVerdict::Allow,
        };
        pick_stronger(
            &mut summary,
            secret_verdict,
            "browser.dlp.secret-detected",
            "Outbound browser payload matched a sensitive credential pattern.",
            false,
            false,
        );
    } else if (labels_mask & LABEL_TAINTED_EXFIL) != 0 {
        let upload_verdict = match mode {
            BrowserMode::Block => FastVerdict::Deny,
            BrowserMode::Ask => FastVerdict::StepUp,
            BrowserMode::Watch | BrowserMode::Off => FastVerdict::Allow,
        };
        pick_stronger(
            &mut summary,
            upload_verdict,
            "browser.dlp.sensitive-transfer",
            "Outbound transfer matched restricted file or exfiltration policy.",
            false,
            false,
        );
    }

    if matches!(mode, BrowserMode::Watch) && !summary.hard_fail_closed {
        summary.verdict = FastVerdict::Allow;
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_failsafe_and_secret_labels_safely() {
        let summary = evaluate_action_with_floor(
            &[],
            b"browser-ext\0https://chatgpt.com/backend-api/files/.env.production\0",
            FastActionClass::CredUse,
            BrowserMode::Ask,
            LABEL_CREDENTIAL_ACCESSED,
            PRINCIPAL_SESSION,
        );
        assert_eq!(summary.verdict, FastVerdict::StepUp);
        assert!(summary.floor_hit);
    }

    #[test]
    fn watch_and_off_preserve_corrupt_floor_and_hard_failsafe_denials() {
        let corrupt = evaluate_action_with_floor(
            b"bad-floor-magic",
            b"browser-ext\0https://chatgpt.com/chat\0",
            FastActionClass::NetRequest,
            BrowserMode::Watch,
            0,
            PRINCIPAL_SESSION,
        );
        assert_eq!(corrupt.verdict, FastVerdict::Deny);
        assert_eq!(corrupt.rule_id, "browser.floor.corrupt");

        let corrupt_off = evaluate_action_with_floor(
            b"bad-floor-magic",
            b"browser-ext\0https://chatgpt.com/chat\0",
            FastActionClass::NetRequest,
            BrowserMode::Off,
            0,
            PRINCIPAL_SESSION,
        );
        assert_eq!(corrupt_off.verdict, FastVerdict::Deny);
        assert_eq!(corrupt_off.rule_id, "browser.floor.corrupt");

        let bypass_in_watch = evaluate_action_with_floor(
            &[],
            b"browser-ext\0https://chatgpt.com/cmd\0{\"cmd\":\"--no-sandbox\"}",
            FastActionClass::LlmRequest,
            BrowserMode::Watch,
            0,
            PRINCIPAL_SESSION,
        );
        assert_eq!(bypass_in_watch.verdict, FastVerdict::Deny);
        assert_eq!(bypass_in_watch.rule_id, "browser.fastpath.bypass-flag");
    }

    #[test]
    fn invalid_utf8_target_fails_closed() {
        let summary = evaluate_action_with_floor(
            &[],
            b"browser-ext\0\xff\xfe\0",
            FastActionClass::LlmRequest,
            BrowserMode::Watch,
            0,
            PRINCIPAL_SESSION,
        );
        assert_eq!(summary.verdict, FastVerdict::Deny);
        assert_eq!(summary.rule_id, "browser.input.invalid-utf8");
    }

    #[test]
    fn default_browser_floor_encodes_and_enforces_webmcp_rule() {
        let floor = encode_default_browser_floor().ok().unwrap_or_default();
        assert!(!floor.is_empty());
        let summary = evaluate_action_with_floor(
            &floor,
            b"browser-ext\0webmcp:chatgpt.com/exec_shell\0{}",
            FastActionClass::McpCall,
            BrowserMode::Watch,
            0,
            PRINCIPAL_SESSION,
        );
        assert_eq!(summary.verdict, FastVerdict::Deny);
        assert_eq!(summary.rule_id, "browser.webmcp.deny-shell");
    }
}
