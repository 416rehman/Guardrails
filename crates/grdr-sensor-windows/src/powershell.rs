// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::{ActionAttempt, ActionClass, ControlPoint};

use crate::WindowsSensorError;
use crate::etw::is_powershell_host;
use crate::sysmon::parse_windows_event_xml;

pub const POWERSHELL_SCRIPT_BLOCK_EVENT_ID: u16 = 4104;
const REDACTED_MAX_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureLevel {
    MetadataOnly,
    RedactedArguments,
    FullScript,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawScriptBlockEvent {
    pub script_block_id: String,
    pub script_path: Option<String>,
    pub script_text: String,
    pub host_pid: u32,
    pub host_image: String,
    pub in_agent_lineage: bool,
    pub session_id: String,
    pub agent_name: String,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ScriptBlockNormalization {
    Accepted {
        attempt: Box<ActionAttempt>,
        retained_preview: String,
    },
    IgnoredOutsideLineage,
    RejectedTamper {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedScriptBlock {
    pub script_block_id: String,
    pub capture_level: CaptureLevel,
    pub text_len: usize,
}

pub fn normalize_script_block_4104(
    event: &RawScriptBlockEvent,
    capture: CaptureLevel,
    device_id: &str,
    device_name: &str,
) -> ScriptBlockNormalization {
    if !is_powershell_host(&event.host_image) {
        return ScriptBlockNormalization::RejectedTamper {
            reason: format!(
                "PowerShell 4104 emitted from non-PowerShell host `{}`",
                event.host_image
            ),
        };
    }
    if !event.in_agent_lineage {
        return ScriptBlockNormalization::IgnoredOutsideLineage;
    }

    let retained_preview = match capture {
        CaptureLevel::MetadataOnly => String::new(),
        CaptureLevel::RedactedArguments => {
            let redacted = redact_script_arguments(&event.script_text);
            truncate_utf8(&redacted, REDACTED_MAX_BYTES)
        }
        CaptureLevel::FullScript => event.script_text.clone(),
    };

    let target = event
        .script_path
        .clone()
        .unwrap_or_else(|| format!("powershell://scriptblock/{}", event.script_block_id));

    let attempt = ActionAttempt {
        id: format!("att-ps4104-{}", event.script_block_id),
        session_id: event.session_id.clone(),
        device_id: device_id.into(),
        device_name: device_name.into(),
        agent_name: event.agent_name.clone(),
        action_class: ActionClass::Exec,
        control_point: ControlPoint::Sensor,
        target,
        summary: format!(
            "PowerShell ScriptBlock 4104 pid={} len={}",
            event.host_pid,
            event.script_text.len()
        ),
        timestamp: event.timestamp,
        ..Default::default()
    };

    ScriptBlockNormalization::Accepted {
        attempt: Box::new(attempt),
        retained_preview,
    }
}

pub fn parse_ps4104_event_xml(
    xml: &str,
    host_image: &str,
    in_agent_lineage: bool,
    session_id: &str,
    agent_name: &str,
) -> Result<RawScriptBlockEvent, WindowsSensorError> {
    let parsed = parse_windows_event_xml(xml)?;
    if parsed.event_id != POWERSHELL_SCRIPT_BLOCK_EVENT_ID {
        return Err(WindowsSensorError::Sysmon(format!(
            "expected PowerShell EventID {}, found {}",
            POWERSHELL_SCRIPT_BLOCK_EVENT_ID, parsed.event_id
        )));
    }
    let script_block_id = parsed
        .data
        .get("ScriptBlockId")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("sb-{}", parsed.system_pid));
    let script_text = parsed.data.get("ScriptBlockText").cloned().ok_or_else(|| {
        WindowsSensorError::Sysmon("missing ScriptBlockText in 4104 EventData".to_string())
    })?;
    let script_path = parsed.data.get("Path").filter(|s| !s.is_empty()).cloned();

    Ok(RawScriptBlockEvent {
        script_block_id,
        script_path,
        script_text,
        host_pid: parsed.system_pid,
        host_image: host_image.to_string(),
        in_agent_lineage,
        session_id: session_id.to_string(),
        agent_name: agent_name.to_string(),
        timestamp: parsed.timestamp,
    })
}

fn redact_script_arguments(input: &str) -> String {
    const SECRET_PREFIXES: &[&str] = &[
        "sk-",
        "ghp_",
        "gho_",
        "github_pat_",
        "akia",
        "aiza",
        "xoxb-",
        "xoxp-",
        "-----begin",
    ];
    const SENSITIVE_KEYS: &[&str] = &[
        "password",
        "passwd",
        "token",
        "secret",
        "apikey",
        "api_key",
        "api-key",
        "credential",
        "authorization",
        "bearer",
        "basic",
        "privatekey",
        "private_key",
    ];

    let sanitized: String = input
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let stripped_quotes = strip_quoted_literals(&sanitized);
    let mut out = Vec::new();
    let mut redact_next = false;
    let mut saw_sensitive_env = false;

    for tok in stripped_quotes.split_whitespace() {
        let lower = tok.to_ascii_lowercase();
        let trimmed_flag = lower.trim_start_matches('-');
        if redact_next {
            out.push("[REDACTED]".to_string());
            redact_next = false;
            saw_sensitive_env = false;
            continue;
        }
        if saw_sensitive_env {
            if tok == "=" {
                out.push(tok.to_string());
                redact_next = true;
                saw_sensitive_env = false;
                continue;
            }
            saw_sensitive_env = false;
        }
        if let Some((lhs, _)) = tok.split_once('=') {
            let lhs_low = lhs.to_ascii_lowercase();
            let check_lhs = lhs_low.strip_prefix("$env:").unwrap_or(&lhs_low);
            if SENSITIVE_KEYS.iter().any(|k| check_lhs.contains(k)) {
                out.push(format!("{lhs}=[REDACTED]"));
                continue;
            }
        }
        if let Some(env_name) = lower.strip_prefix("$env:") {
            let clean_env = env_name.trim_end_matches('=');
            if SENSITIVE_KEYS.iter().any(|k| clean_env.contains(k)) {
                out.push(tok.to_string());
                saw_sensitive_env = true;
                continue;
            }
        }
        if SENSITIVE_KEYS
            .iter()
            .any(|k| trimmed_flag == *k || trimmed_flag.ends_with(&format!(".{k}")))
        {
            out.push(tok.to_string());
            redact_next = true;
            continue;
        }
        if SECRET_PREFIXES.iter().any(|p| lower.contains(p)) {
            out.push("[REDACTED]".to_string());
            continue;
        }
        out.push(tok.to_string());
    }
    out.join(" ")
}

fn strip_quoted_literals(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut quote: Option<char> = None;
    let mut here_quote: Option<char> = None;
    let mut escaped = false;

    while let Some(&ch) = chars.get(i) {
        if let Some(hq) = here_quote {
            if ch == hq && chars.get(i.saturating_add(1)) == Some(&'@') {
                here_quote = None;
                out.push_str("\"[REDACTED]\"");
                i = i.saturating_add(2);
                continue;
            }
            i = i.saturating_add(1);
            continue;
        }
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' || (q == '\'' && ch == '\'') || ch == '`' {
                escaped = true;
            } else if ch == q {
                quote = None;
                out.push_str("\"[REDACTED]\"");
            }
            i = i.saturating_add(1);
            continue;
        }
        if ch == '@'
            && let Some(&next_ch) = chars.get(i.saturating_add(1))
            && (next_ch == '"' || next_ch == '\'')
        {
            here_quote = Some(next_ch);
            i = i.saturating_add(2);
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else {
            out.push(ch);
        }
        i = i.saturating_add(1);
    }
    if quote.is_some() || here_quote.is_some() {
        out.push_str("\"[REDACTED]\"");
    }
    out
}

fn truncate_utf8(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    input.get(..end).unwrap_or_default().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_script_block_4104_with_capture_level_and_host_check() {
        let ev = RawScriptBlockEvent {
            script_block_id: "sb-1".into(),
            script_path: None,
            script_text: "Get-Process | Out-Null".into(),
            host_pid: 3300,
            host_image: r"C:\Program Files\PowerShell\7\pwsh.exe".into(),
            in_agent_lineage: true,
            session_id: "sess-ps".into(),
            agent_name: "codex".into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
        };

        let meta = normalize_script_block_4104(&ev, CaptureLevel::MetadataOnly, "d1", "h1");
        assert!(matches!(
            meta,
            ScriptBlockNormalization::Accepted {
                retained_preview,
                ..
            } if retained_preview.is_empty()
        ));

        let secret_ev = RawScriptBlockEvent {
            script_text:
                "Invoke-RestMethod -Token \"ghp_secret999\" -Headers @{Authorization=\"Bearer sk-secret-1234\"} password=hunter2"
                    .into(),
            ..ev.clone()
        };
        let redacted =
            normalize_script_block_4104(&secret_ev, CaptureLevel::RedactedArguments, "d1", "h1");
        let ScriptBlockNormalization::Accepted {
            retained_preview, ..
        } = redacted
        else {
            panic!("expected accepted script block");
        };
        assert!(retained_preview.contains("Invoke-RestMethod"));
        assert!(!retained_preview.contains("ghp_secret999"));
        assert!(!retained_preview.contains("sk-secret-1234"));
        assert!(!retained_preview.contains("hunter2"));

        let env_and_here = RawScriptBlockEvent {
            script_text:
                "$env:OPENAI_API_KEY = aaaabbbbcccc\n$body = @\"\nsk-herestring-secret-99\n\"@"
                    .to_string(),
            ..ev.clone()
        };
        let env_redacted =
            normalize_script_block_4104(&env_and_here, CaptureLevel::RedactedArguments, "d1", "h1");
        if let ScriptBlockNormalization::Accepted {
            retained_preview, ..
        } = env_redacted
        {
            assert!(!retained_preview.contains("aaaabbbbcccc"));
            assert!(!retained_preview.contains("sk-herestring-secret-99"));
        } else {
            panic!("expected accepted script block for env/here-string");
        }

        let bad = RawScriptBlockEvent {
            host_image: "cmd.exe".into(),
            ..ev
        };
        assert!(matches!(
            normalize_script_block_4104(&bad, CaptureLevel::FullScript, "d1", "h1"),
            ScriptBlockNormalization::RejectedTamper { .. }
        ));
    }

    #[test]
    fn parses_ps4104_event_xml_and_validates_event_id() {
        let xml = r#"<Event><System><EventID>4104</EventID><TimeCreated SystemTime="2026-11-26T10:00:00Z"/><Execution ProcessID="5500"/></System><EventData><Data Name="ScriptBlockText">Get-ChildItem env:</Data><Data Name="ScriptBlockId">sb-4104</Data><Data Name="Path"></Data></EventData></Event>"#;
        let ev = parse_ps4104_event_xml(
            xml,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            true,
            "sess-1",
            "claude",
        )
        .expect("4104 XML parse");
        assert_eq!(ev.host_pid, 5500);
        assert_eq!(ev.script_block_id, "sb-4104");
        assert_eq!(ev.script_text, "Get-ChildItem env:");
        assert_eq!(ev.script_path, None);

        let wrong_id = "<Event><System><EventID>1</EventID></System><EventData/></Event>";
        assert!(parse_ps4104_event_xml(wrong_id, "pwsh.exe", true, "s", "a").is_err());
    }
}
