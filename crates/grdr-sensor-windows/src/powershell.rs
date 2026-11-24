// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::{ActionAttempt, ActionClass, ControlPoint};

use crate::etw::is_powershell_host;

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
        CaptureLevel::RedactedArguments => truncate_utf8(&event.script_text, REDACTED_MAX_BYTES),
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

        let bad = RawScriptBlockEvent {
            host_image: "cmd.exe".into(),
            ..ev
        };
        assert!(matches!(
            normalize_script_block_4104(&bad, CaptureLevel::FullScript, "d1", "h1"),
            ScriptBlockNormalization::RejectedTamper { .. }
        ));
    }
}
