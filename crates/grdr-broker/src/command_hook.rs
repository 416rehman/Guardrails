// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! `command-hook` re-hosting instructions, `provider-index.tsv` generation, foreign-hook listing, and `capabilities.json` (`docs/design/07`).

use std::collections::BTreeMap;

use grdr_model::CodedError;
use grdr_model::eval::SigningKeypair;
use grdr_strings::sanitize_untrusted_text;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::fanout::{ProviderEvalRequest, ProviderVerdictKind, ProviderVerdictResponse};
use crate::providers::{
    MAX_PROVIDER_DEADLINE_MS, ProviderCapabilities, ProviderCaptureCeiling, ProviderKind,
    ProviderManifest, ProviderOnFailure,
};
use crate::providers_parse::brk_manifest_err;
use crate::secret_rules::contains_secret_indicator;

pub const MAX_COMMAND_HOOK_STDOUT_BYTES: usize = 64 * 1024;
const PROVIDER_INDEX_SIGN_DOMAIN: &str = "grdr.provider-index.v1";
const ARGUMENT_PREVIEW_MAX_CHARS: usize = 256;
const FULL_MINIMISED_MAX_CHARS: usize = 2_048;

pub const CANONICAL_HOOK_EVENTS: &[&str; 18] = &[
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PermissionRequest",
    "ConfigChange",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "Notification",
    "BeforeShellExecution",
    "BeforeReadFile",
    "BeforeMcpExecution",
    "AcpSessionNew",
    "AcpRequestPermission",
    "AcpFsTerminal",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandHookInstruction {
    pub provider_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub deadline_ms: u64,
    pub on_failure: ProviderOnFailure,
    pub max_capture_level: ProviderCaptureCeiling,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandHookEvalOutcome {
    pub response: ProviderVerdictResponse,
    pub degraded_provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignHookEntry {
    pub event: String,
    pub command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilitySupportClaim {
    Gate,
    Observe,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapabilityMatrixInput {
    pub agent_id: String,
    pub version_range: String,
    pub fail_mode: String,
    pub claims: BTreeMap<String, CapabilitySupportClaim>,
}

#[must_use]
pub fn collect_command_hook_instructions(
    manifests: &[ProviderManifest],
) -> Vec<CommandHookInstruction> {
    manifests
        .iter()
        .filter(|m| m.enabled && m.kind == ProviderKind::CommandHook)
        .filter_map(|m| {
            let cmd = m.command.as_deref()?.trim();
            if cmd.is_empty() {
                return None;
            }
            Some(CommandHookInstruction {
                provider_id: m.id.clone(),
                command: cmd.to_owned(),
                args: m.args.clone(),
                deadline_ms: m.capabilities.timeout_ms.clamp(1, MAX_PROVIDER_DEADLINE_MS),
                on_failure: m.capabilities.on_failure,
                max_capture_level: m.capabilities.max_capture_level,
            })
        })
        .collect()
}

pub fn render_provider_index_tsv(manifests: &[ProviderManifest]) -> Result<String, CodedError> {
    let mut lines = vec!["# provider_id\tcommand\targs\ttimeout_ms\ton_failure".to_owned()];
    for inst in collect_command_hook_instructions(manifests) {
        validate_tsv_field(&inst.provider_id, "provider_id", &inst.provider_id)?;
        validate_tsv_field(&inst.command, "command", &inst.provider_id)?;
        for arg in &inst.args {
            validate_tsv_field(arg, "arg", &inst.provider_id)?;
            if arg.contains(',') {
                return Err(brk_manifest_err(format!(
                    "command-hook `{}` arg contains comma",
                    inst.provider_id
                )));
            }
        }
        let fail_label = match inst.on_failure {
            ProviderOnFailure::FailClosed => "fail_closed",
            ProviderOnFailure::StepUp => "step_up",
            ProviderOnFailure::Ignore => "ignore",
        };
        let args_csv = inst.args.join(",");
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}",
            inst.provider_id, inst.command, args_csv, inst.deadline_ms, fail_label
        ));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

pub fn render_signed_provider_index_tsv(
    manifests: &[ProviderManifest],
    signer: &SigningKeypair,
) -> Result<String, CodedError> {
    let body = render_provider_index_tsv(manifests)?;
    let sig_b64 = signer.sign_bytes(PROVIDER_INDEX_SIGN_DOMAIN, body.as_bytes());
    Ok(format!("{body}# sig_v1:{}:{sig_b64}\n", signer.key_id()))
}

fn validate_tsv_field(val: &str, field: &str, provider_id: &str) -> Result<(), CodedError> {
    if val
        .chars()
        .any(|c| c.is_control() || matches!(c, '\t' | '\r' | '\n'))
    {
        return Err(brk_manifest_err(format!(
            "command-hook `{provider_id}` {field} contains forbidden control or TSV characters"
        )));
    }
    Ok(())
}

#[must_use]
pub fn evaluate_command_hook_result(
    instruction: &CommandHookInstruction,
    exit_code: i32,
    stdout_bytes: &[u8],
    timed_out: bool,
    elapsed_ms: u64,
) -> CommandHookEvalOutcome {
    let failure_verdict = match instruction.on_failure {
        ProviderOnFailure::StepUp => ProviderVerdictKind::StepUp,
        ProviderOnFailure::FailClosed | ProviderOnFailure::Ignore => ProviderVerdictKind::Deny,
    };
    let overrun = timed_out
        || elapsed_ms > instruction.deadline_ms
        || stdout_bytes.len() > MAX_COMMAND_HOOK_STDOUT_BYTES;
    if overrun {
        let verdict = match instruction.on_failure {
            ProviderOnFailure::FailClosed => ProviderVerdictKind::Deny,
            ProviderOnFailure::StepUp => ProviderVerdictKind::StepUp,
            ProviderOnFailure::Ignore => ProviderVerdictKind::Allow,
        };
        return CommandHookEvalOutcome {
            response: ProviderVerdictResponse {
                provider_id: instruction.provider_id.clone(),
                verdict,
                reason_code: "provider.command_hook.overrun".into(),
                reason: "re-hosted command hook exceeded deadline or stdout cap".into(),
                rewritten_target: None,
                latency_ms: elapsed_ms,
            },
            degraded_provider: Some(instruction.provider_id.clone()),
        };
    }

    if exit_code != 0 {
        return CommandHookEvalOutcome {
            response: ProviderVerdictResponse {
                provider_id: instruction.provider_id.clone(),
                verdict: ProviderVerdictKind::Deny,
                reason_code: format!("provider.command_hook.exit_{exit_code}"),
                reason: "re-hosted command hook denied action".into(),
                rewritten_target: None,
                latency_ms: elapsed_ms,
            },
            degraded_provider: None,
        };
    }

    let Ok(raw_text) = std::str::from_utf8(stdout_bytes) else {
        return CommandHookEvalOutcome {
            response: ProviderVerdictResponse {
                provider_id: instruction.provider_id.clone(),
                verdict: failure_verdict,
                reason_code: "provider.command_hook.malformed_stdout".into(),
                reason: "re-hosted command hook emitted non-UTF8 stdout".into(),
                rewritten_target: None,
                latency_ms: elapsed_ms,
            },
            degraded_provider: Some(instruction.provider_id.clone()),
        };
    };
    let trimmed = raw_text.trim();
    if trimmed.is_empty() {
        return CommandHookEvalOutcome {
            response: ProviderVerdictResponse {
                provider_id: instruction.provider_id.clone(),
                verdict: failure_verdict,
                reason_code: "provider.command_hook.empty_stdout".into(),
                reason: "re-hosted command hook produced empty stdout".into(),
                rewritten_target: None,
                latency_ms: elapsed_ms,
            },
            degraded_provider: Some(instruction.provider_id.clone()),
        };
    }

    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(trimmed) {
        let Some(raw_dec) = map
            .get("decision")
            .or_else(|| map.get("verdict"))
            .and_then(Value::as_str)
        else {
            return CommandHookEvalOutcome {
                response: ProviderVerdictResponse {
                    provider_id: instruction.provider_id.clone(),
                    verdict: failure_verdict,
                    reason_code: "provider.command_hook.missing_decision".into(),
                    reason: "re-hosted command hook JSON missing decision/verdict".into(),
                    rewritten_target: None,
                    latency_ms: elapsed_ms,
                },
                degraded_provider: Some(instruction.provider_id.clone()),
            };
        };
        let dec = raw_dec.trim().to_ascii_lowercase();
        let verdict = match dec.as_str() {
            "allow" => ProviderVerdictKind::Allow,
            "deny" | "block" => ProviderVerdictKind::Deny,
            "step_up" | "step-up" | "ask" => ProviderVerdictKind::StepUp,
            "defer" => ProviderVerdictKind::Defer,
            _ => {
                return CommandHookEvalOutcome {
                    response: ProviderVerdictResponse {
                        provider_id: instruction.provider_id.clone(),
                        verdict: failure_verdict,
                        reason_code: "provider.command_hook.unknown_decision".into(),
                        reason: "re-hosted command hook emitted unrecognized decision".into(),
                        rewritten_target: None,
                        latency_ms: elapsed_ms,
                    },
                    degraded_provider: Some(instruction.provider_id.clone()),
                };
            }
        };
        let reason = sanitize_untrusted_text(
            map.get("reason")
                .and_then(Value::as_str)
                .unwrap_or("re-hosted command hook verdict"),
        );
        return CommandHookEvalOutcome {
            response: ProviderVerdictResponse {
                provider_id: instruction.provider_id.clone(),
                verdict,
                reason_code: format!("provider.command_hook.{dec}"),
                reason,
                rewritten_target: None,
                latency_ms: elapsed_ms,
            },
            degraded_provider: None,
        };
    }

    CommandHookEvalOutcome {
        response: ProviderVerdictResponse {
            provider_id: instruction.provider_id.clone(),
            verdict: failure_verdict,
            reason_code: "provider.command_hook.malformed_stdout".into(),
            reason: "re-hosted command hook emitted non-JSON stdout".into(),
            rewritten_target: None,
            latency_ms: elapsed_ms,
        },
        degraded_provider: Some(instruction.provider_id.clone()),
    }
}

pub fn verify_provider_request_minimization(
    caps: &ProviderCapabilities,
    request: &ProviderEvalRequest,
) -> Result<(), CodedError> {
    let preview = request.target_preview.as_str();
    match caps.max_capture_level {
        ProviderCaptureCeiling::MetadataOnly => {
            if !preview.is_empty() {
                return Err(CodedError::new(
                    "GRDR-BRK-0005",
                    format!(
                        "metadata_only provider `{}` received non-empty target_preview",
                        caps.provider_id
                    ),
                    "Strip target argument bytes before dispatching to metadata_only providers.",
                ));
            }
        }
        ProviderCaptureCeiling::ArgumentPreview => {
            if preview.chars().count() > ARGUMENT_PREVIEW_MAX_CHARS {
                return Err(CodedError::new(
                    "GRDR-BRK-0005",
                    format!(
                        "argument_preview provider `{}` target_preview exceeds {ARGUMENT_PREVIEW_MAX_CHARS} chars",
                        caps.provider_id
                    ),
                    "Truncate target_preview before dispatching.",
                ));
            }
        }
        ProviderCaptureCeiling::FullMinimised => {
            if preview.chars().count() > FULL_MINIMISED_MAX_CHARS {
                return Err(CodedError::new(
                    "GRDR-BRK-0005",
                    format!(
                        "full_minimised provider `{}` target_preview exceeds {FULL_MINIMISED_MAX_CHARS} chars",
                        caps.provider_id
                    ),
                    "Truncate target_preview before dispatching.",
                ));
            }
        }
    }
    if contains_unscrubbed_url_parts(preview) {
        return Err(CodedError::new(
            "GRDR-BRK-0005",
            format!(
                "provider `{}` request contained unscrubbed URL userinfo, query, or fragment",
                caps.provider_id
            ),
            "Strip URL userinfo, query, and fragment before provider fanout.",
        ));
    }
    if contains_secret_indicator(preview) {
        return Err(CodedError::new(
            "GRDR-BRK-0005",
            format!(
                "provider `{}` request contained unredacted secret material",
                caps.provider_id
            ),
            "Scrub secrets before provider fanout.",
        ));
    }
    Ok(())
}

fn contains_unscrubbed_url_parts(preview: &str) -> bool {
    for tok in preview.split_whitespace() {
        let Some(scheme_pos) = tok.find("://") else {
            continue;
        };
        let rest = tok.get(scheme_pos.saturating_add(3)..).unwrap_or("");
        if rest.contains('?') || rest.contains('#') {
            return true;
        }
        let auth = rest.split('/').next().unwrap_or("");
        if auth.contains('@') {
            return true;
        }
    }
    false
}

#[must_use]
pub fn list_foreign_hooks(settings_json: &str, own_command: &str) -> Vec<ForeignHookEntry> {
    let Ok(Value::Object(root)) = serde_json::from_str::<Value>(settings_json) else {
        return Vec::new();
    };
    let Some(Value::Object(hooks)) = root.get("hooks") else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (event, entries) in hooks {
        let Some(arr) = entries.as_array() else {
            continue;
        };
        for item in arr {
            collect_foreign_cmds(event, item, own_command, &mut found);
        }
    }
    found
}

#[must_use]
pub fn build_capabilities_json(agents: &[AgentCapabilityMatrixInput]) -> Value {
    let mut agent_map = serde_json::Map::new();
    for agent in agents {
        let mut events_obj = serde_json::Map::new();
        for ev in CANONICAL_HOOK_EVENTS {
            let claim = agent
                .claims
                .get(*ev)
                .copied()
                .unwrap_or(CapabilitySupportClaim::Unavailable);
            events_obj.insert((*ev).to_owned(), json!(claim));
        }
        agent_map.insert(
            agent.agent_id.clone(),
            json!({
                "version_range": agent.version_range,
                "fail_mode": agent.fail_mode,
                "events": Value::Object(events_obj),
            }),
        );
    }
    json!({
        "schema": "grdr.hook-broker.capabilities/v1alpha1",
        "canonical_events": CANONICAL_HOOK_EVENTS,
        "agents": Value::Object(agent_map),
    })
}

fn collect_foreign_cmds(
    event: &str,
    val: &Value,
    own_command: &str,
    out: &mut Vec<ForeignHookEntry>,
) {
    if let Some(cmd) = val.get("command").and_then(Value::as_str)
        && !is_own_hook_command(cmd, own_command)
    {
        out.push(ForeignHookEntry {
            event: event.to_owned(),
            command: cmd.to_owned(),
        });
    }
    if let Some(arr) = val.get("hooks").and_then(Value::as_array) {
        for sub in arr {
            collect_foreign_cmds(event, sub, own_command, out);
        }
    }
}

fn is_own_hook_command(cmd: &str, own_command: &str) -> bool {
    let trimmed = cmd.trim();
    if trimmed.is_empty()
        || own_command.trim().is_empty()
        || trimmed.contains(['&', '<', '>', ';', '|', '`', '\r', '\n'])
        || trimmed.contains("$(")
        || trimmed.contains("${")
    {
        return false;
    }
    let exe = if let Some(rest) = trimmed.strip_prefix('"') {
        rest.split('"').next().unwrap_or("")
    } else if let Some(rest) = trimmed.strip_prefix('\'') {
        rest.split('\'').next().unwrap_or("")
    } else {
        trimmed.split_whitespace().next().unwrap_or("")
    };
    if exe.is_empty() {
        return false;
    }
    let own_trimmed = own_command.trim();
    if exe == own_trimmed {
        return true;
    }
    let exe_is_bare =
        std::path::Path::new(exe).components().count() == 1 && !exe.contains(['/', '\\']);
    let own_is_bare = std::path::Path::new(own_trimmed).components().count() == 1
        && !own_trimmed.contains(['/', '\\']);
    if !(exe_is_bare || own_is_bare) {
        return false;
    }
    let exe_name = exe
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.strip_suffix(".exe").unwrap_or(s));
    let own_name = own_trimmed
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.strip_suffix(".exe").unwrap_or(s));
    matches!((exe_name, own_name), (Some(a), Some(b)) if a == b)
}
