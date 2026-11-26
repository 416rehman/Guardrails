// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use jiff::Timestamp;

use grdr_core::compile::evaluate_compiled_floor;
use grdr_core::policy::{essentials_pack, evaluate};
use grdr_fastpath::{FastActionClass, FastVerdict};
use grdr_model::{
    ActionAttempt, ActionClass, CompiledFloorTable, KillSwitchState, SignatureStatus,
    TrustedKeyInfo, Verdict, verify_floor_table,
};

use crate::gate::{GateDecisionSource, GateVerdict};
use grdr_os_clock::{Clock, SystemClock};
use grdr_peer_os::fs_open::{
    OpenNofollowAccess, open_nofollow_dir, open_nofollow_file, verify_open_dir_trust,
    verify_open_file_trust,
};
use grdr_wire::floor_bin::{
    FloorBinError, FloorRuleRecord, FloorTableFreshness, MAX_FLOOR_BYTES, floor_verdict_rank,
    verify_and_decode_floor_table,
};
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::WireVerdict;
use grdr_wire::peer_auth::Profile;

use crate::RunError;

pub(crate) struct SignedFloorOutcome {
    pub(crate) verdict: WireVerdict,
    pub(crate) rule_id: String,
    pub(crate) reason: String,
    pub(crate) stale: bool,
}

pub(crate) fn is_safe_non_temp_candidate(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    if raw.trim().is_empty() || raw.contains('\0') || raw.chars().any(char::is_control) {
        return false;
    }
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    if raw == "/tmp"
        || raw.starts_with("/tmp/")
        || raw == "/var/tmp"
        || raw.starts_with("/var/tmp/")
    {
        return false;
    }
    let temp = std::env::temp_dir();
    if path.starts_with(&temp) {
        return false;
    }
    #[cfg(unix)]
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        if meta.file_type().is_symlink() || (meta.permissions().mode() & 0o002) != 0 {
            return false;
        }
    }
    true
}

pub(crate) fn default_state_dir(
    profile: Profile,
    custom_root: Option<&Path>,
) -> Result<PathBuf, RunError> {
    if profile == Profile::Protected {
        return Ok(system_state_dir());
    }
    if let Some(root) = custom_root {
        if !is_safe_non_temp_candidate(root) {
            return Err(RunError::PolicyDenied(format!(
                "state dir root `{}` is unsafe or inside a shared temp directory",
                root.display()
            )));
        }
        return Ok(root.to_path_buf());
    }
    if let Ok(explicit) = std::env::var("GRDR_STATE_DIR")
        && !explicit.trim().is_empty()
    {
        let p = PathBuf::from(&explicit);
        if !is_safe_non_temp_candidate(&p) {
            return Err(RunError::PolicyDenied(format!(
                "GRDR_STATE_DIR `{explicit}` rejected: must be non-temp absolute non-symlink directory"
            )));
        }
        return Ok(p);
    }
    #[cfg(windows)]
    {
        let local_app = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|p| is_safe_non_temp_candidate(p))
            .ok_or_else(|| {
                RunError::GateUnavailable(
                    "LOCALAPPDATA unavailable for user profile floor state dir".into(),
                )
            })?;
        Ok(local_app.join("Guardrails").join("state"))
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| is_safe_non_temp_candidate(p))
            .ok_or_else(|| {
                RunError::GateUnavailable(
                    "HOME unavailable for user profile floor state dir".into(),
                )
            })?;
        Ok(home.join(".local/state/guardrails"))
    }
}

pub(crate) fn system_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from("C:\\ProgramData\\Guardrails\\state")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/guardrails/state")
    }
}

pub(crate) fn evaluate_signed_floor_file(
    state_dir: &Path,
    protected: bool,
    attempt: &ActionAttempt,
    now: Timestamp,
    daemon_err: &str,
) -> Result<SignedFloorOutcome, RunError> {
    if protected && state_dir != system_state_dir() {
        return Err(RunError::GateUnavailable(
            "protected profile prohibits custom floor state directory".into(),
        ));
    }
    let dir_file = open_nofollow_dir(state_dir)
        .map_err(|e| RunError::GateUnavailable(format!("{daemon_err}; floor dir open: {e}")))?;
    verify_open_dir_trust(&dir_file, state_dir, protected).map_err(|e| {
        RunError::GateUnavailable(format!("{daemon_err}; floor dir untrusted: {e}"))
    })?;

    let pub_cap = embedded_limits()
        .map_err(|e| RunError::GateUnavailable(format!("limits load: {e}")))?
        .floor_pubkey_max_bytes;
    let floor_path = state_dir.join("floor.bin");
    let pub_path = state_dir.join("floor.pub");
    let floor_bytes = read_trusted_bounded_file(&floor_path, MAX_FLOOR_BYTES, protected)
        .map_err(|e| RunError::GateUnavailable(format!("{daemon_err}; floor.bin: {e}")))?;
    let pub_bytes = read_trusted_bounded_file(&pub_path, pub_cap, protected)
        .map_err(|e| RunError::GateUnavailable(format!("{daemon_err}; floor.pub: {e}")))?;

    let pub_str = std::str::from_utf8(&pub_bytes).map_err(|_| RunError::FloorUntrusted)?;
    let (key_id, key_b64) = pub_str
        .trim()
        .split_once(':')
        .ok_or(RunError::FloorUntrusted)?;
    let now_unix_s = SystemClock::new()
        .now_wall()
        .map_err(|e| RunError::GateUnavailable(format!("system clock unavailable: {e}")))?
        .as_second();

    let doc =
        verify_and_decode_floor_table(&floor_bytes, &[(key_id.trim(), key_b64.trim())], now_unix_s)
            .map_err(|err| match err {
                FloorBinError::UntrustedSignature
                | FloorBinError::InvalidHeader
                | FloorBinError::MalformedField { .. }
                | FloorBinError::Truncated { .. }
                | FloorBinError::TooManyRules { .. } => RunError::FloorUntrusted,
                other => RunError::GateUnavailable(format!("{daemon_err}; floor decode: {other}")),
            })?;

    let stale = matches!(doc.freshness, FloorTableFreshness::Stale { .. });
    let fast_action = to_fast_action_class(attempt.action_class);
    if let Some(matched) = highest_severity_match(
        &doc.document.rules,
        fast_action,
        &attempt.agent_name,
        &attempt.target,
    ) {
        let verdict = match matched.verdict {
            FastVerdict::Allow => WireVerdict::Allow,
            FastVerdict::StepUp => WireVerdict::Ask,
            FastVerdict::Deny => WireVerdict::Block,
        };
        return Ok(SignedFloorOutcome {
            verdict,
            rule_id: matched.rule_id.clone(),
            reason: format!(
                "compiled binary floor rule `{}` ({daemon_err})",
                matched.rule_id
            ),
            stale,
        });
    }

    let packs = [essentials_pack()];
    let receipt = evaluate(attempt, &packs, &[], &KillSwitchState::Inactive, now);
    let verdict = match receipt.verdict {
        Verdict::Allow => WireVerdict::Allow,
        Verdict::StepUp => WireVerdict::Ask,
        Verdict::Deny | Verdict::Defer | Verdict::Modify => WireVerdict::Block,
    };
    Ok(SignedFloorOutcome {
        verdict,
        rule_id: receipt
            .rule_id
            .unwrap_or_else(|| "ESSENTIALS-FALLBACK".into()),
        reason: format!("{} ({daemon_err})", receipt.reason),
        stale,
    })
}

pub(crate) fn evaluate_in_memory_floor(
    table: &CompiledFloorTable,
    trusted_keys: &[TrustedKeyInfo],
    attempt: &ActionAttempt,
    now: Timestamp,
) -> Result<GateVerdict, RunError> {
    if verify_floor_table(table, trusted_keys) != SignatureStatus::Verified {
        return Err(RunError::FloorUntrusted);
    }
    tracing::warn!(
        sr = "SR-15",
        degraded = true,
        session_id = %attempt.session_id,
        action_class = attempt.action_class.as_str(),
        "grdr-daemon unavailable; evaluating signed offline compiled floor in degraded mode"
    );
    let source = GateDecisionSource::SignedCompiledFloor { degraded: true };
    let stale_after_days = i64::from(
        embedded_limits()
            .map_err(|e| RunError::GateUnavailable(format!("limits load: {e}")))?
            .stale_after_days,
    );
    let max_age_s = stale_after_days.saturating_mul(86_400);
    let age_s = now
        .as_second()
        .saturating_sub(table.compiled_at.as_second());
    if age_s > max_age_s || table.compiled_at > now {
        return Ok(GateVerdict::Deny {
            source,
            reason: "signed compiled floor table is stale or future-dated; failing closed".into(),
        });
    }
    if let Some(matched) = evaluate_compiled_floor(
        table,
        attempt.action_class,
        &attempt.agent_name,
        &attempt.target,
    ) {
        return match matched.verdict {
            Verdict::Allow if attempt.action_class != ActionClass::AgentSpawn => {
                Ok(GateVerdict::Allow { source })
            }
            Verdict::Allow => Ok(GateVerdict::Deny {
                source,
                reason: "D-15: session container spawn fails closed while daemon is offline".into(),
            }),
            Verdict::Deny | Verdict::StepUp | Verdict::Defer | Verdict::Modify => {
                Ok(GateVerdict::Deny {
                    source,
                    reason: format!("compiled floor rule `{}` denied launch", matched.rule_id),
                })
            }
        };
    }
    if attempt.action_class == ActionClass::AgentSpawn {
        return Ok(GateVerdict::Deny {
            source,
            reason: "D-15: session container launch denied while grdr-daemon is offline".into(),
        });
    }
    let packs = [essentials_pack()];
    let receipt = evaluate(attempt, &packs, &[], &KillSwitchState::Inactive, now);
    match receipt.verdict {
        Verdict::Allow => Ok(GateVerdict::Allow { source }),
        Verdict::Deny | Verdict::StepUp | Verdict::Defer | Verdict::Modify => {
            Ok(GateVerdict::Deny {
                source,
                reason: receipt.reason,
            })
        }
    }
}

fn read_trusted_bounded_file(
    path: &Path,
    max_bytes: usize,
    protected: bool,
) -> Result<Vec<u8>, String> {
    let file =
        open_nofollow_file(path, OpenNofollowAccess::ReadOnly, 0o600).map_err(|e| e.to_string())?;
    verify_open_file_trust(&file, protected).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    let declared = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    if declared > max_bytes {
        return Err(format!("file exceeds {max_bytes} bytes"));
    }
    let mut out = Vec::new();
    let cap = u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    file.take(cap)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() > max_bytes {
        return Err(format!("file read exceeds {max_bytes} bytes"));
    }
    Ok(out)
}

fn highest_severity_match<'a>(
    rules: &'a [FloorRuleRecord],
    action: FastActionClass,
    agent: &str,
    target: &str,
) -> Option<&'a FloorRuleRecord> {
    let mut best: Option<&FloorRuleRecord> = None;
    for rule in rules {
        if !rule.matches(action, agent, target) {
            continue;
        }
        let replace = match best {
            None => true,
            Some(prev) => floor_verdict_rank(rule.verdict) > floor_verdict_rank(prev.verdict),
        };
        if replace {
            best = Some(rule);
        }
    }
    best
}

fn to_fast_action_class(class: ActionClass) -> FastActionClass {
    match class {
        ActionClass::Exec => FastActionClass::Exec,
        ActionClass::FileRead => FastActionClass::FileRead,
        ActionClass::FileWrite => FastActionClass::FileWrite,
        ActionClass::FileDelete => FastActionClass::FileDelete,
        ActionClass::NetConnect => FastActionClass::NetConnect,
        ActionClass::NetRequest => FastActionClass::NetRequest,
        ActionClass::LlmRequest => FastActionClass::LlmRequest,
        ActionClass::McpConnect => FastActionClass::McpConnect,
        ActionClass::McpCall => FastActionClass::McpCall,
        ActionClass::CredUse => FastActionClass::CredUse,
        ActionClass::AgentSpawn => FastActionClass::AgentSpawn,
        ActionClass::ConfigChange => FastActionClass::ConfigChange,
        ActionClass::Elevate => FastActionClass::Elevate,
        ActionClass::UiAct => FastActionClass::UiAct,
        ActionClass::DataFlow => FastActionClass::DataFlow,
    }
}
