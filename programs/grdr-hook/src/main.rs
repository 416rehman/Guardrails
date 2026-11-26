// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Thin fail-closed endpoint hook binary (`grdr-hook`) over OS IPC and signed binary floor cache.

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use clap::Parser;
use grdr_crypto::sha256_hex;
use grdr_os_clock::{Clock, SystemClock};
use grdr_wire::limits::embedded_limits;
use grdr_wire::messages::WireVerdict;

use grdr_hook::dialect::{HookDialect, classify_action, format_dialect_decision};
use grdr_hook::floor_fallback::HookVerdictOutcome;
use grdr_hook::ipc_client::{evaluate_against_daemon_or_floor, is_protected_profile_active};
use grdr_hook::json_scan::{ScannedHookInput, max_hook_stdin_bytes, scan_hook_json};
use grdr_hook::offline_spool::{
    enqueue_offline_metadata, resolve_offline_spool_dir, resolve_protected_state_dir,
};

const DEFAULT_WATCHDOG_TIMEOUT_MS: u64 = 1950;

#[derive(Debug, Parser)]
#[command(
    name = "grdr-hook",
    about = "Guardrails ADR thin fail-closed hook shim"
)]
struct Args {
    #[arg(long, default_value = "auto")]
    agent: String,
    #[arg(long)]
    action: Option<String>,
    #[arg(long)]
    target: Option<String>,
    #[arg(long)]
    session_id: Option<String>,
    #[arg(long)]
    socket: Option<String>,
    #[arg(long)]
    state_dir: Option<String>,
}

enum WorkerResult {
    Evaluated {
        input: Box<ScannedHookInput>,
        outcome: HookVerdictOutcome,
    },
    InputRejected {
        dialect: HookDialect,
        message: String,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();
    let started = Instant::now();
    let protected = is_protected_profile_active();
    let default_dialect =
        HookDialect::from_cli_name(&args.agent).unwrap_or(HookDialect::ClaudeCode);

    if protected && has_protected_override_tamper(&args) {
        emit_fail_closed(
            default_dialect,
            "PreToolUse",
            "protected profile rejects custom --state-dir, --socket, or environment overrides",
        );
        return ExitCode::from(2);
    }

    let state_dir = if protected {
        resolve_protected_state_dir(true)
    } else {
        args.state_dir
            .as_ref()
            .map_or_else(|| resolve_protected_state_dir(false), PathBuf::from)
    };
    let sock_override = (!protected).then(|| args.socket.clone()).flatten();

    let has_cli_action = args.action.is_some() && args.target.is_some();
    if !has_cli_action && std::io::stdin().is_terminal() {
        emit_fail_closed(
            default_dialect,
            "PreToolUse",
            "grdr-hook requires JSON on stdin or explicit --action and --target",
        );
        return ExitCode::from(2);
    }

    let (tx, rx) = mpsc::channel();
    let state_worker = state_dir.clone();
    let cli_action = args.action;
    let cli_target = args.target;
    let cli_session = args.session_id;
    let cli_agent = args.agent;
    let now_wall = SystemClock::new()
        .now_wall()
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    let req_id = format!("hk-{}-{}", std::process::id(), now_wall.as_millisecond());

    let _worker = std::thread::spawn(move || {
        let result = match parse_invocation(
            &cli_agent,
            cli_action.as_deref(),
            cli_target.as_deref(),
            cli_session.as_deref(),
        ) {
            Ok(input) => {
                let outcome = evaluate_against_daemon_or_floor(
                    &input,
                    &state_worker,
                    sock_override.as_deref(),
                    protected,
                    &req_id,
                    1,
                    started,
                );
                if outcome.floor_fallback || !outcome.degraded_reason.is_empty() {
                    let spool_dir = resolve_offline_spool_dir(protected, &state_worker);
                    record_offline(&spool_dir, &input, &outcome);
                }
                WorkerResult::Evaluated {
                    input: Box::new(input),
                    outcome,
                }
            }
            Err(message) => {
                let dialect =
                    HookDialect::from_cli_name(&cli_agent).unwrap_or(HookDialect::ClaudeCode);
                WorkerResult::InputRejected { dialect, message }
            }
        };
        let _ = tx.send(result);
    });

    let watchdog_ms = embedded_limits().map_or(DEFAULT_WATCHDOG_TIMEOUT_MS, |l| {
        l.shim_hang_max_ms.saturating_sub(50).max(250)
    });
    let remaining_watchdog = Duration::from_millis(watchdog_ms)
        .checked_sub(started.elapsed())
        .unwrap_or(Duration::from_millis(1));
    match rx.recv_timeout(remaining_watchdog) {
        Ok(WorkerResult::Evaluated { input, outcome }) => {
            let rendered = format_dialect_decision(
                input.dialect,
                &input.event_name,
                outcome.verdict,
                &outcome.reason,
                &outcome.rule_id,
            );
            println!("{rendered}");
            match outcome.verdict {
                WireVerdict::Allow => ExitCode::SUCCESS,
                WireVerdict::Ask | WireVerdict::Block | WireVerdict::Unspecified => {
                    ExitCode::from(2)
                }
            }
        }
        Ok(WorkerResult::InputRejected { dialect, message }) => {
            emit_fail_closed(dialect, "PreToolUse", &message);
            ExitCode::from(2)
        }
        Err(_) => {
            emit_fail_closed(
                default_dialect,
                "PreToolUse",
                "hook exceeded watchdog deadline; failing closed",
            );
            ExitCode::from(2)
        }
    }
}

fn has_protected_override_tamper(args: &Args) -> bool {
    args.state_dir.is_some()
        || args.socket.is_some()
        || std::env::var_os("GRDR_STATE_DIR").is_some_and(|v| !v.is_empty())
        || std::env::var_os("GRDR_DECIDE_ENDPOINT").is_some_and(|v| !v.is_empty())
}

fn parse_invocation(
    agent: &str,
    action: Option<&str>,
    target: Option<&str>,
    session_id: Option<&str>,
) -> Result<ScannedHookInput, String> {
    if let (Some(action), Some(target)) = (action, target) {
        if action.trim().is_empty() || target.trim().is_empty() {
            return Err("hook --action and --target cannot be empty".to_string());
        }
        let dialect = HookDialect::from_cli_name(agent).unwrap_or(HookDialect::ClaudeCode);
        let is_shell = action.eq_ignore_ascii_case("bash")
            || action.eq_ignore_ascii_case("exec")
            || action.eq_ignore_ascii_case("sh")
            || action.eq_ignore_ascii_case("pwsh")
            || action.eq_ignore_ascii_case("cmd")
            || action.eq_ignore_ascii_case("powershell");
        return Ok(ScannedHookInput {
            dialect,
            session_id: session_id.unwrap_or_default().to_string(),
            event_name: "PreToolUse".to_string(),
            tool_name: action.to_string(),
            target: target.to_string(),
            command_line: if is_shell {
                target.to_string()
            } else {
                String::new()
            },
            cwd: String::new(),
            payload_sha256: sha256_hex(format!("{action}:{target}").as_bytes()),
            raw_payload: String::new(),
            action_class: classify_action(action, "PreToolUse", ""),
            control_point: 1,
        });
    }

    let max_stdin = max_hook_stdin_bytes();
    let mut raw = Vec::new();
    let mut handle =
        std::io::stdin().take(u64::try_from(max_stdin.saturating_add(1)).unwrap_or(u64::MAX));
    handle
        .read_to_end(&mut raw)
        .map_err(|err| format!("hook stdin read error (fail-closed): {err}"))?;

    scan_hook_json(&raw, agent).map_err(|err| err.to_string())
}

fn record_offline(state_dir: &Path, input: &ScannedHookInput, outcome: &HookVerdictOutcome) {
    let verdict_label = match outcome.verdict {
        WireVerdict::Allow => "allow",
        WireVerdict::Ask => "ask",
        WireVerdict::Block | WireVerdict::Unspecified => "block",
    };
    let wall = SystemClock::new()
        .now_wall()
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    let ts_ms = wall.as_millisecond();
    if let Err(err) = enqueue_offline_metadata(
        state_dir,
        input.dialect.as_agent_str(),
        &input.session_id,
        &input.target,
        verdict_label,
        &outcome.reason,
        ts_ms,
    ) {
        eprintln!("hook offline spool write failed: {}", err.kind());
    }
}

fn emit_fail_closed(dialect: HookDialect, event_name: &str, reason: &str) {
    let body = format_dialect_decision(
        dialect,
        event_name,
        WireVerdict::Block,
        reason,
        "HOOK-FAIL-CLOSED",
    );
    println!("{body}");
    eprintln!("{reason}");
}
