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

use grdr_hook::dialect::{
    DecisionRenderExtras, HookDialect, classify_action, format_dialect_decision_ext, is_shell_tool,
};
use grdr_hook::floor_fallback::HookVerdictOutcome;
use grdr_hook::ipc_client::{evaluate_against_daemon_or_floor, is_protected_profile_active};
use grdr_hook::json_scan::{ScannedHookInput, max_hook_stdin_bytes, scan_hook_json};
use grdr_hook::offline_spool::{
    enqueue_offline_metadata, resolve_offline_spool_dir, resolve_protected_state_dir,
};
use grdr_hook::provider_exec::{
    ProviderFailureMode, ProviderHookOutcome, evaluate_command_hook_outcome, execute_command_hook,
    lookup_provider_index, read_native_messaging_frame_bounded, write_native_messaging_frame,
};

const DEFAULT_WATCHDOG_TIMEOUT_MS: u64 = 1950;

#[derive(Debug, Parser)]
#[command(name = "grdr-hook", about = "Thin fail-closed endpoint hook shim")]
struct Args {
    #[arg(long, default_value = "auto")]
    agent: String,
    #[arg(long)]
    event: Option<String>,
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
    #[arg(long)]
    strict: bool,
    #[arg(long)]
    native_messaging: bool,
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
    let Some(default_dialect) =
        HookDialect::from_cli_name(&args.agent).or_else(HookDialect::default_dialect)
    else {
        eprintln!("hook dialect registry unavailable");
        return ExitCode::from(2);
    };

    if protected && has_protected_override_tamper(&args) {
        if !emit_response(
            args.native_messaging,
            default_dialect,
            args.event.as_deref().unwrap_or("PreToolUse"),
            WireVerdict::Block,
            "protected profile rejects custom --state-dir, --socket, or environment overrides",
            "HOOK-FAIL-CLOSED",
            DecisionRenderExtras::default(),
        ) {
            eprintln!("failed writing tamper rejection response");
        }
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
    if !has_cli_action && !args.native_messaging && std::io::stdin().is_terminal() {
        if !emit_response(
            false,
            default_dialect,
            args.event.as_deref().unwrap_or("PreToolUse"),
            WireVerdict::Block,
            "grdr-hook requires JSON on stdin or explicit --action and --target",
            "HOOK-FAIL-CLOSED",
            DecisionRenderExtras::default(),
        ) {
            eprintln!("failed writing terminal usage rejection");
        }
        return ExitCode::from(2);
    }

    let watchdog_ms = embedded_limits().map_or(DEFAULT_WATCHDOG_TIMEOUT_MS, |l| {
        l.shim_hang_max_ms.saturating_sub(50).max(250)
    });
    let remaining_watchdog = Duration::from_millis(watchdog_ms)
        .checked_sub(started.elapsed())
        .unwrap_or(Duration::from_millis(1));

    let (tx, rx) = mpsc::channel();
    let state_worker = state_dir.clone();
    let cli_action = args.action;
    let cli_target = args.target;
    let cli_session = args.session_id.clone();
    let worker_session = args.session_id;
    let cli_event = args.event.clone();
    let worker_event = args.event;
    let cli_agent = args.agent;
    let cli_native_msg = args.native_messaging;
    let cli_strict = args.strict || protected;
    let now_wall = SystemClock::new()
        .now_wall()
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    let req_id = format!("hk-{}-{}", std::process::id(), now_wall.as_millisecond());

    let _worker = std::thread::spawn(move || {
        let result = match parse_invocation(
            &cli_agent,
            worker_event.as_deref(),
            cli_action.as_deref(),
            cli_target.as_deref(),
            worker_session.as_deref(),
            cli_native_msg,
            remaining_watchdog,
        ) {
            Ok((input, raw_bytes)) => {
                let mut outcome = evaluate_against_daemon_or_floor(
                    &input,
                    &state_worker,
                    sock_override.as_deref(),
                    protected,
                    &req_id,
                    1,
                    started,
                );
                apply_rehosted_providers(&state_worker, protected, &raw_bytes, &mut outcome);
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
                let dialect = HookDialect::from_cli_name(&cli_agent).unwrap_or(default_dialect);
                WorkerResult::InputRejected { dialect, message }
            }
        };
        if let Err(err) = tx.send(result) {
            eprintln!("hook worker result delivery stopped: {err}");
        }
    });

    match rx.recv_timeout(remaining_watchdog) {
        Ok(WorkerResult::Evaluated { input, outcome }) => {
            if !emit_response(
                cli_native_msg,
                input.dialect,
                &input.event_name,
                outcome.verdict,
                &outcome.reason,
                &outcome.rule_id,
                DecisionRenderExtras {
                    retry_token: outcome.retry_token.as_deref(),
                    modified_target: outcome.modified_target.as_deref(),
                },
            ) {
                return ExitCode::from(2);
            }
            match outcome.verdict {
                WireVerdict::Allow => ExitCode::SUCCESS,
                WireVerdict::Ask | WireVerdict::Block | WireVerdict::Unspecified => {
                    ExitCode::from(2)
                }
            }
        }
        Ok(WorkerResult::InputRejected { dialect, message }) => {
            if !emit_response(
                cli_native_msg,
                dialect,
                cli_event.as_deref().unwrap_or("PreToolUse"),
                WireVerdict::Block,
                &message,
                "HOOK-FAIL-CLOSED",
                DecisionRenderExtras::default(),
            ) {
                eprintln!("failed writing input rejection response");
            }
            ExitCode::from(2)
        }
        Err(_) => {
            let timeout_reason = if cli_strict {
                "hook exceeded watchdog deadline in strict mode; failing closed"
            } else {
                "hook-timeout-open: watchdog deadline elapsed in non-strict mode"
            };
            let timeout_verdict = if cli_strict {
                WireVerdict::Block
            } else {
                let spool_dir = resolve_offline_spool_dir(protected, &state_dir);
                if let Err(err) = enqueue_offline_metadata(
                    &spool_dir,
                    default_dialect.as_agent_str(),
                    cli_session.as_deref().unwrap_or_default(),
                    "watchdog-timeout",
                    "hook-timeout-open",
                    timeout_reason,
                    now_wall.as_millisecond(),
                ) {
                    eprintln!("hook timeout offline spool write failed: {}", err.kind());
                }
                WireVerdict::Allow
            };
            let emitted = emit_response(
                cli_native_msg,
                default_dialect,
                cli_event.as_deref().unwrap_or("PreToolUse"),
                timeout_verdict,
                timeout_reason,
                if cli_strict {
                    "HOOK-STRICT-TIMEOUT"
                } else {
                    "HOOK-TIMEOUT-OPEN"
                },
                DecisionRenderExtras::default(),
            );
            if cli_strict || !emitted {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

fn apply_rehosted_providers(
    state_dir: &Path,
    protected: bool,
    raw_bytes: &[u8],
    outcome: &mut HookVerdictOutcome,
) {
    let provider_ids = std::mem::take(&mut outcome.run_provider_ids);
    for prov_id in provider_ids {
        let entry = match lookup_provider_index(state_dir, &prov_id, protected) {
            Ok(e) => e,
            Err(err) => {
                outcome.verdict = WireVerdict::Block;
                outcome.rule_id = format!("provider/{prov_id}");
                outcome.reason =
                    format!("re-hosted provider `{prov_id}` failed index check: {err}");
                outcome.degraded_reason = "provider-index-untrusted".to_string();
                return;
            }
        };
        let prov_outcome = match execute_command_hook(&entry, raw_bytes, protected) {
            Ok(out) => evaluate_command_hook_outcome(&entry, &out),
            Err(err) => {
                let verdict = match entry.on_failure {
                    ProviderFailureMode::FailClosed => WireVerdict::Block,
                    ProviderFailureMode::StepUp => WireVerdict::Ask,
                    ProviderFailureMode::Ignore => WireVerdict::Allow,
                };
                ProviderHookOutcome {
                    verdict,
                    rule_id: format!("provider/{prov_id}"),
                    reason: format!("re-hosted provider `{prov_id}` execution error: {err}"),
                    degraded_reason: format!("provider-exec-error: {err}"),
                }
            }
        };
        if !prov_outcome.degraded_reason.is_empty() {
            outcome.degraded_reason = prov_outcome.degraded_reason;
        }
        if verdict_rank(prov_outcome.verdict) > verdict_rank(outcome.verdict) {
            outcome.verdict = prov_outcome.verdict;
            outcome.rule_id = prov_outcome.rule_id;
            outcome.reason = prov_outcome.reason;
        }
        if outcome.verdict == WireVerdict::Block {
            return;
        }
    }
}

const fn verdict_rank(verdict: WireVerdict) -> u8 {
    match verdict {
        WireVerdict::Allow => 0,
        WireVerdict::Ask => 1,
        WireVerdict::Block | WireVerdict::Unspecified => 2,
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
    event_override: Option<&str>,
    action: Option<&str>,
    target: Option<&str>,
    session_id: Option<&str>,
    native_messaging: bool,
    stdin_timeout: Duration,
) -> Result<(ScannedHookInput, Vec<u8>), String> {
    if let (Some(action), Some(target)) = (action, target) {
        if action.trim().is_empty() || target.trim().is_empty() {
            return Err("hook --action and --target cannot be empty".to_string());
        }
        let dialect = HookDialect::from_cli_name(agent)
            .or_else(HookDialect::default_dialect)
            .ok_or_else(|| "hook dialect registry empty".to_string())?;
        let event_name = event_override
            .unwrap_or_else(|| dialect.default_event())
            .to_string();
        let is_shell = is_shell_tool(action);
        let raw_bytes = format!("{action}:{target}").into_bytes();
        return Ok((
            ScannedHookInput {
                dialect,
                session_id: session_id.unwrap_or_default().to_string(),
                event_name: event_name.clone(),
                tool_name: action.to_string(),
                target: target.to_string(),
                command_line: if is_shell {
                    target.to_string()
                } else {
                    String::new()
                },
                cwd: String::new(),
                payload_sha256: sha256_hex(&raw_bytes),
                raw_payload: String::new(),
                action_class: classify_action(action, &event_name, ""),
                control_point: 1,
            },
            raw_bytes,
        ));
    }

    let max_stdin = max_hook_stdin_bytes();
    let raw = if native_messaging {
        read_native_messaging_frame_bounded(std::io::stdin(), max_stdin, stdin_timeout)
            .map_err(|e| e.to_string())?
    } else {
        let mut buf = Vec::new();
        std::io::stdin()
            .take(u64::try_from(max_stdin.saturating_add(1)).unwrap_or(u64::MAX))
            .read_to_end(&mut buf)
            .map_err(|err| format!("hook stdin read error (fail-closed): {err}"))?;
        buf
    };

    let mut scanned = scan_hook_json(&raw, agent).map_err(|err| err.to_string())?;
    if scanned.event_name.is_empty()
        && let Some(ev) = event_override
    {
        scanned.event_name = ev.to_string();
    }
    Ok((scanned, raw))
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

fn emit_response(
    native_messaging: bool,
    dialect: HookDialect,
    event_name: &str,
    verdict: WireVerdict,
    reason: &str,
    rule_id: &str,
    extras: DecisionRenderExtras<'_>,
) -> bool {
    let body = format_dialect_decision_ext(dialect, event_name, verdict, reason, rule_id, extras);
    if native_messaging {
        if let Err(err) = write_native_messaging_frame(&mut std::io::stdout(), body.as_bytes()) {
            eprintln!("native messaging stdout write failed: {err}");
            return false;
        }
    } else {
        println!("{body}");
    }
    if !matches!(verdict, WireVerdict::Allow) {
        eprintln!("{reason}");
    }
    true
}
