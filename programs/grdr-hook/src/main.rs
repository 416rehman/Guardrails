// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::{IsTerminal, Read};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use jiff::Timestamp;

use grdr_agents::{detect_hostname, parse_claude_hook_stdin};
use grdr_model::eval::{essentials_pack, evaluate_attempt};
use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, DecideInput, DecisionReceipt, KillSwitchState,
    Verdict,
};

#[derive(Debug, Parser)]
#[command(
    name = "grdr-hook",
    about = "Guardrails ADR low-latency agent hook shim"
)]
struct Args {
    #[arg(long, env = "GRDR_DAEMON_URL", default_value = "http://127.0.0.1:8788")]
    daemon: String,

    #[arg(long, default_value_t = 250)]
    timeout_ms: u64,

    #[arg(long)]
    action: Option<String>,

    #[arg(long)]
    target: Option<String>,

    #[arg(long, default_value = "claude-code")]
    agent: String,

    #[arg(long, default_value = "sess-cli-hook")]
    session_id: String,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let device_name = detect_hostname();

    let attempt = if let (Some(action), Some(target)) = (args.action, args.target) {
        ActionAttempt {
            id: format!("att_{}", uuid::Uuid::now_v7().simple()),
            session_id: args.session_id,
            device_id: format!("dev-{device_name}"),
            device_name,
            agent_name: args.agent,
            action_class: ActionClass::from_name(&action),
            control_point: ControlPoint::Hook,
            target,
            summary: "CLI hook test invocation".into(),
            timestamp: Timestamp::now(),
        }
    } else if !std::io::stdin().is_terminal() {
        let mut raw = String::new();
        if let Err(err) = std::io::stdin().read_to_string(&mut raw) {
            eprintln!("grdr-hook fail-open read error: {err}");
            return ExitCode::SUCCESS;
        }
        if raw.trim().is_empty() {
            return ExitCode::SUCCESS;
        }
        match parse_claude_hook_stdin(&raw, &device_name) {
            Ok(attempt) => attempt,
            Err(err) => {
                eprintln!("grdr-hook invalid payload: {err}");
                return ExitCode::SUCCESS;
            }
        }
    } else {
        eprintln!("grdr-hook expects Claude Code hook JSON on stdin or --action and --target.");
        return ExitCode::SUCCESS;
    };

    evaluate_and_exit(&attempt, &args.daemon, args.timeout_ms)
}

fn evaluate_and_exit(attempt: &ActionAttempt, daemon_url: &str, timeout_ms: u64) -> ExitCode {
    let receipt = match query_daemon(attempt, daemon_url, timeout_ms) {
        Ok(receipt) => receipt,
        Err(_err) => evaluate_failsafe(attempt),
    };

    match receipt.verdict {
        Verdict::Allow | Verdict::Modify => ExitCode::SUCCESS,
        Verdict::Deny | Verdict::StepUp | Verdict::Defer => {
            let label = match receipt.verdict {
                Verdict::Deny => "BLOCKED",
                Verdict::StepUp => "APPROVAL REQUIRED",
                _ => "DEFERRED",
            };
            let rule_id = receipt.rule_id.as_deref().unwrap_or("essentials.floor");
            eprintln!(
                "Guardrails ADR {label} [{rule_id}]: {}\nNext step: {}\nReceipt: {}",
                receipt.reason, receipt.next_step, receipt.receipt_id
            );
            ExitCode::from(2)
        }
    }
}

fn query_daemon(
    attempt: &ActionAttempt,
    daemon_url: &str,
    timeout_ms: u64,
) -> Result<DecisionReceipt, String> {
    let url = format!("{}/local/v1/decide", daemon_url.trim_end_matches('/'));
    let payload = DecideInput {
        session_id: Some(attempt.session_id.clone()),
        device_id: Some(attempt.device_id.clone()),
        device_name: Some(attempt.device_name.clone()),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: Some(attempt.control_point),
        target: attempt.target.clone(),
        summary: Some(attempt.summary.clone()),
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.max(25)))
        .build()
        .map_err(|e| format!("http client init failed: {e}"))?;

    let resp = client
        .post(&url)
        .json(&payload)
        .send()
        .map_err(|e| format!("daemon request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("daemon returned {}", resp.status()));
    }

    resp.json::<DecisionReceipt>()
        .map_err(|e| format!("invalid receipt json: {e}"))
}

fn evaluate_failsafe(attempt: &ActionAttempt) -> DecisionReceipt {
    let packs = vec![essentials_pack()];
    evaluate_attempt(
        attempt,
        &packs,
        &[],
        &KillSwitchState::Inactive,
        Timestamp::now(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failsafe_blocks_control_file_even_without_daemon() {
        let attempt =
            parse_claude_hook_stdin(r#"{"session_id":"s1","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}"#, "box")
                .unwrap();
        let receipt = evaluate_failsafe(&attempt);
        assert_eq!(receipt.verdict, Verdict::Deny);
    }

    #[test]
    fn failsafe_allows_safe_command() {
        let attempt = parse_claude_hook_stdin(
            r#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"git status"}}"#,
            "box",
        )
        .unwrap();
        let receipt = evaluate_failsafe(&attempt);
        assert_eq!(receipt.verdict, Verdict::Allow);
    }
}
