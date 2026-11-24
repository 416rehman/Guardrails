// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use jiff::Timestamp;
use uuid::Uuid;

use grdr_agents::{HarnessKind, detect_hostname, parse_hook_stdin};
use grdr_core::compile::evaluate_compiled_floor;
use grdr_core::policy::sha256_hex;
use grdr_crypto::verify_floor_table;
use grdr_model::eval::{essentials_pack, evaluate_attempt};
use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, DecideInput, DecisionReceipt, KillSwitchState, Mode,
    SignatureStatus, SignedFloorBundle, TrustedKeyInfo, Verdict,
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

    #[arg(long, env = "GRDR_FLOOR_TABLE")]
    floor_table: Option<PathBuf>,

    #[arg(long, env = "GRDR_FLOOR_KEY")]
    floor_key: Option<PathBuf>,

    #[arg(long)]
    action: Option<String>,

    #[arg(long)]
    target: Option<String>,

    #[arg(long, default_value = "auto")]
    agent: String,

    #[arg(long, default_value = "sess-cli-hook")]
    session_id: String,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let device_name = detect_hostname();

    let attempt = if let (Some(action), Some(target)) = (args.action, args.target) {
        ActionAttempt {
            id: format!("att_{}", Uuid::now_v7().simple()),
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
        match parse_hook_stdin(HarnessKind::from_name(&args.agent), &raw, &device_name) {
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

    evaluate_and_exit(
        &attempt,
        &args.daemon,
        args.timeout_ms,
        args.floor_table.as_deref(),
        args.floor_key.as_deref(),
    )
}

fn evaluate_and_exit(
    attempt: &ActionAttempt,
    daemon_url: &str,
    timeout_ms: u64,
    floor_table_path: Option<&Path>,
    floor_key_path: Option<&Path>,
) -> ExitCode {
    let receipt = match query_daemon(attempt, daemon_url, timeout_ms) {
        Ok(receipt) => receipt,
        Err(_err) => evaluate_failsafe(attempt, floor_table_path, floor_key_path),
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

fn default_floor_table_path() -> PathBuf {
    std::env::temp_dir().join("grdr-failsafe-floor.json")
}

fn evaluate_failsafe(
    attempt: &ActionAttempt,
    floor_table_path: Option<&Path>,
    floor_key_path: Option<&Path>,
) -> DecisionReceipt {
    let default_path = default_floor_table_path();
    let candidate = floor_table_path.unwrap_or(&default_path);
    let key_path = floor_key_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| candidate.with_extension("pub"));

    if candidate.is_file()
        && key_path.is_file()
        && let Ok(raw_table) = fs::read_to_string(candidate)
        && let Ok(raw_key) = fs::read_to_string(&key_path)
        && let Ok(bundle) = serde_json::from_str::<SignedFloorBundle>(&raw_table)
        && let Ok(pinned_key) = serde_json::from_str::<TrustedKeyInfo>(&raw_key)
    {
        match verify_floor_table(&bundle.table, &[pinned_key]) {
            SignatureStatus::Verified => {
                if let Some(hit) = evaluate_compiled_floor(
                    &bundle.table,
                    attempt.action_class,
                    &attempt.agent_name,
                    &attempt.target,
                ) {
                    let now = Timestamp::now();
                    let digest_input = format!(
                        "{}:{}:{}:{}:{}",
                        attempt.session_id,
                        attempt.agent_name,
                        attempt.action_class.as_str(),
                        attempt.target,
                        hit.rule_id
                    );
                    return DecisionReceipt {
                        receipt_id: format!("rcp_{}", Uuid::now_v7().simple()),
                        attempt_id: attempt.id.clone(),
                        session_id: attempt.session_id.clone(),
                        device_id: attempt.device_id.clone(),
                        agent_name: attempt.agent_name.clone(),
                        action_class: attempt.action_class,
                        control_point: attempt.control_point,
                        target: attempt.target.clone(),
                        verdict: hit.verdict,
                        would_be: None,
                        rule_id: Some(hit.rule_id),
                        pack_id: Some("failsafe-floor".into()),
                        mode_applied: Some(Mode::Block),
                        grant_id: None,
                        reason: hit.reason,
                        next_step: "Blocked by signed offline fail-safe floor table.".into(),
                        receipt_digest: sha256_hex(digest_input.as_bytes()),
                        decided_at: now,
                        key_id: bundle.table.key_id,
                        signature: bundle.table.signature,
                        signature_verified: Some(true),
                    };
                }
            }
            SignatureStatus::Invalid | SignatureStatus::Unsigned => {
                eprintln!(
                    "grdr-hook warning: fail-safe floor table signature check failed against pinned key; falling back to Essentials."
                );
            }
        }
    }

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
    use grdr_agents::parse_claude_hook_stdin;
    use grdr_core::compile::compile_floor_table;
    use grdr_crypto::SigningKeypair;
    use grdr_model::{ApprovalGrade, PolicyPack, PolicyRule, RuleMatch};

    #[test]
    fn failsafe_blocks_control_file_even_without_daemon() {
        let attempt = parse_claude_hook_stdin(
            r#"{"session_id":"s1","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}"#,
            "box",
        )
        .unwrap();
        let receipt = evaluate_failsafe(&attempt, None, None);
        assert_eq!(receipt.verdict, Verdict::Deny);
    }

    #[test]
    fn failsafe_allows_safe_command() {
        let attempt = parse_claude_hook_stdin(
            r#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"git status"}}"#,
            "box",
        )
        .unwrap();
        let receipt = evaluate_failsafe(&attempt, None, None);
        assert_eq!(receipt.verdict, Verdict::Allow);
    }

    #[test]
    fn failsafe_evaluates_signed_compiled_floor_bundle_and_rejects_rogue_or_tampered_tables() {
        let now = Timestamp::now();
        let kp = SigningKeypair::generate().unwrap();
        let custom_pack = PolicyPack {
            id: "pack-custom".into(),
            name: "Custom".into(),
            description: "Custom floor".into(),
            version: "1.0.0".into(),
            channel: "custom".into(),
            rules: vec![PolicyRule {
                id: "custom.block-prod-deploy".into(),
                title: "Block prod deploy".into(),
                description: "Block prod deploy".into(),
                mode: Mode::Block,
                min_grade: ApprovalGrade::G2,
                enabled: true,
                locked: true,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::Exec],
                    target_prefixes: vec![],
                    target_contains: vec!["deploy-prod".into()],
                    agents: vec![],
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Blocked custom prod deploy.".into(),
            }],
            key_id: None,
            signature: None,
        };

        let mut table = compile_floor_table(std::slice::from_ref(&custom_pack), now);
        kp.sign_floor_table(&mut table).unwrap();
        let bundle = SignedFloorBundle {
            table,
            signer: kp.public_info(),
        };

        let dir = std::env::temp_dir().join(format!("grdr-hook-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let floor_path = dir.join("floor.json");
        let key_path = dir.join("floor.pub");
        fs::write(&floor_path, serde_json::to_string(&bundle).unwrap()).unwrap();
        fs::write(&key_path, serde_json::to_string(&kp.public_info()).unwrap()).unwrap();

        let attempt = parse_claude_hook_stdin(
            r#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"./deploy-prod --force"}}"#,
            "box",
        )
        .unwrap();

        let receipt = evaluate_failsafe(&attempt, Some(&floor_path), Some(&key_path));
        assert_eq!(receipt.verdict, Verdict::Deny);
        assert_eq!(receipt.rule_id.as_deref(), Some("custom.block-prod-deploy"));
        assert_eq!(receipt.signature_verified, Some(true));

        let rogue_kp = SigningKeypair::generate().unwrap();
        let mut rogue_table = compile_floor_table(&[custom_pack], now);
        rogue_kp.sign_floor_table(&mut rogue_table).unwrap();
        let rogue_bundle = SignedFloorBundle {
            table: rogue_table,
            signer: rogue_kp.public_info(),
        };
        fs::write(&floor_path, serde_json::to_string(&rogue_bundle).unwrap()).unwrap();

        let rejected_rogue = evaluate_failsafe(&attempt, Some(&floor_path), Some(&key_path));
        assert_eq!(rejected_rogue.verdict, Verdict::Allow);

        let mut tampered = bundle;
        tampered.table.rules[0].target_contains = vec!["unrelated-command".into()];
        fs::write(&floor_path, serde_json::to_string(&tampered).unwrap()).unwrap();

        let after_tamper = evaluate_failsafe(&attempt, Some(&floor_path), Some(&key_path));
        assert_eq!(after_tamper.verdict, Verdict::Allow);

        let _ = fs::remove_dir_all(&dir);
    }
}
