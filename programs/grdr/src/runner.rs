// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;
use std::process::ExitCode;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_agents::detect_hostname;
use grdr_model::{ActionAttempt, ActionClass, ControlPoint, DecisionReceipt, Verdict};
use grdr_sandbox_engine::{ContainmentMode, SandboxSpec, prepare_contained_command};

use crate::mcp_proxy::evaluate_via_daemon_or_offline;

pub fn check_spawn_policy(
    command: &[String],
    agent: &str,
    session_id: &str,
    daemon_url: &str,
) -> DecisionReceipt {
    let device_name = detect_hostname();
    let target = command.join(" ");
    let attempt = ActionAttempt {
        id: format!("att_{}", Uuid::now_v7().simple()),
        session_id: session_id.into(),
        device_id: format!("dev-{device_name}"),
        device_name,
        agent_name: agent.into(),
        action_class: ActionClass::Exec,
        control_point: ControlPoint::Sandbox,
        target,
        summary: "Containment launch check".into(),
        timestamp: Timestamp::now(),
    };
    evaluate_via_daemon_or_offline(&attempt, daemon_url).0
}

pub fn run_contained_command(
    contain: bool,
    workdir: Option<PathBuf>,
    agent: &str,
    session_id: &str,
    daemon_url: &str,
    allow_env: &[String],
    command: &[String],
) -> ExitCode {
    let Some((program, args)) = command.split_first() else {
        eprintln!("GRDR-CLI-0003: run requires a command after `--`.");
        return ExitCode::FAILURE;
    };

    let receipt = check_spawn_policy(command, agent, session_id, daemon_url);
    if matches!(
        receipt.verdict,
        Verdict::Deny | Verdict::StepUp | Verdict::Defer
    ) {
        let rule = receipt.rule_id.as_deref().unwrap_or("essentials.floor");
        eprintln!(
            "Guardrails ADR {:?} [{rule}]: {}\nNext step: {}\nReceipt: {}",
            receipt.verdict, receipt.reason, receipt.next_step, receipt.receipt_id
        );
        return ExitCode::from(2);
    }

    let mode = if contain {
        if workdir.is_some() {
            ContainmentMode::WorkspaceContained
        } else {
            ContainmentMode::SanitizedEnv
        }
    } else {
        ContainmentMode::ObserveOnly
    };

    let spec = SandboxSpec {
        session_id: session_id.into(),
        agent_name: agent.into(),
        mode,
        workdir,
        extra_allow_env: allow_env.to_vec(),
        strip_secret_env: contain,
    };
    let inherited: Vec<(String, String)> = std::env::vars().collect();

    let (mut cmd, report) = match prepare_contained_command(program, args, &spec, &inherited) {
        Ok(res) => res,
        Err(err) => {
            eprintln!("Failed preparing contained command: {err}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!(
        "Guardrails ADR launch [{}] stripped={} env var(s){}",
        report.effective_assurance.label(),
        report.stripped_env_vars.len(),
        report
            .partial_reason
            .as_deref()
            .map(|r| format!(" ({r})"))
            .unwrap_or_default()
    );

    match cmd.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => status
            .code()
            .and_then(|c| u8::try_from(c).ok())
            .map_or(ExitCode::FAILURE, ExitCode::from),
        Err(err) => {
            eprintln!("Failed executing `{program}`: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_command_returns_exit_2_without_spawning() {
        let cmd = vec![
            "claude".to_string(),
            "--dangerously-skip-permissions".to_string(),
        ];
        let code = run_contained_command(
            true,
            None,
            "claude-code",
            "sess-run-block",
            "http://127.0.0.1:19999",
            &[],
            &cmd,
        );
        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn contained_command_strips_secrets_and_executes_cleanly() {
        let env = vec![
            ("PATH".into(), std::env::var("PATH").unwrap_or_default()),
            ("GITHUB_TOKEN".into(), "ghp_should_not_pass".into()),
        ];
        let spec = SandboxSpec {
            session_id: "sess-run-ok".into(),
            agent_name: "claude-code".into(),
            mode: ContainmentMode::SanitizedEnv,
            workdir: None,
            extra_allow_env: vec![],
            strip_secret_env: true,
        };

        #[cfg(windows)]
        let (prog, args) = (
            "cmd",
            vec![
                "/C".into(),
                "if defined GITHUB_TOKEN (exit 9) else (exit 0)".into(),
            ],
        );
        #[cfg(not(windows))]
        let (prog, args) = (
            "sh",
            vec![
                "-c".into(),
                "if [ -n \"$GITHUB_TOKEN\" ]; then exit 9; else exit 0; fi".into(),
            ],
        );

        let (mut cmd, report) = prepare_contained_command(prog, &args, &spec, &env).unwrap();
        assert_eq!(report.stripped_env_vars, vec!["GITHUB_TOKEN"]);
        let status = cmd.status().unwrap();
        assert!(status.success());
    }
}
