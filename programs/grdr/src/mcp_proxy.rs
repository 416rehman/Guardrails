// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::policy;
use grdr_llm_proto::{
    McpRequestKind, build_jsonrpc_denial, build_mcp_target, parse_mcp_jsonrpc_line,
};
use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, DecideInput, DecisionReceipt, KillSwitchState,
    Verdict,
};

pub fn evaluate_via_daemon_or_offline(
    attempt: &ActionAttempt,
    daemon_url: &str,
) -> (DecisionReceipt, &'static str) {
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
        .timeout(Duration::from_millis(250))
        .build();

    if let Ok(client) = client
        && let Ok(resp) = client.post(&url).json(&payload).send()
        && resp.status().is_success()
        && let Ok(parsed) = resp.json::<DecisionReceipt>()
    {
        return (parsed, "daemon");
    }

    let packs = vec![policy::essentials_pack()];
    (
        policy::evaluate(
            attempt,
            &packs,
            &[],
            &KillSwitchState::Inactive,
            attempt.timestamp,
        ),
        "offline-essentials",
    )
}

pub fn run_mcp_proxy(
    server_name: &str,
    agent: &str,
    session_id: &str,
    daemon_url: &str,
    command: &[String],
) -> ExitCode {
    let Some((program, args)) = command.split_first() else {
        eprintln!("GRDR-CLI-0002: mcp-proxy requires a child MCP server command.");
        return ExitCode::FAILURE;
    };

    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!("Failed starting MCP server `{program}`: {err}");
            return ExitCode::FAILURE;
        }
    };

    let Some(child_stdin) = child.stdin.take() else {
        let _ = child.kill();
        return ExitCode::FAILURE;
    };
    let Some(child_stdout) = child.stdout.take() else {
        let _ = child.kill();
        return ExitCode::FAILURE;
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let result = proxy_mcp_stream(
        BufReader::new(stdin.lock()),
        stdout.lock(),
        child_stdin,
        BufReader::new(child_stdout),
        server_name,
        agent,
        session_id,
        |attempt| evaluate_via_daemon_or_offline(attempt, daemon_url).0,
    );

    if let Err(err) = result {
        eprintln!("MCP proxy stream error: {err}");
        let _ = child.kill();
        return ExitCode::FAILURE;
    }

    match child.wait() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => status
            .code()
            .and_then(|c| u8::try_from(c).ok())
            .map_or(ExitCode::FAILURE, ExitCode::from),
        Err(err) => {
            eprintln!("Failed waiting on MCP child server: {err}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn proxy_mcp_stream<R, W, SIn, SOut, E>(
    mut client_in: R,
    mut client_out: W,
    mut server_in: SIn,
    mut server_out: SOut,
    server_name: &str,
    agent: &str,
    session_id: &str,
    mut evaluator: E,
) -> Result<(), String>
where
    R: BufRead,
    W: Write,
    SIn: Write,
    SOut: BufRead,
    E: FnMut(&ActionAttempt) -> DecisionReceipt,
{
    let mut line = String::new();
    loop {
        line.clear();
        let read = client_in
            .read_line(&mut line)
            .map_err(|e| format!("client read error: {e}"))?;
        if read == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parsed = parse_mcp_jsonrpc_line(trimmed).map_err(|e| e.to_string())?;
        let expects_reply = parsed.id.is_some();

        if let McpRequestKind::ToolsCall {
            tool_name,
            target_hint,
            ..
        } = &parsed.kind
        {
            let target = build_mcp_target(server_name, tool_name);
            let summary = match target_hint {
                Some(hint) => format!("MCP {tool_name} ({hint})"),
                None => format!("MCP {tool_name}"),
            };
            let attempt = ActionAttempt {
                id: format!("att_{}", Uuid::now_v7().simple()),
                session_id: session_id.into(),
                device_id: "dev-local".into(),
                device_name: "local".into(),
                agent_name: agent.into(),
                action_class: ActionClass::McpCall,
                control_point: ControlPoint::McpBroker,
                target,
                summary,
                timestamp: Timestamp::now(),
                ..Default::default()
            };
            let receipt = evaluator(&attempt);
            if matches!(
                receipt.verdict,
                Verdict::Deny | Verdict::StepUp | Verdict::Defer
            ) {
                let err_line =
                    build_jsonrpc_denial(parsed.id, &receipt).map_err(|e| e.to_string())?;
                writeln!(client_out, "{err_line}")
                    .map_err(|e| format!("client write error: {e}"))?;
                client_out
                    .flush()
                    .map_err(|e| format!("client flush error: {e}"))?;
                continue;
            }
        }

        writeln!(server_in, "{trimmed}").map_err(|e| format!("server write error: {e}"))?;
        server_in
            .flush()
            .map_err(|e| format!("server flush error: {e}"))?;

        if expects_reply {
            let mut reply = String::new();
            let reply_len = server_out
                .read_line(&mut reply)
                .map_err(|e| format!("server read error: {e}"))?;
            if reply_len == 0 {
                return Err("MCP server closed stdout before replying".into());
            }
            let reply_trimmed = reply.trim();
            writeln!(client_out, "{reply_trimmed}")
                .map_err(|e| format!("client write error: {e}"))?;
            client_out
                .flush()
                .map_err(|e| format!("client flush error: {e}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use grdr_llm_proto::JSONRPC_ERR_DENIED;
    use grdr_model::{ApprovalGrade, Mode, PolicyPack, PolicyRule, RuleMatch};
    use serde_json::Value;

    #[test]
    fn mcp_proxy_blocks_denied_tools_call_and_relays_allowed_requests() {
        let client_requests = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_repo\",\"arguments\":{\"repo\":\"org/core\"}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"get_issue\",\"arguments\":{\"id\":5}}}\n",
        );

        let mock_server_replies = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}\n",
        );

        let pack = PolicyPack {
            id: "pack-mcp-test".into(),
            name: "MCP Test".into(),
            description: "Block delete_repo".into(),
            version: "1.0.0".into(),
            channel: "test".into(),
            rules: vec![PolicyRule {
                id: "mcp.block-delete".into(),
                title: "Block MCP delete".into(),
                description: "Block destructive MCP calls".into(),
                mode: Mode::Block,
                min_grade: ApprovalGrade::G2,
                enabled: true,
                locked: true,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::McpCall],
                    target_prefixes: vec![],
                    target_contains: vec!["delete_repo".into()],
                    agents: vec![],
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "Destructive MCP tool call blocked.".into(),
            }],
            key_id: None,
            signature: None,
        };

        let mut client_out = Vec::new();
        let mut server_in = Vec::new();
        proxy_mcp_stream(
            Cursor::new(client_requests.as_bytes()),
            &mut client_out,
            &mut server_in,
            Cursor::new(mock_server_replies.as_bytes()),
            "github",
            "claude-code",
            "sess-mcp-1",
            |attempt| {
                policy::evaluate(
                    attempt,
                    std::slice::from_ref(&pack),
                    &[],
                    &KillSwitchState::Inactive,
                    attempt.timestamp,
                )
            },
        )
        .unwrap();

        let forwarded_to_server = String::from_utf8(server_in).unwrap();
        assert!(forwarded_to_server.contains("\"initialize\""));
        assert!(forwarded_to_server.contains("\"get_issue\""));
        assert!(!forwarded_to_server.contains("\"delete_repo\""));

        let client_lines: Vec<Value> = String::from_utf8(client_out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(client_lines.len(), 3);
        assert_eq!(client_lines[0]["id"], 1);
        assert_eq!(client_lines[1]["id"], 2);
        assert_eq!(client_lines[1]["error"]["code"], JSONRPC_ERR_DENIED);
        assert_eq!(client_lines[2]["id"], 3);
        assert!(client_lines[2]["result"].is_object());
    }
}
