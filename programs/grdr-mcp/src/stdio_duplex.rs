// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use grdr_mcp_proto::{
    McpMethod, McpResponse, McpRpcError, parse_mcp_request, parse_strict_mcp_json,
};

use crate::McpBrokerError;
use crate::decision::AsyncDecisionSource;
use crate::transport::{MAX_STDIO_LINE_BYTES, McpBrokerService, filter_child_tools_list_response};

#[derive(Debug)]
enum LineEvent {
    Line(String),
    Eof,
}

pub(crate) async fn run_duplex_mediation<S, R1, W1, R2, W2>(
    service: &mut McpBrokerService<S>,
    mut client_in: R1,
    mut client_out: W1,
    child_in: W2,
    mut child_out: R2,
) -> Result<(), McpBrokerError>
where
    S: AsyncDecisionSource,
    R1: AsyncBufRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncBufRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let mut client_scratch = Vec::new();
    let mut child_scratch = Vec::new();
    let mut client_eof = false;
    let mut child_eof = false;
    let mut child_in_opt = Some(child_in);

    while !client_eof || !child_eof {
        tokio::select! {
            biased;
            res = next_bounded_line(&mut child_out, &mut child_scratch, MAX_STDIO_LINE_BYTES), if !child_eof => {
                match res? {
                    LineEvent::Eof => child_eof = true,
                    LineEvent::Line(child_line) => {
                        handle_child_line(service, &child_line, &mut client_out, &mut child_in_opt).await?;
                    }
                }
            }
            res = next_bounded_line(&mut client_in, &mut client_scratch, MAX_STDIO_LINE_BYTES), if !client_eof => {
                match res? {
                    LineEvent::Eof => {
                        client_eof = true;
                        if let Some(mut cin) = child_in_opt.take() {
                            let _ = cin.shutdown().await;
                        }
                    }
                    LineEvent::Line(client_line) => {
                        handle_client_line(service, &client_line, &mut client_out, &mut child_in_opt).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_client_line<
    S: AsyncDecisionSource,
    W1: AsyncWrite + Unpin,
    W2: AsyncWrite + Unpin,
>(
    service: &mut McpBrokerService<S>,
    raw_line: &str,
    client_out: &mut W1,
    child_in_opt: &mut Option<W2>,
) -> Result<(), McpBrokerError> {
    let trimmed = raw_line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if let Some(denial_or_step_up) = service
        .handle_jsonrpc_request(trimmed, service.default_revision)
        .await?
    {
        write_json_line(client_out, &denial_or_step_up).await?;
        return Ok(());
    }
    if let Some(child_in) = child_in_opt.as_mut() {
        write_raw_line(child_in, trimmed).await?;
    }
    Ok(())
}

async fn handle_child_line<
    S: AsyncDecisionSource,
    W1: AsyncWrite + Unpin,
    W2: AsyncWrite + Unpin,
>(
    service: &mut McpBrokerService<S>,
    raw_line: &str,
    client_out: &mut W1,
    child_in_opt: &mut Option<W2>,
) -> Result<(), McpBrokerError> {
    let trimmed = raw_line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let val = parse_strict_mcp_json(trimmed)
        .map_err(|e| McpBrokerError::Transport(format!("invalid JSON from MCP child: {e}")))?;

    let is_server_request = val.get("method").and_then(Value::as_str).is_some()
        && val.get("id").is_some_and(|v| !v.is_null());

    if is_server_request {
        let req =
            parse_mcp_request(trimmed).map_err(|e| McpBrokerError::Transport(e.to_string()))?;
        if req.method == McpMethod::ElicitationCreate
            && req
                .arguments
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("form")
                != "url"
        {
            if let Some(child_in) = child_in_opt.as_mut() {
                let reject = form_elicitation_reject_error(req.id.unwrap_or(Value::Null));
                write_json_line(child_in, &reject).await?;
            }
            return Ok(());
        }
        if matches!(
            req.method,
            McpMethod::RootsList
                | McpMethod::SamplingCreateMessage
                | McpMethod::ElicitationCreate
                | McpMethod::ResourcesRead
                | McpMethod::PromptsGet
                | McpMethod::ToolsCall
        ) && let Some(blocked) = service
            .handle_parsed_request(&req, service.default_revision)
            .await?
        {
            if let Some(child_in) = child_in_opt.as_mut() {
                write_json_line(child_in, &blocked).await?;
            }
            return Ok(());
        }
        write_raw_line(client_out, trimmed).await?;
        return Ok(());
    }

    if val.get("method").and_then(Value::as_str).is_some() {
        write_raw_line(client_out, trimmed).await?;
        return Ok(());
    }

    let filtered = filter_child_tools_list_response(service, trimmed)?;
    write_raw_line(client_out, &filtered).await?;
    Ok(())
}

async fn next_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    scratch: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<LineEvent, McpBrokerError> {
    loop {
        if let Some(nl_pos) = scratch.iter().position(|&b| b == b'\n') {
            let mut bytes = scratch
                .drain(..nl_pos.saturating_add(1))
                .collect::<Vec<u8>>();
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            let text = String::from_utf8(bytes)
                .map_err(|_| McpBrokerError::Transport("non-UTF8 stdio frame".into()))?;
            return Ok(LineEvent::Line(text));
        }
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
        if available.is_empty() {
            if scratch.is_empty() {
                return Ok(LineEvent::Eof);
            }
            let text = String::from_utf8(std::mem::take(scratch))
                .map_err(|_| McpBrokerError::Transport("non-UTF8 trailing stdio bytes".into()))?;
            return Ok(LineEvent::Line(text));
        }
        let nl_in_chunk = available.iter().position(|&b| b == b'\n');
        let consume = nl_in_chunk.map_or(available.len(), |i| i.saturating_add(1));
        if scratch.len().saturating_add(consume) > max_bytes {
            return Err(McpBrokerError::Transport(format!(
                "MCP stdio line exceeded {max_bytes} byte limit"
            )));
        }
        if let Some(slice) = available.get(..consume) {
            scratch.extend_from_slice(slice);
        }
        reader.consume(consume);
    }
}

async fn write_json_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &McpResponse,
) -> Result<(), McpBrokerError> {
    let encoded =
        serde_json::to_string(resp).map_err(|e| McpBrokerError::Transport(e.to_string()))?;
    write_raw_line(writer, &encoded).await
}

async fn write_raw_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    line: &str,
) -> Result<(), McpBrokerError> {
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|e| McpBrokerError::Transport(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| McpBrokerError::Transport(e.to_string()))
}

#[must_use]
pub fn form_elicitation_reject_error(id: Value) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(McpRpcError {
            code: -32001,
            message: "Guardrails ADR: server form elicitation rejected".to_string(),
            data: Some(json!({ "grant_emitted": false })),
        }),
    }
}
