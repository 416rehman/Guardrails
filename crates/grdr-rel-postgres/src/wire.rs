// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use grdr_model::CodedError;

use crate::config::CODE_PG_WIRE;

const PG_PROTOCOL_V3: u32 = 196_608;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostgresWireState {
    Disconnected,
    Authenticating,
    Ready,
    InTransaction,
    Failed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendWireMessage {
    AuthenticationOk,
    AuthenticationCleartextPassword,
    ReadyForQuery { status: u8 },
    RowDescription { columns: Vec<String> },
    DataRow { values: Vec<Option<String>> },
    CommandComplete { tag: String },
    ErrorResponse { message: String },
    Other { tag: u8 },
}

pub fn encode_startup_packet(user: &str, database: &str, app_name: &str) -> Vec<u8> {
    let mut params = Vec::new();
    for (k, v) in [
        ("user", user),
        ("database", database),
        ("application_name", app_name),
        ("client_encoding", "UTF8"),
    ] {
        params.extend_from_slice(k.as_bytes());
        params.push(0);
        params.extend_from_slice(v.as_bytes());
        params.push(0);
    }
    params.push(0);

    let total_len = 8usize.saturating_add(params.len());
    let len_u32 = u32::try_from(total_len).unwrap_or(u32::MAX);
    let mut buf = Vec::with_capacity(total_len);
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(&PG_PROTOCOL_V3.to_be_bytes());
    buf.extend_from_slice(&params);
    buf
}

pub fn encode_query_message(sql: &str) -> Vec<u8> {
    let payload_len = sql.len().saturating_add(1);
    let total_len = 4usize.saturating_add(payload_len);
    let len_u32 = u32::try_from(total_len).unwrap_or(u32::MAX);
    let mut buf = Vec::with_capacity(1usize.saturating_add(total_len));
    buf.push(b'Q');
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(sql.as_bytes());
    buf.push(0);
    buf
}

pub fn encode_password_message(password: &str) -> Vec<u8> {
    let total_len = 4usize.saturating_add(password.len()).saturating_add(1);
    let len_u32 = u32::try_from(total_len).unwrap_or(u32::MAX);
    let mut buf = Vec::with_capacity(1usize.saturating_add(total_len));
    buf.push(b'p');
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(password.as_bytes());
    buf.push(0);
    buf
}

pub fn encode_terminate_message() -> [u8; 5] {
    [b'X', 0, 0, 0, 4]
}

pub fn decode_backend_message<R: Read>(reader: &mut R) -> Result<BackendWireMessage, CodedError> {
    let mut header = [0u8; 5];
    reader.read_exact(&mut header).map_err(wire_io_err)?;
    let tag = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if len < 4 {
        return Err(CodedError::new(
            CODE_PG_WIRE,
            format!("Invalid PostgreSQL wire frame length {len}."),
            "Verify PostgreSQL 18 server wire protocol.",
        ));
    }
    let body_len = usize::try_from(len.saturating_sub(4)).unwrap_or(0);
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).map_err(wire_io_err)?;

    match tag {
        b'R' => {
            let auth_code = match body.get(..4) {
                Some([b0, b1, b2, b3]) => i32::from_be_bytes([*b0, *b1, *b2, *b3]),
                _ => -1,
            };
            match auth_code {
                0 => Ok(BackendWireMessage::AuthenticationOk),
                3 => Ok(BackendWireMessage::AuthenticationCleartextPassword),
                other => Err(CodedError::new(
                    CODE_PG_WIRE,
                    format!("Unsupported PostgreSQL wire auth method code {other}."),
                    "Configure trust/cleartext over TLS or pg_hba auth for wire client.",
                )),
            }
        }
        b'Z' => Ok(BackendWireMessage::ReadyForQuery {
            status: body.first().copied().unwrap_or(b'I'),
        }),
        b'C' => {
            let tag_str = String::from_utf8_lossy(trim_nul(&body)).to_string();
            Ok(BackendWireMessage::CommandComplete { tag: tag_str })
        }
        b'E' => {
            let msg = parse_error_fields(&body);
            Ok(BackendWireMessage::ErrorResponse { message: msg })
        }
        b'T' => Ok(parse_row_description(&body)),
        b'D' => Ok(parse_data_row(&body)),
        _ => Ok(BackendWireMessage::Other { tag }),
    }
}

pub fn execute_simple_query_wire(
    endpoint: &str,
    user: &str,
    database: &str,
    password: Option<&str>,
    app_name: &str,
    timeout_ms: u32,
    sql: &str,
) -> Result<Vec<Vec<Option<String>>>, CodedError> {
    let mut stream = TcpStream::connect(endpoint).map_err(|e| {
        CodedError::new(
            CODE_PG_WIRE,
            format!("Failed connecting to PostgreSQL endpoint `{endpoint}`: {e}"),
            "Verify PostgreSQL 18 host, port, and network reachability.",
        )
    })?;
    let dur = Duration::from_millis(u64::from(timeout_ms.max(100)));
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));

    let startup = encode_startup_packet(user, database, app_name);
    stream.write_all(&startup).map_err(wire_io_err)?;

    let mut state = PostgresWireState::Authenticating;
    while !matches!(state, PostgresWireState::Ready) {
        match decode_backend_message(&mut stream)? {
            BackendWireMessage::AuthenticationOk => {}
            BackendWireMessage::AuthenticationCleartextPassword => {
                let pw = password.unwrap_or("");
                stream
                    .write_all(&encode_password_message(pw))
                    .map_err(wire_io_err)?;
            }
            BackendWireMessage::ReadyForQuery { .. } => {
                state = PostgresWireState::Ready;
            }
            BackendWireMessage::ErrorResponse { message } => {
                return Err(CodedError::new(
                    CODE_PG_WIRE,
                    format!("PostgreSQL startup error: {message}"),
                    "Verify PostgreSQL credentials and database name.",
                ));
            }
            _ => {}
        }
    }

    stream
        .write_all(&encode_query_message(sql))
        .map_err(wire_io_err)?;
    let mut rows = Vec::new();
    loop {
        match decode_backend_message(&mut stream)? {
            BackendWireMessage::DataRow { values } => rows.push(values),
            BackendWireMessage::ReadyForQuery { .. } => break,
            BackendWireMessage::ErrorResponse { message } => {
                let _ = stream.write_all(&encode_terminate_message());
                return Err(CodedError::new(
                    CODE_PG_WIRE,
                    format!("PostgreSQL query error: {message}"),
                    "Inspect SQL query and RLS session settings.",
                ));
            }
            _ => {}
        }
    }
    let _ = stream.write_all(&encode_terminate_message());
    Ok(rows)
}

fn trim_nul(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(&[0]).unwrap_or(bytes)
}

fn parse_error_fields(body: &[u8]) -> String {
    let mut idx = 0usize;
    let mut message = None;
    while let Some(&code) = body.get(idx) {
        idx = idx.saturating_add(1);
        if code == 0 {
            break;
        }
        let end = body
            .get(idx..)
            .and_then(|s| s.iter().position(|&b| b == 0))
            .map_or(body.len(), |pos| idx.saturating_add(pos));
        if code == b'M'
            && let Some(slice) = body.get(idx..end)
        {
            message = Some(String::from_utf8_lossy(slice).to_string());
        }
        idx = end.saturating_add(1);
    }
    message.unwrap_or_else(|| "unknown PostgreSQL error".into())
}

fn parse_row_description(body: &[u8]) -> BackendWireMessage {
    let count = match body.get(..2) {
        Some([b0, b1]) => u16::from_be_bytes([*b0, *b1]) as usize,
        _ => 0,
    };
    let mut cols = Vec::with_capacity(count);
    let mut idx = 2usize;
    for _ in 0..count {
        let Some(rel_nul) = body.get(idx..).and_then(|s| s.iter().position(|&b| b == 0)) else {
            break;
        };
        let end = idx.saturating_add(rel_nul);
        if let Some(name_slice) = body.get(idx..end) {
            cols.push(String::from_utf8_lossy(name_slice).to_string());
        }
        idx = end.saturating_add(1).saturating_add(18);
    }
    BackendWireMessage::RowDescription { columns: cols }
}

fn parse_data_row(body: &[u8]) -> BackendWireMessage {
    let count = match body.get(..2) {
        Some([b0, b1]) => u16::from_be_bytes([*b0, *b1]) as usize,
        _ => 0,
    };
    let mut values = Vec::with_capacity(count);
    let mut idx = 2usize;
    for _ in 0..count {
        let Some([b0, b1, b2, b3]) = body.get(idx..idx.saturating_add(4)) else {
            break;
        };
        let col_len = i32::from_be_bytes([*b0, *b1, *b2, *b3]);
        idx = idx.saturating_add(4);
        if col_len < 0 {
            values.push(None);
        } else {
            let ulen = usize::try_from(col_len).unwrap_or(0);
            let end = idx.saturating_add(ulen);
            let slice = body.get(idx..end).unwrap_or(&[]);
            values.push(Some(String::from_utf8_lossy(slice).to_string()));
            idx = end;
        }
    }
    BackendWireMessage::DataRow { values }
}

fn wire_io_err(err: std::io::Error) -> CodedError {
    CodedError::new(
        CODE_PG_WIRE,
        format!("PostgreSQL wire I/O failed: {err}"),
        "Check PostgreSQL socket connection.",
    )
}
