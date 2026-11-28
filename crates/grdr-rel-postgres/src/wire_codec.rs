// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::Read;

use grdr_model::CodedError;

use crate::config::CODE_PG_WIRE;

pub(crate) const PG_PROTOCOL_V3: u32 = 196_608;
pub(crate) const PG_SSL_REQUEST_CODE: u32 = 80_877_103;
const MAX_WIRE_FRAME_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Idle,
    InTransaction,
    FailedTransaction,
    Unknown(u8),
}

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
    AuthenticationMd5Password,
    AuthenticationSasl { mechanisms: Vec<String> },
    AuthenticationSaslContinue { data: Vec<u8> },
    AuthenticationSaslFinal { data: Vec<u8> },
    ParseComplete,
    BindComplete,
    ReadyForQuery { status: TransactionStatus },
    RowDescription { columns: Vec<String> },
    DataRow { values: Vec<Option<String>> },
    CommandComplete { tag: String },
    ErrorResponse { message: String },
    Other { tag: u8 },
}

pub(crate) fn encode_ssl_request() -> [u8; 8] {
    let mut ssl_req = [0u8; 8];
    let len_bytes = 8u32.to_be_bytes();
    let code_bytes = PG_SSL_REQUEST_CODE.to_be_bytes();
    ssl_req[0] = len_bytes[0];
    ssl_req[1] = len_bytes[1];
    ssl_req[2] = len_bytes[2];
    ssl_req[3] = len_bytes[3];
    ssl_req[4] = code_bytes[0];
    ssl_req[5] = code_bytes[1];
    ssl_req[6] = code_bytes[2];
    ssl_req[7] = code_bytes[3];
    ssl_req
}

pub fn encode_startup_packet(
    user: &str,
    database: &str,
    app_name: &str,
) -> Result<Vec<u8>, CodedError> {
    reject_nul("user", user)?;
    reject_nul("database", database)?;
    reject_nul("application_name", app_name)?;
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
    let len_u32 = checked_frame_len(total_len)?;
    let mut buf = Vec::with_capacity(total_len);
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(&PG_PROTOCOL_V3.to_be_bytes());
    buf.extend_from_slice(&params);
    Ok(buf)
}

pub fn encode_query_message(sql: &str) -> Result<Vec<u8>, CodedError> {
    reject_nul("sql", sql)?;
    let total_len = 4usize.saturating_add(sql.len()).saturating_add(1);
    let len_u32 = checked_frame_len(total_len)?;
    let mut buf = Vec::with_capacity(1usize.saturating_add(total_len));
    buf.push(b'Q');
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(sql.as_bytes());
    buf.push(0);
    Ok(buf)
}

pub fn encode_parse_message(stmt_name: &str, sql: &str) -> Result<Vec<u8>, CodedError> {
    reject_nul("statement_name", stmt_name)?;
    reject_nul("sql", sql)?;
    let body_len = stmt_name
        .len()
        .saturating_add(1)
        .saturating_add(sql.len())
        .saturating_add(1)
        .saturating_add(2);
    let total_len = 4usize.saturating_add(body_len);
    let len_u32 = checked_frame_len(total_len)?;
    let mut buf = Vec::with_capacity(1usize.saturating_add(total_len));
    buf.push(b'P');
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(stmt_name.as_bytes());
    buf.push(0);
    buf.extend_from_slice(sql.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&0u16.to_be_bytes());
    Ok(buf)
}

pub fn encode_bind_message(
    portal_name: &str,
    stmt_name: &str,
    params: &[Option<String>],
) -> Result<Vec<u8>, CodedError> {
    reject_nul("portal_name", portal_name)?;
    reject_nul("statement_name", stmt_name)?;
    let param_count = u16::try_from(params.len()).map_err(|_| {
        CodedError::new(
            CODE_PG_WIRE,
            "PostgreSQL Bind parameter count exceeds u16::MAX.",
            "Reduce statement parameter count.",
        )
    })?;
    let mut body = Vec::new();
    body.extend_from_slice(portal_name.as_bytes());
    body.push(0);
    body.extend_from_slice(stmt_name.as_bytes());
    body.push(0);
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&param_count.to_be_bytes());
    for p in params {
        match p {
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(val) => {
                let len_i32 = i32::try_from(val.len()).map_err(|_| {
                    CodedError::new(
                        CODE_PG_WIRE,
                        "PostgreSQL Bind parameter length exceeds i32::MAX.",
                        "Split oversized parameter payload.",
                    )
                })?;
                body.extend_from_slice(&len_i32.to_be_bytes());
                body.extend_from_slice(val.as_bytes());
            }
        }
    }
    body.extend_from_slice(&0u16.to_be_bytes());

    let total_len = 4usize.saturating_add(body.len());
    let len_u32 = checked_frame_len(total_len)?;
    let mut buf = Vec::with_capacity(1usize.saturating_add(total_len));
    buf.push(b'B');
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(&body);
    Ok(buf)
}

pub fn encode_execute_message(portal_name: &str, max_rows: u32) -> Result<Vec<u8>, CodedError> {
    reject_nul("portal_name", portal_name)?;
    let total_len = 4usize
        .saturating_add(portal_name.len())
        .saturating_add(1)
        .saturating_add(4);
    let len_u32 = checked_frame_len(total_len)?;
    let mut buf = Vec::with_capacity(1usize.saturating_add(total_len));
    buf.push(b'E');
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(portal_name.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&max_rows.to_be_bytes());
    Ok(buf)
}

pub fn encode_sync_message() -> [u8; 5] {
    [b'S', 0, 0, 0, 4]
}

pub fn encode_terminate_message() -> [u8; 5] {
    [b'X', 0, 0, 0, 4]
}

pub(crate) fn encode_sasl_initial_response(
    mechanism: &str,
    client_first: &[u8],
) -> Result<Vec<u8>, CodedError> {
    reject_nul("sasl_mechanism", mechanism)?;
    let data_len_i32 = i32::try_from(client_first.len()).map_err(|_| {
        CodedError::new(
            CODE_PG_WIRE,
            "SASL initial response exceeds i32 length.",
            "Reduce SASL initial payload size.",
        )
    })?;
    let total_len = 4usize
        .saturating_add(mechanism.len())
        .saturating_add(1)
        .saturating_add(4)
        .saturating_add(client_first.len());
    let len_u32 = checked_frame_len(total_len)?;
    let mut buf = Vec::with_capacity(1usize.saturating_add(total_len));
    buf.push(b'p');
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(mechanism.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&data_len_i32.to_be_bytes());
    buf.extend_from_slice(client_first);
    Ok(buf)
}

pub(crate) fn encode_sasl_response(client_final: &[u8]) -> Result<Vec<u8>, CodedError> {
    let total_len = 4usize.saturating_add(client_final.len());
    let len_u32 = checked_frame_len(total_len)?;
    let mut buf = Vec::with_capacity(1usize.saturating_add(total_len));
    buf.push(b'p');
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(client_final);
    Ok(buf)
}

pub fn decode_backend_message<R: Read>(reader: &mut R) -> Result<BackendWireMessage, CodedError> {
    let mut header = [0u8; 5];
    reader.read_exact(&mut header).map_err(wire_io_err)?;
    let tag = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if !(4..=MAX_WIRE_FRAME_BYTES).contains(&len) {
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
            let Some([b0, b1, b2, b3]) = body.get(..4) else {
                return Err(wire_malformed_err(
                    "truncated PostgreSQL authentication frame",
                ));
            };
            let auth_code = i32::from_be_bytes([*b0, *b1, *b2, *b3]);
            let rest = body
                .get(4..)
                .ok_or_else(|| wire_malformed_err("truncated PostgreSQL authentication payload"))?;
            match auth_code {
                0 => Ok(BackendWireMessage::AuthenticationOk),
                3 => Ok(BackendWireMessage::AuthenticationCleartextPassword),
                5 => Ok(BackendWireMessage::AuthenticationMd5Password),
                10 => Ok(BackendWireMessage::AuthenticationSasl {
                    mechanisms: parse_sasl_mechanisms(rest)?,
                }),
                11 => Ok(BackendWireMessage::AuthenticationSaslContinue {
                    data: rest.to_vec(),
                }),
                12 => Ok(BackendWireMessage::AuthenticationSaslFinal {
                    data: rest.to_vec(),
                }),
                other => Err(CodedError::new(
                    CODE_PG_WIRE,
                    format!("Unsupported PostgreSQL wire auth method code {other}."),
                    "Configure TLS/SCRAM or loopback trust authentication for wire client.",
                )),
            }
        }
        b'1' => Ok(BackendWireMessage::ParseComplete),
        b'2' => Ok(BackendWireMessage::BindComplete),
        b'Z' => Ok(BackendWireMessage::ReadyForQuery {
            status: match body.first().copied() {
                Some(b'I') => TransactionStatus::Idle,
                Some(b'T') => TransactionStatus::InTransaction,
                Some(b'E') => TransactionStatus::FailedTransaction,
                Some(other) => TransactionStatus::Unknown(other),
                None => TransactionStatus::Unknown(0),
            },
        }),
        b'C' => {
            let tag_str = std::str::from_utf8(trim_nul(&body))
                .map_err(|_| wire_malformed_err("non-UTF-8 CommandComplete tag"))?;
            Ok(BackendWireMessage::CommandComplete {
                tag: tag_str.to_string(),
            })
        }
        b'E' => Ok(BackendWireMessage::ErrorResponse {
            message: parse_error_fields(&body),
        }),
        b'T' => parse_row_description(&body),
        b'D' => parse_data_row(&body),
        _ => Ok(BackendWireMessage::Other { tag }),
    }
}

pub(crate) fn format_pg_text_array(items: &[String]) -> String {
    let escaped: Vec<String> = items
        .iter()
        .map(|item| {
            let safe = item.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{safe}\"")
        })
        .collect();
    format!("{{{}}}", escaped.join(","))
}

pub(crate) fn wire_io_err(err: std::io::Error) -> CodedError {
    CodedError::new(
        CODE_PG_WIRE,
        format!("PostgreSQL wire I/O failed: {err}"),
        "Check PostgreSQL socket connection.",
    )
}

fn wire_malformed_err(detail: &str) -> CodedError {
    CodedError::new(
        CODE_PG_WIRE,
        format!("Malformed PostgreSQL wire protocol frame: {detail}."),
        "Verify PostgreSQL 18 server wire protocol framing and UTF-8 encoding.",
    )
}

fn reject_nul(field: &str, value: &str) -> Result<(), CodedError> {
    if value.as_bytes().contains(&0) {
        return Err(CodedError::new(
            CODE_PG_WIRE,
            format!("PostgreSQL wire field `{field}` cannot contain NUL bytes."),
            "Strip NUL bytes before encoding wire protocol packets.",
        ));
    }
    Ok(())
}

fn checked_frame_len(len: usize) -> Result<u32, CodedError> {
    let len_u32 = u32::try_from(len).map_err(|_| {
        CodedError::new(
            CODE_PG_WIRE,
            "PostgreSQL wire frame exceeds u32 length.",
            "Reduce statement or parameter size.",
        )
    })?;
    if len_u32 > MAX_WIRE_FRAME_BYTES {
        return Err(CodedError::new(
            CODE_PG_WIRE,
            format!("PostgreSQL wire frame length {len_u32} exceeds {MAX_WIRE_FRAME_BYTES}."),
            "Reduce query payload size.",
        ));
    }
    Ok(len_u32)
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

fn parse_row_description(body: &[u8]) -> Result<BackendWireMessage, CodedError> {
    let Some([b0, b1]) = body.get(..2) else {
        return Err(wire_malformed_err("truncated RowDescription column count"));
    };
    let count = usize::from(u16::from_be_bytes([*b0, *b1]));
    let max_cols = body.len().saturating_sub(2) / 19;
    if count > max_cols {
        return Err(wire_malformed_err(
            "RowDescription column count exceeds payload length",
        ));
    }
    let mut cols = Vec::with_capacity(count);
    let mut idx = 2usize;
    for _ in 0..count {
        let Some(rel_nul) = body.get(idx..).and_then(|s| s.iter().position(|&b| b == 0)) else {
            return Err(wire_malformed_err(
                "unterminated RowDescription column name",
            ));
        };
        let end = idx.saturating_add(rel_nul);
        let Some(name_slice) = body.get(idx..end) else {
            return Err(wire_malformed_err("truncated RowDescription column name"));
        };
        let name = std::str::from_utf8(name_slice)
            .map_err(|_| wire_malformed_err("non-UTF-8 RowDescription column name"))?;
        let next_idx = end
            .checked_add(19)
            .filter(|&n| n <= body.len())
            .ok_or_else(|| wire_malformed_err("truncated RowDescription column attributes"))?;
        cols.push(name.to_string());
        idx = next_idx;
    }
    if idx != body.len() {
        return Err(wire_malformed_err("trailing bytes in RowDescription"));
    }
    Ok(BackendWireMessage::RowDescription { columns: cols })
}

fn parse_data_row(body: &[u8]) -> Result<BackendWireMessage, CodedError> {
    let Some([b0, b1]) = body.get(..2) else {
        return Err(wire_malformed_err("truncated DataRow column count"));
    };
    let count = usize::from(u16::from_be_bytes([*b0, *b1]));
    let max_cols = body.len().saturating_sub(2) / 4;
    if count > max_cols {
        return Err(wire_malformed_err(
            "DataRow column count exceeds payload length",
        ));
    }
    let mut values = Vec::with_capacity(count);
    let mut idx = 2usize;
    for _ in 0..count {
        let Some([b0, b1, b2, b3]) = body.get(idx..idx.saturating_add(4)) else {
            return Err(wire_malformed_err("truncated DataRow column length"));
        };
        let col_len = i32::from_be_bytes([*b0, *b1, *b2, *b3]);
        idx = idx.saturating_add(4);
        if col_len == -1 {
            values.push(None);
        } else if col_len < -1 {
            return Err(wire_malformed_err("invalid negative DataRow column length"));
        } else {
            let ulen = usize::try_from(col_len)
                .map_err(|_| wire_malformed_err("invalid DataRow column length"))?;
            let end = idx
                .checked_add(ulen)
                .ok_or_else(|| wire_malformed_err("DataRow column length overflow"))?;
            let Some(slice) = body.get(idx..end) else {
                return Err(wire_malformed_err("truncated DataRow column payload"));
            };
            let val = std::str::from_utf8(slice)
                .map_err(|_| wire_malformed_err("non-UTF-8 DataRow column value"))?;
            values.push(Some(val.to_string()));
            idx = end;
        }
    }
    if idx != body.len() {
        return Err(wire_malformed_err("trailing bytes in DataRow"));
    }
    Ok(BackendWireMessage::DataRow { values })
}

fn parse_sasl_mechanisms(body: &[u8]) -> Result<Vec<String>, CodedError> {
    let mut mechanisms = Vec::new();
    let mut start = 0usize;
    while let Some(rel) = body
        .get(start..)
        .and_then(|s| s.iter().position(|&b| b == 0))
    {
        if rel == 0 {
            return Ok(mechanisms);
        }
        let end = start.saturating_add(rel);
        let slice = body
            .get(start..end)
            .ok_or_else(|| wire_malformed_err("truncated SASL mechanism name"))?;
        let name = std::str::from_utf8(slice)
            .map_err(|_| wire_malformed_err("non-UTF-8 SASL mechanism name"))?;
        mechanisms.push(name.to_string());
        start = end.saturating_add(1);
    }
    Err(wire_malformed_err("unterminated SASL mechanism list"))
}
