// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use grdr_model::CodedError;

use crate::config::{CODE_PG_WIRE, PostgresSslMode};
pub use crate::wire_codec::{BackendWireMessage, PostgresWireState, TransactionStatus};
use crate::wire_codec::{
    PG_SSL_REQUEST_CODE, decode_backend_message, encode_bind_message, encode_execute_message,
    encode_parse_message, encode_query_message, encode_startup_packet, encode_sync_message,
    encode_terminate_message, wire_io_err,
};

const MAX_WIRE_ROWS: usize = 100_000;
const MAX_WIRE_CONTROL_FRAMES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupAuthState {
    AwaitingChallenge,
    Authenticated,
}

#[derive(Debug, Clone)]
pub(crate) struct WireStatement<'a> {
    pub(crate) sql: &'a str,
    pub(crate) params: Vec<Option<String>>,
}

#[derive(Debug, Clone)]
pub struct WireConnParams<'a> {
    pub endpoint: &'a str,
    pub user: &'a str,
    pub database: &'a str,
    pub app_name: &'a str,
    pub timeout_ms: u32,
    pub ssl_mode: PostgresSslMode,
}

pub fn execute_simple_query_wire(
    conn: &WireConnParams<'_>,
    password: Option<&str>,
    sql: &str,
) -> Result<Vec<Vec<Option<String>>>, CodedError> {
    let mut stream = open_authenticated_stream(conn, password)?;
    let res = run_simple_on_stream(&mut stream, sql);
    let _ = stream.write_all(&encode_terminate_message());
    res
}

pub(crate) fn execute_extended_tx_wire(
    conn: &WireConnParams<'_>,
    password: Option<&str>,
    rls_stmts: &[String],
    statements: &[WireStatement<'_>],
) -> Result<Vec<Vec<Vec<Option<String>>>>, CodedError> {
    let mut stream = open_authenticated_stream(conn, password)?;
    let mut setup = String::from("BEGIN;");
    for rls in rls_stmts {
        setup.push(' ');
        setup.push_str(rls.trim_end_matches(';'));
        setup.push(';');
    }
    if let Err(err) = run_simple_on_stream(&mut stream, &setup) {
        let _ = stream.write_all(&encode_terminate_message());
        return Err(err);
    }

    let mut results = Vec::with_capacity(statements.len());
    for stmt in statements {
        match run_extended_statement(&mut stream, stmt.sql, &stmt.params) {
            Ok(rows) => results.push(rows),
            Err(err) => {
                let _ = run_simple_on_stream(&mut stream, "ROLLBACK;");
                let _ = stream.write_all(&encode_terminate_message());
                return Err(err);
            }
        }
    }

    if let Err(err) = run_simple_on_stream(&mut stream, "COMMIT;") {
        let _ = stream.write_all(&encode_terminate_message());
        return Err(err);
    }
    let _ = stream.write_all(&encode_terminate_message());
    Ok(results)
}

fn open_authenticated_stream(
    conn: &WireConnParams<'_>,
    password: Option<&str>,
) -> Result<TcpStream, CodedError> {
    if matches!(
        conn.ssl_mode,
        PostgresSslMode::Require | PostgresSslMode::VerifyCa | PostgresSslMode::VerifyFull
    ) {
        return Err(CodedError::new(
            CODE_PG_WIRE,
            format!(
                "PostgreSQL sslmode={} requires TLS stream wrapping, which is not enabled in this build.",
                conn.ssl_mode.as_str()
            ),
            "Terminate TLS via a verified local proxy/tunnel with sslmode=disable, or enable TLS transport.",
        ));
    }

    let mut stream = TcpStream::connect(conn.endpoint).map_err(|e| {
        CodedError::new(
            CODE_PG_WIRE,
            format!(
                "Failed connecting to PostgreSQL endpoint `{}`: {e}",
                conn.endpoint
            ),
            "Verify PostgreSQL 18 host, port, and network reachability.",
        )
    })?;
    let dur = Duration::from_millis(u64::from(conn.timeout_ms.max(100)));
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));

    if conn.ssl_mode == PostgresSslMode::Prefer {
        let mut ssl_req = [0u8; 8];
        ssl_req[..4].copy_from_slice(&8u32.to_be_bytes());
        ssl_req[4..8].copy_from_slice(&PG_SSL_REQUEST_CODE.to_be_bytes());
        stream.write_all(&ssl_req).map_err(wire_io_err)?;
        let mut reply = [0u8; 1];
        stream.read_exact(&mut reply).map_err(wire_io_err)?;
        if reply[0] == b'S' {
            let _ = stream.write_all(&encode_terminate_message());
            return Err(CodedError::new(
                CODE_PG_WIRE,
                "PostgreSQL server accepted SSLRequest, but TLS stream wrapping is not enabled in this build.",
                "Use a verified TLS proxy or enable TLS transport.",
            ));
        }
        if reply[0] != b'N' {
            return Err(CodedError::new(
                CODE_PG_WIRE,
                "Invalid PostgreSQL SSLRequest response byte.",
                "Verify PostgreSQL 18 server protocol.",
            ));
        }
    }

    let startup = encode_startup_packet(conn.user, conn.database, conn.app_name)?;
    stream.write_all(&startup).map_err(wire_io_err)?;

    let mut state = PostgresWireState::Authenticating;
    let mut auth_state = StartupAuthState::AwaitingChallenge;
    let mut control_frames = 0usize;
    while !matches!(state, PostgresWireState::Ready) {
        match decode_backend_message(&mut stream)? {
            BackendWireMessage::AuthenticationOk => {
                auth_state = StartupAuthState::Authenticated;
            }
            BackendWireMessage::AuthenticationCleartextPassword => {
                let _ = stream.write_all(&encode_terminate_message());
                let detail = if password.is_none_or(str::is_empty) {
                    "PostgreSQL requested cleartext password authentication without configured credentials on an unencrypted TCP connection."
                } else {
                    "Refusing PostgreSQL cleartext password authentication over an unencrypted TCP connection."
                };
                return Err(CodedError::new(
                    CODE_PG_WIRE,
                    detail,
                    "Use TLS-wrapped transport or loopback trust/SCRAM authentication.",
                ));
            }
            BackendWireMessage::ReadyForQuery { .. } => {
                if auth_state != StartupAuthState::Authenticated {
                    let _ = stream.write_all(&encode_terminate_message());
                    return Err(CodedError::new(
                        CODE_PG_WIRE,
                        "PostgreSQL sent ReadyForQuery before AuthenticationOk.",
                        "Reject incomplete authentication handshake.",
                    ));
                }
                state = PostgresWireState::Ready;
            }
            BackendWireMessage::ErrorResponse { message } => {
                return Err(CodedError::new(
                    CODE_PG_WIRE,
                    format!("PostgreSQL startup error: {message}"),
                    "Verify PostgreSQL credentials and database name.",
                ));
            }
            _ => {
                control_frames = control_frames.saturating_add(1);
                if control_frames > MAX_WIRE_CONTROL_FRAMES {
                    let _ = stream.write_all(&encode_terminate_message());
                    return Err(control_frame_limit_err());
                }
            }
        }
    }
    Ok(stream)
}

fn run_simple_on_stream(
    stream: &mut TcpStream,
    sql: &str,
) -> Result<Vec<Vec<Option<String>>>, CodedError> {
    let msg = encode_query_message(sql)?;
    stream.write_all(&msg).map_err(wire_io_err)?;
    let mut rows = Vec::new();
    let mut control_frames = 0usize;
    loop {
        match decode_backend_message(stream)? {
            BackendWireMessage::DataRow { values } => {
                if rows.len() >= MAX_WIRE_ROWS {
                    return Err(row_limit_err());
                }
                rows.push(values);
            }
            BackendWireMessage::ReadyForQuery { .. } => break,
            BackendWireMessage::ErrorResponse { message } => {
                return Err(CodedError::new(
                    CODE_PG_WIRE,
                    format!("PostgreSQL query error: {message}"),
                    "Inspect SQL query and RLS session settings.",
                ));
            }
            _ => {
                control_frames = control_frames.saturating_add(1);
                if control_frames > MAX_WIRE_CONTROL_FRAMES {
                    return Err(control_frame_limit_err());
                }
            }
        }
    }
    Ok(rows)
}

fn run_extended_statement(
    stream: &mut TcpStream,
    sql: &str,
    params: &[Option<String>],
) -> Result<Vec<Vec<Option<String>>>, CodedError> {
    stream
        .write_all(&encode_parse_message("", sql)?)
        .map_err(wire_io_err)?;
    stream
        .write_all(&encode_bind_message("", "", params)?)
        .map_err(wire_io_err)?;
    stream
        .write_all(&encode_execute_message("", 0)?)
        .map_err(wire_io_err)?;
    stream
        .write_all(&encode_sync_message())
        .map_err(wire_io_err)?;
    stream.flush().map_err(wire_io_err)?;

    let mut rows = Vec::new();
    let mut query_err: Option<String> = None;
    let mut control_frames = 0usize;
    loop {
        match decode_backend_message(stream)? {
            BackendWireMessage::DataRow { values } => {
                if rows.len() >= MAX_WIRE_ROWS {
                    return Err(row_limit_err());
                }
                rows.push(values);
            }
            BackendWireMessage::ErrorResponse { message } => {
                query_err = Some(message);
            }
            BackendWireMessage::ReadyForQuery { .. } => break,
            _ => {
                control_frames = control_frames.saturating_add(1);
                if control_frames > MAX_WIRE_CONTROL_FRAMES {
                    return Err(control_frame_limit_err());
                }
            }
        }
    }
    if let Some(msg) = query_err {
        return Err(CodedError::new(
            CODE_PG_WIRE,
            format!("PostgreSQL extended query error: {msg}"),
            "Inspect SQL parameters and RLS policies.",
        ));
    }
    Ok(rows)
}

fn control_frame_limit_err() -> CodedError {
    CodedError::new(
        CODE_PG_WIRE,
        format!("PostgreSQL wire response exceeded {MAX_WIRE_CONTROL_FRAMES} control frames."),
        "Inspect PostgreSQL server protocol stream.",
    )
}

fn row_limit_err() -> CodedError {
    CodedError::new(
        CODE_PG_WIRE,
        format!("PostgreSQL wire response exceeded {MAX_WIRE_ROWS} rows."),
        "Paginate large queries.",
    )
}
