// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use zeroize::Zeroizing;

use grdr_model::CodedError;

use crate::config::{CODE_PG_WIRE, PostgresSslMode};
use crate::scram::{ScramClientSession, verify_server_final};
use crate::tls::{PgStream, PostgresTlsContext, wrap_tls_stream};
pub use crate::wire_codec::{BackendWireMessage, PostgresWireState, TransactionStatus};
use crate::wire_codec::{
    decode_backend_message, encode_bind_message, encode_execute_message, encode_parse_message,
    encode_query_message, encode_sasl_initial_response, encode_sasl_response, encode_ssl_request,
    encode_startup_packet, encode_sync_message, encode_terminate_message, wire_io_err,
};

const MAX_WIRE_ROWS: usize = 100_000;
const MAX_WIRE_CONTROL_FRAMES: usize = 4_096;

#[derive(Debug)]
enum StartupAuthState {
    AwaitingChallenge,
    AwaitingSaslContinue(ScramClientSession),
    AwaitingSaslFinal(Zeroizing<[u8; 32]>),
    VerifiedSaslWaitingOk,
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
    pub ca_cert_pem: Option<&'a str>,
}

#[derive(Debug)]
struct WireQueryErr {
    error: CodedError,
    desynced: bool,
}

#[derive(Debug)]
pub(crate) struct PgWireConnection {
    stream: PgStream,
    tx_status: TransactionStatus,
    healthy: bool,
}

impl From<CodedError> for WireQueryErr {
    fn from(error: CodedError) -> Self {
        Self {
            error,
            desynced: true,
        }
    }
}

impl PgWireConnection {
    pub(crate) fn connect(
        conn: &WireConnParams<'_>,
        tls_ctx: Option<&PostgresTlsContext>,
        password: Option<&str>,
    ) -> Result<Self, CodedError> {
        let mut stream = open_authenticated_stream(conn, tls_ctx, password)?;
        let tx_status = TransactionStatus::Idle;
        stream.flush().map_err(wire_io_err)?;
        Ok(Self {
            stream,
            tx_status,
            healthy: true,
        })
    }

    pub(crate) fn is_clean_idle(&self) -> bool {
        self.healthy && self.tx_status == TransactionStatus::Idle
    }

    pub(crate) fn set_timeout_ms(&mut self, timeout_ms: u32) -> Result<(), CodedError> {
        let dur = Duration::from_millis(u64::from(timeout_ms.max(100)));
        if let Err(err) = self.stream.set_timeouts(dur) {
            self.healthy = false;
            return Err(err);
        }
        Ok(())
    }

    pub(crate) fn ping(&mut self) -> Result<(), CodedError> {
        let _ = self.simple_query("SELECT 1")?;
        Ok(())
    }

    pub(crate) fn simple_query(
        &mut self,
        sql: &str,
    ) -> Result<Vec<Vec<Option<String>>>, CodedError> {
        match run_simple_on_stream(&mut self.stream, sql, &mut self.tx_status) {
            Ok(rows) => Ok(rows),
            Err(qerr) => {
                if qerr.desynced {
                    self.healthy = false;
                }
                Err(qerr.error)
            }
        }
    }

    pub(crate) fn execute_tx(
        &mut self,
        rls_stmts: &[String],
        statements: &[WireStatement<'_>],
    ) -> Result<Vec<Vec<Vec<Option<String>>>>, CodedError> {
        let mut setup = String::from("BEGIN;");
        for rls in rls_stmts {
            setup.push(' ');
            setup.push_str(rls.trim_end_matches(';'));
            setup.push(';');
        }
        if let Err(qerr) = run_simple_on_stream(&mut self.stream, &setup, &mut self.tx_status) {
            if qerr.desynced {
                self.healthy = false;
                return Err(qerr.error);
            }
            if self.tx_status != TransactionStatus::Idle
                && (run_simple_on_stream(&mut self.stream, "ROLLBACK;", &mut self.tx_status)
                    .is_err()
                    || self.tx_status != TransactionStatus::Idle)
            {
                self.healthy = false;
            }
            return Err(qerr.error);
        }

        let mut results = Vec::with_capacity(statements.len());
        for stmt in statements {
            match run_extended_statement(
                &mut self.stream,
                stmt.sql,
                &stmt.params,
                &mut self.tx_status,
            ) {
                Ok(rows) => results.push(rows),
                Err(qerr) => {
                    if qerr.desynced {
                        self.healthy = false;
                        return Err(qerr.error);
                    }
                    if self.tx_status != TransactionStatus::Idle
                        && (run_simple_on_stream(
                            &mut self.stream,
                            "ROLLBACK;",
                            &mut self.tx_status,
                        )
                        .is_err()
                            || self.tx_status != TransactionStatus::Idle)
                    {
                        self.healthy = false;
                    }
                    return Err(qerr.error);
                }
            }
        }

        if let Err(qerr) = run_simple_on_stream(&mut self.stream, "COMMIT;", &mut self.tx_status) {
            self.healthy = false;
            return Err(qerr.error);
        }
        Ok(results)
    }

    pub(crate) fn terminate(mut self) {
        self.healthy = false;
        let _ = self.stream.write_all(&encode_terminate_message());
        let _ = self.stream.flush();
        self.stream.shutdown();
    }
}

pub fn execute_simple_query_wire(
    conn: &WireConnParams<'_>,
    password: Option<&str>,
    sql: &str,
) -> Result<Vec<Vec<Option<String>>>, CodedError> {
    let tls_ctx = PostgresTlsContext::build(conn.ssl_mode, conn.endpoint, conn.ca_cert_pem)?;
    let mut pg = PgWireConnection::connect(conn, tls_ctx.as_ref(), password)?;
    let res = pg.simple_query(sql);
    pg.terminate();
    res
}

fn connect_tcp_with_timeout(endpoint: &str, timeout: Duration) -> Result<TcpStream, CodedError> {
    let addrs: Vec<_> = endpoint
        .to_socket_addrs()
        .map_err(|e| {
            CodedError::new(
                CODE_PG_WIRE,
                format!("Failed resolving PostgreSQL endpoint `{endpoint}`: {e}"),
                "Verify PostgreSQL 18 DNS hostname and port.",
            )
        })?
        .collect();
    let Some(first_addr) = addrs.first().copied() else {
        return Err(CodedError::new(
            CODE_PG_WIRE,
            format!("PostgreSQL endpoint `{endpoint}` resolved to no addresses."),
            "Provide a valid PostgreSQL host:port endpoint.",
        ));
    };
    let mut last_err = None;
    let mut connected = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(sock) => {
                connected = Some(sock);
                break;
            }
            Err(err) => last_err = Some(err),
        }
    }
    connected.ok_or_else(|| {
        let reason = last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| format!("address {first_addr} unreachable"));
        CodedError::new(
            CODE_PG_WIRE,
            format!("Failed connecting to PostgreSQL endpoint `{endpoint}`: {reason}"),
            "Verify PostgreSQL 18 host, port, and network reachability.",
        )
    })
}

fn negotiate_ssl(
    tcp: TcpStream,
    conn: &WireConnParams<'_>,
    tls_ctx: Option<&PostgresTlsContext>,
) -> Result<PgStream, CodedError> {
    if conn.ssl_mode == PostgresSslMode::Disable {
        return Ok(PgStream::Plain(tcp));
    }
    let ctx = tls_ctx.ok_or_else(|| {
        CodedError::new(
            CODE_PG_WIRE,
            format!(
                "PostgreSQL sslmode={} requires TLS configuration context.",
                conn.ssl_mode.as_str()
            ),
            "Construct a PostgresTlsContext matching the configured sslmode.",
        )
    })?;

    let mut tcp = tcp;
    tcp.write_all(&encode_ssl_request()).map_err(wire_io_err)?;
    tcp.flush().map_err(wire_io_err)?;
    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).map_err(wire_io_err)?;
    match reply[0] {
        b'S' => wrap_tls_stream(tcp, ctx),
        b'N' => {
            if conn.ssl_mode == PostgresSslMode::Prefer {
                Ok(PgStream::Plain(tcp))
            } else {
                Err(CodedError::new(
                    CODE_PG_WIRE,
                    format!(
                        "PostgreSQL server refused TLS SSLRequest under sslmode={}.",
                        conn.ssl_mode.as_str()
                    ),
                    "Enable TLS on PostgreSQL 18 or use a verified TLS endpoint.",
                ))
            }
        }
        _ => Err(CodedError::new(
            CODE_PG_WIRE,
            "Invalid PostgreSQL SSLRequest response byte.",
            "Verify PostgreSQL 18 server protocol.",
        )),
    }
}

fn open_authenticated_stream(
    conn: &WireConnParams<'_>,
    tls_ctx: Option<&PostgresTlsContext>,
    password: Option<&str>,
) -> Result<PgStream, CodedError> {
    let dur = Duration::from_millis(u64::from(conn.timeout_ms.max(100)));
    let tcp = connect_tcp_with_timeout(conn.endpoint, dur)?;
    tcp.set_read_timeout(Some(dur)).map_err(wire_io_err)?;
    tcp.set_write_timeout(Some(dur)).map_err(wire_io_err)?;

    let mut stream = negotiate_ssl(tcp, conn, tls_ctx)?;
    let startup = encode_startup_packet(conn.user, conn.database, conn.app_name)?;
    stream.write_all(&startup).map_err(wire_io_err)?;
    stream.flush().map_err(wire_io_err)?;

    let has_password = password.is_some_and(|p| !p.is_empty());
    let mut state = PostgresWireState::Authenticating;
    let mut auth_state = StartupAuthState::AwaitingChallenge;
    let mut control_frames = 0usize;
    while !matches!(state, PostgresWireState::Ready) {
        match decode_backend_message(&mut stream)? {
            BackendWireMessage::AuthenticationOk => match auth_state {
                StartupAuthState::AwaitingChallenge if has_password => {
                    let _ = stream.write_all(&encode_terminate_message());
                    return Err(CodedError::new(
                        CODE_PG_WIRE,
                        "PostgreSQL server skipped SCRAM authentication despite configured credentials.",
                        "Require SCRAM-SHA-256 authentication on PostgreSQL 18 pg_hba.conf.",
                    ));
                }
                StartupAuthState::AwaitingChallenge | StartupAuthState::VerifiedSaslWaitingOk => {
                    auth_state = StartupAuthState::Authenticated;
                }
                _ => {
                    let _ = stream.write_all(&encode_terminate_message());
                    return Err(CodedError::new(
                        CODE_PG_WIRE,
                        "PostgreSQL sent AuthenticationOk before completing SASL exchange.",
                        "Reject incomplete SASL authentication.",
                    ));
                }
            },
            BackendWireMessage::AuthenticationCleartextPassword => {
                let _ = stream.write_all(&encode_terminate_message());
                return Err(CodedError::new(
                    CODE_PG_WIRE,
                    "Refusing PostgreSQL cleartext password authentication; use SCRAM-SHA-256.",
                    "Configure PostgreSQL 18 pg_hba.conf for scram-sha-256.",
                ));
            }
            BackendWireMessage::AuthenticationMd5Password => {
                let _ = stream.write_all(&encode_terminate_message());
                return Err(CodedError::new(
                    CODE_PG_WIRE,
                    "Refusing deprecated PostgreSQL MD5 password authentication.",
                    "Configure PostgreSQL 18 pg_hba.conf for scram-sha-256.",
                ));
            }
            BackendWireMessage::AuthenticationSasl { mechanisms } => {
                if !matches!(auth_state, StartupAuthState::AwaitingChallenge) {
                    let _ = stream.write_all(&encode_terminate_message());
                    return Err(CodedError::new(
                        CODE_PG_WIRE,
                        "Unexpected PostgreSQL SASL start mid-handshake.",
                        "Reject out-of-order SASL state.",
                    ));
                }
                let pw = password.unwrap_or("");
                let sasl =
                    ScramClientSession::start(&mechanisms, pw, stream.peer_leaf_cert_binding())?;
                let msg =
                    encode_sasl_initial_response(sasl.mechanism(), sasl.client_first_message())?;
                stream.write_all(&msg).map_err(wire_io_err)?;
                stream.flush().map_err(wire_io_err)?;
                auth_state = StartupAuthState::AwaitingSaslContinue(sasl);
            }
            BackendWireMessage::AuthenticationSaslContinue { data } => {
                let StartupAuthState::AwaitingSaslContinue(sasl) = auth_state else {
                    let _ = stream.write_all(&encode_terminate_message());
                    return Err(CodedError::new(
                        CODE_PG_WIRE,
                        "Unexpected PostgreSQL SASLContinue frame.",
                        "Reject out-of-order SASL state.",
                    ));
                };
                let client_final = sasl.process_server_first(&data)?;
                let msg = encode_sasl_response(&client_final.client_final_message)?;
                stream.write_all(&msg).map_err(wire_io_err)?;
                stream.flush().map_err(wire_io_err)?;
                auth_state =
                    StartupAuthState::AwaitingSaslFinal(client_final.expected_server_signature);
            }
            BackendWireMessage::AuthenticationSaslFinal { data } => {
                let StartupAuthState::AwaitingSaslFinal(expected_sig) = auth_state else {
                    let _ = stream.write_all(&encode_terminate_message());
                    return Err(CodedError::new(
                        CODE_PG_WIRE,
                        "Unexpected PostgreSQL SASLFinal frame.",
                        "Reject out-of-order SASL state.",
                    ));
                };
                verify_server_final(&data, &expected_sig)?;
                auth_state = StartupAuthState::VerifiedSaslWaitingOk;
            }
            BackendWireMessage::ReadyForQuery { .. } => {
                if !matches!(auth_state, StartupAuthState::Authenticated) {
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
    stream: &mut PgStream,
    sql: &str,
    tx_status: &mut TransactionStatus,
) -> Result<Vec<Vec<Option<String>>>, WireQueryErr> {
    let msg = encode_query_message(sql)?;
    stream.write_all(&msg).map_err(wire_io_err)?;
    stream.flush().map_err(wire_io_err)?;
    drain_query_frames(stream, tx_status, "PostgreSQL query error")
}

fn run_extended_statement(
    stream: &mut PgStream,
    sql: &str,
    params: &[Option<String>],
    tx_status: &mut TransactionStatus,
) -> Result<Vec<Vec<Option<String>>>, WireQueryErr> {
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
    drain_query_frames(stream, tx_status, "PostgreSQL extended query error")
}

fn drain_query_frames(
    stream: &mut PgStream,
    tx_status: &mut TransactionStatus,
    err_prefix: &str,
) -> Result<Vec<Vec<Option<String>>>, WireQueryErr> {
    let mut rows = Vec::new();
    let mut query_err: Option<String> = None;
    let mut control_frames = 0usize;
    loop {
        match decode_backend_message(stream)? {
            BackendWireMessage::DataRow { values } => {
                if rows.len() >= MAX_WIRE_ROWS {
                    return Err(WireQueryErr {
                        error: row_limit_err(),
                        desynced: true,
                    });
                }
                rows.push(values);
            }
            BackendWireMessage::ErrorResponse { message } => {
                query_err = Some(message);
            }
            BackendWireMessage::ReadyForQuery { status } => {
                *tx_status = status;
                break;
            }
            _ => {
                control_frames = control_frames.saturating_add(1);
                if control_frames > MAX_WIRE_CONTROL_FRAMES {
                    return Err(WireQueryErr {
                        error: control_frame_limit_err(),
                        desynced: true,
                    });
                }
            }
        }
    }
    if let Some(msg) = query_err {
        return Err(WireQueryErr {
            error: CodedError::new(
                CODE_PG_WIRE,
                format!("{err_prefix}: {msg}"),
                "Inspect SQL parameters and RLS policies.",
            ),
            desynced: false,
        });
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
