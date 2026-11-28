// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use grdr_crypto::{hmac_sha256, sha256_digest};
use grdr_rel_postgres::{PostgresConfig, PostgresSslMode, PostgresTransport};
use uuid::Uuid;

use crate::server_preflight::probe_types::{
    ErrCodeSlot, PgClockProbe, PreflightThresholds, ProbeOutcomeKind, RawProbeResult,
    parse_host_and_optional_port,
};
use crate::server_preflight::tls_probes::connect_tls_on_tcp;

const PG_WIRE_TIMEOUT_MS: u32 = 1_500;
const PG_SSL_REQUEST: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F];
const MAX_PG_WIRE_FRAME: usize = 65_536;
const MAX_PG_FRAMES: usize = 64;

pub fn probe_postgres_wire_and_clock(
    cfg: &PostgresConfig,
    cert_files: &[PathBuf],
    clock_probe: PgClockProbe,
    thresholds: &PreflightThresholds,
    now_unix_s: i64,
) -> Vec<RawProbeResult> {
    let mut out = Vec::new();
    let PostgresTransport::TcpWire {
        endpoint,
        user,
        database,
        password,
    } = &cfg.transport
    else {
        return out;
    };

    if cfg.ssl_mode != PostgresSslMode::VerifyFull {
        out.push(pg_res(
            "PF-07",
            "postgres_tls_negotiation",
            ProbeOutcomeKind::Fail,
            ErrCodeSlot::PgConfig,
            format!(
                "PostgreSQL sslmode={} rejected; docs/design/24 section 6 requires verify-full TLS.",
                cfg.ssl_mode.as_str()
            ),
            Some("Set sslmode=verify-full on GRDR_POSTGRES_DSN."),
        ));
        return out;
    }

    let (host, _) = match parse_host_and_optional_port(endpoint, true) {
        Ok(hp) => hp,
        Err(msg) => {
            out.push(pg_res(
                "PF-07",
                "postgres_tls_negotiation",
                ProbeOutcomeKind::Fail,
                ErrCodeSlot::PgTcp,
                format!("Invalid PostgreSQL endpoint `{endpoint}`: {msg}"),
                Some("Verify PostgreSQL host:port in GRDR_POSTGRES_DSN."),
            ));
            return out;
        }
    };
    match upgrade_pg_ssl_and_tls(&host, endpoint, cert_files) {
        Ok(mut tls_stream) => {
            out.push(pg_res(
                "PF-07",
                "postgres_tls_negotiation",
                ProbeOutcomeKind::Pass,
                ErrCodeSlot::None,
                format!(
                    "PostgreSQL `{endpoint}` accepted SSLRequest and verified rustls handshake (verify-full)."
                ),
                None,
            ));
            if clock_probe == PgClockProbe::Enforce {
                let res = query_pg_epoch_over_io(
                    &mut tls_stream,
                    user,
                    database,
                    password.as_deref().map(String::as_str),
                );
                let _ = tls_stream.write_all(&[b'X', 0, 0, 0, 4]);
                let _ = tls_stream.flush();
                out.push(evaluate_pg_epoch_result(res, thresholds, now_unix_s));
            }
        }
        Err(detail) => {
            out.push(pg_res(
                "PF-07",
                "postgres_tls_negotiation",
                ProbeOutcomeKind::Fail,
                ErrCodeSlot::PgTcp,
                detail,
                Some("Enable ssl = on with valid certificates on PostgreSQL 18."),
            ));
        }
    }
    out
}

fn pg_res(
    id: &'static str,
    name: &'static str,
    kind: ProbeOutcomeKind,
    err_slot: ErrCodeSlot,
    detail: String,
    remedy: Option<&'static str>,
) -> RawProbeResult {
    RawProbeResult {
        id,
        name,
        kind,
        err_slot,
        detail,
        remedy,
    }
}

fn evaluate_pg_epoch_result(
    res: Result<i64, String>,
    thresholds: &PreflightThresholds,
    now_unix_s: i64,
) -> RawProbeResult {
    match res {
        Ok(pg_s) => {
            let skew_s = now_unix_s.saturating_sub(pg_s).unsigned_abs();
            if skew_s > thresholds.clock_skew_pg_fail_s {
                pg_res(
                    "PF-06",
                    "postgres_clock_skew",
                    ProbeOutcomeKind::Fail,
                    ErrCodeSlot::PgConfig,
                    format!(
                        "PostgreSQL clock skew {skew_s}s exceeds {}s threshold.",
                        thresholds.clock_skew_pg_fail_s
                    ),
                    Some("Synchronize PostgreSQL and server host clocks within 1s."),
                )
            } else {
                pg_res(
                    "PF-06",
                    "postgres_clock_skew",
                    ProbeOutcomeKind::Pass,
                    ErrCodeSlot::None,
                    format!("PostgreSQL NOW() clock skew is {skew_s}s."),
                    None,
                )
            }
        }
        Err(detail) => pg_res(
            "PF-06",
            "postgres_clock_skew",
            ProbeOutcomeKind::Fail,
            ErrCodeSlot::PgTcp,
            detail,
            Some("Verify PostgreSQL TLS authentication and wire connectivity."),
        ),
    }
}

fn upgrade_pg_ssl_and_tls(
    host: &str,
    endpoint: &str,
    cert_files: &[PathBuf],
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let timeout = Duration::from_millis(u64::from(PG_WIRE_TIMEOUT_MS));
    let addrs: Vec<SocketAddr> = endpoint
        .to_socket_addrs()
        .map_err(|_| format!("Failed resolving PostgreSQL endpoint `{endpoint}` for SSLRequest."))?
        .collect();
    let mut last_err = String::from("no addresses");
    for addr in addrs {
        let mut tcp = match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => s,
            Err(e) => {
                last_err = e.to_string();
                continue;
            }
        };
        if let Err(e) = tcp.set_read_timeout(Some(timeout)) {
            last_err = format!("Failed setting read timeout: {e}");
            continue;
        }
        if let Err(e) = tcp.set_write_timeout(Some(timeout)) {
            last_err = format!("Failed setting write timeout: {e}");
            continue;
        }
        if let Err(e) = tcp.write_all(&PG_SSL_REQUEST) {
            last_err = e.to_string();
            continue;
        }
        let mut byte = [0u8; 1];
        if let Err(e) = tcp.read_exact(&mut byte) {
            last_err = e.to_string();
            continue;
        }
        match byte[0] {
            b'S' => return connect_tls_on_tcp(host, tcp, cert_files),
            b'N' => {
                return Err(format!(
                    "PostgreSQL `{endpoint}` refused TLS SSLRequest ('N') while sslmode requires TLS."
                ));
            }
            other => last_err = format!("unexpected SSLRequest response byte 0x{other:02x}"),
        }
    }
    Err(format!(
        "PostgreSQL TLS negotiation failed for `{endpoint}`: {last_err}"
    ))
}

fn query_pg_epoch_over_io<IO: Read + Write>(
    io: &mut IO,
    user: &str,
    database: &str,
    password: Option<&str>,
) -> Result<i64, String> {
    send_startup_packet(io, user, database)?;
    let mut scram_client_first_bare = String::new();
    let mut scram_server_sig: Option<[u8; 32]> = None;
    let mut scram_pending = false;
    let mut auth_ok = false;

    for _ in 0..MAX_PG_FRAMES {
        let (tag, payload) = read_pg_backend_msg(io)?;
        match tag {
            b'R' => {
                let auth_code = read_be_i32(&payload, 0)?;
                match auth_code {
                    0 => {
                        if scram_pending {
                            return Err(
                                "PostgreSQL returned AuthOk before completing SCRAM ServerFinal."
                                    .into(),
                            );
                        }
                        auth_ok = true;
                    }
                    3 => {
                        let pw = password.ok_or_else(|| {
                            "PostgreSQL requested password authentication without DSN password."
                                .to_string()
                        })?;
                        send_tagged_packet(io, b'p', &[pw.as_bytes(), &[0]])?;
                    }
                    10 => {
                        let mechs =
                            std::str::from_utf8(payload.get(4..).unwrap_or(&[])).unwrap_or("");
                        if !mechs.split('\0').any(|m| m == "SCRAM-SHA-256") {
                            return Err(
                                "PostgreSQL SASL advertised no SCRAM-SHA-256 mechanism.".into()
                            );
                        }
                        scram_pending = true;
                        let nonce = Uuid::now_v7().simple().to_string();
                        scram_client_first_bare = format!("n=,r={nonce}");
                        let gs2_msg = format!("n,,{scram_client_first_bare}");
                        let mut body = Vec::new();
                        body.extend_from_slice(b"SCRAM-SHA-256\0");
                        let mlen = i32::try_from(gs2_msg.len())
                            .map_err(|_| "SCRAM message too long.".to_string())?;
                        body.extend_from_slice(&mlen.to_be_bytes());
                        body.extend_from_slice(gs2_msg.as_bytes());
                        send_tagged_packet(io, b'p', &[&body])?;
                    }
                    11 => {
                        scram_pending = true;
                        let pw = password.ok_or_else(|| {
                            "PostgreSQL SCRAM-SHA-256 requires DSN password.".to_string()
                        })?;
                        let server_first = std::str::from_utf8(payload.get(4..).unwrap_or(&[]))
                            .map_err(|_| "Non-UTF8 SCRAM server-first message.".to_string())?;
                        let (client_final, srv_sig) =
                            build_scram_final(&scram_client_first_bare, server_first, pw)?;
                        scram_server_sig = Some(srv_sig);
                        send_tagged_packet(io, b'p', &[client_final.as_bytes()])?;
                    }
                    12 => {
                        let expected = scram_server_sig.ok_or_else(|| {
                            "Unexpected SCRAM ServerFinal without client proof.".to_string()
                        })?;
                        let srv_final = std::str::from_utf8(payload.get(4..).unwrap_or(&[]))
                            .map_err(|_| "Non-UTF8 SCRAM server-final.".to_string())?;
                        let expected_hdr = format!("v={}", B64_STD.encode(expected));
                        if srv_final.trim() != expected_hdr {
                            return Err(
                                "PostgreSQL SCRAM-SHA-256 server signature mismatch.".into()
                            );
                        }
                        scram_pending = false;
                        auth_ok = true;
                    }
                    other => {
                        return Err(format!("Unsupported PostgreSQL wire auth scheme {other}."));
                    }
                }
            }
            b'Z' => {
                if scram_pending || !auth_ok {
                    return Err(
                        "PostgreSQL sent ReadyForQuery before completing authentication.".into(),
                    );
                }
                break;
            }
            b'E' => return Err("PostgreSQL rejected authentication/startup query.".into()),
            _ => {}
        }
    }
    if scram_pending || !auth_ok {
        return Err("PostgreSQL startup did not complete authentication cleanly.".into());
    }

    send_tagged_packet(
        io,
        b'Q',
        &[b"SELECT FLOOR(EXTRACT(EPOCH FROM NOW()))::bigint\0"],
    )?;
    let mut epoch_val: Option<i64> = None;
    for _ in 0..MAX_PG_FRAMES {
        let (tag, payload) = read_pg_backend_msg(io)?;
        match tag {
            b'D' => {
                epoch_val = parse_first_datarow_i64(&payload);
            }
            b'Z' => break,
            b'E' => return Err("PostgreSQL rejected clock skew NOW() query over TLS.".into()),
            _ => {}
        }
    }
    epoch_val.ok_or_else(|| "PostgreSQL NOW() query returned no DataRow over TLS.".to_string())
}

fn send_startup_packet<IO: Write>(io: &mut IO, user: &str, database: &str) -> Result<(), String> {
    let mut body = Vec::new();
    body.extend_from_slice(&196_608u32.to_be_bytes());
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(database.as_bytes());
    body.push(0);
    body.extend_from_slice(b"application_name\0grdr-preflight\0\0");
    let total = u32::try_from(body.len().saturating_add(4))
        .map_err(|_| "Startup packet overflow.".to_string())?;
    let mut pkt =
        Vec::with_capacity(usize::try_from(total).unwrap_or(body.len().saturating_add(4)));
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&body);
    io.write_all(&pkt).map_err(|e| e.to_string())?;
    io.flush().map_err(|e| e.to_string())
}

fn send_tagged_packet<IO: Write>(io: &mut IO, tag: u8, parts: &[&[u8]]) -> Result<(), String> {
    let payload_len: usize = parts.iter().map(|p| p.len()).sum();
    let total = u32::try_from(payload_len.saturating_add(4))
        .map_err(|_| "PG packet overflow.".to_string())?;
    io.write_all(&[tag]).map_err(|e| e.to_string())?;
    io.write_all(&total.to_be_bytes())
        .map_err(|e| e.to_string())?;
    for part in parts {
        io.write_all(part).map_err(|e| e.to_string())?;
    }
    io.flush().map_err(|e| e.to_string())
}

fn read_pg_backend_msg<IO: Read>(io: &mut IO) -> Result<(u8, Vec<u8>), String> {
    let mut hdr = [0u8; 5];
    io.read_exact(&mut hdr)
        .map_err(|e| format!("PG TLS wire read failed: {e}"))?;
    let len_bytes = [
        *hdr.get(1).unwrap_or(&0),
        *hdr.get(2).unwrap_or(&0),
        *hdr.get(3).unwrap_or(&0),
        *hdr.get(4).unwrap_or(&0),
    ];
    let len = usize::try_from(u32::from_be_bytes(len_bytes)).unwrap_or(0);
    if !(4..=MAX_PG_WIRE_FRAME).contains(&len) {
        return Err("PG wire backend frame length out of safe bounds.".into());
    }
    let body_len = len.saturating_sub(4);
    let mut body = vec![0u8; body_len];
    io.read_exact(&mut body)
        .map_err(|e| format!("PG TLS payload read failed: {e}"))?;
    Ok((hdr[0], body))
}

fn read_be_i32(buf: &[u8], offset: usize) -> Result<i32, String> {
    let slice = buf
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| "Truncated PG BE i32.".to_string())?;
    let arr: [u8; 4] = slice
        .try_into()
        .map_err(|_| "Invalid BE i32 slice.".to_string())?;
    Ok(i32::from_be_bytes(arr))
}

fn parse_first_datarow_i64(payload: &[u8]) -> Option<i64> {
    let cols = i16::from_be_bytes([*payload.first()?, *payload.get(1)?]);
    if cols < 1 {
        return None;
    }
    let col_len = read_be_i32(payload, 2).ok()?;
    let col_usize = usize::try_from(col_len).ok()?;
    let cell = payload.get(6..6usize.saturating_add(col_usize))?;
    std::str::from_utf8(cell).ok()?.trim().parse::<i64>().ok()
}

fn build_scram_final(
    client_first_bare: &str,
    server_first: &str,
    password: &str,
) -> Result<(String, [u8; 32]), String> {
    let mut srv_nonce = "";
    let mut salt_b64 = "";
    let mut iters = 0u32;
    for part in server_first.split(',') {
        if let Some(v) = part.strip_prefix("r=") {
            srv_nonce = v;
        } else if let Some(v) = part.strip_prefix("s=") {
            salt_b64 = v;
        } else if let Some(v) = part.strip_prefix("i=") {
            iters = v
                .parse::<u32>()
                .map_err(|_| "Invalid SCRAM iterations.".to_string())?;
        }
    }
    let client_nonce = client_first_bare
        .strip_prefix("n=,r=")
        .ok_or_else(|| "Invalid SCRAM client nonce.".to_string())?;
    if !srv_nonce.starts_with(client_nonce) || iters == 0 || iters > 1_000_000 {
        return Err("Invalid SCRAM server challenge parameters.".into());
    }
    let salt = B64_STD
        .decode(salt_b64.as_bytes())
        .map_err(|_| "Invalid SCRAM base64 salt.".to_string())?;
    let hi = grdr_crypto::pbkdf2_hmac_sha256(password.as_bytes(), &salt, iters)
        .map_err(|_| "SCRAM PBKDF2 derivation failed.".to_string())?;
    let client_key = hmac_sha256(&*hi, b"Client Key");
    let stored_key = sha256_digest(&client_key);
    let server_key = hmac_sha256(&*hi, b"Server Key");
    let client_final_without_proof = format!("c=biws,r={srv_nonce}");
    let auth_msg = format!("{client_first_bare},{server_first},{client_final_without_proof}");
    let client_sig = hmac_sha256(&stored_key, auth_msg.as_bytes());
    let mut client_proof = [0u8; 32];
    for ((dst, ck), cs) in client_proof
        .iter_mut()
        .zip(client_key.iter())
        .zip(client_sig.iter())
    {
        *dst = *ck ^ *cs;
    }
    let server_sig = hmac_sha256(&server_key, auth_msg.as_bytes());
    let proof_b64 = B64_STD.encode(client_proof);
    Ok((
        format!("{client_final_without_proof},p={proof_b64}"),
        server_sig,
    ))
}

#[cfg(test)]
mod tests {
    use super::{B64_STD, build_scram_final};
    use base64::Engine as _;

    #[test]
    fn scram_sha256_matches_rfc7677_pbkdf2_kdf_and_rejects_bad_params() {
        let client_first_bare = "n=,r=rOprNGfwEbeRWgbNEkqO";
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let (final_msg, srv_sig) =
            build_scram_final(client_first_bare, server_first, "pencil").unwrap();
        assert_eq!(
            final_msg,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=qvT2SWdEH5Q06albL+hjSYuUhCG7VndFyzIb7CK4n9k="
        );
        assert_eq!(
            B64_STD.encode(srv_sig),
            "3HO6Qt1M4MKJrmlKaoOqLAI0/0TV0HZe7J9H3MBtSOg="
        );
        assert!(
            build_scram_final(
                client_first_bare,
                "r=wrongnonce,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
                "pencil",
            )
            .is_err()
        );
        assert!(
            build_scram_final(
                client_first_bare,
                "r=rOprNGfwEbeRWgbNEkqOxyz,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0",
                "pencil",
            )
            .is_err()
        );
    }
}
