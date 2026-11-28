// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use grdr_crypto::{SigningKeypair, hmac_sha256, sha256_digest};
use grdr_ports::{BusAppendMessage, BusPort, KvSnapshotRepo, OrgId, SingleCtx, TenantCtx};
use grdr_rel_postgres::{
    CODE_PG_WIRE, PostgresConfig, PostgresLogBus, PostgresRelationalStore, PostgresSslMode,
};

const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0f];
const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
const OID_EKU: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x25];
const OID_SERVER_AUTH: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

struct CertBundle {
    ca_pem: String,
    leaf_der: Vec<u8>,
    server_config: Arc<ServerConfig>,
}

enum ServerTlsMode {
    AcceptTls(Arc<ServerConfig>),
    RefuseSslRequest,
}

enum ServerAuthMode<'a> {
    Scram {
        password: &'a str,
        iterations: u32,
        tamper_server_sig: bool,
    },
    RejectMd5,
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn der_tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len().saturating_add(4));
    out.push(tag);
    if payload.len() < 128 {
        out.push(u8::try_from(payload.len()).unwrap_or(0));
    } else if payload.len() < 256 {
        out.push(0x81);
        out.push(u8::try_from(payload.len()).unwrap_or(0));
    } else {
        out.push(0x82);
        let be = u16::try_from(payload.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes();
        out.extend_from_slice(&be);
    }
    out.extend_from_slice(payload);
    out
}

fn der_seq(items: &[&[u8]]) -> Vec<u8> {
    let mut inner = Vec::new();
    for item in items {
        inner.extend_from_slice(item);
    }
    der_tlv(0x30, &inner)
}

fn der_name_cn(cn: &str) -> Vec<u8> {
    let utf8 = der_tlv(0x0c, cn.as_bytes());
    let atv = der_seq(&[OID_CN, &utf8]);
    let rdn = der_tlv(0x31, &atv);
    der_seq(&[&rdn])
}

fn der_alg_ed25519() -> Vec<u8> {
    der_seq(&[OID_ED25519])
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(bytes.len().saturating_add(1));
    inner.push(0x00);
    inner.extend_from_slice(bytes);
    der_tlv(0x03, &inner)
}

fn der_ext(oid: &[u8], critical: bool, value_der: &[u8]) -> Vec<u8> {
    let oct = der_tlv(0x04, value_der);
    if critical {
        let bool_true = [0x01, 0x01, 0xff];
        der_seq(&[oid, &bool_true, &oct])
    } else {
        der_seq(&[oid, &oct])
    }
}

struct X509Spec<'a> {
    issuer_kp: &'a SigningKeypair,
    issuer_cn: &'a str,
    subject_kp: &'a SigningKeypair,
    subject_cn: &'a str,
    serial: u64,
    expired: bool,
    is_ca: bool,
    san_dns: Option<&'a str>,
    san_ip: Option<IpAddr>,
}

fn sign_x509(spec: &X509Spec<'_>) -> Vec<u8> {
    let version = der_tlv(0xa0, &[0x02, 0x01, 0x02]);
    let mut ser_bytes = spec.serial.to_be_bytes().to_vec();
    ser_bytes.insert(0, 0x01);
    let serial_der = der_tlv(0x02, &ser_bytes);
    let sig_alg = der_alg_ed25519();
    let issuer = der_name_cn(spec.issuer_cn);
    let subject = der_name_cn(spec.subject_cn);

    let nb = der_tlv(0x17, b"200101000000Z");
    let na = der_tlv(
        0x17,
        if spec.expired {
            b"210101000000Z"
        } else {
            b"400101000000Z"
        },
    );
    let validity = der_seq(&[&nb, &na]);

    let pub_bit = der_bit_string(&spec.subject_kp.public_key_bytes());
    let spki = der_seq(&[&sig_alg, &pub_bit]);

    let mut exts = Vec::new();
    let bc_val = if spec.is_ca {
        der_seq(&[&[0x01, 0x01, 0xff]])
    } else {
        der_seq(&[])
    };
    exts.push(der_ext(OID_BASIC_CONSTRAINTS, true, &bc_val));

    let ku_val = if spec.is_ca {
        vec![0x03, 0x02, 0x01, 0x06]
    } else {
        vec![0x03, 0x02, 0x07, 0x80]
    };
    exts.push(der_ext(OID_KEY_USAGE, true, &ku_val));

    if !spec.is_ca {
        let eku_seq = der_seq(&[OID_SERVER_AUTH]);
        exts.push(der_ext(OID_EKU, false, &eku_seq));

        let mut san_items = Vec::new();
        if let Some(dns) = spec.san_dns {
            san_items.push(der_tlv(0x82, dns.as_bytes()));
        }
        if let Some(ip) = spec.san_ip {
            match ip {
                IpAddr::V4(v4) => san_items.push(der_tlv(0x87, &v4.octets())),
                IpAddr::V6(v6) => san_items.push(der_tlv(0x87, &v6.octets())),
            }
        }
        let mut san_inner = Vec::new();
        for item in &san_items {
            san_inner.extend_from_slice(item);
        }
        let san_seq = der_tlv(0x30, &san_inner);
        exts.push(der_ext(OID_SAN, false, &san_seq));
    }

    let mut exts_inner = Vec::new();
    for ext in &exts {
        exts_inner.extend_from_slice(ext);
    }
    let exts_seq = der_tlv(0x30, &exts_inner);
    let exts_wrapper = der_tlv(0xa3, &exts_seq);

    let tbs = der_seq(&[
        &version,
        &serial_der,
        &sig_alg,
        &issuer,
        &validity,
        &subject,
        &spki,
        &exts_wrapper,
    ]);
    let raw_sig = spec.issuer_kp.sign_ed25519_raw(&tbs);
    let sig_bit = der_bit_string(&raw_sig);
    der_seq(&[&tbs, &sig_alg, &sig_bit])
}

fn der_to_pem(label: &str, der: &[u8]) -> String {
    let encoded = B64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        if let Ok(line) = std::str::from_utf8(chunk) {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn kp_to_pkcs8(kp: &SigningKeypair) -> Result<Vec<u8>, String> {
    let seed = B64.decode(kp.seed_b64()).map_err(|e| e.to_string())?;
    let inner_oct = der_tlv(0x04, &seed);
    let outer_oct = der_tlv(0x04, &inner_oct);
    let alg = der_alg_ed25519();
    let ver = [0x02, 0x01, 0x00];
    Ok(der_seq(&[&ver, &alg, &outer_oct]))
}

fn build_pki(dns: &str, ip: IpAddr, expired: bool) -> Result<CertBundle, String> {
    let ca_kp = SigningKeypair::generate().map_err(|e| e.to_string())?;
    let leaf_kp = SigningKeypair::generate().map_err(|e| e.to_string())?;
    let ca_der = sign_x509(&X509Spec {
        issuer_kp: &ca_kp,
        issuer_cn: "Guardrails Test CA",
        subject_kp: &ca_kp,
        subject_cn: "Guardrails Test CA",
        serial: 1,
        expired: false,
        is_ca: true,
        san_dns: None,
        san_ip: None,
    });
    let leaf_der = sign_x509(&X509Spec {
        issuer_kp: &ca_kp,
        issuer_cn: "Guardrails Test CA",
        subject_kp: &leaf_kp,
        subject_cn: dns,
        serial: 2,
        expired,
        is_ca: false,
        san_dns: Some(dns),
        san_ip: Some(ip),
    });
    let ca_pem = der_to_pem("CERTIFICATE", &ca_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp_to_pkcs8(&leaf_kp)?));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(leaf_der.clone()),
                CertificateDer::from(ca_der),
            ],
            key,
        )
        .map_err(|e| e.to_string())?;
    Ok(CertBundle {
        ca_pem,
        leaf_der,
        server_config: Arc::new(server_config),
    })
}

fn read_pg_startup(sock: &mut dyn Read) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).ok()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len.saturating_sub(4)];
    sock.read_exact(&mut body).ok()?;
    Some(body)
}

fn send_auth_frame(sock: &mut dyn Write, code: i32, payload: &[u8]) {
    let total = u32::try_from(8usize.saturating_add(payload.len())).unwrap_or(u32::MAX);
    let _ = sock.write_all(b"R");
    let _ = sock.write_all(&total.to_be_bytes());
    let _ = sock.write_all(&code.to_be_bytes());
    let _ = sock.write_all(payload);
    let _ = sock.flush();
}

fn send_cmd_complete(sock: &mut dyn Write, tag: &[u8]) {
    let len = u32::try_from(4usize.saturating_add(tag.len())).unwrap_or(u32::MAX);
    let _ = sock.write_all(b"C");
    let _ = sock.write_all(&len.to_be_bytes());
    let _ = sock.write_all(tag);
    let _ = sock.write_all(&[b'Z', 0, 0, 0, 5, b'I']);
    let _ = sock.flush();
}

fn send_single_row(sock: &mut dyn Write, val: &str) {
    let vb = val.as_bytes();
    let t_len: u32 = 4 + 2 + 2 + 18;
    let _ = sock.write_all(b"T");
    let _ = sock.write_all(&t_len.to_be_bytes());
    let _ = sock.write_all(&1u16.to_be_bytes());
    let _ = sock.write_all(b"v\0");
    let _ = sock.write_all(&[0u8; 18]);
    let d_len = u32::try_from(4 + 2 + 4 + vb.len()).unwrap_or(u32::MAX);
    let _ = sock.write_all(b"D");
    let _ = sock.write_all(&d_len.to_be_bytes());
    let _ = sock.write_all(&1u16.to_be_bytes());
    let vb_i32 = i32::try_from(vb.len()).unwrap_or(0);
    let _ = sock.write_all(&vb_i32.to_be_bytes());
    let _ = sock.write_all(vb);
}

fn serve_pg_session(
    mut tcp: TcpStream,
    tls_mode: &ServerTlsMode,
    leaf_der: Option<&[u8]>,
    auth: ServerAuthMode<'_>,
) {
    let mut len_buf = [0u8; 4];
    if tcp.read_exact(&mut len_buf).is_err() {
        return;
    }
    let first_len = u32::from_be_bytes(len_buf) as usize;
    let mut first_body = vec![0u8; first_len.saturating_sub(4)];
    if tcp.read_exact(&mut first_body).is_err() {
        return;
    }
    let Ok(code_bytes): Result<[u8; 4], _> = first_body.get(..4).unwrap_or_default().try_into()
    else {
        return;
    };
    let code = u32::from_be_bytes(code_bytes);
    let mut stream: Box<dyn ReadWrite> = if code == 80_877_103 {
        match tls_mode {
            ServerTlsMode::RefuseSslRequest => {
                let _ = tcp.write_all(b"N");
                let _ = tcp.flush();
                return;
            }
            ServerTlsMode::AcceptTls(cfg) => {
                if tcp.write_all(b"S").is_err() || tcp.flush().is_err() {
                    return;
                }
                let Ok(mut conn) = ServerConnection::new(Arc::clone(cfg)) else {
                    return;
                };
                while conn.is_handshaking() {
                    if conn.complete_io(&mut tcp).is_err() {
                        return;
                    }
                }
                let tls_stream = StreamOwned::new(conn, tcp);
                let mut boxed: Box<dyn ReadWrite> = Box::new(tls_stream);
                let _ = read_pg_startup(boxed.as_mut());
                boxed
            }
        }
    } else {
        Box::new(tcp)
    };

    match auth {
        ServerAuthMode::RejectMd5 => {
            send_auth_frame(stream.as_mut(), 5, &[1, 2, 3, 4]);
            return;
        }
        ServerAuthMode::Scram {
            password,
            iterations,
            tamper_server_sig,
        } => {
            let mechs = b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0";
            send_auth_frame(stream.as_mut(), 10, mechs);
            let Some((tag, body)) = read_pg_frame_opt(stream.as_mut()) else {
                return;
            };
            if tag != b'p' {
                return;
            }
            let Some(nul_pos) = body.iter().position(|&b| b == 0) else {
                return;
            };
            let Some(chosen_mech) = body
                .get(..nul_pos)
                .and_then(|s| std::str::from_utf8(s).ok())
            else {
                return;
            };
            let len_start = nul_pos.saturating_add(1);
            let len_end = len_start.saturating_add(4);
            let Ok(cf_bytes): Result<[u8; 4], _> =
                body.get(len_start..len_end).unwrap_or_default().try_into()
            else {
                return;
            };
            let cf_len = usize::try_from(i32::from_be_bytes(cf_bytes)).unwrap_or(0);
            let cf_end = len_end.saturating_add(cf_len);
            let Some(client_first) = body
                .get(len_end..cf_end)
                .and_then(|s| std::str::from_utf8(s).ok())
            else {
                return;
            };
            let (gs2, client_first_bare) = if chosen_mech == "SCRAM-SHA-256-PLUS" {
                let prefix = "p=tls-server-end-point,,";
                let Some(rest) = client_first.strip_prefix(prefix) else {
                    return;
                };
                (prefix, rest)
            } else {
                let Some(rest) = client_first.strip_prefix("n,,") else {
                    return;
                };
                ("n,,", rest)
            };
            let Some(client_nonce) = client_first_bare.strip_prefix("n=,r=") else {
                return;
            };
            let server_nonce = format!("{client_nonce}srvrandom9876");
            let Ok(salt) = grdr_crypto::random_bytes_16() else {
                return;
            };
            let salt_b64 = B64.encode(salt);
            let server_first = format!("r={server_nonce},s={salt_b64},i={iterations}");
            send_auth_frame(stream.as_mut(), 11, server_first.as_bytes());

            let Some((ftag, fbody)) = read_pg_frame_opt(stream.as_mut()) else {
                return;
            };
            if ftag != b'p' {
                return;
            }
            let Ok(client_final) = std::str::from_utf8(&fbody) else {
                return;
            };
            let Some((without_proof, proof_part)) = client_final.rsplit_once(",p=") else {
                return;
            };
            if chosen_mech == "SCRAM-SHA-256-PLUS"
                && let Some(der) = leaf_der
            {
                let mut cbind = gs2.as_bytes().to_vec();
                cbind.extend_from_slice(&sha256_digest(der));
                let expected_c = format!("c={}", B64.encode(cbind));
                if !without_proof.starts_with(&expected_c) {
                    return;
                }
            }
            let auth_msg = format!("{client_first_bare},{server_first},{without_proof}");
            let Ok(salted) =
                grdr_crypto::pbkdf2_hmac_sha256(password.as_bytes(), &salt, iterations)
            else {
                return;
            };
            let client_key = hmac_sha256(&*salted, b"Client Key");
            let stored_key = sha256_digest(&client_key);
            let client_sig = hmac_sha256(&stored_key, auth_msg.as_bytes());
            let mut expected_proof = [0u8; 32];
            for (slot, (a, b)) in expected_proof
                .iter_mut()
                .zip(client_key.iter().zip(client_sig.iter()))
            {
                *slot = a ^ b;
            }
            let Ok(got_proof) = B64.decode(proof_part) else {
                return;
            };
            if got_proof.as_slice() != expected_proof {
                let msg = b"MSCRAM proof invalid\0\0";
                let elen = u32::try_from(4usize.saturating_add(msg.len())).unwrap_or(u32::MAX);
                let _ = stream.write_all(b"E");
                let _ = stream.write_all(&elen.to_be_bytes());
                let _ = stream.write_all(msg);
                let _ = stream.flush();
                return;
            }
            let server_key = hmac_sha256(&*salted, b"Server Key");
            let mut server_sig = hmac_sha256(&server_key, auth_msg.as_bytes());
            if tamper_server_sig {
                server_sig[0] ^= 0xff;
            }
            let server_final = format!("v={}", B64.encode(server_sig));
            send_auth_frame(stream.as_mut(), 12, server_final.as_bytes());
            send_auth_frame(stream.as_mut(), 0, &[]);
            let _ = stream.write_all(&[b'Z', 0, 0, 0, 5, b'I']);
            let _ = stream.flush();
        }
    }

    while let Some((tag, body)) = read_pg_frame_opt(stream.as_mut()) {
        match tag {
            b'Q' => {
                let sql = String::from_utf8_lossy(&body);
                if sql.contains("SELECT 'force_error'") {
                    let msg = b"Minjected pool error\0\0";
                    let elen = u32::try_from(4usize.saturating_add(msg.len())).unwrap_or(u32::MAX);
                    let _ = stream.write_all(b"E");
                    let _ = stream.write_all(&elen.to_be_bytes());
                    let _ = stream.write_all(msg);
                    let _ = stream.write_all(&[b'Z', 0, 0, 0, 5, b'E']);
                    let _ = stream.flush();
                } else {
                    send_cmd_complete(stream.as_mut(), b"SELECT 1\0");
                }
            }
            b'P' => {
                let _ = read_pg_frame_opt(stream.as_mut());
                let _ = read_pg_frame_opt(stream.as_mut());
                let _ = read_pg_frame_opt(stream.as_mut());
                let _ = stream.write_all(&[b'1', 0, 0, 0, 4]);
                let _ = stream.write_all(&[b'2', 0, 0, 0, 4]);
                send_single_row(stream.as_mut(), "{\"pooled\":true}");
                send_cmd_complete(stream.as_mut(), b"SELECT 1\0");
            }
            b'X' => break,
            _ => {}
        }
    }
}

fn read_pg_frame_opt(sock: &mut dyn Read) -> Option<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    sock.read_exact(&mut hdr).ok()?;
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let mut body = vec![0u8; len.saturating_sub(4)];
    sock.read_exact(&mut body).ok()?;
    Some((hdr[0], body))
}

#[test]
fn postgres_tls_verify_full_verify_ca_require_and_scram_plus() {
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let pki = build_pki("pg.internal.test", ip, false).unwrap();
    let mut pw_rand = [0u8; 16];
    grdr_crypto::fill_random(&mut pw_rand).unwrap();
    let pw = grdr_crypto::sha256_hex(&pw_rand);

    for mode in [
        PostgresSslMode::VerifyFull,
        PostgresSslMode::VerifyCa,
        PostgresSslMode::Require,
        PostgresSslMode::Prefer,
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg_tls = Arc::clone(&pki.server_config);
        let leaf = pki.leaf_der.clone();
        let pw_srv = pw.clone();
        let srv = thread::spawn(move || {
            let Ok((tcp, _)) = listener.accept() else {
                return;
            };
            serve_pg_session(
                tcp,
                &ServerTlsMode::AcceptTls(cfg_tls),
                Some(&leaf),
                ServerAuthMode::Scram {
                    password: &pw_srv,
                    iterations: 4_096,
                    tamper_server_sig: false,
                },
            );
        });

        let cfg = PostgresConfig::parse_dsn(&format!(
            "postgres://grdr:{pw}@{addr}/guardrails?sslmode={}",
            mode.as_str()
        ))
        .unwrap()
        .with_ca_cert_pem(pki.ca_pem.clone());
        let store = PostgresRelationalStore::connect(cfg).unwrap();
        let ctx = TenantCtx::Single(SingleCtx::new(OrgId::new("org-tls").unwrap()));
        let kv = store.get_kv(&ctx, "ns", "k1").unwrap();
        assert_eq!(kv.as_deref(), Some("{\"pooled\":true}"));
        let stats = store.pool_stats().unwrap().unwrap();
        assert_eq!(stats.total_connects, 1);
        assert!(stats.reused_checkouts >= 1);
        drop(store);
        srv.join().unwrap();
    }
}

#[test]
fn postgres_tls_rejects_untrusted_ca_wrong_host_expired_cert_and_refusal() {
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let good_pki = build_pki("pg.good.test", ip, false).unwrap();
    let wrong_host_pki = build_pki("other.host.test", "10.0.0.2".parse().unwrap(), false).unwrap();
    let untrusted_pki = build_pki("pg.good.test", ip, false).unwrap();
    let expired_pki = build_pki("pg.good.test", ip, true).unwrap();

    // Untrusted CA fails under VerifyFull, VerifyCa, and Require.
    for mode in [
        PostgresSslMode::VerifyFull,
        PostgresSslMode::VerifyCa,
        PostgresSslMode::Require,
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv_cfg = Arc::clone(&untrusted_pki.server_config);
        let srv = thread::spawn(move || {
            let Ok((tcp, _)) = listener.accept() else {
                return;
            };
            serve_pg_session(
                tcp,
                &ServerTlsMode::AcceptTls(srv_cfg),
                None,
                ServerAuthMode::Scram {
                    password: "secret-password",
                    iterations: 4_096,
                    tamper_server_sig: false,
                },
            );
        });
        let cfg = PostgresConfig::parse_dsn(&format!(
            "postgres://grdr:secret-password@{addr}/guardrails?sslmode={}",
            mode.as_str()
        ))
        .unwrap()
        .with_ca_cert_pem(good_pki.ca_pem.clone());
        let err = PostgresRelationalStore::connect(cfg).unwrap_err();
        assert_eq!(err.code, CODE_PG_WIRE);
        let _ = srv.join();
    }

    // Wrong SAN hostname fails VerifyFull, but passes VerifyCa when CA is trusted.
    for (mode, expect_ok) in [
        (PostgresSslMode::VerifyFull, false),
        (PostgresSslMode::VerifyCa, true),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv_cfg = Arc::clone(&wrong_host_pki.server_config);
        let leaf = wrong_host_pki.leaf_der.clone();
        let srv = thread::spawn(move || {
            let Ok((tcp, _)) = listener.accept() else {
                return;
            };
            serve_pg_session(
                tcp,
                &ServerTlsMode::AcceptTls(srv_cfg),
                Some(&leaf),
                ServerAuthMode::Scram {
                    password: "secret-password",
                    iterations: 4_096,
                    tamper_server_sig: false,
                },
            );
        });
        let cfg = PostgresConfig::parse_dsn(&format!(
            "postgres://grdr:secret-password@{addr}/guardrails?sslmode={}",
            mode.as_str()
        ))
        .unwrap()
        .with_ca_cert_pem(wrong_host_pki.ca_pem.clone());
        let res = PostgresRelationalStore::connect(cfg);
        assert_eq!(res.is_ok(), expect_ok);
        drop(res);
        let _ = srv.join();
    }

    // Expired cert fails closed.
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv_cfg = Arc::clone(&expired_pki.server_config);
        let srv = thread::spawn(move || {
            let Ok((tcp, _)) = listener.accept() else {
                return;
            };
            serve_pg_session(
                tcp,
                &ServerTlsMode::AcceptTls(srv_cfg),
                None,
                ServerAuthMode::Scram {
                    password: "secret-password",
                    iterations: 4_096,
                    tamper_server_sig: false,
                },
            );
        });
        let cfg = PostgresConfig::parse_dsn(&format!(
            "postgres://grdr:secret-password@{addr}/guardrails?sslmode=verify-full"
        ))
        .unwrap()
        .with_ca_cert_pem(expired_pki.ca_pem.clone());
        assert_eq!(
            PostgresRelationalStore::connect(cfg).unwrap_err().code,
            CODE_PG_WIRE
        );
        let _ = srv.join();
    }

    // SSLRequest refusal ('N') fails closed under sslmode=require.
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let Ok((tcp, _)) = listener.accept() else {
                return;
            };
            serve_pg_session(
                tcp,
                &ServerTlsMode::RefuseSslRequest,
                None,
                ServerAuthMode::Scram {
                    password: "secret-password",
                    iterations: 4_096,
                    tamper_server_sig: false,
                },
            );
        });
        let cfg = PostgresConfig::parse_dsn(&format!(
            "postgres://grdr:secret-password@{addr}/guardrails?sslmode=require"
        ))
        .unwrap()
        .with_ca_cert_pem(good_pki.ca_pem);
        assert_eq!(
            PostgresRelationalStore::connect(cfg).unwrap_err().code,
            CODE_PG_WIRE
        );
        let _ = srv.join();
    }
}

#[test]
fn postgres_scram_adversarial_and_pool_poison_eviction() {
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let pki = build_pki("pg.scram.test", ip, false).unwrap();

    // Wrong password, tampered server signature, low iterations, MD5 reject.
    let cases = [
        (
            "wrong-pw",
            ServerAuthMode::Scram {
                password: "right-pw",
                iterations: 4_096,
                tamper_server_sig: false,
            },
        ),
        (
            "right-pw",
            ServerAuthMode::Scram {
                password: "right-pw",
                iterations: 4_096,
                tamper_server_sig: true,
            },
        ),
        (
            "right-pw",
            ServerAuthMode::Scram {
                password: "right-pw",
                iterations: 500,
                tamper_server_sig: false,
            },
        ),
        ("right-pw", ServerAuthMode::RejectMd5),
    ];
    for (client_pw, mode) in cases {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv_cfg = Arc::clone(&pki.server_config);
        let leaf = pki.leaf_der.clone();
        let srv = thread::spawn(move || {
            let Ok((tcp, _)) = listener.accept() else {
                return;
            };
            serve_pg_session(tcp, &ServerTlsMode::AcceptTls(srv_cfg), Some(&leaf), mode);
        });
        let cfg = PostgresConfig::parse_dsn(&format!(
            "postgres://grdr:{client_pw}@{addr}/guardrails?sslmode=verify-full"
        ))
        .unwrap()
        .with_ca_cert_pem(pki.ca_pem.clone());
        let err = PostgresRelationalStore::connect(cfg).unwrap_err();
        assert_eq!(err.code, CODE_PG_WIRE);
        let _ = srv.join();
    }

    // Pool evicts poisoned connection and opens a clean replacement.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_cfg = Arc::clone(&pki.server_config);
    let leaf = pki.leaf_der.clone();
    let srv = thread::spawn(move || {
        for _ in 0..2 {
            let Ok((tcp, _)) = listener.accept() else {
                return;
            };
            serve_pg_session(
                tcp,
                &ServerTlsMode::AcceptTls(Arc::clone(&srv_cfg)),
                Some(&leaf),
                ServerAuthMode::Scram {
                    password: "pool-password",
                    iterations: 4_096,
                    tamper_server_sig: false,
                },
            );
        }
    });
    let cfg = PostgresConfig::parse_dsn(&format!(
        "postgres://grdr:pool-password@{addr}/guardrails?sslmode=verify-full&pool_size=2"
    ))
    .unwrap()
    .with_ca_cert_pem(pki.ca_pem);
    let pool = grdr_rel_postgres::PgConnectionPool::new(&cfg).unwrap();
    let _ = pool.execute_simple("SELECT 1", 2_000).unwrap();
    assert!(pool.execute_simple("SELECT 'force_error'", 2_000).is_err());
    let _ = pool.execute_simple("SELECT 1", 2_000).unwrap();
    let stats = pool.stats().unwrap();
    assert_eq!(stats.discarded_connections, 1);
    assert_eq!(stats.total_connects, 2);
    drop(pool);
    srv.join().unwrap();
}

#[test]
fn postgres_log_bus_passes_bus_port_contract() {
    let bus = PostgresLogBus::open_offline().unwrap();
    grdr_ports_testkit::assert_bus_port_contract(&bus).unwrap();

    let ctx = SingleCtx::new(OrgId::new("org-pg-bus").unwrap());
    let range = bus
        .append(
            &ctx,
            "decision",
            0,
            &[BusAppendMessage {
                key: "k1".into(),
                headers: BTreeMap::from([("lane".into(), "decision".into())]),
                payload: b"evt-1".to_vec(),
            }],
            42,
        )
        .unwrap();
    assert_eq!(range.first_offset, 0);

    // Offline commit monotonicity guard rejects regressing committed_offset.
    let sub = bus
        .subscribe(
            "g-mono",
            "decision",
            0,
            "h1",
            grdr_ports::FencingToken::new(1),
            10_000,
        )
        .unwrap();
    assert_eq!(sub.fence.value(), 1);
    bus.append(
        &ctx,
        "decision",
        0,
        &[BusAppendMessage {
            key: "k2".into(),
            headers: BTreeMap::new(),
            payload: b"evt-2".to_vec(),
        }],
        43,
    )
    .unwrap();
    bus.commit("g-mono", "decision", 0, 1, None, sub.fence)
        .unwrap();
    let regressed = bus
        .commit("g-mono", "decision", 0, 0, None, sub.fence)
        .unwrap_err();
    assert_eq!(regressed.code, grdr_ports::CODE_BUS_INVALID_INPUT);
}

#[test]
fn postgres_tls_scram_omitted_plus_sends_y_flag_and_rejects_cleartext_everywhere() {
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let pki = build_pki("pg.downgrade.test", ip, false).unwrap();

    // Server omits SCRAM-SHA-256-PLUS over TLS: client MUST announce "y,,".
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_cfg = Arc::clone(&pki.server_config);
    let srv = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let _ = read_pg_startup(&mut tcp);
        tcp.write_all(b"S").unwrap();
        tcp.flush().unwrap();
        let mut conn = ServerConnection::new(srv_cfg).unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp).unwrap();
        }
        let mut tls = StreamOwned::new(conn, tcp);
        let _ = read_pg_startup(&mut tls);
        send_auth_frame(&mut tls, 10, b"SCRAM-SHA-256\0\0");
        let (tag, body) = read_pg_frame_opt(&mut tls).unwrap();
        assert_eq!(tag, b'p');
        let nul = body.iter().position(|&b| b == 0).unwrap();
        let client_first_opt = body
            .get(nul.saturating_add(5)..)
            .and_then(|s| std::str::from_utf8(s).ok());
        assert!(client_first_opt.is_some_and(|s| s.starts_with("y,,n=,r=")));
        // Close gracefully after verification; test expects fail or clean check.
    });
    let cfg = PostgresConfig::parse_dsn(&format!(
        "postgres://grdr:pw123@{addr}/guardrails?sslmode=verify-full"
    ))
    .unwrap()
    .with_ca_cert_pem(pki.ca_pem.clone());
    assert!(PostgresRelationalStore::connect(cfg).is_err());
    srv.join().unwrap();

    // Cleartext auth rejected even under VerifyFull TLS.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_cfg = Arc::clone(&pki.server_config);
    let srv = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let _ = read_pg_startup(&mut tcp);
        tcp.write_all(b"S").unwrap();
        tcp.flush().unwrap();
        let mut conn = ServerConnection::new(srv_cfg).unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp).unwrap();
        }
        let mut tls = StreamOwned::new(conn, tcp);
        let _ = read_pg_startup(&mut tls);
        send_auth_frame(&mut tls, 3, &[]);
    });
    let cfg = PostgresConfig::parse_dsn(&format!(
        "postgres://grdr:pw123@{addr}/guardrails?sslmode=verify-full"
    ))
    .unwrap()
    .with_ca_cert_pem(pki.ca_pem);
    let err = PostgresRelationalStore::connect(cfg).unwrap_err();
    assert_eq!(err.code, CODE_PG_WIRE);
    srv.join().unwrap();
}

#[test]
fn postgres_bus_wire_atomic_rls_fence_and_monotonic_guards() {
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    let pki = build_pki("pg.buswire.test", ip, false).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_cfg = Arc::clone(&pki.server_config);
    let leaf = pki.leaf_der.clone();
    let mut pw_raw = [0u8; 16];
    grdr_crypto::fill_random(&mut pw_raw).unwrap();
    let bus_pw = grdr_crypto::encode_lower_hex(&pw_raw);
    let bus_pw_srv = bus_pw.clone();

    let srv = thread::spawn(move || {
        let Ok((mut tcp, _)) = listener.accept() else {
            return;
        };
        let mut len_buf = [0u8; 4];
        if tcp.read_exact(&mut len_buf).is_err() {
            return;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut first = vec![0u8; len.saturating_sub(4)];
        if tcp.read_exact(&mut first).is_err() {
            return;
        }
        let _ = tcp.write_all(b"S");
        let _ = tcp.flush();
        let mut conn = ServerConnection::new(srv_cfg).unwrap();
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp).unwrap();
        }
        let mut tls = StreamOwned::new(conn, tcp);
        let _ = read_pg_startup(&mut tls);

        let mechs = b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0";
        send_auth_frame(&mut tls, 10, mechs);
        let (_, body) = read_pg_frame_opt(&mut tls).unwrap();
        let nul = body.iter().position(|&b| b == 0).unwrap();
        let Some(cf) = body
            .get(nul.saturating_add(5)..)
            .and_then(|s| std::str::from_utf8(s).ok())
        else {
            return;
        };
        let (_, bare) = cf.split_once(",,").unwrap();
        let cnonce = bare.strip_prefix("n=,r=").unwrap();
        let Ok(salt) = grdr_crypto::random_bytes_16() else {
            return;
        };
        let salt_b64 = B64.encode(salt);
        let srv_first = format!("r={cnonce}buswire12345,s={salt_b64},i=4096");
        send_auth_frame(&mut tls, 11, srv_first.as_bytes());
        let (_, fbody) = read_pg_frame_opt(&mut tls).unwrap();
        let cfinal = std::str::from_utf8(&fbody).unwrap();
        let (wo_proof, _) = cfinal.rsplit_once(",p=").unwrap();
        let auth_msg = format!("{bare},{srv_first},{wo_proof}");
        let Ok(salted) = grdr_crypto::pbkdf2_hmac_sha256(bus_pw_srv.as_bytes(), &salt, 4096) else {
            return;
        };
        let skey = hmac_sha256(&*salted, b"Server Key");
        let ssig = hmac_sha256(&skey, auth_msg.as_bytes());
        let _ = leaf;
        send_auth_frame(&mut tls, 12, format!("v={}", B64.encode(ssig)).as_bytes());
        send_auth_frame(&mut tls, 0, &[]);
        let _ = tls.write_all(&[b'Z', 0, 0, 0, 5, b'I']);
        let _ = tls.flush();

        let mut saw_atomic_ddl = false;
        let mut saw_atomic_subscribe_sql = false;
        let mut saw_atomic_commit_sql = false;
        while let Some((tag, body)) = read_pg_frame_opt(&mut tls) {
            match tag {
                b'Q' => {
                    let sql = std::str::from_utf8(&body).unwrap_or("");
                    if sql.contains("CREATE POLICY grdr_bus_message_select_rls") {
                        assert!(sql.contains("BEGIN;") && sql.contains("COMMIT;"));
                        assert!(sql.contains("NULLIF(current_setting('app.org_id', true), '')"));
                        assert!(sql.contains("app.org_ids"));
                        saw_atomic_ddl = true;
                    }
                    send_cmd_complete(&mut tls, b"OK\0");
                }
                b'P' => {
                    let sql = std::str::from_utf8(&body).unwrap_or("");
                    let _ = read_pg_frame_opt(&mut tls);
                    let _ = read_pg_frame_opt(&mut tls);
                    let _ = read_pg_frame_opt(&mut tls);
                    let _ = tls.write_all(&[b'1', 0, 0, 0, 4, b'2', 0, 0, 0, 4]);
                    if sql.contains("ON CONFLICT (consumer_group, stream, partition) DO UPDATE") {
                        assert!(sql.contains("WHERE excluded.fence >= bus_consumer.fence"));
                        assert!(sql.contains("RETURNING committed_offset::text, checkpoint"));
                        saw_atomic_subscribe_sql = true;
                        // Simulate 0-row fenced-out update!
                    } else if sql.contains("UPDATE bus_consumer c") {
                        assert!(sql.contains("AND c.fence = $6::bigint"));
                        assert!(sql.contains(
                            "AND (c.committed_offset IS NULL OR c.committed_offset <= $4::bigint)"
                        ));
                        saw_atomic_commit_sql = true;
                    } else if sql.contains("SELECT (next_offset - 1)::text FROM bus_partition") {
                        send_single_row(&mut tls, "5");
                    } else if sql
                        .contains("SELECT fence::text, committed_offset::text FROM bus_consumer")
                    {
                        send_single_row(&mut tls, "2");
                    }
                    send_cmd_complete(&mut tls, b"SELECT 0\0");
                }
                b'X' => break,
                _ => {}
            }
        }
        assert!(saw_atomic_ddl && saw_atomic_subscribe_sql && saw_atomic_commit_sql);
    });

    let cfg = PostgresConfig::parse_dsn(&format!(
        "postgres://grdr:{bus_pw}@{addr}/guardrails?sslmode=verify-full"
    ))
    .unwrap()
    .with_ca_cert_pem(pki.ca_pem);
    let bus = PostgresLogBus::connect(cfg).unwrap();

    // Fenced-out 0-row subscribe RETURNING MUST fail closed with CODE_BUS_STALE_FENCE.
    let sub_err = bus
        .subscribe(
            "grp",
            "events",
            0,
            "worker-1",
            grdr_ports::FencingToken::new(1),
            10_000,
        )
        .unwrap_err();
    assert_eq!(sub_err.code, grdr_ports::CODE_BUS_STALE_FENCE);

    // Atomic commit SQL check: verify commit rejects stale fence when 0 rows updated.
    let commit_err = bus
        .commit(
            "grp",
            "events",
            0,
            1,
            None,
            grdr_ports::FencingToken::new(1),
        )
        .unwrap_err();
    assert_eq!(commit_err.code, grdr_ports::CODE_BUS_STALE_FENCE);
    drop(bus);
    srv.join().unwrap();
}
