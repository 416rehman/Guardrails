// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use grdr_bus_nats::{
    CODE_NATS_CONFIG, CODE_NATS_WIRE, NatsConfig, NatsJetStreamBus, NatsTlsHandshake,
    encode_user_seed, parse_nats_creds, public_nkey_from_seed,
};
use grdr_crypto::{SigningKeypair, verify_ed25519_raw};
use grdr_ports::{BusAppendMessage, BusPort, OrgId, SingleCtx};

const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0f];
const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
const OID_EKU: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x25];
const OID_SERVER_AUTH: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

#[derive(Clone)]
struct JsStored {
    seq: u64,
    subject: String,
    headers_raw: String,
    payload: Vec<u8>,
}

#[derive(Default)]
struct JsConsumerState {
    ack_floor: u64,
    delivered: u64,
    acked_seqs: BTreeSet<u64>,
    filter_subject: Option<String>,
}

#[derive(Default)]
struct JsStreamState {
    messages: Vec<JsStored>,
    consumers: BTreeMap<String, JsConsumerState>,
}

#[derive(Default)]
struct MockJsState {
    streams: BTreeMap<String, JsStreamState>,
    expected_nkey: String,
    expected_pubkey_bytes: [u8; 32],
    expected_jwt: Option<String>,
}

struct MockNatsServer {
    addr: std::net::SocketAddr,
    ca_pem: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for MockNatsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

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
    der_seq(&[&der_tlv(0x31, &der_seq(&[OID_CN, &utf8]))])
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
        der_seq(&[oid, &[0x01, 0x01, 0xff], &oct])
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
    is_ca: bool,
    san_dns: Option<&'a str>,
    san_ip: Option<IpAddr>,
}

fn sign_x509(spec: &X509Spec<'_>) -> Vec<u8> {
    let version = der_tlv(0xa0, &[0x02, 0x01, 0x02]);
    let mut ser_bytes = spec.serial.to_be_bytes().to_vec();
    ser_bytes.insert(0, 0x01);
    let serial_der = der_tlv(0x02, &ser_bytes);
    let sig_alg = der_seq(&[OID_ED25519]);
    let issuer = der_name_cn(spec.issuer_cn);
    let subject = der_name_cn(spec.subject_cn);
    let validity = der_seq(&[
        &der_tlv(0x17, b"200101000000Z"),
        &der_tlv(0x17, b"400101000000Z"),
    ]);
    let spki = der_seq(&[
        &sig_alg,
        &der_bit_string(&spec.subject_kp.public_key_bytes()),
    ]);
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
        exts.push(der_ext(OID_EKU, false, &der_seq(&[OID_SERVER_AUTH])));
        let mut san_inner = Vec::new();
        if let Some(dns) = spec.san_dns {
            san_inner.extend_from_slice(&der_tlv(0x82, dns.as_bytes()));
        }
        if let Some(ip) = spec.san_ip {
            match ip {
                IpAddr::V4(v4) => san_inner.extend_from_slice(&der_tlv(0x87, &v4.octets())),
                IpAddr::V6(v6) => san_inner.extend_from_slice(&der_tlv(0x87, &v6.octets())),
            }
        }
        exts.push(der_ext(OID_SAN, false, &der_tlv(0x30, &san_inner)));
    }
    let mut exts_inner = Vec::new();
    for ext in &exts {
        exts_inner.extend_from_slice(ext);
    }
    let exts_wrapper = der_tlv(0xa3, &der_tlv(0x30, &exts_inner));
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
    let sig = spec.issuer_kp.sign_ed25519_raw(&tbs);
    der_seq(&[&tbs, &sig_alg, &der_bit_string(&sig)])
}

fn build_tls_bundle(san_dns: &str, san_ip: IpAddr) -> Result<(String, Arc<ServerConfig>), String> {
    let ca_kp = SigningKeypair::generate().map_err(|e| e.to_string())?;
    let leaf_kp = SigningKeypair::generate().map_err(|e| e.to_string())?;
    let ca_der = sign_x509(&X509Spec {
        issuer_kp: &ca_kp,
        issuer_cn: "NATS Test CA",
        subject_kp: &ca_kp,
        subject_cn: "NATS Test CA",
        serial: 1,
        is_ca: true,
        san_dns: None,
        san_ip: None,
    });
    let leaf_der = sign_x509(&X509Spec {
        issuer_kp: &ca_kp,
        issuer_cn: "NATS Test CA",
        subject_kp: &leaf_kp,
        subject_cn: san_dns,
        serial: 2,
        is_ca: false,
        san_dns: Some(san_dns),
        san_ip: Some(san_ip),
    });
    let b64 = B64.encode(&ca_der);
    let mut ca_pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        if let Ok(line) = std::str::from_utf8(chunk) {
            ca_pem.push_str(line);
            ca_pem.push('\n');
        }
    }
    ca_pem.push_str("-----END CERTIFICATE-----\n");

    let seed = B64.decode(leaf_kp.seed_b64()).map_err(|e| e.to_string())?;
    let inner_oct = der_tlv(0x04, &seed);
    let outer_oct = der_tlv(0x04, &inner_oct);
    let pkcs8 = der_seq(&[&[0x02, 0x01, 0x00], &der_seq(&[OID_ED25519]), &outer_oct]);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let srv_cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf_der), CertificateDer::from(ca_der)],
            key,
        )
        .map_err(|e| e.to_string())?;
    Ok((ca_pem, Arc::new(srv_cfg)))
}

struct LineConn<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: Read + Write> LineConn<S> {
    fn read_line(&mut self) -> Option<String> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let bytes: Vec<u8> = self.buf.drain(..=pos).collect();
                return String::from_utf8(bytes).ok();
            }
            let mut tmp = [0u8; 2048];
            let n = self.stream.read(&mut tmp).ok()?;
            if n == 0 {
                return None;
            }
            self.buf.extend_from_slice(tmp.get(..n)?);
        }
    }

    fn read_exact(&mut self, len: usize) -> Option<Vec<u8>> {
        while self.buf.len() < len {
            let mut tmp = [0u8; 2048];
            let n = self.stream.read(&mut tmp).ok()?;
            if n == 0 {
                return None;
            }
            self.buf.extend_from_slice(tmp.get(..n)?);
        }
        Some(self.buf.drain(..len).collect())
    }
}

fn send_msg<S: Write>(s: &mut S, subject: &str, sid: &str, reply: Option<&str>, payload: &[u8]) {
    let hdr = match reply {
        Some(r) => format!("MSG {subject} {sid} {r} {}\r\n", payload.len()),
        None => format!("MSG {subject} {sid} {}\r\n", payload.len()),
    };
    let _ = s.write_all(hdr.as_bytes());
    let _ = s.write_all(payload);
    let _ = s.write_all(b"\r\n");
    let _ = s.flush();
}

fn send_hmsg<S: Write>(
    s: &mut S,
    subject: &str,
    sid: &str,
    reply: Option<&str>,
    hdr_raw: &str,
    payload: &[u8],
) {
    let hlen = hdr_raw.len();
    let total = hlen.saturating_add(payload.len());
    let line = match reply {
        Some(r) => format!("HMSG {subject} {sid} {r} {hlen} {total}\r\n"),
        None => format!("HMSG {subject} {sid} {hlen} {total}\r\n"),
    };
    let _ = s.write_all(line.as_bytes());
    let _ = s.write_all(hdr_raw.as_bytes());
    let _ = s.write_all(payload);
    let _ = s.write_all(b"\r\n");
    let _ = s.flush();
}

fn spawn_mock_nats(
    tls_first: bool,
    san_dns: &str,
    expected_nkey: String,
    expected_pubkey_bytes: [u8; 32],
    expected_jwt: Option<String>,
) -> Result<MockNatsServer, String> {
    let ip: IpAddr = "127.0.0.1"
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let (ca_pem, tls_cfg) = build_tls_bundle(san_dns, ip)?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(MockJsState {
        streams: BTreeMap::new(),
        expected_nkey,
        expected_pubkey_bytes,
        expected_jwt,
    }));

    let stop_bg = Arc::clone(&stop);
    let st_bg = Arc::clone(&state);
    let handle = thread::spawn(move || {
        while !stop_bg.load(Ordering::SeqCst) {
            let Ok((tcp, _)) = listener.accept() else {
                break;
            };
            if stop_bg.load(Ordering::SeqCst) {
                break;
            }
            let _ = tcp.set_read_timeout(Some(Duration::from_secs(3)));
            let tls_c = Arc::clone(&tls_cfg);
            let st_c = Arc::clone(&st_bg);
            thread::spawn(move || {
                let mut tcp = tcp;
                let mut nonce_raw = [0u8; 16];
                if grdr_crypto::fill_random(&mut nonce_raw).is_err() {
                    return;
                }
                let nonce = grdr_crypto::encode_lower_hex(&nonce_raw);
                let info_line = format!(
                    "INFO {{\"server_id\":\"mock-js\",\"version\":\"2.15.2\",\"jetstream\":true,\"tls_required\":true,\"auth_required\":true,\"headers\":true,\"nonce\":\"{nonce}\"}}\r\n"
                );
                if tls_first {
                    let Ok(mut conn) = ServerConnection::new(tls_c) else {
                        return;
                    };
                    while conn.is_handshaking() {
                        if conn.complete_io(&mut tcp).is_err() {
                            return;
                        }
                    }
                    let mut tls_s = StreamOwned::new(conn, tcp);
                    if tls_s.write_all(info_line.as_bytes()).is_err() || tls_s.flush().is_err() {
                        return;
                    }
                    run_js_loop(
                        LineConn {
                            stream: tls_s,
                            buf: Vec::new(),
                        },
                        &nonce,
                        st_c,
                    );
                } else {
                    if tcp.write_all(info_line.as_bytes()).is_err() || tcp.flush().is_err() {
                        return;
                    }
                    let Ok(mut conn) = ServerConnection::new(tls_c) else {
                        return;
                    };
                    while conn.is_handshaking() {
                        if conn.complete_io(&mut tcp).is_err() {
                            return;
                        }
                    }
                    let tls_s = StreamOwned::new(conn, tcp);
                    run_js_loop(
                        LineConn {
                            stream: tls_s,
                            buf: Vec::new(),
                        },
                        &nonce,
                        st_c,
                    );
                }
            });
        }
    });

    Ok(MockNatsServer {
        addr,
        ca_pem,
        stop,
        handle: Some(handle),
    })
}

fn find_stream_for_subject<'a>(
    streams: &'a mut BTreeMap<String, JsStreamState>,
    subject: &str,
) -> Option<(String, &'a mut JsStreamState)> {
    // Match `grdr.<org>.<stream>.p<partition>` against registered stream names (`GRDR_EVENTS_0`, etc.).
    let parts: Vec<&str> = subject.split('.').collect();
    let [p0, _org, p2, p3] = parts.as_slice() else {
        return None;
    };
    if *p0 != "grdr" {
        return None;
    }
    let st_tok = p2.to_ascii_uppercase();
    let part_num: u32 = p3.strip_prefix('p')?.parse().ok()?;
    let name = if st_tok == "EVENTS" {
        format!("GRDR_EVENTS_{}", part_num % 8)
    } else {
        format!("GRDR_{st_tok}")
    };
    streams.get_mut(&name).map(|s| (name, s))
}

fn run_js_loop<S: Read + Write>(mut lc: LineConn<S>, nonce: &str, state: Arc<Mutex<MockJsState>>) {
    let mut subs: BTreeMap<String, String> = BTreeMap::new();
    while let Some(line) = lc.read_line() {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if let Some(json_str) = trimmed.strip_prefix("CONNECT ") {
            let val: serde_json::Value = serde_json::from_str(json_str).unwrap_or_default();
            let Ok(st) = state.lock() else {
                return;
            };
            let got_nkey = val.get("nkey").and_then(|v| v.as_str()).unwrap_or("");
            let got_sig = val.get("sig").and_then(|v| v.as_str()).unwrap_or("");
            let got_jwt = val.get("jwt").and_then(|v| v.as_str());
            let sig_ok = URL_SAFE_NO_PAD
                .decode(got_sig)
                .ok()
                .and_then(|raw| <[u8; 64]>::try_from(raw.as_slice()).ok())
                .is_some_and(|sig64| {
                    verify_ed25519_raw(&st.expected_pubkey_bytes, nonce.as_bytes(), &sig64).is_ok()
                });
            let jwt_ok = st
                .expected_jwt
                .as_deref()
                .is_none_or(|exp| got_jwt == Some(exp));
            if got_nkey != st.expected_nkey || !sig_ok || !jwt_ok {
                let _ = lc.stream.write_all(b"-ERR 'Authorization Violation'\r\n");
                let _ = lc.stream.flush();
                return;
            }
        } else if trimmed == "PING" {
            let _ = lc.stream.write_all(b"PONG\r\n");
            let _ = lc.stream.flush();
        } else if let Some(rest) = trimmed.strip_prefix("SUB ") {
            let mut it = rest.split_whitespace();
            if let (Some(subj), Some(sid)) = (it.next(), it.next()) {
                subs.insert(subj.to_string(), sid.to_string());
            }
        } else if trimmed.starts_with("UNSUB ") {
            continue;
        } else if let Some(rest) = trimmed.strip_prefix("PUB ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            let (subj, reply, len_r) = match parts.as_slice() {
                [s, r, l] => (*s, Some(*r), l.parse::<usize>()),
                [s, l] => (*s, None, l.parse::<usize>()),
                _ => continue,
            };
            let Ok(len) = len_r else {
                continue;
            };
            let Some(payload) = lc.read_exact(len) else {
                break;
            };
            if lc.read_exact(2).is_none() {
                break;
            }
            handle_js_pub(&mut lc.stream, &subs, &state, subj, reply, &payload);
        } else if let Some(rest) = trimmed.strip_prefix("HPUB ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            let (subj, reply, hlen_r, tlen_r) = match parts.as_slice() {
                [s, r, h, t] => (*s, Some(*r), h.parse::<usize>(), t.parse::<usize>()),
                [s, h, t] => (*s, None, h.parse::<usize>(), t.parse::<usize>()),
                _ => continue,
            };
            let (Ok(hlen), Ok(tlen)) = (hlen_r, tlen_r) else {
                continue;
            };
            let Some(body) = lc.read_exact(tlen) else {
                break;
            };
            if lc.read_exact(2).is_none() {
                break;
            }
            let hdr_raw = String::from_utf8_lossy(body.get(..hlen).unwrap_or_default()).to_string();
            let payload = body.get(hlen..).unwrap_or_default().to_vec();
            let Ok(mut st) = state.lock() else {
                return;
            };
            if let Some((sname, sstate)) = find_stream_for_subject(&mut st.streams, subj) {
                let seq = u64::try_from(sstate.messages.len().saturating_add(1)).unwrap_or(1);
                sstate.messages.push(JsStored {
                    seq,
                    subject: subj.to_string(),
                    headers_raw: hdr_raw,
                    payload,
                });
                if let Some(r_subj) = reply
                    && let Some(sid) = subs.get(r_subj)
                {
                    let ack = format!("{{\"stream\":\"{sname}\",\"seq\":{seq}}}");
                    send_msg(&mut lc.stream, r_subj, sid, None, ack.as_bytes());
                }
            }
        }
    }
}

fn handle_js_pub<S: Write>(
    stream: &mut S,
    subs: &BTreeMap<String, String>,
    state: &Arc<Mutex<MockJsState>>,
    subj: &str,
    reply: Option<&str>,
    payload: &[u8],
) {
    let Ok(mut st) = state.lock() else {
        return;
    };
    if let Some(sname) = subj.strip_prefix("$JS.API.STREAM.INFO.") {
        if let Some(r_subj) = reply
            && let Some(sid) = subs.get(r_subj)
        {
            if let Some(sstate) = st.streams.get(sname) {
                let last_seq = sstate.messages.last().map_or(0, |m| m.seq);
                let json = format!(
                    "{{\"config\":{{\"name\":\"{sname}\"}},\"state\":{{\"messages\":{},\"last_seq\":{last_seq}}}}}",
                    sstate.messages.len()
                );
                send_msg(stream, r_subj, sid, None, json.as_bytes());
            } else {
                send_msg(
                    stream,
                    r_subj,
                    sid,
                    None,
                    br#"{"error":{"code":404,"description":"stream not found"}}"#,
                );
            }
        }
        return;
    }
    if let Some(sname) = subj.strip_prefix("$JS.API.STREAM.CREATE.") {
        st.streams.entry(sname.to_string()).or_default();
        if let Some(r_subj) = reply
            && let Some(sid) = subs.get(r_subj)
        {
            let json = format!(
                "{{\"config\":{{\"name\":\"{sname}\"}},\"state\":{{\"messages\":0,\"last_seq\":0}}}}"
            );
            send_msg(stream, r_subj, sid, None, json.as_bytes());
        }
        return;
    }
    if let Some(rest) = subj.strip_prefix("$JS.API.CONSUMER.CREATE.")
        && let Some((sname, durable)) = rest.split_once('.')
    {
        let req_v: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let start_seq = req_v
            .get("config")
            .and_then(|c| c.get("opt_start_seq"))
            .and_then(|v| v.as_u64());
        let filter_subj = req_v
            .get("config")
            .and_then(|c| c.get("filter_subject"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(sstate) = st.streams.get_mut(sname) {
            let cons = sstate.consumers.entry(durable.to_string()).or_default();
            if let Some(s) = start_seq {
                cons.delivered = s.saturating_sub(1);
            }
            cons.filter_subject = filter_subj;
        }
        if let Some(r_subj) = reply
            && let Some(sid) = subs.get(r_subj)
        {
            let json = format!("{{\"stream_name\":\"{sname}\",\"name\":\"{durable}\"}}");
            send_msg(stream, r_subj, sid, None, json.as_bytes());
        }
        return;
    }
    if let Some(rest) = subj.strip_prefix("$JS.API.CONSUMER.DELETE.")
        && let Some((sname, cname)) = rest.split_once('.')
    {
        if let Some(sstate) = st.streams.get_mut(sname) {
            sstate.consumers.remove(cname);
        }
        if let Some(r_subj) = reply
            && let Some(sid) = subs.get(r_subj)
        {
            send_msg(stream, r_subj, sid, None, br#"{"success":true}"#);
        }
        return;
    }
    if let Some(rest) = subj.strip_prefix("$JS.API.CONSUMER.INFO.")
        && let Some((sname, durable)) = rest.split_once('.')
    {
        if let Some(r_subj) = reply
            && let Some(sid) = subs.get(r_subj)
        {
            let (ack_seq, pending) = st
                .streams
                .get(sname)
                .and_then(|ss| {
                    ss.consumers.get(durable).map(|c| {
                        let total = u64::try_from(ss.messages.len()).unwrap_or(0);
                        let p = total.saturating_sub(c.ack_floor);
                        (c.ack_floor, p)
                    })
                })
                .unwrap_or((0, 0));
            let json = format!(
                "{{\"ack_floor\":{{\"stream_seq\":{ack_seq}}},\"num_pending\":{pending},\"num_ack_pending\":0}}"
            );
            send_msg(stream, r_subj, sid, None, json.as_bytes());
        }
        return;
    }
    if let Some(rest) = subj.strip_prefix("$JS.API.CONSUMER.MSG.NEXT.")
        && let Some((sname, durable)) = rest.split_once('.')
        && let Some(r_subj) = reply
        && let Some(sid) = subs.get(r_subj)
    {
        let req_v: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let batch = req_v.get("batch").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
        if let Some(sstate) = st.streams.get_mut(sname) {
            let cons = sstate.consumers.entry(durable.to_string()).or_default();
            let mut sent = 0usize;
            for msg in &sstate.messages {
                let subj_match = cons.filter_subject.as_deref().is_none_or(|pat| {
                    let p_parts: Vec<&str> = pat.split('.').collect();
                    let s_parts: Vec<&str> = msg.subject.split('.').collect();
                    p_parts.len() == s_parts.len()
                        && p_parts
                            .iter()
                            .zip(s_parts.iter())
                            .all(|(p, s)| *p == "*" || p == s)
                });
                if msg.seq > cons.delivered && subj_match && sent < batch {
                    cons.delivered = msg.seq;
                    let ack_subj =
                        format!("$JS.ACK.{sname}.{durable}.1.{}.{}.0.0", msg.seq, msg.seq);
                    send_hmsg(
                        stream,
                        &msg.subject,
                        sid,
                        Some(&ack_subj),
                        &msg.headers_raw,
                        &msg.payload,
                    );
                    sent = sent.saturating_add(1);
                }
            }
            if sent < batch {
                send_hmsg(
                    stream,
                    r_subj,
                    sid,
                    None,
                    "NATS/1.0 404 No Messages\r\n\r\n",
                    b"",
                );
            }
        }
        return;
    }
    if let Some(rest) = subj.strip_prefix("$JS.ACK.") {
        let parts: Vec<&str> = rest.split('.').collect();
        if let [sname, durable, ..] = parts.as_slice()
            && parts.len() >= 5
            && let Some(seq_str) = parts.get(parts.len().saturating_sub(4))
        {
            let stream_seq = seq_str.parse::<u64>().unwrap_or(0);
            if let Some(sstate) = st.streams.get_mut(*sname)
                && let Some(cons) = sstate.consumers.get_mut(*durable)
            {
                cons.acked_seqs.insert(stream_seq);
                if stream_seq > cons.ack_floor {
                    cons.ack_floor = stream_seq;
                }
            }
        }
    }
}

#[test]
fn nats_tls_nkey_jwt_jetstream_wire_passes_bus_port_contract() {
    let kp = SigningKeypair::generate().unwrap();
    let seed_b = B64.decode(kp.seed_b64()).unwrap();
    let seed_arr: [u8; 32] = seed_b.try_into().unwrap();
    let seed_str = encode_user_seed(&seed_arr);
    let pub_nkey = public_nkey_from_seed(&seed_str).unwrap();
    assert!(seed_str.starts_with("SU"));
    assert!(pub_nkey.starts_with('U'));

    let jwt = "eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJzdWIiOiJVIiwidHlwZSI6InVzZXIifQ.sig";
    let creds = format!(
        "-----BEGIN NATS USER JWT-----\n{jwt}\n-----END NATS USER JWT-----\n\n-----BEGIN USER NKEY SEED-----\n{seed_str}\n-----END USER NKEY SEED-----\n"
    );
    let parsed_creds = parse_nats_creds(&creds).unwrap();
    assert_eq!(parsed_creds.jwt.as_deref().map(String::as_str), Some(jwt));
    let creds_dbg = format!("{parsed_creds:?}");
    assert!(!creds_dbg.contains(&seed_str));
    assert!(!creds_dbg.contains(jwt));
    assert!(creds_dbg.contains("[REDACTED]"));

    assert_eq!(NatsTlsHandshake::default(), NatsTlsHandshake::TlsFirst);

    // StartTLS AfterInfo mode + NKey + JWT running full assert_bus_port_contract!
    let srv = spawn_mock_nats(
        false,
        "nats.internal.test",
        pub_nkey.clone(),
        kp.public_key_bytes(),
        Some(jwt.to_string()),
    )
    .unwrap();
    let cfg = NatsConfig::parse_url(&format!("tls://{}", srv.addr))
        .unwrap()
        .with_ca_cert_pem(srv.ca_pem.clone())
        .with_tls_handshake(NatsTlsHandshake::AfterInfo)
        .with_creds_bundle(&creds)
        .unwrap();
    assert_eq!(
        NatsConfig::parse_url("tls://127.0.0.1:4222")
            .unwrap()
            .tls_handshake,
        NatsTlsHandshake::TlsFirst
    );
    let bus = NatsJetStreamBus::connect(cfg).unwrap();
    grdr_ports_testkit::assert_bus_port_contract(&bus).unwrap();

    // TlsFirst mode also connects & appends cleanly.
    let srv_first = spawn_mock_nats(
        true,
        "nats.first.test",
        pub_nkey,
        kp.public_key_bytes(),
        None,
    )
    .unwrap();
    let cfg_first = NatsConfig::parse_url(&format!("tls://{}", srv_first.addr))
        .unwrap()
        .with_ca_cert_pem(srv_first.ca_pem.clone())
        .with_tls_handshake(NatsTlsHandshake::TlsFirst)
        .with_nkey_seed(&seed_str);
    let bus_first = NatsJetStreamBus::connect(cfg_first).unwrap();
    let org = OrgId::new("org-tls-first").unwrap();
    let ctx = SingleCtx::new(org);
    let range = bus_first
        .append(
            &ctx,
            "events",
            0,
            &[BusAppendMessage {
                key: "k1".into(),
                headers: BTreeMap::new(),
                payload: b"tls-first-event".to_vec(),
            }],
            100,
        )
        .unwrap();
    assert_eq!(range.first_offset, 0);
}

#[test]
fn nats_adversarial_tls_and_nkey_rejections() {
    let kp = SigningKeypair::generate().unwrap();
    let wrong_kp = SigningKeypair::generate().unwrap();
    let seed_arr: [u8; 32] = B64.decode(kp.seed_b64()).unwrap().try_into().unwrap();
    let wrong_arr: [u8; 32] = B64.decode(wrong_kp.seed_b64()).unwrap().try_into().unwrap();
    let good_seed = encode_user_seed(&seed_arr);
    let wrong_seed = encode_user_seed(&wrong_arr);
    let pub_nkey = public_nkey_from_seed(&good_seed).unwrap();

    // Corrupted NKey seed CRC, `=` padding, wrong length, and non-zero trailing bits fail.
    let mut bad_crc = good_seed.clone();
    let last = bad_crc.pop().unwrap();
    bad_crc.push(if last == 'A' { 'B' } else { 'A' });
    let bad_cfg = NatsConfig::parse_url("tls://127.0.0.1:4222")
        .unwrap()
        .with_nkey_seed(bad_crc);
    assert_eq!(bad_cfg.validate().unwrap_err().code, CODE_NATS_CONFIG);

    assert_eq!(
        NatsConfig::parse_url("tls://127.0.0.1:4222")
            .unwrap()
            .with_nkey_seed(format!("{good_seed}=="))
            .validate()
            .unwrap_err()
            .code,
        CODE_NATS_CONFIG
    );
    let mut non_zero_pad = good_seed.clone();
    let last_ch = non_zero_pad.pop().unwrap();
    non_zero_pad.push(if last_ch == 'A' { 'B' } else { 'A' });
    assert_eq!(
        NatsConfig::parse_url("tls://127.0.0.1:4222")
            .unwrap()
            .with_nkey_seed(non_zero_pad)
            .validate()
            .unwrap_err()
            .code,
        CODE_NATS_CONFIG
    );

    let srv = spawn_mock_nats(
        false,
        "nats.auth.test",
        pub_nkey.clone(),
        kp.public_key_bytes(),
        None,
    )
    .unwrap();
    let ctx = SingleCtx::new(OrgId::new("org-fail").unwrap());
    let msg = BusAppendMessage {
        key: "k".into(),
        headers: BTreeMap::new(),
        payload: b"x".to_vec(),
    };

    // Untrusted CA fails TLS handshake.
    let untrusted = NatsJetStreamBus::connect(
        NatsConfig::parse_url(&format!("tls://{}", srv.addr))
            .unwrap()
            .with_tls_handshake(NatsTlsHandshake::AfterInfo)
            .with_nkey_seed(&good_seed),
    )
    .unwrap();
    assert_eq!(
        untrusted
            .append(&ctx, "events", 0, std::slice::from_ref(&msg), 1)
            .unwrap_err()
            .code,
        CODE_NATS_WIRE
    );

    // Wrong NKey rejected by server `-ERR 'Authorization Violation'`.
    let wrong_auth = NatsJetStreamBus::connect(
        NatsConfig::parse_url(&format!("tls://{}", srv.addr))
            .unwrap()
            .with_ca_cert_pem(srv.ca_pem.clone())
            .with_tls_handshake(NatsTlsHandshake::AfterInfo)
            .with_nkey_seed(&wrong_seed),
    )
    .unwrap();
    assert_eq!(
        wrong_auth
            .append(&ctx, "events", 0, &[msg], 2)
            .unwrap_err()
            .code,
        CODE_NATS_WIRE
    );
}

#[test]
fn nats_jetstream_dotted_org_header_stripping_set_ctx_and_no_downgrade() {
    let kp = SigningKeypair::generate().unwrap();
    let seed_arr: [u8; 32] = B64.decode(kp.seed_b64()).unwrap().try_into().unwrap();
    let seed_str = encode_user_seed(&seed_arr);
    let pub_nkey = public_nkey_from_seed(&seed_str).unwrap();

    // TlsFirst authenticated JetStream server test for dotted vs underscore orgs + header strip + SetCtx.
    let srv = spawn_mock_nats(
        true,
        "nats.isolation.test",
        pub_nkey,
        kp.public_key_bytes(),
        None,
    )
    .unwrap();
    let cfg = NatsConfig::parse_url(&format!("tls://{}", srv.addr))
        .unwrap()
        .with_ca_cert_pem(srv.ca_pem.clone())
        .with_nkey_seed(&seed_str);
    let bus = NatsJetStreamBus::connect(cfg).unwrap();

    let org_dot = OrgId::new("org.1").unwrap();
    let org_under = OrgId::new("org_1").unwrap();
    let org_evil = OrgId::new("org-evil").unwrap();

    // Flood stream with unauthorized org-evil messages ahead of org.1 and org_1.
    for i in 0..5 {
        bus.append(
            &SingleCtx::new(org_evil.clone()),
            "events",
            0,
            &[BusAppendMessage {
                key: format!("evil-{i}"),
                headers: BTreeMap::new(),
                payload: b"evil".to_vec(),
            }],
            i,
        )
        .unwrap();
    }

    // Attempt header spoofing via mixed-case X-Grdr-Org-Id.
    let spoofed_headers = BTreeMap::from([
        ("X-Grdr-Org-Id".into(), "org-evil".into()),
        ("X-Grdr-Delegation-Id".into(), "forged-del".into()),
        ("X-Custom".into(), "kept".into()),
    ]);
    bus.append(
        &SingleCtx::new(org_dot.clone()),
        "events",
        0,
        &[BusAppendMessage {
            key: "k-dot".into(),
            headers: spoofed_headers,
            payload: b"payload-dot".to_vec(),
        }],
        10,
    )
    .unwrap();
    bus.append(
        &SingleCtx::new(org_under.clone()),
        "events",
        0,
        &[BusAppendMessage {
            key: "k-under".into(),
            headers: BTreeMap::new(),
            payload: b"payload-under".to_vec(),
        }],
        11,
    )
    .unwrap();

    let fetched_dot = bus
        .fetch(
            &grdr_ports::TenantCtx::Single(SingleCtx::new(org_dot.clone())),
            "events",
            0,
            None,
            10,
        )
        .unwrap();
    assert_eq!(fetched_dot.len(), 1);
    let msg_dot = fetched_dot.first().unwrap();
    assert_eq!(msg_dot.organisation_id, org_dot);
    assert_eq!(msg_dot.payload, b"payload-dot");
    assert_eq!(msg_dot.delegation_id, None);
    assert_eq!(
        msg_dot.headers.get("X-Custom").map(String::as_str),
        Some("kept")
    );

    let fetched_under = bus
        .fetch(
            &grdr_ports::TenantCtx::Single(SingleCtx::new(org_under.clone())),
            "events",
            0,
            None,
            10,
        )
        .unwrap();
    assert_eq!(fetched_under.len(), 1);
    let msg_under = fetched_under.first().unwrap();
    assert_eq!(msg_under.organisation_id, org_under);
    assert_eq!(msg_under.payload, b"payload-under");

    // SetCtx fetches only authorized orgs without stalling behind org-evil flood.
    let set_ctx = grdr_ports::TenantCtx::set("snap-1", vec![org_dot, org_under]).unwrap();
    let set_msgs = bus.fetch(&set_ctx, "events", 0, None, 1).unwrap();
    assert_eq!(set_msgs.len(), 1);
    assert_eq!(set_msgs.first().unwrap().payload, b"payload-dot");

    // Token validation fails cleanly on empty/NUL stream or consumer_group.
    assert_eq!(
        bus.subscribe(
            "",
            "events",
            0,
            "holder",
            grdr_ports::FencingToken::new(1),
            1_000
        )
        .unwrap_err()
        .code,
        grdr_ports::CODE_BUS_INVALID_INPUT
    );

    // Pre-TLS INFO advertising jetstream=false must never silently downgrade to unacked HPUB.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let no_js_srv = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let _ = sock
            .write_all(b"INFO {\"server_id\":\"nojs\",\"jetstream\":false,\"headers\":true}\r\n");
        let _ = sock.flush();
    });
    let no_js_bus =
        NatsJetStreamBus::connect(NatsConfig::parse_url(&format!("nats://{addr}")).unwrap())
            .unwrap();
    let downgrade_err = no_js_bus
        .append(
            &SingleCtx::new(org_evil),
            "events",
            0,
            &[BusAppendMessage {
                key: "k".into(),
                headers: BTreeMap::new(),
                payload: b"v".to_vec(),
            }],
            1,
        )
        .unwrap_err();
    assert_eq!(downgrade_err.code, CODE_NATS_WIRE);
    let _ = no_js_srv.join();
}
