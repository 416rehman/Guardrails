// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use grdr_blob::{S3AddressingStyle, S3BlobConfig, S3BlobStore, S3Credentials, S3LifecycleMode};
use grdr_crypto::{SigningKeypair, encode_lower_hex, hmac_sha256, sha256_hex};
use grdr_ports::{
    BlobPort, ByteRange, CODE_BLOB_INVALID_RANGE, CODE_BLOB_IO, OrgId, SingleCtx, TenantCtx,
    TenantPath, TenantRelPath,
};

const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0f];
const OID_SAN: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
const OID_EKU: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x25];
const OID_SERVER_AUTH: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

#[derive(Clone)]
struct StoredS3Object {
    bytes: Vec<u8>,
    etag: String,
    version_id: String,
}

#[derive(Default)]
struct MockS3State {
    objects: BTreeMap<String, StoredS3Object>,
    versioning_enabled: bool,
    has_lifecycle: bool,
    last_raw_target: String,
    next_version: u64,
}

struct MockS3Server {
    addr: std::net::SocketAddr,
    ca_pem: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for MockS3Server {
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
    let atv = der_seq(&[OID_CN, &utf8]);
    let rdn = der_tlv(0x31, &atv);
    der_seq(&[&rdn])
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

fn build_tls_bundle() -> Result<(String, Arc<ServerConfig>), String> {
    let ca_kp = SigningKeypair::generate().map_err(|e| e.to_string())?;
    let leaf_kp = SigningKeypair::generate().map_err(|e| e.to_string())?;
    let ca_der = sign_x509(&X509Spec {
        issuer_kp: &ca_kp,
        issuer_cn: "S3 Test CA",
        subject_kp: &ca_kp,
        subject_cn: "S3 Test CA",
        serial: 1,
        is_ca: true,
        san_dns: None,
        san_ip: None,
    });
    let ip: IpAddr = "127.0.0.1"
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let leaf_der = sign_x509(&X509Spec {
        issuer_kp: &ca_kp,
        issuer_cn: "S3 Test CA",
        subject_kp: &leaf_kp,
        subject_cn: "127.0.0.1",
        serial: 2,
        is_ca: false,
        san_dns: Some("localhost"),
        san_ip: Some(ip),
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

fn spawn_mock_s3(
    use_tls: bool,
    versioning: bool,
    lifecycle: bool,
    expected_ak: &str,
    expected_sk: &str,
) -> Result<MockS3Server, String> {
    let (ca_pem, tls_cfg) = build_tls_bundle()?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let state = Arc::new(Mutex::new(MockS3State {
        versioning_enabled: versioning,
        has_lifecycle: lifecycle,
        ..MockS3State::default()
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let state_bg = Arc::clone(&state);
    let stop_bg = Arc::clone(&stop);
    let ak = expected_ak.to_string();
    let sk = expected_sk.to_string();

    let handle = thread::spawn(move || {
        while !stop_bg.load(Ordering::SeqCst) {
            let Ok((tcp, _)) = listener.accept() else {
                break;
            };
            if stop_bg.load(Ordering::SeqCst) {
                break;
            }
            let _ = tcp.set_read_timeout(Some(Duration::from_secs(3)));
            let st = Arc::clone(&state_bg);
            let tls = Arc::clone(&tls_cfg);
            let ak_c = ak.clone();
            let sk_c = sk.clone();
            thread::spawn(move || {
                if use_tls {
                    let Ok(mut conn) = ServerConnection::new(tls) else {
                        return;
                    };
                    let mut tcp = tcp;
                    while conn.is_handshaking() {
                        if conn.complete_io(&mut tcp).is_err() {
                            return;
                        }
                    }
                    let mut stream = StreamOwned::new(conn, tcp);
                    serve_http_loop(&mut stream, &st, &ak_c, &sk_c);
                } else {
                    let mut tcp = tcp;
                    serve_http_loop(&mut tcp, &st, &ak_c, &sk_c);
                }
            });
        }
    });

    Ok(MockS3Server {
        addr,
        ca_pem,
        stop,
        handle: Some(handle),
    })
}

struct ParsedHttpReq {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut dyn Read) -> Option<ParsedHttpReq> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(tmp.get(..n)?);
    };
    let head_str = String::from_utf8_lossy(buf.get(..header_end)?).to_string();
    let mut lines = head_str.split("\r\n");
    let req_line = lines.next()?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let content_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end.saturating_add(4);
    while buf.len() < body_start.saturating_add(content_len) {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(tmp.get(..n)?);
    }
    let body = buf
        .get(body_start..body_start.saturating_add(content_len))?
        .to_vec();
    Some(ParsedHttpReq {
        method,
        target,
        headers,
        body,
    })
}

fn verify_sigv4(
    method: &str,
    path: &str,
    query: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    expected_ak: &str,
    expected_sk: &str,
) -> bool {
    let Some(auth) = headers.get("authorization") else {
        return false;
    };
    let Some(rest) = auth.strip_prefix("AWS4-HMAC-SHA256 ") else {
        return false;
    };
    let mut cred = "";
    let mut signed_hdrs = "";
    let mut got_sig = "";
    for part in rest.split(',') {
        let p = part.trim();
        if let Some(v) = p.strip_prefix("Credential=") {
            cred = v;
        } else if let Some(v) = p.strip_prefix("SignedHeaders=") {
            signed_hdrs = v;
        } else if let Some(v) = p.strip_prefix("Signature=") {
            got_sig = v;
        }
    }
    let Some((ak, scope)) = cred.split_once('/') else {
        return false;
    };
    if ak != expected_ak {
        return false;
    }
    let scope_parts: Vec<&str> = scope.split('/').collect();
    let [p0, p1, p2, p3] = scope_parts.as_slice() else {
        return false;
    };
    let amz_date = headers.get("x-amz-date").map(String::as_str).unwrap_or("");
    let body_hash = sha256_hex(body);
    let mut canon_hdrs = String::new();
    for h in signed_hdrs.split(';') {
        let val = headers.get(h).map(String::as_str).unwrap_or("");
        canon_hdrs.push_str(&format!("{h}:{val}\n"));
    }
    let canon_req = format!("{method}\n{path}\n{query}\n{canon_hdrs}\n{signed_hdrs}\n{body_hash}");
    let sts = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canon_req.as_bytes())
    );
    let mut k_sec = b"AWS4".to_vec();
    k_sec.extend_from_slice(expected_sk.as_bytes());
    let k_date = hmac_sha256(&k_sec, p0.as_bytes());
    let k_reg = hmac_sha256(&k_date, p1.as_bytes());
    let k_svc = hmac_sha256(&k_reg, p2.as_bytes());
    let k_sign = hmac_sha256(&k_svc, p3.as_bytes());
    let expect_sig = encode_lower_hex(&hmac_sha256(&k_sign, sts.as_bytes()));
    got_sig == expect_sig
}

fn write_http_resp(
    stream: &mut dyn Write,
    status: u16,
    reason: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> bool {
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    if stream.write_all(head.as_bytes()).is_err() {
        return false;
    }
    if !body.is_empty() && stream.write_all(body).is_err() {
        return false;
    }
    stream.flush().is_ok()
}

fn serve_http_loop<S: Read + Write>(
    stream: &mut S,
    state: &Arc<Mutex<MockS3State>>,
    ak: &str,
    sk: &str,
) {
    while let Some(ParsedHttpReq {
        method,
        target,
        headers,
        body,
    }) = read_http_request(stream)
    {
        let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
        if !verify_sigv4(&method, path, query, &headers, &body, ak, sk) {
            let err_xml = b"<Error><Code>SignatureDoesNotMatch</Code><Message>SigV4 mismatch</Message></Error>";
            let _ = write_http_resp(stream, 403, "Forbidden", &[], err_xml);
            continue;
        }
        let Ok(mut st) = state.lock() else {
            return;
        };
        st.last_raw_target = target.clone();
        let trimmed = path.trim_start_matches('/');
        let raw_key = trimmed.split_once('/').map(|(_, k)| k).unwrap_or("");
        let decoded_key = url::form_urlencoded::parse(format!("p={raw_key}").as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| raw_key.to_string());
        let key = decoded_key.as_str();

        if query.contains("versioning") {
            let status_tag = if st.versioning_enabled {
                "Enabled"
            } else {
                "Suspended"
            };
            let xml = format!(
                "<VersioningConfiguration><Status>{status_tag}</Status></VersioningConfiguration>"
            );
            let _ = write_http_resp(stream, 200, "OK", &[], xml.as_bytes());
            continue;
        }
        if query.contains("lifecycle") {
            if st.has_lifecycle {
                let xml = b"<LifecycleConfiguration><Rule><ID>expire</ID></Rule></LifecycleConfiguration>";
                let _ = write_http_resp(stream, 200, "OK", &[], xml);
            } else {
                let _ = write_http_resp(
                    stream,
                    404,
                    "Not Found",
                    &[],
                    b"<Error><Code>NoSuchLifecycleConfiguration</Code></Error>",
                );
            }
            continue;
        }
        if query.contains("list-type=2") {
            let mut prefix = "";
            let mut cont_token: Option<&str> = None;
            for pair in query.split('&') {
                if let Some(p) = pair.strip_prefix("prefix=") {
                    prefix = p;
                } else if let Some(t) = pair.strip_prefix("continuation-token=") {
                    cont_token = Some(t);
                }
            }
            let decoded_prefix = url::form_urlencoded::parse(format!("p={prefix}").as_bytes())
                .next()
                .map(|(_, v)| v.into_owned())
                .unwrap_or_else(|| prefix.to_string());
            let matching: Vec<_> = st
                .objects
                .iter()
                .filter(|(k, _)| k.starts_with(&decoded_prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let offset = cont_token
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let page_size = 2usize;
            let end = offset.saturating_add(page_size).min(matching.len());
            let truncated = end < matching.len();
            let mut xml = format!(
                "<ListBucketResult><IsTruncated>{}</IsTruncated>",
                if truncated { "true" } else { "false" }
            );
            if truncated {
                xml.push_str(&format!(
                    "<NextContinuationToken>{end}</NextContinuationToken>"
                ));
            }
            for (k, obj) in matching.get(offset..end).unwrap_or_default() {
                let escaped_k = k.replace('&', "&amp;").replace('<', "&lt;");
                xml.push_str(&format!(
                    "<Contents><Key>{escaped_k}</Key><Size>{}</Size><ETag>\"{}\"</ETag><LastModified>2026-11-24T00:00:00Z</LastModified></Contents>",
                    obj.bytes.len(),
                    obj.etag
                ));
            }
            xml.push_str("</ListBucketResult>");
            let _ = write_http_resp(stream, 200, "OK", &[], xml.as_bytes());
            continue;
        }

        match method.as_str() {
            "PUT" => {
                if headers.get("if-none-match").map(String::as_str) == Some("*")
                    && st.objects.contains_key(key)
                {
                    let _ = write_http_resp(stream, 412, "Precondition Failed", &[], b"");
                    continue;
                }
                if let Some(expect_etag) = headers.get("if-match") {
                    let clean_expect = expect_etag.trim().trim_matches('"');
                    let matches = st
                        .objects
                        .get(key)
                        .is_some_and(|obj| obj.etag == clean_expect);
                    if !matches {
                        let _ = write_http_resp(stream, 412, "Precondition Failed", &[], b"");
                        continue;
                    }
                }
                st.next_version = st.next_version.saturating_add(1);
                let etag = sha256_hex(&body);
                let ver = format!("v-{}", st.next_version);
                st.objects.insert(
                    key.to_string(),
                    StoredS3Object {
                        bytes: body,
                        etag: etag.clone(),
                        version_id: ver.clone(),
                    },
                );
                let qetag = format!("\"{etag}\"");
                let _ = write_http_resp(
                    stream,
                    200,
                    "OK",
                    &[("ETag", &qetag), ("x-amz-version-id", &ver)],
                    b"",
                );
            }
            "GET" => {
                let Some(obj) = st.objects.get(key).cloned() else {
                    let _ = write_http_resp(
                        stream,
                        404,
                        "Not Found",
                        &[],
                        b"<Error><Code>NoSuchKey</Code></Error>",
                    );
                    continue;
                };
                let qetag = format!("\"{}\"", obj.etag);
                if let Some(range_hdr) = headers.get("range")
                    && let Some(spec) = range_hdr.strip_prefix("bytes=")
                    && let Some((s_str, e_str)) = spec.split_once('-')
                    && let (Ok(s), Ok(e)) = (s_str.parse::<usize>(), e_str.parse::<usize>())
                {
                    if s >= obj.bytes.len() && !obj.bytes.is_empty() {
                        let _ = write_http_resp(stream, 416, "Range Not Satisfiable", &[], b"");
                        continue;
                    }
                    let end_excl = e.saturating_add(1).min(obj.bytes.len());
                    let slice = obj.bytes.get(s..end_excl).unwrap_or_default();
                    let _ = write_http_resp(
                        stream,
                        206,
                        "Partial Content",
                        &[("ETag", &qetag), ("x-amz-version-id", &obj.version_id)],
                        slice,
                    );
                    continue;
                }
                let _ = write_http_resp(
                    stream,
                    200,
                    "OK",
                    &[("ETag", &qetag), ("x-amz-version-id", &obj.version_id)],
                    &obj.bytes,
                );
            }
            "HEAD" => {
                let Some(obj) = st.objects.get(key) else {
                    let _ = write_http_resp(stream, 404, "Not Found", &[], b"");
                    continue;
                };
                let qetag = format!("\"{}\"", obj.etag);
                let len_s = obj.bytes.len().to_string();
                let _ = write_http_resp(
                    stream,
                    200,
                    "OK",
                    &[("ETag", &qetag), ("Content-Length", &len_s)],
                    b"",
                );
            }
            "DELETE" => {
                let existed = st.objects.remove(key).is_some();
                if existed {
                    let _ = write_http_resp(stream, 204, "No Content", &[], b"");
                } else {
                    let _ = write_http_resp(stream, 404, "Not Found", &[], b"");
                }
            }
            _ => {
                let _ = write_http_resp(stream, 405, "Method Not Allowed", &[], b"");
            }
        }
    }
}

#[test]
fn s3_blob_store_https_tls_sigv4_passes_port_contract_and_pagination() {
    let ak = "GRDRACCESSKEY1";
    let sk = "grdr-secret-access-key-test-value";
    let srv = spawn_mock_s3(true, true, true, ak, sk).unwrap();
    let cfg = S3BlobConfig::new(
        format!("https://{}", srv.addr),
        "grdr-lake-test",
        "us-east-1",
        S3Credentials::new(ak, sk),
    )
    .with_ca_cert_pem(srv.ca_pem.clone())
    .with_key_prefix("cell-01");
    let store = S3BlobStore::connect(cfg).unwrap();

    grdr_ports_testkit::assert_blob_port_contract(&store).unwrap();
    let report = store.require_versioned_conformance().unwrap();
    assert!(report.versioning_enabled);
    assert!(report.has_bucket_lifecycle);

    // Multi-page ListObjectsV2 (mock page size = 2, write 5 objects).
    let org = OrgId::new("org-page").unwrap();
    let wctx = SingleCtx::new(org.clone());
    for i in 0..5 {
        let p = TenantPath::parse(&wctx, &format!("batches/obj-{i:02}.parquet")).unwrap();
        store
            .put(&wctx, &p, format!("payload-{i}").as_bytes())
            .unwrap();
    }
    let listed = store
        .list(
            &TenantCtx::Single(wctx.clone()),
            &TenantRelPath::parse_prefix("batches").unwrap(),
        )
        .unwrap();
    assert_eq!(listed.len(), 5);

    // Zero-length range on existing vs missing, and out-of-bounds range.
    let target = TenantPath::parse(&wctx, "batches/obj-00.parquet").unwrap();
    let empty_slice = store
        .get_range(
            &TenantCtx::Single(wctx.clone()),
            &target,
            ByteRange {
                offset: 0,
                length: 0,
            },
        )
        .unwrap();
    assert_eq!(empty_slice, Some(Vec::new()));
    let oob = store
        .get_range(
            &TenantCtx::Single(wctx),
            &target,
            ByteRange {
                offset: 99_999,
                length: 10,
            },
        )
        .unwrap_err();
    assert_eq!(oob.code, CODE_BLOB_INVALID_RANGE);
}

#[test]
fn s3_blob_store_adversarial_tls_sigv4_and_conformance_guards() {
    // Reject http:// on non-loopback host even with loopback override.
    let remote_http = S3BlobConfig::new(
        "http://s3.example.com",
        "grdr-bucket",
        "us-east-1",
        S3Credentials::new("ak", "sk"),
    )
    .with_allow_insecure_loopback_http();
    assert_eq!(
        S3BlobStore::connect(remote_http).unwrap_err().code,
        CODE_BLOB_IO
    );

    // Reject http:// when RequireTls is active.
    let local_http_strict = S3BlobConfig::new(
        "http://127.0.0.1:9000",
        "grdr-bucket",
        "us-east-1",
        S3Credentials::new("ak", "sk"),
    );
    assert_eq!(
        S3BlobStore::connect(local_http_strict).unwrap_err().code,
        CODE_BLOB_IO
    );

    // Untrusted CA fails TLS handshake cleanly.
    let srv = spawn_mock_s3(true, false, false, "AK", "SK").unwrap();
    let untrusted_store = S3BlobStore::connect(
        S3BlobConfig::new(
            format!("https://{}", srv.addr),
            "grdr-bucket",
            "us-east-1",
            S3Credentials::new("AK", "SK"),
        )
        .with_timeouts_ms(1_000, 1_500),
    )
    .unwrap();
    let org = OrgId::new("org-adv").unwrap();
    let ctx = SingleCtx::new(org);
    let path = TenantPath::parse(&ctx, "test/fail.bin").unwrap();
    let tls_err = untrusted_store.put(&ctx, &path, b"data").unwrap_err();
    assert_eq!(tls_err.code, CODE_BLOB_IO);

    // Wrong SigV4 secret fails 403, and unversioned bucket fails require_versioned_conformance.
    let bad_sig_store = S3BlobStore::connect(
        S3BlobConfig::new(
            format!("https://{}", srv.addr),
            "grdr-bucket",
            "us-east-1",
            S3Credentials::new("AK", "WRONG-SECRET"),
        )
        .with_ca_cert_pem(srv.ca_pem.clone()),
    )
    .unwrap();
    assert_eq!(
        bad_sig_store.put(&ctx, &path, b"data").unwrap_err().code,
        CODE_BLOB_IO
    );

    let unversioned_store = S3BlobStore::connect(
        S3BlobConfig::new(
            format!("https://{}", srv.addr),
            "grdr-bucket",
            "us-east-1",
            S3Credentials::new("AK", "SK"),
        )
        .with_ca_cert_pem(srv.ca_pem.clone())
        .with_lifecycle_mode(S3LifecycleMode::ServerManaged)
        .with_addressing(S3AddressingStyle::PathStyle),
    )
    .unwrap();
    assert_eq!(
        unversioned_store
            .require_versioned_conformance()
            .unwrap_err()
            .code,
        CODE_BLOB_IO
    );

    // Reject URL userinfo/query/fragment, bad SigV4 scope chars, and empty/quoted IfMatch.
    for bad_endpoint in [
        "https://user:pass@s3.internal",
        "https://s3.internal?q=1",
        "https://s3.internal#frag",
    ] {
        let cfg = S3BlobConfig::new(
            bad_endpoint,
            "grdr-bucket",
            "us-east-1",
            S3Credentials::new("AK", "SK"),
        );
        assert!(S3BlobStore::connect(cfg).is_err());
    }
    let bad_region = S3BlobConfig::new(
        format!("https://{}", srv.addr),
        "grdr-bucket",
        "us-east-1/evil",
        S3Credentials::new("AK", "SK"),
    );
    assert!(S3BlobStore::connect(bad_region).is_err());
    let bad_ak = S3BlobConfig::new(
        format!("https://{}", srv.addr),
        "grdr-bucket",
        "us-east-1",
        S3Credentials::new("AK=evil", "SK"),
    );
    assert!(S3BlobStore::connect(bad_ak).is_err());

    let clean_store = S3BlobStore::connect(
        S3BlobConfig::new(
            format!("https://{}", srv.addr),
            "grdr-bucket",
            "us-east-1",
            S3Credentials::new("AK", "SK"),
        )
        .with_ca_cert_pem(srv.ca_pem.clone()),
    )
    .unwrap();
    for bad_etag in ["", "   ", "etag\"with\"quote"] {
        assert_eq!(
            clean_store
                .put_versioned(
                    &ctx,
                    &path,
                    b"x",
                    &grdr_ports::BlobVersionCondition::IfMatch(bad_etag.into()),
                )
                .unwrap_err()
                .code,
            CODE_BLOB_IO
        );
    }
}
