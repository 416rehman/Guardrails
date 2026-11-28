// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use grdr_model::CodedError;

use crate::config::{CODE_NATS_WIRE, NatsAuthConfig, NatsTlsHandshake, parse_validated_nats_url};
use crate::tls::{NatsStream, NatsTlsContext, wrap_nats_tls};
use crate::wire_codec::{
    NatsInboundFrame, NatsInboundMessage, NatsServerInfo, encode_connect_with_auth, encode_pub_cmd,
    nats_frame_err, parse_nats_headers,
};
pub use crate::wire_codec::{
    NatsWireState, encode_connect_cmd, encode_hpub_cmd, encode_stream_create_payload,
    jetstream_stream_create_subject, jetstream_stream_purge_subject,
};

const MAX_NATS_LINE_BYTES: usize = 64 * 1024;
const MAX_NATS_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_REPLY_FRAMES: usize = 4_096;

#[derive(Debug, Clone)]
pub(crate) struct NatsWireOptions<'a> {
    pub(crate) client_name: &'a str,
    pub(crate) timeout_ms: u32,
    pub(crate) tls_ca_pem: Option<&'a str>,
    pub(crate) tls_handshake: NatsTlsHandshake,
    pub(crate) auth: Option<&'a NatsAuthConfig>,
}

#[derive(Debug)]
pub(crate) struct NatsWireConnection {
    stream: NatsStream,
    read_buf: Vec<u8>,
    info: NatsServerInfo,
    next_sid: u64,
}

impl NatsWireConnection {
    pub(crate) fn connect(
        server_url: &str,
        opts: &NatsWireOptions<'_>,
    ) -> Result<Self, CodedError> {
        let (is_tls_scheme, hostport) = parse_validated_nats_url(server_url)?;
        let timeout = Duration::from_millis(u64::from(opts.timeout_ms.max(100)));
        let tcp = connect_tcp_with_timeout(&hostport, timeout, server_url)?;
        tcp.set_read_timeout(Some(timeout)).map_err(nats_io_err)?;
        tcp.set_write_timeout(Some(timeout)).map_err(nats_io_err)?;

        let tls_ctx = NatsTlsContext::build(&hostport, opts.tls_ca_pem)?;
        let initial_stream = if is_tls_scheme && opts.tls_handshake == NatsTlsHandshake::TlsFirst {
            wrap_nats_tls(tcp, &tls_ctx)?
        } else {
            NatsStream::Plain(tcp)
        };

        let mut conn = Self {
            stream: initial_stream,
            read_buf: Vec::new(),
            info: NatsServerInfo::default(),
            next_sid: 1,
        };

        let info_line = conn.read_line()?;
        let info_json = info_line.strip_prefix("INFO ").ok_or_else(|| {
            CodedError::new(
                CODE_NATS_WIRE,
                format!("Expected NATS INFO handshake, got `{}`.", info_line.trim()),
                "Verify NATS server protocol compatibility.",
            )
        })?;
        conn.info = serde_json::from_str(info_json.trim()).map_err(|e| {
            CodedError::new(
                CODE_NATS_WIRE,
                format!("Invalid NATS INFO JSON payload: {e}"),
                "Verify NATS server protocol compatibility.",
            )
        })?;

        if (is_tls_scheme || conn.info.tls_required == Some(true)) && !conn.stream.is_tls() {
            conn.upgrade_to_tls(&tls_ctx)?;
        }

        let connect_cmd = encode_connect_with_auth(
            opts.client_name,
            conn.stream.is_tls() || is_tls_scheme,
            &conn.info,
            opts.auth,
        )?;
        conn.write_all_flushed(connect_cmd.as_bytes())?;

        let verify_handshake_now = conn.stream.is_tls()
            || conn.info.jetstream == Some(true)
            || conn.info.auth_required == Some(true)
            || opts.auth.is_some();
        if verify_handshake_now {
            conn.ping_pong()?;
        }

        Ok(conn)
    }

    pub(crate) fn is_jetstream(&self) -> bool {
        self.info.jetstream == Some(true)
    }

    pub(crate) fn next_sid(&mut self) -> String {
        let sid = self.next_sid;
        self.next_sid = self.next_sid.saturating_add(1);
        sid.to_string()
    }

    pub(crate) fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), CodedError> {
        self.stream.write_all(bytes).map_err(nats_io_err)
    }

    pub(crate) fn flush(&mut self) -> Result<(), CodedError> {
        self.stream.flush().map_err(nats_io_err)
    }

    pub(crate) fn write_all_flushed(&mut self, bytes: &[u8]) -> Result<(), CodedError> {
        self.write_bytes(bytes)?;
        self.flush()
    }

    pub(crate) fn ping_pong(&mut self) -> Result<(), CodedError> {
        self.write_all_flushed(b"PING\r\n")?;
        for _ in 0..MAX_REPLY_FRAMES {
            match self.read_frame()? {
                NatsInboundFrame::Pong => return Ok(()),
                NatsInboundFrame::Ok => continue,
                NatsInboundFrame::Ping => {
                    self.write_all_flushed(b"PONG\r\n")?;
                }
                NatsInboundFrame::Err(err) => {
                    return Err(CodedError::new(
                        CODE_NATS_WIRE,
                        format!("NATS server rejected command: {err}"),
                        "Verify NATS TLS, NKey/JWT credentials, and permissions.",
                    ));
                }
                NatsInboundFrame::Msg(msg) => {
                    return Err(CodedError::new(
                        CODE_NATS_WIRE,
                        format!(
                            "Unexpected NATS MSG on `{}` while awaiting PONG.",
                            msg.subject
                        ),
                        "Verify NATS protocol framing synchronization.",
                    ));
                }
            }
        }
        Err(CodedError::new(
            CODE_NATS_WIRE,
            "NATS server exceeded maximum reply frames without PONG.",
            "Inspect NATS server health.",
        ))
    }

    pub(crate) fn drain_until_pong(&mut self, discard_sid: &str) -> Result<(), CodedError> {
        self.write_all_flushed(b"PING\r\n")?;
        for _ in 0..MAX_REPLY_FRAMES {
            match self.read_frame()? {
                NatsInboundFrame::Pong => return Ok(()),
                NatsInboundFrame::Ok => continue,
                NatsInboundFrame::Ping => {
                    self.write_all_flushed(b"PONG\r\n")?;
                }
                NatsInboundFrame::Err(err) => {
                    return Err(CodedError::new(
                        CODE_NATS_WIRE,
                        format!("NATS server rejected drain command: {err}"),
                        "Inspect NATS JetStream protocol synchronization.",
                    ));
                }
                NatsInboundFrame::Msg(msg) if msg.sid == discard_sid => continue,
                NatsInboundFrame::Msg(msg) => {
                    return Err(CodedError::new(
                        CODE_NATS_WIRE,
                        format!(
                            "Unexpected NATS MSG sid `{}` while draining `{discard_sid}`.",
                            msg.sid
                        ),
                        "Verify NATS protocol framing synchronization.",
                    ));
                }
            }
        }
        Err(CodedError::new(
            CODE_NATS_WIRE,
            "NATS server exceeded maximum frames while draining unsubscribed pull.",
            "Inspect NATS server health.",
        ))
    }

    pub(crate) fn request(
        &mut self,
        subject: &str,
        payload: &[u8],
    ) -> Result<NatsInboundMessage, CodedError> {
        let sid = self.next_sid();
        let inbox = format!("_INBOX.grdr.{sid}");
        let sub_cmd = format!("SUB {inbox} {sid}\r\nUNSUB {sid} 1\r\n");
        self.write_bytes(sub_cmd.as_bytes())?;
        let pub_cmd = encode_pub_cmd(subject, Some(&inbox), payload)?;
        self.write_all_flushed(&pub_cmd)?;

        for _ in 0..MAX_REPLY_FRAMES {
            match self.read_frame()? {
                NatsInboundFrame::Ok => continue,
                NatsInboundFrame::Ping => {
                    self.write_all_flushed(b"PONG\r\n")?;
                }
                NatsInboundFrame::Pong => continue,
                NatsInboundFrame::Err(err) => {
                    return Err(CodedError::new(
                        CODE_NATS_WIRE,
                        format!("NATS server error on request `{subject}`: {err}"),
                        "Inspect JetStream permissions and subject configuration.",
                    ));
                }
                NatsInboundFrame::Msg(msg) => {
                    if msg.sid == sid {
                        if msg.status_code == Some(503) {
                            return Err(CodedError::new(
                                CODE_NATS_WIRE,
                                format!("NATS JetStream no responders on `{subject}`."),
                                "Verify JetStream is enabled on the NATS cluster.",
                            ));
                        }
                        return Ok(msg);
                    }
                }
            }
        }
        Err(CodedError::new(
            CODE_NATS_WIRE,
            format!("Timed out reading NATS response on `{subject}`."),
            "Inspect NATS JetStream cluster responsiveness.",
        ))
    }

    pub(crate) fn read_frame(&mut self) -> Result<NatsInboundFrame, CodedError> {
        let line = self.read_line()?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "PONG" {
            return Ok(NatsInboundFrame::Pong);
        }
        if trimmed == "PING" {
            return Ok(NatsInboundFrame::Ping);
        }
        if trimmed == "+OK" {
            return Ok(NatsInboundFrame::Ok);
        }
        if let Some(err) = trimmed.strip_prefix("-ERR") {
            return Ok(NatsInboundFrame::Err(err.trim().to_string()));
        }
        if let Some(rest) = trimmed.strip_prefix("MSG ") {
            return self.read_msg_payload(rest).map(NatsInboundFrame::Msg);
        }
        if let Some(rest) = trimmed.strip_prefix("HMSG ") {
            return self.read_hmsg_payload(rest).map(NatsInboundFrame::Msg);
        }
        Err(CodedError::new(
            CODE_NATS_WIRE,
            format!("Unexpected NATS protocol frame `{trimmed}`."),
            "Verify NATS JetStream wire protocol compatibility.",
        ))
    }

    pub(crate) fn close(mut self) {
        self.stream.shutdown();
    }

    fn upgrade_to_tls(&mut self, ctx: &NatsTlsContext) -> Result<(), CodedError> {
        if !self.read_buf.is_empty() {
            return Err(CodedError::new(
                CODE_NATS_WIRE,
                "Unexpected trailing plaintext bytes before NATS TLS upgrade.",
                "Reject mixed plaintext and TLS handshake framing.",
            ));
        }
        let prev = std::mem::replace(&mut self.stream, NatsStream::Closed);
        match prev {
            NatsStream::Plain(tcp) => {
                self.stream = wrap_nats_tls(tcp, ctx)?;
                Ok(())
            }
            NatsStream::Tls(s) => {
                self.stream = NatsStream::Tls(s);
                Ok(())
            }
            NatsStream::Closed => Err(nats_frame_err("closed NATS stream before TLS upgrade")),
        }
    }

    fn read_line(&mut self) -> Result<String, CodedError> {
        loop {
            if let Some(nl_pos) = self.read_buf.iter().position(|&b| b == b'\n') {
                let end = nl_pos.saturating_add(1);
                let line_bytes: Vec<u8> = self.read_buf.drain(..end).collect();
                return String::from_utf8(line_bytes).map_err(|e| {
                    CodedError::new(
                        CODE_NATS_WIRE,
                        format!("Non-UTF-8 NATS wire line: {e}"),
                        "Inspect NATS server encoding.",
                    )
                });
            }
            if self.read_buf.len() >= MAX_NATS_LINE_BYTES {
                return Err(CodedError::new(
                    CODE_NATS_WIRE,
                    "NATS server wire line exceeded maximum frame length.",
                    "Verify NATS server protocol health.",
                ));
            }
            let mut chunk = [0u8; 4_096];
            let n = self.stream.read(&mut chunk).map_err(nats_io_err)?;
            if n == 0 {
                return Err(CodedError::new(
                    CODE_NATS_WIRE,
                    "Unexpected EOF reading NATS wire frame.",
                    "Verify NATS server stayed connected through handshake.",
                ));
            }
            if let Some(slice) = chunk.get(..n) {
                self.read_buf.extend_from_slice(slice);
            }
        }
    }

    fn read_exact_bytes(&mut self, len: usize) -> Result<Vec<u8>, CodedError> {
        if len > MAX_NATS_PAYLOAD_BYTES {
            return Err(CodedError::new(
                CODE_NATS_WIRE,
                format!("NATS payload length {len} exceeds limit."),
                "Reject oversized NATS message frame.",
            ));
        }
        while self.read_buf.len() < len {
            let need = len.saturating_sub(self.read_buf.len()).clamp(64, 16_384);
            let mut chunk = vec![0u8; need];
            let n = self.stream.read(&mut chunk).map_err(nats_io_err)?;
            if n == 0 {
                return Err(CodedError::new(
                    CODE_NATS_WIRE,
                    "Unexpected EOF reading NATS payload bytes.",
                    "Check NATS stream connectivity.",
                ));
            }
            if let Some(slice) = chunk.get(..n) {
                self.read_buf.extend_from_slice(slice);
            }
        }
        Ok(self.read_buf.drain(..len).collect())
    }

    fn read_msg_payload(&mut self, args: &str) -> Result<NatsInboundMessage, CodedError> {
        let parts: Vec<&str> = args.split_whitespace().collect();
        let (subject, sid, reply_to, len_str) = match parts.as_slice() {
            [subj, sid, len_s] => (*subj, *sid, None, *len_s),
            [subj, sid, reply, len_s] => (*subj, *sid, Some((*reply).to_string()), *len_s),
            _ => return Err(nats_frame_err("malformed MSG header")),
        };
        let len = len_str
            .parse::<usize>()
            .map_err(|_| nats_frame_err("invalid MSG payload length"))?;
        let payload = self.read_exact_bytes(len)?;
        let crlf = self.read_exact_bytes(2)?;
        if crlf != b"\r\n" {
            return Err(nats_frame_err("MSG missing CRLF terminator"));
        }
        Ok(NatsInboundMessage {
            subject: subject.to_string(),
            sid: sid.to_string(),
            reply_to,
            status_code: None,
            headers: BTreeMap::new(),
            payload,
        })
    }

    fn read_hmsg_payload(&mut self, args: &str) -> Result<NatsInboundMessage, CodedError> {
        let parts: Vec<&str> = args.split_whitespace().collect();
        let (subject, sid, reply_to, hdr_str, tot_str) = match parts.as_slice() {
            [subj, sid, hdr_s, tot_s] => (*subj, *sid, None, *hdr_s, *tot_s),
            [subj, sid, reply, hdr_s, tot_s] => {
                (*subj, *sid, Some((*reply).to_string()), *hdr_s, *tot_s)
            }
            _ => return Err(nats_frame_err("malformed HMSG header")),
        };
        let hdr_len = hdr_str
            .parse::<usize>()
            .map_err(|_| nats_frame_err("HMSG header length"))?;
        let total_len = tot_str
            .parse::<usize>()
            .map_err(|_| nats_frame_err("HMSG total length"))?;
        if hdr_len > total_len {
            return Err(nats_frame_err("HMSG header_len > total_len"));
        }
        let body = self.read_exact_bytes(total_len)?;
        let crlf = self.read_exact_bytes(2)?;
        if crlf != b"\r\n" {
            return Err(nats_frame_err("HMSG missing CRLF terminator"));
        }
        let hdr_bytes = body.get(..hdr_len).unwrap_or(&[]);
        let payload = body.get(hdr_len..).unwrap_or(&[]).to_vec();
        let (status_code, headers) = parse_nats_headers(hdr_bytes)?;
        Ok(NatsInboundMessage {
            subject: subject.to_string(),
            sid: sid.to_string(),
            reply_to,
            status_code,
            headers,
            payload,
        })
    }
}

pub fn publish_batch_wire(
    server_url: &str,
    client_name: &str,
    timeout_ms: u32,
    frames: &[Vec<u8>],
) -> Result<(), CodedError> {
    let opts = NatsWireOptions {
        client_name,
        timeout_ms,
        tls_ca_pem: None,
        tls_handshake: NatsTlsHandshake::TlsFirst,
        auth: None,
    };
    let mut conn = NatsWireConnection::connect(server_url, &opts)?;
    for frame in frames {
        conn.write_bytes(frame)?;
    }
    conn.ping_pong()?;
    conn.close();
    Ok(())
}

fn connect_tcp_with_timeout(
    hostport: &str,
    timeout: Duration,
    server_url: &str,
) -> Result<TcpStream, CodedError> {
    let addrs: Vec<_> = hostport
        .to_socket_addrs()
        .map_err(|e| {
            CodedError::new(
                CODE_NATS_WIRE,
                format!("Failed resolving NATS server `{server_url}`: {e}"),
                "Verify NATS JetStream hostname and port.",
            )
        })?
        .collect();
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(sock) => return Ok(sock),
            Err(err) => last_err = Some(err),
        }
    }
    let detail = last_err.map_or_else(|| "no resolved addresses".to_string(), |e| e.to_string());
    Err(CodedError::new(
        CODE_NATS_WIRE,
        format!("Failed connecting to NATS server `{server_url}`: {detail}"),
        "Verify NATS JetStream endpoint and network reachability.",
    ))
}

pub(crate) fn nats_io_err(err: std::io::Error) -> CodedError {
    CodedError::new(
        CODE_NATS_WIRE,
        format!("NATS wire I/O failed: {err}"),
        "Check NATS socket connection.",
    )
}
