// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Signed `grdr-wire` transport with Ed25519 signature, nonce replay-window, and skew checks.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use grdr_crypto::SigningKeypair;
use grdr_model::TrustedKeyInfo;
use grdr_wire::{
    MAX_FRAME_BYTES, ReplayWindow, WireEnvelope, WireError, decode_frame, encode_frame,
    generate_nonce, sign_envelope,
};

use crate::adapters::{AcpProtocolDialect, evaluate_dialect_request};
use crate::{AcpError, DecisionClient};

const WIRE_HEADER_BYTES: usize = 10;
const WIRE_MAGIC: [u8; 4] = *b"GRDR";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpWireRequest {
    pub dialect: AcpProtocolDialect,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpWireResponse {
    pub dialect: AcpProtocolDialect,
    pub accepted: bool,
    pub error_code: Option<String>,
    pub body: Value,
}

pub struct AcpWireServer<C> {
    host_keypair: SigningKeypair,
    trusted_peers: Vec<TrustedKeyInfo>,
    replay_window: ReplayWindow,
    client: C,
}

impl<C: DecisionClient> AcpWireServer<C> {
    #[must_use]
    pub fn new(
        host_keypair: SigningKeypair,
        trusted_peers: Vec<TrustedKeyInfo>,
        max_skew_seconds: i64,
        client: C,
    ) -> Self {
        Self {
            host_keypair,
            trusted_peers,
            replay_window: ReplayWindow::new(4096, max_skew_seconds.max(1)),
            client,
        }
    }

    #[must_use]
    pub fn host_public_info(&self) -> TrustedKeyInfo {
        self.host_keypair.public_info()
    }

    pub fn verify_incoming_envelope(
        &mut self,
        envelope: &WireEnvelope<AcpWireRequest>,
        now: Timestamp,
    ) -> Result<(), AcpError> {
        self.replay_window
            .verify_and_record(envelope, &self.trusted_peers, now)
            .map_err(map_wire_error)
    }

    pub async fn handle_frame_bytes(
        &mut self,
        frame_bytes: &[u8],
        now: Timestamp,
    ) -> Result<Vec<u8>, AcpError> {
        let (envelope, consumed) = decode_frame::<AcpWireRequest>(frame_bytes)
            .map_err(|e| AcpError::Transport(e.to_string()))?;
        if consumed != frame_bytes.len() {
            return Err(AcpError::Transport(
                "trailing bytes after decoded wire frame".into(),
            ));
        }

        self.verify_incoming_envelope(&envelope, now)?;

        let response_body = evaluate_dialect_request(
            envelope.payload.dialect,
            &envelope.payload.body,
            &self.client,
            now,
        )
        .await;

        let accepted = matches!(
            response_body.get("verdict").and_then(Value::as_str),
            Some("allow")
        ) || matches!(
            response_body.get("decision").and_then(Value::as_str),
            Some("approve")
        );

        let wire_resp = AcpWireResponse {
            dialect: envelope.payload.dialect,
            accepted,
            error_code: None,
            body: response_body,
        };
        let nonce = generate_nonce().map_err(|e| AcpError::Transport(e.to_string()))?;
        let signed = sign_envelope(&self.host_keypair, nonce, now, wire_resp)
            .map_err(|e| AcpError::Transport(e.to_string()))?;
        encode_frame(&signed).map_err(|e| AcpError::Transport(e.to_string()))
    }

    pub async fn serve_stream<R, W>(&mut self, mut reader: R, mut writer: W) -> Result<(), AcpError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            let mut hdr = [0_u8; WIRE_HEADER_BYTES];
            match reader.read_exact(&mut hdr).await {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(AcpError::Transport(err.to_string())),
            }
            let magic = hdr.get(0..4).unwrap_or(&[]);
            if magic != WIRE_MAGIC {
                return Err(AcpError::Transport("invalid wire magic header".into()));
            }
            let (Some(&v0), Some(&v1)) = (hdr.get(4), hdr.get(5)) else {
                return Err(AcpError::Transport("truncated wire version".into()));
            };
            let version = u16::from_be_bytes([v0, v1]);
            if version != grdr_wire::WIRE_PROTOCOL_VERSION {
                return Err(AcpError::SignatureInvalid(format!(
                    "unsupported wire version {version}"
                )));
            }
            let (Some(&l0), Some(&l1), Some(&l2), Some(&l3)) =
                (hdr.get(6), hdr.get(7), hdr.get(8), hdr.get(9))
            else {
                return Err(AcpError::Transport("truncated wire payload length".into()));
            };
            let payload_len = usize::try_from(u32::from_be_bytes([l0, l1, l2, l3]))
                .map_err(|_| AcpError::Transport("incoming frame length overflows usize".into()))?;
            if payload_len == 0 || payload_len > MAX_FRAME_BYTES {
                return Err(AcpError::Transport(format!(
                    "invalid incoming frame length {payload_len}"
                )));
            }
            let mut frame = vec![0_u8; WIRE_HEADER_BYTES.saturating_add(payload_len)];
            let (prefix, body) = frame.split_at_mut(WIRE_HEADER_BYTES);
            prefix.copy_from_slice(&hdr);
            reader
                .read_exact(body)
                .await
                .map_err(|e| AcpError::Transport(e.to_string()))?;

            let response_frame = self.handle_frame_bytes(&frame, Timestamp::now()).await?;
            writer
                .write_all(&response_frame)
                .await
                .map_err(|e| AcpError::Transport(e.to_string()))?;
            writer
                .flush()
                .await
                .map_err(|e| AcpError::Transport(e.to_string()))?;
        }
    }
}

fn map_wire_error(err: WireError) -> AcpError {
    match err {
        WireError::ReplayDetected { .. } | WireError::ExpiredTimestamp => {
            AcpError::ReplayOrSkew(err.to_string())
        }
        WireError::Crypto(_) | WireError::UnsupportedVersion(_) => {
            AcpError::SignatureInvalid(err.to_string())
        }
        WireError::FrameTooLarge { .. }
        | WireError::TruncatedFrame { .. }
        | WireError::InvalidMagic
        | WireError::Codec(_) => AcpError::Transport(err.to_string()),
    }
}
