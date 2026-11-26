// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Framed `grdr-wire` IPC host for networkless advisory evaluation.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use grdr_crypto::SigningKeypair;
use grdr_model::{SigningKeypairExt as _, TrustedKeyInfo};
use grdr_wire::{
    MAX_FRAME_BYTES, ReplayWindow, WireEnvelope, decode_frame, encode_frame, generate_nonce,
    sign_envelope,
};

use crate::InferError;
use crate::advisory::{ModelAdvisorySignal, UnavailableReason};
use crate::detector::{
    DEFAULT_INFER_TIMEOUT_MS, DetectorAdapter, HeuristicJudgeDetector, evaluate_framed_with_budget,
};
use crate::framing::{FramedDataClass, SessionMacKey};

const WIRE_HEADER_BYTES: usize = 10;
const WIRE_MAGIC: [u8; 4] = *b"GRDR";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferWireRequest {
    pub request_id: String,
    pub record_id: String,
    pub session_id: String,
    pub data_class: FramedDataClass,
    pub raw_content: String,
    pub max_latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferWireResponse {
    pub request_id: String,
    pub signal: ModelAdvisorySignal,
}

pub struct InferIpcHost<D> {
    detector: D,
    host_keypair: SigningKeypair,
    trusted_callers: Vec<TrustedKeyInfo>,
    replay_window: ReplayWindow,
    mac_key: SessionMacKey,
}

impl InferIpcHost<HeuristicJudgeDetector> {
    pub fn with_default_detector(
        host_keypair: SigningKeypair,
        trusted_callers: Vec<TrustedKeyInfo>,
        max_skew_seconds: i64,
    ) -> Result<Self, InferError> {
        Self::new(
            HeuristicJudgeDetector,
            host_keypair,
            trusted_callers,
            max_skew_seconds,
        )
    }
}

impl<D: DetectorAdapter> InferIpcHost<D> {
    pub fn new(
        detector: D,
        host_keypair: SigningKeypair,
        trusted_callers: Vec<TrustedKeyInfo>,
        max_skew_seconds: i64,
    ) -> Result<Self, InferError> {
        let mac_key = SessionMacKey::generate()?;
        Ok(Self {
            detector,
            host_keypair,
            trusted_callers,
            replay_window: ReplayWindow::new(4096, max_skew_seconds.max(1)),
            mac_key,
        })
    }

    #[must_use]
    pub fn host_public_info(&self) -> TrustedKeyInfo {
        self.host_keypair.public_info()
    }

    pub async fn handle_frame_bytes(
        &mut self,
        frame_bytes: &[u8],
        now: Timestamp,
    ) -> Result<Vec<u8>, InferError> {
        let (envelope, consumed) = decode_frame::<InferWireRequest>(frame_bytes)
            .map_err(|e| InferError::Ipc(e.to_string()))?;
        if consumed != frame_bytes.len() {
            return Err(InferError::Ipc(
                "trailing bytes after decoded wire frame".into(),
            ));
        }
        self.replay_window
            .verify_and_record(&envelope, &self.trusted_callers, now)
            .map_err(|e| InferError::Ipc(e.to_string()))?;

        let signal = match self.mac_key.seal_record(
            &envelope.payload.record_id,
            envelope.payload.data_class,
            &envelope.payload.raw_content,
        ) {
            Ok(framed) => {
                let budget_ms = if envelope.payload.max_latency_ms == 0 {
                    DEFAULT_INFER_TIMEOUT_MS
                } else {
                    envelope.payload.max_latency_ms
                };
                evaluate_framed_with_budget(
                    &self.detector,
                    &self.mac_key,
                    &envelope.payload.record_id,
                    &framed,
                    budget_ms,
                )
                .await
            }
            Err(_) => ModelAdvisorySignal::CouldNotLook(UnavailableReason::MalformedOutput),
        };

        let response = InferWireResponse {
            request_id: envelope.payload.request_id,
            signal,
        };
        let nonce = generate_nonce().map_err(|e| InferError::Ipc(e.to_string()))?;
        let signed: WireEnvelope<InferWireResponse> =
            sign_envelope(&self.host_keypair, nonce, now, response)
                .map_err(|e| InferError::Ipc(e.to_string()))?;
        encode_frame(&signed).map_err(|e| InferError::Ipc(e.to_string()))
    }

    pub async fn serve_stream<R, W>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> Result<(), InferError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            let mut hdr = [0_u8; WIRE_HEADER_BYTES];
            match reader.read_exact(&mut hdr).await {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(InferError::Ipc(err.to_string())),
            }
            let magic = hdr.get(0..4).unwrap_or(&[]);
            if magic != WIRE_MAGIC {
                return Err(InferError::Ipc("invalid wire magic header".into()));
            }
            let (Some(&v0), Some(&v1)) = (hdr.get(4), hdr.get(5)) else {
                return Err(InferError::Ipc("truncated wire version".into()));
            };
            let version = u16::from_be_bytes([v0, v1]);
            if version != grdr_wire::WIRE_PROTOCOL_VERSION {
                return Err(InferError::Ipc(format!(
                    "unsupported wire version {version}"
                )));
            }
            let (Some(&l0), Some(&l1), Some(&l2), Some(&l3)) =
                (hdr.get(6), hdr.get(7), hdr.get(8), hdr.get(9))
            else {
                return Err(InferError::Ipc("truncated wire payload length".into()));
            };
            let payload_len = usize::try_from(u32::from_be_bytes([l0, l1, l2, l3]))
                .map_err(|_| InferError::Ipc("incoming frame length overflows usize".into()))?;
            if payload_len == 0 || payload_len > MAX_FRAME_BYTES {
                return Err(InferError::Ipc(format!(
                    "invalid incoming frame length {payload_len}"
                )));
            }
            let mut frame = vec![0_u8; WIRE_HEADER_BYTES.saturating_add(payload_len)];
            let (prefix, body) = frame.split_at_mut(WIRE_HEADER_BYTES);
            prefix.copy_from_slice(&hdr);
            reader
                .read_exact(body)
                .await
                .map_err(|e| InferError::Ipc(e.to_string()))?;

            let response_frame = self.handle_frame_bytes(&frame, Timestamp::now()).await?;
            writer
                .write_all(&response_frame)
                .await
                .map_err(|e| InferError::Ipc(e.to_string()))?;
            writer
                .flush()
                .await
                .map_err(|e| InferError::Ipc(e.to_string()))?;
        }
    }
}
