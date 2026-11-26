// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Framed `grdr-wire` IPC host for networkless advisory evaluation.

use std::time::Duration;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use grdr_crypto::SigningKeypair;
use grdr_model::{SigningKeypairExt as _, TrustedKeyInfo};
use grdr_ports::Clock;
use grdr_schema::limits::load_embedded_limits;
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
const MAX_IPC_SKEW_SECS_CAP: i64 = 300;
const MAX_FRAME_READ_TIMEOUT_MS: u64 = 30_000;

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

/// Bridges `grdr_os_clock::SystemClock` into the workspace `grdr_ports::Clock` trait.
#[derive(Debug, Clone)]
pub struct OsClockAdapter(grdr_os_clock::SystemClock);

pub struct InferIpcHost<D> {
    detector: D,
    host_keypair: SigningKeypair,
    trusted_callers: Vec<TrustedKeyInfo>,
    replay_window: ReplayWindow,
    mac_key: SessionMacKey,
    max_frame_bytes: usize,
    frame_read_timeout_ms: u64,
}

impl OsClockAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self(grdr_os_clock::SystemClock::new())
    }
}

impl Default for OsClockAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for OsClockAdapter {
    fn now_timestamp(&self) -> Timestamp {
        match grdr_os_clock::Clock::now_wall(&self.0) {
            Ok(ts) => ts,
            Err(_) => Timestamp::UNIX_EPOCH,
        }
    }

    fn monotonic_ms(&self) -> u64 {
        grdr_os_clock::Clock::now_monotonic(&self.0).map_or(0, |instant| {
            instant.nanos.checked_div(1_000_000).unwrap_or(0)
        })
    }
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
        let limits = load_embedded_limits()
            .map_err(|e| InferError::Ipc(format!("failed to load embedded limits: {e}")))?;
        let max_skew_cap = i64::try_from(limits.server.ingest.max_skew_seconds.max(1))
            .unwrap_or(MAX_IPC_SKEW_SECS_CAP)
            .min(MAX_IPC_SKEW_SECS_CAP);
        let bounded_skew = max_skew_seconds.clamp(1, max_skew_cap);
        let min_frame = WIRE_HEADER_BYTES.saturating_add(1);
        let max_frame_bytes =
            MAX_FRAME_BYTES.min(limits.endpoint.ipc.max_frame_bytes.max(min_frame));
        let frame_read_timeout_ms = limits
            .endpoint
            .ipc
            .read_timeout_ms
            .clamp(1, MAX_FRAME_READ_TIMEOUT_MS);

        let mac_key = SessionMacKey::generate()?;
        Ok(Self {
            detector,
            host_keypair,
            trusted_callers,
            replay_window: ReplayWindow::new(4096, bounded_skew),
            mac_key,
            max_frame_bytes,
            frame_read_timeout_ms,
        })
    }

    #[must_use]
    pub fn host_public_info(&self) -> TrustedKeyInfo {
        self.host_keypair.public_info()
    }

    #[must_use]
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    #[must_use]
    pub const fn frame_read_timeout_ms(&self) -> u64 {
        self.frame_read_timeout_ms
    }

    pub fn set_frame_read_timeout_ms(&mut self, timeout_ms: u64) {
        self.frame_read_timeout_ms = timeout_ms.clamp(1, self.frame_read_timeout_ms.max(1));
    }

    pub async fn handle_frame_bytes(
        &mut self,
        frame_bytes: &[u8],
        now: Timestamp,
    ) -> Result<Vec<u8>, InferError> {
        if frame_bytes.len() > self.max_frame_bytes {
            return Err(InferError::Ipc(format!(
                "incoming frame length {} exceeds bound {}",
                frame_bytes.len(),
                self.max_frame_bytes
            )));
        }
        let (envelope, consumed) = decode_frame::<InferWireRequest>(frame_bytes)
            .map_err(|_| InferError::Ipc("malformed wire request frame".into()))?;
        if consumed != frame_bytes.len() {
            return Err(InferError::Ipc(
                "trailing bytes after decoded wire frame".into(),
            ));
        }
        self.replay_window
            .verify_and_record(&envelope, &self.trusted_callers, now)
            .map_err(|_| {
                InferError::Ipc("wire envelope authentication or replay check failed".into())
            })?;

        let signal = match self
            .mac_key
            .derive_request_key(&envelope.payload.session_id, &envelope.payload.request_id)
            .and_then(|req_key| {
                req_key
                    .seal_record(
                        &envelope.payload.record_id,
                        envelope.payload.data_class,
                        &envelope.payload.raw_content,
                    )
                    .map(|framed| (req_key, framed))
            }) {
            Ok((req_key, framed)) => {
                let budget_ms = if envelope.payload.max_latency_ms == 0 {
                    DEFAULT_INFER_TIMEOUT_MS
                } else {
                    envelope.payload.max_latency_ms
                };
                evaluate_framed_with_budget(
                    &self.detector,
                    &req_key,
                    &envelope.payload.record_id,
                    &framed,
                    budget_ms,
                )
                .await
            }
            Err(InferError::InvalidInput(_)) => {
                ModelAdvisorySignal::CouldNotLook(UnavailableReason::InputLimitExceeded)
            }
            Err(InferError::FrameTampered(_) | InferError::UngroundedQuote(_)) => {
                ModelAdvisorySignal::CouldNotLook(UnavailableReason::TamperedFrame)
            }
            Err(InferError::PermissiveOutputRejected(_)) => {
                ModelAdvisorySignal::CouldNotLook(UnavailableReason::PermissiveOutputRejected)
            }
            Err(InferError::Crypto(_)) => {
                ModelAdvisorySignal::CouldNotLook(UnavailableReason::ModelFault)
            }
            Err(InferError::Ipc(_)) => {
                ModelAdvisorySignal::CouldNotLook(UnavailableReason::MalformedOutput)
            }
        };

        let safe_request_id = if crate::framing::is_valid_scope_id(&envelope.payload.request_id) {
            envelope.payload.request_id
        } else {
            "invalid-request-id".to_owned()
        };
        let response = InferWireResponse {
            request_id: safe_request_id,
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
        clock: &dyn Clock,
    ) -> Result<(), InferError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            let mut first = [0_u8; 1];
            match reader.read_exact(&mut first).await {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(InferError::Ipc(err.to_string())),
            }
            let mut hdr = [0_u8; WIRE_HEADER_BYTES];
            let (first_slot, rest_hdr) = hdr.split_at_mut(1);
            first_slot.copy_from_slice(&first);
            read_exact_bounded(&mut reader, rest_hdr, self.frame_read_timeout_ms).await?;

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
            let total_len = WIRE_HEADER_BYTES
                .checked_add(payload_len)
                .ok_or_else(|| InferError::Ipc("incoming frame length overflows usize".into()))?;
            if payload_len == 0 || total_len > self.max_frame_bytes {
                return Err(InferError::Ipc(format!(
                    "invalid incoming frame length {payload_len}"
                )));
            }
            let mut frame = vec![0_u8; total_len];
            let (prefix, body) = frame.split_at_mut(WIRE_HEADER_BYTES);
            prefix.copy_from_slice(&hdr);
            read_exact_bounded(&mut reader, body, self.frame_read_timeout_ms).await?;

            let now = clock.now_timestamp();
            let response_frame = self.handle_frame_bytes(&frame, now).await?;
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

async fn read_exact_bounded<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    timeout_ms: u64,
) -> Result<(), InferError> {
    match tokio::time::timeout(Duration::from_millis(timeout_ms), reader.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(InferError::Ipc(format!("frame read error: {err}"))),
        Err(_) => Err(InferError::Ipc("frame read timed out".into())),
    }
}
