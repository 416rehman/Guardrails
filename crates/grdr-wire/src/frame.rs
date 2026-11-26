// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Bounded protobuf `WireFrame` codec and credit flow controller (`docs/design/11`).

use prost::Message;
use thiserror::Error;

use crate::limits::embedded_limits;
use crate::messages::{
    BundleLoadFrame, CreditGrantFrame, DecideAckFrame, DecideRequestFrame, DecideVerdictFrame,
    EngineForwardFrame, EngineResultFrame, ErrorFrame, HeartbeatFrame, HelloFrame,
    LocalRequestFrame, LocalResponseFrame, ReadyFrame, UpdaterCommandFrame, UpdaterEventFrame,
    UplinkCommandFrame, UplinkEventFrame,
};

pub const IPC_WIRE_VERSION: u32 = 1;
pub const IPC_FRAME_HEADER_LEN: usize = 4;
pub const DEFAULT_INITIAL_CREDIT: u32 = 64;
pub const MAX_CREDIT_WINDOW: u32 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpcFrameError {
    #[error("GRDR-WIRE-0009: failed loading embedded IPC frame limit: {detail}")]
    LimitsUnavailable { detail: String },
    #[error("GRDR-WIRE-0010: IPC frame length {len} exceeds maximum {max} bytes")]
    FrameTooLarge { len: usize, max: usize },
    #[error("GRDR-WIRE-0011: truncated IPC frame (expected {expected} bytes, have {available})")]
    TruncatedFrame { expected: usize, available: usize },
    #[error("GRDR-WIRE-0012: zero-length IPC frame is not permitted")]
    ZeroLengthFrame,
    #[error("GRDR-WIRE-0013: invalid protobuf frame payload: {detail}")]
    InvalidProtobuf { detail: String },
    #[error("GRDR-WIRE-0014: IPC wire frame has no payload variant")]
    EmptyPayload,
    #[error(
        "GRDR-WIRE-0015: outbound IPC credit exhausted (available {available}, required {required})"
    )]
    CreditExhausted { available: u32, required: u32 },
    #[error("GRDR-WIRE-0016: IPC credit window overflow")]
    CreditOverflow,
    #[error("GRDR-WIRE-0017: unsupported IPC protocol version {found}, expected {expected}")]
    InvalidProtocolVersion { found: u32, expected: u32 },
    #[error("GRDR-WIRE-0036: clean end-of-stream before IPC frame header")]
    EndOfStream,
    #[error("GRDR-WIRE-0037: IPC frame operation timed out after {timeout_ms} ms")]
    TimedOut { timeout_ms: u64 },
    #[error("GRDR-WIRE-0038: IPC frame stream I/O error: {detail}")]
    Io { detail: String },
}

#[derive(Clone, PartialEq, Eq, prost::Oneof)]
pub enum WirePayload {
    #[prost(message, tag = "10")]
    Hello(HelloFrame),
    #[prost(message, tag = "11")]
    Ready(ReadyFrame),
    #[prost(message, tag = "12")]
    Heartbeat(HeartbeatFrame),
    #[prost(message, tag = "13")]
    CreditGrant(CreditGrantFrame),
    #[prost(message, tag = "14")]
    DecideRequest(DecideRequestFrame),
    #[prost(message, tag = "15")]
    DecideAck(DecideAckFrame),
    #[prost(message, tag = "16")]
    DecideVerdict(DecideVerdictFrame),
    #[prost(message, tag = "17")]
    LocalRequest(LocalRequestFrame),
    #[prost(message, tag = "18")]
    LocalResponse(LocalResponseFrame),
    #[prost(message, tag = "19")]
    EngineForward(EngineForwardFrame),
    #[prost(message, tag = "20")]
    EngineResult(EngineResultFrame),
    #[prost(message, tag = "21")]
    BundleLoad(BundleLoadFrame),
    #[prost(message, tag = "22")]
    UplinkCommand(UplinkCommandFrame),
    #[prost(message, tag = "23")]
    UplinkEvent(UplinkEventFrame),
    #[prost(message, tag = "24")]
    UpdaterCommand(UpdaterCommandFrame),
    #[prost(message, tag = "25")]
    UpdaterEvent(UpdaterEventFrame),
    #[prost(message, tag = "26")]
    Error(ErrorFrame),
}

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct WireFrame {
    #[prost(uint64, tag = "1")]
    pub stream_id: u64,
    #[prost(uint64, tag = "2")]
    pub seq: u64,
    #[prost(uint32, tag = "3")]
    pub credit_delta: u32,
    #[prost(
        oneof = "WirePayload",
        tags = "10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26"
    )]
    pub payload: Option<WirePayload>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreditFlow {
    outbound_available: u32,
    inbound_granted: u32,
    unblocked_sent: u64,
}

impl IpcFrameError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::LimitsUnavailable { .. } => "GRDR-WIRE-0009",
            Self::FrameTooLarge { .. } => "GRDR-WIRE-0010",
            Self::TruncatedFrame { .. } => "GRDR-WIRE-0011",
            Self::ZeroLengthFrame => "GRDR-WIRE-0012",
            Self::InvalidProtobuf { .. } => "GRDR-WIRE-0013",
            Self::EmptyPayload => "GRDR-WIRE-0014",
            Self::CreditExhausted { .. } => "GRDR-WIRE-0015",
            Self::CreditOverflow => "GRDR-WIRE-0016",
            Self::InvalidProtocolVersion { .. } => "GRDR-WIRE-0017",
            Self::EndOfStream => "GRDR-WIRE-0036",
            Self::TimedOut { .. } => "GRDR-WIRE-0037",
            Self::Io { .. } => "GRDR-WIRE-0038",
        }
    }
}

impl WireFrame {
    #[must_use]
    pub fn with_payload(stream_id: u64, seq: u64, payload: WirePayload) -> Self {
        Self {
            stream_id,
            seq,
            credit_delta: 0,
            payload: Some(payload),
        }
    }

    /// Decision path, heartbeat, handshake, credit grants, and error frames bypass credit gating.
    #[must_use]
    pub fn is_unblockable(&self) -> bool {
        matches!(
            self.payload,
            Some(
                WirePayload::Hello(_)
                    | WirePayload::Ready(_)
                    | WirePayload::Heartbeat(_)
                    | WirePayload::CreditGrant(_)
                    | WirePayload::DecideRequest(_)
                    | WirePayload::DecideAck(_)
                    | WirePayload::DecideVerdict(_)
                    | WirePayload::Error(_)
            )
        )
    }
}

impl CreditFlow {
    #[must_use]
    pub const fn new(initial_credit: u32) -> Self {
        let clamped = if initial_credit > MAX_CREDIT_WINDOW {
            MAX_CREDIT_WINDOW
        } else {
            initial_credit
        };
        Self {
            outbound_available: clamped,
            inbound_granted: clamped,
            unblocked_sent: 0,
        }
    }

    #[must_use]
    pub const fn outbound_available(&self) -> u32 {
        self.outbound_available
    }

    #[must_use]
    pub const fn inbound_granted(&self) -> u32 {
        self.inbound_granted
    }

    #[must_use]
    pub const fn unblocked_sent(&self) -> u64 {
        self.unblocked_sent
    }

    pub fn try_consume_send(&mut self, frame: &WireFrame) -> Result<(), IpcFrameError> {
        if frame.is_unblockable() {
            self.unblocked_sent = self.unblocked_sent.saturating_add(1);
            return Ok(());
        }
        let next =
            self.outbound_available
                .checked_sub(1)
                .ok_or(IpcFrameError::CreditExhausted {
                    available: self.outbound_available,
                    required: 1,
                })?;
        self.outbound_available = next;
        Ok(())
    }

    pub fn replenish_outbound(&mut self, delta: u32) -> Result<(), IpcFrameError> {
        let next = self
            .outbound_available
            .checked_add(delta)
            .ok_or(IpcFrameError::CreditOverflow)?;
        if next > MAX_CREDIT_WINDOW {
            return Err(IpcFrameError::CreditOverflow);
        }
        self.outbound_available = next;
        Ok(())
    }

    pub fn grant_inbound(&mut self, delta: u32) -> Result<u32, IpcFrameError> {
        if delta == 0 {
            return Err(IpcFrameError::InvalidProtobuf {
                detail: "inbound credit grant delta must be positive".to_string(),
            });
        }
        let next = self
            .inbound_granted
            .checked_add(delta)
            .ok_or(IpcFrameError::CreditOverflow)?;
        if next > MAX_CREDIT_WINDOW {
            return Err(IpcFrameError::CreditOverflow);
        }
        self.inbound_granted = next;
        Ok(delta)
    }

    #[must_use]
    pub const fn recommended_inbound_grant(&self) -> Option<u32> {
        let half = DEFAULT_INITIAL_CREDIT / 2;
        if self.inbound_granted <= half {
            Some(DEFAULT_INITIAL_CREDIT.saturating_sub(self.inbound_granted))
        } else {
            None
        }
    }

    pub fn record_inbound(&mut self, frame: &WireFrame) -> Result<(), IpcFrameError> {
        let next_inbound = if frame.is_unblockable() {
            self.inbound_granted
        } else {
            self.inbound_granted
                .checked_sub(1)
                .ok_or(IpcFrameError::CreditExhausted {
                    available: self.inbound_granted,
                    required: 1,
                })?
        };

        let delta = match &frame.payload {
            Some(WirePayload::CreditGrant(grant)) => {
                if frame.credit_delta > 0 {
                    return Err(IpcFrameError::InvalidProtobuf {
                        detail: "frame cannot combine credit_delta with CreditGrant".to_string(),
                    });
                }
                if grant.delta == 0 {
                    return Err(IpcFrameError::InvalidProtobuf {
                        detail: "CreditGrant delta must be > 0".to_string(),
                    });
                }
                grant.delta
            }
            _ => frame.credit_delta,
        };

        let next_outbound = self
            .outbound_available
            .checked_add(delta)
            .ok_or(IpcFrameError::CreditOverflow)?;
        if next_outbound > MAX_CREDIT_WINDOW {
            return Err(IpcFrameError::CreditOverflow);
        }

        self.outbound_available = next_outbound;
        self.inbound_granted = next_inbound;
        Ok(())
    }
}

pub fn embedded_max_frame_bytes() -> Result<usize, IpcFrameError> {
    Ok(embedded_limits()?.max_frame_bytes)
}

pub fn encode_proto_payload(
    frame: &WireFrame,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, IpcFrameError> {
    if max_frame_bytes == 0 {
        return Err(IpcFrameError::FrameTooLarge { len: 0, max: 0 });
    }
    if frame.payload.is_none() {
        return Err(IpcFrameError::EmptyPayload);
    }
    let payload = frame.encode_to_vec();
    if payload.is_empty() {
        return Err(IpcFrameError::ZeroLengthFrame);
    }
    if payload.len() > max_frame_bytes {
        return Err(IpcFrameError::FrameTooLarge {
            len: payload.len(),
            max: max_frame_bytes,
        });
    }
    Ok(payload)
}

pub fn encode_proto_frame(
    frame: &WireFrame,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, IpcFrameError> {
    let payload = encode_proto_payload(frame, max_frame_bytes)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| IpcFrameError::FrameTooLarge {
        len: payload.len(),
        max: max_frame_bytes,
    })?;
    let total_len =
        IPC_FRAME_HEADER_LEN
            .checked_add(payload.len())
            .ok_or(IpcFrameError::FrameTooLarge {
                len: payload.len(),
                max: max_frame_bytes,
            })?;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_proto_payload(
    payload: &[u8],
    max_frame_bytes: usize,
) -> Result<WireFrame, IpcFrameError> {
    if payload.is_empty() {
        return Err(IpcFrameError::ZeroLengthFrame);
    }
    if max_frame_bytes == 0 || payload.len() > max_frame_bytes {
        return Err(IpcFrameError::FrameTooLarge {
            len: payload.len(),
            max: max_frame_bytes,
        });
    }
    let frame = WireFrame::decode(payload).map_err(|err| IpcFrameError::InvalidProtobuf {
        detail: err.to_string(),
    })?;
    if frame.payload.is_none() {
        return Err(IpcFrameError::EmptyPayload);
    }
    Ok(frame)
}

pub fn decode_proto_frame(
    buf: &[u8],
    max_frame_bytes: usize,
) -> Result<(WireFrame, usize), IpcFrameError> {
    let Some(header_bytes) = buf.get(..IPC_FRAME_HEADER_LEN) else {
        return Err(IpcFrameError::TruncatedFrame {
            expected: IPC_FRAME_HEADER_LEN,
            available: buf.len(),
        });
    };
    let len_array: [u8; IPC_FRAME_HEADER_LEN] =
        header_bytes
            .try_into()
            .map_err(|_| IpcFrameError::TruncatedFrame {
                expected: IPC_FRAME_HEADER_LEN,
                available: buf.len(),
            })?;
    let payload_len = usize::try_from(u32::from_le_bytes(len_array)).map_err(|_| {
        IpcFrameError::FrameTooLarge {
            len: usize::MAX,
            max: max_frame_bytes,
        }
    })?;
    if payload_len == 0 {
        return Err(IpcFrameError::ZeroLengthFrame);
    }
    if max_frame_bytes == 0 || payload_len > max_frame_bytes {
        return Err(IpcFrameError::FrameTooLarge {
            len: payload_len,
            max: max_frame_bytes,
        });
    }
    let total_len =
        IPC_FRAME_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(IpcFrameError::FrameTooLarge {
                len: payload_len,
                max: max_frame_bytes,
            })?;
    let Some(frame_bytes) = buf.get(IPC_FRAME_HEADER_LEN..total_len) else {
        return Err(IpcFrameError::TruncatedFrame {
            expected: total_len,
            available: buf.len(),
        });
    };
    let frame = decode_proto_payload(frame_bytes, max_frame_bytes)?;
    Ok((frame, total_len))
}
