// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::io::{ErrorKind, Read, Write};
use std::time::Duration;

use jiff::Timestamp;

use grdr_wire::WIRE_PROTOCOL_VERSION;
use grdr_wire::limits::embedded_limits;

use crate::IpcError;
use crate::endpoint::{LocalEndpointAddress, WindowsPipeOpenPolicy};

pub const MAX_CALL_DEADLINE_MS: u64 = 1_500;
pub const MAX_FIRST_FRAME_DEADLINE_MS: u64 = 2_000;
pub(crate) const FRAME_HEADER_LEN: usize = 10;
const FRAME_MAGIC: [u8; 4] = *b"GRDR";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcDeadline {
    duration: Duration,
}

pub trait TimestampSource {
    fn now_utc(&self) -> Timestamp;
}

#[derive(Debug, Clone, Copy)]
pub struct FixedTimestampSource {
    timestamp: Timestamp,
}

pub trait Link {
    fn send_bytes(&mut self, frame_bytes: &[u8]) -> Result<(), IpcError>;
    fn recv_bytes(&mut self) -> Result<Vec<u8>, IpcError>;
    fn set_deadlines(&mut self, read: IpcDeadline, write: IpcDeadline) -> Result<(), IpcError>;
    fn connected_at(&self) -> Timestamp;
}

pub trait Connector {
    type ConnectedLink: Link;

    fn connect(
        &self,
        address: &LocalEndpointAddress,
        deadline: IpcDeadline,
        clock: &dyn TimestampSource,
    ) -> Result<Self::ConnectedLink, IpcError>;
}

pub trait Acceptor {
    type AcceptedLink: Link;

    fn accept(
        &mut self,
        deadline: IpcDeadline,
        clock: &dyn TimestampSource,
    ) -> Result<Self::AcceptedLink, IpcError>;
    fn stop(&mut self);
    fn address(&self) -> &LocalEndpointAddress;
}

#[derive(Debug)]
pub struct StreamLink<S> {
    stream: S,
    connected_at: Timestamp,
    read_deadline: IpcDeadline,
    write_deadline: IpcDeadline,
}

#[derive(Debug, Clone, Default)]
pub struct SystemConnector {
    windows_policy: WindowsPipeOpenPolicy,
}

impl IpcDeadline {
    #[must_use]
    pub fn from_millis_capped(ms: u64, max_ms: u64) -> Self {
        let bounded = ms.max(1).min(max_ms.max(1));
        Self {
            duration: Duration::from_millis(bounded),
        }
    }

    #[must_use]
    pub fn call_default() -> Self {
        let ms = embedded_limits().map_or(MAX_CALL_DEADLINE_MS, |l| l.read_timeout_ms);
        Self {
            duration: Duration::from_millis(ms.max(1)),
        }
    }

    #[must_use]
    pub fn first_frame_default() -> Self {
        let ms = embedded_limits().map_or(MAX_FIRST_FRAME_DEADLINE_MS, |l| l.shim_hang_max_ms);
        Self {
            duration: Duration::from_millis(ms.max(1)),
        }
    }

    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.duration
    }

    #[must_use]
    pub fn as_millis_u64(self) -> u64 {
        u64::try_from(self.duration.as_millis()).unwrap_or(u64::MAX)
    }
}

impl FixedTimestampSource {
    #[must_use]
    pub const fn new(timestamp: Timestamp) -> Self {
        Self { timestamp }
    }
}

impl TimestampSource for FixedTimestampSource {
    fn now_utc(&self) -> Timestamp {
        self.timestamp
    }
}

impl<S: Read + Write> StreamLink<S> {
    #[must_use]
    pub fn new(stream: S, connected_at: Timestamp) -> Self {
        Self {
            stream,
            connected_at,
            read_deadline: IpcDeadline::call_default(),
            write_deadline: IpcDeadline::call_default(),
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    #[must_use]
    pub const fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    #[cfg(unix)]
    pub(crate) const fn read_deadline(&self) -> IpcDeadline {
        self.read_deadline
    }

    #[cfg(unix)]
    pub(crate) const fn write_deadline(&self) -> IpcDeadline {
        self.write_deadline
    }
}

impl<S: Read + Write> Link for StreamLink<S> {
    fn send_bytes(&mut self, frame_bytes: &[u8]) -> Result<(), IpcError> {
        validate_outgoing_frame(frame_bytes)?;
        self.stream
            .write_all(frame_bytes)
            .and_then(|()| self.stream.flush())
            .map_err(|e| map_io_err(e, self.write_deadline))
    }

    fn recv_bytes(&mut self) -> Result<Vec<u8>, IpcError> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| map_io_err(e, self.read_deadline))?;

        let body_len = parse_and_validate_frame_header(&header)?;
        let total = FRAME_HEADER_LEN
            .checked_add(body_len)
            .ok_or_else(|| IpcError::FrameInvalid("frame length overflow".into()))?;
        let mut frame = vec![0u8; total];
        if let Some(dst_hdr) = frame.get_mut(..FRAME_HEADER_LEN) {
            dst_hdr.copy_from_slice(&header);
        }
        if let Some(dst_body) = frame.get_mut(FRAME_HEADER_LEN..) {
            self.stream
                .read_exact(dst_body)
                .map_err(|e| map_io_err(e, self.read_deadline))?;
        }
        Ok(frame)
    }

    fn set_deadlines(&mut self, read: IpcDeadline, write: IpcDeadline) -> Result<(), IpcError> {
        self.read_deadline = read;
        self.write_deadline = write;
        Ok(())
    }

    fn connected_at(&self) -> Timestamp {
        self.connected_at
    }
}

impl SystemConnector {
    #[must_use]
    pub const fn with_windows_policy(policy: WindowsPipeOpenPolicy) -> Self {
        Self {
            windows_policy: policy,
        }
    }

    #[must_use]
    pub const fn windows_policy(&self) -> WindowsPipeOpenPolicy {
        self.windows_policy
    }
}

#[cfg(unix)]
impl Connector for SystemConnector {
    type ConnectedLink = crate::unix_domain::UnixDomainLink;

    fn connect(
        &self,
        address: &LocalEndpointAddress,
        deadline: IpcDeadline,
        clock: &dyn TimestampSource,
    ) -> Result<Self::ConnectedLink, IpcError> {
        crate::unix_domain::UnixDomainConnector.connect(address, deadline, clock)
    }
}

#[cfg(windows)]
impl Connector for SystemConnector {
    type ConnectedLink = crate::windows_pipe::WindowsNamedPipeLink;

    fn connect(
        &self,
        address: &LocalEndpointAddress,
        deadline: IpcDeadline,
        clock: &dyn TimestampSource,
    ) -> Result<Self::ConnectedLink, IpcError> {
        crate::windows_pipe::WindowsNamedPipeConnector::with_policy(self.windows_policy)
            .connect(address, deadline, clock)
    }
}

pub fn local_frame_cap() -> Result<usize, IpcError> {
    embedded_limits()
        .map(|l| l.max_frame_bytes)
        .map_err(|e| IpcError::FrameInvalid(e.to_string()))
}

pub fn validate_outgoing_frame(frame_bytes: &[u8]) -> Result<(), IpcError> {
    let Some(header) = frame_bytes.get(..FRAME_HEADER_LEN) else {
        return Err(IpcError::FrameInvalid(
            "frame smaller than 10-byte GRDR header".into(),
        ));
    };
    let cap = local_frame_cap()?;
    let max_total = FRAME_HEADER_LEN.saturating_add(cap);
    if frame_bytes.len() > max_total {
        return Err(IpcError::FrameInvalid(format!(
            "frame size {} exceeds local IPC cap {}",
            frame_bytes.len(),
            max_total
        )));
    }
    let body_len = parse_and_validate_frame_header(header)?;
    let expected_total = FRAME_HEADER_LEN.saturating_add(body_len);
    if frame_bytes.len() != expected_total {
        return Err(IpcError::FrameInvalid(format!(
            "frame length {} does not match header total {}",
            frame_bytes.len(),
            expected_total
        )));
    }
    Ok(())
}

pub fn parse_and_validate_frame_header(header: &[u8]) -> Result<usize, IpcError> {
    if header.len() != FRAME_HEADER_LEN {
        return Err(IpcError::FrameInvalid("invalid frame header length".into()));
    }
    let Some(magic) = header.get(..4) else {
        return Err(IpcError::FrameInvalid("missing frame magic".into()));
    };
    if magic != FRAME_MAGIC {
        return Err(IpcError::FrameInvalid(
            "invalid wire frame magic header".into(),
        ));
    }
    let Some(ver_slice) = header.get(4..6) else {
        return Err(IpcError::FrameInvalid("missing wire version".into()));
    };
    let ver_bytes: [u8; 2] = ver_slice
        .try_into()
        .map_err(|_| IpcError::FrameInvalid("invalid wire version slice".into()))?;
    let version = u16::from_be_bytes(ver_bytes);
    if version != WIRE_PROTOCOL_VERSION {
        return Err(IpcError::FrameInvalid(format!(
            "unsupported wire version {version}"
        )));
    }

    let Some(len_slice) = header.get(6..10) else {
        return Err(IpcError::FrameInvalid(
            "missing frame payload length".into(),
        ));
    };
    let len_bytes: [u8; 4] = len_slice
        .try_into()
        .map_err(|_| IpcError::FrameInvalid("invalid length header".into()))?;
    let body_len = usize::try_from(u32::from_be_bytes(len_bytes))
        .map_err(|_| IpcError::FrameInvalid("frame length exceeds usize".into()))?;
    let cap = local_frame_cap()?;
    if body_len > cap {
        return Err(IpcError::FrameInvalid(format!(
            "frame payload {body_len} exceeds local IPC cap {cap}"
        )));
    }
    Ok(body_len)
}

pub(crate) fn map_io_err(err: std::io::Error, deadline: IpcDeadline) -> IpcError {
    if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
        IpcError::DeadlineExceeded {
            timeout_ms: deadline.as_millis_u64(),
        }
    } else {
        IpcError::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_frame(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN.saturating_add(body.len()));
        out.extend_from_slice(&FRAME_MAGIC);
        out.extend_from_slice(&WIRE_PROTOCOL_VERSION.to_be_bytes());
        out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn deadline_never_rounds_to_zero_and_caps_at_limit() {
        let zero = IpcDeadline::from_millis_capped(0, MAX_CALL_DEADLINE_MS);
        assert_eq!(zero.as_millis_u64(), 1);
        let high = IpcDeadline::from_millis_capped(9_999, MAX_CALL_DEADLINE_MS);
        assert_eq!(high.as_millis_u64(), MAX_CALL_DEADLINE_MS);
    }

    #[test]
    fn stream_link_roundtrips_binary_frames() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let frame = make_frame(b"hello-grdr-ipc");

        let buf = Cursor::new(Vec::<u8>::new());
        let mut writer_link = StreamLink::new(buf, now);
        writer_link.send_bytes(&frame).unwrap();
        let written = writer_link.into_inner().into_inner();

        let mut reader_link = StreamLink::new(Cursor::new(written), now);
        let decoded = reader_link.recv_bytes().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(reader_link.connected_at(), now);
    }

    #[test]
    fn rejects_bad_magic_unsupported_version_and_oversized_frame_before_allocation() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let cap = local_frame_cap().unwrap();
        let mut bad_magic = [0u8; 10];
        bad_magic[..4].copy_from_slice(b"EVIL");
        bad_magic[4..6].copy_from_slice(&1u16.to_be_bytes());
        bad_magic[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut link = StreamLink::new(Cursor::new(bad_magic.to_vec()), now);
        assert!(matches!(link.recv_bytes(), Err(IpcError::FrameInvalid(_))));

        let mut bad_ver = [0u8; 10];
        bad_ver[..4].copy_from_slice(b"GRDR");
        bad_ver[4..6].copy_from_slice(&99u16.to_be_bytes());
        bad_ver[6..10].copy_from_slice(&64u32.to_be_bytes());
        let mut link_ver = StreamLink::new(Cursor::new(bad_ver.to_vec()), now);
        assert!(matches!(
            link_ver.recv_bytes(),
            Err(IpcError::FrameInvalid(_))
        ));

        let mut oversized = [0u8; 10];
        oversized[..4].copy_from_slice(b"GRDR");
        oversized[4..6].copy_from_slice(&1u16.to_be_bytes());
        let over_len = u32::try_from(cap + 1).unwrap();
        oversized[6..10].copy_from_slice(&over_len.to_be_bytes());
        let mut link_over = StreamLink::new(Cursor::new(oversized.to_vec()), now);
        assert!(matches!(
            link_over.recv_bytes(),
            Err(IpcError::FrameInvalid(_))
        ));

        let mut truncated = Vec::from(b"GRDR".as_slice());
        truncated.extend_from_slice(&1u16.to_be_bytes());
        truncated.extend_from_slice(&32u32.to_be_bytes());
        truncated.extend_from_slice(&[0xAB; 8]);
        let mut link_trunc = StreamLink::new(Cursor::new(truncated), now);
        assert!(matches!(link_trunc.recv_bytes(), Err(IpcError::Io(_))));

        let encoded = make_frame(b"ok");
        let mut with_trailing = encoded;
        with_trailing.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            validate_outgoing_frame(&with_trailing),
            Err(IpcError::FrameInvalid(_))
        ));
    }
}
