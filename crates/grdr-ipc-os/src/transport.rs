// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};

use jiff::Timestamp;
use serde::Serialize;
use serde::de::DeserializeOwned;

use grdr_wire::{MAX_FRAME_BYTES, WireEnvelope, decode_frame, encode_frame};

use crate::IpcError;
use crate::endpoint::{
    LocalEndpointAddress, TargetOsKind, WindowsPipeOpenPolicy, validate_endpoint_address,
};

pub const MAX_CALL_DEADLINE_MS: u64 = 1_000;
pub const MAX_FIRST_FRAME_DEADLINE_MS: u64 = 1_800;
const FRAME_HEADER_LEN: usize = 10;
#[cfg(windows)]
const FIVE_RIGHT_CLIENT_MASK: u32 = 0x0012_0083;
#[cfg(windows)]
const SQOS_IDENTIFICATION: u32 = 0x0011_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcDeadline {
    duration: Duration,
}

pub trait Link {
    fn send_bytes(&mut self, frame_bytes: &[u8]) -> Result<(), IpcError>;
    fn recv_bytes(&mut self) -> Result<Vec<u8>, IpcError>;
    fn set_deadlines(&mut self, read: IpcDeadline, write: IpcDeadline) -> Result<(), IpcError>;
    fn connected_at(&self) -> Timestamp;

    fn send_envelope<T: Serialize>(&mut self, envelope: &WireEnvelope<T>) -> Result<(), IpcError> {
        let encoded = encode_frame(envelope).map_err(|e| IpcError::FrameInvalid(e.to_string()))?;
        self.send_bytes(&encoded)
    }

    fn recv_envelope<T: DeserializeOwned>(&mut self) -> Result<WireEnvelope<T>, IpcError> {
        let raw = self.recv_bytes()?;
        let (env, consumed) =
            decode_frame(&raw).map_err(|e| IpcError::FrameInvalid(e.to_string()))?;
        if consumed != raw.len() {
            return Err(IpcError::FrameInvalid(format!(
                "trailing bytes after frame: {} != {}",
                consumed,
                raw.len()
            )));
        }
        Ok(env)
    }
}

pub trait Connector {
    type ConnectedLink: Link;

    fn connect(
        &self,
        address: &LocalEndpointAddress,
        deadline: IpcDeadline,
    ) -> Result<Self::ConnectedLink, IpcError>;
}

pub trait Acceptor {
    type AcceptedLink: Link;

    fn accept(&mut self, deadline: IpcDeadline) -> Result<Self::AcceptedLink, IpcError>;
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

#[cfg(unix)]
#[derive(Debug)]
pub struct UnixDomainLink {
    inner: StreamLink<std::os::unix::net::UnixStream>,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UnixDomainConnector;

#[cfg(unix)]
#[derive(Debug)]
pub struct UnixDomainAcceptor {
    listener: std::os::unix::net::UnixListener,
    address: LocalEndpointAddress,
    stopped: bool,
}

#[cfg(windows)]
#[derive(Debug, Clone, Default)]
pub struct WindowsNamedPipeConnector {
    policy: WindowsPipeOpenPolicy,
}

impl IpcDeadline {
    pub fn from_millis_capped(ms: u64, max_ms: u64) -> Self {
        let bounded = ms.max(1).min(max_ms.max(1));
        Self {
            duration: Duration::from_millis(bounded),
        }
    }

    pub fn call_default() -> Self {
        Self {
            duration: Duration::from_millis(MAX_CALL_DEADLINE_MS),
        }
    }

    pub fn first_frame_default() -> Self {
        Self {
            duration: Duration::from_millis(MAX_FIRST_FRAME_DEADLINE_MS),
        }
    }

    pub const fn as_duration(self) -> Duration {
        self.duration
    }

    pub fn as_millis_u64(self) -> u64 {
        u64::try_from(self.duration.as_millis()).unwrap_or(u64::MAX)
    }
}

impl<S: Read + Write> StreamLink<S> {
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
}

impl<S: Read + Write> Link for StreamLink<S> {
    fn send_bytes(&mut self, frame_bytes: &[u8]) -> Result<(), IpcError> {
        if frame_bytes.len() < FRAME_HEADER_LEN {
            return Err(IpcError::FrameInvalid(
                "frame smaller than 10-byte GRDR header".into(),
            ));
        }
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

        let len_slice = header
            .get(6..10)
            .ok_or_else(|| IpcError::FrameInvalid("missing length header".into()))?;
        let len_bytes: [u8; 4] = len_slice
            .try_into()
            .map_err(|_| IpcError::FrameInvalid("invalid length header".into()))?;
        let body_len = usize::try_from(u32::from_be_bytes(len_bytes))
            .map_err(|_| IpcError::FrameInvalid("frame length exceeds usize".into()))?;
        if body_len > MAX_FRAME_BYTES {
            return Err(IpcError::FrameInvalid(format!(
                "frame payload {body_len} exceeds max {MAX_FRAME_BYTES}"
            )));
        }

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
    pub fn with_windows_policy(policy: WindowsPipeOpenPolicy) -> Self {
        Self {
            windows_policy: policy,
        }
    }

    pub fn windows_policy(&self) -> WindowsPipeOpenPolicy {
        self.windows_policy
    }
}

#[cfg(unix)]
impl UnixDomainLink {
    pub fn from_stream(stream: std::os::unix::net::UnixStream) -> Result<Self, IpcError> {
        let connected_at = Timestamp::now();
        let default_deadline = IpcDeadline::call_default();
        stream
            .set_read_timeout(Some(default_deadline.as_duration()))
            .map_err(|e| IpcError::Io(e.to_string()))?;
        stream
            .set_write_timeout(Some(default_deadline.as_duration()))
            .map_err(|e| IpcError::Io(e.to_string()))?;
        Ok(Self {
            inner: StreamLink::new(stream, connected_at),
        })
    }
}

#[cfg(unix)]
impl Link for UnixDomainLink {
    fn send_bytes(&mut self, frame_bytes: &[u8]) -> Result<(), IpcError> {
        self.inner.send_bytes(frame_bytes)
    }

    fn recv_bytes(&mut self) -> Result<Vec<u8>, IpcError> {
        self.inner.recv_bytes()
    }

    fn set_deadlines(&mut self, read: IpcDeadline, write: IpcDeadline) -> Result<(), IpcError> {
        self.inner
            .stream
            .set_read_timeout(Some(read.as_duration()))
            .map_err(|e| IpcError::Io(e.to_string()))?;
        self.inner
            .stream
            .set_write_timeout(Some(write.as_duration()))
            .map_err(|e| IpcError::Io(e.to_string()))?;
        self.inner.set_deadlines(read, write)
    }

    fn connected_at(&self) -> Timestamp {
        self.inner.connected_at()
    }
}

#[cfg(unix)]
impl Connector for UnixDomainConnector {
    type ConnectedLink = UnixDomainLink;

    fn connect(
        &self,
        address: &LocalEndpointAddress,
        deadline: IpcDeadline,
    ) -> Result<Self::ConnectedLink, IpcError> {
        validate_endpoint_address(TargetOsKind::current(), address)?;
        let LocalEndpointAddress::UnixSocket { path } = address else {
            return Err(IpcError::InvalidAddress(
                "UnixDomainConnector requires UnixSocket address".into(),
            ));
        };
        let stream = std::os::unix::net::UnixStream::connect(path)
            .map_err(|e| map_connect_err(e, path.display().to_string()))?;
        let mut link = UnixDomainLink::from_stream(stream)?;
        link.set_deadlines(deadline, deadline)?;
        Ok(link)
    }
}

#[cfg(unix)]
impl UnixDomainAcceptor {
    pub fn bind(address: LocalEndpointAddress) -> Result<Self, IpcError> {
        validate_endpoint_address(TargetOsKind::current(), &address)?;
        let LocalEndpointAddress::UnixSocket { path } = &address else {
            return Err(IpcError::InvalidAddress(
                "UnixDomainAcceptor requires UnixSocket address".into(),
            ));
        };
        let listener = std::os::unix::net::UnixListener::bind(path)
            .map_err(|e| IpcError::Io(format!("bind `{}` failed: {e}", path.display())))?;
        Self::from_listener(listener, address)
    }

    pub fn from_listener(
        listener: std::os::unix::net::UnixListener,
        address: LocalEndpointAddress,
    ) -> Result<Self, IpcError> {
        listener
            .set_nonblocking(true)
            .map_err(|e| IpcError::Io(e.to_string()))?;
        Ok(Self {
            listener,
            address,
            stopped: false,
        })
    }
}

#[cfg(unix)]
impl Acceptor for UnixDomainAcceptor {
    type AcceptedLink = UnixDomainLink;

    fn accept(&mut self, deadline: IpcDeadline) -> Result<Self::AcceptedLink, IpcError> {
        if self.stopped {
            return Err(IpcError::Stopped);
        }
        let start = Instant::now();
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|e| IpcError::Io(e.to_string()))?;
                    return UnixDomainLink::from_stream(stream);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    if start.elapsed() >= deadline.as_duration() {
                        return Err(IpcError::DeadlineExceeded {
                            timeout_ms: deadline.as_millis_u64(),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(err) => return Err(IpcError::Io(err.to_string())),
            }
        }
    }

    fn stop(&mut self) {
        self.stopped = true;
    }

    fn address(&self) -> &LocalEndpointAddress {
        &self.address
    }
}

#[cfg(windows)]
impl WindowsNamedPipeConnector {
    pub fn with_policy(policy: WindowsPipeOpenPolicy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> WindowsPipeOpenPolicy {
        self.policy
    }
}

#[cfg(windows)]
impl Connector for WindowsNamedPipeConnector {
    type ConnectedLink = StreamLink<std::fs::File>;

    fn connect(
        &self,
        address: &LocalEndpointAddress,
        deadline: IpcDeadline,
    ) -> Result<Self::ConnectedLink, IpcError> {
        use std::os::windows::fs::OpenOptionsExt;

        validate_endpoint_address(TargetOsKind::Windows, address)?;
        let LocalEndpointAddress::WindowsPipe { pipe_name } = address else {
            return Err(IpcError::InvalidAddress(
                "WindowsNamedPipeConnector requires WindowsPipe address".into(),
            ));
        };
        let access_mask = match self.policy.access_policy {
            crate::endpoint::PipeClientAccessPolicy::FiveRightRestrictedMask => {
                FIVE_RIGHT_CLIENT_MASK
            }
        };
        let sqos_flags = match self.policy.impersonation {
            crate::endpoint::PipeImpersonationLevel::Identification => SQOS_IDENTIFICATION,
        };
        let start = Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .access_mode(access_mask)
                .security_qos_flags(sqos_flags)
                .open(pipe_name)
            {
                Ok(file) => {
                    let connected_at = Timestamp::now();
                    let mut link = StreamLink::new(file, connected_at);
                    link.set_deadlines(deadline, deadline)?;
                    return Ok(link);
                }
                Err(err) if is_retryable_pipe_err(&err) => {
                    if start.elapsed() >= deadline.as_duration() {
                        return Err(IpcError::DeadlineExceeded {
                            timeout_ms: deadline.as_millis_u64(),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(err) => return Err(map_connect_err(err, pipe_name.clone())),
            }
        }
    }
}

#[cfg(windows)]
fn is_retryable_pipe_err(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(231))
}

fn map_io_err(err: std::io::Error, deadline: IpcDeadline) -> IpcError {
    if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
        IpcError::DeadlineExceeded {
            timeout_ms: deadline.as_millis_u64(),
        }
    } else {
        IpcError::Io(err.to_string())
    }
}

fn map_connect_err(err: std::io::Error, target: String) -> IpcError {
    if matches!(
        err.kind(),
        ErrorKind::NotFound | ErrorKind::ConnectionRefused
    ) {
        IpcError::Unavailable(format!("{target}: {err}"))
    } else {
        IpcError::Io(format!("{target}: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_crypto::SigningKeypair;
    use grdr_model::{ActionClass, DecideInput};
    use grdr_wire::sign_envelope;
    use std::io::Cursor;

    #[test]
    fn deadline_never_rounds_to_zero_and_caps_at_limit() {
        let zero = IpcDeadline::from_millis_capped(0, MAX_CALL_DEADLINE_MS);
        assert_eq!(zero.as_millis_u64(), 1);
        let high = IpcDeadline::from_millis_capped(9_999, MAX_CALL_DEADLINE_MS);
        assert_eq!(high.as_millis_u64(), MAX_CALL_DEADLINE_MS);
    }

    #[test]
    fn stream_link_roundtrips_signed_wire_envelopes() {
        let kp = SigningKeypair::generate().unwrap();
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let input = DecideInput {
            session_id: Some("sess-ipc-1".into()),
            device_id: Some("dev-ipc-1".into()),
            device_name: Some("host-ipc".into()),
            agent_name: "claude-code".into(),
            action_class: ActionClass::Exec,
            control_point: None,
            target: "git status".into(),
            summary: None,
        };
        let env = sign_envelope(&kp, "nonce-ipc-1", now, input).unwrap();

        let buf = Cursor::new(Vec::<u8>::new());
        let mut writer_link = StreamLink::new(buf, now);
        writer_link.send_envelope(&env).unwrap();
        let written = writer_link.into_inner().into_inner();

        let mut reader_link = StreamLink::new(Cursor::new(written), now);
        let decoded: WireEnvelope<DecideInput> = reader_link.recv_envelope().unwrap();
        assert_eq!(decoded.payload.target, "git status");
        assert_eq!(reader_link.connected_at(), now);
    }

    #[cfg(unix)]
    #[test]
    fn unix_acceptor_and_connector_exchange_frames_with_deadlines() {
        let sock_path =
            std::path::PathBuf::from(format!("/tmp/grdr-ipc-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let addr = LocalEndpointAddress::UnixSocket {
            path: sock_path.clone(),
        };

        let mut acceptor = UnixDomainAcceptor::bind(addr.clone()).unwrap();
        let handle = std::thread::spawn(move || {
            let mut client = UnixDomainConnector
                .connect(&addr, IpcDeadline::call_default())
                .unwrap();
            let kp = SigningKeypair::generate().unwrap();
            let now = Timestamp::from_second(1_700_000_000).unwrap();
            let env = sign_envelope(&kp, "n-unix", now, "ping".to_string()).unwrap();
            client.send_envelope(&env).unwrap();
        });

        let mut server_link = acceptor.accept(IpcDeadline::call_default()).unwrap();
        let received: WireEnvelope<String> = server_link.recv_envelope().unwrap();
        assert_eq!(received.payload, "ping");
        acceptor.stop();
        assert!(matches!(
            acceptor.accept(IpcDeadline::call_default()),
            Err(IpcError::Stopped)
        ));
        handle.join().unwrap();
        let _ = std::fs::remove_file(&sock_path);
    }
}
