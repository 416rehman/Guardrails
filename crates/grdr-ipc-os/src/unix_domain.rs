// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

use jiff::Timestamp;

use crate::IpcError;
use crate::endpoint::{LocalEndpointAddress, TargetOsKind, validate_endpoint_address};
use crate::transport::{
    Acceptor, Connector, FRAME_HEADER_LEN, IpcDeadline, Link, StreamLink, TimestampSource,
    map_io_err, parse_and_validate_frame_header, validate_outgoing_frame,
};

#[derive(Debug)]
pub struct UnixDomainLink {
    inner: StreamLink<UnixStream>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnixDomainConnector;

#[derive(Debug)]
pub struct UnixDomainAcceptor {
    listener: UnixListener,
    address: LocalEndpointAddress,
    stopped: bool,
}

impl UnixDomainLink {
    pub fn from_stream(stream: UnixStream, connected_at: Timestamp) -> Result<Self, IpcError> {
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

    fn read_exact_cumulative(&mut self, buf: &mut [u8]) -> Result<(), IpcError> {
        let deadline = self.inner.read_deadline();
        let total = deadline.as_duration();
        let start = Instant::now();
        let mut offset = 0usize;
        while offset < buf.len() {
            let remaining = remaining_budget(start, total, deadline)?;
            self.inner
                .stream_mut()
                .set_read_timeout(Some(remaining))
                .map_err(|e| IpcError::Io(e.to_string()))?;
            let Some(slot) = buf.get_mut(offset..) else {
                break;
            };
            match self.inner.stream_mut().read(slot) {
                Ok(0) => return Err(IpcError::Io("unexpected EOF reading IPC frame".into())),
                Ok(n) => offset = offset.saturating_add(n),
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(map_io_err(err, deadline)),
            }
        }
        Ok(())
    }

    fn write_all_cumulative(&mut self, data: &[u8]) -> Result<(), IpcError> {
        let deadline = self.inner.write_deadline();
        let total = deadline.as_duration();
        let start = Instant::now();
        let mut offset = 0usize;
        while offset < data.len() {
            let remaining = remaining_budget(start, total, deadline)?;
            self.inner
                .stream_mut()
                .set_write_timeout(Some(remaining))
                .map_err(|e| IpcError::Io(e.to_string()))?;
            let Some(chunk) = data.get(offset..) else {
                break;
            };
            match self.inner.stream_mut().write(chunk) {
                Ok(0) => return Err(IpcError::Io("zero-byte write on IPC stream".into())),
                Ok(n) => offset = offset.saturating_add(n),
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(map_io_err(err, deadline)),
            }
        }
        let remaining = remaining_budget(start, total, deadline)?;
        self.inner
            .stream_mut()
            .set_write_timeout(Some(remaining))
            .map_err(|e| IpcError::Io(e.to_string()))?;
        self.inner
            .stream_mut()
            .flush()
            .map_err(|e| map_io_err(e, deadline))
    }
}

impl Link for UnixDomainLink {
    fn send_bytes(&mut self, frame_bytes: &[u8]) -> Result<(), IpcError> {
        validate_outgoing_frame(frame_bytes)?;
        self.write_all_cumulative(frame_bytes)
    }

    fn recv_bytes(&mut self) -> Result<Vec<u8>, IpcError> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        self.read_exact_cumulative(&mut header)?;
        let body_len = parse_and_validate_frame_header(&header)?;
        let total = FRAME_HEADER_LEN
            .checked_add(body_len)
            .ok_or_else(|| IpcError::FrameInvalid("frame length overflow".into()))?;
        let mut frame = vec![0u8; total];
        if let Some(dst_hdr) = frame.get_mut(..FRAME_HEADER_LEN) {
            dst_hdr.copy_from_slice(&header);
        }
        if let Some(dst_body) = frame.get_mut(FRAME_HEADER_LEN..) {
            self.read_exact_cumulative(dst_body)?;
        }
        Ok(frame)
    }

    fn set_deadlines(&mut self, read: IpcDeadline, write: IpcDeadline) -> Result<(), IpcError> {
        self.inner
            .stream_mut()
            .set_read_timeout(Some(read.as_duration()))
            .map_err(|e| IpcError::Io(e.to_string()))?;
        self.inner
            .stream_mut()
            .set_write_timeout(Some(write.as_duration()))
            .map_err(|e| IpcError::Io(e.to_string()))?;
        self.inner.set_deadlines(read, write)
    }

    fn connected_at(&self) -> Timestamp {
        self.inner.connected_at()
    }
}

impl Connector for UnixDomainConnector {
    type ConnectedLink = UnixDomainLink;

    fn connect(
        &self,
        address: &LocalEndpointAddress,
        deadline: IpcDeadline,
        clock: &dyn TimestampSource,
    ) -> Result<Self::ConnectedLink, IpcError> {
        validate_endpoint_address(TargetOsKind::current(), address)?;
        let LocalEndpointAddress::UnixSocket { path } = address else {
            return Err(IpcError::InvalidAddress(
                "UnixDomainConnector requires UnixSocket address".into(),
            ));
        };
        let start = Instant::now();
        let stream = loop {
            match UnixStream::connect(path) {
                Ok(s) => break s,
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    if start.elapsed() >= deadline.as_duration() {
                        return Err(IpcError::DeadlineExceeded {
                            timeout_ms: deadline.as_millis_u64(),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(err) => return Err(map_connect_err(err, path.display().to_string())),
            }
        };
        let connected_at = clock.now_utc();
        let mut link = UnixDomainLink::from_stream(stream, connected_at)?;
        link.set_deadlines(deadline, deadline)?;
        Ok(link)
    }
}

impl UnixDomainAcceptor {
    pub fn bind(address: LocalEndpointAddress) -> Result<Self, IpcError> {
        validate_endpoint_address(TargetOsKind::current(), &address)?;
        let LocalEndpointAddress::UnixSocket { path } = &address else {
            return Err(IpcError::InvalidAddress(
                "UnixDomainAcceptor requires UnixSocket address".into(),
            ));
        };
        let listener = UnixListener::bind(path)
            .map_err(|e| IpcError::Io(format!("bind `{}` failed: {e}", path.display())))?;
        Self::from_listener(listener, address)
    }

    pub fn from_listener(
        listener: UnixListener,
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

impl Acceptor for UnixDomainAcceptor {
    type AcceptedLink = UnixDomainLink;

    fn accept(
        &mut self,
        deadline: IpcDeadline,
        clock: &dyn TimestampSource,
    ) -> Result<Self::AcceptedLink, IpcError> {
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
                    let connected_at = clock.now_utc();
                    return UnixDomainLink::from_stream(stream, connected_at);
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

fn remaining_budget(
    start: Instant,
    total: Duration,
    deadline: IpcDeadline,
) -> Result<Duration, IpcError> {
    match total.checked_sub(start.elapsed()) {
        Some(rem) if !rem.is_zero() => Ok(rem),
        _ => Err(IpcError::DeadlineExceeded {
            timeout_ms: deadline.as_millis_u64(),
        }),
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
    use crate::transport::FixedTimestampSource;
    use grdr_crypto::SigningKeypair;
    use grdr_wire::{WireEnvelope, generate_nonce, sign_envelope};

    #[test]
    fn unix_acceptor_and_connector_exchange_frames_with_deadlines() {
        let sock_path =
            std::path::PathBuf::from(format!("/tmp/grdr-ipc-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let addr = LocalEndpointAddress::UnixSocket {
            path: sock_path.clone(),
        };
        let clock = FixedTimestampSource::new(Timestamp::from_second(1_700_000_000).unwrap());

        let mut acceptor = UnixDomainAcceptor::bind(addr.clone()).unwrap();
        assert!(matches!(
            acceptor.accept(IpcDeadline::from_millis_capped(5, 1_000), &clock),
            Err(IpcError::DeadlineExceeded { .. })
        ));
        let handle = std::thread::spawn(move || {
            let mut client = UnixDomainConnector
                .connect(&addr, IpcDeadline::call_default(), &clock)
                .unwrap();
            let kp = SigningKeypair::generate().unwrap();
            let env = sign_envelope(
                &kp,
                generate_nonce().unwrap(),
                clock.now_utc(),
                "ping".to_string(),
            )
            .unwrap();
            client.send_envelope(&env).unwrap();
        });

        let mut server_link = acceptor
            .accept(IpcDeadline::call_default(), &clock)
            .unwrap();
        let received: WireEnvelope<String> = server_link.recv_envelope().unwrap();
        assert_eq!(received.payload, "ping");
        acceptor.stop();
        assert!(matches!(
            acceptor.accept(IpcDeadline::call_default(), &clock),
            Err(IpcError::Stopped)
        ));
        handle.join().unwrap();
        let _ = std::fs::remove_file(&sock_path);
    }

    #[test]
    fn unix_link_enforces_cumulative_frame_deadline_against_trickle() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let mut link = UnixDomainLink::from_stream(reader, now).unwrap();
        let short = IpcDeadline::from_millis_capped(30, 1_000);
        link.set_deadlines(short, short).unwrap();

        let t = std::thread::spawn(move || {
            let mut hdr = Vec::from(b"GRDR".as_slice());
            hdr.extend_from_slice(&1u16.to_be_bytes());
            hdr.extend_from_slice(&64u32.to_be_bytes());
            let _ = writer.write_all(&hdr);
            for _ in 0..8 {
                if writer.write_all(&[b'x']).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(12));
            }
        });

        let res = link.recv_bytes();
        assert!(matches!(res, Err(IpcError::DeadlineExceeded { .. })));
        let _ = t.join();
    }
}
