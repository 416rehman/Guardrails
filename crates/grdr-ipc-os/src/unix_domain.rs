// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

use grdr_wire::frame::IpcFrameError;
use jiff::Timestamp;

use crate::IpcError;
use crate::endpoint::{LocalEndpointAddress, TargetOsKind, validate_endpoint_address};
use crate::transport::{
    Acceptor, Connector, FRAME_HEADER_LEN, IpcDeadline, Link, StreamLink, TimestampSource,
    map_io_err, parse_and_validate_frame_header, validate_outgoing_frame,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamBlockingMode {
    Blocking,
    NonBlockingFallback,
}

#[derive(Debug)]
pub struct UnixDomainLink {
    inner: StreamLink<UnixStream>,
    blocking_mode: StreamBlockingMode,
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
        Self::from_accepted_stream(stream, connected_at, StreamBlockingMode::Blocking)
    }

    fn from_accepted_stream(
        stream: UnixStream,
        connected_at: Timestamp,
        blocking_mode: StreamBlockingMode,
    ) -> Result<Self, IpcError> {
        let default_deadline = IpcDeadline::call_default();
        apply_read_timeout(&stream, default_deadline.as_duration())?;
        apply_write_timeout(&stream, default_deadline.as_duration())?;
        Ok(Self {
            inner: StreamLink::new(stream, connected_at),
            blocking_mode,
        })
    }

    pub(crate) const fn read_deadline(&self) -> IpcDeadline {
        self.inner.read_deadline()
    }

    pub(crate) const fn write_deadline(&self) -> IpcDeadline {
        self.inner.write_deadline()
    }

    pub(crate) fn read_chunk_cumulative(
        &mut self,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, IpcFrameError> {
        let timeout_ms = self.inner.read_deadline().as_millis_u64();
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(IpcFrameError::TimedOut { timeout_ms });
            };
            if let Err(err) = apply_read_timeout(self.inner.stream_mut(), remaining) {
                return Err(IpcFrameError::Io {
                    detail: err.to_string(),
                });
            }
            match self.inner.stream_mut().read(buf) {
                Ok(n) => return Ok(n),
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err)
                    if self.blocking_mode == StreamBlockingMode::NonBlockingFallback
                        && err.kind() == ErrorKind::WouldBlock =>
                {
                    let Some(rem_after) = deadline.checked_duration_since(Instant::now()) else {
                        return Err(IpcFrameError::TimedOut { timeout_ms });
                    };
                    std::thread::sleep(Duration::from_millis(2).min(rem_after));
                }
                Err(err) if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                    return Err(IpcFrameError::TimedOut { timeout_ms });
                }
                Err(err) => {
                    return Err(IpcFrameError::Io {
                        detail: err.to_string(),
                    });
                }
            }
        }
    }

    pub(crate) fn write_all_cumulative_until(
        &mut self,
        data: &[u8],
        deadline: Instant,
    ) -> Result<(), IpcFrameError> {
        let timeout_ms = self.inner.write_deadline().as_millis_u64();
        let mut offset = 0usize;
        while offset < data.len() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(IpcFrameError::TimedOut { timeout_ms });
            };
            if let Err(err) = apply_write_timeout(self.inner.stream_mut(), remaining) {
                return Err(IpcFrameError::Io {
                    detail: err.to_string(),
                });
            }
            let Some(chunk) = data.get(offset..) else {
                break;
            };
            match self.inner.stream_mut().write(chunk) {
                Ok(0) => {
                    return Err(IpcFrameError::Io {
                        detail: "zero-byte write on IPC stream".to_string(),
                    });
                }
                Ok(n) => offset = offset.saturating_add(n),
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err)
                    if self.blocking_mode == StreamBlockingMode::NonBlockingFallback
                        && err.kind() == ErrorKind::WouldBlock =>
                {
                    let Some(rem_after) = deadline.checked_duration_since(Instant::now()) else {
                        return Err(IpcFrameError::TimedOut { timeout_ms });
                    };
                    std::thread::sleep(Duration::from_millis(2).min(rem_after));
                }
                Err(err) if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                    return Err(IpcFrameError::TimedOut { timeout_ms });
                }
                Err(err) => {
                    return Err(IpcFrameError::Io {
                        detail: err.to_string(),
                    });
                }
            }
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(IpcFrameError::TimedOut { timeout_ms });
        };
        if let Err(err) = apply_write_timeout(self.inner.stream_mut(), remaining) {
            return Err(IpcFrameError::Io {
                detail: err.to_string(),
            });
        }
        self.inner
            .stream_mut()
            .flush()
            .map_err(|err| IpcFrameError::Io {
                detail: err.to_string(),
            })
    }

    fn read_exact_cumulative(&mut self, buf: &mut [u8]) -> Result<(), IpcError> {
        let deadline = self.inner.read_deadline();
        let total = deadline.as_duration();
        let start = Instant::now();
        let mut offset = 0usize;
        while offset < buf.len() {
            let remaining = remaining_budget(start, total, deadline)?;
            apply_read_timeout(self.inner.stream_mut(), remaining)?;
            let Some(slot) = buf.get_mut(offset..) else {
                break;
            };
            match self.inner.stream_mut().read(slot) {
                Ok(0) => return Err(IpcError::Io("unexpected EOF reading IPC frame".into())),
                Ok(n) => offset = offset.saturating_add(n),
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err)
                    if self.blocking_mode == StreamBlockingMode::NonBlockingFallback
                        && err.kind() == ErrorKind::WouldBlock =>
                {
                    if start.elapsed() >= total {
                        return Err(IpcError::DeadlineExceeded {
                            timeout_ms: deadline.as_millis_u64(),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(2).min(remaining));
                    continue;
                }
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
            apply_write_timeout(self.inner.stream_mut(), remaining)?;
            let Some(chunk) = data.get(offset..) else {
                break;
            };
            match self.inner.stream_mut().write(chunk) {
                Ok(0) => return Err(IpcError::Io("zero-byte write on IPC stream".into())),
                Ok(n) => offset = offset.saturating_add(n),
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err)
                    if self.blocking_mode == StreamBlockingMode::NonBlockingFallback
                        && err.kind() == ErrorKind::WouldBlock =>
                {
                    if start.elapsed() >= total {
                        return Err(IpcError::DeadlineExceeded {
                            timeout_ms: deadline.as_millis_u64(),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(2).min(remaining));
                    continue;
                }
                Err(err) => return Err(map_io_err(err, deadline)),
            }
        }
        let remaining = remaining_budget(start, total, deadline)?;
        apply_write_timeout(self.inner.stream_mut(), remaining)?;
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
        apply_read_timeout(self.inner.stream_mut(), read.as_duration())?;
        apply_write_timeout(self.inner.stream_mut(), write.as_duration())?;
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
                Ok(s) => {
                    set_fd_cloexec(&s)?;
                    break s;
                }
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
        Self::bind_with_mode(address, 0o600)
    }

    pub fn bind_with_mode(
        address: LocalEndpointAddress,
        socket_mode: u32,
    ) -> Result<Self, IpcError> {
        let (listener, _) =
            crate::unix_domain_bind::bind_unix_listener_with_mode(&address, socket_mode)?;
        Self::from_listener(listener, address)
    }

    pub fn from_listener(
        listener: UnixListener,
        address: LocalEndpointAddress,
    ) -> Result<Self, IpcError> {
        set_fd_cloexec(&listener)?;
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
                    set_fd_cloexec(&stream)?;
                    let blocking_mode = restore_accepted_blocking_mode(&stream)?;
                    let connected_at = clock.now_utc();
                    return UnixDomainLink::from_accepted_stream(
                        stream,
                        connected_at,
                        blocking_mode,
                    );
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

use crate::unix_domain_bind::set_fd_cloexec;

fn is_macos_disconnected_invalid_input(err: &std::io::Error) -> bool {
    #[cfg(target_os = "macos")]
    {
        err.kind() == ErrorKind::InvalidInput
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = err;
        false
    }
}

fn restore_accepted_blocking_mode(stream: &UnixStream) -> Result<StreamBlockingMode, IpcError> {
    match stream.set_nonblocking(false) {
        Ok(()) => Ok(StreamBlockingMode::Blocking),
        Err(err) if is_macos_disconnected_invalid_input(&err) => {
            Ok(StreamBlockingMode::NonBlockingFallback)
        }
        Err(err) => Err(IpcError::Io(err.to_string())),
    }
}

fn apply_read_timeout(stream: &UnixStream, dur: Duration) -> Result<(), IpcError> {
    match stream.set_read_timeout(Some(dur)) {
        Ok(()) => Ok(()),
        Err(err) if !dur.is_zero() && is_macos_disconnected_invalid_input(&err) => Ok(()),
        Err(err) => Err(IpcError::Io(err.to_string())),
    }
}

fn apply_write_timeout(stream: &UnixStream, dur: Duration) -> Result<(), IpcError> {
    match stream.set_write_timeout(Some(dur)) {
        Ok(()) => Ok(()),
        Err(err) if !dur.is_zero() && is_macos_disconnected_invalid_input(&err) => Ok(()),
        Err(err) => Err(IpcError::Io(err.to_string())),
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

impl UnixDomainLink {
    #[must_use]
    pub fn borrowed_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.inner.stream().as_fd()
    }
}

impl std::os::fd::AsRawFd for UnixDomainLink {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.stream().as_raw_fd()
    }
}

impl std::io::Read for UnixDomainLink {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.stream_mut().read(buf)
    }
}

impl std::io::Write for UnixDomainLink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.stream_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.stream_mut().flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::FixedTimestampSource;

    fn make_frame(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN.saturating_add(body.len()));
        out.extend_from_slice(b"GRDR");
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn unix_acceptor_and_connector_exchange_frames_with_deadlines() {
        let base = ["XDG_RUNTIME_DIR", "HOME"]
            .into_iter()
            .find_map(|key| {
                std::env::var_os(key).and_then(|val| {
                    let path = std::path::PathBuf::from(val);
                    (!path.as_os_str().is_empty() && path.is_absolute()).then_some(path)
                })
            })
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!(".grdr-ipc-u-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("decide.sock");
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
        let frame = make_frame(b"ping");
        let sent_frame = frame.clone();
        let handle = std::thread::spawn(move || {
            let mut client = UnixDomainConnector
                .connect(&addr, IpcDeadline::call_default(), &clock)
                .unwrap();
            client.send_bytes(&sent_frame).unwrap();
        });

        let mut server_link = acceptor
            .accept(IpcDeadline::call_default(), &clock)
            .unwrap();
        let received = server_link.recv_bytes().unwrap();
        assert_eq!(received, frame);
        acceptor.stop();
        assert!(matches!(
            acceptor.accept(IpcDeadline::call_default(), &clock),
            Err(IpcError::Stopped)
        ));
        handle.join().unwrap();
        let _ = std::fs::remove_file(&sock_path);
        let _ = std::fs::remove_dir_all(&dir);
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
                if writer.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(12));
            }
        });

        let res = link.recv_bytes();
        assert!(matches!(res, Err(IpcError::DeadlineExceeded { .. })));
        let _ = t.join();
    }

    #[test]
    fn nonblocking_fallback_reads_buffered_frame_and_enforces_deadline() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let (mut writer, reader) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();

        let frame = make_frame(b"fallback");
        writer.write_all(&frame).unwrap();
        drop(writer);

        let mut link = UnixDomainLink::from_accepted_stream(
            reader,
            now,
            StreamBlockingMode::NonBlockingFallback,
        )
        .unwrap();
        let decoded = link.recv_bytes().unwrap();
        assert_eq!(decoded, frame);

        let (stalled_writer, stalled_reader) = UnixStream::pair().unwrap();
        stalled_reader.set_nonblocking(true).unwrap();
        let mut timed_link = UnixDomainLink::from_accepted_stream(
            stalled_reader,
            now,
            StreamBlockingMode::NonBlockingFallback,
        )
        .unwrap();
        let short = IpcDeadline::from_millis_capped(25, 1_000);
        timed_link.set_deadlines(short, short).unwrap();
        assert!(matches!(
            timed_link.recv_bytes(),
            Err(IpcError::DeadlineExceeded { .. })
        ));
        drop(stalled_writer);
    }
}
