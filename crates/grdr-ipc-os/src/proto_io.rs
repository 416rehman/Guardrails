// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Bounded 4-byte LE protobuf `FrameStream` adapters enforcing cumulative frame deadlines
//! and watchdog-safe anonymous stdio pipes across Unix and Windows.

use std::io;
use std::time::{Duration, Instant};

use grdr_wire::frame::{IPC_FRAME_HEADER_LEN, IpcFrameError};
use grdr_wire::limits::embedded_limits;
use grdr_wire::peer_auth::FrameStream;

pub use crate::duplex_pipe::DuplexPipe;

const CHUNK_ALLOC_STEP: usize = 65_536;

pub type InheritedStdioPair = (
    DuplexPipe<io::PipeReader, io::PipeWriter>,
    (io::PipeReader, io::PipeWriter),
);

pub trait ProtoTransportIo {
    fn read_chunk_until(
        &mut self,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, IpcFrameError>;
    fn write_all_until(&mut self, buf: &[u8], deadline: Instant) -> Result<(), IpcFrameError>;
    fn read_timeout(&self) -> Duration;
    fn write_timeout(&self) -> Duration;
    fn set_timeouts(&mut self, read: Duration, write: Duration) -> Result<(), IpcFrameError>;
}

#[derive(Debug)]
pub struct ProtoIpcStream<S> {
    inner: S,
    read_timeout_override: Option<Duration>,
    write_timeout_override: Option<Duration>,
}

#[cfg(unix)]
impl ProtoTransportIo for crate::unix_domain::UnixDomainLink {
    fn read_chunk_until(
        &mut self,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, IpcFrameError> {
        self.read_chunk_cumulative(buf, deadline)
    }

    fn write_all_until(&mut self, buf: &[u8], deadline: Instant) -> Result<(), IpcFrameError> {
        self.write_all_cumulative_until(buf, deadline)
    }

    fn read_timeout(&self) -> Duration {
        self.read_deadline().as_duration()
    }

    fn write_timeout(&self) -> Duration {
        self.write_deadline().as_duration()
    }

    fn set_timeouts(&mut self, read: Duration, write: Duration) -> Result<(), IpcFrameError> {
        crate::transport::Link::set_deadlines(
            self,
            crate::transport::IpcDeadline::from_millis_capped(duration_ms_u64(read), 60_000),
            crate::transport::IpcDeadline::from_millis_capped(duration_ms_u64(write), 60_000),
        )
        .map_err(|err| IpcFrameError::Io {
            detail: err.to_string(),
        })
    }
}

#[cfg(windows)]
impl ProtoTransportIo for crate::windows_pipe::WindowsNamedPipeLink {
    fn read_chunk_until(
        &mut self,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, IpcFrameError> {
        self.read_chunk_with_deadline(buf, deadline)
    }

    fn write_all_until(&mut self, buf: &[u8], deadline: Instant) -> Result<(), IpcFrameError> {
        self.write_all_with_instant(buf, deadline)
    }

    fn read_timeout(&self) -> Duration {
        self.read_deadline().as_duration()
    }

    fn write_timeout(&self) -> Duration {
        self.write_deadline().as_duration()
    }

    fn set_timeouts(&mut self, read: Duration, write: Duration) -> Result<(), IpcFrameError> {
        crate::transport::Link::set_deadlines(
            self,
            crate::transport::IpcDeadline::from_millis_capped(duration_ms_u64(read), 60_000),
            crate::transport::IpcDeadline::from_millis_capped(duration_ms_u64(write), 60_000),
        )
        .map_err(|err| IpcFrameError::Io {
            detail: err.to_string(),
        })
    }
}

#[cfg(windows)]
impl ProtoTransportIo for crate::windows_pipe_server::WindowsServerPipeStream {
    fn read_chunk_until(
        &mut self,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, IpcFrameError> {
        self.link_mut().read_chunk_with_deadline(buf, deadline)
    }

    fn write_all_until(&mut self, buf: &[u8], deadline: Instant) -> Result<(), IpcFrameError> {
        self.link_mut().write_all_with_instant(buf, deadline)
    }

    fn read_timeout(&self) -> Duration {
        self.link().read_deadline().as_duration()
    }

    fn write_timeout(&self) -> Duration {
        self.link().write_deadline().as_duration()
    }

    fn set_timeouts(&mut self, read: Duration, write: Duration) -> Result<(), IpcFrameError> {
        crate::transport::Link::set_deadlines(
            self,
            crate::transport::IpcDeadline::from_millis_capped(duration_ms_u64(read), 60_000),
            crate::transport::IpcDeadline::from_millis_capped(duration_ms_u64(write), 60_000),
        )
        .map_err(|err| IpcFrameError::Io {
            detail: err.to_string(),
        })
    }
}

impl<S> ProtoIpcStream<S> {
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            read_timeout_override: None,
            write_timeout_override: None,
        }
    }

    #[must_use]
    pub const fn with_timeouts(inner: S, read: Duration, write: Duration) -> Self {
        Self {
            inner,
            read_timeout_override: Some(read),
            write_timeout_override: Some(write),
        }
    }

    pub fn set_timeouts(&mut self, read: Duration, write: Duration) -> Result<(), IpcFrameError>
    where
        S: ProtoTransportIo,
    {
        let r = read.max(Duration::from_millis(1));
        let w = write.max(Duration::from_millis(1));
        self.read_timeout_override = Some(r);
        self.write_timeout_override = Some(w);
        self.inner.set_timeouts(r, w)
    }

    #[must_use]
    pub const fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: ProtoTransportIo> FrameStream for ProtoIpcStream<S> {
    fn send_frame_bytes(&mut self, payload: &[u8]) -> Result<(), IpcFrameError> {
        if payload.is_empty() {
            return Err(IpcFrameError::ZeroLengthFrame);
        }
        let max_bytes = embedded_limits()?.max_frame_bytes;
        if payload.len() > max_bytes {
            return Err(IpcFrameError::FrameTooLarge {
                len: payload.len(),
                max: max_bytes,
            });
        }
        let len = u32::try_from(payload.len()).map_err(|_| IpcFrameError::FrameTooLarge {
            len: payload.len(),
            max: max_bytes,
        })?;
        let total_len = IPC_FRAME_HEADER_LEN.checked_add(payload.len()).ok_or(
            IpcFrameError::FrameTooLarge {
                len: payload.len(),
                max: max_bytes,
            },
        )?;
        let mut frame = Vec::with_capacity(total_len);
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(payload);

        let write_dur = self
            .write_timeout_override
            .unwrap_or_else(|| self.inner.write_timeout());
        let deadline = Instant::now()
            .checked_add(write_dur.max(Duration::from_millis(1)))
            .unwrap_or_else(Instant::now);
        self.inner.write_all_until(&frame, deadline)
    }

    fn recv_frame_bytes(&mut self, max_bytes: usize) -> Result<Vec<u8>, IpcFrameError> {
        if max_bytes == 0 {
            return Err(IpcFrameError::FrameTooLarge { len: 0, max: 0 });
        }
        let read_dur = self
            .read_timeout_override
            .unwrap_or_else(|| self.inner.read_timeout());
        let deadline = Instant::now()
            .checked_add(read_dur.max(Duration::from_millis(1)))
            .unwrap_or_else(Instant::now);

        let mut hdr = [0u8; IPC_FRAME_HEADER_LEN];
        let mut hdr_read = 0usize;
        while hdr_read < IPC_FRAME_HEADER_LEN {
            let Some(slot) = hdr.get_mut(hdr_read..) else {
                break;
            };
            let n = self.inner.read_chunk_until(slot, deadline)?;
            if n == 0 {
                if hdr_read == 0 {
                    return Err(IpcFrameError::EndOfStream);
                }
                return Err(IpcFrameError::TruncatedFrame {
                    expected: IPC_FRAME_HEADER_LEN,
                    available: hdr_read,
                });
            }
            hdr_read = hdr_read.saturating_add(n);
        }

        let payload_len =
            usize::try_from(u32::from_le_bytes(hdr)).map_err(|_| IpcFrameError::FrameTooLarge {
                len: usize::MAX,
                max: max_bytes,
            })?;
        if payload_len == 0 {
            return Err(IpcFrameError::ZeroLengthFrame);
        }
        if payload_len > max_bytes {
            return Err(IpcFrameError::FrameTooLarge {
                len: payload_len,
                max: max_bytes,
            });
        }

        // Grow buffer incrementally so a 4-byte spoofed length cannot force immediate 1 MiB alloc.
        let mut out = Vec::with_capacity(payload_len.min(CHUNK_ALLOC_STEP));
        let mut scratch = vec![0u8; payload_len.min(CHUNK_ALLOC_STEP)];
        while out.len() < payload_len {
            let remaining = payload_len.saturating_sub(out.len());
            let want = remaining.min(scratch.len());
            let Some(chunk_buf) = scratch.get_mut(..want) else {
                break;
            };
            let n = self.inner.read_chunk_until(chunk_buf, deadline)?;
            if n == 0 {
                return Err(IpcFrameError::TruncatedFrame {
                    expected: payload_len,
                    available: out.len(),
                });
            }
            if let Some(filled) = scratch.get(..n) {
                out.extend_from_slice(filled);
            }
        }
        Ok(out)
    }
}

fn duration_ms_u64(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1)
}

/// Creates OS anonymous pipes (`stdin`/`stdout`) for a supervised child without shared shell handles.
pub fn create_inherited_stdio_pair() -> io::Result<InheritedStdioPair> {
    let (to_child_r, parent_w) = io::pipe()?;
    let (parent_r, to_parent_w) = io::pipe()?;
    Ok((
        DuplexPipe::new(parent_r, parent_w),
        (to_child_r, to_parent_w),
    ))
}
