// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Deadline-bounded `DuplexPipe` implementation over OS anonymous pipes (`Unix` `poll` + `O_NONBLOCK`
//! and Windows `PeekNamedPipe` / `PIPE_NOWAIT` wait loop).

use std::io::{self, ErrorKind, Read, Write};
use std::time::{Duration, Instant};

use grdr_wire::frame::IpcFrameError;
use grdr_wire::limits::embedded_limits;

use crate::proto_io::ProtoTransportIo;

const DEFAULT_PROTO_DEADLINE_MS: u64 = 1_500;

#[derive(Debug)]
pub struct DuplexPipe<R, W> {
    reader: R,
    writer: W,
    read_timeout: Duration,
    write_timeout: Duration,
}

#[cfg(unix)]
struct NonBlockGuard {
    fd: std::os::fd::RawFd,
    prev_flags: libc::c_int,
    changed: bool,
}

#[cfg(windows)]
struct PipeWaitModeGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
    restored_mode: u32,
    active: bool,
}

#[cfg(unix)]
impl Drop for NonBlockGuard {
    #[allow(
        unsafe_code,
        reason = "Restores original POSIX fd status flags after write"
    )]
    fn drop(&mut self) {
        if self.changed {
            // SAFETY: `self.fd` remains open across the scope and `self.prev_flags` came from F_GETFL.
            unsafe {
                let _ = libc::fcntl(self.fd, libc::F_SETFL, self.prev_flags);
            }
        }
    }
}

#[cfg(windows)]
impl Drop for PipeWaitModeGuard {
    #[allow(
        unsafe_code,
        reason = "Restores Win32 PIPE_WAIT mode on anonymous pipe handle"
    )]
    fn drop(&mut self) {
        if self.active {
            let mode = self.restored_mode;
            // SAFETY: `self.handle` is open pipe handle owned by writer for scope of write call.
            unsafe {
                let _ = windows_sys::Win32::System::Pipes::SetNamedPipeHandleState(
                    self.handle,
                    &mode,
                    std::ptr::null(),
                    std::ptr::null(),
                );
            }
        }
    }
}

impl<R, W> DuplexPipe<R, W> {
    #[must_use]
    pub fn new(reader: R, writer: W) -> Self {
        let default_dur = Duration::from_millis(
            embedded_limits().map_or(DEFAULT_PROTO_DEADLINE_MS, |l| l.read_timeout_ms),
        );
        Self {
            reader,
            writer,
            read_timeout: default_dur,
            write_timeout: default_dur,
        }
    }

    pub fn set_deadlines(&mut self, read: Duration, write: Duration) {
        self.read_timeout = read.max(Duration::from_millis(1));
        self.write_timeout = write.max(Duration::from_millis(1));
    }

    pub fn split_mut(&mut self) -> (&mut R, &mut W) {
        (&mut self.reader, &mut self.writer)
    }
}

impl<R: Read, W: Write> Read for DuplexPipe<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R: Read, W: Write> Write for DuplexPipe<R, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn duration_ms_u64(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1)
}

#[cfg(unix)]
#[allow(
    unsafe_code,
    reason = "POSIX F_GETFL/F_SETFL O_NONBLOCK enables bounded pipe writes with RAII restore"
)]
fn enter_nonblocking(fd: std::os::fd::RawFd) -> Result<NonBlockGuard, IpcFrameError> {
    // SAFETY: `fd` is borrowed open descriptor for write duration.
    let prev_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if prev_flags < 0 {
        return Err(IpcFrameError::Io {
            detail: io::Error::last_os_error().to_string(),
        });
    }
    if (prev_flags & libc::O_NONBLOCK) != 0 {
        return Ok(NonBlockGuard {
            fd,
            prev_flags,
            changed: false,
        });
    }
    // SAFETY: setting O_NONBLOCK avoids indefinite blocking in write().
    if unsafe { libc::fcntl(fd, libc::F_SETFL, prev_flags | libc::O_NONBLOCK) } != 0 {
        return Err(IpcFrameError::Io {
            detail: io::Error::last_os_error().to_string(),
        });
    }
    Ok(NonBlockGuard {
        fd,
        prev_flags,
        changed: true,
    })
}

#[cfg(unix)]
#[allow(
    unsafe_code,
    reason = "POSIX poll waits bounded time for POLLIN/POLLOUT"
)]
fn poll_fd(
    fd: std::os::fd::RawFd,
    events: libc::c_short,
    rem: Duration,
) -> Result<bool, IpcFrameError> {
    let poll_ms = i32::try_from(rem.as_millis().clamp(1, i32::MAX as u128)).unwrap_or(1);
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    // SAFETY: stack `pollfd` passed cleanly to `libc::poll`.
    let rc = unsafe { libc::poll(&raw mut pfd, 1, poll_ms) };
    if rc == 0 {
        return Ok(false);
    }
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == ErrorKind::Interrupted {
            return Ok(true);
        }
        return Err(IpcFrameError::Io {
            detail: err.to_string(),
        });
    }
    Ok(true)
}

#[cfg(unix)]
impl<R, W> ProtoTransportIo for DuplexPipe<R, W>
where
    R: Read + std::os::fd::AsRawFd,
    W: Write + std::os::fd::AsRawFd,
{
    fn read_chunk_until(
        &mut self,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, IpcFrameError> {
        let fd = self.reader.as_raw_fd();
        loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(IpcFrameError::TimedOut {
                    timeout_ms: duration_ms_u64(self.read_timeout),
                });
            };
            if !poll_fd(fd, libc::POLLIN, rem)? {
                return Err(IpcFrameError::TimedOut {
                    timeout_ms: duration_ms_u64(self.read_timeout),
                });
            }
            match self.reader.read(buf) {
                Ok(n) => return Ok(n),
                Err(err)
                    if matches!(err.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) =>
                {
                    continue;
                }
                Err(err) => {
                    return Err(IpcFrameError::Io {
                        detail: err.to_string(),
                    });
                }
            }
        }
    }

    fn write_all_until(&mut self, buf: &[u8], deadline: Instant) -> Result<(), IpcFrameError> {
        let fd = self.writer.as_raw_fd();
        let _guard = enter_nonblocking(fd)?;
        let mut offset = 0usize;
        while offset < buf.len() {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(IpcFrameError::TimedOut {
                    timeout_ms: duration_ms_u64(self.write_timeout),
                });
            };
            if !poll_fd(fd, libc::POLLOUT, rem)? {
                return Err(IpcFrameError::TimedOut {
                    timeout_ms: duration_ms_u64(self.write_timeout),
                });
            }
            let Some(chunk) = buf.get(offset..) else {
                break;
            };
            match self.writer.write(chunk) {
                Ok(0) => {
                    return Err(IpcFrameError::Io {
                        detail: "zero-byte write on anonymous pipe".to_string(),
                    });
                }
                Ok(n) => offset = offset.saturating_add(n),
                Err(err)
                    if matches!(err.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) =>
                {
                    continue;
                }
                Err(err) => {
                    return Err(IpcFrameError::Io {
                        detail: err.to_string(),
                    });
                }
            }
        }
        self.writer.flush().map_err(|err| IpcFrameError::Io {
            detail: err.to_string(),
        })
    }

    fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    fn set_timeouts(&mut self, read: Duration, write: Duration) -> Result<(), IpcFrameError> {
        self.set_deadlines(read, write);
        Ok(())
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Queries Win32 handle type and enables PIPE_NOWAIT with RAII restore to PIPE_WAIT"
)]
fn enter_pipe_nowait(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<PipeWaitModeGuard> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
    use windows_sys::Win32::System::Pipes::{PIPE_NOWAIT, PIPE_WAIT, SetNamedPipeHandleState};

    // SAFETY: `handle` is open writer handle from `AsRawHandle`.
    let file_type = unsafe { GetFileType(handle) };
    if file_type != FILE_TYPE_PIPE {
        return None;
    }
    let nowait = PIPE_NOWAIT;
    let ok;
    // SAFETY: setting PIPE_NOWAIT on anonymous pipe avoids unbounded blocking when buffer is full.
    unsafe {
        ok = SetNamedPipeHandleState(handle, &nowait, std::ptr::null(), std::ptr::null());
    }
    if ok == 0 {
        return None;
    }
    Some(PipeWaitModeGuard {
        handle,
        restored_mode: PIPE_WAIT,
        active: true,
    })
}

#[cfg(windows)]
impl<R, W> ProtoTransportIo for DuplexPipe<R, W>
where
    R: Read + std::os::windows::io::AsRawHandle,
    W: Write + std::os::windows::io::AsRawHandle,
{
    #[allow(
        unsafe_code,
        reason = "Win32 PeekNamedPipe polls anonymous pipe readiness without blocking indefinitely"
    )]
    fn read_chunk_until(
        &mut self,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, IpcFrameError> {
        use windows_sys::Win32::Foundation::{
            ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, GetLastError, HANDLE,
        };
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;

        let handle = self.reader.as_raw_handle() as HANDLE;
        loop {
            let mut avail: u32 = 0;
            // SAFETY: `handle` is open readable pipe handle and `avail` is stack storage.
            let ok = unsafe {
                PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut avail,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // SAFETY: thread-local Win32 error code read.
                let code = unsafe { GetLastError() };
                if code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED {
                    return Ok(0);
                }
                let raw = i32::try_from(code).unwrap_or(0);
                return Err(IpcFrameError::Io {
                    detail: io::Error::from_raw_os_error(raw).to_string(),
                });
            }
            if avail > 0 {
                let want = buf
                    .len()
                    .min(usize::try_from(avail).unwrap_or(buf.len()))
                    .max(1);
                let Some(slice) = buf.get_mut(..want) else {
                    return Ok(0);
                };
                return self.reader.read(slice).map_err(|err| IpcFrameError::Io {
                    detail: err.to_string(),
                });
            }
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(IpcFrameError::TimedOut {
                    timeout_ms: duration_ms_u64(self.read_timeout),
                });
            };
            std::thread::sleep(Duration::from_millis(2).min(rem));
        }
    }

    fn write_all_until(&mut self, buf: &[u8], deadline: Instant) -> Result<(), IpcFrameError> {
        use windows_sys::Win32::Foundation::{ERROR_NO_DATA, ERROR_PIPE_BUSY, HANDLE};

        let handle = self.writer.as_raw_handle() as HANDLE;
        let _guard = enter_pipe_nowait(handle);
        let mut offset = 0usize;
        while offset < buf.len() {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(IpcFrameError::TimedOut {
                    timeout_ms: duration_ms_u64(self.write_timeout),
                });
            };
            let end = offset.saturating_add(4096).min(buf.len());
            let Some(chunk) = buf.get(offset..end) else {
                break;
            };
            match self.writer.write(chunk) {
                Ok(0) => {
                    std::thread::sleep(Duration::from_millis(2).min(rem));
                }
                Ok(n) => offset = offset.saturating_add(n),
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err)
                    if err.kind() == ErrorKind::WouldBlock
                        || matches!(
                            err.raw_os_error(),
                            Some(raw) if raw == ERROR_NO_DATA as i32 || raw == ERROR_PIPE_BUSY as i32
                        ) =>
                {
                    std::thread::sleep(Duration::from_millis(2).min(rem));
                }
                Err(err) => {
                    return Err(IpcFrameError::Io {
                        detail: err.to_string(),
                    });
                }
            }
        }
        self.writer.flush().map_err(|err| IpcFrameError::Io {
            detail: err.to_string(),
        })
    }

    fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    fn set_timeouts(&mut self, read: Duration, write: Duration) -> Result<(), IpcFrameError> {
        self.set_deadlines(read, write);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplex_pipe_write_all_until_times_out_when_pipe_buffer_full() {
        let (_reader, writer) = io::pipe().expect("os pipe");
        let (dummy_r, _dummy_w) = io::pipe().expect("dummy pipe");
        let mut duplex = DuplexPipe::new(dummy_r, writer);
        duplex.set_deadlines(Duration::from_millis(50), Duration::from_millis(50));

        let payload = vec![0x5Au8; 256 * 1024];
        let deadline = Instant::now() + Duration::from_millis(60);
        let err = duplex
            .write_all_until(&payload, deadline)
            .expect_err("full un-drained pipe must time out");
        assert!(matches!(err, IpcFrameError::TimedOut { .. }), "{err:?}");
    }
}
