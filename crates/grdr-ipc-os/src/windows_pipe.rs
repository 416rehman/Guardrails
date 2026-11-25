// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::time::{Duration, Instant};

use jiff::Timestamp;
use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_PIPE_BUSY, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use crate::IpcError;
use crate::endpoint::{
    LocalEndpointAddress, PipeClientAccessPolicy, PipeImpersonationLevel, TargetOsKind,
    WindowsPipeOpenPolicy, validate_endpoint_address,
};
use crate::transport::{
    Connector, IpcDeadline, Link, TimestampSource, parse_and_validate_frame_header,
    validate_outgoing_frame,
};

const FRAME_HEADER_LEN: usize = 10;
const FIVE_RIGHT_CLIENT_MASK: u32 = 0x0012_0083;
const SQOS_IDENTIFICATION: u32 = 0x0011_0000;
const ERROR_FILE_NOT_FOUND_RAW: i32 = 2;

#[derive(Debug)]
pub struct WindowsNamedPipeLink {
    pipe: File,
    connected_at: Timestamp,
    read_deadline: IpcDeadline,
    write_deadline: IpcDeadline,
}

#[derive(Debug, Clone, Default)]
pub struct WindowsNamedPipeConnector {
    policy: WindowsPipeOpenPolicy,
}

impl WindowsNamedPipeLink {
    pub fn from_overlapped_file(pipe: File, connected_at: Timestamp) -> Self {
        Self {
            pipe,
            connected_at,
            read_deadline: IpcDeadline::call_default(),
            write_deadline: IpcDeadline::call_default(),
        }
    }

    fn read_exact_with_deadline(
        &self,
        buf: &mut [u8],
        deadline: IpcDeadline,
    ) -> Result<(), IpcError> {
        let start = Instant::now();
        let mut offset = 0usize;
        while offset < buf.len() {
            let Some(remaining) = deadline.as_duration().checked_sub(start.elapsed()) else {
                return Err(IpcError::DeadlineExceeded {
                    timeout_ms: deadline.as_millis_u64(),
                });
            };
            let Some(chunk) = buf.get_mut(offset..) else {
                return Err(IpcError::Io("buffer offset out of bounds".into()));
            };
            let read_n = overlapped_read(&self.pipe, chunk, remaining, deadline)?;
            if read_n == 0 {
                return Err(IpcError::Io("unexpected EOF on named pipe".into()));
            }
            offset = offset.saturating_add(read_n);
        }
        Ok(())
    }

    fn write_all_with_deadline(&self, buf: &[u8], deadline: IpcDeadline) -> Result<(), IpcError> {
        let start = Instant::now();
        let mut offset = 0usize;
        while offset < buf.len() {
            let Some(remaining) = deadline.as_duration().checked_sub(start.elapsed()) else {
                return Err(IpcError::DeadlineExceeded {
                    timeout_ms: deadline.as_millis_u64(),
                });
            };
            let Some(chunk) = buf.get(offset..) else {
                return Err(IpcError::Io("buffer offset out of bounds".into()));
            };
            let wrote_n = overlapped_write(&self.pipe, chunk, remaining, deadline)?;
            if wrote_n == 0 {
                return Err(IpcError::Io("zero-byte write on named pipe".into()));
            }
            offset = offset.saturating_add(wrote_n);
        }
        Ok(())
    }
}

impl Link for WindowsNamedPipeLink {
    fn send_bytes(&mut self, frame_bytes: &[u8]) -> Result<(), IpcError> {
        validate_outgoing_frame(frame_bytes)?;
        self.write_all_with_deadline(frame_bytes, self.write_deadline)
    }

    fn recv_bytes(&mut self) -> Result<Vec<u8>, IpcError> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        self.read_exact_with_deadline(&mut header, self.read_deadline)?;
        let body_len = parse_and_validate_frame_header(&header)?;
        let total = FRAME_HEADER_LEN
            .checked_add(body_len)
            .ok_or_else(|| IpcError::FrameInvalid("frame length overflow".into()))?;
        let mut frame = vec![0u8; total];
        if let Some(dst_hdr) = frame.get_mut(..FRAME_HEADER_LEN) {
            dst_hdr.copy_from_slice(&header);
        }
        if let Some(dst_body) = frame.get_mut(FRAME_HEADER_LEN..) {
            self.read_exact_with_deadline(dst_body, self.read_deadline)?;
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

impl WindowsNamedPipeConnector {
    pub fn with_policy(policy: WindowsPipeOpenPolicy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> WindowsPipeOpenPolicy {
        self.policy
    }
}

impl Connector for WindowsNamedPipeConnector {
    type ConnectedLink = WindowsNamedPipeLink;

    #[allow(
        unsafe_code,
        reason = "Win32 WaitNamedPipeW and pipe handle security checks require FFI"
    )]
    fn connect(
        &self,
        address: &LocalEndpointAddress,
        deadline: IpcDeadline,
        clock: &dyn TimestampSource,
    ) -> Result<Self::ConnectedLink, IpcError> {
        validate_endpoint_address(TargetOsKind::Windows, address)?;
        let LocalEndpointAddress::WindowsPipe { pipe_name } = address else {
            return Err(IpcError::InvalidAddress(
                "WindowsNamedPipeConnector requires WindowsPipe address".into(),
            ));
        };
        let access_mask = match self.policy.access_policy {
            PipeClientAccessPolicy::FiveRightRestrictedMask => FIVE_RIGHT_CLIENT_MASK,
        };
        let sqos_flags = match self.policy.impersonation {
            PipeImpersonationLevel::Identification => SQOS_IDENTIFICATION,
        };
        let wide_name = encode_wide_nul(pipe_name);
        let start = Instant::now();

        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .access_mode(access_mask)
                .security_qos_flags(sqos_flags)
                .custom_flags(FILE_FLAG_OVERLAPPED)
                .open(pipe_name)
            {
                Ok(file) => {
                    let connected_at = clock.now_utc();
                    let mut link = WindowsNamedPipeLink::from_overlapped_file(file, connected_at);
                    link.set_deadlines(deadline, deadline)?;
                    return Ok(link);
                }
                Err(err)
                    if err.raw_os_error()
                        == Some(i32::try_from(ERROR_PIPE_BUSY).unwrap_or(231)) =>
                {
                    let Some(remaining) = deadline.as_duration().checked_sub(start.elapsed())
                    else {
                        return Err(IpcError::DeadlineExceeded {
                            timeout_ms: deadline.as_millis_u64(),
                        });
                    };
                    let wait_ms = duration_to_wait_ms(remaining);
                    // SAFETY: `wide_name` is NUL-terminated UTF-16 valid for the call duration.
                    let ready = unsafe { WaitNamedPipeW(wide_name.as_ptr(), wait_ms) };
                    if ready == 0 && start.elapsed() >= deadline.as_duration() {
                        return Err(IpcError::DeadlineExceeded {
                            timeout_ms: deadline.as_millis_u64(),
                        });
                    }
                }
                Err(err) => {
                    if err.raw_os_error() == Some(ERROR_FILE_NOT_FOUND_RAW) {
                        return Err(IpcError::Unavailable(format!("{pipe_name}: {err}")));
                    }
                    return Err(IpcError::Io(format!("{pipe_name}: {err}")));
                }
            }
        }
    }
}

#[allow(unsafe_code, reason = "Win32 ReadFile overlapped IPC requires FFI")]
fn overlapped_read(
    file: &File,
    buf: &mut [u8],
    remaining: Duration,
    deadline: IpcDeadline,
) -> Result<usize, IpcError> {
    let event = create_manual_reset_event()?;
    let mut overlapped = zeroed_overlapped(event.as_raw_handle());
    let len = u32::try_from(
        buf.len()
            .min(usize::try_from(u32::MAX).unwrap_or(usize::MAX)),
    )
    .unwrap_or(u32::MAX);
    let handle = file.as_raw_handle() as HANDLE;

    // SAFETY: `handle` is an open overlapped pipe handle, `buf` is valid for `len` bytes,
    // and `overlapped` remains pinned on the stack until `finish_overlapped` completes or cancels.
    let ok = unsafe {
        ReadFile(
            handle,
            buf.as_mut_ptr(),
            len,
            ptr::null_mut(),
            &mut overlapped,
        )
    };
    finish_overlapped(handle, ok, &mut overlapped, &event, remaining, deadline)
}

#[allow(unsafe_code, reason = "Win32 WriteFile overlapped IPC requires FFI")]
fn overlapped_write(
    file: &File,
    buf: &[u8],
    remaining: Duration,
    deadline: IpcDeadline,
) -> Result<usize, IpcError> {
    let event = create_manual_reset_event()?;
    let mut overlapped = zeroed_overlapped(event.as_raw_handle());
    let len = u32::try_from(
        buf.len()
            .min(usize::try_from(u32::MAX).unwrap_or(usize::MAX)),
    )
    .unwrap_or(u32::MAX);
    let handle = file.as_raw_handle() as HANDLE;

    // SAFETY: `handle` is an open overlapped pipe handle, `buf` is valid for `len` bytes,
    // and `overlapped` remains on the stack until `finish_overlapped` completes or cancels.
    let ok = unsafe { WriteFile(handle, buf.as_ptr(), len, ptr::null_mut(), &mut overlapped) };
    finish_overlapped(handle, ok, &mut overlapped, &event, remaining, deadline)
}

#[allow(
    unsafe_code,
    reason = "Win32 GetOverlappedResult and CancelIoEx require FFI"
)]
fn finish_overlapped(
    handle: HANDLE,
    immediate_ok: i32,
    overlapped: &mut OVERLAPPED,
    event: &OwnedHandle,
    remaining: Duration,
    deadline: IpcDeadline,
) -> Result<usize, IpcError> {
    if immediate_ok == 0 {
        // SAFETY: Reading thread-local Win32 last error requires no preconditions.
        let last_err = unsafe { GetLastError() };
        if last_err != ERROR_IO_PENDING {
            return Err(IpcError::Io(
                std::io::Error::from_raw_os_error(i32::try_from(last_err).unwrap_or(-1))
                    .to_string(),
            ));
        }

        let wait_ms = duration_to_wait_ms(remaining);
        // SAFETY: `event` is a valid event handle owned by this stack frame.
        let wait_res = unsafe { WaitForSingleObject(event.as_raw_handle() as HANDLE, wait_ms) };
        if wait_res != WAIT_OBJECT_0 {
            // SAFETY: Cancel pending I/O and wait synchronously for kernel completion on EVERY
            // non-success wait exit (`WAIT_TIMEOUT`, `WAIT_FAILED`, `WAIT_ABANDONED`) so stack
            // `overlapped` and caller buffers are never accessed after return.
            unsafe {
                let _ = CancelIoEx(handle, overlapped);
                let mut ignored_bytes: u32 = 0;
                let _ = GetOverlappedResult(handle, overlapped, &mut ignored_bytes, 1);
            }
            if wait_res == WAIT_TIMEOUT {
                return Err(IpcError::DeadlineExceeded {
                    timeout_ms: deadline.as_millis_u64(),
                });
            }
            return Err(IpcError::Io(format!(
                "WaitForSingleObject failed with status {wait_res}"
            )));
        }
    }

    let mut transferred: u32 = 0;
    // SAFETY: The I/O operation or its event has completed; `transferred` is valid stack storage.
    let res = unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, 1) };
    if res == 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error().to_string()));
    }
    Ok(usize::try_from(transferred).unwrap_or(0))
}

#[allow(
    unsafe_code,
    reason = "Win32 CreateEventW for overlapped I/O requires FFI"
)]
fn create_manual_reset_event() -> Result<OwnedHandle, IpcError> {
    // SAFETY: Creating an unnamed manual-reset Win32 event with null security attributes.
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(IpcError::Io(std::io::Error::last_os_error().to_string()));
    }
    // SAFETY: `raw` is a newly created valid Win32 event handle returned by `CreateEventW`.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

#[allow(
    unsafe_code,
    reason = "Zero-initializing C OVERLAPPED struct requires unsafe"
)]
fn zeroed_overlapped(event: std::os::windows::io::RawHandle) -> OVERLAPPED {
    // SAFETY: `OVERLAPPED` is a plain C struct where zero-initialization with `hEvent` is valid.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = event as HANDLE;
    ov
}

fn duration_to_wait_ms(dur: Duration) -> u32 {
    let ms = dur.as_millis().max(1).min(u128::from(u32::MAX - 1));
    u32::try_from(ms).unwrap_or(1)
}

fn encode_wide_nul(input: &str) -> Vec<u16> {
    input.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::FixedTimestampSource;
    use grdr_crypto::SigningKeypair;
    use grdr_wire::{generate_nonce, sign_envelope};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    #[test]
    #[allow(
        unsafe_code,
        reason = "Test creates raw Windows named pipe server handle via CreateNamedPipeW"
    )]
    fn overlapped_named_pipe_enforces_read_deadline_on_stalled_server() {
        let pipe_name = format!(r"\\.\pipe\grdr-test-overlapped-{}", std::process::id());
        let wide = encode_wide_nul(&pipe_name);
        // SAFETY: Test-only named pipe creation with valid NUL-terminated UTF-16 name.
        let server_raw = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                0x0000_0003 | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                ptr::null(),
            )
        };
        assert_ne!(server_raw, INVALID_HANDLE_VALUE);
        // SAFETY: `server_raw` was just validated non-invalid.
        let _server_guard = unsafe { OwnedHandle::from_raw_handle(server_raw) };

        let srv_handle_val = server_raw as usize;
        let server_thread = std::thread::spawn(move || {
            let h = srv_handle_val as HANDLE;
            // SAFETY: Wait for client connection then stall without writing any bytes.
            unsafe {
                let _ = ConnectNamedPipe(h, ptr::null_mut());
            }
            std::thread::sleep(Duration::from_millis(250));
        });

        let addr = LocalEndpointAddress::WindowsPipe { pipe_name };
        let clock = FixedTimestampSource::new(Timestamp::from_second(1_700_000_000).unwrap());
        let short_deadline = IpcDeadline::from_millis_capped(40, 1_000);
        let mut link = WindowsNamedPipeConnector::default()
            .connect(&addr, short_deadline, &clock)
            .unwrap();

        let kp = SigningKeypair::generate().unwrap();
        let env = sign_envelope(
            &kp,
            generate_nonce().unwrap(),
            clock.now_utc(),
            "hi".to_string(),
        )
        .unwrap();
        link.send_envelope(&env).unwrap();

        let err = link.recv_bytes().unwrap_err();
        assert!(matches!(err, IpcError::DeadlineExceeded { .. }));
        server_thread.join().unwrap();
    }
}
