// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Windows named pipe server acceptor enforcing `FILE_FLAG_FIRST_PIPE_INSTANCE`,
//! `PIPE_REJECT_REMOTE_CLIENTS`, explicit SDDL DACL, and non-inheritable overlapped handles.

#[cfg(windows)]
mod win_srv {
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::windows::io::{
        AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle, RawHandle,
    };
    use std::ptr::null_mut;
    use std::time::Duration;

    use grdr_wire::endpoint::validate_windows_pipe_name;
    use jiff::Timestamp;
    use windows_sys::Win32::Foundation::{
        ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, FILETIME, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    use crate::IpcError;
    use crate::endpoint::LocalEndpointAddress;
    use crate::transport::{Acceptor, IpcDeadline, Link, TimestampSource};
    use crate::windows_pipe::WindowsNamedPipeLink;

    const PIPE_BUF_BYTES: u32 = 64 * 1024;
    const FILETIME_UNIX_EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;

    struct LocalSdGuard(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSdGuard {
        #[allow(
            unsafe_code,
            reason = "Frees Win32 SDDL security descriptor via LocalFree"
        )]
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct WindowsServerPipeStream {
        link: WindowsNamedPipeLink,
        connected_at_100ns: u64,
    }

    #[derive(Debug)]
    pub struct WindowsNamedPipeAcceptor {
        address: LocalEndpointAddress,
        wide_name: Vec<u16>,
        sddl: String,
        pending_instance: Option<OwnedHandle>,
        stopped: bool,
    }

    impl WindowsServerPipeStream {
        #[must_use]
        pub const fn connected_at_100ns(&self) -> u64 {
            self.connected_at_100ns
        }

        #[must_use]
        pub const fn link(&self) -> &WindowsNamedPipeLink {
            &self.link
        }

        pub fn link_mut(&mut self) -> &mut WindowsNamedPipeLink {
            &mut self.link
        }

        #[must_use]
        pub fn borrowed_handle(&self) -> BorrowedHandle<'_> {
            self.link.borrowed_handle()
        }
    }

    impl AsHandle for WindowsServerPipeStream {
        fn as_handle(&self) -> BorrowedHandle<'_> {
            self.link.borrowed_handle()
        }
    }

    impl AsRawHandle for WindowsServerPipeStream {
        fn as_raw_handle(&self) -> RawHandle {
            self.link.raw_handle()
        }
    }

    impl Read for WindowsServerPipeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.link.read(buf)
        }
    }

    impl Write for WindowsServerPipeStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.link.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.link.flush()
        }
    }

    impl Link for WindowsServerPipeStream {
        fn send_bytes(&mut self, frame_bytes: &[u8]) -> Result<(), IpcError> {
            self.link.send_bytes(frame_bytes)
        }

        fn recv_bytes(&mut self) -> Result<Vec<u8>, IpcError> {
            self.link.recv_bytes()
        }

        fn set_deadlines(&mut self, read: IpcDeadline, write: IpcDeadline) -> Result<(), IpcError> {
            self.link.set_deadlines(read, write)
        }

        fn connected_at(&self) -> Timestamp {
            self.link.connected_at()
        }
    }

    impl WindowsNamedPipeAcceptor {
        pub fn bind(pipe_name: &str, sddl: &str) -> Result<Self, IpcError> {
            validate_windows_pipe_name(pipe_name)
                .map_err(|e| IpcError::InvalidAddress(e.to_string()))?;
            if sddl.trim().is_empty() || sddl.contains('\0') {
                return Err(IpcError::InvalidAddress(
                    "named pipe server SDDL cannot be empty or contain NUL".to_string(),
                ));
            }
            let mut wide_name: Vec<u16> = pipe_name.encode_utf16().collect();
            wide_name.push(0);
            let first = create_pipe_instance(&wide_name, sddl, true)?;
            Ok(Self {
                address: LocalEndpointAddress::WindowsPipe {
                    pipe_name: pipe_name.to_string(),
                },
                wide_name,
                sddl: sddl.to_string(),
                pending_instance: Some(first),
                stopped: false,
            })
        }

        #[must_use]
        pub fn pipe_name(&self) -> &str {
            match &self.address {
                LocalEndpointAddress::WindowsPipe { pipe_name } => pipe_name,
                LocalEndpointAddress::UnixSocket { .. } => "",
            }
        }

        pub fn accept(&mut self, timeout: Duration) -> Result<WindowsServerPipeStream, IpcError> {
            self.accept_inner(timeout, None)
        }

        pub fn accept_with_clock(
            &mut self,
            timeout: Duration,
            clock: &dyn TimestampSource,
        ) -> Result<WindowsServerPipeStream, IpcError> {
            self.accept_inner(timeout, Some(clock))
        }

        fn accept_inner(
            &mut self,
            timeout: Duration,
            clock: Option<&dyn TimestampSource>,
        ) -> Result<WindowsServerPipeStream, IpcError> {
            if self.stopped {
                return Err(IpcError::Stopped);
            }
            let Some(instance) = self.pending_instance.take() else {
                return Err(IpcError::Stopped);
            };

            let connected_at_100ns = match wait_connect(&instance, timeout) {
                Ok(ts) => ts,
                Err(err) => {
                    disconnect_handle(&instance);
                    self.pending_instance = Some(instance);
                    return Err(err);
                }
            };

            // Pre-create standby server handle BEFORE releasing connected `instance` so the pipe
            // always keeps >= 1 open kernel server handle (zero pipe-squatting gap).
            let next = match create_pipe_instance(&self.wide_name, &self.sddl, false) {
                Ok(h) => h,
                Err(err) => {
                    disconnect_handle(&instance);
                    self.pending_instance = Some(instance);
                    return Err(err);
                }
            };
            self.pending_instance = Some(next);

            let connected_ts = clock
                .map(TimestampSource::now_utc)
                .unwrap_or_else(|| filetime_to_timestamp(connected_at_100ns));
            let file = File::from(instance);
            let link = WindowsNamedPipeLink::from_overlapped_file(file, connected_ts);
            Ok(WindowsServerPipeStream {
                link,
                connected_at_100ns,
            })
        }
    }

    impl Acceptor for WindowsNamedPipeAcceptor {
        type AcceptedLink = WindowsServerPipeStream;

        fn accept(
            &mut self,
            deadline: IpcDeadline,
            clock: &dyn TimestampSource,
        ) -> Result<Self::AcceptedLink, IpcError> {
            self.accept_with_clock(deadline.as_duration(), clock)
        }

        fn stop(&mut self) {
            self.stopped = true;
            self.pending_instance.take();
        }

        fn address(&self) -> &LocalEndpointAddress {
            &self.address
        }
    }

    #[allow(unsafe_code, reason = "Win32 DisconnectNamedPipe on rollback recovery")]
    fn disconnect_handle(handle: &OwnedHandle) {
        // SAFETY: `handle` is an open server pipe instance owned by `WindowsNamedPipeAcceptor`.
        unsafe {
            let _ = DisconnectNamedPipe(handle.as_raw_handle() as HANDLE);
        }
    }

    #[allow(
        unsafe_code,
        reason = "Win32 SDDL parse and CreateNamedPipeW with non-inheritable handle"
    )]
    fn create_pipe_instance(
        wide_name: &[u16],
        sddl: &str,
        first: bool,
    ) -> Result<OwnedHandle, IpcError> {
        let mut wide_sddl: Vec<u16> = sddl.encode_utf16().collect();
        wide_sddl.push(0);
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `wide_sddl` is NUL-terminated UTF-16 and `sd` is freed on all paths by `LocalSdGuard`.
        let conv_ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        let _sd_guard = LocalSdGuard(sd);
        if conv_ok == 0 || sd.is_null() {
            return Err(IpcError::InvalidAddress(format!(
                "invalid SDDL security descriptor: {}",
                io::Error::last_os_error()
            )));
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

        // SAFETY: `wide_name` and `sa` stay valid across synchronous pipe creation.
        let raw = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                open_mode,
                pipe_mode,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUF_BYTES,
                PIPE_BUF_BYTES,
                0,
                &sa,
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(IpcError::Io(format!(
                "CreateNamedPipeW failed: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: validated non-null, non-INVALID_HANDLE_VALUE handle owned exclusively here.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    #[allow(
        unsafe_code,
        reason = "Win32 overlapped ConnectNamedPipe and safe cancellation drain"
    )]
    fn wait_connect(handle: &OwnedHandle, timeout: Duration) -> Result<u64, IpcError> {
        let raw_h = handle.as_raw_handle() as HANDLE;
        // SAFETY: creates an unnamed manual-reset Win32 event handle wrapped immediately in `OwnedHandle`.
        let event_raw = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };
        if event_raw.is_null() || event_raw == INVALID_HANDLE_VALUE {
            return Err(IpcError::Io(format!(
                "CreateEventW failed: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: validated handle wrapped cleanly in `OwnedHandle`.
        let event = unsafe { OwnedHandle::from_raw_handle(event_raw) };

        // SAFETY: `OVERLAPPED` is valid all-zero C POD struct.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.as_raw_handle() as HANDLE;

        // SAFETY: `raw_h` is valid overlapped pipe handle and `overlapped` stays pinned until drained.
        let rc = unsafe { ConnectNamedPipe(raw_h, &mut overlapped) };
        if rc != 0 {
            return Ok(current_filetime_100ns());
        }
        // SAFETY: no safety preconditions.
        let err = unsafe { GetLastError() };
        if err == ERROR_PIPE_CONNECTED {
            return Ok(current_filetime_100ns());
        }
        if err != ERROR_IO_PENDING {
            return Err(IpcError::Io(format!(
                "ConnectNamedPipe failed with win32 error {err}"
            )));
        }

        let bounded_ms = timeout.as_millis().clamp(1, u128::from(u32::MAX - 1));
        let wait_ms = u32::try_from(bounded_ms).unwrap_or(1);
        // SAFETY: valid event handle and strictly non-INFINITE wait_ms.
        let wait_rc = unsafe { WaitForSingleObject(overlapped.hEvent, wait_ms) };
        if wait_rc == WAIT_OBJECT_0 {
            let mut transferred: u32 = 0;
            // SAFETY: overlapped wait succeeded; query result synchronously before returning.
            let done = unsafe { GetOverlappedResult(raw_h, &overlapped, &mut transferred, 1) };
            if done == 0 {
                return Err(IpcError::Io(format!(
                    "GetOverlappedResult(ConnectNamedPipe) failed: {}",
                    io::Error::last_os_error()
                )));
            }
            return Ok(current_filetime_100ns());
        }

        // SAFETY: cancel pending overlapped connect and check whether completion won the race.
        let completed_during_cancel = unsafe {
            let _ = CancelIoEx(raw_h, &overlapped);
            let mut transferred: u32 = 0;
            GetOverlappedResult(raw_h, &overlapped, &mut transferred, 1) != 0
        };
        if completed_during_cancel {
            return Ok(current_filetime_100ns());
        }
        if wait_rc == WAIT_TIMEOUT {
            return Err(IpcError::DeadlineExceeded {
                timeout_ms: u64::try_from(bounded_ms).unwrap_or(u64::MAX),
            });
        }
        Err(IpcError::Io(format!(
            "WaitForSingleObject(ConnectNamedPipe) failed with status {wait_rc}"
        )))
    }

    #[allow(unsafe_code, reason = "Win32 GetSystemTimeAsFileTime stack write")]
    fn current_filetime_100ns() -> u64 {
        let mut ft = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // SAFETY: stack `FILETIME` passed cleanly.
        unsafe {
            GetSystemTimeAsFileTime(&mut ft);
        }
        (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
    }

    fn filetime_to_timestamp(ft_100ns: u64) -> Timestamp {
        let since_unix_100ns = ft_100ns.saturating_sub(FILETIME_UNIX_EPOCH_DIFF_100NS);
        let secs = i64::try_from(since_unix_100ns / 10_000_000).unwrap_or(0);
        Timestamp::from_second(secs).unwrap_or(Timestamp::UNIX_EPOCH)
    }
}

#[cfg(windows)]
pub use win_srv::{WindowsNamedPipeAcceptor, WindowsServerPipeStream};
