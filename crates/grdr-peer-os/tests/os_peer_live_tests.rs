// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#[cfg(unix)]
#[test]
fn unix_socketpair_kernel_peer_read_and_live_path_check() {
    let res = run_unix_peer_check();
    assert!(res.is_ok(), "{res:?}");
}

#[cfg(unix)]
fn run_unix_peer_check() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    use grdr_os_clock::{Clock, SystemClock};
    use grdr_peer_os::PeerError;
    use grdr_peer_os::unix_peer::{
        UnixConnectStamp, inspect_unix_path_live, read_unix_socket_peer,
        refresh_unix_path_post_connect,
    };
    use grdr_wire::endpoint::{PathExpectation, check_directory_path, check_path};
    use grdr_wire::peer_auth::{OsPeerClaims, Profile, Refusal, ServerIdentityPolicy};
    use grdr_wire::peer_policy::verify_client_peer;

    let (a, _b) = UnixStream::pair()?;
    let clk = SystemClock::new();
    let boot_ms = clk
        .boot_uptime()
        .map_or(1, |d| u64::try_from(d.as_millis()).unwrap_or(1));
    let wall_us = clk
        .now_wall()
        .map_or(1, |ts| u64::try_from(ts.as_microsecond()).unwrap_or(1));
    let stamp = UnixConnectStamp {
        boot_uptime_ms: boot_ms,
        wall_unix_us: wall_us,
    };

    let held = read_unix_socket_peer(a.as_fd(), stamp)?;
    let claims = held.claims;
    let policy = ServerIdentityPolicy {
        profile: Profile::User,
        allowed_client_uids: vec![claims.uid],
        allowed_windows_sids: vec![],
        minimum_integrity_rid: 0,
        reject_app_container: true,
        require_start_time_before_connect: claims.peer_started_at_ticks.is_some(),
        require_open_as_self_pipe_check: true,
        require_kernel_peer_token: true,
    };
    let verified = verify_client_peer(&OsPeerClaims::Unix(claims), stamp.for_platform(), &policy)?;
    if verified.uid().is_none() {
        return Err("expected verified unix uid".into());
    }

    // Connected stamp before process boot/wall start must trigger PidReuse.
    let zero_stamp = UnixConnectStamp {
        boot_uptime_ms: 1,
        wall_unix_us: 1,
    };
    if !matches!(
        read_unix_socket_peer(a.as_fd(), zero_stamp),
        Err(PeerError::PidReuse)
    ) {
        return Err("expected PidReuse when stamp precedes process start".into());
    }

    // Un-refreshed inspect_unix_path_live initializes post_dev=0, so check_directory_path refuses.
    // Refreshing post-connect restores dev/ino, and /tmp is still refused as world-writable.
    let tmp_dir = std::env::temp_dir();
    if let Ok(mut facts) = inspect_unix_path_live(&tmp_dir) {
        let exp = PathExpectation {
            profile: Profile::User,
            trusted_owner_uids: vec![0, verified.uid().unwrap_or(0)],
            trusted_group_gids: vec![0, verified.gid().unwrap_or(0)],
            allow_world_writable_socket_leaf: false,
        };
        if !matches!(
            check_directory_path(&facts, &exp),
            Err(Refusal::UnsafeEndpointPath(_))
        ) {
            return Err("unrefreshed facts must fail check_directory_path".into());
        }
        refresh_unix_path_post_connect(&mut facts, &tmp_dir)?;
        let check = check_path(&facts, &exp);
        if !matches!(check, Err(Refusal::UnsafeEndpointPath(_))) {
            return Err("expected UnsafeEndpointPath for world-writable /tmp directory".into());
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_peer_auth_sid_time_and_non_windows_unix_refusal() {
    let res = run_windows_peer_checks();
    assert!(res.is_ok(), "{res:?}");
}

#[cfg(windows)]
fn run_windows_peer_checks() -> Result<(), Box<dyn std::error::Error>> {
    use grdr_peer_os::PeerError;
    use grdr_peer_os::unix_peer::{
        UnixConnectStamp, inspect_unix_path_live, read_unix_socket_peer,
    };
    use grdr_peer_os::win_peer::{current_filetime_100ns, current_process_sid, probe_scm_services};

    let t1 = current_filetime_100ns();
    if t1 == 0 {
        return Err("expected non-zero FILETIME".into());
    }
    let sid = current_process_sid()?;
    if !sid.starts_with("S-1-") {
        return Err(format!("invalid current process SID `{sid}`").into());
    }
    let probes = probe_scm_services(&["GuardrailsNonExistentServiceForUnitTest"]);
    if probes.len() != 1 || probes.first().is_none_or(Option::is_some) {
        return Err("missing SCM service must yield None".into());
    }
    if !matches!(
        read_unix_socket_peer(UnixConnectStamp::default()),
        Err(PeerError::Unverifiable(_))
    ) {
        return Err("non-Unix peer reader must fail closed".into());
    }
    if !matches!(
        inspect_unix_path_live(std::path::Path::new("/tmp")),
        Err(PeerError::PathUnsafe(_))
    ) {
        return Err("non-Unix inspect_unix_path_live must fail closed".into());
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_live_named_pipe_roundtrip_verifies_open_as_self_and_server_owner() {
    let res = run_windows_pipe_live_roundtrip();
    assert!(res.is_ok(), "{res:?}");
}

#[cfg(windows)]
fn run_windows_pipe_live_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsHandle, FromRawHandle, OwnedHandle};

    use grdr_peer_os::win_peer::{
        current_filetime_100ns, current_process_sid, read_windows_pipe_client_pre,
        read_windows_pipe_server, verify_windows_pipe_client_post_read,
    };
    use grdr_wire::peer_auth::{ClientIdentityPolicy, OsPeerClaims, Profile, ServerIdentityPolicy};
    use grdr_wire::peer_policy::{verify_client_peer, verify_server_peer};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    let sid = current_process_sid()?;
    let pipe_name = format!(r"\\.\pipe\grdr-peer-live-{}", std::process::id());
    let mut wide: Vec<u16> = pipe_name.encode_utf16().collect();
    wide.push(0);

    #[allow(
        unsafe_code,
        reason = "Live named pipe integration test handle creation"
    )]
    let raw = {
        // SAFETY: `wide` is NUL-terminated UTF-16 pipe name valid for `CreateNamedPipeW`.
        unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        }
    };
    if raw.is_null() || raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(format!(
            "CreateNamedPipeW failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    #[allow(unsafe_code, reason = "Valid CreateNamedPipeW handle owned for test")]
    let server_handle = {
        // SAFETY: `raw` checked non-null and not INVALID_HANDLE_VALUE above.
        unsafe { OwnedHandle::from_raw_handle(raw) }
    };

    let client_pipe = pipe_name.clone();
    let expected_sid = sid.clone();
    let client_join = std::thread::spawn(move || -> Result<(), String> {
        let mut client = OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&client_pipe)
            .map_err(|e| e.to_string())?;
        let pre = Vec::new();
        let server_claims = read_windows_pipe_server(client.as_handle(), Profile::User, &[], &pre)
            .map_err(|e| e.to_string())?;
        let policy = ClientIdentityPolicy {
            profile: Profile::User,
            allowed_server_uids: Vec::new(),
            expected_windows_sids: vec![expected_sid],
            minimum_integrity_rid: 0x2000,
            require_kernel_peer_token: true,
            require_start_time_before_connect: true,
        };
        let connected = current_filetime_100ns().saturating_add(10_000_000);
        verify_server_peer(&OsPeerClaims::Windows(server_claims), connected, &policy)
            .map_err(|e| e.to_string())?;
        client.write_all(&[0x42]).map_err(|e| e.to_string())?;
        let mut ack = [0u8; 1];
        client.read_exact(&mut ack).map_err(|e| e.to_string())?;
        Ok(())
    });

    #[allow(
        unsafe_code,
        reason = "ConnectNamedPipe accepts single live test client"
    )]
    let conn_ok = {
        // SAFETY: `raw` remains owned by `server_file`/`server_handle` and accepts a single client.
        unsafe { ConnectNamedPipe(raw, std::ptr::null_mut()) }
    };
    if conn_ok == 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED as i32) {
            return Err(format!("ConnectNamedPipe failed: {err}").into());
        }
    }

    let (pre_claims, proc_hold) = read_windows_pipe_client_pre(server_handle.as_handle())?;
    let mut server_file = std::fs::File::from(server_handle);
    let mut byte = [0u8; 1];
    server_file.read_exact(&mut byte)?;
    let post_claims = verify_windows_pipe_client_post_read(
        server_file.as_handle(),
        &proc_hold,
        pre_claims.pid,
        &pre_claims.peer_sid,
    )?;
    if !post_claims.thread_token_open_as_self {
        return Err("expected OpenAsSelf=TRUE verification".into());
    }
    let srv_policy = ServerIdentityPolicy {
        profile: Profile::User,
        allowed_client_uids: Vec::new(),
        allowed_windows_sids: vec![sid],
        minimum_integrity_rid: 0x2000,
        reject_app_container: true,
        require_start_time_before_connect: true,
        require_open_as_self_pipe_check: true,
        require_kernel_peer_token: false,
    };
    let connected = current_filetime_100ns().saturating_add(10_000_000);
    let verified = verify_client_peer(&OsPeerClaims::Windows(post_claims), connected, &srv_policy)?;
    if verified.windows_sid().is_none() {
        return Err("expected verified Windows client SID".into());
    }
    server_file.write_all(&[0x99])?;
    let join_res = client_join.join().map_err(|_| "client thread panicked")?;
    join_res.map_err(|e| e.into())
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[test]
fn os_peer_reader_walks_live_parent_chain_with_monotonic_start_times() {
    use grdr_peer_os::{OsPeerReader, PeerReader};

    let reader = OsPeerReader;
    let self_pid = std::process::id();
    let chain = reader
        .read_parent_chain(self_pid, 16)
        .expect("live parent chain on Tier-1 OS");
    assert!(!chain.is_empty());
    assert_eq!(chain[0].pid, self_pid);
    assert!(chain[0].exe_path.is_some());
    assert!(chain[0].started_at_ticks > 0);
    for pair in chain.windows(2) {
        assert!(pair[1].started_at_ticks <= pair[0].started_at_ticks);
    }

    let exe = reader
        .read_exe_identity(self_pid)
        .expect("read current process exe identity");
    assert!(exe.exe_path.is_some());

    let missing = reader.read_parent_chain(u32::MAX - 1, 16);
    assert!(missing.is_err());
}
