// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use grdr_crypto::SigningKeypair;
use grdr_fastpath::{FastActionClass, FastVerdict};
use grdr_os_clock::{Clock, SystemClock};
use grdr_peer_os::fs_open::create_private_dir_all;
use grdr_wire::floor_bin::{
    FloorMatchKind, FloorRuleRecord, FloorTableDocument, encode_signed_floor_table,
};
use grdr_wire::frame::{WireFrame, WirePayload};
use grdr_wire::messages::{
    DecideAckFrame, DecideVerdictFrame, EndpointServiceKind, ErrorFrame, HandoverStage, WireVerdict,
};
#[cfg(unix)]
use grdr_wire::peer_auth::accept;
#[cfg(windows)]
use grdr_wire::peer_auth::{Evidence, Refusal, accept_deferred_windows};
use grdr_wire::peer_auth::{OsPeerClaims, Profile, ServerIdentityPolicy};

use grdr_hook::dialect::{HookDialect, format_dialect_decision};
use grdr_hook::floor_fallback::evaluate_signed_floor_fallback;
use grdr_hook::ipc_client::evaluate_against_daemon_or_floor;
use grdr_hook::json_scan::scan_hook_json;
use grdr_hook::offline_spool::{
    HOOK_OFFLINE_SPOOL_CAP_BYTES, active_handover_remaining_ms, enqueue_offline_metadata,
};

static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

fn temp_state_dir(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let n = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("grdr-hook-{tag}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    create_private_dir_all(&dir)?;
    Ok(dir)
}

#[test]
fn hook_fails_closed_on_empty_or_malformed_stdin_and_missing_floor() {
    let res = run_fail_closed_check();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn hook_uses_signed_binary_floor_fallback_when_daemon_unreachable_and_spools_offline() {
    let res = run_signed_floor_fallback();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn hook_enforces_floor_match_kind_agent_filter_severity_rank_and_key_id() {
    let res = run_floor_adversarial_checks();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn hook_formats_all_five_dialects_copilot_toolargs_and_action_classification() {
    let res = run_dialect_and_codec_checks();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn hook_offline_spool_rotates_at_4mib_and_rejects_invalid_handover_markers() {
    let res = run_spool_rotation_and_handover_checks();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn hook_ipc_handles_credit_grant_mismatched_request_id_error_and_deadline() {
    let res = run_ipc_client_adversarial_checks();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn hook_protected_profile_rejects_custom_state_dir_without_floor_fallback() {
    let dir = temp_state_dir("prot-tamper").expect("temp dir");
    let scanned = scan_hook_json(
        br#"{"session_id":"s-prot","tool_name":"Bash","tool_input":{"command":"echo ok"}}"#,
        "claude",
    )
    .expect("scan ok");
    let outcome = evaluate_signed_floor_fallback(&scanned, &dir, true, "daemon-down");
    assert_eq!(outcome.verdict, WireVerdict::Block);
    assert_eq!(outcome.rule_id, "HOOK-FAIL-CLOSED");
    assert!(!outcome.floor_fallback);
    let _ = fs::remove_dir_all(&dir);
}

fn run_fail_closed_check() -> Result<(), Box<dyn Error>> {
    let exe = env!("CARGO_BIN_EXE_grdr-hook");
    let state_dir = temp_state_dir("fail-closed")?;

    for bad_input in [
        &b""[..],
        &b"{not-json"[..],
        &b"{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":1}}}}}"[..],
        br#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"\uD83D"}}"#,
    ] {
        let mut child = Command::new(exe)
            .arg("--state-dir")
            .arg(&state_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(bad_input);
        }
        let out = child.wait_with_output()?;
        if out.status.code() != Some(2) {
            return Err(
                format!("expected exit 2 on bad stdin, got {:?}", out.status.code()).into(),
            );
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !stdout.contains("deny") {
            return Err(format!("dialect output must deny: {stdout}").into());
        }
    }

    let mut missing_floor = Command::new(exe)
        .args(["--agent", "cursor", "--state-dir"])
        .arg(&state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = missing_floor.stdin.take() {
        let _ = stdin.write_all(
            br#"{"hook_event_name":"beforeShellExecution","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
        );
    }
    let cursor_out = missing_floor.wait_with_output()?;
    if cursor_out.status.code() != Some(2) {
        return Err("missing floor must fail closed".into());
    }
    let cursor_json = String::from_utf8_lossy(&cursor_out.stdout);
    if !cursor_json.contains("\"continue\":false")
        || !cursor_json.contains("\"permission\":\"deny\"")
    {
        return Err(format!("unexpected cursor fail-closed JSON: {cursor_json}").into());
    }

    let _ = fs::remove_dir_all(&state_dir);
    Ok(())
}

fn write_test_floor(
    dir: &std::path::Path,
    rules: Vec<FloorRuleRecord>,
    pub_override: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let key = SigningKeypair::generate()?;
    let pub_content = pub_override.map_or_else(
        || format!("{}:{}", key.key_id(), key.public_key_b64()),
        str::to_string,
    );
    fs::write(dir.join("floor.pub"), pub_content)?;
    let doc = FloorTableDocument {
        epoch: 1,
        expires_at_unix_s: i64::MAX / 2,
        signer_key_id: key.key_id().to_string(),
        rules,
    };
    let bin = encode_signed_floor_table(&doc, &key)?;
    fs::write(dir.join("floor.bin"), bin)?;
    Ok(())
}

fn run_signed_floor_fallback() -> Result<(), Box<dyn Error>> {
    let exe = env!("CARGO_BIN_EXE_grdr-hook");
    let state_dir = temp_state_dir("floor-fallback")?;

    write_test_floor(
        &state_dir,
        vec![
            FloorRuleRecord {
                action_class: FastActionClass::Exec,
                verdict: FastVerdict::Deny,
                match_kind: FloorMatchKind::Contains,
                rule_id: "FLOOR-RM-RF".into(),
                pattern: "rm -rf /".into(),
                agents: Vec::new(),
            },
            FloorRuleRecord {
                action_class: FastActionClass::FileRead,
                verdict: FastVerdict::StepUp,
                match_kind: FloorMatchKind::Contains,
                rule_id: "FLOOR-SSH-ASK".into(),
                pattern: ".ssh/id_rsa".into(),
                agents: Vec::new(),
            },
            FloorRuleRecord {
                action_class: FastActionClass::McpCall,
                verdict: FastVerdict::Deny,
                match_kind: FloorMatchKind::Contains,
                rule_id: "FLOOR-MCP-DENY".into(),
                pattern: "mcp__shell__exec".into(),
                agents: Vec::new(),
            },
            FloorRuleRecord {
                action_class: FastActionClass::FileWrite,
                verdict: FastVerdict::Deny,
                match_kind: FloorMatchKind::Contains,
                rule_id: "FLOOR-PATCH-DENY".into(),
                pattern: "/etc/passwd".into(),
                agents: Vec::new(),
            },
        ],
        None,
    )?;

    let missing_sock = if cfg!(windows) {
        r"\\.\pipe\grdr-nonexistent-test-pipe-9999"
    } else {
        "/tmp/grdr-nonexistent-hook-test.sock"
    };

    let mut deny_child = Command::new(exe)
        .args(["--agent", "claude", "--socket", missing_sock, "--state-dir"])
        .arg(&state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = deny_child.stdin.take() {
        let _ = stdin.write_all(
            br#"{"session_id":"secret-session-s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /etc"}}"#,
        );
    }
    let deny_out = deny_child.wait_with_output()?;
    if deny_out.status.code() != Some(2) {
        return Err(format!(
            "expected exit 2 on floor deny, got {:?}",
            deny_out.status.code()
        )
        .into());
    }
    let deny_stdout = String::from_utf8_lossy(&deny_out.stdout);
    if !deny_stdout.contains("\"permissionDecision\":\"deny\"") {
        return Err(format!("expected claude deny JSON, got {deny_stdout}").into());
    }

    let mut stepup_child = Command::new(exe)
        .args(["--agent", "codex", "--socket", missing_sock, "--state-dir"])
        .arg(&state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = stepup_child.stdin.take() {
        let _ = stdin.write_all(
            br#"{"thread_id":"th-stepup","tool_name":"Read","tool_input":{"file_path":"/home/u/.ssh/id_rsa"}}"#,
        );
    }
    let stepup_out = stepup_child.wait_with_output()?;
    if stepup_out.status.code() != Some(2) {
        return Err(format!(
            "expected exit 2 on floor step-up, got {:?}",
            stepup_out.status.code()
        )
        .into());
    }
    let stepup_stdout = String::from_utf8_lossy(&stepup_out.stdout);
    if !stepup_stdout.contains("\"permissionDecision\":\"deny\"")
        || !stepup_stdout.contains("Approval required")
    {
        return Err(format!("expected step-up deny guidance, got {stepup_stdout}").into());
    }

    let cli_exec = Command::new(exe)
        .args([
            "--agent",
            "claude",
            "--action",
            "exec",
            "--target",
            "rm -rf /etc",
            "--socket",
            missing_sock,
            "--state-dir",
        ])
        .arg(&state_dir)
        .output()?;
    if cli_exec.status.code() != Some(2) {
        return Err("expected exit 2 on --action exec deny".into());
    }

    let mut mcp_child = Command::new(exe)
        .args(["--agent", "claude", "--socket", missing_sock, "--state-dir"])
        .arg(&state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = mcp_child.stdin.take() {
        let _ = stdin.write_all(
            br#"{"session_id":"s-mcp","tool_name":"mcp__shell__exec","tool_input":{"command":"echo hi"}}"#,
        );
    }
    if mcp_child.wait_with_output()?.status.code() != Some(2) {
        return Err("expected mcp__ tool classification to deny".into());
    }

    let mut patch_child = Command::new(exe)
        .args([
            "--agent",
            "copilot",
            "--socket",
            missing_sock,
            "--state-dir",
        ])
        .arg(&state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = patch_child.stdin.take() {
        let _ = stdin.write_all(
            br#"{"session_id":"s-patch","tool_name":"apply_patch","tool_input":{"file_path":"/etc/passwd"}}"#,
        );
    }
    if patch_child.wait_with_output()?.status.code() != Some(2) {
        return Err("expected patch tool classification to deny".into());
    }

    let now_mono = SystemClock::new()
        .boot_uptime()
        .map_or(100, |d| u64::try_from(d.as_millis()).unwrap_or(100));
    let marker = serde_json_handover_literal(now_mono, now_mono.saturating_add(150));
    fs::write(state_dir.join("handover"), marker)?;

    let spool_path = state_dir.join("hook-offline-spool.jsonl");
    if !spool_path.is_file() {
        return Err("expected offline spool queue file".into());
    }
    let spool_body = fs::read_to_string(&spool_path)?;
    if spool_body.contains("secret-session-s1") || spool_body.contains("rm -rf /etc") {
        return Err(format!("P8 leak in offline spool: {spool_body}").into());
    }

    let mut allow_child = Command::new(exe)
        .args(["--agent", "gemini", "--socket", missing_sock, "--state-dir"])
        .arg(&state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = allow_child.stdin.take() {
        let _ = stdin.write_all(
            br#"{"session_id":"s2","hook_event_name":"BeforeTool","tool_name":"run_command","tool_input":{"command":"git status"}}"#,
        );
    }
    let allow_out = allow_child.wait_with_output()?;
    if allow_out.status.code() != Some(0) {
        return Err(format!(
            "expected exit 0 on floor allow, got {:?} (stdout={}, stderr={})",
            allow_out.status.code(),
            String::from_utf8_lossy(&allow_out.stdout),
            String::from_utf8_lossy(&allow_out.stderr),
        )
        .into());
    }
    let allow_stdout = String::from_utf8_lossy(&allow_out.stdout);
    if !allow_stdout.contains("\"decision\":\"allow\"") {
        return Err(format!("expected gemini allow JSON, got {allow_stdout}").into());
    }

    let _ = fs::remove_dir_all(&state_dir);
    Ok(())
}

fn check_eq<T: PartialEq + std::fmt::Debug>(lhs: &T, rhs: &T, label: &str) -> Result<(), String> {
    if lhs != rhs {
        Err(format!("{label}: left={lhs:?}, right={rhs:?}"))
    } else {
        Ok(())
    }
}

fn run_floor_adversarial_checks() -> Result<(), Box<dyn Error>> {
    let dir = temp_state_dir("floor-adv")?;

    // Earlier StepUp must NOT shadow later Deny; Prefix/agents filters must be honored.
    write_test_floor(
        &dir,
        vec![
            FloorRuleRecord {
                action_class: FastActionClass::Exec,
                verdict: FastVerdict::StepUp,
                match_kind: FloorMatchKind::Prefix,
                rule_id: "FLOOR-FIRST-ASK".into(),
                pattern: "sudo".into(),
                agents: vec!["claude-code".to_string()],
            },
            FloorRuleRecord {
                action_class: FastActionClass::Exec,
                verdict: FastVerdict::Deny,
                match_kind: FloorMatchKind::Prefix,
                rule_id: "FLOOR-HIGHEST-DENY".into(),
                pattern: "sudo".into(),
                agents: vec!["claude-code".to_string()],
            },
            FloorRuleRecord {
                action_class: FastActionClass::Exec,
                verdict: FastVerdict::Deny,
                match_kind: FloorMatchKind::Contains,
                rule_id: "FLOOR-CURSOR-ONLY".into(),
                pattern: "echo cursor-only".into(),
                agents: vec!["cursor".to_string()],
            },
        ],
        None,
    )?;

    let sudo_claude = scan_hook_json(
        br#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"}}"#,
        "claude",
    )?;
    let hit = evaluate_signed_floor_fallback(&sudo_claude, &dir, false, "down");
    check_eq(&hit.verdict, &WireVerdict::Block, "highest severity block")?;
    check_eq(
        &hit.rule_id.as_str(),
        &"FLOOR-HIGHEST-DENY",
        "highest severity rule_id",
    )?;

    let echo_claude = scan_hook_json(
        br#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"echo cursor-only"}}"#,
        "claude",
    )?;
    let non_cursor = evaluate_signed_floor_fallback(&echo_claude, &dir, false, "down");
    check_eq(
        &non_cursor.verdict,
        &WireVerdict::Allow,
        "agent filter skip",
    )?;

    let echo_cursor = scan_hook_json(
        br#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"echo cursor-only"}}"#,
        "cursor",
    )?;
    let hit_cursor = evaluate_signed_floor_fallback(&echo_cursor, &dir, false, "down");
    check_eq(
        &hit_cursor.verdict,
        &WireVerdict::Block,
        "cursor match block",
    )?;
    check_eq(
        &hit_cursor.rule_id.as_str(),
        &"FLOOR-CURSOR-ONLY",
        "cursor match rule_id",
    )?;

    // Bare pubkey missing `<key_id>:` must fail closed (never guess floor-active / floor-k1).
    let key = SigningKeypair::generate()?;
    write_test_floor(&dir, vec![], Some(key.public_key_b64().as_str()))?;
    let bare_res = evaluate_signed_floor_fallback(&echo_claude, &dir, false, "down");
    check_eq(
        &bare_res.verdict,
        &WireVerdict::Block,
        "bare key fail closed",
    )?;
    check_eq(
        &bare_res.rule_id.as_str(),
        &"HOOK-FAIL-CLOSED",
        "bare key rule_id",
    )?;

    // Tampered floor.bin signature must fail closed.
    write_test_floor(&dir, vec![], None)?;
    let mut raw_bin = fs::read(dir.join("floor.bin"))?;
    if let Some(last) = raw_bin.last_mut() {
        *last ^= 0xFF;
    }
    fs::write(dir.join("floor.bin"), raw_bin)?;
    let sig_fail = evaluate_signed_floor_fallback(&echo_claude, &dir, false, "down");
    check_eq(&sig_fail.verdict, &WireVerdict::Block, "bad sig block")?;
    check_eq(
        &sig_fail.rule_id.as_str(),
        &"HOOK-FAIL-CLOSED",
        "bad sig rule_id",
    )?;

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

fn run_dialect_and_codec_checks() -> Result<(), Box<dyn Error>> {
    for agent_name in ["claude", "cursor", "codex", "copilot", "gemini"] {
        let dialect = HookDialect::from_cli_name(agent_name)
            .ok_or_else(|| format!("unknown dialect alias {agent_name}"))?;
        let ask = format_dialect_decision(
            dialect,
            "PreToolUse",
            WireVerdict::Ask,
            "needs grant",
            "R-1",
        );
        if !ask.contains("Approval required") && !ask.contains("deny") {
            return Err(format!("unexpected Ask output for {agent_name}: {ask}").into());
        }
    }

    let exe = env!("CARGO_BIN_EXE_grdr-hook");
    let dir = temp_state_dir("action-confusion")?;
    write_test_floor(
        &dir,
        vec![FloorRuleRecord {
            action_class: FastActionClass::NetRequest,
            verdict: FastVerdict::Deny,
            match_kind: FloorMatchKind::Contains,
            rule_id: "FLOOR-NET-DENY".into(),
            pattern: "https://evil.test".into(),
            agents: Vec::new(),
        }],
        None,
    )?;
    let missing_sock = if cfg!(windows) {
        r"\\.\pipe\grdr-nonexistent-test-pipe-9998"
    } else {
        "/tmp/grdr-nonexistent-hook-test-2.sock"
    };
    let out = Command::new(exe)
        .args([
            "--agent",
            "claude",
            "--action",
            "Write",
            "--target",
            "https://evil.test",
            "--socket",
            missing_sock,
            "--state-dir",
        ])
        .arg(&dir)
        .output()?;
    if out.status.code() != Some(0) {
        return Err(format!(
            "Write action misclassified as NetRequest: {:?} stdout={}",
            out.status,
            String::from_utf8_lossy(&out.stdout)
        )
        .into());
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

fn run_spool_rotation_and_handover_checks() -> Result<(), Box<dyn Error>> {
    let dir = temp_state_dir("spool-rot")?;

    for invalid in [
        "99999999",
        "{\"version\":2,\"marker_status\":\"active\",\"created_mono_ms\":100,\"expires_mono_ms\":500}",
        "{\"version\":1,\"marker_status\":\"inactive\",\"created_mono_ms\":100,\"expires_mono_ms\":500}",
        "{\"version\":1,\"marker_status\":\"active\",\"created_mono_ms\":1000,\"expires_mono_ms\":1500}",
        "{\"version\":1,\"marker_status\":\"active\",\"created_mono_ms\":100,\"expires_mono_ms\":2500}",
    ] {
        fs::write(dir.join("handover"), invalid)?;
        if active_handover_remaining_ms(&dir, 300).is_some() {
            return Err(format!("invalid handover marker accepted: {invalid}").into());
        }
    }
    fs::write(
        dir.join("handover"),
        "{\"version\":1,\"marker_status\":\"active\",\"created_mono_ms\":200,\"expires_mono_ms\":1500}",
    )?;
    check_eq(
        &active_handover_remaining_ms(&dir, 300),
        &Some(1200),
        "valid handover remaining ms",
    )?;

    let mut seed = Vec::with_capacity(
        usize::try_from(HOOK_OFFLINE_SPOOL_CAP_BYTES.saturating_sub(128))
            .unwrap_or(4 * 1024 * 1024),
    );
    let sample = b"{\"ts_ms\":1,\"agent\":\"claude\",\"session_sha\":\"00\",\"target_sha\":\"11\",\"verdict\":\"allow\",\"reason\":\"ok\"}\n";
    while u64::try_from(seed.len().saturating_add(sample.len())).unwrap_or(u64::MAX)
        < HOOK_OFFLINE_SPOOL_CAP_BYTES.saturating_sub(10)
    {
        seed.extend_from_slice(sample);
    }
    fs::write(dir.join("hook-offline-spool.jsonl"), &seed)?;

    let rot = enqueue_offline_metadata(
        &dir,
        "claude",
        "secret-session",
        "secret-target",
        "block",
        "connect failed https://secret.example/path \"rm -rf /\"",
        42,
    )?;
    if rot.total_bytes >= HOOK_OFFLINE_SPOOL_CAP_BYTES || rot.dropped_count == 0 {
        return Err(format!("rotation invariant failed: {rot:?}").into());
    }
    let body = fs::read_to_string(&rot.path)?;
    if body.contains("https://secret.example") || !body.contains("[redacted]") {
        return Err(format!("P8 reason redaction failed: {body}").into());
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

fn run_ipc_client_adversarial_checks() -> Result<(), Box<dyn Error>> {
    #[derive(Clone, Copy)]
    enum Mode {
        CreditThenValid,
        WrongAckId,
        DaemonError,
        AckStall,
    }

    let floor_dir = temp_state_dir("ipc-floor")?;
    write_test_floor(&floor_dir, vec![], None)?;
    let scanned = scan_hook_json(
        br#"{"session_id":"ipc-s1","tool_name":"Bash","tool_input":{"command":"echo ipc"}}"#,
        "claude",
    )?;

    for (idx, mode) in [
        Mode::CreditThenValid,
        Mode::WrongAckId,
        Mode::DaemonError,
        Mode::AckStall,
    ]
    .into_iter()
    .enumerate()
    {
        #[cfg(windows)]
        let (addr_str, srv_handle) = {
            use grdr_ipc_os::proto_io::ProtoIpcStream;
            use grdr_ipc_os::windows_pipe_server::{
                WindowsNamedPipeAcceptor, WindowsServerPipeStream,
            };
            let pipe_name = format!(r"\\.\pipe\grdr-user-hkipc-{}-{idx}", std::process::id());
            let mut acceptor = WindowsNamedPipeAcceptor::bind(
                &pipe_name,
                "D:(A;;GA;;;OW)(A;;0x00120083;;;AU)S:(ML;;NW;;;ME)",
            )?;
            let handle = std::thread::spawn(move || -> Result<(), String> {
                let link = acceptor
                    .accept(Duration::from_secs(3))
                    .map_err(|e| e.to_string())?;
                let connected_at = link.connected_at_100ns();
                let (pre_claims, proc_hold) =
                    grdr_peer_os::win_peer::read_windows_pipe_client_pre(link.borrowed_handle())
                        .map_err(|e| e.to_string())?;
                let expected_pid = pre_claims.pid;
                let expected_sid = pre_claims.peer_sid;
                let policy = ServerIdentityPolicy {
                    profile: Profile::User,
                    allowed_client_uids: vec![],
                    allowed_windows_sids: vec![expected_sid.clone()],
                    minimum_integrity_rid: 0x2000,
                    reject_app_container: true,
                    require_start_time_before_connect: true,
                    require_open_as_self_pipe_check: true,
                    require_kernel_peer_token: false,
                };
                let pending =
                    accept_deferred_windows(ProtoIpcStream::new(link), connected_at, &policy)
                        .map_err(|e| e.to_string())?;
                let (mut chan, _) = pending
                    .first_frame_with_claims(
                        EndpointServiceKind::Decide,
                        "sha256:test",
                        1,
                        HandoverStage::Normal,
                        1_048_576,
                        Some(move |s: &mut ProtoIpcStream<WindowsServerPipeStream>| {
                            let verified =
                                grdr_peer_os::win_peer::verify_windows_pipe_client_post_read(
                                    s.get_ref().borrowed_handle(),
                                    &proc_hold,
                                    expected_pid,
                                    &expected_sid,
                                )
                                .map_err(|err| {
                                    Refusal::UnauthenticatedPeer(Evidence::MissingPeerToken {
                                        detail: err.to_string(),
                                    })
                                })?;
                            Ok(OsPeerClaims::Windows(verified))
                        }),
                    )
                    .map_err(|e| e.to_string())?;
                let req = chan.recv_frame().map_err(|e| e.to_string())?;
                let req_id = match req.payload {
                    Some(WirePayload::DecideRequest(r)) => r.request_id,
                    other => return Err(format!("expected DecideRequest, got {other:?}")),
                };
                match mode {
                    Mode::CreditThenValid => {
                        chan.send_credit_grant(8).map_err(|e| e.to_string())?;
                        chan.send_frame(WireFrame::with_payload(
                            1,
                            1,
                            WirePayload::DecideAck(DecideAckFrame {
                                request_id: req_id.clone(),
                                epoch: 1,
                                accepted_at_mono_ms: 10,
                                handover_stage: HandoverStage::Normal as i32,
                            }),
                        ))
                        .map_err(|e| e.to_string())?;
                        chan.send_frame(WireFrame::with_payload(
                            1,
                            2,
                            WirePayload::DecideVerdict(DecideVerdictFrame {
                                request_id: req_id,
                                verdict: WireVerdict::Allow as i32,
                                rule_id: "R-ALLOW".to_string(),
                                reason: "ok".to_string(),
                                receipt_id: "rec-1".to_string(),
                                labels: Vec::new(),
                                floor_fallback: false,
                                audit_fsynced: true,
                                degraded_reason: String::new(),
                            }),
                        ))
                        .map_err(|e| e.to_string())?;
                    }
                    Mode::WrongAckId => {
                        chan.send_frame(WireFrame::with_payload(
                            1,
                            1,
                            WirePayload::DecideAck(DecideAckFrame {
                                request_id: "wrong-id".to_string(),
                                epoch: 1,
                                accepted_at_mono_ms: 10,
                                handover_stage: HandoverStage::Normal as i32,
                            }),
                        ))
                        .map_err(|e| e.to_string())?;
                    }
                    Mode::DaemonError => {
                        chan.send_frame(WireFrame::with_payload(
                            1,
                            1,
                            WirePayload::Error(ErrorFrame {
                                code: "GRDR-DAEMON-0009".to_string(),
                                message: "overloaded".to_string(),
                                retryable: false,
                            }),
                        ))
                        .map_err(|e| e.to_string())?;
                    }
                    Mode::AckStall => {
                        chan.send_credit_grant(4).map_err(|e| e.to_string())?;
                        std::thread::sleep(Duration::from_millis(350));
                    }
                }
                Ok(())
            });
            (pipe_name, handle)
        };

        #[cfg(unix)]
        let (addr_str, srv_handle) = {
            use grdr_ipc_os::LocalEndpointAddress;
            use grdr_ipc_os::proto_io::ProtoIpcStream;
            use grdr_ipc_os::transport::{Acceptor, FixedTimestampSource, IpcDeadline};
            use grdr_ipc_os::unix_domain::UnixDomainAcceptor;
            let base = std::env::var_os("XDG_RUNTIME_DIR")
                .or_else(|| std::env::var_os("HOME"))
                .map(PathBuf::from)
                .ok_or("missing XDG_RUNTIME_DIR or HOME for unix IPC test")?;
            let sock_dir = base.join(format!(".grdr-hkipc-{}-{idx}", std::process::id()));
            fs::create_dir_all(&sock_dir)?;
            let sock_path = sock_dir.join("decide.sock");
            let addr_str = sock_path.to_string_lossy().into_owned();
            let mut acceptor = UnixDomainAcceptor::bind_with_mode(
                LocalEndpointAddress::UnixSocket {
                    path: sock_path.clone(),
                },
                0o600,
            )?;
            let handle = std::thread::spawn(move || -> Result<(), String> {
                let clock = SystemClock::new();
                let now = clock.now_wall().map_err(|e| e.to_string())?;
                let ts = FixedTimestampSource::new(now);
                let link = acceptor
                    .accept(IpcDeadline::from_millis_capped(3_000, 3_000), &ts)
                    .map_err(|e| e.to_string())?;
                let (uid, _gid) = grdr_peer_os::unix_peer::current_effective_ids()
                    .ok_or_else(|| "uid unavailable".to_string())?;
                let stamp = grdr_peer_os::unix_peer::UnixConnectStamp {
                    boot_uptime_ms: clock
                        .boot_uptime()
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                    wall_unix_us: clock
                        .now_wall()
                        .ok()
                        .and_then(|t| u64::try_from(t.as_microsecond()).ok())
                        .unwrap_or(0),
                };
                let hold =
                    grdr_peer_os::unix_peer::read_unix_socket_peer(link.borrowed_fd(), stamp)
                        .map_err(|e| e.to_string())?;
                let policy = ServerIdentityPolicy {
                    profile: Profile::User,
                    allowed_client_uids: vec![uid, 0],
                    allowed_windows_sids: vec![],
                    minimum_integrity_rid: 0,
                    reject_app_container: false,
                    require_start_time_before_connect: true,
                    require_open_as_self_pipe_check: false,
                    require_kernel_peer_token: true,
                };
                let pending = accept(
                    ProtoIpcStream::new(link),
                    &OsPeerClaims::Unix(hold.claims.clone()),
                    stamp.for_platform(),
                    &policy,
                )
                .map_err(|e| e.to_string())?;
                let (mut chan, _) = pending
                    .first_frame(
                        EndpointServiceKind::Decide,
                        "sha256:test",
                        1,
                        HandoverStage::Normal,
                        1_048_576,
                    )
                    .map_err(|e| e.to_string())?;
                let req = chan.recv_frame().map_err(|e| e.to_string())?;
                let req_id = match req.payload {
                    Some(WirePayload::DecideRequest(r)) => r.request_id,
                    other => return Err(format!("expected DecideRequest, got {other:?}")),
                };
                match mode {
                    Mode::CreditThenValid => {
                        chan.send_credit_grant(8).map_err(|e| e.to_string())?;
                        chan.send_frame(WireFrame::with_payload(
                            1,
                            1,
                            WirePayload::DecideAck(DecideAckFrame {
                                request_id: req_id.clone(),
                                epoch: 1,
                                accepted_at_mono_ms: 10,
                                handover_stage: HandoverStage::Normal as i32,
                            }),
                        ))
                        .map_err(|e| e.to_string())?;
                        chan.send_frame(WireFrame::with_payload(
                            1,
                            2,
                            WirePayload::DecideVerdict(DecideVerdictFrame {
                                request_id: req_id,
                                verdict: WireVerdict::Allow as i32,
                                rule_id: "R-ALLOW".to_string(),
                                reason: "ok".to_string(),
                                receipt_id: "rec-1".to_string(),
                                labels: Vec::new(),
                                floor_fallback: false,
                                audit_fsynced: true,
                                degraded_reason: String::new(),
                            }),
                        ))
                        .map_err(|e| e.to_string())?;
                    }
                    Mode::WrongAckId => {
                        chan.send_frame(WireFrame::with_payload(
                            1,
                            1,
                            WirePayload::DecideAck(DecideAckFrame {
                                request_id: "wrong-id".to_string(),
                                epoch: 1,
                                accepted_at_mono_ms: 10,
                                handover_stage: HandoverStage::Normal as i32,
                            }),
                        ))
                        .map_err(|e| e.to_string())?;
                    }
                    Mode::DaemonError => {
                        chan.send_frame(WireFrame::with_payload(
                            1,
                            1,
                            WirePayload::Error(ErrorFrame {
                                code: "GRDR-DAEMON-0009".to_string(),
                                message: "overloaded".to_string(),
                                retryable: false,
                            }),
                        ))
                        .map_err(|e| e.to_string())?;
                    }
                    Mode::AckStall => {
                        chan.send_credit_grant(4).map_err(|e| e.to_string())?;
                        std::thread::sleep(Duration::from_millis(350));
                    }
                }
                let _ = fs::remove_dir_all(&sock_dir);
                Ok(())
            });
            (addr_str, handle)
        };

        let outcome = evaluate_against_daemon_or_floor(
            &scanned,
            &floor_dir,
            Some(&addr_str),
            false,
            "req-ipc-test",
            1,
            Instant::now(),
        );
        let srv_res = srv_handle.join().map_err(|_| "server thread panicked")?;
        srv_res?;
        match mode {
            Mode::CreditThenValid => {
                check_eq(
                    &outcome.verdict,
                    &WireVerdict::Allow,
                    "credit then valid verdict",
                )?;
                check_eq(
                    &outcome.rule_id.as_str(),
                    &"R-ALLOW",
                    "credit then valid rule_id",
                )?;
            }
            Mode::WrongAckId | Mode::DaemonError => {
                check_eq(&outcome.verdict, &WireVerdict::Block, "fail closed verdict")?;
                check_eq(
                    &outcome.rule_id.as_str(),
                    &"HOOK-FAIL-CLOSED",
                    "fail closed rule_id",
                )?;
                if outcome.floor_fallback {
                    return Err(
                        "must not fall back to floor on WirePayload::Error or ack mismatch".into(),
                    );
                }
            }
            Mode::AckStall => {
                if !outcome.floor_fallback || outcome.rule_id != "FLOOR-VERIFIED-ALLOW" {
                    return Err(format!(
                        "expected floor fallback after ack stall deadline, got {outcome:?}"
                    )
                    .into());
                }
            }
        }
    }

    let _ = fs::remove_dir_all(&floor_dir);
    Ok(())
}

fn serde_json_handover_literal(created_ms: u64, expires_ms: u64) -> String {
    format!(
        "{{\"version\":1,\"marker_status\":\"active\",\"target_slot\":\"slot_a\",\"target_binary_path\":\"a.bin\",\"target_sha256\":\"00\",\"created_mono_ms\":{created_ms},\"expires_mono_ms\":{expires_ms},\"issued_wall_unix_ms\":0,\"expires_wall_unix_ms\":0}}"
    )
}
