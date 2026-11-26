// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ffi::{CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::sync::Mutex;

use grdr_fastpath::{FastActionClass, FastVerdict, FloorRuleRef, evaluate_floor_entries};
use grdr_model::ActionClass;
use serde::{Deserialize, Serialize};

use crate::es_tree::{EsEventPayload, EsTreeFollower};
use crate::macos_probes::{MacOsLiveCapabilities, probe_host_capabilities};
use crate::network_ext::{EgressDefaultPolicy, NeFlowRecord, evaluate_ne_flow};
use crate::seatbelt::{SeatbeltProfileSpec, plan_macos_launch};

pub const GRDR_MACOS_ABI_VERSION: u32 = 1;
pub const MAX_FFI_JSON_BYTES: usize = 1_048_576;
const MAX_FFI_FLOOR_RULES: usize = 1_024;

#[repr(C)]
pub struct GrdrMacEsFollower {
    _private: [u8; 0],
}

struct FfiFollowerHolder {
    inner: Mutex<EsTreeFollower>,
}

#[derive(Debug, Clone, Deserialize)]
struct FfiFloorRuleSpec {
    rule_id: String,
    action_mask: u32,
    #[serde(default)]
    prefixes: Vec<String>,
    #[serde(default)]
    contains: Vec<String>,
    #[serde(default)]
    agents: Vec<String>,
    verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FfiEsApplyResult {
    verdict: String,
    session_id: Option<String>,
    action_class: ActionClass,
    summary: String,
    member_count: usize,
    unmuted_pids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize)]
struct FfiErrorEnvelope {
    error: String,
}

pub fn abi_probe_capabilities_json() -> String {
    let caps: MacOsLiveCapabilities = probe_host_capabilities();
    serde_json::to_string(&caps).unwrap_or_else(|_| "{}".to_string())
}

#[allow(
    unsafe_code,
    reason = "C-ABI version probe exported for Swift extensions."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_macos_abi_version() -> u32 {
    GRDR_MACOS_ABI_VERSION
}

#[allow(
    unsafe_code,
    reason = "Allocate opaque Mutex-guarded EsTreeFollower handle across C ABI."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_macos_follower_new() -> *mut GrdrMacEsFollower {
    match catch_unwind(|| {
        let holder = FfiFollowerHolder {
            inner: Mutex::new(EsTreeFollower::new()),
        };
        Box::into_raw(Box::new(holder)).cast::<GrdrMacEsFollower>()
    }) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Destroy an opaque `GrdrMacEsFollower` allocated by `grdr_macos_follower_new`.
///
/// # Safety
/// `ptr` must be null or a pointer returned by `grdr_macos_follower_new` not yet freed.
#[allow(
    unsafe_code,
    reason = "Free opaque Mutex-guarded EsTreeFollower allocated across C ABI."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_follower_free(ptr: *mut GrdrMacEsFollower) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        #[allow(
            unsafe_code,
            reason = "Reclaim FfiFollowerHolder Box owned by Swift caller."
        )]
        // SAFETY: Caller passes pointer allocated by grdr_macos_follower_new once.
        let boxed = unsafe { Box::from_raw(ptr.cast::<FfiFollowerHolder>()) };
        drop(boxed);
    }));
}

/// Apply one JSON-serialized `EsEventPayload` to an opaque `EsTreeFollower`.
/// Free the returned string with `grdr_macos_free_string`.
///
/// # Safety
/// `follower` must point to a live `GrdrMacEsFollower` and `event_json_ptr` must cover `event_json_len` readable bytes.
#[allow(
    unsafe_code,
    reason = "C-ABI Endpoint Security tree update entry point."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_apply_es_event(
    follower: *mut GrdrMacEsFollower,
    event_json_ptr: *const u8,
    event_json_len: usize,
) -> *mut c_char {
    if follower.is_null() {
        return error_json("null follower pointer");
    }
    let res = catch_unwind(AssertUnwindSafe(|| {
        #[allow(
            unsafe_code,
            reason = "Read UTF-8 JSON bytes and mutable follower handle from C ABI."
        )]
        // SAFETY: Checked non-null follower and bounded JSON slice matching caller preconditions.
        let raw = unsafe { read_utf8_arg(event_json_ptr, event_json_len) }?;
        let payload: EsEventPayload =
            serde_json::from_str(raw).map_err(|e| format!("invalid EsEventPayload JSON: {e}"))?;
        #[allow(
            unsafe_code,
            reason = "Lock Mutex-guarded EsTreeFollower owned by caller across C ABI."
        )]
        // SAFETY: Non-null aligned FfiFollowerHolder pointer created by grdr_macos_follower_new.
        let holder = unsafe { &*follower.cast::<FfiFollowerHolder>() };
        let mut state = holder
            .inner
            .lock()
            .map_err(|_| "EsTreeFollower mutex poisoned".to_string())?;
        let outcome = state.apply_event(&payload);
        let result = FfiEsApplyResult {
            verdict: "allow".to_string(),
            session_id: outcome.session_id,
            action_class: outcome.action_class,
            summary: outcome.summary,
            member_count: state.member_count(),
            unmuted_pids: outcome.unmuted_targets.into_iter().map(|k| k.pid).collect(),
        };
        serde_json::to_string(&result).map_err(|e| format!("serialize apply result failed: {e}"))
    }));
    wrap_ffi_result(res)
}

/// Mute an Apple Team ID across an opaque `GrdrMacEsFollower` over the C ABI.
/// Free the returned string with `grdr_macos_free_string`.
///
/// # Safety
/// `follower` must point to a live `GrdrMacEsFollower` and `team_id_ptr` must cover `team_id_len` readable bytes.
#[allow(
    unsafe_code,
    reason = "C-ABI incumbent Team ID muting entry point for Endpoint Security."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_follower_mute_team(
    follower: *mut GrdrMacEsFollower,
    team_id_ptr: *const u8,
    team_id_len: usize,
) -> *mut c_char {
    if follower.is_null() {
        return error_json("null follower pointer");
    }
    let res = catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Read UTF-8 Team ID bytes across C ABI.")]
        // SAFETY: Checked non-null follower and bounded slice validated by read_utf8_arg.
        let team = unsafe { read_utf8_arg(team_id_ptr, team_id_len) }?;
        if team.is_empty() {
            return Err("muted team ID must not be empty".to_string());
        }
        #[allow(
            unsafe_code,
            reason = "Lock Mutex-guarded EsTreeFollower owned by caller across C ABI."
        )]
        // SAFETY: Non-null aligned FfiFollowerHolder pointer created by grdr_macos_follower_new.
        let holder = unsafe { &*follower.cast::<FfiFollowerHolder>() };
        let mut state = holder
            .inner
            .lock()
            .map_err(|_| "EsTreeFollower mutex poisoned".to_string())?;
        state.mute_incumbent_team(team);
        Ok("{\"ok\":true}".to_string())
    }));
    wrap_ffi_result(res)
}

/// Evaluate an `AUTH_EXEC` event against tracked tree state and compiled floor rules.
/// Free the returned string with `grdr_macos_free_string`.
///
/// # Safety
/// `follower`, `event_json_ptr`, and optional `floor_json_ptr` must be valid for their byte lengths.
#[allow(
    unsafe_code,
    reason = "C-ABI AUTH_EXEC fastpath verdict entry point for Endpoint Security."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_eval_es_auth_exec(
    follower: *mut GrdrMacEsFollower,
    event_json_ptr: *const u8,
    event_json_len: usize,
    floor_json_ptr: *const u8,
    floor_json_len: usize,
    default_deny: u8,
) -> *mut c_char {
    if follower.is_null() {
        return error_json("null follower pointer");
    }
    let res = catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Read ES event JSON bytes across C ABI.")]
        // SAFETY: Checked non-null follower and event slice validated by read_utf8_arg.
        let raw = unsafe { read_utf8_arg(event_json_ptr, event_json_len) }?;
        let payload: EsEventPayload =
            serde_json::from_str(raw).map_err(|e| format!("invalid EsEventPayload JSON: {e}"))?;
        let floor_specs = {
            #[allow(unsafe_code, reason = "Validate floor rule slice across C ABI.")]
            // SAFETY: floor_json_ptr and floor_json_len checked by parse_floor_specs_ffi.
            unsafe {
                parse_floor_specs_ffi(floor_json_ptr, floor_json_len)
            }
        }?;

        #[allow(
            unsafe_code,
            reason = "Lock Mutex-guarded EsTreeFollower owned by caller across C ABI."
        )]
        // SAFETY: Non-null aligned FfiFollowerHolder pointer created by grdr_macos_follower_new.
        let holder = unsafe { &*follower.cast::<FfiFollowerHolder>() };
        let mut state = holder
            .inner
            .lock()
            .map_err(|_| "EsTreeFollower mutex poisoned".to_string())?;
        let outcome = state.apply_event(&payload);

        let mut verdict = "allow".to_string();
        if let EsEventPayload::AuthExec {
            target,
            executable_path,
            ..
        } = &payload
            && let Some(sid) = outcome.session_id.as_deref()
        {
            let deny_reason = with_floor_refs(&floor_specs, FastActionClass::Exec, |refs| {
                let hit = evaluate_floor_entries(refs, FastActionClass::Exec, "", executable_path);
                match hit {
                    Some(h) if matches!(h.verdict, FastVerdict::Deny | FastVerdict::StepUp) => {
                        Some(format!("floor rule `{}`", h.rule_id))
                    }
                    None if default_deny != 0 => {
                        Some("default_deny with no matching exec allow rule".to_string())
                    }
                    _ => None,
                }
            });
            if let Some(reason) = deny_reason {
                state.record_denied_auth_exec(target.key, sid, executable_path, reason);
                verdict = "deny".to_string();
            }
        }

        let result = FfiEsApplyResult {
            verdict,
            session_id: outcome.session_id,
            action_class: outcome.action_class,
            summary: outcome.summary,
            member_count: state.member_count(),
            unmuted_pids: outcome.unmuted_targets.into_iter().map(|k| k.pid).collect(),
        };
        serde_json::to_string(&result).map_err(|e| format!("serialize auth verdict failed: {e}"))
    }));
    wrap_ffi_result(res)
}

/// Evaluate a JSON-encoded `NeFlowRecord` against JSON-encoded floor rules.
/// Free the returned string with `grdr_macos_free_string`.
///
/// # Safety
/// `flow_json_ptr` and optional `floor_json_ptr` must be valid for their declared byte lengths.
#[allow(
    unsafe_code,
    reason = "C-ABI Network Extension flow evaluator entry point."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_eval_ne_flow(
    flow_json_ptr: *const u8,
    flow_json_len: usize,
    floor_json_ptr: *const u8,
    floor_json_len: usize,
    default_deny: u8,
) -> *mut c_char {
    let res = catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Read flow JSON byte slice across C ABI.")]
        // SAFETY: flow_json_ptr and flow_json_len validated by read_utf8_arg.
        let flow_raw = unsafe { read_utf8_arg(flow_json_ptr, flow_json_len) }?;
        let flow: NeFlowRecord =
            serde_json::from_str(flow_raw).map_err(|e| format!("invalid NeFlowRecord: {e}"))?;

        let floor_specs = {
            #[allow(unsafe_code, reason = "Validate floor rule slice across C ABI.")]
            // SAFETY: floor_json_ptr and floor_json_len validated by parse_floor_specs_ffi.
            unsafe {
                parse_floor_specs_ffi(floor_json_ptr, floor_json_len)
            }
        }?;
        let policy = if default_deny != 0 {
            EgressDefaultPolicy::DefaultDeny
        } else {
            EgressDefaultPolicy::DefaultAllow
        };
        let verdict = with_floor_refs(&floor_specs, FastActionClass::NetConnect, |refs| {
            evaluate_ne_flow(&flow, refs, policy)
        });
        serde_json::to_string(&verdict).map_err(|e| format!("serialize verdict failed: {e}"))
    }));
    wrap_ffi_result(res)
}

#[allow(
    unsafe_code,
    reason = "Read and deserialize bounded floor rule JSON slice across C ABI."
)]
// SAFETY: Validates non-null pointer whenever floor_json_len > 0 via read_utf8_arg.
unsafe fn parse_floor_specs_ffi(
    floor_json_ptr: *const u8,
    floor_json_len: usize,
) -> Result<Vec<FfiFloorRuleSpec>, String> {
    let specs: Vec<FfiFloorRuleSpec> = if floor_json_len == 0 {
        Vec::new()
    } else {
        #[allow(
            unsafe_code,
            reason = "Read non-empty floor rule JSON byte slice across C ABI."
        )]
        // SAFETY: floor_json_ptr and floor_json_len checked by read_utf8_arg.
        let floor_raw = unsafe { read_utf8_arg(floor_json_ptr, floor_json_len) }?;
        serde_json::from_str(floor_raw).map_err(|e| format!("invalid floor JSON: {e}"))?
    };
    if specs.len() > MAX_FFI_FLOOR_RULES {
        return Err(format!("floor rules exceed cap {MAX_FFI_FLOOR_RULES}"));
    }
    Ok(specs)
}

fn with_floor_refs<R>(
    floor_specs: &[FfiFloorRuleSpec],
    default_action: FastActionClass,
    f: impl FnOnce(&[FloorRuleRef<'_>]) -> R,
) -> R {
    let mut prefixes: Vec<Vec<&str>> = Vec::with_capacity(floor_specs.len());
    let mut contains: Vec<Vec<&str>> = Vec::with_capacity(floor_specs.len());
    let mut agents: Vec<Vec<&str>> = Vec::with_capacity(floor_specs.len());
    for spec in floor_specs {
        prefixes.push(spec.prefixes.iter().map(String::as_str).collect());
        contains.push(spec.contains.iter().map(String::as_str).collect());
        agents.push(spec.agents.iter().map(String::as_str).collect());
    }
    let mut refs: Vec<FloorRuleRef<'_>> = Vec::with_capacity(floor_specs.len());
    for (idx, spec) in floor_specs.iter().enumerate() {
        let verdict = match spec.verdict.to_ascii_lowercase().as_str() {
            "allow" => FastVerdict::Allow,
            "step_up" => FastVerdict::StepUp,
            _ => FastVerdict::Deny,
        };
        let mask = if spec.action_mask == 0 {
            1u32 << (default_action as u8)
        } else {
            spec.action_mask
        };
        refs.push(FloorRuleRef {
            rule_id: &spec.rule_id,
            action_mask: mask,
            prefixes: prefixes.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            contains: contains.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            agents: agents.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            verdict,
        });
    }
    f(&refs)
}

/// Plan a Seatbelt launch profile from JSON-encoded `SeatbeltProfileSpec`.
/// Free the returned string with `grdr_macos_free_string`.
///
/// # Safety
/// `agent_ptr` and `spec_json_ptr` must cover their declared byte lengths.
#[allow(unsafe_code, reason = "C-ABI Seatbelt launch planner entry point.")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_plan_seatbelt(
    agent_ptr: *const u8,
    agent_len: usize,
    own_seatbelt: u8,
    spec_json_ptr: *const u8,
    spec_json_len: usize,
) -> *mut c_char {
    let res = catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Read agent name bytes across C ABI.")]
        // SAFETY: agent_ptr and agent_len checked by read_utf8_arg.
        let agent = unsafe { read_utf8_arg(agent_ptr, agent_len) }?;
        #[allow(
            unsafe_code,
            reason = "Read SeatbeltProfileSpec JSON bytes across C ABI."
        )]
        // SAFETY: spec_json_ptr and spec_json_len checked by read_utf8_arg.
        let spec_raw = unsafe { read_utf8_arg(spec_json_ptr, spec_json_len) }?;
        let spec: SeatbeltProfileSpec = serde_json::from_str(spec_raw)
            .map_err(|e| format!("invalid SeatbeltProfileSpec JSON: {e}"))?;
        let plan = plan_macos_launch(agent, own_seatbelt != 0, &spec)
            .map_err(|e| format!("Seatbelt planning error: {e}"))?;
        serde_json::to_string(&plan).map_err(|e| format!("serialize plan failed: {e}"))
    }));
    wrap_ffi_result(res)
}

#[allow(
    unsafe_code,
    reason = "C-ABI host capability probe exported for Swift UI and extensions."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_macos_probe_capabilities() -> *mut c_char {
    let res = catch_unwind(abi_probe_capabilities_json);
    match res {
        Ok(json) => to_c_string_sanitized(&json),
        Err(_) => error_json("panic caught in grdr_macos_probe_capabilities"),
    }
}

/// Free a string pointer previously returned by any `grdr_macos_*` function.
///
/// # Safety
/// `ptr` must be null or a pointer previously allocated by `grdr_macos_*` and not yet freed.
#[allow(
    unsafe_code,
    reason = "Free CString returned across macOS Swift/C ABI."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        #[allow(
            unsafe_code,
            reason = "Reclaim CString ownership allocated by to_c_string_sanitized."
        )]
        // SAFETY: Non-null pointer created by CString::into_raw in this crate.
        let cs = unsafe { CString::from_raw(ptr) };
        drop(cs);
    }));
}

#[allow(
    unsafe_code,
    reason = "Validate and read bounded UTF-8 byte buffer passed across C ABI."
)]
unsafe fn read_utf8_arg<'a>(ptr: *const u8, len: usize) -> Result<&'a str, String> {
    if len == 0 {
        return Ok("");
    }
    if ptr.is_null() {
        return Err("null C-ABI input pointer".to_string());
    }
    if len > MAX_FFI_JSON_BYTES {
        return Err(format!("C-ABI input exceeds {MAX_FFI_JSON_BYTES} bytes"));
    }
    #[allow(unsafe_code, reason = "Slice caller-provided readable UTF-8 buffer.")]
    // SAFETY: Caller guarantees ptr covers len readable bytes.
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).map_err(|_| "C-ABI input is not valid UTF-8".to_string())
}

fn wrap_ffi_result(
    res: Result<Result<String, String>, Box<dyn std::any::Any + Send>>,
) -> *mut c_char {
    match res {
        Ok(Ok(json)) => to_c_string_sanitized(&json),
        Ok(Err(msg)) => error_json(&msg),
        Err(_) => error_json("panic caught across grdr_macos C ABI"),
    }
}

fn error_json(msg: &str) -> *mut c_char {
    let encoded = serde_json::to_string(&FfiErrorEnvelope {
        error: msg.to_string(),
    })
    .unwrap_or_else(|_| "{\"error\":\"serialization fault\"}".to_string());
    to_c_string_sanitized(&encoded)
}

fn to_c_string_sanitized(s: &str) -> *mut c_char {
    let cleaned = s.replace('\0', " ");
    match CString::new(cleaned) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::es_tree::{EsAuditToken, ProcessTreeKey};
    use crate::network_ext::FlowTransport;
    use std::ffi::CStr;

    #[test]
    #[allow(unsafe_code)]
    fn c_abi_follower_ne_flow_and_seatbelt_roundtrip() {
        assert_eq!(grdr_macos_abi_version(), 1);
        let follower = grdr_macos_follower_new();
        assert!(!follower.is_null());

        let event = serde_json::to_vec(&EsEventPayload::RegisterAgentRoot {
            root: EsAuditToken {
                key: ProcessTreeKey {
                    pid: 500,
                    pidversion: 1,
                },
                uid: 501,
                team_id: None,
            },
            session_id: "sess-ffi-mac".into(),
        })
        .unwrap();

        // SAFETY: Valid follower pointer and valid event byte buffer; freed below.
        let apply_ptr = unsafe { grdr_macos_apply_es_event(follower, event.as_ptr(), event.len()) };
        assert!(!apply_ptr.is_null());
        // SAFETY: Valid CString returned by grdr_macos_apply_es_event.
        let apply_str = unsafe { CStr::from_ptr(apply_ptr) }
            .to_str()
            .unwrap()
            .to_owned();
        // SAFETY: Reclaim returned CString cleanly once.
        unsafe { grdr_macos_free_string(apply_ptr) };
        let parsed: FfiEsApplyResult = serde_json::from_str(&apply_str).unwrap();
        assert_eq!(parsed.session_id.as_deref(), Some("sess-ffi-mac"));
        assert_eq!(parsed.member_count, 1);

        let flow = serde_json::to_vec(&NeFlowRecord {
            flow_id: 1,
            agent_name: "claude-code".into(),
            governed_process: true,
            transport: FlowTransport::Udp,
            remote_port: 443,
            host_name: Some("api.anthropic.com".into()),
            tls_sni: None,
        })
        .unwrap();
        // SAFETY: Valid flow byte buffer and empty floor rules; freed below.
        let flow_ptr =
            unsafe { grdr_macos_eval_ne_flow(flow.as_ptr(), flow.len(), std::ptr::null(), 0, 0) };
        assert!(!flow_ptr.is_null());
        // SAFETY: Valid CString returned by grdr_macos_eval_ne_flow.
        let flow_str = unsafe { CStr::from_ptr(flow_ptr) }
            .to_str()
            .unwrap()
            .to_owned();
        // SAFETY: Reclaim returned CString once.
        unsafe { grdr_macos_free_string(flow_ptr) };
        assert!(flow_str.contains("drop"));

        // SAFETY: Passing null floor pointer with non-zero length must fail closed.
        let invalid_ptr =
            unsafe { grdr_macos_eval_ne_flow(flow.as_ptr(), flow.len(), std::ptr::null(), 16, 1) };
        assert!(!invalid_ptr.is_null());
        // SAFETY: Valid CString returned by grdr_macos_eval_ne_flow.
        let invalid_str = unsafe { CStr::from_ptr(invalid_ptr) }
            .to_str()
            .unwrap()
            .to_owned();
        // SAFETY: Reclaim returned CString once.
        unsafe { grdr_macos_free_string(invalid_ptr) };
        assert!(invalid_str.contains("\"error\""));

        // SAFETY: Valid probe pointer returned by grdr_macos_probe_capabilities.
        let caps_ptr = grdr_macos_probe_capabilities();
        assert!(!caps_ptr.is_null());
        // SAFETY: Reclaim returned CString once.
        unsafe { grdr_macos_free_string(caps_ptr) };

        let team = b"ABCDE12345";
        // SAFETY: Valid follower pointer and static team ID bytes; freed below.
        let mute_ptr =
            unsafe { grdr_macos_follower_mute_team(follower, team.as_ptr(), team.len()) };
        assert!(!mute_ptr.is_null());
        // SAFETY: Reclaim mute CString once.
        unsafe { grdr_macos_free_string(mute_ptr) };

        let exec_floor =
            br#"[{"rule_id":"deny-curl","action_mask":1,"prefixes":["/usr/bin/curl"],"verdict":"deny"}]"#;
        let auth_ev = serde_json::to_vec(&EsEventPayload::AuthExec {
            old_key: ProcessTreeKey {
                pid: 500,
                pidversion: 1,
            },
            target: EsAuditToken {
                key: ProcessTreeKey {
                    pid: 501,
                    pidversion: 1,
                },
                uid: 501,
                team_id: None,
            },
            executable_path: "/usr/bin/curl".into(),
        })
        .unwrap();
        // SAFETY: Valid follower, auth event JSON, and floor rules JSON; freed below.
        let auth_ptr = unsafe {
            grdr_macos_eval_es_auth_exec(
                follower,
                auth_ev.as_ptr(),
                auth_ev.len(),
                exec_floor.as_ptr(),
                exec_floor.len(),
                0,
            )
        };
        assert!(!auth_ptr.is_null());
        // SAFETY: Valid CString returned by grdr_macos_eval_es_auth_exec.
        let auth_str = unsafe { CStr::from_ptr(auth_ptr) }
            .to_str()
            .unwrap()
            .to_owned();
        // SAFETY: Reclaim auth CString once.
        unsafe { grdr_macos_free_string(auth_ptr) };
        let auth_parsed: FfiEsApplyResult = serde_json::from_str(&auth_str).unwrap();
        assert_eq!(auth_parsed.verdict, "deny");
        assert_eq!(auth_parsed.member_count, 1);

        // SAFETY: Reclaim follower handle once.
        unsafe { grdr_macos_follower_free(follower) };
    }
}
