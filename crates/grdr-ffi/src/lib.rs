// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ffi::{CString, c_char};
use std::slice;

use serde::{Deserialize, Serialize};

use grdr_core::policy::{essentials_pack, evaluate_with_session};
use grdr_core::session::SessionRuleState;
use grdr_fastpath::FLOOR_FORMAT_VERSION;
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{ActionAttempt, CodedError, DecisionReceipt, Grant, KillSwitchState, PolicyPack};

pub const MAX_FFI_JSON_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Deserialize)]
pub struct FfiEvalRequest {
    pub attempt: ActionAttempt,
    #[serde(default)]
    pub packs: Vec<PolicyPack>,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiEvalResponse {
    pub receipt: DecisionReceipt,
    pub fastpath_version: u32,
}

pub fn evaluate_json_str(input: &str) -> String {
    let parsed: Result<FfiEvalRequest, _> = serde_json::from_str(input);
    let mut req = match parsed {
        Ok(r) => r,
        Err(err) => {
            let coded = CodedError::new(
                CODE_INVALID_INPUT,
                format!("Invalid FFI evaluation JSON: {err}"),
                "Provide valid FfiEvalRequest JSON payload.",
            );
            return serde_json::to_string(&coded).unwrap_or_else(|_| "{}".into());
        }
    };

    if req.packs.is_empty() {
        req.packs.push(essentials_pack());
    }

    let mut session = SessionRuleState::default();
    let receipt = evaluate_with_session(
        &req.attempt,
        &req.packs,
        &mut req.grants,
        &KillSwitchState::Inactive,
        &mut session,
        req.attempt.timestamp,
    );
    let out = FfiEvalResponse {
        receipt,
        fastpath_version: FLOOR_FORMAT_VERSION,
    };
    serde_json::to_string(&out).unwrap_or_else(|_| "{}".into())
}

fn to_c_string_sanitized(s: &str) -> *mut c_char {
    let cleaned = s.replace('\0', " ");
    match CString::new(cleaned) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Evaluate a JSON-encoded FfiEvalRequest and return a heap-allocated NUL-terminated UTF-8 string.
/// Free the returned pointer with `grdr_ffi_free_string`.
///
/// # Safety
/// `input_ptr` must be valid for `input_len` readable bytes.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_ffi_eval_json(input_ptr: *const u8, input_len: usize) -> *mut c_char {
    if input_ptr.is_null() || input_len == 0 || input_len > MAX_FFI_JSON_BYTES {
        return std::ptr::null_mut();
    }
    // SAFETY: Verified non-null and bounded byte slice provided by caller.
    let bytes = unsafe { slice::from_raw_parts(input_ptr, input_len) };
    let Ok(raw_str) = std::str::from_utf8(bytes) else {
        let coded = CodedError::new(
            CODE_INVALID_INPUT,
            "FFI input is not valid UTF-8.",
            "Encode FfiEvalRequest as UTF-8 JSON.",
        );
        let msg = serde_json::to_string(&coded).unwrap_or_else(|_| "{}".into());
        return to_c_string_sanitized(&msg);
    };
    let result_json = evaluate_json_str(raw_str);
    to_c_string_sanitized(&result_json)
}

/// Return the default Essentials PolicyPack serialized as a C string.
/// Free the returned pointer with `grdr_ffi_free_string`.
// SAFETY: Exported symbol name `grdr_ffi_essentials_pack_json` is unique across the workspace C ABI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_ffi_essentials_pack_json() -> *mut c_char {
    let json = serde_json::to_string(&essentials_pack()).unwrap_or_else(|_| "{}".into());
    to_c_string_sanitized(&json)
}

/// Free a string pointer previously allocated by `grdr_ffi_eval_json` or `grdr_ffi_essentials_pack_json`.
///
/// # Safety
/// `ptr` must be null or a pointer previously returned by `grdr_ffi_*` and not yet freed.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_ffi_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: Non-null pointer allocated via `CString::into_raw` by this crate.
    let _ = unsafe { CString::from_raw(ptr) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::{ActionClass, ControlPoint, Verdict};
    use jiff::Timestamp;
    use std::ffi::CStr;

    #[test]
    #[allow(unsafe_code)]
    fn c_abi_json_eval_and_free_roundtrip() {
        let req = serde_json::json!({
            "attempt": {
                "id": "att-ffi-1",
                "session_id": "sess-ffi",
                "device_id": "dev-ffi",
                "device_name": "host-ffi",
                "agent_name": "claude-code",
                "action_class": ActionClass::FileWrite,
                "control_point": ControlPoint::Hook,
                "target": ".claude/settings.json",
                "summary": "Edit settings",
                "timestamp": Timestamp::from_second(1_700_000_000).unwrap(),
            }
        });
        let raw = serde_json::to_vec(&req).unwrap();

        // SAFETY: `raw` buffer is valid for `raw.len()` bytes; pointer freed immediately below.
        let out_ptr = unsafe { grdr_ffi_eval_json(raw.as_ptr(), raw.len()) };
        assert!(!out_ptr.is_null());

        // SAFETY: `out_ptr` is valid NUL-terminated CString returned by `grdr_ffi_eval_json`.
        let out_str = unsafe { CStr::from_ptr(out_ptr) }
            .to_str()
            .unwrap()
            .to_owned();
        // SAFETY: Reclaiming ownership cleanly once.
        unsafe { grdr_ffi_free_string(out_ptr) };

        let parsed: FfiEvalResponse = serde_json::from_str(&out_str).unwrap();
        assert_eq!(parsed.receipt.verdict, Verdict::Deny);

        // SAFETY: Null pointer free is a safe no-op.
        unsafe { grdr_ffi_free_string(std::ptr::null_mut()) };
    }
}
