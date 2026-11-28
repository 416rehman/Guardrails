// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod engine;
pub mod types;

use std::ffi::{CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

use grdr_core::policy::{essentials_pack, evaluate_with_session};
use grdr_core::session::SessionRuleState;
use grdr_fastpath::FLOOR_FORMAT_VERSION;
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{ActionAttempt, CodedError, DecisionReceipt, Grant, KillSwitchState, PolicyPack};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

pub use engine::FfiEngine;
pub use types::{
    AssuranceKind, BrandManifestDto, CapabilityPresence, DEFAULT_STEP_BUDGET, EngineCheckpoint,
    FfiStepOutput, HostProfileDto, InterestSummary, PackAssuranceDto, RequiredHostSignal,
    SnapshotSummary,
};

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

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FfiCommandEnvelope {
    Eval {
        attempt: Box<ActionAttempt>,
        #[serde(default)]
        packs: Vec<PolicyPack>,
        #[serde(default)]
        grants: Vec<Grant>,
        #[serde(default)]
        host_profile: Option<HostProfileDto>,
    },
    CompileFastpath {
        #[serde(default)]
        packs: Vec<PolicyPack>,
        #[serde(default)]
        timestamp_seconds: i64,
    },
    AssessHost {
        #[serde(default)]
        packs: Vec<PolicyPack>,
        host_profile: HostProfileDto,
    },
    Interest {
        #[serde(default)]
        packs: Vec<PolicyPack>,
        #[serde(default)]
        bundle_tag: String,
    },
    BrandManifest {
        #[serde(default)]
        brand_toml: Option<String>,
    },
}

pub fn evaluate_json_str(input: &str) -> String {
    if let Ok(cmd) = serde_json::from_str::<FfiCommandEnvelope>(input) {
        return handle_command_envelope(cmd);
    }

    let parsed: Result<FfiEvalRequest, _> = serde_json::from_str(input);
    let mut req = match parsed {
        Ok(r) => r,
        Err(err) => {
            let coded = CodedError::new(
                CODE_INVALID_INPUT,
                format!("Invalid FFI evaluation JSON: {err}"),
                "Provide valid FfiEvalRequest JSON payload with explicit packs.",
            );
            return serialize_or_fallback(&coded);
        }
    };

    if req.packs.is_empty() {
        let coded = CodedError::new(
            CODE_INVALID_INPUT,
            "Policy packs are required; implicit Essentials fallback is disabled.",
            "Pass an explicit non-empty packs array (or call grdr_ffi_essentials_pack_json).",
        );
        return serialize_or_fallback(&coded);
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
    serialize_or_fallback(&out)
}

fn handle_command_envelope(cmd: FfiCommandEnvelope) -> String {
    match cmd {
        FfiCommandEnvelope::Eval {
            attempt,
            packs,
            grants,
            host_profile,
        } => {
            let mut engine = FfiEngine::default();
            if let Err(err) = engine.load(
                packs,
                grants,
                KillSwitchState::Inactive,
                host_profile.unwrap_or_default(),
                String::new(),
            ) {
                return serialize_or_fallback(&err);
            }
            match engine.step(&attempt) {
                Ok(out) => serialize_or_fallback(&out),
                Err(err) => serialize_or_fallback(&err),
            }
        }
        FfiCommandEnvelope::CompileFastpath {
            packs,
            timestamp_seconds,
        } => {
            let mut engine = FfiEngine::default();
            if let Err(err) = engine.load(
                packs,
                Vec::new(),
                KillSwitchState::Inactive,
                HostProfileDto::default(),
                String::new(),
            ) {
                return serialize_or_fallback(&err);
            }
            let ts = Timestamp::from_second(timestamp_seconds).unwrap_or(Timestamp::UNIX_EPOCH);
            match engine.compile_fastpath(ts) {
                Ok(table) => serialize_or_fallback(&table),
                Err(err) => serialize_or_fallback(&err),
            }
        }
        FfiCommandEnvelope::AssessHost {
            packs,
            host_profile,
        } => {
            let mut engine = FfiEngine::default();
            if let Err(err) = engine.load(
                packs,
                Vec::new(),
                KillSwitchState::Inactive,
                host_profile,
                String::new(),
            ) {
                return serialize_or_fallback(&err);
            }
            serialize_or_fallback(&engine.assess_host_profile())
        }
        FfiCommandEnvelope::Interest { packs, bundle_tag } => {
            let mut engine = FfiEngine::default();
            if let Err(err) = engine.load(
                packs,
                Vec::new(),
                KillSwitchState::Inactive,
                HostProfileDto::default(),
                bundle_tag,
            ) {
                return serialize_or_fallback(&err);
            }
            serialize_or_fallback(&engine.interest())
        }
        FfiCommandEnvelope::BrandManifest { brand_toml } => {
            let dto = FfiEngine::brand_manifest(brand_toml.as_deref());
            serialize_or_fallback(&dto)
        }
    }
}

fn serialize_or_fallback<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".into())
}

fn to_c_string_sanitized(s: &str) -> *mut c_char {
    let cleaned = s.replace('\0', " ");
    match CString::new(cleaned) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Evaluate a JSON-encoded FfiEvalRequest or FfiCommandEnvelope and return a heap-allocated NUL-terminated UTF-8 string.
/// Free the returned pointer with `grdr_ffi_free_string`.
///
/// # Safety
/// `input_ptr` must be valid for `input_len` readable bytes.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_ffi_eval_json(input_ptr: *const u8, input_len: usize) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
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
            let msg = serialize_or_fallback(&coded);
            return to_c_string_sanitized(&msg);
        };
        let result_json = evaluate_json_str(raw_str);
        to_c_string_sanitized(&result_json)
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Return the explicitly requested Essentials PolicyPack serialized as a C string.
/// Free the returned pointer with `grdr_ffi_free_string`.
// SAFETY: Exported symbol name `grdr_ffi_essentials_pack_json` is unique across the workspace C ABI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_ffi_essentials_pack_json() -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        let json = serialize_or_fallback(&essentials_pack());
        to_c_string_sanitized(&json)
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Free a string pointer previously allocated by `grdr_ffi_eval_json` or `grdr_ffi_essentials_pack_json`.
///
/// # Safety
/// `ptr` must be null or a pointer previously returned by `grdr_ffi_*` and not yet freed.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_ffi_free_string(ptr: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() {
            return;
        }
        // SAFETY: Non-null pointer allocated via `CString::into_raw` by this crate.
        let _ = unsafe { CString::from_raw(ptr) };
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::{ActionClass, ControlPoint, Verdict};
    use jiff::Timestamp;
    use std::ffi::CStr;

    #[test]
    #[allow(unsafe_code)]
    fn c_abi_requires_explicit_packs_and_roundtrips_json() {
        let missing_packs = serde_json::json!({
            "attempt": {
                "id": "att-ffi-missing",
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
        let err_json = evaluate_json_str(&missing_packs.to_string());
        let coded: CodedError = serde_json::from_str(&err_json).unwrap();
        assert!(coded.message.contains("Policy packs are required"));

        let req = serde_json::json!({
            "packs": [essentials_pack()],
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
