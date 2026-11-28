// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use core::slice;
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

use serde::Serialize;

use crate::evaluate_attempt_receipt;
use crate::model_dto::{WasmDecisionReceipt, WasmVerdict};

pub const WASM_ABI_VERSION: u32 = 1;
pub const MAX_WASM_ABI_BYTES: usize = 1_048_576;

static ALLOCATED_BUFFERS: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
static RESULT_BUFFER: Mutex<Vec<u8>> = Mutex::new(Vec::new());

#[derive(Serialize)]
struct WasmAbiResult<'a> {
    verdict: &'static str,
    rule_id: Option<&'a str>,
    reason: &'a str,
    receipt: &'a WasmDecisionReceipt,
}

#[derive(Serialize)]
struct WasmAbiError<'a> {
    error: &'a str,
    code: &'a str,
}

fn lock_alloc_map() -> std::sync::MutexGuard<'static, BTreeMap<usize, usize>> {
    match ALLOCATED_BUFFERS.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn lock_result_buf() -> std::sync::MutexGuard<'static, Vec<u8>> {
    match RESULT_BUFFER.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn store_result(bytes: Vec<u8>) {
    let mut guard = lock_result_buf();
    *guard = bytes;
}

fn store_error(code: &str, error: &str) {
    let encoded = serde_json::to_vec(&WasmAbiError { error, code }).unwrap_or_else(|_| {
        br#"{"error":"serialization failed","code":"GRDR-MODEL-0001"}"#.to_vec()
    });
    store_result(encoded);
}

fn sdk_verdict_str(verdict: WasmVerdict) -> &'static str {
    match verdict {
        WasmVerdict::Allow => "allow",
        WasmVerdict::Modify => "modify",
        WasmVerdict::StepUp | WasmVerdict::Defer => "ask",
        WasmVerdict::Deny => "block",
    }
}

/// Allocate a bounded byte buffer for host-to-WASM input transfer.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_alloc(len: usize) -> *mut u8 {
    catch_unwind(AssertUnwindSafe(|| {
        if len == 0 || len > MAX_WASM_ABI_BYTES {
            return core::ptr::null_mut();
        }
        let Ok(layout) = Layout::from_size_align(len, 1) else {
            return core::ptr::null_mut();
        };
        // SAFETY: `layout` has verified non-zero size <= MAX_WASM_ABI_BYTES and alignment 1.
        let ptr = unsafe { alloc_zeroed(layout) };
        if !ptr.is_null() {
            lock_alloc_map().insert(ptr as usize, len);
        }
        ptr
    }))
    .unwrap_or(core::ptr::null_mut())
}

/// Free a buffer previously returned by `grdr_alloc` with matching length.
///
/// # Safety
/// `ptr` must be null or a live allocation returned by `grdr_alloc` with matching `len`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_free(ptr: *mut u8, len: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() || len == 0 || len > MAX_WASM_ABI_BYTES {
            return;
        }
        let addr = ptr as usize;
        let expected_len = {
            let mut map = lock_alloc_map();
            match map.get(&addr).copied() {
                Some(stored) if stored == len => map.remove(&addr),
                _ => None,
            }
        };
        if let Some(valid_len) = expected_len
            && let Ok(layout) = Layout::from_size_align(valid_len, 1)
        {
            // SAFETY: `addr` and `valid_len` matched a live `grdr_alloc` entry removed atomically from `ALLOCATED_BUFFERS`.
            unsafe { dealloc(ptr, layout) };
        }
    }));
}

/// Return the WASM C-ABI protocol version.
// SAFETY: Unique exported C-ABI symbol across workspace.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_wasm_abi_version() -> u32 {
    WASM_ABI_VERSION
}

/// Evaluate a JSON `{ attempt, packs }` input span in WASM linear memory.
/// Returns `0` on success or `-1` on error; inspect output via `grdr_result_ptr` / `grdr_result_len`.
///
/// # Safety
/// `ptr` must point to `len` readable bytes.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_wasm_eval_attempt(ptr: *const u8, len: usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() || len == 0 || len > MAX_WASM_ABI_BYTES {
            store_error(
                crate::model_dto::CODE_INVALID_INPUT,
                "WASM input pointer is null or length is out of bounds.",
            );
            return -1;
        }
        // SAFETY: Caller guaranteed `ptr` points to `len <= MAX_WASM_ABI_BYTES` readable bytes.
        let bytes = unsafe { slice::from_raw_parts(ptr, len) };
        let Ok(raw_json) = core::str::from_utf8(bytes) else {
            store_error(
                crate::model_dto::CODE_INVALID_INPUT,
                "WASM input is not valid UTF-8.",
            );
            return -1;
        };
        match evaluate_attempt_receipt(raw_json) {
            Ok(receipt) => {
                let payload = WasmAbiResult {
                    verdict: sdk_verdict_str(receipt.verdict),
                    rule_id: receipt.rule_id.as_deref(),
                    reason: &receipt.reason,
                    receipt: &receipt,
                };
                match serde_json::to_vec(&payload) {
                    Ok(encoded) => {
                        store_result(encoded);
                        0
                    }
                    Err(e) => {
                        store_error(
                            crate::model_dto::CODE_INVALID_INPUT,
                            &format!("Failed serializing WASM receipt: {e}"),
                        );
                        -1
                    }
                }
            }
            Err(err) => {
                store_error(&err.code, &err.message);
                -1
            }
        }
    }))
    .unwrap_or(-1)
}

/// Return pointer to the last result buffer written by `grdr_wasm_eval_attempt` (valid until next eval call under single-threaded Wasm / sequential C-ABI host contract).
// SAFETY: Unique exported C-ABI symbol across workspace; single-threaded Wasm / sequential host reads immediately after eval before next write.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_result_ptr() -> *const u8 {
    lock_result_buf().as_ptr()
}

/// Return byte length of the last result buffer written by `grdr_wasm_eval_attempt`.
// SAFETY: Unique exported C-ABI symbol across workspace; reads synchronized RESULT_BUFFER length matching grdr_result_ptr.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_result_len() -> usize {
    lock_result_buf().len()
}
