// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![cfg_attr(not(test), no_std)]
#![deny(clippy::arithmetic_side_effects)]

use core::slice;
use core::str;

use grdr_fastpath::{FastActionClass, FastVerdict, FloorRuleRef, evaluate_floor_entries};

pub const MAX_FASTPATH_RULES: usize = 1024;
pub const MAX_FASTPATH_STR_BYTES: usize = 65_536;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrdrFastStatus {
    Ok = 0,
    ErrNullPtr = -1,
    ErrInvalidArg = -2,
    ErrInvalidUtf8 = -3,
    ErrLimitExceeded = -4,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrdrFastVerdict {
    Allow = 0,
    StepUp = 1,
    Deny = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GrdrFastRuleC {
    pub rule_id_ptr: *const u8,
    pub rule_id_len: usize,
    pub action_mask: u32,
    pub needle_ptr: *const u8,
    pub needle_len: usize,
    pub verdict: u8,
}

fn decode_verdict(raw: u8) -> Option<FastVerdict> {
    match raw {
        0 => Some(FastVerdict::Allow),
        1 => Some(FastVerdict::StepUp),
        2 => Some(FastVerdict::Deny),
        _ => None,
    }
}

fn encode_verdict(verdict: FastVerdict) -> u8 {
    match verdict {
        FastVerdict::Allow => GrdrFastVerdict::Allow as u8,
        FastVerdict::StepUp => GrdrFastVerdict::StepUp as u8,
        FastVerdict::Deny => GrdrFastVerdict::Deny as u8,
    }
}

/// Read a bounded UTF-8 byte range passed across C ABI.
///
/// # Safety
/// Caller must ensure `ptr` points to `len` valid readable bytes when `len > 0`.
#[allow(unsafe_code)]
unsafe fn read_utf8_arg<'a>(ptr: *const u8, len: usize) -> Result<&'a str, GrdrFastStatus> {
    if len == 0 {
        return Ok("");
    }
    if ptr.is_null() {
        return Err(GrdrFastStatus::ErrNullPtr);
    }
    if len > MAX_FASTPATH_STR_BYTES {
        return Err(GrdrFastStatus::ErrLimitExceeded);
    }
    // SAFETY: Caller guaranteed `ptr` is non-null and valid for `len <= MAX_FASTPATH_STR_BYTES` bytes.
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    str::from_utf8(bytes).map_err(|_| GrdrFastStatus::ErrInvalidUtf8)
}

/// Evaluate an array of C-ABI fastpath floor rules without heap allocation.
///
/// # Safety
/// Every non-empty pointer in `agent_ptr`, `target_ptr`, `rules_ptr`, and each rule's `rule_id_ptr` /
/// `needle_ptr` must be valid for its declared byte/element count, and `out_verdict` / `out_matched_index`
/// must be valid writable aligned pointers.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_fastpath_eval_rules(
    action_code: u8,
    agent_ptr: *const u8,
    agent_len: usize,
    target_ptr: *const u8,
    target_len: usize,
    rules_ptr: *const GrdrFastRuleC,
    rules_len: usize,
    out_verdict: *mut u8,
    out_matched_index: *mut usize,
) -> i32 {
    if out_verdict.is_null() || out_matched_index.is_null() {
        return GrdrFastStatus::ErrNullPtr as i32;
    }
    if rules_len > MAX_FASTPATH_RULES {
        return GrdrFastStatus::ErrLimitExceeded as i32;
    }
    let Some(action) = FastActionClass::from_u8(action_code) else {
        return GrdrFastStatus::ErrInvalidArg as i32;
    };

    // SAFETY: Caller guaranteed agent and target byte spans are readable for their lengths.
    let agent = match unsafe { read_utf8_arg(agent_ptr, agent_len) } {
        Ok(s) => s,
        Err(status) => return status as i32,
    };
    // SAFETY: Caller guaranteed target byte span is readable for `target_len`.
    let target = match unsafe { read_utf8_arg(target_ptr, target_len) } {
        Ok(s) => s,
        Err(status) => return status as i32,
    };

    // SAFETY: Caller guaranteed `out_verdict` and `out_matched_index` are valid writable pointers.
    unsafe {
        *out_verdict = GrdrFastVerdict::Allow as u8;
        *out_matched_index = usize::MAX;
    }

    if rules_len == 0 {
        return GrdrFastStatus::Ok as i32;
    }
    if rules_ptr.is_null() {
        return GrdrFastStatus::ErrNullPtr as i32;
    }

    // SAFETY: Non-null `rules_ptr` verified valid for `rules_len <= MAX_FASTPATH_RULES` items.
    let rules = unsafe { slice::from_raw_parts(rules_ptr, rules_len) };

    let empty_prefixes: [&str; 0] = [];
    let empty_agents: [&str; 0] = [];
    for (idx, rule) in rules.iter().enumerate() {
        let Some(verdict) = decode_verdict(rule.verdict) else {
            return GrdrFastStatus::ErrInvalidArg as i32;
        };
        // SAFETY: Each rule's string pointers are validated via `read_utf8_arg`.
        let rule_id = match unsafe { read_utf8_arg(rule.rule_id_ptr, rule.rule_id_len) } {
            Ok(s) => s,
            Err(status) => return status as i32,
        };
        // SAFETY: Rule needle span validated via `read_utf8_arg`.
        let needle = match unsafe { read_utf8_arg(rule.needle_ptr, rule.needle_len) } {
            Ok(s) => s,
            Err(status) => return status as i32,
        };
        let contains = [needle];
        let refs = [FloorRuleRef {
            rule_id,
            action_mask: rule.action_mask,
            prefixes: &empty_prefixes,
            contains: &contains,
            agents: &empty_agents,
            verdict,
        }];
        if let Some(hit) = evaluate_floor_entries(&refs, action, agent, target) {
            // SAFETY: Caller guaranteed writable aligned output pointers.
            unsafe {
                *out_verdict = encode_verdict(hit.verdict);
                *out_matched_index = idx;
            }
            break;
        }
    }

    GrdrFastStatus::Ok as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn c_abi_evaluates_rules_and_rejects_null_and_invalid_inputs() {
        let agent = b"claude-code";
        let target = br"C:\repo\.CLAUDE\settings.json";
        let rid = b"essentials.agent-control-files";
        let needle = b".claude/";

        let rules = [GrdrFastRuleC {
            rule_id_ptr: rid.as_ptr(),
            rule_id_len: rid.len(),
            action_mask: FastActionClass::FileWrite.bit(),
            needle_ptr: needle.as_ptr(),
            needle_len: needle.len(),
            verdict: GrdrFastVerdict::Deny as u8,
        }];

        let mut verdict = 99u8;
        let mut matched_idx = 99usize;

        // SAFETY: Valid stack buffers and output pointers.
        let rc = unsafe {
            grdr_fastpath_eval_rules(
                FastActionClass::FileWrite as u8,
                agent.as_ptr(),
                agent.len(),
                target.as_ptr(),
                target.len(),
                rules.as_ptr(),
                rules.len(),
                &mut verdict,
                &mut matched_idx,
            )
        };
        assert_eq!(rc, GrdrFastStatus::Ok as i32);
        assert_eq!(verdict, GrdrFastVerdict::Deny as u8);
        assert_eq!(matched_idx, 0);

        // SAFETY: Testing explicit null output guard.
        let null_rc = unsafe {
            grdr_fastpath_eval_rules(
                FastActionClass::FileWrite as u8,
                agent.as_ptr(),
                agent.len(),
                target.as_ptr(),
                target.len(),
                rules.as_ptr(),
                rules.len(),
                core::ptr::null_mut(),
                &mut matched_idx,
            )
        };
        assert_eq!(null_rc, GrdrFastStatus::ErrNullPtr as i32);
    }
}
