// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![cfg_attr(not(test), no_std)]
#![deny(clippy::arithmetic_side_effects)]

pub mod host_bridge;

use core::slice;
use core::str;

use grdr_fastpath::{FastActionClass, FastVerdict, FloorRuleRef, evaluate_floor_entries};

pub use host_bridge::{
    GrdrFpHostProfileC, GrdrFpInterestC, HostEvalRequest, HostEvalSummary, HostLabelStateC,
    assess_host_profile_c, embedded_brand_manifest, eval_binary_table_with_interest,
    eval_manifest_failsafe,
};

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
    ErrNotEvaluable = -5,
    ErrState = -6,
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
    pub struct_size: usize,
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

fn verdict_rank(verdict: FastVerdict) -> u8 {
    match verdict {
        FastVerdict::Allow => 0,
        FastVerdict::StepUp => 1,
        FastVerdict::Deny => 2,
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

fn ranges_overlap(a_ptr: usize, a_len: usize, b_ptr: usize, b_len: usize) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let a_end = a_ptr.saturating_add(a_len);
    let b_end = b_ptr.saturating_add(b_len);
    a_ptr < b_end && b_ptr < a_end
}

fn check_no_output_overlap(
    out_verdict: *mut u8,
    out_matched_index: *mut usize,
    in_ptr: *const u8,
    in_len: usize,
) -> bool {
    let v_addr = out_verdict as usize;
    let m_addr = out_matched_index as usize;
    let i_addr = in_ptr as usize;
    let m_size = core::mem::size_of::<usize>();
    ranges_overlap(v_addr, 1, m_addr, m_size)
        || ranges_overlap(v_addr, 1, i_addr, in_len)
        || ranges_overlap(m_addr, m_size, i_addr, in_len)
}

/// Evaluate an array of C-ABI fastpath floor rules without heap allocation, using deny-wins order.
///
/// # Safety
/// Every non-empty pointer in `agent_ptr`, `target_ptr`, `rules_ptr`, and each rule's `rule_id_ptr` /
/// `needle_ptr` must be valid for its declared byte/element count, non-overlapping with outputs, and
/// `out_verdict` / `out_matched_index` must be valid writable aligned pointers.
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
    if !out_verdict.is_aligned() || !out_matched_index.is_aligned() {
        return GrdrFastStatus::ErrInvalidArg as i32;
    }
    if rules_len > MAX_FASTPATH_RULES {
        return GrdrFastStatus::ErrLimitExceeded as i32;
    }
    let Some(action) = FastActionClass::from_u8(action_code) else {
        return GrdrFastStatus::ErrInvalidArg as i32;
    };
    if check_no_output_overlap(out_verdict, out_matched_index, agent_ptr, agent_len)
        || check_no_output_overlap(out_verdict, out_matched_index, target_ptr, target_len)
    {
        return GrdrFastStatus::ErrInvalidArg as i32;
    }

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

    if rules_len == 0 {
        // SAFETY: Output pointers verified non-null, aligned, and disjoint.
        unsafe {
            *out_verdict = GrdrFastVerdict::Allow as u8;
            *out_matched_index = usize::MAX;
        }
        return GrdrFastStatus::Ok as i32;
    }
    if rules_ptr.is_null() {
        return GrdrFastStatus::ErrNullPtr as i32;
    }
    if !rules_ptr.is_aligned() {
        return GrdrFastStatus::ErrInvalidArg as i32;
    }
    let Some(rules_bytes) = rules_len.checked_mul(core::mem::size_of::<GrdrFastRuleC>()) else {
        return GrdrFastStatus::ErrLimitExceeded as i32;
    };
    if check_no_output_overlap(
        out_verdict,
        out_matched_index,
        rules_ptr.cast::<u8>(),
        rules_bytes,
    ) {
        return GrdrFastStatus::ErrInvalidArg as i32;
    }

    // SAFETY: Non-null aligned `rules_ptr` verified valid for `rules_len <= MAX_FASTPATH_RULES` items.
    let rules = unsafe { slice::from_raw_parts(rules_ptr, rules_len) };

    let empty_prefixes: [&str; 0] = [];
    let empty_agents: [&str; 0] = [];
    let mut best: Option<(FastVerdict, usize)> = None;

    for (idx, rule) in rules.iter().enumerate() {
        if rule.struct_size != core::mem::size_of::<GrdrFastRuleC>() {
            return GrdrFastStatus::ErrInvalidArg as i32;
        }
        let Some(verdict) = decode_verdict(rule.verdict) else {
            return GrdrFastStatus::ErrInvalidArg as i32;
        };
        if check_no_output_overlap(
            out_verdict,
            out_matched_index,
            rule.rule_id_ptr,
            rule.rule_id_len,
        ) || check_no_output_overlap(
            out_verdict,
            out_matched_index,
            rule.needle_ptr,
            rule.needle_len,
        ) {
            return GrdrFastStatus::ErrInvalidArg as i32;
        }
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
        if let Some(hit) = evaluate_floor_entries(&refs, action, agent, target)
            && best.is_none_or(|(cur, _)| verdict_rank(hit.verdict) > verdict_rank(cur))
        {
            best = Some((hit.verdict, idx));
        }
    }

    // SAFETY: All rule entries validated cleanly and output pointers are verified aligned and disjoint.
    unsafe {
        match best {
            Some((verdict, idx)) => {
                *out_verdict = encode_verdict(verdict);
                *out_matched_index = idx;
            }
            None => {
                *out_verdict = GrdrFastVerdict::Allow as u8;
                *out_matched_index = usize::MAX;
            }
        }
    }

    GrdrFastStatus::Ok as i32
}

/// Assess whether a C-ABI host capability profile satisfies rule requirements.
///
/// # Safety
/// `profile` must be non-null and aligned for `GrdrFpHostProfileC`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_fastpath_assess_host_profile(
    profile: *const GrdrFpHostProfileC,
    req_mask: u8,
) -> i32 {
    if profile.is_null() {
        return GrdrFastStatus::ErrNullPtr as i32;
    }
    if !profile.is_aligned() {
        return GrdrFastStatus::ErrInvalidArg as i32;
    }
    // SAFETY: Caller provided a non-null, aligned `GrdrFpHostProfileC` pointer.
    let raw = unsafe { *profile };
    if raw.struct_size != core::mem::size_of::<GrdrFpHostProfileC>() {
        return GrdrFastStatus::ErrInvalidArg as i32;
    }
    host_bridge::assess_host_profile_mask_c(raw, req_mask) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_fastpath::{
        BinaryRuleInput, LABEL_CREDENTIAL_ACCESSED, PRINCIPAL_SESSION, encode_binary_floor,
        encoded_binary_floor_size,
    };

    #[test]
    #[allow(unsafe_code)]
    fn c_abi_evaluates_rules_deny_wins_and_rejects_invalid_inputs() {
        let agent = b"claude-code";
        let target = br"C:\repo\.CLAUDE\settings.json";
        let rid_step = b"r.stepup";
        let rid_deny = b"essentials.agent-control-files";
        let needle = b".claude/";

        let rules = [
            GrdrFastRuleC {
                struct_size: core::mem::size_of::<GrdrFastRuleC>(),
                rule_id_ptr: rid_step.as_ptr(),
                rule_id_len: rid_step.len(),
                action_mask: FastActionClass::FileWrite.bit(),
                needle_ptr: needle.as_ptr(),
                needle_len: needle.len(),
                verdict: GrdrFastVerdict::StepUp as u8,
            },
            GrdrFastRuleC {
                struct_size: core::mem::size_of::<GrdrFastRuleC>(),
                rule_id_ptr: rid_deny.as_ptr(),
                rule_id_len: rid_deny.len(),
                action_mask: FastActionClass::FileWrite.bit(),
                needle_ptr: needle.as_ptr(),
                needle_len: needle.len(),
                verdict: GrdrFastVerdict::Deny as u8,
            },
        ];

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
        assert_eq!(matched_idx, 1);

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

    #[test]
    fn host_bridge_enforces_label_bundle_state_and_brand_manifest() {
        let entry = [BinaryRuleInput {
            rule_id: "r.label",
            reason: "Blocked tainted exfil",
            action_mask: FastActionClass::NetRequest.bit(),
            principal_mask: PRINCIPAL_SESSION,
            label_mask: LABEL_CREDENTIAL_ACCESSED,
            verdict: FastVerdict::Deny,
            agents: &[],
            prefixes: &[],
            contains: &["drop.example"],
        }];
        let (size, _) = encoded_binary_floor_size(&entry).unwrap();
        let mut buf = [0u8; 512];
        let written = encode_binary_floor(&entry, &mut buf[..size]).unwrap();

        let tag = [0x42u8; 32];
        let interest = GrdrFpInterestC {
            action_mask: FastActionClass::NetRequest.bit(),
            label_mask: LABEL_CREDENTIAL_ACCESSED,
            expected_bundle_tag: tag,
        };

        let missing = eval_binary_table_with_interest(
            &buf[..written],
            &HostEvalRequest {
                interest,
                label_state: HostLabelStateC::MissingOrLate,
                action: FastActionClass::NetRequest,
                principal_mask: PRINCIPAL_SESSION,
                agent: "claude-code",
                target: "https://drop.example/upload",
            },
        );
        assert_eq!(missing.status, GrdrFastStatus::ErrState);
        assert_eq!(missing.verdict, GrdrFastVerdict::Deny);

        let ready = eval_binary_table_with_interest(
            &buf[..written],
            &HostEvalRequest {
                interest,
                label_state: HostLabelStateC::Ready {
                    active_labels_mask: LABEL_CREDENTIAL_ACCESSED,
                    bundle_tag: tag,
                },
                action: FastActionClass::NetRequest,
                principal_mask: PRINCIPAL_SESSION,
                agent: "claude-code",
                target: "https://drop.example/upload",
            },
        );
        assert_eq!(ready.status, GrdrFastStatus::Ok);
        assert_eq!(ready.verdict, GrdrFastVerdict::Deny);
        assert_eq!(
            assess_host_profile_c(
                GrdrFpHostProfileC {
                    struct_size: core::mem::size_of::<GrdrFpHostProfileC>(),
                    principal_attestation: 1,
                    user_identity: 0,
                    os_file_sensor: 1,
                    net_egress_sensor: 0,
                    command_parser: 1,
                    session_store: 0,
                },
                true,
                false,
                false,
            ),
            GrdrFastStatus::ErrNotEvaluable
        );
        assert!(!embedded_brand_manifest().product_name.is_empty());
    }

    #[test]
    #[allow(unsafe_code)]
    fn c_abi_rejects_unaligned_overlapping_and_invalid_rules_without_partial_writes() {
        let agent = b"claude-code";
        let target = b".claude/settings.json";
        let rid = b"r.deny";
        let needle = b".claude/";
        let bad_utf8: [u8; 2] = [0xff, 0xfe];

        let mut verdict = 99u8;
        let mut matched_idx = 99usize;

        // 1. Unaligned out_matched_index must fail before any write.
        let mut raw_usize_buf = [0u8; 32];
        let unaligned_idx = raw_usize_buf.as_mut_ptr().wrapping_add(1).cast::<usize>();
        let rc_unaligned = unsafe {
            grdr_fastpath_eval_rules(
                FastActionClass::FileWrite as u8,
                agent.as_ptr(),
                agent.len(),
                target.as_ptr(),
                target.len(),
                core::ptr::null(),
                0,
                &mut verdict,
                unaligned_idx,
            )
        };
        assert_eq!(rc_unaligned, GrdrFastStatus::ErrInvalidArg as i32);
        assert_eq!(verdict, 99u8);

        // 2. Overlapping output and input buffer must fail before any write.
        let mut overlap_buf = *b"claude-code";
        let rc_overlap = unsafe {
            grdr_fastpath_eval_rules(
                FastActionClass::FileWrite as u8,
                overlap_buf.as_ptr(),
                overlap_buf.len(),
                target.as_ptr(),
                target.len(),
                core::ptr::null(),
                0,
                overlap_buf.as_mut_ptr().add(2),
                &mut matched_idx,
            )
        };
        assert_eq!(rc_overlap, GrdrFastStatus::ErrInvalidArg as i32);
        assert_eq!(matched_idx, 99usize);

        // 3. Rule 0 matches, Rule 1 has invalid UTF-8: must fail without writing matched outputs.
        let rules = [
            GrdrFastRuleC {
                struct_size: core::mem::size_of::<GrdrFastRuleC>(),
                rule_id_ptr: rid.as_ptr(),
                rule_id_len: rid.len(),
                action_mask: FastActionClass::FileWrite.bit(),
                needle_ptr: needle.as_ptr(),
                needle_len: needle.len(),
                verdict: GrdrFastVerdict::Deny as u8,
            },
            GrdrFastRuleC {
                struct_size: core::mem::size_of::<GrdrFastRuleC>(),
                rule_id_ptr: bad_utf8.as_ptr(),
                rule_id_len: bad_utf8.len(),
                action_mask: FastActionClass::FileWrite.bit(),
                needle_ptr: needle.as_ptr(),
                needle_len: needle.len(),
                verdict: GrdrFastVerdict::StepUp as u8,
            },
        ];
        let rc_partial = unsafe {
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
        assert_eq!(rc_partial, GrdrFastStatus::ErrInvalidUtf8 as i32);
        assert_eq!(verdict, 99u8);
        assert_eq!(matched_idx, 99usize);

        // 3b. Bad struct_size in GrdrFastRuleC must fail cleanly.
        let bad_size_rule = [GrdrFastRuleC {
            struct_size: 1,
            rule_id_ptr: rid.as_ptr(),
            rule_id_len: rid.len(),
            action_mask: FastActionClass::FileWrite.bit(),
            needle_ptr: needle.as_ptr(),
            needle_len: needle.len(),
            verdict: GrdrFastVerdict::Deny as u8,
        }];
        let rc_bad_rule_size = unsafe {
            grdr_fastpath_eval_rules(
                FastActionClass::FileWrite as u8,
                agent.as_ptr(),
                agent.len(),
                target.as_ptr(),
                target.len(),
                bad_size_rule.as_ptr(),
                bad_size_rule.len(),
                &mut verdict,
                &mut matched_idx,
            )
        };
        assert_eq!(rc_bad_rule_size, GrdrFastStatus::ErrInvalidArg as i32);

        // 4. Unaligned rules_ptr must fail.
        let mut rule_bytes = [0u8; 128];
        let unaligned_rules = rule_bytes
            .as_mut_ptr()
            .wrapping_add(1)
            .cast::<GrdrFastRuleC>();
        let rc_unaligned_rules = unsafe {
            grdr_fastpath_eval_rules(
                FastActionClass::FileWrite as u8,
                agent.as_ptr(),
                agent.len(),
                target.as_ptr(),
                target.len(),
                unaligned_rules,
                1,
                &mut verdict,
                &mut matched_idx,
            )
        };
        assert_eq!(rc_unaligned_rules, GrdrFastStatus::ErrInvalidArg as i32);

        // 5. Host profile C ABI assesses REQ_OS_FILE_SENSOR, REQ_COMMAND_PARSER, and struct_size.
        let no_file_profile = GrdrFpHostProfileC {
            struct_size: core::mem::size_of::<GrdrFpHostProfileC>(),
            principal_attestation: 1,
            user_identity: 1,
            os_file_sensor: 0,
            net_egress_sensor: 1,
            command_parser: 1,
            session_store: 1,
        };
        let rc_no_file = unsafe {
            grdr_fastpath_assess_host_profile(&no_file_profile, grdr_fastpath::REQ_OS_FILE_SENSOR)
        };
        assert_eq!(rc_no_file, GrdrFastStatus::ErrNotEvaluable as i32);
        let rc_ok = unsafe {
            grdr_fastpath_assess_host_profile(&no_file_profile, grdr_fastpath::REQ_COMMAND_PARSER)
        };
        assert_eq!(rc_ok, GrdrFastStatus::Ok as i32);

        let mut bad_profile = no_file_profile;
        bad_profile.struct_size = 0;
        let rc_bad_prof_size = unsafe {
            grdr_fastpath_assess_host_profile(&bad_profile, grdr_fastpath::REQ_COMMAND_PARSER)
        };
        assert_eq!(rc_bad_prof_size, GrdrFastStatus::ErrInvalidArg as i32);
    }
}
