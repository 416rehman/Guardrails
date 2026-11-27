// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

use grdr_fastpath::{BinaryFloorTable, FastActionClass};

use crate::catalogue::HarnessCatalogue;
use crate::ffi_common::{
    read_bytes_arg, read_floor_rules_c, read_utf8_arg, with_decoded_floor_refs, wrap_status,
};
use crate::ffi_types::{
    GrdrMacDnsParseOutC, GrdrMacFfiStatus, GrdrMacFloorRuleC, GrdrMacNeFlowC, GrdrMacNeVerdictC,
    GrdrMacSeatbeltPlanC, GrdrMacSeatbeltRequestC, GrdrMacStrSliceC, GrdrMacTlsSniOutC,
    GrdrMacTlsSniStatusCode, GrdrMacVerdictCode, MAX_FFI_SEATBELT_PATHS, copy_str_into_fixed,
};
use crate::network_ext::{
    EgressDefaultPolicy, FlowTransport, NeFlowRecord, NeFlowVerdict, evaluate_ne_flow,
    evaluate_ne_flow_table,
};
use crate::seatbelt::{MacOsContainmentMode, SeatbeltProfileSpec, plan_macos_launch};
use crate::tls_dns::{TlsSniPeekResult, parse_dns_packet, peek_tls_client_hello_sni};

/// Evaluate a fixed-layout `GrdrMacNeFlowC` against `GrdrMacFloorRuleC` array.
///
/// # Safety
/// `flow`, `out_verdict`, and optional `floor_rules` (`floor_len` entries) must be valid pointers.
#[allow(
    unsafe_code,
    reason = "Zero-JSON Network Extension flow evaluation across C ABI."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_eval_ne_flow_c(
    flow: *const GrdrMacNeFlowC,
    floor_rules: *const GrdrMacFloorRuleC,
    floor_len: usize,
    out_verdict: *mut GrdrMacNeVerdictC,
) -> i32 {
    if flow.is_null() || out_verdict.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Decode flow record across C ABI.")]
        // SAFETY: Validated non-null pointers above.
        let (record, default_policy) = unsafe { decode_ne_flow_c(&*flow) }?;
        #[allow(unsafe_code, reason = "Read fixed-layout floor rules across C ABI.")]
        // SAFETY: Bounded floor_len checked by read_floor_rules_c.
        let decoded = unsafe { read_floor_rules_c(floor_rules, floor_len) }?;
        let verdict = with_decoded_floor_refs(&decoded, FastActionClass::NetConnect, |refs| {
            evaluate_ne_flow(&record, refs, default_policy)
        });
        let out = encode_ne_verdict(&verdict);
        #[allow(unsafe_code, reason = "Write GrdrMacNeVerdictC to caller buffer.")]
        // SAFETY: Checked out_verdict non-null above.
        unsafe {
            *out_verdict = out;
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

/// Evaluate a fixed-layout `GrdrMacNeFlowC` against compiled binary floor table bytes.
///
/// # Safety
/// `flow`, `out_verdict`, and optional `floor_bin_ptr` (`floor_bin_len` bytes) must be valid.
#[allow(
    unsafe_code,
    reason = "Zero-JSON Network Extension binary floor table evaluation across C ABI."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_eval_ne_flow_bin_c(
    flow: *const GrdrMacNeFlowC,
    floor_bin_ptr: *const u8,
    floor_bin_len: usize,
    out_verdict: *mut GrdrMacNeVerdictC,
) -> i32 {
    if flow.is_null() || out_verdict.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Decode flow record across C ABI.")]
        // SAFETY: Validated non-null flow pointer above.
        let (record, default_policy) = unsafe { decode_ne_flow_c(&*flow) }?;
        let verdict = if floor_bin_len == 0 {
            evaluate_ne_flow(&record, &[], default_policy)
        } else {
            #[allow(unsafe_code, reason = "Read binary floor table bytes across C ABI.")]
            // SAFETY: Bounded slice verified via read_bytes_arg.
            let bin = unsafe { read_bytes_arg(floor_bin_ptr, floor_bin_len) }?;
            let table =
                BinaryFloorTable::parse(bin).map_err(|_| GrdrMacFfiStatus::ErrInvalidArg)?;
            evaluate_ne_flow_table(&record, &table, default_policy)
        };
        let out = encode_ne_verdict(&verdict);
        #[allow(unsafe_code, reason = "Write GrdrMacNeVerdictC to caller buffer.")]
        // SAFETY: Checked out_verdict non-null above.
        unsafe {
            *out_verdict = out;
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

/// Peek TLS ClientHello SNI from outbound TCP flow bytes without JSON.
///
/// # Safety
/// `bytes_ptr` (when `bytes_len > 0`) and `out_sni` must be valid pointers.
#[allow(unsafe_code, reason = "Zero-JSON TLS SNI packet peek across C ABI.")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_peek_tls_sni_c(
    bytes_ptr: *const u8,
    bytes_len: usize,
    out_sni: *mut GrdrMacTlsSniOutC,
) -> i32 {
    if out_sni.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Read outbound TCP bytes across C ABI.")]
        // SAFETY: Bounded slice validated by read_bytes_arg.
        let raw = unsafe { read_bytes_arg(bytes_ptr, bytes_len) }?;
        let mut out = GrdrMacTlsSniOutC::default();
        match peek_tls_client_hello_sni(raw) {
            TlsSniPeekResult::Found { sni } => {
                out.status_code = GrdrMacTlsSniStatusCode::Found as u8;
                out.sni_len = copy_str_into_fixed(&sni, &mut out.sni);
            }
            TlsSniPeekResult::NeedMoreBytes => {
                out.status_code = GrdrMacTlsSniStatusCode::NeedMoreBytes as u8;
            }
            TlsSniPeekResult::NotTls => {
                out.status_code = GrdrMacTlsSniStatusCode::NotTls as u8;
            }
            TlsSniPeekResult::NoSniExtension => {
                out.status_code = GrdrMacTlsSniStatusCode::NoSni as u8;
            }
            TlsSniPeekResult::Malformed => {
                out.status_code = GrdrMacTlsSniStatusCode::Malformed as u8;
            }
        }
        #[allow(unsafe_code, reason = "Write GrdrMacTlsSniOutC to caller buffer.")]
        // SAFETY: Checked out_sni non-null above.
        unsafe {
            *out_sni = out;
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

/// Parse DNS query/response wire bytes into a fixed `GrdrMacDnsParseOutC` struct.
///
/// # Safety
/// `pkt_ptr` (`pkt_len` bytes) and `out_dns` must be valid pointers.
#[allow(unsafe_code, reason = "Zero-JSON DNS wire packet parser across C ABI.")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_parse_dns_packet_c(
    pkt_ptr: *const u8,
    pkt_len: usize,
    out_dns: *mut GrdrMacDnsParseOutC,
) -> i32 {
    if out_dns.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Read DNS wire packet bytes across C ABI.")]
        // SAFETY: Bounded slice verified via read_bytes_arg.
        let pkt = unsafe { read_bytes_arg(pkt_ptr, pkt_len) }?;
        let Some(parsed) = parse_dns_packet(pkt) else {
            return Err(GrdrMacFfiStatus::ErrInvalidArg);
        };
        let mut out = GrdrMacDnsParseOutC {
            tx_id: parsed.tx_id,
            is_response: u8::from(parsed.is_response),
            rcode: parsed.rcode,
            qtype: parsed.query_type,
            min_ttl_secs: parsed.min_ttl_secs,
            ..Default::default()
        };
        out.qname_len = copy_str_into_fixed(&parsed.query_name, &mut out.qname);
        let max_ips = parsed.answer_ips.len().min(8);
        for idx in 0..max_ips {
            let Some(ip) = parsed.answer_ips.get(idx) else {
                break;
            };
            match ip {
                IpAddr::V4(v4) => {
                    if let (Some(dst), Some(fam)) =
                        (out.ips.get_mut(idx), out.ip_families.get_mut(idx))
                    {
                        if let Some(head) = dst.get_mut(..4) {
                            head.copy_from_slice(&v4.octets());
                        }
                        *fam = 4;
                    }
                }
                IpAddr::V6(v6) => {
                    if let (Some(dst), Some(fam)) =
                        (out.ips.get_mut(idx), out.ip_families.get_mut(idx))
                    {
                        dst.copy_from_slice(&v6.octets());
                        *fam = 6;
                    }
                }
            }
        }
        out.ip_count = u8::try_from(max_ips).unwrap_or(0);
        #[allow(unsafe_code, reason = "Write GrdrMacDnsParseOutC to caller buffer.")]
        // SAFETY: Checked out_dns non-null above.
        unsafe {
            *out_dns = out;
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

/// Check if a hostname matches any catalogued LLM model API host suffix via P14 `HarnessCatalogue`.
///
/// # Safety
/// `host_ptr` (when `host_len > 0`) and `out_matched` must be valid pointers.
#[allow(
    unsafe_code,
    reason = "C-ABI P14 model host suffix check for TransparentProxyProvider."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_match_model_host_c(
    host_ptr: *const u8,
    host_len: usize,
    out_matched: *mut u8,
) -> i32 {
    if out_matched.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Read UTF-8 host bytes across C ABI.")]
        // SAFETY: Bounded slice verified via read_utf8_arg.
        let host = unsafe { read_utf8_arg(host_ptr, host_len) }?;
        let matched = HarnessCatalogue::embedded().match_model_host(host);
        #[allow(unsafe_code, reason = "Write match boolean byte to caller pointer.")]
        // SAFETY: Checked out_matched non-null above.
        unsafe {
            *out_matched = u8::from(matched);
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

/// Plan a Seatbelt launch profile from fixed `GrdrMacSeatbeltRequestC` into caller-supplied output buffer.
///
/// # Safety
/// `req`, `out_plan`, optional `out_plan.profile_buf` (`profile_buf_cap` bytes), and slice arrays in `req` must be valid.
#[allow(
    unsafe_code,
    reason = "Zero-JSON fixed-struct Seatbelt planner entry point across C ABI."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_plan_seatbelt_c(
    req: *const GrdrMacSeatbeltRequestC,
    out_plan: *mut GrdrMacSeatbeltPlanC,
) -> i32 {
    if req.is_null() || out_plan.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(
            unsafe_code,
            reason = "Copy caller GrdrMacSeatbeltRequestC and GrdrMacSeatbeltPlanC."
        )]
        // SAFETY: Non-null aligned pointers checked above.
        let (r, mut plan_out) = unsafe { (*req, *out_plan) };
        let (agent, session_id, workspace_root, decide_socket_path, state_dirs, protected_paths) = {
            #[allow(
                unsafe_code,
                reason = "Read UTF-8 paths and slices from GrdrMacSeatbeltRequestC."
            )]
            // SAFETY: All pointer/len fields verified via read_utf8_arg and read_str_slice_array.
            unsafe {
                (
                    read_utf8_arg(r.agent_ptr, r.agent_len)?,
                    read_utf8_arg(r.session_id_ptr, r.session_id_len)?,
                    read_utf8_arg(r.workspace_ptr, r.workspace_len)?,
                    read_utf8_arg(r.decide_socket_ptr, r.decide_socket_len)?,
                    read_str_slice_array(r.state_dirs_ptr, r.state_dirs_len)?,
                    read_str_slice_array(r.protected_paths_ptr, r.protected_paths_len)?,
                )
            }
        };
        let spec = SeatbeltProfileSpec {
            session_id: session_id.to_string(),
            workspace_root: workspace_root.to_string(),
            state_dirs,
            protected_paths,
            decide_socket_path: decide_socket_path.to_string(),
            proxy_port: r.proxy_port,
            deny_elevation_binaries: r.deny_elevation_binaries != 0,
        };
        let plan = plan_macos_launch(agent, r.agent_has_own_seatbelt != 0, &spec)
            .map_err(|_| GrdrMacFfiStatus::ErrInvalidArg)?;

        plan_out.containment_code = match plan.containment_mode {
            MacOsContainmentMode::Delegate => 0,
            MacOsContainmentMode::WrapAgent => 1,
            MacOsContainmentMode::WrapTools => 2,
            MacOsContainmentMode::RequestOnly => 3,
        };
        plan_out.visibility_is_claimed = u8::from(plan.visibility_is_claimed);
        plan_out.on_failure_closed = u8::from(plan.on_failure_closed);
        if let Some(sbpl) = plan.profile_sbpl {
            let bytes = sbpl.as_bytes();
            plan_out.has_profile = 1;
            plan_out.profile_len = bytes.len();
            if plan_out.profile_buf.is_null() || plan_out.profile_buf_cap < bytes.len() {
                #[allow(
                    unsafe_code,
                    reason = "Write required buffer length before returning ErrBufferTooSmall."
                )]
                // SAFETY: Checked out_plan non-null above.
                unsafe {
                    *out_plan = plan_out;
                }
                return Err(GrdrMacFfiStatus::ErrBufferTooSmall);
            }
            #[allow(unsafe_code, reason = "Copy SBPL UTF-8 bytes into caller profile_buf.")]
            // SAFETY: profile_buf verified non-null with capacity >= bytes.len().
            unsafe {
                let dst = slice::from_raw_parts_mut(plan_out.profile_buf, plan_out.profile_buf_cap);
                if let Some(head) = dst.get_mut(..bytes.len()) {
                    head.copy_from_slice(bytes);
                }
            }
        } else {
            plan_out.has_profile = 0;
            plan_out.profile_len = 0;
        }
        #[allow(
            unsafe_code,
            reason = "Write populated GrdrMacSeatbeltPlanC to caller output."
        )]
        // SAFETY: Checked out_plan non-null above.
        unsafe {
            *out_plan = plan_out;
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

#[allow(unsafe_code, reason = "Read UTF-8 flow strings from GrdrMacNeFlowC.")]
// SAFETY: Caller verified flow struct pointer; slices validated by read_utf8_arg.
unsafe fn decode_ne_flow_c(
    raw: &GrdrMacNeFlowC,
) -> Result<(NeFlowRecord, EgressDefaultPolicy), GrdrMacFfiStatus> {
    let (agent, host, sni) = {
        #[allow(
            unsafe_code,
            reason = "Read flow host/agent/sni UTF-8 slices across C ABI."
        )]
        // SAFETY: Each pointer/len validated via read_utf8_arg.
        unsafe {
            (
                read_utf8_arg(raw.agent_name_ptr, raw.agent_name_len)?,
                read_utf8_arg(raw.host_name_ptr, raw.host_name_len)?,
                read_utf8_arg(raw.tls_sni_ptr, raw.tls_sni_len)?,
            )
        }
    };
    let transport = match raw.transport_code {
        0 => FlowTransport::Tcp,
        1 => FlowTransport::Udp,
        _ => return Err(GrdrMacFfiStatus::ErrInvalidArg),
    };
    let policy = if raw.default_deny != 0 {
        EgressDefaultPolicy::DefaultDeny
    } else {
        EgressDefaultPolicy::DefaultAllow
    };
    Ok((
        NeFlowRecord {
            flow_id: raw.flow_id,
            agent_name: agent.to_string(),
            governed_process: raw.governed_process != 0,
            transport,
            remote_port: raw.remote_port,
            host_name: (!host.trim().is_empty()).then(|| host.to_string()),
            tls_sni: (!sni.trim().is_empty()).then(|| sni.to_string()),
        },
        policy,
    ))
}

#[allow(
    unsafe_code,
    reason = "Read bounded array of GrdrMacStrSliceC path entries."
)]
// SAFETY: Caller guarantees ptr covers len aligned GrdrMacStrSliceC structs when len > 0.
unsafe fn read_str_slice_array(
    ptr: *const GrdrMacStrSliceC,
    len: usize,
) -> Result<Vec<String>, GrdrMacFfiStatus> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(GrdrMacFfiStatus::ErrNullPtr);
    }
    if len > MAX_FFI_SEATBELT_PATHS {
        return Err(GrdrMacFfiStatus::ErrInvalidArg);
    }
    #[allow(
        unsafe_code,
        reason = "Borrow bounded GrdrMacStrSliceC array across C ABI."
    )]
    // SAFETY: Validated non-null ptr and bounded len above.
    let entries = unsafe { slice::from_raw_parts(ptr, len) };
    let mut out = Vec::with_capacity(len);
    for e in entries {
        #[allow(unsafe_code, reason = "Read UTF-8 path entry from GrdrMacStrSliceC.")]
        // SAFETY: Validated via read_utf8_arg.
        let s = unsafe { read_utf8_arg(e.ptr, e.len)? };
        out.push(s.to_string());
    }
    Ok(out)
}

fn encode_ne_verdict(verdict: &NeFlowVerdict) -> GrdrMacNeVerdictC {
    let mut out = GrdrMacNeVerdictC::default();
    match verdict {
        NeFlowVerdict::Allow => {
            out.verdict_code = GrdrMacVerdictCode::Allow as u8;
        }
        NeFlowVerdict::AllowOpaqueWithFinding { reason } => {
            out.verdict_code = GrdrMacVerdictCode::AllowOpaqueWithFinding as u8;
            out.rule_id_len = copy_str_into_fixed(reason, &mut out.rule_id);
        }
        NeFlowVerdict::Drop { rule_id, .. } => {
            out.verdict_code = GrdrMacVerdictCode::Deny as u8;
            out.rule_id_len = copy_str_into_fixed(rule_id, &mut out.rule_id);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null;

    #[test]
    fn validates_fixed_c_abi_ne_tls_dns_model_host_and_seatbelt() {
        #[allow(
            unsafe_code,
            reason = "Exercise unsafe C-ABI entrypoints in unit test."
        )]
        // SAFETY: All test buffers remain valid for each FFI call.
        unsafe {
            let flow = GrdrMacNeFlowC {
                flow_id: 9,
                pid: 400,
                pidversion: 1,
                governed_process: 1,
                transport_code: 1,
                remote_port: 443,
                default_deny: 0,
                reserved: [0; 3],
                agent_name_ptr: b"claude-code".as_ptr(),
                agent_name_len: 11,
                host_name_ptr: null(),
                host_name_len: 0,
                tls_sni_ptr: null(),
                tls_sni_len: 0,
            };
            let mut verdict = GrdrMacNeVerdictC::default();
            assert_eq!(grdr_macos_eval_ne_flow_c(&flow, null(), 0, &mut verdict), 0);
            assert_eq!(verdict.verdict_code, GrdrMacVerdictCode::Deny as u8);

            let mut matched = 0u8;
            assert_eq!(
                grdr_macos_match_model_host_c(
                    b"api.anthropic.com".as_ptr(),
                    "api.anthropic.com".len(),
                    &mut matched
                ),
                0
            );
            assert_eq!(matched, 1);

            let mut sni_out = GrdrMacTlsSniOutC::default();
            assert_eq!(
                grdr_macos_peek_tls_sni_c(b"GET ".as_ptr(), 4, &mut sni_out),
                0
            );
            assert_eq!(
                sni_out.status_code,
                GrdrMacTlsSniStatusCode::NeedMoreBytes as u8
            );

            let dns_pkt: [u8; 33] = [
                0x00, 0x2A, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
                b'p', b'i', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
                0x00, 0x00, 0x01, 0x00, 0x01,
            ];
            let mut dns_out = GrdrMacDnsParseOutC::default();
            assert_eq!(
                grdr_macos_parse_dns_packet_c(dns_pkt.as_ptr(), dns_pkt.len(), &mut dns_out),
                0
            );
            assert_eq!(dns_out.tx_id, 0x002A);
            assert_eq!(
                std::str::from_utf8(&dns_out.qname[..usize::from(dns_out.qname_len)]).unwrap(),
                "api.example.com"
            );

            let mut small_buf = [0u8; 16];
            let req = GrdrMacSeatbeltRequestC {
                agent_ptr: b"cursor".as_ptr(),
                agent_len: 6,
                session_id_ptr: b"sess-ffi-sb".as_ptr(),
                session_id_len: 11,
                workspace_ptr: b"/Users/dev/ws".as_ptr(),
                workspace_len: 13,
                decide_socket_ptr: b"/var/run/grdr.sock".as_ptr(),
                decide_socket_len: 18,
                state_dirs_ptr: null(),
                state_dirs_len: 0,
                protected_paths_ptr: null(),
                protected_paths_len: 0,
                proxy_port: 44444,
                agent_has_own_seatbelt: 0,
                deny_elevation_binaries: 1,
            };
            let mut plan = GrdrMacSeatbeltPlanC {
                containment_code: 0,
                visibility_is_claimed: 0,
                on_failure_closed: 0,
                has_profile: 0,
                reserved: 0,
                profile_len: 0,
                profile_buf: small_buf.as_mut_ptr(),
                profile_buf_cap: small_buf.len(),
            };
            assert_eq!(
                grdr_macos_plan_seatbelt_c(&req, &mut plan),
                GrdrMacFfiStatus::ErrBufferTooSmall as i32
            );
            assert!(plan.profile_len > 16);

            let mut full_buf = vec![0u8; plan.profile_len];
            plan.profile_buf = full_buf.as_mut_ptr();
            plan.profile_buf_cap = full_buf.len();
            assert_eq!(grdr_macos_plan_seatbelt_c(&req, &mut plan), 0);
            let sbpl = std::str::from_utf8(&full_buf[..plan.profile_len]).unwrap();
            assert!(sbpl.contains("44444"));
            assert!(!sbpl.contains("(allow file-write* (subpath \"/private/tmp\"))"));

            // Verify TLS SNI takes precedence when host_name is an IP literal, and bare IP is opaque.
            let mut bin_buf = vec![0u8; 4_096];
            let allow_sni_rule = grdr_fastpath::BinaryRuleInput {
                rule_id: "net.allow.openai",
                reason: "allow openai",
                action_mask: FastActionClass::NetConnect.bit(),
                principal_mask: 0,
                label_mask: 0,
                verdict: grdr_fastpath::FastVerdict::Allow,
                agents: &[],
                prefixes: &["api.openai.com"],
                contains: &[],
            };
            let bin_len = grdr_fastpath::encode_binary_floor(&[allow_sni_rule], &mut bin_buf)
                .expect("encode ne binary floor");
            let ip_bytes = b"104.18.6.7";
            let sni_bytes = b"api.openai.com";
            let sni_flow = GrdrMacNeFlowC {
                flow_id: 10,
                pid: 400,
                pidversion: 1,
                governed_process: 1,
                transport_code: 0,
                remote_port: 443,
                default_deny: 1,
                reserved: [0; 3],
                agent_name_ptr: b"claude-code".as_ptr(),
                agent_name_len: 11,
                host_name_ptr: ip_bytes.as_ptr(),
                host_name_len: ip_bytes.len(),
                tls_sni_ptr: sni_bytes.as_ptr(),
                tls_sni_len: sni_bytes.len(),
            };
            assert_eq!(
                grdr_macos_eval_ne_flow_bin_c(&sni_flow, bin_buf.as_ptr(), bin_len, &mut verdict),
                0
            );
            assert_eq!(verdict.verdict_code, GrdrMacVerdictCode::Allow as u8);

            let bare_ip_flow = GrdrMacNeFlowC {
                default_deny: 0,
                tls_sni_ptr: null(),
                tls_sni_len: 0,
                ..sni_flow
            };
            assert_eq!(
                grdr_macos_eval_ne_flow_bin_c(
                    &bare_ip_flow,
                    bin_buf.as_ptr(),
                    bin_len,
                    &mut verdict
                ),
                0
            );
            assert_eq!(
                verdict.verdict_code,
                GrdrMacVerdictCode::AllowOpaqueWithFinding as u8
            );
        }
    }
}
