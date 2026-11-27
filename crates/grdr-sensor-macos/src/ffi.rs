// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::sync::Mutex;

use grdr_fastpath::{BinaryFloorTable, FastActionClass};

use crate::brand::MacOsBrandConfig;
use crate::es_eval::{EsCoordinatorRuntime, FloorEvaluator};
use crate::es_tree::{EsClientStatus, ProcessTreeKey};
use crate::ffi_common::{
    FfiFollowerHolder, eval_es_event_inner, read_bytes_arg, read_floor_rules_c, read_utf8_arg,
    with_decoded_floor_refs, wrap_status,
};
use crate::ffi_types::{
    GRDR_MACOS_ABI_VERSION, GrdrMacBrandInfoC, GrdrMacCapabilitiesC, GrdrMacEsEventC,
    GrdrMacEsFollower, GrdrMacEsVerdictC, GrdrMacFfiStatus, GrdrMacFloorRuleC,
    GrdrMacTokenLookupOutC, copy_str_into_fixed,
};
use crate::macos_probes::{
    DeveloperSigningStatus, probe_local_capabilities, probe_self_signing_team_and_es_entitlement,
};
use crate::network_ext::{SlotCapability, SlotRung};

#[allow(
    unsafe_code,
    reason = "C-ABI version probe exported for Swift system extensions."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_macos_abi_version() -> u32 {
    GRDR_MACOS_ABI_VERSION
}

/// Populate fixed C-ABI brand identity strings from brand manifest.
///
/// # Safety
/// `out_info` must point to writable aligned `GrdrMacBrandInfoC`.
#[allow(
    unsafe_code,
    reason = "Write fixed #[repr(C)] brand metadata fields into caller output pointer."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_get_brand_info(out_info: *mut GrdrMacBrandInfoC) -> i32 {
    if out_info.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        let brand = MacOsBrandConfig::try_embedded().map_err(|_| GrdrMacFfiStatus::ErrInternal)?;
        let own_prefix = brand.own_extension_prefix();
        let group = brand.app_group_id();
        let mut info = GrdrMacBrandInfoC {
            abi_version: GRDR_MACOS_ABI_VERSION,
            ..Default::default()
        };
        info.bundle_id_len = copy_str_into_fixed(&brand.macos_bundle_id, &mut info.bundle_id);
        info.own_prefix_len = copy_str_into_fixed(&own_prefix, &mut info.own_prefix);
        info.netext_bundle_id_len =
            copy_str_into_fixed(&brand.macos_netext_bundle_id, &mut info.netext_bundle_id);
        info.esext_bundle_id_len =
            copy_str_into_fixed(&brand.macos_esext_bundle_id, &mut info.esext_bundle_id);
        info.product_name_len = copy_str_into_fixed(&brand.product_name, &mut info.product_name);
        info.daemon_label_len =
            copy_str_into_fixed(&brand.macos_daemon_label, &mut info.daemon_label);
        info.app_group_id_len = copy_str_into_fixed(&group, &mut info.app_group_id);
        #[allow(
            unsafe_code,
            reason = "Write populated GrdrMacBrandInfoC value to non-null caller pointer."
        )]
        // SAFETY: Checked out_info non-null above.
        unsafe {
            *out_info = info;
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

#[allow(
    unsafe_code,
    reason = "Allocate opaque Mutex-guarded EsCoordinatorRuntime handle across C ABI."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_macos_follower_new() -> *mut GrdrMacEsFollower {
    match catch_unwind(|| {
        let holder = FfiFollowerHolder {
            inner: Mutex::new(EsCoordinatorRuntime::new()),
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
    reason = "Free opaque Mutex-guarded EsCoordinatorRuntime allocated across C ABI."
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

/// Mute an Apple Team ID across an opaque `GrdrMacEsFollower`.
///
/// # Safety
/// `follower` must point to a live `GrdrMacEsFollower` and `team_id_ptr` must cover `team_id_len` bytes.
#[allow(unsafe_code, reason = "C-ABI incumbent Team ID muting entry point.")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_follower_mute_team(
    follower: *mut GrdrMacEsFollower,
    team_id_ptr: *const u8,
    team_id_len: usize,
) -> i32 {
    if follower.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Read UTF-8 Team ID bytes across C ABI.")]
        // SAFETY: Bounded slice verified via read_utf8_arg.
        let team = unsafe { read_utf8_arg(team_id_ptr, team_id_len) }?;
        if team.is_empty() {
            return Err(GrdrMacFfiStatus::ErrInvalidArg);
        }
        #[allow(unsafe_code, reason = "Lock opaque EsCoordinatorRuntime holder.")]
        // SAFETY: Valid FfiFollowerHolder pointer created by grdr_macos_follower_new.
        let holder = unsafe { &*follower.cast::<FfiFollowerHolder>() };
        let mut rt = holder
            .inner
            .lock()
            .map_err(|_| GrdrMacFfiStatus::ErrLockPoisoned)?;
        rt.tree.mute_incumbent_team(team);
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

/// Register a self-protection PID inside `GrdrMacEsFollower`.
///
/// # Safety
/// `follower` must point to a live `GrdrMacEsFollower`.
#[allow(unsafe_code, reason = "C-ABI self-protection PID registration.")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_follower_register_self_pid(
    follower: *mut GrdrMacEsFollower,
    pid: u32,
) -> i32 {
    if follower.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    if pid == 0 {
        return GrdrMacFfiStatus::ErrInvalidArg as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Lock opaque EsCoordinatorRuntime holder.")]
        // SAFETY: Valid FfiFollowerHolder pointer created by grdr_macos_follower_new.
        let holder = unsafe { &*follower.cast::<FfiFollowerHolder>() };
        let mut rt = holder
            .inner
            .lock()
            .map_err(|_| GrdrMacFfiStatus::ErrLockPoisoned)?;
        rt.register_self_pid(pid);
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

/// Register a protected path guarded against agent modification in `ProtectedPathGuard`.
///
/// # Safety
/// `follower` must be live and `path_ptr` must cover `path_len` bytes.
#[allow(unsafe_code, reason = "C-ABI protected path registration.")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_follower_add_protected_path(
    follower: *mut GrdrMacEsFollower,
    path_ptr: *const u8,
    path_len: usize,
) -> i32 {
    register_path_in_follower(follower, path_ptr, path_len, false)
}

/// Register a self-protection path guarded against agent modification in `SelfProtection`.
///
/// # Safety
/// `follower` must be live and `path_ptr` must cover `path_len` bytes.
#[allow(unsafe_code, reason = "C-ABI self-protection path registration.")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_follower_add_self_path(
    follower: *mut GrdrMacEsFollower,
    path_ptr: *const u8,
    path_len: usize,
) -> i32 {
    register_path_in_follower(follower, path_ptr, path_len, true)
}

fn register_path_in_follower(
    follower: *mut GrdrMacEsFollower,
    path_ptr: *const u8,
    path_len: usize,
    self_path: bool,
) -> i32 {
    if follower.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Read UTF-8 path bytes across C ABI.")]
        // SAFETY: Bounded slice verified via read_utf8_arg.
        let path = unsafe { read_utf8_arg(path_ptr, path_len) }?;
        if path.trim().is_empty() {
            return Err(GrdrMacFfiStatus::ErrInvalidArg);
        }
        #[allow(unsafe_code, reason = "Lock opaque EsCoordinatorRuntime holder.")]
        // SAFETY: Valid FfiFollowerHolder pointer created by grdr_macos_follower_new.
        let holder = unsafe { &*follower.cast::<FfiFollowerHolder>() };
        let mut rt = holder
            .inner
            .lock()
            .map_err(|_| GrdrMacFfiStatus::ErrLockPoisoned)?;
        if self_path {
            rt.add_self_path(path);
        } else {
            rt.add_protected_path(path);
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

/// Look up whether a `(pid, pidversion)` belongs to a governed agent tree.
///
/// # Safety
/// `follower` and `out_info` must be valid aligned non-null pointers.
#[allow(
    unsafe_code,
    reason = "C-ABI governed audit-token lineage lookup for Network Extension providers."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_follower_lookup_token(
    follower: *const GrdrMacEsFollower,
    pid: u32,
    pidversion: u32,
    out_info: *mut GrdrMacTokenLookupOutC,
) -> i32 {
    if follower.is_null() || out_info.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(unsafe_code, reason = "Lock opaque EsCoordinatorRuntime holder.")]
        // SAFETY: Valid FfiFollowerHolder pointer created by grdr_macos_follower_new.
        let holder = unsafe { &*follower.cast::<FfiFollowerHolder>() };
        let rt = holder
            .inner
            .lock()
            .map_err(|_| GrdrMacFfiStatus::ErrLockPoisoned)?;
        let key = ProcessTreeKey { pid, pidversion };
        let mut out = GrdrMacTokenLookupOutC::default();
        if let Some(member) = rt.tree.lookup_member(key) {
            out.governed = 1;
            out.root_pid = member.agent_root_pid;
            out.session_id_len = copy_str_into_fixed(&member.session_id, &mut out.session_id);
            let agent = rt.agent_for_session(&member.session_id);
            out.agent_name_len = copy_str_into_fixed(agent, &mut out.agent_name);
        }
        #[allow(unsafe_code, reason = "Write GrdrMacTokenLookupOutC to caller buffer.")]
        // SAFETY: Checked out_info non-null above.
        unsafe {
            *out_info = out;
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

/// Evaluate an Endpoint Security event using fixed `GrdrMacEsEventC` and `GrdrMacFloorRuleC` array.
///
/// # Safety
/// `follower`, `event`, `out_verdict`, and optional `floor_rules` (`floor_len` elements) must be valid.
#[allow(
    unsafe_code,
    reason = "Zero-JSON fixed-struct C-ABI Endpoint Security event evaluator."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_eval_es_event_c(
    follower: *mut GrdrMacEsFollower,
    event: *const GrdrMacEsEventC,
    floor_rules: *const GrdrMacFloorRuleC,
    floor_len: usize,
    out_verdict: *mut GrdrMacEsVerdictC,
) -> i32 {
    if follower.is_null() || event.is_null() || out_verdict.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        #[allow(
            unsafe_code,
            reason = "Read fixed-layout floor rules from caller slice."
        )]
        // SAFETY: Validated non-null pointers when lengths are non-zero.
        let decoded = unsafe { read_floor_rules_c(floor_rules, floor_len) }?;
        with_decoded_floor_refs(&decoded, FastActionClass::Exec, |refs| {
            #[allow(
                unsafe_code,
                reason = "Evaluate fixed-layout ES event against runtime and floor rules."
            )]
            // SAFETY: Validated non-null follower, event, and out_verdict pointers.
            unsafe {
                eval_es_event_inner(follower, event, FloorEvaluator::Rules(refs), out_verdict)
            }
        })
    })))
}

/// Evaluate an Endpoint Security event using fixed `GrdrMacEsEventC` and compiled binary floor table.
///
/// # Safety
/// `follower`, `event`, `out_verdict`, and optional `floor_bin_ptr` (`floor_bin_len` bytes) must be valid.
#[allow(
    unsafe_code,
    reason = "Zero-JSON compiled binary floor table Endpoint Security evaluator."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_eval_es_event_bin_c(
    follower: *mut GrdrMacEsFollower,
    event: *const GrdrMacEsEventC,
    floor_bin_ptr: *const u8,
    floor_bin_len: usize,
    out_verdict: *mut GrdrMacEsVerdictC,
) -> i32 {
    if follower.is_null() || event.is_null() || out_verdict.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        if floor_bin_len == 0 {
            #[allow(
                unsafe_code,
                reason = "Evaluate ES event with empty floor table when length is zero."
            )]
            // SAFETY: Validated non-null follower, event, and out_verdict pointers.
            return unsafe {
                eval_es_event_inner(follower, event, FloorEvaluator::Rules(&[]), out_verdict)
            };
        }
        #[allow(unsafe_code, reason = "Read binary floor table bytes across C ABI.")]
        // SAFETY: Bounded slice verified by read_bytes_arg.
        let bin = unsafe { read_bytes_arg(floor_bin_ptr, floor_bin_len) }?;
        let table = BinaryFloorTable::parse(bin).map_err(|_| GrdrMacFfiStatus::ErrInvalidArg)?;
        #[allow(
            unsafe_code,
            reason = "Evaluate ES event against compiled binary floor table."
        )]
        // SAFETY: Validated non-null follower, event, and out_verdict pointers.
        unsafe {
            eval_es_event_inner(follower, event, FloorEvaluator::Binary(&table), out_verdict)
        }
    })))
}

/// Probe macOS host extension and slot capabilities into a fixed `GrdrMacCapabilitiesC` struct.
///
/// # Safety
/// `out_caps` must point to writable aligned `GrdrMacCapabilitiesC`.
#[allow(
    unsafe_code,
    reason = "Populate fixed #[repr(C)] macOS capability probe struct."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_probe_capabilities_c(
    out_caps: *mut GrdrMacCapabilitiesC,
) -> i32 {
    probe_capabilities_impl(None, out_caps)
}

/// Probe macOS host capabilities combined with live ES client statuses inside `GrdrMacEsFollower`.
///
/// # Safety
/// `follower` and `out_caps` must point to valid live objects.
#[allow(
    unsafe_code,
    reason = "Populate GrdrMacCapabilitiesC from live follower ES client states."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_probe_capabilities_with_follower_c(
    follower: *const GrdrMacEsFollower,
    out_caps: *mut GrdrMacCapabilitiesC,
) -> i32 {
    if follower.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    probe_capabilities_impl(Some(follower), out_caps)
}

/// Probe current process code-signing Team ID and ES entitlement using Security.framework SecCode.
///
/// # Safety
/// `out_team_len` and `out_es_entitled` must be non-null; `out_team_ptr` may be null only when `team_cap == 0`.
#[allow(
    unsafe_code,
    reason = "Write self SecCode signing team ID and ES entitlement flag across C ABI."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn grdr_macos_self_signing_info_c(
    out_team_ptr: *mut u8,
    team_cap: usize,
    out_team_len: *mut usize,
    out_es_entitled: *mut u8,
) -> i32 {
    if out_team_len.is_null() || out_es_entitled.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        let (_status, team, es_entitled) = probe_self_signing_team_and_es_entitlement();
        let team_bytes = team.as_deref().map_or(&[][..], str::as_bytes);
        #[allow(
            unsafe_code,
            reason = "Write team length and ES entitlement flag to caller pointers."
        )]
        // SAFETY: Validated non-null pointers above.
        unsafe {
            *out_team_len = team_bytes.len();
            *out_es_entitled = u8::from(es_entitled);
        }
        if !team_bytes.is_empty() {
            if out_team_ptr.is_null() {
                return Err(GrdrMacFfiStatus::ErrNullPtr);
            }
            if team_cap < team_bytes.len() {
                return Err(GrdrMacFfiStatus::ErrBufferTooSmall);
            }
            #[allow(unsafe_code, reason = "Copy Team ID bytes into caller buffer.")]
            // SAFETY: out_team_ptr verified non-null with capacity >= team_bytes.len().
            unsafe {
                let dst = slice::from_raw_parts_mut(out_team_ptr, team_cap);
                if let Some(head) = dst.get_mut(..team_bytes.len()) {
                    head.copy_from_slice(team_bytes);
                }
            }
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

fn probe_capabilities_impl(
    follower: Option<*const GrdrMacEsFollower>,
    out_caps: *mut GrdrMacCapabilitiesC,
) -> i32 {
    if out_caps.is_null() {
        return GrdrMacFfiStatus::ErrNullPtr as i32;
    }
    wrap_status(catch_unwind(AssertUnwindSafe(|| {
        let live_es = match follower {
            Some(ptr) => {
                #[allow(unsafe_code, reason = "Lock live FfiFollowerHolder to read ES states.")]
                // SAFETY: Caller verified follower pointer non-null and live.
                let holder = unsafe { &*ptr.cast::<FfiFollowerHolder>() };
                let rt = holder
                    .inner
                    .lock()
                    .map_err(|_| GrdrMacFfiStatus::ErrLockPoisoned)?;
                Some(rt.clients.clone())
            }
            None => None,
        };
        let caps = probe_local_capabilities(live_es.as_ref())
            .map_err(|_| GrdrMacFfiStatus::ErrInternal)?;
        let brand = MacOsBrandConfig::try_embedded().map_err(|_| GrdrMacFfiStatus::ErrInternal)?;
        let mut own_count: u8 = 0;
        let mut foreign_count: u8 = 0;
        for ext in &caps.system_extensions {
            if brand.is_own_extension_identifier(&ext.identifier) {
                own_count = own_count.saturating_add(1);
            } else {
                foreign_count = foreign_count.saturating_add(1);
            }
        }
        let slot_code = |cap: SlotCapability| -> u8 {
            caps.slot_reports
                .iter()
                .find(|r| r.capability == cap)
                .map_or(0, |r| encode_slot_rung(r.rung))
        };
        let out = GrdrMacCapabilitiesC {
            process_probe_available: u8::from(caps.process_probe_available),
            developer_program_held: u8::from(caps.developer_program_held),
            signing_status_code: match caps.developer_signing_status {
                DeveloperSigningStatus::VerifiedWithEntitlements => 0,
                DeveloperSigningStatus::SignedMissingTeamOrEntitlement => 1,
                DeveloperSigningStatus::UnsignedOrAdhoc => 2,
                DeveloperSigningStatus::Unavailable => 3,
            },
            content_filter_rung: slot_code(SlotCapability::ContentFilter),
            dns_proxy_rung: slot_code(SlotCapability::DnsProxy),
            transparent_proxy_rung: slot_code(SlotCapability::TransparentProxy),
            es_status_code: match caps.es_status {
                EsClientStatus::Active => 0,
                EsClientStatus::MissingEntitlement => 1,
                EsClientStatus::TooManyClients => 2,
                EsClientStatus::NotPermittedFda => 3,
            },
            own_extension_count: own_count,
            foreign_extension_count: foreign_count,
            vpn_proxy_count: u8::try_from(caps.network_services_scutil.len()).unwrap_or(u8::MAX),
        };
        #[allow(unsafe_code, reason = "Write GrdrMacCapabilitiesC to caller pointer.")]
        // SAFETY: Checked out_caps non-null above.
        unsafe {
            *out_caps = out;
        }
        Ok(GrdrMacFfiStatus::Ok)
    })))
}

const fn encode_slot_rung(rung: SlotRung) -> u8 {
    match rung {
        SlotRung::None => 0,
        SlotRung::Ingest => 1,
        SlotRung::Observe => 2,
        SlotRung::Enforce => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi_types::{
        GrdrMacAuditTokenC, GrdrMacEsConcernCode, GrdrMacEsEventKind, GrdrMacProcessKeyC,
        GrdrMacVerdictCode,
    };
    use grdr_fastpath::{BinaryRuleInput, encode_binary_floor};
    use std::ptr::{null, null_mut};

    fn empty_event() -> GrdrMacEsEventC {
        GrdrMacEsEventC {
            kind_code: GrdrMacEsEventKind::AuthExec as u8,
            concern_code: GrdrMacEsConcernCode::ExecAuthorizer as u8,
            default_deny: 0,
            reserved0: 0,
            access_flags: 0,
            event_flags: 0,
            reserved1: 0,
            seq_num: 1,
            timestamp_ns: 0,
            elapsed_ms: 5,
            kernel_deadline_ms: 10_000,
            actor: GrdrMacAuditTokenC {
                key: GrdrMacProcessKeyC {
                    pid: 100,
                    pidversion: 1,
                },
                uid: 501,
                reserved: 0,
                team_id_ptr: null(),
                team_id_len: 0,
            },
            target: GrdrMacAuditTokenC {
                key: GrdrMacProcessKeyC {
                    pid: 101,
                    pidversion: 2,
                },
                uid: 501,
                reserved: 0,
                team_id_ptr: null(),
                team_id_len: 0,
            },
            path_ptr: null(),
            path_len: 0,
            secondary_path_ptr: null(),
            secondary_path_len: 0,
            session_id_ptr: null(),
            session_id_len: 0,
            agent_name_ptr: null(),
            agent_name_len: 0,
        }
    }

    #[test]
    fn validates_fixed_c_abi_es_brand_and_negative_pointer_paths() {
        assert_eq!(grdr_macos_abi_version(), GRDR_MACOS_ABI_VERSION);

        #[allow(
            unsafe_code,
            reason = "Exercise unsafe C-ABI entrypoints in unit test."
        )]
        // SAFETY: All stack/heap buffers and pointers created within test scope live across calls.
        unsafe {
            assert_eq!(
                grdr_macos_get_brand_info(null_mut()),
                GrdrMacFfiStatus::ErrNullPtr as i32
            );
            let mut brand = GrdrMacBrandInfoC::default();
            assert_eq!(grdr_macos_get_brand_info(&mut brand), 0);
            let bundle_id =
                std::str::from_utf8(&brand.bundle_id[..usize::from(brand.bundle_id_len)]).unwrap();
            assert_eq!(bundle_id, "com.guardrailshq.grdr");
            let prefix =
                std::str::from_utf8(&brand.own_prefix[..usize::from(brand.own_prefix_len)])
                    .unwrap();
            assert_eq!(prefix, "com.guardrailshq.grdr.");

            let mut caps = GrdrMacCapabilitiesC::default();
            assert_eq!(grdr_macos_probe_capabilities_c(&mut caps), 0);

            let follower = grdr_macos_follower_new();
            assert!(!follower.is_null());

            assert_eq!(
                grdr_macos_follower_mute_team(null_mut(), b"TEAM".as_ptr(), 4),
                GrdrMacFfiStatus::ErrNullPtr as i32
            );
            assert_eq!(
                grdr_macos_follower_mute_team(follower, null(), 4),
                GrdrMacFfiStatus::ErrNullPtr as i32
            );
            assert_eq!(
                grdr_macos_follower_register_self_pid(follower, 888),
                GrdrMacFfiStatus::Ok as i32
            );
            assert_eq!(
                grdr_macos_follower_add_protected_path(
                    follower,
                    b"/private/var/db/grdr".as_ptr(),
                    20
                ),
                GrdrMacFfiStatus::Ok as i32
            );
            assert_eq!(
                grdr_macos_follower_add_self_path(
                    follower,
                    b"/Library/Application Support/Guardrails".as_ptr(),
                    39
                ),
                GrdrMacFfiStatus::Ok as i32
            );

            let mut reg = empty_event();
            reg.kind_code = GrdrMacEsEventKind::RegisterRoot as u8;
            let sid = b"sess-ffi-c-1";
            let agent = b"claude-code";
            reg.session_id_ptr = sid.as_ptr();
            reg.session_id_len = sid.len();
            reg.agent_name_ptr = agent.as_ptr();
            reg.agent_name_len = agent.len();
            let mut v = GrdrMacEsVerdictC::default();
            assert_eq!(
                grdr_macos_eval_es_event_c(follower, &reg, null(), 0, &mut v),
                0
            );
            assert_eq!(v.governed_member, 1);

            let mut lookup = GrdrMacTokenLookupOutC::default();
            assert_eq!(
                grdr_macos_follower_lookup_token(follower, 100, 1, &mut lookup),
                0
            );
            assert_eq!(lookup.governed, 1);
            let looked_agent =
                std::str::from_utf8(&lookup.agent_name[..usize::from(lookup.agent_name_len)])
                    .unwrap();
            assert_eq!(looked_agent, "claude-code");

            let mut bin_buf = vec![0u8; 4_096];
            let rule = BinaryRuleInput {
                rule_id: "es.deny.curl",
                reason: "deny curl",
                action_mask: FastActionClass::Exec.bit(),
                principal_mask: 0,
                label_mask: 0,
                verdict: grdr_fastpath::FastVerdict::Deny,
                agents: &[],
                prefixes: &["/usr/bin/curl"],
                contains: &[],
            };
            let bin_len = encode_binary_floor(&[rule], &mut bin_buf).expect("encode binary table");

            let mut auth_ev = empty_event();
            let exe = b"/usr/bin/curl";
            auth_ev.path_ptr = exe.as_ptr();
            auth_ev.path_len = exe.len();
            assert_eq!(
                grdr_macos_eval_es_event_bin_c(
                    follower,
                    &auth_ev,
                    bin_buf.as_ptr(),
                    bin_len,
                    &mut v
                ),
                0
            );
            assert_eq!(v.verdict_code, GrdrMacVerdictCode::Deny as u8);
            assert_eq!(v.should_cache, 0);

            let mut exit_ev = empty_event();
            exit_ev.kind_code = GrdrMacEsEventKind::NotifyExit as u8;
            exit_ev.concern_code = GrdrMacEsConcernCode::Recorder as u8;
            exit_ev.actor.key = auth_ev.target.key;
            assert_eq!(
                grdr_macos_eval_es_event_c(follower, &exit_ev, null(), 0, &mut v),
                0
            );
            assert_eq!(v.synthesized_denied_exec, 1);

            let mut bad_recorder_auth = empty_event();
            bad_recorder_auth.concern_code = GrdrMacEsConcernCode::Recorder as u8;
            assert_eq!(
                grdr_macos_eval_es_event_c(follower, &bad_recorder_auth, null(), 0, &mut v),
                GrdrMacFfiStatus::ErrInvalidArg as i32
            );

            let mut sig_ev = empty_event();
            sig_ev.concern_code = GrdrMacEsConcernCode::SelfProtection as u8;
            sig_ev.kind_code = GrdrMacEsEventKind::AuthSignal as u8;
            sig_ev.target.key.pid = 888;
            assert_eq!(
                grdr_macos_eval_es_event_c(follower, &sig_ev, null(), 0, &mut v),
                0
            );
            assert_eq!(v.verdict_code, GrdrMacVerdictCode::Deny as u8);

            let mut team_len = 0usize;
            let mut es_ent = 0u8;
            let mut team_buf = [0u8; 32];
            assert_eq!(
                grdr_macos_self_signing_info_c(
                    team_buf.as_mut_ptr(),
                    team_buf.len(),
                    &mut team_len,
                    &mut es_ent
                ),
                0
            );

            grdr_macos_follower_free(follower);
            grdr_macos_follower_free(null_mut());
        }
    }
}
