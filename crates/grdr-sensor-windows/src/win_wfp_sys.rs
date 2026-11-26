// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, FWP_E_ALREADY_EXISTS, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND,
    HANDLE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_DISPLAY_DATA0, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmFilterDeleteById0, FwpmFreeMemory0, FwpmProviderAdd0, FwpmProviderCreateEnumHandle0,
    FwpmProviderDestroyEnumHandle0, FwpmProviderEnum0, FwpmProviderGetByKey0, FwpmSubLayerAdd0,
    FwpmSubLayerGetByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::GUID;

use crate::WindowsSensorError;
use crate::wfp::WfpSublayerPlan;
use crate::win_wfp::{AppliedWfpRules, WfpCoexistenceReport, WfpEngineAccess, WfpProviderInfo};
use crate::win_wfp_filters::install_single_filter;

const MAX_ENUM_PROVIDERS: u32 = 64;
const HRESULT_ACCESS_DENIED: u32 = 0x8007_0005;
const WFP_ACCESS_DENIED_ERR: u32 = 0x8032_000d;
const GRDR_WFP_PROVIDER_DYNAMIC_GUID: GUID =
    GUID::from_u128(0x6772_6472_0001_4000_8000_0000_0000_0001);
const GRDR_WFP_SUBLAYER_DYNAMIC_GUID: GUID =
    GUID::from_u128(0x6772_6472_0001_4000_8000_0000_0000_0002);
const GRDR_WFP_PROVIDER_PERSISTENT_GUID: GUID =
    GUID::from_u128(0x6772_6472_0001_4000_8000_0000_0000_0003);
const GRDR_WFP_SUBLAYER_PERSISTENT_GUID: GUID =
    GUID::from_u128(0x6772_6472_0001_4000_8000_0000_0000_0004);

struct WfpEngineGuard {
    handle: HANDLE,
}

struct WfpEnumGuard {
    engine: HANDLE,
    enum_handle: HANDLE,
}

struct WfpTxGuard {
    engine: HANDLE,
    active: bool,
}

impl WfpEngineGuard {
    fn open() -> Result<Self, u32> {
        let mut handle: HANDLE = null_mut();
        #[allow(
            unsafe_code,
            reason = "Open local Windows Filtering Platform BFE session."
        )]
        // SAFETY: FwpmEngineOpen0 writes valid engine handle on zero status.
        let rc = unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), null(), &mut handle) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Self { handle })
    }
}

impl Drop for WfpEngineGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            #[allow(unsafe_code, reason = "Close opened WFP BFE engine handle.")]
            // SAFETY: self.handle was opened by FwpmEngineOpen0 and closed once on Drop.
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
            self.handle = null_mut();
        }
    }
}

impl Drop for WfpEnumGuard {
    fn drop(&mut self) {
        if !self.enum_handle.is_null() {
            #[allow(unsafe_code, reason = "Destroy WFP provider enumeration handle.")]
            // SAFETY: enum_handle belongs to open engine handle and is destroyed once.
            unsafe {
                let _ = FwpmProviderDestroyEnumHandle0(self.engine, self.enum_handle);
            }
            self.enum_handle = null_mut();
        }
    }
}

impl WfpTxGuard {
    fn begin(engine: HANDLE) -> Result<Self, u32> {
        #[allow(unsafe_code, reason = "Begin atomic BFE WFP transaction.")]
        // SAFETY: engine is a live opened WFP engine handle.
        let rc = unsafe { FwpmTransactionBegin0(engine, 0) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Self {
            engine,
            active: true,
        })
    }

    fn commit(mut self) -> Result<(), u32> {
        #[allow(unsafe_code, reason = "Commit atomic BFE WFP transaction.")]
        // SAFETY: self.engine has an active WFP transaction begun by FwpmTransactionBegin0.
        let rc = unsafe { FwpmTransactionCommit0(self.engine) };
        self.active = false;
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for WfpTxGuard {
    fn drop(&mut self) {
        if self.active {
            #[allow(unsafe_code, reason = "Abort uncommitted BFE WFP transaction.")]
            // SAFETY: self.engine has an uncommitted WFP transaction aborted once on unwind/error.
            unsafe {
                let _ = FwpmTransactionAbort0(self.engine);
            }
            self.active = false;
        }
    }
}

pub(crate) fn probe_win_wfp_coexistence() -> Result<WfpCoexistenceReport, WindowsSensorError> {
    let guard = match WfpEngineGuard::open() {
        Ok(g) => g,
        Err(rc) if is_access_denied(rc) => {
            return Ok(WfpCoexistenceReport {
                engine_access: WfpEngineAccess::AccessDenied,
                provider_count: 0,
                providers: Vec::new(),
                grdr_sublayer_present: false,
                detail: format!(
                    "FwpmEngineOpen0 denied (0x{rc:08x}); WFP coexistence probe skipped"
                ),
            });
        }
        Err(rc) => {
            return Err(WindowsSensorError::Wfp(format!(
                "FwpmEngineOpen0 failed with 0x{rc:08x}"
            )));
        }
    };

    let mut enum_handle: HANDLE = null_mut();
    #[allow(unsafe_code, reason = "Create WFP provider enumeration cursor.")]
    // SAFETY: guard.handle is open and enum_handle receives valid handle on success.
    let enum_rc = unsafe { FwpmProviderCreateEnumHandle0(guard.handle, null(), &mut enum_handle) };
    if enum_rc != 0 {
        if is_access_denied(enum_rc) {
            return Ok(WfpCoexistenceReport {
                engine_access: WfpEngineAccess::AccessDenied,
                provider_count: 0,
                providers: Vec::new(),
                grdr_sublayer_present: false,
                detail: format!("FwpmProviderCreateEnumHandle0 denied (0x{enum_rc:08x})"),
            });
        }
        return Err(WindowsSensorError::Wfp(format!(
            "FwpmProviderCreateEnumHandle0 failed with 0x{enum_rc:08x}"
        )));
    }
    let _enum_guard = WfpEnumGuard {
        engine: guard.handle,
        enum_handle,
    };

    let providers = enumerate_providers(guard.handle, enum_handle)?;
    let grdr_sublayer_present =
        check_sublayer_present(guard.handle, &GRDR_WFP_SUBLAYER_DYNAMIC_GUID)?
            || check_sublayer_present(guard.handle, &GRDR_WFP_SUBLAYER_PERSISTENT_GUID)?;

    Ok(WfpCoexistenceReport {
        engine_access: WfpEngineAccess::ReadOnlyProbe,
        provider_count: providers.len(),
        providers,
        grdr_sublayer_present,
        detail: "WFP coexistence probe completed".to_string(),
    })
}

pub(crate) fn apply_win_wfp_plan(
    plan: &WfpSublayerPlan,
) -> Result<AppliedWfpRules, WindowsSensorError> {
    let guard = match WfpEngineGuard::open() {
        Ok(g) => g,
        Err(rc) if is_access_denied(rc) => {
            return Ok(AppliedWfpRules {
                applied: false,
                filter_ids: Vec::new(),
                detail: format!(
                    "FwpmEngineOpen0 denied (0x{rc:08x}); elevation required to install WFP filters"
                ),
            });
        }
        Err(rc) => {
            return Err(WindowsSensorError::Wfp(format!(
                "FwpmEngineOpen0 failed with 0x{rc:08x}"
            )));
        }
    };

    let tx = match WfpTxGuard::begin(guard.handle) {
        Ok(t) => t,
        Err(rc) if is_access_denied(rc) => {
            return Ok(AppliedWfpRules {
                applied: false,
                filter_ids: Vec::new(),
                detail: format!("FwpmTransactionBegin0 denied (0x{rc:08x})"),
            });
        }
        Err(rc) => {
            return Err(WindowsSensorError::Wfp(format!(
                "FwpmTransactionBegin0 failed with 0x{rc:08x}"
            )));
        }
    };

    let mut filter_ids = Vec::with_capacity(plan.rules.len());
    let has_dyn = plan.rules.iter().any(|r| !r.persistent);
    let has_pers = plan.rules.iter().any(|r| r.persistent);
    if has_dyn || plan.rules.is_empty() {
        ensure_tier_provider_and_sublayer(guard.handle, plan.sublayer_weight, false)?;
    }
    if has_pers {
        ensure_tier_provider_and_sublayer(guard.handle, plan.sublayer_weight, true)?;
    }

    for rule in &plan.rules {
        let (prov_guid, sub_guid) = if rule.persistent {
            (
                GRDR_WFP_PROVIDER_PERSISTENT_GUID,
                GRDR_WFP_SUBLAYER_PERSISTENT_GUID,
            )
        } else {
            (
                GRDR_WFP_PROVIDER_DYNAMIC_GUID,
                GRDR_WFP_SUBLAYER_DYNAMIC_GUID,
            )
        };
        match install_single_filter(guard.handle, rule, prov_guid, sub_guid) {
            Ok(id) => filter_ids.push(id),
            Err(err) => {
                if let Some(denied_msg) = strip_wfp_access_denied(&err) {
                    return Ok(AppliedWfpRules {
                        applied: false,
                        filter_ids: Vec::new(),
                        detail: denied_msg,
                    });
                }
                return Err(err);
            }
        }
    }

    tx.commit().map_err(|rc| {
        WindowsSensorError::Wfp(format!("FwpmTransactionCommit0 failed with 0x{rc:08x}"))
    })?;

    Ok(AppliedWfpRules {
        applied: true,
        filter_ids,
        detail: format!("installed {} WFP filters", plan.rules.len()),
    })
}

pub(crate) fn remove_win_wfp_filters(
    applied: &AppliedWfpRules,
) -> Result<usize, WindowsSensorError> {
    if !applied.applied || applied.filter_ids.is_empty() {
        return Ok(0);
    }
    let guard = WfpEngineGuard::open().map_err(|rc| {
        WindowsSensorError::Wfp(format!("FwpmEngineOpen0 failed during cleanup: 0x{rc:08x}"))
    })?;
    let tx = WfpTxGuard::begin(guard.handle).map_err(|rc| {
        WindowsSensorError::Wfp(format!("FwpmTransactionBegin0 failed cleanup: 0x{rc:08x}"))
    })?;
    let mut removed = 0usize;
    for &id in &applied.filter_ids {
        #[allow(unsafe_code, reason = "Delete installed Guardrails WFP filter by ID.")]
        // SAFETY: guard.handle is open and filter_id came from FwpmFilterAdd0.
        let rc = unsafe { FwpmFilterDeleteById0(guard.handle, id) };
        if rc == 0 {
            removed = removed.saturating_add(1);
        }
    }
    tx.commit().map_err(|rc| {
        WindowsSensorError::Wfp(format!("FwpmTransactionCommit0 cleanup failed: 0x{rc:08x}"))
    })?;
    Ok(removed)
}

fn ensure_tier_provider_and_sublayer(
    engine: HANDLE,
    weight: u16,
    persistent: bool,
) -> Result<(), WindowsSensorError> {
    let (prov_guid, sub_guid) = if persistent {
        (
            GRDR_WFP_PROVIDER_PERSISTENT_GUID,
            GRDR_WFP_SUBLAYER_PERSISTENT_GUID,
        )
    } else {
        (
            GRDR_WFP_PROVIDER_DYNAMIC_GUID,
            GRDR_WFP_SUBLAYER_DYNAMIC_GUID,
        )
    };
    let mut existing_prov: *mut FWPM_PROVIDER0 = null_mut();
    #[allow(unsafe_code, reason = "Check Guardrails WFP provider registration.")]
    let prov_rc = {
        // SAFETY: engine is open and existing_prov receives optional BFE allocation.
        unsafe { FwpmProviderGetByKey0(engine, &prov_guid, &mut existing_prov) }
    };
    if !existing_prov.is_null() {
        #[allow(unsafe_code, reason = "Free FWPM_PROVIDER0 allocated by BFE.")]
        // SAFETY: existing_prov was returned by BFE and freed once.
        unsafe {
            let mut free_target = existing_prov as *mut core::ffi::c_void;
            FwpmFreeMemory0(&mut free_target);
        }
    } else if prov_rc == hresult_to_u32(FWP_E_PROVIDER_NOT_FOUND) {
        let mut name = encode_utf16_nul("Guardrails ADR")?;
        let mut desc = encode_utf16_nul("Guardrails ADR network containment provider")?;
        #[allow(unsafe_code, reason = "Register Guardrails WFP provider.")]
        // SAFETY: name and desc UTF-16 buffers outlive FwpmProviderAdd0.
        let add_rc = unsafe {
            let mut prov: FWPM_PROVIDER0 = std::mem::zeroed();
            prov.providerKey = prov_guid;
            prov.flags = if persistent {
                FWPM_PROVIDER_FLAG_PERSISTENT
            } else {
                0
            };
            prov.displayData = FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: desc.as_mut_ptr(),
            };
            FwpmProviderAdd0(engine, &prov, null_mut())
        };
        if add_rc != 0 && add_rc != hresult_to_u32(FWP_E_ALREADY_EXISTS) {
            return Err(map_wfp_status("FwpmProviderAdd0", add_rc));
        }
    } else if prov_rc != 0 {
        return Err(map_wfp_status("FwpmProviderGetByKey0", prov_rc));
    }

    if !check_sublayer_present(engine, &sub_guid)? {
        let mut name = encode_utf16_nul("Guardrails Session Containment")?;
        let mut desc = encode_utf16_nul("Dedicated high-weight Guardrails containment sublayer")?;
        let mut prov_key = prov_guid;
        #[allow(unsafe_code, reason = "Register Guardrails WFP sublayer.")]
        // SAFETY: name, desc, and prov_key outlive FwpmSubLayerAdd0.
        let add_rc = unsafe {
            let mut sub: FWPM_SUBLAYER0 = std::mem::zeroed();
            sub.subLayerKey = sub_guid;
            sub.flags = if persistent {
                FWPM_SUBLAYER_FLAG_PERSISTENT
            } else {
                0
            };
            sub.displayData = FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: desc.as_mut_ptr(),
            };
            sub.providerKey = &mut prov_key;
            sub.weight = weight;
            FwpmSubLayerAdd0(engine, &sub, null_mut())
        };
        if add_rc != 0 && add_rc != hresult_to_u32(FWP_E_ALREADY_EXISTS) {
            return Err(map_wfp_status("FwpmSubLayerAdd0", add_rc));
        }
    }
    Ok(())
}

fn enumerate_providers(
    engine: HANDLE,
    enum_handle: HANDLE,
) -> Result<Vec<WfpProviderInfo>, WindowsSensorError> {
    let mut entries_ptr: *mut *mut FWPM_PROVIDER0 = null_mut();
    let mut count: u32 = 0;
    #[allow(
        unsafe_code,
        reason = "Enumerate installed WFP providers for coexistence check."
    )]
    // SAFETY: enum_handle is valid and entries_ptr/count receive BFE-allocated array freed below.
    let list_rc = unsafe {
        FwpmProviderEnum0(
            engine,
            enum_handle,
            MAX_ENUM_PROVIDERS,
            &mut entries_ptr,
            &mut count,
        )
    };
    if list_rc != 0 {
        return Err(map_wfp_status("FwpmProviderEnum0", list_rc));
    }
    let mut providers = Vec::new();
    if !entries_ptr.is_null() {
        let len = usize::try_from(count).unwrap_or(0);
        #[allow(
            unsafe_code,
            reason = "Read provider metadata slice from FwpmProviderEnum0."
        )]
        // SAFETY: BFE guarantees entries_ptr holds count initialized *mut FWPM_PROVIDER0 pointers.
        unsafe {
            let ptr_slice = std::slice::from_raw_parts(entries_ptr, len);
            for &prov_ptr in ptr_slice {
                if !prov_ptr.is_null() {
                    let prov = &*prov_ptr;
                    providers.push(WfpProviderInfo {
                        key: format_guid(&prov.providerKey),
                        name: read_pwstr(prov.displayData.name),
                        persistent: (prov.flags & FWPM_PROVIDER_FLAG_PERSISTENT) != 0,
                    });
                }
            }
            let mut free_target = entries_ptr as *mut core::ffi::c_void;
            FwpmFreeMemory0(&mut free_target);
        }
    }
    Ok(providers)
}

fn check_sublayer_present(engine: HANDLE, sub_guid: &GUID) -> Result<bool, WindowsSensorError> {
    let mut sublayer_ptr: *mut FWPM_SUBLAYER0 = null_mut();
    #[allow(
        unsafe_code,
        reason = "Check whether Guardrails WFP sublayer is present."
    )]
    let sub_rc = {
        // SAFETY: engine is open and sublayer_ptr receives optional BFE allocation freed below.
        unsafe { FwpmSubLayerGetByKey0(engine, sub_guid, &mut sublayer_ptr) }
    };
    let present = sub_rc == 0 && !sublayer_ptr.is_null();
    if !sublayer_ptr.is_null() {
        #[allow(
            unsafe_code,
            reason = "Free FWPM_SUBLAYER0 structure allocated by BFE."
        )]
        // SAFETY: sublayer_ptr was allocated by FwpmSubLayerGetByKey0 and is freed once.
        unsafe {
            let mut free_target = sublayer_ptr as *mut core::ffi::c_void;
            FwpmFreeMemory0(&mut free_target);
        }
    }
    if !present && sub_rc != 0 && sub_rc != hresult_to_u32(FWP_E_SUBLAYER_NOT_FOUND) {
        return Err(map_wfp_status("FwpmSubLayerGetByKey0", sub_rc));
    }
    Ok(present)
}

fn map_wfp_status(op: &str, code: u32) -> WindowsSensorError {
    if is_access_denied(code) {
        WindowsSensorError::Wfp(format!("WFP_ACCESS_DENIED:{op} denied (0x{code:08x})"))
    } else {
        WindowsSensorError::Wfp(format!("{op} failed with 0x{code:08x}"))
    }
}

pub(crate) const fn is_access_denied(code: u32) -> bool {
    code == ERROR_ACCESS_DENIED || code == HRESULT_ACCESS_DENIED || code == WFP_ACCESS_DENIED_ERR
}

fn strip_wfp_access_denied(err: &WindowsSensorError) -> Option<String> {
    if let WindowsSensorError::Wfp(msg) = err
        && let Some(rest) = msg.strip_prefix("WFP_ACCESS_DENIED:")
    {
        return Some(rest.to_string());
    }
    None
}

const fn hresult_to_u32(hr: windows_sys::core::HRESULT) -> u32 {
    u32::from_ne_bytes(hr.to_ne_bytes())
}

pub(crate) fn encode_utf16_nul(value: &str) -> Result<Vec<u16>, WindowsSensorError> {
    if value.chars().any(|c| c == '\0') {
        return Err(WindowsSensorError::Wfp(
            "WFP string contains interior NUL byte".to_string(),
        ));
    }
    let mut out: Vec<u16> = value.encode_utf16().collect();
    out.push(0);
    Ok(out)
}

fn read_pwstr(ptr: *mut u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < 512 {
        #[allow(
            unsafe_code,
            reason = "Read NUL-terminated UTF-16 provider name from BFE."
        )]
        // SAFETY: ptr is non-null BFE displayData.name terminated within 512 WCHARs.
        let ch = unsafe { *ptr.add(len) };
        if ch == 0 {
            break;
        }
        len = len.saturating_add(1);
    }
    #[allow(unsafe_code, reason = "Convert BFE UTF-16 name slice to Rust String.")]
    // SAFETY: Verified non-null NUL-terminated slice of len UTF-16 units.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

fn format_guid(g: &GUID) -> String {
    let [b0, b1, b2, b3, b4, b5, b6, b7] = g.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{b0:02x}{b1:02x}-{b2:02x}{b3:02x}{b4:02x}{b5:02x}{b6:02x}{b7:02x}",
        g.data1, g.data2, g.data3,
    )
}
