// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    E_ACCESSDENIED, ERROR_ACCESS_DENIED, FWP_E_ALREADY_EXISTS, FWP_E_PROVIDER_NOT_FOUND,
    FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
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
use crate::wfp::{WfpPrincipalKey, WfpSublayerPlan};
use crate::win_wfp::{AppliedWfpRules, WfpCoexistenceReport, WfpEngineAccess, WfpProviderInfo};
use crate::win_wfp_filters::{encode_utf16_nul, install_single_filter, validate_wfp_sid_str};

const MAX_ENUM_PROVIDERS: u32 = 64;
const GRDR_WFP_PROVIDER_DYNAMIC_GUID: GUID =
    GUID::from_u128(0x6772_6472_0001_4000_8000_0000_0000_0001);
const GRDR_WFP_SUBLAYER_DYNAMIC_GUID: GUID =
    GUID::from_u128(0x6772_6472_0001_4000_8000_0000_0000_0002);
const GRDR_WFP_PROVIDER_PERSISTENT_GUID: GUID =
    GUID::from_u128(0x6772_6472_0001_4000_8000_0000_0000_0003);
const GRDR_WFP_SUBLAYER_PERSISTENT_GUID: GUID =
    GUID::from_u128(0x6772_6472_0001_4000_8000_0000_0000_0004);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WfpCallError {
    AccessDenied { op: &'static str, code: u32 },
    WfpApi { op: &'static str, code: u32 },
    InvalidInput(String),
    ConversionFailed { op: &'static str, detail: String },
}

trait WfpTxOps {
    fn commit_tx(&self) -> u32;
    fn abort_tx(&self) -> u32;
}

struct WfpEngineGuard {
    handle: HANDLE,
}

struct WfpEnumGuard<'a> {
    engine: &'a WfpEngineGuard,
    enum_handle: HANDLE,
}

struct WfpTxGuard<'a, B: WfpTxOps = WfpEngineGuard> {
    ops: &'a B,
    active: bool,
}

impl WfpCallError {
    pub(crate) const fn from_status(op: &'static str, code: u32) -> Self {
        if is_access_denied(code) {
            Self::AccessDenied { op, code }
        } else {
            Self::WfpApi { op, code }
        }
    }
}

impl From<WfpCallError> for WindowsSensorError {
    fn from(err: WfpCallError) -> Self {
        match err {
            WfpCallError::AccessDenied { op, code } => {
                Self::Wfp(format!("{op} denied (0x{code:08x})"))
            }
            WfpCallError::WfpApi { op, code } => {
                Self::Wfp(format!("{op} failed with 0x{code:08x}"))
            }
            WfpCallError::InvalidInput(msg) => Self::Wfp(msg),
            WfpCallError::ConversionFailed { op, detail } => Self::Wfp(format!("{op} {detail}")),
        }
    }
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

impl WfpTxOps for WfpEngineGuard {
    fn commit_tx(&self) -> u32 {
        #[allow(unsafe_code, reason = "Commit atomic BFE WFP transaction.")]
        // SAFETY: self.handle has an active WFP transaction begun by FwpmTransactionBegin0.
        unsafe {
            FwpmTransactionCommit0(self.handle)
        }
    }

    fn abort_tx(&self) -> u32 {
        #[allow(unsafe_code, reason = "Abort uncommitted BFE WFP transaction.")]
        // SAFETY: self.handle has an uncommitted WFP transaction aborted once on unwind/error.
        unsafe {
            FwpmTransactionAbort0(self.handle)
        }
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

impl Drop for WfpEnumGuard<'_> {
    fn drop(&mut self) {
        if !self.enum_handle.is_null() {
            #[allow(unsafe_code, reason = "Destroy WFP provider enumeration handle.")]
            // SAFETY: enum_handle belongs to open engine handle and is destroyed once.
            unsafe {
                let _ = FwpmProviderDestroyEnumHandle0(self.engine.handle, self.enum_handle);
            }
            self.enum_handle = null_mut();
        }
    }
}

impl<'a> WfpTxGuard<'a, WfpEngineGuard> {
    fn begin(engine: &'a WfpEngineGuard) -> Result<Self, u32> {
        #[allow(unsafe_code, reason = "Begin atomic BFE WFP transaction.")]
        // SAFETY: engine holds a live opened WFP engine handle.
        let rc = unsafe { FwpmTransactionBegin0(engine.handle, 0) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Self {
            ops: engine,
            active: true,
        })
    }
}

impl<'a, B: WfpTxOps> WfpTxGuard<'a, B> {
    fn commit(mut self) -> Result<(), u32> {
        let rc = self.ops.commit_tx();
        if rc == 0 {
            self.active = false;
            Ok(())
        } else {
            Err(rc)
        }
    }

    fn abort(&mut self) -> Result<(), u32> {
        if !self.active {
            return Ok(());
        }
        let rc = self.ops.abort_tx();
        if rc == 0 {
            self.active = false;
            Ok(())
        } else {
            Err(rc)
        }
    }
}

impl<B: WfpTxOps> Drop for WfpTxGuard<'_, B> {
    fn drop(&mut self) {
        let _ = self.abort();
    }
}

pub(crate) fn probe_win_wfp_coexistence() -> Result<WfpCoexistenceReport, WindowsSensorError> {
    match probe_win_wfp_coexistence_inner() {
        Ok(report) => Ok(report),
        Err(WfpCallError::AccessDenied { op, code }) => Ok(WfpCoexistenceReport {
            engine_access: WfpEngineAccess::AccessDenied,
            provider_count: 0,
            providers: Vec::new(),
            grdr_sublayer_present: false,
            detail: format!("{op} denied (0x{code:08x}); WFP coexistence probe skipped"),
        }),
        Err(err) => Err(err.into()),
    }
}

fn probe_win_wfp_coexistence_inner() -> Result<WfpCoexistenceReport, WfpCallError> {
    let guard =
        WfpEngineGuard::open().map_err(|rc| WfpCallError::from_status("FwpmEngineOpen0", rc))?;
    let mut enum_handle: HANDLE = null_mut();
    #[allow(unsafe_code, reason = "Create WFP provider enumeration cursor.")]
    // SAFETY: guard.handle is open and enum_handle receives valid handle on success.
    let enum_rc = unsafe { FwpmProviderCreateEnumHandle0(guard.handle, null(), &mut enum_handle) };
    let enum_guard = WfpEnumGuard {
        engine: &guard,
        enum_handle,
    };
    if enum_rc != 0 {
        return Err(WfpCallError::from_status(
            "FwpmProviderCreateEnumHandle0",
            enum_rc,
        ));
    }
    let providers = enumerate_providers(guard.handle, enum_guard.enum_handle)?;
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
    match apply_win_wfp_plan_tx(plan) {
        Ok(applied) => Ok(applied),
        Err(WfpCallError::AccessDenied { op, code }) => Ok(AppliedWfpRules {
            applied: false,
            filter_ids: Vec::new(),
            detail: format!("{op} denied (0x{code:08x})"),
        }),
        Err(err) => Err(err.into()),
    }
}

fn validate_wfp_plan_inputs(plan: &WfpSublayerPlan) -> Result<(), WfpCallError> {
    for rule in &plan.rules {
        if rule.rule_name.contains('\0') {
            return Err(WfpCallError::InvalidInput(
                "WFP rule_name contains interior NUL byte".to_string(),
            ));
        }
        let sid = match &rule.principal {
            WfpPrincipalKey::SandboxSid { sid } => sid,
            WfpPrincipalKey::AppContainerPackageSid { package_sid } => package_sid,
            WfpPrincipalKey::ServiceSid { service_sid } => service_sid,
        };
        validate_wfp_sid_str(sid)?;
    }
    Ok(())
}

fn apply_win_wfp_plan_tx(plan: &WfpSublayerPlan) -> Result<AppliedWfpRules, WfpCallError> {
    validate_wfp_plan_inputs(plan)?;
    let guard =
        WfpEngineGuard::open().map_err(|rc| WfpCallError::from_status("FwpmEngineOpen0", rc))?;
    let tx = WfpTxGuard::begin(&guard)
        .map_err(|rc| WfpCallError::from_status("FwpmTransactionBegin0", rc))?;

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
        let (prov_guid, sub_guid) = tier_guids(rule.persistent);
        filter_ids.push(install_single_filter(
            guard.handle,
            rule,
            prov_guid,
            sub_guid,
        )?);
    }

    tx.commit()
        .map_err(|rc| WfpCallError::from_status("FwpmTransactionCommit0", rc))?;

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
    let guard = WfpEngineGuard::open()
        .map_err(|rc| WindowsSensorError::from(WfpCallError::from_status("FwpmEngineOpen0", rc)))?;
    let tx = WfpTxGuard::begin(&guard).map_err(|rc| {
        WindowsSensorError::from(WfpCallError::from_status("FwpmTransactionBegin0", rc))
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
        WindowsSensorError::from(WfpCallError::from_status("FwpmTransactionCommit0", rc))
    })?;
    Ok(removed)
}

fn ensure_tier_provider_and_sublayer(
    engine: HANDLE,
    weight: u16,
    persistent: bool,
) -> Result<(), WfpCallError> {
    let (prov_guid, sub_guid) = tier_guids(persistent);
    let mut existing_prov: *mut FWPM_PROVIDER0 = null_mut();
    #[allow(unsafe_code, reason = "Check Guardrails WFP provider registration.")]
    // SAFETY: engine is open and existing_prov receives optional BFE allocation.
    let prov_rc = unsafe { FwpmProviderGetByKey0(engine, &prov_guid, &mut existing_prov) };
    if !existing_prov.is_null() {
        #[allow(unsafe_code, reason = "Free FWPM_PROVIDER0 allocated by BFE.")]
        // SAFETY: existing_prov was returned by BFE and freed once unconditionally.
        unsafe {
            let mut free_target = existing_prov as *mut core::ffi::c_void;
            FwpmFreeMemory0(&mut free_target);
        }
    }
    if prov_rc == hresult_to_u32(FWP_E_PROVIDER_NOT_FOUND) {
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
            return Err(WfpCallError::from_status("FwpmProviderAdd0", add_rc));
        }
    } else if prov_rc != 0 {
        return Err(WfpCallError::from_status("FwpmProviderGetByKey0", prov_rc));
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
            return Err(WfpCallError::from_status("FwpmSubLayerAdd0", add_rc));
        }
    }
    Ok(())
}

fn enumerate_providers(
    engine: HANDLE,
    enum_handle: HANDLE,
) -> Result<Vec<WfpProviderInfo>, WfpCallError> {
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
        if !entries_ptr.is_null() {
            #[allow(unsafe_code, reason = "Free BFE buffer returned alongside error.")]
            // SAFETY: entries_ptr was returned non-null by BFE and freed once.
            unsafe {
                let mut free_target = entries_ptr as *mut core::ffi::c_void;
                FwpmFreeMemory0(&mut free_target);
            }
        }
        return Err(WfpCallError::from_status("FwpmProviderEnum0", list_rc));
    }
    let mut providers = Vec::new();
    if !entries_ptr.is_null() {
        let len = usize::try_from(count).map_err(|_| {
            WfpCallError::InvalidInput("WFP provider count exceeds usize".to_string())
        })?;
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

fn check_sublayer_present(engine: HANDLE, sub_guid: &GUID) -> Result<bool, WfpCallError> {
    let mut sublayer_ptr: *mut FWPM_SUBLAYER0 = null_mut();
    #[allow(
        unsafe_code,
        reason = "Check whether Guardrails WFP sublayer is present."
    )]
    // SAFETY: engine is open and sublayer_ptr receives optional BFE allocation freed below.
    let sub_rc = unsafe { FwpmSubLayerGetByKey0(engine, sub_guid, &mut sublayer_ptr) };
    let non_null = !sublayer_ptr.is_null();
    if non_null {
        #[allow(
            unsafe_code,
            reason = "Free FWPM_SUBLAYER0 structure allocated by BFE."
        )]
        // SAFETY: sublayer_ptr was allocated by FwpmSubLayerGetByKey0 and is freed once unconditionally.
        unsafe {
            let mut free_target = sublayer_ptr as *mut core::ffi::c_void;
            FwpmFreeMemory0(&mut free_target);
        }
    }
    if sub_rc == 0 {
        return Ok(non_null);
    }
    if sub_rc == hresult_to_u32(FWP_E_SUBLAYER_NOT_FOUND) {
        return Ok(false);
    }
    Err(WfpCallError::from_status("FwpmSubLayerGetByKey0", sub_rc))
}

const fn tier_guids(persistent: bool) -> (GUID, GUID) {
    if persistent {
        (
            GRDR_WFP_PROVIDER_PERSISTENT_GUID,
            GRDR_WFP_SUBLAYER_PERSISTENT_GUID,
        )
    } else {
        (
            GRDR_WFP_PROVIDER_DYNAMIC_GUID,
            GRDR_WFP_SUBLAYER_DYNAMIC_GUID,
        )
    }
}

pub(crate) const fn is_access_denied(code: u32) -> bool {
    // Winerror.h has no FWP_E_ACCESS_DENIED; BFE returns ERROR_ACCESS_DENIED or E_ACCESSDENIED.
    code == ERROR_ACCESS_DENIED || code == hresult_to_u32(E_ACCESSDENIED)
}

const fn hresult_to_u32(hr: windows_sys::core::HRESULT) -> u32 {
    u32::from_ne_bytes(hr.to_ne_bytes())
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

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::Cell;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

    use windows_sys::Win32::Foundation::{
        FWP_E_CONDITION_NOT_FOUND, FWP_E_INVALID_PARAMETER, FWP_E_NO_TXN_IN_PROGRESS,
        FWP_E_TIMEOUT, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, TOKEN_ELEVATION,
        TOKEN_QUERY, TokenElevation, WinBuiltinAdministratorsSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::*;
    use crate::wfp::{WfpFilterAction, WfpFilterRule, WfpLayer};

    struct FakeTxOps {
        commit_rc: u32,
        abort_rcs: [u32; 2],
        commit_calls: Cell<usize>,
        abort_calls: Cell<usize>,
    }

    impl WfpTxOps for FakeTxOps {
        fn commit_tx(&self) -> u32 {
            self.commit_calls
                .set(self.commit_calls.get().saturating_add(1));
            self.commit_rc
        }

        fn abort_tx(&self) -> u32 {
            let idx = self.abort_calls.get();
            self.abort_calls.set(idx.saturating_add(1));
            self.abort_rcs.get(idx).copied().unwrap_or(0)
        }
    }

    pub(crate) fn current_process_is_elevated_admin() -> Result<bool, WindowsSensorError> {
        let mut raw_token: HANDLE = null_mut();
        #[allow(
            unsafe_code,
            reason = "Open current process token for test elevation check."
        )]
        // SAFETY: GetCurrentProcess() is always valid and raw_token receives owned token handle.
        let tok_ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) };
        if tok_ok == 0 || raw_token.is_null() || raw_token == INVALID_HANDLE_VALUE {
            return Err(WindowsSensorError::Wfp(format!(
                "OpenProcessToken failed ({})",
                std::io::Error::last_os_error()
            )));
        }
        #[allow(
            unsafe_code,
            reason = "Wrap current process token HANDLE in OwnedHandle."
        )]
        // SAFETY: raw_token was verified non-null and valid from OpenProcessToken.
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token as RawHandle) };

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let elev_size = u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>())
            .map_err(|_| WindowsSensorError::Wfp("TOKEN_ELEVATION size exceeds u32".to_string()))?;
        #[allow(unsafe_code, reason = "Query TokenElevation on current process token.")]
        // SAFETY: token is valid TOKEN_QUERY handle and elevation buffer matches elev_size.
        let elev_ok = unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenElevation,
                (&raw mut elevation).cast(),
                elev_size,
                &mut ret_len,
            )
        };
        if elev_ok == 0 {
            return Err(WindowsSensorError::Wfp(format!(
                "GetTokenInformation(TokenElevation) failed ({})",
                std::io::Error::last_os_error()
            )));
        }

        let mut sid_buf = [0u64; 16];
        let mut sid_size = u32::try_from(std::mem::size_of_val(&sid_buf))
            .map_err(|_| WindowsSensorError::Wfp("SID buffer size exceeds u32".to_string()))?;
        #[allow(unsafe_code, reason = "Build Builtin Administrators well-known SID.")]
        // SAFETY: sid_buf is 128-byte aligned storage sized cleanly for a Windows SID.
        let sid_ok = unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                null_mut(),
                sid_buf.as_mut_ptr().cast(),
                &mut sid_size,
            )
        };
        if sid_ok == 0 {
            return Err(WindowsSensorError::Wfp(format!(
                "CreateWellKnownSid failed ({})",
                std::io::Error::last_os_error()
            )));
        }
        let mut is_member: windows_sys::core::BOOL = 0;
        #[allow(
            unsafe_code,
            reason = "Check token membership against Builtin Administrators SID."
        )]
        // SAFETY: null token inspects calling thread effective token; sid_buf holds valid initialized SID.
        let mem_ok = unsafe {
            CheckTokenMembership(null_mut(), sid_buf.as_mut_ptr().cast(), &mut is_member)
        };
        if mem_ok == 0 {
            return Err(WindowsSensorError::Wfp(format!(
                "CheckTokenMembership failed ({})",
                std::io::Error::last_os_error()
            )));
        }

        Ok(elevation.TokenIsElevated != 0 && is_member != 0)
    }

    #[test]
    fn classifies_access_denied_distinct_from_fwp_status_codes() {
        assert!(is_access_denied(ERROR_ACCESS_DENIED));
        assert!(is_access_denied(hresult_to_u32(E_ACCESSDENIED)));
        assert!(!is_access_denied(hresult_to_u32(FWP_E_NO_TXN_IN_PROGRESS)));
        assert!(!is_access_denied(hresult_to_u32(FWP_E_CONDITION_NOT_FOUND)));
        assert!(!is_access_denied(hresult_to_u32(FWP_E_INVALID_PARAMETER)));

        assert_eq!(
            WfpCallError::from_status("FwpmEngineOpen0", ERROR_ACCESS_DENIED),
            WfpCallError::AccessDenied {
                op: "FwpmEngineOpen0",
                code: ERROR_ACCESS_DENIED,
            }
        );
        assert_eq!(
            WfpCallError::from_status("FwpmEngineOpen0", hresult_to_u32(E_ACCESSDENIED)),
            WfpCallError::AccessDenied {
                op: "FwpmEngineOpen0",
                code: 0x8007_0005,
            }
        );
        assert_eq!(
            WfpCallError::from_status(
                "FwpmTransactionCommit0",
                hresult_to_u32(FWP_E_NO_TXN_IN_PROGRESS)
            ),
            WfpCallError::WfpApi {
                op: "FwpmTransactionCommit0",
                code: 0x8032_000d,
            }
        );
        assert_eq!(
            WfpCallError::from_status("FwpmFilterAdd0", hresult_to_u32(FWP_E_CONDITION_NOT_FOUND)),
            WfpCallError::WfpApi {
                op: "FwpmFilterAdd0",
                code: 0x8032_0002,
            }
        );

        assert!(matches!(
            WindowsSensorError::from(WfpCallError::InvalidInput("bad input".into())),
            WindowsSensorError::Wfp(ref msg) if msg == "bad input"
        ));
        assert!(matches!(
            WindowsSensorError::from(WfpCallError::ConversionFailed {
                op: "ConvertStringSidToSidW",
                detail: "failed".into(),
            }),
            WindowsSensorError::Wfp(ref msg) if msg == "ConvertStringSidToSidW failed"
        ));
    }

    #[test]
    fn pre_validates_plan_rules_before_opening_wfp_engine() {
        let base_rule = WfpFilterRule {
            rule_name: "valid-rule".into(),
            layer: WfpLayer::AleAuthConnectV4,
            principal: WfpPrincipalKey::AppContainerPackageSid {
                package_sid: "S-1-15-2-1001".into(),
            },
            action: WfpFilterAction::HardBlock,
            weight: 100,
            persistent: false,
            remote_port: None,
            loopback_only: false,
        };

        let mut nul_rule = base_rule.clone();
        nul_rule.rule_name = "bad\0rule".into();
        let nul_plan = WfpSublayerPlan {
            provider_key: "p",
            sublayer_key: "s",
            sublayer_weight: 0x7000,
            rules: vec![nul_rule],
        };
        assert!(matches!(
            validate_wfp_plan_inputs(&nul_plan),
            Err(WfpCallError::InvalidInput(_))
        ));
        assert!(apply_win_wfp_plan(&nul_plan).is_err());

        for bad_sid in [
            "S-1-1-0",
            "S-1-0-0",
            " S-1-5-18",
            "S-1-5-018",
            "S-1-5",
            "S-2-1-0",
        ] {
            let mut bad_rule = base_rule.clone();
            bad_rule.principal = WfpPrincipalKey::SandboxSid {
                sid: bad_sid.into(),
            };
            let bad_plan = WfpSublayerPlan {
                provider_key: "p",
                sublayer_key: "s",
                sublayer_weight: 0x7000,
                rules: vec![bad_rule],
            };
            assert!(matches!(
                validate_wfp_plan_inputs(&bad_plan),
                Err(WfpCallError::InvalidInput(_))
            ));
            assert!(
                apply_win_wfp_plan(&bad_plan).is_err(),
                "invalid SID `{bad_sid}` must fail pre-validation before BFE open"
            );
        }

        let valid_plan = WfpSublayerPlan {
            provider_key: "p",
            sublayer_key: "s",
            sublayer_weight: 0x7000,
            rules: vec![base_rule],
        };
        assert!(validate_wfp_plan_inputs(&valid_plan).is_ok());
    }

    #[test]
    fn tx_guard_tracks_commit_abort_and_drop_semantics() {
        let ops_drop = FakeTxOps {
            commit_rc: 0,
            abort_rcs: [0, 0],
            commit_calls: Cell::new(0),
            abort_calls: Cell::new(0),
        };
        {
            let _tx = WfpTxGuard {
                ops: &ops_drop,
                active: true,
            };
        }
        assert_eq!(ops_drop.commit_calls.get(), 0);
        assert_eq!(ops_drop.abort_calls.get(), 1);

        let ops_ok = FakeTxOps {
            commit_rc: 0,
            abort_rcs: [0, 0],
            commit_calls: Cell::new(0),
            abort_calls: Cell::new(0),
        };
        WfpTxGuard {
            ops: &ops_ok,
            active: true,
        }
        .commit()
        .expect("commit rc=0 succeeds");
        assert_eq!(ops_ok.commit_calls.get(), 1);
        assert_eq!(ops_ok.abort_calls.get(), 0);

        let timeout = hresult_to_u32(FWP_E_TIMEOUT);
        let ops_fail_commit = FakeTxOps {
            commit_rc: timeout,
            abort_rcs: [0, 0],
            commit_calls: Cell::new(0),
            abort_calls: Cell::new(0),
        };
        let err = WfpTxGuard {
            ops: &ops_fail_commit,
            active: true,
        }
        .commit()
        .expect_err("non-zero commit must return error");
        assert_eq!(err, timeout);
        assert_eq!(ops_fail_commit.commit_calls.get(), 1);
        assert_eq!(ops_fail_commit.abort_calls.get(), 1);

        let ops_retry_abort = FakeTxOps {
            commit_rc: 0,
            abort_rcs: [timeout, 0],
            commit_calls: Cell::new(0),
            abort_calls: Cell::new(0),
        };
        let mut tx = WfpTxGuard {
            ops: &ops_retry_abort,
            active: true,
        };
        assert_eq!(tx.abort(), Err(timeout));
        assert!(tx.active);
        drop(tx);
        assert_eq!(ops_retry_abort.abort_calls.get(), 2);
    }
}
