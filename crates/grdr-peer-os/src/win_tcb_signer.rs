// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Microsoft Root chain, publisher, and Windows System Component EKU verification (`b.peer`).

use std::ffi::{CStr, c_void};
use std::mem::size_of;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{FILETIME, HANDLE};

const CERT_CHAIN_POLICY_MICROSOFT_ROOT: *const u8 = 7usize as *const u8;
const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
const WINDOWS_SYSTEM_COMPONENT_EKU: &str = "1.3.6.1.4.1.311.10.3.6";
const MAX_EKU_BUFFER_BYTES: usize = 65_536;
const MAX_EKU_COUNT: usize = 64;

#[repr(C)]
pub(crate) struct CryptProviderSgnr {
    cb_struct: u32,
    sft_verify_as_of: FILETIME,
    cs_cert_chain: u32,
    pas_cert_chain: *mut CryptProviderCert,
    dw_signer_type: u32,
    ps_signer: *mut c_void,
    dw_error: u32,
    cs_counter_signers: u32,
    pas_counter_signers: *mut CryptProviderSgnr,
    p_chain_context: *const c_void,
}

#[repr(C)]
pub(crate) struct CryptProviderCert {
    cb_struct: u32,
    p_cert: *const c_void,
    f_commercial: i32,
    f_trusted_root: i32,
    f_self_signed: i32,
    f_test_cert: i32,
    dw_revoked_reason: u32,
    dw_confidence: u32,
    dw_error: u32,
    p_trust_list_context: *mut c_void,
    f_trust_list_signer_cert: i32,
    p_ctl_context: *mut c_void,
    dw_ctl_error: u32,
    f_is_cyclic: i32,
    p_chain_element: *mut c_void,
}

#[repr(C)]
struct CertChainPolicyPara {
    cb_size: u32,
    dw_flags: u32,
    pv_extra_policy_para: *mut c_void,
}

#[repr(C)]
struct CertChainPolicyStatus {
    cb_size: u32,
    dw_error: u32,
    l_chain_index: i32,
    l_element_index: i32,
    pv_extra_policy_status: *mut c_void,
}

#[repr(C)]
struct CtlUsage {
    c_usage_identifier: u32,
    rgpsz_usage_identifier: *const *const i8,
}

#[allow(
    unsafe_code,
    reason = "Win32 wintrust state data and signer chain inspection ABI bindings"
)]
#[link(name = "wintrust")]
unsafe extern "system" {
    fn WTHelperProvDataFromStateData(h_state_data: HANDLE) -> *mut c_void;
    fn WTHelperGetProvSignerFromChain(
        p_prov_data: *mut c_void,
        idx_signer: u32,
        f_countersigner: i32,
        idx_countersigner: u32,
    ) -> *mut CryptProviderSgnr;
    fn WTHelperGetProvCertFromChain(
        p_sgnr: *mut CryptProviderSgnr,
        idx_cert: u32,
    ) -> *mut CryptProviderCert;
}

#[allow(
    unsafe_code,
    reason = "Win32 crypt32 Microsoft root policy, publisher name, and EKU inspection ABI bindings"
)]
#[link(name = "crypt32")]
unsafe extern "system" {
    fn CertVerifyCertificateChainPolicy(
        psz_policy_oid: *const u8,
        p_chain_context: *const c_void,
        p_policy_para: *const CertChainPolicyPara,
        p_policy_status: *mut CertChainPolicyStatus,
    ) -> i32;
    fn CertGetNameStringW(
        p_cert_context: *const c_void,
        dw_type: u32,
        dw_flags: u32,
        pv_type_para: *const c_void,
        psz_name_string: *mut u16,
        cch_name_string: u32,
    ) -> u32;
    fn CertGetEnhancedKeyUsage(
        p_cert_context: *const c_void,
        dw_flags: u32,
        p_usage: *mut CtlUsage,
        pcb_usage: *mut u32,
    ) -> i32;
}

pub(crate) fn validate_microsoft_os_signer_claims(
    ms_root_verified: bool,
    is_test_cert: bool,
    publisher: &str,
    eku_oids: &[&str],
) -> bool {
    if !ms_root_verified || is_test_cert {
        return false;
    }
    let pub_lc = publisher.trim().to_ascii_lowercase();
    if !pub_lc.contains("microsoft") {
        return false;
    }
    eku_oids
        .iter()
        .any(|oid| oid.trim() == WINDOWS_SYSTEM_COMPONENT_EKU)
}

#[allow(
    unsafe_code,
    reason = "Inspects active WinVerifyTrust state handle for Microsoft Root chain and Windows OS EKU"
)]
pub(crate) fn verify_wvt_microsoft_os_signer(state_data: HANDLE) -> bool {
    if state_data.is_null() {
        return false;
    }
    // SAFETY: `state_data` is an active open WinVerifyTrust handle prior to `WTD_STATEACTION_CLOSE`.
    let prov_data = unsafe { WTHelperProvDataFromStateData(state_data) };
    if prov_data.is_null() {
        return false;
    }
    // SAFETY: `prov_data` is a valid non-null `CRYPT_PROVIDER_DATA` pointer returned by `WTHelperProvDataFromStateData`.
    let signer_ptr = unsafe { WTHelperGetProvSignerFromChain(prov_data, 0, 0, 0) };
    // SAFETY: `signer_ptr` is either null or points to the first signer element inside `prov_data`.
    let Some(signer) = (unsafe { signer_ptr.as_ref() }) else {
        return false;
    };
    if signer.dw_error != 0 || signer.cs_cert_chain == 0 || signer.p_chain_context.is_null() {
        return false;
    }

    let para = CertChainPolicyPara {
        cb_size: u32::try_from(size_of::<CertChainPolicyPara>()).unwrap_or(0),
        dw_flags: 0,
        pv_extra_policy_para: null_mut(),
    };
    let mut policy_status = CertChainPolicyStatus {
        cb_size: u32::try_from(size_of::<CertChainPolicyStatus>()).unwrap_or(0),
        dw_error: 1,
        l_chain_index: -1,
        l_element_index: -1,
        pv_extra_policy_status: null_mut(),
    };
    // SAFETY: `signer.p_chain_context` is a valid `PCERT_CHAIN_CONTEXT` owned by `prov_data`.
    let policy_ok = unsafe {
        CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_MICROSOFT_ROOT,
            signer.p_chain_context,
            &para,
            &mut policy_status,
        )
    };
    let ms_root_verified = policy_ok != 0 && policy_status.dw_error == 0;

    // SAFETY: `signer_ptr` is non-null inside `prov_data`; index 0 is the leaf signer certificate.
    let cert_ptr = unsafe { WTHelperGetProvCertFromChain(signer_ptr, 0) };
    // SAFETY: `cert_ptr` is either null or points to `CRYPT_PROVIDER_CERT` owned by `prov_data`.
    let Some(prov_cert) = (unsafe { cert_ptr.as_ref() }) else {
        return false;
    };
    if prov_cert.dw_error != 0 || prov_cert.p_cert.is_null() {
        return false;
    }
    let publisher = read_cert_simple_name(prov_cert.p_cert);
    let ekus = read_cert_ekus(prov_cert.p_cert);
    let eku_refs: Vec<&str> = ekus.iter().map(String::as_str).collect();
    validate_microsoft_os_signer_claims(
        ms_root_verified,
        prov_cert.f_test_cert != 0,
        &publisher,
        &eku_refs,
    )
}

#[allow(
    unsafe_code,
    reason = "Queries CertGetNameStringW into bounded stack UTF-16 buffer"
)]
fn read_cert_simple_name(p_cert: *const c_void) -> String {
    let mut buf = [0u16; 256];
    let cap = u32::try_from(buf.len()).unwrap_or(256);
    // SAFETY: `p_cert` is a live `PCCERT_CONTEXT` and `buf` holds `cap` UTF-16 units.
    let chars = unsafe {
        CertGetNameStringW(
            p_cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            null(),
            buf.as_mut_ptr(),
            cap,
        )
    };
    let len = usize::try_from(chars).unwrap_or(0);
    if len <= 1 || len > buf.len() {
        return String::new();
    }
    String::from_utf16_lossy(buf.get(..len.saturating_sub(1)).unwrap_or(&[]))
}

#[allow(
    unsafe_code,
    reason = "Queries CertGetEnhancedKeyUsage into aligned heap buffer and decodes OID strings"
)]
fn read_cert_ekus(p_cert: *const c_void) -> Vec<String> {
    let mut needed: u32 = 0;
    // SAFETY: Size probe call with null output buffer.
    let ok = unsafe { CertGetEnhancedKeyUsage(p_cert, 0, null_mut(), &mut needed) };
    let bytes = usize::try_from(needed).unwrap_or(0);
    if ok == 0 || bytes < size_of::<CtlUsage>() || bytes > MAX_EKU_BUFFER_BYTES {
        return Vec::new();
    }
    let words = bytes.div_ceil(size_of::<u64>());
    let mut aligned = vec![0u64; words];
    let mut out_len = u32::try_from(bytes).unwrap_or(0);
    let filled = {
        // SAFETY: `aligned` is 8-byte aligned and sized >= `bytes` for `CTL_USAGE` output.
        unsafe { CertGetEnhancedKeyUsage(p_cert, 0, aligned.as_mut_ptr().cast(), &mut out_len) }
    };
    if filled == 0 {
        return Vec::new();
    }
    // SAFETY: `aligned` contains an initialized `CTL_USAGE` written by `CertGetEnhancedKeyUsage`.
    let usage = unsafe { &*aligned.as_ptr().cast::<CtlUsage>() };
    let count = usize::try_from(usage.c_usage_identifier)
        .unwrap_or(0)
        .min(MAX_EKU_COUNT);
    if count == 0 || usage.rgpsz_usage_identifier.is_null() {
        return Vec::new();
    }
    // SAFETY: `rgpsz_usage_identifier` points inside `aligned` to `count` NUL-terminated ASCII OID pointers.
    let ptrs = unsafe { std::slice::from_raw_parts(usage.rgpsz_usage_identifier, count) };
    let mut oids = Vec::with_capacity(count);
    for &ptr in ptrs {
        if ptr.is_null() {
            continue;
        }
        // SAFETY: `ptr` is a valid C string written into `aligned` by `CertGetEnhancedKeyUsage`.
        let cstr = unsafe { CStr::from_ptr(ptr.cast()) };
        if let Ok(text) = cstr.to_str() {
            oids.push(text.to_owned());
        }
    }
    oids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_policy_pins_microsoft_root_publisher_and_system_component_eku() {
        assert!(validate_microsoft_os_signer_claims(
            true,
            false,
            "Microsoft Windows",
            &["1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.10.3.6"]
        ));
        assert!(!validate_microsoft_os_signer_claims(
            false,
            false,
            "Microsoft Windows",
            &["1.3.6.1.4.1.311.10.3.6"]
        ));
        assert!(!validate_microsoft_os_signer_claims(
            true,
            true,
            "Microsoft Windows",
            &["1.3.6.1.4.1.311.10.3.6"]
        ));
        assert!(!validate_microsoft_os_signer_claims(
            true,
            false,
            "Third-Party Attacker CA",
            &["1.3.6.1.4.1.311.10.3.6"]
        ));
        assert!(!validate_microsoft_os_signer_claims(
            true,
            false,
            "Microsoft Corporation",
            &["1.3.6.1.5.5.7.3.3"]
        ));
    }
}
