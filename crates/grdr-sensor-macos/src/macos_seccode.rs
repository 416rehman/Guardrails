// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ffi::{CString, c_char, c_int, c_void};
use std::ptr::null;

use crate::brand::is_valid_apple_team_id;
use crate::macos_probes::{DeveloperSigningStatus, evaluate_developer_signing_status};

const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_CF_NUMBER_SINT64_TYPE: isize = 4;
const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;
const K_SEC_CS_DYNAMIC_INFORMATION: u32 = 1 << 3;
const CS_VALID: u32 = 0x0000_0001;
const CS_ADHOC: u32 = 0x0000_0002;
const ENTITLEMENT_NE: &str = "com.apple.developer.networking.networkextension";
const ENTITLEMENT_ES: &str = "com.apple.developer.endpoint-security.client";
const ENTITLEMENT_SYSEXT_INSTALL: &str = "com.apple.developer.system-extension.install";
const ENTITLEMENT_KEYS: &[&str] = &[ENTITLEMENT_NE, ENTITLEMENT_ES, ENTITLEMENT_SYSEXT_INSTALL];

struct CfGuard(*const c_void);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigningTrust {
    ValidSigned,
    AdhocOrInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntitlementGrant {
    None,
    ExtensionOnly,
    EndpointSecurity,
}

pub(crate) struct SecCodeOutcome {
    pub(crate) team_id: Option<String>,
    pub(crate) signing_id: Option<String>,
    pub(crate) cdhash: Option<String>,
    pub(crate) trust: SigningTrust,
    pub(crate) entitlements: EntitlementGrant,
}

#[link(name = "CoreFoundation", kind = "framework")]
#[allow(
    unsafe_code,
    reason = "Apple CoreFoundation bindings for Security framework calls."
)]
// SAFETY: Standard Apple CoreFoundation C ABI declarations matching CFBase/CFString/CFData/CFNumber/CFDictionary headers.
unsafe extern "C" {
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;
    fn CFRelease(cf: *const c_void);
    fn CFStringCreateWithCString(
        alloc: *const c_void,
        c_str: *const c_char,
        encoding: u32,
    ) -> *const c_void;
    fn CFStringGetCString(
        the_string: *const c_void,
        buffer: *mut c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> u8;
    fn CFDataCreate(allocator: *const c_void, bytes: *const u8, length: isize) -> *const c_void;
    fn CFDataGetLength(the_data: *const c_void) -> isize;
    fn CFDataGetBytePtr(the_data: *const c_void) -> *const u8;
    fn CFNumberCreate(
        allocator: *const c_void,
        the_type: isize,
        value_ptr: *const c_void,
    ) -> *const c_void;
    fn CFNumberGetValue(number: *const c_void, the_type: isize, value_ptr: *mut c_void) -> u8;
    fn CFDictionaryCreate(
        allocator: *const c_void,
        keys: *const *const c_void,
        values: *const *const c_void,
        num_values: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> *const c_void;
    fn CFDictionaryGetValue(the_dict: *const c_void, key: *const c_void) -> *const c_void;
}

#[link(name = "Security", kind = "framework")]
#[allow(
    unsafe_code,
    non_upper_case_globals,
    reason = "Apple Security framework bindings for SecCodeCopySelf, SecCodeCopyGuestWithAttributes, and SecCodeCheckValidity."
)]
// SAFETY: Standard Apple Security.framework C ABI symbols matching <Security/SecCode.h>.
unsafe extern "C" {
    static kSecGuestAttributeAudit: *const c_void;
    static kSecGuestAttributePid: *const c_void;
    static kSecCodeInfoTeamIdentifier: *const c_void;
    static kSecCodeInfoIdentifier: *const c_void;
    static kSecCodeInfoFlags: *const c_void;
    static kSecCodeInfoStatus: *const c_void;
    static kSecCodeInfoUnique: *const c_void;
    static kSecCodeInfoEntitlementsDict: *const c_void;
    fn SecCodeCopySelf(flags: u32, self_code: *mut *const c_void) -> i32;
    fn SecCodeCopyGuestWithAttributes(
        host: *const c_void,
        attributes: *const c_void,
        flags: u32,
        guest: *mut *const c_void,
    ) -> i32;
    fn SecCodeCheckValidity(code: *const c_void, flags: u32, requirement: *const c_void) -> i32;
    fn SecCodeCopySigningInformation(
        code: *const c_void,
        flags: u32,
        information: *mut *const c_void,
    ) -> i32;
}

impl Drop for CfGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            #[allow(unsafe_code, reason = "Release owned CoreFoundation object reference.")]
            // SAFETY: Non-null CFTypeRef created/retained by CoreFoundation or Security framework.
            let () = unsafe {
                CFRelease(self.0);
            };
            self.0 = null();
        }
    }
}

pub(crate) fn darwin_probe_self_signing() -> (DeveloperSigningStatus, Option<String>, bool) {
    let mut self_code: *const c_void = null();
    #[allow(
        unsafe_code,
        reason = "Inspect current process code signature and entitlements via SecCodeCopySelf."
    )]
    // SAFETY: self_code receives retained SecCodeRef managed by CfGuard.
    let rc = unsafe { SecCodeCopySelf(0, &mut self_code) };
    if rc != 0 || self_code.is_null() {
        return (DeveloperSigningStatus::Unavailable, None, false);
    }
    let _guard = CfGuard(self_code);
    let outcome = darwin_inspect_seccode_ref(self_code, 0);
    let has_profile = std::env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .and_then(|p| p.parent())
                .map(|contents| contents.join("embedded.provisionprofile"))
        })
        .is_some_and(|p| p.is_file());
    let team_ok = outcome
        .team_id
        .as_deref()
        .is_some_and(is_valid_apple_team_id);
    let valid_team = team_ok.then_some(outcome.team_id.clone()).flatten();
    let is_adhoc = outcome.trust != SigningTrust::ValidSigned;
    let has_any_ext = outcome.entitlements != EntitlementGrant::None;
    let status = evaluate_developer_signing_status(
        valid_team.as_deref(),
        is_adhoc,
        !is_adhoc && has_any_ext,
        has_profile,
    );
    let es_entitled = !is_adhoc && outcome.entitlements == EntitlementGrant::EndpointSecurity;
    (status, valid_team, es_entitled)
}

pub(crate) fn darwin_read_guest_seccode_by_audit(audit_token_bytes: &[u8; 32]) -> SecCodeOutcome {
    #[allow(
        unsafe_code,
        reason = "Wrap audit_token_t bytes in CFDataRef and inspect guest via kSecGuestAttributeAudit."
    )]
    // SAFETY: audit_token_bytes covers 32 readable bytes; kSecGuestAttributeAudit is a constant Security CFStringRef.
    unsafe {
        let cf_audit = CFDataCreate(null(), audit_token_bytes.as_ptr(), 32);
        if cf_audit.is_null() {
            return empty_seccode();
        }
        let _audit_guard = CfGuard(cf_audit);
        copy_guest_with_single_attr(kSecGuestAttributeAudit, cf_audit)
    }
}

pub(crate) fn darwin_read_guest_seccode_info(raw_pid: c_int) -> SecCodeOutcome {
    let pid_val = i64::from(raw_pid);
    #[allow(
        unsafe_code,
        reason = "Wrap process PID in CFNumberRef and inspect guest via kSecGuestAttributePid."
    )]
    // SAFETY: pid_val lives on stack for CFNumberCreate; kSecGuestAttributePid is a constant Security CFStringRef.
    unsafe {
        let cf_pid = CFNumberCreate(
            null(),
            K_CF_NUMBER_SINT64_TYPE,
            (&raw const pid_val).cast::<c_void>(),
        );
        if cf_pid.is_null() {
            return empty_seccode();
        }
        let _pid_guard = CfGuard(cf_pid);
        copy_guest_with_single_attr(kSecGuestAttributePid, cf_pid)
    }
}

fn copy_guest_with_single_attr(attr_key: *const c_void, attr_val: *const c_void) -> SecCodeOutcome {
    if attr_key.is_null() || attr_val.is_null() {
        return empty_seccode();
    }
    #[allow(
        unsafe_code,
        reason = "Build CFDictionaryRef with single guest attribute for SecCodeCopyGuestWithAttributes."
    )]
    // SAFETY: attr_key is a valid Apple constant CFStringRef and attr_val is a retained CFTypeRef.
    let attrs_dict = unsafe {
        let keys = [attr_key];
        let vals = [attr_val];
        CFDictionaryCreate(
            null(),
            keys.as_ptr(),
            vals.as_ptr(),
            1,
            (&raw const kCFTypeDictionaryKeyCallBacks).cast::<c_void>(),
            (&raw const kCFTypeDictionaryValueCallBacks).cast::<c_void>(),
        )
    };
    if attrs_dict.is_null() {
        return empty_seccode();
    }
    let _attrs_guard = CfGuard(attrs_dict);

    let mut guest_code: *const c_void = null();
    let guest_rc = {
        #[allow(
            unsafe_code,
            reason = "Resolve running guest SecCodeRef via audit token or PID attribute."
        )]
        // SAFETY: attrs_dict is a valid CFDictionaryRef and guest_code receives retained SecCodeRef.
        unsafe {
            SecCodeCopyGuestWithAttributes(null(), attrs_dict, 0, &mut guest_code)
        }
    };
    if guest_rc != 0 || guest_code.is_null() {
        return empty_seccode();
    }
    let _code_guard = CfGuard(guest_code);
    darwin_inspect_seccode_ref(guest_code, K_SEC_CS_DYNAMIC_INFORMATION)
}

fn darwin_inspect_seccode_ref(code_ref: *const c_void, extra_flags: u32) -> SecCodeOutcome {
    #[allow(
        unsafe_code,
        reason = "Verify live running code signature validity via SecCodeCheckValidity."
    )]
    // SAFETY: code_ref is a retained live SecCodeRef checked with default flags and null requirement.
    let valid_rc = unsafe { SecCodeCheckValidity(code_ref, 0, null()) };
    if valid_rc != 0 {
        return empty_seccode();
    }

    let mut info_dict: *const c_void = null();
    #[allow(
        unsafe_code,
        reason = "Copy signing metadata from verified SecCodeRef."
    )]
    // SAFETY: code_ref is live and info_dict receives retained CFDictionaryRef released by CfGuard.
    let info_rc = unsafe {
        SecCodeCopySigningInformation(
            code_ref,
            K_SEC_CS_SIGNING_INFORMATION | extra_flags,
            &mut info_dict,
        )
    };
    if info_rc != 0 || info_dict.is_null() {
        return empty_seccode();
    }
    let _dict_guard = CfGuard(info_dict);

    #[allow(
        unsafe_code,
        reason = "Read signing status, flags, TeamIdentifier, Identifier, cdhash, and entitlements from verified SecCode dictionary."
    )]
    // SAFETY: info_dict is a valid CFDictionaryRef and kSecCodeInfo* keys are Apple constant CFStringRefs.
    unsafe {
        let status_flags = cfnumber_to_u32(CFDictionaryGetValue(info_dict, kSecCodeInfoStatus));
        if (status_flags.unwrap_or(0) & CS_VALID) == 0 {
            return empty_seccode();
        }
        let code_flags = cfnumber_to_u32(CFDictionaryGetValue(info_dict, kSecCodeInfoFlags));
        let adhoc_signed = code_flags.is_some_and(|f| (f & CS_ADHOC) != 0);
        let team_id = cfstring_to_rust(CFDictionaryGetValue(info_dict, kSecCodeInfoTeamIdentifier));
        let signing_id = cfstring_to_rust(CFDictionaryGetValue(info_dict, kSecCodeInfoIdentifier));
        let cdhash = cfdata_to_hex(CFDictionaryGetValue(info_dict, kSecCodeInfoUnique));
        let ent_dict = CFDictionaryGetValue(info_dict, kSecCodeInfoEntitlementsDict);
        let entitlements = if has_entitlement_key(ent_dict, ENTITLEMENT_ES) {
            EntitlementGrant::EndpointSecurity
        } else if ENTITLEMENT_KEYS
            .iter()
            .any(|&key| has_entitlement_key(ent_dict, key))
        {
            EntitlementGrant::ExtensionOnly
        } else {
            EntitlementGrant::None
        };
        SecCodeOutcome {
            team_id,
            signing_id,
            cdhash,
            trust: if adhoc_signed {
                SigningTrust::AdhocOrInvalid
            } else {
                SigningTrust::ValidSigned
            },
            entitlements,
        }
    }
}

fn empty_seccode() -> SecCodeOutcome {
    SecCodeOutcome {
        team_id: None,
        signing_id: None,
        cdhash: None,
        trust: SigningTrust::AdhocOrInvalid,
        entitlements: EntitlementGrant::None,
    }
}

#[allow(
    unsafe_code,
    reason = "Check borrowed kSecCodeInfoEntitlementsDict CFDictionaryRef for specific entitlement key."
)]
// SAFETY: ent_dict is null or a borrowed CFDictionaryRef inside retained signing info dictionary.
unsafe fn has_entitlement_key(ent_dict: *const c_void, key_name: &str) -> bool {
    if ent_dict.is_null() {
        return false;
    }
    let Ok(c_key) = CString::new(key_name) else {
        return false;
    };
    #[allow(
        unsafe_code,
        reason = "Create temporary CFStringRef lookup key and check CFDictionaryGetValue."
    )]
    // SAFETY: c_key is valid NUL-terminated ASCII; cf_key is released via CfGuard.
    unsafe {
        let cf_key = CFStringCreateWithCString(null(), c_key.as_ptr(), CF_STRING_ENCODING_UTF8);
        if cf_key.is_null() {
            false
        } else {
            let _key_guard = CfGuard(cf_key);
            !CFDictionaryGetValue(ent_dict, cf_key).is_null()
        }
    }
}

#[allow(
    unsafe_code,
    reason = "Extract u32 value from borrowed CFNumberRef inside verified CFDictionaryRef."
)]
// SAFETY: Caller passes null or a borrowed CFNumberRef inside a live retained CFDictionaryRef.
unsafe fn cfnumber_to_u32(cf_num: *const c_void) -> Option<u32> {
    if cf_num.is_null() {
        return None;
    }
    let mut out: i64 = 0;
    #[allow(unsafe_code, reason = "Copy integer value from borrowed CFNumberRef.")]
    // SAFETY: cf_num is verified non-null and out points to valid i64 stack storage.
    let ok = unsafe {
        CFNumberGetValue(
            cf_num,
            K_CF_NUMBER_SINT64_TYPE,
            (&mut out as *mut i64).cast::<c_void>(),
        )
    };
    if ok == 0 {
        return None;
    }
    u32::try_from(out).ok()
}

#[allow(
    unsafe_code,
    reason = "Extract UTF-8 string bytes from borrowed CFStringRef."
)]
// SAFETY: Caller passes null or a borrowed CFStringRef value inside a retained CFDictionaryRef.
unsafe fn cfstring_to_rust(cf_str: *const c_void) -> Option<String> {
    if cf_str.is_null() {
        return None;
    }
    let mut buf = [0u8; 512];
    #[allow(
        unsafe_code,
        reason = "Copy CFStringRef bytes into fixed stack buffer."
    )]
    // SAFETY: cf_str is verified non-null borrowed CFStringRef and buf holds 512 writable bytes.
    let ok = unsafe {
        CFStringGetCString(
            cf_str,
            buf.as_mut_ptr().cast::<c_char>(),
            isize::try_from(buf.len()).unwrap_or(512),
            CF_STRING_ENCODING_UTF8,
        )
    };
    if ok == 0 {
        return None;
    }
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf.get(..nul)?.to_vec()).ok()
}

#[allow(
    unsafe_code,
    reason = "Extract lowercase hex cdhash bytes from borrowed CFDataRef."
)]
// SAFETY: Caller passes null or a borrowed CFDataRef inside a retained CFDictionaryRef.
unsafe fn cfdata_to_hex(cf_data: *const c_void) -> Option<String> {
    if cf_data.is_null() {
        return None;
    }
    #[allow(
        unsafe_code,
        reason = "Read byte length and pointer of borrowed CFDataRef."
    )]
    // SAFETY: cf_data is verified non-null borrowed CFDataRef with read-only contiguous bytes.
    let bytes: &[u8] = unsafe {
        let len = CFDataGetLength(cf_data);
        if len <= 0 || len > 128 {
            return None;
        }
        let ptr = CFDataGetBytePtr(cf_data);
        if ptr.is_null() {
            return None;
        }
        std::slice::from_raw_parts(ptr, usize::try_from(len).unwrap_or(0))
    };
    let mut hex = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    Some(hex)
}
