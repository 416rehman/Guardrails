// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_CONDITION_FLAG_IS_LOOPBACK,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
    FWP_SECURITY_DESCRIPTOR_TYPE, FWP_SID, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_VALUE0,
    FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_ALE_PACKAGE_ID, FWPM_CONDITION_ALE_USER_ID,
    FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FwpmFilterAdd0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, PSID, SID};
use windows_sys::core::GUID;

use crate::WindowsSensorError;
use crate::wfp::{WfpFilterAction, WfpFilterRule, WfpLayer, WfpPrincipalKey};
use crate::win_wfp_sys::{encode_utf16_nul, is_access_denied};

const SDDL_REVISION_1: u32 = 1;

struct LocalAllocSid {
    sid: PSID,
}

struct LocalAllocSd {
    ptr: PSECURITY_DESCRIPTOR,
    size: u32,
}

enum PrincipalConditionGuard {
    PackageSid {
        _sid: LocalAllocSid,
    },
    UserSecurityDescriptor {
        _guard: LocalAllocSd,
        _blob: Box<FWP_BYTE_BLOB>,
    },
}

impl PrincipalConditionGuard {
    fn from_package_sid(sid: LocalAllocSid) -> Self {
        Self::PackageSid { _sid: sid }
    }
}

impl Drop for LocalAllocSid {
    fn drop(&mut self) {
        if !self.sid.is_null() {
            #[allow(
                unsafe_code,
                reason = "Release SID buffer allocated by ConvertStringSidToSidW."
            )]
            // SAFETY: self.sid came from ConvertStringSidToSidW and is freed once via LocalFree.
            unsafe {
                let _ = LocalFree(self.sid);
            }
            self.sid = null_mut();
        }
    }
}

impl Drop for LocalAllocSd {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            #[allow(
                unsafe_code,
                reason = "Release self-relative SECURITY_DESCRIPTOR allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW."
            )]
            // SAFETY: self.ptr came from ConvertStringSecurityDescriptorToSecurityDescriptorW and is freed once via LocalFree.
            unsafe {
                let _ = LocalFree(self.ptr);
            }
            self.ptr = null_mut();
        }
    }
}

impl LocalAllocSid {
    fn parse(sid_str: &str) -> Result<Self, WindowsSensorError> {
        if !sid_str.starts_with("S-1-") || !sid_str.bytes().all(|b| b.is_ascii_digit() || b == b'-')
        {
            return Err(WindowsSensorError::Wfp(format!(
                "invalid Windows SID format `{sid_str}`"
            )));
        }
        let wide = encode_utf16_nul(sid_str)?;
        let mut raw_sid: PSID = null_mut();
        #[allow(
            unsafe_code,
            reason = "Parse Windows SID string into native SID buffer."
        )]
        // SAFETY: wide is NUL-terminated UTF-16 and raw_sid receives LocalAlloc buffer on success.
        let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw_sid) };
        if ok == 0 || raw_sid.is_null() {
            return Err(WindowsSensorError::Wfp(format!(
                "ConvertStringSidToSidW failed for `{sid_str}`"
            )));
        }
        Ok(Self { sid: raw_sid })
    }
}

impl LocalAllocSd {
    fn for_user_match_sid(sid_str: &str) -> Result<Self, WindowsSensorError> {
        let _verified = LocalAllocSid::parse(sid_str)?;
        let sddl = format!("O:SYG:SYD:(A;;CC;;;{sid_str})");
        let wide_sddl = encode_utf16_nul(&sddl)?;
        let mut raw_sd: PSECURITY_DESCRIPTOR = null_mut();
        let mut sd_size: u32 = 0;
        #[allow(
            unsafe_code,
            reason = "Build self-relative SECURITY_DESCRIPTOR granting FWP_ACTRL_MATCH_FILTER for ALE user condition."
        )]
        // SAFETY: wide_sddl is validated canonical SID SDDL; raw_sd receives LocalAlloc self-relative descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut raw_sd,
                &mut sd_size,
            )
        };
        if ok == 0 || raw_sd.is_null() || sd_size == 0 {
            return Err(WindowsSensorError::Wfp(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed for `{sid_str}`"
            )));
        }
        Ok(Self {
            ptr: raw_sd,
            size: sd_size,
        })
    }
}

impl PrincipalConditionGuard {
    fn build(
        principal: &WfpPrincipalKey,
    ) -> Result<(Self, GUID, FWP_CONDITION_VALUE0), WindowsSensorError> {
        match principal {
            WfpPrincipalKey::AppContainerPackageSid { package_sid } => {
                let parsed_sid = LocalAllocSid::parse(package_sid)?;
                let sid_ptr = parsed_sid.sid as *mut SID;
                let guard = Self::from_package_sid(parsed_sid);
                let val = FWP_CONDITION_VALUE0 {
                    r#type: FWP_SID,
                    Anonymous: FWP_CONDITION_VALUE0_0 { sid: sid_ptr },
                };
                Ok((guard, FWPM_CONDITION_ALE_PACKAGE_ID, val))
            }
            WfpPrincipalKey::SandboxSid { sid } => Self::build_user_sd(sid),
            WfpPrincipalKey::ServiceSid { service_sid } => Self::build_user_sd(service_sid),
        }
    }

    fn build_user_sd(
        sid_str: &str,
    ) -> Result<(Self, GUID, FWP_CONDITION_VALUE0), WindowsSensorError> {
        let sd_guard = LocalAllocSd::for_user_match_sid(sid_str)?;
        let mut blob = Box::new(FWP_BYTE_BLOB {
            size: sd_guard.size,
            data: sd_guard.ptr.cast::<u8>(),
        });
        let blob_ptr: *mut FWP_BYTE_BLOB = &mut *blob;
        let guard = Self::UserSecurityDescriptor {
            _guard: sd_guard,
            _blob: blob,
        };
        let val = FWP_CONDITION_VALUE0 {
            r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { sd: blob_ptr },
        };
        Ok((guard, FWPM_CONDITION_ALE_USER_ID, val))
    }
}

pub(crate) fn install_single_filter(
    engine: HANDLE,
    rule: &WfpFilterRule,
    provider_guid: GUID,
    sublayer_guid: GUID,
) -> Result<u64, WindowsSensorError> {
    let (principal_guard, principal_field_key, principal_val) =
        PrincipalConditionGuard::build(&rule.principal)?;
    let _keep_principal_alive = &principal_guard;

    let mut name = encode_utf16_nul(&rule.rule_name)?;
    let mut desc = encode_utf16_nul("Guardrails session containment rule")?;
    let mut prov_key = provider_guid;
    let mut weight_val = rule.weight;

    let mut conditions = vec![FWPM_FILTER_CONDITION0 {
        fieldKey: principal_field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: principal_val,
    }];
    if let Some(port) = rule.remote_port {
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
            },
        });
    }
    if rule.loopback_only {
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_FLAGS,
            matchType: FWP_MATCH_FLAGS_ALL_SET,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            },
        });
    }

    let action_type = match rule.action {
        WfpFilterAction::HardBlock => FWP_ACTION_BLOCK,
        WfpFilterAction::AllowLoopbackProxyOnly => FWP_ACTION_PERMIT,
    };
    let mut filter_id: u64 = 0;

    #[allow(
        unsafe_code,
        reason = "Install ALE WFP filter keyed on principal user security descriptor or package SID."
    )]
    // SAFETY: All pointers in FWPM_FILTER0 and principal_guard outlive FwpmFilterAdd0.
    let rc = unsafe {
        let mut filter: FWPM_FILTER0 = std::mem::zeroed();
        filter.displayData = FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: desc.as_mut_ptr(),
        };
        filter.flags = if rule.persistent {
            FWPM_FILTER_FLAG_PERSISTENT
        } else {
            0
        };
        filter.providerKey = &mut prov_key;
        filter.layerKey = map_layer_guid(rule.layer);
        filter.subLayerKey = sublayer_guid;
        filter.weight = FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 {
                uint64: &mut weight_val,
            },
        };
        filter.numFilterConditions = u32::try_from(conditions.len()).unwrap_or(0);
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action = FWPM_ACTION0 {
            r#type: action_type,
            Anonymous: std::mem::zeroed(),
        };
        FwpmFilterAdd0(engine, &filter, null_mut(), &mut filter_id)
    };
    drop(conditions);
    drop(principal_guard);
    if rc != 0 {
        if is_access_denied(rc) {
            return Err(WindowsSensorError::Wfp(format!(
                "WFP_ACCESS_DENIED:FwpmFilterAdd0 denied for `{}` (0x{rc:08x})",
                rule.rule_name
            )));
        }
        return Err(WindowsSensorError::Wfp(format!(
            "FwpmFilterAdd0 failed for `{}` with 0x{rc:08x}",
            rule.rule_name
        )));
    }
    Ok(filter_id)
}

const fn map_layer_guid(layer: WfpLayer) -> GUID {
    match layer {
        WfpLayer::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        WfpLayer::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        WfpLayer::AleAuthRecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        WfpLayer::AleAuthRecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}
