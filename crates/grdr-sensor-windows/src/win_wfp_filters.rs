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

use crate::wfp::{WfpFilterAction, WfpFilterRule, WfpLayer, WfpPrincipalKey};
use crate::win_wfp_sys::WfpCallError;

const SDDL_REVISION_1: u32 = 1;
const BROAD_WFP_SIDS: &[&str] = &["S-1-0-0", "S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545"];

struct LocalAllocSid {
    sid: PSID,
}

struct LocalAllocSd {
    ptr: PSECURITY_DESCRIPTOR,
    size: u32,
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
    fn parse(sid_str: &str) -> Result<Self, WfpCallError> {
        validate_wfp_sid_str(sid_str)?;
        let wide = encode_utf16_nul(sid_str)?;
        let mut raw_sid: PSID = null_mut();
        #[allow(
            unsafe_code,
            reason = "Parse Windows SID string into native SID buffer."
        )]
        // SAFETY: wide is NUL-terminated UTF-16 and raw_sid receives LocalAlloc buffer on success.
        let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw_sid) };
        let guard = Self { sid: raw_sid };
        if ok == 0 || guard.sid.is_null() {
            return Err(WfpCallError::ConversionFailed {
                op: "ConvertStringSidToSidW",
                detail: format!("failed for `{sid_str}`"),
            });
        }
        Ok(guard)
    }
}

impl LocalAllocSd {
    fn for_user_match_sid(sid_str: &str) -> Result<Self, WfpCallError> {
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
        let guard = Self {
            ptr: raw_sd,
            size: sd_size,
        };
        if ok == 0 || guard.ptr.is_null() || guard.size == 0 {
            return Err(WfpCallError::ConversionFailed {
                op: "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                detail: format!("failed for `{sid_str}` (size={})", guard.size),
            });
        }
        Ok(guard)
    }
}

pub(crate) fn validate_wfp_sid_str(sid_str: &str) -> Result<(), WfpCallError> {
    if sid_str.contains('\0') {
        return Err(WfpCallError::InvalidInput(
            "Windows SID contains interior NUL byte".to_string(),
        ));
    }
    if sid_str != sid_str.trim() {
        return Err(WfpCallError::InvalidInput(format!(
            "Windows SID `{sid_str}` must not contain surrounding whitespace"
        )));
    }
    if BROAD_WFP_SIDS.contains(&sid_str) {
        return Err(WfpCallError::InvalidInput(format!(
            "broad Windows SID `{sid_str}` is prohibited for principal-scoped WFP rules"
        )));
    }
    let rest = sid_str.strip_prefix("S-1-").ok_or_else(|| {
        WfpCallError::InvalidInput(format!("invalid Windows SID format `{sid_str}`"))
    })?;
    if rest.is_empty()
        || !rest.split('-').all(|seg| {
            !seg.is_empty()
                && seg.bytes().all(|b| b.is_ascii_digit())
                && (seg == "0" || !seg.starts_with('0'))
        })
    {
        return Err(WfpCallError::InvalidInput(format!(
            "non-canonical Windows SID format `{sid_str}`"
        )));
    }
    grdr_os_service::validate_windows_sid(sid_str)
        .map(|_| ())
        .map_err(|err| WfpCallError::InvalidInput(err.to_string()))
}

pub(crate) fn encode_utf16_nul(value: &str) -> Result<Vec<u16>, WfpCallError> {
    if value.contains('\0') {
        return Err(WfpCallError::InvalidInput(
            "WFP string contains interior NUL byte".to_string(),
        ));
    }
    let mut out: Vec<u16> = value.encode_utf16().collect();
    out.push(0);
    Ok(out)
}

fn with_principal_condition<R>(
    principal: &WfpPrincipalKey,
    use_condition: impl FnOnce(GUID, FWP_CONDITION_VALUE0) -> Result<R, WfpCallError>,
) -> Result<R, WfpCallError> {
    match principal {
        WfpPrincipalKey::AppContainerPackageSid { package_sid } => {
            let sid_guard = LocalAllocSid::parse(package_sid)?;
            let val = FWP_CONDITION_VALUE0 {
                r#type: FWP_SID,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sid: sid_guard.sid.cast::<SID>(),
                },
            };
            use_condition(FWPM_CONDITION_ALE_PACKAGE_ID, val)
        }
        WfpPrincipalKey::SandboxSid { sid } | WfpPrincipalKey::ServiceSid { service_sid: sid } => {
            let sd_guard = LocalAllocSd::for_user_match_sid(sid)?;
            let mut blob = FWP_BYTE_BLOB {
                size: sd_guard.size,
                data: sd_guard.ptr.cast::<u8>(),
            };
            let val = FWP_CONDITION_VALUE0 {
                r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sd: std::ptr::addr_of_mut!(blob),
                },
            };
            use_condition(FWPM_CONDITION_ALE_USER_ID, val)
        }
    }
}

pub(crate) fn install_single_filter(
    engine: HANDLE,
    rule: &WfpFilterRule,
    provider_guid: GUID,
    sublayer_guid: GUID,
) -> Result<u64, WfpCallError> {
    let mut name = encode_utf16_nul(&rule.rule_name)?;
    let mut desc = encode_utf16_nul("Guardrails session containment rule")?;
    let mut prov_key = provider_guid;
    let mut weight_val = rule.weight;

    let action_type = match rule.action {
        WfpFilterAction::HardBlock => FWP_ACTION_BLOCK,
        WfpFilterAction::AllowLoopbackProxyOnly => FWP_ACTION_PERMIT,
    };

    let (filter_id, rc) = with_principal_condition(
        &rule.principal,
        |principal_field_key, principal_val| {
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

            let condition_count = u32::try_from(conditions.len()).map_err(|_| {
                WfpCallError::InvalidInput(format!(
                    "WFP filter `{}` condition count {} exceeds u32",
                    rule.rule_name,
                    conditions.len()
                ))
            })?;

            let mut filter_id: u64 = 0;
            #[allow(
                unsafe_code,
                reason = "Install ALE WFP filter keyed on principal user security descriptor or package SID."
            )]
            // SAFETY: All pointers in FWPM_FILTER0, conditions, and with_principal_condition stack locals remain valid and unaliased across FwpmFilterAdd0.
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
                filter.numFilterConditions = condition_count;
                filter.filterCondition = conditions.as_mut_ptr();
                filter.action = FWPM_ACTION0 {
                    r#type: action_type,
                    Anonymous: std::mem::zeroed(),
                };
                FwpmFilterAdd0(engine, &filter, null_mut(), &mut filter_id)
            };
            Ok((filter_id, rc))
        },
    )?;

    if rc != 0 {
        return Err(WfpCallError::from_status("FwpmFilterAdd0", rc));
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

#[cfg(test)]
mod tests {
    use super::*;

    const fn guid_parts(g: GUID) -> (u32, u16, u16, [u8; 8]) {
        (g.data1, g.data2, g.data3, g.data4)
    }

    #[test]
    fn parses_valid_windows_sids_and_builds_principal_conditions() {
        for sid in [
            "S-1-5-18",
            "S-1-15-2-1001",
            "S-1-15-2-0-1-2-3-4-5-6",
            "S-1-15-2-1-2-3-4-5-6-7-8",
            "S-1-5-80-1234567890-1-2-3-4",
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15",
        ] {
            let parsed = LocalAllocSid::parse(sid).expect("valid SID must parse natively");
            assert!(!parsed.sid.is_null());
        }

        let sd = LocalAllocSd::for_user_match_sid("S-1-5-18")
            .expect("valid user SID must build match security descriptor");
        assert!(!sd.ptr.is_null());
        assert!(sd.size > 0);

        with_principal_condition(
            &WfpPrincipalKey::AppContainerPackageSid {
                package_sid: "S-1-15-2-1-2-3-4-5-6-7-8".into(),
            },
            |pkg_key, pkg_val| {
                assert_eq!(
                    guid_parts(pkg_key),
                    guid_parts(FWPM_CONDITION_ALE_PACKAGE_ID)
                );
                assert_eq!(pkg_val.r#type, FWP_SID);
                #[allow(unsafe_code, reason = "Verify package SID pointer non-null in test.")]
                // SAFETY: pkg_val.Anonymous.sid came from LocalAllocSid::parse within live scope.
                let sid_ptr = unsafe { pkg_val.Anonymous.sid };
                assert!(!sid_ptr.is_null());
                Ok(())
            },
        )
        .expect("AppContainer package SID condition must build");

        with_principal_condition(
            &WfpPrincipalKey::SandboxSid {
                sid: "S-1-5-21-1000-2000-3000-1001".into(),
            },
            |sbx_key, sbx_val| {
                assert_eq!(guid_parts(sbx_key), guid_parts(FWPM_CONDITION_ALE_USER_ID));
                assert_eq!(sbx_val.r#type, FWP_SECURITY_DESCRIPTOR_TYPE);
                #[allow(
                    unsafe_code,
                    reason = "Verify self-relative security descriptor blob inside live scope."
                )]
                // SAFETY: sbx_val.Anonymous.sd points to pinned stack FWP_BYTE_BLOB within closure scope.
                let blob = unsafe { &*sbx_val.Anonymous.sd };
                assert!(blob.size > 0);
                assert!(!blob.data.is_null());
                Ok(())
            },
        )
        .expect("Sandbox SID user condition must build");

        with_principal_condition(
            &WfpPrincipalKey::ServiceSid {
                service_sid: "S-1-5-80-1234567890-1-2-3-4".into(),
            },
            |svc_key, svc_val| {
                assert_eq!(guid_parts(svc_key), guid_parts(FWPM_CONDITION_ALE_USER_ID));
                assert_eq!(svc_val.r#type, FWP_SECURITY_DESCRIPTOR_TYPE);
                #[allow(
                    unsafe_code,
                    reason = "Verify service SID self-relative security descriptor blob inside live scope."
                )]
                // SAFETY: svc_val.Anonymous.sd points to pinned stack FWP_BYTE_BLOB within closure scope.
                let blob = unsafe { &*svc_val.Anonymous.sd };
                assert!(blob.size > 0);
                assert!(!blob.data.is_null());
                Ok(())
            },
        )
        .expect("Service SID user condition must build");
    }

    #[test]
    fn rejects_malformed_or_non_canonical_sids_fail_closed() {
        for bad in [
            "",
            "S-1-",
            "S-1--1001",
            "S-1-15-",
            "S-2-1-0",
            "O:LA",
            "S-1-15-2-1001;bad",
            "S-1-5",
            " S-1-5-18",
            "S-1-5-18 ",
            "\tS-1-5-18",
            "S-1-5-18\n",
            "S-1-5-18\0",
            "S-1-5-018",
            "S-1-05-18",
            "S-1-5-00",
            "S-1-15-02-1001",
            "S-1-281474976710656-1",
            "S-1-5-4294967296",
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
            "S-1-0-0",
            "S-1-1-0",
            "S-1-5-7",
            "S-1-5-11",
            "S-1-5-32-545",
        ] {
            assert!(
                validate_wfp_sid_str(bad).is_err(),
                "expected validate_wfp_sid_str `{bad}` to reject"
            );
            assert!(
                LocalAllocSid::parse(bad).is_err(),
                "expected SID `{bad}` to be rejected"
            );
            assert!(
                LocalAllocSd::for_user_match_sid(bad).is_err(),
                "expected SDDL match builder to reject `{bad}`"
            );
        }
    }
}
