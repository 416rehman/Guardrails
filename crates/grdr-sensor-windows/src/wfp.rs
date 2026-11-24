// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::WindowsSensorError;

pub const WFP_PROVIDER_KEY: &str = "grdr.wfp.provider.v1";
pub const WFP_SUBLAYER_KEY: &str = "grdr.wfp.sublayer.v1";
pub const WFP_SUBLAYER_WEIGHT: u16 = 0x7000;
const WEIGHT_BLOCK_ALL: u64 = 100;
const WEIGHT_ALLOW_PROXY: u64 = 200;
const WEIGHT_BLOCK_CONSOLE_LOOPBACK: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WfpLayer {
    AleAuthConnectV4,
    AleAuthConnectV6,
    AleAuthRecvAcceptV4,
    AleAuthRecvAcceptV6,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WfpPrincipalKey {
    SandboxSid { sid: String },
    AppContainerPackageSid { package_sid: String },
    ServiceSid { service_sid: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WfpFilterAction {
    HardBlock,
    AllowLoopbackProxyOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WfpFilterRule {
    pub rule_name: String,
    pub layer: WfpLayer,
    pub principal: WfpPrincipalKey,
    pub action: WfpFilterAction,
    pub weight: u64,
    pub persistent: bool,
    pub remote_port: Option<u16>,
    pub loopback_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WfpSublayerPlan {
    pub provider_key: &'static str,
    pub sublayer_key: &'static str,
    pub sublayer_weight: u16,
    pub rules: Vec<WfpFilterRule>,
}

pub fn plan_session_wfp_filters(
    principal: WfpPrincipalKey,
    proxy_port: u16,
    console_port: Option<u16>,
) -> Result<WfpSublayerPlan, WindowsSensorError> {
    validate_principal(&principal)?;
    if proxy_port == 0 {
        return Err(WindowsSensorError::Wfp(
            "proxy_port cannot be 0 in session WFP plan".into(),
        ));
    }
    if let Some(c_port) = console_port
        && (c_port == 0 || c_port == proxy_port)
    {
        return Err(WindowsSensorError::Wfp(
            "console_port must be non-zero and distinct from proxy_port".into(),
        ));
    }

    let mut rules = Vec::new();
    for layer in [WfpLayer::AleAuthConnectV4, WfpLayer::AleAuthConnectV6] {
        rules.push(WfpFilterRule {
            rule_name: format!("session-egress-block-{layer:?}"),
            layer,
            principal: principal.clone(),
            action: WfpFilterAction::HardBlock,
            weight: WEIGHT_BLOCK_ALL,
            persistent: false,
            remote_port: None,
            loopback_only: false,
        });
        rules.push(WfpFilterRule {
            rule_name: format!("session-proxy-permit-{layer:?}"),
            layer,
            principal: principal.clone(),
            action: WfpFilterAction::AllowLoopbackProxyOnly,
            weight: WEIGHT_ALLOW_PROXY,
            persistent: false,
            remote_port: Some(proxy_port),
            loopback_only: true,
        });
        if let Some(c_port) = console_port {
            rules.push(WfpFilterRule {
                rule_name: format!("session-console-loopback-block-{layer:?}"),
                layer,
                principal: principal.clone(),
                action: WfpFilterAction::HardBlock,
                weight: WEIGHT_BLOCK_CONSOLE_LOOPBACK,
                persistent: false,
                remote_port: Some(c_port),
                loopback_only: true,
            });
        }
    }

    for recv_layer in [WfpLayer::AleAuthRecvAcceptV4, WfpLayer::AleAuthRecvAcceptV6] {
        rules.push(WfpFilterRule {
            rule_name: format!("session-loopback-recv-block-{recv_layer:?}"),
            layer: recv_layer,
            principal: principal.clone(),
            action: WfpFilterAction::HardBlock,
            weight: WEIGHT_BLOCK_CONSOLE_LOOPBACK,
            persistent: false,
            remote_port: None,
            loopback_only: true,
        });
    }

    Ok(WfpSublayerPlan {
        provider_key: WFP_PROVIDER_KEY,
        sublayer_key: WFP_SUBLAYER_KEY,
        sublayer_weight: WFP_SUBLAYER_WEIGHT,
        rules,
    })
}

pub fn plan_service_wfp_filters(
    service_sids: &[String],
) -> Result<WfpSublayerPlan, WindowsSensorError> {
    let mut rules = Vec::new();
    for sid in service_sids {
        let principal = WfpPrincipalKey::ServiceSid {
            service_sid: sid.clone(),
        };
        validate_principal(&principal)?;
        for layer in [WfpLayer::AleAuthConnectV4, WfpLayer::AleAuthConnectV6] {
            rules.push(WfpFilterRule {
                rule_name: format!("service-egress-block-{sid}"),
                layer,
                principal: principal.clone(),
                action: WfpFilterAction::HardBlock,
                weight: WEIGHT_BLOCK_ALL,
                persistent: true,
                remote_port: None,
                loopback_only: false,
            });
        }
    }
    Ok(WfpSublayerPlan {
        provider_key: WFP_PROVIDER_KEY,
        sublayer_key: WFP_SUBLAYER_KEY,
        sublayer_weight: WFP_SUBLAYER_WEIGHT,
        rules,
    })
}

pub fn validate_sid_syntax(raw_sid: &str) -> Result<(), WindowsSensorError> {
    grdr_os_service::validate_windows_sid(raw_sid)
        .map(|_| ())
        .map_err(|e| WindowsSensorError::Wfp(e.to_string()))
}

fn validate_principal(principal: &WfpPrincipalKey) -> Result<(), WindowsSensorError> {
    let sid = match principal {
        WfpPrincipalKey::SandboxSid { sid } => sid,
        WfpPrincipalKey::AppContainerPackageSid { package_sid } => package_sid,
        WfpPrincipalKey::ServiceSid { service_sid } => service_sid,
    };
    validate_sid_syntax(sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_wfp_plan_keys_on_sid_blocks_console_and_recv_and_permits_only_proxy() {
        let plan = plan_session_wfp_filters(
            WfpPrincipalKey::AppContainerPackageSid {
                package_sid: "S-1-15-2-1001".into(),
            },
            18080,
            Some(43199),
        )
        .unwrap();
        assert!(plan.rules.iter().all(|r| !r.persistent));
        assert!(
            plan.rules
                .iter()
                .any(|r| r.action == WfpFilterAction::AllowLoopbackProxyOnly
                    && r.remote_port == Some(18080)
                    && r.loopback_only)
        );
        assert!(
            plan.rules
                .iter()
                .any(|r| r.layer == WfpLayer::AleAuthRecvAcceptV4
                    && r.action == WfpFilterAction::HardBlock
                    && r.loopback_only)
        );
        assert!(
            plan.rules
                .iter()
                .any(|r| r.action == WfpFilterAction::HardBlock
                    && r.remote_port == Some(43199)
                    && r.weight > WEIGHT_ALLOW_PROXY)
        );
    }

    #[test]
    fn service_wfp_plan_rejects_malformed_sids_and_colliding_console_port() {
        assert!(plan_service_wfp_filters(&["".into()]).is_err());
        assert!(plan_service_wfp_filters(&["S-1-".into()]).is_err());
        assert!(plan_service_wfp_filters(&["S-1-5".into()]).is_err());
        assert!(
            plan_session_wfp_filters(
                WfpPrincipalKey::SandboxSid {
                    sid: "S-1-5-80-99".into()
                },
                18080,
                Some(18080),
            )
            .is_err()
        );
        let plan = plan_service_wfp_filters(&["S-1-5-80-99".into()]).unwrap();
        assert_eq!(plan.rules.len(), 2);
        assert!(plan.rules.iter().all(|r| r.persistent));
    }
}
