// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use grdr_fastpath::{
    BinaryFloorTable, FastActionClass, FastVerdict, FloorRuleRef, PRINCIPAL_PROCESS,
    PRINCIPAL_SESSION, evaluate_floor_entries,
};

pub const QUIC_UDP_PORT: u16 = 443;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotCapability {
    ContentFilter,
    DnsProxy,
    TransparentProxy,
    EndpointSecurity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterGrade {
    Inspector,
    Firewall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotRung {
    Enforce,
    Observe,
    Ingest,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotProbeReport {
    pub capability: SlotCapability,
    pub rung: SlotRung,
    pub owner_description: Option<String>,
    pub filter_grade: Option<FilterGrade>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SlotBrokerState {
    slots: BTreeMap<SlotCapability, SlotProbeReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressDefaultPolicy {
    DefaultAllow,
    DefaultDeny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeFlowRecord {
    pub flow_id: u64,
    pub agent_name: String,
    pub governed_process: bool,
    pub transport: FlowTransport,
    pub remote_port: u16,
    pub host_name: Option<String>,
    pub tls_sni: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum NeFlowVerdict {
    Allow,
    AllowOpaqueWithFinding {
        reason: &'static str,
    },
    Drop {
        rule_id: String,
        reason: &'static str,
    },
}

use std::collections::BTreeMap;

impl SlotBrokerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn probe_content_filter(
        &mut self,
        developer_program_held: bool,
        incumbent_owner: Option<&str>,
    ) -> SlotProbeReport {
        let report = if !developer_program_held {
            SlotProbeReport {
                capability: SlotCapability::ContentFilter,
                rung: SlotRung::None,
                owner_description: None,
                filter_grade: None,
            }
        } else {
            // D-23: always run at Inspector grade so incumbent Firewall filters run first.
            SlotProbeReport {
                capability: SlotCapability::ContentFilter,
                rung: SlotRung::Enforce,
                owner_description: incumbent_owner.map(str::to_string),
                filter_grade: Some(FilterGrade::Inspector),
            }
        };
        self.slots
            .insert(SlotCapability::ContentFilter, report.clone());
        report
    }

    pub fn probe_exclusive_opt_in_slot(
        &mut self,
        capability: SlotCapability,
        opt_in_enabled: bool,
        slot_owner: Option<&str>,
    ) -> SlotProbeReport {
        let rung = if !opt_in_enabled || slot_owner.is_some() {
            SlotRung::None
        } else {
            SlotRung::Enforce
        };
        let report = SlotProbeReport {
            capability,
            rung,
            owner_description: slot_owner.map(str::to_string),
            filter_grade: None,
        };
        self.slots.insert(capability, report.clone());
        report
    }

    pub fn get(&self, capability: SlotCapability) -> Option<&SlotProbeReport> {
        self.slots.get(&capability)
    }
}

pub fn evaluate_ne_flow(
    flow: &NeFlowRecord,
    floor: &[FloorRuleRef<'_>],
    default_policy: EgressDefaultPolicy,
) -> NeFlowVerdict {
    evaluate_ne_flow_inner(flow, default_policy, |host| {
        evaluate_floor_entries(floor, FastActionClass::NetConnect, &flow.agent_name, host)
            .map(|h| (h.rule_id.to_string(), h.verdict))
    })
}

pub fn evaluate_ne_flow_table(
    flow: &NeFlowRecord,
    table: &BinaryFloorTable<'_>,
    default_policy: EgressDefaultPolicy,
) -> NeFlowVerdict {
    evaluate_ne_flow_inner(flow, default_policy, |host| {
        table
            .evaluate(
                FastActionClass::NetConnect,
                PRINCIPAL_SESSION | PRINCIPAL_PROCESS,
                0,
                &flow.agent_name,
                host,
            )
            .map(|h| (h.rule_id.to_string(), h.verdict))
    })
}

fn evaluate_ne_flow_inner<F>(
    flow: &NeFlowRecord,
    default_policy: EgressDefaultPolicy,
    eval_host: F,
) -> NeFlowVerdict
where
    F: Fn(&str) -> Option<(String, FastVerdict)>,
{
    if flow.governed_process
        && flow.transport == FlowTransport::Udp
        && flow.remote_port == QUIC_UDP_PORT
    {
        return NeFlowVerdict::Drop {
            rule_id: "macos.ne.drop_quic".into(),
            reason: "drop UDP/443 for governed processes so QUIC falls back to TCP",
        };
    }

    let host_opt = flow
        .host_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let sni_opt = flow
        .tls_sni
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // Evaluate SNI first when present so an IP literal host_name never shadows domain rules.
    let mut candidates: Vec<&str> = Vec::with_capacity(2);
    if let Some(sni) = sni_opt {
        candidates.push(sni);
    }
    if let Some(host) = host_opt
        && !candidates.contains(&host)
    {
        candidates.push(host);
    }

    for target in &candidates {
        if let Some((rule_id, verdict)) = eval_host(target)
            && verdict != FastVerdict::Allow
        {
            return NeFlowVerdict::Drop {
                rule_id,
                reason: "blocked by fastpath egress floor rule",
            };
        }
    }

    let has_domain_identity = sni_opt.is_some() || host_opt.is_some_and(|h| !is_ip_literal(h));
    if !has_domain_identity {
        return match default_policy {
            EgressDefaultPolicy::DefaultDeny => NeFlowVerdict::Drop {
                rule_id: "macos.ne.opaque_host_deny".into(),
                reason: "opaque flow denied under default-deny egress profile",
            },
            EgressDefaultPolicy::DefaultAllow => NeFlowVerdict::AllowOpaqueWithFinding {
                reason: "opaque-egress-host",
            },
        };
    }

    NeFlowVerdict::Allow
}

fn is_ip_literal(host: &str) -> bool {
    let bare = host
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host.trim());
    bare.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_broker_selects_inspector_grade_and_yields_occupied_exclusive_slots() {
        let mut broker = SlotBrokerState::new();
        let cf = broker.probe_content_filter(true, Some("CrowdStrike"));
        assert_eq!(cf.rung, SlotRung::Enforce);
        assert_eq!(cf.filter_grade, Some(FilterGrade::Inspector));

        let dns = broker.probe_exclusive_opt_in_slot(
            SlotCapability::DnsProxy,
            true,
            Some("Tailscale DNS"),
        );
        assert_eq!(dns.rung, SlotRung::None);
    }

    #[test]
    fn ne_flow_drops_quic_prefers_sni_over_ip_and_flags_bare_ip_as_opaque() {
        let quic = NeFlowRecord {
            flow_id: 1,
            agent_name: "claude-code".into(),
            governed_process: true,
            transport: FlowTransport::Udp,
            remote_port: 443,
            host_name: Some("api.anthropic.com".into()),
            tls_sni: None,
        };
        assert!(matches!(
            evaluate_ne_flow(&quic, &[], EgressDefaultPolicy::DefaultAllow),
            NeFlowVerdict::Drop { .. }
        ));

        let ip_with_sni = NeFlowRecord {
            transport: FlowTransport::Tcp,
            host_name: Some("198.51.100.7".into()),
            tls_sni: Some("blocked.example".into()),
            ..quic.clone()
        };
        let rules = [FloorRuleRef {
            rule_id: "egress.deny",
            action_mask: FastActionClass::NetConnect.bit(),
            prefixes: &[],
            contains: &["blocked.example"],
            agents: &[],
            verdict: FastVerdict::Deny,
        }];
        assert!(matches!(
            evaluate_ne_flow(&ip_with_sni, &rules, EgressDefaultPolicy::DefaultAllow),
            NeFlowVerdict::Drop { rule_id, .. } if rule_id == "egress.deny"
        ));

        let bare_ip = NeFlowRecord {
            transport: FlowTransport::Tcp,
            host_name: Some("198.51.100.7".into()),
            tls_sni: None,
            ..quic.clone()
        };
        assert!(matches!(
            evaluate_ne_flow(&bare_ip, &[], EgressDefaultPolicy::DefaultDeny),
            NeFlowVerdict::Drop { rule_id, .. } if rule_id == "macos.ne.opaque_host_deny"
        ));
        assert!(matches!(
            evaluate_ne_flow(&bare_ip, &[], EgressDefaultPolicy::DefaultAllow),
            NeFlowVerdict::AllowOpaqueWithFinding { .. }
        ));
    }
}
