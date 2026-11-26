// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::MacOsSensorError;
use crate::es_tree::ProcessTreeKey;
use crate::network_ext::{SlotBrokerState, SlotCapability, SlotProbeReport};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsProcessIdentity {
    pub key: ProcessTreeKey,
    pub parent_pid: u32,
    pub uid: u32,
    pub executable_path: String,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub adhoc_signed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacOsExtensionState {
    ActivatedEnabled,
    AwaitingApproval,
    Disabled,
    Uninstalled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsExtensionEntry {
    pub identifier: String,
    pub team_id: String,
    pub version: String,
    pub extension_state: MacOsExtensionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsLiveCapabilities {
    pub platform: &'static str,
    pub process_probe_available: bool,
    pub system_extensions: Vec<MacOsExtensionEntry>,
    pub network_services_scutil: Vec<String>,
    pub slot_reports: Vec<SlotProbeReport>,
    pub developer_program_held: bool,
}

#[derive(Debug, Clone)]
pub struct FseventsDirectoryWatch {
    roots: Vec<PathBuf>,
    last_mtimes: BTreeMap<PathBuf, SystemTime>,
}

impl FseventsDirectoryWatch {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            last_mtimes: BTreeMap::new(),
        }
    }

    pub fn poll_changed_paths(&mut self) -> Result<Vec<PathBuf>, MacOsSensorError> {
        let mut changed = Vec::new();
        for root in &self.roots {
            if !root.exists() {
                continue;
            }
            let Ok(entries) = fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                let Ok(mtime) = meta.modified() else {
                    continue;
                };
                let prev = self.last_mtimes.get(&path).copied();
                if prev != Some(mtime) {
                    self.last_mtimes.insert(path.clone(), mtime);
                    changed.push(path);
                }
            }
        }
        Ok(changed)
    }
}

pub fn inspect_macos_process(pid: u32) -> Result<Option<MacOsProcessIdentity>, MacOsSensorError> {
    #[cfg(target_os = "macos")]
    {
        crate::macos_sys::darwin_inspect_process(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        Ok(None)
    }
}

pub fn apply_seatbelt_profile(profile_sbpl: &str) -> Result<(), MacOsSensorError> {
    if !profile_sbpl.contains("(version 1)") {
        return Err(MacOsSensorError::Seatbelt(
            "Seatbelt SBPL profile must start with (version 1)".to_string(),
        ));
    }
    #[cfg(target_os = "macos")]
    {
        crate::macos_sys::darwin_apply_seatbelt_profile(profile_sbpl)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(MacOsSensorError::Seatbelt(
            "Seatbelt execution unavailable on non-macOS host".to_string(),
        ))
    }
}

pub fn parse_systemextensionsctl_output(raw: &str) -> Vec<MacOsExtensionEntry> {
    let mut entries = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("---") || trimmed.contains("extension(s)") {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(team_id) = tokens.get(2).copied() else {
            continue;
        };
        if team_id.eq_ignore_ascii_case("teamID") {
            continue;
        }
        let Some(ident_ver) = tokens.get(3).copied() else {
            continue;
        };
        let ident = ident_ver.to_string();
        let version = tokens
            .get(4)
            .map(|s| s.trim_matches(|c| c == '(' || c == ')').to_string())
            .unwrap_or_default();
        let rest_lower = trimmed.to_ascii_lowercase();
        let extension_state = if rest_lower.contains("[activated enabled]") {
            MacOsExtensionState::ActivatedEnabled
        } else if rest_lower.contains("waiting for user") || rest_lower.contains("awaiting") {
            MacOsExtensionState::AwaitingApproval
        } else if rest_lower.contains("terminated") || rest_lower.contains("uninstalled") {
            MacOsExtensionState::Uninstalled
        } else {
            MacOsExtensionState::Disabled
        };
        entries.push(MacOsExtensionEntry {
            identifier: ident,
            team_id: team_id.to_string(),
            version,
            extension_state,
        });
    }
    entries
}

pub fn parse_scutil_nc_list(raw: &str) -> Vec<String> {
    let mut active = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('*') {
            continue;
        }
        if let Some(start) = trimmed.find('"')
            && let Some(tail) = trimmed.get(start.saturating_add(1)..)
            && let Some(end) = tail.find('"')
            && let Some(name) = tail.get(..end)
            && !name.is_empty()
        {
            active.push(name.to_string());
        }
    }
    active
}

pub fn build_slot_broker_from_probes(
    developer_program_held: bool,
    extensions: &[MacOsExtensionEntry],
    vpn_dns_proxies: &[String],
) -> SlotBrokerState {
    let mut broker = SlotBrokerState::new();
    let incumbent_filter = extensions
        .iter()
        .find(|e| {
            e.extension_state == MacOsExtensionState::ActivatedEnabled
                && !e.identifier.starts_with("io.guardrails.")
        })
        .map(|e| e.identifier.as_str());
    broker.probe_content_filter(developer_program_held, incumbent_filter);

    let incumbent_dns = vpn_dns_proxies.first().map(String::as_str);
    broker.probe_exclusive_opt_in_slot(
        SlotCapability::DnsProxy,
        developer_program_held,
        incumbent_dns,
    );
    broker.probe_exclusive_opt_in_slot(
        SlotCapability::TransparentProxy,
        developer_program_held,
        incumbent_dns,
    );
    broker
}

pub fn probe_host_capabilities() -> MacOsLiveCapabilities {
    #[cfg(target_os = "macos")]
    {
        let ext_out = Command::new("/usr/bin/systemextensionsctl")
            .arg("list")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let scutil_out = Command::new("/usr/sbin/scutil")
            .args(["--nc", "list"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let extensions = parse_systemextensionsctl_output(&ext_out);
        let vpn_dns_proxies = parse_scutil_nc_list(&scutil_out);
        let dev_held = false;
        let broker = build_slot_broker_from_probes(dev_held, &extensions, &vpn_dns_proxies);
        let mut reports = Vec::new();
        for cap in [
            SlotCapability::ContentFilter,
            SlotCapability::DnsProxy,
            SlotCapability::TransparentProxy,
        ] {
            if let Some(r) = broker.get(cap) {
                reports.push(r.clone());
            }
        }
        MacOsLiveCapabilities {
            platform: "macos",
            process_probe_available: true,
            system_extensions: extensions,
            network_services_scutil: vpn_dns_proxies,
            slot_reports: reports,
            developer_program_held: dev_held,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let broker = build_slot_broker_from_probes(false, &[], &[]);
        let mut reports = Vec::new();
        for cap in [
            SlotCapability::ContentFilter,
            SlotCapability::DnsProxy,
            SlotCapability::TransparentProxy,
        ] {
            if let Some(r) = broker.get(cap) {
                reports.push(r.clone());
            }
        }
        MacOsLiveCapabilities {
            platform: std::env::consts::OS,
            process_probe_available: false,
            system_extensions: Vec::new(),
            network_services_scutil: Vec::new(),
            slot_reports: reports,
            developer_program_held: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ext::{FilterGrade, SlotRung};

    #[test]
    fn parses_systemextensionsctl_and_scutil_and_brokers_slots() {
        let sysext = r#"2 extension(s)
--- com.apple.system_extension.network_extension
enabled	active	TEAM123456	com.vendor.ztna.ne (1.2.3/45)	Vendor ZTNA	[activated enabled]
--- com.apple.system_extension.endpoint_security
enabled	waiting	TEAM999999	io.guardrails.es (0.1.0/1)	Guardrails ES	[activated waiting for user]
"#;
        let entries = parse_systemextensionsctl_output(sysext);
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries.first().map(|e| e.extension_state),
            Some(MacOsExtensionState::ActivatedEnabled)
        );
        assert_eq!(
            entries.get(1).map(|e| e.extension_state),
            Some(MacOsExtensionState::AwaitingApproval)
        );

        let scutil = r#"Available network connection services in the current set (*=enabled):
* (Connected)      12345678-1234-1234-1234-123456789012 VPN (com.vendor.vpn) "Corporate ZTNA VPN" [VPN:com.vendor.vpn]
  (Disconnected)   ABCDEFAB-1234-1234-1234-123456789012 VPN "Personal VPN" [IKEv2]
"#;
        let proxies = parse_scutil_nc_list(scutil);
        assert_eq!(proxies, vec!["Corporate ZTNA VPN".to_string()]);

        let broker = build_slot_broker_from_probes(true, &entries, &proxies);
        let cf = broker
            .get(SlotCapability::ContentFilter)
            .expect("cf report");
        assert_eq!(cf.rung, SlotRung::Enforce);
        assert_eq!(cf.filter_grade, Some(FilterGrade::Inspector));
        assert_eq!(cf.owner_description.as_deref(), Some("com.vendor.ztna.ne"));
        let dns = broker.get(SlotCapability::DnsProxy).expect("dns report");
        assert_eq!(dns.rung, SlotRung::None);
    }

    #[test]
    fn watches_directory_modifications_via_fsevents_fallback() {
        let dir = std::env::temp_dir().join(format!("grdr-fsevents-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create watch dir");
        let file = dir.join("sample.jsonl");
        std::fs::write(&file, b"line1\n").expect("write file");

        let mut watch = FseventsDirectoryWatch::new(vec![dir.clone()]);
        let initial = watch.poll_changed_paths().expect("first poll");
        assert_eq!(initial, vec![file]);

        let second = watch.poll_changed_paths().expect("second poll unchanged");
        assert!(second.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
