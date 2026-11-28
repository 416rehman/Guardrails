// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::MacOsSensorError;
use crate::brand::{MacOsBrandConfig, is_valid_apple_team_id};
use crate::es_clients::EsClientSetState;
use crate::es_tree::{EsClientStatus, ProcessTreeKey};
#[cfg(target_os = "macos")]
use crate::macos_fsevents::DarwinFseventsStream;
use crate::network_ext::{SlotBrokerState, SlotCapability, SlotProbeReport};

const MAX_PARSED_ARGV_COUNT: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsProcessIdentity {
    pub key: ProcessTreeKey,
    pub parent_pid: u32,
    pub uid: u32,
    pub executable_path: String,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub cdhash: Option<String>,
    pub argv: Vec<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeveloperSigningStatus {
    VerifiedWithEntitlements,
    SignedMissingTeamOrEntitlement,
    UnsignedOrAdhoc,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FseventsBackendKind {
    CoreServicesStream,
    StatFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsExtensionEntry {
    pub identifier: String,
    pub team_id: String,
    pub version: String,
    pub extension_state: MacOsExtensionState,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacOsExternalProbeInputs {
    pub system_extensions: Vec<MacOsExtensionEntry>,
    pub vpn_dns_proxies: Vec<String>,
    pub live_es_state: Option<EsClientSetState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsLiveCapabilities {
    pub platform: &'static str,
    pub process_probe_available: bool,
    pub system_extensions: Vec<MacOsExtensionEntry>,
    pub network_services_scutil: Vec<String>,
    pub slot_reports: Vec<SlotProbeReport>,
    pub developer_program_held: bool,
    pub developer_signing_status: DeveloperSigningStatus,
    pub es_status: EsClientStatus,
}

#[derive(Debug)]
pub struct FseventsDirectoryWatch {
    roots: Vec<PathBuf>,
    last_mtimes: BTreeMap<PathBuf, SystemTime>,
    #[cfg(target_os = "macos")]
    darwin_stream: Option<DarwinFseventsStream>,
    seeded_roots: BTreeMap<PathBuf, bool>,
}

impl FseventsDirectoryWatch {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        #[cfg(target_os = "macos")]
        let darwin_stream = DarwinFseventsStream::start(&roots);
        Self {
            roots,
            last_mtimes: BTreeMap::new(),
            #[cfg(target_os = "macos")]
            darwin_stream,
            seeded_roots: BTreeMap::new(),
        }
    }

    pub fn backend_kind(&self) -> FseventsBackendKind {
        #[cfg(target_os = "macos")]
        if self.darwin_stream.is_some() {
            return FseventsBackendKind::CoreServicesStream;
        }
        FseventsBackendKind::StatFallback
    }

    pub fn poll_changed_paths(&mut self) -> Result<Vec<PathBuf>, MacOsSensorError> {
        #[cfg(target_os = "macos")]
        if let Some(stream) = &self.darwin_stream {
            let mut changed = Vec::new();
            for root in &self.roots {
                if !root.exists() || self.seeded_roots.get(root).copied().unwrap_or(false) {
                    continue;
                }
                self.seeded_roots.insert(root.clone(), true);
                for existing in scan_existing_files(root) {
                    if !changed.contains(&existing) {
                        changed.push(existing);
                    }
                }
            }
            for live_path in stream.drain_paths() {
                if !changed.contains(&live_path) {
                    changed.push(live_path);
                }
            }
            return Ok(changed);
        }

        let _ = &self.seeded_roots;
        let mut changed = Vec::new();
        for root in &self.roots {
            if !root.exists() {
                continue;
            }
            collect_stat_changes(root, &mut self.last_mtimes, &mut changed);
        }
        Ok(changed)
    }
}

fn collect_stat_changes(
    dir: &Path,
    last_mtimes: &mut BTreeMap<PathBuf, SystemTime>,
    changed: &mut Vec<PathBuf>,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.file_type().is_dir() {
            collect_stat_changes(&path, last_mtimes, changed);
            continue;
        }
        let Ok(mtime) = meta.modified() else {
            continue;
        };
        let prev = last_mtimes.get(&path).copied();
        if prev != Some(mtime) {
            last_mtimes.insert(path.clone(), mtime);
            changed.push(path);
        }
    }
}

#[cfg(target_os = "macos")]
fn scan_existing_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.metadata().is_ok_and(|m| m.file_type().is_dir()) {
            found.extend(scan_existing_files(&path));
        } else {
            found.push(path);
        }
    }
    found
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

pub fn enumerate_macos_processes() -> Result<Vec<MacOsProcessIdentity>, MacOsSensorError> {
    #[cfg(target_os = "macos")]
    {
        let pids = crate::macos_sys::darwin_list_pids()?;
        let mut out = Vec::new();
        for pid in pids {
            if let Ok(Some(identity)) = crate::macos_sys::darwin_inspect_process(pid) {
                out.push(identity);
            }
        }
        Ok(out)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(Vec::new())
    }
}

pub fn probe_self_signing_team_and_es_entitlement() -> (DeveloperSigningStatus, Option<String>, bool)
{
    #[cfg(target_os = "macos")]
    {
        crate::macos_seccode::darwin_probe_self_signing()
    }
    #[cfg(not(target_os = "macos"))]
    {
        (DeveloperSigningStatus::Unavailable, None, false)
    }
}

pub fn evaluate_developer_signing_status(
    team_id: Option<&str>,
    adhoc_signed: bool,
    has_extension_entitlement: bool,
    has_provisioning_profile: bool,
) -> DeveloperSigningStatus {
    if adhoc_signed {
        return DeveloperSigningStatus::UnsignedOrAdhoc;
    }
    let valid_team = team_id.is_some_and(is_valid_apple_team_id);
    if valid_team && (has_extension_entitlement || has_provisioning_profile) {
        DeveloperSigningStatus::VerifiedWithEntitlements
    } else if valid_team {
        DeveloperSigningStatus::SignedMissingTeamOrEntitlement
    } else {
        DeveloperSigningStatus::UnsignedOrAdhoc
    }
}

pub fn parse_kern_procargs2(buf: &[u8]) -> Vec<String> {
    let Some((argc_bytes, rest)) = buf.split_at_checked(4) else {
        return Vec::new();
    };
    let Ok(argc_arr): Result<[u8; 4], _> = argc_bytes.try_into() else {
        return Vec::new();
    };
    let argc = i32::from_ne_bytes(argc_arr);
    let Ok(argc_usize) = usize::try_from(argc) else {
        return Vec::new();
    };
    if argc_usize == 0 {
        return Vec::new();
    }
    let mut cursor = rest;
    let Some(exec_end) = cursor.iter().position(|&b| b == 0) else {
        return Vec::new();
    };
    cursor = cursor.get(exec_end.saturating_add(1)..).unwrap_or_default();
    while cursor.first() == Some(&0) {
        cursor = cursor.get(1..).unwrap_or_default();
    }
    let limit = argc_usize.min(MAX_PARSED_ARGV_COUNT);
    let mut args = Vec::with_capacity(limit);
    for _ in 0..limit {
        if cursor.is_empty() {
            break;
        }
        let end = cursor.iter().position(|&b| b == 0).unwrap_or(cursor.len());
        let arg_bytes = cursor.get(..end).unwrap_or_default();
        args.push(String::from_utf8_lossy(arg_bytes).into_owned());
        if end >= cursor.len() {
            break;
        }
        cursor = cursor.get(end.saturating_add(1)..).unwrap_or_default();
    }
    args
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

pub fn build_slot_broker_from_probes_with_brand(
    developer_program_held: bool,
    extensions: &[MacOsExtensionEntry],
    vpn_dns_proxies: &[String],
    brand: &MacOsBrandConfig,
) -> SlotBrokerState {
    let mut broker = SlotBrokerState::new();
    let incumbent_filter = extensions
        .iter()
        .find(|e| {
            e.extension_state == MacOsExtensionState::ActivatedEnabled
                && !brand.is_own_extension_identifier(&e.identifier)
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

pub fn resolve_developer_program_held(
    signing_status: DeveloperSigningStatus,
    extensions: &[MacOsExtensionEntry],
    brand: &MacOsBrandConfig,
) -> (bool, DeveloperSigningStatus) {
    if signing_status == DeveloperSigningStatus::VerifiedWithEntitlements {
        return (true, signing_status);
    }
    let active_own_sysext = extensions.iter().any(|ext| {
        brand.is_own_extension_identifier(&ext.identifier)
            && ext.extension_state == MacOsExtensionState::ActivatedEnabled
            && is_valid_apple_team_id(&ext.team_id)
    });
    if active_own_sysext {
        return (true, DeveloperSigningStatus::VerifiedWithEntitlements);
    }
    (false, signing_status)
}

pub fn evaluate_host_capabilities(
    inputs: &MacOsExternalProbeInputs,
) -> Result<MacOsLiveCapabilities, MacOsSensorError> {
    let brand = MacOsBrandConfig::try_embedded()?;
    let (raw_signing, _team, es_entitled) = probe_self_signing_team_and_es_entitlement();
    let (dev_held, signing_status) =
        resolve_developer_program_held(raw_signing, &inputs.system_extensions, brand);
    let broker = build_slot_broker_from_probes_with_brand(
        dev_held,
        &inputs.system_extensions,
        &inputs.vpn_dns_proxies,
        brand,
    );
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

    let es_status = if let Some(live) = &inputs.live_es_state {
        live.rollup_status()
    } else if inputs.system_extensions.iter().any(|e| {
        e.identifier == brand.macos_esext_bundle_id
            && e.extension_state == MacOsExtensionState::ActivatedEnabled
    }) {
        EsClientStatus::Active
    } else if inputs.system_extensions.iter().any(|e| {
        e.identifier == brand.macos_esext_bundle_id
            && e.extension_state == MacOsExtensionState::AwaitingApproval
    }) {
        EsClientStatus::NotPermittedFda
    } else if es_entitled {
        EsClientStatus::Active
    } else {
        EsClientStatus::MissingEntitlement
    };

    Ok(MacOsLiveCapabilities {
        platform: std::env::consts::OS,
        process_probe_available: cfg!(target_os = "macos"),
        system_extensions: inputs.system_extensions.clone(),
        network_services_scutil: inputs.vpn_dns_proxies.clone(),
        slot_reports: reports,
        developer_program_held: dev_held,
        developer_signing_status: signing_status,
        es_status,
    })
}

pub fn probe_local_capabilities(
    live_es_state: Option<&EsClientSetState>,
) -> Result<MacOsLiveCapabilities, MacOsSensorError> {
    evaluate_host_capabilities(&MacOsExternalProbeInputs {
        system_extensions: Vec::new(),
        vpn_dns_proxies: Vec::new(),
        live_es_state: live_es_state.cloned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::es_clients::all_client_concerns;
    use crate::network_ext::{FilterGrade, SlotRung};

    #[test]
    fn evaluates_typed_probe_inputs_brand_alignment_and_es_status() {
        let brand = MacOsBrandConfig::try_embedded().expect("brand");
        let entries = vec![
            MacOsExtensionEntry {
                identifier: brand.macos_netext_bundle_id.clone(),
                team_id: "TEAM123456".into(),
                version: "0.1.0".into(),
                extension_state: MacOsExtensionState::ActivatedEnabled,
            },
            MacOsExtensionEntry {
                identifier: "com.vendor.ztna.ne".into(),
                team_id: "TEAM789012".into(),
                version: "1.2.3".into(),
                extension_state: MacOsExtensionState::ActivatedEnabled,
            },
            MacOsExtensionEntry {
                identifier: brand.macos_esext_bundle_id.clone(),
                team_id: "TEAM123456".into(),
                version: "0.1.0".into(),
                extension_state: MacOsExtensionState::AwaitingApproval,
            },
        ];

        let mut live_es = EsClientSetState::default();
        for c in all_client_concerns() {
            live_es.set_status(c, EsClientStatus::Active);
        }
        let caps_live = evaluate_host_capabilities(&MacOsExternalProbeInputs {
            system_extensions: entries.clone(),
            vpn_dns_proxies: vec!["Corporate ZTNA VPN".into()],
            live_es_state: Some(live_es),
        })
        .expect("eval caps");
        assert!(caps_live.developer_program_held);
        assert_eq!(caps_live.es_status, EsClientStatus::Active);
        let cf = caps_live
            .slot_reports
            .iter()
            .find(|r| r.capability == SlotCapability::ContentFilter)
            .expect("cf");
        assert_eq!(cf.rung, SlotRung::Enforce);
        assert_eq!(cf.filter_grade, Some(FilterGrade::Inspector));
        assert_eq!(cf.owner_description.as_deref(), Some("com.vendor.ztna.ne"));
        let dns = caps_live
            .slot_reports
            .iter()
            .find(|r| r.capability == SlotCapability::DnsProxy)
            .expect("dns");
        assert_eq!(dns.rung, SlotRung::None);

        let caps_awaiting = evaluate_host_capabilities(&MacOsExternalProbeInputs {
            system_extensions: entries,
            vpn_dns_proxies: vec![],
            live_es_state: None,
        })
        .expect("awaiting");
        assert_eq!(caps_awaiting.es_status, EsClientStatus::NotPermittedFda);

        let (dev_held, resolved_status) = resolve_developer_program_held(
            DeveloperSigningStatus::Unavailable,
            &[MacOsExtensionEntry {
                identifier: brand.macos_netext_bundle_id.clone(),
                team_id: "TEAM123456".into(),
                version: "0.1.0".into(),
                extension_state: MacOsExtensionState::ActivatedEnabled,
            }],
            brand,
        );
        assert!(dev_held);
        assert_eq!(
            resolved_status,
            DeveloperSigningStatus::VerifiedWithEntitlements
        );
    }

    #[test]
    fn parses_kern_procargs2_layout() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&3i32.to_ne_bytes());
        raw.extend_from_slice(b"/usr/local/bin/agent\0\0\0");
        raw.extend_from_slice(b"agent\0--model\0test-1\0PWD=/tmp\0");
        let parsed = parse_kern_procargs2(&raw);
        assert_eq!(parsed, vec!["agent", "--model", "test-1"]);
        assert!(parse_kern_procargs2(&[1, 2]).is_empty());
    }

    #[test]
    fn watches_existing_and_later_created_directories() {
        let dir = std::env::temp_dir().join(format!("grdr-fsevents-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let delayed = dir.join(".claude");
        let mut watch = FseventsDirectoryWatch::new(vec![delayed.clone()]);
        assert!(
            watch
                .poll_changed_paths()
                .expect("before create")
                .is_empty()
        );

        std::fs::create_dir_all(&delayed).expect("create delayed watch dir");
        let file = delayed.join("settings.json");
        std::fs::write(&file, b"{}\n").expect("write file");
        let initial = watch.poll_changed_paths().expect("after create poll");
        assert_eq!(initial, vec![file]);

        let second = watch.poll_changed_paths().expect("second poll unchanged");
        assert!(second.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
