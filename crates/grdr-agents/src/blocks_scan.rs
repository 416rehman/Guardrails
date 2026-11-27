// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pass 2 building-block dependency scanner for candidate workspaces and process packages (`docs/design/05`).

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use grdr_core::discover::{AgenticIndicator, BuildingBlockRole, ScanBlockedReason};
use grdr_ports::{LocalFsPort, RegularEntryKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::catalogue::BuildingBlockCatalogue;

const MAX_PACKAGE_FILE_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedBuildingBlock {
    pub block_id: String,
    pub name: String,
    pub role: BuildingBlockRole,
    pub agentic: AgenticIndicator,
    pub matched_ecosystem: String,
    pub matched_package: String,
    pub source_manifest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildingBlockScanResult {
    pub detected: Vec<DetectedBuildingBlock>,
    pub blocked_reason: Option<ScanBlockedReason>,
}

pub fn scan_workspace_building_blocks(
    workspace: Option<&Path>,
    blocks: &BuildingBlockCatalogue,
    fs: &dyn LocalFsPort,
) -> BuildingBlockScanResult {
    let Some(ws_root) = workspace else {
        return BuildingBlockScanResult {
            detected: Vec::new(),
            blocked_reason: None,
        };
    };
    let started = Instant::now();
    let budget_ms = blocks.classifier.candidate_scan_budget_ms.max(1);
    let mut detected = Vec::new();
    let mut seen_ids = BTreeSet::new();

    let candidates = [
        ("npm", ws_root.join("package.json")),
        ("pypi", ws_root.join("pyproject.toml")),
        ("pypi", ws_root.join("requirements.txt")),
        ("cargo", ws_root.join("Cargo.toml")),
        ("cargo", ws_root.join("Cargo.lock")),
    ];

    for (eco, path) in candidates {
        if u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX) > budget_ms {
            return BuildingBlockScanResult {
                detected,
                blocked_reason: Some(ScanBlockedReason::BudgetExceeded),
            };
        }
        match fs.inspect_nofollow(&path) {
            Ok(RegularEntryKind::Missing) => continue,
            Ok(RegularEntryKind::File) => {}
            Ok(RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther) | Err(_) => {
                return BuildingBlockScanResult {
                    detected,
                    blocked_reason: Some(ScanBlockedReason::PermissionDenied),
                };
            }
        }
        let Ok(raw) = fs.read_bounded_regular_string(&path, MAX_PACKAGE_FILE_BYTES) else {
            return BuildingBlockScanResult {
                detected,
                blocked_reason: Some(ScanBlockedReason::PermissionDenied),
            };
        };
        let manifest_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("manifest")
            .to_owned();
        let pkg_tokens = extract_package_tokens(eco, &manifest_name, &raw);
        match_blocks_against_tokens(
            eco,
            &manifest_name,
            &pkg_tokens,
            blocks,
            &mut seen_ids,
            &mut detected,
        );
    }

    BuildingBlockScanResult {
        detected,
        blocked_reason: None,
    }
}

fn extract_package_tokens(eco: &str, file_name: &str, raw: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if eco == "npm" && file_name == "package.json" {
        if let Ok(Value::Object(root)) = serde_json::from_str::<Value>(raw) {
            for section in ["dependencies", "devDependencies", "peerDependencies"] {
                if let Some(Value::Object(map)) = root.get(section) {
                    for k in map.keys() {
                        out.insert(k.to_ascii_lowercase());
                    }
                }
            }
        }
        return out;
    }
    for line in raw.lines() {
        let cleaned = line.trim();
        if cleaned.is_empty() || cleaned.starts_with('#') || cleaned.starts_with('[') {
            continue;
        }
        let token = cleaned
            .split(['=', '<', '>', '!', '~', '[', ';', ' ', '"', '\''])
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !token.is_empty() {
            out.insert(token);
        }
        for part in cleaned.split(['"', '\'', ',', ' ', '=']) {
            let candidate = part.trim().to_ascii_lowercase();
            if !candidate.is_empty() {
                out.insert(candidate);
            }
        }
    }
    out
}

fn match_blocks_against_tokens(
    eco: &str,
    source_manifest: &str,
    tokens: &BTreeSet<String>,
    blocks: &BuildingBlockCatalogue,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<DetectedBuildingBlock>,
) {
    for block in blocks.blocks() {
        let pkg_list = match eco {
            "npm" => &block.ecosystems.npm,
            "pypi" => &block.ecosystems.pypi,
            "cargo" => &block.ecosystems.cargo,
            _ => continue,
        };
        for pkg in pkg_list {
            let pkg_lower = pkg.to_ascii_lowercase();
            if tokens.contains(&pkg_lower) && seen.insert(block.id.clone()) {
                out.push(DetectedBuildingBlock {
                    block_id: block.id.clone(),
                    name: block.name.clone(),
                    role: block.role,
                    agentic: block.agentic,
                    matched_ecosystem: eco.to_owned(),
                    matched_package: pkg.clone(),
                    source_manifest: source_manifest.to_owned(),
                });
                break;
            }
        }
    }
}
