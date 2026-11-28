// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pass 2 building-block dependency scanner with strict resource budgets (`docs/design/05`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use grdr_core::discover::{
    AgenticIndicator, BuildingBlockRole, ClassifierConfig, ScanBlockedReason,
};
use grdr_ports::{LocalFsPort, RegularEntryKind};
use serde::{Deserialize, Serialize};

use crate::blocks_env_scan::{
    extract_package_tokens, scan_resolved_dotnet_and_jvm, scan_resolved_node_modules,
    scan_resolved_python_envs,
};
use crate::catalogue::BuildingBlockCatalogue;

const MAX_PACKAGE_FILE_BYTES: u64 = 512 * 1024;
const MAX_BINARY_SCAN_BYTES: usize = 4 * 1024 * 1024;
const DOC05_MAX_SCAN_BUDGET_MS: u64 = 200;
const DOC05_MAX_FS_STATS: usize = 4_000;
const DOC05_MAX_MANIFESTS: usize = 2_000;
const DOC05_MAX_SCAN_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanBudget {
    pub max_ms: u64,
    pub max_stats: usize,
    pub max_manifests: usize,
    pub max_bytes: u64,
}

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
    pub stats_count: usize,
    pub manifests_read: usize,
    pub bytes_read: u64,
}

pub(crate) struct ScanLedger {
    started: Instant,
    budget: ScanBudget,
    stats_count: usize,
    manifests_read: usize,
    bytes_read: u64,
}

impl Default for ScanBudget {
    fn default() -> Self {
        Self {
            max_ms: DOC05_MAX_SCAN_BUDGET_MS,
            max_stats: DOC05_MAX_FS_STATS,
            max_manifests: DOC05_MAX_MANIFESTS,
            max_bytes: DOC05_MAX_SCAN_BYTES,
        }
    }
}

impl ScanBudget {
    #[must_use]
    pub fn from_classifier(cfg: &ClassifierConfig) -> Self {
        Self {
            max_ms: cfg.candidate_scan_budget_ms.max(1),
            ..Self::default()
        }
    }
}

impl ScanLedger {
    fn new(budget: ScanBudget) -> Self {
        Self {
            started: Instant::now(),
            budget,
            stats_count: 0,
            manifests_read: 0,
            bytes_read: 0,
        }
    }

    fn check_budget(&self) -> Result<(), ScanBlockedReason> {
        let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if elapsed_ms > self.budget.max_ms
            || self.stats_count >= self.budget.max_stats
            || self.manifests_read >= self.budget.max_manifests
            || self.bytes_read >= self.budget.max_bytes
        {
            return Err(ScanBlockedReason::BudgetExceeded);
        }
        Ok(())
    }

    pub(crate) fn inspect(
        &mut self,
        path: &Path,
        fs: &dyn LocalFsPort,
    ) -> Result<RegularEntryKind, ScanBlockedReason> {
        self.check_budget()?;
        self.stats_count = self.stats_count.saturating_add(1);
        fs.inspect_nofollow(path)
            .map_err(|_| ScanBlockedReason::PermissionDenied)
    }

    pub(crate) fn inspect_optional_dir(
        &mut self,
        path: &Path,
        fs: &dyn LocalFsPort,
    ) -> Result<bool, ScanBlockedReason> {
        match self.inspect(path, fs)? {
            RegularEntryKind::Dir => Ok(true),
            RegularEntryKind::Missing | RegularEntryKind::File => Ok(false),
            RegularEntryKind::UnsafeOrOther => Err(ScanBlockedReason::PermissionDenied),
        }
    }

    pub(crate) fn inspect_optional_file(
        &mut self,
        path: &Path,
        fs: &dyn LocalFsPort,
    ) -> Result<bool, ScanBlockedReason> {
        match self.inspect(path, fs)? {
            RegularEntryKind::File => Ok(true),
            RegularEntryKind::Missing | RegularEntryKind::Dir => Ok(false),
            RegularEntryKind::UnsafeOrOther => Err(ScanBlockedReason::PermissionDenied),
        }
    }

    pub(crate) fn read_dir_bounded(
        &mut self,
        dir: &Path,
        fs: &dyn LocalFsPort,
    ) -> Result<Vec<PathBuf>, ScanBlockedReason> {
        self.check_budget()?;
        self.stats_count = self.stats_count.saturating_add(1);
        let entries = fs
            .read_dir_entries(dir)
            .map_err(|_| ScanBlockedReason::PermissionDenied)?;
        let mut bounded = Vec::with_capacity(entries.len().min(256));
        for entry in entries {
            self.check_budget()?;
            self.stats_count = self.stats_count.saturating_add(1);
            bounded.push(entry);
        }
        Ok(bounded)
    }

    pub(crate) fn read_manifest(
        &mut self,
        path: &Path,
        fs: &dyn LocalFsPort,
    ) -> Result<String, ScanBlockedReason> {
        self.check_budget()?;
        let remaining = self.budget.max_bytes.saturating_sub(self.bytes_read);
        let cap = remaining.min(MAX_PACKAGE_FILE_BYTES);
        if cap == 0 {
            return Err(ScanBlockedReason::BudgetExceeded);
        }
        let raw = fs
            .read_bounded_regular_string(path, cap)
            .map_err(|_| ScanBlockedReason::PermissionDenied)?;
        self.manifests_read = self.manifests_read.saturating_add(1);
        self.bytes_read = self
            .bytes_read
            .saturating_add(u64::try_from(raw.len()).unwrap_or(u64::MAX));
        Ok(raw)
    }
}

pub fn scan_workspace_building_blocks(
    workspace: Option<&Path>,
    blocks: &BuildingBlockCatalogue,
    fs: &dyn LocalFsPort,
) -> BuildingBlockScanResult {
    scan_workspace_building_blocks_with_budget(
        workspace,
        blocks,
        ScanBudget::from_classifier(&blocks.classifier),
        fs,
    )
}

pub fn scan_workspace_building_blocks_with_budget(
    workspace: Option<&Path>,
    blocks: &BuildingBlockCatalogue,
    budget: ScanBudget,
    fs: &dyn LocalFsPort,
) -> BuildingBlockScanResult {
    let Some(ws_root) = workspace else {
        return BuildingBlockScanResult {
            detected: Vec::new(),
            blocked_reason: None,
            stats_count: 0,
            manifests_read: 0,
            bytes_read: 0,
        };
    };

    let mut ledger = ScanLedger::new(budget);
    let mut detected = Vec::new();
    let mut seen_ids = BTreeSet::new();

    let candidates = [
        ("npm", ws_root.join("package.json")),
        ("npm", ws_root.join("package-lock.json")),
        ("npm", ws_root.join("pnpm-lock.yaml")),
        ("pypi", ws_root.join("pyproject.toml")),
        ("pypi", ws_root.join("requirements.txt")),
        ("pypi", ws_root.join("pyvenv.cfg")),
        ("cargo", ws_root.join("Cargo.toml")),
        ("cargo", ws_root.join("Cargo.lock")),
        ("go", ws_root.join("go.mod")),
        ("go", ws_root.join("go.sum")),
        ("jvm", ws_root.join("pom.xml")),
        ("jvm", ws_root.join("build.gradle")),
        ("jvm", ws_root.join("build.gradle.kts")),
        ("jvm", ws_root.join("META-INF/MANIFEST.MF")),
    ];

    for (eco, path) in candidates {
        match ledger.inspect(&path, fs) {
            Ok(RegularEntryKind::Missing) => continue,
            Ok(RegularEntryKind::File) => {}
            Ok(RegularEntryKind::Dir | RegularEntryKind::UnsafeOrOther) => {
                return finish_blocked(&ledger, detected, ScanBlockedReason::PermissionDenied);
            }
            Err(reason) => return finish_blocked(&ledger, detected, reason),
        }
        let raw = match ledger.read_manifest(&path, fs) {
            Ok(raw) => raw,
            Err(reason) => return finish_blocked(&ledger, detected, reason),
        };
        let manifest_name = file_label(&path, "manifest");
        let tokens = extract_package_tokens(eco, &manifest_name, &raw);
        match_blocks_against_tokens(
            eco,
            &manifest_name,
            &tokens,
            blocks,
            &mut seen_ids,
            &mut detected,
        );
    }

    if let Err(reason) = scan_resolved_python_envs(
        ws_root,
        blocks,
        fs,
        &mut ledger,
        &mut seen_ids,
        &mut detected,
    )
    .and_then(|()| {
        scan_resolved_node_modules(
            ws_root,
            blocks,
            fs,
            &mut ledger,
            &mut seen_ids,
            &mut detected,
        )
    })
    .and_then(|()| {
        scan_resolved_dotnet_and_jvm(
            ws_root,
            blocks,
            fs,
            &mut ledger,
            &mut seen_ids,
            &mut detected,
        )
    }) {
        return finish_blocked(&ledger, detected, reason);
    }

    BuildingBlockScanResult {
        detected,
        blocked_reason: None,
        stats_count: ledger.stats_count,
        manifests_read: ledger.manifests_read,
        bytes_read: ledger.bytes_read,
    }
}

#[must_use]
pub fn scan_embedded_binary_markers(
    binary_bytes: &[u8],
    source_label: &str,
    blocks: &BuildingBlockCatalogue,
) -> Vec<DetectedBuildingBlock> {
    let bounded = binary_bytes
        .get(..binary_bytes.len().min(MAX_BINARY_SCAN_BYTES))
        .unwrap_or(binary_bytes);
    let mut detected = Vec::new();
    let mut seen = BTreeSet::new();
    for block in blocks.blocks() {
        for (eco, list) in [
            ("go", &block.ecosystems.go),
            ("cargo", &block.ecosystems.cargo),
            ("npm", &block.ecosystems.npm),
            ("pypi", &block.ecosystems.pypi),
            ("dotnet", &block.ecosystems.dotnet),
        ] {
            for pkg in list {
                let needle = pkg.as_bytes();
                if contains_ascii_ignore_case(bounded, needle) && seen.insert(block.id.clone()) {
                    detected.push(DetectedBuildingBlock {
                        block_id: block.id.clone(),
                        name: block.name.clone(),
                        role: block.role,
                        agentic: block.agentic,
                        matched_ecosystem: eco.to_owned(),
                        matched_package: pkg.clone(),
                        source_manifest: source_label.to_owned(),
                    });
                    break;
                }
            }
        }
    }
    detected
}

fn contains_ascii_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[must_use]
pub fn has_corroborated_mcp_sdk(
    detected: &[DetectedBuildingBlock],
    has_mcp_server_or_flow: bool,
) -> bool {
    has_mcp_server_or_flow
        && detected
            .iter()
            .any(|b| b.role == BuildingBlockRole::ProtocolBridge)
}

fn finish_blocked(
    ledger: &ScanLedger,
    detected: Vec<DetectedBuildingBlock>,
    reason: ScanBlockedReason,
) -> BuildingBlockScanResult {
    BuildingBlockScanResult {
        detected,
        blocked_reason: Some(reason),
        stats_count: ledger.stats_count,
        manifests_read: ledger.manifests_read,
        bytes_read: ledger.bytes_read,
    }
}

pub(crate) fn file_label(path: &Path, fallback: &str) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(fallback)
        .to_owned()
}

pub(crate) fn match_blocks_against_tokens(
    eco: &str,
    source_manifest: &str,
    tokens: &BTreeSet<String>,
    blocks: &BuildingBlockCatalogue,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<DetectedBuildingBlock>,
) {
    if eco == "jvm" {
        match_blocks_against_jvm(source_manifest, tokens, blocks, seen, out);
        return;
    }
    for block in blocks.blocks() {
        let pkg_list = match eco {
            "npm" => &block.ecosystems.npm,
            "pypi" => &block.ecosystems.pypi,
            "cargo" => &block.ecosystems.cargo,
            "go" => &block.ecosystems.go,
            "dotnet" => &block.ecosystems.dotnet,
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

pub(crate) fn match_blocks_against_jvm(
    source_manifest: &str,
    tokens: &BTreeSet<String>,
    blocks: &BuildingBlockCatalogue,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<DetectedBuildingBlock>,
) {
    for block in blocks.blocks() {
        for pkg in &block.ecosystems.jvm {
            let pkg_lower = pkg.to_ascii_lowercase();
            let artifact = pkg_lower
                .split_once(':')
                .map(|(_, a)| a.to_owned())
                .unwrap_or_else(|| pkg_lower.clone());
            let matched = tokens.contains(&pkg_lower)
                || tokens.contains(&artifact)
                || tokens
                    .iter()
                    .any(|t| t.starts_with(&format!("{artifact}-")));
            if matched && seen.insert(block.id.clone()) {
                out.push(DetectedBuildingBlock {
                    block_id: block.id.clone(),
                    name: block.name.clone(),
                    role: block.role,
                    agentic: block.agentic,
                    matched_ecosystem: "jvm".to_owned(),
                    matched_package: pkg.clone(),
                    source_manifest: source_manifest.to_owned(),
                });
                break;
            }
        }
    }
}
