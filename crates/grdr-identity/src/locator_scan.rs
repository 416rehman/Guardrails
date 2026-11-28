// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::IdentityError;
use crate::broker_types::ContainmentStatus;
use crate::locator::{
    ArtifactScanContext, CredentialLocationFinding, CredentialLocatorPack, HygieneSignal,
};

const MAX_SCAN_DEPTH: usize = 6;
const MAX_SCAN_FILES: usize = 2_048;
const MAX_SCAN_QUEUE: usize = 4_096;
const MAX_READ_BYTES: usize = 256 * 1024;
const K8S_SA_TOKEN_SUFFIX: &str = "secrets/kubernetes.io/serviceaccount/token";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsPermissionSnapshot {
    pub path: String,
    pub unix_mode: Option<u32>,
    pub human_principal: Option<String>,
    pub agent_lineages: Vec<String>,
    pub world_or_group_readable: bool,
    pub acl_shared_with_human: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub roots_scanned: usize,
    pub files_inspected: usize,
    pub findings: Vec<CredentialLocationFinding>,
}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub containment: Option<ContainmentStatus>,
    pub extra_signals: BTreeSet<HygieneSignal>,
}

#[must_use]
pub fn evaluate_readable_by_oracle(
    snapshot: &OsPermissionSnapshot,
) -> (Vec<String>, BTreeSet<HygieneSignal>) {
    let mut readable_by = Vec::new();
    let mut signals = BTreeSet::new();
    let mode_world_or_group = snapshot.unix_mode.is_some_and(|mode| (mode & 0o044) != 0);

    if snapshot.world_or_group_readable || mode_world_or_group {
        for lineage in &snapshot.agent_lineages {
            readable_by.push(lineage.clone());
        }
        if snapshot.human_principal.is_some() && !snapshot.agent_lineages.is_empty() {
            signals.insert(HygieneSignal::SharedWithHuman);
        }
    } else if !snapshot.agent_lineages.is_empty() {
        for lineage in &snapshot.agent_lineages {
            readable_by.push(lineage.clone());
        }
        if snapshot.acl_shared_with_human && snapshot.human_principal.is_some() {
            signals.insert(HygieneSignal::SharedWithHuman);
        }
    }

    let norm_path = snapshot.path.replace('\\', "/");
    if norm_path.ends_with(K8S_SA_TOKEN_SUFFIX) {
        signals.insert(HygieneSignal::K8sAutomountSaToken);
    }
    (readable_by, signals)
}

pub fn scan_roots_for_credentials(
    pack: &CredentialLocatorPack,
    hmac_key: &[u8],
    roots: &[&Path],
    permissions_by_path: &[OsPermissionSnapshot],
    opts: &ScanOptions,
) -> Result<ScanReport, IdentityError> {
    let mut findings = Vec::new();
    let mut files_inspected: usize = 0;

    for root in roots {
        if !root.exists() {
            continue;
        }
        let mut queue: Vec<(PathBuf, usize)> = vec![((*root).to_path_buf(), 0)];
        while let Some((path, depth)) = queue.pop() {
            if files_inspected >= MAX_SCAN_FILES {
                break;
            }
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if is_reparse_or_symlink(&meta) {
                continue;
            }
            if meta.is_dir() {
                if depth >= MAX_SCAN_DEPTH {
                    continue;
                }
                let Ok(entries) = fs::read_dir(&path) else {
                    continue;
                };
                for entry in entries.flatten() {
                    if queue.len() >= MAX_SCAN_QUEUE {
                        break;
                    }
                    queue.push((entry.path(), depth.saturating_add(1)));
                }
                continue;
            }
            if !meta.is_file() || meta.len() > u64::try_from(MAX_READ_BYTES).unwrap_or(u64::MAX) {
                continue;
            }
            files_inspected = files_inspected.saturating_add(1);
            let Some(raw_bytes) = read_zeroized_prefix(&path) else {
                continue;
            };
            let content = Zeroizing::new(String::from_utf8_lossy(&raw_bytes).into_owned());
            let norm_path = path.to_string_lossy().replace('\\', "/");
            let mut ctx = build_artifact_context(&norm_path, &meta, permissions_by_path, opts);
            if content.contains("sk-ant-oat01") || content.contains("setupToken") {
                ctx.signals.insert(HygieneSignal::LongLivedSetupToken);
            }
            if let Some(finding) = pack.scan_artifact(hmac_key, &content, &ctx)? {
                findings.push(finding);
            }
        }
    }

    Ok(ScanReport {
        roots_scanned: roots.len(),
        files_inspected,
        findings,
    })
}

fn build_artifact_context(
    norm_path: &str,
    meta: &fs::Metadata,
    permissions_by_path: &[OsPermissionSnapshot],
    opts: &ScanOptions,
) -> ArtifactScanContext {
    let mut ctx = ArtifactScanContext {
        artifact_path: norm_path.to_owned(),
        readable_by_agent_lineages: Vec::new(),
        containment: opts.containment.unwrap_or(ContainmentStatus::Contained),
        signals: opts.extra_signals.clone(),
    };

    if let Some(snap) = permissions_by_path
        .iter()
        .find(|p| p.path.replace('\\', "/") == norm_path)
    {
        let (lineages, oracle_signals) = evaluate_readable_by_oracle(snap);
        ctx.readable_by_agent_lineages = lineages;
        ctx.signals.extend(oracle_signals);
    } else if norm_path.ends_with(K8S_SA_TOKEN_SUFFIX) {
        ctx.signals.insert(HygieneSignal::K8sAutomountSaToken);
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if (mode & 0o044) != 0 {
                ctx.readable_by_agent_lineages
                    .push("local-user-group".into());
            }
        }
        #[cfg(not(unix))]
        let _ = meta;
    }

    ctx
}

fn is_reparse_or_symlink(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

fn read_zeroized_prefix(path: &Path) -> Option<Zeroizing<Vec<u8>>> {
    let meta = fs::symlink_metadata(path).ok()?;
    if is_reparse_or_symlink(&meta) || !meta.is_file() {
        return None;
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = opts.open(path).ok()?;
    let opened_meta = file.metadata().ok()?;
    if is_reparse_or_symlink(&opened_meta) || !opened_meta.is_file() {
        return None;
    }
    let mut buf = Zeroizing::new(Vec::new());
    let mut reader = file.take(u64::try_from(MAX_READ_BYTES).unwrap_or(u64::MAX));
    reader.read_to_end(&mut buf).ok()?;
    Some(buf)
}
