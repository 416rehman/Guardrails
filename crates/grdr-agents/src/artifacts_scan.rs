// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Symlink-safe filesystem walker and bounded Merkle tree hashing for agent artifacts.

use std::path::{Path, PathBuf};

use grdr_crypto::{Sha256Hasher, encode_lower_hex};
use jiff::Timestamp;

use grdr_model::{ArtifactEntry, ArtifactKind, ArtifactRiskFlag, ArtifactScope, slugify_id};
use grdr_ports::{LocalFsPort, RegularEntryKind, validate_safe_rel_path};

use crate::parse::display_path;

const MAX_ARTIFACT_BYTES: u64 = 10 * 1024 * 1024;
const MAX_ARTIFACT_FILES: usize = 2000;
const SCRIPT_EXTENSIONS: &[&str] = &["sh", "ps1", "py", "js", "mjs", "bat", "cmd"];
const BROAD_TOOL_PATTERNS: &[&str] = &[
    "bash(*)",
    "allowed-tools: *",
    "allowed_tools: *",
    "dangerously-skip-permissions",
    "bypasspermissions",
    "tools: *",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteScanMode {
    SkillDirs,
    MarkdownFiles,
    CursorRuleFiles,
    SingleFile,
    PluginDirs,
}

pub(crate) struct ArtifactRouteSpec {
    pub(crate) relative_path: String,
    pub(crate) kind: ArtifactKind,
    pub(crate) scope: ArtifactScope,
    pub(crate) source_agent: String,
    pub(crate) mode: RouteScanMode,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_route_set(
    base_root: &Path,
    routes: &[ArtifactRouteSpec],
    device_name: &str,
    now: Timestamp,
    fs: &dyn LocalFsPort,
    scanned_paths: &mut Vec<String>,
    warnings: &mut Vec<String>,
    out: &mut Vec<ArtifactEntry>,
) {
    for spec in routes {
        if validate_safe_rel_path(&spec.relative_path, false, false, false).is_err() {
            warnings.push(format!(
                "Skipped unsafe artifact route `{}`.",
                spec.relative_path
            ));
            continue;
        }
        let target = base_root.join(&spec.relative_path);
        scanned_paths.push(display_path(&target));
        match spec.mode {
            RouteScanMode::SingleFile => {
                if fs.is_regular_file_nofollow(&target) {
                    let name = target
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("rule")
                        .to_string();
                    if let Some(entry) = build_artifact_entry(
                        spec,
                        &name,
                        &target,
                        std::slice::from_ref(&target),
                        device_name,
                        now,
                        fs,
                        warnings,
                    ) {
                        out.push(entry);
                    }
                }
            }
            RouteScanMode::SkillDirs | RouteScanMode::PluginDirs => {
                scan_dir_children(spec, &target, device_name, now, fs, warnings, out);
            }
            RouteScanMode::MarkdownFiles | RouteScanMode::CursorRuleFiles => {
                scan_markdown_children(spec, &target, device_name, now, fs, warnings, out);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_dir_children(
    spec: &ArtifactRouteSpec,
    target: &Path,
    device_name: &str,
    now: Timestamp,
    fs: &dyn LocalFsPort,
    warnings: &mut Vec<String>,
    out: &mut Vec<ArtifactEntry>,
) {
    if !fs.is_regular_dir_nofollow(target) {
        return;
    }
    let Ok(children) = fs.read_dir_entries(target) else {
        return;
    };
    for child_path in children {
        if !fs.is_regular_dir_nofollow(&child_path) {
            continue;
        }
        let dir_name = child_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("artifact")
            .to_string();
        if spec.mode == RouteScanMode::SkillDirs
            && !fs.is_regular_file_nofollow(&child_path.join("SKILL.md"))
        {
            continue;
        }
        let mut files = Vec::new();
        collect_files_sorted(&child_path, fs, &mut files);
        if files.is_empty() {
            continue;
        }
        if let Some(entry) = build_artifact_entry(
            spec,
            &dir_name,
            &child_path,
            &files,
            device_name,
            now,
            fs,
            warnings,
        ) {
            out.push(entry);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_markdown_children(
    spec: &ArtifactRouteSpec,
    target: &Path,
    device_name: &str,
    now: Timestamp,
    fs: &dyn LocalFsPort,
    warnings: &mut Vec<String>,
    out: &mut Vec<ArtifactEntry>,
) {
    if !fs.is_regular_dir_nofollow(target) {
        return;
    }
    let Ok(children) = fs.read_dir_entries(target) else {
        return;
    };
    let expected_ext = if spec.mode == RouteScanMode::CursorRuleFiles {
        "mdc"
    } else {
        "md"
    };
    for child_path in children {
        if !fs.is_regular_file_nofollow(&child_path) {
            continue;
        }
        let matches_ext = child_path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case(expected_ext));
        if !matches_ext {
            continue;
        }
        let name = child_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rule")
            .to_string();
        if let Some(entry) = build_artifact_entry(
            spec,
            &name,
            &child_path,
            std::slice::from_ref(&child_path),
            device_name,
            now,
            fs,
            warnings,
        ) {
            out.push(entry);
        }
    }
}

fn collect_files_sorted(root: &Path, fs: &dyn LocalFsPort, out: &mut Vec<PathBuf>) {
    if !fs.is_regular_dir_nofollow(root) {
        return;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs.read_dir_entries(&dir) else {
            continue;
        };
        for path in entries {
            if out.len() >= MAX_ARTIFACT_FILES {
                out.sort();
                return;
            }
            match fs.inspect_nofollow(&path) {
                Ok(RegularEntryKind::Dir) => stack.push(path),
                Ok(RegularEntryKind::File) => out.push(path),
                _ => {}
            }
        }
    }
    out.sort();
}

#[allow(clippy::too_many_arguments)]
fn build_artifact_entry(
    spec: &ArtifactRouteSpec,
    name: &str,
    root_path: &Path,
    files: &[PathBuf],
    device_name: &str,
    now: Timestamp,
    fs: &dyn LocalFsPort,
    warnings: &mut Vec<String>,
) -> Option<ArtifactEntry> {
    let mut tree_hasher = Sha256Hasher::new();
    let mut total_bytes: u64 = 0;
    let mut file_count: usize = 0;
    let mut has_scripts = false;
    let mut broad_tools = false;
    let mut bidi = false;

    for file in files {
        if file_count >= MAX_ARTIFACT_FILES {
            warnings.push(format!(
                "Artifact {name} exceeded file limit ({MAX_ARTIFACT_FILES}); digest partial."
            ));
            break;
        }
        if !fs.is_regular_file_nofollow(file) {
            continue;
        }
        let remaining = MAX_ARTIFACT_BYTES.saturating_sub(total_bytes);
        let Ok(bytes) = fs.read_bounded_regular_bytes(file, remaining) else {
            warnings.push(format!(
                "Artifact {name} exceeded size limit or unsafe file skipped."
            ));
            break;
        };
        total_bytes = total_bytes.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        file_count = file_count.saturating_add(1);

        let rel = file
            .strip_prefix(root_path)
            .ok()
            .and_then(|p| p.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(name)
            .replace('\\', "/");

        let mut leaf_hasher = Sha256Hasher::new();
        leaf_hasher.update(rel.as_bytes());
        leaf_hasher.update(b"\0");
        leaf_hasher.update(&bytes);
        let leaf_digest = leaf_hasher.finalize_digest();

        tree_hasher.update(rel.as_bytes());
        tree_hasher.update(&leaf_digest);

        if file
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|ext| {
                SCRIPT_EXTENSIONS
                    .iter()
                    .any(|candidate| ext.eq_ignore_ascii_case(candidate))
            })
        {
            has_scripts = true;
        }

        if let Ok(text) = std::str::from_utf8(&bytes) {
            if contains_bidi_control(text) {
                bidi = true;
            }
            let lower = text.to_ascii_lowercase();
            if BROAD_TOOL_PATTERNS.iter().any(|pat| lower.contains(pat)) {
                broad_tools = true;
            }
            if lower.contains("```bash")
                || lower.contains("```sh")
                || lower.contains("```powershell")
            {
                has_scripts = true;
            }
        }
    }

    if file_count == 0 {
        return None;
    }

    let digest_hex = encode_lower_hex(&tree_hasher.finalize_digest());
    let mut risk_flags = Vec::new();
    if has_scripts {
        risk_flags.push(ArtifactRiskFlag::HasScripts);
    }
    if broad_tools {
        risk_flags.push(ArtifactRiskFlag::RequestsBroadTools);
    }
    if bidi {
        risk_flags.push(ArtifactRiskFlag::BidiObfuscation);
    }

    let scope_tag = match spec.scope {
        ArtifactScope::User => "usr",
        ArtifactScope::Workspace => "ws",
        ArtifactScope::Managed => "mng",
    };
    let kind_tag = match spec.kind {
        ArtifactKind::Skill => "skl",
        ArtifactKind::Rule => "rul",
        ArtifactKind::Plugin => "plg",
        ArtifactKind::Command => "cmd",
        ArtifactKind::Subagent => "sub",
        ArtifactKind::Other => "oth",
    };
    let id = format!(
        "art_{}_{}_{}",
        kind_tag,
        scope_tag,
        slugify_id(name, 36, "artifact")
    );

    Some(ArtifactEntry {
        id,
        name: name.to_string(),
        kind: spec.kind,
        kind_other: None,
        scope: spec.scope,
        source_agent: spec.source_agent.to_string(),
        path: display_path(root_path),
        content_digest: digest_hex,
        file_count,
        total_bytes,
        usage_count: 0,
        pinned: false,
        risk_flags,
        device_id: slugify_id(device_name, 32, "local-device"),
        device_name: device_name.to_string(),
        user_id: None,
        detected_at: now,
    })
}

fn contains_bidi_control(text: &str) -> bool {
    text.chars().any(|ch| {
        matches!(
            ch,
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
    })
}
