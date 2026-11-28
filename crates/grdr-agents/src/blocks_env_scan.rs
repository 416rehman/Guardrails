// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Resolved-environment scanners for Pass 2 building-block detection (`docs/design/05`).

use std::collections::BTreeSet;
use std::path::Path;

use grdr_core::discover::ScanBlockedReason;
use grdr_ports::LocalFsPort;
use serde_json::Value;

use crate::blocks_scan::{
    DetectedBuildingBlock, ScanLedger, file_label, match_blocks_against_jvm,
    match_blocks_against_tokens,
};
use crate::catalogue::BuildingBlockCatalogue;

pub(crate) fn scan_resolved_python_envs(
    ws_root: &Path,
    blocks: &BuildingBlockCatalogue,
    fs: &dyn LocalFsPort,
    ledger: &mut ScanLedger,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<DetectedBuildingBlock>,
) -> Result<(), ScanBlockedReason> {
    for env_name in [".venv", "venv", "env"] {
        let env_dir = ws_root.join(env_name);
        if !ledger.inspect_optional_dir(&env_dir, fs)? {
            continue;
        }
        let mut site_dirs = vec![env_dir.join("Lib/site-packages")];
        let lib_dir = env_dir.join("lib");
        if ledger.inspect_optional_dir(&lib_dir, fs)? {
            for sub in ledger.read_dir_bounded(&lib_dir, fs)? {
                if ledger.inspect_optional_dir(&sub, fs)? {
                    site_dirs.push(sub.join("site-packages"));
                }
            }
        }
        for site_dir in site_dirs {
            if !ledger.inspect_optional_dir(&site_dir, fs)? {
                continue;
            }
            for entry in ledger.read_dir_bounded(&site_dir, fs)? {
                let name = file_label(&entry, "");
                if !name.ends_with(".dist-info") {
                    continue;
                }
                if !ledger.inspect_optional_dir(&entry, fs)? {
                    continue;
                }
                let meta_path = entry.join("METADATA");
                if !ledger.inspect_optional_file(&meta_path, fs)? {
                    continue;
                }
                let raw = ledger.read_manifest(&meta_path, fs)?;
                let tokens = extract_dist_info_tokens(&raw);
                match_blocks_against_tokens("pypi", &name, &tokens, blocks, seen, out);
            }
        }
    }
    Ok(())
}

pub(crate) fn scan_resolved_node_modules(
    ws_root: &Path,
    blocks: &BuildingBlockCatalogue,
    fs: &dyn LocalFsPort,
    ledger: &mut ScanLedger,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<DetectedBuildingBlock>,
) -> Result<(), ScanBlockedReason> {
    let nm = ws_root.join("node_modules");
    if !ledger.inspect_optional_dir(&nm, fs)? {
        return Ok(());
    }
    for entry in ledger.read_dir_bounded(&nm, fs)? {
        let dir_name = file_label(&entry, "");
        if dir_name.starts_with('@') {
            if !ledger.inspect_optional_dir(&entry, fs)? {
                continue;
            }
            for sub in ledger.read_dir_bounded(&entry, fs)? {
                scan_node_package_json(&sub, blocks, fs, ledger, seen, out)?;
            }
        } else {
            scan_node_package_json(&entry, blocks, fs, ledger, seen, out)?;
        }
    }
    Ok(())
}

fn scan_node_package_json(
    pkg_dir: &Path,
    blocks: &BuildingBlockCatalogue,
    fs: &dyn LocalFsPort,
    ledger: &mut ScanLedger,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<DetectedBuildingBlock>,
) -> Result<(), ScanBlockedReason> {
    if !ledger.inspect_optional_dir(pkg_dir, fs)? {
        return Ok(());
    }
    let pkg_json = pkg_dir.join("package.json");
    if !ledger.inspect_optional_file(&pkg_json, fs)? {
        return Ok(());
    }
    let raw = ledger.read_manifest(&pkg_json, fs)?;
    let mut tokens = extract_package_tokens("npm", "package.json", &raw);
    if let Ok(Value::Object(root)) = serde_json::from_str::<Value>(&raw)
        && let Some(name) = root.get("name").and_then(Value::as_str)
    {
        tokens.insert(name.to_ascii_lowercase());
    }
    let label = file_label(pkg_dir, "node_module");
    match_blocks_against_tokens("npm", &label, &tokens, blocks, seen, out);
    Ok(())
}

pub(crate) fn scan_resolved_dotnet_and_jvm(
    ws_root: &Path,
    blocks: &BuildingBlockCatalogue,
    fs: &dyn LocalFsPort,
    ledger: &mut ScanLedger,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<DetectedBuildingBlock>,
) -> Result<(), ScanBlockedReason> {
    for rel in ["", "bin", "lib", "target"] {
        let dir = if rel.is_empty() {
            ws_root.to_path_buf()
        } else {
            ws_root.join(rel)
        };
        if !ledger.inspect_optional_dir(&dir, fs)? {
            continue;
        }
        for entry in ledger.read_dir_bounded(&dir, fs)? {
            let fname = file_label(&entry, "");
            if fname.ends_with(".deps.json") && ledger.inspect_optional_file(&entry, fs)? {
                let raw = ledger.read_manifest(&entry, fs)?;
                let tokens = extract_dotnet_deps_tokens(&raw);
                match_blocks_against_tokens("dotnet", &fname, &tokens, blocks, seen, out);
            } else if fname.ends_with(".jar") && ledger.inspect_optional_file(&entry, fs)? {
                let mut tokens = BTreeSet::new();
                let lower = fname.to_ascii_lowercase();
                if let Some(stem) = lower.strip_suffix(".jar") {
                    tokens.insert(stem.to_owned());
                    if let Some((prefix, _)) = stem.split_once('-') {
                        tokens.insert(prefix.to_owned());
                    }
                }
                match_blocks_against_jvm(&fname, &tokens, blocks, seen, out);
            }
        }
    }
    Ok(())
}

fn extract_dist_info_tokens(raw: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("Name:") {
            let trimmed = rest.trim().to_ascii_lowercase();
            if !trimmed.is_empty() {
                out.insert(trimmed);
            }
            break;
        }
    }
    out
}

fn extract_dotnet_deps_tokens(raw: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(Value::Object(root)) = serde_json::from_str::<Value>(raw) else {
        return out;
    };
    if let Some(Value::Object(libs)) = root.get("libraries") {
        for key in libs.keys() {
            let pkg = key
                .split('/')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if !pkg.is_empty() {
                out.insert(pkg);
            }
        }
    }
    out
}

pub(crate) fn extract_package_tokens(eco: &str, file_name: &str, raw: &str) -> BTreeSet<String> {
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
    if eco == "jvm" && file_name == "pom.xml" {
        return extract_pom_tokens(raw);
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
        for part in cleaned.split(['"', '\'', ',', ' ', '=', '(', ')']) {
            let candidate = part.trim().to_ascii_lowercase();
            if !candidate.is_empty() {
                out.insert(candidate.clone());
                if let Some((grp, rest)) = candidate.split_once(':')
                    && let Some((art, _)) = rest.split_once(':')
                {
                    out.insert(format!("{grp}:{art}"));
                }
            }
        }
    }
    out
}

fn extract_pom_tokens(raw: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = raw;
    let mut in_dependency = false;
    let mut current_group: Option<String> = None;
    while let Some(pos) = rest.find('<') {
        let after_lt = rest.get(pos..).unwrap_or("");
        if let Some(tail) = after_lt.strip_prefix("<dependency>") {
            in_dependency = true;
            current_group = None;
            rest = tail;
        } else if let Some(tail) = after_lt.strip_prefix("</dependency>") {
            in_dependency = false;
            current_group = None;
            rest = tail;
        } else if after_lt.starts_with("<parent>")
            || after_lt.starts_with("</parent>")
            || after_lt.starts_with("<project>")
            || after_lt.starts_with("</project>")
        {
            current_group = None;
            rest = after_lt.get(1..).unwrap_or("");
        } else if let Some((grp, tail)) = take_xml_tag(after_lt, "groupId") {
            if in_dependency {
                current_group = Some(grp.to_ascii_lowercase());
            }
            rest = tail;
        } else if let Some((art, tail)) = take_xml_tag(after_lt, "artifactId") {
            if in_dependency {
                let art_l = art.to_ascii_lowercase();
                out.insert(art_l.clone());
                if let Some(grp) = &current_group {
                    out.insert(format!("{grp}:{art_l}"));
                }
            }
            rest = tail;
        } else {
            rest = after_lt.get(1..).unwrap_or("");
        }
    }
    out
}

fn take_xml_tag<'a>(slice: &'a str, tag: &str) -> Option<(&'a str, &'a str)> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let after_open = slice.strip_prefix(&open)?;
    let (inner, tail) = after_open.split_once(&close)?;
    Some((inner.trim(), tail))
}
