// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Workspace path confinement and Windows ADS/8.3/DOS-device validation backed by `grdr-core`.

use std::io::ErrorKind;
use std::path::{Component, Path};

use grdr_core::analyze::path::{
    OsKind, PathFacts, SymlinkResolution, VolumeCase, resolve_path, split_ntfs_ads,
};
use grdr_core::analyze::types::Resolution;
use grdr_model::ActionClass;
use serde_json::{Value, json};

const DOS_DEVICE_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

pub(crate) struct ValidatedTerminalSpec {
    pub(crate) target: String,
    pub(crate) summary: String,
}

/// Resolve a caller-supplied path and confine it inside `workspace_root`.
/// Rejects empty strings, control chars, traversal (`..`), Windows verbatim/ADS/8.3/DOS-device escapes,
/// symlinks, and Windows reparse points.
pub(crate) fn resolve_confined_path(
    workspace_root: &Path,
    raw_path: &str,
    require_existing_dir: bool,
) -> Result<String, &'static str> {
    if raw_path.trim().is_empty() || raw_path.chars().any(is_control_or_bidi) {
        return Err("path contains empty, control, or bidi characters");
    }
    if workspace_root.as_os_str().is_empty() {
        return Err("workspace_root is empty");
    }
    let root_meta =
        std::fs::symlink_metadata(workspace_root).map_err(|_| "workspace_root inaccessible")?;
    if is_symlink_or_reparse(&root_meta) {
        return Err("workspace_root cannot be a symlink or reparse point");
    }
    let canon_root = std::fs::canonicalize(workspace_root).map_err(|_| "invalid workspace_root")?;
    let clean_canon_root = strip_verbatim_prefix(&canon_root);
    let clean_raw_root = strip_verbatim_prefix(workspace_root);

    check_lexical_windows_and_core_rules(raw_path, &clean_canon_root)?;

    let clean_candidate_str = strip_verbatim_str(raw_path);
    let candidate = Path::new(clean_candidate_str);
    let rel_path = if candidate.is_absolute() {
        strip_prefix_os_aware(candidate, &clean_raw_root)
            .or_else(|| strip_prefix_os_aware(candidate, &clean_canon_root))
            .ok_or("absolute path escapes workspace_root")?
    } else {
        candidate.to_path_buf()
    };

    let mut normal_segments = Vec::new();
    for component in rel_path.components() {
        match component {
            Component::Normal(seg) => {
                let seg_str = seg.to_string_lossy();
                if has_bad_windows_segment(&seg_str) {
                    return Err("path segment violates NTFS/Windows safety rules");
                }
                normal_segments.push(seg);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("path traversal or root prefix is prohibited");
            }
        }
    }
    if normal_segments.is_empty() && !require_existing_dir {
        return Err("file path must reference a child inside workspace_root");
    }

    let mut cur = canon_root.clone();
    let mut missing_seen = false;
    for seg in normal_segments {
        cur.push(seg);
        if missing_seen {
            continue;
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    return Err("symlink or reparse point rejected");
                }
                let canon_cur =
                    std::fs::canonicalize(&cur).map_err(|_| "canonicalize child failed")?;
                let clean_cur = strip_verbatim_prefix(&canon_cur);
                if strip_prefix_os_aware(&clean_cur, &clean_canon_root).is_none() {
                    return Err("canonical child escapes workspace_root");
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                missing_seen = true;
            }
            Err(_) => return Err("path metadata inspection failed"),
        }
    }

    if require_existing_dir {
        let dir_meta =
            std::fs::symlink_metadata(&cur).map_err(|_| "cwd does not exist inside workspace")?;
        if is_symlink_or_reparse(&dir_meta) || !dir_meta.is_dir() {
            return Err("cwd must be a real non-symlink directory inside workspace");
        }
    }
    Ok(strip_verbatim_prefix(&cur).to_string_lossy().into_owned())
}

pub(crate) fn validate_terminal_create_params(
    workspace_root: &Path,
    params: &Value,
) -> Result<ValidatedTerminalSpec, &'static str> {
    let Some(cmd) = params
        .get("command")
        .and_then(Value::as_str)
        .filter(|c| !c.trim().is_empty() && !c.chars().any(is_control_or_bidi))
    else {
        return Err("terminal/create requires valid non-control command string");
    };
    if cmd.contains("..") {
        return Err("terminal/create command contains prohibited traversal");
    }

    let mut arg_tokens = Vec::new();
    if let Some(raw_args) = params.get("args") {
        let Some(arr) = raw_args.as_array() else {
            return Err("terminal/create args must be an array of strings");
        };
        for item in arr {
            let Some(arg) = item.as_str() else {
                return Err("terminal/create args elements must be strings");
            };
            if arg.chars().any(is_control_or_bidi) {
                return Err("terminal/create arg contains prohibited control characters");
            }
            arg_tokens.push(arg);
        }
    }

    let confined_cwd = match params.get("cwd") {
        None | Some(Value::Null) => resolve_confined_path(workspace_root, ".", true)?,
        Some(Value::String(raw_cwd)) => resolve_confined_path(workspace_root, raw_cwd, true)?,
        Some(_) => return Err("terminal/create cwd must be a string"),
    };

    let mut env_keys = Vec::new();
    if let Some(raw_env) = params.get("env") {
        let Some(obj) = raw_env.as_object() else {
            return Err("terminal/create env must be an object");
        };
        for (k, v) in obj {
            if k.trim().is_empty()
                || k.contains('=')
                || k.chars().any(is_control_or_bidi)
                || !v.is_string()
            {
                return Err(
                    "terminal/create env entries must have safe key names and string values",
                );
            }
            env_keys.push(k.as_str());
        }
        env_keys.sort_unstable();
    }

    let full_cmd = if arg_tokens.is_empty() {
        cmd.to_string()
    } else {
        format!("{cmd} {}", arg_tokens.join(" "))
    };
    let env_tag = if env_keys.is_empty() {
        "none".to_string()
    } else {
        env_keys.join(",")
    };
    let summary = format!("ACP terminal/create {full_cmd} cwd={confined_cwd} env_keys={env_tag}");
    let target = format!("{full_cmd} [cwd:{confined_cwd} env:{env_tag}]");
    Ok(ValidatedTerminalSpec { target, summary })
}

pub(crate) fn validate_modify_target(
    workspace_root: &Path,
    action_class: ActionClass,
    candidate: &str,
) -> Result<String, &'static str> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() || trimmed.chars().any(is_control_or_bidi) {
        return Err("modify target empty or contains control characters");
    }
    match action_class {
        ActionClass::FileRead
        | ActionClass::FileWrite
        | ActionClass::FileDelete
        | ActionClass::ConfigChange => resolve_confined_path(workspace_root, trimmed, false),
        ActionClass::Exec => {
            if trimmed
                .chars()
                .any(|c| matches!(c, ';' | '|' | '&' | '`' | '$'))
                || trimmed.contains("..")
            {
                return Err("exec modify target contains shell injection or traversal");
            }
            let mut parts = trimmed.split_whitespace();
            let cmd = parts.next().ok_or("exec modify target missing command")?;
            let args: Vec<&str> = parts.collect();
            let spec = validate_terminal_create_params(
                workspace_root,
                &json!({ "command": cmd, "args": args }),
            )?;
            Ok(spec.target)
        }
        _ => Ok(trimmed.to_string()),
    }
}

fn check_lexical_windows_and_core_rules(
    raw_path: &str,
    clean_canon_root: &Path,
) -> Result<(), &'static str> {
    let clean_raw = strip_verbatim_str(raw_path);
    let root_str = clean_canon_root.to_string_lossy().replace('\\', "/");
    let full_for_core = if Path::new(clean_raw).is_absolute() {
        clean_raw.replace('\\', "/")
    } else {
        format!(
            "{}/{}",
            root_str.trim_end_matches('/'),
            clean_raw.replace('\\', "/")
        )
    };
    let (_base, ads) = split_ntfs_ads(&full_for_core);
    if ads.is_some() {
        return Err("NTFS alternate data streams rejected");
    }
    for (os, case) in [
        (
            if cfg!(windows) {
                OsKind::Windows
            } else if cfg!(target_os = "macos") {
                OsKind::MacOs
            } else {
                OsKind::Linux
            },
            if cfg!(windows) || cfg!(target_os = "macos") {
                VolumeCase::CaseInsensitive
            } else {
                VolumeCase::CaseSensitive
            },
        ),
        (OsKind::Windows, VolumeCase::CaseInsensitive),
    ] {
        let facts = PathFacts {
            os,
            volume_case: case,
            symlink: SymlinkResolution::Direct,
            workspace_root: Some(root_str.clone()),
        };
        match resolve_path(&full_for_core, Some(&facts)) {
            Resolution::Resolved(canon) => {
                if canon.escaped_workspace || canon.ads_stream.is_some() {
                    return Err("resolved path escaped workspace or used ADS");
                }
            }
            Resolution::Malformed(_) | Resolution::Unresolved(_) => {
                return Err("path failed core canonical resolution");
            }
        }
    }
    Ok(())
}

fn strip_verbatim_str(raw: &str) -> &str {
    raw.strip_prefix(r"\\?\")
        .or_else(|| raw.strip_prefix(r"//?/"))
        .unwrap_or(raw)
}

fn strip_verbatim_prefix(path: &Path) -> std::path::PathBuf {
    let text = path.to_string_lossy();
    std::path::PathBuf::from(strip_verbatim_str(&text))
}

fn strip_prefix_os_aware(path: &Path, prefix: &Path) -> Option<std::path::PathBuf> {
    if let Ok(rel) = path.strip_prefix(prefix) {
        return Some(rel.to_path_buf());
    }
    if cfg!(windows) {
        let p_norm = path
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        let pre_norm = prefix
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_ascii_lowercase();
        if p_norm == pre_norm {
            return Some(std::path::PathBuf::new());
        }
        if let Some(rest) = p_norm
            .strip_prefix(&pre_norm)
            .and_then(|r| r.strip_prefix('/'))
        {
            return Some(std::path::PathBuf::from(rest));
        }
    }
    None
}

fn has_bad_windows_segment(seg: &str) -> bool {
    if seg.contains(':') || seg.ends_with(['.', ' ']) {
        return true;
    }
    let stem = seg.split('.').next().unwrap_or(seg).to_ascii_lowercase();
    if DOS_DEVICE_NAMES.iter().any(|dev| *dev == stem) {
        return true;
    }
    if let Some((_prefix, suffix)) = seg.rsplit_once('~')
        && !suffix.is_empty()
        && suffix.bytes().all(|b| b.is_ascii_digit())
    {
        return true;
    }
    false
}

fn is_control_or_bidi(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

fn is_symlink_or_reparse(meta: &std::fs::Metadata) -> bool {
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
