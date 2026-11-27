// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Layer 2 port for symlink-safe, bounded local filesystem access (`ARCH-001`, `ARCH-027`).

use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegularEntryKind {
    Missing,
    File,
    Dir,
    UnsafeOrOther,
}

pub trait LocalFsPort: Send + Sync {
    fn check_no_ancestor_symlinks(&self, path: &Path) -> Result<(), String>;
    fn inspect_nofollow(&self, path: &Path) -> Result<RegularEntryKind, String>;

    fn is_regular_file_nofollow(&self, path: &Path) -> bool {
        self.inspect_nofollow(path)
            .is_ok_and(|kind| kind == RegularEntryKind::File)
    }

    fn is_regular_dir_nofollow(&self, path: &Path) -> bool {
        self.inspect_nofollow(path)
            .is_ok_and(|kind| kind == RegularEntryKind::Dir)
    }

    fn read_bounded_regular_bytes(&self, path: &Path, max_bytes: u64) -> Result<Vec<u8>, String>;
    fn read_bounded_regular_string(&self, path: &Path, max_bytes: u64) -> Result<String, String>;
    fn read_dir_entries(&self, dir: &Path) -> Result<Vec<PathBuf>, String>;
    fn ensure_dir_nofollow(&self, dir: &Path, private_dir: bool) -> Result<(), String>;
    fn atomic_write_nofollow(
        &self,
        path: &Path,
        bytes: &[u8],
        private_file: bool,
    ) -> Result<(), String>;
    fn remove_regular_file_nofollow(&self, path: &Path) -> Result<(), String>;
}

pub fn validate_safe_rel_path(
    raw: &str,
    allow_ws: bool,
    allow_appdata: bool,
    allow_empty: bool,
) -> Result<(), String> {
    if raw.chars().any(|c| c == '\0' || c.is_control()) {
        return Err("path contains NUL or control character".to_string());
    }
    if raw.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err("relative path cannot be empty".to_string())
        };
    }
    let body = if allow_ws && let Some(rest) = raw.strip_prefix("$WORKSPACE/") {
        rest
    } else if allow_appdata && let Some(rest) = raw.strip_prefix("$APPDATA/") {
        rest
    } else if raw.starts_with('$') {
        return Err(format!("disallowed path variable prefix in `{raw}`"));
    } else {
        raw
    };

    if body.starts_with('/') || body.starts_with('\\') || body.contains('\\') || body.contains(':')
    {
        return Err(format!("unsafe path separator or prefix in `{raw}`"));
    }
    let trimmed = body.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(format!("relative path `{raw}` resolves to empty"));
    }
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(format!("disallowed path segment `{seg}` in `{raw}`"));
        }
    }
    let path = Path::new(trimmed);
    if path.is_absolute()
        || !path
            .components()
            .all(|comp| matches!(comp, Component::Normal(_)))
    {
        return Err(format!("disallowed non-relative component in `{raw}`"));
    }
    Ok(())
}
