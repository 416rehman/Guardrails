// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![cfg(test)]

//! Standard-library test double for `LocalFsPort` inside `grdr-agents` unit tests.

use std::fs;
use std::path::{Path, PathBuf};

use grdr_ports::{LocalFsPort, RegularEntryKind};

pub(crate) struct TestLocalFs;

impl LocalFsPort for TestLocalFs {
    fn check_no_ancestor_symlinks(&self, _path: &Path) -> Result<(), String> {
        Ok(())
    }

    fn inspect_nofollow(&self, path: &Path) -> Result<RegularEntryKind, String> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => Ok(RegularEntryKind::UnsafeOrOther),
            Ok(meta) if meta.is_file() => Ok(RegularEntryKind::File),
            Ok(meta) if meta.is_dir() => Ok(RegularEntryKind::Dir),
            Ok(_) => Ok(RegularEntryKind::UnsafeOrOther),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RegularEntryKind::Missing),
            Err(e) => Err(e.to_string()),
        }
    }

    fn read_bounded_regular_bytes(&self, path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
        if self.inspect_nofollow(path)? != RegularEntryKind::File {
            return Err("not a regular file".into());
        }
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
            return Err("file exceeds max_bytes".into());
        }
        Ok(bytes)
    }

    fn read_bounded_regular_string(&self, path: &Path, max_bytes: u64) -> Result<String, String> {
        let bytes = self.read_bounded_regular_bytes(path, max_bytes)?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    fn read_dir_entries(&self, dir: &Path) -> Result<Vec<PathBuf>, String> {
        let rd = fs::read_dir(dir).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for entry in rd {
            out.push(entry.map_err(|e| e.to_string())?.path());
        }
        out.sort();
        Ok(out)
    }

    fn ensure_dir_nofollow(&self, dir: &Path, _private_dir: bool) -> Result<(), String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())
    }

    fn atomic_write_nofollow(
        &self,
        path: &Path,
        bytes: &[u8],
        _private_file: bool,
    ) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(path, bytes).map_err(|e| e.to_string())
    }

    fn remove_regular_file_nofollow(&self, path: &Path) -> Result<(), String> {
        fs::remove_file(path).map_err(|e| e.to_string())
    }
}
