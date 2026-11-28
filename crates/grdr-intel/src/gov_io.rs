// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Symlink-safe bounded reader for `<packs_dir>/lists/intel-governance.yaml`.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Read as _;
use std::path::Path;

use crate::IntelError;

pub(crate) fn load_gov_yaml_from_packs_dir(
    packs_dir: &Path,
    max_bytes: u64,
) -> Result<String, IntelError> {
    let packs_meta = std::fs::symlink_metadata(packs_dir)
        .map_err(|e| IntelError::CodecParse(format!("failed inspecting packs dir: {e}")))?;
    if is_symlink_or_reparse(&packs_meta) || !packs_meta.is_dir() {
        return Err(IntelError::CodecParse(
            "packs_dir must be a non-symlink directory".into(),
        ));
    }

    let lists_dir = packs_dir.join("lists");
    let lists_meta = std::fs::symlink_metadata(&lists_dir)
        .map_err(|e| IntelError::CodecParse(format!("failed inspecting lists dir: {e}")))?;
    if is_symlink_or_reparse(&lists_meta) || !lists_meta.is_dir() {
        return Err(IntelError::CodecParse(
            "lists dir must be a non-symlink directory".into(),
        ));
    }

    let path = lists_dir.join("intel-governance.yaml");
    let file_meta = std::fs::symlink_metadata(&path).map_err(|e| {
        IntelError::CodecParse(format!("failed inspecting {}: {e}", path.display()))
    })?;
    if is_symlink_or_reparse(&file_meta) || !file_meta.is_file() || file_meta.len() > max_bytes {
        return Err(IntelError::CodecParse(format!(
            "{} must be a bounded regular file",
            path.display()
        )));
    }

    let file = open_regular_nofollow(&path)?;
    let handle_meta = file
        .metadata()
        .map_err(|e| IntelError::CodecParse(format!("failed stating {}: {e}", path.display())))?;
    if is_symlink_or_reparse(&handle_meta)
        || !handle_meta.is_file()
        || handle_meta.len() > max_bytes
    {
        return Err(IntelError::CodecParse(format!(
            "{} must remain a bounded regular file after open",
            path.display()
        )));
    }
    verify_same_file_identity(&path, &file_meta, &handle_meta)?;

    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| IntelError::CodecParse(format!("failed reading {}: {e}", path.display())))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(IntelError::CodecParse(format!(
            "{} exceeds byte bound",
            path.display()
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| IntelError::CodecParse("intel-governance YAML is not valid UTF-8".into()))
}

fn is_symlink_or_reparse(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn verify_same_file_identity(
    path: &Path,
    pre_meta: &Metadata,
    handle_meta: &Metadata,
) -> Result<(), IntelError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if pre_meta.dev() != handle_meta.dev() || pre_meta.ino() != handle_meta.ino() {
            return Err(IntelError::CodecParse(format!(
                "file identity changed during open for {}",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, pre_meta, handle_meta);
    }
    Ok(())
}

fn open_regular_nofollow(path: &Path) -> Result<File, IntelError> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(unix_o_nofollow());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts.open(path)
        .map_err(|e| IntelError::CodecParse(format!("failed opening {}: {e}", path.display())))
}

#[cfg(unix)]
const fn unix_o_nofollow() -> i32 {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        0x0100
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        #[cfg(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        ))]
        {
            0o100_000
        }
        #[cfg(any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))]
        {
            0x20000
        }
        #[cfg(not(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        )))]
        {
            0o400_000
        }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "linux",
        target_os = "android"
    )))]
    {
        0x20000
    }
}
