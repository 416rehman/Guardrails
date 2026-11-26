// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::Path;

use crate::SensorError;

pub(crate) fn open_nofollow_bounded_bytes(
    path: &Path,
    max_bytes: u64,
    context: &str,
) -> Result<Vec<u8>, SensorError> {
    if max_bytes == 0 {
        return Err(SensorError::CatalogueLoad {
            path: path.display().to_string(),
            detail: format!("{context}: max_bytes limit must be > 0"),
        });
    }
    let meta_link = fs::symlink_metadata(path).map_err(|err| SensorError::CatalogueLoad {
        path: path.display().to_string(),
        detail: err.to_string(),
    })?;
    if meta_link.file_type().is_symlink() || !meta_link.file_type().is_file() {
        return Err(SensorError::CatalogueLoad {
            path: path.display().to_string(),
            detail: format!("{context}: expected non-symlink regular file"),
        });
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file: File = opts.open(path).map_err(|err| SensorError::CatalogueLoad {
        path: path.display().to_string(),
        detail: err.to_string(),
    })?;
    let opened_meta = file.metadata().map_err(|err| SensorError::CatalogueLoad {
        path: path.display().to_string(),
        detail: err.to_string(),
    })?;
    if opened_meta.file_type().is_symlink() || !opened_meta.is_file() {
        return Err(SensorError::CatalogueLoad {
            path: path.display().to_string(),
            detail: format!("{context}: opened descriptor is not a regular file"),
        });
    }

    let cap_plus_one = max_bytes.saturating_add(1);
    let mut buf = Vec::new();
    file.take(cap_plus_one)
        .read_to_end(&mut buf)
        .map_err(|err| SensorError::CatalogueLoad {
            path: path.display().to_string(),
            detail: err.to_string(),
        })?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(SensorError::CatalogueLoad {
            path: path.display().to_string(),
            detail: format!("{context}: file exceeds {max_bytes} byte limit"),
        });
    }
    Ok(buf)
}

pub(crate) fn read_nofollow_bounded_utf8(
    path: &Path,
    max_bytes: u64,
    context: &str,
) -> Result<String, SensorError> {
    let bytes = open_nofollow_bounded_bytes(path, max_bytes, context)?;
    String::from_utf8(bytes).map_err(|err| SensorError::CatalogueLoad {
        path: path.display().to_string(),
        detail: format!("{context}: invalid UTF-8: {err}"),
    })
}

pub(crate) fn verify_non_symlink_dir(
    dir: &Path,
    context: &str,
) -> Result<fs::ReadDir, SensorError> {
    let meta = fs::symlink_metadata(dir).map_err(|err| SensorError::CatalogueLoad {
        path: dir.display().to_string(),
        detail: err.to_string(),
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(SensorError::CatalogueLoad {
            path: dir.display().to_string(),
            detail: format!("{context}: expected non-symlink directory"),
        });
    }
    fs::read_dir(dir).map_err(|err| SensorError::CatalogueLoad {
        path: dir.display().to_string(),
        detail: err.to_string(),
    })
}
