// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! TOCTOU-hardened bounded regular-file readers and symlink/case-collision guards for packs.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use crate::ComplyError;
use crate::pack_toml::is_safe_manifest_token;

const MAX_SCAN_DEPTH: usize = 8;
pub(crate) const MAX_BUNDLE_FILES: usize = 256;

pub(crate) fn validate_bundle_rel_path(
    rel: &str,
    seen_lower: &mut BTreeSet<String>,
) -> Result<(), ComplyError> {
    if !is_safe_manifest_token(rel) || rel.starts_with('/') || rel.contains('\\') {
        return Err(ComplyError::VerificationFailed {
            detail: format!("unsafe relative pack path `{rel}`"),
        });
    }
    for comp in Path::new(rel).components() {
        if !matches!(comp, Component::Normal(_)) {
            return Err(ComplyError::VerificationFailed {
                detail: format!("path traversal forbidden in `{rel}`"),
            });
        }
    }
    if !seen_lower.insert(rel.to_ascii_lowercase()) {
        return Err(ComplyError::VerificationFailed {
            detail: format!("case-colliding or duplicate path `{rel}` in pack bundle"),
        });
    }
    Ok(())
}

pub(crate) fn verify_exact_dir_entry(dir: &Path, name: &str) -> Result<(), ComplyError> {
    let entries = fs::read_dir(dir).map_err(|e| ComplyError::VerificationFailed {
        detail: format!("cannot scan `{}`: {e}", dir.display()),
    })?;
    let mut exact_found = false;
    for res in entries {
        let entry = res.map_err(|e| ComplyError::VerificationFailed {
            detail: e.to_string(),
        })?;
        let fname = entry.file_name();
        let lossy = fname.to_string_lossy();
        if lossy == name {
            exact_found = true;
        } else if lossy.eq_ignore_ascii_case(name) {
            return Err(ComplyError::VerificationFailed {
                detail: format!("ambiguous filename casing `{lossy}` near `{name}`"),
            });
        }
    }
    if !exact_found {
        return Err(ComplyError::VerificationFailed {
            detail: format!("missing required file `{name}` in pack directory"),
        });
    }
    Ok(())
}

pub(crate) fn reject_symlinks_on_existing_prefixes(path: &Path) -> Result<(), ComplyError> {
    let mut acc = PathBuf::new();
    let mut comps = path.components().peekable();
    while let Some(comp) = comps.next() {
        acc.push(comp.as_os_str());
        if matches!(
            comp,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        match fs::symlink_metadata(&acc) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    if comps.peek().is_some() && is_os_root_alias(&acc, &meta) {
                        continue;
                    }
                    return Err(ComplyError::VerificationFailed {
                        detail: format!(
                            "symlink or reparse ancestor refused at `{}`",
                            acc.display()
                        ),
                    });
                }
                if comps.peek().is_some() && !meta.is_dir() {
                    return Err(ComplyError::VerificationFailed {
                        detail: format!("non-directory ancestor refused at `{}`", acc.display()),
                    });
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => {
                return Err(ComplyError::VerificationFailed {
                    detail: format!("cannot inspect ancestor `{}`: {err}", acc.display()),
                });
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn is_os_root_alias(path: &Path, meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let expected = |p: &Path, target: &Path| {
        matches!(
            (p.to_str(), target.to_str()),
            (Some("/var"), Some("private/var" | "/private/var"))
                | (Some("/tmp"), Some("private/tmp" | "/private/tmp"))
                | (Some("/etc"), Some("private/etc" | "/private/etc"))
        )
    };
    meta.uid() == 0 && fs::read_link(path).is_ok_and(|target| expected(path, &target))
}

#[cfg(not(target_os = "macos"))]
fn is_os_root_alias(_path: &Path, _meta: &fs::Metadata) -> bool {
    false
}

pub(crate) fn read_regular_text(path: &Path, max_file_bytes: u64) -> Result<String, ComplyError> {
    let bytes = read_regular_bounded_bytes(path, max_file_bytes)?;
    String::from_utf8(bytes).map_err(|e| ComplyError::VerificationFailed {
        detail: format!("non-UTF8 compliance file `{}`: {e}", path.display()),
    })
}

pub(crate) fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub(crate) fn collect_dir_files(
    root: &Path,
    dir: &Path,
    depth: usize,
    max_file_bytes: u64,
    max_bundle_bytes: u64,
    total_bytes: &mut u64,
    seen_lower: &mut BTreeSet<String>,
) -> Result<Vec<(String, Vec<u8>)>, ComplyError> {
    if depth > MAX_SCAN_DEPTH {
        return Err(ComplyError::VerificationFailed {
            detail: "compliance pack directory depth exceeded".into(),
        });
    }
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| ComplyError::VerificationFailed {
            detail: e.to_string(),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ComplyError::VerificationFailed {
            detail: e.to_string(),
        })?
        .into_iter()
        .map(|e| e.path())
        .collect();
    children.sort();
    let mut out = Vec::new();
    for p in children {
        let meta = fs::symlink_metadata(&p).map_err(|e| ComplyError::VerificationFailed {
            detail: e.to_string(),
        })?;
        if is_symlink_or_reparse(&meta) {
            return Err(ComplyError::VerificationFailed {
                detail: format!("symlink or reparse point forbidden at `{}`", p.display()),
            });
        }
        if meta.is_dir() {
            out.extend(collect_dir_files(
                root,
                &p,
                depth.saturating_add(1),
                max_file_bytes,
                max_bundle_bytes,
                total_bytes,
                seen_lower,
            )?);
        } else if meta.is_file() {
            let rel = p
                .strip_prefix(root)
                .map_err(|e| ComplyError::VerificationFailed {
                    detail: e.to_string(),
                })?
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "signature.json" {
                continue;
            }
            validate_bundle_rel_path(&rel, seen_lower)?;
            if seen_lower.len() > MAX_BUNDLE_FILES {
                return Err(ComplyError::VerificationFailed {
                    detail: "compliance pack file count exceeds bundle limit".into(),
                });
            }
            let bytes = read_regular_bounded_bytes(&p, max_file_bytes)?;
            let len_u64 = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            *total_bytes = total_bytes.saturating_add(len_u64);
            if *total_bytes > max_bundle_bytes {
                return Err(ComplyError::VerificationFailed {
                    detail: "compliance pack bundle total size exceeds limits.toml cap".into(),
                });
            }
            out.push((rel, bytes));
        } else {
            return Err(ComplyError::VerificationFailed {
                detail: format!("non-regular entry `{}` forbidden in pack", p.display()),
            });
        }
    }
    Ok(out)
}

pub(crate) fn read_regular_bounded_bytes(
    path: &Path,
    max_file_bytes: u64,
) -> Result<Vec<u8>, ComplyError> {
    let meta = fs::symlink_metadata(path).map_err(|e| ComplyError::VerificationFailed {
        detail: format!("cannot stat `{}`: {e}", path.display()),
    })?;
    if is_symlink_or_reparse(&meta) || !meta.is_file() {
        return Err(ComplyError::VerificationFailed {
            detail: format!("`{}` must be a regular non-symlink file", path.display()),
        });
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_nofollow_flags(&mut opts);
    let file = opts
        .open(path)
        .map_err(|e| ComplyError::VerificationFailed {
            detail: format!("cannot open `{}`: {e}", path.display()),
        })?;
    let handle_meta = file
        .metadata()
        .map_err(|e| ComplyError::VerificationFailed {
            detail: format!("cannot inspect opened `{}`: {e}", path.display()),
        })?;
    if is_symlink_or_reparse(&handle_meta) || !handle_meta.is_file() {
        return Err(ComplyError::VerificationFailed {
            detail: format!("opened `{}` failed regular-file check", path.display()),
        });
    }
    verify_same_file_identity(path, &meta, &handle_meta)?;

    let mut buf = Vec::new();
    let limit = usize::try_from(max_file_bytes).unwrap_or(usize::MAX);
    file.take(max_file_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| ComplyError::VerificationFailed {
            detail: format!("failed reading `{}`: {e}", path.display()),
        })?;
    if buf.len() > limit {
        return Err(ComplyError::VerificationFailed {
            detail: format!("`{}` exceeds pack file byte cap", path.display()),
        });
    }
    Ok(buf)
}

#[cfg(unix)]
fn verify_same_file_identity(
    path: &Path,
    pre: &fs::Metadata,
    handle: &fs::Metadata,
) -> Result<(), ComplyError> {
    use std::os::unix::fs::MetadataExt as _;
    if pre.dev() != handle.dev() || pre.ino() != handle.ino() {
        return Err(ComplyError::VerificationFailed {
            detail: format!("`{}` changed between stat and open", path.display()),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_same_file_identity(
    path: &Path,
    pre: &fs::Metadata,
    handle: &fs::Metadata,
) -> Result<(), ComplyError> {
    if pre.len() != handle.len() {
        return Err(ComplyError::VerificationFailed {
            detail: format!("`{}` size changed between stat and open", path.display()),
        });
    }
    Ok(())
}

fn apply_nofollow_flags(opts: &mut OpenOptions) {
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
}

#[cfg(unix)]
const fn unix_o_nofollow() -> i32 {
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        )
    ))]
    {
        0o100_000
    }
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        )
    ))]
    {
        0x20000
    }
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ))]
    {
        0o400_000
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "netbsd"
    ))]
    {
        0x0100
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "netbsd"
    )))]
    {
        0
    }
}
