// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Deterministic, safe POSIX ustar tar archive reader and writer without external archive crates.

use std::collections::BTreeSet;
use std::path::Path;

use crate::fs_safe::{atomic_write_bytes, read_bounded_regular};

const BLOCK_BYTES: usize = 512;
const MAX_ARCHIVE_ENTRIES: usize = 512;
const MAX_ENTRY_BYTES: usize = 32 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarEntry {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TarError {
    #[error("GRDR-TAR-0001: I/O error on `{path}`: {detail}")]
    Io { path: String, detail: String },
    #[error("GRDR-TAR-0002: unsafe or invalid archive member path `{0}`")]
    InvalidPath(String),
    #[error("GRDR-TAR-0003: malformed POSIX ustar archive: {0}")]
    MalformedArchive(String),
}

pub fn validate_archive_rel_path(path: &str) -> Result<(), TarError> {
    if path.is_empty()
        || path.len() > 250
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
    {
        return Err(TarError::InvalidPath(path.to_owned()));
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(TarError::InvalidPath(path.to_owned()));
        }
    }
    Ok(())
}

pub fn write_tar_file(dest: &Path, entries: &[TarEntry]) -> Result<(), TarError> {
    let encoded = encode_tar(entries)?;
    atomic_write_bytes(dest, &encoded, false).map_err(|e| TarError::Io {
        path: dest.display().to_string(),
        detail: e.to_string(),
    })
}

pub fn encode_tar(entries: &[TarEntry]) -> Result<Vec<u8>, TarError> {
    if entries.len() > MAX_ARCHIVE_ENTRIES {
        return Err(TarError::MalformedArchive(
            "archive entry count exceeds maximum bound".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for entry in entries {
        validate_archive_rel_path(&entry.path)?;
        if !seen.insert(entry.path.as_str()) {
            return Err(TarError::InvalidPath(format!(
                "duplicate archive path `{}`",
                entry.path
            )));
        }
        if entry.bytes.len() > MAX_ENTRY_BYTES {
            return Err(TarError::MalformedArchive(format!(
                "entry `{}` exceeds maximum member size",
                entry.path
            )));
        }
        let header = build_ustar_header(&entry.path, entry.bytes.len())?;
        out.extend_from_slice(&header);
        out.extend_from_slice(&entry.bytes);
        let rem = entry.bytes.len() % BLOCK_BYTES;
        if rem != 0 {
            let pad = BLOCK_BYTES.saturating_sub(rem);
            out.extend(std::iter::repeat_n(0_u8, pad));
        }
    }
    out.extend(std::iter::repeat_n(0_u8, BLOCK_BYTES.saturating_mul(2)));
    Ok(out)
}

pub fn read_tar_file(src: &Path) -> Result<Vec<TarEntry>, TarError> {
    let raw = read_bounded_regular(src, MAX_ARCHIVE_BYTES).map_err(|e| TarError::Io {
        path: src.display().to_string(),
        detail: e.to_string(),
    })?;
    decode_tar(&raw)
}

pub fn decode_tar(raw: &[u8]) -> Result<Vec<TarEntry>, TarError> {
    if !raw.len().is_multiple_of(BLOCK_BYTES) || raw.len() < BLOCK_BYTES {
        return Err(TarError::MalformedArchive(
            "tar stream length is not a non-empty 512-byte multiple".into(),
        ));
    }
    let mut offset: usize = 0;
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut saw_eof_marker = false;

    while offset < raw.len() {
        let Some(hdr_slice) = raw.get(offset..offset.saturating_add(BLOCK_BYTES)) else {
            return Err(TarError::MalformedArchive("truncated tar header".into()));
        };
        offset = offset.saturating_add(BLOCK_BYTES);

        if hdr_slice.iter().all(|b| *b == 0) {
            if raw
                .get(offset..)
                .is_some_and(|rest| rest.iter().any(|b| *b != 0))
            {
                return Err(TarError::MalformedArchive(
                    "trailing non-zero payload after tar EOF marker".into(),
                ));
            }
            saw_eof_marker = true;
            break;
        }
        if entries.len() >= MAX_ARCHIVE_ENTRIES {
            return Err(TarError::MalformedArchive(
                "archive entry count exceeds limit".into(),
            ));
        }

        verify_header_checksum(hdr_slice)?;
        let path = extract_header_path(hdr_slice)?;
        validate_archive_rel_path(&path)?;
        if !seen.insert(path.clone()) {
            return Err(TarError::InvalidPath(format!(
                "duplicate member `{path}` in archive"
            )));
        }

        let typeflag = hdr_slice.get(156).copied().unwrap_or(0);
        if typeflag != b'0' && typeflag != 0 {
            return Err(TarError::MalformedArchive(format!(
                "unsupported non-regular member `{path}` (typeflag {typeflag})"
            )));
        }

        let size = parse_octal_field(hdr_slice.get(124..136).unwrap_or(&[]))?;
        if size > MAX_ENTRY_BYTES {
            return Err(TarError::MalformedArchive(format!(
                "member `{path}` size {size} exceeds bound"
            )));
        }
        let end = offset.checked_add(size).ok_or_else(|| {
            TarError::MalformedArchive("integer overflow in archive payload offset".into())
        })?;
        let Some(payload) = raw.get(offset..end) else {
            return Err(TarError::MalformedArchive(format!(
                "truncated payload for `{path}`"
            )));
        };
        entries.push(TarEntry {
            path,
            bytes: payload.to_vec(),
        });

        let padded = size.div_ceil(BLOCK_BYTES).saturating_mul(BLOCK_BYTES);
        offset = offset.saturating_add(padded);
    }

    if !saw_eof_marker {
        return Err(TarError::MalformedArchive(
            "tar stream ended without EOF marker".into(),
        ));
    }

    Ok(entries)
}

fn build_ustar_header(path: &str, size: usize) -> Result<[u8; BLOCK_BYTES], TarError> {
    let mut hdr = [0_u8; BLOCK_BYTES];
    let (prefix, name) = split_ustar_path(path)?;

    write_field(&mut hdr, 0, name.as_bytes())?;
    write_field(&mut hdr, 100, b"0000644\0")?;
    write_field(&mut hdr, 108, b"0000000\0")?;
    write_field(&mut hdr, 116, b"0000000\0")?;
    let size_str = format!("{size:011o}\0");
    write_field(&mut hdr, 124, size_str.as_bytes())?;
    write_field(&mut hdr, 136, b"00000000000\0")?;
    write_field(&mut hdr, 148, b"        ")?;
    write_field(&mut hdr, 156, b"0")?;
    write_field(&mut hdr, 257, b"ustar\0")?;
    write_field(&mut hdr, 263, b"00")?;
    if !prefix.is_empty() {
        write_field(&mut hdr, 345, prefix.as_bytes())?;
    }

    let csum: u32 = hdr.iter().map(|b| u32::from(*b)).sum();
    let csum_str = format!("{csum:06o}\0 ");
    write_field(&mut hdr, 148, csum_str.as_bytes())?;
    Ok(hdr)
}

fn split_ustar_path(path: &str) -> Result<(&str, &str), TarError> {
    if path.len() <= 100 {
        return Ok(("", path));
    }
    for (idx, ch) in path.char_indices() {
        if ch == '/' {
            let prefix = path.get(..idx).unwrap_or("");
            let name = path.get(idx.saturating_add(1)..).unwrap_or("");
            if !prefix.is_empty() && prefix.len() <= 155 && !name.is_empty() && name.len() <= 100 {
                return Ok((prefix, name));
            }
        }
    }
    Err(TarError::InvalidPath(format!(
        "path `{path}` exceeds ustar name/prefix limits"
    )))
}

fn write_field(hdr: &mut [u8; BLOCK_BYTES], start: usize, bytes: &[u8]) -> Result<(), TarError> {
    let end = start.saturating_add(bytes.len());
    let Some(slot) = hdr.get_mut(start..end) else {
        return Err(TarError::MalformedArchive(
            "ustar header field out of range".into(),
        ));
    };
    slot.copy_from_slice(bytes);
    Ok(())
}

fn verify_header_checksum(hdr: &[u8]) -> Result<(), TarError> {
    let expected = parse_octal_field(hdr.get(148..156).unwrap_or(&[]))?;
    let mut sum: usize = 0;
    for (idx, byte) in hdr.iter().enumerate() {
        let val = if (148..156).contains(&idx) {
            usize::from(b' ')
        } else {
            usize::from(*byte)
        };
        sum = sum.saturating_add(val);
    }
    if sum != expected {
        return Err(TarError::MalformedArchive(
            "tar header checksum mismatch".into(),
        ));
    }
    Ok(())
}

fn extract_header_path(hdr: &[u8]) -> Result<String, TarError> {
    let name = cstr_utf8(hdr.get(0..100).unwrap_or(&[]))?;
    let prefix = cstr_utf8(hdr.get(345..500).unwrap_or(&[]))?;
    if prefix.is_empty() {
        Ok(name)
    } else {
        Ok(format!("{prefix}/{name}"))
    }
}

fn cstr_utf8(slice: &[u8]) -> Result<String, TarError> {
    let end = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
    let trimmed = slice.get(..end).unwrap_or(&[]);
    String::from_utf8(trimmed.to_vec())
        .map_err(|_| TarError::MalformedArchive("non-UTF-8 path in tar header".into()))
}

fn parse_octal_field(slice: &[u8]) -> Result<usize, TarError> {
    let text = cstr_utf8(slice)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(trimmed, 8)
        .map_err(|e| TarError::MalformedArchive(format!("invalid octal field `{trimmed}`: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_ustar_and_reject_traversal() {
        let entries = vec![
            TarEntry {
                path: "MANIFEST.txt".into(),
                bytes: b"manifest body\n".to_vec(),
            },
            TarEntry {
                path: "nested/long/subpath/file.json".into(),
                bytes: b"{\"ok\":true}".to_vec(),
            },
        ];
        let encoded = encode_tar(&entries).unwrap();
        let decoded = decode_tar(&encoded).unwrap();
        assert_eq!(decoded, entries);

        let traversal = vec![TarEntry {
            path: "../escape.txt".into(),
            bytes: b"bad".to_vec(),
        }];
        assert!(matches!(
            encode_tar(&traversal),
            Err(TarError::InvalidPath(_))
        ));

        let mut trailing = encoded.clone();
        trailing.extend_from_slice(&[b'A'; 512]);
        assert!(matches!(
            decode_tar(&trailing),
            Err(TarError::MalformedArchive(_))
        ));
        let truncated_end = encoded.len().saturating_sub(1024);
        assert!(matches!(
            decode_tar(encoded.get(..truncated_end).unwrap_or(&[])),
            Err(TarError::MalformedArchive(_))
        ));
    }
}
