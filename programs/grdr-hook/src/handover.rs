// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Strict JSON `HandoverMarker` v1 reader and bounded window validator (`0 < rem <= 2000ms`).

use std::io::Read;
use std::path::Path;

use grdr_peer_os::fs_open::{
    OpenNofollowAccess, open_nofollow_dir, open_nofollow_file, verify_open_dir_trust,
    verify_open_file_trust,
};

use crate::json_lexer::JsonScanner;

pub const HANDOVER_MARKER_MAX_MS: u64 = 2000;
const MAX_HANDOVER_MARKER_BYTES: u64 = 65_536;
const MAX_HANDOVER_SKIP_DEPTH: usize = 8;

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum HandoverMarkerStatus {
    #[default]
    MissingOrOther,
    Active,
}

#[derive(Default)]
struct HandoverFields {
    version: Option<u64>,
    marker_status: HandoverMarkerStatus,
    created_mono_ms: Option<u64>,
    expires_mono_ms: Option<u64>,
}

/// Validate `<state_dir>/handover` (`grdr-updater` JSON `HandoverMarker` v1)
/// and return remaining milliseconds only inside `(0..=2000]`.
#[must_use]
pub fn active_handover_remaining_ms(state_dir: &Path, now_ms: u64) -> Option<u64> {
    active_handover_remaining_ms_for_profile(state_dir, now_ms, false)
}

/// Validate `<state_dir>/handover` enforcing profile-appropriate directory and file trust.
#[must_use]
pub fn active_handover_remaining_ms_for_profile(
    state_dir: &Path,
    now_ms: u64,
    protected: bool,
) -> Option<u64> {
    let dir_file = open_nofollow_dir(state_dir).ok()?;
    if verify_open_dir_trust(&dir_file, state_dir, protected).is_err() {
        return None;
    }
    let marker = state_dir.join("handover");
    let file = open_nofollow_file(&marker, OpenNofollowAccess::ReadOnly, 0o600).ok()?;
    let meta = file.metadata().ok()?;
    if meta.len() > MAX_HANDOVER_MARKER_BYTES {
        return None;
    }
    if verify_open_file_trust(&file, protected).is_err() {
        return None;
    }
    let mut buf = Vec::new();
    file.take(MAX_HANDOVER_MARKER_BYTES.saturating_add(1))
        .read_to_end(&mut buf)
        .ok()?;
    let cap = usize::try_from(MAX_HANDOVER_MARKER_BYTES).unwrap_or(usize::MAX);
    if buf.len() > cap {
        return None;
    }
    let raw = std::str::from_utf8(&buf).ok()?.trim();
    if !raw.starts_with('{') || !raw.ends_with('}') {
        return None;
    }
    let expires_ms = parse_handover_marker_json(raw, now_ms)?;
    let remaining = expires_ms.checked_sub(now_ms)?;
    if remaining == 0 || remaining > HANDOVER_MARKER_MAX_MS {
        None
    } else {
        Some(remaining)
    }
}

fn parse_handover_marker_json(raw: &str, now_ms: u64) -> Option<u64> {
    let mut scanner = JsonScanner::new(raw.as_bytes());
    let mut fields = HandoverFields::default();
    scan_handover_object(&mut scanner, &mut fields).ok()?;
    scanner.skip_ws();
    if scanner.pos() != raw.len() {
        return None;
    }
    if fields.version != Some(1) || fields.marker_status != HandoverMarkerStatus::Active {
        return None;
    }
    let created = fields.created_mono_ms?;
    let expires = fields.expires_mono_ms?;
    if now_ms < created {
        return None;
    }
    let window = expires.checked_sub(created)?;
    if window == 0 || window > HANDOVER_MARKER_MAX_MS {
        return None;
    }
    Some(expires)
}

fn scan_handover_object(scanner: &mut JsonScanner<'_>, out: &mut HandoverFields) -> Result<(), ()> {
    scanner.skip_ws();
    if scanner.next() != Some(b'{') {
        return Err(());
    }
    scanner.skip_ws();
    if scanner.peek() == Some(b'}') {
        scanner.advance(1);
        return Ok(());
    }
    loop {
        scanner.skip_ws();
        let key = scanner.read_string().map_err(|_| ())?;
        scanner.skip_ws();
        if scanner.next() != Some(b':') {
            return Err(());
        }
        scanner.skip_ws();
        match scanner.peek() {
            Some(b'"') => {
                let val = scanner.read_string().map_err(|_| ())?;
                if key == "marker_status" {
                    out.marker_status = if val == "active" {
                        HandoverMarkerStatus::Active
                    } else {
                        HandoverMarkerStatus::MissingOrOther
                    };
                }
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = scanner.pos();
                scanner.skip_number().map_err(|_| ())?;
                let end = scanner.pos();
                if matches!(
                    key.as_str(),
                    "version" | "created_mono_ms" | "expires_mono_ms"
                ) {
                    let slice = scanner.slice_bytes(start, end).ok_or(())?;
                    let text = std::str::from_utf8(slice).map_err(|_| ())?;
                    let num = text.parse::<u64>().ok();
                    match key.as_str() {
                        "version" => out.version = num,
                        "created_mono_ms" => out.created_mono_ms = num,
                        "expires_mono_ms" => out.expires_mono_ms = num,
                        _ => {}
                    }
                }
            }
            Some(b't' | b'f' | b'n') => scanner.skip_keyword().map_err(|_| ())?,
            Some(b'{' | b'[') => skip_nested_value(scanner, 1)?,
            _ => return Err(()),
        }
        scanner.skip_ws();
        match scanner.next() {
            Some(b',') => continue,
            Some(b'}') => return Ok(()),
            _ => return Err(()),
        }
    }
}

fn skip_nested_value(scanner: &mut JsonScanner<'_>, depth: usize) -> Result<(), ()> {
    if depth > MAX_HANDOVER_SKIP_DEPTH {
        return Err(());
    }
    scanner.skip_ws();
    match scanner.peek() {
        Some(b'"') => {
            let _ = scanner.read_string().map_err(|_| ())?;
            Ok(())
        }
        Some(b't' | b'f' | b'n') => scanner.skip_keyword().map_err(|_| ()),
        Some(b'-' | b'0'..=b'9') => scanner.skip_number().map_err(|_| ()),
        Some(b'{') => {
            let _ = scanner.next();
            scanner.skip_ws();
            if scanner.peek() == Some(b'}') {
                scanner.advance(1);
                return Ok(());
            }
            loop {
                scanner.skip_ws();
                let _ = scanner.read_string().map_err(|_| ())?;
                scanner.skip_ws();
                if scanner.next() != Some(b':') {
                    return Err(());
                }
                skip_nested_value(scanner, depth.saturating_add(1))?;
                scanner.skip_ws();
                match scanner.next() {
                    Some(b',') => continue,
                    Some(b'}') => return Ok(()),
                    _ => return Err(()),
                }
            }
        }
        Some(b'[') => {
            let _ = scanner.next();
            scanner.skip_ws();
            if scanner.peek() == Some(b']') {
                scanner.advance(1);
                return Ok(());
            }
            loop {
                skip_nested_value(scanner, depth.saturating_add(1))?;
                scanner.skip_ws();
                match scanner.next() {
                    Some(b',') => continue,
                    Some(b']') => return Ok(()),
                    _ => return Err(()),
                }
            }
        }
        _ => Err(()),
    }
}
