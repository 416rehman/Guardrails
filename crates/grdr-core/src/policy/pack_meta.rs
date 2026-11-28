// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Strict P7 `pack.toml` parser and cryptographically verified Cedar policy pack directory loader (`D-12`, `P7`, `P14`).

use std::collections::BTreeSet;
use std::path::Path;

use grdr_crypto::sha256_hex;

use super::PolicyError;
use super::essentials_cedar::{PackTomlMeta, compile_cedar_pack_from_sources};
use crate::analyze::pack_io::{
    collect_signed_pack_digests, ensure_real_dir, essentials_max_bytes, pack_list_max_bytes,
    read_bounded_regular_bytes, read_bounded_regular_text, safe_pack_child_path,
};
use crate::detect::pack_sig::verify_pack_signature_json;

const MAX_PACK_TOML_BYTES: u64 = 65_536;
const MAX_CEDAR_SIG_BYTES: u64 = 1_048_576;
const EMBEDDED_TRUST_ROOTS_TOML: &str = include_str!("../../../../packs/trust-roots.toml");

#[derive(Clone, Copy, PartialEq, Eq)]
enum PackTomlSection {
    Root,
    Reads,
}

#[derive(Default)]
struct PendingReadEntry {
    seen_keys: BTreeSet<String>,
    path: Option<String>,
    data_class: Option<String>,
}

/// Parses and enforces strict P7 compliance for a Cedar policy `pack.toml`.
pub(crate) fn parse_pack_toml_meta(src: &str) -> Result<PackTomlMeta, PolicyError> {
    if u64::try_from(src.len()).unwrap_or(u64::MAX) > MAX_PACK_TOML_BYTES {
        return Err(pack_toml_err("pack.toml exceeds byte bound"));
    }
    let mut section = PackTomlSection::Root;
    let mut root_keys = BTreeSet::new();
    let mut id = None;
    let mut version = None;
    let mut kind = String::from("policy");
    let mut per_person = None;
    let mut declared_reads = BTreeSet::new();
    let mut pending_read: Option<PendingReadEntry> = None;

    for raw_line in src.lines() {
        let line = strip_toml_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[reads]]" {
            flush_read_entry(&mut pending_read, &mut declared_reads)?;
            section = PackTomlSection::Reads;
            pending_read = Some(PendingReadEntry::default());
            continue;
        }
        if line.starts_with('[') {
            return Err(pack_toml_err(&format!(
                "unexpected TOML section `{line}` in pack.toml"
            )));
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(pack_toml_err(&format!(
                "malformed TOML line `{line}` in pack.toml"
            )));
        };
        let key = k.trim();
        let val = v.trim();
        if key.is_empty() || key.contains('.') || key.starts_with('"') || key.starts_with('\'') {
            return Err(pack_toml_err(&format!(
                "invalid TOML key `{key}` in pack.toml"
            )));
        }
        match section {
            PackTomlSection::Root => {
                if !root_keys.insert(key.to_owned()) {
                    return Err(pack_toml_err(&format!(
                        "duplicate root key `{key}` in pack.toml"
                    )));
                }
                match key {
                    "id" => id = Some(parse_toml_quoted(val, "id")?),
                    "version" => version = Some(parse_toml_quoted(val, "version")?),
                    "kind" => kind = parse_toml_quoted(val, "kind")?,
                    "per_person_scoring" => match val {
                        "false" => per_person = Some(false),
                        "true" => per_person = Some(true),
                        _ => {
                            return Err(pack_toml_err(
                                "`per_person_scoring` must be a boolean `false`",
                            ));
                        }
                    },
                    "commands"
                    | "executables"
                    | "urls"
                    | "env_vars_to_set"
                    | "mcp_servers_to_start" => {
                        if val != "[]" {
                            return Err(pack_toml_err(&format!(
                                "P7 forbidden active capability `{key}` must be empty"
                            )));
                        }
                    }
                    other => {
                        return Err(pack_toml_err(&format!(
                            "unknown or disallowed pack.toml key `{other}`"
                        )));
                    }
                }
            }
            PackTomlSection::Reads => {
                let entry = pending_read.as_mut().ok_or_else(|| {
                    pack_toml_err("internal parser state missing `[[reads]]` entry")
                })?;
                if !entry.seen_keys.insert(key.to_owned()) {
                    return Err(pack_toml_err(&format!(
                        "duplicate `[[reads]]` key `{key}` in pack.toml"
                    )));
                }
                match key {
                    "path" => entry.path = Some(parse_toml_quoted(val, "reads.path")?),
                    "data_class" => {
                        let dc = parse_toml_quoted(val, "reads.data_class")?;
                        if !matches!(dc.as_str(), "structural" | "derived" | "sensitive") {
                            return Err(pack_toml_err(&format!(
                                "invalid `reads.data_class` `{dc}` in pack.toml"
                            )));
                        }
                        entry.data_class = Some(dc);
                    }
                    other => {
                        return Err(pack_toml_err(&format!(
                            "unknown key `{other}` inside `[[reads]]`"
                        )));
                    }
                }
            }
        }
    }

    flush_read_entry(&mut pending_read, &mut declared_reads)?;

    if per_person != Some(false) {
        return Err(pack_toml_err(
            "pack.toml must set `per_person_scoring = false`",
        ));
    }
    let id = id
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| pack_toml_err("pack.toml missing required `id`"))?;
    let version = version
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| pack_toml_err("pack.toml missing required `version`"))?;
    Ok(PackTomlMeta {
        id,
        version,
        kind,
        declared_reads,
    })
}

/// Loads, cryptographically verifies, and compiles a signed Cedar policy pack directory against embedded trust roots.
pub fn load_cedar_policy_pack_from_dir(
    pack_dir: &Path,
) -> Result<grdr_model::PolicyPack, PolicyError> {
    let pack_toml_path =
        safe_pack_child_path(pack_dir, "pack.toml").map_err(|d| pack_io_err("pack.toml", d))?;
    let max_bytes = essentials_max_bytes().map_err(|d| pack_io_err("pack.limits", d))?;
    let pack_toml = read_bounded_regular_text(&pack_toml_path, MAX_PACK_TOML_BYTES.min(max_bytes))
        .map_err(|d| pack_io_err("pack.toml", d))?;
    let meta = parse_pack_toml_meta(&pack_toml)?;
    load_signed_cedar_pack_with_trust_roots(pack_dir, EMBEDDED_TRUST_ROOTS_TOML, &meta.id)
}

/// Loads, cryptographically verifies, and compiles a signed Cedar policy pack directory against `trust_roots_path`.
pub fn load_signed_cedar_policy_pack_from_dir(
    pack_dir: &Path,
    trust_roots_path: &Path,
    expected_pack_id: &str,
) -> Result<grdr_model::PolicyPack, PolicyError> {
    let trust_cap = pack_list_max_bytes().map_err(|d| pack_io_err("pack.trust", d))?;
    let trust_raw = read_bounded_regular_text(trust_roots_path, trust_cap)
        .map_err(|d| pack_io_err("pack.trust", d))?;
    load_signed_cedar_pack_with_trust_roots(pack_dir, &trust_raw, expected_pack_id)
}

fn load_signed_cedar_pack_with_trust_roots(
    pack_dir: &Path,
    trust_roots_toml: &str,
    expected_pack_id: &str,
) -> Result<grdr_model::PolicyPack, PolicyError> {
    ensure_real_dir(pack_dir, "policy pack dir").map_err(|d| pack_io_err("pack.dir", d))?;
    let max_bytes = essentials_max_bytes().map_err(|d| pack_io_err("pack.limits", d))?;
    let sig_path = safe_pack_child_path(pack_dir, "signature.json")
        .map_err(|d| pack_io_err("pack.signature", d))?;
    let sig_raw = read_bounded_regular_text(&sig_path, MAX_CEDAR_SIG_BYTES.min(max_bytes))
        .map_err(|d| pack_io_err("pack.signature", d))?;
    let verified = verify_pack_signature_json(&sig_raw, trust_roots_toml, expected_pack_id)
        .map_err(|e| pack_io_err("pack.signature", e.to_string()))?;

    let mut cumulative_bytes: u64 = 0;
    for (_, expected_len) in verified.verified_file_sha256s.values() {
        cumulative_bytes = cumulative_bytes
            .checked_add(*expected_len)
            .filter(|sum| *sum <= max_bytes)
            .ok_or_else(|| {
                pack_io_err(
                    "pack.limits",
                    "signed Cedar policy pack exceeds schema byte cap".into(),
                )
            })?;
    }

    let mut pack_toml = None;
    let mut cedar_sources = Vec::new();
    for (rel_path, (expected_sha, expected_len)) in &verified.verified_file_sha256s {
        let full = safe_pack_child_path(pack_dir, rel_path)
            .map_err(|d| pack_io_err("pack.manifest", d))?;
        let bytes = read_bounded_regular_bytes(&full, max_bytes)
            .map_err(|d| pack_io_err("pack.manifest", d))?;
        let actual_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual_len != *expected_len || sha256_hex(&bytes) != *expected_sha {
            return Err(pack_io_err(
                "pack.manifest",
                format!("signed file digest or length mismatch for `{rel_path}`"),
            ));
        }
        if rel_path == "pack.toml" {
            let text = String::from_utf8(bytes)
                .map_err(|_| pack_io_err("pack.toml", "pack.toml is not valid UTF-8".into()))?;
            pack_toml = Some(text);
        } else if rel_path.starts_with("rules/") && rel_path.ends_with(".cedar") {
            let text = String::from_utf8(bytes)
                .map_err(|_| pack_io_err("pack.rules", format!("`{rel_path}` is not UTF-8")))?;
            cedar_sources.push(text);
        }
    }

    let actual_digests = collect_signed_pack_digests(pack_dir, max_bytes, max_bytes)
        .map_err(|d| pack_io_err("pack.parity", d))?;
    if actual_digests.len() != verified.verified_file_sha256s.len() {
        return Err(pack_io_err(
            "pack.parity",
            "policy pack directory contains extra unsigned files".into(),
        ));
    }
    for (rel_path, actual_sha, actual_len) in actual_digests {
        let Some((expected_sha, expected_len)) = verified.verified_file_sha256s.get(&rel_path)
        else {
            return Err(pack_io_err(
                "pack.parity",
                format!("unsigned file `{rel_path}` present in signed policy directory"),
            ));
        };
        if actual_len != *expected_len || actual_sha != *expected_sha {
            return Err(pack_io_err(
                "pack.parity",
                format!("directory parity mismatch on `{rel_path}`"),
            ));
        }
    }

    let pack_toml = pack_toml
        .ok_or_else(|| pack_io_err("pack.toml", "signed pack missing `pack.toml`".into()))?;
    if cedar_sources.is_empty() {
        return Err(pack_io_err(
            "pack.rules",
            "signed pack contains zero `.cedar` files under `rules/`".into(),
        ));
    }
    compile_cedar_pack_from_sources(&pack_toml, &cedar_sources.join("\n"))
}

fn flush_read_entry(
    pending: &mut Option<PendingReadEntry>,
    out: &mut BTreeSet<String>,
) -> Result<(), PolicyError> {
    let Some(entry) = pending.take() else {
        return Ok(());
    };
    let path = entry
        .path
        .ok_or_else(|| pack_toml_err("`[[reads]]` entry missing required `path`"))?;
    if path.is_empty() || path == "*" || path.contains('*') || path.chars().any(char::is_whitespace)
    {
        return Err(pack_toml_err(&format!(
            "wildcard or invalid `[[reads]]` path `{path}` forbidden by P7"
        )));
    }
    let _ = entry
        .data_class
        .ok_or_else(|| pack_toml_err("`[[reads]]` entry missing required `data_class`"))?;
    out.insert(path);
    Ok(())
}

fn strip_toml_comment(raw: &str) -> &str {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quotes {
            match ch {
                '\\' => escaped = true,
                '"' => in_quotes = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => in_quotes = true,
            '#' => return raw.get(..idx).unwrap_or(raw),
            _ => {}
        }
    }
    raw
}

fn parse_toml_quoted(raw: &str, field: &str) -> Result<String, PolicyError> {
    let inner = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| pack_toml_err(&format!("expected quoted string for `{field}`")))?;
    if inner.contains('\\') || inner.contains('"') || inner.chars().any(char::is_control) {
        return Err(pack_toml_err(&format!(
            "invalid escape or control character in `{field}`"
        )));
    }
    Ok(inner.to_owned())
}

fn pack_toml_err(detail: &str) -> PolicyError {
    PolicyError::ValidationFailed {
        rule_id: "pack.toml".into(),
        detail: detail.to_owned(),
    }
}

fn pack_io_err(rule_id: &str, detail: String) -> PolicyError {
    PolicyError::ValidationFailed {
        rule_id: rule_id.into(),
        detail,
    }
}
