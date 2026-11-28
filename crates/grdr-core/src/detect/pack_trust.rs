// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Trust-root manifest parser and strict Ed25519 signature helper for signed detection/policy packs.

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use grdr_crypto::{validate_public_key_b64, verify_ed25519_raw};

use crate::detect::types::DetectError;

const TRUST_ROOTS_FORMAT: &str = "grdr.trust-roots.v1";

/// Parses active Ed25519 signers from `trust-roots.toml`.
pub fn parse_trust_roots_toml(raw_toml: &str) -> Result<BTreeMap<String, String>, DetectError> {
    let mut format_seen = false;
    let mut active_signers = BTreeMap::new();
    let mut seen_refs = BTreeSet::new();
    let mut in_signer = false;
    let mut signer_keys = BTreeSet::new();
    let mut signer_ref: Option<String> = None;
    let mut pub_b64: Option<String> = None;
    let mut status: Option<String> = None;

    for raw_line in raw_toml.lines() {
        let line = strip_toml_line_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[signers]]" {
            flush_signer(
                &mut in_signer,
                &mut signer_keys,
                &mut signer_ref,
                &mut pub_b64,
                &mut status,
                &mut seen_refs,
                &mut active_signers,
            )?;
            in_signer = true;
            continue;
        }
        if line.starts_with('[') {
            return Err(DetectError::ResponseBreaker(format!(
                "unexpected TOML section `{line}` in trust-roots.toml"
            )));
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(DetectError::ResponseBreaker(format!(
                "malformed TOML line `{line}` in trust-roots.toml"
            )));
        };
        let key = k.trim();
        let val = parse_toml_quoted_str(v.trim())?;
        if !in_signer {
            if key != "format" || format_seen {
                return Err(DetectError::ResponseBreaker(format!(
                    "unexpected or duplicate top-level key `{key}` in trust-roots.toml"
                )));
            }
            if val != TRUST_ROOTS_FORMAT {
                return Err(DetectError::ResponseBreaker(format!(
                    "unexpected trust-roots format `{val}`"
                )));
            }
            format_seen = true;
            continue;
        }
        if !signer_keys.insert(key.to_owned()) {
            return Err(DetectError::ResponseBreaker(format!(
                "duplicate key `{key}` in trust-roots signer entry"
            )));
        }
        match key {
            "signer_ref" => signer_ref = Some(val),
            "verifier_ed25519_b64" => pub_b64 = Some(val),
            "status" => status = Some(val),
            other => {
                return Err(DetectError::ResponseBreaker(format!(
                    "unknown trust-roots signer key `{other}`"
                )));
            }
        }
    }
    flush_signer(
        &mut in_signer,
        &mut signer_keys,
        &mut signer_ref,
        &mut pub_b64,
        &mut status,
        &mut seen_refs,
        &mut active_signers,
    )?;

    if !format_seen || active_signers.is_empty() {
        return Err(DetectError::ResponseBreaker(
            "trust-roots.toml missing valid format or active signers".into(),
        ));
    }
    Ok(active_signers)
}

fn flush_signer(
    in_s: &mut bool,
    keys: &mut BTreeSet<String>,
    sref: &mut Option<String>,
    pubk: &mut Option<String>,
    st: &mut Option<String>,
    seen: &mut BTreeSet<String>,
    out: &mut BTreeMap<String, String>,
) -> Result<(), DetectError> {
    if !*in_s {
        return Ok(());
    }
    *in_s = false;
    keys.clear();
    let r = sref.take().ok_or_else(|| {
        DetectError::ResponseBreaker("trust-roots signer missing `signer_ref`".into())
    })?;
    let p = pubk.take().ok_or_else(|| {
        DetectError::ResponseBreaker("trust-roots signer missing `verifier_ed25519_b64`".into())
    })?;
    let s = st.take().ok_or_else(|| {
        DetectError::ResponseBreaker("trust-roots signer missing `status`".into())
    })?;
    validate_public_key_b64(&p).map_err(|e| {
        DetectError::ResponseBreaker(format!("invalid Ed25519 key for signer `{r}`: {e}"))
    })?;
    if !seen.insert(r.clone()) {
        return Err(DetectError::ResponseBreaker(format!(
            "duplicate `signer_ref` `{r}` in trust-roots.toml"
        )));
    }
    match s.as_str() {
        "active" => {
            out.insert(r, p);
        }
        "revoked" | "retired" => {}
        other => {
            return Err(DetectError::ResponseBreaker(format!(
                "unknown trust-roots signer status `{other}`"
            )));
        }
    }
    Ok(())
}

pub(crate) fn verify_pack_ed25519_strict(
    public_key_b64: &str,
    domain: &str,
    payload: &[u8],
    signature_b64: &str,
) -> Result<(), DetectError> {
    if domain.as_bytes().contains(&0) {
        return Err(DetectError::ResponseBreaker(
            "signature domain contains NUL byte".into(),
        ));
    }
    let pub_vec = B64
        .decode(public_key_b64.trim())
        .map_err(|e| DetectError::ResponseBreaker(format!("invalid Ed25519 key base64: {e}")))?;
    let pub_arr: [u8; 32] = pub_vec
        .try_into()
        .map_err(|_| DetectError::ResponseBreaker("Ed25519 key must be 32 bytes".into()))?;
    let sig_vec = B64
        .decode(signature_b64.trim())
        .map_err(|e| DetectError::ResponseBreaker(format!("invalid Ed25519 sig base64: {e}")))?;
    let sig_arr: [u8; 64] = sig_vec
        .try_into()
        .map_err(|_| DetectError::ResponseBreaker("Ed25519 signature must be 64 bytes".into()))?;
    let mut msg = Vec::with_capacity(
        12usize
            .saturating_add(domain.len())
            .saturating_add(payload.len()),
    );
    msg.extend_from_slice(b"grdr.sig.v1\0");
    msg.extend_from_slice(domain.as_bytes());
    msg.push(0);
    msg.extend_from_slice(payload);
    verify_ed25519_raw(&pub_arr, &msg, &sig_arr).map_err(|_| {
        DetectError::ResponseBreaker("Ed25519 pack signature verification failed".into())
    })
}

pub(crate) fn is_lower_hex_sha256(val: &str) -> bool {
    val.len() == 64 && val.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn strip_toml_line_comment(raw: &str) -> &str {
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

fn parse_toml_quoted_str(raw: &str) -> Result<String, DetectError> {
    let inner = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| {
            DetectError::ResponseBreaker("expected quoted TOML string in trust-roots".into())
        })?;
    if inner.contains('\\') || inner.contains('"') || inner.chars().any(char::is_control) {
        return Err(DetectError::ResponseBreaker(
            "invalid escape or control character in trust-roots string".into(),
        ));
    }
    Ok(inner.to_owned())
}
