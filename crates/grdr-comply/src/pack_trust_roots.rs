// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Fail-closed `trust-roots.toml` AST parser and strict semver comparison helpers.

use std::collections::BTreeSet;

use grdr_crypto::validate_public_key_b64;
use jiff::Timestamp;

use crate::ComplyError;
use crate::pack_toml::{opt_safe_str, reject_unsafe_toml_text, req_safe_str};
use crate::toml_ast::{TomlVal, parse_toml_document};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerTrustStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRootEntry {
    pub signer_ref: String,
    pub verifier_ed25519_b64: String,
    pub status: SignerTrustStatus,
    pub min_version: Option<String>,
    pub expires_at: Option<Timestamp>,
}

pub(crate) fn parse_trust_roots_toml(raw: &str) -> Result<Vec<TrustedRootEntry>, ComplyError> {
    reject_unsafe_toml_text(raw, "trust-roots.toml")?;
    let root = parse_toml_document(raw)?;
    for key in root.keys() {
        if !matches!(key.as_str(), "format" | "signers") {
            return Err(ComplyError::VerificationFailed {
                detail: format!("unknown trust-roots top key `{key}`"),
            });
        }
    }
    let format = req_safe_str(&root, "format", "trust-roots.toml")?;
    if format != "grdr.trust-roots.v1" {
        return Err(ComplyError::VerificationFailed {
            detail: format!("unexpected trust-roots format `{format}`"),
        });
    }
    let Some(TomlVal::Array(signers)) = root.get("signers") else {
        return Err(ComplyError::VerificationFailed {
            detail: "trust-roots missing `[[signers]]` entries".into(),
        });
    };

    let mut out = Vec::with_capacity(signers.len());
    let mut seen_refs = BTreeSet::new();
    let mut active_count = 0usize;
    for entry in signers {
        let TomlVal::Table(tbl) = entry else {
            return Err(ComplyError::VerificationFailed {
                detail: "trust-roots signer entry must be a table".into(),
            });
        };
        for key in tbl.keys() {
            if !matches!(
                key.as_str(),
                "signer_ref" | "verifier_ed25519_b64" | "status" | "min_version" | "expires_at"
            ) {
                return Err(ComplyError::VerificationFailed {
                    detail: format!("unknown signer key `{key}`"),
                });
            }
        }
        let signer_ref = req_safe_str(tbl, "signer_ref", "trust-roots signer")?;
        let pubkey = req_safe_str(tbl, "verifier_ed25519_b64", &signer_ref)?;
        validate_public_key_b64(&pubkey).map_err(|e| ComplyError::VerificationFailed {
            detail: format!("invalid Ed25519 public key for `{signer_ref}`: {e}"),
        })?;
        let status_raw = req_safe_str(tbl, "status", &signer_ref)?;
        let status = parse_signer_status(&status_raw)?;
        let min_version = opt_safe_str(tbl, "min_version")?;
        if let Some(ref min_v) = min_version {
            parse_semver_triple(min_v)?;
        }
        let expires_at = opt_safe_str(tbl, "expires_at")?
            .map(|s| {
                s.parse::<Timestamp>()
                    .map_err(|e| ComplyError::VerificationFailed {
                        detail: format!("invalid expires_at for `{signer_ref}`: {e}"),
                    })
            })
            .transpose()?;
        if !seen_refs.insert(signer_ref.to_ascii_lowercase()) {
            return Err(ComplyError::VerificationFailed {
                detail: format!("duplicate trust-root entry `{signer_ref}`"),
            });
        }
        if status == SignerTrustStatus::Active {
            active_count = active_count.saturating_add(1);
        }
        out.push(TrustedRootEntry {
            signer_ref,
            verifier_ed25519_b64: pubkey,
            status,
            min_version,
            expires_at,
        });
    }
    if active_count == 0 {
        return Err(ComplyError::VerificationFailed {
            detail: "trust-roots defines zero active signers".into(),
        });
    }
    Ok(out)
}

pub(crate) fn compare_semver(lhs: &str, rhs: &str) -> Result<std::cmp::Ordering, ComplyError> {
    Ok(parse_semver_triple(lhs)?.cmp(&parse_semver_triple(rhs)?))
}

pub(crate) fn parse_semver_triple(raw: &str) -> Result<(u64, u64, u64), ComplyError> {
    let mut parts = raw.split('.');
    let major = parts
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: format!("invalid semver major in `{raw}`"),
        })?;
    let minor = parts
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: format!("invalid semver minor in `{raw}`"),
        })?;
    let patch_raw = parts
        .next()
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: format!("invalid semver patch in `{raw}`"),
        })?;
    if parts.next().is_some() {
        return Err(ComplyError::VerificationFailed {
            detail: format!("unexpected semver extra segment in `{raw}`"),
        });
    }
    let patch_digits = patch_raw.split('-').next().unwrap_or(patch_raw);
    let patch = patch_digits
        .parse::<u64>()
        .map_err(|_| ComplyError::VerificationFailed {
            detail: format!("invalid semver patch in `{raw}`"),
        })?;
    Ok((major, minor, patch))
}

fn parse_signer_status(raw: &str) -> Result<SignerTrustStatus, ComplyError> {
    match raw {
        "active" => Ok(SignerTrustStatus::Active),
        "retired" => Ok(SignerTrustStatus::Retired),
        "revoked" => Ok(SignerTrustStatus::Revoked),
        other => Err(ComplyError::VerificationFailed {
            detail: format!("unknown signer status `{other}`"),
        }),
    }
}
