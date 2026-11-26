// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! External pack trust-root manifest loader (`packs/trust-roots.toml`).

use std::collections::BTreeSet;
use std::path::Path;

use grdr_crypto::validate_public_key_b64;

use crate::ConformanceError;
use crate::pack_manifest::{conf_err, read_regular_text};
use crate::pack_toml::{TomlVal, parse_toml_document};

pub(crate) const TRUST_ROOTS_FILENAME: &str = "trust-roots.toml";
const TRUST_ROOTS_FORMAT: &str = "grdr.trust-roots.v1";

pub fn load_pack_trust_roots(
    trust_roots_path: &Path,
) -> Result<Vec<(String, String)>, ConformanceError> {
    let raw = read_regular_text(trust_roots_path)?;
    let root = parse_toml_document(&raw)?;
    for key in root.keys() {
        if !matches!(key.as_str(), "format" | "signers") {
            return Err(conf_err(
                "pack-trust",
                &format!(
                    "unknown top-level key `{key}` in `{}`",
                    trust_roots_path.display()
                ),
            ));
        }
    }
    let format = match root.get("format") {
        Some(TomlVal::Str(s)) => s.as_str(),
        _ => {
            return Err(conf_err(
                "pack-trust",
                &format!("missing `format` in `{}`", trust_roots_path.display()),
            ));
        }
    };
    if format != TRUST_ROOTS_FORMAT {
        return Err(conf_err(
            "pack-trust",
            &format!("unexpected trust-roots format `{format}`"),
        ));
    }
    let Some(TomlVal::Array(signers)) = root.get("signers") else {
        return Err(conf_err(
            "pack-trust",
            &format!(
                "missing `[[signers]]` table array in `{}`",
                trust_roots_path.display()
            ),
        ));
    };

    let mut active = Vec::new();
    let mut seen_refs = BTreeSet::new();
    for entry in signers {
        let TomlVal::Table(tbl) = entry else {
            return Err(conf_err(
                "pack-trust",
                "`[[signers]]` entry must be a table",
            ));
        };
        for key in tbl.keys() {
            if !matches!(
                key.as_str(),
                "signer_ref" | "verifier_ed25519_b64" | "status"
            ) {
                return Err(conf_err(
                    "pack-trust",
                    &format!("unknown signer field `{key}` in trust roots"),
                ));
            }
        }
        let signer_ref = match tbl.get("signer_ref") {
            Some(TomlVal::Str(s)) if !s.trim().is_empty() => s.trim().to_owned(),
            _ => {
                return Err(conf_err(
                    "pack-trust",
                    "missing `signer_ref` in trust roots",
                ));
            }
        };
        let pubkey_b64 = match tbl.get("verifier_ed25519_b64") {
            Some(TomlVal::Str(s)) if !s.trim().is_empty() => s.trim().to_owned(),
            _ => {
                return Err(conf_err(
                    "pack-trust",
                    &format!("missing `verifier_ed25519_b64` for signer `{signer_ref}`"),
                ));
            }
        };
        validate_public_key_b64(&pubkey_b64).map_err(|e| {
            conf_err(
                "pack-trust",
                &format!("invalid Ed25519 key for signer `{signer_ref}`: {e}"),
            )
        })?;
        let status = match tbl.get("status") {
            Some(TomlVal::Str(s)) if !s.trim().is_empty() => s.trim(),
            _ => {
                return Err(conf_err(
                    "pack-trust",
                    &format!("missing `status` for signer `{signer_ref}`"),
                ));
            }
        };
        if !matches!(status, "active" | "retired" | "revoked") {
            return Err(conf_err(
                "pack-trust",
                &format!("unknown signer status `{status}` for `{signer_ref}`"),
            ));
        }
        if !seen_refs.insert(signer_ref.clone()) {
            return Err(conf_err(
                "pack-trust",
                &format!("duplicate trust-root entry `{signer_ref}`"),
            ));
        }
        if status == "active" {
            active.push((signer_ref, pubkey_b64));
        }
    }

    if active.is_empty() {
        return Err(conf_err(
            "pack-trust",
            &format!("no active pack signers in `{}`", trust_roots_path.display()),
        ));
    }
    Ok(active)
}
