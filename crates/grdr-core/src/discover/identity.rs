// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Program identity grammar, runtime-signer exclusion, P8 HMAC scoping, and Pass 1 routing (`docs/design/05`).

use grdr_crypto::{domain_hmac_sha256, encode_lower_hex, sha256_hex};
use grdr_model::CodedError;
use serde::{Deserialize, Serialize};

const SCOPED_ID_HMAC_DOMAIN: &str = "grdr.discover.identity.v1";
pub const MIN_IDENTITY_HMAC_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramIdentity {
    CodeSigned {
        signer: String,
        digest: String,
    },
    PackageOwned {
        ecosystem: String,
        package: String,
        version: String,
    },
    ImageDigest {
        sha256: String,
    },
    SourceTree {
        workspace: String,
        digest: String,
    },
    RawPath {
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityHints {
    pub code_signer: Option<String>,
    pub binary_digest: Option<String>,
    pub ecosystem: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub image_sha256: Option<String>,
    pub image_repository: Option<String>,
    pub workspace_id: Option<String>,
    pub source_forge: Option<String>,
    pub entrypoint: Option<String>,
    pub tree_digest: Option<String>,
    pub executable_path: String,
    pub runtime_signers_excluded: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pass1MatchState {
    NotFound,
    Candidate,
    InstalledMatched,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInterpreterAttributes {
    pub runtime_name: String,
    pub runtime_version: Option<String>,
    pub entrypoint: Option<String>,
    pub runtime_signer_excluded: bool,
}

impl ProgramIdentity {
    #[must_use]
    pub fn canonical_id(&self) -> String {
        match self {
            Self::CodeSigned { signer, digest } => format!("sig:{signer}:{digest}"),
            Self::PackageOwned {
                ecosystem,
                package,
                version,
            } => format!("pkg:{ecosystem}:{package}@{version}"),
            Self::ImageDigest { sha256 } => format!("img:{sha256}"),
            Self::SourceTree { workspace, digest } => format!("src:{workspace}:{digest}"),
            Self::RawPath { path } => format!("path:{}", sha256_hex(path.as_bytes())),
        }
    }

    pub fn try_scoped_identity_id(
        &self,
        tenant_salt: &[u8],
        declared_public_owners: &[String],
    ) -> Result<String, CodedError> {
        if tenant_salt.len() < MIN_IDENTITY_HMAC_KEY_LEN {
            return Err(CodedError::new(
                "GRDR-SESS-0003",
                format!(
                    "identity HMAC salt length {} below minimum {MIN_IDENTITY_HMAC_KEY_LEN}",
                    tenant_salt.len()
                ),
                "Provide a CSPRNG >= 32-byte per-tenant HMAC key.",
            ));
        }
        Ok(match self {
            Self::CodeSigned { signer, .. } => format!("sig:{signer}"),
            Self::PackageOwned {
                ecosystem, package, ..
            } => format!("pkg:{ecosystem}:{package}"),
            Self::ImageDigest { sha256 } => {
                let public_registry_or_digest = sha256.starts_with("sha256:")
                    || (!sha256.contains('/') && sha256.bytes().all(|b| b.is_ascii_hexdigit()))
                    || is_public_owner_path(sha256, declared_public_owners);
                if public_registry_or_digest && !sha256.is_empty() {
                    format!("img:{sha256}")
                } else {
                    format!("img:hmac_{}", short_hmac(tenant_salt, sha256.as_bytes()))
                }
            }
            Self::SourceTree { workspace, digest } => {
                if is_public_owner_path(workspace, declared_public_owners) {
                    format!("src:{workspace}:{digest}")
                } else {
                    format!(
                        "src:hmac_{}",
                        short_hmac(tenant_salt, format!("{workspace}:{digest}").as_bytes())
                    )
                }
            }
            Self::RawPath { path } => {
                format!("path:hmac_{}", short_hmac(tenant_salt, path.as_bytes()))
            }
        })
    }

    #[must_use]
    pub fn from_hints(h: &IdentityHints) -> Self {
        fn ne(o: &Option<String>) -> Option<&str> {
            o.as_deref().filter(|s| !s.is_empty())
        }
        if let (Some(signer), Some(digest)) = (ne(&h.code_signer), ne(&h.binary_digest))
            && !is_signer_excluded(signer, &h.runtime_signers_excluded)
        {
            return Self::CodeSigned {
                signer: signer.into(),
                digest: digest.into(),
            };
        }
        if let (Some(eco), Some(pkg)) = (ne(&h.ecosystem), ne(&h.package_name)) {
            let version = ne(&h.package_version).unwrap_or("unknown").into();
            return Self::PackageOwned {
                ecosystem: eco.into(),
                package: pkg.into(),
                version,
            };
        }
        if let Some(repo) = ne(&h.image_repository) {
            return Self::ImageDigest {
                sha256: repo.into(),
            };
        }
        if let Some(sha) = ne(&h.image_sha256) {
            return Self::ImageDigest { sha256: sha.into() };
        }
        if let (Some(ws), Some(digest)) = (ne(&h.workspace_id), ne(&h.tree_digest)) {
            let full_ws = match (ne(&h.source_forge), ne(&h.entrypoint)) {
                (Some(forge), Some(entry)) => format!("{forge}/{ws}#{entry}"),
                (Some(forge), None) => format!("{forge}/{ws}"),
                (None, Some(entry)) => format!("{ws}#{entry}"),
                (None, None) => ws.to_string(),
            };
            return Self::SourceTree {
                workspace: full_ws,
                digest: digest.into(),
            };
        }
        Self::RawPath {
            path: normalize_template_path(&h.executable_path),
        }
    }
}

fn is_public_owner_path(path: &str, declared_public_owners: &[String]) -> bool {
    let lower = path.trim().to_ascii_lowercase();
    declared_public_owners.iter().any(|entry| {
        let pat = entry.trim().to_ascii_lowercase();
        !pat.is_empty() && (lower == pat || lower.starts_with(&format!("{pat}/")))
    })
}

#[must_use]
pub fn is_signer_excluded(signer: &str, excluded: &[String]) -> bool {
    let lower = signer.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    excluded.iter().any(|pattern| {
        let pat = pattern.trim().to_ascii_lowercase();
        if let Some(prefix) = pat.strip_suffix('*') {
            lower.starts_with(prefix)
        } else {
            lower == pat
        }
    })
}

#[must_use]
pub fn evaluate_pass1_routes(matched_route_count: usize) -> Pass1MatchState {
    match matched_route_count {
        0 => Pass1MatchState::NotFound,
        1 => Pass1MatchState::Candidate,
        _ => Pass1MatchState::InstalledMatched,
    }
}

#[must_use]
pub fn evaluate_pass1_with_attributes(
    matched_route_count: usize,
    attrs: Option<&RuntimeInterpreterAttributes>,
) -> Pass1MatchState {
    let base = evaluate_pass1_routes(matched_route_count);
    if base == Pass1MatchState::InstalledMatched
        && let Some(info) = attrs
        && info.runtime_signer_excluded
        && info
            .entrypoint
            .as_deref()
            .is_none_or(|e| e.trim().is_empty())
    {
        return Pass1MatchState::Candidate;
    }
    base
}

#[must_use]
pub fn canonical_sha256_hex(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

fn short_hmac(salt: &[u8], payload: &[u8]) -> String {
    let digest = domain_hmac_sha256(salt, SCOPED_ID_HMAC_DOMAIN, payload);
    let hex = encode_lower_hex(&digest);
    hex.chars().take(16).collect()
}

fn normalize_template_path(raw: &str) -> String {
    raw.trim().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_signer_falls_back_to_package_or_src_and_hmacs_private_paths() {
        let hints = IdentityHints {
            code_signer: Some("com.apple.python3".into()),
            binary_digest: Some("abc".into()),
            runtime_signers_excluded: vec!["com.apple.*".into()],
            ecosystem: Some("pypi".into()),
            package_name: Some("invoice-bot".into()),
            package_version: Some("1.0.0".into()),
            ..IdentityHints::default()
        };
        let id = ProgramIdentity::from_hints(&hints);
        assert_eq!(id.canonical_id(), "pkg:pypi:invoice-bot@1.0.0");

        let key = b"tenant-hmac-key-at-least-32-bytes";
        let private_src = ProgramIdentity::SourceTree {
            workspace: "git.internal/fin/bot".into(),
            digest: "d1".into(),
        };
        let declared = vec!["github.com/acme".to_string()];
        let scoped_priv = private_src.try_scoped_identity_id(key, &declared).unwrap();
        assert!(scoped_priv.starts_with("src:hmac_"));
        assert!(!scoped_priv.contains("fin/bot"));

        let pub_src = ProgramIdentity::SourceTree {
            workspace: "github.com/acme/bot".into(),
            digest: "d1".into(),
        };
        let scoped_pub = pub_src.try_scoped_identity_id(key, &declared).unwrap();
        assert_eq!(scoped_pub, "src:github.com/acme/bot:d1");

        // Private corporate image repository is HMACed even when containing '/'.
        let priv_img = ProgramIdentity::ImageDigest {
            sha256: "corp-registry.internal/team/agent".into(),
        };
        let scoped_img = priv_img.try_scoped_identity_id(key, &declared).unwrap();
        assert!(scoped_img.starts_with("img:hmac_"));
        assert!(!scoped_img.contains("corp-registry"));

        // Non-org owner under github.com is also HMACed when only github.com/acme is declared.
        let other_org_src = ProgramIdentity::SourceTree {
            workspace: "github.com/private-corp/secret-bot".into(),
            digest: "d1".into(),
        };
        let scoped_other = other_org_src
            .try_scoped_identity_id(key, &declared)
            .unwrap();
        assert!(scoped_other.starts_with("src:hmac_"));

        assert!(
            priv_img
                .try_scoped_identity_id(b"short", &declared)
                .is_err()
        );
    }
}
