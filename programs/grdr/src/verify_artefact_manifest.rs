// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Signed release-manifest DSSE/TUF attestation, trusted-root binding, and OIDC/SLSA checks.

use std::path::Path;

use grdr_crypto::constant_time_eq;
use grdr_update::{
    DsseEnvelope, DsseLimits, RootMetadata, SignedMetadata, SigstoreTrustedRoot, TargetsMetadata,
    UpdateError, UpdateTrust, canonical_sha256, verify_dsse_envelope_with_limits,
};
use jiff::Timestamp;

use crate::airgap::AirgapCliError;
use crate::airgap::verify_artefact_binding::{
    MAX_META_JSON_BYTES, read_file_bounded, read_json_meta,
};
use crate::airgap::verify_artefact_sigstore::VerifyArtefactPolicy;
use crate::airgap::verify_artefact_types::RELEASE_MANIFEST_PAYLOAD_TYPE;

#[allow(clippy::too_many_arguments)]
pub fn verify_release_manifest_binding(
    manifest_path: &Path,
    manifest_dsse_path: Option<&Path>,
    verified_tuf_root: Option<&SignedMetadata<RootMetadata>>,
    tuf_root_sha256: Option<&str>,
    verified_targets: Option<&SignedMetadata<TargetsMetadata>>,
    trusted_root: &SigstoreTrustedRoot,
    trusted_root_sha256: &str,
    policy: &VerifyArtefactPolicy<'_>,
    artefact_sha256: &str,
    now: Timestamp,
) -> Result<(), AirgapCliError> {
    let raw = read_file_bounded(manifest_path, MAX_META_JSON_BYTES)?;
    let manifest_sha = canonical_sha256(&raw);

    let verified_payload = if let Some(dsse_path) = manifest_dsse_path {
        let Some(tuf_root) = verified_tuf_root else {
            return Err(UpdateError::UnauthorizedRoot(
                "--release-manifest-dsse requires --tuf-root".into(),
            )
            .into());
        };
        let env: DsseEnvelope = read_json_meta(dsse_path, "release-manifest DSSE")?;
        if env.payload_type != RELEASE_MANIFEST_PAYLOAD_TYPE {
            return Err(UpdateError::MalformedMetadata(format!(
                "unexpected release-manifest DSSE payloadType `{}`",
                env.payload_type
            ))
            .into());
        }
        let payload = verify_manifest_dsse(&env, tuf_root, now)?;
        if payload != raw {
            return Err(UpdateError::ArtifactIntegrity {
                target: manifest_path.display().to_string(),
                detail: "release-manifest bytes diverge from signed DSSE payload".into(),
            }
            .into());
        }
        payload
    } else if let Some(targets_meta) = verified_targets {
        let len_u64 = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        if !targets_meta
            .signed
            .targets
            .values()
            .any(|d| d.sha256 == manifest_sha && d.length == len_u64)
        {
            return Err(UpdateError::UnauthorizedRoot(
                "unsigned release-manifest not attested in verified --tuf-targets".into(),
            )
            .into());
        }
        raw
    } else {
        return Err(UpdateError::UnauthorizedRoot(
            "--release-manifest requires --release-manifest-dsse + --tuf-root or verified --tuf-targets attestation"
                .into(),
        )
        .into());
    };

    check_manifest_policy_and_artefact(
        &verified_payload,
        manifest_path,
        trusted_root,
        trusted_root_sha256,
        verified_tuf_root,
        tuf_root_sha256,
        policy,
        artefact_sha256,
    )
}

#[allow(clippy::too_many_arguments)]
fn check_manifest_policy_and_artefact(
    verified_payload: &[u8],
    manifest_path: &Path,
    trusted_root: &SigstoreTrustedRoot,
    trusted_root_sha256: &str,
    verified_tuf_root: Option<&SignedMetadata<RootMetadata>>,
    tuf_root_sha256: Option<&str>,
    policy: &VerifyArtefactPolicy<'_>,
    artefact_sha256: &str,
) -> Result<(), AirgapCliError> {
    let val: serde_json::Value = serde_json::from_slice(verified_payload)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid release-manifest: {e}")))?;
    verify_manifest_trusted_root(
        &val,
        trusted_root,
        trusted_root_sha256,
        verified_tuf_root,
        tuf_root_sha256,
    )?;
    verify_manifest_oidc_and_slsa(&val, policy)?;

    let hex_prefixed = format!("sha256:{artefact_sha256}");
    let matched = val
        .get("artefacts")
        .and_then(|v| v.as_array())
        .is_some_and(|arr| {
            arr.iter().any(|item| {
                let d = item.get("sha256").and_then(|s| s.as_str()).unwrap_or("");
                let dig = item.get("digest").and_then(|s| s.as_str()).unwrap_or("");
                d == artefact_sha256 || dig == hex_prefixed || dig == artefact_sha256
            })
        });
    if !matched {
        return Err(UpdateError::ArtifactIntegrity {
            target: manifest_path.display().to_string(),
            detail: format!("artefact sha256 {artefact_sha256} not present in release-manifest"),
        }
        .into());
    }
    Ok(())
}

fn verify_manifest_trusted_root(
    val: &serde_json::Value,
    trusted_root: &SigstoreTrustedRoot,
    trusted_root_sha256: &str,
    verified_tuf_root: Option<&SignedMetadata<RootMetadata>>,
    tuf_root_sha256: Option<&str>,
) -> Result<(), AirgapCliError> {
    let tr_val = val.get("trusted_root").ok_or_else(|| {
        UpdateError::UnauthorizedRoot(
            "verified release-manifest missing required trusted_root anchor".into(),
        )
    })?;
    if let Some(sig_hash) = tr_val
        .get("sigstore_trusted_root_sha256")
        .and_then(|v| v.as_str())
    {
        if !constant_time_eq(sig_hash.as_bytes(), trusted_root_sha256.as_bytes()) {
            return Err(UpdateError::MixAndMatchDetected(
                "release-manifest sigstore_trusted_root_sha256 mismatches pinned --trusted-root"
                    .into(),
            )
            .into());
        }
        if let (Some(tuf_root), Some(tuf_sha)) = (verified_tuf_root, tuf_root_sha256) {
            let man_ver = tr_val
                .get("tuf_root_version")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| {
                    UpdateError::MalformedMetadata(
                        "manifest trusted_root missing tuf_root_version".into(),
                    )
                })?;
            let man_tuf_sha = tr_val
                .get("tuf_root_sha256")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    UpdateError::MalformedMetadata(
                        "manifest trusted_root missing tuf_root_sha256".into(),
                    )
                })?;
            if man_ver != tuf_root.signed.version
                || !constant_time_eq(man_tuf_sha.as_bytes(), tuf_sha.as_bytes())
            {
                return Err(UpdateError::MixAndMatchDetected(
                    "release-manifest TUF root digest or version mismatches pinned --tuf-root"
                        .into(),
                )
                .into());
            }
        }
        return Ok(());
    }
    let manifest_tr: SigstoreTrustedRoot = serde_json::from_value(tr_val.clone()).map_err(|e| {
        UpdateError::MalformedMetadata(format!("invalid manifest trusted_root: {e}"))
    })?;
    if manifest_tr != *trusted_root {
        return Err(UpdateError::MixAndMatchDetected(
            "verified release-manifest embedded trusted_root mismatches pinned --trusted-root"
                .into(),
        )
        .into());
    }
    Ok(())
}

fn verify_manifest_oidc_and_slsa(
    val: &serde_json::Value,
    policy: &VerifyArtefactPolicy<'_>,
) -> Result<(), AirgapCliError> {
    let oidc = val.get("oidc").and_then(|v| v.as_object()).ok_or_else(|| {
        UpdateError::UnauthorizedRoot(
            "verified release-manifest missing required oidc provenance constraints".into(),
        )
    })?;
    let iss = oidc.get("issuer").and_then(|v| v.as_str()).ok_or_else(|| {
        UpdateError::UnauthorizedRoot("release-manifest oidc.issuer is required".into())
    })?;
    if iss.is_empty() || iss != policy.expected_issuer {
        return Err(UpdateError::UnauthorizedRoot(
            "release-manifest OIDC issuer mismatches verification policy".into(),
        )
        .into());
    }
    let repo = oidc
        .get("repository")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            UpdateError::UnauthorizedRoot("release-manifest oidc.repository is required".into())
        })?;
    if repo.is_empty() || repo != policy.expected_repository {
        return Err(UpdateError::UnauthorizedRoot(
            "release-manifest repository mismatches verification policy".into(),
        )
        .into());
    }
    let slsa = val.get("slsa").and_then(|v| v.as_object());
    let opt_str = |key: &str| {
        oidc.get(key)
            .or_else(|| slsa.and_then(|m| m.get(key)))
            .or_else(|| val.get(key))
            .and_then(|v| v.as_str())
    };
    if let Some(wf) = opt_str("workflow_path")
        && wf != policy.expected_workflow
    {
        return Err(UpdateError::UnauthorizedRoot(
            "release-manifest workflow_path mismatches verification policy".into(),
        )
        .into());
    }
    if let Some(rp) = opt_str("ref_prefix")
        && rp != policy.expected_ref_prefix
    {
        return Err(UpdateError::UnauthorizedRoot(
            "release-manifest ref_prefix mismatches verification policy".into(),
        )
        .into());
    }
    if let Some(pat) = opt_str("ref_pattern") {
        let ok = pat == policy.expected_ref_prefix
            || pat.strip_suffix('*') == Some(policy.expected_ref_prefix);
        if !ok {
            return Err(UpdateError::UnauthorizedRoot(
                "release-manifest ref_pattern mismatches verification policy".into(),
            )
            .into());
        }
    }
    if let Some(b) = opt_str("builder_id")
        && b != policy.expected_builder
    {
        return Err(UpdateError::UnauthorizedRoot(
            "release-manifest builder_id mismatches verification policy".into(),
        )
        .into());
    }
    if let Some(bt) = opt_str("build_type")
        && bt != policy.expected_build_type
    {
        return Err(UpdateError::UnauthorizedRoot(
            "release-manifest build_type mismatches verification policy".into(),
        )
        .into());
    }
    Ok(())
}

fn verify_manifest_dsse(
    env: &DsseEnvelope,
    tuf_root: &SignedMetadata<RootMetadata>,
    now: Timestamp,
) -> Result<Vec<u8>, AirgapCliError> {
    let trust = UpdateTrust::new(tuf_root.clone(), now)?;
    let (keys, threshold) = trust.project_binaries_role_keys()?;
    Ok(verify_dsse_envelope_with_limits(
        env,
        &keys,
        threshold,
        &DsseLimits::default(),
    )?)
}
