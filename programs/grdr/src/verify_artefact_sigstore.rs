// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Offline Sigstore bundle timestamp, RFC 6962 inclusion proof, certificate, and SLSA v1 verifier.

use grdr_crypto::{constant_time_eq, sha256_hex, verify_bytes};
use grdr_model::TrustedKeyInfo;
use grdr_update::{
    DsseLimits, SigstoreTrustedRoot, TrustedRootLogEntry, UpdateError, canonical_sha256,
    decode_base64, decode_ed25519_pubkey, verify_dsse_envelope_with_limits,
};
use jiff::Timestamp;

use crate::airgap::AirgapCliError;
use crate::airgap::verify_artefact_types::{
    FULCIO_CERT_DOMAIN, IN_TOTO_STATEMENT_V1, OfflineSigstoreBundle, REKOR_CHECKPOINT_DOMAIN,
    REKOR_ENTRY_DOMAIN, RekorInclusionEntry, SLSA_PROVENANCE_V1, SlsaInTotoStatement,
    TSA_STAMP_DOMAIN, cert_binding_message, rekor_set_message, rfc6962_leaf_hash,
    rfc6962_node_hash, tsa_imprint_message,
};

const MAX_TIMESTAMP_DRIFT_SECS: i64 = 600;

#[derive(Debug, Clone)]
pub struct VerifyArtefactPolicy<'a> {
    pub expected_issuer: &'a str,
    pub expected_repository: &'a str,
    pub expected_workflow: &'a str,
    pub expected_ref_prefix: &'a str,
    pub expected_builder: &'a str,
    pub expected_build_type: &'a str,
    pub require_platform_signature: bool,
}

pub fn verify_signed_timestamp(
    bundle: &OfflineSigstoreBundle,
    trusted_root: &SigstoreTrustedRoot,
    artefact_sha256: &str,
) -> Result<Timestamp, AirgapCliError> {
    if bundle.verification_material.timestamps.is_empty() {
        return Err(UpdateError::InvalidSignature(
            "Sigstore bundle missing signed timestamp verification data".into(),
        )
        .into());
    }
    for ts_rec in &bundle.verification_material.timestamps {
        if !constant_time_eq(
            ts_rec.message_imprint_sha256.as_bytes(),
            artefact_sha256.as_bytes(),
        ) {
            continue;
        }
        for tsa in &trusted_root.timestamp_authorities {
            if tsa.key_id != ts_rec.tsa_key_id {
                continue;
            }
            if ts_rec.signed_at < tsa.valid_from
                || tsa.valid_to.is_some_and(|to| ts_rec.signed_at > to)
            {
                continue;
            }
            let msg = tsa_imprint_message(ts_rec.signed_at, artefact_sha256);
            if verify_bytes(
                &tsa.public_key_b64,
                TSA_STAMP_DOMAIN,
                msg.as_bytes(),
                &ts_rec.signature_b64,
            )
            .is_ok()
            {
                return Ok(ts_rec.signed_at);
            }
        }
    }
    Err(UpdateError::InvalidSignature(
        "no valid signed timestamp matching pinned TSA in trusted_root.json".into(),
    )
    .into())
}

pub fn verify_rekor_inclusion(
    bundle: &OfflineSigstoreBundle,
    trusted_root: &SigstoreTrustedRoot,
    artefact_sha256: &str,
    dsse_payload_sha256: &str,
    verified_ts: Timestamp,
) -> Result<(), AirgapCliError> {
    if bundle.verification_material.tlog_entries.is_empty() {
        return Err(UpdateError::InvalidSignature(
            "Sigstore bundle missing transparency log inclusion proof".into(),
        )
        .into());
    }
    let cert = &bundle.verification_material.certificate;
    for entry in &bundle.verification_material.tlog_entries {
        if !constant_time_eq(entry.artifact_sha256.as_bytes(), artefact_sha256.as_bytes())
            || !constant_time_eq(
                entry.dsse_payload_sha256.as_bytes(),
                dsse_payload_sha256.as_bytes(),
            )
        {
            continue;
        }
        let drift = entry
            .integrated_time
            .as_second()
            .saturating_sub(verified_ts.as_second())
            .abs();
        if drift > MAX_TIMESTAMP_DRIFT_SECS {
            continue;
        }
        for tlog in &trusted_root.tlogs {
            if tlog.log_id != entry.log_id {
                continue;
            }
            if entry.integrated_time < tlog.valid_from
                || tlog.valid_to.is_some_and(|to| entry.integrated_time > to)
            {
                continue;
            }
            if verify_single_rekor_entry(
                entry,
                tlog,
                artefact_sha256,
                dsse_payload_sha256,
                &cert.subject_public_key_b64,
                &cert.subject_key_id,
            )
            .is_ok()
            {
                return Ok(());
            }
        }
    }
    Err(UpdateError::InvalidSignature(
        "no verified Rekor RFC 6962 inclusion proof, checkpoint, and SET matching trusted_root.json"
            .into(),
    )
    .into())
}

fn verify_single_rekor_entry(
    entry: &RekorInclusionEntry,
    tlog: &TrustedRootLogEntry,
    artefact_sha256: &str,
    dsse_payload_sha256: &str,
    subject_public_key_b64: &str,
    subject_key_id: &str,
) -> Result<(), UpdateError> {
    let msg = rekor_set_message(
        entry.log_index,
        &entry.log_id,
        entry.integrated_time,
        artefact_sha256,
        dsse_payload_sha256,
        subject_public_key_b64,
        subject_key_id,
    );
    verify_bytes(
        &tlog.public_key_b64,
        REKOR_ENTRY_DOMAIN,
        msg.as_bytes(),
        &entry.signed_entry_timestamp_b64,
    )
    .map_err(|_| UpdateError::InvalidSignature("Rekor SET signature failed".into()))?;

    verify_bytes(
        &tlog.public_key_b64,
        REKOR_CHECKPOINT_DOMAIN,
        entry.checkpoint.as_bytes(),
        &entry.checkpoint_signature_b64,
    )
    .map_err(|_| UpdateError::InvalidSignature("Rekor checkpoint signature failed".into()))?;

    let (tree_size, expected_root) = parse_signed_checkpoint(&entry.checkpoint, tlog)?;
    if entry.tree_size != tree_size || entry.log_index >= tree_size {
        return Err(UpdateError::InvalidSignature(
            "Rekor checkpoint tree_size or log_index out of range".into(),
        ));
    }
    let leaf_hash = rfc6962_leaf_hash(msg.as_bytes());
    verify_rfc6962_inclusion_proof(
        &leaf_hash,
        entry.log_index,
        tree_size,
        &entry.inclusion_proof_hashes,
        &expected_root,
    )
}

fn parse_signed_checkpoint(
    checkpoint: &str,
    tlog: &TrustedRootLogEntry,
) -> Result<(u64, [u8; 32]), UpdateError> {
    let mut lines = checkpoint.lines();
    let origin = lines.next().unwrap_or("").trim();
    let expected_host = tlog
        .base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    if origin.is_empty() || (!expected_host.is_empty() && origin != expected_host) {
        return Err(UpdateError::InvalidSignature(
            "Rekor checkpoint origin mismatches pinned tlog base_url".into(),
        ));
    }
    let size_line = lines
        .next()
        .ok_or_else(|| UpdateError::MalformedMetadata("checkpoint missing tree size".into()))?;
    let tree_size: u64 = size_line
        .trim()
        .parse()
        .map_err(|_| UpdateError::MalformedMetadata("invalid checkpoint tree size".into()))?;
    let root_b64 = lines
        .next()
        .ok_or_else(|| UpdateError::MalformedMetadata("checkpoint missing root hash".into()))?;
    let root_vec = decode_base64(root_b64)?;
    let root_arr: [u8; 32] = root_vec.try_into().map_err(|_| {
        UpdateError::MalformedMetadata("Rekor checkpoint root must be 32 bytes".into())
    })?;
    Ok((tree_size, root_arr))
}

fn verify_rfc6962_inclusion_proof(
    leaf_hash: &[u8; 32],
    log_index: u64,
    tree_size: u64,
    proof_hex: &[String],
    expected_root: &[u8; 32],
) -> Result<(), UpdateError> {
    if tree_size == 0 || log_index >= tree_size {
        return Err(UpdateError::InvalidSignature(
            "invalid RFC 6962 log_index or tree_size".into(),
        ));
    }
    let inner_bits =
        64u32.saturating_sub((log_index ^ (tree_size.saturating_sub(1))).leading_zeros());
    let border_bits = (log_index >> inner_bits).count_ones();
    let expected_len =
        usize::try_from(inner_bits.saturating_add(border_bits)).unwrap_or(usize::MAX);
    if proof_hex.len() != expected_len {
        return Err(UpdateError::InvalidSignature(format!(
            "RFC 6962 proof length {} != expected {expected_len}",
            proof_hex.len()
        )));
    }
    let mut cur = *leaf_hash;
    let mut pos = 0usize;
    for bit in 0..inner_bits {
        let sibling_hex = proof_hex.get(pos).ok_or_else(|| {
            UpdateError::InvalidSignature("RFC 6962 inner proof truncated".into())
        })?;
        let sibling = decode_hex_32(sibling_hex)?;
        cur = if ((log_index >> bit) & 1) == 1 {
            rfc6962_node_hash(&sibling, &cur)
        } else {
            rfc6962_node_hash(&cur, &sibling)
        };
        pos = pos.saturating_add(1);
    }
    for sibling_hex in proof_hex.iter().skip(pos) {
        let sibling = decode_hex_32(sibling_hex)?;
        cur = rfc6962_node_hash(&sibling, &cur);
    }
    if !constant_time_eq(&cur, expected_root) {
        return Err(UpdateError::InvalidSignature(
            "RFC 6962 computed Merkle root does not match signed checkpoint".into(),
        ));
    }
    Ok(())
}

pub fn verify_fulcio_certificate(
    bundle: &OfflineSigstoreBundle,
    trusted_root: &SigstoreTrustedRoot,
    verified_ts: Timestamp,
    policy: &VerifyArtefactPolicy<'_>,
) -> Result<(), AirgapCliError> {
    let cert = &bundle.verification_material.certificate;
    let expected_kid = derive_subject_key_id(&cert.subject_public_key_b64)?;
    if cert.subject_key_id != expected_kid {
        return Err(UpdateError::InvalidSignature(
            "Fulcio certificate subject_key_id is not derived from subject_public_key_b64".into(),
        )
        .into());
    }
    if verified_ts < cert.not_before || verified_ts > cert.not_after {
        return Err(UpdateError::MetadataExpired {
            role: "sigstore::certificate".into(),
            expired_at: cert.not_after.to_string(),
        }
        .into());
    }
    let mut ca_verified = false;
    for ca in &trusted_root.certificate_authorities {
        if ca.key_id != cert.ca_key_id {
            continue;
        }
        if verified_ts < ca.valid_from || ca.valid_to.is_some_and(|to| verified_ts > to) {
            continue;
        }
        if !ca.subject_issuer.is_empty() && cert.issuer != ca.subject_issuer {
            continue;
        }
        if !ca.repository_prefix.is_empty()
            && !repo_matches_prefix(&cert.repository, &ca.repository_prefix)
        {
            continue;
        }
        if !ca.workflow_path.is_empty() && cert.workflow_path != ca.workflow_path {
            continue;
        }
        let msg = cert_binding_message(
            &cert.issuer,
            &cert.repository,
            &cert.workflow_path,
            &cert.source_ref,
            &cert.subject_public_key_b64,
            &cert.subject_key_id,
            cert.not_before,
            cert.not_after,
        );
        if verify_bytes(
            &ca.public_key_b64,
            FULCIO_CERT_DOMAIN,
            msg.as_bytes(),
            &cert.ca_signature_b64,
        )
        .is_ok()
        {
            ca_verified = true;
            break;
        }
    }
    if !ca_verified {
        return Err(UpdateError::UnauthorizedRoot(
            "Sigstore certificate CA chain or issuer/repo/workflow constraint not trusted".into(),
        )
        .into());
    }
    if cert.issuer != policy.expected_issuer
        || cert.repository != policy.expected_repository
        || cert.workflow_path != policy.expected_workflow
        || !cert.source_ref.starts_with(policy.expected_ref_prefix)
    {
        return Err(UpdateError::UnauthorizedRoot(format!(
            "OIDC certificate identity {} repo={} workflow={} ref={} fails policy",
            cert.issuer, cert.repository, cert.workflow_path, cert.source_ref
        ))
        .into());
    }
    Ok(())
}

pub fn decode_and_verify_slsa_dsse(
    bundle: &OfflineSigstoreBundle,
    artefact_sha256: &str,
    policy: &VerifyArtefactPolicy<'_>,
) -> Result<(SlsaInTotoStatement, String), AirgapCliError> {
    if bundle.dsse_envelope.payload_type != "application/vnd.in-toto+json" {
        return Err(UpdateError::MalformedMetadata(format!(
            "unexpected SLSA DSSE payloadType `{}`",
            bundle.dsse_envelope.payload_type
        ))
        .into());
    }
    let cert = &bundle.verification_material.certificate;
    let trusted_keys = [TrustedKeyInfo {
        key_id: cert.subject_key_id.clone(),
        public_key_b64: cert.subject_public_key_b64.clone(),
    }];
    let payload = verify_dsse_envelope_with_limits(
        &bundle.dsse_envelope,
        &trusted_keys,
        1,
        &DsseLimits::default(),
    )?;
    let payload_sha = canonical_sha256(&payload);
    let stmt: SlsaInTotoStatement = serde_json::from_slice(&payload)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid SLSA statement JSON: {e}")))?;
    if stmt.statement_type != IN_TOTO_STATEMENT_V1 || stmt.predicate_type != SLSA_PROVENANCE_V1 {
        return Err(UpdateError::MalformedMetadata(
            "SLSA DSSE payload is not Statement v1 / Provenance v1".into(),
        )
        .into());
    }
    if stmt.predicate.build_definition.build_type != policy.expected_build_type {
        return Err(UpdateError::UnauthorizedRoot(format!(
            "SLSA buildType `{}` != expected `{}`",
            stmt.predicate.build_definition.build_type, policy.expected_build_type
        ))
        .into());
    }
    let subject_ok = !stmt.subject.is_empty()
        && stmt
            .subject
            .iter()
            .any(|s| s.digest.get("sha256").map(String::as_str) == Some(artefact_sha256));
    if !subject_ok {
        return Err(UpdateError::ArtifactIntegrity {
            target: "slsa.subject".into(),
            detail: format!("SLSA statement missing subject digest {artefact_sha256}"),
        }
        .into());
    }
    let wf = &stmt.predicate.build_definition.external_parameters.workflow;
    if wf.repository != cert.repository
        || wf.workflow_path != cert.workflow_path
        || wf.source_ref != cert.source_ref
    {
        return Err(UpdateError::MixAndMatchDetected(
            "SLSA workflow provenance diverges from signing certificate identity".into(),
        )
        .into());
    }
    if policy.expected_builder.is_empty()
        || stmt.predicate.run_details.builder.id != policy.expected_builder
    {
        return Err(UpdateError::UnauthorizedRoot(format!(
            "SLSA builder `{}` != expected `{}`",
            stmt.predicate.run_details.builder.id, policy.expected_builder
        ))
        .into());
    }
    Ok((stmt, payload_sha))
}

fn derive_subject_key_id(public_key_b64: &str) -> Result<String, UpdateError> {
    let pk = decode_ed25519_pubkey(public_key_b64)?;
    let hex = sha256_hex(&pk);
    let prefix = hex.get(..16).unwrap_or(&hex);
    Ok(format!("kid_{prefix}"))
}

pub(crate) fn repo_matches_prefix(repo: &str, prefix: &str) -> bool {
    repo == prefix
        || repo
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], UpdateError> {
    if hex.len() != 64 {
        return Err(UpdateError::MalformedMetadata(
            "RFC 6962 proof hash must be 64 hex characters".into(),
        ));
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(*bytes.get(i.saturating_mul(2)).unwrap_or(&b'!'))?;
        let lo = hex_nibble(
            *bytes
                .get(i.saturating_mul(2).saturating_add(1))
                .unwrap_or(&b'!'),
        )?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, UpdateError> {
    match b {
        b'0'..=b'9' => Ok(b.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Ok(b.saturating_sub(b'A').saturating_add(10)),
        _ => Err(UpdateError::MalformedMetadata(
            "invalid hex character in proof hash".into(),
        )),
    }
}
