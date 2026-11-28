// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Offline Sigstore bundle, SLSA Provenance v1, RFC 6962 Merkle tree, and platform attestation types.

use std::collections::BTreeMap;

use grdr_crypto::{SigningKeypair, sha256_digest};
use grdr_update::{
    DsseEnvelope, SigstoreTrustedRoot, TrustedRootAuthority, TrustedRootLogEntry, UpdateError,
    canonical_sha256, encode_base64, sign_dsse_envelope,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

pub const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";
pub const DEFAULT_SLSA_BUILD_TYPE: &str =
    "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1";
pub const DEFAULT_GITHUB_BUILDER: &str = "https://github.com/actions/runner";
pub const SIGSTORE_BUNDLE_MEDIA_V03: &str = "application/vnd.dev.sigstore.bundle+json;version=0.3";
pub const PLATFORM_SIG_PAYLOAD_TYPE: &str = "application/vnd.grdr.platform-signature+json";
pub const RELEASE_MANIFEST_PAYLOAD_TYPE: &str = "application/vnd.grdr.release-manifest+json";
pub const REKOR_ENTRY_DOMAIN: &str = "grdr.sigstore.rekor-set.v1";
pub const REKOR_CHECKPOINT_DOMAIN: &str = "grdr.sigstore.rekor-checkpoint.v1";
pub const TSA_STAMP_DOMAIN: &str = "grdr.sigstore.rfc3161.v1";
pub const FULCIO_CERT_DOMAIN: &str = "grdr.sigstore.fulcio-cert.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformSignatureStatus {
    Verified,
    AuthenticodeChainUntrusted,
    NotPlatformSigned,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformSignaturePayload {
    pub platform: String,
    pub artefact_sha256: String,
    pub signer_subject: String,
    pub issuer: String,
    pub verified_at: Timestamp,
    pub status: PlatformSignatureStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPlatformSignatureAttestation {
    pub dsse_envelope: DsseEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FulcioCertDescriptor {
    pub issuer: String,
    pub repository: String,
    pub workflow_path: String,
    pub source_ref: String,
    pub subject_public_key_b64: String,
    pub subject_key_id: String,
    pub not_before: Timestamp,
    pub not_after: Timestamp,
    pub ca_key_id: String,
    pub ca_signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RekorInclusionEntry {
    pub log_index: u64,
    pub tree_size: u64,
    pub log_id: String,
    pub integrated_time: Timestamp,
    pub artifact_sha256: String,
    pub dsse_payload_sha256: String,
    pub inclusion_proof_hashes: Vec<String>,
    pub checkpoint: String,
    pub checkpoint_signature_b64: String,
    pub signed_entry_timestamp_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTimestampRecord {
    pub tsa_key_id: String,
    pub signed_at: Timestamp,
    pub message_imprint_sha256: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigstoreVerificationMaterial {
    pub certificate: FulcioCertDescriptor,
    pub tlog_entries: Vec<RekorInclusionEntry>,
    pub timestamps: Vec<SignedTimestampRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineSigstoreBundle {
    pub media_type: String,
    pub verification_material: SigstoreVerificationMaterial,
    pub dsse_envelope: DsseEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InTotoSubject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaWorkflowExternalParams {
    pub repository: String,
    pub workflow_path: String,
    pub source_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaExternalParams {
    pub workflow: SlsaWorkflowExternalParams,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaBuildDefinition {
    pub build_type: String,
    pub external_parameters: SlsaExternalParams,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaBuilderInfo {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaRunDetails {
    pub builder: SlsaBuilderInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaProvenancePredicate {
    pub build_definition: SlsaBuildDefinition,
    pub run_details: SlsaRunDetails,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaInTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<InTotoSubject>,
    pub predicate_type: String,
    pub predicate: SlsaProvenancePredicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtefactVerificationReport {
    pub verified: bool,
    pub artefact_path: String,
    pub artefact_sha256: String,
    pub verified_at_signed_timestamp: Timestamp,
    pub oidc_issuer: String,
    pub repository: String,
    pub workflow_path: String,
    pub source_ref: String,
    pub builder_id: String,
    pub platform_signature_status: PlatformSignatureStatus,
    pub offline_mode: bool,
}

#[derive(Clone)]
pub struct OfflineBundleSignParams<'a> {
    pub subject_name: &'a str,
    pub artefact_bytes: &'a [u8],
    pub issuer: &'a str,
    pub repository: &'a str,
    pub workflow_path: &'a str,
    pub source_ref: &'a str,
    pub builder_id: &'a str,
    pub signed_at: Timestamp,
    pub cert_not_before: Timestamp,
    pub cert_not_after: Timestamp,
    pub eph_signer: &'a SigningKeypair,
    pub ca_signer: &'a SigningKeypair,
    pub rekor_signer: &'a SigningKeypair,
    pub tsa_signer: &'a SigningKeypair,
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn build_signed_trusted_root(
    issuer: &str,
    repo_prefix: &str,
    workflow_path: &str,
    ca_signer: &SigningKeypair,
    rekor_signer: &SigningKeypair,
    tsa_signer: &SigningKeypair,
    valid_from: Timestamp,
    valid_to: Timestamp,
) -> SigstoreTrustedRoot {
    SigstoreTrustedRoot {
        media_type: grdr_update::TRUSTED_ROOT_MEDIA_TYPE.into(),
        tlogs: vec![TrustedRootLogEntry {
            log_id: rekor_signer.key_id().to_owned(),
            base_url: "https://rekor.sigstore.dev".into(),
            hash_algorithm: "sha2-256".into(),
            public_key_b64: rekor_signer.public_key_b64(),
            valid_from,
            valid_to: Some(valid_to),
        }],
        timestamp_authorities: vec![TrustedRootAuthority {
            subject_issuer: issuer.to_owned(),
            repository_prefix: repo_prefix.to_owned(),
            workflow_path: workflow_path.to_owned(),
            public_key_b64: tsa_signer.public_key_b64(),
            key_id: tsa_signer.key_id().to_owned(),
            valid_from,
            valid_to: Some(valid_to),
        }],
        certificate_authorities: vec![TrustedRootAuthority {
            subject_issuer: issuer.to_owned(),
            repository_prefix: repo_prefix.to_owned(),
            workflow_path: workflow_path.to_owned(),
            public_key_b64: ca_signer.public_key_b64(),
            key_id: ca_signer.key_id().to_owned(),
            valid_from,
            valid_to: Some(valid_to),
        }],
    }
}

pub fn create_signed_offline_sigstore_bundle(
    params: &OfflineBundleSignParams<'_>,
) -> Result<OfflineSigstoreBundle, UpdateError> {
    let artefact_sha256 = canonical_sha256(params.artefact_bytes);
    let statement = SlsaInTotoStatement {
        statement_type: IN_TOTO_STATEMENT_V1.into(),
        subject: vec![InTotoSubject {
            name: params.subject_name.to_owned(),
            digest: BTreeMap::from([("sha256".into(), artefact_sha256.clone())]),
        }],
        predicate_type: SLSA_PROVENANCE_V1.into(),
        predicate: SlsaProvenancePredicate {
            build_definition: SlsaBuildDefinition {
                build_type: DEFAULT_SLSA_BUILD_TYPE.into(),
                external_parameters: SlsaExternalParams {
                    workflow: SlsaWorkflowExternalParams {
                        repository: params.repository.to_owned(),
                        workflow_path: params.workflow_path.to_owned(),
                        source_ref: params.source_ref.to_owned(),
                    },
                },
            },
            run_details: SlsaRunDetails {
                builder: SlsaBuilderInfo {
                    id: params.builder_id.to_owned(),
                },
            },
        },
    };
    let payload = serde_json::to_vec(&statement)
        .map_err(|e| UpdateError::MalformedMetadata(format!("SLSA serialize error: {e}")))?;
    let dsse_payload_sha256 = canonical_sha256(&payload);
    let dsse_envelope = sign_dsse_envelope(
        "application/vnd.in-toto+json",
        &payload,
        &[params.eph_signer],
    )?;

    let eph_pk_b64 = params.eph_signer.public_key_b64();
    let eph_kid = params.eph_signer.key_id();
    let cert_msg = cert_binding_message(
        params.issuer,
        params.repository,
        params.workflow_path,
        params.source_ref,
        &eph_pk_b64,
        eph_kid,
        params.cert_not_before,
        params.cert_not_after,
    );
    let ca_signature_b64 = params
        .ca_signer
        .sign_bytes(FULCIO_CERT_DOMAIN, cert_msg.as_bytes());

    let rekor_msg = rekor_set_message(
        1,
        params.rekor_signer.key_id(),
        params.signed_at,
        &artefact_sha256,
        &dsse_payload_sha256,
        &eph_pk_b64,
        eph_kid,
    );
    let set_sig = params
        .rekor_signer
        .sign_bytes(REKOR_ENTRY_DOMAIN, rekor_msg.as_bytes());

    let sibling_leaf = rfc6962_leaf_hash(b"rekor-anchor-leaf-0");
    let target_leaf = rfc6962_leaf_hash(rekor_msg.as_bytes());
    let merkle_root = rfc6962_node_hash(&sibling_leaf, &target_leaf);
    let checkpoint = format!("rekor.sigstore.dev\n2\n{}\n", encode_base64(&merkle_root));
    let checkpoint_signature_b64 = params
        .rekor_signer
        .sign_bytes(REKOR_CHECKPOINT_DOMAIN, checkpoint.as_bytes());

    let tsa_msg = tsa_imprint_message(params.signed_at, &artefact_sha256);
    let tsa_sig = params
        .tsa_signer
        .sign_bytes(TSA_STAMP_DOMAIN, tsa_msg.as_bytes());

    Ok(OfflineSigstoreBundle {
        media_type: SIGSTORE_BUNDLE_MEDIA_V03.into(),
        verification_material: SigstoreVerificationMaterial {
            certificate: FulcioCertDescriptor {
                issuer: params.issuer.to_owned(),
                repository: params.repository.to_owned(),
                workflow_path: params.workflow_path.to_owned(),
                source_ref: params.source_ref.to_owned(),
                subject_public_key_b64: eph_pk_b64,
                subject_key_id: eph_kid.to_owned(),
                not_before: params.cert_not_before,
                not_after: params.cert_not_after,
                ca_key_id: params.ca_signer.key_id().to_owned(),
                ca_signature_b64,
            },
            tlog_entries: vec![RekorInclusionEntry {
                log_index: 1,
                tree_size: 2,
                log_id: params.rekor_signer.key_id().to_owned(),
                integrated_time: params.signed_at,
                artifact_sha256: artefact_sha256.clone(),
                dsse_payload_sha256,
                inclusion_proof_hashes: vec![hex_lower(&sibling_leaf)],
                checkpoint,
                checkpoint_signature_b64,
                signed_entry_timestamp_b64: set_sig,
            }],
            timestamps: vec![SignedTimestampRecord {
                tsa_key_id: params.tsa_signer.key_id().to_owned(),
                signed_at: params.signed_at,
                message_imprint_sha256: artefact_sha256,
                signature_b64: tsa_sig,
            }],
        },
        dsse_envelope,
    })
}

pub fn create_signed_platform_sig_attestation(
    payload: &PlatformSignaturePayload,
    signer: &SigningKeypair,
) -> Result<SignedPlatformSignatureAttestation, UpdateError> {
    let bytes = serde_json::to_vec(payload).map_err(|e| {
        UpdateError::MalformedMetadata(format!("platform attestation serialize error: {e}"))
    })?;
    let dsse_envelope = sign_dsse_envelope(PLATFORM_SIG_PAYLOAD_TYPE, &bytes, &[signer])?;
    Ok(SignedPlatformSignatureAttestation { dsse_envelope })
}

#[must_use]
pub fn rfc6962_leaf_hash(entry_bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1usize.saturating_add(entry_bytes.len()));
    buf.push(0x00);
    buf.extend_from_slice(entry_bytes);
    sha256_digest(&buf)
}

#[must_use]
pub fn rfc6962_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha256_digest(&buf)
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn cert_binding_message(
    issuer: &str,
    repository: &str,
    workflow_path: &str,
    source_ref: &str,
    subject_pubkey_b64: &str,
    subject_key_id: &str,
    not_before: Timestamp,
    not_after: Timestamp,
) -> String {
    format!(
        "issuer={issuer}|repo={repository}|wf={workflow_path}|ref={source_ref}|pk={subject_pubkey_b64}|kid={subject_key_id}|nb={}|na={}",
        not_before.as_second(),
        not_after.as_second()
    )
}

#[must_use]
pub fn rekor_set_message(
    log_index: u64,
    log_id: &str,
    integrated_time: Timestamp,
    artifact_sha256: &str,
    dsse_payload_sha256: &str,
    subject_public_key_b64: &str,
    subject_key_id: &str,
) -> String {
    format!(
        "idx={log_index}|log={log_id}|ts={}|sha={artifact_sha256}|dsse={dsse_payload_sha256}|pk={subject_public_key_b64}|kid={subject_key_id}",
        integrated_time.as_second()
    )
}

#[must_use]
pub fn tsa_imprint_message(signed_at: Timestamp, artifact_sha256: &str) -> String {
    format!("tsa_ts={}|imprint={artifact_sha256}", signed_at.as_second())
}

fn hex_lower(bytes: &[u8; 32]) -> String {
    grdr_crypto::encode_lower_hex(bytes)
}
