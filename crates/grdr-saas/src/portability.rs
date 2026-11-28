// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_compat::SemVer;
use grdr_crypto::{SigningKeypair, sha256_hex, verify_bytes};
use grdr_model::CodedError;
use grdr_ports::{OrgId, SingleCtx, TenantPath, TenantRelPath};

use crate::framing::{CanonicalFrame, ensure_clean_token};
pub use crate::redirect::{
    DeviceRedirectSpec, SignedDeviceRedirect, sign_device_redirect, verify_device_redirect,
};
use crate::{
    CODE_SAAS_INVALID_INPUT, CODE_SAAS_SIGNATURE_INVALID, CODE_SAAS_TENANT_MISMATCH, saas_error,
};

pub const BUNDLE_SCHEMA_VERSION: u32 = 1;
const BUNDLE_DOMAIN: &str = "grdr.saas.org-bundle.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationTargetKind {
    HostedCell,
    SelfHostedCluster,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStage {
    DualWrite,
    CatchingUp,
    Frozen,
    Cutover,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkedState {
    pub lake_watermark: u64,
    pub audit_watermark: u64,
    pub revoked_grant_ids: Vec<String>,
    pub kill_switch_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifestEntry {
    pub relative_path: TenantRelPath,
    pub sha256_hex: String,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportOrgBundleRequest {
    pub source_cell: String,
    pub target_kind: MigrationTargetKind,
    pub exported_at: Timestamp,
    pub min_agent_version: SemVer,
    pub watermarks: WatermarkedState,
    pub raw_files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ImportBaseline {
    pub min_exported_at: Option<Timestamp>,
    pub min_kill_switch_epoch: u64,
    pub min_lake_watermark: u64,
    pub min_audit_watermark: u64,
    pub required_revoked_grant_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMigrationBundle {
    pub schema_version: u32,
    pub org_id: OrgId,
    pub source_cell: String,
    pub target_kind: MigrationTargetKind,
    pub stage: MigrationStage,
    pub exported_at: Timestamp,
    pub min_agent_version: SemVer,
    pub watermarks: WatermarkedState,
    pub lake_entries: Vec<BundleManifestEntry>,
    pub audit_entries: Vec<BundleManifestEntry>,
    pub payload_blobs: BTreeMap<String, Vec<u8>>,
    pub bundle_sha256: String,
    pub signer_key_id: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedOrgState {
    pub org_id: OrgId,
    pub target_kind: MigrationTargetKind,
    pub watermarks: WatermarkedState,
    pub restored_files: usize,
    pub verified_digest: String,
}

pub fn export_org_bundle(
    ctx: &SingleCtx,
    req: ExportOrgBundleRequest,
    signer: &SigningKeypair,
) -> Result<OrgMigrationBundle, CodedError> {
    reject_delegated_context(ctx)?;
    ensure_clean_token("source_cell", &req.source_cell)?;
    let signer_key_id = signer.key_id().to_owned();
    ensure_clean_token("signer_key_id", &signer_key_id)?;

    let mut lake_entries = Vec::new();
    let mut audit_entries = Vec::new();
    let mut payload_blobs = BTreeMap::new();
    let mut seen = BTreeSet::new();

    for (raw_path, bytes) in req.raw_files {
        let scoped = TenantPath::parse(ctx, &raw_path)?;
        let rel = scoped.relative().clone();
        let rel_str = rel.as_str().to_owned();
        if rel_str != raw_path || !seen.insert(rel_str.clone()) {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Path `{raw_path}` must be canonical and unique."),
                "Provide normalized unique lake/ or audit/ relative paths.",
            ));
        }
        let byte_len = u64::try_from(bytes.len()).map_err(|_| {
            saas_error(
                CODE_SAAS_INVALID_INPUT,
                "Migration blob length overflow.",
                "Split large migration blobs cleanly.",
            )
        })?;
        let entry = BundleManifestEntry {
            relative_path: rel,
            sha256_hex: sha256_hex(&bytes),
            byte_len,
        };
        if rel_str.starts_with("lake/") {
            lake_entries.push(entry);
        } else if rel_str.starts_with("audit/") {
            audit_entries.push(entry);
        } else {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Migration file `{rel_str}` must live under lake/ or audit/."),
                "Restrict organisation migration bundles to lake/ and audit/ prefixes.",
            ));
        }
        payload_blobs.insert(rel_str, bytes);
    }

    if lake_entries.is_empty() && audit_entries.is_empty() {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Organisation migration bundle cannot be empty.",
            "Include at least one lake/ or audit/ artifact in the migration bundle.",
        ));
    }

    let mut bundle = OrgMigrationBundle {
        schema_version: BUNDLE_SCHEMA_VERSION,
        org_id: ctx.organisation_id().clone(),
        source_cell: req.source_cell,
        target_kind: req.target_kind,
        stage: MigrationStage::Frozen,
        exported_at: req.exported_at,
        min_agent_version: req.min_agent_version,
        watermarks: req.watermarks,
        lake_entries,
        audit_entries,
        payload_blobs,
        bundle_sha256: String::new(),
        signer_key_id,
        signature_b64: String::new(),
    };
    let frame = canonical_bundle_frame(&bundle);
    bundle.bundle_sha256 = sha256_hex(frame.as_bytes());
    bundle.signature_b64 = signer.sign_bytes(BUNDLE_DOMAIN, bundle.bundle_sha256.as_bytes());
    Ok(bundle)
}

pub fn import_org_bundle(
    target_ctx: &SingleCtx,
    bundle: &OrgMigrationBundle,
    verifier_public_key_b64: &str,
    baseline: &ImportBaseline,
) -> Result<ImportedOrgState, CodedError> {
    reject_delegated_context(target_ctx)?;
    if bundle.schema_version != BUNDLE_SCHEMA_VERSION {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            format!(
                "Unsupported bundle schema version {}.",
                bundle.schema_version
            ),
            "Regenerate the export bundle with schema version 1.",
        ));
    }
    if bundle.stage != MigrationStage::Frozen {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Organisation migration bundle must be in Frozen stage for import.",
            "Freeze tenant mutations cleanly before exporting migration bundles.",
        ));
    }
    if bundle.org_id != *target_ctx.organisation_id() {
        return Err(saas_error(
            CODE_SAAS_TENANT_MISMATCH,
            format!(
                "Bundle organisation `{}` does not match target context `{}`.",
                bundle.org_id.as_str(),
                target_ctx.organisation_id().as_str()
            ),
            "Refusing cross-tenant import.",
        ));
    }
    ensure_clean_token("source_cell", &bundle.source_cell)?;
    ensure_clean_token("signer_key_id", &bundle.signer_key_id)?;
    if bundle.lake_entries.is_empty() && bundle.audit_entries.is_empty() {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Organisation migration bundle manifest cannot be empty.",
            "Export at least one verified lake/ or audit/ artifact.",
        ));
    }

    let frame = canonical_bundle_frame(bundle);
    if sha256_hex(frame.as_bytes()) != bundle.bundle_sha256 {
        return Err(saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Organisation migration bundle manifest digest mismatch.",
            "Re-export the bundle cleanly; manifest contents appear corrupted.",
        ));
    }
    verify_bytes(
        verifier_public_key_b64,
        BUNDLE_DOMAIN,
        bundle.bundle_sha256.as_bytes(),
        &bundle.signature_b64,
    )
    .map_err(|_| {
        saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Organisation migration bundle signature verification failed.",
            "Supply the trusted export signer public key or reject tampered bundles.",
        )
    })?;

    verify_baseline_monotonicity(bundle, baseline)?;
    let restored_files = verify_bundle_entries(target_ctx, bundle)?;

    Ok(ImportedOrgState {
        org_id: bundle.org_id.clone(),
        target_kind: bundle.target_kind,
        watermarks: bundle.watermarks.clone(),
        restored_files,
        verified_digest: bundle.bundle_sha256.clone(),
    })
}

fn reject_delegated_context(ctx: &SingleCtx) -> Result<(), CodedError> {
    if ctx.delegation_id().is_some() {
        return Err(saas_error(
            CODE_SAAS_TENANT_MISMATCH,
            "Delegated SingleCtx tokens are not authorized for bulk tenant bundle export/import.",
            "Authenticate with a non-delegated operator tenant context.",
        ));
    }
    Ok(())
}

fn verify_baseline_monotonicity(
    bundle: &OrgMigrationBundle,
    baseline: &ImportBaseline,
) -> Result<(), CodedError> {
    if let Some(min_ts) = baseline.min_exported_at
        && bundle.exported_at < min_ts
    {
        return Err(saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Bundle timestamp predates target tenant watermark.",
            "Reject stale bundle replays.",
        ));
    }
    if bundle.watermarks.kill_switch_epoch < baseline.min_kill_switch_epoch
        || bundle.watermarks.lake_watermark < baseline.min_lake_watermark
        || bundle.watermarks.audit_watermark < baseline.min_audit_watermark
    {
        return Err(saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Bundle watermarks would downgrade active kill-switch or log positions.",
            "Re-export from latest frozen primary watermarks.",
        ));
    }
    let revoked_set: BTreeSet<&str> = bundle
        .watermarks
        .revoked_grant_ids
        .iter()
        .map(String::as_str)
        .collect();
    for req in &baseline.required_revoked_grant_ids {
        if !revoked_set.contains(req.as_str()) {
            return Err(saas_error(
                CODE_SAAS_SIGNATURE_INVALID,
                format!("Bundle dropped active revoked grant `{req}`."),
                "Reject bundle missing required revocation watermarks.",
            ));
        }
    }
    Ok(())
}

fn verify_bundle_entries(
    target_ctx: &SingleCtx,
    bundle: &OrgMigrationBundle,
) -> Result<usize, CodedError> {
    let mut seen = BTreeSet::new();
    let entries = bundle
        .lake_entries
        .iter()
        .map(|e| ("lake/", e))
        .chain(bundle.audit_entries.iter().map(|e| ("audit/", e)));

    for (expected_prefix, entry) in entries {
        let rel_str = entry.relative_path.as_str();
        if !rel_str.starts_with(expected_prefix) {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Manifest entry `{rel_str}` outside `{expected_prefix}` lane."),
                "Place lake/ and audit/ entries in their matching manifest lists.",
            ));
        }
        let parsed = TenantPath::parse(target_ctx, rel_str)?;
        if parsed.relative().as_str() != rel_str || !seen.insert(rel_str) {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Duplicate or non-canonical bundle path `{rel_str}`."),
                "Reject ambiguous or duplicate bundle paths.",
            ));
        }
        let blob = bundle.payload_blobs.get(rel_str).ok_or_else(|| {
            saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Missing payload blob for `{rel_str}`."),
                "Include all declared manifest payloads in the bundle.",
            )
        })?;
        let actual_len = u64::try_from(blob.len()).map_err(|_| {
            saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Payload size overflow for `{rel_str}`."),
                "Reject invalid payload sizes.",
            )
        })?;
        if actual_len != entry.byte_len || sha256_hex(blob) != entry.sha256_hex {
            return Err(saas_error(
                CODE_SAAS_SIGNATURE_INVALID,
                format!("Payload length or checksum mismatch for `{rel_str}`."),
                "Re-transfer the corrupted migration blob before cutover.",
            ));
        }
    }
    if bundle.payload_blobs.len() != seen.len() {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Bundle contains unmanifested payload blobs.",
            "Reject bundles with extra payload keys outside verified manifest.",
        ));
    }
    Ok(seen.len())
}

fn canonical_bundle_frame(bundle: &OrgMigrationBundle) -> CanonicalFrame {
    let mut frame = CanonicalFrame::new("org_bundle_v1");
    frame.push_u32(bundle.schema_version);
    frame.push_str(bundle.org_id.as_str());
    frame.push_str(&bundle.source_cell);
    frame.push_str(match bundle.target_kind {
        MigrationTargetKind::HostedCell => "hosted_cell",
        MigrationTargetKind::SelfHostedCluster => "self_hosted_cluster",
    });
    frame.push_str(match bundle.stage {
        MigrationStage::DualWrite => "dual_write",
        MigrationStage::CatchingUp => "catching_up",
        MigrationStage::Frozen => "frozen",
        MigrationStage::Cutover => "cutover",
        MigrationStage::RolledBack => "rolled_back",
    });
    frame.push_str(&bundle.exported_at.to_string());
    frame.push_str(&bundle.min_agent_version.to_string());
    frame.push_str(&bundle.signer_key_id);
    frame.push_u64(bundle.watermarks.lake_watermark);
    frame.push_u64(bundle.watermarks.audit_watermark);
    frame.push_u64(bundle.watermarks.kill_switch_epoch);
    frame.push_u32(u32::try_from(bundle.watermarks.revoked_grant_ids.len()).unwrap_or(u32::MAX));
    for grant in &bundle.watermarks.revoked_grant_ids {
        frame.push_str(grant);
    }
    frame.push_u32(u32::try_from(bundle.lake_entries.len()).unwrap_or(u32::MAX));
    for entry in &bundle.lake_entries {
        frame.push_str(entry.relative_path.as_str());
        frame.push_u64(entry.byte_len);
        frame.push_str(&entry.sha256_hex);
    }
    frame.push_u32(u32::try_from(bundle.audit_entries.len()).unwrap_or(u32::MAX));
    for entry in &bundle.audit_entries {
        frame.push_str(entry.relative_path.as_str());
        frame.push_u64(entry.byte_len);
        frame.push_str(&entry.sha256_hex);
    }
    frame
}
