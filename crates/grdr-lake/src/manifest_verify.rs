// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use rusqlite::{Connection, OptionalExtension};

use grdr_crypto::{AeadKey, verify_ed25519_raw};
use grdr_model::CodedError;
use grdr_ports::{
    BlobPort, CODE_LAKE_IO, CODE_LAKE_NOT_FOUND, OrgId, RetentionClass, SingleCtx, TenantCtx,
    TenantPath,
};

use crate::crypto::{derive_segment_dek, sha256_hex};
use crate::parquet_modular::export_decrypted_par1;
use crate::schema::lake_sql_err;

const MANIFEST_SIG_DOMAIN: &[u8] = b"grdr:lake:manifest:v1\0";

pub(crate) fn manifest_sig_message(digest: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(MANIFEST_SIG_DOMAIN.len().saturating_add(digest.len()));
    msg.extend_from_slice(MANIFEST_SIG_DOMAIN);
    msg.extend_from_slice(digest.as_bytes());
    msg
}

pub(crate) fn daily_agg_rows_conn(
    conn: &Connection,
    org_id: &OrgId,
    day: &str,
) -> Result<Vec<(String, String, u64)>, CodedError> {
    let mut stmt = conn
        .prepare(
            "SELECT retention_class, category, event_count FROM lake_agg_daily
             WHERE organisation_id = ?1 AND day = ?2
             ORDER BY retention_class ASC, category ASC",
        )
        .map_err(lake_sql_err)?;
    let rows = stmt
        .query_map(rusqlite::params![org_id.as_str(), day], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .map_err(lake_sql_err)?;
    let mut out = Vec::new();
    for row in rows {
        let (rc, cat, cnt) = row.map_err(lake_sql_err)?;
        out.push((rc, cat, u64::try_from(cnt).unwrap_or(0)));
    }
    Ok(out)
}

pub(crate) fn export_segment_as_par1_conn<B: BlobPort>(
    conn: &Connection,
    blobs: &B,
    org_kek: &AeadKey,
    ctx: &TenantCtx,
    org_id: &OrgId,
    object_key: &str,
) -> Result<Vec<u8>, CodedError> {
    if !ctx.contains(org_id) {
        return Err(CodedError::new(
            CODE_LAKE_NOT_FOUND,
            "Requested organisation is outside caller TenantCtx.",
            "Provide a TenantCtx authorized for the segment's organisation.",
        ));
    }
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT retention_class, day FROM lake_segments
             WHERE organisation_id = ?1 AND object_key = ?2",
            rusqlite::params![org_id.as_str(), object_key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(lake_sql_err)?;
    let Some((class_str, day)) = row else {
        return Err(CodedError::new(
            CODE_LAKE_NOT_FOUND,
            format!("Lake segment `{object_key}` not found."),
            "Check manifest entries for valid segment object_key values.",
        ));
    };
    let class = RetentionClass::parse(&class_str).ok_or_else(|| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Invalid retention class `{class_str}` for `{object_key}`."),
            "Inspect lake_segments catalogue integrity.",
        )
    })?;
    let path = TenantPath::parse(&SingleCtx::new(org_id.clone()), object_key)?;
    let Some(blob) = blobs.get(ctx, &path)? else {
        return Err(CodedError::new(
            CODE_LAKE_NOT_FOUND,
            format!("Lake segment blob `{object_key}` missing in object store."),
            "Restore missing object from backup or rebuild manifest.",
        ));
    };
    let (_, day_dek) = derive_segment_dek(org_kek, org_id, &class_str, &day);
    export_decrypted_par1(org_id, class, &day, object_key, &day_dek, &blob.bytes)
}

pub(crate) fn verify_manifest_chain_conn(
    conn: &Connection,
    ctx: &TenantCtx,
    trusted_pubkeys: &[[u8; 32]],
) -> Result<usize, CodedError> {
    if trusted_pubkeys.is_empty() {
        return Err(CodedError::new(
            CODE_LAKE_IO,
            "No trusted manifest verification public keys configured.",
            "Configure trusted manifest Ed25519 public keys on LakeStore.",
        ));
    }
    let mut verified = 0usize;
    for org_id in ctx.organisation_ids() {
        let mut stmt = conn
            .prepare(
                "SELECT manifest_seq, prev_manifest_digest, manifest_digest, created_at_ms,
                        entries_json, signature_b64, signer_pubkey_b64
                 FROM lake_manifests WHERE organisation_id = ?1
                 ORDER BY manifest_seq ASC",
            )
            .map_err(lake_sql_err)?;
        let rows = stmt
            .query_map(rusqlite::params![org_id.as_str()], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(lake_sql_err)?;
        let mut expected_prev: Option<String> = None;
        let mut last_seq: Option<u64> = None;
        let mut org_verified = 0usize;
        for item in rows {
            let (seq_raw, prev, digest, created_at_ms, entries_json, sig_b64, pk_b64) =
                item.map_err(lake_sql_err)?;
            let seq = u64::try_from(seq_raw).map_err(|_| {
                CodedError::new(
                    CODE_LAKE_IO,
                    "Negative manifest sequence number in lake_manifests.",
                    "Inspect lake manifest integrity.",
                )
            })?;
            let expected_seq = last_seq.map_or(1, |s| s.saturating_add(1));
            if seq != expected_seq {
                return Err(CodedError::new(
                    CODE_LAKE_IO,
                    format!(
                        "Non-contiguous manifest sequence at seq {seq} (expected {expected_seq}) for org `{}`.",
                        org_id.as_str()
                    ),
                    "Rebuild lake manifest chain from state-log.",
                ));
            }
            last_seq = Some(seq);
            if prev != expected_prev {
                return Err(CodedError::new(
                    CODE_LAKE_IO,
                    format!(
                        "Manifest chain break at seq {seq} for org `{}`.",
                        org_id.as_str()
                    ),
                    "Rebuild lake manifest from state-log.",
                ));
            }
            let material = format!(
                "{}:{}:{}:{}:{}",
                org_id.as_str(),
                seq,
                prev.as_deref().unwrap_or("genesis"),
                created_at_ms,
                entries_json
            );
            let computed = sha256_hex(material.as_bytes());
            if computed != digest {
                return Err(CodedError::new(
                    CODE_LAKE_IO,
                    format!("Manifest digest mismatch at seq {seq}."),
                    "Inspect lake manifest tampering or corruption.",
                ));
            }
            let (Some(sig_str), Some(pk_str)) = (sig_b64, pk_b64) else {
                return Err(CodedError::new(
                    CODE_LAKE_IO,
                    format!("Unsigned manifest at seq {seq} rejected (fail-closed)."),
                    "Configure manifest signing key before flushing.",
                ));
            };
            let sig_raw = B64.decode(&sig_str).map_err(|e| {
                CodedError::new(
                    CODE_LAKE_IO,
                    format!("Invalid manifest sig: {e}"),
                    "Check manifest.",
                )
            })?;
            let pk_raw = B64.decode(&pk_str).map_err(|e| {
                CodedError::new(
                    CODE_LAKE_IO,
                    format!("Invalid manifest pubkey: {e}"),
                    "Check manifest.",
                )
            })?;
            let sig_arr: [u8; 64] = sig_raw.try_into().map_err(|_| {
                CodedError::new(
                    CODE_LAKE_IO,
                    "Manifest signature length invalid.",
                    "Check manifest.",
                )
            })?;
            let pk_arr: [u8; 32] = pk_raw.try_into().map_err(|_| {
                CodedError::new(
                    CODE_LAKE_IO,
                    "Manifest pubkey length invalid.",
                    "Check manifest.",
                )
            })?;
            if !trusted_pubkeys.contains(&pk_arr) {
                return Err(CodedError::new(
                    CODE_LAKE_IO,
                    format!("Untrusted manifest signer public key at seq {seq}."),
                    "Verify trusted manifest signer key configuration.",
                ));
            }
            let sig_msg = manifest_sig_message(&digest);
            verify_ed25519_raw(&pk_arr, &sig_msg, &sig_arr).map_err(|e| {
                CodedError::new(
                    CODE_LAKE_IO,
                    format!("Manifest signature verification failed at seq {seq}: {e}"),
                    "Verify manifest signing key.",
                )
            })?;
            expected_prev = Some(digest);
            org_verified = org_verified.saturating_add(1);
            verified = verified.saturating_add(1);
        }
        if org_verified == 0 {
            return Err(CodedError::new(
                CODE_LAKE_IO,
                format!("Manifest chain is empty for org `{}`.", org_id.as_str()),
                "Flush at least one signed manifest before verifying.",
            ));
        }
        let expected_tail: Option<i64> = conn
            .query_row(
                "SELECT manifest_seq FROM lake_fencing WHERE organisation_id = ?1",
                rusqlite::params![org_id.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(lake_sql_err)?;
        let expected_tail_u64 = expected_tail
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(0);
        if last_seq != Some(expected_tail_u64) {
            return Err(CodedError::new(
                CODE_LAKE_IO,
                format!(
                    "Manifest chain tail mismatch for org `{}` (expected seq {expected_tail_u64}).",
                    org_id.as_str()
                ),
                "Rebuild lake manifest chain from state-log.",
            ));
        }
    }
    Ok(verified)
}
