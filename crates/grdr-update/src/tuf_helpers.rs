// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use crate::UpdateError;
use crate::dsse::DsseTargetStatement;
use crate::tuf_types::{
    FreshnessEvaluation, FreshnessStatement, RootMetadata, SignedMetadata, SnapshotMetadata,
    TargetDescriptor, TimestampMetadata, TufRole, TufRootKind, UpdateFreshness, canonical_json,
    canonical_sha256, check_monotonic, verify_role_signatures,
};

pub(crate) fn validate_target_signing_role(
    root_kind: TufRootKind,
    role: TufRole,
) -> Result<TufRole, UpdateError> {
    match role {
        TufRole::Targets => Ok(role),
        TufRole::Binaries if root_kind == TufRootKind::Project => Ok(role),
        TufRole::Fleet if root_kind == TufRootKind::Deployment => Ok(role),
        r if root_kind == TufRootKind::Project
            && matches!(
                r,
                TufRole::Content
                    | TufRole::ContentDetection
                    | TufRole::ContentPolicy
                    | TufRole::ContentAdapters
                    | TufRole::ContentDictionary
                    | TufRole::IntelBase
                    | TufRole::IntelRapid
                    | TufRole::Rollout
            ) =>
        {
            Ok(r)
        }
        other => Err(UpdateError::UnauthorizedRoot(format!(
            "targets metadata role {other:?} cannot carry target descriptors for {root_kind:?}"
        ))),
    }
}

pub(crate) fn evaluate_deployment_vouch(
    dep_root: &RootMetadata,
    project_root_version: u64,
    snapshot: &SnapshotMetadata,
    stmt: &SignedMetadata<FreshnessStatement>,
    now: Timestamp,
) -> Result<FreshnessEvaluation, UpdateError> {
    if dep_root.expires <= now {
        return Ok(FreshnessEvaluation {
            freshness: UpdateFreshness::Expired,
            enforcement_active: true,
            install_permitted: false,
            reason: Some("deployment root expired; cannot vouch for snapshot freshness".into()),
        });
    }
    if verify_role_signatures(dep_root, TufRole::Fleet, stmt).is_err() {
        return Ok(FreshnessEvaluation {
            freshness: UpdateFreshness::Stale,
            enforcement_active: true,
            install_permitted: false,
            reason: Some(
                "TUF metadata expired without valid freshness statement; enforcement stays active"
                    .into(),
            ),
        });
    }
    let snapshot_bytes = canonical_json(snapshot)?;
    let snapshot_sha = canonical_sha256(&snapshot_bytes);
    let matches = stmt.signed.expires > now
        && stmt.signed.project_root_version == project_root_version
        && stmt.signed.project_snapshot_version == snapshot.version
        && stmt.signed.project_snapshot_sha256 == snapshot_sha;
    Ok(if matches {
        FreshnessEvaluation {
            freshness: UpdateFreshness::Current,
            enforcement_active: true,
            install_permitted: true,
            reason: None,
        }
    } else {
        FreshnessEvaluation {
            freshness: UpdateFreshness::Expired,
            enforcement_active: true,
            install_permitted: false,
            reason: Some("freshness statement expired or snapshot mismatch".into()),
        }
    })
}

pub(crate) fn verify_dsse_binding(
    payload_bytes: &[u8],
    target_path: &str,
    descriptor: &TargetDescriptor,
    artifact_bytes: &[u8],
) -> Result<(), UpdateError> {
    if let Ok(stmt) = serde_json::from_slice::<DsseTargetStatement>(payload_bytes) {
        if stmt.target_path != target_path
            || stmt.sha256 != descriptor.sha256
            || stmt.length != descriptor.length
        {
            return Err(UpdateError::MixAndMatchDetected(
                "DSSE target statement does not match target descriptor".into(),
            ));
        }
        return Ok(());
    }
    if payload_bytes != artifact_bytes {
        return Err(UpdateError::MixAndMatchDetected(
            "DSSE payload bytes do not match target artifact".into(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_timestamp_snapshot_pair(
    kind: TufRootKind,
    root: &RootMetadata,
    timestamp: &SignedMetadata<TimestampMetadata>,
    snapshot: &SignedMetadata<SnapshotMetadata>,
    trusted_ts: u64,
    trusted_snap: u64,
    now: Timestamp,
) -> Result<(), UpdateError> {
    if timestamp.signed.version < 1 || snapshot.signed.version < 1 {
        return Err(UpdateError::MalformedMetadata(
            "TUF timestamp and snapshot versions must be >= 1".into(),
        ));
    }
    if root.expires <= now {
        return Err(UpdateError::MetadataExpired {
            role: format!("{kind:?}::root"),
            expired_at: root.expires.to_string(),
        });
    }
    verify_role_signatures(root, TufRole::Timestamp, timestamp)?;
    verify_role_signatures(root, TufRole::Snapshot, snapshot)?;
    check_monotonic(
        &format!("{kind:?}::timestamp"),
        timestamp.signed.version,
        trusted_ts,
    )?;
    check_monotonic(
        &format!("{kind:?}::snapshot"),
        snapshot.signed.version,
        trusted_snap,
    )?;

    let snapshot_bytes = canonical_json(&snapshot.signed)?;
    let snapshot_len = u64::try_from(snapshot_bytes.len()).unwrap_or(u64::MAX);
    let snapshot_sha = canonical_sha256(&snapshot_bytes);
    if timestamp.signed.snapshot.version != snapshot.signed.version
        || timestamp.signed.snapshot.length != snapshot_len
        || timestamp.signed.snapshot.sha256 != snapshot_sha
    {
        return Err(UpdateError::MixAndMatchDetected(
            "timestamp snapshot reference does not match snapshot metadata".into(),
        ));
    }
    Ok(())
}
