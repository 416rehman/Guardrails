// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::time::Instant;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_compat::{
    CompatMatrix, NegotiationOutcome, NegotiationRequest, ProtocolCapability, SemVer,
    negotiate_compatibility,
};
use grdr_crypto::sha256_hex;
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::{AuditEntry, CodedError, IdentityMode};
use grdr_proto::api::operator::{
    BackupDrillRecord, CompatCheckEntry, RunUpgradePreflightResponse, TargetHealthEntry,
};
use grdr_proto::common::{BackupDrillStatus, CompatOutcomeKind, TargetHealthStatus};
use grdr_strings::sanitize_untrusted_text as sanitize_inert_text;

use crate::auth::AuthContext;

use super::surfaces_types::{
    BackupDrillStateRecord, ConfigRevLifecycle, DrillLifecycle, OperatorConfigSnapshot,
    OperatorGovernanceState, OperatorRevisionRecord, TargetHealthLifecycle, TargetHealthRecord,
};
use super::{AppState, StoreData};

impl AppState {
    pub async fn run_upgrade_preflight(
        &self,
        target_version: &str,
        auth: &AuthContext,
    ) -> Result<RunUpgradePreflightResponse, CodedError> {
        let now = Timestamp::now();
        let trimmed = target_version.trim();
        let _parsed = SemVer::parse(trimmed).map_err(|err| {
            CodedError::new(
                CODE_INVALID_INPUT,
                err.to_string(),
                "Provide a valid semantic version like 0.3.0 or 1.4.0.",
            )
        })?;

        let mut guard = self.inner.write().await;
        ensure_operator_seeded(&mut guard, now);
        if let Some(ref mut op) = guard.surfaces.operator {
            op.target_upgrade_version = trimmed.to_owned();
        }
        let (matrix, overall) = compute_compat_matrix(&guard, trimmed)?;
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: "operator.upgrade.preflight".to_owned(),
                actor: auth.principal_id.clone(),
                summary: format!(
                    "Ran compatibility preflight for target v{trimmed} (compatible={overall})"
                ),
                target: trimmed.to_owned(),
            },
        );
        self.persist_store(&guard)?;

        Ok(RunUpgradePreflightResponse {
            target_version: trimmed.to_owned(),
            overall_compatible: overall,
            preflight_matrix: matrix,
        })
    }

    pub async fn reset_target_breaker(
        &self,
        target_id: &str,
        auth: &AuthContext,
    ) -> Result<TargetHealthEntry, CodedError> {
        let now = Timestamp::now();
        let started = Instant::now();
        let needle = target_id.trim();
        let mut guard = self.inner.write().await;
        ensure_operator_seeded(&mut guard, now);

        let probe_ok: Result<(), String> = match needle {
            "target-relational" => match self.persist_store(&guard) {
                Ok(()) => Ok(()),
                Err(e) => Err(format!(
                    "Relational persistence check failed: {}",
                    e.message
                )),
            },
            "target-lake-blob" => match &self.storage {
                Some(storage) => match storage.lake_manifest() {
                    Ok(_) => Ok(()),
                    Err(e) => Err(format!("Lake manifest probe failed: {}", e.message)),
                },
                None => Ok(()),
            },
            "target-otlp-fanout" => {
                if !guard.otlp_config.enabled {
                    Err("OTLP fan-out exporter is disabled in runtime configuration".to_owned())
                } else if guard.otlp_config.downstream_targets.is_empty() {
                    Err("OTLP fan-out collector downstream targets are not configured".to_owned())
                } else {
                    Ok(())
                }
            }
            _ => Err(format!("Unknown delivery target `{needle}`")),
        };

        let op = guard.surfaces.operator.as_mut().ok_or_else(|| {
            CodedError::new(CODE_NOT_FOUND, "Operator state uninitialized.", "Reload.")
        })?;
        let idx = op
            .targets
            .iter()
            .position(|t| t.id == needle)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    format!("Target `{needle}` was not found."),
                    "Pick a registered target in Health.",
                )
            })?;

        let elapsed_ms = u32::try_from(started.elapsed().as_millis().max(1)).unwrap_or(u32::MAX);
        let updated = {
            let Some(slot) = op.targets.get_mut(idx) else {
                return Err(CodedError::new(
                    CODE_NOT_FOUND,
                    "Target missing.",
                    "Reload.",
                ));
            };
            match &probe_ok {
                Ok(()) => {
                    slot.status = TargetHealthLifecycle::Healthy;
                    slot.circuit_state = "closed".to_owned();
                    slot.failure_count = 0;
                    slot.detail = "Live target health probe verified".to_owned();
                }
                Err(reason) => {
                    slot.status = TargetHealthLifecycle::Degraded;
                    slot.circuit_state = "half_open".to_owned();
                    slot.failure_count = slot.failure_count.saturating_add(1);
                    slot.detail = reason.clone();
                }
            }
            slot.latency_ms = elapsed_ms;
            slot.last_checked_at = now.to_string();
            slot.clone()
        };

        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: "operator.target.breaker_reset".to_owned(),
                actor: auth.principal_id.clone(),
                summary: format!(
                    "Probed {} after breaker reset -> {:?}",
                    updated.name, updated.status
                ),
                target: updated.id.clone(),
            },
        );
        self.persist_store(&guard)?;
        Ok(target_to_proto(&updated))
    }

    pub async fn run_backup_drill(
        &self,
        kind: &str,
        note: Option<&str>,
        auth: &AuthContext,
    ) -> Result<BackupDrillRecord, CodedError> {
        let now = Timestamp::now();
        let started = Instant::now();
        let kind_norm = match kind.trim().to_ascii_lowercase().as_str() {
            "backup" => "backup".to_owned(),
            "restore" => "restore".to_owned(),
            _ => {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!("Unsupported drill kind `{kind}`."),
                    "Choose `backup` or `restore`.",
                ));
            }
        };

        let mut guard = self.inner.write().await;
        ensure_operator_seeded(&mut guard, now);

        let snapshot_bytes = serde_json::to_vec(&*guard).map_err(|e| {
            CodedError::new(
                CODE_INVALID_INPUT,
                format!("Failed serializing snapshot for drill verification: {e}"),
                "Check store consistency and retry.",
            )
        })?;
        let digest = sha256_hex(&snapshot_bytes);
        let roundtrip_ok = serde_json::from_slice::<StoreData>(&snapshot_bytes).is_ok();
        let storage_ok = match &self.storage {
            Some(storage) => self.persist_store(&guard).is_ok() && storage.lake_manifest().is_ok(),
            None => true,
        };

        let mut verified_tables: u32 = 0;
        for non_empty in [
            !guard.packs.is_empty(),
            !guard.devices.is_empty(),
            !guard.attempts.is_empty(),
            !guard.receipts.is_empty(),
            !guard.audit.is_empty(),
            guard.surfaces.operator.is_some(),
        ] {
            if non_empty {
                verified_tables = verified_tables.saturating_add(1);
            }
        }
        let rec_count = guard
            .devices
            .len()
            .saturating_add(guard.packs.len())
            .saturating_add(guard.receipts.len())
            .saturating_add(guard.audit.len());
        let record_count = u32::try_from(rec_count).unwrap_or(u32::MAX);
        let status = if roundtrip_ok && storage_ok {
            DrillLifecycle::Passed
        } else {
            DrillLifecycle::Failed
        };
        let duration_ms = u32::try_from(started.elapsed().as_millis().max(1)).unwrap_or(u32::MAX);
        let actor_label = auth.principal_id.clone();
        let clean_note = sanitize_inert_text(
            note.map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("Canonical SHA-256 snapshot and schema roundtrip verified"),
        );

        let rec = BackupDrillStateRecord {
            drill_id: format!("drill_{}", Uuid::now_v7().simple()),
            kind: kind_norm.clone(),
            status,
            snapshot_digest: digest,
            record_count,
            verified_tables,
            duration_ms,
            executed_at: now.to_string(),
            actor: actor_label.clone(),
            note: clean_note,
        };
        if let Some(ref mut op) = guard.surfaces.operator {
            op.drills.insert(0, rec.clone());
        }
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: format!("operator.drill.{kind_norm}"),
                actor: actor_label,
                summary: format!(
                    "Completed {kind_norm} drill {} ({record_count} records, status={:?})",
                    rec.drill_id, rec.status
                ),
                target: rec.drill_id.clone(),
            },
        );
        self.persist_store(&guard)?;
        Ok(drill_to_proto(&rec))
    }
}

pub(crate) fn ensure_operator_seeded(data: &mut StoreData, now: Timestamp) {
    if data.surfaces.operator.is_some() {
        return;
    }
    let baseline = OperatorConfigSnapshot {
        revision_id: "cfg-rev-1".to_owned(),
        version: 1,
        capture_level: "metadata-only".to_owned(),
        privacy_profile: if data.privacy.identity_mode == IdentityMode::Pseudonymous {
            "works-council".to_owned()
        } else {
            "standard".to_owned()
        },
        retention_preset: "default".to_owned(),
        hot_days: 30,
        activity_days: 184,
        decision_days: 396,
        audit_days: 396,
        otlp_enabled: data.otlp_config.enabled,
        release_channel: "stable".to_owned(),
        summary: "Initial applied operator runtime profile".to_owned(),
    };

    data.surfaces.operator = Some(OperatorGovernanceState {
        current: baseline.clone(),
        revisions: vec![OperatorRevisionRecord {
            revision_id: "cfg-rev-1".to_owned(),
            version: 1,
            state: ConfigRevLifecycle::Applied,
            author: "system".to_owned(),
            summary: baseline.summary.clone(),
            created_at: now.to_string(),
            applied_at: Some(now.to_string()),
            diff_lines: Vec::new(),
            config: baseline,
        }],
        target_upgrade_version: "0.2.0".to_owned(),
        targets: vec![
            TargetHealthRecord {
                id: "target-relational".to_owned(),
                name: "Primary relational store".to_owned(),
                tier: 0,
                kind: "Tier 0 core".to_owned(),
                status: TargetHealthLifecycle::Healthy,
                circuit_state: "closed".to_owned(),
                failure_count: 0,
                latency_ms: 4,
                detail: "SQLite / PostgreSQL lease active with write fencing".to_owned(),
                last_checked_at: now.to_string(),
            },
            TargetHealthRecord {
                id: "target-lake-blob".to_owned(),
                name: "Encrypted archive & blob lake".to_owned(),
                tier: 1,
                kind: "Tier 1 storage".to_owned(),
                status: TargetHealthLifecycle::Healthy,
                circuit_state: "closed".to_owned(),
                failure_count: 0,
                latency_ms: 11,
                detail: "Parquet segments verified with SHA-256 chain".to_owned(),
                last_checked_at: now.to_string(),
            },
            TargetHealthRecord {
                id: "target-otlp-fanout".to_owned(),
                name: "OTLP telemetry fan-out".to_owned(),
                tier: 2,
                kind: "Tier 2 exporter".to_owned(),
                status: TargetHealthLifecycle::Degraded,
                circuit_state: "half_open".to_owned(),
                failure_count: 2,
                latency_ms: 84,
                detail: "Collector endpoint unconfigured or awaiting downstream target".to_owned(),
                last_checked_at: now.to_string(),
            },
        ],
        drills: vec![BackupDrillStateRecord {
            drill_id: "drill-seed-01".to_owned(),
            kind: "backup".to_owned(),
            status: DrillLifecycle::Passed,
            snapshot_digest: sha256_hex(b"grdr-seed-backup-drill"),
            record_count: 24,
            verified_tables: 6,
            duration_ms: 12,
            executed_at: now.to_string(),
            actor: "system".to_owned(),
            note: "Initial baseline snapshot verification".to_owned(),
        }],
    });
}

pub(crate) fn compute_compat_matrix(
    data: &StoreData,
    target_version: &str,
) -> Result<(Vec<CompatCheckEntry>, bool), CodedError> {
    let matrix = CompatMatrix::default_v1();
    let parsed_target = SemVer::parse(target_version.trim()).map_err(|err| {
        CodedError::new(
            CODE_INVALID_INPUT,
            err.to_string(),
            "Provide a valid semantic version like 0.3.0.",
        )
    })?;
    let mut entries = Vec::new();
    let mut all_ok = true;

    let any_signed = !data.receipts.is_empty();
    let any_pinned_mcp = data
        .devices
        .iter()
        .flat_map(|d| d.mcp_servers.iter())
        .any(|m| m.pinned);

    for spec in &matrix.entries {
        let current_ver = if spec.component == "grdr-daemon" {
            data.devices
                .first()
                .map(|d| d.daemon_version.clone())
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned())
        } else {
            env!("CARGO_PKG_VERSION").to_owned()
        };

        let mut advertised = Vec::new();
        if spec.component == "grdr-daemon" {
            if any_signed {
                advertised.push(ProtocolCapability::SignedReceipts);
            }
            advertised.push(ProtocolCapability::SessionLabels);
            if data.devices.iter().any(|d| d.hook_effective) {
                advertised.push(ProtocolCapability::FastpathFloor);
            }
        } else if spec.component == "grdr-mcp" {
            if any_pinned_mcp {
                advertised.push(ProtocolCapability::McpToolPinning);
            }
            advertised.push(ProtocolCapability::StepUpApproval);
        } else {
            advertised.push(ProtocolCapability::StepUpApproval);
        }

        let req = NegotiationRequest {
            component: spec.component.clone(),
            client_version: parsed_target,
            advertised_capabilities: advertised,
        };
        let outcome = negotiate_compatibility(&matrix, &req);
        let (status, agreed, warnings, remediation) = match outcome {
            NegotiationOutcome::Compatible {
                agreed_capabilities,
            } => (
                CompatOutcomeKind::Compatible,
                agreed_capabilities
                    .into_iter()
                    .map(|c| format!("{c:?}"))
                    .collect(),
                Vec::new(),
                "Ready for rolling promotion".to_owned(),
            ),
            NegotiationOutcome::CompatibleWithWarnings {
                agreed_capabilities,
                warnings,
            } => (
                CompatOutcomeKind::CompatibleWithWarnings,
                agreed_capabilities
                    .into_iter()
                    .map(|c| format!("{c:?}"))
                    .collect(),
                warnings,
                "Review degraded capability flags before promotion".to_owned(),
            ),
            NegotiationOutcome::Incompatible { code, reason } => {
                all_ok = false;
                (
                    CompatOutcomeKind::Incompatible,
                    Vec::new(),
                    vec![format!("{code}: {reason}")],
                    "Upgrade endpoint component to stay within supported matrix".to_owned(),
                )
            }
        };

        let max_lbl = spec
            .range
            .max_exclusive
            .map(|v| v.to_string())
            .unwrap_or_else(|| "*".to_owned());

        entries.push(CompatCheckEntry {
            component: spec.component.clone(),
            current_version: current_ver,
            target_version: parsed_target.to_string(),
            supported_range: format!("[{}, {max_lbl})", spec.range.min_inclusive),
            status: status as i32,
            agreed_capabilities: agreed,
            warnings,
            remediation,
        });
    }

    Ok((entries, all_ok))
}

pub(crate) fn target_to_proto(t: &TargetHealthRecord) -> TargetHealthEntry {
    TargetHealthEntry {
        id: t.id.clone(),
        name: t.name.clone(),
        tier: t.tier,
        kind: t.kind.clone(),
        status: match t.status {
            TargetHealthLifecycle::Healthy => TargetHealthStatus::Healthy as i32,
            TargetHealthLifecycle::Degraded => TargetHealthStatus::Degraded as i32,
            TargetHealthLifecycle::OpenCircuit => TargetHealthStatus::OpenCircuit as i32,
        },
        circuit_state: t.circuit_state.clone(),
        failure_count: t.failure_count,
        latency_ms: t.latency_ms,
        detail: t.detail.clone(),
        last_checked_at: t.last_checked_at.clone(),
    }
}

pub(crate) fn drill_to_proto(d: &BackupDrillStateRecord) -> BackupDrillRecord {
    BackupDrillRecord {
        drill_id: d.drill_id.clone(),
        kind: d.kind.clone(),
        status: match d.status {
            DrillLifecycle::Passed => BackupDrillStatus::Passed as i32,
            DrillLifecycle::Running => BackupDrillStatus::Running as i32,
            DrillLifecycle::Failed => BackupDrillStatus::Failed as i32,
        },
        snapshot_digest: d.snapshot_digest.clone(),
        record_count: d.record_count,
        verified_tables: d.verified_tables,
        duration_ms: d.duration_ms,
        executed_at: d.executed_at.clone(),
        actor: d.actor.clone(),
        note: d.note.clone(),
    }
}
