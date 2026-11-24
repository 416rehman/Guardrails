// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use rusqlite::Connection;
use serde::Serialize;

use grdr_blob::FilesystemBlobStore;
use grdr_bus_log::SqliteLogBus;
use grdr_model::CodedError;
use grdr_ports::{
    BlobPort, BusPort, DeviceRepo, FindingRepo, KvSnapshotRepo, OrgId, PolicyRepo,
    SessionSummaryRepo, SingleCtx, TenantCtx, TenantRelPath, UserRepo,
};
use grdr_rel_postgres::{PostgresConfig, PostgresRelationalStore};
use grdr_rel_sqlite::SqliteRelationalStore;

pub const CODE_MIGRATE_BUCKET_NOT_EMPTY: &str = "GRDR-MIGRATE-0001";
pub const CODE_MIGRATE_INVALID_TARGET: &str = "GRDR-MIGRATE-0002";
pub const CODE_MIGRATE_SOURCE_INVALID: &str = "GRDR-MIGRATE-0003";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationReport {
    pub target_profile: String,
    pub dry_run: bool,
    pub organisations_migrated: usize,
    pub devices_copied: usize,
    pub sessions_copied: usize,
    pub findings_copied: usize,
    pub packs_copied: usize,
    pub users_copied: usize,
    pub kv_entries_copied: usize,
    pub blobs_copied: usize,
    pub bus_messages_replayed: usize,
}

pub struct MigrateHaOptions<'a> {
    pub to_profile: &'a str,
    pub from_data_dir: &'a Path,
    pub target_bucket_dir: &'a Path,
    pub postgres_dsn: Option<&'a str>,
    pub dry_run: bool,
}

pub fn run_migrate_command(opts: &MigrateHaOptions<'_>, json: bool) -> ExitCode {
    match migrate_embedded_to_ha(opts) {
        Ok(report) => {
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(out) => println!("{out}"),
                    Err(err) => {
                        eprintln!("GRDR-MIGRATE-0004: failed encoding migration report: {err}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                println!(
                    "Migrated embedded store to {} (dry_run={}): orgs={}, devices={}, sessions={}, findings={}, packs={}, users={}, kv={}, blobs={}, bus_tail={}",
                    report.target_profile,
                    report.dry_run,
                    report.organisations_migrated,
                    report.devices_copied,
                    report.sessions_copied,
                    report.findings_copied,
                    report.packs_copied,
                    report.users_copied,
                    report.kv_entries_copied,
                    report.blobs_copied,
                    report.bus_messages_replayed
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{} (next: {})", err, err.next_step);
            ExitCode::FAILURE
        }
    }
}

pub fn migrate_embedded_to_ha(opts: &MigrateHaOptions<'_>) -> Result<MigrationReport, CodedError> {
    if !opts.to_profile.trim().eq_ignore_ascii_case("ha") {
        return Err(CodedError::new(
            CODE_MIGRATE_INVALID_TARGET,
            format!(
                "Unsupported migration target `{}`; only `ha` is supported.",
                opts.to_profile
            ),
            "Run `grdr server migrate --to ha`.",
        ));
    }
    let rel_path = opts.from_data_dir.join("relational.sqlite3");
    let bus_path = opts.from_data_dir.join("bus.sqlite3");
    let blobs_dir = opts.from_data_dir.join("blobs");
    if !rel_path.is_file() || !bus_path.is_file() {
        return Err(CodedError::new(
            CODE_MIGRATE_SOURCE_INVALID,
            format!(
                "Source embedded directory `{}` is missing relational.sqlite3 or bus.sqlite3.",
                opts.from_data_dir.display()
            ),
            "Point --from-data-dir at an initialized embedded server directory.",
        ));
    }

    ensure_bucket_empty(opts.target_bucket_dir)?;

    let src_rel = SqliteRelationalStore::open(&rel_path)?;
    let src_bus = SqliteLogBus::open(&bus_path)?;
    let src_blobs = FilesystemBlobStore::open(&blobs_dir)?;
    let dst_rel = match opts.postgres_dsn {
        Some(dsn) => PostgresRelationalStore::connect(PostgresConfig::parse_dsn(dsn)?)?,
        None => PostgresRelationalStore::open_offline()?,
    };
    let dst_blobs = if opts.dry_run {
        None
    } else {
        Some(FilesystemBlobStore::open(opts.target_bucket_dir)?)
    };

    let org_ids = discover_organisations(&rel_path)?;
    let mut report = MigrationReport {
        target_profile: "ha".into(),
        dry_run: opts.dry_run,
        organisations_migrated: org_ids.len(),
        devices_copied: 0,
        sessions_copied: 0,
        findings_copied: 0,
        packs_copied: 0,
        users_copied: 0,
        kv_entries_copied: 0,
        blobs_copied: 0,
        bus_messages_replayed: 0,
    };

    for org in org_ids {
        let single_ctx = SingleCtx::new(org);
        let read_ctx = TenantCtx::Single(single_ctx.clone());
        copy_org_relational(
            &src_rel,
            &dst_rel,
            &single_ctx,
            &read_ctx,
            opts.dry_run,
            &mut report,
        )?;
        copy_org_kv(
            &rel_path,
            &src_rel,
            &dst_rel,
            &single_ctx,
            &read_ctx,
            opts.dry_run,
            &mut report,
        )?;
        copy_org_blobs(
            &src_blobs,
            dst_blobs.as_ref(),
            &single_ctx,
            &read_ctx,
            opts.dry_run,
            &mut report,
        )?;
        let msgs = src_bus.fetch(&read_ctx, "events", 0, None, usize::MAX)?;
        report.bus_messages_replayed = report.bus_messages_replayed.saturating_add(msgs.len());
    }

    Ok(report)
}

fn ensure_bucket_empty(dir: &Path) -> Result<(), CodedError> {
    if !dir.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(dir).map_err(|e| {
        CodedError::new(
            CODE_MIGRATE_BUCKET_NOT_EMPTY,
            format!("Failed inspecting target bucket `{}`: {e}", dir.display()),
            "Verify target bucket path permissions.",
        )
    })?;
    if entries.next().transpose().ok().flatten().is_some() {
        return Err(CodedError::new(
            CODE_MIGRATE_BUCKET_NOT_EMPTY,
            format!(
                "Target HA bucket `{}` is not empty; refusing migration.",
                dir.display()
            ),
            "Point --target-bucket-dir at an empty bucket before migrating.",
        ));
    }
    Ok(())
}

fn discover_organisations(rel_path: &Path) -> Result<Vec<OrgId>, CodedError> {
    let conn = Connection::open(rel_path).map_err(|e| {
        CodedError::new(
            CODE_MIGRATE_SOURCE_INVALID,
            format!("Failed opening source SQLite DB: {e}"),
            "Verify relational.sqlite3 is readable.",
        )
    })?;
    let mut orgs = BTreeSet::new();
    for table in [
        "device",
        "session_summary",
        "finding",
        "policy_pack",
        "user_profile",
        "tenant_kv",
    ] {
        let sql = format!("SELECT DISTINCT organisation_id FROM {table}");
        if let Ok(mut stmt) = conn.prepare(&sql)
            && let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0))
        {
            for item in rows.flatten() {
                if let Ok(org) = OrgId::new(item) {
                    orgs.insert(org);
                }
            }
        }
    }
    Ok(orgs.into_iter().collect())
}

fn copy_org_relational(
    src: &SqliteRelationalStore,
    dst: &PostgresRelationalStore,
    single_ctx: &SingleCtx,
    read_ctx: &TenantCtx,
    dry_run: bool,
    report: &mut MigrationReport,
) -> Result<(), CodedError> {
    for dev in src.list_devices(read_ctx)? {
        if !dry_run {
            dst.upsert_device(single_ctx, &dev)?;
        }
        report.devices_copied = report.devices_copied.saturating_add(1);
    }
    for sess in src.list_session_summaries(read_ctx)? {
        if !dry_run {
            dst.upsert_session_summary(single_ctx, &sess)?;
        }
        report.sessions_copied = report.sessions_copied.saturating_add(1);
    }
    for fnd in src.list_findings(read_ctx)? {
        if !dry_run {
            dst.upsert_finding(single_ctx, &fnd)?;
        }
        report.findings_copied = report.findings_copied.saturating_add(1);
    }
    for pack in src.list_packs(read_ctx)? {
        if !dry_run {
            dst.upsert_pack(single_ctx, &pack)?;
        }
        report.packs_copied = report.packs_copied.saturating_add(1);
    }
    for user in src.list_users(read_ctx)? {
        if !dry_run {
            dst.upsert_user(single_ctx, &user)?;
        }
        report.users_copied = report.users_copied.saturating_add(1);
    }
    Ok(())
}

fn copy_org_kv(
    rel_path: &Path,
    src: &SqliteRelationalStore,
    dst: &PostgresRelationalStore,
    single_ctx: &SingleCtx,
    read_ctx: &TenantCtx,
    dry_run: bool,
    report: &mut MigrationReport,
) -> Result<(), CodedError> {
    let conn = Connection::open(rel_path).map_err(|e| {
        CodedError::new(
            CODE_MIGRATE_SOURCE_INVALID,
            format!("Failed opening source SQLite DB for KV: {e}"),
            "Verify relational.sqlite3 is readable.",
        )
    })?;
    let mut stmt = conn
        .prepare("SELECT DISTINCT namespace FROM tenant_kv WHERE organisation_id = ?1")
        .map_err(|e| {
            CodedError::new(
                CODE_MIGRATE_SOURCE_INVALID,
                e.to_string(),
                "Check KV table.",
            )
        })?;
    let namespaces = stmt
        .query_map(
            rusqlite::params![single_ctx.organisation_id().as_str()],
            |r| r.get::<_, String>(0),
        )
        .map_err(|e| {
            CodedError::new(
                CODE_MIGRATE_SOURCE_INVALID,
                e.to_string(),
                "Check KV table.",
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            CodedError::new(
                CODE_MIGRATE_SOURCE_INVALID,
                e.to_string(),
                "Check KV table.",
            )
        })?;

    for ns in namespaces {
        for (key, val) in src.list_kv(read_ctx, &ns)? {
            if !dry_run {
                dst.put_kv(single_ctx, &ns, &key, &val)?;
            }
            report.kv_entries_copied = report.kv_entries_copied.saturating_add(1);
        }
    }
    Ok(())
}

fn copy_org_blobs(
    src_blobs: &FilesystemBlobStore,
    dst_blobs: Option<&FilesystemBlobStore>,
    single_ctx: &SingleCtx,
    read_ctx: &TenantCtx,
    dry_run: bool,
    report: &mut MigrationReport,
) -> Result<(), CodedError> {
    let prefix = TenantRelPath::parse_prefix("")?;
    for meta in src_blobs.list(read_ctx, &prefix)? {
        if !dry_run
            && let Some(dst) = dst_blobs
            && let Some(obj) = src_blobs.get(read_ctx, &meta.path)?
        {
            dst.put(single_ctx, &meta.path, &obj.bytes)?;
        }
        report.blobs_copied = report.blobs_copied.saturating_add(1);
    }
    Ok(())
}
