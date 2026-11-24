// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
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
    pub lake_catalogue_rows_copied: usize,
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
                    "Migrated embedded store to {} (dry_run={}): orgs={}, devices={}, sessions={}, findings={}, packs={}, users={}, kv={}, blobs={}, bus_tail={}, lake_rows={}",
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
                    report.bus_messages_replayed,
                    report.lake_catalogue_rows_copied
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
    let src_blobs = if blobs_dir.is_dir() {
        Some(FilesystemBlobStore::open(&blobs_dir)?)
    } else {
        None
    };

    let dst_rel = if opts.dry_run {
        if let Some(dsn) = opts.postgres_dsn {
            PostgresConfig::parse_dsn(dsn)?.validate()?;
        }
        None
    } else {
        let store = match opts.postgres_dsn {
            Some(dsn) => {
                let s = PostgresRelationalStore::connect(PostgresConfig::parse_dsn(dsn)?)?;
                s.run_migrations()?;
                s
            }
            None => PostgresRelationalStore::open_offline()?,
        };
        Some(store)
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
        lake_catalogue_rows_copied: 0,
    };

    for org in org_ids {
        let single_ctx = SingleCtx::new(org);
        let read_ctx = TenantCtx::Single(single_ctx.clone());
        copy_org_relational(
            &src_rel,
            dst_rel.as_ref(),
            &single_ctx,
            &read_ctx,
            opts.dry_run,
            &mut report,
        )?;
        copy_org_kv(
            &rel_path,
            &src_rel,
            dst_rel.as_ref(),
            &single_ctx,
            &read_ctx,
            opts.dry_run,
            &mut report,
        )?;
        if let Some(ref sb) = src_blobs {
            copy_org_blobs(
                sb,
                dst_blobs.as_ref(),
                &single_ctx,
                &read_ctx,
                opts.dry_run,
                &mut report,
            )?;
        }
        replay_org_bus_tail(
            &src_bus,
            dst_rel.as_ref(),
            &single_ctx,
            &read_ctx,
            opts.dry_run,
            &mut report,
        )?;
    }

    let lake_cat_src = opts.from_data_dir.join("lake-catalogue.sqlite3");
    if lake_cat_src.is_file() {
        report.lake_catalogue_rows_copied = copy_lake_catalogue(
            &lake_cat_src,
            opts.from_data_dir,
            opts.target_bucket_dir,
            opts.dry_run,
        )?;
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
    let first = entries.next().transpose().map_err(|e| {
        CodedError::new(
            CODE_MIGRATE_BUCKET_NOT_EMPTY,
            format!("Failed reading target bucket `{}`: {e}", dir.display()),
            "Verify target bucket directory entries are readable.",
        )
    })?;
    if first.is_some() {
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
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                rusqlite::params![table],
                |r| r.get(0),
            )
            .map_err(migrate_sql_err)?;
        if exists == 0 {
            continue;
        }
        let sql = format!("SELECT DISTINCT organisation_id FROM {table}");
        let mut stmt = conn.prepare(&sql).map_err(migrate_sql_err)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(migrate_sql_err)?;
        for item in rows {
            let raw = item.map_err(migrate_sql_err)?;
            orgs.insert(OrgId::new(raw)?);
        }
    }
    Ok(orgs.into_iter().collect())
}

fn copy_org_relational(
    src: &SqliteRelationalStore,
    dst: Option<&PostgresRelationalStore>,
    single_ctx: &SingleCtx,
    read_ctx: &TenantCtx,
    dry_run: bool,
    report: &mut MigrationReport,
) -> Result<(), CodedError> {
    for dev in src.list_devices(read_ctx)? {
        if !dry_run && let Some(target) = dst {
            target.upsert_device(single_ctx, &dev)?;
        }
        report.devices_copied = report.devices_copied.saturating_add(1);
    }
    for sess in src.list_session_summaries(read_ctx)? {
        if !dry_run && let Some(target) = dst {
            target.upsert_session_summary(single_ctx, &sess)?;
        }
        report.sessions_copied = report.sessions_copied.saturating_add(1);
    }
    for fnd in src.list_findings(read_ctx)? {
        if !dry_run && let Some(target) = dst {
            target.upsert_finding(single_ctx, &fnd)?;
        }
        report.findings_copied = report.findings_copied.saturating_add(1);
    }
    for pack in src.list_packs(read_ctx)? {
        if !dry_run && let Some(target) = dst {
            target.upsert_pack(single_ctx, &pack)?;
        }
        report.packs_copied = report.packs_copied.saturating_add(1);
    }
    for user in src.list_users(read_ctx)? {
        if !dry_run && let Some(target) = dst {
            target.upsert_user(single_ctx, &user)?;
        }
        report.users_copied = report.users_copied.saturating_add(1);
    }
    Ok(())
}

fn copy_org_kv(
    rel_path: &Path,
    src: &SqliteRelationalStore,
    dst: Option<&PostgresRelationalStore>,
    single_ctx: &SingleCtx,
    read_ctx: &TenantCtx,
    dry_run: bool,
    report: &mut MigrationReport,
) -> Result<(), CodedError> {
    let conn = Connection::open(rel_path).map_err(migrate_sql_err)?;
    let mut stmt = conn
        .prepare("SELECT DISTINCT namespace FROM tenant_kv WHERE organisation_id = ?1")
        .map_err(migrate_sql_err)?;
    let namespaces = stmt
        .query_map(
            rusqlite::params![single_ctx.organisation_id().as_str()],
            |r| r.get::<_, String>(0),
        )
        .map_err(migrate_sql_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(migrate_sql_err)?;

    for ns in namespaces {
        for (key, val) in src.list_kv(read_ctx, &ns)? {
            if !dry_run && let Some(target) = dst {
                target.put_kv(single_ctx, &ns, &key, &val)?;
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

fn replay_org_bus_tail(
    src_bus: &SqliteLogBus,
    dst: Option<&PostgresRelationalStore>,
    single_ctx: &SingleCtx,
    read_ctx: &TenantCtx,
    dry_run: bool,
    report: &mut MigrationReport,
) -> Result<(), CodedError> {
    for stream in ["events", "decision"] {
        let msgs = src_bus.fetch(read_ctx, stream, 0, None, usize::MAX)?;
        for msg in msgs {
            if !dry_run && let Some(target) = dst {
                let encoded = serde_json::to_string(&msg).map_err(|e| {
                    CodedError::new(
                        CODE_MIGRATE_SOURCE_INVALID,
                        format!("Failed encoding bus message for replay: {e}"),
                        "Inspect source bus records.",
                    )
                })?;
                target.put_kv(
                    single_ctx,
                    "bus_replay",
                    &format!("{stream}/p{}/{}", msg.partition, msg.offset),
                    &encoded,
                )?;
            }
            report.bus_messages_replayed = report.bus_messages_replayed.saturating_add(1);
        }
    }
    Ok(())
}

fn copy_lake_catalogue(
    src_cat: &Path,
    from_data_dir: &Path,
    target_bucket_dir: &Path,
    dry_run: bool,
) -> Result<usize, CodedError> {
    let conn = Connection::open(src_cat).map_err(migrate_sql_err)?;
    let mut row_count = 0usize;
    for table in [
        "lake_fencing",
        "lake_segments",
        "lake_archive_segments",
        "lake_holds",
        "lake_content_keys",
        "lake_manifests",
        "lake_observables",
    ] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                rusqlite::params![table],
                |r| r.get(0),
            )
            .map_err(migrate_sql_err)?;
        if exists == 0 {
            continue;
        }
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 = conn
            .query_row(&sql, [], |r| r.get(0))
            .map_err(migrate_sql_err)?;
        row_count = row_count.saturating_add(usize::try_from(count).unwrap_or(0));
    }

    if !dry_run {
        let state_dir = target_state_dir(target_bucket_dir);
        fs::create_dir_all(&state_dir).map_err(|e| {
            CodedError::new(
                CODE_MIGRATE_SOURCE_INVALID,
                format!("Failed creating target HA state dir: {e}"),
                "Verify write permissions.",
            )
        })?;
        let dst_cat = state_dir.join("lake-catalogue.sqlite3");
        let dst_cat_str = dst_cat.to_string_lossy().to_string();
        let _ = fs::remove_file(&dst_cat);
        conn.execute("VACUUM INTO ?1", rusqlite::params![dst_cat_str])
            .map_err(migrate_sql_err)?;

        let src_kek = from_data_dir.join("lake.kek");
        if src_kek.is_file() {
            fs::copy(&src_kek, state_dir.join("lake.kek")).map_err(|e| {
                CodedError::new(
                    CODE_MIGRATE_SOURCE_INVALID,
                    format!("Failed copying lake.kek to HA state dir: {e}"),
                    "Verify permissions on lake.kek.",
                )
            })?;
        }
    }
    Ok(row_count)
}

fn target_state_dir(target_bucket_dir: &Path) -> PathBuf {
    let name = target_bucket_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "grdr".into());
    target_bucket_dir.with_file_name(format!("{name}-state"))
}

fn migrate_sql_err(err: rusqlite::Error) -> CodedError {
    CodedError::new(
        CODE_MIGRATE_SOURCE_INVALID,
        format!("Migration SQLite query failed: {err}"),
        "Verify source SQLite databases are readable and valid.",
    )
}
