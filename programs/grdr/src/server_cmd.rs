// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;

use crate::server_migrate::{MigrateHaOptions, run_migrate_command};
use crate::server_preflight::{PreflightOptions, run_preflight};

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// Run storage, database, bus, and object-store preflight checks.
    Preflight {
        #[arg(long, default_value = "embedded")]
        profile: String,

        #[arg(long)]
        data_dir: Option<PathBuf>,

        #[arg(long)]
        backup_dir: Option<PathBuf>,

        #[arg(long, env = "GRDR_POSTGRES_DSN")]
        postgres_dsn: Option<String>,

        #[arg(long, env = "GRDR_NATS_URL")]
        nats_url: Option<String>,

        #[arg(long)]
        object_store_dir: Option<PathBuf>,

        #[arg(long, default_value_t = false)]
        json: bool,

        #[arg(long, default_value_t = false)]
        strict: bool,
    },
    /// Migrate an embedded installation to HA (PostgreSQL + object storage).
    Migrate {
        #[arg(long, default_value = "ha")]
        to: String,

        #[arg(long)]
        from_data_dir: PathBuf,

        #[arg(long)]
        target_bucket_dir: PathBuf,

        #[arg(long, env = "GRDR_POSTGRES_DSN")]
        postgres_dsn: Option<String>,

        #[arg(long, default_value_t = false)]
        dry_run: bool,

        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

pub fn handle_server_command(cmd: ServerCommand) -> ExitCode {
    match cmd {
        ServerCommand::Preflight {
            profile,
            data_dir,
            backup_dir,
            postgres_dsn,
            nats_url,
            object_store_dir,
            json,
            strict,
        } => {
            let opts = PreflightOptions {
                profile: &profile,
                data_dir: data_dir.as_deref(),
                backup_dir: backup_dir.as_deref(),
                postgres_dsn: postgres_dsn.as_deref(),
                nats_url: nats_url.as_deref(),
                object_store_dir: object_store_dir.as_deref(),
            };
            run_preflight(&opts, json, strict)
        }
        ServerCommand::Migrate {
            to,
            from_data_dir,
            target_bucket_dir,
            postgres_dsn,
            dry_run,
            json,
        } => {
            let opts = MigrateHaOptions {
                to_profile: &to,
                from_data_dir: &from_data_dir,
                target_bucket_dir: &target_bucket_dir,
                postgres_dsn: postgres_dsn.as_deref(),
                dry_run,
            };
            run_migrate_command(&opts, json)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use grdr_blob::FilesystemBlobStore;
    use grdr_bus_log::SqliteLogBus;
    use grdr_model::{Device, InstallProfile};
    use grdr_ports::{
        BlobPort, BusAppendMessage, BusPort, DeviceRepo, OrgId, SingleCtx, TenantPath,
    };
    use grdr_rel_sqlite::SqliteRelationalStore;
    use jiff::Timestamp;

    use super::*;
    use crate::server_migrate::{
        CODE_MIGRATE_BUCKET_NOT_EMPTY, CODE_MIGRATE_INVALID_TARGET, migrate_embedded_to_ha,
    };
    use crate::server_preflight::{CheckOutcome, build_preflight_report};

    #[test]
    fn server_preflight_validates_all_profiles() {
        let embedded = build_preflight_report(&PreflightOptions {
            profile: "embedded",
            data_dir: None,
            backup_dir: None,
            postgres_dsn: None,
            nats_url: None,
            object_store_dir: None,
        });
        assert_eq!(embedded.overall, CheckOutcome::Warn);

        let ha_bad = build_preflight_report(&PreflightOptions {
            profile: "ha",
            data_dir: None,
            backup_dir: None,
            postgres_dsn: None,
            nats_url: None,
            object_store_dir: None,
        });
        assert_eq!(ha_bad.overall, CheckOutcome::Fail);

        let dist_dir = std::env::temp_dir().join("grdr-preflight-bucket");
        let dist_ok = build_preflight_report(&PreflightOptions {
            profile: "distributed",
            data_dir: None,
            backup_dir: None,
            postgres_dsn: Some(
                "postgres://grdr:pw@pg.example.test:5432/guardrails?sslmode=require",
            ),
            nats_url: Some("nats://nats.example.test:4222"),
            object_store_dir: Some(&dist_dir),
        });
        assert_eq!(dist_ok.overall, CheckOutcome::Pass);
    }

    #[test]
    fn server_migrate_to_ha_copies_embedded_state_and_refuses_nonempty_bucket() {
        let base = std::env::temp_dir().join(format!(
            "grdr-cli-migrate-{}",
            uuid::Uuid::now_v7().simple()
        ));
        let src_dir = base.join("embedded");
        let dst_bucket = base.join("ha-bucket");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&src_dir).unwrap();

        let org = OrgId::new("org-embedded").unwrap();
        let ctx = SingleCtx::new(org);
        let rel = SqliteRelationalStore::open(&src_dir.join("relational.sqlite3")).unwrap();
        rel.upsert_device(
            &ctx,
            &Device {
                id: "dev-mig-1".into(),
                hostname: "mig-host".into(),
                os: "linux".into(),
                arch: "x86_64".into(),
                install_profile: InstallProfile::Protected,
                daemon_version: "0.1.0".into(),
                online: true,
                hook_effective: true,
                agents: Vec::new(),
                mcp_servers: Vec::new(),
                artifacts: Vec::new(),
                user_id: None,
                user_display: None,
                last_seen: Timestamp::from_second(1_700_000_000).unwrap(),
                public_key: None,
            },
        )
        .unwrap();
        let bus = SqliteLogBus::open(&src_dir.join("bus.sqlite3")).unwrap();
        bus.append(
            &ctx,
            "events",
            0,
            &[BusAppendMessage {
                key: "dev-mig-1".into(),
                headers: BTreeMap::new(),
                payload: b"tail-msg".to_vec(),
            }],
            1_000,
        )
        .unwrap();
        let blobs = FilesystemBlobStore::open(&src_dir.join("blobs")).unwrap();
        blobs
            .put(
                &ctx,
                &TenantPath::parse(&ctx, "class=decision/day=2026-11-24/seg-1.json").unwrap(),
                b"{\"ok\":true}",
            )
            .unwrap();

        let bad_target = migrate_embedded_to_ha(&MigrateHaOptions {
            to_profile: "distributed",
            from_data_dir: &src_dir,
            target_bucket_dir: &dst_bucket,
            postgres_dsn: None,
            dry_run: false,
        })
        .unwrap_err();
        assert_eq!(bad_target.code, CODE_MIGRATE_INVALID_TARGET);

        let report = migrate_embedded_to_ha(&MigrateHaOptions {
            to_profile: "ha",
            from_data_dir: &src_dir,
            target_bucket_dir: &dst_bucket,
            postgres_dsn: None,
            dry_run: false,
        })
        .unwrap();
        assert_eq!(report.devices_copied, 1);
        assert_eq!(report.blobs_copied, 1);
        assert_eq!(report.bus_messages_replayed, 1);

        // Second run against non-empty bucket must refuse cleanly.
        let err = migrate_embedded_to_ha(&MigrateHaOptions {
            to_profile: "ha",
            from_data_dir: &src_dir,
            target_bucket_dir: &dst_bucket,
            postgres_dsn: None,
            dry_run: false,
        })
        .unwrap_err();
        assert_eq!(err.code, CODE_MIGRATE_BUCKET_NOT_EMPTY);

        let _ = std::fs::remove_dir_all(&base);
    }
}
