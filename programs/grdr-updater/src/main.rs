// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Privileged Guardrails ADR update verifier and A/B slot activator (`grdr-updater`).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use grdr_crypto::load_or_create_keypair;
use grdr_os_clock::{Clock as _, SystemClock};
use grdr_update::{FipsMode, RootMetadata, SignedMetadata, UpdateSlot};
use tracing_subscriber::EnvFilter;

use grdr_updater::cohort_fips::{detect_host_os_profile, enforce_fips_startup};
use grdr_updater::fs_safe::{
    confine_path_under_root, ensure_safe_dir, path_exists_nofollow, read_bounded_bytes,
};
use grdr_updater::handover::{
    DEFAULT_HANDOVER_WINDOW_MS, HandoverCoordinator, run_updater_self_test,
};
use grdr_updater::slots::{SlotActivationManager, UpdateAuthority};
use grdr_updater::worker::{UpdaterWorkerConfig, run_stdio_daemon_worker_with_config};

#[derive(Debug, Parser)]
#[command(
    name = "grdr-updater",
    version,
    about = "Guardrails ADR update verifier and slot activator"
)]
struct Cli {
    #[command(subcommand)]
    command: UpdaterCommand,
}

#[derive(Debug, Subcommand)]
enum UpdaterCommand {
    /// Prepare a `<= 2s` atomic handover marker pointing to the verified active slot binary.
    PrepareHandover {
        #[arg(long)]
        state_root: PathBuf,
        #[arg(long, default_value = "self")]
        authority: String,
        #[arg(long)]
        slot: String,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        expected_sha256: String,
        #[arg(long, default_value_t = DEFAULT_HANDOVER_WINDOW_MS)]
        window_ms: u64,
    },
    /// Report configured update authority mode cleanly.
    InspectAuthority {
        #[arg(long, default_value = "self")]
        authority: String,
    },
    /// Verify clock, compatibility matrix defaults, and handover bounds locally.
    SelfTest,
    /// Run FIPS 140-3 startup known-answer self-tests for the active host OS profile.
    FipsSelfTest {
        #[arg(long, default_value_t = false)]
        required: bool,
    },
    /// Run supervised inherited-IPC worker loop attached to `grdr-daemon`.
    DaemonWorker {
        #[arg(long)]
        state_root: PathBuf,
        #[arg(long, default_value = "self")]
        authority: String,
        #[arg(long)]
        project_root_json: Option<PathBuf>,
        #[arg(long)]
        deployment_root_json: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init()
        .is_err()
    {
        tracing::debug!("tracing subscriber already initialized");
    }

    let cli = Cli::parse();
    match run_cli(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            tracing::error!("{msg}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli(cli: Cli) -> Result<(), String> {
    let clock = SystemClock::new();
    match cli.command {
        UpdaterCommand::PrepareHandover {
            state_root,
            authority,
            slot,
            binary,
            expected_sha256,
            window_ms,
        } => {
            let parsed_auth = parse_authority(&authority)?;
            if parsed_auth == UpdateAuthority::Image {
                return Err("UpdateAuthority::Image forbids binary handover".to_string());
            }
            let parsed_slot = match slot.to_ascii_lowercase().as_str() {
                "a" | "slot_a" | "slota" => UpdateSlot::SlotA,
                "b" | "slot_b" | "slotb" => UpdateSlot::SlotB,
                _ => return Err(format!("invalid slot '{slot}' (expected slot_a or slot_b)")),
            };
            ensure_safe_dir(&state_root).map_err(|e| e.to_string())?;
            let canonical_root = std::fs::canonicalize(&state_root)
                .map_err(|e| format!("failed to canonicalize state root: {e}"))?;
            let confined_bin =
                confine_path_under_root(&canonical_root, &binary).map_err(|e| e.to_string())?;
            let journal_path = state_root.join("slots.journal.json");
            if parsed_auth == UpdateAuthority::SelfManaged
                || path_exists_nofollow(&journal_path).map_err(|e| e.to_string())?
            {
                let signer = load_or_create_keypair(&state_root.join("slot-journal.key"))
                    .map_err(|e| format!("failed to load slot journal signer: {e}"))?;
                let mgr =
                    SlotActivationManager::open_existing(state_root.clone(), parsed_auth, signer)
                        .map_err(|e| e.to_string())?;
                let active = mgr.active_slot();
                if active.slot != parsed_slot || active.sha256 != expected_sha256 {
                    return Err(format!(
                        "handover target {:?} ({}) does not match active slot {:?} ({})",
                        parsed_slot, expected_sha256, active.slot, active.sha256
                    ));
                }
                let expected_path = std::fs::canonicalize(mgr.slot_binary_path(parsed_slot))
                    .map_err(|e| format!("active slot binary unreadable: {e}"))?;
                if confined_bin != expected_path {
                    return Err(format!(
                        "handover binary {} must match active slot binary {}",
                        confined_bin.display(),
                        expected_path.display()
                    ));
                }
            }
            let coord = HandoverCoordinator::new(&state_root);
            let marker = coord
                .prepare_handover(
                    parsed_slot,
                    &confined_bin,
                    &expected_sha256,
                    window_ms,
                    &clock,
                )
                .map_err(|e| e.to_string())?;
            tracing::info!(
                slot = ?marker.target_slot,
                expires_mono_ms = marker.expires_mono_ms,
                "handover marker prepared"
            );
            Ok(())
        }
        UpdaterCommand::InspectAuthority { authority } => {
            let parsed = parse_authority(&authority)?;
            tracing::info!(authority = ?parsed, "validated update authority mode");
            Ok(())
        }
        UpdaterCommand::SelfTest => {
            run_updater_self_test(&clock).map_err(|e| e.to_string())?;
            tracing::info!("grdr-updater self-test passed");
            Ok(())
        }
        UpdaterCommand::FipsSelfTest { required } => {
            let now = clock.now_wall().map_err(|e| e.to_string())?;
            let mode = if required {
                FipsMode::Required
            } else {
                FipsMode::Disabled
            };
            let report = enforce_fips_startup(detect_host_os_profile(), mode, now)
                .map_err(|e| e.to_string())?;
            tracing::info!(fips_state = ?report.state, "grdr-updater FIPS self-test complete");
            Ok(())
        }
        UpdaterCommand::DaemonWorker {
            state_root,
            authority,
            project_root_json,
            deployment_root_json,
        } => {
            let parsed_auth = parse_authority(&authority)?;
            let project_root = match project_root_json {
                Some(path) => {
                    let bytes = read_bounded_bytes(&path, 1_048_576).map_err(|e| e.to_string())?;
                    let meta: SignedMetadata<RootMetadata> =
                        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                    Some(meta)
                }
                None => None,
            };
            let deployment_root = match deployment_root_json {
                Some(path) => {
                    let bytes = read_bounded_bytes(&path, 1_048_576).map_err(|e| e.to_string())?;
                    let meta: SignedMetadata<RootMetadata> =
                        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                    Some(meta)
                }
                None => None,
            };
            run_stdio_daemon_worker_with_config(
                &state_root,
                UpdaterWorkerConfig {
                    authority: parsed_auth,
                    project_root,
                    deployment_root,
                },
            )
        }
    }
}

fn parse_authority(authority: &str) -> Result<UpdateAuthority, String> {
    match authority.to_ascii_lowercase().as_str() {
        "self" | "self_managed" => Ok(UpdateAuthority::SelfManaged),
        "managed" => Ok(UpdateAuthority::Managed),
        "image" => Ok(UpdateAuthority::Image),
        _ => Err(format!("invalid update authority '{authority}'")),
    }
}
