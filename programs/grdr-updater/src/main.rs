// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Privileged Guardrails ADR update verifier and A/B slot activator (`grdr-updater`).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use grdr_os_clock::SystemClock;
use grdr_update::UpdateSlot;
use tracing_subscriber::EnvFilter;

use grdr_updater::handover::{
    DEFAULT_HANDOVER_WINDOW_MS, HandoverCoordinator, run_updater_self_test,
};
use grdr_updater::slots::UpdateAuthority;

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
    /// Prepare a `<= 2s` atomic handover marker pointing to an inactive slot binary.
    PrepareHandover {
        #[arg(long)]
        state_root: PathBuf,
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
}

fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if tracing_subscriber::fmt()
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
            slot,
            binary,
            expected_sha256,
            window_ms,
        } => {
            let parsed_slot = match slot.to_ascii_lowercase().as_str() {
                "a" | "slot_a" | "slota" => UpdateSlot::SlotA,
                "b" | "slot_b" | "slotb" => UpdateSlot::SlotB,
                _ => return Err(format!("invalid slot '{slot}' (expected slot_a or slot_b)")),
            };
            let coord = HandoverCoordinator::new(&state_root);
            let marker = coord
                .prepare_handover(parsed_slot, &binary, &expected_sha256, window_ms, &clock)
                .map_err(|e| e.to_string())?;
            tracing::info!(
                slot = ?marker.target_slot,
                expires_mono_ms = marker.expires_mono_ms,
                "handover marker prepared"
            );
            Ok(())
        }
        UpdaterCommand::InspectAuthority { authority } => {
            let parsed = match authority.to_ascii_lowercase().as_str() {
                "self" | "self_managed" => UpdateAuthority::SelfManaged,
                "managed" => UpdateAuthority::Managed,
                "image" => UpdateAuthority::Image,
                _ => return Err(format!("invalid update authority '{authority}'")),
            };
            tracing::info!(authority = ?parsed, "validated update authority mode");
            Ok(())
        }
        UpdaterCommand::SelfTest => {
            run_updater_self_test(&clock).map_err(|e| e.to_string())?;
            tracing::info!("grdr-updater self-test passed");
            Ok(())
        }
    }
}
