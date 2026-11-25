// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Endpoint enrolment and profile lifecycle transitions (`grdr join`, `grdr leave`, `grdr protect`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use grdr_model::InstallProfile;
use grdr_update::RolloutHaltEntry;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::airgap::verify_airgap_tar_file;
use crate::egress::{NetworkMode, check_destination_allowed, parse_endpoint_host_port};
use crate::enrol_state::{
    consume_enrol_credential, count_local_audit_entries, discover_final_policy_rules,
    load_enrolled_server, load_or_init_state, resolve_state_dir, save_state,
    validate_server_origin,
};
use crate::fs_safe::reject_symlinks_on_existing_prefixes;

const CODE_ENROL_INVALID: &str = "GRDR-ENROL-0001";
const CODE_PROTECT_UNVERIFIED: &str = "GRDR-UPD-0002";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureLevel {
    Metadata,
    Structural,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeviceLifecycleState {
    Standalone {
        profile: InstallProfile,
        capture_level: CaptureLevel,
        local_org_id: String,
        history_preserved_entries: usize,
        updated_at: Timestamp,
    },
    Enrolled {
        server_url: String,
        profile: InstallProfile,
        capture_level: CaptureLevel,
        local_org_alias: String,
        server_org_id: String,
        readers: Vec<String>,
        locked_rules: Vec<String>,
        backfill_audit: bool,
        history_preserved_entries: usize,
        joined_at: Timestamp,
    },
}

#[derive(Debug, Clone)]
pub struct JoinOptions {
    pub server: String,
    pub enrol_file: Option<PathBuf>,
    pub readers: Vec<String>,
    pub packs_dir: Option<PathBuf>,
    pub backfill: bool,
    pub network_mode: NetworkMode,
    pub allow_patterns: Vec<String>,
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ProtectOptions {
    pub from: Option<PathBuf>,
    pub accept_terms: Option<String>,
    pub expected_fingerprint: Option<String>,
    pub root: Option<PathBuf>,
    pub apply: bool,
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct JoinCliArgs {
    pub server: String,
    #[arg(long)]
    pub enrol_file: Option<PathBuf>,
    #[arg(long = "reader")]
    pub readers: Vec<String>,
    #[arg(long)]
    pub packs_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub backfill: bool,
    #[arg(long, value_enum, default_value_t = NetworkMode::Standard)]
    pub network_mode: NetworkMode,
    #[arg(long = "allow")]
    pub allow: Vec<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct LeaveCliArgs {
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ProtectCliArgs {
    #[arg(long)]
    pub from: Option<PathBuf>,
    #[arg(long)]
    pub accept_terms: Option<String>,
    #[arg(long)]
    pub expected_fingerprint: Option<String>,
    #[arg(long)]
    pub root: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub apply: bool,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnrolCliError {
    #[error("{CODE_ENROL_INVALID}: I/O error on `{path}`: {detail}")]
    Io { path: String, detail: String },
    #[error("{CODE_ENROL_INVALID}: {0}")]
    Invalid(String),
    #[error("{CODE_PROTECT_UNVERIFIED}: {0}")]
    UnverifiedArtifact(String),
    #[error("{0}")]
    Egress(#[from] crate::egress::EgressError),
}

pub fn handle_join_args(args: JoinCliArgs) -> ExitCode {
    run_join_command(
        &JoinOptions {
            server: args.server,
            enrol_file: args.enrol_file,
            readers: args.readers,
            packs_dir: args.packs_dir,
            backfill: args.backfill,
            network_mode: args.network_mode,
            allow_patterns: args.allow,
            state_dir: args.state_dir,
        },
        args.json,
    )
}

pub fn handle_leave_args(args: LeaveCliArgs) -> ExitCode {
    run_leave_command(args.state_dir.as_deref(), args.json)
}

pub fn handle_protect_args(args: ProtectCliArgs) -> ExitCode {
    run_protect_command(
        &ProtectOptions {
            from: args.from,
            accept_terms: args.accept_terms,
            expected_fingerprint: args.expected_fingerprint,
            root: args.root,
            apply: args.apply,
            state_dir: args.state_dir,
        },
        args.json,
    )
}

pub fn load_enrolment_summary(state_dir: Option<&Path>) -> Option<String> {
    load_enrolled_server(state_dir)
}

pub fn run_join_command(opts: &JoinOptions, json: bool) -> ExitCode {
    match execute_join(opts) {
        Ok(state) => print_lifecycle_output("enrol.join", &state, json),
        Err(err) => print_enrol_error("enrol.join", &err, json),
    }
}

pub fn run_leave_command(state_dir: Option<&Path>, json: bool) -> ExitCode {
    match execute_leave(state_dir) {
        Ok(state) => print_lifecycle_output("enrol.leave", &state, json),
        Err(err) => print_enrol_error("enrol.leave", &err, json),
    }
}

pub fn run_protect_command(opts: &ProtectOptions, json: bool) -> ExitCode {
    match execute_protect(opts) {
        Ok((state, applied, bundle_digest)) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "apiVersion": "grdr.cli.v1alpha1",
                        "type": "enrol.protect",
                        "applied": applied,
                        "verified_bundle_sha256": bundle_digest,
                        "lifecycle": state,
                    })
                );
            } else {
                println!(
                    "Protect profile (applied={applied}, verified_bundle={:?}): {:?}",
                    bundle_digest, state
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => print_enrol_error("enrol.protect", &err, json),
    }
}

pub fn execute_join(opts: &JoinOptions) -> Result<DeviceLifecycleState, EnrolCliError> {
    validate_server_origin(&opts.server)?;
    let (host, _) = parse_endpoint_host_port(&opts.server)?;
    check_destination_allowed(
        opts.network_mode,
        &opts.allow_patterns,
        &host,
        "enrolment.server_url",
    )?;

    let locked_from_packs = discover_final_policy_rules(opts.packs_dir.as_deref());
    let consumed = consume_enrol_credential(
        opts.enrol_file.as_deref(),
        &opts.server,
        &opts.readers,
        locked_from_packs,
    )?;

    let dir = resolve_state_dir(opts.state_dir.as_deref())?;
    let current = load_or_init_state(&dir)?;
    let history_count = count_local_audit_entries(&dir);
    let now = Timestamp::now();

    let (profile, local_org_id) = match current {
        DeviceLifecycleState::Standalone {
            profile,
            local_org_id,
            ..
        } => (profile, local_org_id),
        DeviceLifecycleState::Enrolled {
            profile,
            local_org_alias,
            ..
        } => (profile, local_org_alias),
    };

    let next = DeviceLifecycleState::Enrolled {
        server_url: opts.server.clone(),
        profile,
        capture_level: CaptureLevel::Metadata,
        local_org_alias: local_org_id,
        server_org_id: consumed.server_org_id,
        readers: consumed.readers,
        locked_rules: consumed.locked_rules,
        backfill_audit: opts.backfill,
        history_preserved_entries: history_count,
        joined_at: now,
    };
    save_state(&dir, &next)?;
    Ok(next)
}

pub fn execute_leave(state_dir: Option<&Path>) -> Result<DeviceLifecycleState, EnrolCliError> {
    let dir = resolve_state_dir(state_dir)?;
    let current = load_or_init_state(&dir)?;
    let history_count = count_local_audit_entries(&dir);
    let now = Timestamp::now();

    let (profile, local_org_id) = match current {
        DeviceLifecycleState::Enrolled {
            profile,
            local_org_alias,
            ..
        } => (profile, local_org_alias),
        DeviceLifecycleState::Standalone {
            profile,
            local_org_id,
            ..
        } => (profile, local_org_id),
    };

    let next = DeviceLifecycleState::Standalone {
        profile,
        capture_level: CaptureLevel::Metadata,
        local_org_id,
        history_preserved_entries: history_count,
        updated_at: now,
    };
    save_state(&dir, &next)?;
    Ok(next)
}

pub fn execute_protect(
    opts: &ProtectOptions,
) -> Result<(DeviceLifecycleState, bool, Option<String>), EnrolCliError> {
    let verified_sha = match opts.from.as_deref() {
        Some(src) => Some(verify_protect_source(
            src,
            opts.root.as_deref(),
            opts.expected_fingerprint.as_deref(),
            opts.state_dir.as_deref(),
            opts.accept_terms.as_deref(),
        )?),
        None => None,
    };

    let dir = resolve_state_dir(opts.state_dir.as_deref())?;
    let current = load_or_init_state(&dir)?;
    let now = Timestamp::now();
    let history_count = count_local_audit_entries(&dir);

    let next = match current {
        DeviceLifecycleState::Standalone {
            capture_level,
            local_org_id,
            ..
        } => DeviceLifecycleState::Standalone {
            profile: InstallProfile::Protected,
            capture_level,
            local_org_id,
            history_preserved_entries: history_count,
            updated_at: now,
        },
        DeviceLifecycleState::Enrolled {
            server_url,
            capture_level,
            local_org_alias,
            server_org_id,
            readers,
            locked_rules,
            backfill_audit,
            joined_at,
            ..
        } => DeviceLifecycleState::Enrolled {
            server_url,
            profile: InstallProfile::Protected,
            capture_level,
            local_org_alias,
            server_org_id,
            readers,
            locked_rules,
            backfill_audit,
            history_preserved_entries: history_count,
            joined_at,
        },
    };

    if opts.apply {
        save_state(&dir, &next)?;
    }
    Ok((next, opts.apply, verified_sha))
}

fn verify_protect_source(
    src: &Path,
    override_root: Option<&Path>,
    expected_fp: Option<&str>,
    state_dir: Option<&Path>,
    accept_terms: Option<&str>,
) -> Result<String, EnrolCliError> {
    reject_symlinks_on_existing_prefixes(src).map_err(|e| EnrolCliError::Io {
        path: src.display().to_string(),
        detail: e.to_string(),
    })?;
    let meta = fs::symlink_metadata(src).map_err(|e| EnrolCliError::Io {
        path: src.display().to_string(),
        detail: e.to_string(),
    })?;
    if meta.file_type().is_symlink() {
        return Err(EnrolCliError::UnverifiedArtifact(
            "symlinks are forbidden for --from protect source".into(),
        ));
    }
    if meta.is_file() {
        let ext = src.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "tar" {
            return Err(EnrolCliError::UnverifiedArtifact(
                "bare package files without DSSE envelope and TUF metadata cannot be verified under project root".into(),
            ));
        }
        let halts: [RolloutHaltEntry; 0] = [];
        let (_, manifest_sha) = verify_airgap_tar_file(
            src,
            override_root,
            expected_fp,
            state_dir,
            accept_terms,
            "local-operator",
            &halts,
            None,
        )
        .map_err(|e| EnrolCliError::UnverifiedArtifact(e.to_string()))?;
        return Ok(manifest_sha);
    }
    if meta.is_dir() {
        let tar_candidate = src.join("grdr-airgap.tar");
        if let Ok(cand_meta) = fs::symlink_metadata(&tar_candidate)
            && !cand_meta.file_type().is_symlink()
            && cand_meta.is_file()
        {
            let halts: [RolloutHaltEntry; 0] = [];
            let (_, manifest_sha) = verify_airgap_tar_file(
                &tar_candidate,
                override_root,
                expected_fp,
                state_dir,
                accept_terms,
                "local-operator",
                &halts,
                None,
            )
            .map_err(|e| EnrolCliError::UnverifiedArtifact(e.to_string()))?;
            return Ok(manifest_sha);
        }
        return Err(EnrolCliError::UnverifiedArtifact(
            "mirror directory lacks verified TUF/DSSE air-gap bundle".into(),
        ));
    }
    Err(EnrolCliError::UnverifiedArtifact(
        "unsupported --from artifact type".into(),
    ))
}

fn print_lifecycle_output(kind: &str, state: &DeviceLifecycleState, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "apiVersion": "grdr.cli.v1alpha1",
                "type": kind,
                "lifecycle": state,
            })
        );
    } else {
        println!("{kind}: {:?}", state);
    }
    ExitCode::SUCCESS
}

fn print_enrol_error(kind: &str, err: &EnrolCliError, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "apiVersion": "grdr.cli.v1alpha1",
                "type": format!("{kind}.error"),
                "error": err.to_string(),
            })
        );
    } else {
        eprintln!("{err}");
    }
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_leave_preserves_history_and_rejects_bad_origins() {
        let dir =
            std::env::temp_dir().join(format!("grdr-enrol-{}", uuid::Uuid::now_v7().simple()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("audit.log.jsonl"), b"{\"seq\":1}\n{\"seq\":2}\n").unwrap();
        let enrol_tok = dir.join("enrol.txt");
        fs::write(&enrol_tok, b"airgap-deployment-anchor").unwrap();

        let http_err = execute_join(&JoinOptions {
            server: "http://server.airgap.test".into(),
            enrol_file: Some(enrol_tok.clone()),
            readers: vec![],
            packs_dir: None,
            backfill: false,
            network_mode: NetworkMode::Standard,
            allow_patterns: vec![],
            state_dir: Some(dir.clone()),
        });
        assert!(http_err.is_err());

        let imds_v6 = execute_join(&JoinOptions {
            server: "https://[::ffff:169.254.169.254]/latest".into(),
            enrol_file: Some(enrol_tok.clone()),
            readers: vec![],
            packs_dir: None,
            backfill: false,
            network_mode: NetworkMode::Standard,
            allow_patterns: vec![],
            state_dir: Some(dir.clone()),
        });
        assert!(imds_v6.is_err());

        let joined = execute_join(&JoinOptions {
            server: "https://server.airgap.test:8443".into(),
            enrol_file: Some(enrol_tok.clone()),
            readers: vec![],
            packs_dir: None,
            backfill: false,
            network_mode: NetworkMode::Isolated,
            allow_patterns: vec![".airgap.test".into()],
            state_dir: Some(dir.clone()),
        })
        .unwrap();
        assert!(matches!(
            joined,
            DeviceLifecycleState::Enrolled {
                history_preserved_entries: 2,
                ..
            }
        ));
        assert!(!enrol_tok.exists(), "enrol file must be deleted after join");

        let left = execute_leave(Some(&dir)).unwrap();
        assert!(matches!(
            left,
            DeviceLifecycleState::Standalone {
                history_preserved_entries: 2,
                ..
            }
        ));

        let bare_deb = dir.join("grdr.deb");
        fs::write(&bare_deb, b"bare-package").unwrap();
        let bad_protect = execute_protect(&ProtectOptions {
            from: Some(bare_deb),
            accept_terms: None,
            expected_fingerprint: None,
            root: None,
            apply: true,
            state_dir: Some(dir.clone()),
        });
        assert!(matches!(
            bad_protect,
            Err(EnrolCliError::UnverifiedArtifact(_))
        ));

        let _ = fs::remove_dir_all(&dir);
    }
}
