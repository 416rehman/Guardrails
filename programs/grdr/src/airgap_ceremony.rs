// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! TUF project/deployment root key ceremony and deployment freshness vouch helpers.

use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use grdr_crypto::SigningKeypair;
use grdr_update::{
    CeremonyIdentityConfig, RootMetadata, SignedMetadata, SnapshotMetadata, UpdateError,
    issue_freshness_vouch, run_deployment_root_ceremony, run_project_root_ceremony,
    verify_root_self,
};
use jiff::Timestamp;
use serde::Serialize;

use crate::airgap::AirgapCliError;
use crate::airgap::airgap_bundle_tuf::load_deployment_signers;
use crate::fs_safe::{
    atomic_write_bytes, ensure_safe_dir_all, load_or_create_private_keypair, read_bounded_regular,
};

const MAX_CEREMONY_JSON_BYTES: u64 = 16 * 1024 * 1024;
const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CeremonyKindCli {
    Project,
    Deployment,
}

#[derive(Debug, Clone, Args)]
pub struct MirrorVouchArgs {
    #[arg(long)]
    pub deployment_root: PathBuf,
    #[arg(long)]
    pub deployment_key_dir: PathBuf,
    #[arg(long)]
    pub deployment_id: String,
    #[arg(long)]
    pub project_root_version: u64,
    #[arg(long)]
    pub project_snapshot: PathBuf,
    #[arg(long, default_value_t = 720)]
    pub valid_hours: i64,
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct KeysCeremonyArgs {
    #[arg(long, value_enum)]
    pub kind: CeremonyKindCli,
    #[arg(long, default_value = "ceremony-01")]
    pub ceremony_id: String,
    #[arg(long, default_value = "org-airgap")]
    pub deployment_id: String,
    #[arg(long)]
    pub out_dir: PathBuf,
    #[arg(long, default_value_t = 2)]
    pub custodians: usize,
    #[arg(long, default_value_t = 2)]
    pub threshold: u32,
    #[arg(long, default_value_t = 365)]
    pub expires_days: i64,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run_mirror_vouch(args: &MirrorVouchArgs) -> Result<(), AirgapCliError> {
    let now = Timestamp::now();
    let dep_raw = read_bounded_regular(&args.deployment_root, MAX_CEREMONY_JSON_BYTES)
        .map_err(|e| io_err(&args.deployment_root, &e.to_string()))?;
    let dep_root: SignedMetadata<RootMetadata> = serde_json::from_slice(&dep_raw)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid deployment root: {e}")))?;
    verify_root_self(&dep_root, now)?;

    let snap_raw = read_bounded_regular(&args.project_snapshot, MAX_CEREMONY_JSON_BYTES)
        .map_err(|e| io_err(&args.project_snapshot, &e.to_string()))?;
    let snap: SignedMetadata<SnapshotMetadata> = serde_json::from_slice(&snap_raw)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid snapshot: {e}")))?;

    let fleet_keys = load_deployment_signers(&args.deployment_key_dir, &dep_root.signed)?;
    let key_refs: Vec<&SigningKeypair> = fleet_keys.iter().collect();
    let expires = Timestamp::from_second(
        now.as_second()
            .saturating_add(args.valid_hours.max(1).saturating_mul(3_600)),
    )
    .unwrap_or(now);
    let vouch = issue_freshness_vouch(
        &dep_root.signed,
        &key_refs,
        &args.deployment_id,
        args.project_root_version,
        &snap.signed,
        now,
        now,
        expires,
    )?;
    write_json_pretty(&args.out, &vouch)
}

pub fn run_keys_ceremony(args: &KeysCeremonyArgs) -> Result<String, AirgapCliError> {
    let priv_dir = args.out_dir.join("private");
    let pub_dir = args.out_dir.join("public");
    ensure_safe_dir_all(&priv_dir, true).map_err(|e| io_err(&priv_dir, &e.to_string()))?;
    ensure_safe_dir_all(&pub_dir, false).map_err(|e| io_err(&pub_dir, &e.to_string()))?;

    let now = Timestamp::now();
    let expires = Timestamp::from_second(
        now.as_second()
            .saturating_add(args.expires_days.max(1).saturating_mul(SECONDS_PER_DAY)),
    )
    .unwrap_or(now);

    match args.kind {
        CeremonyKindCli::Project => {
            let s1 = load_or_create_private_keypair(&priv_dir.join("release-signer.key"))
                .map_err(|e| io_err(&priv_dir, &e.to_string()))?;
            let s2 = load_or_create_private_keypair(&priv_dir.join("rebuilder.key"))
                .map_err(|e| io_err(&priv_dir, &e.to_string()))?;
            let ops = load_or_create_private_keypair(&priv_dir.join("ops.key"))
                .map_err(|e| io_err(&priv_dir, &e.to_string()))?;
            let rekor = load_or_create_private_keypair(&priv_dir.join("rekor.key"))
                .map_err(|e| io_err(&priv_dir, &e.to_string()))?;
            let tsa = load_or_create_private_keypair(&priv_dir.join("tsa.key"))
                .map_err(|e| io_err(&priv_dir, &e.to_string()))?;
            let fulcio_ca = load_or_create_private_keypair(&priv_dir.join("fulcio-ca.key"))
                .map_err(|e| io_err(&priv_dir, &e.to_string()))?;
            let bundle = run_project_root_ceremony(
                &args.ceremony_id,
                &s1,
                &s2,
                &ops,
                &rekor,
                &tsa,
                &fulcio_ca,
                &CeremonyIdentityConfig::default(),
                expires,
                now,
            )?;
            write_json_pretty(&pub_dir.join("1.root.json"), &bundle.signed_root)?;
            write_json_pretty(&pub_dir.join("trusted_root.json"), &bundle.trusted_root)?;
            write_json_pretty(
                &pub_dir.join("ceremony-transcript.json"),
                &bundle.transcript,
            )?;
            Ok(bundle.transcript.root_fingerprint)
        }
        CeremonyKindCli::Deployment => {
            let count = args.custodians.clamp(1, 8);
            let mut keypairs: Vec<SigningKeypair> = Vec::with_capacity(count);
            for i in 1..=count {
                let kp =
                    load_or_create_private_keypair(&priv_dir.join(format!("custodian-{i}.key")))
                        .map_err(|e| io_err(&priv_dir, &e.to_string()))?;
                keypairs.push(kp);
            }
            let refs: Vec<&SigningKeypair> = keypairs.iter().collect();
            let bundle = run_deployment_root_ceremony(
                &args.ceremony_id,
                &args.deployment_id,
                &refs,
                args.threshold,
                expires,
                now,
            )?;
            write_json_pretty(&pub_dir.join("1.root.json"), &bundle.signed_root)?;
            write_json_pretty(
                &pub_dir.join("ceremony-transcript.json"),
                &bundle.transcript,
            )?;
            Ok(bundle.transcript.root_fingerprint)
        }
    }
}

fn write_json_pretty<T: Serialize>(path: &Path, val: &T) -> Result<(), AirgapCliError> {
    let bytes =
        serde_json::to_vec_pretty(val).map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
    atomic_write_bytes(path, &bytes, false).map_err(|e| io_err(path, &e.to_string()))
}

fn io_err(path: &Path, detail: &str) -> AirgapCliError {
    AirgapCliError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}
