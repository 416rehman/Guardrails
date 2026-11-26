// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! On-device redacted diagnostic bundle (`grdr support-bundle --preview|--out|--inspect`, `D-59`, `P8`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, ValueEnum};
use grdr_agents::{detect_home_dir, detect_state_dir};
use grdr_comply::deployment_fingerprint;
use grdr_crypto::{SigningKeypair, fill_random, sha256_hex, verify_bytes};
use grdr_model::{InstallProfile, SigningKeypairExt as _, TrustedKeyInfo};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::doctor::collect_doctor_report;
use crate::fs_safe::{load_or_create_private_keypair, read_bounded_utf8};
use crate::support_redact::{
    prepend_marking_if_set, pseudonymize_with_salt, redact_json_value, scrub_text,
};
use crate::tar_archive::{TarEntry, read_tar_file, write_tar_file};

const DOMAIN_SUPPORT_BUNDLE: &str = "grdr.support-bundle.manifest.v1";
const PATH_MANIFEST: &str = "MANIFEST.txt";
const PATH_SIGNATURE: &str = "SIGNATURE.json";
const PATH_DOCTOR: &str = "doctor.json";
const PATH_CONFIG: &str = "config.redacted.json";
const PATH_JOURNAL: &str = "install-journal.json";
const MAX_JOURNAL_FILE_BYTES: u64 = 1024 * 1024;
const MAX_JOURNAL_RECORDS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleSignature {
    pub format: String,
    pub deployment_fingerprint: String,
    pub root_key: TrustedKeyInfo,
    pub manifest_sha256: String,
    pub signature_b64: String,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundlePreview {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub marking: Option<String>,
    pub deployment_fingerprint: String,
    pub manifest: String,
    pub members: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SupportBundleOptions {
    pub preview: bool,
    pub out: Option<PathBuf>,
    pub inspect: Option<PathBuf>,
    pub fingerprint: Option<String>,
    pub marking: Option<String>,
    pub config_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub profile: InstallProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BundleProfileArg {
    User,
    Protected,
}

#[derive(Debug, Clone, Args)]
pub struct SupportBundleCliArgs {
    #[arg(long, default_value_t = false)]
    pub preview: bool,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long)]
    pub inspect: Option<PathBuf>,
    #[arg(long)]
    pub fingerprint: Option<String>,
    #[arg(long)]
    pub marking: Option<String>,
    #[arg(long)]
    pub config_file: Option<PathBuf>,
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = BundleProfileArg::User)]
    pub profile: BundleProfileArg,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SupportBundleError {
    #[error("GRDR-SUP-0001: I/O error on `{path}`: {detail}")]
    Io { path: String, detail: String },
    #[error("GRDR-SUP-0002: {0}")]
    VerificationFailed(String),
}

pub fn handle_support_bundle_args(args: SupportBundleCliArgs) -> ExitCode {
    let profile = match args.profile {
        BundleProfileArg::User => InstallProfile::User,
        BundleProfileArg::Protected => InstallProfile::Protected,
    };
    run_support_bundle_command(
        &SupportBundleOptions {
            preview: args.preview,
            out: args.out,
            inspect: args.inspect,
            fingerprint: args.fingerprint,
            marking: args.marking,
            config_file: args.config_file,
            key_file: args.key_file,
            state_dir: args.state_dir,
            profile,
        },
        args.json,
    )
}

pub fn run_support_bundle_command(opts: &SupportBundleOptions, json: bool) -> ExitCode {
    if let Some(archive) = opts.inspect.as_deref() {
        let Some(fp) = opts.fingerprint.as_deref() else {
            eprintln!("GRDR-SUP-0002: --fingerprint is required with --inspect");
            return ExitCode::FAILURE;
        };
        return match inspect_support_bundle_tar(archive, fp) {
            Ok(sig) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "apiVersion": "grdr.cli.v1alpha1",
                            "type": "support-bundle.inspect",
                            "verified": true,
                            "signature": sig,
                        })
                    );
                } else {
                    println!(
                        "Verified support bundle offline (fp={} manifest_sha256={})",
                        sig.deployment_fingerprint, sig.manifest_sha256
                    );
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "apiVersion": "grdr.cli.v1alpha1",
                            "type": "support-bundle.inspect",
                            "verified": false,
                            "error": err.to_string(),
                        })
                    );
                } else {
                    eprintln!("{err}");
                }
                ExitCode::FAILURE
            }
        };
    }

    match build_redacted_bundle(opts) {
        Ok((preview, entries)) => {
            if let Some(dest) = opts.out.as_deref()
                && let Err(err) = write_tar_file(dest, &entries)
            {
                eprintln!("{err}");
                return ExitCode::FAILURE;
            }
            if json {
                match serde_json::to_string_pretty(&preview) {
                    Ok(rendered) => println!("{rendered}"),
                    Err(err) => {
                        eprintln!("GRDR-SUP-0002: serialization failed: {err}");
                        return ExitCode::FAILURE;
                    }
                }
            } else if opts.preview || opts.out.is_none() {
                println!("{}", preview.manifest);
            } else if let Some(dest) = opts.out.as_deref() {
                println!(
                    "Wrote signed support bundle to {} (fp={})",
                    dest.display(),
                    preview.deployment_fingerprint
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

pub fn build_redacted_bundle(
    opts: &SupportBundleOptions,
) -> Result<(SupportBundlePreview, Vec<TarEntry>), SupportBundleError> {
    let salt = ephemeral_device_salt()?;
    let home_dir = detect_home_string();
    let username = detect_username();
    let mut doctor = collect_doctor_report(opts.profile);
    let raw_hostname = doctor.device_name.clone();
    doctor.device_name = pseudonymize_with_salt("host", &salt, &raw_hostname);

    let doctor_raw = serde_json::to_string_pretty(&doctor)
        .map_err(|e| SupportBundleError::VerificationFailed(e.to_string()))?;
    let doctor_redacted = scrub_text(
        &doctor_raw,
        home_dir.as_deref(),
        Some(&raw_hostname),
        username.as_deref(),
        &salt,
        opts.marking.as_deref(),
    );

    let cfg_raw = match opts.config_file.as_deref() {
        Some(path) => read_optional_bounded_config(path)?,
        None => serde_json::json!({
            "profile": format!("{:?}", opts.profile),
            "capture_ceiling": "metadata",
            "memory_dumps": false,
            "prompt_capture": false,
        }),
    };
    let cfg_sanitized = redact_json_value(
        &cfg_raw,
        home_dir.as_deref(),
        Some(&raw_hostname),
        username.as_deref(),
        &salt,
    );
    let cfg_str = serde_json::to_string_pretty(&cfg_sanitized)
        .map_err(|e| SupportBundleError::VerificationFailed(e.to_string()))?;
    let cfg_redacted = prepend_marking_if_set(&cfg_str, opts.marking.as_deref());

    let journal_raw = collect_redacted_journal_doc(
        opts.state_dir.as_deref(),
        home_dir.as_deref(),
        Some(&raw_hostname),
        username.as_deref(),
        &salt,
    )?;
    let journal_str = serde_json::to_string_pretty(&journal_raw)
        .map_err(|e| SupportBundleError::VerificationFailed(e.to_string()))?;
    let journal_redacted = prepend_marking_if_set(&journal_str, opts.marking.as_deref());

    let keypair = match opts.key_file.as_deref() {
        Some(p) => load_or_create_private_keypair(p)
            .map_err(|e| SupportBundleError::VerificationFailed(e.to_string()))?,
        None => SigningKeypair::generate()
            .map_err(|e| SupportBundleError::VerificationFailed(e.to_string()))?,
    };
    let root_key = keypair.public_info();
    let fp = deployment_fingerprint(&root_key);

    let mut members = BTreeMap::new();
    members.insert(PATH_DOCTOR.to_owned(), doctor_redacted);
    members.insert(PATH_CONFIG.to_owned(), cfg_redacted);
    members.insert(PATH_JOURNAL.to_owned(), journal_redacted);

    let manifest = render_manifest(opts.marking.as_deref(), &fp, &members);
    let sig = SupportBundleSignature {
        format: "grdr.support-bundle.v1".into(),
        deployment_fingerprint: fp.clone(),
        root_key,
        manifest_sha256: sha256_hex(manifest.as_bytes()),
        signature_b64: keypair.sign_bytes(DOMAIN_SUPPORT_BUNDLE, manifest.as_bytes()),
        created_at: Timestamp::now(),
    };
    let sig_json = serde_json::to_string_pretty(&sig)
        .map_err(|e| SupportBundleError::VerificationFailed(e.to_string()))?;

    let mut entries = Vec::new();
    entries.push(TarEntry {
        path: PATH_MANIFEST.into(),
        bytes: manifest.as_bytes().to_vec(),
    });
    entries.push(TarEntry {
        path: PATH_SIGNATURE.into(),
        bytes: sig_json.into_bytes(),
    });
    for (name, body) in &members {
        entries.push(TarEntry {
            path: name.clone(),
            bytes: body.as_bytes().to_vec(),
        });
    }

    Ok((
        SupportBundlePreview {
            api_version: "grdr.cli.v1alpha1".into(),
            kind: "support-bundle.preview".into(),
            marking: opts.marking.clone(),
            deployment_fingerprint: fp,
            manifest,
            members,
        },
        entries,
    ))
}

pub fn inspect_support_bundle_tar(
    archive_path: &Path,
    expected_fingerprint: &str,
) -> Result<SupportBundleSignature, SupportBundleError> {
    let entries = read_tar_file(archive_path)
        .map_err(|e| SupportBundleError::VerificationFailed(e.to_string()))?;
    let mut map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in entries {
        map.insert(entry.path, entry.bytes);
    }

    let manifest_bytes = map
        .get(PATH_MANIFEST)
        .ok_or_else(|| SupportBundleError::VerificationFailed("missing MANIFEST.txt".into()))?;
    let sig_bytes = map
        .get(PATH_SIGNATURE)
        .ok_or_else(|| SupportBundleError::VerificationFailed("missing SIGNATURE.json".into()))?;
    let sig: SupportBundleSignature = serde_json::from_slice(sig_bytes).map_err(|e| {
        SupportBundleError::VerificationFailed(format!("invalid signature JSON: {e}"))
    })?;

    if sig.format != "grdr.support-bundle.v1" {
        return Err(SupportBundleError::VerificationFailed(
            "unexpected support bundle signature format".into(),
        ));
    }
    let derived_fp = deployment_fingerprint(&sig.root_key);
    if derived_fp != sig.deployment_fingerprint
        || sig.deployment_fingerprint != expected_fingerprint
    {
        return Err(SupportBundleError::VerificationFailed(format!(
            "deployment fingerprint `{}` != expected `{expected_fingerprint}`",
            sig.deployment_fingerprint
        )));
    }
    if sha256_hex(manifest_bytes) != sig.manifest_sha256 {
        return Err(SupportBundleError::VerificationFailed(
            "manifest SHA-256 mismatch".into(),
        ));
    }
    verify_bytes(
        &sig.root_key.public_key_b64,
        DOMAIN_SUPPORT_BUNDLE,
        manifest_bytes,
        &sig.signature_b64,
    )
    .map_err(|e| {
        SupportBundleError::VerificationFailed(format!("Ed25519 signature check failed: {e}"))
    })?;

    let manifest_str = std::str::from_utf8(manifest_bytes)
        .map_err(|e| SupportBundleError::VerificationFailed(e.to_string()))?;
    let mut verified_members: usize = 0;
    for line in manifest_str.lines() {
        let Some(rest) = line.strip_prefix("member ") else {
            continue;
        };
        let parts: Vec<&str> = rest.split_whitespace().collect();
        let (Some(name), Some(digest), Some(len_str)) = (parts.first(), parts.get(1), parts.get(2))
        else {
            return Err(SupportBundleError::VerificationFailed(
                "malformed member digest line in MANIFEST.txt".into(),
            ));
        };
        let Some(bytes) = map.get(*name) else {
            return Err(SupportBundleError::VerificationFailed(format!(
                "manifest member `{name}` missing from tar"
            )));
        };
        if sha256_hex(bytes) != *digest || bytes.len().to_string() != *len_str {
            return Err(SupportBundleError::VerificationFailed(format!(
                "digest or length mismatch for member `{name}`"
            )));
        }
        verified_members = verified_members.saturating_add(1);
    }

    if verified_members.saturating_add(2) != map.len() {
        return Err(SupportBundleError::VerificationFailed(
            "archive contains unmanifested members".into(),
        ));
    }
    Ok(sig)
}

fn collect_redacted_journal_doc(
    state_dir: Option<&Path>,
    home_dir: Option<&str>,
    hostname: Option<&str>,
    username: Option<&str>,
    salt: &str,
) -> Result<serde_json::Value, SupportBundleError> {
    let mut candidate_files: Vec<PathBuf> = Vec::new();
    if let Some(dir) = state_dir {
        candidate_files.push(dir.join("enrolment-state.json"));
        candidate_files.push(dir.join("audit.log.jsonl"));
        candidate_files.push(dir.join("audit.jsonl"));
    } else if let Some(home) = detect_home_dir() {
        let st = detect_state_dir(&home);
        candidate_files.push(st.join("enrolment-state.json"));
        candidate_files.push(st.join("audit.jsonl"));
        candidate_files.push(home.join(".local/share/grdr/state/enrolment-state.json"));
        candidate_files.push(home.join(".local/share/grdr/state/audit.log.jsonl"));
    }

    let mut entries = Vec::new();
    let mut sources = Vec::new();
    for file in candidate_files {
        let Ok(meta) = fs::symlink_metadata(&file) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        let raw = match read_bounded_utf8(&file, MAX_JOURNAL_FILE_BYTES) {
            Ok(text) => text,
            Err(_) => continue,
        };
        let label = file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("journal")
            .to_owned();
        sources.push(label.clone());
        if label.ends_with(".json")
            && let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw)
        {
            entries.push(serde_json::json!({
                "source": label,
                "record": redact_json_value(&val, home_dir, hostname, username, salt),
            }));
            continue;
        }
        for line in raw.lines() {
            if entries.len() >= MAX_JOURNAL_RECORDS {
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let record = match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(val) => redact_json_value(&val, home_dir, hostname, username, salt),
                Err(_) => serde_json::Value::String(scrub_text(
                    trimmed, home_dir, hostname, username, salt, None,
                )),
            };
            entries.push(serde_json::json!({
                "source": label,
                "record": record,
            }));
        }
    }

    Ok(serde_json::json!({
        "entries": entries,
        "journal_sources": sources,
        "redaction": "on-device-pre-preview",
        "excluded_classes": ["content", "secret", "memory_dump"],
    }))
}

fn render_manifest(marking: Option<&str>, fp: &str, members: &BTreeMap<String, String>) -> String {
    let mut lines = Vec::new();
    if let Some(m) = marking
        && !m.trim().is_empty()
    {
        lines.push(format!("Marking: {} (human-handling-only)", m.trim()));
    }
    lines.push("Format: grdr.support-bundle.v1".to_owned());
    lines.push(format!("Deployment-Fingerprint: {fp}"));
    lines.push("Data-Classes: metadata,structural".to_owned());
    lines.push("Excluded: content,secret,memory_dump".to_owned());
    for (name, content) in members {
        lines.push(format!(
            "member {} {} {}",
            name,
            sha256_hex(content.as_bytes()),
            content.len()
        ));
    }
    lines.join("\n")
}

fn ephemeral_device_salt() -> Result<String, SupportBundleError> {
    let mut buf = [0_u8; 16];
    fill_random(&mut buf).map_err(|e| SupportBundleError::VerificationFailed(e.to_string()))?;
    Ok(sha256_hex(&buf))
}

fn detect_home_string() -> Option<String> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|s| s.to_string_lossy().into_owned())
}

fn detect_username() -> Option<String> {
    std::env::var_os("USER")
        .or_else(|| std::env::var_os("USERNAME"))
        .map(|s| s.to_string_lossy().into_owned())
}

fn read_optional_bounded_config(path: &Path) -> Result<serde_json::Value, SupportBundleError> {
    let text = read_bounded_utf8(path, 1024 * 1024).map_err(|e| SupportBundleError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    serde_json::from_str(&text)
        .map_err(|e| SupportBundleError::VerificationFailed(format!("invalid config JSON: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_bundle_redacts_secrets_and_homes_and_verifies_offline() {
        let dir = std::env::temp_dir().join(format!("grdr-sup-{}", uuid::Uuid::now_v7().simple()));
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let fake_home = dir.join("home_alice");
        let cfg_path = dir.join("cfg.json");
        let synthetic_tok = ["sk-", "canary", "998877"].concat();
        let synthetic_ph = ["grdr_ph_", "canary1234"].concat();
        let synthetic_gh = ["github_pat_", "11AABBCCDD", "2233445566"].concat();
        let synthetic_dsn = ["postgres://alice:", "s3cr3tPass", "@db.local:5432/grdr"].concat();
        let synthetic_jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhIn0.c2lnbmF0dXJl";
        let synthetic_pem =
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----";
        let cfg_doc = serde_json::json!({
            "note": "disk_free ok; task-123 ok",
            "api_token": synthetic_tok,
            "ph_note": synthetic_ph,
            "kv_note": "password=mySecret99; Authorization: Token hdrTok77",
            "pat_note": format!("bearer {synthetic_gh}"),
            "db_url": synthetic_dsn,
            "jwt_line": format!("tok={synthetic_jwt}"),
            "key_material": synthetic_pem,
            "workspace": fake_home.join("repo").to_string_lossy().to_string(),
            "mode": "Ask",
        });
        fs::write(&cfg_path, serde_json::to_vec(&cfg_doc).unwrap()).unwrap();
        fs::write(
            state_dir.join("audit.log.jsonl"),
            format!("{{\"receipt_id\":\"rcp_1\",\"note\":\"{synthetic_dsn}\"}}\n"),
        )
        .unwrap();

        let key_path = dir.join("device.key");
        let kp = load_or_create_private_keypair(&key_path).unwrap();
        let fp = deployment_fingerprint(&kp.public_info());
        let tar_path = dir.join("support.tar");

        let opts = SupportBundleOptions {
            preview: true,
            out: Some(tar_path.clone()),
            inspect: None,
            fingerprint: None,
            marking: Some("TLP-AMBER".into()),
            config_file: Some(cfg_path),
            key_file: Some(key_path),
            state_dir: Some(state_dir),
            profile: InstallProfile::User,
        };
        let (preview, entries) = build_redacted_bundle(&opts).unwrap();
        let cfg_out = preview
            .members
            .get(PATH_CONFIG)
            .map(String::as_str)
            .unwrap_or("");
        assert!(!cfg_out.is_empty());
        assert!(cfg_out.contains("disk_free ok; task-123 ok"));
        for needle in [
            &synthetic_tok,
            &synthetic_ph,
            &synthetic_gh,
            "mySecret99",
            "hdrTok77",
            "s3cr3tPass",
            synthetic_jwt,
            "BEGIN PRIVATE KEY",
        ] {
            assert!(!cfg_out.contains(needle), "leaked {needle} in config");
        }
        let journal_out = preview
            .members
            .get(PATH_JOURNAL)
            .map(String::as_str)
            .unwrap_or("");
        assert!(journal_out.contains("rcp_1"));
        assert!(!journal_out.contains("s3cr3tPass"));
        assert!(preview.manifest.contains("TLP-AMBER"));
        write_tar_file(&tar_path, &entries).unwrap();
        let sig = inspect_support_bundle_tar(&tar_path, &fp).unwrap();
        assert_eq!(sig.deployment_fingerprint, fp);
        assert!(inspect_support_bundle_tar(&tar_path, "fp_mismatch").is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
