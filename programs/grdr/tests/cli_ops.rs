// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Subprocess CLI integration tests for S-31 air-gap, egress, support-bundle, comply, and enrolment commands.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use grdr_core::audit::{GENESIS_PREV_HASH, compute_chain_hash};

fn grdr_bin() -> &'static str {
    env!("CARGO_BIN_EXE_grdr")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn run_cli(args: &[&str], workdir: &Path) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(grdr_bin())
        .args(args)
        .current_dir(workdir)
        .env("HOME", workdir)
        .env("USERPROFILE", workdir)
        .output()?)
}

fn p_str(path: &Path) -> Result<&str, Box<dyn Error>> {
    path.to_str().ok_or_else(|| "non-UTF-8 test path".into())
}

fn check(cond: bool, msg: &str) -> Result<(), Box<dyn Error>> {
    if !cond {
        return Err(msg.into());
    }
    Ok(())
}

fn write_valid_chain_log(path: &Path, receipt_id: &str) -> Result<(), Box<dyn Error>> {
    let payload = format!(
        "{{\"event\":\"decision\",\"prev_hash\":\"{GENESIS_PREV_HASH}\",\"receipt_id\":\"{receipt_id}\",\"seq\":0}}"
    );
    let h0 = compute_chain_hash(GENESIS_PREV_HASH, payload.as_bytes());
    let line = format!(
        "{{\"event\":\"decision\",\"receipt_id\":\"{receipt_id}\",\"seq\":0,\"prev_hash\":\"{GENESIS_PREV_HASH}\",\"entry_hash\":\"{h0}\"}}\n"
    );
    fs::write(path, line)?;
    Ok(())
}

fn verify_egress_cli_flow() -> Result<(), Box<dyn Error>> {
    let dir =
        std::env::temp_dir().join(format!("grdr-cli-egress-{}", uuid::Uuid::now_v7().simple()));
    fs::create_dir_all(&dir)?;

    let out = run_cli(&["egress", "--isolated", "--json"], &dir)?;
    check(out.status.success(), &String::from_utf8_lossy(&out.stderr))?;
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    check(
        doc.get("isolated").and_then(|v| v.as_bool()) == Some(true),
        "expected isolated=true",
    )?;
    check(
        doc.get("destinations")
            .and_then(|v| v.as_array())
            .is_some_and(Vec::is_empty),
        "expected empty isolated destinations",
    )?;

    for bad in [
        "https://siem.outside.example/ingest",
        "https://evil.com?.airgap.test",
        "https://evil.com#x.airgap.test",
        "https://evil.com\\@ok.airgap.test",
        "http://2130706433/",
        "https://[::ffff:169.254.169.254]/latest",
    ] {
        let denied = run_cli(
            &[
                "server",
                "egress",
                "--isolated",
                "--allow",
                ".airgap.test",
                "--sink",
                bad,
                "--json",
            ],
            &dir,
        )?;
        check(
            !denied.status.success(),
            &format!("expected failure for {bad}"),
        )?;
    }

    let allowed = run_cli(
        &[
            "server",
            "egress",
            "--isolated",
            "--allow",
            ".airgap.test",
            "--mirror",
            "https://mirror.airgap.test:8443",
            "--json",
        ],
        &dir,
    )?;
    check(allowed.status.success(), "expected allowed mirror success")?;

    let v6_cidr_ok = run_cli(
        &[
            "server",
            "egress",
            "--isolated",
            "--allow",
            "10.77.0.0/16",
            "--sink",
            "https://[::ffff:10.77.2.15]:9000",
            "--json",
        ],
        &dir,
    )?;
    check(
        v6_cidr_ok.status.success(),
        "expected IPv4-mapped CIDR match",
    )?;

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

fn verify_end_to_end_ops_cli_flow() -> Result<(), Box<dyn Error>> {
    let dir = std::env::temp_dir().join(format!("grdr-cli-e2e-{}", uuid::Uuid::now_v7().simple()));
    fs::create_dir_all(&dir)?;
    let packs_dir = repo_root().join("packs");
    let keys_dir = dir.join("keys");
    let tar_path = dir.join("grdr-airgap-0.1.0.tar");

    // Without --key-dir or --ephemeral-dev-keys, build refuses.
    let no_keys = run_cli(
        &[
            "airgap",
            "build",
            "--packs-dir",
            p_str(&packs_dir)?,
            "--out",
            p_str(&tar_path)?,
            "--json",
        ],
        &dir,
    )?;
    check(
        !no_keys.status.success(),
        "build without --key-dir must fail",
    )?;

    let build = run_cli(
        &[
            "airgap",
            "build",
            "--packs-dir",
            p_str(&packs_dir)?,
            "--key-dir",
            p_str(&keys_dir)?,
            "--out",
            p_str(&tar_path)?,
            "--json",
        ],
        &dir,
    )?;
    check(
        build.status.success(),
        &String::from_utf8_lossy(&build.stderr),
    )?;
    let build_doc: serde_json::Value = serde_json::from_slice(&build.stdout)?;
    let fp = build_doc
        .get("root_fingerprint")
        .and_then(|v| v.as_str())
        .ok_or("missing root_fingerprint")?
        .to_owned();
    let manifest_sha = build_doc
        .get("manifest_sha256")
        .and_then(|v| v.as_str())
        .ok_or("missing manifest_sha256")?
        .to_owned();

    // Verify without any pinned root or --expected-fingerprint must fail (no self-signed fallback).
    let no_anchor = run_cli(
        &[
            "airgap",
            "verify",
            "--bundle",
            p_str(&tar_path)?,
            "--accept-terms",
            &manifest_sha,
            "--json",
        ],
        &dir,
    )?;
    check(
        !no_anchor.status.success(),
        "verify without trust anchor must fail",
    )?;

    let no_terms = run_cli(
        &[
            "airgap",
            "verify",
            "--bundle",
            p_str(&tar_path)?,
            "--expected-fingerprint",
            &fp,
            "--json",
        ],
        &dir,
    )?;
    check(
        !no_terms.status.success(),
        "verify without accept-terms must fail",
    )?;

    // Trailing smuggled bytes appended after zero tar EOF blocks must fail.
    let trailing_tar = dir.join("trailing.tar");
    let mut raw_tar = fs::read(&tar_path)?;
    raw_tar.extend_from_slice(&[b'X'; 512]);
    fs::write(&trailing_tar, &raw_tar)?;
    let trailing_res = run_cli(
        &[
            "airgap",
            "verify",
            "--bundle",
            p_str(&trailing_tar)?,
            "--expected-fingerprint",
            &fp,
            "--accept-terms",
            &manifest_sha,
            "--json",
        ],
        &dir,
    )?;
    check(
        !trailing_res.status.success(),
        "tar with trailing non-zero payload must fail",
    )?;

    let extract_dir = dir.join("verified");
    let ok_verify = run_cli(
        &[
            "airgap",
            "verify",
            "--bundle",
            p_str(&tar_path)?,
            "--expected-fingerprint",
            &fp,
            "--accept-terms",
            &manifest_sha,
            "--extract",
            p_str(&extract_dir)?,
            "--json",
        ],
        &dir,
    )?;
    check(
        ok_verify.status.success(),
        &String::from_utf8_lossy(&ok_verify.stderr),
    )?;
    check(
        extract_dir
            .join("packs/essentials/rules/essentials.cedar")
            .is_file(),
        "extracted cedar policy missing",
    )?;

    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let audit_path = state_dir.join("audit.log.jsonl");
    write_valid_chain_log(&audit_path, "rcp_cli_valid_01")?;

    let cfg_path = dir.join("cfg.json");
    let synthetic_secret = ["sk-", "cli", "canary", "001122"].concat();
    let synthetic_ph = ["grdr_ph_", "cliCanary88"].concat();
    let synthetic_pat = ["github_pat_", "cliTestToken9988"].concat();
    let synthetic_dsn = ["postgres://alice:", "dsnSecretPwd", "@db:5432/grdr"].concat();
    let synthetic_jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl";
    let synthetic_pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQY=\n-----END PRIVATE KEY-----";
    fs::write(
        &cfg_path,
        serde_json::to_vec(&serde_json::json!({
            "note": "disk_free ok; task-123 ok",
            "api_token": synthetic_secret,
            "ph_note": synthetic_ph,
            "kv_note": "password=inlineSecret99; Authorization: Token tokCli44",
            "note_auth": format!("bearer {synthetic_pat}"),
            "db_url": synthetic_dsn,
            "jwt_sample": format!("tok={synthetic_jwt}"),
            "pem_sample": synthetic_pem,
            "workspace": dir.join("repo").display().to_string(),
        }))?,
    )?;
    let key_path = dir.join("device.key");
    let sup_tar = dir.join("support.tar");
    let preview = run_cli(
        &[
            "support-bundle",
            "--preview",
            "--config-file",
            p_str(&cfg_path)?,
            "--state-dir",
            p_str(&state_dir)?,
            "--key-file",
            p_str(&key_path)?,
            "--out",
            p_str(&sup_tar)?,
            "--json",
        ],
        &dir,
    )?;
    check(
        preview.status.success(),
        &String::from_utf8_lossy(&preview.stderr),
    )?;
    let preview_str = String::from_utf8_lossy(&preview.stdout);
    check(
        preview_str.contains("disk_free ok; task-123 ok"),
        "benign disk_free/task-123 text was corrupted",
    )?;
    for needle in [
        synthetic_secret.as_str(),
        synthetic_ph.as_str(),
        synthetic_pat.as_str(),
        "inlineSecret99",
        "tokCli44",
        "dsnSecretPwd",
        synthetic_jwt,
        "BEGIN PRIVATE KEY",
    ] {
        check(
            !preview_str.contains(needle),
            "support bundle leaked secret",
        )?;
    }
    check(
        preview_str.contains("rcp_cli_valid_01"),
        "support bundle did not include redacted journal entries",
    )?;
    let sup_doc: serde_json::Value = serde_json::from_slice(&preview.stdout)?;
    let dev_fp = sup_doc
        .get("deployment_fingerprint")
        .and_then(|v| v.as_str())
        .ok_or("missing deployment_fingerprint")?
        .to_owned();

    let inspect = run_cli(
        &[
            "support-bundle",
            "--inspect",
            p_str(&sup_tar)?,
            "--fingerprint",
            &dev_fp,
            "--json",
        ],
        &dir,
    )?;
    check(inspect.status.success(), "support bundle inspect failed")?;

    let ev_bundle = dir.join("evidence.json");
    let export = run_cli(
        &[
            "comply",
            "export",
            "--format",
            "bundle",
            "--audit-log",
            p_str(&audit_path)?,
            "--key-file",
            p_str(&key_path)?,
            "--out",
            p_str(&ev_bundle)?,
            "--json",
        ],
        &dir,
    )?;
    check(export.status.success(), "comply export failed")?;

    let verify_ev = run_cli(
        &[
            "comply",
            "verify",
            "--bundle",
            p_str(&ev_bundle)?,
            "--fingerprint",
            &dev_fp,
            "--json",
        ],
        &dir,
    )?;
    check(verify_ev.status.success(), "comply verify failed")?;

    let bad_audit = dir.join("bad-audit.log.jsonl");
    fs::write(
        &bad_audit,
        b"{\"receipt_id\":\"rcp_fake\",\"prev_hash\":\"bad\",\"entry_hash\":\"bad\"}\n",
    )?;
    let bad_comply = run_cli(
        &[
            "comply",
            "evidence",
            "--audit-log",
            p_str(&bad_audit)?,
            "--json",
        ],
        &dir,
    )?;
    check(
        !bad_comply.status.success(),
        "comply evidence must reject tampered audit log",
    )?;

    let rfp = run_cli(
        &[
            "comply",
            "rfp",
            "--audit-log",
            p_str(&audit_path)?,
            "--topology",
            "server-available",
            "--json",
        ],
        &dir,
    )?;
    check(rfp.status.success(), "comply rfp failed")?;
    let rfp_doc: serde_json::Value = serde_json::from_slice(&rfp.stdout)?;
    check(
        rfp_doc.get("release_gate_passed").and_then(|v| v.as_bool()) == Some(false),
        "rfp without --acceptance-report must fail release gate",
    )?;
    let all_red = rfp_doc
        .get("items")
        .and_then(|v| v.as_array())
        .is_some_and(|items| {
            items.len() == 17
                && items
                    .iter()
                    .all(|it| it.get("test_green") == Some(&serde_json::Value::Bool(false)))
        });
    check(
        all_red,
        "all T1..T17 test_green must be false without --acceptance-report",
    )?;

    let enrol_file = dir.join("enrol.tok");
    fs::write(&enrol_file, b"airgap-anchor-secret")?;
    for bad_origin in [
        "http://server.airgap.test:8443",
        "https://[::ffff:169.254.169.254]/latest",
        "https://100.100.100.200/latest",
        "https://metadata.google.internal/",
    ] {
        let bad_join = run_cli(
            &[
                "join",
                bad_origin,
                "--enrol-file",
                p_str(&enrol_file)?,
                "--state-dir",
                p_str(&state_dir)?,
                "--json",
            ],
            &dir,
        )?;
        check(
            !bad_join.status.success(),
            &format!("expected join failure for {bad_origin}"),
        )?;
    }

    let joined = run_cli(
        &[
            "join",
            "https://server.airgap.test:8443",
            "--enrol-file",
            p_str(&enrol_file)?,
            "--network-mode",
            "isolated",
            "--allow",
            ".airgap.test",
            "--state-dir",
            p_str(&state_dir)?,
            "--json",
        ],
        &dir,
    )?;
    check(joined.status.success(), "join failed")?;
    let join_doc: serde_json::Value = serde_json::from_slice(&joined.stdout)?;
    let has_locked = join_doc
        .get("lifecycle")
        .and_then(|v| v.get("locked_rules"))
        .and_then(|v| v.as_array())
        .is_some_and(|arr| !arr.is_empty());
    check(has_locked, "join fallback locked_rules must not be empty")?;
    check(
        !enrol_file.exists(),
        "enrol file must be removed after join",
    )?;

    let left = run_cli(
        &["leave", "--state-dir", p_str(&state_dir)?, "--json"],
        &dir,
    )?;
    check(left.status.success(), "leave failed")?;
    let left_doc: serde_json::Value = serde_json::from_slice(&left.stdout)?;
    check(
        left_doc
            .get("lifecycle")
            .and_then(|v| v.get("history_preserved_entries"))
            .and_then(|v| v.as_u64())
            == Some(1),
        "history count mismatch after leave",
    )?;

    let protect = run_cli(
        &[
            "protect",
            "--from",
            p_str(&tar_path)?,
            "--expected-fingerprint",
            &fp,
            "--accept-terms",
            &manifest_sha,
            "--state-dir",
            p_str(&state_dir)?,
            "--apply",
            "--json",
        ],
        &dir,
    )?;
    check(protect.status.success(), "protect failed")?;

    #[cfg(unix)]
    {
        let sym_extract = dir.join("sym-extract");
        fs::create_dir_all(&sym_extract)?;
        std::os::unix::fs::symlink("/etc", sym_extract.join("packs"))?;
        let sym_res = run_cli(
            &[
                "airgap",
                "verify",
                "--bundle",
                p_str(&tar_path)?,
                "--expected-fingerprint",
                &fp,
                "--accept-terms",
                &manifest_sha,
                "--extract",
                p_str(&sym_extract)?,
                "--json",
            ],
            &dir,
        )?;
        check(
            !sym_res.status.success(),
            "airgap extract into symlink target must fail",
        )?;
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn cli_egress_isolated_and_server_egress_enforce_allow_list() {
    let res = verify_egress_cli_flow();
    assert!(res.is_ok(), "egress cli flow failed: {res:?}");
}

#[test]
fn cli_airgap_support_bundle_comply_and_enrol_end_to_end() {
    let res = verify_end_to_end_ops_cli_flow();
    assert!(res.is_ok(), "end-to-end ops cli flow failed: {res:?}");
}
