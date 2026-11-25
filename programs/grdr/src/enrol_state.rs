// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Endpoint enrolment state, voucher authentication, origin validation, and symlink-safe persistence.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use grdr_crypto::verify_bytes;
use grdr_model::InstallProfile;
use grdr_update::canonical_sha256;
use jiff::Timestamp;
use serde::Deserialize;
use zeroize::Zeroize;

use crate::egress::{parse_endpoint_host_port, unwrap_embedded_ipv4};
use crate::enrol::{CaptureLevel, DeviceLifecycleState, EnrolCliError};
use crate::fs_safe::{
    atomic_write_bytes, ensure_safe_dir_all, read_bounded_regular, read_bounded_utf8,
    secure_delete_file,
};

const MAX_ENROL_FILE_BYTES: u64 = 64 * 1024;
const MAX_STATE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_AUDIT_SCAN_BYTES: u64 = 16 * 1024 * 1024;
const STATE_FILE_NAME: &str = "enrolment-state.json";
const LOCAL_AUDIT_FILE_NAME: &str = "audit.log.jsonl";
const ENROL_VOUCHER_DOMAIN: &str = "grdr.enrol.voucher.v1";

#[derive(Debug, Deserialize)]
struct EnrolVoucherDoc {
    token: String,
    server_url: Option<String>,
    server_org_id: Option<String>,
    #[serde(default)]
    readers: Vec<String>,
    #[serde(default)]
    locked_rules: Vec<String>,
    verifier_ed25519_b64: Option<String>,
    signature_b64: Option<String>,
}

pub struct ConsumedEnrolMaterial {
    pub server_org_id: String,
    pub readers: Vec<String>,
    pub locked_rules: Vec<String>,
}

pub fn validate_server_origin(server: &str) -> Result<(), EnrolCliError> {
    let trimmed = server.trim();
    if !trimmed.starts_with("https://") {
        return Err(EnrolCliError::Invalid(format!(
            "server URL `{server}` must use https://"
        )));
    }
    let (host, _) = parse_endpoint_host_port(trimmed)?;
    if is_forbidden_origin_host(&host) {
        return Err(EnrolCliError::Invalid(format!(
            "forbidden loopback, link-local, or cloud metadata origin `{host}`"
        )));
    }
    Ok(())
}

fn is_forbidden_origin_host(host: &str) -> bool {
    let norm = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if matches!(
        norm.as_str(),
        "localhost" | "metadata" | "metadata.google.internal" | "metadata.goog" | "instance-data"
    ) || norm.ends_with(".localhost")
        || norm.ends_with(".local")
    {
        return true;
    }
    if let Ok(ip) = norm.parse::<IpAddr>() {
        return is_forbidden_origin_ip(ip);
    }
    false
}

fn is_forbidden_origin_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            let segs = v6.segments();
            // AWS IPv6 IMDS fd00:ec2::254 and link-local fe80::/10 and documentation 2001:db8::/32.
            if (segs[0] & 0xffc0) == 0xfe80
                || (segs[0] == 0x2001 && segs[1] == 0x0db8)
                || (segs[0] == 0xfd00 && segs[1] == 0x0ec2 && segs[7] == 0x0254)
            {
                return true;
            }
            unwrap_embedded_ipv4(v6).is_some_and(is_forbidden_v4)
        }
    }
}

fn is_forbidden_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, d] = v4.octets();
    v4.is_loopback()
        || v4.is_unspecified()
        || a == 0
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || (a == 100 && b == 100 && c == 100 && d == 200)
        || (a == 192 && b == 0 && c == 0 && d == 192)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240
}

pub fn consume_enrol_credential(
    enrol_file: Option<&Path>,
    server: &str,
    cli_readers: &[String],
    locked_rules_from_pack: Vec<String>,
) -> Result<ConsumedEnrolMaterial, EnrolCliError> {
    let path = enrol_file.ok_or_else(|| {
        EnrolCliError::Invalid(
            "GRDR-ENROL-0002: --enrol-file enrolment credential is required".into(),
        )
    })?;
    let mut raw = read_bounded_regular(path, MAX_ENROL_FILE_BYTES)
        .map_err(|e| io_err(path, &e.to_string()))?;
    if raw.is_empty() {
        raw.zeroize();
        return Err(EnrolCliError::Invalid(
            "enrolment credential file is empty".into(),
        ));
    }

    let text = String::from_utf8(raw.clone())
        .map_err(|_| EnrolCliError::Invalid("enrolment credential must be UTF-8".into()));
    raw.zeroize();
    let mut text = text?;
    let trimmed = text.trim().to_owned();
    let res = parse_enrol_payload(&trimmed, server, cli_readers, locked_rules_from_pack);
    text.zeroize();
    let material = res?;
    secure_delete_file(path).map_err(|e| io_err(path, &e.to_string()))?;
    Ok(material)
}

fn parse_enrol_payload(
    trimmed: &str,
    server: &str,
    cli_readers: &[String],
    default_locked_rules: Vec<String>,
) -> Result<ConsumedEnrolMaterial, EnrolCliError> {
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err(EnrolCliError::Invalid(
            "enrolment token must not be empty or contain control characters".into(),
        ));
    }
    if trimmed.starts_with('{') {
        let doc: EnrolVoucherDoc = serde_json::from_str(trimmed)
            .map_err(|e| EnrolCliError::Invalid(format!("invalid enrolment voucher JSON: {e}")))?;
        if doc.token.trim().len() < 8 {
            return Err(EnrolCliError::Invalid(
                "enrolment voucher token must be at least 8 characters".into(),
            ));
        }
        if let Some(expected_srv) = doc.server_url.as_deref()
            && parse_endpoint_host_port(expected_srv)? != parse_endpoint_host_port(server)?
        {
            return Err(EnrolCliError::Invalid(
                "enrolment voucher server_url does not match --server".into(),
            ));
        }
        match (
            doc.verifier_ed25519_b64.as_deref(),
            doc.signature_b64.as_deref(),
        ) {
            (Some(pk), Some(sig)) => {
                let org = doc.server_org_id.as_deref().unwrap_or("");
                let msg = format!("{server}|{org}|{}", doc.token.trim());
                verify_bytes(pk, ENROL_VOUCHER_DOMAIN, msg.as_bytes(), sig).map_err(|e| {
                    EnrolCliError::Invalid(format!(
                        "enrolment voucher signature verification failed: {e}"
                    ))
                })?;
            }
            (None, None) => {}
            _ => {
                return Err(EnrolCliError::Invalid(
                    "enrolment voucher must provide both verifier_ed25519_b64 and signature_b64"
                        .into(),
                ));
            }
        }
        let server_org_id = match doc.server_org_id {
            Some(id) if !id.trim().is_empty() => id.trim().to_owned(),
            _ => derive_org_id(server, doc.token.trim()),
        };
        let readers = if !doc.readers.is_empty() {
            doc.readers
        } else if !cli_readers.is_empty() {
            cli_readers.to_vec()
        } else {
            vec!["local-operator".into()]
        };
        let locked_rules = if !doc.locked_rules.is_empty() {
            doc.locked_rules
        } else {
            default_locked_rules
        };
        return Ok(ConsumedEnrolMaterial {
            server_org_id,
            readers,
            locked_rules,
        });
    }

    if trimmed.len() < 8 {
        return Err(EnrolCliError::Invalid(
            "enrolment credential token must be at least 8 characters".into(),
        ));
    }
    let readers = if cli_readers.is_empty() {
        vec!["local-operator".into()]
    } else {
        cli_readers.to_vec()
    };
    Ok(ConsumedEnrolMaterial {
        server_org_id: derive_org_id(server, trimmed),
        readers,
        locked_rules: default_locked_rules,
    })
}

fn derive_org_id(server: &str, token: &str) -> String {
    let tok_hash = canonical_sha256(token.as_bytes());
    let bound = canonical_sha256(format!("{server}:{tok_hash}").as_bytes());
    format!("org_{}", bound.get(..12).unwrap_or("enrolled"))
}

pub fn discover_final_policy_rules(packs_dir: Option<&Path>) -> Vec<String> {
    let candidate = packs_dir
        .map(|p| p.join("essentials/rules/essentials.cedar"))
        .unwrap_or_else(|| PathBuf::from("packs/essentials/rules/essentials.cedar"));
    if let Ok(src) = read_bounded_utf8(&candidate, MAX_STATE_FILE_BYTES) {
        let mut locked = Vec::new();
        for block in src.split(';') {
            if !block.contains("@final(\"true\")") {
                continue;
            }
            if let Some(id_start) = block.find("@id(\"")
                && let Some(rest) = block.get(id_start.saturating_add(5)..)
                && let Some(end) = rest.find('"')
                && let Some(id) = rest.get(..end)
            {
                locked.push(id.to_owned());
            }
        }
        if !locked.is_empty() {
            return locked;
        }
    }
    if packs_dir.is_none() {
        return grdr_core::policy::essentials_pack()
            .rules
            .into_iter()
            .filter(|r| r.locked)
            .map(|r| r.id)
            .collect();
    }
    Vec::new()
}

pub fn resolve_state_dir(override_dir: Option<&Path>) -> Result<PathBuf, EnrolCliError> {
    let dir = match override_dir {
        Some(d) => d.to_path_buf(),
        None => {
            let home = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            home.join(".local").join("share").join("grdr").join("state")
        }
    };
    ensure_safe_dir_all(&dir, true).map_err(|e| io_err(&dir, &e.to_string()))?;
    Ok(dir)
}

pub fn load_or_init_state(dir: &Path) -> Result<DeviceLifecycleState, EnrolCliError> {
    let path = dir.join(STATE_FILE_NAME);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(io_err(
                    &path,
                    "state file must be a regular non-symlink file",
                ));
            }
            let raw = read_bounded_utf8(&path, MAX_STATE_FILE_BYTES)
                .map_err(|e| io_err(&path, &e.to_string()))?;
            serde_json::from_str(&raw).map_err(|e| EnrolCliError::Invalid(e.to_string()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(DeviceLifecycleState::Standalone {
                profile: InstallProfile::User,
                capture_level: CaptureLevel::Metadata,
                local_org_id: "org_local_standalone".into(),
                history_preserved_entries: count_local_audit_entries(dir),
                updated_at: Timestamp::now(),
            })
        }
        Err(e) => Err(io_err(&path, &e.to_string())),
    }
}

pub fn save_state(dir: &Path, state: &DeviceLifecycleState) -> Result<(), EnrolCliError> {
    let path = dir.join(STATE_FILE_NAME);
    let json =
        serde_json::to_vec_pretty(state).map_err(|e| EnrolCliError::Invalid(e.to_string()))?;
    atomic_write_bytes(&path, &json, true).map_err(|e| io_err(&path, &e.to_string()))
}

pub fn load_enrolled_server(state_dir: Option<&Path>) -> Option<String> {
    let dir = resolve_state_dir(state_dir).ok()?;
    let path = dir.join(STATE_FILE_NAME);
    let raw = read_bounded_utf8(&path, MAX_STATE_FILE_BYTES).ok()?;
    match serde_json::from_str::<DeviceLifecycleState>(&raw).ok()? {
        DeviceLifecycleState::Enrolled { server_url, .. } => Some(server_url),
        DeviceLifecycleState::Standalone { .. } => None,
    }
}

pub fn count_local_audit_entries(dir: &Path) -> usize {
    let path = dir.join(LOCAL_AUDIT_FILE_NAME);
    let Ok(raw) = read_bounded_utf8(&path, MAX_AUDIT_SCAN_BYTES) else {
        return 0;
    };
    raw.lines().filter(|l| !l.trim().is_empty()).count()
}

fn io_err(path: &Path, detail: &str) -> EnrolCliError {
    EnrolCliError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}
