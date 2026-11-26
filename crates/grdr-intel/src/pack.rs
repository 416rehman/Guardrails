// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! `PackKind::Intel` restrict-only pack validator (`docs/design/14`, `P2`, `P7`).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::normalize_observable;
use crate::record::{ClaimNature, GrdrIntelId, IntelRecord, IntelStatus, compute_status};
use crate::validators::{
    canonicalize_strict_dns_domain, validate_http_https_url, validate_observable_syntax,
};
use crate::{IntelError, embedded_limits};

const MAX_JSON_SCAN_DEPTH: usize = 64;
const MAX_RAPID_LANE_RECORDS: usize = 10_000;
const MAX_STANDARD_LANE_RECORDS: usize = 500_000;
const MAX_OBSERVABLES_PER_RECORD: usize = 512;
const MAX_EVIDENCE_PER_RECORD: usize = 128;
const MAX_FIELD_STRING_BYTES: usize = 4_096;
const MAX_GUARD_DOMAINS: usize = 10_000;

const FORBIDDEN_INTEL_KEYS: &[&str] = &[
    "allow",
    "allow_list",
    "allowlist",
    "grant",
    "grants",
    "suppress",
    "suppressions",
    "rules",
    "rule",
    "cedar",
    "mode",
    "modes",
    "mode_overrides",
    "action_ceiling",
    "max_mode",
    "exec",
    "command",
    "commands",
    "path",
    "url",
    "env",
    "hooks",
    "hook",
    "mcp_server",
    "mcp_servers",
    "mcpservers",
    "mcpserver",
    "permit",
    "exception",
    "exceptions",
    "declassify",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackKind {
    Intel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Polarity {
    Protect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelPackManifest {
    pub pack_id: String,
    pub kind: PackKind,
    pub polarity: Polarity,
    pub version: String,
    pub channel: String,
    pub publisher: String,
    #[serde(default)]
    pub guard_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawValidatedIntelPack")]
pub struct ValidatedIntelPack {
    pub manifest: IntelPackManifest,
    pub records: Vec<IntelRecord>,
    pub active_malicious_count: u64,
    pub active_suspicious_count: u64,
    pub active_vulnerable_count: u64,
    pub withdrawn_count: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawValidatedIntelPack {
    manifest: IntelPackManifest,
    records: Vec<IntelRecord>,
    active_malicious_count: u64,
    active_suspicious_count: u64,
    active_vulnerable_count: u64,
    withdrawn_count: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlatIntelPackWire {
    pack_id: String,
    kind: PackKind,
    polarity: Polarity,
    version: String,
    channel: String,
    publisher: String,
    #[serde(default)]
    guard_domains: Vec<String>,
    records: Vec<IntelRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NestedIntelPackWire {
    manifest: IntelPackManifest,
    records: Vec<IntelRecord>,
}

impl TryFrom<RawValidatedIntelPack> for ValidatedIntelPack {
    type Error = IntelError;

    fn try_from(raw: RawValidatedIntelPack) -> Result<Self, Self::Error> {
        let estimated_bytes = serde_json::to_vec(&raw.records)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        let validated = build_validated_pack(raw.manifest, raw.records, estimated_bytes)?;
        if validated.active_malicious_count != raw.active_malicious_count
            || validated.active_suspicious_count != raw.active_suspicious_count
            || validated.active_vulnerable_count != raw.active_vulnerable_count
            || validated.withdrawn_count != raw.withdrawn_count
        {
            return Err(IntelError::NonRestrictivePack(
                "intel pack summary counts do not match records".into(),
            ));
        }
        Ok(validated)
    }
}

/// Validates raw JSON pack payloads strictly as restrict-only `PackKind::Intel`,
/// enforcing recursive P7 checks, schema caps, duplicate ID rejection, and lane rules (`D-32`).
pub fn validate_intel_pack_json(raw_json: &str) -> Result<ValidatedIntelPack, IntelError> {
    let (base_max_bytes, _) = pack_byte_limits()?;
    if raw_json.len() > base_max_bytes {
        return Err(IntelError::NonRestrictivePack(format!(
            "intel pack payload {} bytes exceeds intel_base_max_mb bound ({base_max_bytes})",
            raw_json.len()
        )));
    }

    let doc: Value = serde_json::from_str(raw_json)
        .map_err(|e| IntelError::NonRestrictivePack(format!("invalid intel pack JSON: {e}")))?;
    scan_forbidden_keys_recursive(&doc, 0)?;

    let has_manifest_wrapper = doc
        .as_object()
        .ok_or_else(|| {
            IntelError::NonRestrictivePack("intel pack root must be a JSON object".into())
        })?
        .contains_key("manifest");

    let (manifest, records) = if has_manifest_wrapper {
        let nested: NestedIntelPackWire = serde_json::from_value(doc).map_err(|_| {
            IntelError::NonRestrictivePack("invalid nested intel pack schema".into())
        })?;
        (nested.manifest, nested.records)
    } else {
        let flat: FlatIntelPackWire = serde_json::from_value(doc)
            .map_err(|_| IntelError::NonRestrictivePack("invalid intel pack schema".into()))?;
        (
            IntelPackManifest {
                pack_id: flat.pack_id,
                kind: flat.kind,
                polarity: flat.polarity,
                version: flat.version,
                channel: flat.channel,
                publisher: flat.publisher,
                guard_domains: flat.guard_domains,
            },
            flat.records,
        )
    };

    build_validated_pack(manifest, records, raw_json.len())
}

fn pack_byte_limits() -> Result<(usize, usize), IntelError> {
    let limits = embedded_limits().map_err(|msg| IntelError::NonRestrictivePack(msg.into()))?;
    let base_max_bytes = usize::try_from(limits.packs.intel_base_max_mb)
        .unwrap_or(24)
        .saturating_mul(1024)
        .saturating_mul(1024);
    let rapid_max_bytes = usize::try_from(limits.packs.intel_daily_segment_max_kb)
        .unwrap_or(100)
        .saturating_mul(1024);
    Ok((base_max_bytes, rapid_max_bytes))
}

fn build_validated_pack(
    manifest: IntelPackManifest,
    records: Vec<IntelRecord>,
    payload_bytes: usize,
) -> Result<ValidatedIntelPack, IntelError> {
    let (base_max_bytes, rapid_max_bytes) = pack_byte_limits()?;
    if payload_bytes > base_max_bytes {
        return Err(IntelError::NonRestrictivePack(
            "intel pack exceeds intel_base_max_mb bound".into(),
        ));
    }
    validate_manifest_and_lane_bounds(&manifest, payload_bytes, rapid_max_bytes, records.len())?;

    let is_rapid = manifest.channel == "rapid";
    let mut seen_ids = BTreeSet::new();
    let mut active_malicious_count: u64 = 0;
    let mut active_suspicious_count: u64 = 0;
    let mut active_vulnerable_count: u64 = 0;
    let mut withdrawn_count: u64 = 0;

    for rec in &records {
        validate_record(rec, is_rapid, &mut seen_ids)?;
        match compute_status(rec) {
            IntelStatus::Malicious => {
                active_malicious_count = active_malicious_count.saturating_add(1);
            }
            IntelStatus::Suspicious => {
                active_suspicious_count = active_suspicious_count.saturating_add(1);
            }
            IntelStatus::Vulnerable => {
                active_vulnerable_count = active_vulnerable_count.saturating_add(1);
            }
            IntelStatus::Withdrawn => {
                withdrawn_count = withdrawn_count.saturating_add(1);
            }
            IntelStatus::None => {}
        }
    }

    Ok(ValidatedIntelPack {
        manifest,
        records,
        active_malicious_count,
        active_suspicious_count,
        active_vulnerable_count,
        withdrawn_count,
    })
}

fn validate_manifest_and_lane_bounds(
    manifest: &IntelPackManifest,
    raw_bytes: usize,
    rapid_max_bytes: usize,
    record_count: usize,
) -> Result<(), IntelError> {
    if !is_bounded_non_empty(&manifest.pack_id)
        || !is_bounded_non_empty(&manifest.version)
        || !is_bounded_non_empty(&manifest.publisher)
        || !is_bounded_non_empty(&manifest.channel)
    {
        return Err(IntelError::NonRestrictivePack(
            "intel manifest identifiers must be bounded, non-empty, and control-free".into(),
        ));
    }
    if manifest.guard_domains.len() > MAX_GUARD_DOMAINS
        || manifest
            .guard_domains
            .iter()
            .any(|d| !is_bounded_non_empty(d) || canonicalize_strict_dns_domain(d).is_none())
    {
        return Err(IntelError::NonRestrictivePack(
            "intel manifest guard_domains exceed bounds or contain invalid entries".into(),
        ));
    }
    match manifest.channel.as_str() {
        "standard" => {
            if record_count > MAX_STANDARD_LANE_RECORDS {
                return Err(IntelError::NonRestrictivePack(format!(
                    "standard lane record count {record_count} exceeds {MAX_STANDARD_LANE_RECORDS}"
                )));
            }
        }
        "rapid" => {
            if raw_bytes > rapid_max_bytes {
                return Err(IntelError::NonRestrictivePack(format!(
                    "rapid lane payload {raw_bytes} bytes exceeds intel_daily_segment_max_kb ({rapid_max_bytes})"
                )));
            }
            if record_count > MAX_RAPID_LANE_RECORDS {
                return Err(IntelError::NonRestrictivePack(format!(
                    "rapid lane record count {record_count} exceeds {MAX_RAPID_LANE_RECORDS}"
                )));
            }
            if !manifest.guard_domains.is_empty() {
                return Err(IntelError::NonRestrictivePack(
                    "rapid lane packs cannot define guard_domains".into(),
                ));
            }
        }
        _ => {
            return Err(IntelError::NonRestrictivePack(
                "unsupported intel channel; expected 'standard' or 'rapid'".into(),
            ));
        }
    }
    Ok(())
}

fn validate_record(
    rec: &IntelRecord,
    is_rapid: bool,
    seen_ids: &mut BTreeSet<String>,
) -> Result<(), IntelError> {
    let canonical_id = GrdrIntelId::parse(rec.id.as_str())?;
    if !seen_ids.insert(canonical_id.as_str().to_owned()) {
        return Err(IntelError::InvalidRecord(format!(
            "duplicate intel record id `{}`",
            canonical_id.as_str()
        )));
    }
    if !is_bounded_non_empty(&rec.title) {
        return Err(IntelError::InvalidRecord(format!(
            "record `{}` title missing, contains controls, or exceeds byte limit",
            canonical_id.as_str()
        )));
    }
    if rec.observables.is_empty() || rec.observables.len() > MAX_OBSERVABLES_PER_RECORD {
        return Err(IntelError::InvalidRecord(format!(
            "record `{}` observables count invalid",
            canonical_id.as_str()
        )));
    }
    if rec.evidence.len() > MAX_EVIDENCE_PER_RECORD {
        return Err(IntelError::InvalidRecord(format!(
            "record `{}` evidence count exceeds bound",
            canonical_id.as_str()
        )));
    }
    for obs in &rec.observables {
        validate_observable_syntax(obs.kind, &obs.value, MAX_FIELD_STRING_BYTES)
            .map_err(|msg| IntelError::InvalidRecord(msg.into()))?;
        if normalize_observable(obs.kind, &obs.value).is_empty() {
            return Err(IntelError::InvalidRecord(format!(
                "record `{}` contains empty or control-character observable",
                canonical_id.as_str()
            )));
        }
        if let Some(ref range) = obs.version_range {
            crate::semver::validate_version_range_syntax(range)?;
        }
    }
    for ev in &rec.evidence {
        if !is_bounded_non_empty(&ev.organisation)
            || ev.summary.len() > MAX_FIELD_STRING_BYTES
            || ev.summary.chars().any(char::is_control)
            || ev.based_on_organisation.as_deref().is_some_and(|b| {
                b.len() > MAX_FIELD_STRING_BYTES || b.chars().any(char::is_control)
            })
        {
            return Err(IntelError::InvalidRecord(format!(
                "record `{}` evidence string invalid or exceeds byte limit",
                canonical_id.as_str()
            )));
        }
        if let Some(ref u) = ev.reference_url {
            validate_http_https_url(u, MAX_FIELD_STRING_BYTES)
                .map_err(|msg| IntelError::InvalidRecord(msg.into()))?;
        }
    }

    let status = compute_status(rec);
    if is_rapid
        && (status == IntelStatus::Vulnerable
            || (!rec.withdrawn
                && rec
                    .evidence
                    .iter()
                    .any(|ev| ev.nature == ClaimNature::Vulnerable)))
    {
        return Err(IntelError::NonRestrictivePack(format!(
            "rapid lane pack cannot carry vulnerable advisory `{}`",
            canonical_id.as_str()
        )));
    }
    Ok(())
}

fn is_bounded_non_empty(val: &str) -> bool {
    !val.trim().is_empty()
        && val.len() <= MAX_FIELD_STRING_BYTES
        && !val.chars().any(char::is_control)
}

fn scan_forbidden_keys_recursive(val: &Value, depth: usize) -> Result<(), IntelError> {
    if depth > MAX_JSON_SCAN_DEPTH {
        return Err(IntelError::NonRestrictivePack(
            "intel JSON exceeds maximum nesting depth".into(),
        ));
    }
    match val {
        Value::Object(map) => {
            for (k, child) in map {
                let norm = k.trim().to_ascii_lowercase();
                if FORBIDDEN_INTEL_KEYS.contains(&norm.as_str()) {
                    return Err(IntelError::NonRestrictivePack(
                        "forbidden field in PackKind::Intel payload".into(),
                    ));
                }
                scan_forbidden_keys_recursive(child, depth.saturating_add(1))?;
            }
        }
        Value::Array(items) => {
            for item in items {
                scan_forbidden_keys_recursive(item, depth.saturating_add(1))?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_base_pack(channel: &str) -> Value {
        serde_json::json!({
            "pack_id": "grdr.intel.core",
            "kind": "intel",
            "polarity": "protect",
            "version": "1.0.0",
            "channel": channel,
            "publisher": "Guardrails",
            "records": [{
                "id": "GRDRI-2026-00001",
                "title": "Malicious typosquat package",
                "severity": "critical",
                "withdrawn": false,
                "observables": [{
                    "kind": "package-purl",
                    "value": "pkg:npm/evil-typosquat@1.0.0",
                    "version_range": null
                }],
                "evidence": [{
                    "feed": "ossf",
                    "organisation": "OSSF",
                    "method_family": "human_review",
                    "nature": "malicious",
                    "review_state": "published_external_human_review",
                    "disposition": "active",
                    "reference_url": null,
                    "summary": "Verified credential exfiltration in preinstall"
                }]
            }]
        })
    }

    #[test]
    fn rejects_allow_rules_modes_and_exec_inside_intel_pack() {
        for bad_key in [
            "allow",
            "rules",
            "rule",
            "mode",
            "exec",
            "Allow",
            "mcpServers",
            "action_ceiling",
            "max_mode",
            "command",
            "path",
            "url",
            "env",
            "mcp_server",
            "permit",
            "exception",
        ] {
            let mut payload = valid_base_pack("rapid");
            payload
                .as_object_mut()
                .expect("object")
                .insert(bad_key.to_owned(), serde_json::json!(["anything"]));
            assert!(
                matches!(
                    validate_intel_pack_json(&payload.to_string()),
                    Err(IntelError::NonRestrictivePack(_))
                ),
                "expected rejection for forbidden field `{bad_key}`"
            );
        }

        let pack = validate_intel_pack_json(&valid_base_pack("rapid").to_string())
            .expect("valid intel pack");
        assert_eq!(pack.active_malicious_count, 1);
    }

    #[test]
    fn rejects_nested_forbidden_unknown_fields_duplicates_rapid_advisories_and_oversized() {
        let mut nested_bad = valid_base_pack("standard");
        nested_bad["records"][0]["evidence"][0]["mcpServers"] = serde_json::json!({});
        assert!(matches!(
            validate_intel_pack_json(&nested_bad.to_string()),
            Err(IntelError::NonRestrictivePack(_))
        ));

        let mut unknown_field = valid_base_pack("standard");
        unknown_field["records"][0]["observables"][0]["extra_stuff"] = serde_json::json!(true);
        assert!(validate_intel_pack_json(&unknown_field.to_string()).is_err());

        let mut dup = valid_base_pack("standard");
        let first = dup["records"][0].clone();
        dup["records"].as_array_mut().expect("arr").push(first);
        assert!(matches!(
            validate_intel_pack_json(&dup.to_string()),
            Err(IntelError::InvalidRecord(_))
        ));

        let rapid_vuln = serde_json::json!({
            "pack_id": "grdr.intel.rapid",
            "kind": "intel",
            "polarity": "protect",
            "version": "1.0.0",
            "channel": "rapid",
            "publisher": "Guardrails",
            "records": [{
                "id": "GRDRI-2026-00002",
                "title": "Vulnerable SDK advisory",
                "severity": "high",
                "withdrawn": false,
                "observables": [{
                    "kind": "ghsa",
                    "value": "GHSA-0000-0000-0002",
                    "version_range": ">=0.4.0, <0.4.5"
                }],
                "evidence": [{
                    "feed": "ghsa",
                    "organisation": "GitHub Advisory Database",
                    "method_family": "advisory_feed",
                    "nature": "vulnerable",
                    "review_state": "maintainer_verified",
                    "disposition": "active",
                    "reference_url": null,
                    "summary": "SSRF bypass"
                }]
            }]
        })
        .to_string();
        assert!(matches!(
            validate_intel_pack_json(&rapid_vuln),
            Err(IntelError::NonRestrictivePack(_))
        ));

        let mut oversized = valid_base_pack("rapid");
        oversized["records"][0]["title"] = serde_json::json!("x".repeat(120 * 1024));
        assert!(matches!(
            validate_intel_pack_json(&oversized.to_string()),
            Err(IntelError::NonRestrictivePack(_))
        ));

        let shipped = include_str!("../../../packs/intel/sample-intel-pack.json");
        let parsed = validate_intel_pack_json(shipped).expect("shipped sample intel pack valid");
        assert_eq!(parsed.active_malicious_count, 1);
        assert_eq!(parsed.active_vulnerable_count, 1);
    }

    #[test]
    fn round2_pack_rejects_untrimmed_id_bad_version_range_and_oversized_evidence() {
        // Untrimmed record ID rejected at serde boundary (cannot bypass duplicate check).
        let mut untrimmed = valid_base_pack("standard");
        untrimmed["records"][0]["id"] = serde_json::json!(" GRDRI-2026-00001");
        assert!(validate_intel_pack_json(&untrimmed.to_string()).is_err());

        // Malformed observable version_range rejected (valid pack JSON structure, bad version_range syntax).
        for bad_range in ["not-a-semver", ">=", "==1.0.0, bad_clause", ""] {
            let mut bad_ver = valid_base_pack("standard");
            bad_ver["records"][0]["observables"][0]["kind"] = serde_json::json!("package-purl");
            bad_ver["records"][0]["observables"][0]["value"] = serde_json::json!("pkg:npm/evil");
            bad_ver["records"][0]["observables"][0]["version_range"] = serde_json::json!(bad_range);
            let err = validate_intel_pack_json(&bad_ver.to_string())
                .expect_err("expected invalid version_range to fail");
            assert!(
                err.to_string().contains("version_range"),
                "expected version_range error for `{bad_range}`, got `{err}`"
            );
        }

        // Oversized publisher (>4096B) and evidence summary rejected.
        let mut big_pub = valid_base_pack("standard");
        big_pub["publisher"] = serde_json::json!("n".repeat(MAX_FIELD_STRING_BYTES + 1));
        let pub_err = validate_intel_pack_json(&big_pub.to_string()).unwrap_err();
        assert!(pub_err.to_string().contains("intel manifest identifiers"));

        let mut big_summary = valid_base_pack("standard");
        big_summary["records"][0]["evidence"][0]["summary"] = serde_json::json!("s".repeat(16_384));
        let sum_err = validate_intel_pack_json(&big_summary.to_string()).unwrap_err();
        assert!(sum_err.to_string().contains("evidence string invalid"));
    }

    #[test]
    fn round4_pack_deserialize_gate_url_scheme_and_observable_syntax() {
        // 1. Direct ValidatedIntelPack deserialization enforces full validation + summary count integrity.
        let mut tampered_wire = serde_json::json!({
            "manifest": {
                "pack_id": "grdr.intel.rapid",
                "kind": "intel",
                "polarity": "protect",
                "version": "1.0.0",
                "channel": "rapid",
                "publisher": "Guardrails",
                "guard_domains": []
            },
            "records": [{
                "id": "GRDRI-2026-00009",
                "title": "Rapid vuln bypass",
                "severity": "high",
                "withdrawn": false,
                "observables": [{
                    "kind": "cve",
                    "value": "CVE-2026-9999",
                    "version_range": null
                }],
                "evidence": [{
                    "feed": "ghsa",
                    "organisation": "GHSA",
                    "method_family": "advisory_feed",
                    "nature": "vulnerable",
                    "review_state": "maintainer_verified",
                    "disposition": "active",
                    "reference_url": null,
                    "summary": "Bypass"
                }]
            }],
            "active_malicious_count": 0,
            "active_suspicious_count": 0,
            "active_vulnerable_count": 1,
            "withdrawn_count": 0
        });
        assert!(serde_json::from_str::<ValidatedIntelPack>(&tampered_wire.to_string()).is_err());

        tampered_wire["manifest"]["channel"] = serde_json::json!("standard");
        tampered_wire["active_vulnerable_count"] = serde_json::json!(99);
        assert!(serde_json::from_str::<ValidatedIntelPack>(&tampered_wire.to_string()).is_err());

        let valid = validate_intel_pack_json(&valid_base_pack("standard").to_string()).unwrap();
        let rt_json = serde_json::to_string(&valid).unwrap();
        assert_eq!(
            serde_json::from_str::<ValidatedIntelPack>(&rt_json).unwrap(),
            valid
        );

        // 2. Non-HTTP(S) / credentialed URLs and invalid Sha256/IpAddress/Domain observables rejected.
        for bad_url in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,hi",
            "https://user:pass@evil.example/p",
        ] {
            let mut p_obs = valid_base_pack("standard");
            p_obs["records"][0]["observables"][0] = serde_json::json!({
                "kind": "url",
                "value": bad_url,
                "version_range": null
            });
            assert!(validate_intel_pack_json(&p_obs.to_string()).is_err());

            let mut p_ref = valid_base_pack("standard");
            p_ref["records"][0]["evidence"][0]["reference_url"] = serde_json::json!(bad_url);
            assert!(validate_intel_pack_json(&p_ref.to_string()).is_err());
        }

        for (kind, bad_val) in [
            ("sha256", "not-sha256"),
            ("ip-address", "not-an-ip"),
            ("domain", "user:secret@internal.corp/api?tok=1"),
            ("domain", "evil.example.."),
            ("url", "https://-bad.example/p"),
            ("url", "https://evil.example../p"),
            ("package-purl", "pkg:npm/evil@1.0.0||>=0.0.0-0"),
            ("package-purl", "pkg:npm/evil@1.0.0, <2.0.0"),
            ("package-purl", "pkg:npm/evil@1.0.0/sub"),
            ("package-purl", "pkg:npm/evil@1.0.0@2.0.0"),
            ("package-purl", "pkg:npm/evil@"),
        ] {
            let mut p = valid_base_pack("standard");
            p["records"][0]["observables"][0] = serde_json::json!({
                "kind": kind,
                "value": bad_val,
                "version_range": null
            });
            assert!(
                validate_intel_pack_json(&p.to_string()).is_err(),
                "expected {kind}={bad_val} to fail pack validation"
            );
        }

        let mut bad_chan = valid_base_pack("UNTRUSTED_CHANNEL_SECRET");
        bad_chan["channel"] = serde_json::json!("UNTRUSTED_CHANNEL_SECRET");
        let chan_err = validate_intel_pack_json(&bad_chan.to_string()).unwrap_err();
        assert!(!chan_err.to_string().contains("UNTRUSTED_CHANNEL_SECRET"));
        assert!(
            chan_err
                .to_string()
                .contains("unsupported intel channel; expected 'standard' or 'rapid'")
        );
    }

    #[test]
    fn round6_schema_parse_errors_do_not_echo_untrusted_fields_or_values() {
        let mut flat_unknown = valid_base_pack("standard");
        flat_unknown
            .as_object_mut()
            .expect("obj")
            .insert("UNTRUSTED_FIELD_SECRET".into(), serde_json::json!("x"));
        let flat_err = validate_intel_pack_json(&flat_unknown.to_string()).unwrap_err();
        assert!(!flat_err.to_string().contains("UNTRUSTED_FIELD_SECRET"));

        let mut flat_bad_type = valid_base_pack("standard");
        flat_bad_type["records"] = serde_json::json!("UNTRUSTED_VALUE_SECRET");
        let type_err = validate_intel_pack_json(&flat_bad_type.to_string()).unwrap_err();
        assert!(!type_err.to_string().contains("UNTRUSTED_VALUE_SECRET"));

        let nested_bad = serde_json::json!({
            "manifest": {
                "pack_id": "grdr.intel.core",
                "kind": "intel",
                "polarity": "UNTRUSTED_POLARITY_SECRET",
                "version": "1.0.0",
                "channel": "standard",
                "publisher": "Guardrails"
            },
            "records": [],
            "UNTRUSTED_NESTED_FIELD": true
        });
        let nested_err = validate_intel_pack_json(&nested_bad.to_string()).unwrap_err();
        let nested_msg = nested_err.to_string();
        assert!(!nested_msg.contains("UNTRUSTED_POLARITY_SECRET"));
        assert!(!nested_msg.contains("UNTRUSTED_NESTED_FIELD"));
    }
}
