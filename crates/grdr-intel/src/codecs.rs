// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Interoperability codecs for STIX 2.1, TAXII 2.1, MISP Event JSON, and OSV (`docs/design/14`).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::record::{
    ClaimDisposition, ClaimNature, EvidenceFeed, GrdrIntelId, IntelEvidence, IntelObservable,
    IntelRecord, IntelSeverity, MethodFamily, ObservableKind, ReviewState,
};
use crate::stix_pattern::{
    deterministic_stix_uuid, fallback_stix_id, parse_stix_pattern, stix_pattern_for_observable,
    validate_observable_value,
};
use crate::{IntelError, embedded_limits};

const DEFAULT_STIX_TIMESTAMP: &str = "1970-01-01T00:00:00Z";
const MAX_STIX_OBJECTS: usize = 10_000;
const MAX_MISP_ATTRIBUTES: usize = 4_096;
const MAX_MISP_OBSERVABLES: usize = 512;
const MAX_CODEC_STRING_BYTES: usize = 4_096;
const STIX_TLP_RED_V1_ID: &str = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed";
const STIX_TLP_RED_V2_ID: &str = "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxiiEnvelope {
    #[serde(default)]
    pub more: bool,
    pub next: Option<String>,
    #[serde(default)]
    pub objects: Vec<Value>,
}

/// Encodes `IntelRecord` slices into a STIX 2.1 `bundle` JSON value.
#[must_use]
pub fn encode_stix_bundle(records: &[IntelRecord], bundle_id: &str) -> Value {
    let mut objects = Vec::new();
    for rec in records {
        for (idx, obs) in rec.observables.iter().enumerate() {
            if let Some(pattern) = stix_pattern_for_observable(obs) {
                let stix_uuid = deterministic_stix_uuid(rec.id.as_str(), idx);
                objects.push(json!({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": format!("indicator--{stix_uuid}"),
                    "name": rec.title,
                    "created": DEFAULT_STIX_TIMESTAMP,
                    "modified": DEFAULT_STIX_TIMESTAMP,
                    "valid_from": DEFAULT_STIX_TIMESTAMP,
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "revoked": rec.withdrawn,
                    "external_references": [{
                        "source_name": "guardrails-intel",
                        "external_id": rec.id.as_str()
                    }]
                }));
            }
        }
    }
    json!({
        "type": "bundle",
        "id": bundle_id,
        "objects": objects
    })
}

/// Decodes a STIX 2.1 bundle JSON payload into `IntelRecord` entries.
pub fn decode_stix_bundle(raw_json: &str, org_id: &str) -> Result<Vec<IntelRecord>, IntelError> {
    enforce_codec_json_cap(raw_json, true)?;
    let val: Value = serde_json::from_str(raw_json)
        .map_err(|e| IntelError::CodecParse(format!("invalid STIX bundle JSON: {e}")))?;
    if val.get("type").and_then(Value::as_str) != Some("bundle") {
        return Err(IntelError::CodecParse(
            "STIX root must have `type = bundle`".into(),
        ));
    }
    let objects = val
        .get("objects")
        .and_then(Value::as_array)
        .ok_or_else(|| IntelError::CodecParse("STIX bundle missing `objects` array".into()))?;
    decode_stix_objects(objects, org_id)
}

/// Decodes a TAXII 2.1 collection envelope into `IntelRecord` entries.
pub fn decode_taxii_envelope(
    raw_json: &str,
    org_id: &str,
) -> Result<(TaxiiEnvelope, Vec<IntelRecord>), IntelError> {
    enforce_codec_json_cap(raw_json, true)?;
    let env: TaxiiEnvelope = serde_json::from_str(raw_json)
        .map_err(|_| IntelError::CodecParse("invalid TAXII envelope schema".into()))?;
    let records = decode_stix_objects(&env.objects, org_id)?;
    Ok((env, records))
}

/// Encodes `IntelRecord` into MISP Event JSON format.
#[must_use]
pub fn encode_misp_event(rec: &IntelRecord) -> Value {
    let attrs: Vec<Value> = rec
        .observables
        .iter()
        .map(|obs| {
            let attr_type = match obs.kind {
                ObservableKind::Sha256 => "sha256",
                ObservableKind::Domain => "domain",
                ObservableKind::Url => "url",
                ObservableKind::IpAddress => "ip-dst",
                ObservableKind::Cve => "vulnerability",
                _ => "text",
            };
            json!({
                "type": attr_type,
                "category": "Network activity",
                "value": obs.value,
                "to_ids": !rec.withdrawn
            })
        })
        .collect();
    json!({
        "Event": {
            "info": rec.title,
            "threat_level_id": "1",
            "Attribute": attrs
        }
    })
}

/// Decodes a MISP Event JSON payload into an `IntelRecord`, enforcing `to_ids == true`,
/// warninglist drops, and TLP restrictions (`docs/design/14`).
pub fn decode_misp_event(raw_json: &str, assigned_id: &str) -> Result<IntelRecord, IntelError> {
    enforce_codec_json_cap(raw_json, false)?;
    let id = GrdrIntelId::parse(assigned_id)?;
    let val: Value = serde_json::from_str(raw_json)
        .map_err(|e| IntelError::CodecParse(format!("invalid MISP JSON: {e}")))?;
    let event = val
        .get("Event")
        .ok_or_else(|| IntelError::CodecParse("missing MISP `Event` object".into()))?;
    if has_tlp_red(event) {
        return Err(IntelError::CodecParse(
            "MISP Event marked `tlp:red` cannot be imported into shared feeds".into(),
        ));
    }
    let info = event
        .get("info")
        .and_then(Value::as_str)
        .unwrap_or("MISP Event");
    if info.len() > MAX_CODEC_STRING_BYTES || info.chars().any(char::is_control) {
        return Err(IntelError::CodecParse(
            "MISP Event `info` contains control characters or exceeds bound".into(),
        ));
    }
    let attrs = event
        .get("Attribute")
        .and_then(Value::as_array)
        .ok_or_else(|| IntelError::CodecParse("MISP Event missing `Attribute` array".into()))?;
    if attrs.len() > MAX_MISP_ATTRIBUTES {
        return Err(IntelError::CodecParse(
            "MISP Event `Attribute` array exceeds bound".into(),
        ));
    }

    let mut observables = Vec::new();
    for attr in attrs {
        if attr.get("to_ids").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        if has_warninglist_tag(attr) || has_tlp_red(attr) {
            continue;
        }
        let Some(val_str) = attr.get("value").and_then(Value::as_str) else {
            continue;
        };
        if val_str.len() > MAX_CODEC_STRING_BYTES {
            continue;
        }
        let kind = match attr.get("type").and_then(Value::as_str).unwrap_or("") {
            "sha256" => ObservableKind::Sha256,
            "domain" | "hostname" => ObservableKind::Domain,
            "url" => ObservableKind::Url,
            "ip-dst" | "ip-src" => ObservableKind::IpAddress,
            "vulnerability" => ObservableKind::Cve,
            _ => continue,
        };
        if validate_observable_value(kind, val_str).is_err() {
            continue;
        }
        if observables.len() >= MAX_MISP_OBSERVABLES {
            return Err(IntelError::CodecParse(
                "MISP Event observables exceed record bound".into(),
            ));
        }
        observables.push(IntelObservable {
            kind,
            value: val_str.to_owned(),
            version_range: None,
        });
    }
    if observables.is_empty() {
        return Err(IntelError::CodecParse(
            "MISP event contained zero supported `to_ids: true` observables".into(),
        ));
    }
    Ok(IntelRecord {
        id,
        title: info.to_owned(),
        severity: IntelSeverity::High,
        withdrawn: false,
        observables,
        evidence: vec![IntelEvidence {
            feed: EvidenceFeed::VendorAdvisory,
            organisation: "MISP Feed".into(),
            method_family: MethodFamily::AdvisoryFeed,
            nature: ClaimNature::Suspicious,
            review_state: ReviewState::Unreviewed,
            disposition: ClaimDisposition::Active,
            reference_url: None,
            based_on_organisation: None,
            summary: info.to_owned(),
        }],
    })
}

/// Encodes an `IntelRecord` into Open Source Vulnerabilities (OSV 1.6) JSON.
#[must_use]
pub fn encode_osv_record(rec: &IntelRecord) -> Value {
    let affected: Vec<Value> = rec
        .observables
        .iter()
        .filter(|o| o.kind == ObservableKind::PackagePurl)
        .map(|o| {
            json!({
                "package": { "purl": o.value },
                "database_specific": { "version_range": o.version_range }
            })
        })
        .collect();
    if rec.withdrawn {
        json!({
            "schema_version": "1.6.0",
            "id": rec.id.as_str(),
            "summary": rec.title,
            "withdrawn": DEFAULT_STIX_TIMESTAMP,
            "affected": affected
        })
    } else {
        json!({
            "schema_version": "1.6.0",
            "id": rec.id.as_str(),
            "summary": rec.title,
            "affected": affected
        })
    }
}

fn decode_stix_objects(objects: &[Value], org_id: &str) -> Result<Vec<IntelRecord>, IntelError> {
    if org_id.trim().is_empty() || org_id.len() > 128 || org_id.chars().any(char::is_control) {
        return Err(IntelError::CodecParse("invalid STIX/TAXII org_id".into()));
    }
    if objects.len() > MAX_STIX_OBJECTS {
        return Err(IntelError::CodecParse(
            "STIX objects array exceeds bundle bound".into(),
        ));
    }
    let tlp_red_ids = collect_tlp_red_marking_ids(objects);
    let mut records = Vec::new();
    for (idx, obj) in objects.iter().enumerate() {
        if obj.get("type").and_then(Value::as_str) != Some("indicator") {
            continue;
        }
        if stix_obj_has_tlp_red(obj, &tlp_red_ids) {
            continue;
        }
        if let Some(pt) = obj.get("pattern_type")
            && pt.as_str() != Some("stix")
        {
            return Err(IntelError::CodecParse(
                "unsupported STIX indicator pattern_type".into(),
            ));
        }
        let pattern = obj
            .get("pattern")
            .and_then(Value::as_str)
            .ok_or_else(|| IntelError::CodecParse("STIX indicator missing `pattern`".into()))?;
        if pattern.len() > MAX_CODEC_STRING_BYTES {
            return Err(IntelError::CodecParse(
                "STIX pattern exceeds byte bound".into(),
            ));
        }
        let obs = parse_stix_pattern(pattern)?;
        let parsed_ext = obj
            .get("external_references")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|r| r.get("external_id"))
            .and_then(Value::as_str)
            .and_then(|raw| GrdrIntelId::parse(raw).ok());
        let ext_id = match parsed_ext {
            Some(id) => id,
            None => fallback_stix_id(org_id, idx, pattern)?,
        };
        let title = obj
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("STIX indicator");
        if title.len() > MAX_CODEC_STRING_BYTES || title.chars().any(char::is_control) {
            return Err(IntelError::CodecParse(
                "STIX indicator name contains controls or exceeds bound".into(),
            ));
        }
        let revoked = obj.get("revoked").and_then(Value::as_bool).unwrap_or(false);
        records.push(IntelRecord {
            id: ext_id,
            title: title.to_owned(),
            severity: IntelSeverity::High,
            withdrawn: revoked,
            observables: vec![obs],
            evidence: vec![IntelEvidence {
                feed: EvidenceFeed::VendorAdvisory,
                organisation: org_id.to_owned(),
                method_family: MethodFamily::AdvisoryFeed,
                nature: ClaimNature::Suspicious,
                review_state: ReviewState::Unreviewed,
                disposition: ClaimDisposition::Active,
                reference_url: None,
                based_on_organisation: None,
                summary: title.to_owned(),
            }],
        });
    }
    Ok(records)
}

fn enforce_codec_json_cap(raw_json: &str, multi_record: bool) -> Result<(), IntelError> {
    let limits = embedded_limits().map_err(|msg| IntelError::CodecParse(msg.into()))?;
    let max_bytes = if multi_record {
        limits.server.ingest.max_body_bytes
    } else {
        limits.endpoint.ipc.max_frame_bytes
    };
    if raw_json.len() > max_bytes {
        return Err(IntelError::CodecParse(format!(
            "codec payload {} bytes exceeds limit ({max_bytes})",
            raw_json.len()
        )));
    }
    Ok(())
}

fn collect_tlp_red_marking_ids(objects: &[Value]) -> BTreeSet<String> {
    let mut ids = BTreeSet::from([STIX_TLP_RED_V1_ID.to_owned(), STIX_TLP_RED_V2_ID.to_owned()]);
    for obj in objects {
        if obj.get("type").and_then(Value::as_str).map(str::trim) != Some("marking-definition") {
            continue;
        }
        let Some(id) = obj.get("id").and_then(Value::as_str).map(str::trim) else {
            continue;
        };
        if id.is_empty() {
            continue;
        }
        let is_tlp_red_def = obj
            .get("definition_type")
            .and_then(Value::as_str)
            .is_some_and(|dt| dt.trim().eq_ignore_ascii_case("tlp"))
            && obj
                .get("definition")
                .and_then(|d| d.get("tlp"))
                .and_then(Value::as_str)
                .is_some_and(|t| {
                    let trimmed = t.trim();
                    trimmed.eq_ignore_ascii_case("red") || trimmed.eq_ignore_ascii_case("tlp:red")
                });
        let is_named_red = obj
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|n| n.trim().eq_ignore_ascii_case("tlp:red"));
        if is_tlp_red_def || is_named_red {
            ids.insert(id.to_ascii_lowercase());
        }
    }
    ids
}

fn is_tlp_red_ref(raw: &str, tlp_red_ids: &BTreeSet<String>) -> bool {
    let low = raw.trim().to_ascii_lowercase();
    low == "tlp:red" || tlp_red_ids.contains(&low)
}

fn stix_obj_has_tlp_red(obj: &Value, tlp_red_ids: &BTreeSet<String>) -> bool {
    let ref_hit = obj
        .get("object_marking_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter()
                .any(|r| r.as_str().is_some_and(|s| is_tlp_red_ref(s, tlp_red_ids)))
        });
    let granular_hit = obj
        .get("granular_markings")
        .and_then(Value::as_array)
        .is_some_and(|marks| {
            marks.iter().any(|m| {
                m.get("marking_ref")
                    .and_then(Value::as_str)
                    .is_some_and(|s| is_tlp_red_ref(s, tlp_red_ids))
            })
        });
    let label_hit = obj
        .get("labels")
        .and_then(Value::as_array)
        .is_some_and(|labels| {
            labels.iter().any(|l| {
                l.as_str()
                    .is_some_and(|s| s.trim().eq_ignore_ascii_case("tlp:red"))
            })
        });
    ref_hit || granular_hit || label_hit || has_tlp_red(obj)
}

fn has_warninglist_tag(node: &Value) -> bool {
    node.get("Tag")
        .and_then(Value::as_array)
        .is_some_and(|tags| {
            tags.iter().any(|t| {
                t.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.to_ascii_lowercase().contains("warninglist"))
            })
        })
}

fn has_tlp_red(node: &Value) -> bool {
    node.get("Tag")
        .and_then(Value::as_array)
        .is_some_and(|tags| {
            tags.iter().any(|t| {
                t.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.trim().eq_ignore_ascii_case("tlp:red"))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stix_taxii_misp_and_osv_codecs_roundtrip() {
        let rec = IntelRecord {
            id: GrdrIntelId::parse("GRDRI-2026-00100").expect("id"),
            title: "Malicious payload domain".into(),
            severity: IntelSeverity::High,
            withdrawn: false,
            observables: vec![
                IntelObservable {
                    kind: ObservableKind::Domain,
                    value: "bad.example".into(),
                    version_range: None,
                },
                IntelObservable {
                    kind: ObservableKind::PackagePurl,
                    value: "pkg:pypi/evil-pkg".into(),
                    version_range: Some(">=1.0.0,<1.2.0".into()),
                },
                IntelObservable {
                    kind: ObservableKind::IpAddress,
                    value: "2001:db8::1".into(),
                    version_range: None,
                },
            ],
            evidence: Vec::new(),
        };
        let bundle = encode_stix_bundle(std::slice::from_ref(&rec), "bundle--1");
        let parsed = decode_stix_bundle(&bundle.to_string(), "STIX-Org").expect("decode stix");
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed
                .first()
                .and_then(|r| r.observables.first())
                .map(|o| o.value.as_str()),
            Some("bad.example")
        );
        assert!(
            bundle["objects"][1]["pattern"]
                .as_str()
                .expect("ipv6")
                .starts_with("[ipv6-addr:value =")
        );

        let misp = encode_misp_event(&rec);
        let parsed_misp = decode_misp_event(&misp.to_string(), "GRDRI-2026-00101").expect("misp");
        assert_eq!(
            parsed_misp.observables.first().map(|o| o.value.as_str()),
            Some("bad.example")
        );

        let osv = encode_osv_record(&rec);
        assert_eq!(
            osv.get("id").and_then(Value::as_str),
            Some("GRDRI-2026-00100")
        );
        assert!(osv.get("withdrawn").is_none());

        let withdrawn_rec = IntelRecord {
            withdrawn: true,
            ..rec
        };
        let osv_w = encode_osv_record(&withdrawn_rec);
        assert!(osv_w.get("withdrawn").and_then(Value::as_str).is_some());
    }

    #[test]
    fn negative_cases_reject_stix_injection_negation_md5_and_misp_non_ids_warninglists() {
        let injected = IntelObservable {
            kind: ObservableKind::Domain,
            value: "x'] OR [domain-name:value LIKE '%".into(),
            version_range: None,
        };
        let pat = stix_pattern_for_observable(&injected).expect("pattern");
        assert!(pat.contains("\\'"));
        assert!(parse_stix_pattern(&pat).is_err());

        for bad_pat in [
            "[domain-name:value != 'good.example']",
            "[domain-name:value = 'a.example'] OR [domain-name:value = 'b.example']",
            "[domain-name:value = 'a.example' AND domain-name:value = 'b.example']",
            "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']",
            "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']",
            "[ipv4-addr:value = 'not-an-ip']",
        ] {
            assert!(
                parse_stix_pattern(bad_pat).is_err(),
                "expected rejection of `{bad_pat}`"
            );
        }

        let misp_filtered = serde_json::json!({
            "Event": {
                "info": "Mixed MISP",
                "Attribute": [
                    { "type": "domain", "value": "context-only.example", "to_ids": false },
                    { "type": "domain", "value": "warned.example", "to_ids": true, "Tag": [{ "name": "misp:warninglist" }] }
                ]
            }
        })
        .to_string();
        assert!(decode_misp_event(&misp_filtered, "GRDRI-2026-00102").is_err());

        let tlp_red = serde_json::json!({
            "Event": {
                "info": "Secret",
                "Tag": [{ "name": "tlp:red" }],
                "Attribute": [{ "type": "domain", "value": "bad.example", "to_ids": true }]
            }
        })
        .to_string();
        assert!(decode_misp_event(&tlp_red, "GRDRI-2026-00103").is_err());
    }

    #[test]
    fn round2_codecs_stix_tlp_red_url_scheme_domain_syntax_uuid_and_caps() {
        // STIX 2.1 standard TLP:RED (and TLP 2.0 RED) marking definition UUIDs must be dropped,
        // whereas TLP:WHITE passes through.
        for tlp_red_id in [
            "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
        ] {
            let stix_red = serde_json::json!({
                "type": "bundle",
                "id": "bundle--11111111-1111-4111-8111-111111111111",
                "objects": [{
                    "type": "indicator",
                    "id": "indicator--22222222-2222-4222-8222-222222222222",
                    "name": "Secret Red Threat",
                    "pattern_type": "stix",
                    "pattern": "[domain-name:value = 'red-only.example']",
                    "object_marking_refs": [tlp_red_id]
                }]
            })
            .to_string();
            assert!(
                decode_stix_bundle(&stix_red, "OrgA").unwrap().is_empty(),
                "expected {tlp_red_id} to drop indicator"
            );
        }
        let stix_white = serde_json::json!({
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
            "objects": [{
                "type": "indicator",
                "id": "indicator--22222222-2222-4222-8222-222222222222",
                "name": "Public White Threat",
                "pattern_type": "stix",
                "pattern": "[domain-name:value = 'white-ok.example']",
                "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"]
            }]
        })
        .to_string();
        assert_eq!(decode_stix_bundle(&stix_white, "OrgA").unwrap().len(), 1);

        // Disallowed STIX URL schemes and invalid domain syntax fail strict parsing.
        assert!(parse_stix_pattern("[url:value = 'javascript:alert(1)']").is_err());
        assert!(parse_stix_pattern("[url:value = 'ftp://files.example/evil']").is_err());
        assert!(parse_stix_pattern("[domain-name:value = 'a..b.example']").is_err());
        assert!(parse_stix_pattern("[domain-name:value = '-bad.example']").is_err());
        assert!(parse_stix_pattern("[url:value = 'https://evil.example/a']").is_ok());

        // Encoded STIX indicator UUIDs must satisfy RFC 4122 v5 + variant bits.
        let rec = decode_misp_event(
            &serde_json::json!({
                "Event": {
                    "info": "Valid MISP",
                    "Attribute": [{ "type": "domain", "value": "uuid-check.example", "to_ids": true }]
                }
            })
            .to_string(),
            "GRDRI-2026-00104",
        )
        .unwrap();
        let stix_val = encode_stix_bundle(&[rec], "bundle--test");
        let obj_id = stix_val["objects"][0]["id"].as_str().unwrap();
        let uuid_part = obj_id.strip_prefix("indicator--").unwrap();
        let parts: Vec<&str> = uuid_part.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(
            parts[2].starts_with('5'),
            "expected UUID v5 nibble in {obj_id}"
        );
        let var_first = parts[3].chars().next().unwrap();
        assert!(matches!(var_first, '8' | '9' | 'a' | 'b'));

        // Oversized TAXII / STIX / MISP / OSV payloads rejected before deep parsing.
        let limits = embedded_limits().expect("embedded limits");
        let huge_single = format!(
            "{{\"pad\":\"{}\"}}",
            "a".repeat(limits.endpoint.ipc.max_frame_bytes + 64)
        );
        let huge_bundle = format!(
            "{{\"objects\":[],\"pad\":\"{}\"}}",
            "a".repeat(limits.server.ingest.max_body_bytes + 64)
        );
        assert!(decode_taxii_envelope(&huge_bundle, "OrgA").is_err());
        assert!(decode_stix_bundle(&huge_bundle, "OrgA").is_err());
        assert!(decode_misp_event(&huge_single, "GRDRI-2026-00105").is_err());
    }

    #[test]
    fn round4_stix_granular_tlp_red_trimmed_tags_pattern_type_cve_and_p8_errors() {
        // 1. STIX 2.1 granular_markings[].marking_ref with TLP:RED (standard + custom + whitespace) dropped.
        let granular_red = serde_json::json!({
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
            "objects": [{
                "type": "indicator",
                "id": "indicator--22222222-2222-4222-8222-222222222222",
                "name": "Granular Red Threat",
                "pattern_type": "stix",
                "pattern": "[domain-name:value = 'granular-red.example']",
                "granular_markings": [{
                    "marking_ref": " marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed ",
                    "selectors": ["pattern"]
                }]
            }]
        })
        .to_string();
        assert!(
            decode_stix_bundle(&granular_red, "OrgA")
                .unwrap()
                .is_empty()
        );

        let custom_red_def = serde_json::json!({
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
            "objects": [
                {
                    "type": "marking-definition",
                    "id": " marking-definition--custom-red ",
                    "definition_type": " tlp ",
                    "definition": { "tlp": " red " }
                },
                {
                    "type": "indicator",
                    "id": "indicator--22222222-2222-4222-8222-222222222222",
                    "name": "Custom Red",
                    "pattern_type": "stix",
                    "pattern": "[domain-name:value = 'custom-red.example']",
                    "granular_markings": [{
                        "marking_ref": "marking-definition--custom-red",
                        "selectors": ["pattern"]
                    }]
                }
            ]
        })
        .to_string();
        assert!(
            decode_stix_bundle(&custom_red_def, "OrgA")
                .unwrap()
                .is_empty()
        );

        // 2. MISP untrimmed " tlp:red " tag rejected, and invalid CVE rejected.
        let misp_padded_red = serde_json::json!({
            "Event": {
                "info": "Secret",
                "Tag": [{ "name": " tlp:red " }],
                "Attribute": [{ "type": "domain", "value": "bad.example", "to_ids": true }]
            }
        })
        .to_string();
        assert!(decode_misp_event(&misp_padded_red, "GRDRI-2026-00106").is_err());

        let misp_bad_cve = serde_json::json!({
            "Event": {
                "info": "Bad CVE",
                "Attribute": [{ "type": "vulnerability", "value": "NOT-A-CVE-123", "to_ids": true }]
            }
        })
        .to_string();
        assert!(decode_misp_event(&misp_bad_cve, "GRDRI-2026-00107").is_err());

        // 3. Non-stix pattern_type rejected, trailing `..` domain rejected, and no raw pattern echo in error.
        let non_stix = serde_json::json!({
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
            "objects": [{
                "type": "indicator",
                "id": "indicator--22222222-2222-4222-8222-222222222222",
                "name": "YARA rule",
                "pattern_type": "yara",
                "pattern": "[domain-name:value = 'bad.example']"
            }]
        })
        .to_string();
        assert!(decode_stix_bundle(&non_stix, "OrgA").is_err());

        assert!(parse_stix_pattern("[domain-name:value = 'evil.example..']").is_err());
        assert!(parse_stix_pattern("[url:value = 'https://-bad.example/p']").is_err());
        assert!(parse_stix_pattern("[url:value = 'https://evil.example../p']").is_err());
        let misp_bad_url = serde_json::json!({
            "Event": {
                "info": "Bad URL host",
                "Attribute": [{ "type": "url", "value": "https://-bad.example/p", "to_ids": true }]
            }
        })
        .to_string();
        assert!(decode_misp_event(&misp_bad_url, "GRDRI-2026-00108").is_err());

        let mut years = BTreeSet::new();
        for idx in 0..256 {
            let id = fallback_stix_id("OrgWide", idx, "[domain-name:value = 'x.example']").unwrap();
            let year = id.as_str().split('-').nth(1).unwrap().to_owned();
            years.insert(year);
        }
        assert!(years.iter().any(|y| y.as_str() > "2093"));

        let err = parse_stix_pattern("SECRET_UNTRUSTED_PATTERN_ECHO").unwrap_err();
        assert!(!err.to_string().contains("SECRET_UNTRUSTED_PATTERN_ECHO"));
    }

    #[test]
    fn round6_taxii_envelope_schema_error_does_not_echo_untrusted_values() {
        let bad_taxii = serde_json::json!({
            "more": "UNTRUSTED_TAXII_SECRET_VALUE",
            "objects": []
        })
        .to_string();
        let err = decode_taxii_envelope(&bad_taxii, "OrgA").unwrap_err();
        assert!(!err.to_string().contains("UNTRUSTED_TAXII_SECRET_VALUE"));
    }
}
