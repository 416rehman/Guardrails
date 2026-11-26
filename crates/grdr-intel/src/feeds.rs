// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Feed normalisers for OSSF Malicious Packages, GHSA, and CISA KEV (`docs/design/14`).

use serde_json::Value;

use crate::record::{
    ClaimDisposition, ClaimNature, EvidenceFeed, GrdrIntelId, IntelEvidence, IntelObservable,
    IntelRecord, IntelSeverity, MethodFamily, ObservableKind, ReviewState,
};
pub use crate::semver::{
    BoundOp, PreIdent, SemVerTuple, VersionClause, version_in_vulnerable_range,
};
use crate::semver::{extract_osv_versions_range, validate_version_range_syntax};
use crate::validators::{
    validate_cve_syntax, validate_ghsa_syntax, validate_http_https_url, validate_purl_syntax,
};
use crate::{IntelError, embedded_limits};

const MAX_FEED_ARRAY_ITEMS: usize = 512;
const MAX_KEV_CATALOG_ITEMS: usize = 100_000;
const MAX_FEED_STR_BYTES: usize = 4_096;
const MAX_PACKAGE_NAME_BYTES: usize = 512;

/// Normalises an OSSF Malicious Packages OSV JSON object into a deterministic `IntelRecord`.
pub fn normalize_ossf_malicious(
    raw_json: &str,
    assigned_id: &str,
) -> Result<IntelRecord, IntelError> {
    enforce_feed_json_cap(raw_json, false)?;
    let id = GrdrIntelId::parse(assigned_id)?;
    let val: Value = serde_json::from_str(raw_json)
        .map_err(|e| IntelError::CodecParse(format!("invalid OSSF JSON: {e}")))?;
    let osv_id = val
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| IntelError::CodecParse("missing OSSF `id`".into()))?;
    validate_osv_id(osv_id)?;
    let summary = val
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("OSSF malicious package report");
    validate_bounded_text(summary, "OSSF summary")?;
    let ref_url = val
        .get("references")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|r| r.get("url"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(ref u) = ref_url {
        validate_http_https_url(u, MAX_FEED_STR_BYTES)
            .map_err(|msg| IntelError::CodecParse(msg.into()))?;
    }

    let mut observables = Vec::new();
    if let Some(affected) = val.get("affected").and_then(Value::as_array) {
        if affected.len() > MAX_FEED_ARRAY_ITEMS {
            return Err(IntelError::CodecParse(
                "OSSF `affected` array exceeds bound".into(),
            ));
        }
        for aff in affected {
            let pkg = aff.get("package");
            if let Some(ranges) = aff.get("ranges").and_then(Value::as_array)
                && ranges.len() > 64
            {
                return Err(IntelError::CodecParse(
                    "OSSF ranges count exceeds bound".into(),
                ));
            }
            if let Some(versions) = aff.get("versions").and_then(Value::as_array)
                && versions.len() > MAX_FEED_ARRAY_ITEMS
            {
                return Err(IntelError::CodecParse(
                    "OSSF versions count exceeds bound".into(),
                ));
            }
            let version_range = extract_osv_versions_range(aff)?;
            if let Some(ref vr) = version_range {
                validate_bounded_text(vr, "OSSF version_range")?;
            }
            if observables.len() >= MAX_FEED_ARRAY_ITEMS {
                return Err(IntelError::CodecParse(
                    "OSSF observables count exceeds bound".into(),
                ));
            }
            if let Some(purl) = pkg.and_then(|p| p.get("purl")).and_then(Value::as_str) {
                validate_purl_syntax(purl).map_err(|msg| IntelError::CodecParse(msg.into()))?;
                observables.push(IntelObservable {
                    kind: ObservableKind::PackagePurl,
                    value: purl.to_owned(),
                    version_range,
                });
            } else if let (Some(eco), Some(name)) = (
                pkg.and_then(|p| p.get("ecosystem")).and_then(Value::as_str),
                pkg.and_then(|p| p.get("name")).and_then(Value::as_str),
            ) {
                let purl = build_validated_purl(eco, name)?;
                observables.push(IntelObservable {
                    kind: ObservableKind::PackagePurl,
                    value: purl,
                    version_range,
                });
            }
        }
    }

    if observables.is_empty() {
        return Err(IntelError::CodecParse(
            "OSSF entry yielded no package observables".into(),
        ));
    }

    let is_withdrawn = val
        .get("withdrawn")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty());
    Ok(IntelRecord {
        id,
        title: truncate_title(&format!("{osv_id}: {summary}")),
        severity: IntelSeverity::Critical,
        withdrawn: is_withdrawn,
        observables,
        evidence: vec![IntelEvidence {
            feed: EvidenceFeed::Ossf,
            organisation: "OpenSSF Malicious Packages".into(),
            method_family: MethodFamily::HumanReview,
            nature: ClaimNature::Malicious,
            review_state: ReviewState::PublishedExternalHumanReview,
            disposition: ClaimDisposition::Active,
            reference_url: ref_url,
            based_on_organisation: None,
            summary: summary.to_owned(),
        }],
    })
}

/// Normalises a GitHub Security Advisory (GHSA) JSON record into an `IntelRecord`,
/// classifying `type == "malware"` entries as `ClaimNature::Malicious`.
pub fn normalize_ghsa(raw_json: &str, assigned_id: &str) -> Result<IntelRecord, IntelError> {
    enforce_feed_json_cap(raw_json, false)?;
    let id = GrdrIntelId::parse(assigned_id)?;
    let val: Value = serde_json::from_str(raw_json)
        .map_err(|e| IntelError::CodecParse(format!("invalid GHSA JSON: {e}")))?;
    let ghsa_id = val
        .get("ghsa_id")
        .and_then(Value::as_str)
        .ok_or_else(|| IntelError::CodecParse("missing `ghsa_id`".into()))?;
    validate_ghsa_syntax(ghsa_id).map_err(|msg| IntelError::CodecParse(msg.into()))?;
    let summary = val
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("GHSA security advisory");
    validate_bounded_text(summary, "GHSA summary")?;
    let html_url = val
        .get("html_url")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(ref u) = html_url {
        validate_http_https_url(u, MAX_FEED_STR_BYTES)
            .map_err(|msg| IntelError::CodecParse(msg.into()))?;
    }
    let severity = match val
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("medium")
        .to_ascii_lowercase()
        .as_str()
    {
        "critical" => IntelSeverity::Critical,
        "high" => IntelSeverity::High,
        "low" => IntelSeverity::Low,
        _ => IntelSeverity::Medium,
    };

    let is_malware = val
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| t.eq_ignore_ascii_case("malware"));

    let mut observables = vec![IntelObservable {
        kind: ObservableKind::Ghsa,
        value: ghsa_id.to_owned(),
        version_range: None,
    }];
    if let Some(cve) = val.get("cve_id").and_then(Value::as_str) {
        validate_cve_syntax(cve).map_err(|msg| IntelError::CodecParse(msg.into()))?;
        observables.push(IntelObservable {
            kind: ObservableKind::Cve,
            value: cve.to_owned(),
            version_range: None,
        });
    }

    if let Some(vulns) = val.get("vulnerabilities").and_then(Value::as_array) {
        if vulns.len() > MAX_FEED_ARRAY_ITEMS {
            return Err(IntelError::CodecParse(
                "GHSA `vulnerabilities` array exceeds bound".into(),
            ));
        }
        for v in vulns {
            if let (Some(eco), Some(name)) = (
                v.get("package")
                    .and_then(|p| p.get("ecosystem"))
                    .and_then(Value::as_str),
                v.get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str),
            ) {
                let purl = build_validated_purl(eco, name)?;
                let range = match v.get("vulnerable_version_range") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(vr)) => {
                        validate_bounded_text(vr, "GHSA vulnerable_version_range")?;
                        validate_version_range_syntax(vr)?;
                        Some(vr.clone())
                    }
                    Some(_) => {
                        return Err(IntelError::InvalidRecord(
                            "GHSA vulnerable_version_range must be a string".into(),
                        ));
                    }
                };
                if observables.len() >= MAX_FEED_ARRAY_ITEMS {
                    return Err(IntelError::CodecParse(
                        "GHSA observables exceed per-record bound".into(),
                    ));
                }
                observables.push(IntelObservable {
                    kind: ObservableKind::PackagePurl,
                    value: purl,
                    version_range: range,
                });
            }
        }
    }

    let (nature, review_state, method_family) = if is_malware {
        (
            ClaimNature::Malicious,
            ReviewState::PublishedExternalHumanReview,
            MethodFamily::HumanReview,
        )
    } else {
        (
            ClaimNature::Vulnerable,
            ReviewState::MaintainerVerified,
            MethodFamily::AdvisoryFeed,
        )
    };

    Ok(IntelRecord {
        id,
        title: truncate_title(&format!("{ghsa_id}: {summary}")),
        severity,
        withdrawn: val
            .get("withdrawn_at")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty()),
        observables,
        evidence: vec![IntelEvidence {
            feed: EvidenceFeed::Ghsa,
            organisation: "GitHub Advisory Database".into(),
            method_family,
            nature,
            review_state,
            disposition: ClaimDisposition::Active,
            reference_url: html_url,
            based_on_organisation: None,
            summary: summary.to_owned(),
        }],
    })
}

/// Normalises a CISA Known Exploited Vulnerabilities (KEV) catalog JSON document.
pub fn normalize_cisa_kev_catalog(
    raw_json: &str,
    year: u16,
    start_seq: u32,
) -> Result<Vec<IntelRecord>, IntelError> {
    enforce_feed_json_cap(raw_json, true)?;
    let val: Value = serde_json::from_str(raw_json)
        .map_err(|e| IntelError::CodecParse(format!("invalid KEV JSON: {e}")))?;
    let vulns = val
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| IntelError::CodecParse("missing `vulnerabilities` array in KEV".into()))?;
    if vulns.len() > MAX_KEV_CATALOG_ITEMS {
        return Err(IntelError::CodecParse(
            "KEV `vulnerabilities` array exceeds catalog bound".into(),
        ));
    }

    let mut out = Vec::with_capacity(vulns.len());
    for (idx, item) in vulns.iter().enumerate() {
        let cve = item
            .get("cveID")
            .and_then(Value::as_str)
            .ok_or_else(|| IntelError::CodecParse("missing `cveID` in KEV entry".into()))?;
        validate_cve_syntax(cve).map_err(|msg| IntelError::CodecParse(msg.into()))?;
        let name = item
            .get("vulnerabilityName")
            .and_then(Value::as_str)
            .unwrap_or("CISA KEV vulnerability");
        validate_bounded_text(name, "KEV vulnerabilityName")?;
        let idx_u32 = u32::try_from(idx)
            .map_err(|_| IntelError::CodecParse("KEV catalog index overflows u32".into()))?;
        let seq = start_seq
            .checked_add(idx_u32)
            .ok_or_else(|| IntelError::CodecParse("KEV record sequence overflow".into()))?;
        let id = GrdrIntelId::parse(&format!("GRDRI-{year:04}-{seq:05}"))?;
        let ransomware = item
            .get("knownRansomwareCampaignUse")
            .and_then(Value::as_str)
            .is_some_and(|s| s.eq_ignore_ascii_case("Known"));
        out.push(IntelRecord {
            id,
            title: truncate_title(&format!("{cve}: {name}")),
            severity: if ransomware {
                IntelSeverity::Critical
            } else {
                IntelSeverity::High
            },
            withdrawn: false,
            observables: vec![IntelObservable {
                kind: ObservableKind::Cve,
                value: cve.to_owned(),
                version_range: None,
            }],
            evidence: vec![IntelEvidence {
                feed: EvidenceFeed::Kev,
                organisation: "CISA".into(),
                method_family: MethodFamily::ExploitTelemetry,
                nature: ClaimNature::Vulnerable,
                review_state: ReviewState::PublishedExternalHumanReview,
                disposition: ClaimDisposition::Active,
                reference_url: None,
                based_on_organisation: None,
                summary: name.to_owned(),
            }],
        });
    }
    Ok(out)
}

fn enforce_feed_json_cap(raw_json: &str, multi_record: bool) -> Result<(), IntelError> {
    let limits = embedded_limits().map_err(|msg| IntelError::CodecParse(msg.into()))?;
    let max_bytes = if multi_record {
        limits.server.ingest.max_body_bytes
    } else {
        limits.endpoint.ipc.max_frame_bytes
    };
    if raw_json.len() > max_bytes {
        return Err(IntelError::CodecParse(format!(
            "feed payload {} bytes exceeds limit ({max_bytes})",
            raw_json.len()
        )));
    }
    Ok(())
}

fn validate_osv_id(osv_id: &str) -> Result<(), IntelError> {
    if osv_id.is_empty()
        || osv_id.len() > 64
        || osv_id != osv_id.trim()
        || !osv_id.contains('-')
        || !osv_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(IntelError::CodecParse("invalid OSV identifier".into()));
    }
    let Some((prefix, suffix)) = osv_id.split_once('-') else {
        return Err(IntelError::CodecParse("invalid OSV identifier".into()));
    };
    if prefix.is_empty() || suffix.is_empty() {
        return Err(IntelError::CodecParse("invalid OSV identifier".into()));
    }
    Ok(())
}

fn canonical_purl_ecosystem(ecosystem: &str) -> String {
    match ecosystem.trim().to_ascii_lowercase().as_str() {
        "crates.io" | "rust" => "cargo".to_owned(),
        "rubygems" => "gem".to_owned(),
        "go" => "golang".to_owned(),
        "packagist" => "composer".to_owned(),
        "pip" | "python" => "pypi".to_owned(),
        other => other.to_owned(),
    }
}

fn format_purl_from_ecosystem(ecosystem: &str, name: &str) -> String {
    let purl_type = canonical_purl_ecosystem(ecosystem);
    let clean_name = name.trim();
    if purl_type == "maven"
        && let Some((group, artifact)) = clean_name.split_once(':')
    {
        return format!("pkg:maven/{group}/{artifact}");
    }
    format!("pkg:{purl_type}/{clean_name}")
}

fn build_validated_purl(ecosystem: &str, name: &str) -> Result<String, IntelError> {
    validate_package_field(ecosystem, "ecosystem")?;
    validate_package_field(name, "package name")?;
    if name.contains(':') && canonical_purl_ecosystem(ecosystem) != "maven" {
        return Err(IntelError::CodecParse(
            "invalid `package name` package field".into(),
        ));
    }
    let purl = format_purl_from_ecosystem(ecosystem, name);
    validate_purl_syntax(&purl).map_err(|msg| IntelError::CodecParse(msg.into()))?;
    Ok(purl)
}

fn validate_package_field(val: &str, label: &str) -> Result<(), IntelError> {
    if val.trim().is_empty()
        || val != val.trim()
        || val.len() > MAX_PACKAGE_NAME_BYTES
        || val.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(IntelError::CodecParse(format!(
            "invalid `{label}` package field"
        )));
    }
    if label == "ecosystem" {
        if !val
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
        {
            return Err(IntelError::CodecParse(
                "invalid `ecosystem` package field".into(),
            ));
        }
        return Ok(());
    }
    if val.contains(['?', '#']) || val.starts_with('/') || val.ends_with('/') {
        return Err(IntelError::CodecParse(format!(
            "invalid `{label}` package field"
        )));
    }
    if val.starts_with('@') {
        let valid_scoped = val.split_once('/').is_some_and(|(scope, pkg)| {
            scope.len() > 1
                && !scope.strip_prefix('@').is_some_and(|s| s.contains('@'))
                && !scope.contains(':')
                && !pkg.is_empty()
                && !pkg.contains(['/', '@', ':'])
        });
        if !valid_scoped {
            return Err(IntelError::CodecParse(format!(
                "invalid `{label}` package field"
            )));
        }
        return Ok(());
    }
    if val.contains('@') || val.split('/').any(str::is_empty) {
        return Err(IntelError::CodecParse(format!(
            "invalid `{label}` package field"
        )));
    }
    if val.contains(':') {
        let valid_maven = val.split_once(':').is_some_and(|(group, artifact)| {
            !group.is_empty()
                && !artifact.is_empty()
                && !group.contains([':', '/'])
                && !artifact.contains([':', '/'])
        });
        if !valid_maven {
            return Err(IntelError::CodecParse(format!(
                "invalid `{label}` package field"
            )));
        }
    }
    Ok(())
}

fn validate_bounded_text(val: &str, label: &str) -> Result<(), IntelError> {
    if val.len() > MAX_FEED_STR_BYTES || val.chars().any(char::is_control) {
        return Err(IntelError::CodecParse(format!(
            "{label} contains control characters or exceeds byte bound"
        )));
    }
    Ok(())
}

fn truncate_title(raw: &str) -> String {
    if raw.len() <= MAX_FEED_STR_BYTES {
        return raw.to_owned();
    }
    let mut end = MAX_FEED_STR_BYTES;
    while end > 0 && !raw.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    raw.get(..end).unwrap_or("").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{IntelStatus, compute_status};

    #[test]
    fn osv_versions_or_semantics_ranges_prerelease_and_fail_closed_clauses() {
        let ossf_json = serde_json::json!({
            "id": "MAL-2026-0001",
            "summary": "Multi-version malicious package",
            "affected": [{
                "package": { "ecosystem": "npm", "name": "bad-pkg" },
                "versions": ["1.0.0", "1.0.1"]
            }]
        })
        .to_string();
        let rec = normalize_ossf_malicious(&ossf_json, "GRDRI-2026-00200").expect("ossf");
        let range = rec
            .observables
            .first()
            .and_then(|o| o.version_range.as_deref())
            .expect("range");
        assert!(version_in_vulnerable_range("1.0.0", range));
        assert!(version_in_vulnerable_range("1.0.1", range));
        assert!(!version_in_vulnerable_range("1.0.2", range));

        let osv_range_json = serde_json::json!({
            "id": "MAL-2026-0002",
            "summary": "Introduced zero all-versions",
            "affected": [{
                "package": { "ecosystem": "crates.io", "name": "bad-crate" },
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{ "introduced": "0" }, { "fixed": "1.2.0" }]
                }]
            }]
        })
        .to_string();
        let range_rec =
            normalize_ossf_malicious(&osv_range_json, "GRDRI-2026-00201").expect("ossf range");
        assert_eq!(
            range_rec.observables.first().map(|o| o.value.as_str()),
            Some("pkg:cargo/bad-crate")
        );
        let r_expr = range_rec
            .observables
            .first()
            .and_then(|o| o.version_range.as_deref())
            .expect("range");
        assert!(version_in_vulnerable_range("0.0.1-alpha", r_expr));
        assert!(version_in_vulnerable_range("1.2.0-rc1", r_expr));
        assert!(!version_in_vulnerable_range("1.2.0", r_expr));

        assert!(!version_in_vulnerable_range("1.0.5", ">=1.0.0, !=1.0.5"));
        assert!(!version_in_vulnerable_range("1.0.5", ">=1.0.0, bad_bound"));
        assert!(!version_in_vulnerable_range("not-a-ver", ">=1.0.0"));
        assert!(!version_in_vulnerable_range("1.2.0-rc1", "==1.2.0"));
    }

    #[test]
    fn ghsa_malware_maven_purl_and_kev_overflow_checks() {
        let ghsa_malware = serde_json::json!({
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "type": "malware",
            "severity": "critical",
            "summary": "Malicious Maven package",
            "vulnerabilities": [{
                "package": { "ecosystem": "maven", "name": "org.evil:stealer" },
                "vulnerable_version_range": ">= 1.0.0, < 1.1.0"
            }]
        })
        .to_string();
        let rec = normalize_ghsa(&ghsa_malware, "GRDRI-2026-00202").expect("ghsa malware");
        assert_eq!(compute_status(&rec), IntelStatus::Malicious);
        assert_eq!(
            rec.observables.get(1).map(|o| o.value.as_str()),
            Some("pkg:maven/org.evil/stealer")
        );

        let ghsa_vuln = serde_json::json!({
            "ghsa_id": "GHSA-1111-2222-3333",
            "severity": "high",
            "summary": "Standard vuln",
            "vulnerabilities": [{
                "package": { "ecosystem": "crates.io", "name": "vuln-crate" },
                "vulnerable_version_range": ">= 0.1.0, < 0.2.0"
            }]
        })
        .to_string();
        let vrec = normalize_ghsa(&ghsa_vuln, "GRDRI-2026-00203").expect("ghsa vuln");
        assert_eq!(compute_status(&vrec), IntelStatus::Vulnerable);

        let kev = serde_json::json!({
            "vulnerabilities": [{
                "cveID": "CVE-2026-1000",
                "vulnerabilityName": "RCE",
                "knownRansomwareCampaignUse": "Known"
            }]
        })
        .to_string();
        assert!(normalize_cisa_kev_catalog(&kev, 2026, 99_999).is_ok());
        let kev_two = serde_json::json!({
            "vulnerabilities": [
                { "cveID": "CVE-2026-1000" },
                { "cveID": "CVE-2026-1001" }
            ]
        })
        .to_string();
        assert!(matches!(
            normalize_cisa_kev_catalog(&kev_two, 2026, 99_999),
            Err(IntelError::InvalidRecord(_))
        ));
        assert!(matches!(
            normalize_cisa_kev_catalog(&kev_two, 2026, u32::MAX),
            Err(IntelError::InvalidRecord(_) | IntelError::CodecParse(_))
        ));
    }

    #[test]
    fn round2_feeds_mixed_or_clauses_and_strict_id_caps() {
        // Valid left alternative in `||` still matches even when sibling alternative uses `.post1` / non-semver.
        assert!(version_in_vulnerable_range(
            "1.0.0",
            "==1.0.0 || ==1.0.2.post1"
        ));
        // Comma-conjunction stays fail-closed on unparseable clause inside that alternative.
        assert!(!version_in_vulnerable_range(
            "1.0.5",
            ">=1.0.0, !=invalid_ver || ==2.0.0"
        ));
        assert!(version_in_vulnerable_range(
            "2.0.0",
            ">=1.0.0, !=invalid_ver || ==2.0.0"
        ));

        // Invalid GHSA ID / bad CVE format / oversized feed JSON rejected.
        let bad_ghsa = serde_json::json!({
            "ghsa_id": "GHSA-bad",
            "severity": "high",
            "vulnerabilities": []
        })
        .to_string();
        assert!(normalize_ghsa(&bad_ghsa, "GRDRI-2026-00210").is_err());

        let bad_kev_cve = serde_json::json!({
            "vulnerabilities": [{ "cveID": "NOT-A-CVE-123" }]
        })
        .to_string();
        assert!(normalize_cisa_kev_catalog(&bad_kev_cve, 2026, 211).is_err());

        let huge_ossf = format!("{{\"summary\":\"{}\"}}", "x".repeat(200 * 1024));
        assert!(normalize_ossf_malicious(&huge_ossf, "GRDRI-2026-00212").is_err());
    }

    #[test]
    fn round4_semver_mixed_or_hyphen_osv_injection_withdrawn_ghsa_cap_pip_and_urls() {
        use crate::pack::validate_intel_pack_json;
        use crate::semver::validate_version_range_syntax;

        // Mixed `||` with >=1 valid SemVer alternative and safe `==<token>` passes validation.
        assert!(validate_version_range_syntax("==1.0.0 || ==1.0.2.post1").is_ok());
        assert!(validate_version_range_syntax("==1.0.2.post1").is_err());
        assert!(validate_version_range_syntax("==1.0.0, bad_clause").is_err());
        assert!(validate_version_range_syntax("==1.0.0 || ==1.0.2, bad_clause").is_err());

        let mixed_pack = serde_json::json!({
            "pack_id": "grdr.intel.mixed-or",
            "kind": "intel",
            "polarity": "protect",
            "version": "1.0.0",
            "channel": "standard",
            "publisher": "OSSF",
            "records": [{
                "id": "GRDRI-2026-00220",
                "title": "Mixed OSV versions",
                "severity": "critical",
                "withdrawn": false,
                "observables": [{
                    "kind": "package-purl",
                    "value": "pkg:pypi/evil-py",
                    "version_range": "==1.0.0 || ==1.0.2.post1"
                }],
                "evidence": [{
                    "feed": "ossf",
                    "organisation": "OSSF",
                    "method_family": "human_review",
                    "nature": "malicious",
                    "review_state": "published_external_human_review",
                    "disposition": "active",
                    "reference_url": null,
                    "summary": "Mixed range"
                }]
            }]
        })
        .to_string();
        assert!(validate_intel_pack_json(&mixed_pack).is_ok());

        // Hyphen ranges parse as >=lo, <=hi, never as prerelease equality in SemVerTuple::parse.
        assert!(SemVerTuple::parse("1.0.0 - 2.0.0").is_err());
        assert!(validate_version_range_syntax("1.0.0 - 2.0.0").is_ok());
        assert!(version_in_vulnerable_range("1.5.0", "1.0.0 - 2.0.0"));
        assert!(version_in_vulnerable_range("1.0.0", "1.0.0 - 2.0.0"));
        assert!(version_in_vulnerable_range("2.0.0", "1.0.0 - 2.0.0"));
        assert!(!version_in_vulnerable_range("0.9.9", "1.0.0 - 2.0.0"));
        assert!(!version_in_vulnerable_range("2.0.1", "1.0.0 - 2.0.0"));
        assert!(version_in_vulnerable_range(
            "1.5.0",
            "1.0.0-alpha.1 - 2.0.0-rc.1"
        ));

        // OSV injection tokens (`,`, `||`, whitespace, controls) rejected fail-closed.
        for bad_osv in [
            serde_json::json!({
                "id": "MAL-2026-0010",
                "summary": "Injected intro",
                "affected": [{
                    "package": { "ecosystem": "npm", "name": "evil" },
                    "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "1.0.0, <0.0.0" }] }]
                }]
            }),
            serde_json::json!({
                "id": "MAL-2026-0011",
                "summary": "Injected fixed",
                "affected": [{
                    "package": { "ecosystem": "npm", "name": "evil" },
                    "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "1.0.0" }, { "fixed": "2.0.0 || >=0.0.0-0" }] }]
                }]
            }),
            serde_json::json!({
                "id": "MAL-2026-0012",
                "summary": "Injected version",
                "affected": [{
                    "package": { "ecosystem": "npm", "name": "evil" },
                    "versions": ["1.0.0, <0.0.0"]
                }]
            }),
        ] {
            assert!(normalize_ossf_malicious(&bad_osv.to_string(), "GRDRI-2026-00221").is_err());
        }

        // Empty withdrawn / withdrawn_at strings yield withdrawn: false.
        let ossf_empty_w = serde_json::json!({
            "id": "MAL-2026-0013",
            "summary": "Not withdrawn",
            "withdrawn": "",
            "affected": [{ "package": { "ecosystem": "PIP", "name": "evil-py" }, "versions": ["1.0.0"] }]
        })
        .to_string();
        let rec_ossf = normalize_ossf_malicious(&ossf_empty_w, "GRDRI-2026-00222").unwrap();
        assert!(!rec_ossf.withdrawn);
        assert_eq!(rec_ossf.observables[0].value, "pkg:pypi/evil-py");

        // GHSA PIP -> pkg:pypi, empty withdrawn_at -> false, and MAX_OBSERVABLES_PER_RECORD (512) enforced.
        let ghsa_pip = serde_json::json!({
            "ghsa_id": "GHSA-aaaa-bbbb-dddd",
            "severity": "high",
            "withdrawn_at": "   ",
            "summary": "PyPI advisory",
            "vulnerabilities": [{
                "package": { "ecosystem": "PIP", "name": "agent-py" },
                "vulnerable_version_range": "1.0.0 - 1.2.0"
            }]
        })
        .to_string();
        let rec_ghsa = normalize_ghsa(&ghsa_pip, "GRDRI-2026-00223").unwrap();
        assert!(!rec_ghsa.withdrawn);
        assert_eq!(rec_ghsa.observables[1].value, "pkg:pypi/agent-py");

        let vulns_512: Vec<Value> = (0..512)
            .map(|i| {
                serde_json::json!({
                    "package": { "ecosystem": "npm", "name": format!("pkg-{i}") },
                    "vulnerable_version_range": ">=1.0.0"
                })
            })
            .collect();
        let ghsa_overflow = serde_json::json!({
            "ghsa_id": "GHSA-aaaa-bbbb-eeee",
            "severity": "high",
            "summary": "Too many vulns",
            "vulnerabilities": vulns_512
        })
        .to_string();
        assert!(normalize_ghsa(&ghsa_overflow, "GRDRI-2026-00224").is_err());

        // Non-HTTP(S) or empty reference URLs rejected in feeds.
        for bad_url in [
            "",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,hi",
        ] {
            let ossf_bad_url = serde_json::json!({
                "id": "MAL-2026-0014",
                "summary": "Bad ref url",
                "references": [{ "url": bad_url }],
                "affected": [{ "package": { "ecosystem": "npm", "name": "evil" }, "versions": ["1.0.0"] }]
            })
            .to_string();
            assert!(normalize_ossf_malicious(&ossf_bad_url, "GRDRI-2026-00225").is_err());

            let ghsa_bad_url = serde_json::json!({
                "ghsa_id": "GHSA-aaaa-bbbb-ffff",
                "severity": "high",
                "html_url": bad_url,
                "vulnerabilities": []
            })
            .to_string();
            assert!(normalize_ghsa(&ghsa_bad_url, "GRDRI-2026-00226").is_err());
        }

        // Round 5: PURL @version injection, malformed ecosystem/name coordinates, and bad URL hosts.
        let ossf_bad_purl = serde_json::json!({
            "id": "MAL-2026-0015",
            "summary": "Injected purl",
            "affected": [{
                "package": { "purl": "pkg:npm/evil@1.0.0||>=0.0.0-0" },
                "versions": ["1.0.0"]
            }]
        })
        .to_string();
        assert!(normalize_ossf_malicious(&ossf_bad_purl, "GRDRI-2026-00227").is_err());

        for (eco, name) in [
            ("npm", "evil@1.0.0||>=0.0.0-0"),
            ("npm/pypi", "evil"),
            ("npm:1", "evil"),
            ("maven", "g:a@1.0.0"),
            ("maven", ":artifact"),
            ("maven", "group:"),
            ("npm", "@scope"),
            ("npm", "a:b"),
            ("npm", "evil?q=1"),
            ("npm", "evil#frag"),
            ("npm", "/evil"),
            ("npm", "evil/"),
            ("npm", "a//b"),
        ] {
            let ossf_bad_pkg = serde_json::json!({
                "id": "MAL-2026-0016",
                "summary": "Bad pkg field",
                "affected": [{
                    "package": { "ecosystem": eco, "name": name },
                    "versions": ["1.0.0"]
                }]
            })
            .to_string();
            assert!(
                normalize_ossf_malicious(&ossf_bad_pkg, "GRDRI-2026-00228").is_err(),
                "OSSF must reject eco={eco:?} name={name:?}"
            );

            let ghsa_bad_pkg = serde_json::json!({
                "ghsa_id": "GHSA-aaaa-bbbb-9999",
                "severity": "high",
                "summary": "Bad pkg field",
                "vulnerabilities": [{
                    "package": { "ecosystem": eco, "name": name },
                    "vulnerable_version_range": ">=1.0.0"
                }]
            })
            .to_string();
            assert!(
                normalize_ghsa(&ghsa_bad_pkg, "GRDRI-2026-00229").is_err(),
                "GHSA must reject eco={eco:?} name={name:?}"
            );
        }

        let ossf_bad_host = serde_json::json!({
            "id": "MAL-2026-0017",
            "summary": "Bad host",
            "references": [{ "url": "https://-bad.example/p" }],
            "affected": [{ "package": { "ecosystem": "npm", "name": "evil" }, "versions": ["1.0.0"] }]
        })
        .to_string();
        assert!(normalize_ossf_malicious(&ossf_bad_host, "GRDRI-2026-00230").is_err());
    }

    #[test]
    fn round6_ghsa_rejects_empty_or_malformed_vulnerable_version_range() {
        for bad_range in [
            serde_json::json!(""),
            serde_json::json!("   "),
            serde_json::json!("not-a-semver"),
            serde_json::json!(">="),
            serde_json::json!("==1.0.0, bad_clause"),
            serde_json::json!(123),
        ] {
            let ghsa = serde_json::json!({
                "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                "severity": "high",
                "summary": "Bad range test",
                "vulnerabilities": [{
                    "package": { "ecosystem": "npm", "name": "vuln-pkg" },
                    "vulnerable_version_range": bad_range
                }]
            })
            .to_string();
            assert!(
                normalize_ghsa(&ghsa, "GRDRI-2026-00231").is_err(),
                "expected GHSA vulnerable_version_range `{bad_range}` to fail"
            );
        }

        // Absent or null vulnerable_version_range remains accepted.
        let ghsa_null = serde_json::json!({
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "severity": "high",
            "summary": "Null range test",
            "vulnerabilities": [{
                "package": { "ecosystem": "npm", "name": "vuln-pkg" },
                "vulnerable_version_range": null
            }]
        })
        .to_string();
        assert!(normalize_ghsa(&ghsa_null, "GRDRI-2026-00232").is_ok());
    }
}
