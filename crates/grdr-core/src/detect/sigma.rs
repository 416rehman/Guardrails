// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pure-Rust Sigma YAML rule parser supporting `x_grdr`, validated condition ASTs, and `correlation` blocks (`D-09`).

use std::collections::{BTreeMap, BTreeSet};

use ipnet::IpNet;
use regex::RegexBuilder;

use grdr_crypto::sha256_hex;
use grdr_model::{FindingClass, FindingSeverity, MAX_OTHER_LABEL_CHARS};

use crate::detect::eval::parse_condition_ast;
use crate::detect::pack_sig::shipped_core_verified_rule_digests;
use crate::detect::response::validate_response_binding_with_legacy;
use crate::detect::sigma_fields::{
    opt_str_field, parse_ceiling, parse_correlation, parse_finding_class, parse_modifier,
    parse_origin, parse_scope_str, parse_status, req_str,
};
use crate::detect::types::{
    CorrelationSpec, DeploymentScope, DetectError, FieldPredicate, FindingCeiling, LogSourceSpec,
    ResponseBinding, ResponseExecutionMode, RuleOrigin, SelectionBlock, SigmaModifier, SigmaRule,
    SigmaStatus,
};
use crate::detect::yaml::{YamlValue, parse_yaml};

const MAX_REGEX_COMPILED_BYTES: usize = 256 * 1024;
const CONTENT_FIELDS: &[&str] = &[
    "CommandLine",
    "TargetFilename",
    "target",
    "exec.argv",
    "exec.image",
    "file.path",
    "net.url",
];

/// Parses a single Sigma YAML document including `x_grdr`, validated `condition_ast`, and `correlation`.
pub fn parse_sigma_rule(raw_yaml: &str) -> Result<SigmaRule, DetectError> {
    parse_sigma_rule_for_verified_pack(raw_yaml, false, None, false)
}

pub(crate) fn parse_sigma_rule_for_verified_pack(
    raw_yaml: &str,
    allow_official_origin: bool,
    verified_rule_digests: Option<&BTreeSet<String>>,
    verify_shipped_core: bool,
) -> Result<SigmaRule, DetectError> {
    let root = parse_yaml(raw_yaml)?;
    let title = req_str(&root, "title")?;
    let uuid = req_str(&root, "id")?;
    let author = root
        .get("author")
        .and_then(YamlValue::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let status = match root.get("status") {
        None => SigmaStatus::Experimental,
        Some(v) => parse_status(opt_str_field(v, "status")?)?,
    };
    let ls_map = root
        .get("logsource")
        .ok_or_else(|| DetectError::InvalidRule("missing `logsource` section".into()))?;
    let logsource = LogSourceSpec {
        product: ls_map
            .get("product")
            .and_then(YamlValue::as_str)
            .unwrap_or("grdr")
            .to_owned(),
        category: ls_map
            .get("category")
            .and_then(YamlValue::as_str)
            .map(str::to_owned),
        service: ls_map
            .get("service")
            .and_then(YamlValue::as_str)
            .map(str::to_owned),
    };
    let x_grdr = root
        .get("x_grdr")
        .ok_or_else(|| DetectError::InvalidRule("missing `x_grdr` metadata block".into()))?;
    let row = match x_grdr.get("row") {
        None => 0,
        Some(v) => u32::try_from(
            v.as_i64()
                .ok_or_else(|| DetectError::InvalidRule("`x_grdr.row` must be integer".into()))?,
        )
        .map_err(|_| DetectError::InvalidRule("negative `x_grdr.row`".into()))?,
    };
    let rule_id = req_str(x_grdr, "rule_id")?;
    let version = x_grdr
        .get("version")
        .and_then(YamlValue::as_str)
        .unwrap_or("1.0.0")
        .to_owned();
    let finding_class = match x_grdr.get("finding_class") {
        None => FindingClass::Threat,
        Some(v) => parse_finding_class(opt_str_field(v, "x_grdr.finding_class")?)?,
    };
    let finding_class_other = match x_grdr.get("finding_class_other") {
        None => None,
        Some(v) => {
            if finding_class != FindingClass::Other {
                return Err(DetectError::InvalidRule(
                    "`x_grdr.finding_class_other` requires `x_grdr.finding_class: other`".into(),
                ));
            }
            let label = opt_str_field(v, "x_grdr.finding_class_other")?;
            if label.trim().is_empty()
                || label.chars().any(char::is_control)
                || label.chars().count() > MAX_OTHER_LABEL_CHARS
            {
                return Err(DetectError::InvalidRule(format!(
                    "`x_grdr.finding_class_other` must be non-empty <= {MAX_OTHER_LABEL_CHARS} chars with no control chars"
                )));
            }
            Some(label.to_owned())
        }
    };
    let ceiling = match x_grdr.get("ceiling") {
        None => FindingCeiling::Notify,
        Some(v) => parse_ceiling(opt_str_field(v, "x_grdr.ceiling")?)?,
    };
    let raw_sha = sha256_hex(raw_yaml.as_bytes());
    let is_verified_digest = if let Some(digests) = verified_rule_digests {
        digests.contains(&raw_sha)
    } else if verify_shipped_core {
        shipped_core_verified_rule_digests()?.contains(&raw_sha)
    } else {
        false
    };
    let is_official_verified = allow_official_origin && is_verified_digest;
    let (origin, origin_declared) = match x_grdr.get("origin") {
        None => (
            if is_official_verified {
                RuleOrigin::Official
            } else {
                RuleOrigin::Community
            },
            false,
        ),
        Some(v) => {
            let parsed = parse_origin(opt_str_field(v, "x_grdr.origin")?)?;
            // Non-verified or non-official packs always clamp origin to Community.
            let capped = if is_official_verified {
                parsed
            } else {
                RuleOrigin::Community
            };
            (capped, true)
        }
    };
    let det_map = root
        .get("detection")
        .ok_or_else(|| DetectError::InvalidRule("missing `detection` block".into()))?
        .as_map()
        .ok_or_else(|| DetectError::InvalidRule("`detection` must be a mapping".into()))?;
    let condition = match det_map.get("condition") {
        None => "selection".to_owned(),
        Some(v) => opt_str_field(v, "detection.condition")?.trim().to_owned(),
    };
    if condition.is_empty() {
        return Err(DetectError::InvalidRule(
            "`detection.condition` cannot be empty".into(),
        ));
    }
    let mut selections = BTreeMap::new();
    for (key, val) in det_map {
        if key != "condition" && key != "timeframe" {
            selections.insert(key.clone(), parse_selection_block(key, val)?);
        }
    }
    let condition_ast = parse_condition_ast(&condition, &selections)?;
    let correlation = root
        .get("correlation")
        .or_else(|| x_grdr.get("correlation"))
        .map(|c| parse_correlation(c, det_map.get("timeframe").and_then(YamlValue::as_str)))
        .transpose()?;
    let min_provenance = parse_min_provenance(x_grdr)?;
    let response = parse_response_binding(x_grdr.get("response"))?;
    let scope =
        parse_placement_scope(x_grdr, &selections, correlation.as_ref(), response.as_ref())?;
    let effective_ceiling = ceiling.clamp_by_origin(status, origin);
    if let Some(binding) = &response {
        validate_response_binding_with_legacy(binding, effective_ceiling, !is_verified_digest)?;
    }
    let severity = match (&finding_class, &effective_ceiling) {
        (FindingClass::Tamper, FindingCeiling::Remediate | FindingCeiling::Contain) => {
            FindingSeverity::Critical
        }
        (_, FindingCeiling::Remediate | FindingCeiling::Contain) => FindingSeverity::High,
        (_, FindingCeiling::Notify) => FindingSeverity::Medium,
        _ => FindingSeverity::Low,
    };
    Ok(SigmaRule {
        title,
        uuid,
        author,
        status,
        origin,
        origin_declared,
        row,
        rule_id,
        version,
        finding_class,
        finding_class_other,
        severity,
        ceiling,
        scope,
        min_provenance,
        stage: x_grdr
            .get("stage")
            .and_then(YamlValue::as_str)
            .map(str::to_owned),
        atlas: match x_grdr.get("atlas") {
            None => Vec::new(),
            Some(v) => v.try_to_string_list()?,
        },
        owasp_asi: match x_grdr.get("owasp_asi") {
            None => Vec::new(),
            Some(v) => v.try_to_string_list()?,
        },
        logsource,
        selections,
        condition,
        condition_ast,
        correlation,
        response,
        derived_from: x_grdr
            .get("derived_from")
            .and_then(YamlValue::as_str)
            .map(str::to_owned),
        has_tests: x_grdr.get("tests").is_some(),
    })
}

fn is_content_field_name(raw: &str) -> bool {
    let low = raw.trim().to_ascii_lowercase();
    CONTENT_FIELDS
        .iter()
        .any(|cf| cf.eq_ignore_ascii_case(&low))
        || low.starts_with("content.")
}

fn parse_placement_scope(
    x_grdr: &YamlValue,
    selections: &BTreeMap<String, SelectionBlock>,
    correlation: Option<&CorrelationSpec>,
    response: Option<&ResponseBinding>,
) -> Result<DeploymentScope, DetectError> {
    let explicit = x_grdr
        .get("scope")
        .or_else(|| x_grdr.get("requires").and_then(|r| r.get("placement")))
        .map(|v| opt_str_field(v, "x_grdr.scope"))
        .transpose()?
        .map(parse_scope_str)
        .transpose()?;
    let sel_reads_content = selections
        .values()
        .any(|s| s.predicates.iter().any(|p| is_content_field_name(&p.field)));
    let corr_reads_content = correlation.is_some_and(|c| {
        c.group_by.iter().any(|g| is_content_field_name(g))
            || c.count_field.as_deref().is_some_and(is_content_field_name)
            || c.distinct_field
                .as_deref()
                .is_some_and(is_content_field_name)
    });
    let reads_content = sel_reads_content || corr_reads_content;
    let is_org_corr = correlation.is_some_and(|c| {
        c.scope == Some(DeploymentScope::Server)
            || (!c.group_by.is_empty()
                && !c.group_by.iter().any(|g| {
                    matches!(
                        g.as_str(),
                        "device_id" | "session_id" | "root_session_id" | "session.root"
                    )
                }))
    }) || response.is_some_and(|r| {
        r.max_scope.eq_ignore_ascii_case("organisation")
            || r.max_scope.eq_ignore_ascii_case("organization")
    });
    if reads_content {
        if explicit == Some(DeploymentScope::Server) {
            return Err(DetectError::InvalidRule(
                "content-reading Sigma rule cannot declare `server` placement (P8)".into(),
            ));
        }
        if is_org_corr {
            return Err(DetectError::InvalidRule(
                "content-reading Sigma rule cannot be an organisation-scope correlation (P8)"
                    .into(),
            ));
        }
        return Ok(DeploymentScope::Device);
    }
    if is_org_corr {
        if explicit == Some(DeploymentScope::Device) {
            return Err(DetectError::InvalidRule(
                "organisation-scope correlation cannot declare `device` placement".into(),
            ));
        }
        return Ok(DeploymentScope::Server);
    }
    Ok(explicit.unwrap_or(DeploymentScope::Any))
}

fn parse_min_provenance(x_grdr: &YamlValue) -> Result<u8, DetectError> {
    let Some(val) = x_grdr.get("requires").and_then(|r| r.get("min_provenance")) else {
        return Ok(0);
    };
    if let Some(n) = val.as_i64() {
        return u8::try_from(n)
            .map_err(|_| DetectError::InvalidRule("`min_provenance` out of range".into()));
    }
    match val
        .as_str()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "none" | "unverified" => Ok(0),
        "claimed" => Ok(1),
        "verified" => Ok(2),
        other => Err(DetectError::InvalidRule(format!(
            "unknown `min_provenance` `{other}`"
        ))),
    }
}

fn parse_response_binding(
    resp_opt: Option<&YamlValue>,
) -> Result<Option<ResponseBinding>, DetectError> {
    let Some(resp) = resp_opt else {
        return Ok(None);
    };
    let mode_str = match resp.get("mode") {
        None => "simulate",
        Some(v) => opt_str_field(v, "response.mode")?,
    };
    let mode = match mode_str.trim().to_ascii_lowercase().as_str() {
        "simulate" => ResponseExecutionMode::Simulate,
        "live" => ResponseExecutionMode::Live,
        other => {
            return Err(DetectError::InvalidRule(format!(
                "invalid `response.mode` `{other}`"
            )));
        }
    };
    let verbs = resp
        .get("verbs")
        .map(YamlValue::to_string_list)
        .unwrap_or_default();
    let max_scope = resp
        .get("max_scope")
        .and_then(YamlValue::as_str)
        .ok_or_else(|| DetectError::InvalidRule("response binding missing `max_scope`".into()))?
        .to_owned();
    let raw_bp = resp
        .get("max_share_bp")
        .and_then(YamlValue::as_i64)
        .ok_or_else(|| {
            DetectError::InvalidRule("response binding missing `max_share_bp`".into())
        })?;
    let max_share_bp = u16::try_from(raw_bp).map_err(|_| {
        DetectError::InvalidRule(format!("invalid `response.max_share_bp` `{raw_bp}`"))
    })?;
    Ok(Some(ResponseBinding {
        mode,
        verbs,
        max_scope,
        max_share_bp,
        // Never accept self-asserted `opted_in_remediate` from rule YAML (`docs/design/13` s.14).
        opted_in_remediate: false,
    }))
}

fn parse_selection_block(name: &str, val: &YamlValue) -> Result<SelectionBlock, DetectError> {
    let mut predicates = Vec::new();
    let map = val
        .as_map()
        .ok_or_else(|| DetectError::InvalidRule(format!("selection `{name}` must be a map")))?;
    if map.is_empty() {
        return Err(DetectError::InvalidRule(format!(
            "selection `{name}` cannot be empty"
        )));
    }
    for (raw_field, raw_val) in map {
        let mut parts = raw_field.split('|');
        let field = parts.next().unwrap_or("").trim().to_owned();
        if field.is_empty() {
            return Err(DetectError::InvalidRule(
                "empty Sigma selection field".into(),
            ));
        }
        let mut modifiers = Vec::new();
        for m in parts {
            modifiers.push(parse_modifier(m.trim())?);
        }
        if modifiers.is_empty() {
            modifiers.push(SigmaModifier::Exact);
        }
        let values = parse_predicate_values(raw_field, raw_val)?;
        if modifiers.contains(&SigmaModifier::Exists) {
            if values.len() != 1 {
                return Err(DetectError::InvalidRule(format!(
                    "`|exists` predicate `{raw_field}` requires a single boolean value"
                )));
            }
            for pat in &values {
                let norm = pat.trim();
                if !norm.eq_ignore_ascii_case("true") && !norm.eq_ignore_ascii_case("false") {
                    return Err(DetectError::InvalidRule(format!(
                        "`|exists` predicate `{raw_field}` requires boolean `true` or `false`"
                    )));
                }
            }
        }
        let has_expand = modifiers.contains(&SigmaModifier::Expand);
        if !has_expand && modifiers.contains(&SigmaModifier::Re) {
            for pat in &values {
                RegexBuilder::new(pat)
                    .size_limit(MAX_REGEX_COMPILED_BYTES)
                    .dfa_size_limit(256 * 1024)
                    .build()
                    .map_err(|e| {
                        DetectError::InvalidRule(format!("invalid Sigma regex `{pat}`: {e}"))
                    })?;
            }
        }
        if !has_expand && modifiers.contains(&SigmaModifier::Cidr) {
            for pat in &values {
                pat.parse::<IpNet>().map_err(|e| {
                    DetectError::InvalidRule(format!("invalid Sigma CIDR `{pat}`: {e}"))
                })?;
            }
        }
        predicates.push(FieldPredicate {
            field,
            modifiers,
            values,
        });
    }
    Ok(SelectionBlock {
        name: name.to_owned(),
        predicates,
    })
}

fn parse_predicate_values(field: &str, raw: &YamlValue) -> Result<Vec<String>, DetectError> {
    fn scalar_to_string(field: &str, v: &YamlValue) -> Result<String, DetectError> {
        match v {
            YamlValue::Str(s) => Ok(s.clone()),
            YamlValue::Int(i) => Ok(i.to_string()),
            YamlValue::Bool(b) => Ok(if *b { "true" } else { "false" }.to_owned()),
            YamlValue::Null | YamlValue::Seq(_) | YamlValue::Map(_) => {
                Err(DetectError::InvalidRule(format!(
                    "Sigma selection predicate `{field}` contains invalid null/nested value"
                )))
            }
        }
    }
    match raw {
        YamlValue::Seq(items) => {
            if items.is_empty() {
                return Err(DetectError::InvalidRule(format!(
                    "Sigma selection predicate `{field}` sequence cannot be empty"
                )));
            }
            items.iter().map(|v| scalar_to_string(field, v)).collect()
        }
        other => Ok(vec![scalar_to_string(field, other)?]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::engine::SigmaDetectionEngine;
    use crate::detect::types::{DetectionEngine as _, VerifiedDetectionContent};
    use grdr_model::Mode;

    #[test]
    fn rejects_unverified_official_origin_and_crlf_spoofing() {
        let spoofed_rule = "title: Spoofed Official Rule\nid: 11111111-1111-4111-8111-111111111111\nauthor: The Guardrails ADR Authors\nstatus: stable\nlogsource:\n  product: grdr\nx_grdr:\n  rule_id: grdr.det.core.r99.spoof\n  origin: official\n  ceiling: remediate\n  response:\n    mode: simulate\n    verbs: [restore-workspace-files]\n    max_scope: session\n    max_share_bp: 500\ndetection:\n  sel:\n    action_class: exec\n  condition: sel\n";
        assert!(
            SigmaDetectionEngine::load(
                &VerifiedDetectionContent {
                    pack_id: "grdr.det.core".into(),
                    version: "1.0.0".into(),
                    raw_rules_yaml: vec![spoofed_rule.into()],
                    pack_mode: Mode::Watch,
                },
                &crate::detect::types::HostProfile {
                    device_id: "d".into(),
                    device_name: "d".into(),
                    organisation_id: "o".into(),
                    scope: DeploymentScope::Any,
                    provenance_grade: 3,
                    expand_vars: BTreeMap::new(),
                    model_audit_passed: false,
                    remediate_approvers: BTreeMap::new(),
                },
            )
            .expect("load")
            .1
            .loaded_rules
            .is_empty()
        );

        let notify_spoof = "title: Spoofed Official Notify\nid: 22222222-2222-4222-8222-222222222222\nauthor: The Guardrails ADR Authors\nstatus: stable\nlogsource:\n  product: grdr\nx_grdr:\n  rule_id: custom.spoof.notify\ndetection:\n  sel:\n    action_class: exec\n  condition: sel\n";
        let (eng, _rep) = SigmaDetectionEngine::load(
            &VerifiedDetectionContent {
                pack_id: "grdr.det.experimental".into(),
                version: "1.0.0".into(),
                raw_rules_yaml: vec![notify_spoof.into()],
                pack_mode: Mode::Watch,
            },
            &crate::detect::types::HostProfile {
                device_id: "d".into(),
                device_name: "d".into(),
                organisation_id: "o".into(),
                scope: DeploymentScope::Any,
                provenance_grade: 3,
                expand_vars: BTreeMap::new(),
                model_audit_passed: false,
                remediate_approvers: BTreeMap::new(),
            },
        )
        .expect("load exp");
        let loaded = eng.loaded_rules().next().expect("loaded rule");
        assert_eq!(loaded.origin, RuleOrigin::Community);

        let r01 =
            include_str!("../../../../packs/detections/rules/det-01-agent-control-write.yaml");
        let parsed_lf = parse_sigma_rule_for_verified_pack(r01, true, None, true).expect("lf core");
        assert_eq!(parsed_lf.origin, RuleOrigin::Official);
        assert!(
            parse_sigma_rule_for_verified_pack(&r01.replace('\n', "\r\n"), true, None, true,)
                .is_err()
        );

        let r03 =
            include_str!("../../../../packs/detections/rules/det-03-repo-carried-config.yaml");
        assert_eq!(
            parse_sigma_rule_for_verified_pack(r03, true, None, true)
                .expect("lf r03")
                .origin,
            RuleOrigin::Official
        );
        assert!(
            parse_sigma_rule_for_verified_pack(&r03.replace('\n', "\r\n"), true, None, true,)
                .is_err()
        );
    }
}
