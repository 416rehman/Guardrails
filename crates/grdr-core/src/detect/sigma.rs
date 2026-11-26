// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pure-Rust Sigma YAML rule parser supporting `x_grdr`, validated condition ASTs, and `correlation` blocks (`D-09`).

use std::collections::BTreeMap;

use ipnet::IpNet;
use regex::RegexBuilder;

use grdr_crypto::sha256_hex;
use grdr_model::{FindingClass, FindingSeverity, MAX_OTHER_LABEL_CHARS};

use crate::detect::eval::parse_condition_ast;
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
const PINNED_SIGNED_CORE_RULE_SHA256: &[&str] = &[
    "2647b259ab45199aa176a13a960108d289172771596c9856318c2c3ad72d3e27",
    "691ec38811bdc142ed0378914483b2e49f501dbc634a589beffb8dac3587933a",
    "c73ce97a9c9f7c6be770f9fff2212e3b584cb1ec9df96f0ab77bd8ceeb9770eb",
    "a668f21431e838473a7ec243eb8270c53a10814f4e60075051d82b5d30746b7e",
    "11c4559dba5bb4881d1245cde86f23cef84c64249343e0aa2d47fa761f65b235",
    "2b006c16f0a6dfb4cee65f720bb283e497adf7ab5f8a9478e13f419691c38f99",
    "5a52b39035fe9eab8fa6627476d5c87bc1c14d534fbce3e39fe2a11600629a64",
    "3c0723236d7d49a2670d1f74501b9fa509740e1a45f7f784a55b3697da98654a",
    "6df61c9e5d87cd23d0cc23c31934481b56ee9312f3765401cf9fd766ced66ea3",
    "aba17a8fb584ab4279cbcec4139cd6d8b17e1881a16e760319c8bdbad9e937e0",
    "f6b63de5726ab8896703f298f61be337e2bb0382ce75cc03132fcc294adb6779",
    "1552be8069bf6da23ba893f596160c4ce70747b7977d28934da5824444ef6def",
    "597249b814397fcb6995a4b0384811a7aae8bd7e84e3f3d490a747e87f3a2854",
    "879a1245cc5fd36749db1dd506662387181f60e2c617fa67c17960aa3f7f0794",
    "caa4e09c315365faf5a1bcc18f7e63bd08c792bd76b195196ce6db122be665db",
    "6ea9035f1a746eb3f89fe9d1fed3e860b46701187675e925fcb5fe8699add0b1",
    "7f46ab24f27f65a0bd41726b3b44390a404728034cede6aef36698fc73951464",
    "42c72832d67b5d2646e914ba2714441e7cc94b9339d782aff8ece1cf41b74540",
    "7a3453306dad609e8a0d390e739d8bf40acac589b0fbbe2f8740c15f8a49695a",
    "ddabc561ee5237e0da5a0116f513d749bf49724d2c16357b6a3e2014b729b3b8",
    "c5fafc6342caa8eb51fb44efe6c790b168578e015a11acb2f1c56040ac2c07ef",
    "67a90907f7c5dad193346a3e02f22abf8c284e0f19a7b62c1aedd8c547fbfb71",
    "95c5ece6b05df971d5892cc7e4f657b046acc8fdc7ece51c2ab2c25f61f24c27",
    "d053d3f636a6c779fe30672ac14670600794c4f4bd63ed0a6b0647626bf90ff7",
    "5c279f61d2044d05bea889f18a9be528784eef450da89392c0e2a8b2eb5475ca",
    "d9c11f294a76a110f3870f45e985732e0ac06122309a78e0bf863fa3dd2bf4b8",
    "1dded4cdb0474d57674adb49e2fbc5965932a668cb37b324679dc15e4fa60274",
    "63d729724f42dee4f919de5624509c193ae781e9b37901baea9b16e398f4cae4",
    "d94a2234caa4435105af8c53ae3c8da77f68daa7fbb9d7692a8bbfa0f6445356",
    "b2094ef822e4aff21fd45df1d9a9a03c421205e29b9ab8c02fd6e1cbdbcb6ece",
];

/// Parses a single Sigma YAML document including `x_grdr`, validated `condition_ast`, and `correlation`.
pub fn parse_sigma_rule(raw_yaml: &str) -> Result<SigmaRule, DetectError> {
    parse_sigma_rule_for_verified_pack(raw_yaml, false)
}

pub(crate) fn parse_sigma_rule_for_verified_pack(
    raw_yaml: &str,
    trusted_official_pack: bool,
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
    let (origin, origin_declared) = match x_grdr.get("origin") {
        None => {
            let inferred = if trusted_official_pack && author == "The Guardrails ADR Authors" {
                RuleOrigin::Official
            } else {
                RuleOrigin::Community
            };
            (inferred, false)
        }
        Some(v) => {
            let parsed = parse_origin(opt_str_field(v, "x_grdr.origin")?)?;
            // Clamp all non-community provenance on untrusted/standalone rules.
            let capped = if trusted_official_pack && author == "The Guardrails ADR Authors" {
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
    let normalized = raw_yaml.replace("\r\n", "\n");
    let raw_sha = sha256_hex(normalized.as_bytes());
    let is_pinned_signed_core = trusted_official_pack
        && response
            .as_ref()
            .is_some_and(|b| b.mode == ResponseExecutionMode::Simulate)
        && PINNED_SIGNED_CORE_RULE_SHA256.contains(&raw_sha.as_str());
    if let Some(binding) = &response {
        validate_response_binding_with_legacy(binding, effective_ceiling, !is_pinned_signed_core)?;
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
        atlas: x_grdr
            .get("atlas")
            .map(YamlValue::to_string_list)
            .unwrap_or_default(),
        owasp_asi: x_grdr
            .get("owasp_asi")
            .map(YamlValue::to_string_list)
            .unwrap_or_default(),
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
