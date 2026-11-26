// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Scalar, correlation, modifier, and enum field parsers for Sigma rules (`D-09`).

use grdr_model::FindingClass;

use crate::detect::types::{
    CorrelationKind, CorrelationSpec, DeploymentScope, DetectError, FindingCeiling, RuleOrigin,
    SigmaModifier, SigmaStatus,
};
use crate::detect::yaml::YamlValue;

const MAX_RULE_TIMESPAN_SECS: u64 = 7 * 86_400;

pub(super) fn parse_correlation(
    corr: &YamlValue,
    fallback_tf: Option<&str>,
) -> Result<CorrelationSpec, DetectError> {
    let kind_raw = corr
        .get("type")
        .and_then(YamlValue::as_str)
        .ok_or_else(|| DetectError::InvalidRule("correlation missing `type`".into()))?;
    let kind = match kind_raw {
        "event_count" => CorrelationKind::EventCount,
        "value_count" => CorrelationKind::ValueCount,
        "temporal" => CorrelationKind::Temporal,
        "temporal_ordered" => CorrelationKind::TemporalOrdered,
        other => {
            return Err(DetectError::InvalidRule(format!(
                "unsupported correlation type `{other}`"
            )));
        }
    };
    let tf_str = corr
        .get("timespan")
        .and_then(YamlValue::as_str)
        .or(fallback_tf)
        .unwrap_or("5m");
    let timespan_secs = parse_timespan_secs(tf_str)?;
    let threshold = match corr
        .get("condition")
        .and_then(|c| c.get("gte"))
        .or_else(|| corr.get("gte"))
    {
        None => 1,
        Some(v) => {
            let n = v.as_i64().ok_or_else(|| {
                DetectError::InvalidRule("correlation `gte` must be integer".into())
            })?;
            let t = u32::try_from(n)
                .map_err(|_| DetectError::InvalidRule(format!("invalid threshold `{n}`")))?;
            if t == 0 {
                return Err(DetectError::InvalidRule(
                    "correlation `gte` threshold must be >= 1".into(),
                ));
            }
            t
        }
    };
    let distinct_field = corr
        .get("condition")
        .and_then(|c| c.get("distinct_field"))
        .and_then(YamlValue::as_str)
        .map(str::to_owned);
    let distinct_threshold = match corr.get("condition").and_then(|c| c.get("distinct_gte")) {
        None => 0,
        Some(v) => {
            let n = v.as_i64().ok_or_else(|| {
                DetectError::InvalidRule("correlation `distinct_gte` must be integer".into())
            })?;
            let dt = u32::try_from(n)
                .map_err(|_| DetectError::InvalidRule(format!("invalid `distinct_gte` `{n}`")))?;
            if dt == 0 {
                return Err(DetectError::InvalidRule(
                    "correlation `distinct_gte` must be >= 1".into(),
                ));
            }
            dt
        }
    };
    let scope = corr
        .get("scope")
        .map(|v| opt_str_field(v, "correlation.scope"))
        .transpose()?
        .map(parse_scope_str)
        .transpose()?;
    let rules = corr
        .get("rules")
        .map(YamlValue::to_string_list)
        .unwrap_or_default();
    if matches!(
        kind,
        CorrelationKind::Temporal | CorrelationKind::TemporalOrdered
    ) && rules.is_empty()
    {
        return Err(DetectError::InvalidRule(
            "temporal correlation rule requires non-empty `rules` list".into(),
        ));
    }
    let count_field = corr
        .get("condition")
        .and_then(|c| c.get("field"))
        .and_then(YamlValue::as_str)
        .map(str::to_owned);
    if kind == CorrelationKind::ValueCount
        && count_field.as_deref().is_none_or(|f| f.trim().is_empty())
    {
        return Err(DetectError::InvalidRule(
            "value_count correlation rule requires non-empty `condition.field`".into(),
        ));
    }
    if distinct_threshold > 0
        && distinct_field
            .as_deref()
            .is_none_or(|f| f.trim().is_empty())
    {
        return Err(DetectError::InvalidRule(
            "correlation `distinct_gte` requires non-empty `condition.distinct_field`".into(),
        ));
    }
    Ok(CorrelationSpec {
        kind,
        group_by: corr
            .get("group-by")
            .or_else(|| corr.get("group_by"))
            .map(YamlValue::to_string_list)
            .unwrap_or_default(),
        timespan_secs,
        threshold,
        count_field,
        distinct_field,
        distinct_threshold,
        rules,
        scope,
    })
}

fn parse_timespan_secs(raw: &str) -> Result<u64, DetectError> {
    let t = raw.trim();
    let secs = if let Some(s) = t.strip_suffix('s') {
        s.trim()
            .parse::<u64>()
            .map_err(|_| DetectError::InvalidRule(format!("bad timespan `{raw}`")))?
    } else if let Some(m) = t.strip_suffix('m') {
        m.trim()
            .parse::<u64>()
            .map(|v| v.saturating_mul(60))
            .map_err(|_| DetectError::InvalidRule(format!("bad timespan `{raw}`")))?
    } else if let Some(h) = t.strip_suffix('h') {
        h.trim()
            .parse::<u64>()
            .map(|v| v.saturating_mul(3600))
            .map_err(|_| DetectError::InvalidRule(format!("bad timespan `{raw}`")))?
    } else {
        t.parse::<u64>()
            .map_err(|_| DetectError::InvalidRule(format!("bad timespan `{raw}`")))?
    };
    if secs == 0 || secs > MAX_RULE_TIMESPAN_SECS {
        return Err(DetectError::InvalidRule(format!(
            "correlation timespan `{raw}` must be within 1s..=7d"
        )));
    }
    Ok(secs)
}

pub(super) fn parse_modifier(raw: &str) -> Result<SigmaModifier, DetectError> {
    match raw.to_ascii_lowercase().as_str() {
        "contains" => Ok(SigmaModifier::Contains),
        "startswith" => Ok(SigmaModifier::StartsWith),
        "endswith" => Ok(SigmaModifier::EndsWith),
        "re" => Ok(SigmaModifier::Re),
        "cidr" => Ok(SigmaModifier::Cidr),
        "exists" => Ok(SigmaModifier::Exists),
        "expand" => Ok(SigmaModifier::Expand),
        "all" => Ok(SigmaModifier::All),
        other => Err(DetectError::InvalidRule(format!(
            "unsupported Sigma modifier `{other}`"
        ))),
    }
}

pub(super) fn req_str(val: &YamlValue, key: &str) -> Result<String, DetectError> {
    val.get(key)
        .and_then(YamlValue::as_str)
        .map(str::to_owned)
        .ok_or_else(|| DetectError::InvalidRule(format!("missing string field `{key}`")))
}

pub(super) fn opt_str_field<'a>(val: &'a YamlValue, name: &str) -> Result<&'a str, DetectError> {
    val.as_str()
        .ok_or_else(|| DetectError::InvalidRule(format!("`{name}` must be a string")))
}

pub(super) fn parse_status(raw: &str) -> Result<SigmaStatus, DetectError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "stable" => Ok(SigmaStatus::Stable),
        "test" => Ok(SigmaStatus::Test),
        "deprecated" => Ok(SigmaStatus::Deprecated),
        "experimental" => Ok(SigmaStatus::Experimental),
        other => Err(DetectError::InvalidRule(format!(
            "unknown Sigma status `{other}`"
        ))),
    }
}

pub(super) fn parse_origin(raw: &str) -> Result<RuleOrigin, DetectError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "community" => Ok(RuleOrigin::Community),
        "organisation" | "organization" => Ok(RuleOrigin::Organisation),
        "project" => Ok(RuleOrigin::Project),
        "official" => Ok(RuleOrigin::Official),
        other => Err(DetectError::InvalidRule(format!(
            "unknown Sigma origin `{other}`"
        ))),
    }
}

pub(super) fn parse_finding_class(raw: &str) -> Result<FindingClass, DetectError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tamper" => Ok(FindingClass::Tamper),
        "policy-violation" | "policy_violation" => Ok(FindingClass::PolicyViolation),
        "overeager" => Ok(FindingClass::Overeager),
        "coverage-gap" | "coverage_gap" => Ok(FindingClass::CoverageGap),
        "threat" => Ok(FindingClass::Threat),
        other => Err(DetectError::InvalidRule(format!(
            "unknown finding_class `{other}`"
        ))),
    }
}

pub(super) fn parse_ceiling(raw: &str) -> Result<FindingCeiling, DetectError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "record" => Ok(FindingCeiling::Record),
        "notify" => Ok(FindingCeiling::Notify),
        "contain" => Ok(FindingCeiling::Contain),
        "remediate" => Ok(FindingCeiling::Remediate),
        other => Err(DetectError::InvalidRule(format!(
            "unknown x_grdr.ceiling `{other}`"
        ))),
    }
}

pub(super) fn parse_scope_str(raw: &str) -> Result<DeploymentScope, DetectError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "device" => Ok(DeploymentScope::Device),
        "server" => Ok(DeploymentScope::Server),
        "any" => Ok(DeploymentScope::Any),
        other => Err(DetectError::InvalidRule(format!("unknown scope `{other}`"))),
    }
}
