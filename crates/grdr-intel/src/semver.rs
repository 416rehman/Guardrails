// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! SemVer 2.0 comparator with prerelease ordering and OSV range/version extractors (`docs/design/14`).

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::IntelError;

const MAX_RANGE_ALTERNATIVES: usize = 1_024;
const MAX_CLAUSES_PER_ALT: usize = 32;
const MAX_RANGE_BYTES: usize = 4_096;
const MAX_VERSION_STR_BYTES: usize = 512;
const MAX_VERSION_TOKEN_BYTES: usize = 128;
const MAX_OSV_RANGES: usize = 64;
const MAX_OSV_EVENTS_PER_RANGE: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreIdent {
    Numeric(u64),
    Alpha(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemVerTuple {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    #[serde(default)]
    pub prerelease: Vec<PreIdent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionClause {
    pub op: BoundOp,
    pub version: SemVerTuple,
}

impl Ord for PreIdent {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.cmp(b),
            (Self::Numeric(_), Self::Alpha(_)) => Ordering::Less,
            (Self::Alpha(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::Alpha(a), Self::Alpha(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for PreIdent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVerTuple {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(|| compare_prereleases(&self.prerelease, &other.prerelease))
    }
}

impl PartialOrd for SemVerTuple {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl SemVerTuple {
    pub fn parse(raw: &str) -> Result<Self, IntelError> {
        if raw.len() > MAX_VERSION_STR_BYTES || raw.chars().any(char::is_control) {
            return Err(IntelError::CodecParse(
                "version string contains controls or exceeds bound".into(),
            ));
        }
        let trimmed = raw.trim();
        let no_v = trimmed
            .strip_prefix('v')
            .or_else(|| trimmed.strip_prefix('V'))
            .unwrap_or(trimmed);
        let without_build = no_v.split('+').next().unwrap_or(no_v).trim();
        let (core, pre_raw) = match without_build.split_once('-') {
            Some((c, p)) => {
                if c.is_empty() || p.is_empty() || c != c.trim() || p != p.trim() {
                    return Err(IntelError::CodecParse(
                        "invalid prerelease separator or empty suffix".into(),
                    ));
                }
                (c, Some(p))
            }
            None => (without_build, None),
        };
        let parts: Vec<&str> = core.split('.').collect();
        if parts.is_empty() || parts.len() > 3 {
            return Err(IntelError::CodecParse(
                "invalid version component count".into(),
            ));
        }
        let major = parse_numeric_part(parts.first().copied().unwrap_or(""))?;
        let minor = match parts.get(1) {
            Some(&p) => parse_numeric_part(p)?,
            None => 0,
        };
        let patch = match parts.get(2) {
            Some(&p) => parse_numeric_part(p)?,
            None => 0,
        };
        let mut prerelease = Vec::new();
        if let Some(pre) = pre_raw {
            for ident in pre.split('.') {
                if ident.is_empty() {
                    return Err(IntelError::CodecParse("empty prerelease identifier".into()));
                }
                if ident.bytes().all(|b| b.is_ascii_digit()) {
                    let n = ident
                        .parse::<u64>()
                        .map_err(|_| IntelError::CodecParse("invalid prerelease number".into()))?;
                    prerelease.push(PreIdent::Numeric(n));
                } else if ident
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                {
                    prerelease.push(PreIdent::Alpha(ident.to_ascii_lowercase()));
                } else {
                    return Err(IntelError::CodecParse(
                        "invalid prerelease identifier".into(),
                    ));
                }
            }
        }
        Ok(Self {
            major,
            minor,
            patch,
            prerelease,
        })
    }
}

/// Evaluates whether `candidate_version` falls inside a range expression composed of
/// `||`-separated disjunctions of comma-separated bounds like `>= 1.0.0, < 1.4.2 || == 2.0.0`.
/// Skips individual unparseable `||` alternatives while remaining fail-closed within comma conjunctions.
#[must_use]
pub fn version_in_vulnerable_range(candidate_version: &str, range_expr: &str) -> bool {
    let trimmed_cand = candidate_version.trim();
    if candidate_version.len() > MAX_VERSION_STR_BYTES
        || candidate_version.chars().any(char::is_control)
        || trimmed_cand.is_empty()
        || range_expr.len() > MAX_RANGE_BYTES
        || range_expr.chars().any(char::is_control)
    {
        return false;
    }
    let Ok(cand) = SemVerTuple::parse(candidate_version) else {
        return range_expr
            .split("||")
            .take(MAX_RANGE_ALTERNATIVES)
            .any(|alt| {
                non_semver_eq_token(alt.trim())
                    .is_some_and(|tok| tok.eq_ignore_ascii_case(trimmed_cand))
            });
    };
    for alt in range_expr.split("||").take(MAX_RANGE_ALTERNATIVES) {
        let trimmed = alt.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(clauses) = parse_version_clauses(trimmed) else {
            continue;
        };
        if clauses.is_empty() {
            continue;
        }
        let all_match = clauses.iter().all(|c| match c.op {
            BoundOp::Lt => cand < c.version,
            BoundOp::Le => cand <= c.version,
            BoundOp::Gt => cand > c.version,
            BoundOp::Ge => cand >= c.version,
            BoundOp::Eq => cand == c.version,
        });
        if all_match {
            return true;
        }
    }
    false
}

pub(crate) fn validate_version_range_syntax(range_expr: &str) -> Result<(), IntelError> {
    let trimmed = range_expr.trim();
    if trimmed.is_empty()
        || range_expr.len() > MAX_RANGE_BYTES
        || range_expr.chars().any(char::is_control)
    {
        return Err(IntelError::InvalidRecord(
            "version_range must be 1..=4096 non-control bytes".into(),
        ));
    }
    let mut alt_count: usize = 0;
    let mut valid_semver_alts: usize = 0;
    for alt in range_expr.split("||") {
        alt_count = alt_count.saturating_add(1);
        if alt_count > MAX_RANGE_ALTERNATIVES {
            return Err(IntelError::InvalidRecord(
                "version_range exceeds maximum alternative count".into(),
            ));
        }
        let alt_trimmed = alt.trim();
        if alt_trimmed.is_empty() {
            return Err(IntelError::InvalidRecord(
                "empty alternative in version_range".into(),
            ));
        }
        match parse_version_clauses(alt_trimmed) {
            Ok(clauses) if !clauses.is_empty() => {
                valid_semver_alts = valid_semver_alts.saturating_add(1);
            }
            Ok(_) => {
                return Err(IntelError::InvalidRecord(
                    "empty clause list in version_range".into(),
                ));
            }
            Err(_) if non_semver_eq_token(alt_trimmed).is_some() => {}
            Err(_) => {
                return Err(IntelError::InvalidRecord(
                    "invalid clause in version_range".into(),
                ));
            }
        }
    }
    if valid_semver_alts == 0 {
        return Err(IntelError::InvalidRecord(
            "version_range must contain at least one valid SemVer alternative".into(),
        ));
    }
    Ok(())
}

#[must_use]
pub(crate) fn is_unbounded_all_versions_range(range_expr: &str) -> bool {
    if range_expr.len() > MAX_RANGE_BYTES || range_expr.chars().any(char::is_control) {
        return false;
    }
    for alt in range_expr.split("||").take(MAX_RANGE_ALTERNATIVES) {
        let trimmed = alt.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(clauses) = parse_version_clauses(trimmed) else {
            continue;
        };
        if let [clause] = clauses.as_slice()
            && clause.op == BoundOp::Ge
            && clause.version.major == 0
            && clause.version.minor == 0
            && clause.version.patch == 0
            && clause.version.prerelease.as_slice() == [PreIdent::Numeric(0)]
        {
            return true;
        }
    }
    false
}

pub(crate) fn extract_osv_versions_range(affected: &Value) -> Result<Option<String>, IntelError> {
    let mut alternatives = Vec::new();
    if let Some(ranges) = affected.get("ranges").and_then(Value::as_array) {
        if ranges.len() > MAX_OSV_RANGES {
            return Err(IntelError::CodecParse(
                "OSV ranges array exceeds bound".into(),
            ));
        }
        for range in ranges {
            let rtype = range.get("type").and_then(Value::as_str).unwrap_or("");
            if !matches!(rtype, "SEMVER" | "ECOSYSTEM" | "") {
                continue;
            }
            if let Some(events) = range.get("events").and_then(Value::as_array) {
                collect_range_events(events, &mut alternatives)?;
            }
        }
    }
    if let Some(versions) = affected.get("versions").and_then(Value::as_array) {
        if versions.len() > MAX_RANGE_ALTERNATIVES {
            return Err(IntelError::CodecParse(
                "OSV versions array exceeds bound".into(),
            ));
        }
        for v in versions {
            let raw_v = v.as_str().ok_or_else(|| {
                IntelError::CodecParse("OSV version entry must be a string".into())
            })?;
            let clean = validate_osv_version_token(raw_v)?;
            push_range_alt(&mut alternatives, format!("=={clean}"))?;
        }
    }
    Ok((!alternatives.is_empty()).then(|| alternatives.join(" || ")))
}

fn collect_range_events(
    events: &[Value],
    alternatives: &mut Vec<String>,
) -> Result<(), IntelError> {
    if events.len() > MAX_OSV_EVENTS_PER_RANGE {
        return Err(IntelError::CodecParse(
            "OSV range events array exceeds bound".into(),
        ));
    }
    let mut current_intro: Option<String> = None;
    for ev in events {
        if let Some(intro) = ev.get("introduced").and_then(Value::as_str) {
            let clean_intro = validate_osv_version_token(intro)?;
            if let Some(prev_intro) = current_intro.take() {
                push_range_alt(alternatives, format_intro_bound(&prev_intro))?;
            }
            current_intro = Some(clean_intro.to_owned());
        } else if let Some(fixed) = ev.get("fixed").and_then(Value::as_str) {
            let clean_fixed = validate_osv_version_token(fixed)?;
            if let Some(intro) = current_intro.take() {
                push_range_alt(
                    alternatives,
                    format!("{}, <{clean_fixed}", format_intro_bound(&intro)),
                )?;
            }
        } else if let Some(last) = ev.get("last_affected").and_then(Value::as_str) {
            let clean_last = validate_osv_version_token(last)?;
            if let Some(intro) = current_intro.take() {
                push_range_alt(
                    alternatives,
                    format!("{}, <={clean_last}", format_intro_bound(&intro)),
                )?;
            }
        }
    }
    if let Some(intro) = current_intro {
        push_range_alt(alternatives, format_intro_bound(&intro))?;
    }
    Ok(())
}

fn push_range_alt(alternatives: &mut Vec<String>, alt: String) -> Result<(), IntelError> {
    if alternatives.len() >= MAX_RANGE_ALTERNATIVES {
        return Err(IntelError::CodecParse(
            "OSV range alternatives exceed bound".into(),
        ));
    }
    alternatives.push(alt);
    Ok(())
}

fn validate_osv_version_token(raw: &str) -> Result<&str, IntelError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || raw != trimmed
        || raw.len() > MAX_VERSION_TOKEN_BYTES
        || raw.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(c, ',' | '|' | '<' | '>' | '=' | '!' | '~' | '^')
        })
    {
        return Err(IntelError::CodecParse("invalid OSV version token".into()));
    }
    Ok(trimmed)
}

fn format_intro_bound(intro: &str) -> String {
    if intro.trim() == "0" {
        ">=0.0.0-0".to_owned()
    } else {
        format!(">={}", intro.trim())
    }
}

fn compare_prereleases(a: &[PreIdent], b: &[PreIdent]) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => a
            .iter()
            .zip(b.iter())
            .find_map(|(ia, ib)| {
                let ord = ia.cmp(ib);
                (ord != Ordering::Equal).then_some(ord)
            })
            .unwrap_or_else(|| a.len().cmp(&b.len())),
    }
}

fn parse_numeric_part(part: &str) -> Result<u64, IntelError> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(IntelError::CodecParse(
            "invalid numeric version component".into(),
        ));
    }
    part.parse::<u64>()
        .map_err(|_| IntelError::CodecParse("version number overflow".into()))
}

fn non_semver_eq_token(alt_trimmed: &str) -> Option<&str> {
    if alt_trimmed.contains(',') || alt_trimmed.contains('|') {
        return None;
    }
    let token = alt_trimmed.strip_prefix("==")?.trim();
    if token.is_empty()
        || token.len() > MAX_VERSION_TOKEN_BYTES
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
    {
        return None;
    }
    Some(token)
}

fn find_hyphen_range_bounds(part: &str) -> Option<(&str, &str)> {
    let bytes = part.as_bytes();
    for (idx, ch) in part.char_indices() {
        if ch != '-' {
            continue;
        }
        let prev_ws = idx
            .checked_sub(1)
            .and_then(|p| bytes.get(p))
            .is_some_and(u8::is_ascii_whitespace);
        let next_ws = bytes
            .get(idx.saturating_add(1))
            .is_some_and(u8::is_ascii_whitespace);
        if prev_ws && next_ws {
            let left = part.get(..idx)?.trim();
            let right = part.get(idx.saturating_add(1)..)?.trim();
            if left.is_empty() || right.is_empty() {
                return None;
            }
            return Some((left, right));
        }
    }
    None
}

fn parse_version_clauses(expr: &str) -> Result<Vec<VersionClause>, IntelError> {
    let mut clauses = Vec::new();
    for raw_part in expr.split(',') {
        if clauses.len() >= MAX_CLAUSES_PER_ALT {
            return Err(IntelError::CodecParse(
                "version alternative exceeds clause count bound".into(),
            ));
        }
        let part = raw_part.trim();
        if part.is_empty() {
            return Err(IntelError::CodecParse("empty version clause".into()));
        }
        if part.starts_with("!=") || part.starts_with("~=") || part.starts_with('^') {
            return Err(IntelError::CodecParse(
                "unsupported version operator".into(),
            ));
        }
        if !part.starts_with(['>', '<', '='])
            && let Some((left, right)) = find_hyphen_range_bounds(part)
        {
            if find_hyphen_range_bounds(right).is_some()
                || clauses.len().saturating_add(2) > MAX_CLAUSES_PER_ALT
            {
                return Err(IntelError::CodecParse(
                    "invalid or oversized hyphen range".into(),
                ));
            }
            clauses.push(VersionClause {
                op: BoundOp::Ge,
                version: SemVerTuple::parse(left)?,
            });
            clauses.push(VersionClause {
                op: BoundOp::Le,
                version: SemVerTuple::parse(right)?,
            });
            continue;
        }
        let (op, rest) = if let Some(r) = part.strip_prefix(">=") {
            (BoundOp::Ge, r)
        } else if let Some(r) = part.strip_prefix("<=") {
            (BoundOp::Le, r)
        } else if let Some(r) = part.strip_prefix("==") {
            (BoundOp::Eq, r)
        } else if let Some(r) = part.strip_prefix('>') {
            (BoundOp::Gt, r)
        } else if let Some(r) = part.strip_prefix('<') {
            (BoundOp::Lt, r)
        } else if let Some(r) = part.strip_prefix('=') {
            (BoundOp::Eq, r)
        } else {
            (BoundOp::Eq, part)
        };
        clauses.push(VersionClause {
            op,
            version: SemVerTuple::parse(rest)?,
        });
    }
    Ok(clauses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round6_version_in_vulnerable_range_matches_non_semver_exact_alternatives() {
        assert!(version_in_vulnerable_range(
            "1.0.2.post1",
            "==1.0.0 || ==1.0.2.post1"
        ));
        assert!(version_in_vulnerable_range(
            "1.0.0",
            "==1.0.0 || ==1.0.2.post1"
        ));
        assert!(version_in_vulnerable_range(
            "1.0.2.post1",
            "== 1.0.2.post1 || >=2.0.0"
        ));
        assert!(!version_in_vulnerable_range(
            "1.0.3.post1",
            "==1.0.0 || ==1.0.2.post1"
        ));
        assert!(!version_in_vulnerable_range(
            "1.0.2.post1",
            "==1.0.2.post1, !=1.0.2.post1"
        ));
        assert!(!version_in_vulnerable_range("", "==1.0.0 || =="));
        assert!(!version_in_vulnerable_range(
            "1.0.2.post1\n",
            "==1.0.2.post1"
        ));
        assert!(!version_in_vulnerable_range("not-a-ver", ">=1.0.0"));
    }

    #[test]
    fn round7_case_insensitive_prerelease_and_non_semver_versions() {
        assert!(version_in_vulnerable_range(
            "1.0.0.final",
            "==1.0.0 || ==1.0.0.Final"
        ));
        assert!(version_in_vulnerable_range(
            "1.0.2.post1",
            "==1.0.0 || ==1.0.2.POST1"
        ));
        assert!(version_in_vulnerable_range("1.0.0-rc1", "==1.0.0-RC1"));
        assert!(version_in_vulnerable_range(
            "1.0.0-rc1",
            ">=1.0.0-RC1, <1.0.0-RC2"
        ));
        assert!(!version_in_vulnerable_range(
            "1.0.0-rc2",
            ">=1.0.0-RC1, <1.0.0-RC2"
        ));
    }
}
