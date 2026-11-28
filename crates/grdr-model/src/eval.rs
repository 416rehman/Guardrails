// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use jiff::Timestamp;

use crate::api::TrustedKeyInfo;
use crate::domain::{ActionClass, SignatureStatus};
use crate::policy::PolicyPack;
use crate::signing::verify_pack;

use serde::{Deserialize, Serialize};

pub use crate::eval_rules::essentials_rules;
pub use grdr_crypto::{SigningKeypair, sha256_hex};

const PACK_ESSENTIALS_ID: &str = "pack-essentials-slice0";
const PACK_ESSENTIALS_VERSION: &str = "1.0.0";
const MAX_HOLD_DEADLINE_MS: u64 = 30_000;
pub const MAX_POLICY_PACK_JSON_BYTES: usize = 1024 * 1024;
const EMBEDDED_ESSENTIALS_MANIFEST_TOML: &str = include_str!("../../../packs/essentials/pack.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationKind {
    Receipt,
    Expect,
    Snapshot,
    PinRecorder,
    NotifyUser,
    NotifySponsor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformKind {
    RedactSecrets,
    WrapLauncher,
    SwapCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheScope {
    Bundle,
    Session,
    Call,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayBucket {
    Matched,
    AlmostMatched,
    NotMatched,
    NotEvaluable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FourBucketSummary {
    pub matched: u64,
    pub almost_matched: u64,
    pub not_matched: u64,
    pub not_evaluable: u64,
    pub watch_days: u32,
    pub median_prompts_per_dev_day: u32,
    pub p95_prompts_per_dev_day: u32,
    pub promotion_ready: bool,
}

pub fn essentials_manifest_toml() -> &'static str {
    EMBEDDED_ESSENTIALS_MANIFEST_TOML
}

pub fn parse_policy_pack_json(raw: &str) -> Result<PolicyPack, crate::CodedError> {
    if raw.trim().is_empty() || raw.len() > MAX_POLICY_PACK_JSON_BYTES {
        return Err(crate::CodedError::new(
            crate::CODE_INVALID_INPUT,
            format!(
                "PolicyPack JSON size {} is outside allowed bounds (1..={MAX_POLICY_PACK_JSON_BYTES} bytes)",
                raw.len()
            ),
            "Provide a bounded PolicyPack JSON payload within size limits.",
        ));
    }
    let pack: PolicyPack = serde_json::from_str(raw).map_err(|err| {
        crate::CodedError::new(
            crate::CODE_INVALID_INPUT,
            format!("invalid PolicyPack JSON: {err}"),
            "Provide a signed or valid PolicyPack JSON payload from packs/.",
        )
    })?;
    validate_policy_pack_structure(&pack)?;
    Ok(pack)
}

pub fn parse_verified_policy_pack_json(
    raw: &str,
    trusted_keys: &[TrustedKeyInfo],
) -> Result<PolicyPack, crate::CodedError> {
    let pack = parse_policy_pack_json(raw)?;
    if verify_pack(&pack, trusted_keys) != SignatureStatus::Verified {
        return Err(crate::CodedError::new(
            crate::CODE_INVALID_INPUT,
            format!(
                "PolicyPack `{}` failed Ed25519 signature verification",
                pack.id
            ),
            "Sign the PolicyPack with a trusted policy-signing key.",
        ));
    }
    Ok(pack)
}

fn validate_policy_pack_structure(pack: &PolicyPack) -> Result<(), crate::CodedError> {
    for (field, val) in [
        ("id", pack.id.as_str()),
        ("name", pack.name.as_str()),
        ("version", pack.version.as_str()),
        ("channel", pack.channel.as_str()),
    ] {
        if val.trim().is_empty() {
            return Err(crate::CodedError::new(
                crate::CODE_INVALID_INPUT,
                format!("PolicyPack field `{field}` must not be empty"),
                "Populate required PolicyPack metadata fields.",
            ));
        }
    }
    match (pack.key_id.as_deref(), pack.signature.as_deref()) {
        (Some(k), Some(s)) if !k.trim().is_empty() && !s.trim().is_empty() => {}
        (None, None) => {}
        _ => {
            return Err(crate::CodedError::new(
                crate::CODE_INVALID_INPUT,
                "PolicyPack `key_id` and `signature` must both be omitted or non-empty",
                "Provide both non-empty `key_id` and `signature` or omit both.",
            ));
        }
    }
    let mut seen_ids = BTreeSet::new();
    for rule in &pack.rules {
        if rule.id.trim().is_empty() || !seen_ids.insert(rule.id.as_str()) {
            return Err(crate::CodedError::new(
                crate::CODE_INVALID_INPUT,
                format!("invalid or duplicate PolicyRule id `{}`", rule.id),
                "Assign a unique non-empty id to every rule in PolicyPack.",
            ));
        }
    }
    Ok(())
}

/// Legacy transitional slice-0 pack preserved until Post-Wave callers load packs purely from signed store (#133).
pub fn essentials_pack() -> PolicyPack {
    PolicyPack {
        id: PACK_ESSENTIALS_ID.into(),
        name: "Essentials".into(),
        description:
            "Baseline protections for control files, credentials, destructive actions, and egress."
                .into(),
        version: PACK_ESSENTIALS_VERSION.into(),
        channel: "schema-policy".into(),
        rules: essentials_rules(),
        key_id: None,
        signature: None,
    }
}

pub fn add_seconds(ts: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_second(ts.as_second().saturating_add(seconds)).unwrap_or(ts)
}

pub fn is_essentials_rule_id(rule_id: &str) -> bool {
    rule_id.starts_with("essentials.") || rule_id.starts_with("system.")
}

/// Floors the hold deadline to 80% of the host timeout and bounds by both ceiling and requested duration.
pub fn capped_hold_deadline_ms(host_deadline_ms: u64, requested_ms: u64) -> u64 {
    (host_deadline_ms.saturating_mul(4) / 5)
        .min(MAX_HOLD_DEADLINE_MS)
        .min(requested_ms)
}

/// Evaluates whether a Watch rule meets the 7-day replay promotion gate against developer prompt budgets.
pub fn promotion_gate_passes(
    watched_days: u32,
    median_prompts: u32,
    p95_prompts: u32,
    median_limit: u32,
    p95_limit: u32,
) -> bool {
    watched_days >= 7 && median_prompts <= median_limit && p95_prompts <= p95_limit
}

fn split_lexical_root(slash: &str) -> Option<(String, &str)> {
    if let Some(unc_tail) = slash.strip_prefix("//") {
        let (srv, after_srv) = unc_tail.split_once('/')?;
        if srv.is_empty() {
            return None;
        }
        let (share, rest) = match after_srv.split_once('/') {
            Some((s, r)) => (s, r),
            None => (after_srv, ""),
        };
        if share.is_empty() {
            return None;
        }
        if srv == "?" && share.eq_ignore_ascii_case("UNC") {
            let (u_srv, after_u_srv) = rest.split_once('/')?;
            let (u_share, u_rest) = match after_u_srv.split_once('/') {
                Some((s, r)) => (s, r),
                None => (after_u_srv, ""),
            };
            if u_srv.is_empty() || u_share.is_empty() {
                return None;
            }
            return Some((format!("//{srv}/{share}/{u_srv}/{u_share}/"), u_rest));
        }
        return Some((format!("//{srv}/{share}/"), rest));
    }
    if let Some(rest) = slash.strip_prefix('/') {
        return Some(("/".into(), rest));
    }
    if let Some(rest) = slash.strip_prefix("~/") {
        return Some(("~/".into(), rest));
    }
    if slash == "~" {
        return Some(("~/".into(), ""));
    }
    if slash.starts_with('~') {
        let (user, rest) = slash.split_once('/').unwrap_or((slash, ""));
        return Some((format!("{user}/"), rest));
    }
    let mut chars = slash.chars();
    if let (Some(drive), Some(':')) = (chars.next(), chars.next())
        && drive.is_ascii_alphabetic()
    {
        let root_len = if chars.next() == Some('/') { 3 } else { 2 };
        if let (Some(root), Some(rest)) = (slash.get(..root_len), slash.get(root_len..)) {
            return Some((root.to_owned(), rest));
        }
    }
    Some((String::new(), slash))
}

pub(crate) fn normalize_lexical_grant_path(path: &str) -> Option<String> {
    let slash = path.replace('\\', "/");
    let (root, body) = split_lexical_root(&slash)?;
    let mut parts: Vec<&str> = Vec::new();
    for seg in body.split('/') {
        if seg == ".." {
            if parts.is_empty() {
                return None;
            }
            let _ = parts.pop();
        } else if !seg.is_empty() && seg != "." {
            parts.push(seg);
        }
    }
    let joined = parts.join("/");
    Some(format!("{root}{joined}"))
}

fn has_url_traversal(url_lower: &str) -> bool {
    let authority_end = url_lower.find("://").map_or(0, |i| i.saturating_add(3));
    let tail = url_lower.get(authority_end..).unwrap_or("");
    let path_only = tail.split(['?', '#']).next().unwrap_or("");
    let path_start = path_only
        .find('/')
        .and_then(|i| path_only.get(i..))
        .unwrap_or("");
    path_start
        .split('/')
        .any(|seg| matches!(seg, ".." | "%2e%2e" | ".%2e" | "%2e."))
}

pub(crate) fn target_pattern_matches(
    action_class: ActionClass,
    pattern: &str,
    target: &str,
) -> bool {
    if pattern == "*" {
        return true;
    }
    if matches!(
        action_class,
        ActionClass::FileRead
            | ActionClass::FileWrite
            | ActionClass::FileDelete
            | ActionClass::ConfigChange
    ) {
        let (Some(np), Some(nt)) = (
            normalize_lexical_grant_path(pattern.trim()),
            normalize_lexical_grant_path(target.trim()),
        ) else {
            return false;
        };
        let trimmed = np.trim_end_matches('/');
        return nt == np
            || (!trimmed.is_empty()
                && nt.strip_prefix(trimmed).is_some_and(|r| r.starts_with('/')));
    }
    if matches!(
        action_class,
        ActionClass::NetRequest | ActionClass::NetConnect
    ) {
        let p = pattern.trim().trim_end_matches('/').to_ascii_lowercase();
        let t = target.trim().trim_end_matches('/').to_ascii_lowercase();
        if p.is_empty() || p.ends_with(':') || has_url_traversal(&t) {
            return false;
        }
        return t == p
            || t.strip_prefix(&p)
                .is_some_and(|r| r.starts_with('/') || r.starts_with('?'));
    }
    pattern.trim() == target.trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn essentials_pack_ships_seven_cedar_rules() {
        let pack = essentials_pack();
        assert_eq!(pack.rules.len(), 7);
        for rule in &pack.rules {
            let cedar = rule.cedar.as_deref().unwrap_or("");
            assert!(
                cedar.contains("forbid"),
                "rule {} missing Cedar forbid policy",
                rule.id
            );
        }
    }

    #[test]
    fn capped_hold_floors_by_five_and_promotion_gate_enforces_seven_days() {
        assert_eq!(capped_hold_deadline_ms(6, 100), 4);
        assert_eq!(capped_hold_deadline_ms(1, 100), 0);
        assert_eq!(
            capped_hold_deadline_ms(u64::MAX, 50_000),
            MAX_HOLD_DEADLINE_MS
        );
        assert!(!promotion_gate_passes(6, 1, 2, 3, 8));
        assert!(promotion_gate_passes(7, 3, 8, 3, 8));
        assert!(!promotion_gate_passes(7, 4, 8, 3, 8));
    }

    #[test]
    fn parse_policy_pack_json_enforces_schema_bounds_and_signatures() {
        use crate::domain::Mode;
        use crate::signing::SigningKeypairExt as _;

        let mut pack = essentials_pack();
        let unsigned_json = serde_json::to_string(&pack).unwrap();
        let parsed = parse_policy_pack_json(&unsigned_json).unwrap();
        assert_eq!(parsed.id, pack.id);

        assert!(parse_policy_pack_json("").is_err());
        let oversized = " ".repeat(MAX_POLICY_PACK_JSON_BYTES + 1);
        assert!(parse_policy_pack_json(&oversized).is_err());

        let mut with_unknown: serde_json::Value = serde_json::from_str(&unsigned_json).unwrap();
        with_unknown["unexpected_extra"] = serde_json::json!(true);
        assert!(parse_policy_pack_json(&with_unknown.to_string()).is_err());

        let mut empty_id: serde_json::Value = serde_json::from_str(&unsigned_json).unwrap();
        empty_id["id"] = serde_json::json!("  ");
        assert!(parse_policy_pack_json(&empty_id.to_string()).is_err());

        let mut half_signed: serde_json::Value = serde_json::from_str(&unsigned_json).unwrap();
        half_signed["key_id"] = serde_json::json!("key-1");
        assert!(parse_policy_pack_json(&half_signed.to_string()).is_err());

        let kp = SigningKeypair::generate().unwrap();
        let keys = vec![kp.public_info()];
        assert!(parse_verified_policy_pack_json(&unsigned_json, &keys).is_err());

        kp.sign_pack(&mut pack).unwrap();
        let signed_json = serde_json::to_string(&pack).unwrap();
        let verified = parse_verified_policy_pack_json(&signed_json, &keys).unwrap();
        assert_eq!(verified.rules.len(), 7);

        let mut tampered: PolicyPack = parse_policy_pack_json(&signed_json).unwrap();
        tampered.rules[0].mode = Mode::Off;
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        assert!(parse_verified_policy_pack_json(&tampered_json, &keys).is_err());
    }
}
