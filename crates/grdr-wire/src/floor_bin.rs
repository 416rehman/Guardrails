// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Compact signed binary floor table (`GRDRFLT1`) shared between daemon compiler
//! and fail-safe hook fallback without `serde_json` (`docs/design/11`, `docs/design/07`).

use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_fastpath::{FLOOR_FORMAT_MAGIC, FLOOR_FORMAT_VERSION, FastActionClass, FastVerdict};
use thiserror::Error;

use crate::floor_cursor::{
    Cursor, MAX_AGENTS_PER_RULE, MAX_PATTERN_LEN, MAX_RULE_ID_LEN, ascii_contains_icase,
    ascii_starts_with_icase, decode_floor_rule,
};

const FLOOR_SIG_DOMAIN: &str = "grdr.floor.v1\0";
pub const MAX_FLOOR_BYTES: usize = 64 * 1024;
pub const MAX_FLOOR_RULES: usize = 512;
const MAX_SIG_B64_LEN: usize = 256;
const MIN_RULE_WIRE_LEN: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FloorBinError {
    #[error("GRDR-WIRE-0026: floor table truncated at offset {offset}")]
    Truncated { offset: usize },
    #[error("GRDR-WIRE-0027: invalid floor table magic or version")]
    InvalidHeader,
    #[error("GRDR-WIRE-0028: floor table rule count {count} exceeds maximum {max}")]
    TooManyRules { count: usize, max: usize },
    #[error("GRDR-WIRE-0029: floor table string or signature field malformed: {detail}")]
    MalformedField { detail: String },
    #[error("GRDR-WIRE-0030: floor table signature rejected or key untrusted")]
    UntrustedSignature,
    #[error("GRDR-WIRE-0031: floor table expired at {expires_at_unix_s} (now {now_unix_s})")]
    Expired {
        expires_at_unix_s: i64,
        now_unix_s: i64,
    },
    #[error("GRDR-WIRE-0033: floor table size {len} exceeds maximum {max} bytes")]
    TableTooLarge { len: usize, max: usize },
    #[error("GRDR-WIRE-0034: trusted floor key set cannot be empty")]
    EmptyTrustedKeys,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloorTableFreshness {
    Fresh,
    Stale { expired_at_unix_s: i64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFloorTable {
    pub document: FloorTableDocument,
    pub freshness: FloorTableFreshness,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FloorMatchKind {
    #[default]
    Contains = 0,
    Prefix = 1,
    Any = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloorRuleRecord {
    pub action_class: FastActionClass,
    pub verdict: FastVerdict,
    pub match_kind: FloorMatchKind,
    pub rule_id: String,
    pub pattern: String,
    pub agents: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloorTableDocument {
    pub epoch: u64,
    pub expires_at_unix_s: i64,
    pub signer_key_id: String,
    pub rules: Vec<FloorRuleRecord>,
}

impl FloorBinError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Truncated { .. } => "GRDR-WIRE-0026",
            Self::InvalidHeader => "GRDR-WIRE-0027",
            Self::TooManyRules { .. } => "GRDR-WIRE-0028",
            Self::MalformedField { .. } => "GRDR-WIRE-0029",
            Self::UntrustedSignature => "GRDR-WIRE-0030",
            Self::Expired { .. } => "GRDR-WIRE-0031",
            Self::TableTooLarge { .. } => "GRDR-WIRE-0033",
            Self::EmptyTrustedKeys => "GRDR-WIRE-0034",
        }
    }
}

impl FloorRuleRecord {
    #[must_use]
    pub fn matches(&self, action: FastActionClass, agent: &str, target: &str) -> bool {
        if self.action_class != action {
            return false;
        }
        if !self.agents.is_empty()
            && !self
                .agents
                .iter()
                .any(|pat| pat.eq_ignore_ascii_case(agent))
        {
            return false;
        }
        match self.match_kind {
            FloorMatchKind::Any => true,
            FloorMatchKind::Contains => ascii_contains_icase(target, &self.pattern),
            FloorMatchKind::Prefix => ascii_starts_with_icase(target, &self.pattern),
        }
    }
}

#[must_use]
pub const fn floor_verdict_rank(verdict: FastVerdict) -> u8 {
    match verdict {
        FastVerdict::Allow => 0,
        FastVerdict::StepUp => 1,
        FastVerdict::Deny => 2,
    }
}

pub fn encode_signed_floor_table(
    doc: &FloorTableDocument,
    signing_key: &SigningKeypair,
) -> Result<Vec<u8>, FloorBinError> {
    if doc.rules.len() > MAX_FLOOR_RULES {
        return Err(FloorBinError::TooManyRules {
            count: doc.rules.len(),
            max: MAX_FLOOR_RULES,
        });
    }
    if doc.signer_key_id.is_empty()
        || doc.signer_key_id.len() > MAX_RULE_ID_LEN
        || doc.signer_key_id.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err(FloorBinError::MalformedField {
            detail: "signer_key_id must be 1..=256 bytes without whitespace".to_string(),
        });
    }
    if doc.signer_key_id != signing_key.key_id() {
        return Err(FloorBinError::MalformedField {
            detail: "signer_key_id must match signing key".to_string(),
        });
    }
    let key_id_len =
        u16::try_from(doc.signer_key_id.len()).map_err(|_| FloorBinError::MalformedField {
            detail: "signer_key_id too long".to_string(),
        })?;

    let mut body = Vec::new();
    body.extend_from_slice(FLOOR_FORMAT_MAGIC);
    body.extend_from_slice(&FLOOR_FORMAT_VERSION.to_le_bytes());
    body.extend_from_slice(&doc.epoch.to_le_bytes());
    body.extend_from_slice(&doc.expires_at_unix_s.to_le_bytes());
    body.extend_from_slice(&key_id_len.to_le_bytes());
    body.extend_from_slice(doc.signer_key_id.as_bytes());
    let rule_count = u32::try_from(doc.rules.len()).map_err(|_| FloorBinError::TooManyRules {
        count: doc.rules.len(),
        max: MAX_FLOOR_RULES,
    })?;
    body.extend_from_slice(&rule_count.to_le_bytes());

    for rule in &doc.rules {
        encode_floor_rule(&mut body, rule)?;
    }

    let sig_b64 = signing_key.sign_bytes(FLOOR_SIG_DOMAIN, &body);
    let sig_len = u16::try_from(sig_b64.len()).map_err(|_| FloorBinError::MalformedField {
        detail: "signature length overflow".to_string(),
    })?;
    body.extend_from_slice(&sig_len.to_le_bytes());
    body.extend_from_slice(sig_b64.as_bytes());
    if body.len() > MAX_FLOOR_BYTES {
        return Err(FloorBinError::TableTooLarge {
            len: body.len(),
            max: MAX_FLOOR_BYTES,
        });
    }
    Ok(body)
}

fn encode_floor_rule(body: &mut Vec<u8>, rule: &FloorRuleRecord) -> Result<(), FloorBinError> {
    let pattern_ok = match rule.match_kind {
        FloorMatchKind::Any => rule.pattern.is_empty(),
        FloorMatchKind::Contains | FloorMatchKind::Prefix => {
            !rule.pattern.is_empty() && rule.pattern.len() <= MAX_PATTERN_LEN
        }
    };
    if rule.rule_id.is_empty()
        || rule.rule_id.len() > MAX_RULE_ID_LEN
        || !pattern_ok
        || rule.agents.len() > MAX_AGENTS_PER_RULE
        || rule.agents.iter().any(|agent| {
            agent.is_empty()
                || agent.len() > MAX_RULE_ID_LEN
                || agent.bytes().any(|b| b.is_ascii_whitespace())
        })
    {
        return Err(FloorBinError::MalformedField {
            detail: "floor rule id, pattern, or agents malformed or exceeds bound".to_string(),
        });
    }
    let id_len = u16::try_from(rule.rule_id.len()).map_err(|_| FloorBinError::MalformedField {
        detail: "rule_id length overflow".to_string(),
    })?;
    let pat_len = u16::try_from(rule.pattern.len()).map_err(|_| FloorBinError::MalformedField {
        detail: "pattern length overflow".to_string(),
    })?;
    let agent_count =
        u16::try_from(rule.agents.len()).map_err(|_| FloorBinError::MalformedField {
            detail: "agent count overflow".to_string(),
        })?;
    body.push(rule.action_class as u8);
    body.push(rule.verdict as u8);
    body.push(rule.match_kind as u8);
    body.extend_from_slice(&id_len.to_le_bytes());
    body.extend_from_slice(rule.rule_id.as_bytes());
    body.extend_from_slice(&pat_len.to_le_bytes());
    body.extend_from_slice(rule.pattern.as_bytes());
    body.extend_from_slice(&agent_count.to_le_bytes());
    for agent in &rule.agents {
        let agent_len = u16::try_from(agent.len()).map_err(|_| FloorBinError::MalformedField {
            detail: "agent length overflow".to_string(),
        })?;
        body.extend_from_slice(&agent_len.to_le_bytes());
        body.extend_from_slice(agent.as_bytes());
    }
    Ok(())
}

/// Verifies Ed25519 signature over the bounded `GRDRFLT1` floor table before checking expiry.
/// Validly signed expired tables (or wall clock <= 0) return `FloorTableFreshness::Stale` per D-37.
pub fn verify_and_decode_floor_table(
    bytes: &[u8],
    trusted_pubkeys_b64: &[(&str, &str)],
    now_unix_s: i64,
) -> Result<VerifiedFloorTable, FloorBinError> {
    if bytes.len() > MAX_FLOOR_BYTES {
        return Err(FloorBinError::TableTooLarge {
            len: bytes.len(),
            max: MAX_FLOOR_BYTES,
        });
    }
    if trusted_pubkeys_b64.is_empty() {
        return Err(FloorBinError::EmptyTrustedKeys);
    }

    let mut cursor = Cursor::new(bytes);
    let magic = cursor.take(FLOOR_FORMAT_MAGIC.len())?;
    if magic != FLOOR_FORMAT_MAGIC {
        return Err(FloorBinError::InvalidHeader);
    }
    let version = cursor.read_u32_le()?;
    if version != FLOOR_FORMAT_VERSION {
        return Err(FloorBinError::InvalidHeader);
    }
    let epoch = cursor.read_u64_le()?;
    let expires_at_unix_s = cursor.read_i64_le()?;
    let signer_key_id = cursor.read_nonempty_string(MAX_RULE_ID_LEN, false)?;
    let rule_count =
        usize::try_from(cursor.read_u32_le()?).map_err(|_| FloorBinError::TooManyRules {
            count: usize::MAX,
            max: MAX_FLOOR_RULES,
        })?;
    if rule_count > MAX_FLOOR_RULES {
        return Err(FloorBinError::TooManyRules {
            count: rule_count,
            max: MAX_FLOOR_RULES,
        });
    }
    let min_rule_bytes =
        rule_count
            .checked_mul(MIN_RULE_WIRE_LEN)
            .ok_or(FloorBinError::TooManyRules {
                count: rule_count,
                max: MAX_FLOOR_RULES,
            })?;
    if cursor.remaining() < min_rule_bytes {
        return Err(FloorBinError::Truncated {
            offset: cursor.offset,
        });
    }

    let mut rules = Vec::with_capacity(rule_count);
    for _ in 0..rule_count {
        rules.push(decode_floor_rule(&mut cursor)?);
    }
    let body_end = cursor.offset;
    let sig_b64 = cursor.read_nonempty_string(MAX_SIG_B64_LEN, false)?;
    if cursor.offset != bytes.len() {
        return Err(FloorBinError::MalformedField {
            detail: "trailing bytes after floor table signature".to_string(),
        });
    }

    let body = bytes.get(..body_end).ok_or(FloorBinError::InvalidHeader)?;
    let verified = trusted_pubkeys_b64
        .iter()
        .filter(|(id, _)| *id == signer_key_id)
        .any(|(_, pubkey)| verify_bytes(pubkey, FLOOR_SIG_DOMAIN, body, &sig_b64).is_ok());
    if !verified {
        return Err(FloorBinError::UntrustedSignature);
    }

    let freshness = if now_unix_s <= 0 || expires_at_unix_s <= now_unix_s {
        FloorTableFreshness::Stale {
            expired_at_unix_s: expires_at_unix_s,
        }
    } else {
        FloorTableFreshness::Fresh
    };

    Ok(VerifiedFloorTable {
        document: FloorTableDocument {
            epoch,
            expires_at_unix_s,
            signer_key_id,
            rules,
        },
        freshness,
    })
}

pub fn verify_and_decode_fresh_floor_table(
    bytes: &[u8],
    trusted_pubkeys_b64: &[(&str, &str)],
    now_unix_s: i64,
) -> Result<FloorTableDocument, FloorBinError> {
    let verified = verify_and_decode_floor_table(bytes, trusted_pubkeys_b64, now_unix_s)?;
    match verified.freshness {
        FloorTableFreshness::Fresh => Ok(verified.document),
        FloorTableFreshness::Stale { expired_at_unix_s } => Err(FloorBinError::Expired {
            expires_at_unix_s: expired_at_unix_s,
            now_unix_s,
        }),
    }
}
