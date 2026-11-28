// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Compact zero-alloc `#![no_std]` binary floor table reader and evaluator.

use core::str;

use crate::{
    FLOOR_FORMAT_MAGIC, FLOOR_FORMAT_VERSION, FastActionClass, FastVerdict, contains_norm_icase,
    eq_ascii_icase, starts_with_norm_icase,
};

pub const BINARY_HEADER_LEN: usize = 32;
pub const BINARY_RULE_LEN: usize = 24;
pub const BINARY_SLICE_DESC_LEN: usize = 4;
pub const MAX_BINARY_RULES: usize = 256;
pub const MAX_BINARY_SLICES: usize = 2048;

pub const PRINCIPAL_SESSION: u16 = 1 << 0;
pub const PRINCIPAL_PROCESS: u16 = 1 << 1;

pub const LABEL_CREDENTIAL_ACCESSED: u16 = 1 << 0;
pub const LABEL_UNTRUSTED_WEB: u16 = 1 << 1;
pub const LABEL_REPEATED_DENIALS: u16 = 1 << 2;
pub const LABEL_TAINTED_EXFIL: u16 = 1 << 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastpathError {
    TruncatedHeader,
    InvalidMagic,
    UnsupportedVersion,
    LengthMismatch,
    ChecksumMismatch,
    InvalidTableBounds,
    TooManyRules,
    TooManySlices,
    InvalidVerdict,
    InvalidUtf8,
    BufferTooSmall,
    StringTableOverflow,
    NonZeroReserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryRuleInput<'a> {
    pub rule_id: &'a str,
    pub reason: &'a str,
    pub action_mask: u32,
    pub principal_mask: u16,
    pub label_mask: u16,
    pub verdict: FastVerdict,
    pub agents: &'a [&'a str],
    pub prefixes: &'a [&'a str],
    pub contains: &'a [&'a str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryFloorHit<'a> {
    pub rule_id: &'a str,
    pub reason: &'a str,
    pub verdict: FastVerdict,
}

#[derive(Debug, Clone, Copy)]
pub struct BinaryFloorTable<'a> {
    bytes: &'a [u8],
    rule_count: u16,
    slice_count: u16,
    string_table_off: usize,
}

#[derive(Debug, Clone, Copy)]
struct DecodedRule {
    action_mask: u32,
    principal_mask: u16,
    label_mask: u16,
    rule_id_off: u16,
    rule_id_len: u16,
    reason_off: u16,
    reason_len: u16,
    slice_start: u16,
    verdict: FastVerdict,
    agent_count: u8,
    prefix_count: u8,
    contain_count: u8,
}

impl<'a> BinaryFloorTable<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FastpathError> {
        let header = bytes
            .get(..BINARY_HEADER_LEN)
            .ok_or(FastpathError::TruncatedHeader)?;
        if header.get(..8) != Some(FLOOR_FORMAT_MAGIC.as_slice()) {
            return Err(FastpathError::InvalidMagic);
        }
        if read_u32(header, 8)? != FLOOR_FORMAT_VERSION {
            return Err(FastpathError::UnsupportedVersion);
        }
        if read_u32(header, 12)? != 0 {
            return Err(FastpathError::NonZeroReserved);
        }
        let rule_count = read_u16(header, 16)?;
        if usize::from(rule_count) > MAX_BINARY_RULES {
            return Err(FastpathError::TooManyRules);
        }
        let slice_count = read_u16(header, 18)?;
        if usize::from(slice_count) > MAX_BINARY_SLICES {
            return Err(FastpathError::TooManySlices);
        }
        let string_table_off = usize::try_from(read_u32(header, 20)?)
            .map_err(|_| FastpathError::InvalidTableBounds)?;
        let total_len = usize::try_from(read_u32(header, 24)?)
            .map_err(|_| FastpathError::InvalidTableBounds)?;
        if total_len != bytes.len() {
            return Err(FastpathError::LengthMismatch);
        }
        if framing_crc32(bytes) != read_u32(header, 28)? {
            return Err(FastpathError::ChecksumMismatch);
        }

        let rules_bytes = usize::from(rule_count)
            .checked_mul(BINARY_RULE_LEN)
            .ok_or(FastpathError::InvalidTableBounds)?;
        let slices_off = BINARY_HEADER_LEN
            .checked_add(rules_bytes)
            .ok_or(FastpathError::InvalidTableBounds)?;
        let slices_bytes = usize::from(slice_count)
            .checked_mul(BINARY_SLICE_DESC_LEN)
            .ok_or(FastpathError::InvalidTableBounds)?;
        let slices_end = slices_off
            .checked_add(slices_bytes)
            .ok_or(FastpathError::InvalidTableBounds)?;
        if slices_end != string_table_off || string_table_off > total_len {
            return Err(FastpathError::InvalidTableBounds);
        }

        let table = Self {
            bytes,
            rule_count,
            slice_count,
            string_table_off,
        };
        table.validate_all_entries()?;
        Ok(table)
    }

    pub const fn rule_count(&self) -> u16 {
        self.rule_count
    }

    pub fn uses_labels(&self) -> bool {
        for idx in 0..usize::from(self.rule_count) {
            let Ok(rule) = self.read_rule(idx) else {
                return true;
            };
            if rule.label_mask != 0 {
                return true;
            }
        }
        false
    }

    pub fn evaluate(
        &self,
        action: FastActionClass,
        principal_mask: u16,
        active_labels_mask: u16,
        agent: &str,
        target: &str,
    ) -> Option<BinaryFloorHit<'a>> {
        let action_bit = action.bit();
        let mut best: Option<BinaryFloorHit<'a>> = None;
        for idx in 0..usize::from(self.rule_count) {
            let Ok(rule) = self.read_rule(idx) else {
                return Some(corrupt_fail_closed_hit());
            };
            if rule.action_mask != 0 && (rule.action_mask & action_bit) == 0 {
                continue;
            }
            if rule.principal_mask != 0 && (rule.principal_mask & principal_mask) == 0 {
                continue;
            }
            if rule.label_mask != 0 && (active_labels_mask & rule.label_mask) != rule.label_mask {
                continue;
            }
            if !self.matches_agents(&rule, agent) {
                continue;
            }
            let total_matchers =
                usize::from(rule.prefix_count).saturating_add(usize::from(rule.contain_count));
            let matched = total_matchers == 0
                || self.matches_prefixes(&rule, target)
                || self.matches_contains(&rule, target);
            if matched {
                let (Ok(rule_id), Ok(reason)) = (
                    self.read_str(rule.rule_id_off, rule.rule_id_len),
                    self.read_str(rule.reason_off, rule.reason_len),
                ) else {
                    return Some(corrupt_fail_closed_hit());
                };
                let candidate = BinaryFloorHit {
                    rule_id,
                    reason,
                    verdict: rule.verdict,
                };
                if best
                    .as_ref()
                    .is_none_or(|cur| verdict_rank(candidate.verdict) > verdict_rank(cur.verdict))
                {
                    best = Some(candidate);
                }
            }
        }
        best
    }

    fn validate_all_entries(&self) -> Result<(), FastpathError> {
        for idx in 0..usize::from(self.rule_count) {
            let rule = self.read_rule(idx)?;
            let _ = self.read_str(rule.rule_id_off, rule.rule_id_len)?;
            let _ = self.read_str(rule.reason_off, rule.reason_len)?;
            let total_slices = usize::from(rule.agent_count)
                .checked_add(usize::from(rule.prefix_count))
                .and_then(|v| v.checked_add(usize::from(rule.contain_count)))
                .ok_or(FastpathError::InvalidTableBounds)?;
            let end_slice = usize::from(rule.slice_start)
                .checked_add(total_slices)
                .ok_or(FastpathError::InvalidTableBounds)?;
            if end_slice > usize::from(self.slice_count) {
                return Err(FastpathError::InvalidTableBounds);
            }
            for s_idx in usize::from(rule.slice_start)..end_slice {
                let _ = self.read_slice_str(s_idx)?;
            }
        }
        Ok(())
    }

    fn read_rule(&self, idx: usize) -> Result<DecodedRule, FastpathError> {
        let offset = idx
            .checked_mul(BINARY_RULE_LEN)
            .and_then(|v| v.checked_add(BINARY_HEADER_LEN))
            .ok_or(FastpathError::InvalidTableBounds)?;
        let slice = self
            .bytes
            .get(offset..offset.saturating_add(BINARY_RULE_LEN))
            .ok_or(FastpathError::InvalidTableBounds)?;
        let verdict = match *slice.get(18).ok_or(FastpathError::InvalidTableBounds)? {
            0 => FastVerdict::Allow,
            1 => FastVerdict::StepUp,
            2 => FastVerdict::Deny,
            _ => return Err(FastpathError::InvalidVerdict),
        };
        if read_u16(slice, 22)? != 0 {
            return Err(FastpathError::NonZeroReserved);
        }
        Ok(DecodedRule {
            action_mask: read_u32(slice, 0)?,
            principal_mask: read_u16(slice, 4)?,
            label_mask: read_u16(slice, 6)?,
            rule_id_off: read_u16(slice, 8)?,
            rule_id_len: read_u16(slice, 10)?,
            reason_off: read_u16(slice, 12)?,
            reason_len: read_u16(slice, 14)?,
            slice_start: read_u16(slice, 16)?,
            verdict,
            agent_count: *slice.get(19).ok_or(FastpathError::InvalidTableBounds)?,
            prefix_count: *slice.get(20).ok_or(FastpathError::InvalidTableBounds)?,
            contain_count: *slice.get(21).ok_or(FastpathError::InvalidTableBounds)?,
        })
    }

    fn read_slice_str(&self, slice_idx: usize) -> Result<&'a str, FastpathError> {
        let rules_bytes = usize::from(self.rule_count)
            .checked_mul(BINARY_RULE_LEN)
            .ok_or(FastpathError::InvalidTableBounds)?;
        let desc_off = BINARY_HEADER_LEN
            .checked_add(rules_bytes)
            .and_then(|v| {
                slice_idx
                    .checked_mul(BINARY_SLICE_DESC_LEN)
                    .and_then(|s| v.checked_add(s))
            })
            .ok_or(FastpathError::InvalidTableBounds)?;
        let desc = self
            .bytes
            .get(desc_off..desc_off.saturating_add(BINARY_SLICE_DESC_LEN))
            .ok_or(FastpathError::InvalidTableBounds)?;
        self.read_str(read_u16(desc, 0)?, read_u16(desc, 2)?)
    }

    fn read_str(&self, off: u16, len: u16) -> Result<&'a str, FastpathError> {
        let start = self
            .string_table_off
            .checked_add(usize::from(off))
            .ok_or(FastpathError::InvalidTableBounds)?;
        let end = start
            .checked_add(usize::from(len))
            .ok_or(FastpathError::InvalidTableBounds)?;
        let raw = self
            .bytes
            .get(start..end)
            .ok_or(FastpathError::InvalidTableBounds)?;
        str::from_utf8(raw).map_err(|_| FastpathError::InvalidUtf8)
    }

    fn matches_agents(&self, rule: &DecodedRule, agent: &str) -> bool {
        if rule.agent_count == 0 {
            return true;
        }
        let start = usize::from(rule.slice_start);
        let end = start.saturating_add(usize::from(rule.agent_count));
        (start..end).any(|idx| {
            self.read_slice_str(idx)
                .is_ok_and(|a| eq_ascii_icase(a, agent))
        })
    }

    fn matches_prefixes(&self, rule: &DecodedRule, target: &str) -> bool {
        let start = usize::from(rule.slice_start).saturating_add(usize::from(rule.agent_count));
        let end = start.saturating_add(usize::from(rule.prefix_count));
        (start..end).any(|idx| {
            self.read_slice_str(idx)
                .is_ok_and(|p| !p.is_empty() && starts_with_norm_icase(target, p))
        })
    }

    fn matches_contains(&self, rule: &DecodedRule, target: &str) -> bool {
        let start = usize::from(rule.slice_start)
            .saturating_add(usize::from(rule.agent_count))
            .saturating_add(usize::from(rule.prefix_count));
        let end = start.saturating_add(usize::from(rule.contain_count));
        (start..end).any(|idx| {
            self.read_slice_str(idx)
                .is_ok_and(|n| !n.is_empty() && contains_norm_icase(target, n))
        })
    }
}

pub(crate) const fn verdict_rank(verdict: FastVerdict) -> u8 {
    match verdict {
        FastVerdict::Allow => 0,
        FastVerdict::StepUp => 1,
        FastVerdict::Deny => 2,
    }
}

const fn corrupt_fail_closed_hit() -> BinaryFloorHit<'static> {
    BinaryFloorHit {
        rule_id: "fastpath.corrupt",
        reason: "Corrupt binary floor entry (fail-closed).",
        verdict: FastVerdict::Deny,
    }
}

pub(crate) fn framing_crc32(bytes: &[u8]) -> u32 {
    // Non-cryptographic framing checksum; signature checks belong in grdr-crypto.
    let mut crc: u32 = 0xFFFF_FFFF;
    for (idx, &b) in bytes.iter().enumerate() {
        if (28..32).contains(&idx) {
            continue;
        }
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

pub(crate) fn read_u16(slice: &[u8], off: usize) -> Result<u16, FastpathError> {
    let b0 = *slice.get(off).ok_or(FastpathError::InvalidTableBounds)?;
    let b1 = *slice
        .get(off.saturating_add(1))
        .ok_or(FastpathError::InvalidTableBounds)?;
    Ok(u16::from_le_bytes([b0, b1]))
}

pub(crate) fn read_u32(slice: &[u8], off: usize) -> Result<u32, FastpathError> {
    let b0 = *slice.get(off).ok_or(FastpathError::InvalidTableBounds)?;
    let b1 = *slice
        .get(off.saturating_add(1))
        .ok_or(FastpathError::InvalidTableBounds)?;
    let b2 = *slice
        .get(off.saturating_add(2))
        .ok_or(FastpathError::InvalidTableBounds)?;
    let b3 = *slice
        .get(off.saturating_add(3))
        .ok_or(FastpathError::InvalidTableBounds)?;
    Ok(u32::from_le_bytes([b0, b1, b2, b3]))
}
