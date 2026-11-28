// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! `#![no_std]` binary floor encoder and manifest-driven failsafe rule evaluator.

use crate::binary::{
    BINARY_HEADER_LEN, BINARY_RULE_LEN, BINARY_SLICE_DESC_LEN, BinaryFloorHit, BinaryRuleInput,
    FastpathError, MAX_BINARY_RULES, MAX_BINARY_SLICES, framing_crc32, verdict_rank,
};
use crate::manifest::FastpathTablesManifest;
use crate::{
    FLOOR_FORMAT_MAGIC, FLOOR_FORMAT_VERSION, FastActionClass, FastVerdict, contains_norm_icase,
};

pub fn encoded_binary_floor_size(
    entries: &[BinaryRuleInput<'_>],
) -> Result<(usize, usize), FastpathError> {
    if entries.len() > MAX_BINARY_RULES {
        return Err(FastpathError::TooManyRules);
    }
    let mut slice_count: usize = 0;
    let mut str_bytes: usize = 0;
    for entry in entries {
        if entry.agents.len() > usize::from(u8::MAX)
            || entry.prefixes.len() > usize::from(u8::MAX)
            || entry.contains.len() > usize::from(u8::MAX)
        {
            return Err(FastpathError::TooManySlices);
        }
        slice_count = slice_count
            .checked_add(entry.agents.len())
            .and_then(|v| v.checked_add(entry.prefixes.len()))
            .and_then(|v| v.checked_add(entry.contains.len()))
            .ok_or(FastpathError::TooManySlices)?;
        str_bytes = str_bytes
            .checked_add(entry.rule_id.len())
            .and_then(|v| v.checked_add(entry.reason.len()))
            .ok_or(FastpathError::StringTableOverflow)?;
        for s in entry
            .agents
            .iter()
            .chain(entry.prefixes)
            .chain(entry.contains)
        {
            str_bytes = str_bytes
                .checked_add(s.len())
                .ok_or(FastpathError::StringTableOverflow)?;
        }
    }
    if slice_count > MAX_BINARY_SLICES {
        return Err(FastpathError::TooManySlices);
    }
    if str_bytes > usize::from(u16::MAX) {
        return Err(FastpathError::StringTableOverflow);
    }
    let rules_bytes = entries
        .len()
        .checked_mul(BINARY_RULE_LEN)
        .ok_or(FastpathError::InvalidTableBounds)?;
    let slices_bytes = slice_count
        .checked_mul(BINARY_SLICE_DESC_LEN)
        .ok_or(FastpathError::InvalidTableBounds)?;
    let total_len = BINARY_HEADER_LEN
        .checked_add(rules_bytes)
        .and_then(|v| v.checked_add(slices_bytes))
        .and_then(|v| v.checked_add(str_bytes))
        .ok_or(FastpathError::InvalidTableBounds)?;
    Ok((total_len, slice_count))
}

pub fn encode_binary_floor(
    entries: &[BinaryRuleInput<'_>],
    out: &mut [u8],
) -> Result<usize, FastpathError> {
    let (total_len, slice_count) = encoded_binary_floor_size(entries)?;
    let rules_bytes = entries
        .len()
        .checked_mul(BINARY_RULE_LEN)
        .ok_or(FastpathError::InvalidTableBounds)?;
    let slices_off = BINARY_HEADER_LEN
        .checked_add(rules_bytes)
        .ok_or(FastpathError::InvalidTableBounds)?;
    let slices_bytes = slice_count
        .checked_mul(BINARY_SLICE_DESC_LEN)
        .ok_or(FastpathError::InvalidTableBounds)?;
    let string_table_off = slices_off
        .checked_add(slices_bytes)
        .ok_or(FastpathError::InvalidTableBounds)?;
    if out.len() < total_len {
        return Err(FastpathError::BufferTooSmall);
    }

    let mut cur_slice: usize = 0;
    let mut cur_str: usize = 0;
    for (idx, entry) in entries.iter().enumerate() {
        let (id_off, id_len) = write_string(out, string_table_off, &mut cur_str, entry.rule_id)?;
        let (rsn_off, rsn_len) = write_string(out, string_table_off, &mut cur_str, entry.reason)?;
        let slice_start = u16::try_from(cur_slice).map_err(|_| FastpathError::TooManySlices)?;
        for s in entry
            .agents
            .iter()
            .chain(entry.prefixes)
            .chain(entry.contains)
        {
            let (s_off, s_len) = write_string(out, string_table_off, &mut cur_str, s)?;
            let desc_off = slices_off
                .checked_add(
                    cur_slice
                        .checked_mul(BINARY_SLICE_DESC_LEN)
                        .ok_or(FastpathError::InvalidTableBounds)?,
                )
                .ok_or(FastpathError::InvalidTableBounds)?;
            write_u16(out, desc_off, s_off)?;
            write_u16(out, desc_off.saturating_add(2), s_len)?;
            cur_slice = cur_slice.saturating_add(1);
        }
        let rule_off = BINARY_HEADER_LEN.saturating_add(idx.saturating_mul(BINARY_RULE_LEN));
        write_u32(out, rule_off, entry.action_mask)?;
        write_u16(out, rule_off.saturating_add(4), entry.principal_mask)?;
        write_u16(out, rule_off.saturating_add(6), entry.label_mask)?;
        write_u16(out, rule_off.saturating_add(8), id_off)?;
        write_u16(out, rule_off.saturating_add(10), id_len)?;
        write_u16(out, rule_off.saturating_add(12), rsn_off)?;
        write_u16(out, rule_off.saturating_add(14), rsn_len)?;
        write_u16(out, rule_off.saturating_add(16), slice_start)?;
        let verdict_byte = match entry.verdict {
            FastVerdict::Allow => 0u8,
            FastVerdict::StepUp => 1u8,
            FastVerdict::Deny => 2u8,
        };
        let agent_count =
            u8::try_from(entry.agents.len()).map_err(|_| FastpathError::TooManySlices)?;
        let prefix_count =
            u8::try_from(entry.prefixes.len()).map_err(|_| FastpathError::TooManySlices)?;
        let contains_count =
            u8::try_from(entry.contains.len()).map_err(|_| FastpathError::TooManySlices)?;
        write_u8(out, rule_off.saturating_add(18), verdict_byte)?;
        write_u8(out, rule_off.saturating_add(19), agent_count)?;
        write_u8(out, rule_off.saturating_add(20), prefix_count)?;
        write_u8(out, rule_off.saturating_add(21), contains_count)?;
        write_u16(out, rule_off.saturating_add(22), 0)?;
    }

    let hdr = out.get_mut(..8).ok_or(FastpathError::BufferTooSmall)?;
    hdr.copy_from_slice(FLOOR_FORMAT_MAGIC);
    write_u32(out, 8, FLOOR_FORMAT_VERSION)?;
    write_u32(out, 12, 0)?;
    let rule_count_u16 = u16::try_from(entries.len()).map_err(|_| FastpathError::TooManyRules)?;
    let slice_count_u16 = u16::try_from(slice_count).map_err(|_| FastpathError::TooManySlices)?;
    write_u16(out, 16, rule_count_u16)?;
    write_u16(out, 18, slice_count_u16)?;
    write_u32(
        out,
        20,
        u32::try_from(string_table_off).map_err(|_| FastpathError::InvalidTableBounds)?,
    )?;
    write_u32(
        out,
        24,
        u32::try_from(total_len).map_err(|_| FastpathError::InvalidTableBounds)?,
    )?;
    let crc = framing_crc32(out.get(..total_len).ok_or(FastpathError::BufferTooSmall)?);
    write_u32(out, 28, crc)?;
    Ok(total_len)
}

pub fn evaluate_failsafe(action: FastActionClass, target: &str) -> Option<BinaryFloorHit<'static>> {
    let manifest = FastpathTablesManifest::embedded();
    evaluate_failsafe_with_manifest(&manifest, action, target)
}

pub fn evaluate_failsafe_with_manifest<'a>(
    manifest: &FastpathTablesManifest<'a>,
    action: FastActionClass,
    target: &str,
) -> Option<BinaryFloorHit<'a>> {
    let bit = action.bit();
    let mut best: Option<BinaryFloorHit<'a>> = None;
    manifest.visit_failsafe_rules(|entry| {
        if (entry.action_mask & bit) != 0 && contains_norm_icase(target, entry.needle) {
            let hit = BinaryFloorHit {
                rule_id: entry.rule_id,
                reason: entry.reason,
                verdict: entry.verdict,
            };
            if best
                .as_ref()
                .is_none_or(|cur| verdict_rank(hit.verdict) > verdict_rank(cur.verdict))
            {
                best = Some(hit);
            }
        }
    });
    best
}

fn write_string(
    out: &mut [u8],
    table_off: usize,
    cursor: &mut usize,
    text: &str,
) -> Result<(u16, u16), FastpathError> {
    let off = u16::try_from(*cursor).map_err(|_| FastpathError::StringTableOverflow)?;
    let len = u16::try_from(text.len()).map_err(|_| FastpathError::StringTableOverflow)?;
    let start = table_off
        .checked_add(*cursor)
        .ok_or(FastpathError::BufferTooSmall)?;
    let end = start
        .checked_add(text.len())
        .ok_or(FastpathError::BufferTooSmall)?;
    let dst = out
        .get_mut(start..end)
        .ok_or(FastpathError::BufferTooSmall)?;
    dst.copy_from_slice(text.as_bytes());
    *cursor = cursor.saturating_add(text.len());
    Ok((off, len))
}

fn write_u8(out: &mut [u8], off: usize, val: u8) -> Result<(), FastpathError> {
    let slot = out.get_mut(off).ok_or(FastpathError::BufferTooSmall)?;
    *slot = val;
    Ok(())
}

fn write_u16(out: &mut [u8], off: usize, val: u16) -> Result<(), FastpathError> {
    let end = off.checked_add(2).ok_or(FastpathError::BufferTooSmall)?;
    let dst = out.get_mut(off..end).ok_or(FastpathError::BufferTooSmall)?;
    dst.copy_from_slice(&val.to_le_bytes());
    Ok(())
}

fn write_u32(out: &mut [u8], off: usize, val: u32) -> Result<(), FastpathError> {
    let end = off.checked_add(4).ok_or(FastpathError::BufferTooSmall)?;
    let dst = out.get_mut(off..end).ok_or(FastpathError::BufferTooSmall)?;
    dst.copy_from_slice(&val.to_le_bytes());
    Ok(())
}
