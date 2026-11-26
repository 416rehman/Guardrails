// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Compact signed/private binary codecs (`GRDRLAD1` crash ladder + prior `GRDRFLT1` floor loader).

use std::collections::BTreeSet;
use std::path::Path;

use grdr_crypto::SigningKeypair;
use grdr_os_service::ladder::{CrashLoopLadder, FloorRuleUnion, LadderRung};
use grdr_store_local::fs_hardening::{atomic_write_private, read_bounded_nofollow};
use grdr_wire::floor_bin::{FloorRuleRecord, MAX_FLOOR_BYTES, verify_and_decode_floor_table};
use jiff::Timestamp;

const MAX_LADDER_STATE_BYTES: usize = 256 * 1024;
const LADDER_BIN_MAGIC: &[u8; 8] = b"GRDRLAD1";
const LADDER_BIN_VERSION: u32 = 1;

pub(crate) fn load_prior_floor_rules(
    floor_path: &Path,
    signing_key: &SigningKeypair,
    now_s: i64,
) -> Result<Vec<FloorRuleRecord>, String> {
    let raw = match read_bounded_nofollow(floor_path, MAX_FLOOR_BYTES) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("GRDR-DAEM-0001: read prior floor table: {err}")),
    };
    let pub_b64 = signing_key.public_key_b64();
    let pubkeys = [(signing_key.key_id(), pub_b64.as_str())];
    let verified = verify_and_decode_floor_table(&raw, &pubkeys, now_s)
        .map_err(|e| format!("GRDR-DAEM-0001: verify prior floor table: {e}"))?;
    Ok(verified.document.rules)
}

pub(crate) fn load_ladder_state(path: &Path, now: Timestamp) -> (CrashLoopLadder, Vec<i64>) {
    let mut epochs = Vec::new();
    let mut floor = FloorRuleUnion {
        fail_closed_rule_ids: BTreeSet::new(),
    };
    if let Ok(raw) = read_bounded_nofollow(path, MAX_LADDER_STATE_BYTES)
        && let Some((ids, loaded_epochs)) = decode_ladder_binary(&raw)
    {
        for id in ids {
            floor.fail_closed_rule_ids.insert(id);
        }
        epochs = loaded_epochs;
    }
    let mut ladder = CrashLoopLadder::new(now, floor);
    for ts_s in &epochs {
        if let Ok(ts) = Timestamp::from_second(*ts_s) {
            let _ = ladder.record_engine_crash(ts, &[]);
        }
    }
    (ladder, epochs)
}

pub(crate) fn persist_ladder_state(
    path: &Path,
    ladder: &CrashLoopLadder,
    crash_epochs_s: &[i64],
) -> Result<(), String> {
    let rule_ids: Vec<&str> = ladder
        .effective_floor()
        .fail_closed_rule_ids
        .iter()
        .map(String::as_str)
        .collect();
    let bytes = encode_ladder_binary(ladder.rung(), &rule_ids, crash_epochs_s)?;
    atomic_write_private(path, &bytes)
}

fn encode_ladder_binary(
    rung: LadderRung,
    rule_ids: &[&str],
    epochs_s: &[i64],
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(LADDER_BIN_MAGIC);
    buf.extend_from_slice(&LADDER_BIN_VERSION.to_le_bytes());
    buf.push(rung_to_byte(rung));
    let id_count = u16::try_from(rule_ids.len()).map_err(|_| "too many rule_ids".to_string())?;
    buf.extend_from_slice(&id_count.to_le_bytes());
    for id in rule_ids {
        let len = u16::try_from(id.len()).map_err(|_| "rule_id too long".to_string())?;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(id.as_bytes());
    }
    let epoch_count = u16::try_from(epochs_s.len()).map_err(|_| "too many epochs".to_string())?;
    buf.extend_from_slice(&epoch_count.to_le_bytes());
    for ts in epochs_s {
        buf.extend_from_slice(&ts.to_le_bytes());
    }
    if buf.len() > MAX_LADDER_STATE_BYTES {
        return Err("ladder state exceeded size cap".to_string());
    }
    Ok(buf)
}

fn decode_ladder_binary(raw: &[u8]) -> Option<(Vec<String>, Vec<i64>)> {
    if raw.get(..8)? != LADDER_BIN_MAGIC {
        return None;
    }
    let mut off = 8usize;
    let ver = u32::from_le_bytes(raw.get(off..off.checked_add(4)?)?.try_into().ok()?);
    off = off.checked_add(4)?;
    if ver != LADDER_BIN_VERSION {
        return None;
    }
    let _rung = *raw.get(off)?;
    off = off.checked_add(1)?;
    let id_count = usize::from(u16::from_le_bytes(
        raw.get(off..off.checked_add(2)?)?.try_into().ok()?,
    ));
    off = off.checked_add(2)?;
    if id_count > 1_024 {
        return None;
    }
    let mut ids = Vec::with_capacity(id_count);
    for _ in 0..id_count {
        let len = usize::from(u16::from_le_bytes(
            raw.get(off..off.checked_add(2)?)?.try_into().ok()?,
        ));
        off = off.checked_add(2)?;
        let s = std::str::from_utf8(raw.get(off..off.checked_add(len)?)?).ok()?;
        off = off.checked_add(len)?;
        ids.push(s.to_string());
    }
    let epoch_count = usize::from(u16::from_le_bytes(
        raw.get(off..off.checked_add(2)?)?.try_into().ok()?,
    ));
    off = off.checked_add(2)?;
    if epoch_count > 64 {
        return None;
    }
    let mut epochs = Vec::with_capacity(epoch_count);
    for _ in 0..epoch_count {
        let ts = i64::from_le_bytes(raw.get(off..off.checked_add(8)?)?.try_into().ok()?);
        off = off.checked_add(8)?;
        epochs.push(ts);
    }
    if off != raw.len() {
        return None;
    }
    Some((ids, epochs))
}

const fn rung_to_byte(rung: LadderRung) -> u8 {
    match rung {
        LadderRung::Normal => 0,
        LadderRung::Quarantine => 1,
        LadderRung::ContentRevert => 2,
        LadderRung::BinaryRevert => 3,
        LadderRung::SafeMode => 4,
        LadderRung::MinimalCore => 5,
        LadderRung::Stopped => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_ladder_codec_roundtrips_and_rejects_corrupt() {
        let encoded = encode_ladder_binary(
            LadderRung::SafeMode,
            &["essentials.r1", "essentials.r2"],
            &[1_700_000_000, 1_700_000_010],
        );
        assert!(encoded.is_ok());
        let bytes = encoded.unwrap_or_default();
        let decoded = decode_ladder_binary(&bytes);
        assert_eq!(
            decoded,
            Some((
                vec!["essentials.r1".to_string(), "essentials.r2".to_string()],
                vec![1_700_000_000, 1_700_000_010],
            ))
        );
        assert!(decode_ladder_binary(b"BAD").is_none());
    }
}
