// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Normalized byte-span grounding and `ReducedTranscript::offset_map` verification (`docs/design/19`).

use std::collections::BTreeMap;

use unicode_normalization::{
    IsNormalized, UnicodeNormalization as _, char::canonical_combining_class, is_nfc_quick,
};

use grdr_crypto::constant_time_eq;

use crate::reducer::{ELISION_MARKER, SourceSegment, SpanOffsetMapEntry, salted_class_commitment};

enum MatchCount {
    None,
    One(usize),
    Multiple,
}

pub(crate) fn validate_offset_map<'a>(
    offset_map: &'a [SpanOffsetMapEntry],
    source_by_id: &BTreeMap<&str, &SourceSegment>,
    class_salt: &[u8; 32],
) -> Result<BTreeMap<&'a str, Vec<&'a SpanOffsetMapEntry>>, ()> {
    let mut grouped: BTreeMap<&str, Vec<&SpanOffsetMapEntry>> = BTreeMap::new();
    let mut cached_commits: BTreeMap<&str, String> = BTreeMap::new();
    for entry in offset_map {
        let Some(src) = source_by_id.get(entry.record_id.as_str()) else {
            return Err(());
        };
        let red_len = entry
            .reduced_end
            .checked_sub(entry.reduced_start)
            .ok_or(())?;
        let src_len = entry.source_end.checked_sub(entry.source_start).ok_or(())?;
        if red_len == 0 || red_len != src_len {
            return Err(());
        }
        let (Ok(src_start), Ok(src_end)) = (
            usize::try_from(entry.source_start),
            usize::try_from(entry.source_end),
        ) else {
            return Err(());
        };
        if src.text.get(src_start..src_end).is_none() {
            return Err(());
        }
        let expected_commit = cached_commits
            .entry(src.record_id.as_str())
            .or_insert_with(|| {
                salted_class_commitment(class_salt, &src.record_id, src.data_class, &src.text)
            });
        if !constant_time_eq(
            expected_commit.as_bytes(),
            entry.class_commitment_sha256.as_bytes(),
        ) {
            return Err(());
        }
        grouped
            .entry(entry.record_id.as_str())
            .or_default()
            .push(entry);
    }
    for entries in grouped.values_mut() {
        entries.sort_by_key(|e| e.reduced_start);
        let mut prev_red_end: u64 = 0;
        let mut prev_src_end: u64 = 0;
        for (idx, entry) in entries.iter().enumerate() {
            if entry.reduced_end <= entry.reduced_start || entry.source_end <= entry.source_start {
                return Err(());
            }
            if idx > 0 && (entry.reduced_start < prev_red_end || entry.source_start < prev_src_end)
            {
                return Err(());
            }
            prev_red_end = entry.reduced_end;
            prev_src_end = entry.source_end;
        }
    }
    Ok(grouped)
}

pub(crate) fn verify_decoded_against_offset_map(
    decoded_text: &str,
    src_text: &str,
    entries: &[&SpanOffsetMapEntry],
    transcript_partial: bool,
) -> bool {
    if entries.is_empty() {
        return false;
    }
    if !transcript_partial {
        let [only] = entries else {
            return false;
        };
        return only.reduced_start == 0
            && only.source_start == 0
            && usize::try_from(only.reduced_end).ok() == Some(decoded_text.len())
            && usize::try_from(only.source_end).ok() == Some(src_text.len())
            && decoded_text == src_text;
    }
    let mut cursor: usize = 0;
    for (idx, entry) in entries.iter().enumerate() {
        let (Ok(red_start), Ok(red_end), Ok(src_start), Ok(src_end)) = (
            usize::try_from(entry.reduced_start),
            usize::try_from(entry.reduced_end),
            usize::try_from(entry.source_start),
            usize::try_from(entry.source_end),
        ) else {
            return false;
        };
        if idx == 0 {
            if red_start != 0 {
                return false;
            }
        } else if decoded_text.get(cursor..red_start) != Some(ELISION_MARKER) {
            return false;
        }
        let Some(dec_slice) = decoded_text.get(red_start..red_end) else {
            return false;
        };
        let Some(src_slice) = src_text.get(src_start..src_end) else {
            return false;
        };
        if dec_slice != src_slice {
            return false;
        }
        cursor = red_end;
    }
    cursor == decoded_text.len()
}

pub(crate) fn map_reduced_span_to_source(
    entries: &[&SpanOffsetMapEntry],
    red_start: usize,
    red_end: usize,
) -> Option<(usize, usize)> {
    let red_start_u64 = u64::try_from(red_start).ok()?;
    let red_end_u64 = u64::try_from(red_end).ok()?;
    for entry in entries {
        if red_start_u64 >= entry.reduced_start && red_end_u64 <= entry.reduced_end {
            let off_start =
                usize::try_from(red_start_u64.checked_sub(entry.reduced_start)?).ok()?;
            let off_end = usize::try_from(red_end_u64.checked_sub(entry.reduced_start)?).ok()?;
            let src_start = usize::try_from(entry.source_start).ok()?;
            return Some((
                src_start.checked_add(off_start)?,
                src_start.checked_add(off_end)?,
            ));
        }
    }
    None
}

pub(crate) fn normalize_for_quotecheck(raw: &str) -> String {
    normalize_with_byte_map(raw).0
}

pub(crate) fn locate_verified_span(
    source_text: &str,
    exact_quote: &str,
    norm_quote: &str,
    start_hint: Option<u64>,
) -> Option<(usize, usize)> {
    match find_up_to_two_matches(source_text, exact_quote) {
        MatchCount::One(start) => {
            return Some((start, start.saturating_add(exact_quote.len())));
        }
        MatchCount::Multiple => {
            let hint = start_hint.and_then(|h| usize::try_from(h).ok())?;
            let end = hint.checked_add(exact_quote.len())?;
            if source_text.get(hint..end) == Some(exact_quote) {
                return Some((hint, end));
            }
            return None;
        }
        MatchCount::None => {}
    }

    if norm_quote.is_empty() {
        return None;
    }
    let (norm_src, byte_map) = normalize_with_byte_map(source_text);
    match find_up_to_two_matches(&norm_src, norm_quote) {
        MatchCount::None => None,
        MatchCount::One(norm_start) => {
            map_norm_span(source_text, &byte_map, norm_start, norm_quote.len())
        }
        MatchCount::Multiple => {
            let hint = start_hint.and_then(|h| usize::try_from(h).ok())?;
            locate_norm_hint_span(source_text, &norm_src, &byte_map, norm_quote, hint)
        }
    }
}

fn map_norm_span(
    source_text: &str,
    byte_map: &[(usize, usize)],
    norm_start: usize,
    norm_len: usize,
) -> Option<(usize, usize)> {
    let norm_end = norm_start.checked_add(norm_len)?;
    let first_raw = byte_map.get(norm_start)?;
    let last_idx = norm_end.checked_sub(1)?;
    let last_raw = byte_map.get(last_idx)?;
    let span = (first_raw.0, last_raw.1);
    source_text.get(span.0..span.1).map(|_| span)
}

fn locate_norm_hint_span(
    source_text: &str,
    norm_src: &str,
    byte_map: &[(usize, usize)],
    norm_quote: &str,
    hint: usize,
) -> Option<(usize, usize)> {
    let lo = byte_map.partition_point(|&(s, _)| s < hint);
    let hi = byte_map.partition_point(|&(s, _)| s <= hint);
    if lo >= hi || !norm_src.is_char_boundary(lo) {
        return None;
    }
    let mut window_end = hi
        .saturating_sub(1)
        .saturating_add(norm_quote.len())
        .min(norm_src.len());
    while window_end < norm_src.len() && !norm_src.is_char_boundary(window_end) {
        window_end = window_end.saturating_add(1);
    }
    let window = norm_src.get(lo..window_end)?;
    let rel = window.find(norm_quote)?;
    let norm_start = lo.saturating_add(rel);
    if norm_start >= hi {
        return None;
    }
    let span = map_norm_span(source_text, byte_map, norm_start, norm_quote.len())?;
    (span.0 == hint).then_some(span)
}

fn is_independent_nfc_starter(ch: char) -> bool {
    ch.is_ascii()
        || (canonical_combining_class(ch) == 0
            && is_nfc_quick(std::iter::once(ch)) == IsNormalized::Yes)
}

fn normalize_with_byte_map(raw: &str) -> (String, Vec<(usize, usize)>) {
    let mut out = String::with_capacity(raw.len());
    let mut byte_map: Vec<(usize, usize)> = Vec::with_capacity(raw.len());
    let mut pending_ws: Option<(usize, usize)> = None;
    let mut idx: usize = 0;

    while let Some(tail) = raw.get(idx..) {
        let Some(first_ch) = tail.chars().next() else {
            break;
        };
        if first_ch.is_whitespace() {
            let next_idx = idx.saturating_add(first_ch.len_utf8());
            if !out.is_empty() {
                pending_ws = Some(match pending_ws {
                    Some((ws_start, _)) => (ws_start, next_idx),
                    None => (idx, next_idx),
                });
            }
            idx = next_idx;
            continue;
        }

        let chunk_start = idx;
        let mut chunk_end = idx.saturating_add(first_ch.len_utf8());
        while let Some(rest) = raw.get(chunk_end..) {
            let Some(next_ch) = rest.chars().next() else {
                break;
            };
            if next_ch.is_whitespace() || is_independent_nfc_starter(next_ch) {
                break;
            }
            chunk_end = chunk_end.saturating_add(next_ch.len_utf8());
        }

        if let Some(ws_span) = pending_ws.take() {
            out.push(' ');
            byte_map.push(ws_span);
        }
        if let Some(chunk) = raw.get(chunk_start..chunk_end) {
            for norm_ch in chunk.nfc() {
                let mut buf = [0_u8; 4];
                let enc = norm_ch.encode_utf8(&mut buf);
                out.push_str(enc);
                for _ in enc.as_bytes() {
                    byte_map.push((chunk_start, chunk_end));
                }
            }
        }
        idx = chunk_end;
    }

    (out, byte_map)
}

fn find_up_to_two_matches(haystack: &str, needle: &str) -> MatchCount {
    if needle.is_empty() {
        return MatchCount::None;
    }
    let Some(first) = haystack.find(needle) else {
        return MatchCount::None;
    };
    let step = haystack
        .get(first..)
        .and_then(|s| s.chars().next())
        .map_or(1, char::len_utf8);
    let next_pos = first.saturating_add(step);
    if haystack
        .get(next_pos..)
        .is_some_and(|tail| tail.contains(needle))
    {
        MatchCount::Multiple
    } else {
        MatchCount::One(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reducer::ReviewRecordKind;
    use grdr_model::DataClass;

    #[test]
    fn round4_offset_map_rejects_empty_and_non_monotonic_slices_and_handles_repeated_matches() {
        let salt = [7_u8; 32];
        let seg = SourceSegment {
            record_id: "r1".into(),
            kind: ReviewRecordKind::ToolOutput,
            data_class: DataClass::Content,
            text: "head-chunk\n[...elided...]\ntail-chunk".into(),
        };
        let commit = salted_class_commitment(&salt, &seg.record_id, seg.data_class, &seg.text);
        let mut by_id = BTreeMap::new();
        by_id.insert(seg.record_id.as_str(), &seg);

        let empty_slice = [SpanOffsetMapEntry {
            record_id: "r1".into(),
            reduced_start: 0,
            reduced_end: 0,
            source_start: 0,
            source_end: 0,
            class_commitment_sha256: commit.clone(),
        }];
        assert!(validate_offset_map(&empty_slice, &by_id, &salt).is_err());

        let non_monotonic_source = [
            SpanOffsetMapEntry {
                record_id: "r1".into(),
                reduced_start: 0,
                reduced_end: 4,
                source_start: 27,
                source_end: 31,
                class_commitment_sha256: commit.clone(),
            },
            SpanOffsetMapEntry {
                record_id: "r1".into(),
                reduced_start: 21,
                reduced_end: 25,
                source_start: 0,
                source_end: 4,
                class_commitment_sha256: commit.clone(),
            },
        ];
        assert!(validate_offset_map(&non_monotonic_source, &by_id, &salt).is_err());

        let overlapping_reduced = [
            SpanOffsetMapEntry {
                record_id: "r1".into(),
                reduced_start: 0,
                reduced_end: 5,
                source_start: 0,
                source_end: 5,
                class_commitment_sha256: commit.clone(),
            },
            SpanOffsetMapEntry {
                record_id: "r1".into(),
                reduced_start: 4,
                reduced_end: 9,
                source_start: 5,
                source_end: 10,
                class_commitment_sha256: commit.clone(),
            },
        ];
        assert!(validate_offset_map(&overlapping_reduced, &by_id, &salt).is_err());

        let valid_multi = [
            SpanOffsetMapEntry {
                record_id: "r1".into(),
                reduced_start: 0,
                reduced_end: 4,
                source_start: 0,
                source_end: 4,
                class_commitment_sha256: commit.clone(),
            },
            SpanOffsetMapEntry {
                record_id: "r1".into(),
                reduced_start: 21,
                reduced_end: 25,
                source_start: 27,
                source_end: 31,
                class_commitment_sha256: commit,
            },
        ];
        assert!(validate_offset_map(&valid_multi, &by_id, &salt).is_ok());

        // Overlapping verbatim repeat and normalized repeat resolve with O(M) start_hint verification.
        let rep = "a".repeat(20_000);
        let q = "a".repeat(32);
        assert_eq!(locate_verified_span(&rep, &q, &q, None), None);
        assert_eq!(
            locate_verified_span(&rep, &q, &q, Some(10_000)),
            Some((10_000, 10_032))
        );
        assert_eq!(locate_verified_span(&rep, &q, &q, Some(19_990)), None);

        let norm_src = "café   secret  \n token middle café   secret  \n token end";
        let norm_q = normalize_for_quotecheck("café secret token");
        assert_eq!(
            locate_verified_span(norm_src, "café secret token", &norm_q, None),
            None
        );
        assert_eq!(
            locate_verified_span(norm_src, "café secret token", &norm_q, Some(0)),
            Some((0, 23))
        );
        let second_start = norm_src.rfind("café").unwrap();
        assert_eq!(
            locate_verified_span(
                norm_src,
                "café secret token",
                &norm_q,
                Some(u64::try_from(second_start).unwrap())
            ),
            Some((second_start, second_start + 23))
        );
        assert_eq!(
            locate_verified_span(norm_src, "café secret token", &norm_q, Some(1)),
            None
        );
    }
}
