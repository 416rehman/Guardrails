// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Verbatim safe-run quote extraction free of ANSI escapes, bidi overrides, and control bytes.

use std::ops::Range;

use crate::advisory::MAX_ADVISORY_QUOTE_BYTES;
use crate::confusables::{is_safe_quote_char, is_visible_quote_char};

pub(crate) fn extract_context_quote(original: &str, span: Range<usize>) -> Option<String> {
    if original.is_empty() {
        return None;
    }
    let search_from = span.end.min(original.len());
    if let Some(after) = original.get(search_from..)
        && let Some(run) = first_safe_non_blank_run(after)
    {
        return Some(run.to_owned());
    }
    first_safe_non_blank_run(original).map(str::to_owned)
}

pub(crate) fn longest_safe_mapped_run<'a>(
    original: &'a str,
    mapped: &[Range<usize>],
) -> Option<&'a str> {
    let mut best: Option<&'a str> = None;
    let mut seg_start: Option<usize> = None;
    let mut seg_end: usize = 0;

    for span in mapped {
        match seg_start {
            Some(s) if span.start >= s && span.start <= seg_end => {
                seg_end = seg_end.max(span.end);
            }
            Some(s) => {
                let end = clamp_char_boundary_end(original, s, seg_end);
                if let Some(chunk) = original.get(s..end)
                    && let Some(run) = best_safe_run_in_chunk(chunk)
                    && best.is_none_or(|b| run.len() > b.len())
                {
                    best = Some(run);
                }
                seg_start = Some(span.start);
                seg_end = span.end;
            }
            None => {
                seg_start = Some(span.start);
                seg_end = span.end;
            }
        }
    }
    if let Some(s) = seg_start {
        let end = clamp_char_boundary_end(original, s, seg_end);
        if let Some(chunk) = original.get(s..end)
            && let Some(run) = best_safe_run_in_chunk(chunk)
            && best.is_none_or(|b| run.len() > b.len())
        {
            best = Some(run);
        }
    }
    best
}

pub(crate) fn clamp_char_boundary_end(text: &str, start: usize, candidate_end: usize) -> usize {
    let max_end = start
        .saturating_add(MAX_ADVISORY_QUOTE_BYTES)
        .min(text.len());
    let mut end = candidate_end.min(max_end);
    while end > start && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    end
}

fn is_valid_run(trimmed: &str) -> bool {
    !trimmed.is_empty() && trimmed.chars().any(is_visible_quote_char)
}

fn consider_best<'a>(best: &mut Option<&'a str>, candidate: Option<&'a str>) {
    if let Some(trimmed) = candidate.map(str::trim_end)
        && is_valid_run(trimmed)
        && best.is_none_or(|b| trimmed.len() > b.len())
    {
        *best = Some(trimmed);
    }
}

fn best_safe_run_in_chunk(text: &str) -> Option<&str> {
    let mut best: Option<&str> = None;
    let mut cur_start: Option<usize> = None;
    for (idx, ch) in text.char_indices() {
        if !is_safe_quote_char(ch) {
            if let Some(start) = cur_start.take() {
                consider_best(&mut best, text.get(start..idx));
            }
            continue;
        }
        if cur_start.is_none() && is_visible_quote_char(ch) {
            cur_start = Some(idx);
        }
        if let Some(start) = cur_start {
            let end = idx.saturating_add(ch.len_utf8());
            if end.saturating_sub(start) >= MAX_ADVISORY_QUOTE_BYTES {
                consider_best(&mut best, text.get(start..idx));
                cur_start = None;
            }
        }
    }
    if let Some(start) = cur_start {
        consider_best(&mut best, text.get(start..));
    }
    best
}

fn first_safe_non_blank_run(text: &str) -> Option<&str> {
    let mut run_start: Option<usize> = None;
    for (idx, ch) in text.char_indices() {
        if !is_safe_quote_char(ch) {
            if let Some(start) = run_start.take() {
                let trimmed = text.get(start..idx)?.trim_end();
                if is_valid_run(trimmed) {
                    return Some(trimmed);
                }
            }
            continue;
        }
        if run_start.is_none() && is_visible_quote_char(ch) {
            run_start = Some(idx);
        }
        if let Some(start) = run_start {
            let end = idx.saturating_add(ch.len_utf8());
            if end.saturating_sub(start) >= MAX_ADVISORY_QUOTE_BYTES {
                let trimmed = text.get(start..idx)?.trim_end();
                if is_valid_run(trimmed) {
                    return Some(trimmed);
                }
                run_start = None;
            }
        }
    }
    let start = run_start?;
    let trimmed = text.get(start..)?.trim_end();
    is_valid_run(trimmed).then_some(trimmed)
}
