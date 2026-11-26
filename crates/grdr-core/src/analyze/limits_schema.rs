// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Schema-backed analyzer limit loading from `grdr_schema::limits` (`D-10`, `P14`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use grdr_schema::limits::{EMBEDDED_LIMITS_TOML, load_embedded_limits};

use crate::analyze::types::{
    AnalyzeLimits, DEFAULT_SHELL_INPUT_MAX_BYTES, DEFAULT_SHELL_NESTING_DEPTH_MAX,
    DEFAULT_SHELL_WORDS_MAX, LimitKind, MAX_SHELL_BYTE_CAP, ShellLimits, ShellLimitsError,
};

const DEFAULT_DECODE_MAX_LAYERS: u8 = 3;
const DEFAULT_DECODE_MAX_NODES: usize = 128;
const DEFAULT_DEFLATE_MAX_BLOCKS: usize = 16_384;
const DEFAULT_DEFLATE_MAX_EMPTY_BLOCKS: usize = 256;
const DEFAULT_DEFLATE_MAX_MEMBERS: usize = 64;
const DEFAULT_NET_LONG_QUERY_CHARS: usize = 512;
const DEFAULT_NET_HIGH_ENTROPY_MILLI_BITS: u32 = 3_900;

static CACHED_SHELL_LIMITS: OnceLock<ShellLimits> = OnceLock::new();
static CACHED_ANALYZE_LIMITS: OnceLock<AnalyzeLimits> = OnceLock::new();

pub(crate) fn shell_limits_from_schema() -> ShellLimits {
    *CACHED_SHELL_LIMITS.get_or_init(|| {
        shell_limits_from_toml(EMBEDDED_LIMITS_TOML)
            .unwrap_or_else(|_| ShellLimits::default_bounds())
    })
}

pub(crate) fn shell_limits_from_toml(src: &str) -> Result<ShellLimits, ShellLimitsError> {
    let sections = parse_toml_kv_sections(src);
    let embedded_frame = load_embedded_limits()
        .ok()
        .and_then(|cfg| u32::try_from(cfg.endpoint.ipc.max_frame_bytes).ok())
        .filter(|&v| v > 0 && v <= MAX_SHELL_BYTE_CAP)
        .unwrap_or(DEFAULT_SHELL_INPUT_MAX_BYTES);
    let schema_frame = lookup_bound_u32(
        &sections,
        "endpoint.ipc",
        &["max_frame_bytes", "max-frame-bytes"],
        embedded_frame,
        LimitKind::InputBytes,
    )?
    .clamp(1, MAX_SHELL_BYTE_CAP);

    let input_max = lookup_bound_u32(
        &sections,
        "bound.analyze.shell",
        &["input-max", "input_max"],
        schema_frame,
        LimitKind::InputBytes,
    )?;
    let env_max = lookup_bound_u32(
        &sections,
        "bound.analyze.shell",
        &["env-max", "env_max"],
        schema_frame,
        LimitKind::EnvBytes,
    )?;
    let nesting_depth_max = lookup_bound_u32(
        &sections,
        "bound.analyze.shell",
        &["nesting-depth-max", "nesting_depth_max"],
        DEFAULT_SHELL_NESTING_DEPTH_MAX,
        LimitKind::NestingDepth,
    )?;
    let words_max = lookup_bound_u32(
        &sections,
        "bound.analyze.shell",
        &["words-max", "words_max"],
        DEFAULT_SHELL_WORDS_MAX,
        LimitKind::Words,
    )?;
    let expanded_max = lookup_bound_u32(
        &sections,
        "bound.analyze.shell",
        &["expanded-max", "expanded_max"],
        schema_frame,
        LimitKind::ExpandedBytes,
    )?;
    ShellLimits::new(
        input_max,
        env_max,
        nesting_depth_max,
        words_max,
        expanded_max,
    )
}

pub(crate) fn analyze_limits_from_schema() -> AnalyzeLimits {
    *CACHED_ANALYZE_LIMITS.get_or_init(|| analyze_limits_from_toml(EMBEDDED_LIMITS_TOML))
}

pub(crate) fn analyze_limits_from_toml(src: &str) -> AnalyzeLimits {
    let default_input_max = usize::try_from(DEFAULT_SHELL_INPUT_MAX_BYTES).unwrap_or(1_048_576);
    let max_byte_cap = usize::try_from(MAX_SHELL_BYTE_CAP).unwrap_or(16 * 1024 * 1024);
    let sections = parse_toml_kv_sections(src);
    let embedded_frame = load_embedded_limits()
        .map(|cfg| cfg.endpoint.ipc.max_frame_bytes)
        .unwrap_or(default_input_max);
    let frame_bytes = lookup_bound_usize(
        &sections,
        "endpoint.ipc",
        &["max_frame_bytes", "max-frame-bytes"],
        embedded_frame,
    )
    .unwrap_or(embedded_frame)
    .clamp(4096, max_byte_cap);

    let decode_max_layers = lookup_bound_usize(
        &sections,
        "bound.analyze.decode",
        &["max-layers", "max_layers"],
        usize::from(DEFAULT_DECODE_MAX_LAYERS),
    )
    .and_then(|v| u8::try_from(v).ok())
    .filter(|&v| v > 0 && v <= 8)
    .unwrap_or(DEFAULT_DECODE_MAX_LAYERS);

    let decode_max_bytes = lookup_bound_usize(
        &sections,
        "bound.analyze.decode",
        &["max-bytes", "max_bytes"],
        frame_bytes,
    )
    .filter(|&v| v > 0 && v <= max_byte_cap)
    .unwrap_or(frame_bytes);

    let decode_max_nodes = lookup_bound_usize(
        &sections,
        "bound.analyze.decode",
        &["max-nodes", "max_nodes"],
        DEFAULT_DECODE_MAX_NODES,
    )
    .filter(|&v| v > 0 && v <= 65_536)
    .unwrap_or(DEFAULT_DECODE_MAX_NODES);

    let deflate_max_blocks = lookup_bound_usize(
        &sections,
        "bound.analyze.deflate",
        &["max-blocks", "max_blocks"],
        DEFAULT_DEFLATE_MAX_BLOCKS,
    )
    .filter(|&v| v > 0 && v <= 1_048_576)
    .unwrap_or(DEFAULT_DEFLATE_MAX_BLOCKS);

    let deflate_max_empty_blocks = lookup_bound_usize(
        &sections,
        "bound.analyze.deflate",
        &["max-empty-blocks", "max_empty_blocks"],
        DEFAULT_DEFLATE_MAX_EMPTY_BLOCKS,
    )
    .filter(|&v| v > 0 && v <= 65_536)
    .unwrap_or(DEFAULT_DEFLATE_MAX_EMPTY_BLOCKS);

    let deflate_max_members = lookup_bound_usize(
        &sections,
        "bound.analyze.deflate",
        &["max-members", "max_members"],
        DEFAULT_DEFLATE_MAX_MEMBERS,
    )
    .filter(|&v| v > 0 && v <= 4_096)
    .unwrap_or(DEFAULT_DEFLATE_MAX_MEMBERS);

    let content_max_scan_bytes = lookup_bound_usize(
        &sections,
        "bound.analyze.content",
        &["max-scan-bytes", "max_scan_bytes"],
        frame_bytes / 2,
    )
    .filter(|&v| v > 0 && v <= max_byte_cap)
    .unwrap_or(frame_bytes / 2);

    let net_long_query_chars = lookup_bound_usize(
        &sections,
        "bound.analyze.net",
        &["long-query-chars", "long_query_chars"],
        DEFAULT_NET_LONG_QUERY_CHARS,
    )
    .filter(|&v| v > 0 && v <= 65_536)
    .unwrap_or(DEFAULT_NET_LONG_QUERY_CHARS);

    let net_high_entropy_milli_bits = lookup_bound_usize(
        &sections,
        "bound.analyze.net",
        &["high-entropy-milli-bits", "high_entropy_milli_bits"],
        usize::try_from(DEFAULT_NET_HIGH_ENTROPY_MILLI_BITS).unwrap_or(3_900),
    )
    .and_then(|v| u32::try_from(v).ok())
    .filter(|&v| v > 0 && v <= 8_000)
    .unwrap_or(DEFAULT_NET_HIGH_ENTROPY_MILLI_BITS);

    AnalyzeLimits {
        decode_max_layers,
        decode_max_bytes,
        decode_max_nodes,
        deflate_max_blocks,
        deflate_max_empty_blocks,
        deflate_max_members,
        content_max_scan_bytes,
        net_long_query_chars,
        net_high_entropy_milli_bits,
    }
}

fn parse_toml_kv_sections(src: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut map: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current = String::new();
    for raw_line in src.lines() {
        let line = strip_toml_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            current = inner.trim().to_owned();
            map.entry(current.clone()).or_default();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            if !key.is_empty() && !val.is_empty() {
                map.entry(current.clone())
                    .or_default()
                    .insert(key.to_owned(), val.to_owned());
            }
        }
    }
    map
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '#' if !in_double && !in_single => return line.get(..idx).unwrap_or(line),
            _ => {}
        }
    }
    line
}

fn lookup_bound_u32(
    sections: &BTreeMap<String, BTreeMap<String, String>>,
    prefix: &str,
    keys: &[&str],
    default: u32,
    kind: LimitKind,
) -> Result<u32, ShellLimitsError> {
    for &key in keys {
        if let Some(raw) = sections.get(prefix).and_then(|m| m.get(key)) {
            return parse_toml_u32(raw, kind);
        }
        let sub = format!("{prefix}.{key}");
        if let Some(raw) = sections.get(&sub).and_then(|m| m.get("value")) {
            return parse_toml_u32(raw, kind);
        }
    }
    Ok(default)
}

fn parse_toml_u32(raw: &str, kind: LimitKind) -> Result<u32, ShellLimitsError> {
    let clean = raw.trim().replace('_', "");
    match clean.parse::<u64>() {
        Ok(0) => Err(ShellLimitsError::ZeroLimit(kind)),
        Ok(v) => u32::try_from(v).map_err(|_| ShellLimitsError::OutOfRange(kind)),
        Err(_) => Err(ShellLimitsError::OutOfRange(kind)),
    }
}

fn lookup_bound_usize(
    sections: &BTreeMap<String, BTreeMap<String, String>>,
    prefix: &str,
    keys: &[&str],
    default: usize,
) -> Option<usize> {
    for &key in keys {
        if let Some(raw) = sections.get(prefix).and_then(|m| m.get(key)) {
            return raw.trim().replace('_', "").parse::<usize>().ok();
        }
        let sub = format!("{prefix}.{key}");
        if let Some(raw) = sections.get(&sub).and_then(|m| m.get("value")) {
            return raw.trim().replace('_', "").parse::<usize>().ok();
        }
    }
    Some(default)
}
