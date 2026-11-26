// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::error::ProtoError;
use crate::inflate::{adler32, crc32_ieee, inflate_raw_bounded};
use crate::strict_json::MAX_DECOMPRESSION_RATIO;

const MAX_CHAINED_ENCODINGS: usize = 2;
const ZSTD_MAGIC: u32 = 0xFD2F_B528;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentEncodingKind {
    Identity,
    Gzip,
    Deflate,
    Zlib,
    Zstd,
    Brotli,
    Unknown,
}

pub fn parse_content_encoding_header(header: &str) -> Result<Vec<ContentEncodingKind>, ProtoError> {
    let mut kinds = Vec::new();
    for raw in header.split(',') {
        let token = raw.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        let kind = match token.as_str() {
            "identity" => ContentEncodingKind::Identity,
            "gzip" | "x-gzip" => ContentEncodingKind::Gzip,
            "deflate" => ContentEncodingKind::Deflate,
            "zlib" => ContentEncodingKind::Zlib,
            "zstd" => ContentEncodingKind::Zstd,
            "br" => ContentEncodingKind::Brotli,
            _ => {
                return Err(ProtoError::DecompressionRejected(
                    "unknown content encoding",
                ));
            }
        };
        if kind != ContentEncodingKind::Identity {
            kinds.push(kind);
        }
    }
    if kinds.len() > MAX_CHAINED_ENCODINGS {
        return Err(ProtoError::DecompressionRejected(
            "excessive chained content encodings",
        ));
    }
    Ok(kinds)
}

pub fn decompress_bounded(
    raw: &[u8],
    encodings: &[ContentEncodingKind],
    max_output_bytes: usize,
    max_ratio: usize,
) -> Result<Vec<u8>, ProtoError> {
    let ratio = if max_ratio == 0 {
        MAX_DECOMPRESSION_RATIO
    } else {
        max_ratio
    };
    if encodings.is_empty() {
        if raw.len() > max_output_bytes {
            return Err(ProtoError::PayloadTooLarge);
        }
        return Ok(raw.to_vec());
    }
    if raw.is_empty() {
        return Err(ProtoError::DecompressionRejected(
            "empty compressed payload",
        ));
    }
    let total_budget = max_output_bytes.min(raw.len().saturating_mul(ratio));
    let mut current = raw.to_vec();
    for &kind in encodings.iter().rev() {
        current = match kind {
            ContentEncodingKind::Identity => current,
            ContentEncodingKind::Gzip => decompress_gzip_bounded(&current, total_budget)?,
            ContentEncodingKind::Deflate => decompress_deflate_auto(&current, total_budget)?,
            ContentEncodingKind::Zlib => decompress_zlib_bounded(&current, total_budget)?,
            ContentEncodingKind::Zstd => decompress_zstd_bounded(&current, total_budget)?,
            ContentEncodingKind::Brotli | ContentEncodingKind::Unknown => {
                return Err(ProtoError::DecompressionRejected(
                    "unsupported compressed encoding",
                ));
            }
        };
    }
    Ok(current)
}

fn decompress_gzip_bounded(input: &[u8], budget: usize) -> Result<Vec<u8>, ProtoError> {
    if input.len() < 18 {
        return Err(ProtoError::DecompressionRejected("truncated gzip stream"));
    }
    if input.get(0..3) != Some([0x1F, 0x8B, 0x08].as_slice()) {
        return Err(ProtoError::DecompressionRejected("invalid gzip header"));
    }
    let flg = input.get(3).copied().unwrap_or(0);
    let mut pos: usize = 10;
    if flg & 0x04 != 0 {
        let lo = u16::from(
            input
                .get(pos)
                .copied()
                .ok_or(ProtoError::DecompressionRejected("gzip extra len"))?,
        );
        let hi = u16::from(
            input
                .get(pos.saturating_add(1))
                .copied()
                .ok_or(ProtoError::DecompressionRejected("gzip extra len"))?,
        );
        pos = pos
            .saturating_add(2)
            .saturating_add(usize::from(lo | (hi << 8)));
    }
    if flg & 0x08 != 0 {
        pos = advance_cstr(input, pos)?;
    }
    if flg & 0x10 != 0 {
        pos = advance_cstr(input, pos)?;
    }
    if flg & 0x02 != 0 {
        let crc_lo = *input
            .get(pos)
            .ok_or(ProtoError::DecompressionRejected("truncated gzip fhcrc"))?;
        let crc_hi = *input
            .get(pos.saturating_add(1))
            .ok_or(ProtoError::DecompressionRejected("truncated gzip fhcrc"))?;
        let expected_crc16 = u16::from_le_bytes([crc_lo, crc_hi]);
        let hdr_prefix = input
            .get(..pos)
            .ok_or(ProtoError::DecompressionRejected("gzip fhcrc slice"))?;
        let actual_crc16 = u16::try_from(crc32_ieee(hdr_prefix) & 0xFFFF).unwrap_or(0);
        if actual_crc16 != expected_crc16 {
            return Err(ProtoError::DecompressionRejected("gzip fhcrc mismatch"));
        }
        pos = pos.saturating_add(2);
    }
    let trailer_start = input.len().saturating_sub(8);
    if pos > trailer_start {
        return Err(ProtoError::DecompressionRejected(
            "invalid gzip header bounds",
        ));
    }
    let deflate_slice = input
        .get(pos..trailer_start)
        .ok_or(ProtoError::DecompressionRejected("missing deflate payload"))?;
    let out = inflate_raw_bounded(deflate_slice, budget)?;
    verify_gzip_trailer(input, trailer_start, &out)?;
    Ok(out)
}

fn verify_gzip_trailer(input: &[u8], trailer_start: usize, out: &[u8]) -> Result<(), ProtoError> {
    let expected_crc = read_le_u32(input, trailer_start)
        .ok_or(ProtoError::DecompressionRejected("missing gzip crc"))?;
    if crc32_ieee(out) != expected_crc {
        return Err(ProtoError::DecompressionRejected("gzip crc32 mismatch"));
    }
    let declared_size = read_le_u32(input, trailer_start.saturating_add(4))
        .ok_or(ProtoError::DecompressionRejected("missing gzip isize"))?;
    let actual_mod = u64::try_from(out.len()).ok().map(|n| n % (1_u64 << 32));
    if actual_mod != Some(u64::from(declared_size)) {
        return Err(ProtoError::DecompressionRejected("gzip isize mismatch"));
    }
    Ok(())
}

fn read_le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let slice = data.get(offset..offset.saturating_add(4))?;
    Some(u32::from_le_bytes([
        slice.first().copied()?,
        slice.get(1).copied()?,
        slice.get(2).copied()?,
        slice.get(3).copied()?,
    ]))
}

fn advance_cstr(input: &[u8], mut pos: usize) -> Result<usize, ProtoError> {
    while let Some(&b) = input.get(pos) {
        pos = pos.saturating_add(1);
        if b == 0 {
            return Ok(pos);
        }
    }
    Err(ProtoError::DecompressionRejected(
        "unterminated gzip header field",
    ))
}

fn decompress_deflate_auto(input: &[u8], budget: usize) -> Result<Vec<u8>, ProtoError> {
    if is_zlib_header(input) {
        decompress_zlib_bounded(input, budget)
    } else {
        inflate_raw_bounded(input, budget)
    }
}

fn is_zlib_header(input: &[u8]) -> bool {
    let Some(cmf) = input.first().copied() else {
        return false;
    };
    let Some(flg) = input.get(1).copied() else {
        return false;
    };
    let check = (u16::from(cmf) << 8) | u16::from(flg);
    (cmf & 0x0F) == 8 && (flg & 0x20) == 0 && check % 31 == 0 && input.len() >= 6
}

fn decompress_zlib_bounded(input: &[u8], budget: usize) -> Result<Vec<u8>, ProtoError> {
    if !is_zlib_header(input) {
        return Err(ProtoError::DecompressionRejected("invalid zlib header"));
    }
    let trailer_start = input.len().saturating_sub(4);
    let slice = input
        .get(2..trailer_start)
        .ok_or(ProtoError::DecompressionRejected("truncated zlib payload"))?;
    let out = inflate_raw_bounded(slice, budget)?;
    let trailer = input
        .get(trailer_start..trailer_start.saturating_add(4))
        .ok_or(ProtoError::DecompressionRejected("missing zlib adler32"))?;
    let expected = u32::from_be_bytes([
        trailer.first().copied().unwrap_or(0),
        trailer.get(1).copied().unwrap_or(0),
        trailer.get(2).copied().unwrap_or(0),
        trailer.get(3).copied().unwrap_or(0),
    ]);
    if adler32(&out) != expected {
        return Err(ProtoError::DecompressionRejected("zlib adler32 mismatch"));
    }
    Ok(out)
}

fn decompress_zstd_bounded(input: &[u8], budget: usize) -> Result<Vec<u8>, ProtoError> {
    if input.len() < 5 || read_le_u32(input, 0) != Some(ZSTD_MAGIC) {
        return Err(ProtoError::DecompressionRejected("invalid zstd magic"));
    }
    let desc = input.get(4).copied().unwrap_or(0);
    let fcs_flag = (desc >> 6) & 0x03;
    let single_segment = (desc & 0x20) != 0;
    let dict_flag = desc & 0x03;
    let has_checksum = (desc & 0x04) != 0;
    let mut pos: usize = if single_segment { 5 } else { 6 };
    pos = pos.saturating_add(match dict_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    });
    let fcs_bytes = match (fcs_flag, single_segment) {
        (0, true) => 1,
        (0, false) => 0,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    let mut declared_size: Option<u64> = None;
    if fcs_bytes > 0 {
        let fcs = input
            .get(pos..pos.saturating_add(fcs_bytes))
            .ok_or(ProtoError::DecompressionRejected("truncated zstd fcs"))?;
        let mut declared: u64 = 0;
        for (idx, &b) in fcs.iter().enumerate() {
            declared |= u64::from(b) << idx.saturating_mul(8);
        }
        if fcs_flag == 1 {
            declared = declared.saturating_add(256);
        }
        if declared > u64::try_from(budget).unwrap_or(u64::MAX) {
            return Err(ProtoError::DecompressionRejected(
                "zstd declared size exceeds budget",
            ));
        }
        declared_size = Some(declared);
        pos = pos.saturating_add(fcs_bytes);
    }
    decode_zstd_blocks(input, pos, has_checksum, declared_size, budget)
}

fn decode_zstd_blocks(
    input: &[u8],
    mut pos: usize,
    has_checksum: bool,
    declared_size: Option<u64>,
    budget: usize,
) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::new();
    let end_limit = if has_checksum {
        if input.len() < pos.saturating_add(4) {
            return Err(ProtoError::DecompressionRejected("truncated zstd checksum"));
        }
        input.len().saturating_sub(4)
    } else {
        input.len()
    };
    let mut saw_last_block = false;
    while pos < end_limit {
        let hdr =
            input
                .get(pos..pos.saturating_add(3))
                .ok_or(ProtoError::DecompressionRejected(
                    "truncated zstd block header",
                ))?;
        pos = pos.saturating_add(3);
        let raw_hdr = u32::from(hdr.first().copied().unwrap_or(0))
            | (u32::from(hdr.get(1).copied().unwrap_or(0)) << 8)
            | (u32::from(hdr.get(2).copied().unwrap_or(0)) << 16);
        let last_block = (raw_hdr & 1) != 0;
        let block_type = (raw_hdr >> 1) & 3;
        let block_size = usize::try_from(raw_hdr >> 3).unwrap_or(usize::MAX);
        match block_type {
            0 => {
                if out.len().saturating_add(block_size) > budget {
                    return Err(ProtoError::DecompressionRejected(
                        "zstd raw block exceeds budget",
                    ));
                }
                let slice = input.get(pos..pos.saturating_add(block_size)).ok_or(
                    ProtoError::DecompressionRejected("truncated zstd raw block"),
                )?;
                out.extend_from_slice(slice);
                pos = pos.saturating_add(block_size);
            }
            1 => {
                if out.len().saturating_add(block_size) > budget {
                    return Err(ProtoError::DecompressionRejected(
                        "zstd rle block exceeds budget",
                    ));
                }
                let byte = input
                    .get(pos)
                    .copied()
                    .ok_or(ProtoError::DecompressionRejected("truncated zstd rle byte"))?;
                pos = pos.saturating_add(1);
                out.resize(out.len().saturating_add(block_size), byte);
            }
            _ => {
                return Err(ProtoError::DecompressionRejected(
                    "compressed zstd block rejected",
                ));
            }
        }
        if last_block {
            saw_last_block = true;
            break;
        }
    }
    if !saw_last_block || pos != end_limit {
        return Err(ProtoError::DecompressionRejected(
            "zstd missing last block or trailing unconsumed bytes",
        ));
    }
    if let Some(expected_len) = declared_size
        && u64::try_from(out.len()).ok() != Some(expected_len)
    {
        return Err(ProtoError::DecompressionRejected(
            "zstd decompressed size mismatches frame header",
        ));
    }
    if has_checksum {
        let expected = read_le_u32(input, end_limit)
            .ok_or(ProtoError::DecompressionRejected("missing zstd checksum"))?;
        let actual = u32::try_from(xxh64(&out, 0) & 0xFFFF_FFFF).unwrap_or(0);
        if actual != expected {
            return Err(ProtoError::DecompressionRejected(
                "zstd xxhash64 checksum mismatch",
            ));
        }
    }
    Ok(out)
}

fn xxh64(data: &[u8], seed: u64) -> u64 {
    const P1: u64 = 0x9E37_79B1_85EB_CA87;
    const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const P3: u64 = 0x1656_67B1_9E37_79F9;
    const P4: u64 = 0x85EB_CA77_C2B2_AE63;
    const P5: u64 = 0x27D4_EB2F_1656_67C5;
    let round = |acc: u64, lane: u64| -> u64 {
        acc.wrapping_add(lane.wrapping_mul(P2))
            .rotate_left(31)
            .wrapping_mul(P1)
    };
    let merge_round = |mut acc: u64, val: u64| -> u64 {
        acc ^= round(0, val);
        acc.wrapping_mul(P1).wrapping_add(P4)
    };
    let read_u64 = |idx: usize| -> u64 {
        let s = data.get(idx..idx.saturating_add(8)).unwrap_or(&[]);
        u64::from_le_bytes([
            s.first().copied().unwrap_or(0),
            s.get(1).copied().unwrap_or(0),
            s.get(2).copied().unwrap_or(0),
            s.get(3).copied().unwrap_or(0),
            s.get(4).copied().unwrap_or(0),
            s.get(5).copied().unwrap_or(0),
            s.get(6).copied().unwrap_or(0),
            s.get(7).copied().unwrap_or(0),
        ])
    };
    let mut h: u64;
    let mut pos = 0usize;
    if data.len() >= 32 {
        let mut v1 = seed.wrapping_add(P1).wrapping_add(P2);
        let mut v2 = seed.wrapping_add(P2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(P1);
        while pos.saturating_add(32) <= data.len() {
            v1 = round(v1, read_u64(pos));
            v2 = round(v2, read_u64(pos.saturating_add(8)));
            v3 = round(v3, read_u64(pos.saturating_add(16)));
            v4 = round(v4, read_u64(pos.saturating_add(24)));
            pos = pos.saturating_add(32);
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = merge_round(h, v1);
        h = merge_round(h, v2);
        h = merge_round(h, v3);
        h = merge_round(h, v4);
    } else {
        h = seed.wrapping_add(P5);
    }
    h = h.wrapping_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    while pos.saturating_add(8) <= data.len() {
        h ^= round(0, read_u64(pos));
        h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        pos = pos.saturating_add(8);
    }
    while pos.saturating_add(4) <= data.len() {
        let u = u64::from(read_le_u32(data, pos).unwrap_or(0));
        h ^= u.wrapping_mul(P1);
        h = h.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
        pos = pos.saturating_add(4);
    }
    while let Some(&b) = data.get(pos) {
        h ^= u64::from(b).wrapping_mul(P5);
        h = h.rotate_left(11).wrapping_mul(P1);
        pos = pos.saturating_add(1);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^ (h >> 32)
}
