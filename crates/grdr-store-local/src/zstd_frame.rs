// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Bounded RFC 8878 Zstandard frame encoder and decoder (`recorder.db` payload compression).
//!
//! Produces standard Zstandard frames (`0xFD2FB528` magic, Single_Segment header with
//! explicit `Frame_Content_Size`, Raw/RLE blocks bounded at 128 KiB, and mandatory
//! low-32 XXH64 content checksum), verifying bounds incrementally and checking XXH64.

use thiserror::Error;

const ZSTD_MAGIC_LE: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const ZSTD_BLOCK_MAX_BYTES: usize = 128 * 1024;
const BLOCK_TYPE_RAW: u32 = 0;
const BLOCK_TYPE_RLE: u32 = 1;
const MIN_RLE_RUN: usize = 16;
const INITIAL_RESERVE_CAP: usize = 4096;
const MAX_EMPTY_BLOCKS: usize = 128;

const XXH_PRIME1: u64 = 0x9E37_79B1_85EB_CA87;
const XXH_PRIME2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const XXH_PRIME3: u64 = 0x1656_67B1_9E37_79F9;
const XXH_PRIME4: u64 = 0x85EB_CA77_C2B2_AE63;
const XXH_PRIME5: u64 = 0x27D4_EB2F_1656_67C5;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ZstdFrameError {
    #[error("GRDR-LSTORE-0004: payload length {len} exceeds u32 frame header limit")]
    InputTooLarge { len: usize },
    #[error("GRDR-LSTORE-0005: invalid or truncated RFC 8878 zstd frame: {detail}")]
    InvalidFrame { detail: String },
    #[error("GRDR-LSTORE-0006: zstd decoded size {decoded} exceeds limit {limit}")]
    DecompressedLimitExceeded { decoded: usize, limit: usize },
}

enum PlannedBlock<'a> {
    Raw(&'a [u8]),
    Rle { byte: u8, count: usize },
}

pub fn compress_zstd_frame(input: &[u8]) -> Result<Vec<u8>, ZstdFrameError> {
    let fcs = u32::try_from(input.len())
        .map_err(|_| ZstdFrameError::InputTooLarge { len: input.len() })?;
    let mut out = Vec::with_capacity(input.len().saturating_add(16));
    out.extend_from_slice(&ZSTD_MAGIC_LE);
    // Single_Segment_flag = 1 (0x20) | FCS_flag = 2 (0x80) | Content_Checksum_flag = 1 (0x04).
    out.push(0xA4);
    out.extend_from_slice(&fcs.to_le_bytes());

    if input.is_empty() {
        write_block_header(&mut out, true, BLOCK_TYPE_RAW, 0)?;
    } else {
        let chunks = plan_blocks(input);
        let last_idx = chunks.len().saturating_sub(1);
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let is_last = idx == last_idx;
            match chunk {
                PlannedBlock::Rle { byte, count } => {
                    let count_u32 = u32::try_from(count)
                        .map_err(|_| ZstdFrameError::InputTooLarge { len: count })?;
                    write_block_header(&mut out, is_last, BLOCK_TYPE_RLE, count_u32)?;
                    out.push(byte);
                }
                PlannedBlock::Raw(slice) => {
                    let len_u32 = u32::try_from(slice.len())
                        .map_err(|_| ZstdFrameError::InputTooLarge { len: slice.len() })?;
                    write_block_header(&mut out, is_last, BLOCK_TYPE_RAW, len_u32)?;
                    out.extend_from_slice(slice);
                }
            }
        }
    }

    let cksum_low32 = u32::try_from(xxh64(input, 0) & 0xFFFF_FFFF).unwrap_or(0);
    out.extend_from_slice(&cksum_low32.to_le_bytes());
    Ok(out)
}

pub fn decompress_zstd_frame(
    frame: &[u8],
    max_decompressed_bytes: usize,
) -> Result<Vec<u8>, ZstdFrameError> {
    let magic = frame.get(..4).ok_or_else(|| ZstdFrameError::InvalidFrame {
        detail: "truncated zstd magic".to_string(),
    })?;
    if magic != ZSTD_MAGIC_LE {
        return Err(ZstdFrameError::InvalidFrame {
            detail: "missing RFC 8878 magic 0xFD2FB528".to_string(),
        });
    }
    let fhd = *frame.get(4).ok_or_else(|| ZstdFrameError::InvalidFrame {
        detail: "missing frame header descriptor".to_string(),
    })?;
    if (fhd & 0x08) != 0 {
        return Err(ZstdFrameError::InvalidFrame {
            detail: "reserved bit set in frame header descriptor".to_string(),
        });
    }
    let has_checksum = (fhd & 0x04) != 0;
    let single_segment = (fhd & 0x20) != 0;
    let fcs_flag = (fhd >> 6) & 0x03;
    let dict_flag = fhd & 0x03;
    if dict_flag != 0 {
        return Err(ZstdFrameError::InvalidFrame {
            detail: "dictionary IDs unsupported".to_string(),
        });
    }

    let mut pos: usize = 5;
    if !single_segment {
        if frame.get(pos).is_none() {
            return Err(ZstdFrameError::InvalidFrame {
                detail: "missing window descriptor".to_string(),
            });
        }
        pos = pos.saturating_add(1);
    }

    let declared_size = read_frame_content_size(
        frame,
        &mut pos,
        single_segment,
        fcs_flag,
        max_decompressed_bytes,
    )?;
    if let Some(expected) = declared_size
        && expected > max_decompressed_bytes
    {
        return Err(ZstdFrameError::DecompressedLimitExceeded {
            decoded: expected,
            limit: max_decompressed_bytes,
        });
    }

    // Never allocate full `declared_size` before verifying actual blocks exist.
    let initial_cap = declared_size
        .unwrap_or(0)
        .min(max_decompressed_bytes)
        .min(INITIAL_RESERVE_CAP);
    let mut out = Vec::with_capacity(initial_cap);
    let mut zero_blocks: usize = 0;

    loop {
        let hdr_end = pos
            .checked_add(3)
            .ok_or_else(|| ZstdFrameError::InvalidFrame {
                detail: "block header offset overflow".to_string(),
            })?;
        let hdr = frame
            .get(pos..hdr_end)
            .ok_or_else(|| ZstdFrameError::InvalidFrame {
                detail: "truncated zstd block header".to_string(),
            })?;
        pos = hdr_end;

        let word = u32::from(hdr.first().copied().unwrap_or(0))
            | (u32::from(hdr.get(1).copied().unwrap_or(0)) << 8)
            | (u32::from(hdr.get(2).copied().unwrap_or(0)) << 16);
        let last_block = (word & 1) != 0;
        let block_type = (word >> 1) & 0x03;
        let block_size = usize::try_from(word >> 3).unwrap_or(usize::MAX);

        if block_type == 3 || block_size > ZSTD_BLOCK_MAX_BYTES {
            return Err(ZstdFrameError::InvalidFrame {
                detail: "invalid block type or oversized zstd block".to_string(),
            });
        }

        if block_size == 0 && !last_block {
            zero_blocks = zero_blocks.saturating_add(1);
            if zero_blocks > MAX_EMPTY_BLOCKS {
                return Err(ZstdFrameError::InvalidFrame {
                    detail: "excessive zero-length blocks in zstd frame".to_string(),
                });
            }
        }

        let next_total =
            out.len()
                .checked_add(block_size)
                .ok_or(ZstdFrameError::DecompressedLimitExceeded {
                    decoded: usize::MAX,
                    limit: max_decompressed_bytes,
                })?;
        if next_total > max_decompressed_bytes {
            return Err(ZstdFrameError::DecompressedLimitExceeded {
                decoded: next_total,
                limit: max_decompressed_bytes,
            });
        }
        if let Some(expected) = declared_size
            && next_total > expected
        {
            return Err(ZstdFrameError::InvalidFrame {
                detail: "decoded block exceeds Frame_Content_Size".to_string(),
            });
        }

        match block_type {
            BLOCK_TYPE_RAW => {
                let data_end =
                    pos.checked_add(block_size)
                        .ok_or_else(|| ZstdFrameError::InvalidFrame {
                            detail: "raw block offset overflow".to_string(),
                        })?;
                let slice =
                    frame
                        .get(pos..data_end)
                        .ok_or_else(|| ZstdFrameError::InvalidFrame {
                            detail: "truncated raw zstd block".to_string(),
                        })?;
                pos = data_end;
                out.extend_from_slice(slice);
            }
            BLOCK_TYPE_RLE => {
                let byte = *frame.get(pos).ok_or_else(|| ZstdFrameError::InvalidFrame {
                    detail: "truncated RLE zstd block".to_string(),
                })?;
                pos = pos.saturating_add(1);
                out.resize(next_total, byte);
            }
            2 => {
                return Err(ZstdFrameError::InvalidFrame {
                    detail: "compressed Huffman blocks unsupported by bounded codec".to_string(),
                });
            }
            _ => {
                return Err(ZstdFrameError::InvalidFrame {
                    detail: "reserved block type".to_string(),
                });
            }
        }

        if last_block {
            break;
        }
    }

    if has_checksum {
        let cksum_end = pos
            .checked_add(4)
            .ok_or_else(|| ZstdFrameError::InvalidFrame {
                detail: "checksum offset overflow".to_string(),
            })?;
        let cksum_slice =
            frame
                .get(pos..cksum_end)
                .ok_or_else(|| ZstdFrameError::InvalidFrame {
                    detail: "missing trailing RFC 8878 content checksum".to_string(),
                })?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(cksum_slice);
        let expected_cksum = u32::from_le_bytes(arr);
        let actual_cksum = u32::try_from(xxh64(&out, 0) & 0xFFFF_FFFF).unwrap_or(0);
        if actual_cksum != expected_cksum {
            return Err(ZstdFrameError::InvalidFrame {
                detail: "RFC 8878 content checksum mismatch".to_string(),
            });
        }
        pos = cksum_end;
    }
    if pos != frame.len() {
        return Err(ZstdFrameError::InvalidFrame {
            detail: "trailing bytes after RFC 8878 frame".to_string(),
        });
    }
    if let Some(expected) = declared_size
        && out.len() != expected
    {
        return Err(ZstdFrameError::InvalidFrame {
            detail: format!(
                "decoded length {} != Frame_Content_Size {expected}",
                out.len()
            ),
        });
    }
    Ok(out)
}

#[must_use]
pub fn xxh64(input: &[u8], seed: u64) -> u64 {
    let mut h: u64 = if input.len() >= 32 {
        let mut v1 = seed.wrapping_add(XXH_PRIME1).wrapping_add(XXH_PRIME2);
        let mut v2 = seed.wrapping_add(XXH_PRIME2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(XXH_PRIME1);

        let mut offset = 0usize;
        while offset.saturating_add(32) <= input.len() {
            v1 = xxh64_round(v1, read_le_u64(input, offset));
            v2 = xxh64_round(v2, read_le_u64(input, offset.saturating_add(8)));
            v3 = xxh64_round(v3, read_le_u64(input, offset.saturating_add(16)));
            v4 = xxh64_round(v4, read_le_u64(input, offset.saturating_add(24)));
            offset = offset.saturating_add(32);
        }

        let mut merged = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        merged = xxh64_merge_round(merged, v1);
        merged = xxh64_merge_round(merged, v2);
        merged = xxh64_merge_round(merged, v3);
        xxh64_merge_round(merged, v4)
    } else {
        seed.wrapping_add(XXH_PRIME5)
    };

    h = h.wrapping_add(u64::try_from(input.len()).unwrap_or(u64::MAX));
    let mut pos = input.len() & !31usize;

    while pos.saturating_add(8) <= input.len() {
        let k1 = xxh64_round(0, read_le_u64(input, pos));
        h ^= k1;
        h = h
            .rotate_left(27)
            .wrapping_mul(XXH_PRIME1)
            .wrapping_add(XXH_PRIME4);
        pos = pos.saturating_add(8);
    }
    if pos.saturating_add(4) <= input.len() {
        let lane = u64::from(read_le_u32(input, pos));
        h ^= lane.wrapping_mul(XXH_PRIME1);
        h = h
            .rotate_left(23)
            .wrapping_mul(XXH_PRIME2)
            .wrapping_add(XXH_PRIME3);
        pos = pos.saturating_add(4);
    }
    while pos < input.len() {
        let b = u64::from(input.get(pos).copied().unwrap_or(0));
        h ^= b.wrapping_mul(XXH_PRIME5);
        h = h.rotate_left(11).wrapping_mul(XXH_PRIME1);
        pos = pos.saturating_add(1);
    }

    h ^= h >> 33;
    h = h.wrapping_mul(XXH_PRIME2);
    h ^= h >> 29;
    h = h.wrapping_mul(XXH_PRIME3);
    h ^ (h >> 32)
}

const fn xxh64_round(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(XXH_PRIME2))
        .rotate_left(31)
        .wrapping_mul(XXH_PRIME1)
}

const fn xxh64_merge_round(acc: u64, val: u64) -> u64 {
    (acc ^ xxh64_round(0, val))
        .wrapping_mul(XXH_PRIME1)
        .wrapping_add(XXH_PRIME4)
}

fn read_le_u64(src: &[u8], offset: usize) -> u64 {
    let mut arr = [0u8; 8];
    if let Some(slice) = src.get(offset..offset.saturating_add(8)) {
        arr.copy_from_slice(slice);
    }
    u64::from_le_bytes(arr)
}

fn read_le_u32(src: &[u8], offset: usize) -> u32 {
    let mut arr = [0u8; 4];
    if let Some(slice) = src.get(offset..offset.saturating_add(4)) {
        arr.copy_from_slice(slice);
    }
    u32::from_le_bytes(arr)
}

fn plan_blocks(input: &[u8]) -> Vec<PlannedBlock<'_>> {
    let mut blocks = Vec::new();
    let mut raw_start = 0usize;
    let mut i = 0usize;
    while i < input.len() {
        let Some(&b) = input.get(i) else {
            break;
        };
        let mut run = 1usize;
        while run < ZSTD_BLOCK_MAX_BYTES && input.get(i.saturating_add(run)) == Some(&b) {
            run = run.saturating_add(1);
        }
        if run >= MIN_RLE_RUN {
            push_raw_chunks(&mut blocks, input.get(raw_start..i).unwrap_or(&[]));
            blocks.push(PlannedBlock::Rle {
                byte: b,
                count: run,
            });
            i = i.saturating_add(run);
            raw_start = i;
        } else {
            i = i.saturating_add(1);
        }
    }
    push_raw_chunks(&mut blocks, input.get(raw_start..).unwrap_or(&[]));
    blocks
}

fn push_raw_chunks<'a>(out: &mut Vec<PlannedBlock<'a>>, slice: &'a [u8]) {
    if slice.is_empty() {
        return;
    }
    for chunk in slice.chunks(ZSTD_BLOCK_MAX_BYTES) {
        out.push(PlannedBlock::Raw(chunk));
    }
}

fn write_block_header(
    out: &mut Vec<u8>,
    last_block: bool,
    block_type: u32,
    size: u32,
) -> Result<(), ZstdFrameError> {
    if usize::try_from(size).unwrap_or(usize::MAX) > ZSTD_BLOCK_MAX_BYTES {
        return Err(ZstdFrameError::InputTooLarge {
            len: usize::try_from(size).unwrap_or(usize::MAX),
        });
    }
    let last_bit: u32 = u32::from(last_block);
    let word = last_bit | ((block_type & 0x03) << 1) | (size << 3);
    let bytes = word.to_le_bytes();
    out.extend_from_slice(bytes.get(..3).unwrap_or(&[0, 0, 0]));
    Ok(())
}

fn read_frame_content_size(
    frame: &[u8],
    pos: &mut usize,
    single_segment: bool,
    fcs_flag: u8,
    max_decompressed_bytes: usize,
) -> Result<Option<usize>, ZstdFrameError> {
    let field_len = match (single_segment, fcs_flag) {
        (false, 0) => return Ok(None),
        (true, 0) => 1usize,
        (_, 1) => 2usize,
        (_, 2) => 4usize,
        (_, 3) => 8usize,
        _ => return Ok(None),
    };
    let end = pos
        .checked_add(field_len)
        .ok_or_else(|| ZstdFrameError::InvalidFrame {
            detail: "frame content size offset overflow".to_string(),
        })?;
    let raw = frame
        .get(*pos..end)
        .ok_or_else(|| ZstdFrameError::InvalidFrame {
            detail: "truncated frame content size".to_string(),
        })?;
    *pos = end;
    let size = match field_len {
        1 => usize::from(*raw.first().unwrap_or(&0)),
        2 => {
            let mut arr = [0u8; 2];
            arr.copy_from_slice(raw);
            usize::from(u16::from_le_bytes(arr)).saturating_add(256)
        }
        4 => {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(raw);
            usize::try_from(u32::from_le_bytes(arr)).map_err(|_| {
                ZstdFrameError::DecompressedLimitExceeded {
                    decoded: usize::MAX,
                    limit: max_decompressed_bytes,
                }
            })?
        }
        8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(raw);
            usize::try_from(u64::from_le_bytes(arr)).map_err(|_| {
                ZstdFrameError::DecompressedLimitExceeded {
                    decoded: usize::MAX,
                    limit: max_decompressed_bytes,
                }
            })?
        }
        _ => 0,
    };
    Ok(Some(size))
}
