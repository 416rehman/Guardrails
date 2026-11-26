// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pure-Rust bounded RFC 1952/1951 gunzip decompressor with CRC-32/ISIZE and multi-member support.

use crate::analyze::huffman::{BitReader, FIXED_TABLES, HuffmanTable, TreeKind};
use crate::analyze::types::AnalyzeLimits;

const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GunzipErr {
    Malformed,
    LimitExceeded,
}

struct InflateBudgets {
    max_output: usize,
    max_blocks: usize,
    max_empty_blocks: usize,
    blocks: usize,
    empty_blocks: usize,
}

/// Bounded RFC 1952 multi-member gzip decompression verifying FHCRC, CRC-32, ISIZE, and trailing bytes.
pub fn gunzip_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, GunzipErr> {
    let limits = AnalyzeLimits::from_schema();
    if max_output == 0 {
        return Err(GunzipErr::LimitExceeded);
    }
    let mut cursor: usize = 0;
    let mut members: usize = 0;
    let mut total_out = Vec::new();
    let mut budgets = InflateBudgets {
        max_output,
        max_blocks: limits.deflate_max_blocks,
        max_empty_blocks: limits.deflate_max_empty_blocks,
        blocks: 0,
        empty_blocks: 0,
    };

    loop {
        members = members.saturating_add(1);
        if members > limits.deflate_max_members {
            return Err(GunzipErr::LimitExceeded);
        }
        let deflate_start = parse_gzip_header(input, cursor)?;
        let member_start_out = total_out.len();
        let deflate_end = inflate_member(
            input,
            deflate_start,
            &mut total_out,
            member_start_out,
            &mut budgets,
        )?;
        let trailer_end = deflate_end.saturating_add(8);
        let trailer = input
            .get(deflate_end..trailer_end)
            .ok_or(GunzipErr::Malformed)?;
        let expected_crc = read_u32_le(trailer, 0)?;
        let expected_isize = read_u32_le(trailer, 4)?;
        let member_bytes = total_out
            .get(member_start_out..)
            .ok_or(GunzipErr::Malformed)?;
        if crc32_ieee(member_bytes) != expected_crc {
            return Err(GunzipErr::Malformed);
        }
        let actual_isize =
            u32::try_from(member_bytes.len() & 0xFFFF_FFFF).map_err(|_| GunzipErr::Malformed)?;
        if actual_isize != expected_isize {
            return Err(GunzipErr::Malformed);
        }
        cursor = trailer_end;
        if cursor >= input.len() {
            break;
        }
    }
    Ok(total_out)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, GunzipErr> {
    Ok(u32::from_le_bytes([
        *bytes.get(offset).ok_or(GunzipErr::Malformed)?,
        *bytes
            .get(offset.saturating_add(1))
            .ok_or(GunzipErr::Malformed)?,
        *bytes
            .get(offset.saturating_add(2))
            .ok_or(GunzipErr::Malformed)?,
        *bytes
            .get(offset.saturating_add(3))
            .ok_or(GunzipErr::Malformed)?,
    ]))
}

fn parse_gzip_header(input: &[u8], start: usize) -> Result<usize, GunzipErr> {
    let hdr_end = start.saturating_add(10);
    if hdr_end > input.len()
        || input.get(start) != Some(&0x1F)
        || input.get(start.saturating_add(1)) != Some(&0x8B)
        || input.get(start.saturating_add(2)) != Some(&0x08)
    {
        return Err(GunzipErr::Malformed);
    }
    let flags = *input
        .get(start.saturating_add(3))
        .ok_or(GunzipErr::Malformed)?;
    if (flags & 0xE0) != 0 {
        return Err(GunzipErr::Malformed);
    }
    let mut offset = hdr_end;

    if (flags & 0x04) != 0 {
        let l0 = *input.get(offset).ok_or(GunzipErr::Malformed)?;
        let l1 = *input
            .get(offset.saturating_add(1))
            .ok_or(GunzipErr::Malformed)?;
        offset = offset
            .saturating_add(2)
            .saturating_add(usize::from(u16::from_le_bytes([l0, l1])));
    }
    if (flags & 0x08) != 0 {
        offset = skip_nul_terminated(input, offset).ok_or(GunzipErr::Malformed)?;
    }
    if (flags & 0x10) != 0 {
        offset = skip_nul_terminated(input, offset).ok_or(GunzipErr::Malformed)?;
    }
    if (flags & 0x02) != 0 {
        let h0 = *input.get(offset).ok_or(GunzipErr::Malformed)?;
        let h1 = *input
            .get(offset.saturating_add(1))
            .ok_or(GunzipErr::Malformed)?;
        let hdr_bytes = input.get(start..offset).ok_or(GunzipErr::Malformed)?;
        let expected_hcrc = u16::from_le_bytes([h0, h1]);
        let computed_hcrc =
            u16::try_from(crc32_ieee(hdr_bytes) & 0xFFFF).map_err(|_| GunzipErr::Malformed)?;
        if expected_hcrc != computed_hcrc {
            return Err(GunzipErr::Malformed);
        }
        offset = offset.saturating_add(2);
    }
    if offset > input.len() {
        return Err(GunzipErr::Malformed);
    }
    Ok(offset)
}

fn inflate_member(
    input: &[u8],
    start_offset: usize,
    out: &mut Vec<u8>,
    member_start_out: usize,
    budgets: &mut InflateBudgets,
) -> Result<usize, GunzipErr> {
    let mut reader = BitReader::new(input, start_offset);
    loop {
        budgets.blocks = budgets.blocks.saturating_add(1);
        if budgets.blocks > budgets.max_blocks {
            return Err(GunzipErr::LimitExceeded);
        }
        let block_start_len = out.len();
        let bfinal = reader.read_bits(1)?;
        let btype = reader.read_bits(2)?;
        match btype {
            0 => {
                let len_u16 = reader.read_u16_le_aligned()?;
                let nlen = reader.read_u16_le_aligned()?;
                if len_u16 ^ nlen != 0xFFFF {
                    return Err(GunzipErr::Malformed);
                }
                let len = usize::from(len_u16);
                let remaining = budgets.max_output.saturating_sub(out.len());
                if len > remaining {
                    return Err(GunzipErr::LimitExceeded);
                }
                out.try_reserve(len).map_err(|_| GunzipErr::LimitExceeded)?;
                reader.copy_aligned_bytes(len, out)?;
            }
            1 => {
                let (lit_table, dist_table) = FIXED_TABLES.as_ref().ok_or(GunzipErr::Malformed)?;
                decode_huffman_block(
                    &mut reader,
                    lit_table,
                    dist_table,
                    out,
                    member_start_out,
                    budgets.max_output,
                )?;
            }
            2 => {
                let (lit_table, dist_table) = read_dynamic_tables(&mut reader)?;
                decode_huffman_block(
                    &mut reader,
                    &lit_table,
                    &dist_table,
                    out,
                    member_start_out,
                    budgets.max_output,
                )?;
            }
            _ => return Err(GunzipErr::Malformed),
        }
        if out.len() == block_start_len {
            budgets.empty_blocks = budgets.empty_blocks.saturating_add(1);
            if budgets.empty_blocks > budgets.max_empty_blocks {
                return Err(GunzipErr::LimitExceeded);
            }
        }
        if bfinal == 1 {
            break;
        }
    }
    reader.align_to_byte();
    reader.exact_byte_pos()
}

fn read_dynamic_tables(
    reader: &mut BitReader<'_>,
) -> Result<(HuffmanTable, HuffmanTable), GunzipErr> {
    let hlit = usize::try_from(reader.read_bits(5)?)
        .unwrap_or(0)
        .saturating_add(257);
    let hdist = usize::try_from(reader.read_bits(5)?)
        .unwrap_or(0)
        .saturating_add(1);
    let hclen = usize::try_from(reader.read_bits(4)?)
        .unwrap_or(0)
        .saturating_add(4);
    if hlit > 286 || hdist > 30 || hclen > 19 {
        return Err(GunzipErr::Malformed);
    }
    let mut cl_lengths = [0_u8; 19];
    for &idx in CL_ORDER.iter().take(hclen) {
        let v = u8::try_from(reader.read_bits(3)?).map_err(|_| GunzipErr::Malformed)?;
        if let Some(slot) = cl_lengths.get_mut(idx) {
            *slot = v;
        }
    }
    let cl_table = HuffmanTable::from_lengths(&cl_lengths, TreeKind::CodeLengths)?;
    let total = hlit.saturating_add(hdist);
    let mut lengths = Vec::with_capacity(total);
    while lengths.len() < total {
        let sym = cl_table.decode(reader)?;
        match sym {
            0..=15 => lengths.push(u8::try_from(sym).map_err(|_| GunzipErr::Malformed)?),
            16 => {
                let prev = *lengths.last().ok_or(GunzipErr::Malformed)?;
                let repeat = usize::try_from(reader.read_bits(2)?)
                    .unwrap_or(0)
                    .saturating_add(3);
                push_repeat(&mut lengths, prev, repeat, total)?;
            }
            17 => {
                let repeat = usize::try_from(reader.read_bits(3)?)
                    .unwrap_or(0)
                    .saturating_add(3);
                push_repeat(&mut lengths, 0, repeat, total)?;
            }
            18 => {
                let repeat = usize::try_from(reader.read_bits(7)?)
                    .unwrap_or(0)
                    .saturating_add(11);
                push_repeat(&mut lengths, 0, repeat, total)?;
            }
            _ => return Err(GunzipErr::Malformed),
        }
    }
    let lit_slice = lengths.get(..hlit).ok_or(GunzipErr::Malformed)?;
    let dist_slice = lengths.get(hlit..).ok_or(GunzipErr::Malformed)?;
    Ok((
        HuffmanTable::from_lengths(lit_slice, TreeKind::LitLen)?,
        HuffmanTable::from_lengths(dist_slice, TreeKind::Distance)?,
    ))
}

fn push_repeat(out: &mut Vec<u8>, val: u8, count: usize, total: usize) -> Result<(), GunzipErr> {
    for _ in 0..count {
        if out.len() >= total {
            return Err(GunzipErr::Malformed);
        }
        out.push(val);
    }
    Ok(())
}

fn decode_huffman_block(
    reader: &mut BitReader<'_>,
    lit_table: &HuffmanTable,
    dist_table: &HuffmanTable,
    out: &mut Vec<u8>,
    member_start_out: usize,
    max_output: usize,
) -> Result<(), GunzipErr> {
    loop {
        let sym = lit_table.decode(reader)?;
        if sym < 256 {
            if out.len() >= max_output {
                return Err(GunzipErr::LimitExceeded);
            }
            out.push(u8::try_from(sym).map_err(|_| GunzipErr::Malformed)?);
            continue;
        }
        if sym == 256 {
            return Ok(());
        }
        let len_idx = usize::from(sym)
            .checked_sub(257)
            .ok_or(GunzipErr::Malformed)?;
        let base_len = *LEN_BASE.get(len_idx).ok_or(GunzipErr::Malformed)?;
        let extra_len_bits = *LEN_EXTRA.get(len_idx).ok_or(GunzipErr::Malformed)?;
        let extra_len = u16::try_from(reader.read_bits(extra_len_bits)?).unwrap_or(0);
        let match_len = usize::from(base_len.saturating_add(extra_len));

        let dist_idx = usize::from(dist_table.decode(reader)?);
        let base_dist = *DIST_BASE.get(dist_idx).ok_or(GunzipErr::Malformed)?;
        let extra_dist_bits = *DIST_EXTRA.get(dist_idx).ok_or(GunzipErr::Malformed)?;
        let extra_dist = u16::try_from(reader.read_bits(extra_dist_bits)?).unwrap_or(0);
        let match_dist = usize::from(base_dist.saturating_add(extra_dist));

        let member_len = out.len().saturating_sub(member_start_out);
        if match_dist == 0 || match_dist > member_len {
            return Err(GunzipErr::Malformed);
        }
        let remaining = max_output.saturating_sub(out.len());
        if match_len > remaining {
            return Err(GunzipErr::LimitExceeded);
        }
        out.try_reserve(match_len)
            .map_err(|_| GunzipErr::LimitExceeded)?;
        for _ in 0..match_len {
            let src_idx = out.len().saturating_sub(match_dist);
            let byte = *out.get(src_idx).ok_or(GunzipErr::Malformed)?;
            out.push(byte);
        }
    }
}

fn skip_nul_terminated(input: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    while cursor < input.len() {
        if input.get(cursor) == Some(&0) {
            return Some(cursor.saturating_add(1));
        }
        cursor = cursor.saturating_add(1);
    }
    None
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320_u32 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stored_gzip_member(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF];
        let len = u16::try_from(payload.len()).expect("len fits u16");
        let nlen = !len;
        out.push(0x01);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&crc32_ieee(payload).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out
    }

    #[test]
    fn multi_member_gzip_and_crc_isize_validation_work() {
        let mut combined = make_stored_gzip_member(b"curl ");
        combined.extend_from_slice(&make_stored_gzip_member(b"http://evil.test"));
        let decoded = gunzip_bounded(&combined, 1024).expect("multi-member gzip decodes");
        assert_eq!(decoded, b"curl http://evil.test");

        let mut bad_crc = make_stored_gzip_member(b"hello");
        let last_idx = bad_crc.len() - 5;
        bad_crc[last_idx] ^= 0xFF;
        assert_eq!(gunzip_bounded(&bad_crc, 1024), Err(GunzipErr::Malformed));

        let mut bad_isize = make_stored_gzip_member(b"hello");
        let end_idx = bad_isize.len() - 1;
        bad_isize[end_idx] ^= 0x01;
        assert_eq!(gunzip_bounded(&bad_isize, 1024), Err(GunzipErr::Malformed));

        let mut with_trailing = make_stored_gzip_member(b"hello");
        with_trailing.extend_from_slice(&[0x00, 0x01, 0x02]);
        assert_eq!(
            gunzip_bounded(&with_trailing, 1024),
            Err(GunzipErr::Malformed)
        );
    }

    #[test]
    fn rejects_stored_nlen_mismatch_huffman_kraft_violations_and_empty_block_bomb() {
        let mut bad_nlen = make_stored_gzip_member(b"abc");
        bad_nlen[13] ^= 0x55;
        assert_eq!(gunzip_bounded(&bad_nlen, 1024), Err(GunzipErr::Malformed));

        assert_eq!(
            HuffmanTable::from_lengths(&[1, 1, 1], TreeKind::LitLen).err(),
            Some(GunzipErr::Malformed)
        );
        assert_eq!(
            HuffmanTable::from_lengths(&[2, 2], TreeKind::CodeLengths).err(),
            Some(GunzipErr::Malformed)
        );

        let mut bomb = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF];
        for _ in 0..300 {
            bomb.extend_from_slice(&[0x00, 0x00, 0x00, 0xFF, 0xFF]);
        }
        bomb.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
        bomb.extend_from_slice(&crc32_ieee(b"").to_le_bytes());
        bomb.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(gunzip_bounded(&bomb, 1024), Err(GunzipErr::LimitExceeded));

        let big = make_stored_gzip_member(&[b'A'; 512]);
        assert_eq!(gunzip_bounded(&big, 128), Err(GunzipErr::LimitExceeded));
    }

    #[test]
    fn fhcrc_flag_verified_and_short_trailer_rejected() {
        let mut hdr = vec![0x1F, 0x8B, 0x08, 0x02, 0, 0, 0, 0, 0, 0xFF];
        let hcrc = (crc32_ieee(&hdr) & 0xFFFF) as u16;
        hdr.extend_from_slice(&hcrc.to_le_bytes());
        hdr.extend_from_slice(&[0x03, 0x00]);
        hdr.extend_from_slice(&crc32_ieee(b"").to_le_bytes());
        hdr.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(gunzip_bounded(&hdr, 64), Ok(Vec::new()));

        let mut bad_hcrc = hdr.clone();
        bad_hcrc[10] ^= 0x01;
        assert_eq!(gunzip_bounded(&bad_hcrc, 64), Err(GunzipErr::Malformed));

        let short = &hdr[..hdr.len() - 3];
        assert_eq!(gunzip_bounded(short, 64), Err(GunzipErr::Malformed));
    }

    #[test]
    fn rejects_cross_member_lz77_backreference() {
        let member1 = make_stored_gzip_member(b"SECRET_FROM_M1");
        // Fixed-Huffman deflate block in member 2 emitting back-reference length=3, distance=1 (byte 0..).
        // Fixed Huffman: BFINAL=1 (1), BTYPE=01 (LSB bits 1,0), sym 257 (MSB 0000001), dist 0 (00000), EOB 256 (0000000).
        // Bits LSB-per-byte: byte0=0b0000_0011=0x03, byte1=0b0000_0010=0x02, byte2=0x00.
        let mut member2 = vec![
            0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF, 0x03, 0x02, 0x00,
        ];
        member2.extend_from_slice(&crc32_ieee(b"").to_le_bytes());
        member2.extend_from_slice(&0_u32.to_le_bytes());

        let mut combined = member1;
        combined.extend_from_slice(&member2);
        assert_eq!(gunzip_bounded(&combined, 1024), Err(GunzipErr::Malformed));
    }
}
