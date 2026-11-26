// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::error::ProtoError;

const MAX_CODE_LEN: usize = 15;
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
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_buf: u32,
    bit_count: u8,
}

struct HuffTree {
    counts: [u16; 16],
    first_code: [u32; 16],
    first_sym: [usize; 16],
    symbols: Vec<u16>,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_buf: 0,
            bit_count: 0,
        }
    }

    fn ensure_bits(&mut self, needed: u8) -> Result<(), ProtoError> {
        while self.bit_count < needed {
            let next =
                self.data
                    .get(self.byte_pos)
                    .copied()
                    .ok_or(ProtoError::DecompressionRejected(
                        "truncated compressed stream",
                    ))?;
            self.byte_pos = self.byte_pos.saturating_add(1);
            self.bit_buf |= u32::from(next) << self.bit_count;
            self.bit_count = self.bit_count.saturating_add(8);
        }
        Ok(())
    }

    fn read_bits(&mut self, count: u8) -> Result<u32, ProtoError> {
        if count == 0 {
            return Ok(0);
        }
        self.ensure_bits(count)?;
        let mask = (1u32 << count).saturating_sub(1);
        let val = self.bit_buf & mask;
        self.bit_buf >>= count;
        self.bit_count = self.bit_count.saturating_sub(count);
        Ok(val)
    }

    fn align_byte(&mut self) {
        let drop = self.bit_count % 8;
        self.bit_buf >>= drop;
        self.bit_count = self.bit_count.saturating_sub(drop);
    }

    fn read_aligned_bytes(&mut self, len: usize) -> Result<Vec<u8>, ProtoError> {
        self.align_byte();
        let mut out = Vec::with_capacity(len.min(65_536));
        while out.len() < len && self.bit_count >= 8 {
            out.push((self.bit_buf & 0xFF) as u8);
            self.bit_buf >>= 8;
            self.bit_count = self.bit_count.saturating_sub(8);
        }
        let rem = len.saturating_sub(out.len());
        let end = self.byte_pos.saturating_add(rem);
        let slice = self
            .data
            .get(self.byte_pos..end)
            .ok_or(ProtoError::DecompressionRejected(
                "truncated stored deflate block",
            ))?;
        out.extend_from_slice(slice);
        self.byte_pos = end;
        Ok(out)
    }

    fn has_unconsumed_bytes(&mut self) -> bool {
        self.align_byte();
        self.bit_count >= 8 || self.byte_pos < self.data.len()
    }
}

impl HuffTree {
    fn from_lengths(lengths: &[u8]) -> Result<Self, ProtoError> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            let idx = usize::from(len);
            if idx > MAX_CODE_LEN {
                return Err(ProtoError::DecompressionRejected("invalid huffman length"));
            }
            if idx > 0
                && let Some(slot) = counts.get_mut(idx)
            {
                *slot = slot.saturating_add(1);
            }
        }
        let mut first_code = [0u32; 16];
        let mut first_sym = [0usize; 16];
        let mut code: u32 = 0;
        let mut sym_offset: usize = 0;
        for bits in 1..=MAX_CODE_LEN {
            let prev_count = u32::from(counts.get(bits.saturating_sub(1)).copied().unwrap_or(0));
            code = code.saturating_add(prev_count) << 1;
            let count_here = u32::from(counts.get(bits).copied().unwrap_or(0));
            if code.saturating_add(count_here) > (1u32 << bits) {
                return Err(ProtoError::DecompressionRejected(
                    "oversubscribed huffman tree",
                ));
            }
            if let Some(fc) = first_code.get_mut(bits) {
                *fc = code;
            }
            if let Some(fs) = first_sym.get_mut(bits) {
                *fs = sym_offset;
            }
            sym_offset = sym_offset.saturating_add(usize::try_from(count_here).unwrap_or(0));
        }
        let mut symbols = vec![0u16; sym_offset];
        let mut offsets = first_sym;
        for (sym_idx, &len) in lengths.iter().enumerate() {
            let b = usize::from(len);
            if b > 0
                && let Some(pos) = offsets.get_mut(b)
            {
                if let Some(target) = symbols.get_mut(*pos) {
                    *target = u16::try_from(sym_idx).unwrap_or(0);
                }
                *pos = pos.saturating_add(1);
            }
        }
        Ok(Self {
            counts,
            first_code,
            first_sym,
            symbols,
        })
    }

    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, ProtoError> {
        let mut code: u32 = 0;
        for bits in 1..=MAX_CODE_LEN {
            let bit = reader.read_bits(1)?;
            code = (code << 1) | bit;
            let count = u32::from(self.counts.get(bits).copied().unwrap_or(0));
            let base = self.first_code.get(bits).copied().unwrap_or(0);
            if code >= base && code < base.saturating_add(count) {
                let delta = usize::try_from(code.saturating_sub(base)).unwrap_or(usize::MAX);
                let idx = self
                    .first_sym
                    .get(bits)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(delta);
                return self
                    .symbols
                    .get(idx)
                    .copied()
                    .ok_or(ProtoError::DecompressionRejected(
                        "invalid huffman symbol index",
                    ));
            }
        }
        Err(ProtoError::DecompressionRejected("invalid huffman code"))
    }
}

pub(crate) fn inflate_raw_bounded(input: &[u8], budget: usize) -> Result<Vec<u8>, ProtoError> {
    let mut reader = BitReader::new(input);
    let mut out = Vec::new();
    loop {
        let bfinal = reader.read_bits(1)?;
        let btype = reader.read_bits(2)?;
        match btype {
            0 => inflate_stored_block(&mut reader, &mut out, budget)?,
            1 => {
                let (lit_tree, dist_tree) = fixed_huffman_trees()?;
                inflate_huffman_block(&mut reader, &lit_tree, &dist_tree, &mut out, budget)?;
            }
            2 => {
                let (lit_tree, dist_tree) = decode_dynamic_trees(&mut reader)?;
                inflate_huffman_block(&mut reader, &lit_tree, &dist_tree, &mut out, budget)?;
            }
            _ => {
                return Err(ProtoError::DecompressionRejected(
                    "invalid deflate block type",
                ));
            }
        }
        if bfinal == 1 {
            break;
        }
    }
    if reader.has_unconsumed_bytes() {
        return Err(ProtoError::DecompressionRejected(
            "trailing unconsumed deflate bytes",
        ));
    }
    Ok(out)
}

fn inflate_stored_block(
    reader: &mut BitReader<'_>,
    out: &mut Vec<u8>,
    budget: usize,
) -> Result<(), ProtoError> {
    let hdr = reader.read_aligned_bytes(4)?;
    let len = u16::from_le_bytes([
        hdr.first().copied().unwrap_or(0),
        hdr.get(1).copied().unwrap_or(0),
    ]);
    let nlen = u16::from_le_bytes([
        hdr.get(2).copied().unwrap_or(0),
        hdr.get(3).copied().unwrap_or(0),
    ]);
    if len != !nlen {
        return Err(ProtoError::DecompressionRejected(
            "stored deflate length mismatch",
        ));
    }
    let count = usize::from(len);
    if out.len().saturating_add(count) > budget {
        return Err(ProtoError::DecompressionRejected(
            "decompression ratio or byte budget exceeded",
        ));
    }
    let bytes = reader.read_aligned_bytes(count)?;
    out.extend_from_slice(&bytes);
    Ok(())
}

fn fixed_huffman_trees() -> Result<(HuffTree, HuffTree), ProtoError> {
    let mut lit_lens = vec![0u8; 288];
    for (idx, slot) in lit_lens.iter_mut().enumerate() {
        *slot = match idx {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let dist_lens = vec![5u8; 32];
    Ok((
        HuffTree::from_lengths(&lit_lens)?,
        HuffTree::from_lengths(&dist_lens)?,
    ))
}

fn decode_dynamic_trees(reader: &mut BitReader<'_>) -> Result<(HuffTree, HuffTree), ProtoError> {
    let hlit = usize::try_from(reader.read_bits(5)?)
        .unwrap_or(0)
        .saturating_add(257);
    let hdist = usize::try_from(reader.read_bits(5)?)
        .unwrap_or(0)
        .saturating_add(1);
    let hclen = usize::try_from(reader.read_bits(4)?)
        .unwrap_or(0)
        .saturating_add(4);
    if hlit > 286 || hdist > 30 {
        return Err(ProtoError::DecompressionRejected(
            "invalid dynamic huffman header",
        ));
    }
    let mut cl_lengths = [0u8; 19];
    for idx in 0..hclen {
        let len = u8::try_from(reader.read_bits(3)?).unwrap_or(0);
        if let Some(&order_pos) = CL_ORDER.get(idx)
            && let Some(slot) = cl_lengths.get_mut(order_pos)
        {
            *slot = len;
        }
    }
    let cl_tree = HuffTree::from_lengths(&cl_lengths)?;
    let total = hlit.saturating_add(hdist);
    let mut all_lens = Vec::with_capacity(total);
    while all_lens.len() < total {
        let sym = cl_tree.decode(reader)?;
        match sym {
            0..=15 => all_lens.push(u8::try_from(sym).unwrap_or(0)),
            16 => {
                let prev = all_lens
                    .last()
                    .copied()
                    .ok_or(ProtoError::DecompressionRejected("invalid repeat length"))?;
                let rep = usize::try_from(reader.read_bits(2)?)
                    .unwrap_or(0)
                    .saturating_add(3);
                if all_lens.len().saturating_add(rep) > total {
                    return Err(ProtoError::DecompressionRejected(
                        "dynamic tree repeat count overflows HLIT+HDIST",
                    ));
                }
                all_lens.resize(all_lens.len().saturating_add(rep), prev);
            }
            17 => {
                let rep = usize::try_from(reader.read_bits(3)?)
                    .unwrap_or(0)
                    .saturating_add(3);
                if all_lens.len().saturating_add(rep) > total {
                    return Err(ProtoError::DecompressionRejected(
                        "dynamic tree zero repeat overflows HLIT+HDIST",
                    ));
                }
                all_lens.resize(all_lens.len().saturating_add(rep), 0);
            }
            18 => {
                let rep = usize::try_from(reader.read_bits(7)?)
                    .unwrap_or(0)
                    .saturating_add(11);
                if all_lens.len().saturating_add(rep) > total {
                    return Err(ProtoError::DecompressionRejected(
                        "dynamic tree zero long repeat overflows HLIT+HDIST",
                    ));
                }
                all_lens.resize(all_lens.len().saturating_add(rep), 0);
            }
            _ => {
                return Err(ProtoError::DecompressionRejected(
                    "invalid code length symbol",
                ));
            }
        }
    }
    let lit_slice = all_lens
        .get(..hlit)
        .ok_or(ProtoError::DecompressionRejected("missing literal lengths"))?;
    let dist_slice = all_lens
        .get(hlit..)
        .ok_or(ProtoError::DecompressionRejected(
            "missing distance lengths",
        ))?;
    Ok((
        HuffTree::from_lengths(lit_slice)?,
        HuffTree::from_lengths(dist_slice)?,
    ))
}

fn inflate_huffman_block(
    reader: &mut BitReader<'_>,
    lit_tree: &HuffTree,
    dist_tree: &HuffTree,
    out: &mut Vec<u8>,
    budget: usize,
) -> Result<(), ProtoError> {
    loop {
        let sym = lit_tree.decode(reader)?;
        if sym < 256 {
            if out.len() >= budget {
                return Err(ProtoError::DecompressionRejected(
                    "decompression ratio or byte budget exceeded",
                ));
            }
            out.push(u8::try_from(sym).unwrap_or(0));
            continue;
        }
        if sym == 256 {
            return Ok(());
        }
        let len_idx = usize::from(sym).saturating_sub(257);
        let base_len = usize::from(LEN_BASE.get(len_idx).copied().ok_or(
            ProtoError::DecompressionRejected("invalid deflate length symbol"),
        )?);
        let extra_len =
            usize::try_from(reader.read_bits(LEN_EXTRA.get(len_idx).copied().unwrap_or(0))?)
                .unwrap_or(0);
        let match_len = base_len.saturating_add(extra_len);
        let dist_sym = usize::from(dist_tree.decode(reader)?);
        let base_dist = usize::from(DIST_BASE.get(dist_sym).copied().ok_or(
            ProtoError::DecompressionRejected("invalid deflate distance symbol"),
        )?);
        let extra_dist =
            usize::try_from(reader.read_bits(DIST_EXTRA.get(dist_sym).copied().unwrap_or(0))?)
                .unwrap_or(0);
        let dist = base_dist.saturating_add(extra_dist);
        if dist == 0 || dist > out.len() {
            return Err(ProtoError::DecompressionRejected(
                "invalid deflate backreference distance",
            ));
        }
        if out.len().saturating_add(match_len) > budget {
            return Err(ProtoError::DecompressionRejected(
                "decompression ratio or byte budget exceeded",
            ));
        }
        for _ in 0..match_len {
            let src_idx = out.len().saturating_sub(dist);
            let byte = out
                .get(src_idx)
                .copied()
                .ok_or(ProtoError::DecompressionRejected(
                    "backreference out of bounds",
                ))?;
            out.push(byte);
        }
    }
}

pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

pub(crate) fn adler32(data: &[u8]) -> u32 {
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for &b in data {
        s1 = (s1.saturating_add(u32::from(b))) % 65_521;
        s2 = (s2.saturating_add(s1)) % 65_521;
    }
    (s2 << 16) | s1
}
