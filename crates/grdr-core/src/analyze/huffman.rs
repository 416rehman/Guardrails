// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Bit reader and O(1) lookup + canonical Huffman tables with Kraft validation for DEFLATE.

use std::sync::LazyLock;

use crate::analyze::deflate::GunzipErr;

const FAST_BITS: u8 = 9;
const FAST_SIZE: usize = 1 << FAST_BITS;
const FAST_MASK: u64 = (FAST_SIZE - 1) as u64;
const MAX_CODE_LEN: usize = 15;

pub(crate) static FIXED_TABLES: LazyLock<Option<(HuffmanTable, HuffmanTable)>> =
    LazyLock::new(|| build_fixed_tables().ok());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeKind {
    CodeLengths,
    LitLen,
    Distance,
}

pub(crate) struct BitReader<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) byte_pos: usize,
    pub(crate) bit_buf: u64,
    pub(crate) bit_count: u8,
}

pub(crate) struct HuffmanTable {
    max_len: u8,
    fast: [u32; FAST_SIZE],
    counts: [u16; 16],
    first_code: [u32; 16],
    first_sym_idx: [u16; 16],
    symbols: Vec<u16>,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(data: &'a [u8], start_offset: usize) -> Self {
        Self {
            data,
            byte_pos: start_offset,
            bit_buf: 0,
            bit_count: 0,
        }
    }

    fn ensure_bits(&mut self, n: u8) -> Result<(), GunzipErr> {
        while self.bit_count < n {
            let byte = *self.data.get(self.byte_pos).ok_or(GunzipErr::Malformed)?;
            let shifted = u64::from(byte)
                .checked_shl(u32::from(self.bit_count))
                .ok_or(GunzipErr::Malformed)?;
            self.byte_pos = self.byte_pos.saturating_add(1);
            self.bit_buf |= shifted;
            self.bit_count = self.bit_count.saturating_add(8);
        }
        Ok(())
    }

    fn fill_available(&mut self, target_bits: u8) {
        while self.bit_count < target_bits && self.byte_pos < self.data.len() {
            if let Some(&byte) = self.data.get(self.byte_pos)
                && let Some(shifted) = u64::from(byte).checked_shl(u32::from(self.bit_count))
            {
                self.byte_pos = self.byte_pos.saturating_add(1);
                self.bit_buf |= shifted;
                self.bit_count = self.bit_count.saturating_add(8);
            } else {
                break;
            }
        }
    }

    pub(crate) fn read_bits(&mut self, n: u8) -> Result<u32, GunzipErr> {
        if n == 0 {
            return Ok(0);
        }
        self.ensure_bits(n)?;
        let mask = 1_u64
            .checked_shl(u32::from(n))
            .ok_or(GunzipErr::Malformed)?
            .saturating_sub(1);
        let val = u32::try_from(self.bit_buf & mask).map_err(|_| GunzipErr::Malformed)?;
        self.consume_bits(n)?;
        Ok(val)
    }

    fn consume_bits(&mut self, n: u8) -> Result<(), GunzipErr> {
        self.bit_buf = self
            .bit_buf
            .checked_shr(u32::from(n))
            .ok_or(GunzipErr::Malformed)?;
        self.bit_count = self.bit_count.saturating_sub(n);
        Ok(())
    }

    pub(crate) fn align_to_byte(&mut self) {
        let drop = self.bit_count % 8;
        self.bit_buf >>= drop;
        self.bit_count = self.bit_count.saturating_sub(drop);
    }

    pub(crate) fn exact_byte_pos(&self) -> Result<usize, GunzipErr> {
        let buffered_bytes = usize::from(self.bit_count / 8);
        self.byte_pos
            .checked_sub(buffered_bytes)
            .ok_or(GunzipErr::Malformed)
    }

    pub(crate) fn read_u16_le_aligned(&mut self) -> Result<u16, GunzipErr> {
        self.align_to_byte();
        let lo = u8::try_from(self.read_bits(8)?).map_err(|_| GunzipErr::Malformed)?;
        let hi = u8::try_from(self.read_bits(8)?).map_err(|_| GunzipErr::Malformed)?;
        Ok(u16::from_le_bytes([lo, hi]))
    }

    pub(crate) fn copy_aligned_bytes(
        &mut self,
        len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), GunzipErr> {
        self.align_to_byte();
        for _ in 0..len {
            let b = u8::try_from(self.read_bits(8)?).map_err(|_| GunzipErr::Malformed)?;
            out.push(b);
        }
        Ok(())
    }
}

impl HuffmanTable {
    pub(crate) fn from_lengths(lengths: &[u8], kind: TreeKind) -> Result<Self, GunzipErr> {
        let mut counts = [0_u16; 16];
        let mut max_len: u8 = 0;
        let mut num_syms: u16 = 0;
        for &len in lengths {
            if usize::from(len) > MAX_CODE_LEN {
                return Err(GunzipErr::Malformed);
            }
            if len > max_len {
                max_len = len;
            }
            if len > 0 {
                num_syms = num_syms.saturating_add(1);
                if let Some(slot) = counts.get_mut(usize::from(len)) {
                    *slot = slot.saturating_add(1);
                }
            }
        }

        if max_len == 0 {
            if kind == TreeKind::Distance {
                return Ok(Self {
                    max_len: 0,
                    fast: [0; FAST_SIZE],
                    counts,
                    first_code: [0; 16],
                    first_sym_idx: [0; 16],
                    symbols: Vec::new(),
                });
            }
            return Err(GunzipErr::Malformed);
        }

        // Validate Kraft inequality: reject over-subscribed and incomplete trees.
        let mut left: u32 = 1;
        for bits in 1..=MAX_CODE_LEN {
            left = left.checked_shl(1).ok_or(GunzipErr::Malformed)?;
            let count = u32::from(counts.get(bits).copied().unwrap_or(0));
            left = left.checked_sub(count).ok_or(GunzipErr::Malformed)?;
        }
        if left > 0 && (kind == TreeKind::CodeLengths || max_len != 1) {
            return Err(GunzipErr::Malformed);
        }

        let mut next_code = [0_u32; 16];
        let mut first_code = [0_u32; 16];
        let mut first_sym_idx = [0_u16; 16];
        let mut code: u32 = 0;
        let mut sym_offset: u16 = 0;
        for bits in 1..=MAX_CODE_LEN {
            let prev = u32::from(counts.get(bits.saturating_sub(1)).copied().unwrap_or(0));
            code = code
                .checked_add(prev)
                .and_then(|v| v.checked_shl(1))
                .ok_or(GunzipErr::Malformed)?;
            if let Some(slot) = first_code.get_mut(bits) {
                *slot = code;
            }
            if let Some(slot) = next_code.get_mut(bits) {
                *slot = code;
            }
            if let Some(slot) = first_sym_idx.get_mut(bits) {
                *slot = sym_offset;
            }
            sym_offset = sym_offset.saturating_add(counts.get(bits).copied().unwrap_or(0));
        }

        let mut symbols = vec![0_u16; usize::from(num_syms)];
        let mut fast = [0_u32; FAST_SIZE];
        let mut write_idx = first_sym_idx;

        for (sym, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let len_idx = usize::from(len);
            let sym_u16 = u16::try_from(sym).map_err(|_| GunzipErr::Malformed)?;

            let slot_pos = usize::from(write_idx.get(len_idx).copied().unwrap_or(0));
            if let Some(s) = symbols.get_mut(slot_pos) {
                *s = sym_u16;
            }
            if let Some(w) = write_idx.get_mut(len_idx) {
                *w = w.saturating_add(1);
            }

            let sym_code = next_code.get(len_idx).copied().unwrap_or(0);
            if let Some(n) = next_code.get_mut(len_idx) {
                *n = n.saturating_add(1);
            }

            if len <= FAST_BITS {
                let rev = reverse_bits(sym_code, len);
                let step = 1_usize
                    .checked_shl(u32::from(len))
                    .ok_or(GunzipErr::Malformed)?;
                let entry = (u32::from(sym_u16) << 8) | (u32::from(len) << 1) | 1;
                let mut pos = rev;
                while pos < FAST_SIZE {
                    if let Some(f) = fast.get_mut(pos) {
                        *f = entry;
                    }
                    pos = pos.saturating_add(step);
                }
            }
        }

        Ok(Self {
            max_len,
            fast,
            counts,
            first_code,
            first_sym_idx,
            symbols,
        })
    }

    pub(crate) fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, GunzipErr> {
        if self.max_len == 0 {
            return Err(GunzipErr::Malformed);
        }
        reader.fill_available(FAST_BITS);
        if reader.bit_count >= 1 {
            let idx = usize::try_from(reader.bit_buf & FAST_MASK).unwrap_or(0);
            let entry = self.fast.get(idx).copied().unwrap_or(0);
            if (entry & 1) != 0 {
                let len = u8::try_from((entry >> 1) & 0x0F).unwrap_or(16);
                if len <= reader.bit_count {
                    reader.consume_bits(len)?;
                    return u16::try_from(entry >> 8).map_err(|_| GunzipErr::Malformed);
                }
            }
        }

        let mut acc: u32 = 0;
        for bit_len in 1..=usize::from(self.max_len) {
            let bit = reader.read_bits(1)?;
            acc = acc
                .checked_shl(1)
                .map(|v| v | bit)
                .ok_or(GunzipErr::Malformed)?;
            let first = self.first_code.get(bit_len).copied().unwrap_or(0);
            let cnt = u32::from(self.counts.get(bit_len).copied().unwrap_or(0));
            if acc >= first && acc.saturating_sub(first) < cnt {
                let offset = usize::try_from(acc.saturating_sub(first)).unwrap_or(0);
                let base = usize::from(self.first_sym_idx.get(bit_len).copied().unwrap_or(0));
                return self
                    .symbols
                    .get(base.saturating_add(offset))
                    .copied()
                    .ok_or(GunzipErr::Malformed);
            }
        }
        Err(GunzipErr::Malformed)
    }
}

fn build_fixed_tables() -> Result<(HuffmanTable, HuffmanTable), GunzipErr> {
    let mut lit = vec![0_u8; 288];
    for (idx, item) in lit.iter_mut().enumerate() {
        *item = match idx {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let dist = vec![5_u8; 32];
    Ok((
        HuffmanTable::from_lengths(&lit, TreeKind::LitLen)?,
        HuffmanTable::from_lengths(&dist, TreeKind::Distance)?,
    ))
}

fn reverse_bits(code: u32, len: u8) -> usize {
    let mut rev: u32 = 0;
    let mut c = code;
    for _ in 0..len {
        rev = (rev << 1) | (c & 1);
        c >>= 1;
    }
    usize::try_from(rev).unwrap_or(0)
}
