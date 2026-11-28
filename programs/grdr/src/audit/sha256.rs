// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Independent pure-Rust FIPS 180-4 SHA-256 and constant-time comparison primitives (`04-15`).

const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const ROUND_KEYS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

pub struct Sha256 {
    state: [u32; 8],
    bit_len: u64,
    buffer: [u8; 64],
    buf_len: usize,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            bit_len: 0,
            buffer: [0u8; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let added_bits = u64::try_from(data.len())
            .unwrap_or(u64::MAX)
            .wrapping_mul(8);
        self.bit_len = self.bit_len.wrapping_add(added_bits);

        let mut rest = data;
        if self.buf_len > 0 {
            let need = 64usize.saturating_sub(self.buf_len);
            if let Some((head, tail)) = rest.split_at_checked(need) {
                if let Some(dst) = self.buffer.get_mut(self.buf_len..64) {
                    dst.copy_from_slice(head);
                }
                let block = self.buffer;
                compress_block(&mut self.state, &block);
                self.buf_len = 0;
                rest = tail;
            } else {
                let end = self.buf_len.saturating_add(rest.len());
                if let Some(dst) = self.buffer.get_mut(self.buf_len..end) {
                    dst.copy_from_slice(rest);
                }
                self.buf_len = end;
                return;
            }
        }

        let (chunks, remainder) = rest.as_chunks::<64>();
        for block in chunks {
            compress_block(&mut self.state, block);
        }

        if !remainder.is_empty() {
            if let Some(dst) = self.buffer.get_mut(..remainder.len()) {
                dst.copy_from_slice(remainder);
            }
            self.buf_len = remainder.len();
        }
    }

    #[must_use]
    pub fn finalize_digest(mut self) -> [u8; 32] {
        let len_bytes = self.bit_len.to_be_bytes();
        if let Some(slot) = self.buffer.get_mut(self.buf_len) {
            *slot = 0x80;
        }
        let next = self.buf_len.saturating_add(1);
        if next > 56 {
            if let Some(pad) = self.buffer.get_mut(next..64) {
                pad.fill(0);
            }
            let block = self.buffer;
            compress_block(&mut self.state, &block);
            self.buffer.fill(0);
        } else if let Some(pad) = self.buffer.get_mut(next..56) {
            pad.fill(0);
        }

        if let Some(tail) = self.buffer.get_mut(56..64) {
            tail.copy_from_slice(&len_bytes);
        }
        let final_block = self.buffer;
        compress_block(&mut self.state, &final_block);

        let mut out = [0u8; 32];
        let (out_chunks, _) = out.as_chunks_mut::<4>();
        for (word, chunk) in self.state.iter().zip(out_chunks.iter_mut()) {
            *chunk = word.to_be_bytes();
        }
        out
    }

    #[must_use]
    pub fn finalize_hex(self) -> String {
        encode_lower_hex(&self.finalize_digest())
    }
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize_digest()
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    encode_lower_hex(&sha256_digest(bytes))
}

#[must_use]
pub fn sha256_framed(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(&len.to_be_bytes());
        hasher.update(part);
    }
    format!("sha256:{}", hasher.finalize_hex())
}

#[must_use]
pub fn encode_lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        let hi = LOWER_HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        let lo = LOWER_HEX
            .get(usize::from(b & 0x0f))
            .copied()
            .unwrap_or(b'0');
        out.push(char::from(hi));
        out.push(char::from(lo));
    }
    out
}

#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    let (word_chunks, _) = block.as_chunks::<4>();
    for (slot, chunk) in w.iter_mut().zip(word_chunks.iter()) {
        *slot = u32::from_be_bytes(*chunk);
    }
    for i in 16usize..64 {
        let w2 = w.get(i.saturating_sub(2)).copied().unwrap_or(0);
        let w7 = w.get(i.saturating_sub(7)).copied().unwrap_or(0);
        let w15 = w.get(i.saturating_sub(15)).copied().unwrap_or(0);
        let w16 = w.get(i.saturating_sub(16)).copied().unwrap_or(0);
        let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        if let Some(slot) = w.get_mut(i) {
            *slot = w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
        }
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (&k, &wi) in ROUND_KEYS.iter().zip(w.iter()) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    let delta = [a, b, c, d, e, f, g, h];
    for (slot, add) in state.iter_mut().zip(delta) {
        *slot = slot.wrapping_add(add);
    }
}
