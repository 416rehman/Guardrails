// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Pure-Rust IEEE/Castagnoli CRC-32C (`0x82F63B78`) for 4 MiB spool segment framing.

const CASTAGNOLI_POLY_REVERSED: u32 = 0x82F6_3B78;

const fn crc32c_nibble(nibble: u8) -> u32 {
    let mut crc = nibble as u32;
    let mut bit = 0u8;
    while bit < 4 {
        if (crc & 1) != 0 {
            crc = (crc >> 1) ^ CASTAGNOLI_POLY_REVERSED;
        } else {
            crc >>= 1;
        }
        bit = bit.wrapping_add(1);
    }
    crc
}

#[must_use]
pub fn crc32c_append(seed: u32, data: &[u8]) -> u32 {
    let mut crc = !seed;
    for &byte in data {
        crc ^= u32::from(byte);
        crc = (crc >> 4) ^ crc32c_nibble((crc as u8) & 0x0f);
        crc = (crc >> 4) ^ crc32c_nibble((crc as u8) & 0x0f);
    }
    !crc
}

#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_append(0, data)
}
