// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::wire::WireDecodeError;

pub fn copy_bounded(dst: &mut [u8], src: &[u8]) -> (usize, bool) {
    let len = src.len().min(dst.len());
    if let (Some(d), Some(s)) = (dst.get_mut(..len), src.get(..len)) {
        d.copy_from_slice(s);
    }
    (len, src.len() > dst.len())
}

pub fn write_segment(dst: &mut [u8], offset: usize, src: &[u8]) -> Result<usize, WireDecodeError> {
    let end = offset
        .checked_add(src.len())
        .ok_or(WireDecodeError::PayloadTooLarge)?;
    let slice = dst
        .get_mut(offset..end)
        .ok_or(WireDecodeError::BufferTooShort)?;
    slice.copy_from_slice(src);
    Ok(end)
}

pub fn read_segment(
    src: &[u8],
    offset: usize,
    len: usize,
    dst: &mut [u8],
) -> Result<usize, WireDecodeError> {
    let end = offset
        .checked_add(len)
        .ok_or(WireDecodeError::PayloadTooLarge)?;
    let slice = src
        .get(offset..end)
        .ok_or(WireDecodeError::BufferTooShort)?;
    let out = dst.get_mut(..len).ok_or(WireDecodeError::BoundsExceeded)?;
    out.copy_from_slice(slice);
    Ok(end)
}

pub fn put_u8(dst: &mut [u8], offset: usize, val: u8) -> Result<(), WireDecodeError> {
    let slot = dst.get_mut(offset).ok_or(WireDecodeError::BufferTooShort)?;
    *slot = val;
    Ok(())
}

pub fn put_u16(dst: &mut [u8], offset: usize, val: u16) -> Result<(), WireDecodeError> {
    let end = offset
        .checked_add(2)
        .ok_or(WireDecodeError::PayloadTooLarge)?;
    let slot = dst
        .get_mut(offset..end)
        .ok_or(WireDecodeError::BufferTooShort)?;
    slot.copy_from_slice(&val.to_le_bytes());
    Ok(())
}

pub fn put_u32(dst: &mut [u8], offset: usize, val: u32) -> Result<(), WireDecodeError> {
    let end = offset
        .checked_add(4)
        .ok_or(WireDecodeError::PayloadTooLarge)?;
    let slot = dst
        .get_mut(offset..end)
        .ok_or(WireDecodeError::BufferTooShort)?;
    slot.copy_from_slice(&val.to_le_bytes());
    Ok(())
}

pub fn put_u64(dst: &mut [u8], offset: usize, val: u64) -> Result<(), WireDecodeError> {
    let end = offset
        .checked_add(8)
        .ok_or(WireDecodeError::PayloadTooLarge)?;
    let slot = dst
        .get_mut(offset..end)
        .ok_or(WireDecodeError::BufferTooShort)?;
    slot.copy_from_slice(&val.to_le_bytes());
    Ok(())
}

pub fn get_u8(src: &[u8], offset: usize) -> Result<u8, WireDecodeError> {
    src.get(offset)
        .copied()
        .ok_or(WireDecodeError::BufferTooShort)
}

pub fn get_u16(src: &[u8], offset: usize) -> Result<u16, WireDecodeError> {
    let end = offset
        .checked_add(2)
        .ok_or(WireDecodeError::PayloadTooLarge)?;
    let slot = src
        .get(offset..end)
        .ok_or(WireDecodeError::BufferTooShort)?;
    let mut arr = [0u8; 2];
    arr.copy_from_slice(slot);
    Ok(u16::from_le_bytes(arr))
}

pub fn get_u32(src: &[u8], offset: usize) -> Result<u32, WireDecodeError> {
    let end = offset
        .checked_add(4)
        .ok_or(WireDecodeError::PayloadTooLarge)?;
    let slot = src
        .get(offset..end)
        .ok_or(WireDecodeError::BufferTooShort)?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(slot);
    Ok(u32::from_le_bytes(arr))
}

pub fn get_u64(src: &[u8], offset: usize) -> Result<u64, WireDecodeError> {
    let end = offset
        .checked_add(8)
        .ok_or(WireDecodeError::PayloadTooLarge)?;
    let slot = src
        .get(offset..end)
        .ok_or(WireDecodeError::BufferTooShort)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(slot);
    Ok(u64::from_le_bytes(arr))
}
