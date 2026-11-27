// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::CodedError;
use grdr_ports::CODE_LAKE_IO;

pub(crate) const CT_STOP: u8 = 0;
pub(crate) const CT_BOOLEAN_TRUE: u8 = 1;
pub(crate) const CT_BOOLEAN_FALSE: u8 = 2;
pub(crate) const CT_I32: u8 = 5;
pub(crate) const CT_I64: u8 = 6;
pub(crate) const CT_BINARY: u8 = 8;
pub(crate) const CT_LIST: u8 = 9;
pub(crate) const CT_STRUCT: u8 = 12;

const MAX_THRIFT_SKIP_STEPS: usize = 1_000_000;

#[derive(Debug, Default)]
pub(crate) struct CompactWriter {
    buf: Vec<u8>,
    last_field_stack: Vec<i16>,
    last_field: i16,
}

#[derive(Debug)]
pub(crate) struct CompactReader<'a> {
    data: &'a [u8],
    pos: usize,
    last_field_stack: Vec<i16>,
    last_field: i16,
}

impl CompactWriter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub(crate) fn begin_struct(&mut self) {
        self.last_field_stack.push(self.last_field);
        self.last_field = 0;
    }

    pub(crate) fn end_struct(&mut self) {
        self.buf.push(CT_STOP);
        self.last_field = self.last_field_stack.pop().unwrap_or(0);
    }

    pub(crate) fn write_field_header(&mut self, field_id: i16, ct_type: u8) {
        let delta = field_id.saturating_sub(self.last_field);
        if delta > 0 && delta <= 15 {
            let byte = u8::try_from((delta << 4) | i16::from(ct_type)).unwrap_or(ct_type);
            self.buf.push(byte);
        } else {
            self.buf.push(ct_type);
            self.write_zigzag_i32(i32::from(field_id));
        }
        self.last_field = field_id;
    }

    pub(crate) fn write_i32_field(&mut self, field_id: i16, value: i32) {
        self.write_field_header(field_id, CT_I32);
        self.write_zigzag_i32(value);
    }

    pub(crate) fn write_i64_field(&mut self, field_id: i16, value: i64) {
        self.write_field_header(field_id, CT_I64);
        self.write_zigzag_i64(value);
    }

    pub(crate) fn write_bytes_field(&mut self, field_id: i16, bytes: &[u8]) {
        self.write_field_header(field_id, CT_BINARY);
        self.write_binary(bytes);
    }

    pub(crate) fn write_str_field(&mut self, field_id: i16, value: &str) {
        self.write_bytes_field(field_id, value.as_bytes());
    }

    pub(crate) fn write_list_header(&mut self, field_id: i16, elem_type: u8, len: usize) {
        self.write_field_header(field_id, CT_LIST);
        if len < 15 {
            let hdr = u8::try_from((len << 4) | usize::from(elem_type)).unwrap_or(elem_type);
            self.buf.push(hdr);
        } else {
            self.buf.push(0xF0 | elem_type);
            self.write_varint_u64(u64::try_from(len).unwrap_or(0));
        }
    }

    pub(crate) fn write_i32_elem(&mut self, value: i32) {
        self.write_zigzag_i32(value);
    }

    pub(crate) fn write_binary(&mut self, bytes: &[u8]) {
        self.write_varint_u64(u64::try_from(bytes.len()).unwrap_or(0));
        self.buf.extend_from_slice(bytes);
    }

    fn write_zigzag_i32(&mut self, val: i32) {
        let zz = u32::from_ne_bytes(((val << 1) ^ (val >> 31)).to_ne_bytes());
        self.write_varint_u64(u64::from(zz));
    }

    fn write_zigzag_i64(&mut self, val: i64) {
        let zz = u64::from_ne_bytes(((val << 1) ^ (val >> 63)).to_ne_bytes());
        self.write_varint_u64(zz);
    }

    fn write_varint_u64(&mut self, mut val: u64) {
        loop {
            let byte = u8::try_from(val & 0x7F).unwrap_or(0);
            val >>= 7;
            if val == 0 {
                self.buf.push(byte);
                break;
            }
            self.buf.push(byte | 0x80);
        }
    }
}

impl<'a> CompactReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            last_field_stack: Vec::new(),
            last_field: 0,
        }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn begin_struct(&mut self) {
        self.last_field_stack.push(self.last_field);
        self.last_field = 0;
    }

    pub(crate) fn end_struct(&mut self) {
        self.last_field = self.last_field_stack.pop().unwrap_or(0);
    }

    pub(crate) fn read_field_header(&mut self) -> Result<Option<(i16, u8)>, CodedError> {
        let first = self.read_u8()?;
        if first == CT_STOP {
            return Ok(None);
        }
        let ct_type = first & 0x0F;
        let delta = i16::from(first >> 4);
        let field_id = if delta == 0 {
            i16::try_from(self.read_i32()?).map_err(|_| thrift_err("field_id overflow"))?
        } else {
            self.last_field.saturating_add(delta)
        };
        self.last_field = field_id;
        Ok(Some((field_id, ct_type)))
    }

    pub(crate) fn read_i32(&mut self) -> Result<i32, CodedError> {
        let u = u32::try_from(self.read_varint_u64()?)
            .map_err(|_| thrift_err("zigzag i32 out of bounds"))?;
        let shifted = u >> 1;
        let sign = (u & 1).wrapping_neg();
        Ok(i32::from_ne_bytes((shifted ^ sign).to_ne_bytes()))
    }

    pub(crate) fn read_i64(&mut self) -> Result<i64, CodedError> {
        let u = self.read_varint_u64()?;
        let shifted = u >> 1;
        let sign = (u & 1).wrapping_neg();
        Ok(i64::from_ne_bytes((shifted ^ sign).to_ne_bytes()))
    }

    pub(crate) fn read_binary(&mut self) -> Result<&'a [u8], CodedError> {
        let len = usize::try_from(self.read_varint_u64()?)
            .map_err(|_| thrift_err("binary length exceeds usize"))?;
        let end = self.pos.saturating_add(len);
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| thrift_err("unexpected EOF reading binary"))?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn read_string(&mut self) -> Result<String, CodedError> {
        let bytes = self.read_binary()?;
        std::str::from_utf8(bytes)
            .map(ToString::to_string)
            .map_err(|_| thrift_err("invalid UTF-8 string"))
    }

    pub(crate) fn read_list_header(&mut self) -> Result<(u8, usize), CodedError> {
        let hdr = self.read_u8()?;
        let elem_type = hdr & 0x0F;
        let short_len = hdr >> 4;
        let len = if short_len == 0x0F {
            usize::try_from(self.read_varint_u64()?)
                .map_err(|_| thrift_err("list length exceeds usize"))?
        } else {
            usize::from(short_len)
        };
        Ok((elem_type, len))
    }

    pub(crate) fn remaining_bytes(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub(crate) fn skip_field(&mut self, ct_type: u8) -> Result<(), CodedError> {
        let mut steps = 0usize;
        self.skip_value(ct_type, 0, &mut steps)
    }

    fn skip_value(
        &mut self,
        ct_type: u8,
        depth: usize,
        steps: &mut usize,
    ) -> Result<(), CodedError> {
        if depth > 16 {
            return Err(thrift_err("Thrift nesting depth exceeded"));
        }
        *steps = steps.saturating_add(1);
        if *steps > MAX_THRIFT_SKIP_STEPS {
            return Err(thrift_err("Thrift element budget exceeded"));
        }
        match ct_type {
            CT_BOOLEAN_TRUE | CT_BOOLEAN_FALSE => Ok(()),
            3 => {
                let _ = self.read_u8()?;
                Ok(())
            }
            4 | CT_I32 | CT_I64 => {
                let _ = self.read_varint_u64()?;
                Ok(())
            }
            7 => {
                let end = self.pos.saturating_add(8);
                if end > self.data.len() {
                    return Err(thrift_err("unexpected EOF skipping double"));
                }
                self.pos = end;
                Ok(())
            }
            CT_BINARY => {
                let _ = self.read_binary()?;
                Ok(())
            }
            CT_LIST | 10 => {
                let (et, len) = self.read_list_header()?;
                if len > self.remaining_bytes() {
                    return Err(thrift_err("list length exceeds remaining input"));
                }
                if matches!(et, CT_BOOLEAN_TRUE | CT_BOOLEAN_FALSE) {
                    let end = self
                        .pos
                        .checked_add(len)
                        .ok_or_else(|| thrift_err("bool list offset overflow"))?;
                    if end > self.data.len() {
                        return Err(thrift_err("unexpected EOF skipping bool list"));
                    }
                    self.pos = end;
                    return Ok(());
                }
                for _ in 0..len {
                    self.skip_value(et, depth.saturating_add(1), steps)?;
                }
                Ok(())
            }
            11 => {
                let len = self.read_varint_u64()?;
                if len > 0 {
                    let kv = self.read_u8()?;
                    let kt = (kv >> 4) & 0x0F;
                    let vt = kv & 0x0F;
                    let count = usize::try_from(len).map_err(|_| thrift_err("map len"))?;
                    if count.saturating_mul(2) > self.remaining_bytes() {
                        return Err(thrift_err("map length exceeds remaining input"));
                    }
                    for _ in 0..count {
                        if matches!(kt, CT_BOOLEAN_TRUE | CT_BOOLEAN_FALSE) {
                            let _ = self.read_u8()?;
                        } else {
                            self.skip_value(kt, depth.saturating_add(1), steps)?;
                        }
                        if matches!(vt, CT_BOOLEAN_TRUE | CT_BOOLEAN_FALSE) {
                            let _ = self.read_u8()?;
                        } else {
                            self.skip_value(vt, depth.saturating_add(1), steps)?;
                        }
                    }
                }
                Ok(())
            }
            CT_STRUCT => {
                self.begin_struct();
                while let Some((_, ft)) = self.read_field_header()? {
                    self.skip_value(ft, depth.saturating_add(1), steps)?;
                }
                self.end_struct();
                Ok(())
            }
            _ => Err(thrift_err("unsupported Thrift compact type")),
        }
    }

    fn read_u8(&mut self) -> Result<u8, CodedError> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or_else(|| thrift_err("unexpected EOF"))?;
        self.pos = self.pos.saturating_add(1);
        Ok(byte)
    }

    fn read_varint_u64(&mut self) -> Result<u64, CodedError> {
        let mut res: u64 = 0;
        let mut shift: u32 = 0;
        for idx in 0..10usize {
            let b = self.read_u8()?;
            if idx == 9 && b > 1 {
                return Err(thrift_err("varint exceeds u64 range"));
            }
            res |= u64::from(b & 0x7F) << shift;
            if (b & 0x80) == 0 {
                return Ok(res);
            }
            shift = shift.saturating_add(7);
        }
        Err(thrift_err("varint exceeded 10 bytes"))
    }
}

fn thrift_err(detail: &str) -> CodedError {
    CodedError::new(
        CODE_LAKE_IO,
        format!("Parquet Thrift Compact codec error: {detail}."),
        "Verify Parquet file metadata integrity.",
    )
}
