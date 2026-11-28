// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Protobuf wire-level reader and bounded packed/raw tensor decoders for ONNX (`onnx.proto3`).

use crate::InferError;
use crate::onnx_proto::{
    MAX_TENSOR_ELEMENTS, ONNX_DTYPE_BOOL, ONNX_DTYPE_FLOAT, ONNX_DTYPE_INT32, ONNX_DTYPE_INT64,
};

pub(crate) struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn is_eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn read_varint(&mut self) -> Result<u64, InferError> {
        let mut out: u64 = 0;
        let mut shift: u32 = 0;
        for _ in 0..10 {
            let b = self
                .buf
                .get(self.pos)
                .copied()
                .ok_or_else(|| InferError::InvalidInput("truncated ONNX varint".into()))?;
            self.pos = self.pos.saturating_add(1);
            out |= u64::from(b & 0x7F) << shift;
            if (b & 0x80) == 0 {
                return Ok(out);
            }
            shift = shift.saturating_add(7);
        }
        Err(InferError::InvalidInput("overlong ONNX varint".into()))
    }

    pub(crate) fn read_tag(&mut self) -> Result<(u32, u8), InferError> {
        let raw = self.read_varint()?;
        let field = u32::try_from(raw >> 3)
            .map_err(|_| InferError::InvalidInput("invalid protobuf field".into()))?;
        let wire_type = u8::try_from(raw & 0x07).unwrap_or(0);
        Ok((field, wire_type))
    }

    pub(crate) fn read_bytes(&mut self) -> Result<&'a [u8], InferError> {
        let len_u64 = self.read_varint()?;
        let len = usize::try_from(len_u64)
            .map_err(|_| InferError::InvalidInput("protobuf length overflow".into()))?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| InferError::InvalidInput("protobuf slice overflow".into()))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| InferError::InvalidInput("truncated ONNX byte field".into()))?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn read_fixed32(&mut self) -> Result<f32, InferError> {
        let end = self
            .pos
            .checked_add(4)
            .ok_or_else(|| InferError::InvalidInput("protobuf fixed32 overflow".into()))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| InferError::InvalidInput("truncated ONNX fixed32".into()))?;
        self.pos = end;
        let arr: [u8; 4] = slice
            .try_into()
            .map_err(|_| InferError::InvalidInput("invalid f32 byte width".into()))?;
        let val = f32::from_le_bytes(arr);
        if !val.is_finite() {
            return Err(InferError::InvalidInput(
                "non-finite float32 weight or attribute rejected".into(),
            ));
        }
        Ok(val)
    }

    pub(crate) fn skip_field(&mut self, wire_type: u8) -> Result<(), InferError> {
        match wire_type {
            0 => {
                self.read_varint()?;
                Ok(())
            }
            1 => {
                let end = self
                    .pos
                    .checked_add(8)
                    .ok_or_else(|| InferError::InvalidInput("fixed64 overflow".into()))?;
                if end > self.buf.len() {
                    return Err(InferError::InvalidInput("truncated fixed64".into()));
                }
                self.pos = end;
                Ok(())
            }
            2 => {
                self.read_bytes()?;
                Ok(())
            }
            5 => {
                self.read_fixed32()?;
                Ok(())
            }
            _ => Err(InferError::InvalidInput(format!(
                "unsupported wire type {wire_type}"
            ))),
        }
    }
}

pub(crate) fn decode_raw_tensor_data(
    data_type: i32,
    raw_data: &[u8],
    floats: &mut Vec<f32>,
    ints: &mut Vec<i64>,
) -> Result<(), InferError> {
    if raw_data.is_empty() {
        return Ok(());
    }
    match data_type {
        ONNX_DTYPE_FLOAT => read_packed_f32(raw_data, floats),
        ONNX_DTYPE_INT32 => read_packed_i32_as_i64(raw_data, ints),
        ONNX_DTYPE_INT64 => {
            let (chunks, rem) = raw_data.as_chunks::<8>();
            if !rem.is_empty() || ints.len().saturating_add(chunks.len()) > MAX_TENSOR_ELEMENTS {
                return Err(InferError::InvalidInput(
                    "invalid or oversized int64 raw_data".into(),
                ));
            }
            for arr in chunks {
                ints.push(i64::from_le_bytes(*arr));
            }
            Ok(())
        }
        ONNX_DTYPE_BOOL => {
            if ints.len().saturating_add(raw_data.len()) > MAX_TENSOR_ELEMENTS {
                return Err(InferError::InvalidInput("bool tensor exceeds cap".into()));
            }
            ints.extend(raw_data.iter().map(|&b| i64::from(b != 0)));
            Ok(())
        }
        other => Err(InferError::InvalidInput(format!(
            "unsupported dtype {other}"
        ))),
    }
}

pub(crate) fn read_utf8(r: &mut WireReader<'_>) -> Result<String, InferError> {
    String::from_utf8(r.read_bytes()?.to_vec())
        .map_err(|_| InferError::InvalidInput("non-UTF8 string in ONNX".into()))
}

pub(crate) fn dim_to_nonzero_usize(raw: u64) -> Result<usize, InferError> {
    let val =
        usize::try_from(raw).map_err(|_| InferError::InvalidInput("ONNX dim overflow".into()))?;
    if val == 0 {
        return Err(InferError::InvalidInput(
            "zero ONNX tensor dim rejected".into(),
        ));
    }
    Ok(val)
}

pub(crate) fn checked_shape_product(dims: &[usize]) -> Result<usize, InferError> {
    if dims.is_empty() {
        return Ok(1);
    }
    let mut prod: usize = 1;
    for &d in dims {
        prod = prod
            .checked_mul(d)
            .ok_or_else(|| InferError::InvalidInput("shape overflow".into()))?;
        if prod > MAX_TENSOR_ELEMENTS {
            return Err(InferError::InvalidInput("shape exceeds cap".into()));
        }
    }
    Ok(prod)
}

pub(crate) fn decode_signed_varint(v: u64) -> i64 {
    i64::from_ne_bytes(v.to_ne_bytes())
}

pub(crate) fn read_packed_f32(bytes: &[u8], out: &mut Vec<f32>) -> Result<(), InferError> {
    let (chunks, rem) = bytes.as_chunks::<4>();
    if !rem.is_empty() {
        return Err(InferError::InvalidInput("misaligned float32 buffer".into()));
    }
    for arr in chunks {
        if out.len() >= MAX_TENSOR_ELEMENTS {
            return Err(InferError::InvalidInput("float tensor exceeds cap".into()));
        }
        let v = f32::from_le_bytes(*arr);
        if !v.is_finite() {
            return Err(InferError::InvalidInput(
                "non-finite float weight rejected".into(),
            ));
        }
        out.push(v);
    }
    Ok(())
}

pub(crate) fn read_packed_i64(bytes: &[u8], out: &mut Vec<i64>) -> Result<(), InferError> {
    let mut r = WireReader::new(bytes);
    while !r.is_eof() {
        if out.len() >= MAX_TENSOR_ELEMENTS {
            return Err(InferError::InvalidInput("int64 tensor exceeds cap".into()));
        }
        out.push(decode_signed_varint(r.read_varint()?));
    }
    Ok(())
}

pub(crate) fn read_packed_i32_as_i64(bytes: &[u8], out: &mut Vec<i64>) -> Result<(), InferError> {
    let (chunks, rem) = bytes.as_chunks::<4>();
    if !rem.is_empty() {
        return Err(InferError::InvalidInput("misaligned int32 raw_data".into()));
    }
    for arr in chunks {
        if out.len() >= MAX_TENSOR_ELEMENTS {
            return Err(InferError::InvalidInput("int32 tensor exceeds cap".into()));
        }
        out.push(i64::from(i32::from_le_bytes(*arr)));
    }
    Ok(())
}
