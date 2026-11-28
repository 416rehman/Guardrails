// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pure-Rust ONNX protobuf binary (`onnx.proto3`) wire parser (`docs/design/19`).

use crate::InferError;
use crate::onnx_wire::{
    WireReader, checked_shape_product, decode_raw_tensor_data, decode_signed_varint,
    dim_to_nonzero_usize, read_packed_f32, read_packed_i32_as_i64, read_packed_i64, read_utf8,
};

pub const MAX_ONNX_MODEL_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_ONNX_NODES: usize = 4_096;
pub const MAX_ONNX_INITIALIZERS: usize = 2_048;
pub const MAX_TENSOR_ELEMENTS: usize = 1_048_576;
pub const MAX_ONNX_SESSION_ELEMENTS: usize = 8_388_608;
pub(crate) const MAX_TENSOR_RANK: usize = 16;
const MAX_NODE_ARGS: usize = 256;

pub const ONNX_DTYPE_FLOAT: i32 = 1;
pub const ONNX_DTYPE_INT32: i32 = 6;
pub const ONNX_DTYPE_INT64: i32 = 7;
pub const ONNX_DTYPE_BOOL: i32 = 9;

#[derive(Debug, Clone, PartialEq)]
pub struct OnnxTensorProto {
    pub name: String,
    pub dims: Vec<usize>,
    pub data_type: i32,
    pub floats: Vec<f32>,
    pub ints: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct OnnxAttributeProto {
    pub name: String,
    pub f: Option<f32>,
    pub i: Option<i64>,
    pub s: Option<String>,
    pub floats: Vec<f32>,
    pub ints: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct OnnxNodeProto {
    pub name: String,
    pub op_type: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub attributes: Vec<OnnxAttributeProto>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct OnnxGraphProto {
    pub name: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub initializers: Vec<OnnxTensorProto>,
    pub nodes: Vec<OnnxNodeProto>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct OnnxModelProto {
    pub ir_version: i64,
    pub producer_name: String,
    pub opset_version: i64,
    pub graph: OnnxGraphProto,
}

/// Decodes an `.onnx` binary protobuf payload with strict structural and size caps.
pub fn parse_onnx_model(bytes: &[u8]) -> Result<OnnxModelProto, InferError> {
    if bytes.is_empty() || bytes.len() > MAX_ONNX_MODEL_BYTES {
        return Err(InferError::InvalidInput(format!(
            "ONNX model byte length {} outside 1..={MAX_ONNX_MODEL_BYTES}",
            bytes.len()
        )));
    }
    let mut reader = WireReader::new(bytes);
    let mut model = OnnxModelProto::default();
    let mut saw_graph = false;
    while !reader.is_eof() {
        let (field, wt) = reader.read_tag()?;
        match (field, wt) {
            (1, 0) => model.ir_version = decode_signed_varint(reader.read_varint()?),
            (2, 2) => model.producer_name = read_utf8(&mut reader)?,
            (7, 2) => {
                model.graph = parse_graph(reader.read_bytes()?)?;
                saw_graph = true;
            }
            (8, 2) => model.opset_version = parse_opset_version(reader.read_bytes()?)?,
            _ => reader.skip_field(wt)?,
        }
    }
    if !saw_graph {
        return Err(InferError::InvalidInput(
            "ONNX ModelProto missing GraphProto".into(),
        ));
    }
    Ok(model)
}

fn parse_opset_version(bytes: &[u8]) -> Result<i64, InferError> {
    let mut r = WireReader::new(bytes);
    let mut ver: i64 = 0;
    while !r.is_eof() {
        let (field, wt) = r.read_tag()?;
        if field == 2 && wt == 0 {
            ver = decode_signed_varint(r.read_varint()?);
        } else {
            r.skip_field(wt)?;
        }
    }
    Ok(ver)
}

fn parse_graph(bytes: &[u8]) -> Result<OnnxGraphProto, InferError> {
    let mut r = WireReader::new(bytes);
    let mut g = OnnxGraphProto::default();
    while !r.is_eof() {
        let (field, wt) = r.read_tag()?;
        match (field, wt) {
            (1, 2) => {
                if g.nodes.len() >= MAX_ONNX_NODES {
                    return Err(InferError::InvalidInput(
                        "ONNX node count exceeds cap".into(),
                    ));
                }
                g.nodes.push(parse_node(r.read_bytes()?)?);
            }
            (2, 2) => g.name = read_utf8(&mut r)?,
            (5, 2) => {
                if g.initializers.len() >= MAX_ONNX_INITIALIZERS {
                    return Err(InferError::InvalidInput(
                        "ONNX initializer count exceeds cap".into(),
                    ));
                }
                g.initializers.push(parse_tensor(r.read_bytes()?)?);
            }
            (11, 2) => push_capped(
                &mut g.inputs,
                parse_value_info_name(r.read_bytes()?)?,
                MAX_NODE_ARGS,
                "graph inputs",
            )?,
            (12, 2) => push_capped(
                &mut g.outputs,
                parse_value_info_name(r.read_bytes()?)?,
                MAX_NODE_ARGS,
                "graph outputs",
            )?,
            _ => r.skip_field(wt)?,
        }
    }
    Ok(g)
}

fn push_capped<T>(vec: &mut Vec<T>, val: T, cap: usize, label: &str) -> Result<(), InferError> {
    if vec.len() >= cap {
        return Err(InferError::InvalidInput(format!("{label} exceeds cap")));
    }
    vec.push(val);
    Ok(())
}

fn parse_value_info_name(bytes: &[u8]) -> Result<String, InferError> {
    let mut r = WireReader::new(bytes);
    let mut name = String::new();
    while !r.is_eof() {
        let (field, wt) = r.read_tag()?;
        if field == 1 && wt == 2 {
            name = read_utf8(&mut r)?;
        } else {
            r.skip_field(wt)?;
        }
    }
    Ok(name)
}

fn parse_node(bytes: &[u8]) -> Result<OnnxNodeProto, InferError> {
    let mut r = WireReader::new(bytes);
    let mut n = OnnxNodeProto::default();
    while !r.is_eof() {
        let (field, wt) = r.read_tag()?;
        match (field, wt) {
            (1, 2) => push_capped(
                &mut n.inputs,
                read_utf8(&mut r)?,
                MAX_NODE_ARGS,
                "node inputs",
            )?,
            (2, 2) => push_capped(
                &mut n.outputs,
                read_utf8(&mut r)?,
                MAX_NODE_ARGS,
                "node outputs",
            )?,
            (3, 2) => n.name = read_utf8(&mut r)?,
            (4, 2) => n.op_type = read_utf8(&mut r)?,
            (5, 2) => push_capped(
                &mut n.attributes,
                parse_attribute(r.read_bytes()?)?,
                MAX_NODE_ARGS,
                "node attributes",
            )?,
            _ => r.skip_field(wt)?,
        }
    }
    Ok(n)
}

fn parse_attribute(bytes: &[u8]) -> Result<OnnxAttributeProto, InferError> {
    let mut r = WireReader::new(bytes);
    let mut a = OnnxAttributeProto::default();
    while !r.is_eof() {
        let (field, wt) = r.read_tag()?;
        match (field, wt) {
            (1, 2) => a.name = read_utf8(&mut r)?,
            (2, 5) => a.f = Some(r.read_fixed32()?),
            (3, 0) => a.i = Some(decode_signed_varint(r.read_varint()?)),
            (4, 2) => a.s = Some(read_utf8(&mut r)?),
            (7, 5) => push_capped(
                &mut a.floats,
                r.read_fixed32()?,
                MAX_TENSOR_ELEMENTS,
                "attr floats",
            )?,
            (7, 2) => read_packed_f32(r.read_bytes()?, &mut a.floats)?,
            (8, 0) => push_capped(
                &mut a.ints,
                decode_signed_varint(r.read_varint()?),
                MAX_TENSOR_ELEMENTS,
                "attr ints",
            )?,
            (8, 2) => read_packed_i64(r.read_bytes()?, &mut a.ints)?,
            _ => r.skip_field(wt)?,
        }
    }
    Ok(a)
}

fn parse_tensor(bytes: &[u8]) -> Result<OnnxTensorProto, InferError> {
    let mut r = WireReader::new(bytes);
    let mut name = String::new();
    let mut dims = Vec::new();
    let mut data_type: Option<i32> = None;
    let mut floats = Vec::new();
    let mut ints = Vec::new();
    let mut raw_data: &[u8] = &[];
    while !r.is_eof() {
        let (field, wt) = r.read_tag()?;
        match (field, wt) {
            (1, 0) => push_capped(
                &mut dims,
                dim_to_nonzero_usize(r.read_varint()?)?,
                MAX_TENSOR_RANK,
                "tensor rank",
            )?,
            (1, 2) => {
                let mut raw_dims = Vec::new();
                read_packed_i64(r.read_bytes()?, &mut raw_dims)?;
                for d in raw_dims {
                    push_capped(
                        &mut dims,
                        dim_to_nonzero_usize(d.cast_unsigned())?,
                        MAX_TENSOR_RANK,
                        "tensor rank",
                    )?;
                }
            }
            (2, 0) => {
                data_type = Some(
                    i32::try_from(decode_signed_varint(r.read_varint()?))
                        .map_err(|_| InferError::InvalidInput("invalid tensor dtype".into()))?,
                );
            }
            (4, 5) => push_capped(
                &mut floats,
                r.read_fixed32()?,
                MAX_TENSOR_ELEMENTS,
                "float tensor",
            )?,
            (4, 2) => read_packed_f32(r.read_bytes()?, &mut floats)?,
            (5, 0) | (7, 0) => push_capped(
                &mut ints,
                decode_signed_varint(r.read_varint()?),
                MAX_TENSOR_ELEMENTS,
                "int tensor",
            )?,
            (5, 2) => read_packed_i32_as_i64(r.read_bytes()?, &mut ints)?,
            (7, 2) => read_packed_i64(r.read_bytes()?, &mut ints)?,
            (8, 2) => name = read_utf8(&mut r)?,
            (9, 2) => raw_data = r.read_bytes()?,
            _ => r.skip_field(wt)?,
        }
    }
    let resolved_dtype = data_type.unwrap_or(ONNX_DTYPE_FLOAT);
    if !matches!(
        resolved_dtype,
        ONNX_DTYPE_FLOAT | ONNX_DTYPE_INT32 | ONNX_DTYPE_INT64 | ONNX_DTYPE_BOOL
    ) {
        return Err(InferError::InvalidInput(format!(
            "unsupported tensor dtype {resolved_dtype}"
        )));
    }
    let expected_elems = checked_shape_product(&dims)?;
    decode_raw_tensor_data(resolved_dtype, raw_data, &mut floats, &mut ints)?;
    let dtype_conflict = if resolved_dtype == ONNX_DTYPE_FLOAT {
        !ints.is_empty()
    } else {
        !floats.is_empty()
    };
    let actual_len = if resolved_dtype == ONNX_DTYPE_FLOAT {
        floats.len()
    } else {
        ints.len()
    };
    if dtype_conflict || actual_len > MAX_TENSOR_ELEMENTS || actual_len != expected_elems {
        return Err(InferError::InvalidInput(format!(
            "tensor `{name}` shape or dtype mismatch"
        )));
    }
    Ok(OnnxTensorProto {
        name,
        dims,
        data_type: resolved_dtype,
        floats,
        ints,
    })
}
