// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pure-Rust ONNX protobuf binary (`onnx.proto3`) serializer for offline model bundles.

use crate::onnx_proto::{
    ONNX_DTYPE_FLOAT, OnnxAttributeProto, OnnxGraphProto, OnnxModelProto, OnnxNodeProto,
    OnnxTensorProto,
};

/// Serializes an `OnnxModelProto` into standard `onnx.proto3` binary wire bytes.
#[must_use]
pub fn encode_onnx_model(model: &OnnxModelProto) -> Vec<u8> {
    let mut out = Vec::new();
    if model.ir_version > 0 {
        write_varint_field(&mut out, 1, model.ir_version.cast_unsigned());
    }
    if !model.producer_name.is_empty() {
        write_bytes_field(&mut out, 2, model.producer_name.as_bytes());
    }
    let graph_bytes = encode_graph(&model.graph);
    write_bytes_field(&mut out, 7, &graph_bytes);
    if model.opset_version > 0 {
        let mut opset = Vec::new();
        write_varint_field(&mut opset, 2, model.opset_version.cast_unsigned());
        write_bytes_field(&mut out, 8, &opset);
    }
    out
}

fn encode_graph(g: &OnnxGraphProto) -> Vec<u8> {
    let mut out = Vec::new();
    for node in &g.nodes {
        write_bytes_field(&mut out, 1, &encode_node(node));
    }
    if !g.name.is_empty() {
        write_bytes_field(&mut out, 2, g.name.as_bytes());
    }
    for init in &g.initializers {
        write_bytes_field(&mut out, 5, &encode_tensor(init));
    }
    for input in &g.inputs {
        let mut vi = Vec::new();
        write_bytes_field(&mut vi, 1, input.as_bytes());
        write_bytes_field(&mut out, 11, &vi);
    }
    for output in &g.outputs {
        let mut vi = Vec::new();
        write_bytes_field(&mut vi, 1, output.as_bytes());
        write_bytes_field(&mut out, 12, &vi);
    }
    out
}

fn encode_node(n: &OnnxNodeProto) -> Vec<u8> {
    let mut out = Vec::new();
    for inp in &n.inputs {
        write_bytes_field(&mut out, 1, inp.as_bytes());
    }
    for out_name in &n.outputs {
        write_bytes_field(&mut out, 2, out_name.as_bytes());
    }
    if !n.name.is_empty() {
        write_bytes_field(&mut out, 3, n.name.as_bytes());
    }
    write_bytes_field(&mut out, 4, n.op_type.as_bytes());
    for attr in &n.attributes {
        write_bytes_field(&mut out, 5, &encode_attribute(attr));
    }
    out
}

fn encode_attribute(a: &OnnxAttributeProto) -> Vec<u8> {
    let mut out = Vec::new();
    write_bytes_field(&mut out, 1, a.name.as_bytes());
    if let Some(f) = a.f {
        write_varint(&mut out, (2 << 3) | 5);
        out.extend_from_slice(&f.to_le_bytes());
    }
    if let Some(i) = a.i {
        write_varint_field(&mut out, 3, i.cast_unsigned());
    }
    if let Some(ref s) = a.s {
        write_bytes_field(&mut out, 4, s.as_bytes());
    }
    for &f in &a.floats {
        write_varint(&mut out, (7 << 3) | 5);
        out.extend_from_slice(&f.to_le_bytes());
    }
    for &i in &a.ints {
        write_varint_field(&mut out, 8, i.cast_unsigned());
    }
    out
}

fn encode_tensor(t: &OnnxTensorProto) -> Vec<u8> {
    let mut out = Vec::new();
    for &d in &t.dims {
        write_varint_field(&mut out, 1, u64::try_from(d).unwrap_or(0));
    }
    write_varint_field(&mut out, 2, i64::from(t.data_type).cast_unsigned());
    write_bytes_field(&mut out, 8, t.name.as_bytes());
    if t.data_type == ONNX_DTYPE_FLOAT {
        let mut raw = Vec::with_capacity(t.floats.len().saturating_mul(4));
        for &v in &t.floats {
            raw.extend_from_slice(&v.to_le_bytes());
        }
        write_bytes_field(&mut out, 9, &raw);
    } else {
        for &i in &t.ints {
            write_varint_field(&mut out, 7, i.cast_unsigned());
        }
    }
    out
}

fn write_varint(out: &mut Vec<u8>, mut val: u64) {
    loop {
        let low = u8::try_from(val & 0x7F).unwrap_or(0);
        val >>= 7;
        if val == 0 {
            out.push(low);
            break;
        }
        out.push(low | 0x80);
    }
}

fn write_varint_field(out: &mut Vec<u8>, field: u32, val: u64) {
    write_varint(out, u64::from(field) << 3);
    write_varint(out, val);
}

fn write_bytes_field(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    write_varint(out, (u64::from(field) << 3) | 2);
    write_varint(out, u64::try_from(bytes.len()).unwrap_or(0));
    out.extend_from_slice(bytes);
}
