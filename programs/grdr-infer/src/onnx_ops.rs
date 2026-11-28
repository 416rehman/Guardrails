// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! ONNX operator implementations for pure-Rust deterministic tensor execution.

use std::collections::BTreeMap;

use crate::InferError;
use crate::onnx_proto::{MAX_TENSOR_ELEMENTS, MAX_TENSOR_RANK, OnnxAttributeProto, OnnxNodeProto};
use crate::onnx_runtime::{TensorData, TensorValue};
use crate::onnx_tree::op_tree_ensemble;

struct GemmParams<'a> {
    a: &'a [f32],
    a_shape: &'a [usize],
    b: &'a [f32],
    b_shape: &'a [usize],
    trans_a: bool,
    trans_b: bool,
    alpha: f32,
    c: Option<&'a [f32]>,
    beta: f32,
}

pub(crate) fn eval_node(
    node: &OnnxNodeProto,
    env: &BTreeMap<String, TensorValue>,
) -> Result<Vec<TensorValue>, InferError> {
    let outs = match node.op_type.as_str() {
        "Gather" => op_gather(node, env),
        "ReduceMean" => op_reduce_mean(node, env),
        "MatMul" => op_matmul(node, env),
        "Gemm" => op_gemm(node, env),
        "Add" => op_elementwise(node, env, |a, b| a + b),
        "Sub" => op_elementwise(node, env, |a, b| a - b),
        "Mul" => op_elementwise(node, env, |a, b| a * b),
        "Relu" => op_unary(node, env, |x| x.max(0.0)),
        "Tanh" => op_unary(node, env, f32::tanh),
        "Sigmoid" => op_unary(node, env, |x| 1.0 / (1.0 + (-x).exp())),
        "Gelu" => op_unary(node, env, gelu_scalar),
        "Softmax" => op_softmax(node, env),
        "Reshape" => op_reshape(node, env),
        "TreeEnsembleClassifier" => op_tree_ensemble(node, env),
        other => Err(InferError::InvalidInput(format!(
            "unsupported ONNX op `{other}`"
        ))),
    }?;
    for tv in &outs {
        if let TensorData::Float(ref floats) = tv.data
            && floats.iter().any(|v| !v.is_finite())
        {
            return Err(InferError::InvalidInput(format!(
                "non-finite output from op `{}`",
                node.op_type
            )));
        }
    }
    Ok(outs)
}

pub(crate) fn get_tensor<'a>(
    env: &'a BTreeMap<String, TensorValue>,
    node: &OnnxNodeProto,
    idx: usize,
) -> Result<&'a TensorValue, InferError> {
    let name = node
        .inputs
        .get(idx)
        .ok_or_else(|| InferError::InvalidInput("missing node input".into()))?;
    env.get(name)
        .ok_or_else(|| InferError::InvalidInput(format!("tensor `{name}` not found")))
}

pub(crate) fn attr<'a>(node: &'a OnnxNodeProto, name: &str) -> Option<&'a OnnxAttributeProto> {
    node.attributes.iter().find(|a| a.name == name)
}

fn checked_alloc_elems(a: usize, b: usize, op: &str) -> Result<usize, InferError> {
    let prod = a
        .checked_mul(b)
        .ok_or_else(|| InferError::InvalidInput(format!("{op} shape overflow")))?;
    if prod == 0 || prod > MAX_TENSOR_ELEMENTS {
        return Err(InferError::InvalidInput(format!(
            "{op} allocation size {prod} outside 1..={MAX_TENSOR_ELEMENTS}"
        )));
    }
    Ok(prod)
}

fn op_gather(
    node: &OnnxNodeProto,
    env: &BTreeMap<String, TensorValue>,
) -> Result<Vec<TensorValue>, InferError> {
    let (table, indices) = (get_tensor(env, node, 0)?, get_tensor(env, node, 1)?);
    let (table_f, idx_vals) = (table.as_floats()?, indices.as_ints()?);
    if table.shape.len() != 2 {
        return Err(InferError::InvalidInput("Gather table must be 2D".into()));
    }
    let vocab_size = table.shape.first().copied().unwrap_or(0);
    let dim = table.shape.get(1).copied().unwrap_or(0);
    if checked_alloc_elems(vocab_size, dim, "Gather table")? != table_f.len() {
        return Err(InferError::InvalidInput(
            "Gather table shape mismatch".into(),
        ));
    }
    let out_elems = checked_alloc_elems(idx_vals.len(), dim, "Gather output")?;
    let mut out = Vec::with_capacity(out_elems);
    for &raw_id in idx_vals {
        let row = usize::try_from(raw_id)
            .ok()
            .filter(|&r| r < vocab_size)
            .ok_or_else(|| InferError::InvalidInput("Gather index OOB".into()))?;
        let start = row.saturating_mul(dim);
        let row_slice = table_f
            .get(start..start.saturating_add(dim))
            .ok_or_else(|| InferError::InvalidInput("Gather slice OOB".into()))?;
        out.extend_from_slice(row_slice);
    }
    let mut shape = indices.shape.clone();
    shape.push(dim);
    Ok(vec![TensorValue {
        shape,
        data: TensorData::Float(out),
    }])
}

fn op_reduce_mean(
    node: &OnnxNodeProto,
    env: &BTreeMap<String, TensorValue>,
) -> Result<Vec<TensorValue>, InferError> {
    let inp = get_tensor(env, node, 0)?;
    let floats = inp.as_floats()?;
    if inp.shape.len() != 3 {
        return Err(InferError::InvalidInput(
            "ReduceMean expects 3D [batch, seq, dim] tensor".into(),
        ));
    }
    let batch = inp.shape.first().copied().unwrap_or(0);
    let seq = inp.shape.get(1).copied().unwrap_or(0);
    let dim = inp.shape.get(2).copied().unwrap_or(0);
    let batch_seq = checked_alloc_elems(batch, seq, "ReduceMean")?;
    if checked_alloc_elems(batch_seq, dim, "ReduceMean")? != floats.len() {
        return Err(InferError::InvalidInput(
            "ReduceMean length mismatch".into(),
        ));
    }
    let seq_lo = u16::try_from(seq.checked_rem(1_000).unwrap_or(0))
        .map_err(|_| InferError::InvalidInput("ReduceMean seq mod overflow".into()))?;
    let seq_hi = u16::try_from(seq.checked_div(1_000).unwrap_or(0))
        .map_err(|_| InferError::InvalidInput("ReduceMean seq exceeds bound".into()))?;
    let denom = f32::from(seq_hi) * 1_000.0 + f32::from(seq_lo);
    let out_len = checked_alloc_elems(batch, dim, "ReduceMean output")?;
    let mut out = vec![0.0_f32; out_len];
    for b in 0..batch {
        for d in 0..dim {
            let mut sum = 0.0_f32;
            for t in 0..seq {
                let s = b
                    .saturating_mul(seq)
                    .saturating_add(t)
                    .saturating_mul(dim)
                    .saturating_add(d);
                let v = floats
                    .get(s)
                    .copied()
                    .ok_or_else(|| InferError::InvalidInput("ReduceMean OOB".into()))?;
                sum += v;
            }
            let res = sum / denom;
            if !res.is_finite() {
                return Err(InferError::InvalidInput(
                    "non-finite ReduceMean output".into(),
                ));
            }
            if let Some(acc) = out.get_mut(b.saturating_mul(dim).saturating_add(d)) {
                *acc = res;
            }
        }
    }
    Ok(vec![TensorValue {
        shape: vec![batch, dim],
        data: TensorData::Float(out),
    }])
}

fn op_matmul(
    node: &OnnxNodeProto,
    env: &BTreeMap<String, TensorValue>,
) -> Result<Vec<TensorValue>, InferError> {
    let (a, b) = (get_tensor(env, node, 0)?, get_tensor(env, node, 1)?);
    matmul_2d(GemmParams {
        a: a.as_floats()?,
        a_shape: &a.shape,
        b: b.as_floats()?,
        b_shape: &b.shape,
        trans_a: false,
        trans_b: false,
        alpha: 1.0,
        c: None,
        beta: 0.0,
    })
}

fn op_gemm(
    node: &OnnxNodeProto,
    env: &BTreeMap<String, TensorValue>,
) -> Result<Vec<TensorValue>, InferError> {
    let (a, b) = (get_tensor(env, node, 0)?, get_tensor(env, node, 1)?);
    let c = if node.inputs.len() >= 3 {
        Some(get_tensor(env, node, 2)?.as_floats()?)
    } else {
        None
    };
    let trans_a = attr(node, "transA").and_then(|x| x.i).unwrap_or(0) != 0;
    let trans_b = attr(node, "transB").and_then(|x| x.i).unwrap_or(0) != 0;
    let alpha = attr(node, "alpha").and_then(|x| x.f).unwrap_or(1.0);
    let beta = attr(node, "beta").and_then(|x| x.f).unwrap_or(1.0);
    matmul_2d(GemmParams {
        a: a.as_floats()?,
        a_shape: &a.shape,
        b: b.as_floats()?,
        b_shape: &b.shape,
        trans_a,
        trans_b,
        alpha,
        c,
        beta,
    })
}

fn matmul_2d(p: GemmParams<'_>) -> Result<Vec<TensorValue>, InferError> {
    if p.a_shape.len() != 2 || p.b_shape.len() != 2 || !p.alpha.is_finite() || !p.beta.is_finite() {
        return Err(InferError::InvalidInput(
            "Gemm/MatMul requires valid rank-2 finite inputs".into(),
        ));
    }
    let (ra, ca) = (
        p.a_shape.first().copied().unwrap_or(0),
        p.a_shape.get(1).copied().unwrap_or(0),
    );
    let (rb, cb) = (
        p.b_shape.first().copied().unwrap_or(0),
        p.b_shape.get(1).copied().unwrap_or(0),
    );
    if checked_alloc_elems(ra, ca, "MatMul A")? != p.a.len()
        || checked_alloc_elems(rb, cb, "MatMul B")? != p.b.len()
    {
        return Err(InferError::InvalidInput(
            "MatMul input length mismatch".into(),
        ));
    }
    let (m, k_a) = if p.trans_a { (ca, ra) } else { (ra, ca) };
    let (k_b, n) = if p.trans_b { (cb, rb) } else { (rb, cb) };
    if k_a != k_b {
        return Err(InferError::InvalidInput(format!(
            "MatMul inner dim {k_a} != {k_b}"
        )));
    }
    if let Some(bias) = p.c
        && bias.len() != n
        && bias.len() != 1
    {
        return Err(InferError::InvalidInput(
            "Gemm bias dimension mismatch".into(),
        ));
    }
    let out_len = checked_alloc_elems(m, n, "MatMul output")?;
    let mut out = vec![0.0_f32; out_len];
    for i in 0..m {
        for j in 0..n {
            let mut sum = 0.0_f32;
            for k in 0..k_a {
                let a_idx = if p.trans_a {
                    k.saturating_mul(m).saturating_add(i)
                } else {
                    i.saturating_mul(k_a).saturating_add(k)
                };
                let b_idx = if p.trans_b {
                    j.saturating_mul(k_b).saturating_add(k)
                } else {
                    k.saturating_mul(n).saturating_add(j)
                };
                let av =
                    p.a.get(a_idx)
                        .copied()
                        .ok_or_else(|| InferError::InvalidInput("MatMul A OOB".into()))?;
                let bv =
                    p.b.get(b_idx)
                        .copied()
                        .ok_or_else(|| InferError::InvalidInput("MatMul B OOB".into()))?;
                sum += av * bv;
            }
            let mut acc = sum * p.alpha;
            if let Some(bias) = p.c {
                let bv = if bias.len() == 1 {
                    bias.first()
                } else {
                    bias.get(j)
                }
                .copied()
                .ok_or_else(|| InferError::InvalidInput("Gemm bias OOB".into()))?;
                acc += p.beta * bv;
            }
            if !acc.is_finite() {
                return Err(InferError::InvalidInput(
                    "non-finite MatMul/Gemm output".into(),
                ));
            }
            if let Some(dst) = out.get_mut(i.saturating_mul(n).saturating_add(j)) {
                *dst = acc;
            }
        }
    }
    Ok(vec![TensorValue {
        shape: vec![m, n],
        data: TensorData::Float(out),
    }])
}

fn op_elementwise<F: Fn(f32, f32) -> f32>(
    node: &OnnxNodeProto,
    env: &BTreeMap<String, TensorValue>,
    f: F,
) -> Result<Vec<TensorValue>, InferError> {
    let (a, b) = (get_tensor(env, node, 0)?, get_tensor(env, node, 1)?);
    let (af, bf) = (a.as_floats()?, b.as_floats()?);
    let same = a.shape == b.shape && af.len() == bf.len();
    let scalar = bf.len() == 1 && (b.shape.is_empty() || b.shape == [1]);
    let trailing_shape_ok = b.shape == [bf.len()] || b.shape == [1, bf.len()];
    let trailing = !bf.is_empty()
        && trailing_shape_ok
        && a.shape.last() == Some(&bf.len())
        && af.len().is_multiple_of(bf.len());
    if af.is_empty() || (!same && !scalar && !trailing) {
        return Err(InferError::InvalidInput(
            "incompatible elementwise broadcast shape".into(),
        ));
    }
    let out = af
        .iter()
        .enumerate()
        .map(|(idx, &av)| {
            let bv = idx
                .checked_rem(bf.len())
                .and_then(|i| bf.get(i))
                .copied()
                .unwrap_or(0.0);
            f(av, bv)
        })
        .collect();
    Ok(vec![TensorValue {
        shape: a.shape.clone(),
        data: TensorData::Float(out),
    }])
}

fn op_unary<F: Fn(f32) -> f32>(
    node: &OnnxNodeProto,
    env: &BTreeMap<String, TensorValue>,
    f: F,
) -> Result<Vec<TensorValue>, InferError> {
    let a = get_tensor(env, node, 0)?;
    Ok(vec![TensorValue {
        shape: a.shape.clone(),
        data: TensorData::Float(a.as_floats()?.iter().copied().map(f).collect()),
    }])
}

fn op_softmax(
    node: &OnnxNodeProto,
    env: &BTreeMap<String, TensorValue>,
) -> Result<Vec<TensorValue>, InferError> {
    let a = get_tensor(env, node, 0)?;
    let af = a.as_floats()?;
    let cols = a.shape.last().copied().unwrap_or(0);
    if af.is_empty()
        || cols == 0
        || !af.len().is_multiple_of(cols)
        || af.iter().any(|v| !v.is_finite())
    {
        return Err(InferError::InvalidInput(
            "invalid Softmax input tensor".into(),
        ));
    }
    let mut out = Vec::with_capacity(af.len());
    for row in af.chunks(cols) {
        let max_v = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let exps: Vec<f32> = row.iter().map(|&v| (v - max_v).exp()).collect();
        let sum: f32 = exps.iter().copied().sum();
        if !sum.is_finite() || sum <= 0.0 {
            return Err(InferError::InvalidInput(
                "Softmax denominator overflow".into(),
            ));
        }
        out.extend(exps.into_iter().map(|e| e / sum));
    }
    Ok(vec![TensorValue {
        shape: a.shape.clone(),
        data: TensorData::Float(out),
    }])
}

fn op_reshape(
    node: &OnnxNodeProto,
    env: &BTreeMap<String, TensorValue>,
) -> Result<Vec<TensorValue>, InferError> {
    let (a, shape_t) = (get_tensor(env, node, 0)?, get_tensor(env, node, 1)?);
    let req_dims = shape_t.as_ints()?;
    let total = match &a.data {
        TensorData::Float(v) => v.len(),
        TensorData::Int(v) => v.len(),
    };
    if total == 0 || req_dims.is_empty() || req_dims.len() > MAX_TENSOR_RANK {
        return Err(InferError::InvalidInput(
            "empty or over-rank Reshape input or target shape".into(),
        ));
    }
    let (mut out_shape, mut infer_idx, mut prod) =
        (Vec::with_capacity(req_dims.len()), None, 1_usize);
    for (idx, &d) in req_dims.iter().enumerate() {
        if d == -1 {
            if infer_idx.is_some() {
                return Err(InferError::InvalidInput(
                    "Reshape allows at most one -1 dim".into(),
                ));
            }
            infer_idx = Some(idx);
            out_shape.push(1);
        } else {
            let ud = usize::try_from(d)
                .map_err(|_| InferError::InvalidInput("negative Reshape dim".into()))?;
            if ud == 0 {
                return Err(InferError::InvalidInput("zero Reshape dim rejected".into()));
            }
            prod = prod
                .checked_mul(ud)
                .ok_or_else(|| InferError::InvalidInput("Reshape dim overflow".into()))?;
            if prod > MAX_TENSOR_ELEMENTS {
                return Err(InferError::InvalidInput("Reshape size exceeds cap".into()));
            }
            out_shape.push(ud);
        }
    }
    if let Some(pos) = infer_idx {
        let inferred = total
            .checked_div(prod)
            .filter(|&v| v > 0 && total.is_multiple_of(prod))
            .ok_or_else(|| {
                InferError::InvalidInput("Reshape inferred dim not exact divisor".into())
            })?;
        if let Some(slot) = out_shape.get_mut(pos) {
            *slot = inferred;
        }
    } else if prod != total {
        return Err(InferError::InvalidInput(
            "Reshape element count mismatch".into(),
        ));
    }
    Ok(vec![TensorValue {
        shape: out_shape,
        data: a.data.clone(),
    }])
}

fn gelu_scalar(x: f32) -> f32 {
    0.5 * x * (1.0 + (0.797_884_6_f32 * (x + 0.044_715 * x * x * x)).tanh())
}
