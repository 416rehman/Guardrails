// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pure-Rust deterministic ONNX graph and sliding-window tokenizer runtime (`docs/design/19`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::InferError;
use crate::onnx_ops::eval_node;
use crate::onnx_proto::{
    MAX_ONNX_SESSION_ELEMENTS, MAX_TENSOR_ELEMENTS, MAX_TENSOR_RANK, ONNX_DTYPE_FLOAT,
    OnnxGraphProto, OnnxModelProto, OnnxTensorProto, parse_onnx_model,
};
use crate::onnx_wire::checked_shape_product;

pub const WINDOW_TOKENS: usize = 512;
pub const WINDOW_OVERLAP_TOKENS: usize = 64;
const MAX_WINDOWS_PER_INPUT: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum TensorData {
    Float(Vec<f32>),
    Int(Vec<i64>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TensorValue {
    pub shape: Vec<usize>,
    pub data: TensorData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnnxVocab {
    pub unk_id: i64,
    pub pad_id: i64,
    pub token_to_id: BTreeMap<String, i64>,
}

#[derive(Debug, Clone)]
pub struct OnnxSession {
    graph: OnnxGraphProto,
    initializers: BTreeMap<String, TensorValue>,
}

#[derive(Debug, Clone)]
pub struct WindowScore {
    pub start_token: usize,
    pub end_token: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub probability: f32,
}

impl TensorValue {
    pub fn from_proto(p: &OnnxTensorProto) -> Result<Self, InferError> {
        let data = if p.data_type == ONNX_DTYPE_FLOAT {
            TensorData::Float(p.floats.clone())
        } else {
            TensorData::Int(p.ints.clone())
        };
        Ok(Self {
            shape: p.dims.clone(),
            data,
        })
    }

    pub fn as_floats(&self) -> Result<&[f32], InferError> {
        match &self.data {
            TensorData::Float(v) => Ok(v),
            TensorData::Int(_) => Err(InferError::InvalidInput("expected float32 tensor".into())),
        }
    }

    pub fn as_ints(&self) -> Result<&[i64], InferError> {
        match &self.data {
            TensorData::Int(v) => Ok(v),
            TensorData::Float(_) => Err(InferError::InvalidInput("expected int64 tensor".into())),
        }
    }
}

impl OnnxVocab {
    /// Splits UTF-8 text into byte-tracked tokens and chunks into overlapping `512`-token windows.
    #[must_use]
    pub fn tokenize_windows(&self, text: &str) -> Vec<(Vec<i64>, usize, usize)> {
        let mut tokens: Vec<(i64, usize, usize)> = Vec::new();
        let mut cur_start: Option<usize> = None;
        for (idx, ch) in text.char_indices() {
            if ch.is_alphanumeric() || matches!(ch, '_' | '-' | '/' | '.') {
                if cur_start.is_none() {
                    cur_start = Some(idx);
                }
            } else if let Some(s) = cur_start.take() {
                push_token_slice(self, text, s, idx, &mut tokens);
            }
        }
        if let Some(s) = cur_start {
            push_token_slice(self, text, s, text.len(), &mut tokens);
        }
        if tokens.is_empty() {
            return vec![(vec![self.pad_id], 0, 0)];
        }
        let stride = WINDOW_TOKENS.saturating_sub(WINDOW_OVERLAP_TOKENS).max(1);
        let mut out = Vec::new();
        let mut offset: usize = 0;
        while offset < tokens.len() && out.len() < MAX_WINDOWS_PER_INPUT {
            let end = offset.saturating_add(WINDOW_TOKENS).min(tokens.len());
            if let Some(slice) = tokens.get(offset..end) {
                let ids: Vec<i64> = slice.iter().map(|t| t.0).collect();
                out.push((
                    ids,
                    slice.first().map_or(0, |t| t.1),
                    slice.last().map_or(0, |t| t.2),
                ));
            }
            if end == tokens.len() {
                break;
            }
            offset = offset.saturating_add(stride);
        }
        out
    }
}

impl OnnxSession {
    pub fn from_bytes(onnx_bytes: &[u8]) -> Result<Self, InferError> {
        Self::from_model(parse_onnx_model(onnx_bytes)?)
    }

    pub fn from_model(model: OnnxModelProto) -> Result<Self, InferError> {
        let mut initializers = BTreeMap::new();
        let mut known_tensors = BTreeSet::new();
        let mut total_elems: usize = 0;
        for init in &model.graph.initializers {
            let tv = TensorValue::from_proto(init)?;
            let count = tensor_len(&tv);
            total_elems = total_elems
                .checked_add(count)
                .filter(|&n| n <= MAX_ONNX_SESSION_ELEMENTS)
                .ok_or_else(|| {
                    InferError::InvalidInput("ONNX initializers exceed memory budget".into())
                })?;
            if initializers.insert(init.name.clone(), tv).is_some() {
                return Err(InferError::InvalidInput(
                    "duplicate ONNX initializer".into(),
                ));
            }
            known_tensors.insert(init.name.clone());
        }
        for inp in &model.graph.inputs {
            known_tensors.insert(inp.clone());
        }
        for node in &model.graph.nodes {
            if node.op_type.is_empty() || node.inputs.is_empty() || node.outputs.is_empty() {
                return Err(InferError::InvalidInput(
                    "invalid ONNX node metadata".into(),
                ));
            }
            for inp in &node.inputs {
                if !known_tensors.contains(inp) {
                    return Err(InferError::InvalidInput(format!(
                        "ONNX topological/SSA violation: input `{inp}` undefined before node `{}`",
                        node.name
                    )));
                }
            }
            for out in &node.outputs {
                if out.is_empty() || !known_tensors.insert(out.clone()) {
                    return Err(InferError::InvalidInput(format!(
                        "ONNX SSA violation: empty or redefined output `{out}`"
                    )));
                }
            }
        }
        for out_name in &model.graph.outputs {
            if !known_tensors.contains(out_name) {
                return Err(InferError::InvalidInput(format!(
                    "ONNX graph output `{out_name}` never produced"
                )));
            }
        }
        Ok(Self {
            graph: model.graph,
            initializers,
        })
    }

    /// Executes the parsed ONNX graph deterministically on the provided input tensors.
    pub fn run(&self, inputs: &[(&str, TensorValue)]) -> Result<Vec<TensorValue>, InferError> {
        let mut env = self.initializers.clone();
        let mut total_elems: usize = env.values().map(tensor_len).sum();
        for (name, val) in inputs {
            if val.shape.len() > MAX_TENSOR_RANK || val.shape.contains(&0) {
                return Err(InferError::InvalidInput(
                    "input tensor exceeds max rank or contains zero dim".into(),
                ));
            }
            let expected = checked_shape_product(&val.shape)?;
            let count = tensor_len(val);
            if expected != count || count > MAX_TENSOR_ELEMENTS {
                return Err(InferError::InvalidInput(
                    "input tensor shape/element count mismatch or exceeds cap".into(),
                ));
            }
            if let TensorData::Float(ref floats) = val.data
                && floats.iter().any(|v| !v.is_finite())
            {
                return Err(InferError::InvalidInput(
                    "non-finite caller float input rejected".into(),
                ));
            }
            total_elems = total_elems
                .checked_add(count)
                .filter(|&n| n <= MAX_ONNX_SESSION_ELEMENTS)
                .ok_or_else(|| {
                    InferError::InvalidInput("ONNX session memory cap exceeded".into())
                })?;
            env.insert((*name).to_owned(), val.clone());
        }
        for node in &self.graph.nodes {
            let outputs = eval_node(node, &env)?;
            for (out_name, val) in node.outputs.iter().zip(outputs) {
                let count = tensor_len(&val);
                total_elems = total_elems
                    .checked_add(count)
                    .filter(|&n| n <= MAX_ONNX_SESSION_ELEMENTS)
                    .ok_or_else(|| {
                        InferError::InvalidInput("ONNX runtime memory budget exceeded".into())
                    })?;
                if !out_name.is_empty() {
                    env.insert(out_name.clone(), val);
                }
            }
        }
        let mut results = Vec::with_capacity(self.graph.outputs.len());
        for out_name in &self.graph.outputs {
            let v = env
                .get(out_name)
                .ok_or_else(|| InferError::InvalidInput(format!("missing output `{out_name}`")))?;
            results.push(v.clone());
        }
        Ok(results)
    }

    /// Scores text over overlapping 512-token windows and returns max positive-class probability.
    pub fn score_text_windows(
        &self,
        vocab: &OnnxVocab,
        text: &str,
    ) -> Result<(f32, Option<WindowScore>), InferError> {
        let windows = vocab.tokenize_windows(text);
        let input_name = self
            .graph
            .inputs
            .first()
            .map(String::as_str)
            .unwrap_or("input_ids");
        let mut best_prob: f32 = 0.0;
        let mut best_win: Option<WindowScore> = None;
        for (ids, start_byte, end_byte) in windows {
            let seq_len = ids.len();
            let outs = self.run(&[(
                input_name,
                TensorValue {
                    shape: vec![1, seq_len],
                    data: TensorData::Int(ids),
                },
            )])?;
            let prob = extract_positive_probability(&outs)?;
            if prob >= best_prob {
                best_prob = prob;
                best_win = Some(WindowScore {
                    start_token: 0,
                    end_token: seq_len,
                    start_byte,
                    end_byte,
                    probability: prob,
                });
            }
        }
        Ok((best_prob, best_win))
    }
}

fn tensor_len(tv: &TensorValue) -> usize {
    match &tv.data {
        TensorData::Float(v) => v.len(),
        TensorData::Int(v) => v.len(),
    }
}

fn push_token_slice(
    vocab: &OnnxVocab,
    text: &str,
    start: usize,
    end: usize,
    out: &mut Vec<(i64, usize, usize)>,
) {
    if let Some(raw) = text.get(start..end) {
        let key = raw.to_ascii_lowercase();
        let id = vocab.token_to_id.get(&key).copied().unwrap_or(vocab.unk_id);
        out.push((id, start, end));
    }
}

fn extract_positive_probability(outs: &[TensorValue]) -> Result<f32, InferError> {
    let floats = outs
        .first()
        .ok_or_else(|| InferError::InvalidInput("empty ONNX output".into()))?
        .as_floats()?;
    let raw = if floats.len() >= 2 {
        floats.get(1).copied()
    } else {
        floats.first().copied()
    }
    .ok_or_else(|| InferError::InvalidInput("empty ONNX float probability output".into()))?;
    if !raw.is_finite() {
        return Err(InferError::InvalidInput("non-finite ONNX logit".into()));
    }
    Ok(raw.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_positive_probability_rejects_empty_float_tensor() {
        let empty = TensorValue {
            shape: Vec::new(),
            data: TensorData::Float(Vec::new()),
        };
        assert!(extract_positive_probability(&[empty]).is_err());
    }
}
