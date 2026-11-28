// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Indexed `O(N log N)` ONNX `TreeEnsembleClassifier` evaluator with cycle and finiteness checks.

use std::collections::{BTreeMap, BTreeSet};

use crate::InferError;
use crate::onnx_ops::{attr, get_tensor};
use crate::onnx_proto::OnnxNodeProto;
use crate::onnx_runtime::{TensorData, TensorValue};

const MAX_TREE_DEPTH: usize = 512;

pub(crate) fn op_tree_ensemble(
    node: &OnnxNodeProto,
    env: &BTreeMap<String, TensorValue>,
) -> Result<Vec<TensorValue>, InferError> {
    let x = get_tensor(env, node, 0)?;
    let xf = x.as_floats()?;
    if xf.is_empty() || xf.iter().any(|v| !v.is_finite()) {
        return Err(InferError::InvalidInput(
            "invalid TreeEnsemble input".into(),
        ));
    }
    let tree_ids = attr(node, "nodes_treeids")
        .map(|a| a.ints.as_slice())
        .unwrap_or(&[]);
    let node_ids = attr(node, "nodes_nodeids")
        .map(|a| a.ints.as_slice())
        .unwrap_or(&[]);
    let feat_ids = attr(node, "nodes_featureids")
        .map(|a| a.ints.as_slice())
        .unwrap_or(&[]);
    let values = attr(node, "nodes_values")
        .map(|a| a.floats.as_slice())
        .unwrap_or(&[]);
    let trues = attr(node, "nodes_truenodeids")
        .map(|a| a.ints.as_slice())
        .unwrap_or(&[]);
    let falses = attr(node, "nodes_falsenodeids")
        .map(|a| a.ints.as_slice())
        .unwrap_or(&[]);
    let class_tids = attr(node, "class_treeids")
        .map(|a| a.ints.as_slice())
        .unwrap_or(&[]);
    let class_nids = attr(node, "class_nodeids")
        .map(|a| a.ints.as_slice())
        .unwrap_or(&[]);
    let class_weights = attr(node, "class_weights")
        .map(|a| a.floats.as_slice())
        .unwrap_or(&[]);

    let n = tree_ids.len();
    if n == 0
        || node_ids.len() != n
        || feat_ids.len() != n
        || values.len() != n
        || trues.len() != n
        || falses.len() != n
        || class_tids.is_empty()
        || class_nids.len() != class_tids.len()
        || class_weights.len() != class_tids.len()
    {
        return Err(InferError::InvalidInput(
            "TreeEnsemble attribute array length mismatch".into(),
        ));
    }
    let mut leaf_map = BTreeMap::new();
    for ((&ct, &cn), &w) in class_tids
        .iter()
        .zip(class_nids.iter())
        .zip(class_weights.iter())
    {
        if !w.is_finite() || leaf_map.insert((ct, cn), w).is_some() {
            return Err(InferError::InvalidInput(
                "invalid or duplicate TreeEnsemble leaf".into(),
            ));
        }
    }
    let mut node_map = BTreeMap::new();
    let mut distinct_trees = BTreeSet::new();
    for (idx, (&tid, &nid)) in tree_ids.iter().zip(node_ids.iter()).enumerate() {
        distinct_trees.insert(tid);
        if node_map.insert((tid, nid), idx).is_some() {
            return Err(InferError::InvalidInput(
                "duplicate TreeEnsemble node key".into(),
            ));
        }
    }

    let mut score_sum = 0.0_f32;
    for tid in distinct_trees {
        let mut cur_nid: i64 = 0;
        let mut visited = BTreeSet::new();
        let mut resolved = false;
        for _ in 0..MAX_TREE_DEPTH {
            if !visited.insert(cur_nid) {
                return Err(InferError::InvalidInput("cycle in TreeEnsemble".into()));
            }
            if let Some(&w) = leaf_map.get(&(tid, cur_nid)) {
                score_sum += w;
                resolved = true;
                break;
            }
            let &pos = node_map
                .get(&(tid, cur_nid))
                .ok_or_else(|| InferError::InvalidInput("unresolved TreeEnsemble node".into()))?;
            let fid = usize::try_from(feat_ids.get(pos).copied().unwrap_or(-1))
                .map_err(|_| InferError::InvalidInput("negative TreeEnsemble feature id".into()))?;
            let fv = xf
                .get(fid)
                .copied()
                .ok_or_else(|| InferError::InvalidInput("TreeEnsemble feature OOB".into()))?;
            let thresh = values
                .get(pos)
                .copied()
                .ok_or_else(|| InferError::InvalidInput("TreeEnsemble value OOB".into()))?;
            let next = if fv <= thresh {
                trues.get(pos)
            } else {
                falses.get(pos)
            };
            cur_nid = next
                .copied()
                .ok_or_else(|| InferError::InvalidInput("TreeEnsemble branch OOB".into()))?;
        }
        if !resolved {
            return Err(InferError::InvalidInput(
                "TreeEnsemble depth exceeded or unresolved leaf".into(),
            ));
        }
    }
    if !score_sum.is_finite() {
        return Err(InferError::InvalidInput(
            "non-finite TreeEnsemble sum".into(),
        ));
    }
    let prob = 1.0_f32 / (1.0_f32 + (-score_sum).exp());
    if !prob.is_finite() {
        return Err(InferError::InvalidInput(
            "non-finite TreeEnsemble probability".into(),
        ));
    }
    Ok(vec![
        TensorValue {
            shape: vec![1, 1],
            data: TensorData::Int(vec![i64::from(prob >= 0.5)]),
        },
        TensorValue {
            shape: vec![1, 2],
            data: TensorData::Float(vec![1.0 - prob, prob]),
        },
    ])
}
