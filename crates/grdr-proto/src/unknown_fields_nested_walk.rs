// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Wire walker and budget helpers for descriptor-guided nested unknown preservation.

use std::collections::{BTreeMap, BTreeSet};

use prost::bytes::Buf;
use prost::encoding::{WireType, decode_key, decode_varint, encode_varint};

use crate::ProtoError;
use crate::descriptor::{DescriptorSet, FieldLabel, FieldType, MessageDescriptor};
use crate::descriptor_wire::skip_other_field;
use crate::unknown_fields::{
    MAX_NESTED_PRESERVE_DEPTH, MAX_UNKNOWN_FIELD_BYTES, MAX_UNKNOWN_FIELD_COUNT,
    UNKNOWN_FIELD_MAX_TAG, UNKNOWN_FIELD_MIN_TAG, validate_unknown_wire_slice,
};
use crate::unknown_fields_nested::{MAX_NESTED_NODES, NestedPath, PathSegment, UnknownFieldTree};

#[derive(Clone, Copy)]
pub(crate) struct IndexedField<'a> {
    kind: FieldType,
    label: FieldLabel,
    child_name: &'a str,
    oneof_index: Option<i32>,
    is_map: bool,
}

pub(crate) struct IndexedMessage<'a> {
    fields: BTreeMap<u32, IndexedField<'a>>,
    known_tags: BTreeSet<u32>,
    key_kind: Option<FieldType>,
}

#[derive(Default)]
pub(crate) struct NestedCollectState {
    visited_nodes: usize,
    total_count: usize,
    total_bytes: usize,
    occ_state: BTreeMap<(NestedPath, u32), usize>,
    oneof_state: BTreeMap<(NestedPath, i32), u32>,
}

impl NestedCollectState {
    fn prune_prefix(&mut self, prefix: &[PathSegment]) {
        self.occ_state.retain(|(p, _), _| !p.starts_with(prefix));
        self.oneof_state.retain(|(p, _), _| !p.starts_with(prefix));
    }
}

fn collect_raw<'a>(
    prefix: &str,
    msg: &'a MessageDescriptor,
    out: &mut BTreeMap<String, &'a MessageDescriptor>,
) {
    let full = if prefix.is_empty() {
        msg.name.clone()
    } else {
        format!("{prefix}.{}", msg.name)
    };
    for nested in &msg.nested_messages {
        collect_raw(&full, nested, out);
    }
    out.insert(full, msg);
}

pub(crate) fn build_indexed_messages(set: &DescriptorSet) -> BTreeMap<String, IndexedMessage<'_>> {
    let mut raw = BTreeMap::new();
    for f in &set.files {
        for m in &f.messages {
            collect_raw(&f.package, m, &mut raw);
        }
    }
    let mut out = BTreeMap::new();
    for (full, desc) in &raw {
        let (mut fields, mut known_tags, mut key_kind) = (BTreeMap::new(), BTreeSet::new(), None);
        for f in &desc.fields {
            if let Ok(tag) = u32::try_from(f.number) {
                known_tags.insert(tag);
                if desc.is_map_entry && tag == 1 {
                    key_kind = Some(f.kind);
                }
                let child_name = f.type_name.trim_start_matches('.');
                let is_map = f.label == FieldLabel::Repeated
                    && f.kind == FieldType::Message
                    && raw.get(child_name).is_some_and(|c| c.is_map_entry);
                let oneof_index = if f.proto3_optional {
                    None
                } else {
                    f.oneof_index
                };
                fields.insert(
                    tag,
                    IndexedField {
                        kind: f.kind,
                        label: f.label,
                        child_name,
                        oneof_index,
                        is_map,
                    },
                );
            }
        }
        out.insert(
            full.clone(),
            IndexedMessage {
                fields,
                known_tags,
                key_kind,
            },
        );
    }
    out
}

fn canonical_map_entry_key(
    bytes: &[u8],
    key_kind: Option<FieldType>,
) -> Result<Vec<u8>, ProtoError> {
    let mut cursor = bytes;
    let mut last_key_bytes: Option<Vec<u8>> = None;
    let mut last_wire = WireType::Varint;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor)
            .map_err(|e| ProtoError::InvalidPayload(format!("map key wire error: {e}")))?;
        let val_start = bytes.len().saturating_sub(cursor.len());
        skip_other_field(wire, tag, &mut cursor)?;
        let val_end = bytes.len().saturating_sub(cursor.len());
        if tag == 1 {
            last_wire = wire;
            let slice = bytes
                .get(val_start..val_end)
                .ok_or_else(|| ProtoError::InvalidPayload("map key slice oob".into()))?;
            last_key_bytes = Some(slice.to_vec());
        }
    }
    let Some(raw) = last_key_bytes else {
        return Ok(Vec::new());
    };
    if last_wire == WireType::Varint {
        let mut c = raw.as_slice();
        let v = decode_varint(&mut c)
            .map_err(|e| ProtoError::InvalidPayload(format!("map key varint error: {e}")))?;
        if !c.is_empty() {
            return Err(ProtoError::InvalidPayload(
                "trailing bytes in map key varint".into(),
            ));
        }
        if v == 0 {
            return Ok(Vec::new());
        }
        if key_kind == Some(FieldType::Bool) {
            return Ok(vec![1]);
        }
        let mut norm = Vec::new();
        encode_varint(v, &mut norm);
        return Ok(norm);
    }
    if matches!(
        (key_kind, last_wire),
        (
            Some(FieldType::String | FieldType::Bytes),
            WireType::LengthDelimited
        )
    ) {
        let mut c = raw.as_slice();
        let len = decode_varint(&mut c)
            .map_err(|e| ProtoError::InvalidPayload(format!("map key len error: {e}")))?;
        let len_us = usize::try_from(len)
            .map_err(|_| ProtoError::InvalidPayload("map key len overflows usize".into()))?;
        if c.len() != len_us {
            return Err(ProtoError::InvalidPayload(
                "malformed length-delimited map key".into(),
            ));
        }
        if len_us == 0 {
            return Ok(Vec::new());
        }
        let mut norm = Vec::new();
        encode_varint(len, &mut norm);
        norm.extend_from_slice(c);
        return Ok(norm);
    }
    let is_default = matches!(last_wire, WireType::ThirtyTwoBit | WireType::SixtyFourBit)
        && raw.iter().all(|&b| b == 0);
    Ok(if is_default { Vec::new() } else { raw })
}

fn read_submessage_slice<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], ProtoError> {
    let len_u64 = decode_varint(cursor)
        .map_err(|e| ProtoError::InvalidPayload(format!("submessage len: {e}")))?;
    let len = usize::try_from(len_u64)
        .map_err(|_| ProtoError::InvalidPayload("submessage len overflows usize".into()))?;
    let sub_slice = cursor
        .get(..len)
        .ok_or_else(|| ProtoError::InvalidPayload("truncated submessage".into()))?;
    *cursor = cursor
        .get(len..)
        .ok_or_else(|| ProtoError::InvalidPayload("truncated submessage cursor".into()))?;
    Ok(sub_slice)
}

fn bump_node_budget(depth: usize, visited_nodes: &mut usize) -> Result<usize, ProtoError> {
    if depth > MAX_NESTED_PRESERVE_DEPTH {
        return Err(ProtoError::ConstraintViolation(format!(
            "nested message depth exceeds MAX_NESTED_PRESERVE_DEPTH ({MAX_NESTED_PRESERVE_DEPTH})"
        )));
    }
    *visited_nodes = visited_nodes
        .checked_add(1)
        .ok_or_else(|| ProtoError::ConstraintViolation("nested node count overflow".into()))?;
    if *visited_nodes > MAX_NESTED_NODES {
        return Err(ProtoError::ConstraintViolation(format!(
            "nested traversal exceeds MAX_NESTED_NODES ({MAX_NESTED_NODES})"
        )));
    }
    depth
        .checked_add(1)
        .ok_or_else(|| ProtoError::ConstraintViolation("depth overflow".into()))
}

fn account_field_budget(
    len: usize,
    total_count: &mut usize,
    total_bytes: &mut usize,
) -> Result<(), ProtoError> {
    *total_count = total_count
        .checked_add(1)
        .ok_or_else(|| ProtoError::ConstraintViolation("unknown field count overflow".into()))?;
    if *total_count > MAX_UNKNOWN_FIELD_COUNT {
        return Err(ProtoError::ConstraintViolation(format!(
            "nested unknown fields exceed MAX_UNKNOWN_FIELD_COUNT ({MAX_UNKNOWN_FIELD_COUNT})"
        )));
    }
    *total_bytes = total_bytes.checked_add(len).ok_or_else(|| {
        ProtoError::ConstraintViolation("unknown field byte count overflow".into())
    })?;
    if *total_bytes > MAX_UNKNOWN_FIELD_BYTES {
        return Err(ProtoError::ConstraintViolation(format!(
            "nested unknown fields exceed MAX_UNKNOWN_FIELD_BYTES ({MAX_UNKNOWN_FIELD_BYTES})"
        )));
    }
    Ok(())
}

pub(crate) fn account_wire_chunk(
    chunk: &[u8],
    total_count: &mut usize,
    total_bytes: &mut usize,
) -> Result<(), ProtoError> {
    let mut cursor = chunk;
    while cursor.has_remaining() {
        let start = chunk.len().saturating_sub(cursor.len());
        let (tag, wire) = decode_key(&mut cursor)
            .map_err(|e| ProtoError::InvalidPayload(format!("tree unknown key error: {e}")))?;
        skip_other_field(wire, tag, &mut cursor)?;
        let end = chunk.len().saturating_sub(cursor.len());
        account_field_budget(end.saturating_sub(start), total_count, total_bytes)?;
    }
    Ok(())
}

pub(crate) fn collect_nested_unknowns(
    bytes: &[u8],
    msg_full_name: &str,
    index: &BTreeMap<String, IndexedMessage<'_>>,
    path: &mut NestedPath,
    depth: usize,
    state: &mut NestedCollectState,
    tree: &mut UnknownFieldTree,
) -> Result<(), ProtoError> {
    let next_depth = bump_node_budget(depth, &mut state.visited_nodes)?;
    let msg_idx = index.get(msg_full_name).ok_or_else(|| {
        ProtoError::InvalidPayload(format!("missing message descriptor `{msg_full_name}`"))
    })?;
    let mut cursor = bytes;
    let mut local_unknown = Vec::new();

    while cursor.has_remaining() {
        let field_start = bytes.len().saturating_sub(cursor.len());
        let (tag, wire) = decode_key(&mut cursor)
            .map_err(|e| ProtoError::InvalidPayload(format!("nested wire key error: {e}")))?;
        if let Some(&field) = msg_idx.fields.get(&tag) {
            if let Some(oo_idx) = field.oneof_index
                && let Some(prev_tag) = state.oneof_state.insert((path.clone(), oo_idx), tag)
                && prev_tag != tag
            {
                path.push(PathSegment::Singular(prev_tag));
                tree.remove_subtree(path);
                state.prune_prefix(path);
                path.pop();
            }
            if field.kind == FieldType::Message && wire == WireType::LengthDelimited {
                let child_idx = index.get(field.child_name).ok_or_else(|| {
                    ProtoError::InvalidPayload(format!(
                        "missing child message descriptor `{}`",
                        field.child_name
                    ))
                })?;
                let sub_slice = read_submessage_slice(&mut cursor)?;
                let seg = if field.is_map {
                    let key_wire = canonical_map_entry_key(sub_slice, child_idx.key_kind)?;
                    let seg = PathSegment::MapEntry { tag, key_wire };
                    path.push(seg.clone());
                    tree.remove_subtree(path);
                    state.prune_prefix(path);
                    path.pop();
                    seg
                } else if field.label == FieldLabel::Repeated {
                    let occ = state
                        .occ_state
                        .get(&(path.clone(), tag))
                        .copied()
                        .unwrap_or(0);
                    let next_occ = occ
                        .checked_add(1)
                        .ok_or_else(|| ProtoError::ConstraintViolation("occ overflow".into()))?;
                    state.occ_state.insert((path.clone(), tag), next_occ);
                    PathSegment::Repeated { tag, occ }
                } else {
                    PathSegment::Singular(tag)
                };
                path.push(seg);
                collect_nested_unknowns(
                    sub_slice,
                    field.child_name,
                    index,
                    path,
                    next_depth,
                    state,
                    tree,
                )?;
                path.pop();
            } else {
                skip_other_field(wire, tag, &mut cursor)?;
            }
        } else {
            skip_other_field(wire, tag, &mut cursor)?;
            let field_end = bytes.len().saturating_sub(cursor.len());
            if !(UNKNOWN_FIELD_MIN_TAG..=UNKNOWN_FIELD_MAX_TAG).contains(&tag) {
                return Err(ProtoError::ConstraintViolation(format!(
                    "unmatched tag {tag} in `{msg_full_name}` outside 900..=999"
                )));
            }
            let slice = bytes
                .get(field_start..field_end)
                .ok_or_else(|| ProtoError::InvalidPayload("nested slice oob".into()))?;
            account_field_budget(slice.len(), &mut state.total_count, &mut state.total_bytes)?;
            local_unknown.extend_from_slice(slice);
        }
    }
    if !local_unknown.is_empty() {
        tree.merge_at(path, &local_unknown);
    }
    Ok(())
}

pub(crate) fn rewrite_with_nested_unknowns(
    bytes: &[u8],
    msg_full_name: &str,
    index: &BTreeMap<String, IndexedMessage<'_>>,
    path: &mut NestedPath,
    depth: usize,
    visited_nodes: &mut usize,
    tree: &UnknownFieldTree,
) -> Result<Vec<u8>, ProtoError> {
    let next_depth = bump_node_budget(depth, visited_nodes)?;
    let msg_idx = index.get(msg_full_name).ok_or_else(|| {
        ProtoError::InvalidPayload(format!("missing message descriptor `{msg_full_name}`"))
    })?;
    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = bytes;
    let mut occ_map: BTreeMap<u32, usize> = BTreeMap::new();
    while cursor.has_remaining() {
        let field_start = bytes.len().saturating_sub(cursor.len());
        let (tag, wire) = decode_key(&mut cursor)
            .map_err(|e| ProtoError::InvalidPayload(format!("rewrite wire key: {e}")))?;
        if let Some(&field) = msg_idx.fields.get(&tag)
            && field.kind == FieldType::Message
            && wire == WireType::LengthDelimited
        {
            let child_idx = index.get(field.child_name).ok_or_else(|| {
                ProtoError::InvalidPayload(format!(
                    "missing child message descriptor `{}`",
                    field.child_name
                ))
            })?;
            let sub_slice = read_submessage_slice(&mut cursor)?;
            let seg = if field.is_map {
                PathSegment::MapEntry {
                    tag,
                    key_wire: canonical_map_entry_key(sub_slice, child_idx.key_kind)?,
                }
            } else if field.label == FieldLabel::Repeated {
                let occ = occ_map.get(&tag).copied().unwrap_or(0);
                let next_occ = occ
                    .checked_add(1)
                    .ok_or_else(|| ProtoError::ConstraintViolation("occ overflow".into()))?;
                occ_map.insert(tag, next_occ);
                PathSegment::Repeated { tag, occ }
            } else {
                PathSegment::Singular(tag)
            };
            path.push(seg);
            if tree.has_prefix(path) {
                let child_rewritten = rewrite_with_nested_unknowns(
                    sub_slice,
                    field.child_name,
                    index,
                    path,
                    next_depth,
                    visited_nodes,
                    tree,
                )?;
                encode_varint((u64::from(tag) << 3) | 2u64, &mut out);
                encode_varint(child_rewritten.len() as u64, &mut out);
                out.extend_from_slice(&child_rewritten);
            } else {
                let field_end = bytes.len().saturating_sub(cursor.len());
                let slice = bytes
                    .get(field_start..field_end)
                    .ok_or_else(|| ProtoError::InvalidPayload("rewrite field slice oob".into()))?;
                out.extend_from_slice(slice);
            }
            path.pop();
        } else {
            skip_other_field(wire, tag, &mut cursor)?;
            let field_end = bytes.len().saturating_sub(cursor.len());
            let slice = bytes
                .get(field_start..field_end)
                .ok_or_else(|| ProtoError::InvalidPayload("rewrite scalar slice oob".into()))?;
            out.extend_from_slice(slice);
        }
    }
    let chunk_opt = tree.chunk_at(path);
    if let Some(chunk) = chunk_opt {
        validate_unknown_wire_slice(
            chunk.as_bytes(),
            &msg_idx.known_tags,
            MAX_UNKNOWN_FIELD_COUNT,
            MAX_UNKNOWN_FIELD_BYTES,
        )?;
        out.extend_from_slice(chunk.as_bytes());
    }
    Ok(out)
}
