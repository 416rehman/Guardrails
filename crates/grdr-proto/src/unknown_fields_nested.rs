// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Descriptor-guided nested `900..=999` sealed-twin unknown-field preservation.

use std::collections::BTreeMap;

use prost::Message;

use crate::ProtoError;
use crate::descriptor::DescriptorSet;
use crate::unknown_fields::UnknownFields;
use crate::unknown_fields_nested_walk::{
    NestedCollectState, account_wire_chunk, build_indexed_messages, collect_nested_unknowns,
    rewrite_with_nested_unknowns,
};

pub const MAX_NESTED_NODES: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PathSegment {
    Singular(u32),
    Repeated { tag: u32, occ: usize },
    MapEntry { tag: u32, key_wire: Vec<u8> },
}

pub(crate) type NestedPath = Vec<PathSegment>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnknownFieldTree {
    pub(crate) root: UnknownFields,
    pub(crate) nested: BTreeMap<NestedPath, UnknownFields>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NestedPreservingEnvelope<M> {
    pub message: M,
    pub unknown_tree: UnknownFieldTree,
}

impl UnknownFieldTree {
    pub fn is_empty(&self) -> bool {
        self.root.is_empty() && self.nested.is_empty()
    }

    pub fn root(&self) -> &UnknownFields {
        &self.root
    }

    pub fn nested_count(&self) -> usize {
        self.nested.len()
    }

    pub(crate) fn merge_at(&mut self, path: &[PathSegment], slice: &[u8]) {
        let mut combined = if path.is_empty() {
            self.root.as_bytes().to_vec()
        } else {
            self.nested
                .get(path)
                .map(|u| u.as_bytes().to_vec())
                .unwrap_or_default()
        };
        combined.extend_from_slice(slice);
        let merged = UnknownFields::from_validated_raw(combined);
        if path.is_empty() {
            self.root = merged;
        } else {
            self.nested.insert(path.to_vec(), merged);
        }
    }

    pub(crate) fn remove_subtree(&mut self, prefix: &[PathSegment]) {
        self.nested.retain(|k, _| !k.starts_with(prefix));
    }

    pub(crate) fn has_prefix(&self, prefix: &[PathSegment]) -> bool {
        let start = prefix.to_vec();
        self.nested
            .range(start..)
            .next()
            .is_some_and(|(k, _)| k.starts_with(prefix))
    }

    pub(crate) fn chunk_at(&self, path: &[PathSegment]) -> Option<&UnknownFields> {
        if path.is_empty() {
            (!self.root.is_empty()).then_some(&self.root)
        } else {
            self.nested.get(path)
        }
    }
}

impl<M: Message + Default> NestedPreservingEnvelope<M> {
    pub fn decode_with_descriptor(
        bytes: &[u8],
        message_full_name: &str,
        set: &DescriptorSet,
    ) -> Result<Self, ProtoError> {
        let message = M::decode(bytes)
            .map_err(|e| ProtoError::InvalidPayload(format!("protobuf decode failed: {e}")))?;
        let index = build_indexed_messages(set);
        let key = message_full_name.trim_start_matches('.');
        let mut state = NestedCollectState::default();
        let mut tree = UnknownFieldTree::default();
        let mut path = Vec::new();
        collect_nested_unknowns(bytes, key, &index, &mut path, 0, &mut state, &mut tree)?;
        Ok(Self {
            message,
            unknown_tree: tree,
        })
    }

    pub fn encode_with_descriptor(
        &self,
        message_full_name: &str,
        set: &DescriptorSet,
    ) -> Result<Vec<u8>, ProtoError> {
        let mut total_count = 0usize;
        let mut total_bytes = 0usize;
        for chunk in
            std::iter::once(&self.unknown_tree.root).chain(self.unknown_tree.nested.values())
        {
            account_wire_chunk(chunk.as_bytes(), &mut total_count, &mut total_bytes)?;
        }
        let mut root_bytes = Vec::with_capacity(self.message.encoded_len());
        self.message
            .encode(&mut root_bytes)
            .map_err(|e| ProtoError::InvalidPayload(format!("protobuf encode failed: {e}")))?;
        let index = build_indexed_messages(set);
        let key = message_full_name.trim_start_matches('.');
        let mut nodes = 0usize;
        let mut path = Vec::new();
        rewrite_with_nested_unknowns(
            &root_bytes,
            key,
            &index,
            &mut path,
            0,
            &mut nodes,
            &self.unknown_tree,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::activity::{QueryCellKind, QueryCellValue, QueryRow};
    use crate::canonical::common_types::TargetRef;
    use crate::canonical::telemetry::event::{
        Action, Envelope, Event, ExecAction, action, event_payload,
    };
    use crate::descriptor::{
        FieldLabel, FieldType, MessageDescriptor, load_embedded_descriptor_set,
    };
    use crate::unknown_fields::MAX_NESTED_PRESERVE_DEPTH;
    use prost::encoding::encode_varint;

    #[test]
    fn preserves_nested_900_fields_split_singular_oneof_and_map_reordering() {
        let set = load_embedded_descriptor_set().unwrap();
        let mut exec1 = ExecAction {
            argv_count: 1,
            argv_digest: "sha256:abc".into(),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(905, &b"sealed-exec-cmd".to_vec(), &mut exec1);
        let mut env_a = Envelope {
            event_id: "evt-1".into(),
            organisation_id: "org-1".into(),
            device_id: "dev-1".into(),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(901, &b"env-part-1".to_vec(), &mut env_a);
        let mut env_b = Envelope {
            epoch: 1,
            lane: 2,
            seq: 1,
            event_class: "action.exec".into(),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(902, &b"env-part-2".to_vec(), &mut env_b);
        let mut act = Action {
            action_id: "act-1".into(),
            action_class: 1,
            phase: 1,
            outcome: 2,
            resolution: 1,
            target: Some(TargetRef {
                target_digest: "sha256:def".into(),
                classification: "cmd".into(),
                value: None,
            }),
            action_digest: "sha256:123".into(),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(12, &exec1, &mut act);
        // Superseded oneof arm: Action tag 2 then HealthEvent tag 9 then fresh Action tag 2 without 905 -> stale 905 dropped, or split singular Envelope merges 901+902.
        let mut root_wire = Vec::new();
        prost::encoding::bytes::encode(1, &env_a, &mut root_wire);
        prost::encoding::bytes::encode(1, &env_b, &mut root_wire);
        prost::encoding::bytes::encode(2, &act, &mut root_wire);
        prost::encoding::bytes::encode(909, &b"sealed-root".to_vec(), &mut root_wire);

        let mut env = NestedPreservingEnvelope::<Event>::decode_with_descriptor(
            &root_wire,
            "grdr.event.v1alpha1.Event",
            &set,
        )
        .unwrap();
        assert!(!env.unknown_tree.root().is_empty());
        assert_eq!(env.unknown_tree.nested_count(), 2);
        if let Some(event_payload::Payload::Action(ref mut a)) = env.message.payload
            && let Some(action::Detail::Exec(ref mut ex)) = a.detail
        {
            ex.argv_count = 9;
        }
        let encoded = env
            .encode_with_descriptor("grdr.event.v1alpha1.Event", &set)
            .unwrap();
        let redecoded = NestedPreservingEnvelope::<Event>::decode_with_descriptor(
            &encoded,
            "grdr.event.v1alpha1.Event",
            &set,
        )
        .unwrap();
        assert_eq!(redecoded.unknown_tree, env.unknown_tree);

        // Superseded oneof drops stale sealed twin on earlier arm.
        let mut superseded_wire = Vec::new();
        prost::encoding::bytes::encode(2, &act, &mut superseded_wire);
        let health_wire = crate::canonical::event::HealthEvent {
            code: "ok".into(),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(9, &health_wire, &mut superseded_wire);
        let act_clean = Action {
            action_id: "act-clean".into(),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(2, &act_clean, &mut superseded_wire);
        let sup = NestedPreservingEnvelope::<Event>::decode_with_descriptor(
            &superseded_wire,
            "grdr.event.v1alpha1.Event",
            &set,
        )
        .unwrap();
        assert!(sup.unknown_tree.is_empty());

        // Map entries coded out-of-order ("z" then "a") stay bound to their exact map keys after BTreeMap sort.
        let mut cell_z = QueryCellValue {
            kind: Some(QueryCellKind::Text("z-txt".into())),
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(901, &b"seal-z".to_vec(), &mut cell_z);
        let mut cell_a = QueryCellValue {
            kind: Some(QueryCellKind::Text("a-txt".into())),
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(902, &b"seal-a".to_vec(), &mut cell_a);
        let mut map_z = Vec::new();
        prost::encoding::string::encode(1, &"z".to_owned(), &mut map_z);
        prost::encoding::bytes::encode(2, &cell_z, &mut map_z);
        let mut map_a = Vec::new();
        prost::encoding::string::encode(1, &"a".to_owned(), &mut map_a);
        prost::encoding::bytes::encode(2, &cell_a, &mut map_a);
        let mut row_wire = Vec::new();
        prost::encoding::bytes::encode(1, &map_z, &mut row_wire);
        prost::encoding::bytes::encode(1, &map_a, &mut row_wire);
        let row_env = NestedPreservingEnvelope::<QueryRow>::decode_with_descriptor(
            &row_wire,
            "grdr.api.activity.v1alpha1.QueryRow",
            &set,
        )
        .unwrap();
        let row_out = row_env
            .encode_with_descriptor("grdr.api.activity.v1alpha1.QueryRow", &set)
            .unwrap();
        let row_re = NestedPreservingEnvelope::<QueryRow>::decode_with_descriptor(
            &row_out,
            "grdr.api.activity.v1alpha1.QueryRow",
            &set,
        )
        .unwrap();
        let key_z = PathSegment::MapEntry {
            tag: 1,
            key_wire: row_wire[2..4].to_vec(),
        };
        let _ = key_z;
        assert_eq!(row_re.unknown_tree, row_env.unknown_tree);
    }

    #[test]
    fn rejects_nested_lower_tag_group_missing_descriptor_depth_and_global_caps() {
        let set = load_embedded_descriptor_set().unwrap();
        let mut bad_env = Envelope {
            event_id: "e1".into(),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::string::encode(888, &"smuggled".into(), &mut bad_env);
        let mut root_bad = Vec::new();
        prost::encoding::bytes::encode(1, &bad_env, &mut root_bad);
        assert!(
            NestedPreservingEnvelope::<Event>::decode_with_descriptor(
                &root_bad,
                "grdr.event.v1alpha1.Event",
                &set
            )
            .is_err()
        );

        let mut grp_env = Vec::new();
        encode_varint((901u64 << 3) | 3, &mut grp_env);
        let mut root_grp = Vec::new();
        prost::encoding::bytes::encode(1, &grp_env, &mut root_grp);
        assert!(
            NestedPreservingEnvelope::<Event>::decode_with_descriptor(
                &root_grp,
                "grdr.event.v1alpha1.Event",
                &set
            )
            .is_err()
        );

        let mut missing_set = set.clone();
        for f in &mut missing_set.files {
            f.messages.retain(|m| m.name != "Envelope");
        }
        let mut valid_env = Envelope {
            event_id: "e1".into(),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(901, &b"ok".to_vec(), &mut valid_env);
        let mut root_missing = Vec::new();
        prost::encoding::bytes::encode(1, &valid_env, &mut root_missing);
        assert!(
            NestedPreservingEnvelope::<Event>::decode_with_descriptor(
                &root_missing,
                "grdr.event.v1alpha1.Event",
                &set
            )
            .is_ok()
        );
        assert!(
            NestedPreservingEnvelope::<Event>::decode_with_descriptor(
                &root_missing,
                "grdr.event.v1alpha1.Event",
                &missing_set
            )
            .is_err()
        );

        let mut cap_env = Envelope {
            event_id: "e1".into(),
            ..Default::default()
        }
        .encode_to_vec();
        for _ in 0..40 {
            prost::encoding::uint64::encode(901, &1u64, &mut cap_env);
        }
        let mut cap_root = Vec::new();
        prost::encoding::bytes::encode(1, &cap_env, &mut cap_root);
        for _ in 0..25 {
            prost::encoding::uint64::encode(902, &2u64, &mut cap_root);
        }
        assert!(
            NestedPreservingEnvelope::<Event>::decode_with_descriptor(
                &cap_root,
                "grdr.event.v1alpha1.Event",
                &set
            )
            .is_err()
        );

        // Depth > 32
        let mut rec_set = DescriptorSet { files: vec![] };
        rec_set.files.push(crate::descriptor::FileDescriptor {
            name: "r.proto".into(),
            package: "r".into(),
            dependencies: vec![],
            public_dependencies: vec![],
            weak_dependencies: vec![],
            messages: vec![MessageDescriptor {
                name: "Node".into(),
                fields: vec![crate::descriptor::FieldDescriptor {
                    name: "child".into(),
                    number: 1,
                    label: FieldLabel::Optional,
                    kind: FieldType::Message,
                    type_name: ".r.Node".into(),
                    extendee: String::new(),
                    oneof_index: None,
                    proto3_optional: false,
                    raw_options: vec![],
                }],
                nested_messages: vec![],
                nested_enums: vec![],
                nested_extensions: vec![],
                reserved_ranges: vec![],
                oneofs: vec![],
                is_map_entry: false,
            }],
            enums: vec![],
            services: vec![],
            extensions: vec![],
            syntax: "proto3".into(),
            raw_proto_bytes: vec![],
        });
        let mut wire = Vec::new();
        for _ in 0..=(MAX_NESTED_PRESERVE_DEPTH + 1) {
            let mut next = Vec::new();
            prost::encoding::bytes::encode(1, &wire, &mut next);
            wire = next;
        }
        assert!(
            NestedPreservingEnvelope::<crate::common::RevisionMeta>::decode_with_descriptor(
                &wire, "r.Node", &rec_set
            )
            .is_err()
        );
    }

    #[test]
    fn preserves_split_singular_action_facts_and_supersedes_nested_oneof() {
        let set = load_embedded_descriptor_set().unwrap();
        let mut fact0 = crate::canonical::telemetry::event::DeterministicFact {
            key: "k0".into(),
            origin: 1,
            analyser: "test".into(),
            value: None,
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(901, &b"f0-seal".to_vec(), &mut fact0);
        let mut fact1 = crate::canonical::telemetry::event::DeterministicFact {
            key: "k1".into(),
            origin: 1,
            analyser: "test".into(),
            value: None,
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(902, &b"f1-seal".to_vec(), &mut fact1);
        let mut exec_old = ExecAction {
            argv_count: 1,
            argv_digest: "sha256:old".into(),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(905, &b"stale-exec-seal".to_vec(), &mut exec_old);
        let file_mid = crate::canonical::telemetry::event::FileAction {
            content_digest: Some("sha256:mid".into()),
            ..Default::default()
        }
        .encode_to_vec();
        let exec_new = ExecAction {
            argv_count: 2,
            argv_digest: "sha256:new".into(),
            ..Default::default()
        }
        .encode_to_vec();

        let mut act_chunk1 = Action {
            action_id: "a1".into(),
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::bytes::encode(8, &fact0, &mut act_chunk1);
        prost::encoding::bytes::encode(12, &exec_old, &mut act_chunk1);

        let mut act_chunk2 = Vec::new();
        prost::encoding::bytes::encode(8, &fact1, &mut act_chunk2);
        prost::encoding::bytes::encode(13, &file_mid, &mut act_chunk2);

        let mut act_chunk3 = Vec::new();
        prost::encoding::bytes::encode(12, &exec_new, &mut act_chunk3);

        let mut wire = Vec::new();
        prost::encoding::bytes::encode(2, &act_chunk1, &mut wire);
        prost::encoding::bytes::encode(2, &act_chunk2, &mut wire);
        prost::encoding::bytes::encode(2, &act_chunk3, &mut wire);

        let env = NestedPreservingEnvelope::<Event>::decode_with_descriptor(
            &wire,
            "grdr.event.v1alpha1.Event",
            &set,
        )
        .unwrap();
        assert_eq!(env.unknown_tree.nested_count(), 2);
        let out = env
            .encode_with_descriptor("grdr.event.v1alpha1.Event", &set)
            .unwrap();
        assert!(
            !out.windows(b"stale-exec-seal".len())
                .any(|w| w == b"stale-exec-seal")
        );
        let re = NestedPreservingEnvelope::<Event>::decode_with_descriptor(
            &out,
            "grdr.event.v1alpha1.Event",
            &set,
        )
        .unwrap();
        assert_eq!(re.unknown_tree, env.unknown_tree);
    }

    #[test]
    fn enforces_max_nested_nodes_4096_and_canonicalizes_varint_bool_map_keys() {
        #[derive(Clone, PartialEq, prost::Message)]
        struct DummyMsg {}
        let mut r_set = DescriptorSet { files: vec![] };
        r_set.files.push(crate::descriptor::FileDescriptor {
            name: "n.proto".into(),
            package: "n".into(),
            dependencies: vec![],
            public_dependencies: vec![],
            weak_dependencies: vec![],
            messages: vec![MessageDescriptor {
                name: "Node".into(),
                fields: vec![crate::descriptor::FieldDescriptor {
                    name: "children".into(),
                    number: 1,
                    label: FieldLabel::Repeated,
                    kind: FieldType::Message,
                    type_name: ".n.Node".into(),
                    extendee: String::new(),
                    oneof_index: None,
                    proto3_optional: false,
                    raw_options: vec![],
                }],
                nested_messages: vec![],
                nested_enums: vec![],
                nested_extensions: vec![],
                reserved_ranges: vec![],
                oneofs: vec![],
                is_map_entry: false,
            }],
            enums: vec![],
            services: vec![],
            extensions: vec![],
            syntax: "proto3".into(),
            raw_proto_bytes: vec![],
        });
        let mut ok_wire = Vec::new();
        for _ in 0..4095 {
            prost::encoding::bytes::encode(1, &Vec::new(), &mut ok_wire);
        }
        assert!(
            NestedPreservingEnvelope::<DummyMsg>::decode_with_descriptor(
                &ok_wire, "n.Node", &r_set
            )
            .is_ok()
        );
        prost::encoding::bytes::encode(1, &Vec::new(), &mut ok_wire);
        assert!(
            NestedPreservingEnvelope::<DummyMsg>::decode_with_descriptor(
                &ok_wire, "n.Node", &r_set
            )
            .is_err()
        );

        let entry = |name: &str, key_kind: FieldType| MessageDescriptor {
            name: name.into(),
            fields: vec![
                crate::descriptor::FieldDescriptor {
                    name: "key".into(),
                    number: 1,
                    label: FieldLabel::Optional,
                    kind: key_kind,
                    type_name: String::new(),
                    extendee: String::new(),
                    oneof_index: None,
                    proto3_optional: false,
                    raw_options: vec![],
                },
                crate::descriptor::FieldDescriptor {
                    name: "value".into(),
                    number: 2,
                    label: FieldLabel::Optional,
                    kind: FieldType::Message,
                    type_name: ".m.Val".into(),
                    extendee: String::new(),
                    oneof_index: None,
                    proto3_optional: false,
                    raw_options: vec![],
                },
            ],
            nested_messages: vec![],
            nested_enums: vec![],
            nested_extensions: vec![],
            reserved_ranges: vec![],
            oneofs: vec![],
            is_map_entry: true,
        };
        let mut m_set = DescriptorSet { files: vec![] };
        m_set.files.push(crate::descriptor::FileDescriptor {
            name: "m.proto".into(),
            package: "m".into(),
            dependencies: vec![],
            public_dependencies: vec![],
            weak_dependencies: vec![],
            messages: vec![
                MessageDescriptor {
                    name: "Val".into(),
                    fields: vec![],
                    nested_messages: vec![],
                    nested_enums: vec![],
                    nested_extensions: vec![],
                    reserved_ranges: vec![],
                    oneofs: vec![],
                    is_map_entry: false,
                },
                MessageDescriptor {
                    name: "Holder".into(),
                    fields: vec![
                        crate::descriptor::FieldDescriptor {
                            name: "u".into(),
                            number: 1,
                            label: FieldLabel::Repeated,
                            kind: FieldType::Message,
                            type_name: ".m.Holder.UEntry".into(),
                            extendee: String::new(),
                            oneof_index: None,
                            proto3_optional: false,
                            raw_options: vec![],
                        },
                        crate::descriptor::FieldDescriptor {
                            name: "b".into(),
                            number: 2,
                            label: FieldLabel::Repeated,
                            kind: FieldType::Message,
                            type_name: ".m.Holder.BEntry".into(),
                            extendee: String::new(),
                            oneof_index: None,
                            proto3_optional: false,
                            raw_options: vec![],
                        },
                    ],
                    nested_messages: vec![
                        entry("UEntry", FieldType::Uint64),
                        entry("BEntry", FieldType::Bool),
                    ],
                    nested_enums: vec![],
                    nested_extensions: vec![],
                    reserved_ranges: vec![],
                    oneofs: vec![],
                    is_map_entry: false,
                },
            ],
            enums: vec![],
            services: vec![],
            extensions: vec![],
            syntax: "proto3".into(),
            raw_proto_bytes: vec![],
        });

        let mut val_old = Vec::new();
        prost::encoding::bytes::encode(901, &b"stale-u".to_vec(), &mut val_old);
        let mut val_new = Vec::new();
        prost::encoding::bytes::encode(902, &b"fresh-u".to_vec(), &mut val_new);
        let mut u_overlong = vec![(1u8 << 3), 0x85, 0x00];
        prost::encoding::bytes::encode(2, &val_old, &mut u_overlong);
        let mut u_canon = vec![(1u8 << 3), 0x05];
        prost::encoding::bytes::encode(2, &val_new, &mut u_canon);
        let mut b_two = vec![(1u8 << 3), 0x02];
        prost::encoding::bytes::encode(2, &val_old, &mut b_two);
        let mut b_one = vec![(1u8 << 3), 0x01];
        prost::encoding::bytes::encode(2, &val_new, &mut b_one);

        let mut m_wire = Vec::new();
        prost::encoding::bytes::encode(1, &u_overlong, &mut m_wire);
        prost::encoding::bytes::encode(1, &u_canon, &mut m_wire);
        prost::encoding::bytes::encode(2, &b_two, &mut m_wire);
        prost::encoding::bytes::encode(2, &b_one, &mut m_wire);

        let dec = NestedPreservingEnvelope::<DummyMsg>::decode_with_descriptor(
            &m_wire, "m.Holder", &m_set,
        )
        .unwrap();
        assert_eq!(dec.unknown_tree.nested_count(), 2);
        for u in dec.unknown_tree.nested.values() {
            assert!(
                !u.as_bytes()
                    .windows(b"stale-u".len())
                    .any(|w| w == b"stale-u")
            );
        }
    }
}
