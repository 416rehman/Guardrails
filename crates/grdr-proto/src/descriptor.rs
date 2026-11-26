// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Offline protobuf FileDescriptorSet decoder backed by the committed `proto.binpb`.

use std::collections::BTreeMap;

use prost::bytes::Buf;
use prost::encoding::{WireType, decode_key, decode_varint};

use crate::ProtoError;
use crate::descriptor_wire::{
    MAX_DESCRIPTOR_BYTES, decode_file_descriptor, read_len_delimited, skip_other_field,
};

pub const FILE_DESCRIPTOR_SET_BYTES: &[u8] = include_bytes!("../descriptors/proto.binpb");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorSet {
    pub files: Vec<FileDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileDescriptor {
    pub name: String,
    pub package: String,
    pub dependencies: Vec<String>,
    pub public_dependencies: Vec<i32>,
    pub weak_dependencies: Vec<i32>,
    pub messages: Vec<MessageDescriptor>,
    pub enums: Vec<EnumDescriptor>,
    pub services: Vec<ServiceDescriptor>,
    pub extensions: Vec<FieldDescriptor>,
    pub syntax: String,
    pub raw_proto_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDescriptor {
    pub name: String,
    pub fields: Vec<FieldDescriptor>,
    pub nested_messages: Vec<MessageDescriptor>,
    pub nested_enums: Vec<EnumDescriptor>,
    pub nested_extensions: Vec<FieldDescriptor>,
    pub reserved_ranges: Vec<ReservedRange>,
    pub oneofs: Vec<String>,
    pub is_map_entry: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservedRange {
    pub start: i32,
    pub end_exclusive: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDescriptor {
    pub name: String,
    pub number: i32,
    pub label: FieldLabel,
    pub kind: FieldType,
    pub type_name: String,
    pub extendee: String,
    pub oneof_index: Option<i32>,
    pub proto3_optional: bool,
    pub raw_options: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldLabel {
    Optional,
    Required,
    Repeated,
    Unknown(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    Double,
    Float,
    Int64,
    Uint64,
    Int32,
    Fixed64,
    Fixed32,
    Bool,
    String,
    Group,
    Message,
    Bytes,
    Uint32,
    Enum,
    Sfixed32,
    Sfixed64,
    Sint32,
    Sint64,
    Unknown(i32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumDescriptor {
    pub name: String,
    pub values: Vec<EnumValueDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumValueDescriptor {
    pub name: String,
    pub number: i32,
    pub raw_options: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDescriptor {
    pub name: String,
    pub methods: Vec<MethodDescriptorProto>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodDescriptorProto {
    pub name: String,
    pub input_type: String,
    pub output_type: String,
    pub client_streaming: bool,
    pub server_streaming: bool,
    pub raw_options: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedOptionsExtension {
    pub package: String,
    pub field_data_class_tag: i32,
    pub field_content_kind_tag: i32,
    pub field_policy_readable_tag: i32,
    pub field_sealable_tag: i32,
    pub enum_wire_name_tag: i32,
}

pub fn load_embedded_descriptor_set() -> Result<DescriptorSet, ProtoError> {
    decode_descriptor_set(FILE_DESCRIPTOR_SET_BYTES)
}

pub fn decode_descriptor_set(bytes: &[u8]) -> Result<DescriptorSet, ProtoError> {
    if bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err(ProtoError::ConstraintViolation(format!(
            "descriptor set exceeds MAX_DESCRIPTOR_BYTES ({MAX_DESCRIPTOR_BYTES})"
        )));
    }
    let mut files = Vec::new();
    let mut budget = 0usize;
    let mut cursor = bytes;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor)
            .map_err(|e| ProtoError::InvalidPayload(format!("descriptor set key error: {e}")))?;
        if tag == 1 {
            if wire != WireType::LengthDelimited {
                return Err(ProtoError::InvalidPayload(format!(
                    "descriptor set tag 1 expected LengthDelimited, got {wire:?}"
                )));
            }
            let slice = read_len_delimited(&mut cursor)?;
            let mut file = decode_file_descriptor(slice, 0, &mut budget)?;
            file.raw_proto_bytes = slice.to_vec();
            files.push(file);
        } else {
            skip_other_field(wire, tag, &mut cursor)?;
        }
    }
    Ok(DescriptorSet { files })
}

pub fn read_varint_option(raw_options: &[u8], target_tag: i32) -> Result<Option<u64>, ProtoError> {
    let mut cursor = raw_options;
    let mut result = None;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor)
            .map_err(|e| ProtoError::InvalidPayload(format!("options key error: {e}")))?;
        if i32::try_from(tag).ok() == Some(target_tag) {
            if wire != WireType::Varint {
                return Err(ProtoError::InvalidPayload(format!(
                    "option tag {target_tag} expected Varint wire type, got {wire:?}"
                )));
            }
            let val = decode_varint(&mut cursor)
                .map_err(|e| ProtoError::InvalidPayload(format!("options varint error: {e}")))?;
            result = Some(val);
        } else {
            skip_other_field(wire, tag, &mut cursor)?;
        }
    }
    Ok(result)
}

pub fn read_string_option(
    raw_options: &[u8],
    target_tag: i32,
) -> Result<Option<String>, ProtoError> {
    let mut cursor = raw_options;
    let mut result = None;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor)
            .map_err(|e| ProtoError::InvalidPayload(format!("options key error: {e}")))?;
        if i32::try_from(tag).ok() == Some(target_tag) {
            if wire != WireType::LengthDelimited {
                return Err(ProtoError::InvalidPayload(format!(
                    "option tag {target_tag} expected LengthDelimited wire type, got {wire:?}"
                )));
            }
            let bytes = read_len_delimited(&mut cursor)?;
            let text = std::str::from_utf8(bytes)
                .map_err(|e| ProtoError::InvalidPayload(format!("non-utf8 option string: {e}")))?;
            result = Some(text.to_owned());
        } else {
            skip_other_field(wire, tag, &mut cursor)?;
        }
    }
    Ok(result)
}

pub fn resolve_options_extensions(
    file: &FileDescriptor,
) -> Result<ResolvedOptionsExtension, ProtoError> {
    let mut field_tags: BTreeMap<String, i32> = BTreeMap::new();
    let mut enum_tags: BTreeMap<String, i32> = BTreeMap::new();
    let mut seen_numbers: std::collections::BTreeSet<(String, i32)> =
        std::collections::BTreeSet::new();
    for ext in &file.extensions {
        if ext.number <= 0 {
            return Err(ProtoError::ConstraintViolation(format!(
                "extension `{}` has non-positive tag {}",
                ext.name, ext.number
            )));
        }
        if !seen_numbers.insert((ext.extendee.clone(), ext.number)) {
            return Err(ProtoError::ConstraintViolation(format!(
                "duplicate extension tag {} on `{}`",
                ext.number, ext.extendee
            )));
        }
        if ext.extendee == ".google.protobuf.FieldOptions" {
            validate_canonical_option_ext(&file.package, ext)?;
            if field_tags.insert(ext.name.clone(), ext.number).is_some() {
                return Err(ProtoError::ConstraintViolation(format!(
                    "duplicate FieldOptions extension `{}`",
                    ext.name
                )));
            }
        } else if ext.extendee == ".google.protobuf.EnumValueOptions" {
            validate_canonical_option_ext(&file.package, ext)?;
            if enum_tags.insert(ext.name.clone(), ext.number).is_some() {
                return Err(ProtoError::ConstraintViolation(format!(
                    "duplicate EnumValueOptions extension `{}`",
                    ext.name
                )));
            }
        } else if ext.extendee == ".google.protobuf.MethodOptions" {
            validate_canonical_option_ext(&file.package, ext)?;
        }
    }
    let get_field = |name: &str| {
        field_tags
            .get(name)
            .copied()
            .ok_or_else(|| ProtoError::InvalidPayload(format!("missing FieldOptions.{name}")))
    };
    let get_enum = |name: &str| {
        enum_tags
            .get(name)
            .copied()
            .ok_or_else(|| ProtoError::InvalidPayload(format!("missing EnumValueOptions.{name}")))
    };
    Ok(ResolvedOptionsExtension {
        package: file.package.clone(),
        field_data_class_tag: get_field("data_class")?,
        field_content_kind_tag: get_field("content_kind")?,
        field_policy_readable_tag: get_field("policy_readable")?,
        field_sealable_tag: get_field("sealable")?,
        enum_wire_name_tag: get_enum("wire_name")?,
    })
}

fn validate_canonical_option_ext(pkg: &str, ext: &FieldDescriptor) -> Result<(), ProtoError> {
    let dc_ty = format!(".{pkg}.DataClass");
    let ck_ty = format!(".{pkg}.ContentKind");
    let audit_ty = format!(".{pkg}.AuditClass");
    let rate_ty = format!(".{pkg}.RateClass");
    let confirm_ty = format!(".{pkg}.ConfirmClass");
    let (exp_kind, exp_ty): (FieldType, &str) = match (ext.extendee.as_str(), ext.name.as_str()) {
        (".google.protobuf.FieldOptions", "data_class") => (FieldType::Enum, dc_ty.as_str()),
        (".google.protobuf.FieldOptions", "content_kind") => (FieldType::Enum, ck_ty.as_str()),
        (
            ".google.protobuf.FieldOptions",
            "policy_readable" | "sealable" | "filterable" | "sortable",
        ) => (FieldType::Bool, ""),
        (".google.protobuf.EnumValueOptions", "wire_name") => (FieldType::String, ""),
        (".google.protobuf.MethodOptions", "scope") => (FieldType::String, ""),
        (".google.protobuf.MethodOptions", "audit") => (FieldType::Enum, audit_ty.as_str()),
        (".google.protobuf.MethodOptions", "rate_class") => (FieldType::Enum, rate_ty.as_str()),
        (".google.protobuf.MethodOptions", "confirm") => (FieldType::Enum, confirm_ty.as_str()),
        (".google.protobuf.MethodOptions", "mcp_exposed") => (FieldType::Bool, ""),
        _ => {
            return Err(ProtoError::ConstraintViolation(format!(
                "unexpected option extension `{}` on `{}`",
                ext.name, ext.extendee
            )));
        }
    };
    if ext.label != FieldLabel::Optional || ext.kind != exp_kind || ext.type_name != exp_ty {
        return Err(ProtoError::ConstraintViolation(format!(
            "option extension `{}` must have label Optional, type {exp_kind:?}, type_name `{exp_ty}`",
            ext.name
        )));
    }
    Ok(())
}

pub(crate) fn map_field_label(raw: i32) -> FieldLabel {
    match raw {
        1 => FieldLabel::Optional,
        2 => FieldLabel::Required,
        3 => FieldLabel::Repeated,
        other => FieldLabel::Unknown(other),
    }
}

pub(crate) fn map_field_type(raw: i32) -> FieldType {
    match raw {
        1 => FieldType::Double,
        2 => FieldType::Float,
        3 => FieldType::Int64,
        4 => FieldType::Uint64,
        5 => FieldType::Int32,
        6 => FieldType::Fixed64,
        7 => FieldType::Fixed32,
        8 => FieldType::Bool,
        9 => FieldType::String,
        10 => FieldType::Group,
        11 => FieldType::Message,
        12 => FieldType::Bytes,
        13 => FieldType::Uint32,
        14 => FieldType::Enum,
        15 => FieldType::Sfixed32,
        16 => FieldType::Sfixed64,
        17 => FieldType::Sint32,
        18 => FieldType::Sint64,
        other => FieldType::Unknown(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor_wire::MAX_DESCRIPTOR_DEPTH;

    fn push_key(buf: &mut Vec<u8>, tag: u32, wire: u32) {
        let key = u64::from(tag) << 3 | u64::from(wire);
        prost::encoding::encode_varint(key, buf);
    }

    #[test]
    fn loads_embedded_descriptor_set_with_imports_offline() {
        let set = load_embedded_descriptor_set().expect("embedded proto.binpb loads offline");
        assert!(set.files.len() >= 30);
        let opts = set
            .files
            .iter()
            .find(|f| f.name.ends_with("options.proto"))
            .expect("options.proto present in descriptor set");
        let resolved = resolve_options_extensions(opts).expect("options extensions resolve");
        assert_eq!(resolved.package, "grdr.common.v1alpha1");
        assert_eq!(resolved.field_data_class_tag, 50001);
        assert_eq!(resolved.field_content_kind_tag, 50002);
        assert_eq!(resolved.field_policy_readable_tag, 50003);
        assert_eq!(resolved.field_sealable_tag, 50004);
        assert_eq!(resolved.enum_wire_name_tag, 50011);
        assert!(
            set.files
                .iter()
                .any(|f| f.name == "google/protobuf/descriptor.proto"),
            "imports must not be excluded from proto.binpb"
        );
    }

    #[test]
    fn rejects_truncated_varint_and_invalid_utf8_options() {
        assert!(read_varint_option(&[0x80], 1).is_err());
        let mut bad_utf8 = Vec::new();
        push_key(&mut bad_utf8, 50011, 2);
        prost::encoding::encode_varint(2, &mut bad_utf8);
        bad_utf8.extend_from_slice(&[0xff, 0xfe]);
        assert!(read_string_option(&bad_utf8, 50011).is_err());
    }

    #[test]
    fn options_use_last_value_wins_and_reject_wire_type_mismatch() {
        let mut dup = Vec::new();
        push_key(&mut dup, 50001, 0);
        prost::encoding::encode_varint(2, &mut dup);
        push_key(&mut dup, 50001, 0);
        prost::encoding::encode_varint(4, &mut dup);
        assert_eq!(read_varint_option(&dup, 50001).unwrap(), Some(4));

        let mut dup_str = Vec::new();
        push_key(&mut dup_str, 50011, 2);
        prost::encoding::encode_varint(1, &mut dup_str);
        dup_str.push(b'a');
        push_key(&mut dup_str, 50011, 2);
        prost::encoding::encode_varint(1, &mut dup_str);
        dup_str.push(b'b');
        assert_eq!(
            read_string_option(&dup_str, 50011).unwrap().as_deref(),
            Some("b")
        );

        let mut wrong_wire = Vec::new();
        push_key(&mut wrong_wire, 50001, 2);
        prost::encoding::encode_varint(0, &mut wrong_wire);
        assert!(read_varint_option(&wrong_wire, 50001).is_err());

        let mut start_group = Vec::new();
        push_key(&mut start_group, 1, 3);
        assert!(read_varint_option(&start_group, 50001).is_err());
    }

    #[test]
    fn rejects_deep_nesting_dos_and_int32_overflow() {
        let mut msg = Vec::new();
        for _ in 0..=MAX_DESCRIPTOR_DEPTH + 2 {
            let mut outer = Vec::new();
            push_key(&mut outer, 3, 2);
            prost::encoding::encode_varint(msg.len() as u64, &mut outer);
            outer.extend_from_slice(&msg);
            msg = outer;
        }
        let mut file = Vec::new();
        push_key(&mut file, 4, 2);
        prost::encoding::encode_varint(msg.len() as u64, &mut file);
        file.extend_from_slice(&msg);
        let mut set = Vec::new();
        push_key(&mut set, 1, 2);
        prost::encoding::encode_varint(file.len() as u64, &mut set);
        set.extend_from_slice(&file);
        assert!(decode_descriptor_set(&set).is_err());

        let mut field = Vec::new();
        push_key(&mut field, 3, 0);
        prost::encoding::encode_varint((1u64 << 32) + 900, &mut field);
        let mut bad_msg = Vec::new();
        push_key(&mut bad_msg, 2, 2);
        prost::encoding::encode_varint(field.len() as u64, &mut bad_msg);
        bad_msg.extend_from_slice(&field);
        let mut bad_file = Vec::new();
        push_key(&mut bad_file, 4, 2);
        prost::encoding::encode_varint(bad_msg.len() as u64, &mut bad_file);
        bad_file.extend_from_slice(&bad_msg);
        let mut bad_set = Vec::new();
        push_key(&mut bad_set, 1, 2);
        prost::encoding::encode_varint(bad_file.len() as u64, &mut bad_set);
        bad_set.extend_from_slice(&bad_file);
        assert!(decode_descriptor_set(&bad_set).is_err());
    }

    #[test]
    fn merges_repeated_options_and_rejects_duplicate_or_non_positive_extensions() {
        let mut opt1 = Vec::new();
        push_key(&mut opt1, 7, 0);
        prost::encoding::encode_varint(1, &mut opt1);
        let opt2: Vec<u8> = Vec::new();
        let mut msg = Vec::new();
        push_key(&mut msg, 7, 2);
        prost::encoding::encode_varint(opt1.len() as u64, &mut msg);
        msg.extend_from_slice(&opt1);
        push_key(&mut msg, 7, 2);
        prost::encoding::encode_varint(opt2.len() as u64, &mut msg);
        msg.extend_from_slice(&opt2);
        let mut file = Vec::new();
        push_key(&mut file, 4, 2);
        prost::encoding::encode_varint(msg.len() as u64, &mut file);
        file.extend_from_slice(&msg);
        let mut set = Vec::new();
        push_key(&mut set, 1, 2);
        prost::encoding::encode_varint(file.len() as u64, &mut set);
        set.extend_from_slice(&file);
        let decoded = decode_descriptor_set(&set).unwrap();
        assert!(decoded.files[0].messages[0].is_map_entry);

        let mut dup_file = decoded.files[0].clone();
        dup_file.extensions = vec![FieldDescriptor {
            name: "data_class".into(),
            number: 0,
            label: FieldLabel::Optional,
            kind: FieldType::Enum,
            type_name: String::new(),
            extendee: ".google.protobuf.FieldOptions".into(),
            oneof_index: None,
            proto3_optional: false,
            raw_options: Vec::new(),
        }];
        assert!(resolve_options_extensions(&dup_file).is_err());

        // Colliding tag numbers across distinct extension names on same extendee rejected.
        dup_file.extensions = vec![
            FieldDescriptor {
                name: "a".into(),
                number: 50001,
                label: FieldLabel::Optional,
                kind: FieldType::Bool,
                type_name: String::new(),
                extendee: ".google.protobuf.FieldOptions".into(),
                oneof_index: None,
                proto3_optional: false,
                raw_options: Vec::new(),
            },
            FieldDescriptor {
                name: "b".into(),
                number: 50001,
                label: FieldLabel::Optional,
                kind: FieldType::Bool,
                type_name: String::new(),
                extendee: ".google.protobuf.FieldOptions".into(),
                oneof_index: None,
                proto3_optional: false,
                raw_options: Vec::new(),
            },
        ];
        assert!(resolve_options_extensions(&dup_file).is_err());

        // Chunk-boundary spliced FieldOptions (truncated LengthDelimited tag inside chunk 1) rejected.
        let mut spliced_field = Vec::new();
        push_key(&mut spliced_field, 8, 2);
        prost::encoding::encode_varint(2, &mut spliced_field);
        spliced_field.push((1 << 3) | 2);
        spliced_field.push(10); // truncated LengthDelimited length=10
        push_key(&mut spliced_field, 8, 2);
        prost::encoding::encode_varint(2, &mut spliced_field);
        spliced_field.extend_from_slice(&[0x08, 0x01]);
        let mut msg_spliced = Vec::new();
        push_key(&mut msg_spliced, 2, 2);
        prost::encoding::encode_varint(spliced_field.len() as u64, &mut msg_spliced);
        msg_spliced.extend_from_slice(&spliced_field);
        let mut file_spliced = Vec::new();
        push_key(&mut file_spliced, 4, 2);
        prost::encoding::encode_varint(msg_spliced.len() as u64, &mut file_spliced);
        file_spliced.extend_from_slice(&msg_spliced);
        let mut set_spliced = Vec::new();
        push_key(&mut set_spliced, 1, 2);
        prost::encoding::encode_varint(file_spliced.len() as u64, &mut set_spliced);
        set_spliced.extend_from_slice(&file_spliced);
        assert!(decode_descriptor_set(&set_spliced).is_err());

        // FileDescriptorProto tag 14 (edition) accepts Varint and rejects LengthDelimited.
        let mut ed_ok = Vec::new();
        push_key(&mut ed_ok, 14, 0);
        prost::encoding::encode_varint(1000, &mut ed_ok);
        let mut set_ed_ok = Vec::new();
        push_key(&mut set_ed_ok, 1, 2);
        prost::encoding::encode_varint(ed_ok.len() as u64, &mut set_ed_ok);
        set_ed_ok.extend_from_slice(&ed_ok);
        assert!(decode_descriptor_set(&set_ed_ok).is_ok());

        let mut ed_bad = Vec::new();
        push_key(&mut ed_bad, 14, 2);
        prost::encoding::encode_varint(1, &mut ed_bad);
        ed_bad.push(b'x');
        let mut set_ed_bad = Vec::new();
        push_key(&mut set_ed_bad, 1, 2);
        prost::encoding::encode_varint(ed_bad.len() as u64, &mut set_ed_bad);
        set_ed_bad.extend_from_slice(&ed_bad);
        assert!(decode_descriptor_set(&set_ed_bad).is_err());

        // EnumValueOptions and MethodOptions chunk-splicing must also fail closed.
        let mut bad_evo = Vec::new();
        push_key(&mut bad_evo, 3, 2);
        prost::encoding::encode_varint(2, &mut bad_evo);
        bad_evo.extend_from_slice(&[(1 << 3) | 2, 10]);
        let mut bad_enum = Vec::new();
        push_key(&mut bad_enum, 2, 2);
        prost::encoding::encode_varint(bad_evo.len() as u64, &mut bad_enum);
        bad_enum.extend_from_slice(&bad_evo);
        let mut bad_ef = Vec::new();
        push_key(&mut bad_ef, 5, 2);
        prost::encoding::encode_varint(bad_enum.len() as u64, &mut bad_ef);
        bad_ef.extend_from_slice(&bad_enum);
        let mut set_ef = Vec::new();
        push_key(&mut set_ef, 1, 2);
        prost::encoding::encode_varint(bad_ef.len() as u64, &mut set_ef);
        set_ef.extend_from_slice(&bad_ef);
        assert!(decode_descriptor_set(&set_ef).is_err());

        let mut bad_m = Vec::new();
        push_key(&mut bad_m, 4, 2);
        prost::encoding::encode_varint(2, &mut bad_m);
        bad_m.extend_from_slice(&[(1 << 3) | 2, 10]);
        let mut bad_svc = Vec::new();
        push_key(&mut bad_svc, 2, 2);
        prost::encoding::encode_varint(bad_m.len() as u64, &mut bad_svc);
        bad_svc.extend_from_slice(&bad_m);
        let mut bad_sf = Vec::new();
        push_key(&mut bad_sf, 6, 2);
        prost::encoding::encode_varint(bad_svc.len() as u64, &mut bad_sf);
        bad_sf.extend_from_slice(&bad_svc);
        let mut set_sf = Vec::new();
        push_key(&mut set_sf, 1, 2);
        prost::encoding::encode_varint(bad_sf.len() as u64, &mut set_sf);
        set_sf.extend_from_slice(&bad_sf);
        assert!(decode_descriptor_set(&set_sf).is_err());

        // Canonical option extension wrong type/label rejected by resolve_options_extensions.
        let mut bad_ext_file = load_embedded_descriptor_set()
            .unwrap()
            .files
            .into_iter()
            .find(|f| f.name.ends_with("options.proto"))
            .unwrap();
        assert!(resolve_options_extensions(&bad_ext_file).is_ok());
        bad_ext_file.extensions[0].label = FieldLabel::Repeated;
        assert!(resolve_options_extensions(&bad_ext_file).is_err());
    }
}
