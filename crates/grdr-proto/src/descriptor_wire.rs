// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Low-level wire decoders for protobuf `FileDescriptorProto` records.

use prost::bytes::Buf;
use prost::encoding::{WireType, decode_key, decode_varint};

use crate::ProtoError;
use crate::descriptor::{
    EnumDescriptor, EnumValueDescriptor, FieldDescriptor, FieldLabel, FieldType, FileDescriptor,
    MessageDescriptor, MethodDescriptorProto, ReservedRange, ServiceDescriptor, map_field_label,
    map_field_type,
};

pub(crate) const MAX_DESCRIPTOR_DEPTH: usize = 64;
pub(crate) const MAX_DESCRIPTOR_ITEMS: usize = 65_536;
pub(crate) const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;

fn consume_budget(budget: &mut usize) -> Result<(), ProtoError> {
    let next = budget.checked_add(1).ok_or_else(|| {
        ProtoError::ConstraintViolation("descriptor item count overflowed usize".into())
    })?;
    if next > MAX_DESCRIPTOR_ITEMS {
        return Err(ProtoError::ConstraintViolation(format!(
            "descriptor item count exceeds MAX_DESCRIPTOR_ITEMS ({MAX_DESCRIPTOR_ITEMS})"
        )));
    }
    *budget = next;
    Ok(())
}

fn wire_err(ctx: &str, err: impl std::fmt::Display) -> ProtoError {
    ProtoError::InvalidPayload(format!("{ctx}: {err}"))
}

fn bad_wire(ctx: &str, tag: u32, wire: WireType) -> ProtoError {
    ProtoError::InvalidPayload(format!("unexpected wire type {wire:?} for {ctx} tag {tag}"))
}

pub(crate) fn decode_file_descriptor(
    bytes: &[u8],
    depth: usize,
    budget: &mut usize,
) -> Result<FileDescriptor, ProtoError> {
    consume_budget(budget)?;
    let mut out = FileDescriptor {
        name: String::new(),
        package: String::new(),
        dependencies: Vec::new(),
        public_dependencies: Vec::new(),
        weak_dependencies: Vec::new(),
        messages: Vec::new(),
        enums: Vec::new(),
        services: Vec::new(),
        extensions: Vec::new(),
        syntax: String::new(),
        raw_proto_bytes: Vec::new(),
    };
    let mut cursor = bytes;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("file key", e))?;
        match (tag, wire) {
            (1, WireType::LengthDelimited) => out.name = read_string(&mut cursor)?,
            (2, WireType::LengthDelimited) => out.package = read_string(&mut cursor)?,
            (3, WireType::LengthDelimited) => {
                consume_budget(budget)?;
                out.dependencies.push(read_string(&mut cursor)?);
            }
            (4, WireType::LengthDelimited) => {
                let d = depth.checked_add(1).ok_or_else(|| {
                    ProtoError::ConstraintViolation("descriptor depth overflow".into())
                })?;
                out.messages.push(decode_message_descriptor(
                    read_len_delimited(&mut cursor)?,
                    d,
                    budget,
                )?);
            }
            (5, WireType::LengthDelimited) => out.enums.push(decode_enum_descriptor(
                read_len_delimited(&mut cursor)?,
                budget,
            )?),
            (6, WireType::LengthDelimited) => out.services.push(decode_service_descriptor(
                read_len_delimited(&mut cursor)?,
                budget,
            )?),
            (7, WireType::LengthDelimited) => out.extensions.push(decode_field_descriptor(
                read_len_delimited(&mut cursor)?,
                budget,
            )?),
            (8 | 9, WireType::LengthDelimited) => skip_other_field(wire, tag, &mut cursor)?,
            (10, WireType::Varint) => {
                consume_budget(budget)?;
                out.public_dependencies.push(read_i32(&mut cursor)?);
            }
            (10, WireType::LengthDelimited) => {
                read_packed_i32(&mut cursor, &mut out.public_dependencies, budget)?
            }
            (11, WireType::Varint) => {
                consume_budget(budget)?;
                out.weak_dependencies.push(read_i32(&mut cursor)?);
            }
            (11, WireType::LengthDelimited) => {
                read_packed_i32(&mut cursor, &mut out.weak_dependencies, budget)?
            }
            (12, WireType::LengthDelimited) => out.syntax = read_string(&mut cursor)?,
            (14, WireType::Varint) => {
                let _ = decode_varint(&mut cursor).map_err(|e| wire_err("file edition", e))?;
            }
            (1..=12 | 14, _) => return Err(bad_wire("FileDescriptorProto", tag, wire)),
            _ => skip_other_field(wire, tag, &mut cursor)?,
        }
    }
    Ok(out)
}

fn decode_message_descriptor(
    bytes: &[u8],
    depth: usize,
    budget: &mut usize,
) -> Result<MessageDescriptor, ProtoError> {
    if depth > MAX_DESCRIPTOR_DEPTH {
        return Err(ProtoError::ConstraintViolation(format!(
            "descriptor nesting depth exceeds MAX_DESCRIPTOR_DEPTH ({MAX_DESCRIPTOR_DEPTH})"
        )));
    }
    consume_budget(budget)?;
    let mut out = MessageDescriptor {
        name: String::new(),
        fields: Vec::new(),
        nested_messages: Vec::new(),
        nested_enums: Vec::new(),
        nested_extensions: Vec::new(),
        reserved_ranges: Vec::new(),
        oneofs: Vec::new(),
        is_map_entry: false,
    };
    let mut map_entry_opt: Option<bool> = None;
    let mut cursor = bytes;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("message key", e))?;
        match (tag, wire) {
            (1, WireType::LengthDelimited) => out.name = read_string(&mut cursor)?,
            (2, WireType::LengthDelimited) => out.fields.push(decode_field_descriptor(
                read_len_delimited(&mut cursor)?,
                budget,
            )?),
            (3, WireType::LengthDelimited) => {
                let next_depth = depth.checked_add(1).ok_or_else(|| {
                    ProtoError::ConstraintViolation("descriptor depth overflow".into())
                })?;
                out.nested_messages.push(decode_message_descriptor(
                    read_len_delimited(&mut cursor)?,
                    next_depth,
                    budget,
                )?);
            }
            (4, WireType::LengthDelimited) => out.nested_enums.push(decode_enum_descriptor(
                read_len_delimited(&mut cursor)?,
                budget,
            )?),
            (5, WireType::LengthDelimited) => skip_other_field(wire, tag, &mut cursor)?,
            (6, WireType::LengthDelimited) => out.nested_extensions.push(decode_field_descriptor(
                read_len_delimited(&mut cursor)?,
                budget,
            )?),
            (7, WireType::LengthDelimited) => {
                if let Some(flag) = decode_map_entry_flag(read_len_delimited(&mut cursor)?)? {
                    map_entry_opt = Some(flag);
                }
            }
            (8, WireType::LengthDelimited) => out
                .oneofs
                .push(decode_oneof_name(read_len_delimited(&mut cursor)?, budget)?),
            (9, WireType::LengthDelimited) => out.reserved_ranges.push(decode_reserved_range(
                read_len_delimited(&mut cursor)?,
                budget,
            )?),
            (10, WireType::LengthDelimited) => {
                consume_budget(budget)?;
                skip_other_field(wire, tag, &mut cursor)?;
            }
            (1..=10, _) => return Err(bad_wire("DescriptorProto", tag, wire)),
            _ => skip_other_field(wire, tag, &mut cursor)?,
        }
    }
    out.is_map_entry = map_entry_opt.unwrap_or(false);
    Ok(out)
}

fn decode_map_entry_flag(bytes: &[u8]) -> Result<Option<bool>, ProtoError> {
    let mut cursor = bytes;
    let mut result = None;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("message options", e))?;
        if tag == 7 {
            if wire != WireType::Varint {
                return Err(bad_wire("MessageOptions.map_entry", tag, wire));
            }
            let v = decode_varint(&mut cursor).map_err(|e| wire_err("map_entry", e))?;
            result = Some(v != 0);
        } else {
            skip_other_field(wire, tag, &mut cursor)?;
        }
    }
    Ok(result)
}

fn decode_oneof_name(bytes: &[u8], budget: &mut usize) -> Result<String, ProtoError> {
    consume_budget(budget)?;
    let mut cursor = bytes;
    let mut name = String::new();
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("oneof key", e))?;
        match (tag, wire) {
            (1, WireType::LengthDelimited) => name = read_string(&mut cursor)?,
            (2, WireType::LengthDelimited) => skip_other_field(wire, tag, &mut cursor)?,
            (1..=2, _) => return Err(bad_wire("OneofDescriptorProto", tag, wire)),
            _ => skip_other_field(wire, tag, &mut cursor)?,
        }
    }
    Ok(name)
}

fn decode_reserved_range(bytes: &[u8], budget: &mut usize) -> Result<ReservedRange, ProtoError> {
    consume_budget(budget)?;
    let mut start = 0;
    let mut end_exclusive = 0;
    let mut cursor = bytes;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("reserved range", e))?;
        match (tag, wire) {
            (1, WireType::Varint) => start = read_i32(&mut cursor)?,
            (2, WireType::Varint) => end_exclusive = read_i32(&mut cursor)?,
            (1..=2, _) => return Err(bad_wire("ReservedRange", tag, wire)),
            _ => skip_other_field(wire, tag, &mut cursor)?,
        }
    }
    Ok(ReservedRange {
        start,
        end_exclusive,
    })
}

fn validate_raw_options_chunk(chunk: &[u8]) -> Result<(), ProtoError> {
    let mut cursor = chunk;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("options chunk key", e))?;
        if tag == 0 {
            return Err(ProtoError::InvalidPayload(
                "protobuf field tag 0 in options chunk is forbidden".into(),
            ));
        }
        skip_other_field(wire, tag, &mut cursor)?;
    }
    Ok(())
}

fn decode_field_descriptor(
    bytes: &[u8],
    budget: &mut usize,
) -> Result<FieldDescriptor, ProtoError> {
    consume_budget(budget)?;
    let mut out = FieldDescriptor {
        name: String::new(),
        number: 0,
        label: FieldLabel::Unknown(0),
        kind: FieldType::Unknown(0),
        type_name: String::new(),
        extendee: String::new(),
        oneof_index: None,
        proto3_optional: false,
        raw_options: Vec::new(),
    };
    let mut cursor = bytes;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("field key", e))?;
        match (tag, wire) {
            (1, WireType::LengthDelimited) => out.name = read_string(&mut cursor)?,
            (2, WireType::LengthDelimited) => out.extendee = read_string(&mut cursor)?,
            (3, WireType::Varint) => out.number = read_i32(&mut cursor)?,
            (4, WireType::Varint) => out.label = map_field_label(read_i32(&mut cursor)?),
            (5, WireType::Varint) => out.kind = map_field_type(read_i32(&mut cursor)?),
            (6, WireType::LengthDelimited) => out.type_name = read_string(&mut cursor)?,
            (7 | 10, WireType::LengthDelimited) => skip_other_field(wire, tag, &mut cursor)?,
            (8, WireType::LengthDelimited) => {
                let chunk = read_len_delimited(&mut cursor)?;
                validate_raw_options_chunk(chunk)?;
                out.raw_options.extend_from_slice(chunk);
            }
            (9, WireType::Varint) => out.oneof_index = Some(read_i32(&mut cursor)?),
            (17, WireType::Varint) => {
                let v = decode_varint(&mut cursor).map_err(|e| wire_err("proto3_optional", e))?;
                out.proto3_optional = v != 0;
            }
            (1..=10 | 17, _) => return Err(bad_wire("FieldDescriptorProto", tag, wire)),
            _ => skip_other_field(wire, tag, &mut cursor)?,
        }
    }
    Ok(out)
}

fn decode_enum_descriptor(bytes: &[u8], budget: &mut usize) -> Result<EnumDescriptor, ProtoError> {
    consume_budget(budget)?;
    let mut out = EnumDescriptor {
        name: String::new(),
        values: Vec::new(),
    };
    let mut cursor = bytes;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("enum key", e))?;
        match (tag, wire) {
            (1, WireType::LengthDelimited) => out.name = read_string(&mut cursor)?,
            (2, WireType::LengthDelimited) => out.values.push(decode_enum_value_descriptor(
                read_len_delimited(&mut cursor)?,
                budget,
            )?),
            (3..=5, WireType::LengthDelimited) => skip_other_field(wire, tag, &mut cursor)?,
            (1..=5, _) => return Err(bad_wire("EnumDescriptorProto", tag, wire)),
            _ => skip_other_field(wire, tag, &mut cursor)?,
        }
    }
    Ok(out)
}

fn decode_enum_value_descriptor(
    bytes: &[u8],
    budget: &mut usize,
) -> Result<EnumValueDescriptor, ProtoError> {
    consume_budget(budget)?;
    let mut out = EnumValueDescriptor {
        name: String::new(),
        number: 0,
        raw_options: Vec::new(),
    };
    let mut cursor = bytes;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("enum value key", e))?;
        match (tag, wire) {
            (1, WireType::LengthDelimited) => out.name = read_string(&mut cursor)?,
            (2, WireType::Varint) => out.number = read_i32(&mut cursor)?,
            (3, WireType::LengthDelimited) => {
                let chunk = read_len_delimited(&mut cursor)?;
                validate_raw_options_chunk(chunk)?;
                out.raw_options.extend_from_slice(chunk);
            }
            (1..=3, _) => return Err(bad_wire("EnumValueDescriptorProto", tag, wire)),
            _ => skip_other_field(wire, tag, &mut cursor)?,
        }
    }
    Ok(out)
}

fn decode_service_descriptor(
    bytes: &[u8],
    budget: &mut usize,
) -> Result<ServiceDescriptor, ProtoError> {
    consume_budget(budget)?;
    let mut out = ServiceDescriptor {
        name: String::new(),
        methods: Vec::new(),
    };
    let mut cursor = bytes;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("service key", e))?;
        match (tag, wire) {
            (1, WireType::LengthDelimited) => out.name = read_string(&mut cursor)?,
            (2, WireType::LengthDelimited) => out.methods.push(decode_method_descriptor(
                read_len_delimited(&mut cursor)?,
                budget,
            )?),
            (3, WireType::LengthDelimited) => skip_other_field(wire, tag, &mut cursor)?,
            (1..=3, _) => return Err(bad_wire("ServiceDescriptorProto", tag, wire)),
            _ => skip_other_field(wire, tag, &mut cursor)?,
        }
    }
    Ok(out)
}

fn decode_method_descriptor(
    bytes: &[u8],
    budget: &mut usize,
) -> Result<MethodDescriptorProto, ProtoError> {
    consume_budget(budget)?;
    let mut out = MethodDescriptorProto {
        name: String::new(),
        input_type: String::new(),
        output_type: String::new(),
        client_streaming: false,
        server_streaming: false,
        raw_options: Vec::new(),
    };
    let mut cursor = bytes;
    while cursor.has_remaining() {
        let (tag, wire) = decode_key(&mut cursor).map_err(|e| wire_err("method key", e))?;
        match (tag, wire) {
            (1, WireType::LengthDelimited) => out.name = read_string(&mut cursor)?,
            (2, WireType::LengthDelimited) => out.input_type = read_string(&mut cursor)?,
            (3, WireType::LengthDelimited) => out.output_type = read_string(&mut cursor)?,
            (4, WireType::LengthDelimited) => {
                let chunk = read_len_delimited(&mut cursor)?;
                validate_raw_options_chunk(chunk)?;
                out.raw_options.extend_from_slice(chunk);
            }
            (5, WireType::Varint) => {
                out.client_streaming =
                    decode_varint(&mut cursor).map_err(|e| wire_err("client_streaming", e))? != 0;
            }
            (6, WireType::Varint) => {
                out.server_streaming =
                    decode_varint(&mut cursor).map_err(|e| wire_err("server_streaming", e))? != 0;
            }
            (1..=6, _) => return Err(bad_wire("MethodDescriptorProto", tag, wire)),
            _ => skip_other_field(wire, tag, &mut cursor)?,
        }
    }
    Ok(out)
}

pub(crate) fn read_len_delimited<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], ProtoError> {
    let len_u64 = decode_varint(cursor).map_err(|e| wire_err("length prefix", e))?;
    let len = usize::try_from(len_u64)
        .map_err(|_| ProtoError::InvalidPayload("descriptor length overflows usize".into()))?;
    let slice = cursor.get(..len).ok_or_else(|| {
        ProtoError::InvalidPayload("truncated length-delimited descriptor".into())
    })?;
    *cursor = cursor
        .get(len..)
        .ok_or_else(|| ProtoError::InvalidPayload("truncated descriptor cursor".into()))?;
    Ok(slice)
}

fn read_string(cursor: &mut &[u8]) -> Result<String, ProtoError> {
    let bytes = read_len_delimited(cursor)?;
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|e| wire_err("descriptor string invalid utf-8", e))
}

fn read_i32(cursor: &mut &[u8]) -> Result<i32, ProtoError> {
    let v = decode_varint(cursor).map_err(|e| wire_err("descriptor varint", e))?;
    if v <= i32::MAX as u64 {
        return i32::try_from(v).map_err(|_| ProtoError::InvalidPayload("int32 range".into()));
    }
    let signed = i64::from_ne_bytes(v.to_ne_bytes());
    i32::try_from(signed).map_err(|_| {
        ProtoError::InvalidPayload(format!("descriptor varint {v} outside signed int32 range"))
    })
}

fn read_packed_i32(
    cursor: &mut &[u8],
    out: &mut Vec<i32>,
    budget: &mut usize,
) -> Result<(), ProtoError> {
    let mut packed = read_len_delimited(cursor)?;
    while packed.has_remaining() {
        consume_budget(budget)?;
        out.push(read_i32(&mut packed)?);
    }
    Ok(())
}

pub(crate) fn skip_other_field(
    wire: WireType,
    tag: u32,
    cursor: &mut &[u8],
) -> Result<(), ProtoError> {
    match wire {
        WireType::Varint => {
            let _ = decode_varint(cursor).map_err(|e| wire_err("skip varint", e))?;
            Ok(())
        }
        WireType::SixtyFourBit => advance_fixed(cursor, 8, tag),
        WireType::LengthDelimited => {
            let _ = read_len_delimited(cursor)?;
            Ok(())
        }
        WireType::ThirtyTwoBit => advance_fixed(cursor, 4, tag),
        WireType::StartGroup | WireType::EndGroup => Err(ProtoError::ConstraintViolation(format!(
            "deprecated protobuf group wire type is forbidden (tag {tag})"
        ))),
    }
}

fn advance_fixed(cursor: &mut &[u8], len: usize, tag: u32) -> Result<(), ProtoError> {
    *cursor = cursor.get(len..).ok_or_else(|| {
        ProtoError::InvalidPayload(format!("truncated fixed-width descriptor field {tag}"))
    })?;
    Ok(())
}
