// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Comprehensive unit/integration tests for `SL01`..`SL13`, `foreign_files.toml`, `SL12` compare, and codegen.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::path::PathBuf;

use grdr_proto::descriptor::{DescriptorSet, FieldLabel, FieldType, load_embedded_descriptor_set};
use grdr_schema::{DataClass, SchemaKind, parse_brand_identity_toml, schema_base_uri, schema_for};
use grdr_schema_lint::{
    CaptureConfig, CaptureLevelRow, EnumValueSnapshot, FieldSnapshot, LintError, ReclassKind,
    ReclassificationEntry, check_descriptor_set, compare_schemas_sl12, parse_capture_toml,
    parse_reclassifications_toml, sync_or_check_generated_artifacts, validate_capture_sl13,
};

type TestRes = Result<(), Box<dyn Error>>;
type LiveInputs = (
    DescriptorSet,
    Vec<String>,
    String,
    String,
    String,
    CaptureConfig,
);

fn check(cond: bool, msg: impl Into<String>) -> TestRes {
    if cond { Ok(()) } else { Err(msg.into().into()) }
}

fn check_eq<T: PartialEq + Debug>(actual: T, expected: T, label: &str) -> TestRes {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected:?}, got {actual:?}").into())
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn live_inputs() -> Result<LiveInputs, Box<dyn Error>> {
    let root = repo_root();
    let set = load_embedded_descriptor_set()?;
    let foreign_toml = fs::read_to_string(root.join("crates/grdr-schema-lint/foreign_files.toml"))?;
    let brand_toml = fs::read_to_string(root.join("contracts/interface/brand/brand.toml"))?;
    let surfaces_toml = fs::read_to_string(root.join("contracts/surfaces.toml"))?;
    let capture_toml = fs::read_to_string(root.join("crates/grdr-schema/capture.toml"))?;
    let capture_cfg = parse_capture_toml(&capture_toml)?;
    let disk_paths: Vec<String> = set
        .files
        .iter()
        .filter(|f| f.name.starts_with("grdr/"))
        .map(|f| f.name.clone())
        .collect();
    Ok((
        set,
        disk_paths,
        foreign_toml,
        brand_toml,
        surfaces_toml,
        capture_cfg,
    ))
}

#[test]
fn descriptor_checks_reject_foreign_sha256_tamper_and_sl08_to_sl11_violations() -> TestRes {
    let (set, disk_paths, foreign_toml, brand_toml, surfaces_toml, _) = live_inputs()?;

    let bad_foreign = foreign_toml.replace("7b591d4f", "00000000");
    let mut findings = Vec::new();
    check_descriptor_set(
        &set,
        &disk_paths,
        &bad_foreign,
        &brand_toml,
        &surfaces_toml,
        &mut findings,
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("SL10") && f.message.contains("SHA-256")),
        format!("expected SL10 SHA-256 mismatch finding: {findings:?}"),
    )?;

    let mut extra_paths = disk_paths.clone();
    extra_paths.push("grdr/undeclared/v1alpha1/orphan.proto".into());
    let mut bad_syntax_set = set.clone();
    let ev_file = bad_syntax_set
        .files
        .iter_mut()
        .find(|f| f.name == "grdr/event/v1alpha1/event.proto")
        .ok_or("event.proto missing")?;
    ev_file.syntax = "proto2".into();
    let mut findings_sl08_09 = Vec::new();
    check_descriptor_set(
        &bad_syntax_set,
        &extra_paths,
        &foreign_toml,
        &brand_toml,
        &surfaces_toml,
        &mut findings_sl08_09,
    )?;
    check(
        findings_sl08_09.iter().any(|f| f.message.contains("SL08")),
        "expected SL08 finding",
    )?;
    check(
        findings_sl08_09.iter().any(|f| f.message.contains("SL09")),
        "expected SL09 finding",
    )?;

    let stripped_surfaces = surfaces_toml.replace("event.v1alpha1", "missing.v1alpha1");
    let mut findings_sl11 = Vec::new();
    check_descriptor_set(
        &set,
        &disk_paths,
        &foreign_toml,
        &brand_toml,
        &stripped_surfaces,
        &mut findings_sl11,
    )?;
    check(
        findings_sl11.iter().any(|f| f.message.contains("SL11")),
        "expected SL11 finding",
    )
}

#[test]
fn descriptor_checks_enforce_sl01_sl04_sl05_sl06_and_sl07() -> TestRes {
    let (mut set, disk_paths, foreign_toml, brand_toml, surfaces_toml, _) = live_inputs()?;

    let event_file = set
        .files
        .iter_mut()
        .find(|f| f.name == "grdr/event/v1alpha1/event.proto")
        .ok_or("event.proto in descriptor set")?;
    let event_msg = event_file
        .messages
        .iter_mut()
        .find(|m| m.name == "Event")
        .ok_or("Event message")?;
    event_msg.reserved_ranges.clear();

    let mut bad_opts = Vec::new();
    let push_varint_opt = |buf: &mut Vec<u8>, tag: u64, val: u64| {
        for mut n in [tag << 3, val] {
            while n >= 0x80 {
                buf.push(((n as u8) & 0x7f) | 0x80);
                n >>= 7;
            }
            buf.push(n as u8);
        }
    };
    push_varint_opt(&mut bad_opts, 50001, 4);
    push_varint_opt(&mut bad_opts, 50003, 1);
    event_msg
        .fields
        .push(grdr_proto::descriptor::FieldDescriptor {
            name: "bad_float".into(),
            number: 80,
            label: FieldLabel::Optional,
            kind: FieldType::Double,
            type_name: String::new(),
            extendee: String::new(),
            oneof_index: None,
            proto3_optional: false,
            raw_options: bad_opts,
        });
    event_msg
        .fields
        .push(grdr_proto::descriptor::FieldDescriptor {
            name: "bad_any".into(),
            number: 81,
            label: FieldLabel::Optional,
            kind: FieldType::Message,
            type_name: ".google.protobuf.Any".into(),
            extendee: String::new(),
            oneof_index: None,
            proto3_optional: false,
            raw_options: Vec::new(),
        });

    let enums_file = set
        .files
        .iter_mut()
        .find(|f| f.name == "grdr/common/v1alpha1/enums.proto")
        .ok_or("enums.proto in descriptor set")?;
    if let Some(open_enum) = enums_file
        .enums
        .iter_mut()
        .find(|e| e.name == "FindingClass")
    {
        for v in &mut open_enum.values {
            if v.number == 1 {
                v.raw_options.clear();
            }
            if v.number == 99 {
                v.number = 98;
            }
        }
    }

    let mut findings = Vec::new();
    check_descriptor_set(
        &set,
        &disk_paths,
        &foreign_toml,
        &brand_toml,
        &surfaces_toml,
        &mut findings,
    )?;
    for tag in ["SL01", "SL02", "SL03", "SL04", "SL05", "SL06", "SL07"] {
        check(
            findings.iter().any(|f| f.message.contains(tag)),
            format!("expected {tag} finding in {findings:?}"),
        )?;
    }
    Ok(())
}

#[test]
fn dynamic_brand_namespace_resolves_custom_options_package_and_uris() -> TestRes {
    let (mut set, mut disk_paths, foreign_toml, _brand_toml, surfaces_toml, _) = live_inputs()?;
    let custom_brand = r#"
[identity]
namespace = "acme"
domain = "acme.example"
"#;
    let parsed_brand = parse_brand_identity_toml(custom_brand);
    check_eq(parsed_brand.namespace.as_str(), "acme", "namespace")?;
    check_eq(parsed_brand.domain.as_str(), "acme.example", "domain")?;
    check_eq(DataClass::Identifier.wire_name(), "identifier", "wire_name")?;
    check(schema_base_uri().starts_with("https://"), "schema base uri")?;
    check(
        schema_for(SchemaKind::PolicyPack)
            .id
            .contains("/schemas/v1/"),
        "schema pack id",
    )?;

    fn rewrite_type_ns(ty: &mut String) {
        if let Some(rest) = ty.strip_prefix(".grdr.") {
            *ty = format!(".acme.{rest}");
        }
    }
    fn rewrite_msg_ns(msg: &mut grdr_proto::descriptor::MessageDescriptor) {
        for f in &mut msg.fields {
            rewrite_type_ns(&mut f.type_name);
        }
        for ext in &mut msg.nested_extensions {
            rewrite_type_ns(&mut ext.type_name);
        }
        for nested in &mut msg.nested_messages {
            rewrite_msg_ns(nested);
        }
    }
    for f in &mut set.files {
        if f.name.starts_with("grdr/") {
            f.name = f.name.replacen("grdr/", "acme/", 1);
            f.package = f.package.replacen("grdr.", "acme.", 1);
            for dep in &mut f.dependencies {
                if dep.starts_with("grdr/") {
                    *dep = dep.replacen("grdr/", "acme/", 1);
                }
            }
            for ext in &mut f.extensions {
                rewrite_type_ns(&mut ext.type_name);
            }
            for msg in &mut f.messages {
                rewrite_msg_ns(msg);
            }
            for svc in &mut f.services {
                for m in &mut svc.methods {
                    rewrite_type_ns(&mut m.input_type);
                    rewrite_type_ns(&mut m.output_type);
                }
            }
        }
    }
    for p in &mut disk_paths {
        *p = p.replacen("grdr/", "acme/", 1);
    }
    let mut findings = Vec::new();
    let ctx = check_descriptor_set(
        &set,
        &disk_paths,
        &foreign_toml,
        custom_brand,
        &surfaces_toml,
        &mut findings,
    )?;
    check_eq(ctx.namespace.as_str(), "acme", "ctx.namespace")?;
    check_eq(
        ctx.options_package.as_str(),
        "acme.common.v1alpha1",
        "ctx.options_package",
    )?;
    check(
        findings.is_empty(),
        format!("unexpected findings: {findings:?}"),
    )
}

#[test]
fn sl12_compare_and_sl13_capture_enforce_rules_cleanly() -> TestRes {
    let (_, _, _, _, _, capture_cfg) = live_inputs()?;
    let base_fields = vec![FieldSnapshot {
        path: "grdr.event.v1alpha1.Envelope.event_id".into(),
        package: "grdr.event.v1alpha1".into(),
        message: "Envelope".into(),
        field: "event_id".into(),
        number: 1,
        data_class: "structural".into(),
        content_kind: None,
        commitment_class: "structural".into(),
        policy_readable: true,
        sealable: false,
        wire_type: 9,
        label: "optional".into(),
        type_name: String::new(),
        oneof_index: None,
    }];
    let base_enums = vec![EnumValueSnapshot {
        path: "grdr.common.v1alpha1.ActionClass.ACTION_CLASS_EXEC".into(),
        number: 1,
        wire_name: "exec".into(),
    }];

    let accepted: BTreeSet<String> = ["0006".into()].into_iter().collect();
    let rem_fail = compare_schemas_sl12(
        &base_fields,
        &[],
        &base_enums,
        &base_enums,
        &capture_cfg,
        &capture_cfg,
        &[],
        &[],
        &accepted,
    );
    check(
        rem_fail
            .findings
            .iter()
            .any(|f| f.message.contains("successor")),
        "expected successor requirement finding",
    )?;

    let head_fields = vec![FieldSnapshot {
        path: "grdr.event.v1alpha1.Envelope.record_id".into(),
        package: "grdr.event.v1alpha1".into(),
        message: "Envelope".into(),
        field: "record_id".into(),
        number: 2,
        data_class: "structural".into(),
        content_kind: None,
        commitment_class: "structural".into(),
        policy_readable: true,
        sealable: false,
        wire_type: 9,
        label: "optional".into(),
        type_name: String::new(),
        oneof_index: None,
    }];
    let valid_reclass = vec![ReclassificationEntry {
        kind: ReclassKind::Field,
        target: "grdr.event.v1alpha1.Envelope.event_id".into(),
        from: "structural".into(),
        to: "removed".into(),
        rfc: "0006".into(),
        seat: "persona-privacy-officer".into(),
        successor: Some("grdr.event.v1alpha1.Envelope.record_id".into()),
        from_sealable: None,
        to_sealable: None,
        from_policy_readable: None,
        to_policy_readable: None,
        justification: "replaced by record_id".into(),
    }];
    let rem_ok = compare_schemas_sl12(
        &base_fields,
        &head_fields,
        &base_enums,
        &base_enums,
        &capture_cfg,
        &capture_cfg,
        &[],
        &valid_reclass,
        &accepted,
    );
    check(
        rem_ok.findings.is_empty(),
        format!("unexpected compare findings: {:?}", rem_ok.findings),
    )?;

    let mut new_enums = base_enums.clone();
    if let Some(first) = new_enums.first_mut() {
        first.wire_name = "execute".into();
    }
    let bad_seat = vec![ReclassificationEntry {
        kind: ReclassKind::WireName,
        target: base_enums.first().ok_or("base_enums missing")?.path.clone(),
        from: "exec".into(),
        to: "execute".into(),
        rfc: "0006".into(),
        seat: "persona-privacy-officer".into(),
        successor: None,
        from_sealable: None,
        to_sealable: None,
        from_policy_readable: None,
        to_policy_readable: None,
        justification: "rename".into(),
    }];
    let wire_fail = compare_schemas_sl12(
        &base_fields,
        &base_fields,
        &base_enums,
        &new_enums,
        &capture_cfg,
        &capture_cfg,
        &[],
        &bad_seat,
        &accepted,
    );
    check(
        wire_fail
            .findings
            .iter()
            .any(|f| f.message.contains("persona-soc-analyst")),
        "expected persona-soc-analyst finding",
    )?;

    let append_fail = compare_schemas_sl12(
        &base_fields,
        &base_fields,
        &base_enums,
        &base_enums,
        &capture_cfg,
        &capture_cfg,
        &valid_reclass,
        &[],
        &accepted,
    );
    check(
        append_fail
            .findings
            .iter()
            .any(|f| f.message.contains("append-only")),
        "expected append-only finding",
    )?;

    let mut bad_capture = capture_cfg.clone();
    bad_capture.levels = vec![CaptureLevelRow {
        name: "broken".into(),
        rank: 1,
        dispositions: BTreeMap::from([
            ("structural".into(), "withheld".into()),
            ("derived".into(), "full".into()),
            ("identifier".into(), "withheld".into()),
            ("content.argument".into(), "withheld".into()),
            ("content.body".into(), "withheld".into()),
        ]),
    }];
    bad_capture.default_level = "broken".into();
    let opts: BTreeSet<String> = [
        "structural",
        "derived",
        "identifier",
        "content.argument",
        "content.body",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let mut sl13_findings = Vec::new();
    validate_capture_sl13(&bad_capture, &opts, &mut sl13_findings);
    check(
        sl13_findings.iter().any(|f| f.message.contains("SL13")),
        "expected SL13 finding",
    )?;
    check(
        parse_reclassifications_toml("schema = \"bad\"").is_err(),
        "expected reclassifications schema error",
    )
}

#[test]
fn codegen_check_detects_drift_in_temp_tree() -> TestRes {
    let (set, disk_paths, foreign_toml, brand_toml, surfaces_toml, capture_cfg) = live_inputs()?;
    let mut findings = Vec::new();
    let ctx = check_descriptor_set(
        &set,
        &disk_paths,
        &foreign_toml,
        &brand_toml,
        &surfaces_toml,
        &mut findings,
    )?;
    check(findings.is_empty(), "expected clean descriptor findings")?;

    let dir = std::env::temp_dir().join(format!("grdr-codegen-drift-{}", std::process::id()));
    let schema_dir = dir.join("crates/grdr-schema");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    sync_or_check_generated_artifacts(&dir, &ctx, &capture_cfg, &[], false)?;
    sync_or_check_generated_artifacts(&dir, &ctx, &capture_cfg, &[], true)?;

    fs::write(schema_dir.join("registry/fields.json"), "{}\n")?;
    let err = sync_or_check_generated_artifacts(&dir, &ctx, &capture_cfg, &[], true)
        .err()
        .ok_or("expected drift error")?;
    check(
        matches!(err, LintError::CaptureOrCodegenViolation { .. }),
        "expected CaptureOrCodegenViolation",
    )?;

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

fn push_varint_opt(buf: &mut Vec<u8>, tag: u64, val: u64) {
    for mut n in [tag << 3, val] {
        while n >= 0x80 {
            buf.push(((n as u8) & 0x7f) | 0x80);
            n >>= 7;
        }
        buf.push(n as u8);
    }
}

fn sample_field(path: &str, number: i32) -> FieldSnapshot {
    FieldSnapshot {
        path: path.into(),
        package: "grdr.event.v1alpha1".into(),
        message: "Envelope".into(),
        field: "field_a".into(),
        number,
        data_class: "structural".into(),
        content_kind: None,
        commitment_class: "structural".into(),
        policy_readable: true,
        sealable: false,
        wire_type: 9,
        label: "optional".into(),
        type_name: String::new(),
        oneof_index: None,
    }
}

#[test]
fn descriptor_adversarial_bypasses_are_rejected() -> TestRes {
    use grdr_proto::descriptor::{EnumValueDescriptor, MessageDescriptor, ReservedRange};

    let (base_set, base_paths, foreign_toml, brand_toml, surfaces_toml, _) = live_inputs()?;

    // 1. Dangling dependency (--exclude-imports simulation).
    let mut set = base_set.clone();
    set.files
        .retain(|f| f.name != "google/protobuf/timestamp.proto");
    let mut findings = Vec::new();
    check_descriptor_set(
        &set,
        &base_paths,
        &foreign_toml,
        &brand_toml,
        &surfaces_toml,
        &mut findings,
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("missing from descriptor set")),
        "expected dangling dependency finding",
    )?;

    // 2. Nested message extend + public import + extra options path segment + DataClass wire_name tamper.
    let mut set = base_set.clone();
    let ev = set
        .files
        .iter_mut()
        .find(|f| f.name == "grdr/event/v1alpha1/event.proto")
        .ok_or("event.proto")?;
    ev.public_dependencies.push(0);
    if let Some(m) = ev.messages.first_mut() {
        m.nested_extensions
            .push(grdr_proto::descriptor::FieldDescriptor {
                name: "sneaky_ext".into(),
                number: 50099,
                label: FieldLabel::Optional,
                kind: FieldType::Bool,
                type_name: String::new(),
                extendee: ".google.protobuf.FieldOptions".into(),
                oneof_index: None,
                proto3_optional: false,
                raw_options: Vec::new(),
            });
    }
    let opts = set
        .files
        .iter_mut()
        .find(|f| f.name == "grdr/common/v1alpha1/options.proto")
        .ok_or("options.proto")?;
    if let Some(dc) = opts.enums.iter_mut().find(|e| e.name == "DataClass")
        && let Some(v) = dc.values.iter_mut().find(|v| v.number == 1)
    {
        v.raw_options.clear();
    }
    findings.clear();
    check_descriptor_set(
        &set,
        &base_paths,
        &foreign_toml,
        &brand_toml,
        &surfaces_toml,
        &mut findings,
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("public and weak")),
        "expected public import finding",
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("nested message `extend`")),
        "expected nested extend finding",
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("missing (wire_name)")),
        "expected DataClass wire_name finding",
    )?;

    // Extra options path segment.
    let mut set = base_set.clone();
    let mut extra_paths = base_paths.clone();
    for p in &mut extra_paths {
        if p == "grdr/common/v1alpha1/options.proto" {
            *p = "grdr/common/v1alpha1/extra/options.proto".into();
        }
    }
    for f in &mut set.files {
        if f.name == "grdr/common/v1alpha1/options.proto" {
            f.name = "grdr/common/v1alpha1/extra/options.proto".into();
        }
        for dep in &mut f.dependencies {
            if dep == "grdr/common/v1alpha1/options.proto" {
                *dep = "grdr/common/v1alpha1/extra/options.proto".into();
            }
        }
    }
    findings.clear();
    check_descriptor_set(
        &set,
        &extra_paths,
        &foreign_toml,
        &brand_toml,
        &surfaces_toml,
        &mut findings,
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("extra segments")),
        "expected extra options segment finding",
    )?;

    // 3. Map entry Any/Struct/float policy_readable + non-CONTENT native + field tag 900..=999 + closed _OTHER=99 + missing _other sibling.
    let mut set = base_set;
    let finding_file = set
        .files
        .iter_mut()
        .find(|f| f.name == "grdr/finding/v1alpha1/finding.proto")
        .ok_or("finding.proto")?;
    let finding_msg = finding_file
        .messages
        .iter_mut()
        .find(|m| m.name == "Finding")
        .ok_or("Finding")?;
    let mut cls_content_opts = Vec::new();
    push_varint_opt(&mut cls_content_opts, 50001, 4);
    push_varint_opt(&mut cls_content_opts, 50002, 2);
    let mut cls_struct_opts = Vec::new();
    push_varint_opt(&mut cls_struct_opts, 50001, 2);
    let mut readable_struct = cls_struct_opts.clone();
    push_varint_opt(&mut readable_struct, 50003, 1);

    finding_msg.nested_messages.push(MessageDescriptor {
        name: "EvilAnyEntry".into(),
        is_map_entry: true,
        fields: vec![
            grdr_proto::descriptor::FieldDescriptor {
                name: "key".into(),
                number: 1,
                label: FieldLabel::Optional,
                kind: FieldType::String,
                type_name: String::new(),
                extendee: String::new(),
                oneof_index: None,
                proto3_optional: false,
                raw_options: Vec::new(),
            },
            grdr_proto::descriptor::FieldDescriptor {
                name: "value".into(),
                number: 2,
                label: FieldLabel::Optional,
                kind: FieldType::Message,
                type_name: ".google.protobuf.Value".into(),
                extendee: String::new(),
                oneof_index: None,
                proto3_optional: false,
                raw_options: Vec::new(),
            },
        ],
        nested_messages: Vec::new(),
        nested_enums: Vec::new(),
        nested_extensions: Vec::new(),
        reserved_ranges: Vec::new(),
        oneofs: Vec::new(),
    });
    finding_msg.nested_messages.push(MessageDescriptor {
        name: "EvilFloatEntry".into(),
        is_map_entry: true,
        fields: vec![
            grdr_proto::descriptor::FieldDescriptor {
                name: "key".into(),
                number: 1,
                label: FieldLabel::Optional,
                kind: FieldType::String,
                type_name: String::new(),
                extendee: String::new(),
                oneof_index: None,
                proto3_optional: false,
                raw_options: Vec::new(),
            },
            grdr_proto::descriptor::FieldDescriptor {
                name: "value".into(),
                number: 2,
                label: FieldLabel::Optional,
                kind: FieldType::Double,
                type_name: String::new(),
                extendee: String::new(),
                oneof_index: None,
                proto3_optional: false,
                raw_options: Vec::new(),
            },
        ],
        nested_messages: Vec::new(),
        nested_enums: Vec::new(),
        nested_extensions: Vec::new(),
        reserved_ranges: Vec::new(),
        oneofs: Vec::new(),
    });
    finding_msg
        .fields
        .retain(|f| f.name != "finding_class_other");
    finding_msg
        .fields
        .push(grdr_proto::descriptor::FieldDescriptor {
            name: "native".into(),
            number: 910,
            label: FieldLabel::Repeated,
            kind: FieldType::Message,
            type_name: ".grdr.finding.v1alpha1.Finding.EvilAnyEntry".into(),
            extendee: String::new(),
            oneof_index: None,
            proto3_optional: false,
            raw_options: cls_struct_opts.clone(),
        });
    finding_msg
        .fields
        .push(grdr_proto::descriptor::FieldDescriptor {
            name: "bad_weights".into(),
            number: 91,
            label: FieldLabel::Repeated,
            kind: FieldType::Message,
            type_name: ".grdr.finding.v1alpha1.Finding.EvilFloatEntry".into(),
            extendee: String::new(),
            oneof_index: None,
            proto3_optional: false,
            raw_options: readable_struct,
        });
    finding_msg.reserved_ranges.push(ReservedRange {
        start: 900,
        end_exclusive: 1000,
    });
    let enums_file = set
        .files
        .iter_mut()
        .find(|f| f.name == "grdr/common/v1alpha1/enums.proto")
        .ok_or("enums.proto")?;
    let closed = enums_file
        .enums
        .iter_mut()
        .find(|e| e.name == "ActionClass")
        .ok_or("ActionClass")?;
    let mut other_wire = vec![0xda, 0xb5, 0x18, 5];
    other_wire.extend_from_slice(b"other");
    closed.values.push(EnumValueDescriptor {
        name: "ACTION_CLASS_OTHER".into(),
        number: 99,
        raw_options: other_wire,
    });
    findings.clear();
    check_descriptor_set(
        &set,
        &base_paths,
        &foreign_toml,
        &brand_toml,
        &surfaces_toml,
        &mut findings,
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("SL05: map value cannot be")),
        "expected SL05 map Value finding",
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("SL03: map<K, float/double>")),
        "expected SL03 map float finding",
    )?;
    check(
        findings.iter().any(|f| f.message.contains("native")),
        "expected SL05 native DATA_CLASS_CONTENT finding",
    )?;
    check(
        findings.iter().any(|f| f.message.contains("900..=999")),
        "expected SL06 tag 910 finding",
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("finding_class_other")),
        "expected SL07 missing _other sibling finding",
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("closed enum cannot declare _OTHER = 99")),
        "expected SL07 closed enum _OTHER=99 finding",
    )?;
    Ok(())
}

#[test]
fn toml_compare_and_codegen_adversarial_inputs_fail_closed() -> TestRes {
    use grdr_schema_lint::{
        compare_schemas_sl12, generate_registry_rs, parse_foreign_files_toml,
        parse_surfaces_proto_packages, validate_reclassifications_entries,
    };

    check(parse_foreign_files_toml("schema = \"grdr.foreign_files.v1alpha1\"\n[[foreign_file]]\npath = \"../evil.proto\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n").is_err(), "reject traversal")?;
    check(parse_foreign_files_toml("schema = \"grdr.foreign_files.v1alpha1\"\n[[foreign_file]]\npath = \"a/b.proto\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n[[foreign_file]]\npath = \"a/b.proto\"\nsha256 = \"1111111111111111111111111111111111111111111111111111111111111111\"\n").is_err(), "reject duplicate pin")?;
    check(
        parse_surfaces_proto_packages("[[proto_package]]\npackage = \"a.v1\"\nclass = \"beta\"\n")
            .is_err(),
        "reject missing schema in surfaces",
    )?;

    check(parse_capture_toml("schema = \"grdr.capture.v1alpha1\"\ndefault = \"full_content\"\nclasses = [\"structural\"]\n[[levels]]\nname = \"full_content\"\nrank = 1\n[levels.dispositions]\nstructural = \"full\"\n").is_err(), "reject unexpected [levels.dispositions] header")?;
    let non_meta_cap = parse_capture_toml(
        "schema = \"grdr.capture.v1alpha1\"\ndefault = \"full_content\"\nclasses = [\"structural\", \"derived\", \"identifier\", \"content.argument\", \"content.body\"]\n[[levels]]\nname = \"full_content\"\nrank = 1\nstructural = \"full\"\nderived = \"full\"\nidentifier = \"full\"\n\"content.argument\" = \"full\"\n\"content.body\" = \"full\"\n",
    )?;
    let opts: BTreeSet<String> = [
        "structural",
        "derived",
        "identifier",
        "content.argument",
        "content.body",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let mut non_meta_findings = Vec::new();
    validate_capture_sl13(&non_meta_cap, &opts, &mut non_meta_findings);
    check(
        non_meta_findings
            .iter()
            .any(|f| f.message.contains("default level must be `metadata`")),
        "expected SL13 non-metadata default finding",
    )?;
    check(parse_capture_toml("schema = \"grdr.capture.v1alpha1\"\ndefault = \"metadata\"\nclasses = [\"structural\"\n").is_err(), "reject unclosed bracket")?;

    let (_, _, _, _, _, mut capture_cfg) = live_inputs()?;
    let dup_lvl = capture_cfg.levels.first().cloned().ok_or("level")?;
    capture_cfg.levels.push(dup_lvl);
    let mut sl13 = Vec::new();
    validate_capture_sl13(&capture_cfg, &opts, &mut sl13);
    check(
        sl13.iter()
            .any(|f| f.message.contains("duplicate capture level name")),
        "expected duplicate level finding",
    )?;

    let (_, _, _, _, _, clean_cap) = live_inputs()?;
    let empty_rfcs = BTreeSet::new();
    let f1 = vec![sample_field("grdr.event.v1alpha1.Envelope.a", 1)];
    let f2 = vec![FieldSnapshot {
        number: 9,
        policy_readable: false,
        ..sample_field("grdr.event.v1alpha1.Envelope.a", 9)
    }];
    let r = compare_schemas_sl12(
        &f1,
        &f2,
        &[],
        &[],
        &clean_cap,
        &clean_cap,
        &[],
        &[ReclassificationEntry {
            kind: ReclassKind::Field,
            target: "grdr.event.v1alpha1.Envelope.a".into(),
            from: "structural".into(),
            to: "derived".into(),
            rfc: "0006".into(),
            seat: "persona-privacy-officer".into(),
            successor: None,
            from_sealable: None,
            to_sealable: None,
            from_policy_readable: None,
            to_policy_readable: None,
            justification: "j".into(),
        }],
        &empty_rfcs,
    );
    check(
        r.findings
            .iter()
            .any(|f| f.message.contains("is not listed as Accepted")),
        "expected fail-closed accepted_rfcs finding",
    )?;
    check(
        r.findings
            .iter()
            .any(|f| f.message.contains("incompatible wire number")),
        "expected field renumber finding",
    )?;
    check(
        r.findings
            .iter()
            .any(|f| f.message.contains("policy_readable shift")),
        "expected policy_readable flip finding",
    )?;

    let mut cycle_findings = Vec::new();
    validate_reclassifications_entries(
        &[
            ReclassificationEntry {
                kind: ReclassKind::Field,
                target: "a.B.x".into(),
                from: "structural".into(),
                to: "removed".into(),
                rfc: "0006".into(),
                seat: "persona-privacy-officer".into(),
                successor: Some("a.B.y".into()),
                from_sealable: None,
                to_sealable: None,
                from_policy_readable: None,
                to_policy_readable: None,
                justification: "c1".into(),
            },
            ReclassificationEntry {
                kind: ReclassKind::Field,
                target: "a.B.y".into(),
                from: "structural".into(),
                to: "removed".into(),
                rfc: "0006".into(),
                seat: "persona-privacy-officer".into(),
                successor: Some("a.B.x".into()),
                from_sealable: None,
                to_sealable: None,
                from_policy_readable: None,
                to_policy_readable: None,
                justification: "c2".into(),
            },
        ],
        &mut cycle_findings,
    );
    check(
        cycle_findings.iter().any(|f| f.message.contains("cyclic")),
        "expected cyclic successor finding",
    )?;

    let (set, disk_paths, foreign_toml, brand_toml, surfaces_toml, _) = live_inputs()?;
    let mut f_clean = Vec::new();
    let mut ctx = check_descriptor_set(
        &set,
        &disk_paths,
        &foreign_toml,
        &brand_toml,
        &surfaces_toml,
        &mut f_clean,
    )?;
    check(f_clean.is_empty(), "live clean check")?;
    ctx.options_package = "bad\"; panic!(\"".into();
    check(
        generate_registry_rs(&ctx).is_err(),
        "codegen must reject unsafe identifier",
    )?;
    Ok(())
}
