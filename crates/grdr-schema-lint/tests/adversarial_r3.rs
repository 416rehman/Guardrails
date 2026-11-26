// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Adversarial Round 3 security and contract-integrity regression tests for `grdr-schema-lint`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use grdr_proto::descriptor::{DescriptorSet, FieldLabel, FieldType, load_embedded_descriptor_set};
use grdr_schema_lint::{
    CaptureConfig, CaptureLevelRow, EnumValueSnapshot, FieldSnapshot, ReclassKind,
    ReclassificationEntry, check_capture_only, check_descriptor_set, check_manifests,
    check_registry_only, compare_schemas_sl12, generate_capture_rs, generate_registry_rs,
    lint_repo_root, parse_capture_toml, parse_reclassifications_toml,
};

type TestRes = Result<(), Box<dyn Error>>;

fn push_varint(out: &mut Vec<u8>, mut val: u64) {
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn push_varint_opt(out: &mut Vec<u8>, tag: u32, val: u64) {
    let key = u64::from(tag) << 3;
    push_varint(out, key);
    push_varint(out, val);
}

fn check(cond: bool, msg: impl Into<String>) -> TestRes {
    if cond { Ok(()) } else { Err(msg.into().into()) }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

type LiveRaw = (
    DescriptorSet,
    Vec<String>,
    String,
    String,
    String,
    CaptureConfig,
);

fn live_raw() -> Result<LiveRaw, Box<dyn Error>> {
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

fn sample_field(path: &str, number: i32) -> FieldSnapshot {
    let mut parts = path.rsplit('.');
    let field = parts.next().unwrap_or("f").to_owned();
    let message = parts.next().unwrap_or("Msg").to_owned();
    let package = path
        .strip_suffix(&format!(".{message}.{field}"))
        .unwrap_or("grdr.event.v1alpha1")
        .to_owned();
    FieldSnapshot {
        path: path.into(),
        package,
        message,
        field,
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
fn rejects_swapped_dataclass_numbers_varint2_policy_readable_and_sl04_sl07_gaps() -> TestRes {
    let (base_set, disk_paths, foreign, brand, surfaces, _) = live_raw()?;

    // 1a) Swap DataClass enum numbers -> dynamic dc_n2w remaps 2 -> content, triggering SL02 across fields.
    let mut swapped_set = base_set.clone();
    let mut bad_wire_set = base_set.clone();
    for f in &mut swapped_set.files {
        if f.name.ends_with("options.proto") {
            for enm in &mut f.enums {
                if enm.name == "DataClass" {
                    for v in &mut enm.values {
                        if v.name == "DATA_CLASS_STRUCTURAL" {
                            v.number = 4;
                        } else if v.name == "DATA_CLASS_CONTENT" {
                            v.number = 2;
                        }
                    }
                }
            }
        }
    }
    let mut swap_findings = Vec::new();
    check_descriptor_set(
        &swapped_set,
        &disk_paths,
        &foreign,
        &brand,
        &surfaces,
        &mut swap_findings,
    )?;
    check(
        swap_findings.iter().any(|f| f.message.contains("SL02:")),
        format!("expected dynamic DataClass remapping SL02 finding, got {swap_findings:?}"),
    )?;

    // 1b) Mutate DataClass wire_name -> explicit R11 violation.
    for f in &mut bad_wire_set.files {
        if f.name.ends_with("options.proto") {
            for enm in &mut f.enums {
                if enm.name == "DataClass"
                    && let Some(v) = enm
                        .values
                        .iter_mut()
                        .find(|v| v.name == "DATA_CLASS_STRUCTURAL")
                {
                    v.raw_options.clear();
                }
            }
        }
    }
    let mut r11_findings = Vec::new();
    check_descriptor_set(
        &bad_wire_set,
        &disk_paths,
        &foreign,
        &brand,
        &surfaces,
        &mut r11_findings,
    )?;
    check(
        r11_findings.iter().any(|f| f.message.contains("R11:")),
        format!("expected R11 finding on stripped wire_name, got {r11_findings:?}"),
    )?;

    // SL03 varint = 2 on policy_readable content field + transitive content subtree + SL04/SL07/SL05 checks.
    let mut mutated = base_set;
    let mut opts_pr_tag = 0i32;
    for f in &mut mutated.files {
        if f.name.ends_with("options.proto") {
            for ext in &f.extensions {
                if ext.name == "policy_readable" {
                    opts_pr_tag = ext.number;
                }
            }
        }
    }
    for f in &mut mutated.files {
        if f.package == "grdr.event.v1alpha1" && f.name.ends_with("action.proto") {
            for m in &mut f.messages {
                if m.name == "ExecAction"
                    && let Some(cmd_line) =
                        m.fields.iter_mut().find(|fld| fld.name == "command_line")
                    && let Ok(tag) = u32::try_from(opts_pr_tag)
                {
                    push_varint_opt(&mut cmd_line.raw_options, tag, 2);
                }
            }
        }
        if f.package == "grdr.common.v1alpha1" && f.name.ends_with("enums.proto") {
            if let Some(enm) = f.enums.iter_mut().find(|e| e.name == "Mode")
                && let Some(zero) = enm.values.iter_mut().find(|v| v.number == 0)
            {
                zero.name = "MODE_BAD_ZERO".into();
            }
            if let Some(open_e) = f.enums.iter_mut().find(|e| e.name == "GapReason") {
                open_e.values.retain(|v| v.number != 99);
            }
        }
        if f.package == "grdr.entity.v1alpha1" {
            for m in &mut f.messages {
                if m.name == "Principal"
                    && let Some(fld) = m.fields.first_mut()
                {
                    fld.kind = FieldType::Message;
                    fld.label = FieldLabel::Optional;
                    fld.type_name = "MissingLeadingDot".into();
                }
            }
        }
        if f.package == "grdr.finding.v1alpha1" {
            for m in &mut f.messages {
                if m.name == "EvidenceSpan"
                    && let Some(other) = m.fields.iter_mut().find(|fld| fld.name == "kind_other")
                {
                    other.kind = FieldType::Int32;
                }
            }
        }
    }
    let mut findings = Vec::new();
    check_descriptor_set(
        &mutated,
        &disk_paths,
        &foreign,
        &brand,
        &surfaces,
        &mut findings,
    )?;
    check(
        findings.iter().any(|f| f.message.contains("SL03:")),
        "expected SL03 varint=2 finding",
    )?;
    check(
        findings.iter().any(|f| f.message.contains("_UNSPECIFIED")),
        "expected SL04 _UNSPECIFIED finding",
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("open enum must declare *_OTHER = 99")),
        "expected SL07 missing _OTHER=99",
    )?;
    check(
        findings.iter().any(|f| f.message.contains("leading `.`")),
        "expected leading dot type_name finding",
    )?;
    check(
        findings
            .iter()
            .any(|f| f.message.contains("requires string sibling")),
        "expected non-string _other sibling finding",
    )?;
    Ok(())
}

#[test]
fn rejects_sl11_loose_stable_versions_sl12_tag_reuse_and_live_removed_targets() -> TestRes {
    let (set, disk_paths, foreign, brand, surfaces, capture) = live_raw()?;

    for bad_ver in ["v0", "v1rc1", "v1Alpha1"] {
        let mut s = surfaces.clone();
        s.push_str(&format!(
            "\n[[proto_package]]\npackage = \"common.{bad_ver}\"\nclass = \"stable\"\n"
        ));
        let mut f = Vec::new();
        check_descriptor_set(&set, &disk_paths, &foreign, &brand, &s, &mut f)?;
        check(
            f.iter().any(|x| x.message.contains("^v[1-9][0-9]*$")),
            format!("expected strict stable rejection for `{bad_ver}`: {f:?}"),
        )?;
    }

    let accepted: BTreeSet<String> = ["0006".into()].into_iter().collect();
    let f1 = vec![sample_field("grdr.event.v1alpha1.Envelope.old_tag", 5)];
    let f2 = vec![sample_field("grdr.event.v1alpha1.Envelope.new_tag", 5)];
    let reuse_rec = vec![ReclassificationEntry {
        kind: ReclassKind::Field,
        target: "grdr.event.v1alpha1.Envelope.old_tag".into(),
        from: "structural".into(),
        to: "removed".into(),
        rfc: "0006".into(),
        seat: "persona-privacy-officer".into(),
        successor: Some("grdr.event.v1alpha1.Envelope.new_tag".into()),
        from_sealable: None,
        to_sealable: None,
        from_policy_readable: None,
        to_policy_readable: None,
        justification: "reuse attempt".into(),
    }];
    let reuse_rep = compare_schemas_sl12(
        &f1,
        &f2,
        &[],
        &[],
        &capture,
        &capture,
        &[],
        &reuse_rec,
        &accepted,
    );
    check(
        reuse_rep
            .findings
            .iter()
            .any(|x| x.message.contains("cannot be reused")),
        "expected SL12 tag reuse rejection",
    )?;

    // Live target listed with `to = "removed"` must fail SL12.
    let live_removed = compare_schemas_sl12(
        &f1,
        &f1,
        &[],
        &[],
        &capture,
        &capture,
        &[],
        &reuse_rec,
        &accepted,
    );
    check(
        live_removed
            .findings
            .iter()
            .any(|x| x.message.contains("still exists in head schema")),
        "expected SL12 live target removed rejection",
    )?;

    // sealable flip with from == to rejected unless explicit from_sealable/to_sealable present.
    let f1_unsealed = vec![FieldSnapshot {
        sealable: false,
        ..sample_field("grdr.event.v1alpha1.Envelope.a", 1)
    }];
    let f2_sealed = vec![FieldSnapshot {
        sealable: true,
        ..sample_field("grdr.event.v1alpha1.Envelope.a", 1)
    }];
    let seal_rep = compare_schemas_sl12(
        &f1_unsealed,
        &f2_sealed,
        &[],
        &[],
        &capture,
        &capture,
        &[],
        &[],
        &accepted,
    );
    check(
        seal_rep
            .findings
            .iter()
            .any(|x| x.message.contains("sealable/policy_readable shift")),
        "expected SL12 sealable flip rejection",
    )?;

    // Newly added capture level requires `from = "absent"`.
    let mut expanded_cap = capture.clone();
    expanded_cap.levels.push(CaptureLevelRow {
        name: "extra_tier".into(),
        rank: 5,
        dispositions: expanded_cap
            .levels
            .last()
            .map(|l| l.dispositions.clone())
            .unwrap_or_default(),
    });
    let lvl_rep = compare_schemas_sl12(
        &f1,
        &f1,
        &[],
        &[],
        &capture,
        &expanded_cap,
        &[],
        &[],
        &accepted,
    );
    check(
        lvl_rep
            .findings
            .iter()
            .any(|x| x.message.contains("from = \"absent\"")),
        "expected SL12 new capture level absent check",
    )?;

    // Enum zero rename and tag alias reuse rejected.
    let e_base = vec![EnumValueSnapshot {
        path: "grdr.common.v1alpha1.Mode.MODE_UNSPECIFIED".into(),
        number: 0,
        wire_name: String::new(),
    }];
    let e_head = vec![EnumValueSnapshot {
        path: "grdr.common.v1alpha1.Mode.MODE_OTHER".into(),
        number: 0,
        wire_name: String::new(),
    }];
    let enum_rep = compare_schemas_sl12(
        &f1,
        &f1,
        &e_base,
        &e_head,
        &capture,
        &capture,
        &[],
        &[],
        &accepted,
    );
    check(
        enum_rep
            .findings
            .iter()
            .any(|x| x.message.contains("zero enum value")),
        "expected SL12 zero enum rejection",
    )?;
    Ok(())
}

#[test]
fn rejects_codegen_fallbacks_emits_r17b_holds_and_rejects_bad_manifests_or_paths() -> TestRes {
    let (set, disk_paths, foreign, brand, surfaces, mut capture) = live_raw()?;
    let mut ctx = check_descriptor_set(
        &set,
        &disk_paths,
        &foreign,
        &brand,
        &surfaces,
        &mut Vec::new(),
    )?;

    // Codegen rejects empty levels & missing default level & duplicate field path & unknown class.
    let mut empty_cap = capture.clone();
    empty_cap.levels.clear();
    check(
        generate_capture_rs(&empty_cap, &[]).is_err(),
        "reject empty capture levels",
    )?;

    capture.default_level = "nonexistent".into();
    check(
        generate_capture_rs(&capture, &[]).is_err(),
        "reject missing default_level",
    )?;

    let dup_f = ctx.fields.first().cloned().ok_or("missing field")?;
    ctx.fields.push(dup_f);
    check(
        generate_registry_rs(&ctx).is_err(),
        "reject duplicate field.path",
    )?;

    let mut bad_class_ctx = check_descriptor_set(
        &set,
        &disk_paths,
        &foreign,
        &brand,
        &surfaces,
        &mut Vec::new(),
    )?;
    if let Some(first) = bad_class_ctx.fields.first_mut() {
        first.data_class = "bogus".into();
    }
    check(
        generate_registry_rs(&bad_class_ctx).is_err(),
        "reject unknown data_class",
    )?;

    // R17b codegen emits successor, from_sealable, to_disposition and matches successor in has_reclassification_hold.
    let r17_entries = parse_reclassifications_toml(
        "schema = \"grdr.reclassifications.v1alpha1\"\n[[field]]\ntarget = \"grdr.a.v1alpha1.M.old\"\nfrom = \"structural\"\nto = \"removed\"\nsuccessor = \"grdr.a.v1alpha1.M.new\"\nfrom_sealable = false\nto_sealable = true\nrfc = \"0099\"\nseat = \"persona-privacy-officer\"\njustification = \"migrate\"\n",
    )?;
    let (_, _, _, _, _, clean_cap) = live_raw()?;
    let rendered = generate_capture_rs(&clean_cap, &r17_entries)?;
    check(
        rendered.contains("successor: Some(\"grdr.a.v1alpha1.M.new\")"),
        "missing successor",
    )?;
    check(
        rendered.contains("from_sealable: Some(false)"),
        "missing from_sealable",
    )?;
    check(
        rendered.contains("to_disposition: \"removed\""),
        "missing to_disposition",
    )?;
    check(
        rendered.contains("hold.successor == Some(target)"),
        "missing successor check in has_reclassification_hold",
    )?;

    // Check temp copy rejecting missing/invalid brand.toml, invalid manifest, and off-prefix proto.
    let tmp = std::env::temp_dir().join(format!("grdr_lint_adv_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("contracts/interface/brand"))?;
    fs::create_dir_all(tmp.join("crates/grdr-schema-lint"))?;
    fs::create_dir_all(tmp.join("crates/grdr-schema"))?;
    fs::create_dir_all(tmp.join("contracts/proto/grdr"))?;
    fs::write(
        tmp.join("contracts/interface/brand/brand.toml"),
        "[identity]\nnamespace = \"\"\ndomain = \"bad\"\n",
    )?;
    fs::write(
        tmp.join("crates/grdr-schema-lint/foreign_files.toml"),
        "schema = \"grdr.foreign_files.v1alpha1\"\n",
    )?;
    fs::write(
        tmp.join("contracts/surfaces.toml"),
        "schema = \"grdr.surfaces.v1alpha1\"\n",
    )?;
    fs::write(
        tmp.join("crates/grdr-schema/capture.toml"),
        fs::read_to_string(repo_root().join("crates/grdr-schema/capture.toml"))?,
    )?;
    fs::write(
        tmp.join("crates/grdr-schema/reclassifications.toml"),
        "schema = \"grdr.reclassifications.v1alpha1\"\n",
    )?;

    check(
        lint_repo_root(&tmp).is_err(),
        "empty brand namespace must fail closed",
    )?;
    check(
        check_manifests(&tmp).is_err(),
        "empty brand namespace in manifests must fail closed",
    )?;
    check(
        check_capture_only(&tmp).is_err(),
        "empty brand namespace in capture --check must fail closed",
    )?;
    check(
        check_registry_only(&tmp).is_err(),
        "empty brand namespace in registry --check must fail closed",
    )?;

    fs::write(
        tmp.join("contracts/interface/brand/brand.toml"),
        "[identity]\nnamespace = \"grdr\"\ndomain = \"guardrails.dev\"\n",
    )?;
    fs::write(
        tmp.join("crates/grdr-schema/capture.toml"),
        "schema = \"grdr.capture.v1alpha1\"\ndefault = \"full_content\"\nclasses = [\"structural\"]\n[[levels]]\nname = \"full_content\"\nrank = 1\nstructural = \"full\"\n",
    )?;
    check(
        check_manifests(&tmp).is_err(),
        "check_manifests must run SL13 and fail closed",
    )?;

    let _ = fs::remove_dir_all(&tmp);
    let _ = BTreeMap::<String, String>::new();
    Ok(())
}

fn copy_dir_tree(src: &std::path::Path, dst: &std::path::Path) -> TestRes {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_tree(&entry.path(), &dst_path)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}

#[test]
fn rejects_dot_dir_mapentry_transitive_content_off_prefix_and_source_drift() -> TestRes {
    let (base_set, mut disk_paths, foreign, brand, surfaces, _) = live_raw()?;

    // Directory segment containing `.` fails SL08/path rules inside descriptor set.
    let mut dot_set = base_set.clone();
    if let Some(mut cloned) = dot_set
        .files
        .iter()
        .find(|f| f.name.ends_with("ids.proto"))
        .cloned()
    {
        cloned.name = "grdr/bad.dir/v1alpha1/x.proto".into();
        cloned.package = "grdr.bad.dir.v1alpha1".into();
        cloned.messages.clear();
        dot_set.files.push(cloned);
    }
    disk_paths.push("grdr/bad.dir/v1alpha1/x.proto".into());
    let mut dot_findings = Vec::new();
    check_descriptor_set(
        &dot_set,
        &disk_paths,
        &foreign,
        &brand,
        &surfaces,
        &mut dot_findings,
    )?;
    check(
        dot_findings.iter().any(|f| {
            f.message
                .contains("directory segments inside namespace cannot contain `.`")
        }),
        format!("expected dot-segment path rejection, got {dot_findings:?}"),
    )?;
    disk_paths.pop();

    // Non-repeated MapEntry reference + transitive content field inside policy_readable message.
    let mut mutated = base_set;
    let mut opts_pr_tag = 0i32;
    let mut opts_dc_tag = 0i32;
    for f in &mut mutated.files {
        if f.name.ends_with("options.proto") {
            for ext in &f.extensions {
                if ext.name == "policy_readable" {
                    opts_pr_tag = ext.number;
                } else if ext.name == "data_class" {
                    opts_dc_tag = ext.number;
                }
            }
        }
    }
    for f in &mut mutated.files {
        if f.package == "grdr.common.v1alpha1"
            && f.name.ends_with("types.proto")
            && let Some(err_info) = f.messages.iter_mut().find(|m| m.name == "ErrorInfo")
            && let Some(meta_fld) = err_info
                .fields
                .iter_mut()
                .find(|fld| fld.name == "metadata")
        {
            meta_fld.label = FieldLabel::Optional;
        }
        if f.package == "grdr.event.v1alpha1"
            && f.name.ends_with("event.proto")
            && let Some(ev) = f.messages.iter_mut().find(|m| m.name == "Event")
            && let Some(act_fld) = ev.fields.iter_mut().find(|fld| fld.name == "action")
            && let Ok(tag_pr) = u32::try_from(opts_pr_tag)
            && let Ok(tag_dc) = u32::try_from(opts_dc_tag)
        {
            act_fld.raw_options.clear();
            push_varint_opt(&mut act_fld.raw_options, tag_dc, 2);
            push_varint_opt(&mut act_fld.raw_options, tag_pr, 1);
        }
    }
    let mut struct_findings = Vec::new();
    check_descriptor_set(
        &mutated,
        &disk_paths,
        &foreign,
        &brand,
        &surfaces,
        &mut struct_findings,
    )?;
    check(
        struct_findings
            .iter()
            .any(|f| f.message.contains("non-repeated reference to map entry")),
        format!("expected non-repeated MapEntry rejection, got {struct_findings:?}"),
    )?;
    check(
        struct_findings
            .iter()
            .any(|f| f.message.contains("nested subtrees")),
        format!(
            "expected transitive nested content policy_readable rejection, got {struct_findings:?}"
        ),
    )?;

    // Copy real repo files into temp dir and test (a) off-prefix .proto and (b) source vs proto.binpb option drift.
    let root = repo_root();
    let tmp = std::env::temp_dir().join(format!("grdr_lint_parity_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    copy_dir_tree(&root.join("contracts"), &tmp.join("contracts"))?;
    copy_dir_tree(
        &root.join("crates/grdr-schema"),
        &tmp.join("crates/grdr-schema"),
    )?;
    fs::create_dir_all(tmp.join("crates/grdr-proto/descriptors"))?;
    fs::copy(
        root.join("crates/grdr-proto/descriptors/proto.binpb"),
        tmp.join("crates/grdr-proto/descriptors/proto.binpb"),
    )?;
    fs::create_dir_all(tmp.join("crates/grdr-schema-lint"))?;
    fs::copy(
        root.join("crates/grdr-schema-lint/foreign_files.toml"),
        tmp.join("crates/grdr-schema-lint/foreign_files.toml"),
    )?;

    // (a) Off-prefix .proto under contracts/proto/rogue/ must produce GRDR-LINT-0002 / SL09 finding.
    let rogue_dir = tmp.join("contracts/proto/rogue/evil/v1");
    fs::create_dir_all(&rogue_dir)?;
    fs::write(
        rogue_dir.join("evil.proto"),
        "syntax = \"proto3\";\npackage rogue.evil.v1;\nmessage X { string id = 1; }\n",
    )?;
    let rep_off_prefix = lint_repo_root(&tmp)?;
    check(
        !rep_off_prefix.is_clean(),
        "off-prefix proto must fail lint_repo_root",
    )?;
    check(
        rep_off_prefix
            .findings
            .iter()
            .any(|f| f.message.contains("SL09:")),
        format!(
            "expected SL09 finding on off-prefix proto, got {:?}",
            rep_off_prefix.findings
        ),
    )?;
    let _ = fs::remove_dir_all(tmp.join("contracts/proto/rogue"));

    // (b) Source vs proto.binpb drift: change a field number in source .proto without updating proto.binpb.
    let target_proto = tmp.join("contracts/proto/grdr/common/v1alpha1/ids.proto");
    let orig = fs::read_to_string(&target_proto)?;
    let mutated_src = orig
        .replacen("= 1 ", "= 91 ", 1)
        .replacen("= 1;", "= 91;", 1);
    check(mutated_src != orig, "expected mutation in ids.proto")?;
    fs::write(&target_proto, mutated_src)?;
    let rep_drift = lint_repo_root(&tmp)?;
    check(
        !rep_drift.is_clean(),
        "source vs proto.binpb drift must fail lint_repo_root",
    )?;

    let _ = fs::remove_dir_all(&tmp);
    Ok(())
}

#[test]
fn round4_sl12_level_delimiter_sealable_removal_and_reclass_validation() -> TestRes {
    let (_, _, _, _, _, capture) = live_raw()?;
    let accepted = BTreeSet::from(["0099".to_owned()]);
    let f_base = vec![FieldSnapshot {
        sealable: true,
        policy_readable: false,
        ..sample_field("grdr.event.v1alpha1.Envelope.secret", 1)
    }];
    let f_succ = vec![FieldSnapshot {
        sealable: false,
        policy_readable: false,
        ..sample_field("grdr.event.v1alpha1.Envelope.next_secret", 2)
    }];

    // Missing `successor` on [[field]] with `to = "removed"` must fail validate_reclassifications_entries.
    let no_succ = parse_reclassifications_toml(
        "schema = \"grdr.reclassifications.v1alpha1\"\n[[field]]\ntarget = \"grdr.event.v1alpha1.Envelope.secret\"\nfrom = \"structural\"\nto = \"removed\"\nrfc = \"0099\"\nseat = \"persona-privacy-officer\"\njustification = \"drop\"\n",
    )?;
    let mut r_findings = Vec::new();
    grdr_schema_lint::validate_reclassifications_entries(&no_succ, &mut r_findings);
    check(
        r_findings
            .iter()
            .any(|f| f.message.contains("requires non-empty `successor`")),
        format!("expected missing successor rejection, got {r_findings:?}"),
    )?;

    // Field-only attributes on [[level]] must be rejected.
    let bad_lvl_attr = parse_reclassifications_toml(
        "schema = \"grdr.reclassifications.v1alpha1\"\n[[level]]\ntarget = \"standard:content.body\"\nfrom = \"withheld\"\nto = \"redacted\"\nsuccessor = \"grdr.event.v1alpha1.Envelope.x\"\nrfc = \"0099\"\nseat = \"persona-privacy-officer\"\njustification = \"bad\"\n",
    )?;
    let mut lvl_attr_findings = Vec::new();
    grdr_schema_lint::validate_reclassifications_entries(&bad_lvl_attr, &mut lvl_attr_findings);
    check(
        lvl_attr_findings
            .iter()
            .any(|f| f.message.contains("field-only")),
        format!("expected field-only attribute rejection on [[level]], got {lvl_attr_findings:?}"),
    )?;

    // Removing a sealable=true field without `from_sealable = true` must be rejected; with it passes.
    let rem_no_seal = parse_reclassifications_toml(
        "schema = \"grdr.reclassifications.v1alpha1\"\n[[field]]\ntarget = \"grdr.event.v1alpha1.Envelope.secret\"\nfrom = \"structural\"\nto = \"removed\"\nsuccessor = \"grdr.event.v1alpha1.Envelope.next_secret\"\nrfc = \"0099\"\nseat = \"persona-privacy-officer\"\njustification = \"retire\"\n",
    )?;
    let rem_bad_rep = compare_schemas_sl12(
        &f_base,
        &f_succ,
        &[],
        &[],
        &capture,
        &capture,
        &[],
        &rem_no_seal,
        &accepted,
    );
    check(
        !rem_bad_rep.findings.is_empty(),
        "removing sealable=true field without from_sealable=true must fail",
    )?;

    let rem_with_seal = parse_reclassifications_toml(
        "schema = \"grdr.reclassifications.v1alpha1\"\n[[field]]\ntarget = \"grdr.event.v1alpha1.Envelope.secret\"\nfrom = \"structural\"\nto = \"removed\"\nsuccessor = \"grdr.event.v1alpha1.Envelope.next_secret\"\nfrom_sealable = true\nto_sealable = false\nrfc = \"0099\"\nseat = \"persona-privacy-officer\"\njustification = \"retire\"\n",
    )?;
    let rem_ok_rep = compare_schemas_sl12(
        &f_base,
        &f_succ,
        &[],
        &[],
        &capture,
        &capture,
        &[],
        &rem_with_seal,
        &accepted,
    );
    check(
        rem_ok_rep.findings.is_empty(),
        format!(
            "expected clean removal with from_sealable=true, got {:?}",
            rem_ok_rep.findings
        ),
    )?;

    // Falsified from_sealable=true on unchanged sealable=false field during class shift must fail.
    let f_unchanged_base = vec![FieldSnapshot {
        sealable: false,
        ..sample_field("grdr.event.v1alpha1.Envelope.a", 1)
    }];
    let f_unchanged_head = vec![FieldSnapshot {
        sealable: false,
        commitment_class: "derived".into(),
        data_class: "derived".into(),
        ..sample_field("grdr.event.v1alpha1.Envelope.a", 1)
    }];
    let falsified_seal = parse_reclassifications_toml(
        "schema = \"grdr.reclassifications.v1alpha1\"\n[[field]]\ntarget = \"grdr.event.v1alpha1.Envelope.a\"\nfrom = \"structural\"\nto = \"derived\"\nfrom_sealable = true\nto_sealable = true\nrfc = \"0099\"\nseat = \"persona-privacy-officer\"\njustification = \"lie\"\n",
    )?;
    let falsified_rep = compare_schemas_sl12(
        &f_unchanged_base,
        &f_unchanged_head,
        &[],
        &[],
        &capture,
        &capture,
        &[],
        &falsified_seal,
        &accepted,
    );
    check(
        !falsified_rep.findings.is_empty(),
        "falsified from_sealable=true on sealable=false field must fail SL12",
    )?;

    // [[level]] delimiter uses `:` matching validate_reclassifications_entries.
    let mut cap_head = capture.clone();
    if let Some(lvl) = cap_head.levels.iter_mut().find(|l| l.name == "standard") {
        lvl.dispositions
            .insert("content.body".into(), "redacted".into());
    }
    let lvl_reclass = parse_reclassifications_toml(
        "schema = \"grdr.reclassifications.v1alpha1\"\n[[level]]\ntarget = \"standard:content.body\"\nfrom = \"withheld\"\nto = \"redacted\"\nrfc = \"0099\"\nseat = \"persona-privacy-officer\"\njustification = \"widen\"\n",
    )?;
    let mut l_findings = Vec::new();
    grdr_schema_lint::validate_reclassifications_entries(&lvl_reclass, &mut l_findings);
    check(
        l_findings.is_empty(),
        format!("valid [[level]] with `:` failed validation: {l_findings:?}"),
    )?;
    let lvl_cmp = compare_schemas_sl12(
        &[],
        &[],
        &[],
        &[],
        &capture,
        &cap_head,
        &[],
        &lvl_reclass,
        &accepted,
    );
    check(
        lvl_cmp.findings.is_empty(),
        format!(
            "valid `level:class` entry must satisfy compare_schemas_sl12: {:?}",
            lvl_cmp.findings
        ),
    )?;
    Ok(())
}

#[test]
fn round4_options_extension_extra_variant_sl03_depth_and_map_key_rules() -> TestRes {
    let (base_set, disk_paths, foreign, brand, surfaces, _) = live_raw()?;

    // 1) Extra DataClass variant rejected + duplicate enum tag + top-level is_map_entry + invalid Bytes map key + out-of-range content_kind.
    let mut mutated = base_set.clone();
    let mut ck_tag = 0u32;
    let mut dc_tag = 0u32;
    let mut pr_tag = 0u32;
    for f in &mut mutated.files {
        if f.name.ends_with("options.proto") {
            for ext in &f.extensions {
                if ext.name == "content_kind" {
                    ck_tag = u32::try_from(ext.number).unwrap_or(0);
                } else if ext.name == "data_class" {
                    dc_tag = u32::try_from(ext.number).unwrap_or(0);
                } else if ext.name == "policy_readable" {
                    pr_tag = u32::try_from(ext.number).unwrap_or(0);
                }
            }
            if let Some(dc) = f.enums.iter_mut().find(|e| e.name == "DataClass") {
                dc.values.push(grdr_proto::descriptor::EnumValueDescriptor {
                    name: "DATA_CLASS_EXTRA".into(),
                    number: 9,
                    raw_options: vec![],
                });
            }
        }
        if f.package == "grdr.common.v1alpha1"
            && f.name.ends_with("enums.proto")
            && let Some(m) = f.enums.iter_mut().find(|e| e.name == "Mode")
        {
            m.values.push(grdr_proto::descriptor::EnumValueDescriptor {
                name: "MODE_DUP".into(),
                number: 1,
                raw_options: vec![],
            });
        }
        if f.package == "grdr.common.v1alpha1" && f.name.ends_with("ids.proto") {
            if let Some(msg) = f.messages.first_mut() {
                msg.is_map_entry = true;
            }
            if let Some(trace) = f.messages.get_mut(1)
                && let Some(fld) = trace.fields.first_mut()
            {
                push_varint_opt(&mut fld.raw_options, ck_tag, u64::from(u32::MAX) + 1);
            }
        }
        if f.package == "grdr.common.v1alpha1"
            && f.name.ends_with("types.proto")
            && let Some(ei) = f.messages.iter_mut().find(|m| m.name == "ErrorInfo")
        {
            for nm in &mut ei.nested_messages {
                if nm.is_map_entry
                    && let Some(k) = nm.fields.iter_mut().find(|kf| kf.number == 1)
                {
                    k.kind = FieldType::Bytes;
                }
            }
        }
    }
    let mut findings = Vec::new();
    check_descriptor_set(
        &mutated,
        &disk_paths,
        &foreign,
        &brand,
        &surfaces,
        &mut findings,
    )?;
    for needle in [
        "unexpected enum variant",
        "duplicate enum tag number",
        "top-level message cannot carry map_entry",
        "invalid map key type",
        "(content_kind) only permitted on DATA_CLASS_CONTENT",
    ] {
        check(
            findings.iter().any(|f| f.message.contains(needle)),
            format!("expected finding `{needle}`, got {findings:?}"),
        )?;
    }

    // 2) SL03 visited >= 256 chain and missing child message descriptor must both fail closed.
    let mut chain_set = base_set.clone();
    let mut missing_set = base_set;
    for f in &mut chain_set.files {
        if f.package == "grdr.common.v1alpha1" && f.name.ends_with("ids.proto") {
            let mut extra = Vec::new();
            for i in 0..=260usize {
                let next_ty = if i == 260 {
                    ".grdr.common.v1alpha1.Chain260".to_owned()
                } else {
                    format!(".grdr.common.v1alpha1.Chain{}", i + 1)
                };
                let mut f_opts = Vec::new();
                push_varint_opt(&mut f_opts, dc_tag, 2);
                extra.push(grdr_proto::descriptor::MessageDescriptor {
                    name: format!("Chain{i}"),
                    fields: vec![grdr_proto::descriptor::FieldDescriptor {
                        name: "next".into(),
                        number: 1,
                        label: FieldLabel::Optional,
                        kind: FieldType::Message,
                        type_name: next_ty,
                        extendee: String::new(),
                        oneof_index: None,
                        proto3_optional: false,
                        raw_options: f_opts,
                    }],
                    nested_messages: vec![],
                    nested_enums: vec![],
                    nested_extensions: vec![],
                    reserved_ranges: vec![grdr_proto::descriptor::ReservedRange {
                        start: 900,
                        end_exclusive: 1000,
                    }],
                    oneofs: vec![],
                    is_map_entry: false,
                });
            }
            if let Some(root_msg) = f.messages.first_mut()
                && let Some(fld) = root_msg.fields.first_mut()
            {
                fld.kind = FieldType::Message;
                fld.label = FieldLabel::Optional;
                fld.type_name = ".grdr.common.v1alpha1.Chain0".into();
                fld.raw_options.clear();
                push_varint_opt(&mut fld.raw_options, dc_tag, 2);
                push_varint_opt(&mut fld.raw_options, pr_tag, 1);
            }
            f.messages.extend(extra);
        }
    }
    let mut chain_findings = Vec::new();
    check_descriptor_set(
        &chain_set,
        &disk_paths,
        &foreign,
        &brand,
        &surfaces,
        &mut chain_findings,
    )?;
    check(
        chain_findings.iter().any(|f| f.message.contains("SL03:")),
        format!("expected SL03 fail-closed on >=256 visited nodes, got {chain_findings:?}"),
    )?;

    for f in &mut missing_set.files {
        if f.package == "grdr.common.v1alpha1"
            && f.name.ends_with("ids.proto")
            && let Some(root_msg) = f.messages.first_mut()
            && let Some(fld) = root_msg.fields.first_mut()
        {
            fld.kind = FieldType::Message;
            fld.label = FieldLabel::Optional;
            fld.type_name = ".grdr.missing.NoSuchType".into();
            fld.raw_options.clear();
            push_varint_opt(&mut fld.raw_options, dc_tag, 2);
            push_varint_opt(&mut fld.raw_options, pr_tag, 1);
        }
    }
    let mut miss_findings = Vec::new();
    check_descriptor_set(
        &missing_set,
        &disk_paths,
        &foreign,
        &brand,
        &surfaces,
        &mut miss_findings,
    )?;
    check(
        miss_findings.iter().any(|f| f.message.contains("SL03:")),
        format!("expected SL03 fail-closed on missing child descriptor, got {miss_findings:?}"),
    )?;
    Ok(())
}

#[test]
fn round4_source_parity_rpc_oneof_extendee_whitespace_boundary_and_suffix() -> TestRes {
    let root = repo_root();
    let tmp = std::env::temp_dir().join(format!("grdr_lint_r4_parity_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    copy_dir_tree(&root.join("contracts"), &tmp.join("contracts"))?;
    copy_dir_tree(
        &root.join("crates/grdr-schema"),
        &tmp.join("crates/grdr-schema"),
    )?;
    fs::create_dir_all(tmp.join("crates/grdr-proto/descriptors"))?;
    fs::copy(
        root.join("crates/grdr-proto/descriptors/proto.binpb"),
        tmp.join("crates/grdr-proto/descriptors/proto.binpb"),
    )?;
    fs::create_dir_all(tmp.join("crates/grdr-schema-lint"))?;
    fs::copy(
        root.join("crates/grdr-schema-lint/foreign_files.toml"),
        tmp.join("crates/grdr-schema-lint/foreign_files.toml"),
    )?;
    check(
        lint_repo_root(&tmp)?.is_clean(),
        "baseline parity copy must be clean",
    )?;

    let check_mutation = |rel: &str, find: &str, replace: &str, needle: &str| -> TestRes {
        let p = tmp.join(rel);
        let orig = fs::read_to_string(&p)?;
        check(
            orig.contains(find),
            format!("pattern `{find}` missing in `{rel}`"),
        )?;
        fs::write(&p, orig.replacen(find, replace, 1))?;
        let rep = lint_repo_root(&tmp)?;
        fs::write(&p, &orig)?;
        check(
            !rep.is_clean() && rep.findings.iter().any(|f| f.message.contains(needle)),
            format!(
                "expected `{needle}` on `{rel}` mutation, got {:?}",
                rep.findings
            ),
        )
    };

    check_mutation(
        "contracts/proto/grdr/operator/v1alpha1/operator.proto",
        "CONFIRM_CLASS_TYPED",
        "CONFIRM_CLASS_NONE",
        "confirm option differs",
    )?;
    check_mutation(
        "contracts/proto/grdr/operator/v1alpha1/operator.proto",
        "AUDIT_CLASS_CRITICAL_MUTATION",
        "AUDIT_CLASS_NONE",
        "audit option differs",
    )?;
    check_mutation(
        "contracts/proto/grdr/operator/v1alpha1/operator.proto",
        "RATE_CLASS_CRITICAL",
        "RATE_CLASS_STANDARD",
        "rate_class option differs",
    )?;
    check_mutation(
        "contracts/proto/grdr/operator/v1alpha1/operator.proto",
        "option idempotency_level = NO_SIDE_EFFECTS;",
        "",
        "idempotency_level option differs",
    )?;
    check_mutation(
        "contracts/proto/grdr/operator/v1alpha1/operator.proto",
        "rpc ListTargetHealth(ListTargetHealthRequest)",
        "rpc ListTargetHealth(ListRuntimeRevisionsRequest)",
        "request/response or streaming differs",
    )?;
    check_mutation(
        "contracts/proto/grdr/local/v1alpha1/local.proto",
        "returns (stream SubscribeResponse);",
        "returns (SubscribeResponse);",
        "request/response or streaming differs",
    )?;
    check_mutation(
        "contracts/proto/grdr/event/v1alpha1/action.proto",
        "  oneof value {\n",
        "  oneof value {\n  }\n  oneof bogus_empty {\n",
        "oneof",
    )?;
    check_mutation(
        "contracts/proto/grdr/common/v1alpha1/options.proto",
        "extend google.protobuf.EnumValueOptions {",
        "extend google.protobuf.MessageOptions {",
        "top-level extensions differ",
    )?;
    check_mutation(
        "contracts/proto/grdr/common/v1alpha1/options.proto",
        "\"argument\"",
        "\"arg ument\"",
        "wire_names differ",
    )?;
    check_mutation(
        "contracts/proto/grdr/common/v1alpha1/ids.proto",
        "[(data_class) = DATA_CLASS_STRUCTURAL]",
        "[(custom_data_class) = DATA_CLASS_STRUCTURAL]",
        "data_class option differs",
    )?;
    check_mutation(
        "contracts/proto/grdr/common/v1alpha1/ids.proto",
        "[(data_class) = DATA_CLASS_STRUCTURAL]",
        "[(evil.data_class) = DATA_CLASS_STRUCTURAL]",
        "data_class option differs",
    )?;
    check_mutation(
        "contracts/proto/grdr/event/v1alpha1/event.proto",
        "HealthEvent health_event = 9",
        "Event health_event = 9",
        "field type differs",
    )?;

    let _ = fs::remove_dir_all(&tmp);
    Ok(())
}

#[test]
fn round4_check_manifests_positive_and_adversarial_tamper() -> TestRes {
    let root = repo_root();
    check_manifests(&root)?;

    let tmp = std::env::temp_dir().join(format!("grdr_lint_r4_mani_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    copy_dir_tree(&root.join("contracts"), &tmp.join("contracts"))?;
    copy_dir_tree(
        &root.join("crates/grdr-schema"),
        &tmp.join("crates/grdr-schema"),
    )?;
    fs::create_dir_all(tmp.join("crates/grdr-model/src"))?;
    fs::copy(
        root.join("crates/grdr-model/Cargo.toml"),
        tmp.join("crates/grdr-model/Cargo.toml"),
    )?;
    fs::copy(
        root.join("crates/grdr-model/src/lib.rs"),
        tmp.join("crates/grdr-model/src/lib.rs"),
    )?;
    fs::create_dir_all(tmp.join("security"))?;
    fs::copy(
        root.join("security/trust-core.paths"),
        tmp.join("security/trust-core.paths"),
    )?;
    fs::create_dir_all(tmp.join("crates/grdr-schema-lint"))?;
    fs::copy(
        root.join("crates/grdr-schema-lint/foreign_files.toml"),
        tmp.join("crates/grdr-schema-lint/foreign_files.toml"),
    )?;
    let min_root = "[workspace]\nresolver = \"3\"\nmembers = [\"crates/*\", \"programs/*\"]\n[workspace.dependencies]\ngrdr-schema = { version = \"0.1.0\", path = \"crates/grdr-schema\" }\ngrdr-model = { version = \"0.1.0\", path = \"crates/grdr-model\" }\n";
    fs::write(tmp.join("Cargo.toml"), min_root)?;
    check_manifests(&tmp)?;

    // 1) package.build forbidden
    let schema_toml_path = tmp.join("crates/grdr-schema/Cargo.toml");
    let orig_schema_toml = fs::read_to_string(&schema_toml_path)?;
    fs::write(
        &schema_toml_path,
        orig_schema_toml.replacen(
            "license = \"Apache-2.0\"",
            "license = \"Apache-2.0\"\nbuild = \"evil.rs\"",
            1,
        ),
    )?;
    check(
        check_manifests(&tmp).is_err(),
        "package.build must fail check_manifests",
    )?;
    fs::write(&schema_toml_path, &orig_schema_toml)?;

    // 2) external path dependency forbidden
    fs::write(
        &schema_toml_path,
        format!("{orig_schema_toml}\n[dependencies.evil]\npath = \"../../outside\"\n"),
    )?;
    check(
        check_manifests(&tmp).is_err(),
        "external path dep must fail check_manifests",
    )?;
    fs::write(&schema_toml_path, &orig_schema_toml)?;

    // 3) unlisted proc-macro crate outside security/trust-core.paths forbidden
    let pm_dir = tmp.join("crates/grdr-evil-macro/src");
    fs::create_dir_all(&pm_dir)?;
    fs::write(pm_dir.join("lib.rs"), "")?;
    fs::write(
        tmp.join("crates/grdr-evil-macro/Cargo.toml"),
        "[package]\nname = \"grdr-evil-macro\"\nversion = \"0.1.0\"\n[lib]\nproc-macro = true\n",
    )?;
    check(
        check_manifests(&tmp).is_err(),
        "unlisted proc-macro must fail check_manifests",
    )?;
    let _ = fs::remove_dir_all(tmp.join("crates/grdr-evil-macro"));

    // 4) non-matching grdr-schema/src/lib.rs rejected
    let schema_lib = tmp.join("crates/grdr-schema/src/lib.rs");
    let orig_schema_lib = fs::read_to_string(&schema_lib)?;
    fs::write(
        &schema_lib,
        orig_schema_lib.replacen("pub mod registry;", "// removed", 1),
    )?;
    check(
        check_manifests(&tmp).is_err(),
        "non-matching grdr-schema/src/lib.rs must fail check_manifests",
    )?;
    fs::write(&schema_lib, &orig_schema_lib)?;

    // 5) out-of-crate bin target rejected
    let decoy = tmp.join("crates/grdr-decoy/src");
    fs::create_dir_all(&decoy)?;
    fs::write(decoy.join("lib.rs"), "")?;
    fs::write(
        tmp.join("crates/grdr-decoy/Cargo.toml"),
        "[package]\nname = \"grdr-decoy\"\nversion = \"0.1.0\"\n[[bin]]\nname = \"x\"\npath = \"../../outside.rs\"\n",
    )?;
    check(
        check_manifests(&tmp).is_err(),
        "out-of-crate target must fail check_manifests",
    )?;

    let _ = fs::remove_dir_all(&tmp);
    Ok(())
}
