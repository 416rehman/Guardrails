// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Descriptor environment validation checks (`SL08`..`SL11`, foreign digests, options schema).

use std::collections::{BTreeMap, BTreeSet};

use grdr_model::eval::sha256_hex;
use grdr_proto::descriptor::{
    DescriptorSet, FileDescriptor, MessageDescriptor, ResolvedOptionsExtension,
    resolve_options_extensions,
};

use crate::descriptor_env::parse_surfaces_proto_packages;
use crate::{LintDomain, LintError, LintFinding, LintSeverity};

const WELL_KNOWN_DESCRIPTOR_PROTO: &str = "google/protobuf/descriptor.proto";

pub(crate) fn is_valid_rel_proto_path(path: &str) -> bool {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || !path.ends_with(".proto")
    {
        return false;
    }
    path.split('/').all(|seg| {
        !seg.is_empty()
            && seg != "."
            && seg != ".."
            && seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    })
}

pub(crate) fn is_valid_proto_version(seg: &str) -> bool {
    let Some(rest) = seg.strip_prefix('v') else {
        return false;
    };
    let tail = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    if tail.len() == rest.len() {
        return false;
    }
    if tail.is_empty() {
        return true;
    }
    let Some(pre) = tail
        .strip_prefix("alpha")
        .or_else(|| tail.strip_prefix("beta"))
    else {
        return false;
    };
    !pre.is_empty() && pre.bytes().all(|b| b.is_ascii_digit())
}

pub(crate) fn is_strict_stable_version(ver: &str) -> bool {
    let Some(digits) = ver.strip_prefix('v') else {
        return false;
    };
    !digits.is_empty() && !digits.starts_with('0') && digits.bytes().all(|b| b.is_ascii_digit())
}

pub(crate) fn check_foreign_descriptors(
    set: &DescriptorSet,
    ns_path_prefix: &str,
    foreign_pins: &BTreeMap<String, String>,
    findings: &mut Vec<LintFinding>,
) {
    let mut seen_names = BTreeSet::new();
    for file in &set.files {
        if !is_valid_rel_proto_path(&file.name) {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &file.name,
                &format!("SL10: invalid descriptor path `{}`", file.name),
            ));
            continue;
        }
        if !seen_names.insert(file.name.as_str()) {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &file.name,
                &format!(
                    "SL09: duplicate descriptor entry `{}` in proto.binpb",
                    file.name
                ),
            ));
        }
        if file.name.starts_with(ns_path_prefix) {
            continue;
        }
        let Some(expected_sha) = foreign_pins.get(&file.name) else {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &file.name,
                &format!(
                    "SL10: foreign import `{}` missing from foreign_files.toml",
                    file.name
                ),
            ));
            continue;
        };
        let actual = sha256_hex(&file.raw_proto_bytes);
        if &actual != expected_sha {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &file.name,
                &format!(
                    "SL10: foreign descriptor SHA-256 mismatch for `{}` (expected {expected_sha}, got {actual})",
                    file.name
                ),
            ));
        }
    }
}

pub(crate) fn find_and_check_options_file<'a>(
    set: &'a DescriptorSet,
    ns: &str,
    findings: &mut Vec<LintFinding>,
) -> Result<(&'a FileDescriptor, ResolvedOptionsExtension), LintError> {
    let ns_prefix = format!("{ns}/");
    for file in &set.files {
        if file.name.starts_with(&ns_prefix) && has_nested_extensions(&file.messages) {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &file.name,
                "SL10: nested message `extend` declarations are forbidden under namespace",
            ));
        }
    }

    let ext_files: Vec<&FileDescriptor> = set
        .files
        .iter()
        .filter(|f| f.name.starts_with(&ns_prefix) && !f.extensions.is_empty())
        .collect();
    if ext_files.len() != 1 {
        return Err(LintError::ForeignDescriptorViolation {
            file: format!("{ns}/common/"),
            detail: format!(
                "SL10: expected exactly 1 options file declaring extensions, found {}",
                ext_files.len()
            ),
        });
    }
    let Some(opts) = ext_files.first().copied() else {
        return Err(LintError::ForeignDescriptorViolation {
            file: ns.into(),
            detail: "SL10: missing options.proto".into(),
        });
    };
    validate_options_shape(opts, ns, findings);
    let resolved =
        resolve_options_extensions(opts).map_err(|e| LintError::ForeignDescriptorViolation {
            file: opts.name.clone(),
            detail: e.to_string(),
        })?;
    Ok((opts, resolved))
}

fn has_nested_extensions(messages: &[MessageDescriptor]) -> bool {
    messages
        .iter()
        .any(|msg| !msg.nested_extensions.is_empty() || has_nested_extensions(&msg.nested_messages))
}

fn validate_options_shape(opts: &FileDescriptor, ns: &str, findings: &mut Vec<LintFinding>) {
    let segs: Vec<&str> = opts.name.split('/').collect();
    let valid_layout = matches!(
        segs.as_slice(),
        [s_ns, "common", ver, "options.proto"] if *s_ns == ns && is_valid_proto_version(ver)
    );
    if !valid_layout {
        findings.push(lint_err(
            "GRDR-LINT-0006",
            &opts.name,
            "SL10: options file must match `<namespace>/common/<version>/options.proto` with no extra segments",
        ));
    }
    if let [s_ns, s_common, ver, _] = segs.as_slice() {
        let expected_pkg = format!("{s_ns}.{s_common}.{ver}");
        if opts.package != expected_pkg {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &opts.name,
                &format!(
                    "SL10: options.proto package `{}` must match `{expected_pkg}`",
                    opts.package
                ),
            ));
        }
    }
    if !opts.messages.is_empty() || !opts.services.is_empty() {
        findings.push(lint_err(
            "GRDR-LINT-0006",
            &opts.name,
            "SL10: options.proto must declare zero messages and zero services",
        ));
    }
    if opts.dependencies != [WELL_KNOWN_DESCRIPTOR_PROTO]
        || !opts.public_dependencies.is_empty()
        || !opts.weak_dependencies.is_empty()
    {
        findings.push(lint_err(
            "GRDR-LINT-0006",
            &opts.name,
            "SL10: options.proto must import solely `google/protobuf/descriptor.proto` directly",
        ));
    }
}

pub(crate) fn check_sl08_sl09_layout(
    set: &DescriptorSet,
    disk_proto_rel_paths: &[String],
    ns_path_prefix: &str,
    ns_pkg_prefix: &str,
    findings: &mut Vec<LintFinding>,
) {
    let all_set_names: BTreeSet<&str> = set.files.iter().map(|f| f.name.as_str()).collect();
    let mut set_ns_paths = BTreeSet::new();
    for file in &set.files {
        for dep in &file.dependencies {
            if !all_set_names.contains(dep.as_str()) {
                findings.push(lint_err(
                    "GRDR-LINT-0006",
                    &file.name,
                    &format!(
                        "SL10: dependency `{dep}` is missing from descriptor set (built with --exclude-imports?)"
                    ),
                ));
            }
        }
        if !file.name.starts_with(ns_path_prefix) {
            continue;
        }
        set_ns_paths.insert(file.name.clone());
        if file.syntax != "proto3" {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &file.name,
                "SL08: syntax must be proto3",
            ));
        }
        let dir_has_dot = file
            .name
            .rsplit_once('/')
            .is_some_and(|(dir, _)| dir.split('/').any(|seg| seg.contains('.')));
        if dir_has_dot {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &file.name,
                "SL08: directory segments inside namespace cannot contain `.`",
            ));
        }
        let expected_pkg = file
            .name
            .rsplit_once('/')
            .map(|(dir, _)| dir.replace('/', "."))
            .unwrap_or_default();
        let tail_ver = expected_pkg.rsplit('.').next().unwrap_or("");
        if !file.package.starts_with(ns_pkg_prefix)
            || file.package != expected_pkg
            || !is_valid_proto_version(tail_ver)
        {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                &file.name,
                &format!(
                    "SL08: package `{}` must match directory path `<namespace>/<domain>/<version>/` (expected `{expected_pkg}`)",
                    file.package
                ),
            ));
        }
    }
    let mut disk_set = BTreeSet::new();
    for p in disk_proto_rel_paths {
        if !p.starts_with(ns_path_prefix) {
            findings.push(lint_err(
                "GRDR-LINT-0002",
                p,
                &format!(
                    "SL09: unexpected `.proto` file `{p}` outside namespace `{ns_path_prefix}`"
                ),
            ));
        } else {
            disk_set.insert(p.clone());
        }
    }
    for missing in disk_set.difference(&set_ns_paths) {
        findings.push(lint_err(
            "GRDR-LINT-0002",
            missing,
            "SL09: proto file on disk is absent from committed `proto.binpb`",
        ));
    }
    for extra in set_ns_paths.difference(&disk_set) {
        findings.push(lint_err(
            "GRDR-LINT-0002",
            extra,
            "SL09: `proto.binpb` contains file missing on disk",
        ));
    }
}

pub(crate) fn check_sl10_imports(
    set: &DescriptorSet,
    ns_path_prefix: &str,
    options_file_name: &str,
    findings: &mut Vec<LintFinding>,
) {
    for file in &set.files {
        if !file.name.starts_with(ns_path_prefix) || file.name == options_file_name {
            continue;
        }
        if file
            .dependencies
            .iter()
            .any(|d| d == WELL_KNOWN_DESCRIPTOR_PROTO)
        {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &file.name,
                "SL10: non-options proto files must never import `google/protobuf/descriptor.proto`",
            ));
        }
        if !file.public_dependencies.is_empty() || !file.weak_dependencies.is_empty() {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &file.name,
                "SL10: public and weak proto imports are forbidden",
            ));
        }
        if !file.dependencies.iter().any(|d| d == options_file_name) {
            findings.push(lint_err(
                "GRDR-LINT-0006",
                &file.name,
                &format!("SL10: must import `{options_file_name}` directly"),
            ));
        }
    }
}

pub(crate) fn validate_surfaces_rows_only(
    surfaces_toml_raw: &str,
    findings: &mut Vec<LintFinding>,
) -> Result<BTreeMap<String, String>, LintError> {
    let rows = parse_surfaces_proto_packages(surfaces_toml_raw)?;
    let mut row_map: BTreeMap<String, String> = BTreeMap::new();
    for row in rows {
        if !matches!(row.class.as_str(), "experimental" | "beta" | "stable") {
            findings.push(lint_err(
                "GRDR-LINT-0007",
                &row.package,
                &format!(
                    "SL11: invalid stability class `{}` in surfaces.toml",
                    row.class
                ),
            ));
        }
        let ver_seg = row.package.rsplit('.').next().unwrap_or("");
        if row.class == "stable" && !is_strict_stable_version(ver_seg) {
            findings.push(lint_err(
                "GRDR-LINT-0007",
                &row.package,
                "SL11: stable class requires strict ^v[1-9][0-9]*$ package version",
            ));
        }
        if row_map.insert(row.package.clone(), row.class).is_some() {
            findings.push(lint_err(
                "GRDR-LINT-0007",
                &row.package,
                "SL11: duplicate [[proto_package]] row in surfaces.toml",
            ));
        }
    }
    Ok(row_map)
}

pub(crate) fn check_sl11_surfaces(
    set: &DescriptorSet,
    ns_pkg_prefix: &str,
    surfaces_toml_raw: &str,
    findings: &mut Vec<LintFinding>,
) -> Result<(), LintError> {
    let row_map = validate_surfaces_rows_only(surfaces_toml_raw, findings)?;
    let mut desc_pkgs = BTreeSet::new();
    for file in &set.files {
        if let Some(stripped) = file.package.strip_prefix(ns_pkg_prefix) {
            desc_pkgs.insert(stripped.to_owned());
        }
    }
    for pkg in &desc_pkgs {
        if !row_map.contains_key(pkg) {
            findings.push(lint_err(
                "GRDR-LINT-0007",
                pkg,
                "SL11: missing [[proto_package]] row in contracts/surfaces.toml",
            ));
        }
    }
    for pkg in row_map.keys() {
        if !desc_pkgs.contains(pkg) {
            findings.push(lint_err(
                "GRDR-LINT-0007",
                pkg,
                "SL11: stale [[proto_package]] row not present in proto.binpb",
            ));
        }
    }
    Ok(())
}

pub(crate) fn lint_err(code: &str, target: &str, msg: &str) -> LintFinding {
    LintFinding {
        code: code.into(),
        domain: LintDomain::Proto,
        severity: LintSeverity::Error,
        target: target.into(),
        message: msg.into(),
    }
}
