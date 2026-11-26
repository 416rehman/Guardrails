// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Workspace Cargo manifest, proc-macro, build script, and library-root integrity checks (`docs/design/04:521`).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

use crate::capture_toml::strip_toml_comment;
use crate::io_safe::read_bounded_regular_file;
use crate::io_safe_fs::{
    canonicalize_real_dir, is_symlink_or_reparse, reject_symlinks_under, relative_under_root,
};
use crate::manifest_toml::{
    extract_inline_string_attr, manifest_err, parse_string_array, parse_toml_assignments,
    unquote_toml_value,
};
use crate::{LintError, MAX_LINT_FILE_BYTES};

const TARGET_SECTIONS: &[&str] = &["lib", "bin", "test", "bench", "example"];

struct PackageSummary {
    pkg_name: Option<String>,
    lib_path: Option<String>,
    is_proc_macro: bool,
    has_build_deps: bool,
    resolved_path_deps: Vec<String>,
}

pub(crate) fn verify_workspace_manifests(canon_root: &Path) -> Result<(), LintError> {
    let trust_raw = read_bounded_regular_file(
        canon_root,
        &canon_root.join("security/trust-core.paths"),
        MAX_LINT_FILE_BYTES,
    )?;
    let trust_patterns = parse_trust_core_patterns(&trust_raw);
    let has_build_rs_glob = trust_patterns
        .iter()
        .any(|p| p.eq_ignore_ascii_case("**/build.rs"));

    let root_raw = read_bounded_regular_file(
        canon_root,
        &canon_root.join("Cargo.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let extra_members = check_root_manifest(canon_root, &root_raw)?;

    check_pinned_crate_root(
        canon_root,
        "crates/grdr-schema",
        "grdr-schema",
        &["pub mod brand;", "pub mod capture;", "pub mod registry;"],
        None,
        &trust_patterns,
        has_build_rs_glob,
    )?;
    check_pinned_crate_root(
        canon_root,
        "crates/grdr-model",
        "grdr-model",
        &["pub mod proto_conv;"],
        Some("crates/grdr-schema"),
        &trust_patterns,
        has_build_rs_glob,
    )?;

    let mut checked = BTreeSet::new();
    for top_dir in ["crates", "programs"] {
        scan_workspace_crate_dir(
            canon_root,
            top_dir,
            &trust_patterns,
            has_build_rs_glob,
            &mut checked,
        )?;
    }
    for member in extra_members {
        if checked.insert(member.clone()) {
            let clean = member.trim_end_matches('/');
            let pkg_dir = canon_root.join(clean);
            relative_under_root(canon_root, &pkg_dir)?;
            let manifest = pkg_dir.join("Cargo.toml");
            if matches!(fs::symlink_metadata(&manifest), Ok(m) if !is_symlink_or_reparse(&m) && m.is_file())
            {
                check_package_manifest(canon_root, clean, &trust_patterns, has_build_rs_glob)?;
            }
        }
    }
    Ok(())
}

fn parse_trust_core_patterns(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|l| strip_toml_comment(l).trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

fn is_pkg_covered_by_trust_core(patterns: &[String], pkg_rel: &str) -> bool {
    patterns.iter().any(|pat| {
        let Some(prefix) = pat.strip_suffix("/**") else {
            return false;
        };
        let norm_prefix = prefix.trim_end_matches('/');
        pkg_rel.eq_ignore_ascii_case(norm_prefix)
            || (pkg_rel
                .get(..norm_prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(norm_prefix))
                && pkg_rel
                    .as_bytes()
                    .get(norm_prefix.len())
                    .is_some_and(|&b| b == b'/'))
    })
}

fn check_root_manifest(canon_root: &Path, raw: &str) -> Result<Vec<String>, LintError> {
    let mut has_workspace = false;
    let mut explicit_members = Vec::new();
    for (section, key, val) in parse_toml_assignments(raw, "Cargo.toml")? {
        if section == "workspace" {
            has_workspace = true;
            if key == "members" {
                for m in parse_string_array(&val, "Cargo.toml")? {
                    if !m.contains('*') && !m.contains('?') {
                        explicit_members.push(m);
                    }
                }
            }
        }
        if section == "workspace.dependencies" {
            if let Some(dep_path) = extract_inline_string_attr(&val, "path")? {
                verify_workspace_dep_path(canon_root, "", &dep_path, "Cargo.toml")?;
            }
            if extract_inline_string_attr(&val, "git")?.is_some() {
                return Err(manifest_err(
                    "Cargo.toml",
                    &format!("git dependency `{key}` is forbidden in workspace manifest"),
                ));
            }
        }
    }
    if !has_workspace {
        return Err(manifest_err("Cargo.toml", "missing `[workspace]` section"));
    }
    Ok(explicit_members)
}

fn scan_workspace_crate_dir(
    canon_root: &Path,
    top_dir: &str,
    trust_patterns: &[String],
    has_build_rs_glob: bool,
    checked: &mut BTreeSet<String>,
) -> Result<(), LintError> {
    let base = canon_root.join(top_dir);
    match fs::symlink_metadata(&base) {
        Ok(m) => {
            if is_symlink_or_reparse(&m) || !m.is_dir() {
                return Err(manifest_err(
                    top_dir,
                    "workspace group must be real directory",
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(manifest_err(top_dir, &err.to_string())),
    }
    let canon_base = canonicalize_real_dir(&base, top_dir)?;
    let entries = fs::read_dir(&canon_base).map_err(|e| manifest_err(top_dir, &e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| manifest_err(top_dir, &e.to_string()))?;
        let path = entry.path();
        let meta =
            fs::symlink_metadata(&path).map_err(|e| manifest_err(top_dir, &e.to_string()))?;
        if is_symlink_or_reparse(&meta) {
            return Err(manifest_err(
                &path.display().to_string(),
                "symlinks are forbidden inside workspace crate directories",
            ));
        }
        if !meta.is_dir() {
            continue;
        }
        let Some(dir_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let pkg_rel = format!("{top_dir}/{dir_name}");
        checked.insert(pkg_rel.clone());
        let cargo_toml = canon_root.join(&pkg_rel).join("Cargo.toml");
        if matches!(fs::symlink_metadata(&cargo_toml), Ok(m) if !is_symlink_or_reparse(&m) && m.is_file())
        {
            check_package_manifest(canon_root, &pkg_rel, trust_patterns, has_build_rs_glob)?;
        }
    }
    Ok(())
}

fn check_pinned_crate_root(
    canon_root: &Path,
    pkg_rel: &str,
    expected_name: &str,
    required_pub_mods: &[&str],
    allowed_only_path_dep: Option<&str>,
    trust_patterns: &[String],
    has_build_rs_glob: bool,
) -> Result<(), LintError> {
    let build_rs = canon_root.join(pkg_rel).join("build.rs");
    match fs::symlink_metadata(&build_rs) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(manifest_err(
                &format!("{pkg_rel}/build.rs"),
                &format!("`{pkg_rel}` is pinned with no build script"),
            ));
        }
        Err(err) => return Err(manifest_err(pkg_rel, &err.to_string())),
    }

    let summary = check_package_manifest(canon_root, pkg_rel, trust_patterns, has_build_rs_glob)?;
    if summary.pkg_name.as_deref() != Some(expected_name) {
        return Err(manifest_err(
            &format!("{pkg_rel}/Cargo.toml"),
            &format!("expected package name `{expected_name}`"),
        ));
    }
    if summary.is_proc_macro || summary.has_build_deps {
        return Err(manifest_err(
            &format!("{pkg_rel}/Cargo.toml"),
            &format!("`{pkg_rel}` cannot enable proc-macro or build-dependencies"),
        ));
    }
    if let Some(lib_path) = summary.lib_path
        && lib_path != "src/lib.rs"
    {
        return Err(manifest_err(
            &format!("{pkg_rel}/Cargo.toml"),
            &format!("`{pkg_rel}` [lib].path must be `src/lib.rs`, found `{lib_path}`"),
        ));
    }
    for dep in &summary.resolved_path_deps {
        if allowed_only_path_dep != Some(dep.as_str()) {
            return Err(manifest_err(
                &format!("{pkg_rel}/Cargo.toml"),
                &format!("unexpected path dependency `{dep}` in `{pkg_rel}`"),
            ));
        }
    }

    let lib_rel = format!("{pkg_rel}/src/lib.rs");
    let lib_raw =
        read_bounded_regular_file(canon_root, &canon_root.join(&lib_rel), MAX_LINT_FILE_BYTES)?;
    if lib_raw.contains("#[path")
        || lib_raw.contains("include!(")
        || lib_raw.contains("include_str!(")
        || lib_raw.contains("include_bytes!(")
    {
        return Err(manifest_err(
            &lib_rel,
            "library root must not redirect modules via `#[path]` or `include*!`",
        ));
    }
    for req in required_pub_mods {
        if !lib_raw.lines().any(|line| line.trim() == *req) {
            return Err(manifest_err(
                &lib_rel,
                &format!("library root missing plain declaration `{req}`"),
            ));
        }
    }
    Ok(())
}

fn check_package_manifest(
    canon_root: &Path,
    pkg_rel: &str,
    trust_patterns: &[String],
    has_build_rs_glob: bool,
) -> Result<PackageSummary, LintError> {
    let manifest_rel = format!("{pkg_rel}/Cargo.toml");
    let raw = read_bounded_regular_file(
        canon_root,
        &canon_root.join(&manifest_rel),
        MAX_LINT_FILE_BYTES,
    )?;
    let canon_pkg = canonicalize_real_dir(&canon_root.join(pkg_rel), pkg_rel)?;
    let (mut pkg_name, mut lib_path) = (None, None);
    let (mut is_proc_macro, mut has_build_deps) = (false, false);
    let mut resolved_path_deps = Vec::new();

    for (section, key, val) in parse_toml_assignments(&raw, &manifest_rel)? {
        if section == "package" {
            if key == "name" {
                pkg_name = Some(unquote_toml_value(&val, &manifest_rel)?);
            } else if key == "build" {
                return Err(manifest_err(
                    &manifest_rel,
                    "`package.build` is forbidden (custom build targets disallowed)",
                ));
            }
        } else if is_target_section(&section) && key == "path" {
            let tgt = unquote_toml_value(&val, &manifest_rel)?;
            let joined = canon_pkg.join(&tgt);
            relative_under_root(&canon_pkg, &joined)?;
            reject_symlinks_under(&canon_pkg, &joined, false)?;
            if section == "lib" {
                lib_path = Some(tgt);
            }
        } else if section == "lib" && (key == "proc-macro" || key == "proc_macro") {
            if val.trim() == "true" {
                is_proc_macro = true;
            }
        } else if is_build_dep_section(&section) {
            has_build_deps = true;
            if let Some(p) =
                check_dep_assignment(canon_root, pkg_rel, &section, &key, &val, &manifest_rel)?
            {
                resolved_path_deps.push(p);
            }
        } else if is_dep_section(&section)
            && let Some(p) =
                check_dep_assignment(canon_root, pkg_rel, &section, &key, &val, &manifest_rel)?
        {
            resolved_path_deps.push(p);
        }
    }

    let build_rs_path = canon_pkg.join("build.rs");
    let has_build_rs = match fs::symlink_metadata(&build_rs_path) {
        Ok(m) => {
            if is_symlink_or_reparse(&m) || !m.is_file() {
                return Err(manifest_err(
                    &format!("{pkg_rel}/build.rs"),
                    "build.rs must be a real non-symlink file",
                ));
            }
            true
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => {
            return Err(manifest_err(
                &format!("{pkg_rel}/build.rs"),
                &err.to_string(),
            ));
        }
    };
    if has_build_rs && !has_build_rs_glob && !is_pkg_covered_by_trust_core(trust_patterns, pkg_rel)
    {
        return Err(manifest_err(
            &format!("{pkg_rel}/build.rs"),
            "build script requires `**/build.rs` or `<pkg>/**` in security/trust-core.paths",
        ));
    }
    if has_build_deps && !has_build_rs {
        return Err(manifest_err(
            &manifest_rel,
            "`[build-dependencies]` forbidden without `<pkg>/build.rs`",
        ));
    }
    if is_proc_macro && !is_pkg_covered_by_trust_core(trust_patterns, pkg_rel) {
        return Err(manifest_err(
            &manifest_rel,
            &format!(
                "unlisted proc-macro package `{pkg_rel}` missing `<dir>/**` in security/trust-core.paths"
            ),
        ));
    }

    Ok(PackageSummary {
        pkg_name,
        lib_path,
        is_proc_macro,
        has_build_deps,
        resolved_path_deps,
    })
}

fn check_dep_assignment(
    canon_root: &Path,
    pkg_rel: &str,
    section: &str,
    key: &str,
    val: &str,
    manifest_rel: &str,
) -> Result<Option<String>, LintError> {
    if extract_inline_string_attr(val, "git")?.is_some() || (section.contains('.') && key == "git")
    {
        return Err(manifest_err(
            manifest_rel,
            &format!("git dependency in `{section}` is forbidden"),
        ));
    }
    let dep_path = if section.ends_with("dependencies") {
        extract_inline_string_attr(val, "path")?
    } else if key == "path" {
        Some(unquote_toml_value(val, manifest_rel)?)
    } else {
        None
    };
    let Some(raw_p) = dep_path else {
        return Ok(None);
    };
    let resolved = verify_workspace_dep_path(canon_root, pkg_rel, &raw_p, manifest_rel)?;
    Ok(Some(resolved))
}

fn verify_workspace_dep_path(
    canon_root: &Path,
    pkg_rel: &str,
    raw_p: &str,
    manifest_rel: &str,
) -> Result<String, LintError> {
    let rel_path = Path::new(raw_p);
    if rel_path.is_absolute() {
        return Err(manifest_err(
            manifest_rel,
            &format!("external absolute path dependency `{raw_p}` is forbidden"),
        ));
    }
    let mut segs: Vec<String> = if pkg_rel.is_empty() {
        Vec::new()
    } else {
        pkg_rel.split('/').map(str::to_owned).collect()
    };
    for comp in rel_path.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(s) => {
                let text = s
                    .to_str()
                    .ok_or_else(|| manifest_err(manifest_rel, "non-utf8 path dependency"))?;
                segs.push(text.to_owned());
            }
            Component::ParentDir => {
                if segs.pop().is_none() {
                    return Err(manifest_err(
                        manifest_rel,
                        &format!("external path dependency `{raw_p}` escapes repository root"),
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(manifest_err(
                    manifest_rel,
                    &format!("external path dependency `{raw_p}` is forbidden"),
                ));
            }
        }
    }
    let norm_rel = segs.join("/");
    if !(norm_rel.starts_with("crates/") || norm_rel.starts_with("programs/")) {
        return Err(manifest_err(
            manifest_rel,
            &format!(
                "external path dependency `{raw_p}` must resolve inside `crates/` or `programs/`"
            ),
        ));
    }
    let canon_dep = canonicalize_real_dir(&canon_root.join(&norm_rel), &norm_rel)?;
    if !canon_dep.starts_with(canon_root) {
        return Err(manifest_err(
            manifest_rel,
            &format!("external path dependency `{raw_p}` escapes workspace root"),
        ));
    }
    Ok(norm_rel)
}

fn is_target_section(sec: &str) -> bool {
    TARGET_SECTIONS.contains(&sec)
}

fn is_build_dep_section(sec: &str) -> bool {
    sec == "build-dependencies"
        || sec.starts_with("build-dependencies.")
        || (sec.starts_with("target.") && sec.contains(".build-dependencies"))
}

fn is_dep_section(sec: &str) -> bool {
    let roots = ["dependencies", "dev-dependencies"];
    roots
        .iter()
        .any(|r| sec == *r || sec.starts_with(&format!("{r}.")))
        || (sec.starts_with("target.")
            && (sec.contains(".dependencies") || sec.contains(".dev-dependencies")))
}
