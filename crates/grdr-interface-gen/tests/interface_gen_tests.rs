// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use grdr_interface_gen::emit_contracts::render_rune_theme_json;
use grdr_interface_gen::emit_rust::{render_grdr_strings, rust_str};
use grdr_interface_gen::loader::load_interface_bundle;
use grdr_interface_gen::toml_doc::parse_toml_table;
use grdr_interface_gen::{RunMode, run};

type TestResult = Result<(), Box<dyn Error>>;

fn ensure(cond: bool, msg: impl Into<String>) -> TestResult {
    if cond { Ok(()) } else { Err(msg.into().into()) }
}

fn ensure_eq<T: PartialEq + std::fmt::Debug>(left: &T, right: &T, label: &str) -> TestResult {
    if left == right {
        Ok(())
    } else {
        Err(format!("{label}: expected {right:?}, got {left:?}").into())
    }
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or("crate sits under <repo>/crates/grdr-interface-gen")?;
    Ok(root.to_path_buf())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> TestResult {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[test]
fn loads_workspace_interface_and_matches_checked_in_artifacts_with_zero_drift() -> TestResult {
    let root = workspace_root()?;
    let checked = run(&root, RunMode::Check)?;
    ensure_eq(&checked.len(), &12, "checked artifact count")
}

#[test]
fn canonical_assurance_labels_and_23_routes_and_brand_align_with_design_docs() -> TestResult {
    let root = workspace_root()?;
    let bundle = load_interface_bundle(&root)?;

    ensure_eq(&bundle.routes.len(), &23, "route count")?;
    ensure_eq(
        &bundle.brand.font_sans.as_str(),
        &"\"DM Sans\", system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
        "font_sans",
    )?;
    ensure_eq(
        &bundle.brand.font_mono.as_str(),
        &"\"IBM Plex Mono\", ui-monospace, SFMono-Regular, monospace",
        "font_mono",
    )?;

    let expected_al = [
        ("assurance.al0", "AL0 Inventoried"),
        ("assurance.al1", "AL1 Observed"),
        ("assurance.al2", "AL2 Guided"),
        ("assurance.al3", "AL3 Contained"),
        ("assurance.al4", "AL4 Enforced"),
    ];
    for (id, text) in expected_al {
        let msg = bundle
            .messages
            .iter()
            .find(|m| m.id == id)
            .ok_or_else(|| format!("missing assurance label token '{id}'"))?;
        ensure_eq(&msg.msg.as_str(), &text, id)?;
    }

    let mut covered_ids = BTreeSet::new();
    for h in &bundle.harness_icons {
        covered_ids.insert(h.id.as_str());
    }
    let agents_dir = root.join("packs").join("catalogue").join("agents");
    for entry in fs::read_dir(agents_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            ensure(
                covered_ids.contains(stem),
                format!(
                    "catalogue agent '{stem}' must be registered in contracts/interface/icons.toml"
                ),
            )?;
        }
    }
    Ok(())
}

#[test]
fn dx25_rune_theme_json_schema_uses_eight_digit_hex_and_required_sections() -> TestResult {
    let root = workspace_root()?;
    let bundle = load_interface_bundle(&root)?;
    let raw = render_rune_theme_json(&bundle)?;
    let parsed: serde_json::Value = serde_json::from_str(&raw)?;

    for required in [
        "name",
        "blend",
        "palette",
        "light",
        "dark",
        "numbers",
        "locked_tokens",
    ] {
        ensure(
            parsed.get(required).is_some(),
            format!("missing Rune theme key '{required}'"),
        )?;
    }
    for mode_key in ["light", "dark"] {
        let map = parsed
            .get(mode_key)
            .and_then(|v| v.as_object())
            .ok_or_else(|| format!("missing object '{mode_key}'"))?;
        ensure(map.contains_key("bg_canvas"), "missing bg_canvas")?;
        ensure(map.contains_key("allow"), "missing allow")?;
        ensure(map.contains_key("block"), "missing block")?;
        for (name, val) in map {
            let hex = val.as_str().ok_or("color string")?;
            ensure(
                hex.starts_with('#') && hex.len() == 9,
                format!("DX-25 color '{mode_key}.{name}' must be #rrggbbaa, got '{hex}'"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn write_and_check_round_trip_detects_drift_in_temp_workspace() -> TestResult {
    let root = workspace_root()?;
    let temp_root =
        std::env::temp_dir().join(format!("grdr-interface-gen-test-{}", std::process::id()));
    if temp_root.exists() {
        fs::remove_dir_all(&temp_root)?;
    }
    copy_dir_recursive(
        &root.join("contracts/interface"),
        &temp_root.join("contracts/interface"),
    )?;

    let written = run(&temp_root, RunMode::Write)?;
    ensure_eq(&written.len(), &12, "written artifact count")?;
    run(&temp_root, RunMode::Check)?;

    let tokens_path = temp_root.join("web/packages/tokens/src/tokens.css");
    fs::write(&tokens_path, "/* drifted */\n")?;
    let Err(err) = run(&temp_root, RunMode::Check) else {
        return Err("must detect drift".into());
    };
    let err_str = err.to_string();
    ensure(err_str.contains("GRDR-GEN-0006"), "missing GRDR-GEN-0006")?;
    ensure(
        err_str.contains("web/packages/tokens/src/tokens.css"),
        "missing drifted tokens path",
    )?;

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn validation_rejects_forbidden_vocabulary_missing_refs_and_duplicate_shortcuts() -> TestResult {
    let root = workspace_root()?;
    let temp_root =
        std::env::temp_dir().join(format!("grdr-interface-gen-val-{}", std::process::id()));
    if temp_root.exists() {
        fs::remove_dir_all(&temp_root)?;
    }
    copy_dir_recursive(
        &root.join("contracts/interface"),
        &temp_root.join("contracts/interface"),
    )?;

    let common_path = temp_root.join("contracts/interface/strings/src/common.mf2.toml");
    let original = fs::read_to_string(&common_path)?;
    let bad = format!(
        "{original}\n[\"console.bad.example\"]\ndesc = \"Bad\"\nmax = 40\nrisk = \"normal\"\nmsg = \"Check device posture\"\n"
    );
    fs::write(&common_path, bad)?;
    let Err(err) = load_interface_bundle(&temp_root) else {
        return Err("must reject forbidden vocabulary".into());
    };
    let err_str = err.to_string();
    ensure(err_str.contains("GRDR-GEN-0004"), "missing GRDR-GEN-0004")?;
    ensure(err_str.contains("posture"), "missing posture keyword")?;

    fs::write(&common_path, original)?;
    let shortcuts_path = temp_root.join("contracts/interface/shortcuts.toml");
    let sc_orig = fs::read_to_string(&shortcuts_path)?;
    let sc_bad = format!(
        "{sc_orig}\n[[shortcut]]\naction = \"dup\"\nscope = \"global\"\nkeys = \"Ctrl+K\"\nmacos_keys = \"Cmd+K\"\ndesc = \"Duplicate\"\n"
    );
    fs::write(&shortcuts_path, sc_bad)?;
    let Err(sc_err) = load_interface_bundle(&temp_root) else {
        return Err("must reject duplicate shortcut".into());
    };
    ensure(
        sc_err.to_string().contains("duplicate shortcut"),
        "missing duplicate shortcut error",
    )?;

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn rejects_orphan_translation_keys_and_placeholder_mismatches() -> TestResult {
    let root = workspace_root()?;
    let temp_root =
        std::env::temp_dir().join(format!("grdr-interface-gen-tr-{}", std::process::id()));
    if temp_root.exists() {
        fs::remove_dir_all(&temp_root)?;
    }
    copy_dir_recursive(
        &root.join("contracts/interface"),
        &temp_root.join("contracts/interface"),
    )?;

    let ar_path = temp_root.join("contracts/interface/strings/tr/ar/messages.mf2.toml");
    let ar_orig = fs::read_to_string(&ar_path)?;
    let with_orphan = format!("{ar_orig}\n[\"nonexistent.orphan.key\"]\nmsg = \"x\"\n");
    fs::write(&ar_path, with_orphan)?;
    let Err(orphan_err) = load_interface_bundle(&temp_root) else {
        return Err("must reject orphan translation key".into());
    };
    ensure(
        orphan_err.to_string().contains("orphan translation"),
        "missing orphan translation error",
    )?;

    fs::write(&ar_path, ar_orig)?;
    let de_path = temp_root.join("contracts/interface/strings/tr/de-DE/messages.mf2.toml");
    let de_orig = fs::read_to_string(&de_path)?;
    let broken_var = de_orig.replacen(
        "msg = \"forderte {$action} auf\"",
        "msg = \"forderte auf\"",
        1,
    );
    fs::write(&de_path, broken_var)?;
    let Err(var_err) = load_interface_bundle(&temp_root) else {
        return Err("must reject placeholder mismatch".into());
    };
    ensure(
        var_err.to_string().contains("placeholder"),
        "missing placeholder parity error",
    )?;

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn rejects_duplicate_toml_keys_and_css_injection() -> TestResult {
    let dup = parse_toml_table("[sec]\na = \"1\"\na = \"2\"\n");
    ensure(dup.is_err(), "duplicate key in TOML must fail")?;
    let dup_sec = parse_toml_table("[sec]\na = \"1\"\n[sec]\nb = \"2\"\n");
    ensure(dup_sec.is_err(), "duplicate TOML table must fail")?;

    let root = workspace_root()?;
    let temp_root =
        std::env::temp_dir().join(format!("grdr-interface-gen-css-{}", std::process::id()));
    if temp_root.exists() {
        fs::remove_dir_all(&temp_root)?;
    }
    copy_dir_recursive(
        &root.join("contracts/interface"),
        &temp_root.join("contracts/interface"),
    )?;

    let brand_path = temp_root.join("contracts/interface/brand/brand.toml");
    let orig = fs::read_to_string(&brand_path)?;
    let injected = orig.replacen(
        "\\\"DM Sans\\\", system-ui",
        "\\\"DM Sans\\\"; } body { display: none; }",
        1,
    );
    fs::write(&brand_path, injected)?;
    let Err(css_err) = load_interface_bundle(&temp_root) else {
        return Err("must reject unsafe CSS token".into());
    };
    ensure(
        css_err.to_string().contains("unsafe CSS token content"),
        "missing CSS injection error",
    )?;

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn rust_str_escapes_control_chars_and_emits_mf2_runtime() -> TestResult {
    let escaped = rust_str("a\u{0008}\x0c\n\"b\"");
    ensure_eq(
        &escaped.as_str(),
        &"\"a\\u{8}\\u{c}\\n\\\"b\\\"\"",
        "rust_str control escaping",
    )?;

    let root = workspace_root()?;
    let bundle = load_interface_bundle(&root)?;
    let rust_src = render_grdr_strings(&bundle);
    ensure(
        rust_src.contains("pub fn resolve_mf2_template"),
        "missing MF2 resolver in generated grdr-strings",
    )?;
    ensure(
        rust_src.contains("pub fn lookup_with_count"),
        "missing lookup_with_count in generated grdr-strings",
    )?;
    ensure(
        !rust_src.contains("action.net_egress"),
        "dead orphan key must not appear in generated grdr-strings",
    )?;
    Ok(())
}

#[test]
fn rejects_duplicate_icon_notification_and_locale_entries() -> TestResult {
    let root = workspace_root()?;
    let temp_root =
        std::env::temp_dir().join(format!("grdr-interface-gen-uniq-{}", std::process::id()));
    if temp_root.exists() {
        fs::remove_dir_all(&temp_root)?;
    }
    copy_dir_recursive(
        &root.join("contracts/interface"),
        &temp_root.join("contracts/interface"),
    )?;

    let icons_path = temp_root.join("contracts/interface/icons.toml");
    let icons_orig = fs::read_to_string(&icons_path)?;
    fs::write(
        &icons_path,
        format!(
            "{icons_orig}\n[[icon]]\nkey = \"mode.off\"\nlucide = \"circle-off\"\nmirror = false\n"
        ),
    )?;
    let Err(icon_err) = load_interface_bundle(&temp_root) else {
        return Err("must reject duplicate icon.key".into());
    };
    ensure(
        icon_err.to_string().contains("GRDR-GEN-0004"),
        "missing GRDR-GEN-0004",
    )?;
    ensure(
        icon_err.to_string().contains("duplicate icon key"),
        "missing duplicate icon key error",
    )?;
    fs::write(&icons_path, icons_orig)?;

    let notif_path = temp_root.join("contracts/interface/notifications.toml");
    let notif_orig = fs::read_to_string(&notif_path)?;
    fs::write(
        &notif_path,
        format!(
            "{notif_orig}\n[[notification]]\nclass = \"page\"\nchannels = [\"tray\"]\ndedup_window_secs = 60\nquiet_hours = false\ntone = \"danger\"\nicon = \"security.alert\"\ntitle_token = \"desktop.why.blocked\"\n"
        ),
    )?;
    let Err(notif_err) = load_interface_bundle(&temp_root) else {
        return Err("must reject duplicate notification.class".into());
    };
    ensure(
        notif_err.to_string().contains("GRDR-GEN-0004"),
        "missing GRDR-GEN-0004",
    )?;
    ensure(
        notif_err
            .to_string()
            .contains("duplicate notification class"),
        "missing duplicate notification class error",
    )?;
    fs::write(&notif_path, notif_orig)?;

    let loc_path = temp_root.join("contracts/interface/strings/locales.toml");
    let loc_orig = fs::read_to_string(&loc_path)?;
    fs::write(
        &loc_path,
        format!(
            "{loc_orig}\n[[locale]]\ntag = \"EN-US\"\nrust_variant = \"EnUsDup\"\nnative_name = \"Dup\"\ntier = \"shipped\"\nscript = \"latn\"\ndirection = \"ltr\"\nfallback = \"en-US\"\naliases = []\n"
        ),
    )?;
    let Err(loc_err) = load_interface_bundle(&temp_root) else {
        return Err("must reject duplicate locale.tag".into());
    };
    ensure(
        loc_err.to_string().contains("GRDR-GEN-0004"),
        "missing GRDR-GEN-0004",
    )?;
    ensure(
        loc_err.to_string().contains("duplicate locale tag"),
        "missing duplicate locale tag error",
    )?;

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}
