// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::loader_extra::{
    ensure_not_symlink, load_optional_cli, load_optional_notifications, load_optional_shortcuts,
    load_routes, load_translations, opt_str, opt_str_array, opt_table_array, parse_toml_file,
    req_str, req_table, req_table_array, sorted_mf2_files,
};
use crate::model::{
    BaseTokensFile, BrandSpec, ExtendedTokensFile, ForbiddenTerm, GenError, HarnessIconSpec,
    IconCatalogSpec, IconSpec, InterfaceBundle, LocaleSpec, MessageSpec, OsIconSpec,
    PresentationSpec, TokenBundle, VocabularySpec, VocabularyTerm,
};
use crate::toml_doc::TomlValue;
use crate::validate::validate_bundle;

/// Loads and validates all single-source specs under `contracts/interface/`.
pub fn load_interface_bundle(repo_root: &Path) -> Result<InterfaceBundle, GenError> {
    let iface = repo_root.join("contracts").join("interface");
    let brand = load_brand(&iface.join("brand").join("brand.toml"))?;
    let tokens = load_tokens(&iface)?;
    let locales = load_locales(&iface.join("strings").join("locales.toml"))?;
    let messages = load_messages(&iface.join("strings").join("src"))?;
    let translations = load_translations(&iface.join("strings").join("tr"))?;
    let vocabulary = load_vocabulary(&iface.join("vocabulary.toml"))?;
    let icon_catalog = load_icons(&iface.join("icons.toml"))?;
    let presentations = load_presentations(&iface.join("presentation.toml"))?;
    let routes = load_routes(&iface.join("routes.toml"))?;
    let cli = load_optional_cli(&iface.join("cli.toml"))?;
    let shortcuts = load_optional_shortcuts(&iface.join("shortcuts.toml"))?;
    let notifications = load_optional_notifications(&iface.join("notifications.toml"))?;

    let bundle = InterfaceBundle {
        brand,
        tokens,
        locales,
        messages,
        translations,
        vocabulary,
        icons: icon_catalog.icons,
        harness_icons: icon_catalog.harnesses,
        os_icons: icon_catalog.operating_systems,
        presentations,
        routes,
        cli,
        shortcuts,
        notifications,
    };
    validate_bundle(&bundle, repo_root)?;
    Ok(bundle)
}

fn read_text(path: &Path) -> Result<String, GenError> {
    ensure_not_symlink(path, "contracts/interface")?;
    fs::read_to_string(path).map_err(|source| GenError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn load_brand(path: &Path) -> Result<BrandSpec, GenError> {
    let doc = parse_toml_file(path)?;
    let file = "contracts/interface/brand/brand.toml".to_owned();
    let identity = req_table(&doc, "identity", &file)?;
    let tokens = req_table(&doc, "tokens", &file)?;
    Ok(BrandSpec {
        product_name: req_str(identity, "product_name", &file)?,
        short_name: req_str(identity, "short_name", &file)?,
        accent: req_str(tokens, "accent", &file)?,
        accent_dark: req_str(tokens, "accent_dark", &file)?,
        surface_light: req_str(tokens, "surface_light", &file)?,
        surface_dark: req_str(tokens, "surface_dark", &file)?,
        font_sans: req_str(tokens, "font_sans", &file)?,
        font_mono: req_str(tokens, "font_mono", &file)?,
    })
}

fn load_tokens(iface: &Path) -> Result<TokenBundle, GenError> {
    let base_path = iface.join("tokens.json");
    let base_text = read_text(&base_path)?;
    let base: BaseTokensFile =
        serde_json::from_str(&base_text).map_err(|source| GenError::Json {
            path: base_path,
            source,
        })?;

    let ext_path = iface.join("tokens").join("studio-extended.json");
    let ext_text = read_text(&ext_path)?;
    let extended: ExtendedTokensFile =
        serde_json::from_str(&ext_text).map_err(|source| GenError::Json {
            path: ext_path,
            source,
        })?;

    let light_resolved = resolve_theme_map(&base.light, &extended.light, &base)?;
    let dark_resolved = resolve_theme_map(&base.dark, &extended.dark, &base)?;

    Ok(TokenBundle {
        base,
        extended,
        light_resolved,
        dark_resolved,
    })
}

fn resolve_theme_map(
    base_theme: &BTreeMap<String, String>,
    ext_theme: &BTreeMap<String, String>,
    base_all: &BaseTokensFile,
) -> Result<BTreeMap<String, String>, GenError> {
    let mut merged = BTreeMap::new();
    for (k, v) in base_theme {
        merged.insert(k.clone(), v.clone());
    }
    for (k, v) in ext_theme {
        merged.insert(k.clone(), resolve_refs(v, base_all)?);
    }
    Ok(merged)
}

fn resolve_refs(raw: &str, base: &BaseTokensFile) -> Result<String, GenError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some((before, after_open)) = rest.split_once('{') {
        out.push_str(before);
        let Some((token_ref, after_close)) = after_open.split_once('}') else {
            return Err(GenError::UnresolvedTokenRef {
                reference: raw.to_owned(),
            });
        };
        let resolved =
            lookup_token_ref(token_ref, base).ok_or_else(|| GenError::UnresolvedTokenRef {
                reference: token_ref.to_owned(),
            })?;
        out.push_str(resolved);
        rest = after_close;
    }
    out.push_str(rest);
    Ok(out)
}

fn lookup_token_ref<'a>(token_ref: &str, base: &'a BaseTokensFile) -> Option<&'a str> {
    let (group, key) = token_ref.split_once('.')?;
    match group {
        "light" => base.light.get(key).map(String::as_str),
        "dark" => base.dark.get(key).map(String::as_str),
        _ => None,
    }
}

fn load_locales(path: &Path) -> Result<Vec<LocaleSpec>, GenError> {
    let doc = parse_toml_file(path)?;
    let file = "contracts/interface/strings/locales.toml".to_owned();
    let rows = req_table_array(&doc, "locale", &file)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let tag = req_str(row, "tag", &file)?;
        out.push(LocaleSpec {
            native_name: opt_str(row, "native_name").unwrap_or_else(|| tag.clone()),
            rust_variant: req_str(row, "rust_variant", &file)?,
            tier: req_str(row, "tier", &file)?,
            script: req_str(row, "script", &file)?,
            direction: req_str(row, "direction", &file)?,
            fallback: opt_str(row, "fallback").unwrap_or_else(|| "en-US".to_owned()),
            aliases: opt_str_array(row, "aliases"),
            tag,
        });
    }
    Ok(out)
}

fn load_messages(dir: &Path) -> Result<Vec<MessageSpec>, GenError> {
    let paths = sorted_mf2_files(dir)?;
    let mut out = Vec::new();
    for path in paths {
        let ns = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".mf2.toml"))
            .unwrap_or("common")
            .to_owned();
        let file = format!("contracts/interface/strings/src/{ns}.mf2.toml");
        let doc = parse_toml_file(&path)?;
        for (id, val) in doc {
            let table = val.as_table().ok_or_else(|| GenError::Validation {
                file: file.clone(),
                detail: format!("entry '{id}' must be a table"),
            })?;
            out.push(MessageSpec {
                id,
                namespace: ns.clone(),
                rust_variant: opt_str(table, "rust_variant"),
                desc: req_str(table, "desc", &file)?,
                max: table.get("max").and_then(TomlValue::as_i64),
                risk: opt_str(table, "risk").unwrap_or_else(|| "normal".to_owned()),
                msg: req_str(table, "msg", &file)?,
            });
        }
    }
    Ok(out)
}

fn load_vocabulary(path: &Path) -> Result<VocabularySpec, GenError> {
    let doc = parse_toml_file(path)?;
    let file = "contracts/interface/vocabulary.toml".to_owned();
    let brand_tbl = req_table(&doc, "brand", &file)?;
    let brand_name = req_str(brand_tbl, "name", &file)?;
    let brand_short_name = req_str(brand_tbl, "short_name", &file)?;

    let term_rows = req_table_array(&doc, "term", &file)?;
    let mut terms = Vec::with_capacity(term_rows.len());
    for row in term_rows {
        terms.push(VocabularyTerm {
            key: req_str(row, "key", &file)?,
            term: req_str(row, "term", &file)?,
            translate: row
                .get("translate")
                .and_then(TomlValue::as_bool)
                .unwrap_or(true),
            desc: req_str(row, "desc", &file)?,
        });
    }

    let forbidden_rows = opt_table_array(&doc, "forbidden");
    let mut forbidden = Vec::with_capacity(forbidden_rows.len());
    for row in forbidden_rows {
        forbidden.push(ForbiddenTerm {
            word: req_str(row, "word", &file)?,
            replacement: req_str(row, "replacement", &file)?,
        });
    }

    Ok(VocabularySpec {
        brand_name,
        brand_short_name,
        terms,
        forbidden,
    })
}

fn load_icons(path: &Path) -> Result<IconCatalogSpec, GenError> {
    let doc = parse_toml_file(path)?;
    let file = "contracts/interface/icons.toml".to_owned();
    let icon_rows = req_table_array(&doc, "icon", &file)?;
    let mut icons = Vec::with_capacity(icon_rows.len());
    for row in icon_rows {
        icons.push(IconSpec {
            key: req_str(row, "key", &file)?,
            lucide: req_str(row, "lucide", &file)?,
            mirror: row
                .get("mirror")
                .and_then(TomlValue::as_bool)
                .unwrap_or(false),
            same_as: opt_str(row, "same_as"),
        });
    }

    let harness_rows = opt_table_array(&doc, "harness_icon");
    let mut harnesses = Vec::with_capacity(harness_rows.len());
    for row in harness_rows {
        harnesses.push(HarnessIconSpec {
            id: req_str(row, "id", &file)?,
            display_name: req_str(row, "display_name", &file)?,
            vendor: opt_str(row, "vendor").unwrap_or_default(),
            kind: opt_str(row, "kind").unwrap_or_else(|| "coding-agent".to_owned()),
            aliases: opt_str_array(row, "aliases"),
            simple_icon: opt_str(row, "simple_icon").unwrap_or_default(),
            lucide: req_str(row, "lucide", &file)?,
            tone: opt_str(row, "tone").unwrap_or_else(|| "primary".to_owned()),
        });
    }

    let os_rows = opt_table_array(&doc, "os_icon");
    let mut operating_systems = Vec::with_capacity(os_rows.len());
    for row in os_rows {
        operating_systems.push(OsIconSpec {
            id: req_str(row, "id", &file)?,
            display_name: req_str(row, "display_name", &file)?,
            aliases: opt_str_array(row, "aliases"),
            simple_icon: opt_str(row, "simple_icon").unwrap_or_default(),
            lucide: req_str(row, "lucide", &file)?,
            tone: opt_str(row, "tone").unwrap_or_else(|| "primary".to_owned()),
        });
    }

    Ok(IconCatalogSpec {
        icons,
        harnesses,
        operating_systems,
    })
}

fn load_presentations(path: &Path) -> Result<Vec<PresentationSpec>, GenError> {
    let doc = parse_toml_file(path)?;
    let file = "contracts/interface/presentation.toml".to_owned();
    let rows = req_table_array(&doc, "entry", &file)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(PresentationSpec {
            enum_name: req_str(row, "enum", &file)?,
            value: req_str(row, "value", &file)?,
            label: req_str(row, "label", &file)?,
            description: opt_str(row, "description"),
            icon: req_str(row, "icon", &file)?,
            tone: req_str(row, "tone", &file)?,
        });
    }
    Ok(out)
}
