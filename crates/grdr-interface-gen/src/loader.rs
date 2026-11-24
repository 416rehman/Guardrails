use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::model::{
    BaseTokensFile, ExtendedTokensFile, ForbiddenTerm, GenError, IconSpec, InterfaceBundle,
    LocaleSpec, MessageSpec, PresentationSpec, RouteSpec, TokenBundle, VocabularySpec,
    VocabularyTerm,
};
use crate::toml_doc::{TomlValue, parse_toml_table};

/// Loads and validates all single-source specs under `interface/`.
pub fn load_interface_bundle(repo_root: &Path) -> Result<InterfaceBundle, GenError> {
    let iface = repo_root.join("interface");
    let tokens = load_tokens(&iface)?;
    let locales = load_locales(&iface.join("strings").join("locales.toml"))?;
    let messages = load_messages(&iface.join("strings").join("src"))?;
    let vocabulary = load_vocabulary(&iface.join("vocabulary.toml"))?;
    let icons = load_icons(&iface.join("icons.toml"))?;
    let presentations = load_presentations(&iface.join("presentation.toml"))?;
    let routes = load_routes(&iface.join("routes.toml"))?;

    let bundle = InterfaceBundle {
        tokens,
        locales,
        messages,
        vocabulary,
        icons,
        presentations,
        routes,
    };
    validate_bundle(&bundle)?;
    Ok(bundle)
}

fn read_text(path: &Path) -> Result<String, GenError> {
    fs::read_to_string(path).map_err(|source| GenError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_toml_file(path: &Path) -> Result<BTreeMap<String, TomlValue>, GenError> {
    let text = read_text(path)?;
    parse_toml_table(&text).map_err(|source| GenError::Toml {
        path: path.to_path_buf(),
        source,
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
    let file = "interface/strings/locales.toml".to_owned();
    let rows = doc
        .get("locale")
        .and_then(TomlValue::as_table_array)
        .ok_or_else(|| GenError::Validation {
            file: file.clone(),
            detail: "missing [[locale]] entries".to_owned(),
        })?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(LocaleSpec {
            tag: req_str(row, "tag", &file)?,
            rust_variant: req_str(row, "rust_variant", &file)?,
            tier: req_str(row, "tier", &file)?,
            script: req_str(row, "script", &file)?,
            direction: req_str(row, "direction", &file)?,
            aliases: row
                .get("aliases")
                .and_then(TomlValue::as_str_array)
                .unwrap_or_default(),
        });
    }
    Ok(out)
}

fn load_messages(dir: &Path) -> Result<Vec<MessageSpec>, GenError> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let entries = fs::read_dir(dir).map_err(|source| GenError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| GenError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".mf2.toml"))
        {
            paths.push(path);
        }
    }
    paths.sort();

    let mut out = Vec::new();
    for path in paths {
        let ns = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".mf2.toml"))
            .unwrap_or("common")
            .to_owned();
        let file = format!("interface/strings/src/{ns}.mf2.toml");
        let doc = parse_toml_file(&path)?;
        for (id, val) in doc {
            let table = val.as_table().ok_or_else(|| GenError::Validation {
                file: file.clone(),
                detail: format!("entry '{id}' must be a table"),
            })?;
            out.push(MessageSpec {
                id,
                namespace: ns.clone(),
                rust_variant: table
                    .get("rust_variant")
                    .and_then(TomlValue::as_str)
                    .map(str::to_owned),
                desc: req_str(table, "desc", &file)?,
                max: table.get("max").and_then(TomlValue::as_i64),
                risk: table
                    .get("risk")
                    .and_then(TomlValue::as_str)
                    .unwrap_or("normal")
                    .to_owned(),
                msg: req_str(table, "msg", &file)?,
            });
        }
    }
    Ok(out)
}

fn load_vocabulary(path: &Path) -> Result<VocabularySpec, GenError> {
    let doc = parse_toml_file(path)?;
    let file = "interface/vocabulary.toml".to_owned();
    let brand_tbl = doc
        .get("brand")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| GenError::Validation {
            file: file.clone(),
            detail: "missing [brand] table".to_owned(),
        })?;
    let brand_name = req_str(brand_tbl, "name", &file)?;
    let brand_short_name = req_str(brand_tbl, "short_name", &file)?;

    let term_rows = doc
        .get("term")
        .and_then(TomlValue::as_table_array)
        .ok_or_else(|| GenError::Validation {
            file: file.clone(),
            detail: "missing [[term]] entries".to_owned(),
        })?;
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

    let forbidden_rows = doc
        .get("forbidden")
        .and_then(TomlValue::as_table_array)
        .unwrap_or_default();
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

fn load_icons(path: &Path) -> Result<Vec<IconSpec>, GenError> {
    let doc = parse_toml_file(path)?;
    let file = "interface/icons.toml".to_owned();
    let rows = doc
        .get("icon")
        .and_then(TomlValue::as_table_array)
        .ok_or_else(|| GenError::Validation {
            file: file.clone(),
            detail: "missing [[icon]] entries".to_owned(),
        })?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(IconSpec {
            key: req_str(row, "key", &file)?,
            lucide: req_str(row, "lucide", &file)?,
            mirror: row
                .get("mirror")
                .and_then(TomlValue::as_bool)
                .unwrap_or(false),
            same_as: row
                .get("same_as")
                .and_then(TomlValue::as_str)
                .map(str::to_owned),
        });
    }
    Ok(out)
}

fn load_presentations(path: &Path) -> Result<Vec<PresentationSpec>, GenError> {
    let doc = parse_toml_file(path)?;
    let file = "interface/presentation.toml".to_owned();
    let rows = doc
        .get("entry")
        .and_then(TomlValue::as_table_array)
        .ok_or_else(|| GenError::Validation {
            file: file.clone(),
            detail: "missing [[entry]] entries".to_owned(),
        })?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(PresentationSpec {
            enum_name: req_str(row, "enum", &file)?,
            value: req_str(row, "value", &file)?,
            label: req_str(row, "label", &file)?,
            description: row
                .get("description")
                .and_then(TomlValue::as_str)
                .map(str::to_owned),
            icon: req_str(row, "icon", &file)?,
            tone: req_str(row, "tone", &file)?,
        });
    }
    Ok(out)
}

fn load_routes(path: &Path) -> Result<Vec<RouteSpec>, GenError> {
    let doc = parse_toml_file(path)?;
    let file = "interface/routes.toml".to_owned();
    let rows = doc
        .get("route")
        .and_then(TomlValue::as_table_array)
        .ok_or_else(|| GenError::Validation {
            file: file.clone(),
            detail: "missing [[route]] entries".to_owned(),
        })?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(RouteSpec {
            id: req_str(row, "id", &file)?,
            title: req_str(row, "title", &file)?,
            icon: req_str(row, "icon", &file)?,
            area: req_str(row, "area", &file)?,
            scopes: row
                .get("scopes")
                .and_then(TomlValue::as_str_array)
                .unwrap_or_default(),
            requires: req_str(row, "requires", &file)?,
        });
    }
    Ok(out)
}

fn req_str(table: &BTreeMap<String, TomlValue>, key: &str, file: &str) -> Result<String, GenError> {
    table
        .get(key)
        .and_then(TomlValue::as_str)
        .map(str::to_owned)
        .ok_or_else(|| GenError::Validation {
            file: file.to_owned(),
            detail: format!("missing string field '{key}'"),
        })
}

fn validate_bundle(bundle: &InterfaceBundle) -> Result<(), GenError> {
    let icon_keys: BTreeSet<&str> = bundle.icons.iter().map(|i| i.key.as_str()).collect();
    let msg_keys: BTreeSet<&str> = bundle.messages.iter().map(|m| m.id.as_str()).collect();

    for icon in &bundle.icons {
        if let Some(same_as) = &icon.same_as
            && !icon_keys.contains(same_as.as_str())
        {
            return Err(GenError::Validation {
                file: "interface/icons.toml".to_owned(),
                detail: format!("icon '{}' references missing same_as '{same_as}'", icon.key),
            });
        }
    }

    for entry in &bundle.presentations {
        if !icon_keys.contains(entry.icon.as_str()) {
            return Err(GenError::Validation {
                file: "interface/presentation.toml".to_owned(),
                detail: format!(
                    "entry '{}::{}' references missing icon '{}'",
                    entry.enum_name, entry.value, entry.icon
                ),
            });
        }
        if !msg_keys.contains(entry.label.as_str()) {
            return Err(GenError::Validation {
                file: "interface/presentation.toml".to_owned(),
                detail: format!(
                    "entry '{}::{}' references missing label token '{}'",
                    entry.enum_name, entry.value, entry.label
                ),
            });
        }
        if let Some(desc_key) = &entry.description
            && !msg_keys.contains(desc_key.as_str())
        {
            return Err(GenError::Validation {
                file: "interface/presentation.toml".to_owned(),
                detail: format!(
                    "entry '{}::{}' references missing description token '{}'",
                    entry.enum_name, entry.value, desc_key
                ),
            });
        }
    }

    for route in &bundle.routes {
        if !icon_keys.contains(route.icon.as_str()) {
            return Err(GenError::Validation {
                file: "interface/routes.toml".to_owned(),
                detail: format!(
                    "route '{}' references missing icon '{}'",
                    route.id, route.icon
                ),
            });
        }
        if !msg_keys.contains(route.title.as_str()) {
            return Err(GenError::Validation {
                file: "interface/routes.toml".to_owned(),
                detail: format!(
                    "route '{}' references missing title token '{}'",
                    route.id, route.title
                ),
            });
        }
    }

    for msg in &bundle.messages {
        for bad in &bundle.vocabulary.forbidden {
            if contains_word_ci(&msg.msg, &bad.word) {
                return Err(GenError::Validation {
                    file: format!("interface/strings/src/{}.mf2.toml", msg.namespace),
                    detail: format!(
                        "token '{}' uses forbidden term '{}' (use '{}' instead)",
                        msg.id, bad.word, bad.replacement
                    ),
                });
            }
        }
    }

    Ok(())
}

fn contains_word_ci(haystack: &str, needle: &str) -> bool {
    let lower_hay = haystack.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    lower_hay
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|tok| tok == lower_needle)
}
