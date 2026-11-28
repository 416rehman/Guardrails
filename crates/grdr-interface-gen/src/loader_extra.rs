// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::model::{
    CliCommandSpec, CliExitCodeSpec, CliSpec, GenError, NotificationSpec, RouteSpec, ShortcutSpec,
    TranslationCatalog,
};
use crate::toml_doc::{TomlValue, parse_toml_table};

pub fn ensure_not_symlink(path: &Path, context_file: &str) -> Result<(), GenError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(GenError::Validation {
            file: context_file.to_owned(),
            detail: format!("symlink not allowed at '{}'", path.display()),
        }),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(GenError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub fn load_translations(dir: &Path) -> Result<Vec<TranslationCatalog>, GenError> {
    ensure_not_symlink(dir, "contracts/interface/strings/tr")?;
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut locale_dirs = Vec::new();
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
        ensure_not_symlink(&path, "contracts/interface/strings/tr")?;
        if path.is_dir() {
            locale_dirs.push(path);
        }
    }
    locale_dirs.sort();

    let mut catalogs = Vec::with_capacity(locale_dirs.len());
    for locale_dir in locale_dirs {
        let Some(tag) = locale_dir
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_owned)
        else {
            continue;
        };
        let mut entries_map = BTreeMap::new();
        for mf2_path in sorted_mf2_files(&locale_dir)? {
            let doc = parse_toml_file(&mf2_path)?;
            let rel = format!("contracts/interface/strings/tr/{tag}");
            for (id, val) in doc {
                let tbl = val.as_table().ok_or_else(|| GenError::Validation {
                    file: rel.clone(),
                    detail: format!("entry '{id}' must be a table"),
                })?;
                entries_map.insert(id, req_str(tbl, "msg", &rel)?);
            }
        }
        catalogs.push(TranslationCatalog {
            locale_tag: tag,
            entries: entries_map,
        });
    }
    Ok(catalogs)
}

pub fn sorted_mf2_files(dir: &Path) -> Result<Vec<PathBuf>, GenError> {
    ensure_not_symlink(dir, "contracts/interface/strings")?;
    let mut paths = Vec::new();
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
        ensure_not_symlink(&path, "contracts/interface/strings")?;
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".mf2.toml"))
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

pub fn load_routes(path: &Path) -> Result<Vec<RouteSpec>, GenError> {
    let doc = parse_toml_file(path)?;
    let file = "contracts/interface/routes.toml".to_owned();
    let rows = req_table_array(&doc, "route", &file)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let id = req_str(row, "id", &file)?;
        let default_path = if id == "home" {
            "/".to_owned()
        } else {
            format!("/{}", id.strip_prefix("op-").unwrap_or(&id))
        };
        out.push(RouteSpec {
            id,
            title: req_str(row, "title", &file)?,
            icon: req_str(row, "icon", &file)?,
            area: req_str(row, "area", &file)?,
            scopes: opt_str_array(row, "scopes"),
            requires: req_str(row, "requires", &file)?,
            path: opt_str(row, "path").unwrap_or(default_path),
            shell_nav: row
                .get("shell_nav")
                .and_then(TomlValue::as_bool)
                .unwrap_or(true),
        });
    }
    Ok(out)
}

pub fn load_optional_cli(path: &Path) -> Result<Option<CliSpec>, GenError> {
    if !path.is_file() {
        return Ok(None);
    }
    let doc = parse_toml_file(path)?;
    let file = "contracts/interface/cli.toml".to_owned();
    let schema = req_str(&doc, "schema", &file)?;
    let mut exit_codes = Vec::new();
    for row in opt_table_array(&doc, "exit_code") {
        let code =
            row.get("code")
                .and_then(TomlValue::as_i64)
                .ok_or_else(|| GenError::Validation {
                    file: file.clone(),
                    detail: "missing int field 'code'".to_owned(),
                })?;
        exit_codes.push(CliExitCodeSpec {
            code,
            name: req_str(row, "name", &file)?,
            desc: req_str(row, "desc", &file)?,
        });
    }
    let mut commands = Vec::new();
    for row in opt_table_array(&doc, "command") {
        commands.push(CliCommandSpec {
            name: req_str(row, "name", &file)?,
            kind: req_str(row, "kind", &file)?,
            verbs: opt_str_array(row, "verbs"),
            desc: req_str(row, "desc", &file)?,
            flags: opt_str_array(row, "flags"),
            agent_callable: row
                .get("agent_callable")
                .and_then(TomlValue::as_bool)
                .unwrap_or(false),
        });
    }
    Ok(Some(CliSpec {
        schema,
        exit_codes,
        commands,
    }))
}

pub fn load_optional_shortcuts(path: &Path) -> Result<Vec<ShortcutSpec>, GenError> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let doc = parse_toml_file(path)?;
    let file = "contracts/interface/shortcuts.toml".to_owned();
    let rows = opt_table_array(&doc, "shortcut");
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let keys = req_str(row, "keys", &file)?;
        out.push(ShortcutSpec {
            action: req_str(row, "action", &file)?,
            scope: req_str(row, "scope", &file)?,
            macos_keys: opt_str(row, "macos_keys").unwrap_or_else(|| keys.clone()),
            keys,
            desc: req_str(row, "desc", &file)?,
        });
    }
    Ok(out)
}

pub fn load_optional_notifications(path: &Path) -> Result<Vec<NotificationSpec>, GenError> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let doc = parse_toml_file(path)?;
    let file = "contracts/interface/notifications.toml".to_owned();
    let rows = opt_table_array(&doc, "notification");
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let dedup_window_secs = row
            .get("dedup_window_secs")
            .and_then(TomlValue::as_i64)
            .unwrap_or(0);
        out.push(NotificationSpec {
            class: req_str(row, "class", &file)?,
            channels: opt_str_array(row, "channels"),
            dedup_window_secs,
            quiet_hours: row
                .get("quiet_hours")
                .and_then(TomlValue::as_bool)
                .unwrap_or(false),
            tone: req_str(row, "tone", &file)?,
            icon: req_str(row, "icon", &file)?,
            title_token: req_str(row, "title_token", &file)?,
        });
    }
    Ok(out)
}

pub fn parse_toml_file(path: &Path) -> Result<BTreeMap<String, TomlValue>, GenError> {
    ensure_not_symlink(path, "contracts/interface")?;
    let text = fs::read_to_string(path).map_err(|source| GenError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_toml_table(&text).map_err(|source| GenError::Toml {
        path: path.to_path_buf(),
        source,
    })
}

pub fn req_table<'a>(
    doc: &'a BTreeMap<String, TomlValue>,
    key: &str,
    file: &str,
) -> Result<&'a BTreeMap<String, TomlValue>, GenError> {
    doc.get(key)
        .and_then(TomlValue::as_table)
        .ok_or_else(|| GenError::Validation {
            file: file.to_owned(),
            detail: format!("missing [{key}] table"),
        })
}

pub fn req_table_array<'a>(
    doc: &'a BTreeMap<String, TomlValue>,
    key: &str,
    file: &str,
) -> Result<Vec<&'a BTreeMap<String, TomlValue>>, GenError> {
    doc.get(key)
        .and_then(TomlValue::as_table_array)
        .ok_or_else(|| GenError::Validation {
            file: file.to_owned(),
            detail: format!("missing [[{key}]] entries"),
        })
}

pub fn opt_table_array<'a>(
    doc: &'a BTreeMap<String, TomlValue>,
    key: &str,
) -> Vec<&'a BTreeMap<String, TomlValue>> {
    doc.get(key)
        .and_then(TomlValue::as_table_array)
        .unwrap_or_default()
}

pub fn req_str(
    table: &BTreeMap<String, TomlValue>,
    key: &str,
    file: &str,
) -> Result<String, GenError> {
    table
        .get(key)
        .and_then(TomlValue::as_str)
        .map(str::to_owned)
        .ok_or_else(|| GenError::Validation {
            file: file.to_owned(),
            detail: format!("missing string field '{key}'"),
        })
}

pub fn opt_str(table: &BTreeMap<String, TomlValue>, key: &str) -> Option<String> {
    table
        .get(key)
        .and_then(TomlValue::as_str)
        .map(str::to_owned)
}

pub fn opt_str_array(table: &BTreeMap<String, TomlValue>, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(TomlValue::as_str_array)
        .unwrap_or_default()
}
