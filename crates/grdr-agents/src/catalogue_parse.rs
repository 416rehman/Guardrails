// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! YAML map parsing and manifest path/schema validation for `catalogue.rs`.

use std::collections::BTreeMap;
use std::path::Path;

use grdr_core::detect::yaml::YamlValue;
use grdr_model::CodedError;
use grdr_ports::LocalFsPort;

use crate::catalogue::{
    AdminConfigPaths, AgentArtifactRoutes, AgentFlagMode, AgentManifest, AgentRoutes,
    HookEntryStyle, HookSpec, MdmIds, TimeoutUnit,
};
use crate::fs_safe;

const MAX_MANIFEST_BYTES: u64 = 1_048_576;

pub(crate) fn cat_err(code: &str, msg: impl Into<String>) -> CodedError {
    CodedError::new(
        code,
        msg,
        "Verify P14 YAML manifest syntax and required fields in packs/catalogue or packs/building-blocks.",
    )
}

pub(crate) fn read_bounded_regular_yaml(
    path: &Path,
    fs: &dyn LocalFsPort,
) -> Result<String, CodedError> {
    fs.read_bounded_regular_string(path, MAX_MANIFEST_BYTES)
        .map_err(|e| cat_err("GRDR-AGENTS-0004", e))
}

pub(crate) fn validate_slug_id(id: &str, code: &'static str) -> Result<(), CodedError> {
    let valid_chars = id
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'));
    let valid_edge = !id.starts_with('-') && !id.ends_with('-');
    if id.is_empty() || id.len() > 128 || !valid_chars || !valid_edge {
        return Err(cat_err(
            code,
            format!("invalid manifest id `{id}`; expected [a-z0-9-]"),
        ));
    }
    Ok(())
}

pub(crate) fn req_str(
    map: &BTreeMap<String, YamlValue>,
    key: &str,
    code: &'static str,
) -> Result<String, CodedError> {
    map.get(key)
        .and_then(YamlValue::as_str)
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| cat_err(code, format!("missing required string field `{key}`")))
}

pub(crate) fn opt_str(map: &BTreeMap<String, YamlValue>, key: &str) -> String {
    map.get(key)
        .and_then(YamlValue::as_str)
        .unwrap_or("")
        .to_owned()
}

pub(crate) fn opt_clean_str(
    map: &BTreeMap<String, YamlValue>,
    key: &str,
    code: &'static str,
) -> Result<Option<String>, CodedError> {
    let Some(val) = map.get(key) else {
        return Ok(None);
    };
    let text = val
        .as_str()
        .ok_or_else(|| cat_err(code, format!("field `{key}` must be a string")))?;
    if text.chars().any(char::is_control) {
        return Err(cat_err(
            code,
            format!("field `{key}` contains control character"),
        ));
    }
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(text.to_owned()))
    }
}

pub(crate) fn opt_bool(
    map: &BTreeMap<String, YamlValue>,
    key: &str,
    default: bool,
    code: &'static str,
) -> Result<bool, CodedError> {
    match map.get(key) {
        None => Ok(default),
        Some(val) => val
            .as_bool()
            .ok_or_else(|| cat_err(code, format!("field `{key}` must be a boolean"))),
    }
}

pub(crate) fn str_list(map: &BTreeMap<String, YamlValue>, key: &str) -> Vec<String> {
    map.get(key)
        .and_then(YamlValue::as_seq)
        .map(|seq| {
            seq.iter()
                .filter_map(YamlValue::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn clean_str_list(
    map: &BTreeMap<String, YamlValue>,
    key: &str,
    code: &'static str,
) -> Result<Vec<String>, CodedError> {
    let Some(val) = map.get(key) else {
        return Ok(Vec::new());
    };
    let seq = val
        .as_seq()
        .ok_or_else(|| cat_err(code, format!("field `{key}` must be a YAML sequence")))?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let s = item
            .as_str()
            .ok_or_else(|| cat_err(code, format!("sequence `{key}` must contain strings")))?;
        if s.is_empty() || s.chars().any(char::is_control) {
            return Err(cat_err(
                code,
                format!("sequence `{key}` contains empty or control-char item"),
            ));
        }
        out.push(s.to_owned());
    }
    Ok(out)
}

fn validate_rel_list(
    paths: &[String],
    allow_ws: bool,
    allow_appdata: bool,
) -> Result<(), CodedError> {
    for rel in paths {
        fs_safe::validate_safe_rel_path(rel, allow_ws, allow_appdata, false)
            .map_err(|e| cat_err("GRDR-AGENTS-0004", e))?;
    }
    Ok(())
}

fn validate_admin_path(opt: &Option<String>) -> Result<(), CodedError> {
    if let Some(p) = opt
        && (p.chars().any(char::is_control) || p.contains(".."))
    {
        return Err(cat_err("GRDR-AGENTS-0004", "unsafe admin config path"));
    }
    Ok(())
}

pub(crate) fn parse_agent_map(
    m: &BTreeMap<String, YamlValue>,
) -> Result<AgentManifest, CodedError> {
    let id = req_str(m, "id", "GRDR-AGENTS-0004")?;
    validate_slug_id(&id, "GRDR-AGENTS-0004")?;

    let routes_map = m
        .get("routes")
        .and_then(YamlValue::as_map)
        .ok_or_else(|| cat_err("GRDR-AGENTS-0004", "missing routes map"))?;
    let hook_map = m
        .get("hook")
        .and_then(YamlValue::as_map)
        .ok_or_else(|| cat_err("GRDR-AGENTS-0004", "missing hook map"))?;
    let admin_map = routes_map
        .get("admin_config_paths")
        .and_then(YamlValue::as_map);
    let art_map = routes_map.get("artifacts").and_then(YamlValue::as_map);
    let mdm_map = hook_map.get("mdm_ids").and_then(YamlValue::as_map);

    let entry_style = match opt_str(hook_map, "entry_style").as_str() {
        "matcher-hooks" => HookEntryStyle::MatcherHooks,
        "command-item" => HookEntryStyle::CommandItem,
        "toml-hook" => HookEntryStyle::TomlHook,
        "none" | "" => HookEntryStyle::None,
        other => {
            return Err(cat_err(
                "GRDR-AGENTS-0004",
                format!("unknown hook.entry_style `{other}` in `{id}`"),
            ));
        }
    };

    let supported = opt_bool(hook_map, "supported", false, "GRDR-AGENTS-0004")?;
    let config_rel = opt_str(hook_map, "config_rel");
    fs_safe::validate_safe_rel_path(&config_rel, false, false, !supported)
        .map_err(|e| cat_err("GRDR-AGENTS-0004", format!("in agent `{id}`: {e}")))?;

    let timeout_ms = match hook_map.get("timeout_ms") {
        None => 250,
        Some(v) => v
            .as_i64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0 && *n <= 60_000)
            .ok_or_else(|| cat_err("GRDR-AGENTS-0004", "invalid hook.timeout_ms"))?,
    };
    let version_field = match hook_map.get("version_field") {
        None => None,
        Some(v) => Some(
            v.as_i64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n > 0)
                .ok_or_else(|| cat_err("GRDR-AGENTS-0004", "invalid hook.version_field"))?,
        ),
    };

    let routes = parse_routes_map(routes_map, admin_map, art_map)?;
    let plist_domain = mdm_map
        .map(|a| opt_clean_str(a, "plist_domain", "GRDR-AGENTS-0004"))
        .transpose()?
        .flatten();
    let registry_subkey = mdm_map
        .map(|a| opt_clean_str(a, "registry_subkey", "GRDR-AGENTS-0004"))
        .transpose()?
        .flatten();
    if let Some(sub) = &registry_subkey
        && (sub.contains('[') || sub.contains(']') || sub.contains(".."))
    {
        return Err(cat_err("GRDR-AGENTS-0004", "unsafe registry_subkey"));
    }

    let timeout_unit = if opt_bool(hook_map, "timeout_unit_secs", false, "GRDR-AGENTS-0004")? {
        TimeoutUnit::Seconds
    } else {
        TimeoutUnit::Milliseconds
    };
    let agent_flag = if opt_bool(hook_map, "append_agent_flag", true, "GRDR-AGENTS-0004")? {
        AgentFlagMode::Append
    } else {
        AgentFlagMode::Omit
    };

    Ok(AgentManifest {
        id,
        aliases: str_list(m, "aliases"),
        name: req_str(m, "name", "GRDR-AGENTS-0004")?,
        vendor: opt_str(m, "vendor"),
        kind: opt_str(m, "kind"),
        catalogue_tier: opt_str(m, "catalogue_tier"),
        surfaces: str_list(m, "surfaces"),
        declared_action_classes: str_list(m, "declared_action_classes"),
        containment_default: opt_str(m, "containment_default"),
        adapter: opt_str(m, "adapter"),
        routes,
        hook: HookSpec {
            supported,
            dialect: opt_clean_str(hook_map, "dialect", "GRDR-AGENTS-0004")?.unwrap_or_default(),
            config_rel,
            config_format: opt_str(hook_map, "config_format"),
            root_key: opt_clean_str(hook_map, "root_key", "GRDR-AGENTS-0004")?.unwrap_or_default(),
            version_field,
            entry_style,
            matcher: opt_clean_str(hook_map, "matcher", "GRDR-AGENTS-0004")?,
            entry_name: opt_clean_str(hook_map, "entry_name", "GRDR-AGENTS-0004")?,
            events: clean_str_list(hook_map, "events", "GRDR-AGENTS-0004")?,
            all_events: clean_str_list(hook_map, "all_events", "GRDR-AGENTS-0004")?,
            payload_session_keys: clean_str_list(
                hook_map,
                "payload_session_keys",
                "GRDR-AGENTS-0004",
            )?,
            timeout_ms,
            timeout_unit,
            agent_flag,
            fail_mode: opt_str(hook_map, "fail_mode"),
            mdm_ids: MdmIds {
                plist_domain,
                registry_subkey,
            },
        },
    })
}

fn parse_routes_map(
    routes_map: &BTreeMap<String, YamlValue>,
    admin_map: Option<&BTreeMap<String, YamlValue>>,
    art_map: Option<&BTreeMap<String, YamlValue>>,
) -> Result<AgentRoutes, CodedError> {
    let state_dirs = str_list(routes_map, "state_dirs");
    let config_paths = str_list(routes_map, "config_paths");
    let mcp_config_paths = str_list(routes_map, "mcp_config_paths");
    validate_rel_list(&state_dirs, false, false)?;
    validate_rel_list(&config_paths, true, false)?;
    validate_rel_list(&mcp_config_paths, true, true)?;

    let artifacts = AgentArtifactRoutes {
        skills: art_map.map(|a| str_list(a, "skills")).unwrap_or_default(),
        plugins: art_map.map(|a| str_list(a, "plugins")).unwrap_or_default(),
        rules: art_map.map(|a| str_list(a, "rules")).unwrap_or_default(),
        commands: art_map.map(|a| str_list(a, "commands")).unwrap_or_default(),
        subagents: art_map
            .map(|a| str_list(a, "subagents"))
            .unwrap_or_default(),
        transcripts: art_map
            .map(|a| str_list(a, "transcripts"))
            .unwrap_or_default(),
    };
    validate_rel_list(&artifacts.skills, true, false)?;
    validate_rel_list(&artifacts.plugins, true, false)?;
    validate_rel_list(&artifacts.rules, true, false)?;
    validate_rel_list(&artifacts.commands, true, false)?;
    validate_rel_list(&artifacts.subagents, true, false)?;
    validate_rel_list(&artifacts.transcripts, true, false)?;

    let admin_config_paths = AdminConfigPaths {
        macos: admin_map
            .map(|a| opt_clean_str(a, "macos", "GRDR-AGENTS-0004"))
            .transpose()?
            .flatten(),
        linux: admin_map
            .map(|a| opt_clean_str(a, "linux", "GRDR-AGENTS-0004"))
            .transpose()?
            .flatten(),
        windows: admin_map
            .map(|a| opt_clean_str(a, "windows", "GRDR-AGENTS-0004"))
            .transpose()?
            .flatten(),
    };
    validate_admin_path(&admin_config_paths.macos)?;
    validate_admin_path(&admin_config_paths.linux)?;
    validate_admin_path(&admin_config_paths.windows)?;

    Ok(AgentRoutes {
        binaries: str_list(routes_map, "binaries"),
        windows_exes: str_list(routes_map, "windows_exes"),
        wsl_harnesses: str_list(routes_map, "wsl_harnesses"),
        cmdline_markers: str_list(routes_map, "cmdline_markers"),
        npm: str_list(routes_map, "npm"),
        pypi: str_list(routes_map, "pypi"),
        vscode_extensions: str_list(routes_map, "vscode_extensions"),
        state_dirs,
        config_paths,
        admin_config_paths,
        mcp_config_paths,
        mcp_config_key: opt_str(routes_map, "mcp_config_key"),
        env_markers: str_list(routes_map, "env_markers"),
        net: str_list(routes_map, "net"),
        artifacts,
        autonomy_flags: str_list(routes_map, "autonomy_flags"),
    })
}
