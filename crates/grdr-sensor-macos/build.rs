// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct RawAgent {
    id: String,
    aliases: Vec<String>,
    binaries: Vec<String>,
    cmdline_markers: Vec<String>,
    signing_ids: Vec<String>,
    native_sandbox: &'static str,
    delegation_mode: &'static str,
    model_hosts: Vec<String>,
    state_dirs: Vec<String>,
    config_paths: Vec<String>,
    admin_config_path_macos: Option<String>,
    transcript_dirs: Vec<String>,
}

#[derive(Clone, Copy)]
struct SandboxOverride {
    native_sandbox: &'static str,
    delegation_mode: &'static str,
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or("cannot locate workspace root from CARGO_MANIFEST_DIR")?;

    let catalogue_path = repo_root.join("packs/catalogue/catalogue.yaml");
    let overrides_path = manifest_dir.join("data/macos_sandbox_overrides.toml");
    let brand_path = repo_root.join("contracts/interface/brand/brand.toml");

    println!("cargo:rerun-if-changed={}", catalogue_path.display());
    println!("cargo:rerun-if-changed={}", overrides_path.display());
    println!("cargo:rerun-if-changed={}", brand_path.display());

    let catalogue_raw = fs::read_to_string(&catalogue_path)?;
    let overrides_raw = fs::read_to_string(&overrides_path)?;
    let brand_raw = fs::read_to_string(&brand_path)?;

    let overrides = parse_sandbox_overrides(&overrides_raw)?;
    let mut agents = parse_catalogue_yaml(&catalogue_raw)?;
    if agents.is_empty() {
        return Err("packs/catalogue/catalogue.yaml produced zero agents".into());
    }

    for (agent_id, ov) in &overrides {
        let Some(entry) = agents.iter_mut().find(|a| &a.id == agent_id) else {
            return Err(format!("override references unknown catalogue agent `{agent_id}`").into());
        };
        entry.native_sandbox = ov.native_sandbox;
        entry.delegation_mode = ov.delegation_mode;
    }

    let generated_cat = render_catalogue_rs(&agents);
    fs::write(out_dir.join("generated_catalogue.rs"), generated_cat)?;

    let generated_brand = render_brand_rs(&brand_raw)?;
    fs::write(out_dir.join("generated_brand.rs"), generated_brand)?;

    Ok(())
}

fn parse_sandbox_overrides(raw: &str) -> Result<BTreeMap<String, SandboxOverride>, Box<dyn Error>> {
    let mut map: BTreeMap<String, (Option<&'static str>, Option<&'static str>)> = BTreeMap::new();
    let mut current_agent: Option<String> = None;

    for raw_line in raw.lines() {
        let line = strip_comment_quote_aware(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(sec) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let clean_sec = sec.trim();
            let id = clean_sec
                .strip_prefix("agent.")
                .ok_or_else(|| format!("unexpected section `[{clean_sec}]` in overrides"))?;
            current_agent = Some(id.trim().to_string());
            map.entry(id.trim().to_string()).or_insert((None, None));
            continue;
        }
        let Some(agent_id) = current_agent.as_ref() else {
            return Err("assignment outside [agent.<id>] section in overrides".into());
        };
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid assignment `{line}` in overrides"))?;
        let key = k.trim();
        let val = unquote_scalar(v.trim());
        let entry = map
            .get_mut(agent_id)
            .ok_or("missing agent map entry during override parse")?;
        match key {
            "native_sandbox" => {
                entry.0 = Some(match val.as_str() {
                    "seatbelt" => "Seatbelt",
                    "none" => "None",
                    other => return Err(format!("invalid native_sandbox `{other}`").into()),
                });
            }
            "delegation_mode" => {
                entry.1 = Some(match val.as_str() {
                    "delegate" => "Delegate",
                    "wrap_tools" => "WrapTools",
                    "wrap_agent" => "WrapAgent",
                    other => return Err(format!("invalid delegation_mode `{other}`").into()),
                });
            }
            other => return Err(format!("unknown override key `{other}`").into()),
        }
    }

    let mut resolved = BTreeMap::new();
    for (id, (sb, mode)) in map {
        resolved.insert(
            id,
            SandboxOverride {
                native_sandbox: sb.unwrap_or("None"),
                delegation_mode: mode.unwrap_or("WrapAgent"),
            },
        );
    }
    Ok(resolved)
}

fn parse_catalogue_yaml(raw: &str) -> Result<Vec<RawAgent>, Box<dyn Error>> {
    let mut agents = Vec::new();
    let mut current: Option<RawAgent> = None;
    let mut in_routes = false;
    let mut in_artifacts = false;
    let mut in_admin_paths = false;
    let mut in_hook = false;
    let mut in_mdm_ids = false;

    for raw_line in raw.lines() {
        let stripped = strip_comment_quote_aware(raw_line);
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = raw_line.len().saturating_sub(raw_line.trim_start().len());

        if let Some(after_dash) = trimmed.strip_prefix("- id:").filter(|_| indent <= 4) {
            if let Some(done) = current.take() {
                agents.push(done);
            }
            let id = unquote_scalar(after_dash.trim());
            current = Some(RawAgent {
                id,
                native_sandbox: "None",
                delegation_mode: "WrapAgent",
                ..Default::default()
            });
            in_routes = false;
            in_artifacts = false;
            in_admin_paths = false;
            in_hook = false;
            in_mdm_ids = false;
            continue;
        }

        let Some(agent) = current.as_mut() else {
            continue;
        };

        if indent <= 4 {
            in_routes = trimmed == "routes:";
            in_hook = trimmed == "hook:";
            in_artifacts = false;
            in_admin_paths = false;
            in_mdm_ids = false;
            if let Some((k, v)) = trimmed.split_once(':')
                && k.trim() == "aliases"
            {
                agent.aliases = parse_inline_yaml_list(v.trim())?;
            }
            continue;
        }

        if in_routes {
            if indent <= 6 {
                in_artifacts = trimmed == "artifacts:";
                in_admin_paths = trimmed == "admin_config_paths:";
                if let Some((k, v)) = trimmed.split_once(':') {
                    match k.trim() {
                        "binaries" => agent.binaries = parse_inline_yaml_list(v.trim())?,
                        "cmdline_markers" => {
                            agent.cmdline_markers = parse_inline_yaml_list(v.trim())?;
                        }
                        "state_dirs" => agent.state_dirs = parse_inline_yaml_list(v.trim())?,
                        "config_paths" => agent.config_paths = parse_inline_yaml_list(v.trim())?,
                        "net" => agent.model_hosts = parse_inline_yaml_list(v.trim())?,
                        _ => {}
                    }
                }
            } else if in_admin_paths
                && let Some((k, v)) = trimmed.split_once(':')
                && k.trim() == "macos"
            {
                let path = unquote_scalar(v.trim());
                if !path.is_empty() {
                    agent.admin_config_path_macos = Some(path);
                }
            } else if in_artifacts
                && let Some((k, v)) = trimmed.split_once(':')
                && k.trim() == "transcripts"
            {
                agent.transcript_dirs = parse_inline_yaml_list(v.trim())?;
            }
        } else if in_hook {
            if indent <= 6 {
                in_mdm_ids = trimmed == "mdm_ids:";
            } else if in_mdm_ids
                && let Some((k, v)) = trimmed.split_once(':')
                && k.trim() == "plist_domain"
            {
                let domain = unquote_scalar(v.trim());
                if !domain.is_empty() && !agent.signing_ids.contains(&domain) {
                    agent.signing_ids.push(domain);
                }
            }
        }
    }

    if let Some(last) = current.take() {
        agents.push(last);
    }
    Ok(agents)
}

fn parse_inline_yaml_list(raw: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let trimmed = raw.trim();
    if trimmed == "[]" {
        return Ok(Vec::new());
    }
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("expected inline YAML list `[...]` got `{trimmed}`"))?;
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for ch in inner.chars() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
                cur.push(ch);
            }
            '"' if !in_single => {
                in_double = !in_double;
                cur.push(ch);
            }
            ',' if !in_single && !in_double => {
                let item = unquote_scalar(cur.trim());
                if !item.is_empty() {
                    out.push(item);
                }
                cur.clear();
            }
            other => cur.push(other),
        }
    }
    let tail = unquote_scalar(cur.trim());
    if !tail.is_empty() {
        out.push(tail);
    }
    Ok(out)
}

fn render_catalogue_rs(agents: &[RawAgent]) -> String {
    let mut out = String::new();
    out.push_str("pub(crate) struct StaticHarnessSpec {\n");
    out.push_str("    pub(crate) id: &'static str,\n");
    out.push_str("    pub(crate) aliases: &'static [&'static str],\n");
    out.push_str("    pub(crate) binaries: &'static [&'static str],\n");
    out.push_str("    pub(crate) cmdline_markers: &'static [&'static str],\n");
    out.push_str("    pub(crate) signing_ids: &'static [&'static str],\n");
    out.push_str("    pub(crate) native_sandbox: NativeSandboxKind,\n");
    out.push_str("    pub(crate) delegation_mode: DelegationPolicy,\n");
    out.push_str("    pub(crate) model_hosts: &'static [&'static str],\n");
    out.push_str("    pub(crate) state_dirs: &'static [&'static str],\n");
    out.push_str("    pub(crate) config_paths: &'static [&'static str],\n");
    out.push_str("    pub(crate) admin_config_path_macos: Option<&'static str>,\n");
    out.push_str("    pub(crate) transcript_dirs: &'static [&'static str],\n");
    out.push_str("}\n\n");
    out.push_str("pub(crate) const EMBEDDED_HARNESSES: &[StaticHarnessSpec] = &[\n");

    for a in agents {
        out.push_str("    StaticHarnessSpec {\n");
        let _ = writeln!(out, "        id: {:?},", a.id);
        let _ = writeln!(out, "        aliases: {},", render_str_slice(&a.aliases));
        let _ = writeln!(out, "        binaries: {},", render_str_slice(&a.binaries));
        let _ = writeln!(
            out,
            "        cmdline_markers: {},",
            render_str_slice(&a.cmdline_markers)
        );
        let _ = writeln!(
            out,
            "        signing_ids: {},",
            render_str_slice(&a.signing_ids)
        );
        let _ = writeln!(
            out,
            "        native_sandbox: NativeSandboxKind::{},",
            a.native_sandbox
        );
        let _ = writeln!(
            out,
            "        delegation_mode: DelegationPolicy::{},",
            a.delegation_mode
        );
        let _ = writeln!(
            out,
            "        model_hosts: {},",
            render_str_slice(&a.model_hosts)
        );
        let _ = writeln!(
            out,
            "        state_dirs: {},",
            render_str_slice(&a.state_dirs)
        );
        let _ = writeln!(
            out,
            "        config_paths: {},",
            render_str_slice(&a.config_paths)
        );
        match &a.admin_config_path_macos {
            Some(p) => {
                let _ = writeln!(out, "        admin_config_path_macos: Some({p:?}),");
            }
            None => {
                out.push_str("        admin_config_path_macos: None,\n");
            }
        }
        let _ = writeln!(
            out,
            "        transcript_dirs: {},",
            render_str_slice(&a.transcript_dirs)
        );
        out.push_str("    },\n");
    }
    out.push_str("];\n");
    out
}

fn render_str_slice(items: &[String]) -> String {
    let mut s = String::from("&[");
    for (idx, item) in items.iter().enumerate() {
        if idx > 0 {
            s.push_str(", ");
        }
        let _ = write!(s, "{item:?}");
    }
    s.push(']');
    s
}

fn render_brand_rs(raw: &str) -> Result<String, Box<dyn Error>> {
    let mut section = String::new();
    let mut vals: BTreeMap<(String, String), String> = BTreeMap::new();
    for raw_line in raw.lines() {
        let stripped = strip_comment_quote_aware(raw_line).trim();
        if stripped.is_empty() {
            continue;
        }
        if let Some(sec) = stripped.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = sec.trim().to_string();
            continue;
        }
        if let Some((k, v)) = stripped.split_once('=') {
            vals.insert(
                (section.clone(), k.trim().to_string()),
                unquote_scalar(v.trim()),
            );
        }
    }

    let req = |sec: &str, key: &str| -> Result<String, Box<dyn Error>> {
        vals.get(&(sec.to_string(), key.to_string()))
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or_else(|| format!("brand.toml missing required {sec}.{key}").into())
    };

    let app_bundle_name = req("os_identity", "app_bundle_name")?;
    let macos_bundle_id = req("os_identity", "macos_bundle_id")?;
    let macos_daemon_label = req("os_identity", "macos_daemon_label")?;
    let macos_netext_bundle_id = req("os_identity", "macos_netext_bundle_id")?;
    let macos_esext_bundle_id = req("os_identity", "macos_esext_bundle_id")?;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "pub(crate) const BRAND_APP_BUNDLE_NAME: &str = {app_bundle_name:?};"
    );
    let _ = writeln!(
        out,
        "pub(crate) const BRAND_MACOS_BUNDLE_ID: &str = {macos_bundle_id:?};"
    );
    let _ = writeln!(
        out,
        "pub(crate) const BRAND_MACOS_DAEMON_LABEL: &str = {macos_daemon_label:?};"
    );
    let _ = writeln!(
        out,
        "pub(crate) const BRAND_MACOS_NETEXT_BUNDLE_ID: &str = {macos_netext_bundle_id:?};"
    );
    let _ = writeln!(
        out,
        "pub(crate) const BRAND_MACOS_ESEXT_BUNDLE_ID: &str = {macos_esext_bundle_id:?};"
    );
    Ok(out)
}

fn strip_comment_quote_aware(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return line.get(..idx).unwrap_or(line),
            _ => {}
        }
    }
    line
}

fn unquote_scalar(raw: &str) -> String {
    if let Some(inner) = raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return inner.to_string();
    }
    if let Some(inner) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return inner.replace("\\\"", "\"").replace("\\\\", "\\");
    }
    raw.to_string()
}
