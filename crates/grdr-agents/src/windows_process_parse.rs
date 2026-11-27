// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;

use crate::catalogue::AgentCatalogue;

pub const CODE_WIN_SNAPSHOT_PARSE: &str = "GRDR-WIN-0002";

pub const WSL_BRIDGE_IMAGES: &[&str] = &[
    "wsl.exe",
    "wslg.exe",
    "wslhost.exe",
    "wslservice.exe",
    "vmmem",
    "vmmem.exe",
    "vmmemwsl",
    "vmmemwsl.exe",
];

const WSL_COMMAND_HOST_IMAGES: &[&str] = &["wsl.exe", "wslg.exe"];
const WSL_VALUE_FLAGS: &[&str] = &[
    "-d",
    "--distribution",
    "-u",
    "--user",
    "--cd",
    "--shell-type",
];
const WSL_NO_VALUE_FLAGS: &[&str] = &["-e", "--exec", "--", "--raw", "--system", "--no-launch"];
const SHELL_LAUNCHERS: &[&str] = &["sh", "bash", "zsh", "dash", "fish", "ash"];

static EMBEDDED_CATALOGUE_CACHE: OnceLock<Option<AgentCatalogue>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedProcessSpec {
    pub id: String,
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_name: String,
    pub executable_path: Option<String>,
    pub command_line: Option<String>,
    pub session_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "surface", rename_all = "snake_case")]
pub enum AgentExecutionSurface {
    NativeWindows,
    WslBridge {
        distro: Option<String>,
        wsl_pid: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WslInvocation {
    pub distro: Option<String>,
    pub target_command: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CimProcessRecord {
    process_id: Option<u32>,
    parent_process_id: Option<u32>,
    name: Option<String>,
    executable_path: Option<String>,
    command_line: Option<String>,
    session_id: Option<u32>,
}

pub fn is_wsl_bridge_image(entry: &WindowsProcessEntry) -> bool {
    let image = entry.image_name.to_ascii_lowercase();
    if WSL_BRIDGE_IMAGES
        .iter()
        .any(|candidate| image == *candidate)
    {
        return true;
    }
    entry
        .executable_path
        .as_deref()
        .map(|p| executable_basename(p).to_ascii_lowercase())
        .is_some_and(|base| WSL_BRIDGE_IMAGES.iter().any(|candidate| base == *candidate))
}

pub fn parse_wsl_command_invocation(command_line: &str) -> WslInvocation {
    let tokens = tokenize_windows_cmdline(command_line);
    let mut distro = None;
    let mut idx = 0usize;

    if let Some(first) = tokens.first()
        && executable_basename(first)
            .to_ascii_lowercase()
            .starts_with("wsl")
    {
        idx = 1;
    }

    while let Some(tok) = tokens.get(idx) {
        let lower = tok.to_ascii_lowercase();
        if let Some(val) = lower
            .strip_prefix("--distribution=")
            .and_then(|_| tok.split_once('='))
            .map(|(_, v)| v)
        {
            distro = Some(val.to_string());
            idx = idx.saturating_add(1);
            continue;
        }
        if WSL_VALUE_FLAGS.iter().any(|flag| lower == *flag) {
            if matches!(lower.as_str(), "-d" | "--distribution")
                && let Some(val) = tokens.get(idx.saturating_add(1))
            {
                distro = Some(val.clone());
            }
            idx = idx.saturating_add(2);
            continue;
        }
        if lower == "--" {
            idx = idx.saturating_add(1);
            break;
        }
        if WSL_NO_VALUE_FLAGS.iter().any(|flag| lower == *flag) || tok.starts_with('-') {
            idx = idx.saturating_add(1);
            continue;
        }
        break;
    }

    let remaining = tokens.get(idx..).unwrap_or(&[]);
    WslInvocation {
        distro,
        target_command: extract_harness_command_from_tokens(remaining),
    }
}

pub fn parse_cim_process_json(raw: &str) -> Result<Vec<WindowsProcessEntry>, CodedError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let records: Vec<CimProcessRecord> = if trimmed.starts_with('[') {
        serde_json::from_str(trimmed).map_err(|e| {
            CodedError::new(
                CODE_WIN_SNAPSHOT_PARSE,
                format!("Failed parsing Windows CIM process array: {e}"),
                "Verify PowerShell Get-CimInstance Win32_Process JSON schema.",
            )
        })?
    } else {
        let single: CimProcessRecord = serde_json::from_str(trimmed).map_err(|e| {
            CodedError::new(
                CODE_WIN_SNAPSHOT_PARSE,
                format!("Failed parsing Windows CIM process record: {e}"),
                "Verify PowerShell Get-CimInstance Win32_Process JSON schema.",
            )
        })?;
        vec![single]
    };

    Ok(records
        .into_iter()
        .filter_map(|rec| {
            let pid = rec.process_id?;
            let image_name = rec.name.filter(|n| !n.trim().is_empty())?;
            Some(WindowsProcessEntry {
                pid,
                parent_pid: rec.parent_process_id.unwrap_or(0),
                image_name,
                executable_path: rec.executable_path.filter(|s| !s.trim().is_empty()),
                command_line: rec.command_line.filter(|s| !s.trim().is_empty()),
                session_id: rec.session_id,
            })
        })
        .collect())
}

pub fn parse_tasklist_csv(raw: &str) -> Vec<WindowsProcessEntry> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let cols = split_csv_line(trimmed);
        let Some(image_name) = cols.first().map(|s| s.trim().to_string()) else {
            continue;
        };
        if image_name.is_empty() {
            continue;
        }
        let Some(pid) = cols.get(1).and_then(|s| s.trim().parse::<u32>().ok()) else {
            continue;
        };
        let session_id = cols.get(3).and_then(|s| s.trim().parse::<u32>().ok());
        out.push(WindowsProcessEntry {
            pid,
            parent_pid: 0,
            image_name,
            executable_path: None,
            command_line: None,
            session_id,
        });
    }
    out
}

pub fn tokenize_windows_cmdline(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut active_quote: Option<char> = None;
    let mut has_token = false;

    for ch in raw.chars() {
        match active_quote {
            Some(q) if ch == q => {
                active_quote = None;
            }
            Some(_) => {
                current.push(ch);
            }
            None if ch == '"' || ch == '\'' => {
                active_quote = Some(ch);
                has_token = true;
            }
            None if ch.is_whitespace() => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            None => {
                current.push(ch);
                has_token = true;
            }
        }
    }
    if has_token {
        tokens.push(current);
    }
    tokens
}

pub fn executable_basename(raw: &str) -> &str {
    raw.rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(raw)
}

pub fn classify_process_entry(
    entry: &WindowsProcessEntry,
) -> Option<(MatchedProcessSpec, AgentExecutionSurface)> {
    let catalogue = EMBEDDED_CATALOGUE_CACHE
        .get_or_init(|| AgentCatalogue::embedded().ok())
        .as_ref()?;
    classify_process_entry_with_catalogue(entry, catalogue)
}

pub fn classify_process_entry_with_catalogue(
    entry: &WindowsProcessEntry,
    catalogue: &AgentCatalogue,
) -> Option<(MatchedProcessSpec, AgentExecutionSurface)> {
    let image_lower = entry.image_name.to_ascii_lowercase();
    let exe_base_lower = entry
        .executable_path
        .as_deref()
        .map(|p| executable_basename(p).to_ascii_lowercase());

    for agent in catalogue.agents() {
        let matched_native = agent.routes.windows_exes.iter().any(|exe| {
            let lower = exe.to_ascii_lowercase();
            image_lower == lower || exe_base_lower.as_deref() == Some(lower.as_str())
        });
        if matched_native {
            return Some((
                MatchedProcessSpec {
                    id: format!("agent-{}", agent.id),
                    name: agent.name.clone(),
                    kind: agent.id.clone(),
                },
                AgentExecutionSurface::NativeWindows,
            ));
        }
    }

    let is_wsl_cmd_host = WSL_COMMAND_HOST_IMAGES
        .iter()
        .any(|img| image_lower == *img || exe_base_lower.as_deref() == Some(*img));
    if !is_wsl_cmd_host {
        return None;
    }

    let cmdline = entry.command_line.as_deref()?;
    let invocation = parse_wsl_command_invocation(cmdline);
    let target_cmd = invocation.target_command?;
    let target_lower = executable_basename(&target_cmd).to_ascii_lowercase();

    for agent in catalogue.agents() {
        if agent
            .routes
            .wsl_harnesses
            .iter()
            .any(|h| target_lower == h.to_ascii_lowercase())
        {
            return Some((
                MatchedProcessSpec {
                    id: format!("agent-{}", agent.id),
                    name: agent.name.clone(),
                    kind: agent.id.clone(),
                },
                AgentExecutionSurface::WslBridge {
                    distro: invocation.distro,
                    wsl_pid: entry.pid,
                },
            ));
        }
    }
    None
}

fn extract_harness_command_from_tokens(tokens: &[String]) -> Option<String> {
    let mut idx = 0usize;
    while let Some(tok) = tokens.get(idx) {
        let base = executable_basename(tok).to_ascii_lowercase();
        if matches!(base.as_str(), "env" | "sudo" | "nohup") {
            idx = idx.saturating_add(1);
            continue;
        }
        if tok.contains('=') && !tok.starts_with('/') {
            idx = idx.saturating_add(1);
            continue;
        }
        if SHELL_LAUNCHERS.iter().any(|s| base == *s) {
            if let Some(script_arg) = find_shell_command_arg(tokens.get(idx.saturating_add(1)..)) {
                let inner = tokenize_windows_cmdline(script_arg);
                return inner.first().cloned();
            }
            return Some(tok.clone());
        }
        return Some(tok.clone());
    }
    None
}

fn find_shell_command_arg(args: Option<&[String]>) -> Option<&str> {
    let args = args?;
    for (idx, tok) in args.iter().enumerate() {
        if matches!(tok.as_str(), "-c" | "-lc" | "-ic") {
            return args.get(idx.saturating_add(1)).map(String::as_str);
        }
    }
    None
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut cols = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == ',' && !in_quotes {
            cols.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    cols.push(current);
    cols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cim_json_and_tasklist_csv_outputs() {
        let json_arr = r#"[{"ProcessId":412,"ParentProcessId":100,"Name":"claude.exe","ExecutablePath":"D:\\bin\\claude.exe","CommandLine":"claude.exe --print","SessionId":1}]"#;
        let parsed = parse_cim_process_json(json_arr).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].pid, 412);
        assert_eq!(parsed[0].image_name, "claude.exe");

        let single_obj = r#"{"ProcessId":900,"ParentProcessId":1,"Name":"agy.exe","ExecutablePath":null,"CommandLine":null,"SessionId":2}"#;
        let parsed_single = parse_cim_process_json(single_obj).unwrap();
        assert_eq!(parsed_single.len(), 1);
        assert_eq!(parsed_single[0].pid, 900);

        let csv = "\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"\n\"cursor.exe\",\"4242\",\"Console\",\"1\",\"120,000 K\"\n";
        let csv_entries = parse_tasklist_csv(csv);
        assert_eq!(csv_entries.len(), 2);
        assert_eq!(csv_entries[1].image_name, "cursor.exe");
        assert_eq!(csv_entries[1].pid, 4242);
        assert_eq!(csv_entries[1].session_id, Some(1));
    }

    #[test]
    fn parses_wsl_command_invocations_without_false_positives() {
        let inv = parse_wsl_command_invocation("wsl.exe -d Ubuntu-24.04 -- /usr/local/bin/codex");
        assert_eq!(inv.distro.as_deref(), Some("Ubuntu-24.04"));
        assert_eq!(inv.target_command.as_deref(), Some("/usr/local/bin/codex"));

        let nested =
            parse_wsl_command_invocation(r#"wsl.exe --distribution=Debian -- bash -lc "agy run""#);
        assert_eq!(nested.distro.as_deref(), Some("Debian"));
        assert_eq!(nested.target_command.as_deref(), Some("agy"));

        let non_agent = WindowsProcessEntry {
            pid: 55,
            parent_pid: 1,
            image_name: "wsl.exe".into(),
            executable_path: None,
            command_line: Some("wsl.exe -d Ubuntu -- ls -la claude.md".into()),
            session_id: Some(1),
        };
        assert!(classify_process_entry(&non_agent).is_none());
    }
}
