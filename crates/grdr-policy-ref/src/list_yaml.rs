// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Zero-dependency YAML list loader for `grdr-policy-ref` signal parity (`P14`).

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::Path;
use std::sync::OnceLock;

const EMBEDDED_LIMITS_TOML: &str = include_str!("../../../contracts/limits.toml");
const EMBEDDED_SIGNAL_PATTERNS_YAML: &str =
    include_str!("../../../packs/lists/signal-patterns.yaml");
const EMBEDDED_ESSENTIALS_YAML: &str =
    include_str!("../../../packs/essentials/lists/protected-paths.yaml");
const EMBEDDED_AGENTS_YAML: &str =
    include_str!("../../../packs/agents/lists/agent-control-files.yaml");
const EMBEDDED_DESTRUCTIVE_YAML: &str =
    include_str!("../../../packs/destructive/lists/destructive-patterns.yaml");
const EMBEDDED_EGRESS_YAML: &str =
    include_str!("../../../packs/egress/lists/egress-destinations.yaml");
const EMBEDDED_SECRETS_YAML: &str = include_str!("../../../packs/secrets/lists/secret-paths.yaml");
const POLICY_LISTS_FORMAT: &str = "grdr.policy-lists.v1";
const MAX_PATTERNS_PER_LIST: usize = 2_048;

#[derive(Debug, Clone)]
pub struct RefSignalLists {
    pub(crate) opaque_command_patterns: Vec<String>,
    pub(crate) agent_control_risk_patterns: Vec<String>,
    pub(crate) credential_risk_patterns: Vec<String>,
    pub(crate) hook_bypass_risk_patterns: Vec<String>,
    pub(crate) destructive_risk_patterns: Vec<String>,
    pub(crate) privilege_escalation_patterns: Vec<String>,
    pub(crate) external_network_risk_patterns: Vec<String>,
}

impl RefSignalLists {
    pub fn from_yaml_sources(
        sig_yaml: &str,
        ess_yaml: &str,
        agt_yaml: &str,
        dest_yaml: &str,
        eg_yaml: &str,
        sec_yaml: &str,
    ) -> Result<Self, String> {
        let sig = parse_policy_lists(sig_yaml)?;
        let ess = parse_policy_lists(ess_yaml)?;
        let agt = parse_policy_lists(agt_yaml)?;
        let dest = parse_policy_lists(dest_yaml)?;
        let eg = parse_policy_lists(eg_yaml)?;
        let sec = parse_policy_lists(sec_yaml)?;

        let mut agent_control = extract(&sig, "agent_control_risk_patterns");
        extend_unique(&mut agent_control, extract(&agt, "protected_control_paths"));

        let mut credential = extract(&sig, "credential_risk_patterns");
        extend_unique(&mut credential, extract(&sec, "credential_stores"));

        let mut hook_bypass = extract(&sig, "hook_bypass_risk_patterns");
        extend_unique(&mut hook_bypass, extract(&ess, "bypass_flags"));

        let mut destructive = extract(&sig, "destructive_risk_patterns");
        extend_unique(&mut destructive, extract(&dest, "destructive_commands"));

        let mut external_network = extract(&sig, "external_network_risk_patterns");
        extend_unique(
            &mut external_network,
            extract(&eg, "monitored_upload_hosts"),
        );

        Ok(Self {
            opaque_command_patterns: extract(&sig, "opaque_command_patterns"),
            agent_control_risk_patterns: agent_control,
            credential_risk_patterns: credential,
            hook_bypass_risk_patterns: hook_bypass,
            destructive_risk_patterns: destructive,
            privilege_escalation_patterns: extract(&sig, "privilege_escalation_patterns"),
            external_network_risk_patterns: external_network,
        })
    }

    pub fn load_from_packs_dir(packs_dir: &Path) -> Result<Self, String> {
        let max_bytes = pack_list_max_bytes()?;
        ensure_real_dir(packs_dir)?;
        let sig = read_pack_child_text(packs_dir, "lists/signal-patterns.yaml", max_bytes)?;
        let ess = read_pack_child_text(
            packs_dir,
            "essentials/lists/protected-paths.yaml",
            max_bytes,
        )?;
        let agt = read_pack_child_text(
            packs_dir,
            "agents/lists/agent-control-files.yaml",
            max_bytes,
        )?;
        let dest = read_pack_child_text(
            packs_dir,
            "destructive/lists/destructive-patterns.yaml",
            max_bytes,
        )?;
        let eg = read_pack_child_text(
            packs_dir,
            "egress/lists/egress-destinations.yaml",
            max_bytes,
        )?;
        let sec = read_pack_child_text(packs_dir, "secrets/lists/secret-paths.yaml", max_bytes)?;
        Self::from_yaml_sources(&sig, &ess, &agt, &dest, &eg, &sec)
    }
}

pub(crate) fn default_ref_signal_lists() -> Result<&'static RefSignalLists, &'static str> {
    static CACHE: OnceLock<Result<RefSignalLists, String>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            RefSignalLists::from_yaml_sources(
                EMBEDDED_SIGNAL_PATTERNS_YAML,
                EMBEDDED_ESSENTIALS_YAML,
                EMBEDDED_AGENTS_YAML,
                EMBEDDED_DESTRUCTIVE_YAML,
                EMBEDDED_EGRESS_YAML,
                EMBEDDED_SECRETS_YAML,
            )
        })
        .as_ref()
        .map_err(|_| "embedded reference policy YAML catalog failed to load")
}

fn pack_list_max_bytes() -> Result<u64, String> {
    let mut in_packs = false;
    for raw_line in EMBEDDED_LIMITS_TOML.lines() {
        let trimmed = raw_line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_packs = trimmed == "[packs]";
            continue;
        }
        if in_packs
            && let Some((k, v)) = trimmed.split_once('=')
            && k.trim() == "essentials_max_kb"
        {
            let kb: u64 = v
                .trim()
                .parse()
                .map_err(|e| format!("invalid essentials_max_kb in limits.toml: {e}"))?;
            return Ok(kb.saturating_mul(1024));
        }
    }
    Err("missing [packs].essentials_max_kb in limits.toml".into())
}

fn is_symlink_or_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn ensure_real_dir(dir: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| format!("failed reading {}: {e}", dir.display()))?;
    if is_symlink_or_reparse(&meta) || !meta.is_dir() {
        return Err(format!("{} must be a non-symlink directory", dir.display()));
    }
    Ok(())
}

fn read_pack_child_text(pack_dir: &Path, rel: &str, max_bytes: u64) -> Result<String, String> {
    let mut cur = pack_dir.to_path_buf();
    let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return Err("empty pack relative path".into());
    }
    let mut pre_meta: Option<std::fs::Metadata> = None;
    for (idx, part) in parts.iter().enumerate() {
        if *part == "." || *part == ".." || part.contains('\\') || part.contains('\0') {
            return Err(format!("invalid relative pack segment `{part}`"));
        }
        cur.push(part);
        let is_last = idx.saturating_add(1) == parts.len();
        let meta = std::fs::symlink_metadata(&cur)
            .map_err(|e| format!("failed reading {}: {e}", cur.display()))?;
        if is_symlink_or_reparse(&meta) {
            return Err(format!("symlink forbidden at {}", cur.display()));
        }
        if !is_last && !meta.is_dir() {
            return Err(format!("expected directory at {}", cur.display()));
        }
        if is_last {
            if !meta.is_file() {
                return Err(format!("expected regular file at {}", cur.display()));
            }
            pre_meta = Some(meta);
        }
    }
    let expected_meta = pre_meta
        .as_ref()
        .ok_or_else(|| format!("missing regular file metadata for {}", cur.display()))?;
    let file = open_regular_nofollow(&cur)?;
    let handle_meta = file
        .metadata()
        .map_err(|e| format!("failed stating {}: {e}", cur.display()))?;
    if is_symlink_or_reparse(&handle_meta) || !handle_meta.is_file() {
        return Err(format!("{} is not a regular file", cur.display()));
    }
    if handle_meta.len() > max_bytes {
        return Err(format!("{} exceeds byte bound", cur.display()));
    }
    verify_same_file_identity(&cur, expected_meta, &handle_meta)?;
    let cap = max_bytes.saturating_add(1);
    let mut bytes = Vec::new();
    file.take(cap)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed reading {}: {e}", cur.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(format!("{} exceeds byte bound", cur.display()));
    }
    String::from_utf8(bytes).map_err(|_| format!("{} is not valid UTF-8", cur.display()))
}

fn verify_same_file_identity(
    path: &Path,
    pre_meta: &std::fs::Metadata,
    handle_meta: &std::fs::Metadata,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if pre_meta.dev() != handle_meta.dev() || pre_meta.ino() != handle_meta.ino() {
            return Err(format!(
                "file identity changed during open for {}",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, pre_meta, handle_meta);
    }
    Ok(())
}

fn open_regular_nofollow(path: &Path) -> Result<File, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(unix_o_nofollow());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts.open(path)
        .map_err(|e| format!("failed opening {}: {e}", path.display()))
}

#[cfg(unix)]
const fn unix_o_nofollow() -> i32 {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        0x0100
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        #[cfg(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        ))]
        {
            0o100_000
        }
        #[cfg(any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))]
        {
            0x20000
        }
        #[cfg(not(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        )))]
        {
            0o400_000
        }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "linux",
        target_os = "android"
    )))]
    {
        0x20000
    }
}

fn parse_policy_lists(src: &str) -> Result<BTreeMap<String, Vec<String>>, String> {
    let max_bytes = usize::try_from(pack_list_max_bytes()?).unwrap_or(usize::MAX);
    if src.len() > max_bytes {
        return Err("policy list YAML exceeds byte bound".into());
    }
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut format: Option<String> = None;
    let mut saw_lists = false;
    let mut in_lists = false;
    let mut current_key: Option<String> = None;

    for raw_line in src.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw_line.len().saturating_sub(raw_line.trim_start().len());
        if indent == 0 {
            in_lists = trimmed == "lists:";
            if in_lists {
                if saw_lists {
                    return Err("duplicate `lists` section in policy list YAML".into());
                }
                saw_lists = true;
            } else if let Some((k, v)) = trimmed.split_once(':') {
                let key = k.trim();
                let val = unquote_yaml_scalar(v.trim())?;
                if key == "format" {
                    format = Some(val);
                } else if key != "pack_id" && key != "version" {
                    return Err(format!(
                        "unexpected top-level key `{key}` in policy list YAML"
                    ));
                }
            } else {
                return Err("malformed top-level line in policy list YAML".into());
            }
            current_key = None;
            continue;
        }
        if !in_lists {
            return Err("unexpected indented line outside `lists` section".into());
        }
        if let Some(after_dash) = trimmed.strip_prefix("- ") {
            let key = current_key
                .as_ref()
                .ok_or_else(|| "list item without active key in policy list YAML".to_owned())?;
            let item = unquote_yaml_scalar(after_dash.trim())?.to_ascii_lowercase();
            let entry = map.entry(key.clone()).or_default();
            if entry.len() >= MAX_PATTERNS_PER_LIST {
                return Err(format!(
                    "policy list `{key}` exceeds {MAX_PATTERNS_PER_LIST} entries"
                ));
            }
            if !item.is_empty() {
                entry.push(item);
            }
            continue;
        }
        if let Some(key_name) = trimmed.strip_suffix(':') {
            let key = key_name.trim();
            if key.is_empty() || map.contains_key(key) {
                return Err(format!("invalid or duplicate list key `{key}`"));
            }
            map.insert(key.to_owned(), Vec::new());
            current_key = Some(key.to_owned());
            continue;
        }
        return Err(format!("malformed line inside `lists`: `{trimmed}`"));
    }
    if format.as_deref() != Some(POLICY_LISTS_FORMAT) {
        return Err("policy list YAML missing expected format header".into());
    }
    if !saw_lists {
        return Err("policy list YAML missing `lists` section".into());
    }
    Ok(map)
}

fn unquote_yaml_scalar(raw: &str) -> Result<String, String> {
    if raw.starts_with('"') {
        let inner = raw
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(|| "unclosed double-quoted YAML scalar".to_owned())?;
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch != '\\' {
                out.push(ch);
                continue;
            }
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => {
                    return Err(format!("unsupported YAML escape sequence `\\{other}`"));
                }
                None => return Err("dangling escape at end of double-quoted YAML scalar".into()),
            }
        }
        return Ok(out);
    }
    if raw.starts_with('\'') {
        let inner = raw
            .strip_prefix('\'')
            .and_then(|s| s.strip_suffix('\''))
            .ok_or_else(|| "unclosed single-quoted YAML scalar".to_owned())?;
        return Ok(inner.replace("''", "'"));
    }
    Ok(raw.to_owned())
}

fn extract(map: &BTreeMap<String, Vec<String>>, key: &str) -> Vec<String> {
    map.get(key).cloned().unwrap_or_default()
}

fn extend_unique(dst: &mut Vec<String>, items: Vec<String>) {
    for item in items {
        if !item.is_empty() && !dst.contains(&item) {
            dst.push(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_yaml_escapes_headers_and_oversized_lists() {
        assert_eq!(
            unquote_yaml_scalar("\"a\\\\b\\\"c\"").expect("escaped backslash and quote"),
            "a\\b\"c"
        );
        assert_eq!(
            unquote_yaml_scalar("\"a\\\\\"").expect("trailing escaped backslash"),
            "a\\"
        );
        assert!(unquote_yaml_scalar("\"unclosed").is_err());

        let bad_fmt = "format: wrong\npack_id: p\nlists:\n  k:\n    - \"x\"\n";
        assert!(parse_policy_lists(bad_fmt).is_err());

        let mut over = String::from("format: grdr.policy-lists.v1\npack_id: p\nlists:\n  k:\n");
        for i in 0..=MAX_PATTERNS_PER_LIST {
            over.push_str(&format!("    - \"item-{i}\"\n"));
        }
        assert!(parse_policy_lists(&over).is_err());

        let packs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packs");
        let loaded = RefSignalLists::load_from_packs_dir(&packs_dir).expect("load packs dir");
        assert!(!loaded.agent_control_risk_patterns.is_empty());

        assert!(read_pack_child_text(&packs_dir, "../etc/passwd", 1024).is_err());
        assert!(read_pack_child_text(&packs_dir, "lists\\signal-patterns.yaml", 1024).is_err());

        let tmp = std::env::temp_dir().join(format!("grdr_policy_ref_io_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("lists")).expect("create tmp lists");
        let regular_file = tmp.join("not-a-dir.yaml");
        std::fs::write(
            &regular_file,
            "format: grdr.policy-lists.v1\npack_id: t\nlists:\n",
        )
        .expect("write regular file");
        assert!(RefSignalLists::load_from_packs_dir(&regular_file).is_err());

        #[cfg(unix)]
        {
            let link = tmp.join("lists/signal-patterns.yaml");
            std::os::unix::fs::symlink(&regular_file, &link).expect("create symlink");
            assert!(read_pack_child_text(&tmp, "lists/signal-patterns.yaml", 4096).is_err());
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
