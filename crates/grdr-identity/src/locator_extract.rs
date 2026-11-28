// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub(crate) fn normalize_path_slashes(raw: &str) -> String {
    raw.replace('\\', "/").trim().to_string()
}

pub(crate) fn glob_matches(pattern: &str, path: &str) -> bool {
    let norm_pat = normalize_path_slashes(pattern);
    if let Some(suffix) = norm_pat.strip_prefix("**/") {
        return wildcard_match(suffix, path)
            || path
                .rsplit('/')
                .next()
                .is_some_and(|base| wildcard_match(suffix, base))
            || path.ends_with(&format!("/{suffix}"))
            || wildcard_match(&format!("*/{suffix}"), path);
    }
    if let Some(suffix) = norm_pat
        .strip_prefix("~/")
        .or_else(|| norm_pat.strip_prefix("%USERPROFILE%/"))
        .or_else(|| norm_pat.strip_prefix("%APPDATA%/"))
        .or_else(|| norm_pat.strip_prefix("%LOCALAPPDATA%/"))
    {
        return path == norm_pat
            || path.ends_with(&format!("/{suffix}"))
            || wildcard_match(suffix, path.trim_start_matches("~/"))
            || wildcard_match(&format!("*/{suffix}"), path);
    }
    wildcard_match(&norm_pat, path)
        || path
            .rsplit('/')
            .next()
            .is_some_and(|base| wildcard_match(&norm_pat, base))
}

fn wildcard_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let mut dp = vec![false; t.len().saturating_add(1)];
    if let Some(first) = dp.first_mut() {
        *first = true;
    }
    for pc in p {
        if pc == '*' {
            for j in 1..=t.len() {
                if let Some(prev) = dp.get(j.saturating_sub(1)).copied()
                    && prev
                    && let Some(slot) = dp.get_mut(j)
                {
                    *slot = true;
                }
            }
        } else {
            let mut next = vec![false; t.len().saturating_add(1)];
            for (j, &tc) in t.iter().enumerate() {
                if let Some(prev) = dp.get(j).copied()
                    && prev
                    && (pc == tc || pc == '?')
                    && let Some(slot) = next.get_mut(j.saturating_add(1))
                {
                    *slot = true;
                }
            }
            dp = next;
        }
    }
    dp.last().copied().unwrap_or(false)
}

pub(crate) fn extract_public_part(extractor: &str, path: &str, content: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    match extractor {
        "key_name" => content
            .lines()
            .find_map(|l| l.split_once('=').map(|(k, _)| k.trim().to_string()))
            .filter(|k| !k.is_empty())
            .unwrap_or_else(|| base.to_string()),
        "url_host_and_user" => {
            extract_url_host_and_user(content).unwrap_or_else(|| base.to_string())
        }
        "access_key_prefix" => {
            extract_aws_access_key_prefix(content).unwrap_or_else(|| base.to_string())
        }
        "json_client_id" => extract_json_string_field(content, &["client_id", "clientId"])
            .unwrap_or_else(|| base.to_string()),
        "json_client_email" => {
            extract_json_string_field(content, &["client_email", "private_key_id"])
                .unwrap_or_else(|| base.to_string())
        }
        "registry_host" => extract_registry_host(content).unwrap_or_else(|| base.to_string()),
        "cluster_context" => extract_kube_context(content).unwrap_or_else(|| base.to_string()),
        "yaml_host_user" => extract_yaml_host_user(content).unwrap_or_else(|| base.to_string()),
        "json_account_uuid" => extract_json_string_field(
            content,
            &["accountUuid", "organizationUuid", "email", "user"],
        )
        .unwrap_or_else(|| base.to_string()),
        _ => base.to_string(),
    }
}

fn extract_url_host_and_user(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(after_scheme) = trimmed.split("://").nth(1)
            && let Some((creds, host_tail)) = after_scheme.split_once('@')
        {
            let user = creds.split(':').next().unwrap_or("").trim();
            let host = host_tail.split(['/', '?', '#']).next().unwrap_or("").trim();
            if !host.is_empty() {
                return Some(format!("{user}@{host}"));
            }
        }
        if let Some(rest) = trimmed.strip_prefix("machine ")
            && let Some(host) = rest.split_whitespace().next()
        {
            return Some(host.to_string());
        }
    }
    None
}

fn extract_aws_access_key_prefix(content: &str) -> Option<String> {
    for tok in content.split(|c: char| !c.is_ascii_alphanumeric()) {
        if (tok.starts_with("AKIA") || tok.starts_with("ASIA")) && tok.len() >= 12 {
            return Some(tok.get(..8).unwrap_or(tok).to_string());
        }
    }
    None
}

fn extract_json_string_field(content: &str, keys: &[&str]) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(content).ok()?;
    for key in keys {
        if let Some(found) = val.get(*key).and_then(|v| v.as_str())
            && !found.is_empty()
        {
            return Some(found.to_string());
        }
    }
    None
}

fn extract_registry_host(content: &str) -> Option<String> {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(content)
        && let Some(first_host) = val
            .get("auths")
            .and_then(|a| a.as_object())
            .and_then(|m| m.keys().next())
    {
        return Some(first_host.clone());
    }
    for line in content.lines() {
        if let Some(after) = line.trim().strip_prefix("//")
            && let Some((host, _)) = after.split_once('/')
            && !host.is_empty()
        {
            return Some(host.to_string());
        }
    }
    None
}

fn extract_kube_context(content: &str) -> Option<String> {
    for line in content.lines() {
        let t = line.trim();
        if let Some(ctx) = t.strip_prefix("current-context:") {
            let clean = ctx.trim().trim_matches(['"', '\'']);
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
    }
    None
}

fn extract_yaml_host_user(content: &str) -> Option<String> {
    let mut host = None;
    let mut user = None;
    for line in content.lines() {
        if !line.starts_with(' ') && line.trim_end().ends_with(':') {
            host = Some(line.trim().trim_end_matches(':').to_string());
        } else if let Some(u) = line.trim().strip_prefix("user:") {
            user = Some(u.trim().trim_matches(['"', '\'']).to_string());
            break;
        }
    }
    match (host, user) {
        (Some(h), Some(u)) if !h.is_empty() && !u.is_empty() => Some(format!("{u}@{h}")),
        (Some(h), _) if !h.is_empty() => Some(h),
        _ => None,
    }
}
