// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! On-device pre-preview secret, credential, DSN, JWT, PEM, and home/host scrubbing (`P8`).

use grdr_crypto::sha256_hex;

pub const SENSITIVE_KEY_WORDS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "private_key",
    "privkey",
    "seed",
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "enrol",
    "dsn",
    "connection_string",
    "cookie",
    "session_key",
    "hmac",
    "pem",
    "client_secret",
    "signing_key",
    "passphrase",
    "bearer",
];

const PSEUDONYM_KEY_WORDS: &[&str] = &["hostname", "device_name", "repo", "remote", "workspace"];

const TOKEN_PREFIXES: &[&str] = &[
    "sk-",
    "sk_",
    "pk_live_",
    "pk_test_",
    "rk_",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "AKIA",
    "ASIA",
    "grdr_wk_",
    "grdr_enrol_",
    "grdr_tok_",
    "grdr_ph_",
    "grdr_hk_",
    "grdr_key_",
    "npm_",
    "pypi-",
    "AIza",
];

const INLINE_KV_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "auth_token",
    "access_token",
    "refresh_token",
    "client_secret",
    "signing_key",
    "private_key",
    "privkey",
    "passphrase",
    "credential",
    "token",
    "dsn",
];

pub fn pseudonymize_with_salt(prefix: &str, salt: &str, raw: &str) -> String {
    let hex = sha256_hex(format!("{salt}:{raw}").as_bytes());
    format!("{prefix}_{}", hex.get(..12).unwrap_or("anon"))
}

pub fn scrub_text(
    input: &str,
    home_dir: Option<&str>,
    hostname: Option<&str>,
    username: Option<&str>,
    salt: &str,
    marking: Option<&str>,
) -> String {
    let mut text = input.to_owned();
    if let Some(home) = home_dir
        && !home.is_empty()
    {
        let normalized_home = home.replace('\\', "/");
        text = text.replace(home, "~").replace(&normalized_home, "~");
    }
    if let Some(host) = hostname {
        let trimmed = host.trim();
        if trimmed.len() >= 3 {
            let anon_host = pseudonymize_with_salt("host", salt, trimmed);
            text = text.replace(trimmed, &anon_host);
        }
    }
    if let Some(user) = username {
        let trimmed = user.trim();
        if trimmed.len() >= 2 {
            let anon_user = pseudonymize_with_salt("user", salt, trimmed);
            for pattern in [
                format!("/home/{trimmed}"),
                format!("/Users/{trimmed}"),
                format!("C:\\Users\\{trimmed}"),
                format!("C:/Users/{trimmed}"),
            ] {
                text = text.replace(&pattern, &format!("~/{anon_user}"));
            }
        }
    }

    text = redact_pem_blocks(&text);
    text = redact_dsn_credentials(&text);
    text = redact_case_insensitive_auth_schemes(&text);
    text = redact_inline_kv_pairs(&text);
    text = redact_prefixed_tokens(&text);
    text = redact_jwts(&text);
    prepend_marking_if_set(&text, marking)
}

pub fn prepend_marking_if_set(body: &str, marking: Option<&str>) -> String {
    match marking {
        Some(m) if !m.trim().is_empty() => format!("# Marking: {}\n{body}", m.trim()),
        _ => body.to_owned(),
    }
}

pub fn redact_json_value(
    val: &serde_json::Value,
    home_dir: Option<&str>,
    hostname: Option<&str>,
    username: Option<&str>,
    salt: &str,
) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let mut next = serde_json::Map::new();
            for (k, v) in map {
                let lower = k.to_ascii_lowercase();
                if SENSITIVE_KEY_WORDS.iter().any(|w| lower.contains(w)) {
                    next.insert(k.clone(), serde_json::Value::String("[REDACTED]".into()));
                } else if matches!(
                    lower.as_str(),
                    "content" | "prompt" | "body" | "payload" | "raw_command" | "memory_dump"
                ) {
                    next.insert(
                        k.clone(),
                        serde_json::Value::String("[EXCLUDED_BY_P8]".into()),
                    );
                } else if PSEUDONYM_KEY_WORDS.iter().any(|w| lower == *w)
                    && let Some(raw_s) = v.as_str()
                {
                    let scrubbed = scrub_text(raw_s, home_dir, hostname, username, salt, None);
                    let final_s = if lower == "workspace" {
                        scrubbed
                    } else {
                        pseudonymize_with_salt(&lower, salt, &scrubbed)
                    };
                    next.insert(k.clone(), serde_json::Value::String(final_s));
                } else {
                    next.insert(
                        k.clone(),
                        redact_json_value(v, home_dir, hostname, username, salt),
                    );
                }
            }
            serde_json::Value::Object(next)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| redact_json_value(v, home_dir, hostname, username, salt))
                .collect(),
        ),
        serde_json::Value::String(s) => {
            serde_json::Value::String(scrub_text(s, home_dir, hostname, username, salt, None))
        }
        other => other.clone(),
    }
}

fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')
}

fn has_ident_boundary(before: &str) -> bool {
    before.chars().next_back().is_some_and(is_ident_char)
}

fn redact_pem_blocks(input: &str) -> String {
    let mut cur = input.to_owned();
    while let Some(start) = cur.find("-----BEGIN ") {
        let after_begin = cur.get(start..).unwrap_or("");
        let end_rel = after_begin.find("-----END ").and_then(|end_tag| {
            after_begin
                .get(end_tag.saturating_add(9)..)
                .and_then(|tail| {
                    tail.find("-----").map(|k| {
                        end_tag
                            .saturating_add(9)
                            .saturating_add(k)
                            .saturating_add(5)
                    })
                })
        });
        let head = cur.get(..start).unwrap_or("");
        match end_rel {
            Some(rel_end) => {
                let tail = cur.get(start.saturating_add(rel_end)..).unwrap_or("");
                cur = format!("{head}[REDACTED_PEM]{tail}");
            }
            None => {
                cur = format!("{head}[REDACTED_PEM]");
                break;
            }
        }
    }
    cur
}

fn redact_dsn_credentials(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(scheme_pos) = rest.find("://") {
        let prefix_end = scheme_pos.saturating_add(3);
        let before = rest.get(..prefix_end).unwrap_or("");
        let after = rest.get(prefix_end..).unwrap_or("");
        out.push_str(before);
        let auth_end = after
            .find(|c: char| {
                c.is_ascii_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | ',' | '}')
            })
            .unwrap_or(after.len());
        let authority = after.get(..auth_end).unwrap_or("");
        if let Some(at_pos) = authority.rfind('@') {
            out.push_str("[REDACTED]@");
            out.push_str(authority.get(at_pos.saturating_add(1)..).unwrap_or(""));
        } else {
            out.push_str(authority);
        }
        rest = after.get(auth_end..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

fn redact_case_insensitive_auth_schemes(input: &str) -> String {
    let mut text = input.to_owned();
    for scheme in ["bearer ", "basic ", "token "] {
        let mut out = String::with_capacity(text.len());
        let mut offset = 0_usize;
        while let Some(sub) = text.get(offset..) {
            let lower = sub.to_ascii_lowercase();
            let Some(pos) = lower.find(scheme) else {
                out.push_str(sub);
                break;
            };
            let head = sub.get(..pos).unwrap_or("");
            let prev_char = head.chars().next_back().or_else(|| out.chars().next_back());
            if prev_char.is_some_and(is_ident_char) {
                let keep_end = pos.saturating_add(scheme.len());
                out.push_str(sub.get(..keep_end).unwrap_or(""));
                offset = offset.saturating_add(keep_end);
                continue;
            }
            out.push_str(head);
            out.push_str("[REDACTED_AUTH]");
            let val_start = pos.saturating_add(scheme.len());
            let tail = sub.get(val_start..).unwrap_or("");
            let tok_end = tail
                .find(|c: char| {
                    c.is_ascii_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '}' | ')')
                })
                .unwrap_or(tail.len());
            offset = offset.saturating_add(val_start).saturating_add(tok_end);
        }
        text = out;
    }
    text
}

fn redact_inline_kv_pairs(input: &str) -> String {
    let mut text = input.to_owned();
    for key in INLINE_KV_KEYS {
        let mut out = String::with_capacity(text.len());
        let mut offset = 0_usize;
        while let Some(sub) = text.get(offset..) {
            let lower = sub.to_ascii_lowercase();
            let Some(pos) = lower.find(key) else {
                out.push_str(sub);
                break;
            };
            let head = sub.get(..pos).unwrap_or("");
            let prev_char = head.chars().next_back().or_else(|| out.chars().next_back());
            let after_key_pos = pos.saturating_add(key.len());
            let after_key = sub.get(after_key_pos..).unwrap_or("");
            if prev_char.is_some_and(is_ident_char) {
                out.push_str(sub.get(..after_key_pos).unwrap_or(""));
                offset = offset.saturating_add(after_key_pos);
                continue;
            }
            let ws_len = after_key
                .len()
                .saturating_sub(after_key.trim_start_matches(' ').len());
            let after_ws = after_key.get(ws_len..).unwrap_or("");
            let has_kv_sep = after_ws.starts_with('=')
                || (after_ws.starts_with(':') && !after_ws.starts_with("://"));
            if !has_kv_sep {
                out.push_str(sub.get(..after_key_pos).unwrap_or(""));
                offset = offset.saturating_add(after_key_pos);
                continue;
            }
            let sep_len = 1_usize;
            let after_sep = after_ws.get(sep_len..).unwrap_or("");
            let post_ws = after_sep
                .len()
                .saturating_sub(after_sep.trim_start_matches(' ').len());
            let val_slice = after_sep.get(post_ws..).unwrap_or("");
            let quote = val_slice.chars().next().filter(|c| matches!(c, '"' | '\''));
            let (inner, val_consumed) = if let Some(q) = quote {
                let inner_slice = val_slice.get(1..).unwrap_or("");
                let end_q = inner_slice
                    .find(q)
                    .map(|idx| idx.saturating_add(2))
                    .unwrap_or(val_slice.len());
                (
                    val_slice.get(1..end_q.saturating_sub(1)).unwrap_or(""),
                    end_q,
                )
            } else {
                let end_tok = val_slice
                    .find(|c: char| {
                        c.is_ascii_whitespace()
                            || matches!(c, '"' | '\'' | ',' | ';' | '&' | '}' | ')')
                    })
                    .unwrap_or(val_slice.len());
                (val_slice.get(..end_tok).unwrap_or(""), end_tok)
            };
            if inner.is_empty() {
                out.push_str(sub.get(..after_key_pos).unwrap_or(""));
                offset = offset.saturating_add(after_key_pos);
                continue;
            }
            let prefix_keep = pos
                .saturating_add(key.len())
                .saturating_add(ws_len)
                .saturating_add(sep_len)
                .saturating_add(post_ws);
            out.push_str(sub.get(..prefix_keep).unwrap_or(""));
            if let Some(q) = quote {
                out.push(q);
                out.push_str("[REDACTED]");
                out.push(q);
            } else {
                out.push_str("[REDACTED]");
            }
            offset = offset
                .saturating_add(prefix_keep)
                .saturating_add(val_consumed);
        }
        text = out;
    }
    text
}

fn redact_prefixed_tokens(input: &str) -> String {
    let mut text = input.to_owned();
    for prefix in TOKEN_PREFIXES {
        let mut out = String::with_capacity(text.len());
        let mut offset = 0_usize;
        while let Some(sub) = text.get(offset..) {
            let Some(pos) = sub.find(prefix) else {
                out.push_str(sub);
                break;
            };
            let head = sub.get(..pos).unwrap_or("");
            let prev_char = head.chars().next_back().or_else(|| out.chars().next_back());
            if prev_char.is_some_and(is_ident_char) {
                let keep_end = pos.saturating_add(prefix.len());
                out.push_str(sub.get(..keep_end).unwrap_or(""));
                offset = offset.saturating_add(keep_end);
                continue;
            }
            out.push_str(head);
            out.push_str("[REDACTED]");
            let tail = sub.get(pos..).unwrap_or("");
            let end_offset = tail
                .find(|c: char| {
                    c.is_ascii_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '}' | ')')
                })
                .unwrap_or(tail.len());
            offset = offset.saturating_add(pos).saturating_add(end_offset);
        }
        text = out;
    }
    text
}

fn redact_jwts(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("eyJ") {
        let head = rest.get(..pos).unwrap_or("");
        if has_ident_boundary(head) || head.ends_with('.') {
            out.push_str(head);
            out.push_str("eyJ");
            rest = rest.get(pos.saturating_add(3)..).unwrap_or("");
            continue;
        }
        let cand_full = rest.get(pos..).unwrap_or("");
        let tok_len = cand_full
            .find(|c: char| !c.is_ascii_alphanumeric() && !matches!(c, '_' | '-' | '.'))
            .unwrap_or(cand_full.len());
        let token = cand_full.get(..tok_len).unwrap_or("");
        if is_jwt_like(token) {
            out.push_str(head);
            out.push_str("[REDACTED_JWT]");
            rest = cand_full.get(tok_len..).unwrap_or("");
        } else {
            out.push_str(head);
            out.push_str("eyJ");
            rest = rest.get(pos.saturating_add(3)..).unwrap_or("");
        }
    }
    out.push_str(rest);
    out
}

fn is_jwt_like(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3
        && parts.first().is_some_and(|h| h.len() >= 6)
        && parts.get(1).is_some_and(|p| p.len() >= 6)
        && parts.iter().all(|seg| {
            seg.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}
