use std::collections::BTreeMap;
use thiserror::Error;

/// Errors raised while parsing `contracts/interface/*.toml` files (`GRDR-GEN-*`).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TomlParseError {
    #[error("GRDR-GEN-0001: TOML syntax error on line {line}: {detail}")]
    Syntax { line: usize, detail: String },
}

#[derive(Clone, Debug, PartialEq)]
pub enum TomlValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<TomlValue>),
    Table(BTreeMap<String, TomlValue>),
}

enum CursorTarget {
    Root,
    Table(String),
    ArrayTable { key: String, index: usize },
}

struct MultilineCapture {
    key: String,
    quote: &'static str,
    buf: Vec<String>,
}

impl TomlValue {
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(v) => Some(v.as_str()),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str_array(&self) -> Option<Vec<String>> {
        let Self::Array(items) = self else {
            return None;
        };
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            out.push(item.as_str()?.to_owned());
        }
        Some(out)
    }

    #[must_use]
    pub fn as_table(&self) -> Option<&BTreeMap<String, TomlValue>> {
        match self {
            Self::Table(map) => Some(map),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_table_array(&self) -> Option<Vec<&BTreeMap<String, TomlValue>>> {
        let Self::Array(items) = self else {
            return None;
        };
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            out.push(item.as_table()?);
        }
        Some(out)
    }
}

/// Parses a subset of TOML sufficient for `contracts/interface/` registries and string catalogs.
pub fn parse_toml_table(source: &str) -> Result<BTreeMap<String, TomlValue>, TomlParseError> {
    let mut root: BTreeMap<String, TomlValue> = BTreeMap::new();
    let mut target = CursorTarget::Root;
    let mut multiline: Option<MultilineCapture> = None;

    for (idx, raw_line) in source.lines().enumerate() {
        let line_no = idx.saturating_add(1);
        if let Some(mut cap) = multiline.take() {
            if let Some(before) = raw_line.strip_suffix(cap.quote) {
                if !before.is_empty() {
                    cap.buf.push(before.to_owned());
                }
                let val = TomlValue::Str(cap.buf.join("\n"));
                insert_into_target(&mut root, &target, cap.key, val, line_no)?;
            } else {
                cap.buf.push(raw_line.to_owned());
                multiline = Some(cap);
            }
            continue;
        }

        let trimmed = strip_comment(raw_line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(inner) = trimmed
            .strip_prefix("[[")
            .and_then(|s| s.strip_suffix("]]"))
        {
            let key = parse_key_token(inner.trim(), line_no)?;
            let entry = root
                .entry(key.clone())
                .or_insert_with(|| TomlValue::Array(Vec::new()));
            let TomlValue::Array(arr) = entry else {
                return Err(TomlParseError::Syntax {
                    line: line_no,
                    detail: format!("expected array of tables for [[{key}]]"),
                });
            };
            arr.push(TomlValue::Table(BTreeMap::new()));
            target = CursorTarget::ArrayTable {
                key,
                index: arr.len().saturating_sub(1),
            };
            continue;
        }

        if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let key = parse_key_token(inner.trim(), line_no)?;
            let entry = root
                .entry(key.clone())
                .or_insert_with(|| TomlValue::Table(BTreeMap::new()));
            if !matches!(entry, TomlValue::Table(_)) {
                return Err(TomlParseError::Syntax {
                    line: line_no,
                    detail: format!("key [{key}] collides with non-table entry"),
                });
            }
            target = CursorTarget::Table(key);
            continue;
        }

        let Some((lhs, rhs)) = trimmed.split_once('=') else {
            return Err(TomlParseError::Syntax {
                line: line_no,
                detail: "expected key = value assignment".to_owned(),
            });
        };
        let key = parse_key_token(lhs.trim(), line_no)?;
        let rhs_trim = rhs.trim();

        if let Some(rest) = rhs_trim.strip_prefix("'''") {
            if let Some(inline) = rest.strip_suffix("'''") {
                insert_into_target(
                    &mut root,
                    &target,
                    key,
                    TomlValue::Str(inline.to_owned()),
                    line_no,
                )?;
            } else {
                let mut buf = Vec::new();
                if !rest.is_empty() {
                    buf.push(rest.to_owned());
                }
                multiline = Some(MultilineCapture {
                    key,
                    quote: "'''",
                    buf,
                });
            }
            continue;
        }

        let value = parse_value(rhs_trim, line_no)?;
        insert_into_target(&mut root, &target, key, value, line_no)?;
    }

    if multiline.is_some() {
        return Err(TomlParseError::Syntax {
            line: source.lines().count(),
            detail: "unterminated multiline string".to_owned(),
        });
    }

    Ok(root)
}

fn insert_into_target(
    root: &mut BTreeMap<String, TomlValue>,
    target: &CursorTarget,
    key: String,
    value: TomlValue,
    line: usize,
) -> Result<(), TomlParseError> {
    match target {
        CursorTarget::Root => {
            root.insert(key, value);
            Ok(())
        }
        CursorTarget::Table(section) => {
            let Some(TomlValue::Table(map)) = root.get_mut(section) else {
                return Err(TomlParseError::Syntax {
                    line,
                    detail: format!("missing section table '{section}'"),
                });
            };
            map.insert(key, value);
            Ok(())
        }
        CursorTarget::ArrayTable {
            key: arr_key,
            index,
        } => {
            let Some(TomlValue::Array(arr)) = root.get_mut(arr_key) else {
                return Err(TomlParseError::Syntax {
                    line,
                    detail: format!("missing array table '{arr_key}'"),
                });
            };
            let Some(TomlValue::Table(map)) = arr.get_mut(*index) else {
                return Err(TomlParseError::Syntax {
                    line,
                    detail: format!("invalid array table index for '{arr_key}'"),
                });
            };
            map.insert(key, value);
            Ok(())
        }
    }
}

fn strip_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_double {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        if ch == '"' {
            in_double = true;
        } else if ch == '\'' {
            in_single = true;
        } else if ch == '#' {
            return line.split_at(idx).0;
        }
    }
    line
}

fn parse_key_token(raw: &str, line: usize) -> Result<String, TomlParseError> {
    if let Some(inner) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return unescape_basic(inner, line);
    }
    if let Some(inner) = raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return Ok(inner.to_owned());
    }
    if raw.is_empty() {
        return Err(TomlParseError::Syntax {
            line,
            detail: "empty key".to_owned(),
        });
    }
    Ok(raw.to_owned())
}

fn parse_value(raw: &str, line: usize) -> Result<TomlValue, TomlParseError> {
    if raw == "true" {
        return Ok(TomlValue::Bool(true));
    }
    if raw == "false" {
        return Ok(TomlValue::Bool(false));
    }
    if let Some(inner) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Ok(TomlValue::Str(unescape_basic(inner, line)?));
    }
    if let Some(inner) = raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return Ok(TomlValue::Str(inner.to_owned()));
    }
    if let Some(inner) = raw.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return parse_array(inner, line);
    }
    if let Ok(num) = raw.parse::<i64>() {
        return Ok(TomlValue::Int(num));
    }
    Err(TomlParseError::Syntax {
        line,
        detail: format!("unsupported TOML value: {raw}"),
    })
}

fn parse_array(inner: &str, line: usize) -> Result<TomlValue, TomlParseError> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;

    for ch in inner.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if in_double {
            current.push(ch);
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            current.push(ch);
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        if ch == '"' {
            in_double = true;
            current.push(ch);
        } else if ch == '\'' {
            in_single = true;
            current.push(ch);
        } else if ch == ',' {
            let trimmed = current.trim();
            if !trimmed.is_empty() {
                items.push(parse_value(trimmed, line)?);
            }
            current.clear();
        } else {
            current.push(ch);
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        items.push(parse_value(trimmed, line)?);
    }
    Ok(TomlValue::Array(items))
}

fn unescape_basic(raw: &str, line: usize) -> Result<String, TomlParseError> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let Some(esc) = chars.next() else {
            return Err(TomlParseError::Syntax {
                line,
                detail: "trailing backslash in string".to_owned(),
            });
        };
        match esc {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            other => {
                return Err(TomlParseError::Syntax {
                    line,
                    detail: format!("unsupported escape sequence \\{other}"),
                });
            }
        }
    }
    Ok(out)
}
