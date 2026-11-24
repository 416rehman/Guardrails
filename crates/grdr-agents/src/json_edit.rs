// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde_json::Value;

#[derive(Debug, Clone)]
struct JsonNode {
    start: usize,
    end: usize,
    kind: JsonKind,
}

#[derive(Debug, Clone)]
enum JsonKind {
    Object(Vec<JsonMember>),
    Array(Vec<JsonNode>),
    Scalar,
}

#[derive(Debug, Clone)]
struct JsonMember {
    key_start: usize,
    key_name: String,
    value: JsonNode,
}

pub(crate) fn insert_array_entries_preserving_spans(
    raw: &str,
    event_entries: &[(&str, Value)],
) -> Result<String, String> {
    let mut current = raw.to_string();
    for (event_key, entry) in event_entries {
        current = insert_single_event_entry(&current, event_key, entry)?;
    }
    Ok(current)
}

fn insert_single_event_entry(raw: &str, event_key: &str, entry: &Value) -> Result<String, String> {
    let root = parse_root_object(raw)?;
    let JsonKind::Object(root_members) = &root.kind else {
        return Err("GRDR-AGENTS-0003: root hook config must be a JSON object".into());
    };

    if let Some(hooks_member) = root_members.iter().find(|m| m.key_name == "hooks") {
        let JsonKind::Object(hooks_members) = &hooks_member.value.kind else {
            return Err("GRDR-AGENTS-0003: `hooks` field must be a JSON object".into());
        };
        if let Some(ev_member) = hooks_members.iter().find(|m| m.key_name == event_key) {
            let JsonKind::Array(items) = &ev_member.value.kind else {
                return Err(format!(
                    "GRDR-AGENTS-0003: `hooks.{event_key}` must be a JSON array"
                ));
            };
            return insert_into_array(raw, &ev_member.value, items, entry);
        }
        return insert_event_member_into_hooks(
            raw,
            &hooks_member.value,
            hooks_members,
            event_key,
            entry,
        );
    }

    insert_hooks_member_into_root(raw, &root, root_members, event_key, entry)
}

fn insert_into_array(
    raw: &str,
    arr_node: &JsonNode,
    items: &[JsonNode],
    entry: &Value,
) -> Result<String, String> {
    let entry_pretty = serde_json::to_string_pretty(entry)
        .map_err(|e| format!("failed serializing hook entry: {e}"))?;

    if let Some(last) = items.last() {
        let indent = line_indent_at(raw, last.start);
        let indented = indent_multiline(&entry_pretty, &indent);
        let insertion = format!(",\n{indent}{indented}");
        return splice_str(raw, last.end, last.end, &insertion);
    }

    let base_indent = line_indent_at(raw, arr_node.start);
    let item_indent = format!("{base_indent}  ");
    let indented = indent_multiline(&entry_pretty, &item_indent);
    let inner_start = arr_node.start.saturating_add(1);
    let inner_end = arr_node.end.saturating_sub(1);
    let replacement = format!("\n{item_indent}{indented}\n{base_indent}");
    splice_str(raw, inner_start, inner_end, &replacement)
}

fn insert_event_member_into_hooks(
    raw: &str,
    hooks_node: &JsonNode,
    hooks_members: &[JsonMember],
    event_key: &str,
    entry: &Value,
) -> Result<String, String> {
    let entry_pretty = serde_json::to_string_pretty(entry)
        .map_err(|e| format!("failed serializing hook entry: {e}"))?;
    let key_json = serde_json::to_string(event_key)
        .map_err(|e| format!("failed serializing event key: {e}"))?;

    if let Some(last) = hooks_members.last() {
        let member_indent = line_indent_at(raw, last.key_start);
        let item_indent = format!("{member_indent}  ");
        let indented = indent_multiline(&entry_pretty, &item_indent);
        let insertion =
            format!(",\n{member_indent}{key_json}: [\n{item_indent}{indented}\n{member_indent}]");
        return splice_str(raw, last.value.end, last.value.end, &insertion);
    }

    let base_indent = line_indent_at(raw, hooks_node.start);
    let member_indent = format!("{base_indent}  ");
    let item_indent = format!("{member_indent}  ");
    let indented = indent_multiline(&entry_pretty, &item_indent);
    let inner_start = hooks_node.start.saturating_add(1);
    let inner_end = hooks_node.end.saturating_sub(1);
    let replacement = format!(
        "\n{member_indent}{key_json}: [\n{item_indent}{indented}\n{member_indent}]\n{base_indent}"
    );
    splice_str(raw, inner_start, inner_end, &replacement)
}

fn insert_hooks_member_into_root(
    raw: &str,
    root_node: &JsonNode,
    root_members: &[JsonMember],
    event_key: &str,
    entry: &Value,
) -> Result<String, String> {
    let entry_pretty = serde_json::to_string_pretty(entry)
        .map_err(|e| format!("failed serializing hook entry: {e}"))?;
    let key_json = serde_json::to_string(event_key)
        .map_err(|e| format!("failed serializing event key: {e}"))?;

    if let Some(last) = root_members.last() {
        let member_indent = line_indent_at(raw, last.key_start);
        let ev_indent = format!("{member_indent}  ");
        let item_indent = format!("{ev_indent}  ");
        let indented = indent_multiline(&entry_pretty, &item_indent);
        let insertion = format!(
            ",\n{member_indent}\"hooks\": {{\n{ev_indent}{key_json}: [\n{item_indent}{indented}\n{ev_indent}]\n{member_indent}}}"
        );
        return splice_str(raw, last.value.end, last.value.end, &insertion);
    }

    let base_indent = line_indent_at(raw, root_node.start);
    let member_indent = format!("{base_indent}  ");
    let ev_indent = format!("{member_indent}  ");
    let item_indent = format!("{ev_indent}  ");
    let indented = indent_multiline(&entry_pretty, &item_indent);
    let inner_start = root_node.start.saturating_add(1);
    let inner_end = root_node.end.saturating_sub(1);
    let replacement = format!(
        "\n{member_indent}\"hooks\": {{\n{ev_indent}{key_json}: [\n{item_indent}{indented}\n{ev_indent}]\n{member_indent}}}\n{base_indent}"
    );
    splice_str(raw, inner_start, inner_end, &replacement)
}

fn splice_str(raw: &str, start: usize, end: usize, insert: &str) -> Result<String, String> {
    let prefix = raw
        .get(..start)
        .ok_or_else(|| "GRDR-AGENTS-0003: invalid JSON span start".to_string())?;
    let suffix = raw
        .get(end..)
        .ok_or_else(|| "GRDR-AGENTS-0003: invalid JSON span end".to_string())?;
    let mut out = String::with_capacity(
        prefix
            .len()
            .saturating_add(insert.len())
            .saturating_add(suffix.len()),
    );
    out.push_str(prefix);
    out.push_str(insert);
    out.push_str(suffix);
    Ok(out)
}

fn line_indent_at(raw: &str, pos: usize) -> String {
    let head = raw.get(..pos).unwrap_or("");
    let line_start = head.rfind('\n').map_or(0, |idx| idx.saturating_add(1));
    let slice = head.get(line_start..).unwrap_or("");
    slice
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

fn indent_multiline(pretty: &str, indent: &str) -> String {
    let mut out = String::new();
    for (idx, line) in pretty.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
            out.push_str(indent);
        }
        out.push_str(line);
    }
    out
}

fn parse_root_object(raw: &str) -> Result<JsonNode, String> {
    let bytes = raw.as_bytes();
    let pos = skip_ws(bytes, 0);
    let (node, end) = parse_value(raw, bytes, pos)?;
    let trailing = skip_ws(bytes, end);
    if trailing != bytes.len() {
        return Err("GRDR-AGENTS-0003: trailing characters after JSON document".into());
    }
    Ok(node)
}

fn parse_value(raw: &str, bytes: &[u8], pos: usize) -> Result<(JsonNode, usize), String> {
    let p = skip_ws(bytes, pos);
    let byte = bytes
        .get(p)
        .copied()
        .ok_or_else(|| "GRDR-AGENTS-0003: unexpected end of JSON".to_string())?;
    match byte {
        b'{' => parse_object(raw, bytes, p),
        b'[' => parse_array(raw, bytes, p),
        b'"' => {
            let end = scan_string(bytes, p)?;
            Ok((
                JsonNode {
                    start: p,
                    end,
                    kind: JsonKind::Scalar,
                },
                end,
            ))
        }
        _ => {
            let end = scan_scalar(bytes, p)?;
            Ok((
                JsonNode {
                    start: p,
                    end,
                    kind: JsonKind::Scalar,
                },
                end,
            ))
        }
    }
}

fn parse_object(raw: &str, bytes: &[u8], start: usize) -> Result<(JsonNode, usize), String> {
    let mut p = skip_ws(bytes, start.saturating_add(1));
    let mut members = Vec::new();
    if bytes.get(p).copied() == Some(b'}') {
        return Ok((
            JsonNode {
                start,
                end: p.saturating_add(1),
                kind: JsonKind::Object(members),
            },
            p.saturating_add(1),
        ));
    }

    loop {
        p = skip_ws(bytes, p);
        if bytes.get(p).copied() != Some(b'"') {
            return Err("GRDR-AGENTS-0003: expected JSON object key".into());
        }
        let key_start = p;
        let key_end = scan_string(bytes, key_start)?;
        let key_raw = raw
            .get(key_start..key_end)
            .ok_or_else(|| "GRDR-AGENTS-0003: invalid key span".to_string())?;
        let key_name: String = serde_json::from_str(key_raw)
            .map_err(|e| format!("GRDR-AGENTS-0003: invalid JSON key string: {e}"))?;

        p = skip_ws(bytes, key_end);
        if bytes.get(p).copied() != Some(b':') {
            return Err("GRDR-AGENTS-0003: expected ':' in JSON object".into());
        }
        let (value, next) = parse_value(raw, bytes, p.saturating_add(1))?;
        members.push(JsonMember {
            key_start,
            key_name,
            value,
        });
        p = skip_ws(bytes, next);
        match bytes.get(p).copied() {
            Some(b'}') => {
                let end = p.saturating_add(1);
                return Ok((
                    JsonNode {
                        start,
                        end,
                        kind: JsonKind::Object(members),
                    },
                    end,
                ));
            }
            Some(b',') => p = p.saturating_add(1),
            _ => return Err("GRDR-AGENTS-0003: expected ',' or '}' in JSON object".into()),
        }
    }
}

fn parse_array(raw: &str, bytes: &[u8], start: usize) -> Result<(JsonNode, usize), String> {
    let mut p = skip_ws(bytes, start.saturating_add(1));
    let mut items = Vec::new();
    if bytes.get(p).copied() == Some(b']') {
        return Ok((
            JsonNode {
                start,
                end: p.saturating_add(1),
                kind: JsonKind::Array(items),
            },
            p.saturating_add(1),
        ));
    }

    loop {
        let (item, next) = parse_value(raw, bytes, p)?;
        items.push(item);
        p = skip_ws(bytes, next);
        match bytes.get(p).copied() {
            Some(b']') => {
                let end = p.saturating_add(1);
                return Ok((
                    JsonNode {
                        start,
                        end,
                        kind: JsonKind::Array(items),
                    },
                    end,
                ));
            }
            Some(b',') => p = p.saturating_add(1),
            _ => return Err("GRDR-AGENTS-0003: expected ',' or ']' in JSON array".into()),
        }
    }
}

fn scan_string(bytes: &[u8], start: usize) -> Result<usize, String> {
    let mut p = start.saturating_add(1);
    while let Some(b) = bytes.get(p).copied() {
        if b == b'\\' {
            p = p.saturating_add(2);
            continue;
        }
        if b == b'"' {
            return Ok(p.saturating_add(1));
        }
        p = p.saturating_add(1);
    }
    Err("GRDR-AGENTS-0003: unterminated JSON string".into())
}

fn scan_scalar(bytes: &[u8], start: usize) -> Result<usize, String> {
    let mut p = start;
    while let Some(b) = bytes.get(p).copied() {
        if matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
            break;
        }
        p = p.saturating_add(1);
    }
    if p == start {
        return Err("GRDR-AGENTS-0003: empty JSON scalar".into());
    }
    Ok(p)
}

fn skip_ws(bytes: &[u8], mut pos: usize) -> usize {
    while let Some(b) = bytes.get(pos).copied() {
        if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            break;
        }
        pos = pos.saturating_add(1);
    }
    pos
}
