// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Statement-level `.proto` AST parser supporting full source-to-descriptor parity (`SL09`).

use std::collections::{BTreeMap, BTreeSet};

use grdr_proto::descriptor::FieldLabel;

use crate::proto_option_lex::{
    find_char_outside_quotes, remove_all_ws, strip_keyword, unquote_simple,
};

#[derive(Default)]
pub(crate) struct SrcMsg {
    pub(crate) messages: BTreeMap<String, SrcMsg>,
    pub(crate) enums: BTreeMap<String, Vec<SrcEnumVal>>,
    pub(crate) fields: Vec<SrcField>,
    pub(crate) oneofs: Vec<String>,
    pub(crate) reserved: Vec<(i32, i32)>,
    pub(crate) extension_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SrcField {
    pub(crate) name: String,
    pub(crate) number: i32,
    pub(crate) label: FieldLabel,
    pub(crate) type_token: String,
    pub(crate) oneof_group: Option<String>,
    pub(crate) options_raw: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SrcEnumVal {
    pub(crate) name: String,
    pub(crate) number: i32,
    pub(crate) options_raw: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SrcRpc {
    pub(crate) name: String,
    pub(crate) input_type: String,
    pub(crate) client_streaming: bool,
    pub(crate) output_type: String,
    pub(crate) server_streaming: bool,
    pub(crate) options: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SrcExtend {
    pub(crate) extendee: String,
    pub(crate) type_token: String,
    pub(crate) name: String,
    pub(crate) number: i32,
}

pub(crate) struct ParsedProtoFile {
    pub(crate) syntax: Option<String>,
    pub(crate) package: Option<String>,
    pub(crate) imports: BTreeSet<String>,
    pub(crate) public_imports: BTreeSet<String>,
    pub(crate) weak_imports: BTreeSet<String>,
    pub(crate) root_msgs: BTreeMap<String, SrcMsg>,
    pub(crate) root_enums: BTreeMap<String, Vec<SrcEnumVal>>,
    pub(crate) root_svcs: BTreeMap<String, Vec<SrcRpc>>,
    pub(crate) root_extends: Vec<SrcExtend>,
}

enum ScopeEntry {
    Msg(String, SrcMsg),
    Oneof(String),
    Enum(String, Vec<SrcEnumVal>),
    Service(String, Vec<SrcRpc>),
    Rpc(SrcRpc),
    Extend(String, Vec<(String, String, i32)>),
    Other,
}

pub(crate) fn parse_proto_statements(stmts: &[(usize, String)]) -> ParsedProtoFile {
    let syntax = stmts
        .iter()
        .find_map(|(_, s)| extract_quoted_rhs(s, "syntax"));
    let package = stmts.iter().find_map(|(_, s)| {
        let rest = strip_keyword(s.trim().strip_suffix(';')?, "package")?;
        Some(remove_all_ws(rest))
    });

    let mut out = ParsedProtoFile {
        syntax,
        package,
        imports: BTreeSet::new(),
        public_imports: BTreeSet::new(),
        weak_imports: BTreeSet::new(),
        root_msgs: BTreeMap::new(),
        root_enums: BTreeMap::new(),
        root_svcs: BTreeMap::new(),
        root_extends: Vec::new(),
    };
    let mut stack: Vec<ScopeEntry> = Vec::new();

    for (_, code) in stmts {
        if code == "}" {
            if let Some(popped) = stack.pop() {
                finish_scope(popped, &mut stack, &mut out);
            }
            continue;
        }
        if stack.is_empty()
            && let Some((kind, path)) = parse_import_stmt(code)
        {
            out.imports.insert(path.clone());
            if kind == "public" {
                out.public_imports.insert(path);
            } else if kind == "weak" {
                out.weak_imports.insert(path);
            }
            continue;
        }
        if let Some(name) = parse_header_name(code, "message") {
            stack.push(ScopeEntry::Msg(name, SrcMsg::default()));
            continue;
        }
        if let Some(name) = parse_header_name(code, "enum") {
            stack.push(ScopeEntry::Enum(name, Vec::new()));
            continue;
        }
        if let Some(name) = parse_header_name(code, "service") {
            stack.push(ScopeEntry::Service(name, Vec::new()));
            continue;
        }
        if let Some(target) = parse_header_name(code, "extend") {
            stack.push(ScopeEntry::Extend(target, Vec::new()));
            continue;
        }
        if let Some(oneof_name) = parse_header_name(code, "oneof") {
            stack.push(ScopeEntry::Oneof(oneof_name));
            continue;
        }
        if code.ends_with('{') {
            if matches!(stack.last(), Some(ScopeEntry::Service(_, _)))
                && let Some(rpc) = parse_rpc_header(code)
            {
                stack.push(ScopeEntry::Rpc(rpc));
            } else {
                stack.push(ScopeEntry::Other);
            }
            continue;
        }

        match stack.last_mut() {
            Some(ScopeEntry::Msg(_, msg)) => parse_msg_statement(code, msg),
            Some(ScopeEntry::Oneof(oneof_name)) => {
                if let Some(field) = parse_field_decl(code, Some(oneof_name.clone()))
                    && let Some(ScopeEntry::Msg(_, msg)) = stack.iter_mut().rev().nth(1)
                {
                    msg.fields.push(field);
                }
            }
            Some(ScopeEntry::Enum(_, vals)) => {
                if let Some(ev) = parse_enum_value_decl(code) {
                    vals.push(ev);
                }
            }
            Some(ScopeEntry::Extend(_, fields)) => {
                if let Some(f) = parse_field_decl(code, None) {
                    fields.push((f.type_token, f.name, f.number));
                }
            }
            Some(ScopeEntry::Service(_, rpcs)) => {
                if let Some(rpc) = parse_rpc_header(code) {
                    rpcs.push(rpc);
                }
            }
            Some(ScopeEntry::Rpc(rpc)) => rpc.options.push(code.clone()),
            Some(ScopeEntry::Other) | None => {}
        }
    }
    out
}

fn finish_scope(popped: ScopeEntry, stack: &mut [ScopeEntry], out: &mut ParsedProtoFile) {
    match popped {
        ScopeEntry::Msg(name, msg) => match stack.last_mut() {
            Some(ScopeEntry::Msg(_, parent)) => {
                parent.messages.insert(name, msg);
            }
            _ => {
                out.root_msgs.insert(name, msg);
            }
        },
        ScopeEntry::Oneof(name) => {
            if let Some(ScopeEntry::Msg(_, parent)) = stack.last_mut() {
                parent.oneofs.push(name);
            }
        }
        ScopeEntry::Enum(name, vals) => match stack.last_mut() {
            Some(ScopeEntry::Msg(_, parent)) => {
                parent.enums.insert(name, vals);
            }
            _ => {
                out.root_enums.insert(name, vals);
            }
        },
        ScopeEntry::Extend(target, fields) => {
            if let Some(ScopeEntry::Msg(_, parent)) = stack.last_mut() {
                parent.extension_count = parent.extension_count.saturating_add(fields.len());
            } else {
                for (type_token, name, number) in fields {
                    out.root_extends.push(SrcExtend {
                        extendee: target.clone(),
                        type_token,
                        name,
                        number,
                    });
                }
            }
        }
        ScopeEntry::Rpc(rpc) => {
            if let Some(ScopeEntry::Service(_, rpcs)) = stack.last_mut() {
                rpcs.push(rpc);
            }
        }
        ScopeEntry::Service(name, rpcs) => {
            out.root_svcs.insert(name, rpcs);
        }
        ScopeEntry::Other => {}
    }
}

fn parse_msg_statement(code: &str, msg: &mut SrcMsg) {
    if code.starts_with("option ") || code.starts_with("option\t") {
        return;
    }
    if code.starts_with("reserved ") || code.starts_with("reserved\t") {
        if let Some(rest) = code.trim_start_matches("reserved").trim().strip_suffix(';') {
            for part in rest.split(',') {
                let p = part.trim();
                if p.starts_with('"') || p.starts_with('\'') {
                    continue;
                }
                if let Some((a_s, b_s)) = p.split_once("to") {
                    if let (Ok(a), Ok(b)) = (
                        a_s.trim().parse::<i32>(),
                        if b_s.trim() == "max" {
                            Ok(536_870_911)
                        } else {
                            b_s.trim().parse::<i32>()
                        },
                    ) {
                        msg.reserved.push((a, b));
                    }
                } else if let Ok(v) = p.parse::<i32>() {
                    msg.reserved.push((v, v));
                }
            }
        }
        return;
    }
    if let Some(f) = parse_field_decl(code, None) {
        msg.fields.push(f);
    }
}

fn parse_field_decl(code: &str, oneof_group: Option<String>) -> Option<SrcField> {
    let stmt = code.trim().strip_suffix(';')?;
    let (lhs, opts_raw) = if let Some(b_start) = find_char_outside_quotes(stmt, '[') {
        let before = stmt.get(..b_start)?.trim();
        let after = stmt.get(b_start..)?.trim();
        (before, after.to_owned())
    } else {
        (stmt, String::new())
    };
    let (head, num_str) = lhs.rsplit_once('=')?;
    let number = num_str.trim().parse::<i32>().ok()?;
    let head = head.trim();
    let (label, rest) = if oneof_group.is_some() {
        (FieldLabel::Optional, head)
    } else if let Some(r) = strip_keyword(head, "repeated") {
        (FieldLabel::Repeated, r)
    } else if let Some(r) = strip_keyword(head, "optional") {
        (FieldLabel::Optional, r)
    } else if let Some(r) = strip_keyword(head, "required") {
        (FieldLabel::Required, r)
    } else {
        (FieldLabel::Optional, head)
    };
    let (ty_part, name_part) = split_type_and_name(rest)?;
    let label = if ty_part.starts_with("map<") {
        FieldLabel::Repeated
    } else {
        label
    };
    Some(SrcField {
        name: name_part,
        number,
        label,
        type_token: ty_part,
        oneof_group,
        options_raw: opts_raw,
    })
}

fn split_type_and_name(rest: &str) -> Option<(String, String)> {
    let mut split_at = None;
    let mut angle = 0usize;
    for (idx, ch) in rest.char_indices() {
        match ch {
            '<' => angle = angle.saturating_add(1),
            '>' => angle = angle.saturating_sub(1),
            c if c.is_ascii_whitespace() && angle == 0 => split_at = Some(idx),
            _ => {}
        }
    }
    let pos = split_at?;
    let ty = remove_all_ws(rest.get(..pos)?);
    let name = rest.get(pos..)?.trim().to_owned();
    if ty.is_empty() || name.is_empty() {
        None
    } else {
        Some((ty, name))
    }
}

fn parse_enum_value_decl(code: &str) -> Option<SrcEnumVal> {
    let stmt = code.trim().strip_suffix(';')?;
    if stmt.starts_with("option ") || stmt.starts_with("option\t") || stmt.starts_with("reserved") {
        return None;
    }
    let (lhs, opts) = if let Some(idx) = find_char_outside_quotes(stmt, '[') {
        (stmt.get(..idx)?.trim(), stmt.get(idx..)?.trim())
    } else {
        (stmt, "")
    };
    let (name_raw, num_raw) = lhs.split_once('=')?;
    let number = num_raw.trim().parse::<i32>().ok()?;
    Some(SrcEnumVal {
        name: name_raw.trim().to_owned(),
        number,
        options_raw: opts.to_owned(),
    })
}

fn extract_quoted_rhs(code: &str, kw: &str) -> Option<String> {
    let rest = strip_keyword(code.trim().strip_suffix(';')?, kw)?;
    let rhs = rest.strip_prefix('=')?.trim();
    unquote_simple(rhs)
}

fn parse_import_stmt(code: &str) -> Option<(String, String)> {
    let rest = strip_keyword(code.trim().strip_suffix(';')?, "import")?;
    let (kind, path_raw) = if let Some(r) = strip_keyword(rest, "public") {
        ("public", r)
    } else if let Some(r) = strip_keyword(rest, "weak") {
        ("weak", r)
    } else {
        ("normal", rest)
    };
    Some((kind.to_owned(), unquote_simple(path_raw)?))
}

fn parse_header_name(code: &str, kw: &str) -> Option<String> {
    let trimmed = code.trim();
    if !trimmed.ends_with('{') {
        return None;
    }
    let rest = strip_keyword(trimmed.strip_suffix('{')?.trim(), kw)?;
    if rest.is_empty() {
        None
    } else {
        Some(rest.split_whitespace().next()?.to_owned())
    }
}

fn parse_rpc_param(raw: &str) -> Option<(bool, String)> {
    let s = raw.trim();
    let (stream, type_raw) = if let Some(rest) = s
        .strip_prefix("stream")
        .filter(|r| r.chars().next().is_some_and(char::is_whitespace))
    {
        (true, rest)
    } else {
        (false, s)
    };
    let ty = remove_all_ws(type_raw);
    if ty.is_empty() {
        None
    } else {
        Some((stream, ty))
    }
}

fn parse_rpc_header(code: &str) -> Option<SrcRpc> {
    let rest = strip_keyword(code.trim(), "rpc")?;
    let open1 = rest.find('(')?;
    let name = rest.get(..open1)?.trim();
    if name.is_empty() {
        return None;
    }
    let after1 = rest.get(open1.saturating_add(1)..)?;
    let close1 = after1.find(')')?;
    let (client_streaming, input_type) = parse_rpc_param(after1.get(..close1)?)?;
    let after_in = after1.get(close1.saturating_add(1)..)?.trim_start();
    let after_ret = after_in
        .strip_prefix("returns")
        .filter(|r| {
            r.chars()
                .next()
                .is_some_and(|c| c.is_ascii_whitespace() || c == '(')
        })?
        .trim_start();
    let after2 = after_ret.strip_prefix('(')?;
    let close2 = after2.find(')')?;
    let (server_streaming, output_type) = parse_rpc_param(after2.get(..close2)?)?;
    Some(SrcRpc {
        name: name.to_owned(),
        input_type,
        client_streaming,
        output_type,
        server_streaming,
        options: Vec::new(),
    })
}
