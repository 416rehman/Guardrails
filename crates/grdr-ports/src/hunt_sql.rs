// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::CodedError;

use crate::events::CODE_LAKE_INVALID_QUERY;

#[derive(Debug, Clone, PartialEq, Eq)]
enum SqlToken {
    Word(String),
    Str(String),
    Comma,
    Star,
    Eq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuntTable {
    Decision,
    Activity,
    Content,
    Events,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHunt {
    pub table: HuntTable,
    pub projection: Vec<String>,
    pub predicates: Vec<(String, String)>,
    pub sql_limit: Option<usize>,
}

pub fn parse_hunt_sql(sql: &str, include_content: bool) -> Result<ParsedHunt, CodedError> {
    let tokens = tokenize_hunt_sql(sql)?;
    let mut pos = 0usize;

    match tokens.get(pos) {
        Some(SqlToken::Word(w)) if w.eq_ignore_ascii_case("SELECT") => pos = pos.saturating_add(1),
        _ => {
            return Err(invalid_hunt_err(
                "Hunt queries must start with restricted SELECT.",
            ));
        }
    }

    let mut projection = Vec::new();
    match tokens.get(pos) {
        Some(SqlToken::Star) => {
            pos = pos.saturating_add(1);
        }
        Some(SqlToken::Word(_)) => loop {
            let Some(SqlToken::Word(col)) = tokens.get(pos) else {
                return Err(invalid_hunt_err("Invalid SELECT projection list."));
            };
            let trimmed = col.trim_matches('"');
            validate_hunt_column(trimmed, include_content)?;
            projection.push(trimmed.to_string());
            pos = pos.saturating_add(1);
            if matches!(tokens.get(pos), Some(SqlToken::Comma)) {
                pos = pos.saturating_add(1);
            } else {
                break;
            }
        },
        _ => return Err(invalid_hunt_err("Missing SELECT projection.")),
    }

    match tokens.get(pos) {
        Some(SqlToken::Word(w)) if w.eq_ignore_ascii_case("FROM") => pos = pos.saturating_add(1),
        _ => return Err(invalid_hunt_err("Hunt query must specify FROM <table>.")),
    }

    let table = match tokens.get(pos) {
        Some(SqlToken::Word(t)) => {
            pos = pos.saturating_add(1);
            match t.trim_matches('"').to_ascii_lowercase().as_str() {
                "decision" => HuntTable::Decision,
                "activity" => HuntTable::Activity,
                "content" => HuntTable::Content,
                "events" => HuntTable::Events,
                other => {
                    return Err(invalid_hunt_err(&format!(
                        "Unsupported Hunt table `{other}`; expected decision, activity, content, or events."
                    )));
                }
            }
        }
        _ => return Err(invalid_hunt_err("Missing table name after FROM.")),
    };

    let mut predicates = Vec::new();
    if matches!(tokens.get(pos), Some(SqlToken::Word(w)) if w.eq_ignore_ascii_case("WHERE")) {
        pos = pos.saturating_add(1);
        loop {
            let Some(SqlToken::Word(col)) = tokens.get(pos) else {
                return Err(invalid_hunt_err(
                    "Expected column identifier in WHERE clause.",
                ));
            };
            let col_name = col.trim_matches('"');
            validate_hunt_column(col_name, include_content)?;
            pos = pos.saturating_add(1);
            if !matches!(tokens.get(pos), Some(SqlToken::Eq)) {
                return Err(invalid_hunt_err(
                    "Hunt WHERE predicates only support `=` comparisons.",
                ));
            }
            pos = pos.saturating_add(1);
            let Some(SqlToken::Str(val)) = tokens.get(pos) else {
                return Err(invalid_hunt_err(
                    "Hunt WHERE value must be a single-quoted literal.",
                ));
            };
            predicates.push((col_name.to_string(), val.clone()));
            pos = pos.saturating_add(1);
            if matches!(tokens.get(pos), Some(SqlToken::Word(w)) if w.eq_ignore_ascii_case("AND")) {
                pos = pos.saturating_add(1);
            } else {
                break;
            }
        }
    }

    let mut sql_limit = None;
    if matches!(tokens.get(pos), Some(SqlToken::Word(w)) if w.eq_ignore_ascii_case("LIMIT")) {
        pos = pos.saturating_add(1);
        let Some(SqlToken::Word(n_str)) = tokens.get(pos) else {
            return Err(invalid_hunt_err("Expected positive integer after LIMIT."));
        };
        let n = n_str
            .parse::<usize>()
            .map_err(|_| invalid_hunt_err("Invalid integer in LIMIT clause."))?;
        sql_limit = Some(n);
        pos = pos.saturating_add(1);
    }

    if pos != tokens.len() {
        return Err(invalid_hunt_err(
            "Unexpected trailing SQL clause in Hunt query.",
        ));
    }

    Ok(ParsedHunt {
        table,
        projection,
        predicates,
        sql_limit,
    })
}

fn validate_hunt_column(col: &str, include_content: bool) -> Result<(), CodedError> {
    if col.is_empty()
        || !col
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
    {
        return Err(invalid_hunt_err(&format!(
            "Invalid identifier `{col}` in Hunt query."
        )));
    }
    if !include_content && col.to_ascii_lowercase().starts_with("content.") {
        return Err(invalid_hunt_err(
            "Hunt query cannot reference `content.*` columns when include_content is false.",
        ));
    }
    Ok(())
}

fn tokenize_hunt_sql(sql: &str) -> Result<Vec<SqlToken>, CodedError> {
    let chars: Vec<char> = sql.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while let Some(&ch) = chars.get(i) {
        if ch.is_whitespace() {
            i = i.saturating_add(1);
            continue;
        }
        if ch == ';' || ch == '\0' {
            return Err(invalid_hunt_err("Forbidden SQL separator in Hunt query."));
        }
        if ch == '-' && chars.get(i.saturating_add(1)) == Some(&'-') {
            return Err(invalid_hunt_err(
                "SQL comments are forbidden in Hunt query.",
            ));
        }
        if ch == '/' && chars.get(i.saturating_add(1)) == Some(&'*') {
            return Err(invalid_hunt_err(
                "SQL block comments are forbidden in Hunt query.",
            ));
        }
        if ch == '\'' {
            i = i.saturating_add(1);
            let mut literal = String::new();
            let mut closed = false;
            while let Some(&c) = chars.get(i) {
                if c == '\'' {
                    if chars.get(i.saturating_add(1)) == Some(&'\'') {
                        literal.push('\'');
                        i = i.saturating_add(2);
                    } else {
                        closed = true;
                        i = i.saturating_add(1);
                        break;
                    }
                } else {
                    literal.push(c);
                    i = i.saturating_add(1);
                }
            }
            if !closed {
                return Err(invalid_hunt_err(
                    "Unterminated string literal in Hunt query.",
                ));
            }
            tokens.push(SqlToken::Str(literal));
            continue;
        }
        if ch == ',' {
            tokens.push(SqlToken::Comma);
            i = i.saturating_add(1);
            continue;
        }
        if ch == '*' {
            tokens.push(SqlToken::Star);
            i = i.saturating_add(1);
            continue;
        }
        if ch == '=' {
            tokens.push(SqlToken::Eq);
            i = i.saturating_add(1);
            continue;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '"') {
            let mut word = String::new();
            while let Some(&c) = chars.get(i) {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '"') {
                    word.push(c);
                    i = i.saturating_add(1);
                } else {
                    break;
                }
            }
            for forbidden in [
                "drop", "delete", "insert", "update", "alter", "copy", "union", "into", "attach",
                "pragma", "create", "replace", "exec", "or",
            ] {
                if word.eq_ignore_ascii_case(forbidden) {
                    return Err(invalid_hunt_err(&format!(
                        "Forbidden SQL keyword `{word}` in Hunt query."
                    )));
                }
            }
            tokens.push(SqlToken::Word(word));
            continue;
        }
        return Err(invalid_hunt_err(&format!(
            "Unsupported token `{ch}` in Hunt query."
        )));
    }
    Ok(tokens)
}

fn invalid_hunt_err(msg: &str) -> CodedError {
    CodedError::new(
        CODE_LAKE_INVALID_QUERY,
        msg,
        "Use read-only `SELECT <cols> FROM <table|events> [WHERE <col> = '<val>'] [LIMIT <n>]` syntax.",
    )
}
