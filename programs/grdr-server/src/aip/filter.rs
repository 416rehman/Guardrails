// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

pub const MAX_FILTER_TERMS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterFieldType {
    Text,
    Bool,
    U64,
    Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterFieldSpec {
    pub name: &'static str,
    pub ty: FilterFieldType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterValue {
    Text(String),
    Bool(bool),
    U64(u64),
    Timestamp(Timestamp),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Has,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterExpr {
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
    Compare {
        field: String,
        op: CompareOp,
        value: FilterValue,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    Syntax(String),
    TooManyTerms(usize),
    UnknownField(String),
    TypeMismatch {
        field: String,
        expected: &'static str,
    },
    BareLiteralDisallowed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Quoted(String),
    Op(CompareOp),
    LParen,
    RParen,
    Minus,
    And,
    Or,
    Not,
}

pub trait FilterRecord {
    fn field_value(&self, field: &str) -> Option<FilterValue>;
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    terms: usize,
    allowed: &'a [FilterFieldSpec],
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syntax(msg) => write!(f, "invalid filter syntax: {msg}"),
            Self::TooManyTerms(n) => {
                write!(f, "filter exceeds {MAX_FILTER_TERMS} term limit (got {n})")
            }
            Self::UnknownField(field) => {
                write!(f, "field '{field}' is not filterable on this resource")
            }
            Self::TypeMismatch { field, expected } => {
                write!(f, "field '{field}' expects {expected} value")
            }
            Self::BareLiteralDisallowed(lit) => {
                write!(
                    f,
                    "bare literal '{lit}' is not allowed; specify field operator value"
                )
            }
        }
    }
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let tok = self.tokens.get(self.pos);
        if tok.is_some() {
            self.pos = self.pos.saturating_add(1);
        }
        tok
    }

    fn parse_or(&mut self) -> Result<FilterExpr, FilterError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.advance();
            let right = self.parse_and()?;
            left = FilterExpr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<FilterExpr, FilterError> {
        let mut left = self.parse_unary()?;
        loop {
            if matches!(self.peek(), Some(Token::And)) {
                self.advance();
                let right = self.parse_unary()?;
                left = FilterExpr::And(Box::new(left), Box::new(right));
            } else if matches!(
                self.peek(),
                Some(
                    Token::Ident(_) | Token::Quoted(_) | Token::LParen | Token::Not | Token::Minus
                )
            ) {
                let right = self.parse_unary()?;
                left = FilterExpr::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<FilterExpr, FilterError> {
        if matches!(self.peek(), Some(Token::Not | Token::Minus)) {
            self.advance();
            let inner = self.parse_unary()?;
            return Ok(FilterExpr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<FilterExpr, FilterError> {
        if matches!(self.peek(), Some(Token::LParen)) {
            self.advance();
            let inner = self.parse_or()?;
            if !matches!(self.advance(), Some(Token::RParen)) {
                return Err(FilterError::Syntax("unclosed '(' in filter".into()));
            }
            return Ok(inner);
        }

        let field = match self.advance() {
            Some(Token::Ident(name)) => name.clone(),
            Some(Token::Quoted(lit)) => {
                return Err(FilterError::BareLiteralDisallowed(lit.clone()));
            }
            Some(other) => {
                return Err(FilterError::Syntax(format!(
                    "unexpected token {other:?} in filter"
                )));
            }
            None => return Err(FilterError::Syntax("unexpected end of filter".into())),
        };

        let Some(Token::Op(op)) = self.peek().cloned() else {
            return Err(FilterError::BareLiteralDisallowed(field));
        };
        self.advance();

        let raw_val = match self.advance() {
            Some(Token::Ident(s) | Token::Quoted(s)) => s.clone(),
            _ => {
                return Err(FilterError::Syntax(format!(
                    "expected comparison value after '{field}'"
                )));
            }
        };

        self.terms = self.terms.saturating_add(1);
        if self.terms > MAX_FILTER_TERMS {
            return Err(FilterError::TooManyTerms(self.terms));
        }

        let Some(spec) = self.allowed.iter().find(|s| s.name == field) else {
            return Err(FilterError::UnknownField(field));
        };

        let typed = parse_typed_value(&field, spec.ty, op, &raw_val)?;
        Ok(FilterExpr::Compare {
            field,
            op,
            value: typed,
        })
    }
}

pub fn parse_filter(
    raw: &str,
    allowed: &[FilterFieldSpec],
) -> Result<Option<FilterExpr>, FilterError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let tokens = tokenize(trimmed)?;
    if tokens.is_empty() {
        return Ok(None);
    }
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
        terms: 0,
        allowed,
    };
    let expr = parser.parse_or()?;
    if let Some(extra) = parser.peek() {
        return Err(FilterError::Syntax(format!(
            "unexpected trailing token {extra:?}"
        )));
    }
    Ok(Some(expr))
}

pub fn eval_filter(expr: &FilterExpr, record: &dyn FilterRecord) -> bool {
    match expr {
        FilterExpr::And(a, b) => eval_filter(a, record) && eval_filter(b, record),
        FilterExpr::Or(a, b) => eval_filter(a, record) || eval_filter(b, record),
        FilterExpr::Not(inner) => !eval_filter(inner, record),
        FilterExpr::Compare { field, op, value } => {
            let Some(actual) = record.field_value(field) else {
                return false;
            };
            compare_values(&actual, *op, value)
        }
    }
}

fn compare_values(actual: &FilterValue, op: CompareOp, expected: &FilterValue) -> bool {
    match (actual, expected) {
        (FilterValue::Text(a), FilterValue::Text(b)) => {
            let a_l = a.to_ascii_lowercase();
            let b_l = b.to_ascii_lowercase();
            match op {
                CompareOp::Eq => a_l == b_l,
                CompareOp::Ne => a_l != b_l,
                CompareOp::Lt => a_l < b_l,
                CompareOp::Le => a_l <= b_l,
                CompareOp::Gt => a_l > b_l,
                CompareOp::Ge => a_l >= b_l,
                CompareOp::Has => a_l.contains(&b_l),
            }
        }
        (FilterValue::Bool(a), FilterValue::Bool(b)) => match op {
            CompareOp::Eq | CompareOp::Has => a == b,
            CompareOp::Ne => a != b,
            _ => false,
        },
        (FilterValue::U64(a), FilterValue::U64(b)) => match op {
            CompareOp::Eq | CompareOp::Has => a == b,
            CompareOp::Ne => a != b,
            CompareOp::Lt => a < b,
            CompareOp::Le => a <= b,
            CompareOp::Gt => a > b,
            CompareOp::Ge => a >= b,
        },
        (FilterValue::Timestamp(a), FilterValue::Timestamp(b)) => match op {
            CompareOp::Eq | CompareOp::Has => a == b,
            CompareOp::Ne => a != b,
            CompareOp::Lt => a < b,
            CompareOp::Le => a <= b,
            CompareOp::Gt => a > b,
            CompareOp::Ge => a >= b,
        },
        _ => false,
    }
}

fn parse_typed_value(
    field: &str,
    ty: FilterFieldType,
    op: CompareOp,
    raw: &str,
) -> Result<FilterValue, FilterError> {
    match ty {
        FilterFieldType::Text => Ok(FilterValue::Text(raw.to_string())),
        FilterFieldType::Bool => {
            if !matches!(op, CompareOp::Eq | CompareOp::Ne | CompareOp::Has) {
                return Err(FilterError::TypeMismatch {
                    field: field.into(),
                    expected: "boolean equality",
                });
            }
            match raw.to_ascii_lowercase().as_str() {
                "true" => Ok(FilterValue::Bool(true)),
                "false" => Ok(FilterValue::Bool(false)),
                _ => Err(FilterError::TypeMismatch {
                    field: field.into(),
                    expected: "true or false",
                }),
            }
        }
        FilterFieldType::U64 => {
            raw.parse::<u64>()
                .map(FilterValue::U64)
                .map_err(|_| FilterError::TypeMismatch {
                    field: field.into(),
                    expected: "unsigned integer",
                })
        }
        FilterFieldType::Timestamp => raw
            .parse::<Timestamp>()
            .map(FilterValue::Timestamp)
            .map_err(|_| FilterError::TypeMismatch {
                field: field.into(),
                expected: "RFC 3339 timestamp",
            }),
    }
}

fn tokenize(input: &str) -> Result<Vec<Token>, FilterError> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(ch) = chars.get(i).copied() {
        if ch.is_whitespace() {
            i = i.saturating_add(1);
            continue;
        }
        match ch {
            '(' => {
                out.push(Token::LParen);
                i = i.saturating_add(1);
            }
            ')' => {
                out.push(Token::RParen);
                i = i.saturating_add(1);
            }
            ':' => {
                out.push(Token::Op(CompareOp::Has));
                i = i.saturating_add(1);
            }
            '=' => {
                out.push(Token::Op(CompareOp::Eq));
                i = i.saturating_add(1);
            }
            '!' => {
                if chars.get(i.saturating_add(1)) == Some(&'=') {
                    out.push(Token::Op(CompareOp::Ne));
                    i = i.saturating_add(2);
                } else {
                    return Err(FilterError::Syntax("expected '!='".into()));
                }
            }
            '<' => {
                if chars.get(i.saturating_add(1)) == Some(&'=') {
                    out.push(Token::Op(CompareOp::Le));
                    i = i.saturating_add(2);
                } else {
                    out.push(Token::Op(CompareOp::Lt));
                    i = i.saturating_add(1);
                }
            }
            '>' => {
                if chars.get(i.saturating_add(1)) == Some(&'=') {
                    out.push(Token::Op(CompareOp::Ge));
                    i = i.saturating_add(2);
                } else {
                    out.push(Token::Op(CompareOp::Gt));
                    i = i.saturating_add(1);
                }
            }
            '-' => {
                out.push(Token::Minus);
                i = i.saturating_add(1);
            }
            '"' | '\'' => {
                let quote = ch;
                i = i.saturating_add(1);
                let mut val = String::new();
                let mut closed = false;
                while let Some(qch) = chars.get(i).copied() {
                    i = i.saturating_add(1);
                    if qch == '\\' {
                        if let Some(esc) = chars.get(i).copied() {
                            val.push(esc);
                            i = i.saturating_add(1);
                        } else {
                            return Err(FilterError::Syntax("dangling escape in string".into()));
                        }
                    } else if qch == quote {
                        closed = true;
                        break;
                    } else {
                        val.push(qch);
                    }
                }
                if !closed {
                    return Err(FilterError::Syntax("unterminated quoted string".into()));
                }
                out.push(Token::Quoted(val));
            }
            _ => {
                let mut ident = String::new();
                while let Some(ich) = chars.get(i).copied() {
                    if ich.is_whitespace() || matches!(ich, '(' | ')' | '=' | '!' | '<' | '>' | ':')
                    {
                        break;
                    }
                    ident.push(ich);
                    i = i.saturating_add(1);
                }
                match ident.as_str() {
                    "AND" => out.push(Token::And),
                    "OR" => out.push(Token::Or),
                    "NOT" => out.push(Token::Not),
                    _ => out.push(Token::Ident(ident)),
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct MapFilterRecord(BTreeMap<&'static str, FilterValue>);

    impl FilterRecord for MapFilterRecord {
        fn field_value(&self, field: &str) -> Option<FilterValue> {
            self.0.get(field).cloned()
        }
    }

    fn specs() -> &'static [FilterFieldSpec] {
        &[
            FilterFieldSpec {
                name: "os",
                ty: FilterFieldType::Text,
            },
            FilterFieldSpec {
                name: "online",
                ty: FilterFieldType::Bool,
            },
            FilterFieldSpec {
                name: "blocked_count",
                ty: FilterFieldType::U64,
            },
            FilterFieldSpec {
                name: "last_seen",
                ty: FilterFieldType::Timestamp,
            },
        ]
    }

    #[test]
    fn parses_and_evaluates_compound_aip160_filter() {
        let expr = parse_filter(
            r#"os = "macos" AND (online = true OR blocked_count >= 5) AND NOT os:win"#,
            specs(),
        )
        .unwrap()
        .unwrap();

        let rec = MapFilterRecord(BTreeMap::from([
            ("os", FilterValue::Text("macos".into())),
            ("online", FilterValue::Bool(true)),
            ("blocked_count", FilterValue::U64(1)),
        ]));
        assert!(eval_filter(&expr, &rec));
    }

    #[test]
    fn rejects_bare_literals_unknown_fields_and_excess_terms() {
        assert!(matches!(
            parse_filter("macos", specs()),
            Err(FilterError::BareLiteralDisallowed(_))
        ));
        assert!(matches!(
            parse_filter("target = '/etc/passwd'", specs()),
            Err(FilterError::UnknownField(_))
        ));
        assert!(matches!(
            parse_filter("online = maybe", specs()),
            Err(FilterError::TypeMismatch { .. })
        ));
        let many = (0..17)
            .map(|i| format!("blocked_count = {i}"))
            .collect::<Vec<_>>()
            .join(" AND ");
        assert!(matches!(
            parse_filter(&many, specs()),
            Err(FilterError::TooManyTerms(17))
        ));
    }
}
