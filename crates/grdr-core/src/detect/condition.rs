// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Sigma boolean condition AST parser, quantifier matcher, and case-insensitive wildcard matching (`D-09`).

use std::collections::BTreeMap;

use crate::detect::eval::{CompiledSelection, eval_compiled_selection};
use crate::detect::types::{
    ConditionExpr, DetectError, EventView, MAX_CONDITION_DEPTH, SelectionBlock,
};

const MAX_CONDITION_TOKENS: usize = 256;

/// Parses and validates a Sigma `condition` expression against known `selections` up to `MAX_CONDITION_DEPTH`.
pub fn parse_condition_ast(
    cond: &str,
    selections: &BTreeMap<String, SelectionBlock>,
) -> Result<ConditionExpr, DetectError> {
    if selections.is_empty() {
        return Err(DetectError::InvalidRule(
            "Sigma detection requires at least one selection".into(),
        ));
    }
    let tokens = tokenize_condition(cond)?;
    if tokens.is_empty() {
        return Err(DetectError::InvalidRule(
            "Sigma detection condition cannot be empty".into(),
        ));
    }
    let mut pos: usize = 0;
    let ast = parse_or(&tokens, &mut pos, selections, 0)?;
    if pos != tokens.len() {
        let extra = tokens.get(pos).map_or("", String::as_str);
        return Err(DetectError::InvalidRule(format!(
            "unexpected trailing token `{extra}` in Sigma condition"
        )));
    }
    if ast_height(&ast) >= MAX_CONDITION_DEPTH {
        return Err(DetectError::InvalidRule(
            "Sigma condition AST depth exceeds evaluation limit".into(),
        ));
    }
    Ok(ast)
}

fn ast_height(expr: &ConditionExpr) -> usize {
    match expr {
        ConditionExpr::Sel(_) | ConditionExpr::Of { .. } => 1,
        ConditionExpr::Not(inner) => ast_height(inner).saturating_add(1),
        ConditionExpr::And(lhs, rhs) | ConditionExpr::Or(lhs, rhs) => {
            ast_height(lhs).max(ast_height(rhs)).saturating_add(1)
        }
    }
}

pub fn eval_condition_ast(
    expr: &ConditionExpr,
    selections: &BTreeMap<String, CompiledSelection>,
    ev: &EventView<'_>,
    depth: usize,
) -> bool {
    if depth >= MAX_CONDITION_DEPTH {
        return false;
    }
    match expr {
        ConditionExpr::Sel(name) => selections
            .get(name)
            .is_some_and(|s| eval_compiled_selection(s, ev)),
        ConditionExpr::Not(inner) => {
            !eval_condition_ast(inner, selections, ev, depth.saturating_add(1))
        }
        ConditionExpr::And(lhs, rhs) => {
            eval_condition_ast(lhs, selections, ev, depth.saturating_add(1))
                && eval_condition_ast(rhs, selections, ev, depth.saturating_add(1))
        }
        ConditionExpr::Or(lhs, rhs) => {
            eval_condition_ast(lhs, selections, ev, depth.saturating_add(1))
                || eval_condition_ast(rhs, selections, ev, depth.saturating_add(1))
        }
        ConditionExpr::Of { all, pattern } => {
            let mut matched_any = false;
            for (name, sel) in selections {
                if !sel_name_matches_pattern(name, pattern) {
                    continue;
                }
                matched_any = true;
                let hit = eval_compiled_selection(sel, ev);
                if *all && !hit {
                    return false;
                }
                if !*all && hit {
                    return true;
                }
            }
            *all && matched_any
        }
    }
}

pub fn sel_name_matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return !name.starts_with('_');
    }
    wildcard_match_ci(name, pattern)
}

pub fn wildcard_match_ci(text: &str, pat: &str) -> bool {
    let t: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    let mut p_tokens: Vec<(char, bool)> = Vec::new();
    let mut p_chars = pat.chars();
    while let Some(c) = p_chars.next() {
        if c == '\\' {
            if let Some(esc) = p_chars.next() {
                p_tokens.push((esc.to_ascii_lowercase(), false));
            } else {
                p_tokens.push(('\\', false));
            }
        } else if c == '*' || c == '?' {
            p_tokens.push((c, true));
        } else {
            p_tokens.push((c.to_ascii_lowercase(), false));
        }
    }
    let (mut ti, mut pi) = (0_usize, 0_usize);
    let (mut star_pi, mut match_ti) = (None::<usize>, 0_usize);
    while ti < t.len() {
        if let Some(&(pc, is_wc)) = p_tokens.get(pi) {
            if is_wc && pc == '*' {
                star_pi = Some(pi);
                match_ti = ti;
                pi = pi.saturating_add(1);
                continue;
            }
            let tc = t.get(ti).copied().unwrap_or('\0');
            if (is_wc && pc == '?') || tc == pc {
                ti = ti.saturating_add(1);
                pi = pi.saturating_add(1);
                continue;
            }
        }
        if let Some(sp) = star_pi {
            pi = sp.saturating_add(1);
            match_ti = match_ti.saturating_add(1);
            ti = match_ti;
        } else {
            return false;
        }
    }
    while p_tokens.get(pi).is_some_and(|&(pc, wc)| wc && pc == '*') {
        pi = pi.saturating_add(1);
    }
    pi == p_tokens.len()
}

fn parse_or(
    tokens: &[String],
    pos: &mut usize,
    selections: &BTreeMap<String, SelectionBlock>,
    depth: usize,
) -> Result<ConditionExpr, DetectError> {
    if depth >= MAX_CONDITION_DEPTH {
        return Err(DetectError::InvalidRule(
            "Sigma condition depth exceeded".into(),
        ));
    }
    let mut lhs = parse_and(tokens, pos, selections, depth.saturating_add(1))?;
    while tokens
        .get(*pos)
        .is_some_and(|t| t.eq_ignore_ascii_case("or"))
    {
        *pos = pos.saturating_add(1);
        let rhs = parse_and(tokens, pos, selections, depth.saturating_add(1))?;
        lhs = ConditionExpr::Or(Box::new(lhs), Box::new(rhs));
    }
    Ok(lhs)
}

fn parse_and(
    tokens: &[String],
    pos: &mut usize,
    selections: &BTreeMap<String, SelectionBlock>,
    depth: usize,
) -> Result<ConditionExpr, DetectError> {
    if depth >= MAX_CONDITION_DEPTH {
        return Err(DetectError::InvalidRule(
            "Sigma condition depth exceeded".into(),
        ));
    }
    let mut lhs = parse_unary(tokens, pos, selections, depth.saturating_add(1))?;
    while tokens
        .get(*pos)
        .is_some_and(|t| t.eq_ignore_ascii_case("and"))
    {
        *pos = pos.saturating_add(1);
        let rhs = parse_unary(tokens, pos, selections, depth.saturating_add(1))?;
        lhs = ConditionExpr::And(Box::new(lhs), Box::new(rhs));
    }
    Ok(lhs)
}

fn parse_unary(
    tokens: &[String],
    pos: &mut usize,
    selections: &BTreeMap<String, SelectionBlock>,
    depth: usize,
) -> Result<ConditionExpr, DetectError> {
    if depth >= MAX_CONDITION_DEPTH {
        return Err(DetectError::InvalidRule(
            "Sigma condition depth exceeded".into(),
        ));
    }
    let tok = tokens
        .get(*pos)
        .ok_or_else(|| DetectError::InvalidRule("unexpected end of Sigma condition".into()))?;
    if tok.eq_ignore_ascii_case("not") {
        *pos = pos.saturating_add(1);
        let inner = parse_unary(tokens, pos, selections, depth.saturating_add(1))?;
        return Ok(ConditionExpr::Not(Box::new(inner)));
    }
    if tok == "(" {
        *pos = pos.saturating_add(1);
        let inner = parse_or(tokens, pos, selections, depth.saturating_add(1))?;
        if tokens.get(*pos).map(String::as_str) != Some(")") {
            return Err(DetectError::InvalidRule(
                "unclosed `(` in Sigma condition".into(),
            ));
        }
        *pos = pos.saturating_add(1);
        return Ok(inner);
    }
    if let (Some(quant), Some(of_tok), Some(pat)) = (
        tokens.get(*pos),
        tokens.get(pos.saturating_add(1)),
        tokens.get(pos.saturating_add(2)),
    ) && of_tok.eq_ignore_ascii_case("of")
    {
        let all = if quant.eq_ignore_ascii_case("all") {
            true
        } else if quant == "1" {
            false
        } else {
            return Err(DetectError::InvalidRule(format!(
                "unsupported Sigma quantifier `{quant} of {pat}`"
            )));
        };
        *pos = pos.saturating_add(3);
        let pattern = if pat.eq_ignore_ascii_case("them") {
            "*".to_owned()
        } else {
            pat.clone()
        };
        let has_match = selections
            .keys()
            .any(|k| sel_name_matches_pattern(k, &pattern));
        if !has_match {
            return Err(DetectError::InvalidRule(format!(
                "Sigma condition quantifier `{quant} of {pat}` matches zero selections"
            )));
        }
        return Ok(ConditionExpr::Of { all, pattern });
    }
    let ident = tok.clone();
    if ident == ")" || ident.eq_ignore_ascii_case("and") || ident.eq_ignore_ascii_case("or") {
        return Err(DetectError::InvalidRule(format!(
            "unexpected operator `{ident}` in Sigma condition"
        )));
    }
    if !selections.contains_key(&ident) {
        return Err(DetectError::InvalidRule(format!(
            "unknown selection `{ident}` referenced in Sigma condition"
        )));
    }
    *pos = pos.saturating_add(1);
    Ok(ConditionExpr::Sel(ident))
}

fn tokenize_condition(cond: &str) -> Result<Vec<String>, DetectError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in cond.chars() {
        if ch == '(' || ch == ')' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
                if out.len() > MAX_CONDITION_TOKENS {
                    return Err(DetectError::InvalidRule(
                        "Sigma condition exceeds maximum token budget".into(),
                    ));
                }
            }
            out.push(ch.to_string());
            if out.len() > MAX_CONDITION_TOKENS {
                return Err(DetectError::InvalidRule(
                    "Sigma condition exceeds maximum token budget".into(),
                ));
            }
        } else if ch.is_ascii_whitespace() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
                if out.len() > MAX_CONDITION_TOKENS {
                    return Err(DetectError::InvalidRule(
                        "Sigma condition exceeds maximum token budget".into(),
                    ));
                }
            }
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
        if out.len() > MAX_CONDITION_TOKENS {
            return Err(DetectError::InvalidRule(
                "Sigma condition exceeds maximum token budget".into(),
            ));
        }
    }
    Ok(out)
}
