//! Step 6 of `audits/README.md`: the runner, not the model, decides what a finder wrote. The report
//! must be a `finder` report of the prompt at the commit; a result whose class key is neither the
//! prompt's nor `injected-instruction` is rejected; every evidence span must match the file at the
//! commit from its cited line (indentation aside), and a result left with no span is dropped. Each
//! survivor gets its fingerprint: SHA-256 of `prompt_id|prompt_major|class_key|crate|item`.

use std::ops::RangeInclusive;

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::{Value, json};

use super::library::{Entry, INJECTED_INSTRUCTION};
use crate::orchestrate::issue::sha256_hex;

pub const FINDING_SCHEMA: &str = "audit-finding.v1";
const LABELS: &[&str] = &["CONFIRMED", "LIKELY", "SMELL"];
const SEVERITY_MINIMUM: &str = "/$defs/severity/minimum";
const SEVERITY_MAXIMUM: &str = "/$defs/severity/maximum";
const QUOTE_PATTERN: &str = "/$defs/quote/pattern";

/// What `audit-finding.v1` allows for a severity and a quote, read from the schema file the
/// library names, so the runner applies the schema's own rules.
#[derive(Debug, Clone)]
pub struct FindingFormat {
    pub severities: RangeInclusive<i64>,
    pub quote: Regex,
}

/// A result that survived the checks, with its fingerprint.
#[derive(Debug, Clone, PartialEq)]
pub struct Checked {
    pub fingerprint: String,
    pub result: Value,
    pub severity: i64,
}

/// What one refuting verifier decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub verdict: String,
    pub label: Option<String>,
    pub severity: Option<i64>,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CheckReport {
    pub returned: usize,
    pub kept: Vec<Checked>,
    pub problems: Vec<String>,
    pub checked_and_sound: Vec<Value>,
    pub not_applicable: Option<String>,
}

impl FindingFormat {
    pub fn parse(schema: &str) -> Result<FindingFormat> {
        let schema: Value =
            serde_json::from_str(schema).context("parsing the audit-finding schema")?;
        let field = |pointer: &str| {
            schema
                .pointer(pointer)
                .with_context(|| format!("the audit-finding schema has no {pointer}"))
        };
        let bound = |pointer: &str| -> Result<i64> {
            field(pointer)?
                .as_i64()
                .with_context(|| format!("the audit-finding schema's {pointer} is not an integer"))
        };
        let pattern = field(QUOTE_PATTERN)?
            .as_str()
            .with_context(|| format!("the audit-finding schema's {QUOTE_PATTERN} is not text"))?;
        Ok(FindingFormat {
            severities: bound(SEVERITY_MINIMUM)?..=bound(SEVERITY_MAXIMUM)?,
            quote: Regex::new(pattern).context("compiling the audit-finding quote pattern")?,
        })
    }
}

/// Checks a finder report against the prompt and the files at the commit.
pub fn check_finder(
    report: &Value,
    entry: &Entry,
    commit: &str,
    file_at: &dyn Fn(&str) -> Option<String>,
) -> CheckReport {
    let mut out = CheckReport::default();
    let text = |key: &str| report.get(key).and_then(Value::as_str);
    let shape = [
        (
            text("schema") == Some(FINDING_SCHEMA),
            "`schema` is not audit-finding.v1",
        ),
        (
            text("report") == Some("finder"),
            "`report` is not \"finder\"",
        ),
        (
            report.pointer("/prompt/id").and_then(Value::as_str) == Some(entry.id.as_str()),
            "`prompt.id` is not this prompt",
        ),
        (
            text("commit") == Some(commit),
            "`commit` is not the audited commit",
        ),
        (
            report.get("applicable").is_some_and(Value::is_boolean),
            "`applicable` is not a boolean",
        ),
    ];
    out.problems.extend(
        shape
            .iter()
            .filter(|(ok, _)| !ok)
            .map(|(_, problem)| (*problem).to_owned()),
    );
    if !out.problems.is_empty() {
        return out;
    }
    out.checked_and_sound = report
        .get("checked_and_sound")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if report.get("applicable") == Some(&Value::Bool(false)) {
        out.not_applicable = Some(
            text("not_applicable_reason")
                .unwrap_or("no reason given")
                .to_owned(),
        );
        return out;
    }
    let results = report
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    out.returned = results.len();
    for (index, result) in results.into_iter().take(entry.max_findings).enumerate() {
        match check_result(result, entry, file_at) {
            Ok(checked) => out.kept.push(checked),
            Err(problem) => out
                .problems
                .push(format!("result {}: {problem}", index + 1)),
        }
    }
    out
}

fn check_result(
    mut result: Value,
    entry: &Entry,
    file_at: &dyn Fn(&str) -> Option<String>,
) -> Result<Checked, String> {
    let class_key = result
        .get("class_key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if class_key != INJECTED_INSTRUCTION && !entry.class_keys.contains(&class_key) {
        return Err(format!(
            "class key `{class_key}` is not on the prompt's Class keys line"
        ));
    }
    let label_ok = result
        .get("label")
        .and_then(Value::as_str)
        .is_some_and(|label| LABELS.contains(&label));
    let severity = result
        .get("severity")
        .and_then(Value::as_i64)
        .filter(|s| entry.format.severities.contains(s));
    let (true, Some(severity)) = (label_ok, severity) else {
        return Err("label or severity is missing or out of range".to_owned());
    };
    let crate_name = result
        .pointer("/locus/crate")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let item = result
        .pointer("/locus/item")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if crate_name.is_empty() || item.is_empty() {
        return Err("locus.crate or locus.item is missing".to_owned());
    }
    let spans: Vec<Value> = result
        .get("evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|span| span_matches(span, &entry.format.quote, file_at))
        .map(|mut span| {
            let quote = span
                .get("quote")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            set(
                &mut span,
                "snippet_sha256",
                json!(prefixed_sha256(quote.as_bytes())),
            );
            span
        })
        .collect();
    if spans.is_empty() {
        return Err("no evidence span matches the file at the commit".to_owned());
    }
    let quotes: String = spans
        .iter()
        .filter_map(|s| s.get("quote").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    set(&mut result, "evidence", Value::Array(spans));
    if let Some(locus) = result.get_mut("locus") {
        set(
            locus,
            "item_sha256",
            json!(prefixed_sha256(quotes.as_bytes())),
        );
    }
    let key = format!(
        "{}|{}|{class_key}|{crate_name}|{item}",
        entry.id,
        entry.major()
    );
    Ok(Checked {
        fingerprint: prefixed_sha256(key.as_bytes()),
        result,
        severity,
    })
}

/// The quote has the schema's form and occurs in the file from its cited line: each quoted line,
/// trimmed, is inside the file's line at the same offset.
pub fn span_matches(
    span: &Value,
    quote_form: &Regex,
    file_at: &dyn Fn(&str) -> Option<String>,
) -> bool {
    let (Some(path), Some(line), Some(quote)) = (
        span.get("path").and_then(Value::as_str),
        span.get("line").and_then(Value::as_u64),
        span.get("quote").and_then(Value::as_str),
    ) else {
        return false;
    };
    let quoted: Vec<&str> = quote.lines().map(str::trim).collect();
    if quoted.is_empty()
        || !quote_form.is_match(quote.trim_end_matches('\n'))
        || path.starts_with('/')
        || path.contains(':')
    {
        return false;
    }
    let Some(text) = file_at(path) else {
        return false;
    };
    let Some(start) = usize::try_from(line)
        .ok()
        .and_then(|line| line.checked_sub(1))
    else {
        return false;
    };
    let lines: Vec<&str> = text.lines().skip(start).take(quoted.len()).collect();
    lines.len() == quoted.len()
        && quoted
            .iter()
            .zip(&lines)
            .all(|(quote, actual)| !quote.is_empty() && actual.contains(quote))
}

/// `sha256:<hex>`, the digest form the audit records use.
pub fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// Sets `key` on a JSON object; anything else is left as it is.
pub fn set(target: &mut Value, key: &str, value: Value) {
    if let Some(object) = target.as_object_mut() {
        object.insert(key.to_owned(), value);
    }
}

/// A verifier report's verdict, label and severity, when it is well formed.
pub fn verdict(report: &Value, fingerprint: &str) -> Option<Verdict> {
    if report.get("report").and_then(Value::as_str) != Some("verifier")
        || report.get("fingerprint").and_then(Value::as_str) != Some(fingerprint)
    {
        return None;
    }
    let verdict = report.get("verdict").and_then(Value::as_str)?;
    if !matches!(verdict, "REFUTED" | "UPHELD" | "DOWNGRADED") {
        return None;
    }
    let label = report
        .get("label")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let severity = report.get("severity").and_then(Value::as_i64);
    let corrected = matches!((&label, severity), (Some(_), Some(_)));
    if verdict == "DOWNGRADED" && !corrected {
        return None;
    }
    let reason = report
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Some(Verdict {
        verdict: verdict.to_owned(),
        label,
        severity,
        reason,
    })
}
