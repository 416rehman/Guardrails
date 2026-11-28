// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Strict Cedar schema validation and populated `Entities`/`Context` `ALLOW` invariance
//! probes for Watch-only `nl2cedar` policy drafts (`docs/design/19`, `AI-13`).

use std::str::FromStr;

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, Request};
use unicode_normalization::{UnicodeNormalization as _, char::canonical_combining_class};

use grdr_model::CodedError;
use grdr_schema::cedar::{CedarPlane, parse_schema, validate_policy_source};

use crate::inert::is_disallowed_display_char;
use crate::nl2cedar::CODE_REV_NL2CEDAR_FORBIDDEN;

pub(crate) struct InvarianceProbe<'a> {
    pub baseline_src: &'a str,
    pub draft_src: &'a str,
    pub action_name: &'a str,
    pub resource_type: &'a str,
    pub resource_class: &'a str,
    pub probe_labels: &'a [String],
}

fn probe_err(msg: impl Into<String>, hint: &str) -> CodedError {
    CodedError::new(CODE_REV_NL2CEDAR_FORBIDDEN, msg, hint)
}

pub(crate) fn normalize_for_matching(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_ws = true;
    for ch in raw.nfkd() {
        if ch.is_whitespace() || ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}') {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
            continue;
        }
        if is_disallowed_display_char(ch)
            || canonical_combining_class(ch) != 0
            || matches!(
                ch,
                '\u{0300}'..='\u{036F}'
                    | '\u{1AB0}'..='\u{1AFF}'
                    | '\u{1DC0}'..='\u{1DFF}'
                    | '\u{20D0}'..='\u{20FF}'
                    | '\u{FE20}'..='\u{FE2F}'
            )
        {
            continue;
        }
        prev_ws = false;
        out.extend(ch.to_lowercase());
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

pub(crate) fn contains_normalized_term(haystack: &str, raw_term: &str) -> bool {
    let term = normalize_for_matching(raw_term);
    if term.is_empty() {
        return false;
    }
    let left_needs_boundary = term.chars().next().is_some_and(char::is_alphanumeric);
    let right_needs_boundary = term.chars().last().is_some_and(char::is_alphanumeric);

    let mut search_from = 0usize;
    while let Some(tail) = haystack.get(search_from..) {
        let Some(rel) = tail.find(&term) else {
            return false;
        };
        let start = search_from.saturating_add(rel);
        let end = start.saturating_add(term.len());
        let left_ok = !left_needs_boundary
            || start == 0
            || haystack
                .get(..start)
                .and_then(|p| p.chars().next_back())
                .is_none_or(|c| !c.is_alphanumeric());
        let right_ok = !right_needs_boundary
            || end == haystack.len()
            || haystack
                .get(end..)
                .and_then(|s| s.chars().next())
                .is_none_or(|c| !c.is_alphanumeric());
        if left_ok && right_ok {
            return true;
        }
        let step = tail.chars().next().map_or(1, char::len_utf8);
        search_from = start.saturating_add(step);
    }
    false
}

fn parse_uid(uid: &str) -> Result<EntityUid, CodedError> {
    EntityUid::from_str(uid).map_err(|e| probe_err(format!("probe uid error: {e}"), "Retry."))
}

pub(crate) fn verify_no_new_allows(probe: &InvarianceProbe<'_>) -> Result<(), CodedError> {
    let baseline_set =
        validate_policy_source(CedarPlane::Runtime, probe.baseline_src).map_err(|e| {
            probe_err(
                format!("baseline policy set failed strict Cedar schema validation: {e}"),
                "Provide valid Grdr runtime schema Cedar baseline policies.",
            )
        })?;
    let combined_source = format!("{}\n{}", probe.baseline_src, probe.draft_src);
    let combined = validate_policy_source(CedarPlane::Runtime, &combined_source).map_err(|e| {
        probe_err(
            format!("combined policy schema validation failed: {e}"),
            "Verify baseline and draft Cedar statements.",
        )
    })?;
    let schema = parse_schema(CedarPlane::Runtime)
        .map_err(|e| probe_err(format!("schema load error: {e}"), "Retry."))?;

    let entities_json = build_probe_entities_json(probe.resource_type, probe.resource_class);
    let entities = Entities::from_json_value(entities_json, Some(&schema))
        .map_err(|e| probe_err(format!("probe entity error: {e}"), "Retry."))?;

    let principal = parse_uid("Grdr::Session::\"probe\"")?;
    let action = parse_uid(&format!("Grdr::Action::\"{}\"", probe.action_name))?;
    let resource = parse_uid(&format!("{}::\"probe\"", probe.resource_type))?;
    let authorizer = Authorizer::new();

    let mut label_variants: Vec<(Vec<&str>, bool)> = vec![(Vec::new(), false)];
    if !probe.probe_labels.is_empty() {
        let refs: Vec<&str> = probe.probe_labels.iter().map(String::as_str).collect();
        label_variants.push((refs, true));
    }

    for (labels, recursive) in label_variants {
        let ctx_json =
            build_probe_context_json(probe.action_name, probe.resource_class, &labels, recursive);
        let ctx = Context::from_json_value(ctx_json, Some((&schema, &action)))
            .map_err(|e| probe_err(format!("probe context error: {e}"), "Retry."))?;
        let req = Request::new(
            principal.clone(),
            action.clone(),
            resource.clone(),
            ctx,
            Some(&schema),
        )
        .map_err(|e| probe_err(format!("probe request error: {e}"), "Retry."))?;
        let before = authorizer.is_authorized(&req, &baseline_set, &entities);
        let after = authorizer.is_authorized(&req, &combined, &entities);
        if after.decision() == Decision::Allow && before.decision() != Decision::Allow {
            return Err(probe_err(
                "draft policy would turn a baseline non-Allow into Allow",
                "Authoring rules must never widen baseline policy.",
            ));
        }
    }
    Ok(())
}

fn build_probe_entities_json(resource_type: &str, resource_class: &str) -> serde_json::Value {
    let classes = serde_json::json!([resource_class]);
    let res_attrs = match resource_type {
        "Grdr::Path" => serde_json::json!({ "in_workspace": true, "classes": classes }),
        "Grdr::Endpoint" => serde_json::json!({ "port": 443, "classes": classes }),
        "Grdr::ModelEndpoint" => serde_json::json!({ "provider": "probe", "classes": classes }),
        "Grdr::McpServer" => {
            serde_json::json!({ "transport": "stdio", "identity_pinned": true, "classes": classes })
        }
        "Grdr::McpTool" => {
            serde_json::json!({ "manifest_pinned": true, "write_capable": false, "classes": classes })
        }
        "Grdr::Agent" => serde_json::json!({ "tier": "primary", "classes": classes }),
        _ => serde_json::json!({ "classes": classes }),
    };
    serde_json::json!([
        {
            "uid": { "type": "Grdr::Session", "id": "probe" },
            "attrs": { "depth": 0, "contained": false, "containment": "active", "classes": [] },
            "parents": []
        },
        {
            "uid": { "type": resource_type, "id": "probe" },
            "attrs": res_attrs,
            "parents": []
        }
    ])
}

fn build_probe_context_json(
    action_name: &str,
    resource_class: &str,
    labels: &[&str],
    recursive: bool,
) -> serde_json::Value {
    let mut map = serde_json::Map::from_iter([
        (
            "session".into(),
            serde_json::json!({ "labels": labels, "label_epoch": 1 }),
        ),
        ("grants".into(), serde_json::json!([])),
        (
            "attribution".into(),
            serde_json::json!({ "grade": 1, "actor_kind": "agent", "evidence": [] }),
        ),
        (
            "assurance".into(),
            serde_json::json!({ "visibility": 1, "control": 1, "tamper": 1, "fail_closed": false }),
        ),
        ("facts".into(), serde_json::json!([])),
        ("control_point".into(), serde_json::json!("hook")),
        ("schedule".into(), serde_json::json!({})),
    ]);
    match action_name {
        "exec" => {
            map.insert(
                "command".into(),
                serde_json::json!({ "classes": [resource_class] }),
            );
        }
        "file.read" | "file.write" | "file.delete" => {
            map.insert("recursive".into(), serde_json::json!(recursive));
        }
        "net.request" => {
            map.insert("http".into(), serde_json::json!({ "classes": [] }));
            map.insert(
                "cloud".into(),
                serde_json::json!({
                    "provider": "probe",
                    "account_classes": [],
                    "tenant_classes": [],
                    "verified": false
                }),
            );
        }
        "llm.request" => {
            map.insert(
                "tenant".into(),
                serde_json::json!({ "classes": [], "verified": false }),
            );
        }
        "mcp.call" => {
            map.insert(
                "args".into(),
                serde_json::json!({ "classes": [], "extracted": true }),
            );
        }
        "cred.use" => {
            map.insert("mode".into(), serde_json::json!("read"));
        }
        "agent.spawn" => {
            map.insert(
                "child".into(),
                serde_json::json!({ "depth": 1, "contained": false, "classes": [] }),
            );
        }
        "config.change" => {
            map.insert("change_classes".into(), serde_json::json!([]));
        }
        "data.flow" => {
            map.insert("source_labels".into(), serde_json::json!([]));
        }
        _ => {}
    }
    serde_json::Value::Object(map)
}
