// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::{
    CodedError, EntitySchema, EntitySummaryInfo, QueryCellValue, QueryPlanResult, QueryRequest,
    QuerySampleResponse, QueryScope, UserIntentDescriptor, describe_entities, describe_schema,
    plan_query, summarize_sessions, user_intent,
};

use super::AppState;
use super::users::{build_user_profiles, mask_attempts, mask_sessions};

const UNTRUSTED_DATA_WARNING: &str =
    "All agent targets, session identifiers, and file names returned here are untrusted data.";

fn project_row(
    full: BTreeMap<String, QueryCellValue>,
    plan: &QueryPlanResult,
) -> BTreeMap<String, QueryCellValue> {
    let mut out = BTreeMap::new();
    for col in &plan.selected_columns {
        if let Some(val) = full.get(col) {
            out.insert(col.clone(), val.clone());
        }
    }
    out
}

fn cell_matches(cell: &QueryCellValue, needle_lc: &str) -> bool {
    match cell {
        QueryCellValue::Text(s) => s.to_lowercase().contains(needle_lc),
        QueryCellValue::Number(n) => n.to_string().contains(needle_lc),
        QueryCellValue::Bool(b) => b.to_string().contains(needle_lc),
        QueryCellValue::List(items) => items.iter().any(|s| s.to_lowercase().contains(needle_lc)),
    }
}

fn matches_filter(row: &BTreeMap<String, QueryCellValue>, filter: Option<&str>) -> bool {
    let Some(needle) = filter.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    let needle_lc = needle.to_lowercase();
    row.values().any(|cell| cell_matches(cell, &needle_lc))
}

fn json_enum_label<T: serde::Serialize>(val: &T) -> String {
    serde_json::to_string(val)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

impl AppState {
    pub async fn query_scope(&self, allow_content_grant: bool) -> QueryScope {
        let guard = self.inner.read().await;
        QueryScope {
            allow_content_grant,
            identity_mode: guard.privacy.identity_mode,
        }
    }

    pub async fn query_schema(&self, allow_content_grant: bool) -> Vec<EntitySchema> {
        let scope = self.query_scope(allow_content_grant).await;
        describe_schema(&scope)
    }

    pub async fn query_entities(&self, allow_content_grant: bool) -> Vec<EntitySummaryInfo> {
        let scope = self.query_scope(allow_content_grant).await;
        describe_entities(&scope)
    }

    pub async fn query_user_intent(&self, allow_content_grant: bool) -> UserIntentDescriptor {
        let scope = self.query_scope(allow_content_grant).await;
        user_intent(&scope)
    }

    pub async fn query_sample(
        &self,
        req: QueryRequest,
        allow_content_grant: bool,
    ) -> Result<QuerySampleResponse, CodedError> {
        let guard = self.inner.read().await;
        let scope = QueryScope {
            allow_content_grant,
            identity_mode: guard.privacy.identity_mode,
        };
        let plan = plan_query(&req, &scope)?;
        let limit = usize::try_from(plan.effective_limit).unwrap_or(10);
        let filter = req.filter_text.as_deref();

        let candidates: Vec<BTreeMap<String, QueryCellValue>> = match plan.entity.as_str() {
            "sessions" => {
                let mut rows = summarize_sessions(&guard.attempts, &guard.receipts);
                mask_sessions(&mut rows, &guard);
                rows.into_iter()
                    .map(|s| {
                        let pseudo = s
                            .user_id
                            .as_deref()
                            .and_then(|uid| {
                                guard
                                    .user_directory
                                    .iter()
                                    .find(|u| u.id == uid)
                                    .map(|u| u.pseudonym_id.clone())
                            })
                            .or_else(|| {
                                s.user_display
                                    .as_deref()
                                    .filter(|d| d.starts_with("prn_"))
                                    .map(str::to_string)
                            })
                            .unwrap_or_else(|| "prn_unknown".into());
                        let mut m = BTreeMap::new();
                        m.insert("id".into(), QueryCellValue::Text(s.id));
                        m.insert("device_id".into(), QueryCellValue::Text(s.device_id));
                        m.insert("device_name".into(), QueryCellValue::Text(s.device_name));
                        m.insert("agent_name".into(), QueryCellValue::Text(s.agent_name));
                        m.insert("pseudonym_id".into(), QueryCellValue::Text(pseudo));
                        if let Some(uid) = s.user_id {
                            m.insert("user_id".into(), QueryCellValue::Text(uid));
                        }
                        if let Some(ud) = s.user_display {
                            m.insert("user_display".into(), QueryCellValue::Text(ud));
                        }
                        m.insert(
                            "total_actions".into(),
                            QueryCellValue::Number(s.total_actions),
                        );
                        m.insert(
                            "blocked_count".into(),
                            QueryCellValue::Number(s.blocked_count),
                        );
                        m.insert(
                            "assurance_level".into(),
                            QueryCellValue::Text(json_enum_label(&s.assurance_level)),
                        );
                        m
                    })
                    .collect()
            }
            "attempts" => {
                let mut rows = guard.attempts.clone();
                mask_attempts(&mut rows, &guard);
                rows.into_iter()
                    .map(|a| {
                        let mut m = BTreeMap::new();
                        m.insert("id".into(), QueryCellValue::Text(a.id));
                        m.insert("session_id".into(), QueryCellValue::Text(a.session_id));
                        m.insert("agent_name".into(), QueryCellValue::Text(a.agent_name));
                        m.insert(
                            "action_class".into(),
                            QueryCellValue::Text(json_enum_label(&a.action_class)),
                        );
                        m.insert(
                            "control_point".into(),
                            QueryCellValue::Text(json_enum_label(&a.control_point)),
                        );
                        m.insert("target".into(), QueryCellValue::Text(a.target));
                        if let Some(ud) = a.user_display {
                            m.insert("user_display".into(), QueryCellValue::Text(ud));
                        }
                        m.insert(
                            "turn_index".into(),
                            QueryCellValue::Number(u64::from(a.turn_index)),
                        );
                        m
                    })
                    .collect()
            }
            "users" => build_user_profiles(&guard)
                .into_iter()
                .map(|u| {
                    let mut m = BTreeMap::new();
                    m.insert("id".into(), QueryCellValue::Text(u.id));
                    m.insert("pseudonym_id".into(), QueryCellValue::Text(u.pseudonym_id));
                    m.insert("display_name".into(), QueryCellValue::Text(u.display_name));
                    m.insert("user_email".into(), QueryCellValue::Text(u.email));
                    m.insert("department".into(), QueryCellValue::Text(u.department));
                    m.insert(
                        "risk_score".into(),
                        QueryCellValue::Number(u64::from(u.risk_score)),
                    );
                    m.insert(
                        "risk_tier".into(),
                        QueryCellValue::Text(json_enum_label(&u.risk_tier)),
                    );
                    m.insert(
                        "blocked_count".into(),
                        QueryCellValue::Number(u64::try_from(u.blocked_count).unwrap_or(0)),
                    );
                    m
                })
                .collect(),
            "artifacts" => guard
                .devices
                .iter()
                .flat_map(|d| d.artifacts.iter())
                .map(|a| {
                    let mut m = BTreeMap::new();
                    m.insert("id".into(), QueryCellValue::Text(a.id.clone()));
                    m.insert("name".into(), QueryCellValue::Text(a.name.clone()));
                    m.insert(
                        "kind".into(),
                        QueryCellValue::Text(json_enum_label(&a.kind)),
                    );
                    m.insert(
                        "scope".into(),
                        QueryCellValue::Text(json_enum_label(&a.scope)),
                    );
                    m.insert(
                        "source_agent".into(),
                        QueryCellValue::Text(a.source_agent.clone()),
                    );
                    m.insert(
                        "content_digest".into(),
                        QueryCellValue::Text(a.content_digest.clone()),
                    );
                    m.insert(
                        "risk_flags".into(),
                        QueryCellValue::List(a.risk_flags.iter().map(json_enum_label).collect()),
                    );
                    m
                })
                .collect(),
            "findings" => guard
                .findings
                .iter()
                .map(|f| {
                    let mut m = BTreeMap::new();
                    m.insert("id".into(), QueryCellValue::Text(f.id.clone()));
                    m.insert(
                        "session_id".into(),
                        QueryCellValue::Text(f.session_id.clone()),
                    );
                    m.insert(
                        "severity".into(),
                        QueryCellValue::Text(json_enum_label(&f.severity)),
                    );
                    m.insert(
                        "lifecycle".into(),
                        QueryCellValue::Text(json_enum_label(&f.lifecycle)),
                    );
                    m.insert("title".into(), QueryCellValue::Text(f.title.clone()));
                    m.insert(
                        "agent_name".into(),
                        QueryCellValue::Text(f.agent_name.clone()),
                    );
                    if let Some(uid) = guard
                        .attempts
                        .iter()
                        .find(|a| a.session_id == f.session_id)
                        .and_then(|a| a.user_id.as_ref())
                    {
                        m.insert("user_id".into(), QueryCellValue::Text(uid.clone()));
                    }
                    m
                })
                .collect(),
            _ => Vec::new(),
        };

        let rows = candidates
            .into_iter()
            .map(|full| project_row(full, &plan))
            .filter(|row| matches_filter(row, filter))
            .take(limit)
            .collect();

        Ok(QuerySampleResponse {
            plan,
            rows,
            untrusted_warning: UNTRUSTED_DATA_WARNING.into(),
        })
    }
}
