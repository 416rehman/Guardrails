// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use grdr_model::CodedError;
use grdr_ports::{
    CODE_LAKE_INVALID_QUERY, HuntTable, LakeAggOp, LakeAggSpec, LakeCoverage, LakePredicate,
    LakeQueryIr, LakeQueryResult, LakeQueryRow, LakeRecord, OrgId, RetentionClass, parse_hunt_sql,
};

const DEFAULT_QUERY_LIMIT: usize = 1_000;
const MAX_QUERY_LIMIT: usize = 100_000;

type SealedRowRef<'a> = &'a (OrgId, LakeRecord, bool);

pub(crate) fn evaluate_rows(
    rows: &[(OrgId, LakeRecord, bool)],
    query: &LakeQueryIr,
    scanned_segments: usize,
    tail_rows_merged: usize,
) -> Result<LakeQueryResult, CodedError> {
    match query {
        LakeQueryIr::Timeline {
            root_session_id,
            include_content,
            limit,
        } => {
            let mut matched: Vec<SealedRowRef<'_>> = rows
                .iter()
                .filter(|(_, r, _)| &r.root_session_id == root_session_id)
                .collect();
            matched.sort_by(|a, b| {
                (
                    &a.1.device_id,
                    a.1.epoch,
                    a.1.monotonic_ns,
                    &a.1.lane,
                    a.1.seq,
                )
                    .cmp(&(
                        &b.1.device_id,
                        b.1.epoch,
                        b.1.monotonic_ns,
                        &b.1.lane,
                        b.1.seq,
                    ))
            });
            let cap = normalize_limit(*limit, DEFAULT_QUERY_LIMIT);
            let out = matched
                .into_iter()
                .take(cap)
                .map(|(org, rec, shredded)| {
                    record_to_row(org, rec, &[], *include_content, *shredded)
                })
                .collect();
            Ok(LakeQueryResult {
                rows: out,
                coverage: LakeCoverage::Complete,
                next_cursor: None,
                scanned_segments,
                tail_rows_merged,
            })
        }
        LakeQueryIr::Scan {
            retention_class,
            category,
            predicates,
            projection,
            include_content,
            limit,
        } => {
            let cap = normalize_limit(*limit, DEFAULT_QUERY_LIMIT);
            let out = rows
                .iter()
                .filter(|(_, rec, _)| {
                    rec.retention_class == *retention_class
                        && category
                            .as_ref()
                            .is_none_or(|c| rec.category.eq_ignore_ascii_case(c))
                        && predicates_match(rec, predicates, *include_content)
                })
                .take(cap)
                .map(|(org, rec, shredded)| {
                    record_to_row(org, rec, projection, *include_content, *shredded)
                })
                .collect();
            Ok(LakeQueryResult {
                rows: out,
                coverage: LakeCoverage::Complete,
                next_cursor: None,
                scanned_segments,
                tail_rows_merged,
            })
        }
        LakeQueryIr::Aggregate {
            retention_class,
            group_by,
            aggregations,
            predicates,
        } => {
            let filtered: Vec<SealedRowRef<'_>> = rows
                .iter()
                .filter(|(_, rec, _)| {
                    rec.retention_class == *retention_class
                        && predicates_match(rec, predicates, false)
                })
                .collect();
            let mut groups: BTreeMap<(OrgId, Vec<String>), Vec<SealedRowRef<'_>>> = BTreeMap::new();
            for item in filtered {
                let key = group_by
                    .iter()
                    .map(|col| resolve_field(&item.1, col).unwrap_or_default())
                    .collect();
                groups.entry((item.0.clone(), key)).or_default().push(item);
            }
            let mut out = Vec::new();
            for ((org, key_vals), group_rows) in groups {
                let mut cols = BTreeMap::new();
                for (col, val) in group_by.iter().zip(key_vals) {
                    cols.insert(col.clone(), val);
                }
                for agg in aggregations {
                    cols.insert(agg.alias.clone(), compute_agg(agg, &group_rows));
                }
                out.push(LakeQueryRow {
                    organisation_id: org,
                    event_id: None,
                    retention_class: Some(*retention_class),
                    root_session_id: None,
                    observed_time_ms: None,
                    columns: cols,
                    content_redacted: false,
                });
            }
            Ok(LakeQueryResult {
                rows: out,
                coverage: LakeCoverage::Complete,
                next_cursor: None,
                scanned_segments,
                tail_rows_merged,
            })
        }
        LakeQueryIr::Lookup {
            observable_type,
            value,
            limit,
        } => {
            let cap = normalize_limit(*limit, DEFAULT_QUERY_LIMIT);
            let out = rows
                .iter()
                .filter(|(_, rec, _)| {
                    rec.observables.iter().any(|obs| {
                        obs.value == *value
                            && observable_type
                                .as_ref()
                                .is_none_or(|t| obs.observable_type == *t)
                    })
                })
                .take(cap)
                .map(|(org, rec, shredded)| record_to_row(org, rec, &[], false, *shredded))
                .collect();
            Ok(LakeQueryResult {
                rows: out,
                coverage: LakeCoverage::Complete,
                next_cursor: None,
                scanned_segments,
                tail_rows_merged,
            })
        }
        LakeQueryIr::Hunt {
            sql_select,
            include_content,
            limit,
        } => eval_hunt(
            rows,
            sql_select,
            *include_content,
            *limit,
            scanned_segments,
            tail_rows_merged,
        ),
        LakeQueryIr::Export {
            retention_class,
            cursor,
            include_content,
            limit,
        } => eval_export(
            rows,
            *retention_class,
            cursor.as_deref(),
            *include_content,
            *limit,
            scanned_segments,
            tail_rows_merged,
        ),
    }
}

fn normalize_limit(limit: usize, default_limit: usize) -> usize {
    if limit == 0 {
        default_limit
    } else {
        limit.min(MAX_QUERY_LIMIT)
    }
}

fn eval_hunt(
    rows: &[(OrgId, LakeRecord, bool)],
    sql_select: &str,
    include_content: bool,
    limit: usize,
    scanned_segments: usize,
    tail_rows_merged: usize,
) -> Result<LakeQueryResult, CodedError> {
    let parsed = parse_hunt_sql(sql_select, include_content)?;
    let requested = normalize_limit(limit, MAX_QUERY_LIMIT);
    let cap = parsed.sql_limit.map_or(requested, |sql_lim| {
        if sql_lim == 0 {
            requested
        } else {
            requested.min(sql_lim)
        }
    });
    let out = rows
        .iter()
        .filter(|(_, rec, _)| {
            let table_ok = match parsed.table {
                HuntTable::Decision => rec.retention_class == RetentionClass::Decision,
                HuntTable::Activity => rec.retention_class == RetentionClass::Activity,
                HuntTable::Content => rec.retention_class == RetentionClass::Content,
                HuntTable::Events => true,
            };
            let filter_ok = parsed.predicates.iter().all(|(col, val)| {
                resolve_field_for_hunt(rec, col, include_content).is_some_and(|v| v == *val)
            });
            table_ok && filter_ok
        })
        .take(cap)
        .map(|(org, rec, shredded)| {
            record_to_row(org, rec, &parsed.projection, include_content, *shredded)
        })
        .collect();
    Ok(LakeQueryResult {
        rows: out,
        coverage: LakeCoverage::Complete,
        next_cursor: None,
        scanned_segments,
        tail_rows_merged,
    })
}

fn eval_export(
    rows: &[(OrgId, LakeRecord, bool)],
    retention_class: Option<RetentionClass>,
    cursor: Option<&str>,
    include_content: bool,
    limit: usize,
    scanned_segments: usize,
    tail_rows_merged: usize,
) -> Result<LakeQueryResult, CodedError> {
    let start = match cursor {
        Some(raw) => raw.trim().parse::<usize>().map_err(|_| {
            CodedError::new(
                CODE_LAKE_INVALID_QUERY,
                format!("Invalid export cursor `{raw}`."),
                "Supply a valid numeric export cursor from the previous page.",
            )
        })?,
        None => 0,
    };
    let cap = normalize_limit(limit, DEFAULT_QUERY_LIMIT);
    let filtered: Vec<SealedRowRef<'_>> = rows
        .iter()
        .filter(|(_, rec, _)| retention_class.is_none_or(|rc| rec.retention_class == rc))
        .collect();
    let next_idx = start.saturating_add(cap);
    let next_cursor = if next_idx < filtered.len() {
        Some(next_idx.to_string())
    } else {
        None
    };
    let out = filtered
        .into_iter()
        .skip(start)
        .take(cap)
        .map(|(org, rec, shredded)| record_to_row(org, rec, &[], include_content, *shredded))
        .collect();
    Ok(LakeQueryResult {
        rows: out,
        coverage: LakeCoverage::Complete,
        next_cursor,
        scanned_segments,
        tail_rows_merged,
    })
}

fn record_to_row(
    org: &OrgId,
    rec: &LakeRecord,
    projection: &[String],
    include_content: bool,
    shredded: bool,
) -> LakeQueryRow {
    let mut cols = BTreeMap::new();
    cols.insert("event_id".into(), rec.event_id.clone());
    cols.insert("device_id".into(), rec.device_id.clone());
    cols.insert("category".into(), rec.category.clone());
    cols.insert("session_id".into(), rec.session_id.clone());
    cols.insert("root_session_id".into(), rec.root_session_id.clone());
    cols.insert("lane".into(), rec.lane.clone());
    cols.insert("seq".into(), rec.seq.to_string());
    for (k, v) in &rec.fields {
        cols.insert(k.clone(), v.clone());
    }
    let mut content_redacted = false;
    if include_content {
        if shredded {
            content_redacted = true;
        } else {
            for (k, v) in &rec.content_fields {
                cols.insert(format!("content.{k}"), v.clone());
            }
        }
    }
    if !projection.is_empty() {
        cols.retain(|k, _| projection.contains(k));
    }
    LakeQueryRow {
        organisation_id: org.clone(),
        event_id: Some(rec.event_id.clone()),
        retention_class: Some(rec.retention_class),
        root_session_id: Some(rec.root_session_id.clone()),
        observed_time_ms: Some(rec.observed_time_ms),
        columns: cols,
        content_redacted,
    }
}

fn predicates_match(rec: &LakeRecord, predicates: &[LakePredicate], include_content: bool) -> bool {
    predicates.iter().all(|p| {
        let Some(val) = resolve_field_for_hunt(rec, &p.field, include_content) else {
            return false;
        };
        let eq_ok = p.equals.as_ref().is_none_or(|e| val == *e);
        let contains_ok = p.contains.as_ref().is_none_or(|c| val.contains(c.as_str()));
        eq_ok && contains_ok
    })
}

fn resolve_field_for_hunt(rec: &LakeRecord, field: &str, include_content: bool) -> Option<String> {
    if let Some(content_key) = field.strip_prefix("content.") {
        if !include_content {
            return None;
        }
        return rec.content_fields.get(content_key).cloned();
    }
    resolve_field(rec, field)
}

fn resolve_field(rec: &LakeRecord, field: &str) -> Option<String> {
    match field {
        "event_id" => Some(rec.event_id.clone()),
        "device_id" => Some(rec.device_id.clone()),
        "category" => Some(rec.category.clone()),
        "root_session_id" => Some(rec.root_session_id.clone()),
        "session_id" => Some(rec.session_id.clone()),
        "lane" => Some(rec.lane.clone()),
        other => rec.fields.get(other).cloned(),
    }
}

fn compute_agg(agg: &LakeAggSpec, rows: &[SealedRowRef<'_>]) -> String {
    match agg.op {
        LakeAggOp::Count => rows.len().to_string(),
        LakeAggOp::Sum => {
            let total: i64 = rows
                .iter()
                .filter_map(|(_, r, _)| {
                    agg.field
                        .as_deref()
                        .and_then(|f| resolve_field(r, f))
                        .and_then(|v| v.parse::<i64>().ok())
                })
                .fold(0i64, i64::saturating_add);
            total.to_string()
        }
        LakeAggOp::Min => rows
            .iter()
            .filter_map(|(_, r, _)| agg.field.as_deref().and_then(|f| resolve_field(r, f)))
            .min()
            .unwrap_or_default(),
        LakeAggOp::Max => rows
            .iter()
            .filter_map(|(_, r, _)| agg.field.as_deref().and_then(|f| resolve_field(r, f)))
            .max()
            .unwrap_or_default(),
        LakeAggOp::ApproxDistinct => {
            let set: BTreeSet<String> = rows
                .iter()
                .filter_map(|(_, r, _)| agg.field.as_deref().and_then(|f| resolve_field(r, f)))
                .collect();
            set.len().to_string()
        }
    }
}
