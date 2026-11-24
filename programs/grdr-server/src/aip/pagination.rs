// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::cmp::Ordering;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_crypto::{AeadKey, open_token, seal_token};
use grdr_proto::common::PageInfo;

use super::filter::{FilterError, FilterFieldSpec, FilterRecord, eval_filter, parse_filter};

pub const DEFAULT_PAGE_SIZE: u32 = 50;
pub const MAX_PAGE_SIZE: u32 = 1000;
pub const PAGE_TOKEN_TTL_SECS: i64 = 72 * 3600;
const CURSOR_DOMAIN: &str = "cursor-domain";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderSpec {
    pub field: &'static str,
    pub desc: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortKeyValue {
    Text(String),
    U64(u64),
    Bool(bool),
    TimestampNanos(i128),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CursorDir {
    Next,
    Prev,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CursorPayload {
    dir: CursorDir,
    sort_val: SortKeyValue,
    id: String,
    hwm: u64,
    exp_unix: i64,
}

#[derive(Debug, Clone)]
pub struct PageContext<'a> {
    pub tenant: &'a str,
    pub principal: &'a str,
    pub method: &'a str,
    pub page_size: u32,
    pub page_token: &'a str,
    pub filter: &'a str,
    pub order_by: &'a str,
    pub hwm: u64,
    pub now: Timestamp,
}

#[derive(Debug, Clone)]
pub struct PagedSlice<T> {
    pub items: Vec<T>,
    pub page_info: PageInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaginationError {
    InvalidFilter(FilterError),
    InvalidOrderBy(String),
    PageTokenInvalid,
}

pub trait KeysetItem: FilterRecord {
    fn item_id(&self) -> &str;
    fn sort_key(&self, field: &str) -> SortKeyValue;
}

impl Ord for SortKeyValue {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Text(a), Self::Text(b)) => a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()),
            (Self::U64(a), Self::U64(b)) => a.cmp(b),
            (Self::Bool(a), Self::Bool(b)) => a.cmp(b),
            (Self::TimestampNanos(a), Self::TimestampNanos(b)) => a.cmp(b),
            (Self::Text(a), _) => a.cmp(&String::new()),
            (_, Self::Text(b)) => String::new().cmp(b),
            (Self::U64(a), _) => a.cmp(&0),
            (_, Self::U64(b)) => 0u64.cmp(b),
            (Self::Bool(a), _) => a.cmp(&false),
            (_, Self::Bool(b)) => false.cmp(b),
        }
    }
}

impl PartialOrd for SortKeyValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<FilterError> for PaginationError {
    fn from(value: FilterError) -> Self {
        Self::InvalidFilter(value)
    }
}

impl std::fmt::Display for PaginationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFilter(err) => err.fmt(f),
            Self::InvalidOrderBy(msg) => write!(f, "invalid order_by: {msg}"),
            Self::PageTokenInvalid => write!(f, "invalid or expired page_token"),
        }
    }
}

pub fn parse_order_by(
    raw: &str,
    allowed_sort: &[&'static str],
    default: OrderSpec,
) -> Result<OrderSpec, PaginationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() > 2 {
        return Err(PaginationError::InvalidOrderBy(
            "expected '<field> [asc|desc]'".into(),
        ));
    }
    let Some(&raw_field) = parts.first() else {
        return Ok(default);
    };
    let Some(&field) = allowed_sort.iter().find(|&&f| f == raw_field) else {
        return Err(PaginationError::InvalidOrderBy(format!(
            "field '{raw_field}' is not sortable"
        )));
    };
    let desc = match parts.get(1).copied() {
        None => false,
        Some(dir) if dir.eq_ignore_ascii_case("asc") => false,
        Some(dir) if dir.eq_ignore_ascii_case("desc") => true,
        Some(other) => {
            return Err(PaginationError::InvalidOrderBy(format!(
                "unsupported sort direction '{other}'"
            )));
        }
    };
    Ok(OrderSpec { field, desc })
}

pub fn effective_page_size(requested: u32) -> usize {
    let bounded = if requested == 0 {
        DEFAULT_PAGE_SIZE
    } else {
        requested.min(MAX_PAGE_SIZE)
    };
    usize::try_from(bounded).unwrap_or(50)
}

pub fn paginate_keyset<T: KeysetItem + Clone>(
    items: Vec<T>,
    ctx: &PageContext<'_>,
    aead_key: &AeadKey,
    allowed_filters: &[FilterFieldSpec],
    allowed_sort: &[&'static str],
    default_order: OrderSpec,
) -> Result<PagedSlice<T>, PaginationError> {
    let filter_expr = parse_filter(ctx.filter, allowed_filters)?;
    let order = parse_order_by(ctx.order_by, allowed_sort, default_order)?;
    let page_size = effective_page_size(ctx.page_size);

    let mut filtered: Vec<T> = match &filter_expr {
        Some(expr) => items
            .into_iter()
            .filter(|it| eval_filter(expr, it))
            .collect(),
        None => items,
    };
    let total_size_estimate = u64::try_from(filtered.len()).unwrap_or(u64::MAX);

    filtered.sort_by(|a, b| compare_items(a, b, order));

    let aad = build_aad(ctx, order);
    let cursor = if ctx.page_token.trim().is_empty() {
        None
    } else {
        Some(decode_cursor(aead_key, &aad, ctx.page_token, ctx.now)?)
    };

    let (page_items, has_prev, has_next) = match cursor {
        None => {
            let has_next = filtered.len() > page_size;
            let page: Vec<T> = filtered.into_iter().take(page_size).collect();
            (page, false, has_next)
        }
        Some(ref cur) if cur.dir == CursorDir::Next => {
            let mut after: Vec<T> = filtered
                .into_iter()
                .filter(|item| compare_against_cursor(item, cur, order) == Ordering::Greater)
                .collect();
            let has_next = after.len() > page_size;
            after.truncate(page_size);
            let has_prev = !after.is_empty();
            (after, has_prev, has_next)
        }
        Some(ref cur) => {
            let before: Vec<T> = filtered
                .into_iter()
                .filter(|item| compare_against_cursor(item, cur, order) == Ordering::Less)
                .collect();
            let has_prev = before.len() > page_size;
            let skip = before.len().saturating_sub(page_size);
            let page: Vec<T> = before.into_iter().skip(skip).collect();
            let has_next = !page.is_empty();
            (page, has_prev, has_next)
        }
    };

    let next_page_token = if has_next {
        page_items
            .last()
            .and_then(|last| seal_cursor(aead_key, &aad, CursorDir::Next, last, order, ctx).ok())
            .unwrap_or_default()
    } else {
        String::new()
    };

    let prev_page_token = if has_prev {
        page_items
            .first()
            .and_then(|first| seal_cursor(aead_key, &aad, CursorDir::Prev, first, order, ctx).ok())
            .unwrap_or_default()
    } else {
        String::new()
    };

    Ok(PagedSlice {
        items: page_items,
        page_info: PageInfo {
            next_page_token,
            prev_page_token,
            total_size_estimate,
            has_more: has_next,
        },
    })
}

fn compare_items<T: KeysetItem>(a: &T, b: &T, order: OrderSpec) -> Ordering {
    let key_cmp = a.sort_key(order.field).cmp(&b.sort_key(order.field));
    let oriented = if order.desc {
        key_cmp.reverse()
    } else {
        key_cmp
    };
    oriented.then_with(|| a.item_id().cmp(b.item_id()))
}

fn compare_against_cursor<T: KeysetItem>(
    item: &T,
    cur: &CursorPayload,
    order: OrderSpec,
) -> Ordering {
    let key_cmp = item.sort_key(order.field).cmp(&cur.sort_val);
    let oriented = if order.desc {
        key_cmp.reverse()
    } else {
        key_cmp
    };
    oriented.then_with(|| item.item_id().cmp(cur.id.as_str()))
}

fn build_aad(ctx: &PageContext<'_>, order: OrderSpec) -> Vec<u8> {
    let dir = if order.desc { "desc" } else { "asc" };
    format!(
        "tenant={}|principal={}|method={}|filter={}|order={}:{}",
        ctx.tenant,
        ctx.principal,
        ctx.method,
        ctx.filter.trim(),
        order.field,
        dir
    )
    .into_bytes()
}

fn seal_cursor<T: KeysetItem>(
    key: &AeadKey,
    aad: &[u8],
    dir: CursorDir,
    item: &T,
    order: OrderSpec,
    ctx: &PageContext<'_>,
) -> Result<String, PaginationError> {
    let payload = CursorPayload {
        dir,
        sort_val: item.sort_key(order.field),
        id: item.item_id().to_string(),
        hwm: ctx.hwm,
        exp_unix: ctx.now.as_second().saturating_add(PAGE_TOKEN_TTL_SECS),
    };
    let bytes = serde_json::to_vec(&payload).map_err(|_| PaginationError::PageTokenInvalid)?;
    seal_token(key, CURSOR_DOMAIN, aad, &bytes).map_err(|_| PaginationError::PageTokenInvalid)
}

fn decode_cursor(
    key: &AeadKey,
    aad: &[u8],
    token: &str,
    now: Timestamp,
) -> Result<CursorPayload, PaginationError> {
    let bytes = open_token(key, CURSOR_DOMAIN, aad, token)
        .map_err(|_| PaginationError::PageTokenInvalid)?;
    let payload: CursorPayload =
        serde_json::from_slice(&bytes).map_err(|_| PaginationError::PageTokenInvalid)?;
    if now.as_second() > payload.exp_unix {
        return Err(PaginationError::PageTokenInvalid);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aip::filter::{FilterFieldType, FilterValue};

    #[derive(Clone)]
    struct Row {
        id: String,
        score: u64,
    }

    impl FilterRecord for Row {
        fn field_value(&self, field: &str) -> Option<FilterValue> {
            match field {
                "id" => Some(FilterValue::Text(self.id.clone())),
                "score" => Some(FilterValue::U64(self.score)),
                _ => None,
            }
        }
    }

    impl KeysetItem for Row {
        fn item_id(&self) -> &str {
            &self.id
        }

        fn sort_key(&self, field: &str) -> SortKeyValue {
            match field {
                "score" => SortKeyValue::U64(self.score),
                _ => SortKeyValue::Text(self.id.clone()),
            }
        }
    }

    #[test]
    fn sealed_keyset_pagination_walks_pages_and_rejects_tamper_or_expiry() {
        let key = grdr_crypto::SigningKeypair::generate()
            .unwrap()
            .derive_aead_key("test-cursor");
        let rows: Vec<Row> = (1..=5)
            .map(|i| Row {
                id: format!("row-{i}"),
                score: i * 10,
            })
            .collect();
        let filters = &[
            FilterFieldSpec {
                name: "id",
                ty: FilterFieldType::Text,
            },
            FilterFieldSpec {
                name: "score",
                ty: FilterFieldType::U64,
            },
        ];
        let sorts = &["id", "score"];
        let default = OrderSpec {
            field: "score",
            desc: true,
        };
        let now = Timestamp::from_second(1_800_000_000).unwrap();

        let p1 = paginate_keyset(
            rows.clone(),
            &PageContext {
                tenant: "org-1",
                principal: "op-1",
                method: "ListTest",
                page_size: 2,
                page_token: "",
                filter: "",
                order_by: "",
                hwm: 7,
                now,
            },
            &key,
            filters,
            sorts,
            default,
        )
        .unwrap();
        assert_eq!(
            p1.items.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["row-5", "row-4"]
        );
        assert!(p1.page_info.has_more);
        assert_eq!(p1.page_info.total_size_estimate, 5);
        assert!(!p1.page_info.next_page_token.is_empty());

        let p2 = paginate_keyset(
            rows.clone(),
            &PageContext {
                tenant: "org-1",
                principal: "op-1",
                method: "ListTest",
                page_size: 2,
                page_token: &p1.page_info.next_page_token,
                filter: "",
                order_by: "",
                hwm: 7,
                now,
            },
            &key,
            filters,
            sorts,
            default,
        )
        .unwrap();
        assert_eq!(
            p2.items.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["row-3", "row-2"]
        );
        assert!(p2.page_info.has_more);
        assert!(!p2.page_info.prev_page_token.is_empty());

        let back = paginate_keyset(
            rows.clone(),
            &PageContext {
                tenant: "org-1",
                principal: "op-1",
                method: "ListTest",
                page_size: 2,
                page_token: &p2.page_info.prev_page_token,
                filter: "",
                order_by: "",
                hwm: 7,
                now,
            },
            &key,
            filters,
            sorts,
            default,
        )
        .unwrap();
        assert_eq!(
            back.items.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["row-5", "row-4"]
        );

        // Changed filter invalidates AEAD token binding.
        assert!(matches!(
            paginate_keyset(
                rows.clone(),
                &PageContext {
                    tenant: "org-1",
                    principal: "op-1",
                    method: "ListTest",
                    page_size: 2,
                    page_token: &p1.page_info.next_page_token,
                    filter: "score > 10",
                    order_by: "",
                    hwm: 7,
                    now,
                },
                &key,
                filters,
                sorts,
                default,
            ),
            Err(PaginationError::PageTokenInvalid)
        ));

        // Expired token (> 72h) fails cleanly.
        let expired_now =
            Timestamp::from_second(now.as_second() + PAGE_TOKEN_TTL_SECS + 5).unwrap();
        assert!(matches!(
            paginate_keyset(
                rows,
                &PageContext {
                    tenant: "org-1",
                    principal: "op-1",
                    method: "ListTest",
                    page_size: 2,
                    page_token: &p1.page_info.next_page_token,
                    filter: "",
                    order_by: "",
                    hwm: 7,
                    now: expired_now,
                },
                &key,
                filters,
                sorts,
                default,
            ),
            Err(PaginationError::PageTokenInvalid)
        ));
    }
}
