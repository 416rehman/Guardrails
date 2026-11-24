// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;

use crate::tenant::{FencingToken, OrgId, SingleCtx, TenantCtx};

pub const CODE_LAKE_IO: &str = "GRDR-LAKE-0001";
pub const CODE_LAKE_STALE_FENCE: &str = "GRDR-LAKE-0002";
pub const CODE_LAKE_HOLD_ACTIVE: &str = "GRDR-LAKE-0003";
pub const CODE_LAKE_INVALID_QUERY: &str = "GRDR-LAKE-0004";
pub const CODE_LAKE_KEY_DESTROYED: &str = "GRDR-LAKE-0005";
pub const CODE_LAKE_NOT_FOUND: &str = "GRDR-LAKE-0006";

const DECISION_RETENTION_DAYS: u32 = 396;
const ACTIVITY_RETENTION_DAYS: u32 = 184;
const CONTENT_RETENTION_DAYS: u32 = 30;
const MS_PER_DAY: i64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    Decision,
    Activity,
    Content,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakeObservable {
    pub observable_type: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakeRecord {
    pub event_id: String,
    pub device_id: String,
    pub epoch: u64,
    pub lane: String,
    pub seq: u64,
    pub retention_class: RetentionClass,
    pub category: String,
    pub root_session_id: String,
    pub session_id: String,
    pub tool_call_id: Option<String>,
    pub observed_time_ms: i64,
    pub monotonic_ns: u64,
    pub received_at_ms: i64,
    pub schema_rev: u32,
    pub fields: BTreeMap<String, String>,
    pub content_fields: BTreeMap<String, String>,
    pub observables: Vec<LakeObservable>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakeBatch {
    pub partition: u32,
    pub bus_offset: u64,
    pub lane: String,
    pub records: Vec<LakeRecord>,
    pub archive_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakeFlushResult {
    pub organisation_id: OrgId,
    pub snapshot_id: u64,
    pub committed_through: Option<u64>,
    pub segments_written: usize,
    pub archive_segments_written: usize,
    pub rows_flushed: usize,
    pub manifest_seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LegalHoldState {
    Active,
    Released { released_at_ms: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LegalHoldScope {
    pub tables: Vec<RetentionClass>,
    pub day_start: Option<String>,
    pub day_end: Option<String>,
    pub device_ids: Vec<String>,
    pub root_session_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHoldRequest {
    pub hold_id: String,
    pub scope: LegalHoldScope,
    pub reason: String,
    pub incident_ref: Option<String>,
    pub created_by: String,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHold {
    pub organisation_id: OrgId,
    pub hold_id: String,
    pub scope: LegalHoldScope,
    pub reason: String,
    pub incident_ref: Option<String>,
    pub created_by: String,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub state: LegalHoldState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ContentKeyState {
    Active,
    Destroyed {
        destroyed_at_ms: i64,
        destruction_record_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContentKey {
    pub organisation_id: OrgId,
    pub root_session_id: String,
    pub key_id: String,
    pub wrapped_key: String,
    pub created_at_ms: i64,
    pub destroy_after_ms: i64,
    pub state: ContentKeyState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureReceipt {
    pub organisation_id: OrgId,
    pub root_session_id: String,
    pub destruction_record_id: String,
    pub erased_at_ms: i64,
    pub keys_destroyed: usize,
    pub archive_segments_reduced: usize,
    pub held_segments_deferred: usize,
    pub state_log_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakeManifestEntry {
    pub object_key: String,
    pub retention_class: RetentionClass,
    pub day: String,
    pub row_count: u64,
    pub size_bytes: u64,
    pub digest_sha256: String,
    pub schema_rev: u32,
    pub data_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakeManifest {
    pub organisation_id: OrgId,
    pub manifest_seq: u64,
    pub prev_manifest_digest: Option<String>,
    pub manifest_digest: String,
    pub object_key: String,
    pub created_at_ms: i64,
    pub entries: Vec<LakeManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakeCompactionResult {
    pub organisation_id: OrgId,
    pub segments_compacted: usize,
    pub segments_logically_deleted: usize,
    pub segments_physically_deleted: usize,
    pub segments_held: usize,
    pub observables_written: usize,
    pub keys_destroyed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LakeAggOp {
    Count,
    Sum,
    Min,
    Max,
    ApproxDistinct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakeAggSpec {
    pub alias: String,
    pub op: LakeAggOp,
    pub field: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakePredicate {
    pub field: String,
    pub equals: Option<String>,
    pub contains: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LakeCoverage {
    Complete,
    WithoutTail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LakeQueryIr {
    Timeline {
        root_session_id: String,
        include_content: bool,
        limit: usize,
    },
    Scan {
        retention_class: RetentionClass,
        category: Option<String>,
        predicates: Vec<LakePredicate>,
        projection: Vec<String>,
        include_content: bool,
        limit: usize,
    },
    Aggregate {
        retention_class: RetentionClass,
        group_by: Vec<String>,
        aggregations: Vec<LakeAggSpec>,
        predicates: Vec<LakePredicate>,
    },
    Lookup {
        observable_type: Option<String>,
        value: String,
        limit: usize,
    },
    Hunt {
        sql_select: String,
        include_content: bool,
        limit: usize,
    },
    Export {
        retention_class: Option<RetentionClass>,
        cursor: Option<String>,
        include_content: bool,
        limit: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakeQueryRow {
    pub organisation_id: OrgId,
    pub event_id: Option<String>,
    pub retention_class: Option<RetentionClass>,
    pub root_session_id: Option<String>,
    pub observed_time_ms: Option<i64>,
    pub columns: BTreeMap<String, String>,
    pub content_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LakeQueryResult {
    pub rows: Vec<LakeQueryRow>,
    pub coverage: LakeCoverage,
    pub next_cursor: Option<String>,
    pub scanned_segments: usize,
    pub tail_rows_merged: usize,
}

pub trait EventsPort {
    fn append(
        &self,
        ctx: &SingleCtx,
        fence: FencingToken,
        batch: &LakeBatch,
    ) -> Result<u64, CodedError>;

    fn flush(
        &self,
        ctx: &SingleCtx,
        fence: FencingToken,
        due_before_ms: i64,
        now_ms: i64,
    ) -> Result<LakeFlushResult, CodedError>;

    fn execute_query_ir(
        &self,
        ctx: &TenantCtx,
        query: &LakeQueryIr,
    ) -> Result<LakeQueryResult, CodedError>;

    fn place_hold(&self, ctx: &SingleCtx, hold: &LegalHoldRequest)
    -> Result<LegalHold, CodedError>;

    fn release_hold(
        &self,
        ctx: &SingleCtx,
        hold_id: &str,
        now_ms: i64,
    ) -> Result<LegalHold, CodedError>;

    fn erase_session(
        &self,
        ctx: &SingleCtx,
        root_session_id: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<ErasureReceipt, CodedError>;

    fn compact_and_retain(
        &self,
        ctx: &SingleCtx,
        fence: FencingToken,
        now_ms: i64,
    ) -> Result<LakeCompactionResult, CodedError>;

    fn manifest(&self, ctx: &TenantCtx) -> Result<Option<LakeManifest>, CodedError>;
}

impl RetentionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::Activity => "activity",
            Self::Content => "content",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "decision" => Some(Self::Decision),
            "activity" => Some(Self::Activity),
            "content" => Some(Self::Content),
            _ => None,
        }
    }

    pub const fn retention_days(self) -> u32 {
        match self {
            Self::Decision => DECISION_RETENTION_DAYS,
            Self::Activity => ACTIVITY_RETENTION_DAYS,
            Self::Content => CONTENT_RETENTION_DAYS,
        }
    }

    pub const fn retention_ms(self) -> i64 {
        (self.retention_days() as i64).saturating_mul(MS_PER_DAY)
    }
}

impl LegalHold {
    pub fn is_active_at(&self, now_ms: i64) -> bool {
        if !matches!(self.state, LegalHoldState::Active) {
            return false;
        }
        match self.expires_at_ms {
            Some(exp) => now_ms < exp,
            None => true,
        }
    }

    pub fn covers(
        &self,
        retention_class: RetentionClass,
        day: &str,
        device_ids: &[String],
        root_session_ids: &[String],
    ) -> bool {
        if !self.scope.tables.is_empty() && !self.scope.tables.contains(&retention_class) {
            return false;
        }
        if let Some(start) = &self.scope.day_start
            && day < start.as_str()
        {
            return false;
        }
        if let Some(end) = &self.scope.day_end
            && day > end.as_str()
        {
            return false;
        }
        if !self.scope.device_ids.is_empty()
            && !device_ids.iter().any(|d| self.scope.device_ids.contains(d))
        {
            return false;
        }
        if !self.scope.root_session_ids.is_empty()
            && !root_session_ids
                .iter()
                .any(|s| self.scope.root_session_ids.contains(s))
        {
            return false;
        }
        true
    }
}
