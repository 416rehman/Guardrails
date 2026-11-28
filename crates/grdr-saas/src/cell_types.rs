// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_compat::VersionRange;
use grdr_crypto::sha256_digest;
use grdr_model::CodedError;
use grdr_ports::OrgId;

use crate::config::SaasOperationalBounds;
use crate::{CODE_SAAS_CELL_UNAVAILABLE, CODE_SAAS_INVALID_INPUT, saas_error};

pub const BUCKET_COUNT: u16 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RegionId(String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct CellId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellState {
    Active,
    Draining,
    ReadOnly,
    Decommissioned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawBucketRange")]
pub struct BucketRange {
    pub start_inclusive: u16,
    pub end_exclusive: u16,
}

#[derive(Debug, Deserialize)]
struct RawBucketRange {
    start_inclusive: u16,
    end_exclusive: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellCapacityVector {
    pub cpu_pct: u8,
    pub active_sessions: u32,
    pub storage_pct: u8,
    pub write_iops_pct: u8,
    pub max_sessions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellEndpoint {
    pub cell_id: CellId,
    pub region: RegionId,
    pub api_endpoint: String,
    pub state: CellState,
    pub buckets: BucketRange,
    pub capacity: CellCapacityVector,
    pub protocol_range: VersionRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgPlacement {
    pub org_id: OrgId,
    pub required_region: RegionId,
    pub primary_cell: CellId,
    pub target_cell: Option<CellId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellSplitResult {
    pub source_cell: CellId,
    pub new_cell: CellId,
    pub source_buckets: BucketRange,
    pub new_buckets: BucketRange,
    pub reassigned_orgs: Vec<OrgId>,
}

impl RegionId {
    pub fn new(raw: impl Into<String>) -> Result<Self, CodedError> {
        let trimmed = raw.into().trim().to_ascii_lowercase();
        if trimmed.is_empty()
            || !trimmed
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                "Region identifier must contain lowercase ASCII letters, digits, or hyphens.",
                "Pass a normalized region identifier such as us-east-1 or eu-central-1.",
            ));
        }
        Ok(Self(trimmed))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RegionId {
    type Error = CodedError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl CellId {
    pub fn new(raw: impl Into<String>) -> Result<Self, CodedError> {
        let trimmed = raw.into().trim().to_ascii_lowercase();
        if trimmed.is_empty()
            || !trimmed
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                "Cell identifier must contain lowercase ASCII letters, digits, or hyphens.",
                "Use a stable cell slug such as cell-us-01.",
            ));
        }
        Ok(Self(trimmed))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CellId {
    type Error = CodedError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl BucketRange {
    pub fn new(start_inclusive: u16, end_exclusive: u16) -> Result<Self, CodedError> {
        if start_inclusive >= end_exclusive || end_exclusive > BUCKET_COUNT {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!(
                    "Invalid bucket range [{start_inclusive}, {end_exclusive}) outside [0, {BUCKET_COUNT})."
                ),
                "Ensure start_inclusive < end_exclusive <= 4096.",
            ));
        }
        Ok(Self {
            start_inclusive,
            end_exclusive,
        })
    }

    #[must_use]
    pub const fn full() -> Self {
        Self {
            start_inclusive: 0,
            end_exclusive: BUCKET_COUNT,
        }
    }

    #[must_use]
    pub const fn contains(&self, bucket: u16) -> bool {
        bucket >= self.start_inclusive && bucket < self.end_exclusive
    }

    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start_inclusive < other.end_exclusive && other.start_inclusive < self.end_exclusive
    }

    #[must_use]
    pub fn len(&self) -> u16 {
        self.end_exclusive.saturating_sub(self.start_inclusive)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn split_midpoint(&self) -> Result<(Self, Self), CodedError> {
        let width = self.len();
        if width < 2 {
            return Err(saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                "Cannot split a cell bucket range with fewer than two buckets.",
                "Add a dedicated region cell before moving single-bucket tenants.",
            ));
        }
        let half = width / 2;
        let midpoint = self.start_inclusive.saturating_add(half);
        Ok((
            Self::new(self.start_inclusive, midpoint)?,
            Self::new(midpoint, self.end_exclusive)?,
        ))
    }
}

impl TryFrom<RawBucketRange> for BucketRange {
    type Error = CodedError;

    fn try_from(raw: RawBucketRange) -> Result<Self, Self::Error> {
        Self::new(raw.start_inclusive, raw.end_exclusive)
    }
}

impl CellCapacityVector {
    #[must_use]
    pub fn max_utilization_pct(&self) -> u8 {
        let session_pct = if self.max_sessions == 0 {
            100
        } else {
            let scaled = u64::from(self.active_sessions)
                .saturating_mul(100)
                .checked_div(u64::from(self.max_sessions))
                .unwrap_or(100);
            u8::try_from(scaled.min(100)).unwrap_or(100)
        };
        self.cpu_pct
            .max(self.storage_pct)
            .max(self.write_iops_pct)
            .max(session_pct)
    }

    #[must_use]
    pub fn needs_split(&self, bounds: &SaasOperationalBounds) -> bool {
        self.max_utilization_pct() >= bounds.cell_soft_cap_pct
    }

    #[must_use]
    pub fn can_accept_org(&self, bounds: &SaasOperationalBounds) -> bool {
        let ceiling = 100u8.saturating_sub(bounds.cell_reserve_pct);
        self.max_utilization_pct() < bounds.cell_soft_cap_pct
            && self.max_utilization_pct() < ceiling
    }
}

#[must_use]
pub fn device_bucket(device_id: &str) -> u16 {
    let digest = sha256_digest(device_id.as_bytes());
    let b0 = digest.first().copied().unwrap_or(0);
    let b1 = digest.get(1).copied().unwrap_or(0);
    u16::from_be_bytes([b0, b1]) & BUCKET_COUNT.saturating_sub(1)
}
