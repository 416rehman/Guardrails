// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;

use crate::tenant::{FencingToken, OrgId, SingleCtx, TenantCtx};

pub const CODE_BUS_IO: &str = "GRDR-BUS-0001";
pub const CODE_BUS_STALE_FENCE: &str = "GRDR-BUS-0002";
pub const CODE_BUS_BEYOND_LOG: &str = "GRDR-BUS-0003";
pub const CODE_BUS_INVALID_INPUT: &str = "GRDR-BUS-0004";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusAppendMessage {
    pub key: String,
    pub headers: BTreeMap<String, String>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusOffsetRange {
    pub first_offset: u64,
    pub last_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusMessage {
    pub stream: String,
    pub partition: u32,
    pub offset: u64,
    pub organisation_id: OrgId,
    pub delegation_id: Option<String>,
    pub delegation_epoch: Option<u64>,
    pub key: String,
    pub headers: BTreeMap<String, String>,
    pub payload: Vec<u8>,
    pub appended_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusSubscription {
    pub consumer_group: String,
    pub stream: String,
    pub partition: u32,
    pub holder: String,
    pub fence: FencingToken,
    pub committed_offset: Option<u64>,
    pub checkpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusLag {
    pub stream: String,
    pub partition: u32,
    pub head_offset: Option<u64>,
    pub committed_offset: Option<u64>,
    pub pending_messages: u64,
}

pub trait BusPort {
    fn append(
        &self,
        ctx: &SingleCtx,
        stream: &str,
        partition: u32,
        messages: &[BusAppendMessage],
        now_ms: i64,
    ) -> Result<BusOffsetRange, CodedError>;

    fn subscribe(
        &self,
        consumer_group: &str,
        stream: &str,
        partition: u32,
        holder: &str,
        fence: FencingToken,
        expiry_ms: i64,
    ) -> Result<BusSubscription, CodedError>;

    fn fetch(
        &self,
        ctx: &TenantCtx,
        stream: &str,
        partition: u32,
        after_offset: Option<u64>,
        limit: usize,
    ) -> Result<Vec<BusMessage>, CodedError>;

    fn commit(
        &self,
        consumer_group: &str,
        stream: &str,
        partition: u32,
        offset: u64,
        checkpoint: Option<&str>,
        fence: FencingToken,
    ) -> Result<(), CodedError>;

    fn lag(
        &self,
        ctx: &TenantCtx,
        consumer_group: &str,
        stream: &str,
        partition: u32,
    ) -> Result<BusLag, CodedError>;
}
