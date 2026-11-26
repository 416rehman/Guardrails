// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Typed JSON codecs for `grdr-daemon` storage, check-in, grant, receipt, and history messages
//! so privileged layer-4 daemon code avoids direct `serde_json` dependency (`ARCH-004`).

use grdr_model::{DecisionReceipt, DeviceCheckinRequest, DeviceCheckinResponse, Grant, PolicyPack};
use serde::{Deserialize, Serialize};

use crate::StoreError;
use crate::recorder::RecordedEntry;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecorderHistoryItem {
    pub id: i64,
    pub ts_unix_s: i64,
    pub lane: String,
    pub kind: String,
    pub session_id: String,
    pub payload_utf8: String,
}

pub fn encode_pack_json(pack: &PolicyPack) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(pack).map_err(|e| StoreError::Codec(e.to_string()))
}

pub fn encode_grant_json(grant: &Grant) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(grant).map_err(|e| StoreError::Codec(e.to_string()))
}

pub fn decode_grant_json(bytes: &[u8]) -> Result<Grant, StoreError> {
    serde_json::from_slice(bytes).map_err(|e| StoreError::Codec(e.to_string()))
}

pub fn encode_receipt_json(receipt: &DecisionReceipt) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(receipt).map_err(|e| StoreError::Codec(e.to_string()))
}

pub fn encode_receipt_list_json(receipts: &[DecisionReceipt]) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(receipts).map_err(|e| StoreError::Codec(e.to_string()))
}

pub fn decode_receipt_list_json(bytes: &[u8]) -> Result<Vec<DecisionReceipt>, StoreError> {
    serde_json::from_slice(bytes).map_err(|e| StoreError::Codec(e.to_string()))
}

pub fn encode_history_entries_json(entries: &[RecordedEntry]) -> Result<Vec<u8>, StoreError> {
    let items: Vec<RecorderHistoryItem> = entries
        .iter()
        .map(|entry| RecorderHistoryItem {
            id: entry.id,
            ts_unix_s: entry.ts_unix_s,
            lane: entry.lane.clone(),
            kind: entry.kind.clone(),
            session_id: entry.session_id.clone(),
            payload_utf8: String::from_utf8_lossy(&entry.payload).into_owned(),
        })
        .collect();
    serde_json::to_vec(&items).map_err(|e| StoreError::Codec(e.to_string()))
}

pub fn decode_history_entries_json(bytes: &[u8]) -> Result<Vec<RecorderHistoryItem>, StoreError> {
    serde_json::from_slice(bytes).map_err(|e| StoreError::Codec(e.to_string()))
}

pub fn encode_checkin_request_json(req: &DeviceCheckinRequest) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(req).map_err(|e| StoreError::Codec(e.to_string()))
}

pub fn decode_checkin_response_json(bytes: &[u8]) -> Result<DeviceCheckinResponse, StoreError> {
    serde_json::from_slice(bytes).map_err(|e| StoreError::Codec(e.to_string()))
}

#[must_use]
pub fn encode_checkin_response_json_for_test(resp: &DeviceCheckinResponse) -> Vec<u8> {
    serde_json::to_vec(resp).unwrap_or_default()
}
