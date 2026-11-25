// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod blob;
pub mod bus;
pub mod clock;
pub mod events;
pub mod hunt_sql;
pub mod jobs;
pub mod relational;
pub mod tenant;

use serde::{Deserialize, Serialize};

pub use blob::{
    BlobMetadata, BlobObject, BlobPort, BlobVersionCondition, ByteRange, CODE_BLOB_ALREADY_EXISTS,
    CODE_BLOB_INVALID_RANGE, CODE_BLOB_IO, CODE_BLOB_VERSION_CONFLICT,
};
pub use bus::{
    BusAppendMessage, BusLag, BusMessage, BusOffsetRange, BusPort, BusSubscription,
    CODE_BUS_BEYOND_LOG, CODE_BUS_INVALID_INPUT, CODE_BUS_IO, CODE_BUS_STALE_FENCE,
};
pub use clock::Clock;
pub use events::{
    CODE_LAKE_HOLD_ACTIVE, CODE_LAKE_INVALID_QUERY, CODE_LAKE_IO, CODE_LAKE_KEY_DESTROYED,
    CODE_LAKE_NOT_FOUND, CODE_LAKE_STALE_FENCE, ContentKeyState, ErasureReceipt, EventsPort,
    LakeAggOp, LakeAggSpec, LakeBatch, LakeCompactionResult, LakeCoverage, LakeFlushResult,
    LakeManifest, LakeManifestEntry, LakeObservable, LakePredicate, LakeQueryIr, LakeQueryResult,
    LakeQueryRow, LakeRecord, LegalHold, LegalHoldRequest, LegalHoldScope, LegalHoldState,
    RetentionClass, SessionContentKey,
};
pub use hunt_sql::{HuntTable, ParsedHunt, parse_hunt_sql};
pub use jobs::{
    CODE_JOBS_INVALID_STATE, CODE_JOBS_IO, CODE_JOBS_NOT_FOUND, CODE_JOBS_STALE_FENCE,
    JobEnqueueOutcome, JobEnqueueRequest, JobPort, JobRecord, JobState, JobStepRecord,
    JobStepState, LeaseAcquireOutcome, LeaseRecord, LeaseState,
};
pub use relational::{
    DeviceRepo, EntityKind, EntitySearchHit, FindingRepo, KvSnapshotRepo, MigrationRecord,
    PolicyRepo, RelationalStorePort, SessionSummaryRepo, TenantUserRecord, UserRepo,
};
pub use tenant::{
    CODE_BLOB_INVALID_PATH, CODE_TENANT_INVALID_ID, CODE_TENANT_SCOPE_MISMATCH,
    CODE_TENANT_WRITE_FORBIDDEN, FencingToken, OrgId, ProfileKind, SetCtx, SingleCtx, TenantCtx,
    TenantPath, TenantRelPath,
};

use grdr_model::{
    ActionAttempt, CodedError, DecisionReceipt, Grant, KillSwitchState, LiveEvent, PolicyPack,
    TrustedKeyInfo,
};

pub const PORT_SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSnapshot {
    pub schema_version: u32,
    pub device_id: String,
    pub hostname: String,
    pub packs: Vec<PolicyPack>,
    pub grants: Vec<Grant>,
    pub trusted_keys: Vec<TrustedKeyInfo>,
    pub kill_switch: KillSwitchState,
    pub attempts: Vec<ActionAttempt>,
    pub receipts: Vec<DecisionReceipt>,
    pub pending_attempts: Vec<ActionAttempt>,
    pub pending_receipts: Vec<DecisionReceipt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentMode {
    Advisory,
    Restricted,
    Isolated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedContainment {
    pub mode: ContainmentMode,
    pub binary: String,
    pub sanitized_args: Vec<String>,
    pub stripped_env_keys: Vec<String>,
}

pub trait StorePort {
    fn save_snapshot(&self, snapshot: &PortSnapshot) -> Result<(), CodedError>;
    fn load_snapshot(&self) -> Result<Option<PortSnapshot>, CodedError>;
    fn append_receipt(&self, receipt: &DecisionReceipt) -> Result<(), CodedError>;
    fn read_receipts(&self) -> Result<Vec<DecisionReceipt>, CodedError>;
}

pub trait EventSinkPort {
    fn publish(&mut self, event: LiveEvent) -> Result<(), CodedError>;
    fn drain(&mut self) -> Result<Vec<LiveEvent>, CodedError>;
    fn pending_len(&self) -> usize;
}

pub trait DecisionEnginePort {
    fn load_packs(&mut self, packs: Vec<PolicyPack>) -> Result<(), CodedError>;
    fn add_grant(&mut self, grant: Grant) -> Result<(), CodedError>;
    fn evaluate(&mut self, attempt: &ActionAttempt) -> Result<DecisionReceipt, CodedError>;
}

pub trait SensorPort {
    fn sensor_name(&self) -> &'static str;
    fn poll_events(&mut self, max_events: usize) -> Result<Vec<ActionAttempt>, CodedError>;
}

pub trait SandboxPort {
    fn containment_mode(&self) -> ContainmentMode;
    fn prepare_command(
        &self,
        binary: &str,
        args: &[String],
    ) -> Result<PreparedContainment, CodedError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_snapshot_roundtrips_json() {
        let snapshot = PortSnapshot {
            schema_version: PORT_SNAPSHOT_VERSION,
            device_id: "dev-port-1".into(),
            hostname: "host-port".into(),
            packs: Vec::new(),
            grants: Vec::new(),
            trusted_keys: Vec::new(),
            kill_switch: KillSwitchState::Inactive,
            attempts: Vec::new(),
            receipts: Vec::new(),
            pending_attempts: Vec::new(),
            pending_receipts: Vec::new(),
        };
        let encoded = serde_json::to_string(&snapshot).unwrap();
        let decoded: PortSnapshot = serde_json::from_str(&encoded).unwrap();
        assert_eq!(snapshot, decoded);
    }
}
