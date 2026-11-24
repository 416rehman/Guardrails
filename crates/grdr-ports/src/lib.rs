// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedContainment {
    pub mode: String,
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
    fn containment_mode(&self) -> &'static str;
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
