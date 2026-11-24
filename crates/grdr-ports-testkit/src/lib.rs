// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod contract_blob_jobs;
pub mod contract_events;
pub mod contract_rel_bus;
pub mod mem_blob;
pub mod mem_bus;
pub mod mem_jobs;
pub mod mem_lake;
pub mod mem_lake_ops;
pub mod mem_relational;
pub mod query_eval;

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub use contract_blob_jobs::{assert_blob_port_contract, assert_job_port_contract};
pub use contract_events::assert_events_port_contract;
pub use contract_rel_bus::{assert_bus_port_contract, assert_relational_store_contract};
pub use mem_blob::MemoryBlobStore;
pub use mem_bus::MemoryLogBus;
pub use mem_jobs::MemoryJobJournal;
pub use mem_lake::MemoryEventLake;
pub use mem_relational::MemoryRelationalStore;

use jiff::Timestamp;

use grdr_model::error::{CODE_INVALID_INPUT, CODE_STORE_IO};
use grdr_model::{
    ActionAttempt, ActionClass, CodedError, ControlPoint, DecisionReceipt, Grant, KillSwitchState,
    LiveEvent, Verdict,
};
use grdr_ports::{
    Clock, ContainmentMode, DecisionEnginePort, EventSinkPort, PORT_SNAPSHOT_VERSION, PortSnapshot,
    PreparedContainment, SandboxPort, SensorPort, StorePort,
};

#[derive(Debug)]
pub struct FixedClock {
    timestamp_ms: AtomicU64,
    monotonic_ms: AtomicU64,
}

impl FixedClock {
    pub fn new(timestamp: Timestamp, monotonic_ms: u64) -> Self {
        let ts_ms = u64::try_from(timestamp.as_millisecond()).unwrap_or(0);
        Self {
            timestamp_ms: AtomicU64::new(ts_ms),
            monotonic_ms: AtomicU64::new(monotonic_ms),
        }
    }

    pub fn advance_ms(&self, delta_ms: u64) {
        self.timestamp_ms.fetch_add(delta_ms, Ordering::SeqCst);
        self.monotonic_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now_timestamp(&self) -> Timestamp {
        let ms = i64::try_from(self.timestamp_ms.load(Ordering::SeqCst)).unwrap_or(i64::MAX);
        Timestamp::from_millisecond(ms).unwrap_or(Timestamp::UNIX_EPOCH)
    }

    fn monotonic_ms(&self) -> u64 {
        self.monotonic_ms.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Default)]
struct MemoryStoreInner {
    snapshot: Option<PortSnapshot>,
    receipts: Vec<DecisionReceipt>,
}

#[derive(Debug, Default)]
pub struct MemoryStoreAdapter {
    inner: Mutex<MemoryStoreInner>,
}

#[derive(Debug, Default)]
pub struct MemoryEventSink {
    queue: VecDeque<LiveEvent>,
}

#[derive(Debug, Default)]
pub struct MemorySensorAdapter {
    events: VecDeque<ActionAttempt>,
}

#[derive(Debug, Clone, Default)]
pub struct StubSandboxAdapter;

impl StorePort for MemoryStoreAdapter {
    fn save_snapshot(&self, snapshot: &PortSnapshot) -> Result<(), CodedError> {
        let mut guard = self.inner.lock().map_err(|_| {
            CodedError::new(
                CODE_STORE_IO,
                "In-memory store lock poisoned.",
                "Recreate MemoryStoreAdapter.",
            )
        })?;
        guard.snapshot = Some(snapshot.clone());
        Ok(())
    }

    fn load_snapshot(&self) -> Result<Option<PortSnapshot>, CodedError> {
        let guard = self.inner.lock().map_err(|_| {
            CodedError::new(
                CODE_STORE_IO,
                "In-memory store lock poisoned.",
                "Recreate MemoryStoreAdapter.",
            )
        })?;
        Ok(guard.snapshot.clone())
    }

    fn append_receipt(&self, receipt: &DecisionReceipt) -> Result<(), CodedError> {
        let mut guard = self.inner.lock().map_err(|_| {
            CodedError::new(
                CODE_STORE_IO,
                "In-memory store lock poisoned.",
                "Recreate MemoryStoreAdapter.",
            )
        })?;
        guard.receipts.push(receipt.clone());
        Ok(())
    }

    fn read_receipts(&self) -> Result<Vec<DecisionReceipt>, CodedError> {
        let guard = self.inner.lock().map_err(|_| {
            CodedError::new(
                CODE_STORE_IO,
                "In-memory store lock poisoned.",
                "Recreate MemoryStoreAdapter.",
            )
        })?;
        Ok(guard.receipts.clone())
    }
}

impl EventSinkPort for MemoryEventSink {
    fn publish(&mut self, event: LiveEvent) -> Result<(), CodedError> {
        self.queue.push_back(event);
        Ok(())
    }

    fn drain(&mut self) -> Result<Vec<LiveEvent>, CodedError> {
        Ok(self.queue.drain(..).collect())
    }

    fn pending_len(&self) -> usize {
        self.queue.len()
    }
}

impl MemorySensorAdapter {
    pub fn push_event(&mut self, attempt: ActionAttempt) {
        self.events.push_back(attempt);
    }
}

impl SensorPort for MemorySensorAdapter {
    fn sensor_name(&self) -> &'static str {
        "memory-sensor"
    }

    fn poll_events(&mut self, max_events: usize) -> Result<Vec<ActionAttempt>, CodedError> {
        let mut out = Vec::new();
        for _ in 0..max_events {
            let Some(item) = self.events.pop_front() else {
                break;
            };
            out.push(item);
        }
        Ok(out)
    }
}

impl SandboxPort for StubSandboxAdapter {
    fn containment_mode(&self) -> ContainmentMode {
        ContainmentMode::Advisory
    }

    fn prepare_command(
        &self,
        binary: &str,
        args: &[String],
    ) -> Result<PreparedContainment, CodedError> {
        if binary.trim().is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Binary path cannot be empty.",
                "Specify an executable path to launch under containment.",
            ));
        }
        Ok(PreparedContainment {
            mode: self.containment_mode(),
            binary: binary.into(),
            sanitized_args: args.to_vec(),
            stripped_env_keys: vec!["OPENAI_API_KEY".into()],
        })
    }
}

pub fn sample_timestamp() -> Timestamp {
    Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH)
}

pub fn sample_receipt(id: &str, verdict: Verdict, target: &str) -> DecisionReceipt {
    DecisionReceipt {
        receipt_id: id.into(),
        attempt_id: format!("att-{id}"),
        session_id: "sess-testkit".into(),
        device_id: "dev-testkit".into(),
        agent_name: "claude-code".into(),
        action_class: ActionClass::FileWrite,
        control_point: ControlPoint::Hook,
        target: target.into(),
        verdict,
        would_be: None,
        rule_id: None,
        pack_id: None,
        mode_applied: None,
        grant_id: None,
        reason: "Contract test receipt".into(),
        next_step: "None".into(),
        receipt_digest: format!("digest-{id}"),
        decided_at: sample_timestamp(),
        key_id: None,
        signature: None,
        signature_verified: None,
    }
}

pub fn assert_store_port_contract(store: &impl StorePort) -> Result<(), String> {
    let initial = store
        .load_snapshot()
        .map_err(|e| format!("initial load failed: {e}"))?;
    if initial.is_some() {
        return Err("expected fresh store to return None snapshot".into());
    }

    let snapshot = PortSnapshot {
        schema_version: PORT_SNAPSHOT_VERSION,
        device_id: "dev-contract-1".into(),
        hostname: "contract-host".into(),
        packs: Vec::new(),
        grants: Vec::new(),
        trusted_keys: Vec::new(),
        kill_switch: KillSwitchState::Inactive,
        attempts: Vec::new(),
        receipts: Vec::new(),
        pending_attempts: Vec::new(),
        pending_receipts: Vec::new(),
    };
    store
        .save_snapshot(&snapshot)
        .map_err(|e| format!("save_snapshot failed: {e}"))?;

    let loaded = store
        .load_snapshot()
        .map_err(|e| format!("load_snapshot failed: {e}"))?;
    if loaded.as_ref() != Some(&snapshot) {
        return Err("loaded snapshot does not match saved snapshot".into());
    }

    let r1 = sample_receipt("rcp-1", Verdict::Deny, ".claude/settings.json");
    let r2 = sample_receipt("rcp-2", Verdict::Allow, "src/lib.rs");
    store
        .append_receipt(&r1)
        .map_err(|e| format!("append r1 failed: {e}"))?;
    store
        .append_receipt(&r2)
        .map_err(|e| format!("append r2 failed: {e}"))?;

    let receipts = store
        .read_receipts()
        .map_err(|e| format!("read_receipts failed: {e}"))?;
    if receipts != vec![r1, r2] {
        return Err("receipt WAL order mismatch".into());
    }
    Ok(())
}

pub fn assert_event_sink_contract(sink: &mut impl EventSinkPort) -> Result<(), String> {
    if sink.pending_len() != 0 {
        return Err("fresh sink must have 0 pending events".into());
    }
    let now = sample_timestamp();
    let e1 = LiveEvent {
        id: "ev-1".into(),
        topic: "session.verdict".into(),
        summary: "First".into(),
        verdict: Some(Verdict::Allow),
        timestamp: now,
    };
    let e2 = LiveEvent {
        id: "ev-2".into(),
        topic: "policy.changed".into(),
        summary: "Second".into(),
        verdict: None,
        timestamp: now,
    };
    sink.publish(e1.clone())
        .map_err(|e| format!("publish e1 failed: {e}"))?;
    sink.publish(e2.clone())
        .map_err(|e| format!("publish e2 failed: {e}"))?;
    if sink.pending_len() != 2 {
        return Err("expected pending_len == 2".into());
    }
    let drained = sink.drain().map_err(|e| format!("drain failed: {e}"))?;
    if drained != vec![e1, e2] {
        return Err("drained events did not preserve FIFO order".into());
    }
    if sink.pending_len() != 0 {
        return Err("expected pending_len == 0 after drain".into());
    }
    Ok(())
}

pub fn assert_decision_engine_contract(
    engine: &mut impl DecisionEnginePort,
    packs: Vec<grdr_model::PolicyPack>,
    grants: Vec<Grant>,
) -> Result<(), String> {
    engine
        .load_packs(packs)
        .map_err(|e| format!("load_packs failed: {e}"))?;
    for grant in grants {
        engine
            .add_grant(grant)
            .map_err(|e| format!("add_grant failed: {e}"))?;
    }

    let now = sample_timestamp();
    let denied_attempt = ActionAttempt {
        id: "att-deny".into(),
        session_id: "sess-contract".into(),
        device_id: "dev-contract".into(),
        device_name: "host".into(),
        agent_name: "claude-code".into(),
        action_class: ActionClass::FileWrite,
        control_point: ControlPoint::Hook,
        target: ".claude/settings.json".into(),
        summary: "Write protected settings".into(),
        timestamp: now,
        ..Default::default()
    };
    let r_deny = engine
        .evaluate(&denied_attempt)
        .map_err(|e| format!("evaluate denied failed: {e}"))?;
    if r_deny.verdict != Verdict::Deny {
        return Err(format!("expected Deny, got {:?}", r_deny.verdict));
    }

    let safe_attempt = ActionAttempt {
        id: "att-allow".into(),
        session_id: "sess-contract".into(),
        device_id: "dev-contract".into(),
        device_name: "host".into(),
        agent_name: "claude-code".into(),
        action_class: ActionClass::Exec,
        control_point: ControlPoint::Hook,
        target: "git status".into(),
        summary: "Safe git status".into(),
        timestamp: now,
        ..Default::default()
    };
    let r_allow = engine
        .evaluate(&safe_attempt)
        .map_err(|e| format!("evaluate allow failed: {e}"))?;
    if r_allow.verdict != Verdict::Allow {
        return Err(format!("expected Allow, got {:?}", r_allow.verdict));
    }
    Ok(())
}

pub fn assert_sensor_port_contract(sensor: &mut impl SensorPort) -> Result<(), String> {
    if sensor.sensor_name().trim().is_empty() {
        return Err("sensor_name must be non-empty".into());
    }
    let zero = sensor
        .poll_events(0)
        .map_err(|e| format!("poll_events(0) failed: {e}"))?;
    if !zero.is_empty() {
        return Err("poll_events(0) must return empty vec".into());
    }
    let batch = sensor
        .poll_events(2)
        .map_err(|e| format!("poll_events(2) failed: {e}"))?;
    if batch.len() > 2 {
        return Err("poll_events(2) exceeded cap".into());
    }
    Ok(())
}

pub fn assert_sandbox_port_contract(sandbox: &impl SandboxPort) -> Result<(), String> {
    if sandbox.prepare_command("   ", &[]).is_ok() {
        return Err("empty binary should fail".into());
    }
    let prepared = sandbox
        .prepare_command("echo", &["ok".into()])
        .map_err(|e| format!("prepare_command failed: {e}"))?;
    if prepared.mode != sandbox.containment_mode() {
        return Err("prepared containment mode must match sandbox containment_mode".into());
    }
    if prepared.binary != "echo" {
        return Err("unexpected prepared binary".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_core::policy::{essentials_pack, evaluate_with_session};
    use grdr_core::session::SessionRuleState;

    #[derive(Default)]
    struct CoreDecisionAdapter {
        packs: Vec<grdr_model::PolicyPack>,
        grants: Vec<Grant>,
        session_state: SessionRuleState,
    }

    impl DecisionEnginePort for CoreDecisionAdapter {
        fn load_packs(&mut self, packs: Vec<grdr_model::PolicyPack>) -> Result<(), CodedError> {
            self.packs = packs;
            Ok(())
        }

        fn add_grant(&mut self, grant: Grant) -> Result<(), CodedError> {
            self.grants.push(grant);
            Ok(())
        }

        fn evaluate(&mut self, attempt: &ActionAttempt) -> Result<DecisionReceipt, CodedError> {
            Ok(evaluate_with_session(
                attempt,
                &self.packs,
                &mut self.grants,
                &KillSwitchState::Inactive,
                &mut self.session_state,
                attempt.timestamp,
            ))
        }
    }

    #[test]
    fn memory_adapters_satisfy_all_port_contracts() {
        let store = MemoryStoreAdapter::default();
        assert!(assert_store_port_contract(&store).is_ok());

        let mut sink = MemoryEventSink::default();
        assert!(assert_event_sink_contract(&mut sink).is_ok());

        let mut engine = CoreDecisionAdapter::default();
        assert!(
            assert_decision_engine_contract(&mut engine, vec![essentials_pack()], vec![]).is_ok()
        );

        let mut sensor = MemorySensorAdapter::default();
        sensor.push_event(ActionAttempt {
            id: "att-s1".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            device_name: "host-1".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::Exec,
            control_point: ControlPoint::Sensor,
            target: "ls".into(),
            summary: "Sensor test".into(),
            timestamp: sample_timestamp(),
            ..Default::default()
        });
        assert!(assert_sensor_port_contract(&mut sensor).is_ok());

        let sandbox = StubSandboxAdapter;
        assert!(assert_sandbox_port_contract(&sandbox).is_ok());

        let rel = MemoryRelationalStore::default();
        assert!(assert_relational_store_contract(&rel).is_ok());

        let bus = MemoryLogBus::default();
        assert!(assert_bus_port_contract(&bus).is_ok());

        let blobs = MemoryBlobStore::default();
        assert!(assert_blob_port_contract(&blobs).is_ok());

        let jobs = MemoryJobJournal::default();
        assert!(assert_job_port_contract(&jobs).is_ok());

        let lake = MemoryEventLake::default();
        assert_events_port_contract(&lake).unwrap();

        let clock = FixedClock::new(sample_timestamp(), 100);
        clock.advance_ms(250);
        assert_eq!(clock.monotonic_ms(), 350);
    }
}
