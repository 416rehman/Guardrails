// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use grdr_fastpath::{
    AssuranceVerdict, FLOOR_FORMAT_VERSION, FastpathBrandManifest, HostProfile,
    HostRuleRequirements, REQ_COMMAND_PARSER, REQ_NET_EGRESS_SENSOR, REQ_OS_FILE_SENSOR,
    REQ_SESSION_STORE, REQ_USER_IDENTITY,
};
use jiff::Timestamp;

use crate::eval::evaluate_wasm_with_session;
use crate::floor::{collect_pack_requirements, compile_wasm_floor_table};
use crate::model_dto::{
    WasmActionAttempt, WasmActionClass, WasmCodedError, WasmCompiledFloorTable, WasmGrant,
    WasmKillSwitchState, WasmMode, WasmPolicyPack,
};
use crate::types::{
    DEFAULT_WASM_STEP_BUDGET, WasmAssuranceKind, WasmBrandManifest, WasmCheckpoint,
    WasmHostProfile, WasmInterestSummary, WasmPackAssurance, WasmRequiredSignal, WasmSessionState,
    WasmSnapshotSummary, WasmStepOutput,
};

#[derive(Debug, Clone)]
pub struct WasmEngine {
    packs: Vec<WasmPolicyPack>,
    grants: Vec<WasmGrant>,
    kill_switch: WasmKillSwitchState,
    host_profile: WasmHostProfile,
    session: WasmSessionState,
    epoch: u64,
    steps_executed: u64,
    step_budget: u64,
    bundle_tag: String,
    snapshots: BTreeMap<String, WasmCheckpoint>,
}

impl Default for WasmEngine {
    fn default() -> Self {
        Self::new(DEFAULT_WASM_STEP_BUDGET)
    }
}

impl WasmEngine {
    pub fn new(step_budget: u64) -> Self {
        Self {
            packs: Vec::new(),
            grants: Vec::new(),
            kill_switch: WasmKillSwitchState::Inactive,
            host_profile: WasmHostProfile::default(),
            session: WasmSessionState::default(),
            epoch: 0,
            steps_executed: 0,
            step_budget,
            bundle_tag: String::new(),
            snapshots: BTreeMap::new(),
        }
    }

    pub fn load(
        &mut self,
        packs: Vec<WasmPolicyPack>,
        grants: Vec<WasmGrant>,
        kill_switch: WasmKillSwitchState,
        host_profile: WasmHostProfile,
        bundle_tag: String,
    ) -> Result<WasmInterestSummary, WasmCodedError> {
        if packs.is_empty() {
            return Err(WasmCodedError::invalid_input(
                "Policy packs are required; implicit Essentials fallback is disabled.",
                "Supply at least one PolicyPack explicitly in WasmEngine::load.",
            ));
        }
        self.packs = packs;
        self.grants = grants;
        self.kill_switch = kill_switch;
        self.host_profile = host_profile;
        self.bundle_tag = bundle_tag;
        self.epoch = self.epoch.saturating_add(1);
        self.session = WasmSessionState::default();
        self.steps_executed = 0;
        Ok(self.interest())
    }

    pub fn interest(&self) -> WasmInterestSummary {
        let mut actions: Vec<WasmActionClass> = Vec::new();
        let mut prefixes = BTreeSet::new();
        let mut contains = BTreeSet::new();
        let mut agents = BTreeSet::new();
        let mut required_signals = BTreeSet::new();

        for pack in &self.packs {
            let (req, _) = collect_pack_requirements(pack);
            push_required_signals(req, &mut required_signals);
            for rule in &pack.rules {
                if !rule.enabled || rule.mode == WasmMode::Off {
                    continue;
                }
                for ac in &rule.matcher.action_classes {
                    if !actions.contains(ac) {
                        actions.push(*ac);
                    }
                }
                for p in &rule.matcher.target_prefixes {
                    prefixes.insert(p.clone());
                }
                for c in &rule.matcher.target_contains {
                    contains.insert(c.clone());
                }
                for a in &rule.matcher.agents {
                    agents.insert(a.clone());
                }
            }
        }

        WasmInterestSummary {
            action_classes: actions,
            target_prefixes: prefixes.into_iter().collect(),
            target_contains: contains.into_iter().collect(),
            agents: agents.into_iter().collect(),
            required_signals,
            bundle_tag: self.bundle_tag.clone(),
        }
    }

    pub fn assess_host_profile(&self) -> Vec<WasmPackAssurance> {
        let hp = HostProfile::from(self.host_profile);
        let mut out = Vec::with_capacity(self.packs.len());
        for pack in &self.packs {
            let (req, has_enforced) = collect_pack_requirements(pack);
            let (assurance, reason) = match hp.assess_full_requirements(req) {
                AssuranceVerdict::Evaluable => {
                    if has_enforced {
                        (
                            WasmAssuranceKind::Enforced,
                            "host capabilities satisfied".into(),
                        )
                    } else {
                        (
                            WasmAssuranceKind::WatchOnly,
                            "pack contains watch-only rules".into(),
                        )
                    }
                }
                AssuranceVerdict::NotEvaluable(msg) => {
                    (WasmAssuranceKind::NotEvaluable, msg.into())
                }
            };
            out.push(WasmPackAssurance {
                pack_id: pack.id.clone(),
                assurance,
                reason,
            });
        }
        out
    }

    pub fn checkpoint(&self) -> WasmCheckpoint {
        WasmCheckpoint {
            packs: self.packs.clone(),
            grants: self.grants.clone(),
            kill_switch: self.kill_switch.clone(),
            host_profile: self.host_profile,
            session: self.session.clone(),
            epoch: self.epoch,
            steps_executed: self.steps_executed,
            step_budget: self.step_budget,
            bundle_tag: self.bundle_tag.clone(),
        }
    }

    pub fn snapshot(&mut self, id: String) -> WasmSnapshotSummary {
        let cp = self.checkpoint();
        let summary = WasmSnapshotSummary {
            snapshot_id: id.clone(),
            epoch: cp.epoch,
            steps_executed: cp.steps_executed,
            denial_count: cp.session.denial_count,
            step_up_count: cp.session.step_up_count,
        };
        self.snapshots.insert(id, cp);
        summary
    }

    pub fn restore(&mut self, id: &str) -> Result<WasmSnapshotSummary, WasmCodedError> {
        let Some(cp) = self.snapshots.get(id).cloned() else {
            return Err(WasmCodedError::invalid_input(
                format!("Snapshot '{id}' does not exist."),
                "Provide a valid snapshot identifier.",
            ));
        };
        self.restore_checkpoint(cp);
        Ok(WasmSnapshotSummary {
            snapshot_id: id.to_owned(),
            epoch: self.epoch,
            steps_executed: self.steps_executed,
            denial_count: self.session.denial_count,
            step_up_count: self.session.step_up_count,
        })
    }

    pub fn restore_checkpoint(&mut self, cp: WasmCheckpoint) {
        self.packs = cp.packs;
        self.grants = cp.grants;
        self.kill_switch = cp.kill_switch;
        self.host_profile = cp.host_profile;
        self.session = cp.session;
        self.epoch = cp.epoch;
        self.steps_executed = cp.steps_executed;
        self.step_budget = cp.step_budget;
        self.bundle_tag = cp.bundle_tag;
    }

    pub fn step(&mut self, attempt: &WasmActionAttempt) -> Result<WasmStepOutput, WasmCodedError> {
        if self.packs.is_empty() {
            return Err(WasmCodedError::invalid_input(
                "No policy packs loaded into WASM engine.",
                "Call load() before step().",
            ));
        }
        let pre_step = self.checkpoint();
        if self.steps_executed >= self.step_budget {
            self.restore_checkpoint(pre_step);
            return Err(WasmCodedError::invalid_input(
                "WASM engine step budget exceeded; state rolled back.",
                "Restore snapshot or allocate larger step budget.",
            ));
        }

        let pack_assurances = self.assess_host_profile();
        if let Some(failed) = pack_assurances
            .iter()
            .find(|p| p.assurance == WasmAssuranceKind::NotEvaluable)
        {
            let reason = failed.reason.clone();
            self.restore_checkpoint(pre_step);
            return Err(WasmCodedError::invalid_input(
                format!("HostProfile cannot evaluate loaded policy ({reason})."),
                "Supply required host capabilities or filter incompatible rules.",
            ));
        }

        if attempt.target.trim().is_empty() {
            self.restore_checkpoint(pre_step);
            return Err(WasmCodedError::invalid_input(
                "ActionAttempt requires non-empty target; state rolled back.",
                "Provide valid ActionAttempt.",
            ));
        }

        let receipt = evaluate_wasm_with_session(
            attempt,
            &self.packs,
            &mut self.grants,
            &self.kill_switch,
            &mut self.session,
            attempt.timestamp,
        );
        self.steps_executed = self.steps_executed.saturating_add(1);
        let assurance = worst_case_assurance(&pack_assurances);
        Ok(WasmStepOutput {
            receipt,
            assurance,
            steps_executed: self.steps_executed,
            fastpath_version: FLOOR_FORMAT_VERSION,
        })
    }

    pub fn compile_floor_at(
        &self,
        compiled_at: Timestamp,
    ) -> Result<WasmCompiledFloorTable, WasmCodedError> {
        if self.packs.is_empty() {
            return Err(WasmCodedError::invalid_input(
                "No policy packs loaded for floor compilation.",
                "Call load() first.",
            ));
        }
        Ok(compile_wasm_floor_table(&self.packs, compiled_at))
    }

    pub fn brand_manifest(custom_toml: Option<&str>) -> WasmBrandManifest {
        let parsed = match custom_toml {
            Some(raw) => FastpathBrandManifest::from_toml(raw),
            None => FastpathBrandManifest::embedded(),
        };
        WasmBrandManifest {
            schema: parsed.schema.to_owned(),
            namespace: parsed.namespace.to_owned(),
            product_name: parsed.product_name.to_owned(),
            short_name: parsed.short_name.to_owned(),
            publisher: parsed.publisher.to_owned(),
            domain: parsed.domain.to_owned(),
            copyright_holder: parsed.copyright_holder.to_owned(),
        }
    }
}

fn push_required_signals(req: HostRuleRequirements, out: &mut BTreeSet<WasmRequiredSignal>) {
    if req.contains(REQ_USER_IDENTITY) {
        out.insert(WasmRequiredSignal::UserIdentity);
    }
    if req.contains(REQ_OS_FILE_SENSOR) {
        out.insert(WasmRequiredSignal::FileSensor);
    }
    if req.contains(REQ_NET_EGRESS_SENSOR) {
        out.insert(WasmRequiredSignal::NetEgressSensor);
    }
    if req.contains(REQ_COMMAND_PARSER) {
        out.insert(WasmRequiredSignal::CommandParser);
    }
    if req.contains(REQ_SESSION_STORE) {
        out.insert(WasmRequiredSignal::SessionStore);
    }
}

fn worst_case_assurance(items: &[WasmPackAssurance]) -> WasmAssuranceKind {
    items
        .iter()
        .map(|p| p.assurance)
        .min_by_key(|a| a.severity_rank())
        .unwrap_or(WasmAssuranceKind::WatchOnly)
}
