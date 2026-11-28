// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use grdr_core::compile::compile_floor_table;
use grdr_core::policy::evaluate_with_session;
use grdr_core::session::SessionRuleState;
use grdr_fastpath::{
    AssuranceVerdict, FLOOR_FORMAT_VERSION, FastpathBrandManifest, HostProfile,
    HostRuleRequirements, REQ_COMMAND_PARSER, REQ_NET_EGRESS_SENSOR, REQ_OS_FILE_SENSOR,
    REQ_SESSION_STORE, REQ_USER_IDENTITY,
};
use grdr_model::{
    ActionAttempt, ActionClass, CodedError, CompiledFloorTable, Grant, KillSwitchState, Mode,
    PolicyPack,
};
use jiff::Timestamp;

use crate::types::invalid_input;
pub use crate::types::{
    AssuranceKind, BrandManifestDto, CapabilityPresence, DEFAULT_STEP_BUDGET, EngineCheckpoint,
    FfiStepOutput, HostProfileDto, InterestSummary, PackAssuranceDto, RequiredHostSignal,
    SnapshotSummary,
};

#[derive(Debug, Clone)]
pub struct FfiEngine {
    packs: Vec<PolicyPack>,
    grants: Vec<Grant>,
    kill_switch: KillSwitchState,
    host_profile: HostProfileDto,
    session: SessionRuleState,
    epoch: u64,
    steps_executed: u64,
    step_budget: u64,
    bundle_tag: String,
    snapshots: BTreeMap<String, EngineCheckpoint>,
}

impl Default for FfiEngine {
    fn default() -> Self {
        Self::new(DEFAULT_STEP_BUDGET)
    }
}

impl FfiEngine {
    pub fn new(step_budget: u64) -> Self {
        Self {
            packs: Vec::new(),
            grants: Vec::new(),
            kill_switch: KillSwitchState::Inactive,
            host_profile: HostProfileDto::default(),
            session: SessionRuleState::default(),
            epoch: 0,
            steps_executed: 0,
            step_budget,
            bundle_tag: String::new(),
            snapshots: BTreeMap::new(),
        }
    }

    pub fn load(
        &mut self,
        packs: Vec<PolicyPack>,
        grants: Vec<Grant>,
        kill_switch: KillSwitchState,
        host_profile: HostProfileDto,
        bundle_tag: String,
    ) -> Result<InterestSummary, CodedError> {
        if packs.is_empty() {
            return Err(invalid_input(
                "Policy packs are required; implicit Essentials fallback is disabled.",
                "Supply at least one PolicyPack explicitly in load().",
            ));
        }
        self.packs = packs;
        self.grants = grants;
        self.kill_switch = kill_switch;
        self.host_profile = host_profile;
        self.bundle_tag = bundle_tag;
        self.epoch = self.epoch.saturating_add(1);
        self.session = SessionRuleState::default();
        self.steps_executed = 0;
        Ok(self.interest())
    }

    pub fn interest(&self) -> InterestSummary {
        let mut actions: Vec<ActionClass> = Vec::new();
        let mut prefixes = BTreeSet::new();
        let mut contains = BTreeSet::new();
        let mut agents = BTreeSet::new();
        let mut required_signals = BTreeSet::new();

        for pack in &self.packs {
            let (req, _) = collect_pack_requirements(pack);
            push_required_signals(req, &mut required_signals);
            for rule in &pack.rules {
                if !rule.enabled || rule.mode == Mode::Off {
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

        InterestSummary {
            action_classes: actions,
            target_prefixes: prefixes.into_iter().collect(),
            target_contains: contains.into_iter().collect(),
            agents: agents.into_iter().collect(),
            required_signals,
            bundle_tag: self.bundle_tag.clone(),
        }
    }

    pub fn assess_host_profile(&self) -> Vec<PackAssuranceDto> {
        let hp = HostProfile::from(self.host_profile);
        let mut out = Vec::with_capacity(self.packs.len());
        for pack in &self.packs {
            let (req, has_enforced) = collect_pack_requirements(pack);
            let (assurance, reason) = match hp.assess_full_requirements(req) {
                AssuranceVerdict::Evaluable => {
                    if has_enforced {
                        (
                            AssuranceKind::Enforced,
                            "host capabilities satisfied".into(),
                        )
                    } else {
                        (
                            AssuranceKind::WatchOnly,
                            "pack contains watch-only rules".into(),
                        )
                    }
                }
                AssuranceVerdict::NotEvaluable(msg) => (AssuranceKind::NotEvaluable, msg.into()),
            };
            out.push(PackAssuranceDto {
                pack_id: pack.id.clone(),
                assurance,
                reason,
            });
        }
        out
    }

    pub fn checkpoint(&self) -> EngineCheckpoint {
        EngineCheckpoint {
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

    pub fn snapshot(&mut self, id: String) -> SnapshotSummary {
        let cp = self.checkpoint();
        let summary = SnapshotSummary {
            snapshot_id: id.clone(),
            epoch: cp.epoch,
            steps_executed: cp.steps_executed,
            denial_count: cp.session.denial_count,
            step_up_count: cp.session.step_up_count,
            labels: cp.session.extra_labels.iter().cloned().collect(),
        };
        self.snapshots.insert(id, cp);
        summary
    }

    pub fn restore(&mut self, id: &str) -> Result<SnapshotSummary, CodedError> {
        let Some(cp) = self.snapshots.get(id).cloned() else {
            return Err(invalid_input(
                format!("Snapshot '{id}' does not exist."),
                "Provide a snapshot_id returned by snapshot().",
            ));
        };
        self.restore_checkpoint(cp);
        Ok(SnapshotSummary {
            snapshot_id: id.to_owned(),
            epoch: self.epoch,
            steps_executed: self.steps_executed,
            denial_count: self.session.denial_count,
            step_up_count: self.session.step_up_count,
            labels: self.session.extra_labels.iter().cloned().collect(),
        })
    }

    pub fn restore_checkpoint(&mut self, cp: EngineCheckpoint) {
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

    pub fn step(&mut self, attempt: &ActionAttempt) -> Result<FfiStepOutput, CodedError> {
        if self.packs.is_empty() {
            return Err(invalid_input(
                "No policy packs loaded into engine.",
                "Call load() with explicit PolicyPacks before step().",
            ));
        }
        let pre_step = self.checkpoint();
        if self.steps_executed >= self.step_budget {
            self.restore_checkpoint(pre_step);
            return Err(invalid_input(
                "Engine step budget exceeded; state rolled back.",
                "Reset or snapshot/restore with higher budget.",
            ));
        }

        let pack_assurances = self.assess_host_profile();
        if let Some(failed) = pack_assurances
            .iter()
            .find(|p| p.assurance == AssuranceKind::NotEvaluable)
        {
            let reason = failed.reason.clone();
            self.restore_checkpoint(pre_step);
            return Err(invalid_input(
                format!("HostProfile cannot evaluate loaded policy ({reason})."),
                "Provide missing HostProfile capabilities or remove dependent rules.",
            ));
        }

        if attempt.target.trim().is_empty() {
            self.restore_checkpoint(pre_step);
            return Err(invalid_input(
                "ActionAttempt requires non-empty target; state rolled back.",
                "Supply a non-empty target.",
            ));
        }

        let receipt = evaluate_with_session(
            attempt,
            &self.packs,
            &mut self.grants,
            &self.kill_switch,
            &mut self.session,
            attempt.timestamp,
        );
        self.steps_executed = self.steps_executed.saturating_add(1);
        let assurance = worst_case_assurance(&pack_assurances);
        Ok(FfiStepOutput {
            receipt,
            assurance,
            steps_executed: self.steps_executed,
            fastpath_version: FLOOR_FORMAT_VERSION,
        })
    }

    pub fn compile_fastpath(
        &self,
        compiled_at: Timestamp,
    ) -> Result<CompiledFloorTable, CodedError> {
        if self.packs.is_empty() {
            return Err(invalid_input(
                "No policy packs loaded for fastpath compilation.",
                "Call load() first.",
            ));
        }
        Ok(compile_floor_table(&self.packs, compiled_at))
    }

    pub fn brand_manifest(custom_toml: Option<&str>) -> BrandManifestDto {
        let parsed = match custom_toml {
            Some(raw) => FastpathBrandManifest::from_toml(raw),
            None => FastpathBrandManifest::embedded(),
        };
        BrandManifestDto {
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

fn collect_pack_requirements(pack: &PolicyPack) -> (HostRuleRequirements, bool) {
    let mut req = HostRuleRequirements::empty();
    let mut has_enforced = false;
    for rule in &pack.rules {
        if !rule.enabled || rule.mode == Mode::Off {
            continue;
        }
        if matches!(rule.mode, Mode::Ask | Mode::Block) {
            has_enforced = true;
        }
        for ac in &rule.matcher.action_classes {
            match ac {
                ActionClass::FileRead | ActionClass::FileWrite | ActionClass::FileDelete => {
                    req = req.with(REQ_OS_FILE_SENSOR);
                }
                ActionClass::Exec => {
                    req = req.with(REQ_COMMAND_PARSER);
                }
                ActionClass::NetConnect | ActionClass::NetRequest | ActionClass::DataFlow => {
                    req = req.with(REQ_NET_EGRESS_SENSOR);
                }
                _ => {}
            }
        }
        let cedar_src = rule.cedar.as_deref().unwrap_or("");
        if cedar_src.contains("Grdr::User") || cedar_src.contains("user.") {
            req = req.with(REQ_USER_IDENTITY);
        }
        if cedar_src.contains("context.session")
            || cedar_src.contains("session.")
            || cedar_src.contains("labels.")
        {
            req = req.with(REQ_SESSION_STORE);
        }
    }
    (req, has_enforced)
}

fn push_required_signals(req: HostRuleRequirements, out: &mut BTreeSet<RequiredHostSignal>) {
    if req.contains(REQ_USER_IDENTITY) {
        out.insert(RequiredHostSignal::UserIdentity);
    }
    if req.contains(REQ_OS_FILE_SENSOR) {
        out.insert(RequiredHostSignal::FileSensor);
    }
    if req.contains(REQ_NET_EGRESS_SENSOR) {
        out.insert(RequiredHostSignal::NetEgressSensor);
    }
    if req.contains(REQ_COMMAND_PARSER) {
        out.insert(RequiredHostSignal::CommandParser);
    }
    if req.contains(REQ_SESSION_STORE) {
        out.insert(RequiredHostSignal::SessionStore);
    }
}

fn worst_case_assurance(items: &[PackAssuranceDto]) -> AssuranceKind {
    items
        .iter()
        .map(|p| p.assurance)
        .min_by_key(|a| a.severity_rank())
        .unwrap_or(AssuranceKind::WatchOnly)
}
