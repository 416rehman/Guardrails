// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use jiff::Timestamp;
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use grdr_blob::FilesystemBlobStore;
use grdr_bus_log::SqliteLogBus;
use grdr_bus_nats::{NatsConfig, NatsJetStreamBus};
use grdr_core::detect;
use grdr_crypto::load_or_create_keypair;
use grdr_jobs::SqliteJobJournal;
use grdr_lake::LakeStore;
use grdr_model::error::{CODE_STORE_CORRUPT, CODE_STORE_IO};
use grdr_model::eval::add_seconds;
use grdr_model::{
    ActionAttempt, ApprovalGrade, ApprovalRequest, ApprovalState, CodedError, DecisionReceipt,
    PolicyPack, Verdict, summarize_sessions,
};
use grdr_ports::{
    BusAppendMessage, EventsPort, FencingToken, JobPort, LakeManifest, LeaseAcquireOutcome,
    LeaseState, OrgId, SingleCtx, TenantCtx, TenantUserRecord,
};
#[cfg(test)]
use grdr_ports::{
    ErasureReceipt, LakeCompactionResult, LakeFlushResult, LakeQueryIr, LakeQueryResult,
};
use grdr_rel_postgres::{PostgresConfig, PostgresRelationalStore};
use grdr_rel_sqlite::SqliteRelationalStore;

use super::adapters::{ServerBus, ServerRelational};
use super::lake_ops::append_event_to_lake;
use super::users::DirectoryUserRecord;
use super::{MAX_RETAINED_EVENTS, StoreData};

const EMBEDDED_ORG_ID: &str = "org-embedded";
const KV_NAMESPACE_STATE: &str = "server_state";
const EVENTS_STREAM: &str = "events";
const STORE_CONSUMER_GROUP: &str = "store";
const STORE_LEASE_NAME: &str = "embedded-store";
const STORE_HOLDER_NAME: &str = "grdr-server";
const LEASE_TTL_MS: i64 = 60_000;

pub(crate) struct EmbeddedStorage {
    org_ctx: SingleCtx,
    relational: ServerRelational,
    bus: ServerBus,
    jobs: SqliteJobJournal,
    lake: LakeStore<FilesystemBlobStore>,
    bus_fence: Mutex<FencingToken>,
}

impl EmbeddedStorage {
    pub(crate) fn open(dir: &Path) -> Result<Self, CodedError> {
        let relational = ServerRelational::Sqlite(SqliteRelationalStore::open(
            &dir.join("relational.sqlite3"),
        )?);
        let bus = ServerBus::Log(SqliteLogBus::open(&dir.join("bus.sqlite3"))?);
        Self::open_with_adapters(dir, &dir.join("blobs"), relational, bus)
    }

    pub(crate) fn open_ha(
        state_dir: &Path,
        object_store_dir: &Path,
        postgres_dsn: &str,
    ) -> Result<Self, CodedError> {
        fs::create_dir_all(state_dir).map_err(|e| {
            CodedError::new(
                CODE_STORE_IO,
                format!("Failed creating HA state dir {}: {e}", state_dir.display()),
                "Verify write permissions in state directory.",
            )
        })?;
        let pg_cfg = PostgresConfig::parse_dsn(postgres_dsn)?;
        let relational = ServerRelational::Postgres(PostgresRelationalStore::connect(pg_cfg)?);
        let bus = ServerBus::Log(SqliteLogBus::open(&state_dir.join("bus.sqlite3"))?);
        Self::open_with_adapters(state_dir, object_store_dir, relational, bus)
    }

    pub(crate) fn open_distributed(
        state_dir: &Path,
        object_store_dir: &Path,
        postgres_dsn: &str,
        nats_url: &str,
    ) -> Result<Self, CodedError> {
        fs::create_dir_all(state_dir).map_err(|e| {
            CodedError::new(
                CODE_STORE_IO,
                format!(
                    "Failed creating Distributed state dir {}: {e}",
                    state_dir.display()
                ),
                "Verify write permissions in state directory.",
            )
        })?;
        let pg_cfg = PostgresConfig::parse_dsn(postgres_dsn)?;
        let relational = ServerRelational::Postgres(PostgresRelationalStore::connect(pg_cfg)?);
        let nats_cfg = NatsConfig::parse_url(nats_url)?;
        let bus = ServerBus::Nats(NatsJetStreamBus::connect(nats_cfg)?);
        Self::open_with_adapters(state_dir, object_store_dir, relational, bus)
    }

    fn open_with_adapters(
        state_dir: &Path,
        blobs_dir: &Path,
        relational: ServerRelational,
        bus: ServerBus,
    ) -> Result<Self, CodedError> {
        let org = OrgId::new(EMBEDDED_ORG_ID)?;
        let org_ctx = SingleCtx::new(org);

        let jobs = SqliteJobJournal::open(&state_dir.join("jobs.sqlite3"))?;
        let lake_kek = load_or_create_keypair(&state_dir.join("lake.kek"))
            .map_err(|e| {
                CodedError::new(
                    CODE_STORE_IO,
                    format!("Failed initializing lake KEK: {e}"),
                    "Verify write permissions in state directory.",
                )
            })?
            .derive_aead_key("lake.kek.v1");
        let lake_blobs = FilesystemBlobStore::open(blobs_dir)?;
        let lake = LakeStore::open(
            &state_dir.join("lake-catalogue.sqlite3"),
            lake_blobs,
            lake_kek,
        )?;

        let now_ms = Timestamp::now().as_millisecond();
        let fence =
            match jobs.acquire_lease(STORE_LEASE_NAME, STORE_HOLDER_NAME, now_ms, LEASE_TTL_MS)? {
                LeaseAcquireOutcome::Acquired(rec) => match rec.state {
                    LeaseState::Held { fence, .. } => fence,
                    _ => FencingToken::new(1),
                },
                LeaseAcquireOutcome::Contended { fence, .. } => fence,
            };
        let sub = bus.subscribe(
            STORE_CONSUMER_GROUP,
            EVENTS_STREAM,
            0,
            STORE_HOLDER_NAME,
            fence,
            now_ms.saturating_add(LEASE_TTL_MS),
        )?;

        Ok(Self {
            org_ctx,
            relational,
            bus,
            jobs,
            lake,
            bus_fence: Mutex::new(sub.fence),
        })
    }

    pub(crate) fn load_store_data(&self) -> Result<StoreData, CodedError> {
        let read_ctx = TenantCtx::Single(self.org_ctx.clone());
        let initialized = self
            .relational
            .get_kv(&read_ctx, KV_NAMESPACE_STATE, "initialized")?;
        if initialized.is_none() {
            return Ok(StoreData::default());
        }

        let mut data = StoreData {
            packs: self.relational.list_packs(&read_ctx)?,
            devices: self.relational.list_devices(&read_ctx)?,
            findings: self.relational.list_findings(&read_ctx)?,
            user_directory: self
                .relational
                .list_users(&read_ctx)?
                .into_iter()
                .map(|u| DirectoryUserRecord {
                    id: u.id,
                    display_name: u.display_name,
                    email: u.email,
                    department: u.department,
                    idp_source: u.idp_source,
                    pseudonym_id: u.pseudonym_id,
                })
                .collect(),
            ..StoreData::default()
        };

        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "privacy")? {
            data.privacy = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "otlp_config")? {
            data.otlp_config = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "kill_switch")? {
            data.kill_switch = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "deployment_keys")? {
            data.deployment_keys = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "integrations")? {
            data.integrations = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "browser_policies")? {
            data.browser_policies = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "approvals")? {
            data.approvals = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "grants")? {
            data.grants = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "audit")? {
            data.audit = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "attempts")? {
            data.attempts = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "receipts")? {
            data.receipts = v;
        }
        if let Some(v) = load_kv_json(&self.relational, &read_ctx, "surfaces")? {
            data.surfaces = v;
        }
        Ok(data)
    }

    pub(crate) fn persist_store_data(&self, data: &StoreData) -> Result<(), CodedError> {
        for pack in &data.packs {
            self.relational.upsert_pack(&self.org_ctx, pack)?;
        }
        for dev in &data.devices {
            self.relational.upsert_device(&self.org_ctx, dev)?;
        }
        for finding in &data.findings {
            self.relational.upsert_finding(&self.org_ctx, finding)?;
        }
        for user in &data.user_directory {
            self.relational.upsert_user(
                &self.org_ctx,
                &TenantUserRecord {
                    id: user.id.clone(),
                    display_name: user.display_name.clone(),
                    email: user.email.clone(),
                    department: user.department.clone(),
                    idp_source: user.idp_source.clone(),
                    pseudonym_id: user.pseudonym_id.clone(),
                },
            )?;
        }
        for summary in summarize_sessions(&data.attempts, &data.receipts) {
            self.relational
                .upsert_session_summary(&self.org_ctx, &summary)?;
        }

        put_kv_json(&self.relational, &self.org_ctx, "privacy", &data.privacy)?;
        put_kv_json(
            &self.relational,
            &self.org_ctx,
            "otlp_config",
            &data.otlp_config,
        )?;
        put_kv_json(
            &self.relational,
            &self.org_ctx,
            "kill_switch",
            &data.kill_switch,
        )?;
        put_kv_json(
            &self.relational,
            &self.org_ctx,
            "deployment_keys",
            &data.deployment_keys,
        )?;
        put_kv_json(
            &self.relational,
            &self.org_ctx,
            "integrations",
            &data.integrations,
        )?;
        put_kv_json(
            &self.relational,
            &self.org_ctx,
            "browser_policies",
            &data.browser_policies,
        )?;
        put_kv_json(
            &self.relational,
            &self.org_ctx,
            "approvals",
            &data.approvals,
        )?;
        put_kv_json(&self.relational, &self.org_ctx, "grants", &data.grants)?;
        put_kv_json(&self.relational, &self.org_ctx, "audit", &data.audit)?;
        put_kv_json(&self.relational, &self.org_ctx, "attempts", &data.attempts)?;
        put_kv_json(&self.relational, &self.org_ctx, "receipts", &data.receipts)?;
        put_kv_json(&self.relational, &self.org_ctx, "surfaces", &data.surfaces)?;
        self.relational
            .put_kv(&self.org_ctx, KV_NAMESPACE_STATE, "initialized", "true")?;
        Ok(())
    }

    pub(crate) fn append_and_commit_event(
        &self,
        device_id: &str,
        payload_bytes: &[u8],
    ) -> Result<(), CodedError> {
        let now_ms = Timestamp::now().as_millisecond();
        let mut headers = BTreeMap::new();
        headers.insert("device_id".into(), device_id.into());
        let range = self.bus.append(
            &self.org_ctx,
            EVENTS_STREAM,
            0,
            &[BusAppendMessage {
                key: device_id.into(),
                headers,
                payload: payload_bytes.to_vec(),
            }],
            now_ms,
        )?;
        let mut fence = self.bus_fence.lock().map_err(|_| {
            CodedError::new(
                CODE_STORE_IO,
                "Embedded bus fence mutex poisoned.",
                "Restart server.",
            )
        })?;
        if matches!(
            self.jobs.inspect_lease(STORE_LEASE_NAME, now_ms)?.state,
            LeaseState::Vacant | LeaseState::Expired { .. }
        ) && let LeaseAcquireOutcome::Acquired(rec) =
            self.jobs
                .acquire_lease(STORE_LEASE_NAME, STORE_HOLDER_NAME, now_ms, LEASE_TTL_MS)?
            && let LeaseState::Held { fence: renewed, .. } = rec.state
        {
            self.bus.subscribe(
                STORE_CONSUMER_GROUP,
                EVENTS_STREAM,
                0,
                STORE_HOLDER_NAME,
                renewed,
                now_ms.saturating_add(LEASE_TTL_MS),
            )?;
            *fence = renewed;
        }
        self.bus.commit(
            STORE_CONSUMER_GROUP,
            EVENTS_STREAM,
            0,
            range.last_offset,
            None,
            *fence,
        )?;
        let _ = append_event_to_lake(
            &self.lake,
            &self.org_ctx,
            *fence,
            range.last_offset,
            device_id,
            payload_bytes,
            now_ms,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn flush_lake(&self, now_ms: i64) -> Result<LakeFlushResult, CodedError> {
        let fence = *self.bus_fence.lock().map_err(|_| {
            CodedError::new(
                CODE_STORE_IO,
                "Embedded bus fence mutex poisoned.",
                "Restart server.",
            )
        })?;
        self.lake.flush(&self.org_ctx, fence, now_ms, now_ms)
    }

    #[cfg(test)]
    pub(crate) fn compact_lake(&self, now_ms: i64) -> Result<LakeCompactionResult, CodedError> {
        let fence = *self.bus_fence.lock().map_err(|_| {
            CodedError::new(
                CODE_STORE_IO,
                "Embedded bus fence mutex poisoned.",
                "Restart server.",
            )
        })?;
        self.lake.compact_and_retain(&self.org_ctx, fence, now_ms)
    }

    #[cfg(test)]
    pub(crate) fn query_lake(&self, query: &LakeQueryIr) -> Result<LakeQueryResult, CodedError> {
        let read_ctx = TenantCtx::Single(self.org_ctx.clone());
        self.lake.execute_query_ir(&read_ctx, query)
    }

    #[cfg(test)]
    pub(crate) fn erase_lake_session(
        &self,
        root_session_id: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<ErasureReceipt, CodedError> {
        self.lake
            .erase_session(&self.org_ctx, root_session_id, reason, now_ms)
    }

    pub(crate) fn lake_manifest(&self) -> Result<Option<LakeManifest>, CodedError> {
        let read_ctx = TenantCtx::Single(self.org_ctx.clone());
        self.lake.manifest(&read_ctx)
    }
}

fn load_kv_json<T: DeserializeOwned>(
    store: &ServerRelational,
    ctx: &TenantCtx,
    key: &str,
) -> Result<Option<T>, CodedError> {
    let Some(raw) = store.get_kv(ctx, KV_NAMESPACE_STATE, key)? else {
        return Ok(None);
    };
    let parsed = serde_json::from_str(&raw).map_err(|e| {
        CodedError::new(
            CODE_STORE_CORRUPT,
            format!("Corrupt relational KV payload for `{key}`: {e}"),
            "Inspect relational database state.",
        )
    })?;
    Ok(Some(parsed))
}

fn put_kv_json<T: Serialize>(
    store: &ServerRelational,
    ctx: &SingleCtx,
    key: &str,
    value: &T,
) -> Result<(), CodedError> {
    let json = serde_json::to_string(value).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Failed encoding relational KV payload for `{key}`: {e}"),
            "Check server state serialization.",
        )
    })?;
    store.put_kv(ctx, KV_NAMESPACE_STATE, key, &json)
}

pub(crate) fn record_attempt_and_receipt(
    guard: &mut StoreData,
    attempt: ActionAttempt,
    receipt: DecisionReceipt,
    now: Timestamp,
) {
    bump_rule_counters(&mut guard.packs, &receipt);

    if receipt.verdict == Verdict::StepUp {
        let (rule_title, required_grade) =
            find_rule_metadata(&guard.packs, receipt.rule_id.as_deref());
        guard.approvals.insert(
            0,
            ApprovalRequest {
                id: format!("apr_{}", Uuid::now_v7().simple()),
                receipt_id: receipt.receipt_id.clone(),
                session_id: attempt.session_id.clone(),
                device_id: attempt.device_id.clone(),
                device_name: attempt.device_name.clone(),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                target: attempt.target.clone(),
                rule_id: receipt
                    .rule_id
                    .clone()
                    .unwrap_or_else(|| "essentials.credential-stores".into()),
                rule_title,
                required_grade,
                reason: receipt.reason.clone(),
                requested_at: now,
                state: ApprovalState::Pending {
                    expires_at: add_seconds(now, 1800),
                },
            },
        );
    }

    if let Some(finding) = detect::finding_from_receipt(&receipt, &attempt.device_name) {
        guard.findings.insert(0, finding);
    }

    guard.attempts.push(attempt);
    guard.receipts.push(receipt);
    trim_retained(guard);
}

pub(crate) fn trim_retained(guard: &mut StoreData) {
    if guard.attempts.len() > MAX_RETAINED_EVENTS {
        let drop_count = guard.attempts.len().saturating_sub(MAX_RETAINED_EVENTS);
        guard.attempts.drain(..drop_count);
    }
    if guard.receipts.len() > MAX_RETAINED_EVENTS {
        let drop_count = guard.receipts.len().saturating_sub(MAX_RETAINED_EVENTS);
        guard.receipts.drain(..drop_count);
    }
    if guard.audit.len() > MAX_RETAINED_EVENTS {
        guard.audit.truncate(MAX_RETAINED_EVENTS);
    }
}

pub(crate) fn bump_rule_counters(packs: &mut [PolicyPack], receipt: &DecisionReceipt) {
    let Some(rule_id) = &receipt.rule_id else {
        return;
    };
    for pack in packs {
        if let Some(rule) = pack.rules.iter_mut().find(|r| &r.id == rule_id) {
            rule.hits = rule.hits.saturating_add(1);
            if receipt.verdict == Verdict::StepUp {
                rule.would_ask_hits = rule.would_ask_hits.saturating_add(1);
            } else if receipt.verdict == Verdict::Deny {
                rule.would_block_hits = rule.would_block_hits.saturating_add(1);
            }
        }
    }
}

pub(crate) fn find_rule_metadata(
    packs: &[PolicyPack],
    rule_id: Option<&str>,
) -> (String, ApprovalGrade) {
    let Some(target) = rule_id else {
        return ("Policy approval required".into(), ApprovalGrade::G1);
    };
    packs
        .iter()
        .flat_map(|p| p.rules.iter())
        .find(|r| r.id == target)
        .map(|r| (r.title.clone(), r.min_grade))
        .unwrap_or_else(|| (target.into(), ApprovalGrade::G1))
}

pub(crate) fn expire_pending_approvals(approvals: &mut [ApprovalRequest], now: Timestamp) -> bool {
    let mut changed = false;
    for approval in approvals {
        if let ApprovalState::Pending { expires_at } = approval.state
            && expires_at <= now
        {
            approval.state = ApprovalState::Expired { expired_at: now };
            changed = true;
        }
    }
    changed
}
