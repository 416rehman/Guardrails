// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_bus_log::SqliteLogBus;
use grdr_bus_nats::NatsJetStreamBus;
use grdr_model::{CodedError, Device, Finding, PolicyPack, SessionSummary};
use grdr_ports::{
    BusAppendMessage, BusOffsetRange, BusPort, BusSubscription, DeviceRepo, FencingToken,
    FindingRepo, KvSnapshotRepo, PolicyRepo, SessionSummaryRepo, SingleCtx, TenantCtx,
    TenantUserRecord, UserRepo,
};
use grdr_rel_postgres::PostgresRelationalStore;
use grdr_rel_sqlite::SqliteRelationalStore;

pub(crate) enum ServerRelational {
    Sqlite(SqliteRelationalStore),
    Postgres(PostgresRelationalStore),
}

pub(crate) enum ServerBus {
    Log(SqliteLogBus),
    Nats(NatsJetStreamBus),
}

impl ServerRelational {
    pub(crate) fn list_packs(&self, ctx: &TenantCtx) -> Result<Vec<PolicyPack>, CodedError> {
        match self {
            Self::Sqlite(s) => s.list_packs(ctx),
            Self::Postgres(p) => p.list_packs(ctx),
        }
    }

    pub(crate) fn upsert_pack(&self, ctx: &SingleCtx, pack: &PolicyPack) -> Result<(), CodedError> {
        match self {
            Self::Sqlite(s) => s.upsert_pack(ctx, pack),
            Self::Postgres(p) => p.upsert_pack(ctx, pack),
        }
    }

    pub(crate) fn list_devices(&self, ctx: &TenantCtx) -> Result<Vec<Device>, CodedError> {
        match self {
            Self::Sqlite(s) => s.list_devices(ctx),
            Self::Postgres(p) => p.list_devices(ctx),
        }
    }

    pub(crate) fn upsert_device(&self, ctx: &SingleCtx, dev: &Device) -> Result<(), CodedError> {
        match self {
            Self::Sqlite(s) => s.upsert_device(ctx, dev),
            Self::Postgres(p) => p.upsert_device(ctx, dev),
        }
    }

    pub(crate) fn list_findings(&self, ctx: &TenantCtx) -> Result<Vec<Finding>, CodedError> {
        match self {
            Self::Sqlite(s) => s.list_findings(ctx),
            Self::Postgres(p) => p.list_findings(ctx),
        }
    }

    pub(crate) fn upsert_finding(
        &self,
        ctx: &SingleCtx,
        finding: &Finding,
    ) -> Result<(), CodedError> {
        match self {
            Self::Sqlite(s) => s.upsert_finding(ctx, finding),
            Self::Postgres(p) => p.upsert_finding(ctx, finding),
        }
    }

    pub(crate) fn list_users(&self, ctx: &TenantCtx) -> Result<Vec<TenantUserRecord>, CodedError> {
        match self {
            Self::Sqlite(s) => s.list_users(ctx),
            Self::Postgres(p) => p.list_users(ctx),
        }
    }

    pub(crate) fn upsert_user(
        &self,
        ctx: &SingleCtx,
        user: &TenantUserRecord,
    ) -> Result<(), CodedError> {
        match self {
            Self::Sqlite(s) => s.upsert_user(ctx, user),
            Self::Postgres(p) => p.upsert_user(ctx, user),
        }
    }

    pub(crate) fn upsert_session_summary(
        &self,
        ctx: &SingleCtx,
        summary: &SessionSummary,
    ) -> Result<(), CodedError> {
        match self {
            Self::Sqlite(s) => s.upsert_session_summary(ctx, summary),
            Self::Postgres(p) => p.upsert_session_summary(ctx, summary),
        }
    }

    pub(crate) fn get_kv(
        &self,
        ctx: &TenantCtx,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, CodedError> {
        match self {
            Self::Sqlite(s) => s.get_kv(ctx, namespace, key),
            Self::Postgres(p) => p.get_kv(ctx, namespace, key),
        }
    }

    pub(crate) fn put_kv(
        &self,
        ctx: &SingleCtx,
        namespace: &str,
        key: &str,
        value_json: &str,
    ) -> Result<(), CodedError> {
        match self {
            Self::Sqlite(s) => s.put_kv(ctx, namespace, key, value_json),
            Self::Postgres(p) => p.put_kv(ctx, namespace, key, value_json),
        }
    }
}

impl ServerBus {
    pub(crate) fn append(
        &self,
        ctx: &SingleCtx,
        stream: &str,
        partition: u32,
        messages: &[BusAppendMessage],
        now_ms: i64,
    ) -> Result<BusOffsetRange, CodedError> {
        match self {
            Self::Log(l) => l.append(ctx, stream, partition, messages, now_ms),
            Self::Nats(n) => n.append(ctx, stream, partition, messages, now_ms),
        }
    }

    pub(crate) fn subscribe(
        &self,
        consumer_group: &str,
        stream: &str,
        partition: u32,
        holder: &str,
        fence: FencingToken,
        expiry_ms: i64,
    ) -> Result<BusSubscription, CodedError> {
        match self {
            Self::Log(l) => {
                l.subscribe(consumer_group, stream, partition, holder, fence, expiry_ms)
            }
            Self::Nats(n) => {
                n.subscribe(consumer_group, stream, partition, holder, fence, expiry_ms)
            }
        }
    }

    pub(crate) fn commit(
        &self,
        consumer_group: &str,
        stream: &str,
        partition: u32,
        offset: u64,
        checkpoint: Option<&str>,
        fence: FencingToken,
    ) -> Result<(), CodedError> {
        match self {
            Self::Log(l) => l.commit(consumer_group, stream, partition, offset, checkpoint, fence),
            Self::Nats(n) => n.commit(consumer_group, stream, partition, offset, checkpoint, fence),
        }
    }
}
