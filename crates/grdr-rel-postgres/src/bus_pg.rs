// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::sync::Mutex;

use rusqlite::Connection;

use grdr_model::CodedError;
use grdr_ports::{
    BusAppendMessage, BusLag, BusMessage, BusOffsetRange, BusPort, BusSubscription,
    CODE_BUS_INVALID_INPUT, CODE_BUS_IO, FencingToken, SingleCtx, TenantCtx,
};

use crate::bus_pg_offline::{
    OFFLINE_BUS_SCHEMA_SQL, append_offline, bus_sql_err, commit_offline, fetch_offline,
    lag_offline, subscribe_offline,
};
use crate::bus_pg_wire::{
    PG_BUS_ATOMIC_DDL_SQL, append_wire, commit_wire, fetch_wire, lag_wire, subscribe_wire,
};
use crate::config::{PostgresConfig, PostgresTransport};
use crate::pool::PgConnectionPool;

#[derive(Debug)]
enum BusBackend {
    OfflineSqlite(Mutex<Connection>),
    WireTcp(PgConnectionPool),
}

#[derive(Debug)]
pub struct PostgresLogBus {
    config: PostgresConfig,
    backend: BusBackend,
}

impl PostgresLogBus {
    pub fn open_offline() -> Result<Self, CodedError> {
        let conn = Connection::open_in_memory().map_err(bus_sql_err)?;
        conn.execute_batch(OFFLINE_BUS_SCHEMA_SQL)
            .map_err(bus_sql_err)?;
        Ok(Self {
            config: PostgresConfig::offline(),
            backend: BusBackend::OfflineSqlite(Mutex::new(conn)),
        })
    }

    pub fn connect(config: PostgresConfig) -> Result<Self, CodedError> {
        config.validate()?;
        match &config.transport {
            PostgresTransport::OfflineEmbedded => Self::open_offline(),
            PostgresTransport::TcpWire { .. } => {
                let pool = PgConnectionPool::new(&config)?;
                let _ = pool.execute_simple(PG_BUS_ATOMIC_DDL_SQL, config.statement_timeout_ms)?;
                Ok(Self {
                    config,
                    backend: BusBackend::WireTcp(pool),
                })
            }
        }
    }

    pub fn config(&self) -> &PostgresConfig {
        &self.config
    }
}

impl BusPort for PostgresLogBus {
    fn append(
        &self,
        ctx: &SingleCtx,
        stream: &str,
        partition: u32,
        messages: &[BusAppendMessage],
        now_ms: i64,
    ) -> Result<BusOffsetRange, CodedError> {
        validate_token("stream", stream)?;
        if messages.is_empty() {
            return Err(CodedError::new(
                CODE_BUS_INVALID_INPUT,
                "Cannot append an empty batch to PostgreSQL bus.",
                "Include at least one message when appending.",
            ));
        }
        match &self.backend {
            BusBackend::OfflineSqlite(m) => {
                let mut conn = m.lock().map_err(|_| bus_mutex_err())?;
                append_offline(&mut conn, ctx, stream, partition, messages, now_ms)
            }
            BusBackend::WireTcp(pool) => {
                append_wire(pool, ctx, stream, partition, messages, now_ms)
            }
        }
    }

    fn subscribe(
        &self,
        consumer_group: &str,
        stream: &str,
        partition: u32,
        holder: &str,
        fence: FencingToken,
        expiry_ms: i64,
    ) -> Result<BusSubscription, CodedError> {
        validate_token("consumer_group", consumer_group)?;
        validate_token("stream", stream)?;
        validate_token("holder", holder)?;
        match &self.backend {
            BusBackend::OfflineSqlite(m) => {
                let mut conn = m.lock().map_err(|_| bus_mutex_err())?;
                subscribe_offline(
                    &mut conn,
                    consumer_group,
                    stream,
                    partition,
                    holder,
                    fence,
                    expiry_ms,
                )
            }
            BusBackend::WireTcp(pool) => subscribe_wire(
                pool,
                consumer_group,
                stream,
                partition,
                holder,
                fence,
                expiry_ms,
            ),
        }
    }

    fn fetch(
        &self,
        ctx: &TenantCtx,
        stream: &str,
        partition: u32,
        after_offset: Option<u64>,
        limit: usize,
    ) -> Result<Vec<BusMessage>, CodedError> {
        validate_token("stream", stream)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        match &self.backend {
            BusBackend::OfflineSqlite(m) => {
                let conn = m.lock().map_err(|_| bus_mutex_err())?;
                fetch_offline(&conn, ctx, stream, partition, after_offset, limit)
            }
            BusBackend::WireTcp(pool) => {
                fetch_wire(pool, ctx, stream, partition, after_offset, limit)
            }
        }
    }

    fn commit(
        &self,
        consumer_group: &str,
        stream: &str,
        partition: u32,
        offset: u64,
        checkpoint: Option<&str>,
        fence: FencingToken,
    ) -> Result<(), CodedError> {
        validate_token("consumer_group", consumer_group)?;
        validate_token("stream", stream)?;
        match &self.backend {
            BusBackend::OfflineSqlite(m) => {
                let mut conn = m.lock().map_err(|_| bus_mutex_err())?;
                commit_offline(
                    &mut conn,
                    consumer_group,
                    stream,
                    partition,
                    offset,
                    checkpoint,
                    fence,
                )
            }
            BusBackend::WireTcp(pool) => commit_wire(
                pool,
                consumer_group,
                stream,
                partition,
                offset,
                checkpoint,
                fence,
            ),
        }
    }

    fn lag(
        &self,
        _ctx: &TenantCtx,
        consumer_group: &str,
        stream: &str,
        partition: u32,
    ) -> Result<BusLag, CodedError> {
        validate_token("consumer_group", consumer_group)?;
        validate_token("stream", stream)?;
        match &self.backend {
            BusBackend::OfflineSqlite(m) => {
                let conn = m.lock().map_err(|_| bus_mutex_err())?;
                lag_offline(&conn, consumer_group, stream, partition)
            }
            BusBackend::WireTcp(pool) => lag_wire(pool, consumer_group, stream, partition),
        }
    }
}

fn validate_token(field: &str, value: &str) -> Result<(), CodedError> {
    if value.trim().is_empty() || value.contains('\0') {
        return Err(CodedError::new(
            CODE_BUS_INVALID_INPUT,
            format!("PostgreSQL bus field `{field}` cannot be empty or contain NUL."),
            "Provide a valid non-empty stream or consumer group identifier.",
        ));
    }
    Ok(())
}

fn bus_mutex_err() -> CodedError {
    CodedError::new(
        CODE_BUS_IO,
        "PostgreSQL log bus mutex poisoned.",
        "Recreate PostgresLogBus instance.",
    )
}
