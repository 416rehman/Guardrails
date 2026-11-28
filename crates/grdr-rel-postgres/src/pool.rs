// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use grdr_model::CodedError;

use crate::config::{CODE_PG_CONFIG, CODE_PG_IO, PostgresConfig, PostgresTransport};
use crate::tls::PostgresTlsContext;
use crate::wire::{PgWireConnection, WireConnParams, WireStatement};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PooledConnDisposition {
    KeepIdle,
    DiscardPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PgPoolStats {
    pub active_connections: usize,
    pub idle_connections: usize,
    pub total_connects: u64,
    pub reused_checkouts: u64,
    pub discarded_connections: u64,
}

#[derive(Debug)]
struct PoolState {
    idle: VecDeque<PgWireConnection>,
    active: usize,
    total_connects: u64,
    reused_checkouts: u64,
    discarded_connections: u64,
}

pub struct PgConnectionPool {
    endpoint: String,
    database: String,
    user: String,
    password: Option<Zeroizing<String>>,
    application_name: String,
    ssl_mode: crate::config::PostgresSslMode,
    connect_timeout_ms: u32,
    statement_timeout_ms: u32,
    max_size: usize,
    tls_ctx: Option<PostgresTlsContext>,
    state: Arc<Mutex<PoolState>>,
    notify: Arc<Condvar>,
}

impl fmt::Debug for PgConnectionPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgConnectionPool")
            .field("endpoint", &self.endpoint)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("application_name", &self.application_name)
            .field("ssl_mode", &self.ssl_mode)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("statement_timeout_ms", &self.statement_timeout_ms)
            .field("max_size", &self.max_size)
            .finish()
    }
}

impl PgConnectionPool {
    pub fn new(config: &PostgresConfig) -> Result<Self, CodedError> {
        config.validate()?;
        let PostgresTransport::TcpWire {
            endpoint,
            database,
            user,
            password,
        } = &config.transport
        else {
            return Err(CodedError::new(
                CODE_PG_CONFIG,
                "Cannot create PgConnectionPool for OfflineEmbedded transport.",
                "Provide a postgres:// DSN to create a connection pool.",
            ));
        };

        let tls_ctx =
            PostgresTlsContext::build(config.ssl_mode, endpoint, config.ca_cert_pem.as_deref())?;
        Ok(Self {
            endpoint: endpoint.clone(),
            database: database.clone(),
            user: user.clone(),
            password: password.clone(),
            application_name: config.application_name.clone(),
            ssl_mode: config.ssl_mode,
            connect_timeout_ms: config.connect_timeout_ms,
            statement_timeout_ms: config.statement_timeout_ms,
            max_size: usize::from(config.max_pool_size.max(1)),
            tls_ctx,
            state: Arc::new(Mutex::new(PoolState {
                idle: VecDeque::new(),
                active: 0,
                total_connects: 0,
                reused_checkouts: 0,
                discarded_connections: 0,
            })),
            notify: Arc::new(Condvar::new()),
        })
    }

    pub fn stats(&self) -> Result<PgPoolStats, CodedError> {
        let guard = self.state.lock().map_err(|_| pool_poison_err())?;
        Ok(PgPoolStats {
            active_connections: guard.active,
            idle_connections: guard.idle.len(),
            total_connects: guard.total_connects,
            reused_checkouts: guard.reused_checkouts,
            discarded_connections: guard.discarded_connections,
        })
    }

    pub fn execute_simple(
        &self,
        sql: &str,
        timeout_ms: u32,
    ) -> Result<Vec<Vec<Option<String>>>, CodedError> {
        let mut conn = self.checkout(timeout_ms)?;
        let res = conn.simple_query(sql);
        let disposition = if res.is_ok() && conn.is_clean_idle() {
            PooledConnDisposition::KeepIdle
        } else {
            PooledConnDisposition::DiscardPoisoned
        };
        self.checkin(conn, disposition);
        res
    }

    pub(crate) fn execute_tx(
        &self,
        rls_stmts: &[String],
        statements: &[WireStatement<'_>],
    ) -> Result<Vec<Vec<Vec<Option<String>>>>, CodedError> {
        let mut conn = self.checkout(self.statement_timeout_ms)?;
        let res = conn.execute_tx(rls_stmts, statements);
        let disposition = if res.is_ok() && conn.is_clean_idle() {
            PooledConnDisposition::KeepIdle
        } else {
            PooledConnDisposition::DiscardPoisoned
        };
        self.checkin(conn, disposition);
        res
    }

    fn checkout(&self, query_timeout_ms: u32) -> Result<PgWireConnection, CodedError> {
        let wait_limit = Duration::from_millis(u64::from(self.connect_timeout_ms.max(100)));
        let deadline = Instant::now().checked_add(wait_limit).ok_or_else(|| {
            CodedError::new(
                CODE_PG_IO,
                "Connection pool timeout overflow.",
                "Use a smaller connect_timeout_ms.",
            )
        })?;

        loop {
            let mut guard = self.state.lock().map_err(|_| pool_poison_err())?;
            if let Some(mut conn) = guard.idle.pop_back() {
                guard.reused_checkouts = guard.reused_checkouts.saturating_add(1);
                drop(guard);
                let refresh_ms = query_timeout_ms.max(self.connect_timeout_ms);
                if conn.is_clean_idle()
                    && conn.set_timeout_ms(refresh_ms).is_ok()
                    && conn.ping().is_ok()
                {
                    return Ok(conn);
                }
                conn.terminate();
                self.mark_discarded();
                continue;
            }

            if guard.active < self.max_size {
                guard.active = guard.active.saturating_add(1);
                guard.total_connects = guard.total_connects.saturating_add(1);
                drop(guard);
                match self.open_new(query_timeout_ms) {
                    Ok(conn) => return Ok(conn),
                    Err(err) => {
                        self.release_slot();
                        return Err(err);
                    }
                }
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(CodedError::new(
                    CODE_PG_IO,
                    format!(
                        "Timed out waiting for PostgreSQL connection pool slot (max_size={}).",
                        self.max_size
                    ),
                    "Increase pool_size or reduce PostgreSQL query concurrency.",
                ));
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_guard, wait_res) = self
                .notify
                .wait_timeout(guard, remaining)
                .map_err(|_| pool_poison_err())?;
            if wait_res.timed_out()
                && next_guard.idle.is_empty()
                && next_guard.active >= self.max_size
            {
                return Err(CodedError::new(
                    CODE_PG_IO,
                    format!(
                        "Timed out waiting for PostgreSQL connection pool slot (max_size={}).",
                        self.max_size
                    ),
                    "Increase pool_size or reduce PostgreSQL query concurrency.",
                ));
            }
        }
    }

    fn checkin(&self, conn: PgWireConnection, disposition: PooledConnDisposition) {
        if disposition == PooledConnDisposition::KeepIdle && conn.is_clean_idle() {
            if let Ok(mut guard) = self.state.lock()
                && guard.idle.len() < self.max_size
            {
                guard.idle.push_back(conn);
                self.notify.notify_one();
                return;
            }
            conn.terminate();
            self.release_slot();
            return;
        }
        conn.terminate();
        self.mark_discarded();
    }

    fn mark_discarded(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.active = guard.active.saturating_sub(1);
            guard.discarded_connections = guard.discarded_connections.saturating_add(1);
            self.notify.notify_one();
        }
    }

    fn release_slot(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.active = guard.active.saturating_sub(1);
            self.notify.notify_one();
        }
    }

    fn open_new(&self, query_timeout_ms: u32) -> Result<PgWireConnection, CodedError> {
        let params = WireConnParams {
            endpoint: &self.endpoint,
            user: &self.user,
            database: &self.database,
            app_name: &self.application_name,
            timeout_ms: query_timeout_ms.max(self.connect_timeout_ms),
            ssl_mode: self.ssl_mode,
            ca_cert_pem: None,
        };
        PgWireConnection::connect(
            &params,
            self.tls_ctx.as_ref(),
            self.password.as_ref().map(|pw| pw.as_str()),
        )
    }
}

impl Drop for PgConnectionPool {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.state.lock() {
            while let Some(conn) = guard.idle.pop_front() {
                conn.terminate();
            }
            guard.active = 0;
        }
    }
}

fn pool_poison_err() -> CodedError {
    CodedError::new(
        CODE_PG_IO,
        "PostgreSQL connection pool mutex poisoned.",
        "Recreate PostgresRelationalStore connection pool.",
    )
}
