// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Bounded-concurrency worker pool driven by `contracts/limits.toml` (`broker.max_worker_threads`).

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use grdr_schema::limits::load_embedded_limits;

type PoolJob = Box<dyn FnOnce() + Send + 'static>;

struct PoolInner {
    tasks: VecDeque<(PoolJob, Arc<AtomicBool>)>,
    idle_workers: usize,
    spawned_workers: usize,
    shutdown: bool,
}

struct PoolState {
    inner: Mutex<PoolInner>,
    cvar: Condvar,
}

#[derive(Clone)]
pub(crate) struct BrokerWorkerPool {
    state: Arc<PoolState>,
    max_workers: usize,
}

impl BrokerWorkerPool {
    pub(crate) fn from_limits() -> Self {
        let max_workers = load_embedded_limits()
            .map(|l| l.broker.max_worker_threads)
            .unwrap_or(8)
            .clamp(1, 64);
        Self::with_capacity(max_workers)
    }

    pub(crate) fn with_capacity(max_workers: usize) -> Self {
        Self {
            state: Arc::new(PoolState {
                inner: Mutex::new(PoolInner {
                    tasks: VecDeque::new(),
                    idle_workers: 0,
                    spawned_workers: 0,
                    shutdown: false,
                }),
                cvar: Condvar::new(),
            }),
            max_workers: max_workers.clamp(1, 64),
        }
    }

    pub(crate) fn dispatch(&self, job: PoolJob, cancelled: Arc<AtomicBool>) -> Result<(), String> {
        let mut guard = self
            .state
            .inner
            .lock()
            .map_err(|_| "broker worker pool lock poisoned".to_string())?;
        if guard.shutdown {
            return Err("broker worker pool shut down".to_string());
        }
        let max_queue = self.max_workers.saturating_mul(2);
        if guard.tasks.len() >= max_queue {
            return Err("broker worker pool saturated".to_string());
        }
        if guard.idle_workers == 0 && guard.spawned_workers < self.max_workers {
            let next_id = guard.spawned_workers.saturating_add(1);
            guard.spawned_workers = next_id;
            let state = Arc::clone(&self.state);
            if std::thread::Builder::new()
                .name(format!("brk-pool-{next_id}"))
                .spawn(move || worker_loop(state))
                .is_err()
            {
                guard.spawned_workers = guard.spawned_workers.saturating_sub(1);
                return Err("failed spawning broker worker thread".to_string());
            }
        }
        guard.tasks.push_back((job, cancelled));
        self.state.cvar.notify_one();
        Ok(())
    }

    pub(crate) fn max_workers(&self) -> usize {
        self.max_workers
    }

    pub(crate) fn spawned_workers(&self) -> usize {
        self.state
            .inner
            .lock()
            .map(|g| g.spawned_workers)
            .unwrap_or(0)
    }

    pub(crate) fn shutdown(&self) {
        if let Ok(mut guard) = self.state.inner.lock() {
            guard.shutdown = true;
            guard.tasks.clear();
            self.state.cvar.notify_all();
        }
    }
}

fn worker_loop(state: Arc<PoolState>) {
    loop {
        let next_job = {
            let Ok(mut guard) = state.inner.lock() else {
                return;
            };
            while guard.tasks.is_empty() && !guard.shutdown {
                guard.idle_workers = guard.idle_workers.saturating_add(1);
                let Ok(res) = state.cvar.wait(guard) else {
                    return;
                };
                guard = res;
                guard.idle_workers = guard.idle_workers.saturating_sub(1);
            }
            if guard.shutdown {
                guard.tasks.clear();
                guard.spawned_workers = guard.spawned_workers.saturating_sub(1);
                return;
            }
            guard.tasks.pop_front()
        };
        if let Some((job, cancelled)) = next_job
            && !cancelled.load(Ordering::Acquire)
        {
            let _ = catch_unwind(AssertUnwindSafe(job));
        }
    }
}
