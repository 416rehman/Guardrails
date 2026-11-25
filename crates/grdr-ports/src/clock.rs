// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

pub trait Clock: Send + Sync {
    fn now_timestamp(&self) -> Timestamp;
    fn monotonic_ms(&self) -> u64;
}
