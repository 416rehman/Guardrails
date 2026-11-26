// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Guardrails ADR Layer 4 privileged update verifier and atomic A/B slot manager (`grdr-updater`).

mod dsse_guard;
pub mod error;
pub mod fs_safe;
pub mod handover;
pub mod p7_delta;
mod slot_journal;
pub mod slots;
mod tuf_journal;
pub mod verify;
pub mod worker;
mod worker_ipc;
