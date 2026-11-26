// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Thin fail-closed endpoint hook helpers exposed for differential fuzzing and CLI execution.

pub mod dialect;
pub mod floor_fallback;
mod handover;
pub mod ipc_client;
mod ipc_transport;
mod json_lexer;
pub mod json_scan;
pub mod offline_spool;

pub use json_scan::{HookCodecError, MAX_HOOK_STDIN_BYTES, ScannedHookInput, scan_hook_json};
