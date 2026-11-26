// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Guardrails ADR Layer 4 unprivileged fleet uplink transport library and S-23 simulator.

pub mod allowlist;
pub mod auth;
pub mod auth_certs;
pub mod backoff;
pub mod control;
pub mod dialer;
pub mod error;
pub mod herd_sim;
pub mod herd_wheel;
pub mod lanes;
pub mod rfc9421;
pub mod schedule;
mod staging_fs;
pub mod watermark;
pub mod worker;
mod worker_ipc;
mod worker_verify;
