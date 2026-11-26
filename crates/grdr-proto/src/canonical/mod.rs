// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Canonical `v1alpha1` / `v1` protobuf wire codecs for all 17 core Guardrails packages.

pub mod common_types;
mod embed_local;
mod entity_extra;
mod fleet_extra;
pub mod fleet_ops;
pub mod governance;
pub mod governance_rpc;
mod serde_time;
pub mod telemetry;
pub mod telemetry_action;

pub use fleet_ops::{bootstrap, embed, fleet, identity, ingest, local, operator};
pub use governance::{assurance, decision, finding, inventory};
pub use governance_rpc::{decide, provider};
pub use telemetry::{entity, event, export, feed};
