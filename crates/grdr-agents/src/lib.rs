// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod discover;
pub mod hook_codec;
mod parse;

pub use discover::{detect_hostname, discover_from_roots, discover_local_agents};
pub use hook_codec::parse_claude_hook_stdin;
