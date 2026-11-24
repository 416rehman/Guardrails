// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod artifacts;
pub mod discover;
pub mod hook_codec;
pub mod install;
mod parse;

pub use artifacts::scan_artifacts_for_roots;
pub use discover::{
    detect_home_dir, detect_hostname, discover_from_roots, discover_from_roots_with_workspace,
    discover_local_agents,
};
pub use hook_codec::{HarnessKind, parse_claude_hook_stdin, parse_hook_stdin};
pub use install::{HookInstallReport, HookTargetKind, install_hook, uninstall_hook};
