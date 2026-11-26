// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_conformance::parse_pack_manifest_toml;
use grdr_model::identity::IdentityMode;
use grdr_schema::limits::parse_limits_toml;
use grdr_schema_lint::{first_forbidden_execution_pattern, lint_pack_manifest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(manifest) = parse_pack_manifest_toml(text) {
        let has_hostile_snippet = manifest
            .rule_snippets
            .iter()
            .any(|s| first_forbidden_execution_pattern(s).is_some());
        let has_hostile = !manifest.commands.is_empty()
            || !manifest.executables.is_empty()
            || !manifest.urls.is_empty()
            || !manifest.env_vars_to_set.is_empty()
            || !manifest.mcp_servers_to_start.is_empty()
            || has_hostile_snippet;
        for mode in [IdentityMode::Named, IdentityMode::Pseudonymous] {
            let res = lint_pack_manifest(&manifest, mode);
            if has_hostile {
                assert!(res.is_err(), "P7 invariant: hostile pack must fail linting");
            }
        }
    }
    let _ = parse_limits_toml(text);
});
