// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_agents::hook_codec::{HarnessKind, parse_hook_stdin};
use grdr_fastpath::{FastActionClass, FastVerdict, FloorRuleRef, evaluate_floor_entries};
use grdr_wire::floor_bin::{MAX_FLOOR_RULES, verify_and_decode_floor_table};
use libfuzzer_sys::fuzz_target;

const RFC8032_VEC1_PUBKEY_B64: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let trusted_keys = [("floor-active", RFC8032_VEC1_PUBKEY_B64)];
    assert!(verify_and_decode_floor_table(data, &[], 0).is_err());
    if let Ok(verified) = verify_and_decode_floor_table(data, &trusted_keys, 1_750_000_000) {
        assert!(verified.document.rules.len() <= MAX_FLOOR_RULES);
    }

    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    let floor_rules = [FloorRuleRef {
        rule_id: "FUZZ-RM-RF",
        action_mask: FastActionClass::Exec.bit(),
        prefixes: &[],
        contains: &["rm -rf /"],
        agents: &["claude-code"],
        verdict: FastVerdict::Deny,
    }];
    let hit = evaluate_floor_entries(&floor_rules, FastActionClass::Exec, "claude-code", raw);
    if raw.contains("rm -rf /") {
        assert!(hit.is_some());
    }
    if let Some(found) = hit {
        assert_eq!(found.verdict, FastVerdict::Deny);
    }

    let serde_valid =
        serde_json::from_str::<serde_json::Value>(raw.trim_start_matches('\u{FEFF}')).is_ok();
    for kind in [
        HarnessKind::Auto,
        HarnessKind::ClaudeCode,
        HarnessKind::Cursor,
        HarnessKind::Codex,
        HarnessKind::Gemini,
    ] {
        let parsed = parse_hook_stdin(kind, raw, "fuzz-device");
        if !serde_valid {
            assert!(parsed.is_err());
        }
    }
});
