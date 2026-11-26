// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_fastpath::{FastActionClass, FastVerdict, FloorRuleRef, evaluate_floor_entries};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 || data.len() > 32_768 {
        return;
    }
    let Some((&tag, rest)) = data.split_first() else {
        return;
    };
    let action = FastActionClass::from_u8(tag % 15).unwrap_or(FastActionClass::Exec);
    let wrong_action = FastActionClass::from_u8((tag % 15).saturating_add(1) % 15)
        .unwrap_or(FastActionClass::FileRead);
    let split_mid = rest.len() / 2;
    let (needle_bytes, target_bytes) = rest.split_at(split_mid);
    let Ok(needle) = std::str::from_utf8(needle_bytes) else {
        return;
    };
    let Ok(target) = std::str::from_utf8(target_bytes) else {
        return;
    };
    let verdict = if tag & 1 == 0 {
        FastVerdict::Deny
    } else {
        FastVerdict::StepUp
    };
    let prefixes = [needle];
    let contains = [needle];
    let agents = ["claude-code"];
    let entries = [FloorRuleRef {
        rule_id: "fuzz.floor.rule",
        action_mask: action.bit(),
        prefixes: &prefixes,
        contains: &contains,
        agents: &agents,
        verdict,
    }];
    let hit = evaluate_floor_entries(&entries, action, "claude-code", target);
    let wrong_agent = evaluate_floor_entries(&entries, action, "other-agent", target);
    assert!(wrong_agent.is_none());
    let wrong_class = evaluate_floor_entries(&entries, wrong_action, "claude-code", target);
    assert!(wrong_class.is_none());
    if needle.is_empty() {
        assert!(hit.is_some());
    }
});
