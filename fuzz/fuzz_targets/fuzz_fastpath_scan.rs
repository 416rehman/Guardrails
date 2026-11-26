// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_fastpath::{
    BinaryFloorTable, BinaryRuleInput, FLAG_TRUNCATED, FastActionClass, FastVerdict, FloorRuleRef,
    MAX_EXTRACTED_FIELD_BYTES, PRINCIPAL_SESSION, encode_binary_floor, evaluate_failsafe,
    evaluate_floor_entries, scan_hook_payload,
};
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
    if let Ok(parsed) = BinaryFloorTable::parse(data) {
        let _ = parsed.evaluate(action, PRINCIPAL_SESSION, 0, "claude-code", "git status");
    }

    let scan = scan_hook_payload(data, 4096);
    assert!(scan.scanned_bytes <= 4096.min(data.len()));
    assert!(scan.target.len() <= MAX_EXTRACTED_FIELD_BYTES);
    if data.len() > 4096 {
        assert_ne!(scan.flags & FLAG_TRUNCATED, 0);
    }
    let _ = evaluate_failsafe(action, scan.target);

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
    let entries = [
        FloorRuleRef {
            rule_id: "fuzz.floor.allow",
            action_mask: action.bit(),
            prefixes: &prefixes,
            contains: &contains,
            agents: &agents,
            verdict: FastVerdict::Allow,
        },
        FloorRuleRef {
            rule_id: "fuzz.floor.rule",
            action_mask: action.bit(),
            prefixes: &prefixes,
            contains: &contains,
            agents: &agents,
            verdict,
        },
    ];
    let hit = evaluate_floor_entries(&entries, action, "claude-code", target);
    let wrong_agent = evaluate_floor_entries(&entries, action, "other-agent", target);
    assert!(wrong_agent.is_none());
    let wrong_class = evaluate_floor_entries(&entries, wrong_action, "claude-code", target);
    assert!(wrong_class.is_none());
    if needle.is_empty() {
        assert!(hit.is_none());
    } else if let Some(h) = hit {
        assert_eq!(h.verdict, verdict);
        assert_eq!(h.rule_id, "fuzz.floor.rule");
    }

    if needle.len() <= 256 {
        let mut buf = [0u8; 4096];
        let bin_inputs = [
            BinaryRuleInput {
                rule_id: "fuzz.floor.allow",
                reason: "Fuzz floor allow",
                action_mask: action.bit(),
                principal_mask: PRINCIPAL_SESSION,
                label_mask: 0,
                verdict: FastVerdict::Allow,
                agents: &agents,
                prefixes: &prefixes,
                contains: &contains,
            },
            BinaryRuleInput {
                rule_id: "fuzz.floor.rule",
                reason: "Fuzz floor match",
                action_mask: action.bit(),
                principal_mask: PRINCIPAL_SESSION,
                label_mask: 0,
                verdict,
                agents: &agents,
                prefixes: &prefixes,
                contains: &contains,
            },
        ];
        let len =
            encode_binary_floor(&bin_inputs, &mut buf).expect("bounded 256B floor fits 4KB buffer");
        let table = BinaryFloorTable::parse(&buf[..len]).expect("encoded binary floor must parse");
        let bin_hit = table.evaluate(action, PRINCIPAL_SESSION, 0, "claude-code", target);
        assert_eq!(hit.map(|h| h.rule_id), bin_hit.map(|h| h.rule_id));
        assert_eq!(hit.map(|h| h.verdict), bin_hit.map(|h| h.verdict));
    }
});
