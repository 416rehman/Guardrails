// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_core::policy::{essentials_pack, evaluate, validate_cedar_rule};
use grdr_model::{ActionAttempt, ActionClass, ControlPoint, KillSwitchState};
use jiff::Timestamp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 32_768 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = validate_cedar_rule(text);

    let packs = vec![essentials_pack()];
    let attempt = ActionAttempt {
        id: "att_fuzz".into(),
        session_id: "sess_fuzz".into(),
        device_id: "dev_fuzz".into(),
        device_name: "fuzz-host".into(),
        agent_name: "claude-code".into(),
        action_class: ActionClass::Exec,
        control_point: ControlPoint::Hook,
        target: text.to_string(),
        summary: String::new(),
        timestamp: Timestamp::UNIX_EPOCH,
        ..Default::default()
    };
    let _ = evaluate(
        &attempt,
        &packs,
        &[],
        &KillSwitchState::Inactive,
        Timestamp::UNIX_EPOCH,
    );
});
