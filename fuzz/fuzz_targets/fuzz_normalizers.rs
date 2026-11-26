// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_core::analyze::{
    canonicalize_path, classify_target, normalize_attempt_target, normalize_command,
};
use grdr_model::{ActionClass, CommandParseStatus};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let cmd = normalize_command(&text);
    if cmd.status == CommandParseStatus::Resolved && !cmd.canonical_text.is_empty() {
        let again = normalize_command(&cmd.canonical_text);
        assert_eq!(again.canonical_text, cmd.canonical_text);
    }

    let canon_path = canonicalize_path(&text);
    assert_eq!(canonicalize_path(&canon_path), canon_path);

    let exec_analysis = classify_target(ActionClass::Exec, &text);
    if cmd.status == CommandParseStatus::Malformed {
        assert_eq!(exec_analysis.command_status, CommandParseStatus::Malformed);
        assert!(
            exec_analysis
                .risk_tags
                .iter()
                .any(|t| t == "exec.malformed")
        );
        assert!(exec_analysis.risk_score >= 85);
    }

    for class in [
        ActionClass::FileRead,
        ActionClass::FileWrite,
        ActionClass::FileDelete,
        ActionClass::NetConnect,
        ActionClass::NetRequest,
        ActionClass::McpCall,
        ActionClass::Elevate,
    ] {
        let _ = normalize_attempt_target(class, &text);
        let _ = classify_target(class, &text);
    }
});
