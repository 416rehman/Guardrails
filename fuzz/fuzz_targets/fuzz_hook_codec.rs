// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_agents::hook_codec::{HarnessKind, parse_hook_stdin};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    for kind in [
        HarnessKind::Auto,
        HarnessKind::ClaudeCode,
        HarnessKind::Cursor,
        HarnessKind::Codex,
        HarnessKind::Gemini,
    ] {
        let _ = parse_hook_stdin(kind, raw, "fuzz-device");
    }
});
