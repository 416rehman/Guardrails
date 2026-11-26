// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_llm_proto::parse_llm_request_metadata;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for provider in ["openai", "anthropic", "gemini"] {
        let _ = parse_llm_request_metadata(provider, text);
    }
});
