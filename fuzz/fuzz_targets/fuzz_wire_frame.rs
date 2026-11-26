// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_wire::{WireEnvelope, decode_frame, encode_frame, verify_envelope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }
    if let Ok((envelope, _consumed)) = decode_frame::<serde_json::Value>(data) {
        let _ = encode_frame(&envelope);
        let _ = verify_envelope(&envelope, &[]);
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(env) = serde_json::from_str::<WireEnvelope<serde_json::Value>>(text)
    {
        let _ = verify_envelope(&env, &[]);
    }
});
