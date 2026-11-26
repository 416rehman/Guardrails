// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use grdr_llm_proto::parse_mcp_jsonrpc_line;
use grdr_mcp_proto::{ToolDescriptor, detect_tool_poisoning, parse_mcp_request, verify_tool_pin};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_mcp_request(text);
    let _ = parse_mcp_jsonrpc_line(text);

    let desc = ToolDescriptor {
        name: "fuzz_tool".into(),
        description: text.to_string(),
        input_schema: serde_json::json!({ "prompt": text }),
    };
    let _ = detect_tool_poisoning(&desc);
    let _ = verify_tool_pin(&desc, None);
});
