// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod eval;

use std::sync::Mutex;

use grdr_fastpath::{
    BinaryFloorTable, FLAG_TRUNCATED, FastActionClass, MAX_HOOK_SCAN_BYTES, scan_hook_payload,
};

use crate::eval::{
    BrowserMode, encode_default_browser_floor, evaluate_action_with_floor, format_error_json,
    format_eval_json, push_json_escaped, verdict_code,
};

const MAX_INPUT_BYTES: usize = 32_768;
const MAX_OUTPUT_BYTES: usize = 4_096;
const MAX_FIELD_BYTES: usize = 256;
const ABI_VERSION: u32 = 1;

struct WasmCoreState {
    input: Vec<u8>,
    floor: Vec<u8>,
    output: Vec<u8>,
}

static STATE: Mutex<WasmCoreState> = Mutex::new(WasmCoreState {
    input: Vec::new(),
    floor: Vec::new(),
    output: Vec::new(),
});

fn utf8_prefix_bytes(bytes: &[u8], max_bytes: usize) -> &[u8] {
    if bytes.len() <= max_bytes {
        return bytes;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let cut = text.floor_char_boundary(max_bytes);
        return text.as_bytes().get(..cut).unwrap_or(&[]);
    }
    let mut cut = max_bytes;
    while cut > 0 {
        if std::str::from_utf8(bytes.get(..cut).unwrap_or(&[])).is_ok() {
            break;
        }
        cut = cut.saturating_sub(1);
    }
    bytes.get(..cut).unwrap_or(&[])
}

impl WasmCoreState {
    fn clear_input(&mut self) {
        self.input.clear();
    }

    fn write_output(&mut self, bytes: &[u8]) {
        self.output.clear();
        self.output
            .extend_from_slice(utf8_prefix_bytes(bytes, MAX_OUTPUT_BYTES));
    }

    fn write_error(&mut self, code: &str, message: &str) {
        let json = format_error_json(code, message);
        self.write_output(json.as_bytes());
    }
}

#[allow(
    unsafe_code,
    reason = "Exported C ABI symbol name `grdr_abi_version` is required by Wasm host."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_abi_version() -> u32 {
    ABI_VERSION
}

#[allow(
    unsafe_code,
    reason = "Exported C ABI symbol name `grdr_input_reset` is required by Wasm host."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_input_reset() -> i32 {
    let Ok(mut state) = STATE.lock() else {
        return -1;
    };
    state.clear_input();
    0
}

#[allow(
    unsafe_code,
    reason = "Exported C ABI symbol name `grdr_input_push_word` is required by Wasm host."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_input_push_word(word: u32, byte_count: u32) -> i32 {
    let Ok(mut state) = STATE.lock() else {
        return -1;
    };
    if byte_count == 0 || byte_count > 4 {
        state.write_error(
            "browser.wasm.invalid-word-count",
            "Word byte count must be 1..=4.",
        );
        return -2;
    }
    let count = byte_count as usize;
    if state.input.len().saturating_add(count) > MAX_INPUT_BYTES {
        state.write_error("browser.wasm.input-overflow", "Input exceeds 32 KiB limit.");
        return -3;
    }
    let bytes = word.to_le_bytes();
    if let Some(slice) = bytes.get(..count) {
        state.input.extend_from_slice(slice);
        return i32::try_from(state.input.len()).unwrap_or(-4);
    }
    state.write_error("browser.wasm.slice-error", "Failed extracting word bytes.");
    -4
}

#[allow(
    unsafe_code,
    reason = "Exported C ABI symbol name `grdr_output_len` is required by Wasm host."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_output_len() -> u32 {
    let Ok(state) = STATE.lock() else {
        return 0;
    };
    u32::try_from(state.output.len()).unwrap_or(0)
}

#[allow(
    unsafe_code,
    reason = "Exported C ABI symbol name `grdr_output_word` is required by Wasm host."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_output_word(word_idx: u32) -> u32 {
    let Ok(state) = STATE.lock() else {
        return 0;
    };
    let start = (word_idx as usize).saturating_mul(4);
    let mut chunk = [0u8; 4];
    for (idx, slot) in chunk.iter_mut().enumerate() {
        if let Some(b) = state.output.get(start.saturating_add(idx)) {
            *slot = *b;
        }
    }
    u32::from_le_bytes(chunk)
}

#[allow(
    unsafe_code,
    reason = "Exported C ABI symbol name `grdr_load_floor_binary` is required by Wasm host."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_load_floor_binary() -> i32 {
    let Ok(mut state) = STATE.lock() else {
        return -1;
    };
    let rule_count = match BinaryFloorTable::parse(&state.input) {
        Ok(table) => table.rule_count(),
        Err(_) => {
            state.write_error(
                "browser.floor.corrupt",
                "Compiled binary floor failed magic or CRC32 check.",
            );
            return -2;
        }
    };
    let copy_bytes = state.input.clone();
    state.floor = copy_bytes;
    i32::from(rule_count)
}

#[allow(
    unsafe_code,
    reason = "Exported C ABI symbol name `grdr_load_default_browser_floor` is required by Wasm host."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_load_default_browser_floor() -> i32 {
    let Ok(mut state) = STATE.lock() else {
        return -1;
    };
    let Ok(floor_bytes) = encode_default_browser_floor() else {
        state.write_error(
            "browser.floor.encode-failed",
            "Failed building default browser floor.",
        );
        return -2;
    };
    let Ok(table) = BinaryFloorTable::parse(&floor_bytes) else {
        state.write_error(
            "browser.floor.corrupt",
            "Built-in browser floor failed self-verification.",
        );
        return -3;
    };
    let count = i32::from(table.rule_count());
    state.floor = floor_bytes;
    count
}

#[allow(
    unsafe_code,
    reason = "Exported C ABI symbol name `grdr_scan_hook_payload` is required by Wasm host."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_scan_hook_payload() -> i32 {
    let Ok(mut state) = STATE.lock() else {
        return -1;
    };
    let scan = scan_hook_payload(&state.input, MAX_HOOK_SCAN_BYTES);
    let flags = scan.flags;
    let truncated = (flags & FLAG_TRUNCATED) != 0;
    let mut json = String::with_capacity(256);
    json.push_str("{\"flags\":");
    json.push_str(&flags.to_string());
    json.push_str(",\"truncated\":");
    json.push_str(if truncated { "true" } else { "false" });
    json.push_str(",\"tool\":\"");
    push_json_escaped(&mut json, scan.tool_name, MAX_FIELD_BYTES);
    json.push_str("\",\"target\":\"");
    push_json_escaped(&mut json, scan.target, MAX_FIELD_BYTES);
    json.push_str("\"}");
    state.write_output(json.as_bytes());
    if flags == 0 { 0 } else { 1 }
}

#[allow(
    unsafe_code,
    reason = "Exported C ABI symbol name `grdr_evaluate_browser_action` is required by Wasm host."
)]
#[unsafe(no_mangle)]
pub extern "C" fn grdr_evaluate_browser_action(
    action_code: u32,
    mode_code: u32,
    labels_mask: u32,
    principal_mask: u32,
) -> i32 {
    let Ok(mut state) = STATE.lock() else {
        return -1;
    };
    let Ok(action_u8) = u8::try_from(action_code) else {
        state.write_error("browser.wasm.invalid-action", "Invalid action class code.");
        return -2;
    };
    let Some(action) = FastActionClass::from_u8(action_u8) else {
        state.write_error("browser.wasm.unknown-action", "Unknown action class code.");
        return -2;
    };
    let Some(mode) = BrowserMode::from_u32(mode_code) else {
        state.write_error("browser.wasm.invalid-mode", "Invalid browser mode code.");
        return -3;
    };
    let Ok(labels) = u16::try_from(labels_mask) else {
        state.write_error(
            "browser.wasm.invalid-labels",
            "Labels mask exceeds u16 range.",
        );
        return -4;
    };
    let Ok(principal) = u16::try_from(principal_mask) else {
        state.write_error(
            "browser.wasm.invalid-principal",
            "Principal mask exceeds u16 range.",
        );
        return -5;
    };

    let floor_copy = state.floor.clone();
    let input_copy = state.input.clone();
    let summary =
        evaluate_action_with_floor(&floor_copy, &input_copy, action, mode, labels, principal);
    let code = verdict_code(summary.verdict);
    let json = format_eval_json(&summary, mode);
    state.write_output(json.as_bytes());
    code
}

#[cfg(test)]
mod tests {
    use super::utf8_prefix_bytes;

    #[test]
    fn truncates_output_on_valid_utf8_char_boundary() {
        let raw = "ééé".as_bytes();
        let cut = utf8_prefix_bytes(raw, 5);
        assert_eq!(cut.len(), 4);
        assert!(std::str::from_utf8(cut).is_ok());
    }
}
