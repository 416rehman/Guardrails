// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import * as fs from "node:fs";
import type { LocalFloorEvaluator } from "./client.ts";
import type { DecideInput, DecisionReceipt, Verdict } from "./types.ts";
import { GuardrailsError, parseVerdict } from "./types.ts";

export interface WasmEvaluatorExports {
  memory?: WebAssembly.Memory;
  grdr_alloc?: (len: number) => number;
  grdr_free?: (ptr: number, len: number) => void;
  grdr_wasm_abi_version?: () => number;
  grdr_wasm_eval_attempt?: (ptr: number, len: number) => number;
  grdr_result_ptr?: () => number;
  grdr_result_len?: () => number;
}

export async function inspectWasmModuleImports(wasmPath: string): Promise<string[]> {
  const bytes = fs.readFileSync(wasmPath);
  const compiled = await WebAssembly.compile(bytes);
  return WebAssembly.Module.imports(compiled).map((imp) => `${imp.module}.${imp.name}`);
}

export async function loadZeroImportWasmModule(wasmPath: string): Promise<WebAssembly.Instance> {
  const bytes = fs.readFileSync(wasmPath);
  const compiled = await WebAssembly.compile(bytes);
  const imports = WebAssembly.Module.imports(compiled);
  if (imports.length > 0) {
    throw new GuardrailsError(
      `grdr-wasm core module must have zero host imports, found: ${imports.map((i) => i.name).join(", ")}`,
    );
  }
  return await WebAssembly.instantiate(compiled, {});
}

export function createWasmFloorEvaluator(
  instance: WebAssembly.Instance,
  packsJson: string,
): LocalFloorEvaluator {
  const exportsObj = instance.exports as unknown as WasmEvaluatorExports;
  if (
    !exportsObj.memory ||
    !exportsObj.grdr_alloc ||
    !exportsObj.grdr_free ||
    !exportsObj.grdr_wasm_eval_attempt ||
    !exportsObj.grdr_result_ptr ||
    !exportsObj.grdr_result_len
  ) {
    throw new GuardrailsError("WASM module missing required Guardrails C-ABI exports");
  }
  const memory = exportsObj.memory;
  const alloc = exportsObj.grdr_alloc;
  const free = exportsObj.grdr_free;
  const evalFn = exportsObj.grdr_wasm_eval_attempt;
  const resultPtr = exportsObj.grdr_result_ptr;
  const resultLen = exportsObj.grdr_result_len;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  return (attempt: DecideInput): DecisionReceipt => {
    const reqJson = JSON.stringify({ attempt, packs: JSON.parse(packsJson) });
    const reqBytes = encoder.encode(reqJson);
    const ptr = alloc(reqBytes.length);
    if (ptr === 0) {
      throw new GuardrailsError("WASM input exceeds allocation budget");
    }
    try {
      new Uint8Array(memory.buffer, ptr, reqBytes.length).set(reqBytes);
      const rc = evalFn(ptr, reqBytes.length);
      const outPtr = resultPtr();
      const outLen = resultLen();
      const outText = decoder.decode(new Uint8Array(memory.buffer, outPtr, outLen));
      const parsed = JSON.parse(outText) as {
        verdict?: string;
        rule_id?: string;
        reason?: string;
        error?: string;
      };
      if (rc !== 0 && parsed.error) {
        throw new GuardrailsError(parsed.error);
      }
      const verdict: Verdict = parseVerdict(parsed.verdict ?? "block");
      return {
        id: `wasm_${Date.now()}`,
        verdict,
        rule_id: parsed.rule_id ?? "",
        reason: parsed.reason ?? "",
        session_id: attempt.session_id ?? "",
        mode: verdict === "allow" ? "Watch" : verdict === "ask" ? "Ask" : "Block",
        degraded: true,
      };
    } finally {
      if (ptr !== 0) {
        free(ptr, reqBytes.length);
      }
    }
  };
}
