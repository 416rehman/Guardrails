// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type {
  ActionClass,
  AiDestinationSpec,
  AiDestinationsCatalog,
  BrowserInspectDecision,
  BrowserInspectRequest,
  BrowserMode,
  BrowserVerdict,
  DlpDetectorsCatalog,
} from "./types.js";

const ACTION_CODE_MAP: Record<ActionClass, number> = {
  net_request: 5,
  llm_request: 6,
  "mcp.call": 8,
  cred_use: 9,
  data_flow: 14,
};

const MODE_CODE_MAP: Record<BrowserMode, number> = {
  off: 0,
  watch: 1,
  ask: 2,
  block: 3,
};

const LABEL_CREDENTIAL_ACCESSED = 1 << 0;
const LABEL_TAINTED_EXFIL = 1 << 3;
const PRINCIPAL_SESSION = 1 << 0;
const MAX_U16 = 0xffff;

interface WasmExports extends WebAssembly.Exports {
  grdr_abi_version: () => number;
  grdr_input_reset: () => number;
  grdr_input_push_word: (word: number, byteCount: number) => number;
  grdr_output_len: () => number;
  grdr_output_word: (wordIdx: number) => number;
  grdr_load_floor_binary: () => number;
  grdr_load_default_browser_floor: () => number;
  grdr_scan_hook_payload: () => number;
  grdr_evaluate_browser_action: (
    actionCode: number,
    modeCode: number,
    labelsMask: number,
    principalMask: number,
  ) => number;
}

interface CompiledRule {
  id: string;
  kind: "secret" | "pii";
  severity: "deny" | "stepup";
  label: string;
  regex: RegExp;
}

interface RawWasmEvalResult {
  verdict: BrowserVerdict;
  rule_id: string;
  reason: string;
  flags: number;
  floor_hit: boolean;
  hard_fail_closed?: boolean;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: false });

function compileDetectors(catalog: DlpDetectorsCatalog): CompiledRule[] {
  return catalog.rules.map((rule) => ({
    id: rule.id,
    kind: rule.kind,
    severity: rule.severity,
    label: rule.label,
    regex: new RegExp(rule.pattern, rule.flags),
  }));
}

function matchHost(hostname: string, destination: AiDestinationSpec): boolean {
  const lower = hostname.toLowerCase();
  for (const host of destination.hosts) {
    const h = host.toLowerCase();
    if (lower === h || lower.endsWith(`.${h}`)) {
      return true;
    }
  }
  for (const pattern of destination.wildcardHosts ?? []) {
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1).toLowerCase();
      if (lower.endsWith(suffix) && lower.length > suffix.length) {
        return true;
      }
    }
  }
  return false;
}

export function extractFileExtensions(fileName: string): string[] {
  const base = fileName.trim().split(/[\\/]/).pop() ?? "";
  if (!base) return [];
  const lower = base.toLowerCase();
  const out: string[] = [];

  if (lower.startsWith(".")) {
    const secondDot = lower.indexOf(".", 1);
    if (secondDot > 1) {
      out.push(lower.slice(0, secondDot));
      out.push(lower.slice(secondDot));
      out.push(lower);
    } else {
      out.push(lower);
    }
    return [...new Set(out)];
  }

  const lastDot = lower.lastIndexOf(".");
  if (lastDot > 0 && lastDot < lower.length - 1) {
    out.push(lower.slice(lastDot));
  }
  return out;
}

function sanitizePackedField(value: string): string {
  return value.replace(/\0/g, "");
}

export class WasmPolicyEngine {
  readonly abiVersion: number;
  readonly importCount: number;
  private readonly exports: WasmExports;
  private readonly destinations: AiDestinationsCatalog;
  private readonly detectors: CompiledRule[];
  private readonly maxInspectBytes: number;
  private floorRuleCount = 0;

  private constructor(
    exports: WasmExports,
    abiVersion: number,
    importCount: number,
    destinations: AiDestinationsCatalog,
    dlpCatalog: DlpDetectorsCatalog,
  ) {
    this.exports = exports;
    this.abiVersion = abiVersion;
    this.importCount = importCount;
    this.destinations = destinations;
    this.detectors = compileDetectors(dlpCatalog);
    this.maxInspectBytes = Math.min(dlpCatalog.maxInspectBytes, 65_536);
  }

  static async create(
    wasmBytes: Uint8Array | ArrayBuffer,
    destinations: AiDestinationsCatalog,
    dlpCatalog: DlpDetectorsCatalog,
  ): Promise<WasmPolicyEngine> {
    const ownedBytes =
      wasmBytes instanceof ArrayBuffer
        ? new Uint8Array(wasmBytes)
        : new Uint8Array(wasmBytes.slice());
    const mod = await WebAssembly.compile(ownedBytes);
    const imports = WebAssembly.Module.imports(mod);
    if (imports.length !== 0) {
      throw new Error(
        `GRDR-EXT-0001 Wasm policy core must define zero imports; found ${imports.length}`,
      );
    }
    const instance = await WebAssembly.instantiate(mod, {});
    const exports = instance.exports as WasmExports;
    const abi = exports.grdr_abi_version();
    return new WasmPolicyEngine(exports, abi, imports.length, destinations, dlpCatalog);
  }

  get loadedFloorRules(): number {
    return this.floorRuleCount;
  }

  loadDefaultBrowserFloor(): number {
    const count = this.exports.grdr_load_default_browser_floor();
    if (count < 0) {
      throw new Error(`GRDR-EXT-0005 Default floor load failed (rc=${count})`);
    }
    this.floorRuleCount = count;
    return count;
  }

  loadFloorBinary(tableBytes: Uint8Array): number {
    this.writeInputBytes(tableBytes);
    const count = this.exports.grdr_load_floor_binary();
    if (count < 0) {
      throw new Error(`GRDR-EXT-0002 Invalid compiled binary floor table (rc=${count})`);
    }
    this.floorRuleCount = count;
    return count;
  }

  scanHookPayload(payloadBytes: Uint8Array): {
    flags: number;
    truncated: boolean;
    tool: string;
    target: string;
  } {
    this.writeInputBytes(payloadBytes);
    const rc = this.exports.grdr_scan_hook_payload();
    if (rc < 0) {
      throw new Error(`GRDR-EXT-0006 Wasm hook scanner failed (rc=${rc})`);
    }
    try {
      const text = this.readOutputString();
      return JSON.parse(text) as { flags: number; truncated: boolean; tool: string; target: string };
    } catch {
      return { flags: 1, truncated: true, tool: "", target: "" };
    }
  }

  matchDestination(hostname: string): AiDestinationSpec | null {
    for (const dest of this.destinations.destinations) {
      if (matchHost(hostname, dest)) {
        return dest;
      }
    }
    return null;
  }

  inspectContentLocally(req: BrowserInspectRequest): {
    secretHits: string[];
    sensitiveExtensions: string[];
  } {
    const sample = req.bodyPreview.slice(0, this.maxInspectBytes);
    const secretHits: string[] = [];
    for (const rule of this.detectors) {
      rule.regex.lastIndex = 0;
      if (rule.regex.test(sample)) {
        secretHits.push(rule.id);
      }
    }

    const sensitiveSet = new Set(
      this.destinations.sensitiveFileExtensions.map((ext) => ext.toLowerCase()),
    );
    const sensitiveExtensions: string[] = [];
    const addSensitive = (candidate: string) => {
      const normalized = candidate.toLowerCase();
      if (normalized && sensitiveSet.has(normalized) && !sensitiveExtensions.includes(normalized)) {
        sensitiveExtensions.push(normalized);
      }
    };

    for (const ext of req.fileExtensions) {
      addSensitive(ext);
    }
    for (const fileName of req.fileNames) {
      for (const ext of extractFileExtensions(fileName)) {
        addSensitive(ext);
      }
      const base = fileName.trim().split(/[\\/]/).pop()?.toLowerCase() ?? "";
      if (base === "id_rsa" || base === "id_ed25519") {
        addSensitive(base);
      }
    }
    return { secretHits, sensitiveExtensions };
  }

  evaluateRawAbi(
    actionCode: number,
    modeCode: number,
    labelsMask: number,
    principalMask: number,
    packedInput: Uint8Array,
  ): { rc: number; output: string } {
    this.writeInputBytes(packedInput);
    const rc = this.exports.grdr_evaluate_browser_action(
      actionCode,
      modeCode,
      labelsMask,
      principalMask,
    );
    return { rc, output: this.readOutputString() };
  }

  evaluateLocally(
    req: BrowserInspectRequest,
    modeOverrides: Record<string, BrowserMode>,
    failClosedOnDegraded: boolean,
    hostDegraded: boolean,
  ): BrowserInspectDecision {
    const dest = this.matchDestination(req.hostname);
    const modeApplied: BrowserMode = dest
      ? (modeOverrides[dest.id] ?? dest.defaultMode)
      : "watch";
    const { secretHits, sensitiveExtensions } = this.inspectContentLocally(req);

    if (req.hostname.includes("\0") || req.url.includes("\0") || req.toolName?.includes("\0")) {
      return {
        requestId: req.requestId,
        verdict: "deny",
        ruleId: "browser.input.nul-injection",
        reason: "Rejected NUL byte inside browser target metadata.",
        modeApplied,
        appId: dest?.id ?? null,
        appName: dest?.name ?? sanitizePackedField(req.hostname),
        source: "wasm_floor",
        hostDegraded,
        secretHits,
        sensitiveExtensions,
        flags: 0,
      };
    }

    let labelsMask = 0;
    if (secretHits.length > 0 && (!dest || dest.blockSecretPayloads)) {
      labelsMask |= LABEL_CREDENTIAL_ACCESSED;
    }
    if (
      (sensitiveExtensions.length > 0 || req.hasFileUpload) &&
      (!dest || dest.blockFileUploads || sensitiveExtensions.length > 0)
    ) {
      labelsMask |= LABEL_TAINTED_EXFIL;
    }

    const safeHost = sanitizePackedField(req.hostname);
    const safeTransport = sanitizePackedField(req.transport);
    const safeUrl = sanitizePackedField(req.url);
    const safeTool = req.toolName ? sanitizePackedField(req.toolName) : "";
    const safeFile = req.fileNames[0] ? sanitizePackedField(req.fileNames[0]) : "";

    const target =
      req.actionClass === "mcp.call" && safeTool
        ? `webmcp:${safeHost}/${safeTool}`
        : `${safeUrl}${safeFile ? `/${safeFile}` : ""}`;
    const packedInput = `${safeTransport}\0${target}\0${sanitizePackedField(req.bodyPreview.slice(0, 4096))}`;
    this.writeInputBytes(textEncoder.encode(packedInput));

    const actionCode = ACTION_CODE_MAP[req.actionClass];
    const modeCode = MODE_CODE_MAP[modeApplied];
    const clampedLabels = labelsMask & MAX_U16;
    const rc = this.exports.grdr_evaluate_browser_action(
      actionCode,
      modeCode,
      clampedLabels,
      PRINCIPAL_SESSION,
    );

    if (rc < 0) {
      return {
        requestId: req.requestId,
        verdict: failClosedOnDegraded || modeApplied === "block" ? "deny" : "step_up",
        ruleId: "browser.wasm.abi-error",
        reason: `Wasm policy evaluator returned error rc=${rc}; enforced fail-closed verdict.`,
        modeApplied,
        appId: dest?.id ?? null,
        appName: dest?.name ?? safeHost,
        source: "wasm_floor",
        hostDegraded: true,
        secretHits,
        sensitiveExtensions,
        flags: 0,
      };
    }

    let parsed: RawWasmEvalResult;
    try {
      parsed = JSON.parse(this.readOutputString()) as RawWasmEvalResult;
    } catch {
      return {
        requestId: req.requestId,
        verdict: failClosedOnDegraded || modeApplied === "block" ? "deny" : "step_up",
        ruleId: "browser.wasm.parse-error",
        reason: "Wasm policy output failed JSON parsing; enforced fail-closed verdict.",
        modeApplied,
        appId: dest?.id ?? null,
        appName: dest?.name ?? safeHost,
        source: "wasm_floor",
        hostDegraded: true,
        secretHits,
        sensitiveExtensions,
        flags: 0,
      };
    }

    let finalVerdict: BrowserVerdict = parsed.verdict;
    let finalRule = parsed.rule_id;
    let finalReason = parsed.reason;

    if (!parsed.hard_fail_closed) {
      if (
        modeApplied === "block" &&
        (secretHits.length > 0 || sensitiveExtensions.length > 0) &&
        finalVerdict !== "deny"
      ) {
        finalVerdict = "deny";
        finalRule = secretHits[0] ?? "browser.dlp.block-transfer";
        finalReason = "Destination block mode denied sensitive outbound transfer.";
      } else if (
        modeApplied === "ask" &&
        finalVerdict === "allow" &&
        (req.actionClass === "mcp.call" ||
          req.hasFileUpload ||
          secretHits.length > 0 ||
          sensitiveExtensions.length > 0)
      ) {
        finalVerdict = "step_up";
        finalRule =
          req.actionClass === "mcp.call"
            ? "browser.webmcp.ask"
            : (secretHits[0] ?? "browser.dlp.ask-confirmation");
        finalReason =
          req.actionClass === "mcp.call"
            ? "WebMCP tool invocation requires confirmation under Ask mode."
            : "Outbound transfer requires user confirmation under Ask mode.";
      }
    }

    if (
      hostDegraded &&
      failClosedOnDegraded &&
      dest !== null &&
      modeApplied !== "off" &&
      finalVerdict === "allow" &&
      (modeApplied === "block" ||
        req.hasFileUpload ||
        req.actionClass === "mcp.call" ||
        secretHits.length > 0 ||
        sensitiveExtensions.length > 0)
    ) {
      finalVerdict = "deny";
      finalRule = "browser.degraded.fail-closed";
      finalReason =
        "Native host unavailable in fail-closed mode; blocked sensitive browser action.";
    }

    return {
      requestId: req.requestId,
      verdict: finalVerdict,
      ruleId: finalRule,
      reason: finalReason,
      modeApplied,
      appId: dest?.id ?? null,
      appName: dest?.name ?? safeHost,
      source: "wasm_floor",
      hostDegraded,
      secretHits,
      sensitiveExtensions,
      flags: parsed.flags,
    };
  }

  private writeInputBytes(bytes: Uint8Array): void {
    const resetCode = this.exports.grdr_input_reset();
    if (resetCode < 0) {
      throw new Error(`GRDR-EXT-0003 Wasm input buffer reset failed (rc=${resetCode})`);
    }
    const maxLen = Math.min(bytes.length, 32_768);
    for (let offset = 0; offset < maxLen; offset += 4) {
      const remaining = Math.min(4, maxLen - offset);
      const b0 = bytes[offset] ?? 0;
      const b1 = remaining > 1 ? (bytes[offset + 1] ?? 0) : 0;
      const b2 = remaining > 2 ? (bytes[offset + 2] ?? 0) : 0;
      const b3 = remaining > 3 ? (bytes[offset + 3] ?? 0) : 0;
      const word = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
      const rc = this.exports.grdr_input_push_word(word, remaining);
      if (rc < 0) {
        throw new Error(`GRDR-EXT-0004 Wasm input buffer push failed (rc=${rc})`);
      }
    }
  }

  private readOutputString(): string {
    const len = this.exports.grdr_output_len();
    if (len < 0 || len > 65_536) {
      throw new Error(`GRDR-EXT-0008 Invalid Wasm output buffer length (${len})`);
    }
    const out = new Uint8Array(len);
    const wordCount = Math.ceil(len / 4);
    for (let wordIdx = 0; wordIdx < wordCount; wordIdx += 1) {
      const word = this.exports.grdr_output_word(wordIdx);
      const base = wordIdx * 4;
      if (base < len) out[base] = word & 0xff;
      if (base + 1 < len) out[base + 1] = (word >>> 8) & 0xff;
      if (base + 2 < len) out[base + 2] = (word >>> 16) & 0xff;
      if (base + 3 < len) out[base + 3] = (word >>> 24) & 0xff;
    }
    return textDecoder.decode(out);
  }
}
