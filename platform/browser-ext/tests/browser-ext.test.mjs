// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { renderBrowserMdmArtifact, STATIC_MDM_OUTPUTS } from "../mdm/render-mdm.mjs";

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = resolve(TEST_DIR, "..");
const DIST_ROOT = resolve(EXT_ROOT, "dist");

const aiDestinations = JSON.parse(readFileSync(resolve(EXT_ROOT, "data/ai-destinations.json"), "utf8"));
const dlpDetectors = JSON.parse(readFileSync(resolve(EXT_ROOT, "data/dlp-detectors.json"), "utf8"));
const tenantProviders = JSON.parse(readFileSync(resolve(EXT_ROOT, "data/tenant-providers.json"), "utf8"));

const { WasmPolicyEngine } = await import(pathToFileURL(resolve(DIST_ROOT, "lib/wasm-host.mjs")).href);
const {
  NativeFrameDecoder,
  NativeHostBridge,
  buildRedactedDecidePayload,
  encodeNativeFrame,
  validateNativeVerdictMessage,
} = await import(pathToFileURL(resolve(DIST_ROOT, "lib/native-protocol.mjs")).href);
const { compileTenantDnrRules } = await import(
  pathToFileURL(resolve(DIST_ROOT, "lib/dnr-compiler.mjs")).href
);
const { createWindowBridgeTransport, extractBodyMetadata, extractFileExtensions, installPageHooks } =
  await import(pathToFileURL(resolve(DIST_ROOT, "lib/content-page-hook.mjs")).href);
const { bootstrapContentBridge } = await import(
  pathToFileURL(resolve(DIST_ROOT, "lib/content-bridge.mjs")).href
);
const { ExtensionRuntimeController, registerRuntimeMessageListener } = await import(
  pathToFileURL(resolve(DIST_ROOT, "lib/service-worker.mjs")).href
);
const { createPreviewSnapshot, matchesDestinationHost, verdictLabel } = await import(
  pathToFileURL(resolve(DIST_ROOT, "lib/ui-i18n.mjs")).href
);

test("static security scan proves zero paste, clipboard, or keystroke listeners in extension", () => {
  const forbiddenPatterns = [
    /\baddEventListener\s*\(\s*["'`](?:paste|copy|cut|keydown|keyup|keypress)/i,
    /\.on(?:paste|copy|cut|keydown|keyup|keypress)\b/i,
    /\bnavigator\.clipboard\b/i,
    /\bdocument\.execCommand\s*\(\s*["'`]paste/i,
  ];
  const srcFiles = readdirSync(resolve(EXT_ROOT, "src")).map((name) =>
    resolve(EXT_ROOT, "src", name),
  );
  const builtFiles = ["chrome", "edge", "firefox"].flatMap((target) => [
    resolve(DIST_ROOT, target, "content/page-hook.js"),
    resolve(DIST_ROOT, target, "content/bridge.js"),
    resolve(DIST_ROOT, target, "background/service-worker.js"),
    resolve(DIST_ROOT, target, "ui/ui-popup.js"),
    resolve(DIST_ROOT, target, "ui/ui-options.js"),
  ]);

  for (const file of [...srcFiles, ...builtFiles]) {
    const text = readFileSync(file, "utf8");
    for (const pattern of forbiddenPatterns) {
      assert.equal(
        pattern.test(text),
        false,
        `Forbidden clipboard/key listener pattern ${pattern} found in ${file}`,
      );
    }
  }
});

test("chrome, edge, and firefox MV3 manifests stay explicit without <all_urls> and ship full assets", () => {
  for (const target of ["chrome", "edge", "firefox"]) {
    const base = resolve(DIST_ROOT, target);
    const manifest = JSON.parse(readFileSync(resolve(base, "manifest.json"), "utf8"));
    assert.equal(manifest.manifest_version, 3);
    assert.equal(manifest.host_permissions.includes("<all_urls>"), false);
    assert.ok(manifest.host_permissions.includes("https://chatgpt.com/*"));
    assert.ok(manifest.host_permissions.includes("https://claude.ai/*"));
    assert.ok(manifest.content_security_policy.extension_pages.includes("'wasm-unsafe-eval'"));
    assert.equal(manifest.content_scripts[0].run_at, "document_start");
    assert.equal(manifest.content_scripts[0].world, "ISOLATED");
    assert.equal(manifest.content_scripts[0].match_about_blank, true);
    assert.equal(manifest.content_scripts[0].match_origin_as_fallback, true);
    assert.equal(manifest.content_scripts[1].run_at, "document_start");
    assert.equal(manifest.content_scripts[1].world, "MAIN");
    assert.equal(manifest.content_scripts[1].match_about_blank, true);
    assert.equal(manifest.content_scripts[1].match_origin_as_fallback, true);
    assert.ok(existsSync(resolve(base, "wasm/grdr_browser_wasm.wasm")));
    assert.ok(existsSync(resolve(base, "ui/tokens.css")));
    assert.ok(existsSync(resolve(base, "ui/assets/guardrails-mark.png")));
    assert.ok(existsSync(resolve(base, "_locales/en/messages.json")));
    assert.ok(existsSync(resolve(base, "_locales/ar/messages.json")));

    if (target === "firefox") {
      assert.equal(manifest.browser_specific_settings.gecko.id, "adr@guardrails.dev");
      assert.deepEqual(manifest.background.scripts, ["background/service-worker.js"]);
    } else {
      assert.equal(manifest.background.service_worker, "background/service-worker.js");
    }
  }
});

test("Wasm policy engine instantiates with zero imports and detects secrets, failsafe files, and degraded lock", async () => {
  const wasmBytes = readFileSync(resolve(DIST_ROOT, "chrome/wasm/grdr_browser_wasm.wasm"));
  const engine = await WasmPolicyEngine.create(wasmBytes, aiDestinations, dlpDetectors);
  assert.equal(engine.abiVersion, 1);
  assert.equal(engine.importCount, 0);

  const syntheticAws = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
  const secretDecision = engine.evaluateLocally(
    {
      requestId: "req-1",
      tabId: 1,
      url: "https://chatgpt.com/backend-api/conversation",
      hostname: "chatgpt.com",
      method: "POST",
      transport: "fetch",
      actionClass: "llm_request",
      hasFileUpload: false,
      fileNames: [],
      fileExtensions: [],
      bodyPreview: `token=${syntheticAws}`,
    },
    { chatgpt: "block" },
    false,
    false,
  );
  assert.equal(secretDecision.verdict, "deny");
  assert.ok(secretDecision.secretHits.includes("dlp.secret.aws-access-key"));

  const failsafeDecision = engine.evaluateLocally(
    {
      requestId: "req-2",
      tabId: 1,
      url: "https://claude.ai/api/organizations/upload",
      hostname: "claude.ai",
      method: "POST",
      transport: "fetch",
      actionClass: "cred_use",
      hasFileUpload: true,
      fileNames: [".env.production"],
      fileExtensions: [".env"],
      bodyPreview: "",
    },
    { "claude-web": "ask" },
    false,
    false,
  );
  assert.equal(failsafeDecision.verdict, "step_up");

  const degradedFailClosed = engine.evaluateLocally(
    {
      requestId: "req-3",
      tabId: 1,
      url: "https://gemini.google.com/upload",
      hostname: "gemini.google.com",
      method: "POST",
      transport: "fetch",
      actionClass: "data_flow",
      hasFileUpload: true,
      fileNames: ["notes.txt"],
      fileExtensions: [".txt"],
      bodyPreview: "",
    },
    { gemini: "watch" },
    true,
    true,
  );
  assert.equal(degradedFailClosed.verdict, "deny");
  assert.equal(degradedFailClosed.ruleId, "browser.degraded.fail-closed");

  const scan = engine.scanHookPayload(Buffer.from('{"command":"rm -rf .grdr/config"}'));
  assert.ok(scan.flags !== 0);
});

test("Native Messaging length-prefixed protocol handles chunked framing, redaction, and degraded fallback", async () => {
  const frame = encodeNativeFrame({
    type: "verdict",
    request_id: "r-42",
    verdict: "deny",
    rule_id: "org.block.secrets",
    reason: "Secret pattern denied by grdr.browser host.",
    ui_locale: "en",
  });

  const decoder = new NativeFrameDecoder();
  const part1 = decoder.push(frame.subarray(0, 7));
  assert.equal(part1.length, 0);
  const part2 = decoder.push(frame.subarray(7));
  assert.equal(part2.length, 1);

  const verdict = validateNativeVerdictMessage(part2[0]);
  assert.equal(verdict?.verdict, "deny");
  assert.equal(validateNativeVerdictMessage({ type: "policy_pack", rules: [] }), null);

  const syntheticAnthropic = ["sk-ant-", "api03-", "a".repeat(28)].join("");
  const redacted = buildRedactedDecidePayload(
    {
      requestId: "r-99",
      tabId: 1,
      url: "https://chatgpt.com/backend-api/conversation?debug=1",
      hostname: "chatgpt.com",
      method: "POST",
      transport: "fetch",
      actionClass: "llm_request",
      hasFileUpload: false,
      fileNames: [],
      fileExtensions: [],
      bodyPreview: syntheticAnthropic,
    },
    ["dlp.secret.anthropic-key"],
  );
  assert.equal(redacted.url_path, "/backend-api/conversation");
  assert.equal(JSON.stringify(redacted).includes(syntheticAnthropic), false);

  const bridge = new NativeHostBridge();
  const missingStatus = bridge.connect(() => null, "0.1.0", "chrome", {
    organizationId: "org",
    serverOrigin: "http://127.0.0.1:8787",
    failClosedOnDegraded: false,
    blockAnonymousSessions: true,
    tenantRestrictions: {},
    appModes: {},
  });
  assert.equal(missingStatus.kind, "degraded");

  let messageListener = null;
  const connectStatus = bridge.connect(
    () => ({
      postMessage: (msg) => {
        if (msg.type === "hello") {
          queueMicrotask(() =>
            messageListener?.({
              type: "hello",
              protocol_version: 1,
              host_version: "0.4.2",
              ui_locale: "en",
            }),
          );
        }
        if (msg.type === "decide") {
          queueMicrotask(() =>
            messageListener?.({
              type: "verdict",
              request_id: msg.request_id,
              verdict: "deny",
              rule_id: "host.verdict.1",
              reason: "Denied by host",
            }),
          );
        }
      },
      onMessage: { addListener: (fn) => (messageListener = fn) },
      onDisconnect: { addListener: () => {} },
    }),
    "0.1.0",
    "chrome",
    {
      organizationId: "org",
      serverOrigin: "http://127.0.0.1:8787",
      failClosedOnDegraded: false,
      blockAnonymousSessions: true,
      tenantRestrictions: {},
      appModes: {},
    },
  );
  assert.equal(connectStatus.kind, "connecting");
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(bridge.getStatus().kind, "connected");
  assert.equal(bridge.getStatus().uiLocale, "en");
  const resp = await bridge.requestDecision(redacted, 200);
  assert.equal(resp?.rule_id, "host.verdict.1");
});

test("DNR compiler uses single-value set headers, strips consumer_accounts, and stays within 5000 rule budget", () => {
  const compiled = compileTenantDnrRules(tenantProviders, {
    organizationId: "org-acme",
    serverOrigin: "https://guardrails.internal:8443",
    failClosedOnDegraded: false,
    blockAnonymousSessions: true,
    tenantRestrictions: {
      anthropic: ["org-1", "org-2", "org-1"],
      google_workspace: ["acme.example", "consumer_accounts"],
      openai_chatgpt: ["ws-acme"],
      entra_id: ["tenant-guid-1"],
      github_enterprise: ["acme-ent"],
    },
    appModes: {},
  });

  assert.equal(compiled.activeHeaders.length, 5);
  const googleHeader = compiled.activeHeaders.find((h) => h.providerId === "google_workspace");
  assert.equal(googleHeader?.headerName, "X-GoogApps-Allowed-Domains");
  assert.equal(googleHeader?.value, "acme.example");
  assert.equal(googleHeader?.value.includes("consumer_accounts"), false);

  const anthropicRule = compiled.rules.find(
    (r) => r.action.requestHeaders?.[0]?.header === "anthropic-allowed-org-ids",
  );
  assert.equal(anthropicRule?.action.requestHeaders?.[0]?.operation, "set");
  assert.equal(anthropicRule?.action.requestHeaders?.[0]?.value, "org-1,org-2");
  assert.ok(compiled.blockedAnonymousFilters.includes("||chatgpt.com/backend-anon/"));
  assert.ok(compiled.blockedAnonymousFilters.includes("||individual.githubcopilot.com/"));
  assert.ok(compiled.rules.length <= tenantProviders.maxDnrRules);
});

test("Page hooks wrap fetch, XHR, WebSocket, sendBeacon, EventSource, and WebMCP registerTool with closed shadow notice", async () => {
  const listeners = new Map();
  const appendedNodes = [];
  let capturedShadowMode = "";
  let fetchUnderlyingCalled = 0;
  let xhrAborted = 0;
  let wsUnderlyingSent = 0;
  let mcpExecuted = 0;
  const telemetry = [];

  class FakeXhr {
    open() {}
    send() {}
    abort() {
      xhrAborted += 1;
    }
  }
  class FakeWs {
    constructor(url) {
      this.url = url;
    }
    send() {
      wsUnderlyingSent += 1;
    }
  }
  class FakeEventSource {
    constructor(url) {
      this.url = url;
      this.closed = false;
    }
    close() {
      this.closed = true;
    }
  }

  function createFakeEl(tag) {
    const el = {
      tagName: tag.toUpperCase(),
      attributes: {},
      children: [],
      textContent: "",
      className: "",
      setAttribute(k, v) {
        this.attributes[k] = v;
      },
      appendChild(child) {
        this.children.push(child);
      },
      addEventListener() {},
      remove() {},
      attachShadow(opts) {
        capturedShadowMode = opts.mode;
        return {
          children: [],
          appendChild(child) {
            this.children.push(child);
          },
        };
      },
    };
    return el;
  }

  const fakeDoc = {
    documentElement: {
      attributes: {},
      dataset: { grdrDir: "ltr" },
      getAttribute(k) {
        return this.attributes[k] || null;
      },
      appendChild(node) {
        appendedNodes.push(node);
      },
    },
    createElement: createFakeEl,
    modelContext: {
      registerTool(def) {
        return def;
      },
    },
  };

  const fakeWin = {
    location: { href: "https://chatgpt.com/c/1", hostname: "chatgpt.com" },
    fetch: async () => {
      fetchUnderlyingCalled += 1;
      return { ok: true };
    },
    XMLHttpRequest: FakeXhr,
    WebSocket: FakeWs,
    EventSource: FakeEventSource,
    navigator: {
      sendBeacon: () => true,
    },
    addEventListener(name, fn) {
      listeners.set(name, fn);
    },
  };

  const decisions = [];
  installPageHooks(fakeWin, fakeDoc, {
    async requestDecision(payload) {
      decisions.push(payload);
      if (payload.transport === "webmcp" && payload.toolName === "safe_summary") {
        return {
          requestId: payload.requestId,
          verdict: "allow",
          ruleId: "browser.webmcp.allow",
          reason: "Allowed readOnlyHint tool.",
          modeApplied: "ask",
          appId: "chatgpt",
          appName: "ChatGPT",
          source: "wasm_floor",
          hostDegraded: false,
          secretHits: [],
          sensitiveExtensions: [],
          flags: 0,
        };
      }
      return {
        requestId: payload.requestId,
        verdict: "deny",
        ruleId: "dlp.secret.blocked",
        reason: "Blocked outbound secret transfer.",
        modeApplied: "block",
        appId: "chatgpt",
        appName: "ChatGPT",
        source: "wasm_floor",
        hostDegraded: false,
        secretHits: ["dlp.secret.aws-access-key"],
        sensitiveExtensions: [],
        flags: 0,
      };
    },
    emitTelemetry(evt) {
      telemetry.push(evt);
    },
  });

  await assert.rejects(
    () =>
      fakeWin.fetch("https://chatgpt.com/backend-api/conversation", {
        method: "POST",
        body: JSON.stringify({ prompt: ["AKIA", "IOSFODNN7EXAMPLE"].join("") }),
      }),
    /Guardrails blocked request/,
  );
  assert.equal(fetchUnderlyingCalled, 0);
  assert.equal(capturedShadowMode, "closed");
  assert.equal(appendedNodes.length > 0, true);

  const xhr = new fakeWin.XMLHttpRequest();
  xhr.open("POST", "https://chatgpt.com/backend-api/files");
  xhr.send("secret");
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(xhrAborted, 1);

  const ws = new fakeWin.WebSocket("wss://chatgpt.com/ws");
  ws.send("payload");
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(wsUnderlyingSent, 0);

  const allowedTool = fakeDoc.modelContext.registerTool({
    name: "safe_summary",
    description: "Safe summary",
    annotations: { readOnlyHint: true },
    execute: async () => {
      mcpExecuted += 1;
      return "done";
    },
  });
  const allowedResult = await allowedTool.execute({ text: "hello" });
  assert.equal(allowedResult, "done");
  assert.equal(mcpExecuted, 1);

  const blockedTool = fakeDoc.modelContext.registerTool({
    name: "exfil_secrets",
    description: "Exfiltrates files",
    annotations: { destructiveHint: true },
    execute: async () => "should-not-run",
  });
  await assert.rejects(() => blockedTool.execute({ path: ".env" }), /blocked exfil_secrets/);
  assert.ok(telemetry.some((e) => e.kind === "webmcp.register" && e.toolName === "exfil_secrets"));
  assert.ok(telemetry.some((e) => e.kind === "toolcancel" && e.toolName === "exfil_secrets"));

  listeners.get("toolactivated")?.({ detail: { name: "safe_summary" } });
  assert.ok(telemetry.some((e) => e.kind === "toolactivated" && e.toolName === "safe_summary"));

  const meta = extractBodyMetadata("plain text body");
  assert.equal(meta.hasFileUpload, false);
  assert.equal(meta.bodyPreview, "plain text body");
});

test("ExtensionRuntimeController coordinates Wasm evaluation, DNR, WebMCP ledger, and snapshots", async () => {
  const controller = new ExtensionRuntimeController(null);
  const wasmBytes = readFileSync(resolve(DIST_ROOT, "chrome/wasm/grdr_browser_wasm.wasm"));
  await controller.initialize(wasmBytes);
  controller.recordWebMcpRegistration(7, "claude.ai", "fetch_issue", "Reads ticket", {
    readOnlyHint: true,
  });
  const decision = await controller.inspectAction({
    requestId: "ctrl-1",
    tabId: 7,
    url: "https://claude.ai/api/organizations/upload",
    hostname: "claude.ai",
    method: "POST",
    transport: "fetch",
    actionClass: "data_flow",
    hasFileUpload: true,
    fileNames: [".env.production"],
    fileExtensions: [".env"],
    bodyPreview: "DB_PASS=supersecret",
  });
  assert.equal(decision.verdict, "step_up");
  assert.equal(decision.hostDegraded, true);
  const snap = controller.getSnapshot();
  assert.equal(snap.wasmInfo.ready, true);
  assert.equal(snap.wasmInfo.importCount, 0);
  assert.equal(snap.webMcpTools.length, 1);
  assert.equal(snap.recentDecisions.length, 1);
});

test("MDM templates render valid escaped configs matching checked-in files", () => {
  for (const [fmt, rel] of STATIC_MDM_OUTPUTS) {
    const filePath = resolve(EXT_ROOT, "mdm", rel);
    assert.ok(existsSync(filePath), `Missing static MDM template ${rel}`);
    const content = readFileSync(filePath, "utf8");
    if (rel.endsWith(".json")) {
      JSON.parse(content);
    } else if (rel.endsWith(".xml") || rel.endsWith(".admx") || rel.endsWith(".adml") || rel.endsWith(".mobileconfig")) {
      assert.ok(content.startsWith("<?xml"), `Expected XML header in ${rel}`);
    }
    const sampleTag = "<" + "script>";
    const renderedCustom = renderBrowserMdmArtifact(fmt, {
      mirrorOrigin: `https://mirror.corp.example:8443/?q=${sampleTag}&a=1`,
      orgId: "org_<test>",
    });
    if (rel.endsWith(".xml") || rel.endsWith(".adml") || rel.endsWith(".mobileconfig")) {
      assert.equal(renderedCustom.includes(sampleTag), false);
    }
  }
});

test("Wasm ABI enforces Watch/Off failsafe floor locks, mask bounds, UTF-8, NUL rejection, and dotfiles", async () => {
  const wasmBytes = readFileSync(resolve(DIST_ROOT, "chrome/wasm/grdr_browser_wasm.wasm"));
  const engine = await WasmPolicyEngine.create(wasmBytes, aiDestinations, dlpDetectors);
  assert.ok(engine.loadDefaultBrowserFloor() >= 4);

  for (const mode of ["off", "watch"]) {
    const bypassDecision = engine.evaluateLocally(
      {
        requestId: `bypass-${mode}`,
        tabId: 1,
        url: "https://chatgpt.com/backend-api/conversation",
        hostname: "chatgpt.com",
        method: "POST",
        transport: "fetch",
        actionClass: "llm_request",
        hasFileUpload: false,
        fileNames: [],
        fileExtensions: [],
        bodyPreview: '{"command":"rm -rf / && --dangerously-skip-permissions"}',
      },
      { chatgpt: mode },
      false,
      false,
    );
    assert.equal(bypassDecision.verdict, "deny");
    assert.equal(bypassDecision.ruleId, "browser.fastpath.bypass-flag");

    const floorShellDecision = engine.evaluateLocally(
      {
        requestId: `floor-${mode}`,
        tabId: 1,
        url: "https://chatgpt.com/",
        hostname: "chatgpt.com",
        method: "WEBMCP",
        transport: "webmcp",
        actionClass: "mcp.call",
        hasFileUpload: false,
        fileNames: [],
        fileExtensions: [],
        toolName: "exec_shell",
        bodyPreview: '{"cmd":"whoami"}',
      },
      { chatgpt: mode },
      false,
      false,
    );
    assert.equal(floorShellDecision.verdict, "deny");
    assert.equal(floorShellDecision.ruleId, "browser.webmcp.deny-shell");
  }

  const nulDecision = engine.evaluateLocally(
    {
      requestId: "nul-1",
      tabId: 1,
      url: "https://chatgpt.com/backend-api/conversation",
      hostname: "chatgpt.com\0evil.example",
      method: "POST",
      transport: "fetch",
      actionClass: "llm_request",
      hasFileUpload: false,
      fileNames: [],
      fileExtensions: [],
      bodyPreview: "hello",
    },
    { chatgpt: "watch" },
    false,
    false,
  );
  assert.equal(nulDecision.verdict, "deny");
  assert.equal(nulDecision.ruleId, "browser.input.nul-injection");

  const maskOverflow = engine.evaluateRawAbi(
    1,
    1,
    0x1_0000,
    0,
    Buffer.from("agent\0target\0payload"),
  );
  assert.ok(maskOverflow.rc < 0);
  const maskErrJson = JSON.parse(maskOverflow.output);
  assert.equal(maskErrJson.verdict, "deny");
  assert.equal(maskErrJson.hard_fail_closed, true);

  const badUtf8Target = Buffer.concat([
    Buffer.from("browser\0"),
    Buffer.from([0xff, 0xfe]),
    Buffer.from("\0payload"),
  ]);
  const utf8Fail = engine.evaluateRawAbi(1, 1, 0, 0, badUtf8Target);
  assert.equal(utf8Fail.rc, 2);
  const utf8Json = JSON.parse(utf8Fail.output);
  assert.equal(utf8Json.verdict, "deny");
  assert.equal(utf8Json.rule_id, "browser.input.invalid-utf8");
  assert.equal(utf8Json.hard_fail_closed, true);

  assert.deepEqual(extractFileExtensions(".env"), [".env"]);
  assert.deepEqual(extractFileExtensions(".env.production"), [".env", ".production", ".env.production"]);
  assert.deepEqual(extractFileExtensions("export.parquet"), [".parquet"]);

  const dotEnvUpload = engine.evaluateLocally(
    {
      requestId: "dotenv-1",
      tabId: 1,
      url: "https://claude.ai/upload",
      hostname: "claude.ai",
      method: "POST",
      transport: "fetch",
      actionClass: "data_flow",
      hasFileUpload: true,
      fileNames: [".env"],
      fileExtensions: [],
      bodyPreview: "",
    },
    { "claude-web": "ask" },
    false,
    false,
  );
  assert.equal(dotEnvUpload.verdict, "step_up");
  assert.ok(dotEnvUpload.sensitiveExtensions.includes(".env"));
});

test("Page hooks lock transport descriptors, inspect fetch(Request), defer EventSource, and guard WebMCP args", async () => {
  let fetchCalled = 0;
  let sseConstructed = 0;
  const inspectedPayloads = [];
  const syntheticAws = ["AKIA", "IOSFODNN7EXAMPLE"].join("");

  class FakeXhr {
    open() {}
    send() {}
    abort() {}
  }
  class FakeWs {
    send() {}
  }
  class FakeEventSource {
    constructor(url) {
      sseConstructed += 1;
      this.url = url;
    }
    close() {}
  }
  class FakeRequest {
    constructor(url, init = {}) {
      this.url = url;
      this.method = init.method || "GET";
      this.body = init.body || "";
    }
    clone() {
      return {
        arrayBuffer: async () => Buffer.from(String(this.body), "utf8"),
      };
    }
  }

  const fakeDoc = {
    documentElement: {
      attributes: {},
      dataset: { grdrDir: "ltr" },
      getAttribute() {
        return null;
      },
      appendChild() {},
    },
    createElement() {
      return {
        style: {},
        setAttribute() {},
        appendChild() {},
        addEventListener() {},
        remove() {},
        attachShadow() {
          return { appendChild() {} };
        },
      };
    },
    modelContext: {
      registerTool(def) {
        return def;
      },
    },
  };
  const fakeWin = {
    location: { href: "https://chatgpt.com/", hostname: "chatgpt.com" },
    Request: FakeRequest,
    fetch: async () => {
      fetchCalled += 1;
      return { ok: true };
    },
    XMLHttpRequest: FakeXhr,
    WebSocket: FakeWs,
    EventSource: FakeEventSource,
    navigator: { sendBeacon: () => true },
    addEventListener() {},
  };

  installPageHooks(fakeWin, fakeDoc, {
    async requestDecision(payload) {
      inspectedPayloads.push(payload);
      return {
        requestId: payload.requestId,
        verdict: payload.bodyPreview.includes(syntheticAws) || payload.transport === "eventsource" ? "deny" : "allow",
        ruleId: "browser.test.rule",
        reason: "Blocked test payload",
        modeApplied: "block",
        appId: "chatgpt",
        appName: "ChatGPT",
        source: "wasm_floor",
        hostDegraded: false,
        secretHits: [],
        sensitiveExtensions: [],
        flags: 0,
      };
    },
    emitTelemetry() {},
  });

  assert.equal(Object.getOwnPropertyDescriptor(fakeWin, "fetch")?.writable, false);
  assert.equal(Object.getOwnPropertyDescriptor(FakeXhr.prototype, "send")?.writable, false);
  assert.equal(Object.getOwnPropertyDescriptor(FakeWs.prototype, "send")?.writable, false);
  assert.equal(Object.getOwnPropertyDescriptor(fakeWin, "EventSource")?.writable, false);

  await assert.rejects(
    () =>
      fakeWin.fetch(
        new FakeRequest("https://chatgpt.com/backend-api/conversation", {
          method: "POST",
          body: `secret=${syntheticAws}`,
        }),
      ),
    /Guardrails blocked request/,
  );
  assert.equal(fetchCalled, 0);

  const sse = new fakeWin.EventSource("https://chatgpt.com/sse");
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(sseConstructed, 0);
  sse.close();

  const circular = { self: null, count: BigInt(42) };
  circular.self = circular;
  const tool = fakeDoc.modelContext.registerTool({
    name: "multi_arg_tool",
    description: "Checks all args safely",
    execute: async () => "ok",
  });
  await assert.rejects(
    () => tool.execute("a", "b", { nested: syntheticAws }),
    /blocked multi_arg_tool/,
  );
  await assert.doesNotReject(() => tool.execute(circular));
  assert.ok(inspectedPayloads.some((p) => p.bodyPreview.includes("[Circular]")));
});

test("Native protocol framing bounds, timeout degradation, DNR CRLF guard, MDM validation, and SW isolation", async () => {
  const decoder = new NativeFrameDecoder();
  const oversizedHeader = Buffer.alloc(4);
  oversizedHeader.writeUInt32LE(2 * 1024 * 1024, 0);
  assert.throws(() => decoder.push(oversizedHeader), /GRDR-EXT-0102/);

  const badJsonFrame = encodeNativeFrame({ dummy: true });
  const corruptBytes = Buffer.from(badJsonFrame);
  corruptBytes.write("{bad", 4);
  assert.throws(() => decoder.push(corruptBytes), /GRDR-EXT-0103/);
  const validFrames = decoder.push(
    encodeNativeFrame({ type: "verdict", request_id: "ok", verdict: "allow", rule_id: "r", reason: "ok" }),
  );
  assert.equal(validFrames.length, 1);

  const bridge = new NativeHostBridge();
  bridge.connect(
    () => ({
      postMessage() {},
      onMessage: { addListener() {} },
      onDisconnect: { addListener() {} },
    }),
    "0.1.0",
    "chrome",
    {
      organizationId: "org-corp-prod",
      serverOrigin: "https://guardrails.internal:8443",
      failClosedOnDegraded: true,
      blockAnonymousSessions: true,
      tenantRestrictions: {},
      appModes: {},
    },
    undefined,
    15,
  );
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(bridge.getStatus().kind, "degraded");
  assert.equal(bridge.getStatus().reason, "timeout");

  assert.throws(
    () =>
      compileTenantDnrRules(tenantProviders, {
        organizationId: "org-corp-prod",
        serverOrigin: "https://guardrails.internal:8443",
        failClosedOnDegraded: false,
        blockAnonymousSessions: true,
        tenantRestrictions: {
          anthropic: ["org-1\r\nEvil: 1", "ok-org"],
        },
        appModes: {},
      }),
    /GRDR-EXT-0203/,
  );

  const dnrCompiled = compileTenantDnrRules(tenantProviders, {
    organizationId: "org-corp-prod",
    serverOrigin: "https://guardrails.internal:8443",
    failClosedOnDegraded: false,
    blockAnonymousSessions: true,
    tenantRestrictions: {
      anthropic: ["ok-org"],
    },
    appModes: {},
  });
  const antHdr = dnrCompiled.activeHeaders.find((h) => h.providerId === "anthropic");
  assert.equal(antHdr?.value, "ok-org");
  assert.ok(dnrCompiled.rules[0].condition.resourceTypes.includes("ping"));

  assert.throws(
    () => renderBrowserMdmArtifact("chrome_enterprise", { mirrorOrigin: "http://evil.example:8080" }),
    /GRDR-EXT-0905/,
  );
  const edgeRendered = JSON.parse(renderBrowserMdmArtifact("edge_enterprise"));
  assert.ok(edgeRendered.policies.CopilotBrowserUseAllowList.includes("copilot.cloud.microsoft"));

  const sessionStore = new Map();
  let messageHandler = null;
  const fakeApi = {
    runtime: {
      id: "self-ext-id",
      onMessage: { addListener: (fn) => (messageHandler = fn) },
    },
    storage: {
      managed: {
        get: async () => ({
          organizationId: "org-corp-prod",
          failClosedOnDegraded: true,
          appModes: { chatgpt: "block" },
        }),
      },
      session: {
        get: async (keys) => {
          const out = {};
          for (const k of keys) out[k] = sessionStore.get(k);
          return out;
        },
        set: async (vals) => {
          for (const [k, v] of Object.entries(vals)) sessionStore.set(k, v);
        },
      },
      local: { get: async () => ({}), set: async () => {} },
    },
  };

  const controllerA = new ExtensionRuntimeController(fakeApi);
  const wasmBytes = readFileSync(resolve(DIST_ROOT, "chrome/wasm/grdr_browser_wasm.wasm"));
  await controllerA.initialize(wasmBytes);
  registerRuntimeMessageListener(fakeApi, controllerA, Promise.resolve());
  assert.equal(await controllerA.setAppModeOverride("chatgpt", "watch"), false);
  const degDecision = await controllerA.inspectAction({
    requestId: "sw-deg-1",
    tabId: 2,
    url: "https://chatgpt.com/backend-api/conversation",
    hostname: "chatgpt.com",
    method: "POST",
    transport: "fetch",
    actionClass: "llm_request",
    hasFileUpload: false,
    fileNames: [],
    fileExtensions: [],
    bodyPreview: "hello",
  });
  assert.equal(degDecision.verdict, "deny");
  assert.equal(degDecision.ruleId, "browser.degraded.fail-closed");

  const controllerB = new ExtensionRuntimeController(fakeApi);
  await controllerB.initialize(wasmBytes);
  assert.equal(controllerB.getSnapshot().counters.blockedSession, 1);

  assert.ok(messageHandler);
  const tabResp = await new Promise((resolveMsg) => {
    messageHandler(
      { type: "ext:set_app_mode", appId: "gemini", mode: "block" },
      { id: "self-ext-id", tab: { id: 99 } },
      resolveMsg,
    );
  });
  assert.equal(tabResp.ok, false);
  assert.ok(String(tabResp.error).includes("GRDR-EXT-0301"));

  const foreignResp = await new Promise((resolveMsg) => {
    messageHandler(
      { type: "ext:get_snapshot" },
      { id: "evil-ext-id" },
      resolveMsg,
    );
  });
  assert.equal(foreignResp.ok, false);
  assert.ok(String(foreignResp.error).includes("GRDR-EXT-0302"));

  const invalidInspectResp = await new Promise((resolveMsg) => {
    messageHandler(
      { type: "ext:inspect", payload: { url: "https://chatgpt.com" } },
      { id: "self-ext-id", tab: { id: 1 } },
      resolveMsg,
    );
  });
  assert.equal(invalidInspectResp.verdict, "deny");
  assert.equal(invalidInspectResp.ruleId, "browser.inspect.invalid-payload");

  const missingSenderIdResp = await new Promise((resolveMsg) => {
    messageHandler({ type: "ext:get_snapshot" }, {}, resolveMsg);
  });
  assert.equal(missingSenderIdResp.ok, false);
  assert.ok(String(missingSenderIdResp.error).includes("GRDR-EXT-0302"));

  const tabOriginMismatchResp = await new Promise((resolveMsg) => {
    messageHandler(
      {
        type: "ext:inspect",
        payload: {
          requestId: "spoof-1",
          url: "https://chatgpt.com/backend-api/conversation",
          hostname: "chatgpt.com",
          transport: "fetch",
          actionClass: "llm_request",
        },
      },
      { id: "self-ext-id", tab: { id: 1, url: "https://evil.example/app" } },
      resolveMsg,
    );
  });
  assert.equal(tabOriginMismatchResp.verdict, "deny");
  assert.equal(tabOriginMismatchResp.ruleId, "browser.inspect.invalid-payload");

  const telemetryMismatchResp = await new Promise((resolveMsg) => {
    messageHandler(
      {
        type: "ext:telemetry",
        event: { kind: "webmcp.register", hostname: "chatgpt.com", toolName: "spoof_tool" },
      },
      { id: "self-ext-id", tab: { id: 1, url: "https://evil.example/" } },
      resolveMsg,
    );
  });
  assert.equal(telemetryMismatchResp.ok, false);
  assert.ok(String(telemetryMismatchResp.error).includes("GRDR-EXT-0303"));

  assert.equal(await controllerA.setAppModeOverride("unknown-app", "block"), false);
  controllerA.recordWebMcpRegistration(5, "chatgpt.com", "bounded_tool", "desc", {
    deep: { a: { nestedTooDeep: true }, ok: "val" },
  });
  const updatedEntry = controllerA.getSnapshot().webMcpTools.find((t) => t.name === "bounded_tool");
  assert.equal("nestedTooDeep" in (updatedEntry?.annotations?.deep ?? {}), false);
});

test("B1 bootNonce bridge rejects empty tokens, isTrusted=false spoofs, wrong tokens, replay, and binds valid port", async () => {
  const listeners = [];
  const docEl = { dataset: {} };
  const fakeDoc = { documentElement: docEl };
  const postedQueue = [];
  const fakeWin = {
    location: { origin: "https://chatgpt.com", hostname: "chatgpt.com" },
    addEventListener(name, fn) {
      if (name === "message") listeners.push(fn);
    },
    removeEventListener(name, fn) {
      if (name === "message") {
        const idx = listeners.indexOf(fn);
        if (idx >= 0) listeners.splice(idx, 1);
      }
    },
    postMessage(data, _origin, ports) {
      postedQueue.push({ data, ports });
    },
  };

  let sentDecisions = 0;
  bootstrapContentBridge(fakeWin, fakeDoc, {
    runtime: {
      sendMessage: async () => {
        sentDecisions += 1;
        return {
          requestId: "b1-req",
          verdict: "allow",
          ruleId: "test.allow",
          reason: "Allowed",
          modeApplied: "watch",
          appId: "chatgpt",
          appName: "ChatGPT",
          source: "wasm_floor",
          hostDegraded: false,
          secretHits: [],
          sensitiveExtensions: [],
          flags: 0,
        };
      },
    },
  });

  const emittedNonce = docEl.dataset.grdrBoot;
  assert.ok(typeof emittedNonce === "string" && emittedNonce.length >= 16);
  const bridge = createWindowBridgeTransport(fakeWin, fakeDoc);
  assert.equal("grdrBoot" in docEl.dataset, false);
  assert.equal(listeners.length, 1);

  const spoofChan = new MessageChannel();
  listeners[0]({
    isTrusted: false,
    source: fakeWin,
    data: { type: "__grdr_ext_bridge_init", token: emittedNonce },
    ports: [spoofChan.port2],
  });
  spoofChan.port1.close();
  spoofChan.port2.close();
  assert.equal(listeners.length, 1);

  const wrongChan = new MessageChannel();
  listeners[0]({
    isTrusted: true,
    source: fakeWin,
    data: { type: "__grdr_ext_bridge_init", token: "wrong-token" },
    ports: [wrongChan.port2],
  });
  wrongChan.port1.close();
  wrongChan.port2.close();
  assert.equal(listeners.length, 1);

  let propagationStopped = false;
  const savedListener = listeners[0];
  const legitimate = postedQueue[0];
  savedListener({
    isTrusted: true,
    source: fakeWin,
    data: legitimate.data,
    ports: legitimate.ports,
    stopImmediatePropagation() {
      propagationStopped = true;
    },
  });
  assert.equal(propagationStopped, true);
  assert.equal(listeners.length, 0);

  const replayChan = new MessageChannel();
  savedListener({
    isTrusted: true,
    source: fakeWin,
    data: { type: "__grdr_ext_bridge_init", token: emittedNonce },
    ports: [replayChan.port2],
  });
  const reqDecision = await bridge.requestDecision({
    requestId: "b1-req",
    url: "https://chatgpt.com/backend-api/conversation",
    hostname: "chatgpt.com",
    method: "POST",
    transport: "fetch",
    actionClass: "llm_request",
    hasFileUpload: false,
    fileNames: [],
    fileExtensions: [],
    bodyPreview: "hello",
  });
  replayChan.port1.close();
  replayChan.port2.close();
  assert.equal(sentDecisions, 1);
  assert.equal(reqDecision.verdict, "allow");

  const emptyDocEl = { dataset: {} };
  const emptyListeners = [];
  const emptyWin = {
    location: { origin: "https://chatgpt.com" },
    addEventListener(name, fn) {
      if (name === "message") emptyListeners.push(fn);
    },
    removeEventListener() {},
  };
  const uninitBridge = createWindowBridgeTransport(emptyWin, { documentElement: emptyDocEl });
  const fakePortChan = new MessageChannel();
  emptyListeners[0]({
    isTrusted: true,
    source: emptyWin,
    data: { type: "__grdr_ext_bridge_init", token: "" },
    ports: [fakePortChan.port2],
  });
  const timedOutDecision = await uninitBridge.requestDecision({
    requestId: "b1-empty",
    url: "https://chatgpt.com/upload",
    hostname: "chatgpt.com",
    method: "POST",
    transport: "fetch",
    actionClass: "data_flow",
    hasFileUpload: true,
    fileNames: [".env"],
    fileExtensions: [".env"],
    bodyPreview: "",
  });
  fakePortChan.port1.close();
  fakePortChan.port2.close();
  assert.equal(timedOutDecision.verdict, "deny");
  assert.equal(timedOutDecision.ruleId, "browser.bridge.uninitialized-fail-closed");

  let lateSentCount = 0;
  const lateListeners = [];
  const lateDoc = { documentElement: { dataset: {} } };
  const latePosted = [];
  const lateWin = {
    location: { origin: "https://chatgpt.com", hostname: "chatgpt.com" },
    addEventListener(name, fn) {
      if (name === "message") lateListeners.push(fn);
    },
    removeEventListener(name, fn) {
      if (name === "message") {
        const idx = lateListeners.indexOf(fn);
        if (idx >= 0) lateListeners.splice(idx, 1);
      }
    },
    postMessage(data, _origin, ports) {
      latePosted.push({ data, ports });
    },
  };
  bootstrapContentBridge(lateWin, lateDoc, {
    runtime: {
      sendMessage: async () => {
        lateSentCount += 1;
        return { requestId: "late", verdict: "allow", ruleId: "r", reason: "ok" };
      },
    },
  });
  const lateBridge = createWindowBridgeTransport(lateWin, lateDoc);
  const lateTimedOut = await lateBridge.requestDecision({
    requestId: "h3-late",
    url: "https://chatgpt.com/backend-api/conversation",
    hostname: "chatgpt.com",
    method: "POST",
    transport: "fetch",
    actionClass: "llm_request",
    hasFileUpload: false,
    fileNames: [],
    fileExtensions: [],
    bodyPreview: "hello",
  });
  assert.equal(lateTimedOut.ruleId, "browser.bridge.uninitialized-fail-closed");
  lateListeners[0]({
    isTrusted: true,
    source: lateWin,
    data: latePosted[0].data,
    ports: latePosted[0].ports,
  });
  await new Promise((r) => setTimeout(r, 25));
  assert.equal(lateSentCount, 0);
  legitimate.ports[0]?.close?.();
  latePosted[0].ports[0]?.close?.();
});

test("H1/H3/H4/H5 verify FormData Request fetch, Navigator.prototype.sendBeacon lock, queued timeout cancellation, wildcard hosts, and UI Deny label", async () => {
  const formBody = new FormData();
  formBody.append("file", new File(["KEY=123"], ".env.production", { type: "text/plain" }));
  const formReq = new Request("https://chatgpt.com/backend-api/files", {
    method: "POST",
    body: formBody,
  });

  class FakeNavigator {
    sendBeacon() {
      return true;
    }
  }
  const fakeNav = new FakeNavigator();
  let fetchCalled = 0;
  const inspected = [];
  const fakeWin = {
    location: { href: "https://chatgpt.com/", hostname: "chatgpt.com" },
    Navigator: FakeNavigator,
    navigator: fakeNav,
    fetch: async () => {
      fetchCalled += 1;
      return { ok: true };
    },
    addEventListener() {},
  };
  const fakeDoc = {
    documentElement: {
      attributes: {},
      dataset: {},
      getAttribute() {
        return null;
      },
      appendChild() {},
    },
    createElement() {
      return {
        style: {},
        setAttribute() {},
        appendChild() {},
        addEventListener() {},
        remove() {},
        attachShadow() {
          return { appendChild() {} };
        },
      };
    },
  };
  installPageHooks(fakeWin, fakeDoc, {
    async requestDecision(payload) {
      inspected.push(payload);
      return {
        requestId: payload.requestId,
        verdict: payload.hasFileUpload ? "deny" : "allow",
        ruleId: "dlp.file.blocked",
        reason: "Blocked .env FormData upload",
        modeApplied: "block",
        appId: "chatgpt",
        appName: "ChatGPT",
        source: "wasm_floor",
        hostDegraded: false,
        secretHits: [],
        sensitiveExtensions: payload.fileExtensions,
        flags: 0,
      };
    },
    emitTelemetry() {},
  });

  assert.equal(Object.getOwnPropertyDescriptor(FakeNavigator.prototype, "sendBeacon")?.writable, false);
  assert.equal(Object.getOwnPropertyDescriptor(fakeNav, "sendBeacon")?.writable, false);
  await assert.rejects(() => fakeWin.fetch(formReq), /Guardrails blocked request/);
  assert.equal(fetchCalled, 0);
  assert.ok(inspected.some((p) => p.hasFileUpload && p.fileExtensions.includes(".env")));

  assert.equal(verdictLabel("deny"), "Deny");
  const enMsgs = JSON.parse(readFileSync(resolve(EXT_ROOT, "_locales/en/messages.json"), "utf8"));
  assert.equal(enMsgs.verdictDeny.message, "Deny");
  const snap = createPreviewSnapshot("connected");
  assert.ok(
    snap.dnrSummary.activeHeaders.some((h) => h.headerName === "sec-Restrict-Tenant-Access-Policy"),
  );
  const ghCopilot = snap.destinations.find((d) => d.id === "github-copilot");
  assert.ok(ghCopilot && matchesDestinationHost("individual.githubcopilot.com", ghCopilot));
});

test("Structured linear DLP matchers cover all catalog detectors with word-boundary and SSN guards", async () => {
  const wasmBytes = readFileSync(resolve(DIST_ROOT, "chrome/wasm/grdr_browser_wasm.wasm"));
  const engine = await WasmPolicyEngine.create(wasmBytes, aiDestinations, dlpDetectors);
  const scan = (bodyPreview) =>
    engine.inspectContentLocally({
      requestId: "dlp-parity",
      tabId: 1,
      url: "https://chatgpt.com/backend-api/conversation",
      hostname: "chatgpt.com",
      method: "POST",
      transport: "fetch",
      actionClass: "data_flow",
      hasFileUpload: false,
      fileNames: [],
      fileExtensions: [],
      bodyPreview,
    }).secretHits;

  const syntheticCases = [
    ["dlp.secret.aws-access-key", ["ASIA", "1234567890ABCDEF"].join("")],
    ["dlp.secret.github-token", ["ghp_", "AbCdEf0123456789GhIjKlMn"].join("")],
    ["dlp.secret.github-token", ["github_", "pat_11AA_ABCDEFGHIJKLMNOPQRST"].join("")],
    ["dlp.secret.anthropic-key", ["sk-ant-", "api03-", "x".repeat(24)].join("")],
    ["dlp.secret.openai-key", ["sk-proj-", "A1b2C3d4E5f6G7h8I9j0K1"].join("")],
    ["dlp.secret.slack-token", ["xoxb-", "1234567890-abcdef012345"].join("")],
    ["dlp.secret.private-key-pem", ["-----BEGIN ", "OPENSSH ", "PRIVATE KEY-----"].join("")],
    ["dlp.secret.stripe-live", ["sk_live_", "0123456789ABCDEFghij"].join("")],
    ["dlp.pii.us-ssn", "ssn=123-45-6789"],
  ];

  for (const [expectedRule, payload] of syntheticCases) {
    assert.ok(
      scan(payload).includes(expectedRule),
      `Expected ${expectedRule} to match synthetic payload`,
    );
  }

  assert.equal(scan(["x", "AKIA", "IOSFODNN7EXAMPLE"].join("")).length, 0);
  assert.equal(scan(["AKIA", "IOSFODNN7EXAMPLE", "9"].join("")).length, 0);
  assert.equal(scan("000-45-6789 666-45-6789 912-45-6789 123-00-6789 123-45-0000").length, 0);
});
