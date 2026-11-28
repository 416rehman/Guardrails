// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  ActionBlocked,
  ApprovalRequired,
  GuardrailsClient,
  GuardrailsError,
  canonicalDeclarationJson,
  claudeAgentSdkHook,
  langGraphToolMiddleware,
  openAiAgentsGuardrail,
  parseVerdict,
} from "../src/index.ts";
import { createWasmFloorEvaluator } from "../src/wasm.ts";
import type { AgentDeclaration } from "../src/index.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_DIR = path.resolve(__dirname, "../../../conformance");

interface GuardFixture {
  vectors: Array<{
    id: string;
    agent_name: string;
    control_point: string;
    action_class: string;
    target: string;
    summary: string;
    expected_verdicts: string[];
    expected_rule_prefix: string;
  }>;
}

describe("@grdr/sdk TypeScript Agent SDK", () => {
  let server: http.Server;
  let endpoint = "";
  let ingestedCount = 0;

  before(async () => {
    server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
        if (req.url === "/v1/ingest") {
          const attempts = Array.isArray(body.attempts) ? body.attempts.length : 0;
          ingestedCount += attempts;
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ accepted: attempts }));
          return;
        }
        if (req.url !== "/v1/guard") {
          res.writeHead(404);
          res.end();
          return;
        }
        if (req.headers.authorization === "Bearer reject-401") {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ code: "unauthenticated", message: "bad token" }));
          return;
        }
        if (req.headers.authorization === "Bearer redirect-302") {
          res.writeHead(302, { Location: "http://127.0.0.1:9/steal" });
          res.end();
          return;
        }
        const target = String(body.target ?? "");
        const actionClass = String(body.action_class ?? "");
        let verdict = "allow";
        let ruleId = "";
        let reason = "allowed";
        if (target.includes("--dangerously-skip-permissions")) {
          verdict = "block";
          ruleId = "essentials.bypass-flags";
          reason = "bypass flag forbidden";
        } else if (target.includes(".claude/settings.json") && actionClass === "file.write") {
          verdict = "block";
          ruleId = "essentials.control-files.write";
          reason = "control path protected";
        } else if (target.includes("id_rsa") && actionClass === "file.read") {
          verdict = "ask";
          ruleId = "essentials.cred-store.read";
          reason = "credential read requires approval";
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            receipt: {
              id: "rcpt_ts_1",
              verdict,
              ruleId,
              reason,
              sessionId: String(body.session_id ?? ""),
            },
          }),
        );
      });
    });
    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (addr && typeof addr === "object") {
          endpoint = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  after(() => {
    server.close();
  });

  it("declares canonical AgentDeclaration matching conformance fixture", () => {
    const fixtureRaw = fs.readFileSync(
      path.join(CONFORMANCE_DIR, "agent-declaration-v1.json"),
      "utf8",
    );
    const fixture = JSON.parse(fixtureRaw) as AgentDeclaration;
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "grdr-ts-decl-"));
    try {
      const client = new GuardrailsClient({ endpoint, declarationDir: tmpDir });
      const canonical = client.declare(fixture);
      assert.deepEqual(JSON.parse(canonical), fixture);
      assert.equal(canonical, canonicalDeclarationJson(fixture));
      const written = path.join(tmpDir, "research-orchestrator.declaration.json");
      assert.ok(fs.existsSync(written));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("evaluates conformance guard vectors and raises ApprovalRequired/ActionBlocked", async () => {
    const fixture = JSON.parse(
      fs.readFileSync(path.join(CONFORMANCE_DIR, "guard-vectors.json"), "utf8"),
    ) as GuardFixture;
    const client = new GuardrailsClient({ endpoint });
    for (const vec of fixture.vectors.slice(0, 4)) {
      const receipt = await client.decide({
        agent_name: vec.agent_name,
        action_class: vec.action_class,
        target: vec.target,
        control_point: vec.control_point,
        summary: vec.summary,
      });
      assert.ok(vec.expected_verdicts.includes(receipt.verdict));
      if (vec.expected_rule_prefix) {
        assert.ok(receipt.rule_id.startsWith(vec.expected_rule_prefix));
      }
    }

    await assert.rejects(
      () =>
        client.decide(
          { agent_name: "claude-code", action_class: "file.read", target: "~/.ssh/id_rsa" },
          { raiseOnDeny: true },
        ),
      ApprovalRequired,
    );

    await assert.rejects(
      () =>
        client.decide(
          {
            agent_name: "claude-code",
            action_class: "exec",
            target: "claude --dangerously-skip-permissions",
          },
          { raiseOnDeny: true },
        ),
      ActionBlocked,
    );
  });

  it("supports GRDR_ON_UNREACHABLE policies and framework middleware", async () => {
    const failOpenClient = new GuardrailsClient({
      endpoint: "http://127.0.0.1:1",
      timeoutMs: 150,
      onUnreachable: "fail_open",
    });
    const openRes = await failOpenClient.decide({
      agent_name: "a",
      action_class: "exec",
      target: "echo ok",
    });
    assert.equal(openRes.verdict, "allow");
    assert.equal(openRes.degraded, true);

    const floorClient = new GuardrailsClient(
      {
        endpoint: "http://127.0.0.1:1",
        timeoutMs: 150,
        onUnreachable: "local_floor",
      },
      (attempt) => ({
        id: "floor-1",
        verdict: attempt.target.includes("id_rsa") ? "block" : "allow",
        rule_id: "floor.secret",
        reason: "local floor decision",
        session_id: attempt.session_id ?? "",
        mode: "Block",
        degraded: true,
      }),
    );
    assert.equal(
      (
        await floorClient.decide({
          agent_name: "a",
          action_class: "file.read",
          target: "~/.ssh/id_rsa",
        })
      ).verdict,
      "block",
    );

    const client = new GuardrailsClient({ endpoint });
    const lgMiddleware = langGraphToolMiddleware(client, {
      agentName: "lg-ts",
      actionClassMap: { read_file: "file.read" },
    });
    assert.equal(
      await lgMiddleware({ name: "read_file", args: { path: "README.md" } }, () => "done"),
      "done",
    );

    const oaGuard = openAiAgentsGuardrail(client, {
      agentName: "oa-ts",
      hostedTools: ["openai:web_search_preview"],
    });
    const oaRes = await oaGuard({
      toolName: "exec",
      actionClass: "exec",
      target: "claude --dangerously-skip-permissions",
    });
    assert.equal(oaRes.tripwireTriggered, true);
    assert.ok(
      client.recordedDeclarations()[0]?.uncovered_hosted_tools.includes(
        "openai:web_search_preview",
      ),
    );

    const claudeHook = claudeAgentSdkHook(client);
    const hookOut = await claudeHook({
      tool_name: "Read",
      tool_input: { file_path: "~/.ssh/id_rsa" },
    });
    assert.equal(hookOut.permissionDecision, "ask");

    const rep = await client.report("lg-ts", "file.read", "README.md", "allow");
    assert.equal(rep.accepted, 1);
    assert.equal(ingestedCount, 1);

    assert.equal(parseVerdict("modify"), "modify");
    for (const tok of ["reject-401", "redirect-302"]) {
      const guarded = new GuardrailsClient({
        endpoint,
        token: tok,
        onUnreachable: "fail_open",
      });
      await assert.rejects(
        () =>
          guarded.decide({
            agent_name: "a",
            action_class: "file.read",
            target: "README.md",
          }),
        GuardrailsError,
      );
    }
  });

  it("rejects null pointer from grdr_alloc without writing to WASM linear memory offset 0", () => {
    const memory = new WebAssembly.Memory({ initial: 1 });
    const bytes = new Uint8Array(memory.buffer);
    bytes.set([0xaa, 0xbb, 0xcc, 0xdd], 0);
    let freeCalls = 0;
    let evalCalls = 0;
    const fakeInstance = {
      exports: {
        memory,
        grdr_alloc: () => 0,
        grdr_free: () => {
          freeCalls += 1;
        },
        grdr_wasm_eval_attempt: () => {
          evalCalls += 1;
          return 0;
        },
        grdr_result_ptr: () => 0,
        grdr_result_len: () => 0,
      },
    } as unknown as WebAssembly.Instance;

    const evaluator = createWasmFloorEvaluator(fakeInstance, "[]");
    assert.throws(
      () =>
        evaluator({
          agent_name: "a",
          action_class: "file.read",
          target: "README.md",
        }),
      (err: unknown) =>
        err instanceof GuardrailsError &&
        err.message.includes("WASM input exceeds allocation budget"),
    );
    assert.deepEqual(Array.from(bytes.subarray(0, 4)), [0xaa, 0xbb, 0xcc, 0xdd]);
    assert.equal(freeCalls, 0);
    assert.equal(evalCalls, 0);
  });
});
