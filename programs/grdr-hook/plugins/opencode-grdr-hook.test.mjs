// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import assert from "node:assert/strict";
import { test } from "node:test";
import { createGuardrailsOpenCodePlugin } from "./opencode-grdr-hook.mjs";

test("opencode plugin fails closed on empty, malformed, and non-allow verdicts", () => {
  const emptyPlug = createGuardrailsOpenCodePlugin({ execFileSync: () => "" });
  assert.throws(
    () =>
      emptyPlug.hooks["tool.execute.before"](
        { sessionID: "s1", tool: "bash" },
        { args: { command: "ls" } },
      ),
    /empty or malformed/i,
  );

  const badPlug = createGuardrailsOpenCodePlugin({ execFileSync: () => "{not-json" });
  assert.throws(
    () =>
      badPlug.hooks["tool.execute.before"](
        { sessionID: "s1", tool: "bash" },
        { args: { command: "ls" } },
      ),
    /empty or malformed/i,
  );

  const askPlug = createGuardrailsOpenCodePlugin({
    execFileSync: () =>
      JSON.stringify({
        hookSpecificOutput: {
          permissionDecision: "ask",
          permissionDecisionReason: "owner approval",
          retry_token: "rty_deadbeef0123456789abcdef012345",
        },
      }),
  });
  assert.throws(
    () =>
      askPlug.hooks["tool.execute.before"](
        { sessionID: "s1", tool: "bash" },
        { args: { command: "ls" } },
      ),
    (err) => err.retryToken === "rty_deadbeef0123456789abcdef012345",
  );

  const exitNonZero = createGuardrailsOpenCodePlugin({
    execFileSync: () => {
      const err = new Error("exit 2");
      err.stdout = JSON.stringify({
        decision: "deny",
        reason: "policy block",
        retry_token: "rty_feedface",
      });
      throw err;
    },
  });
  assert.throws(
    () =>
      exitNonZero.hooks["tool.execute.before"](
        { sessionID: "s1", tool: "bash" },
        { args: { command: "rm -rf /" } },
      ),
    (err) => err.retryToken === "rty_feedface" && /policy block/.test(err.message),
  );
});

test("opencode plugin rewrites canonical structured fields and ignores array updatedInput", () => {
  const bashMod = createGuardrailsOpenCodePlugin({
    execFileSync: () =>
      JSON.stringify({
        hookSpecificOutput: {
          permissionDecision: "allow",
          updatedInput: "git status",
        },
      }),
  });
  const bashOut = { args: { command: "rm -rf /" } };
  bashMod.hooks["tool.execute.before"]({ sessionID: "s1", tool: "bash" }, bashOut);
  assert.equal(bashOut.args.command, "git status");
  assert.equal(bashOut.args.target, undefined);

  const arrayMod = createGuardrailsOpenCodePlugin({
    execFileSync: () =>
      JSON.stringify({
        hookSpecificOutput: {
          permissionDecision: "allow",
          updatedInput: ["unexpected", "array"],
        },
      }),
  });
  const keepOut = { args: { filePath: "README.md" } };
  arrayMod.hooks["tool.execute.before"]({ sessionID: "s1", tool: "read" }, keepOut);
  assert.deepEqual(keepOut.args, { filePath: "README.md" });
});
