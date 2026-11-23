// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Tests for Antigravity PreToolUse hook (.agents/hooks/agy-pre-tool-use.mjs) and shared
// branch/PR rules in .claude/hooks/docs-check.mjs.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { evaluateHookCommand } from "../../.claude/hooks/docs-check.mjs";
import { handleHookPayload } from "./agy-pre-tool-use.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK_SCRIPT = join(HERE, "agy-pre-tool-use.mjs");

function initTempRepo(branch) {
  const dir = mkdtempSync(join(tmpdir(), "agy-hook-"));
  const git = (...args) => spawnSync("git", args, { cwd: dir, encoding: "utf8" });
  git("init", "-b", "main");
  git("config", "user.name", "Test");
  git("config", "user.email", "test@example.com");
  writeFileSync(join(dir, "README.md"), "# Test\n", "utf8");
  git("add", "README.md");
  git("commit", "-m", "chore: init");
  git("update-ref", "refs/remotes/origin/main", "HEAD");
  if (branch !== "main") {
    git("switch", "-c", branch);
  }
  return dir;
}

test("blocks direct git push to main via Antigravity PreToolUse JSON contract", () => {
  const payload = JSON.stringify({
    toolCall: {
      name: "run_command",
      args: { CommandLine: "git push origin main" },
    },
    cwd: process.cwd(),
  });
  const out = handleHookPayload(payload);
  assert.equal(out.decision, "deny");
  assert.match(out.reason, /direct push to main is refused/);
});

test("blocks git push HEAD:refs/heads/main", () => {
  const out = evaluateHookCommand("git push origin HEAD:refs/heads/main", process.cwd(), { listOpenPrs: () => [] });
  assert.ok(out.some((msg) => msg.includes("direct push to main is refused")), out.join("\n"));
});

test("blocks git push from a branch without an issue slug", (t) => {
  const dir = initTempRepo("issue/42");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const out = evaluateHookCommand("git push -u origin issue/42", dir, { listOpenPrs: () => [] });
  assert.ok(out.some((msg) => msg.includes("issue/<n>-<slug>")), out.join("\n"));
});

test("allows git push from a valid issue/<n>-<slug> branch", (t) => {
  const dir = initTempRepo("issue/42-add-auth-token");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const out = evaluateHookCommand("git push -u origin issue/42-add-auth-token", dir, { listOpenPrs: () => [] });
  assert.deepEqual(out, []);
});

test("allows git push --delete for branch cleanup", () => {
  const out = evaluateHookCommand("git push origin --delete issue/42", process.cwd(), { listOpenPrs: () => [] });
  assert.deepEqual(out, []);
});

test("blocks gh pr create without target issue link or issue name", (t) => {
  const dir = initTempRepo("issue/42-add-auth-token");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, "pr.md"), "Summary only.\n", "utf8");
  const out = evaluateHookCommand(
    'gh pr create --draft --base main --head issue/42-add-auth-token --title "misc cleanup" --body-file pr.md',
    dir,
    { listOpenPrs: () => [] },
  );
  assert.ok(out.some((msg) => msg.includes("target issue #42")), out.join("\n"));
  assert.ok(out.some((msg) => msg.includes("include the issue name")), out.join("\n"));
});

test("blocks gh pr create when an open PR already exists for the issue", (t) => {
  const dir = initTempRepo("issue/42-add-auth-token");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, "pr.md"), "Issue: #42 Add auth token\nRefs #42\n", "utf8");
  const out = evaluateHookCommand(
    'gh pr create --draft --base main --head issue/42-add-auth-token --title "feat(auth): add auth token (#42)" --body-file pr.md',
    dir,
    {
      listOpenPrs: () => [{ number: 100, headRefName: "issue/42-old", body: "Refs #42" }],
    },
  );
  assert.ok(out.some((msg) => msg.includes("already has open pull request #100")), out.join("\n"));
});

test("allows valid gh pr create with issue name, target issue, and docs check", (t) => {
  const dir = initTempRepo("issue/42-add-auth-token");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, "pr.md"), "Issue: #42 Add auth token\n\nSummary.\n\nRefs #42\n", "utf8");
  const out = evaluateHookCommand(
    'gh pr create --draft --base main --head issue/42-add-auth-token --title "feat(auth): add auth token (#42)" --body-file pr.md',
    dir,
    { listOpenPrs: () => [] },
  );
  assert.deepEqual(out, []);
});

test("stdin/stdout CLI contract outputs valid JSON allow for non-git commands", () => {
  const payload = JSON.stringify({
    toolCall: { name: "run_command", args: { CommandLine: "cargo test --workspace" } },
    cwd: process.cwd(),
  });
  const res = spawnSync(process.execPath, [HOOK_SCRIPT], { input: payload, encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);
  assert.deepEqual(JSON.parse(res.stdout), { decision: "allow" });
});

test("stdin/stdout CLI contract outputs JSON deny for pushing to main", () => {
  const payload = JSON.stringify({
    toolCall: { name: "run_command", args: { CommandLine: "git push origin main" } },
    cwd: process.cwd(),
  });
  const res = spawnSync(process.execPath, [HOOK_SCRIPT], { input: payload, encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);
  const parsed = JSON.parse(res.stdout);
  assert.equal(parsed.decision, "deny");
  assert.match(parsed.reason, /direct push to main is refused/);
});
