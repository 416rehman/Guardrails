// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Tests for branch-check.mjs: node --test .claude/hooks/branch-check.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { checkState, findings, isValidWorkBranch, liveState, loadRules, openPullsArgs, printable, slugifyTitle } from "./branch-findings.mjs";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const SCRIPT = join(HERE, "branch-check.mjs");
const RULES_TEXT = readFileSync(join(HERE, "branch-rules.json"), "utf8");
const SUMMARY = /^branch-check: example\/repo: \d+ branches, \d+ open pull requests, findings: (\d+)\.$/;
const LINK_REFUSED = new Set(["EPERM", "EACCES", "ENOTSUP", "ENOSYS"]);
const PULL = { number: 1, head: "feat/sample-change", title: "Sample change", head_repo: "example/repo", author: { login: "example-dev", type: "User" }, body: "Summary" };
const STATE = { repo: "example/repo", default_branch: "main", branches: ["main", "feat/sample-change"], pulls: [PULL] };

function run(script, ...args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
}

function linkOrSkip(t, target, path, type) {
  try {
    symlinkSync(target, path, type);
    return true;
  } catch (error) {
    if (!LINK_REFUSED.has(error.code)) throw error;
    t.skip(`this system refuses to create a ${type} link (${error.code})`);
    return false;
  }
}

test("accepts standard feature, fix, chore, docs, refactor, and issue branches", () => {
  const rules = loadRules(RULES_TEXT);
  for (const name of [
    "feat/web-console",
    "fix/agent-panic",
    "chore/deps-update",
    "docs/quickstart",
    "refactor/policy-core",
    "issue/42-sample-slug",
  ]) {
    assert.ok(isValidWorkBranch(name, rules), name);
  }
  for (const bad of ["main", "wip", "Issue/42", "dependabot homoglyph/x"]) {
    assert.ok(!isValidWorkBranch(bad, rules), bad);
  }
});

test("flags branches without open PRs and unprefixed branch names", () => {
  const rules = loadRules(RULES_TEXT);
  assert.deepEqual(findings(checkState(STATE), rules), []);
  const badState = checkState({
    ...STATE,
    branches: ["main", "feat/sample-change", "random-branch"],
    pulls: [PULL],
  });
  const list = findings(badState, rules).map((f) => f.kind);
  assert.deepEqual(list, ["no-pull-request", "bad-name"]);
});

test("allows exempt dependabot and release-please branches with open PRs", () => {
  const rules = loadRules(RULES_TEXT);
  const state = checkState({
    repo: "example/repo",
    default_branch: "main",
    branches: ["main", "dependabot/npm/vite-1", "release-please--branches--main"],
    pulls: [
      { ...PULL, number: 2, head: "dependabot/npm/vite-1", author: { login: "dependabot", type: "Bot" } },
      { ...PULL, number: 3, head: "release-please--branches--main", author: { login: "github-actions", type: "Bot" } },
    ],
  });
  assert.deepEqual(findings(state, rules), []);
});

test("CLI --state exits 0 when clean and 1 on findings", (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "branch-check-"));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const cleanFile = join(scratch, "clean.json");
  writeFileSync(cleanFile, JSON.stringify(STATE));
  const ok = run(SCRIPT, "--state", cleanFile);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout.trim(), SUMMARY);
  assert.equal(Number(SUMMARY.exec(ok.stdout.trim())[1]), 0);

  const dirtyFile = join(scratch, "dirty.json");
  writeFileSync(dirtyFile, JSON.stringify({ ...STATE, branches: ["main", "feat/sample-change", "orphan"] }));
  const fail = run(SCRIPT, "--state", dirtyFile);
  assert.equal(fail.status, 1, fail.stderr);
  assert.match(fail.stdout.trim().split(/\r?\n/).at(-1), /findings: 2\.$/);
});

test("runs through a directory junction or file link", (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "branch-check-"));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const linked = join(scratch, "hooks");
  if (!linkOrSkip(t, HERE, linked, "junction")) return;
  const stateFile = join(scratch, "state.json");
  writeFileSync(stateFile, JSON.stringify(STATE));
  const result = run(join(linked, "branch-check.mjs"), "--state", stateFile);
  assert.equal(result.status, 0, result.stderr);
});

test("printable escapes non-ASCII and control characters", () => {
  assert.equal(printable("feat/ui"), '"feat/ui"');
  assert.equal(printable("d\u0435pendabot/x"), '"d\\u{435}pendabot/x"');
  assert.equal(printable("\u001b[2Jx"), '"\\u{1b}[2Jx"');
});

test("unreadable or incomplete state exits 2", () => {
  assert.equal(run(SCRIPT, "--state").status, 2);
  assert.throws(() => checkState({ ...STATE, branches: ["feat/sample-change"] }), /lacks the default branch/);
});

test("liveState reads repository metadata, branches and pulls", () => {
  const rules = loadRules(RULES_TEXT);
  const gh = (args) => {
    const query = args.find((arg) => arg.startsWith("query=")) ?? "";
    if (args[1] === "repos/{owner}/{repo}") return JSON.stringify({ full_name: "example/repo", default_branch: "main" });
    if (args[1] === "repos/{owner}/{repo}/branches") return "main\nfeat/sample-change\n";
    if (query.includes("pullRequests(")) return JSON.stringify(PULL);
    throw new Error(`unexpected gh call: ${args.join(" ")}`);
  };
  const state = checkState(liveState(rules, gh));
  assert.equal(state.pulls.length, 1);
  assert.deepEqual(findings(state, rules), []);
});

test("slugifyTitle and openPullsArgs work as expected", () => {
  assert.equal(slugifyTitle("Web UI, API & Agent MVP!"), "web-ui-api-agent-mvp");
  const args = openPullsArgs("123", "true", 100);
  assert.ok(args.includes("owner=123") && args.includes("name=true"));
});
