// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  evaluateVisualAuditFiles,
  evaluateVisualAuditToolPayload,
  recordVisualAudit,
} from "./visual-audit-check.mjs";

function makeTempUiRepo(t) {
  const dir = mkdtempSync(join(tmpdir(), "grdr-vaudit-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const git = (...args) => spawnSync("git", args, { cwd: dir, encoding: "utf8" });
  git("init", "-b", "main");
  git("config", "user.name", "Test");
  git("config", "user.email", "test@example.com");
  mkdirSync(join(dir, "web/apps/console/src"), { recursive: true });
  mkdirSync(join(dir, "web/screenshots"), { recursive: true });
  mkdirSync(join(dir, "desktop/screenshots"), { recursive: true });
  writeFileSync(join(dir, "README.md"), "# Test\n", "utf8");
  git("add", "README.md");
  git("commit", "-m", "chore: init");
  return dir;
}

test("allows non-UI commits without requiring a visual audit record", (t) => {
  const dir = makeTempUiRepo(t);
  assert.deepEqual(evaluateVisualAuditFiles(["crates/grdr-core/src/lib.rs"], dir), []);
});

test("denies UI commit when visual audit record is missing, allows after matching stamp, and rejects stale PNG edits", (t) => {
  const dir = makeTempUiRepo(t);
  writeFileSync(join(dir, "web/screenshots/home.png"), "png-v1", "utf8");

  const missing = evaluateVisualAuditFiles(["web/apps/console/src/App.tsx"], dir);
  assert.ok(missing.some((m) => m.includes("visual-audit")));

  recordVisualAudit({ cwd: dir, verdict: "pass", summary: "Clean", unresolvedIssues: 0 });
  assert.deepEqual(evaluateVisualAuditFiles(["web/apps/console/src/App.tsx"], dir), []);

  writeFileSync(join(dir, "web/screenshots/home.png"), "png-v2-modified", "utf8");
  const stale = evaluateVisualAuditFiles(["web/screenshots/home.png"], dir);
  assert.ok(stale.some((m) => m.includes("unaudited")));
});

test("evaluates git commit payload with staged web UI file", (t) => {
  const dir = makeTempUiRepo(t);
  writeFileSync(join(dir, "web/apps/console/src/App.tsx"), "export const x = 1;\n", "utf8");
  spawnSync("git", ["add", "web/apps/console/src/App.tsx"], { cwd: dir });

  const denied = evaluateVisualAuditToolPayload(
    { toolCall: { name: "run_command", args: { CommandLine: 'git commit -m "feat(ui): change"' } } },
    dir,
  );
  assert.ok(denied.some((m) => m.includes("visual-audit")));
});
