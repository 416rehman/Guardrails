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

test("denies UI commit when visual audit record or mobile screenshot is missing, allows after matching stamp, and rejects stale PNG edits", (t) => {
  const dir = makeTempUiRepo(t);
  writeFileSync(join(dir, "web/screenshots/home.png"), "png-v1", "utf8");

  const missing = evaluateVisualAuditFiles(["web/apps/console/src/App.tsx"], dir);
  assert.ok(missing.some((m) => m.includes("visual-audit")));

  recordVisualAudit({ cwd: dir, verdict: "pass", summary: "Desktop only", unresolvedIssues: 0, unresolvedPolish: 0 });
  const missingMobile = evaluateVisualAuditFiles(["web/apps/console/src/App.tsx"], dir);
  assert.ok(missingMobile.some((m) => m.includes("*-mobile.png")));

  writeFileSync(join(dir, "web/screenshots/home-mobile.png"), "png-mobile-v1", "utf8");
  recordVisualAudit({ cwd: dir, verdict: "pass", summary: "Has polish", unresolvedIssues: 0, unresolvedPolish: 1 });
  const polishPending = evaluateVisualAuditFiles(["web/apps/console/src/App.tsx"], dir);
  assert.ok(polishPending.some((m) => m.includes("polish")));

  recordVisualAudit({ cwd: dir, verdict: "pass", summary: "Clean", unresolvedIssues: 0, unresolvedPolish: 0 });
  assert.deepEqual(evaluateVisualAuditFiles(["web/apps/console/src/App.tsx"], dir), []);

  writeFileSync(join(dir, "web/screenshots/home.png"), "png-v2-modified", "utf8");
  const stale = evaluateVisualAuditFiles(["web/apps/console/src/App.tsx"], dir);
  assert.ok(stale.some((m) => m.includes("unaudited")));

  const rejectedWebShot = evaluateVisualAuditFiles(["web/screenshots/home.png"], dir);
  assert.ok(rejectedWebShot.some((m) => m.includes("must not be committed")));

  const rejectedDesktopShot = evaluateVisualAuditFiles(["desktop/screenshots/home.png"], dir);
  assert.ok(rejectedDesktopShot.some((m) => m.includes("must not be committed")));
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
