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
import { checkEngineeringContent, evaluateHookCommand } from "../../.claude/hooks/docs-check.mjs";
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
  const out = evaluateHookCommand("git push origin HEAD:refs/heads/main", process.cwd());
  assert.ok(out.some((msg) => msg.includes("direct push to main is refused")), out.join("\n"));
});

test("blocks git push from an unprefixed branch", (t) => {
  const dir = initTempRepo("misc-wip");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const out = evaluateHookCommand("git push -u origin misc-wip", dir);
  assert.ok(out.some((msg) => msg.includes("should follow feat/<slug>")), out.join("\n"));
});

test("allows git push from feat/, fix/, and issue/<n>-<slug> branches", (t) => {
  for (const branch of ["feat/platform-mvp", "fix/agent-timeout", "issue/42-add-auth-token"]) {
    const dir = initTempRepo(branch);
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const out = evaluateHookCommand(`git push -u origin ${branch}`, dir);
    assert.deepEqual(out, [], branch);
  }
});

test("allows git push --delete for branch cleanup", () => {
  const out = evaluateHookCommand("git push origin --delete issue/42", process.cwd());
  assert.deepEqual(out, []);
});

test("blocks gh pr create from main", (t) => {
  const dir = initTempRepo("main");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, "pr.md"), "Summary only.\n", "utf8");
  const out = evaluateHookCommand(
    'gh pr create --base main --head main --title "chore: test" --body-file pr.md',
    dir,
  );
  assert.ok(out.some((msg) => msg.includes("must target a work branch")), out.join("\n"));
});

test("allows gh pr create from feat/ branch with an accompanying issue link and design ref", (t) => {
  const dir = initTempRepo("feat/web-console");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(
    join(dir, "pr.md"),
    "Closes #42\n\nGoverning design: D-42 (`docs/design/27-web-console-ux.md`). Implements initial Web Console.\n",
    "utf8",
  );
  const out = evaluateHookCommand(
    'gh pr create --base main --head feat/web-console --title "feat(web): implement console" --body-file pr.md',
    dir,
  );
  assert.deepEqual(out, []);
});

test("blocks gh pr create without an accompanying issue link", (t) => {
  const dir = initTempRepo("feat/web-console");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, "pr.md"), "Implements initial Web Console per D-42.\n", "utf8");
  const out = evaluateHookCommand(
    'gh pr create --base main --head feat/web-console --title "feat(web): implement console" --body-file pr.md',
    dir,
  );
  assert.ok(out.some((msg) => msg.includes("accompanying GitHub issue")), out.join("\n"));
});

test("blocks gh pr create missing a governing docs/design/ or decision/principle ID", (t) => {
  const dir = initTempRepo("feat/web-console");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, "pr.md"), "Closes #50\n\nImplements initial Web Console.\n", "utf8");
  const out = evaluateHookCommand(
    'gh pr create --base main --head feat/web-console --title "feat(web): implement console" --body-file pr.md',
    dir,
  );
  assert.ok(out.some((msg) => msg.includes("governing docs/design/")), out.join("\n"));
});

test("allows gh pr create citing Closes #50 and D-42 via inline --body", (t) => {
  const dir = initTempRepo("chore/issue-50-guard");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const out = evaluateHookCommand(
    'gh pr create --base main --head chore/issue-50-guard --title "chore(hooks): design alignment" --body "Closes #50 per D-42"',
    dir,
  );
  assert.deepEqual(out, []);
});

test("rejects banned web/server frameworks in web/**/package.json and allows Vite + React 19 stack", () => {
  for (const pkg of ["next", "express"]) {
    const denied = handleHookPayload(
      JSON.stringify({
        toolCall: {
          name: "write_file",
          args: {
            Path: "D:/repo/web/apps/console/package.json",
            Content: JSON.stringify({
              name: "@grdr/console",
              dependencies: {
                react: "^19.1.0",
                [pkg]: "^4.0.0",
              },
            }),
          },
        },
        cwd: "D:/repo",
      }),
    );
    assert.equal(denied.decision, "deny", pkg);
    assert.match(denied.reason, /stack alignment.*D-33\/D-42/);
  }

  const allowed = handleHookPayload(
    JSON.stringify({
      toolCall: {
        name: "write_file",
        args: {
          Path: "D:/repo/web/apps/console/package.json",
          Content: JSON.stringify({
            name: "@grdr/console",
            dependencies: {
              "@grdr/ui": "workspace:*",
              "@tanstack/react-router": "^1.120.0",
              react: "^19.1.0",
              "react-dom": "^19.1.0",
            },
            devDependencies: {
              vite: "^6.3.0",
              vitest: "^4.1.12",
            },
          }),
        },
      },
      cwd: "D:/repo",
    }),
  );
  assert.equal(allowed.decision, "allow", allowed.reason);
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

test("denies write_file introducing AI design tells into web UI", () => {
  const payload = JSON.stringify({
    toolCall: {
      name: "write_file",
      args: {
        Path: "D:/repo/web/apps/console/src/Demo.tsx",
        Content: 'export const Demo = () => <div style={{ color: "#6366F1" }}>Seamless UI</div>;',
      },
    },
    cwd: "D:/repo",
  });
  const out = handleHookPayload(payload);
  assert.equal(out.decision, "deny");
  assert.match(out.reason, /design-check/);
});

test("enforces beta no-backward-compat, no-stopgap, and no-speculative rules in non-test code", () => {
  const rustCompat = checkEngineeringContent(
    "crates/grdr-core/src/lib.rs",
    '#[deprecated(note = "old API")] pub fn legacy() {}\n// backward compatibility shim',
  );
  assert.ok(rustCompat.some((f) => f.includes("engineering rule 1")));

  const gaAllowed = checkEngineeringContent(
    "crates/grdr-core/src/lib.rs",
    '#[deprecated(note = "old API")] pub fn legacy() {}',
    { preReleaseBeta: false },
  );
  assert.deepEqual(gaAllowed, []);

  const stopgapAndSpeculative = checkEngineeringContent(
    "web/packages/api/src/client.ts",
    "// temporary workaround to make it work for now\n// config option just in case we need it later",
  );
  assert.ok(stopgapAndSpeculative.some((f) => f.includes("engineering rule 2")));
  assert.ok(stopgapAndSpeculative.some((f) => f.includes("engineering rule 7")));

  const agyDeny = handleHookPayload(
    JSON.stringify({
      toolCall: {
        name: "edit_file",
        args: {
          Path: "D:/repo/crates/grdr-core/src/eval.rs",
          Replacement: "// HACK: make it work for now",
        },
      },
      cwd: "D:/repo",
    }),
  );
  assert.equal(agyDeny.decision, "deny");
  assert.match(agyDeny.reason, /engineering rule 7/);

  assert.deepEqual(
    checkEngineeringContent("crates/grdr-core/tests/compat_test.rs", "// backward compatibility test"),
    [],
  );
});

test("enforces grdr-structure S1-S6, interface, commit, and pnpm-only rules via Antigravity PreToolUse", () => {
  const npmDeny = handleHookPayload(
    JSON.stringify({
      toolCall: { name: "run_command", args: { CommandLine: "npx vitest run" } },
      cwd: "D:/repo",
    }),
  );
  assert.equal(npmDeny.decision, "deny");
  assert.match(npmDeny.reason, /use pnpm instead of "npx"/);

  const commitDeny = handleHookPayload(
    JSON.stringify({
      toolCall: { name: "run_command", args: { CommandLine: 'git commit -m "bad msg"' } },
      cwd: process.cwd(),
    }),
  );
  assert.equal(commitDeny.decision, "deny");
  assert.match(commitDeny.reason, /Conventional Commits/);

  const rustDeny = handleHookPayload(
    JSON.stringify({
      toolCall: {
        name: "edit_file",
        args: {
          Path: "D:/repo/crates/grdr-core/src/lib.rs",
          Replacement: "pub fn bad(x: Option<u8>) -> u8 { x.unwrap() }",
        },
      },
      cwd: "D:/repo",
    }),
  );
  assert.equal(rustDeny.decision, "deny");
  assert.match(rustDeny.reason, /S6/);
});
