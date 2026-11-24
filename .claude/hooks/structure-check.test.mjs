// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  checkStructureContent,
  evaluateStructureCommand,
  evaluateStructurePayload,
} from "./structure-check.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK_SCRIPT = join(HERE, "structure-check.mjs");

function repeatLines(line, count) {
  return Array.from({ length: count }, (_, idx) => `${line}_${idx}();`).join("\n");
}

test("S1: enforces 500 non-test code line limit and shrink-or-stay ratchet", (t) => {
  const overRust = repeatLines("fn f", 501);
  const denyNew = checkStructureContent("crates/grdr-core/src/big.rs", overRust);
  assert.ok(denyNew.some((m) => m.includes("S1") && m.includes("501")));

  const withTests = `${repeatLines("fn f", 400)}\n#[cfg(test)]\nmod tests {\n${repeatLines("fn t", 200)}\n}\n`;
  assert.deepEqual(checkStructureContent("crates/grdr-core/src/ok.rs", withTests), []);
  assert.deepEqual(checkStructureContent("web/apps/console/src/App.test.tsx", repeatLines("const x", 600)), []);

  const dir = mkdtempSync(join(tmpdir(), "grdr-s1-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, "crates/grdr-core/src"), { recursive: true });
  const existingPath = join(dir, "crates/grdr-core/src/legacy.rs");
  const base520 = repeatLines("fn f", 520);
  writeFileSync(existingPath, `${base520}\n`, "utf8");

  const grew = evaluateStructurePayload(
    {
      toolCall: {
        name: "edit_file",
        args: { Path: existingPath, Target: "fn f_0();", Replacement: "fn f_0();\nfn added();" },
      },
    },
    dir,
  );
  assert.ok(grew.some((m) => m.includes("S1") && m.includes("grew to 521")));

  const shrunk = evaluateStructurePayload(
    {
      toolCall: {
        name: "edit_file",
        args: { Path: existingPath, Target: "fn f_0();\nfn f_1();", Replacement: "fn f_0();" },
      },
    },
    dir,
  );
  assert.deepEqual(shrunk, []);
});

test("S2: checks top-level Rust declaration order on full writes while ignoring fn-local structs and const fn", () => {
  const badOrder = "pub fn run() {}\npub struct Late { x: u32 }\n";
  assert.ok(checkStructureContent("crates/grdr-core/src/lib.rs", badOrder).some((m) => m.includes("S2")));

  const badConst = "impl Foo {}\npub const LIMIT: usize = 4;\n";
  assert.ok(checkStructureContent("crates/grdr-core/src/lib.rs", badConst).some((m) => m.includes("S2")));

  const goodOrder = [
    "pub const LIMIT: usize = 4;",
    "pub struct Foo { x: u32 }",
    "impl Foo { pub const fn id(&self) -> u32 { self.x } }",
    "pub const fn helper() -> u32 { 1 }",
    "pub fn run() { struct Local; }",
    "#[cfg(test)]",
    "mod tests { struct TestHelper; }",
  ].join("\n");
  assert.deepEqual(checkStructureContent("crates/grdr-core/src/lib.rs", goodOrder), []);
});

test("S3: rejects bare TODO/FIXME, step-narration comments, and em dashes while allowing cited work items", () => {
  const bad = [
    "// TODO: fix later",
    "// FIXME: broken",
    "// Step 1: parse payload",
    "// Reason \u2014 explain",
  ].join("\n");
  const findings = checkStructureContent("crates/grdr-core/src/lib.rs", bad);
  assert.equal(findings.length, 4);

  const good = [
    "// TODO(#53): finish parser",
    "// TODO(WI-0041): wire accessor",
    'const S: &str = "// Step 1: TODO: \u2014 inside string literal";',
  ].join("\n");
  assert.deepEqual(checkStructureContent("crates/grdr-core/src/lib.rs", good), []);

  const editClean = checkStructureContent(
    "crates/grdr-core/src/lib.rs",
    "// TODO: old untouched context\nlet x = 2;",
    { isFullWrite: false, target: "// TODO: old untouched context\nlet x = 1;" },
  );
  assert.deepEqual(editClean, []);
});

test("S4: detects implicit state machines in Rust structs, TS types, and TSX hooks unless allow-annotated", () => {
  const rustBad = "pub struct Job { started: bool, done: bool, failed: bool }\npub struct Wire { status: String }\n";
  assert.equal(checkStructureContent("crates/grdr-core/src/job.rs", rustBad).length, 2);

  const rustAllowed = [
    "// grdr:allow-s4 orthogonal wire flags",
    "pub struct WireFlags { a: bool, b: bool, c: bool }",
    "pub enum Mode { Off, Watch }",
    "pub struct Good { mode: Mode }",
  ].join("\n");
  assert.deepEqual(checkStructureContent("crates/grdr-core/src/job.rs", rustAllowed), []);

  const tsBad = "export interface Job { a: boolean; b: boolean; c: boolean; }\nexport type Flow = { phase: string; };\n";
  assert.equal(checkStructureContent("web/packages/kit/src/job.ts", tsBad).length, 2);

  const tsxBad = [
    "export function Modal() {",
    "  const [open, setOpen] = useState(false);",
    "  const [busy, setBusy] = useState(true);",
    "  const [err, setErr] = useState<string | null>(null);",
    "  return null;",
    "}",
  ].join("\n");
  assert.ok(checkStructureContent("web/apps/console/src/Modal.tsx", tsxBad).some((m) => m.includes("S4")));

  const tsxAllowed = [
    "export function Modal() {",
    "  // grdr:allow-s4 independent display toggles",
    "  const [open, setOpen] = useState(false);",
    "  const [busy, setBusy] = useState(true);",
    "  const [err, setErr] = useState<string | null>(null);",
    "  return null;",
    "}",
  ].join("\n");
  assert.deepEqual(checkStructureContent("web/apps/console/src/Modal.tsx", tsxAllowed), []);
});

test("S6: rejects Rust panic paths and unannotated unsafe while allowing test blocks and SAFETY comments", (t) => {
  const bad = [
    "pub fn f(v: Option<u32>) -> u32 { v.unwrap() }",
    "pub fn g() { unsafe { do_ffi(); } }",
  ].join("\n");
  const findings = checkStructureContent("crates/grdr-core/src/ffi.rs", bad);
  assert.equal(findings.length, 2);

  const good = [
    "pub fn f(v: Option<u32>) -> u32 { v.unwrap_or_default() }",
    "// SAFETY: pointer is aligned and non-null for call duration.",
    "pub fn g() { unsafe { do_ffi(); } }",
    "#[cfg(test)]",
    "mod tests { #[test] fn t() { Some(1).unwrap(); panic!(\"ok\"); } }",
  ].join("\n");
  assert.deepEqual(checkStructureContent("crates/grdr-core/src/ffi.rs", good), []);

  const dir = mkdtempSync(join(tmpdir(), "grdr-s6-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, "crates/grdr-core/src"), { recursive: true });
  const file = join(dir, "crates/grdr-core/src/lib.rs");
  writeFileSync(file, "pub fn ok() {}\n#[cfg(test)]\nmod tests {\n  fn t() { let x = 1; }\n}\n", "utf8");
  const testEdit = evaluateStructurePayload(
    { tool_name: "Edit", tool_input: { file_path: file, old_string: "let x = 1;", new_string: "let x = Some(1).unwrap();" } },
    dir,
  );
  assert.deepEqual(testEdit, []);
});

test("grdr-interface: enforces react-aria, astryx/ui-sdk boundaries, logical CSS, and no dangerouslySetInnerHTML", () => {
  const badAria = checkStructureContent("web/apps/console/src/A.tsx", 'import { Button } from "react-aria-components";');
  assert.ok(badAria.some((m) => m.includes("ARCH-103")));
  assert.deepEqual(checkStructureContent("web/packages/ui/src/A.tsx", 'import { Button } from "react-aria-components";'), []);

  const badAstryx = checkStructureContent("web/packages/kit/src/K.tsx", 'import { Box } from "@astryxdesign/core";');
  assert.ok(badAstryx.some((m) => m.includes("ARCH-101..102")));

  const badCss = checkStructureContent("web/apps/console/src/app.css", ".card { margin-left: 8px; }");
  assert.ok(badCss.some((m) => m.includes("UX6")));
  assert.deepEqual(checkStructureContent("web/apps/console/src/app.css", ".card { margin-inline-start: var(--s-2); }"), []);

  const badXss = checkStructureContent("web/apps/console/src/X.tsx", "<div dangerouslySetInnerHTML={{ __html: x }} />");
  assert.ok(badXss.some((m) => m.includes("dangerouslySetInnerHTML")));
});

test("workflow, repo hygiene, commit message, and pnpm-only command rules", () => {
  assert.ok(checkStructureContent(".git/config", "[core]").some((m) => m.includes(".git/")));
  assert.ok(checkStructureContent(".github/workflows/ci.yml", "      - uses: actions/checkout@v4").some((m) => m.includes("40-hex")));
  assert.deepEqual(
    checkStructureContent(
      ".github/workflows/ci.yml",
      "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n      - uses: ./.github/actions/local",
    ),
    [],
  );

  assert.deepEqual(evaluateStructureCommand("git commit -m 'feat(hooks): add structure check'"), []);
  assert.ok(evaluateStructureCommand('git commit -m "wip stuff"').some((m) => m.includes("Conventional Commits")));
  assert.ok(evaluateStructureCommand(`git commit -m "feat: ${"a".repeat(70)}"`).some((m) => m.includes("max 72")));
  assert.ok(evaluateStructureCommand('git commit -m "feat: ok" -m "body"').some((m) => m.includes("multiple -m")));
  assert.ok(evaluateStructureCommand('git commit -m "feat: ok`nCo-Authored-By: Bot"').some((m) => m.includes("AI trailers")));

  assert.ok(evaluateStructureCommand("npm install").some((m) => m.includes("pnpm")));
  assert.ok(evaluateStructureCommand("pnpm test; npx vitest").some((m) => m.includes("pnpm")));
  assert.ok(evaluateStructureCommand("yarn build").some((m) => m.includes("pnpm")));
  assert.ok(evaluateStructureCommand("bun test").some((m) => m.includes("pnpm")));
  assert.deepEqual(evaluateStructureCommand('pnpm --dir web run test; echo "avoid npm and yarn"'), []);
  assert.deepEqual(evaluateStructureCommand('Select-String -Path AGENTS.md -Pattern "npm|npx"'), []);
});

test("CLI stdin contract exits 2 on denial and 0 on clean payload", () => {
  const denyPayload = '{"toolCall":{"name":"run_command","args":{"CommandLine":"npm test"}}}';
  const denied = spawnSync(process.execPath, [HOOK_SCRIPT], { input: denyPayload, encoding: "utf8" });
  assert.equal(denied.status, 2);
  assert.match(denied.stderr, /use pnpm instead of "npm"/);

  const allowPayload = '{"tool_name":"Bash","tool_input":{"command":"pnpm --dir web run test"}}';
  const allowed = spawnSync(process.execPath, [HOOK_SCRIPT], { input: allowPayload, encoding: "utf8" });
  assert.equal(allowed.status, 0);
});
