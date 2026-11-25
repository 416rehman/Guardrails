// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  collectNonUiFileHashes,
  discoverChangedNonUiFiles,
  evaluateSecurityAuditFiles,
  evaluateSecurityAuditToolPayload,
  findTrustCoreFiles,
  isNonUiSecurityPath,
  loadTrustCoreMatchers,
  recordSecurityAudit,
  resolveSecurityAuditRecordPath,
} from "./security-audit-check.mjs";
import {
  GIT_MAX_BUFFER_BYTES,
  parseCatFileBatchZ,
  readBatchBytesForSource,
  readBytesForSource,
  readCleanAuditBytes,
} from "./security-audit-git.mjs";
import { globSpecToMatcher } from "./security-audit-glob.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK_SCRIPT = join(HERE, "security-audit-check.mjs");
const REPO_ROOT = join(HERE, "..", "..");

function makeTempRepo(t, { withTrustCore = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "grdr-saudit-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const git = (...args) => spawnSync("git", args, { cwd: dir, encoding: "utf8" });
  git("init", "-b", "main");
  git("config", "user.name", "Test");
  git("config", "user.email", "test@example.com");
  mkdirSync(join(dir, "crates/grdr-core/src"), { recursive: true });
  mkdirSync(join(dir, "crates/grdr-ui-model/src"), { recursive: true });
  mkdirSync(join(dir, "web/apps/console/src"), { recursive: true });
  mkdirSync(join(dir, "web/packages/api/src"), { recursive: true });
  writeFileSync(join(dir, "README.md"), "# Test\n", "utf8");
  git("add", "README.md");
  if (withTrustCore) {
    mkdirSync(join(dir, "security"), { recursive: true });
    writeFileSync(
      join(dir, "security/trust-core.paths"),
      readFileSync(join(REPO_ROOT, "security/trust-core.paths"), "utf8"),
      "utf8",
    );
    git("add", "security/trust-core.paths");
  }
  git("commit", "-m", "chore: init");
  git("update-ref", "refs/remotes/origin/main", "HEAD");
  git("switch", "-c", "feat/test-audit");
  return dir;
}

test("isNonUiSecurityPath covers all non-UI and trust-core paths while keeping src/target and excluding UI/artifacts", (t) => {
  const dir = makeTempRepo(t);
  const included = [
    "crates/grdr-core/src/lib.rs",
    "crates/grdr-core/src/target/windows.rs",
    "././crates/grdr-core/src/lib.rs",
    "crates/grdr-ui-model/../grdr-crypto/src/lib.rs",
    "Crates/grdr-crypto/src/lib.rs",
    "crates\\grdr-crypto\\src\\lib.rs",
    "programs/grdr-daemon/src/main.rs",
    "bpf/probe.c",
    "proto/grdr/v1/event.proto",
    "schema/tenancy/lifecycle.toml",
    "deploy/helm/Chart.yaml",
    "scripts/release.sh",
    "platform/windows/service.rs",
    ".github/workflows/verify.yml",
    ".github/actions/tree-paths/trust_core_touched.py",
    ".claude/hooks/docs-check.mjs",
    ".claude/settings.json",
    ".agents/hooks/agy-pre-tool-use.mjs",
    ".agents/hooks.json",
    "security/trust-core.paths",
    "supply-chain/licences.toml",
    "web/packages/api/src/client.ts",
    "limits.toml",
    "deny.toml",
    ".cargo/config.toml",
    "build.rs",
    "crates/grdr-ui-model/build.rs",
    "desktop/grdr-desktop/build.rs",
  ];
  for (const path of included) {
    assert.equal(isNonUiSecurityPath(path, dir), true, `expected included: ${path}`);
  }

  const excluded = [
    "crates/grdr-ui-model/src/lib.rs",
    "crates\\grdr-ui-model\\src\\state.rs",
    "web/apps/console/src/App.tsx",
    "web/packages/ui/src/Button.tsx",
    "desktop/grdr-desktop/src/main.rs",
    "docs/design/02-threat-model.md",
    "README.md",
    "target/debug/lib.rlib",
    "crates/grdr-core/target/debug/lib.rlib",
    "web/packages/api/node_modules/foo/index.js",
    "web/packages/api/dist/index.js",
    "deploy/assets/logo.png",
    "scripts/preview.jpg",
    "security/badge.webp",
    "crates/grdr-core/font.woff2",
    "security/threat-report.pdf",
  ];
  for (const path of excluded) {
    assert.equal(isNonUiSecurityPath(path, dir), false, `expected excluded: ${path}`);
  }

  // Trust-core matches must never be suppressed by IGNORED_NON_UI_RE, and absolute subdir paths normalize to repo root.
  for (const tcIgnored of [
    "crates/grdr-crypto/target/backdoor.rs",
    "programs/grdr-daemon/target/build.rs",
    "bpf/node_modules/probe.c",
    "crates/grdr-crypto/blob.png",
  ]) {
    assert.equal(isNonUiSecurityPath(tcIgnored, dir), true, `trust-core must override ignore: ${tcIgnored}`);
  }
  assert.equal(isNonUiSecurityPath(join(dir, "crates/grdr-core/src/lib.rs"), join(dir, "crates/grdr-core")), true);
});

test("allows UI-only and docs-only file sets without a security audit record", (t) => {
  const dir = makeTempRepo(t);
  assert.deepEqual(
    evaluateSecurityAuditFiles(
      ["crates/grdr-ui-model/src/lib.rs", "web/apps/console/src/App.tsx", "README.md"],
      dir,
    ),
    [],
  );
});

test("denies missing, unreadable, failed, nonzero, or metadata-tampered records and allows exact SHA-256 stamp", (t) => {
  const dir = makeTempRepo(t);
  const libRel = "crates/grdr-core/src/lib.rs";
  writeFileSync(join(dir, libRel), "pub fn safe() -> u8 { 1 }\n", "utf8");

  const missing = evaluateSecurityAuditFiles([libRel], dir);
  assert.ok(missing.some((m) => m.includes("grdr-security-audit") && m.includes("--record")));

  const recordPath = resolveSecurityAuditRecordPath(dir);
  writeFileSync(recordPath, "{corrupt-json", "utf8");
  assert.ok(evaluateSecurityAuditFiles([libRel], dir).some((m) => m.includes("unreadable")));

  writeFileSync(recordPath, '"string-record"\n', "utf8");
  assert.ok(evaluateSecurityAuditFiles([libRel], dir).some((m) => m.includes("malformed")));

  recordSecurityAudit({
    cwd: dir,
    verdict: "fail",
    summary: "Found issue",
    unresolvedIssues: 0,
    unresolvedHardening: 0,
    files: [libRel],
  });
  assert.ok(evaluateSecurityAuditFiles([libRel], dir).some((m) => m.includes('verdict is "fail"')));

  assert.throws(
    () => recordSecurityAudit({ cwd: dir, verdict: "ok", files: [libRel] }),
    /GRDR-HOOK-0001/,
  );

  recordSecurityAudit({
    cwd: dir,
    verdict: "pass",
    summary: "Blocking open",
    unresolvedIssues: 1,
    unresolvedHardening: 0,
    files: [libRel],
  });
  assert.ok(evaluateSecurityAuditFiles([libRel], dir).some((m) => m.includes("1 blocking")));

  recordSecurityAudit({
    cwd: dir,
    verdict: "pass",
    summary: "Hardening open",
    unresolvedIssues: 0,
    unresolvedHardening: 2,
    files: [libRel],
  });
  assert.ok(evaluateSecurityAuditFiles([libRel], dir).some((m) => m.includes("2 hardening")));

  const clean = recordSecurityAudit({
    cwd: dir,
    verdict: "pass",
    summary: "All 8 dimensions passed",
    unresolvedIssues: 0,
    unresolvedHardening: 0,
    reviewer: "judge-01",
    files: [libRel],
  });
  assert.equal(clean.verdict, "pass");
  assert.equal(clean.reviewer, "judge-01");
  assert.equal(clean.trustCoreTouched, false);
  assert.deepEqual(evaluateSecurityAuditFiles([libRel], dir), []);

  const validJson = JSON.parse(readFileSync(recordPath, "utf8"));
  for (const tampered of [
    { ...validJson, reviewer: "" },
    { ...validJson, recordedAt: "not-a-date" },
    { ...validJson, trustCoreTouched: true },
    { ...validJson, trustCoreFiles: "not-an-array" },
    { ...validJson, unresolvedIssues: "0" },
    { ...validJson, fileHashes: { [libRel]: validJson.fileHashes[libRel].toUpperCase() } },
  ]) {
    writeFileSync(recordPath, JSON.stringify(tampered), "utf8");
    assert.ok(evaluateSecurityAuditFiles([libRel], dir).length > 0);
  }

  // Missing trust-core entry in trustCoreFiles must fail even when trustCoreTouched is true.
  const tcRel = "crates/grdr-crypto/src/tc.rs";
  mkdirSync(join(dir, "crates/grdr-crypto/src"), { recursive: true });
  writeFileSync(join(dir, tcRel), "pub fn seal() {}\n", "utf8");
  const tcRec = recordSecurityAudit({ cwd: dir, files: [tcRel], reviewer: "judge-tc" });
  writeFileSync(recordPath, JSON.stringify({ ...tcRec, trustCoreFiles: [] }), "utf8");
  assert.ok(evaluateSecurityAuditFiles([tcRel], dir).some((m) => m.includes("metadata valid: false")));

  writeFileSync(recordPath, JSON.stringify(validJson), "utf8");
  writeFileSync(join(dir, libRel), "pub fn safe() -> u8 { 2 }\n", "utf8");
  const stale = evaluateSecurityAuditFiles([libRel], dir);
  assert.ok(stale.some((m) => m.includes("updated or unaudited") && m.includes(libRel)));
});

test("trust-core matching uses ASCII icase, prevents ReDoS, reads HEAD union, and works from subdirectories", (t) => {
  const dir = makeTempRepo(t);
  const matchers = loadTrustCoreMatchers(dir);
  assert.ok(matchers.length > 10);

  const matched = findTrustCoreFiles(
    [
      "bpf/lsm.c",
      "crates/grdr-crypto/src/aead.rs",
      "crates/grdr-wire/src/peer_auth.rs",
      "crates/grdr-wire/src/peer_auth/unix.rs",
      "BUILD.RS",
      "crates/grdr-core/build.rs",
      "crates/grdr-core/.cargo/config.toml",
      "deny.toml",
      "crates/grdr-core/deny.ci.toml",
      "limits.toml",
      "crates/grdr-core/src/lib.rs",
      "scripts/helper.sh",
    ],
    dir,
  );
  assert.deepEqual(matched, [
    "bpf/lsm.c",
    "crates/grdr-crypto/src/aead.rs",
    "crates/grdr-wire/src/peer_auth.rs",
    "crates/grdr-wire/src/peer_auth/unix.rs",
    "BUILD.RS",
    "crates/grdr-core/build.rs",
    "crates/grdr-core/.cargo/config.toml",
    "deny.toml",
    "crates/grdr-core/deny.ci.toml",
    "limits.toml",
  ]);

  // Removing a path from disk trust-core.paths in the same branch cannot hide it from HEAD union.
  writeFileSync(join(dir, "security/trust-core.paths"), "security/trust-core.paths\n", "utf8");
  assert.deepEqual(findTrustCoreFiles(["limits.toml"], dir), ["limits.toml"]);
  writeFileSync(
    join(dir, "security/trust-core.paths"),
    `${readFileSync(join(REPO_ROOT, "security/trust-core.paths"), "utf8")}\n${"**/".repeat(12)}deep.rs\nfoo/**/**\n*a*a*a*a*a*a*a*a*b.rs\n`,
    "utf8",
  );
  const startMs = Date.now();
  assert.deepEqual(findTrustCoreFiles([`${"a/".repeat(25)}other.rs`, `${"a".repeat(35)}c.rs`, "foo/bar/baz.rs"], dir), [
    "foo/bar/baz.rs",
  ]);
  assert.ok(Date.now() - startMs < 1000, "multi-** and multi-* glob matching must stay linear-time");

  writeFileSync(join(dir, "limits.toml"), "max_events = 100\n", "utf8");
  spawnSync("git", ["add", "limits.toml"], { cwd: dir });
  const subDir = join(dir, "crates/grdr-core");
  const deniedFromSubdir = evaluateSecurityAuditToolPayload(
    { tool_input: { command: 'git commit -m "chore(limits): update"' } },
    subDir,
  );
  assert.ok(deniedFromSubdir.some((m) => m.includes("Trust-core paths touched") && m.includes("limits.toml")));

  const rec = recordSecurityAudit({ cwd: subDir, reviewer: "subdir-judge" });
  assert.equal(rec.trustCoreTouched, true);
  assert.ok(rec.fileHashes["limits.toml"]);
  assert.deepEqual(
    evaluateSecurityAuditToolPayload({ tool_input: { command: 'git commit -m "chore(limits): update"' } }, subDir),
    [],
  );
});

test("collectNonUiFileHashes enforces strict head/staged/disk separation and rejects path traversal & symlinks", (t) => {
  const dir = makeTempRepo(t);
  const outside = mkdtempSync(join(tmpdir(), "grdr-saudit-out-"));
  t.after(() => rmSync(outside, { recursive: true, force: true }));
  const rel = "crates/grdr-core/src/bytes.rs";
  const v1 = Buffer.from([0x70, 0x75, 0x62, 0x00, 0xff, 0x0a]);
  const v2 = Buffer.from("pub fn v2() {}\n", "utf8");
  const v3 = Buffer.from("pub fn v3() {}\n", "utf8");

  writeFileSync(join(dir, rel), v1);
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): add bytes"], { cwd: dir });

  writeFileSync(join(dir, rel), v2);
  spawnSync("git", ["add", rel], { cwd: dir });
  writeFileSync(join(dir, rel), v3);

  const sha = (buf) => createHash("sha256").update(buf).digest("hex");
  assert.deepEqual(collectNonUiFileHashes(dir, [rel], { source: "head" }), { [rel]: sha(v1) });
  assert.deepEqual(collectNonUiFileHashes(dir, [rel], { source: "staged" }), { [rel]: sha(v2) });
  assert.deepEqual(collectNonUiFileHashes(dir, [rel], { source: "disk" }), { [rel]: sha(v3) });

  const untracked = "crates/grdr-core/src/untracked.rs";
  writeFileSync(join(dir, untracked), v2);
  assert.deepEqual(collectNonUiFileHashes(dir, [untracked], { source: "staged" }), {});
  assert.deepEqual(collectNonUiFileHashes(dir, [untracked], { source: "head" }), {});
  assert.deepEqual(collectNonUiFileHashes(dir, [untracked], { source: "disk" }), { [untracked]: sha(v2) });

  assert.deepEqual(collectNonUiFileHashes(dir, ["../../etc/passwd", "../outside.rs"], { source: "disk" }), {});

  const secret = join(outside, "secret.txt");
  writeFileSync(secret, "secret", "utf8");
  try {
    symlinkSync(secret, join(dir, "crates/grdr-core/src/ext_link.rs"));
    symlinkSync(join(dir, "README.md"), join(dir, "crates/grdr-core/src/int_link.rs"));
    assert.deepEqual(
      collectNonUiFileHashes(dir, ["crates/grdr-core/src/ext_link.rs", "crates/grdr-core/src/int_link.rs"], {
        source: "disk",
      }),
      {},
    );
  } catch {
    // Windows unprivileged environments may disallow file symlinks without Developer Mode.
  }
});

test("detects git rm deletions, git mv renames out of non-UI, and pathspec / -a / --amend commit bypasses", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/target.rs";
  writeFileSync(join(dir, rel), "pub fn v1() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): add target"], { cwd: dir });

  // 1. Positional pathspec commit on unstaged modification must be caught from disk.
  writeFileSync(join(dir, rel), "pub fn v2_unstaged() {}\n", "utf8");
  const deniedPathspec = evaluateSecurityAuditToolPayload(
    { tool_input: { command: `git commit -m "feat(core): pathspec" ${rel}` } },
    dir,
  );
  assert.ok(deniedPathspec.some((m) => m.includes("security-audit") && m.includes(rel)));

  // 2. git commit -a / -o / -i / --amend must also catch unaudited files.
  const deniedDashA = evaluateSecurityAuditToolPayload(
    { tool_input: { command: 'git commit -am "feat(core): dash-a"' } },
    dir,
  );
  assert.ok(deniedDashA.some((m) => m.includes("security-audit") && m.includes(rel)));

  const deniedOnly = evaluateSecurityAuditToolPayload(
    { tool_input: { command: `git commit -o -m "feat(core): only" -- ${rel}` } },
    dir,
  );
  assert.ok(deniedOnly.some((m) => m.includes("security-audit") && m.includes(rel)));

  // Reset unstaged change and test --amend on an unaudited HEAD commit.
  spawnSync("git", ["checkout", "--", rel], { cwd: dir });
  const deniedAmend = evaluateSecurityAuditToolPayload(
    { tool_input: { command: 'git commit --amend -m "feat(core): amend"' } },
    dir,
  );
  assert.ok(deniedAmend.some((m) => m.includes("security-audit") && m.includes(rel)));

  // 3. git mv out of non-UI to docs/ must still require security audit of the deleted non-UI file.
  mkdirSync(join(dir, "docs"), { recursive: true });
  spawnSync("git", ["mv", rel, "docs/moved.txt"], { cwd: dir });
  const deniedMv = evaluateSecurityAuditToolPayload(
    { tool_input: { command: 'git commit -m "refactor: move out"' } },
    dir,
  );
  assert.ok(deniedMv.some((m) => m.includes("security-audit") && m.includes(rel)));

  recordSecurityAudit({ cwd: dir, reviewer: "mv-judge", summary: "Reviewed removal" });
  assert.deepEqual(
    evaluateSecurityAuditToolPayload({ tool_input: { command: 'git commit -m "refactor: move out"' } }, dir),
    [],
  );

  // git rm --cached leaves untracked file on disk while staging deletion; --record and git commit must reconcile.
  const cachedDel = "crates/grdr-core/src/cached_del.rs";
  writeFileSync(join(dir, cachedDel), "pub fn x() {}\n", "utf8");
  spawnSync("git", ["add", cachedDel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): add cached_del"], { cwd: dir });
  spawnSync("git", ["rm", "--cached", cachedDel], { cwd: dir });
  recordSecurityAudit({ cwd: dir, reviewer: "rm-cached-judge", summary: "Reviewed unstage removal" });
  assert.deepEqual(
    evaluateSecurityAuditToolPayload({ tool_input: { command: 'git commit -m "chore: stop tracking"' } }, dir),
    [],
  );
  assert.ok(
    evaluateSecurityAuditToolPayload(
      { tool_input: { command: `git add ${cachedDel} && git commit -m "feat(core): re-add"` } },
      dir,
    ).some((m) => m.includes("updated or unaudited")),
  );
});

test("blocks shell bypasses (&, subshells, braces, $(), sudo, cd, nested shells, chained TOCTOU) and gh pr --head", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/bypass.rs";
  writeFileSync(join(dir, rel), "pub fn clean() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  recordSecurityAudit({ cwd: dir, reviewer: "judge-0", summary: "Clean v1" });

  const encodedCommit = Buffer.from('git commit -m "feat(core): encoded"', "utf16le").toString("base64");
  const bypassCommands = [
    'echo ok & git commit -m "feat(core): single-amp"',
    '(git commit -m "feat(core): subshell")',
    '{ git commit -m "feat(core): brace"; }',
    'echo $(git commit -m "feat(core): subst")',
    'echo "`git commit -m feat:dq-backtick`"',
    'Write-Output "a`"b"; git commit -m "feat(core): ps-quote"',
    "# don't push\ngit commit -m \"feat(core): comment-apostrophe\"",
    '<# don\'t #> git commit -m "feat(core): ps-block-comment"',
    "@'\ndon't break\n'@\ngit commit -m \"feat(core): ps-herestring\"",
    "@'\ndon't break\n'@\ngit `\ncommit -m \"feat(core): ps-here-cont\"",
    "cat <<'EOF' && git commit -m \"feat(core): bash-heredoc\"\ndon't break\nEOF",
    'git \\\ncommit -m "feat(core): bash-line-cont"',
    'git `\ncommit -m "feat(core): ps-line-cont"',
    'g\\it c\\ommit -m "feat(core): backslash-token"',
    'sudo -u root env -i git commit -m "feat(core): sudo-env"',
    'sudo -D . git commit -m "feat(core): sudo-dir"',
    'env -C. git commit -m "feat(core): env-c"',
    'env -S "git commit -m feat:env-s"',
    'env --split-string="git commit -m feat:env-split-eq"',
    'env -S"git commit -m feat:env-s-attached"',
    'bash -ec "git commit -m \\"feat(core): bundled-ec\\""',
    'bash -c -- "git commit -m \\"feat(core): dash-dash\\""',
    'cmd /c git commit -m "feat(core): unquoted-cmd-c"',
    'cmd /k git commit -m "feat(core): unquoted-cmd-k"',
    'pwsh -NoProfile -Command git commit -m "feat(core): unquoted-pwsh"',
    `pwsh -EncodedCommand ${encodedCommit}`,
    'eval "git commit -m feat:eval"',
    'iex "git commit -m feat:iex"',
    'Set-Location -Path . ; git commit -m "feat(core): set-loc"',
    'git --attr-source HEAD commit -m "feat(core): attr-src"',
    'git --config-env user.name=USERNAME commit -m "feat(core): cfg-env"',
    'git -c alias.x=commit x -m "feat(core): alias"',
    'declare -x GIT_INDEX_FILE=/tmp/idx && git commit -m "feat(core): declare-idx"',
    'env git_index_file=/tmp/idx git commit -m "feat(core): lower-idx"',
    'iex $EVIL_CMD',
    'bash -c "$EVIL_CMD"',
    `echo evil > ${rel} && git add ${rel} && git commit -m "feat(core): toctou-redir"`,
    `cp README.md ${rel} && git commit -m "feat(core): toctou-cp"`,
    'cd "$TMPDIR" && git commit -m "feat(core): dynamic-cd"',
    'cd ~ && git commit -m "feat(core): tilde-cd"',
    'export GIT_INDEX_FILE=/tmp/idx && git commit -m "feat(core): custom-idx"',
  ];

  // Unset stamp for bypass commands that don't mutate, then test dynamic/env/TOCTOU commands WITH valid stamp!
  for (const cmd of bypassCommands.slice(30)) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.length > 0, `expected dynamic/alias/env/TOCTOU denial for: ${cmd}`);
  }

  // Test git add + cd subdir + git commit (chainedAdd across subdirectory cd) and isolated subshell (cd ..).
  writeFileSync(join(dir, rel), "pub fn modified_disk() {}\n", "utf8");
  const deniedChainedSubdir = evaluateSecurityAuditToolPayload(
    { tool_input: { command: `git add ${rel} && cd crates/grdr-core && git commit -m "feat(core): cd-add"` } },
    dir,
  );
  assert.ok(deniedChainedSubdir.some((m) => m.includes("updated or unaudited") && m.includes(rel)));
  writeFileSync(join(dir, rel), "pub fn clean() {}\n", "utf8");

  // Remove audit stamp and verify all shell wrapper/comment/here-string/backtick/escape variants catch git commit.
  rmSync(resolveSecurityAuditRecordPath(dir));
  for (const cmd of bypassCommands.slice(0, 30)) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.some((m) => m.includes("security-audit")), `expected denial for: ${cmd}`);
  }
  const deniedBraceCd = evaluateSecurityAuditToolPayload(
    { tool_input: { command: `{ cd "${dir}"; } && git commit -m "feat(core): brace-cd"` } },
    tmpdir(),
  );
  assert.ok(deniedBraceCd.some((m) => m.includes("security-audit") && m.includes(rel)));

  const deniedNestedSubshell = evaluateSecurityAuditToolPayload(
    { tool_input: { command: `(cd "${dir}"; (cd "${tmpdir()}"); git commit -m "feat(core): nested-sub")` } },
    tmpdir(),
  );
  assert.ok(deniedNestedSubshell.some((m) => m.includes("security-audit") && m.includes(rel)));

  const deniedSubshellCd = evaluateSecurityAuditToolPayload(
    { tool_input: { command: '(cd /tmp/other) && git commit -m "feat(core): subshell-cd"' } },
    dir,
  );
  assert.ok(deniedSubshellCd.some((m) => m.includes("security-audit") && m.includes(rel)));

  const deniedMissingCmd = evaluateSecurityAuditToolPayload({ tool_name: "Bash", tool_input: {} }, dir);
  assert.ok(deniedMissingCmd.some((m) => m.includes("missing command field")));

  // Nonexistent repo / failing git diff / --git-dir pointing to another repo (including -C after --git-dir) must fail closed.
  const failClosedNonRepo = evaluateSecurityAuditToolPayload(
    { tool_input: { command: 'git -C nonexistent-dir-xyz commit -m "feat: fail-closed"' } },
    dir,
  );
  assert.ok(failClosedNonRepo.some((m) => m.includes("failing closed")));

  const otherRepo = makeTempRepo(t);
  writeFileSync(join(otherRepo, "crates/grdr-core/src/other.rs"), "pub fn other() {}\n", "utf8");
  spawnSync("git", ["add", "crates/grdr-core/src/other.rs"], { cwd: otherRepo });
  const deniedOtherGitDir = evaluateSecurityAuditToolPayload(
    { tool_input: { command: `git --git-dir="${join(otherRepo, ".git")}" --work-tree="${otherRepo}" commit -m "feat: gitdir"` } },
    dir,
  );
  assert.ok(deniedOtherGitDir.some((m) => m.includes("crates/grdr-core/src/other.rs")));

  const deniedEagerGitDir = evaluateSecurityAuditToolPayload(
    { tool_input: { command: `git --git-dir=.git -C "${otherRepo}" commit -m "feat: gitdir-order"` } },
    dir,
  );
  assert.ok(deniedEagerGitDir.some((m) => m.includes("crates/grdr-core/src/other.rs")));

  // Verify gh pr create --head and attached -B/-H flags target the specified head branch even when checked out on main.
  spawnSync("git", ["commit", "-m", "feat(core): commit on branch"], { cwd: dir });
  spawnSync("git", ["switch", "main"], { cwd: dir });
  for (const prCmd of [
    'gh pr create --base main --head feat/test-audit --body "Closes #79 per D-62"',
    'gh pr create -Bmain -Hfeat/test-audit --body "Closes #79 per D-62"',
  ]) {
    const deniedPrHead = evaluateSecurityAuditToolPayload({ tool_input: { command: prCmd } }, dir);
    assert.ok(deniedPrHead.some((m) => m.includes("security-audit") && m.includes(rel)), prCmd);
  }

  // Verify core.autocrlf=true clean-byte hashing and committed deletion shadowed by untracked file reconcile cleanly.
  spawnSync("git", ["switch", "feat/test-audit"], { cwd: dir });
  spawnSync("git", ["config", "core.autocrlf", "true"], { cwd: dir });
  writeFileSync(join(dir, rel), "pub fn clean() {}\r\n", "utf8");
  const shadowedDel = "crates/grdr-core/src/shadowed_del.rs";
  writeFileSync(join(dir, shadowedDel), "pub fn del1() {}\n", "utf8");
  spawnSync("git", ["add", shadowedDel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): add shadowed"], { cwd: dir });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });
  spawnSync("git", ["rm", shadowedDel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "chore(core): remove shadowed"], { cwd: dir });
  writeFileSync(join(dir, shadowedDel), "pub fn untracked_shadow() {}\n", "utf8");

  recordSecurityAudit({ cwd: dir, reviewer: "judge-final" });
  assert.deepEqual(
    evaluateSecurityAuditToolPayload(
      { tool_input: { command: 'gh pr create -Bmain -Hfeat/test-audit --body "Closes #79 per D-62"' } },
      dir,
    ),
    [],
  );
  assert.deepEqual(
    evaluateSecurityAuditToolPayload(
      { tool_input: { command: 'cd crates/grdr-core && git commit -m"add note"' } },
      dir,
    ),
    [],
  );
});

test("discoverChangedNonUiFiles returns union of branch diff, staged, unstaged, and untracked non-UI files", (t) => {
  const dir = makeTempRepo(t);
  const committedNonUi = "crates/grdr-core/src/committed.rs";
  const stagedNonUi = "programs/grdr-daemon/src/main.rs";
  const unstagedNonUi = "scripts/run.sh";
  const untrackedNonUi = "web/packages/api/src/client.ts";

  mkdirSync(join(dir, "programs/grdr-daemon/src"), { recursive: true });
  mkdirSync(join(dir, "scripts"), { recursive: true });

  writeFileSync(join(dir, committedNonUi), "pub fn c() {}\n", "utf8");
  writeFileSync(join(dir, unstagedNonUi), "#!/bin/sh\necho 1\n", "utf8");
  writeFileSync(join(dir, "web/apps/console/src/App.tsx"), "export const x = 1;\n", "utf8");
  writeFileSync(join(dir, "crates/grdr-ui-model/src/lib.rs"), "pub struct Ui;\n", "utf8");
  spawnSync("git", ["add", "."], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): branch base changes"], { cwd: dir });

  writeFileSync(join(dir, stagedNonUi), "fn main() {}\n", "utf8");
  spawnSync("git", ["add", stagedNonUi], { cwd: dir });
  writeFileSync(join(dir, unstagedNonUi), "#!/bin/sh\necho 2\n", "utf8");
  writeFileSync(join(dir, untrackedNonUi), "export const api = {};\n", "utf8");

  assert.deepEqual(discoverChangedNonUiFiles(dir), [
    committedNonUi,
    stagedNonUi,
    unstagedNonUi,
    untrackedNonUi,
  ]);
});

test("supports git worktree .git pointer files and rejects malformed .git files", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "grdr-saudit-wt-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  mkdirSync(join(dir, ".worktree-gitdir"), { recursive: true });
  mkdirSync(join(dir, "crates/grdr-core/src"), { recursive: true });
  writeFileSync(join(dir, ".git"), "gitdir: .worktree-gitdir\n", "utf8");
  writeFileSync(join(dir, "crates/grdr-core/src/lib.rs"), "pub fn ok() {}\n", "utf8");

  assert.equal(
    resolveSecurityAuditRecordPath(dir),
    join(dir, ".worktree-gitdir", "grdr-security-audit.json"),
  );
  recordSecurityAudit({ cwd: dir, files: ["crates/grdr-core/src/lib.rs"] });
  assert.deepEqual(evaluateSecurityAuditFiles(["crates/grdr-core/src/lib.rs"], dir), []);

  writeFileSync(join(dir, ".git"), "corrupt-pointer-file\n", "utf8");
  assert.throws(() => resolveSecurityAuditRecordPath(dir), /GRDR-HOOK-0001/);
});

test("CLI supports --record, fails closed on malformed stdin, and works through directory junctions", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/cli_test.rs";
  writeFileSync(join(dir, rel), "pub fn cli() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });

  const deniedCli = spawnSync(process.execPath, [HOOK_SCRIPT], {
    cwd: dir,
    input: JSON.stringify({ tool_input: { command: 'git commit -m "feat(core): cli"' }, cwd: dir }),
    encoding: "utf8",
  });
  assert.equal(deniedCli.status, 2);
  assert.match(deniedCli.stderr, /security-audit:/);

  const badStdin = spawnSync(process.execPath, [HOOK_SCRIPT], {
    cwd: dir,
    input: "{not-json",
    encoding: "utf8",
  });
  assert.equal(badStdin.status, 2);
  assert.match(badStdin.stderr, /failed closed/);

  const nonObjStdin = spawnSync(process.execPath, [HOOK_SCRIPT], {
    cwd: dir,
    input: "null",
    encoding: "utf8",
  });
  assert.equal(nonObjStdin.status, 2);
  assert.match(nonObjStdin.stderr, /expected JSON object/);

  const trailingFlag = spawnSync(process.execPath, [HOOK_SCRIPT, "--record", "--unresolved"], {
    cwd: dir,
    encoding: "utf8",
  });
  assert.equal(trailingFlag.status, 2);
  assert.match(trailingFlag.stderr, /GRDR-HOOK-0001/);

  const goodRecord = spawnSync(
    process.execPath,
    [
      HOOK_SCRIPT,
      "--record",
      "--verdict",
      "pass",
      "--unresolved",
      "0",
      "--unresolved-hardening",
      "0",
      "--reviewer",
      "cli-judge",
      "--summary",
      "Verified cleanly",
    ],
    { cwd: dir, encoding: "utf8" },
  );
  assert.equal(goodRecord.status, 0, goodRecord.stderr);
  assert.match(goodRecord.stdout, /Recorded security audit \(pass, 1 non-UI file\(s\)\)/);

  const linkDir = mkdtempSync(join(tmpdir(), "grdr-saudit-junc-"));
  t.after(() => rmSync(linkDir, { recursive: true, force: true }));
  const linkedHooks = join(linkDir, "hooks-link");
  symlinkSync(HERE, linkedHooks, process.platform === "win32" ? "junction" : "dir");
  const allowedViaJunction = spawnSync(process.execPath, [join(linkedHooks, "security-audit-check.mjs")], {
    cwd: dir,
    input: JSON.stringify({ tool_input: { command: 'git commit -m "feat(core): cli"' }, cwd: dir }),
    encoding: "utf8",
  });
  assert.equal(allowedViaJunction.status, 0, allowedViaJunction.stderr);
});

test("blocks Round 4 bypasses (brace expansion, heredoc+cont, $'...', &(\"git\"), -Comm/-Enco, env -S, wrappers, include.path, --amen/--al)", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/r4.rs";
  writeFileSync(join(dir, rel), "pub fn r4_v1() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): r4 base"], { cwd: dir });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });

  writeFileSync(join(dir, rel), "pub fn r4_v2() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  recordSecurityAudit({ cwd: dir, reviewer: "judge-r4", summary: "Clean v2" });

  const b64Commit = Buffer.from('git commit -m "feat(core): ps-enco"', "utf16le").toString("base64");
  const alwaysDenied = [
    'git {commit,-m} "feat(core): brace-exp"',
    'git {commit,} -m "feat(core): brace-empty"',
    '{git,echo} commit -m "feat(core): brace-cmd"',
    '&("gi" + "t") commit -m "feat(core): ps-dyn-call"',
    'git ("com" + "mit") -m "feat(core): ps-dyn-arg"',
    "pwsh -Command -",
    "echo commit | xargs git",
    'echo x | xargs git commit -m "feat(core): xargs-git"',
    'git -c include.path=/tmp/evil commit -m "feat(core): inc"',
    'git -c includeIf.gitdir:/.path=/tmp/evil commit -m "feat(core): incif"',
    'git -c core.hooksPath=/tmp/hooks commit -m "feat(core): hookspath"',
    'git commit --unknown-evil-flag -m "feat(core): unk"',
  ];
  for (const cmd of alwaysDenied) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.length > 0, `expected fail-closed denial for: ${cmd}`);
  }

  for (const safeCmd of [
    'cargo test -- foo{bar,baz}',
    'echo ok | xargs wc -l',
    'if ($hits) { Write-Output $hits }',
    'foreach ($f in $files) { Select-String -Path $f -Pattern ([char]0x2014) }',
    'git commit -m "{quoted,brace}"',
    '&("git") commit -m "feat(core): ps-call-paren"',
    '. ("git") commit -m "feat(core): ps-dot-paren"',
    'git ("commit") -m "feat(core): ps-arg-paren"',
    'git commit --me "feat(core): msg-abbrev"',
  ]) {
    assert.deepEqual(evaluateSecurityAuditToolPayload({ tool_input: { command: safeCmd } }, dir), [], safeCmd);
  }

  // Test --al detecting unstaged disk change and --amen detecting amended HEAD~1 change even when staged matches clean stamp.
  writeFileSync(join(dir, rel), "pub fn r4_dirty() {}\n", "utf8");
  const deniedAllAbbrev = evaluateSecurityAuditToolPayload({ tool_input: { command: 'git commit --al -m "feat(core): al"' } }, dir);
  assert.ok(deniedAllAbbrev.some((m) => m.includes("updated or unaudited")), deniedAllAbbrev.join("\n"));
  writeFileSync(join(dir, rel), "pub fn r4_v2() {}\n", "utf8");

  rmSync(resolveSecurityAuditRecordPath(dir));
  const unstampedBypasses = [
    "cat <<'EOF'\n'\nEOF\ngit \\\ncommit -m \"feat(core): heredoc-cont\"",
    "echo $'don\\'t' && git commit -m \"feat(core): ansic-quote\"",
    'git $\'commit\' -m "feat(core): ansic-sub"',
    'git $\'\\x63ommit\' -m "feat(core): ansic-hex"',
    'git $"commit" -m "feat(core): locale-sub"',
    '&("git") commit -m "feat(core): ps-call-paren"',
    '. ("git") commit -m "feat(core): ps-dot-paren"',
    'git ("commit") -m "feat(core): ps-arg-paren"',
    'pwsh -Comm "git commit -m \'feat(core): ps-comm\'"',
    `pwsh -Enco ${b64Commit}`,
    'pwsh -Command:"git commit -m \'feat(core): ps-colon\'"',
    'env -S "-i FOO=1" git commit -m "feat(core): env-s-prefix"',
    'env -C crates/grdr-core -S "FOO=1" git commit -m "feat(core): env-c-s"',
    'env --unset HOME git commit -m "feat(core): env-unset"',
    'exec -a evilgit git commit -m "feat(core): exec-a"',
    'nice --adjustment 10 git commit -m "feat(core): nice-adj"',
    'sudo -U nobody git commit -m "feat(core): sudo-U"',
    'timeout 10 git commit -m "feat(core): timeout"',
    'stdbuf -o0 git commit -m "feat(core): stdbuf"',
  ];
  for (const cmd of unstampedBypasses) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.some((m) => m.includes("security-audit:")), `expected unstamped denial for: ${cmd}`);
  }

  // Test --amen detects amended parent commit non-UI file even when staged is empty against HEAD.
  spawnSync("git", ["commit", "-m", "feat(core): commit v2"], { cwd: dir });
  writeFileSync(join(dir, "README.md"), "# README change\n", "utf8");
  spawnSync("git", ["add", "README.md"], { cwd: dir });
  const deniedAmend = evaluateSecurityAuditToolPayload(
    { tool_input: { command: 'git commit --amen -m "feat(core): amend"' } },
    dir,
  );
  assert.ok(deniedAmend.some((m) => m.includes(rel)), deniedAmend.join("\n"));

  // Hardening 1: external --git-dir with core.worktree without --work-tree uses core.worktree rather than invoking cwd.
  const extBase = mkdtempSync(join(tmpdir(), "grdr-core-wt-"));
  t.after(() => rmSync(extBase, { recursive: true, force: true }));
  const extGitDir = join(extBase, "ext.git");
  const realWt = join(extBase, "real-wt");
  const decoyCwd = join(extBase, "decoy");
  mkdirSync(join(realWt, "crates/grdr-core/src"), { recursive: true });
  mkdirSync(join(decoyCwd, "crates/grdr-core/src"), { recursive: true });
  spawnSync("git", ["init", "--bare", extGitDir]);
  spawnSync("git", ["--git-dir", extGitDir, "config", "core.bare", "false"]);
  spawnSync("git", ["--git-dir", extGitDir, "config", "core.worktree", realWt]);
  const wtRel = "crates/grdr-core/src/wt.rs";
  writeFileSync(join(realWt, wtRel), "pub fn wt_v1() {}\n", "utf8");
  writeFileSync(join(decoyCwd, wtRel), "pub fn wt_v1() {}\n", "utf8");
  spawnSync("git", ["--git-dir", extGitDir, "--work-tree", realWt, "add", wtRel]);
  spawnSync("git", ["--git-dir", extGitDir, "--work-tree", realWt, "commit", "-m", "feat: wt init"]);
  recordSecurityAudit({ cwd: realWt, files: [wtRel], reviewer: "judge-wt" });
  const stampedWtPath = resolveSecurityAuditRecordPath(realWt, extGitDir);
  writeFileSync(stampedWtPath, readFileSync(resolveSecurityAuditRecordPath(realWt)));
  writeFileSync(join(realWt, wtRel), "pub fn wt_tampered() {}\n", "utf8");
  const deniedExtWt = evaluateSecurityAuditToolPayload(
    { tool_input: { command: `git --git-dir="${extGitDir}" commit -am "feat: ext-wt"` } },
    decoyCwd,
  );
  assert.ok(deniedExtWt.some((m) => m.includes("updated or unaudited") && m.includes(wtRel)), deniedExtWt.join("\n"));

  // Hardening 3: staged trust-core.paths + trustCoreFiles type/emptiness validation.
  const tcRepo = makeTempRepo(t);
  writeFileSync(join(tcRepo, "security/trust-core.paths"), "custom-secret/**\n", "utf8");
  spawnSync("git", ["add", "security/trust-core.paths"], { cwd: tcRepo });
  writeFileSync(join(tcRepo, "security/trust-core.paths"), "# reverted on disk\n", "utf8");
  mkdirSync(join(tcRepo, "custom-secret"), { recursive: true });
  writeFileSync(join(tcRepo, "custom-secret/key.txt"), "secret\n", "utf8");
  spawnSync("git", ["add", "custom-secret/key.txt"], { cwd: tcRepo });
  const deniedStagedTc = evaluateSecurityAuditToolPayload({ tool_input: { command: 'git commit -m "feat: tc"' } }, tcRepo);
  assert.ok(deniedStagedTc.some((m) => m.includes("custom-secret/key.txt") && m.includes("Trust-core paths touched")), deniedStagedTc.join("\n"));

  const cleanTc = makeTempRepo(t);
  writeFileSync(join(cleanTc, rel), "pub fn x() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: cleanTc });
  const recBadList = recordSecurityAudit({ cwd: cleanTc, reviewer: "judge-badlist" });
  recBadList.trustCoreFiles = [123];
  writeFileSync(resolveSecurityAuditRecordPath(cleanTc), JSON.stringify(recBadList), "utf8");
  const deniedBadList = evaluateSecurityAuditFiles([rel], cleanTc);
  assert.ok(deniedBadList.some((m) => m.includes("metadata valid: false")), deniedBadList.join("\n"));

  // Hardening 4: symlinked .git rejected even when invoked from a subdirectory.
  const subDir = join(cleanTc, "crates/grdr-core/src");
  assert.equal(resolveSecurityAuditRecordPath(subDir), resolveSecurityAuditRecordPath(cleanTc));
  const symRepo = mkdtempSync(join(tmpdir(), "grdr-symdotgit-"));
  t.after(() => rmSync(symRepo, { recursive: true, force: true }));
  const realGitDir = join(symRepo, "actual-git");
  const wtDir = join(symRepo, "repo");
  mkdirSync(realGitDir, { recursive: true });
  mkdirSync(join(wtDir, "crates/grdr-core"), { recursive: true });
  spawnSync("git", ["init", "--separate-git-dir", realGitDir], { cwd: wtDir });
  rmSync(join(wtDir, ".git"), { force: true });
  symlinkSync(realGitDir, join(wtDir, ".git"), process.platform === "win32" ? "junction" : "dir");
  assert.throws(() => resolveSecurityAuditRecordPath(join(wtDir, "crates/grdr-core")), /GRDR-HOOK-0001/);
});

test("blocks Round 5 bypasses (cmd subst, case/escaped parens, $1/$@, stdin shell, PS assign/wd, xargs -i, cross-repo GIT_DIR)", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/r5.rs";
  writeFileSync(join(dir, rel), "pub fn r5_base() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): r5 base"], { cwd: dir });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });

  writeFileSync(join(dir, rel), "pub fn r5_v2() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  recordSecurityAudit({ cwd: dir, reviewer: "judge-r5", summary: "Clean r5" });

  const otherRepo = makeTempRepo(t);
  const otherRel = "crates/grdr-core/src/other_r5.rs";
  writeFileSync(join(otherRepo, otherRel), "pub fn other() {}\n", "utf8");
  spawnSync("git", ["add", otherRel], { cwd: otherRepo });

  const spacedBase = mkdtempSync(join(tmpdir(), "grdr r5 space "));
  t.after(() => rmSync(spacedBase, { recursive: true, force: true }));
  const spacedGitDir = join(spacedBase, "spaced .git");
  const spacedWt = join(spacedBase, "wt");
  mkdirSync(join(spacedWt, "crates/grdr-core/src"), { recursive: true });
  spawnSync("git", ["init", "--bare", spacedGitDir]);
  spawnSync("git", ["--git-dir", spacedGitDir, "config", "core.bare", "false"]);
  spawnSync("git", ["--git-dir", spacedGitDir, "config", "core.worktree", spacedWt]);
  writeFileSync(join(spacedWt, otherRel), "pub fn spaced() {}\n", "utf8");
  spawnSync("git", ["--git-dir", spacedGitDir, "--work-tree", spacedWt, "add", otherRel]);

  const alwaysDeniedWithStamp = [
    'git `echo commit` -m "feat: bt"',
    '`echo git` commit -m "feat: bt2"',
    'git "$(echo commit)" -m "feat: dq"',
    '"$(echo git)" commit -m "feat: dq2"',
    'gh "$(echo pr)" create --base main',
    'SUB=commit; git $SUB -m "feat: var"',
    'X="git commit"; $X',
    'CMD=git; $CMD commit -m "feat: var2"',
    'echo "$(git commit"',
    "bash -c '$1 commit -m \"feat: p\"' _ git",
    "bash -c '$@' _ git commit -m \"feat: at\"",
    'bash -c \'eval $1\' _ "git commit -m feat:e"',
    'echo "git commit -m feat:pipe" | bash',
    "pwsh -",
    "bash -s",
    'echo x | xargs -i git commit -m "feat: xi"',
    "echo x | xargs -e git commit",
    "echo x | xargs -l git commit",
    `pwsh -WorkingDirectory "${otherRepo}" -Command "git commit -m 'feat: wd'"`,
    '$x = & $dynCmd commit -m "feat: ps-dyn-var"',
    `export GIT_DIR=.git && cd "${otherRepo}" && git commit -m "feat(core): x"`,
    `set -a && GIT_DIR="${otherRepo}/.git" && git commit -m "feat(core): set-a"`,
    `$env:GIT_DIR = "${spacedGitDir}" ; $env:GIT_WORK_TREE = "${spacedWt}" ; git commit -m "feat(core): spaced"`,
    'cmd /c "set GIT_INDEX_FILE=/tmp/idx & git commit -m feat:cmdset"',
    'git --exec-path=/tmp/evil commit -m "feat: execp"',
    'env GIT_EXEC_PATH=/tmp/evil git commit -m "feat: envexec"',
    'git -c core.autocrlf=false commit -m "feat: acrlf"',
    'git -c core.editor="sh -c evil" commit -m "feat: editor"',
    `env GIT_DIR="${otherRepo}/.git" gh pr create --base main --head feat/test-audit --body "Closes #79 per D-62"`,
  ];
  for (const cmd of alwaysDeniedWithStamp) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.length > 0, `expected denial even with stamp for: ${cmd}`);
  }

  for (const allowedCmd of [
    'git commit --amend --no-edit',
    'git commit --no-verify -m "feat(core): nv"',
    "@'\n{\"ok\":true}\n'@ | node -e \"console.log(1)\"",
    '$x = git commit -m "feat(core): psa"',
    '$x = (git commit -m "feat(core): ps-paren")',
    '$x = &("git") commit -m "feat(core): psac"',
    'foreach ($f in $files) { $lines = (Get-Content $f).Count; Write-Output "$f`: $lines lines" }',
    "$x=echo ok",
  ]) {
    assert.deepEqual(evaluateSecurityAuditToolPayload({ tool_input: { command: allowedCmd } }, dir), [], allowedCmd);
  }

  rmSync(resolveSecurityAuditRecordPath(dir));
  const unstampedCaught = [
    "echo \"$(case x in a) git commit -m 'feat: c' ;; esac)\"",
    'echo "`git commit -m feat:btq`"',
    "echo \"$(echo \\(; git commit -m 'feat: ep')\"",
    "echo \"$(cat <<'EOF'\n(\nEOF\n; git commit -m 'feat: hp')\"",
    '$x = git commit -m "feat: psa"',
    '$x = (git commit -m "feat: ps-paren")',
    '$x = &("git") commit -m "feat: psac"',
    'env -iS "git commit -m feat:eis"',
    '/usr/bin/time -o /tmp/t.log git commit -m "feat: time-o"',
    'flock /tmp/lk git commit -m "feat: flock"',
    'flock /tmp/lk -c "git commit -m feat:flock-c"',
    'doas git commit -m "feat: doas"',
    'taskset -c 0 git commit -m "feat: taskset-c"',
    'taskset 0x1 git commit -m "feat: taskset-mask"',
    'script -q -c "git commit -m feat:script" /dev/null',
  ];
  for (const cmd of unstampedCaught) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.some((m) => m.includes("security-audit:")), `expected unstamped denial for: ${cmd}`);
  }
});

test("blocks Round 6 bypasses (export/for/read $X, PS '.', nested backticks, bundled wrappers, bash stdin, cmd ^/!VAR!, case, work-tree, aliases, pushd/popd)", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/r6.rs";
  writeFileSync(join(dir, rel), "pub fn r6_base() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): r6 base"], { cwd: dir });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });

  writeFileSync(join(dir, rel), "pub fn r6_v2() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  recordSecurityAudit({ cwd: dir, reviewer: "judge-r6", summary: "Clean r6" });

  const otherRepo = makeTempRepo(t);
  const otherRel = "crates/grdr-core/src/other_r6.rs";
  writeFileSync(join(otherRepo, otherRel), "pub fn other() {}\n", "utf8");
  spawnSync("git", ["add", otherRel], { cwd: otherRepo });

  const cleanOther = makeTempRepo(t);
  writeFileSync(join(cleanOther, rel), "pub fn clean_other() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: cleanOther });
  recordSecurityAudit({ cwd: cleanOther, reviewer: "judge-clean-other", summary: "Clean other" });
  const alwaysDeniedWithStamp = [
    'export X="git commit -m feat:x" && $X',
    'for X in "git commit -m feat:x"; do $X; done',
    'echo "git commit -m feat:x" | { read X; $X; }',
    '$X',
    '. $dynCmd commit -m "feat: ps-dot-dyn"',
    'echo "git commit -m feat:x" | bash -O extglob',
    "bash <<'EOF'\necho 'hi\ngit commit -m \"feat: hd\"\nEOF",
    'cmd /v:on /c "set X=git& !X! commit -m feat:x"',
    'git update-index crates/grdr-core/src/r6.rs && git commit -m "feat: ui"',
    'dd if=README.md of=crates/grdr-core/src/r6.rs && git add crates/grdr-core/src/r6.rs && git commit -m "feat: dd"',
    'cpi README.md crates/grdr-core/src/r6.rs ; git add crates/grdr-core/src/r6.rs ; git commit -m "feat: cpi"',
    'git -c gpg.program=/tmp/evil commit -m "feat: gpg"',
    'git -c filter.x.clean=evil commit -m "feat: filter"',
    'git -c core.attributesfile=/tmp/attr commit -m "feat: attr"',
    `si Env:GIT_DIR "${otherRepo}/.git" ; git commit -m "feat: si-gitdir"`,
    'si Env:GIT_INDEX_FILE /tmp/idx ; git commit -m "feat: si-idx"',
    `Set-Item Env:\\GIT_DIR -Value "${otherRepo}/.git" ; git commit -m "feat: env-bs"`,
    `Push-Location "${otherRepo}" ; git commit -m "feat: push-loc"`,
    `chdir "${otherRepo}" && git commit -m "feat: chdir"`,
    'popd && git commit -m "feat: unpaired-popd"',
  ];
  for (const cmd of alwaysDeniedWithStamp) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.length > 0, `expected denial even with stamp for: ${cmd}`);
  }
  const deniedWorkTreeSplit = evaluateSecurityAuditToolPayload(
    { tool_input: { command: `git --work-tree="${cleanOther}" commit -m "feat: wt-split"` } },
    otherRepo,
  );
  assert.ok(deniedWorkTreeSplit.some((m) => m.includes(otherRel)), deniedWorkTreeSplit.join("\n"));

  for (const allowedSafe of [
    "@'\nhi\n'@.Trim()",
    "@{a=@'\nhi\n'@}",
    'echo ok <<< "hello"',
    '$x=sudo echo ok',
    'echo "$(echo in case; git status)"',
    'pushd crates/grdr-core && popd && git commit -m "feat: balanced-popd"',
  ]) {
    assert.deepEqual(evaluateSecurityAuditToolPayload({ tool_input: { command: allowedSafe } }, dir), [], allowedSafe);
  }

  rmSync(resolveSecurityAuditRecordPath(dir));
  const unstampedCaught = [
    '. git commit -m "feat: ps-dot"',
    '."git" commit -m "feat: ps-dot-quoted"',
    'echo `echo \\`git commit -m "feat: nested"\\``',
    'echo "`echo \\`git commit -m \\"feat: nested2\\"\\``"',
    'script --command="git commit -m feat:x" /dev/null',
    'script -qc "git commit -m feat:x" /dev/null',
    'flock /tmp/lk --command="git commit -m feat:x"',
    'flock -nc "git commit -m feat:x" /tmp/lk',
    'sudo -Eu root git commit -m "feat: sudo-eu"',
    'env -iC . git commit -m "feat: env-ic"',
    'echo x | xargs -0n 1 git commit -m "feat: xargs-0n"',
    'taskset ff git commit -m "feat: taskset-hex"',
    'cmd /c"git commit -m feat:cmd-attached"',
    'cmd /c "g^it c^ommit -m feat:cmd-caret"',
    "echo \"$(case x in a|esac) git commit -m 'feat: case1' ;; esac)\"",
    "echo \"$(case x in (esac) git commit -m 'feat: case2' ;; esac)\"",
    "echo \"$(case x in @(a|b)) git commit -m 'feat: case3' ;; esac)\"",
    "(Write-Output 1)#'\ngit commit -m \"feat: ps-paren-comment\"",
    'pushd crates/grdr-core && popd && git commit -m "feat: balanced-popd"',
  ];
  for (const cmd of unstampedCaught) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.some((m) => m.includes("security-audit:")), `expected unstamped denial for: ${cmd}`);
  }
});

test("blocks Round 7 bypasses (PS here-strings, bash stdin/redirs/+e/-o, comments, case esac, env -S/-R, cmd for/if/@/call, cond cd) and allows GEMINI.md $env:", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/r7.rs";
  writeFileSync(join(dir, rel), "pub fn r7_base() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): r7 base"], { cwd: dir });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });

  writeFileSync(join(dir, rel), "pub fn r7_v2() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  recordSecurityAudit({ cwd: dir, reviewer: "judge-r7", summary: "Clean r7" });

  const cleanOther = makeTempRepo(t);
  writeFileSync(join(cleanOther, rel), "pub fn clean_other() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: cleanOther });
  recordSecurityAudit({ cwd: cleanOther, reviewer: "judge-clean-r7", summary: "Clean other r7" });

  const alwaysDeniedWithStamp = [
    '$env:GIT_DIR = $dynPath ; git commit -m "feat: ps-dyn-env"',
    '$env:GIT_DIR=$dynPath ; git commit -m "feat: ps-dyn-env2"',
    '$env:GIT_INDEX_FILE = "/tmp/idx" ; git commit -m "feat: ps-idx"',
    'bash <<< "git commit -m feat:hs"',
    'echo "git commit -m feat:x" | bash > /dev/null',
    "bash <<'EOF' > /dev/null\ngit commit -m \"feat: r7\"\nEOF",
    "bash < script.sh",
    'echo "git commit -m feat:x" | bash +e',
    'cmd /c "for /f %i in (\'git commit -m feat:x\') do @echo %i"',
    'cmd /c "if 1==1 @git commit -m feat:x"',
    `(cd "${cleanOther}" && pushd "${cleanOther}") && popd && git commit -m "feat: sub-dirstack"`,
    `false && cd "${cleanOther}" ; git commit -m "feat: false-cd"`,
    `if ($false) { cd "${cleanOther}" } ; git commit -m "feat: ps-false-cd"`,
    `true || cd "${cleanOther}" && git commit -m "feat: true-or-cd"`,
    `Push-Location -StackName "${cleanOther}" "${dir}" ; Pop-Location -StackName "${cleanOther}" ; git commit -m "feat: stackname"`,
    'Set-Content .git/hooks/pre-commit "env:x" ; git commit -m "feat: sc-mutation"',
    'git update-ref refs/remotes/origin/main HEAD && gh pr create --base main --head feat/test --body "Closes #79 per D-62"',
  ];
  for (const cmd of alwaysDeniedWithStamp) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.length > 0, `expected fail-closed denial for: ${cmd}`);
  }

  for (const allowedSafe of [
    '$env:GH_REPO = "416rehman/Guardrails"; $env:GH_PROMPT_DISABLED = "1"; $env:CARGO_TERM_COLOR = "never"; cargo test --workspace',
    '$env:CARGO_TERM_COLOR="never"; git commit -m "feat(core): r7"',
    'Write-Output a[0]# ; git status',
  ]) {
    assert.deepEqual(evaluateSecurityAuditToolPayload({ tool_input: { command: allowedSafe } }, dir), [], allowedSafe);
  }

  // Subdirectory `git --work-tree=.` inspects actual repo .git instead of skipping ctx.
  const subDir = join(dir, "crates/grdr-core");
  assert.deepEqual(evaluateSecurityAuditToolPayload({ tool_input: { command: 'git --work-tree=. commit -m "feat: wt-dot"' } }, subDir), []);

  // Glob `**/**` matches cleanly without catastrophic backtracking.
  const mStarStar = globSpecToMatcher("**/**");
  assert.ok(mStarStar && mStarStar.test("crates/grdr-core/src/lib.rs"));

  rmSync(resolveSecurityAuditRecordPath(dir));
  const unstampedCaught = [
    "iex @'\ngit commit -m \"feat: ps-hs-iex\"\n'@",
    "pwsh -Command @'\ngit commit -m \"feat: ps-hs-pwsh\"\n'@",
    "& @'\ngit\n'@ commit -m \"feat: ps-hs-call\"",
    "git @'\ncommit\n'@ -m \"feat: ps-hs-arg\"",
    'bash -onoclobber -c "git commit -m feat:onoclobber"',
    'Write-Output ``# ; git commit -m "feat: ps-tick-hash"',
    'Write-Output a[0]# ; git commit -m "feat: ps-bracket-hash"',
    'echo `echo 1`# ; git commit -m "feat: bash-tick-hash"',
    "echo \"$(case x in a) echo esac ;; b) git commit -m 'feat: esac-arg' ;; esac)\"",
    "echo \"$(case x in \\ esac) git commit -m 'feat: esc-esac' ;; esac)\"",
    'env -S "git commit -m feat:multi-s" -S "--allow-empty"',
    'script /dev/null -c "git commit -m feat:script-pos"',
    'sudo -R / git commit -m "feat: sudo-R"',
    'echo x | xargs -J % git commit -m "feat: xargs-J"',
    'cmd /c "call git commit -m feat:cmd-call"',
    'cmd /c "@git commit -m feat:cmd-at"',
  ];
  for (const cmd of unstampedCaught) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.some((m) => m.includes("security-audit:")), `expected unstamped denial for: ${cmd}`);
  }
});

test("blocks Round 8 bypasses (subshell comments, unclosed quote, PS @\"\"@ backticks, param/case subst, abbreviated PS env flags, cond/pipe/bg cd, GNU wrapper prefixes, pwsh brace cwd, cmd slices) and allows safe patterns", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/r8.rs";
  writeFileSync(join(dir, rel), "pub fn r8_base() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): r8 base"], { cwd: dir });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });

  writeFileSync(join(dir, rel), "pub fn r8_v2() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  // Leave `dir` UNSTAMPED while `cleanOther` IS stamped cleanly so directory escapes and fail-closed gates can be tested directly.
  const cleanOther = makeTempRepo(t);
  writeFileSync(join(cleanOther, rel), "pub fn clean_other_r8() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: cleanOther });
  recordSecurityAudit({ cwd: cleanOther, reviewer: "judge-clean-r8", summary: "Clean other r8" });

  // 1) Commands targeting dirty `dir` or unverified/fail-closed overrides MUST be denied (including with cleanOther stamped, and after stamping `dir` too for fail-closed paths).
  const deniedUnstamped = [
    ": <<'PS'\n<#\nPS\n(echo 1)#'\ngit commit -m \"feat: sub-hash\"\n# #>",
    'echo $(echo 1)# ; git commit -m "feat: subst-hash"',
    "<# ' #> & @\"\ng`it\n\"@ commit -m \"feat: ps-dqhs-call\" ; # '",
    "<# ' #> git @\"\ncom`mit\n\"@ -m \"feat: ps-dqhs-arg\" ; # '",
    "echo \"$(! case a in a) git commit -m 'feat: bang-case' ;; esac)\"",
    "echo \"$(if case a in a) git commit -m 'feat: if-case' ;; esac; then :; fi)\"",
    'echo "$(echo ${x:-)} ; git commit -m \'feat: param-close\')"',
    'echo "$(echo ${x:-(} ; git commit -m \'feat: param-paren\')"',
    `Set-Item -Val "${dir}/.git" Env:GIT_DIR ; git commit -m "feat: ps-abrev-val"`,
    `Set-Item ("Env:" + "GIT_DIR") "${dir}/.git" ; git commit -m "feat: ps-dyn-env-key"`,
    `Push-Location Env: ; Set-Item GIT_DIR "${dir}/.git" ; Pop-Location ; git commit -m "feat: env-drive"`,
    `$env:GIT_DIR = "${cleanOther}/.git" -replace "clean","dirty" ; git commit -m "feat: ps-multi-tok"`,
    `false && cd "${cleanOther}" ; (git commit -m "feat: and-subshell")`,
    `if ($false) { cd "${cleanOther}" } ; (git commit -m "feat: block-subshell")`,
    `try { } catch { cd "${cleanOther}" } ; git commit -m "feat: try-catch-cd"`,
    `if false; then cd "${cleanOther}"; fi ; git commit -m "feat: bash-if-cd"`,
    `echo ok | cd "${cleanOther}" ; git commit -m "feat: pipe-cd"`,
    `cd "${cleanOther}" & git commit -m "feat: bg-cd"`,
    'echo x | xargs --replace git commit -m "feat: xargs-replace"',
    'echo x | xargs --eof git commit -m "feat: xargs-eof"',
    'env --sp="git commit -m feat:env-sp" echo ignored',
    'script --com="git commit -m feat:script-com" /dev/null',
    'echo "git commit -m feat:eo" | bash -eo pipefail',
    'echo "git commit -m feat:amp" | bash &>> /dev/null',
    "pwsh -Command 'git' 'commit -m feat:ps-multi-cmd'",
    `<# ' #> pwsh -WorkingDirectory "${dir}" -Command { git commit -m "feat: pwsh-brace-wd" } ; # '`,
    'pwsh -CommandWithArgs "git commit -m feat:cwa" extraArg',
    'cmd /c "set X=gitxx& call %X:~0,3% commit -m feat:cmd-slice"',
    'cmd /c "%OS:~0,0%git commit -m feat:cmd-empty-slice"',
    'cmd /c "call call git commit -m feat:cmd-double-call"',
    'cmd /c "call;git commit -m feat:cmd-call-semi"',
  ];
  for (const cmd of deniedUnstamped) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.some((m) => m.includes("security-audit:")), `expected denial while dir unstamped for: ${cmd}`);
  }

  // Test cleanOther as cwd with `sudo -R` or escaping into `dir` via `-WorkingDirectory` / `Set-Item -Val` / cond cd:
  const deniedFromClean = [
    'sudo -R /other_root git commit -m "feat: sudo-chroot"',
    `Set-Item -Val "${dir}/.git" Env:GIT_DIR ; git commit -m "feat: escape-setitem"`,
    `Push-Location Env: ; Set-Item GIT_DIR "${dir}/.git" ; Pop-Location ; git commit -m "feat: escape-envdrive"`,
    `$env:GIT_DIR = "${cleanOther}/.git" -replace "clean","dirty" ; git commit -m "feat: escape-ps-replace"`,
    `<# ' #> pwsh -WorkingDirectory "${dir}" -Command { git commit -m "feat: escape-brace-wd" } ; # '`,
    `false && cd "${cleanOther}" ; (git commit -m "feat: fail-closed-and-sub")`,
    `if ($false) { cd "${cleanOther}" } ; (git commit -m "feat: fail-closed-if-sub")`,
    `try { } catch { cd "${cleanOther}" } ; git commit -m "feat: fail-closed-catch"`,
    `if false; then cd "${cleanOther}"; fi ; git commit -m "feat: fail-closed-bash-if"`,
    `echo ok | cd "${cleanOther}" ; git commit -m "feat: fail-closed-pipe-cd"`,
    `cd "${cleanOther}" & git commit -m "feat: fail-closed-bg-cd"`,
  ];
  for (const cmd of deniedFromClean) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, cleanOther);
    assert.ok(res.length > 0, `expected denial from cleanOther for: ${cmd}`);
  }

  // Unclosed shell quote must fail closed even on a stamped repo.
  recordSecurityAudit({ cwd: dir, reviewer: "judge-r8", summary: "Clean r8" });
  const unclosedQuote = evaluateSecurityAuditToolPayload({ tool_input: { command: 'git commit -m "unclosed' } }, dir);
  assert.ok(unclosedQuote.some((m) => m.includes("security-audit:")));

  // Safe patterns that MUST be allowed cleanly on stamped `dir`:
  for (const safeCmd of [
    `echo "$(case x in a) echo hi;; esac>/dev/null)"`,
    'git commit -m "feat(core): \\"fix\\" {a,b} \\"ok\\""',
    "bash -c 'date +%Y-%m-%d'",
  ]) {
    assert.deepEqual(evaluateSecurityAuditToolPayload({ tool_input: { command: safeCmd } }, dir), [], safeCmd);
  }
});

test("blocks Round 9 bypasses (scoped export/env, brace/coproc/newline conds, select/case esac, param/escaped-hash/case-$(...), ps slash, cmd comma/eq, rel Env:\\, git config/revert) and hardens PR headRef + autocrlf + unclosed backticks", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/r9.rs";
  writeFileSync(join(dir, rel), "pub fn r9_base() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): r9 base"], { cwd: dir });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });

  writeFileSync(join(dir, rel), "pub fn r9_v2() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });

  const cleanOther = makeTempRepo(t);
  writeFileSync(join(cleanOther, rel), "pub fn clean_other_r9() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: cleanOther });
  recordSecurityAudit({ cwd: cleanOther, reviewer: "judge-clean-r9", summary: "Clean other r9" });

  // Dirty unstamped `dir` attempts to escape into `cleanOther` or evade lexer/parser:
  const deniedUnstampedDir = [
    `(export GIT_DIR="${cleanOther}/.git"; export GIT_WORK_TREE="${cleanOther}") ; git commit -m "feat: r9-subshell-export"`,
    `if false; then export GIT_DIR="${cleanOther}/.git"; export GIT_WORK_TREE="${cleanOther}"; fi ; git commit -m "feat: r9-if-export"`,
    `if ($false) { $env:GIT_DIR="${cleanOther}/.git"; $env:GIT_WORK_TREE="${cleanOther}" } ; git commit -m "feat: r9-ps-if-env"`,
    `false && { cd "${cleanOther}"; }; git commit -m "feat: r9-and-brace"`,
    `echo ok | { cd "${cleanOther}"; }; git commit -m "feat: r9-pipe-brace"`,
    `echo ok | { echo hi; cd "${cleanOther}"; }; git commit -m "feat: r9-pipe-multi-brace"`,
    `{ cd "${cleanOther}"; } < /dev/null & git commit -m "feat: r9-redir-bg-brace"`,
    `coproc { cd "${cleanOther}"; } ; git commit -m "feat: r9-coproc-brace"`,
    `coproc cd "${cleanOther}" ; git commit -m "feat: r9-coproc-cmd"`,
    `try\n{\n}\ncatch\n{\ncd "${cleanOther}"\n}\ngit commit -m "feat: r9-nl-catch"`,
    `if ($false)\n{\ncd "${cleanOther}"\n}\ngit commit -m "feat: r9-nl-if"`,
    `if ($true) { } else\n{\ncd "${cleanOther}"\n}\ngit commit -m "feat: r9-nl-else"`,
    `foreach ($x in @())\n{\ncd "${cleanOther}"\n}\ngit commit -m "feat: r9-nl-foreach"`,
    `select x in a; do\ncd "${cleanOther}"\ndone <<< "" ; git commit -m "feat: r9-select"`,
    `case a in x|esac) : ;; b) cd "${cleanOther}" ;; esac ; git commit -m "feat: r9-case-pipe-esac"`,
    `case a in (esac) : ;; b) cd "${cleanOther}" ;; esac ; git commit -m "feat: r9-case-paren-esac"`,
    `( : \${x:-)} ; cd "${cleanOther}" ) ; git commit -m "feat: r9-top-param"`,
    ": <<'PS'\n<#\nPS\necho \"$(echo \\)# )\" && git commit -m 'feat: r9-esc-hash' && echo \"\n)\"\n# #>",
    ": <<'PS'\n<#\nPS\necho \"$(case a in $(echo a)) git commit -m 'feat: r9-case-subst' ;; esac)\"\n# #>",
    'powershell.exe /NoProfile /c "git commit -m \'feat: r9-ps-slash\'"',
    'cmd /c "cmd,/c,git commit -m feat:r9-cmd-comma"',
    'cmd /c "cmd=/c=git commit -m feat:r9-cmd-eq"',
    'cmd //c "git commit -m feat:r9-cmd-double-slash"',
  ];
  for (const cmd of deniedUnstampedDir) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.some((m) => m.includes("security-audit:")), `expected denial on unstamped dir for: ${cmd}`);
  }

  // From stamped `cleanOther`: fail closed on conditional scopes and catch relative Env:\ escapes into dirty `dir` + `git config`/`revert`:
  const deniedFromClean = [
    `if false; then export GIT_DIR="${cleanOther}/.git"; export GIT_WORK_TREE="${cleanOther}"; fi ; git commit -m "feat: r9-fail-if-export"`,
    `if ($false) { $env:GIT_DIR="${cleanOther}/.git"; $env:GIT_WORK_TREE="${cleanOther}" } ; git commit -m "feat: r9-fail-ps-if-env"`,
    `false && { cd "${cleanOther}"; }; git commit -m "feat: r9-fail-and-brace"`,
    `echo ok | { echo hi; cd "${cleanOther}"; }; git commit -m "feat: r9-fail-pipe-brace"`,
    `{ cd "${cleanOther}"; } < /dev/null & git commit -m "feat: r9-fail-redir-bg"`,
    `coproc { cd "${cleanOther}"; } ; git commit -m "feat: r9-fail-coproc"`,
    `try\n{\n}\ncatch\n{\ncd "${cleanOther}"\n}\ngit commit -m "feat: r9-fail-nl-catch"`,
    `select x in a; do\ncd "${cleanOther}"\ndone <<< "" ; git commit -m "feat: r9-fail-select"`,
    `case a in x|esac) : ;; b) cd "${cleanOther}" ;; esac ; git commit -m "feat: r9-fail-case-pipe-esac"`,
    `Push-Location Env: ; Set-Item .\\GIT_DIR "${dir}/.git" ; Set-Item .\\GIT_WORK_TREE "${dir}" ; Pop-Location ; git commit -m "feat: r9-rel-env"`,
    'git config alias.ci commit && git ci -m "feat: r9-cfg-alias"',
    'git revert -n HEAD && git commit -m "feat: r9-revert"',
  ];
  for (const cmd of deniedFromClean) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, cleanOther);
    assert.ok(res.length > 0, `expected fail-closed denial from cleanOther for: ${cmd}`);
  }

  // Hardening 3: unclosed backtick command substitutions fail closed even on a stamped repo.
  recordSecurityAudit({ cwd: dir, reviewer: "judge-r9", summary: "Clean r9" });
  for (const badTick of ['echo "`git commit"', "echo `git commit"]) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: badTick } }, dir);
    assert.ok(res.some((m) => m.includes("unclosed backtick command substitution")), badTick);
  }

  // Hardening 2: `git commit -am` with core.autocrlf=true matches recorded canonical LF audit digest.
  const crlfRepo = makeTempRepo(t);
  spawnSync("git", ["config", "core.autocrlf", "false"], { cwd: crlfRepo });
  writeFileSync(join(crlfRepo, rel), "pub fn lf_v1() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: crlfRepo });
  spawnSync("git", ["commit", "-m", "feat(core): lf init"], { cwd: crlfRepo });
  spawnSync("git", ["config", "core.autocrlf", "true"], { cwd: crlfRepo });
  writeFileSync(join(crlfRepo, rel), "pub fn crlf_v2() {}\r\n", "utf8");
  recordSecurityAudit({ cwd: crlfRepo, reviewer: "judge-r9-crlf", summary: "Clean CRLF" });
  assert.deepEqual(evaluateSecurityAuditToolPayload({ tool_input: { command: 'git commit -am "feat(core): r9-autocrlf"' } }, crlfRepo), []);

  // Hardening 1: `gh pr create --head feat/tc` while checked out on `main` respects `headRef:security/trust-core.paths`.
  const branchRepo = makeTempRepo(t);
  writeFileSync(join(branchRepo, "README.md"), "init\n", "utf8");
  spawnSync("git", ["add", "README.md", "security/trust-core.paths"], { cwd: branchRepo });
  spawnSync("git", ["commit", "-m", "chore: init"], { cwd: branchRepo });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: branchRepo });
  spawnSync("git", ["checkout", "-b", "feat/tc"], { cwd: branchRepo });
  writeFileSync(join(branchRepo, "security/trust-core.paths"), "crates/grdr-core/**\ndocs/custom-security/**\n", "utf8");
  mkdirSync(join(branchRepo, "docs/custom-security"), { recursive: true });
  writeFileSync(join(branchRepo, "docs/custom-security/rule.txt"), "strict rule\n", "utf8");
  spawnSync("git", ["add", "security/trust-core.paths", "docs/custom-security/rule.txt"], { cwd: branchRepo });
  spawnSync("git", ["commit", "-m", "feat(sec): add custom trust-core path"], { cwd: branchRepo });
  spawnSync("git", ["checkout", "main"], { cwd: branchRepo });
  recordSecurityAudit({ cwd: branchRepo, reviewer: "judge-r9-stale", summary: "Only trust-core.paths", files: ["security/trust-core.paths"] });
  const prHeadRes = evaluateSecurityAuditToolPayload(
    { tool_input: { command: 'gh pr create --base main --head feat/tc --title "t" --body "Closes #79 per D-62"' } },
    branchRepo,
  );
  assert.ok(prHeadRes.some((m) => m.includes("docs/custom-security/rule.txt") && m.includes("Trust-core paths touched")));
});

test("blocks Round 10 bypasses (piped/flagged eval & iex, positional/brace ps, cmd//c & cmd/c & %%var%%, bare/cross-dialect GIT_DIR & cd, ${$'...'}, case [)] & time -p, ps comment/trap/func/time braces) and H1-H4", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/r10.rs";
  writeFileSync(join(dir, rel), "pub fn r10_base() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): r10 base"], { cwd: dir });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });
  writeFileSync(join(dir, rel), "pub fn r10_v2() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });

  const cleanOther = makeTempRepo(t);
  writeFileSync(join(cleanOther, rel), "pub fn clean_r10() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: cleanOther });
  recordSecurityAudit({ cwd: cleanOther, reviewer: "judge-clean-r10", summary: "Clean r10" });

  const deniedUnstamped = [
    "'git commit -m \"feat: r10-pipe-iex\"' | iex",
    "Write-Output 'git commit -m \"feat: r10-pipe-invoke\"' | Invoke-Expression",
    "iex -Command 'git commit -m \"feat: r10-iex-cmd\"'",
    "iex -ErrorAction Stop 'git commit -m \"feat: r10-iex-ea\"'",
    "eval -- 'git commit -m \"feat: r10-eval-dd\"'",
    `(eval "cd \\"${cleanOther}\\"") ; git commit -m "feat: r10-sub-eval"`,
    `false && eval "cd \\"${cleanOther}\\"" ; git commit -m "feat: r10-and-eval"`,
    `echo ok | eval "cd \\"${cleanOther}\\"" ; git commit -m "feat: r10-pipe-eval"`,
    `eval "cd \\"${cleanOther}\\"" & git commit -m "feat: r10-bg-eval"`,
    `coproc eval "cd \\"${cleanOther}\\"" ; git commit -m "feat: r10-coproc-eval"`,
    `if ($false) { iex "cd '${cleanOther}'" } ; git commit -m "feat: r10-if-iex"`,
    `powershell -NoProfile "git commit -m 'feat: r10-pos-cmd'"`,
    `powershell /NoProfile /ExecutionPolicy Bypass "git commit -m 'feat: r10-pos-slash'"`,
    'cmd //c"git commit -m feat:r10-cmd-2slash-att"',
    'cmd /c "cmd/c git commit -m feat:r10-cmd-slash-c"',
    'cmd /c "cmd.exe/c git commit -m feat:r10-cmdexe-slash-c"',
    'cmd /c "powershell/Command git commit -m feat:r10-ps-slash-cmd"',
    'cmd /c "set a-b=git& call %%a-b%% commit -m feat:r10-hyphen-pct"',
    `GIT_DIR="${cleanOther}/.git"; GIT_WORK_TREE="${cleanOther}"; git commit -m "feat: r10-bare-gitdir"`,
    `if false; then GIT_DIR="${cleanOther}/.git"; GIT_WORK_TREE="${cleanOther}"; fi ; git commit -m "feat: r10-if-bare-gitdir"`,
    `GIT_DIR="${cleanOther}/.git" GIT_WORK_TREE="${cleanOther}" & git commit -m "feat: r10-bg-bare-gitdir"`,
    `export GIT_DIR="${cleanOther}/.git"; export GIT_WORK_TREE="${cleanOther}"; git commit -m "feat: r10-cross-export"`,
    `Set-Location "${cleanOther}"; git commit -m "feat: r10-cross-setloc"`,
    `$env:GIT_DIR="${cleanOther}/.git"; $env:GIT_WORK_TREE="${cleanOther}"; git commit -m "feat: r10-cross-psenv"`,
    ": <<'PS'\n<#\nPS\n: ${foo:-$'\\''} ; git commit -m \"feat: r10-param-ansic\" ; : '}''\n# #>",
    'echo "\\\\" ; if (1) { : ; } ; : \\\\" " ; : ${x:-$\'\\\'\'} ; echo \'`\' ; git commit -m "feat: r10-psbt-ansic"',
    `echo "$(case x in [)]) echo "hi" ; git commit -m 'feat: r10-case-br' ;; esac)"`,
    `echo "$(time -p case x in a) echo "hi" ; git commit -m 'feat: r10-time-p-case' ;; esac)"`,
    `if ($false) # c\n{\ncd "${cleanOther}"\n}\ngit commit -m "feat: r10-comment-brace"`,
    `trap [System.Exception] { cd "${cleanOther}" } ; git commit -m "feat: r10-trap-type"`,
    `f() { cd "${cleanOther}"; } ; git commit -m "feat: r10-func-parens"`,
    `function f { cd "${cleanOther}"; } ; git commit -m "feat: r10-func-kw"`,
    `& { cd "${cleanOther}" } ; git commit -m "feat: r10-amp-brace"`,
    `$sb = {\ncd "${cleanOther}"\n}\ngit commit -m "feat: r10-sb-assign"`,
    `time { cd "${cleanOther}"; echo 1; } | cat ; git commit -m "feat: r10-time-pipe"`,
    `! { cd "${cleanOther}"; echo 1; } & git commit -m "feat: r10-bang-bg"`,
    `false && time { echo 1; cd "${cleanOther}"; } ; git commit -m "feat: r10-and-time"`,
    `echo "$(echo "a $(echo '"') b" ; git commit -m 'feat: r10-nested-dq')"`,
  ];
  for (const cmd of deniedUnstamped) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.some((m) => m.includes("security-audit:")), `expected denial on unstamped dir for: ${cmd}`);
  }

  // From stamped `cleanOther`, fail closed on conditional scopes, bare GIT_DIR, eval scopes, brace headers, and `-WorkingDirectory { ... }` targeting dirty `dir`:
  const deniedFromClean = [
    `'git commit -m "feat: r10-clean-pipe-iex"' | iex`,
    `powershell -WorkingDirectory "${dir}" { git commit -m "feat: r10-wd-brace" }`,
    `false && eval "cd \\"${cleanOther}\\"" ; git commit -m "feat: r10-clean-and-eval"`,
    `echo ok | eval "cd \\"${cleanOther}\\"" ; git commit -m "feat: r10-clean-pipe-eval"`,
    `eval "cd \\"${cleanOther}\\"" & git commit -m "feat: r10-clean-bg-eval"`,
    `coproc eval "cd \\"${cleanOther}\\"" ; git commit -m "feat: r10-clean-coproc-eval"`,
    `if ($false) { iex "cd '${cleanOther}'" } ; git commit -m "feat: r10-clean-if-iex"`,
    `GIT_DIR="${cleanOther}/.git"; GIT_WORK_TREE="${cleanOther}"; git commit -m "feat: r10-clean-bare"`,
    `if ($false) # c\n{\ncd "${cleanOther}"\n}\ngit commit -m "feat: r10-clean-comment-brace"`,
    `trap [System.Exception] { cd "${cleanOther}" } ; git commit -m "feat: r10-clean-trap"`,
    `f() { cd "${cleanOther}"; } ; git commit -m "feat: r10-clean-f"`,
    `function f { cd "${cleanOther}"; } ; git commit -m "feat: r10-clean-fn"`,
    `& { cd "${cleanOther}" } ; git commit -m "feat: r10-clean-amp"`,
    `$sb = {\ncd "${cleanOther}"\n}\ngit commit -m "feat: r10-clean-sb"`,
    `time { cd "${cleanOther}"; echo 1; } | cat ; git commit -m "feat: r10-clean-time-pipe"`,
    `! { cd "${cleanOther}"; echo 1; } & git commit -m "feat: r10-clean-bang-bg"`,
    `false && time { echo 1; cd "${cleanOther}"; } ; git commit -m "feat: r10-clean-and-time"`,
    "pwsh -EncodedCommand AAAA=AAA",
    'git -c core.sshcommand=evil commit -m "feat: r10-sshcmd"',
    'git -c core.gitproxy=evil commit -m "feat: r10-proxy"',
    'git -c extensions.noop=true commit -m "feat: r10-ext"',
    'git branch -M tmp && git commit -m "feat: r10-branch"',
    'Clear-Item Env:GIT_DIR ; git commit -m "feat: r10-clearitem"',
    'iex -UnknownFlag "git status"',
    'eval -z "git status"',
  ];
  for (const cmd of deniedFromClean) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, cleanOther);
    assert.ok(res.length > 0, `expected denial from cleanOther for: ${cmd}`);
  }

  // H4: fail closed on missing command with empty tool_name; allow explicit non-command tools.
  assert.ok(evaluateSecurityAuditToolPayload({}).some((m) => m.includes("missing command field")));
  assert.deepEqual(evaluateSecurityAuditToolPayload({ tool_name: "Read", tool_input: { file_path: "README.md" } }), []);
});

test("blocks Round 11 bypasses (nested GIT_DIR inheritance, PS braces & @()/@var, eval &&/|| multi-seg, case fi)/done)/esac|/time-p, script -t/xargs --max-lines, cmd %a b%/cmd/c) and H1-H6 + ${#HOME}", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/r11.rs";
  writeFileSync(join(dir, rel), "pub fn r11_base() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): r11 base"], { cwd: dir });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });
  writeFileSync(join(dir, rel), "pub fn r11_v2() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });

  const cleanOther = makeTempRepo(t);
  writeFileSync(join(cleanOther, rel), "pub fn clean_r11() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: cleanOther });
  recordSecurityAudit({ cwd: cleanOther, reviewer: "judge-clean-r11", summary: "Clean r11" });

  // Unstamped dirty `dir`: non-header PS blocks, @()/@var, eval multi-seg, case/time-p, wrappers, cmd spaces/slash:
  const deniedUnstamped = [
    `if ($true) { Write-Output "\`a" } ; echo { cd "${cleanOther}" } ; git commit -m "feat: r11-ps-echo-brace"`,
    `if ($true) { Write-Output "\`a" } ; try { } catch[System.Exception] { cd "${cleanOther}" } ; git commit -m "feat: r11-ps-catch-type"`,
    `Start-Job { cd "${cleanOther}" } ; git commit -m "feat: r11-ps-job"`,
    `1..0 | ForEach-Object { cd "${cleanOther}" } ; git commit -m "feat: r11-ps-foreach-obj"`,
    `$sb = [scriptblock]{ cd "${cleanOther}" } ; git commit -m "feat: r11-ps-cast-sb"`,
    "git @('commit', '-m', 'feat: r11-at-array')",
    "New-Variable a @('commit', '-m', 'feat: r11-splat-git') ; git @a",
    "New-Variable a 'git commit -m feat:r11-splat-iex' ; iex @a",
    `false && eval 'true; cd "${cleanOther}"' ; git commit -m "feat: r11-eval-and-2"`,
    `true || eval 'true; cd "${cleanOther}"' && git commit -m "feat: r11-eval-or-2"`,
    `if false; then case a in z) : ;; fi) : ;; esac ; cd "${cleanOther}" ; fi ; git commit -m "feat: r11-case-fi"`,
    `while false; do case a in z) : ;; done) : ;; esac ; cd "${cleanOther}" ; done ; git commit -m "feat: r11-case-done"`,
    `case a in z) : ;; esac|x) cd "${cleanOther}" ;; esac ; git commit -m "feat: r11-case-esac-pipe"`,
    `time -p if false; then cd "${cleanOther}"; fi ; git commit -m "feat: r11-timep-if"`,
    'script -t -c "git commit -m feat:r11-script-t" /dev/null',
    'script --timing -c "git commit -m feat:r11-script-timing" /dev/null',
    'echo x | xargs --max-lines 1 git commit -m "feat: r11-xargs-ml"',
    'cmd /c "set a b=git& call %a b% commit -m feat:r11-space-pct"',
    'cmd /c "set a b=git& echo !a b! & git status"',
    'cmd/c git commit -m "feat: r11-top-cmd-slash"',
    "echo \"$(coproc MYPROC case x in a) git commit -m 'feat: r11-coproc-case' ;; esac)\"",
  ];
  for (const cmd of deniedUnstamped) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.some((m) => m.includes("security-audit:")), `expected denial on unstamped dir for: ${cmd}`);
  }

  // From stamped `cleanOther`, catch nested-shell/eval GIT_DIR targeting dirty `dir`, conditional traps, and H2/H3/H5:
  const deniedFromClean = [
    `export GIT_DIR="${dir}/.git"; export GIT_WORK_TREE="${dir}"; bash -c 'git commit -m "feat: r11-export-bash"'`,
    `$env:GIT_DIR="${dir}/.git"; $env:GIT_WORK_TREE="${dir}"; pwsh -Command 'git commit -m "feat: r11-env-pwsh"'`,
    `GIT_DIR="${dir}/.git" GIT_WORK_TREE="${dir}" bash -c 'git commit -m "feat: r11-inline-bash"'`,
    `env GIT_DIR="${dir}/.git" GIT_WORK_TREE="${dir}" pwsh -Command 'git commit -m "feat: r11-envwrap-pwsh"'`,
    `GIT_DIR="${dir}/.git" GIT_WORK_TREE="${dir}" eval 'git commit -m "feat: r11-inline-eval"'`,
    `pwsh -WorkingDirectory "${dir}" -Command & { git commit -m "feat: r11-amp-wd" }`,
    `[Environment]::SetEnvironmentVariable("GIT" + "_DIR", "${dir}/.git") ; git commit -m "feat: r11-concat-setenv"`,
    `false && eval 'true; cd "${cleanOther}"' ; git commit -m "feat: r11-clean-eval-and2"`,
    `if false; then case a in z) : ;; fi) : ;; esac ; cd "${cleanOther}" ; fi ; git commit -m "feat: r11-clean-fi"`,
    `case a in a) cd "${cleanOther}" ;; esac | cat ; git commit -m "feat: r11-clean-esac-pipe"`,
    `export GIT_DIR="${dir}/.git"; if false; then unset GIT_DIR; fi; git commit -m "feat: r11-cond-unset"`,
    `git config --add core.autocrlf false && git commit -m "feat: r11-cfg-add"`,
  ];
  for (const cmd of deniedFromClean) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, cleanOther);
    assert.ok(res.length > 0, `expected denial from cleanOther for: ${cmd}`);
  }

  // Allowed safe checks on stamped `cleanOther`: B8 (${#HOME}), H1 (pwsh -w Hidden), H3 (unset / env -i / env -u GIT_DIR), H6 (git config --get):
  for (const safeCmd of [
    "echo $(echo ${#HOME})\necho ok",
    'pwsh -w Hidden git commit -m "feat: r11-winstyle"',
    `export GIT_DIR="${dir}/.git"; export GIT_WORK_TREE="${dir}"; unset GIT_DIR GIT_WORK_TREE; git commit -m "feat: r11-unset"`,
    `export GIT_DIR="${dir}/.git"; env -u GIT_DIR git commit -m "feat: r11-env-u"`,
    `export GIT_DIR="${dir}/.git"; env -i git commit -m "feat: r11-env-i"`,
    'git config --get core.autocrlf && git commit -m "feat: r11-cfg-read"',
  ]) {
    assert.deepEqual(evaluateSecurityAuditToolPayload({ tool_input: { command: safeCmd } }, cleanOther), [], safeCmd);
  }
});

test("blocks Round 12 bypasses (dq-param nested quote, PS paren state, eval/iex persistent env, cmd ^\", Start-Process/saps, quoted bash ctrl, NUL ANSI-C, /dev/stdin, env -/exec -c/doas/sudo) and H1-H7", (t) => {
  const dir = makeTempRepo(t);
  const rel = "crates/grdr-core/src/r12.rs";
  writeFileSync(join(dir, rel), "pub fn r12_base() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): r12 base"], { cwd: dir });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });
  writeFileSync(join(dir, rel), "pub fn r12_v2() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: dir });

  const cleanOther = makeTempRepo(t);
  writeFileSync(join(cleanOther, rel), "pub fn clean_r12() {}\n", "utf8");
  spawnSync("git", ["add", rel], { cwd: cleanOther });
  recordSecurityAudit({ cwd: cleanOther, reviewer: "judge-clean-r12", summary: "Clean r12" });

  const deniedUnstamped = [
    `echo "\${foo:-"'"}" ; git commit -m 'feat: r12-dq-param' # '`,
    `echo "$(echo "\${foo:-"'"}" ; git commit -m 'feat: r12-dq-param-sub' # ')"`,
    `cmd /c 'echo a^" & git commit -m feat:r12-caret & echo ^"b'`,
    "Start-Process git -ArgumentList 'commit','-m','feat: r12-sp'",
    "saps git 'commit -m feat:r12-saps'",
    `case a in b) : ;; "esac") cd "${cleanOther}" ;; esac ; git commit -m "feat: r12-q-esac"`,
    `if false; then "fi"; cd "${cleanOther}"; fi; git commit -m "feat: r12-q-fi"`,
    `$'git\\0x' $'commit\\0y' -m "feat: r12-nul"`,
    `git $'commit\\0y' -m "feat: r12-nul2"`,
    `echo 'git commit -m "feat: r12-devstdin"' | bash /dev/stdin`,
    `bash /dev/fd/0 <<< 'git commit -m "feat: r12-devfd0"'`,
    "bash /proc/self/fd/0",
    `env GIT_DIR="${cleanOther}/.git" GIT_WORK_TREE="${cleanOther}" env - git commit -m "feat: r12-env-dash"`,
    `env GIT_DIR="${cleanOther}/.git" GIT_WORK_TREE="${cleanOther}" doas git commit -m "feat: r12-doas"`,
    `env GIT_DIR="${cleanOther}/.git" GIT_WORK_TREE="${cleanOther}" exec -c git commit -m "feat: r12-exec-c"`,
    `env GIT_DIR="${cleanOther}/.git" GIT_WORK_TREE="${cleanOther}" sudo git commit -m "feat: r12-sudo"`,
    "[ScriptBlock]::Create('git commit -m feat:r12-sbc').Invoke()",
    "Invoke-Command -ScriptBlock { git commit -m feat:r12-icm }",
    "Start-ThreadJob { git commit -m feat:r12-thread }",
    "Start-Process -wa Continue git -ArgumentList 'commit','-m','feat: r13-wa'",
    "Start-Process -Verb RunAs git -ArgumentList 'commit','-m','feat: r13-verb'",
    `Start-Process git -ArgumentList 'commit -m "a,b"'`,
    "Start-Process git -ArgumentList '-C', '.', 'commit -m feat:r13-multiword'",
    "bash /proc/thread-self/fd/0",
    `echo \${x:-\$(cd "${cleanOther}")} ; git commit -m "feat: r13-param-subst"`,
    `echo \${x:-\`cd "${cleanOther}"\`} ; git commit -m "feat: r13-param-tick"`,
    `Set-Item -WhatIf Env:GIT_DIR "${cleanOther}/.git" ; git commit -m "feat: r13-whatif"`,
    "Start-Process git -ArgumentList '-c', 'x=a,b', 'commit', '-m', 'feat: r14-qcomma'",
    "Start-Process git -ArgumentList '-C', 'sub,dir', 'commit', '-m', 'feat: r14-ccomma'",
    "Start-Process git -ArgumentList:'commit -m feat:r15-colon'",
    "Start-Process git -ArgumentList:commit,-m,x",
    "saps git -a:'commit -m feat:r15-a-colon'",
    "Start-Process git -ArgumentList:'commit', '-m', 'hello, world'",
    "Start-Process git -ArgumentList:'commit', 'foo.rs'",
    "Start-Process git -ArgumentList 'commit', '-m', 'hello, world'",
  ];
  for (const cmd of deniedUnstamped) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, dir);
    assert.ok(res.some((m) => m.includes("security-audit:")), `expected denial on unstamped dir for: ${cmd}`);
  }

  const deniedFromClean = [
    `(cd "${dir}") ; git commit -m "feat: r12-ps-paren-cd"`,
    `(Set-Location "${dir}") ; git commit -m "feat: r12-ps-paren-sl"`,
    `($env:GIT_DIR="${dir}/.git"; $env:GIT_WORK_TREE="${dir}") ; git commit -m "feat: r12-ps-paren-env"`,
    `eval 'export GIT_DIR="${dir}/.git"; export GIT_WORK_TREE="${dir}"' ; git commit -m "feat: r12-eval-export"`,
    `iex 'Set-Item Env:GIT_DIR "${dir}/.git"; Set-Item Env:GIT_WORK_TREE "${dir}"' ; git commit -m "feat: r12-iex-setitem"`,
    `Start-Process -WorkingDirectory "${dir}" git -ArgumentList 'commit','-m','feat: r12-sp-wd'`,
    `pushd "${dir}" ; popd -n ; git commit -m "feat: r13-popd-n"`,
    `pushd "${dir}" ; Pop-Location -Bogus ; git commit -m "feat: r13-pop-bogus"`,
    `pushd "${dir}" && popd +1 && git commit -m "feat: r14-popd-plus"`,
    `pushd "${dir}" && pushd +1 && git commit -m "feat: r14-pushd-plus"`,
    `Push-Location "${dir}" ; Push-Location -StackName s1 ; Set-Location -StackName s1 ; Pop-Location ; git commit -m "feat: r14-ps-stack"`,
    `Set-Location -StackName s1 ; git commit -m "feat: r14-sl-stack"`,
    `if ($false) { Write-Output @(cd "${cleanOther}") } ; git commit -m "feat: r12-ps-at-cond"`,
    `if ($false) { Write-Output (cd "${cleanOther}") } ; git commit -m "feat: r12-ps-p-cond"`,
    `cmd /c "cd /d ${dir} & git commit -m feat:r12-cmd-cdd"`,
    `Set-Location -ErrorAction SilentlyContinue "${dir}" ; git commit -m "feat: r12-sl-ea"`,
    `export GIT_EDITOR='sh -c evil' ; git commit -m "feat: r12-git-editor"`,
    `GIT_SEQUENCE_EDITOR=evil git commit -m "feat: r12-git-seq"`,
  ];
  for (const cmd of deniedFromClean) {
    const res = evaluateSecurityAuditToolPayload({ tool_input: { command: cmd } }, cleanOther);
    assert.ok(res.length > 0, `expected denial from cleanOther for: ${cmd}`);
  }

  // H6: control characters in unknownOption are sanitized via printableText.
  const ctrlRes = evaluateSecurityAuditToolPayload({ tool_input: { command: 'git commit --bad\x1b[31mopt -m "feat: x"' } }, cleanOther);
  assert.ok(ctrlRes.length > 0 && !ctrlRes.some((m) => m.includes("\x1b")));

  // H3: trust-core classification retains patterns present on origin/main even if removed on branch.
  const tcRepo = makeTempRepo(t);
  writeFileSync(join(tcRepo, "security/trust-core.paths"), "scripts/**\n", "utf8");
  mkdirSync(join(tcRepo, "scripts"), { recursive: true });
  writeFileSync(join(tcRepo, "scripts/check.sh"), "echo 1\n", "utf8");
  spawnSync("git", ["add", "security/trust-core.paths", "scripts/check.sh"], { cwd: tcRepo });
  spawnSync("git", ["commit", "-m", "feat: base trust core"], { cwd: tcRepo });
  spawnSync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: tcRepo });
  writeFileSync(join(tcRepo, "security/trust-core.paths"), "", "utf8");
  writeFileSync(join(tcRepo, "scripts/check.sh"), "echo 2\n", "utf8");
  spawnSync("git", ["add", "security/trust-core.paths", "scripts/check.sh"], { cwd: tcRepo });
  const tcRes = evaluateSecurityAuditToolPayload({ tool_input: { command: 'git commit -m "feat: del tc"' } }, tcRepo);
  assert.ok(tcRes.some((m) => m.includes("security/trust-core.paths") && m.includes("scripts/check.sh")));

  // Safe commands allowed on stamped repo without false positives:
  for (const safeCmd of [
    `GIT_DIR="${dir}/.git" GIT_WORK_TREE="${dir}" eval 'git status' ; git commit -m "feat: r12-inline-eval-ok"`,
    `GIT_DIR="${dir}/.git" GIT_WORK_TREE="${dir}" eval 'export FOO=1' ; git commit -m "feat: r13-eval-non-git-env"`,
    "Start-Process git -ArgumentList 'commit', '-m', 'hello, world'",
    `Push-Location "${dir}" ; git status ; Pop-Location ; git commit -m "feat: r14-clean-push-pop"`,
    'echo "${foo:-$(echo "hi")}" ; git commit -m "feat: r12-safe-subst"',
    'cargo fmt --all -- --check && cargo test --workspace --locked && git status && git diff',
    '$env:GH_REPO = "416rehman/Guardrails"; $env:GH_PROMPT_DISABLED = "1"; gh pr view 79',
  ]) {
    assert.deepEqual(evaluateSecurityAuditToolPayload({ tool_input: { command: safeCmd } }, cleanOther), [], safeCmd);
  }
});

test("readBatchBytesForSource, collectNonUiFileHashes, and evaluateSecurityAuditFiles match legacy semantics across all sources and rejections", (t) => {
  const dir = makeTempRepo(t);
  const outside = mkdtempSync(join(tmpdir(), "grdr-saudit-batch-out-"));
  t.after(() => rmSync(outside, { recursive: true, force: true }));

  const binRel = "crates/grdr-core/src/bin_data.rs";
  const emptyRel = "crates/grdr-core/src/empty.rs";
  const spacedRel = "crates/grdr-core/src/with space.rs";
  const dirtyMatchHeadRel = "crates/grdr-core/src/dirty_head.rs";
  const crlfCleanRel = "crates/grdr-core/src/crlf_clean.rs";
  const deletedRel = "crates/grdr-core/src/deleted.rs";
  const untrackedRel = "crates/grdr-core/src/untracked.rs";
  const missingRel = "crates/grdr-core/src/missing.rs";

  const binV1 = Buffer.from([0x70, 0x75, 0x62, 0x00, 0xff, 0x0a]);
  const binV2 = Buffer.from("pub fn staged_bin() {}\n", "utf8");
  const binV3 = Buffer.from("pub fn disk_bin() {}\n", "utf8");

  writeFileSync(join(dir, binRel), binV1);
  writeFileSync(join(dir, emptyRel), Buffer.alloc(0));
  writeFileSync(join(dir, spacedRel), Buffer.from("pub fn spaced() {}\n", "utf8"));
  writeFileSync(join(dir, dirtyMatchHeadRel), Buffer.from("pub fn h1() {}\n", "utf8"));
  writeFileSync(join(dir, crlfCleanRel), Buffer.from("pub fn crlf() {}\n", "utf8"));
  writeFileSync(join(dir, deletedRel), Buffer.from("pub fn del() {}\n", "utf8"));
  spawnSync("git", ["add", "."], { cwd: dir });
  spawnSync("git", ["commit", "-m", "feat(core): batch parity base"], { cwd: dir });

  spawnSync("git", ["config", "core.autocrlf", "true"], { cwd: dir });
  writeFileSync(join(dir, binRel), binV2);
  writeFileSync(join(dir, dirtyMatchHeadRel), Buffer.from("pub fn s2() {}\n", "utf8"));
  spawnSync("git", ["add", binRel, dirtyMatchHeadRel], { cwd: dir });
  spawnSync("git", ["rm", deletedRel], { cwd: dir });

  writeFileSync(join(dir, binRel), binV3);
  writeFileSync(join(dir, dirtyMatchHeadRel), Buffer.from("pub fn h1() {}\n", "utf8"));
  writeFileSync(join(dir, crlfCleanRel), Buffer.from("pub fn crlf() {}\r\n", "utf8"));
  writeFileSync(join(dir, untrackedRel), Buffer.from("pub fn untracked() {}\n", "utf8"));

  // Directory junction escaping outside root must be rejected alongside unsafe paths.
  writeFileSync(join(outside, "leak.rs"), "pub fn secret() {}\n", "utf8");
  const juncDirRel = "crates/grdr-core/escaped_dir";
  symlinkSync(outside, join(dir, juncDirRel), process.platform === "win32" ? "junction" : "dir");
  const juncFileRel = `${juncDirRel}/leak.rs`;

  // Extra chunked files (> 64) to exercise multi-batch git cat-file --batch -Z execution.
  const chunkPaths = [];
  for (let i = 0; i < 70; i += 1) {
    const p = `crates/grdr-core/src/chunk_${String(i).padStart(3, "0")}.rs`;
    chunkPaths.push(p);
    writeFileSync(join(dir, p), `pub const CHUNK_${i}: u32 = ${i};\n`, "utf8");
  }
  spawnSync("git", ["add", ...chunkPaths], { cwd: dir });

  const edgePaths = [
    binRel,
    emptyRel,
    spacedRel,
    dirtyMatchHeadRel,
    crlfCleanRel,
    deletedRel,
    untrackedRel,
    missingRel,
    juncFileRel,
    "../outside.rs",
    "crates/grdr-core/src/nul\0path.rs",
    "crates/grdr-core/src/lf\npath.rs",
    "crates/grdr-core/src/cr\rpath.rs",
  ];
  const probePaths = [...edgePaths, ...chunkPaths];

  const sha = (buf) => createHash("sha256").update(buf).digest("hex");
  for (const [source, canonicalClean] of [
    ["head", false],
    ["staged", false],
    ["disk", false],
    ["disk", true],
  ]) {
    const batchMap = readBatchBytesForSource(dir, probePaths, { source, headRef: "HEAD", canonicalClean });
    for (const relPath of edgePaths) {
      const legacyBuf = canonicalClean && source === "disk"
        ? readCleanAuditBytes(dir, relPath)
        : readBytesForSource(dir, relPath, source, "HEAD");
      const batchBuf = batchMap.get(relPath);
      if (legacyBuf === undefined) {
        assert.equal(batchBuf, undefined, `${source}(clean=${canonicalClean}) expected omitted for ${relPath}`);
      } else {
        assert.ok(Buffer.isBuffer(batchBuf), `${source}(clean=${canonicalClean}) expected Buffer for ${relPath}`);
        assert.equal(sha(batchBuf), sha(legacyBuf), `${source}(clean=${canonicalClean}) mismatch for ${relPath}`);
      }
    }
    for (let i = 0; i < chunkPaths.length; i += 1) {
      const batchBuf = batchMap.get(chunkPaths[i]);
      if (source === "head") {
        assert.equal(batchBuf, undefined, `head expected omitted for newly staged ${chunkPaths[i]}`);
      } else {
        assert.deepEqual(batchBuf, Buffer.from(`pub const CHUNK_${i}: u32 = ${i};\n`, "utf8"));
      }
    }
  }

  const deletedSet = new Set([deletedRel]);
  const hashed = collectNonUiFileHashes(dir, probePaths, { source: "disk", deletedFiles: deletedSet, canonicalClean: true });
  assert.equal(hashed[deletedRel], "DELETED");
  assert.equal(hashed[crlfCleanRel], sha(Buffer.from("pub fn crlf() {}\n", "utf8")));
  assert.equal(hashed[dirtyMatchHeadRel], sha(Buffer.from("pub fn h1() {}\n", "utf8")));
  assert.equal(hashed[emptyRel], sha(Buffer.alloc(0)));
  assert.equal(Object.hasOwn(hashed, missingRel), false);
  assert.equal(Object.hasOwn(hashed, juncFileRel), false);

  const rec = recordSecurityAudit({ cwd: dir, reviewer: "parity-judge", summary: "Parity check" });
  assert.equal(rec.fileHashes[deletedRel], "DELETED");
  assert.deepEqual(
    evaluateSecurityAuditFiles(
      [binRel, emptyRel, spacedRel, dirtyMatchHeadRel, crlfCleanRel, deletedRel, ...chunkPaths],
      dir,
      { source: "disk", deletedFiles: deletedSet, canonicalClean: true },
    ),
    [],
  );

  // Tampering one file, non-canonical paths, or invalid source/headRef fail closed cleanly.
  writeFileSync(join(dir, spacedRel), "pub fn tampered() {}\n", "utf8");
  const stale = evaluateSecurityAuditFiles([spacedRel], dir, { source: "disk", canonicalClean: true });
  assert.ok(stale.some((m) => m.includes("updated or unaudited") && m.includes(spacedRel)));
  assert.throws(() => readBatchBytesForSource(dir, [binRel], { source: "invalid" }), /GRDR-HOOK-0001/);
  assert.equal(readBatchBytesForSource(dir, [binRel], { source: "head", headRef: "-badref" }).size, 0);
  assert.equal(
    readBatchBytesForSource(
      dir,
      [`./${crlfCleanRel}`, crlfCleanRel.replace(/\//g, "\\"), "crates/grdr-core/src/../src/crlf_clean.rs"],
      { source: "disk", canonicalClean: true },
    ).size,
    0,
  );
});

test("parseCatFileBatchZ and cat-file --batch -Z reject malformed frames and non-blob objects fail-closed", (t) => {
  const oid40 = "a".repeat(40);
  const oid64 = "b".repeat(64);
  const payload = Buffer.from("hi\0\nthere", "utf8");
  const validStream = Buffer.concat([
    Buffer.from(`${oid64} blob ${payload.length}\0`, "utf8"),
    payload,
    Buffer.from("\0", "utf8"),
    Buffer.from(":crates/my file.rs missing\0", "utf8"),
    Buffer.from(`${oid40} blob 0\0\0`, "utf8"),
  ]);
  const validParsed = parseCatFileBatchZ(validStream, [
    { relPath: "crates/a.rs", spec: ":crates/a.rs" },
    { relPath: "crates/my file.rs", spec: ":crates/my file.rs" },
    { relPath: "crates/empty.rs", spec: ":crates/empty.rs" },
  ]);
  assert.deepEqual(validParsed.get("crates/a.rs"), payload);
  assert.equal(validParsed.has("crates/my file.rs"), false);
  assert.deepEqual(validParsed.get("crates/empty.rs"), Buffer.alloc(0));

  // Non-blob git objects (tree, commit, tag, submodule) are never accepted as file blobs.
  for (const objType of ["tree", "commit", "tag"]) {
    const nonBlobBuf = Buffer.concat([
      Buffer.from(`${oid40} ${objType} 4\0tree\0`, "utf8"),
      Buffer.from(`${oid40} blob 2\0ok\0`, "utf8"),
    ]);
    const parsed = parseCatFileBatchZ(nonBlobBuf, [
      { relPath: "crates", spec: "HEAD:crates" },
      { relPath: "crates/ok.rs", spec: "HEAD:crates/ok.rs" },
    ]);
    assert.equal(parsed.has("crates"), false, `${objType} must not be accepted`);
    assert.deepEqual(parsed.get("crates/ok.rs"), Buffer.from("ok", "utf8"));
  }
  for (const subOid of [oid40, oid64]) {
    const subBuf = Buffer.concat([
      Buffer.from(`${subOid} submodule\0`, "utf8"),
      Buffer.from(`${oid40} blob 2\0ok\0`, "utf8"),
    ]);
    const parsed = parseCatFileBatchZ(subBuf, [
      { relPath: "crates/sub", spec: ":crates/sub" },
      { relPath: "crates/ok.rs", spec: ":crates/ok.rs" },
    ]);
    assert.equal(parsed.has("crates/sub"), false, "submodule gitlink must not be accepted");
    assert.deepEqual(parsed.get("crates/ok.rs"), Buffer.from("ok", "utf8"));
  }

  const malformedCases = [
    ["empty relPath query", Buffer.from(":a missing\0"), [{ relPath: "", spec: ":a" }]],
    ["missing header NUL", Buffer.from(`${oid40} blob 2`), [{ relPath: "a", spec: ":a" }]],
    ["truncated payload", Buffer.from(`${oid40} blob 10\0abc\0`), [{ relPath: "a", spec: ":a" }]],
    ["missing trailing NUL", Buffer.from(`${oid40} blob 3\0abcX`), [{ relPath: "a", spec: ":a" }]],
    ["negative size", Buffer.from(`${oid40} blob -1\0\0`), [{ relPath: "a", spec: ":a" }]],
    ["leading zero size", Buffer.from(`${oid40} blob 01\0a\0`), [{ relPath: "a", spec: ":a" }]],
    ["non-numeric size", Buffer.from(`${oid40} blob NaN\0\0`), [{ relPath: "a", spec: ":a" }]],
    ["oversized blob", Buffer.from(`${oid40} blob ${GIT_MAX_BUFFER_BYTES + 1}\0\0`), [{ relPath: "a", spec: ":a" }]],
    ["invalid oid", Buffer.from("abcd blob 1\0x\0"), [{ relPath: "a", spec: ":a" }]],
    ["invalid submodule oid", Buffer.from("abcd submodule\0"), [{ relPath: "sub", spec: ":sub" }]],
    ["submodule with size", Buffer.from(`${oid40} submodule 0\0\0`), [{ relPath: "sub", spec: ":sub" }]],
    ["submodule trailing nul", Buffer.from(`${oid40} submodule\0\0`), [{ relPath: "sub", spec: ":sub" }]],
    ["unknown type", Buffer.from(`${oid40} unknown 1\0x\0`), [{ relPath: "a", spec: ":a" }]],
    ["spec mismatch missing", Buffer.from(":other missing\0"), [{ relPath: "a", spec: ":a" }]],
    ["ambiguous status", Buffer.from(":a ambiguous\0"), [{ relPath: "a", spec: ":a" }]],
    ["excluded status", Buffer.from(":a excluded\0"), [{ relPath: "a", spec: ":a" }]],
    ["truncated record count", Buffer.from(":a missing\0"), [{ relPath: "a", spec: ":a" }, { relPath: "b", spec: ":b" }]],
    ["trailing bytes", Buffer.from(":a missing\0extra"), [{ relPath: "a", spec: ":a" }]],
    ["truncated tree payload", Buffer.from(`${oid40} tree 8\0short\0`), [{ relPath: "crates", spec: "HEAD:crates" }]],
  ];
  for (const [label, buf, queries] of malformedCases) {
    assert.throws(() => parseCatFileBatchZ(buf, queries), /GRDR-HOOK-0001/, `expected throw for ${label}`);
  }
  assert.throws(
    () => parseCatFileBatchZ(Buffer.from(`${oid40} blob 5\0hello\0`), [{ relPath: "a", spec: ":a" }], 4),
    /GRDR-HOOK-0001/,
  );

  // End-to-end real repo tree and 160000 submodule gitlink queries alongside real blobs omit non-blobs cleanly.
  const dir = makeTempRepo(t);
  writeFileSync(join(dir, "crates/grdr-core/src/lib.rs"), "pub fn ok() {}\n", "utf8");
  spawnSync("git", ["add", "crates/grdr-core/src/lib.rs"], { cwd: dir });
  spawnSync("git", ["update-index", "--add", "--cacheinfo", `160000,${"1".repeat(40)},crates/grdr-core/submod`], { cwd: dir });
  const stagedSubMap = readBatchBytesForSource(dir, ["crates/grdr-core/submod", "crates/grdr-core/src/lib.rs"], { source: "staged" });
  assert.equal(stagedSubMap.has("crates/grdr-core/submod"), false);
  assert.deepEqual(stagedSubMap.get("crates/grdr-core/src/lib.rs"), Buffer.from("pub fn ok() {}\n", "utf8"));
  spawnSync("git", ["commit", "-m", "feat(core): tree and submodule test"], { cwd: dir });
  const liveMap = readBatchBytesForSource(dir, ["crates", "crates/grdr-core/submod", "crates/grdr-core/src/lib.rs"], { source: "head" });
  assert.equal(liveMap.has("crates"), false);
  assert.equal(liveMap.has("crates/grdr-core/submod"), false);
  assert.deepEqual(liveMap.get("crates/grdr-core/src/lib.rs"), Buffer.from("pub fn ok() {}\n", "utf8"));
});

test("evaluates 250-file staged commit and gh pr create cleanly well under 5 seconds", (t) => {
  const dir = makeTempRepo(t);
  const nonUiFiles = [];
  for (let i = 0; i < 250; i += 1) {
    const rel = `crates/grdr-core/src/mod_${String(i).padStart(3, "0")}.rs`;
    nonUiFiles.push(rel);
    writeFileSync(join(dir, rel), `pub fn f_${i}() -> u32 { ${i} }\n`, "utf8");
  }
  for (let i = 0; i < 20; i += 1) {
    writeFileSync(join(dir, `web/apps/console/src/view_${i}.tsx`), `export const V${i} = ${i};\n`, "utf8");
  }
  spawnSync("git", ["add", "."], { cwd: dir });

  const deniedUnstamped = evaluateSecurityAuditToolPayload(
    { tool_input: { command: 'git commit -m "feat(core): add 250 modules"' } },
    dir,
  );
  assert.ok(deniedUnstamped.some((m) => m.includes("security-audit:")));

  const startMs = Date.now();
  const rec = recordSecurityAudit({ cwd: dir, reviewer: "bench-judge", summary: "250 non-UI files" });
  assert.equal(Object.keys(rec.fileHashes).length, 250);

  assert.deepEqual(
    evaluateSecurityAuditToolPayload({ tool_input: { command: 'git commit -m "feat(core): add 250 modules"' } }, dir),
    [],
  );
  spawnSync("git", ["commit", "-m", "feat(core): add 250 modules"], { cwd: dir });

  assert.deepEqual(
    evaluateSecurityAuditToolPayload(
      { tool_input: { command: 'gh pr create --base main --head feat/test-audit --body "Closes #102 per D-62"' } },
      dir,
    ),
    [],
  );
  const elapsedMs = Date.now() - startMs;
  assert.ok(elapsedMs < 5000, `250-file record + commit + PR evaluation took ${elapsedMs}ms (budget < 5000ms)`);

  // Mutating 1 of 250 files after stamping must still fail closed cleanly.
  writeFileSync(join(dir, nonUiFiles[137]), "pub fn tampered() -> u32 { 999 }\n", "utf8");
  spawnSync("git", ["add", nonUiFiles[137]], { cwd: dir });
  spawnSync("git", ["commit", "-m", "fix(core): tamper 137"], { cwd: dir });
  const deniedPrTamper = evaluateSecurityAuditToolPayload(
    { tool_input: { command: 'gh pr create --base main --head feat/test-audit --body "Closes #102 per D-62"' } },
    dir,
  );
  assert.ok(deniedPrTamper.some((m) => m.includes("updated or unaudited") && m.includes(nonUiFiles[137])));
});
