// AC-6 of #1550: .claude/settings.json and .claude/gate-paths.json against R3 c, R6, R7 and the
// chief architect's ruling. The expected lists are copied from the spec, not from either file.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { GATE_LIST_PATH, SETTINGS_PATH } from "./fixture.mjs";

const D63 = ["lead-agent-kit", "chief-architect"];
const R7_D63 = [
  ".claude/agents/**", ".claude/skills/**", ".claude/hooks/**", ".claude/gate-paths.json", ".claude/risk-tiers.toml",
  ".claude/owners.toml", "CLAUDE.md", "AGENTS.md", ".github/**", "architecture.toml", "Cargo.toml", "rust-toolchain.toml",
  ".cargo/**", "deny.toml", "**/clippy.toml", "rustfmt.toml", "pnpm-workspace.yaml", "supply-chain/**", "security/**",
  "audits/**", "web/packages/ui/exceptions.toml", "surfaces.toml", "support.toml", "**/REVIEW.md",
];
const R7_ANY = ["*/**/AGENTS.md", "limits.toml", "dist.toml", "brand/**", "third_party/**", "Cargo.lock", "pnpm-lock.yaml"];
const R6_NEVER_GRANTABLE = [
  ".claude/settings.json", ".git/**", "conformance/vectors/**", "tests/golden/**", "**/*.snap", "**/__screenshots__/**",
  "fuzz/corpus/regressions/**", "spec/**", "specs/**", "governance/**", "release/**", "release-please-config.json",
  ".release-please-manifest.json", "**/CHANGELOG.md", "docs/agents/status/**", "docs/references/research/**", "LICENSE",
  "NOTICE", "COVENANT.md", "GOVERNANCE.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md", "MAINTAINERS.md",
  "AI_POLICY.md", "ADOPTERS.md", "TRADEMARKS.md",
];
const R3C_PREFIXES = [
  "git status", "git diff", "git log", "git show", "git ls-files", "git add", "git commit -m", "git blame", "rg", "cargo",
  "gh issue view", "node --test", "node .claude/hooks/grant.mjs",
];
const MATCHER = "Edit|Write|NotebookEdit|MultiEdit|Bash|PowerShell";
const HOOK_COMMAND = 'node "${CLAUDE_PROJECT_DIR}/.claude/hooks/gate-paths.mjs"';
const GRANT_RULES = ["open", "close", "print"].map((action) => `Bash(node .claude/hooks/grant.mjs ${action} *)`);

const settings = JSON.parse(readFileSync(SETTINGS_PATH, "utf8"));
const gateList = JSON.parse(readFileSync(GATE_LIST_PATH, "utf8"));
const sorted = (list) => [...list].sort();
const editGlobs = () => settings.permissions.deny.map((rule) => rule.match(/^Edit\((.+)\)$/)?.[1]).filter(Boolean).map((glob) => glob.replace(/^\.?\//, ""));

test("settings: gate-paths.mjs is registered for the file and shell tools with onFailure block", () => {
  assert.equal(settings.$schema, "https://json.schemastore.org/claude-code-settings.json");
  const entries = (settings.hooks?.PreToolUse ?? []).filter((entry) => entry.hooks?.some((hook) => hook.command === HOOK_COMMAND));
  assert.equal(entries.length, 1);
  assert.equal(entries[0].matcher, MATCHER);
  const [hook] = entries[0].hooks.filter((h) => h.command === HOOK_COMMAND);
  assert.equal(hook.type, "command");
  assert.equal(hook.onFailure, "block");
  assert.ok(Number.isInteger(hook.timeout) && hook.timeout > 0);
});

test("settings: the static Edit deny list is exactly the never-grantable paths, and the gate list mirrors it", () => {
  assert.deepEqual(sorted(editGlobs()), sorted(R6_NEVER_GRANTABLE));
  assert.deepEqual(sorted(gateList.never_grantable), sorted(R6_NEVER_GRANTABLE));
  const gateGlobs = gateList.entries.flatMap((entry) => entry.globs);
  assert.deepEqual(editGlobs().filter((glob) => gateGlobs.includes(glob)), []);
});

test("settings: the only grant.mjs allow rules are open, close and print", () => {
  assert.deepEqual(sorted(settings.permissions.allow.filter((rule) => rule.includes("grant.mjs"))), sorted(GRANT_RULES));
});

test("settings: the gate list's entries, classes and shell prefixes equal R7 and R3 c", () => {
  assert.equal(gateList.schema, "grdr.kit.gate-paths.v1");
  const classOf = (agents) => gateList.entries.filter((entry) => sorted(entry.agents).join() === sorted(agents).join()).flatMap((entry) => entry.globs);
  assert.deepEqual(sorted(classOf(D63)), sorted(R7_D63));
  assert.deepEqual(sorted(classOf(["*"])), sorted(R7_ANY));
  assert.equal(gateList.entries.flatMap((entry) => entry.globs).length, R7_D63.length + R7_ANY.length);
  for (const moved of ["surfaces.toml", "support.toml", "**/REVIEW.md", "AGENTS.md"]) assert.ok(classOf(D63).includes(moved), moved);
  assert.ok(classOf(["*"]).includes("*/**/AGENTS.md"));
  assert.deepEqual(gateList.shell_prefixes, R3C_PREFIXES);
});
