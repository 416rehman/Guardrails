import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
export const HOOKS_DIR = dirname(dirname(TEST_DIR));
export const CHECKOUT = dirname(dirname(HOOKS_DIR));
export const HOOK = join(HOOKS_DIR, "gate-paths.mjs");
export const GATE_LIST_PATH = join(CHECKOUT, ".claude", "gate-paths.json");
export const SETTINGS_PATH = join(CHECKOUT, ".claude", "settings.json");
export const ISSUE_2 = JSON.parse(readFileSync(join(TEST_DIR, "issue-2.json"), "utf8"));
const FAKE_GH = pathToFileURL(join(TEST_DIR, "fake-gh.mjs")).href;
const GIT_ENV = {
  GIT_AUTHOR_NAME: "fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.com",
  GIT_COMMITTER_NAME: "fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.com",
  GIT_CONFIG_NOSYSTEM: "1",
};

// The Write set lines of an issue body, read here without gate/grant-record.mjs.
export function writeSetOf(issue) {
  const after = issue.body.split("### Write set")[1].split("\n###")[0];
  return after.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

export const GRANT_2 = { schema: "grdr.kit.grant.v1", issue: 2, agent: "lead-agent-kit", branch: "issue/2", write_set: writeSetOf(ISSUE_2) };
export const GRANT_5 = { schema: "grdr.kit.grant.v1", issue: 5, agent: "impl-rust", branch: "issue/5", write_set: ["crates/**", "architecture.toml", "Cargo.lock"] };

export function git(dir, ...args) {
  return execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", env: { ...process.env, ...GIT_ENV } }).trim();
}

// A main checkout with the gate list and hooks of this checkout, worktrees on issue/2 (a grant
// for lead-agent-kit), issue/3 (none, nested like the session's own worktrees), issue/4 (an
// invalid grant), issue/5 (a grant for impl-rust) and a detached one, and a directory outside.
export function makeRepository() {
  const base = realpathSync.native(mkdtempSync(join(tmpdir(), "grdr-gate-")));
  const main = join(base, "main");
  mkdirSync(join(main, ".claude"), { recursive: true });
  git(main, "init", "-q", "-b", "main");
  cpSync(HOOKS_DIR, join(main, ".claude", "hooks"), { recursive: true });
  cpSync(GATE_LIST_PATH, join(main, ".claude", "gate-paths.json"));
  writeFileSync(join(main, "architecture.toml"), "");
  git(main, "add", "-A");
  git(main, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture");
  const roots = {
    main,
    w2: join(base, "w2"),
    w3: join(main, ".claude", "worktrees", "w3"),
    w4: join(base, "w4"),
    w5: join(base, "w5"),
    wd: join(base, "wd"),
  };
  for (const [name, branch] of [["w2", "issue/2"], ["w3", "issue/3"], ["w4", "issue/4"], ["w5", "issue/5"]]) {
    git(main, "worktree", "add", "-q", "-b", branch, roots[name]);
  }
  git(main, "worktree", "add", "-q", "--detach", roots.wd);
  const grants = join(main, ".claude", "grants");
  mkdirSync(grants);
  writeFileSync(join(grants, "2.json"), JSON.stringify(GRANT_2));
  writeFileSync(join(grants, "4.json"), "{ not json");
  writeFileSync(join(grants, "5.json"), JSON.stringify(GRANT_5));
  const outside = join(base, "outside");
  mkdirSync(outside);
  return { base, main, roots, outside, remove: () => rmSync(base, { recursive: true, force: true }) };
}

export function hookInput(cwd, tool, toolInput, caller = {}) {
  return {
    session_id: "s",
    transcript_path: join(cwd, "t.jsonl"),
    cwd,
    permission_mode: caller.mode ?? "default",
    hook_event_name: "PreToolUse",
    tool_name: tool,
    tool_input: toolInput,
    tool_use_id: "toolu_1",
    ...(caller.agentId ? { agent_id: caller.agentId } : {}),
    ...(caller.agentType ? { agent_type: caller.agentType } : {}),
  };
}

// Runs the hook as Claude Code does: JSON on stdin, `CLAUDE_PROJECT_DIR` set, decision on stdout.
export function runHook(projectDir, input, env = {}) {
  const started = performance.now();
  const stdin = typeof input === "string" ? input : JSON.stringify(input);
  const childEnv = { ...process.env, CLAUDE_PROJECT_DIR: projectDir, ...env };
  for (const [key, value] of Object.entries(childEnv)) if (value === undefined) delete childEnv[key];
  const result = spawnSync(process.execPath, [HOOK], { input: stdin, env: childEnv, encoding: "utf8" });
  const ms = performance.now() - started;
  if (result.status !== 0) return { status: result.status, code: undefined, ms, stderr: result.stderr };
  if (result.stdout === "") return { status: 0, code: null, ms };
  const output = JSON.parse(result.stdout).hookSpecificOutput;
  const reason = output.permissionDecisionReason;
  return { status: 0, code: reason.split(":")[0], reason, output, ms };
}

// Runs a checkout's grant.mjs with `gh issue view <n>` answered from `issues/<n>.json`.
export function runGrant(scriptCheckout, cwd, issuesDir, ...args) {
  const script = join(scriptCheckout, ".claude", "hooks", "grant.mjs");
  const env = { ...process.env, GRDR_TEST_ISSUES: issuesDir };
  const result = spawnSync(process.execPath, ["--import", FAKE_GH, script, ...args], { cwd, env, encoding: "utf8" });
  const line = (result.stderr || result.stdout).trim();
  return { status: result.status, stdout: result.stdout, code: result.status === 0 ? null : line.split(":")[0], line };
}

export function realHookTimeoutMs() {
  const settings = JSON.parse(readFileSync(SETTINGS_PATH, "utf8"));
  const hook = (settings.hooks?.PreToolUse ?? []).flatMap((entry) => entry.hooks ?? []).find((h) => String(h.command).includes("gate-paths.mjs"));
  return hook?.timeout === undefined ? undefined : hook.timeout * 1000;
}
