// AC-4 of #1550: `decide` in-process against the static deny list at 1b37f9b and against the
// reference model of model.mjs.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { decide } from "../decide.mjs";
import { parseGateList } from "../gate-list.mjs";
import { platformOf, resolvePath } from "../paths.mjs";
import { CHECKOUT, GATE_LIST_PATH, GRANT_2, GRANT_5, SETTINGS_PATH, git } from "./fixture.mjs";
import { generateCase, rng, writeSetPredicate } from "./model.mjs";

const BASELINE = "1b37f9b";
const CASES = 10000;
const GATE_LIST = parseGateList(readFileSync(GATE_LIST_PATH, "utf8"), GATE_LIST_PATH);
const WORLDS = [false, true].map((windows) => {
  const top = windows ? "C:/r" : "/r";
  return {
    windows,
    platform: platformOf(windows ? "win32" : "linux"),
    roots: { main: `${top}/main`, w2: `${top}/w2`, w3: `${top}/main/.claude/worktrees/w3`, w4: `${top}/w4`, w5: `${top}/w5`, wd: `${top}/wd` },
    branches: { main: "main", w2: "issue/2", w3: "issue/3", w4: "issue/4", w5: "issue/5", wd: null },
    outside: `${top}/outside`,
    grants: {
      w2: { agent: GRANT_2.agent, inWriteSet: writeSetPredicate(GRANT_2.write_set) },
      w4: "invalid",
      w5: { agent: GRANT_5.agent, inWriteSet: writeSetPredicate(GRANT_5.write_set) },
    },
  };
});
const GRANT_STATES = { w2: { kind: "valid", record: GRANT_2 }, w4: { kind: "invalid", detail: "grant 4 does not parse" }, w5: { kind: "valid", record: GRANT_5 } };

// The context gate-paths.mjs would build for a caller whose cwd is the root `callerRoot`.
function contextFor(world, callerRoot) {
  const resolve = (path) => resolvePath(path, "", world.platform);
  const names = Object.keys(world.roots);
  return {
    platform: world.platform,
    roots: names.map((name) => resolve(world.roots[name])),
    cwd: resolve(world.roots[callerRoot]),
    caller: { worktree: resolve(world.roots[callerRoot]), branch: world.branches[callerRoot] },
    gateList: GATE_LIST,
    grant: GRANT_STATES[callerRoot] ?? { kind: "none" },
    expand: () => [],
  };
}

function codeOf(result) {
  return result.kind === "deny" ? result.code : null;
}

function editGlobs(settings) {
  return settings.permissions.deny.map((rule) => rule.match(/^Edit\((.+)\)$/)?.[1]).filter(Boolean).map((glob) => glob.replace(/^\.?\//, ""));
}

// Gitignore-style matching of a permission rule's path, written here apart from gate/glob.mjs.
function ruleMatches(glob, rel) {
  const source = glob
    .split("/")
    .map((part) => (part === "**" ? "\u0000" : part.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", "[^/]*")))
    .join("/")
    .replaceAll("\u0000/", "(?:.*/)?")
    .replaceAll("/\u0000", "(?:/.*)?")
    .replaceAll("\u0000", ".*");
  return new RegExp(`^${source}$`).test(rel);
}

function samplePaths(glob) {
  const fill = (inner) => glob.replaceAll("**", inner).replaceAll("*", "sample").replaceAll("//", "/").replace(/^\//, "");
  return [...new Set([fill("a"), fill("a/b"), fill("")].map((path) => path.replace(/\/$/, "/x.txt")))].filter(Boolean);
}

function agentNames() {
  const dir = join(CHECKOUT, ".claude", "agents");
  return readdirSync(dir)
    .filter((file) => file.endsWith(".md"))
    .map((file) => readFileSync(join(dir, file), "utf8").match(/^name:\s*(\S+)/m)?.[1])
    .filter(Boolean);
}

test("differential: every path today's static deny list holds stays refused without a grant", () => {
  const baseline = JSON.parse(git(CHECKOUT, "show", `${BASELINE}:.claude/settings.json`));
  const staticNow = editGlobs(JSON.parse(readFileSync(SETTINGS_PATH, "utf8")));
  const world = WORLDS[0];
  const agents = agentNames();
  assert.ok(agents.length > 40, `agents read: ${agents.length}`);
  const callers = [["main", {}], ...agents.flatMap((agent) => [["w3", { agent_id: "a", agent_type: agent }], ["main", { agent_id: "a", agent_type: agent }]])];
  const open = [];
  for (const glob of editGlobs(baseline)) {
    for (const rel of samplePaths(glob)) {
      assert.ok(ruleMatches(glob, rel), `${rel} does not match ${glob}`);
      if (staticNow.some((rule) => ruleMatches(rule, rel))) continue;
      for (const [root, caller] of callers) {
        const input = { cwd: world.roots[root], tool_name: "Write", tool_input: { file_path: `${world.roots[root]}/${rel}` }, ...caller };
        if (codeOf(decide(input, contextFor(world, root))) === null) open.push(`${rel} for ${caller.agent_type ?? "the main session"}`);
      }
    }
  }
  assert.deepEqual(open, []);
});

test("differential: decide equals the reference model on 10000 seeded cases", () => {
  const seed = Number(process.env.GRDR_GATE_SEED ?? Date.now() % 2 ** 31);
  console.log(`differential seed ${seed}`);
  const random = rng(seed);
  const mismatches = [];
  for (let i = 0; i < CASES; i += 1) {
    const world = WORLDS[i % 2];
    const { input, expected } = generateCase(random, world);
    const callerRoot = Object.keys(world.roots).find((name) => resolvePath(input.cwd, "", world.platform) === resolvePath(world.roots[name], "", world.platform));
    const actual = codeOf(decide(input, contextFor(world, callerRoot)));
    if (actual !== expected) mismatches.push({ expected, actual, input });
  }
  assert.deepEqual(mismatches.slice(0, 5), [], `seed ${seed}: ${mismatches.length} mismatches`);
});
