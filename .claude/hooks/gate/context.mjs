import { existsSync, globSync } from "node:fs";
import { join } from "node:path";
import { GATE_LIST_FILE, parseGateList } from "./gate-list.mjs";
import { parseGrant } from "./grant-record.mjs";
import { GateFailure, readText, runCommand } from "./io.mjs";
import { isWithin, platformOf, resolvePath } from "./paths.mjs";

const BRANCH_REF = "refs/heads/";
const DETACHED_EXIT = 1;

export function buildContext(input, env, platformName) {
  const platform = platformOf(platformName);
  if (!env.CLAUDE_PROJECT_DIR) throw new GateFailure("CLAUDE_PROJECT_DIR", "not set");
  if (typeof input.cwd !== "string" || input.cwd === "") throw new GateFailure("hook input cwd", "missing");
  const worktrees = listWorktrees(env.CLAUDE_PROJECT_DIR);
  const mainPath = worktrees[0]?.path;
  if (mainPath === undefined) throw new GateFailure(`git -C ${env.CLAUDE_PROJECT_DIR} worktree list`, "listed no checkout");
  const listPath = join(mainPath, GATE_LIST_FILE);
  const gateList = parseGateList(readText(listPath), listPath);
  const roots = worktrees.map((worktree) => resolvePath(worktree.path, "", platform));
  const cwd = resolvePath(input.cwd, "", platform);
  const caller = callerWorktree(input.cwd, cwd, roots, worktrees, platform);
  return {
    platform,
    roots,
    cwd,
    caller,
    gateList,
    grant: readGrant(mainPath, caller.branch, gateList, platform),
    expand: (word, dir) => globSync(word, { cwd: dir }),
  };
}

// `git worktree list` names the main checkout first: the parent of the shared git directory.
function listWorktrees(dir) {
  return git(dir, ["worktree", "list", "--porcelain"])
    .split(/\r?\n\r?\n/)
    .map((block) => block.split(/\r?\n/))
    .filter((lines) => lines[0]?.startsWith("worktree "))
    .map((lines) => ({
      path: lines[0].slice("worktree ".length),
      branch: lines.find((line) => line.startsWith(`branch ${BRANCH_REF}`))?.slice(`branch ${BRANCH_REF}`.length) ?? null,
    }));
}

function callerWorktree(rawCwd, cwd, roots, worktrees, platform) {
  if (!roots.some((root) => isWithin(cwd, root))) return { worktree: null, branch: null };
  const worktree = resolvePath(git(rawCwd, ["rev-parse", "--show-toplevel"]), "", platform);
  const listed = roots.indexOf(worktree);
  if (listed !== -1) return { worktree, branch: worktrees[listed].branch };
  return { worktree, branch: symbolicBranch(rawCwd) };
}

function symbolicBranch(dir) {
  try {
    return git(dir, ["symbolic-ref", "--short", "-q", "HEAD"]);
  } catch (error) {
    if (error.cause?.status === DETACHED_EXIT) return null;
    throw error;
  }
}

function readGrant(mainPath, branch, list, platform) {
  const number = branch?.startsWith(list.branchPrefix) ? branch.slice(list.branchPrefix.length) : "";
  if (!/^[1-9]\d*$/.test(number)) return { kind: "none" };
  const path = join(mainPath, list.grantsDir, `${number}.json`);
  return existsSync(path) ? parseGrant(readText(path), Number(number), list, platform.fold) : { kind: "none" };
}

function git(dir, args) {
  return runCommand("git", ["-C", dir, ...args]);
}
