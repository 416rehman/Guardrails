// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Shared PreToolUse and CI checks:
// - Refuse direct git push to main/master; require a valid work branch name.
// - Refuse third-party analytics/fonts or curl|sh in published docs pages.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { coversBranch, isValidWorkBranch, loadRules } from "./branch-findings.mjs";

const PRODUCT_PAGE = /^docs\/product\/(?!reference\/_generated\/).+\.mdx?$/;
const PUBLISHED = /^(site|docs\/product|docs\/runbooks|docs\/training)\/.+\.(mdx?|[cm]?[jt]sx?|json|ya?ml|css|html)$/;
const FRONT_MATTER_KEYS = ["id", "type", "personas", "shapes", "covers", "owner_squad", "stability"];
const THIRD_PARTY =
  /googletagmanager|google-analytics|gtag\(|fonts\.googleapis|fonts\.gstatic|use\.typekit|plausible\.io|segment\.(io|com)|hotjar|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare/;
const PIPE_TO_SHELL = /curl[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b/;
const BRANCH_RULES_PATH = fileURLToPath(new URL("./branch-rules.json", import.meta.url));

function run(command, args, cwd) {
  return execFileSync(command, args, { encoding: "utf8", cwd, stdio: ["ignore", "pipe", "ignore"] });
}

export function optionValue(command, name) {
  const match = command.match(new RegExp(`(?:^|\\s)${name}(?:[ =])(?:"([^"]*)"|'([^']*)'|(\\S+))`));
  return match ? (match[1] ?? match[2] ?? match[3]) : undefined;
}

function diffFiles(range, cwd) {
  return run("git", ["diff", "--name-only", "--diff-filter=d", range], cwd).split(/\r?\n/).filter(Boolean);
}

function currentBranch(cwd) {
  try {
    return run("git", ["rev-parse", "--abbrev-ref", "HEAD"], cwd).trim();
  } catch {
    return undefined;
  }
}

function readBranchRules() {
  return loadRules(readFileSync(BRANCH_RULES_PATH, "utf8"));
}

function normalizeBranchRef(ref) {
  return ref.replace(/^refs\/heads\//, "");
}

function isExemptBranch(branch, rules) {
  return rules.exemptions.some((exemption) => coversBranch(exemption, branch));
}

function checkGitPush(command, cwd, rules) {
  const found = [];
  if (!/\bgit(?:\s+-C\s+\S+)?\s+push\b/.test(command)) return found;
  if (/(?:^|\s)(?:-d|--delete)(?:\s|$)/.test(command)) return found;
  const pushMatch = command.match(/\bgit(?:\s+-C\s+\S+)?\s+push\b([^;&|\n]*)/);
  const rest = pushMatch ? pushMatch[1] : "";
  const tokens = rest
    .trim()
    .split(/\s+/)
    .filter((t) => t && !t.startsWith("-"));
  const refspecs = tokens.slice(1);
  const targets = [];
  for (const spec of refspecs) {
    const dest = spec.includes(":") ? spec.split(":").at(-1) : spec;
    if (dest) targets.push(normalizeBranchRef(dest));
  }
  if (targets.length === 0) {
    const cur = currentBranch(cwd);
    if (cur && cur !== "HEAD") targets.push(cur);
  }
  for (const branch of targets) {
    if (branch === "main" || branch === "master") {
      found.push(`branch rule: direct push to ${branch} is refused; push to a feature branch (${rules.workBranchForm}) and open a pull request.`);
      continue;
    }
    if (!isValidWorkBranch(branch, rules) && !isExemptBranch(branch, rules)) {
      found.push(`branch rule: branch "${branch}" should follow ${rules.workBranchForm}.`);
    }
  }
  return found;
}

function checkPrCreateRules(command, cwd, rules) {
  const found = [];
  const headOpt = optionValue(command, "--head");
  const branch = headOpt ? normalizeBranchRef(headOpt) : currentBranch(cwd);
  if (!branch || branch === "HEAD" || branch === "main" || branch === "master") {
    found.push(`branch rule: gh pr create must target a work branch (${rules.workBranchForm}), not "${branch ?? "detached HEAD"}".`);
    return found;
  }
  if (!isValidWorkBranch(branch, rules) && !isExemptBranch(branch, rules)) {
    found.push(`branch rule: branch "${branch}" should follow ${rules.workBranchForm}.`);
  }
  return found;
}

function resolveRef(candidates, cwd) {
  for (const candidate of candidates) {
    if (!candidate) continue;
    try {
      run("git", ["rev-parse", "--verify", candidate], cwd);
      return candidate;
    } catch {}
  }
  return "HEAD";
}

export function fromHookCommand(command, cwd = process.cwd()) {
  const merge = command.match(/gh pr merge\s+(\d+)/);
  if (merge) {
    const pr = JSON.parse(run("gh", ["pr", "view", merge[1], "--json", "files,headRefOid,headRefName,title"], cwd));
    return { files: pr.files.map((file) => file.path), ref: pr.headRefOid, headRefName: pr.headRefName, title: pr.title };
  }
  const head = optionValue(command, "--head");
  const base = resolveRef(["origin/main", "main"], cwd);
  const ref = resolveRef([head ? `origin/${head}` : undefined, head, "HEAD"], cwd);
  return { files: diffFiles(`${base}...${ref}`, cwd), ref };
}

function fromCi(cwd = process.cwd()) {
  const { BASE, HEAD } = process.env;
  return { files: diffFiles(`${BASE}...${HEAD}`, cwd), ref: HEAD };
}

function fileAt(ref, path, cwd) {
  try {
    return run("git", ["show", `${ref}:${path}`], cwd);
  } catch {
    return undefined;
  }
}

function frontMatterKeys(text) {
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return [];
  return match[1].split(/\r?\n/).map((line) => line.match(/^([A-Za-z_]+):/)?.[1]).filter(Boolean);
}

export function findings({ files, ref }, cwd = process.cwd()) {
  const found = [];
  for (const path of files.filter((f) => PRODUCT_PAGE.test(f) || PUBLISHED.test(f))) {
    const text = fileAt(ref, path, cwd);
    if (text === undefined) continue;
    if (PRODUCT_PAGE.test(path)) {
      const keys = frontMatterKeys(text);
      const missing = FRONT_MATTER_KEYS.filter((key) => !keys.includes(key));
      if (missing.length) found.push(`docs: ${path} front matter lacks ${missing.join(", ")}.`);
    }
    if (THIRD_PARTY.test(text)) found.push(`docs: ${path} loads a third-party script, font or analytics.`);
    if (PIPE_TO_SHELL.test(text)) found.push(`docs: ${path} pipes a download into a shell; show signed installation instructions.`);
  }
  return found;
}

export function evaluateHookCommand(command, cwd = process.cwd()) {
  const rules = readBranchRules();
  const found = [];
  if (/\bgit(?:\s+-C\s+\S+)?\s+push\b/.test(command)) {
    found.push(...checkGitPush(command, cwd, rules));
  }
  if (/\bgh\s+pr\s+create\b/.test(command)) {
    const ctx = fromHookCommand(command, cwd);
    found.push(...checkPrCreateRules(command, cwd, rules));
    found.push(...findings(ctx, cwd));
  } else if (/\bgh\s+pr\s+merge\b/.test(command)) {
    const ctx = fromHookCommand(command, cwd);
    found.push(...findings(ctx, cwd));
  }
  return found;
}

function isMainModule() {
  if (!process.argv[1]) return false;
  return resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
}

if (isMainModule()) {
  try {
    const ci = process.argv.includes("--ci");
    if (ci) {
      const found = findings(fromCi(process.cwd()), process.cwd());
      if (found.length) {
        process.stderr.write(`${found.join("\n")}\n`);
        for (const line of found) process.stdout.write(`::error::${line}\n`);
        process.exit(1);
      }
    } else {
      const payload = JSON.parse(readFileSync(0, "utf8"));
      const command = payload.tool_input?.command ?? payload.toolCall?.args?.CommandLine ?? "";
      const cwd = payload.cwd ?? process.cwd();
      const found = evaluateHookCommand(command, cwd);
      if (found.length) {
        process.stderr.write(`${found.join("\n")}\n`);
        process.exit(2);
      }
    }
  } catch (error) {
    process.stderr.write(`docs-check skipped: ${error.message}\n`);
    process.exit(0);
  }
}
