// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Shared PreToolUse and CI checks for design/34 docs rules, branch naming (`issue/<n>-<slug>`),
// no direct push to `main`, one PR per issue, and issue-targeted PRs.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { coversBranch, hasIssueNameInPull, isValidWorkBranch, loadRules } from "./branch-findings.mjs";

const CODE = /^(crates|programs|proto|schema|web|desktop|platform|bpf|packs|rules|interface|sdk|spec|conformance|lab)\//;
const DOCS = /^(docs|site)\/|(^|\/)README(\.md)?$/;
const PRODUCT_PAGE = /^docs\/product\/(?!reference\/_generated\/).+\.mdx?$/;
const PUBLISHED = /^(site|docs\/product|docs\/runbooks|docs\/training)\/.+\.(mdx?|[cm]?[jt]sx?|json|ya?ml|css|html)$/;
const FRONT_MATTER_KEYS = ["id", "type", "personas", "shapes", "covers", "owner_squad", "stability"];
const NOTE_CATEGORIES = ["feature", "fix", "security", "deprecation", "breaking", "known-issue", "none"];
const THIRD_PARTY =
  /googletagmanager|google-analytics|gtag\(|fonts\.googleapis|fonts\.gstatic|use\.typekit|plausible\.io|segment\.(io|com)|hotjar|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare/;
const PIPE_TO_SHELL = /curl[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b/;
const DOCS_ESCAPE = /(^|\n|")Docs: unchanged because \S/;
const BRANCH_RULES_PATH = fileURLToPath(new URL("./branch-rules.json", import.meta.url));
const ISSUE_KEYWORDS = "Refs|Issue:|Close|Closes|Closed|Fix|Fixes|Fixed|Resolve|Resolves|Resolved";
const ISSUE_LINK_RE = new RegExp(`(?:^|\\n)[ \\t]*(?:${ISSUE_KEYWORDS}):?[ \\t]+#([1-9][0-9]*)\\b`, "im");

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

function bodyFromCommand(command, cwd) {
  const bodyFile = optionValue(command, "--body-file");
  if (bodyFile) {
    return readFileSync(resolve(cwd, bodyFile), "utf8");
  }
  const inlineBody = optionValue(command, "--body");
  return (inlineBody ?? command).replace(/\\n/g, "\n");
}

function readBranchRules() {
  return loadRules(readFileSync(BRANCH_RULES_PATH, "utf8"));
}

function normalizeBranchRef(ref) {
  return ref.replace(/^refs\/heads\//, "");
}

function isExemptOrLegacyBranch(branch, rules) {
  return rules.legacyPreSlugBranches.has(branch) || rules.exemptions.some((exemption) => coversBranch(exemption, branch));
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
      found.push(`branch rule: direct push to ${branch} is refused; push to ${rules.workBranchForm} and open a pull request.`);
      continue;
    }
    if (!isValidWorkBranch(branch, rules) && !isExemptOrLegacyBranch(branch, rules)) {
      found.push(`branch rule: branch "${branch}" must follow ${rules.workBranchForm} (3 to 60 lowercase kebab-case characters).`);
    }
  }
  return found;
}

function checkPrCreateRules(command, cwd, body, rules, listOpenPrs) {
  const found = [];
  const headOpt = optionValue(command, "--head");
  const branch = headOpt ? normalizeBranchRef(headOpt) : currentBranch(cwd);
  if (!branch || branch === "HEAD" || branch === "main") {
    found.push(`branch rule: gh pr create must target a ${rules.workBranchForm} branch, not "${branch ?? "detached HEAD"}".`);
    return found;
  }
  const isLegacy = rules.legacyPreSlugBranches.has(branch);
  const match = rules.workBranch.exec(branch);
  if (!isLegacy && (!match || !isValidWorkBranch(branch, rules))) {
    found.push(`branch rule: branch "${branch}" must follow ${rules.workBranchForm} (3 to 60 lowercase kebab-case characters).`);
    return found;
  }
  const issueNum = isLegacy ? /^issue\/([1-9][0-9]*)$/.exec(branch)?.[1] : match[1];
  const slug = isLegacy ? undefined : match[2];
  const linkMatch = body.match(ISSUE_LINK_RE);
  if (!linkMatch || (issueNum && !new RegExp(`(?:${ISSUE_KEYWORDS}):?\\s+#${issueNum}\\b`, "i").test(body))) {
    found.push(`branch rule: pull request body must target issue #${issueNum ?? "<n>"} with 'Refs #${issueNum ?? "<n>"}' or 'Closes #${issueNum ?? "<n>"}'.`);
  }
  if (!isLegacy) {
    const title = optionValue(command, "--title") ?? "";
    if (!hasIssueNameInPull(title, body, issueNum, slug)) {
      found.push(`branch rule: pull request must include the issue name in its title (matching "${slug}") or an 'Issue: #${issueNum} <title>' body line.`);
    }
  }
  if (issueNum) {
    try {
      const openPrs = listOpenPrs(cwd);
      const conflict = openPrs.find((pr) => {
        if (pr.headRefName === branch) return true;
        const headIssue = /^issue\/([1-9][0-9]*)(?:-|$)/.exec(pr.headRefName ?? "")?.[1];
        if (headIssue === issueNum) return true;
        const prBody = String(pr.body ?? "");
        return new RegExp(`(?:^|\\n)[ \\t]*(?:Refs|Close|Closes|Closed|Fix|Fixes|Fixed|Resolve|Resolves|Resolved):?[ \\t]+#${issueNum}\\b`, "im").test(prBody);
      });
      if (conflict) {
        found.push(`branch rule: issue #${issueNum} already has open pull request #${conflict.number} (${conflict.headRefName}); one issue gets only one PR.`);
      }
    } catch {
      // Offline or unauthenticated `gh`: CI branch-check catches duplicates before landing.
    }
  }
  return found;
}

function defaultListOpenPrs(cwd) {
  return JSON.parse(run("gh", ["pr", "list", "--state", "open", "--limit", "100", "--json", "number,headRefName,body"], cwd));
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
    const pr = JSON.parse(run("gh", ["pr", "view", merge[1], "--json", "files,body,headRefOid,headRefName,title"], cwd));
    return { files: pr.files.map((file) => file.path), body: pr.body ?? "", ref: pr.headRefOid, headRefName: pr.headRefName, title: pr.title };
  }
  const head = optionValue(command, "--head");
  const base = resolveRef(["origin/main", "main"], cwd);
  const ref = resolveRef([head ? `origin/${head}` : undefined, head, "HEAD"], cwd);
  const body = bodyFromCommand(command, cwd);
  return { files: diffFiles(`${base}...${ref}`, cwd), body, ref };
}

function fromCi(cwd = process.cwd()) {
  const { BASE, HEAD, BODY } = process.env;
  return { files: diffFiles(`${BASE}...${HEAD}`, cwd), body: (BODY ?? "").replace(/\r/g, ""), ref: HEAD };
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

export function findings({ files, body, ref }, cwd = process.cwd()) {
  const found = [];
  const codeChanged = files.some((f) => CODE.test(f));
  if (codeChanged && !files.some((f) => DOCS.test(f)) && !DOCS_ESCAPE.test(body)) {
    found.push(
      "design/34 §1 and §3: code changed but no docs did. Update the design doc (docs/design), the docs site (docs/product, site/) or a README, or add a body line 'Docs: unchanged because <reason>'.",
    );
  }
  if (/Closes #\d+/.test(body)) {
    const category = body.match(/category\s*=\s*\\?"([\w-]+)\\?"/)?.[1];
    if (!body.includes("[release_note]") || !NOTE_CATEGORIES.includes(category)) {
      found.push(
        `design/34 §14: the body needs a [release_note] block with category one of ${NOTE_CATEGORIES.join(", ")}.`,
      );
    } else if (["breaking", "deprecation"].includes(category) && !/action_required\s*=\s*\\?"[^"\\\s]/.test(body)) {
      found.push("design/34 §14: a breaking or deprecation release note needs action_required.");
    }
  }
  for (const path of files.filter((f) => PRODUCT_PAGE.test(f) || PUBLISHED.test(f))) {
    const text = fileAt(ref, path, cwd);
    if (text === undefined) continue;
    if (PRODUCT_PAGE.test(path)) {
      const keys = frontMatterKeys(text);
      const missing = FRONT_MATTER_KEYS.filter((key) => !keys.includes(key));
      if (missing.length) found.push(`design/34 §1: ${path} front matter lacks ${missing.join(", ")}.`);
    }
    if (THIRD_PARTY.test(text)) found.push(`design/34 §1 (F11): ${path} loads a third-party script, font or analytics.`);
    if (PIPE_TO_SHELL.test(text)) found.push(`design/34 §1: ${path} pipes a download into a shell; show a signed package and its verification.`);
  }
  return found;
}

export function evaluateHookCommand(command, cwd = process.cwd(), { listOpenPrs = defaultListOpenPrs } = {}) {
  const rules = readBranchRules();
  const found = [];
  if (/\bgit(?:\s+-C\s+\S+)?\s+push\b/.test(command)) {
    found.push(...checkGitPush(command, cwd, rules));
  }
  if (/\bgh\s+pr\s+create\b/.test(command)) {
    const ctx = fromHookCommand(command, cwd);
    found.push(...checkPrCreateRules(command, cwd, ctx.body, rules, listOpenPrs));
    found.push(...findings(ctx, cwd));
  } else if (/\bgh\s+pr\s+merge\b/.test(command)) {
    const ctx = fromHookCommand(command, cwd);
    if (!ISSUE_LINK_RE.test(ctx.body)) {
      found.push("branch rule: pull request being merged must target an issue in its body.");
    }
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
