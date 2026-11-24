// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Shared PreToolUse and CI checks:
// - Refuse direct git push to main/master; require a valid work branch name.
// - Refuse third-party analytics/fonts or curl|sh in published docs pages.
// - Enforce engineering principles (delete outdated code in pre-release beta, ban stopgaps & speculative hacks).
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { coversBranch, isValidWorkBranch, loadRules } from "./branch-findings.mjs";

// Rule 1 enforces deleting outdated unreleased dev-version code/shims during pre-release development
// (while data schemas and wire contracts remain cleanly modeled for post-GA evolution).
// Flip to false once Guardrails ships out of beta (GA release) to retire the pre-release Rule 1 check.
export const PRE_RELEASE_BETA = true;

const PRODUCT_PAGE = /^docs\/product\/(?!reference\/_generated\/).+\.mdx?$/;
const PUBLISHED = /^(site|docs\/product|docs\/runbooks|docs\/training)\/.+\.(mdx?|[cm]?[jt]sx?|json|ya?ml|css|html)$/;
const PRODUCT_SOURCE_RE = /^(?:crates|programs|desktop|web\/(?:apps|packages))\/.+\.(?:rs|[cm]?[jt]sx?)$/;
const SOURCE_TEST_RE = /(?:^|\/)(?:tests?\/|.*(?:\.test\.|_test\.))[^/]+$/;
const GENERATED_SOURCE_RE = /^\s*\/\/\s*@generated\b/;
const DEPRECATED_OR_COMPAT_RE =
  /#\[deprecated\b|@deprecated\b|\b(?:backwards?[_ -]?compat(?:ibility)?|compat[_ -]?shim|legacy[_ -]?fallback|migration[_ -]?shim|kept for compatibility|deprecated alias)\b/i;
const STOPGAP_RE =
  /\b(?:make it work for now|deal with it later|temporary workaround|temp hack|stopgap)\b|(?:\/\/|\/\*)\s*(?:HACK|FIXME|XXX):/i;
const SPECULATIVE_COMMENT_RE = /(?:\/\/|\/\*).*?\b(?:just in case|for future use)\b/i;
const FRONT_MATTER_KEYS = ["id", "type", "personas", "shapes", "covers", "owner_squad", "stability"];
const THIRD_PARTY =
  /googletagmanager|google-analytics|gtag\(|fonts\.googleapis|fonts\.gstatic|use\.typekit|plausible\.io|segment\.(io|com)|hotjar|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare/;
const PIPE_TO_SHELL = /curl[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b/;
const BRANCH_RULES_PATH = fileURLToPath(new URL("./branch-rules.json", import.meta.url));
const DESIGN_REF_RE = /(?:\bD-\d+\b|\bP\d+\b|docs\/design\/)/;
const GH_PR_CREATE_RE = /(?:^|[\s&;])\$?gh\s+pr\s+create\b/;
const GH_PR_MERGE_RE = /(?:^|[\s&;])\$?gh\s+pr\s+merge\b/;
const WEB_PACKAGE_JSON_RE = /^web\/(?:.+\/)?package\.json$/;
const DEP_SECTIONS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
const BANNED_WEB_PACKAGES = new Set([
  "next",
  "nuxt",
  "astro",
  "gatsby",
  "remix",
  "svelte",
  "vue",
  "solid-js",
  "express",
  "fastify",
  "koa",
  "hono",
  "polka",
  "restify",
  "hapi",
  "mongodb",
  "mongoose",
  "prisma",
  "drizzle-orm",
  "typeorm",
  "sequelize",
]);
const BANNED_WEB_PACKAGE_PREFIXES = [
  "@nestjs/",
  "@next/",
  "@nuxt/",
  "@prisma/",
  "@remix-run/",
  "@sveltejs/",
  "@angular/",
  "@solidjs/",
  "@hapi/",
  "@builder.io/qwik",
];

function run(command, args, cwd) {
  return execFileSync(command, args, { encoding: "utf8", cwd, stdio: ["ignore", "pipe", "ignore"] });
}

function stripQuotes(token) {
  if (
    (token.startsWith('"') && token.endsWith('"')) ||
    (token.startsWith("'") && token.endsWith("'"))
  ) {
    return token.slice(1, -1);
  }
  return token;
}

export function optionValue(command, name) {
  const tokens = command.match(/"[^"]*"|'[^']*'|[^\s]+/g) ?? [];
  for (let i = 0; i < tokens.length; i += 1) {
    const tok = tokens[i];
    if (tok === name && i + 1 < tokens.length) {
      return stripQuotes(tokens[i + 1]);
    }
    if (tok.startsWith(`${name}=`)) {
      return stripQuotes(tok.slice(name.length + 1));
    }
  }
  return undefined;
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

function extractPrBodyText(command, cwd) {
  const inline = optionValue(command, "--body") ?? optionValue(command, "-b");
  if (inline) return inline;
  const bodyFile = optionValue(command, "--body-file") ?? optionValue(command, "-F");
  if (!bodyFile) return "";
  try {
    return readFileSync(resolve(cwd, bodyFile), "utf8");
  } catch {
    return "";
  }
}

export function checkPrBodyAlignment(body) {
  const found = [];
  if (typeof body !== "string" || !/(?:Closes|Fixes|Resolves|Refs?)\s+#\d+/i.test(body)) {
    found.push("pr rule: every PR must have an accompanying GitHub issue linked in the PR body (for example, Closes #42).");
  }
  if (typeof body !== "string" || !DESIGN_REF_RE.test(body)) {
    found.push(
      "pr rule: every PR must cite a governing docs/design/ path or decision/principle ID (for example, D-42, P14, or docs/design/00-decisions.md).",
    );
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
  found.push(...checkPrBodyAlignment(extractPrBodyText(command, cwd)));
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

export function isProductSourcePath(relPath) {
  return PRODUCT_SOURCE_RE.test(relPath) && !SOURCE_TEST_RE.test(relPath);
}

export function isWebPackageJsonPath(relPath) {
  return WEB_PACKAGE_JSON_RE.test(relPath) && !/(?:^|\/)node_modules\//.test(relPath);
}

function isBannedWebPackage(pkgName) {
  return (
    BANNED_WEB_PACKAGES.has(pkgName) ||
    BANNED_WEB_PACKAGE_PREFIXES.some((prefix) => pkgName.startsWith(prefix))
  );
}

function extractPackageNamesFromManifest(content) {
  try {
    const parsed = JSON.parse(content);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const names = [];
      for (const section of DEP_SECTIONS) {
        const deps = parsed[section];
        if (deps && typeof deps === "object" && !Array.isArray(deps)) {
          names.push(...Object.keys(deps));
        }
      }
      return names;
    }
  } catch {
    // edit_file payloads pass partial JSON fragments rather than a full manifest.
  }
  const names = [];
  const propRe = /"([^"\s]+)"\s*:\s*"[^"]*"/g;
  let match;
  while ((match = propRe.exec(content)) !== null) {
    names.push(match[1]);
  }
  return names;
}

export function checkWebStack(relPath, content) {
  if (!isWebPackageJsonPath(relPath) || typeof content !== "string") {
    return [];
  }
  const found = [];
  const seen = new Set();
  for (const pkg of extractPackageNamesFromManifest(content)) {
    if (seen.has(pkg) || !isBannedWebPackage(pkg)) continue;
    seen.add(pkg);
    found.push(
      `stack alignment (${relPath}, D-33/D-42): unapproved package "${pkg}" is forbidden; web/ is a static Vite + React 19 bundle on pnpm served by Rust programs/grdr-server.`,
    );
  }
  return found;
}

function normalizeRepoPath(filePath, cwd = process.cwd()) {
  if (!filePath || typeof filePath !== "string") return "";
  const normalized = filePath.replace(/\\/g, "/");
  if (/^[A-Za-z]:\//.test(normalized) || normalized.startsWith("/")) {
    return relative(resolve(cwd), resolve(filePath)).replace(/\\/g, "/");
  }
  return normalized.replace(/^\.\//, "");
}

export function checkEngineeringContent(
  relPath,
  content,
  { preReleaseBeta = PRE_RELEASE_BETA } = {},
) {
  if (!isProductSourcePath(relPath) || typeof content !== "string" || GENERATED_SOURCE_RE.test(content)) {
    return [];
  }
  const found = [];
  if (preReleaseBeta && DEPRECATED_OR_COMPAT_RE.test(content)) {
    found.push(
      `engineering rule 1 (${relPath}, pre-release beta): delete outdated code outright instead of adding deprecated annotations or backward-compatibility shims.`,
    );
  }
  if (SPECULATIVE_COMMENT_RE.test(content)) {
    found.push(
      `engineering rule 2 (${relPath}): avoid speculative "just in case" or "for future use" layers; implement the simplest design for current needs.`,
    );
  }
  if (STOPGAP_RE.test(content)) {
    found.push(
      `engineering rule 7 (${relPath}): remove stopgap/HACK/FIXME workarounds; fix the architecture directly.`,
    );
  }
  return found;
}

function stagedProductFiles(cwd) {
  return run("git", ["diff", "--cached", "--name-only", "--diff-filter=d"], cwd)
    .split(/\r?\n/)
    .filter(Boolean);
}

function checkFileContent(relPath, content, options) {
  return [
    ...checkEngineeringContent(relPath, content, options),
    ...checkWebStack(relPath, content),
  ];
}

export function evaluateEngineeringPayload(payload, cwd = process.cwd(), options = {}) {
  if (!payload || typeof payload !== "object") return [];

  const agyToolName = payload?.toolCall?.name ?? "";
  if (agyToolName === "write_file" || agyToolName === "edit_file") {
    const args = payload?.toolCall?.args ?? {};
    const relPath = normalizeRepoPath(args.Path ?? "", cwd);
    const snippet = args.Content ?? args.Replacement ?? "";
    return checkFileContent(relPath, snippet, options);
  }

  const claudeTool = payload?.tool_name ?? "";
  const claudeInput = payload?.tool_input ?? {};
  if (claudeTool === "Write" || claudeTool === "Edit") {
    const relPath = normalizeRepoPath(claudeInput.file_path ?? "", cwd);
    const snippet = claudeInput.content ?? claudeInput.new_string ?? "";
    return checkFileContent(relPath, snippet, options);
  }
  if (claudeTool === "MultiEdit" && Array.isArray(claudeInput.edits)) {
    const relPath = normalizeRepoPath(claudeInput.file_path ?? "", cwd);
    const combined = claudeInput.edits.map((e) => e?.new_string ?? "").join("\n");
    return checkFileContent(relPath, combined, options);
  }

  const command = payload?.tool_input?.command ?? payload?.toolCall?.args?.CommandLine ?? "";
  if (typeof command === "string" && /\bgit(?:\s+-C\s+\S+)?\s+commit\b/.test(command)) {
    const found = [];
    for (const relPath of stagedProductFiles(cwd)) {
      if (!isProductSourcePath(relPath) && !isWebPackageJsonPath(relPath)) continue;
      const full = resolve(cwd, relPath);
      if (!existsSync(full)) continue;
      found.push(...checkFileContent(relPath, readFileSync(full, "utf8"), options));
    }
    return found;
  }

  return [];
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
  for (const path of files.filter((f) => isProductSourcePath(f))) {
    const text = fileAt(ref, path, cwd);
    if (text === undefined) continue;
    found.push(...checkEngineeringContent(path, text));
  }
  for (const path of files.filter((f) => isWebPackageJsonPath(f))) {
    const text = fileAt(ref, path, cwd);
    if (text === undefined) continue;
    found.push(...checkWebStack(path, text));
  }
  return found;
}

export function evaluateHookCommand(command, cwd = process.cwd()) {
  const rules = readBranchRules();
  const found = [];
  if (/\bgit(?:\s+-C\s+\S+)?\s+push\b/.test(command)) {
    found.push(...checkGitPush(command, cwd, rules));
  }
  if (GH_PR_CREATE_RE.test(command)) {
    const ctx = fromHookCommand(command, cwd);
    found.push(...checkPrCreateRules(command, cwd, rules));
    found.push(...findings(ctx, cwd));
  } else if (GH_PR_MERGE_RE.test(command)) {
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
      const found = [
        ...evaluateHookCommand(command, cwd),
        ...evaluateEngineeringPayload(payload, cwd),
      ];
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
