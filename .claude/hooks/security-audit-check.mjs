// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Enforces independent Principal Security & Safe-Coding Judge audit before committing or opening PRs for non-UI changes.
import { createHash, randomBytes } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SECURITY_AUDIT_RECORD_REL,
  gitOptionalBuffer,
  gitOptionalLine,
  gitRequiredLinesZ,
  isGitRepository,
  parseRequiredNameStatusZ,
  printableText,
  readBytesForSource,
  readCleanAuditBytes,
  resolveGitRef,
  resolveParentHead,
  resolveRepoRoot,
  resolveSecurityAuditRecordPath,
} from "./security-audit-git.mjs";
import { globSpecToMatcher, isSafeRepoRelative, normalizeRepoRelPath } from "./security-audit-glob.mjs";
import { parseToolCommandPlan } from "./security-audit-scan.mjs";

export { SECURITY_AUDIT_RECORD_REL, resolveSecurityAuditRecordPath };
export const NON_UI_SECURITY_AUDIT_RE =
  /^(?:crates\/(?!grdr-ui-model\/)|programs\/|bpf\/|proto\/|schema\/|deploy\/|scripts\/|platform\/|\.github\/(?:workflows|actions)\/|\.claude\/(?:hooks\/|settings\.json$)|\.agents\/(?:hooks\/|hooks\.json$)|security\/|supply-chain\/|web\/packages\/api\/)/i;
export const IGNORED_NON_UI_RE =
  /(?:^|\/)node_modules\/|^target\/|^(?:crates|programs)\/[^/]+\/target\/|^web\/(?:packages\/[^/]+\/)?dist(?:-operator)?\/|\.(?:png|jpe?g|gif|webp|ico|woff2?|pdf)$/i;

const TRUST_CORE_PATHS_REL = "security/trust-core.paths";
const SHA256_LOWER_HEX_RE = /^[0-9a-f]{64}$/;
const DELETED_MARKER = "DELETED";
const VALID_SOURCES = new Set(["disk", "staged", "head"]);
const VALID_VERDICTS = new Set(["pass", "fail"]);

function parseStrictNonNegInt(value, label) {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
  if (typeof value === "string" && /^\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    if (Number.isSafeInteger(parsed) && parsed >= 0) return parsed;
  }
  throw new Error(`GRDR-HOOK-0001 invalid ${label}: expected non-negative integer`);
}

function uniqueSorted(items) {
  return [...new Set(items)].sort();
}

function discoverBranchState(rootDir) {
  if (!isGitRepository(rootDir)) {
    return { ok: true, files: [], deletedFiles: new Set() };
  }
  const base = resolveGitRef(["origin/main", "main"], rootDir);
  const hasHead = Boolean(gitOptionalLine(["rev-parse", "--verify", "--quiet", "HEAD"], rootDir));
  const staged = parseRequiredNameStatusZ(["diff", "--no-ext-diff", "--cached", "--name-status", "-z"], rootDir);
  const unstaged = parseRequiredNameStatusZ(["diff", "--no-ext-diff", "--name-status", "-z"], rootDir);
  const untracked = gitRequiredLinesZ(["ls-files", "--others", "--exclude-standard", "-z"], rootDir);
  const branchDiff =
    base && hasHead ? parseRequiredNameStatusZ(["diff", "--no-ext-diff", "--name-status", "-z", `${base}...HEAD`], rootDir) : { ok: true, files: [], deleted: new Set() };

  for (const res of [staged, unstaged, untracked, branchDiff]) {
    if (!res.ok) return { ok: false, error: res.error, files: [], deletedFiles: new Set() };
  }

  const mergedFiles = [...branchDiff.files, ...staged.files, ...unstaged.files];
  const deletedSet = new Set([...branchDiff.deleted, ...staged.deleted, ...unstaged.deleted]);
  const stagedSet = new Set(staged.files);
  const unstagedSet = new Set(unstaged.files);
  for (const file of untracked.lines) {
    const norm = normalizeRepoRelPath(file);
    if (norm) {
      mergedFiles.push(norm);
      if (!staged.deleted.has(norm) && !branchDiff.deleted.has(norm)) deletedSet.delete(norm);
    }
  }
  for (const del of [...deletedSet]) {
    if (staged.deleted.has(del)) continue;
    if (branchDiff.deleted.has(del) && !stagedSet.has(del) && !unstagedSet.has(del)) continue;
    if (existsSync(resolve(rootDir, del))) deletedSet.delete(del);
  }
  const files = uniqueSorted(mergedFiles.filter((f) => isNonUiSecurityPath(f, rootDir)));
  return { ok: true, files, deletedFiles: new Set([...deletedSet].filter((f) => isNonUiSecurityPath(f, rootDir))) };
}

export function loadTrustCoreMatchers(cwd = process.cwd(), ctx, headRef) {
  const rootDir = resolveRepoRoot(cwd, ctx);
  const rawLines = [];
  const trustCoreAbs = resolve(rootDir, TRUST_CORE_PATHS_REL);
  let tcStat;
  try {
    tcStat = lstatSync(trustCoreAbs);
  } catch {
    tcStat = undefined;
  }
  if (tcStat?.isSymbolicLink()) {
    throw new Error("GRDR-HOOK-0001 refusing symlinked security/trust-core.paths");
  }
  const diskBuf = readBytesForSource(rootDir, TRUST_CORE_PATHS_REL, "disk", "HEAD", ctx);
  if (diskBuf) rawLines.push(...diskBuf.toString("utf8").split(/\r?\n/));
  const stagedBuf = gitOptionalBuffer(["cat-file", "blob", `:${TRUST_CORE_PATHS_REL}`], rootDir, ctx);
  if (stagedBuf) rawLines.push(...stagedBuf.toString("utf8").split(/\r?\n/));
  const headBuf = gitOptionalBuffer(["cat-file", "blob", `HEAD:${TRUST_CORE_PATHS_REL}`], rootDir, ctx);
  if (headBuf) rawLines.push(...headBuf.toString("utf8").split(/\r?\n/));
  if (headRef && headRef !== "HEAD") {
    const refBuf = gitOptionalBuffer(["cat-file", "blob", `${headRef}:${TRUST_CORE_PATHS_REL}`], rootDir, ctx);
    if (refBuf) rawLines.push(...refBuf.toString("utf8").split(/\r?\n/));
  }
  const baseRef = resolveGitRef(["origin/main", "main"], rootDir, ctx);
  if (baseRef && baseRef !== "HEAD" && baseRef !== headRef) {
    const baseBuf = gitOptionalBuffer(["cat-file", "blob", `${baseRef}:${TRUST_CORE_PATHS_REL}`], rootDir, ctx);
    if (baseBuf) rawLines.push(...baseBuf.toString("utf8").split(/\r?\n/));
  }

  const seen = new Set();
  const matchers = [];
  for (const raw of rawLines) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#") || seen.has(trimmed)) continue;
    seen.add(trimmed);
    const matcher = globSpecToMatcher(trimmed);
    if (matcher) matchers.push(matcher);
  }
  return matchers;
}

export function findTrustCoreFiles(files, cwd = process.cwd(), ctx, headRef) {
  const matchers = loadTrustCoreMatchers(cwd, ctx, headRef);
  if (matchers.length === 0) return [];
  const rootDir = resolveRepoRoot(cwd, ctx);
  const matched = [];
  const seen = new Set();
  for (const raw of files) {
    const norm = normalizeRepoRelPath(raw, rootDir);
    if (!norm || seen.has(norm)) continue;
    if (matchers.some((re) => re.test(norm))) {
      seen.add(norm);
      matched.push(norm);
    }
  }
  return matched;
}

export function isNonUiSecurityPath(relPath, cwd, ctx, headRef) {
  const needsRoot = typeof relPath === "string" && cwd && (isAbsolute(relPath) || /^[A-Za-z]:[\\/]/.test(relPath));
  const norm = normalizeRepoRelPath(relPath, needsRoot ? resolveRepoRoot(cwd, ctx) : undefined);
  if (!norm || norm.startsWith("../") || norm === "..") return false;
  if (!IGNORED_NON_UI_RE.test(norm) && NON_UI_SECURITY_AUDIT_RE.test(norm)) return true;
  const rootDir = cwd ? resolveRepoRoot(cwd, ctx) : resolveRepoRoot(process.cwd(), ctx);
  return findTrustCoreFiles([norm], rootDir, ctx, headRef).length > 0;
}

export function collectNonUiFileHashes(cwd = process.cwd(), files = [], { source = "disk", headRef = "HEAD", deletedFiles, canonicalClean = false, ctx } = {}) {
  if (!VALID_SOURCES.has(source)) throw new Error(`GRDR-HOOK-0001 invalid hash source "${String(source)}"`);
  const rootDir = resolveRepoRoot(cwd, ctx);
  const deletedSet = deletedFiles instanceof Set ? deletedFiles : new Set(Array.isArray(deletedFiles) ? deletedFiles : []);
  const normalized = uniqueSorted(
    files.map((file) => normalizeRepoRelPath(file, rootDir)).filter((file) => isSafeRepoRelative(file, rootDir)),
  );
  const out = {};
  for (const relPath of normalized) {
    if (deletedSet.has(relPath)) { out[relPath] = DELETED_MARKER; continue; }
    const bytes = canonicalClean && source === "disk"
      ? readCleanAuditBytes(rootDir, relPath, ctx)
      : readBytesForSource(rootDir, relPath, source, headRef, ctx);
    if (bytes !== undefined) out[relPath] = createHash("sha256").update(bytes).digest("hex");
  }
  return out;
}

export function discoverChangedNonUiFiles(cwd = process.cwd()) {
  const state = discoverBranchState(resolveRepoRoot(cwd));
  if (!state.ok) throw new Error(`GRDR-HOOK-0001 ${state.error}`);
  return state.files;
}

export function recordSecurityAudit({
  cwd = process.cwd(), verdict = "pass", summary = "", unresolvedIssues = 0, unresolvedHardening = 0, reviewer = "grdr-security-judge", files,
}) {
  const cleanVerdict = typeof verdict === "string" ? verdict.trim() : "";
  if (!VALID_VERDICTS.has(cleanVerdict)) throw new Error('GRDR-HOOK-0001 verdict must be "pass" or "fail"');
  if (typeof reviewer !== "string" || !reviewer.trim()) throw new Error("GRDR-HOOK-0001 reviewer must be a non-empty string");
  const cleanIssues = parseStrictNonNegInt(unresolvedIssues, "unresolvedIssues");
  const cleanHardening = parseStrictNonNegInt(unresolvedHardening, "unresolvedHardening");

  const rootDir = resolveRepoRoot(cwd);
  const discovered = Array.isArray(files) ? undefined : discoverBranchState(rootDir);
  if (discovered && !discovered.ok) throw new Error(`GRDR-HOOK-0001 ${discovered.error}`);

  const targetFiles = Array.isArray(files)
    ? uniqueSorted(files.map((f) => normalizeRepoRelPath(f, rootDir)).filter((f) => isNonUiSecurityPath(f, rootDir)))
    : discovered.files;
  const deletedFiles = discovered ? discovered.deletedFiles : new Set(targetFiles.filter((f) => !existsSync(resolve(rootDir, f))));
  const trustCoreFiles = findTrustCoreFiles(targetFiles, rootDir);
  const record = {
    recordedAt: new Date().toISOString(),
    verdict: cleanVerdict,
    unresolvedIssues: cleanIssues,
    unresolvedHardening: cleanHardening,
    reviewer: reviewer.trim(),
    summary: String(summary ?? ""),
    trustCoreTouched: trustCoreFiles.length > 0,
    trustCoreFiles,
    fileHashes: collectNonUiFileHashes(rootDir, targetFiles, { source: "disk", deletedFiles, canonicalClean: true }),
  };

  const target = resolveSecurityAuditRecordPath(cwd);
  mkdirSync(dirname(target), { recursive: true });
  try {
    if (lstatSync(target).isSymbolicLink()) throw new Error("GRDR-HOOK-0001 refusing to overwrite symlinked audit record");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const tmpTarget = `${target}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    writeFileSync(tmpTarget, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
    renameSync(tmpTarget, target);
  } catch (error) {
    if (existsSync(tmpTarget)) unlinkSync(tmpTarget);
    throw error;
  }
  return record;
}

export function evaluateSecurityAuditFiles(
  changedFiles,
  cwd = process.cwd(),
  { source = "disk", headRef = "HEAD", deletedFiles, canonicalClean = false, gitDir, ctx } = {},
) {
  if (!VALID_SOURCES.has(source)) return [`security-audit: invalid hash source "${printableText(source)}".`];
  const rootDir = resolveRepoRoot(cwd, ctx);
  const nonUiFiles = uniqueSorted(
    (Array.isArray(changedFiles) ? changedFiles : [])
      .map((f) => normalizeRepoRelPath(f, rootDir))
      .filter((f) => isNonUiSecurityPath(f, rootDir, ctx, headRef)),
  );
  if (nonUiFiles.length === 0) return [];

  const trustCoreFiles = findTrustCoreFiles(nonUiFiles, rootDir, ctx, headRef);
  const trustCoreNote =
    trustCoreFiles.length > 0
      ? ` Trust-core paths touched (${trustCoreFiles.map((f) => printableText(f, 80)).join(", ")}): heightened adversarial audit required per ${TRUST_CORE_PATHS_REL}.`
      : "";

  let recordPath;
  try {
    recordPath = resolveSecurityAuditRecordPath(cwd, gitDir);
  } catch (error) {
    return [`security-audit: ${printableText(error.message, 120)}.${trustCoreNote}`];
  }

  let recordStat;
  try {
    recordStat = lstatSync(recordPath);
  } catch {
    const fileList = nonUiFiles.map((f) => printableText(f, 80)).join(", ");
    return [
      "security-audit: non-UI changes detected (" +
        fileList +
        ") without a security judge audit record." +
        trustCoreNote +
        ' Run grdr-security-audit and record with: node .claude/hooks/security-audit-check.mjs --record --verdict pass --unresolved 0 --unresolved-hardening 0 --reviewer "<judge-id>" --summary "<summary>"',
    ];
  }
  if (recordStat.isSymbolicLink() || !recordStat.isFile()) {
    return [`security-audit: audit record at ${printableText(recordPath, 80)} is not a regular file.${trustCoreNote}`];
  }

  let record;
  try {
    record = JSON.parse(readFileSync(recordPath, "utf8"));
  } catch {
    return [`security-audit: audit record at ${printableText(recordPath, 80)} is unreadable.${trustCoreNote} Re-run grdr-security-audit and record cleanly.`];
  }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return [`security-audit: audit record at ${printableText(recordPath, 80)} is malformed.${trustCoreNote} Re-run grdr-security-audit and record cleanly.`];
  }

  const issuesValid = Number.isInteger(record.unresolvedIssues) && record.unresolvedIssues >= 0;
  const hardeningValid = Number.isInteger(record.unresolvedHardening) && record.unresolvedHardening >= 0;
  const reviewerValid = typeof record.reviewer === "string" && record.reviewer.trim().length > 0;
  const timestampValid = typeof record.recordedAt === "string" && !Number.isNaN(Date.parse(record.recordedAt));
  const trustFlagValid = typeof record.trustCoreTouched === "boolean" && record.trustCoreTouched === (trustCoreFiles.length > 0);
  const trustListValid =
    Array.isArray(record.trustCoreFiles) &&
    record.trustCoreFiles.every((f) => typeof f === "string") &&
    (trustCoreFiles.length > 0 || record.trustCoreFiles.length === 0) &&
    trustCoreFiles.every((f) => record.trustCoreFiles.includes(f));

  if (
    record.verdict !== "pass" || !issuesValid || !hardeningValid ||
    record.unresolvedIssues !== 0 || record.unresolvedHardening !== 0 ||
    !reviewerValid || !timestampValid || !trustFlagValid || !trustListValid
  ) {
    const issueStr = issuesValid ? String(record.unresolvedIssues) : "invalid";
    const hardStr = hardeningValid ? String(record.unresolvedHardening) : "invalid";
    return [
      `security-audit: last security judge verdict is "${printableText(record.verdict ?? "unknown")}" with ${issueStr} blocking and ${hardStr} hardening issue(s) (metadata valid: ${reviewerValid && timestampValid && trustFlagValid && trustListValid}).${trustCoreNote} Action every finding and re-run the judge.`,
    ];
  }

  const currentHashes = collectNonUiFileHashes(rootDir, nonUiFiles, { source, headRef, deletedFiles, canonicalClean, ctx });
  const recordedHashes =
    record.fileHashes && typeof record.fileHashes === "object" && !Array.isArray(record.fileHashes) ? record.fileHashes : {};
  const stale = nonUiFiles.filter((file) => {
    if (!Object.hasOwn(recordedHashes, file)) return true;
    const currentHash = currentHashes[file];
    const recordedHash = recordedHashes[file];
    if (typeof currentHash !== "string" || typeof recordedHash !== "string") return true;
    if (currentHash === DELETED_MARKER) return recordedHash !== DELETED_MARKER;
    return !SHA256_LOWER_HEX_RE.test(recordedHash) || currentHash !== recordedHash;
  });
  if (stale.length > 0) {
    return [
      `security-audit: non-UI file(s) updated or unaudited since last security judge pass (${stale.map((f) => printableText(f, 80)).join(", ")}).${trustCoreNote} Re-run the Principal Security & Safe-Coding Judge and record cleanly.`,
    ];
  }
  return [];
}

function evaluateCommitAction(action) {
  let effectiveGitDir = action.gitDir;
  if (!effectiveGitDir && action.hasExplicitWorkTree && action.gitDiscoveryCwd) {
    try {
      resolveSecurityAuditRecordPath(action.gitDiscoveryCwd);
    } catch (error) {
      return [`security-audit: ${printableText(error.message, 120)}.`];
    }
    const discovered = gitOptionalLine(["rev-parse", "--git-dir"], action.gitDiscoveryCwd);
    if (!discovered) {
      return [`security-audit: cannot inspect git state at "${printableText(action.gitDiscoveryCwd, 80)}"; failing closed.`];
    }
    effectiveGitDir = resolve(action.gitDiscoveryCwd, discovered);
  }
  const ctx = effectiveGitDir
    ? (action.hasExplicitWorkTree ? { gitDir: effectiveGitDir, workTree: action.targetCwd } : { gitDir: effectiveGitDir })
    : undefined;
  if (!isGitRepository(action.targetCwd, ctx)) {
    return [`security-audit: cannot inspect git state at "${printableText(action.targetCwd, 80)}"; failing closed.`];
  }
  const rootDir = resolveRepoRoot(action.targetCwd, ctx);
  const useDisk = action.chainedAdd || action.hasAll || action.hasPathspecOrPartial;
  const staged = parseRequiredNameStatusZ(["diff", "--no-ext-diff", "--cached", "--name-status", "-z"], rootDir, ctx);
  if (!staged.ok) return [`security-audit: failed reading staged git diff (${staged.error}).`];

  const files = [...staged.files];
  const deleted = new Set(staged.deleted);
  if (action.hasAmend) {
    const hasParent = resolveParentHead(rootDir, ctx);
    const amendDiff = hasParent
      ? parseRequiredNameStatusZ(["diff", "--no-ext-diff", "--cached", "--name-status", "-z", "HEAD~1"], rootDir, ctx)
      : parseRequiredNameStatusZ(["diff-tree", "--no-ext-diff", "-r", "--root", "--no-commit-id", "--name-status", "-z", "HEAD"], rootDir, ctx);
    if (!amendDiff.ok) return [`security-audit: failed reading amended git diff (${amendDiff.error}).`];
    files.push(...amendDiff.files);
    for (const d of amendDiff.deleted) deleted.add(d);
  }
  if (useDisk) {
    const unstaged = parseRequiredNameStatusZ(["diff", "--no-ext-diff", "--name-status", "-z"], rootDir, ctx);
    if (!unstaged.ok) return [`security-audit: failed reading working tree diff (${unstaged.error}).`];
    files.push(...unstaged.files);
    for (const d of unstaged.deleted) deleted.add(d);
    if (action.chainedAdd) {
      const untracked = gitRequiredLinesZ(["ls-files", "--others", "--exclude-standard", "-z"], rootDir, ctx);
      if (!untracked.ok) return [`security-audit: failed listing untracked files (${untracked.error}).`];
      files.push(...untracked.lines);
    }
    for (const d of [...deleted]) {
      if ((action.chainedAdd || !staged.deleted.has(d)) && existsSync(resolve(rootDir, d))) deleted.delete(d);
    }
  }
  return evaluateSecurityAuditFiles(uniqueSorted(files), action.targetCwd, {
    source: useDisk ? "disk" : "staged", canonicalClean: useDisk, deletedFiles: deleted, gitDir: effectiveGitDir, ctx,
  });
}

function evaluatePrCreateAction(action) {
  if (!isGitRepository(action.targetCwd)) {
    return [`security-audit: cannot inspect git repository at "${printableText(action.targetCwd, 80)}" for gh pr create.`];
  }
  const rootDir = resolveRepoRoot(action.targetCwd);
  const baseCandidates = action.baseOpt ? [`origin/${action.baseOpt}`, action.baseOpt] : ["origin/main", "main"];
  const base = resolveGitRef(baseCandidates, rootDir);
  if (!base) return [`security-audit: cannot resolve PR base ref (${baseCandidates.map((r) => printableText(r, 40)).join(" or ")}).`];
  const cleanHead = action.headOpt ? action.headOpt.replace(/^[^:]+:/, "") : undefined;
  const headCandidates = cleanHead ? [cleanHead, `origin/${cleanHead}`] : ["HEAD"];
  const headRef = resolveGitRef(headCandidates, rootDir);
  if (!headRef) return [`security-audit: cannot resolve PR head ref (${headCandidates.map((r) => printableText(r, 40)).join(" or ")}).`];

  const diff = parseRequiredNameStatusZ(["diff", "--no-ext-diff", "--name-status", "-z", `${base}...${headRef}`], rootDir);
  if (!diff.ok) return [`security-audit: failed computing PR diff ${base}...${headRef} (${diff.error}).`];
  return evaluateSecurityAuditFiles(diff.files, action.targetCwd, { source: "head", headRef, deletedFiles: diff.deleted });
}

export function evaluateSecurityAuditToolPayload(payload, cwd = process.cwd()) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return ["security-audit: malformed PreToolUse payload; expected JSON object."];
  }
  const rawName = payload.tool_name ?? payload.toolCall?.name;
  const toolName = typeof rawName === "string" ? rawName.trim() : "";
  const command = payload?.tool_input?.command ?? payload?.toolCall?.args?.CommandLine;
  if (command === undefined) {
    if (!toolName || toolName === "Bash" || toolName === "PowerShell" || toolName === "run_command") {
      return ["security-audit: missing command field in command-execution PreToolUse payload."];
    }
    return [];
  }
  if (typeof command !== "string") return ["security-audit: malformed command field in PreToolUse payload."];
  if (!command) return [];

  const plan = parseToolCommandPlan(command, cwd);
  const findings = [...plan.errors];
  for (const action of plan.actions) {
    if (action.type === "commit") findings.push(...evaluateCommitAction(action));
    else if (action.type === "pr_create") findings.push(...evaluatePrCreateAction(action));
  }
  return findings;
}

function getCliArg(argv, flag, fallback) {
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === flag) {
      if (i + 1 >= argv.length) throw new Error(`GRDR-HOOK-0001 missing value for flag ${flag}`);
      return argv[i + 1];
    }
    if (argv[i].startsWith(`${flag}=`)) return argv[i].slice(flag.length + 1);
  }
  return fallback;
}

function canonicalPath(targetPath) {
  let out;
  try {
    out = realpathSync(targetPath);
  } catch {
    out = resolve(targetPath);
  }
  return process.platform === "win32" ? out.toLowerCase() : out;
}

function isMainModule() {
  return Boolean(process.argv[1]) && canonicalPath(process.argv[1]) === canonicalPath(fileURLToPath(import.meta.url));
}

if (isMainModule()) {
  const argv = process.argv.slice(2);
  if (argv.includes("--record")) {
    try {
      const rawFiles = getCliArg(argv, "--files", undefined);
      const files = typeof rawFiles === "string" ? rawFiles.split(",").map((e) => e.trim()).filter(Boolean) : undefined;
      const rec = recordSecurityAudit({
        cwd: process.cwd(),
        verdict: getCliArg(argv, "--verdict", "pass"),
        summary: getCliArg(argv, "--summary", "Verified by Principal Security and Safe-Coding Judge"),
        unresolvedIssues: getCliArg(argv, "--unresolved", "0"),
        unresolvedHardening: getCliArg(argv, "--unresolved-hardening", "0"),
        reviewer: getCliArg(argv, "--reviewer", "grdr-security-judge"),
        files,
      });
      const auditRel = relative(process.cwd(), resolveSecurityAuditRecordPath(process.cwd())).replace(/\\/g, "/");
      const trustSuffix = rec.trustCoreTouched ? `, ${rec.trustCoreFiles.length} trust-core` : "";
      console.log(`Recorded security audit (${rec.verdict}, ${Object.keys(rec.fileHashes).length} non-UI file(s)${trustSuffix}) at ${auditRel}`);
      process.exit(0);
    } catch (error) {
      process.stderr.write(`security-audit record failed: ${printableText(error.message, 160)}\n`);
      process.exit(2);
    }
  }

  try {
    const payload = JSON.parse(readFileSync(0, "utf8"));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      process.stderr.write("security-audit failed closed: expected JSON object payload.\n");
      process.exit(2);
    }
    const payloadCwd = typeof payload.cwd === "string" && payload.cwd.trim() ? payload.cwd.trim() : process.cwd();
    const findings = evaluateSecurityAuditToolPayload(payload, payloadCwd);
    if (findings.length > 0) {
      process.stderr.write(`${findings.join("\n")}\n`);
      process.exit(2);
    }
  } catch (error) {
    process.stderr.write(`security-audit failed closed: ${printableText(error?.message ?? String(error), 160)}\n`);
    process.exit(2);
  }
}
