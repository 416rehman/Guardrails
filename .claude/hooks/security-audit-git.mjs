// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Fail-closed git inspection and audit-record path/byte helpers for security-audit-check.mjs.
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
import { isSafeRepoRelative, normalizeRepoRelPath } from "./security-audit-glob.mjs";

export const SECURITY_AUDIT_RECORD_REL = ".git/grdr-security-audit.json";
export const GIT_MAX_BUFFER_BYTES = 64 * 1024 * 1024;
const VALID_REF_RE = /^(?!-)(?!.*\.\.)[^\x00-\x20\x7f~^:?*\[\\]+$/;

export function printableText(value, maxLen = 64) {
  const clean = String(value ?? "").replace(/[^\x20-\x7e]/g, "?");
  return clean.length > maxLen ? `${clean.slice(0, maxLen)}...` : clean;
}

export function gitContextArgs(gitDir, workTree) {
  const args = [
    "--no-replace-objects",
    "-c", "core.fsmonitor=false",
    "-c", "diff.external=",
    "-c", "core.quotePath=false",
    "-c", "diff.relative=false",
    "-c", "diff.renames=false",
  ];
  if (gitDir) args.push("--git-dir", gitDir);
  if (workTree && gitDir) args.push("--work-tree", workTree);
  return args;
}

export function gitOptionalBuffer(args, cwd, { inputBuf, gitDir, workTree } = {}) {
  try {
    return execFileSync("git", [...gitContextArgs(gitDir, workTree), ...args], {
      cwd,
      input: inputBuf,
      maxBuffer: GIT_MAX_BUFFER_BYTES,
      stdio: [inputBuf === undefined ? "ignore" : "pipe", "pipe", "ignore"],
    });
  } catch {
    return undefined;
  }
}

export function gitRequiredBuffer(args, cwd, { gitDir, workTree } = {}) {
  try {
    const data = execFileSync("git", [...gitContextArgs(gitDir, workTree), ...args], {
      cwd,
      maxBuffer: GIT_MAX_BUFFER_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, data };
  } catch (error) {
    return { ok: false, error: printableText(error?.message ?? "git command failed", 140) };
  }
}

export function gitOptionalLine(args, cwd, ctx) {
  const buf = gitOptionalBuffer(args, cwd, ctx);
  return buf ? buf.toString("utf8").trim() : "";
}

export function gitRequiredLinesZ(args, cwd, ctx) {
  const res = gitRequiredBuffer(args, cwd, ctx);
  if (!res.ok) return res;
  return { ok: true, lines: res.data.toString("utf8").split("\0").filter(Boolean) };
}

export function parseRequiredNameStatusZ(args, cwd, ctx) {
  const res = gitRequiredLinesZ(args, cwd, ctx);
  if (!res.ok) return res;
  const files = [];
  const deleted = new Set();
  for (let i = 0; i < res.lines.length; i += 1) {
    const status = res.lines[i];
    const path = normalizeRepoRelPath(res.lines[i + 1] ?? "");
    i += 1;
    if (!path) continue;
    files.push(path);
    if (status === "D") deleted.add(path);
    else deleted.delete(path);
  }
  return { ok: true, files, deleted };
}

export function isGitRepository(cwd, ctx) {
  return Boolean(gitOptionalLine(["rev-parse", "--git-dir"], cwd, ctx));
}

export function resolveRepoRoot(cwd, ctx) {
  const top = gitOptionalLine(["rev-parse", "--show-toplevel"], cwd, ctx);
  if (top) return resolve(top);
  if (ctx?.workTree) return resolve(ctx.workTree);
  return resolve(cwd);
}

export function resolveParentHead(cwd, ctx) {
  return Boolean(gitOptionalLine(["rev-parse", "--verify", "--quiet", "--end-of-options", "HEAD~1"], cwd, ctx));
}

export function resolveGitRef(candidates, cwd, ctx) {
  for (const candidate of candidates) {
    if (typeof candidate !== "string" || !candidate || !VALID_REF_RE.test(candidate)) continue;
    if (gitOptionalLine(["rev-parse", "--verify", "--quiet", "--end-of-options", candidate], cwd, ctx)) {
      return candidate;
    }
  }
  return undefined;
}

function resolveDotGitRecordAt(dir) {
  const dotGit = resolve(dir, ".git");
  let stat;
  try {
    stat = lstatSync(dotGit);
  } catch {
    return undefined;
  }
  if (stat.isSymbolicLink()) {
    throw new Error("GRDR-HOOK-0001 refusing symlinked .git entry");
  }
  if (stat.isFile()) {
    const gitdirMatch = readFileSync(dotGit, "utf8").match(/^gitdir:\s*(.+)$/m);
    if (gitdirMatch) {
      const target = resolve(dir, gitdirMatch[1].trim());
      try {
        if (lstatSync(target).isSymbolicLink()) {
          throw new Error("GRDR-HOOK-0001 refusing symlinked gitdir target");
        }
      } catch (err) {
        if (err?.code !== "ENOENT") throw err;
      }
      return resolve(target, "grdr-security-audit.json");
    }
    throw new Error("GRDR-HOOK-0001 invalid .git pointer file without gitdir");
  }
  return resolve(dir, SECURITY_AUDIT_RECORD_REL);
}

export function resolveSecurityAuditRecordPath(cwd = process.cwd(), explicitGitDir) {
  if (explicitGitDir) {
    const resolvedGitDir = resolve(cwd, explicitGitDir);
    try {
      if (lstatSync(resolvedGitDir).isSymbolicLink()) {
        throw new Error("GRDR-HOOK-0001 refusing symlinked --git-dir entry");
      }
    } catch (err) {
      if (err?.code !== "ENOENT") throw err;
    }
    return resolve(resolvedGitDir, "grdr-security-audit.json");
  }
  const direct = resolveDotGitRecordAt(cwd);
  if (direct) return direct;

  const topLevel = gitOptionalLine(["rev-parse", "--show-toplevel"], cwd);
  if (topLevel && resolve(topLevel) !== resolve(cwd)) {
    const rootRecord = resolveDotGitRecordAt(resolve(topLevel));
    if (rootRecord) return rootRecord;
  }

  const discoveredGitDir = gitOptionalLine(["rev-parse", "--git-dir"], cwd);
  if (discoveredGitDir) {
    const resolved = resolve(cwd, discoveredGitDir);
    try {
      if (lstatSync(resolved).isSymbolicLink()) {
        throw new Error("GRDR-HOOK-0001 refusing symlinked .git entry");
      }
    } catch (err) {
      if (err?.code !== "ENOENT") throw err;
    }
    return resolve(resolved, "grdr-security-audit.json");
  }
  return resolve(cwd, SECURITY_AUDIT_RECORD_REL);
}

export function readBytesForSource(rootDir, relPath, source, headRef = "HEAD", ctx) {
  if (!isSafeRepoRelative(relPath, rootDir)) return undefined;
  if (source === "staged") return gitOptionalBuffer(["cat-file", "blob", `:${relPath}`], rootDir, ctx);
  if (source === "head") {
    if (!VALID_REF_RE.test(headRef)) return undefined;
    return gitOptionalBuffer(["cat-file", "blob", `${headRef}:${relPath}`], rootDir, ctx);
  }

  const absPath = resolve(rootDir, relPath);
  let lstat;
  try {
    lstat = lstatSync(absPath);
  } catch {
    return undefined;
  }
  if (lstat.isSymbolicLink() || !lstat.isFile() || lstat.size > GIT_MAX_BUFFER_BYTES) return undefined;
  try {
    const realRoot = realpathSync(rootDir);
    const realFile = realpathSync(absPath);
    const relReal = relative(realRoot, realFile).replace(/\\/g, "/");
    if (!relReal || relReal.startsWith("../") || relReal === ".." || isAbsolute(relReal)) return undefined;
    return readFileSync(realFile);
  } catch {
    return undefined;
  }
}

export function readCleanAuditBytes(rootDir, relPath, ctx) {
  const diskBytes = readBytesForSource(rootDir, relPath, "disk", "HEAD", ctx);
  if (diskBytes === undefined) return undefined;
  const oidBuf = gitOptionalBuffer(["hash-object", "-t", "blob", "--stdin", "--path", relPath], rootDir, {
    ...ctx,
    inputBuf: diskBytes,
  });
  const diskOid = oidBuf ? oidBuf.toString("utf8").trim() : "";
  if (diskOid) {
    const stagedOid = gitOptionalLine(["rev-parse", "--verify", "--quiet", `:${relPath}`], rootDir, ctx);
    if (stagedOid && stagedOid === diskOid) {
      const stagedBuf = readBytesForSource(rootDir, relPath, "staged", "HEAD", ctx);
      if (stagedBuf !== undefined) return stagedBuf;
    }
    const headOid = gitOptionalLine(["rev-parse", "--verify", "--quiet", `HEAD:${relPath}`], rootDir, ctx);
    if (headOid && headOid === diskOid) {
      const headBuf = readBytesForSource(rootDir, relPath, "head", "HEAD", ctx);
      if (headBuf !== undefined) return headBuf;
    }
  }
  return diskBytes;
}
