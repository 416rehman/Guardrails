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
const VALID_BATCH_SOURCES = new Set(["disk", "staged", "head"]);
const VALID_OBJECT_TYPES = new Set(["blob", "tree", "commit", "tag"]);
const BATCH_CHUNK_SIZE = 64;
const BATCH_OBJECT_HEADER_RE = /^([0-9a-f]{40}|[0-9a-f]{64}) ([a-z]+) (0|[1-9][0-9]*)$/;
const BATCH_SUBMODULE_HEADER_RE = /^([0-9a-f]{40}|[0-9a-f]{64}) submodule$/;
const UNSAFE_PATH_CHAR_RE = /[\0\r\n]/;

function isSafeBatchPath(relPath, rootDir) {
  return (
    typeof relPath === "string" &&
    relPath.length > 0 &&
    !relPath.endsWith("/") &&
    !UNSAFE_PATH_CHAR_RE.test(relPath) &&
    normalizeRepoRelPath(relPath, rootDir) === relPath &&
    isSafeRepoRelative(relPath, rootDir)
  );
}

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

function statSafeDiskFile(rootDir, realRoot, relPath) {
  const absPath = resolve(rootDir, relPath);
  let lstat;
  try {
    lstat = lstatSync(absPath);
  } catch {
    return undefined;
  }
  if (lstat.isSymbolicLink() || !lstat.isFile() || lstat.size > GIT_MAX_BUFFER_BYTES) return undefined;
  try {
    const realFile = realpathSync(absPath);
    const relReal = relative(realRoot, realFile).replace(/\\/g, "/");
    if (!relReal || relReal.startsWith("../") || relReal === ".." || isAbsolute(relReal)) return undefined;
    return realFile;
  } catch {
    return undefined;
  }
}

function readVerifiedDiskFile(realFile) {
  try {
    const data = readFileSync(realFile);
    return data.length <= GIT_MAX_BUFFER_BYTES ? data : undefined;
  } catch {
    return undefined;
  }
}

export function readBytesForSource(rootDir, relPath, source, headRef = "HEAD", ctx) {
  if (!isSafeBatchPath(relPath, rootDir)) return undefined;
  if (source === "staged") return gitOptionalBuffer(["cat-file", "blob", `:${relPath}`], rootDir, ctx);
  if (source === "head") {
    if (typeof headRef !== "string" || !VALID_REF_RE.test(headRef)) return undefined;
    return gitOptionalBuffer(["cat-file", "blob", `${headRef}:${relPath}`], rootDir, ctx);
  }
  let realRoot;
  try {
    realRoot = realpathSync(rootDir);
  } catch {
    return undefined;
  }
  const realFile = statSafeDiskFile(rootDir, realRoot, relPath);
  return realFile ? readVerifiedDiskFile(realFile) : undefined;
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

export function parseCatFileBatchZ(outputBuf, queries, maxBlobBytes = GIT_MAX_BUFFER_BYTES) {
  if (!Buffer.isBuffer(outputBuf)) {
    throw new Error("GRDR-HOOK-0001 cat-file batch output must be a Buffer");
  }
  if (!Array.isArray(queries)) {
    throw new Error("GRDR-HOOK-0001 cat-file batch queries must be an array");
  }
  if (!Number.isSafeInteger(maxBlobBytes) || maxBlobBytes < 0) {
    throw new Error("GRDR-HOOK-0001 invalid maxBlobBytes limit");
  }
  const results = new Map();
  let offset = 0;

  for (let i = 0; i < queries.length; i += 1) {
    const query = queries[i];
    const relPath = query?.relPath;
    const spec = query?.spec;
    if (typeof relPath !== "string" || !relPath || typeof spec !== "string" || !spec) {
      throw new Error("GRDR-HOOK-0001 malformed cat-file batch query entry");
    }
    if (offset >= outputBuf.length) {
      throw new Error(`GRDR-HOOK-0001 truncated cat-file batch stream at record ${i} (${printableText(spec, 64)})`);
    }

    const nulIdx = outputBuf.indexOf(0, offset);
    if (nulIdx === -1) {
      throw new Error(`GRDR-HOOK-0001 missing NUL header terminator at record ${i}`);
    }
    const header = outputBuf.subarray(offset, nulIdx).toString("utf8");
    offset = nulIdx + 1;

    if (header === `${spec} missing` || BATCH_SUBMODULE_HEADER_RE.test(header)) continue;
    if (header === `${spec} ambiguous` || header === `${spec} excluded`) {
      throw new Error(`GRDR-HOOK-0001 cat-file batch rejected record (${printableText(header, 80)})`);
    }

    const match = header.match(BATCH_OBJECT_HEADER_RE);
    if (!match) {
      throw new Error(`GRDR-HOOK-0001 malformed or mismatched cat-file batch header (${printableText(header, 80)})`);
    }
    const objType = match[2];
    if (!VALID_OBJECT_TYPES.has(objType)) {
      throw new Error(`GRDR-HOOK-0001 invalid git object type "${printableText(objType, 32)}"`);
    }
    const size = Number(match[3]);
    if (!Number.isSafeInteger(size) || size < 0 || size > maxBlobBytes) {
      throw new Error(`GRDR-HOOK-0001 invalid or oversized git object (${size} bytes)`);
    }
    if (offset + size + 1 > outputBuf.length) {
      throw new Error(`GRDR-HOOK-0001 truncated git object payload for ${printableText(spec, 64)}`);
    }
    if (outputBuf[offset + size] !== 0) {
      throw new Error(`GRDR-HOOK-0001 missing NUL record trailer for ${printableText(spec, 64)}`);
    }

    if (objType === "blob") {
      results.set(relPath, Buffer.from(outputBuf.subarray(offset, offset + size)));
    }
    offset += size + 1;
  }

  if (offset !== outputBuf.length) {
    throw new Error(`GRDR-HOOK-0001 unexpected trailing bytes in cat-file batch stream (${outputBuf.length - offset})`);
  }
  return results;
}

function runCatFileBatchChunk(rootDir, queries, ctx) {
  const inputBuf = Buffer.from(queries.map((q) => `${q.spec}\0`).join(""), "utf8");
  let stdoutBuf;
  try {
    stdoutBuf = execFileSync("git", [...gitContextArgs(ctx?.gitDir, ctx?.workTree), "cat-file", "--batch", "-Z"], {
      cwd: rootDir,
      input: inputBuf,
      maxBuffer: GIT_MAX_BUFFER_BYTES,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (error) {
    if (error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" && queries.length > 1) {
      const mid = Math.floor(queries.length / 2);
      const left = runCatFileBatchChunk(rootDir, queries.slice(0, mid), ctx);
      const right = runCatFileBatchChunk(rootDir, queries.slice(mid), ctx);
      for (const [k, v] of right) left.set(k, v);
      return left;
    }
    throw new Error(`GRDR-HOOK-0001 git cat-file --batch -Z failed: ${printableText(error?.message ?? "git failed", 120)}`);
  }
  return parseCatFileBatchZ(stdoutBuf, queries, GIT_MAX_BUFFER_BYTES);
}

function readDiskBatchBytes(rootDir, validPaths, canonicalClean, ctx) {
  const out = new Map();
  let realRoot;
  try {
    realRoot = realpathSync(rootDir);
  } catch {
    return out;
  }

  const safePaths = [];
  const safeRealFiles = new Map();
  for (const relPath of validPaths) {
    const realFile = statSafeDiskFile(rootDir, realRoot, relPath);
    if (!realFile) continue;
    safePaths.push(relPath);
    safeRealFiles.set(relPath, realFile);
  }
  if (safePaths.length === 0) return out;

  if (!canonicalClean || !isGitRepository(rootDir, ctx)) {
    for (const relPath of safePaths) {
      const diskBuf = readVerifiedDiskFile(safeRealFiles.get(relPath));
      if (diskBuf !== undefined) out.set(relPath, diskBuf);
    }
    return out;
  }

  const dirtyRes = gitRequiredLinesZ(["diff", "--no-ext-diff", "--name-only", "-z"], rootDir, ctx);
  if (!dirtyRes.ok) {
    throw new Error(`GRDR-HOOK-0001 failed reading unstaged git diff: ${dirtyRes.error}`);
  }
  const dirtySet = new Set(dirtyRes.lines.map((p) => normalizeRepoRelPath(p)).filter(Boolean));
  const cleanCandidates = safePaths.filter((p) => !dirtySet.has(normalizeRepoRelPath(p, rootDir)));
  const stagedMap = cleanCandidates.length > 0
    ? readBatchBytesForSource(rootDir, cleanCandidates, { source: "staged", ctx })
    : new Map();
  const untrackedCandidates = cleanCandidates.filter((p) => !stagedMap.has(p));
  const headMap = untrackedCandidates.length > 0
    ? readBatchBytesForSource(rootDir, untrackedCandidates, { source: "head", headRef: "HEAD", ctx })
    : new Map();

  for (const relPath of safePaths) {
    const normRel = normalizeRepoRelPath(relPath, rootDir);
    if (!dirtySet.has(normRel)) {
      if (stagedMap.has(relPath)) {
        out.set(relPath, stagedMap.get(relPath));
        continue;
      }
      if (!headMap.has(relPath)) {
        const diskBuf = readVerifiedDiskFile(safeRealFiles.get(relPath));
        if (diskBuf !== undefined) out.set(relPath, diskBuf);
        continue;
      }
    }
    const cleanBuf = readCleanAuditBytes(rootDir, relPath, ctx);
    if (cleanBuf !== undefined) out.set(relPath, cleanBuf);
  }
  return out;
}

export function readBatchBytesForSource(
  rootDir,
  relPaths,
  { source, headRef = "HEAD", canonicalClean = false, ctx } = {},
) {
  if (!VALID_BATCH_SOURCES.has(source)) {
    throw new Error(`GRDR-HOOK-0001 invalid batch byte source "${printableText(source, 40)}"`);
  }
  if (relPaths === undefined || relPaths === null) return new Map();

  const validPaths = [];
  const seen = new Set();
  for (const relPath of relPaths) {
    if (!isSafeBatchPath(relPath, rootDir) || seen.has(relPath)) continue;
    seen.add(relPath);
    validPaths.push(relPath);
  }
  if (validPaths.length === 0) return new Map();

  if (source === "disk") {
    return readDiskBatchBytes(rootDir, validPaths, canonicalClean, ctx);
  }

  if (source === "head" && (typeof headRef !== "string" || !VALID_REF_RE.test(headRef))) {
    return new Map();
  }

  const out = new Map();
  for (let i = 0; i < validPaths.length; i += BATCH_CHUNK_SIZE) {
    const chunk = validPaths.slice(i, i + BATCH_CHUNK_SIZE);
    const queries = chunk.map((relPath) => ({
      relPath,
      spec: source === "staged" ? `:${relPath}` : `${headRef}:${relPath}`,
    }));
    const chunkMap = runCatFileBatchChunk(rootDir, queries, ctx);
    for (const [relPath, buf] of chunkMap) out.set(relPath, buf);
  }
  return out;
}
