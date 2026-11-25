// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Repo-relative path normalization and linear-time ASCII-icase glob matcher for security-audit-check.mjs.
import { posix, isAbsolute, relative, resolve } from "node:path";

export function normalizeRepoRelPath(filePath, cwd) {
  if (typeof filePath !== "string" || !filePath) return "";
  const slash = filePath.replace(/\\/g, "/").trim();
  if (!slash) return "";
  const raw =
    cwd && (isAbsolute(filePath) || /^[A-Za-z]:\//.test(slash))
      ? relative(resolve(cwd), resolve(filePath)).replace(/\\/g, "/")
      : slash;
  const norm = posix.normalize(raw).replace(/^(?:\.\/)+/, "");
  return norm === "." ? "" : norm;
}

export function isSafeRepoRelative(relPath, cwd) {
  if (!relPath || relPath.startsWith("../") || relPath === ".." || isAbsolute(relPath)) return false;
  if (/^[A-Za-z]:/.test(relPath)) return false;
  const root = resolve(cwd);
  const back = relative(root, resolve(root, relPath)).replace(/\\/g, "/");
  return back !== "" && !back.startsWith("../") && back !== ".." && !isAbsolute(back);
}

function asciiLower(text) {
  return text.replace(/[A-Z]/g, (ch) => ch.toLowerCase());
}

function matchWildcardSegment(pattern, text) {
  const pat = pattern.replace(/\*+/g, "*");
  let pi = 0;
  let ti = 0;
  let starIdx = -1;
  let matchIdx = 0;
  while (ti < text.length) {
    if (pi < pat.length && (pat[pi] === "?" || pat[pi] === text[ti])) {
      pi += 1;
      ti += 1;
    } else if (pi < pat.length && pat[pi] === "*") {
      starIdx = pi;
      matchIdx = ti;
      pi += 1;
    } else if (starIdx !== -1) {
      pi = starIdx + 1;
      matchIdx += 1;
      ti = matchIdx;
    } else {
      return false;
    }
  }
  while (pi < pat.length && pat[pi] === "*") pi += 1;
  return pi === pat.length;
}

function matchGlobSegments(patternSegs, pathSegs) {
  const m = patternSegs.length;
  const n = pathSegs.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(false));
  dp[0][0] = true;
  for (let i = 1; i <= m; i += 1) {
    if (patternSegs[i - 1] === "**") dp[i][0] = dp[i - 1][0];
  }
  const lowerPatSegs = patternSegs.map((s) => asciiLower(s));
  for (let i = 1; i <= m; i += 1) {
    const pSeg = lowerPatSegs[i - 1];
    for (let j = 1; j <= n; j += 1) {
      if (pSeg === "**") dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
      else if (dp[i - 1][j - 1] && matchWildcardSegment(pSeg, pathSegs[j - 1])) dp[i][j] = true;
    }
  }
  return dp[m][n];
}

export function globSpecToMatcher(spec) {
  const clean = spec.trim().replace(/\\/g, "/").replace(/^\/+/, "");
  if (!clean) return undefined;
  if (clean.endsWith("/")) return { source: clean, test: () => false };

  const segs = [];
  for (const part of clean.split("/").filter(Boolean)) {
    if (part !== "**" || segs[segs.length - 1] !== "**") segs.push(part);
  }
  if (segs.length === 1 && segs[0] === "**") {
    return {
      source: "**",
      test(candidate) {
        return Boolean(normalizeRepoRelPath(candidate));
      },
    };
  }

  let matchFolderSelf = false;
  if (segs.length > 1 && segs[segs.length - 1] === "**") {
    matchFolderSelf = true;
    segs.pop();
  }
  return {
    source: clean,
    test(candidate) {
      const norm = asciiLower(normalizeRepoRelPath(candidate));
      if (!norm) return false;
      const pSegs = norm.split("/");
      return matchGlobSegments(segs, pSegs) || (matchFolderSelf && matchGlobSegments([...segs, "**"], pSegs));
    },
  };
}
