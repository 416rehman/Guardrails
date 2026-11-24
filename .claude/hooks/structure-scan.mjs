// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Lexical line, shell, and command scanners shared by .claude/hooks/structure-check.mjs.
import { basename } from "node:path";

const MAX_COMMIT_SUBJECT = 72;
const CFG_TEST_RE = /#\[cfg\([^)]*\btest\b[^)]*\)\]/;
const CONVENTIONAL_COMMIT_RE =
  /^(feat|fix|chore|docs|refactor|test|ci|build|perf|style)(\([a-z0-9._-]+\))?:\s+\S/;
const AI_TRAILER_RE = /(?:`n|\b)Co-Authored-By\s*:|\bGenerated with\b|\u{1F916}/iu;
const BANNED_PKG_MGRS = new Set(["npm", "npx", "yarn", "bun"]);
const WEB_CSS_RE = /^web\/.+\.css$/;
const WEB_UI_PKG_RE = /^web\/packages\/ui\//;
const WEB_KIT_OR_APP_RE = /^web\/(?:packages\/kit|apps)\//;
const REACT_ARIA_IMPORT_RE =
  /(?:\bfrom\s+|\bimport\s*\(?\s*|\brequire\s*\(\s*)(['"])(?:@react-aria\/[^'"]+|react-aria(?:-components)?(?:\/[^'"]*)?)\1/;
const ASTRYX_IMPORT_RE =
  /(?:\bfrom\s+|\bimport\s*\(?\s*|\brequire\s*\(\s*)(['"])@(?:astryxdesign|ui-sdk)\/[^'"]+\1/;
const PHYSICAL_CSS_PROP_RE =
  /(?<![A-Za-z0-9_-])(?:margin|padding|border)-(?:left|right)(?:-(?:width|style|color))?\s*:/i;
const DANGEROUS_HTML_RE = /\bdangerouslySetInnerHTML\b/;
const PINNED_SHA_RE = /^[^@\s]+@[0-9a-f]{40}$/i;

export function scanRust(content) {
  const lines = content.split(/\r?\n/);
  const result = [];
  let blockCommentDepth = 0;
  let inString = false;
  let rawHashes = -1;
  let braceDepth = 0;
  let pendingCfgTest = false;
  let inCfgTest = false;
  let cfgTestExitDepth = 0;

  for (const line of lines) {
    const braceDepthBefore = braceDepth;
    let codeLine = "";
    let commentText = "";

    for (let i = 0; i < line.length; i += 1) {
      const ch = line[i];
      const next = line[i + 1] ?? "";

      if (blockCommentDepth > 0) {
        if (ch === "/" && next === "*") {
          blockCommentDepth += 1;
          commentText += "/*";
          i += 1;
        } else if (ch === "*" && next === "/") {
          blockCommentDepth -= 1;
          commentText += "*/";
          i += 1;
        } else {
          commentText += ch;
        }
        continue;
      }

      if (rawHashes >= 0) {
        if (ch === '"') {
          let matched = true;
          for (let h = 1; h <= rawHashes; h += 1) {
            if (line[i + h] !== "#") {
              matched = false;
              break;
            }
          }
          if (matched) {
            i += rawHashes;
            rawHashes = -1;
            codeLine += '"';
          }
        }
        continue;
      }

      if (inString) {
        if (ch === "\\") i += 1;
        else if (ch === '"') {
          inString = false;
          codeLine += '"';
        }
        continue;
      }

      if (ch === "/" && next === "/") {
        commentText += line.slice(i);
        break;
      }
      if (ch === "/" && next === "*") {
        blockCommentDepth = 1;
        commentText += "/*";
        i += 1;
        continue;
      }

      const prev = i > 0 ? line[i - 1] : "";
      if (!/[A-Za-z0-9_]/.test(prev) && (ch === "r" || ((ch === "b" || ch === "c") && next === "r"))) {
        let j = ch === "r" ? i + 1 : i + 2;
        let hashes = 0;
        while (line[j] === "#") {
          hashes += 1;
          j += 1;
        }
        if (line[j] === '"') {
          rawHashes = hashes;
          i = j;
          codeLine += '"';
          continue;
        }
      }

      if (ch === '"') {
        inString = true;
        codeLine += '"';
        continue;
      }
      if (ch === "'") {
        if (next === "\\" && line[i + 3] === "'") {
          codeLine += "''";
          i += 3;
          continue;
        }
        if (next && next !== "'" && line[i + 2] === "'") {
          codeLine += "''";
          i += 2;
          continue;
        }
      }

      if (ch === "{") braceDepth += 1;
      else if (ch === "}") braceDepth = Math.max(0, braceDepth - 1);
      codeLine += ch;
    }

    const trimmed = codeLine.trim();
    let isTest = inCfgTest;
    if (!inCfgTest) {
      if (CFG_TEST_RE.test(trimmed)) {
        pendingCfgTest = true;
        isTest = true;
      } else if (pendingCfgTest) {
        isTest = true;
        if (trimmed && !trimmed.startsWith("#[")) {
          if (braceDepth > braceDepthBefore) {
            inCfgTest = true;
            cfgTestExitDepth = braceDepthBefore;
            pendingCfgTest = false;
          } else if (trimmed.endsWith(";")) {
            pendingCfgTest = false;
          }
        }
      }
    } else if (braceDepth <= cfgTestExitDepth && trimmed.includes("}")) {
      inCfgTest = false;
    }

    result.push({
      codeLine,
      commentText,
      braceDepthBefore,
      braceDepthAfter: braceDepth,
      isTest,
      hasCode: !isTest && trimmed.length > 0,
    });
  }
  return result;
}

export function scanScript(content) {
  const lines = content.split(/\r?\n/);
  const result = [];
  let inBlockComment = false;
  let quote = "";

  for (const line of lines) {
    let codeLine = "";
    let rawCodeLine = "";
    let commentText = "";
    for (let i = 0; i < line.length; i += 1) {
      const ch = line[i];
      const next = line[i + 1] ?? "";

      if (inBlockComment) {
        if (ch === "*" && next === "/") {
          inBlockComment = false;
          commentText += "*/";
          i += 1;
        } else {
          commentText += ch;
        }
        continue;
      }
      if (quote) {
        rawCodeLine += ch;
        if (ch === "\\") {
          rawCodeLine += next;
          i += 1;
        } else if (ch === quote) {
          quote = "";
          codeLine += ch;
        }
        continue;
      }
      if (ch === "/" && next === "/") {
        commentText += line.slice(i);
        break;
      }
      if (ch === "/" && next === "*") {
        inBlockComment = true;
        commentText += "/*";
        i += 1;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === "`") {
        quote = ch;
        codeLine += ch;
        rawCodeLine += ch;
        continue;
      }
      codeLine += ch;
      rawCodeLine += ch;
    }
    if (quote && quote !== "`") quote = "";
    result.push({ codeLine, rawCodeLine, commentText, hasCode: rawCodeLine.trim().length > 0 });
  }
  return result;
}

export function countNonTestCodeLines(content, kind) {
  const scanned = kind === "rust" ? scanRust(content) : scanScript(content);
  let count = 0;
  for (const line of scanned) {
    if (line.hasCode) count += 1;
  }
  return count;
}

export function splitShellSegments(command) {
  const segments = [];
  let current = "";
  let quote = "";

  for (let i = 0; i < command.length; i += 1) {
    const ch = command[i];
    const next = command[i + 1] ?? "";
    if (quote) {
      current += ch;
      if (quote === '"' && ch === "\\" && (next === '"' || next === "\\")) {
        current += next;
        i += 1;
      } else if (quote === '"' && ch === "`" && next) {
        current += next;
        i += 1;
      } else if (ch === quote) {
        quote = "";
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === ";" || ch === "\n" || ch === "\r" || ch === "|") {
      if (current.trim()) segments.push(current.trim());
      current = "";
      if (ch === "|" && next === "|") i += 1;
      continue;
    }
    if (ch === "&" && next === "&") {
      if (current.trim()) segments.push(current.trim());
      current = "";
      i += 1;
      continue;
    }
    current += ch;
  }
  if (current.trim()) segments.push(current.trim());
  return segments;
}

export function tokenizeSegment(segment) {
  const tokens = [];
  let cur = "";
  let quote = "";
  let hasToken = false;

  for (let i = 0; i < segment.length; i += 1) {
    const ch = segment[i];
    const next = segment[i + 1] ?? "";
    if (quote) {
      if (quote === '"' && ch === "\\" && (next === '"' || next === "\\")) {
        cur += next;
        i += 1;
      } else if (quote === '"' && ch === "`" && next) {
        cur += ch + next;
        i += 1;
      } else if (ch === quote) {
        quote = "";
      } else {
        cur += ch;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      hasToken = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (hasToken) {
        tokens.push(cur);
        cur = "";
        hasToken = false;
      }
      continue;
    }
    cur += ch;
    hasToken = true;
  }
  if (hasToken) tokens.push(cur);
  return tokens;
}

function checkGitCommitTokens(tokens) {
  let idx = 0;
  while (idx < tokens.length && (/^[A-Za-z_]\w*=/.test(tokens[idx]) || tokens[idx] === "&")) {
    idx += 1;
  }
  if (idx >= tokens.length) return [];
  if (basename(tokens[idx]).toLowerCase().replace(/\.exe$/, "") !== "git") return [];

  let i = idx + 1;
  while (i < tokens.length && tokens[i].startsWith("-")) {
    i += ["-C", "-c", "--git-dir", "--work-tree"].includes(tokens[i]) ? 2 : 1;
  }
  if (tokens[i] !== "commit") return [];

  const messages = [];
  for (let j = i + 1; j < tokens.length; j += 1) {
    const tok = tokens[j];
    if ((tok === "-m" || tok === "--message" || /^-[a-zA-Z]*m$/.test(tok)) && j + 1 < tokens.length) {
      messages.push(tokens[j + 1]);
      j += 1;
    } else if (tok.startsWith("--message=")) {
      messages.push(tok.slice("--message=".length));
    } else if (tok.startsWith("-m") && tok.length > 2) {
      messages.push(tok.slice(2));
    }
  }
  if (messages.length === 0) return [];

  const findings = [];
  if (messages.length > 1) {
    findings.push("commit rule: use a single-line Conventional Commit message with no body (multiple -m flags rejected).");
  }
  const msg = messages[0];
  if (/[\r\n]|`n/.test(msg)) {
    findings.push("commit rule: commit message must be a single line with no body or newlines.");
  }
  if (AI_TRAILER_RE.test(msg)) {
    findings.push("commit rule: AI trailers (Co-Authored-By, Generated with, robot emoji) are forbidden.");
  }
  if (msg.length > MAX_COMMIT_SUBJECT) {
    findings.push(`commit rule: subject is ${msg.length} chars (max ${MAX_COMMIT_SUBJECT}).`);
  }
  if (!CONVENTIONAL_COMMIT_RE.test(msg.trim())) {
    findings.push(
      "commit rule: commit message must follow Conventional Commits (feat|fix|chore|docs|refactor|test|ci|build|perf|style).",
    );
  }
  return findings;
}

function checkPnpmOnlyTokens(tokens) {
  let idx = 0;
  while (idx < tokens.length) {
    const tok = tokens[idx].replace(/^[({$]+/, "");
    if (/^[A-Za-z_]\w*=/.test(tok) || ["env", "command", "sudo", "time", "&"].includes(tok)) {
      idx += 1;
      continue;
    }
    const base = basename(tok).toLowerCase().replace(/\.(?:cmd|exe|ps1|bat)$/, "");
    if (BANNED_PKG_MGRS.has(base)) {
      return [`package manager rule: use pnpm instead of "${base}" (AGENTS.md).`];
    }
    break;
  }
  return [];
}

export function evaluateStructureCommand(command) {
  if (!command || typeof command !== "string") return [];
  const findings = [];
  for (const segment of splitShellSegments(command)) {
    const tokens = tokenizeSegment(segment);
    findings.push(...checkPnpmOnlyTokens(tokens));
    findings.push(...checkGitCommitTokens(tokens));
  }
  return findings;
}

export function checkWebInterface(relPath, scanned) {
  const findings = [];
  const codeOnly = scanned.map((l) => l.codeLine).join("\n");
  const rawCodeOnly = scanned.map((l) => l.rawCodeLine).join("\n");

  if (WEB_CSS_RE.test(relPath)) {
    if (PHYSICAL_CSS_PROP_RE.test(codeOnly)) {
      findings.push(
        `grdr-interface (${relPath}, UX6): replace physical margin/padding/border left/right CSS properties with logical inline-start/inline-end properties.`,
      );
    }
    return findings;
  }

  if (!WEB_UI_PKG_RE.test(relPath) && REACT_ARIA_IMPORT_RE.test(rawCodeOnly)) {
    findings.push(
      `grdr-interface (${relPath}, ARCH-103): react-aria / react-aria-components may only be imported inside web/packages/ui/.`,
    );
  }
  if (WEB_KIT_OR_APP_RE.test(relPath) && ASTRYX_IMPORT_RE.test(rawCodeOnly)) {
    findings.push(
      `grdr-interface (${relPath}, ARCH-101..102): @astryxdesign/* and @ui-sdk/* may not be imported inside web/packages/kit/ or web/apps/; import from @grdr/ui.`,
    );
  }
  if (DANGEROUS_HTML_RE.test(codeOnly)) {
    findings.push(`grdr-interface (${relPath}): dangerouslySetInnerHTML is forbidden in web/.`);
  }
  return findings;
}

export function checkWorkflowPins(relPath, content) {
  const findings = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const match = lines[i].match(/^\s*(?:-\s*)?uses\s*:\s*([^\s#]+)/);
    if (!match) continue;
    const ref = match[1].replace(/^['"]|['"]$/g, "");
    if (ref.startsWith("./") || ref.startsWith("../") || ref.startsWith("$/.")) continue;
    if (!PINNED_SHA_RE.test(ref)) {
      findings.push(
        `workflow hygiene (${relPath}:${i + 1}): external action "${ref}" must be pinned to a full 40-hex commit SHA or be a local ./ action.`,
      );
    }
  }
  return findings;
}
