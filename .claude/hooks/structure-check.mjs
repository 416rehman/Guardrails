// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// PreToolUse checks for grdr-structure (S1-S4, S6), grdr-interface (ARCH-101..104, UX6),
// and AGENTS.md workflow/supply-chain hygiene.
import { existsSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  checkWebInterface,
  checkWorkflowPins,
  countNonTestCodeLines,
  evaluateStructureCommand,
  scanRust,
  scanScript,
} from "./structure-scan.mjs";

export { evaluateStructureCommand };

const MAX_NON_TEST_LINES = 500;

const GIT_INTERNALS_RE = /(?:^|\/)\.git(?:\/|$)/;
const WORKFLOW_FILE_RE = /^\.github\/workflows\/.+\.ya?ml$/;
const RUST_SOURCE_RE = /^(?:crates|programs|desktop)\/.+\.rs$/;
const RUST_TEST_PATH_RE = /(?:^|\/)(?:tests?\/|benches\/|(?:tests|.*_tests?|testkit)\.rs$)/;
const TS_SOURCE_RE = /^web\/(?:apps|packages)\/.+\.[cm]?tsx?$/;
const TS_DECLARATION_RE = /\.d\.[cm]?ts$/;
const SCRIPT_TEST_PATH_RE = /(?:^|\/)(?:__tests__|e2e|tests?)\/|\.(?:test|spec)\.[cm]?[jt]sx?$/;
const WEB_CODE_RE = /^web\/.+\.(?:[cm]?[jt]sx?|css)$/;
const IGNORED_DIR_RE = /(?:^|\/)(?:node_modules|target|dist)\//;
const GENERATED_RE = /^\s*\/\/\s*@generated\b/m;

const BARE_TODO_RE = /\b(?:TODO|FIXME)\b/;
const WORK_ITEM_ID_RE = /(?:#\d+|\bWI-\d+\b)/;
const STEP_COMMENT_RE = /\bStep\s+\d+\s*[:.)-]/i;
const EM_DASH_RE = /\u2014/;
const ALLOW_S4_RE = /\/\/\s*grdr:allow-s4\b|\/\*\s*grdr:allow-s4\b/;
const SAFETY_COMMENT_RE = /\/\/\s*SAFETY:|\/\*\s*SAFETY:/;

const STATE_FIELD_NAME_RE = /^(?:state|status|phase|stage|mode)$/;
const RUST_INT_TYPE_RE = /^(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize)$/;
const RUST_STR_TYPE_RE = /^(?:(?:std::string::)?String|&(?:'[A-Za-z_]\w*\s+)?str)$/;
const RUST_FN_MODIFIERS = new Set(["default", "const", "async", "unsafe"]);
const RUST_DECL_RE = /^(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+)?(?:struct|enum|trait|type|static)\b/;
const RUST_CONST_DECL_RE = /^(?:pub(?:\s*\([^)]*\))?\s+)?const\s+[A-Za-z_]\w*\s*:/;
const RUST_PANIC_RE =
  /\.unwrap\s*\(|\.unwrap_err\s*\(|\.expect\s*\(|\.expect_err\s*\(|\b(?:panic|todo|unimplemented|unreachable)\s*!|\b(?:std::)?process::exit\b/;
const RUST_UNSAFE_BLOCK_RE = /\bunsafe\s*(?:\{|$)/;

export function normalizeRepoPath(filePath, cwd = process.cwd()) {
  if (!filePath || typeof filePath !== "string") return "";
  const normalized = filePath.replace(/\\/g, "/");
  if (/^[A-Za-z]:\//.test(normalized) || normalized.startsWith("/")) {
    return relative(resolve(cwd), resolve(filePath)).replace(/\\/g, "/");
  }
  return normalized.replace(/^\.\//, "");
}

function isRustSource(relPath) {
  return RUST_SOURCE_RE.test(relPath) && !RUST_TEST_PATH_RE.test(relPath) && !IGNORED_DIR_RE.test(relPath);
}

function isTsSource(relPath) {
  return (
    TS_SOURCE_RE.test(relPath) &&
    !TS_DECLARATION_RE.test(relPath) &&
    !SCRIPT_TEST_PATH_RE.test(relPath) &&
    !IGNORED_DIR_RE.test(relPath)
  );
}

function isWebCode(relPath) {
  return WEB_CODE_RE.test(relPath) && !SCRIPT_TEST_PATH_RE.test(relPath) && !IGNORED_DIR_RE.test(relPath);
}

function isGenerated(content) {
  return GENERATED_RE.test(content.slice(0, 512));
}

function readExisting(relPath, cwd) {
  if (!relPath || relPath.startsWith("..")) return undefined;
  const full = resolve(cwd, relPath);
  if (!existsSync(full)) return undefined;
  try {
    return readFileSync(full, "utf8");
  } catch {
    return undefined;
  }
}

function checkS1(relPath, content, isFullWrite, target, cwd) {
  const kind = isRustSource(relPath) ? "rust" : isTsSource(relPath) ? "ts" : "";
  if (!kind || isGenerated(content)) return [];

  const diskContent = readExisting(relPath, cwd);
  let afterContent = content;
  if (!isFullWrite) {
    if (diskContent === undefined || !target || !diskContent.includes(target)) return [];
    afterContent = diskContent.replace(target, content);
  }

  const newCount = countNonTestCodeLines(afterContent, kind);
  if (newCount <= MAX_NON_TEST_LINES) return [];

  if (diskContent !== undefined) {
    const oldCount = countNonTestCodeLines(diskContent, kind);
    if (oldCount > MAX_NON_TEST_LINES) {
      if (newCount <= oldCount) return [];
      return [
        `S1 (${relPath}): file already exceeds ${MAX_NON_TEST_LINES} non-test code lines (${oldCount}) and grew to ${newCount}; shrink or split by responsibility.`,
      ];
    }
  }
  return [
    `S1 (${relPath}): ${newCount} non-test code lines exceeds the ${MAX_NON_TEST_LINES}-line limit; split by responsibility.`,
  ];
}

function isRustImplOrFn(trimmed) {
  let rest = trimmed.replace(/^pub(?:\s*\([^)]*\))?\s+/, "");
  while (true) {
    const wordMatch = rest.match(/^([a-z]+)\s+/);
    if (!wordMatch || !RUST_FN_MODIFIERS.has(wordMatch[1])) break;
    rest = rest.slice(wordMatch[0].length);
  }
  rest = rest.replace(/^extern\s+(?:"[^"]*"\s+)?/, "");
  return /^(?:impl|fn)\b/.test(rest);
}

function checkS2(relPath, scannedRust) {
  let sawImplOrFn = false;
  for (let i = 0; i < scannedRust.length; i += 1) {
    const line = scannedRust[i];
    if (line.isTest || line.braceDepthBefore !== 0) continue;
    const trimmed = line.codeLine.trim();
    if (!trimmed || trimmed.startsWith("#[") || trimmed.startsWith("#![")) continue;

    if (isRustImplOrFn(trimmed)) {
      sawImplOrFn = true;
    } else if (sawImplOrFn && (RUST_DECL_RE.test(trimmed) || RUST_CONST_DECL_RE.test(trimmed))) {
      return [
        `S2 (${relPath}:${i + 1}): move top-level type/const/static declaration above the first impl or free fn.`,
      ];
    }
  }
  return [];
}

function checkS3(relPath, scanned, addedCommentsOnly, targetComments) {
  const findings = [];
  for (let i = 0; i < scanned.length; i += 1) {
    const comment = scanned[i].commentText.trim();
    if (!comment) continue;
    if (addedCommentsOnly && targetComments.has(comment)) continue;

    if (BARE_TODO_RE.test(comment) && !WORK_ITEM_ID_RE.test(comment)) {
      findings.push(`S3 (${relPath}:${i + 1}): TODO/FIXME comment must cite a work-item id (for example #123).`);
    }
    if (STEP_COMMENT_RE.test(comment)) {
      findings.push(`S3 (${relPath}:${i + 1}): remove step-narration comments; extract or name clearly instead.`);
    }
    if (EM_DASH_RE.test(comment)) {
      findings.push(`S3 (${relPath}:${i + 1}): em dashes are forbidden in comments; use plain punctuation.`);
    }
  }
  return findings;
}

function hasPrecedingAllowS4(lines, startIndex, attrPrefix) {
  for (let i = startIndex - 1; i >= Math.max(0, startIndex - 4); i -= 1) {
    if (ALLOW_S4_RE.test(lines[i].commentText)) return true;
    const code = lines[i].codeLine.trim();
    if (code && !code.startsWith(attrPrefix)) break;
  }
  return false;
}

function checkRustS4(relPath, scanned) {
  const findings = [];
  for (let i = 0; i < scanned.length; i += 1) {
    if (scanned[i].isTest) continue;
    const structMatch = scanned[i].codeLine.match(/(?:^|\s)struct\s+([A-Za-z_]\w*)\b/);
    if (!structMatch) continue;

    let bodyStart = -1;
    for (let j = i; j < Math.min(scanned.length, i + 8); j += 1) {
      if (scanned[j].codeLine.includes("{")) {
        bodyStart = j;
        break;
      }
      if (scanned[j].codeLine.includes(";")) break;
    }
    if (bodyStart === -1) continue;

    const startDepth = scanned[bodyStart].braceDepthBefore;
    let bodyEnd = bodyStart;
    let allow = hasPrecedingAllowS4(scanned, i, "#[");
    const bodyChunks = [];

    for (let j = bodyStart; j < scanned.length; j += 1) {
      if (ALLOW_S4_RE.test(scanned[j].commentText)) allow = true;
      const lineCode = scanned[j].codeLine;
      if (j === bodyStart) {
        const afterOpen = lineCode.slice(lineCode.indexOf("{") + 1);
        const endBrace = scanned[j].braceDepthAfter <= startDepth ? afterOpen.lastIndexOf("}") : -1;
        bodyChunks.push(endBrace >= 0 ? afterOpen.slice(0, endBrace) : afterOpen);
      } else if (scanned[j].braceDepthAfter <= startDepth && lineCode.includes("}")) {
        bodyChunks.push(lineCode.slice(0, lineCode.indexOf("}")));
      } else if (scanned[j].braceDepthBefore === startDepth + 1) {
        bodyChunks.push(lineCode);
      }
      if (scanned[j].braceDepthAfter <= startDepth && lineCode.includes("}")) {
        bodyEnd = j;
        break;
      }
    }

    let boolCount = 0;
    let badStateField = "";
    for (const part of bodyChunks.join("\n").split(/[,\n]/)) {
      const fieldMatch = part.trim().match(/^(?:pub(?:\s*\([^)]*\))?\s+)?([A-Za-z_]\w*)\s*:\s*(.+)$/);
      if (!fieldMatch) continue;
      const fieldName = fieldMatch[1];
      const fieldType = fieldMatch[2].trim();
      if (fieldType === "bool") boolCount += 1;
      if (
        STATE_FIELD_NAME_RE.test(fieldName) &&
        (fieldType === "bool" || RUST_STR_TYPE_RE.test(fieldType) || RUST_INT_TYPE_RE.test(fieldType))
      ) {
        badStateField = `${fieldName}: ${fieldType}`;
      }
    }

    if (!allow && (boolCount >= 3 || badStateField)) {
      const detail = badStateField ? `field "${badStateField}"` : `${boolCount} bool fields`;
      findings.push(
        `S4 (${relPath}:${i + 1}): struct ${structMatch[1]} has an implicit state machine (${detail}); use an enum or annotate with // grdr:allow-s4 reason.`,
      );
    }
    i = bodyEnd;
  }
  return findings;
}

function checkTsS4(relPath, scanned) {
  const findings = [];
  for (let i = 0; i < scanned.length; i += 1) {
    const line = scanned[i].codeLine;
    if (!line.includes("{")) continue;
    const ifaceMatch = line.match(/^(?:export\s+)?(?:interface|type)\s+([A-Za-z_]\w*)\b/);
    if (!ifaceMatch || line.slice(0, line.indexOf("{")).includes(";")) continue;

    let allow = hasPrecedingAllowS4(scanned, i, "@");
    let depth = 0;
    const bodyChunks = [];
    let endIdx = i;

    for (let j = i; j < scanned.length; j += 1) {
      if (ALLOW_S4_RE.test(scanned[j].commentText)) allow = true;
      const lineCode = scanned[j].codeLine;
      let chunk = "";
      for (const ch of lineCode) {
        if (ch === "{") {
          depth += 1;
          if (depth === 1) continue;
        } else if (ch === "}") {
          depth = Math.max(0, depth - 1);
          if (depth === 0) continue;
        }
        if (depth === 1) chunk += ch;
      }
      if (chunk.trim()) bodyChunks.push(chunk);
      if (depth === 0) {
        endIdx = j;
        break;
      }
    }

    let boolCount = 0;
    let badStateField = "";
    for (const part of bodyChunks.join("\n").split(/[;,\n]/)) {
      const fieldMatch = part.trim().match(/^(?:readonly\s+)?([A-Za-z_]\w*)\??\s*:\s*(.+)$/);
      if (!fieldMatch) continue;
      const fieldName = fieldMatch[1];
      const fieldType = fieldMatch[2].trim();
      if (fieldType === "boolean") boolCount += 1;
      if (STATE_FIELD_NAME_RE.test(fieldName) && /^(?:string|number|boolean)$/.test(fieldType)) {
        badStateField = `${fieldName}: ${fieldType}`;
      }
    }

    if (!allow && (boolCount >= 3 || badStateField)) {
      const detail = badStateField ? `field "${badStateField}"` : `${boolCount} boolean fields`;
      findings.push(
        `S4 (${relPath}:${i + 1}): ${ifaceMatch[1]} has an implicit state machine (${detail}); use a discriminated union or annotate with // grdr:allow-s4 reason.`,
      );
    }
    i = endIdx;
  }

  if (/\.[jt]sx$/.test(relPath)) {
    const frames = [{ count: 0, allow: false, startLine: 1 }];
    for (let i = 0; i < scanned.length; i += 1) {
      const top = frames[frames.length - 1];
      if (ALLOW_S4_RE.test(scanned[i].commentText)) top.allow = true;

      const lineCode = scanned[i].codeLine;
      const isBoolNullHook =
        /\buseState(?:\s*<[^>]+>)?\s*\(\s*(?:true|false|null)\s*\)/.test(lineCode) ||
        /\buseState\s*<\s*boolean\s*>\s*\(/.test(lineCode);
      if (isBoolNullHook && !ALLOW_S4_RE.test(scanned[i].commentText)) {
        top.count += 1;
      }

      for (const ch of lineCode) {
        if (ch === "{") {
          frames.push({ count: 0, allow: hasPrecedingAllowS4(scanned, i, "@"), startLine: i + 1 });
        } else if (ch === "}" && frames.length > 1) {
          const closed = frames.pop();
          if (closed.count >= 3 && !closed.allow) {
            findings.push(
              `S4 (${relPath}:${closed.startLine}): component has ${closed.count} boolean/null useState flags; consolidate into a state union or annotate with // grdr:allow-s4 reason.`,
            );
          }
        }
      }
    }
    if (frames[0].count >= 3 && !frames[0].allow) {
      findings.push(
        `S4 (${relPath}:1): snippet has ${frames[0].count} boolean/null useState flags; consolidate into a state union or annotate with // grdr:allow-s4 reason.`,
      );
    }
  }
  return findings;
}

function hasSafetyComment(scanned, index) {
  if (SAFETY_COMMENT_RE.test(scanned[index].commentText)) return true;
  for (let i = index - 1; i >= Math.max(0, index - 5); i -= 1) {
    if (SAFETY_COMMENT_RE.test(scanned[i].commentText)) return true;
    const code = scanned[i].codeLine.trim();
    if (code && !code.startsWith("#[")) break;
  }
  return false;
}

function checkS6(relPath, scanned, startIdx = 0, endIdx = scanned.length - 1) {
  const findings = [];
  for (let i = startIdx; i <= endIdx; i += 1) {
    if (scanned[i].isTest) continue;
    const code = scanned[i].codeLine;
    if (RUST_PANIC_RE.test(code)) {
      findings.push(
        `S6 (${relPath}:${i + 1}): panic path (unwrap/expect/panic!/todo!/unimplemented!/unreachable!/process::exit) is forbidden in non-test Rust.`,
      );
    }
    if (RUST_UNSAFE_BLOCK_RE.test(code) && !hasSafetyComment(scanned, i)) {
      findings.push(`S6 (${relPath}:${i + 1}): unsafe block requires a preceding // SAFETY: comment.`);
    }
  }
  return findings;
}

export function checkStructureContent(relPath, content, options = {}) {
  const { isFullWrite = true, target = "", cwd = process.cwd() } = options;
  if (!relPath || typeof content !== "string") return [];

  if (GIT_INTERNALS_RE.test(relPath)) {
    return [`repo hygiene (${relPath}): direct edits to .git/ internals are forbidden.`];
  }
  if (WORKFLOW_FILE_RE.test(relPath)) {
    return checkWorkflowPins(relPath, content);
  }
  if (IGNORED_DIR_RE.test(relPath) || isGenerated(content)) return [];

  const findings = [...checkS1(relPath, content, isFullWrite, target, cwd)];
  const targetComments = new Set();
  if (!isFullWrite && target) {
    const targetScan = isRustSource(relPath) ? scanRust(target) : scanScript(target);
    for (const l of targetScan) {
      const c = l.commentText.trim();
      if (c) targetComments.add(c);
    }
  }

  if (isRustSource(relPath)) {
    const scanned = scanRust(content);
    if (isFullWrite) findings.push(...checkS2(relPath, scanned));
    findings.push(...checkS3(relPath, scanned, !isFullWrite && Boolean(target), targetComments));
    findings.push(...checkRustS4(relPath, scanned));

    if (!isFullWrite && target) {
      const diskContent = readExisting(relPath, cwd);
      if (diskContent !== undefined && diskContent.includes(target)) {
        const idx = diskContent.indexOf(target);
        const startLine = diskContent.slice(0, idx).split(/\r?\n/).length - 1;
        const endLine = startLine + content.split(/\r?\n/).length - 1;
        const fullScanned = scanRust(diskContent.replace(target, content));
        findings.push(...checkS6(relPath, fullScanned, startLine, endLine));
        return findings;
      }
    }
    findings.push(...checkS6(relPath, scanned));
    return findings;
  }

  if (isTsSource(relPath) || isWebCode(relPath)) {
    const scanned = scanScript(content);
    findings.push(...checkS3(relPath, scanned, !isFullWrite && Boolean(target), targetComments));
    if (isTsSource(relPath)) findings.push(...checkTsS4(relPath, scanned));
    if (isWebCode(relPath)) findings.push(...checkWebInterface(relPath, scanned));
  }
  return findings;
}

export function evaluateStructurePayload(payload, cwd = process.cwd()) {
  if (!payload || typeof payload !== "object") return [];

  const agyTool = payload?.toolCall?.name ?? "";
  if (agyTool === "write_file" || agyTool === "edit_file") {
    const args = payload?.toolCall?.args ?? {};
    const relPath = normalizeRepoPath(args.Path ?? "", cwd);
    const isFullWrite = agyTool === "write_file";
    const content = isFullWrite ? (args.Content ?? "") : (args.Replacement ?? "");
    return checkStructureContent(relPath, content, { isFullWrite, target: args.Target ?? "", cwd });
  }

  const claudeTool = payload?.tool_name ?? "";
  const claudeInput = payload?.tool_input ?? {};
  if (claudeTool === "Write" || claudeTool === "Edit") {
    const relPath = normalizeRepoPath(claudeInput.file_path ?? "", cwd);
    const isFullWrite = claudeTool === "Write";
    const content = isFullWrite ? (claudeInput.content ?? "") : (claudeInput.new_string ?? "");
    return checkStructureContent(relPath, content, {
      isFullWrite,
      target: claudeInput.old_string ?? "",
      cwd,
    });
  }
  if (claudeTool === "MultiEdit" && Array.isArray(claudeInput.edits)) {
    const relPath = normalizeRepoPath(claudeInput.file_path ?? "", cwd);
    const findings = [];
    for (const edit of claudeInput.edits) {
      findings.push(
        ...checkStructureContent(relPath, edit?.new_string ?? "", {
          isFullWrite: false,
          target: edit?.old_string ?? "",
          cwd,
        }),
      );
    }
    return findings;
  }

  const command = claudeInput.command ?? payload?.toolCall?.args?.CommandLine ?? "";
  return evaluateStructureCommand(command);
}

function isMainModule() {
  if (!process.argv[1]) return false;
  return resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
}

if (isMainModule()) {
  try {
    const payload = JSON.parse(readFileSync(0, "utf8"));
    const cwd = payload?.cwd ?? process.cwd();
    const findings = evaluateStructurePayload(payload, cwd);
    if (findings.length > 0) {
      process.stderr.write(`${findings.join("\n")}\n`);
      process.exit(2);
    }
  } catch (error) {
    process.stderr.write(`structure-check skipped: ${error.message}\n`);
    process.exit(0);
  }
}
