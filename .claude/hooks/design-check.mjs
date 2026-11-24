// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Enforces Guardrails Studio design tokens and signs-of-ai-design rules across Web and Desktop UI.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const UI_PATH_RE = /^(?:web\/(?:packages|apps)|desktop\/).+\.(?:[cm]?[jt]sx?|css|html|rs)$/;
const TOKEN_OWNER_RE = /^(?:web\/packages\/tokens\/|interface\/tokens\.json$|desktop\/grdr-desktop\/src\/theme\.rs$)/;
const TEST_FILE_RE = /(?:^|\/)(?:tests?\/|.*(?:\.test\.|_test\.))[^/]+$/;

const HEX_COLOR_RE = /(?:^|[\s:,('"])#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b/m;
const AI_PURPLE_OR_CLIP_RE =
  /(?:#6366f1|#8b5cf6|#a855f7|indigo-500|violet-500|purple-500|bg-clip-text|0\s+0\s+20px\s+rgba\()/i;
const EXTERNAL_CDN_RE =
  /fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com/i;
const UNCHOSEN_FONT_RE = /\b(?:Space Grotesk|Instrument Serif|Geist Mono|Geist Sans)\b/i;
const EMOJI_RE = /[\u{1F300}-\u{1FAFF}]/u;
const LEFT_STRIPE_RE = /\b(?:border-inline-start|border-left)\s*:\s*[3-9]\d*px\s+solid\b/i;
const BANNED_BUZZWORDS_RE =
  /\b(?:world-class|enterprise-grade|supercharge|streamline|unleash|seamless|empower)\b/i;
const FORBIDDEN_VOCAB_RE = /\bposture\b/i;
const ASTRYX_OR_UISDK_IMPORT_RE = /['"]@(?:astryxdesign|ui-sdk)\//;

export function normalizeRepoPath(filePath, cwd = process.cwd()) {
  if (!filePath || typeof filePath !== "string") return "";
  const normalized = filePath.replace(/\\/g, "/");
  if (/^[A-Za-z]:\//.test(normalized) || normalized.startsWith("/")) {
    const rel = relative(resolve(cwd), resolve(filePath)).replace(/\\/g, "/");
    return rel;
  }
  return normalized.replace(/^\.\//, "");
}

export function isUiSourcePath(relPath) {
  return UI_PATH_RE.test(relPath) && !TEST_FILE_RE.test(relPath);
}

export function checkDesignContent(relPath, content) {
  if (!isUiSourcePath(relPath) || typeof content !== "string") {
    return [];
  }
  const findings = [];
  const isTokenOwner = TOKEN_OWNER_RE.test(relPath);
  const isUiWrapper = relPath.startsWith("web/packages/ui/");

  if (!isTokenOwner && HEX_COLOR_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): use semantic design tokens from interface/tokens.json instead of raw #hex colors.`,
    );
  }
  if (AI_PURPLE_OR_CLIP_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): avoid indigo/violet gradient accents, gradient clip text, or glowing shadow defaults.`,
    );
  }
  if (!isUiWrapper && ASTRYX_OR_UISDK_IMPORT_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): import Astryx and UI SDK only inside web/packages/ui/ (ARCH-101..104).`,
    );
  }
  if (EXTERNAL_CDN_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): external font or script CDNs are forbidden; bundle self-hosted assets only.`,
    );
  }
  if (UNCHOSEN_FONT_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): use the committed Guardrails Studio fonts (DM Sans, IBM Plex Mono).`,
    );
  }
  if (EMOJI_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): decorative emojis are forbidden in product UI; use crisp geometric icons.`,
    );
  }
  if (LEFT_STRIPE_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): do not apply colored left border stripes to general cards or checklist rows.`,
    );
  }
  if (BANNED_BUZZWORDS_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): replace generic AI marketing filler with factual domain copy.`,
    );
  }
  if (FORBIDDEN_VOCAB_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): replace legacy "posture" terminology with Guardrails terms (Mode, Assurance level, Verdict).`,
    );
  }
  return findings;
}

function stagedFiles(cwd) {
  const out = execFileSync(
    "git",
    ["diff", "--cached", "--name-only", "--diff-filter=d"],
    { encoding: "utf8", cwd, stdio: ["ignore", "pipe", "ignore"] },
  );
  return out.split(/\r?\n/).filter(Boolean);
}

export function evaluateStagedUiFiles(cwd = process.cwd()) {
  const findings = [];
  for (const relPath of stagedFiles(cwd)) {
    if (!isUiSourcePath(relPath)) continue;
    const full = resolve(cwd, relPath);
    if (!existsSync(full)) continue;
    findings.push(...checkDesignContent(relPath, readFileSync(full, "utf8")));
  }
  return findings;
}

export function evaluateDesignToolPayload(payload, cwd = process.cwd()) {
  if (!payload || typeof payload !== "object") return [];

  // Antigravity write_file / edit_file
  const agyToolName = payload?.toolCall?.name ?? "";
  if (agyToolName === "write_file" || agyToolName === "edit_file") {
    const args = payload?.toolCall?.args ?? {};
    const relPath = normalizeRepoPath(args.Path ?? "", cwd);
    const snippet = args.Content ?? args.Replacement ?? "";
    return checkDesignContent(relPath, snippet);
  }

  // Claude Code Edit / Write / MultiEdit
  const claudeTool = payload?.tool_name ?? "";
  const claudeInput = payload?.tool_input ?? {};
  if (claudeTool === "Write" || claudeTool === "Edit") {
    const relPath = normalizeRepoPath(claudeInput.file_path ?? "", cwd);
    const snippet = claudeInput.content ?? claudeInput.new_string ?? "";
    return checkDesignContent(relPath, snippet);
  }
  if (claudeTool === "MultiEdit" && Array.isArray(claudeInput.edits)) {
    const relPath = normalizeRepoPath(claudeInput.file_path ?? "", cwd);
    const combined = claudeInput.edits.map((e) => e?.new_string ?? "").join("\n");
    return checkDesignContent(relPath, combined);
  }

  // Bash / PowerShell / run_command pre-commit verification
  const command = payload?.tool_input?.command ?? payload?.toolCall?.args?.CommandLine ?? "";
  if (typeof command === "string" && /\bgit(?:\s+-C\s+\S+)?\s+commit\b/.test(command)) {
    return evaluateStagedUiFiles(cwd);
  }

  return [];
}

function isMainModule() {
  if (!process.argv[1]) return false;
  return resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
}

if (isMainModule()) {
  try {
    const payload = JSON.parse(readFileSync(0, "utf8"));
    const cwd = payload?.cwd ?? process.cwd();
    const findings = evaluateDesignToolPayload(payload, cwd);
    if (findings.length > 0) {
      process.stderr.write(`${findings.join("\n")}\n`);
      process.exit(2);
    }
  } catch (error) {
    process.stderr.write(`design-check skipped: ${error.message}\n`);
    process.exit(0);
  }
}
