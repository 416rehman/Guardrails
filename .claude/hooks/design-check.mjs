// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Enforces Guardrails Studio design tokens and signs-of-ai-design rules across Web and Desktop UI.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const UI_PATH_RE =
  /^(?:web\/(?:packages|apps)|desktop\/|interface\/brand\/|crates\/grdr-ui-model\/src\/).+\.(?:[cm]?[jt]sx?|css|html|rs|svg)$/;
const RAW_CONTROL_PATH_RE = /^(?:web\/apps\/|web\/packages\/kit\/).+\.[cm]?[jt]sx$/;
const CUSTOMER_COPY_PATH_RE =
  /^(?:web\/apps\/|web\/packages\/(?:kit|i18n)\/|desktop\/grdr-desktop\/src\/|crates\/grdr-ui-model\/src\/).+\.(?:[cm]?[jt]sx?|rs)$/;
const SVG_FILE_RE = /^(?:web\/(?:packages|apps)|desktop\/|interface\/brand\/).+\.svg$/i;
const TOKEN_OWNER_RE = /^(?:web\/packages\/tokens\/|interface\/tokens\.json$|desktop\/grdr-desktop\/src\/theme\.rs$)/;
const TEST_FILE_RE = /(?:^|\/)(?:tests?\/|.*(?:\.test\.|_test\.))[^/]+$/;

const HEX_COLOR_RE = /(?:^|[\s:,('"])#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b/m;
const AI_PURPLE_OR_CLIP_RE =
  /(?:#6366f1|#8b5cf6|#a855f7|indigo-500|violet-500|purple-500|bg-clip-text|0\s+0\s+20px\s+rgba\()/i;
const EXTERNAL_CDN_RE =
  /fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com/i;
const UNCHOSEN_FONT_RE = /\b(?:Space Grotesk|Instrument Serif|Geist Mono|Geist Sans)\b/i;
const EMOJI_RE = /[\u{1F300}-\u{1FAFF}]/u;
const EM_OR_EN_DASH_RE = /[\u2014\u2013]/;
const LEFT_STRIPE_RE = /\b(?:border-inline-start|border-left)\s*:\s*[3-9]\d*px\s+solid\b/i;
const AI_WRITING_TELLS_RE =
  /\b(?:world-class|enterprise-grade|supercharge|streamline|streamlined|unleash|seamless|seamlessly|empower|empowering|delve|effortless|effortlessly|cutting-edge|next-gen|game-changing|revolutionary|leverage|leveraging|crafted|bespoke|holistic|synergy|elevate your|reimagine|reimagined|transformative|unparalleled|state-of-the-art|frictionless|harnessing|tapestry|pivotal|multifaceted|not just [^.!?\n]{1,40} but|it's not about|more than just)\b/i;
const FORBIDDEN_VOCAB_RE = /\bposture\b/i;
const ASTRYX_OR_UISDK_IMPORT_RE = /['"]@(?:astryxdesign|ui-sdk)\//;
const RAW_SVG_RE = /<svg\b|<path\s+[^>]*\bd\s*=/i;
const RAW_HTML_CONTROL_RE = /<(?:select|input|textarea|dialog)\b/;
const CUSTOMER_JARGON_RE = /\b(?:AL[0-4]\s*[/–-]\s*AL[0-4]|G1\/G2|D-50|grdr-approve)\b/;
const GENERATED_HEADER_RE = /^\s*\/\/\s*@generated\b/;
const QUOTED_LITERAL_RE = /"([^"\\]|\\.)*"|'([^'\\]|\\.)*'|`([^`\\]|\\.)*`/g;
const JSX_INLINE_TEXT_RE = />([^<>{}]*)</g;
const SEMICOLON_PROSE_RE = /[A-Za-z0-9];\s+[A-Za-z]/;
const SEMICOLON_DATA_ALLOW_RE =
  /data:|image\/|charset|font-|color:|padding:|margin:|display:|http|text\/|application\/|&[a-z]+;|use strict/i;
const ENTITY_JSX_PATH_RE = /^(?:web\/apps\/console\/|web\/packages\/kit\/).+\.[jt]sx$/;
const ENTITY_EXPR_RE = /\b(?:device_name|deviceHostname|agent_name|session_id|rule_id|[A-Za-z_]\w*\.hostname)\b/;
const JSX_CHILD_ENTITY_INLINE_RE = />[^{<\n]*\{[^}\n]*\b(?:device_name|deviceHostname|agent_name|session_id|rule_id|[A-Za-z_]\w*\.hostname)\b[^}\n]*\}[^{<\n]*</;

function hasPlaintextEntityJsx(relPath, content) {
  if (!ENTITY_JSX_PATH_RE.test(relPath) || relPath.endsWith("/EntityLink.tsx")) {
    return false;
  }
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    if (JSX_CHILD_ENTITY_INLINE_RE.test(line)) {
      return true;
    }
    if (
      /^\{[^}\n]*\}$/.test(trimmed) &&
      ENTITY_EXPR_RE.test(trimmed) &&
      !/^\{[`"']?[^}]+:\s/.test(trimmed)
    ) {
      return true;
    }
  }
  return false;
}

function hasSemicolonProse(relPath, content) {
  for (const line of content.split(/\r?\n/)) {
    QUOTED_LITERAL_RE.lastIndex = 0;
    let match;
    while ((match = QUOTED_LITERAL_RE.exec(line)) !== null) {
      const literal = match[0];
      if (SEMICOLON_PROSE_RE.test(literal) && !SEMICOLON_DATA_ALLOW_RE.test(literal)) {
        return true;
      }
    }
    if (/\.[jt]sx$/.test(relPath)) {
      JSX_INLINE_TEXT_RE.lastIndex = 0;
      let jsxMatch;
      while ((jsxMatch = JSX_INLINE_TEXT_RE.exec(line)) !== null) {
        if (SEMICOLON_PROSE_RE.test(jsxMatch[1])) {
          return true;
        }
      }
      const stripped = line
        .replace(/<[^>]+>/g, " ")
        .replace(/\{[^}]+\}/g, " ")
        .replace(/\/\/.*$/, "");
      if (
        SEMICOLON_PROSE_RE.test(stripped) &&
        !/^\s*(?:import|export|const|let|var|return|if|else|for|while|\}|type\s|interface\s)/.test(line)
      ) {
        return true;
      }
    }
  }
  return false;
}

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

  if (SVG_FILE_RE.test(relPath)) {
    findings.push(
      `design-check (${relPath}): hand-authored .svg files are forbidden; use official icon libraries or source PNG assets.`,
    );
  }
  if (!GENERATED_HEADER_RE.test(content) && RAW_SVG_RE.test(content)) {
    findings.push(
      ["design-check (", relPath, "): hand-drawn <svg>/<path d=> markup is forbidden; use official icon packages, uploaded brand assets, or registered chart/graph libraries (@grdr/ui)."].join(""),
    );
  }
  if (RAW_CONTROL_PATH_RE.test(relPath) && RAW_HTML_CONTROL_RE.test(content)) {
    findings.push(
      ["design-check (", relPath, "): raw <select>/<input>/<textarea>/<dialog> elements are forbidden in apps and kit; use canonical @grdr/ui Astryx primitives (GrdrSelect, TextInput, CheckboxInput, Dialog)."].join(""),
    );
  }
  if (CUSTOMER_COPY_PATH_RE.test(relPath) && CUSTOMER_JARGON_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): avoid internal codes (AL0-AL4 ranges, G1/G2, D-50, grdr-approve) in customer-facing UI; use plain language.`,
    );
  }

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
  if (EM_OR_EN_DASH_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): em dashes and en dashes are forbidden in UI copy and comments; use plain punctuation.`,
    );
  }
  if (CUSTOMER_COPY_PATH_RE.test(relPath) && hasSemicolonProse(relPath, content)) {
    findings.push(
      `design-check (${relPath}): avoid semicolon-joined sentences in UI copy; use short separate sentences.`,
    );
  }
  if (LEFT_STRIPE_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): do not apply colored left border stripes to general cards or checklist rows.`,
    );
  }
  if (AI_WRITING_TELLS_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): replace generic AI writing tells and marketing filler with factual domain copy.`,
    );
  }
  if (FORBIDDEN_VOCAB_RE.test(content)) {
    findings.push(
      `design-check (${relPath}): replace legacy "posture" terminology with Guardrails terms (Mode, Assurance level, Verdict).`,
    );
  }
  if (hasPlaintextEntityJsx(relPath, content)) {
    findings.push(
      ["design-check (", relPath, "): render device, agent, session, and rule references via clickable EntityLink instead of plaintext JSX."].join(""),
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
