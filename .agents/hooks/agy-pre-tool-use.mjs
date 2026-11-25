// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Antigravity (Gemini) PreToolUse hook enforcing branch/PR rules (docs-check.mjs),
// Guardrails Studio UI rules (design-check.mjs), visual audit gate (visual-audit-check.mjs),
// security audit gate (security-audit-check.mjs), and structure/workflow rules (structure-check.mjs).
import { readFileSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateDesignToolPayload } from "../../.claude/hooks/design-check.mjs";
import { evaluateEngineeringPayload, evaluateHookCommand } from "../../.claude/hooks/docs-check.mjs";
import { evaluateSecurityAuditToolPayload } from "../../.claude/hooks/security-audit-check.mjs";
import { printableText } from "../../.claude/hooks/security-audit-git.mjs";
import { evaluateStructurePayload } from "../../.claude/hooks/structure-check.mjs";
import { evaluateVisualAuditToolPayload } from "../../.claude/hooks/visual-audit-check.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

function resolvePayloadCwd(payload) {
  if (typeof payload?.cwd === "string" && payload.cwd.trim()) {
    return payload.cwd.trim();
  }
  if (Array.isArray(payload?.workspacePaths)) {
    const firstValid = payload.workspacePaths.find((p) => typeof p === "string" && p.trim());
    if (firstValid) return firstValid.trim();
  }
  return REPO_ROOT;
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

export function handleHookPayload(rawText) {
  const payload = JSON.parse(rawText);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { decision: "deny", reason: "agy-pre-tool-use failed closed: expected JSON object payload." };
  }
  const rawName = payload?.toolCall?.name;
  if (typeof rawName !== "string" || !rawName.trim()) {
    return { decision: "deny", reason: "agy-pre-tool-use failed closed: toolCall.name must be a non-empty string." };
  }
  const toolName = rawName.trim();
  const cwd = resolvePayloadCwd(payload);

  if (toolName === "write_file" || toolName === "edit_file") {
    const findings = [
      ...evaluateEngineeringPayload(payload, cwd),
      ...evaluateDesignToolPayload(payload, cwd),
      ...evaluateStructurePayload(payload, cwd),
    ];
    if (findings.length > 0) {
      return { decision: "deny", reason: findings.join("\n") };
    }
    return { decision: "allow" };
  }

  if (toolName !== "run_command") {
    return { decision: "allow" };
  }
  const command = payload?.toolCall?.args?.CommandLine;
  if (typeof command !== "string") {
    return { decision: "deny", reason: "agy-pre-tool-use failed closed: run_command CommandLine must be a string." };
  }
  if (!command) {
    return { decision: "allow" };
  }
  const found = [
    ...evaluateHookCommand(command, cwd),
    ...evaluateEngineeringPayload(payload, cwd),
    ...evaluateDesignToolPayload(payload, cwd),
    ...evaluateVisualAuditToolPayload(payload, cwd),
    ...evaluateSecurityAuditToolPayload(payload, cwd),
    ...evaluateStructurePayload(payload, cwd),
  ];
  if (found.length > 0) {
    return { decision: "deny", reason: found.join("\n") };
  }
  return { decision: "allow" };
}

function isMainModule() {
  return Boolean(process.argv[1]) && canonicalPath(process.argv[1]) === canonicalPath(fileURLToPath(import.meta.url));
}

if (isMainModule()) {
  try {
    const raw = readFileSync(0, "utf8");
    const response = handleHookPayload(raw);
    process.stdout.write(`${JSON.stringify(response)}\n`);
  } catch (error) {
    const rawMsg = error instanceof Error ? error.message : String(error);
    const reason = `agy-pre-tool-use failed closed: ${printableText(rawMsg, 200)}`;
    process.stderr.write(`${reason}\n`);
    process.stdout.write(`${JSON.stringify({ decision: "deny", reason })}\n`);
  }
}
