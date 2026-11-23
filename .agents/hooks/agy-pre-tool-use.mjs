// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Antigravity (Gemini) PreToolUse hook wrapping the shared docs, branch and PR rules in
// .claude/hooks/docs-check.mjs. Reads Antigravity's camelCase stdin payload and writes a
// { decision: "allow" | "deny", reason? } JSON object on stdout.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateHookCommand } from "../../.claude/hooks/docs-check.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

export function handleHookPayload(rawText) {
  const payload = JSON.parse(rawText);
  const toolName = payload?.toolCall?.name ?? "";
  if (toolName && toolName !== "run_command") {
    return { decision: "allow" };
  }
  const command = payload?.toolCall?.args?.CommandLine ?? "";
  if (!command || typeof command !== "string") {
    return { decision: "allow" };
  }
  const cwd =
    typeof payload?.cwd === "string" && payload.cwd
      ? payload.cwd
      : Array.isArray(payload?.workspacePaths) && typeof payload.workspacePaths[0] === "string"
        ? payload.workspacePaths[0]
        : REPO_ROOT;
  const found = evaluateHookCommand(command, cwd);
  if (found.length > 0) {
    return { decision: "deny", reason: found.join("\n") };
  }
  return { decision: "allow" };
}

function isMainModule() {
  if (!process.argv[1]) return false;
  return resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
}

if (isMainModule()) {
  try {
    const raw = readFileSync(0, "utf8");
    const response = handleHookPayload(raw);
    process.stdout.write(`${JSON.stringify(response)}\n`);
  } catch (error) {
    process.stderr.write(`agy-pre-tool-use skipped: ${error.message}\n`);
    process.stdout.write(`${JSON.stringify({ decision: "allow" })}\n`);
  }
}
