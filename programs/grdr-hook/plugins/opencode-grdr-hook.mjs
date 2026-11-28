// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { execFileSync } from "node:child_process";

const STRUCTURED_ARG_PRIORITY = [
  "command",
  "cmd",
  "command_line",
  "CommandLine",
  "filePath",
  "file_path",
  "path",
  "TargetFile",
  "target_file",
  "url",
  "uri",
];

/**
 * Create an OpenCode `tool.execute.before` plugin forwarder that delegates every
 * tool invocation to `grdr-hook` in exec form (zero shell expansion).
 */
export function createGuardrailsOpenCodePlugin(options = {}) {
  const hookBin = options.hookBin || "grdr-hook";
  const dialect = options.dialect || "opencode";
  const spawnSync = options.execFileSync || execFileSync;

  return {
    name: "guardrails-adr-opencode",
    hooks: {
      "tool.execute.before"(input, output) {
        const sessionId =
          input && typeof input.sessionID === "string"
            ? input.sessionID
            : input && typeof input.session_id === "string"
              ? input.session_id
              : "";
        const toolName = input && typeof input.tool === "string" ? input.tool : "tool";
        const toolInput = output && output.args !== undefined ? output.args : input?.args ?? {};
        const payload = JSON.stringify({
          session_id: sessionId,
          hook_event_name: "tool.execute.before",
          tool_name: toolName,
          tool_input: toolInput,
        });

        let stdout = "";
        try {
          stdout = String(
            spawnSync(hookBin, ["--agent", dialect, "--event", "tool.execute.before"], {
              input: payload,
              encoding: "utf8",
              timeout: 2500,
              maxBuffer: 1024 * 1024,
            }),
          );
        } catch (err) {
          const outText = err && err.stdout ? String(err.stdout) : "";
          const parsed = tryParseJson(outText);
          throw decisionError(
            parsed,
            err?.message || "Blocked by Guardrails ADR hook",
          );
        }

        const decision = tryParseJson(stdout);
        if (!decision || typeof decision !== "object") {
          throw new Error("Blocked by Guardrails ADR hook: empty or malformed hook response");
        }
        const hookOut = decision.hookSpecificOutput;
        const verdict =
          hookOut?.permissionDecision || decision.decision || decision.permission;
        if (verdict !== "allow") {
          throw decisionError(decision, "Blocked by Guardrails ADR hook");
        }
        const rewritten = hookOut?.updatedInput ?? decision.updatedInput;
        if (rewritten !== undefined && output && typeof output === "object") {
          if (typeof rewritten === "string" && rewritten.length > 0) {
            const baseArgs =
              output.args && typeof output.args === "object" && !Array.isArray(output.args)
                ? { ...output.args }
                : {};
            const field = resolveModifiedArgField(toolName, baseArgs);
            baseArgs[field] = rewritten;
            output.args = baseArgs;
          } else if (
            rewritten &&
            typeof rewritten === "object" &&
            !Array.isArray(rewritten)
          ) {
            output.args = rewritten;
          }
        }
      },
    },
  };
}

function resolveModifiedArgField(toolName, baseArgs) {
  for (const key of STRUCTURED_ARG_PRIORITY) {
    if (Object.prototype.hasOwnProperty.call(baseArgs, key)) {
      return key;
    }
  }
  const lower = String(toolName || "").toLowerCase();
  if (lower.includes("bash") || lower.includes("exec") || lower === "sh" || lower === "pwsh") {
    return "command";
  }
  if (lower.includes("fetch") || lower.includes("web") || lower.includes("http")) {
    return "url";
  }
  return "filePath";
}

function decisionError(parsed, fallbackReason) {
  const reason =
    parsed?.hookSpecificOutput?.permissionDecisionReason ||
    parsed?.reason ||
    fallbackReason;
  const retryToken = parsed?.retry_token || parsed?.hookSpecificOutput?.retry_token;
  const error = new Error(retryToken ? `${reason} [retry_token=${retryToken}]` : reason);
  if (retryToken) {
    error.retryToken = retryToken;
  }
  return error;
}

function tryParseJson(text) {
  try {
    return text && text.trim() ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}
