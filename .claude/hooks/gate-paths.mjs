// PreToolUse hook: refuses gate-path writes that carry no grant (#1550, ADR-0030). It only denies,
// and denies every call when it cannot decide.
import { readFileSync } from "node:fs";
import { buildContext } from "./gate/context.mjs";
import { decide, deny } from "./gate/decide.mjs";
import { CODES } from "./gate/gate-list.mjs";

function decision() {
  try {
    const input = JSON.parse(readFileSync(0, "utf8"));
    return decide(input, buildContext(input, process.env, process.platform));
  } catch (error) {
    return deny(CODES.failure, `${CODES.failure}: ${error.message}`);
  }
}

function hookOutput(result) {
  if (result.kind !== "deny") return "";
  const output = { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: result.message };
  return JSON.stringify({ hookSpecificOutput: output });
}

process.stdout.write(hookOutput(decision()));
