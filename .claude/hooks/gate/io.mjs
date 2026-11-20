import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

export class GateFailure extends Error {
  constructor(subject, reason, options) {
    super(`${subject}: ${reason}`, options);
  }
}

export function parseJson(text, subject) {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new GateFailure(subject, error.message);
  }
}

export function readText(path) {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    throw new GateFailure(path, error.message);
  }
}

export function runCommand(program, args) {
  try {
    return execFileSync(program, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch (error) {
    throw new GateFailure(`${program} ${args.join(" ")}`, error.stderr?.trim() || error.message, { cause: error });
  }
}
