// Preloaded with `node --import` by fixture.mjs: answers `gh issue view <n> ...` from
// `$GRDR_TEST_ISSUES/<n>.json`, and fails like gh when the file is missing.
import childProcess from "node:child_process";
import { readFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { join } from "node:path";

const realExecFileSync = childProcess.execFileSync;

childProcess.execFileSync = (program, args, options) => {
  if (program !== "gh") return realExecFileSync(program, args, options);
  try {
    return readFileSync(join(process.env.GRDR_TEST_ISSUES, `${args[2]}.json`), "utf8");
  } catch {
    const error = new Error("Command failed: gh");
    error.status = 1;
    error.stderr = `GraphQL: Could not resolve to an issue with the number of ${args[2]}.`;
    throw error;
  }
};
syncBuiltinESMExports();
