// node .claude/hooks/grant.mjs open <n> | close <n> | print <n>: the main session's grant for
// issue <n>, read by gate-paths.mjs (#1550).
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CODES, GATE_LIST_FILE, message, parseGateList } from "./gate/gate-list.mjs";
import { grantFromIssue, isHighTier } from "./gate/grant-record.mjs";
import { GateFailure, parseJson, readText, runCommand } from "./gate/io.mjs";
import { platformOf, resolvePath } from "./gate/paths.mjs";

const ACTIONS = new Set(["open", "close", "print"]);
const ISSUE_NUMBER = /^[1-9]\d*$/;

function run(argv, cwd, platform) {
  const [action, number, ...extra] = argv;
  if (!ACTIONS.has(action) || !ISSUE_NUMBER.test(number ?? "") || extra.length > 0) {
    throw new GateFailure("grant.mjs", "usage: open <n> | close <n> | print <n>");
  }
  const n = Number(number);
  const scriptCheckout = runCommand("git", ["-C", dirname(fileURLToPath(import.meta.url)), "rev-parse", "--show-toplevel"]);
  const mainCheckout = dirname(runCommand("git", ["-C", cwd, "rev-parse", "--path-format=absolute", "--git-common-dir"]));
  const listPath = join(scriptCheckout, GATE_LIST_FILE);
  const list = parseGateList(readText(listPath), listPath);
  const refused = (code, detail) => ({ status: 1, text: message(list, code, detail) });
  const sameCheckout = resolvePath(scriptCheckout, "", platform) === resolvePath(mainCheckout, "", platform);
  if (action !== "print" && !sameCheckout) return refused(CODES.notMainCheckout, scriptCheckout);
  const grantPath = join(mainCheckout, list.grantsDir, `${n}.json`);
  if (action === "close") {
    rmSync(grantPath, { force: true });
    return { status: 0, text: grantPath };
  }
  const issueCommand = ["issue", "view", String(n), "--json", "state,labels,body"];
  const issue = parseJson(runCommand("gh", issueCommand), `gh ${issueCommand.join(" ")}`);
  const { grant, refusal } = grantFromIssue(n, issue, list, platform.fold);
  if (refusal) return refused(refusal.code, refusal.detail);
  const text = JSON.stringify(grant, null, 2);
  if (action === "print") return { status: 0, text };
  const missing = list.highTierRequires.find((path) => !existsSync(join(mainCheckout, path)));
  if (isHighTier(issue, list) && missing) return refused(CODES.highTierPrecondition, missing);
  mkdirSync(dirname(grantPath), { recursive: true });
  writeFileSync(grantPath, `${text}\n`);
  return { status: 0, text };
}

function outcome() {
  try {
    return run(process.argv.slice(2), process.cwd(), platformOf(process.platform));
  } catch (error) {
    return { status: 1, text: `${CODES.failure}: ${error.message}` };
  }
}

const { status, text } = outcome();
(status === 0 ? process.stdout : process.stderr).write(`${text}\n`);
process.exitCode = status;
