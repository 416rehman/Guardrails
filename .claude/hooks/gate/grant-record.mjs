import { CODES } from "./gate-list.mjs";
import { matchGlob } from "./glob.mjs";

export const GRANT_SCHEMA = "grdr.kit.grant.v1";
const GRANT_KEYS = ["agent", "branch", "issue", "schema", "write_set"];

// A grant, or the refusal `grant.mjs` reports, for issue `n` as `gh issue view --json state,labels,body` returns it.
export function grantFromIssue(n, issue, list, fold) {
  const refuse = (detail) => ({ refusal: { code: CODES.invalidGrant, detail } });
  if (issue?.state !== list.openState) return refuse(`issue #${n} is not open`);
  const agents = labelNames(issue).filter((name) => name.startsWith(list.agentLabelPrefix));
  if (agents.length !== 1) return refuse(`issue #${n} has ${agents.length} ${list.agentLabelPrefix} labels, not one`);
  const writeSet = writeSetLines(String(issue.body ?? ""), list.writeSetHeading);
  if (writeSet.length === 0) return refuse(`issue #${n} has no ${list.writeSetHeading} lines`);
  const problem = writeSet.map((line) => writeSetLineProblem(line, list, fold)).find((found) => found !== null);
  if (problem) return { refusal: problem };
  const agent = agents[0].slice(list.agentLabelPrefix.length);
  return { grant: { schema: GRANT_SCHEMA, issue: n, agent, branch: `${list.branchPrefix}${n}`, write_set: writeSet } };
}

export function isHighTier(issue, list) {
  return labelNames(issue).some((name) => list.highTierLabels.includes(name));
}

export function parseGrant(text, n, list, fold) {
  let record;
  try {
    record = JSON.parse(text);
  } catch (error) {
    return { kind: "invalid", detail: `grant ${n}: ${error.message}` };
  }
  const keys = record !== null && typeof record === "object" ? Object.keys(record).sort().join() : "";
  const valid =
    keys === GRANT_KEYS.join() &&
    record.schema === GRANT_SCHEMA &&
    record.issue === n &&
    record.branch === `${list.branchPrefix}${n}` &&
    typeof record.agent === "string" &&
    record.agent !== "" &&
    Array.isArray(record.write_set) &&
    record.write_set.length > 0 &&
    record.write_set.every((line) => typeof line === "string" && writeSetLineProblem(line, list, fold) === null);
  return valid ? { kind: "valid", record } : { kind: "invalid", detail: `grant ${n} does not match ${GRANT_SCHEMA}` };
}

function writeSetLines(body, heading) {
  const lines = body.split(/\r?\n/).map((line) => line.trim());
  const start = lines.indexOf(heading);
  if (start === -1) return [];
  const section = lines.slice(start + 1);
  const end = section.findIndex((line) => line.startsWith("#"));
  return (end === -1 ? section : section.slice(0, end)).filter((line) => line !== "");
}

// The line is read as a path whose wildcards are plain characters, so `spec/*.md` meets `spec/**`
// but `crates/x/**` does not meet `**/*.snap`.
function writeSetLineProblem(line, list, fold) {
  const relative = line !== "" && !/^[/!]|^[a-zA-Z]:|\\/.test(line) && !line.split("/").includes("..");
  if (!relative) return { code: CODES.invalidGrant, detail: `write set line ${line} is not a relative glob` };
  if (list.neverGrantable.some((glob) => matchGlob(glob, line, fold))) return { code: CODES.notGrantable, detail: line };
  return null;
}

function labelNames(issue) {
  return (Array.isArray(issue?.labels) ? issue.labels : []).map((label) => label?.name).filter((name) => typeof name === "string");
}
