import { literalPrefix, matchGlob } from "./glob.mjs";
import { GateFailure, parseJson } from "./io.mjs";

export const GATE_LIST_FILE = ".claude/gate-paths.json";
export const GATE_LIST_SCHEMA = "grdr.kit.gate-paths.v1";
export const ANY_AGENT = "*";
export const CODES = Object.freeze({
  noGrant: "GRDR-KIT-0001",
  outsideWorktree: "GRDR-KIT-0002",
  outsideWriteSet: "GRDR-KIT-0003",
  shellGatePath: "GRDR-KIT-0004",
  grantsTouched: "GRDR-KIT-0005",
  notGrantable: "GRDR-KIT-0006",
  invalidGrant: "GRDR-KIT-0007",
  failure: "GRDR-KIT-0008",
  notMainCheckout: "GRDR-KIT-0009",
  highTierPrecondition: "GRDR-KIT-0010",
});

// GRDR-KIT-0008 has no message in the gate list: it is also the code for a gate list that cannot be read.
const MESSAGE_CODES = Object.values(CODES).filter((code) => code !== CODES.failure);

export function parseGateList(text, subject) {
  const raw = parseJson(text, subject);
  const field = (value, name, valid) => {
    if (!valid(value)) throw new GateFailure(subject, `${name} is missing or invalid`);
    return value;
  };
  const strings = (value, name) => field(value, name, isStringList);
  const string = (value, name) => field(value, name, isText);
  field(raw?.schema, "schema", (value) => value === GATE_LIST_SCHEMA);
  const groups = field(raw.entries, "entries", (value) => Array.isArray(value) && value.length > 0);
  return {
    entries: groups.flatMap((group, index) => {
      const agents = strings(group?.agents, `entries[${index}].agents`);
      return strings(group.globs, `entries[${index}].globs`).map((glob) => ({ glob, agents, prefix: literalPrefix(glob) }));
    }),
    neverGrantable: strings(raw.never_grantable, "never_grantable"),
    alwaysWritable: strings(raw.always_writable, "always_writable"),
    shellPrefixes: strings(raw.shell_prefixes, "shell_prefixes").map((prefix) => prefix.split(" ")),
    grantTool: string(raw.grant_tool, "grant_tool"),
    grantsDir: string(raw.grants_dir, "grants_dir"),
    branchPrefix: string(raw.issue?.branch_prefix, "issue.branch_prefix"),
    agentLabelPrefix: string(raw.issue?.agent_label_prefix, "issue.agent_label_prefix"),
    writeSetHeading: string(raw.issue?.write_set_heading, "issue.write_set_heading"),
    openState: string(raw.issue?.open_state, "issue.open_state"),
    highTierLabels: strings(raw.high_tier?.labels, "high_tier.labels"),
    highTierRequires: strings(raw.high_tier?.requires, "high_tier.requires"),
    messages: field(raw.messages, "messages", (value) => MESSAGE_CODES.every((code) => isText(value?.[code]))),
  };
}

export function message(list, code, detail) {
  return `${code}: ${list.messages[code].replaceAll("{detail}", detail)}`;
}

export function matchingEntries(list, rel, fold) {
  return list.entries.filter((entry) => matchGlob(entry.glob, rel, fold));
}

export function grantableTo(entries, agent) {
  return entries.every((entry) => entry.agents.includes(ANY_AGENT) || entry.agents.includes(agent));
}

function isText(value) {
  return typeof value === "string" && value !== "";
}

function isStringList(value) {
  return Array.isArray(value) && value.every(isText);
}
