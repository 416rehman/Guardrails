import { CODES, grantableTo, matchingEntries, message } from "./gate-list.mjs";
import { matchGlob } from "./glob.mjs";
import { foldPath, isWithin, joinPath, locate, resolvePath } from "./paths.mjs";
import { parseShell } from "./shell.mjs";

export const NO_DECISION = Object.freeze({ kind: "no-decision" });
const PATH_FIELDS = Object.freeze({ Edit: "file_path", Write: "file_path", MultiEdit: "file_path", NotebookEdit: "notebook_path" });
const SHELL_DIALECTS = Object.freeze({ Bash: "bash", PowerShell: "powershell" });
const CHANGE_DIRECTORY = new Set(["cd", "pushd", "set-location"]);
const TEE = "tee";
const OPTION_VALUE = /^--[^=]+=(.+)$/;

export function deny(code, reason) {
  return Object.freeze({ kind: "deny", code, message: reason });
}

// `context`: { platform, roots (main checkout first), cwd, caller: { worktree, branch }, gateList,
// grant: { kind: "none" } | { kind: "invalid", detail } | { kind: "valid", record }, expand(word, dir) }.
// Reads no file, environment, process or clock, and never allows.
export function decide(input, context) {
  if (Object.hasOwn(PATH_FIELDS, input.tool_name)) return decideFile(input, context);
  if (Object.hasOwn(SHELL_DIALECTS, input.tool_name)) return decideShell(input, context);
  return NO_DECISION;
}

export function isSubagent(input) {
  return typeof input.agent_id === "string" && input.agent_id !== "";
}

function grantState(input, context) {
  const { grant } = context;
  if (grant.kind !== "valid") return grant.kind;
  return isSubagent(input) && grant.record.agent === input.agent_type ? "matching" : "other-agent";
}

function refuse(context, code, detail) {
  return deny(code, message(context.gateList, code, detail));
}

function decideFile(input, context) {
  const { gateList: list, platform } = context;
  const field = PATH_FIELDS[input.tool_name];
  const raw = input.tool_input?.[field];
  if (typeof raw !== "string" || raw === "") return deny(CODES.failure, `${CODES.failure}: tool_input.${field} is missing`);
  const target = resolvePath(raw, context.cwd, platform);
  const place = locate(target, context.roots);
  if (place && isGrantsPath(place.rel, context)) return refuse(context, CODES.grantsTouched, place.rel);
  if (!place) return NO_DECISION;
  const inOwnWorktree = inCallerWorktree(target, context);
  if (isSubagent(input) && !inOwnWorktree) return refuse(context, CODES.outsideWorktree, target);
  const state = grantState(input, context);
  if (state === "invalid" && inOwnWorktree) return refuse(context, CODES.invalidGrant, context.grant.detail);
  const entries = matchingEntries(list, place.rel, platform.fold);
  if (state !== "matching") return entries.length > 0 ? refuse(context, CODES.noGrant, place.rel) : NO_DECISION;
  const { record } = context.grant;
  const writable = [...record.write_set, ...list.alwaysWritable].some((glob) => matchGlob(glob, place.rel, platform.fold));
  if (!writable) return refuse(context, CODES.outsideWriteSet, place.rel);
  return grantableTo(entries, record.agent) ? NO_DECISION : refuse(context, CODES.notGrantable, place.rel);
}

function decideShell(input, context) {
  const segments = parseShell(String(input.tool_input?.command ?? ""), SHELL_DIALECTS[input.tool_name]);
  const analysed = [];
  let bases = [context.cwd];
  for (const segment of segments) {
    const pathsOf = (word) => bases.flatMap((base) => wordPaths(word, base, context));
    const changesDirectory = CHANGE_DIRECTORY.has(segment.words[0]?.text.toLowerCase());
    const teeAt = segment.words.findIndex((word) => word.text === TEE);
    const teeTargets = teeAt === -1 ? [] : segment.words.slice(teeAt + 1).filter((word) => !word.text.startsWith("-"));
    analysed.push({
      checked: !changesDirectory && !hasShellPrefix(segment.words, context.gateList),
      words: segment.words.flatMap(pathsOf),
      writes: [...segment.redirects, ...teeTargets].flatMap(pathsOf),
    });
    const dir = changesDirectory ? segment.words.slice(1).filter((word) => !word.text.startsWith("-")).at(-1) : undefined;
    if (dir) bases = [...new Set([...bases, ...pathsOf(dir)])];
  }
  if (isSubagent(input)) {
    const touched = analysed.flatMap((s) => [...s.words, ...s.writes]).find((path) => touchesGrants(path, context));
    if (touched) return refuse(context, CODES.grantsTouched, touched);
  }
  const written = analysed.flatMap((s) => s.writes).find((path) => namesGatePath(path, context));
  if (written) return refuse(context, CODES.shellGatePath, written);
  const named = analysed.filter((s) => s.checked).flatMap((s) => s.words).find((path) => namesGatePath(path, context));
  return named ? refuse(context, CODES.shellGatePath, named) : NO_DECISION;
}

function wordPaths(word, base, context) {
  const texts = [word.text, word.text.match(OPTION_VALUE)?.[1]].filter((text) => text !== undefined && text !== "");
  return texts.flatMap((text) => {
    const expanded = word.glob ? context.expand(text, base) : [];
    return (expanded.length > 0 ? expanded : [text]).map((path) => resolvePath(path, base, context.platform));
  });
}

function hasShellPrefix(words, list) {
  return list.shellPrefixes.some((prefix) => prefix.length <= words.length && prefix.every((part, i) => words[i].text === part));
}

// A gate-list path, or a directory holding an entry's literal prefix under some checkout root.
function namesGatePath(path, context) {
  const { gateList: list, platform, roots } = context;
  const place = locate(path, roots);
  if (place && matchingEntries(list, place.rel, platform.fold).length > 0) return true;
  return roots.some((root) => list.entries.some((entry) => isWithin(joinPath(root, foldPath(entry.prefix, platform)), path)));
}

function touchesGrants(path, context) {
  const place = locate(path, context.roots);
  return place !== null && (place.rel === foldPath(context.gateList.grantTool, context.platform) || isGrantsPath(place.rel, context));
}

function isGrantsPath(rel, context) {
  return isWithin(rel, foldPath(context.gateList.grantsDir, context.platform));
}

function inCallerWorktree(target, context) {
  const { worktree } = context.caller;
  if (worktree === null || !isWithin(target, worktree)) return false;
  return locate(target, context.roots)?.root === locate(worktree, context.roots)?.root;
}
