// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Environment declaration, directory-change, and Bash control-block helpers for security-audit-scan.mjs.
import { resolve } from "node:path";
import {
  NESTED_SHELL_NAMES,
  PS_COMMON_VAL_FLAG_RE,
  SENSITIVE_GIT_ENV_RE,
  SENSITIVE_GIT_TEXT_RE,
  commandBaseName,
  isDynamicPath,
} from "./security-audit-flags.mjs";

export const SENSITIVE_ARG_BASES = new Set([
  "git", "gh", "eval", "iex", "invoke-expression", "invoke-command", "icm", "start-process", "saps", "start", "start-threadjob",
  "export", "declare", "typeset", "local", "readonly", "unset",
  "set", "cd", "chdir", "pushd", "push-location", "set-location", "sl", "for", "select", "read", "mapfile", "readarray", "printf",
  "set-item", "si", "set-content", "sc", "new-item", "ni", "add-content", "ac", "set-variable", "sv",
  "clear-item", "cli", "clear-content", "clc",
]);
export const BASH_ASSIGN_BUILTINS = new Set([
  "export", "declare", "typeset", "local", "readonly", "unset", "for", "select", "read", "mapfile", "readarray", "printf",
]);
export const PS_ENV_COMMANDS = new Set([
  "set-item", "si", "set-content", "sc", "new-item", "ni", "add-content", "ac", "set-variable", "sv",
  "clear-item", "cli", "clear-content", "clc",
]);
export const PS_ENV_PROVIDER_CMDS = new Set([
  "set-item", "si", "set-content", "sc", "new-item", "ni", "add-content", "ac", "clear-item", "cli", "clear-content", "clc",
]);
export const PS_ENV_TARGET_RE = /^env:(?:[\\/.\w]|$)/i;
export const PS_DRIVE_RE = /^[A-Za-z]{2,}:(?:[\\/]|$)/;

const PS_SWITCH_RE = /^-(?:f(?:o(?:r(?:c(?:e)?)?)?)?|pas(?:s(?:t(?:h(?:r(?:u)?)?)?)?)?|no(?:n(?:e(?:w(?:l(?:i(?:ne?)?)?)?)?)?)?|ve(?:r(?:b(?:o(?:s(?:e)?)?)?)?)?)$/i;
const PS_DRYRUN_RE = /^-(?:wh(?:a(?:t(?:if?)?)?)?|co(?:n(?:f(?:i(?:rm?)?)?)?)?)$/i;
const PS_VAL_FLAG_RE = /^-va(?:l(?:u(?:e)?)?)?(?::([\s\S]*))?$/i;
const PS_PATH_FLAG_RE = /^-(?:p(?:a(?:t(?:h)?)?)?|li(?:t(?:e(?:r(?:a(?:l(?:p(?:a(?:t(?:h)?)?)?)?)?)?)?)?)?)(?::([\s\S]*))?$/i;
const PS_NAME_FLAG_RE = /^-na(?:m(?:e)?)?(?::([\s\S]*))?$/i;
const PS_STACK_FLAG_RE = /^-st(?:a(?:c(?:k(?:n(?:a(?:m(?:e)?)?)?)?)?)?)?(?::([\s\S]*))?$/i;
const BASH_CTRL_PREFIX_WORDS = new Set([
  "if", "then", "elif", "else", "fi", "while", "until", "for", "select", "do", "done", "case", "esac", "!", "coproc", "time",
]);

export function parsePsEnvCommandArgs(tokens, cmdIndex) {
  let pathArg;
  let nameArg;
  let pos0;
  let value;
  let unknownFlag = false;
  let dryRunFlag = false;
  for (let j = cmdIndex + 1; j < tokens.length; j += 1) {
    const raw = tokens[j];
    if (PS_DRYRUN_RE.test(raw)) { dryRunFlag = true; continue; }
    if (PS_SWITCH_RE.test(raw)) continue;
    const valM = raw.match(PS_VAL_FLAG_RE);
    if (valM) { value = valM[1] !== undefined ? valM[1] : tokens[++j]; continue; }
    const pathM = raw.match(PS_PATH_FLAG_RE);
    if (pathM) { pathArg = pathM[1] !== undefined ? pathM[1] : tokens[++j]; continue; }
    const nameM = raw.match(PS_NAME_FLAG_RE);
    if (nameM) { nameArg = nameM[1] !== undefined ? nameM[1] : tokens[++j]; continue; }
    if (raw.startsWith("-")) { unknownFlag = true; continue; }
    if (pos0 === undefined) pos0 = raw;
    else if (value === undefined) value = raw;
  }
  const basePath = pathArg ?? pos0;
  let target = basePath ?? nameArg ?? "";
  if (pathArg && nameArg && /^env:[\\/]?$/i.test(pathArg)) target = `Env:${nameArg}`;
  else if (!pathArg && nameArg && pos0 === undefined) target = nameArg;
  return { target, value, unknownFlag, dryRunFlag };
}

export function isPsEnvWriteSegment(base, tokens, psParsed, inEnvNs) {
  if (!psParsed) return false;
  if (PS_ENV_TARGET_RE.test(psParsed.target)) return true;
  if (!PS_ENV_PROVIDER_CMDS.has(base)) return false;
  if (inEnvNs) return true;
  return psParsed.unknownFlag && tokens.some((t) => /^(?:env:|GIT_)/i.test(t));
}

function recordGitEnvVar(state, name, val, item, activeBash, hasCoproc, markConditionalScope) {
  const upper = name.toUpperCase();
  if (upper !== "GIT_DIR" && upper !== "GIT_WORK_TREE") return;
  state.envTickByDepth?.set(item.subshellDepth, (state.envTickByDepth.get(item.subshellDepth) ?? 0) + 1);
  markConditionalScope(state.condEnvByDepth, item, activeBash, hasCoproc);
  if (isDynamicPath(val)) { state.dynamicDir = true; return; }
  if (upper === "GIT_DIR") state.gitDirStack[state.gitDirStack.length - 1] = val;
  else state.workTreeStack[state.workTreeStack.length - 1] = val;
}

export function handleEnvDecl(tokens, cmdIndex, state, item, activeBash, hasCoproc, markConditionalScope) {
  const base = commandBaseName(tokens[cmdIndex] ?? "");
  if (base === "unset") {
    for (let i = cmdIndex + 1; i < tokens.length; i += 1) {
      const tok = tokens[i];
      if (tok.startsWith("-")) continue;
      if (SENSITIVE_GIT_ENV_RE.test(tok)) state.sensitiveGitEnv = true;
      const upper = tok.toUpperCase();
      if (upper === "GIT_DIR" || upper === "GIT_WORK_TREE") {
        state.envTickByDepth?.set(item.subshellDepth, (state.envTickByDepth.get(item.subshellDepth) ?? 0) + 1);
        markConditionalScope(state.condEnvByDepth, item, activeBash, hasCoproc);
        if (upper === "GIT_DIR") state.gitDirStack[state.gitDirStack.length - 1] = undefined;
        else state.workTreeStack[state.workTreeStack.length - 1] = undefined;
      }
    }
    return;
  }
  if (PS_ENV_COMMANDS.has(base)) {
    const { target, value, unknownFlag, dryRunFlag } = parsePsEnvCommandArgs(tokens, cmdIndex);
    if (tokens.some((t) => SENSITIVE_GIT_TEXT_RE.test(t))) state.sensitiveGitEnv = true;
    const inEnvNs = state.psEnvDriveStack[state.psEnvDriveStack.length - 1];
    const hasEnvPrefix = /^env:/i.test(target);
    const touchesEnv = PS_ENV_TARGET_RE.test(target) || inEnvNs || tokens.some((t) => /^env:/i.test(t));
    if ((unknownFlag || dryRunFlag) && (touchesEnv || tokens.some((t) => /GIT_/i.test(t)))) {
      state.sensitiveGitEnv = true;
      return;
    }
    if (touchesEnv && (hasEnvPrefix || inEnvNs)) {
      const cleaned = target.replace(/^env:[\\/]?/i, "").replace(/^(?:[.\\/])+/, "");
      if (SENSITIVE_GIT_ENV_RE.test(cleaned)) state.sensitiveGitEnv = true;
      const m = cleaned.match(/^(GIT_DIR|GIT_WORK_TREE)$/i);
      if (m) {
        if (["clear-item", "cli", "clear-content", "clc"].includes(base)) {
          state.envTickByDepth?.set(item.subshellDepth, (state.envTickByDepth.get(item.subshellDepth) ?? 0) + 1);
          state.sensitiveGitEnv = true;
        } else recordGitEnvVar(state, m[1], value, item, activeBash, hasCoproc, markConditionalScope);
      } else if (/GIT_/i.test(cleaned) || cleaned.includes("..")) state.sensitiveGitEnv = true;
    }
    return;
  }

  for (let i = cmdIndex; i < tokens.length; i += 1) {
    const tok = tokens[i];
    if (SENSITIVE_GIT_TEXT_RE.test(tok)) state.sensitiveGitEnv = true;
    const m = tok.match(/^(?:\$env:|env:[\\/]?)?(GIT_DIR|GIT_WORK_TREE)(?:=(.*))?$/i);
    if (!m) continue;
    let val = m[2];
    if (val === undefined) {
      if (tokens[i + 1] === "=" && i + 2 < tokens.length) { val = tokens[i + 2]; i += 2; }
      else if (i + 1 < tokens.length && tokens[i + 1] !== "=") { val = tokens[i + 1]; i += 1; }
    }
    recordGitEnvVar(state, m[1], val, item, activeBash, hasCoproc, markConditionalScope);
  }
}

export function resolveChildGitEnv(envVars, envCleared, unsetEnvVars, baseCwd, state) {
  const curGitDir = envCleared || unsetEnvVars.has("GIT_DIR") ? undefined : state.gitDirStack[state.gitDirStack.length - 1];
  const curWorkTree = envCleared || unsetEnvVars.has("GIT_WORK_TREE") ? undefined : state.workTreeStack[state.workTreeStack.length - 1];
  const rawGitDir = envVars.GIT_DIR ?? envVars.git_dir ?? curGitDir;
  const rawWorkTree = envVars.GIT_WORK_TREE ?? envVars.git_work_tree ?? curWorkTree;
  const dynamic = (rawGitDir !== undefined && isDynamicPath(rawGitDir)) || (rawWorkTree !== undefined && isDynamicPath(rawWorkTree));
  return {
    gitDir: rawGitDir !== undefined && !isDynamicPath(rawGitDir) ? resolve(baseCwd, rawGitDir) : undefined,
    workTree: rawWorkTree !== undefined && !isDynamicPath(rawWorkTree) ? resolve(baseCwd, rawWorkTree) : undefined,
    dynamic,
  };
}

export function parseDirChangeArgs(tokens, cmdIndex, dialect, fromCmd = false) {
  let dest;
  let usedNamedStack = false;
  let unknownFlag = false;
  let afterDashDash = false;
  for (let j = cmdIndex + 1; j < tokens.length; j += 1) {
    const raw = tokens[j];
    if (!afterDashDash) {
      if (raw === "--") { afterDashDash = true; continue; }
      if (fromCmd && /^\/d$/i.test(raw)) continue;
      if (dialect === "powershell") {
        if (!PS_DRYRUN_RE.test(raw) && PS_SWITCH_RE.test(raw)) continue;
        const commonM = raw.match(PS_COMMON_VAL_FLAG_RE);
        if (commonM) { if (commonM[1] === undefined) j += 1; continue; }
        const pathM = raw.match(PS_PATH_FLAG_RE);
        if (pathM) { dest = pathM[1] !== undefined ? pathM[1] : tokens[++j]; continue; }
        const stackM = raw.match(PS_STACK_FLAG_RE);
        if (stackM) { usedNamedStack = true; if (stackM[1] === undefined) j += 1; continue; }
        if (raw.startsWith("-") && raw !== "-") return { dest: undefined, usedNamedStack: false, unknownFlag: true };
      } else if (dialect === "bash") {
        if (/^-[LPe@]+$/.test(raw)) continue;
        if (raw.startsWith("-") && raw !== "-") return { dest: undefined, usedNamedStack: false, unknownFlag: true };
      }
    }
    if (raw === "-" && dest === undefined) { dest = "-"; continue; }
    if (dest === undefined) dest = raw;
  }
  return { dest, usedNamedStack, unknownFlag };
}

export function isBenignPsVarSegment(tokens, envStartIdx, cmdIndex, state, item) {
  if (!item.inPsCond || state.sawBashVarAssign) return false;
  if (envStartIdx !== cmdIndex || cmdIndex >= tokens.length) return false;
  if (!/^\$[A-Za-z_][A-Za-z0-9_.:]*$/.test(tokens[cmdIndex])) return false;
  if (tokens.some((t) => /^(?:git|gh|commit|&|\.)$/i.test(t))) return false;
  if (tokens.length === cmdIndex + 1) return true;
  const nextTok = tokens[cmdIndex + 1];
  return nextTok === "in" || /^[=+]$|^-(?:eq|ne|gt|lt|ge|le|and|or|not|match|like|contains|in|is)$/i.test(nextTok);
}

export function hasSensitiveDynamicArgs(base, flags) {
  return (SENSITIVE_ARG_BASES.has(base) || NESTED_SHELL_NAMES.has(base)) && flags.some(Boolean);
}

export function updateBashCtrlStack(tokens, item, state, quotedOrEscapedFlags = []) {
  const topCase = state.bashCtrlStack[state.bashCtrlStack.length - 1];
  if (topCase && topCase.kind === "case" && topCase.subshellDepth === item.subshellDepth && item.sep === ")") {
    topCase.branch += 1;
  }
  let sawTimeWord = false;
  for (let i = 0; i < tokens.length; i += 1) {
    if (quotedOrEscapedFlags[i]) break;
    const rawTok = tokens[i];
    if (sawTimeWord && rawTok === "-p") { sawTimeWord = false; continue; }
    sawTimeWord = false;
    const word = rawTok.replace(/^[({]+/, "").replace(/[);]+$/, "");
    if (!word || !BASH_CTRL_PREFIX_WORDS.has(word)) break;
    if (word === "time") { sawTimeWord = true; continue; }
    if (word === "if" || word === "case") {
      state.bashCtrlStack.push({ kind: word, id: state.nextBashCtrlId++, branch: 0, subshellDepth: item.subshellDepth });
    } else if (word === "while" || word === "until" || word === "for" || word === "select") {
      state.bashCtrlStack.push({ kind: "loop", id: state.nextBashCtrlId++, branch: 0, subshellDepth: item.subshellDepth });
    } else if (word === "then" || word === "elif" || word === "else" || word === "do") {
      const top = state.bashCtrlStack[state.bashCtrlStack.length - 1];
      if (top && top.subshellDepth === item.subshellDepth) top.branch += 1;
    } else if (word === "fi" || word === "done" || (word === "esac" && !item.pipedIn)) {
      const want = word === "fi" ? "if" : word === "esac" ? "case" : "loop";
      const top = state.bashCtrlStack[state.bashCtrlStack.length - 1];
      if (top && top.kind === want && top.subshellDepth === item.subshellDepth) {
        if (want === "case" && item.pipedOut) top.sawPipeEsac = true;
        else state.bashCtrlStack.pop();
      }
    }
  }
}

export function markConditionalScope(map, item, activeBash, forceAlways = false) {
  const inPipelineOrBg = forceAlways || item.pipedIn || item.pipedOut || item.isBackground;
  const isCond = item.sep === "&&" || item.sep === "||" || item.condBlockTag > 0 || inPipelineOrBg || Boolean(activeBash);
  if (!isCond) return;
  map.set(item.subshellDepth, {
    type: inPipelineOrBg || item.sep === "||" ? "always" : activeBash ? "bashBlock" : item.condBlockTag > 0 ? "block" : "and",
    condBlockTag: item.condBlockTag,
    bashBlockId: activeBash?.id ?? 0,
    bashBranch: activeBash?.branch ?? 0,
  });
}

export function hasLeftConditionalScope(map, state, item) {
  for (const [d, pending] of map.entries()) {
    if (d > item.subshellDepth) continue;
    const leftBlock = pending.condBlockTag > 0 && item.condBlockTag !== pending.condBlockTag;
    const leftAnd = pending.type === "and" && item.sep !== "&&";
    const activeBash = pending.type === "bashBlock"
      ? state.bashCtrlStack.find((b) => b.id === pending.bashBlockId)
      : undefined;
    const leftBash = pending.type === "bashBlock" && (!activeBash || activeBash.branch !== pending.bashBranch || Boolean(activeBash.sawPipeEsac));
    if (pending.type === "always" || leftBlock || leftAnd || leftBash) return true;
  }
  return false;
}

export function applyScopeOffset(rawItem, scopeOffset, nextCondOffset) {
  if (!scopeOffset) return rawItem;
  return {
    ...rawItem,
    subshellDepth: rawItem.subshellDepth + scopeOffset.baseSubshellDepth,
    braceDepth: rawItem.braceDepth + scopeOffset.baseBraceDepth,
    condBlockTag: rawItem.condBlockTag > 0 ? nextCondOffset + rawItem.condBlockTag : (scopeOffset.evalCondTag || scopeOffset.rootCondBlockTag),
    pipedIn: rawItem.pipedIn || scopeOffset.rootPipedOrBg,
    sep: rawItem.subshellDepth === 0 && rawItem.sep === "start" ? scopeOffset.rootSep : rawItem.sep,
  };
}
