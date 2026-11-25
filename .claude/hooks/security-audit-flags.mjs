// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Wrapper, git, and gh argument parsers for security-audit-scan.mjs.
import { resolve } from "node:path";

export const NESTED_SHELL_NAMES = new Set(["bash", "sh", "zsh", "dash", "ksh", "ash", "pwsh", "powershell", "cmd"]);
export const SHELL_CONTROL_WORDS = new Set([
  "if", "then", "elif", "else", "fi", "do", "done", "while", "until", "case", "in", "!", "coproc", "(", ")", "{", "}",
]);
export const MUTATING_COMMANDS = new Set([
  "tee", "cp", "mv", "rm", "del", "erase", "rmdir", "touch", "ln", "install", "sed", "awk", "perl", "python",
  "python3", "node", "ruby", "curl", "wget", "dd", "patch", "truncate", "copy", "move", "ren", "cpi", "mi",
  "ri", "rni", "ni", "sc", "ac", "si", "cli", "clc", "add-content", "out-file", "new-item", "remove-item",
  "move-item", "copy-item", "rename-item", "set-content", "clear-item", "clear-content",
]);
export const MUTATING_GIT_SUBCOMMANDS = new Set([
  "checkout", "switch", "reset", "restore", "apply", "am", "cherry-pick", "rebase", "merge", "pull", "rm",
  "mv", "stash", "clean", "update-index", "read-tree", "checkout-index", "commit-tree",
  "update-ref", "symbolic-ref", "replace", "config", "revert", "worktree", "submodule", "sparse-checkout", "branch",
]);
export const SENSITIVE_GIT_ENV_RE =
  /^(?:GIT_INDEX_FILE|GIT_OBJECT_DIRECTORY|GIT_ALTERNATE_OBJECT_DIRECTORIES|GIT_COMMON_DIR|GIT_EXEC_PATH|GIT_EDITOR|GIT_SEQUENCE_EDITOR|GIT_ATTR_NOSYSTEM|GIT_ATTR_NOUSER|GIT_CONFIG.*)$/i;
export const SENSITIVE_GIT_TEXT_RE =
  /\b(?:env:[\\/]?)?GIT_(?:INDEX_FILE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|COMMON_DIR|EXEC_PATH|EDITOR|SEQUENCE_EDITOR|ATTR_NOSYSTEM|ATTR_NOUSER|CONFIG\w*)/i;
export const PS_COMMON_VAL_FLAG_RE =
  /^-(?:e(?:a|rrora(?:c(?:t(?:i(?:o(?:n)?)?)?)?)?)|e(?:v|rrorv(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?)|w(?:a|arninga(?:c(?:t(?:i(?:o(?:n)?)?)?)?)?)|w(?:v|arningv(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?)|o(?:v|utv(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?)|o(?:b|utb(?:u(?:f(?:f(?:er?)?)?)?)?)|i(?:nfa|nformationa(?:c(?:t(?:i(?:o(?:n)?)?)?)?)?)|i(?:v|nformationv(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?)|p(?:v|ipelinev(?:a(?:r(?:i(?:a(?:b(?:le?)?)?)?)?)?)?))(?::([\s\S]*))?$/i;
export const SENSITIVE_GIT_CFG_RE =
  /^(?:alias\.|include\.|includeif\.|core\.(?:worktree|bare|fsmonitor|hookspath|autocrlf|eol|editor|sparsecheckout|excludesfile|attributesfile|askpass|pager|sshcommand|gitproxy)|credential\.helper|filter\.|gpg\.(?:[a-z0-9_-]+\.)?program|extensions\.|diff\.external|sequence\.editor)/i;

const WRAPPER_SPECS = {
  env: {
    valueFlags: [/^--un(?:s(?:et?)?)?$/, /^--ar(?:g(?:v0?)?)?$/],
    dirFlags: [/^--ch(?:d(?:ir?)?)?$/],
    splitFlags: [/^--sp(?:l(?:i(?:t(?:-s(?:t(?:r(?:i(?:ng?)?)?)?)?)?)?)?)?$/],
    shortValueChars: new Set(["C", "S", "u", "a"]),
    shortDirChars: new Set(["C"]),
  },
  sudo: {
    valueFlags: [
      /^--us(?:er?)?$/, /^--ot(?:h(?:e(?:r(?:-u(?:s(?:er?)?)?)?)?)?)?$/, /^--gr(?:o(?:up?)?)?$/,
      /^--ho(?:st?)?$/, /^--pr(?:o(?:m(?:pt?)?)?)?$/, /^--ro(?:le?)?$/, /^--ty(?:pe?)?$/,
      /^--cl(?:o(?:s(?:e(?:-f(?:r(?:om?)?)?)?)?)?)?$/, /^--co(?:m(?:m(?:a(?:n(?:d(?:-t(?:i(?:m(?:e(?:o(?:ut?)?)?)?)?)?)?)?)?)?)?)?$/,
    ],
    dirFlags: [/^--chd(?:ir?)?$/],
    chrootFlags: [/^--chr(?:o(?:ot?)?)?$/],
    preserveEnvFlags: [/^--pr(?:e(?:s(?:e(?:r(?:v(?:e(?:-e(?:n(?:v)?)?)?)?)?)?)?)?)?$/],
    shortValueChars: new Set(["D", "R", "u", "U", "g", "h", "p", "r", "t", "C", "T"]),
    shortDirChars: new Set(["D"]),
    shortChrootChars: new Set(["R"]),
  },
  doas: { valueFlags: [], shortValueChars: new Set(["u", "C"]) },
  exec: { valueFlags: [], shortValueChars: new Set(["a"]) },
  nice: { valueFlags: [/^--ad(?:j(?:u(?:s(?:t(?:m(?:e(?:nt?)?)?)?)?)?)?)?$/], shortValueChars: new Set(["n"]) },
  timeout: { valueFlags: [/^--ki(?:l(?:l(?:-a(?:f(?:t(?:er?)?)?)?)?)?)?$/, /^--si(?:g(?:n(?:al?)?)?)?$/], shortValueChars: new Set(["k", "s"]), positionalOperands: 1 },
  stdbuf: { valueFlags: [/^--in(?:p(?:ut?)?)?$/, /^--ou(?:t(?:p(?:ut?)?)?)?$/, /^--er(?:r(?:or?)?)?$/], shortValueChars: new Set(["i", "o", "e"]) },
  ionice: { valueFlags: [/^--cla(?:s(?:s(?:d(?:a(?:ta?)?)?)?)?)?$/, /^--cl$/, /^--pi(?:d)?$/, /^--pg(?:id?)?$/, /^--ui(?:d)?$/], shortValueChars: new Set(["c", "n", "p", "P", "u"]) },
  chrt: { valueFlags: [/^--pi(?:d)?$/], shortValueChars: new Set(["p"]), optionalNumericOperand: true },
  flock: {
    valueFlags: [/^--conf(?:l(?:i(?:c(?:t(?:-e(?:x(?:i(?:t(?:-c(?:o(?:de?)?)?)?)?)?)?)?)?)?)?)?$/, /^--wa(?:it?)?$/, /^--ti(?:m(?:e(?:o(?:ut?)?)?)?)?$/],
    shortValueChars: new Set(["E", "w"]),
    positionalOperands: 1,
    supportsDashC: true,
  },
  taskset: { valueFlags: [/^--cp(?:u(?:-l(?:i(?:st?)?)?)?)?$/], shortValueChars: new Set(["c"]), positionalIfNoFlag: /^--cp|-c$/ },
  script: {
    valueFlags: [/^--log-t/, /^--log-i(?!o)/, /^--log-o/, /^--log-io/, /^--ec(?:ho?)?$/],
    shortValueChars: new Set(["T", "I", "O", "B", "E"]),
    positionalOperands: 1,
    supportsDashC: true,
  },
  xargs: {
    valueFlags: [
      /^--ar(?:g(?:-f(?:i(?:le?)?)?)?)?$/, /^--de(?:l(?:i(?:m(?:i(?:t(?:er?)?)?)?)?)?)?$/,
      /^--max-a(?:r(?:gs?)?)?$/, /^--max-l(?:i(?:n(?:es?)?)?)?$/, /^--max-p(?:r(?:o(?:cs?)?)?)?$/,
      /^--max-c(?:h(?:a(?:rs?)?)?)?$/,
      /^--pr(?:o(?:c(?:e(?:s(?:s(?:-s(?:l(?:o(?:t(?:-v(?:ar?)?)?)?)?)?)?)?)?)?)?)?$/,
    ],
    shortValueChars: new Set(["a", "d", "E", "I", "J", "L", "n", "P", "R", "S", "s"]),
  },
  time: { valueFlags: [/^--ou(?:t(?:p(?:ut?)?)?)?$/, /^--fo(?:r(?:m(?:at?)?)?)?$/], shortValueChars: new Set(["o", "f"]) },
  setsid: { valueFlags: [], shortValueChars: new Set() },
  nohup: { valueFlags: [], shortValueChars: new Set() },
  command: { valueFlags: [], shortValueChars: new Set() },
  builtin: { valueFlags: [], shortValueChars: new Set() },
  "&": { valueFlags: [], shortValueChars: new Set() },
  ".": { valueFlags: [], shortValueChars: new Set() },
};

const GIT_GLOBAL_VALUE_FLAGS = new Set(["-c", "--namespace", "--config-env", "--attr-source", "--super-prefix", "--exec-path"]);
const GIT_COMMIT_SHORT_VALUE_CHARS = new Set(["C", "c", "F", "m", "t"]);
const GH_VALUE_FLAGS = new Set([
  "-B", "-F", "-H", "-R", "-T", "-a", "-b", "-l", "-m", "-p", "-r", "-t", "--assignee", "--base", "--body",
  "--body-file", "--head", "--label", "--milestone", "--project", "--recover", "--repo", "--reviewer", "--template", "--title",
]);
const LONG_CMD_RE = /^--co(?:m(?:m(?:a(?:nd?)?)?)?)?$/;

export function commandBaseName(token) {
  const clean = token.replace(/^\$+/, "");
  const base = clean.slice(Math.max(clean.lastIndexOf("/"), clean.lastIndexOf("\\")) + 1);
  return base.toLowerCase().replace(/\.(?:exe|cmd|ps1|bat)$/i, "");
}

export function isDynamicPath(value) {
  return typeof value !== "string" || !value || /[$`()%~]/.test(value) || value === "-" || value.includes("__dyn_herestring__");
}

function isCmdVarNameChar(ch) {
  return /[A-Za-z0-9_()]/.test(ch);
}

function hasCmdPercentVar(value) {
  for (let i = 0; i < value.length; i += 1) {
    if (value[i] !== "%") continue;
    let j = i + 1;
    if (j >= value.length || !/[A-Za-z_]/.test(value[j])) continue;
    j += 1;
    while (j < value.length && isCmdVarNameChar(value[j])) j += 1;
    while (j + 1 < value.length && value[j] === "-" && isCmdVarNameChar(value[j + 1])) {
      j += 2;
      while (j < value.length && isCmdVarNameChar(value[j])) j += 1;
    }
    if (value[j] === ":") {
      j += 1;
      while (j < value.length && value[j] !== "%" && value[j] !== "\r" && value[j] !== "\n") j += 1;
    }
    if (j < value.length && value[j] === "%") return true;
  }
  return false;
}

export function isDynamicShellExpr(value) {
  return (
    typeof value === "string" &&
    (value.includes("__dyn_herestring__") ||
      /(?:^|[^\\])(?:\\\\)*\$(?:[A-Za-z0-9_{(@*?!$-])/.test(value) ||
      /(?:^|\s)@[A-Za-z_][A-Za-z0-9_:]*(?:\s|$)/.test(value) ||
      hasCmdPercentVar(value) ||
      /(?:^|[^\\])(?:\\\\)*`/.test(value))
  );
}

export function quoteTokensForDialect(tokens, isPs) {
  return tokens
    .map((tok) => {
      if (/^[A-Za-z0-9_./:=+-]+$/.test(tok)) return tok;
      if (isPs) return `'${tok.replace(/'/g, "''")}'`;
      return `'${tok.replace(/'/g, "'\\''")}'`;
    })
    .join(" ");
}

export function parseCommandEnvelope(tokens, baseCwd, dialect = "bash") {
  const envVars = {};
  const unsetEnvVars = new Set();
  const psReplacedIndices = [];
  const envSplitCmds = [];
  let idx = 0;
  let wrapperMode = "";
  let wrapperCwd = baseCwd;
  let dynamicWrapperDir = false;
  let viaXargs = false;
  let envCleared = false;
  let envStartIdx = 0;
  let savedPreSudoEnv;
  let inlineSubCmd;
  let remainingOperands = 0;
  let checkNumericOperand = false;
  let sawTasksetFlag = false;

  while (idx < tokens.length) {
    const rawTok = tokens[idx];
    const tok = rawTok.replace(/^[({]+/, "").replace(/[);]+$/, "");
    if (!tok || SHELL_CONTROL_WORDS.has(tok.toLowerCase())) { idx += 1; envStartIdx = idx; continue; }
    if (remainingOperands > 0 && !tok.startsWith("-")) { remainingOperands -= 1; idx += 1; continue; }
    if (checkNumericOperand && !tok.startsWith("-")) {
      checkNumericOperand = false;
      if (/^(?:0x)?[0-9a-f]+$/i.test(tok) && idx + 1 < tokens.length && !sawTasksetFlag) { idx += 1; continue; }
    }
    if (/^(?:\[[\w.]+\])?\$(?!env:)[A-Za-z_][\w:.]*$/i.test(tok) && tokens[idx + 1] === "=") {
      idx += 2;
      envStartIdx = idx;
      continue;
    }
    if (/^(?:\[[\w.]+\])?\$(?!env:)[A-Za-z_][\w:.]*=/i.test(rawTok)) {
      const rhs = rawTok.slice(rawTok.indexOf("=") + 1);
      psReplacedIndices.push(idx);
      if (rhs) tokens[idx] = rhs;
      else { idx += 1; envStartIdx = idx; }
      continue;
    }
    if (dialect === "bash" || wrapperMode === "env") {
      const envMatch = tok.match(/^([A-Za-z_]\w*)=(.*)$/);
      if (envMatch) { envVars[envMatch[1]] = envMatch[2]; idx += 1; continue; }
    }
    const base = commandBaseName(tok);
    if (Object.hasOwn(WRAPPER_SPECS, base) && (base !== "." || dialect === "powershell")) {
      wrapperMode = base;
      if (base === "xargs") viaXargs = true;
      if (base === "sudo") {
        savedPreSudoEnv = { ...envVars };
        for (const k of Object.keys(envVars)) delete envVars[k];
        envCleared = true;
      } else if (base === "doas") {
        for (const k of Object.keys(envVars)) delete envVars[k];
        envCleared = true;
      }
      remainingOperands = WRAPPER_SPECS[base].positionalOperands ?? 0;
      checkNumericOperand = Boolean(WRAPPER_SPECS[base].optionalNumericOperand || WRAPPER_SPECS[base].positionalIfNoFlag);
      sawTasksetFlag = false;
      idx += 1;
      continue;
    }
    const spec = wrapperMode ? WRAPPER_SPECS[wrapperMode] : undefined;
    if (spec && tok.startsWith("-")) {
      if (tok === "--") { idx += 1; continue; }
      if (wrapperMode === "env" && tok === "-") {
        envCleared = true;
        for (const k of Object.keys(envVars)) delete envVars[k];
        idx += 1;
        continue;
      }
      const eqPos = tok.indexOf("=");
      const flagName = eqPos >= 0 ? tok.slice(0, eqPos) : tok;
      const eqVal = eqPos >= 0 ? tok.slice(eqPos + 1) : undefined;
      if (wrapperMode === "sudo" && spec.preserveEnvFlags?.some((re) => re.test(flagName))) {
        envCleared = false;
        if (savedPreSudoEnv) Object.assign(envVars, savedPreSudoEnv);
        idx += 1;
        continue;
      }
      if (wrapperMode === "env" && /^--i(?:g(?:n(?:o(?:r(?:e(?:-e(?:n(?:v(?:i(?:r(?:o(?:n(?:m(?:e(?:nt?)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?$/.test(flagName)) {
        envCleared = true;
        for (const k of Object.keys(envVars)) delete envVars[k];
        idx += 1;
        continue;
      }
      if (wrapperMode === "env" && /^--un(?:s(?:et?)?)?$/.test(flagName)) {
        const uName = eqVal !== undefined ? eqVal : idx + 1 < tokens.length ? tokens[++idx] : "";
        if (uName) { unsetEnvVars.add(uName.toUpperCase()); delete envVars[uName]; }
        idx += 1;
        continue;
      }
      if (spec.supportsDashC) {
        if (LONG_CMD_RE.test(flagName)) {
          inlineSubCmd = eqVal !== undefined ? eqVal : idx + 1 < tokens.length ? tokens[++idx] : "$missing";
          idx += 1;
          break;
        }
        const shortC = !tok.startsWith("--") ? tok.match(/^-[A-Za-z0-9]*c([\s\S]*)$/) : null;
        if (shortC) { inlineSubCmd = shortC[1] ? shortC[1] : idx + 1 < tokens.length ? tokens[++idx] : "$missing"; idx += 1; break; }
      }
      if (spec.dirFlags?.some((re) => re.test(flagName))) {
        const val = eqVal !== undefined ? eqVal : idx + 1 < tokens.length ? tokens[++idx] : "";
        if (isDynamicPath(val)) dynamicWrapperDir = true;
        else wrapperCwd = resolve(wrapperCwd, val);
        idx += 1;
        continue;
      }
      if (spec.chrootFlags?.some((re) => re.test(flagName))) {
        if (eqVal === undefined && idx + 1 < tokens.length) idx += 1;
        dynamicWrapperDir = true;
        idx += 1;
        continue;
      }
      if (spec.splitFlags?.some((re) => re.test(flagName))) {
        envSplitCmds.push(eqVal !== undefined ? eqVal : idx + 1 < tokens.length ? tokens[++idx] : "");
        idx += 1;
        continue;
      }
      if (!tok.startsWith("--")) {
        for (let k = 1; k < tok.length; k += 1) {
          const ch = tok[k];
          const tail = tok.slice(k + 1);
          if (wrapperMode === "taskset" && ch === "c") sawTasksetFlag = true;
          if (wrapperMode === "sudo" && ch === "E") {
            envCleared = false;
            if (savedPreSudoEnv) Object.assign(envVars, savedPreSudoEnv);
            continue;
          }
          if (wrapperMode === "exec" && ch === "c") {
            envCleared = true;
            for (const key of Object.keys(envVars)) delete envVars[key];
            continue;
          }
          if (wrapperMode === "env" && ch === "i") { envCleared = true; for (const key of Object.keys(envVars)) delete envVars[key]; continue; }
          if (wrapperMode === "env" && ch === "u") {
            const uName = tail || (idx + 1 < tokens.length ? tokens[++idx] : "");
            if (uName) { unsetEnvVars.add(uName.toUpperCase()); delete envVars[uName]; }
            break;
          }
          if (spec.shortDirChars?.has(ch)) {
            const val = tail || (idx + 1 < tokens.length ? tokens[++idx] : "");
            if (isDynamicPath(val)) dynamicWrapperDir = true;
            else wrapperCwd = resolve(wrapperCwd, val);
            break;
          }
          if (spec.shortChrootChars?.has(ch)) {
            if (!tail && idx + 1 < tokens.length) idx += 1;
            dynamicWrapperDir = true;
            break;
          }
          if (wrapperMode === "env" && ch === "S") {
            envSplitCmds.push(tail || (idx + 1 < tokens.length ? tokens[++idx] : ""));
            break;
          }
          if (spec.shortValueChars.has(ch)) {
            if (!tail && idx + 1 < tokens.length) idx += 1;
            break;
          }
        }
        idx += 1;
        continue;
      }
      if (spec.positionalIfNoFlag?.test(flagName)) sawTasksetFlag = true;
      if (eqVal !== undefined) idx += 1;
      else idx += spec.valueFlags.some((re) => re.test(flagName)) ? 2 : 1;
      continue;
    }
    break;
  }
  return { cmdIndex: idx, envStartIdx, envVars, envCleared, unsetEnvVars, wrapperCwd, dynamicWrapperDir, viaXargs, psReplacedIndices, envSplitCmds, inlineSubCmd };
}

function classifyGitCommitLongFlag(flag) {
  if (/^--al(?:l)?$/.test(flag)) return "all";
  if (/^--am(?:e(?:n(?:d)?)?)?$/.test(flag)) return "amend";
  if (/^--in(?:c(?:l(?:u(?:d(?:e)?)?)?)?|t(?:e(?:r(?:a(?:c(?:t(?:i(?:ve?)?)?)?)?)?)?)?)?$/.test(flag)) return "partial";
  if (/^--on(?:l(?:y)?)?$/.test(flag)) return "partial";
  if (/^--pa(?:t(?:c(?:h)?)?)?$/.test(flag) && flag !== "--pa") return "partial";
  if (/^--pathspec-fi(?:l(?:e(?:-n(?:u(?:l)?)?)?)?)?$/.test(flag)) return "partial";
  if (/^--pathspec-fr(?:o(?:m(?:-f(?:i(?:l(?:e)?)?)?)?)?)?$/.test(flag)) return "partial_value";
  if (/^--(?:au(?:t(?:h(?:or?)?)?)?|cl(?:e(?:a(?:n(?:up?)?)?)?)?|da(?:te?)?|fi(?:le?)?|fix(?:up?)?|me(?:s(?:s(?:a(?:ge?)?)?)?)?|ree(?:d(?:i(?:t(?:-m(?:e(?:s(?:s(?:a(?:ge?)?)?)?)?)?)?)?)?)?|reu(?:s(?:e(?:-m(?:e(?:s(?:s(?:a(?:ge?)?)?)?)?)?)?)?)?|sq(?:u(?:a(?:sh?)?)?)?|te(?:m(?:p(?:l(?:a(?:te?)?)?)?)?)?|tr(?:a(?:i(?:l(?:er?)?)?)?)?)$/.test(flag)) {
    return "value";
  }
  if (/^--(?:no-(?:ed(?:it?)?|veri(?:fy?)?|post-r(?:e(?:w(?:r(?:i(?:te?)?)?)?)?)?|st(?:a(?:t(?:us?)?)?)?|sig(?:n(?:o(?:ff?)?)?)?|gpg-s(?:i(?:gn?)?)?|res(?:e(?:t(?:-a(?:u(?:t(?:h(?:or?)?)?)?)?)?)?)?|ahead-b(?:e(?:h(?:i(?:nd?)?)?)?)?)|allow-e(?:m(?:p(?:t(?:y(?:-m(?:e(?:s(?:s(?:a(?:ge?)?)?)?)?)?)?)?)?)?)?|ahead-b(?:e(?:h(?:i(?:nd?)?)?)?)?|br(?:a(?:n(?:ch?)?)?)?|dry(?:-r(?:u(?:n)?)?)?|ed(?:it?)?|gp(?:g(?:-s(?:i(?:gn?)?)?)?)?|lo(?:ng?)?|nu(?:ll?)?|por(?:c(?:e(?:l(?:a(?:in?)?)?)?)?)?|qu(?:i(?:et?)?)?|res(?:e(?:t(?:-a(?:u(?:t(?:h(?:or?)?)?)?)?)?)?)?|sh(?:o(?:rt?)?)?|sig(?:n(?:o(?:ff?)?)?)?|st(?:a(?:t(?:us?)?)?)?|untr(?:a(?:c(?:k(?:e(?:d(?:-f(?:i(?:l(?:es?)?)?)?)?)?)?)?)?)?|verb(?:o(?:se?)?)?|veri(?:fy?)?|ze(?:ro?)?)$/.test(flag)) {
    return "safe";
  }
  return "unknown";
}

export function parseGitCommitArgs(restTokens) {
  let hasAll = false;
  let hasAmend = false;
  let hasPathspecOrPartial = false;
  let unknownOption;
  for (let i = 0; i < restTokens.length; i += 1) {
    const tok = restTokens[i];
    if (tok === "--") { if (i + 1 < restTokens.length) hasPathspecOrPartial = true; break; }
    if (tok.startsWith("--")) {
      const eq = tok.indexOf("=");
      const flag = eq >= 0 ? tok.slice(0, eq) : tok;
      const kind = classifyGitCommitLongFlag(flag);
      if (kind === "all") hasAll = true;
      else if (kind === "amend") hasAmend = true;
      else if (kind === "partial") hasPathspecOrPartial = true;
      else if (kind === "partial_value") { hasPathspecOrPartial = true; if (eq < 0) i += 1; }
      else if (kind === "value") { if (eq < 0) i += 1; }
      else if (kind === "unknown") unknownOption = flag;
      continue;
    }
    if (tok.startsWith("-") && tok.length > 1) {
      for (let k = 1; k < tok.length; k += 1) {
        const ch = tok[k];
        if (ch === "a") hasAll = true;
        else if (ch === "p") hasPathspecOrPartial = true;
        else if (GIT_COMMIT_SHORT_VALUE_CHARS.has(ch)) { if (k === tok.length - 1) i += 1; break; }
      }
      continue;
    }
    hasPathspecOrPartial = true;
  }
  return { hasAll, hasAmend, hasPathspecOrPartial, unknownOption };
}

export function parseGhPrCreateArgs(tokens, startIdx) {
  let baseOpt;
  let headOpt;
  const positional = [];
  for (let i = startIdx + 1; i < tokens.length; i += 1) {
    const tok = tokens[i];
    if ((tok === "--base" || tok === "-B") && i + 1 < tokens.length) baseOpt = tokens[++i];
    else if (tok.startsWith("--base=")) baseOpt = tok.slice("--base=".length);
    else if (tok.startsWith("-B") && tok.length > 2) baseOpt = tok.slice(2);
    else if ((tok === "--head" || tok === "-H") && i + 1 < tokens.length) headOpt = tokens[++i];
    else if (tok.startsWith("--head=")) headOpt = tok.slice("--head=".length);
    else if (tok.startsWith("-H") && tok.length > 2) headOpt = tok.slice(2);
    else if (GH_VALUE_FLAGS.has(tok)) i += 1;
    else if (!tok.startsWith("-")) positional.push(tok);
  }
  return positional[0] === "pr" && positional[1] === "create" ? { baseOpt, headOpt } : undefined;
}

export function parseGitGlobalFlags(tokens, cmdIndex, initialCwd, envVars) {
  let targetCwd = initialCwd;
  let rawGitDir = envVars.GIT_DIR ?? envVars.git_dir;
  let rawWorkTree = envVars.GIT_WORK_TREE ?? envVars.git_work_tree;
  let hasExplicitWorkTree = Boolean(rawWorkTree);
  let dynamicGitPath = Boolean((rawGitDir && isDynamicPath(rawGitDir)) || (rawWorkTree && isDynamicPath(rawWorkTree)));
  let suspiciousConfig = false;

  let i = cmdIndex + 1;
  while (i < tokens.length && tokens[i].startsWith("-")) {
    const flag = tokens[i];
    const eq = flag.indexOf("=");
    const flagName = eq >= 0 ? flag.slice(0, eq) : flag;
    const val = eq >= 0 ? flag.slice(eq + 1) : undefined;

    if (flagName === "-C") {
      const dir = val ?? (i + 1 < tokens.length ? tokens[++i] : undefined);
      if (isDynamicPath(dir)) dynamicGitPath = true;
      else targetCwd = resolve(targetCwd, dir);
    } else if (flag.startsWith("-C") && flag.length > 2) {
      const dir = flag.slice(2);
      if (isDynamicPath(dir)) dynamicGitPath = true;
      else targetCwd = resolve(targetCwd, dir);
    } else if (flagName === "--git-dir") {
      const dir = val ?? (i + 1 < tokens.length ? tokens[++i] : undefined);
      if (isDynamicPath(dir)) dynamicGitPath = true;
      else rawGitDir = dir;
    } else if (flagName === "--work-tree") {
      const dir = val ?? (i + 1 < tokens.length ? tokens[++i] : undefined);
      if (isDynamicPath(dir)) dynamicGitPath = true;
      else { rawWorkTree = dir; hasExplicitWorkTree = true; }
    } else if (flagName === "-c" || (flag.startsWith("-c") && flag.length > 2)) {
      const cfg = flagName === "-c" ? (val ?? (i + 1 < tokens.length ? tokens[++i] : "")) : flag.slice(2);
      if (SENSITIVE_GIT_CFG_RE.test(cfg.trim())) suspiciousConfig = true;
    } else if (flagName === "--config-env" || flagName === "--exec-path") {
      if (eq < 0 && i + 1 < tokens.length) i += 1;
      suspiciousConfig = true;
    } else if (eq < 0 && GIT_GLOBAL_VALUE_FLAGS.has(flagName) && i + 1 < tokens.length) {
      i += 1;
    }
    i += 1;
  }

  const gitDiscoveryCwd = targetCwd;
  const finalCwd = rawWorkTree && !dynamicGitPath ? resolve(targetCwd, rawWorkTree) : targetCwd;
  const finalGitDir = rawGitDir && !dynamicGitPath ? resolve(targetCwd, rawGitDir) : undefined;
  return { subIdx: i, targetCwd: finalCwd, gitDiscoveryCwd, gitDir: finalGitDir, hasExplicitWorkTree, dynamicGitPath, suspiciousConfig };
}

const GIT_CFG_READ_FLAGS = new Set(["--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l"]);
const GIT_CFG_WRITE_FLAGS = new Set(["--add", "--replace-all", "--unset", "--unset-all", "--rename-section", "--remove-section", "--edit", "-e", "--file", "-f"]);

export function isReadOnlyGitConfig(restTokens) {
  let sawRead = false;
  let posCount = 0;
  for (let i = 0; i < restTokens.length; i += 1) {
    const t = restTokens[i];
    if (GIT_CFG_WRITE_FLAGS.has(t)) return false;
    if (GIT_CFG_READ_FLAGS.has(t)) { sawRead = true; continue; }
    if (t.startsWith("-")) continue;
    posCount += 1;
  }
  return sawRead && posCount <= 1;
}
