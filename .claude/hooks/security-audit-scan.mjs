// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Dual-dialect command plan analyzer for git commit / gh pr create security auditing.
import { resolve } from "node:path";
import {
  BASH_ASSIGN_BUILTINS,
  PS_DRIVE_RE,
  PS_ENV_COMMANDS,
  PS_ENV_PROVIDER_CMDS,
  applyScopeOffset,
  handleEnvDecl,
  hasLeftConditionalScope,
  hasSensitiveDynamicArgs,
  isBenignPsVarSegment,
  isPsEnvWriteSegment,
  markConditionalScope,
  parseDirChangeArgs,
  parsePsEnvCommandArgs,
  resolveChildGitEnv,
  updateBashCtrlStack,
} from "./security-audit-env.mjs";
import {
  MUTATING_COMMANDS,
  MUTATING_GIT_SUBCOMMANDS,
  NESTED_SHELL_NAMES,
  SENSITIVE_GIT_CFG_RE,
  SENSITIVE_GIT_ENV_RE,
  SENSITIVE_GIT_TEXT_RE,
  commandBaseName,
  isDynamicPath,
  isDynamicShellExpr,
  isReadOnlyGitConfig,
  parseCommandEnvelope,
  parseGhPrCreateArgs,
  parseGitCommitArgs,
  parseGitGlobalFlags,
  quoteTokensForDialect,
} from "./security-audit-flags.mjs";
import { printableText } from "./security-audit-git.mjs";
import {
  extractNestedShellCommand,
  parseEvalIexCommand,
  parseStartProcessCommand,
  splitCmdSlashToken,
} from "./security-audit-nested.mjs";
import { extractShellSegments, tokenizeDialect, tokenizeSegmentMeta } from "./security-audit-shell.mjs";

const MAX_SHELL_DEPTH = 6;
const PS_ONLY_DIR_CMDS = new Set(["push-location", "set-location", "sl", "pop-location"]);

function analyzeDialect(command, initialCwd, dialect) {
  const state = {
    cwdStack: [resolve(initialCwd)], dirStackByDepth: [[]], condDirByDepth: new Map(),
    gitDirStack: [undefined], workTreeStack: [undefined], condEnvByDepth: new Map(),
    envTickByDepth: new Map(), psEnvDriveStack: [false], psVirtualDrive: false,
    bashCtrlStack: [], nextBashCtrlId: 1, braceScopes: [], nextEvalCondOffset: 100000,
    sawMutation: false, sawGitAdd: false, dynamicDir: false, sawBashVarAssign: false,
    sensitiveGitEnv: false, sawPsCondBlock: false, sawOutsidePsCond: false, sawNestedBash: false,
    actions: [], errors: [],
  };
  const topCwd = () => state.cwdStack[state.cwdStack.length - 1];
  const topDirStack = () => state.dirStackByDepth[state.dirStackByDepth.length - 1];
  const topGitDir = () => state.gitDirStack[state.gitDirStack.length - 1];
  const topWorkTree = () => state.workTreeStack[state.workTreeStack.length - 1];

  function visit(cmdText, depth = 0, { childInitialCwd, fromCmd = false, scopeOffset, inheritedEnv } = {}) {
    if (depth > MAX_SHELL_DEPTH) { state.errors.push("security-audit: command nesting exceeded safety limit."); return; }
    const saved = childInitialCwd !== undefined ? {
      cwdStack: [...state.cwdStack], dirStack: state.dirStackByDepth.map((s) => [...s]),
      condDirs: new Map(state.condDirByDepth), gitDirStack: [...state.gitDirStack],
      workTreeStack: [...state.workTreeStack], condEnvs: new Map(state.condEnvByDepth),
      psEnv: [...state.psEnvDriveStack], psVirt: state.psVirtualDrive,
      bashCtrl: state.bashCtrlStack.map((b) => ({ ...b })), braceScopes: [...state.braceScopes],
    } : undefined;
    const entryDepth = scopeOffset?.baseSubshellDepth ?? 0;
    const beforeEnvTick = state.envTickByDepth.get(entryDepth) ?? 0;
    const savedScopeEnv = !saved && scopeOffset?.hasInlinePrefixEnv ? { gitDir: topGitDir(), workTree: topWorkTree() } : undefined;
    if (childInitialCwd !== undefined) {
      state.cwdStack = [resolve(childInitialCwd)];
      state.dirStackByDepth = [[]];
      state.condDirByDepth = new Map();
      state.gitDirStack = [inheritedEnv?.gitDir];
      state.workTreeStack = [inheritedEnv?.workTree];
      state.condEnvByDepth = new Map();
      state.psEnvDriveStack = [false];
      state.psVirtualDrive = false;
      state.bashCtrlStack = [];
      state.braceScopes = [];
    } else if (savedScopeEnv && inheritedEnv) {
      state.gitDirStack[state.gitDirStack.length - 1] = inheritedEnv.gitDir;
      state.workTreeStack[state.workTreeStack.length - 1] = inheritedEnv.workTree;
    }
    const evalCondOffset = scopeOffset ? (state.nextEvalCondOffset += 100000) : 0;
    try {
      for (const rawItem of extractShellSegments(cmdText, dialect, depth)) {
        const item = applyScopeOffset(rawItem, scopeOffset, evalCondOffset);
        if (item.unclosedConstruct) { state.errors.push(`security-audit: ${item.unclosedConstruct}; failing closed.`); return; }
        if (item.hasRedirection) state.sawMutation = true;
        if (dialect === "powershell") {
          if (item.inPsCond) state.sawPsCondBlock = true;
          else if (item.condBlockTag === 0) state.sawOutsidePsCond = true;
        }

        while (state.braceScopes.length > 0 && item.braceDepth < state.braceScopes[state.braceScopes.length - 1].enterBraceDepth) {
          const scope = state.braceScopes.pop();
          state.cwdStack = scope.savedCwdStack; state.dirStackByDepth = scope.savedDirStack;
          state.condDirByDepth = scope.savedCondDirs; state.gitDirStack = scope.savedGitDirStack;
          state.workTreeStack = scope.savedWorkTreeStack; state.condEnvByDepth = scope.savedCondEnvs;
          state.psEnvDriveStack = scope.savedPsEnvDriveStack; state.psVirtualDrive = scope.savedPsVirtualDrive;
          state.dynamicDir = scope.savedDynamicDir;
        }
        while (state.cwdStack.length > item.subshellDepth + 1) {
          const poppedDepth = state.cwdStack.length - 1;
          state.condDirByDepth.delete(poppedDepth); state.condEnvByDepth.delete(poppedDepth);
          state.cwdStack.pop(); state.dirStackByDepth.pop(); state.gitDirStack.pop(); state.workTreeStack.pop(); state.psEnvDriveStack.pop();
          while (state.bashCtrlStack.length > 0 && state.bashCtrlStack[state.bashCtrlStack.length - 1].subshellDepth >= poppedDepth) {
            state.bashCtrlStack.pop();
          }
        }
        while (state.cwdStack.length < item.subshellDepth + 1) {
          state.cwdStack.push(topCwd()); state.dirStackByDepth.push([...topDirStack()]);
          state.gitDirStack.push(topGitDir()); state.workTreeStack.push(topWorkTree());
          state.psEnvDriveStack.push(state.psEnvDriveStack[state.psEnvDriveStack.length - 1]);
        }

        const { tokens, braceExpandFlags, parenExprFlags, dynamicSubstFlags, dynamicVarFlags, quotedOrEscapedFlags, commaSplits } = tokenizeSegmentMeta(item.segment, dialect);
        if (tokens.length === 0) continue;
        if (dialect === "bash") updateBashCtrlStack(tokens, item, state, quotedOrEscapedFlags);
        if (hasLeftConditionalScope(state.condDirByDepth, state, item)) state.dynamicDir = true;
        if (hasLeftConditionalScope(state.condEnvByDepth, state, item)) state.sensitiveGitEnv = true;

        const env = parseCommandEnvelope(tokens, topCwd(), dialect);
        const { cmdIndex, envStartIdx, envVars, envCleared, unsetEnvVars, wrapperCwd, dynamicWrapperDir, viaXargs, psReplacedIndices, envSplitCmds, inlineSubCmd } = env;
        if (cmdIndex < tokens.length) {
          const slashParts = splitCmdSlashToken(tokens[cmdIndex]);
          if (slashParts) {
            tokens.splice(cmdIndex, 1, ...slashParts);
            const pad = Array(slashParts.length - 1).fill(false);
            braceExpandFlags.splice(cmdIndex + 1, 0, ...pad);
            parenExprFlags.splice(cmdIndex + 1, 0, ...pad);
            dynamicSubstFlags.splice(cmdIndex + 1, 0, ...pad);
            dynamicVarFlags.splice(cmdIndex + 1, 0, ...pad);
            quotedOrEscapedFlags.splice(cmdIndex + 1, 0, ...pad);
            commaSplits.splice(cmdIndex + 1, 0, ...Array(slashParts.length - 1).fill({ sawUnquotedComma: false, endsUnquotedComma: false, startsUnquotedComma: false, parts: [] }));
          }
        }
        const hasCoprocPrefix = dialect === "bash" && tokens.slice(0, cmdIndex).some((t) => t.toLowerCase() === "coproc");
        const activeBash = dialect === "bash" ? state.bashCtrlStack[state.bashCtrlStack.length - 1] : undefined;
        for (const rIdx of psReplacedIndices) {
          if (rIdx < tokens.length) dynamicVarFlags[rIdx] = isDynamicShellExpr(tokens[rIdx]);
        }

        for (const [k, v] of Object.entries(envVars)) {
          state.sawBashVarAssign = true;
          if (SENSITIVE_GIT_ENV_RE.test(k)) state.sensitiveGitEnv = true;
          const upper = k.toUpperCase();
          if (upper === "GIT_DIR" || upper === "GIT_WORK_TREE") {
            if (isDynamicPath(v)) state.dynamicDir = true;
            else if (cmdIndex >= tokens.length) {
              markConditionalScope(state.condEnvByDepth, item, activeBash, hasCoprocPrefix);
              state.sensitiveGitEnv = true;
            }
          }
        }

        const psEnvMatch = cmdIndex === envStartIdx && cmdIndex < tokens.length ? tokens[cmdIndex].match(/^\$env:([A-Za-z_][\w]*)(?:=([\s\S]*))?$/i) : null;
        const isPsEnvAssign = Boolean(psEnvMatch && (psEnvMatch[2] !== undefined || tokens[cmdIndex + 1] === "="));
        const headLimit = Math.min(cmdIndex + 1, tokens.length);
        const varHeadSlice = isPsEnvAssign ? [] : dynamicVarFlags.slice(envStartIdx, headLimit);
        const expectedAssignTokens = psEnvMatch && psEnvMatch[2] !== undefined ? 1 : 3;
        const rhsDyn =
          isPsEnvAssign &&
          (tokens.length > cmdIndex + expectedAssignTokens ||
            (psEnvMatch[2] !== undefined && isDynamicShellExpr(psEnvMatch[2])) ||
            braceExpandFlags.slice(cmdIndex + 1).some(Boolean) ||
            parenExprFlags.slice(cmdIndex + 1).some(Boolean) ||
            dynamicSubstFlags.slice(cmdIndex + 1).some(Boolean) ||
            dynamicVarFlags.slice(cmdIndex + 1).some(Boolean));
        const badHead =
          braceExpandFlags.slice(0, headLimit).some(Boolean) ||
          parenExprFlags.slice(0, headLimit).some(Boolean) ||
          dynamicSubstFlags.slice(0, headLimit).some(Boolean) ||
          rhsDyn ||
          (varHeadSlice.some(Boolean) && !isBenignPsVarSegment(tokens, envStartIdx, cmdIndex, state, item));
        if (badHead) {
          state.errors.push("security-audit: cannot verify command with unquoted brace expansion or dynamic expression.");
          continue;
        }
        if (dialect === "powershell" && /SetEnvironmentVariable/i.test(item.segment)) {
          state.sensitiveGitEnv = true;
        }
        if (dialect === "powershell" && /\[(?:[\w.]*\.)?ScriptBlock\]::Create\b/i.test(item.segment)) {
          state.errors.push("security-audit: cannot verify dynamic PowerShell ScriptBlock::Create invocation.");
          continue;
        }

        const effectiveEnv = resolveChildGitEnv(envVars, envCleared, unsetEnvVars, wrapperCwd, state);
        if (effectiveEnv.dynamic) state.dynamicDir = true;

        if (envSplitCmds.length > 0) {
          if (dynamicWrapperDir || envSplitCmds.some(isDynamicShellExpr)) {
            state.errors.push("security-audit: cannot verify dynamic env -S command.");
            continue;
          }
          const splitTokens = envSplitCmds.flatMap((sc) => tokenizeDialect(sc, dialect));
          if (splitTokens.some((t) => t === "-S" || t.startsWith("--split-string") || /^-S./.test(t))) {
            state.errors.push("security-audit: nested env -S cannot be verified.");
            continue;
          }
          const envAssigns = Object.entries(envVars).map(([k, v]) => `${k}=${v}`);
          visit(quoteTokensForDialect(["env", ...envAssigns, ...splitTokens, ...tokens.slice(cmdIndex)], dialect === "powershell"), depth + 1, { childInitialCwd: wrapperCwd, fromCmd, inheritedEnv: effectiveEnv });
          continue;
        }
        if (inlineSubCmd !== undefined) {
          if (isDynamicShellExpr(inlineSubCmd)) state.errors.push("security-audit: cannot verify dynamic wrapped -c command.");
          else visit(inlineSubCmd, depth + 1, { childInitialCwd: wrapperCwd, fromCmd, inheritedEnv: effectiveEnv });
          continue;
        }
        if (cmdIndex >= tokens.length) continue;

        const base = commandBaseName(tokens[cmdIndex].replace(dialect === "powershell" ? /^[&.]+/ : /^&+/, ""));
        if (viaXargs && (base === "git" || base === "gh" || NESTED_SHELL_NAMES.has(base) || ["eval", "iex", "invoke-expression"].includes(base))) {
          state.errors.push("security-audit: cannot verify xargs-invoked command with stdin-controlled arguments.");
          continue;
        }
        if (
          !isPsEnvAssign &&
          (hasSensitiveDynamicArgs(base, braceExpandFlags) ||
            hasSensitiveDynamicArgs(base, parenExprFlags) ||
            hasSensitiveDynamicArgs(base, dynamicSubstFlags) ||
            hasSensitiveDynamicArgs(base, dynamicVarFlags.slice(envStartIdx)))
        ) {
          state.errors.push("security-audit: cannot verify git/gh/shell command with unquoted brace expansion or dynamic expression.");
          continue;
        }

        if (BASH_ASSIGN_BUILTINS.has(base)) state.sawBashVarAssign = true;
        const isPsDialect = dialect === "powershell";
        const isBashDialect = dialect === "bash";
        const psParsed = isPsDialect && PS_ENV_COMMANDS.has(base) ? parsePsEnvCommandArgs(tokens, cmdIndex) : null;
        const inEnvNs = state.psEnvDriveStack[state.psEnvDriveStack.length - 1];
        const isPsEnvWrite = isPsDialect && isPsEnvWriteSegment(base, tokens, psParsed, inEnvNs);
        const isBashEnvExport = isBashDialect && ["export", "declare", "typeset", "local", "readonly", "unset"].includes(base);
        const isCmdSet = fromCmd && base === "set" && tokens.slice(cmdIndex + 1).some((t) => /=/.test(t) || /^(?:GIT_DIR|GIT_WORK_TREE)$/i.test(t) || SENSITIVE_GIT_TEXT_RE.test(t));
        if (isBashEnvExport || (isPsDialect && (isPsEnvWrite || isPsEnvAssign)) || isCmdSet) {
          handleEnvDecl(tokens, cmdIndex, state, item, activeBash, hasCoprocPrefix, markConditionalScope);
          continue;
        }
        if (isPsEnvAssign) continue;
        if (isPsDialect && PS_ENV_COMMANDS.has(base)) {
          if (PS_ENV_PROVIDER_CMDS.has(base)) state.sawMutation = true;
          continue;
        }
        if (BASH_ASSIGN_BUILTINS.has(base)) {
          if ((base === "for" || base === "select") && tokens.slice(cmdIndex + 1).some((t) => SENSITIVE_GIT_TEXT_RE.test(t))) {
            state.sensitiveGitEnv = true;
          }
          continue;
        }
        if (["cd", "chdir", "pushd", "push-location", "set-location", "sl"].includes(base)) {
          if (!isPsDialect && PS_ONLY_DIR_CMDS.has(base)) continue;
          const { dest, usedNamedStack, unknownFlag } = parseDirChangeArgs(tokens, cmdIndex, dialect, fromCmd);
          markConditionalScope(state.condDirByDepth, item, activeBash, hasCoprocPrefix);
          const curInEnv = state.psEnvDriveStack[state.psEnvDriveStack.length - 1];
          if ((base === "pushd" || base === "push-location") && !usedNamedStack && !unknownFlag) {
            topDirStack().push({ cwd: topCwd(), inPsEnvDrive: curInEnv, psVirtualDrive: state.psVirtualDrive });
          }
          if (unknownFlag || usedNamedStack || (isBashDialect && base === "pushd" && typeof dest === "string" && /^[+-]\d+$/.test(dest))) {
            state.dynamicDir = true;
            continue;
          }
          if (isPsDialect && typeof dest === "string" && PS_DRIVE_RE.test(dest)) {
            state.psEnvDriveStack[state.psEnvDriveStack.length - 1] = /^env:(?:[\\/]|$)/i.test(dest);
            state.psVirtualDrive = true;
            continue;
          }
          if (isDynamicPath(dest)) state.dynamicDir = true;
          else {
            state.cwdStack[state.cwdStack.length - 1] = resolve(topCwd(), dest);
            state.psEnvDriveStack[state.psEnvDriveStack.length - 1] = false;
            state.psVirtualDrive = false;
          }
          continue;
        }
        if (base === "popd" || base === "pop-location") {
          if (!isPsDialect && PS_ONLY_DIR_CMDS.has(base)) continue;
          const { dest, usedNamedStack, unknownFlag } = parseDirChangeArgs(tokens, cmdIndex, dialect, fromCmd);
          markConditionalScope(state.condDirByDepth, item, activeBash, hasCoprocPrefix);
          if (dest !== undefined || unknownFlag || usedNamedStack || topDirStack().length === 0) state.dynamicDir = true;
          else {
            const popped = topDirStack().pop();
            state.cwdStack[state.cwdStack.length - 1] = popped.cwd;
            state.psEnvDriveStack[state.psEnvDriveStack.length - 1] = popped.inPsEnvDrive;
            state.psVirtualDrive = popped.psVirtualDrive;
          }
          continue;
        }
        if (isPsDialect && ["invoke-command", "icm", "start-threadjob"].includes(base)) {
          state.errors.push("security-audit: cannot verify PowerShell Invoke-Command or Start-ThreadJob execution.");
          continue;
        }
        if (isPsDialect && ["start-process", "saps", "start"].includes(base)) {
          const parsedSp = parseStartProcessCommand(tokens, cmdIndex, wrapperCwd, commaSplits);
          if (parsedSp.unparseable) state.errors.push("security-audit: cannot verify dynamic or unparseable Start-Process invocation.");
          else if (parsedSp.isMutation) state.sawMutation = true;
          else if (parsedSp.text) {
            visit(parsedSp.text, depth + 1, { childInitialCwd: parsedSp.nestedCwd ?? wrapperCwd, inheritedEnv: parsedSp.useNewEnv ? {} : effectiveEnv });
          }
          continue;
        }
        if (base === "eval" || base === "iex" || base === "invoke-expression") {
          const parsedEval = parseEvalIexCommand(base, tokens, cmdIndex, { pipedIn: item.pipedIn, hasInputRedir: item.hasInputRedir });
          if (parsedEval?.unparseable) state.errors.push("security-audit: cannot verify dynamic eval/Invoke-Expression command.");
          else if (parsedEval?.text) {
            const evalCondTag = item.sep === "&&" || item.sep === "||" || item.condBlockTag > 0
              ? (item.condBlockTag > 0 ? item.condBlockTag : (state.nextEvalCondOffset += 1))
              : 0;
            visit(parsedEval.text, depth + 1, {
              fromCmd,
              inheritedEnv: effectiveEnv,
              scopeOffset: {
                baseSubshellDepth: item.subshellDepth,
                baseBraceDepth: item.braceDepth,
                rootSep: item.sep,
                rootCondBlockTag: item.condBlockTag,
                evalCondTag,
                rootPipedOrBg: item.pipedIn || item.pipedOut || item.isBackground || hasCoprocPrefix,
                hasInlinePrefixEnv: Object.keys(envVars).length > 0 || envCleared || unsetEnvVars.size > 0,
              },
            });
          }
          continue;
        }
        if (NESTED_SHELL_NAMES.has(base)) {
          if (!["pwsh", "powershell", "cmd"].includes(base)) state.sawNestedBash = true;
          const nested = extractNestedShellCommand(base, tokens, cmdIndex, { baseCwd: wrapperCwd, pipedIn: item.pipedIn, hasInputRedir: item.hasInputRedir });
          if (nested?.unparseable) state.errors.push("security-audit: unparseable or dynamic nested shell command cannot be verified.");
          else if (nested?.text) visit(nested.text, depth + 1, { childInitialCwd: nested.nestedCwd ?? wrapperCwd, fromCmd: Boolean(nested.fromCmd), inheritedEnv: effectiveEnv });
          else if (nested?.pendingBraceCwd) {
            if (item.opensBrace) {
              state.braceScopes.push({
                enterBraceDepth: item.braceDepth + 1,
                savedCwdStack: [...state.cwdStack], savedDirStack: state.dirStackByDepth.map((s) => [...s]),
                savedCondDirs: new Map(state.condDirByDepth), savedGitDirStack: [...state.gitDirStack],
                savedWorkTreeStack: [...state.workTreeStack], savedCondEnvs: new Map(state.condEnvByDepth),
                savedPsEnvDriveStack: [...state.psEnvDriveStack], savedPsVirtualDrive: state.psVirtualDrive,
                savedDynamicDir: state.dynamicDir,
              });
              state.cwdStack = [resolve(nested.pendingBraceCwd)];
              state.dirStackByDepth = [[]];
              state.condDirByDepth = new Map();
              state.gitDirStack = [effectiveEnv.gitDir];
              state.workTreeStack = [effectiveEnv.workTree];
              state.condEnvByDepth = new Map();
              state.psEnvDriveStack = [false];
              state.psVirtualDrive = false;
            } else if (item.pipedIn || item.hasInputRedir) {
              state.errors.push("security-audit: unparseable or dynamic nested shell command cannot be verified.");
            }
          }
          continue;
        }
        if (MUTATING_COMMANDS.has(base)) { state.sawMutation = true; continue; }

        if (base === "git") {
          const mergedEnv = {
            ...(effectiveEnv.gitDir ? { GIT_DIR: effectiveEnv.gitDir } : {}),
            ...(effectiveEnv.workTree ? { GIT_WORK_TREE: effectiveEnv.workTree } : {}),
            ...envVars,
          };
          const parsedGit = parseGitGlobalFlags(tokens, cmdIndex, wrapperCwd, mergedEnv);
          if (parsedGit.subIdx >= tokens.length) continue;
          if (parsedGit.suspiciousConfig) {
            state.errors.push("security-audit: cannot verify git command with inline alias, include, hooksPath, exec-path, config-env, or worktree/bare override.");
            continue;
          }
          const sub = tokens[parsedGit.subIdx];
          if (sub === "config") {
            const cfgRest = tokens.slice(parsedGit.subIdx + 1);
            if (!isReadOnlyGitConfig(cfgRest)) {
              if (cfgRest.some((t) => SENSITIVE_GIT_CFG_RE.test(t.trim()))) {
                state.errors.push("security-audit: cannot verify git config modifying alias, include, hooksPath, or worktree settings.");
              }
              state.sawMutation = true;
            }
            continue;
          }
          if (MUTATING_GIT_SUBCOMMANDS.has(sub)) state.sawMutation = true;
          else if (sub === "add" || sub === "stage") state.sawGitAdd = true;
          else if (sub === "commit") {
            const commitArgs = parseGitCommitArgs(tokens.slice(parsedGit.subIdx + 1));
            if (commitArgs.unknownOption) {
              state.errors.push(`security-audit: cannot verify git commit with unrecognized option "${printableText(commitArgs.unknownOption, 64)}".`);
            } else if (state.dynamicDir || state.psVirtualDrive || dynamicWrapperDir || parsedGit.dynamicGitPath || state.sensitiveGitEnv || parsedGit.suspiciousConfig) {
              state.errors.push("security-audit: cannot verify git commit with dynamic directory, alias, or custom GIT_* override.");
            } else if (state.sawMutation) {
              state.errors.push("security-audit: cannot chain file-mutating commands or redirections with git commit in one invocation.");
            } else {
              state.actions.push({
                type: "commit", targetCwd: parsedGit.targetCwd, gitDiscoveryCwd: parsedGit.gitDiscoveryCwd,
                gitDir: parsedGit.gitDir, hasExplicitWorkTree: parsedGit.hasExplicitWorkTree,
                chainedAdd: state.sawGitAdd, ...commitArgs,
              });
            }
          }
          continue;
        }
        if (base === "gh") {
          const prArgs = parseGhPrCreateArgs(tokens, cmdIndex);
          if (prArgs) {
            const hasGitOverride =
              state.sensitiveGitEnv || effectiveEnv.gitDir || effectiveEnv.workTree ||
              Object.keys(envVars).some((k) => SENSITIVE_GIT_ENV_RE.test(k) || /^GIT_(?:DIR|WORK_TREE)$/i.test(k));
            if (hasGitOverride) state.errors.push("security-audit: cannot verify gh pr create with custom GIT_* environment override.");
            else if (state.dynamicDir || state.psVirtualDrive || dynamicWrapperDir) state.errors.push("security-audit: cannot verify gh pr create after dynamic directory change; run from repository root.");
            else if (state.sawMutation) state.errors.push("security-audit: cannot chain file-mutating commands or redirections with gh pr create in one invocation.");
            else state.actions.push({ type: "pr_create", targetCwd: wrapperCwd, ...prArgs });
          }
        }
      }
    } finally {
      if (saved !== undefined) {
        state.cwdStack = saved.cwdStack; state.dirStackByDepth = saved.dirStack;
        state.condDirByDepth = saved.condDirs; state.gitDirStack = saved.gitDirStack;
        state.workTreeStack = saved.workTreeStack; state.condEnvByDepth = saved.condEnvs;
        state.psEnvDriveStack = saved.psEnv; state.psVirtualDrive = saved.psVirt;
        state.bashCtrlStack = saved.bashCtrl; state.braceScopes = saved.braceScopes;
      } else if (savedScopeEnv && (state.envTickByDepth.get(entryDepth) ?? 0) === beforeEnvTick) {
        state.gitDirStack[state.gitDirStack.length - 1] = savedScopeEnv.gitDir;
        state.workTreeStack[state.workTreeStack.length - 1] = savedScopeEnv.workTree;
      }
    }
  }

  visit(command, 0);
  return {
    actions: state.actions, errors: state.errors,
    sawPsCondBlock: state.sawPsCondBlock, sawOutsidePsCond: state.sawOutsidePsCond, sawNestedBash: state.sawNestedBash,
  };
}

export function parseToolCommandPlan(command, initialCwd) {
  const bashPlan = analyzeDialect(command, initialCwd, "bash");
  const psPlan = analyzeDialect(command, initialCwd, "powershell");
  const actions = [];
  const seenAction = new Set();
  for (const act of [...bashPlan.actions, ...psPlan.actions]) {
    const key = JSON.stringify(act);
    if (!seenAction.has(key)) { seenAction.add(key); actions.push(act); }
  }
  const psBacktickOnly =
    psPlan.sawPsCondBlock &&
    !psPlan.sawOutsidePsCond &&
    !psPlan.sawNestedBash &&
    psPlan.errors.length === 0 &&
    bashPlan.errors.length > 0 &&
    bashPlan.errors.every((e) => e === "security-audit: unclosed backtick command substitution; failing closed.");
  const effectiveBashErrors = psBacktickOnly ? [] : bashPlan.errors;
  return { actions, errors: [...new Set([...effectiveBashErrors, ...psPlan.errors])] };
}
