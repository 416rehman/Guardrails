// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Nested shell (bash/pwsh/cmd) and eval/iex argument extractors for security-audit-scan.mjs.
import { posix, resolve } from "node:path";
import {
  MUTATING_COMMANDS,
  NESTED_SHELL_NAMES,
  PS_COMMON_VAL_FLAG_RE,
  commandBaseName,
  isDynamicPath,
  isDynamicShellExpr,
  quoteTokensForDialect,
} from "./security-audit-flags.mjs";

const BASH_NESTED_VALUE_FLAGS = new Set(["-o", "+o", "-O", "+O", "--rcfile", "--init-file"]);
const BASH_STDIN_DEV_RE = /^(?:\/dev\/stdin|\/dev\/fd\/\d+|\/proc\/(?:self|thread-self|\d+)\/fd\/\d+)$/;
const PS_CMD_RE = /^[-/]c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?(?::([\s\S]*))?$/i;
const PS_CWA_RE = /^[-/]c(?:wa|ommandw(?:i(?:t(?:h(?:a(?:r(?:gs?)?)?)?)?)?)?)(?::([\s\S]*))?$/i;
const PS_ENC_RE = /^[-/]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)?)?)?)?)?)?)?(?::([\s\S]*))?$/i;
const PS_FILE_RE = /^[-/]f(?:i(?:le?)?)?(?::([\s\S]*))?$/i;
const PS_WD_RE = /^[-/]w(?:d|o(?:r(?:k(?:i(?:n(?:g(?:d(?:i(?:r(?:e(?:c(?:t(?:o(?:r(?:y)?)?)?)?)?)?)?)?)?)?)?)?)?)?)(?::([\s\S]*))?$/i;
const PS_SWITCH_CLI_RE = /^[-/](?:nop(?:r(?:o(?:f(?:i(?:le?)?)?)?)?)?|noni(?:n(?:t(?:e(?:r(?:a(?:c(?:t(?:i(?:ve?)?)?)?)?)?)?)?)?)?|nol(?:o(?:go?)?)?|noe(?:x(?:it?)?)?|mta|sta|v(?:e(?:r(?:s(?:i(?:on?)?)?)?)?)?|h(?:e(?:lp?)?)?|\?)$/i;
const PS_VALUE_CLI_RE = /^[-/](?:ep|ex(?:e(?:c(?:u(?:t(?:i(?:o(?:n(?:p(?:o(?:l(?:i(?:cy?)?)?)?)?)?)?)?)?)?)?)?)?|w|wi(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:le?)?)?)?)?)?)?)?)?|i(?:f|nputf(?:o(?:r(?:m(?:at?)?)?)?)?)|o(?:f|utputf(?:o(?:r(?:m(?:at?)?)?)?)?)|se(?:t(?:t(?:i(?:n(?:g(?:s(?:f(?:i(?:le?)?)?)?)?)?)?)?)?)?|cu(?:s(?:t(?:o(?:m(?:p(?:i(?:p(?:e(?:n(?:a(?:me?)?)?)?)?)?)?)?)?)?)?)?|co(?:n(?:f(?:i(?:g(?:u(?:r(?:a(?:t(?:i(?:o(?:n(?:f(?:i(?:le?)?|n(?:a(?:me?)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?)(?::([\s\S]*))?$/i;
const STRICT_BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
export const CMD_SLASH_EXEC_RE = /^(cmd(?:\.exe|\.cmd)?|pwsh(?:\.exe)?|powershell(?:\.exe)?)(\/[\s\S]*)$/i;
const IEX_SWITCH_RE = /^-(?:v(?:e(?:r(?:b(?:o(?:se?)?)?)?)?)?|d(?:e(?:b(?:ug?)?)?)?|wh(?:a(?:t(?:if?)?)?)?|co(?:n(?:f(?:i(?:rm?)?)?)?)?|fo(?:r(?:ce?)?)?)$/i;
const SP_SWITCH_RE = /^-(?:no(?:n(?:e(?:w(?:w(?:i(?:n(?:d(?:ow?)?)?)?)?)?)?)?)?|wai(?:t)?|pa(?:s(?:s(?:t(?:h(?:ru?)?)?)?)?)?|vb|verbo(?:s(?:e)?)?|d(?:e(?:b(?:ug?)?)?)?)$/i;
const SP_USE_NEW_ENV_RE = /^-us(?:e(?:n(?:e(?:w(?:e(?:n(?:v(?:i(?:r(?:o(?:n(?:m(?:e(?:nt?)?)?)?)?)?)?)?)?)?)?)?)?)?)?$/i;
const SP_FILE_FLAG_RE = /^-f(?:i(?:l(?:e(?:p(?:a(?:th?)?)?)?)?)?)?(?::([\s\S]*))?$/i;
const SP_ARGS_FLAG_RE = /^-a(?:r(?:g(?:u(?:m(?:e(?:n(?:t(?:l(?:i(?:st?)?)?)?)?)?)?)?)?)?)?(?::([\s\S]*))?$/i;

function splitCmdTopSegments(rawText) {
  const segs = [];
  let cur = "";
  let inDq = false;
  for (let i = 0; i < rawText.length; i += 1) {
    const ch = rawText[i];
    const next = rawText[i + 1] ?? "";
    if (ch === '"') { inDq = !inDq; cur += ch; continue; }
    if (!inDq && ch === "^") {
      if (!next || next === '"') return null;
      cur += next;
      i += 1;
      continue;
    }
    if (!inDq && (ch === "&" || ch === "|" || ch === "\n" || ch === "(" || ch === ")")) {
      if (cur.trim()) segs.push(cur.trim());
      cur = "";
      if ((ch === "&" && next === "&") || (ch === "|" && next === "|")) i += 1;
      continue;
    }
    cur += !inDq && (ch === "," || ch === "=" || ch === ";") ? " " : ch;
  }
  if (inDq) return null;
  if (cur.trim()) segs.push(cur.trim());
  return segs;
}

export function splitCmdSlashToken(token) {
  const m = token.match(CMD_SLASH_EXEC_RE);
  if (!m) return null;
  const parts = m[2].split(/\/+/).filter(Boolean).map((p) => `/${p}`);
  return [m[1], ...parts];
}

function splitLeadingSlashCmd(seg) {
  const firstSpace = seg.search(/\s/);
  const head = firstSpace < 0 ? seg : seg.slice(0, firstSpace);
  const rest = firstSpace < 0 ? "" : seg.slice(firstSpace);
  const parts = splitCmdSlashToken(head);
  return parts ? `${parts.join(" ")}${rest}` : seg;
}

function normalizeCmdRest(rest) {
  if (rest.some((t) => /![^!\r\n]+!/.test(t) || /%[^%\r\n]+%/.test(t) || isDynamicShellExpr(t) || /(?:^|[^^])(?:\^\^)*\^"/.test(t))) return undefined;
  const rawSegs = splitCmdTopSegments(rest.join(" "));
  if (!rawSegs) return undefined;
  const rewritten = [];
  for (const seg of rawSegs) {
    if (/![^!\r\n]+!/.test(seg) || /%[^%\r\n]+%/.test(seg) || isDynamicShellExpr(seg)) return undefined;
    let s = seg;
    while (true) {
      const prev = s;
      s = s.replace(/^@+[\s;,=]*/, "").replace(/^call(?:[\s;,=]+|$)/i, "");
      if (s === prev) break;
    }
    s = splitLeadingSlashCmd(s);
    if (/^(?:for|if|start)\b/i.test(s)) return undefined;
    if (s) rewritten.push(s);
  }
  return rewritten.join(" ; ");
}

export function extractNestedShellCommand(base, tokens, startIdx, { baseCwd, pipedIn = false, hasInputRedir = false } = {}) {
  const isPs = base === "pwsh" || base === "powershell";
  const isCmd = base === "cmd";
  let nestedCwd;
  let sawEmptyPsCmd = false;
  let sawFile = false;
  let sawStdin = false;
  let expectRedirTarget = false;
  let afterDashDash = false;

  for (let i = startIdx + 1; i < tokens.length; i += 1) {
    const raw = tokens[i];
    const lower = raw.toLowerCase();
    if (expectRedirTarget) { expectRedirTarget = false; continue; }
    if (isPs) {
      const wdMatch = raw.match(PS_WD_RE);
      if (wdMatch) {
        const wdArg = wdMatch[1] !== undefined ? wdMatch[1] : tokens[++i];
        if (!wdArg || isDynamicPath(wdArg)) return { unparseable: true };
        nestedCwd = resolve(baseCwd, wdArg);
        continue;
      }
      const encMatch = raw.match(PS_ENC_RE);
      if (encMatch) {
        const rawB64 = encMatch[1] !== undefined ? encMatch[1] : tokens[i + 1];
        if (!rawB64 || !STRICT_BASE64_RE.test(rawB64)) return { unparseable: true };
        return { text: Buffer.from(rawB64, "base64").toString("utf16le"), nestedCwd };
      }
      const cwaMatch = raw.match(PS_CWA_RE);
      const cmdMatch = cwaMatch ? null : raw.match(PS_CMD_RE);
      if (cwaMatch || cmdMatch) {
        const inline = (cwaMatch ?? cmdMatch)[1];
        const rest = inline !== undefined && inline !== "" ? [inline, ...tokens.slice(i + 1)] : tokens.slice(i + 1);
        if (rest.length === 0) { sawEmptyPsCmd = true; continue; }
        if (!cwaMatch && rest.length === 1 && (rest[0] === "&" || rest[0] === ".")) { sawEmptyPsCmd = true; continue; }
        if (rest[0] === "-" || rest.some(isDynamicShellExpr)) return { unparseable: true };
        return { text: cwaMatch ? rest[0] : rest.join(" "), nestedCwd };
      }
      const fileMatch = raw.match(PS_FILE_RE);
      if (fileMatch) {
        const fileArg = fileMatch[1] !== undefined ? fileMatch[1] : tokens[++i];
        if (!fileArg || fileArg === "-" || isDynamicShellExpr(fileArg)) return { unparseable: true };
        sawFile = true;
        continue;
      }
      const valCliMatch = raw.match(PS_VALUE_CLI_RE);
      if (valCliMatch) {
        if (valCliMatch[1] === undefined) i += 1;
        continue;
      }
      if (PS_SWITCH_CLI_RE.test(raw)) continue;
      if (raw === "-") { sawStdin = true; continue; }
      if (/\.ps1$/i.test(raw) && !/[\s;|&$`()]/.test(raw)) { sawFile = true; continue; }
      if (raw.startsWith("-") || /^\/[A-Za-z]/.test(raw)) return { unparseable: true };
      const posRest = tokens.slice(i);
      if (posRest.length === 1 && (posRest[0] === "&" || posRest[0] === ".")) { sawEmptyPsCmd = true; continue; }
      if (posRest.some(isDynamicShellExpr)) return { unparseable: true };
      return { text: posRest.join(" "), nestedCwd };
    }
    if (isCmd) {
      const cmdMatch = lower.match(/^\/{1,2}([ck])([\s\S]*)$/);
      if (cmdMatch) {
        const tail = cmdMatch[2] ? raw.slice(raw.length - cmdMatch[2].length) : "";
        const rest = tail ? [tail, ...tokens.slice(i + 1)] : tokens.slice(i + 1);
        if (rest.length === 0) return { unparseable: true };
        const text = normalizeCmdRest(rest);
        return text === undefined ? { unparseable: true } : { text, fromCmd: true };
      }
      continue;
    }
    if (/^(?:\d*(?:<{1,3}|>{1,2}|<>|>[|&])|&>>?)$/.test(raw)) { expectRedirTarget = true; continue; }
    if (/^(?:\d*[<>]|<<|&>)/.test(raw)) continue;
    if (!afterDashDash) {
      if (raw === "--") { afterDashDash = true; continue; }
      if (BASH_NESTED_VALUE_FLAGS.has(raw)) { i += 1; continue; }
      if (raw.startsWith("--") || raw.startsWith("+")) continue;
      if (raw === "-") { sawStdin = true; continue; }
      if (raw.startsWith("-")) {
        let sawC = false;
        for (let k = 1; k < raw.length; k += 1) {
          const ch = raw[k];
          if (ch === "o" || ch === "O") { if (k === raw.length - 1 && i + 1 < tokens.length) i += 1; break; }
          if (ch === "s") sawStdin = true;
          if (ch === "c") sawC = true;
        }
        if (sawC) {
          let nextIdx = i + 1;
          if (tokens[nextIdx] === "--") nextIdx += 1;
          if (nextIdx >= tokens.length) return { unparseable: true };
          const arg = tokens[nextIdx];
          return isDynamicShellExpr(arg) ? { unparseable: true } : { text: arg, nestedCwd };
        }
        continue;
      }
    }
    if (raw === "-" || BASH_STDIN_DEV_RE.test(posix.normalize(raw))) { sawStdin = true; continue; }
    sawFile = true;
  }
  if (sawStdin || ((pipedIn || hasInputRedir) && !sawFile)) return { unparseable: true };
  if (isPs && (sawEmptyPsCmd || !sawFile)) return { pendingBraceCwd: nestedCwd ?? baseCwd };
  return undefined;
}

export function parseStartProcessCommand(tokens, cmdIndex, baseCwd, commaSplits = []) {
  let filePath;
  let nestedCwd;
  let useNewEnv = false;
  const argEntries = [];
  const pushCommaTokens = (firstEntry, idxRef) => {
    argEntries.push(firstEntry);
    while (idxRef.i + 1 < tokens.length) {
      const prevSplit = argEntries.length === 1 ? firstEntry.split : commaSplits[idxRef.i];
      if (!prevSplit?.endsUnquotedComma && !commaSplits[idxRef.i + 1]?.startsUnquotedComma) break;
      idxRef.i += 1;
      argEntries.push({ text: tokens[idxRef.i], split: commaSplits[idxRef.i] });
    }
  };
  for (let i = cmdIndex + 1; i < tokens.length; i += 1) {
    const raw = tokens[i];
    const cf = raw.match(PS_COMMON_VAL_FLAG_RE);
    if (cf) { if (cf[1] === undefined) i += 1; continue; }
    if (SP_SWITCH_RE.test(raw)) continue;
    if (SP_USE_NEW_ENV_RE.test(raw)) { useNewEnv = true; continue; }
    const wdM = raw.match(PS_WD_RE);
    if (wdM) {
      const wdArg = wdM[1] !== undefined ? wdM[1] : tokens[++i];
      if (!wdArg || isDynamicPath(wdArg)) return { unparseable: true };
      nestedCwd = resolve(baseCwd, wdArg);
      continue;
    }
    const fpM = raw.match(SP_FILE_FLAG_RE);
    if (fpM) { filePath = fpM[1] !== undefined ? fpM[1] : tokens[++i]; continue; }
    const alM = raw.match(SP_ARGS_FLAG_RE);
    if (alM) {
      if (alM[1] !== undefined) {
        if (!alM[1]) return { unparseable: true };
        const colonPos = raw.indexOf(":");
        const baseSplit = commaSplits[i];
        const parts = baseSplit?.parts ? [baseSplit.parts[0].slice(colonPos + 1), ...baseSplit.parts.slice(1)] : [alM[1]];
        const idxRef = { i };
        pushCommaTokens({ text: alM[1], split: baseSplit ? { ...baseSplit, parts } : undefined }, idxRef);
        i = idxRef.i;
      } else if (i + 1 < tokens.length) {
        const idxRef = { i: i + 1 };
        pushCommaTokens({ text: tokens[idxRef.i], split: commaSplits[idxRef.i] }, idxRef);
        i = idxRef.i;
      } else return { unparseable: true };
      continue;
    }
    if (raw.startsWith("-")) return { unparseable: true };
    if (filePath === undefined) filePath = raw;
    else {
      const idxRef = { i };
      pushCommaTokens({ text: raw, split: commaSplits[i] }, idxRef);
      i = idxRef.i;
    }
  }
  if (!filePath || isDynamicPath(filePath)) return { unparseable: true };
  const targetBase = commandBaseName(filePath);
  if (/\.(?:ps1|bat|cmd|sh|bash|zsh)$/i.test(filePath)) return { unparseable: true };
  if (targetBase !== "git" && targetBase !== "gh" && !NESTED_SHELL_NAMES.has(targetBase)) {
    return MUTATING_COMMANDS.has(targetBase) || targetBase ? { isMutation: true } : { unparseable: true };
  }
  if (argEntries.length === 0) return { text: quoteTokensForDialect([filePath], true), nestedCwd, useNewEnv };
  if (argEntries.length === 1 && !argEntries[0].split?.sawUnquotedComma) {
    const singleArg = argEntries[0].text;
    if (isDynamicShellExpr(singleArg)) return { unparseable: true };
    if (/\s/.test(singleArg)) return { text: `${quoteTokensForDialect([filePath], true)} ${singleArg}`, nestedCwd, useNewEnv };
    return { text: quoteTokensForDialect([filePath, singleArg], true), nestedCwd, useNewEnv };
  }
  const elems = argEntries.flatMap((e) => (e.split?.parts ? e.split.parts : [e.text]));
  for (let k = 0; k < elems.length; k += 1) {
    const el = elems[k];
    if (isDynamicShellExpr(el)) return { unparseable: true };
    if (/\s/.test(el) && !(k > 0 && /^(?:-m|--message|-c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)$/i.test(elems[k - 1]))) {
      return { unparseable: true };
    }
  }
  return { text: quoteTokensForDialect([filePath, ...elems], true), nestedCwd, useNewEnv };
}

export function parseEvalIexCommand(base, tokens, cmdIndex, { pipedIn = false, hasInputRedir = false } = {}) {
  if (base === "eval") {
    let idx = cmdIndex + 1;
    if (tokens[idx] === "--") idx += 1;
    else if (tokens[idx]?.startsWith("-")) return { unparseable: true };
    const rest = tokens.slice(idx);
    if (rest.some(isDynamicShellExpr)) return { unparseable: true };
    return rest.length > 0 ? { text: rest.join(" ") } : undefined;
  }
  if (pipedIn || hasInputRedir) return { unparseable: true };
  const args = [];
  for (let i = cmdIndex + 1; i < tokens.length; i += 1) {
    const raw = tokens[i];
    if (IEX_SWITCH_RE.test(raw)) continue;
    const vf = raw.match(PS_COMMON_VAL_FLAG_RE);
    if (vf) { if (vf[1] === undefined) i += 1; continue; }
    const cmdM = raw.match(PS_CMD_RE);
    if (cmdM) {
      const val = cmdM[1] !== undefined ? cmdM[1] : tokens[++i];
      if (!val || isDynamicShellExpr(val)) return { unparseable: true };
      args.push(val);
      continue;
    }
    if (raw.startsWith("-")) return { unparseable: true };
    args.push(raw);
  }
  if (args.some(isDynamicShellExpr)) return { unparseable: true };
  return args.length > 0 ? { text: args.join(" ") } : undefined;
}
