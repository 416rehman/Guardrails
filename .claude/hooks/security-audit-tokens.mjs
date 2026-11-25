// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Tokenization and line-continuation pre-pass for dual-dialect shell scanning.
import {
  BASH_HEREDOC_START_RE,
  consumeBashHereDocs,
  consumePowerShellHereString,
  decodeAnsiCEscapes,
  decodePsDoubleEscapes,
  isWordBoundaryBefore,
  readAnsiCQuoteEnd,
  scanBashDqParam,
} from "./security-audit-heredoc.mjs";

export function stripLineContinuations(text, dialect) {
  let out = "";
  let inSingle = false;
  let inDouble = false;
  const pendingHereDocs = [];
  const parenSubstStack = [];
  const paramScopes = [];
  let justClosedSubshell = false;
  const escChar = dialect === "powershell" ? "`" : "\\";

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1] ?? "";
    if (!inSingle && ch === escChar) {
      justClosedSubshell = false;
      if (next === "\r" && text[i + 2] === "\n") { i += 2; continue; }
      if (next === "\n") { i += 1; continue; }
      if (next) { out += ch + next; i += 1; continue; }
    }
    if (!inSingle && inDouble && dialect === "bash" && ch === "$" && next === "{") {
      justClosedSubshell = false;
      const dqParam = scanBashDqParam(text, i);
      if (!dqParam) { out += text.slice(i); break; }
      for (let k = i; k <= dqParam.endIdx; k += 1) {
        if (text[k] === "\\" && text[k + 1] === "\n") { k += 1; continue; }
        if (text[k] === "\\" && text[k + 1] === "\r" && text[k + 2] === "\n") { k += 2; continue; }
        out += text[k];
      }
      i = dqParam.endIdx;
      continue;
    }
    if (!inSingle && !inDouble && paramScopes.length > 0) {
      justClosedSubshell = false;
      if (dialect === "powershell") {
        if (ch === "}") paramScopes.pop();
        out += ch;
        continue;
      }
      if (ch === "$" && next === "'") {
        const endAnsi = readAnsiCQuoteEnd(text, i);
        if (endAnsi < 0) { out += text.slice(i); break; }
        out += text.slice(i, endAnsi + 1);
        i = endAnsi;
        continue;
      }
      if (ch === "'") { inSingle = true; out += ch; continue; }
      if (ch === '"') { inDouble = true; out += ch; continue; }
      if (ch === "{") { paramScopes.push({ innerDepth: 0 }); out += ch; continue; }
      if (ch === "}") { paramScopes.pop(); out += ch; continue; }
      out += ch;
      continue;
    }
    if (!inSingle && !inDouble) {
      if (dialect === "powershell" && text.startsWith("<#", i) && isWordBoundaryBefore(text, i, dialect)) {
        justClosedSubshell = false;
        const endBlock = text.indexOf("#>", i + 2);
        if (endBlock >= 0) { out += text.slice(i, endBlock + 2); i = endBlock + 1; continue; }
      }
      if (ch === "#" && (isWordBoundaryBefore(text, i, dialect) || (dialect === "bash" && justClosedSubshell))) {
        justClosedSubshell = false;
        const nl = text.indexOf("\n", i);
        if (nl < 0) { out += text.slice(i); break; }
        out += text.slice(i, nl);
        i = nl - 1;
        continue;
      }
      justClosedSubshell = false;
      if (dialect === "powershell" && ch === "@" && (next === "'" || next === '"') && (text[i + 2] === "\n" || (text[i + 2] === "\r" && text[i + 3] === "\n"))) {
        const here = consumePowerShellHereString(text, i + 2, next);
        if (here) { out += text.slice(i, here.endIdx + 1); i = here.endIdx; continue; }
      }
      if (dialect === "bash" && ch === "$" && next === "'") {
        const endAnsi = readAnsiCQuoteEnd(text, i);
        if (endAnsi < 0) { out += text.slice(i); break; }
        out += text.slice(i, endAnsi + 1);
        i = endAnsi;
        continue;
      }
      if (dialect === "bash" && ch === "$" && next === '"') { out += '$"'; inDouble = true; i += 1; continue; }
      if (ch === "$" && next === "{") { paramScopes.push({ innerDepth: 0 }); out += "${"; i += 1; continue; }
      if (dialect === "bash" && text.startsWith("<<<", i)) { out += "<<<"; i += 2; continue; }
      if (dialect === "bash" && ch === "<" && next === "<" && text[i + 2] !== "<") {
        const m = text.slice(i).match(BASH_HEREDOC_START_RE);
        if (m) {
          pendingHereDocs.push({ stripTabs: Boolean(m[1]), quoted: Boolean(m[2]), tag: m[3] || m[4] });
          out += m[0];
          i += m[0].length - 1;
          continue;
        }
      }
      if (ch === "(") { parenSubstStack.push(i > 0 && text[i - 1] === "$"); out += ch; continue; }
      if (ch === ")") { const wasSubst = parenSubstStack.pop() ?? false; if (!wasSubst) justClosedSubshell = true; out += ch; continue; }
    } else {
      justClosedSubshell = false;
    }
    if (!inSingle && !inDouble && dialect === "bash" && ch === "\n" && pendingHereDocs.length > 0) {
      const docs = consumeBashHereDocs(text, i, pendingHereDocs.splice(0));
      if (docs) { out += text.slice(i, docs.nextIdx + 1); i = docs.nextIdx; continue; }
    }
    if (!inDouble && ch === "'") {
      if (dialect === "powershell" && inSingle && next === "'") { out += "''"; i += 1; continue; }
      inSingle = !inSingle;
      out += ch;
      continue;
    }
    if (!inSingle && ch === '"') { inDouble = !inDouble; out += ch; continue; }
    out += ch;
  }
  return out;
}

export function tokenizeSegmentMeta(segment, dialect) {
  const tokens = [];
  const braceExpandFlags = [];
  const parenExprFlags = [];
  const dynamicSubstFlags = [];
  const dynamicVarFlags = [];
  const quotedOrEscapedFlags = [];
  const commaSplits = [];
  let cur = "";
  let quote = "";
  let hasToken = false;
  let curBraceExpand = false;
  let curParenExpr = false;
  let curDynamicSubst = false;
  let curDynamicVar = false;
  let curQuotedOrEscaped = false;
  let curParts = [];
  let curPart = "";
  let curPartHas = false;
  let sawUnquotedComma = false;
  let startsUnquotedComma = false;
  const braceStack = [];

  const appendPart = (text) => {
    cur += text;
    hasToken = true;
    curPart += text;
    curPartHas = true;
  };
  const pushCurrent = () => {
    if (!hasToken) return;
    if (dialect === "powershell" && cur.includes("__dyn_herestring__")) curDynamicVar = true;
    const endsUnquotedComma = sawUnquotedComma && !curPartHas;
    if (curPartHas) curParts.push(curPart);
    tokens.push(cur);
    braceExpandFlags.push(curBraceExpand);
    parenExprFlags.push(curParenExpr);
    dynamicSubstFlags.push(curDynamicSubst);
    dynamicVarFlags.push(curDynamicVar);
    quotedOrEscapedFlags.push(curQuotedOrEscaped);
    commaSplits.push({ sawUnquotedComma, endsUnquotedComma, startsUnquotedComma, parts: curParts });
    cur = ""; hasToken = false; curBraceExpand = false; curParenExpr = false;
    curDynamicSubst = false; curDynamicVar = false; curQuotedOrEscaped = false;
    curParts = []; curPart = ""; curPartHas = false; sawUnquotedComma = false; startsUnquotedComma = false;
    braceStack.length = 0;
  };

  for (let i = 0; i < segment.length; i += 1) {
    const ch = segment[i];
    const next = segment[i + 1] ?? "";
    if (quote) {
      if (dialect === "powershell" && quote === "'" && ch === "'" && next === "'") { appendPart("'"); i += 1; }
      else if (dialect === "powershell" && quote === '"' && ch === "`" && next) { appendPart(decodePsDoubleEscapes("`" + next)); i += 1; }
      else if (dialect === "bash" && quote === '"' && ch === "\\" && next === "\n") { i += 1; }
      else if (dialect === "bash" && quote === '"' && ch === "\\" && next === "\r" && segment[i + 2] === "\n") { i += 2; }
      else if (dialect === "bash" && quote === '"' && ch === "\\" && next && ['"', "\\", "$", "`"].includes(next)) { appendPart(next); i += 1; }
      else if (ch === quote) quote = "";
      else {
        if (quote === '"') {
          if (ch === "$" && next === "(") curDynamicSubst = true;
          else if (ch === "$" && /[A-Za-z0-9_{@*?!$-]/.test(next)) curDynamicVar = true;
          else if (dialect === "bash" && ch === "`") curDynamicSubst = true;
        }
        appendPart(ch);
      }
      continue;
    }
    if (dialect === "bash" && ch === "$" && next === "'") {
      const endAnsi = readAnsiCQuoteEnd(segment, i);
      if (endAnsi >= 0) {
        appendPart(decodeAnsiCEscapes(segment.slice(i + 2, endAnsi)));
        curQuotedOrEscaped = true; i = endAnsi; continue;
      }
    }
    if (dialect === "bash" && ch === "$" && next === '"') { quote = '"'; hasToken = true; curPartHas = true; curQuotedOrEscaped = true; i += 1; continue; }
    if (dialect === "powershell" && !hasToken && (ch === "&" || ch === ".") && (next === '"' || next === "'")) {
      tokens.push(ch); braceExpandFlags.push(false); parenExprFlags.push(false);
      dynamicSubstFlags.push(false); dynamicVarFlags.push(false); quotedOrEscapedFlags.push(false);
      commaSplits.push({ sawUnquotedComma: false, endsUnquotedComma: false, startsUnquotedComma: false, parts: [ch] });
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; hasToken = true; curPartHas = true; curQuotedOrEscaped = true; continue; }
    if (dialect === "bash" && ch === "\\") {
      if (next === "\n") { i += 1; continue; }
      if (next === "\r" && segment[i + 2] === "\n") { i += 2; continue; }
      if (next && !/^[A-Za-z]:/.test(cur)) { appendPart(next); curQuotedOrEscaped = true; i += 1; continue; }
    }
    if (dialect === "powershell" && ch === "`" && next) { appendPart(next); curQuotedOrEscaped = true; i += 1; continue; }
    if (/\s/.test(ch)) { pushCurrent(); continue; }
    if (dialect === "powershell" && ch === ",") {
      if (!hasToken) startsUnquotedComma = true;
      cur += ch; hasToken = true; sawUnquotedComma = true;
      if (curPartHas) { curParts.push(curPart); curPart = ""; curPartHas = false; }
      continue;
    }
    if (dialect === "powershell" && !hasToken && ch === "@" && /[A-Za-z_(]/.test(next)) curDynamicVar = true;
    if (ch === "$" && next === "(") curDynamicSubst = true;
    else if (ch === "$" && /[A-Za-z0-9_{@*?!$-]/.test(next)) curDynamicVar = true;
    else if (dialect === "bash" && ch === "`") curDynamicSubst = true;
    if (dialect === "bash") {
      if (ch === "{") braceStack.push({ isParam: segment[i - 1] === "$", hasOp: false });
      else if (braceStack.length > 0 && (ch === "," || (ch === "." && next === ".")) && !braceStack.some((b) => b.isParam)) braceStack[braceStack.length - 1].hasOp = true;
      else if (ch === "}" && braceStack.length > 0) { const top = braceStack.pop(); if (!top.isParam && top.hasOp) curBraceExpand = true; }
    } else if (dialect === "powershell" && ch === "(" && next !== ")") curParenExpr = true;
    appendPart(ch);
  }
  pushCurrent();
  return { tokens, braceExpandFlags, parenExprFlags, dynamicSubstFlags, dynamicVarFlags, quotedOrEscapedFlags, commaSplits };
}

export function tokenizeDialect(segment, dialect) {
  return tokenizeSegmentMeta(segment, dialect).tokens;
}
