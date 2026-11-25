// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Dual-dialect Bash and PowerShell segment lexer.
import { quoteTokensForDialect } from "./security-audit-flags.mjs";
import {
  BASH_HEREDOC_START_RE,
  consumeBashHereDocs,
  consumePowerShellHereString,
  decodePsDoubleEscapes,
  isStaticPowerShellStringLiteral,
  isWordBoundaryBefore,
  nextNonCommentChar,
  readAnsiCQuoteEnd,
  readBalancedParen,
  readClosingBacktick,
  scanBashDqParam,
  unescapeBashBacktickBody,
} from "./security-audit-heredoc.mjs";
import { stripLineContinuations, tokenizeDialect, tokenizeSegmentMeta } from "./security-audit-tokens.mjs";

export { tokenizeDialect, tokenizeSegmentMeta };

const MAX_SHELL_DEPTH = 6;
const PS_CONDITIONAL_KEYWORDS = new Set(["if", "elseif", "while", "for", "foreach", "switch", "catch", "until"]);
const BASH_BRACE_PREFIX_RE = /^(?:(?:!\s+|time(?:\s+-p)?\s+)*(?:!|time(?:\s+-p)?))$/;

function isPsBackgroundAmpersand(text, idx) {
  let j = idx + 1;
  while (j < text.length) {
    if (text[j] === " " || text[j] === "\t") { j += 1; continue; }
    if (text.startsWith("<#", j)) {
      const end = text.indexOf("#>", j + 2);
      if (end < 0) return false;
      j = end + 2;
      continue;
    }
    break;
  }
  return j >= text.length || ";\n\r|})".includes(text[j]);
}

function isBraceConditionalHeader(trimmed) {
  return (
    /^(?:try|else|finally)$/i.test(trimmed) ||
    /^(?:catch|trap)(?:\s*\[[^\]]+\]|\s|$)/i.test(trimmed) ||
    /^function\b/i.test(trimmed) ||
    /^[&.]$/.test(trimmed) ||
    /^(?:\[[\w.]+\]\s*)?\$[\w:.]+\s*=$/.test(trimmed)
  );
}

function makeSegment(segment, opts = {}) {
  return {
    segment,
    hasRedirection: opts.hasRedirection ?? false,
    subshellDepth: opts.subshellDepth ?? 0,
    pipedIn: opts.pipedIn ?? false,
    pipedOut: opts.pipedOut ?? false,
    isBackground: opts.isBackground ?? false,
    hasInputRedir: opts.hasInputRedir ?? false,
    inPsCond: opts.inPsCond ?? false,
    sep: opts.sep ?? "start",
    condBlockTag: opts.condBlockTag ?? 0,
    braceDepth: opts.braceDepth ?? 0,
    opensBrace: opts.opensBrace ?? false,
    ...(opts.unclosedConstruct ? { unclosedConstruct: opts.unclosedConstruct } : {}),
  };
}

function scanExpandableBody(body, dialect, out, appendNested, subshellOffset) {
  for (let i = 0; i < body.length; i += 1) {
    if (dialect === "powershell" && body[i] === "`" && i + 1 < body.length) { i += 1; continue; }
    if (dialect === "bash" && body[i] === "\\" && /[$\\`]/.test(body[i + 1] ?? "")) { i += 1; continue; }
    if (body[i] === "$" && body[i + 1] === "(") {
      const close = readBalancedParen(body, i + 1, dialect);
      if (close < 0) { out.push(makeSegment("", { unclosedConstruct: "unclosed command substitution in here-document" })); return; }
      appendNested(body.slice(i + 2, close), { subshellOffset });
      i = close;
    } else if (dialect === "bash" && body[i] === "`") {
      const endTick = readClosingBacktick(body, i);
      if (endTick < 0) { out.push(makeSegment("", { unclosedConstruct: "unclosed backtick command substitution in here-document" })); return; }
      appendNested(unescapeBashBacktickBody(body.slice(i + 1, endTick), true), { subshellOffset });
      i = endTick;
    }
  }
}

export function extractShellSegments(command, dialect, depth = 0) {
  if (depth > MAX_SHELL_DEPTH) {
    return [makeSegment("", { unclosedConstruct: "command substitution nesting exceeded safety limit", hasRedirection: true })];
  }
  const normalized = stripLineContinuations(command, dialect);
  const out = [];
  const esc = dialect === "powershell" ? "`" : "\\";
  const pendingHereDocs = [];
  const condDepths = [];
  const condBlocks = [];
  const paramScopes = [];
  const parenKindStack = [];
  const braceOutStarts = [];
  const pipedBraceDepths = [];
  let lastClosedBraceRange = null;
  let nextCondBlockId = 1;
  let braceDepth = 0;
  let justClosedCond = false;
  let justClosedSubshell = false;
  let cur = "";
  let quote = "";
  let hasRedir = false;
  let hasInputRedir = false;
  let subshellDepth = 0;
  let parenDepth = 0;
  let curPipedIn = false;
  let curSep = "start";

  const fail = (unclosedConstruct) => [
    makeSegment("", { unclosedConstruct, subshellDepth, pipedIn: curPipedIn, hasInputRedir, sep: curSep, braceDepth }),
  ];
  const appendNestedSegments = (innerText, { subshellOffset = subshellDepth, markInCond = false } = {}) => {
    const outerCondTag = condBlocks.length > 0 ? condBlocks[condBlocks.length - 1].id : 0;
    const outerPiped = curPipedIn || pipedBraceDepths.length > 0;
    const outerInPsCond = markInCond || condDepths.length > 0;
    for (const seg of extractShellSegments(innerText, dialect, depth + 1)) {
      if (seg.unclosedConstruct) { out.push(seg); return; }
      const nextTag = seg.condBlockTag > 0 ? nextCondBlockId + seg.condBlockTag : outerCondTag;
      out.push({
        ...seg,
        subshellDepth: seg.subshellDepth + subshellOffset,
        braceDepth: seg.braceDepth + braceDepth,
        condBlockTag: nextTag,
        inPsCond: seg.inPsCond || outerInPsCond,
        pipedIn: seg.pipedIn || outerPiped,
      });
    }
    nextCondBlockId += 1000;
  };
  const flush = (delta = 0, pipeNext = false, nextSep = curSep, { markPipedOut = false, isBg = false, opensBrace = false, opensPsCond = false, deltaParen = 0 } = {}) => {
    const inPsCond = opensPsCond || condDepths.length > 0;
    const condBlockTag = condBlocks.length > 0 ? condBlocks[condBlocks.length - 1].id : 0;
    const effectivePipedIn = curPipedIn || pipedBraceDepths.length > 0;
    if (cur.trim()) {
      out.push(makeSegment(cur.trim(), {
        hasRedirection: hasRedir, subshellDepth, pipedIn: effectivePipedIn, pipedOut: markPipedOut,
        isBackground: isBg, hasInputRedir, inPsCond, sep: curSep, condBlockTag, braceDepth, opensBrace,
      }));
    } else if (markPipedOut && out.length > 0) {
      out[out.length - 1].pipedOut = true;
    }
    cur = ""; hasRedir = false; hasInputRedir = false;
    subshellDepth = Math.max(0, subshellDepth + delta);
    parenDepth = Math.max(0, parenDepth + deltaParen);
    let poppedCond = false;
    while (condDepths.length > 0 && condDepths[condDepths.length - 1] > parenDepth) { condDepths.pop(); poppedCond = true; }
    if (deltaParen < 0 && poppedCond) justClosedCond = true;
    curPipedIn = pipeNext;
    curSep = nextSep;
  };

  for (let i = 0; i < normalized.length; i += 1) {
    const ch = normalized[i];
    const next = normalized[i + 1] ?? "";
    if (quote) {
      justClosedSubshell = false;
      if (dialect === "bash" && quote === '"' && ch === "$" && next === "{") {
        const dqParam = scanBashDqParam(normalized, i);
        if (!dqParam) return fail("unverified or unclosed ${...} inside double quotes");
        for (const [s, e] of dqParam.substRanges) appendNestedSegments(normalized.slice(s, e), { subshellOffset: subshellDepth + 1 });
        cur += normalized.slice(i, dqParam.endIdx + 1);
        i = dqParam.endIdx;
        continue;
      }
      if (quote === '"' && ch === "$" && next === "(") {
        const close = readBalancedParen(normalized, i + 1, dialect);
        if (close < 0) return fail("unclosed $(...) command substitution");
        appendNestedSegments(normalized.slice(i + 2, close), { subshellOffset: dialect === "bash" ? subshellDepth + 1 : subshellDepth });
        cur += normalized.slice(i, close + 1);
        i = close;
        continue;
      }
      if (dialect === "bash" && quote === '"' && ch === "`") {
        const endTick = readClosingBacktick(normalized, i);
        if (endTick < 0) return fail("unclosed backtick command substitution");
        appendNestedSegments(unescapeBashBacktickBody(normalized.slice(i + 1, endTick), true), { subshellOffset: subshellDepth + 1 });
        cur += normalized.slice(i, endTick + 1);
        i = endTick;
        continue;
      }
      cur += ch;
      if (quote === '"' && ch === esc && next) { cur += next; i += 1; }
      else if (dialect === "powershell" && quote === "'" && ch === "'" && next === "'") { cur += next; i += 1; }
      else if (ch === quote) quote = "";
      continue;
    }
    if (paramScopes.length > 0) {
      justClosedSubshell = false;
      if (dialect === "powershell") {
        if (ch === "`" && next) { cur += ch + next; i += 1; continue; }
        if (ch === "}") paramScopes.pop();
        cur += ch;
        continue;
      }
      if (ch === "\\" && next) { cur += ch + next; i += 1; continue; }
      if (ch === "$" && next === "'") {
        const endAnsi = readAnsiCQuoteEnd(normalized, i);
        if (endAnsi < 0) return fail("unclosed Bash $'...' quote");
        cur += normalized.slice(i, endAnsi + 1); i = endAnsi; continue;
      }
      if (ch === "$" && next === "(") {
        const close = readBalancedParen(normalized, i + 1, dialect);
        if (close < 0) return fail("unclosed $(...) command substitution");
        appendNestedSegments(normalized.slice(i + 2, close), { subshellOffset: subshellDepth + 1 });
        cur += normalized.slice(i, close + 1); i = close; continue;
      }
      if (ch === "`") {
        const endTick = readClosingBacktick(normalized, i);
        if (endTick < 0) return fail("unclosed backtick command substitution");
        appendNestedSegments(unescapeBashBacktickBody(normalized.slice(i + 1, endTick), false), { subshellOffset: subshellDepth + 1 });
        cur += normalized.slice(i, endTick + 1); i = endTick; continue;
      }
      if (ch === "'" || ch === '"') { quote = ch; cur += ch; continue; }
      if (ch === "{") { paramScopes.push({ innerDepth: 0 }); cur += ch; continue; }
      if (ch === "}") { paramScopes.pop(); cur += ch; continue; }
      if (ch === "(") { paramScopes[paramScopes.length - 1].innerDepth += 1; cur += ch; continue; }
      if (ch === ")") { const pTop = paramScopes[paramScopes.length - 1]; if (pTop.innerDepth > 0) pTop.innerDepth -= 1; cur += ch; continue; }
      cur += ch;
      continue;
    }
    if (dialect === "powershell" && normalized.startsWith("<#", i) && isWordBoundaryBefore(normalized, i, dialect)) {
      justClosedSubshell = false;
      const endBlock = normalized.indexOf("#>", i + 2);
      if (endBlock < 0) return fail("unclosed PowerShell <# ... #> block comment");
      i = endBlock + 1;
      continue;
    }
    if (ch === "#" && (isWordBoundaryBefore(normalized, i, dialect) || (dialect === "bash" && justClosedSubshell))) {
      justClosedSubshell = false;
      const nl = normalized.indexOf("\n", i);
      if (nl < 0) break;
      i = nl - 1;
      continue;
    }
    justClosedSubshell = false;
    if (!/\s/.test(ch) && ch !== "{") justClosedCond = false;
    if (dialect === "powershell" && ch === "@" && (next === "'" || next === '"') && (normalized[i + 2] === "\n" || (normalized[i + 2] === "\r" && normalized[i + 3] === "\n"))) {
      const here = consumePowerShellHereString(normalized, i + 2, next);
      if (!here) return fail("unclosed PowerShell here-string");
      const hasDyn = next === '"' && /(?:^|[^`])(?:``)*\$(?:[A-Za-z0-9_{(@*?!$-])/.test(here.body);
      if (hasDyn) { scanExpandableBody(here.body, dialect, out, appendNestedSegments, subshellDepth); cur += "__dyn_herestring__"; }
      else cur += quoteTokensForDialect([next === '"' ? decodePsDoubleEscapes(here.body) : here.body], true);
      i = here.endIdx;
      continue;
    }
    if (dialect === "bash" && normalized.startsWith("<<<", i)) { hasInputRedir = true; cur += "<<<"; i += 2; continue; }
    if (dialect === "bash" && ch === "<" && next === "<" && normalized[i + 2] !== "<") {
      const m = normalized.slice(i).match(BASH_HEREDOC_START_RE);
      if (!m) return fail("unparseable or dynamic Bash here-document");
      pendingHereDocs.push({ stripTabs: Boolean(m[1]), quoted: Boolean(m[2]), tag: m[3] || m[4] });
      hasInputRedir = true;
      cur += m[0];
      i += m[0].length - 1;
      continue;
    }
    if (dialect === "bash" && ch === "$" && next === "'") {
      const endAnsi = readAnsiCQuoteEnd(normalized, i);
      if (endAnsi < 0) return fail("unclosed Bash $'...' quote");
      cur += normalized.slice(i, endAnsi + 1);
      i = endAnsi;
      continue;
    }
    if (dialect === "bash" && ch === "$" && next === '"') { quote = '"'; cur += '$"'; i += 1; continue; }
    if (ch === "'" || ch === '"') { quote = ch; cur += ch; continue; }
    if (dialect === "bash" && ch === "\\") {
      if (next === "\n") { i += 1; continue; }
      if (next === "\r" && normalized[i + 2] === "\n") { i += 2; continue; }
    }
    if (ch === esc && next) { cur += ch + next; i += 1; continue; }
    if (ch === "$" && next === "{") { paramScopes.push({ innerDepth: 0 }); cur += "${"; i += 1; continue; }
    if (ch === "$" && next === "(") {
      const close = readBalancedParen(normalized, i + 1, dialect);
      if (close < 0) return fail("unclosed $(...) command substitution");
      appendNestedSegments(normalized.slice(i + 2, close), { subshellOffset: dialect === "bash" ? subshellDepth + 1 : subshellDepth });
      cur += normalized.slice(i, close + 1);
      i = close;
      continue;
    }
    if (dialect === "bash" && ch === "`") {
      const endTick = readClosingBacktick(normalized, i);
      if (endTick < 0) return fail("unclosed backtick command substitution");
      appendNestedSegments(unescapeBashBacktickBody(normalized.slice(i + 1, endTick), false), { subshellOffset: subshellDepth + 1 });
      cur += normalized.slice(i, endTick + 1);
      i = endTick;
      continue;
    }
    if (ch === "\n" && pendingHereDocs.length > 0) {
      const docs = consumeBashHereDocs(normalized, i, pendingHereDocs.splice(0));
      if (!docs) return fail("unclosed Bash here-document");
      lastClosedBraceRange = null;
      flush(0, false, ";");
      for (const doc of docs.bodies) if (!doc.quoted) scanExpandableBody(doc.body, dialect, out, appendNestedSegments, subshellDepth + 1);
      i = docs.nextIdx;
      continue;
    }
    if (ch === ";") { justClosedCond = false; lastClosedBraceRange = null; flush(0, false, ";"); continue; }
    if (ch === "\n" || ch === "\r") {
      const isCondHeader = isBraceConditionalHeader(cur.trim());
      lastClosedBraceRange = null;
      flush(0, false, ";");
      if (isCondHeader) justClosedCond = true;
      continue;
    }
    if (ch === "|") {
      justClosedCond = false;
      const isOr = next === "|";
      const isBashPipeErr = !isOr && dialect === "bash" && next === "&";
      if (isOr) { lastClosedBraceRange = null; flush(0, false, "||"); i += 1; }
      else {
        flush(0, true, "|", { markPipedOut: true });
        if (lastClosedBraceRange) {
          for (let k = lastClosedBraceRange.start; k < lastClosedBraceRange.end; k += 1) out[k].pipedOut = true;
        }
        lastClosedBraceRange = null;
        if (isBashPipeErr) i += 1;
      }
      continue;
    }
    if (ch === "(") {
      lastClosedBraceRange = null;
      const trimmedCur = cur.trim();
      if (dialect === "powershell") {
        const callMatch = trimmedCur.match(/^((?:\[[\w.]+\]\s*)?\$[\w:.]+\s*=\s*)?([&.])$/);
        if (callMatch) {
          const close = readBalancedParen(normalized, i, dialect);
          if (close < 0) return fail("unclosed PowerShell call expression");
          const inner = normalized.slice(i + 1, close).trim();
          if (!isStaticPowerShellStringLiteral(inner)) return fail("dynamic PowerShell call expression &(...)");
          cur = `${callMatch[1] ?? ""}${inner}`; i = close; continue;
        }
        if (cur.endsWith("@")) {
          const close = readBalancedParen(normalized, i, dialect);
          if (close < 0) return fail("unclosed PowerShell @(...) expression");
          appendNestedSegments(normalized.slice(i + 1, close), { subshellOffset: subshellDepth });
          cur += normalized.slice(i, close + 1); i = close; continue;
        }
        const isCondKeyword = PS_CONDITIONAL_KEYWORDS.has(trimmedCur.toLowerCase());
        const isPsAssignParen = /^(?:\[[\w.]+\]\s*)?\$[\w:.]+\s*=$/.test(trimmedCur);
        if (trimmedCur.length > 0 && !isPsAssignParen && !isCondKeyword && !/^function\b/i.test(trimmedCur)) {
          const close = readBalancedParen(normalized, i, dialect);
          if (close < 0) return fail("unclosed PowerShell parenthesized expression");
          const inner = normalized.slice(i + 1, close).trim();
          appendNestedSegments(inner, { subshellOffset: subshellDepth });
          cur += isStaticPowerShellStringLiteral(inner) ? inner : normalized.slice(i, close + 1);
          i = close;
          continue;
        }
        const isFuncParen = /^function\b/i.test(trimmedCur);
        parenKindStack.push({ isFuncParen, deltaSub: 0 });
        const condClose = isCondKeyword ? readBalancedParen(normalized, i, dialect) : -1;
        const opensPsCond = Boolean(isCondKeyword && condClose > i + 1 && nextNonCommentChar(normalized, condClose + 1, dialect) === "{");
        flush(0, false, trimmedCur ? "block" : curSep, { opensPsCond, deltaParen: 1 });
        if (opensPsCond) condDepths.push(parenDepth);
        continue;
      }
      const isPsKeywordInBash = PS_CONDITIONAL_KEYWORDS.has(trimmedCur.toLowerCase());
      const isFuncParen = trimmedCur.length > 0 && !isPsKeywordInBash && !/^[$@]/.test(trimmedCur) && !/=$/.test(trimmedCur);
      parenKindStack.push({ isFuncParen, deltaSub: 1 });
      const condClose = isPsKeywordInBash ? readBalancedParen(normalized, i, "powershell") : -1;
      const opensPsCond = Boolean(isPsKeywordInBash && condClose > i + 1 && nextNonCommentChar(normalized, condClose + 1, "powershell") === "{");
      flush(1, false, trimmedCur ? "block" : curSep, { opensPsCond, deltaParen: 1 });
      if (opensPsCond) condDepths.push(parenDepth);
      continue;
    }
    if (ch === ")") {
      lastClosedBraceRange = null;
      const kind = parenKindStack.pop();
      const deltaSub = kind?.deltaSub ?? (dialect === "powershell" ? 0 : 1);
      flush(-deltaSub, false, ")", { deltaParen: -1 });
      justClosedSubshell = deltaSub > 0;
      if (kind?.isFuncParen) justClosedCond = true;
      continue;
    }
    const trimmedForBrace = cur.trim();
    const isCoprocHeader = dialect === "bash" && /^coproc(?:\s+[A-Za-z_][A-Za-z0-9_]*)?$/.test(trimmedForBrace);
    const isBashBracePrefix = dialect === "bash" && BASH_BRACE_PREFIX_RE.test(trimmedForBrace);
    const isFuncBrace = /^function\b/i.test(trimmedForBrace);
    if (ch === "{" && (dialect === "powershell" || isCoprocHeader || isBashBracePrefix || isFuncBrace || (trimmedForBrace.length === 0 && (next === "" || /[\s\r\n]/.test(next))))) {
      lastClosedBraceRange = null;
      const condWord = isBraceConditionalHeader(trimmedForBrace);
      const isTransparentPrefix = !trimmedForBrace || isBashBracePrefix;
      const isCondSep = isTransparentPrefix && (curSep === "&&" || curSep === "||");
      const inheritsPiped = isTransparentPrefix && (curPipedIn || pipedBraceDepths.length > 0);
      flush(0, inheritsPiped, isTransparentPrefix ? curSep : "block", { opensBrace: true });
      braceDepth += 1;
      if (dialect === "powershell" || justClosedCond || condWord || isCoprocHeader || isCondSep) {
        condBlocks.push({ depth: braceDepth, id: nextCondBlockId++ });
        justClosedCond = false;
      }
      if (inheritsPiped) pipedBraceDepths.push(braceDepth);
      braceOutStarts.push(out.length);
      continue;
    }
    if (ch === "}" && (dialect === "powershell" || (trimmedForBrace.length === 0 && (next === "" || /[\s\r\n;|&)]/.test(next))))) {
      flush(0, false, "}");
      braceDepth = Math.max(0, braceDepth - 1);
      while (condBlocks.length > 0 && condBlocks[condBlocks.length - 1].depth > braceDepth) condBlocks.pop();
      while (pipedBraceDepths.length > 0 && pipedBraceDepths[pipedBraceDepths.length - 1] > braceDepth) pipedBraceDepths.pop();
      const startOut = braceOutStarts.pop();
      if (startOut !== undefined && out.length > startOut) lastClosedBraceRange = { start: startOut, end: out.length };
      continue;
    }
    if (ch === ">" && next === "&" && /^\d+$/.test(normalized[i + 2] ?? "")) { cur += `>&${normalized[i + 2]}`; i += 2; continue; }
    if (ch === "<") hasInputRedir = true;
    if (ch === ">") hasRedir = true;
    if (ch === "&") {
      if (next === "&") { lastClosedBraceRange = null; flush(0, false, "&&"); i += 1; continue; }
      if (next === ">") { hasRedir = true; cur += "&>"; i += 1; continue; }
      const prev = i > 0 ? normalized[i - 1] : "";
      if (prev === ">" || prev === "<" || (dialect === "powershell" && (/=\s*$/.test(cur) || !isPsBackgroundAmpersand(normalized, i)))) { cur += ch; continue; }
      if (cur.trim().length > 0 || lastClosedBraceRange) {
        flush(0, false, ";", { isBg: true });
        if (lastClosedBraceRange) {
          for (let k = lastClosedBraceRange.start; k < lastClosedBraceRange.end; k += 1) out[k].isBackground = true;
        }
        lastClosedBraceRange = null;
        continue;
      }
    }
    cur += ch;
  }
  if (pendingHereDocs.length > 0) return fail("unclosed Bash here-document");
  if (quote) return fail("unclosed shell quote");
  if (paramScopes.length > 0) return fail("unclosed ${...} parameter expansion");
  flush();
  return out;
}
