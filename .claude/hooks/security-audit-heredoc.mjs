// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Here-doc, PowerShell here-string, ANSI-C quote, and balanced-paren helpers.

export const BASH_HEREDOC_START_RE =
  /^<<(-?)\s*(?:(['"])([A-Za-z_][A-Za-z0-9_-]*)\2|([A-Za-z_][A-Za-z0-9_-]*))/;
const CMD_CONT_WORDS = new Set(["then", "do", "else", "elif", "if", "while", "until", "for", "select", "time", "coproc"]);

export function isWordBoundaryBefore(text, idx, dialect = "bash") {
  if (idx === 0) return true;
  if (dialect === "powershell") return /[\s;|&({})'"]/.test(text[idx - 1]);
  return /[\s;|&({]/.test(text[idx - 1]);
}

export function nextNonCommentChar(text, startIdx, dialect = "bash") {
  let i = startIdx;
  while (i < text.length) {
    if (/\s/.test(text[i])) { i += 1; continue; }
    if (text[i] === "#") {
      const nl = text.indexOf("\n", i);
      if (nl < 0) return "";
      i = nl + 1;
      continue;
    }
    if (dialect === "powershell" && text.startsWith("<#", i)) {
      const end = text.indexOf("#>", i + 2);
      if (end < 0) return "";
      i = end + 2;
      continue;
    }
    return text[i];
  }
  return "";
}

export function readAnsiCQuoteEnd(text, dollarIdx) {
  for (let i = dollarIdx + 2; i < text.length; i += 1) {
    if (text[i] === "\\" && i + 1 < text.length) { i += 1; continue; }
    if (text[i] === "'") return i;
  }
  return -1;
}

export function readBashCaseBracketEnd(text, openIdx) {
  let k = openIdx + 1;
  if (text[k] === "!" || text[k] === "^") k += 1;
  if (text[k] === "]") k += 1;
  for (; k < text.length; k += 1) {
    if (text[k] === "\\" && k + 1 < text.length) { k += 1; continue; }
    if (text[k] === "[" && (text[k + 1] === ":" || text[k + 1] === "=" || text[k + 1] === ".")) {
      const clsEnd = text.indexOf(`${text[k + 1]}]`, k + 2);
      if (clsEnd >= 0) { k = clsEnd + 1; continue; }
    }
    if (text[k] === "]") return k;
  }
  return -1;
}

export function decodeAnsiCEscapes(body) {
  const table = {
    a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", n: "\n",
    r: "\r", t: "\t", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?",
  };
  const decoded = body.replace(
    /\\([abefnrtvE\\'"?]|x([0-9a-fA-F]{1,2})|u([0-9a-fA-F]{1,4})|U([0-9a-fA-F]{1,8})|([0-7]{1,3})|c(.))?/gs,
    (m, simple, hex, u4, u8, oct, ctrl) => {
      if (hex) return String.fromCharCode(parseInt(hex, 16));
      if (u4 || u8) {
        const cp = parseInt(u4 || u8, 16);
        return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
      }
      if (oct) return String.fromCharCode(parseInt(oct, 8) & 0xff);
      if (ctrl) return String.fromCharCode(ctrl.toUpperCase().charCodeAt(0) & 0x1f);
      return simple && table[simple] !== undefined ? table[simple] : m;
    },
  );
  const nulIdx = decoded.indexOf("\0");
  return nulIdx >= 0 ? decoded.slice(0, nulIdx) : decoded;
}

export function scanBashDqParam(text, dollarIdx) {
  let depth = 1;
  const substRanges = [];
  for (let i = dollarIdx + 2; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1] ?? "";
    if (ch === "\\") {
      if (next === "\n") { i += 1; continue; }
      if (next === "\r" && text[i + 2] === "\n") { i += 2; continue; }
      if (next === '"' || next === "'") return null;
      if (next) { i += 1; continue; }
      return null;
    }
    if (ch === '"' || ch === "'" || ch === "`") return null;
    if (ch === "$" && next === "(") {
      const subClose = readBalancedParen(text, i + 1, "bash");
      if (subClose < 0) return null;
      substRanges.push([i + 2, subClose]);
      i = subClose;
      continue;
    }
    if (ch === "$" && next === "{") { depth += 1; i += 1; continue; }
    if (ch === "}") {
      depth -= 1;
      if (depth === 0) return { endIdx: i, substRanges };
    }
  }
  return null;
}

export function decodePsDoubleEscapes(body) {
  const map = { 0: "\0", a: "\x07", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v" };
  return body.replace(/`([\s\S])/g, (_, ch) => map[ch] ?? ch);
}

export function unescapeBashBacktickBody(body, inDoubleQuote) {
  return body.replace(/\\([$\\`"])/g, (m, ch) => (ch === '"' && !inDoubleQuote ? m : ch));
}

export function isStaticPowerShellStringLiteral(expr) {
  if (/^'(?:[^']|'')*'$/.test(expr)) return true;
  if (!/^"(?:[^"$`]|`[\s\S])*"$/.test(expr)) return false;
  return !/\$\(|`\$/.test(expr);
}

export function consumePowerShellHereString(text, startIdx, delim) {
  const firstNl = text.indexOf("\n", startIdx);
  if (firstNl < 0) return undefined;
  let pos = firstNl + 1;
  const endRe = delim === "'" ? /^'@(?=$|[\s;|&),.}\]\[+\-*/])/ : /^"@(?=$|[\s;|&),.}\]\[+\-*/])/;
  while (pos <= text.length) {
    const nextNl = text.indexOf("\n", pos);
    const lineEnd = nextNl === -1 ? text.length : nextNl;
    const rawLine = text.slice(pos, lineEnd).replace(/\r$/, "");
    if (endRe.test(rawLine)) {
      return { body: text.slice(firstNl + 1, pos).replace(/\r?\n$/, ""), endIdx: pos + 1 };
    }
    if (nextNl === -1) break;
    pos = nextNl + 1;
  }
  return undefined;
}

export function consumeBashHereDocs(text, lineEndNlIdx, pendingHereDocs) {
  let pos = lineEndNlIdx + 1;
  const bodies = [];
  for (const doc of pendingHereDocs) {
    const startBody = pos;
    let found = false;
    while (pos <= text.length) {
      const nextNl = text.indexOf("\n", pos);
      const endLine = nextNl === -1 ? text.length : nextNl;
      let line = text.slice(pos, endLine).replace(/\r$/, "");
      if (doc.stripTabs) line = line.replace(/^\t+/, "");
      if (line === doc.tag) {
        bodies.push({ body: text.slice(startBody, pos), quoted: doc.quoted });
        pos = nextNl === -1 ? text.length : nextNl + 1;
        found = true;
        break;
      }
      if (nextNl === -1) break;
      pos = nextNl + 1;
    }
    if (!found) return undefined;
  }
  return { bodies, nextIdx: pos - 1 };
}

export function readClosingBacktick(text, openIdx) {
  for (let i = openIdx + 1; i < text.length; i += 1) {
    if (text[i] === "\\" && i + 1 < text.length) { i += 1; continue; }
    if (text[i] === "`") return i;
  }
  return -1;
}

export function readBalancedParen(text, openIdx, dialect) {
  let depth = 0;
  let quote = "";
  const esc = dialect === "powershell" ? "`" : "\\";
  const pendingHereDocs = [];
  const caseStack = [];
  const paramScopes = [];
  const parenSubstStack = [];
  let justClosedSubshell = false;
  let wordBuf = "";
  let canStartCmd = true;
  let cmdPrefix = "";
  let lastPatternOp = "";
  let lastEscapedEnd = -1;

  const flushWord = (boundaryBefore, nextCh, startWord) => {
    if (!wordBuf || dialect !== "bash") { wordBuf = ""; return; }
    const boundaryAfter = !nextCh || /[\s;|&(\n)<>]/.test(nextCh);
    const top = caseStack[caseStack.length - 1];
    if (cmdPrefix === "time" && startWord > openIdx && text[startWord - 1] === "-" && wordBuf === "p" && boundaryAfter) {
      canStartCmd = true;
      cmdPrefix = "";
      wordBuf = "";
      return;
    }
    if (boundaryBefore && boundaryAfter) {
      if (wordBuf === "case" && canStartCmd && (!top || top.inBody)) {
        caseStack.push({ seenIn: false, inBody: false, optParen: false, extglobDepth: 0 });
        canStartCmd = false;
        cmdPrefix = "";
      } else if (wordBuf === "in" && top && !top.seenIn) {
        top.seenIn = true;
        top.inBody = false;
        lastPatternOp = "";
        canStartCmd = false;
        cmdPrefix = "";
      } else if (
        wordBuf === "esac" && top && top.seenIn &&
        ((top.inBody && canStartCmd) || (!top.inBody && !top.optParen && top.extglobDepth === 0 && lastPatternOp !== "|"))
      ) {
        caseStack.pop();
        lastPatternOp = "";
        canStartCmd = true;
        cmdPrefix = "";
      } else if (cmdPrefix === "coproc") {
        canStartCmd = true;
        cmdPrefix = "";
      } else {
        canStartCmd = CMD_CONT_WORDS.has(wordBuf);
        if (wordBuf === "time" || wordBuf === "coproc") {
          cmdPrefix = wordBuf;
        } else {
          cmdPrefix = "";
        }
      }
    } else {
      canStartCmd = false;
      cmdPrefix = "";
    }
    wordBuf = "";
  };

  for (let i = openIdx; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1] ?? "";
    if (quote) {
      justClosedSubshell = false;
      if (dialect === "bash" && quote === '"' && ch === "$" && next === "{") {
        const dqParam = scanBashDqParam(text, i);
        if (!dqParam) return -1;
        i = dqParam.endIdx;
        continue;
      }
      if (quote === '"' && ch === "$" && next === "(") {
        const sub = readBalancedParen(text, i + 1, dialect);
        if (sub < 0) return -1;
        i = sub;
        continue;
      }
      if (dialect === "bash" && quote === '"' && ch === "`") {
        const endTick = readClosingBacktick(text, i);
        if (endTick < 0) return -1;
        i = endTick;
        continue;
      }
      if (quote === '"' && ch === esc && next) i += 1;
      else if (dialect === "powershell" && quote === "'" && ch === "'" && next === "'") i += 1;
      else if (ch === quote) quote = "";
      continue;
    }
    if (dialect === "bash" && ch === "\\") {
      wordBuf = ""; canStartCmd = false; cmdPrefix = ""; justClosedSubshell = false;
      if (next) { lastEscapedEnd = i + 1; i += 1; }
      continue;
    }
    if (dialect === "powershell" && ch === "`" && next) { justClosedSubshell = false; i += 1; continue; }
    if (dialect === "bash" && ch === "$" && next === "'") {
      wordBuf = ""; canStartCmd = false; cmdPrefix = ""; justClosedSubshell = false;
      const endAnsi = readAnsiCQuoteEnd(text, i);
      if (endAnsi < 0) return -1;
      i = endAnsi;
      continue;
    }
    if (dialect === "powershell" && text.startsWith("<#", i) && isWordBoundaryBefore(text, i, dialect)) {
      justClosedSubshell = false;
      const endBlock = text.indexOf("#>", i + 2);
      if (endBlock < 0) return -1;
      i = endBlock + 1;
      continue;
    }
    if (dialect === "powershell" && ch === "@" && (next === "'" || next === '"') && (text[i + 2] === "\n" || (text[i + 2] === "\r" && text[i + 3] === "\n"))) {
      justClosedSubshell = false;
      const here = consumePowerShellHereString(text, i + 2, next);
      if (!here) return -1;
      i = here.endIdx;
      continue;
    }
    if (paramScopes.length > 0) {
      justClosedSubshell = false;
      if (dialect === "powershell") {
        if (ch === "}") paramScopes.pop();
        continue;
      }
      if (ch === "$" && next === "'") {
        const endAnsi = readAnsiCQuoteEnd(text, i);
        if (endAnsi < 0) return -1;
        i = endAnsi;
        continue;
      }
      if (ch === "$" && next === "(") {
        const sub = readBalancedParen(text, i + 1, dialect);
        if (sub < 0) return -1;
        i = sub;
        continue;
      }
      if (ch === "`") {
        const endTick = readClosingBacktick(text, i);
        if (endTick < 0) return -1;
        i = endTick;
        continue;
      }
      if (ch === "'" || ch === '"') { quote = ch; continue; }
      if (ch === "{") { paramScopes.push({ innerDepth: 0 }); continue; }
      if (ch === "}") { paramScopes.pop(); continue; }
      if (ch === "(") { paramScopes[paramScopes.length - 1].innerDepth += 1; continue; }
      if (ch === ")") {
        const pTop = paramScopes[paramScopes.length - 1];
        if (pTop.innerDepth > 0) pTop.innerDepth -= 1;
        continue;
      }
      continue;
    }
    if (ch === "#" && (isWordBoundaryBefore(text, i, dialect) || (dialect === "bash" && justClosedSubshell))) {
      wordBuf = "";
      justClosedSubshell = false;
      const nl = text.indexOf("\n", i);
      if (nl < 0) return -1;
      i = nl - 1;
      continue;
    }
    justClosedSubshell = false;
    if (ch === "$" && next === "{") {
      wordBuf = ""; canStartCmd = false; cmdPrefix = "";
      paramScopes.push({ innerDepth: 0 });
      i += 1;
      continue;
    }
    if (dialect === "bash" && text.startsWith("<<<", i)) { wordBuf = ""; canStartCmd = false; cmdPrefix = ""; i += 2; continue; }
    if (dialect === "bash" && ch === "<" && next === "<" && text[i + 2] !== "<") {
      wordBuf = ""; canStartCmd = false; cmdPrefix = "";
      const m = text.slice(i).match(BASH_HEREDOC_START_RE);
      if (!m) return -1;
      pendingHereDocs.push({ stripTabs: Boolean(m[1]), quoted: Boolean(m[2]), tag: m[3] || m[4] });
      i += m[0].length - 1;
      continue;
    }
    if (dialect === "bash" && ch === "\n" && pendingHereDocs.length > 0) {
      wordBuf = ""; canStartCmd = true; cmdPrefix = "";
      const docs = consumeBashHereDocs(text, i, pendingHereDocs.splice(0));
      if (!docs) return -1;
      i = docs.nextIdx;
      continue;
    }
    if (/[A-Za-z0-9_]/.test(ch)) { wordBuf += ch; continue; }
    const startWord = i - wordBuf.length;
    const before = startWord - 1 !== lastEscapedEnd && (startWord <= openIdx || /[\s;|&(\n{]/.test(text[startWord - 1]));
    flushWord(before, ch, startWord);
    if (ch === "'" || ch === '"') { quote = ch; canStartCmd = false; continue; }
    if (ch === "!" && canStartCmd) continue;
    if (dialect === "bash" && ch === "`") {
      const endTick = readClosingBacktick(text, i);
      if (endTick < 0) return -1;
      canStartCmd = false;
      i = endTick;
      continue;
    }
    if (ch === "(" && i > openIdx && text[i - 1] === "$" && i - 1 !== lastEscapedEnd) {
      const subClose = readBalancedParen(text, i, dialect);
      if (subClose < 0) return -1;
      canStartCmd = false;
      i = subClose;
      continue;
    }
    const topCase = caseStack[caseStack.length - 1];
    if (dialect === "bash" && topCase && topCase.seenIn) {
      if (!topCase.inBody) {
        if (ch === "[" && i - 1 !== lastEscapedEnd) {
          const endBr = readBashCaseBracketEnd(text, i);
          if (endBr >= 0) { i = endBr; continue; }
        }
        if (ch === "|") { lastPatternOp = "|"; continue; }
        if (ch === "(") {
          const prevChar = i > openIdx ? text[i - 1] : "";
          if (/[@?*+!]/.test(prevChar)) topCase.extglobDepth += 1;
          else topCase.optParen = true;
          continue;
        }
        if (ch === ")") {
          if (topCase.extglobDepth > 0) topCase.extglobDepth -= 1;
          else { topCase.optParen = false; topCase.inBody = true; lastPatternOp = ""; canStartCmd = true; }
          continue;
        }
      } else if (ch === ";" && (next === ";" || next === "&")) {
        topCase.inBody = false; lastPatternOp = ""; canStartCmd = true;
        i += text[i + 2] === "&" ? 2 : 1;
        continue;
      }
    }
    if (/[\n;|&({]/.test(ch)) canStartCmd = true;
    else if (!/\s/.test(ch)) canStartCmd = false;
    if (ch === "(") { parenSubstStack.push(i > openIdx && text[i - 1] === "$" && i - 1 !== lastEscapedEnd); depth += 1; }
    else if (ch === ")") {
      const wasSubst = parenSubstStack.pop() ?? false;
      depth -= 1;
      if (depth === 0) return i;
      if (!wasSubst) justClosedSubshell = true;
    }
  }
  return -1;
}
