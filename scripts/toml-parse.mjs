// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Shared deterministic TOML subset parser used by architecture and licence lint scripts.

const FORBIDDEN_TOML_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function safeKey(key, lineNo) {
  if (FORBIDDEN_TOML_KEYS.has(key)) {
    throw new Error(`Forbidden TOML key "${key}"${lineNo ? ` at line ${lineNo}` : ""}`);
  }
  return key;
}

function stripTomlComment(line) {
  let inDouble = false;
  let inSingle = false;
  let escaped = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\" && inDouble) {
      escaped = true;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === "#" && !inDouble && !inSingle) {
      return line.slice(0, i);
    }
  }
  return line;
}

function splitTopLevel(inner, sep = ",") {
  const parts = [];
  let cur = "";
  let inDouble = false;
  let inSingle = false;
  let escaped = false;
  let depth = 0;
  for (let i = 0; i < inner.length; i += 1) {
    const ch = inner[i];
    if (escaped) {
      cur += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\" && inDouble) {
      cur += ch;
      escaped = true;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      cur += ch;
    } else if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      cur += ch;
    } else if (!inDouble && !inSingle) {
      if (ch === "[" || ch === "{") depth += 1;
      else if (ch === "]" || ch === "}") depth = Math.max(0, depth - 1);
      if (ch === sep && depth === 0) {
        if (cur.trim()) parts.push(cur.trim());
        cur = "";
        continue;
      }
      cur += ch;
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

function unquoteKey(raw) {
  const k = raw.trim();
  if ((k.startsWith('"') && k.endsWith('"')) || (k.startsWith("'") && k.endsWith("'"))) {
    return safeKey(k.slice(1, -1));
  }
  return safeKey(k);
}

function parseTomlValue(raw) {
  const s = raw.trim();
  if (s === "true") return true;
  if (s === "false") return false;
  if (/^-?\d+$/.test(s)) return Number.parseInt(s, 10);
  if (/^-?\d+\.\d+$/.test(s)) return Number.parseFloat(s);
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  if (s.startsWith("[") && s.endsWith("]")) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    return splitTopLevel(inner, ",").map((item) => parseTomlValue(item));
  }
  if (s.startsWith("{") && s.endsWith("}")) {
    const inner = s.slice(1, -1).trim();
    const tbl = new Map();
    if (!inner) return tbl;
    for (const pair of splitTopLevel(inner, ",")) {
      const eq = pair.indexOf("=");
      if (eq === -1) throw new Error(`Invalid inline TOML table entry: ${pair}`);
      const k = unquoteKey(pair.slice(0, eq));
      const v = parseTomlValue(pair.slice(eq + 1));
      tbl.set(k, v);
    }
    return tbl;
  }
  return s;
}

function setNested(rootMap, pathParts, isArrayTable, lineNo) {
  let cur = rootMap;
  for (let i = 0; i < pathParts.length - 1; i += 1) {
    const seg = safeKey(pathParts[i], lineNo);
    const existing = cur.get(seg);
    if (Array.isArray(existing)) {
      cur = existing.at(-1);
    } else if (existing instanceof Map) {
      cur = existing;
    } else if (existing === undefined) {
      const sub = new Map();
      cur.set(seg, sub);
      cur = sub;
    } else {
      throw new Error(`TOML header conflict at line ${lineNo}`);
    }
  }
  const last = safeKey(pathParts[pathParts.length - 1], lineNo);
  const existing = cur.get(last);
  if (isArrayTable) {
    let arr = existing;
    if (arr === undefined) {
      arr = [];
      cur.set(last, arr);
    }
    if (!Array.isArray(arr)) throw new Error(`TOML header conflict at line ${lineNo}`);
    const obj = new Map();
    arr.push(obj);
    return obj;
  }
  if (existing === undefined) {
    const obj = new Map();
    cur.set(last, obj);
    return obj;
  }
  if (!(existing instanceof Map)) {
    throw new Error(`TOML table conflict at line ${lineNo}`);
  }
  return existing;
}

function materializeToml(val) {
  if (val instanceof Map) {
    return Object.fromEntries(Array.from(val.entries(), ([k, v]) => [k, materializeToml(v)]));
  }
  if (Array.isArray(val)) {
    return val.map((item) => materializeToml(item));
  }
  return val;
}

function countBracketDelta(s) {
  let inDouble = false;
  let inSingle = false;
  let escaped = false;
  let delta = 0;
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\" && inDouble) {
      escaped = true;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (!inDouble && !inSingle) {
      if (ch === "[") delta += 1;
      else if (ch === "]") delta -= 1;
    }
  }
  return delta;
}

export function parseSimpleToml(text) {
  const clean = text.replace(/^\uFEFF/, "");
  const root = new Map();
  let current = root;
  const lines = clean.split(/\r?\n/);
  let pendingKey = null;
  let pendingVal = "";
  let pendingBracketDepth = 0;

  for (let i = 0; i < lines.length; i += 1) {
    const stripped = stripTomlComment(lines[i]).trim();
    if (!stripped) continue;

    if (pendingKey !== null) {
      pendingVal += " " + stripped;
      pendingBracketDepth += countBracketDelta(stripped);
      if (pendingBracketDepth <= 0) {
        if (current.has(pendingKey)) {
          throw new Error(`Duplicate TOML key ${pendingKey} at line ${i + 1}`);
        }
        current.set(pendingKey, parseTomlValue(pendingVal));
        pendingKey = null;
        pendingVal = "";
        pendingBracketDepth = 0;
      }
      continue;
    }

    if (stripped.startsWith("[[") && stripped.endsWith("]]")) {
      const pathParts = splitTopLevel(stripped.slice(2, -2), ".").map(unquoteKey);
      current = setNested(root, pathParts, true, i + 1);
      continue;
    }
    if (stripped.startsWith("[") && stripped.endsWith("]")) {
      const pathParts = splitTopLevel(stripped.slice(1, -1), ".").map(unquoteKey);
      current = setNested(root, pathParts, false, i + 1);
      continue;
    }
    const eq = stripped.indexOf("=");
    if (eq === -1) {
      throw new Error(`Malformed TOML at line ${i + 1}: ${stripped}`);
    }
    const key = safeKey(unquoteKey(stripped.slice(0, eq)), i + 1);
    const val = stripped.slice(eq + 1).trim();
    const delta = countBracketDelta(val);
    if (delta > 0) {
      pendingKey = key;
      pendingVal = val;
      pendingBracketDepth = delta;
      continue;
    }
    if (current.has(key)) {
      throw new Error(`Duplicate TOML key ${key} at line ${i + 1}`);
    }
    current.set(key, parseTomlValue(val));
  }
  if (pendingKey !== null) {
    throw new Error(`Unclosed multiline TOML array for key ${pendingKey}`);
  }
  return materializeToml(root);
}
