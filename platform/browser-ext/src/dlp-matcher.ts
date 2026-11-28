// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type {
  DelimitedDigitsClause,
  DlpCharset,
  DlpDetectorRule,
  DlpMatcherClause,
  FramedMarkerClause,
  PrefixedTokenClause,
} from "./types.js";

function isAsciiDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}

function isAsciiUpper(code: number): boolean {
  return code >= 65 && code <= 90;
}

function isAsciiLower(code: number): boolean {
  return code >= 97 && code <= 122;
}

function isWordChar(code: number): boolean {
  return isAsciiDigit(code) || isAsciiUpper(code) || isAsciiLower(code) || code === 95;
}

function hasWordBoundaryAt(text: string, index: number): boolean {
  const prevIsWord = index > 0 && isWordChar(text.charCodeAt(index - 1));
  const nextIsWord = index < text.length && isWordChar(text.charCodeAt(index));
  return prevIsWord !== nextIsWord;
}

function isCharsetChar(charset: DlpCharset, code: number): boolean {
  switch (charset) {
    case "upper_alnum":
      return isAsciiDigit(code) || isAsciiUpper(code);
    case "alnum":
      return isAsciiDigit(code) || isAsciiUpper(code) || isAsciiLower(code);
    case "alnum_underscore":
      return isWordChar(code);
    case "alnum_dash":
      return isAsciiDigit(code) || isAsciiUpper(code) || isAsciiLower(code) || code === 45;
    case "alnum_dash_underscore":
      return isWordChar(code) || code === 45;
  }
}

function matchesPrefixedToken(text: string, clause: PrefixedTokenClause): boolean {
  for (const prefix of clause.prefixes) {
    if (prefix.length === 0) continue;
    let pos = 0;
    while (pos <= text.length - prefix.length) {
      const idx = text.indexOf(prefix, pos);
      if (idx === -1) break;
      if (clause.wordBoundary && !hasWordBoundaryAt(text, idx)) {
        pos = idx + prefix.length;
        continue;
      }

      const tailStart = idx + prefix.length;
      let tailLen = 0;
      while (
        tailStart + tailLen < text.length &&
        tailLen <= clause.maxTailLen &&
        isCharsetChar(clause.charset, text.charCodeAt(tailStart + tailLen))
      ) {
        tailLen += 1;
      }

      const end = tailStart + tailLen;
      if (
        tailLen >= clause.minTailLen &&
        tailLen <= clause.maxTailLen &&
        (!clause.wordBoundary || hasWordBoundaryAt(text, end))
      ) {
        return true;
      }

      if (
        clause.wordBoundary &&
        tailLen > clause.minTailLen &&
        tailLen - 1 <= clause.maxTailLen &&
        text.charCodeAt(end - 1) === 45 &&
        hasWordBoundaryAt(text, end - 1)
      ) {
        return true;
      }

      pos = idx + prefix.length;
    }
  }
  return false;
}

function matchesFramedMarker(text: string, clause: FramedMarkerClause): boolean {
  if (clause.start.length === 0 || clause.end.length === 0) return false;
  let pos = 0;
  while (pos <= text.length - clause.start.length) {
    const idx = text.indexOf(clause.start, pos);
    if (idx === -1) break;
    const afterStart = idx + clause.start.length;
    for (const middle of clause.middleOptions) {
      if (
        text.startsWith(middle, afterStart) &&
        text.startsWith(clause.end, afterStart + middle.length)
      ) {
        return true;
      }
    }
    pos = idx + clause.start.length;
  }
  return false;
}

function allZeroDigits(segment: string): boolean {
  for (let i = 0; i < segment.length; i += 1) {
    if (segment.charCodeAt(i) !== 48) return false;
  }
  return segment.length > 0;
}

function extractDelimitedSegments(
  text: string,
  start: number,
  clause: DelimitedDigitsClause,
): { segments: string[]; end: number } | null {
  const segments: string[] = [];
  let cursor = start;
  for (let s = 0; s < clause.segments.length; s += 1) {
    const segLen = clause.segments[s] ?? 0;
    if (segLen <= 0 || cursor + segLen > text.length) return null;
    for (let j = 0; j < segLen; j += 1) {
      if (!isAsciiDigit(text.charCodeAt(cursor + j))) return null;
    }
    segments.push(text.slice(cursor, cursor + segLen));
    cursor += segLen;
    if (s < clause.segments.length - 1) {
      if (!text.startsWith(clause.delimiter, cursor)) return null;
      cursor += clause.delimiter.length;
    }
  }
  return { segments, end: cursor };
}

function matchesDelimitedDigits(text: string, clause: DelimitedDigitsClause): boolean {
  const firstLen = clause.segments[0] ?? 0;
  if (firstLen <= 0 || clause.delimiter.length === 0) return false;
  let searchFrom = firstLen;
  while (searchFrom <= text.length - clause.delimiter.length) {
    const delimIdx = text.indexOf(clause.delimiter, searchFrom);
    if (delimIdx === -1) break;
    const start = delimIdx - firstLen;
    if (start < 0 || (clause.wordBoundary && !hasWordBoundaryAt(text, start))) {
      searchFrom = delimIdx + clause.delimiter.length;
      continue;
    }

    const parsed = extractDelimitedSegments(text, start, clause);
    if (parsed !== null && (!clause.wordBoundary || hasWordBoundaryAt(text, parsed.end))) {
      const firstSeg = parsed.segments[0] ?? "";
      const disallowedPrefix = clause.disallowedFirstPrefixes.some((p) => firstSeg.startsWith(p));
      const hasZeroSeg =
        clause.disallowAllZeroSegment && parsed.segments.some((seg) => allZeroDigits(seg));
      if (!disallowedPrefix && !hasZeroSeg) {
        return true;
      }
    }
    searchFrom = delimIdx + clause.delimiter.length;
  }
  return false;
}

function matchesClause(text: string, clause: DlpMatcherClause): boolean {
  switch (clause.type) {
    case "prefixed_token":
      return matchesPrefixedToken(text, clause);
    case "framed_marker":
      return matchesFramedMarker(text, clause);
    case "delimited_digits":
      return matchesDelimitedDigits(text, clause);
  }
}

export function matchesDlpRule(text: string, rule: DlpDetectorRule): boolean {
  return rule.clauses.some((clause) => matchesClause(text, clause));
}
