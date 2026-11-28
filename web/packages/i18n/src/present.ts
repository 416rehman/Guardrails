// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import {
  HARNESS_CATALOG_ICONS,
  OS_CATALOG_ICONS,
  PRESENTATION_REGISTRY,
  getLocale,
  t,
  type LocaleCode,
  type MessageKey,
} from "./generated";

export interface CatalogHarnessPresentation {
  id: string;
  displayName: string;
  vendor: string;
  kind: string;
  aliases: readonly string[];
  simpleIcon: string;
  lucide: string;
  tone: string;
}

export interface CatalogOsPresentation {
  id: string;
  displayName: string;
  aliases: readonly string[];
  simpleIcon: string;
  lucide: string;
  tone: string;
}

const HARNESS_SLUGS: readonly string[] = Array.from(
  new Set(
    HARNESS_CATALOG_ICONS.flatMap((entry) => [entry.id, ...entry.aliases]).filter(
      (s) => s.includes("-") || s.includes("_"),
    ),
  ),
).sort((a, b) => b.length - a.length);

const ACTION_LOOKUP: ReadonlyMap<string, MessageKey> = (() => {
  const map = new Map<string, MessageKey>();
  for (const entry of PRESENTATION_REGISTRY) {
    if (entry.enumName !== "ActionClass") continue;
    const raw = entry.value.toLowerCase();
    const labelKey = entry.labelKey as MessageKey;
    map.set(raw, labelKey);
    map.set(raw.replace(/\./g, "_"), labelKey);
    const pascal = entry.value
      .split(".")
      .map((part) => capitalizeLabel(part))
      .join("");
    map.set(pascal.toLowerCase(), labelKey);
  }
  return map;
})();

const ACTION_TOKENS: readonly string[] = Array.from(
  new Set(
    PRESENTATION_REGISTRY.filter((e) => e.enumName === "ActionClass").flatMap((e) => [
      e.value,
      e.value
        .split(".")
        .map((p) => capitalizeLabel(p))
        .join(""),
    ]),
  ),
).sort((a, b) => b.length - a.length);

export function capitalizeLabel(value: string): string {
  if (!value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function isAsciiAlphaNum(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function hasAsciiBoundaryMatch(haystack: string, needle: string): boolean {
  if (!needle) return false;
  let idx = haystack.indexOf(needle);
  while (idx !== -1) {
    const leftOk = idx === 0 || !isAsciiAlphaNum(haystack.charCodeAt(idx - 1));
    const end = idx + needle.length;
    const rightOk = end >= haystack.length || !isAsciiAlphaNum(haystack.charCodeAt(end));
    if (leftOk && rightOk) return true;
    idx = haystack.indexOf(needle, idx + 1);
  }
  return false;
}

function isJsWordChar(code: number): boolean {
  return isAsciiAlphaNum(code) || code === 95;
}

function replaceBoundedTokens(
  input: string,
  targets: readonly string[],
  caseInsensitive: boolean,
  replacer: (matched: string) => string,
): string {
  if (!input || targets.length === 0) return input;
  const haystack = caseInsensitive ? input.toLowerCase() : input;
  const needles = caseInsensitive ? targets.map((item) => item.toLowerCase()) : targets;
  let out = "";
  let lastFlush = 0;
  let i = 0;
  while (i < input.length) {
    const code = input.charCodeAt(i);
    const atWordStart = isJsWordChar(code) && (i === 0 || !isJsWordChar(input.charCodeAt(i - 1)));
    if (atWordStart) {
      let matchedLen = 0;
      for (const needle of needles) {
        const end = i + needle.length;
        if (
          end <= input.length &&
          haystack.startsWith(needle, i) &&
          (end === input.length || !isJsWordChar(input.charCodeAt(end)))
        ) {
          matchedLen = needle.length;
          break;
        }
      }
      if (matchedLen > 0) {
        out += input.slice(lastFlush, i) + replacer(input.slice(i, i + matchedLen));
        i += matchedLen;
        lastFlush = i;
        continue;
      }
    }
    i += 1;
  }
  return lastFlush === 0 ? input : out + input.slice(lastFlush);
}

function matchesExactCatalogCandidate(norm: string, compact: string, candidate: string): boolean {
  const cand = candidate.trim().toLowerCase();
  if (!cand) return false;
  if (norm === cand) return true;
  const candCompact = cand.replace(/[^a-z0-9]/g, "");
  return candCompact.length >= 3 && compact === candCompact;
}

function matchesBoundedCatalogCandidate(
  norm: string,
  tokens: readonly string[],
  candidate: string,
): boolean {
  const cand = candidate.trim().toLowerCase();
  if (!cand) return false;
  if (cand.length < 4) {
    return tokens.includes(cand);
  }
  return hasAsciiBoundaryMatch(norm, cand);
}

export function resolveHarnessCatalogEntry(
  raw: string,
  extraCatalog?: ReadonlyArray<CatalogHarnessPresentation>,
): CatalogHarnessPresentation | null {
  const norm = raw.trim().toLowerCase();
  if (!norm) return null;
  const compact = norm.replace(/[^a-z0-9]/g, "");
  const tokens = norm.split(/[^a-z0-9]+/).filter(Boolean);
  const catalog = extraCatalog?.length
    ? [...extraCatalog, ...HARNESS_CATALOG_ICONS]
    : HARNESS_CATALOG_ICONS;

  for (const entry of catalog) {
    if (
      matchesExactCatalogCandidate(norm, compact, entry.id) ||
      matchesExactCatalogCandidate(norm, compact, entry.displayName) ||
      entry.aliases.some((alias) => matchesExactCatalogCandidate(norm, compact, alias))
    ) {
      return entry;
    }
  }
  const sortedBySpecificity = [...catalog].sort((a, b) => b.id.length - a.id.length);
  for (const entry of sortedBySpecificity) {
    if (
      matchesBoundedCatalogCandidate(norm, tokens, entry.id) ||
      matchesBoundedCatalogCandidate(norm, tokens, entry.displayName) ||
      entry.aliases.some((alias) => matchesBoundedCatalogCandidate(norm, tokens, alias))
    ) {
      return entry;
    }
  }
  return null;
}

export function resolveOsCatalogEntry(raw: string): CatalogOsPresentation | null {
  const norm = raw.trim().toLowerCase();
  if (!norm) return null;
  const compact = norm.replace(/[^a-z0-9]/g, "");
  const tokens = norm.split(/[^a-z0-9]+/).filter(Boolean);
  for (const entry of OS_CATALOG_ICONS) {
    if (
      matchesExactCatalogCandidate(norm, compact, entry.id) ||
      matchesExactCatalogCandidate(norm, compact, entry.displayName) ||
      entry.aliases.some((alias) => matchesExactCatalogCandidate(norm, compact, alias))
    ) {
      return entry;
    }
  }
  const sortedBySpecificity = [...OS_CATALOG_ICONS].sort((a, b) => b.id.length - a.id.length);
  for (const entry of sortedBySpecificity) {
    if (
      matchesBoundedCatalogCandidate(norm, tokens, entry.id) ||
      matchesBoundedCatalogCandidate(norm, tokens, entry.displayName) ||
      entry.aliases.some((alias) => matchesBoundedCatalogCandidate(norm, tokens, alias))
    ) {
      return entry;
    }
  }
  return null;
}

export function presentAgentName(
  raw: string,
  extraCatalog?: ReadonlyArray<CatalogHarnessPresentation>,
): string {
  const trimmed = raw.trim();
  if (!trimmed) return trimmed;
  const match = resolveHarnessCatalogEntry(trimmed, extraCatalog);
  if (match) return match.displayName;
  return trimmed;
}

export function formatActionLabel(actionClass: string, locale?: LocaleCode): string {
  const key = ACTION_LOOKUP.get(actionClass.trim().toLowerCase());
  if (key) {
    return t(key, undefined, locale ?? getLocale());
  }
  return actionClass;
}

export function presentFindingTitle(
  rawTitle: string,
  agentName?: string,
  locale?: LocaleCode,
): string {
  const active = locale ?? getLocale();
  let clean = replaceBoundedTokens(rawTitle, ACTION_TOKENS, false, (token) =>
    formatActionLabel(token, active),
  );
  clean = replaceBoundedTokens(clean, HARNESS_SLUGS, true, (slug) => presentAgentName(slug));
  if (agentName) {
    const candidates = Array.from(
      new Set([
        agentName.trim().toLowerCase(),
        presentAgentName(agentName).toLowerCase(),
      ]),
    ).filter(Boolean);
    for (const target of candidates) {
      const trimmed = clean.trim();
      const lower = trimmed.toLowerCase();
      const onSuffix = ` on ${target}`;
      const parenSuffix = `(${target})`;
      if (lower.endsWith(onSuffix)) {
        clean = trimmed.slice(0, trimmed.length - onSuffix.length);
        break;
      }
      if (lower.endsWith(parenSuffix)) {
        clean = trimmed.slice(0, trimmed.length - parenSuffix.length);
        break;
      }
    }
  }
  return clean.trim();
}

export function presentIncidentTitle(rawTitle: string): string {
  return replaceBoundedTokens(rawTitle, HARNESS_SLUGS, true, (slug) => presentAgentName(slug)).trim();
}

export function presentIncidentSummary(rawSummary: string, locale?: LocaleCode): string {
  const active = locale ?? getLocale();
  let cleaned = replaceBoundedTokens(rawSummary, ACTION_TOKENS, false, (token) =>
    formatActionLabel(token, active).toLowerCase(),
  );
  cleaned = replaceBoundedTokens(cleaned, HARNESS_SLUGS, true, (slug) => presentAgentName(slug));
  cleaned = cleaned
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .join(". ");
  if (!cleaned) return cleaned;
  return cleaned.endsWith(".") || cleaned.endsWith("!") || cleaned.endsWith("?")
    ? cleaned
    : `${cleaned}.`;
}

function presentByEnum(enumName: string, value: string, locale?: LocaleCode): string {
  const entry = PRESENTATION_REGISTRY.find(
    (item) => item.enumName === enumName && item.value === value,
  );
  if (entry) {
    return t(entry.labelKey as MessageKey, undefined, locale ?? getLocale());
  }
  return capitalizeLabel(value.replace(/[_-]/g, " "));
}

export function presentArtifactKind(kind: string, locale?: LocaleCode): string {
  return presentByEnum("ArtifactKind", kind, locale);
}

export function presentArtifactScope(scope: string, locale?: LocaleCode): string {
  return presentByEnum("ArtifactScope", scope, locale);
}

export function presentArtifactRiskFlag(flag: string, locale?: LocaleCode): string {
  return presentByEnum("ArtifactRiskFlag", flag, locale);
}

export function presentApprovalGrade(grade: string, locale?: LocaleCode): string {
  return presentByEnum("ApprovalGrade", grade, locale);
}
