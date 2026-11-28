// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type { ManagedExtensionConfig, TenantProvidersCatalog } from "./types.js";

export interface DnrHeaderModification {
  header: string;
  operation: "set";
  value: string;
}

export interface DnrRule {
  id: number;
  priority: number;
  action: {
    type: "modifyHeaders" | "block";
    requestHeaders?: DnrHeaderModification[];
  };
  condition: {
    requestDomains?: string[];
    urlFilter?: string;
    resourceTypes: string[];
  };
}

export interface CompiledDnrBundle {
  rules: DnrRule[];
  activeHeaders: Array<{
    providerId: string;
    headerName: string;
    value: string;
    domains: string[];
  }>;
  blockedAnonymousFilters: string[];
}

const DEFAULT_RESOURCE_TYPES = [
  "main_frame",
  "sub_frame",
  "xmlhttprequest",
  "websocket",
  "ping",
  "other",
];

function hasControlOrSeparator(value: string, separator: string): boolean {
  if (/[\x00-\x1f\x7f\r\n]/.test(value)) {
    return true;
  }
  if (separator && value.includes(separator)) {
    return true;
  }
  return false;
}

function sanitizeHeaderTokens(
  rawValues: string[],
  omitConsumerAccounts: boolean,
  separator: string,
): string[] {
  const seen = new Set<string>();
  const clean: string[] = [];
  for (const item of rawValues) {
    if (typeof item !== "string") continue;
    const trimmed = item.trim();
    if (!trimmed) continue;
    if (hasControlOrSeparator(trimmed, separator)) {
      throw new Error(
        "GRDR-EXT-0203 Invalid tenant header token containing control bytes or embedded separator",
      );
    }
    if (omitConsumerAccounts && trimmed.toLowerCase() === "consumer_accounts") {
      continue;
    }
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      clean.push(trimmed);
    }
  }
  return clean;
}

export function compileTenantDnrRules(
  catalog: TenantProvidersCatalog,
  managed: ManagedExtensionConfig,
): CompiledDnrBundle {
  const rules: DnrRule[] = [];
  const activeHeaders: CompiledDnrBundle["activeHeaders"] = [];
  const blockedAnonymousFilters: string[] = [];
  const emittedHeaders = new Set<string>();

  let nextRuleId = 100;

  for (const provider of catalog.providers) {
    const rawValues = managed.tenantRestrictions[provider.id] ?? [];
    const tokens = sanitizeHeaderTokens(
      rawValues,
      provider.omitConsumerAccountsHeader,
      provider.multiValueSeparator,
    );

    if (tokens.length > 0) {
      const normalizedHeaderKey = `${provider.id}:${provider.headerName.toLowerCase()}`;
      if (emittedHeaders.has(normalizedHeaderKey)) {
        throw new Error(`GRDR-EXT-0201 Duplicate tenant header rule for ${normalizedHeaderKey}`);
      }
      emittedHeaders.add(normalizedHeaderKey);

      const singleValue = tokens.join(provider.multiValueSeparator);
      rules.push({
        id: nextRuleId,
        priority: 10,
        action: {
          type: "modifyHeaders",
          requestHeaders: [
            {
              header: provider.headerName,
              operation: "set",
              value: singleValue,
            },
          ],
        },
        condition: {
          requestDomains: provider.requestDomains,
          resourceTypes: DEFAULT_RESOURCE_TYPES,
        },
      });
      nextRuleId += 1;

      activeHeaders.push({
        providerId: provider.id,
        headerName: provider.headerName,
        value: singleValue,
        domains: provider.requestDomains,
      });
    }

    if (managed.blockAnonymousSessions && provider.blockUrlFilters.length > 0) {
      for (const filter of provider.blockUrlFilters) {
        rules.push({
          id: nextRuleId,
          priority: 20,
          action: { type: "block" },
          condition: {
            urlFilter: filter,
            resourceTypes: DEFAULT_RESOURCE_TYPES,
          },
        });
        nextRuleId += 1;
        blockedAnonymousFilters.push(filter);
      }
    }
  }

  if (rules.length > catalog.maxDnrRules) {
    throw new Error(
      `GRDR-EXT-0202 Compiled DNR rule count ${rules.length} exceeds limit ${catalog.maxDnrRules}`,
    );
  }

  return {
    rules,
    activeHeaders,
    blockedAnonymousFilters,
  };
}
