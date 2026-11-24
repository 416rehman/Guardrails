import { QueryClient, useQueries, useQueryClient } from "@tanstack/react-query";
import {
  api,
  type AuditEntry,
  type HealthResponse,
  type OverviewResponse,
  type TrustedKeyInfo,
} from "@grdr/api";

export const OPERATOR_SCOPE = "operator" as const;

export const operatorQueryKeys = {
  all: [OPERATOR_SCOPE] as const,
  health: () => [OPERATOR_SCOPE, "health", {}] as const,
  overview: () => [OPERATOR_SCOPE, "overview", {}] as const,
  keys: () => [OPERATOR_SCOPE, "keys", {}] as const,
  audit: (params: Record<string, unknown> = {}) =>
    [OPERATOR_SCOPE, "audit", params] as const,
};

export interface OperatorSnapshot {
  health: HealthResponse;
  overview: OverviewResponse;
  keys: TrustedKeyInfo[];
  audit: AuditEntry[];
}

export type OperatorLoadPhase =
  | { kind: "loading" }
  | { kind: "ready"; data: OperatorSnapshot }
  | { kind: "error"; message: string; staleData?: OperatorSnapshot };

export function createOperatorQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        refetchOnWindowFocus: false,
        staleTime: 5_000,
      },
    },
  });
}

export function useOperatorSnapshotQueries(): {
  phase: OperatorLoadPhase;
  invalidateAll: () => Promise<void>;
} {
  const queryClient = useQueryClient();
  const results = useQueries({
    queries: [
      {
        queryKey: operatorQueryKeys.health(),
        queryFn: (): Promise<HealthResponse> => api.getHealth(),
      },
      {
        queryKey: operatorQueryKeys.overview(),
        queryFn: (): Promise<OverviewResponse> => api.getOverview(),
      },
      {
        queryKey: operatorQueryKeys.keys(),
        queryFn: (): Promise<TrustedKeyInfo[]> => api.getKeys(),
      },
      {
        queryKey: operatorQueryKeys.audit({ pageSize: 200 }),
        queryFn: (): Promise<AuditEntry[]> => api.getAudit(),
      },
    ],
  });

  const firstErr = results.find((r) => r.error != null)?.error;
  const health = results[0].data;
  const overview = results[1].data;
  const keys = results[2].data;
  const audit = results[3].data;

  const data: OperatorSnapshot | undefined =
    health && overview && keys && audit
      ? { health, overview, keys, audit }
      : undefined;

  let phase: OperatorLoadPhase;
  if (firstErr) {
    const message =
      firstErr instanceof Error
        ? firstErr.message
        : "Failed to load operator state";
    phase = { kind: "error", message, staleData: data };
  } else if (data) {
    phase = { kind: "ready", data };
  } else {
    phase = { kind: "loading" };
  }

  return {
    phase,
    invalidateAll: () =>
      queryClient.invalidateQueries({ queryKey: operatorQueryKeys.all }),
  };
}
