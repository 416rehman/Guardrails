import { createContext, useContext } from "react";
import type { ActionAttempt, GrantScope } from "@grdr/api";
import type { ConsoleRouteId } from "@grdr/i18n";
import type { EntityTarget } from "@grdr/kit";
import type { GrdrThemeMode } from "@grdr/ui";
import type { ConsoleSnapshot, PrefillDraft, StreamState } from "./consoleState";
import type { ConsoleSearchParams } from "./searchSchema";

export type ConsoleLoadPhase =
  | { kind: "loading" }
  | { kind: "ready" }
  | { kind: "error"; message: string };

export interface ConsoleWorkspaceContextValue {
  snapshot: ConsoleSnapshot;
  loadPhase: ConsoleLoadPhase;
  streamState: StreamState;
  invalidateAll: () => Promise<void>;
  theme: GrdrThemeMode;
  onToggleTheme: () => void;
  searchQuery: string;
  onSearchQueryChange: (q: string) => void;
  prefill: PrefillDraft;
  onClearPrefill: () => void;
  onCreateRuleFromAttempt: (attempt: ActionAttempt) => void;
  onOpenEntity: (target: EntityTarget) => void;
  onOpenSessionTurn: (sessionId: string, turnIndex: number) => void;
  onNavigateRoute: (route: ConsoleRouteId, childId?: string) => void;
  onUpdateSearch: (patch: Partial<ConsoleSearchParams>) => void;
  onDecideApproval: (
    id: string,
    approve: boolean,
    scope: GrantScope,
  ) => Promise<void>;
  onStreamVersionBump: () => void;
}

export const ConsoleWorkspaceContext =
  createContext<ConsoleWorkspaceContextValue | null>(null);

export function useConsoleWorkspace(): ConsoleWorkspaceContextValue {
  const ctx = useContext(ConsoleWorkspaceContext);
  if (!ctx) {
    throw new Error(
      "GRDR-WEB-0001: ConsoleWorkspaceContext must be used inside ConsoleShell",
    );
  }
  return ctx;
}
