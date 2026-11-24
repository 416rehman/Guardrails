import {
  createBrowserHistory,
  createRootRoute,
  createRoute,
  createRouter,
  useNavigate,
  useParams,
  useSearch,
  type RouterHistory,
} from "@tanstack/react-router";
import type { InventorySectionId, ProtectSectionId } from "@grdr/i18n";
import { ConsoleShell } from "./ConsoleShell";
import { useConsoleWorkspace } from "./ConsoleContext";
import { CoveragePage } from "./pages/CoveragePage";
import { HomePage } from "./pages/HomePage";
import { InventoryPage } from "./pages/InventoryPage";
import { ProtectPage } from "./pages/ProtectPage";
import { RespondPage } from "./pages/RespondPage";
import { SessionsPage, type SessionViewMode } from "./pages/SessionsPage";
import { TesterPage } from "./pages/TesterPage";
import { UsersPage } from "./pages/UsersPage";
import {
  normalizeInventorySection,
  normalizeProtectSection,
  normalizeSessionView,
  validateConsoleSearch,
  type ConsoleSearchParams,
} from "./searchSchema";

function HomeRouteView() {
  const {
    snapshot,
    onNavigateRoute,
    onOpenEntity,
    onDecideApproval,
  } = useConsoleWorkspace();

  return (
    <HomePage
      overview={snapshot.overview}
      devices={snapshot.devices}
      packs={snapshot.packs}
      approvals={snapshot.approvals}
      findings={snapshot.findings}
      onNavigate={(next) => onNavigateRoute(next)}
      onOpenEntity={onOpenEntity}
      onDecideApproval={onDecideApproval}
    />
  );
}

function UsersRouteView() {
  const {
    snapshot,
    searchQuery,
    onOpenEntity,
    onOpenSessionTurn,
    onUpdateSearch,
    invalidateAll,
  } = useConsoleWorkspace();
  const urlSearch = useSearch({ strict: false }) as ConsoleSearchParams;

  return (
    <UsersPage
      users={snapshot.users}
      privacyConfig={snapshot.privacyConfig}
      searchQuery={searchQuery}
      urlSearch={urlSearch}
      onUpdateSearch={onUpdateSearch}
      onOpenEntity={onOpenEntity}
      onOpenSessionTurn={onOpenSessionTurn}
      onPrivacyUpdated={() => void invalidateAll()}
    />
  );
}

function InventoryRouteView({ sectionOverride }: { sectionOverride?: InventorySectionId }) {
  const navigate = useNavigate();
  const params = useParams({ strict: false }) as { section?: string };
  const urlSearch = useSearch({ strict: false }) as ConsoleSearchParams;
  const {
    snapshot,
    searchQuery,
    onOpenEntity,
    onUpdateSearch,
    invalidateAll,
  } = useConsoleWorkspace();

  const section = sectionOverride ?? normalizeInventorySection(params.section);

  return (
    <InventoryPage
      devices={snapshot.devices}
      searchQuery={searchQuery}
      urlSearch={urlSearch}
      onUpdateSearch={onUpdateSearch}
      section={section}
      onSectionChange={(next) => {
        void navigate({
          to: "/inventory/$section",
          params: { section: next },
          search: {},
        });
      }}
      selectedDeviceId={urlSearch.device ?? null}
      onSelectDevice={(id) => onUpdateSearch({ device: id ?? undefined })}
      onOpenEntity={onOpenEntity}
      onRefresh={() => void invalidateAll()}
    />
  );
}

function SessionsRouteView({ viewOverride }: { viewOverride?: SessionViewMode }) {
  const navigate = useNavigate();
  const params = useParams({ strict: false }) as { view?: string };
  const urlSearch = useSearch({ strict: false }) as ConsoleSearchParams;
  const {
    snapshot,
    searchQuery,
    onOpenEntity,
    onUpdateSearch,
    onCreateRuleFromAttempt,
  } = useConsoleWorkspace();

  const section = viewOverride ?? normalizeSessionView(params.view);

  return (
    <SessionsPage
      sessions={snapshot.sessions}
      devices={snapshot.devices}
      searchQuery={searchQuery}
      urlSearch={urlSearch}
      onUpdateSearch={onUpdateSearch}
      section={section}
      onSectionChange={(next) => {
        void navigate({
          to: "/sessions/$view",
          params: { view: next },
          search: (prev: Record<string, unknown>) => ({
            ...validateConsoleSearch(prev ?? {}),
          }),
        });
      }}
      selectedSessionId={urlSearch.sessionId ?? null}
      onSelectSessionId={(id) =>
        onUpdateSearch({
          sessionId: id ?? undefined,
          turn: undefined,
          attemptId: undefined,
        })
      }
      onOpenEntity={onOpenEntity}
      onCreateRuleFromAttempt={onCreateRuleFromAttempt}
    />
  );
}

function ProtectRouteView({ sectionOverride }: { sectionOverride?: ProtectSectionId }) {
  const navigate = useNavigate();
  const params = useParams({ strict: false }) as { section?: string };
  const urlSearch = useSearch({ strict: false }) as ConsoleSearchParams;
  const {
    snapshot,
    prefill,
    onClearPrefill,
    onOpenEntity,
    onUpdateSearch,
    invalidateAll,
  } = useConsoleWorkspace();

  const section = sectionOverride ?? normalizeProtectSection(params.section);
  const prefillAttempt = prefill.kind === "fromAttempt" ? prefill.attempt : null;

  return (
    <ProtectPage
      packs={snapshot.packs}
      devices={snapshot.devices}
      section={section}
      onSectionChange={(next) => {
        void navigate({
          to: "/protect/$section",
          params: { section: next },
          search: {},
        });
      }}
      urlSearch={urlSearch}
      onUpdateSearch={onUpdateSearch}
      prefillAttempt={prefillAttempt}
      onClearPrefill={onClearPrefill}
      onOpenEntity={onOpenEntity}
      onUpdated={() => void invalidateAll()}
    />
  );
}

function RespondRouteView() {
  const urlSearch = useSearch({ strict: false }) as ConsoleSearchParams;
  const {
    snapshot,
    onOpenEntity,
    onOpenSessionTurn,
    onUpdateSearch,
    invalidateAll,
  } = useConsoleWorkspace();

  return (
    <RespondPage
      approvals={snapshot.approvals}
      findings={snapshot.findings}
      incidents={snapshot.incidents}
      devices={snapshot.devices}
      killSwitch={snapshot.killSwitch}
      defaultSessionId={snapshot.sessions[0]?.id ?? "sess-demo-refactor"}
      urlSearch={urlSearch}
      onUpdateSearch={onUpdateSearch}
      onOpenEntity={onOpenEntity}
      onOpenSessionTurn={onOpenSessionTurn}
      onUpdated={() => void invalidateAll()}
    />
  );
}

function CoverageRouteView() {
  const { snapshot, onOpenEntity } = useConsoleWorkspace();
  return <CoveragePage devices={snapshot.devices} onOpenEntity={onOpenEntity} />;
}

function TesterRouteView() {
  const { invalidateAll, onOpenEntity } = useConsoleWorkspace();
  return (
    <TesterPage
      onEvaluated={() => void invalidateAll()}
      onOpenEntity={onOpenEntity}
    />
  );
}

const rootRoute = createRootRoute({
  validateSearch: validateConsoleSearch,
  component: ConsoleShell,
  notFoundComponent: HomeRouteView,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  validateSearch: validateConsoleSearch,
  component: HomeRouteView,
});

const homeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/home",
  validateSearch: validateConsoleSearch,
  component: HomeRouteView,
});

const usersRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/users",
  validateSearch: validateConsoleSearch,
  component: UsersRouteView,
});

const inventoryIndexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/inventory",
  validateSearch: validateConsoleSearch,
  component: () => <InventoryRouteView sectionOverride="endpoints" />,
});

const inventorySectionRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/inventory/$section",
  validateSearch: validateConsoleSearch,
  component: () => <InventoryRouteView />,
});

const sessionsIndexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sessions",
  validateSearch: validateConsoleSearch,
  component: () => <SessionsRouteView viewOverride="graph" />,
});

const sessionsViewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sessions/$view",
  validateSearch: validateConsoleSearch,
  component: () => <SessionsRouteView />,
});

const protectIndexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/protect",
  validateSearch: validateConsoleSearch,
  component: () => <ProtectRouteView sectionOverride="rules" />,
});

const protectSectionRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/protect/$section",
  validateSearch: validateConsoleSearch,
  component: () => <ProtectRouteView />,
});

const respondRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/respond",
  validateSearch: validateConsoleSearch,
  component: RespondRouteView,
});

const coverageRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/coverage",
  validateSearch: validateConsoleSearch,
  component: CoverageRouteView,
});

const testerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/tester",
  validateSearch: validateConsoleSearch,
  component: TesterRouteView,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  homeRoute,
  usersRoute,
  inventoryIndexRoute,
  inventorySectionRoute,
  sessionsIndexRoute,
  sessionsViewRoute,
  protectIndexRoute,
  protectSectionRoute,
  respondRoute,
  coverageRoute,
  testerRoute,
]);

export function createConsoleRouter(history?: RouterHistory) {
  return createRouter({
    routeTree,
    history: history ?? createBrowserHistory(),
    defaultNotFoundComponent: HomeRouteView,
  });
}

export type ConsoleRouter = ReturnType<typeof createConsoleRouter>;
