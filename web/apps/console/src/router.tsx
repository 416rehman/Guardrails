import { useEffect } from "react";
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
import { CompliancePage } from "./pages/CompliancePage";
import { CoveragePage } from "./pages/CoveragePage";
import { FirstRunPage } from "./pages/FirstRunPage";
import { HomePage } from "./pages/HomePage";
import { InventoryPage } from "./pages/InventoryPage";
import { ProtectPage } from "./pages/ProtectPage";
import { ProviderWorkbenchPage } from "./pages/ProviderWorkbenchPage";
import { RespondPage } from "./pages/RespondPage";
import { ReviewQueuePage } from "./pages/ReviewQueuePage";
import { SessionsPage, type SessionViewMode } from "./pages/SessionsPage";
import { SettingsPrivacyPage } from "./pages/SettingsPrivacyPage";
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
    onExplainReceipt,
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
      onExplainReceipt={onExplainReceipt}
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
    onExplainReceipt,
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
      onExplainReceipt={onExplainReceipt}
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
    onExplainReceipt,
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
      onExplainReceipt={onExplainReceipt}
      onUpdated={() => void invalidateAll()}
    />
  );
}

function FirstRunRouteView() {
  const { snapshot, onOpenEntity, onNavigateRoute, invalidateAll } =
    useConsoleWorkspace();
  return (
    <FirstRunPage
      devices={snapshot.devices}
      onOpenEntity={onOpenEntity}
      onNavigateCompliance={() => onNavigateRoute("compliance")}
      onChanged={invalidateAll}
    />
  );
}

function ReviewRouteView() {
  const { snapshot, onOpenEntity, onExplainReceipt, invalidateAll } =
    useConsoleWorkspace();
  return (
    <ReviewQueuePage
      devices={snapshot.devices}
      onOpenEntity={onOpenEntity}
      onExplainReceipt={onExplainReceipt}
      onChanged={invalidateAll}
    />
  );
}

function ComplianceRouteView() {
  const { invalidateAll } = useConsoleWorkspace();
  return <CompliancePage onChanged={invalidateAll} />;
}

function SettingsRouteView() {
  const { invalidateAll } = useConsoleWorkspace();
  return <SettingsPrivacyPage onChanged={invalidateAll} />;
}

function ProviderRouteView() {
  const { invalidateAll } = useConsoleWorkspace();
  return <ProviderWorkbenchPage onChanged={invalidateAll} />;
}

function WhyRedirectView() {
  const params = useParams({ strict: false }) as { reference?: string };
  const { onExplainReceipt } = useConsoleWorkspace();

  useEffect(() => {
    if (params.reference) {
      onExplainReceipt(params.reference);
    }
  }, [params.reference, onExplainReceipt]);

  return <HomeRouteView />;
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

const firstRunRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/first-run",
  validateSearch: validateConsoleSearch,
  component: FirstRunRouteView,
});

const reviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/review",
  validateSearch: validateConsoleSearch,
  component: ReviewRouteView,
});

const complianceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/compliance",
  validateSearch: validateConsoleSearch,
  component: ComplianceRouteView,
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  validateSearch: validateConsoleSearch,
  component: SettingsRouteView,
});

const providerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/provider",
  validateSearch: validateConsoleSearch,
  component: ProviderRouteView,
});

const whyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/why/$reference",
  validateSearch: validateConsoleSearch,
  component: WhyRedirectView,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  homeRoute,
  firstRunRoute,
  usersRoute,
  inventoryIndexRoute,
  inventorySectionRoute,
  sessionsIndexRoute,
  sessionsViewRoute,
  protectIndexRoute,
  protectSectionRoute,
  reviewRoute,
  respondRoute,
  complianceRoute,
  settingsRoute,
  providerRoute,
  coverageRoute,
  testerRoute,
  whyRoute,
]);

export function createConsoleRouter(history?: RouterHistory) {
  return createRouter({
    routeTree,
    history: history ?? createBrowserHistory(),
    defaultNotFoundComponent: HomeRouteView,
  });
}

export type ConsoleRouter = ReturnType<typeof createConsoleRouter>;
