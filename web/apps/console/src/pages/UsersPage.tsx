import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  api,
  type IdentityMode,
  type OrgPrivacyConfig,
  type UserDetailResponse,
  type UserProfile,
} from "@grdr/api";
import { pluralize } from "@grdr/i18n";
import { EntityLink, type EntityTarget } from "@grdr/kit";
import {
  Badge,
  Banner,
  GrdrIcon,
  GrdrSelect,
  Heading,
  HStack,
  StatusInline,
  Text,
  TextInput,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";
import { CursorPagerBar } from "../components/PagerBar";
import { aipQuote, useServerPage } from "../components/useServerPage";
import { consoleQueryKeys } from "../queries";
import type { ConsoleSearchParams } from "../searchSchema";
import {
  capitalizeTier,
  riskBadgeVariant,
  riskTone,
  UserDetailSection,
} from "./UserDetailSection";

type PrivacySaveState =
  | { kind: "idle" }
  | { kind: "saving" }
  | { kind: "failed"; message: string };

export function UsersPage({
  users,
  privacyConfig,
  searchQuery,
  urlSearch,
  onUpdateSearch,
  focusedEntity,
  onClearFocus,
  onOpenEntity,
  onOpenSessionTurn,
  onPrivacyUpdated,
}: {
  users: UserProfile[];
  privacyConfig: OrgPrivacyConfig;
  searchQuery: string;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  focusedEntity?: EntityTarget | null;
  onClearFocus?: () => void;
  onOpenEntity?: (target: EntityTarget) => void;
  onOpenSessionTurn: (sessionId: string, turnIndex: number) => void;
  onPrivacyUpdated: () => void;
}) {
  const [fallbackUserId, setFallbackUserId] = useState<string | null>(
    () => users[0]?.id ?? null,
  );
  const [fallbackDept, setFallbackDept] = useState("all");
  const [fallbackTier, setFallbackTier] = useState("all");
  const [fallbackQuery, setFallbackQuery] = useState("");
  const [privacySave, setPrivacySave] = useState<PrivacySaveState>({ kind: "idle" });

  const departmentFilter = urlSearch?.dept ?? fallbackDept;
  const tierFilter = urlSearch?.tier ?? fallbackTier;
  const localFilter = urlSearch?.q ?? fallbackQuery;

  const setDepartmentFilter = (dept: string) => {
    setFallbackDept(dept);
    onUpdateSearch?.({
      dept: dept === "all" ? undefined : dept,
      pageToken: undefined,
      page: undefined,
    });
  };
  const setTierFilter = (tier: string) => {
    setFallbackTier(tier);
    onUpdateSearch?.({
      tier: tier === "all" ? undefined : tier,
      pageToken: undefined,
      page: undefined,
    });
  };
  const setLocalFilter = (q: string) => {
    setFallbackQuery(q);
    onUpdateSearch?.({
      q: q.trim() ? q : undefined,
      pageToken: undefined,
      page: undefined,
    });
  };

  useEffect(() => {
    if (focusedEntity?.kind === "user") {
      const match = users.find(
        (u) =>
          u.id === focusedEntity.id ||
          u.display_name === focusedEntity.label ||
          u.pseudonym_id === focusedEntity.id,
      );
      if (match) {
        setFallbackUserId(match.id);
        onUpdateSearch?.({ userId: match.id });
      }
      onClearFocus?.();
    }
  }, [focusedEntity, users, onClearFocus, onUpdateSearch]);

  const departments = useMemo(() => {
    const unique = Array.from(new Set(users.map((u) => u.department))).sort();
    return [{ value: "all", label: "All departments" }, ...unique.map((d) => ({ value: d, label: d }))];
  }, [users]);

  const isPseudonymous = privacyConfig.identity_mode === "pseudonymous";
  const effectiveQuery = (localFilter || searchQuery).trim().toLowerCase();
  const aipFilter = useMemo(() => {
    const clauses: string[] = [];
    if (departmentFilter !== "all") clauses.push(`department = ${aipQuote(departmentFilter)}`);
    if (!isPseudonymous && tierFilter !== "all") clauses.push(`risk_tier = ${aipQuote(tierFilter)}`);
    if (effectiveQuery) {
      clauses.push(
        `(display_name:${aipQuote(effectiveQuery)} OR email:${aipQuote(effectiveQuery)} OR department:${aipQuote(effectiveQuery)})`,
      );
    }
    return clauses.join(" AND ");
  }, [departmentFilter, tierFilter, isPseudonymous, effectiveQuery]);

  const usersPage = useServerPage(
    api.listUsersPage,
    aipFilter,
    "risk_score desc",
    25,
    isPseudonymous ? 1 : 0,
    onUpdateSearch
      ? {
          resource: "usersPage",
          pageToken: urlSearch?.pageToken ?? "",
          pageIndex: urlSearch?.page ?? 0,
          pageSize: urlSearch?.pageSize ?? 25,
          onPageChange: ({ pageToken, pageIndex }) =>
            onUpdateSearch({
              pageToken: pageToken || undefined,
              page: pageIndex > 0 ? pageIndex : undefined,
            }),
          onPageSizeChange: (nextSize) =>
            onUpdateSearch({
              pageSize: nextSize === 25 ? undefined : nextSize,
              pageToken: undefined,
              page: undefined,
            }),
        }
      : { resource: "usersPage" },
  );

  const displayedUsers = usersPage.items;
  const totalUsersCount = usersPage.pageInfo.total_size_estimate || displayedUsers.length;
  const selectedUserId =
    urlSearch?.userId ?? fallbackUserId ?? displayedUsers[0]?.id ?? users[0]?.id ?? null;

  function selectUser(userId: string) {
    setFallbackUserId(userId);
    onUpdateSearch?.({ userId });
  }

  const detailQuery = useQuery<UserDetailResponse>({
    queryKey: consoleQueryKeys.userDetail(
      selectedUserId ?? "",
      privacyConfig.identity_mode,
    ),
    queryFn: () => api.getUserDetail(selectedUserId ?? ""),
    enabled: Boolean(selectedUserId),
  });

  async function handleIdentityModeChange(nextMode: IdentityMode) {
    setPrivacySave({ kind: "saving" });
    try {
      await api.updatePrivacyConfig({
        identity_mode: nextMode,
        user_risk_scoring: nextMode === "named",
        actor: "console-admin",
      });
      setPrivacySave({ kind: "idle" });
      onPrivacyUpdated();
    } catch (err) {
      setPrivacySave({
        kind: "failed",
        message: err instanceof Error ? err.message : "Failed updating privacy configuration.",
      });
    }
  }

  const highRiskCount = users.filter((u) => u.risk_tier === "critical" || u.risk_tier === "high").length;
  const detailErr =
    detailQuery.error instanceof Error ? detailQuery.error.message : undefined;
  const errorMessage =
    privacySave.kind === "failed"
      ? privacySave.message
      : usersPage.error ?? detailErr;

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Users & risk directory</Heading>
          <Text color="secondary" style={{ marginTop: 6 }}>
            Per-user activity feeds, assigned endpoints and skills, and deterministic risk rankings.
          </Text>
        </div>
        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
          <UiSdkSegmentedControl<IdentityMode>
            ariaLabel="Organisation identity visibility mode"
            value={privacyConfig.identity_mode}
            options={[
              { value: "named", label: "Named users", icon: <GrdrIcon name="user" size={13} /> },
              {
                value: "pseudonymous",
                label: "Works-council",
                icon: <GrdrIcon name="lock" size={13} />,
              },
            ]}
            onChange={(mode) => {
              if (privacySave.kind !== "saving" && mode !== privacyConfig.identity_mode) {
                void handleIdentityModeChange(mode);
              }
            }}
          />
        </HStack>
      </div>

      {isPseudonymous && (
        <Banner
          status="info"
          title="Works-council pseudonymous mode active"
          collapsible={false}
        >
          Display names, emails, and individual risk scores are masked to vault pseudonyms across consoles and exports.
        </Banner>
      )}

      {errorMessage && <Banner status="error" title={errorMessage} collapsible={false} />}

      <div className="metric-strip">
        <div className="metric-cell">
          <div className="metric-value tabular">{users.length}</div>
          <div className="metric-label">Synced users</div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">{isPseudonymous ? "Masked" : highRiskCount}</div>
          <div className="metric-label">High or critical risk</div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">
            {users.reduce((acc, u) => acc + u.blocked_count + u.asked_count, 0)}
          </div>
          <div className="metric-label">Flagged actions</div>
        </div>
        <div className="metric-cell">
          <div className="metric-value tabular">
            {users.reduce((acc, u) => acc + u.artifact_count, 0)}
          </div>
          <div className="metric-label">User skills & rules</div>
        </div>
      </div>

      <div className="facet-bar">
        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
          <TextInput
            label="Filter users"
            isLabelHidden
            placeholder="Search name, email, department, agent..."
            startIcon={<GrdrIcon name="search" size={14} color="var(--ink-muted)" />}
            value={localFilter}
            onChange={setLocalFilter}
            width={260}
          />
          <GrdrSelect
            label="Department"
            isLabelHidden
            size="sm"
            value={departmentFilter}
            options={departments}
            onChange={setDepartmentFilter}
            width={180}
          />
          {!isPseudonymous && (
            <GrdrSelect
              label="Risk tier"
              isLabelHidden
              size="sm"
              value={tierFilter}
              options={[
                { value: "all", label: "All risk tiers" },
                { value: "critical", label: "Critical risk" },
                { value: "high", label: "High risk" },
                { value: "elevated", label: "Elevated risk" },
                { value: "low", label: "Low risk" },
              ]}
              onChange={setTierFilter}
              width={160}
            />
          )}
        </HStack>
        <Text size="sm" color="secondary" className="tabular">
          {pluralize(totalUsersCount, "user")}
        </Text>
      </div>

      <div className="storyline-split">
        <div className="ledger-section">
          <div className="ledger-header">
            <Heading level={2}>{`Risk ranking (${totalUsersCount})`}</Heading>
          </div>
          {displayedUsers.length === 0 ? (
            <Text color="secondary">
              {usersPage.loading ? "Loading users..." : "No users match the active filters."}
            </Text>
          ) : (
            <div className="ledger-list">
              {displayedUsers.map((u, idx) => {
                const isSelected = selectedUserId === u.id;
                const highAttention = !isPseudonymous && u.risk_score >= 45;
                const rankNumber = usersPage.pageIndex * usersPage.pageSize + idx + 1;
                return (
                  <div
                    key={u.id}
                    className={`ledger-row selectable ${isSelected ? "selected" : ""} ${highAttention ? "attention-row" : ""}`}
                    style={{ paddingInline: 12, cursor: "pointer" }}
                    onClick={() => selectUser(u.id)}
                  >
                    <div className="ledger-row-main">
                      <VStack gap={1}>
                        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                          <span className="mono" style={{ color: "var(--ink-muted)", fontSize: 12 }}>
                            {`#${rankNumber}`}
                          </span>
                          <EntityLink
                            kind="user"
                            id={u.id}
                            label={u.display_name}
                            onSelect={() => selectUser(u.id)}
                          />
                        </HStack>
                        <Text size="sm" color="secondary">
                          {`${u.department} · ${u.idp_source}`}
                        </Text>
                      </VStack>
                      <VStack gap={1} align="end">
                        {isPseudonymous ? (
                          <StatusInline tone="neutral" icon={<GrdrIcon name="lock" size={12} />} label="Masked" />
                        ) : (
                          <>
                            <Badge
                              variant={riskBadgeVariant(u.risk_tier)}
                              label={`${u.risk_score} / 100`}
                            />
                            <StatusInline
                              dot
                              tone={riskTone(u.risk_tier)}
                              label={capitalizeTier(u.risk_tier)}
                            />
                          </>
                        )}
                      </VStack>
                    </div>
                    <HStack gap={2} align="center" style={{ flexWrap: "wrap", marginTop: 6 }}>
                      <Text size="sm" color="secondary" className="tabular">
                        {`${pluralize(u.session_count, "session")} · ${u.blocked_count} denied · ${u.finding_count} findings · ${pluralize(u.artifact_count, "skill")}`}
                      </Text>
                    </HStack>
                  </div>
                );
              })}
            </div>
          )}
          <CursorPagerBar
            pageIndex={usersPage.pageIndex}
            pageSize={usersPage.pageSize}
            itemCount={displayedUsers.length}
            pageInfo={usersPage.pageInfo}
            label="Users pagination"
            onNext={usersPage.goNext}
            onPrev={usersPage.goPrev}
            onPageSizeChange={usersPage.setPageSize}
          />
        </div>

        <UserDetailSection
          detail={detailQuery.data ?? null}
          isPseudonymous={isPseudonymous}
          onOpenEntity={onOpenEntity}
          onOpenSessionTurn={onOpenSessionTurn}
        />
      </div>
    </VStack>
  );
}
