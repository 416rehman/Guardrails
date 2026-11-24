import { useEffect, useMemo, useState } from "react";
import {
  api,
  type IdentityMode,
  type OrgPrivacyConfig,
  type RiskTier,
  type UserDetailResponse,
  type UserProfile,
} from "@grdr/api";
import { pluralize } from "@grdr/i18n";
import { EntityLink, type EntityTarget } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
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
import {
  capitalizeTier,
  riskBadgeVariant,
  riskTone,
  UserDetailSection,
} from "./UserDetailSection";

export function UsersPage({
  users,
  privacyConfig,
  searchQuery,
  focusedEntity,
  onClearFocus,
  onOpenEntity,
  onOpenSessionTurn,
  onPrivacyUpdated,
}: {
  users: UserProfile[];
  privacyConfig: OrgPrivacyConfig;
  searchQuery: string;
  focusedEntity?: EntityTarget | null;
  onClearFocus?: () => void;
  onOpenEntity?: (target: EntityTarget) => void;
  onOpenSessionTurn: (sessionId: string, turnIndex: number) => void;
  onPrivacyUpdated: () => void;
}) {
  const [selectedUserId, setSelectedUserId] = useState<string | null>(users[0]?.id ?? null);
  const [detail, setDetail] = useState<UserDetailResponse | null>(null);
  const [departmentFilter, setDepartmentFilter] = useState<string>("all");
  const [tierFilter, setTierFilter] = useState<string>("all");
  const [localFilter, setLocalFilter] = useState("");
  const [savingPrivacy, setSavingPrivacy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (focusedEntity?.kind === "user") {
      const match = users.find(
        (u) =>
          u.id === focusedEntity.id ||
          u.display_name === focusedEntity.label ||
          u.pseudonym_id === focusedEntity.id,
      );
      if (match) {
        setSelectedUserId(match.id);
      }
      onClearFocus?.();
    }
  }, [focusedEntity, users, onClearFocus]);

  const departments = useMemo(() => {
    const unique = Array.from(new Set(users.map((u) => u.department))).sort();
    return [{ value: "all", label: "All departments" }, ...unique.map((d) => ({ value: d, label: d }))];
  }, [users]);

  const effectiveQuery = (localFilter || searchQuery).trim().toLowerCase();
  const filteredUsers = useMemo(
    () =>
      users.filter((u) => {
        const matchesQuery =
          !effectiveQuery ||
          u.display_name.toLowerCase().includes(effectiveQuery) ||
          u.email.toLowerCase().includes(effectiveQuery) ||
          u.department.toLowerCase().includes(effectiveQuery) ||
          u.agent_names.some((a) => a.toLowerCase().includes(effectiveQuery));
        const matchesDept = departmentFilter === "all" || u.department === departmentFilter;
        const matchesTier = tierFilter === "all" || u.risk_tier === tierFilter;
        return matchesQuery && matchesDept && matchesTier;
      }),
    [users, effectiveQuery, departmentFilter, tierFilter],
  );

  const firstFilteredId = filteredUsers[0]?.id ?? null;
  useEffect(() => {
    if (!selectedUserId && firstFilteredId) {
      setSelectedUserId(firstFilteredId);
    }
  }, [selectedUserId, firstFilteredId]);

  useEffect(() => {
    if (!selectedUserId) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    api
      .getUserDetail(selectedUserId)
      .then((res) => {
        if (!cancelled) {
          setDetail(res);
          setError(null);
        }
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedUserId, users, privacyConfig.identity_mode]);

  async function handleIdentityModeChange(nextMode: IdentityMode) {
    setSavingPrivacy(true);
    setError(null);
    try {
      await api.updatePrivacyConfig({
        identity_mode: nextMode,
        user_risk_scoring: nextMode === "named",
        actor: "console-admin",
      });
      onPrivacyUpdated();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSavingPrivacy(false);
    }
  }

  const isPseudonymous = privacyConfig.identity_mode === "pseudonymous";
  const highRiskCount = users.filter((u) => u.risk_tier === "critical" || u.risk_tier === "high").length;

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
              if (!savingPrivacy && mode !== privacyConfig.identity_mode) {
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

      {error && <Banner status="error" title={error} collapsible={false} />}

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
          {pluralize(filteredUsers.length, "user")}
        </Text>
      </div>

      <div className="storyline-split">
        <div className="ledger-section">
          <div className="ledger-header">
            <Heading level={2}>{`Risk ranking (${filteredUsers.length})`}</Heading>
          </div>
          {filteredUsers.length === 0 ? (
            <Text color="secondary">No users match the active filters.</Text>
          ) : (
            <div className="ledger-list">
              {filteredUsers.map((u, idx) => {
                const isSelected = selectedUserId === u.id;
                const highAttention = !isPseudonymous && u.risk_score >= 45;
                return (
                  <div
                    key={u.id}
                    className={`ledger-row selectable ${isSelected ? "selected" : ""} ${highAttention ? "attention-row" : ""}`}
                    style={{ paddingInline: 12, cursor: "pointer" }}
                    onClick={() => setSelectedUserId(u.id)}
                  >
                    <div className="ledger-row-main">
                      <VStack gap={1}>
                        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
                          <span className="mono" style={{ color: "var(--ink-muted)", fontSize: 12 }}>
                            {`#${idx + 1}`}
                          </span>
                          <EntityLink
                            kind="user"
                            id={u.id}
                            label={u.display_name}
                            onSelect={() => setSelectedUserId(u.id)}
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
        </div>

        <UserDetailSection
          detail={detail}
          isPseudonymous={isPseudonymous}
          onOpenEntity={onOpenEntity}
          onOpenSessionTurn={onOpenSessionTurn}
        />
      </div>
    </VStack>
  );
}
