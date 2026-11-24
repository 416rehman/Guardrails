import { useEffect, useMemo, useState } from "react";
import { api, type Device, type SessionSummary } from "@grdr/api";
import { pluralize } from "@grdr/i18n";
import { EntityLink, type EntityTarget, SessionLabelBadge } from "@grdr/kit";
import { Badge, Banner, GrdrIcon, HStack, Text, TextInput, VStack } from "@grdr/ui";
import { CursorPagerBar } from "../components/PagerBar";
import { aipQuote, useServerPage } from "../components/useServerPage";

export function SessionListPane({
  devices,
  searchQuery,
  selectedId,
  onSelectSession,
  onOpenEntity,
}: {
  devices: Device[];
  searchQuery: string;
  selectedId: string | null;
  onSelectSession: (id: string) => void;
  onOpenEntity?: (target: EntityTarget) => void;
}) {
  const [localQuery, setLocalQuery] = useState("");
  const query = `${searchQuery} ${localQuery}`.trim().toLowerCase();

  const aipFilter = useMemo(() => {
    if (!query) return "";
    const q = aipQuote(query);
    return `(id:${q} OR agent_name:${q} OR device_name:${q} OR user_id:${q})`;
  }, [query]);

  const sessionsPage = useServerPage(api.listSessionsPage, aipFilter, "last_activity desc", 25);
  const displayedSessions: SessionSummary[] = sessionsPage.items;
  const totalCount = sessionsPage.pageInfo.total_size_estimate || displayedSessions.length;
  const startIdx = sessionsPage.pageIndex * sessionsPage.pageSize;
  const firstSessionId = displayedSessions[0]?.id ?? null;

  useEffect(() => {
    if (!selectedId && firstSessionId) {
      onSelectSession(firstSessionId);
    }
  }, [firstSessionId, selectedId, onSelectSession]);

  return (
    <div className="ledger-section">
      <div className="ledger-header" style={{ flexWrap: "wrap", gap: 8 }}>
        <h2 className="ledger-title">{`Recorded sessions (${totalCount})`}</h2>
        <Text size="sm" color="secondary" className="tabular">
          {totalCount === 0
            ? "0 of 0"
            : `${startIdx + 1}-${Math.min(startIdx + displayedSessions.length, Math.max(totalCount, startIdx + displayedSessions.length))} of ${Math.max(totalCount, startIdx + displayedSessions.length)}`}
        </Text>
      </div>

      {sessionsPage.error && (
        <Banner status="error" title={sessionsPage.error} collapsible={false} />
      )}

      <div style={{ marginBlock: 8 }}>
        <TextInput
          label="Search recorded sessions"
          isLabelHidden
          size="sm"
          placeholder="Filter by session, agent, host, or user..."
          startIcon={<GrdrIcon name="search" size={13} color="var(--ink-muted)" />}
          value={localQuery}
          onChange={setLocalQuery}
          width="100%"
        />
      </div>

      <div className="ledger-list">
        {displayedSessions.length === 0 ? (
          <Text color="secondary">
            {sessionsPage.loading ? "Loading sessions..." : "No sessions match the active filters."}
          </Text>
        ) : (
          displayedSessions.map((sess) => {
            const labels = sess.labels ?? [];
            const isSelected = selectedId === sess.id;
            return (
              <div
                key={sess.id}
                className={`ledger-row selectable ${isSelected ? "selected" : ""}`}
                style={{ paddingInline: 12, cursor: "pointer" }}
                onClick={() => onSelectSession(sess.id)}
              >
                <div className="ledger-row-main">
                  <VStack gap={1}>
                    <HStack
                      gap={1}
                      align="center"
                      style={{ flexWrap: "wrap", columnGap: 6, rowGap: 2 }}
                    >
                      <EntityLink
                        kind="agent"
                        label={sess.agent_name}
                        compact
                        onSelect={onOpenEntity}
                      />
                      <Text size="sm" color="secondary">
                        on
                      </Text>
                      <EntityLink
                        kind="device"
                        id={sess.device_id}
                        label={sess.device_name}
                        os={
                          devices.find(
                            (d) => d.id === sess.device_id || d.hostname === sess.device_name,
                          )?.os
                        }
                        compact
                        onSelect={onOpenEntity}
                      />
                    </HStack>
                    <HStack
                      gap={2}
                      align="center"
                      style={{ columnGap: 8, rowGap: 2, flexWrap: "wrap" }}
                    >
                      {sess.user_display && (
                        <EntityLink
                          kind="user"
                          id={sess.user_id ?? sess.user_display}
                          label={sess.user_display}
                          compact
                          onSelect={onOpenEntity}
                        />
                      )}
                      <EntityLink
                        kind="session"
                        id={sess.id}
                        label={sess.id}
                        compact
                        onSelect={() => onSelectSession(sess.id)}
                      />
                      <Text size="sm" color="secondary" className="tabular">
                        {`${pluralize(sess.total_actions, "call")} · ${pluralize(sess.turn_count ?? 1, "turn")}`}
                      </Text>
                    </HStack>
                  </VStack>
                  <HStack gap={1}>
                    {sess.blocked_count > 0 && (
                      <Badge
                        variant="error"
                        icon={<GrdrIcon name="ban" size={11} />}
                        label={`${sess.blocked_count} denied`}
                      />
                    )}
                    {sess.step_up_count > 0 && (
                      <Badge
                        variant="warning"
                        icon={<GrdrIcon name="hand" size={11} />}
                        label={`${sess.step_up_count} ask`}
                      />
                    )}
                  </HStack>
                </div>

                {labels.length > 0 && (
                  <HStack gap={1}>
                    {labels.map((lbl) => (
                      <SessionLabelBadge key={lbl} label={lbl} />
                    ))}
                  </HStack>
                )}
              </div>
            );
          })
        )}
      </div>

      <CursorPagerBar
        pageIndex={sessionsPage.pageIndex}
        pageSize={sessionsPage.pageSize}
        itemCount={displayedSessions.length}
        pageInfo={sessionsPage.pageInfo}
        label="Sessions pagination"
        onNext={sessionsPage.goNext}
        onPrev={sessionsPage.goPrev}
        onPageSizeChange={sessionsPage.setPageSize}
      />
    </div>
  );
}
