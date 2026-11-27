// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useMemo, useState } from "react";
import { formatTimestamp } from "@grdr/i18n";
import {
  Badge,
  Button,
  EmptyState,
  GrdrIcon,
  GrdrSelect,
  Heading,
  Text,
  TextInput,
  VStack,
} from "@grdr/ui";
import type { OperatorSnapshot } from "./queries";

export function formatAuditKind(kind: string): string {
  switch (kind) {
    case "policy.pack.loaded":
      return "Policy pack loaded";
    case "policy.update":
      return "Policy updated";
    case "kill_switch.updated":
      return "Kill switch changed";
    default:
      return kind.replace(/\./g, " ");
  }
}

export function OperatorAuditView({ snapshot }: { snapshot: OperatorSnapshot }) {
  const [searchQuery, setSearchQuery] = useState("");
  const [kindFilter, setKindFilter] = useState("all");

  const kindOptions = useMemo(() => {
    const uniqueKinds = Array.from(new Set(snapshot.audit.map((entry) => entry.kind)));
    return [
      { value: "all", label: "All event kinds" },
      ...uniqueKinds.map((kind) => ({ value: kind, label: formatAuditKind(kind) })),
    ];
  }, [snapshot.audit]);

  const filteredEntries = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return snapshot.audit.filter((entry) => {
      if (kindFilter !== "all" && entry.kind !== kindFilter) {
        return false;
      }
      if (!q) {
        return true;
      }
      return (
        entry.actor.toLowerCase().includes(q) ||
        entry.summary.toLowerCase().includes(q) ||
        entry.target.toLowerCase().includes(q) ||
        entry.kind.toLowerCase().includes(q)
      );
    });
  }, [kindFilter, searchQuery, snapshot.audit]);

  return (
    <section className="ledger-section">
      <div className="ledger-header" style={{ flexWrap: "wrap", gap: 10 }}>
        <VStack gap={0}>
          <Heading level={2}>Control-plane audit ledger</Heading>
          <Text size="sm" color="secondary">
            Tamper-evident record of operator authentication, policy, upgrade, and backup events.
          </Text>
        </VStack>
        <Badge variant="neutral" label={`${filteredEntries.length} of ${snapshot.audit.length}`} />
      </div>

      {snapshot.audit.length > 0 && (
        <div className="op-actions-row">
          <div style={{ flex: "1 1 220px", minWidth: 0, maxWidth: 320 }}>
            <TextInput
              label="Filter audit events"
              placeholder="Search actor, target, or summary"
              value={searchQuery}
              onChange={setSearchQuery}
              width="100%"
            />
          </div>
          <div style={{ flex: "0 1 220px", minWidth: 160 }}>
            <GrdrSelect
              label="Event kind"
              value={kindFilter}
              onChange={setKindFilter}
              options={kindOptions}
            />
          </div>
        </div>
      )}

      {snapshot.audit.length === 0 ? (
        <EmptyState
          title="No control audit events"
          description="Operator administrative actions are appended here automatically."
          icon={<GrdrIcon name="file-text" size={20} />}
        />
      ) : filteredEntries.length === 0 ? (
        <EmptyState
          title="No matching audit events"
          description="Clear the search filter or select All event kinds."
          icon={<GrdrIcon name="search" size={20} />}
          actions={
            <Button
              size="sm"
              variant="secondary"
              label="Reset filters"
              onClick={() => {
                setSearchQuery("");
                setKindFilter("all");
              }}
            />
          }
        />
      ) : (
        <div className="table-wrap">
          <table className="table responsive-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Kind</th>
                <th>Actor</th>
                <th>Summary</th>
                <th>Target</th>
              </tr>
            </thead>
            <tbody>
              {filteredEntries.map((entry) => (
                <tr key={entry.id}>
                  <td data-label="Time" className="mono">
                    {formatTimestamp(entry.timestamp)}
                  </td>
                  <td data-label="Kind">{formatAuditKind(entry.kind)}</td>
                  <td data-label="Actor">{entry.actor}</td>
                  <td data-label="Summary">{entry.summary}</td>
                  <td data-label="Target" className="mono">
                    {entry.target}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
