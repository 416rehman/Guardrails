// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import type { Device, NavRoute, SetupStep } from "@grdr/api";
import { pluralize } from "@grdr/i18n";
import { AssuranceBadge, EntityLink, type EntityTarget, OsLabel } from "@grdr/kit";
import { Badge, Button, GrdrIcon, HStack, ProgressBar, Text, VStack } from "@grdr/ui";

export function SetupReadinessCard({
  steps,
  completedSteps,
  totalSteps,
  readinessPct,
  onNavigate,
}: {
  steps: SetupStep[];
  completedSteps: number;
  totalSteps: number;
  readinessPct: number;
  onNavigate: (route: NavRoute) => void;
}) {
  return (
    <div className="ledger-section">
      <div className="ledger-header">
        <h2 className="ledger-title">Setup readiness</h2>
        <Text size="sm" color="secondary" className="tabular">
          {`${completedSteps} of ${totalSteps} ready (${readinessPct}%)`}
        </Text>
      </div>

      <ProgressBar value={readinessPct} max={100} label="Setup readiness" isLabelHidden />

      <div className="checklist">
        {steps.map((step) => (
          <div key={step.id} className="check-row">
            <HStack gap={2} align="center">
              <GrdrIcon
                name={step.done ? "check-circle" : "circle"}
                size={15}
                color={step.done ? "var(--tone-allow)" : "var(--ink-muted)"}
              />
              <div>
                <div style={{ fontWeight: 500 }}>{step.label}</div>
                <Text size="sm" color="secondary">
                  {step.detail}
                </Text>
              </div>
            </HStack>
            {!step.done && (
              <Button
                size="sm"
                variant="ghost"
                label="Finish"
                onClick={() => onNavigate("protect")}
              />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export function EnrolledEndpointsCard({
  devices,
  onNavigate,
  onOpenEntity,
}: {
  devices: Device[];
  onNavigate: (route: NavRoute) => void;
  onOpenEntity: (target: EntityTarget) => void;
}) {
  return (
    <div className="ledger-section">
      <div className="ledger-header">
        <h2 className="ledger-title">Enrolled endpoints</h2>
        <Button
          size="sm"
          variant="ghost"
          label="Inventory"
          endContent={<GrdrIcon name="arrow-right" size={13} />}
          onClick={() => onNavigate("inventory")}
        />
      </div>

      <div className="checklist">
        {devices.map((device) => (
          <div
            key={device.id}
            className="check-row"
            style={{ alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}
          >
            <VStack gap={1} style={{ flex: "1 1 220px", minWidth: 0 }}>
              <div>
                <EntityLink
                  kind="device"
                  id={device.id}
                  label={device.hostname}
                  os={device.os}
                  onSelect={onOpenEntity}
                />
              </div>
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  alignItems: "center",
                  columnGap: 10,
                  rowGap: 2,
                  color: "var(--ink-secondary)",
                  fontSize: 13,
                }}
              >
                <OsLabel os={device.os} arch={device.arch} size={13} />
                <span>{pluralize(device.agents.length, "agent")}</span>
                <span>{pluralize(device.mcp_servers.length, "MCP server")}</span>
              </div>
              <HStack gap={1} style={{ flexWrap: "wrap" }}>
                {device.agents.map((ag) => (
                  <AssuranceBadge
                    key={ag.id}
                    level={ag.assurance_level}
                    control={`${ag.name}: ${ag.assurance.control}`}
                  />
                ))}
              </HStack>
            </VStack>
            <Badge
              variant={device.hook_effective ? "success" : "warning"}
              icon={<GrdrIcon name={device.hook_effective ? "shield-check" : "shield-alert"} size={12} />}
              label={device.hook_effective ? "Hook active" : "User mode"}
            />
          </div>
        ))}
      </div>
    </div>
  );
}
