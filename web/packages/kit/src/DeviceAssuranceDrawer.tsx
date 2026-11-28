// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { formatOsName, presentAssurance, t, type LocaleCode } from "@grdr/i18n";
import {
  Badge,
  type GrdrFlowEdge,
  type GrdrFlowNode,
  GrdrFlowGraph,
  GrdrIcon,
  Heading,
  HStack,
  OsIcon,
  Text,
  UiSdkDrawer,
  VStack,
  useGrdrLocale,
} from "@grdr/ui";
import { EntityLink, type EntityTarget } from "./EntityLink";
import { AssuranceBadge } from "./VerdictBadge";
import { Quoted } from "./Quoted";

function friendlyVisibility(visibility: string, failMode: string, locale: LocaleCode): string {
  const vis =
    visibility === "observed"
      ? t("kit.device.vis_verified", undefined, locale)
      : t("kit.device.vis_unverified", undefined, locale);
  const fail = failMode.includes("closed")
    ? t("kit.device.fail_closed", undefined, locale)
    : t("kit.device.fail_open", undefined, locale);
  return `${vis} · ${fail}`;
}

function friendlyTamper(tamper: string, locale: LocaleCode): string {
  return tamper === "admin"
    ? t("kit.device.tamper_admin", undefined, locale)
    : t("kit.device.tamper_user", undefined, locale);
}

export interface MatrixDevice {
  id: string;
  hostname: string;
  os: string;
  arch: string;
  install_profile: string;
  hook_effective: boolean;
  agents: ReadonlyArray<{
    id: string;
    name: string;
    kind: string;
    config_path: string;
    hook_installed: boolean;
    assurance_level: "AL0" | "AL1" | "AL2" | "AL3" | "AL4";
    assurance: { visibility: string; control: string; on_failure: string; tamper: string };
  }>;
  mcp_servers: ReadonlyArray<{
    name: string;
    transport: string;
    command: string;
    pinned: boolean;
  }>;
}

export function DeviceAssuranceDrawer({
  device,
  onOpenEntity,
  onClose,
}: {
  device: MatrixDevice | null;
  onOpenEntity?: (target: EntityTarget) => void;
  onClose: () => void;
}) {
  const { locale } = useGrdrLocale();
  const assetNodes: GrdrFlowNode[] = [];
  const assetEdges: GrdrFlowEdge[] = [];
  if (device) {
    assetNodes.push({
      id: "device-host",
      label: device.hostname,
      subtitle: `${formatOsName(device.os, locale)} / ${device.arch}`,
      badge: t("kit.device.badge_host", undefined, locale),
      tone: "accent",
      icon: "cpu",
    });
    for (const ag of device.agents) {
      const pres = presentAssurance(ag.assurance_level, ag.assurance.control, locale);
      const nodeTone =
        pres.tone === "success" ? "allow" : pres.tone === "warning" ? "ask" : "neutral";
      assetNodes.push({
        id: `ag-${ag.id}`,
        label: ag.name,
        subtitle: pres.controlLabel,
        badge: pres.label,
        tone: nodeTone,
        harnessName: ag.name,
      });
      assetEdges.push({
        id: `edge-host-${ag.id}`,
        source: "device-host",
        target: `ag-${ag.id}`,
        tone: pres.tone === "success" ? "allow" : "neutral",
      });
    }
    const primaryAgentId = device.agents[0] ? `ag-${device.agents[0].id}` : "device-host";
    device.mcp_servers.forEach((mcp, idx) => {
      const mcpId = `mcp-${idx}-${mcp.name}`;
      assetNodes.push({
        id: mcpId,
        label: mcp.name,
        subtitle: mcp.transport,
        badge: mcp.pinned
          ? t("kit.device.badge_pinned", undefined, locale)
          : t("kit.device.badge_unpinned", undefined, locale),
        tone: mcp.pinned ? "allow" : "ask",
        icon: "plug",
      });
      assetEdges.push({
        id: `edge-${primaryAgentId}-${mcpId}`,
        source: primaryAgentId,
        target: mcpId,
        dashed: !mcp.pinned,
        tone: mcp.pinned ? "allow" : "neutral",
      });
    });
  }

  return (
    <UiSdkDrawer
      open={device !== null}
      onClose={onClose}
      title={t("kit.device.title", undefined, locale)}
      description={device ? `${device.hostname} (${device.id})` : undefined}
    >
      {device && (
        <VStack gap={3}>
          <HStack gap={2}>
            <Badge
              variant="info"
              icon={<GrdrIcon name={device.install_profile === "protected" ? "shield-check" : "shield-half"} size={12} />}
              label={
                device.install_profile === "protected"
                  ? t("kit.device.profile_protected", undefined, locale)
                  : t("kit.device.profile_user", undefined, locale)
              }
            />
            <Badge
              variant={device.hook_effective ? "success" : "warning"}
              icon={<GrdrIcon name={device.hook_effective ? "check-circle" : "alert-triangle"} size={12} />}
              label={
                device.hook_effective
                  ? t("kit.device.hook_active", undefined, locale)
                  : t("kit.device.discovery_only", undefined, locale)
              }
            />
            <Badge
              variant="neutral"
              icon={<OsIcon os={device.os} size={12} />}
              label={<bdi>{`${formatOsName(device.os, locale)} / ${device.arch}`}</bdi>}
            />
          </HStack>

          <VStack gap={1}>
            <HStack gap={1} align="center">
              <GrdrIcon name="route" size={14} color="var(--accent-primary)" />
              <Text size="sm" style={{ fontWeight: 600 }}>
                {t("kit.device.topology", undefined, locale)}
              </Text>
            </HStack>
            <GrdrFlowGraph
              nodes={assetNodes}
              edges={assetEdges}
              direction="LR"
              height={236}
              ariaLabel={`${t("kit.device.topology", undefined, locale)}: ${device.hostname}`}
            />
          </VStack>

          <VStack gap={2}>
            <Heading level={3}>{t("kit.device.agent_protection", { count: device.agents.length }, locale)}</Heading>
            {device.agents.length === 0 ? (
              <Text color="secondary">{t("kit.device.no_agents", undefined, locale)}</Text>
            ) : (
              <div className="table-wrap">
                <table style={{ tableLayout: "fixed", width: "100%" }}>
                  <colgroup>
                    <col style={{ width: "22%" }} />
                    <col style={{ width: "18%" }} />
                    <col style={{ width: "26%" }} />
                    <col style={{ width: "34%" }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>{t("kit.device.col_agent", undefined, locale)}</th>
                      <th>{t("kit.device.col_protection", undefined, locale)}</th>
                      <th>{t("kit.device.col_verification", undefined, locale)}</th>
                      <th>{t("kit.device.col_config", undefined, locale)}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {device.agents.map((agent) => (
                      <tr key={agent.id}>
                        <td>
                          <EntityLink
                            kind="agent"
                            id={agent.id}
                            label={agent.name}
                            compact
                            onSelect={onOpenEntity}
                          />
                          <div style={{ fontSize: 12, color: "var(--ink-muted)", marginTop: 3 }}>
                            {friendlyTamper(agent.assurance.tamper, locale)}
                          </div>
                        </td>
                        <td>
                          <AssuranceBadge
                            level={agent.assurance_level}
                            control={agent.assurance.control}
                          />
                        </td>
                        <td>
                          <div>
                            {friendlyVisibility(agent.assurance.visibility, agent.assurance.on_failure, locale)}
                          </div>
                          <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>
                            {agent.hook_installed
                              ? t("kit.device.hook_active", undefined, locale)
                              : t("kit.device.hook_absent", undefined, locale)}
                          </div>
                        </td>
                        <td title={agent.config_path}>
                          <Quoted text={agent.config_path} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </VStack>

          <VStack gap={2}>
            <Heading level={3}>{t("kit.device.mcp_inventory", { count: device.mcp_servers.length }, locale)}</Heading>
            {device.mcp_servers.length === 0 ? (
              <Text color="secondary">{t("kit.device.no_mcp", undefined, locale)}</Text>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>{t("kit.device.col_server", undefined, locale)}</th>
                      <th>{t("kit.device.col_transport", undefined, locale)}</th>
                      <th>{t("kit.device.col_digest_pin", undefined, locale)}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {device.mcp_servers.map((mcp, idx) => (
                      <tr key={`${mcp.name}-${idx}`}>
                        <td>
                          <EntityLink
                            kind="mcp"
                            id={mcp.name}
                            label={mcp.name}
                            compact
                            onSelect={onOpenEntity}
                          />
                          <div style={{ marginTop: 4 }}>
                            <Quoted text={mcp.command} />
                          </div>
                        </td>
                        <td>
                          <HStack gap={1} align="center">
                            <GrdrIcon
                              name={mcp.transport.toLowerCase() === "stdio" ? "terminal" : "globe"}
                              size={12}
                              color="var(--ink-secondary)"
                            />
                            <span className="mono"><bdi dir="ltr">{mcp.transport}</bdi></span>
                          </HStack>
                        </td>
                        <td>
                          <Badge
                            variant={mcp.pinned ? "success" : "warning"}
                            icon={<GrdrIcon name={mcp.pinned ? "lock" : "alert-triangle"} size={11} />}
                            label={
                              mcp.pinned
                                ? t("kit.device.badge_pinned", undefined, locale)
                                : t("kit.device.badge_unpinned", undefined, locale)
                            }
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </VStack>
        </VStack>
      )}
    </UiSdkDrawer>
  );
}
