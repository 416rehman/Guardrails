import { useEffect, useState } from "react";
import type { Device } from "@grdr/api";
import type { InventorySectionId } from "@grdr/i18n";
import { DeviceAssuranceDrawer, type EntityTarget } from "@grdr/kit";
import { Button, GrdrIcon, Heading, HStack, Text, UiSdkSegmentedControl, VStack } from "@grdr/ui";
import type { ConsoleSearchParams } from "../searchSchema";
import { ConnectSection } from "./ConnectSection";
import { InventoryAgentsSection } from "./InventoryAgentsSection";
import { InventoryEndpointsSection } from "./InventoryEndpointsSection";
import { InventoryMcpAndSkills } from "./InventoryMcpAndSkills";

const SECTION_SUBTITLES: Record<InventorySectionId, string> = {
  endpoints: "Enrolled endpoints, boundary protection status, and fleet topology.",
  agents: "Discovered AI coding harnesses, hook shims, and assurance tiers across your fleet.",
  mcps: "Model Context Protocol server definitions, transports, and digest pin status.",
  skills: "Discovered skills, standing rules, commands, and plugins with risk signals.",
  connect: "Endpoint installers, deployment wave keys, MDM payloads, and identity sync.",
};

export function InventoryPage({
  devices,
  searchQuery,
  urlSearch,
  onUpdateSearch,
  section,
  onSectionChange,
  selectedDeviceId,
  onSelectDevice,
  focusedEntity,
  onClearFocus,
  onOpenEntity,
  onRefresh,
}: {
  devices: Device[];
  searchQuery: string;
  urlSearch?: ConsoleSearchParams;
  onUpdateSearch?: (patch: Partial<ConsoleSearchParams>) => void;
  section: InventorySectionId;
  onSectionChange: (next: InventorySectionId) => void;
  selectedDeviceId: string | null;
  onSelectDevice: (deviceId: string | null) => void;
  focusedEntity?: EntityTarget | null;
  onClearFocus?: () => void;
  onOpenEntity?: (target: EntityTarget) => void;
  onRefresh: () => void;
}) {
  const [fallbackAgentFilter, setFallbackAgentFilter] = useState<string>("all");
  const agentFilter = urlSearch?.agent ?? fallbackAgentFilter;

  function setAgentFilter(next: string) {
    setFallbackAgentFilter(next);
    onUpdateSearch?.({
      agent: next === "all" ? undefined : next,
      pageToken: undefined,
      page: undefined,
    });
  }

  useEffect(() => {
    if (!focusedEntity) return;
    if (focusedEntity.kind === "device") {
      const match = devices.find((d) => d.id === focusedEntity.id || d.hostname === focusedEntity.label);
      if (match) {
        onSelectDevice(match.id);
        setFallbackAgentFilter("all");
      }
      onSectionChange("endpoints");
      onClearFocus?.();
    } else if (focusedEntity.kind === "agent") {
      setAgentFilter(focusedEntity.label.toLowerCase());
      onSelectDevice(null);
      onSectionChange("agents");
      onClearFocus?.();
    } else if (focusedEntity.kind === "mcp") {
      onSelectDevice(null);
      onSectionChange("mcps");
      onClearFocus?.();
    } else if (focusedEntity.kind === "artifact") {
      onSelectDevice(null);
      onSectionChange("skills");
      onClearFocus?.();
    }
  }, [focusedEntity, devices, onClearFocus, onSectionChange, onSelectDevice]);

  const selectedDevice = devices.find((d) => d.id === selectedDeviceId) ?? null;

  return (
    <VStack gap={4}>
      <div className="page-header">
        <div>
          <Heading level={1}>Inventory</Heading>
          <Text color="secondary">{SECTION_SUBTITLES[section]}</Text>
        </div>
        <HStack gap={2} align="center" style={{ flexWrap: "wrap" }}>
          <div className="inventory-section-tabs">
            <UiSdkSegmentedControl<InventorySectionId>
              ariaLabel="Inventory section"
              value={section}
              options={[
                { value: "endpoints", label: "Endpoints" },
                { value: "agents", label: "Agents" },
                { value: "mcps", label: "MCP servers" },
                { value: "skills", label: "Skills & rules" },
                { value: "connect", label: "Connect & MDM" },
              ]}
              onChange={onSectionChange}
            />
          </div>
          <Button label="Refresh inventory" icon={<GrdrIcon name="refresh" size={14} />} onClick={onRefresh} />
        </HStack>
      </div>

      {section === "connect" && <ConnectSection />}

      {section === "agents" && (
        <InventoryAgentsSection
          devices={devices}
          globalQuery={searchQuery}
          initialAgentFilter={agentFilter}
          urlSearch={urlSearch}
          onUpdateSearch={onUpdateSearch}
          onSelectDevice={(id) => onSelectDevice(id)}
          onOpenEntity={onOpenEntity}
        />
      )}

      {(section === "mcps" || section === "skills") && (
        <InventoryMcpAndSkills
          mode={section}
          devices={devices}
          globalQuery={searchQuery}
          urlSearch={urlSearch}
          onUpdateSearch={onUpdateSearch}
          onSelectDevice={(id) => onSelectDevice(id)}
          onOpenEntity={onOpenEntity}
        />
      )}

      {section === "endpoints" && (
        <InventoryEndpointsSection
          devices={devices}
          searchQuery={searchQuery}
          urlSearch={urlSearch}
          onUpdateSearch={onUpdateSearch}
          agentFilter={agentFilter}
          selectedDeviceId={selectedDevice?.id ?? null}
          onAgentFilterChange={setAgentFilter}
          onSelectDevice={onSelectDevice}
          onNavigateSection={onSectionChange}
        />
      )}

      <DeviceAssuranceDrawer
        device={selectedDevice}
        onOpenEntity={onOpenEntity}
        onClose={() => onSelectDevice(null)}
      />
    </VStack>
  );
}
