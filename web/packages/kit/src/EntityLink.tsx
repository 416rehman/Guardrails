// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { formatOsName, presentAgentName, t, type CatalogHarnessPresentation } from "@grdr/i18n";
import { GrdrIcon, HarnessIcon, HStack, OsIcon, useGrdrLocale } from "@grdr/ui";

export type EntityKind =
  | "device"
  | "agent"
  | "session"
  | "rule"
  | "mcp"
  | "user"
  | "artifact";

export interface EntityTarget {
  kind: EntityKind;
  id: string;
  label: string;
}

export function OsLabel({
  os,
  arch,
  size = 13,
}: {
  os: string;
  arch?: string;
  size?: number;
}) {
  const { locale } = useGrdrLocale();
  const formatted = formatOsName(os, locale);
  const text = arch ? `${formatted} / ${arch}` : formatted;
  return (
    <HStack gap={1} align="center">
      <OsIcon os={os} size={size} />
      <span>{text}</span>
    </HStack>
  );
}

function formatEntityLabel(
  kind: EntityKind,
  label: string,
  extraCatalog?: ReadonlyArray<CatalogHarnessPresentation>,
): string {
  if (kind !== "agent") return label;
  return presentAgentName(label, extraCatalog);
}

export function EntityLink({
  kind,
  id,
  label,
  os,
  compact = false,
  extraCatalog,
  onSelect,
}: {
  kind: EntityKind;
  id?: string;
  label: string;
  os?: string;
  compact?: boolean;
  extraCatalog?: ReadonlyArray<CatalogHarnessPresentation>;
  onSelect?: (target: EntityTarget) => void;
}) {
  const { locale } = useGrdrLocale();
  const targetId = id ?? label;
  const displayLabel = formatEntityLabel(kind, label, extraCatalog);
  const iconSize = compact ? 12 : 14;
  const icon =
    kind === "agent" ? (
      <HarnessIcon name={label} size={iconSize} extraCatalog={extraCatalog} />
    ) : kind === "device" && os ? (
      <OsIcon os={os} size={iconSize} />
    ) : (
      <GrdrIcon
        name={
          kind === "device"
            ? "hard-drive"
            : kind === "session"
              ? "activity"
              : kind === "rule"
                ? "shield"
                : kind === "user"
                  ? "user"
                  : kind === "artifact"
                    ? "file-code"
                    : "plug"
        }
        size={iconSize}
      />
    );

  return (
    <button
      type="button"
      className={compact ? "grdr-entity-link compact" : "grdr-entity-link"}
      data-entity-kind={kind}
      title={t("kit.entity.open_label", { kind, label: displayLabel }, locale)}
      onClick={(e) => {
        e.stopPropagation();
        onSelect?.({ kind, id: targetId, label: displayLabel });
      }}
    >
      {icon}
      <bdi>{displayLabel}</bdi>
    </button>
  );
}
