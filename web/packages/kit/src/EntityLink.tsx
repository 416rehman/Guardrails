import { formatOsName } from "@grdr/i18n";
import { GrdrIcon, HarnessIcon, HStack, OsIcon } from "@grdr/ui";

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
  const text = arch ? `${formatOsName(os)} / ${arch}` : formatOsName(os);
  return (
    <HStack gap={1} align="center">
      <OsIcon os={os} size={size} />
      <span>{text}</span>
    </HStack>
  );
}

export function EntityLink({
  kind,
  id,
  label,
  os,
  compact = false,
  onSelect,
}: {
  kind: EntityKind;
  id?: string;
  label: string;
  os?: string;
  compact?: boolean;
  onSelect?: (target: EntityTarget) => void;
}) {
  const targetId = id ?? label;
  const iconSize = compact ? 12 : 14;
  const icon =
    kind === "agent" ? (
      <HarnessIcon name={label} size={iconSize} />
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
      title={`Open ${kind}: ${label}`}
      onClick={(e) => {
        e.stopPropagation();
        onSelect?.({ kind, id: targetId, label });
      }}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}
