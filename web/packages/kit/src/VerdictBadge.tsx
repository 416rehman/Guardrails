import { presentAssurance, presentMode, presentSessionLabel, presentVerdict } from "@grdr/i18n";
import { Badge, GrdrIcon, iconKeyToName, type BadgeVariant } from "@grdr/ui";

export function ModeBadge({ mode }: { mode: "off" | "watch" | "ask" | "block" }) {
  const pres = presentMode(mode);
  const variant: BadgeVariant =
    pres.tone === "danger"
      ? "error"
      : pres.tone === "warning"
        ? "warning"
        : pres.tone === "info"
          ? "info"
          : "neutral";
  return (
    <Badge
      variant={variant}
      icon={<GrdrIcon name={iconKeyToName(pres.iconKey)} size={12} />}
      label={pres.label}
    />
  );
}

export function VerdictBadge({
  verdict,
}: {
  verdict: "allow" | "modify" | "step_up" | "defer" | "deny";
}) {
  const pres = presentVerdict(verdict);
  const variant: BadgeVariant =
    pres.tone === "danger"
      ? "error"
      : pres.tone === "warning"
        ? "warning"
        : pres.tone === "info"
          ? "info"
          : pres.tone === "success"
            ? "success"
            : "neutral";
  return (
    <Badge
      variant={variant}
      icon={<GrdrIcon name={iconKeyToName(pres.iconKey)} size={12} />}
      label={pres.label}
    />
  );
}

export function AssuranceBadge({
  level,
  control,
}: {
  level: "AL0" | "AL1" | "AL2" | "AL3" | "AL4";
  control: string;
}) {
  const pres = presentAssurance(level, control);
  const variant: BadgeVariant =
    pres.tone === "success" ? "success" : pres.tone === "warning" ? "warning" : "neutral";
  return (
    <Badge
      variant={variant}
      icon={<GrdrIcon name={iconKeyToName(pres.iconKey)} size={12} />}
      label={`${pres.level} (${pres.controlLabel})`}
    />
  );
}

export function SessionLabelBadge({
  label,
}: {
  label: "credential_accessed" | "untrusted_web_fetched" | "repeated_denials" | "tainted_exfil_risk";
}) {
  const pres = presentSessionLabel(label);
  const variant: BadgeVariant =
    pres.tone === "danger" ? "error" : pres.tone === "warning" ? "warning" : "info";
  return <Badge variant={variant} label={pres.text} />;
}
