// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { presentAssurance, presentMode, presentSessionLabel, presentVerdict } from "@grdr/i18n";
import { Badge, GrdrIcon, iconKeyToName, useGrdrLocale, type BadgeVariant } from "@grdr/ui";

export function ModeBadge({ mode }: { mode: "off" | "watch" | "ask" | "block" }) {
  const { locale } = useGrdrLocale();
  const pres = presentMode(mode, locale);
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
  const { locale } = useGrdrLocale();
  const pres = presentVerdict(verdict, locale);
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
  const { locale } = useGrdrLocale();
  const pres = presentAssurance(level, control, locale);
  const variant: BadgeVariant =
    pres.tone === "success" ? "success" : pres.tone === "warning" ? "warning" : "neutral";
  return (
    <span title={pres.description} style={{ display: "inline-flex" }}>
      <Badge
        variant={variant}
        icon={<GrdrIcon name={iconKeyToName(pres.iconKey)} size={12} />}
        label={<bdi>{pres.label}</bdi>}
      />
    </span>
  );
}

export function SessionLabelBadge({
  label,
}: {
  label: "credential_accessed" | "untrusted_web_fetched" | "repeated_denials" | "tainted_exfil_risk";
}) {
  const { locale } = useGrdrLocale();
  const pres = presentSessionLabel(label, locale);
  const variant: BadgeVariant =
    pres.tone === "danger"
      ? "error"
      : pres.tone === "warning"
        ? "warning"
        : pres.tone === "success"
          ? "success"
          : pres.tone === "neutral"
            ? "neutral"
            : "info";
  return (
    <Badge
      variant={variant}
      icon={<GrdrIcon name={iconKeyToName(pres.iconKey)} size={11} />}
      label={pres.text}
    />
  );
}
