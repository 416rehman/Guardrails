// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { presentMode, t } from "@grdr/i18n";
import { GrdrIcon, Text, UiSdkSegmentedControl, VStack, iconKeyToName, useGrdrLocale } from "@grdr/ui";

type Mode = "off" | "watch" | "ask" | "block";
const MODES: ReadonlyArray<Mode> = ["off", "watch", "ask", "block"];

export function ModeControl({
  value,
  locked = false,
  boundaryDevices,
  requestDevices,
  onChange,
}: {
  value: Mode;
  locked?: boolean;
  boundaryDevices?: number;
  requestDevices?: number;
  onChange: (next: Mode) => void;
}) {
  const { locale } = useGrdrLocale();
  const options = MODES.map((m) => {
    const pres = presentMode(m, locale);
    const active = value === m;
    return {
      value: m,
      label: pres.label,
      icon: <GrdrIcon name={iconKeyToName(pres.iconKey)} size={13} />,
      disabled: locked && !active && (m === "off" || m === "watch" || m === "ask"),
      tone: m,
    };
  });

  const modeLabel = presentMode(value, locale).label;
  const summaryText =
    typeof boundaryDevices === "number" && typeof requestDevices === "number"
      ? requestDevices > 0
        ? t(
            "kit.mode_control.scope_with_requests",
            {
              modeLabel,
              boundaryDevicesText: t("common.count.sandboxed_devices", { count: boundaryDevices }, locale),
              requestAgentsText: t("common.count.hook_agents", { count: requestDevices }, locale),
            },
            locale,
          )
        : t(
            "kit.mode_control.scope_boundary_only",
            {
              modeLabel,
              boundaryDevicesText: t("common.count.sandboxed_devices", { count: boundaryDevices }, locale),
            },
            locale,
          )
      : null;

  return (
    <VStack gap={1}>
      <UiSdkSegmentedControl
        ariaLabel={t("kit.mode_control.aria_label", undefined, locale)}
        value={value}
        options={options}
        onChange={onChange}
      />
      {summaryText && (
        <Text type="supporting" color="secondary" size="sm">
          {summaryText}
        </Text>
      )}
    </VStack>
  );
}
