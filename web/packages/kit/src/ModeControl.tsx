import { pluralize, presentMode } from "@grdr/i18n";
import { GrdrIcon, Text, UiSdkSegmentedControl, VStack, iconKeyToName } from "@grdr/ui";

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
  const options = MODES.map((m) => {
    const pres = presentMode(m);
    const active = value === m;
    return {
      value: m,
      label: pres.label,
      icon: <GrdrIcon name={iconKeyToName(pres.iconKey)} size={13} />,
      disabled: locked && !active && (m === "off" || m === "watch" || m === "ask"),
      tone: m,
    };
  });

  return (
    <VStack gap={1}>
      <UiSdkSegmentedControl
        ariaLabel="Rule enforcement mode"
        value={value}
        options={options}
        onChange={onChange}
      />
      {typeof boundaryDevices === "number" && typeof requestDevices === "number" && (
        <Text type="supporting" color="secondary" size="sm">
          {requestDevices > 0
            ? `${presentMode(value).label} on ${pluralize(boundaryDevices, "sandboxed device")} and ${pluralize(requestDevices, "app-hook agent")}.`
            : `Applies in ${presentMode(value).label} mode across ${pluralize(boundaryDevices, "sandboxed device")}.`}
        </Text>
      )}
    </VStack>
  );
}
