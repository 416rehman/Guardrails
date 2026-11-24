import { useEffect, type ReactNode } from "react";
import { createAgent, type AgentComponent } from "@ui-sdk/react/agent";
import {
  Drawer,
  DrawerBackdrop,
  DrawerContent,
  DrawerDescription,
  DrawerTitle,
} from "@ui-sdk/react/drawer";
import {
  SegmentedControl,
  SegmentedControlIndicator,
  SegmentedControlItem,
} from "@ui-sdk/react/segmented-control";
import { Button, GrdrIcon } from "./components";

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
  icon?: ReactNode;
  disabled?: boolean;
  tone?: string;
}

export function UiSdkSegmentedControl<T extends string>({
  value,
  options,
  ariaLabel,
  onChange,
}: {
  value: T;
  options: ReadonlyArray<SegmentedOption<T>>;
  ariaLabel: string;
  onChange: (next: T) => void;
}) {
  return (
    <SegmentedControl
      className="grdr-ui-segmented"
      aria-label={ariaLabel}
      value={value}
      onValueChange={(next) => {
        if (next && next !== value) {
          onChange(next);
        }
      }}
    >
      <SegmentedControlIndicator />
      {options.map((opt) => (
        <SegmentedControlItem
          key={opt.value}
          value={opt.value}
          disabled={opt.disabled}
          className="grdr-ui-seg-item"
          data-tone={opt.tone ?? opt.value}
        >
          {opt.icon}
          <span>{opt.label}</span>
        </SegmentedControlItem>
      ))}
    </SegmentedControl>
  );
}

export function UiSdkDrawer({
  open,
  onClose,
  title,
  description,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <Drawer
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) onClose();
      }}
      side="end"
    >
      <DrawerBackdrop className="grdr-ui-drawer-backdrop" />
      <DrawerContent className="grdr-ui-drawer-content" aria-label={title}>
        <div className="grdr-ui-drawer-header">
          <div>
            <DrawerTitle>{title}</DrawerTitle>
            {description && <DrawerDescription>{description}</DrawerDescription>}
          </div>
          <Button
            variant="secondary"
            size="sm"
            label="Close"
            aria-label={`Close ${title}`}
            icon={<GrdrIcon name="x" size={14} />}
            onClick={onClose}
          />
        </div>
        {children}
      </DrawerContent>
    </Drawer>
  );
}

export function UiSdkInlineBar({ children }: { children: ReactNode }) {
  return <div className="token-popover">{children}</div>;
}

/**
 * Exposes read-only UI SDK observability while enforcing S-17: agent-initiated
 * mutations on guarded surfaces are always refused without explicit human approval.
 */
export function useUiSdkReadOnlyAgentBridge(): AgentComponent[] {
  useEffect(() => {
    const agent = createAgent({
      allow: () => false,
    });
    return () => {
      void agent.snapshot();
    };
  }, []);

  return [];
}

export { Button };
