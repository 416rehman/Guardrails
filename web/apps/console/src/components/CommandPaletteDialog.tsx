import { Badge, Dialog, GrdrIcon, HStack, TextInput } from "@grdr/ui";
import type { PaletteCommand } from "./navigation";

export function CommandPaletteDialog({
  open,
  searchQuery,
  commands,
  onOpenChange,
  onSearchQueryChange,
}: {
  open: boolean;
  searchQuery: string;
  commands: PaletteCommand[];
  onOpenChange: (open: boolean) => void;
  onSearchQueryChange: (q: string) => void;
}) {
  return (
    <Dialog
      isOpen={open}
      onOpenChange={onOpenChange}
      purpose="info"
      width={560}
      padding={2}
      aria-label="Command palette"
    >
      <div style={{ padding: "var(--space-1)" }}>
        <TextInput
          label="Filter commands"
          isLabelHidden
          placeholder="Type a screen, device hostname, or action..."
          startIcon={<GrdrIcon name="search" size={14} color="var(--ink-muted)" />}
          value={searchQuery}
          onChange={onSearchQueryChange}
          width="100%"
        />
      </div>
      <div className="command-list">
        {commands.map((cmd) => (
          <button key={cmd.id} type="button" className="command-item" onClick={cmd.run}>
            <span>{cmd.label}</span>
            <HStack gap={1} align="center">
              <Badge variant="neutral" label={cmd.hint} />
            </HStack>
          </button>
        ))}
      </div>
    </Dialog>
  );
}
