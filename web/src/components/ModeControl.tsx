import { Ban, CircleOff, Eye, Hand } from "lucide-react";
import type { Mode } from "../types";

interface ModeControlProps {
  value: Mode;
  locked?: boolean;
  onChange: (next: Mode) => void;
}

const SEGMENTS: ReadonlyArray<{ mode: Mode; label: string }> = [
  { mode: "off", label: "Off" },
  { mode: "watch", label: "Watch" },
  { mode: "ask", label: "Ask" },
  { mode: "block", label: "Block" },
];

export function ModeControl({ value, locked = false, onChange }: ModeControlProps) {
  return (
    <div className="mode-control" role="radiogroup" aria-label="Rule enforcement mode">
      {SEGMENTS.map((seg) => {
        const active = value === seg.mode;
        return (
          <button
            key={seg.mode}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={locked && !active && (seg.mode === "off" || seg.mode === "watch" || seg.mode === "ask")}
            className={`mode-seg ${seg.mode} ${active ? "active" : ""}`}
            onClick={() => {
              if (!active) onChange(seg.mode);
            }}
          >
            {seg.mode === "off" && <CircleOff size={13} />}
            {seg.mode === "watch" && <Eye size={13} />}
            {seg.mode === "ask" && <Hand size={13} />}
            {seg.mode === "block" && <Ban size={13} />}
            <span>{seg.label}</span>
          </button>
        );
      })}
    </div>
  );
}
