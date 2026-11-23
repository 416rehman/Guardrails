import { AlertTriangle } from "lucide-react";

interface QuotedProps {
  text: string;
}

function hasBidiOrControl(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (
      code < 0x20 ||
      (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069)
    ) {
      return true;
    }
  }
  return false;
}

export function Quoted({ text }: QuotedProps) {
  const flagged = hasBidiOrControl(text);
  return (
    <span className="quoted-text" title={flagged ? "Contains hidden or directional control characters" : undefined}>
      <bdi dir="ltr">{text}</bdi>
      {flagged && (
        <AlertTriangle size={12} aria-label="Control or bidirectional character flagged" />
      )}
    </span>
  );
}
