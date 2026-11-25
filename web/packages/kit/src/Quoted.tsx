import { GrdrIcon } from "@grdr/ui";

function hasBidiOrControl(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (
      (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) ||
      (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069)
    ) {
      return true;
    }
  }
  return false;
}

export function Quoted({ text }: { text: string }) {
  const flagged = hasBidiOrControl(text);
  return (
    <span
      className="grdr-ui-quoted"
      title={flagged ? "Contains hidden or directional control characters" : undefined}
    >
      <bdi dir="ltr">{text}</bdi>
      {flagged && (
        <GrdrIcon
          name="alert-triangle"
          size={12}
          ariaLabel="Control or bidirectional character flagged"
        />
      )}
    </span>
  );
}
