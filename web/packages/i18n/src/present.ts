const AGENT_DISPLAY_MAP: Record<string, string> = {
  "claude-code": "Claude Code",
  claude: "Claude",
  codex: "Codex",
  cursor: "Cursor",
  gemini: "Gemini",
  "gemini-cli": "Gemini CLI",
  "github-copilot": "GitHub Copilot",
  opencode: "OpenCode",
  windsurf: "Windsurf",
};

export function capitalizeLabel(value: string): string {
  if (!value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
}

export function presentAgentName(raw: string): string {
  const trimmed = raw.trim();
  return AGENT_DISPLAY_MAP[trimmed.toLowerCase()] ?? trimmed;
}

export function formatActionLabel(actionClass: string): string {
  switch (actionClass) {
    case "exec":
    case "Exec":
      return "Command run";
    case "file.read":
    case "FileRead":
      return "File read";
    case "file.write":
    case "FileWrite":
      return "File write";
    case "file.delete":
    case "FileDelete":
      return "File delete";
    case "net.connect":
    case "NetConnect":
      return "Network connect";
    case "net.request":
    case "NetRequest":
      return "Network request";
    case "llm.request":
    case "LlmRequest":
      return "LLM request";
    case "mcp.connect":
    case "McpConnect":
      return "MCP connect";
    case "mcp.call":
    case "McpCall":
      return "Tool call";
    case "cred.use":
    case "CredUse":
      return "Credential access";
    case "agent.spawn":
    case "AgentSpawn":
      return "Agent spawn";
    case "config.change":
    case "ConfigChange":
      return "Config change";
    case "elevate":
    case "Elevate":
      return "Privilege elevation";
    case "ui.act":
    case "UiAct":
      return "UI action";
    case "data.flow":
    case "DataFlow":
      return "Data transfer";
    default:
      return actionClass;
  }
}

export function presentFindingTitle(rawTitle: string, agentName?: string): string {
  let clean = rawTitle
    .replace(
      /\b(?:exec|file\.read|file\.write|file\.delete|net\.connect|net\.request|llm\.request|mcp\.connect|mcp\.call|cred\.use|agent\.spawn|config\.change|elevate|ui\.act|data\.flow|Exec|FileRead|FileWrite|FileDelete|NetConnect|NetRequest|LlmRequest|McpConnect|McpCall|CredUse|AgentSpawn|ConfigChange|Elevate|UiAct|DataFlow)\b/g,
      (token) => formatActionLabel(token),
    )
    .replace(
      /\b(?:claude-code|gemini-cli|github-copilot)\b/gi,
      (slug) => presentAgentName(slug),
    );
  if (agentName) {
    const candidates = Array.from(
      new Set([
        agentName.trim().toLowerCase(),
        presentAgentName(agentName).toLowerCase(),
      ]),
    ).filter(Boolean);
    for (const target of candidates) {
      const trimmed = clean.trim();
      const lower = trimmed.toLowerCase();
      const onSuffix = ` on ${target}`;
      const parenSuffix = `(${target})`;
      if (lower.endsWith(onSuffix)) {
        clean = trimmed.slice(0, trimmed.length - onSuffix.length);
        break;
      }
      if (lower.endsWith(parenSuffix)) {
        clean = trimmed.slice(0, trimmed.length - parenSuffix.length);
        break;
      }
    }
  }
  return clean.trim();
}

export function presentIncidentTitle(rawTitle: string): string {
  return rawTitle
    .replace(
      /\b(?:claude-code|gemini-cli|github-copilot|opencode|windsurf|cursor|codex)\b/gi,
      (slug) => presentAgentName(slug),
    )
    .trim();
}

export function presentIncidentSummary(rawSummary: string): string {
  const cleaned = rawSummary
    .replace(
      /\b(?:exec|file\.read|file\.write|file\.delete|net\.connect|net\.request|mcp\.call|cred\.use|elevate|config\.change|data\.flow)\b/g,
      (token) => formatActionLabel(token).toLowerCase(),
    )
    .replace(
      /\b(?:claude-code|gemini-cli|github-copilot)\b/gi,
      (slug) => presentAgentName(slug),
    )
    .replace(/\s*;\s*/g, ". ")
    .trim();
  if (!cleaned) return cleaned;
  return /[.!?]$/.test(cleaned) ? cleaned : `${cleaned}.`;
}

export function presentArtifactKind(kind: string): string {
  switch (kind) {
    case "skill":
      return "Skill";
    case "rule":
      return "Rule";
    case "plugin":
      return "Plugin";
    case "command":
      return "Command";
    case "subagent":
      return "Subagent";
    default:
      return capitalizeLabel(kind);
  }
}

export function presentArtifactScope(scope: string): string {
  switch (scope) {
    case "user":
      return "User";
    case "workspace":
      return "Workspace";
    case "managed":
      return "Managed";
    default:
      return capitalizeLabel(scope);
  }
}

export function presentArtifactRiskFlag(flag: string): string {
  switch (flag) {
    case "has-scripts":
      return "Has scripts";
    case "requests-broad-tools":
      return "Broad tools";
    case "bidi-obfuscation":
      return "Bidi obfuscation";
    case "unpinned-digest":
      return "Unpinned digest";
    default:
      return capitalizeLabel(flag.replace(/-/g, " "));
  }
}
