import { LayoutGrid } from "lucide-react";
import {
  SiAnthropic,
  SiApple,
  SiClaude,
  SiClaudecode,
  SiCursor,
  SiDebian,
  SiFedora,
  SiGithubcopilot,
  SiGoogle,
  SiGooglegemini,
  SiKong,
  SiLinux,
  SiMetaai,
  SiMistralai,
  SiModelcontextprotocol,
  SiOpencode,
  SiUbuntu,
  SiWindsurf,
} from "@icons-pack/react-simple-icons";
import guardrailsMarkPng from "./assets/guardrails-mark.png";
import heroWaveLightPng from "./assets/hero-wave-light.png";
import heroWaveDarkPng from "./assets/hero-wave-dark.png";
import { GrdrIcon, type GrdrIconName } from "./components";

export function iconKeyToName(iconKey: string): GrdrIconName {
  switch (iconKey) {
    case "mode.off":
      return "circle-off";
    case "mode.watch":
      return "eye";
    case "mode.ask":
      return "hand";
    case "mode.block":
      return "ban";
    case "verdict.allow":
      return "check";
    case "verdict.deny":
      return "ban";
    case "verdict.step_up":
      return "hand";
    case "verdict.modify":
      return "pencil";
    case "verdict.defer":
      return "clock";
    case "assurance.al0":
      return "list";
    case "assurance.al1":
      return "binoculars";
    case "assurance.al2":
      return "route";
    case "assurance.al3":
      return "box";
    case "assurance.al4":
      return "shield-check";
    case "security.lock":
      return "lock";
    case "security.alert":
      return "shield-alert";
    case "nav.home":
      return "home";
    case "nav.users":
      return "users";
    case "nav.inventory":
      return "cpu";
    case "nav.sessions":
      return "activity";
    case "nav.protect":
      return "shield";
    case "nav.respond":
      return "shield-alert";
    case "nav.coverage":
      return "shield-check";
    case "nav.tester":
      return "terminal";
    case "nav.first_run":
      return "check-circle";
    case "nav.review":
      return "list";
    case "nav.compliance":
      return "file-text";
    case "nav.settings":
      return "sliders-horizontal";
    case "nav.provider":
      return "layers";
    case "nav.operator_overview":
      return "server";
    case "nav.operator_health":
      return "heart-pulse";
    case "nav.operator_settings":
      return "settings";
    case "nav.operator_upgrades":
      return "refresh";
    case "nav.operator_backups":
      return "hard-drive";
    case "nav.operator_audit":
      return "file-text";
    default:
      return "shield";
  }
}

export function GuardrailsMark({
  size = 24,
  ariaLabel,
}: {
  size?: number;
  ariaLabel?: string;
}) {
  return (
    <img
      src={guardrailsMarkPng}
      width={size}
      height={size}
      alt={ariaLabel ?? ""}
      aria-hidden={ariaLabel ? undefined : true}
      className="grdr-brand-img"
    />
  );
}

export function HeroWaveBackdrop({ theme }: { theme: "light" | "dark" }) {
  return (
    <div className="grdr-hero-wave" aria-hidden="true">
      <img
        src={theme === "dark" ? heroWaveDarkPng : heroWaveLightPng}
        alt=""
        className="grdr-hero-wave-img"
      />
    </div>
  );
}

export function HarnessIcon({
  name,
  size = 15,
}: {
  name: string;
  size?: number;
}) {
  const norm = name.trim().toLowerCase();

  if (norm.includes("claude-code") || norm.includes("claude code")) {
    return <SiClaudecode size={size} color="var(--tone-ask)" aria-hidden="true" />;
  }
  if (norm.includes("claude")) {
    return <SiClaude size={size} color="var(--tone-ask)" aria-hidden="true" />;
  }
  if (norm.includes("anthropic")) {
    return <SiAnthropic size={size} color="var(--ink-primary)" aria-hidden="true" />;
  }
  if (norm.includes("cursor")) {
    return <SiCursor size={size} color="var(--accent-primary)" aria-hidden="true" />;
  }
  if (norm.includes("gemini")) {
    return <SiGooglegemini size={size} color="var(--accent-primary)" aria-hidden="true" />;
  }
  if (norm.includes("google")) {
    return <SiGoogle size={size} color="var(--accent-primary)" aria-hidden="true" />;
  }
  if (norm.includes("copilot")) {
    return <SiGithubcopilot size={size} color="var(--tone-allow)" aria-hidden="true" />;
  }
  if (norm.includes("windsurf")) {
    return <SiWindsurf size={size} color="var(--accent-primary)" aria-hidden="true" />;
  }
  if (norm.includes("opencode")) {
    return <SiOpencode size={size} color="var(--ink-primary)" aria-hidden="true" />;
  }
  if (norm.includes("meta") || norm.includes("llama")) {
    return <SiMetaai size={size} color="var(--accent-primary)" aria-hidden="true" />;
  }
  if (norm.includes("mistral")) {
    return <SiMistralai size={size} color="var(--tone-ask)" aria-hidden="true" />;
  }
  if (norm.includes("guardrails")) {
    return <GuardrailsMark size={size} />;
  }
  if (norm.includes("kong")) {
    return <SiKong size={size} color="var(--tone-allow)" aria-hidden="true" />;
  }
  if (norm.includes("mcp")) {
    return <SiModelcontextprotocol size={size} color="var(--ink-primary)" aria-hidden="true" />;
  }
  if (norm.includes("litellm")) {
    return <GrdrIcon name="layers" size={size} color="var(--accent-primary)" />;
  }
  if (norm.includes("azure")) {
    return <GrdrIcon name="box" size={size} color="var(--accent-primary)" />;
  }
  if (norm.includes("portkey")) {
    return <GrdrIcon name="route" size={size} color="var(--tone-ask)" />;
  }
  if (norm.includes("bedrock") || norm.includes("aws")) {
    return <GrdrIcon name="server" size={size} color="var(--tone-ask)" />;
  }
  if (norm.includes("codex") || norm.includes("openai")) {
    return <GrdrIcon name="key-round" size={size} color="var(--accent-primary)" />;
  }
  if (norm.includes("proxy") || norm.includes("gateway")) {
    return <GrdrIcon name="server" size={size} color="var(--accent-primary)" />;
  }

  return <GrdrIcon name="cpu" size={size} />;
}

export function OsIcon({
  os,
  size = 14,
}: {
  os: string;
  size?: number;
}) {
  const norm = os.trim().toLowerCase();

  if (norm.includes("darwin") || norm.includes("macos") || norm === "mac") {
    return <SiApple size={size} color="var(--ink-primary)" aria-hidden="true" />;
  }
  if (norm.includes("ubuntu")) {
    return <SiUbuntu size={size} color="var(--tone-ask)" aria-hidden="true" />;
  }
  if (norm.includes("debian")) {
    return <SiDebian size={size} color="var(--tone-block)" aria-hidden="true" />;
  }
  if (norm.includes("fedora")) {
    return <SiFedora size={size} color="var(--accent-primary)" aria-hidden="true" />;
  }
  if (norm.includes("linux")) {
    return <SiLinux size={size} color="var(--ink-primary)" aria-hidden="true" />;
  }
  if (norm.includes("win")) {
    return <LayoutGrid size={size} color="var(--accent-primary)" aria-hidden="true" />;
  }

  return <GrdrIcon name="hard-drive" size={size} color="var(--ink-secondary)" />;
}
