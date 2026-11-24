import type { ReactNode } from "react";
import { type BadgeVariant } from "@astryxdesign/core/Badge";
import { Banner, type BannerStatus } from "@astryxdesign/core/Banner";
import { Button, type ButtonSize, type ButtonVariant } from "@astryxdesign/core/Button";
import { Card, type CardVariant } from "@astryxdesign/core/Card";
import { CheckboxInput } from "@astryxdesign/core/CheckboxInput";
import { Dialog } from "@astryxdesign/core/Dialog";
import { Divider } from "@astryxdesign/core/Divider";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { IconButton } from "@astryxdesign/core/IconButton";
import { Kbd } from "@astryxdesign/core/Kbd";
import { Pagination } from "@astryxdesign/core/Pagination";
import { ProgressBar } from "@astryxdesign/core/ProgressBar";
import { Selector, type SelectorOptionData } from "@astryxdesign/core/Selector";
import { HStack, VStack } from "@astryxdesign/core/Stack";
import { Switch } from "@astryxdesign/core/Switch";
import { Heading, Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { Tooltip } from "@astryxdesign/core/Tooltip";
import {
  SiAnthropic,
  SiApple,
  SiClaude,
  SiClaudecode,
  SiCloudflare,
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
import {
  Activity,
  AlertCircle,
  AlertOctagon,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Ban,
  Binoculars,
  Box,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Circle,
  CircleOff,
  Clock,
  Code2,
  Cpu,
  Download,
  Eye,
  FileCode2,
  FileJson,
  FileText,
  GitBranch,
  GitFork,
  Globe,
  Hand,
  HardDrive,
  HeartPulse,
  Home,
  KeyRound,
  Layers,
  LayoutGrid,
  List,
  Lock,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Pencil,
  Play,
  Plug,
  Plus,
  PlusCircle,
  Radio,
  RefreshCw,
  Route,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  ShieldOff,
  SlidersHorizontal,
  Sun,
  Tag,
  Terminal,
  Trash2,
  User,
  Users,
  X,
  ZoomIn,
  ZoomOut,
  Maximize2,
} from "lucide-react";

export function Badge({
  variant = "neutral",
  label,
  icon,
  children,
  className,
  title,
}: {
  variant?: BadgeVariant;
  label?: ReactNode;
  icon?: ReactNode;
  children?: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      className={className ? `grdr-badge ${className}` : "grdr-badge"}
      data-variant={variant}
      title={title}
    >
      {icon ? <span className="grdr-badge-icon" aria-hidden="true">{icon}</span> : null}
      <span>{label ?? children}</span>
    </span>
  );
}

export function StatusInline({
  tone = "neutral",
  icon,
  dot = false,
  dotColor,
  label,
}: {
  tone?: "allow" | "watch" | "ask" | "block" | "neutral";
  icon?: ReactNode;
  dot?: boolean;
  dotColor?: string;
  label: ReactNode;
}) {
  return (
    <span className="grdr-status-inline" data-tone={tone}>
      {dot ? (
        <span
          className="grdr-status-dot"
          style={dotColor ? { backgroundColor: dotColor } : undefined}
          aria-hidden="true"
        />
      ) : null}
      {icon ? <span className="grdr-status-icon" aria-hidden="true">{icon}</span> : null}
      <span>{label}</span>
    </span>
  );
}

export {
  Banner,
  Button,
  Card,
  CheckboxInput,
  Dialog,
  Divider,
  EmptyState,
  Heading,
  HStack,
  IconButton,
  Kbd,
  Pagination,
  ProgressBar,
  Selector,
  Switch,
  Text,
  TextInput,
  Tooltip,
  VStack,
};
export type { BadgeVariant, BannerStatus, ButtonSize, ButtonVariant, CardVariant, SelectorOptionData };

export type GrdrIconName =
  | "activity"
  | "alert-circle"
  | "alert-octagon"
  | "alert-triangle"
  | "arrow-left"
  | "arrow-right"
  | "ban"
  | "binoculars"
  | "box"
  | "check"
  | "check-circle"
  | "chevron-down"
  | "chevron-right"
  | "circle"
  | "circle-off"
  | "clock"
  | "code"
  | "cpu"
  | "download"
  | "eye"
  | "file-code"
  | "file-json"
  | "file-text"
  | "git-branch"
  | "git-fork"
  | "globe"
  | "hand"
  | "hard-drive"
  | "heart-pulse"
  | "home"
  | "key-round"
  | "layers"
  | "layout-grid"
  | "list"
  | "lock"
  | "moon"
  | "panel-left-close"
  | "panel-left-open"
  | "pencil"
  | "play"
  | "plug"
  | "plus"
  | "plus-circle"
  | "radio"
  | "refresh"
  | "route"
  | "search"
  | "server"
  | "settings"
  | "shield"
  | "shield-alert"
  | "shield-check"
  | "shield-half"
  | "shield-off"
  | "sliders-horizontal"
  | "sun"
  | "tag"
  | "terminal"
  | "trash"
  | "user"
  | "users"
  | "x"
  | "zoom-in"
  | "zoom-out"
  | "maximize";

export function GrdrIcon({
  name,
  size = 14,
  color,
  ariaLabel,
}: {
  name: GrdrIconName;
  size?: number;
  color?: string;
  ariaLabel?: string;
}) {
  const props = {
    size,
    color,
    ...(ariaLabel ? { "aria-label": ariaLabel } : { "aria-hidden": true as const }),
  };

  switch (name) {
    case "activity":
      return <Activity {...props} />;
    case "alert-circle":
      return <AlertCircle {...props} />;
    case "alert-octagon":
      return <AlertOctagon {...props} />;
    case "alert-triangle":
      return <AlertTriangle {...props} />;
    case "arrow-left":
      return <ArrowLeft {...props} />;
    case "arrow-right":
      return <ArrowRight {...props} />;
    case "ban":
      return <Ban {...props} />;
    case "binoculars":
      return <Binoculars {...props} />;
    case "box":
      return <Box {...props} />;
    case "check":
      return <Check {...props} />;
    case "check-circle":
      return <CheckCircle2 {...props} />;
    case "chevron-down":
      return <ChevronDown {...props} />;
    case "chevron-right":
      return <ChevronRight {...props} />;
    case "circle":
      return <Circle {...props} />;
    case "circle-off":
      return <CircleOff {...props} />;
    case "clock":
      return <Clock {...props} />;
    case "code":
      return <Code2 {...props} />;
    case "cpu":
      return <Cpu {...props} />;
    case "download":
      return <Download {...props} />;
    case "eye":
      return <Eye {...props} />;
    case "file-code":
      return <FileCode2 {...props} />;
    case "file-json":
      return <FileJson {...props} />;
    case "file-text":
      return <FileText {...props} />;
    case "git-branch":
      return <GitBranch {...props} />;
    case "git-fork":
      return <GitFork {...props} />;
    case "globe":
      return <Globe {...props} />;
    case "hand":
      return <Hand {...props} />;
    case "hard-drive":
      return <HardDrive {...props} />;
    case "heart-pulse":
      return <HeartPulse {...props} />;
    case "home":
      return <Home {...props} />;
    case "key-round":
      return <KeyRound {...props} />;
    case "layers":
      return <Layers {...props} />;
    case "layout-grid":
      return <LayoutGrid {...props} />;
    case "list":
      return <List {...props} />;
    case "lock":
      return <Lock {...props} />;
    case "moon":
      return <Moon {...props} />;
    case "panel-left-close":
      return <PanelLeftClose {...props} />;
    case "panel-left-open":
      return <PanelLeftOpen {...props} />;
    case "pencil":
      return <Pencil {...props} />;
    case "play":
      return <Play {...props} />;
    case "plug":
      return <Plug {...props} />;
    case "plus":
      return <Plus {...props} />;
    case "plus-circle":
      return <PlusCircle {...props} />;
    case "radio":
      return <Radio {...props} />;
    case "refresh":
      return <RefreshCw {...props} />;
    case "route":
      return <Route {...props} />;
    case "search":
      return <Search {...props} />;
    case "server":
      return <Server {...props} />;
    case "settings":
      return <Settings {...props} />;
    case "shield":
      return <Shield {...props} />;
    case "shield-alert":
      return <ShieldAlert {...props} />;
    case "shield-check":
      return <ShieldCheck {...props} />;
    case "shield-half":
      return <ShieldHalf {...props} />;
    case "shield-off":
      return <ShieldOff {...props} />;
    case "sliders-horizontal":
      return <SlidersHorizontal {...props} />;
    case "sun":
      return <Sun {...props} />;
    case "tag":
      return <Tag {...props} />;
    case "terminal":
      return <Terminal {...props} />;
    case "trash":
      return <Trash2 {...props} />;
    case "user":
      return <User {...props} />;
    case "users":
      return <Users {...props} />;
    case "x":
      return <X {...props} />;
    case "zoom-in":
      return <ZoomIn {...props} />;
    case "zoom-out":
      return <ZoomOut {...props} />;
    case "maximize":
      return <Maximize2 {...props} />;
  }
}

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
    case "nav.operator_overview":
      return "server";
    case "nav.operator_health":
      return "heart-pulse";
    case "nav.operator_settings":
      return "settings";
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

export function SelectableTile({
  label,
  checked,
  onChange,
  icon,
  className,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  icon?: ReactNode;
  className?: string;
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      className={className ? `grdr-select-tile ${className}` : "grdr-select-tile"}
      data-checked={checked ? "true" : "false"}
      onClick={() => onChange(!checked)}
    >
      <span className="grdr-select-tile-left">
        {icon ? (
          <span className="grdr-select-tile-icon" aria-hidden="true">
            {icon}
          </span>
        ) : null}
        <span className="grdr-select-tile-label">{label}</span>
      </span>
      {checked ? (
        <span className="grdr-select-tile-check" aria-hidden="true">
          <Check size={15} strokeWidth={2.4} />
        </span>
      ) : null}
    </button>
  );
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

export function GrdrSelect({
  label,
  isLabelHidden = false,
  value,
  options,
  onChange,
  size = "md",
  variant = "input",
  width,
}: {
  label: string;
  isLabelHidden?: boolean;
  value: string;
  options: ReadonlyArray<{ value: string; label: string }>;
  onChange: (value: string) => void;
  size?: "sm" | "md" | "lg";
  variant?: "input" | "secondary" | "ghost";
  width?: number | string;
}) {
  return (
    <Selector
      label={label}
      isLabelHidden={isLabelHidden}
      options={options.map((o) => ({ value: o.value, label: o.label }))}
      value={value}
      onChange={onChange}
      size={size}
      variant={variant}
      width={width}
    />
  );
}

export function surfaceAction(label: string, icon?: GrdrIconName, children?: ReactNode) {
  return { label, icon, children };
}
