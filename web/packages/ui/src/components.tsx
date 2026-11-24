import type { ReactNode } from "react";
import { Badge, type BadgeVariant } from "@astryxdesign/core/Badge";
import { Banner, type BannerStatus } from "@astryxdesign/core/Banner";
import { Button, type ButtonSize, type ButtonVariant } from "@astryxdesign/core/Button";
import { Card, type CardVariant } from "@astryxdesign/core/Card";
import { Divider } from "@astryxdesign/core/Divider";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { HStack, VStack } from "@astryxdesign/core/Stack";
import { Heading, Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import {
  Activity,
  AlertCircle,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Ban,
  Binoculars,
  Box,
  Check,
  CheckCircle2,
  Circle,
  CircleOff,
  Clock,
  Code2,
  Cpu,
  Download,
  Eye,
  FileJson,
  FileText,
  GitBranch,
  Hand,
  HardDrive,
  HeartPulse,
  Home,
  KeyRound,
  Layers,
  List,
  Lock,
  Moon,
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
  Sun,
  Tag,
  Terminal,
  Trash2,
  X,
  ZoomIn,
  ZoomOut,
  Maximize2,
} from "lucide-react";

export { Badge, Banner, Button, Card, Divider, EmptyState, Heading, HStack, Text, TextInput, VStack };
export type { BadgeVariant, BannerStatus, ButtonSize, ButtonVariant, CardVariant };

export type GrdrIconName =
  | "activity"
  | "alert-circle"
  | "alert-octagon"
  | "alert-triangle"
  | "arrow-right"
  | "ban"
  | "binoculars"
  | "box"
  | "check"
  | "check-circle"
  | "circle"
  | "circle-off"
  | "clock"
  | "code"
  | "cpu"
  | "download"
  | "eye"
  | "file-json"
  | "file-text"
  | "git-branch"
  | "hand"
  | "hard-drive"
  | "heart-pulse"
  | "home"
  | "key-round"
  | "layers"
  | "list"
  | "lock"
  | "moon"
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
  | "sun"
  | "tag"
  | "terminal"
  | "trash"
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
    case "file-json":
      return <FileJson {...props} />;
    case "file-text":
      return <FileText {...props} />;
    case "git-branch":
      return <GitBranch {...props} />;
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
    case "list":
      return <List {...props} />;
    case "lock":
      return <Lock {...props} />;
    case "moon":
      return <Moon {...props} />;
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
    case "sun":
      return <Sun {...props} />;
    case "tag":
      return <Tag {...props} />;
    case "terminal":
      return <Terminal {...props} />;
    case "trash":
      return <Trash2 {...props} />;
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
  size = 20,
  ariaLabel,
}: {
  size?: number;
  ariaLabel?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      role={ariaLabel ? "img" : undefined}
      aria-label={ariaLabel}
      aria-hidden={ariaLabel ? undefined : true}
    >
      <path
        d="M 8 47.5 V 25 C 8 17.8 13.8 14 20.5 14 H 43.5 C 50.2 14 56 17.8 56 25 V 47.5 C 56 49.4 53.7 50.2 52.5 48.7 L 47.5 41.2 V 25.8 C 47.5 22.3 45.2 20.5 41.8 20.5 H 22.2 C 18.8 20.5 16.5 22.3 16.5 25.8 V 41.2 L 11.5 48.7 C 10.3 50.2 8 49.4 8 47.5 Z"
        fill="currentColor"
      />
      <path d="M 18.0 43.6 H 46.0 L 49.8 50.5 H 14.2 Z" fill="currentColor" />
      <path d="M 22.0 36.2 H 42.0 L 45.0 41.6 H 19.0 Z" fill="currentColor" fillOpacity={0.68} />
      <path d="M 25.4 30.0 H 38.6 L 41.0 34.4 H 23.0 Z" fill="currentColor" fillOpacity={0.44} />
    </svg>
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
  const baseProps = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none" as const,
    "aria-hidden": true as const,
  };

  if (norm.includes("claude")) {
    return (
      <svg {...baseProps}>
        <path
          d="M12 2v20M4.9 4.9l14.2 14.2M2 12h20M4.9 19.1L19.1 4.9"
          stroke="var(--tone-ask)"
          strokeWidth="2"
          strokeLinecap="round"
        />
      </svg>
    );
  }
  if (norm.includes("cursor")) {
    return (
      <svg {...baseProps}>
        <path
          d="M5 3l14 7.5L12.5 13l-2 7L5 3z"
          fill="var(--accent-primary)"
          fillOpacity={0.18}
          stroke="var(--accent-primary)"
          strokeWidth="1.8"
          strokeLinejoin="round"
        />
      </svg>
    );
  }
  if (norm.includes("codex") || norm.includes("openai")) {
    return (
      <svg {...baseProps}>
        <circle cx="12" cy="12" r="8.5" stroke="var(--accent-primary)" strokeWidth="1.7" />
        <path d="M8.5 9.5L11.5 12l-3 2.5M12.5 14.5h3.5" stroke="var(--ink-primary)" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  if (norm.includes("gemini")) {
    return (
      <svg {...baseProps}>
        <path
          d="M12 2.5C12.8 8.2 15.8 11.2 21.5 12C15.8 12.8 12.8 15.8 12 21.5C11.2 15.8 8.2 12.8 2.5 12C8.2 11.2 11.2 8.2 12 2.5Z"
          fill="var(--accent-primary)"
          fillOpacity={0.22}
          stroke="var(--accent-primary)"
          strokeWidth="1.7"
          strokeLinejoin="round"
        />
      </svg>
    );
  }
  if (norm.includes("copilot")) {
    return (
      <svg {...baseProps}>
        <rect x="4" y="7" width="16" height="10" rx="4" stroke="var(--tone-allow)" strokeWidth="1.8" />
        <circle cx="9.5" cy="12" r="1.4" fill="var(--tone-allow)" />
        <circle cx="14.5" cy="12" r="1.4" fill="var(--tone-allow)" />
      </svg>
    );
  }
  if (norm.includes("opencode") || norm.includes("windsurf")) {
    return (
      <svg {...baseProps}>
        <rect x="4" y="4" width="16" height="16" rx="3" stroke="var(--ink-primary)" strokeWidth="1.8" />
        <path d="M8.5 9L11 12l-2.5 3M13 15h3" stroke="var(--accent-primary)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }

  return <GrdrIcon name="cpu" size={size} />;
}

export function surfaceAction(label: string, icon?: GrdrIconName, children?: ReactNode) {
  return { label, icon, children };
}
