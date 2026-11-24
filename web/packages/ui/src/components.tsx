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
  Cpu,
  Download,
  Eye,
  FileJson,
  FileText,
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
  | "cpu"
  | "download"
  | "eye"
  | "file-json"
  | "file-text"
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
  | "x";

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

export function surfaceAction(label: string, icon?: GrdrIconName, children?: ReactNode) {
  return { label, icon, children };
}
