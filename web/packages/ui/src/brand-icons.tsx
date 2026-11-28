// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type { ComponentType } from "react";
import { LayoutGrid } from "lucide-react";
import {
  ICON_REGISTRY,
  resolveHarnessCatalogEntry,
  resolveOsCatalogEntry,
  type CatalogHarnessPresentation,
} from "@grdr/i18n";
import {
  SiAnthropic,
  SiApple,
  SiClaude,
  SiClaudecode,
  SiCursor,
  SiDebian,
  SiFedora,
  SiGithub,
  SiGithubcopilot,
  SiGoogle,
  SiGooglegemini,
  SiJetbrains,
  SiKong,
  SiLinux,
  SiMetaai,
  SiMistralai,
  SiModelcontextprotocol,
  SiOpencode,
  SiUbuntu,
  SiWindsurf,
  SiZedindustries,
} from "@icons-pack/react-simple-icons";
import guardrailsMarkPng from "./assets/guardrails-mark.png";
import heroWaveLightPng from "./assets/hero-wave-light.png";
import heroWaveDarkPng from "./assets/hero-wave-dark.png";
import { GrdrIcon, type GrdrIconName } from "./components";

type SimpleIconComponent = ComponentType<{
  size?: number | string;
  color?: string;
  "aria-hidden"?: boolean | "true" | "false";
}>;

const SIMPLE_ICON_COMPONENTS: Readonly<Record<string, SimpleIconComponent>> = {
  anthropic: SiAnthropic,
  apple: SiApple,
  claude: SiClaude,
  claudecode: SiClaudecode,
  cursor: SiCursor,
  debian: SiDebian,
  fedora: SiFedora,
  github: SiGithub,
  githubcopilot: SiGithubcopilot,
  google: SiGoogle,
  googlegemini: SiGooglegemini,
  jetbrains: SiJetbrains,
  kong: SiKong,
  linux: SiLinux,
  metaai: SiMetaai,
  mistralai: SiMistralai,
  modelcontextprotocol: SiModelcontextprotocol,
  opencode: SiOpencode,
  ubuntu: SiUbuntu,
  windsurf: SiWindsurf,
  zedindustries: SiZedindustries,
};

const TONE_COLOR_VARS: Readonly<Record<string, string>> = {
  ask: "var(--tone-ask)",
  allow: "var(--tone-allow)",
  block: "var(--tone-block)",
  watch: "var(--tone-watch)",
  accent: "var(--accent-primary)",
  primary: "var(--ink-primary)",
  secondary: "var(--ink-secondary)",
};

export function iconKeyToName(iconKey: string): GrdrIconName {
  const entry = ICON_REGISTRY[iconKey as keyof typeof ICON_REGISTRY];
  if (entry) {
    return entry.lucide as GrdrIconName;
  }
  return "shield";
}

export function iconKeyShouldMirror(iconKey: string): boolean {
  const entry = ICON_REGISTRY[iconKey as keyof typeof ICON_REGISTRY];
  return Boolean(entry?.mirror);
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
  extraCatalog,
}: {
  name: string;
  size?: number;
  extraCatalog?: ReadonlyArray<CatalogHarnessPresentation>;
}) {
  const entry = resolveHarnessCatalogEntry(name, extraCatalog);
  const color = TONE_COLOR_VARS[entry?.tone ?? "primary"] ?? "var(--ink-primary)";

  if (entry?.simpleIcon === "guardrails-mark") {
    return <GuardrailsMark size={size} />;
  }
  if (entry?.simpleIcon) {
    const BrandIcon = SIMPLE_ICON_COMPONENTS[entry.simpleIcon];
    if (BrandIcon) {
      return <BrandIcon size={size} color={color} aria-hidden="true" />;
    }
  }
  const fallbackLucide = (entry?.lucide as GrdrIconName | undefined) ?? "cpu";
  return <GrdrIcon name={fallbackLucide} size={size} color={color} />;
}

export function OsIcon({
  os,
  size = 14,
}: {
  os: string;
  size?: number;
}) {
  const entry = resolveOsCatalogEntry(os);
  const color = TONE_COLOR_VARS[entry?.tone ?? "secondary"] ?? "var(--ink-secondary)";

  if (entry?.simpleIcon === "windows-grid") {
    return <LayoutGrid size={size} color={color} aria-hidden="true" />;
  }
  if (entry?.simpleIcon) {
    const OsBrandIcon = SIMPLE_ICON_COMPONENTS[entry.simpleIcon];
    if (OsBrandIcon) {
      return <OsBrandIcon size={size} color={color} aria-hidden="true" />;
    }
  }
  const fallbackLucide = (entry?.lucide as GrdrIconName | undefined) ?? "hard-drive";
  return <GrdrIcon name={fallbackLucide} size={size} color={color} />;
}
