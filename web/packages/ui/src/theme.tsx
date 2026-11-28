// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import "@astryxdesign/core/reset.css";
import "@astryxdesign/core/astryx.css";
import "@astryxdesign/theme-neutral/theme.css";
import "@grdr/tokens/tokens.css";
import "./ui.css";

import { createContext, useContext, useEffect, useRef, useSyncExternalStore, type ReactNode } from "react";
import { Theme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral/built";
import { TYPOGRAPHY_TOKENS } from "@grdr/tokens";
import {
  SUPPORTED_LOCALES,
  getLocale,
  getLocaleMeta,
  initLocale,
  setLocale,
  subscribeLocale,
  syncDocumentLocale,
  t,
  type LocaleCode,
  type LocaleDirection,
  type LocaleScript,
} from "@grdr/i18n";
import { GrdrSelect } from "./components";

export type GrdrThemeMode = "dark" | "light";

export interface GrdrThemeProviderProps {
  mode?: GrdrThemeMode;
  locale?: LocaleCode;
  children: ReactNode;
}

const GrdrLocaleContext = createContext<LocaleCode | null>(null);

const baseAxes = neutralTheme.__axes;

const STUDIO_ASTRYX_THEME = {
  ...neutralTheme,
  tokens: {
    ...neutralTheme.tokens,
    "--font-family-body": TYPOGRAPHY_TOKENS.sans,
    "--font-family-heading": TYPOGRAPHY_TOKENS.sans,
    "--font-family-code": TYPOGRAPHY_TOKENS.mono,
  },
  ...(baseAxes
    ? {
        __axes: {
          ...baseAxes,
          typography: {
            ...baseAxes.typography,
            body: {
              family: "DM Sans",
              fallbacks: "system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
            },
            heading: {
              ...baseAxes.typography?.heading,
              family: "DM Sans",
              fallbacks: "system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
            },
            code: {
              family: "IBM Plex Mono",
              fallbacks: "ui-monospace, SFMono-Regular, monospace",
            },
          },
        },
      }
    : {}),
};

export function useGrdrLocale(): {
  locale: LocaleCode;
  direction: LocaleDirection;
  script: LocaleScript;
  setLocale: (next: LocaleCode | string) => LocaleCode;
  supportedLocales: typeof SUPPORTED_LOCALES;
} {
  const storeLocale = useSyncExternalStore(subscribeLocale, getLocale, () => "en-US" as LocaleCode);
  const ctxLocale = useContext(GrdrLocaleContext);
  const locale = ctxLocale ?? storeLocale;
  const meta = getLocaleMeta(locale);
  return {
    locale,
    direction: meta.direction,
    script: meta.script,
    setLocale,
    supportedLocales: SUPPORTED_LOCALES,
  };
}

export function LocalePicker({
  size = "sm",
  isLabelHidden = true,
  width,
}: {
  size?: "sm" | "md" | "lg";
  isLabelHidden?: boolean;
  width?: number | string;
}) {
  const { locale, setLocale: applyLocale, supportedLocales } = useGrdrLocale();
  return (
    <GrdrSelect
      label={t("kit.locale.label", undefined, locale)}
      isLabelHidden={isLabelHidden}
      size={size}
      variant="secondary"
      width={width}
      value={locale}
      options={supportedLocales.map((item) => ({
        value: item.tag,
        label: item.nativeName,
      }))}
      onChange={(next) => {
        applyLocale(next);
      }}
    />
  );
}

export function GrdrThemeProvider({
  mode = "light",
  locale,
  children,
}: GrdrThemeProviderProps) {
  const prevLocaleRef = useRef<LocaleCode | undefined>(undefined);
  if (locale !== undefined && prevLocaleRef.current !== locale) {
    prevLocaleRef.current = locale;
    initLocale(locale);
  } else if (locale === undefined && prevLocaleRef.current !== undefined) {
    prevLocaleRef.current = undefined;
  }
  const activeLocale = useSyncExternalStore(subscribeLocale, getLocale, () => "en-US" as LocaleCode);
  const resolvedLocale = locale ?? activeLocale;
  const meta = getLocaleMeta(resolvedLocale);

  useEffect(() => {
    syncDocumentLocale(resolvedLocale);
  }, [resolvedLocale]);

  useEffect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.setAttribute("data-theme", mode);
    }
  }, [mode]);

  return (
    <GrdrLocaleContext.Provider value={resolvedLocale}>
      <div dir={meta.direction} lang={meta.tag} data-script={meta.script} style={{ display: "contents" }}>
        <Theme theme={STUDIO_ASTRYX_THEME} mode={mode}>
          {children}
        </Theme>
      </div>
    </GrdrLocaleContext.Provider>
  );
}
