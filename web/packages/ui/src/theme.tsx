import "@astryxdesign/core/reset.css";
import "@astryxdesign/core/astryx.css";
import "@astryxdesign/theme-neutral/theme.css";
import "@astryxdesign/theme-neutral/fonts.css";
import "@grdr/tokens/tokens.css";
import "./ui.css";

import { useEffect, type ReactNode } from "react";
import { Theme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral/built";

export type GrdrThemeMode = "dark" | "light";

export interface GrdrThemeProviderProps {
  mode?: GrdrThemeMode;
  children: ReactNode;
}

export function GrdrThemeProvider({ mode = "light", children }: GrdrThemeProviderProps) {
  useEffect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.setAttribute("data-theme", mode);
    }
  }, [mode]);

  return (
    <Theme theme={neutralTheme} mode={mode}>
      {children}
    </Theme>
  );
}
