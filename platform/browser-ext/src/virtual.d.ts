// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

declare module "virtual:grdr-lucide-modes" {
  export type SvgNodeTuple = [string, Record<string, string | number>];
  const modeIconNodes: Record<"off" | "watch" | "ask" | "block", SvgNodeTuple[]>;
  export default modeIconNodes;
}

declare module "virtual:grdr-tokens" {
  export interface BrandTokenScheme {
    bgCanvas: string;
    bgRail: string;
    bgRecessed: string;
    bgHover: string;
    borderSubtle: string;
    borderStrong: string;
    inkPrimary: string;
    inkSecondary: string;
    inkMuted: string;
    actionPrimaryBg: string;
    actionPrimaryInk: string;
    accentSignal: string;
    ask: string;
    block: string;
  }
  const brandTokens: { light: BrandTokenScheme; dark: BrandTokenScheme };
  export default brandTokens;
}
