// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { afterEach, describe, expect, it } from "vitest";
import {
  ALL_CONSOLE_ROUTES,
  ALL_OPERATOR_ROUTES,
  BRAND_NAME,
  CONSOLE_ROUTES,
  HARNESS_CATALOG_ICONS,
  INTERFACE_ROUTES,
  OPERATOR_ROUTES,
  formatActionLabel,
  formatOsName,
  formatTimestamp,
  getLocale,
  lookupMessage,
  pluralize,
  presentAgentName,
  presentAssurance,
  presentFindingTitle,
  presentIncidentSummary,
  presentIncidentTitle,
  presentSessionLabel,
  resolveHarnessCatalogEntry,
  resolveOsCatalogEntry,
  routeLabel,
  setLocale,
  t,
} from "../index";

afterEach(() => {
  setLocale("en-US");
});

describe("@grdr/i18n unified interface contracts & runtime MF2", () => {
  it("exposes all 23 routes from routes.toml without fallback maps", () => {
    expect(INTERFACE_ROUTES).toHaveLength(23);
    expect(ALL_CONSOLE_ROUTES).toHaveLength(15);
    expect(ALL_OPERATOR_ROUTES).toHaveLength(8);
    expect(CONSOLE_ROUTES).toHaveLength(13);
    expect(OPERATOR_ROUTES).toHaveLength(6);
    expect(BRAND_NAME).toBe("Guardrails ADR");

    for (const route of INTERFACE_ROUTES) {
      const label = routeLabel(route.titleKey);
      expect(label).not.toBe(route.titleKey);
      expect(label.length).toBeGreaterThan(0);
    }
  });

  it("matches canonical 00-decisions AL0..AL4 assurance labels", () => {
    expect(presentAssurance("AL0", "observe").label).toBe("AL0 Inventoried");
    expect(presentAssurance("AL1", "observe").label).toBe("AL1 Observed");
    expect(presentAssurance("AL2", "request").label).toBe("AL2 Guided");
    expect(presentAssurance("AL3", "boundary").label).toBe("AL3 Contained");
    expect(presentAssurance("AL4", "boundary").label).toBe("AL4 Enforced");
  });

  it("switches runtime locale, updates <html lang dir data-script>, and resolves MF2 plurals", () => {
    setLocale("ar");
    expect(getLocale()).toBe("ar");
    expect(document.documentElement.getAttribute("lang")).toBe("ar");
    expect(document.documentElement.getAttribute("dir")).toBe("rtl");
    expect(document.documentElement.getAttribute("data-script")).toBe("arab");
    expect(t("console.nav.home")).toBe("الرئيسية");
    expect(t("common.count.sandboxed_devices", { count: 1 })).toContain("جهاز");
    expect(t("common.count.sandboxed_devices", { count: 2 })).toContain("جهازان");

    setLocale("de-DE");
    expect(document.documentElement.getAttribute("dir")).toBe("ltr");
    expect(t("console.nav.home")).toBe("Start");
    expect(t("common.count.sandboxed_devices", { count: 1 })).toBe("1 eingegrenztes Gerät");
    expect(t("common.count.sandboxed_devices", { count: 3 })).toBe("3 eingegrenzte Geräte");

    setLocale("ja-JP");
    expect(document.documentElement.getAttribute("data-script")).toBe("jpan");
    expect(t("common.count.sandboxed_devices", { count: 4 })).toBe("4台の分離済みデバイス");
  });

  it("isolates placeholders in ar-XB and decorates pseudo-locales", () => {
    const xa = lookupMessage("en-XA", "console.nav.protect");
    expect(xa).toBe("[Protect ~~~]");
    const xc = lookupMessage("ja-XC", "console.nav.protect");
    expect(xc).toBe("「Protect」");
    const xb = lookupMessage("ar-XB", "kit.approval.confirm_prefix", {
      scopeLabel: "Allow once",
    });
    expect(xb.startsWith("\u2066")).toBe(true);
    expect(xb.endsWith("\u2069")).toBe(true);
    expect(xb).toContain("\u2066Allow once\u2069");
  });

  it("formats timestamps and action labels according to active locale", () => {
    const iso = "2026-11-24T14:30:00Z";
    const enTs = formatTimestamp(iso, "en-US", "UTC");
    const jaTs = formatTimestamp(iso, "ja-JP", "UTC");
    expect(enTs).toContain("Nov");
    expect(jaTs).toContain("11");
    expect(jaTs).not.toBe(enTs);

    expect(formatActionLabel("exec", "en-US")).toBe("Command run");
    setLocale("ar");
    expect(formatActionLabel("exec")).toBe("تشغيل أمر");
    expect(t("kit.device.agent_protection", { count: 6 })).toContain("حماية الوكلاء");
    expect(t("kit.device.agent_protection", { count: 6 })).toContain("\u20686\u2069");
    expect(pluralize(2, "item")).toBeTruthy();
    expect(formatOsName("darwin")).toBe("macOS");
  });

  it("resolves all 17 P14 catalogue agents dynamically from generated catalog metadata", () => {
    expect(HARNESS_CATALOG_ICONS.length).toBeGreaterThanOrEqual(17);
    expect(presentAgentName("claude")).toBe("Claude Code");
    expect(presentAgentName("agy")).toBe("Antigravity");
    expect(presentAgentName("zed")).toBe("Zed AI");
    expect(presentAgentName("jetbrains-junie")).toBe("JetBrains Junie");
    expect(presentAgentName("openai-codex")).toBe("Codex CLI");
    expect(
      presentAgentName("custom-runtime-harness", [
        {
          id: "custom-runtime-harness",
          displayName: "Custom Runtime Harness",
          vendor: "Acme",
          kind: "coding-agent",
          aliases: ["crh"],
          simpleIcon: "",
          lucide: "cpu",
          tone: "accent",
        },
      ]),
    ).toBe("Custom Runtime Harness");
  });

  it("avoids short-alias substring collisions and honors presentation registry tones", () => {
    expect(resolveHarnessCatalogEntry("qwen-coder")).toBeNull();
    expect(presentAgentName("qwen-coder")).toBe("qwen-coder");
    expect(resolveHarnessCatalogEntry("amazon-q/0.9")?.id).toBe("amazon-q");
    expect(resolveOsCatalogEntry("windsurf")).toBeNull();
    expect(resolveOsCatalogEntry("win-eng-surface03")?.id).toBe("windows");

    expect(presentAssurance("AL0", "observe", "en-US").tone).toBe("neutral");
    const al1Req = presentAssurance("AL1", "zed-ai: Request proxy", "en-US");
    expect(al1Req.tone).toBe("neutral");
    expect(al1Req.controlLabel).toBe("Request");
    expect(presentAssurance("AL2", "observe", "en-US").tone).toBe("warning");
    expect(presentAssurance("AL3", "boundary", "en-US").tone).toBe("success");
    expect(presentAssurance("AL4", "boundary", "en-US").tone).toBe("success");

    expect(presentSessionLabel("untrusted_web_fetched", "en-US")).toMatchObject({
      tone: "warning",
      iconKey: "security.alert",
    });
    expect(presentSessionLabel("repeated_denials", "en-US")).toMatchObject({
      tone: "danger",
      iconKey: "mode.block",
    });

    const arDual = t(
      "kit.mode_control.scope_with_requests",
      {
        modeLabel: "مراقبة",
        boundaryDevicesText: t("common.count.sandboxed_devices", { count: 2 }, "ar"),
        requestAgentsText: t("common.count.hook_agents", { count: 1 }, "ar"),
      },
      "ar",
    );
    expect(arDual).toContain("جهازان معزولان");
    expect(arDual).not.toContain("على جهازان");
    expect(t("common.count.sandboxed_devices", { count: 5 }, "ar")).toContain("أجهزة معزولة");
    expect(t("common.count.sandboxed_devices", { count: 15 }, "ar")).toContain("جهازًا معزولًا");

    expect(presentFindingTitle("file.read via claude-code on claude-code", "claude-code", "en-US")).toBe(
      "File read via Claude Code",
    );
    expect(presentIncidentTitle("Repeated denials in zed-ai")).toBe("Repeated denials in Zed AI");
    expect(presentIncidentSummary("Blocked exec ; attempted file.read on claude-code ;   ", "en-US")).toBe(
      "Blocked command run. attempted file read on Claude Code.",
    );
    expect(presentIncidentSummary("   ;  ; ")).toBe("");
  });
});
