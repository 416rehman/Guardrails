// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { getLocale, setLocale } from "@grdr/i18n";
import { AssuranceBadge, ModeControl, Quoted, VerdictBadge } from "../../../kit/src/index";
import { GrdrThemeProvider, HarnessIcon, LocalePicker, OsIcon, UiSdkDrawer } from "../index";

if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

afterEach(() => {
  cleanup();
  globalThis.localStorage?.removeItem("grdr_locale");
  setLocale("en-US");
});

describe("@grdr/ui & @grdr/kit theme, RTL, and P14 icons", () => {
  it("renders porcelain light, carbon obsidian dark, and RTL locale primitives", () => {
    const { container } = render(
      <GrdrThemeProvider mode="light" locale="ar">
        <LocalePicker />
        <AssuranceBadge level="AL3" control="boundary" />
        <VerdictBadge verdict="step_up" />
        <ModeControl value="ask" boundaryDevices={2} requestDevices={1} onChange={() => {}} />
        <HarnessIcon name="claude-code" />
        <HarnessIcon
          name="dynamic-agent"
          extraCatalog={[
            {
              id: "dynamic-agent",
              displayName: "Dynamic Agent",
              vendor: "Loonaro",
              kind: "coding-agent",
              aliases: [],
              simpleIcon: "",
              lucide: "terminal",
              tone: "accent",
            },
          ]}
        />
        <OsIcon os="darwin" />
      </GrdrThemeProvider>,
    );

    const rtlWrapper = container.querySelector("[dir='rtl'][lang='ar'][data-script='arab']");
    expect(rtlWrapper).not.toBeNull();
    expect(screen.getByText("AL3 معزول")).toBeTruthy();
    expect(screen.getAllByText("طلب إذن").length).toBeGreaterThan(0);
  });

  it("strips bidi overrides visibly in Quoted, localizes UiSdkDrawer, and preserves localStorage", () => {
    globalThis.localStorage?.setItem("grdr_locale", "ja-JP");
    const { container } = render(
      <GrdrThemeProvider mode="light" locale="ar">
        <AssuranceBadge level="AL1" control="request" />
        <AssuranceBadge level="AL2" control="observe" />
        <Quoted text={"line1\nline2\r\nline3"} />
        <Quoted text={"rm\u202E-rf\n~/.ssh"} />
        <UiSdkDrawer open title="Test Drawer" onClose={() => {}}>
          <div>body</div>
        </UiSdkDrawer>
      </GrdrThemeProvider>,
    );

    expect(globalThis.localStorage?.getItem("grdr_locale")).toBe("ja-JP");
    expect(getLocale()).toBe("ar");
    const badges = container.querySelectorAll(".grdr-badge");
    expect(badges[0]?.getAttribute("data-variant")).toBe("neutral");
    expect(badges[1]?.getAttribute("data-variant")).toBe("warning");
    const quotedBdis = container.querySelectorAll(".grdr-ui-quoted bdi");
    expect(quotedBdis[0]?.textContent).toBe("line1 line2 line3");
    expect(quotedBdis[1]?.textContent).toBe("rm-rf ~/.ssh");
    expect(quotedBdis[1]?.textContent).not.toContain("\u202E");
    const bidiStatuses = screen.getAllByText("تمت إزالة محارف التحكم");
    expect(bidiStatuses).toHaveLength(1);
    expect(bidiStatuses[0]?.closest("[role='status']")).not.toBeNull();
    expect(screen.getByRole("button", { name: /إغلاق/ })).toBeTruthy();
  });
});
