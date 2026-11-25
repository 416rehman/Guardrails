import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { test as baseTest, expect, type APIRequestContext, type Page } from "@playwright/test";

export { expect };

export const test = baseTest.extend({
  page: async ({ page }, use) => {
    const consoleUrl = process.env.GRDR_E2E_BASE_URL?.trim() ?? "";
    const consoleTok = process.env.GRDR_E2E_CONSOLE_TOKEN?.trim() ?? "";
    const operatorUrl = process.env.GRDR_E2E_OPERATOR_BASE_URL?.trim() ?? "";
    const operatorTok = process.env.GRDR_E2E_OPERATOR_TOKEN?.trim() ?? "";
    await page.addInitScript(
      ({ cOrigin, cTok, oOrigin, oTok }) => {
        const here = window.location.origin;
        if (cOrigin && cTok && here === cOrigin) {
          window.sessionStorage.setItem("grdr_api_token", cTok);
        } else if (oOrigin && oTok && here === oOrigin) {
          window.sessionStorage.setItem("grdr_api_token", oTok);
        }
      },
      {
        cOrigin: consoleUrl ? new URL(consoleUrl).origin : "",
        cTok: consoleTok,
        oOrigin: operatorUrl ? new URL(operatorUrl).origin : "",
        oTok: operatorTok,
      },
    );
    await use(page);
  },
});

export interface PageDiagnostics {
  pageErrors: string[];
  consoleErrors: string[];
  failedResponses: string[];
  failedRequests: string[];
  assertClean: () => void;
}

export function getBaseUrl(): string {
  const url = process.env.GRDR_E2E_BASE_URL?.trim();
  if (!url) {
    throw new Error("GRDR_E2E_BASE_URL is not configured");
  }
  return url.replace(/\/+$/, "");
}

export function attachDiagnostics(page: Page): PageDiagnostics {
  const pageErrors: string[] = [];
  const consoleErrors: string[] = [];
  const failedResponses: string[] = [];
  const failedRequests: string[] = [];

  page.on("pageerror", (err) => {
    pageErrors.push(err.message);
  });

  page.on("console", (msg) => {
    if (msg.type() === "error") {
      consoleErrors.push(msg.text());
    }
  });

  page.on("response", (res) => {
    if (res.status() >= 400) {
      failedResponses.push(`${res.status()} ${res.url()}`);
    }
  });

  page.on("requestfailed", (req) => {
    const failureText = req.failure()?.errorText ?? "failed";
    const isNavAbortedSse =
      req.url().includes("OverviewService/LiveEvents") &&
      failureText === "net::ERR_ABORTED";
    if (!isNavAbortedSse) {
      failedRequests.push(`${req.method()} ${req.url()} (${failureText})`);
    }
  });

  return {
    pageErrors,
    consoleErrors,
    failedResponses,
    failedRequests,
    assertClean: () => {
      expect(pageErrors, `Uncaught pageerrors: ${pageErrors.join("; ")}`).toEqual([]);
      expect(consoleErrors, `Console errors: ${consoleErrors.join("; ")}`).toEqual([]);
      expect(
        failedResponses,
        `Unexpected HTTP >= 400 responses: ${failedResponses.join("; ")}`,
      ).toEqual([]);
      expect(
        failedRequests,
        `Unexpected failed requests: ${failedRequests.join("; ")}`,
      ).toEqual([]);
    },
  };
}

export async function assertNoHorizontalOverflow(page: Page, contextLabel: string): Promise<void> {
  const metrics = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    innerWidth: window.innerWidth,
  }));
  expect(
    metrics.scrollWidth,
    `Horizontal overflow on ${contextLabel}: scrollWidth=${metrics.scrollWidth} > innerWidth=${metrics.innerWidth}`,
  ).toBeLessThanOrEqual(metrics.innerWidth);
}

export async function captureVerifiedScreenshot(
  page: Page,
  projectName: string,
  name: string,
): Promise<void> {
  const dir = process.env.GRDR_E2E_SCREENSHOT_DIR?.trim();
  if (!dir) return;
  mkdirSync(dir, { recursive: true });
  const suffix = projectName === "mobile" ? "-mobile" : "";
  await page.screenshot({
    path: join(dir, `${name}${suffix}.png`),
    fullPage: true,
    animations: "disabled",
  });
}

export async function rpcPost(
  request: APIRequestContext,
  methodPath: string,
  body: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const token = process.env.GRDR_E2E_CONSOLE_TOKEN?.trim() ?? "";
  const stepUp = process.env.GRDR_E2E_STEP_UP_TOKEN?.trim() ?? "";
  const resp = await request.post(`${getBaseUrl()}${methodPath}`, {
    headers: {
      "Content-Type": "application/json",
      "Connect-Protocol-Version": "1",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      "X-Grdr-Confirm": "confirmed",
      ...(stepUp ? { "X-Grdr-Step-Up": stepUp } : {}),
    },
    data: body,
  });
  expect(resp.ok(), `${methodPath} returned ${resp.status()}`).toBeTruthy();
  const parsed: unknown = await resp.json();
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${methodPath} returned non-object JSON`);
  }
  return Object.fromEntries(Object.entries(parsed));
}
