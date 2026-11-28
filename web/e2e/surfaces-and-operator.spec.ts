// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import type { Page, Request } from "@playwright/test";
import {
  assertNoHorizontalOverflow,
  attachDiagnostics,
  captureVerifiedScreenshot,
  expect,
  test,
} from "./helpers";

function trackRpcSettling(page: Page): () => Promise<void> {
  const pending = new Set<Request>();
  const isTracked = (req: Request) =>
    req.url().includes("/grdr.api.") && !req.url().includes("OverviewService/LiveEvents");

  page.on("request", (req) => {
    if (isTracked(req)) {
      pending.add(req);
    }
  });
  page.on("requestfinished", (req) => pending.delete(req));
  page.on("requestfailed", (req) => pending.delete(req));

  return async () => {
    await expect.poll(() => pending.size, { timeout: 10_000 }).toBe(0);
  };
}

async function navigateConsoleSection(
  page: Page,
  isMobile: boolean,
  label: string,
): Promise<void> {
  if (isMobile) {
    await page.getByRole("button", { name: "Toggle navigation menu" }).click();
  }
  await page
    .getByRole("navigation", { name: "Console sections" })
    .getByRole("button", { name: label, exact: true })
    .click();
}

async function navigateOperatorSection(
  page: Page,
  isMobile: boolean,
  label: string,
): Promise<void> {
  if (isMobile) {
    await page.getByRole("button", { name: "Toggle navigation menu" }).click();
  }
  await page
    .locator('aside[aria-label="Operator navigation"] nav.rail-nav')
    .getByRole("button", { name: label, exact: true })
    .click();
}

async function closeWhyCardDrawer(page: Page): Promise<void> {
  await page.keyboard.press("Escape");
  await expect(page.locator(".grdr-ui-drawer-backdrop")).toHaveCount(0);
  await expect(page.locator(".grdr-ui-drawer-content")).toHaveCount(0);
  await expect(page.getByText("What the agent was told (max 600 chars)")).toBeHidden();
}

test.describe("Web Console Surfaces, WhyCard, and Operator Plane", () => {
  test("exercises WhyCardDrawer, FirstRun, Review Queue, Compliance, Settings Privacy, and Provider Workbench", async ({
    page,
  }, testInfo) => {
    const diagnostics = attachDiagnostics(page);
    const waitRpcsSettled = trackRpcSettling(page);
    const isMobile = testInfo.project.name === "mobile";

    await page.goto("/");
    await expect(page.getByRole("region", { name: "Protection overview" })).toBeVisible();
    await waitRpcsSettled();
    await page.locator("main").getByRole("button", { name: "Review", exact: true }).first().click();
    await page.getByRole("button", { name: "Why?" }).first().click();
    await expect(page.getByText("What the agent was told (max 600 chars)")).toBeVisible();
    await expect(page.getByRole("button", { name: /^Close / }).first()).toBeInViewport();
    await page.waitForTimeout(450);
    await assertNoHorizontalOverflow(page, "WhyCard drawer open");
    await captureVerifiedScreenshot(page, testInfo.project.name, "04-why-card-drawer");
    await closeWhyCardDrawer(page);

    await navigateConsoleSection(page, isMobile, "First run");
    await expect(page.getByRole("heading", { name: "First run setup" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Onboarding checklist", exact: true })).toBeVisible();
    await waitRpcsSettled();
    await assertNoHorizontalOverflow(page, "First run page");
    await captureVerifiedScreenshot(page, testInfo.project.name, "05-first-run");
    await page.getByRole("button", { name: "Confirm protection profile" }).click();
    await expect(page.getByText(/Protection profile .* activated/)).toBeVisible();
    await waitRpcsSettled();

    await navigateConsoleSection(page, isMobile, "Review queue");
    await expect(page.getByRole("heading", { name: "Review queue" })).toBeVisible();
    await waitRpcsSettled();
    await assertNoHorizontalOverflow(page, "Review queue page");
    await captureVerifiedScreenshot(page, testInfo.project.name, "06-review-queue");
    await page.getByRole("button", { name: "Why?" }).first().click();
    await expect(page.getByText("What the agent was told (max 600 chars)")).toBeVisible();
    await closeWhyCardDrawer(page);

    await navigateConsoleSection(page, isMobile, "Compliance");
    await expect(page.getByRole("heading", { name: "Compliance & integrations" })).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Framework crosswalk readiness", exact: true }),
    ).toBeVisible();
    await waitRpcsSettled();
    await assertNoHorizontalOverflow(page, "Compliance page");
    await captureVerifiedScreenshot(page, testInfo.project.name, "07-compliance");
    await page.getByRole("button", { name: "Place legal hold (1/2)" }).click();
    await expect(page.getByText(/Staged legal hold/)).toBeVisible();
    await waitRpcsSettled();

    await navigateConsoleSection(page, isMobile, "Settings & privacy");
    await expect(page.getByRole("heading", { name: "Settings, privacy & disclosure" })).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Quarterly disclosure ledger", exact: true }),
    ).toBeVisible();
    await waitRpcsSettled();
    await assertNoHorizontalOverflow(page, "Settings & privacy page");
    await captureVerifiedScreenshot(page, testInfo.project.name, "08-settings-privacy");
    await page.getByRole("button", { name: "Save privacy & retention regime" }).click();
    await expect(page.getByText(/Applied .* privacy regime/)).toBeVisible();
    await waitRpcsSettled();

    await navigateConsoleSection(page, isMobile, "Provider");
    await expect(page.getByRole("heading", { name: "Provider workbench" })).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Managed organizations", exact: true }),
    ).toBeVisible();
    await waitRpcsSettled();
    await assertNoHorizontalOverflow(page, "Provider workbench page");
    await captureVerifiedScreenshot(page, testInfo.project.name, "09-provider-workbench");
    await page.getByRole("button", { name: "Act as org" }).first().click();
    await expect(page.getByRole("button", { name: "Exit acting-as" })).toBeVisible();
    await waitRpcsSettled();
    await page.getByRole("button", { name: "Exit acting-as" }).click();
    await expect(page.getByRole("button", { name: "Exit acting-as" })).toHaveCount(0);
    await waitRpcsSettled();

    diagnostics.assertClean();
  });

  test("exercises Operator Plane overview, runtime revisions, preflight, targets, and backup drills", async ({
    page,
  }, testInfo) => {
    const opBaseUrl = process.env.GRDR_E2E_OPERATOR_BASE_URL?.trim();
    test.skip(!opBaseUrl, "GRDR_E2E_OPERATOR_BASE_URL not configured");

    const diagnostics = attachDiagnostics(page);
    const waitRpcsSettled = trackRpcSettling(page);
    const isMobile = testInfo.project.name === "mobile";

    await page.goto(`${opBaseUrl}/`);
    await expect(page.getByText("Deployment boundary")).toBeVisible();
    await waitRpcsSettled();
    await assertNoHorizontalOverflow(page, "Operator overview");

    await navigateOperatorSection(page, isMobile, "Upgrades");
    await expect(page.getByRole("heading", { name: "Runtime configuration revisions" })).toBeVisible();
    await waitRpcsSettled();
    await assertNoHorizontalOverflow(page, "Operator upgrades");
    await captureVerifiedScreenshot(page, testInfo.project.name, "10-operator-upgrades");
    await page.getByRole("button", { name: "Stage revision" }).click();
    await expect(page.getByText(/Staged config revision/)).toBeVisible();
    await waitRpcsSettled();
    await page.getByRole("button", { name: "Run preflight" }).click();
    await expect(page.getByText(/Preflight for v/)).toBeVisible();
    await waitRpcsSettled();

    await navigateOperatorSection(page, isMobile, "Backups");
    await expect(page.getByRole("heading", { name: "Delivery targets and circuit breakers" })).toBeVisible();
    await waitRpcsSettled();
    await assertNoHorizontalOverflow(page, "Operator backups");
    await captureVerifiedScreenshot(page, testInfo.project.name, "11-operator-backups");
    await page.getByRole("button", { name: "Run backup drill" }).click();
    await expect(page.getByText(/Completed backup drill/)).toBeVisible();
    await waitRpcsSettled();

    diagnostics.assertClean();
  });
});
