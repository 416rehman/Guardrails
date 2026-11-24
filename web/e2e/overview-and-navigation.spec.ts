import { expect, test } from "@playwright/test";
import {
  assertNoHorizontalOverflow,
  attachDiagnostics,
  captureVerifiedScreenshot,
} from "./helpers";

test.describe("Overview, Navigation, Breadcrumbs, and Deep-Link Routing", () => {
  test("renders 360 telemetry ring, 3-group collapsible sidebar, interactive breadcrumbs, and TanStack Router history", async ({
    page,
  }, testInfo) => {
    const diagnostics = attachDiagnostics(page);
    const isMobile = testInfo.project.name === "mobile";

    await page.goto("/");
    await expect(page.getByRole("region", { name: "Protection overview" })).toBeVisible();
    await expect(page.locator('[aria-label*="percent Boundary"] canvas')).toBeVisible();
    await expect(page.getByText("Enrolled hosts", { exact: true })).toBeVisible();
    await expect(page.getByText("Waiting approvals", { exact: true })).toBeVisible();
    await expect(page.getByText("Open findings", { exact: true })).toBeVisible();
    await expect(page.getByText("Active rules", { exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Weekly decision velocity" })).toBeVisible();

    await assertNoHorizontalOverflow(page, "Home overview");
    await captureVerifiedScreenshot(page, testInfo.project.name, "01-overview-home");

    const sidebar = page.getByRole("navigation", { name: "Console sections" });

    if (!isMobile) {
      await expect(sidebar.getByText("Overview")).toBeVisible();
      await expect(sidebar.getByText("Fleet & Activity")).toBeVisible();
      await expect(sidebar.getByText("Protection & Response")).toBeVisible();

      await page.getByRole("button", { name: "Collapse navigation" }).click();
      await expect(page.locator("aside.rail.collapsed")).toBeVisible();
      await assertNoHorizontalOverflow(page, "Home collapsed rail");

      await page.getByRole("button", { name: "Expand navigation" }).click();
      await expect(page.locator("aside.rail.collapsed")).toHaveCount(0);

      await page.getByRole("button", { name: "Toggle Inventory sub-navigation" }).click();
      await expect(page.locator('.nav-sublist[aria-label="Inventory views"]')).toHaveCount(0);
      await page.getByRole("button", { name: "Toggle Inventory sub-navigation" }).click();
      await expect(page.locator('.nav-sublist[aria-label="Inventory views"]')).toBeVisible();

      await page
        .locator('.nav-sublist[aria-label="Inventory views"]')
        .getByRole("button", { name: "Agents" })
        .click();
    } else {
      await sidebar.getByRole("button", { name: "Inventory" }).click();
      await expect(page).toHaveURL(/\/inventory\/endpoints/);
      await assertNoHorizontalOverflow(page, "Mobile Inventory endpoints");
      await page
        .locator('.mobile-subnav[aria-label="Inventory views"]')
        .getByRole("button", { name: "Agents" })
        .click();
    }

    await expect(page).toHaveURL(/\/inventory\/agents/);
    await expect(page.getByText(/Discovered AI agents \(\d+\)/)).toBeVisible();
    await assertNoHorizontalOverflow(page, "Inventory agents");

    const breadcrumbs = page.getByRole("navigation", { name: "Breadcrumb" });
    await expect(breadcrumbs.getByRole("button", { name: "Inventory" })).toBeVisible();
    await expect(breadcrumbs.getByText("Agents")).toBeVisible();

    await breadcrumbs.getByRole("button", { name: "Inventory" }).click();
    await expect(page).toHaveURL(/\/inventory\/endpoints/);
    await expect(page.getByText(/Enrolled devices \(\d+\)/)).toBeVisible();

    await page.getByRole("button", { name: "dev-macbook-pro" }).first().click();
    await expect(page).toHaveURL(/device=dev-demo-01/);
    await expect(page.getByText("Device assurance matrix")).toBeVisible();
    await expect(breadcrumbs.getByText("dev-macbook-pro")).toBeVisible();
    await assertNoHorizontalOverflow(page, "Inventory device drawer");

    await page.getByRole("button", { name: "Close Device assurance matrix" }).click();
    await expect(page).not.toHaveURL(/device=/);
    await expect(page.getByText("Device assurance matrix")).toBeHidden();

    await breadcrumbs.getByRole("button", { name: "Home" }).click();
    await expect(page).toHaveURL(/\/$/);

    await sidebar.getByRole("button", { name: "Protect", exact: true }).click();
    await expect(page).toHaveURL(/\/protect\/rules/);
    await assertNoHorizontalOverflow(page, "Protect rules");

    await sidebar.getByRole("button", { name: "Live Tester", exact: true }).click();
    await expect(page).toHaveURL(/\/tester/);
    await assertNoHorizontalOverflow(page, "Live Tester");

    await page.goBack();
    await expect(page).toHaveURL(/\/protect\/rules/);

    await page.goForward();
    await expect(page).toHaveURL(/\/tester/);

    await page.goto("/sessions/trace?sessionId=sess-demo-refactor&turn=2");
    await expect(page.getByRole("heading", { name: "Sessions", exact: true })).toBeVisible();
    await expect(breadcrumbs.getByText("Trace waterfall")).toBeVisible();
    await expect(breadcrumbs.getByText("sess-demo-refactor")).toBeVisible();
    await assertNoHorizontalOverflow(page, "Deep link sessions trace");

    await page.reload();
    await expect(page).toHaveURL(/\/sessions\/trace\?sessionId=sess-demo-refactor&turn=2/);
    await expect(breadcrumbs.getByText("Trace waterfall")).toBeVisible();
    await expect(breadcrumbs.getByText("sess-demo-refactor")).toBeVisible();
    await assertNoHorizontalOverflow(page, "Reloaded deep link sessions trace");

    diagnostics.assertClean();
  });
});
