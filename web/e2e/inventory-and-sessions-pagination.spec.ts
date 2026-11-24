import { expect, test, type Page } from "@playwright/test";
import {
  assertNoHorizontalOverflow,
  attachDiagnostics,
  captureVerifiedScreenshot,
} from "./helpers";

async function verifyKeysetPaginationRoundTrip(
  page: Page,
  opts: {
    url: string;
    pagerLabel: string;
    rpcSegment: string;
    contextLabel: string;
  },
): Promise<void> {
  await page.goto(opts.url);
  const pagerNav = page.getByRole("navigation", { name: opts.pagerLabel });
  await expect(pagerNav).toBeVisible();
  await assertNoHorizontalOverflow(page, `${opts.contextLabel} page 1`);

  const nextBtn = pagerNav.getByRole("button", { name: "Go to next page" });
  await expect(nextBtn).toBeEnabled();

  const [nextResp] = await Promise.all([
    page.waitForResponse((res) => {
      if (!res.url().includes(opts.rpcSegment) || res.request().method() !== "POST" || res.status() !== 200) {
        return false;
      }
      try {
        const body = res.request().postDataJSON() as Record<string, unknown> | null;
        return typeof body?.pageToken === "string" && body.pageToken.length > 0;
      } catch {
        return false;
      }
    }),
    nextBtn.click(),
  ]);
  const reqBody = nextResp.request().postDataJSON() as Record<string, unknown>;
  expect(typeof reqBody.pageToken).toBe("string");
  expect(String(reqBody.pageToken ?? "")).not.toBe("");
  await expect(page).toHaveURL(/pageToken=/);
  await expect(page).toHaveURL(/page=1/);
  await assertNoHorizontalOverflow(page, `${opts.contextLabel} page 2`);

  const prevBtn = pagerNav.getByRole("button", { name: "Go to previous page" });
  await expect(prevBtn).toBeEnabled();
  await prevBtn.click();
  await expect(page).not.toHaveURL(/page=1/);
}

test.describe("AIP-158 Sealed Keyset Pagination & AIP-160 Search/Filters", () => {
  test("drives server-side keyset page_token pagination and filters across Endpoints, Agents, MCP servers, Skills, Sessions, and Users", async ({
    page,
  }, testInfo) => {
    const diagnostics = attachDiagnostics(page);

    await verifyKeysetPaginationRoundTrip(page, {
      url: "/inventory/endpoints?pageSize=2",
      pagerLabel: "Enrolled devices pagination",
      rpcSegment: "InventoryService/ListDevices",
      contextLabel: "Endpoints",
    });

    await page.getByRole("button", { name: "Outliers only" }).click();
    await expect(page).toHaveURL(/outliers=true/);
    await page.getByRole("button", { name: "Outliers only" }).click();
    await expect(page).not.toHaveURL(/outliers=/);
    await captureVerifiedScreenshot(page, testInfo.project.name, "04-inventory-endpoints");

    await verifyKeysetPaginationRoundTrip(page, {
      url: "/inventory/agents?pageSize=2",
      pagerLabel: "Agents pagination",
      rpcSegment: "InventoryService/ListAgents",
      contextLabel: "Agents",
    });
    const agentSearch = page.getByLabel("Search agents");
    await agentSearch.fill("codex");
    await expect(page).toHaveURL(/q=codex/);
    await expect(page.locator("table").getByText("Codex").first()).toBeVisible();
    await agentSearch.fill("");

    await verifyKeysetPaginationRoundTrip(page, {
      url: "/inventory/mcps?pageSize=2",
      pagerLabel: "MCP servers pagination",
      rpcSegment: "InventoryService/ListMcpServers",
      contextLabel: "MCP servers",
    });
    const mcpSearch = page.getByLabel("Search MCP servers");
    await mcpSearch.fill("postgres");
    await expect(page).toHaveURL(/q=postgres/);
    await expect(page.locator("table").getByText("postgres").first()).toBeVisible();
    await mcpSearch.fill("");

    await verifyKeysetPaginationRoundTrip(page, {
      url: "/inventory/skills?pageSize=2",
      pagerLabel: "Skills and rules pagination",
      rpcSegment: "InventoryService/ListArtifacts",
      contextLabel: "Skills & rules",
    });
    const skillSearch = page.getByLabel("Search skills and rules");
    await skillSearch.fill("deploy-helper");
    await expect(page).toHaveURL(/q=deploy-helper/);
    await expect(page.locator("table").getByText("deploy-helper").first()).toBeVisible();
    await skillSearch.fill("");

    await verifyKeysetPaginationRoundTrip(page, {
      url: "/sessions/graph?pageSize=2",
      pagerLabel: "Sessions pagination",
      rpcSegment: "SessionService/ListSessions",
      contextLabel: "Sessions",
    });
    const sessionSearch = page.getByLabel("Search recorded sessions");
    await sessionSearch.fill("sess-demo-triage");
    await expect(page).toHaveURL(/q=sess-demo-triage/);
    await expect(page.locator(".ledger-list").getByText("sess-demo-triage").first()).toBeVisible();
    await captureVerifiedScreenshot(page, testInfo.project.name, "05-sessions-graph");

    await verifyKeysetPaginationRoundTrip(page, {
      url: "/users?pageSize=2",
      pagerLabel: "Users pagination",
      rpcSegment: "UserService/ListUsers",
      contextLabel: "Users",
    });
    const userSearch = page.getByLabel("Filter users");
    await userSearch.fill("Devon");
    await expect(page).toHaveURL(/q=Devon/);
    await expect(page.locator(".ledger-list").getByText("Devon Patel").first()).toBeVisible();

    diagnostics.assertClean();
  });
});
