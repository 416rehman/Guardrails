// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import {
  assertNoHorizontalOverflow,
  attachDiagnostics,
  captureVerifiedScreenshot,
  expect,
  rpcPost,
  test,
} from "./helpers";

test.describe("W4-2 Live Telemetry, Dynamic Matrices, Responsive Tables, Cedar Filter, and Large Graph", () => {
  test("drives Home velocity from live evaluations and verifies responsive Coverage, Inventory, Sessions, Protect, Tester, and honest KillSwitch payloads", async ({
    page,
    request,
  }, testInfo) => {
    const diagnostics = attachDiagnostics(page);
    const inflight = new Set<object>();
    page.on("request", (req) => {
      if (!req.url().includes("OverviewService/LiveEvents")) {
        inflight.add(req);
      }
    });
    const finishReq = (req: object) => {
      inflight.delete(req);
    };
    page.on("requestfinished", finishReq);
    page.on("requestfailed", finishReq);
    const waitSettled = async () => {
      await expect.poll(() => inflight.size, { timeout: 10_000 }).toBe(0);
    };

    const baseViewport = page.viewportSize() ?? { width: 1440, height: 900 };
    const isDesktop = testInfo.project.name === "desktop";

    const assertDesktopTabletMobileClean = async (label: string) => {
      await waitSettled();
      await assertNoHorizontalOverflow(page, label);
      if (isDesktop) {
        await page.setViewportSize({ width: 768, height: 1024 });
        await assertNoHorizontalOverflow(page, `${label} tablet 768px`);
        await page.setViewportSize(baseViewport);
      }
    };

    await page.goto("/");
    await waitSettled();
    const velocityRegion = page.getByRole("region", { name: "Weekly decision velocity" });
    await expect(velocityRegion).toBeVisible();
    await expect(velocityRegion).not.toContainText("Evaluated agent calls this week (169)");
    await expect(velocityRegion).not.toContainText("Allowed 156");

    const beforeText = await velocityRegion.textContent();
    const beforeMatch = beforeText?.match(/Evaluated agent calls this week \((\d+)\)/);
    expect(beforeMatch).not.toBeNull();
    const beforeTotal = Number.parseInt(beforeMatch?.[1] ?? "0", 10);
    expect(beforeTotal).toBeGreaterThan(0);

    await Promise.all([
      page.waitForResponse(
        (res) =>
          res.url().includes("SessionService/GetSession") && res.status() === 200,
      ),
      rpcPost(request, "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate", {
        sessionId: "sess-demo-refactor",
        deviceId: "dev-demo-01",
        deviceName: "dev-macbook-pro",
        agentName: "Claude Code",
        actionClass: "ACTION_CLASS_EXEC",
        target: "git status --short",
        summary: "W4-2 verify live home decision velocity increments",
      }),
    ]);
    await waitSettled();

    await page.reload();
    await waitSettled();
    await expect(velocityRegion).toBeVisible();
    await expect
      .poll(async () => {
        const txt = (await velocityRegion.textContent()) ?? "";
        const m = txt.match(/Evaluated agent calls this week \((\d+)\)/);
        return m ? Number.parseInt(m[1], 10) : 0;
      })
      .toBeGreaterThanOrEqual(beforeTotal + 1);
    await assertDesktopTabletMobileClean("Home live velocity");
    await captureVerifiedScreenshot(page, testInfo.project.name, "w4-home-live");

    await page.goto("/coverage");
    await expect(page.getByRole("heading", { name: "Coverage", exact: true })).toBeVisible();
    const heatmapTable = page.locator("table.heatmap-grid.responsive-table");
    await expect(heatmapTable).toBeVisible();
    await expect(heatmapTable.locator("tbody tr")).toHaveCount(3);
    await expect(heatmapTable.getByRole("button", { name: "Claude Code" }).first()).toBeVisible();
    await expect(heatmapTable.getByRole("button", { name: "Cursor" }).first()).toBeVisible();
    await expect(heatmapTable.locator("td[data-label]").first()).toBeVisible();
    await expect(page.locator(".table-wrap table.responsive-table").nth(1)).toBeVisible();
    await assertDesktopTabletMobileClean("Coverage dynamic matrix");
    await captureVerifiedScreenshot(page, testInfo.project.name, "w4-coverage");

    for (const inv of [
      { url: "/inventory/agents", name: "Inventory agents" },
      { url: "/inventory/mcps", name: "Inventory MCPs" },
      { url: "/inventory/skills", name: "Inventory skills" },
    ]) {
      await page.goto(inv.url);
      const table = page.locator(".table-wrap table.responsive-table").first();
      await expect(table).toBeVisible();
      expect(await table.locator("td[data-label]").count()).toBeGreaterThan(0);
      await assertDesktopTabletMobileClean(inv.name);
      if (inv.url === "/inventory/agents") {
        await captureVerifiedScreenshot(page, testInfo.project.name, "w4-inventory-agents");
      }
    }

    await page.goto("/sessions");
    await expect(page.getByRole("heading", { name: "Sessions", exact: true })).toBeVisible();
    await page.getByRole("radio", { name: "Stream" }).click();
    await expect(page.locator(".table-wrap table.responsive-table").first()).toBeVisible();
    await assertDesktopTabletMobileClean("Sessions stream table");
    await page.getByRole("radio", { name: "Graph" }).click();
    await assertDesktopTabletMobileClean("Sessions graph view");
    await captureVerifiedScreenshot(page, testInfo.project.name, "w4-sessions");

    const largeSessionRoute = "**/grdr.api.activity.v1alpha1.SessionService/GetSession";
    await page.route(largeSessionRoute, async (route) => {
      const realResp = await route.fetch();
      const body = (await realResp.json()) as Record<string, unknown>;
      const attempts = Array.isArray(body.attempts) ? body.attempts : [];
      const receipts = Array.isArray(body.receipts) ? body.receipts : [];
      const templateAttempt = (attempts[0] ?? {}) as Record<string, unknown>;
      const templateReceipt = (receipts[0] ?? {}) as Record<string, unknown>;
      const scaledAttempts: Array<Record<string, unknown>> = [];
      const scaledReceipts: Array<Record<string, unknown>> = [];
      for (let idx = 0; idx < 105; idx += 1) {
        const attemptId = `att-scale-${idx}`;
        scaledAttempts.push({
          ...templateAttempt,
          id: attemptId,
          target: `src/module-${idx}.ts`,
        });
        scaledReceipts.push({
          ...templateReceipt,
          receiptId: `rcp-scale-${idx}`,
          attemptId,
          target: `src/module-${idx}.ts`,
          verdict: idx === 104 ? "VERDICT_DENY" : "VERDICT_ALLOW",
        });
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...body,
          attempts: scaledAttempts,
          receipts: scaledReceipts,
        }),
      });
    });

    await page.reload();
    await expect(
      page.getByText(/Large session graph \(108 nodes\): clustered by action class/),
    ).toBeVisible();
    await expect(page.locator(".table-wrap table.responsive-table").first()).toBeVisible();
    await assertDesktopTabletMobileClean("Sessions large clustered graph");
    await page.getByRole("button", { name: "Focus denied" }).click();
    await expect(page.getByText("src/module-104.ts").first()).toBeVisible();
    await page.getByRole("button", { name: "Preview priority 100 nodes" }).click();
    const sampledGraph = page.locator('[aria-label="Sampled agent session execution path graph"]');
    await expect(sampledGraph).toBeVisible();
    await expect(sampledGraph.locator(".react-flow__node")).toHaveCount(100);
    await expect(sampledGraph.locator('[data-id="att-scale-104"]')).toHaveCount(1);
    await page.getByRole("button", { name: "Cluster by action class" }).click();
    await expect(page.getByRole("button", { name: "Preview priority 100 nodes" })).toBeVisible();
    await page.unroute(largeSessionRoute);

    await page.goto("/protect/rules");
    await page.getByRole("radio", { name: "Code" }).click();
    await expect(page.getByText("Read-only Cedar projection")).toBeVisible();
    await expect(page.getByRole("button", { name: "Copy Cedar" })).toBeVisible();
    await expect(page.locator("pre.cedar-code")).toContainText("Grdr::Session");
    await expect(page.locator("pre.cedar-code")).toContainText("Grdr::Action::");
    await page.getByPlaceholder("Filter Cedar rules by id, action, or target...").fill("ssh");
    await expect(page.locator("pre.cedar-code")).toContainText("ssh");
    await page.getByPlaceholder("Filter Cedar rules by id, action, or target...").fill("");
    await assertDesktopTabletMobileClean("Protect Cedar projection");
    await captureVerifiedScreenshot(page, testInfo.project.name, "w4-protect-cedar");

    await page.goto("/tester");
    await page.getByRole("button", { name: "Safe git status (Allow)" }).click();
    await expect(page.getByRole("heading", { name: "Decision receipt" })).toBeVisible();
    await assertDesktopTabletMobileClean("Live tester receipt");
    await captureVerifiedScreenshot(page, testInfo.project.name, "w4-tester");

    await page.goto("/respond");
    await waitSettled();
    await page.getByRole("combobox", { name: "Scope" }).click();
    await page.getByRole("option", { name: "Device" }).click();
    await expect(page.getByRole("combobox", { name: "Target ID" })).toContainText("dev-macbook-pro");
    await page.getByRole("combobox", { name: "Scope" }).click();
    await page.getByRole("option", { name: "Session" }).click();
    await expect(page.getByRole("combobox", { name: "Target ID" })).not.toContainText("dev-macbook-pro");

    await page.getByRole("button", { name: "Emergency controls" }).click();
    const modal = page.getByRole("dialog", { name: "Scoped Kill Switch Matrix" });
    await expect(modal).toBeVisible();
    await expect(modal.getByRole("checkbox", { name: "Portkey" })).toHaveCount(0);
    await expect(modal.getByRole("checkbox", { name: "write" })).toHaveCount(0);
    await expect(modal.getByText("No model endpoints discovered in telemetry yet.")).toBeVisible();
    await expect(modal.getByRole("checkbox", { name: "Claude Code" })).toBeVisible();
    await expect(modal.getByRole("checkbox", { name: "Cursor" })).toBeVisible();

    let releasedInUi = false;
    try {
      await modal.getByRole("checkbox", { name: "Cursor" }).click();
      await expect(
        modal.getByText(/Targets endpoint dev-macbook-pro \(dev-demo-01\) using device scope containment/),
      ).toBeVisible();
      await modal.getByLabel("Type fleet-kill to confirm").fill("fleet-kill");

      const [deviceKillReq] = await Promise.all([
        page.waitForRequest(
          (req) =>
            req.url().includes("ResponseService/SetKillSwitch") && req.method() === "POST",
        ),
        modal.getByRole("button", { name: /Activate kill switch \(1\)/ }).click(),
      ]);

      const devicePayload = deviceKillReq.postDataJSON() as Record<string, unknown>;
      expect(devicePayload.scope).toBe("device");
      expect(devicePayload.targetId).toBe("dev-demo-01");
      expect(String(devicePayload.reason ?? "")).toContain("agents=Cursor");
      await expect(
        page.getByText(/Active device containment \(target dev-demo-01\)/),
      ).toBeVisible();

      const releaseBtn = page.getByRole("button", { name: "Release" });
      await expect(releaseBtn).toBeVisible();
      await releaseBtn.click();
      await expect(releaseBtn).toHaveCount(0);
      await waitSettled();

      await page.getByRole("button", { name: "Emergency controls" }).click();
      await expect(modal).toBeVisible();
      await modal.getByRole("checkbox", { name: "Claude Code" }).click();
      await expect(
        modal.getByText(/Fleet-wide organisation containment applies across all/),
      ).toBeVisible();
      await modal.getByLabel("Type fleet-kill to confirm").fill("fleet-kill");

      const [orgKillReq] = await Promise.all([
        page.waitForRequest(
          (req) =>
            req.url().includes("ResponseService/SetKillSwitch") && req.method() === "POST",
        ),
        modal.getByRole("button", { name: /Activate kill switch \(1\)/ }).click(),
      ]);

      const orgPayload = orgKillReq.postDataJSON() as Record<string, unknown>;
      expect(orgPayload.scope).toBe("organisation");
      expect(orgPayload.targetId).toBe("*");
      expect(String(orgPayload.reason ?? "")).toContain("agents=Claude Code");
      await expect(
        page.getByText(/Active fleet-wide organisation containment/),
      ).toBeVisible();
      await assertDesktopTabletMobileClean("Respond active scoped kill switch");
      await captureVerifiedScreenshot(page, testInfo.project.name, "w4-respond-killswitch");

      await page.getByRole("button", { name: "Emergency controls" }).click();
      await expect(modal).toBeVisible();
      await expect(modal.getByRole("checkbox", { name: "Claude Code" })).toBeChecked();
      await expect(modal.getByRole("checkbox", { name: "Cursor" })).not.toBeChecked();
      await modal.getByRole("checkbox", { name: "Cursor" }).click();
      await expect(modal.getByRole("checkbox", { name: "Cursor" })).toBeChecked();
      await modal.getByRole("button", { name: "Cancel" }).click();
      await expect(modal).toHaveCount(0);

      await page.getByRole("button", { name: "Emergency controls" }).click();
      await expect(modal).toBeVisible();
      await expect(modal.getByRole("checkbox", { name: "Claude Code" })).toBeChecked();
      await expect(modal.getByRole("checkbox", { name: "Cursor" })).not.toBeChecked();
      await modal.getByRole("button", { name: "Cancel" }).click();
      await expect(modal).toHaveCount(0);

      await expect(releaseBtn).toBeVisible();
      await releaseBtn.click();
      await expect(releaseBtn).toHaveCount(0);
      await waitSettled();
      releasedInUi = true;
    } finally {
      if (!releasedInUi) {
        await rpcPost(request, "/grdr.api.response.v1alpha1.ResponseService/SetKillSwitch", {
          action: "KILL_ACTION_RELEASE",
          scope: "KILL_SCOPE_ORGANISATION",
          targetId: "*",
          reason: "W4-2 E2E cleanup",
        }).catch(() => {});
      }
    }

    await waitSettled();
    diagnostics.assertClean();
  });
});
