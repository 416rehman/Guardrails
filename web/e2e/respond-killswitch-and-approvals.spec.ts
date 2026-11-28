// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import type { Frame } from "@playwright/test";
import {
  assertNoHorizontalOverflow,
  attachDiagnostics,
  captureVerifiedScreenshot,
  expect,
  rpcPost,
  test,
} from "./helpers";

test.describe("Respond Kill Switch, Single-Use Approvals, Findings, and Live SSE", () => {
  test("exercises ethical-friction kill switch modal, mints and consumes single-use Ask grant, denies approval, and receives live SSE updates", async ({
    page,
    request,
  }, testInfo) => {
    const diagnostics = attachDiagnostics(page);
    const suffix = `${testInfo.project.name}-${Date.now()}`;
    const sshTarget = `~/.ssh/id_rsa_e2e_${suffix}`;
    const sessionId = `sess-e2e-ask-${suffix}`;

    try {
      await rpcPost(request, "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate", {
        sessionId,
        deviceId: "dev-demo-01",
        deviceName: "dev-macbook-pro",
        agentName: "Claude Code",
        actionClass: "ACTION_CLASS_FILE_READ",
        target: sshTarget,
        summary: "Trigger Ask approval for single-use grant test",
      });

      await page.goto("/respond");
      await expect(page.getByRole("heading", { name: "Respond" })).toBeVisible();
      await expect(page.getByRole("heading", { name: /Pending approval queue/ })).toBeVisible();
      await expect(page.getByText("1s hold to confirm")).toBeVisible();
      await assertNoHorizontalOverflow(page, "Respond initial");

      const approvalCard = page
        .locator(".grdr-attention-card")
        .filter({ hasText: sshTarget })
        .first();
      await expect(approvalCard).toBeVisible();

      const allowOnceBtn = approvalCard.getByRole("button", { name: "Allow once" });
      await allowOnceBtn.click();
      await expect(
        approvalCard.getByRole("button", { name: "Arming (1s)..." }),
      ).toBeVisible();
      const confirmBtn = approvalCard.getByRole("button", { name: "Confirm Allow once" });
      await expect(confirmBtn).toBeVisible({ timeout: 5_000 });
      await confirmBtn.click();
      await expect(
        page.locator(".grdr-attention-card").filter({ hasText: sshTarget }),
      ).toHaveCount(0);

      const firstUse = await rpcPost(
        request,
        "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate",
        {
          sessionId,
          deviceId: "dev-demo-01",
          deviceName: "dev-macbook-pro",
          agentName: "Claude Code",
          actionClass: "ACTION_CLASS_FILE_READ",
          target: sshTarget,
          summary: "Consume minted single-use Ask grant",
        },
      );
      const firstReceipt = firstUse.receipt as Record<string, unknown> | undefined;
      expect(firstReceipt?.verdict).toBe("VERDICT_ALLOW");
      expect(typeof firstReceipt?.grantId).toBe("string");
      expect(String(firstReceipt?.grantId ?? "")).not.toBe("");

      const secondUse = await rpcPost(
        request,
        "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate",
        {
          sessionId,
          deviceId: "dev-demo-01",
          deviceName: "dev-macbook-pro",
          agentName: "Claude Code",
          actionClass: "ACTION_CLASS_FILE_READ",
          target: sshTarget,
          summary: "Verify single-use grant is depleted on second call",
        },
      );
      const secondReceipt = secondUse.receipt as Record<string, unknown> | undefined;
      expect(secondReceipt?.verdict).toBe("VERDICT_STEP_UP");

      await page.reload();
      const requeuedCard = page
        .locator(".grdr-attention-card")
        .filter({ hasText: sshTarget })
        .first();
      await expect(requeuedCard).toBeVisible();
      await requeuedCard.getByRole("button", { name: "Deny" }).click();
      await expect(
        page.locator(".grdr-attention-card").filter({ hasText: sshTarget }),
      ).toHaveCount(0);

      const findingsCard = page
        .locator("div")
        .filter({ has: page.getByRole("heading", { name: /Findings \(\d+\)/ }) })
        .first();
      const acknowledgeBtn = findingsCard.getByRole("button", { name: "Acknowledge" }).first();
      if ((await acknowledgeBtn.count()) > 0) {
        await acknowledgeBtn.click();
        await expect(findingsCard.locator("table").getByText("Acknowledged").first()).toBeVisible();
      }
      await expect(page.getByRole("heading", { name: /Correlated incidents/ })).toBeVisible();

      await page.getByRole("button", { name: "Emergency controls" }).click();
      const modal = page.getByRole("dialog", { name: "Scoped Kill Switch Matrix" });
      await expect(modal).toBeVisible();
      await assertNoHorizontalOverflow(page, "Kill switch modal open");

      const activateDisabled = modal.getByRole("button", { name: /Activate kill switch \(0\)/ });
      await expect(activateDisabled).toBeDisabled();

      await modal.getByRole("checkbox", { name: "Claude Code" }).click();
      await expect(
        modal.getByText("Preview: will isolate 1 agent type, 0 providers, and 0 gateways."),
      ).toBeVisible();
      const activateOne = modal.getByRole("button", { name: /Activate kill switch \(1\)/ });
      await expect(activateOne).toBeDisabled();

      await modal.getByLabel("Type fleet-kill to confirm").fill("fleet-kill");
      await expect(activateOne).toBeEnabled();
      await activateOne.click();
      await expect(modal).toHaveCount(0);

      const releaseBtn = page.getByRole("button", { name: "Release" });
      await expect(releaseBtn).toBeVisible();
      await assertNoHorizontalOverflow(page, "Respond kill switch active");
      await captureVerifiedScreenshot(page, testInfo.project.name, "03-respond-killswitch");

      await releaseBtn.click();
      await expect(releaseBtn).toHaveCount(0);

      const suppressOrphanRejection = () => undefined;
      let homeNavCommitted = false;
      const onMainFrameNavigated = (frame: Frame) => {
        if (frame === page.mainFrame() && new URL(frame.url()).pathname === "/") {
          homeNavCommitted = true;
        }
      };
      page.on("framenavigated", onMainFrameNavigated);
      const initialOverview = page.waitForResponse(
        (res) =>
          homeNavCommitted &&
          res.url().includes("OverviewService/GetOverview") &&
          res.status() === 200,
      );
      const liveStreamOpen = page.waitForResponse(
        (res) =>
          homeNavCommitted &&
          res.url().includes("OverviewService/LiveEvents") &&
          res.status() === 200,
      );
      initialOverview.catch(suppressOrphanRejection);
      liveStreamOpen.catch(suppressOrphanRejection);
      try {
        await Promise.all([page.goto("/"), initialOverview, liveStreamOpen]);
      } finally {
        page.off("framenavigated", onMainFrameNavigated);
      }
      await expect(page.getByRole("region", { name: "Protection overview" })).toBeVisible();

      const liveTarget = `~/.ssh/id_rsa_sse_${suffix}`;
      const [sseResponse] = await Promise.all([
        page.waitForResponse(
          (res) =>
            res.url().includes("OverviewService/GetOverview") && res.status() === 200,
        ),
        rpcPost(request, "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate", {
          sessionId: `sess-sse-${suffix}`,
          deviceId: "dev-demo-01",
          deviceName: "dev-macbook-pro",
          agentName: "Claude Code",
          actionClass: "ACTION_CLASS_FILE_READ",
          target: liveTarget,
          summary: "Verify SSE invalidation triggers live overview refresh",
        }),
      ]);
      expect(sseResponse.ok()).toBeTruthy();

      const pendingAfter = await rpcPost(
        request,
        "/grdr.api.response.v1alpha1.ResponseService/ListApprovals",
        { pageSize: 25, filter: 'status = "pending"' },
      );
      const approvalsList = Array.isArray(pendingAfter.approvals) ? pendingAfter.approvals : [];
      for (const item of approvalsList) {
        const rec = item as Record<string, unknown>;
        if (rec.target === liveTarget && typeof rec.id === "string") {
          await rpcPost(request, "/grdr.api.response.v1alpha1.ResponseService/DecideApproval", {
            id: rec.id,
            approve: false,
            note: "Cleanup SSE test approval",
          });
        }
      }
    } finally {
      await rpcPost(request, "/grdr.api.response.v1alpha1.ResponseService/SetKillSwitch", {
        action: "KILL_ACTION_RELEASE",
        scope: "KILL_SCOPE_SESSION",
        targetId: "sess-demo-refactor",
        reason: "E2E cleanup",
      }).catch(() => {});
    }

    diagnostics.assertClean();
  });
});
