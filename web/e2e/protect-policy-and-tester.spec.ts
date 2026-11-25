import {
  assertNoHorizontalOverflow,
  attachDiagnostics,
  captureVerifiedScreenshot,
  expect,
  test,
} from "./helpers";

test.describe("Protect Policy Authoring, Replay Promotion, and Live Tester", () => {
  test("creates, edits, replays, evaluates in Tester, persists across reload, and deletes a Cedar rule", async ({
    page,
  }, testInfo) => {
    const diagnostics = attachDiagnostics(page);
    const uniqueSuffix = `${testInfo.project.name}-${Date.now()}`;
    const initialTitle = `E2E Secret Vault Guard ${uniqueSuffix}`;
    const updatedTitle = `E2E Secret Vault Guard Updated ${uniqueSuffix}`;
    const targetToken = `e2e-vault-${uniqueSuffix}`;

    await page.goto("/protect/rules");
    await expect(page.getByRole("heading", { name: "Protect" })).toBeVisible();
    await assertNoHorizontalOverflow(page, "Protect rules initial");

    await page.getByRole("radio", { name: "Code" }).click();
    await expect(page.getByText("Read-only Cedar projection")).toBeVisible();
    await expect(page.locator("pre.cedar-code")).toContainText("forbid(");
    await assertNoHorizontalOverflow(page, "Protect rules code view");

    await page.getByRole("radio", { name: "Simple" }).click();
    await page.getByRole("button", { name: "New rule" }).click();
    await expect(page.getByRole("heading", { name: "Create policy rule" })).toBeVisible();

    await page.getByLabel("Rule title").fill(initialTitle);
    await page.getByLabel("Target contains pattern").fill(targetToken);
    await page
      .locator(".field")
      .filter({ hasText: "Initial mode" })
      .getByRole("radio", { name: "Watch" })
      .click();
    await page
      .getByLabel("Reason shown on block or approval")
      .fill("Blocked by Playwright E2E persistence test.");

    await page.getByRole("button", { name: "Save rule" }).click();
    await expect(page.getByText(initialTitle)).toBeVisible();
    await assertNoHorizontalOverflow(page, "Protect rules after create");

    await page.reload();
    await expect(page.getByText(initialTitle)).toBeVisible();

    await page.getByRole("button", { name: `Edit rule ${initialTitle}` }).click();
    await expect(page.getByRole("heading", { name: /Edit rule/ })).toBeVisible();
    await page.getByLabel("Rule title").fill(updatedTitle);
    await page.getByRole("button", { name: "Update rule" }).click();
    await expect(page.getByText(updatedTitle)).toBeVisible();

    await page.reload();
    await expect(page.getByText(updatedTitle)).toBeVisible();

    const ruleRow = page.locator(".ledger-row").filter({ hasText: updatedTitle });
    await ruleRow.getByRole("radio", { name: "Block" }).click();
    await expect(page.getByRole("heading", { name: /Replay impact before promoting/ })).toBeVisible();
    await expect(page.getByText(/Window chosen:/)).toBeVisible();
    await assertNoHorizontalOverflow(page, "Protect rules replay impact");

    await page.getByRole("button", { name: "Confirm promotion to block" }).click();
    await expect(page.getByRole("heading", { name: /Replay impact before promoting/ })).toHaveCount(0);

    await captureVerifiedScreenshot(page, testInfo.project.name, "02-protect-rules");

    await page.goto("/tester");
    await expect(page.getByRole("heading", { name: "Live policy tester" })).toBeVisible();
    await assertNoHorizontalOverflow(page, "Tester initial");

    await page.getByLabel("Target path or command").fill(`/tmp/${targetToken}/token.json`);
    await page.getByRole("button", { name: "Evaluate action" }).click();
    const receiptCard = page.locator("div").filter({
      has: page.getByRole("heading", { name: "Decision receipt" }),
      hasText: "SHA-256:",
    }).last();
    await expect(receiptCard).toContainText(`/tmp/${targetToken}/token.json`);
    await expect(receiptCard).toContainText("Blocked by Playwright E2E persistence test.");
    await assertNoHorizontalOverflow(page, "Tester block receipt");

    await page.getByRole("button", { name: "Safe git status (Allow)" }).click();
    await expect(receiptCard).toContainText("git status --short");
    await expect(page.getByText(/SHA-256:/)).toBeVisible();
    await assertNoHorizontalOverflow(page, "Tester allow receipt");

    await page.goto("/protect/rules");
    await expect(page.getByText(updatedTitle)).toBeVisible();
    await page.getByRole("button", { name: `Delete rule ${updatedTitle}` }).click();
    await page.getByRole("button", { name: "Confirm delete" }).click();
    await expect(page.getByText(updatedTitle)).toHaveCount(0);

    await page.reload();
    await expect(page.getByText(updatedTitle)).toHaveCount(0);

    diagnostics.assertClean();
  });
});
