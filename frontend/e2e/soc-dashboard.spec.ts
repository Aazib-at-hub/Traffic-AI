import { expect, test } from "@playwright/test";

test("renders NetSentinel AI login screen", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("NetSentinel AI")).toBeVisible();
  await expect(page.getByRole("button", { name: /Sign In to SOC Workspace/i })).toBeVisible();
});
