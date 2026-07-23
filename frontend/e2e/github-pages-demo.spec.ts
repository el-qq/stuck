import { expect, test } from "@playwright/test";

// The standard e2e command serves the authenticated application. This spec
// must run only with the dedicated static entry configured by test:e2e:demo.
test.skip(process.env.STUCK_DEMO_E2E !== "1", "requires the static GitHub Pages demo entry");

test("static GitHub Pages demo works without backend requests", async ({ page }) => {
  const apiRequests: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/")) apiRequests.push(url.pathname);
  });

  await page.goto("/");
  await expect(page.getByText("Demo mode", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Exit demo" })).toHaveCount(0);

  // Exercise all three workspaces; the static entry supplies local fixtures
  // rather than using the live login screen's API bootstrap.
  await page.getByRole("button", { name: "Check address" }).click();
  await expect(page.getByText("Access allowed", { exact: true })).toBeVisible();
  await page.getByRole("tab", { name: /Rule hygiene/ }).click();
  await expect(page.getByText("Firewall · Forward")).toBeVisible();
  await page.getByRole("tab", { name: /Rule snapshots/ }).click();
  await expect(page.getByText("Saved snapshots")).toBeVisible();

  expect(apiRequests).toEqual([]);
});
