import { expect, Page, test } from "@playwright/test";
import { DEMO_HYGIENE_REPORT } from "../lib/demoData";

/** Offline demo bootstrap: no backend, /api/* is mocked at the network edge. */
async function openDemo(page: Page) {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/session") {
      await route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ error: { code: "not_authenticated", message: "Not authenticated" } }),
      });
      return;
    }
    if (path === "/api/health") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ status: "ok", ngfw_port: 8443, ngfw_access_mode: "allowlist" }),
      });
      return;
    }
    if (path === "/api/config") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ default_server: "", trace_animation_enabled: true }),
      });
      return;
    }
    await route.abort();
  });
  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;
  await page.getByRole("button", { name: "Explore the demo" }).click();
  await expect(page.getByText("Demo mode", { exact: true })).toBeVisible();
}

test("demo hygiene tab shows the grouped report and filters by section", async ({ page }) => {
  await openDemo(page);

  // The tab carries the findings-count badge.
  const hygieneTab = page.getByRole("tab", { name: new RegExp(`Rule hygiene\\s*${DEMO_HYGIENE_REPORT.summary.total}`) });
  await hygieneTab.click();
  await expect(hygieneTab).toHaveAttribute("aria-selected", "true");

  // The check workspace is hidden (not unmounted) while hygiene is open.
  await expect(page.locator("#tabpanel-check")).toBeHidden();

  // Both chain groups and a known finding are visible.
  await expect(page.getByText("Firewall · Forward")).toBeVisible();
  await expect(page.getByText("Firewall · Input")).toBeVisible();
  await expect(page.getByText("«TEMP: allow any→any (debug)»").first()).toBeVisible();

  // Left-panel navigation filters the tree down to one chain.
  await page.getByRole("button", { name: /^Forward/ }).click();
  await expect(page.getByText("Firewall · Forward")).toBeVisible();
  await expect(page.getByText("Firewall · Input")).toHaveCount(0);

  // Back to "All" restores both groups.
  await page.getByRole("button", { name: /^All/ }).click();
  await expect(page.getByText("Firewall · Input")).toBeVisible();

  // Returning to the check tab restores the workspace.
  await page.getByRole("tab", { name: "Traffic check" }).click();
  await expect(page.locator("#tabpanel-check")).toBeVisible();
  await expect(page.locator("#tabpanel-hygiene")).toBeHidden();
});

test("mobile: hygiene tab is reachable and the tab bar stays visible when scrolling", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 720 });
  await openDemo(page);

  // Run a check so the page has scrollable results, then scroll down.
  await page.getByRole("button", { name: "Check address" }).click();
  await page.mouse.wheel(0, 1200);

  // The sticky tab bar must remain actionable after scrolling.
  const hygieneTab = page.getByRole("tab", { name: /Rule hygiene/ });
  await expect(hygieneTab).toBeInViewport();
  await hygieneTab.click();
  await expect(page.getByText("Firewall · Forward")).toBeVisible();
});
