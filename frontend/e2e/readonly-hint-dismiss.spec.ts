import { expect, Page, test } from "@playwright/test";

/**
 * Mock Bootstrap for login screen (unauthenticated state).
 * Provides minimal API mocks (/api/config, /api/health, /api/session returning 401).
 */
async function mockLoginPageBootstrap(page: Page) {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/config") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ default_server: "", trace_animation_enabled: false }),
      });
      return;
    }
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
        body: JSON.stringify({ status: "ok", ngfw_access_mode: "allowlist" }),
      });
      return;
    }
    await route.abort();
  });
}

test("readonly admin hint is visible by default on login screen", async ({ page }) => {
  await mockLoginPageBootstrap(page);

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  // Check that hint text is visible with correct i18n message
  const hint = page.getByText("We recommend signing in with a read-only administrator account.");
  await expect(hint).toBeVisible();

  // Check that OK button is present
  const okButton = page.getByRole("button", { name: "OK" });
  await expect(okButton).toBeVisible();

  // Verify login form is still visible (isolation check)
  await expect(page.getByLabel("Server")).toBeVisible();
  await expect(page.getByLabel("Login")).toBeVisible();
  await expect(page.getByRole("button", { name: "Connect" })).toBeVisible();
});

test("clicking OK dismisses readonly admin hint and sets cookie", async ({ page }) => {
  await mockLoginPageBootstrap(page);

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  // Click the OK button to dismiss the hint
  await page.getByRole("button", { name: "OK" }).click();

  // Verify hint is no longer visible
  const hint = page.getByText("We recommend signing in with a read-only administrator account.");
  await expect(hint).not.toBeVisible();

  // Verify cookie is set correctly
  const cookies = await page.context().cookies();
  const dismissed = cookies.find((c) => c.name === "stuck_ro_hint_dismissed");
  expect(dismissed).toBeDefined();
  expect(dismissed?.value).toBe("1");
  expect(dismissed?.sameSite).toBe("Lax");
  expect(dismissed?.path).toBe("/");

  // Verify login form is still fully visible after dismissing (isolation check)
  await expect(page.getByLabel("Server")).toBeVisible();
  await expect(page.getByLabel("Login")).toBeVisible();
  await expect(page.getByRole("button", { name: "Connect" })).toBeVisible();
});

test("readonly admin hint does not appear after page reload once dismissed", async ({ page }) => {
  await mockLoginPageBootstrap(page);

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  // Click OK to dismiss the hint
  await page.getByRole("button", { name: "OK" }).click();

  // Wait for hint to disappear
  const hint = page.getByText("We recommend signing in with a read-only administrator account.");
  await expect(hint).not.toBeVisible();

  // Reload the page
  await page.reload();

  // Mock the same API responses for the reloaded page
  await mockLoginPageBootstrap(page);

  // Verify hint is NOT visible after reload (cookie persists)
  await expect(hint).not.toBeVisible();

  // Verify login form is still visible
  await expect(page.getByLabel("Server")).toBeVisible();
  await expect(page.getByLabel("Login")).toBeVisible();
});

test("readonly admin hint appears again when cookie is cleared", async ({ page }) => {
  await mockLoginPageBootstrap(page);

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  // Click OK to dismiss the hint and set cookie
  await page.getByRole("button", { name: "OK" }).click();

  const hint = page.getByText("We recommend signing in with a read-only administrator account.");
  await expect(hint).not.toBeVisible();

  // Clear the cookie
  await page.context().clearCookies({ name: "stuck_ro_hint_dismissed" });

  // Reload page
  await page.reload();

  // Mock the same API responses for the reloaded page
  await mockLoginPageBootstrap(page);

  // Verify hint appears again (since cookie is gone)
  await expect(hint).toBeVisible();

  // Verify OK button is present again
  const okButton = page.getByRole("button", { name: "OK" });
  await expect(okButton).toBeVisible();
});
