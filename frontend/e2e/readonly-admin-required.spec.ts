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

test("login fails with readonly_admin_required when non-read-only admin attempts login", async ({ page }) => {
  // Set up the page routing
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

    if (path === "/api/auth/login") {
      await route.fulfill({
        status: 403,
        contentType: "application/json",
        body: JSON.stringify({
          error: {
            code: "readonly_admin_required",
            message: "Read-only admin role is required",
            details: { role_id: "predefined_admin_write" },
          },
        }),
      });
      return;
    }

    await route.abort();
  });

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  // Fill in the login form
  await page.getByLabel("Server").fill("ngfw.example");
  await page.getByLabel("Login").fill("admin");
  await page.locator('input[type="password"]').fill("password123");

  // Submit the form
  await page.getByRole("button", { name: "Connect" }).click();

  // Verify that the error message is displayed on the login screen
  // The error should be in the red error box (apiErrorText)
  const errorAlert = page.locator('div[role="alert"]').filter({ hasText: /Sign-in is allowed only for administrators/ });
  await expect(errorAlert).toBeVisible();

  // Verify we remain on the login screen (form is still visible)
  await expect(page.getByLabel("Server")).toBeVisible();
  await expect(page.getByLabel("Login")).toBeVisible();
  await expect(page.locator('input[type="password"]')).toBeVisible();
});

test("2FA path: readonly_admin_required after 2FA code is accepted", async ({ page }) => {
  // Track how many times 2FA was called
  let twoFACalls = 0;

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

    if (path === "/api/auth/login") {
      // First attempt: login succeeds with 2FA required
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ok: true,
          two_factor_required: true,
          expires_at: "2026-07-23T10:30:00Z",
          message: "Enter the code from your authenticator",
        }),
      });
      return;
    }

    if (path === "/api/auth/2fa") {
      twoFACalls += 1;
      // After code is submitted, reject with readonly_admin_required
      await route.fulfill({
        status: 403,
        contentType: "application/json",
        body: JSON.stringify({
          error: {
            code: "readonly_admin_required",
            message: "Read-only admin role is required",
            details: { role_id: "predefined_admin_write" },
          },
        }),
      });
      return;
    }

    if (path === "/api/auth/2fa/cancel") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true }),
      });
      return;
    }

    await route.abort();
  });

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  // Fill in the login form
  await page.getByLabel("Server").fill("ngfw.example");
  await page.getByLabel("Login").fill("admin");
  await page.locator('input[type="password"]').fill("password123");

  // Submit the form
  await page.getByRole("button", { name: "Connect" }).click();

  // Verify that the 2FA form appears (title should be visible)
  const twoFactorTitle = page.getByText("Two-factor authentication", { exact: true });
  await expect(twoFactorTitle).toBeVisible();

  // Enter a code
  await page.getByLabel("Confirmation code").fill("123456");

  // Submit the 2FA code
  await page.getByRole("button", { name: "Confirm" }).click();

  // After 2FA rejection with readonly_admin_required, we should be back at login
  // The 2FA form should be gone
  const twoFactorForm = page.getByText("Two-factor authentication", { exact: true });
  await expect(twoFactorForm).not.toBeVisible();

  // The login form should reappear
  await expect(page.getByLabel("Server")).toBeVisible();
  await expect(page.getByLabel("Login")).toBeVisible();

  // The warn banner with readonly_admin_required message should be visible
  const warnBanner = page.locator('div[role="alert"]').filter({ hasText: /Sign-in is allowed only for administrators/ });
  await expect(warnBanner).toBeVisible();

  // Verify the 2FA call was made
  expect(twoFACalls).toBe(1);
});

test("successful login as read-only admin works (regression)", async ({ page }) => {
  let sessionCallCount = 0;

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
      sessionCallCount += 1;
      // First call: unauthenticated (during page load)
      // After login, it should return authenticated
      if (sessionCallCount === 1) {
        await route.fulfill({
          status: 401,
          contentType: "application/json",
          body: JSON.stringify({ error: { code: "not_authenticated", message: "Not authenticated" } }),
        });
      } else {
        // Subsequent calls after login return authenticated
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            authenticated: true,
            login: "admin.readonly",
            server: "ngfw.example",
            expires_at: "2099-01-01T00:00:00Z",
            rules_loaded: true,
            rules_updated_at: "2026-01-01T09:00:00Z",
            ngfw_port: 8443,
            access_profile: {
              role_id: "predefined_admin_readonly",
              role_name: "Read-only administrator",
              trace_allowed: true,
            },
          }),
        });
      }
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

    if (path === "/api/auth/login") {
      // Successful login for read-only admin
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ok: true,
          session: {
            login: "admin.readonly",
            server: "ngfw.example",
            expires_at: "2099-01-01T00:00:00Z",
            first_login: false,
            rules_updated_at: "2026-01-01T09:00:00Z",
          },
        }),
      });
      return;
    }

    await route.abort();
  });

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  // Fill in the login form
  await page.getByLabel("Server").fill("ngfw.example");
  await page.getByLabel("Login").fill("admin.readonly");
  await page.locator('input[type="password"]').fill("password123");

  // Submit the form
  await page.getByRole("button", { name: "Connect" }).click();

  // After successful login, we should see the main application
  // The login form should disappear and we should see the "Check an address" interface
  await expect(page.getByText("Check an address", { exact: true })).toBeVisible();

  // The login form should not be visible anymore
  await expect(page.getByLabel("Server")).not.toBeVisible();
});
