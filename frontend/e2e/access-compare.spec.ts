import { expect, Page, test } from "@playwright/test";
import { DEMO_ACCESS_COMPARE } from "../lib/demoData";

/** Authenticated session mock; `compareEnabled` toggles the feature flag the
 * compare tab is gated on (mirrors how the backend publishes it). */
async function mockAuthenticatedSession(page: Page, compareEnabled: boolean) {
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

    if (path === "/api/health") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          status: "ok",
          ngfw_port: 8443,
          ngfw_access_mode: "allowlist",
          // Snapshots on so the tab bar renders regardless of the compare flag
          // (the bar is only shown when at least one optional tab is enabled),
          // which lets the gating test isolate the compare tab specifically.
          rule_snapshots_enabled: true,
          access_compare_enabled: compareEnabled,
        }),
      });
      return;
    }

    if (path === "/api/session") {
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
          rule_snapshots_enabled: true,
          access_compare_enabled: compareEnabled,
        }),
      });
      return;
    }

    await route.abort();
  });
}

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
        body: JSON.stringify({ status: "ok", ngfw_port: 8443, ngfw_access_mode: "allowlist", access_compare_enabled: true }),
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

test("demo: access-compare tab shows the side-by-side stage diff", async ({ page }) => {
  await openDemo(page);

  await page.getByRole("tab", { name: "Traffic compare" }).click();

  // Both sides render side by side.
  await expect(page.getByText("Side A", { exact: true })).toBeVisible();
  await expect(page.getByText("Side B", { exact: true })).toBeVisible();

  // The demo fixture diverges (side B is blocked at the firewall), so the
  // primary-divergence banner names the first differing stage and that stage
  // carries the "first difference" tag. (Per-stage classification is encoded
  // by row colour, not text, so it is asserted structurally, not by label.)
  await expect(page.getByText(/The first stage where access clearly differs/)).toBeVisible();
  await expect(page.getByText("first difference").first()).toBeVisible();
});

test("live: access-compare tab is available when enabled and trace is allowed", async ({ page }) => {
  await mockAuthenticatedSession(page, true);
  await page.goto("/");
  await expect(page.getByRole("tab", { name: "Traffic compare" })).toBeVisible();
});

test("live: the selected tab survives a page reload (sessionStorage)", async ({ page }) => {
  await mockAuthenticatedSession(page, true);
  await page.goto("/");

  const compareTab = page.getByRole("tab", { name: "Traffic compare" });
  await compareTab.click();
  await expect(compareTab).toHaveAttribute("aria-selected", "true");

  await page.reload();

  // Before the fix, a reload reset the workspace to the default "Traffic check"
  // tab; the selection must now persist.
  await expect(page.getByRole("tab", { name: "Traffic compare" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("tab", { name: "Traffic check" })).toHaveAttribute("aria-selected", "false");
});

test("live: submitting a UDP comparison sends protocol=udp and renders the result", async ({ page }) => {
  let comparePayload: Record<string, unknown> | null = null;

  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;

    if (path === "/api/config") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ default_server: "", trace_animation_enabled: false }) });
      return;
    }
    if (path === "/api/health") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ status: "ok", ngfw_port: 8443, ngfw_access_mode: "allowlist", access_compare_enabled: true }),
      });
      return;
    }
    if (path === "/api/session") {
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
          access_profile: { role_id: "predefined_admin_readonly", role_name: "Read-only administrator", trace_allowed: true },
          access_compare_enabled: true,
        }),
      });
      return;
    }
    if (path === "/api/trace/compare" && route.request().method() === "POST") {
      comparePayload = route.request().postDataJSON();
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(DEMO_ACCESS_COMPARE) });
      return;
    }
    await route.abort();
  });

  await page.goto("/");
  await page.getByRole("tab", { name: "Traffic compare" }).click();

  // The traffic-check tab stays mounted, so scope inputs to the compare panel.
  const panel = page.locator("#tabpanel-compare");
  await panel.getByPlaceholder("example.com:12345").fill("example.com:443");
  await panel.getByRole("button", { name: "UDP", exact: true }).click();
  await panel.getByRole("button", { name: "Compare", exact: true }).click();

  // Result renders (the mocked fixture diverges, so its banner is unique to
  // the result view and unambiguous vs. the "Side A" form label)...
  await expect(panel.getByText(/The first stage where access clearly differs/)).toBeVisible();
  // ...and the request carried the chosen transport (regression: protocol was
  // previously never sent, so UDP-only rules were mis-evaluated as TCP).
  expect(comparePayload).not.toBeNull();
  expect(comparePayload!.protocol).toBe("udp");
});

test("gating: access-compare tab is hidden when access_compare_enabled=false", async ({ page }) => {
  await mockAuthenticatedSession(page, false);
  await page.goto("/");
  // Positive anchor: the snapshots tab (enabled in the mock) confirms the tab
  // bar rendered, so the absence assertion below is meaningful rather than
  // trivially true.
  await expect(page.getByRole("tab", { name: "Rule snapshots" })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole("tab", { name: "Traffic compare" })).toHaveCount(0);
});
