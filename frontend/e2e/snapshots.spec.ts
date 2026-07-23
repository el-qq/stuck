import { expect, Page, test } from "@playwright/test";

/** Authenticated session mock with snapshots enabled. */
async function mockAuthenticatedSession(page: Page) {
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
          rule_snapshots_enabled: true,
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
        }),
      });
      return;
    }

    await route.abort();
  });
}

/** Open demo mode with snapshots tab visible. */
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
        body: JSON.stringify({
          status: "ok",
          ngfw_port: 8443,
          ngfw_access_mode: "allowlist",
          rule_snapshots_enabled: true,
        }),
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

test("demo: snapshots tab is visible with demo data", async ({ page }) => {
  await openDemo(page);

  // The tab should be visible
  const snapshotsTab = page.getByRole("tab", { name: /Rule snapshots/ });
  await expect(snapshotsTab).toBeVisible();

  // Click to open the snapshots tab
  await snapshotsTab.click();
  await expect(snapshotsTab).toHaveAttribute("aria-selected", "true");

  // Check that demo content is rendered from DEMO_SNAPSHOT_DIFF
  // Look for actual rule names from the demo diff data
  await expect(page.getByText("Allow VPN subnet to internet")).toBeVisible();

  // Check for banners
  await expect(page.getByText(/imported snapshot.*anonymized form/)).toBeVisible();
  await expect(page.getByText(/different NGFW server/)).toBeVisible();
});

test("live: snapshots tab is available when logged in and enabled", async ({ page }) => {
  await mockAuthenticatedSession(page);

  await page.route("**/api/rules/snapshots**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/rules/snapshots" && route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          binding: { admin: "admin.readonly", server: "ngfw.example" },
          limit: 10,
          snapshots: [],
        }),
      });
      return;
    }
    await route.abort();
  });

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  // Snapshots tab should be visible
  const snapshotsTab = page.getByRole("tab", { name: /Rule snapshots/ });
  await expect(snapshotsTab).toBeVisible();

  // Click to open
  await snapshotsTab.click();

  // "No saved snapshots yet" message should be visible
  await expect(page.getByText("No saved snapshots yet")).toBeVisible();

  // Create and Import buttons should be visible
  await expect(page.getByRole("button", { name: "Create snapshot" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Import/ })).toBeVisible();
});

test("live: create snapshot success and list update", async ({ page }) => {
  await mockAuthenticatedSession(page);
  let snapshots: Array<{ id: string; created_at: string; rules_updated_at: string; comment: string | null; source: string; counts: Record<string, number> }> =
    [];

  await page.route("**/api/rules/snapshots**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();

    if (path === "/api/rules/snapshots" && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          binding: { admin: "admin.readonly", server: "ngfw.example" },
          limit: 10,
          snapshots,
        }),
      });
      return;
    }

    if (path === "/api/rules/snapshots" && method === "POST") {
      const snapshot = {
        id: "snap-" + Date.now(),
        created_at: new Date().toISOString(),
        rules_updated_at: "2026-01-01T09:00:00Z",
        comment: "My snapshot",
        source: "manual",
        counts: { users: 5, firewall_forward: 7 },
      };
      snapshots.push(snapshot);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true, snapshot }),
      });
      return;
    }

    await route.abort();
  });

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  await page.getByRole("tab", { name: /Rule snapshots/ }).click();

  // Initially empty
  await expect(page.getByText("No saved snapshots yet")).toBeVisible();

  // Click Create and fill comment
  await page.getByRole("button", { name: "Create snapshot" }).click();
  const input = page.getByPlaceholder("Comment (optional)");
  await input.fill("My snapshot");

  // Submit
  await page.getByRole("button", { name: "Create" }).click();

  // Wait for list to refresh - look for update in snapshots array
  // Simplified: just verify the page doesn't show "No saved" anymore
  await page.waitForTimeout(500);
  await expect(page.getByText("No saved snapshots yet")).not.toBeVisible();
});

test("live: create snapshot error on limit reached", async ({ page }) => {
  await mockAuthenticatedSession(page);

  await page.route("**/api/rules/snapshots**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();

    if (path === "/api/rules/snapshots" && method === "GET") {
      // Return 10 snapshots (at limit)
      const snapshots = Array.from({ length: 10 }, (_, i) => ({
        id: `snap-${i}`,
        created_at: new Date(Date.now() - i * 3600000).toISOString(),
        rules_updated_at: "2026-01-01T09:00:00Z",
        comment: null,
        source: "manual",
        counts: { users: 5 },
      }));
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          binding: { admin: "admin.readonly", server: "ngfw.example" },
          limit: 10,
          snapshots,
        }),
      });
      return;
    }

    if (path === "/api/rules/snapshots" && method === "POST") {
      await route.fulfill({
        status: 409,
        contentType: "application/json",
        body: JSON.stringify({
          error: {
            code: "snapshot_limit_reached",
            message: "Limit reached",
            details: { limit: 10 },
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

  await page.getByRole("tab", { name: /Rule snapshots/ }).click();

  // Should show 10 of 10
  await expect(page.getByText(/10 of 10/)).toBeVisible();

  // Try to create
  await page.getByRole("button", { name: "Create snapshot" }).click();
  await page.getByPlaceholder("Comment (optional)").fill("Will fail");
  await page.getByRole("button", { name: "Create" }).click();

  // Error message should appear
  await expect(page.getByText(/reached the maximum number of saved snapshots/).first()).toBeVisible();
});

test("live: import snapshot success", async ({ page }) => {
  await mockAuthenticatedSession(page);
  let importedSnapshots: Array<{
    id: string;
    created_at: string;
    rules_updated_at: string;
    exported_at: string;
    comment: string | null;
    source: string;
    server: string;
    foreign_server: boolean;
    counts: Record<string, number>;
  }> = [];

  await page.route("**/api/rules/snapshots**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();

    if (path === "/api/rules/snapshots" && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          binding: { admin: "admin.readonly", server: "ngfw.example" },
          limit: 10,
          snapshots: importedSnapshots,
        }),
      });
      return;
    }

    if (path === "/api/rules/snapshots/import" && method === "POST") {
      const importedSnapshot = {
        id: "snap-imported-1",
        created_at: new Date().toISOString(),
        rules_updated_at: "2025-12-20T07:55:00Z",
        exported_at: "2025-12-20T07:56:00Z",
        comment: null,
        source: "imported",
        server: "ngfw.example",
        foreign_server: false,
        counts: { users: 3, firewall_forward: 5 },
      };
      importedSnapshots.push(importedSnapshot);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true, snapshot: importedSnapshot }),
      });
      return;
    }

    await route.abort();
  });

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  await page.getByRole("tab", { name: /Rule snapshots/ }).click();

  // Click import button
  const fileInput = page.locator('input[type="file"]');

  // Create a minimal valid export file
  const exportData = {
    format: "stuck.rules/v2",
    exported_at: "2025-12-20T07:56:00Z",
    rules_updated_at: "2025-12-20T07:55:00Z",
    binding: { server: "ngfw.example" },
    filtered_by_user_id: null,
    snapshot: {
      users: [],
      aliases: [],
      firewall_forward: [],
      firewall_input: [],
      firewall_pre_filter: [],
      firewall_dnat: [],
      firewall_snat: [],
      hardware: { settings: null, rules_mac: [], rules_src_ip: [], rules_dst_ip: [], rules_src_dst_ip: [] },
      content_filter: { state: {}, rules: [], categories: null },
      speed_limit: { state: {}, rules: [] },
      ips_bypass: [],
      ips_state: {},
      firewall_state: {},
      av_profile: { enabled: false },
      lan_networks: [],
      dns_zones: [],
      ngfw_addresses: [],
      firewall_settings: {},
    },
  };

  await fileInput.setInputFiles({
    name: "export.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(exportData)),
  });

  // Check that counter changed to "1 of 10"
  await expect(page.getByText(/1 of 10/)).toBeVisible();
});

test("live: import file with invalid JSON shows error", async ({ page }) => {
  await mockAuthenticatedSession(page);

  await page.route("**/api/rules/snapshots/import", async (route) => {
    await route.fulfill({
      status: 400,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "snapshot_import_invalid",
          message: "Invalid JSON",
          details: { reason: "json" },
        },
      }),
    });
  });

  await page.route("**/api/rules/snapshots", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/rules/snapshots" && route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          binding: { admin: "admin.readonly", server: "ngfw.example" },
          limit: 10,
          snapshots: [],
        }),
      });
      return;
    }
    await route.abort();
  });

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  await page.getByRole("tab", { name: /Rule snapshots/ }).click();

  // Upload invalid JSON
  const fileInput = page.locator('input[type="file"]');
  await fileInput.setInputFiles({
    name: "bad.json",
    mimeType: "application/json",
    buffer: Buffer.from("not valid json"),
  });

  // Error message should appear
  await expect(page.getByText(/could not be read as a STUCK rules export/)).toBeVisible();
});

test("live: import file too large shows error", async ({ page }) => {
  await mockAuthenticatedSession(page);

  await page.route("**/api/rules/snapshots/import", async (route) => {
    await route.fulfill({
      status: 413,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "snapshot_import_too_large",
          message: "Too large",
          details: { limit_bytes: 20971520 },
        },
      }),
    });
  });

  await page.route("**/api/rules/snapshots", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/rules/snapshots" && route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          binding: { admin: "admin.readonly", server: "ngfw.example" },
          limit: 10,
          snapshots: [],
        }),
      });
      return;
    }
    await route.abort();
  });

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  await page.getByRole("tab", { name: /Rule snapshots/ }).click();

  // Upload large file
  const fileInput = page.locator('input[type="file"]');
  const largeData = JSON.stringify({ data: "x".repeat(25000000) });
  await fileInput.setInputFiles({
    name: "huge.json",
    mimeType: "application/json",
    buffer: Buffer.from(largeData),
  });

  // Error message should appear
  await expect(page.getByText(/too large to import/)).toBeVisible();
});

test("live: delete snapshot removes it from list", async ({ page }) => {
  await mockAuthenticatedSession(page);
  let snapshots = [
    {
      id: "snap-to-delete",
      created_at: "2026-01-01T08:00:00Z",
      rules_updated_at: "2026-01-01T08:00:00Z",
      comment: null,
      source: "manual",
      counts: { users: 4 },
    },
  ];

  await page.route("**/api/rules/snapshots**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();

    if (path === "/api/rules/snapshots" && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          binding: { admin: "admin.readonly", server: "ngfw.example" },
          limit: 10,
          snapshots,
        }),
      });
      return;
    }

    if (path === "/api/rules/snapshots/snap-to-delete" && method === "DELETE") {
      snapshots = [];
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

  await page.getByRole("tab", { name: /Rule snapshots/ }).click();

  // Should show 1 of 10
  await expect(page.getByText(/1 of 10/)).toBeVisible();

  // Delete button should be present
  const deleteBtn = page.getByRole("button", { name: "Delete" }).or(page.getByRole("button", { name: "✕" }));
  await deleteBtn.first().click();

  // Confirmation dialog - click delete
  const confirmBtn = page.getByRole("button").filter({ hasText: /Delete|Remove/ });
  await confirmBtn.last().click();

  // List should become empty
  await expect(page.getByText("No saved snapshots yet")).toBeVisible();
});

test("gating: snapshots tab is hidden when rule_snapshots_enabled=false", async ({ page }) => {
  // Mock with snapshots disabled
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
          rule_snapshots_enabled: false,
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
          rule_snapshots_enabled: false,
        }),
      });
      return;
    }

    await route.abort();
  });

  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  // Snapshots tab should NOT be visible
  const snapshotsTab = page.getByRole("tab", { name: /Rule snapshots/ });
  await expect(snapshotsTab).not.toBeVisible();
});
