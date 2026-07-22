import { expect, test } from "@playwright/test";

test("rules export requires confirmation before downloading the anonymized attachment", async ({ page }) => {
  let exportRequests = 0;

  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/config") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ default_server: "", trace_animation_enabled: false }) });
      return;
    }
    if (path === "/api/session") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          authenticated: true,
          login: "admin",
          server: "ngfw.example",
          expires_at: "2099-01-01T00:00:00Z",
          rules_loaded: true,
          rules_updated_at: "2026-01-01T00:00:00Z",
          rules_export_enabled: true,
          access_profile: { role_id: "predefined_admin_readonly", role_name: "Read-only administrator", trace_allowed: true },
        }),
      });
      return;
    }
    if (path === "/api/health") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ status: "ok", ngfw_access_mode: "allowlist" }) });
      return;
    }
    if (path === "/api/rules/export") {
      exportRequests += 1;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "Content-Disposition": 'attachment; filename="rules-ngfw.example.json"' },
        body: '{\n  "format": "stuck.rules/v2"\n}\n',
      });
      return;
    }
    await route.abort();
  });

  await page.goto("/");
  await page.getByRole("button", { name: /Export rules/ }).click();

  const dialog = page.getByTestId("rules-export-confirmation");
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("All rules for the current NGFW will be downloaded");
  expect(exportRequests).toBe(0);

  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
  expect(exportRequests).toBe(0);

  await page.getByRole("button", { name: /Export rules/ }).click();
  const download = page.waitForEvent("download");
  await dialog.getByRole("button", { name: "Download" }).click();
  await expect(dialog).toBeHidden();

  expect(exportRequests).toBe(1);
  expect((await download).suggestedFilename()).toBe("rules-ngfw.example.json");
});
