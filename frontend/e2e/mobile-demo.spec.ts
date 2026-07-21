import { expect, Page, test } from "@playwright/test";
import { STAGE_ORDER } from "../lib/types";

const MOBILE_WIDTHS = [320, 360, 390, 430, 768] as const;

async function mockAnonymousBootstrap(
  page: Page,
  ngfwAccessMode: "allowlist" | "unrestricted" = "allowlist",
  traceAnimationEnabled = true,
  defaultServer = "",
) {
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
          ngfw_access_mode: ngfwAccessMode,
        }),
      });
      return;
    }
    if (path === "/api/config") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ default_server: defaultServer, trace_animation_enabled: traceAnimationEnabled }),
      });
      return;
    }
    await route.abort();
  });
}

async function openDemo(page: Page, traceAnimationEnabled = true) {
  await mockAnonymousBootstrap(page, "allowlist", traceAnimationEnabled);
  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;
  await page.getByRole("button", { name: "Explore the demo" }).click();
  await expect(page.getByText("Demo mode", { exact: true })).toBeVisible();
}

async function openAuthenticatedApp(page: Page) {
  await page.route("**/api/config", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ default_server: "", trace_animation_enabled: true }),
    });
  });
  await page.route("**/api/session", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        login: "mobile.admin.with.a.long.login",
        server: "ngfw-with-a-very-long-hostname.example.internal",
        expires_at: "2099-01-01T00:00:00Z",
        rules_loaded: true,
        rules_updated_at: "2026-01-01T09:00:00Z",
      }),
    });
  });
  await page.goto("/");
  await expect(page.getByText("Check an address", { exact: true })).toBeVisible();
}

async function expectNoHorizontalOverflow(page: Page) {
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
    bodyScrollWidth: document.body.scrollWidth,
  }));
  expect(dimensions.scrollWidth).toBe(dimensions.clientWidth);
  expect(dimensions.bodyScrollWidth).toBeLessThanOrEqual(dimensions.clientWidth);
}

for (const width of MOBILE_WIDTHS) {
  test(`demo success is one-column without overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: width === 768 ? 1024 : 800 });
    await openDemo(page);
    await expectNoHorizontalOverflow(page);

    const controls = await page.locator(".check-workspace__controls").boundingBox();
    const resultBefore = await page.locator(".check-workspace__result").boundingBox();
    expect(controls).not.toBeNull();
    expect(resultBefore).not.toBeNull();
    expect(resultBefore!.y).toBeGreaterThanOrEqual(controls!.y + controls!.height);

    await page.getByRole("button", { name: "Check address" }).click();
    await expect(page.getByText("Access allowed", { exact: true })).toBeVisible();
    await expect(page.locator(".stage-node")).toHaveCount(STAGE_ORDER.length);
    await page.waitForTimeout(500);
    const resultAfter = await page.locator(".check-workspace__result").boundingBox();
    expect(resultAfter).not.toBeNull();
    expect(resultAfter!.y).toBeLessThanOrEqual(130);
    await expectNoHorizontalOverflow(page);
  });
}

test("login form itself fits 320px and uses iOS-safe field sizes", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await mockAnonymousBootstrap(page);
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Explore the demo" })).toBeVisible();
  await expectNoHorizontalOverflow(page);

  const fieldSizes = await page.locator("input").evaluateAll((inputs) => inputs.map((input) => Number.parseFloat(getComputedStyle(input).fontSize)));
  expect(fieldSizes.every((size) => size >= 16)).toBe(true);
});

test("login warns when unrestricted NGFW lab mode is enabled", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockAnonymousBootstrap(page, "unrestricted");
  await page.goto("/");

  await expect(page.getByText(/Lab mode is enabled/i)).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("configured default server is locked on the login form", async ({ page }) => {
  await mockAnonymousBootstrap(page, "allowlist", true, "locked-ngfw.example");
  const configLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/config");
  await page.goto("/");
  await configLoaded;

  const server = page.getByLabel("Server");
  await expect(server).toHaveValue("locked-ngfw.example");
  await expect(server).toBeDisabled();
  await expect(server).toHaveCSS("background-color", "rgb(238, 240, 244)");
  await expect(server).toHaveCSS("color", "rgb(102, 115, 138)");
  await expect(server).toHaveCSS("cursor", "not-allowed");
});

test("a preset value in the port field maps to its service and submits", async ({ page }) => {
  let tracePayload: unknown;
  await page.route("**/api/trace", async (route) => {
    tracePayload = route.request().postDataJSON();
    await route.fulfill({
      status: 422,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "validation_error", message: "test response" } }),
    });
  });
  await openAuthenticatedApp(page);

  await page.getByPlaceholder("example.com:12345").fill("target.example");
  const portField = page.getByLabel("Port / service");
  await portField.fill("3389");
  // The field holds the number; the matched service name shows on hover.
  await expect(portField).toHaveAttribute("title", "RDP");

  await page.getByRole("button", { name: "Check address" }).click();
  await expect.poll(() => tracePayload).toEqual({ url: "target.example:3389" });
});

test("the port field accepts any custom port inline", async ({ page }) => {
  let tracePayload: unknown;
  await page.route("**/api/trace", async (route) => {
    tracePayload = route.request().postDataJSON();
    await route.fulfill({
      status: 422,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "validation_error", message: "test response" } }),
    });
  });
  await openAuthenticatedApp(page);

  await page.getByPlaceholder("example.com:12345").fill("target.example");
  const portField = page.getByLabel("Port / service");
  await portField.fill("9443");
  await expect(portField).toHaveAttribute("title", "Port 9443");

  await page.getByRole("button", { name: "Check address" }).click();
  await expect.poll(() => tracePayload).toEqual({ url: "target.example:9443" });
});

test("a port typed into the address moves into the port block on blur", async ({ page }) => {
  await openAuthenticatedApp(page);

  const address = page.getByPlaceholder("example.com:12345");
  await address.fill("intranet.example:443");
  await address.blur();
  await expect(address).toHaveValue("intranet.example");
  await expect(page.getByLabel("Port / service")).toHaveValue("443");
});

test("pasting a URL reduces it to its host and port", async ({ page }) => {
  await openAuthenticatedApp(page);

  const address = page.getByPlaceholder("example.com:12345");
  await address.click();
  await page.evaluate(() => {
    const dt = new DataTransfer();
    dt.setData("text/plain", "https://sub.example.com:8443/path?q=1#frag");
    document.activeElement!.dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }));
  });

  await expect(address).toHaveValue("sub.example.com");
  await expect(page.getByLabel("Port / service")).toHaveValue("8443");
});

test("demo derives the service from its selected target", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await openDemo(page);

  const portField = page.locator("[data-service-preset]");
  await expect(portField).toHaveValue("443");
  await expect(portField).toHaveAttribute("title", "HTTPS");
  await expect(portField).toHaveAttribute("data-service-preset", "HTTPS");

  await page.getByRole("button", { name: "failure.com:8080" }).click();
  await expect(portField).toHaveValue("8080");
  await expect(portField).toHaveAttribute("title", "Port 8080");
  await expect(portField).toHaveAttribute("data-service-preset", "");
  await expectNoHorizontalOverflow(page);
});

test("failure result and long rule names wrap on a phone", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 800 });
  await openDemo(page);
  await page.getByRole("button", { name: "failure.com:8080" }).click();
  await page.getByRole("button", { name: "Check address" }).click();

  await expect(page.getByText("Access blocked", { exact: true })).toBeVisible();
  await expect(page.getByText("Default deny (non-standard ports)", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("specific-user controls stack and remain touch-friendly", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 800 });
  await openDemo(page);
  await page.getByRole("button", { name: "As a specific user" }).click();

  const filters = page.locator(".user-picker__filters");
  const search = filters.getByRole("textbox");
  const group = filters.getByRole("combobox");
  const searchBox = await search.boundingBox();
  const groupBox = await group.boundingBox();
  expect(searchBox).not.toBeNull();
  expect(groupBox).not.toBeNull();
  expect(groupBox!.y).toBeGreaterThanOrEqual(searchBox!.y + searchBox!.height);

  const fontSizes = await filters
    .locator("input, select")
    .evaluateAll((elements) => elements.map((element) => Number.parseFloat(getComputedStyle(element).fontSize)));
  expect(fontSizes.every((size) => size >= 16)).toBe(true);

  const touchHeights = await page.locator("button:visible").evaluateAll((buttons) => buttons.map((button) => button.getBoundingClientRect().height));
  expect(touchHeights.every((height) => height >= 44)).toBe(true);
  await expectNoHorizontalOverflow(page);

  await page.getByRole("button", { name: /Alexey Ivanov/ }).click();
  await expect(page.getByRole("button", { name: /Check as Alexey Ivanov/ })).toBeEnabled();
});

test("settings dialog fits the viewport, traps focus and closes with Escape", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 640 });
  await openDemo(page);
  const settings = page.getByRole("button", { name: "Settings" });
  await settings.click();

  const dialog = page.getByRole("dialog", { name: "Settings" });
  await expect(dialog).toBeVisible();
  const box = await dialog.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.y).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(360);
  expect(box!.y + box!.height).toBeLessThanOrEqual(640);
  await expect(page.locator("body")).toHaveCSS("overflow", "hidden");

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(settings).toBeFocused();
  await expectNoHorizontalOverflow(page);
});

test("Russian dark theme remains responsive", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openDemo(page);
  await page.getByRole("button", { name: "Settings" }).click();
  const darkTheme = page.getByRole("button", { name: "Dark" });
  await darkTheme.click();
  await expect(darkTheme).toBeFocused();

  const language = page.getByRole("combobox");
  await language.focus();
  await language.selectOption("ru");
  await expect(language).toBeFocused();
  await page.keyboard.press("Escape");

  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.getByText("Демо-режим", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
  await page.getByRole("button", { name: "Проверить адрес" }).click();
  await expect(page.getByText("Доступ разрешён", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("landscape compact layout stays one-column", async ({ page }) => {
  await page.setViewportSize({ width: 844, height: 390 });
  await openDemo(page);
  await page.getByRole("button", { name: "Check address" }).click();
  await expect(page.getByText("Access allowed", { exact: true })).toBeVisible();
  const columns = await page.locator(".check-workspace").evaluate((workspace) => getComputedStyle(workspace).gridTemplateColumns.split(" ").length);
  expect(columns).toBe(1);
  await expectNoHorizontalOverflow(page);
});

test("authenticated mobile header and real workspace do not overflow", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 800 });
  await openAuthenticatedApp(page);
  await expect(page.getByRole("button", { name: "Refresh" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
  await expect(page.locator(".app-header__identity")).toHaveCSS("text-overflow", "ellipsis");
  await expectNoHorizontalOverflow(page);

  const controls = await page.locator(".check-workspace__controls").boundingBox();
  const result = await page.locator(".check-workspace__result").boundingBox();
  expect(controls).not.toBeNull();
  expect(result).not.toBeNull();
  expect(result!.y).toBeGreaterThanOrEqual(controls!.y + controls!.height);
});

test("reduced motion skips the desktop stage timer", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 800 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await openDemo(page);
  await page.getByRole("button", { name: "Check address" }).click();
  await page.waitForTimeout(50);

  await expect(page.locator(".stage-node")).toHaveCount(STAGE_ORDER.length);
  await expect(page.getByText("Access allowed", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("live user with multiple source IPs requires a mobile-friendly choice", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 800 });
  await page.route("**/api/users/user.id.1/source-addresses", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        user_id: "user.id.1",
        addresses: [
          { ip: "10.0.0.10", subnet: "10.0.0.10/24", external_ip: null, auth_module: "web", node_name: null, active: true, assigned: false },
          { ip: "10.0.0.11", subnet: "10.0.0.11/24", external_ip: null, auth_module: "ip_permanent", node_name: null, active: false, assigned: true },
        ],
      }),
    });
  });
  await page.route("**/api/users", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        users: [{ id: "user.id.1", name: "Mobile User", login: "mobile", enabled: true, domain_type: "local", group_id: null }],
        rules_updated_at: "2026-01-01T09:00:00Z",
        cached: true,
      }),
    });
  });
  await openAuthenticatedApp(page);
  await page.getByRole("button", { name: "As a specific user" }).click();
  await page.getByRole("button", { name: /Mobile User/ }).click();

  await expect(page.getByRole("radio", { name: "10.0.0.10" })).toBeVisible();
  await expect(page.getByRole("radio", { name: "10.0.0.11" })).toBeVisible();
  await page.getByPlaceholder("example.com:12345").fill("example.com");
  await expect(page.getByRole("button", { name: /Check as Mobile User/ })).toBeDisabled();
  await page.getByRole("radio", { name: "10.0.0.11" }).click();
  await expect(page.getByRole("button", { name: /Check as Mobile User/ })).toBeEnabled();
  await expectNoHorizontalOverflow(page);
});

test("user without a source IP can still run an identity-only check", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 800 });
  await page.route("**/api/users/user.id.1/source-addresses", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ user_id: "user.id.1", addresses: [] }),
    });
  });
  await page.route("**/api/users", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        users: [{ id: "user.id.1", name: "No IP User", login: "no-ip", enabled: true, domain_type: "local", group_id: null }],
        rules_updated_at: "2026-01-01T09:00:00Z",
        cached: true,
      }),
    });
  });

  await openAuthenticatedApp(page);
  await page.getByRole("button", { name: "As a specific user" }).click();
  await page.getByRole("button", { name: /No IP User/ }).click();
  await page.getByPlaceholder("example.com:12345").fill("example.com");

  await expect(page.getByText(/no active or assigned IP address/i)).toBeVisible();
  await expect(page.getByRole("button", { name: /Check as No IP User/ })).toBeEnabled();
  await expectNoHorizontalOverflow(page);
});

test("desktop keeps the staged animation and the skip control", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 800 });
  await openDemo(page);
  await page.getByRole("button", { name: "Check address" }).click();

  await page.waitForTimeout(100);
  await expect(page.locator(".stage-node")).toHaveCount(0);
  await page.waitForTimeout(400);
  await expect(page.locator(".stage-node")).toHaveCount(1);
  await page.getByRole("button", { name: "Skip animation" }).click();
  await expect(page.locator(".stage-node")).toHaveCount(STAGE_ORDER.length);
  await expect(page.getByText("Access allowed", { exact: true })).toBeVisible();
});

test("trace-animation configuration shows the full result immediately", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 800 });
  await openDemo(page, false);
  await page.getByRole("button", { name: "Check address" }).click();

  await expect(page.locator(".stage-node")).toHaveCount(STAGE_ORDER.length);
  await expect(page.getByText("Access allowed", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Skip animation" })).toBeHidden();
});
