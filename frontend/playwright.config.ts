import { defineConfig, devices } from "@playwright/test";

const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
const staticDemoE2E = process.env.STUCK_DEMO_E2E === "1";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:3100",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    ...devices["Desktop Chrome"],
    launchOptions: executablePath ? { executablePath } : undefined,
  },
  webServer: {
    command: staticDemoE2E ? "VITE_BASE_PATH=/ npm run build:demo && npm start -- --host 127.0.0.1 --port 3100" : "npm start -- --host 127.0.0.1 --port 3100",
    url: "http://127.0.0.1:3100",
    // A pre-existing live preview is not a valid substitute for the static
    // demo under test: it would hide an accidental API dependency.
    reuseExistingServer: staticDemoE2E ? false : !process.env.CI,
    timeout: 30_000,
  },
});
