const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./tests",
  timeout: 30000,
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:8765",
    trace: "off",
  },
  webServer: {
    command: "python3 -m uvicorn main:app --host 127.0.0.1 --port 8765",
    cwd: "../api",
    url: "http://127.0.0.1:8765/healthz",
    reuseExistingServer: true,
    env: {
      BUILD_SHA: "0123456789abcdef",
    },
  },
});
