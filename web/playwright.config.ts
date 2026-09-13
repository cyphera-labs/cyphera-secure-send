import { defineConfig } from "@playwright/test";

const port = 18080;
const mgmt = 19090;

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  fullyParallel: false,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    headless: true,
  },
  webServer: {
    command: `../target/debug/cyphera-secure-send serve`,
    url: `http://127.0.0.1:${port}/v1/health`,
    reuseExistingServer: false,
    timeout: 30_000,
    env: {
      CYPHERA_SECURESEND__SERVER__BIND: `127.0.0.1:${port}`,
      CYPHERA_SECURESEND__SERVER__MANAGEMENT_BIND: `127.0.0.1:${mgmt}`,
      CYPHERA_SECURESEND__AUDIT__SINK: "discard",
      CYPHERA_SECURESEND__MESSAGES__KDF__RECOMMENDED_ITERATIONS: "10000",
      CYPHERA_SECURESEND__MESSAGES__KDF__MIN_ITERATIONS: "1000",
      CYPHERA_SECURESEND__MESSAGES__MAX_FAILED_PROOFS: "3",
      CYPHERA_SECURESEND__RATE_LIMITS__CONSUME_PER_MINUTE: "200",
      CYPHERA_SECURESEND__RATE_LIMITS__CREATE_PER_MINUTE: "200",
      CYPHERA_SECURESEND__BRANDING__COMPANY_NAME: "Acme",
      CYPHERA_SECURESEND__BRANDING__COLORS__PRIMARY: "#0057b8",
      RUST_LOG: "warn",
    },
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
