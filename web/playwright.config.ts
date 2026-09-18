import { defineConfig } from "@playwright/test";

const port = 18080;
const mgmt = 19090;
// The enterprise instance and the identity provider it trusts.
const idpPort = 18091;
const entPort = 18084;
const entMgmt = 19094;

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
  webServer: [
    {
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
    {
      command: `node e2e/idp.mjs`,
      url: `http://127.0.0.1:${idpPort}/.well-known/openid-configuration`,
      reuseExistingServer: false,
      timeout: 30_000,
      env: { IDP_PORT: String(idpPort) },
    },
    {
      // Enterprise, in the shape that lets an employee hand a secret to a
      // customer: signing in to create, link and password to read.
      command: `../target/debug/cyphera-secure-send serve`,
      url: `http://127.0.0.1:${entPort}/v1/health`,
      reuseExistingServer: false,
      timeout: 30_000,
      env: {
        CYPHERA_SECURESEND__MODE: "enterprise",
        CYPHERA_SECURESEND__SERVER__BIND: `127.0.0.1:${entPort}`,
        CYPHERA_SECURESEND__SERVER__MANAGEMENT_BIND: `127.0.0.1:${entMgmt}`,
        CYPHERA_SECURESEND__SERVER__PUBLIC_BASE_URL: `http://127.0.0.1:${entPort}`,
        CYPHERA_SECURESEND__ENTERPRISE__OIDC__ISSUER: `http://127.0.0.1:${idpPort}`,
        CYPHERA_SECURESEND__ENTERPRISE__OIDC__CLIENT_ID: "securesend",
        CYPHERA_SECURESEND__ENTERPRISE__OIDC__CLIENT_SECRET: "dev",
        CYPHERA_SECURESEND__ENTERPRISE__CREATION__ALLOWED_DOMAINS: "acme.com",
        CYPHERA_SECURESEND__ENTERPRISE__RECIPIENT__REQUIRE_OIDC: "false",
        CYPHERA_SECURESEND__ENTERPRISE__RECIPIENT__REQUIRE_IDENTITY_MATCH: "false",
        CYPHERA_SECURESEND__ENTERPRISE__RECIPIENT__EXTERNAL_RECIPIENTS: "true",
        CYPHERA_SECURESEND__AUDIT__SINK: "discard",
        CYPHERA_SECURESEND__MESSAGES__KDF__RECOMMENDED_ITERATIONS: "10000",
        CYPHERA_SECURESEND__MESSAGES__KDF__MIN_ITERATIONS: "1000",
        CYPHERA_SECURESEND__RATE_LIMITS__CONSUME_PER_MINUTE: "200",
        CYPHERA_SECURESEND__RATE_LIMITS__CREATE_PER_MINUTE: "200",
        RUST_LOG: "warn",
      },
    },
  ],
  projects: [
    {
      name: "standard",
      testMatch: /flow\.spec\.ts/,
      use: { browserName: "chromium" },
    },
    {
      name: "enterprise",
      testMatch: /enterprise\.spec\.ts/,
      use: { browserName: "chromium", baseURL: `http://127.0.0.1:${entPort}` },
    },
  ],
});
