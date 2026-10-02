import { expect, test, type Page } from "@playwright/test";

const SAMPLE_MESSAGE = "vpn temp password: Tr0ub4dor&3 (rotate after use)";
const SAMPLE_PASSPHRASE = "correct-horse-battery";

async function createMessage(page: Page): Promise<{ link: string; revokeLink: string }> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Cyphera SecureSend" })).toBeVisible();
  await page.getByLabel("Your email").fill("alice@example.com");
  await page.getByLabel("Recipient email").fill("bob@example.com");
  await page.getByLabel("Message").fill(SAMPLE_MESSAGE);
  await page.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await page.getByRole("button", { name: "Create secure link" }).click();
  await expect(page.getByRole("heading", { name: "Secure link created" })).toBeVisible();
  const link = await page.getByLabel("Secure link").inputValue();
  const revokeLink = await page.getByLabel("Revoke link").inputValue();
  expect(link).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/m\/[a-z0-9]{26}#[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{22}\.[0-9a-z]+$/);
  expect(revokeLink).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/r\/[a-z0-9]{26}#[A-Za-z0-9_-]{43}$/);
  return { link, revokeLink };
}

test("branding from configuration is applied and the access model is stated", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveTitle("Acme Cyphera SecureSend");
  await expect(page.getByText(/controlled by the secure link and the password/)).toBeVisible();
  const primary = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--md-primary").trim());
  expect(primary).toBe("#0057b8");
});

test("secrets never leave the browser and the message is delivered exactly once", async ({ page, browser }) => {
  const requests: { url: string; body: string }[] = [];
  page.on("request", (req) => {
    if (req.method() === "POST") requests.push({ url: req.url(), body: req.postData() ?? "" });
  });

  const { link } = await createMessage(page);
  const fragment = link.split("#")[1]!;
  const linkSecret = fragment.split(".")[0]!;

  for (const r of requests) {
    expect(r.url).not.toContain("#");
    expect(r.body).not.toContain(SAMPLE_MESSAGE);
    expect(r.body).not.toContain(SAMPLE_PASSPHRASE);
    expect(r.body).not.toContain(linkSecret);
  }

  const recipient = await browser.newContext();
  const rpage = await recipient.newPage();
  const rrequests: string[] = [];
  rpage.on("request", (req) => {
    if (req.method() === "POST") rrequests.push(req.postData() ?? "");
  });
  await rpage.goto(link);
  await expect(rpage.getByRole("heading", { name: "You have a secure message" })).toBeVisible();
  await rpage.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await rpage.getByRole("button", { name: "Reveal message" }).click();
  await expect(rpage.getByRole("heading", { name: "Message", exact: true })).toBeVisible();
  await expect(rpage.getByLabel("Message")).toHaveValue(SAMPLE_MESSAGE);
  await expect(rpage.getByText("alice@example.com")).toBeVisible();
  // Nobody vouched for that address, and the reader is told so.
  await expect(rpage.getByText(/as entered by the sender/)).toBeVisible();
  // The link's secret does not outlive the message in the address bar.
  expect(new URL(rpage.url()).hash).toBe("");
  for (const body of rrequests) {
    expect(body).not.toContain(SAMPLE_PASSPHRASE);
    expect(body).not.toContain(linkSecret);
  }

  const again = await recipient.newPage();
  await again.goto(link);
  await again.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await again.getByRole("button", { name: "Reveal message" }).click();
  await expect(again.getByText(/no longer available/)).toBeVisible();
  await recipient.close();
});

test("a wrong password does not consume the message", async ({ page }) => {
  const { link } = await createMessage(page);
  await page.goto(link);
  await page.locator('input[name="password"]').fill("wrong password");
  await page.getByRole("button", { name: "Reveal message" }).click();
  await expect(page.getByText(/password may be wrong/)).toBeVisible();
  await page.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await page.getByRole("button", { name: "Reveal message" }).click();
  await expect(page.getByLabel("Message")).toHaveValue(SAMPLE_MESSAGE);
});

test("too many wrong passwords destroy the message", async ({ page }) => {
  const { link } = await createMessage(page);
  await page.goto(link);
  for (let i = 0; i < 3; i++) {
    await page.locator('input[name="password"]').fill(`wrong ${i}`);
    await page.getByRole("button", { name: "Reveal message" }).click();
    await expect(page.getByText(/password may be wrong/)).toBeVisible();
  }
  await page.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await page.getByRole("button", { name: "Reveal message" }).click();
  await expect(page.getByText(/password may be wrong/)).toBeVisible();
});

test("the sender can revoke before retrieval", async ({ page, browser }) => {
  const { link, revokeLink } = await createMessage(page);
  const other = await browser.newContext();
  const rpage = await other.newPage();
  await rpage.goto(revokeLink);
  await rpage.getByRole("button", { name: "Revoke message" }).click();
  await expect(rpage.getByText(/has been destroyed/)).toBeVisible();
  await rpage.goto(link);
  await rpage.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await rpage.getByRole("button", { name: "Reveal message" }).click();
  await expect(rpage.getByText(/no longer available/)).toBeVisible();
  await other.close();
});

test("two simultaneous reveals deliver exactly once", async ({ page, browser }) => {
  const { link } = await createMessage(page);
  const a = await (await browser.newContext()).newPage();
  const b = await (await browser.newContext()).newPage();
  await a.goto(link);
  await b.goto(link);
  await a.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await b.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await Promise.all([
    a.getByRole("button", { name: "Reveal message" }).click(),
    b.getByRole("button", { name: "Reveal message" }).click(),
  ]);
  const aWon = await a.getByLabel("Message").isVisible({ timeout: 15_000 }).catch(() => false);
  const bWon = await b.getByLabel("Message").isVisible({ timeout: 15_000 }).catch(() => false);
  await Promise.all([a.waitForTimeout(500), b.waitForTimeout(500)]);
  const aFinal = await a.getByLabel("Message").isVisible().catch(() => false);
  const bFinal = await b.getByLabel("Message").isVisible().catch(() => false);
  expect([aWon || aFinal, bWon || bFinal].filter(Boolean)).toHaveLength(1);
});

test("a link without its fragment is refused", async ({ page }) => {
  const { link } = await createMessage(page);
  await page.goto(link.split("#")[0]!);
  await expect(page.getByRole("heading", { name: "Incomplete link" })).toBeVisible();
});

test("responses carry the security headers", async ({ request }) => {
  const res = await request.get("/");
  const csp = res.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("default-src 'none'");
  expect(csp).not.toContain("unsafe");
  expect(res.headers()["cache-control"]).toBe("no-store");
  expect(res.headers()["referrer-policy"]).toBe("no-referrer");
});
