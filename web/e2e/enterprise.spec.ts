import { expect, test, type Page } from "@playwright/test";

// This instance requires a signed-in sender and lets the recipient read with
// the link and the password, which is the handoff to someone outside the
// directory. The identity provider is the local test one.
const IDP = "http://127.0.0.1:18091";
const SAMPLE_MESSAGE = "firewall admin password: Tr0ub4dor&3";
const SAMPLE_PASSPHRASE = "correct-horse-battery";

async function signInAs(page: Page, email: string): Promise<void> {
  await page.request.get(`${IDP}/switch?email=${encodeURIComponent(email)}`);
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL("**/");
  await expect(page.getByText(email)).toBeVisible();
}

test("creating requires signing in, and the sender is the signed-in identity", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  await expect(page.locator('textarea[name="message"]')).toHaveCount(0);

  await signInAs(page, "alice@acme.com");
  const sender = page.getByLabel("Your email");
  await expect(sender).toHaveValue("alice@acme.com");
  await expect(sender).toHaveAttribute("readonly", "");
});

test("an outside customer reads with the link and the password, without signing in", async ({ page, browser }) => {
  await signInAs(page, "alice@acme.com");
  await page.getByLabel("Recipient email").fill("customer@outside.example");
  await page.getByLabel("Message").fill(SAMPLE_MESSAGE);
  await page.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await page.getByRole("button", { name: "Create secure link" }).click();
  await expect(page.getByRole("heading", { name: "Secure link created" })).toBeVisible();
  const link = await page.getByLabel("Secure link").inputValue();

  // A browser that has never met the identity provider.
  const customer = await browser.newContext();
  const cpage = await customer.newPage();
  const idpRequests: string[] = [];
  cpage.on("request", (r) => {
    if (r.url().startsWith(IDP)) idpRequests.push(r.url());
  });

  await cpage.goto(link);
  // The password form, not a sign-in card, and no detour to the provider.
  await expect(cpage.locator('input[name="password"]')).toBeVisible();
  await expect(cpage.getByRole("button", { name: "Sign in" })).toHaveCount(0);
  expect(idpRequests).toEqual([]);

  await cpage.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await cpage.getByRole("button", { name: "Reveal message" }).click();
  await expect(cpage.getByLabel("Message")).toHaveValue(SAMPLE_MESSAGE);

  // Once only.
  const again = await customer.newPage();
  await again.goto(link);
  await again.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await again.getByRole("button", { name: "Reveal message" }).click();
  await expect(again.getByText(/no longer available/)).toBeVisible();

  // And that same browser cannot create anything.
  await cpage.goto("/");
  await expect(cpage.getByRole("button", { name: "Sign in" })).toBeVisible();
  await expect(cpage.locator('textarea[name="message"]')).toHaveCount(0);
  await customer.close();
});

test("a sender outside the allowed domains is refused", async ({ page }) => {
  await signInAs(page, "eve@outside.example");
  await page.getByLabel("Recipient email").fill("customer@outside.example");
  await page.getByLabel("Message").fill(SAMPLE_MESSAGE);
  await page.locator('input[name="password"]').fill(SAMPLE_PASSPHRASE);
  await page.getByRole("button", { name: "Create secure link" }).click();
  await expect(page.getByText(/not permitted/)).toBeVisible();
});
