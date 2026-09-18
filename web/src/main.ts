import "./styles.css";
import { ApiError, api, loadSession, loadUiConfig, logout, type SessionView, type UiConfig } from "./api";
import { decodeFragment, encodeFragment, open, proofFor, seal, suggestPassword } from "./crypto";
import { byteLength, clear, copyToClipboard, formatDuration, formatTime, h } from "./dom";

const root = document.getElementById("app") as HTMLElement;
let config: UiConfig;
let session: SessionView = { authenticated: false };
const FRAGMENT_KEY = "securesend.fragment";

/// Creating and reading are separate questions: a deployment can require a
/// signed-in sender while letting a customer outside the directory read with
/// the link and the password.
function needsSignInToCreate(): boolean {
  return config.creation_requires_sign_in && !session.authenticated;
}

function needsSignInToRead(): boolean {
  return config.consumption_requires_sign_in && !session.authenticated;
}

/** Sends the browser to the provider. The fragment never reaches the server,
 *  so it is parked in sessionStorage for the trip and restored on return. */
function signIn(next: string): void {
  try {
    if (location.hash.length > 1) sessionStorage.setItem(FRAGMENT_KEY, `${location.pathname}${location.hash}`);
  } catch {
    // storage unavailable: the user re-opens the full link after signing in
  }
  location.assign(`/auth/login?next=${encodeURIComponent(next)}`);
}

function restoreFragment(): void {
  if (location.hash.length > 1) return;
  try {
    const saved = sessionStorage.getItem(FRAGMENT_KEY);
    if (!saved) return;
    sessionStorage.removeItem(FRAGMENT_KEY);
    const hashAt = saved.indexOf("#");
    if (hashAt > 0 && saved.slice(0, hashAt) === location.pathname) {
      history.replaceState(null, "", saved);
    }
  } catch {
    // nothing to restore
  }
}

function applyBranding(c: UiConfig): void {
  const s = document.documentElement.style;
  s.setProperty("--md-primary", c.colors.primary);
  s.setProperty("--md-on-primary", c.colors.on_primary);
  s.setProperty("--md-secondary", c.colors.secondary);
  s.setProperty("--md-surface", c.colors.surface);
  s.setProperty("--md-on-surface", c.colors.on_surface);
  s.setProperty("--md-surface-variant", c.colors.surface_variant);
  s.setProperty("--md-error", c.colors.error);
  document.title = c.company_name ? `${c.company_name} ${c.product_name}` : c.product_name;
  if (!c.has_favicon) document.querySelector('link[rel="icon"]')?.remove();
}

function header(): HTMLElement {
  const brand = h("a", { class: "brand", href: "/" });
  if (config.has_logo) brand.append(h("img", { class: "brand-logo", src: "/brand/logo", alt: "" }));
  const name = h("span", { class: "brand-name" });
  if (config.company_name) name.append(h("span", { class: "brand-company" }, config.company_name), " ");
  name.append(config.product_name);
  brand.append(name);
  const header = h("header", { class: "top" }, brand);
  if (config.mode === "enterprise" && session.authenticated) {
    header.append(
      h("div", { class: "who" },
        h("span", { class: "who-email" }, session.email ?? ""),
        h("button", { type: "button", class: "text-button", onclick: async () => { await logout(); location.assign("/"); } }, "Sign out"),
      ),
    );
  }
  return header;
}

function signInCard(title: string, text: string, next: string): void {
  page(
    h("section", { class: "card" },
      h("h1", {}, title),
      h("p", {}, text),
      h("div", { class: "actions" }, h("button", { type: "button", class: "filled-button", onclick: () => signIn(next) }, "Sign in")),
    ),
  );
}

function footer(): HTMLElement {
  const parts: (HTMLElement | string)[] = [];
  if (config.footer_text) parts.push(h("span", {}, config.footer_text));
  if (config.support_url) parts.push(h("a", { href: config.support_url, rel: "noreferrer noopener" }, "Help"));
  if (config.show_powered_by) parts.push(h("span", { class: "muted" }, "Powered by Cyphera SecureSend"));
  const f = h("footer", { class: "bottom" });
  parts.forEach((p, i) => {
    if (i > 0) f.append(h("span", { class: "dot" }, "·"));
    f.append(p);
  });
  return f;
}

function modeNotice(): HTMLElement | null {
  if (config.mode !== "standard") return null;
  return h(
    "div",
    { class: "mode-banner", role: "note" },
    "Access is controlled by the secure link and the password. Email addresses are recorded but not verified.",
  );
}

function page(...content: HTMLElement[]): void {
  clear(root);
  root.append(header());
  const banner = modeNotice();
  if (banner) root.append(banner);
  root.append(h("main", { class: "page" }, ...content), footer());
  root.hidden = false;
}

function field(label: string, input: HTMLElement, hint?: string): HTMLElement {
  const wrap = h("label", { class: "field" }, h("span", { class: "field-label" }, label), input);
  if (hint) wrap.append(h("span", { class: "field-hint" }, hint));
  return wrap;
}

function notice(kind: "info" | "warn" | "error", text: string): HTMLElement {
  return h("p", { class: `notice notice-${kind}`, role: kind === "error" ? "alert" : "status" }, text);
}

function busy(button: HTMLButtonElement, on: boolean, label?: string): void {
  button.disabled = on;
  if (label) button.textContent = label;
}

function describeError(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    if (e.status === 429) return "Too many requests from your network. Wait a minute and try again.";
    if (e.status === 413) return "The message is too large.";
    if (e.status === 503) return "The service is at capacity. Try again shortly.";
    return e.message;
  }
  return fallback;
}

// ---------------------------------------------------------------- compose

function compose(): void {
  if (needsSignInToCreate()) {
    signInCard(config.product_name, "Sign in to send a secure message.", "/");
    return;
  }
  const sender = h("input", { type: "email", name: "sender", autocomplete: "email", required: true, maxlength: "254", spellcheck: "false" });
  if (session.authenticated && session.email) {
    sender.value = session.email;
    sender.readOnly = true;
    sender.classList.add("readonly");
  }
  const recipient = h("input", { type: "email", name: "recipient", autocomplete: "off", required: true, maxlength: "254", spellcheck: "false" });
  const message = h("textarea", { name: "message", rows: "8", required: true, spellcheck: "false", autocomplete: "off" });
  const password = h("input", { type: "password", name: "password", autocomplete: "new-password", required: true, minlength: "8", spellcheck: "false" });
  const showPw = h("button", { type: "button", class: "text-button", onclick: () => {
    password.type = password.type === "password" ? "text" : "password";
    showPw.textContent = password.type === "password" ? "Show" : "Hide";
  } }, "Show");
  const suggest = h("button", { type: "button", class: "text-button", onclick: () => {
    password.value = suggestPassword();
    password.type = "text";
    showPw.textContent = "Hide";
  } }, "Suggest");
  const ttl = h("select", { name: "ttl" });
  for (const secs of config.ttl_options_seconds) {
    const opt = h("option", { value: String(secs) }, formatDuration(secs));
    if (secs === config.default_ttl_seconds) opt.selected = true;
    ttl.append(opt);
  }
  const counter = h("span", { class: "field-hint" }, `0 / ${config.max_plaintext_bytes.toLocaleString()} bytes`);
  message.addEventListener("input", () => {
    const n = byteLength(message.value);
    counter.textContent = `${n.toLocaleString()} / ${config.max_plaintext_bytes.toLocaleString()} bytes`;
    counter.classList.toggle("over", n > config.max_plaintext_bytes);
  });
  const status = h("div", { class: "status" });
  const submit = h("button", { type: "submit", class: "filled-button" }, "Create secure link");

  const form = h(
    "form",
    { class: "card", novalidate: true, onsubmit: (e: Event) => { e.preventDefault(); void submitCompose(); } },
    h("h1", {}, config.product_name),
    h("p", { class: "lede" }, config.tagline),
    field("Your email", sender),
    field("Recipient email", recipient),
    field("Message", message),
    counter,
    h("div", { class: "field" },
      h("span", { class: "field-label" }, "Password"),
      h("div", { class: "row" }, password, suggest, showPw),
      h("span", { class: "field-hint" }, "Share it with the recipient through a different channel than the link."),
    ),
    field("Expires after", ttl),
    status,
    h("div", { class: "actions" }, submit),
  );

  async function submitCompose(): Promise<void> {
    clear(status);
    const bytes = byteLength(message.value);
    if (!sender.checkValidity() || !recipient.checkValidity()) {
      status.append(notice("error", "Enter a valid sender and recipient email address."));
      return;
    }
    if (message.value.length === 0) {
      status.append(notice("error", "Enter a message."));
      return;
    }
    if (bytes > config.max_plaintext_bytes) {
      status.append(notice("error", `The message is limited to ${config.max_plaintext_bytes.toLocaleString()} bytes.`));
      return;
    }
    if (password.value.length < 8) {
      status.append(notice("error", "Use a password of at least 8 characters, or pick Suggest."));
      return;
    }
    busy(submit, true, "Encrypting…");
    try {
      const sealed = await seal(message.value, password.value, config.kdf_iterations);
      busy(submit, true, "Creating link…");
      const created = await api.create({
        sender: sender.value.trim(),
        recipient: recipient.value.trim(),
        ttl_seconds: Number(ttl.value),
        verifier: sealed.verifier,
        envelope: sealed.envelope,
      });
      const fragment = encodeFragment({ linkSecret: sealed.linkSecret, salt: sealed.envelope.kdf.salt, iterations: config.kdf_iterations });
      const link = `${location.origin}/m/${created.id}#${fragment}`;
      const revokeLink = `${location.origin}/r/${created.id}#${created.revoke_token}`;
      message.value = "";
      password.value = "";
      createdView({ link, revokeLink, recipient: recipient.value.trim(), expiresAt: created.expires_at, id: created.id, revokeToken: created.revoke_token });
    } catch (e) {
      status.append(notice("error", describeError(e, "Could not create the message. Try again.")));
      busy(submit, false, "Create secure link");
    }
  }

  page(form);
  if (sender.readOnly) recipient.focus();
  else sender.focus();
}

interface CreatedInfo {
  link: string;
  revokeLink: string;
  recipient: string;
  expiresAt: string;
  id: string;
  revokeToken: string;
}

function copyRow(label: string, value: string, ariaLabel: string): HTMLElement {
  const box = h("input", { type: "text", readonly: true, value, "aria-label": ariaLabel, spellcheck: "false" });
  box.value = value;
  box.addEventListener("focus", () => box.select());
  const button = h("button", { type: "button", class: "tonal-button", onclick: async () => {
    const ok = await copyToClipboard(value);
    button.textContent = ok ? "Copied" : "Select and copy";
    if (!ok) box.select();
    setTimeout(() => (button.textContent = "Copy"), 2000);
  } }, "Copy");
  return h("div", { class: "field" }, h("span", { class: "field-label" }, label), h("div", { class: "row" }, box, button));
}

function createdView(info: CreatedInfo): void {
  const status = h("div", { class: "status" });
  const revokeBtn = h("button", { type: "button", class: "outlined-button", onclick: async () => {
    busy(revokeBtn, true, "Revoking…");
    try {
      await api.revoke(info.id, info.revokeToken);
      clear(status);
      status.append(notice("info", "The message has been revoked. The link no longer works."));
      revokeBtn.remove();
    } catch (e) {
      clear(status);
      status.append(notice("error", describeError(e, "Could not revoke. Try again.")));
      busy(revokeBtn, false, "Revoke message");
    }
  } }, "Revoke message");

  page(
    h("section", { class: "card" },
      h("h1", {}, "Secure link created"),
      h("dl", { class: "facts" },
        h("dt", {}, "Recipient"), h("dd", {}, info.recipient),
        h("dt", {}, "Expires"), h("dd", {}, formatTime(info.expiresAt)),
      ),
      copyRow("Share this link with the recipient", info.link, "Secure link"),
      notice("warn", "Share the password through a different channel. Never send the link and the password together."),
      copyRow("Keep this link if you want to revoke later", info.revokeLink, "Revoke link"),
      notice("info", "This page cannot be reopened. Copy what you need before leaving it."),
      status,
      h("div", { class: "actions" }, revokeBtn, h("a", { class: "text-button", href: "/" }, "Send another")),
    ),
  );
}

// ----------------------------------------------------------------- reveal

function unavailable(): void {
  page(
    h("section", { class: "card" },
      h("h1", {}, "Message unavailable"),
      h("p", {}, "This message may have been viewed already, revoked by the sender, or expired. It is not stored anywhere and cannot be recovered."),
      h("p", {}, "If you expected a message, ask the sender to create a new one."),
      h("div", { class: "actions" }, h("a", { class: "text-button", href: "/" }, "Send a message")),
    ),
  );
}

function reveal(id: string): void {
  if (needsSignInToRead()) {
    const why = config.recipient_must_match
      ? "Sign in to read it. It can be viewed only once, by the person it was sent to."
      : "Sign in to read it. It can be viewed only once.";
    signInCard("You have a secure message", why, `/m/${id}`);
    return;
  }
  const params = decodeFragment(location.hash);
  if (!params) {
    page(
      h("section", { class: "card" },
        h("h1", {}, "Incomplete link"),
        h("p", {}, "This link is missing the part after the # sign. Copy the whole link exactly as the sender shared it."),
      ),
    );
    return;
  }
  const password = h("input", { type: "password", name: "password", autocomplete: "off", required: true, spellcheck: "false" });
  const status = h("div", { class: "status" });
  const submit = h("button", { type: "submit", class: "filled-button" }, "Reveal message");
  const form = h(
    "form",
    { class: "card", novalidate: true, onsubmit: (e: Event) => { e.preventDefault(); void submitReveal(); } },
    h("h1", {}, "You have a secure message"),
    notice("warn", "This message can be viewed only once. Make sure you are ready to read it now."),
    field("Password", password, "The sender gave you this separately from the link."),
    status,
    h("div", { class: "actions" }, submit),
  );

  async function submitReveal(): Promise<void> {
    clear(status);
    if (!password.value) {
      status.append(notice("error", "Enter the password."));
      return;
    }
    busy(submit, true, "Checking…");
    try {
      const envelopeForProof = {
        version: 1,
        kdf: { name: "PBKDF2-SHA256", iterations: params!.iterations, salt: params!.salt },
        cipher: { name: "AES-256-GCM", iv: "" },
        ciphertext: "",
      };
      const proof = await proofFor(envelopeForProof, password.value, params!.linkSecret);
      const consumed = await api.consume(id, proof);
      busy(submit, true, "Decrypting…");
      const plain = await open(consumed.envelope, password.value, params!.linkSecret);
      password.value = "";
      revealedView(plain, consumed.sender);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        status.append(notice("error", "The password may be wrong, or the message is no longer available. Check the password and try again."));
      } else {
        status.append(notice("error", describeError(e, "Could not decrypt the message.")));
      }
      busy(submit, false, "Reveal message");
    }
  }

  page(form);
  password.focus();
}

function revealedView(plain: string, sender: string): void {
  const text = h("textarea", { class: "plain", readonly: true, rows: "10", spellcheck: "false", "aria-label": "Message" });
  text.value = plain;
  const copy = h("button", { type: "button", class: "tonal-button", onclick: async () => {
    const ok = await copyToClipboard(plain);
    copy.textContent = ok ? "Copied" : "Select and copy";
    if (!ok) text.select();
    setTimeout(() => (copy.textContent = "Copy message"), 2000);
  } }, "Copy message");
  page(
    h("section", { class: "card" },
      h("h1", {}, "Message"),
      h("dl", { class: "facts" }, h("dt", {}, "From"), h("dd", {}, sender)),
      text,
      notice("warn", "This message has been destroyed on the server. Do not refresh or leave this page until you have what you need."),
      h("div", { class: "actions" }, copy),
    ),
  );
  window.addEventListener("pagehide", () => {
    text.value = "";
    plain = "";
  });
}

// ----------------------------------------------------------------- revoke

function revokePage(id: string): void {
  const token = location.hash.startsWith("#") ? location.hash.slice(1) : "";
  const status = h("div", { class: "status" });
  const button = h("button", { type: "button", class: "filled-button", onclick: async () => {
    busy(button, true, "Revoking…");
    try {
      await api.revoke(id, token);
      clear(status);
      status.append(notice("info", "Done. If the message was still waiting, it has been destroyed."));
      button.remove();
    } catch (e) {
      clear(status);
      status.append(notice("error", describeError(e, "Could not revoke. Try again.")));
      busy(button, false, "Revoke message");
    }
  } }, "Revoke message");
  page(
    h("section", { class: "card" },
      h("h1", {}, "Revoke a message"),
      h("p", {}, "Revoking destroys the message if it has not been viewed yet. This cannot be undone."),
      status,
      h("div", { class: "actions" }, button),
    ),
  );
}

// ------------------------------------------------------------------ route

function route(): void {
  const path = location.pathname;
  const m = /^\/m\/([a-z0-9]{26})\/?$/.exec(path);
  const r = /^\/r\/([a-z0-9]{26})\/?$/.exec(path);
  if (m) reveal(m[1]!);
  else if (r) revokePage(r[1]!);
  else if (path === "/" || path === "") compose();
  else unavailable();
}

async function boot(): Promise<void> {
  try {
    config = await loadUiConfig();
  } catch {
    root.append(h("main", { class: "page" }, h("section", { class: "card" }, h("h1", {}, "SecureSend"), h("p", {}, "The service is not reachable right now."))));
    root.hidden = false;
    return;
  }
  applyBranding(config);
  if (config.mode === "enterprise") {
    session = await loadSession();
    restoreFragment();
  }
  route();
}

await boot();
