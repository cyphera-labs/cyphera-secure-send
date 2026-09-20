import "./styles.css";
import { ApiError, api, loadSession, loadUiConfig, logout, type SessionView, type UiConfig } from "./api";
import { decodeFragment, encodeFragment, openWith, prepare, seal, suggestPassword } from "./crypto";
import { byteLength, clear, copyToClipboard, formatDuration, formatTime, h } from "./dom";
import { S } from "./strings";

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
        h("button", { type: "button", class: "text-button", onclick: async () => { await logout(); location.assign("/"); } }, S.common.signOut),
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
      h("div", { class: "actions" }, h("button", { type: "button", class: "filled-button", onclick: () => signIn(next) }, S.common.signIn)),
    ),
  );
}

function footer(): HTMLElement {
  const parts: (HTMLElement | string)[] = [];
  if (config.footer_text) parts.push(h("span", {}, config.footer_text));
  if (config.support_url) parts.push(h("a", { href: config.support_url, rel: "noreferrer noopener" }, S.common.help));
  if (config.show_powered_by) parts.push(h("span", { class: "muted" }, S.common.poweredBy));
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
    S.standardNotice,
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
    if (e.status === 429) return S.errors.tooManyRequests;
    if (e.status === 413) return S.errors.tooLarge;
    if (e.status === 503) return S.errors.atCapacity;
    return e.message;
  }
  return fallback;
}

// ---------------------------------------------------------------- compose

function compose(): void {
  if (needsSignInToCreate()) {
    signInCard(config.product_name, S.compose.signInToSend, "/");
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
    showPw.textContent = password.type === "password" ? S.compose.show : S.compose.hide;
  } }, S.compose.show);
  const suggest = h("button", { type: "button", class: "text-button", onclick: () => {
    password.value = suggestPassword();
    password.type = "text";
    showPw.textContent = S.compose.hide;
  } }, S.compose.suggest);
  const ttl = h("select", { name: "ttl" });
  for (const secs of config.ttl_options_seconds) {
    const opt = h("option", { value: String(secs) }, formatDuration(secs));
    if (secs === config.default_ttl_seconds) opt.selected = true;
    ttl.append(opt);
  }
  const counter = h("span", { class: "field-hint" }, S.compose.byteCount(0, config.max_plaintext_bytes));
  message.addEventListener("input", () => {
    const n = byteLength(message.value);
    counter.textContent = S.compose.byteCount(n, config.max_plaintext_bytes);
    counter.classList.toggle("over", n > config.max_plaintext_bytes);
  });
  const status = h("div", { class: "status" });
  const submit = h("button", { type: "submit", class: "filled-button" }, S.compose.create);

  const form = h(
    "form",
    { class: "card", novalidate: true, onsubmit: (e: Event) => { e.preventDefault(); void submitCompose(); } },
    h("h1", {}, config.product_name),
    h("p", { class: "lede" }, config.tagline),
    field(S.compose.yourEmail, sender),
    field(S.compose.recipientEmail, recipient),
    field(S.compose.message, message),
    counter,
    h("div", { class: "field" },
      h("span", { class: "field-label" }, S.compose.password),
      h("div", { class: "row" }, password, suggest, showPw),
      h("span", { class: "field-hint" }, S.compose.passwordHint),
    ),
    field(S.compose.expiresAfter, ttl),
    status,
    h("div", { class: "actions" }, submit),
  );

  async function submitCompose(): Promise<void> {
    clear(status);
    const bytes = byteLength(message.value);
    if (!sender.checkValidity() || !recipient.checkValidity()) {
      status.append(notice("error", S.compose.invalidAddresses));
      return;
    }
    if (message.value.length === 0) {
      status.append(notice("error", S.compose.enterMessage));
      return;
    }
    if (bytes > config.max_plaintext_bytes) {
      status.append(notice("error", S.compose.overLimit(config.max_plaintext_bytes)));
      return;
    }
    if (password.value.length < 8) {
      status.append(notice("error", S.compose.passwordTooShort));
      return;
    }
    busy(submit, true, S.compose.encrypting);
    try {
      const sealed = await seal(message.value, password.value, config.kdf);
      busy(submit, true, S.compose.creatingLink);
      const created = await api.create({
        sender: sender.value.trim(),
        recipient: recipient.value.trim(),
        ttl_seconds: Number(ttl.value),
        verifier: sealed.verifier,
        envelope: sealed.envelope,
      });
      const fragment = encodeFragment({ linkSecret: sealed.linkSecret, salt: sealed.envelope.kdf.salt, iterations: sealed.envelope.kdf.iterations });
      const link = `${location.origin}/m/${created.id}#${fragment}`;
      const revokeLink = `${location.origin}/r/${created.id}#${created.revoke_token}`;
      message.value = "";
      password.value = "";
      createdView({ link, revokeLink, recipient: recipient.value.trim(), expiresAt: created.expires_at, id: created.id, revokeToken: created.revoke_token });
    } catch (e) {
      status.append(notice("error", describeError(e, S.compose.couldNotCreate)));
      busy(submit, false, S.compose.create);
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
    button.textContent = ok ? S.common.copied : S.common.selectAndCopy;
    if (!ok) box.select();
    setTimeout(() => (button.textContent = S.common.copy), 2000);
  } }, S.common.copy);
  return h("div", { class: "field" }, h("span", { class: "field-label" }, label), h("div", { class: "row" }, box, button));
}

function createdView(info: CreatedInfo): void {
  const status = h("div", { class: "status" });
  const revokeBtn = h("button", { type: "button", class: "outlined-button", onclick: async () => {
    busy(revokeBtn, true, S.created.revoking);
    try {
      await api.revoke(info.id, info.revokeToken);
      clear(status);
      status.append(notice("info", S.created.revoked));
      revokeBtn.remove();
    } catch (e) {
      clear(status);
      status.append(notice("error", describeError(e, S.created.couldNotRevoke)));
      busy(revokeBtn, false, S.created.revoke);
    }
  } }, S.created.revoke);

  page(
    h("section", { class: "card" },
      h("h1", {}, S.created.title),
      h("dl", { class: "facts" },
        h("dt", {}, S.created.recipient), h("dd", {}, info.recipient),
        h("dt", {}, S.created.expires), h("dd", {}, formatTime(info.expiresAt)),
      ),
      copyRow(S.created.shareLink, info.link, S.created.shareLinkAria),
      notice("warn", S.created.passwordWarning),
      copyRow(S.created.keepRevokeLink, info.revokeLink, S.created.revokeLinkAria),
      notice("info", S.created.cannotReopen),
      status,
      h("div", { class: "actions" }, revokeBtn, h("a", { class: "text-button", href: "/" }, S.common.sendAnother)),
    ),
  );
}

// ----------------------------------------------------------------- reveal

function unavailable(): void {
  page(
    h("section", { class: "card" },
      h("h1", {}, S.unavailable.title),
      h("p", {}, S.unavailable.body),
      h("p", {}, S.unavailable.askSender),
      h("div", { class: "actions" }, h("a", { class: "text-button", href: "/" }, S.common.sendAMessage)),
    ),
  );
}

function reveal(id: string): void {
  if (needsSignInToRead()) {
    const why = config.recipient_must_match ? S.reveal.signInToReadAsRecipient : S.reveal.signInToRead;
    signInCard(S.reveal.title, why, `/m/${id}`);
    return;
  }
  const params = decodeFragment(location.hash);
  if (!params) {
    page(
      h("section", { class: "card" },
        h("h1", {}, S.reveal.incompleteTitle),
        h("p", {}, S.reveal.incompleteBody),
      ),
    );
    return;
  }
  const password = h("input", { type: "password", name: "password", autocomplete: "off", required: true, spellcheck: "false" });
  const status = h("div", { class: "status" });
  const submit = h("button", { type: "submit", class: "filled-button" }, S.reveal.reveal);
  const form = h(
    "form",
    { class: "card", novalidate: true, onsubmit: (e: Event) => { e.preventDefault(); void submitReveal(); } },
    h("h1", {}, S.reveal.title),
    notice("warn", S.reveal.onlyOnce),
    field(S.reveal.password, password, S.reveal.passwordHint),
    status,
    h("div", { class: "actions" }, submit),
  );

  async function submitReveal(): Promise<void> {
    clear(status);
    if (!password.value) {
      status.append(notice("error", S.reveal.passwordMissing));
      return;
    }
    // Held for the whole operation: the field is read once for the proof and
    // again after the message has been consumed, and a message consumed with
    // an edited field in between could never be decrypted.
    const secret = password.value;
    password.disabled = true;
    busy(submit, true, S.reveal.checking);
    try {
      // One derivation: the proof goes to the server, the key stays here
      // for the ciphertext that comes back.
      const keys = await prepare(secret, params!.linkSecret, params!.salt, params!.iterations);
      const consumed = await api.consume(id, keys.proof);
      busy(submit, true, S.reveal.decrypting);
      const plain = await openWith(consumed.envelope, keys.encKey);
      password.value = "";
      // The message is gone from the server; the link's secret has no
      // further use and should not outlive it in the address bar, the
      // tab's history, or whatever syncs that history elsewhere.
      history.replaceState(null, "", location.pathname);
      revealedView(plain, consumed.sender, consumed.sender_authenticated);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        status.append(notice("error", S.reveal.wrongOrGone));
      } else {
        status.append(notice("error", describeError(e, S.reveal.couldNotDecrypt)));
      }
      password.disabled = false;
      busy(submit, false, S.reveal.reveal);
    }
  }

  page(form);
  password.focus();
}

function revealedView(plain: string, sender: string, senderAuthenticated: boolean): void {
  const text = h("textarea", { class: "plain", readonly: true, rows: "10", spellcheck: "false", "aria-label": S.revealed.messageAria });
  text.value = plain;
  const copy = h("button", { type: "button", class: "tonal-button", onclick: async () => {
    const ok = await copyToClipboard(plain);
    copy.textContent = ok ? S.common.copied : S.common.selectAndCopy;
    if (!ok) text.select();
    setTimeout(() => (copy.textContent = S.revealed.copyMessage), 2000);
  } }, S.revealed.copyMessage);
  page(
    h("section", { class: "card" },
      h("h1", {}, S.revealed.title),
      h("dl", { class: "facts" },
        h("dt", {}, S.revealed.from),
        // An address the sender typed is a claim, and it says so; an
        // address the identity provider vouched for does not need to.
        h("dd", {}, sender, senderAuthenticated ? "" : h("span", { class: "muted" }, S.revealed.notVerified)),
      ),
      text,
      notice("warn", S.revealed.destroyed),
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
    busy(button, true, S.revoke.revoking);
    try {
      await api.revoke(id, token);
      clear(status);
      status.append(notice("info", S.revoke.done));
      button.remove();
    } catch (e) {
      clear(status);
      status.append(notice("error", describeError(e, S.revoke.couldNotRevoke)));
      busy(button, false, S.revoke.revoke);
    }
  } }, S.revoke.revoke);
  page(
    h("section", { class: "card" },
      h("h1", {}, S.revoke.title),
      h("p", {}, S.revoke.body),
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
    root.append(h("main", { class: "page" }, h("section", { class: "card" }, h("h1", {}, S.errors.unreachableTitle), h("p", {}, S.errors.unreachable))));
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
