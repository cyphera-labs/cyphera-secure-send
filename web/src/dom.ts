type Child = Node | string | null | undefined | false;

type Attr = string | boolean | ((e: Event) => void);

function applyAttr(el: Element, key: string, value: Attr): void {
  if (typeof value === "function") {
    el.addEventListener(key.startsWith("on") ? key.slice(2).toLowerCase() : key, value);
    return;
  }
  if (typeof value === "boolean") {
    if (value) el.setAttribute(key, "");
    return;
  }
  if (key === "class") {
    el.className = value;
    return;
  }
  el.setAttribute(key, value);
}

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, Attr> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) applyAttr(el, key, value);
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    el.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return el;
}

export function clear(el: Element): void {
  while (el.firstChild) el.firstChild.remove();
}

export function formatDuration(seconds: number): string {
  if (seconds % 86400 === 0) {
    const d = seconds / 86400;
    return d === 1 ? "1 day" : `${d} days`;
  }
  if (seconds % 3600 === 0) {
    const hrs = seconds / 3600;
    return hrs === 1 ? "1 hour" : `${hrs} hours`;
  }
  if (seconds % 60 === 0) {
    const m = seconds / 60;
    return m === 1 ? "1 minute" : `${m} minutes`;
  }
  return `${seconds} seconds`;
}

export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
