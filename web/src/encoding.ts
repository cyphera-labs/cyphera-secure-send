export type Bytes = Uint8Array<ArrayBuffer>;

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function encode(bytes: Bytes, alphabet: string): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + alphabet[(n >> 6) & 63]! + alphabet[n & 63]!;
  }
  if (i + 1 === bytes.length) {
    const n = bytes[i]! << 16;
    out += alphabet[n >> 18]! + alphabet[(n >> 12) & 63]!;
  } else if (i + 2 === bytes.length) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += alphabet[n >> 18]! + alphabet[(n >> 12) & 63]! + alphabet[(n >> 6) & 63]!;
  }
  return out;
}

function stripPadding(text: string): string {
  let end = text.length;
  while (end > 0 && text[end - 1] === "=") end--;
  return text.slice(0, end);
}

function decode(text: string, alphabet: string): Bytes {
  const clean = stripPadding(text);
  const lookup = new Map<string, number>();
  for (let i = 0; i < alphabet.length; i++) lookup.set(alphabet[i]!, i);
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const v = lookup.get(ch);
    if (v === undefined) throw new Error("invalid encoding");
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** Standard base64 without padding: envelope fields. */
export const base64 = {
  encode: (b: Bytes) => encode(b, B64),
  decode: (s: string) => decode(s, B64),
};

/** URL-safe base64 without padding: secrets that travel in a fragment. */
export const base64url = {
  encode: (b: Bytes) => encode(b, B64URL),
  decode: (s: string) => decode(s, B64URL),
};

export const utf8 = {
  encode: (s: string) => new TextEncoder().encode(s),
  decode: (b: Bytes) => new TextDecoder("utf-8", { fatal: true }).decode(b),
};

export function concat(...parts: Bytes[]): Bytes {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
