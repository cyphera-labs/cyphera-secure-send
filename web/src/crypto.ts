/**
 * Browser-side cryptography. Web Crypto only; nothing else touches key
 * material.
 *
 *   pwKey    = PBKDF2-HMAC-SHA256(password, salt, iterations)
 *   ikm      = pwKey || linkSecret
 *   K_enc    = HKDF-SHA256(ikm, salt, "cyphera-securesend/v1/enc")
 *   K_proof  = HKDF-SHA256(ikm, salt, "cyphera-securesend/v1/proof")
 *   verifier = SHA-256(K_proof)              -> stored by the server at create
 *   proof    = K_proof                       -> sent by the recipient at consume
 *   ciphertext = AES-256-GCM(K_enc, iv, plaintext, aad = "cyphera-securesend/v1")
 *
 * The link secret lives in the URL fragment and never reaches the server.
 */

import { base64, base64url, concat, utf8, type Bytes } from "./encoding";

export const ENVELOPE_VERSION = 1;
/** Bounds on the work a link may ask for. A link is not a stored message, so
 *  nothing the server checked applies to one; without these a crafted link
 *  could ask the browser for an unbounded derivation. */
export const MIN_ITERATIONS = 1_000;
export const MAX_ITERATIONS = 10_000_000;
export const KDF_NAME = "PBKDF2-SHA256";
export const CIPHER_NAME = "AES-256-GCM";
const INFO_ENC = "cyphera-securesend/v1/enc";
const INFO_PROOF = "cyphera-securesend/v1/proof";
const AAD = "cyphera-securesend/v1";
const SALT_BYTES = 16;
const IV_BYTES = 12;
const SECRET_BYTES = 32;

export interface Envelope {
  version: number;
  kdf: { name: string; iterations: number; salt: string };
  cipher: { name: string; iv: string };
  ciphertext: string;
}

export interface Sealed {
  envelope: Envelope;
  /** base64url, 32 bytes. Sent to the server at create. */
  verifier: string;
  /** base64url, 32 bytes. Goes into the URL fragment. Never sent. */
  linkSecret: string;
}

export interface DerivedKeys {
  encKey: CryptoKey;
  proof: Bytes;
}

const subtle = globalThis.crypto.subtle;

export function randomBytes(n: number): Bytes {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function generateLinkSecret(): string {
  return base64url.encode(randomBytes(SECRET_BYTES));
}

/** A memorable, high-entropy password: four words from a 2048-word list would be ideal; without a bundled list we use six groups of base32 characters (≈ 60 bits). */
/**
 * Three groups of four from an alphabet without look-alikes. Each character
 * is drawn uniformly: a byte is used only when it falls inside the largest
 * multiple of the alphabet size, so no character is favoured by the
 * remainder of 256.
 */
export function suggestPassword(): string {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const limit = 256 - (256 % alphabet.length);
  const wanted = 12;
  let out = "";
  let drawn = 0;
  while (drawn < wanted) {
    for (const byte of randomBytes(wanted)) {
      if (byte >= limit) continue;
      if (drawn > 0 && drawn % 4 === 0) out += "-";
      out += alphabet[byte % alphabet.length];
      if (++drawn === wanted) break;
    }
  }
  return out;
}

export async function deriveKeys(
  password: string,
  linkSecret: Bytes,
  salt: Bytes,
  iterations: number,
): Promise<DerivedKeys> {
  if (linkSecret.length !== SECRET_BYTES) throw new Error("link secret must be 32 bytes");
  if (salt.length !== SALT_BYTES) throw new Error("salt must be 16 bytes");
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new Error("unsupported key derivation work factor");
  }
  const passwordKey = await subtle.importKey("raw", utf8.encode(password.normalize("NFKC")), "PBKDF2", false, [
    "deriveBits",
  ]);
  const pwKey = new Uint8Array(
    await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, passwordKey, 256),
  );
  const ikm = await subtle.importKey("raw", concat(pwKey, linkSecret), "HKDF", false, ["deriveBits"]);
  const encBits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: utf8.encode(INFO_ENC) }, ikm, 256);
  const proofBits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8.encode(INFO_PROOF) },
    ikm,
    256,
  );
  pwKey.fill(0);
  const encKey = await subtle.importKey("raw", encBits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return { encKey, proof: new Uint8Array(proofBits) };
}

export async function sha256(bytes: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

export async function seal(plaintext: string, password: string, iterations: number): Promise<Sealed> {
  const linkSecretBytes = randomBytes(SECRET_BYTES);
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const keys = await deriveKeys(password, linkSecretBytes, salt, iterations);
  const ciphertext = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8.encode(AAD), tagLength: 128 }, keys.encKey, utf8.encode(plaintext)),
  );
  const verifier = await sha256(keys.proof);
  keys.proof.fill(0);
  return {
    envelope: {
      version: ENVELOPE_VERSION,
      kdf: { name: KDF_NAME, iterations, salt: base64.encode(salt) },
      cipher: { name: CIPHER_NAME, iv: base64.encode(iv) },
      ciphertext: base64.encode(ciphertext),
    },
    verifier: base64url.encode(verifier),
    linkSecret: base64url.encode(linkSecretBytes),
  };
}

/**
 * What a recipient holds between proving and decrypting: the proof to send,
 * and the key kept back for the ciphertext that comes back. One derivation
 * serves both, so the wait is paid once, not twice.
 */
export interface Prepared {
  proof: string;
  encKey: CryptoKey;
}

/** Derives everything the recipient needs from the link and the password. */
export async function prepare(
  password: string,
  linkSecret: string,
  salt: string,
  iterations: number,
): Promise<Prepared> {
  const keys = await deriveKeys(password, base64url.decode(linkSecret), base64.decode(salt), iterations);
  const proof = base64url.encode(keys.proof);
  keys.proof.fill(0);
  return { proof, encKey: keys.encKey };
}

/** Decrypts an envelope with a key already derived by `prepare`. */
export async function openWith(envelope: Envelope, encKey: CryptoKey): Promise<string> {
  assertSupported(envelope);
  const plain = await subtle.decrypt(
    { name: "AES-GCM", iv: base64.decode(envelope.cipher.iv), additionalData: utf8.encode(AAD), tagLength: 128 },
    encKey,
    base64.decode(envelope.ciphertext),
  );
  return utf8.decode(new Uint8Array(plain));
}

/** Derives the consume proof for an envelope without decrypting anything. */
export async function proofFor(envelope: Envelope, password: string, linkSecret: string): Promise<string> {
  assertSupported(envelope);
  return (await prepare(password, linkSecret, envelope.kdf.salt, envelope.kdf.iterations)).proof;
}

export async function open(envelope: Envelope, password: string, linkSecret: string): Promise<string> {
  assertSupported(envelope);
  const { encKey } = await prepare(password, linkSecret, envelope.kdf.salt, envelope.kdf.iterations);
  return openWith(envelope, encKey);
}

function assertSupported(envelope: Envelope): void {
  if (envelope.version !== ENVELOPE_VERSION) throw new Error("unsupported envelope version");
  if (envelope.kdf.name !== KDF_NAME) throw new Error("unsupported key derivation");
  if (envelope.cipher.name !== CIPHER_NAME) throw new Error("unsupported cipher");
}

/**
 * The recipient needs the salt and iterations to compute the proof before
 * the server will hand over the envelope. They are not secret, so the sender's
 * page encodes them into the fragment alongside the link secret.
 */
export interface LinkParams {
  linkSecret: string;
  salt: string;
  iterations: number;
}

export function encodeFragment(p: LinkParams): string {
  return `${p.linkSecret}.${base64url.encode(base64.decode(p.salt))}.${p.iterations.toString(36)}`;
}

export function decodeFragment(fragment: string): LinkParams | null {
  const raw = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  const parts = raw.split(".");
  if (parts.length !== 3) return null;
  const [linkSecret, salt, iter] = parts as [string, string, string];
  if (!/^[A-Za-z0-9_-]{43}$/.test(linkSecret)) return null;
  if (!/^[A-Za-z0-9_-]{22}$/.test(salt)) return null;
  if (!/^[0-9a-z]{1,8}$/.test(iter)) return null;
  const iterations = Number.parseInt(iter, 36);
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    return null;
  }
  return { linkSecret, salt: base64.encode(base64url.decode(salt)), iterations };
}
