import { describe, expect, it } from "vitest";
import { base64, base64url } from "./encoding";
import { decodeFragment, encodeFragment, open, proofFor, seal, sha256, suggestPassword } from "./crypto";

const ITER = 1000;

describe("encoding", () => {
  it("round-trips arbitrary bytes in both alphabets", () => {
    for (const len of [0, 1, 2, 3, 4, 31, 32, 33, 100]) {
      const bytes = new Uint8Array(len).map((_, i) => (i * 37 + len) & 0xff);
      expect(Array.from(base64.decode(base64.encode(bytes)))).toEqual(Array.from(bytes));
      expect(Array.from(base64url.decode(base64url.encode(bytes)))).toEqual(Array.from(bytes));
    }
    expect(base64.encode(new Uint8Array([0xfb, 0xff]))).toBe("+/8");
    expect(base64url.encode(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
  });

  it("rejects characters outside the alphabet", () => {
    expect(() => base64url.decode("abc+")).toThrow();
  });
});

describe("seal and open", () => {
  it("round-trips with the right password and link secret", async () => {
    const sealed = await seal("hunter2 is not a password", "correct horse", ITER);
    expect(sealed.envelope.version).toBe(1);
    expect(sealed.envelope.kdf.name).toBe("PBKDF2-SHA256");
    expect(sealed.envelope.cipher.name).toBe("AES-256-GCM");
    expect(base64url.decode(sealed.verifier)).toHaveLength(32);
    expect(base64url.decode(sealed.linkSecret)).toHaveLength(32);
    const plain = await open(sealed.envelope, "correct horse", sealed.linkSecret);
    expect(plain).toBe("hunter2 is not a password");
  });

  it("fails with the wrong password, wrong link secret, or tampered ciphertext", async () => {
    const sealed = await seal("secret", "pw", ITER);
    await expect(open(sealed.envelope, "pW", sealed.linkSecret)).rejects.toBeDefined();
    const other = base64url.encode(new Uint8Array(32).fill(7));
    await expect(open(sealed.envelope, "pw", other)).rejects.toBeDefined();
    const bytes = base64.decode(sealed.envelope.ciphertext);
    bytes[0] = bytes[0]! ^ 0x01;
    await expect(open({ ...sealed.envelope, ciphertext: base64.encode(bytes) }, "pw", sealed.linkSecret)).rejects.toBeDefined();
  });

  it("derives a proof whose hash equals the verifier", async () => {
    const sealed = await seal("secret", "pw", ITER);
    const proof = await proofFor(sealed.envelope, "pw", sealed.linkSecret);
    const digest = await sha256(base64url.decode(proof));
    expect(base64url.encode(digest)).toBe(sealed.verifier);
    const wrong = await proofFor(sealed.envelope, "pw2", sealed.linkSecret);
    expect(wrong).not.toBe(proof);
  });

  it("does not put the link secret anywhere in the envelope", async () => {
    const sealed = await seal("secret", "pw", ITER);
    const json = JSON.stringify(sealed.envelope) + sealed.verifier;
    expect(json).not.toContain(sealed.linkSecret);
    expect(json).not.toContain("secret");
    expect(json).not.toContain("pw");
  });

  it("refuses unsupported envelope versions", async () => {
    const sealed = await seal("secret", "pw", ITER);
    await expect(open({ ...sealed.envelope, version: 2 }, "pw", sealed.linkSecret)).rejects.toThrow(/version/);
  });
});

describe("fragment", () => {
  it("round-trips link params", async () => {
    const sealed = await seal("secret", "pw", 600000);
    const fragment = encodeFragment({ linkSecret: sealed.linkSecret, salt: sealed.envelope.kdf.salt, iterations: 600000 });
    expect(fragment).not.toContain("+");
    expect(fragment).not.toContain("/");
    expect(fragment).not.toContain("=");
    const decoded = decodeFragment(`#${fragment}`);
    expect(decoded).toEqual({ linkSecret: sealed.linkSecret, salt: sealed.envelope.kdf.salt, iterations: 600000 });
  });

  it("refuses a work factor outside what the interface supports", () => {
    const secret = "a".repeat(43);
    const salt = "b".repeat(22);
    // 36^7 is far beyond any sane derivation cost.
    expect(decodeFragment(`#${secret}.${salt}.zzzzzzz`)).toBeNull();
    expect(decodeFragment(`#${secret}.${salt}.1`)).toBeNull();
  });

  it("rejects malformed fragments", () => {
    expect(decodeFragment("")).toBeNull();
    expect(decodeFragment("#a.b")).toBeNull();
    expect(decodeFragment("#" + "a".repeat(43) + "." + "b".repeat(22) + ".zz zz")).toBeNull();
    expect(decodeFragment("#" + "a".repeat(42) + "." + "b".repeat(22) + ".1")).toBeNull();
  });
});

describe("suggestPassword", () => {
  it("draws every character uniformly from the alphabet", () => {
    const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
    const counts = new Map<string, number>();
    let total = 0;
    for (let i = 0; i < 4000; i++) {
      const p = suggestPassword();
      expect(p).toMatch(/^[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}$/);
      for (const c of p.replaceAll("-", "")) {
        expect(alphabet).toContain(c);
        counts.set(c, (counts.get(c) ?? 0) + 1);
        total++;
      }
    }
    // 48,000 draws over 31 symbols: about 1,548 each. A byte reduced modulo
    // 31 would favour the first eight symbols by an eighth, which is far
    // outside the spread of a uniform draw at this sample size.
    const expected = total / alphabet.length;
    for (const c of alphabet) {
      const n = counts.get(c) ?? 0;
      expect(Math.abs(n - expected) / expected).toBeLessThan(0.08);
    }
  });
});
