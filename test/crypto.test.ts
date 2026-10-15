import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CryptoError, open, seal } from "../src/core/crypto.js";

const key = randomBytes(32);

describe("crypto seal/open", () => {
  it("round-trips strings, bytes and unicode", () => {
    for (const v of ["", "hunter2", "pässi:wörd ✓", randomBytes(5000)]) {
      const out = open(seal(v, key), key);
      expect(out.equals(typeof v === "string" ? Buffer.from(v) : v)).toBe(true);
    }
  });
  it("uses a fresh IV each time and does not contain the plaintext", () => {
    const a = seal("same", key);
    const b = seal("same", key);
    expect(a.equals(b)).toBe(false);
    expect(a.includes(Buffer.from("same"))).toBe(false);
  });
  it("rejects a wrong key, tampering and truncation", () => {
    const sealed = seal("secret", key);
    expect(() => open(sealed, randomBytes(32))).toThrow(CryptoError);
    for (const i of [0, 1, 13, sealed.length - 1]) {
      const t = Buffer.from(sealed);
      t[i] = t[i]! ^ 1;
      expect(() => open(t, key)).toThrow(CryptoError);
    }
    expect(() => open(sealed.subarray(0, 20), key)).toThrow(CryptoError);
    expect(() => open(Buffer.alloc(0), key)).toThrow(CryptoError);
  });
  it("binds the optional AAD", () => {
    const sealed = seal("secret", key, "acct-1");
    expect(open(sealed, key, "acct-1").toString()).toBe("secret");
    expect(() => open(sealed, key, "acct-2")).toThrow(CryptoError);
    expect(() => open(sealed, key)).toThrow(CryptoError);
  });
  it("requires a 32-byte key", () => {
    expect(() => seal("x", randomBytes(16))).toThrow(CryptoError);
    expect(() => open(seal("x", key), randomBytes(31))).toThrow(CryptoError);
  });
});
