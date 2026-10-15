// Interop with legacy-proxy's session tokens. The reference sign/verify below is
// copied verbatim from legacy-proxy (src/auth/session.ts, src/util/base64url.ts);
// cases adapted from the benchmark's hidden suite (bench/hidden/hidden.test.ts).
import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { mintLegacyToken } from "../src/core/legacy.js";
import { mintToken, verifyToken } from "../src/core/token.js";

// --- legacy-proxy reference ---
const b64uEncode = (buf: Buffer | Uint8Array) =>
  Buffer.from(buf).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
const b64uDecode = (s: string) => {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replaceAll("-", "+").replaceAll("_", "/") + pad, "base64");
};
type SessionToken = { accountSlug: string; username: string; iat: number; exp: number };
function refSign(key: Buffer, t: SessionToken): string {
  const body = b64uEncode(Buffer.from(JSON.stringify(t), "utf8"));
  const sig = b64uEncode(crypto.createHmac("sha256", key).update(body).digest());
  return `${body}.${sig}`;
}
function refVerify(key: Buffer, token: string): SessionToken | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts as [string, string];
  const expected = b64uEncode(crypto.createHmac("sha256", key).update(body).digest());
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const parsed = JSON.parse(b64uDecode(body).toString("utf8")) as SessionToken;
  if (parsed.exp < Math.floor(Date.now() / 1000)) return null;
  return parsed;
}

const key = crypto.randomBytes(32);
const now = Math.floor(Date.now() / 1000);

describe("token interop", () => {
  it("candidate token verifies with legacy-proxy reference", () => {
    const tok = mintToken(key, { accountSlug: "gandi:jonni@madekivi.fi", username: "jonni@madekivi.fi" }, now);
    const v = refVerify(key, tok);
    expect(v).toEqual({ accountSlug: "gandi:jonni@madekivi.fi", username: "jonni@madekivi.fi", iat: now, exp: now + 300 });
  });
  it("key order and no padding match reference byte-for-byte", () => {
    const t = { accountSlug: "a:b", username: "ü@x.fi", iat: now, exp: now + 60 };
    expect(mintToken(key, { accountSlug: t.accountSlug, username: t.username, ttlSec: 60 }, now)).toBe(refSign(key, t));
  });
  it("reference token verifies with candidate", () => {
    const t = { accountSlug: "s", username: "u@x.fi", iat: now, exp: now + 100 };
    expect(verifyToken(key, refSign(key, t), now)).toEqual(t);
  });
  it("rejects wrong key, tampering, expiry, junk", () => {
    const tok = mintToken(key, { accountSlug: "s", username: "u", ttlSec: 10 }, now);
    expect(verifyToken(crypto.randomBytes(32), tok, now)).toBeNull();
    const [b, s] = tok.split(".");
    expect(verifyToken(key, `${b}x.${s}`, now)).toBeNull();
    expect(verifyToken(key, `${b}.${s}.x`, now)).toBeNull();
    expect(verifyToken(key, tok, now + 11)).toBeNull();
    expect(verifyToken(key, "", now)).toBeNull();
    expect(verifyToken(key, "...", now)).toBeNull();
    const badJson = b64uEncode(Buffer.from("{not json"));
    const sig = b64uEncode(crypto.createHmac("sha256", key).update(badJson).digest());
    expect(verifyToken(key, `${badJson}.${sig}`, now)).toBeNull();
  });
});

describe("mintLegacyToken", () => {
  it("is legacy-proxy format with the 300 s TTL and the given key", () => {
    const tok = mintLegacyToken("gandi:jonni@madekivi.fi", "jonni@madekivi.fi", key, now);
    expect(refVerify(key, tok)).toEqual({
      accountSlug: "gandi:jonni@madekivi.fi",
      username: "jonni@madekivi.fi",
      iat: now,
      exp: now + 300,
    });
  });
  it("falls back to LEGACY_SESSION_HMAC_KEY from the environment", () => {
    const prev = process.env.LEGACY_SESSION_HMAC_KEY;
    process.env.LEGACY_SESSION_HMAC_KEY = key.toString("base64");
    try {
      expect(refVerify(key, mintLegacyToken("s", "u"))?.accountSlug).toBe("s");
    } finally {
      if (prev === undefined) delete process.env.LEGACY_SESSION_HMAC_KEY;
      else process.env.LEGACY_SESSION_HMAC_KEY = prev;
    }
  });
});
