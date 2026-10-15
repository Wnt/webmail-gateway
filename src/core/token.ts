// HMAC session tokens, wire-compatible with legacy-proxy (src/auth/session.ts).
// Format: base64url(JSON{accountSlug,username,iat,exp}) + "." + base64url(HMAC-SHA256(key, body)).
import { createHmac, timingSafeEqual } from "node:crypto";

export interface TokenInput {
  accountSlug: string;
  username: string;
  ttlSec?: number;
}

export interface TokenClaims {
  accountSlug: string;
  username: string;
  iat: number;
  exp: number;
}

const DEFAULT_TTL_SEC = 300;

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function sign(key: Buffer, body: string): string {
  return b64url(createHmac("sha256", key).update(body, "utf8").digest());
}

export function mintToken(
  key: Buffer,
  t: TokenInput,
  nowSec: number = Math.floor(Date.now() / 1000),
): string {
  const iat = Math.floor(nowSec);
  const exp = iat + (t.ttlSec ?? DEFAULT_TTL_SEC);
  const claims: TokenClaims = {
    accountSlug: t.accountSlug,
    username: t.username,
    iat,
    exp,
  };
  const body = b64url(Buffer.from(JSON.stringify(claims), "utf8"));
  return `${body}.${sign(key, body)}`;
}

export function verifyToken(
  key: Buffer,
  token: string,
  nowSec: number = Math.floor(Date.now() / 1000),
): TokenClaims | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts as [string, string];

  const expected = Buffer.from(sign(key, body), "utf8");
  const given = Buffer.from(sig, "utf8");
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const c = parsed as Record<string, unknown>;
  if (
    typeof c["accountSlug"] !== "string" ||
    typeof c["username"] !== "string" ||
    typeof c["iat"] !== "number" ||
    typeof c["exp"] !== "number"
  ) {
    return null;
  }
  if (c["exp"] < nowSec) return null;
  return {
    accountSlug: c["accountSlug"],
    username: c["username"],
    iat: c["iat"],
    exp: c["exp"],
  };
}
