import { createHash, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Opaque tokens: a type prefix (for secret scanning and cheap dispatch) plus
 * 32 random bytes, base64url. Only `sha256(token)` is ever stored.
 */
export type TokenKind = "code" | "access" | "refresh" | "session" | "enroll";

const PREFIX: Record<TokenKind, string> = {
  code: "gwc_",
  access: "gwa_",
  refresh: "gwr_",
  session: "gws_",
  enroll: "gwe_",
};

export const TOKEN_RE = /^gw[acrse]_[A-Za-z0-9_-]{43}$/;

export function newToken(kind: TokenKind): string {
  return PREFIX[kind] + randomBytes(32).toString("base64url");
}

export function tokenKind(token: string): TokenKind | null {
  if (!TOKEN_RE.test(token)) return null;
  const p = token.slice(0, 4);
  return (Object.keys(PREFIX) as TokenKind[]).find((k) => PREFIX[k] === p) ?? null;
}

/** sha256 of a token (or any string), as a Buffer for `bytea` columns. */
export function hashToken(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

export const sha256hex = (s: string): string => hashToken(s).toString("hex");

export function constantTimeEqual(a: string | Buffer, b: string | Buffer): boolean {
  const x = Buffer.isBuffer(a) ? a : Buffer.from(a, "utf8");
  const y = Buffer.isBuffer(b) ? b : Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

/** PKCE S256 (RFC 7636): `base64url(sha256(verifier)) == challenge`, compared in constant time. */
export function pkceMatches(verifier: string, challenge: string): boolean {
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return false;
  return constantTimeEqual(createHash("sha256").update(verifier, "ascii").digest("base64url"), challenge);
}

export const isCodeChallenge = (s: string): boolean => /^[A-Za-z0-9_-]{43}$/.test(s);

/**
 * Purpose keys derived from `GATEWAY_ENC_KEY` with HKDF-SHA256 and a distinct
 * `info` label (A6): the flow-cookie sealing key, the refresh-successor key.
 */
export function deriveKey(master: Buffer, info: string): Buffer {
  return Buffer.from(hkdfSync("sha256", master, Buffer.alloc(0), `webmail-gateway/${info}`, 32));
}

/** `bytea` values come back as Buffer from pg and Uint8Array from PGlite. */
export const asBuffer = (v: Uint8Array | Buffer | null | undefined): Buffer | null =>
  v == null ? null : Buffer.isBuffer(v) ? v : Buffer.from(v);

export const b64url = {
  encode: (b: Uint8Array): string => Buffer.from(b).toString("base64url"),
  decode: (s: string): Buffer => Buffer.from(s, "base64url"),
  is: (s: unknown): s is string => typeof s === "string" && /^[A-Za-z0-9_-]+$/.test(s),
};

/** HTML-escape for the few server-rendered pages. */
export const escapeHtml = (s: string): string =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

// --- cookies (no plugin: three cookies, two attributes that matter) ---------

export function parseCookies(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i <= 0) continue;
    const name = part.slice(0, i).trim();
    if (name && !out.has(name)) out.set(name, part.slice(i + 1).trim());
  }
  return out;
}

export interface CookieOptions {
  path: string;
  maxAge: number; // seconds; 0 deletes
  secure: boolean;
  sameSite: "Strict" | "Lax";
}

export function serializeCookie(name: string, value: string, o: CookieOptions): string {
  const parts = [`${name}=${value}`, `Path=${o.path}`, `Max-Age=${o.maxAge}`, "HttpOnly", `SameSite=${o.sameSite}`];
  if (o.secure) parts.push("Secure");
  return parts.join("; ");
}

/** Space-separated scope list <-> array, de-duplicated and ordered. */
export const scopes = {
  parse: (s: string | null | undefined): string[] => [...new Set((s ?? "").split(/\s+/).filter(Boolean))],
  join: (a: readonly string[]): string => [...new Set(a)].join(" "),
};
