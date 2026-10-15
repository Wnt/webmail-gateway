import { CryptoError, open, seal } from "../../core/crypto.js";

/**
 * Browser-bound flow state (the pending authorization request, a ceremony's
 * challenge id, the enrollment token) travels in sealed cookies: AES-256-GCM
 * under an HKDF purpose key, with the cookie name as AAD so a value cannot be
 * replayed under another name, and an expiry inside the payload.
 */
export function sealJson(key: Buffer, name: string, payload: Record<string, unknown>, expiresAtMs: number): string {
  return seal(JSON.stringify({ ...payload, exp: expiresAtMs }), key, name).toString("base64url");
}

export function openJson<T extends Record<string, unknown>>(
  key: Buffer,
  name: string,
  value: string | undefined,
  nowMs: number,
): (T & { exp: number }) | null {
  if (!value || !/^[A-Za-z0-9_-]{40,4096}$/.test(value)) return null;
  try {
    const parsed = JSON.parse(open(Buffer.from(value, "base64url"), key, name).toString("utf8")) as unknown;
    if (typeof parsed !== "object" || parsed === null) return null;
    const p = parsed as T & { exp: number };
    if (typeof p.exp !== "number" || p.exp <= nowMs) return null;
    return p;
  } catch (err) {
    if (err instanceof CryptoError || err instanceof SyntaxError) return null;
    throw err;
  }
}
