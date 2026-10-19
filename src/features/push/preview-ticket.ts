import { createHash, hkdfSync, timingSafeEqual } from "node:crypto";
import { CryptoError, open, seal } from "../../core/crypto.js";

/**
 * Preview tickets: the one credential a push hands the service worker so it
 * can keep the pushed message for the notification's tap even when the
 * webmail session has expired (an idle phone: the access token behind
 * Bulwark's /api/push/preview lives an hour).
 *
 * A ticket names exactly one message of one account for one push target: the
 * browser's relay record as it was (its endpoint and keys) and the very
 * emulated subscription that authorized the push. It lives
 * `PREVIEW_TICKET_TTL_MS`. It is sealed
 * with a purpose key derived from GATEWAY_ENC_KEY (A6), travels only inside
 * the push payload (RFC 8291: encrypted to the subscribed browser) and in the
 * body of a same-origin POST, never in a URL or a log. It grants a read of
 * that message and nothing else, and only while that subscription is still
 * deliverable and that relay record unchanged: a revoked grant, an expired
 * temporary passkey, an account reset, a destroyed subscription (sign-out),
 * a deleted or re-registered relay record ends it for good, and a new
 * subscription or grant on the same relay id does not bring it back
 * (store.ts `previewTicketTarget`, read from the database on every use).
 */

export const PREVIEW_TICKET_TTL_MS = 10 * 60_000;
/** Longest ticket string accepted (a real one is ~250 characters). */
export const PREVIEW_TICKET_MAX_CHARS = 1024;

const AAD = "webmail-gateway/push-preview-ticket/v2";

export interface PreviewTicket {
  /** Gateway account id. */
  accountId: string;
  /** The push target (relay record) it was minted for. */
  relayId: string;
  /** The emulated subscription that authorized the push. */
  subId: string;
  /** `relayKeyHash` of the relay record's endpoint and keys at minting. */
  keyHash: string;
  /** The upstream's JMAP account id (the payload's `accountId`). */
  legacyAccountId: string;
  /** The one message it names. */
  emailId: string;
  /** Expiry, ms since the epoch. */
  expiresAt: number;
}

const keys = new WeakMap<Buffer, Buffer>();

/** A6: the purpose key for preview tickets. */
function ticketKey(encKey: Buffer): Buffer {
  let k = keys.get(encKey);
  if (!k) {
    k = Buffer.from(hkdfSync("sha256", encKey, Buffer.alloc(0), "webmail-gateway/push-preview-ticket", 32));
    keys.set(encKey, k);
  }
  return k;
}

/** Identifies a relay record's endpoint and keys (a re-registration changes it). */
export function relayKeyHash(r: { endpoint: string; p256dh: string; auth: string }): string {
  return createHash("sha256").update(`${r.endpoint}\0${r.p256dh}\0${r.auth}`).digest("base64url").slice(0, 22);
}

export function sameKeyHash(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function mintPreviewTicket(
  encKey: Buffer,
  t: Omit<PreviewTicket, "expiresAt">,
  now = Date.now(),
): string {
  const body = JSON.stringify({
    v: 2, a: t.accountId, r: t.relayId, s: t.subId, k: t.keyHash, l: t.legacyAccountId, m: t.emailId, x: now + PREVIEW_TICKET_TTL_MS,
  });
  return seal(body, ticketKey(encKey), AAD).toString("base64url");
}

const str = (v: unknown, max: number): v is string => typeof v === "string" && v.length > 0 && v.length <= max;

/** The ticket's contents, or null when it is malformed, forged, from another key, expired or dated too far ahead. */
export function openPreviewTicket(encKey: Buffer, ticket: unknown, now = Date.now()): PreviewTicket | null {
  if (typeof ticket !== "string" || ticket.length > PREVIEW_TICKET_MAX_CHARS || !/^[A-Za-z0-9_-]+$/.test(ticket)) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(open(Buffer.from(ticket, "base64url"), ticketKey(encKey), AAD).toString("utf8"));
  } catch (err) {
    if (err instanceof CryptoError || err instanceof SyntaxError) return null;
    throw err;
  }
  const p = parsed as Record<string, unknown> | null;
  if (!p || typeof p !== "object" || p.v !== 2) return null;
  if (!str(p.a, 64) || !str(p.r, 128) || !str(p.s, 64) || !str(p.k, 64) || !str(p.l, 255) || !str(p.m, 255)) return null;
  const x = p.x;
  if (typeof x !== "number" || !Number.isFinite(x) || x <= now || x > now + PREVIEW_TICKET_TTL_MS) return null;
  return { accountId: p.a, relayId: p.r, subId: p.s, keyHash: p.k, legacyAccountId: p.l, emailId: p.m, expiresAt: x };
}
