import { createHash, hkdfSync, timingSafeEqual } from "node:crypto";
import { CryptoError, open, seal } from "../../core/crypto.js";

/**
 * Preview tickets: the one credential a push hands the service worker so it
 * can keep the pushed message for the notification's tap even when the
 * webmail session has expired (an idle phone: the access token behind
 * Bulwark's /api/push/preview lives an hour).
 *
 * A ticket names exactly one message of one account for one push target: the
 * browser's relay record as it was (its incarnation, endpoint and keys) and
 * the very emulated subscription that authorized the push. It lives
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
/**
 * Longest ticket string minted or accepted. A ticket with every field at its
 * longest (uuid, 128-character relay id, 64-character subscription id and
 * incarnation, 22-character key hash, 255-character upstream ids) is about
 * 1,300 characters; a real one about 350. Minting refuses anything longer.
 */
export const PREVIEW_TICKET_MAX_CHARS = 2048;

const AAD = "webmail-gateway/push-preview-ticket/v3";

export interface PreviewTicket {
  /** Gateway account id. */
  accountId: string;
  /** The push target (relay record) it was minted for. */
  relayId: string;
  /** The emulated subscription that authorized the push. */
  subId: string;
  /** `relayKeyHash` of the relay record's endpoint and keys at minting. */
  keyHash: string;
  /** The relay record's incarnation at minting (store.ts, migration 230). */
  incarnation: string;
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

/** A sealed ticket, or null when a field is out of bounds (then the push simply carries none). */
export function mintPreviewTicket(
  encKey: Buffer,
  t: Omit<PreviewTicket, "expiresAt">,
  now = Date.now(),
): string | null {
  if (!fieldsOk(t.accountId, t.relayId, t.subId, t.keyHash, t.incarnation, t.legacyAccountId, t.emailId)) return null;
  const body = JSON.stringify({
    v: 3, a: t.accountId, r: t.relayId, s: t.subId, k: t.keyHash, i: t.incarnation, l: t.legacyAccountId, m: t.emailId,
    x: now + PREVIEW_TICKET_TTL_MS,
  });
  const ticket = seal(body, ticketKey(encKey), AAD).toString("base64url");
  return ticket.length <= PREVIEW_TICKET_MAX_CHARS ? ticket : null;
}

const str = (v: unknown, max: number): v is string => typeof v === "string" && v.length > 0 && v.length <= max;

/** The same per-field bounds for minting and opening, so every minted ticket opens. */
function fieldsOk(a: unknown, r: unknown, s: unknown, k: unknown, i: unknown, l: unknown, m: unknown): boolean {
  return str(a, 64) && str(r, 128) && str(s, 64) && str(k, 64) && str(i, 64) && str(l, 255) && str(m, 255);
}

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
  if (!p || typeof p !== "object" || p.v !== 3) return null;
  if (!fieldsOk(p.a, p.r, p.s, p.k, p.i, p.l, p.m)) return null;
  const x = p.x;
  if (typeof x !== "number" || !Number.isFinite(x) || x <= now || x > now + PREVIEW_TICKET_TTL_MS) return null;
  return {
    accountId: p.a as string, relayId: p.r as string, subId: p.s as string, keyHash: p.k as string, incarnation: p.i as string,
    legacyAccountId: p.l as string, emailId: p.m as string, expiresAt: x,
  };
}
