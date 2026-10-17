import type { Queryable } from "../../db/pool.js";
import { hashToken, newToken, tokenKind } from "./util.js";

export const ENROLL_TTL_MS = 15 * 60_000;

/** Temporary passkeys (CLI `enroll --ttl`): the default lifetime, and the bounds. */
export const TEMP_PASSKEY_DEFAULT_TTL_MS = 4 * 3600_000;
export const TEMP_PASSKEY_MIN_TTL_MS = 60_000;
export const TEMP_PASSKEY_MAX_TTL_MS = 24 * 3600_000;

type Ctx = { db: Queryable };

/** What a temporary enrollment link records: the passkey's lifetime from its creation, and its name. */
export interface TemporaryEnrollment {
  ttlMs: number;
  label?: string | null;
}

/**
 * Mint a one-time enrollment token for an account (the bootstrap CLI prints
 * its URL). `temporary`: the passkey created from it expires `ttlMs` after its
 * creation (bounded by TEMP_PASSKEY_MIN/MAX_TTL_MS) and is named `label`.
 */
export async function createEnrollToken(
  ctx: Ctx,
  accountId: string,
  now: number,
  temporary?: TemporaryEnrollment,
): Promise<{ token: string; expiresAt: Date }> {
  if (temporary && !(temporary.ttlMs >= TEMP_PASSKEY_MIN_TTL_MS && temporary.ttlMs <= TEMP_PASSKEY_MAX_TTL_MS)) {
    throw new RangeError(`temporary passkey TTL must be between ${TEMP_PASSKEY_MIN_TTL_MS / 60_000} min and ${TEMP_PASSKEY_MAX_TTL_MS / 3600_000} h`);
  }
  const token = newToken("enroll");
  const expiresAt = new Date(now + ENROLL_TTL_MS);
  await ctx.db.query(
    "INSERT INTO auth_enroll_token (token_hash, account_id, created_at, expires_at, passkey_ttl_s, label) VALUES ($1, $2, $3, $4, $5, $6)",
    [
      hashToken(token),
      accountId,
      new Date(now),
      expiresAt,
      temporary ? Math.floor(temporary.ttlMs / 1000) : null,
      temporary?.label ?? null,
    ],
  );
  return { token, expiresAt };
}

/**
 * The account behind a live, unused enrollment token, or null. Does not
 * consume it. `generation` is the account's auth generation in the same
 * snapshot (see generation.ts); `bootstrap --reset` deletes older tokens.
 */
export async function peekEnrollToken(
  ctx: Ctx,
  token: string | undefined,
  now: number,
): Promise<{
  accountId: string;
  email: string;
  expiresAt: Date;
  generation: number;
  /** A temporary enrollment: the new passkey's lifetime and name. */
  temporary: { ttlMs: number; label: string | null } | null;
} | null> {
  if (!token || tokenKind(token) !== "enroll") return null;
  const { rows } = await ctx.db.query<{
    account_id: string;
    email: string;
    expires_at: Date;
    auth_generation: number;
    passkey_ttl_s: number | null;
    label: string | null;
  }>(
    `SELECT e.account_id, a.email, e.expires_at, a.auth_generation, e.passkey_ttl_s, e.label
     FROM auth_enroll_token e JOIN account a ON a.id = e.account_id
     WHERE e.token_hash = $1 AND e.used_at IS NULL AND e.expires_at > $2`,
    [hashToken(token), new Date(now)],
  );
  const r = rows[0];
  if (!r) return null;
  return {
    accountId: r.account_id,
    email: r.email,
    expiresAt: r.expires_at,
    generation: r.auth_generation,
    temporary: r.passkey_ttl_s === null ? null : { ttlMs: r.passkey_ttl_s * 1000, label: r.label },
  };
}

/** Mark the token used, exactly once. Returns the account id, or null when it was already used or expired. */
export async function consumeEnrollToken(q: Queryable, tokenHash: Buffer, now: number): Promise<string | null> {
  const { rows } = await q.query<{ account_id: string }>(
    "UPDATE auth_enroll_token SET used_at = $2 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2 RETURNING account_id",
    [tokenHash, new Date(now)],
  );
  return rows[0]?.account_id ?? null;
}
