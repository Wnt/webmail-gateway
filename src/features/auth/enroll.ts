import type { Queryable } from "../../db/pool.js";
import type { AppContext } from "../../types.js";
import { hashToken, newToken, tokenKind } from "./util.js";

export const ENROLL_TTL_MS = 15 * 60_000;

type Ctx = Pick<AppContext, "db">;

/** Mint a one-time enrollment token for an account (the bootstrap CLI prints its URL). */
export async function createEnrollToken(ctx: Ctx, accountId: string, now: number): Promise<{ token: string; expiresAt: Date }> {
  const token = newToken("enroll");
  const expiresAt = new Date(now + ENROLL_TTL_MS);
  await ctx.db.query(
    "INSERT INTO auth_enroll_token (token_hash, account_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
    [hashToken(token), accountId, new Date(now), expiresAt],
  );
  return { token, expiresAt };
}

/** The account behind a live, unused enrollment token, or null. Does not consume it. */
export async function peekEnrollToken(
  ctx: Ctx,
  token: string | undefined,
  now: number,
): Promise<{ accountId: string; email: string; expiresAt: Date } | null> {
  if (!token || tokenKind(token) !== "enroll") return null;
  const { rows } = await ctx.db.query<{ account_id: string; email: string; expires_at: Date }>(
    `SELECT e.account_id, a.email, e.expires_at FROM auth_enroll_token e JOIN account a ON a.id = e.account_id
     WHERE e.token_hash = $1 AND e.used_at IS NULL AND e.expires_at > $2`,
    [hashToken(token), new Date(now)],
  );
  return rows[0] ? { accountId: rows[0].account_id, email: rows[0].email, expiresAt: rows[0].expires_at } : null;
}

/** Mark the token used, exactly once. Returns the account id, or null when it was already used or expired. */
export async function consumeEnrollToken(q: Queryable, tokenHash: Buffer, now: number): Promise<string | null> {
  const { rows } = await q.query<{ account_id: string }>(
    "UPDATE auth_enroll_token SET used_at = $2 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2 RETURNING account_id",
    [tokenHash, new Date(now)],
  );
  return rows[0]?.account_id ?? null;
}
