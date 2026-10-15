import type { Queryable } from "../../db/pool.js";
import type { AuthState } from "./state.js";

/**
 * The account's auth generation (audit gateway-auth-3). `bootstrap --reset`
 * bumps it in the transaction that deletes everything that could still sign
 * someone in, so authentication material from before a reset cannot create
 * authority after it, even when the request validated it a moment before.
 *
 * The rule for issuers of sessions, passkeys, codes and grants: read the
 * generation in the same statement as the material being validated (passkey,
 * enrollment link, session, code), then write inside a transaction that first
 * calls `holdAuth`. It takes the account row FOR SHARE, which the reset's
 * UPDATE waits for and which waits for the reset, and rechecks the generation
 * and the rows the new state hangs on. Lock order everywhere: account, then
 * passkey, then session.
 */
export async function holdAuth(
  tx: Queryable,
  h: { accountId: string; generation: number; passkeyId?: Buffer; session?: { idHash: Buffer; now: number } },
): Promise<boolean> {
  const { rows } = await tx.query<{ auth_generation: number }>("SELECT auth_generation FROM account WHERE id = $1 FOR SHARE", [
    h.accountId,
  ]);
  if (rows[0]?.auth_generation !== h.generation) return false;
  // A passkey deleted meanwhile (its deletion holds the row FOR UPDATE until it commits).
  if (h.passkeyId) {
    const p = await tx.query("SELECT 1 FROM passkey WHERE id = $1 AND account_id = $2 FOR KEY SHARE", [h.passkeyId, h.accountId]);
    if (p.rows.length === 0) return false;
  }
  // A session revoked meanwhile, with its passkey.
  if (h.session) {
    const q = await tx.query("SELECT 1 FROM auth_session WHERE id_hash = $1 AND account_id = $2 AND expires_at > $3 FOR SHARE", [
      h.session.idHash,
      h.accountId,
      new Date(h.session.now),
    ]);
    if (q.rows.length === 0) return false;
  }
  return true;
}

/** The account's place in the lock order, for changes that issue nothing (passkey deletion). */
export async function lockAccountAuth(tx: Queryable, accountId: string): Promise<void> {
  await tx.query("SELECT 1 FROM account WHERE id = $1 FOR SHARE", [accountId]);
}

/**
 * `bootstrap --reset`: one transaction that bumps the generation and removes
 * the account's sessions, passkeys (and with them their codes), enrollment
 * links, unused codes and pending ceremonies, and revokes its grants (and so
 * their push subscriptions). Returns the counts the CLI prints.
 */
export async function resetAccountAuth(s: AuthState, accountId: string): Promise<{ passkeys: number; sessions: number; grants: number }> {
  const { counts, revoked } = await s.ctx.db.transaction(async (tx) => {
    await tx.query("UPDATE account SET auth_generation = auth_generation + 1 WHERE id = $1", [accountId]);
    const sessions = await tx.query("DELETE FROM auth_session WHERE account_id = $1", [accountId]);
    const passkeys = await tx.query("DELETE FROM passkey WHERE account_id = $1", [accountId]);
    await tx.query("DELETE FROM auth_enroll_token WHERE account_id = $1", [accountId]);
    await tx.query("DELETE FROM auth_challenge WHERE account_id = $1", [accountId]);
    await tx.query("DELETE FROM oauth_code WHERE account_id = $1 AND used_at IS NULL", [accountId]);
    const revoked = await s.store.revokeIn(tx, { accountId }, "bootstrap_reset");
    return {
      counts: { passkeys: passkeys.rowCount ?? 0, sessions: sessions.rowCount ?? 0, grants: revoked.length },
      revoked,
    };
  });
  await s.store.announce(revoked, "bootstrap_reset");
  return counts;
}
