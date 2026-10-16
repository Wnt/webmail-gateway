import type { Queryable } from "../../db/pool.js";
import { STEP_UP_WINDOW_MS } from "./sessions.js";
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
  h: { accountId: string; generation: number; passkeyId?: Buffer; session?: { idHash: Buffer; now: number; forUpdate?: boolean } },
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
  return h.session ? holdSession(tx, h.accountId, h.session) : true;
}

/**
 * The session is still live (not reset, not ended with its passkey); locked
 * until the commit: FOR SHARE, or FOR NO KEY UPDATE when the caller will
 * write the row (two writers must not both hold a shared lock and upgrade).
 */
export async function holdSession(
  tx: Queryable,
  accountId: string,
  session: { idHash: Buffer; now: number; forUpdate?: boolean },
): Promise<boolean> {
  const lock = session.forUpdate ? "FOR NO KEY UPDATE" : "FOR SHARE";
  const { rows } = await tx.query(`SELECT 1 FROM auth_session WHERE id_hash = $1 AND account_id = $2 AND expires_at > $3 ${lock}`, [
    session.idHash,
    accountId,
    new Date(session.now),
  ]);
  return rows.length > 0;
}

/**
 * The account row for a deliberate revocation (passkey deletion): taken
 * exclusively, since the revocation also stamps `auth_revoked_at` on it, so
 * concurrent deletions run one after the other. Returns the generation.
 */
export async function lockAccountForRevocation(tx: Queryable, accountId: string): Promise<number | null> {
  const { rows } = await tx.query<{ auth_generation: number }>(
    "SELECT auth_generation FROM account WHERE id = $1 FOR NO KEY UPDATE",
    [accountId],
  );
  return rows[0]?.auth_generation ?? null;
}

/**
 * Inside the transaction that adds or deletes a passkey, after `holdAuth`
 * (or `lockAccountForRevocation` and the passkey locks): the session still
 * holds a step-up authorization (audit gateway-auth-1). The session row is locked FOR SHARE, so deleting the
 * passkey that authorized it (which clears `verified_passkey_id`) waits.
 */
export async function holdStepUp(tx: Queryable, session: { idHash: Buffer; accountId: string }, now: number): Promise<boolean> {
  const { rows } = await tx.query(
    `SELECT 1 FROM auth_session WHERE id_hash = $1 AND account_id = $2 AND expires_at > $3
       AND verified_passkey_id IS NOT NULL AND verified_at > $4 FOR SHARE`,
    [session.idHash, session.accountId, new Date(now), new Date(now - STEP_UP_WINDOW_MS)],
  );
  return rows.length > 0;
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
