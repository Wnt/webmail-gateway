import type { FastifyRequest } from "fastify";
import type { Authenticator, Principal } from "../../core/auth-context.js";
import { open, seal } from "../../core/crypto.js";
import { emitTokenRevoked } from "../../core/hooks.js";
import { notifyRevocation } from "../../core/revocation.js";
import type { Queryable } from "../../db/pool.js";
import type { AppContext } from "../../types.js";
import { holdAuth } from "./generation.js";
import { asBuffer, deriveKey, hashToken, newToken, pkceMatches, scopes as scopeUtil, tokenKind } from "./util.js";

export const CODE_TTL_MS = 60_000;
export const ACCESS_TTL_MS = 3600_000;
export const REFRESH_TTL_MS = 30 * 86400_000;
export const GRANT_TTL_MS = 180 * 86400_000;
/** A10: a refresh token presented again within this window gets the same successor pair. */
export const REFRESH_GRACE_MS = 30_000;

export interface IssuedTokens {
  grantId: string;
  accessToken: string;
  refreshToken: string;
  /** Seconds. */
  expiresIn: number;
  scopes: string[];
}

export type RevokeReason =
  | "client_revoke"
  | "refresh_reuse"
  | "code_replay"
  | "bootstrap_reset"
  | "not_allowed"
  | "passkey_deleted"
  | "passkey_expired";

/** The earliest of two instants, either of which may be absent (epoch ms). */
const earliest = (a: number, b: number | null | undefined): number => (b === null || b === undefined ? a : Math.min(a, b));

/** A grant revoked inside a transaction; `announce` it once that commits. */
export interface RevokedGrant {
  grantId: string;
  accountId: string;
  tokenIds: string[];
}

interface GrantRow {
  id: string;
  client_id: string;
  account_id: string;
  scopes: string;
  resource: string | null;
  expires_at: Date;
  revoked_at: Date | null;
  email: string;
}

type Ctx = Pick<AppContext, "config" | "db" | "log">;

/**
 * Grants, codes, access and refresh tokens. Timestamps come from `now()` so
 * tests can drive the clock; the DB never computes time. Nothing is cached:
 * every Bearer request, refresh and redemption reads the database, so a
 * revocation or expiry, from any process, holds on the very next request.
 * A temporary passkey's expiry caps everything issued from it (code, grant,
 * tokens) and is checked again at every use.
 */
export class TokenStore {
  private readonly successorKey: Buffer;

  constructor(
    private readonly ctx: Ctx,
    private readonly now: () => number = Date.now,
  ) {
    this.successorKey = deriveKey(ctx.config.encKey, "auth/refresh-successor");
  }

  private allowed(email: string): boolean {
    return this.ctx.config.allowedEmails.includes(email);
  }

  // --- authorization codes -------------------------------------------------

  /** `passkeyId`: the passkey whose assertion authorized it; the grant inherits it (deleting the passkey revokes the grant). */
  async issueCode(
    input: {
      clientId: string;
      accountId: string;
      passkeyId: Buffer;
      redirectUri: string;
      codeChallenge: string;
      scopes: readonly string[];
      resource?: string | null;
    },
    q: Queryable = this.ctx.db,
  ): Promise<string> {
    const code = newToken("code");
    const t = this.now();
    await q.query(
      `INSERT INTO oauth_code (code_hash, client_id, account_id, passkey_id, redirect_uri, code_challenge, scopes, resource, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, LEAST($10::timestamptz, (SELECT expires_at FROM passkey WHERE id = $4)))`,
      [
        hashToken(code),
        input.clientId,
        input.accountId,
        input.passkeyId,
        input.redirectUri,
        input.codeChallenge,
        scopeUtil.join(input.scopes),
        input.resource ?? null,
        new Date(t),
        new Date(t + CODE_TTL_MS),
      ],
    );
    return code;
  }

  /**
   * Redeem a code exactly once. Nothing happens unless the request proves it
   * is the client the code was issued to: the same client id, the same
   * redirect URI and the PKCE verifier of the code's challenge. Only then is
   * an unused code spent, and only then does presenting a code that was
   * already redeemed count as a replay, which revokes the grant it produced
   * (RFC 9700 §4.5.3). So a request from another client (the public one
   * needs no secret) or without the verifier neither spends a code nor
   * revokes a grant. Returns null on any failure; the caller answers
   * `invalid_grant`.
   */
  async redeemCode(input: { code: string; clientId: string; redirectUri: string; codeVerifier: string }): Promise<IssuedTokens | null> {
    if (tokenKind(input.code) !== "code") return null;
    const hash = hashToken(input.code);
    const t = this.now();
    let replayOf: string | null = null;
    const issued = await this.ctx.db.transaction(async (tx) => {
      // The code, its bindings and the account's auth generation in one
      // snapshot. The bindings never change, so they are checked here,
      // before anything is written.
      const { rows } = await tx.query<{
        client_id: string;
        redirect_uri: string;
        code_challenge: string;
        used_at: Date | null;
        expires_at: Date;
        account_id: string;
        passkey_id: Uint8Array;
        scopes: string;
        resource: string | null;
        email: string;
        auth_generation: number;
        passkey_expires_at: Date | null;
      }>(
        `SELECT c.client_id, c.redirect_uri, c.code_challenge, c.used_at, c.expires_at, c.account_id, c.passkey_id, c.scopes, c.resource,
                a.email, a.auth_generation, p.expires_at AS passkey_expires_at
         FROM oauth_code c JOIN account a ON a.id = c.account_id JOIN passkey p ON p.id = c.passkey_id
         WHERE c.code_hash = $1`,
        [hash],
      );
      const row = rows[0];
      if (!row) return null;
      if (row.client_id !== input.clientId || row.redirect_uri !== input.redirectUri || !pkceMatches(input.codeVerifier, row.code_challenge)) {
        return null;
      }
      const replay = async () => {
        const prior = await tx.query<{ grant_id: string | null }>(
          "SELECT grant_id FROM oauth_code WHERE code_hash = $1 AND used_at IS NOT NULL",
          [hash],
        );
        replayOf = prior.rows[0]?.grant_id ?? null;
        return null;
      };
      if (row.used_at) return replay();
      if (row.expires_at.getTime() <= t) return null;
      // A temporary passkey that expired meanwhile authorizes no grant.
      if (row.passkey_expires_at && row.passkey_expires_at.getTime() <= t) return null;
      if (!this.allowed(row.email)) return null;
      // The generation and the code's passkey held before the code is spent:
      // a reset or passkey deletion either finished first (no grant) or waits
      // for this grant and revokes it.
      const passkeyId = asBuffer(row.passkey_id)!;
      if (!(await holdAuth(tx, { accountId: row.account_id, generation: row.auth_generation, passkeyId }))) return null;
      const spent = await tx.query("UPDATE oauth_code SET used_at = $2 WHERE code_hash = $1 AND used_at IS NULL AND expires_at > $2", [
        hash,
        new Date(t),
      ]);
      // Spent meanwhile by a request that proved the same bindings: a replay.
      if ((spent.rowCount ?? 0) === 0) return replay();
      const grant = await this.createGrant(tx, {
        accountId: row.account_id,
        passkeyId,
        passkeyExpiresAt: row.passkey_expires_at?.getTime() ?? null,
        clientId: row.client_id,
        scopes: scopeUtil.parse(row.scopes),
        resource: row.resource,
        email: row.email,
      });
      await tx.query("UPDATE oauth_code SET grant_id = $2 WHERE code_hash = $1", [hash, grant.grantId]);
      return grant;
    });
    if (replayOf) await this.revokeGrant(replayOf, "code_replay");
    return issued;
  }

  private async createGrant(
    tx: Queryable,
    g: {
      accountId: string;
      passkeyId: Buffer;
      /** A temporary passkey's expiry: the grant and its tokens end no later. */
      passkeyExpiresAt: number | null;
      clientId: string;
      scopes: string[];
      resource: string | null;
      email: string;
    },
  ): Promise<IssuedTokens> {
    const { accountId, clientId, scopes, email } = g;
    const t = this.now();
    const { rows } = await tx.query<{ id: string }>(
      `INSERT INTO oauth_grant (client_id, account_id, passkey_id, scopes, resource, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [clientId, accountId, g.passkeyId, scopeUtil.join(scopes), g.resource, new Date(t), new Date(earliest(t + GRANT_TTL_MS, g.passkeyExpiresAt))],
    );
    const grantId = rows[0]!.id;
    const { accessExpiresAt: _a, ...pair } = await this.mint(tx, grantId, g.passkeyExpiresAt);
    this.ctx.log?.info({ grantId, accountId, clientId, email }, "oauth grant created");
    return { grantId, scopes, ...pair };
  }

  /** A token pair for the grant; `capAt`: a temporary passkey's expiry, which neither token outlives. */
  private async mint(
    tx: Queryable,
    grantId: string,
    capAt: number | null,
  ): Promise<Pick<IssuedTokens, "accessToken" | "refreshToken" | "expiresIn"> & { accessExpiresAt: number }> {
    const t = this.now();
    const accessToken = newToken("access");
    const refreshToken = newToken("refresh");
    const accessExpiresAt = earliest(t + ACCESS_TTL_MS, capAt);
    await tx.query(
      "INSERT INTO oauth_access_token (token_hash, grant_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
      [hashToken(accessToken), grantId, new Date(t), new Date(accessExpiresAt)],
    );
    await tx.query(
      "INSERT INTO oauth_refresh_token (token_hash, grant_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
      [hashToken(refreshToken), grantId, new Date(t), new Date(earliest(t + REFRESH_TTL_MS, capAt))],
    );
    return { accessToken, refreshToken, expiresIn: Math.max(1, Math.floor((accessExpiresAt - t) / 1000)), accessExpiresAt };
  }

  // --- refresh -------------------------------------------------------------

  /**
   * Rotate a refresh token. A token already used within `REFRESH_GRACE_MS`
   * returns the very same successor pair (sealed on its row); used earlier
   * than that, it is reuse and the whole grant is revoked.
   */
  async refresh(input: { refreshToken: string; clientId: string; scope?: string[] }): Promise<IssuedTokens | null> {
    if (tokenKind(input.refreshToken) !== "refresh") return null;
    const hash = hashToken(input.refreshToken);
    const t = this.now();
    let revoke: { grantId: string; reason: RevokeReason } | null = null;
    const out = await this.ctx.db.transaction(async (tx) => {
      const { rows } = await tx.query<
        GrantRow & { rt_expires_at: Date; used_at: Date | null; successor: Uint8Array | null; passkey_expires_at: Date | null }
      >(
        `SELECT g.id, g.client_id, g.account_id, g.scopes, g.resource, g.expires_at, g.revoked_at, a.email,
                rt.expires_at AS rt_expires_at, rt.used_at, rt.successor, p.expires_at AS passkey_expires_at
         FROM oauth_refresh_token rt
         JOIN oauth_grant g ON g.id = rt.grant_id
         JOIN account a ON a.id = g.account_id
         LEFT JOIN passkey p ON p.id = g.passkey_id
         WHERE rt.token_hash = $1
         FOR UPDATE OF rt`,
        [hash],
      );
      const row = rows[0];
      if (!row || row.client_id !== input.clientId) return null;
      if (row.revoked_at || row.expires_at.getTime() <= t || row.rt_expires_at.getTime() <= t) return null;
      const passkeyExpiresAt = row.passkey_expires_at?.getTime() ?? null;
      if (passkeyExpiresAt !== null && passkeyExpiresAt <= t) return null;
      if (!this.allowed(row.email)) {
        revoke = { grantId: row.id, reason: "not_allowed" };
        return null;
      }
      if (row.used_at) {
        const successor = asBuffer(row.successor);
        if (t - row.used_at.getTime() <= REFRESH_GRACE_MS && successor) {
          const s = JSON.parse(open(successor, this.successorKey, row.id).toString("utf8")) as {
            accessToken: string;
            refreshToken: string;
            accessExpiresAt: number;
            scopes: string[];
          };
          return {
            grantId: row.id,
            accessToken: s.accessToken,
            refreshToken: s.refreshToken,
            expiresIn: Math.max(1, Math.floor((s.accessExpiresAt - t) / 1000)),
            scopes: s.scopes,
          } satisfies IssuedTokens;
        }
        revoke = { grantId: row.id, reason: "refresh_reuse" };
        return null;
      }
      const granted = scopeUtil.parse(row.scopes);
      const scopes = input.scope?.length ? input.scope.filter((s) => granted.includes(s)) : granted;
      if (input.scope?.length && scopes.length !== input.scope.length) return null;
      const { accessExpiresAt, ...pair } = await this.mint(tx, row.id, passkeyExpiresAt);
      const sealed = seal(
        JSON.stringify({ ...pair, accessExpiresAt, scopes }),
        this.successorKey,
        row.id,
      );
      await tx.query("UPDATE oauth_refresh_token SET used_at = $2, successor = $3 WHERE token_hash = $1", [
        hash,
        new Date(t),
        sealed,
      ]);
      return { grantId: row.id, scopes, ...pair } satisfies IssuedTokens;
    });
    if (revoke) {
      const r = revoke as { grantId: string; reason: RevokeReason };
      await this.revokeGrant(r.grantId, r.reason);
    }
    return out;
  }

  // --- revocation ----------------------------------------------------------

  /** Revoke a grant: its tokens are deleted, the grant row stays for the record, listeners are told. */
  async revokeGrant(grantId: string, reason: RevokeReason): Promise<void> {
    await this.announce(await this.ctx.db.transaction((tx) => this.revokeIn(tx, { grantId }, reason)), reason);
  }

  /**
   * Revoke, inside `tx`, the grants that match: one grant, every grant of an
   * account, or (`passkeyId`) the account's grants authorized by that passkey
   * plus those from before grants recorded their passkey (`exact`: only the
   * passkey's own, for a temporary passkey, which stamps nothing on the
   * account either: none of the account's unbound push is its). Revocation is
   * durable: the grant row's `revoked_at` and reason are what token and push
   * checks read, and the account's `auth_revoked_at` is stamped (an account or
   * passkey selector always stamps it, even with no grant to revoke). Grants
   * that merely expired are revoked too: push outlives expiry, not this. The
   * same transaction sends the cross-process notice (core/revocation), so the
   * server closes the grants' streams even when a CLI process revoked them.
   * Call `announce` with the result after the commit.
   *
   * Locks the account row first (FOR NO KEY UPDATE), then grants: the order
   * passkey deletion and reset use, so concurrent revocations cannot deadlock.
   */
  async revokeIn(
    tx: Queryable,
    which: { grantId: string } | { accountId: string; passkeyId?: Buffer; exact?: boolean },
    reason: RevokeReason,
  ): Promise<RevokedGrant[]> {
    const t = new Date(this.now());
    let account: string | undefined;
    if ("grantId" in which) {
      const g = await tx.query<{ account_id: string }>("SELECT account_id FROM oauth_grant WHERE id = $1", [which.grantId]);
      account = g.rows[0]?.account_id;
      if (!account) return [];
    } else account = which.accountId;
    await tx.query("SELECT 1 FROM account WHERE id = $1 FOR NO KEY UPDATE", [account]);
    const revocable = "(revoked_at IS NULL OR revoked_reason = 'expired')";
    const { rows } =
      "grantId" in which
        ? await tx.query<{ id: string; account_id: string }>(
            `UPDATE oauth_grant SET revoked_at = $2, revoked_reason = $3 WHERE id = $1 AND ${revocable} RETURNING id, account_id`,
            [which.grantId, t, reason],
          )
        : which.passkeyId
          ? await tx.query<{ id: string; account_id: string }>(
              `UPDATE oauth_grant SET revoked_at = $3, revoked_reason = $4
               WHERE account_id = $1 AND (passkey_id = $2 ${which.exact ? "" : "OR passkey_id IS NULL"}) AND ${revocable}
               RETURNING id, account_id`,
              [which.accountId, which.passkeyId, t, reason],
            )
          : await tx.query<{ id: string; account_id: string }>(
              `UPDATE oauth_grant SET revoked_at = $2, revoked_reason = $3 WHERE account_id = $1 AND ${revocable} RETURNING id, account_id`,
              [which.accountId, t, reason],
            );
    const exact = !("grantId" in which) && which.exact === true;
    if (!exact && (!("grantId" in which) || rows.length > 0)) {
      await tx.query("UPDATE account SET auth_revoked_at = $2 WHERE id = $1", [account, t]);
    }
    const out: RevokedGrant[] = [];
    for (const g of rows) {
      const ats = await tx.query<{ token_hash: Uint8Array }>("DELETE FROM oauth_access_token WHERE grant_id = $1 RETURNING token_hash", [g.id]);
      await tx.query("DELETE FROM oauth_refresh_token WHERE grant_id = $1", [g.id]);
      out.push({ grantId: g.id, accountId: g.account_id, tokenIds: ats.rows.map((r) => asBuffer(r.token_hash)!.toString("hex")) });
    }
    if (out.length > 0) await notifyRevocation(tx, { accountId: account, grantIds: out.map((g) => g.grantId) });
    return out;
  }

  /**
   * After the revoking transaction committed: log, tell this process's
   * listeners at once (open streams close, A4). Other processes' revocations
   * reach them through the notice that `revokeIn` sent.
   */
  async announce(revoked: RevokedGrant[], reason: RevokeReason): Promise<void> {
    for (const r of revoked) {
      this.ctx.log?.info({ grantId: r.grantId, reason, accountId: r.accountId }, "oauth grant revoked");
      await emitTokenRevoked(r);
    }
  }

  /** RFC 7009: revoke by token. Unknown tokens and other clients' tokens are silently ignored. */
  async revokeToken(token: string, clientId: string): Promise<void> {
    const kind = tokenKind(token);
    const hash = hashToken(token);
    if (kind === "refresh") {
      const { rows } = await this.ctx.db.query<{ grant_id: string }>(
        `SELECT rt.grant_id FROM oauth_refresh_token rt JOIN oauth_grant g ON g.id = rt.grant_id
         WHERE rt.token_hash = $1 AND g.client_id = $2`,
        [hash, clientId],
      );
      if (rows[0]) await this.revokeGrant(rows[0].grant_id, "client_revoke");
    } else if (kind === "access") {
      const id = hash.toString("hex");
      const revoked = await this.ctx.db.transaction(async (tx) => {
        const { rows } = await tx.query<{ grant_id: string; account_id: string }>(
          `DELETE FROM oauth_access_token at USING oauth_grant g
           WHERE at.token_hash = $1 AND g.id = at.grant_id AND g.client_id = $2
           RETURNING at.grant_id, g.account_id`,
          [hash, clientId],
        );
        const r = rows[0];
        if (r) await notifyRevocation(tx, { accountId: r.account_id, grantIds: [r.grant_id], tokenIds: [id], tokensOnly: true });
        return r ?? null;
      });
      if (revoked) {
        await emitTokenRevoked({ grantId: revoked.grant_id, accountId: revoked.account_id, tokenIds: [id], tokensOnly: true });
      }
    }
  }

  /** Every live grant of an account. Returns how many were revoked. */
  async revokeAccount(accountId: string, reason: RevokeReason): Promise<number> {
    const revoked = await this.ctx.db.transaction((tx) => this.revokeIn(tx, { accountId }, reason));
    await this.announce(revoked, reason);
    return revoked.length;
  }

  // --- bearer authentication -----------------------------------------------

  /**
   * The principal behind an access token, read from the database on every
   * call: revoked or expired access (token, grant, a temporary passkey) is
   * refused on the very next request, whichever process revoked it.
   */
  async authenticate(token: string): Promise<Principal | null> {
    if (tokenKind(token) !== "access") return null;
    const { rows } = await this.ctx.db.query<GrantRow & { at_expires_at: Date; passkey_expires_at: Date | null }>(
      `SELECT g.id, g.client_id, g.account_id, g.scopes, g.resource, g.expires_at, g.revoked_at, a.email,
              at.expires_at AS at_expires_at, p.expires_at AS passkey_expires_at
       FROM oauth_access_token at JOIN oauth_grant g ON g.id = at.grant_id JOIN account a ON a.id = g.account_id
       LEFT JOIN passkey p ON p.id = g.passkey_id
       WHERE at.token_hash = $1`,
      [hashToken(token)],
    );
    // The time of the answer, not of the question: a lookup that waited on the database is judged when it returns.
    const t = this.now();
    const row = rows[0];
    if (!row || row.revoked_at || row.at_expires_at.getTime() <= t || row.expires_at.getTime() <= t) return null;
    const passkeyExpiresAt = row.passkey_expires_at?.getTime() ?? null;
    if (passkeyExpiresAt !== null && passkeyExpiresAt <= t) return null;
    if (!this.allowed(row.email)) return null;
    return {
      accountId: row.account_id,
      email: row.email,
      scopes: scopeUtil.parse(row.scopes),
      via: "oauth",
      grantId: row.id,
      expiresAt: earliest(Math.min(row.at_expires_at.getTime(), row.expires_at.getTime()), passkeyExpiresAt),
    };
  }

  /** The `core/auth-context` authenticator: claims only `Bearer gwa_…`, so other schemes keep their turn. */
  authenticator(): Authenticator {
    return async (req: FastifyRequest) => {
      const h = req.headers.authorization;
      if (typeof h !== "string" || !/^Bearer\s+gwa_/i.test(h)) return null;
      return this.authenticate(h.replace(/^Bearer\s+/i, "").trim());
    };
  }

  // --- housekeeping --------------------------------------------------------

  /** Drop expired codes and tokens, clear successors past the grace window, expire old grants. */
  async prune(): Promise<void> {
    const t = this.now();
    const db = this.ctx.db;
    await db.query("DELETE FROM oauth_code WHERE expires_at <= $1", [new Date(t - CODE_TTL_MS)]);
    await db.query("DELETE FROM oauth_access_token WHERE expires_at <= $1", [new Date(t)]);
    await db.query("UPDATE oauth_refresh_token SET successor = NULL WHERE successor IS NOT NULL AND used_at <= $1", [
      new Date(t - REFRESH_GRACE_MS),
    ]);
    // Used refresh tokens stay until they expire: reuse detection needs them.
    // Expired ones stay while a push subscription or an APNs device still
    // belongs to their grant (push outlives expiry, and renewal keeps the
    // grant): presented to /oauth/revoke, they revoke the grant and so those
    // pushes (the native app signs out that way).
    await db.query(
      `DELETE FROM oauth_refresh_token rt WHERE rt.expires_at <= $1
         AND NOT EXISTS (SELECT 1 FROM push_jmap_sub s WHERE s.grant_id = rt.grant_id)
         AND NOT EXISTS (SELECT 1 FROM push_apns_device d WHERE d.grant_id = rt.grant_id)`,
      [new Date(t)],
    );
    await db.query(
      "UPDATE oauth_grant SET revoked_at = $1, revoked_reason = 'expired' WHERE revoked_at IS NULL AND expires_at <= $1",
      [new Date(t)],
    );
  }
}
