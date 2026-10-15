import type { FastifyRequest } from "fastify";
import type { Authenticator, Principal } from "../../core/auth-context.js";
import { open, seal } from "../../core/crypto.js";
import { emitTokenRevoked } from "../../core/hooks.js";
import type { Queryable } from "../../db/pool.js";
import type { AppContext } from "../../types.js";
import { asBuffer, deriveKey, hashToken, newToken, pkceMatches, scopes as scopeUtil, tokenKind } from "./util.js";

export const CODE_TTL_MS = 60_000;
export const ACCESS_TTL_MS = 3600_000;
export const REFRESH_TTL_MS = 30 * 86400_000;
export const GRANT_TTL_MS = 180 * 86400_000;
/** A10: a refresh token presented again within this window gets the same successor pair. */
export const REFRESH_GRACE_MS = 30_000;
const CACHE_TTL_MS = 30_000;
const CACHE_MAX = 1000;

export interface IssuedTokens {
  grantId: string;
  accessToken: string;
  refreshToken: string;
  /** Seconds. */
  expiresIn: number;
  scopes: string[];
}

export type RevokeReason = "client_revoke" | "refresh_reuse" | "code_replay" | "bootstrap_reset" | "not_allowed";

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
 * tests can drive the clock; the DB never computes time.
 */
export class TokenStore {
  private readonly successorKey: Buffer;
  private readonly cache = new Map<string, { principal: Principal; until: number }>();

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

  async issueCode(input: {
    clientId: string;
    accountId: string;
    redirectUri: string;
    codeChallenge: string;
    scopes: readonly string[];
    resource?: string | null;
  }): Promise<string> {
    const code = newToken("code");
    const t = this.now();
    await this.ctx.db.query(
      `INSERT INTO oauth_code (code_hash, client_id, account_id, redirect_uri, code_challenge, scopes, resource, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        hashToken(code),
        input.clientId,
        input.accountId,
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
   * Redeem a code exactly once. A second redemption of a code that already
   * produced a grant revokes that grant (RFC 9700 §4.5.3). Returns null on any
   * failure; the caller answers `invalid_grant`.
   */
  async redeemCode(input: { code: string; clientId: string; redirectUri: string; codeVerifier: string }): Promise<IssuedTokens | null> {
    if (tokenKind(input.code) !== "code") return null;
    const hash = hashToken(input.code);
    const t = this.now();
    let replayOf: string | null = null;
    const issued = await this.ctx.db.transaction(async (tx) => {
      const { rows } = await tx.query<{
        client_id: string;
        account_id: string;
        redirect_uri: string;
        code_challenge: string;
        scopes: string;
        resource: string | null;
        email: string;
      }>(
        `UPDATE oauth_code c SET used_at = $2 FROM account a
         WHERE c.code_hash = $1 AND c.used_at IS NULL AND c.expires_at > $2 AND a.id = c.account_id
         RETURNING c.client_id, c.account_id, c.redirect_uri, c.code_challenge, c.scopes, c.resource, a.email`,
        [hash, new Date(t)],
      );
      const row = rows[0];
      if (!row) {
        const prior = await tx.query<{ grant_id: string | null }>(
          "SELECT grant_id FROM oauth_code WHERE code_hash = $1 AND used_at IS NOT NULL",
          [hash],
        );
        replayOf = prior.rows[0]?.grant_id ?? null;
        return null;
      }
      if (
        row.client_id !== input.clientId ||
        row.redirect_uri !== input.redirectUri ||
        !pkceMatches(input.codeVerifier, row.code_challenge) ||
        !this.allowed(row.email)
      ) {
        return null;
      }
      const grant = await this.createGrant(tx, row.account_id, row.client_id, scopeUtil.parse(row.scopes), row.resource, row.email);
      await tx.query("UPDATE oauth_code SET grant_id = $2 WHERE code_hash = $1", [hash, grant.grantId]);
      return grant;
    });
    if (replayOf) await this.revokeGrant(replayOf, "code_replay");
    return issued;
  }

  private async createGrant(
    tx: Queryable,
    accountId: string,
    clientId: string,
    scopes: string[],
    resource: string | null,
    email: string,
  ): Promise<IssuedTokens> {
    const t = this.now();
    const { rows } = await tx.query<{ id: string }>(
      `INSERT INTO oauth_grant (client_id, account_id, scopes, resource, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [clientId, accountId, scopeUtil.join(scopes), resource, new Date(t), new Date(t + GRANT_TTL_MS)],
    );
    const grantId = rows[0]!.id;
    const pair = await this.mint(tx, grantId);
    this.ctx.log?.info({ grantId, accountId, clientId, email }, "oauth grant created");
    return { grantId, scopes, ...pair };
  }

  private async mint(tx: Queryable, grantId: string): Promise<Pick<IssuedTokens, "accessToken" | "refreshToken" | "expiresIn">> {
    const t = this.now();
    const accessToken = newToken("access");
    const refreshToken = newToken("refresh");
    await tx.query(
      "INSERT INTO oauth_access_token (token_hash, grant_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
      [hashToken(accessToken), grantId, new Date(t), new Date(t + ACCESS_TTL_MS)],
    );
    await tx.query(
      "INSERT INTO oauth_refresh_token (token_hash, grant_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
      [hashToken(refreshToken), grantId, new Date(t), new Date(t + REFRESH_TTL_MS)],
    );
    return { accessToken, refreshToken, expiresIn: ACCESS_TTL_MS / 1000 };
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
        GrantRow & { rt_expires_at: Date; used_at: Date | null; successor: Uint8Array | null }
      >(
        `SELECT g.id, g.client_id, g.account_id, g.scopes, g.resource, g.expires_at, g.revoked_at, a.email,
                rt.expires_at AS rt_expires_at, rt.used_at, rt.successor
         FROM oauth_refresh_token rt
         JOIN oauth_grant g ON g.id = rt.grant_id
         JOIN account a ON a.id = g.account_id
         WHERE rt.token_hash = $1
         FOR UPDATE OF rt`,
        [hash],
      );
      const row = rows[0];
      if (!row || row.client_id !== input.clientId) return null;
      if (row.revoked_at || row.expires_at.getTime() <= t || row.rt_expires_at.getTime() <= t) return null;
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
      const pair = await this.mint(tx, row.id);
      const sealed = seal(
        JSON.stringify({ ...pair, accessExpiresAt: t + ACCESS_TTL_MS, scopes }),
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
    const t = this.now();
    const tokenIds = await this.ctx.db.transaction(async (tx) => {
      const { rows } = await tx.query<{ id: string; account_id: string }>(
        "UPDATE oauth_grant SET revoked_at = $2, revoked_reason = $3 WHERE id = $1 AND revoked_at IS NULL RETURNING id, account_id",
        [grantId, new Date(t), reason],
      );
      if (!rows[0]) return null;
      const ats = await tx.query<{ token_hash: Uint8Array }>(
        "DELETE FROM oauth_access_token WHERE grant_id = $1 RETURNING token_hash",
        [grantId],
      );
      await tx.query("DELETE FROM oauth_refresh_token WHERE grant_id = $1", [grantId]);
      return { accountId: rows[0].account_id, ids: ats.rows.map((r) => asBuffer(r.token_hash)!.toString("hex")) };
    });
    if (!tokenIds) return;
    for (const id of tokenIds.ids) this.cache.delete(id);
    this.ctx.log?.info({ grantId, reason, accountId: tokenIds.accountId }, "oauth grant revoked");
    await emitTokenRevoked({ grantId, accountId: tokenIds.accountId, tokenIds: tokenIds.ids });
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
      const { rows } = await this.ctx.db.query<{ grant_id: string; account_id: string }>(
        `DELETE FROM oauth_access_token at USING oauth_grant g
         WHERE at.token_hash = $1 AND g.id = at.grant_id AND g.client_id = $2
         RETURNING at.grant_id, g.account_id`,
        [hash, clientId],
      );
      if (rows[0]) {
        const id = hash.toString("hex");
        this.cache.delete(id);
        await emitTokenRevoked({ grantId: rows[0].grant_id, accountId: rows[0].account_id, tokenIds: [id] });
      }
    }
  }

  /** Every live grant of an account (bootstrap `--reset`). Returns how many were revoked. */
  async revokeAccount(accountId: string, reason: RevokeReason): Promise<number> {
    const { rows } = await this.ctx.db.query<{ id: string }>(
      "SELECT id FROM oauth_grant WHERE account_id = $1 AND revoked_at IS NULL",
      [accountId],
    );
    for (const r of rows) await this.revokeGrant(r.id, reason);
    return rows.length;
  }

  // --- bearer authentication -----------------------------------------------

  async authenticate(token: string): Promise<Principal | null> {
    if (tokenKind(token) !== "access") return null;
    const t = this.now();
    const hash = hashToken(token);
    const id = hash.toString("hex");
    const hit = this.cache.get(id);
    if (hit && hit.until > t) return hit.principal;
    const { rows } = await this.ctx.db.query<GrantRow & { at_expires_at: Date }>(
      `SELECT g.id, g.client_id, g.account_id, g.scopes, g.resource, g.expires_at, g.revoked_at, a.email,
              at.expires_at AS at_expires_at
       FROM oauth_access_token at JOIN oauth_grant g ON g.id = at.grant_id JOIN account a ON a.id = g.account_id
       WHERE at.token_hash = $1`,
      [hash],
    );
    const row = rows[0];
    if (!row || row.revoked_at || row.at_expires_at.getTime() <= t || row.expires_at.getTime() <= t) return null;
    if (!this.allowed(row.email)) return null;
    const principal: Principal = { accountId: row.account_id, email: row.email, scopes: scopeUtil.parse(row.scopes), via: "oauth" };
    if (this.cache.size >= CACHE_MAX) this.cache.delete(this.cache.keys().next().value!);
    this.cache.set(id, { principal, until: Math.min(t + CACHE_TTL_MS, row.at_expires_at.getTime()) });
    return principal;
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
    await db.query("DELETE FROM oauth_refresh_token WHERE expires_at <= $1", [new Date(t)]);
    await db.query(
      "UPDATE oauth_grant SET revoked_at = $1, revoked_reason = 'expired' WHERE revoked_at IS NULL AND expires_at <= $1",
      [new Date(t)],
    );
    for (const [k, v] of this.cache) if (v.until <= t) this.cache.delete(k);
  }
}
