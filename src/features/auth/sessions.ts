import type { FastifyReply, FastifyRequest } from "fastify";
import type { AppContext } from "../../types.js";
import { hashToken, newToken, parseCookies, serializeCookie, tokenKind, type CookieOptions } from "./util.js";

export interface Session {
  idHash: Buffer;
  accountId: string;
  email: string;
  expiresAt: number;
}

type Ctx = Pick<AppContext, "config" | "db">;

/**
 * Server-side sessions for the gateway's own pages (§6 of the design). The
 * cookie holds `gws_…`; the row is keyed by its sha256. `SameSite=Strict`: every
 * entry to these pages is same-site, and `/oauth/authorize` never relies on
 * the session (A5).
 */
export class SessionStore {
  readonly cookieName: string;
  private readonly cookie: CookieOptions;

  constructor(
    private readonly ctx: Ctx,
    private readonly now: () => number = Date.now,
  ) {
    const secure = ctx.config.publicBaseUrl.startsWith("https://");
    this.cookieName = secure ? "__Host-gw_session" : "gw_session";
    this.cookie = { path: "/", maxAge: Math.floor(ctx.config.auth.sessionTtlMs / 1000), secure, sameSite: "Strict" };
  }

  async create(input: { accountId: string; passkeyId?: Buffer | null; ip?: string | null; userAgent?: string | null }): Promise<string> {
    const token = newToken("session");
    const t = this.now();
    await this.ctx.db.query(
      `INSERT INTO auth_session (id_hash, account_id, passkey_id, created_at, last_seen_at, expires_at, ip, user_agent)
       VALUES ($1, $2, $3, $4, $4, $5, $6, $7)`,
      [
        hashToken(token),
        input.accountId,
        input.passkeyId ?? null,
        new Date(t),
        new Date(t + this.ctx.config.auth.sessionTtlMs),
        input.ip ?? null,
        input.userAgent ?? null,
      ],
    );
    return token;
  }

  /** The live session behind a cookie value, or null. Only allowlisted accounts count. */
  async get(token: string | undefined): Promise<Session | null> {
    if (!token || tokenKind(token) !== "session") return null;
    const t = this.now();
    const hash = hashToken(token);
    const { rows } = await this.ctx.db.query<{ account_id: string; email: string; expires_at: Date; last_seen_at: Date }>(
      `SELECT s.account_id, a.email, s.expires_at, s.last_seen_at FROM auth_session s JOIN account a ON a.id = s.account_id
       WHERE s.id_hash = $1`,
      [hash],
    );
    const row = rows[0];
    if (!row || row.expires_at.getTime() <= t || !this.ctx.config.allowedEmails.includes(row.email)) return null;
    if (t - row.last_seen_at.getTime() > 60_000) {
      await this.ctx.db.query("UPDATE auth_session SET last_seen_at = $2 WHERE id_hash = $1", [hash, new Date(t)]);
    }
    return { idHash: hash, accountId: row.account_id, email: row.email, expiresAt: row.expires_at.getTime() };
  }

  async delete(token: string | undefined): Promise<void> {
    if (!token || tokenKind(token) !== "session") return;
    await this.ctx.db.query("DELETE FROM auth_session WHERE id_hash = $1", [hashToken(token)]);
  }

  /** Every session of an account (bootstrap `--reset`). Returns the count. */
  async deleteAccount(accountId: string): Promise<number> {
    const res = await this.ctx.db.query("DELETE FROM auth_session WHERE account_id = $1", [accountId]);
    return res.rowCount ?? 0;
  }

  async prune(): Promise<void> {
    await this.ctx.db.query("DELETE FROM auth_session WHERE expires_at <= $1", [new Date(this.now())]);
  }

  fromRequest(req: FastifyRequest): string | undefined {
    return parseCookies(req.headers.cookie).get(this.cookieName);
  }

  /** The session of the request's cookie, or null. */
  async ofRequest(req: FastifyRequest): Promise<Session | null> {
    return this.get(this.fromRequest(req));
  }

  setCookie(reply: FastifyReply, token: string): void {
    appendSetCookie(reply, serializeCookie(this.cookieName, token, this.cookie));
  }

  clearCookie(reply: FastifyReply): void {
    appendSetCookie(reply, serializeCookie(this.cookieName, "", { ...this.cookie, maxAge: 0 }));
  }
}

/** Fastify keeps one value per header; Set-Cookie must accumulate. */
export function appendSetCookie(reply: FastifyReply, value: string): void {
  const prev = reply.getHeader("set-cookie");
  const list = prev === undefined ? [] : Array.isArray(prev) ? prev.map(String) : [String(prev)];
  reply.header("set-cookie", [...list, value]);
}

