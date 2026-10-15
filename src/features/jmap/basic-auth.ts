// Password-mode Basic authenticator (Phase 2; design/jmap.md sections 3 and 7).
// Credentials are verified by logging in to legacy-proxy with Basic; on success
// the Gandi password is stored sealed so token minting and re-login work later.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { FastifyRequest } from "fastify";
import { getGandiPassword, normalizeEmail, setGandiPassword, upsertAccount } from "../../core/accounts.js";
import type { Principal } from "../../core/auth-context.js";
import type { AppContext } from "../../types.js";
import { FixedWindowLimiter, Semaphore, type Bucket, type Clock } from "./limiter.js";
import type { Upstream } from "./upstream.js";

/** Thrown by the authenticator when the request is ours but must not get a plain 401. */
export class AuthHttpError extends Error {
  constructor(
    readonly status: 429 | 502 | 503 | 504,
    readonly retryAfterSec?: number,
  ) {
    super(`auth ${status}`);
    this.name = "AuthHttpError";
  }
}

const VERIFY_TIMEOUT_MS = 15_000;
const VERIFY_QUEUE_WAIT_MS = 5_000;
export const BASIC_SCOPES = ["mail"]; // D7

type Outcome = "ok" | "bad_credentials" | "not_allowed" | "rate_limited" | "malformed" | "upstream_error";

interface CacheEntry {
  principal: Principal;
  expires: number;
}

export class BasicAuth {
  private readonly cacheKey = randomBytes(32);
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inflight = new Map<string, Promise<Principal | null>>();
  readonly limiter: FixedWindowLimiter;
  private readonly verifySlots: Semaphore;
  private readonly allowed: ReadonlySet<string>;

  constructor(
    private readonly ctx: AppContext,
    private readonly upstream: Upstream,
    private readonly now: Clock = Date.now,
  ) {
    const rl = ctx.config.jmap.rateLimit;
    this.limiter = new FixedWindowLimiter(rl.windowSec * 1000, now);
    this.verifySlots = new Semaphore(rl.verifyConcurrency);
    this.allowed = new Set(ctx.config.allowedEmails);
  }

  /** The `Authenticator` to register with core/auth-context. */
  readonly authenticate = async (req: FastifyRequest): Promise<Principal | null> => {
    const header = req.headers.authorization;
    if (typeof header !== "string" || !/^basic\s/i.test(header)) return null;
    const ip = req.ip;
    const rl = this.ctx.config.jmap.rateLimit;
    const ipBucket: Bucket = { key: `ip:${ip}`, limit: rl.ip };

    const creds = parseBasic(header);
    if (!creds) return this.reject(ip, null, "malformed", ipBucket);
    const email = normalizeEmail(creds.user);
    const key = this.keyFor(email, creds.password);

    // Cache hits skip the limiter: other people's failures cannot lock out a working session.
    const hit = this.cache.get(key);
    if (hit && hit.expires > this.now()) return hit.principal;
    if (hit) this.cache.delete(key);

    const shared = this.inflight.get(key);
    if (shared) return shared;

    const acctBucket: Bucket = { key: `acct:${email}`, limit: rl.account };
    const globalBucket: Bucket = { key: "global", limit: rl.global };
    const wait = this.limiter.blockedFor([ipBucket, acctBucket, globalBucket]);
    if (wait > 0) {
      this.log(ip, email, "rate_limited");
      throw new AuthHttpError(429, wait);
    }
    if (!this.allowed.has(email)) return this.reject(ip, email, "not_allowed", ipBucket);

    const p = this.verify(ip, email, creds.password, key, [ipBucket, acctBucket, globalBucket]).finally(() =>
      this.inflight.delete(key),
    );
    this.inflight.set(key, p);
    return p;
  };

  /** Drop every cached login of an account (its Gandi password stopped working). */
  invalidateAccount(accountId: string): void {
    for (const [k, e] of this.cache) if (e.principal.accountId === accountId) this.cache.delete(k);
  }

  private async verify(
    ip: string,
    email: string,
    password: string,
    key: string,
    buckets: Bucket[],
  ): Promise<Principal | null> {
    // Reserve before forwarding, so concurrent wrong guesses cannot overshoot the limit.
    const wait = this.limiter.tryReserve(buckets);
    if (wait > 0) {
      this.log(ip, email, "rate_limited");
      throw new AuthHttpError(429, wait);
    }
    const keys = buckets.map((b) => b.key);
    const release = await this.verifySlots.acquire(VERIFY_QUEUE_WAIT_MS);
    if (!release) {
      this.limiter.refund(keys);
      this.log(ip, email, "upstream_error");
      throw new AuthHttpError(503, 5);
    }
    let status: number;
    let session: unknown = null;
    try {
      const res = await this.upstream.raw({
        method: "GET",
        path: "/jmap/session",
        headers: {
          authorization: `Basic ${Buffer.from(`${email}:${password}`, "utf8").toString("base64")}`,
          "accept-encoding": "identity",
        },
        headersTimeout: VERIFY_TIMEOUT_MS,
        bodyTimeout: VERIFY_TIMEOUT_MS,
      });
      status = res.statusCode;
      if (status === 200) session = await res.body.json().catch(() => null);
      else await res.body.dump();
    } catch (err) {
      this.limiter.refund(keys);
      this.log(ip, email, "upstream_error");
      throw new AuthHttpError((err as { status?: number }).status === 504 ? 504 : 502);
    } finally {
      release();
    }

    if (status === 401 || status === 403) {
      this.log(ip, email, "bad_credentials");
      return null;
    }
    if (status !== 200 || !session) {
      this.limiter.refund(keys);
      this.log(ip, email, "upstream_error", status);
      throw new AuthHttpError(502);
    }
    this.limiter.refund(keys);

    const account = await upsertAccount(this.ctx, {
      email,
      legacySlug: `${this.ctx.config.legacyProvider}:${email}`,
    });
    const stored = await getGandiPassword(this.ctx, account.id).catch(() => null);
    if (stored === null || !constantTimeEqual(stored, password)) await setGandiPassword(this.ctx, account.id, password);
    this.upstream.forget(account.id);
    this.upstream.markOk(account.id);

    const principal: Principal = { accountId: account.id, email, scopes: [...BASIC_SCOPES], via: "basic" };
    this.cache.set(key, { principal, expires: this.now() + this.ctx.config.jmap.basicCacheTtlSec * 1000 });
    this.log(ip, email, "ok");
    return principal;
  }

  private reject(ip: string, email: string | null, outcome: Outcome, ipBucket: Bucket): null {
    const wait = this.limiter.blockedFor([ipBucket]);
    if (wait > 0) {
      this.log(ip, email, "rate_limited");
      throw new AuthHttpError(429, wait);
    }
    this.limiter.hit(ipBucket.key);
    this.log(ip, email, outcome);
    return null;
  }

  private keyFor(email: string, password: string): string {
    return createHmac("sha256", this.cacheKey).update(email).update("\0").update(password).digest("base64url");
  }

  /** A short keyed hash of the email: lets logs correlate attempts without naming the person. */
  userTag(email: string): string {
    return createHmac("sha256", this.cacheKey).update(email).digest("hex").slice(0, 8);
  }

  private log(ip: string, email: string | null, outcome: Outcome, upstreamStatus?: number): void {
    const level = outcome === "ok" ? "info" : "warn";
    this.ctx.log[level](
      { event: "basic_auth", outcome, ip, user: email ? this.userTag(email) : null, upstreamStatus },
      "password-mode login",
    );
  }
}

function parseBasic(header: string): { user: string; password: string } | null {
  const b64 = header.slice(header.indexOf(" ") + 1).trim();
  if (!/^[A-Za-z0-9+/]+=*$/.test(b64)) return null;
  const decoded = Buffer.from(b64, "base64").toString("utf8");
  const i = decoded.indexOf(":");
  if (i < 1) return null;
  const user = decoded.slice(0, i).trim();
  const password = decoded.slice(i + 1);
  if (!user.includes("@") || password.length === 0) return null;
  return { user, password };
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
