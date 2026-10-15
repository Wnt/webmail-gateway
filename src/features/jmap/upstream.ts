// The connection to legacy-proxy (design/jmap.md sections 3 and 5): one undici
// Pool, minted Bearer tokens cached per account, and the 401 re-login path.
import { Pool, type Dispatcher } from "undici";
import { LEGACY_TOKEN_TTL_SEC, mintLegacyToken, relogin, type LegacyAccount } from "../../core/legacy.js";
import type { AppContext } from "../../types.js";
import type { Clock } from "./limiter.js";

/** Reuse a minted token while it has more than this many seconds left. */
const TOKEN_MIN_REMAINING_SEC = 60;
/** Skip the upload preflight when legacy-proxy accepted this account this recently. */
const KNOWN_FRESH_MS = 120_000;

export type UpstreamResponse = Dispatcher.ResponseData;

export interface UpstreamRequest {
  method: Dispatcher.HttpMethod;
  /** Path and query, starting with `/`, appended to LEGACY_PROXY_URL as-is. */
  path: string;
  headers?: Record<string, string>;
  body?: Dispatcher.DispatchOptions["body"];
  /** Whether the body may be sent twice (it may not when it is a stream). */
  replayable: boolean;
  signal?: AbortSignal;
  headersTimeout?: number;
  bodyTimeout?: number;
}

export type UpstreamResult =
  | { kind: "response"; res: UpstreamResponse }
  /** legacy-proxy rejected the stored Gandi password (or there is none): the caller answers 401. */
  | { kind: "authLost" }
  /** A non-replayable request got 401; the account was re-logged-in and the client should retry. */
  | { kind: "retryLater" };

/** Transport failure talking to legacy-proxy, mapped to the status the client gets. */
export class UpstreamError extends Error {
  constructor(
    message: string,
    readonly status: 502 | 504,
    readonly code?: string,
  ) {
    super(message);
    this.name = "UpstreamError";
  }
}

export function toUpstreamError(err: unknown): UpstreamError {
  const code = (err as { code?: string } | null)?.code;
  const timeout = code === "UND_ERR_HEADERS_TIMEOUT" || code === "UND_ERR_CONNECT_TIMEOUT";
  return new UpstreamError(timeout ? "legacy-proxy timed out" : "legacy-proxy unreachable", timeout ? 504 : 502, code);
}

export class Upstream {
  readonly pool: Pool;
  private readonly basePath: string;
  private readonly tokens = new Map<string, { token: string; exp: number; slug: string }>();
  private readonly lastOk = new Map<string, number>();
  /** Called when legacy-proxy no longer accepts an account's stored password. */
  onAuthLost: (accountId: string) => void = () => {};

  constructor(
    private readonly ctx: AppContext,
    private readonly now: Clock = Date.now,
  ) {
    const u = new URL(ctx.config.legacyProxyUrl);
    this.pool = new Pool(u.origin, { connections: 256, keepAliveTimeout: 30_000 });
    this.basePath = u.pathname.replace(/\/+$/, "");
  }

  /** A minted legacy-proxy token for `account`, reused while it has at least 60 s left. */
  token(account: LegacyAccount): string {
    const nowSec = Math.floor(this.now() / 1000);
    const c = this.tokens.get(account.id);
    if (c && c.slug === account.legacySlug && c.exp - nowSec > TOKEN_MIN_REMAINING_SEC) return c.token;
    const token = mintLegacyToken(account.legacySlug, account.email, this.ctx.config.legacyHmacKey, nowSec);
    this.tokens.set(account.id, { token, exp: nowSec + LEGACY_TOKEN_TTL_SEC, slug: account.legacySlug });
    return token;
  }

  /** A request without account credentials (the Basic verification). Throws `UpstreamError`. */
  async raw(opts: Omit<UpstreamRequest, "replayable">): Promise<UpstreamResponse> {
    try {
      return await this.pool.request({
        path: this.basePath + opts.path,
        method: opts.method,
        headers: opts.headers ?? {},
        body: opts.body ?? null,
        signal: opts.signal ?? null,
        headersTimeout: opts.headersTimeout ?? 60_000,
        bodyTimeout: opts.bodyTimeout ?? 120_000,
      });
    } catch (err) {
      throw toUpstreamError(err);
    }
  }

  /**
   * A request as `account` with a minted Bearer token. On 401 the account is
   * re-logged-in once with its stored Gandi password; a replayable request is
   * then retried once. Throws `UpstreamError` on transport failures.
   */
  async request(account: LegacyAccount, opts: UpstreamRequest): Promise<UpstreamResult> {
    const send = () =>
      this.raw({ ...opts, headers: { ...opts.headers, authorization: `Bearer ${this.token(account)}` } });

    const first = await send();
    if (first.statusCode !== 401) {
      if (first.statusCode < 300) this.lastOk.set(account.id, this.now());
      return { kind: "response", res: first };
    }
    await first.body.dump();
    this.tokens.delete(account.id);
    this.lastOk.delete(account.id);

    let ok = false;
    try {
      ok = await relogin(this.ctx, account);
    } catch (err) {
      throw toUpstreamError(err);
    }
    if (!ok) {
      this.onAuthLost(account.id);
      return { kind: "authLost" };
    }
    if (!opts.replayable) return { kind: "retryLater" };

    const second = await send();
    if (second.statusCode === 401) {
      await second.body.dump();
      this.onAuthLost(account.id);
      return { kind: "authLost" };
    }
    if (second.statusCode < 300) this.lastOk.set(account.id, this.now());
    return { kind: "response", res: second };
  }

  /**
   * Before a non-replayable request: make sure legacy-proxy still knows the
   * account (a cheap session request, which re-logs-in on 401). Skipped when
   * the account was accepted recently.
   */
  async ensureKnown(account: LegacyAccount): Promise<"ok" | "authLost" | "error"> {
    const at = this.lastOk.get(account.id);
    if (at !== undefined && this.now() - at < KNOWN_FRESH_MS) return "ok";
    const r = await this.request(account, {
      method: "GET",
      path: "/jmap/session",
      headers: { "accept-encoding": "identity" },
      replayable: true,
      headersTimeout: 30_000,
    });
    if (r.kind === "authLost") return "authLost";
    if (r.kind !== "response") return "error";
    await r.res.body.dump();
    return r.res.statusCode < 300 ? "ok" : "error";
  }

  markOk(accountId: string): void {
    this.lastOk.set(accountId, this.now());
  }

  forget(accountId: string): void {
    this.tokens.delete(accountId);
    this.lastOk.delete(accountId);
  }

  close(): Promise<void> {
    return this.pool.close();
  }
}
