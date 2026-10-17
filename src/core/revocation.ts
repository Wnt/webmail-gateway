// Cross-process revocation feed (owner requirement 2026-10-17: no request or
// open stream may outlive a revocation on stale state). Every revocation, in
// the server or in a CLI process (`kubectl exec`), sends `pg_notify` in its
// own transaction, so the notice exists exactly when the revocation commits.
// The server LISTENs and turns each notice into `hooks.emitTokenRevoked`,
// which closes the affected EventSource streams at once. While the LISTEN
// connection is down (or just came back), consumers cannot trust the feed:
// `revocationFeedHealthy()` says so, and `onRevocationFeedChange` fires on
// every transition, so they recheck their streams themselves.
import type { FastifyBaseLogger } from "fastify";
import type { Db, Listener, Queryable } from "../db/pool.js";
import { emitTokenRevoked } from "./hooks.js";

export const REVOCATION_CHANNEL = "gateway_auth_revoked";
/** How often the LISTEN connection is probed; a failed or slow probe counts as lost. */
const PING_MS = 5_000;
const PING_TIMEOUT_MS = 3_000;
const RETRY_MIN_MS = 500;
const RETRY_MAX_MS = 15_000;
/** Postgres caps a NOTIFY payload at 8000 bytes; grants go in chunks well under it. */
const GRANTS_PER_NOTICE = 100;

/**
 * One revocation. `grantIds`: grants that were revoked (all their tokens and
 * streams end). `tokenIds` with `tokensOnly`: only these access tokens (sha256
 * hex) were revoked, the grant lives on.
 */
export interface RevocationNotice {
  accountId: string;
  grantIds: string[];
  tokenIds?: string[];
  tokensOnly?: boolean;
}

/** Inside the revoking transaction: the notice is delivered when (and only if) it commits. */
export async function notifyRevocation(tx: Queryable, n: RevocationNotice): Promise<void> {
  if (n.tokensOnly) {
    await tx.query("SELECT pg_notify($1, $2)", [REVOCATION_CHANNEL, JSON.stringify(n)]);
    return;
  }
  for (let i = 0; i < n.grantIds.length; i += GRANTS_PER_NOTICE) {
    const chunk: RevocationNotice = { accountId: n.accountId, grantIds: n.grantIds.slice(i, i + GRANTS_PER_NOTICE) };
    await tx.query("SELECT pg_notify($1, $2)", [REVOCATION_CHANNEL, JSON.stringify(chunk)]);
  }
}

function parseNotice(payload: string): RevocationNotice | null {
  try {
    const n = JSON.parse(payload) as Partial<RevocationNotice>;
    if (typeof n.accountId !== "string" || !Array.isArray(n.grantIds)) return null;
    return {
      accountId: n.accountId,
      grantIds: n.grantIds.filter((g): g is string => typeof g === "string"),
      tokenIds: Array.isArray(n.tokenIds) ? n.tokenIds.filter((t): t is string => typeof t === "string") : [],
      tokensOnly: n.tokensOnly === true,
    };
  } catch {
    return null;
  }
}

/** Deliver a notice to the in-process listeners (the jmap feature's streams). */
async function deliver(n: RevocationNotice): Promise<void> {
  for (const grantId of n.grantIds) {
    await emitTokenRevoked({
      grantId,
      accountId: n.accountId,
      tokenIds: n.tokensOnly ? (n.tokenIds ?? []) : [],
      ...(n.tokensOnly ? { tokensOnly: true } : {}),
    });
  }
}

// ---------------------------------------------------------------- the feed

type FeedListener = (healthy: boolean) => void;
const feeds = new Set<RevocationFeed>();
const changeListeners = new Set<FeedListener>();

/** Is a revocation feed connected right now? False: consumers recheck on their own. */
export function revocationFeedHealthy(): boolean {
  for (const f of feeds) if (f.healthy) return true;
  return false;
}

/** Called on every feed transition (connected, lost). Returns an unsubscribe function. */
export function onRevocationFeedChange(cb: FeedListener): () => void {
  changeListeners.add(cb);
  return () => changeListeners.delete(cb);
}

function changed(): void {
  const healthy = revocationFeedHealthy();
  for (const cb of [...changeListeners]) {
    try {
      cb(healthy);
    } catch {
      // a consumer's failure is its own
    }
  }
}

export class RevocationFeed {
  healthy = false;
  private listener: Listener | null = null;
  private stopped = false;
  private retryMs = RETRY_MIN_MS;
  private retryTimer: NodeJS.Timeout | null = null;
  private pingTimer: NodeJS.Timeout | null = null;

  constructor(
    private readonly db: Pick<Db, "listen">,
    private readonly log: Pick<FastifyBaseLogger, "info" | "warn" | "error">,
  ) {}

  start(): void {
    feeds.add(this);
    void this.connect();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    if (this.pingTimer) clearInterval(this.pingTimer);
    const l = this.listener;
    this.listener = null;
    feeds.delete(this);
    if (this.healthy) {
      this.healthy = false;
      changed();
    }
    await l?.close().catch(() => {});
  }

  private async connect(): Promise<void> {
    if (this.stopped) return;
    if (!this.db.listen) {
      this.log.warn("revocation feed: the database has no LISTEN; streams recheck on a timer");
      return;
    }
    let lost = false;
    try {
      const l = await this.db.listen(
        REVOCATION_CHANNEL,
        (payload) => {
          const n = parseNotice(payload);
          if (n) void deliver(n);
        },
        (err) => {
          lost = true;
          this.lost(err);
        },
      );
      if (this.stopped || lost) {
        await l.close().catch(() => {});
        return;
      }
      this.listener = l;
      this.retryMs = RETRY_MIN_MS;
      this.healthy = true;
      this.pingTimer = setInterval(() => void this.ping(), PING_MS);
      this.pingTimer.unref();
      this.log.info("revocation feed: listening");
      changed();
    } catch (err) {
      this.log.warn({ err: (err as Error).message }, "revocation feed: LISTEN failed, retrying");
      this.schedule();
    }
  }

  private async ping(): Promise<void> {
    const l = this.listener;
    if (!l) return;
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        l.ping(),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("ping timeout")), PING_TIMEOUT_MS);
        }),
      ]);
    } catch (err) {
      if (this.listener === l) this.lost(err as Error);
    } finally {
      clearTimeout(timer);
    }
  }

  /** The LISTEN connection is gone: tell consumers, reconnect with backoff. */
  lost(err: Error): void {
    if (this.stopped) return;
    const l = this.listener;
    this.listener = null;
    if (this.pingTimer) clearInterval(this.pingTimer);
    this.pingTimer = null;
    void l?.close().catch(() => {});
    if (this.healthy) {
      this.healthy = false;
      this.log.warn({ err: err.message }, "revocation feed: LISTEN lost, streams recheck until it is back");
      changed();
    }
    this.schedule();
  }

  private schedule(): void {
    if (this.stopped || this.retryTimer) return;
    const wait = this.retryMs;
    this.retryMs = Math.min(RETRY_MAX_MS, this.retryMs * 2);
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void this.connect();
    }, wait);
    this.retryTimer.unref();
  }
}
