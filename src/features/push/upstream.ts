import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { getAccountById, type Account } from "../../core/accounts.js";
import {
  getUpstream as getMailUpstream,
  JMAP_CORE,
  watchStateChanges,
  type JmapMethodCall,
  type JmapResponse,
  type Upstream as MailUpstream,
  type Watch,
} from "../../core/upstream/index.js";
import type { AppContext } from "../../types.js";
import type { Pipeline } from "./pipeline.js";
import type { PushStats } from "./stats.js";
import {
  accountsToReconcile,
  acquireUpstreamLease,
  getUpstream,
  getUpstreamByHook,
  hasActiveSubs,
  releaseUpstreamLease,
  storeUpstreamCode,
  updateUpstream,
  type Upstream,
} from "./store.js";

/**
 * Where new-mail signals come from, per account (design/push.md section 4),
 * kept only while the account has an active browser subscription (P1) unless
 * PUSH_UPSTREAM_ALWAYS. The upstream decides the mechanism:
 *
 * - "pushSubscription" (legacy-proxy): the gateway's own RFC 8620
 *   PushSubscription, at most one per account. Created, verified, refreshed
 *   and recreated by `reconcile`; the upstream POSTs to
 *   /internal/push/jmap/:hookId.
 * - "eventSource" (a native JMAP server such as Fastmail): one long-lived
 *   upstream EventSource per account (types=EmailDelivery), reconnecting with
 *   backoff. Nothing has to reach the gateway from outside.
 *
 * Either way a StateChange triggers the Email/changes pipeline.
 */

export const DEVICE_CLIENT_ID = "webmail-gateway";
const LEASE_MS = 60_000;
const REFRESH_BEFORE_MS = 15 * 86_400_000;
const HOOK_RE = /^[A-Za-z0-9_-]{16,64}$/;

export type ReconcileReason = "startup" | "timer" | "relogin" | "subs-changed" | "manual";

export interface UpstreamOptions {
  verifyTimeoutMs?: number;
  verifyPollMs?: number;
  /** "eventSource" mechanism: first reconnect delay (doubles up to 5 min). */
  eventSourceMinBackoffMs?: number;
}

const newHookId = (): string => randomBytes(16).toString("base64url");

function backoffMs(attempts: number): number {
  return Math.min(30_000 * 2 ** Math.max(0, attempts - 1), 15 * 60_000);
}

function setResult(res: { methodResponses: [string, Record<string, unknown>, string][] }, callId: string): Record<string, unknown> {
  const r = res.methodResponses.find(([, , id]) => id === callId);
  if (!r) throw new Error(`no response for ${callId}`);
  if (r[0] === "error") throw new Error(`JMAP error ${String(r[1].type)}`);
  return r[1];
}

export class UpstreamManager {
  private waiters = new Map<string, () => void>();
  private readonly mail: MailUpstream;
  /** Open upstream EventSource connections ("eventSource" mechanism), by gateway account id. */
  private readonly watches = new Map<string, Watch>();
  private readonly verifyTimeoutMs: number;
  private readonly verifyPollMs: number;
  private readonly esMinBackoffMs: number | undefined;

  constructor(
    private readonly ctx: AppContext,
    private readonly stats: PushStats,
    private readonly pipeline: Pipeline,
    opts: UpstreamOptions = {},
  ) {
    this.verifyTimeoutMs = opts.verifyTimeoutMs ?? 15_000;
    this.verifyPollMs = opts.verifyPollMs ?? 250;
    this.esMinBackoffMs = opts.eventSourceMinBackoffMs;
    this.mail = getMailUpstream(ctx);
  }

  private jmap(account: Account, calls: JmapMethodCall[]): Promise<JmapResponse> {
    return this.mail.jmap(account, calls, [JMAP_CORE]);
  }

  /** Close every upstream EventSource (shutdown). */
  stop(): void {
    for (const w of this.watches.values()) w.stop();
    this.watches.clear();
  }

  /** Whether an upstream EventSource is open for the account (tests, logs). */
  watching(accountId: string): boolean {
    return this.watches.get(accountId)?.connected ?? false;
  }

  hookUrl(hookId: string): string {
    return `${this.ctx.config.push.internalBaseUrl}/internal/push/jmap/${hookId}`;
  }

  /** Reconcile every account that has, or should have, an upstream subscription. */
  async reconcileAll(reason: ReconcileReason): Promise<void> {
    const ids = await accountsToReconcile(this.ctx.db, this.ctx.config.push.upstreamAlways);
    for (const id of ids) await this.reconcile(id, reason);
  }

  /** Bring one account's upstream subscription to the wanted state. Never throws. */
  async reconcile(accountId: string, reason: ReconcileReason): Promise<void> {
    let sweep = false;
    try {
      const row = await acquireUpstreamLease(this.ctx.db, accountId, newHookId(), LEASE_MS);
      if (!row) return;
      try {
        sweep = await this.reconcileLeased(accountId, row, reason);
      } finally {
        await releaseUpstreamLease(this.ctx.db, accountId);
      }
    } catch (err) {
      this.ctx.log.error({ accountId, err }, "push: reconcile failed");
      return;
    }
    // Catch-up sweep: mail missed while IDLE or legacy-proxy was down.
    if (sweep) await this.pipeline.trigger(accountId);
  }

  private async wanted(account: Account): Promise<boolean> {
    if (this.ctx.config.push.upstreamAlways) return this.mail.hasCredential(account.id);
    return hasActiveSubs(this.ctx.db, account.id);
  }

  /** Returns true when the upstream is active afterwards (so a sweep makes sense). */
  private async reconcileLeased(accountId: string, row: Upstream, reason: ReconcileReason): Promise<boolean> {
    const account = await getAccountById(this.ctx, accountId);
    if (!account) return false;
    if (!(await this.wanted(account))) {
      if (row.status !== "none" || this.watches.has(accountId)) await this.teardown(account, row);
      return false;
    }
    if (this.mail.pushMechanism === "eventSource") return this.watch(account, row);
    if (row.status === "active" && row.upstreamId) return this.probe(account, row);
    if (row.status === "failed" && reason === "timer" && row.nextAttemptAt && row.nextAttemptAt.getTime() > Date.now()) {
      return false;
    }
    return this.create(account, row, row.status === "none" ? "new" : row.status);
  }

  private async probe(account: Account, row: Upstream): Promise<boolean> {
    const now = Date.now();
    let found: Record<string, unknown> | undefined;
    try {
      const res = await this.jmap(account, [["PushSubscription/get", { ids: [row.upstreamId] }, "g"]]);
      const list = setResult(res, "g").list;
      found = Array.isArray(list) ? (list as Record<string, unknown>[]).find((s) => s.id === row.upstreamId) : undefined;
    } catch (err) {
      this.stats.inc("upstream_probe_failed");
      if (row.lastCheckOk !== false) {
        this.ctx.log.warn({ accountId: account.id, err: (err as Error).message }, "push: legacy-proxy probe failed");
      }
      await updateUpstream(this.ctx.db, account.id, { lastCheckAt: new Date(now), lastCheckOk: false });
      return false;
    }
    if (row.lastCheckOk === false) this.ctx.log.info({ accountId: account.id }, "push: legacy-proxy reachable again");
    if (!found) return this.create(account, row, "missing");
    if (found.verified === false) return this.create(account, row, "unverified");

    const expires = typeof found.expires === "string" ? Date.parse(found.expires) : NaN;
    if (Number.isFinite(expires) && expires - now < REFRESH_BEFORE_MS) {
      const next = new Date(now + this.ctx.config.push.upstreamExpiresMs);
      try {
        const res = await this.jmap(
          account,
          [["PushSubscription/set", { update: { [row.upstreamId!]: { expires: next.toISOString() } } }, "u"]],
        );
        const updated = setResult(res, "u").updated as Record<string, unknown> | null | undefined;
        if (!updated || !(row.upstreamId! in updated)) return this.create(account, row, "refresh-rejected");
        await updateUpstream(this.ctx.db, account.id, { expires: next });
        this.stats.inc("upstream_refreshed");
        this.ctx.log.info({ accountId: account.id }, "push: upstream subscription refreshed");
      } catch (err) {
        this.ctx.log.warn({ accountId: account.id, err: (err as Error).message }, "push: upstream refresh failed");
      }
    }
    await updateUpstream(this.ctx.db, account.id, { lastCheckAt: new Date(now), lastCheckOk: true });
    return true;
  }

  private async create(account: Account, row: Upstream, reason: string): Promise<boolean> {
    const db = this.ctx.db;
    const hookId = newHookId();
    let upstreamId: string | null = null;
    // A new hook id first: the old one now answers 404, so a stray old sub is deleted by legacy-proxy.
    await updateUpstream(db, account.id, { hookId, status: "creating", upstreamId: null, verificationCode: null });
    try {
      const existing = await this.jmap(account, [["PushSubscription/get", { ids: null }, "g"]]);
      const list = setResult(existing, "g").list;
      const others = Array.isArray(list) ? (list as { id?: unknown }[]).map((s) => s.id).filter((id): id is string => typeof id === "string") : [];

      const expires = new Date(Date.now() + this.ctx.config.push.upstreamExpiresMs);
      const calls: [string, Record<string, unknown>, string][] = [];
      // P6: we own legacy-proxy's push subscriptions; anything else is stale.
      if (others.length) calls.push(["PushSubscription/set", { destroy: others }, "d"]);
      calls.push([
        "PushSubscription/set",
        {
          create: {
            u: { deviceClientId: DEVICE_CLIENT_ID, url: this.hookUrl(hookId), types: ["EmailDelivery"], expires: expires.toISOString() },
          },
        },
        "c",
      ]);
      const res = await this.jmap(account, calls);
      if (others.length) this.ctx.log.info({ accountId: account.id, destroyed: others.length }, "push: destroyed other legacy-proxy subscriptions");
      const c = setResult(res, "c");
      const created = (c.created as Record<string, { id?: unknown }> | null | undefined)?.u;
      if (!created || typeof created.id !== "string") {
        const why = (c.notCreated as Record<string, { type?: unknown }> | null | undefined)?.u?.type;
        throw new Error(`create refused: ${String(why ?? "unknown")}`);
      }
      upstreamId = created.id;
      await updateUpstream(db, account.id, { upstreamId, status: "verifying" });

      const code = await this.waitForCode(account.id, hookId);
      if (!code) throw new Error("verification timed out");
      const v = await this.jmap(account, [["PushSubscription/set", { update: { [upstreamId]: { verificationCode: code } } }, "v"]]);
      const updated = setResult(v, "v").updated as Record<string, unknown> | null | undefined;
      if (!updated || !(upstreamId in updated)) throw new Error("verification refused");

      const now = new Date();
      await updateUpstream(db, account.id, {
        status: "active",
        verificationCode: null,
        expires,
        verifiedAt: now,
        // A fresh start (no upstream wanted before) never announces older mail;
        // a recreation keeps the old baseline so the sweep catches the gap.
        baselineAt: row.status === "none" || !row.baselineAt ? now : row.baselineAt,
        attempts: 0,
        lastError: null,
        nextAttemptAt: null,
        lastCheckAt: now,
        lastCheckOk: true,
      });
      this.stats.inc(`upstream_created_${reason}`);
      this.ctx.log.info({ accountId: account.id, reason }, "push: upstream subscription active");
      return true;
    } catch (err) {
      const attempts = row.attempts + 1;
      const message = (err as Error).message.slice(0, 200);
      await updateUpstream(db, account.id, {
        status: "failed",
        attempts,
        lastError: message,
        nextAttemptAt: new Date(Date.now() + backoffMs(attempts)),
      });
      this.stats.inc("upstream_create_failed");
      this.ctx.log.warn({ accountId: account.id, reason, attempts, err: message }, "push: upstream subscription failed");
      if (upstreamId) {
        await this.jmap(account, [["PushSubscription/set", { destroy: [upstreamId] }, "x"]]).catch(
          () => undefined,
        );
      }
      return false;
    }
  }

  /** "eventSource" mechanism: make sure the account's upstream EventSource is open. */
  private async watch(account: Account, row: Upstream): Promise<boolean> {
    if (row.status !== "active") {
      const now = new Date();
      await updateUpstream(this.ctx.db, account.id, {
        status: "active",
        upstreamId: null,
        verificationCode: null,
        verifiedAt: now,
        // As for a new subscription: a fresh start never announces older mail.
        baselineAt: row.status === "none" || !row.baselineAt ? now : row.baselineAt,
        attempts: 0,
        lastError: null,
        nextAttemptAt: null,
      });
      this.ctx.log.info({ accountId: account.id }, "push: upstream eventsource wanted");
    }
    if (!this.watches.has(account.id)) {
      const accountId = account.id;
      let opened = 0;
      this.watches.set(
        accountId,
        watchStateChanges(this.mail, account, {
          types: ["EmailDelivery"],
          log: this.ctx.log,
          ...(this.esMinBackoffMs !== undefined ? { minBackoffMs: this.esMinBackoffMs } : {}),
          onOpen: () => {
            this.stats.inc("upstream_eventsource_open");
            // A reconnect may have missed changes: catch up from the last Email state.
            if (opened++ > 0) void this.event(accountId, {});
          },
          onChange: (change) => {
            for (const [upstreamAccountId, types] of Object.entries(change.changed)) {
              const state = types && typeof types === "object" ? types["EmailDelivery"] : undefined;
              if (typeof state === "string") void this.event(accountId, { legacyAccountId: upstreamAccountId, state });
            }
          },
        }),
      );
      this.stats.inc("upstream_created_eventsource");
    }
    await updateUpstream(this.ctx.db, account.id, { lastCheckAt: new Date(), lastCheckOk: true });
    return true;
  }

  /** A new-mail signal from the upstream: record it and run the pipeline (never throws). */
  private async event(accountId: string, ev: { legacyAccountId?: string; state?: string }): Promise<void> {
    const at = new Date();
    this.stats.inc("internal_StateChange");
    try {
      await updateUpstream(this.ctx.db, accountId, { lastEventAt: at });
      await this.pipeline.trigger(accountId, { at, ...ev });
    } catch (err) {
      this.ctx.log.error({ accountId, err }, "push: StateChange handling failed");
    }
  }

  private async teardown(account: Account, row: Upstream): Promise<void> {
    const w = this.watches.get(account.id);
    if (w) {
      w.stop();
      this.watches.delete(account.id);
    }
    if (row.upstreamId) {
      try {
        await this.jmap(account, [["PushSubscription/set", { destroy: [row.upstreamId] }, "x"]]);
      } catch (err) {
        // A leftover gets a 404 on its next push (new hook id below) and legacy-proxy drops it.
        this.ctx.log.warn({ accountId: account.id, err: (err as Error).message }, "push: upstream destroy failed");
      }
    }
    await updateUpstream(this.ctx.db, account.id, {
      status: "none",
      hookId: newHookId(),
      upstreamId: null,
      verificationCode: null,
      attempts: 0,
      lastError: null,
      nextAttemptAt: null,
    });
    this.stats.inc("upstream_removed");
    this.ctx.log.info({ accountId: account.id }, "push: upstream subscription removed (no active devices)");
  }

  private async waitForCode(accountId: string, hookId: string): Promise<string | null> {
    const deadline = Date.now() + this.verifyTimeoutMs;
    try {
      for (;;) {
        const row = await getUpstream(this.ctx.db, accountId);
        if (!row || row.hookId !== hookId) return null;
        if (row.verificationCode) return row.verificationCode;
        const left = deadline - Date.now();
        if (left <= 0) return null;
        await new Promise<void>((resolve) => {
          const t = setTimeout(resolve, Math.min(this.verifyPollMs, left));
          this.waiters.set(hookId, () => {
            clearTimeout(t);
            resolve();
          });
        });
      }
    } finally {
      this.waiters.delete(hookId);
    }
  }

  /** POST /internal/push/jmap/:hookId - legacy-proxy's PushVerification and StateChange deliveries. */
  registerInternalRoute(app: FastifyInstance): void {
    app.post<{ Params: { hookId: string } }>(
      "/internal/push/jmap/:hookId",
      // logLevel warn: the request log line would carry the secret hook id.
      { bodyLimit: 64 * 1024, logLevel: "warn" },
      async (req, reply) => {
        const { hookId } = req.params;
        if (!HOOK_RE.test(hookId)) return reply.code(404).send({ error: "Unknown subscription" });
        let row: Upstream | null;
        try {
          row = await getUpstreamByHook(this.ctx.db, hookId);
        } catch (err) {
          // Never 404 on our own failure: legacy-proxy would delete a live subscription.
          this.ctx.log.error({ err }, "push: internal hook lookup failed");
          return reply.code(503).send({ error: "Unavailable" });
        }
        if (!row || row.status === "none") {
          this.stats.inc("internal_unknown_hook");
          return reply.code(404).send({ error: "Unknown subscription" });
        }
        const body = req.body as Record<string, unknown> | null;
        const type = body && typeof body === "object" ? body["@type"] : undefined;
        if (typeof type !== "string") return reply.code(400).send({ error: "Invalid JMAP push body" });
        this.stats.inc(`internal_${type === "PushVerification" || type === "StateChange" ? type : "other"}`);

        if (type === "PushVerification") {
          const code = body!.verificationCode;
          const psid = typeof body!.pushSubscriptionId === "string" ? body!.pushSubscriptionId : null;
          if (typeof code === "string" && code.length > 0 && code.length <= 512) {
            if (await storeUpstreamCode(this.ctx.db, hookId, psid, code)) this.waiters.get(hookId)?.();
          }
          return reply.send({ ok: true });
        }

        if (type === "StateChange") {
          const changed = body!.changed;
          let legacyAccountId: string | undefined;
          let state: string | undefined;
          if (changed && typeof changed === "object") {
            for (const [id, types] of Object.entries(changed as Record<string, unknown>)) {
              const s = types && typeof types === "object" ? (types as Record<string, unknown>).EmailDelivery : undefined;
              if (typeof s === "string") {
                legacyAccountId = id;
                state = s;
                break;
              }
            }
          }
          if (legacyAccountId !== undefined) {
            const accountId = row.accountId;
            const at = new Date();
            // Answer first (legacy-proxy waits 5 s at most); the work runs after.
            setImmediate(() => {
              void (async () => {
                try {
                  await updateUpstream(this.ctx.db, accountId, { lastEventAt: at });
                  await this.pipeline.trigger(accountId, { at, legacyAccountId, ...(state !== undefined ? { state } : {}) });
                } catch (err) {
                  this.ctx.log.error({ accountId, err }, "push: StateChange handling failed");
                }
              })();
            });
          }
          return reply.send({ ok: true });
        }
        return reply.send({ ok: true });
      },
    );
  }
}
